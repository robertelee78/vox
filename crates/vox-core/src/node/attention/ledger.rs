//! Current observations in the existing sealed room store; no transcript/body copies.
use super::{Attempt, Cursor, DispatchOutcome, Page, Recipient, Row, State, Wait, PAGE_SIZE};
use crate::atrest::sek::Sek;
use crate::atrest::store::{open_segment, seal_segment, SegmentKind};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::channel::entry_store::session_tree;
use crate::node::store::Batch;
use serde::{Deserialize, Serialize};

const KIND: SegmentKind = SegmentKind::SessionAttention;
const RECORD_BYTES: usize = 16 * 1024;
type Key = [u8; 64];

#[derive(Serialize, Deserialize)]
struct Header {
    instance: [u8; 16],
    next: u64,
    exact: u64,
    ordered: u64,
    queued: u64,
    cleanup: Option<(Digest32, u64)>,
}
impl Header {
    fn new(instance: [u8; 16]) -> Self {
        Self {
            instance,
            next: 1,
            exact: 0,
            ordered: 0,
            queued: 0,
            cleanup: None,
        }
    }
}
#[derive(Serialize, Deserialize)]
struct Session {
    recipient: Recipient,
    revision: u64,
    queued: u64,
    cursor: u64,
    attempt: Option<Attempt>,
    uncertain: bool,
    reason: Option<String>,
    wait: Option<Wait>,
    blocked_route: Option<Digest32>,
    audience_turn: bool,
    audience_after: u64,
    audiences: u64,
    work_after: u64,
    outputs_pending: u64,
}
/// One unresolved audience query; no thread bodies are retained across turns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ThreadScan {
    pub source: Digest32,
    pub arrival: u64,
    pub root: Digest32,
    pub after: u64,
}
impl Session {
    fn new(recipient: &Recipient) -> Self {
        Self {
            recipient: recipient.clone(),
            revision: 1,
            queued: 0,
            cursor: 0,
            attempt: None,
            uncertain: false,
            reason: None,
            wait: None,
            blocked_route: None,
            audience_turn: false,
            audience_after: 0,
            audiences: 0,
            work_after: 0,
            outputs_pending: 0,
        }
    }
}
#[derive(Serialize, Deserialize)]
struct Record {
    recipient: Digest32,
    ordinal: u64,
    row: Row,
    output_pending: Option<[u8; 16]>,
    // Pending audience is sealed but is not a public recipient observation.
    audience: Option<ThreadScan>,
}

fn bad() -> Error {
    Error::MalformedAtRest("room attention record")
}
fn changed() -> Error {
    Error::Profile("attention selection changed; refresh and retry")
}
fn key(a: &Digest32, b: &Digest32) -> Key {
    let mut k = [0; 64];
    k[..32].copy_from_slice(a);
    k[32..].copy_from_slice(b);
    k
}
fn ordered(a: &Digest32, ordinal: u64) -> Key {
    let mut k = [0; 64];
    k[..32].copy_from_slice(a);
    k[32..40].copy_from_slice(&ordinal.to_be_bytes());
    k
}
fn number(k: &Key) -> Result<u64> {
    Ok(u64::from_be_bytes(k[32..40].try_into().map_err(|_| bad())?))
}
fn reason(mut s: String) -> String {
    let mut end = s.len().min(512);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s
}

/// A fresh transaction's bounded working set. The caller commits before any external action.
pub(crate) struct Ledger<'a, 's> {
    batch: &'a mut Batch<'s>,
    sek: &'a Sek,
    room: Digest32,
    header: Header,
    dirty: bool,
}
impl<'a, 's> Ledger<'a, 's> {
    pub(crate) fn open(
        batch: &'a mut Batch<'s>,
        sek: &'a Sek,
        room: Digest32,
        instance: [u8; 16],
    ) -> Result<Self> {
        let header: Header = match batch.get_segment(&room, KIND, 0)? {
            Some(segment) => {
                if segment.ciphertext.len() > RECORD_BYTES + 32 {
                    return Err(bad());
                }
                let body = open_segment(sek, KIND, 0, &segment)?;
                let (v, bound, h): (u8, Digest32, Header) =
                    serde_json::from_slice(&body).map_err(|_| bad())?;
                if v != 1 || bound != room {
                    return Err(bad());
                }
                h
            }
            None => Header::new(instance),
        };
        if header.instance != instance {
            return Err(changed());
        }
        if header.next == 0 {
            return Err(bad());
        }
        Ok(Self {
            batch,
            sek,
            room,
            header,
            dirty: false,
        })
    }
    fn tree(&self) -> session_tree::Read<'_> {
        session_tree::Read::batch(self.batch, self.sek, &self.room, KIND)
    }
    fn get<T: serde::de::DeserializeOwned>(&self, id: u64) -> Result<T> {
        let seg = self
            .batch
            .get_segment(&self.room, KIND, id)?
            .ok_or_else(bad)?;
        if seg.ciphertext.len() > RECORD_BYTES + 32 {
            return Err(bad());
        }
        let body = open_segment(self.sek, KIND, id, &seg)?;
        let (v, bound, value): (u8, Digest32, T) =
            serde_json::from_slice(&body).map_err(|_| bad())?;
        if v != 1 || bound != self.room {
            return Err(bad());
        }
        Ok(value)
    }
    fn put<T: Serialize>(&mut self, id: u64, value: &T) -> Result<()> {
        let body = zeroize::Zeroizing::new(
            serde_json::to_vec(&(1u8, self.room, value)).map_err(|_| bad())?,
        );
        if body.len() > RECORD_BYTES {
            return Err(bad());
        }
        self.batch.put_segment(
            &self.room,
            KIND,
            id,
            &seal_segment(self.sek, KIND, id, &body)?,
        )?;
        self.dirty = true;
        Ok(())
    }
    fn alloc(&mut self) -> Result<u64> {
        let id = self.header.next;
        self.header.next = id.checked_add(1).ok_or_else(bad)?;
        self.dirty = true;
        Ok(id)
    }
    fn set(&mut self, root: u64, key: Key, value: Option<u64>) -> Result<u64> {
        let mut w =
            session_tree::Write::new(self.batch, self.sek, &self.room, KIND, self.header.next)?;
        let root = w.set(root, key, value)?;
        self.header.next = w.next_page();
        self.dirty = true;
        Ok(root)
    }
    fn session(&self, recipient: &Recipient) -> Result<(Option<u64>, Session)> {
        recipient.validate()?;
        if recipient.room != self.room || recipient.instance != self.header.instance {
            return Err(changed());
        }
        let id = self
            .tree()
            .find(self.header.ordered, &ordered(&recipient.key(), 0))?;
        match id {
            Some(id) => {
                let s: Session = self.get(id)?;
                if s.recipient.room != recipient.room
                    || s.recipient.instance != recipient.instance
                    || s.recipient.session != recipient.session
                    || s.recipient.identity != recipient.identity
                {
                    return Err(bad());
                }
                Ok((Some(id), s))
            }
            None => Ok((None, Session::new(recipient))),
        }
    }
    fn save_session(&mut self, id: Option<u64>, mut session: Session) -> Result<()> {
        session.revision = session.revision.checked_add(1).ok_or_else(bad)?;
        self.write_session(id, session)
    }
    fn write_session(&mut self, id: Option<u64>, session: Session) -> Result<()> {
        let id = match id {
            Some(id) => id,
            None => self.alloc()?,
        };
        self.put(id, &session)?;
        self.header.ordered = self.set(
            self.header.ordered,
            ordered(&session.recipient.key(), 0),
            Some(id),
        )?;
        Ok(())
    }
    pub(crate) fn contains_obligation(
        &self,
        recipient: &Recipient,
        source: &Digest32,
    ) -> Result<bool> {
        let Some(id) = self
            .tree()
            .find(self.header.exact, &key(&recipient.key(), source))?
        else {
            return Ok(false);
        };
        let record: Record = self.get(id)?;
        Ok(record.audience.is_none())
    }
    pub(crate) fn notice_pending(&self, recipient: &Recipient) -> Result<bool> {
        let (_, s) = self.session(recipient)?;
        Ok(s.attempt.is_some() || s.outputs_pending != 0)
    }
    pub(crate) fn cursor(&self, recipient: &Recipient) -> Result<u64> {
        Ok(self.session(recipient)?.1.cursor)
    }
    pub(crate) fn initialize(&mut self, recipient: &Recipient, initial: u64) -> Result<()> {
        let (id, mut s) = self.session(recipient)?;
        if id.is_none() {
            s.cursor = initial;
            self.write_session(id, s)?;
        } else if s.recipient.opening != recipient.opening {
            // A grant refresh changes the readable source, not this Session's obligations.
            s.recipient = recipient.clone();
            self.save_session(id, s)?;
        }
        Ok(())
    }
    pub(crate) fn availability(
        &mut self,
        recipient: &Recipient,
        wait: Option<Wait>,
        route: Option<Digest32>,
    ) -> Result<()> {
        let (id, mut session) = self.session(recipient)?;
        let new_route = session.blocked_route.is_some() && session.blocked_route != route;
        if session.wait != wait || new_route {
            session.wait = wait;
            if new_route {
                session.blocked_route = None;
                session.reason = None;
            }
            self.save_session(id, session)?;
        }
        Ok(())
    }
    pub(crate) fn scan_state(&self, recipient: &Recipient) -> Result<(u64, bool)> {
        let (_, s) = self.session(recipient)?;
        Ok((s.cursor, s.audience_turn))
    }
    /// The existing queued root also holds unresolved audiences. Inspect at most 16 slots,
    /// leaving room in this turn's budget for one bounded thread page.
    pub(crate) fn audience_work(&self, recipient: &Recipient) -> Result<(u64, Option<ThreadScan>)> {
        let (_, s) = self.session(recipient)?;
        let rkey = recipient.key();
        let mut after = s.audience_after;
        for _ in 0..16 {
            let Some((k, id)) = self
                .tree()
                .first_after(self.header.queued, Some(ordered(&rkey, after)))?
            else {
                return Ok((0, None));
            };
            if k[..32] != rkey {
                return Ok((0, None));
            }
            after = number(&k)?;
            let r: Record = self.get(id)?;
            if r.recipient != rkey || r.ordinal != after {
                return Err(bad());
            }
            if let Some(audience) = r.audience {
                return Ok((after, Some(audience)));
            }
        }
        Ok((after, None))
    }
    pub(crate) fn scanned(
        &mut self,
        recipient: &Recipient,
        through: u64,
        audience_after: Option<u64>,
    ) -> Result<()> {
        let (id, mut s) = self.session(recipient)?;
        let turn = s.audiences != 0 && audience_after.is_none();
        let after = audience_after.unwrap_or(s.audience_after);
        if through > s.cursor || s.audience_turn != turn || s.audience_after != after {
            s.cursor = s.cursor.max(through);
            s.audience_turn = turn;
            s.audience_after = after;
            self.write_session(id, s)?;
        }
        Ok(())
    }
    pub(crate) fn defer_audience(
        &mut self,
        recipient: &Recipient,
        pending: ThreadScan,
        urgent: bool,
        now: u64,
    ) -> Result<()> {
        if self
            .tree()
            .find(self.header.exact, &key(&recipient.key(), &pending.source))?
            .is_some()
        {
            return Ok(());
        }
        self.admit(
            recipient,
            pending.source,
            pending.arrival,
            urgent,
            None,
            now,
        )?;
        let (sid, mut s) = self.session(recipient)?;
        let id = self
            .tree()
            .find(self.header.exact, &key(&recipient.key(), &pending.source))?
            .ok_or_else(bad)?;
        let mut r: Record = self.get(id)?;
        r.audience = Some(pending);
        s.queued = s.queued.checked_sub(1).ok_or_else(bad)?;
        s.audiences = s.audiences.checked_add(1).ok_or_else(bad)?;
        self.put(id, &r)?;
        self.write_session(sid, s)
    }
    pub(crate) fn audience_progress(
        &mut self,
        recipient: &Recipient,
        pending: &ThreadScan,
        eligible: Option<bool>,
    ) -> Result<()> {
        let Some(id) = self
            .tree()
            .find(self.header.exact, &key(&recipient.key(), &pending.source))?
        else {
            return Ok(());
        };
        let mut r: Record = self.get(id)?;
        if r.audience.is_none() {
            return Ok(());
        }
        match eligible {
            Some(true) => self.admit(
                recipient,
                pending.source,
                pending.arrival,
                r.row.urgent,
                None,
                r.row.at_millis,
            ),
            Some(false) => self.remove_record(recipient, id, &r),
            None => {
                if r.audience.as_ref() != Some(pending) {
                    r.audience = Some(pending.clone());
                    self.put(id, &r)?;
                }
                Ok(())
            }
        }
    }
    fn remove_record(&mut self, recipient: &Recipient, id: u64, record: &Record) -> Result<()> {
        let rkey = recipient.key();
        self.header.exact = self.set(self.header.exact, key(&rkey, &record.row.source), None)?;
        self.header.ordered =
            self.set(self.header.ordered, ordered(&rkey, record.ordinal), None)?;
        self.header.queued = self.set(self.header.queued, ordered(&rkey, record.ordinal), None)?;
        self.batch.delete_segment(&self.room, KIND, id)?;
        if record.audience.is_some() {
            let (sid, mut s) = self.session(recipient)?;
            s.audiences = s.audiences.checked_sub(1).ok_or_else(bad)?;
            self.save_session(sid, s)?;
        }
        Ok(())
    }
    fn apply_wait(s: &Session, r: &mut Record, pending: bool) {
        if r.row.state != State::Queued {
            return;
        }
        if s.attempt
            .as_ref()
            .is_some_and(|a| a.sources.contains(&r.row.source))
            && (s.uncertain || pending)
        {
            r.row.wait = Some(Wait::Unknown);
            r.row.reason = Some(if s.uncertain {
                s.reason
                    .clone()
                    .unwrap_or_else(|| "notice acceptance is unknown".into())
            } else {
                "notice accepted; context receipt pending".into()
            });
        }
        if r.output_pending.is_some() {
            r.row.wait = Some(Wait::Unknown);
            r.row.reason = Some("hook context publication receipt is unconfirmed".into());
        } else if r.row.wait.is_none() {
            r.row.wait = s.wait;
            if s.blocked_route.is_some() {
                r.row.wait = Some(Wait::AdapterUnavailable);
                r.row.reason = s.reason.clone();
            }
        }
    }
    pub(crate) fn pending(&mut self, recipient: &Recipient) -> Result<Page> {
        let (sid, mut s) = self.session(recipient)?;
        let rkey = recipient.key();
        let mut after = s.work_after;
        let mut rows = Vec::new();
        let mut complete = false;
        for _ in 0..PAGE_SIZE {
            let Some((k, id)) = self
                .tree()
                .first_after(self.header.queued, Some(ordered(&rkey, after)))?
            else {
                complete = true;
                break;
            };
            if k[..32] != rkey {
                complete = true;
                break;
            }
            let mut r: Record = self.get(id)?;
            after = number(&k)?;
            if r.recipient != rkey || r.ordinal != after || r.row.state != State::Queued {
                return Err(bad());
            }
            if r.audience.is_some() {
                continue;
            }
            Self::apply_wait(&s, &mut r, true);
            rows.push(r.row);
        }
        let next = if complete { 0 } else { after };
        if s.work_after != next {
            s.work_after = next;
            self.write_session(sid, s)?;
        }
        let (_, s) = self.session(recipient)?;
        Ok(Page {
            instance: recipient.instance,
            opening: recipient.opening,
            revision: s.revision,
            preparing: s.audiences != 0,
            rows,
            next: None,
        })
    }
    pub(crate) fn admit(
        &mut self,
        recipient: &Recipient,
        source: Digest32,
        arrival: u64,
        urgent: bool,
        wait: Option<Wait>,
        now: u64,
    ) -> Result<()> {
        let recipient_key = recipient.key();
        let exact = key(&recipient_key, &source);
        if let Some(id) = self.tree().find(self.header.exact, &exact)? {
            let mut r: Record = self.get(id)?;
            if r.audience.take().is_some() {
                let (sid, mut s) = self.session(recipient)?;
                s.queued = s.queued.checked_add(1).ok_or_else(bad)?;
                s.audiences = s.audiences.checked_sub(1).ok_or_else(bad)?;
                self.put(id, &r)?;
                self.save_session(sid, s)?;
            }
            return Ok(());
        }
        let (sid, mut s) = self.session(recipient)?;
        let id = self.alloc()?;
        let record = Record {
            recipient: recipient_key,
            ordinal: id,
            output_pending: None,
            audience: None,
            row: Row {
                source,
                arrival,
                urgent,
                state: State::Queued,
                wait,
                at_millis: now,
                answer: None,
                reason: None,
            },
        };
        self.put(id, &record)?;
        self.header.exact = self.set(self.header.exact, exact, Some(id))?;
        self.header.ordered =
            self.set(self.header.ordered, ordered(&recipient_key, id), Some(id))?;
        self.header.queued = self.set(self.header.queued, ordered(&recipient_key, id), Some(id))?;
        s.queued = s.queued.checked_add(1).ok_or_else(bad)?;
        self.save_session(sid, s)
    }
    pub(crate) fn begin(
        &mut self,
        recipient: &Recipient,
        route: Digest32,
        sources: &[Digest32],
    ) -> Result<Option<Attempt>> {
        let (id, mut s) = self.session(recipient)?;
        if s.attempt.is_some()
            || s.queued == 0
            || s.outputs_pending != 0
            || s.blocked_route == Some(route)
            || s.wait.is_some()
        {
            return Ok(None);
        }
        if sources.len() > PAGE_SIZE {
            return Err(Error::Profile("attention notice exceeds one page"));
        }
        let mut through = 0;
        let mut selected = Vec::new();
        for source in sources {
            let Some(id) = self
                .tree()
                .find(self.header.exact, &key(&recipient.key(), source))?
            else {
                continue;
            };
            let r: Record = self.get(id)?;
            if r.row.state == State::Queued
                && r.row.wait.is_none()
                && r.audience.is_none()
                && r.output_pending.is_none()
            {
                if !selected.contains(source) {
                    selected.push(*source);
                }
                through = through.max(r.ordinal);
            }
        }
        if selected.is_empty() {
            return Ok(None);
        }
        let a = Attempt {
            recipient: recipient.clone(),
            notice_id: crate::identity::rng::random_array()?,
            route,
            count: selected.len() as u64,
            through,
            sources: selected,
        };
        // A crash after this seal must not turn a possibly accepted write into a fresh turn.
        s.blocked_route = None;
        s.attempt = Some(a.clone());
        s.uncertain = true;
        s.reason = Some("notice acceptance has not been confirmed".into());
        self.save_session(id, s)?;
        Ok(Some(a))
    }
    pub(crate) fn dispatch(&mut self, a: &Attempt, outcome: DispatchOutcome) -> Result<()> {
        let (id, mut s) = self.session(&a.recipient)?;
        let Some(current) = s.attempt.as_ref() else {
            return Ok(());
        };
        if current.notice_id != a.notice_id
            || current.route != a.route
            || current.recipient != a.recipient
        {
            return Err(changed());
        }
        match outcome {
            DispatchOutcome::Held(why) => {
                s.attempt = None;
                s.uncertain = false;
                s.reason = Some(reason(why));
            }
            DispatchOutcome::NotSent(why) | DispatchOutcome::Rejected(why) => {
                s.blocked_route = Some(a.route);
                s.attempt = None;
                s.uncertain = false;
                s.reason = Some(reason(why));
            }
            DispatchOutcome::Accepted => {
                s.uncertain = false;
                s.reason = None;
            }
            DispatchOutcome::Unknown(why) => {
                s.uncertain = true;
                s.reason = Some(reason(why));
            }
            DispatchOutcome::Unavailable(why) => {
                s.blocked_route = Some(a.route);
                s.attempt = None;
                s.uncertain = false;
                s.reason = Some(reason(why));
            }
        }
        self.save_session(id, s)
    }
    pub(crate) fn prepare(
        &mut self,
        recipient: &Recipient,
        sources: &[Digest32],
        ticket: [u8; 16],
    ) -> Result<()> {
        let (sid, mut s) = self.session(recipient)?;
        let mut changed_any = false;
        for source in sources {
            let Some(id) = self
                .tree()
                .find(self.header.exact, &key(&recipient.key(), source))?
            else {
                continue;
            };
            let mut r: Record = self.get(id)?;
            if r.row.state == State::Queued && r.output_pending.is_none() {
                r.output_pending = Some(ticket);
                s.outputs_pending = s.outputs_pending.checked_add(1).ok_or_else(bad)?;
                self.put(id, &r)?;
                changed_any = true;
            }
        }
        if changed_any {
            self.save_session(sid, s)?;
        }
        Ok(())
    }
    pub(crate) fn cancel_prepared(
        &mut self,
        recipient: &Recipient,
        sources: &[Digest32],
        ticket: [u8; 16],
    ) -> Result<()> {
        let (sid, mut s) = self.session(recipient)?;
        let mut changed_any = false;
        for source in sources {
            let Some(id) = self
                .tree()
                .find(self.header.exact, &key(&recipient.key(), source))?
            else {
                continue;
            };
            let mut r: Record = self.get(id)?;
            if r.output_pending == Some(ticket) {
                r.output_pending = None;
                s.outputs_pending = s.outputs_pending.checked_sub(1).ok_or_else(bad)?;
                self.put(id, &r)?;
                changed_any = true;
            }
        }
        if changed_any {
            self.save_session(sid, s)?;
        }
        Ok(())
    }
    pub(crate) fn received(
        &mut self,
        recipient: &Recipient,
        sources: &[Digest32],
        running: bool,
        now: u64,
    ) -> Result<()> {
        if sources.len() > PAGE_SIZE {
            return Err(Error::Profile("attention receipt exceeds one page"));
        }
        let (sid, mut s) = self.session(recipient)?;
        let rkey = recipient.key();
        let mut changed_any = false;
        for source in sources {
            let Some(id) = self.tree().find(self.header.exact, &key(&rkey, source))? else {
                continue;
            };
            let mut r: Record = self.get(id)?;
            if r.recipient != rkey || r.row.source != *source {
                return Err(bad());
            }
            if matches!(r.row.state, State::Answered | State::Unavailable) {
                continue;
            }
            if r.output_pending.is_some() {
                r.output_pending = None;
                s.outputs_pending = s.outputs_pending.checked_sub(1).ok_or_else(bad)?;
            }
            if r.row.state == State::Queued {
                s.queued = s.queued.checked_sub(1).ok_or_else(bad)?;
                self.header.queued =
                    self.set(self.header.queued, ordered(&rkey, r.ordinal), None)?;
            }
            r.row.state = if running || r.row.state == State::Answering {
                State::Answering
            } else {
                State::Delivered
            };
            r.row.wait = None;
            r.row.reason = None;
            r.row.at_millis = now;
            self.put(id, &r)?;
            changed_any = true;
        }
        if changed_any {
            Self::reconcile_attempt(&mut s, sources);
            self.save_session(sid, s)?;
        }
        Ok(())
    }
    pub(crate) fn answered(
        &mut self,
        recipient: &Recipient,
        source: Digest32,
        answer: Digest32,
        now: u64,
    ) -> Result<()> {
        let (sid, mut s) = self.session(recipient)?;
        let rkey = recipient.key();
        let Some(id) = self.tree().find(self.header.exact, &key(&rkey, &source))? else {
            return Ok(());
        };
        let mut r: Record = self.get(id)?;
        if r.recipient != rkey || r.row.source != source {
            return Err(bad());
        }
        if matches!(r.row.state, State::Answered | State::Unavailable) {
            return Ok(());
        }
        if r.audience.take().is_some() {
            s.queued = s.queued.checked_add(1).ok_or_else(bad)?;
            s.audiences = s.audiences.checked_sub(1).ok_or_else(bad)?;
        }
        if r.output_pending.is_some() {
            r.output_pending = None;
            s.outputs_pending = s.outputs_pending.checked_sub(1).ok_or_else(bad)?;
        }
        if r.row.state == State::Queued {
            s.queued = s.queued.checked_sub(1).ok_or_else(bad)?;
            self.header.queued = self.set(self.header.queued, ordered(&rkey, r.ordinal), None)?;
        }
        Self::reconcile_attempt(&mut s, &[source]);
        r.row.state = State::Answered;
        r.row.wait = None;
        r.row.reason = None;
        r.row.answer = Some(answer);
        r.row.at_millis = now;
        self.put(id, &r)?;
        self.save_session(sid, s)
    }
    fn reconcile_attempt(session: &mut Session, sources: &[Digest32]) {
        if let Some(attempt) = session.attempt.as_mut() {
            attempt.sources.retain(|hash| !sources.contains(hash));
            attempt.count = attempt.sources.len() as u64;
            if attempt.sources.is_empty() {
                session.attempt = None;
                session.uncertain = false;
                session.reason = None;
            }
        }
    }
    pub(crate) fn page(&self, recipient: &Recipient, after: Option<Cursor>) -> Result<Page> {
        let (_, s) = self.session(recipient)?;
        let rkey = recipient.key();
        let selection = Recipient::selection_key(
            recipient.room,
            recipient.instance,
            &recipient.session,
            recipient.opening,
        );
        if after.is_some_and(|c| {
            c.instance != recipient.instance || c.recipient != selection || c.revision != s.revision
        }) {
            return Err(changed());
        }
        let mut key = ordered(&rkey, after.map_or(0, |c| c.after));
        let mut rows = Vec::new();
        let mut last = 0;
        let mut inspected = 0;
        for _ in 0..PAGE_SIZE {
            let Some((next, id)) = self.tree().first_after(self.header.ordered, Some(key))? else {
                break;
            };
            if next[..32] != rkey {
                break;
            }
            let mut r: Record = self.get(id)?;
            last = number(&next)?;
            if r.recipient != rkey || r.ordinal != last {
                return Err(bad());
            }
            key = next;
            inspected += 1;
            if r.audience.is_none() {
                Self::apply_wait(&s, &mut r, false);
                rows.push(r.row);
            }
        }
        // Continuation follows examined slots even when all were pending audience work.
        let more = inspected == PAGE_SIZE;
        Ok(Page {
            instance: recipient.instance,
            opening: recipient.opening,
            revision: s.revision,
            preparing: s.audiences != 0,
            rows,
            next: more.then_some(Cursor {
                instance: recipient.instance,
                recipient: selection,
                revision: s.revision,
                after: last,
            }),
        })
    }
    pub(crate) fn maintenance(
        &self,
    ) -> Result<(
        Option<(Digest32, u64)>,
        Vec<(Recipient, Option<(Digest32, State)>)>,
    )> {
        let mut after = self.header.cleanup;
        let mut records = Vec::new();
        for _ in 0..32 {
            let Some((k, id)) = self.tree().first_after(
                self.header.ordered,
                after.map(|(recipient, ordinal)| ordered(&recipient, ordinal)),
            )?
            else {
                return Ok((None, records));
            };
            let recipient_key: Digest32 = k[..32].try_into().map_err(|_| bad())?;
            let ordinal = number(&k)?;
            after = Some((recipient_key, ordinal));
            if ordinal == 0 {
                let session: Session = self.get(id)?;
                if session.recipient.key() != recipient_key {
                    return Err(bad());
                }
                records.push((session.recipient, None));
                continue;
            }
            let row: Record = self.get(id)?;
            let session_id = self
                .tree()
                .find(self.header.ordered, &ordered(&recipient_key, 0))?
                .ok_or_else(bad)?;
            let session: Session = self.get(session_id)?;
            if row.recipient != recipient_key || session.recipient.key() != recipient_key {
                return Err(bad());
            }
            records.push((session.recipient, Some((row.row.source, row.row.state))));
        }
        Ok((after, records))
    }
    pub(crate) fn retire_empty(&mut self, recipient: &Recipient) -> Result<()> {
        let (id, _) = self.session(recipient)?;
        let rkey = recipient.key();
        let empty = self
            .tree()
            .first_after(self.header.ordered, Some(ordered(&rkey, 0)))?
            .is_none_or(|(k, _)| k[..32] != rkey);
        if let Some(id) = id.filter(|_| empty) {
            self.header.ordered = self.set(self.header.ordered, ordered(&rkey, 0), None)?;
            self.batch.delete_segment(&self.room, KIND, id)?;
        }
        Ok(())
    }
    pub(crate) fn retire(
        &mut self,
        recipient: &Recipient,
        source: Digest32,
        closed: bool,
        now: u64,
    ) -> Result<()> {
        let (sid, mut session) = self.session(recipient)?;
        let recipient_key = recipient.key();
        let Some(id) = self
            .tree()
            .find(self.header.exact, &key(&recipient_key, &source))?
        else {
            return Ok(());
        };
        let mut record: Record = self.get(id)?;
        if record.audience.is_some() {
            return self.remove_record(recipient, id, &record);
        }
        if record.row.state == State::Unavailable {
            self.header.exact = self.set(self.header.exact, key(&recipient_key, &source), None)?;
            self.header.ordered = self.set(
                self.header.ordered,
                ordered(&recipient_key, record.ordinal),
                None,
            )?;
            self.batch.delete_segment(&self.room, KIND, id)?;
            if closed
                && self
                    .tree()
                    .first_after(self.header.ordered, Some(ordered(&recipient_key, 0)))?
                    .is_none_or(|(next, _)| next[..32] != recipient_key)
            {
                self.header.ordered =
                    self.set(self.header.ordered, ordered(&recipient_key, 0), None)?;
                if let Some(sid) = sid {
                    self.batch.delete_segment(&self.room, KIND, sid)?;
                }
                return Ok(());
            }
        } else {
            if record.row.state == State::Queued {
                session.queued = session.queued.checked_sub(1).ok_or_else(bad)?;
                self.header.queued = self.set(
                    self.header.queued,
                    ordered(&recipient_key, record.ordinal),
                    None,
                )?;
            }
            if record.output_pending.take().is_some() {
                session.outputs_pending = session.outputs_pending.checked_sub(1).ok_or_else(bad)?;
            }
            record.row.state = State::Unavailable;
            record.row.wait = None;
            record.row.reason = Some(
                if closed {
                    "the exact Session is no longer open"
                } else {
                    "the source is no longer readable or retained"
                }
                .into(),
            );
            record.row.at_millis = now;
            self.put(id, &record)?;
            if let Some(attempt) = session.attempt.as_mut() {
                attempt.sources.retain(|hash| *hash != source);
                attempt.count = attempt.sources.len() as u64;
                if attempt.sources.is_empty() {
                    session.attempt = None;
                    session.uncertain = false;
                }
            }
        }
        self.save_session(sid, session)
    }
    pub(crate) fn maintained(&mut self, after: Option<(Digest32, u64)>) {
        if self.header.cleanup != after {
            self.header.cleanup = after;
            self.dirty = true;
        }
    }
    pub(crate) fn finish(mut self) -> Result<bool> {
        if self.dirty {
            let header = std::mem::replace(&mut self.header, Header::new([0; 16]));
            self.put(0, &header)?;
        }
        Ok(self.dirty)
    }
}
