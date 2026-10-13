//! **A Session is sealed to the members its node trusts with drive** (ADR-029 SC-2, SC-2a, SC-2b;
//! #543).
//!
//! Each node keeps, per room, a second sender-key chain beside its sender key: its **drive key**.
//! Every entry of every one of its Sessions in the room is sealed under it, and it is released only
//! to members whose keyring entry carries drive (ADR-028 K-14). One chain per (room, node), not one
//! per Session: drive is granted per keyring entry, so all of a node's Sessions have the same
//! readers, and a key per Session would only multiply the releases.
//!
//! It is the sender-key machinery (ADR-006) over its own namespace: the chain, its SKDMs and its
//! messages are bound to [`drive_channel`] rather than the room's id, so its AEAD data, its
//! cross-signature and its receiver slots can never be taken for the sender key's, nor the sender
//! key's for it. New steps use the private Session stream and store outside the room log (SA-7).
//! Published older writers' ordinary drive-sealed entries remain readable during upgrade.
//!
//! - **Release** (SC-2a): to each member admitted to the room whose keyring entry carries drive,
//!   from where it became owed the key, so it reads from then onward: a member that had drive when
//!   a generation was minted reads that generation whole, one that gained drive (or was admitted)
//!   later reads from that moment. Owed again at every new generation, retried on the tick. The
//!   cause of every release is that keyring entry (ADR-020 3.3).
//! - **Rotation** (SC-2b): when a member it was released to no longer has drive (downgraded to
//!   read, or untrusted), a new chain with fresh keys, released to the members that still have
//!   drive. The member keeps what it read and reads nothing sealed afterwards.
//! - **Receiving**: a drive key is taken only from a node this node trusts (V210-118), as the sender
//!   key is.
//!
//! The delivery ledger is local and sealed: the keyring is the authority on who may read, and the
//! ledger only says who has been given which generation.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::group::senderkey::ChainKey;
use crate::group::skdm::Skdm;
use crate::group::state::{ReceiverChain, SenderChain};
use crate::hash::Digest32;
use crate::identity::composite::RootSigner;

/// Domain of a room's drive namespace.
const DRIVE_DOMAIN: &[u8] = b"vox/session-key/v1";

/// Encoding version of the sealed drive state.
const DRIVE_VERSION: u64 = 2;

/// The most drive keys a room holds from other members, across generations.
pub const MAX_DRIVE_CHAINS: usize = 4096;

/// The id a room's drive keys are bound to in place of the room's own: `SHA-256(domain ‖ room)`.
#[must_use]
pub fn drive_channel(channel_id: &Digest32) -> Digest32 {
    crate::hash::sha256_concat(&[DRIVE_DOMAIN, channel_id])
}

/// The session id of the entry a node writes under a new drive generation when it changed its
/// key because a member lost drive (SC-2b): no harness session has it, so it is no Session's
/// entry. Members read from it that the key changed, at once rather than at the next entry.
pub const KEY_CHANGED: &str = "vox:drive-key";

/// Whether `session_id` is [`KEY_CHANGED`]'s: an entry that is no Session's, never shown as one.
#[must_use]
pub fn is_key_changed(session_id: &str) -> bool {
    session_id == KEY_CHANGED
}

/// One Session entry this node opened, or wrote (ADR-029 SC-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    /// The entry's ADR-008 hash.
    pub entry_hash: Digest32,
    /// The node whose session it is: the entry's author.
    pub author: Digest32,
    /// The author's recorded send time, milliseconds since the Unix epoch.
    pub created_millis: u64,
    /// The harness's session id.
    pub session_id: String,
    /// The activity item, as the harness's format has it.
    pub body: String,
}

/// A floor's author, recipient, room epoch and drive-key generation.
pub(crate) type SessionFloorKey = (Digest32, Digest32, u64, u64);

/// The recipient's membership generation, first permitted key iteration and first log sequence.
pub(crate) type SessionFloorBoundary = (u64, u64, u64);

/// A room's drive key material: this node's own chain, the drive keys other members released to
/// it, and to whom this node has released which generation.
#[derive(Default)]
pub struct DriveState {
    /// This node's drive chain here; none until its first Session entry in the room.
    pub(crate) chain: Option<SenderChain>,
    /// The live generation's iteration-0 key, from which each release is made at its mark.
    origin: Option<ChainKey>,
    /// Member → `(generation, iteration)` from which it is owed this node's drive key: where the
    /// live generation stood when it became owed it.
    marks: BTreeMap<Digest32, (u64, u64)>,
    /// Public authorization floors, derived from verified control entries; never secret keys.
    pub(crate) floors: BTreeMap<SessionFloorKey, SessionFloorBoundary>,
    pub(crate) floors_indexed: bool,
    /// Bodies a particular peer omitted, only until new authorization is learned or restart.
    pub(crate) omitted: BTreeMap<Digest32, (std::time::Instant, BTreeSet<(Digest32, u64)>)>,
    /// Drive keys released to this node, by `(author, generation)`.
    pub(crate) receivers: BTreeMap<(Digest32, u64), ReceiverChain>,
    /// Member → the generation of this node's drive key last released to it.
    pub(crate) delivered: BTreeMap<Digest32, u64>,
    /// The Session entries opened or written here, in the order they were.
    pub(crate) sessions: SessionLog,
    /// Entries opened in a render pass, placed once its batch has committed.
    pub(crate) pending: Vec<(SessionRow, u64)>,
    /// The sessions with an entry placed here since the node last said so
    /// ([`crate::node::api::NodeEvent::SessionEntry`]).
    pub(crate) news: Vec<String>,
    /// Whether this node changed its key here and has written nothing under the new one yet, so
    /// a member that lost drive cannot tell ([`KEY_CHANGED`]); `None` until worked out from the
    /// room's log. Not kept: it is worked out again when the room is opened.
    pub(crate) change_unsaid: Option<bool>,
    /// Entries under a key of another author's this node does not hold, already said as news
    /// (a lost drive key, SC-2b). Not kept.
    pub(crate) told_unheld: std::collections::HashSet<Digest32>,
}

/// Which Session entries a page is of (ADR-034 FR-5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionFilter {
    /// Every Session's.
    All,
    /// The Session with this harness session id, whoever wrote them (its node's own, and the drive
    /// entries naming it); or the one Session whose id begins with it, eight characters or more.
    Session(String),
    /// Raw records for the Session summary's entry count and newest-change marker.
    SessionRaw(String),
    /// Those announcing a file out of a Session (DR-1.8).
    FilesOut,
    /// Requests still answerable, without walking the Session's transcript.
    Pending(String),
    /// A named request's parts and resolution, however far back it was asked.
    Request {
        /// The complete harness Session id.
        session_id: String,
        /// The request's harness reference.
        reference: String,
    },
}

/// One page of Session activity, oldest origins first, with each origin's complete parts and
/// outcomes. Raw filters instead carry records in their original order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPage {
    /// Activity origins and their indexed companions, or raw records for a raw filter.
    pub rows: Vec<SessionRow>,
    /// How many older activities (raw records for a raw filter) precede this page.
    pub older: u64,
}

/// The Session entries opened or written in a room, in the order they were, with an index by
/// Session, by entry and of files out (ADR-034 FR-5): a page costs what it carries, whatever the
/// history's length.
#[derive(Default)]
pub struct SessionLog {
    rows: Vec<SessionRow>,
    /// The position of every row that is some Session's: all but key-changed entries.
    all: Vec<usize>,
    /// Session id → the positions of its rows.
    by_session: std::collections::HashMap<String, Vec<usize>>,
    /// The positions of rows announcing a file out of a Session.
    files_out: Vec<usize>,
    /// Entry hash → its position.
    at: std::collections::HashMap<Digest32, usize>,
    requests: std::collections::HashMap<(String, String), Vec<usize>>,
    pending: std::collections::HashMap<String, Vec<usize>>,
    resolved: std::collections::HashSet<(String, Digest32, String)>,
    visible: std::collections::HashMap<String, Vec<usize>>,
    pieces: std::collections::HashMap<usize, Vec<usize>>,
    open_parts: std::collections::HashMap<(String, Digest32, String, String), usize>,
    activity_refs: std::collections::HashMap<usize, String>,
    outcomes: std::collections::HashMap<(String, String), Vec<usize>>,
    drives: std::collections::HashSet<(String, String)>,
}

impl SessionLog {
    /// A log of `rows`, in that order.
    #[must_use]
    pub fn of(rows: Vec<SessionRow>) -> Self {
        let mut log = Self::default();
        for row in rows {
            log.push(row);
        }
        log
    }

    /// Add `row` after the rest.
    pub fn push(&mut self, row: SessionRow) {
        let at = self.rows.len();
        self.at.insert(row.entry_hash, at);
        if !is_key_changed(&row.session_id) {
            self.all.push(at);
            self.by_session
                .entry(row.session_id.clone())
                .or_default()
                .push(at);
            if is_file_out(&row) {
                self.files_out.push(at);
            }
            self.index_request(&row, at);
            self.index_activity(&row, at);
        }
        self.rows.push(row);
    }

    fn index_activity(&mut self, row: &SessionRow, at: usize) {
        let Ok(serde_json::Value::Object(body)) = serde_json::from_str(&row.body) else {
            return;
        };
        let body = serde_json::Value::Object(body);
        let kind = body["kind"].as_str().unwrap_or_default();
        let reference = body["ref"]
            .as_str()
            .or_else(|| match kind {
                "drive" => body["id"].as_str(),
                "drive-result" => body["of"].as_str(),
                _ => None,
            })
            .unwrap_or_default();
        if matches!(kind, "tool-done" | "resolved" | "drive-result") && !reference.is_empty() {
            self.outcomes
                .entry((row.session_id.clone(), reference.to_owned()))
                .or_default()
                .push(at);
        }
        let drive_key = (row.session_id.clone(), reference.to_owned());
        if kind == "drive" && !reference.is_empty() {
            self.drives.insert(drive_key.clone());
        }
        // These records update another line rather than occupying a page themselves.
        if matches!(kind, "tool-done" | "resolved")
            || (kind == "drive"
                && !matches!(
                    body["action"].as_str(),
                    Some("text" | "interrupt" | "stop" | "slash" | "file")
                ))
            || (kind == "drive-result" && (body["ok"] == true || self.drives.contains(&drive_key)))
        {
            return;
        }
        let part = body["part"]
            .as_array()
            .and_then(|p| Some((p.first()?.as_u64()?, p.get(1)?.as_u64()?)));
        let key = (
            row.session_id.clone(),
            row.author,
            kind.to_owned(),
            reference.to_owned(),
        );
        if let Some((i, n)) = part {
            if i > 1 {
                if let Some(&origin) = self.open_parts.get(&key) {
                    self.pieces.entry(origin).or_default().push(at);
                    if i >= n {
                        self.open_parts.remove(&key);
                    }
                    return;
                }
            }
            if i < n {
                self.open_parts.insert(key, at);
            }
        }
        self.visible
            .entry(row.session_id.clone())
            .or_default()
            .push(at);
        if !reference.is_empty() {
            self.activity_refs.insert(at, reference.to_owned());
        }
    }

    fn activity(&self, at: usize) -> Vec<usize> {
        let mut rows = vec![at];
        if let Some(parts) = self.pieces.get(&at) {
            rows.extend(parts);
        }
        if let Some(reference) = self.activity_refs.get(&at) {
            if let Some(outcomes) = self
                .outcomes
                .get(&(self.rows[at].session_id.clone(), reference.clone()))
            {
                rows.extend(outcomes);
            }
        }
        rows
    }

    fn index_request(&mut self, row: &SessionRow, at: usize) {
        if !["approval", "question", "resolved"]
            .iter()
            .any(|kind| row.body.contains(kind))
        {
            return;
        }
        let Ok(body) = serde_json::from_str::<serde_json::Value>(&row.body) else {
            return;
        };
        let kind = body["kind"].as_str().unwrap_or_default();
        if !matches!(kind, "approval" | "question" | "resolved") {
            return;
        }
        let reference = body["ref"].as_str().unwrap_or_default();
        if reference.is_empty() {
            return;
        }
        let key = (row.session_id.clone(), reference.to_owned());
        let authored = (row.session_id.clone(), row.author, reference.to_owned());
        let positions = self.requests.entry(key).or_default();
        positions.push(at);
        let pending = self.pending.entry(row.session_id.clone()).or_default();
        if kind == "resolved" {
            self.resolved.insert(authored);
            pending.retain(|old| !positions.contains(old) || self.rows[*old].author != row.author);
        } else if body["answerable"].as_bool() != Some(false) && !self.resolved.contains(&authored)
        {
            pending.push(at);
        }
    }

    /// Keep only the rows `keep` says to, in their order.
    pub fn retain(&mut self, keep: impl FnMut(&SessionRow) -> bool) {
        let mut rows = std::mem::take(&mut self.rows);
        rows.retain(keep);
        *self = Self::of(rows);
    }

    /// Every row, in order.
    #[must_use]
    pub fn rows(&self) -> &[SessionRow] {
        &self.rows
    }

    /// How many rows there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The rows announcing a file out of a Session, in order.
    pub fn files_out(&self) -> impl Iterator<Item = &SessionRow> {
        self.files_out.iter().map(|&at| &self.rows[at])
    }

    /// The positions `which` names, in order.
    fn positions(&self, which: &SessionFilter) -> &[usize] {
        match which {
            SessionFilter::All => &self.all,
            SessionFilter::FilesOut => &self.files_out,
            SessionFilter::Pending(id) => self.pending.get(id).map_or(&[], Vec::as_slice),
            SessionFilter::Request {
                session_id,
                reference,
            } => self
                .requests
                .get(&(session_id.clone(), reference.clone()))
                .map_or(&[], Vec::as_slice),
            SessionFilter::Session(id) | SessionFilter::SessionRaw(id) => {
                let index = if matches!(which, SessionFilter::Session(_)) {
                    &self.visible
                } else {
                    &self.by_session
                };
                if let Some(p) = index.get(id) {
                    return p;
                }
                let id = id.trim();
                if id.chars().count() < 8 {
                    return &[];
                }
                let mut found = index.iter().filter(|(k, _)| k.starts_with(id));
                match (found.next(), found.next()) {
                    (Some((_, p)), None) => p,
                    _ => &[],
                }
            }
        }
    }

    /// The newest rows of `which` before the entry `before` (the newest of all when `None`): at
    /// most `max_rows` of them and `max_bytes` of body and id, and at least one while any are
    /// older. Its cost is the page's, not the history's.
    ///
    /// # Errors
    /// `before` is not among `which`'s rows.
    pub fn page(
        &self,
        which: &SessionFilter,
        before: Option<Digest32>,
        max_rows: usize,
        max_bytes: usize,
    ) -> std::result::Result<SessionPage, String> {
        let positions = self.positions(which);
        let end = match before {
            None => positions.len(),
            Some(h) => self
                .at
                .get(&h)
                .and_then(|at| positions.binary_search(at).ok())
                .ok_or_else(|| "cursor not among these Session entries".to_owned())?,
        };
        let visible = matches!(which, SessionFilter::Session(_));
        let mut start = end;
        let mut bytes = 0usize;
        let mut groups = Vec::new();
        while start > 0 {
            let at = positions[start - 1];
            let group = if visible { self.activity(at) } else { vec![at] };
            let cost = group.iter().fold(0usize, |sum, &p| {
                sum.saturating_add(self.rows[p].body.len() + self.rows[p].session_id.len())
            });
            if start < end && (end - start >= max_rows || bytes.saturating_add(cost) > max_bytes) {
                break;
            }
            bytes = bytes.saturating_add(cost);
            groups.push(group);
            start -= 1;
        }
        let mut seen = std::collections::HashSet::new();
        let rows = groups
            .into_iter()
            .rev()
            .flatten()
            .filter(|p| seen.insert(*p))
            .map(|p| self.rows[p].clone())
            .collect();
        Ok(SessionPage {
            rows,
            older: start as u64,
        })
    }
}

/// Whether `row` announces a file out of its Session (ADR-029 DR-1.8, #546): what a member with
/// drive pulls by itself.
#[must_use]
pub fn is_file_out(row: &SessionRow) -> bool {
    // Most of a Session is not files: those are passed over without parsing them.
    row.body.contains(r#""file""#)
        && serde_json::from_str::<serde_json::Value>(&row.body)
            .is_ok_and(|v| v["kind"] == "file" && v["dir"] == "out")
}

impl DriveState {
    pub(crate) fn floor_mark(&self, member: &Digest32) -> Option<(u64, u64)> {
        self.marks.get(member).copied()
    }

    /// Make `chain` this node's live drive generation, marking every member of `holders` owed it
    /// from its first entry.
    pub fn begin(&mut self, chain: SenderChain, holders: impl IntoIterator<Item = Digest32>) {
        let (_, origin) = chain.current_position();
        let live = chain.chain_id();
        self.marks = holders.into_iter().map(|m| (m, (live, 0))).collect();
        self.origin = Some(origin);
        self.chain = Some(chain);
    }

    /// The members owed this node's live drive key: each of `members` (the room's, this node
    /// excepted) that `drive` names and that has not been released the live generation. A member
    /// owed it for the first time is marked owed from the chain's position now.
    pub fn take_owed(
        &mut self,
        members: &BTreeSet<Digest32>,
        drive: &BTreeSet<Digest32>,
    ) -> Vec<Digest32> {
        let Some(chain) = &self.chain else {
            return Vec::new();
        };
        let (live, now) = (chain.chain_id(), chain.next_iteration());
        let owed: Vec<Digest32> = members
            .iter()
            .filter(|m| drive.contains(*m))
            .filter(|m| self.delivered.get(*m) != Some(&live))
            .copied()
            .collect();
        for m in &owed {
            let mark = self.marks.entry(*m).or_insert((live, now));
            if mark.0 != live {
                *mark = (live, now);
            }
        }
        owed
    }

    /// The SKDM releasing the live drive key to `member` from its mark, and the generation it
    /// releases.
    pub fn release_for(&self, signer: &dyn RootSigner, member: &Digest32) -> Result<(Skdm, u64)> {
        let (Some(chain), Some(origin)) = (&self.chain, &self.origin) else {
            return Err(Error::Profile("this node has no drive key in the room"));
        };
        let live = chain.chain_id();
        let from = match self.marks.get(member) {
            Some((g, i)) if *g == live => *i,
            _ => chain.next_iteration(),
        };
        let mut key = origin.clone();
        for _ in 0..from {
            key = key.advance()?;
        }
        Ok((chain.skdm_for(signer, from, key)?, live))
    }

    /// Record that `member` holds generation `generation`.
    pub fn note_delivered(&mut self, member: Digest32, generation: u64) {
        self.delivered.insert(member, generation);
    }

    /// Forget `members` as holders of this node's drive key: they lost drive, and the key that
    /// replaces it is not theirs (SC-2b).
    pub fn forget(&mut self, members: &[Digest32]) {
        for m in members {
            self.delivered.remove(m);
            self.marks.remove(m);
        }
    }

    /// The members released this node's drive key that `drive` no longer names: each one is why
    /// the key must change (SC-2b).
    #[must_use]
    pub fn lost(&self, drive: &BTreeSet<Digest32>) -> Vec<Digest32> {
        self.delivered
            .keys()
            .filter(|m| !drive.contains(*m))
            .copied()
            .collect()
    }

    /// Whether this node holds any drive key of `author`'s.
    #[must_use]
    pub fn holds_from(&self, author: &Digest32) -> bool {
        self.receivers.keys().any(|(a, _)| a == author)
    }

    /// The sealed state: `[version, chain state or empty, origin key or empty, [receiver state,
    /// …], [[member, generation], …], [[member, generation, iteration], …]]`. Secret-bearing, so
    /// the buffer zeroizes on drop.
    #[must_use]
    pub fn to_state(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Encoder::for_secrets();
        e.array(6).uint(DRIVE_VERSION);
        match &self.chain {
            Some(c) => e.bytes(&c.to_state()),
            None => e.bytes(&[]),
        };
        match &self.origin {
            Some(o) => e.bytes(o.bytes()),
            None => e.bytes(&[]),
        };
        e.array(self.receivers.len());
        for r in self.receivers.values() {
            e.bytes(&r.to_state());
        }
        e.array(self.delivered.len());
        for (m, g) in &self.delivered {
            e.array(2).bytes(m).uint(*g);
        }
        e.array(self.marks.len());
        for (m, (g, i)) in &self.marks {
            e.array(3).bytes(m).uint(*g).uint(*i);
        }
        Zeroizing::new(e.finish())
    }

    /// Strict decode of [`Self::to_state`]. The Session rows come from the plaintext cache.
    pub fn from_state(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 6 || d.uint()? != DRIVE_VERSION {
            return Err(Error::MalformedAtRest("drive state version"));
        }
        let chain = match d.bytes()? {
            [] => None,
            state => Some(SenderChain::from_state(state)?),
        };
        let origin = match d.bytes()? {
            [] => None,
            key => Some(ChainKey::from_bytes(
                key.try_into()
                    .map_err(|_| Error::MalformedAtRest("drive origin key"))?,
            )),
        };
        let n = d.array()?;
        if n > MAX_DRIVE_CHAINS {
            return Err(Error::SizeLimitExceeded("room drive keys"));
        }
        let mut receivers = BTreeMap::new();
        for _ in 0..n {
            let r = ReceiverChain::from_state(d.bytes()?)?;
            receivers.insert((r.author_id(), r.chain_id()), r);
        }
        let n = d.array()?;
        let mut delivered = BTreeMap::new();
        for _ in 0..n {
            if d.array()? != 2 {
                return Err(Error::MalformedAtRest("drive ledger row"));
            }
            let m: Digest32 = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedAtRest("drive ledger member"))?;
            delivered.insert(m, d.uint()?);
        }
        let n = d.array()?;
        let mut marks = BTreeMap::new();
        for _ in 0..n {
            if d.array()? != 3 {
                return Err(Error::MalformedAtRest("drive mark row"));
            }
            let m: Digest32 = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedAtRest("drive mark member"))?;
            marks.insert(m, (d.uint()?, d.uint()?));
        }
        d.finish()?;
        Ok(Self {
            chain,
            origin,
            marks,
            floors: BTreeMap::new(),
            floors_indexed: false,
            omitted: BTreeMap::new(),
            receivers,
            delivered,
            sessions: SessionLog::default(),
            pending: Vec::new(),
            news: Vec::new(),
            change_unsaid: None,
            told_unheld: std::collections::HashSet::new(),
        })
    }
}
