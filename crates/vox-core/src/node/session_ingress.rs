//! Numbered Session activity accepted by this node, before its room can append it.
//!
//! The inbox shares the profile's transaction domain. Its key comes from the unlocked
//! identity, so joining a room need not finish before activity is saved. Completing one
//! item is part of the private Session record/ratchet transaction, never a second write.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::atrest::sek::Sek;
use crate::atrest::store::{open_segment, seal_segment, SegmentKind};
use crate::error::{Error, Result};
use crate::hash::{sha256, Digest32};
use crate::node::profile::Profile;
use crate::node::store::{Batch, Snapshot};

/// One admission is bounded independently of the retained backlog.
pub const MAX_BATCH_BYTES: usize = 128 * 1024;
/// Maximum body count in one admission, including empty activity objects.
pub const MAX_BATCH_ITEMS: usize = 512;
/// Pending work, not retained Session history. Filled inboxes refuse further acceptance.
const MAX_PENDING_BYTES: u64 = 64 * 1024 * 1024;
/// Only sessions with pending work occupy the bounded scheduling directory.
const MAX_PENDING_SESSIONS: usize = 256;
const HEADER: u64 = 0;

/// Inclusive bounds of the durable sequences covered by one atomic admission.
/// A repeated source event names its original sequence rather than allocating another.
/// Both bounds are zero when the whole admission deliberately suppressed driver echoes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Committed {
    /// Lowest durable sequence covered by the batch.
    pub first: u64,
    /// Highest durable sequence covered by the batch.
    pub last: u64,
    /// This admission began a new source activity (or stored an unkeyed activity).
    /// Continuing an already admitted split source does not repeat its control effects.
    pub fresh: bool,
}

/// A failed admission distinguishes a transaction never submitted from an uncertain commit.
#[derive(Debug)]
pub enum AdmissionError {
    /// Preparation failed; this batch committed no new activity or source receipts.
    NotCommitted(Error),
    /// The commit returned an error; its durable outcome must not be guessed or retried.
    Unconfirmed(Error),
}

impl From<Error> for AdmissionError {
    fn from(error: Error) -> Self {
        Self::NotCommitted(error)
    }
}

/// Receipt for one durable batch admission.
pub type AdmissionResult = std::result::Result<Committed, AdmissionError>;

/// One exact room-deletion cleanup, distinct from a later deletion of the same room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Retirement {
    /// The explicitly removed room.
    pub room: Digest32,
    /// Monotonic serial in this node's sealed inbox directory.
    pub serial: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Directory {
    bytes: u64,
    active: Vec<Digest32>,
    /// Only explicit room deletions awaiting daemon registration cleanup.
    retiring: Vec<Retirement>,
    retirement_serial: u64,
}

#[derive(Serialize, Deserialize)]
struct Session {
    name: String,
    head: u64,
    next: u64,
}

#[derive(Serialize, Deserialize)]
struct Item {
    room: Digest32,
    body: String,
}

/// Adapter-only identity, removed before the activity becomes a Session record.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    id: Digest32,
    revision: Digest32,
    part: u64,
    parts: u64,
    #[serde(default)]
    suppressed: bool,
}

#[derive(Serialize, Deserialize)]
struct SourceReceipt {
    session: Digest32,
    room: Digest32,
    source: Digest32,
    kind: String,
    revision: Digest32,
    parts: u64,
    next: u64,
    first: u64,
    last: u64,
    suppressed: bool,
}

#[derive(Serialize, Deserialize)]
struct SourcePart {
    revision: Digest32,
    parts: u64,
    digest: Digest32,
    seq: u64,
}

fn source_scope(session: &Digest32, room: &Digest32, id: &Digest32, kind: &str) -> Digest32 {
    let mut bytes = b"vox/session-ingress-source/v1".to_vec();
    bytes.extend_from_slice(session);
    bytes.extend_from_slice(room);
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(kind.as_bytes());
    sha256(&bytes)
}

fn source_error() -> Error {
    Error::Profile("inconsistent Session activity source")
}

fn bad() -> Error {
    Error::MalformedAtRest("Session ingress record")
}

fn scope(profile: &Profile, session: &str) -> Digest32 {
    scope_for(&profile.fingerprint(), session)
}

fn scope_for(node: &Digest32, session: &str) -> Digest32 {
    let mut bytes = b"vox/session-ingress-scope/v1".to_vec();
    bytes.extend_from_slice(node);
    bytes.extend_from_slice(session.as_bytes());
    sha256(&bytes)
}

fn key(profile: &Profile) -> Result<Sek> {
    crate::atrest::seal::sek(profile.signer()?, b"vox/session-ingress-sek/v1")
}

// The encrypted body binds its namespace as well as the kind and id in the segment AAD.
// Moving a valid encrypted header/item between session namespaces must fail closed.
fn encode<T: Serialize>(scope: &Digest32, value: &T) -> Result<Zeroizing<Vec<u8>>> {
    serde_json::to_vec(&(1u8, scope, value))
        .map(Zeroizing::new)
        .map_err(|_| bad())
}

fn decode<T: serde::de::DeserializeOwned>(
    key: &Sek,
    scope: &Digest32,
    id: u64,
    segment: &crate::atrest::store::SealedSegment,
) -> Result<T> {
    if segment.ciphertext.len() > MAX_BATCH_BYTES + 32768 {
        return Err(bad());
    }
    let bytes = open_segment(key, SegmentKind::SessionIngress, id, segment)?;
    let (version, bound, value): (u8, Digest32, T) =
        serde_json::from_slice(&bytes).map_err(|_| bad())?;
    if version != 1 || bound != *scope {
        return Err(bad());
    }
    Ok(value)
}

fn put<T: Serialize>(
    batch: &mut Batch<'_>,
    key: &Sek,
    scope: &Digest32,
    id: u64,
    value: &T,
) -> Result<()> {
    let segment = seal_segment(key, SegmentKind::SessionIngress, id, &encode(scope, value)?)?;
    batch.put_segment(scope, SegmentKind::SessionIngress, id, &segment)
}

fn directory(batch: &Batch<'_>, key: &Sek, node: &Digest32) -> Result<Directory> {
    let d = match batch.get_segment(node, SegmentKind::SessionIngress, HEADER)? {
        Some(segment) => decode(key, node, HEADER, &segment)?,
        None => Directory::default(),
    };
    check_directory(&d)?;
    Ok(d)
}

fn check_directory(d: &Directory) -> Result<()> {
    if d.retiring.len() > 2
        || d.retiring.iter().enumerate().any(|(i, item)| {
            item.serial == 0
                || item.serial > d.retirement_serial
                || d.retiring[..i]
                    .iter()
                    .any(|old| old.room == item.room || old.serial == item.serial)
        })
        || d.active.len() > MAX_PENDING_SESSIONS
        || d.bytes > MAX_PENDING_BYTES
        || d.active
            .iter()
            .enumerate()
            .any(|(i, id)| d.active[..i].contains(id))
    {
        return Err(bad());
    }
    Ok(())
}

fn session_in(batch: &Batch<'_>, key: &Sek, scope: &Digest32, name: &str) -> Result<Session> {
    let s = match batch.get_segment(scope, SegmentKind::SessionIngress, HEADER)? {
        Some(segment) => decode(key, scope, HEADER, &segment)?,
        None => Session {
            name: name.to_owned(),
            head: 1,
            next: 1,
        },
    };
    if s.name != name || s.head == 0 || s.head > s.next {
        return Err(bad());
    }
    Ok(s)
}

/// Validate, number and commit an entire batch. Preparation errors accept no new sequence
/// or body; source receipts committed by earlier calls remain authoritative.
pub fn admit(
    profile: &Profile,
    room: Digest32,
    name: &str,
    bodies: Vec<String>,
) -> AdmissionResult {
    if name.is_empty()
        || name.len() > crate::node::content::MAX_SESSION_ID_LEN
        || bodies.is_empty()
        || bodies.len() > MAX_BATCH_ITEMS
        || bodies
            .iter()
            .try_fold(0usize, |n, b| n.checked_add(b.len()))
            .is_none_or(|n| n > MAX_BATCH_BYTES)
    {
        return Err(Error::SizeLimitExceeded("Session ingress batch").into());
    }
    let key = key(profile)?;
    let node = profile.fingerprint();
    let scope = scope(profile, name);
    let mut batch = profile.store().batch()?;
    let mut directory = directory(&batch, &key, &node)?;
    if directory.retiring.iter().any(|item| item.room == room) {
        return Err(Error::Profile("this room was removed; its Session cleanup is pending").into());
    }
    let mut session = session_in(&batch, &key, &scope, name)?;
    if directory.active.contains(&scope) != (session.head < session.next) {
        return Err(bad().into());
    }
    let mut first = u64::MAX;
    let mut last = 0;
    let before = session.next;
    let mut fresh = false;
    let mut receipts_changed = false;
    for body in bodies {
        let serde_json::Value::Object(mut object) =
            serde_json::from_str(&body).map_err(|_| bad())?
        else {
            return Err(Error::Profile("Session activity must be a JSON object").into());
        };
        let source = object
            .remove("_vox_source")
            .map(|value| serde_json::from_value::<Source>(value).map_err(|_| source_error()))
            .transpose()?;
        let mut source_write = None;
        if let Some(source) = source {
            let kind = object
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .filter(|kind| matches!(*kind, "user" | "tool" | "tool-done"))
                .ok_or_else(source_error)?;
            if (source.suppressed && kind != "user")
                || source.part == 0
                || source.parts == 0
                || source.part > source.parts
                || source.parts > MAX_BATCH_ITEMS as u64
            {
                return Err(source_error().into());
            }
            let coordinates = object.get("part").and_then(serde_json::Value::as_array);
            if match coordinates {
                Some(part) => {
                    part.len() != 2
                        || part[0].as_u64() != Some(source.part)
                        || part[1].as_u64() != Some(source.parts)
                }
                None => source.part != 1 || source.parts != 1 || object.contains_key("part"),
            } {
                return Err(source_error().into());
            }
            let source_scope = source_scope(&scope, &room, &source.id, kind);
            let saved = batch
                .get_segment(&source_scope, SegmentKind::SessionIngress, HEADER)?
                .map(|segment| decode::<SourceReceipt>(&key, &source_scope, HEADER, &segment))
                .transpose()?;
            let mut receipt = match saved {
                Some(receipt) => {
                    if receipt.session != scope
                        || receipt.room != room
                        || receipt.source != source.id
                        || receipt.kind != kind
                        || receipt.parts == 0
                        || receipt.parts > MAX_BATCH_ITEMS as u64
                        || receipt.next < 2
                        || receipt.next > receipt.parts + 1
                        || if receipt.suppressed {
                            receipt.first != 0
                                || receipt.last != 0
                                || receipt.next != receipt.parts + 1
                        } else {
                            receipt.first == 0
                                || receipt.first > receipt.last
                                || receipt.last >= session.next
                        }
                    {
                        return Err(bad().into());
                    }
                    // Like the adapter's old exact started/finished sets, the first version
                    // of a source event wins. An updated tool input is not another start.
                    if receipt.revision != source.revision {
                        if receipt.next != receipt.parts + 1 {
                            return Err(source_error().into());
                        }
                        if !receipt.suppressed {
                            first = first.min(receipt.first);
                            last = last.max(receipt.last);
                        }
                        continue;
                    }
                    if receipt.parts != source.parts {
                        return Err(source_error().into());
                    }
                    if receipt.suppressed {
                        continue;
                    }
                    receipt
                }
                None => {
                    if source.part != 1 {
                        return Err(source_error().into());
                    }
                    SourceReceipt {
                        session: scope,
                        room,
                        source: source.id,
                        kind: kind.to_owned(),
                        revision: source.revision,
                        parts: source.parts,
                        next: 1,
                        first: session.next,
                        last: session.next,
                        suppressed: false,
                    }
                }
            };
            // A driver echo is deliberately absent from shared history, but its exact
            // identity still survives restart so a late duplicate cannot escape suppression.
            if source.suppressed && receipt.next == 1 {
                receipt.suppressed = true;
                receipt.first = 0;
                receipt.last = 0;
                receipt.next = receipt.parts + 1;
                put(&mut batch, &key, &source_scope, HEADER, &receipt)?;
                receipts_changed = true;
                fresh = true;
                continue;
            }
            // Timestamp is observation time, not source identity. Everything else in this
            // exact split part must agree when an adapter repeats the same source revision.
            let mut canonical = object.clone();
            canonical.remove("ts");
            canonical.remove("seq");
            canonical.remove("session");
            let digest = sha256(serde_json::Value::Object(canonical).to_string().as_bytes());
            if let Some(segment) =
                batch.get_segment(&source_scope, SegmentKind::SessionIngress, source.part)?
            {
                let part: SourcePart = decode(&key, &source_scope, source.part, &segment)?;
                if part.revision != source.revision
                    || part.parts != source.parts
                    || part.seq < receipt.first
                    || part.seq > receipt.last
                    || source.part >= receipt.next
                {
                    return Err(bad().into());
                }
                if part.digest != digest {
                    return Err(source_error().into());
                }
                first = first.min(part.seq);
                last = last.max(part.seq);
                continue;
            }
            if source.part != receipt.next {
                return Err(source_error().into());
            }
            receipt.next += 1;
            receipt.last = session.next;
            source_write = Some((
                source_scope,
                receipt,
                source.part,
                SourcePart {
                    revision: source.revision,
                    parts: source.parts,
                    digest,
                    seq: session.next,
                },
            ));
        }
        // A duplicate needs no scheduling slot or pending bytes, even when the inbox is full.
        if session.head == session.next {
            if directory.active.len() == MAX_PENDING_SESSIONS {
                return Err(Error::SizeLimitExceeded("pending Session inboxes").into());
            }
            directory.active.push(scope);
        }
        object.insert("seq".into(), session.next.into());
        object.insert("session".into(), name.into());
        let body = serde_json::Value::Object(object).to_string();
        // Refuse before accepting something the real private Session append cannot carry.
        crate::node::content::SessionEntry::new(0, name, &body)?;
        let segment = seal_segment(
            &key,
            SegmentKind::SessionIngress,
            session.next,
            &encode(&scope, &Item { room, body })?,
        )?;
        // Charge the encoded payload and conservative key/nonce/row overhead, not just text.
        let charge = segment.ciphertext.len() as u64 + 128;
        directory.bytes = directory.bytes.checked_add(charge).ok_or(bad())?;
        if directory.bytes > MAX_PENDING_BYTES {
            return Err(Error::SizeLimitExceeded("pending Session activity").into());
        }
        batch.put_segment(&scope, SegmentKind::SessionIngress, session.next, &segment)?;
        fresh |= source_write
            .as_ref()
            .is_none_or(|(_, _, part, _)| *part == 1);
        if let Some((source_scope, receipt, part, part_receipt)) = source_write {
            put(&mut batch, &key, &source_scope, part, &part_receipt)?;
            put(&mut batch, &key, &source_scope, HEADER, &receipt)?;
        }
        first = first.min(session.next);
        last = last.max(session.next);
        session.next = session
            .next
            .checked_add(1)
            .ok_or(Error::SizeLimitExceeded("Session sequence"))?;
    }
    if first == u64::MAX {
        first = 0;
    }
    let bodies_changed = session.next != before;
    if !bodies_changed && !receipts_changed {
        return Ok(Committed { first, last, fresh });
    }
    if bodies_changed {
        put(&mut batch, &key, &scope, HEADER, &session)?;
        put(&mut batch, &key, &node, HEADER, &directory)?;
    }
    batch.commit().map_err(AdmissionError::Unconfirmed)?;
    Ok(Committed { first, last, fresh })
}

/// One owned item, bounded by the admission limit. Its completion is never committed alone.
pub struct Pending {
    /// Destination captured at admission; never retargeted after a session moves.
    pub room: Digest32,
    /// Harness session identity.
    pub session: String,
    /// The exact numbered body accepted earlier.
    pub body: String,
    /// Atomic inbox completion for the private Session transaction.
    pub completion: Completion,
}

/// Prepared identity-sealed completion. Only the matching first pending sequence may advance.
pub struct Completion {
    key: Sek,
    node: Digest32,
    scope: Digest32,
    seq: u64,
    bytes: u64,
}

impl Completion {
    pub(crate) fn queue(&self, batch: &mut Batch<'_>) -> Result<()> {
        let mut d = directory(batch, &self.key, &self.node)?;
        let segment = batch
            .get_segment(&self.scope, SegmentKind::SessionIngress, HEADER)?
            .ok_or(bad())?;
        let mut s: Session = decode(&self.key, &self.scope, HEADER, &segment)?;
        if s.head != self.seq || s.head >= s.next || !d.active.contains(&self.scope) {
            return Err(bad());
        }
        if !batch.delete_segment(&self.scope, SegmentKind::SessionIngress, self.seq)? {
            return Err(bad());
        }
        // Explicit room deletion can remove interior entries belonging to an old room.
        // Sequence numbers are never reused: advance to the next retained row, or next.
        s.head = batch
            .segment_after(&self.scope, SegmentKind::SessionIngress, Some(self.seq))?
            .map_or(s.next, |(id, _)| id);
        if s.head <= self.seq || s.head > s.next {
            return Err(bad());
        }
        d.bytes = d.bytes.checked_sub(self.bytes).ok_or(bad())?;
        if s.head == s.next {
            d.active.retain(|id| *id != self.scope);
        }
        put(batch, &self.key, &self.scope, HEADER, &s)?;
        put(batch, &self.key, &self.node, HEADER, &d)
    }
}

fn from_snapshot(snapshot: &Snapshot, key: &Sek, node: &Digest32) -> Result<Directory> {
    let d = match snapshot.get_segment(node, SegmentKind::SessionIngress, HEADER)? {
        Some(segment) => decode(key, node, HEADER, &segment)?,
        None => Directory::default(),
    };
    check_directory(&d)?;
    Ok(d)
}

/// Read one session's head using one snapshot. Round-robin selection avoids an unopened room
/// blocking other sessions, and never loads a whole backlog after restart.
pub fn pending(profile: &Profile, cursor: &mut usize) -> Result<Option<Pending>> {
    let key = key(profile)?;
    let node = profile.fingerprint();
    let snapshot = profile.store().snapshot()?;
    let d = from_snapshot(&snapshot, &key, &node)?;
    if d.active.is_empty() {
        *cursor = 0;
        return Ok(None);
    }
    let scope = d.active[*cursor % d.active.len()];
    *cursor = (*cursor % d.active.len()) + 1;
    let segment = snapshot
        .get_segment(&scope, SegmentKind::SessionIngress, HEADER)?
        .ok_or(bad())?;
    let s: Session = decode(&key, &scope, HEADER, &segment)?;
    if s.head == 0 || s.head >= s.next || scope != self::scope(profile, &s.name) {
        return Err(bad());
    }
    let segment = snapshot
        .get_segment(&scope, SegmentKind::SessionIngress, s.head)?
        .ok_or(bad())?;
    let item: Item = decode(&key, &scope, s.head, &segment)?;
    if item.body.len() > MAX_BATCH_BYTES + 8192 {
        return Err(bad());
    }
    let bytes = segment.ciphertext.len() as u64 + 128;
    Ok(Some(Pending {
        room: item.room,
        session: s.name,
        body: item.body,
        completion: Completion {
            key,
            node,
            scope,
            seq: s.head,
            bytes,
        },
    }))
}

// Other rooms and every session's next sequence survive. The inbox is capped at 64 MiB;
// visits retain one sealed item and the at-most-256 scheduling directory.
fn purge_pending(
    node: &Digest32,
    key: &Sek,
    batch: &mut Batch<'_>,
    d: &mut Directory,
    room: &Digest32,
) -> Result<()> {
    for scope in d.active.clone() {
        let segment = batch
            .get_segment(&scope, SegmentKind::SessionIngress, HEADER)?
            .ok_or(bad())?;
        let mut session: Session = decode(key, &scope, HEADER, &segment)?;
        if session.head == 0
            || session.head >= session.next
            || scope != scope_for(node, &session.name)
        {
            return Err(bad());
        }
        let mut after = Some(HEADER);
        let mut first = None;
        while let Some((id, segment)) =
            batch.segment_after(&scope, SegmentKind::SessionIngress, after)?
        {
            if id < session.head || id >= session.next {
                return Err(bad());
            }
            let item: Item = decode(key, &scope, id, &segment)?;
            if item.room == *room {
                if !batch.delete_segment(&scope, SegmentKind::SessionIngress, id)? {
                    return Err(bad());
                }
                d.bytes = d
                    .bytes
                    .checked_sub(segment.ciphertext.len() as u64 + 128)
                    .ok_or(bad())?;
            } else if first.is_none() {
                first = Some(id);
            }
            after = Some(id);
        }
        session.head = first.unwrap_or(session.next);
        if session.head == session.next {
            d.active.retain(|id| *id != scope);
        }
        put(batch, key, &scope, HEADER, &session)?;
    }
    Ok(())
}

/// Queue explicit deletion and its outstanding owner cleanup in the caller's admitted batch.
/// Reopen-map, consent and pending-lock removals join this same transaction.
pub(crate) fn queue_remove_room(
    batch: &mut Batch<'_>,
    signer: &dyn crate::identity::composite::RootSigner,
    room: &Digest32,
    hosted: bool,
) -> Result<Option<Retirement>> {
    let key = crate::atrest::seal::sek(signer, b"vox/session-ingress-sek/v1")?;
    let node = signer.fingerprint();
    let mut d = directory(batch, &key, &node)?;
    let retirement = if hosted {
        if d.retiring.len() == 2 || d.retiring.iter().any(|item| item.room == *room) {
            return Err(Error::Profile("earlier Session room cleanup is pending"));
        }
        d.retirement_serial = d
            .retirement_serial
            .checked_add(1)
            .ok_or(Error::SizeLimitExceeded("Session room retirement serial"))?;
        let retirement = Retirement {
            room: *room,
            serial: d.retirement_serial,
        };
        d.retiring.push(retirement);
        Some(retirement)
    } else {
        None
    };
    purge_pending(&node, &key, batch, &mut d, room)?;
    batch.purge_channel(room)?;
    put(batch, &key, &node, HEADER, &d)?;
    Ok(retirement)
}

/// Resume the at-most-two outstanding owner cleanups after unlock/restart.
pub(crate) fn retirements(profile: &Profile) -> Result<Vec<Retirement>> {
    let snapshot = profile.store().snapshot()?;
    Ok(from_snapshot(&snapshot, &key(profile)?, &profile.fingerprint())?.retiring)
}

/// The daemon already cleared matching registration bindings and volatile tails. Preserve
/// the durable marker on every failure; ending the actor alone never completes retirement.
pub(crate) fn complete_retirement(profile: &Profile, retirement: Retirement) -> Result<()> {
    let key = key(profile)?;
    let node = profile.fingerprint();
    let mut batch = profile.store().batch()?;
    let mut d = directory(&batch, &key, &node)?;
    // A lost receipt can be retried after a rejoin and even another deletion. Only this
    // exact recorded retirement may remove work; an older completion is a read-only no-op.
    if !d.retiring.contains(&retirement) {
        return Ok(());
    }
    purge_pending(&node, &key, &mut batch, &mut d, &retirement.room)?;
    d.retiring.retain(|item| *item != retirement);
    put(&mut batch, &key, &node, HEADER, &d)?;
    batch.commit()
}
