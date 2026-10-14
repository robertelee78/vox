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

/// The sequence range committed by one atomic admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Committed {
    /// First sequence in the batch.
    pub first: u64,
    /// Last sequence in the batch.
    pub last: u64,
}

/// A failed admission distinguishes a transaction never submitted from an uncertain commit.
#[derive(Debug)]
pub enum AdmissionError {
    /// Preparation failed; none of this batch was committed.
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

#[derive(Default, Serialize, Deserialize)]
struct Directory {
    bytes: u64,
    active: Vec<Digest32>,
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

fn bad() -> Error {
    Error::MalformedAtRest("Session ingress record")
}

fn scope(profile: &Profile, session: &str) -> Digest32 {
    let mut bytes = b"vox/session-ingress-scope/v1".to_vec();
    bytes.extend_from_slice(&profile.fingerprint());
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
    if d.active.len() > MAX_PENDING_SESSIONS
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

/// Validate, number and commit an entire batch. No sequence or body is accepted on error.
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
    let mut session = session_in(&batch, &key, &scope, name)?;
    if session.head == session.next {
        if directory.active.contains(&scope) {
            return Err(bad().into());
        }
        if directory.active.len() == MAX_PENDING_SESSIONS {
            return Err(Error::SizeLimitExceeded("pending Session inboxes").into());
        }
        directory.active.push(scope);
    } else if !directory.active.contains(&scope) {
        return Err(bad().into());
    }
    let first = session.next;
    for body in bodies {
        let serde_json::Value::Object(mut object) =
            serde_json::from_str(&body).map_err(|_| bad())?
        else {
            return Err(Error::Profile("Session activity must be a JSON object").into());
        };
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
        session.next = session
            .next
            .checked_add(1)
            .ok_or(Error::SizeLimitExceeded("Session sequence"))?;
    }
    put(&mut batch, &key, &scope, HEADER, &session)?;
    put(&mut batch, &key, &node, HEADER, &directory)?;
    batch.commit().map_err(AdmissionError::Unconfirmed)?;
    Ok(Committed {
        first,
        last: session.next - 1,
    })
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

/// Erase accepted pending bodies for a room the operator explicitly deletes. Other rooms and
/// every session's next sequence survive. The inbox is capped at 64 MiB; this transaction
/// visits one sealed item at a time and keeps only its at-most-256 scheduling directory.
pub(crate) fn purge_room(profile: &Profile, room: &Digest32) -> Result<()> {
    let key = key(profile)?;
    let node = profile.fingerprint();
    let mut batch = profile.store().batch()?;
    let mut d = directory(&batch, &key, &node)?;
    for scope in d.active.clone() {
        let segment = batch
            .get_segment(&scope, SegmentKind::SessionIngress, HEADER)?
            .ok_or(bad())?;
        let mut session: Session = decode(&key, &scope, HEADER, &segment)?;
        if session.head == 0
            || session.head >= session.next
            || scope != self::scope(profile, &session.name)
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
            let item: Item = decode(&key, &scope, id, &segment)?;
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
        put(&mut batch, &key, &scope, HEADER, &session)?;
    }
    put(&mut batch, &key, &node, HEADER, &d)?;
    batch.commit()
}
