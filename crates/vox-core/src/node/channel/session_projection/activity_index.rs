//! Fixed-size facts for ordinary private activity. The original authenticated row
//! stays in PrivateSession; these sealed locators never retain its body or parts.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256_concat, Digest32};
use crate::node::drive::SessionRow;

use super::record::Key;
use super::storage::{Read, Tree, Write};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Other,
    Approval,
    Question,
    Resolved,
    ToolDone,
    Drive,
    DriveResult,
}

#[derive(Clone)]
pub(super) struct Fact {
    pub arrival: u64,
    pub hash: Digest32,
    pub author: Digest32,
    pub session: String,
    pub created: u64,
    pub sequence: u64,
    pub kind: Kind,
    /// Absent for malformed/non-object JSON; raw listings still retain that row.
    pub part_group: Option<Digest32>,
    pub reference: Option<Digest32>,
    pub part: Option<(u64, u64)>,
    pub answerable: bool,
    pub direct_action: bool,
    pub succeeded: bool,
    pub bytes: u64,
    pub file_out: bool,
}

pub(super) fn group(session: &str, author: &Digest32) -> Digest32 {
    sha256_concat(&[b"vox/session-activity/group/v1", author, session.as_bytes()])
}
pub(super) fn hash_key(hash: &Digest32) -> Key {
    let mut key = [0; 64];
    key[..32].copy_from_slice(hash);
    key
}
pub(super) fn arrival_key(id: u64) -> Key {
    let mut key = [0; 64];
    key[..8].copy_from_slice(&id.to_be_bytes());
    key
}
pub(super) fn member_key(group: &Digest32, id: u64) -> Key {
    let mut key = hash_key(group);
    key[32..40].copy_from_slice(&id.to_be_bytes());
    key
}

impl Fact {
    fn of(row: &SessionRow, arrival: u64) -> Self {
        let body = serde_json::from_str::<serde_json::Value>(&row.body).ok();
        let object = body.as_ref().and_then(serde_json::Value::as_object);
        let text = |name: &str| {
            object
                .and_then(|b| b.get(name))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
        };
        let kind = text("kind");
        let reference_text = object
            .and_then(|b| b.get("ref"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| match kind {
                "drive" => text("id"),
                "drive-result" => text("of"),
                _ => "",
            });
        let reference = (!reference_text.is_empty()).then(|| {
            sha256_concat(&[
                b"vox/session-activity/ref/v1",
                &(row.session_id.len() as u64).to_be_bytes(),
                row.session_id.as_bytes(),
                reference_text.as_bytes(),
            ])
        });
        // Length prefixes keep unlike (session, kind, ref) tuples distinct. No
        // member-written kind/reference string is copied into a descriptor.
        let part_group = object.map(|_| {
            sha256_concat(&[
                b"vox/session-activity/parts/v1",
                &row.author,
                &(row.session_id.len() as u64).to_be_bytes(),
                row.session_id.as_bytes(),
                &(kind.len() as u64).to_be_bytes(),
                kind.as_bytes(),
                reference_text.as_bytes(),
            ])
        });
        let part = object
            .and_then(|b| b.get("part"))
            .and_then(serde_json::Value::as_array)
            .and_then(|p| Some((p.first()?.as_u64()?, p.get(1)?.as_u64()?)));
        Self {
            arrival,
            hash: row.entry_hash,
            author: row.author,
            session: row.session_id.clone(),
            created: row.created_millis,
            sequence: object
                .and_then(|b| b.get("seq"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            kind: match kind {
                "approval" => Kind::Approval,
                "question" => Kind::Question,
                "resolved" => Kind::Resolved,
                "tool-done" => Kind::ToolDone,
                "drive" => Kind::Drive,
                "drive-result" => Kind::DriveResult,
                _ => Kind::Other,
            },
            part_group,
            reference,
            part,
            answerable: object
                .and_then(|b| b.get("answerable"))
                .and_then(serde_json::Value::as_bool)
                != Some(false),
            direct_action: matches!(
                text("action"),
                "text" | "interrupt" | "stop" | "slash" | "file"
            ),
            bytes: (row.body.len() as u64).saturating_add(row.session_id.len() as u64),
            file_out: kind == "file" && text("dir") == "out",
            succeeded: object
                .and_then(|b| b.get("ok"))
                .and_then(serde_json::Value::as_bool)
                == Some(true),
        }
    }
    pub fn group(&self) -> Digest32 {
        group(&self.session, &self.author)
    }
    pub fn created_key(&self) -> Key {
        let mut key = hash_key(&self.group());
        key[32..40].copy_from_slice(&self.created.to_be_bytes());
        key[40..48].copy_from_slice(&self.sequence.to_be_bytes());
        key[48..56].copy_from_slice(&self.arrival.to_be_bytes());
        key
    }
    fn bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(16)
            .uint(2)
            .uint(self.arrival)
            .bytes(&self.hash)
            .bytes(&self.author)
            .text(&self.session)
            .uint(self.created)
            .uint(self.sequence)
            .uint(self.kind as u64)
            .bytes(self.part_group.as_ref().map_or(&[][..], |h| h.as_slice()))
            .bytes(self.reference.as_ref().map_or(&[][..], |h| h.as_slice()))
            .array(usize::from(self.part.is_some()));
        if let Some((i, n)) = self.part {
            e.array(2).uint(i).uint(n);
        }
        e.uint(u64::from(self.answerable))
            .uint(u64::from(self.direct_action))
            .uint(u64::from(self.succeeded))
            .uint(self.bytes)
            .uint(u64::from(self.file_out));
        e.finish()
    }
    pub fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 16 || d.uint()? != 2 {
            return Err(Error::MalformedAtRest("Session activity fact format"));
        }
        let arrival = d.uint()?;
        let digest = |d: &mut Decoder<'_>| -> Result<Digest32> {
            d.bytes()?
                .try_into()
                .map_err(|_| Error::MalformedAtRest("Session activity digest"))
        };
        let hash = digest(&mut d)?;
        let author = digest(&mut d)?;
        let session = d.text()?;
        if session.is_empty() || session.len() > crate::node::content::MAX_SESSION_ID_LEN {
            return Err(Error::MalformedAtRest("Session activity id"));
        }
        let session = session.to_owned();
        let created = d.uint()?;
        let sequence = d.uint()?;
        let kind = match d.uint()? {
            0 => Kind::Other,
            1 => Kind::Approval,
            2 => Kind::Question,
            3 => Kind::Resolved,
            4 => Kind::ToolDone,
            5 => Kind::Drive,
            6 => Kind::DriveResult,
            _ => return Err(Error::MalformedAtRest("Session activity kind")),
        };
        let optional = |d: &mut Decoder<'_>| -> Result<Option<Digest32>> {
            match d.bytes()? {
                [] => Ok(None),
                bytes => Ok(Some(bytes.try_into().map_err(|_| {
                    Error::MalformedAtRest("Session activity optional digest")
                })?)),
            }
        };
        let part_group = optional(&mut d)?;
        let reference = optional(&mut d)?;
        let part = match d.array()? {
            0 => None,
            1 => {
                if d.array()? != 2 {
                    return Err(Error::MalformedAtRest("Session activity part"));
                }
                Some((d.uint()?, d.uint()?))
            }
            _ => return Err(Error::MalformedAtRest("Session activity part")),
        };
        let boolean = |d: &mut Decoder<'_>| -> Result<bool> {
            match d.uint()? {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(Error::MalformedAtRest("Session activity flag")),
            }
        };
        let answerable = boolean(&mut d)?;
        let direct_action = boolean(&mut d)?;
        let succeeded = boolean(&mut d)?;
        let bytes = d.uint()?;
        let file_out = boolean(&mut d)?;
        d.finish()?;
        if arrival == 0 {
            return Err(Error::MalformedAtRest("Session activity arrival"));
        }
        Ok(Self {
            arrival,
            hash,
            author,
            session,
            created,
            sequence,
            kind,
            part_group,
            reference,
            part,
            answerable,
            direct_action,
            succeeded,
            bytes,
            file_out,
        })
    }
}

pub(super) fn fact(read: &Read<'_>, id: u64) -> Result<Fact> {
    let descriptor = read
        .find(Tree::ActivityFacts, &arrival_key(id))?
        .ok_or(Error::MalformedAtRest("Session activity fact missing"))?;
    let fact = Fact::read(&read.descriptor(descriptor)?)?;
    if fact.arrival != id {
        return Err(Error::MalformedAtRest("Session activity arrival differs"));
    }
    Ok(fact)
}

/// Idempotent for an already rendered authenticated record. All facts are written
/// in the same Batch as its body and the receiver-chain advancement.
pub(super) fn put(index: &mut Write<'_, '_>, id: u64, row: &SessionRow) -> Result<()> {
    if crate::node::sessions::is_record(&row.body)
        || crate::node::drive::is_key_changed(&row.session_id)
    {
        return Ok(());
    }
    let key = arrival_key(id);
    if let Some(old) = index.find(Tree::ActivityFacts, &key)? {
        let old = Fact::read(&index.descriptor(old)?)?;
        if old.hash != row.entry_hash || old.author != row.author || old.session != row.session_id {
            return Err(Error::MalformedAtRest("Session activity locator changed"));
        }
        return Ok(());
    }
    let fact = Fact::of(row, id);
    let group = fact.group();
    let descriptor = index.put_descriptor(&fact.bytes())?;
    index.set(Tree::ActivityFacts, key, Some(descriptor))?;
    index.set(Tree::ActivityRaw, member_key(&group, id), Some(id))?;
    index.set(Tree::ActivityCreated, fact.created_key(), Some(id))?;
    let count = index
        .find(Tree::ActivityCounts, &hash_key(&group))?
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(Error::MalformedAtRest("Session activity count exhausted"))?;
    index.set(Tree::ActivityCounts, hash_key(&group), Some(count))?;
    // One representative locates the complete bounded Session id for prefix
    // matching; it owns no second copy of the body or metadata.
    if index
        .find(Tree::ActivitySessions, &hash_key(&group))?
        .is_none()
    {
        index.set(Tree::ActivitySessions, hash_key(&group), Some(id))?;
    }
    super::activity_fold::appended(index, &fact)
}

pub(super) fn remove(index: &mut Write<'_, '_>, id: u64) -> Result<()> {
    let key = arrival_key(id);
    let Some(descriptor) = index.find(Tree::ActivityFacts, &key)? else {
        return Ok(());
    };
    let fact = Fact::read(&index.descriptor(descriptor)?)?;
    let group = fact.group();
    index.set(Tree::ActivityFacts, key, None)?;
    index.set(Tree::ActivityRaw, member_key(&group, id), None)?;
    index.set(Tree::ActivityCreated, fact.created_key(), None)?;
    index.delete_descriptor(descriptor)?;
    let count = index
        .find(Tree::ActivityCounts, &hash_key(&group))?
        .unwrap_or(0)
        .checked_sub(1)
        .ok_or(Error::MalformedAtRest("Session activity count underflow"))?;
    index.set(
        Tree::ActivityCounts,
        hash_key(&group),
        (count != 0).then_some(count),
    )?;
    let next = index
        .next(Tree::ActivityRaw, Some(hash_key(&group)))?
        .filter(|(key, _)| key[..32] == group)
        .map(|(_, id)| id);
    index.set(Tree::ActivitySessions, hash_key(&group), next)?;
    index.header.activity.invalidate()
}
