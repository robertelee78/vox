//! Private wire/cache records remain in PrivateSession. This catalog holds only sealed
//! locators, updated in the same transaction as the authenticated wire and ratchet state.

use crate::atrest::sek::Sek;
use crate::cbor::Encoder;
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::store::{Batch, Snapshot};

use super::super::private_session::Stored;
use super::record::{Key, Position, Source};
use super::storage::{Read, Tree, Write};

fn hash_key(hash: &Digest32) -> Key {
    let mut key = [0; 64];
    key[..32].copy_from_slice(hash);
    key
}

fn arrival_key(id: u64) -> Key {
    let mut key = [0; 64];
    key[..8].copy_from_slice(&id.to_be_bytes());
    key
}

pub(in crate::node::channel) fn find(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
    hash: &Digest32,
) -> Result<Option<u64>> {
    match Read::existing(snapshot, sek, room)? {
        Some(read) => read.find(Tree::PrivateHash, &hash_key(hash)),
        None => Ok(None),
    }
}

pub(in crate::node::channel) fn find_in(
    batch: &Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    hash: &Digest32,
) -> Result<Option<u64>> {
    super::storage::find_in(batch, sek, room, Tree::PrivateHash, &hash_key(hash))
}

/// Exact logical lifecycle content. The row remains authoritative; this fixed locator only
/// avoids scanning every retained private record before refreshing one grant.
fn refresh_key(author: &Digest32, created: u64, body: &str) -> Key {
    let mut key = [0; 64];
    key[..32].copy_from_slice(author);
    key[32..].copy_from_slice(&crate::hash::sha256_concat(&[
        b"vox/private-session-refresh/v1",
        &created.to_be_bytes(),
        body.as_bytes(),
    ]));
    key
}

pub(in crate::node::channel) fn matching_lifecycle(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
    author: &Digest32,
    created: u64,
    body: &str,
) -> Result<Option<u64>> {
    match Read::existing(snapshot, sek, room)? {
        Some(read) => read.find(Tree::RefreshRecords, &refresh_key(author, created, body)),
        None => Ok(None),
    }
}

pub(in crate::node::channel) fn candidate_after(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
    after: Option<Key>,
) -> Result<Option<(Key, u64)>> {
    let Some(read) = Read::existing(snapshot, sek, room)? else {
        return Ok(None);
    };
    let Some((key, descriptor)) = read.next(Tree::Candidates, after)? else {
        return Ok(None);
    };
    let bytes = read.descriptor(descriptor)?;
    let mut d = crate::cbor::Decoder::new(&bytes);
    let source = Source::read(&mut d)?;
    d.finish()?;
    if !source.position.private || source.position.key() != key {
        return Err(Error::MalformedAtRest("private Session candidate binding"));
    }
    Ok(Some((key, source.id)))
}

pub(in crate::node::channel) fn lifecycle_revision(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
) -> Result<u64> {
    Ok(Read::existing(snapshot, sek, room)?.map_or(0, |r| r.header.private_generation))
}

fn age(saved: &Stored, id: u64) -> (Tree, Key) {
    let lifecycle = saved
        .row
        .as_ref()
        .is_some_and(|r| crate::node::sessions::is_record(&r.body));
    let claimed = saved
        .row
        .as_ref()
        .map(|r| r.created_millis)
        .or_else(|| saved.record.legacy_claimed_ms())
        .unwrap_or(saved.first_seen);
    let mut key = [0; 64];
    key[..8].copy_from_slice(&saved.first_seen.min(claimed).to_be_bytes());
    key[8..16].copy_from_slice(&id.to_be_bytes());
    (
        if lifecycle {
            Tree::PrivateAge
        } else {
            Tree::PrivateStepAge
        },
        key,
    )
}

pub(in crate::node::channel) fn next_expired(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
    now: u64,
    ttl: u64,
    step_ttl: u64,
) -> Result<Option<u64>> {
    let Some(read) = Read::existing(snapshot, sek, room)? else {
        return Ok(None);
    };
    for (tree, ttl) in [(Tree::PrivateAge, ttl), (Tree::PrivateStepAge, step_ttl)] {
        if ttl == 0 {
            continue;
        }
        if let Some((key, id)) = read.next(tree, None)? {
            let base = u64::from_be_bytes(
                key[..8]
                    .try_into()
                    .map_err(|_| Error::MalformedAtRest("Session age key"))?,
            );
            let indexed = u64::from_be_bytes(
                key[8..16]
                    .try_into()
                    .map_err(|_| Error::MalformedAtRest("Session age locator"))?,
            );
            if indexed != id {
                return Err(Error::MalformedAtRest("Session age locator differs"));
            }
            if base <= now.saturating_sub(ttl.saturating_mul(1000)) {
                return Ok(Some(id));
            }
        }
    }
    Ok(None)
}

fn candidate(saved: &Stored, id: u64) -> Option<Source> {
    let row = saved.row.as_ref()?;
    if !crate::node::sessions::is_record(&row.body) && !row.body.contains("session_name") {
        return None;
    }
    Some(Source {
        position: Position {
            created: row.created_millis,
            private: true,
            order: id,
            hash: row.entry_hash,
        },
        author: row.author,
        id,
    })
}

/// Called while the original PrivateSession record and any receiver-chain advancement are
/// still queued in this Batch. No reader can see a locator without the matching saved row.
pub(in crate::node::channel) fn put(
    batch: &mut Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    id: u64,
    saved: &Stored,
) -> Result<()> {
    let mut index = Write::open(batch, sek, room)?;
    index.header.activity_generation =
        index
            .header
            .activity_generation
            .checked_add(1)
            .ok_or(Error::MalformedAtRest(
                "Session activity revision exhausted",
            ))?;
    let hash = saved.record.hash();
    if id == 0 {
        return Err(Error::MalformedAtRest("private Session id is zero"));
    }
    if index
        .find(Tree::PrivateHash, &hash_key(&hash))?
        .is_some_and(|old| old != id)
    {
        return Err(Error::MalformedAtRest(
            "private Session hash has two locators",
        ));
    }
    let (tree, key) = age(saved, id);
    index.set(tree, key, Some(id))?;
    index.set(Tree::PrivateHash, hash_key(&hash), Some(id))?;
    index.set(Tree::PrivateArrival, arrival_key(id), Some(id))?;
    if let Some(row) = saved
        .row
        .as_ref()
        .filter(|r| crate::node::sessions::is_record(&r.body))
    {
        let key = refresh_key(&row.author, row.created_millis, &row.body);
        if index
            .find(Tree::RefreshRecords, &key)?
            .is_none_or(|old| old <= id)
        {
            index.set(Tree::RefreshRecords, key, Some(id))?;
        }
    }
    if let Some(source) = candidate(saved, id) {
        index.header.private_generation =
            index
                .header
                .private_generation
                .checked_add(1)
                .ok_or(Error::MalformedAtRest(
                    "Session candidate revision exhausted",
                ))?;
        let key = source.position.key();
        if let Some(old) = index.find(Tree::Candidates, &key)? {
            index.delete_descriptor(old)?;
        }
        let mut e = Encoder::new();
        source.put(&mut e);
        let descriptor = index.put_descriptor(&e.finish())?;
        index.set(Tree::Candidates, key, Some(descriptor))?;
    }
    if let Some(row) = saved
        .row
        .as_ref()
        .filter(|row| crate::node::drive::is_file_out(row))
    {
        index.set(Tree::Files, arrival_key(id), Some(id))?;
        if hash != row.entry_hash {
            return Err(Error::MalformedAtRest("Session file hash binding"));
        }
    }
    if let Some(row) = &saved.row {
        super::activity_index::put(&mut index, id, row)?;
    }
    index.seal()
}

pub(in crate::node::channel) fn remove(
    batch: &mut Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    id: u64,
    saved: &Stored,
) -> Result<()> {
    let mut index = Write::open(batch, sek, room)?;
    super::activity_index::remove(&mut index, id)?;
    index.header.activity_generation =
        index
            .header
            .activity_generation
            .checked_add(1)
            .ok_or(Error::MalformedAtRest(
                "Session activity revision exhausted",
            ))?;
    let (tree, key) = age(saved, id);
    index.set(tree, key, None)?;
    index.set(Tree::PrivateHash, hash_key(&saved.record.hash()), None)?;
    index.set(Tree::PrivateArrival, arrival_key(id), None)?;
    index.set(Tree::Files, arrival_key(id), None)?;
    if let Some(row) = saved
        .row
        .as_ref()
        .filter(|r| crate::node::sessions::is_record(&r.body))
    {
        let key = refresh_key(&row.author, row.created_millis, &row.body);
        if index.find(Tree::RefreshRecords, &key)? == Some(id) {
            index.set(Tree::RefreshRecords, key, None)?;
        }
    }
    if let Some(source) = candidate(saved, id) {
        index.header.private_generation =
            index
                .header
                .private_generation
                .checked_add(1)
                .ok_or(Error::MalformedAtRest(
                    "Session candidate revision exhausted",
                ))?;
        let key = source.position.key();
        if let Some(old) = index.find(Tree::Candidates, &key)? {
            index.set(Tree::Candidates, key, None)?;
            index.delete_descriptor(old)?;
        }
    }
    index.seal()
}
