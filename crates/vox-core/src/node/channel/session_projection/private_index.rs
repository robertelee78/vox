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
    index.set(Tree::PrivateHash, hash_key(&hash), Some(id))?;
    index.set(Tree::PrivateArrival, arrival_key(id), Some(id))?;
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
    index.set(Tree::PrivateHash, hash_key(&saved.record.hash()), None)?;
    index.set(Tree::PrivateArrival, arrival_key(id), None)?;
    index.set(Tree::Files, arrival_key(id), None)?;
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
