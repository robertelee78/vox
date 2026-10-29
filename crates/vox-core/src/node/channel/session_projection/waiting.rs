//! The room-wide waiting scalar, grouped by author for current-drive filtering.
//! Rebuild scans fixed-size Session group facts in bounded turns. Appends adjust
//! already scanned groups in the same transaction, so a busy transcript cannot
//! starve publication and no client needs to collect all Sessions to count them.

use super::activity_index::{hash_key, Fact};
use super::activity_state::ActivityTree;
use super::record::{Descriptor, Key};
use super::storage::{Read, Tree, Write};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256_concat, Digest32};
use crate::node::store::Store;

fn bad() -> Error {
    Error::MalformedAtRest("Session waiting aggregate")
}
#[derive(Clone, Default)]
pub(super) struct State {
    pub root: u64,
    pub metadata: u64,
    pub ready: bool,
    pub work: Option<Work>,
}
#[derive(Clone)]
pub(super) struct Work {
    pub root: u64,
    pub metadata: u64,
    pub invalidated: u64,
    pub cursor: Option<Key>,
    pub cleanup: bool,
}
impl State {
    pub fn put(&self, e: &mut Encoder) {
        e.array(4)
            .uint(self.root)
            .uint(self.metadata)
            .uint(u64::from(self.ready))
            .array(usize::from(self.work.is_some()));
        if let Some(w) = &self.work {
            e.array(5)
                .uint(w.root)
                .uint(w.metadata)
                .uint(w.invalidated)
                .bytes(w.cursor.as_ref().map_or(&[][..], |k| &k[..]))
                .uint(u64::from(w.cleanup));
        }
    }
    pub fn read(d: &mut Decoder<'_>, next: u64) -> Result<Self> {
        let root = |d: &mut Decoder<'_>| -> Result<u64> {
            let id = d.uint()?;
            if id >= next {
                return Err(bad());
            }
            Ok(id)
        };
        let boolean = |d: &mut Decoder<'_>| -> Result<bool> {
            match d.uint()? {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(bad()),
            }
        };
        if d.array()? != 4 {
            return Err(bad());
        }
        let active = root(d)?;
        let metadata = root(d)?;
        let ready = boolean(d)?;
        let work = match d.array()? {
            0 => None,
            1 => {
                if d.array()? != 5 {
                    return Err(bad());
                }
                Some(Work {
                    root: root(d)?,
                    metadata: root(d)?,
                    invalidated: d.uint()?,
                    cursor: match d.bytes()? {
                        [] => None,
                        k => Some(k.try_into().map_err(|_| bad())?),
                    },
                    cleanup: boolean(d)?,
                })
            }
            _ => return Err(bad()),
        };
        Ok(Self {
            root: active,
            metadata,
            ready,
            work,
        })
    }
}
fn is_open(index: &Write<'_, '_>, f: &Fact) -> Result<bool> {
    let key = hash_key(&sha256_concat(&[
        b"vox/session-projection/id/v1",
        &f.author,
        f.session.as_bytes(),
    ]));
    let Some(id) = index.find(Tree::Groups, &key)? else {
        return Ok(false);
    };
    let bytes = index.descriptor(id)?;
    let mut d = Decoder::new(&bytes);
    let row = Descriptor::read(&mut d)?;
    d.finish()?;
    if row.node != f.author || row.id != f.session {
        return Err(bad());
    }
    Ok(row.ended.is_none())
}
fn adjust(
    index: &mut Write<'_, '_>,
    root: u64,
    author: Digest32,
    old: u64,
    new: u64,
) -> Result<u64> {
    let key = hash_key(&author);
    let value = index
        .waiting_find(root, &key)?
        .unwrap_or(0)
        .checked_sub(old)
        .and_then(|n| n.checked_add(new))
        .ok_or_else(bad)?;
    index.waiting_set(root, key, (value != 0).then_some(value))
}
/// Called with the per-group count mutation in the same writer Batch. The work
/// cursor identifies which groups its partial sum already includes.
pub(super) fn changed(index: &mut Write<'_, '_>, f: &Fact, old: u64, new: u64) -> Result<()> {
    if old == new {
        return Ok(());
    }
    let metadata = index.root(Tree::Groups)?;
    if !index.header.ready || !is_open(index, f)? {
        return Ok(());
    }
    let state = index.header.activity.waiting.clone();
    if state.ready && state.metadata == metadata {
        index.header.activity.waiting.root = adjust(index, state.root, f.author, old, new)?;
    }
    if let Some(work) = state.work {
        if !work.cleanup
            && work.metadata == metadata
            && work.invalidated == index.header.activity.invalidated
            && work
                .cursor
                .is_some_and(|cursor| hash_key(&f.group()) <= cursor)
        {
            let root = adjust(index, work.root, f.author, old, new)?;
            index
                .header
                .activity
                .waiting
                .work
                .as_mut()
                .ok_or_else(bad)?
                .root = root;
        }
    }
    Ok(())
}
pub(super) fn advance_owned(
    store: &Store,
    sek: &crate::atrest::sek::Sek,
    room: &Digest32,
) -> Result<bool> {
    let snapshot = store.snapshot()?;
    let Some(read) = Read::existing(&snapshot, sek, room)? else {
        return Ok(false);
    };
    if !read.header.activity.ready || !read.header.ready {
        return Ok(false);
    }
    let metadata = read.root(Tree::Groups)?;
    let saved = &read.header.activity.waiting;
    if saved.ready && saved.metadata == metadata && saved.work.is_none() {
        return Ok(false);
    }
    let mut batch = store.batch()?;
    batch.derived();
    let mut index = Write::open(&mut batch, sek, room)?;
    if index.header.activity.waiting.metadata != metadata {
        index.header.activity.waiting.ready = false;
    }
    let invalidated = index.header.activity.invalidated;
    if let Some(work) = &mut index.header.activity.waiting.work {
        if work.metadata != metadata || work.invalidated != invalidated {
            work.cleanup = true;
        }
    } else {
        index.header.activity.waiting.work = Some(Work {
            root: 0,
            metadata,
            invalidated,
            cursor: None,
            cleanup: false,
        });
    }
    let mut work = index.header.activity.waiting.work.clone().ok_or_else(bad)?;
    if work.cleanup {
        for _ in 0..32 {
            let Some((key, _)) = index.waiting_next(work.root, None)? else {
                index.header.activity.waiting.work = None;
                break;
            };
            work.root = index.waiting_set(work.root, key, None)?;
            index.header.activity.waiting.work = Some(work.clone());
        }
    } else {
        for _ in 0..32 {
            let Some((key, id)) = read.next(Tree::ActivitySessions, work.cursor)? else {
                let old = index.header.activity.waiting.root;
                index.header.activity.waiting.root = work.root;
                index.header.activity.waiting.metadata = metadata;
                index.header.activity.waiting.ready = true;
                work.root = old;
                work.cleanup = true;
                break;
            };
            let fact = super::activity_index::fact(&read, id)?;
            if key != hash_key(&fact.group()) {
                return Err(bad());
            }
            if is_open(&index, &fact)? {
                let count = read
                    .activity_find(ActivityTree::PendingCount, &key)?
                    .unwrap_or(0);
                if count != 0 {
                    work.root = adjust(&mut index, work.root, fact.author, 0, count)?;
                }
            }
            work.cursor = Some(key);
        }
        index.header.activity.waiting.work = Some(work);
    }
    index.seal()?;
    batch.commit()?;
    Ok(true)
}
