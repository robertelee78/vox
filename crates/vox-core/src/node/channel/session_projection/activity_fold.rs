//! Activity-specific derived indexes: raw ranks, multipart origins/companions and
//! pending approvals. Repair never publishes a partial count or a partial grouping.

use super::super::ChannelState;
use super::activity_index::{arrival_key, hash_key, member_key, Fact, Kind};
use super::activity_state::{ActivityTree as T, ActivityWork, ACTIVITY_TREES};
use super::storage::{Read, Tree, Write};
use crate::error::{Error, Result};
use crate::hash::{sha256_concat, Digest32};
use crate::node::store::Store;

fn bad() -> Error {
    Error::MalformedAtRest("Session activity derived index")
}
fn fact(index: &Write<'_, '_>, id: u64) -> Result<Fact> {
    let descriptor = index
        .find(Tree::ActivityFacts, &arrival_key(id))?
        .ok_or_else(bad)?;
    let fact = Fact::read(&index.descriptor(descriptor)?)?;
    if fact.arrival != id {
        return Err(bad());
    }
    Ok(fact)
}
fn plus(index: &mut Write<'_, '_>, tree: T, key: [u8; 64], n: u64) -> Result<u64> {
    let value = index
        .activity_find(tree, &key)?
        .unwrap_or(0)
        .checked_add(n)
        .ok_or_else(bad)?;
    index.activity_set(tree, key, Some(value))?;
    Ok(value)
}
fn authored_reference(fact: &Fact, reference: &Digest32) -> Digest32 {
    sha256_concat(&[
        b"vox/session-activity/authored-ref/v1",
        &fact.author,
        reference,
    ])
}

pub(super) fn visible(index: &mut Write<'_, '_>, f: &Fact) -> Result<()> {
    let group = f.group();
    let rank = plus(index, T::RawCount, hash_key(&group), 1)?;
    index.activity_set(T::RawRank, member_key(&group, f.arrival), Some(rank))?;
    let Some(part_group) = f.part_group else {
        return Ok(());
    };
    if let Some(reference) = f.reference {
        if matches!(f.kind, Kind::ToolDone | Kind::Resolved | Kind::DriveResult) {
            index.activity_set(
                T::Outcomes,
                member_key(&reference, f.arrival),
                Some(f.arrival),
            )?;
            let mut key = hash_key(&reference);
            key[32..].copy_from_slice(&f.author);
            plus(index, T::OutcomeCount, key, 1)?;
        }
        if matches!(f.kind, Kind::Approval | Kind::Question | Kind::Resolved) {
            index.activity_set(
                T::Requests,
                member_key(&reference, f.arrival),
                Some(f.arrival),
            )?;
        }
        if f.kind == Kind::Drive {
            index.activity_set(T::Driven, hash_key(&reference), Some(1))?;
        }
    }
    let driven = f
        .reference
        .map(|r| index.activity_find(T::Driven, &hash_key(&r)))
        .transpose()?
        .flatten()
        .is_some();
    if matches!(f.kind, Kind::ToolDone | Kind::Resolved)
        || (f.kind == Kind::Drive && !f.direct_action)
        || (f.kind == Kind::DriveResult && (f.succeeded || driven))
    {
        return Ok(());
    }
    if let Some((i, n)) = f.part {
        if i > 1 {
            if let Some(origin) = index.activity_find(T::OpenParts, &hash_key(&part_group))? {
                let original = fact(index, origin)?;
                index.activity_set(
                    T::Parts,
                    member_key(&original.hash, f.arrival),
                    Some(f.arrival),
                )?;
                plus(index, T::PartCount, hash_key(&original.hash), 1)?;
                if i >= n {
                    index.activity_set(T::OpenParts, hash_key(&part_group), None)?;
                }
                return Ok(());
            }
        }
        if i < n {
            index.activity_set(T::OpenParts, hash_key(&part_group), Some(f.arrival))?;
        }
    }
    let rank = plus(index, T::VisibleCount, hash_key(&group), 1)?;
    index.activity_set(T::Visible, member_key(&group, f.arrival), Some(rank))
}

/// Pending joins follow the same created-time/seq order as of_session, distinct
/// from the transcript's arrival-ordered origin index. A late insertion requests
/// a bounded repair instead of guessing how it changes prior multipart joins.
pub(super) fn pending(index: &mut Write<'_, '_>, f: &Fact) -> Result<bool> {
    if f.part_group.is_none() || !matches!(f.kind, Kind::Approval | Kind::Question | Kind::Resolved)
    {
        return Ok(true);
    }
    let group = f.group();
    let group_key = hash_key(&group);
    if let Some(previous) = index.activity_find(T::PendingLast, &group_key)? {
        if fact(index, previous)?.created_key() > f.created_key() {
            return Ok(false);
        }
    }
    index.activity_set(T::PendingLast, group_key, Some(f.arrival))?;
    let Some(reference) = f.reference else {
        return Ok(true);
    };
    let authored = authored_reference(f, &reference);
    let authored_key = hash_key(&authored);
    if f.kind == Kind::Resolved {
        if index.activity_find(T::Resolved, &authored_key)?.is_none() {
            let removed = index
                .activity_find(T::PendingRefs, &authored_key)?
                .unwrap_or(0);
            let total = index
                .activity_find(T::PendingCount, &group_key)?
                .unwrap_or(0)
                .checked_sub(removed)
                .ok_or_else(bad)?;
            index.activity_set(T::PendingCount, group_key, (total != 0).then_some(total))?;
            if !index.activity_is_working() {
                super::waiting::changed(
                    index,
                    f,
                    total.checked_add(removed).ok_or_else(bad)?,
                    total,
                )?;
            }
            index.activity_set(T::PendingRefs, authored_key, None)?;
            index.activity_set(T::Resolved, authored_key, Some(1))?;
        }
        return Ok(true);
    }
    let part_group = f.part_group.ok_or_else(bad)?;
    if let Some((i, n)) = f.part {
        if i > 1 {
            if let Some(origin) = index.activity_find(T::WaitingOpen, &hash_key(&part_group))? {
                let original = fact(index, origin)?;
                index.activity_set(
                    T::WaitingParts,
                    member_key(&original.hash, f.arrival),
                    Some(f.arrival),
                )?;
                if i >= n {
                    index.activity_set(T::WaitingOpen, hash_key(&part_group), None)?;
                }
                return Ok(true);
            }
        }
        if n > 1 {
            index.activity_set(T::WaitingOpen, hash_key(&part_group), Some(f.arrival))?;
        }
    }
    if f.answerable && index.activity_find(T::Resolved, &authored_key)?.is_none() {
        index.activity_set(T::Pending, member_key(&group, f.arrival), Some(f.arrival))?;
        index.activity_set(T::RoomPending, arrival_key(f.arrival), Some(f.arrival))?;
        plus(index, T::PendingRefs, authored_key, 1)?;
        let count = plus(index, T::PendingCount, group_key, 1)?;
        if !index.activity_is_working() {
            super::waiting::changed(index, f, count - 1, count)?;
        }
    }
    Ok(true)
}

pub(super) fn appended(index: &mut Write<'_, '_>, f: &Fact) -> Result<()> {
    if !index.header.activity.ready {
        return Ok(());
    }
    if f.arrival <= index.header.activity.applied {
        return index.header.activity.invalidate();
    }
    visible(index, f)?;
    if !pending(index, f)? {
        index.header.activity.invalidate()?;
    } else {
        index.header.activity.applied = f.arrival;
    }
    Ok(())
}

pub(super) fn advance(ch: &ChannelState, store: &Store) -> Result<bool> {
    let snapshot = store.snapshot()?;
    let Some(read) = Read::existing(&snapshot, &ch.sek, &ch.channel_id)? else {
        return Ok(false);
    };
    if read.header.activity.ready && read.header.activity.work.is_none() {
        return Ok(false);
    }
    let mut batch = store.batch()?;
    let mut index = Write::open(&mut batch, &ch.sek, &ch.channel_id)?;
    if let Some(work) = &mut index.header.activity.work {
        if work.phase != 5 && work.invalidated != index.header.activity.invalidated {
            work.phase = 5;
            work.cursor = None;
            work.cleanup = 0;
        }
    } else {
        let boundary = read
            .previous(Tree::ActivityFacts, None)?
            .map(|(key, _)| {
                key[..8]
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| bad())
            })
            .transpose()?
            .unwrap_or(0);
        index.header.activity.work = Some(ActivityWork {
            roots: [0; ACTIVITY_TREES],
            boundary,
            invalidated: index.header.activity.invalidated,
            phase: 1,
            cursor: None,
            cleanup: 0,
        });
    }
    let state = index.header.activity.work.clone().ok_or_else(bad)?;
    let mut index = index.activity_work()?;
    let mut cursor = state.cursor;
    match state.phase {
        1 => {
            for _ in 0..32 {
                let next = read.next(Tree::ActivityFacts, cursor)?;
                let Some((key, descriptor)) = next else {
                    phase(&mut index, 2)?;
                    break;
                };
                let f = Fact::read(&read.descriptor(descriptor)?)?;
                if f.arrival > state.boundary {
                    phase(&mut index, 2)?;
                    break;
                }
                visible(&mut index, &f)?;
                cursor = Some(key);
            }
        }
        2 => {
            for _ in 0..32 {
                let Some((key, id)) = read.next(Tree::ActivityCreated, cursor)? else {
                    phase(&mut index, 3)?;
                    break;
                };
                let f = super::activity_index::fact(&read, id)?;
                if f.arrival <= state.boundary && !pending(&mut index, &f)? {
                    return Err(bad());
                }
                cursor = Some(key);
            }
        }
        3 => {
            let mut after = state.boundary;
            for _ in 0..32 {
                let Some((_, descriptor)) =
                    read.next(Tree::ActivityFacts, Some(arrival_key(after)))?
                else {
                    phase(&mut index, 4)?;
                    break;
                };
                let f = Fact::read(&read.descriptor(descriptor)?)?;
                visible(&mut index, &f)?;
                if !pending(&mut index, &f)? {
                    index.header.activity.invalidate()?;
                    phase(&mut index, 5)?;
                    break;
                }
                after = f.arrival;
            }
            index
                .header
                .activity
                .work
                .as_mut()
                .ok_or_else(bad)?
                .boundary = after;
        }
        4 => {
            // New append between catch-up and this actor turn is folded before
            // publication; no generation-sized snapshot or waiter is retained.
            if read
                .next(Tree::ActivityFacts, Some(arrival_key(state.boundary)))?
                .is_some()
            {
                phase(&mut index, 3)?;
            } else {
                index.publish_activity()?;
            }
        }
        5 => index.cleanup_activity(32)?,
        _ => return Err(bad()),
    }
    if let Some(work) = &mut index.header.activity.work {
        if work.phase == state.phase && matches!(state.phase, 1 | 2) {
            work.cursor = cursor;
        }
    }
    index.seal()?;
    batch.commit()?;
    Ok(true)
}
fn phase(index: &mut Write<'_, '_>, phase: u8) -> Result<()> {
    let work = index.header.activity.work.as_mut().ok_or_else(bad)?;
    work.phase = phase;
    work.cursor = None;
    work.cleanup = 0;
    Ok(())
}
