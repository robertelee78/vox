//! Activity-specific derived indexes: raw ranks, multipart origins/companions and
//! pending approvals. Repair never publishes a partial count or a partial grouping.

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
fn id_of(key: &[u8; 64]) -> u64 {
    u64::from_be_bytes(key[32..40].try_into().unwrap_or([0; 8]))
}
/// Under a rank's count tree, how many members already left this group (`removed`).
pub(super) fn removed_key(group: &Digest32) -> [u8; 64] {
    hash_key(&sha256_concat(&[b"vox/session-activity/removed/v1", group]))
}
/// The live-count tree that pairs with a rank tree.
pub(super) fn count_of(rank: T) -> Result<T> {
    Ok(match rank {
        T::RawRank => T::RawCount,
        T::AllRank => T::AllCount,
        T::FileRank => T::FileCount,
        T::RequestRank => T::RequestCount,
        T::Visible => T::VisibleCount,
        _ => return Err(bad()),
    })
}
/// A rank is the member's prefix count at its arrival: members are folded in arrival
/// order, so it is one more than every earlier member's, counting those that have since
/// left the group (`removed`). `prefix` subtracts the removed count again.
fn rank_plus(index: &mut Write<'_, '_>, count: T, group: &Digest32) -> Result<u64> {
    let live = plus(index, count, hash_key(group), 1)?;
    let removed = index
        .activity_find(count, &removed_key(group))?
        .unwrap_or(0);
    live.checked_add(removed).ok_or_else(bad)
}
fn lowest(index: &Write<'_, '_>, tree: T, group: &Digest32, arrival: u64) -> Result<bool> {
    Ok(index
        .activity_next(tree, Some(hash_key(group)))?
        .is_some_and(|(key, _)| key[..32] == group[..] && id_of(&key) == arrival))
}
pub(super) fn authored_reference(fact: &Fact, reference: &Digest32) -> Digest32 {
    sha256_concat(&[
        b"vox/session-activity/authored-ref/v1",
        &fact.author,
        reference,
    ])
}

pub(super) fn omp_current_key(group: &Digest32) -> Digest32 {
    sha256_concat(&[b"vox/omp-current-snapshot/v1", group])
}

pub(super) fn visible(index: &mut Write<'_, '_>, f: &Fact) -> Result<()> {
    let group = f.group();
    let rank = rank_plus(index, T::RawCount, &group)?;
    index.activity_set(T::RawRank, member_key(&group, f.arrival), Some(rank))?;
    let rank = rank_plus(index, T::AllCount, &f.author)?;
    index.activity_set(T::AllRank, member_key(&f.author, f.arrival), Some(rank))?;
    if f.file_out {
        let rank = rank_plus(index, T::FileCount, &f.author)?;
        index.activity_set(T::FileRank, member_key(&f.author, f.arrival), Some(rank))?;
    }
    if f.kind == Kind::OmpReset && f.omp_branch.is_some() {
        index.activity_set(
            T::Driven,
            hash_key(&omp_current_key(&group)),
            Some(f.arrival),
        )?;
    }
    super::activity_pending::observe(index, f)?;
    let Some(part_group) = f.part_group else {
        return Ok(());
    };
    if let Some(reference) = f.outcome_reference() {
        if matches!(
            f.kind,
            Kind::ToolDone | Kind::Resolved | Kind::DriveResult | Kind::OmpMessageUpdate
        ) {
            let authored = authored_reference(f, &reference);
            let mut key = hash_key(&reference);
            key[32..].copy_from_slice(&f.author);
            if f.latest_only && f.part.is_none_or(|(part, _)| part == 1) {
                // OMP progress is a replacement, not an ever-growing collection of
                // terminal outcomes. The sealed history remains untouched.
                let mut removed = 0usize;
                while let Some((old, _)) =
                    index.activity_next(T::Outcomes, Some(hash_key(&authored)))?
                {
                    if old[..32] != authored {
                        break;
                    }
                    index.activity_set(T::Outcomes, old, None)?;
                    removed += 1;
                    if removed > 512 {
                        return Err(bad());
                    }
                }
                index.activity_set(T::OutcomeCount, key, None)?;
                index.activity_set(T::OutcomeBytes, hash_key(&authored), None)?;
            }
            index.activity_set(
                T::Outcomes,
                member_key(&authored, f.arrival),
                Some(f.arrival),
            )?;
            plus(index, T::OutcomeCount, key, 1)?;
            let bytes = plus(index, T::OutcomeBytes, hash_key(&authored), f.bytes)?;
            index.activity_set(
                T::OutcomeBytes,
                member_key(&authored, f.arrival),
                Some(bytes),
            )?;
        }
        if matches!(f.kind, Kind::Approval | Kind::Question | Kind::Resolved) {
            index.activity_set(
                T::Requests,
                member_key(&authored_reference(f, &reference), f.arrival),
                Some(f.arrival),
            )?;
        }
    }
    if let Some(reference) = f.reference {
        if matches!(f.kind, Kind::Approval | Kind::Question | Kind::Resolved) {
            let authored = authored_reference(f, &reference);
            let rank = rank_plus(index, T::RequestCount, &authored)?;
            index.activity_set(T::RequestRank, member_key(&authored, f.arrival), Some(rank))?;
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
    if matches!(
        f.kind,
        Kind::ToolDone | Kind::Resolved | Kind::OmpMessageUpdate
    ) || (f.kind == Kind::Drive && !f.direct_action)
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
                let bytes = plus(index, T::PartBytes, hash_key(&original.hash), f.bytes)?;
                index.activity_set(
                    T::PartBytes,
                    member_key(&original.hash, f.arrival),
                    Some(bytes),
                )?;
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
    let visible_group = super::activity_index::visible_group(f);
    let rank = rank_plus(index, T::VisibleCount, &visible_group)?;
    index.activity_set(
        T::Visible,
        member_key(&visible_group, f.arrival),
        Some(rank),
    )
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
    let Some(reference) = f.outcome_reference() else {
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

/// Folds one removed fact out of the index exactly, or returns false: the index must be
/// rebuilt. Ranks are prefix counts written in arrival order, so a member leaves its rank
/// groups exactly only while it is the lowest arrival in each; the group's removed count
/// then carries the shift for every remaining rank. Expiry removes the oldest rows, so
/// this is the common shape. A request, a drive, an OMP reset or replacement and a
/// multipart body reach other derived trees and rebuild, as before.
pub(super) fn removed(index: &mut Write<'_, '_>, f: &Fact) -> Result<bool> {
    let activity = &index.header.activity;
    if !activity.ready {
        // A rebuild still walking retained facts below this arrival never sees it.
        return Ok(activity.work.as_ref().is_some_and(|work| {
            work.phase == 1
                && work
                    .cursor
                    .as_ref()
                    .is_none_or(|cursor| super::activity_index::arrival_of(cursor) < f.arrival)
        }));
    }
    if f.arrival > activity.applied {
        return Ok(true);
    }
    if f.latest_only
        || f.part.is_some_and(|(_, n)| n > 1)
        || !matches!(
            f.kind,
            Kind::Other
                | Kind::ToolDone
                | Kind::DriveResult
                | Kind::OmpMessage
                | Kind::OmpMessageUpdate
                | Kind::OmpMedia
                | Kind::OmpDisclosure
        )
    {
        return Ok(false);
    }
    let group = f.group();
    let visible_group = super::activity_index::visible_group(f);
    let mut ranks = vec![(T::RawRank, group), (T::AllRank, f.author)];
    if f.file_out {
        ranks.push((T::FileRank, f.author));
    }
    if index
        .activity_find(T::Visible, &member_key(&visible_group, f.arrival))?
        .is_some()
    {
        ranks.push((T::Visible, visible_group));
    }
    for (rank, group) in &ranks {
        if !lowest(index, *rank, group, f.arrival)? {
            return Ok(false);
        }
    }
    // An outcome's bytes are cumulative per authored reference; later members shift.
    let mut outcome = None;
    if let Some(reference) = f.part_group.and(f.outcome_reference()).filter(|_| {
        matches!(
            f.kind,
            Kind::ToolDone | Kind::DriveResult | Kind::OmpMessageUpdate
        )
    }) {
        let authored = authored_reference(f, &reference);
        if index
            .activity_find(T::Outcomes, &member_key(&authored, f.arrival))?
            .is_some()
        {
            let mut later = Vec::new();
            let mut cursor = member_key(&authored, f.arrival);
            while let Some((key, bytes)) = index.activity_next(T::OutcomeBytes, Some(cursor))? {
                if key[..32] != authored {
                    break;
                }
                later.push((key, bytes.checked_sub(f.bytes).ok_or_else(bad)?));
                if later.len() > 512 {
                    return Ok(false);
                }
                cursor = key;
            }
            outcome = Some((authored, later));
        }
    }
    for (rank, group) in ranks {
        let count = count_of(rank)?;
        index.activity_set(rank, member_key(&group, f.arrival), None)?;
        let live = index
            .activity_find(count, &hash_key(&group))?
            .unwrap_or(0)
            .checked_sub(1)
            .ok_or_else(bad)?;
        index.activity_set(count, hash_key(&group), (live != 0).then_some(live))?;
        plus(index, count, removed_key(&group), 1)?;
    }
    if let Some((authored, later)) = outcome {
        let mut key = hash_key(&authored);
        key[32..].copy_from_slice(&f.author);
        index.activity_set(T::Outcomes, member_key(&authored, f.arrival), None)?;
        let count = index
            .activity_find(T::OutcomeCount, &key)?
            .unwrap_or(0)
            .checked_sub(1)
            .ok_or_else(bad)?;
        index.activity_set(T::OutcomeCount, key, (count != 0).then_some(count))?;
        let total = index
            .activity_find(T::OutcomeBytes, &hash_key(&authored))?
            .unwrap_or(0)
            .checked_sub(f.bytes)
            .ok_or_else(bad)?;
        index.activity_set(
            T::OutcomeBytes,
            hash_key(&authored),
            (total != 0).then_some(total),
        )?;
        index.activity_set(T::OutcomeBytes, member_key(&authored, f.arrival), None)?;
        for (key, bytes) in later {
            index.activity_set(T::OutcomeBytes, key, Some(bytes))?;
        }
    }
    Ok(true)
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
    let retire = read.header.activity.ready && read.activity_next(T::RawRetire, None)?.is_some();
    if read.header.activity.ready && read.header.activity.work.is_none() && !retire {
        return Ok(false);
    }
    let mut batch = store.batch()?;
    batch.derived();
    let mut index = Write::open(&mut batch, sek, room)?;
    if retire {
        super::activity_pending::advance(&mut index, 32)?;
    }
    if read.header.activity.ready && read.header.activity.work.is_none() {
        index.seal()?;
        batch.commit()?;
        return Ok(true);
    }
    if let Some(work) = &mut index.header.activity.work {
        if work.phase != 5 && work.invalidated != index.header.activity.invalidated {
            work.phase = 5;
            work.cursor = None;
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
            } else if super::activity_pending::advance(&mut index, 32)? {
                index.publish_activity()?;
            }
        }
        5 => index.cleanup_activity()?,
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
    Ok(())
}
