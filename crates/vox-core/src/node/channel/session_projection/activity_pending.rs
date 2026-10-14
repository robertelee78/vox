//! Raw request-page membership is separate from logical waiting requests. A
//! resolution can cover any number of retained parts: retire those locators in
//! bounded actor turns, refusing that page until its exact count is current.

use super::activity_index::{arrival_key, hash_key, member_key, Fact, Kind};
use super::activity_state::ActivityTree as T;
use super::storage::{Read, Tree, Write};
use crate::error::{Error, Result};
use crate::hash::Digest32;

fn bad() -> Error {
    Error::MalformedAtRest("Session raw pending index")
}

// Each prefix counter covers the low-bit interval ending at its arrival. A
// mutation or prefix count touches at most 64 sealed facts, independent of the
// transcript length. These are counts, never a retained list of request parts.
fn adjust(index: &mut Write<'_, '_>, group: &Digest32, mut arrival: u64, add: bool) -> Result<()> {
    if arrival == 0 {
        return Err(bad());
    }
    loop {
        let key = member_key(group, arrival);
        let old = index.activity_find(T::RawPendingPrefix, &key)?.unwrap_or(0);
        let value = if add {
            old.checked_add(1)
        } else {
            old.checked_sub(1)
        }
        .ok_or_else(bad)?;
        index.activity_set(T::RawPendingPrefix, key, (value != 0).then_some(value))?;
        let low = arrival & arrival.wrapping_neg();
        let Some(next) = arrival.checked_add(low) else {
            break;
        };
        arrival = next;
    }
    Ok(())
}
pub(super) fn prefix(read: &Read<'_>, groups: &[Digest32], before: u64) -> Result<u64> {
    let mut total = 0u64;
    for group in groups {
        let mut arrival = before.saturating_sub(1);
        while arrival != 0 {
            total = total
                .checked_add(
                    read.activity_find(T::RawPendingPrefix, &member_key(group, arrival))?
                        .unwrap_or(0),
                )
                .ok_or_else(bad)?;
            arrival &= arrival - 1;
        }
    }
    Ok(total)
}
pub(super) fn observe(index: &mut Write<'_, '_>, f: &Fact) -> Result<()> {
    let Some(reference) = f.outcome_reference() else {
        return Ok(());
    };
    if !matches!(f.kind, Kind::Approval | Kind::Question | Kind::Resolved) {
        return Ok(());
    }
    let authored = super::activity_fold::authored_reference(f, &reference);
    let key = hash_key(&authored);
    if f.kind == Kind::Resolved {
        if index.activity_find(T::RawResolved, &key)?.is_none() {
            index.activity_set(T::RawResolved, key, Some(1))?;
            index.activity_set(T::RawRetire, key, Some(0))?;
        }
    } else if f.answerable && index.activity_find(T::RawResolved, &key)?.is_none() {
        let group = f.group();
        index.activity_set(
            T::RawPending,
            member_key(&group, f.arrival),
            Some(f.arrival),
        )?;
        adjust(index, &group, f.arrival, true)?;
    }
    Ok(())
}
/// Returns true only when no resolution cleanup remains. The descriptor records
/// an exclusive request arrival, so restart and lost receipts are idempotent.
pub(super) fn advance(index: &mut Write<'_, '_>, limit: usize) -> Result<bool> {
    for _ in 0..limit {
        let Some((key, after)) = index.activity_next(T::RawRetire, None)? else {
            return Ok(true);
        };
        let mut authored = [0; 32];
        authored.copy_from_slice(&key[..32]);
        let next = index.activity_next(T::Requests, Some(member_key(&authored, after)))?;
        let Some((_, arrival)) = next.filter(|(k, _)| k[..32] == authored) else {
            index.activity_set(T::RawRetire, key, None)?;
            continue;
        };
        let descriptor = index
            .find(Tree::ActivityFacts, &arrival_key(arrival))?
            .ok_or_else(bad)?;
        let f = Fact::read(&index.descriptor(descriptor)?)?;
        if f.arrival != arrival
            || f.outcome_reference()
                .map(|r| super::activity_fold::authored_reference(&f, &r))
                != Some(authored)
        {
            return Err(bad());
        }
        let group = f.group();
        let member = member_key(&group, arrival);
        if index.activity_find(T::RawPending, &member)?.is_some() {
            index.activity_set(T::RawPending, member, None)?;
            adjust(index, &group, arrival, false)?;
        }
        // Logical counts were settled by the resolution's transaction. Removing
        // their obsolete locators here prevents future targeted lookups from
        // walking a history of already answered requests.
        if index.activity_find(T::Pending, &member)?.is_some() {
            index.activity_set(T::Pending, member, None)?;
            index.activity_set(T::RoomPending, arrival_key(arrival), None)?;
        }
        index.activity_set(T::RawRetire, key, Some(arrival))?;
    }
    Ok(index.activity_next(T::RawRetire, None)?.is_none())
}
