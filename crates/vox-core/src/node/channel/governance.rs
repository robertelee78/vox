//! Governance reads its historical inputs from the room's sealed entry index.
//! Causal work is persisted and bounded independently of the room's display order.

mod authority;
mod canonical;
mod context;
mod facts;
mod fold;
mod view;

use super::entry_store::EntryIndex;
use crate::atrest::sek::Sek;
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::entry::EntryRead;
use crate::node::store::Store;

/// At most this many frontier coordinates or reverse edges are applied in one turn.
const CAUSAL_WORK: usize = 64;

/// Advance one queued entry without keeping its body or any tree page between turns.
/// A frontier includes the entry's own coordinate. Strict-past queries separately
/// exclude that exact entry, never substitute a display clock for reachability.
fn advance_frontiers(
    store: &Store,
    entries: &EntryIndex,
    sek: &Sek,
    room: &Digest32,
) -> Result<bool> {
    let mut writer = facts::Write::open(store, sek, room)?;
    let Some(mut work) = writer.work()?.cloned() else {
        writer.commit()?;
        return Ok(true);
    };
    let hash = work
        .entry
        .ok_or(Error::MalformedAtRest("governance work entry missing"))?;
    let input = entries.read(store, sek, room)?;
    let entry = input
        .get_by_hash(&hash)?
        .filter(|entry| entry.entry_hash() == hash)
        .ok_or(Error::MalformedAtRest("governance causal entry missing"))?;
    if input.clock(&hash)?.is_none() {
        return Err(Error::MalformedAtRest(
            "governance causal entry unpublished",
        ));
    }
    work.changed |= writer.raise(&hash, &entry.skeleton.author_id, entry.skeleton.seq)?;
    let own_parent = usize::from(entry.skeleton.seq > 1);
    let parent_count = own_parent + entry.skeleton.seen.len();
    let mut complete = false;
    for _ in 0..CAUSAL_WORK {
        let at = usize::try_from(work.parent)
            .map_err(|_| Error::MalformedAtRest("governance parent cursor"))?;
        if at > parent_count {
            return Err(Error::MalformedAtRest(
                "governance parent cursor beyond entry",
            ));
        }
        if at < parent_count {
            let parent = if at == 0 && own_parent != 0 {
                &entry.skeleton.prev_hash
            } else {
                &entry.skeleton.seen[at - own_parent]
            };
            // A missing parent contributes no coordinate yet. Its eventual arrival
            // queues this child through the already persisted reverse-edge index.
            let next = if input.clock(parent)?.is_some() {
                writer.frontier_after(parent, work.author)?
            } else {
                None
            };
            match next {
                Some((author, seq)) => {
                    work.changed |= writer.raise(&hash, &author, seq)?;
                    work.author = Some(author);
                }
                None => {
                    work.parent += 1;
                    work.author = None;
                }
            }
            continue;
        }
        if !work.changed {
            complete = true;
            break;
        }
        match input.child_after(&hash, work.child)? {
            Some(child) => {
                writer.enqueue(&child)?;
                work.child = Some(child);
            }
            None => {
                complete = true;
                break;
            }
        }
    }
    writer.save_work(work)?;
    if complete {
        writer.finish_work()?;
    }
    writer.commit()?;
    // A caller spends another turn checking the queue rather than draining it
    // here and monopolizing the room lock on a large late-parent fan-out.
    Ok(false)
}

/// Observe a source entry only after the existing EntryIndex has published it.
/// This does not acknowledge an unsigned/staged suffix or invent causal edges.
fn observe(
    writer: &mut facts::Write<'_>,
    published: &super::entry_store::Read<'_>,
    log: u64,
    entry: &crate::log::entry::Entry,
    authors: &std::collections::BTreeMap<Digest32, crate::identity::composite::CompositePublicKey>,
    root: &Digest32,
) -> Result<()> {
    use super::classify_payload;
    use crate::governance::entry::GovEntry;
    use crate::log::entry::EntryKind;
    let hash = entry.entry_hash();
    if published.log_id(&hash)? != Some(log) || published.clock(&hash)?.is_none() {
        return Err(Error::MalformedAtRest(
            "governance source entry unpublished",
        ));
    }
    if writer
        .get(facts::Table::Complete, &facts::hash_key(&hash))?
        .is_none()
        && writer
            .get(facts::Table::Pending, &facts::hash_key(&hash))?
            .is_none()
    {
        writer.enqueue(&hash)?;
    }
    let Some(payload) = entry.payload.as_deref() else {
        return Ok(());
    };
    if !matches!(classify_payload(payload), Ok(EntryKind::Governance))
        && !crate::governance::step_policy::is_step_policy(payload)
    {
        return Ok(());
    }
    if writer
        .get(facts::Table::Hashes, &facts::hash_key(&hash))?
        .is_some()
    {
        // The content hash, not the receipt time or cursor, binds the verified body.
        return Ok(());
    }
    let key = authors
        .get(&entry.skeleton.author_id)
        .ok_or(Error::MalformedAtRest("governance source author unknown"))?;
    let Ok(body) = GovEntry::body_bound_to(entry) else {
        return Ok(());
    };
    // Malformed/unauthenticated nested statements confer nothing, just as in
    // the original pass-1 evaluator. Local Store/index errors above remain errors.
    if body.verify(key).is_err() {
        return Ok(());
    }
    writer.verified(&hash, &entry.skeleton.author_id, entry.skeleton.seq, log)?;
    writer.authority_input(
        &hash,
        &entry.skeleton.author_id,
        entry.skeleton.seq,
        log,
        root,
        &body,
    )?;
    writer.current_input(&entry.skeleton.author_id, entry.skeleton.seq, log, &body)
}

/// Advance one authoritative source row. The cursor and every derived obligation
/// commit together; a crash after source acceptance but before this turn merely
/// leaves the source row beyond the cursor for the next unlock to discover.
fn advance_source(
    store: &Store,
    entries: &EntryIndex,
    sek: &Sek,
    room: &Digest32,
    authors: &std::collections::BTreeMap<Digest32, crate::identity::composite::CompositePublicKey>,
    root: &Digest32,
) -> Result<bool> {
    let input = entries.read(store, sek, room)?;
    let mut writer = facts::Write::open(store, sek, room)?;
    match writer.source_after()? {
        Some((id, entry)) => {
            observe(&mut writer, &input, id, &entry, authors, root)?;
            writer.observed_through(id)?;
            writer.commit()?;
            Ok(false)
        }
        None => {
            writer.source_caught_up();
            writer.commit()?;
            Ok(true)
        }
    }
}
