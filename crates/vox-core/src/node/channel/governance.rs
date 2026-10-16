//! Governance reads its historical inputs from the room's sealed entry index.
//! Causal work is persisted and bounded independently of the room's display order.

mod authority;
mod canonical;
mod channel;
mod context;
mod facts;
mod fold;
mod sparse;
mod view;

pub(crate) use sparse::{
    sparse_control_evaluation, ControlEvaluation, PayloadValidation, SettledGovernanceControl,
    SparseValidation, SparseValidationStep, TypedSparseBody, ValidatedSparseEntry,
    VerifiedParentPrefix,
};

use super::entry_store::EntryIndex;
use crate::atrest::sek::Sek;
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::entry::EntryRead;
use crate::node::store::Store;

/// At most this many frontier coordinates or reverse edges are applied in one turn.
const CAUSAL_WORK: usize = 64;
const SOURCE_ROWS: usize = 64;
const INPUT_BYTES: usize = 1024 * 1024;

/// Advance a bounded part of the queue without keeping bodies or tree pages
/// between turns. Small entries share one transaction and the same work budget.
/// A frontier includes the entry's own coordinate. Strict-past queries separately
/// exclude that exact entry, never substitute a display clock for reachability.
fn advance_frontiers(
    store: &Store,
    entries: &EntryIndex,
    sek: &Sek,
    room: &Digest32,
) -> Result<bool> {
    let input = entries.read(store, sek, room)?;
    let mut batch = store.batch()?;
    let mut writer = facts::Write::open(&mut batch, sek, room)?;
    let mut remaining = CAUSAL_WORK;
    let mut bytes = 0usize;
    let mut rows = 0;
    let mut drained = false;
    while remaining > 0 {
        let Some(mut work) = writer.work()?.cloned() else {
            if rows == 0 {
                return Ok(true);
            }
            drained = true;
            break;
        };
        let hash = work
            .entry
            .ok_or(Error::MalformedAtRest("governance work entry missing"))?;
        // Format 2 retains its individually signed header independently of the body.
        // Causal projection never decrypts a large content body just to read that header.
        let entry = if input.sparse_enabled() {
            input
                .history_object(super::entry_store::sparse::ObjectKind::Header, &hash)?
                .map(|wire| crate::log::entry::Entry::from_wire(&wire))
                .transpose()?
        } else {
            input.get_by_hash(&hash)?
        }
        .filter(|entry| entry.entry_hash() == hash)
        .ok_or(Error::MalformedAtRest("governance causal entry missing"))?;
        let size = entry.to_wire().len();
        // One oversized entry must still make progress; no body survives this turn.
        if rows > 0 && bytes.saturating_add(size) > INPUT_BYTES {
            break;
        }
        bytes = bytes.saturating_add(size);
        rows += 1;
        let clock = input.clock(&hash)?;
        if clock.is_none() {
            return Err(Error::MalformedAtRest(
                "governance causal entry unpublished",
            ));
        }
        writer.observe_clock(
            &hash,
            clock.ok_or(Error::MalformedAtRest("governance clock missing"))?,
        )?;
        work.changed |= writer.raise(&hash, &entry.skeleton.author_id, entry.skeleton.seq)?;
        remaining -= 1;
        // A v2 source was admitted with its exact signed parent/control closure. Its
        // authority frontier is that immutable pre-context plus itself. Inheriting a
        // receiver's newer parent frontier would change strict-past authorization.
        let signed_context = entry
            .skeleton
            .v2
            .as_ref()
            .map(|v2| {
                let context = input
                    .history_context(&v2.pre_context)?
                    .ok_or(Error::MalformedAtRest("validated causal context missing"))?;
                if context.hash() != v2.pre_context
                    || context.room != *room
                    || context.scope != v2.scope
                {
                    return Err(Error::MalformedAtRest("validated causal context binding"));
                }
                Ok(context)
            })
            .transpose()?;
        let own_parent = usize::from(entry.skeleton.seq > 1);
        let parent_count = if signed_context.is_some() {
            1
        } else {
            own_parent + entry.skeleton.seen.len()
        };
        let mut complete = false;
        while remaining > 0 {
            remaining -= 1;
            let at = usize::try_from(work.parent)
                .map_err(|_| Error::MalformedAtRest("governance parent cursor"))?;
            if at > parent_count {
                return Err(Error::MalformedAtRest(
                    "governance parent cursor beyond entry",
                ));
            }
            if at < parent_count {
                if let Some(context) = &signed_context {
                    let at = work.author.map_or(0, |after| {
                        context
                            .coordinates
                            .partition_point(|coordinate| coordinate.author <= after)
                    });
                    if let Some(coordinate) = context.coordinates.get(at) {
                        work.changed |= writer.raise(&hash, &coordinate.author, coordinate.seq)?;
                        work.author = Some(coordinate.author);
                    } else {
                        work.parent += 1;
                        work.author = None;
                    }
                    continue;
                }
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
                    let log = input
                        .log_id(&child)?
                        .ok_or(Error::MalformedAtRest("governance child locator missing"))?;
                    writer.enqueue(&child, log)?;
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
    }
    writer.seal()?;
    batch.commit()?;
    Ok(drained)
}

/// Observe a source entry only after the existing EntryIndex has published it.
/// This does not acknowledge an unsigned/staged suffix or invent causal edges.
fn observe(
    writer: &mut facts::Write<'_, '_>,
    log: u64,
    clock: u64,
    late: bool,
    entry: &crate::log::entry::Entry,
    authors: &std::collections::BTreeMap<Digest32, crate::identity::composite::CompositePublicKey>,
    root: &Digest32,
) -> Result<()> {
    use super::classify_payload;
    use crate::governance::entry::GovEntry;
    use crate::log::entry::EntryKind;
    let hash = entry.entry_hash();
    if late {
        writer.barrier(log);
    }
    if writer
        .get(facts::Table::Complete, &facts::hash_key(&hash))?
        .is_none()
        && writer
            .get(facts::Table::Pending, &facts::hash_key(&hash))?
            .is_none()
    {
        writer.enqueue(&hash, log)?;
    }
    let Some(payload) = entry.payload.as_deref() else {
        return Ok(());
    };
    let governance = match &entry.skeleton.v2 {
        Some(v2) => matches!(
            v2.kind,
            crate::log::history::SignedEntryKind::Governance
                | crate::log::history::SignedEntryKind::StepPolicy
        ),
        None => {
            matches!(classify_payload(payload), Ok(EntryKind::Governance))
                || crate::governance::step_policy::is_step_policy(payload)
        }
    };
    if !governance {
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
    let body = match GovEntry::body_bound_to(entry) {
        Ok(body) => body,
        Err(error) if entry.skeleton.v2.is_some() => return Err(error),
        Err(_) => return Ok(()),
    };
    // Malformed/unauthenticated nested statements confer nothing, just as in
    // the original pass-1 evaluator. Local Store/index errors above remain errors.
    if let Err(error) = body.verify(key) {
        return if entry.skeleton.v2.is_some() {
            Err(error)
        } else {
            Ok(())
        };
    }
    writer.barrier(log);
    writer.verified(&hash, &entry.skeleton.author_id, entry.skeleton.seq, log)?;
    writer.authority_input(
        &hash,
        &entry.skeleton.author_id,
        entry.skeleton.seq,
        log,
        root,
        &body,
    )?;
    writer.observe_clock(&hash, clock)?;
    writer.current_input(&entry.skeleton.author_id, entry.skeleton.seq, log, &body)
}

/// Advance a bounded batch of authoritative source rows. The cursor and every
/// derived obligation commit together; a crash leaves uncommitted source rows
/// beyond the cursor for the next unlock to discover.
fn advance_source(
    store: &Store,
    entries: &EntryIndex,
    sek: &Sek,
    room: &Digest32,
    authors: &std::collections::BTreeMap<Digest32, crate::identity::composite::CompositePublicKey>,
    root: &Digest32,
    me: &Digest32,
) -> Result<bool> {
    let input = entries.read(store, sek, room)?;
    let mut batch = store.batch()?;
    let mut writer = facts::Write::open(&mut batch, sek, room)?;
    writer.discover_source()?;
    if writer.initialized() {
        return Ok(true);
    }
    let mut bytes = 0usize;
    let mut backfill = std::collections::BTreeSet::new();
    let mut done = false;
    for row in 0..SOURCE_ROWS {
        let Some((id, entry)) = writer.source_after()? else {
            writer.source_caught_up();
            done = true;
            break;
        };
        let size = entry.to_wire().len();
        if row > 0 && bytes.saturating_add(size) > INPUT_BYTES {
            break;
        }
        bytes = bytes.saturating_add(size);
        let hash = entry.entry_hash();
        let published = input.log_id(&hash)? == Some(id) && input.clock(&hash)?.is_some();
        if published {
            let clock = published_clock(input.log_id(&hash)?, input.clock(&hash)?, id)?;
            let late = input.child_after(&hash, None)?.is_some();
            observe(&mut writer, id, clock, late, &entry, authors, root)?;
            if writer
                .get(facts::Table::Hashes, &facts::hash_key(&hash))?
                .is_some()
                && grants_this_reader(&entry, me)
            {
                backfill.insert(entry.skeleton.author_id);
            }
        }
        writer.observed_through(id)?;
    }
    writer.seal()?;
    if !backfill.is_empty() {
        let mut writer = entries.write(&mut batch, sek, room)?;
        for author in backfill {
            writer.queue_backfill(author, Some(1))?;
        }
        writer.seal()?;
    }
    batch.commit()?;
    Ok(done)
}

pub(super) use channel::{remember_presence, Presence};
pub use channel::{GovernanceNotices, GovernanceProgress, GovernanceShares, GovernanceTargets};
pub(super) use view::{Display, View};

/// Readiness and remaining background work are different: later ordinary chat
/// must not withhold a governance projection whose causal barrier is complete.
#[derive(Clone, Copy)]
pub(super) struct Progress {
    pub ready: bool,
    pub pending: bool,
}

/// Initialize only the derived directory. Authoritative source rows are neither
/// removed nor treated as empty; the persisted receipt cursor discovers them.
pub(super) fn prepare(store: &Store, sek: &Sek, room: &Digest32) -> Result<()> {
    if store
        .get_segment(room, crate::atrest::store::SegmentKind::GovernanceIndex, 0)?
        .is_none()
    {
        let mut batch = store.batch()?;
        facts::Write::open(&mut batch, sek, room)?.seal()?;
        batch.commit()?;
    }
    Ok(())
}

pub(super) fn progress(store: &Store, sek: &Sek, room: &Digest32, now: u64) -> Result<Progress> {
    let read = facts::Read::open(store, sek, room)?;
    Ok(Progress {
        ready: read.ready(now)?,
        pending: read.pending() || !read.current_ready()?,
    })
}

/// Seal accepted input facts and replay obligations in the exact transaction
/// publishing that source entry, including a body filled at an old receipt id.
/// The caller alone commits or rolls back the Batch.
#[allow(clippy::too_many_arguments)]
pub(super) fn accepted_into(
    batch: &mut crate::node::store::Batch<'_>,
    entries: &EntryIndex,
    sek: &Sek,
    room: &Digest32,
    authors: &std::collections::BTreeMap<Digest32, crate::identity::composite::CompositePublicKey>,
    root: &Digest32,
    me: &Digest32,
    log: u64,
    entry: &crate::log::entry::Entry,
    late: bool,
) -> Result<()> {
    let clock = {
        let input = entries.in_batch(batch, sek, room)?;
        let hash = entry.entry_hash();
        published_clock(input.log_id(&hash)?, input.clock(&hash)?, log)?
    };
    let mut writer = facts::Write::open(batch, sek, room)?;
    observe(&mut writer, log, clock, late, entry, authors, root)?;
    writer.live_receipt(log)?;
    let backfill = writer
        .get(facts::Table::Hashes, &facts::hash_key(&entry.entry_hash()))?
        .is_some()
        && grants_this_reader(entry, me);
    writer.seal()?;
    if backfill {
        queue_backfill(batch, entries, sek, room, entry.skeleton.author_id)?;
    }
    Ok(())
}

fn grants_this_reader(entry: &crate::log::entry::Entry, me: &Digest32) -> bool {
    matches!(crate::governance::entry::GovEntry::body_bound_to(entry),
        Ok(crate::governance::entry::GovBody::ConsentGrant(grant)) if grant.body.epoch == 0 && grant.body.target_id == *me)
}
fn queue_backfill(
    batch: &mut crate::node::store::Batch<'_>,
    entries: &EntryIndex,
    sek: &Sek,
    room: &Digest32,
    author: Digest32,
) -> Result<()> {
    let mut writer = entries.write(batch, sek, room)?;
    writer.queue_backfill(author, Some(1))?;
    writer.seal()
}

pub(super) fn refreshing(error: &Error) -> bool {
    matches!(error, Error::Profile(why) if *why == view::REFRESHING)
}

fn published_clock(found: Option<u64>, clock: Option<u64>, expected: u64) -> Result<u64> {
    if found != Some(expected) {
        return Err(Error::MalformedAtRest(
            "governance source locator unpublished",
        ));
    }
    clock.ok_or(Error::MalformedAtRest(
        "governance source clock unpublished",
    ))
}

/// One actor turn of work. Source and causal work both progress before ordering,
/// rather than draining all newly received rows while starving older obligations.
/// No future complete-page vector or borrowed snapshot survives this function.
#[allow(clippy::too_many_arguments)]
pub(super) fn advance(
    store: &Store,
    entries: &EntryIndex,
    sek: &Sek,
    room: &Digest32,
    authors: &std::collections::BTreeMap<Digest32, crate::identity::composite::CompositePublicKey>,
    root: &Digest32,
    me: &Digest32,
    now: u64,
) -> Result<Progress> {
    let current = progress(store, sek, room, now)?;
    if current.ready && !current.pending {
        return Ok(current);
    }
    advance_source(store, entries, sek, room, authors, root, me)?;
    advance_frontiers(store, entries, sek, room)?;
    {
        let input = entries.read(store, sek, room)?;
        let mut batch = store.batch()?;
        let mut writer = facts::Write::open(&mut batch, sek, room)?;
        // Canonical ordering cannot mutate anything before causal settlement.
        // Do not rewrite its sealed header or fsync an otherwise empty turn.
        if writer.causal_settled()? {
            if canonical::advance(&mut writer)? {
                fold::advance(&mut writer, &input, root, now)?;
            }
            writer.seal()?;
            batch.commit()?;
        }
    }
    progress(store, sek, room, now)
}
