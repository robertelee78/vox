//! Governance reads its historical inputs from the room's sealed entry index.
//! Causal work is persisted and bounded independently of the room's display order.

mod authority;
mod canonical;
mod channel;
mod context;
mod facts;
mod fold;
mod member_fold;
mod sparse;
mod view;
pub(in crate::node::channel) use view::{
    recipient_body_eligibility_at, ConsentFacts, SemanticState, SemanticWork, PAGE_ROWS, REFRESHING,
};

#[cfg(feature = "test-knobs")]
pub(crate) use sparse::seen_hint_mutant;
pub(crate) use sparse::{
    checked_seen, sparse_control_evaluation, ControlEvaluation, PayloadValidation, SparseParent,
    SparsePayloadState, SparseValidation, SparseValidationStep, TypedSparseBody,
    ValidatedSparseEntry, VerifiedParentPrefix,
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

/// Recheck the authority generation under the same writer as a derived checkpoint.
pub(super) fn check_authority_generation_in(
    batch: &crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    root: Digest32,
    now: u64,
    expected: u64,
) -> Result<()> {
    let view = view::View::in_batch(batch, sek, room, root, now)?;
    if view.authority_generation() != expected {
        return Err(Error::Profile(REFRESHING));
    }
    Ok(())
}

/// Index a previously verified fork with the same transaction that retains its signed proof.
/// Different predecessor hashes do not prove a common prefix, so authority is unavailable
/// from the first sequence until stronger evidence is supplied.
pub(super) fn note_fork_in(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    proof: &crate::log::dag::ForkProof,
    issuer_key: &crate::identity::composite::CompositePublicKey,
    validated: Option<&ValidatedSparseEntry>,
) -> Result<()> {
    if proof.seq == 0
        || proof.existing.skeleton.author_id != proof.author_id
        || proof.conflicting.skeleton.author_id != proof.author_id
        || proof.existing.skeleton.seq != proof.seq
        || proof.conflicting.skeleton.seq != proof.seq
        || proof.existing.skeleton.channel_id != *room
        || proof.conflicting.skeleton.channel_id != *room
        || proof.existing.entry_hash() == proof.conflicting.entry_hash()
        || issuer_key.fingerprint() != proof.author_id
    {
        return Err(Error::MalformedAtRest("fork authority proof binding"));
    }
    proof.existing.verify(issuer_key)?;
    proof.conflicting.verify(issuer_key)?;
    let context = match validated {
        Some(validated) => {
            let entry = &proof.conflicting;
            let v2 = entry
                .skeleton
                .v2
                .as_ref()
                .ok_or(Error::MalformedAtRest("fork evidence missing v2 header"))?;
            let context = validated.pre_context();
            if validated.entry_hash() != entry.entry_hash()
                || context.hash() != v2.pre_context
                || context.room != *room
                || context.scope != v2.scope
            {
                return Err(Error::MalformedAtRest("fork evidence context binding"));
            }
            Some(context)
        }
        None => None,
    };
    let receipt = validated
        .map(|value| value.included().local_receipt())
        .transpose()?;
    let mut writer = facts::Write::open(batch, sek, room)?;
    let cutoff = fork_cutoff(proof, |seq| {
        writer
            .get(
                facts::Table::SourcePositions,
                &facts::position(&proof.author_id, seq),
            )?
            .map(|log| writer.entry(log).map(|entry| entry.entry_hash()))
            .transpose()
    })?;
    let mut changed = writer.record_fork_boundary(&proof.author_id, cutoff)?;
    // An alternate exclusion is evidence, never an accepted author-chain position.
    // A malformed or unsigned nested body confers nothing and does not poison the room.
    if let Ok(body) = crate::governance::entry::GovEntry::body_bound_to(&proof.conflicting) {
        if matches!(
            &body,
            crate::governance::entry::GovBody::MemberRemoval(_)
                | crate::governance::entry::GovBody::AdminRevocation(_)
        ) && body.channel_and_epoch() == (*room, 0)
            && body.issuer_id() == proof.author_id
            && body.verify(issuer_key).is_ok()
        {
            changed |=
                writer.retain_fork_exclusion(&proof.conflicting, context, receipt.as_deref())?;
        }
    }
    if changed {
        writer.start_fork_replay()?;
        writer.authority_changed()?;
    }
    writer.seal()
}

/// Rule F2 A (ledger 73): the position from which a proved forker's own entries count for
/// nothing here. The proof's position only when its two entries share a predecessor AND that
/// predecessor is this node's own accepted entry of that member just below it; otherwise 1. Two other
/// histories sharing a predecessor prove nothing about this node's prefix (`sec-1.md`).
fn fork_cutoff(
    proof: &crate::log::dag::ForkProof,
    accepted_hash: impl FnOnce(u64) -> Result<Option<Digest32>>,
) -> Result<u64> {
    let shared = proof.existing.skeleton.prev_hash == proof.conflicting.skeleton.prev_hash;
    if proof.seq > 1
        && shared
        && accepted_hash(proof.seq - 1)? == Some(proof.existing.skeleton.prev_hash)
    {
        Ok(proof.seq)
    } else {
        Ok(1)
    }
}

/// Rule F3 (ledger 73; `rule-f3.md`, `sec-5.md`): one member this node holds a verified fork
/// proof of, as every consumer of a signed context coordinate reads that member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Split {
    /// Its recorded boundary (`ForkBoundary`): from it on, nothing the splitter signed counts here.
    pub(crate) boundary: u64,
    /// The splitter is the creator, or this node holds an authenticated, room-bound
    /// creator-issued certificate naming it: in force, expired, revoked or policy-only alike
    /// (`CreatorCerts`). Such a splitter is not eligible for the coordinate fallback (sec-5
    /// condition 3). Read when the map is built and never kept past that read: the absence of a
    /// certificate is a local decision at that moment.
    pub(crate) certified: bool,
}

/// Every proved splitter here, read at one moment (`splits`). Empty when none is recorded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Splits(std::collections::BTreeMap<Digest32, Split>);

impl Splits {
    /// `author`'s split, when its recorded boundary is at or below `seq`.
    pub(crate) fn reaching(&self, author: &Digest32, seq: u64) -> Option<Split> {
        self.0
            .get(author)
            .copied()
            .filter(|split| seq >= split.boundary)
    }
    /// `author`'s recorded boundary, if a fork proof of that member is recorded.
    pub(crate) fn boundary(&self, author: &Digest32) -> Option<u64> {
        self.0.get(author).map(|split| split.boundary)
    }
    /// Each proved splitter and its boundary.
    pub(crate) fn boundaries(&self) -> impl Iterator<Item = (Digest32, u64)> + '_ {
        self.0
            .iter()
            .map(|(author, split)| (*author, split.boundary))
    }
    /// No proved splitter: every consumer's coordinate path is exactly today's.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Rule F3 (sec-5 conditions 1 and 3): a signed-context coordinate that is not this node's
    /// accepted control at its position (`matched` false) and names an ordinary proved splitter
    /// (neither the creator nor certified) at or after its boundary is ignored: it requires no
    /// entry, adds nothing, and is never read as authenticated ancestry. A matching coordinate
    /// keeps today's exact path, for anyone.
    pub(crate) fn ignores(
        &self,
        coordinate: &crate::log::history::EntryReference,
        matched: bool,
    ) -> bool {
        !matched
            && self
                .reaching(&coordinate.author, coordinate.seq)
                .is_some_and(|split| !split.certified)
    }
}

/// Every proved splitter recorded here, with its boundary and whether it is certified
/// (`Split`), read now from the room's governance facts. `root` is the room's creator.
/// `forked`: whether the room's DAG holds any fork proof (`Dag::any_frozen`). A boundary is
/// recorded only with a proof, so without one nothing is read and an honest room pays nothing
/// for the rule; a caller whose `forked` is a published snapshot's that predates a proof reads
/// no splitter, the exact path, which is stricter, never looser.
pub(crate) fn splits(
    store: &Store,
    sek: &Sek,
    room: &Digest32,
    root: &Digest32,
    forked: bool,
) -> Result<Splits> {
    if !forked {
        return Ok(Splits::default());
    }
    let Some(facts) = facts::Read::open_existing(store, sek, room)? else {
        return Ok(Splits::default());
    };
    let mut out = std::collections::BTreeMap::new();
    let mut after = None;
    while let Some((key, boundary)) = facts.first(facts::Table::ForkBoundary, after)? {
        after = Some(key);
        let author: Digest32 = key[..32]
            .try_into()
            .map_err(|_| Error::MalformedAtRest("fork boundary author"))?;
        let certified = author == *root
            || facts
                .at_or_after(facts::Table::CreatorCerts, facts::hash_key(&author))?
                .is_some_and(|(key, _)| key[..32] == author[..])
            || crate::node::history_stream::fork_mutant_is("fallback-off");
        out.insert(
            author,
            Split {
                boundary,
                certified,
            },
        );
    }
    Ok(Splits(out))
}

/// Whether a proof of an already frozen author gives, by rule A (`fork_cutoff`, no signature
/// read), a lower boundary than the one recorded (rule F2 A, `sec-2.md` condition 1): then it
/// replaces the kept proof and the boundary goes to 1 (the fork rule's two steps,
/// `facts::Write::record_fork_boundary`). At 1 no proof lowers it.
pub(crate) fn fork_proof_lowers(
    store: &Store,
    sek: &Sek,
    room: &Digest32,
    proof: &crate::log::dag::ForkProof,
) -> Result<bool> {
    let facts = facts::Read::open(store, sek, room)?;
    let current = facts.get(
        facts::Table::ForkBoundary,
        &facts::hash_key(&proof.author_id),
    )?;
    let candidate = fork_cutoff(proof, |seq| {
        facts
            .get(
                facts::Table::SourcePositions,
                &facts::position(&proof.author_id, seq),
            )?
            .map(|log| facts.entry(log).map(|entry| entry.entry_hash()))
            .transpose()
    })?;
    Ok(current.is_none_or(|boundary| candidate < boundary))
}

fn removal_generation_key(room: &Digest32) -> String {
    use std::fmt::Write as _;
    let mut key = String::with_capacity(88);
    key.push_str("room-removal-generation/");
    for byte in room {
        let _ = write!(key, "{byte:02x}");
    }
    key
}

/// Durable incarnation of the validated room membership projection.
pub(crate) fn removal_generation(store: &Store, room: &Digest32) -> Result<u64> {
    Ok(store
        .get_meta_prefix::<8>(&removal_generation_key(room))?
        .map(u64::from_be_bytes)
        .unwrap_or(0))
}

/// Last applied exclusion, independent of later rows awaiting causal settlement.
/// Public sync must still carry the evidence needed to settle those rows.
pub(crate) fn peer_removal_applied(
    store: &Store,
    sek: &Sek,
    room: &Digest32,
    peer: &Digest32,
) -> Result<bool> {
    if removal_generation(store, room)? == 0 {
        return Ok(false);
    }
    Ok(facts::Read::open(store, sek, room)?
        .get(facts::Table::CurrentRemoved, &facts::hash_key(peer))?
        .is_some())
}

pub(crate) fn removal_generation_in(
    batch: &crate::node::store::Batch<'_>,
    room: &Digest32,
) -> Result<u64> {
    Ok(batch
        .get_meta_prefix::<8>(&removal_generation_key(room))?
        .map(u64::from_be_bytes)
        .unwrap_or(0))
}

/// Recheck a prepared operation's durable membership incarnation and fold barrier.
pub(crate) fn check_removal_generation(
    store: &Store,
    sek: &Sek,
    room: &Digest32,
    generation: u64,
) -> Result<()> {
    let facts = facts::Read::open(store, sek, room)?;
    if !facts.current_ready()? || !facts.settled() || removal_generation(store, room)? != generation
    {
        return Err(Error::Profile(view::REFRESHING));
    }
    Ok(())
}

/// Recheck the same fence inside the transaction publishing the prepared operation.
pub(crate) fn check_removal_generation_in(
    batch: &crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    generation: u64,
) -> Result<()> {
    if !facts::settled_in(batch, sek, room)? || removal_generation_in(batch, room)? != generation {
        return Err(Error::Profile(view::REFRESHING));
    }
    Ok(())
}

pub(crate) fn content_eligibility_in(
    read: &super::entry_store::Read<'_>,
    entry: &crate::log::entry::Entry,
    now: u64,
) -> Result<ContentEligibility> {
    match View::pinned(read.snapshot(), read.sek(), read.channel(), [0; 32], now) {
        Ok(view) => view.content_eligibility(entry),
        Err(error) if refreshing(&error) => Ok(ContentEligibility::Refreshing),
        Err(error) => Err(error),
    }
}

/// ADR-053 M0, the writer's real-change rule: for each `(author, after)`, the highest position
/// above `after` of a Governance or StepPolicy row of that author that this node has applied
/// (causally complete and its history effect settled here) and that a post must acknowledge.
/// Authors with no such row above `after` are omitted. Content, KeyPackage, floors, support,
/// checkpoints, terminations and empty ContextUpdates are not governance rows and never appear
/// here. Another author's epoch-0 ConsentGrant is skipped (busy-room ack ruling): it changes
/// consent under its own author only, so no decision about this node's post. It is skipped
/// while scanning, so a later grant never masks an earlier removal, revocation or reset of the
/// same author: the scan goes on to that row. Grants stay validated and applied as before.
pub(crate) fn applied_governance_after(
    read: &super::entry_store::Read<'_>,
    reached: &[(Digest32, u64)],
) -> Result<Vec<(Digest32, u64)>> {
    let facts = facts::Read::from_snapshot(read.snapshot(), read.sek(), read.channel())?;
    let mut applied = Vec::new();
    for (author, after) in reached {
        let mut before = Some(facts::position(author, u64::MAX));
        while let Some((key, log)) = facts.last(facts::Table::Positions, before)? {
            if key[..32] != author[..] {
                break;
            }
            let seq = u64::from_be_bytes(
                key[32..40]
                    .try_into()
                    .map_err(|_| Error::MalformedAtRest("governance position key"))?,
            );
            if seq <= *after {
                break;
            }
            let entry = facts.entry(log)?;
            let hash = entry.entry_hash();
            if facts
                .get(facts::Table::Complete, &facts::hash_key(&hash))?
                .is_some()
                && read.history_effect_finished(&hash)?
                && !foreign_open_grant(&entry)
            {
                applied.push((*author, seq));
                break;
            }
            before = Some(key);
        }
    }
    Ok(applied)
}

/// An epoch-0 ConsentGrant (the callers pass other authors' rows only): no acknowledgement.
fn foreign_open_grant(entry: &crate::log::entry::Entry) -> bool {
    matches!(
        crate::governance::entry::GovEntry::body_bound_to(entry),
        Ok(crate::governance::entry::GovBody::ConsentGrant(grant)) if grant.body.epoch == 0
    )
}
/// Re-evaluate a recovered signed floor so its recipient decision is built from
/// the same authenticated frontier as the public author decision.
pub(super) fn queue_floor_eligibility_in(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    entry: &crate::log::entry::Entry,
    log: u64,
) -> Result<()> {
    let mut writer = facts::Write::open(batch, sek, room)?;
    let hash = entry.entry_hash();
    if writer.get(facts::Table::SourceHashes, &facts::hash_key(&hash))? == Some(log)
        && writer
            .get(facts::Table::Complete, &facts::hash_key(&hash))?
            .is_some()
    {
        writer.queue_eligibility(&hash, log)?;
    }
    writer.seal()
}

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
    batch.derived();
    let mut writer = facts::Write::open(&mut batch, sek, room)?;
    writer.set_control_only(input.sparse_enabled());
    let mut remaining = CAUSAL_WORK;
    let mut bytes = 0usize;
    let mut rows = 0;
    let mut drained = false;
    let mut replayed = false;
    while remaining > 0 {
        replayed |= writer.fork_replay_step(&input)?;
        replayed |= writer.fork_evidence_step()?;
        let Some(mut work) = writer.work()?.cloned() else {
            if rows == 0 && !replayed {
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
        if work.parent == 0 && work.author.is_none() && work.child.is_none() {
            work.changed |= writer.set_incomplete(&hash, false)?;
        }
        work.changed |= writer.raise(
            &hash,
            &entry.skeleton.author_id,
            entry.skeleton.seq,
            Some(hash),
        )?;
        remaining -= 1;
        // A v2 source was admitted with its exact signed parent/control closure, less any
        // coordinate rule F3 ignored (an ordinary proved splitter's at or after its boundary
        // that is not the accepted control here). Its authority frontier is that immutable
        // pre-context plus itself, kept raw; an ignored coordinate is never ancestry here,
        // because once its author is forked every reading of it is hash-exact against this
        // node's accepted chain (`causal_contains`, `reference_contains`). Inheriting a
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
                        work.changed |= writer.raise(
                            &hash,
                            &coordinate.author,
                            coordinate.seq,
                            Some(coordinate.hash),
                        )?;
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
                let parent_ready = input.clock(parent)?.is_some()
                    && writer
                        .get(facts::Table::Complete, &facts::hash_key(parent))?
                        .is_some()
                    && writer
                        .get(facts::Table::Incomplete, &facts::hash_key(parent))?
                        .is_none();
                if !parent_ready {
                    work.changed |= writer.set_incomplete(&hash, true)?;
                }
                let next = if parent_ready {
                    writer.frontier_after(parent, work.author)?
                } else {
                    None
                };
                match next {
                    Some((author, seq)) => {
                        let identity = writer.frontier_identity(parent, &author)?;
                        work.changed |= writer.raise(&hash, &author, seq, identity)?;
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
                    // A verified control child is re-queued on the control queue too, so the
                    // order waits for its rework; a content child is background work.
                    let control = writer
                        .get(facts::Table::Hashes, &facts::hash_key(&child))?
                        .is_some();
                    writer.enqueue(&child, log, control)?;
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
/// Whether a row is control work: a governance or step-policy row, by its signed kind in the
/// signed format, or by its payload's classification in the legacy format. A bodyless row is
/// not control work; its signature alone confers nothing and orders nothing.
fn is_control(entry: &crate::log::entry::Entry) -> bool {
    use crate::log::entry::EntryKind;
    match &entry.skeleton.v2 {
        Some(v2) => matches!(
            v2.kind,
            crate::log::history::SignedEntryKind::Governance
                | crate::log::history::SignedEntryKind::StepPolicy
        ),
        None => entry.payload.as_deref().is_some_and(|payload| {
            matches!(super::classify_payload(payload), Ok(EntryKind::Governance))
                || crate::governance::step_policy::is_step_policy(payload)
        }),
    }
}

pub(super) struct Acceptance {
    pub(super) work_changed: bool,
    pub(super) current_advanced: bool,
}

fn observe(
    writer: &mut facts::Write<'_, '_>,
    log: u64,
    clock: u64,
    late: bool,
    entry: &crate::log::entry::Entry,
    authors: &std::collections::BTreeMap<Digest32, crate::identity::composite::CompositePublicKey>,
    root: &Digest32,
) -> Result<Acceptance> {
    use crate::governance::entry::GovEntry;
    let hash = entry.entry_hash();
    writer.observe_source(log, entry)?;
    let control = is_control(entry);
    // A late row (a parent observed after its child) can change the order only through the
    // frontiers below it. In a signed-format room a control row's frontier is its own signed
    // control closure, so a late content row changes nothing the order reads: it neither
    // raises the barrier nor holds the settlement (ADR-037 R2c). A legacy room's control
    // rows can have content parents, so there every late row still raises it.
    let mut changed = late && !control && !writer.control_only();
    if changed {
        writer.barrier(log);
    }
    if writer
        .get(facts::Table::Complete, &facts::hash_key(&hash))?
        .is_none()
        && writer
            .get(facts::Table::Pending, &facts::hash_key(&hash))?
            .is_none()
    {
        writer.enqueue(&hash, log, control)?;
    }
    if !control {
        return Ok(Acceptance {
            work_changed: changed,
            current_advanced: false,
        });
    }
    let Some(payload) = entry.payload.as_deref() else {
        return Ok(Acceptance {
            work_changed: changed,
            current_advanced: false,
        });
    };
    // A malformed or unauthenticated member fact is retained as causal evidence,
    // but must not poison the room's governance replay.
    let member_fact = payload.starts_with(&[0, 0x24]) || payload.starts_with(&[0, 0x25]);
    if writer
        .get(facts::Table::Hashes, &facts::hash_key(&hash))?
        .is_some()
    {
        // The content hash, not the receipt time or cursor, binds the verified body.
        return Ok(Acceptance {
            work_changed: changed,
            current_advanced: false,
        });
    }
    let key = authors
        .get(&entry.skeleton.author_id)
        .ok_or(Error::MalformedAtRest("governance source author unknown"))?;
    let body = match GovEntry::body_bound_to(entry) {
        Ok(body) => body,
        Err(error) if entry.skeleton.v2.is_some() && !member_fact => return Err(error),
        Err(_) => {
            return Ok(Acceptance {
                work_changed: changed,
                current_advanced: false,
            });
        }
    };
    // Malformed/unauthenticated nested statements confer nothing, just as in
    // the original pass-1 evaluator. Local Store/index errors above remain errors.
    if let Err(error) = body.verify(key) {
        return if entry.skeleton.v2.is_some() && !member_fact {
            Err(error)
        } else {
            Ok(Acceptance {
                work_changed: changed,
                current_advanced: false,
            })
        };
    }
    let current = facts::Write::current_input_kind(&body);
    let (updates_current, changes_projection) = if current {
        writer.current_input_change(&entry.skeleton.author_id, entry.skeleton.seq, &body)?
    } else {
        (false, false)
    };
    // Canonical inputs are always ordered: only the checked fold can decide whether a signed
    // action is authorized and changes the published meaning. Current single-writer facts never
    // enter that order and wake only when their canonical value changes.
    if matches!(&body, crate::governance::entry::GovBody::Presence(_)) {
        writer.put(
            facts::Table::SenderPresence,
            facts::position(&entry.skeleton.author_id, entry.skeleton.seq),
            Some(log),
        )?;
    }
    let changes_order = !current;
    if changes_order {
        writer.barrier(log);
    }
    writer.verified(
        &hash,
        &entry.skeleton.author_id,
        entry.skeleton.seq,
        log,
        changes_projection,
        changes_order,
    )?;
    changed |= changes_projection || changes_order;
    if changes_order {
        writer.authority_input(
            &hash,
            &entry.skeleton.author_id,
            entry.skeleton.seq,
            log,
            root,
            &body,
        )?;
        writer.observe_clock(&hash, clock)?;
    }
    if updates_current {
        writer.current_input(
            &entry.skeleton.author_id,
            entry.skeleton.seq,
            log,
            &body,
            changes_projection,
        )?;
    }
    Ok(Acceptance {
        work_changed: changed,
        current_advanced: updates_current,
    })
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
    batch.derived();
    let mut writer = facts::Write::open(&mut batch, sek, room)?;
    writer.set_control_only(input.sparse_enabled());
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
            let accepted = observe(&mut writer, id, clock, late, &entry, authors, root)?;
            if accepted.work_changed && grants_this_reader(&entry, me) {
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

pub(crate) use channel::ContentEligibility;
pub(super) use channel::Presence;
pub use channel::{GovernanceNotices, GovernanceProgress, GovernanceShares, GovernanceTargets};
pub(super) use view::{Display, View};

/// Readiness and remaining background work are different: later ordinary chat
/// must not withhold a governance projection whose causal barrier is complete.
#[derive(Clone, Copy)]
pub(super) struct Progress {
    pub ready: bool,
    pub pending: bool,
    /// This turn took already shown rows away or brought retained ones back (MP-11); the room's
    /// readers must notice.
    pub retracted: bool,
}

/// Initialize only the derived directory. Authoritative source rows are neither
/// removed nor treated as empty; the persisted receipt cursor discovers them.
pub(super) fn prepare(store: &Store, sek: &Sek, room: &Digest32) -> Result<()> {
    use crate::atrest::store::SegmentKind::GovernanceIndex;
    // An index an older vox wrote at format 3 (every release through v0.4.5) is migrated in
    // place (ADR-037 R2c): its pending rows are classified from the log rows they name, the
    // control ones go on the new control settlement queue, and the header is resealed at this
    // build's format. Bounded by the pending rows, never by the room's history: an upgrade
    // of a large store does not scan the archive for a queue the rows it holds determine.
    if let Some(sealed) = store.get_segment(room, GovernanceIndex, 0)? {
        let previous = match crate::atrest::store::open_segment(sek, GovernanceIndex, 0, &sealed) {
            Ok(bytes) => facts::header_version(&bytes).is_some_and(|v| v != facts::HEADER_VERSION),
            Err(_) => false,
        };
        if previous {
            let mut batch = store.batch()?;
            batch.derived();
            let mut writer = facts::Write::open(&mut batch, sek, room)?;
            let mut after = None;
            while let Some((key, log, _hash)) = writer.pending_after(after)? {
                if is_control(&writer.source_entry(log)?) {
                    writer.mark_control_pending(key)?;
                }
                after = Some(key);
            }
            writer.seal()?;
            batch.commit()?;
        }
    }
    if store.get_segment(room, GovernanceIndex, 0)?.is_none() {
        let mut batch = store.batch()?;
        batch.derived();
        facts::Write::open(&mut batch, sek, room)?.seal()?;
        batch.commit()?;
    }
    {
        let mut batch = store.batch()?;
        batch.derived();
        let mut writer = facts::Write::open(&mut batch, sek, room)?;
        if writer.needs_source_replay() {
            writer.start_fork_replay()?;
            writer.authority_changed()?;
            writer.start_eligibility_replay()?;
            writer.seal()?;
            batch.commit()?;
        }
    }
    Ok(())
}

pub(super) fn progress(store: &Store, sek: &Sek, room: &Digest32, now: u64) -> Result<Progress> {
    let read = facts::Read::open(store, sek, room)?;
    Ok(Progress {
        ready: read.ready(now)?,
        pending: read.pending() || !read.current_ready()?,
        retracted: false,
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
) -> Result<Acceptance> {
    let (clock, sparse) = {
        let input = entries.in_batch(batch, sek, room)?;
        let hash = entry.entry_hash();
        (
            published_clock(input.log_id(&hash)?, input.clock(&hash)?, log)?,
            input.sparse_enabled(),
        )
    };
    let mut writer = facts::Write::open(batch, sek, room)?;
    writer.set_control_only(sparse);
    let accepted = observe(&mut writer, log, clock, late, entry, authors, root)?;
    writer.live_receipt(log)?;
    let backfill = accepted.work_changed && grants_this_reader(entry, me);
    writer.seal()?;
    if backfill {
        queue_backfill(batch, entries, sek, room, entry.skeleton.author_id)?;
    }
    Ok(accepted)
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
/// `next_log` is the room's shared log/cache allocator: a row that comes back takes its new
/// arrival from it (MP-11), and the caller installs what it advanced to.
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
    next_log: &mut u64,
) -> Result<Progress> {
    let current = progress(store, sek, room, now)?;
    if current.ready && !current.pending {
        return Ok(current);
    }
    #[cfg(feature = "test-knobs")]
    if fold_held() {
        // A proof holds the fold where it stands to stage "received but not yet folded"
        // (ADR-037 R3's gates). A held room does not spin the actor; after the apparatus releases
        // the marker, the proof supplies a real governance fact whose acceptance wakes this work.
        return Ok(Progress {
            ready: current.ready,
            pending: false,
            retracted: false,
        });
    }
    advance_source(store, entries, sek, room, authors, root, me)?;
    advance_frontiers(store, entries, sek, room)?;
    let mut retracted = false;
    {
        let input = entries.read(store, sek, room)?;
        let mut batch = store.batch()?;
        batch.derived();
        let mut writer = facts::Write::open(&mut batch, sek, room)?;
        writer.set_control_only(input.sparse_enabled());
        // Canonical ordering cannot mutate anything before causal settlement.
        // Do not rewrite its sealed header or fsync an otherwise empty turn.
        if writer.causal_settled()? {
            // The order and the evaluation run to completion inside this one turn, under a
            // bounded budget of phase steps and wall time, in one transaction (ADR-037 R2a):
            // one step per turn paced a room's whole re-fold at the maintenance cadence, so
            // every control entry closed the room for seconds. Each step is itself bounded;
            // the budget bounds the turn. Work left over is the next turn's.
            let started = std::time::Instant::now();
            let mut fold_ready = false;
            for _ in 0..FOLD_STEPS {
                let ordered = canonical::advance(&mut writer)?;
                if ordered && fold::advance(&mut writer, &input, root, now)? {
                    fold_ready = true;
                    break;
                }
                if started.elapsed() >= FOLD_BUDGET {
                    break;
                }
            }
            // MP-11 (ADR-053): a message this node already shows and that an eligibility
            // decision now proves not acceptable (its author outside a removal's cut) leaves the
            // conversation in the same transaction as the decision, so counts, pages and threads
            // never name it again; one taken away before and decided acceptable again (a
            // removal its remover's authority no longer carries) comes back from the plaintext
            // this node retains, in the same transaction.
            let mut decided = Vec::new();
            if fold_ready {
                for _ in 0..FOLD_STEPS {
                    if started.elapsed() >= FOLD_BUDGET || !writer.causal_settled()? {
                        break;
                    }
                    let replayed = writer.eligibility_replay_step(&input)?;
                    if !writer.causal_settled()? {
                        break;
                    }
                    let worked = member_fold::advance_eligibility(&mut writer, &mut decided)?;
                    if !replayed && !worked {
                        break;
                    }
                }
            }
            writer.seal()?;
            #[cfg(feature = "test-knobs")]
            if keep_rows_mutant() {
                decided.clear();
            }
            if !decided.is_empty() {
                let shown = super::shown_now();
                let mut index = entries.write(&mut batch, sek, room)?;
                for (hash, eligible) in &decided {
                    if !eligible {
                        if index.has_rendered(hash)? {
                            index.remove_rendered(hash)?;
                            retracted = true;
                        }
                        index.remove_read_receipt(hash)?;
                    } else if !no_restore_mutant()
                        && index.restore_rendered(hash, shown, next_log)?
                    {
                        retracted = true;
                    }
                }
                index.seal()?;
            }
            batch.commit()?;
        }
    }
    Ok(Progress {
        retracted,
        ..progress(store, sek, room, now)?
    })
}

/// At most this many order/evaluation phase steps, and at most this long, per governance turn.
const FOLD_STEPS: usize = 256;
const FOLD_BUDGET: std::time::Duration = std::time::Duration::from_millis(40);

/// `VOX_TEST_FOLD_HOLD_FILE`: while the named file exists, no room's governance fold advances.
/// Read only by a `test-knobs` build; a release `vox` holds nothing (#300).
#[cfg(feature = "test-knobs")]
pub const TEST_FOLD_HOLD_ENV: &str = "VOX_TEST_FOLD_HOLD_FILE";
#[cfg(feature = "test-knobs")]
fn fold_held() -> bool {
    std::env::var_os(TEST_FOLD_HOLD_ENV)
        .filter(|path| !path.is_empty())
        .is_some_and(|path| std::path::Path::new(&path).exists())
}

/// `VOX_MUTANT_MP11_KEEP_ROWS`: a shown row stays when its author's eligibility is decided
/// false (before MP-11). Says so once when the daemon first reads it.
#[cfg(feature = "test-knobs")]
fn keep_rows_mutant() -> bool {
    static ON: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
        let on = std::env::var_os("VOX_MUTANT_MP11_KEEP_ROWS").is_some();
        if on {
            eprintln!("vox: VOX_MUTANT_MP11_KEEP_ROWS engaged: ineligible shown rows stay");
        }
        on
    });
    *ON
}

/// `VOX_MUTANT_MP11_NO_RESTORE`: a retracted row stays away when its author's eligibility is
/// decided true again. Says so once when the daemon first reads it.
fn no_restore_mutant() -> bool {
    #[cfg(feature = "test-knobs")]
    {
        static ON: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
            let on = std::env::var_os("VOX_MUTANT_MP11_NO_RESTORE").is_some();
            if on {
                eprintln!("vox: VOX_MUTANT_MP11_NO_RESTORE engaged: retracted rows stay away");
            }
            on
        });
        *ON
    }
    #[cfg(not(feature = "test-knobs"))]
    false
}

/// `VOX_MUTANT_MP11_NO_RECONCILE`: an index sealed before format 6 is opened without the new
/// authority generation that recomputes its decisions (`facts::Header::parse`). Says so once
/// when the daemon first reads it.
fn no_reconcile_mutant() -> bool {
    #[cfg(feature = "test-knobs")]
    {
        static ON: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
            let on = std::env::var_os("VOX_MUTANT_MP11_NO_RECONCILE").is_some();
            if on {
                eprintln!(
                    "vox: VOX_MUTANT_MP11_NO_RECONCILE engaged: an older index keeps its decisions"
                );
            }
            on
        });
        *ON
    }
    #[cfg(not(feature = "test-knobs"))]
    false
}
