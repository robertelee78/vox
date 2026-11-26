//! One bounded authenticated-object admission step. Signatures, commitment continuity,
//! control completeness and semantic effects remain distinct states in the existing store.

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::entry::Entry;
use crate::log::history::{
    ConsistencyVerifier, ControlContext, ControlRangeVerifier, Descriptor, HistoryStep,
    InclusionVerifier, LogScope, SignedHead, VerifiedHeader, WorkBudget,
};
use crate::node::channel::{entry_store, governance, HistoryAdmissionRoom};
use crate::node::store::Store;

use super::{Object, Proof, ProofKind, Query, RequestId};
use entry_store::sparse::{CursorBinding, HistoryVerifier};

// A bounded transient result covered by the existing verifier working reservation.
pub(super) enum Staged {
    Object,
    Head {
        head: Digest32,
        author: Digest32,
        tail: u64,
    },
    Header,
    Verifier(CursorBinding),
    Busy,
}

fn invalid(message: &'static str) -> Error {
    Error::MalformedBundle(message)
}

/// A fault in this node's own state (a stored object or locator it relies on is absent, a
/// cursor of its own work contradicts itself, an author it admitted is gone), never a refusal
/// of the author's evidence: a local failure of the admission (`runtime.rs` `turn_inner`).
fn local(message: &'static str) -> Error {
    Error::MalformedAtRest(message)
}

/// Caller owns the 4-MiB verifier envelope and reserved room publication, not its mutex.
/// Peer proof bytes only construct verifiers; they never enter authenticated-local restore APIs.
pub(super) fn stage(
    room: &impl HistoryAdmissionRoom,
    store: &Store,
    ledgers: (
        &std::sync::atomic::AtomicBool,
        &std::sync::atomic::AtomicBool,
    ),
    request: RequestId,
    generation: Digest32,
    query: &Query,
    object: Object<'_>,
) -> Result<Staged> {
    let (committed, own_observed) = ledgers;
    if room.history_publication_busy(store)? {
        return Ok(Staged::Busy);
    }
    let mut work = WorkBudget::default();
    match (query, object) {
        (Query::Head(_) | Query::HeadById(_), Object::Head(bytes)) => {
            let head = SignedHead::from_wire(bytes)?;
            // MP-9 (rule 6): a head asked for by its exact id is staged as an observation like
            // any other: it is verified, retained, and promoted only through the same gates.
            let requested = match query {
                Query::Head(author) => head.binding.author == *author,
                Query::HeadById(id) => head.id() == *id,
                _ => false,
            };
            if head.binding.room != room.channel_id()
                || head.binding.scope != LogScope::Public
                || !requested
            {
                return Err(invalid("requested head binding differs"));
            }
            let author_id = head.binding.author;
            let author = &author_id;
            let key = room
                .history_author_key(author)
                .ok_or(invalid("unknown history author"))?;
            let HistoryStep::Complete(verified) = head.verify(&key, &mut work)? else {
                return Ok(Staged::Busy);
            };
            let id = head.id();
            // A head already observed is not saved again (ADR-038 FX-29): every periodic
            // round's head probe of a held author committed its head and author state
            // unchanged. Only what `observe_history_head` would change is written: a head
            // object not retained, or an author state it would move. A retained conflict
            // still takes the write path and is refused there as before.
            let input = room.history_read(store)?;
            let retained = input
                .history_head(&id)?
                .is_some_and(|stored| stored.binding == head.binding && stored.root == head.root);
            let state = input.sparse_author(author, LogScope::Public)?;
            let observed_already = match state {
                Some(state) if state.observed_conflict.is_none() => {
                    state.observed == Some(id)
                        || match state.observed {
                            Some(observed) => input
                                .history_head(&observed)?
                                .is_some_and(|prior| prior.root.leaves > head.root.leaves),
                            None => false,
                        }
                }
                _ => false,
            };
            // MP-9: a head of the accepted head's size with another root is opened and compared
            // like one of another size (promote_head), not only refused as a conflict.
            let equal_rival = *author != room.me()
                && !fork_mutant_is("equal-rival-refused")
                && match state.and_then(|state| state.committed) {
                    Some(accepted) if accepted != id => {
                        input.history_head(&accepted)?.is_some_and(|accepted| {
                            accepted.root.leaves == head.root.leaves && accepted.root != head.root
                        })
                    }
                    _ => false,
                };
            drop(input);
            let brought = !(retained && observed_already);
            if brought {
                let conflict = if *author == room.me() && !observed_already {
                    room.history_write_own_head_tracked(store, committed, |index| {
                        index.observe_history_head(&verified)
                    })?
                } else {
                    room.history_write_tracked(store, committed, |index| {
                        index.observe_history_head(&verified)
                    })?
                };
                if *author == room.me() && !observed_already {
                    // Set inside the physical callback AFTER commit, even if the following
                    // proof, wire exchange, cancellation or conflict exit never completes.
                    own_observed.store(true, std::sync::atomic::Ordering::Release);
                }
                if conflict && !equal_rival {
                    return Err(invalid("conflicting authenticated heads retained"));
                }
            }
            Ok(Staged::Head {
                head: id,
                author: *author,
                tail: head.root.leaves,
            })
        }
        (Query::Context(expected), Object::Context(bytes)) => {
            let context = ControlContext::from_wire(bytes)?;
            if context.hash() != *expected
                || context.room != room.channel_id()
                || context.scope != LogScope::Public
            {
                return Err(invalid("requested context differs"));
            }
            // A context already held is not saved again (ADR-038 FX-29).
            if room
                .history_read(store)?
                .history_context(expected)?
                .is_some()
            {
                return Ok(Staged::Object);
            }
            room.history_write_tracked(store, committed, |index| {
                index.keep_history_context(&context)
            })?;
            Ok(Staged::Object)
        }
        (Query::Entry { head, seq, .. } | Query::Header { head, seq }, Object::Header(bytes)) => {
            stage_header(room, store, committed, *head, *seq, *seq, bytes, &mut work)
        }
        (Query::Page { head, lo, hi, .. }, Object::Header(bytes)) => {
            stage_header(room, store, committed, *head, *lo, *hi, bytes, &mut work)
        }
        (
            Query::Proof {
                head,
                kind,
                from,
                to,
            },
            Object::Proof(proof),
        ) => {
            let input = room.history_read(store)?;
            let signed = input
                .history_head(head)?
                .ok_or(invalid("proof target head is absent"))?;
            if signed.binding.room != room.channel_id() || signed.binding.scope != LogScope::Public
            {
                return Err(invalid("proof target room differs"));
            }
            let key = room
                .history_author_key(&signed.binding.author)
                .ok_or(invalid("unknown proof author"))?;
            let HistoryStep::Complete(verified) = signed.verify(&key, &mut work)? else {
                return Ok(Staged::Busy);
            };
            let mut binding = CursorBinding {
                request,
                room: room.channel_id(),
                head: *head,
                author: signed.binding.author,
                proof_kind: *kind as u8,
                from: *from,
                through: *to,
                generation,
            };
            let cursor = match (kind, proof) {
                (ProofKind::Inclusion, Proof::Inclusion(proof)) => {
                    if proof.position != *from || from != to || proof.size != signed.root.leaves {
                        return Err(invalid("inclusion response interval differs"));
                    }
                    // MP-9: an accepted position's header is under every accepted head only.
                    // Under another signed head the header its holder sent for that exact head
                    // is the one proven; the accepted entry would fail as if the proof were bad.
                    let accepted_head = input.history_head_accepted(head, signed.binding)?;
                    let position = input.history_position_header(&signed.binding.author, *from)?;
                    let pending = input.history_pending_header(head, *from)?;
                    let header = if accepted_head {
                        position.or(pending)
                    } else {
                        pending.or(position)
                    }
                    .ok_or(invalid("inclusion header is absent"))?;
                    let HistoryStep::Complete(header) =
                        VerifiedHeader::verify(&header, signed.binding, &key, &mut work)?
                    else {
                        return Ok(Staged::Busy);
                    };
                    HistoryVerifier::Inclusion(InclusionVerifier::new(verified, header, proof)?)
                }
                (ProofKind::Consistency, Proof::Consistency { prefix, proof }) => {
                    if proof.from != *from
                        || proof.to != *to
                        || *to != signed.root.leaves
                        || prefix.leaves != *from
                    {
                        return Err(invalid("consistency response interval differs"));
                    }
                    HistoryVerifier::Consistency(ConsistencyVerifier::new(verified, prefix, proof)?)
                }
                (ProofKind::Control, Proof::Control(proof)) => {
                    if proof.head_id != *head || proof.lo != *from || proof.hi > *to {
                        return Err(invalid("control response interval widens request"));
                    }
                    binding.through = proof.hi;
                    HistoryVerifier::ControlRange(ControlRangeVerifier::new(verified, proof)?)
                }
                _ => return Err(invalid("proof response kind differs")),
            };
            drop(input);
            if !room.history_write_tracked(store, committed, |index| {
                index.keep_history_verifier_cursor(binding, &cursor)
            })? {
                return Ok(Staged::Busy);
            }
            Ok(Staged::Verifier(binding))
        }
        _ => Err(invalid("metadata is unrelated to requested object")),
    }
}

#[allow(clippy::too_many_arguments)]
fn stage_header(
    room: &impl HistoryAdmissionRoom,
    store: &Store,
    committed: &std::sync::atomic::AtomicBool,
    head_id: Digest32,
    lo: u64,
    hi: u64,
    bytes: &[u8],
    work: &mut WorkBudget,
) -> Result<Staged> {
    let entry = Entry::from_wire(bytes)?;
    if entry.payload.is_some() || entry.skeleton.seq < lo || entry.skeleton.seq > hi {
        return Err(invalid("requested header position/body differs"));
    }
    let input = room.history_read(store)?;
    let head = input
        .history_head(&head_id)?
        .ok_or(invalid("header target head is absent"))?;
    if entry.skeleton.seq > head.root.leaves {
        return Err(invalid("header exceeds target head"));
    }
    let key = room
        .history_author_key(&head.binding.author)
        .ok_or(invalid("unknown header author"))?;
    let HistoryStep::Complete(header) = VerifiedHeader::verify(&entry, head.binding, &key, work)?
    else {
        return Ok(Staged::Busy);
    };
    // A header already held is not saved again (ADR-038 FX-29): a live retry of a missing body
    // receives its header with every answer, and each one committed the same header and pending
    // position unchanged. Held: published at this position under a head in the accepted chain,
    // or pending (kept by position under an accepted head, whichever accepted head brought it;
    // else under this head).
    let published = if input.history_head_accepted(&head_id, head.binding)? {
        input.history_position_header(&head.binding.author, entry.skeleton.seq)?
    } else {
        None
    };
    let held = published
        .or(input.history_pending_header(&head_id, entry.skeleton.seq)?)
        .is_some_and(|held| held.entry_hash() == entry.entry_hash());
    drop(input);
    if held {
        return Ok(Staged::Header);
    }
    room.history_write_tracked(store, committed, |index| {
        index.keep_history_header(&header)?;
        index.keep_history_pending_header(&head_id, &header)
    })?;
    Ok(Staged::Header)
}

/// Contexts generated while a structurally bounded proof runs to its end. Committing a context
/// and cursor after every Merkle join was ~64% of the idle daemon's commit time (ADR-038 FX-29).
/// The original proof bytes stay in the sealed verifier record, so a crash re-verifies from them;
/// incomplete progress is never durable.
struct Overlay<'a> {
    inner: &'a entry_store::Read<'a>,
    generated: std::cell::RefCell<Vec<(Digest32, ControlContext)>>,
}
impl crate::log::history::ContextSource for Overlay<'_> {
    fn context(&self, hash: &Digest32) -> Result<Option<ControlContext>> {
        if let Some((_, context)) = self
            .generated
            .borrow()
            .iter()
            .find(|(generated, _)| generated == hash)
        {
            return Ok(Some(context.clone()));
        }
        self.inner.history_context(hash)
    }
}
pub(super) enum Advanced {
    Progress,
    MissingContext(Digest32),
    Need(Query),
    Complete,
    Busy,
    /// MP-9: two signed entries of one author at one position, one under the accepted chain
    /// and one under another signed head. The caller records it as a fork.
    Fork(Box<(Entry, Entry)>),
}

/// One verifier turn runs the bounded proof to its end. Primitive cooperative slices replenish
/// their work credit in memory; neither a slice boundary nor a missing context writes generated
/// nodes or an advanced cursor. Only a completed proof commits its generated contexts with its
/// receipt/final cursor. A crash or missing-context retry starts from the retained original proof
/// bytes. A missing proof is never fork evidence.
pub(super) fn advance(
    room: &impl HistoryAdmissionRoom,
    store: &Store,
    committed: &std::sync::atomic::AtomicBool,
    binding: &CursorBinding,
) -> Result<Advanced> {
    if room.history_publication_busy(store)? {
        return Ok(Advanced::Busy);
    }
    let input = room.history_read(store)?;
    let Some(mut cursor) = input.history_verifier_cursor(*binding)? else {
        return Ok(Advanced::Complete);
    };
    let key = room
        .history_author_key(&binding.author)
        .ok_or(local("verifier author is no longer admitted"))?;
    let mut work = WorkBudget::default();
    // A bounded transient result covered by the existing verifier working reservation.
    #[allow(clippy::large_enum_variant)]
    enum ResultStep {
        Missing(Digest32),
        Included(crate::log::history::IncludedHeader),
        Prefix(crate::log::history::ConsistentPrefix),
        Controls(crate::log::history::VerifiedControlRange),
    }
    let overlay = Overlay {
        inner: &input,
        generated: std::cell::RefCell::new(Vec::new()),
    };
    let result = loop {
        let step = match &mut cursor {
            HistoryVerifier::Inclusion(value) => match value.advance(&overlay, &mut work)? {
                HistoryStep::Complete(value) => break ResultStep::Included(value),
                HistoryStep::Progress(value) => value,
                HistoryStep::MissingContext(hash) => break ResultStep::Missing(hash),
                HistoryStep::Yielded => {
                    work = WorkBudget::default();
                    continue;
                }
            },
            HistoryVerifier::Consistency(value) => match value.advance(&overlay, &mut work)? {
                HistoryStep::Complete(value) => break ResultStep::Prefix(value),
                HistoryStep::Progress(value) => value,
                HistoryStep::MissingContext(hash) => break ResultStep::Missing(hash),
                HistoryStep::Yielded => {
                    work = WorkBudget::default();
                    continue;
                }
            },
            HistoryVerifier::ControlRange(value) => {
                match value.advance(&key, &overlay, &mut work)? {
                    HistoryStep::Complete(value) => break ResultStep::Controls(value),
                    HistoryStep::Progress(value) => value,
                    HistoryStep::MissingContext(hash) => break ResultStep::Missing(hash),
                    HistoryStep::Yielded => {
                        work = WorkBudget::default();
                        continue;
                    }
                }
            }
            HistoryVerifier::Validation(_) => {
                return Err(local("entry closure requires the admission driver"))
            }
        };
        overlay.generated.borrow_mut().push((step.hash(), step));
    };
    let generated = overlay.generated.into_inner();
    // Only completed verifiers expose their exact input/reconstructed ranges. These
    // objects are serving-only: a signed proof is not a consistency/authority verdict.
    let ranges = match (&result, &mut cursor) {
        (ResultStep::Included(_), HistoryVerifier::Inclusion(v)) => v.take_verified_ranges()?,
        (ResultStep::Prefix(_), HistoryVerifier::Consistency(v)) => v.take_verified_ranges()?,
        (ResultStep::Controls(_), HistoryVerifier::ControlRange(v)) => {
            let mut ranges = v.take_verified_ranges()?;
            // Preorder (start, then the larger node first): every node precedes the nodes
            // inside it. The Controls arm below relies on it.
            ranges.sort_unstable_by(|(a, x), (b, y)| a.cmp(b).then(y.leaves.cmp(&x.leaves)));
            ranges
        }
        (ResultStep::Missing(_), _) => Vec::new(),
        _ => return Err(local("completed proof range kind")),
    };
    drop(input);
    let keep_generated = |index: &mut entry_store::Write<'_, '_>| -> Result<()> {
        for (_, context) in &generated {
            index.keep_history_context(context)?;
        }
        Ok(())
    };
    let tree = crate::log::history::TreeBinding {
        room: binding.room,
        scope: LogScope::Public,
        author: binding.author,
    };
    // A durable inclusion/prefix receipt keeps, in its own transaction, exactly the verified
    // pieces that serve it again under this head: the inclusion siblings or the consistency
    // nodes (ADR-052 RG-6). Reconstructed ancestors stay cache-only. Control coverage keeps its
    // whole verified trace (ADR-053 MP-7, MP-8): see the Controls arm below.
    let keep_witness = |index: &mut entry_store::Write<'_, '_>,
                        needed: Vec<crate::log::history::TreeRange>|
     -> Result<()> {
        let mutant = witness_mutant();
        if mutant == Some(WitnessMutant::Unkept) {
            return Ok(());
        }
        for (start, descriptor) in &ranges {
            let range = crate::log::history::TreeRange {
                start: *start,
                leaves: descriptor.leaves,
            };
            if needed.contains(&range) || mutant == Some(WitnessMutant::EveryTrace) {
                index.keep_history_proof_range(binding.head, tree, *start, *descriptor)?;
            }
        }
        Ok(())
    };
    let cache_ranges = || -> Result<()> {
        for (start, descriptor) in &ranges {
            entry_store::sparse::cache_history_proof_range(
                binding.head,
                tree,
                *start,
                *descriptor,
            )?;
        }
        Ok(())
    };
    match result {
        ResultStep::Missing(hash) => Ok(Advanced::MissingContext(hash)),
        ResultStep::Included(included) => {
            room.history_write_tracked(store, committed, |index| {
                keep_generated(index)?;
                keep_witness(
                    index,
                    crate::log::history::inclusion_ranges(
                        included.header().entry().skeleton.seq,
                        included.root().leaves,
                    )?,
                )?;
                index.keep_history_inclusion_receipt(&included)?;
                index.finish_history_verifier_cursor(*binding)
            })?;
            cache_ranges()?;
            // The head first, as an answer's check does (bundle.rs): a receipt kept under a head
            // this promotion commits gets its locator by author and position.
            let advanced = promote_head(room, store, committed, binding.head)?;
            combine_parent(
                room,
                store,
                committed,
                binding.head,
                binding.author,
                binding.from,
            )?;
            keep_blocks(room, store, committed, binding.head, tree, &ranges)?;
            Ok(advanced)
        }
        ResultStep::Prefix(prefix) => {
            let accepted_before = room
                .history_read(store)?
                .history_head_accepted(&binding.head, tree)?;
            room.history_write_tracked(store, committed, |index| {
                keep_generated(index)?;
                keep_witness(
                    index,
                    crate::log::history::consistency_ranges(
                        prefix.prefix().leaves,
                        prefix.root().leaves,
                    )?,
                )?;
                // Under its head only, unless that head is already accepted: its range [1, n]
                // is a fact of the accepted chain only once the head is (MP-9).
                index.keep_history_prefix_receipt(&prefix)?;
                index.finish_history_verifier_cursor(*binding)
            })?;
            cache_ranges()?;
            // The head first (as above).
            let advanced = promote_head(room, store, committed, binding.head)?;
            // A head this promotion accepted: the prefix's range [1, n] is now the accepted
            // chain's (`keep_history_prefix_receipt` writes it only under an accepted head).
            if !accepted_before
                && room
                    .history_read(store)?
                    .history_head_accepted(&binding.head, tree)?
            {
                room.history_write_tracked(store, committed, |index| {
                    index.keep_history_prefix_receipt(&prefix)
                })?;
            }
            combine_parent(
                room,
                store,
                committed,
                binding.head,
                binding.author,
                binding.from,
            )?;
            keep_blocks(room, store, committed, binding.head, tree, &ranges)?;
            Ok(advanced)
        }
        ResultStep::Controls(controls) => {
            let input = room.history_read(store)?;
            // Accepted, not merely committed: a control range is frequently about an
            // earlier head of the author's chain — the head the join's control records
            // were sealed under — and an earlier head is proven on the committed chain,
            // never itself the committed head. Gating on `committed` alone meant such a
            // range could never complete: the promotion below proved the head on the
            // chain and returned Complete without committing it, this step re-ran, the
            // gate was still false, and the verify/proof fetches looped for the whole
            // window while every read refused. `history_head_accepted` is the same
            // predicate for the committed head and additionally accepts an earlier head
            // whose prefix range — persisted by the consistency receipt the promotion
            // fetched — matches its own root.
            let accepted = input.history_head_accepted(&controls.head_id(), controls.binding())?;
            drop(input);
            if !accepted {
                // The staged cursor is left as it was, unverified: the next turn, after the
                // promotion, verifies the range again from its retained proof bytes, so the
                // completion below holds the whole trace to keep. A cursor restored from a
                // finished checkpoint carries only the proof's collapse tokens (ADR-053 MP-7).
                room.history_write_tracked(store, committed, |index| keep_generated(index))?;
                cache_ranges()?;
                return Ok(match promote_head(room, store, committed, binding.head)? {
                    Advanced::Complete => Advanced::Progress,
                    other => other,
                });
            }
            // The coverage owns, in its own transaction, the verified trace the serving walk
            // visits again under this exact head for any interval inside this one, the root
            // included (ADR-053 MP-7; MP-8's full closure). That walk (`Source::control_proof`)
            // collapses a node without controls, so nothing inside one is kept: a proof may
            // still expand such a node and verify, and those pieces stay cache-only. In
            // preorder a node inside the last kept node without controls starts at or before
            // its end. Coverage rows are never retired, so neither are these.
            room.history_write_tracked(store, committed, |index| {
                keep_generated(index)?;
                if witness_mutant() != Some(WitnessMutant::ControlUnkept) {
                    let mut collapsed = 0;
                    for (start, descriptor) in &ranges {
                        if *start <= collapsed {
                            continue;
                        }
                        index.keep_history_proof_range(binding.head, tree, *start, *descriptor)?;
                        if descriptor.controls == 0 {
                            collapsed = start + descriptor.leaves - 1;
                        }
                    }
                    index.keep_history_blocks(tree, &ranges)?;
                }
                if let entry_store::sparse::CoverageKept::Partial =
                    index.keep_control_coverage(&controls, 0)?
                {
                    return Err(local("bounded control coverage unexpectedly incomplete"));
                }
                index.finish_history_verifier_cursor(*binding)
            })?;
            cache_ranges()?;
            Ok(Advanced::Complete)
        }
    }
}

/// The full aligned blocks of a trace verified under `head`, kept by author and position once
/// `head` is on this node's accepted chain of the author (`keep_history_blocks`): run after the
/// promotion that may have accepted it. Under a head that is not accepted, the trace keeps only
/// what its owner kept under that head. A block already held writes nothing.
pub(super) fn keep_blocks(
    room: &impl HistoryAdmissionRoom,
    store: &Store,
    committed: &std::sync::atomic::AtomicBool,
    head: Digest32,
    tree: crate::log::history::TreeBinding,
    trace: &[(u64, Descriptor)],
) -> Result<()> {
    let input = room.history_read(store)?;
    if !input.history_head_accepted(&head, tree)? {
        return Ok(());
    }
    let mut blocks: Vec<(u64, Descriptor)> = trace
        .iter()
        .filter(|(start, descriptor)| entry_store::sparse::full_block(*start, descriptor.leaves))
        .copied()
        .collect();
    blocks.sort_unstable_by_key(|(start, descriptor)| (*start, descriptor.leaves));
    blocks.dedup_by_key(|(start, descriptor)| (*start, descriptor.leaves));
    let mut new = Vec::with_capacity(blocks.len());
    for (start, descriptor) in blocks {
        if input
            .history_range(tree, start, descriptor.leaves)?
            .is_none()
        {
            new.push((start, descriptor));
        }
    }
    drop(input);
    if new.is_empty() {
        return Ok(());
    }
    room.history_write_tracked(store, committed, |index| {
        index.keep_history_blocks(tree, &new)
    })
}

/// The inclusion receipt of `author`'s entry `seq`: under `head`, the head it was handed over
/// under, else under the committed head its receipt is located by (`history_parent_head`). A
/// position is one entry under every committed head of its author, so a receipt an answer
/// brought under any of them serves; the caller still compares it with the entry.
fn entry_inclusion(
    input: &entry_store::Read<'_>,
    head: &Digest32,
    author: &Digest32,
    seq: u64,
) -> Result<Option<crate::log::history::IncludedHeader>> {
    if let Some(included) = input.history_inclusion_receipt(head, author, seq)? {
        return Ok(Some(included));
    }
    match input.history_parent_head(author, seq)? {
        Some(located) => input.history_inclusion_receipt(&located, author, seq),
        None => Ok(None),
    }
}

/// What stands for position `seq` of `author` as a parent: ONE lookup by author and position on
/// the accepted chain, for every reader (`start_entry`, `preflight`, and an answer's leading
/// receipt in `bundle::check`). The caller compares its header with the hash it names.
///
/// - Published here: the position itself. Its own admission validated it under a committed head
///   of its author (commitments are never undone) after requiring its prefix [1, seq]
///   (`start_entry`, in every version since sparse history; an own append commits that range
///   with its head), and ranges are never deleted; so the published header, the author's
///   committed head and that range are the parent. This is what a store written before
///   `ParentHead` locators existed holds for every position it admitted.
/// - Else a parent receipt an answer proved, located by position (`history_parent_head`).
/// - Else none: the caller asks for the receipt.
///
/// A published position without its range, or a locator without its receipt, is a fault of
/// this node's store, never a need: a need for a position that is admitted here is met at once
/// by every plan (`pull.rs` `choose`), so it must never be what admission returns for it. This
/// is the parent's identity; admission then checks a published parent's range against its own
/// whole context before following it (`SparseParent::check_published`), the same local fault.
pub(super) fn parent_evidence(
    input: &entry_store::Read<'_>,
    author: &Digest32,
    seq: u64,
) -> Result<Option<governance::SparseParent>> {
    if let Some(header) = input.history_position_header(author, seq)? {
        let head = input
            .sparse_author(author, LogScope::Public)?
            .and_then(|state| state.committed)
            .ok_or(local("published parent has no committed head"))?;
        let binding = input
            .history_head(&head)?
            .ok_or(local("parent target missing"))?
            .binding;
        let prefix = input
            .history_range(binding, 1, seq)?
            .ok_or(local("published parent has no prefix range"))?;
        return Ok(Some(governance::SparseParent::Published {
            head,
            binding,
            header,
            prefix,
        }));
    }
    let Some(located) = input.history_parent_head(author, seq)? else {
        return Ok(None);
    };
    input
        .history_parent_receipt(&located, author, seq)?
        .ok_or(local("located parent receipt missing"))
        .map(|receipt| Some(governance::SparseParent::Receipt(receipt)))
}

pub(super) fn combine_parent(
    room: &impl HistoryAdmissionRoom,
    store: &Store,
    committed: &std::sync::atomic::AtomicBool,
    head: Digest32,
    author: Digest32,
    seq: u64,
) -> Result<()> {
    let input = room.history_read(store)?;
    let included = input.history_inclusion_receipt(&head, &author, seq)?;
    let prefix = input.history_prefix_receipt(&head, &author, seq)?;
    // MP-9: an unlinked prefix makes no parent receipt; it is not the accepted chain.
    let prefix = match prefix {
        Some(prefix) if unlinked_prefix(&input, &prefix)? => None,
        other => other,
    };
    drop(input);
    if let (Some(included), Some(prefix)) = (included, prefix) {
        let parent = governance::VerifiedParentPrefix::new(included, prefix)?;
        room.history_write_tracked(store, committed, |index| {
            index.keep_history_parent_receipt(&parent)
        })?;
    }
    Ok(())
}

pub(super) fn promote_head(
    room: &impl HistoryAdmissionRoom,
    store: &Store,
    committed: &std::sync::atomic::AtomicBool,
    id: Digest32,
) -> Result<Advanced> {
    let input = room.history_read(store)?;
    let signed = input
        .history_head(&id)?
        .ok_or(local("promotion head missing"))?;
    if input.history_head_accepted(&id, signed.binding)? {
        return Ok(Advanced::Complete);
    }
    let (baseline_id, baseline) = match input
        .sparse_author(&signed.binding.author, signed.binding.scope)?
        .and_then(|state| state.committed)
    {
        Some(old) => {
            let root = input
                .history_head(&old)?
                .ok_or(local("accepted baseline missing"))?
                .root;
            (Some(old), root)
        }
        None => (None, Descriptor::empty(signed.binding)),
    };
    if let Some((outcome, unresolved)) = unequal(&input, id, &signed, baseline_id, baseline)? {
        if let (true, Advanced::Need(query)) = (unresolved, &outcome) {
            // MP-9 (rule 6): the comparison waits for evidence a later peer may hold. The head
            // is owned as this author's unresolved observation: listed, served by its id and
            // compared again after a restart; never accepted by being kept.
            let author = signed.binding.author;
            let kept = input.history_unresolved_head(&author)? == Some(id);
            drop(input);
            let keep = !kept && !fork_mutant_is("second-head-unkept");
            if keep {
                room.history_write_tracked(store, committed, |index| {
                    index.keep_history_unresolved_head(&author, &id)
                })?;
            }
            #[cfg(feature = "test-knobs")]
            eprintln!(
                "history comparison unresolved author={} head={} kept={} awaits={}",
                crate::node::link::b32_encode(&author),
                crate::node::link::b32_encode(&id),
                kept || keep,
                match query {
                    Query::Header { head, .. } if Some(*head) == baseline_id => "accepted-side",
                    Query::Header { .. } => "other-side",
                    _ => "proof",
                }
            );
            #[cfg(not(feature = "test-knobs"))]
            let _ = query;
        }
        return Ok(outcome);
    }
    let prefix = input
        .history_prefix_receipt(&id, &signed.binding.author, baseline.leaves)?
        .ok_or(local("promotion consistency receipt vanished"))?;
    if signed.root.leaves != 0
        && input
            .history_inclusion_receipt(&id, &signed.binding.author, signed.root.leaves)?
            .is_none()
    {
        return Ok(Advanced::Need(Query::Header {
            head: id,
            seq: signed.root.leaves,
        }));
    }
    let key = room
        .history_author_key(&signed.binding.author)
        .ok_or(local("head author disappeared"))?;
    let HistoryStep::Complete(verified) = signed.verify(&key, &mut WorkBudget::default())? else {
        return Ok(Advanced::Busy);
    };
    drop(input);
    let conflict = if signed.binding.author == room.me() {
        room.history_write_own_head_tracked(store, committed, |index| {
            index.commit_history_head(&verified, &prefix)
        })?
    } else {
        room.history_write_tracked(store, committed, |index| {
            index.commit_history_head(&verified, &prefix)
        })?
    };
    if conflict {
        return Err(invalid("conflicting authenticated heads retained"));
    }
    // Staging evidence for the ADR-053 P acts: which head of which author this node committed.
    #[cfg(feature = "test-knobs")]
    eprintln!(
        "vox: history head committed author={} size={}",
        crate::node::link::b32_encode(&signed.binding.author),
        signed.root.leaves
    );
    // A newly accepted remote head changes what this room must advertise. The actor touches
    // the room on completion so every port observes this generation immediately and can echo
    // the exact head back to its author.
    room.generation()
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(Advanced::Complete)
}

pub(super) enum EntryStart {
    Preflight,
    BodyNeeded,
    Cursor(CursorBinding),
    Need(Query),
    Busy,
}

/// Start structural/typed-body closure only after exact inclusion. The body may be absent
/// for ordinary content or a recipient-scoped key package; that never claims its effect.
// All scalar bindings belong to this exact entry and current validation phase.
#[allow(clippy::too_many_arguments)]
pub(super) fn start_entry(
    room: &impl HistoryAdmissionRoom,
    store: &Store,
    committed: &std::sync::atomic::AtomicBool,
    request: RequestId,
    generation: Digest32,
    head: Digest32,
    entry: &Entry,
    require_body: bool,
    context_ready: bool,
) -> Result<EntryStart> {
    if room.history_publication_busy(store)? {
        return Ok(EntryStart::Busy);
    }
    let input = room.history_read(store)?;
    let author = entry.skeleton.author_id;
    let seq = entry.skeleton.seq;
    let Some(included) = entry_inclusion(&input, &head, &author, seq)? else {
        return Ok(EntryStart::Need(Query::Proof {
            head,
            kind: ProofKind::Inclusion,
            from: seq,
            to: seq,
        }));
    };
    if included.header().entry().header_wire() != entry.header_wire() {
        return Err(invalid("entry differs from exact inclusion"));
    }
    // The entry is verified under the head its receipt is kept under, which may be a committed
    // head other than the one it was handed over with (`entry_inclusion`): every per-head state
    // this verification makes (its cursor binding, its needs) names that one head, so a
    // checkpoint never meets a target other than its own.
    let head = included.head_id();
    // The validator's own predicate (`governance::sparse` `advance`): an entry is admitted only
    // under a head committed here, which stays committed once it is.
    if !input.history_head_committed(&included.head_id(), included.binding())? {
        drop(input);
        return match promote_head(room, store, committed, head)? {
            Advanced::Need(query) => Ok(EntryStart::Need(query)),
            // The verifier path that opened the competing entry records the fork; an entry
            // under a head proven to be another history is never started.
            Advanced::Fork(_) => Err(invalid("entry head is a competing signed history")),
            // An older prefix of the committed head is complete without being committed, and
            // never is: no entry is handed over under one (`pull.rs` exchange), and one here
            // fails its root. A head this promotion committed starts the entry again.
            Advanced::Complete
                if !room
                    .history_read(store)?
                    .history_head_committed(&head, included.binding())? =>
            {
                Err(invalid("entry head is not committed"))
            }
            _ => Ok(EntryStart::Busy),
        };
    }
    let target = input
        .history_head(&head)?
        .ok_or(local("entry target head missing"))?;
    if input.history_range(target.binding, 1, seq)?.is_none() {
        // A settled entry is eligible to become an explicit parent of the next local append.
        // Retain its exact authenticated prefix before effects can mark it settled; inclusion
        // in a newer head alone does not construct that prefix. The actual author retains each
        // historical local root and can serve this ordinary consistency proof.
        return Ok(EntryStart::Need(Query::Proof {
            head,
            kind: ProofKind::Consistency,
            from: seq,
            to: target.root.leaves,
        }));
    }
    let key = room
        .history_author_key(&author)
        .ok_or(local("entry author is unknown"))?;
    let v2 = entry
        .skeleton
        .v2
        .as_ref()
        .ok_or(invalid("entry is not typed"))?;
    // ADR-053 M0: an ordinary Content entry's `seen` are ordering hints; only its own
    // predecessor needs a receipt here. Controls keep one per reference.
    let seen = governance::checked_seen(v2);
    let mut references = Vec::with_capacity(seen.len() + 1);
    if seq > 1 {
        references.push(crate::log::history::EntryReference {
            author,
            seq: seq - 1,
            hash: entry.skeleton.prev_hash,
        });
    }
    references.extend(seen.iter().cloned());
    let mut parents = Vec::with_capacity(references.len());
    for reference in references {
        // A validated parent must still be the entry it names.
        if let Some((_, held)) = input.history_validated_header(&reference.author, reference.seq)? {
            if held.entry_hash() != reference.hash {
                return Err(invalid("signed parent differs from validated position"));
            }
        }
        if let Some(parent) = parent_evidence(&input, &reference.author, reference.seq)? {
            // Before preflight follows its frontier: a published parent's positional prefix
            // must be its own whole context, else a local fault of this store.
            parent.check_published(&input)?;
            parents.push(parent);
            continue;
        }
        // Neither published here nor proven by an answer: its receipt is asked under the
        // author's committed head, and its admission or an answer that brings it meets that.
        let Some(parent_head) = input
            .sparse_author(&reference.author, LogScope::Public)?
            .and_then(|state| state.committed)
        else {
            return Ok(EntryStart::Need(Query::Head(reference.author)));
        };
        let target = input
            .history_head(&parent_head)?
            .ok_or(local("parent target missing"))?;
        if target.root.leaves < reference.seq {
            return Ok(EntryStart::Need(Query::Head(reference.author)));
        }
        if input
            .history_pending_header(&parent_head, reference.seq)?
            .is_none()
        {
            return Ok(EntryStart::Need(Query::Header {
                head: parent_head,
                seq: reference.seq,
            }));
        }
        if input
            .history_inclusion_receipt(&parent_head, &reference.author, reference.seq)?
            .is_none()
        {
            return Ok(EntryStart::Need(Query::Proof {
                head: parent_head,
                kind: ProofKind::Inclusion,
                from: reference.seq,
                to: reference.seq,
            }));
        }
        return Ok(EntryStart::Need(Query::Proof {
            head: parent_head,
            kind: ProofKind::Consistency,
            from: reference.seq,
            to: target.root.leaves,
        }));
    }
    if !context_ready {
        return Ok(EntryStart::Preflight);
    }
    // Public control admission can retain an authenticated key-package header while the
    // recipient's durable body obligation is serviced independently.
    if require_body && entry.payload.is_none() {
        return Ok(EntryStart::BodyNeeded);
    }
    let body = match governance::TypedSparseBody::verify(entry, &key, &mut WorkBudget::default())? {
        governance::PayloadValidation::Complete(body) => body,
        governance::PayloadValidation::BodyRequired => {
            return Ok(EntryStart::Need(Query::Entry {
                head,
                seq,
                offset: 0,
            }))
        }
        governance::PayloadValidation::Yielded => return Ok(EntryStart::Busy),
    };
    let cursor = governance::SparseValidation::new(included, body, parents)?;
    let binding = CursorBinding {
        request,
        room: room.channel_id(),
        head,
        author,
        proof_kind: 3,
        from: seq,
        through: seq,
        generation,
    };
    drop(input);
    if !room.history_write_tracked(store, committed, |index| {
        index.keep_history_verifier_cursor(binding, &HistoryVerifier::Validation(cursor))
    })? {
        return Ok(EntryStart::Busy);
    }
    Ok(EntryStart::Cursor(binding))
}

// A bounded transient result covered by the existing verifier working reservation.
#[allow(clippy::large_enum_variant)]
pub(super) enum EntryAdvanced {
    Progress,
    Need(Query),
    ControlPending { head: Digest32, through: u64 },
    ControlSource { head: Digest32, seq: u64 },
    Validated(governance::ValidatedSparseEntry),
    Busy,
}

pub(super) fn advance_entry(
    room: &impl HistoryAdmissionRoom,
    store: &Store,
    committed: &std::sync::atomic::AtomicBool,
    binding: CursorBinding,
) -> Result<EntryAdvanced> {
    if room.history_publication_busy(store)? {
        return Ok(EntryAdvanced::Busy);
    }
    let input = room.history_read(store)?;
    let Some(HistoryVerifier::Validation(mut cursor)) = input.history_verifier_cursor(binding)?
    else {
        return Err(local("entry validation cursor missing"));
    };
    let result = cursor.advance(&input, &mut WorkBudget::default())?;
    let outcome = match result {
        governance::SparseValidationStep::Complete(token) => {
            // Keep the prior sealed cursor: publication's next slice can re-create the token
            // from the same final bounded validation step without serializing an authority token.
            return Ok(EntryAdvanced::Validated(token));
        }
        governance::SparseValidationStep::MissingContext(hash) => {
            EntryAdvanced::Need(Query::Context(hash))
        }
        governance::SparseValidationStep::MissingControl(reference) => {
            match input
                .sparse_author(&reference.author, LogScope::Public)?
                .and_then(|state| state.committed)
            {
                Some(head) => {
                    let target = input
                        .history_head(&head)?
                        .ok_or(local("control head missing"))?;
                    if target.root.leaves < reference.seq {
                        EntryAdvanced::Need(Query::Head(reference.author))
                    } else {
                        EntryAdvanced::ControlSource {
                            head,
                            seq: reference.seq,
                        }
                    }
                }
                None => EntryAdvanced::Need(Query::Head(reference.author)),
            }
        }
        governance::SparseValidationStep::ControlPrefixPending { head, through } => {
            EntryAdvanced::ControlPending { head, through }
        }
        governance::SparseValidationStep::Progress | governance::SparseValidationStep::Yielded => {
            EntryAdvanced::Progress
        }
    };
    drop(input);
    room.history_write_tracked(store, committed, |index| {
        if !index.keep_history_verifier_cursor(binding, &HistoryVerifier::Validation(cursor))? {
            return Err(local("existing entry verifier capacity vanished"));
        }
        Ok(())
    })?;
    Ok(outcome)
}

/// Scheduling preflight only: never an authority/admission token. Resolve the exact parent's
/// authenticated frontier as well as the claimed pre-context, so an underclaim cannot occupy
/// the sole control-body slot before its omitted prerequisite control has been received.
pub(super) enum Preflight {
    Progress {
        parent: usize,
        next: usize,
    },
    Need(Query),
    Control {
        head: Digest32,
        through: u64,
        effects: bool,
    },
    Complete,
    Busy,
}
/// Read-only: it runs on the room under a read and writes nothing.
pub(super) fn preflight(
    room: &crate::node::channel::ChannelState,
    store: &Store,
    head: Digest32,
    entry: &Entry,
    parent: usize,
    next: usize,
) -> Result<Preflight> {
    if room.history_publication_busy(store)? {
        return Ok(Preflight::Busy);
    }
    let input = room.history_read(store)?;
    let Some(included) =
        entry_inclusion(&input, &head, &entry.skeleton.author_id, entry.skeleton.seq)?
    else {
        return Ok(Preflight::Need(Query::Proof {
            head,
            kind: ProofKind::Inclusion,
            from: entry.skeleton.seq,
            to: entry.skeleton.seq,
        }));
    };
    if included.header().entry().header_wire() != entry.header_wire() {
        return Err(invalid("preflight differs from exact inclusion"));
    }
    let v2 = entry
        .skeleton
        .v2
        .as_ref()
        .ok_or(invalid("preflight header is legacy"))?;
    let own = usize::from(entry.skeleton.seq > 1);
    let seen = governance::checked_seen(v2);
    let parent_count = own + seen.len();
    // A cursor captured before ADR-053 M0 may still point past Content's own parent at a
    // hint it no longer needs: resume at the context phase.
    let (parent, next) =
        if v2.kind == crate::log::history::SignedEntryKind::Content && parent > parent_count {
            (parent_count, 0)
        } else {
            (parent, next)
        };
    if parent > parent_count {
        return Err(local("preflight parent cursor"));
    }
    let context_id = if parent == parent_count {
        v2.pre_context
    } else {
        let reference = if own == 1 && parent == 0 {
            crate::log::history::EntryReference {
                author: entry.skeleton.author_id,
                seq: entry.skeleton.seq - 1,
                hash: entry.skeleton.prev_hash,
            }
        } else {
            seen[parent - own].clone()
        };
        if let Some((_, prior)) =
            input.history_validated_header(&reference.author, reference.seq)?
        {
            if prior.entry_hash() != reference.hash {
                return Err(invalid("preflight parent position differs"));
            }
        }
        // One lookup, by author and position, as `start_entry` does.
        let Some(receipt) = parent_evidence(&input, &reference.author, reference.seq)? else {
            // Admission starts by acquiring every exact receipt. A changed current head can
            // require a fresh proof; it never permits substituting another parent position.
            let Some(parent_head) = input
                .sparse_author(&reference.author, LogScope::Public)?
                .and_then(|state| state.committed)
            else {
                return Ok(Preflight::Need(Query::Head(reference.author)));
            };
            let target = input
                .history_head(&parent_head)?
                .ok_or(local("preflight parent target missing"))?;
            if target.root.leaves < reference.seq {
                return Ok(Preflight::Need(Query::Head(reference.author)));
            }
            let included = input
                .history_inclusion_receipt(&parent_head, &reference.author, reference.seq)?
                .is_some();
            return Ok(Preflight::Need(Query::Proof {
                head: parent_head,
                kind: if included {
                    ProofKind::Consistency
                } else {
                    ProofKind::Inclusion
                },
                from: reference.seq,
                to: if included {
                    target.root.leaves
                } else {
                    reference.seq
                },
            }));
        };
        if receipt.header().entry_hash() != reference.hash {
            return Err(invalid("preflight parent receipt differs"));
        }
        // Before anything follows the frontier (`start_entry` checked it too; a resumed
        // preflight checks again).
        receipt.check_published(&input)?;
        let parent_head = receipt.head_id();
        // SparseValidation requires this exact parent prefix, not only the
        // control coordinates named in its frontier. Finish it before taking a body
        // slot; validation then cannot recursively discover an earlier control.
        let through = receipt.prefix().leaves;
        for effects in [false, true] {
            let complete = if effects {
                input.control_effects_complete(&parent_head, through)?
            } else {
                input.control_sources_complete(&parent_head, through)?
            };
            if !complete {
                return Ok(Preflight::Control {
                    head: parent_head,
                    through,
                    effects,
                });
            }
        }
        receipt.prefix().frontier
    };
    let Some(context) = input.history_context(&context_id)? else {
        return Ok(Preflight::Need(Query::Context(context_id)));
    };
    if context.room != room.channel_id()
        || context.scope != v2.scope
        || next > context.coordinates.len()
    {
        return Err(invalid("preflight context/cursor differs"));
    }
    // One context and at most 16 exact coordinate/header/receipt lookups: <=64 objects.
    let end = (next + 16).min(context.coordinates.len());
    for coordinate in &context.coordinates[next..end] {
        let Some((control_head, control)) =
            input.history_validated_header(&coordinate.author, coordinate.seq)?
        else {
            let Some(control_head) = input
                .sparse_author(&coordinate.author, LogScope::Public)?
                .and_then(|state| state.committed)
            else {
                return Ok(Preflight::Need(Query::Head(coordinate.author)));
            };
            let target = input
                .history_head(&control_head)?
                .ok_or(local("preflight control head missing"))?;
            if target.root.leaves < coordinate.seq {
                return Ok(Preflight::Need(Query::Head(coordinate.author)));
            }
            // Advance the authenticated control range from its durable prefix.
            // Fetching its latest coordinate directly recursively descends the chain.
            return Ok(Preflight::Control {
                head: control_head,
                through: coordinate.seq,
                effects: false,
            });
        };
        if control.entry_hash() != coordinate.hash {
            return Err(invalid("preflight control coordinate differs"));
        }
        for effects in [false, true] {
            let complete = if effects {
                input.control_effects_complete(&control_head, coordinate.seq)?
            } else {
                input.control_sources_complete(&control_head, coordinate.seq)?
            };
            if !complete {
                return Ok(Preflight::Control {
                    head: control_head,
                    through: coordinate.seq,
                    effects,
                });
            }
        }
    }
    Ok(if end < context.coordinates.len() {
        Preflight::Progress { parent, next: end }
    } else if parent < parent_count {
        Preflight::Progress {
            parent: parent + 1,
            next: 0,
        }
    } else {
        Preflight::Complete
    })
}

#[cfg_attr(not(feature = "test-knobs"), allow(dead_code))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum WitnessMutant {
    /// A durable receipt is saved without the pieces that serve it again (before this repair).
    Unkept,
    /// Every range a completed proof touched is saved, reconstructed ancestors included.
    EveryTrace,
    /// Control coverage is saved without its verified trace (cache-only, before ADR-053 MP-7).
    ControlUnkept,
}

/// MP-9 (rules 6 and 7): where a signed head of another size than the accepted one stands
/// (an equal size with another root included). `None`: it extends the accepted chain and
/// today's promotion goes on. `Some((outcome, unresolved))`: the outcome, and whether it
/// belongs to an unresolved comparison (a `Need` there is evidence a later peer may hold).
/// Read-only.
fn unequal(
    input: &entry_store::Read<'_>,
    id: Digest32,
    signed: &SignedHead,
    baseline_id: Option<Digest32>,
    baseline: Descriptor,
) -> Result<Option<(Advanced, bool)>> {
    let author = signed.binding.author;
    if signed.root.leaves < baseline.leaves {
        let baseline_id = baseline_id.ok_or(local("nonempty baseline has no head"))?;
        let at = signed.root.leaves;
        // Rule 7: when both sides are already opened at m = |smaller head| they are compared
        // before any proof is asked of a peer that may hold only one of them; a different
        // signed entry there is a fork. Matching entries are not continuity.
        let mut opened = true;
        if at != 0 && !fork_mutant() {
            match compare_overlap(input, id, baseline_id, author, at)? {
                Overlap::Same => {
                    if input
                        .history_range(signed.binding, 1, at)?
                        .is_some_and(|held| held != signed.root)
                    {
                        let outcome = prefix_walk(input, id, baseline_id, author, at)?;
                        return Ok(Some((outcome, true)));
                    }
                }
                Overlap::Fork(fork) => return Ok(Some((Advanced::Fork(fork), true))),
                // Not opened yet: today's consistency check decides first, at today's cost.
                Overlap::Need(_) => opened = false,
            }
        }
        let Some(prefix) = input.history_prefix_receipt(&baseline_id, &author, at)? else {
            let need = Advanced::Need(Query::Proof {
                head: baseline_id,
                kind: ProofKind::Consistency,
                from: at,
                to: baseline.leaves,
            });
            return Ok(Some((need, !opened)));
        };
        if prefix.root() == baseline && prefix.prefix() != signed.root && !fork_mutant() {
            // The smaller head is not the accepted chain's prefix: both sides are opened at m,
            // then the prefixes below it.
            let outcome = match compare_overlap(input, id, baseline_id, author, at)? {
                Overlap::Same => prefix_walk(input, id, baseline_id, author, at)?,
                Overlap::Fork(fork) => Advanced::Fork(fork),
                Overlap::Need(query) => Advanced::Need(query),
            };
            return Ok(Some((outcome, true)));
        }
        if prefix.prefix() != signed.root || prefix.root() != baseline {
            return Err(invalid(
                "stale head differs from accepted consistency chain",
            ));
        }
        return Ok(Some((Advanced::Complete, false)));
    }
    if let (Some(baseline_id), true) = (
        baseline_id,
        signed.root.leaves == baseline.leaves && signed.root != baseline,
    ) {
        // Two signed heads of one size and different roots (this head is not accepted): both
        // are opened at that size, then the prefixes below it. A size-zero rival is refused.
        let at = baseline.leaves;
        if at == 0 {
            return Err(invalid("conflicting authenticated heads retained"));
        }
        let outcome = match compare_overlap(input, id, baseline_id, author, at)? {
            Overlap::Same => prefix_walk(input, id, baseline_id, author, at)?,
            Overlap::Fork(fork) => Advanced::Fork(fork),
            Overlap::Need(query) => Advanced::Need(query),
        };
        return Ok(Some((outcome, true)));
    }
    let Some(prefix) = input.history_prefix_receipt(&id, &author, baseline.leaves)? else {
        let need = Advanced::Need(Query::Proof {
            head: id,
            kind: ProofKind::Consistency,
            from: baseline.leaves,
            to: signed.root.leaves,
        });
        return Ok(Some((need, false)));
    };
    if prefix.prefix() != baseline {
        // Rule 7: the head does not extend the accepted one. Both sides are opened at the
        // accepted size, a position that fits both heads; a different signed entry there is a
        // fork, a matching one sends the comparison into the prefixes.
        if let (Some(baseline_id), false) = (baseline_id, fork_mutant()) {
            let at = baseline.leaves;
            let outcome = match compare_overlap(input, id, baseline_id, author, at)? {
                Overlap::Same => prefix_walk(input, id, baseline_id, author, at)?,
                Overlap::Fork(fork) => Advanced::Fork(fork),
                Overlap::Need(query) => Advanced::Need(query),
            };
            return Ok(Some((outcome, true)));
        }
        return Err(invalid(
            "consistency differs from current accepted baseline",
        ));
    }
    Ok(None)
}

/// MP-9 (rule 6): resume the comparison of `author`'s kept unresolved head, after a restart or
/// with a peer met later: the request it needs next, or the fork it already proves. Read-only;
/// what a peer brings is admitted by the ordinary verifiers and `promote_head`.
pub(super) fn unresolved_step(
    input: &entry_store::Read<'_>,
    author: &Digest32,
) -> Result<Option<Advanced>> {
    let Some(id) = input.history_unresolved_head(author)? else {
        return Ok(None);
    };
    comparison_step(input, author, id)
}

/// MP-9 (rule 6): the next step of comparing `author`'s held, not accepted head `id` (a head a
/// peer listed as unresolved and this node fetched by its id, or its own kept one) with the
/// accepted one: a request, or the fork the held openings already prove. Read-only.
pub(super) fn comparison_step(
    input: &entry_store::Read<'_>,
    author: &Digest32,
    id: Digest32,
) -> Result<Option<Advanced>> {
    let Some(signed) = input.history_head(&id)? else {
        return Ok(None);
    };
    if signed.binding.author != *author || input.history_head_accepted(&id, signed.binding)? {
        return Ok(None);
    }
    let Some(baseline_id) = input
        .sparse_author(author, signed.binding.scope)?
        .and_then(|state| state.committed)
    else {
        return Ok(None);
    };
    let baseline = input
        .history_head(&baseline_id)?
        .ok_or(local("accepted baseline missing"))?
        .root;
    // A resumed comparison asks a peer that kept this head what it proved under it: the
    // opening at the smaller size first, whichever head is larger. Matching there, today's
    // consistency check decides (`unequal`). A smaller kept head is not asked a consistency
    // proof under this node's own accepted head first: the peer that listed it may hold that
    // head only as an unresolved one and answer unavailable at every meeting, so the two sides
    // would never be compared. The ordinary promotion of a head keeps today's order and cost.
    let at = signed.root.leaves.min(baseline.leaves);
    if signed.root.leaves != baseline.leaves && at != 0 && !fork_mutant() {
        match compare_overlap(input, id, baseline_id, *author, at)? {
            Overlap::Fork(fork) => return Ok(Some(Advanced::Fork(fork))),
            Overlap::Need(query) => return Ok(Some(Advanced::Need(query))),
            Overlap::Same => {}
        }
    }
    // A refused comparison (Err) has nothing left to ask: it stays unresolved, never a fork.
    Ok(
        match unequal(input, id, &signed, Some(baseline_id), baseline) {
            Ok(Some((outcome @ (Advanced::Need(_) | Advanced::Fork(_)), _))) => Some(outcome),
            Ok(_) | Err(_) => None,
        },
    )
}

/// MP-9: one position compared under two signed heads of one author.
enum Overlap {
    /// The same entry, or one that cannot prove a fork (an expired skeleton without its
    /// signature): continuity is still checked as before.
    Same,
    /// Two different signed entries at one position.
    Fork(Box<(Entry, Entry)>),
    /// A side not opened yet. A peer that withholds it leaves the comparison pending.
    Need(Query),
}

/// Positions below a matching overlap that one comparison opens, nearest first. Past them the
/// head is refused as today and nothing is called a fork.
const MAX_PREFIX_WALK: u64 = 64;

/// MP-9 (rule 7): the entry at `at` under another signed head `head` and under the accepted
/// chain, each authenticated under its own root: the other by inclusion under `head` only (a
/// head not linked to the accepted chain borrows nothing from it); the accepted one as an
/// admitted position, or by inclusion under the accepted head or under any committed head of the
/// author its receipt is located by (`entry_inclusion`): one entry per position on that chain.
fn compare_overlap(
    input: &entry_store::Read<'_>,
    head: Digest32,
    accepted: Digest32,
    author: Digest32,
    at: u64,
) -> Result<Overlap> {
    let Some(other) = input.history_inclusion_receipt(&head, &author, at)? else {
        return Ok(Overlap::Need(Query::Header { head, seq: at }));
    };
    let held = if no_accepted_opening(&author) {
        None
    } else {
        match input.history_position_header(&author, at)? {
            Some(entry) => Some(entry),
            None => entry_inclusion(input, &accepted, &author, at)?
                .map(|included| included.header().entry().clone()),
        }
    };
    let Some(held) = held else {
        return Ok(Overlap::Need(Query::Header {
            head: accepted,
            seq: at,
        }));
    };
    let other = other.header().entry().clone();
    if held.entry_hash() == other.entry_hash() || !held.is_signed() || !other.is_signed() {
        return Ok(Overlap::Same);
    }
    Ok(Overlap::Fork(Box::new((held, other))))
}

/// MP-9 (rule 7): the two heads hold the same entry at `at` but different prefixes. Matching
/// one header is not a common prefix: the positions below are opened under both heads, nearest
/// first, until two different signed entries are found or a side is withheld (pending).
fn prefix_walk(
    input: &entry_store::Read<'_>,
    head: Digest32,
    accepted: Digest32,
    author: Digest32,
    at: u64,
) -> Result<Advanced> {
    if fork_mutant_is("terminal-header-only") {
        // The mutant: a matching terminal header ends the comparison, refused as before.
        return Err(invalid(
            "consistency differs from current accepted baseline",
        ));
    }
    for seq in (at.saturating_sub(MAX_PREFIX_WALK).max(1)..at).rev() {
        match compare_overlap(input, head, accepted, author, seq)? {
            Overlap::Same => {}
            Overlap::Fork(fork) => return Ok(Advanced::Fork(fork)),
            Overlap::Need(query) => return Ok(Advanced::Need(query)),
        }
    }
    Err(invalid(
        "consistency differs from current accepted baseline",
    ))
}

/// MP-9: a verified prefix that differs from the accepted chain's range of the same size. It is
/// another history's prefix: it makes no parent receipt (`combine_parent`).
fn unlinked_prefix(
    input: &entry_store::Read<'_>,
    prefix: &crate::log::history::ConsistentPrefix,
) -> Result<bool> {
    Ok(prefix.prefix().leaves != 0
        && input
            .history_range(prefix.binding(), 1, prefix.prefix().leaves)?
            .is_some_and(|held| held != prefix.prefix()))
}

/// `VOX_MUTANT_FORK` (MP-9): `equal-size-only`, heads of different sizes are never compared;
/// `second-head-unkept`, an unresolved second head is neither kept nor listed;
/// `fork-unpropagated`, a recorded fork is never listed to peers; `equal-rival-refused`, a head
/// of the accepted size with another root is refused at staging as before;
/// `terminal-header-only`, a matching entry at the overlap ends the comparison (no prefix walk).
/// Said once when first read.
#[cfg(feature = "test-knobs")]
pub(crate) fn fork_mutant_is(which: &str) -> bool {
    static VALUE: std::sync::LazyLock<Option<String>> = std::sync::LazyLock::new(|| {
        let value = std::env::var("VOX_MUTANT_FORK").ok();
        if let Some(value) = &value {
            eprintln!("vox: VOX_MUTANT_FORK={value} engaged");
        }
        value
    });
    VALUE.as_deref() == Some(which)
}

#[cfg(not(feature = "test-knobs"))]
pub(crate) const fn fork_mutant_is(_: &str) -> bool {
    false
}

fn fork_mutant() -> bool {
    fork_mutant_is("equal-size-only")
}

/// `VOX_TEST_NO_ACCEPTED_OPENING_FILE` (MP-9 staging): this daemon is a holder that kept an
/// author's accepted head but no opening of it: for the author named in the file, it never opens
/// the accepted side itself, and it serves no header, proof or entry under that accepted head
/// (server.rs). Heads, other heads' openings and fork proofs are unaffected.
#[cfg(feature = "test-knobs")]
pub(super) fn no_accepted_opening(author: &Digest32) -> bool {
    std::env::var_os("VOX_TEST_NO_ACCEPTED_OPENING_FILE")
        .and_then(|path| std::fs::read_to_string(path).ok())
        .is_some_and(|text| text.trim() == crate::node::link::b32_encode(author))
}

#[cfg(not(feature = "test-knobs"))]
const fn no_accepted_opening(_: &Digest32) -> bool {
    false
}

/// `VOX_MUTANT_WITNESS=unkept|every-trace|control-unkept`: says so once when the daemon first
/// reads it.
#[cfg(feature = "test-knobs")]
fn witness_mutant() -> Option<WitnessMutant> {
    static ON: std::sync::LazyLock<Option<WitnessMutant>> = std::sync::LazyLock::new(|| {
        let value = std::env::var("VOX_MUTANT_WITNESS").ok()?;
        eprintln!("vox: VOX_MUTANT_WITNESS={value} engaged: receipt witness pieces");
        match value.as_str() {
            "unkept" => Some(WitnessMutant::Unkept),
            "every-trace" => Some(WitnessMutant::EveryTrace),
            "control-unkept" => Some(WitnessMutant::ControlUnkept),
            _ => None,
        }
    });
    *ON
}

#[cfg(not(feature = "test-knobs"))]
const fn witness_mutant() -> Option<WitnessMutant> {
    None
}
