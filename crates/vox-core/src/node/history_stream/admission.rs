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

/// Rule F2 E and rule F3 (ledger 73): what a cross-author reference or signed-context
/// coordinate that this node's own record of its author contradicts waits for. A wait, never an
/// admission and never a refusal of the citing author.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ForkWait {
    /// The named entry differs from this node's validated one at `at`, and no fork proof of
    /// `author` with a boundary at or below `at` is recorded yet: park on that author's fork,
    /// woken when one is recorded (`pull::Need::Fork`); meanwhile a peer listing it is asked.
    Fork { author: Digest32, at: u64 },
    /// Rule F3 (sec-5 condition 3): a signed-context coordinate that is not this node's
    /// accepted control and names a certified proved splitter (the creator, or one with any
    /// creator-issued certificate held here) at or after its boundary. The citing entry waits
    /// as it was refused before this rule: only the splitter's matching entry there could meet
    /// the wait, and a frozen author's later entries are never accepted here
    /// (`pull::Need::Unmatched`).
    Unmatched(crate::log::history::EntryReference),
}

/// Rule F2 D: a `seen` reference naming a proved forker at or after its boundary requires no
/// entry and adds nothing (`fork_boundary` is that member's recorded boundary, if any).
fn seen_waived(boundary: Option<u64>, reference: &crate::log::history::EntryReference) -> bool {
    boundary.is_some_and(|boundary| reference.seq >= boundary) && !fork_mutant_is("seen-required")
}

/// Rule F2 E: a cross-author `seen` reference whose named entry differs from this node's
/// validated one at that position: two entries of one author at one place. It waits for that
/// fork to be recorded with a boundary that reaches it; once it is, the reference is waived.
fn mismatched_reference(
    boundary: Option<u64>,
    reference: &crate::log::history::EntryReference,
) -> Result<ForkWait> {
    if boundary.is_some_and(|boundary| reference.seq >= boundary) {
        // Only the mutant that requires the reference reaches here: today's refusal.
        return Err(invalid("signed parent differs from validated position"));
    }
    Ok(ForkWait::Fork {
        author: reference.author,
        at: reference.seq,
    })
}

/// Rule F3, scheduling side: a signed-context coordinate that is not this node's accepted
/// control and names a proved splitter at or after its boundary is passed over here, certified
/// or not. Preflight is never an authority token: the validator decides it only once every
/// other coordinate is resolved (`SparseValidation::advance`, sec-5 condition 2).
fn coordinate_deferred(
    splits: &governance::Splits,
    coordinate: &crate::log::history::EntryReference,
) -> bool {
    splits
        .reaching(&coordinate.author, coordinate.seq)
        .is_some()
}

/// Where an entry's admission operation goes on after it had to stop before Begin: at its start,
/// at the exact scalar position of its preflight, or inside validation. What it checked rides
/// with the entry in memory ([`Checked`]); without it, it goes on from its start (preflight
/// from its scalar position).
#[derive(Clone, Copy)]
pub(super) enum Resume {
    Start,
    Preflight { parent: usize, next: usize },
    Validate,
}

/// What an entry's admission operation checked before it stopped (JoinDesign S1), kept in
/// memory with the entry: by the flow for its continuation, by the frontier's `Ready` across a
/// wait (charged to the entry's assembly there), and resumed by the next operation instead of
/// being sealed in a cursor and re-derived from the start. Bound to the activation
/// (`generation`), the room, the head the entry was handed under and the entry itself; a
/// validation also to the fingerprint of the author's key its typed body was checked under.
/// Anything else drops it and the entry starts again. It holds no authority: Begin's token is
/// still made by validation's last step in the operation that runs Begin, and every step still
/// rechecks what can change (`SparseValidation::advance`: the entry's and the parent's heads
/// committed, the parent's whole context; the gates under the owned write).
pub(super) struct Checked {
    generation: Digest32,
    room: Digest32,
    head: Digest32,
    entry: Digest32,
    stage: Stage,
}

enum Stage {
    /// Its body is not held: what start established and preflight's position.
    Preflight {
        started: Started,
        at: (usize, usize),
    },
    /// Its typed body checked under the author's key `key` (a fingerprint), validation's exact
    /// cursor and the head its receipt is kept under (`binding`).
    Validate {
        validation: governance::SparseValidation,
        head: Digest32,
        key: Digest32,
    },
}

impl Checked {
    /// What it takes in memory, as an assembly charge counts it: each header it holds (the
    /// entry's and each parent's) at its largest, with its descriptors, and the allocation of
    /// its validation's F3 deferrals.
    pub(super) fn bytes(&self) -> usize {
        let (parents, deferred) = match &self.stage {
            Stage::Preflight { started, .. } => (started.parents.len(), 0),
            Stage::Validate { validation, .. } => {
                (validation.parents().len(), validation.deferred_bytes())
            }
        };
        Self::HEADER_BYTES * (1 + parents) + std::mem::size_of::<Self>() + deferred
    }

    /// One held header at its largest, with its descriptors.
    const HEADER_BYTES: usize = crate::log::history::MAX_HEADER_BYTES + 256;

    /// An admission's headroom for what it keeps ([`super::pull::CheckedRoom`]), and the
    /// invariant `bytes() <= headroom()` of every state one entry's whole validation can keep,
    /// whatever it resumed from: the entry's header and its most parents
    /// ([`governance::MAX_PARENTS`]), with the most deferrals a whole validation can hold
    /// ([`governance::deferred_bytes_max`], from `AUTHORS_HARD_LIMIT`). Reserved whole before a
    /// root is taken, so a kept state never outgrows it (`Flow::keep_checked` fails the entry's
    /// admission loudly if it ever did).
    pub(super) fn headroom() -> usize {
        Self::HEADER_BYTES * (1 + governance::MAX_PARENTS)
            + std::mem::size_of::<Self>()
            + governance::deferred_bytes_max()
    }
}

/// The one place an operation's [`Checked`] is handed in and given back.
pub(super) type CheckedSlot = std::sync::Arc<std::sync::Mutex<Option<Box<Checked>>>>;

/// What an entry's admission operation waits for when it stops.
pub(super) enum EntryNeed {
    Wire(Query),
    /// The admission of another position.
    Entry {
        head: Digest32,
        seq: u64,
    },
    Fork(ForkWait),
}

/// How far one entry's bounded admission operation reached before Begin (`ready_entry`).
#[allow(clippy::large_enum_variant)]
pub(super) enum EntryReady {
    /// Validated in this operation: Begin commits with this token, re-derived nowhere else.
    Validated(governance::ValidatedSparseEntry, CursorBinding),
    /// The operation stopped: its budget or turn target was spent, or it lacks `need`. What it
    /// checked is kept in the operation's [`CheckedSlot`], and where it goes on in `resume`.
    /// `also`: the other
    /// authors' prerequisite controls (author, position) the same walk found missing after
    /// `need`; the entry waits for each in turn before it runs again (`Frontier::settled`).
    Stop {
        resume: Resume,
        need: Option<EntryNeed>,
        also: Vec<(Digest32, u64)>,
    },
    /// Another publication owns the room, or its bounded work queue is full.
    Busy,
}

/// The bound of one entry's admission operation: ONE default verifier budget, charged by its
/// preflight, its control-prefix walks (the inline ones and the walk in a control's own effect
/// transaction), its typed body and its validation, never replenished inside the operation;
/// and the cooperative turn target (`runtime::LOCAL_TURN_BUDGET`), checked between bounded
/// primitives (`design/adopt/ruling-join-consolidation.md`, condition 3).
pub(super) struct Bound {
    pub(super) work: WorkBudget,
    started: std::time::Instant,
}

impl Bound {
    pub(super) fn new() -> Self {
        Self {
            work: WorkBudget::default(),
            started: std::time::Instant::now(),
        }
    }

    pub(super) fn spent(&self) -> bool {
        self.started.elapsed() >= super::runtime::LOCAL_TURN_BUDGET
    }

    /// What is left of the turn target.
    pub(super) fn left(&self) -> std::time::Duration {
        super::runtime::LOCAL_TURN_BUDGET.saturating_sub(self.started.elapsed())
    }
}

/// An entry's exact inclusion under a head committed here, its authenticated prefix and each
/// parent's receipt, found before preflight follows them.
struct Started {
    included: crate::log::history::IncludedHeader,
    head: Digest32,
    parents: Vec<Option<governance::SparseParent>>,
}

/// An entry's parent references in their signed order: its own predecessor first, then its
/// `seen`. ADR-053 M0: an ordinary Content entry's `seen` are ordering hints; only its own
/// predecessor needs a receipt here. Controls keep one per reference.
fn references(entry: &Entry) -> Result<Vec<crate::log::history::EntryReference>> {
    let v2 = entry
        .skeleton
        .v2
        .as_ref()
        .ok_or(invalid("entry is not typed"))?;
    let seen = governance::checked_seen(v2);
    let mut references = Vec::with_capacity(seen.len() + 1);
    if entry.skeleton.seq > 1 {
        references.push(crate::log::history::EntryReference {
            author: entry.skeleton.author_id,
            seq: entry.skeleton.seq - 1,
            hash: entry.skeleton.prev_hash,
        });
    }
    references.extend(seen.iter().cloned());
    Ok(references)
}

/// What rules F2 D and E make of one parent reference by what is recorded here now.
enum Reference {
    /// F2 D: it names a proved forker at or after its boundary; it requires no entry.
    Waived,
    /// F2 E: this node's validated entry at that position is another one.
    Fork(ForkWait),
    /// Required as it names, under the author's recorded fork boundary, if any.
    Required(Option<u64>),
}

fn reference_rule(
    input: &entry_store::Read<'_>,
    splits: &governance::Splits,
    own_parent: bool,
    reference: &crate::log::history::EntryReference,
) -> Result<Reference> {
    let boundary = if own_parent {
        None
    } else {
        splits.boundary(&reference.author)
    };
    if seen_waived(boundary, reference) {
        return Ok(Reference::Waived);
    }
    // A validated parent must still be the entry it names.
    if let Some((_, held)) = input.history_validated_header(&reference.author, reference.seq)? {
        if held.entry_hash() != reference.hash {
            if own_parent {
                return Err(invalid("signed parent differs from validated position"));
            }
            return mismatched_reference(boundary, reference).map(Reference::Fork);
        }
    }
    Ok(Reference::Required(boundary))
}

/// A carried start ([`Stage::Preflight`]) checked again by [`reference_rule`] against what is
/// recorded here now, as `start_entry` checks each reference.
enum Recheck {
    /// Still good; a reference a fork proved since waives is dropped from it.
    Kept,
    Fork(ForkWait),
    /// It no longer matches what a start would establish: the entry starts again.
    Again,
}

fn recheck_references(
    room: &impl HistoryAdmissionRoom,
    store: &Store,
    entry: &Entry,
    started: &mut Started,
) -> Result<Recheck> {
    let references = references(entry)?;
    if references.len() != started.parents.len() {
        return Ok(Recheck::Again);
    }
    let input = room.history_read(store)?;
    let splits = room.history_splits(store)?;
    for (at, reference) in references.iter().enumerate() {
        let own_parent = at == 0 && entry.skeleton.seq > 1;
        match reference_rule(&input, &splits, own_parent, reference)? {
            Reference::Waived => started.parents[at] = None,
            Reference::Fork(wait) => return Ok(Recheck::Fork(wait)),
            Reference::Required(_) if started.parents[at].is_none() => return Ok(Recheck::Again),
            Reference::Required(_) => {}
        }
    }
    Ok(Recheck::Kept)
}

enum Start {
    Ready(Box<Started>),
    Need(Query),
    Fork(ForkWait),
    Busy,
}

/// The start of structural/typed-body closure, only after exact inclusion.
fn start_entry(
    room: &impl HistoryAdmissionRoom,
    store: &Store,
    committed: &std::sync::atomic::AtomicBool,
    head: Digest32,
    entry: &Entry,
) -> Result<Start> {
    let input = room.history_read(store)?;
    let author = entry.skeleton.author_id;
    let seq = entry.skeleton.seq;
    let Some(included) = entry_inclusion(&input, &head, &author, seq)? else {
        return Ok(Start::Need(Query::Proof {
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
            Advanced::Need(query) => Ok(Start::Need(query)),
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
            _ => Ok(Start::Busy),
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
        return Ok(Start::Need(Query::Proof {
            head,
            kind: ProofKind::Consistency,
            from: seq,
            to: target.root.leaves,
        }));
    }
    let references = references(entry)?;
    let mut parents = Vec::with_capacity(references.len());
    let splits = room.history_splits(store)?;
    for (at, reference) in references.into_iter().enumerate() {
        let own_parent = at == 0 && seq > 1;
        let boundary = match reference_rule(&input, &splits, own_parent, &reference)? {
            Reference::Waived => {
                parents.push(None);
                continue;
            }
            Reference::Fork(wait) => return Ok(Start::Fork(wait)),
            Reference::Required(boundary) => boundary,
        };
        if let Some(parent) = parent_evidence(&input, &reference.author, reference.seq)? {
            if parent.header().entry_hash() != reference.hash {
                if own_parent {
                    return Err(invalid("preflight parent receipt differs"));
                }
                return mismatched_reference(boundary, &reference).map(Start::Fork);
            }
            // Before preflight follows its frontier: a published parent's positional prefix
            // must be its own whole context, else a local fault of this store.
            parent.check_published(&input)?;
            parents.push(Some(parent));
            continue;
        }
        // Neither published here nor proven by an answer: its receipt is asked under the
        // author's committed head, and its admission or an answer that brings it meets that.
        let Some(parent_head) = input
            .sparse_author(&reference.author, LogScope::Public)?
            .and_then(|state| state.committed)
        else {
            return Ok(Start::Need(Query::Head(reference.author)));
        };
        let target = input
            .history_head(&parent_head)?
            .ok_or(local("parent target missing"))?;
        if target.root.leaves < reference.seq {
            return Ok(Start::Need(Query::Head(reference.author)));
        }
        if input
            .history_pending_header(&parent_head, reference.seq)?
            .is_none()
        {
            return Ok(Start::Need(Query::Header {
                head: parent_head,
                seq: reference.seq,
            }));
        }
        if input
            .history_inclusion_receipt(&parent_head, &reference.author, reference.seq)?
            .is_none()
        {
            return Ok(Start::Need(Query::Proof {
                head: parent_head,
                kind: ProofKind::Inclusion,
                from: reference.seq,
                to: reference.seq,
            }));
        }
        return Ok(Start::Need(Query::Proof {
            head: parent_head,
            kind: ProofKind::Consistency,
            from: reference.seq,
            to: target.root.leaves,
        }));
    }
    Ok(Start::Ready(Box::new(Started {
        included,
        head,
        parents,
    })))
}

/// One entry admitted from its start up to Begin as part of ONE bounded native operation
/// (`client::Receiver::admit_entry`), which commits nothing for its progress until it must
/// stop: start, preflight, the control-prefix walks preflight and validation find short, the
/// typed body and validation run in order under the operation's one `Bound`. A stop keeps what
/// it checked in `checked` (JoinDesign S1), which the next operation resumes from when it is
/// still bound to this activation, room, head, entry and author key; preflight's position is
/// also the scalar continuation. The caller owns the room's pending write and the verifier
/// envelope, never the room's mutex.
#[allow(clippy::too_many_arguments)]
pub(super) fn ready_entry(
    room: &impl HistoryAdmissionRoom,
    store: &Store,
    committed: &std::sync::atomic::AtomicBool,
    request: RequestId,
    generation: Digest32,
    head: Digest32,
    entry: &Entry,
    from: Resume,
    checked: &mut Option<Box<Checked>>,
    bound: &mut Bound,
    ready: &mut bool,
) -> Result<EntryReady> {
    if room.history_publication_busy(store)? {
        return Ok(EntryReady::Busy);
    }
    let author = entry.skeleton.author_id;
    let seq = entry.skeleton.seq;
    let hash = entry.entry_hash();
    let stop = |resume, need| {
        Ok(EntryReady::Stop {
            resume,
            need,
            also: Vec::new(),
        })
    };
    let binding = |head| CursorBinding {
        request,
        room: room.channel_id(),
        head,
        author,
        proof_kind: 3,
        from: seq,
        through: seq,
        generation,
    };
    let keep = |stage| {
        Some(Box::new(Checked {
            generation,
            room: room.channel_id(),
            head,
            entry: hash,
            stage,
        }))
    };
    let carried = checked
        .take()
        .filter(|checked| {
            checked.generation == generation
                && checked.room == room.channel_id()
                && checked.head == head
                && checked.entry == hash
        })
        .map(|checked| checked.stage);
    let (mut cursor, binding, fingerprint) = match carried {
        Some(Stage::Validate {
            validation,
            head,
            key: fingerprint,
        }) if room
            .history_author_key(&author)
            .is_some_and(|key| key.fingerprint() == fingerprint) =>
        {
            (validation, binding(head), fingerprint)
        }
        carried => {
            // A carried start is rechecked by rules F2 D and E against what is recorded here
            // now, as `start_entry` checks them: a fork proved since waives a reference, a
            // position validated since as another entry is a fork wait.
            let carried = match carried {
                Some(Stage::Preflight { mut started, at }) => {
                    match recheck_references(room, store, entry, &mut started)? {
                        Recheck::Kept => Some((started, at)),
                        Recheck::Fork(wait) => return stop(from, Some(EntryNeed::Fork(wait))),
                        Recheck::Again => None,
                    }
                }
                _ => None,
            };
            let (started, at, fresh) = match carried {
                Some((started, at)) => (started, at, false),
                None => {
                    let started = match start_entry(room, store, committed, head, entry)? {
                        Start::Ready(started) => *started,
                        Start::Need(query) => return stop(from, Some(EntryNeed::Wire(query))),
                        Start::Fork(wait) => return stop(from, Some(EntryNeed::Fork(wait))),
                        Start::Busy => return Ok(EntryReady::Busy),
                    };
                    let at = match from {
                        Resume::Preflight { parent, next } => (parent, next),
                        _ => (0, 0),
                    };
                    (started, at, true)
                }
            };
            let key = room
                .history_author_key(&author)
                .ok_or(local("entry author is unknown"))?;
            let body = match governance::TypedSparseBody::verify(entry, &key, &mut bound.work)? {
                governance::PayloadValidation::Complete(body) => body,
                governance::PayloadValidation::BodyRequired => {
                    // Before its body is asked for, the entry's prerequisites are made held here
                    // (`prerequisites`), so a body fetch never waits on a control it names. With
                    // its body held, validation walks what it lacks itself, below.
                    let ((parent, next), need, also) = match prerequisites(
                        room,
                        store,
                        committed,
                        entry,
                        &started.parents,
                        at,
                        bound,
                        ready,
                    )? {
                        Prerequisites::Held(at) => (
                            at,
                            Some(EntryNeed::Wire(Query::Entry {
                                head: started.head,
                                seq,
                                offset: 0,
                            })),
                            Vec::new(),
                        ),
                        Prerequisites::Stopped(at, need, also) => (at, need, also),
                    };
                    *checked = keep(Stage::Preflight {
                        started,
                        at: (parent, next),
                    });
                    return Ok(EntryReady::Stop {
                        resume: Resume::Preflight { parent, next },
                        need,
                        also,
                    });
                }
                governance::PayloadValidation::Yielded => {
                    *checked = keep(Stage::Preflight { started, at });
                    return stop(from, None);
                }
            };
            let binding = binding(started.head);
            let Started {
                included, parents, ..
            } = started;
            let mut validation = governance::SparseValidation::new(included, body, parents)?;
            // The start of this operation checked every parent's whole context (S2).
            if fresh {
                validation.parents_checked();
            }
            (validation, binding, key.fingerprint())
        }
    };
    // Validation continues while the operation's bound allows; a parent is not a boundary.
    let mut input = None;
    let mut walked = None;
    let need = loop {
        if bound.spent() {
            break None;
        }
        if input.is_none() {
            input = Some(room.history_read(store)?);
        }
        let Some(read) = &input else {
            return Err(local("entry validation read"));
        };
        let splits = room.history_splits(store)?;
        match cursor.advance(read, &mut bound.work, &splits)? {
            governance::SparseValidationStep::Complete(token) => {
                return Ok(EntryReady::Validated(token, binding));
            }
            governance::SparseValidationStep::Progress => {}
            governance::SparseValidationStep::Yielded => break None,
            governance::SparseValidationStep::MissingContext(hash) => {
                break Some(EntryNeed::Wire(Query::Context(hash)));
            }
            governance::SparseValidationStep::Mismatch(reference) => {
                break Some(EntryNeed::Fork(ForkWait::Fork {
                    author: reference.author,
                    at: reference.seq,
                }));
            }
            governance::SparseValidationStep::Unmatched(reference) => {
                break Some(EntryNeed::Fork(ForkWait::Unmatched(reference)));
            }
            governance::SparseValidationStep::MissingControl(reference) => {
                let Some(head) = read
                    .sparse_author(&reference.author, LogScope::Public)?
                    .and_then(|state| state.committed)
                else {
                    break Some(EntryNeed::Wire(Query::Head(reference.author)));
                };
                let target = read
                    .history_head(&head)?
                    .ok_or(local("control head missing"))?;
                if target.root.leaves < reference.seq {
                    break Some(EntryNeed::Wire(Query::Head(reference.author)));
                }
                // As preflight did: advance the author's authenticated control range from its
                // durable prefix, once; waiting on the named control itself would descend the
                // chain one admission at a time. A walk that completes without it held waits
                // for its admission.
                if walked == Some((reference.author, reference.seq)) {
                    break Some(EntryNeed::Entry {
                        head,
                        seq: reference.seq,
                    });
                }
                walked = Some((reference.author, reference.seq));
                input = None;
                match advance_prefix(
                    room,
                    store,
                    committed,
                    head,
                    reference.seq,
                    false,
                    &mut bound.work,
                    ready,
                )? {
                    Prefix::Complete => {}
                    Prefix::Yielded => break None,
                    Prefix::Need(need) => break Some(need),
                }
            }
            governance::SparseValidationStep::ControlPrefixPending { head, through } => {
                input = None;
                match advance_prefix(
                    room,
                    store,
                    committed,
                    head,
                    through,
                    false,
                    &mut bound.work,
                    ready,
                )? {
                    Prefix::Complete => {}
                    Prefix::Yielded => break None,
                    Prefix::Need(need) => break Some(need),
                }
            }
        }
    };
    drop(input);
    // A control validation lacks: the same pass as before a body fetch, within what is left of
    // the bound, names the other authors' controls the entry lacks, so that it waits once
    // (`prerequisites`). Scheduling only: validation still checks each one when it resumes.
    let mut also = Vec::new();
    if let Some(EntryNeed::Entry { head: missing, .. }) = &need {
        let read = room.history_read(store)?;
        let missing = read.history_head(missing)?.map(|head| head.binding.author);
        drop(read);
        if let Prerequisites::Stopped(_, Some(EntryNeed::Entry { head, seq }), rest) =
            prerequisites(
                room,
                store,
                committed,
                entry,
                cursor.parents(),
                (0, 0),
                bound,
                ready,
            )?
        {
            let first = room
                .history_read(store)?
                .history_head(&head)?
                .map(|head| (head.binding.author, seq));
            also = first
                .into_iter()
                .chain(rest)
                .filter(|(author, _)| Some(*author) != missing)
                .collect();
        }
    }
    // An operation that stops inside validation keeps its exact cursor with the entry, in
    // memory; it commits nothing for it (S1).
    cursor.end_operation();
    *checked = keep(Stage::Validate {
        validation: cursor,
        head: binding.head,
        key: fingerprint,
    });
    Ok(EntryReady::Stop {
        resume: Resume::Validate,
        need,
        also,
    })
}

pub(super) enum Prefix {
    Complete,
    Yielded,
    Need(EntryNeed),
}

/// Advance an author's control-source or control-effect prefix through `through` with the
/// existing walk (`advance_control_receipt`: it stops at a coverage gap, a missing or
/// conflicting source and an unfinished effect), each walk step charged to the operation's
/// budget, the steps in one transaction. `ready`: this walk made the author's controls current
/// here (permission news, `Flow::controls_ready`).
#[allow(clippy::too_many_arguments)]
pub(super) fn advance_prefix(
    room: &impl HistoryAdmissionRoom,
    store: &Store,
    committed: &std::sync::atomic::AtomicBool,
    head: Digest32,
    through: u64,
    effects: bool,
    work: &mut WorkBudget,
    ready: &mut bool,
) -> Result<Prefix> {
    use entry_store::sparse::SourceProgress;
    let input = room.history_read(store)?;
    let named = input
        .history_head(&head)?
        .ok_or(local("control target head missing"))?;
    // Control facts are kept per author (`control_prefix_complete`); an older committed head is
    // replaced by the author's current one only so that a coverage need names the head this
    // node and its peers hold now.
    let head = match input
        .sparse_author(&named.binding.author, named.binding.scope)?
        .and_then(|state| state.committed)
    {
        Some(current)
            if current != head && input.history_head_committed(&head, named.binding)? =>
        {
            current
        }
        _ => head,
    };
    let target = input
        .history_head(&head)?
        .ok_or(local("control target head missing"))?;
    if through == 0 || through > target.root.leaves {
        return Err(local("control receipt bound exceeds target"));
    }
    let leaves = target.root.leaves;
    drop(input);
    if !work.take_control_lookup() {
        return Ok(Prefix::Yielded);
    }
    let progress = room.history_write_tracked(store, committed, |index| loop {
        let progress = if effects {
            index.advance_control_effects(&head, through)?
        } else {
            index.advance_control_sources(&head, through)?
        };
        if !matches!(progress, SourceProgress::Progress { .. }) || !work.take_control_lookup() {
            return Ok(progress);
        }
    })?;
    // The author's effect prefix was below its committed size (not complete when preflight or
    // validation looked, and `through` reaches that size) and this walk brought it there.
    *ready |= effects
        && through >= leaves
        && matches!(
            progress,
            SourceProgress::Complete { through: done } | SourceProgress::Progress { through: done }
                if done >= leaves
        );
    Ok(match progress {
        SourceProgress::Complete { through: done } | SourceProgress::Progress { through: done }
            if done >= through =>
        {
            Prefix::Complete
        }
        SourceProgress::Progress { .. } | SourceProgress::Complete { .. } => Prefix::Yielded,
        SourceProgress::MissingCoverage { after } => Prefix::Need(EntryNeed::Wire(Query::Proof {
            head,
            kind: ProofKind::Control,
            from: after + 1,
            to: through,
        })),
        SourceProgress::MissingSource { seq } => Prefix::Need(EntryNeed::Entry { head, seq }),
        SourceProgress::ConflictingSource {
            author,
            seq,
            expected,
            actual,
        } => {
            tracing::warn!(
                ?author,
                seq,
                ?expected,
                ?actual,
                "conflicting sparse control source"
            );
            return Err(invalid(
                "held sparse control source conflicts with authenticated head",
            ));
        }
        SourceProgress::PendingEffect { hash } => {
            let seq = room
                .history_read(store)?
                .history_object(entry_store::sparse::ObjectKind::Header, &hash)?
                .map(|wire| Entry::from_wire(&wire).map(|entry| entry.skeleton.seq))
                .transpose()?
                .ok_or(local("pending history effect header missing"))?;
            Prefix::Need(EntryNeed::Entry { head, seq })
        }
    })
}

/// Scheduling preflight only: never an authority/admission token. Resolve the exact parent's
/// authenticated frontier as well as the claimed pre-context, so an underclaim cannot occupy
/// the sole control-body slot before its omitted prerequisite control has been received.
enum Preflight {
    Progress {
        parent: usize,
        next: usize,
    },
    /// The operation's budget is spent at this exact position.
    Yielded {
        parent: usize,
        next: usize,
    },
    Need(Query),
    Control {
        head: Digest32,
        through: u64,
        effects: bool,
        /// The control's author, and the coordinate a walk that goes on past this author
        /// continues from (`prerequisites`).
        author: Digest32,
        next: usize,
    },
    Fork(ForkWait),
    Complete,
}

/// How far the walk before a body fetch reached (`prerequisites`).
enum Prerequisites {
    /// Every prerequisite is held here; the body may be asked for.
    Held((usize, usize)),
    /// It stopped at this exact position: its bound was spent, or it lacks `need` and then the
    /// other authors' controls in `also`.
    Stopped((usize, usize), Option<EntryNeed>, Vec<(Digest32, u64)>),
}

/// The walk an entry whose body is not held makes before that body is asked for: preflight
/// from `(parent, next)`, and each control prefix it finds short advanced inline, all under the
/// operation's bound. `parents` are the receipts `start_entry` took in this operation.
///
/// One pass reports every author whose control the entry lacks (one stop per entry, not one
/// per author): a control the walk finds not admitted here is noted, its author is passed over
/// for the rest of the pass (its prefix is one number: a later control of it waits on the same
/// one), and the walk goes on within the same bound. It stops at the first one found, with the
/// others in `also`, so the next pass walks again from there. Scheduling only: the entry is
/// never Held while any author was passed over.
#[allow(clippy::too_many_arguments)]
fn prerequisites(
    room: &impl HistoryAdmissionRoom,
    store: &Store,
    committed: &std::sync::atomic::AtomicBool,
    entry: &Entry,
    parents: &[Option<governance::SparseParent>],
    (mut parent, mut next): (usize, usize),
    bound: &mut Bound,
    ready: &mut bool,
) -> Result<Prerequisites> {
    let mut skip = std::collections::BTreeSet::new();
    let mut first: Option<((usize, usize), EntryNeed)> = None;
    let mut also = Vec::new();
    // What the pass found missing ends it; nothing found leaves `otherwise`.
    let stopped = |first: Option<((usize, usize), EntryNeed)>,
                   also: Vec<(Digest32, u64)>,
                   otherwise: Prerequisites| match first {
        Some((at, need)) => Prerequisites::Stopped(at, Some(need), also),
        None => otherwise,
    };
    // The entry's own context, once: each parent's frontier is compared with it.
    let v2 = entry
        .skeleton
        .v2
        .as_ref()
        .ok_or(invalid("preflight header is legacy"))?;
    if !bound.work.take_context_load() {
        return Ok(Prerequisites::Stopped((parent, next), None, Vec::new()));
    }
    let Some(pre) = room.history_read(store)?.history_context(&v2.pre_context)? else {
        return Ok(Prerequisites::Stopped(
            (parent, next),
            Some(EntryNeed::Wire(Query::Context(v2.pre_context))),
            Vec::new(),
        ));
    };
    bound.work.refund_context_load(pre.coordinates.len());
    if pre.room != room.channel_id() || pre.scope != v2.scope {
        return Err(invalid("preflight context/cursor differs"));
    }
    loop {
        if bound.spent() {
            return Ok(stopped(
                first,
                also,
                Prerequisites::Stopped((parent, next), None, Vec::new()),
            ));
        }
        let input = room.history_read(store)?;
        let splits = room.history_splits(store)?;
        let (head, through, effects, author, resume) = loop {
            match preflight(
                &input,
                &splits,
                &pre,
                parents,
                parent,
                next,
                &skip,
                &mut bound.work,
            )? {
                Preflight::Progress {
                    parent: at,
                    next: coordinate,
                } => (parent, next) = (at, coordinate),
                Preflight::Complete => {
                    return Ok(stopped(first, also, Prerequisites::Held((parent, next))));
                }
                Preflight::Yielded {
                    parent: at,
                    next: coordinate,
                } => {
                    return Ok(stopped(
                        first,
                        also,
                        Prerequisites::Stopped((at, coordinate), None, Vec::new()),
                    ));
                }
                Preflight::Need(query) => {
                    return Ok(stopped(
                        first,
                        also,
                        Prerequisites::Stopped(
                            (parent, next),
                            Some(EntryNeed::Wire(query)),
                            Vec::new(),
                        ),
                    ));
                }
                Preflight::Fork(wait) => {
                    return Ok(Prerequisites::Stopped(
                        (parent, next),
                        Some(EntryNeed::Fork(wait)),
                        Vec::new(),
                    ));
                }
                Preflight::Control {
                    head,
                    through,
                    effects,
                    author,
                    next: resume,
                } => break (head, through, effects, author, resume),
            }
            if bound.spent() {
                return Ok(stopped(
                    first,
                    also,
                    Prerequisites::Stopped((parent, next), None, Vec::new()),
                ));
            }
        };
        drop(input);
        match advance_prefix(
            room,
            store,
            committed,
            head,
            through,
            effects,
            &mut bound.work,
            ready,
        )? {
            Prefix::Complete => {}
            Prefix::Yielded => {
                return Ok(stopped(
                    first,
                    also,
                    Prerequisites::Stopped((parent, next), None, Vec::new()),
                ));
            }
            // Another position's admission: noted, and the pass goes on past its author.
            Prefix::Need(EntryNeed::Entry { head, seq }) => {
                match &first {
                    None => first = Some(((parent, next), EntryNeed::Entry { head, seq })),
                    Some(_) => also.push((author, seq)),
                }
                skip.insert(author);
                next = resume;
            }
            Prefix::Need(need) => {
                return Ok(stopped(
                    first,
                    also,
                    Prerequisites::Stopped((parent, next), Some(need), Vec::new()),
                ));
            }
        }
    }
}

/// Read-only: one parent's control prefixes and its frontier, or one chunk of the entry's own
/// context `pre`, each lookup charged to the operation's budget. The parent's receipt is the one
/// `start_entry` took and checked in this operation. A parent's frontier coordinate that `pre`
/// reaches (the same control, or a later one of its author) is walked once, in `pre`'s phase:
/// an author's control prefixes are one number each, complete through the later coordinate
/// only if complete through the earlier one. Authors in `skip` (a control of theirs is already
/// noted missing in this pass) are passed over, uncharged.
#[allow(clippy::too_many_arguments)]
fn preflight(
    input: &entry_store::Read<'_>,
    splits: &governance::Splits,
    pre: &ControlContext,
    parents: &[Option<governance::SparseParent>],
    parent: usize,
    next: usize,
    skip: &std::collections::BTreeSet<Digest32>,
    work: &mut WorkBudget,
) -> Result<Preflight> {
    let parent_count = parents.len();
    if parent > parent_count {
        return Err(local("preflight parent cursor"));
    }
    if matches!(parents.get(parent), Some(None)) {
        return Ok(Preflight::Progress {
            parent: parent + 1,
            next: 0,
        });
    }
    let frontier = if let Some(Some(receipt)) = parents.get(parent) {
        // The parent's two prefix receipts.
        if !work.take_control_lookup() {
            return Ok(Preflight::Yielded { parent, next });
        }
        let parent_head = receipt.head_id();
        let parent_author = receipt.header().skeleton.author_id;
        // SparseValidation requires this exact parent prefix, not only the
        // control coordinates named in its frontier. Finish it before taking a body
        // slot; validation then cannot recursively discover an earlier control.
        let through = receipt.prefix().leaves;
        for effects in [false, true] {
            if skip.contains(&parent_author) {
                break;
            }
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
                    author: parent_author,
                    next,
                });
            }
        }
        if !work.take_context_load() {
            return Ok(Preflight::Yielded { parent, next });
        }
        let hash = receipt.prefix().frontier;
        let Some(frontier) = input.history_context(&hash)? else {
            return Ok(Preflight::Need(Query::Context(hash)));
        };
        work.refund_context_load(frontier.coordinates.len());
        if frontier.room != pre.room || frontier.scope != pre.scope {
            return Err(invalid("preflight context/cursor differs"));
        }
        Some(frontier)
    } else {
        None
    };
    let context = frontier.as_ref().unwrap_or(pre);
    if next > context.coordinates.len() {
        return Err(invalid("preflight context/cursor differs"));
    }
    // One context and at most 16 exact coordinate/header/receipt lookups: <=64 objects.
    let end = (next + 16).min(context.coordinates.len());
    for (at, coordinate) in context.coordinates[next..end].iter().enumerate() {
        if frontier.is_some()
            && pre
                .coordinates
                .binary_search_by_key(&coordinate.author, |reached| reached.author)
                .is_ok_and(|found| {
                    let reached = &pre.coordinates[found];
                    reached.seq > coordinate.seq
                        || (reached.seq == coordinate.seq && reached.hash == coordinate.hash)
                })
        {
            continue;
        }
        if skip.contains(&coordinate.author) {
            continue;
        }
        if !work.take_control_lookup() {
            return Ok(Preflight::Yielded {
                parent,
                next: next + at,
            });
        }
        let Some((control_head, control)) =
            input.history_validated_header(&coordinate.author, coordinate.seq)?
        else {
            if coordinate_deferred(splits, coordinate) {
                continue;
            }
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
                author: coordinate.author,
                next: next + at + 1,
            });
        };
        if control.entry_hash() != coordinate.hash {
            if coordinate_deferred(splits, coordinate) {
                continue;
            }
            return Ok(Preflight::Fork(ForkWait::Fork {
                author: coordinate.author,
                at: coordinate.seq,
            }));
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
                    author: coordinate.author,
                    next: next + at + 1,
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
/// `terminal-header-only`, a matching entry at the overlap ends the comparison (no prefix walk);
/// `seen-required`, a control's `seen` reference naming a proved forker past its boundary still
/// requires the reader's own entry there, refused when it differs (rule F2 D switched off);
/// `fallback-off`, every proved splitter reads as certified, so no coordinate naming it is ever
/// ignored (rule F3's coordinate fallback switched off, `governance::splits`).
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
