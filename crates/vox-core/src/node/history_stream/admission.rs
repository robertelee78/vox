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
// `brought` on an object says this node did not hold it before: what a round fetched, as
// `vox status --json` counts an `empty` round (ADR-038 FX-29). An object already held is
// not saved again: the round writes nothing for it.
#[allow(clippy::large_enum_variant)]
pub(super) enum Staged {
    Object {
        brought: bool,
    },
    Head {
        head: Digest32,
        author: Digest32,
        tail: u64,
        departure_receipt: bool,
        /// The exact head is already in this author's accepted chain: nothing of it is
        /// fetched or verified again (no header, no inclusion proof, no promotion).
        held: bool,
        brought: bool,
    },
    Header {
        entry: Entry,
        head: Digest32,
        body_allowed: bool,
        brought: bool,
    },
    Verifier(CursorBinding),
    Busy,
}

fn invalid(message: &'static str) -> Error {
    Error::MalformedBundle(message)
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
            let held = retained && input.history_head_accepted(&id, head.binding)?;
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
            let departure_receipt = room.history_departure_matches(
                store,
                super::HeadHint {
                    author: *author,
                    head: id,
                    size: head.root.leaves,
                },
            )?;
            Ok(Staged::Head {
                head: id,
                author: *author,
                tail: head.root.leaves,
                departure_receipt,
                held,
                brought,
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
                return Ok(Staged::Object { brought: false });
            }
            room.history_write_tracked(store, committed, |index| {
                index.keep_history_context(&context)
            })?;
            Ok(Staged::Object { brought: true })
        }
        (Query::Entry { head, seq, .. } | Query::Header { head, seq }, Object::Header(bytes)) => {
            stage_header(room, store, committed, *head, *seq, *seq, bytes, &mut work)
        }
        (
            Query::KeyBody {
                head,
                author,
                hash,
                seq,
                ..
            },
            Object::Header(bytes),
        ) => {
            let entry = Entry::from_wire(bytes)?;
            if entry.skeleton.author_id != *author
                || entry.entry_hash() != *hash
                || !entry
                    .skeleton
                    .v2
                    .as_ref()
                    .is_some_and(|v| v.kind == crate::log::history::SignedEntryKind::KeyPackage)
            {
                return Err(invalid("requested key body header differs"));
            }
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
    // A header already held under this head is not saved again (ADR-038 FX-29): a live retry
    // of a missing body receives its header with every answer, and each one committed the
    // same header and pending position unchanged.
    let held = input
        .history_pending_header(&head_id, entry.skeleton.seq)?
        .is_some_and(|pending| pending.entry_hash() == entry.entry_hash());
    drop(input);
    // Ordinary role queries need only another member's authenticated package header.
    // An explicit KeyBody query separately admits the sealed bytes for opaque relay.
    let body_allowed = !entry.skeleton.v2.as_ref().is_some_and(|v2| {
        v2.kind == crate::log::history::SignedEntryKind::KeyPackage
            && v2.recipient != Some(room.me())
    });
    if held {
        return Ok(Staged::Header {
            entry,
            head: head_id,
            body_allowed,
            brought: false,
        });
    }
    room.history_write_tracked(store, committed, |index| {
        index.keep_history_header(&header)?;
        index.keep_history_pending_header(&head_id, &header)
    })?;
    Ok(Staged::Header {
        entry,
        head: head_id,
        body_allowed,
        brought: true,
    })
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
        .ok_or(invalid("verifier author is no longer admitted"))?;
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
                return Err(invalid("entry closure requires the admission driver"))
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
        _ => return Err(invalid("completed proof range kind")),
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
        #[cfg(feature = "test-knobs")]
        if !ranges.is_empty() {
            if let Some(path) = std::env::var_os("VOX_TEST_HOLD_VERIFIED_FETCH") {
                let path = std::path::PathBuf::from(path);
                std::fs::write(path.with_extension("verified"), binding.head).map_err(|error| {
                    Error::Storage {
                        op: "verified fetch marker",
                        detail: error.to_string(),
                    }
                })?;
                while path.exists() {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
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
            room.note_role_progress(binding.author, binding.from);
            combine_parent(
                room,
                store,
                committed,
                binding.head,
                binding.author,
                binding.from,
            )?;
            promote_head(room, store, committed, binding.head)
        }
        ResultStep::Prefix(prefix) => {
            let input = room.history_read(store)?;
            let unlinked = unlinked_prefix(&input, &prefix)?;
            drop(input);
            room.history_write_tracked(store, committed, |index| {
                keep_generated(index)?;
                keep_witness(
                    index,
                    crate::log::history::consistency_ranges(
                        prefix.prefix().leaves,
                        prefix.root().leaves,
                    )?,
                )?;
                if unlinked {
                    // MP-9: the head's prefix differs from the accepted chain. Kept under its
                    // own head so the comparison resumes; never as an accepted range.
                    index.keep_history_unlinked_prefix_receipt(&prefix)?;
                } else {
                    index.keep_history_prefix_receipt(&prefix)?;
                }
                index.finish_history_verifier_cursor(*binding)
            })?;
            cache_ranges()?;
            combine_parent(
                room,
                store,
                committed,
                binding.head,
                binding.author,
                binding.from,
            )?;
            promote_head(room, store, committed, binding.head)
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
                }
                if index.keep_control_coverage(&controls, 0)?.is_some() {
                    return Err(invalid("bounded control coverage unexpectedly incomplete"));
                }
                index.finish_history_verifier_cursor(*binding)
            })?;
            cache_ranges()?;
            Ok(Advanced::Complete)
        }
    }
}

fn combine_parent(
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
        .ok_or(invalid("promotion head missing"))?;
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
                .ok_or(invalid("accepted baseline missing"))?
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
        .ok_or(invalid("promotion consistency receipt vanished"))?;
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
        .ok_or(invalid("head author disappeared"))?;
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
    room.note_role_progress(signed.binding.author, signed.root.leaves);
    if signed.binding.author != room.me() {
        room.role_owed().mark_key_dirty(signed.binding.author);
    }
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
    let Some(included) = input.history_inclusion_receipt(&head, &author, seq)? else {
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
    if !input.history_head_accepted(&head, included.binding())? {
        drop(input);
        return match promote_head(room, store, committed, head)? {
            Advanced::Need(query) => Ok(EntryStart::Need(query)),
            // The verifier path that opened the competing entry records the fork; an entry
            // under a head proven to be another history is never started.
            Advanced::Fork(_) => Err(invalid("entry head is a competing signed history")),
            _ => Ok(EntryStart::Busy),
        };
    }
    let target = input
        .history_head(&head)?
        .ok_or(invalid("entry target head missing"))?;
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
        .ok_or(invalid("entry author is unknown"))?;
    let v2 = entry
        .skeleton
        .v2
        .as_ref()
        .ok_or(invalid("entry is not typed"))?;
    let mut references = Vec::with_capacity(v2.seen.len() + 1);
    if seq > 1 {
        references.push(crate::log::history::EntryReference {
            author,
            seq: seq - 1,
            hash: entry.skeleton.prev_hash,
        });
    }
    references.extend(v2.seen.iter().cloned());
    let mut parents = Vec::with_capacity(references.len());
    for reference in references {
        let parent_head = if let Some((id, held)) =
            input.history_validated_header(&reference.author, reference.seq)?
        {
            if held.entry_hash() != reference.hash {
                return Err(invalid("signed parent differs from validated position"));
            }
            id
        } else {
            let Some(id) = input
                .sparse_author(&reference.author, LogScope::Public)?
                .and_then(|state| state.committed)
            else {
                return Ok(EntryStart::Need(Query::Head(reference.author)));
            };
            let target = input
                .history_head(&id)?
                .ok_or(invalid("parent target missing"))?;
            if target.root.leaves < reference.seq {
                return Ok(EntryStart::Need(Query::Head(reference.author)));
            }
            id
        };
        if let Some(parent) =
            input.history_parent_receipt(&parent_head, &reference.author, reference.seq)?
        {
            parents.push(parent);
            continue;
        }
        let target = input
            .history_head(&parent_head)?
            .ok_or(invalid("parent target missing"))?;
        if input
            .history_pending_header(&parent_head, reference.seq)?
            .is_none()
            && input
                .history_position_header(&reference.author, reference.seq)?
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
        return Err(invalid("entry validation cursor missing"));
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
                        .ok_or(invalid("control head missing"))?;
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
            return Err(invalid("existing entry verifier capacity vanished"));
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
pub(super) fn preflight(
    room: &impl HistoryAdmissionRoom,
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
        input.history_inclusion_receipt(&head, &entry.skeleton.author_id, entry.skeleton.seq)?
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
    let parent_count = own + v2.seen.len();
    if parent > parent_count {
        return Err(invalid("preflight parent cursor"));
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
            v2.seen[parent - own].clone()
        };
        let parent_head = match input.history_validated_header(&reference.author, reference.seq)? {
            Some((id, prior)) => {
                if prior.entry_hash() != reference.hash {
                    return Err(invalid("preflight parent position differs"));
                }
                id
            }
            None => match input
                .sparse_author(&reference.author, LogScope::Public)?
                .and_then(|state| state.committed)
            {
                Some(id) => id,
                None => return Ok(Preflight::Need(Query::Head(reference.author))),
            },
        };
        let Some(receipt) =
            input.history_parent_receipt(&parent_head, &reference.author, reference.seq)?
        else {
            // Admission starts by acquiring every exact receipt. A changed current head can
            // require a fresh proof; it never permits substituting another parent position.
            let target = input
                .history_head(&parent_head)?
                .ok_or(invalid("preflight parent target missing"))?;
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
        if receipt.included().header().entry().entry_hash() != reference.hash {
            return Err(invalid("preflight parent receipt differs"));
        }
        // SparseValidation requires this exact parent prefix, not only the
        // control coordinates named in its frontier. Finish it before taking a body
        // slot; validation then cannot recursively discover an earlier control.
        let through = receipt.prefix().prefix().leaves;
        // `VOX_MUTANT_TERMINATION=admitted` (test-knobs, ADR-053 MP-10 (c)): the author's own
        // parent prefix is not waited for.
        let own_unchecked =
            own == 1 && parent == 0 && crate::node::channel::governance::termination_admitted();
        for effects in [false, true] {
            let complete = own_unchecked
                || if effects {
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
        receipt.prefix().prefix().frontier
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
            // `VOX_MUTANT_TERMINATION=admitted`: an absent control of the entry's own author
            // (its withheld termination) is passed over.
            if coordinate.author == entry.skeleton.author_id
                && crate::node::channel::governance::termination_admitted()
            {
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
                .ok_or(invalid("preflight control head missing"))?;
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
        let baseline_id = baseline_id.ok_or(invalid("nonempty baseline has no head"))?;
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
        .ok_or(invalid("accepted baseline missing"))?
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
/// chain, each authenticated under its own root: the other by inclusion under `head`, the
/// accepted one as an admitted position or by inclusion under the accepted head.
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
            None => input
                .history_inclusion_receipt(&accepted, &author, at)?
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
/// another history's prefix, kept under its own head only: the canonical range index holds the
/// accepted chain (a conflicting write there fails, and would end the comparison).
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
pub(super) fn fork_mutant_is(which: &str) -> bool {
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
pub(super) const fn fork_mutant_is(_: &str) -> bool {
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
