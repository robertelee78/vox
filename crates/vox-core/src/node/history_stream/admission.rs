//! One bounded authenticated-object admission step. Signatures, commitment continuity,
//! control completeness and semantic effects remain distinct states in the existing store.

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::entry::Entry;
use crate::log::history::{
    ConsistencyVerifier, ControlContext, ControlRangeVerifier, Descriptor, HistoryStep,
    InclusionVerifier, LogScope, SignedHead, VerifiedHeader, WorkBudget,
};
use crate::node::channel::{entry_store, governance, ChannelState};
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

/// Caller owns the 4-MiB verifier envelope and current room lock. Peer proof bytes only
/// construct ordinary verifiers; they can never enter an authenticated-local restore API.
pub(super) fn stage(
    room: &ChannelState,
    store: &Store,
    committed: &std::sync::atomic::AtomicBool,
    request: RequestId,
    generation: Digest32,
    query: &Query,
    object: Object<'_>,
) -> Result<Staged> {
    if room.history_publication_busy(store)? {
        return Ok(Staged::Busy);
    }
    let mut work = WorkBudget::default();
    match (query, object) {
        (Query::Head(author), Object::Head(bytes)) => {
            let head = SignedHead::from_wire(bytes)?;
            if head.binding.room != room.channel_id()
                || head.binding.scope != LogScope::Public
                || head.binding.author != *author
            {
                return Err(invalid("requested head binding differs"));
            }
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
            drop(input);
            let brought = !(retained && observed_already);
            if brought {
                let conflict = room.history_write_tracked(store, committed, |index| {
                    index.observe_history_head(&verified)
                })?;
                if conflict {
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
                    let header = input
                        .history_position_header(&signed.binding.author, *from)?
                        .or(input.history_pending_header(head, *from)?)
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
    room: &ChannelState,
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
    // Header authentication is the authority for recipient privacy. A peer cannot make a
    // private key package body admissible by merely sending it after its public header.
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
}

/// One verifier turn runs the bounded proof to its end. Primitive cooperative slices replenish
/// their work credit in memory; neither a slice boundary nor a missing context writes generated
/// nodes or an advanced cursor. Only a completed proof commits its generated contexts with its
/// receipt/final cursor. A crash or missing-context retry starts from the retained original proof
/// bytes. A missing proof is never fork evidence.
pub(super) fn advance(
    room: &ChannelState,
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
    drop(input);
    let keep_generated = |index: &mut entry_store::Write<'_, '_>| -> Result<()> {
        for (_, context) in &generated {
            index.keep_history_context(context)?;
        }
        Ok(())
    };
    match result {
        ResultStep::Missing(hash) => Ok(Advanced::MissingContext(hash)),
        ResultStep::Included(included) => {
            room.history_write_tracked(store, committed, |index| {
                keep_generated(index)?;
                index.keep_history_inclusion_receipt(&included)?;
                index.finish_history_verifier_cursor(*binding)
            })?;
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
            room.history_write_tracked(store, committed, |index| {
                keep_generated(index)?;
                index.keep_history_prefix_receipt(&prefix)?;
                index.finish_history_verifier_cursor(*binding)
            })?;
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
                // The finished cursor is kept with what it generated: the next turn, after
                // the promotion, completes at once instead of verifying the range again.
                room.history_write_tracked(store, committed, |index| {
                    keep_generated(index)?;
                    if !index.keep_history_verifier_cursor(*binding, &cursor)? {
                        return Err(invalid("existing verifier capacity vanished"));
                    }
                    Ok(())
                })?;
                return Ok(match promote_head(room, store, committed, binding.head)? {
                    Advanced::Complete => Advanced::Progress,
                    other => other,
                });
            }
            room.history_write_tracked(store, committed, |index| {
                keep_generated(index)?;
                if index.keep_control_coverage(&controls, 0)?.is_some() {
                    return Err(invalid("bounded control coverage unexpectedly incomplete"));
                }
                index.finish_history_verifier_cursor(*binding)
            })?;
            Ok(Advanced::Complete)
        }
    }
}

fn combine_parent(
    room: &ChannelState,
    store: &Store,
    committed: &std::sync::atomic::AtomicBool,
    head: Digest32,
    author: Digest32,
    seq: u64,
) -> Result<()> {
    let input = room.history_read(store)?;
    let included = input.history_inclusion_receipt(&head, &author, seq)?;
    let prefix = input.history_prefix_receipt(&head, &author, seq)?;
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
    room: &ChannelState,
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
    if signed.root.leaves < baseline.leaves {
        let baseline_id = baseline_id.ok_or(invalid("nonempty baseline has no head"))?;
        let Some(prefix) = input.history_prefix_receipt(
            &baseline_id,
            &signed.binding.author,
            signed.root.leaves,
        )?
        else {
            return Ok(Advanced::Need(Query::Proof {
                head: baseline_id,
                kind: ProofKind::Consistency,
                from: signed.root.leaves,
                to: baseline.leaves,
            }));
        };
        if prefix.prefix() != signed.root || prefix.root() != baseline {
            return Err(invalid(
                "stale head differs from accepted consistency chain",
            ));
        }
        return Ok(Advanced::Complete);
    }
    let Some(prefix) =
        input.history_prefix_receipt(&id, &signed.binding.author, baseline.leaves)?
    else {
        return Ok(Advanced::Need(Query::Proof {
            head: id,
            kind: ProofKind::Consistency,
            from: baseline.leaves,
            to: signed.root.leaves,
        }));
    };
    if prefix.prefix() != baseline {
        return Err(invalid(
            "consistency differs from current accepted baseline",
        ));
    }
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
    let conflict = room.history_write_tracked(store, committed, |index| {
        index.commit_history_head(&verified, &prefix)
    })?;
    if conflict {
        return Err(invalid("conflicting authenticated heads retained"));
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
    room: &ChannelState,
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
    // A key-package body is private to its named recipient, but for that recipient it is the
    // delivered key, not optional history. Upgrade every route that encounters this exact
    // entry (live tail, parent or control dependency) before source/effect publication. Other
    // members retain only its authenticated public header.
    let addressed_key = v2.kind == crate::log::history::SignedEntryKind::KeyPackage
        && v2.recipient == Some(room.me());
    let private_for_another = v2.kind == crate::log::history::SignedEntryKind::KeyPackage
        && v2.recipient != Some(room.me());
    if (addressed_key || (require_body && !private_for_another)) && entry.payload.is_none() {
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
    room: &ChannelState,
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
    room: &ChannelState,
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
