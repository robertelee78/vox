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

pub(super) enum Staged {
    Object,
    Head {
        head: Digest32,
        author: Digest32,
        tail: u64,
        departure_receipt: bool,
    },
    Header {
        entry: Entry,
        head: Digest32,
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
            let conflict =
                room.history_write(store, |index| index.observe_history_head(&verified))?;
            if conflict {
                return Err(invalid("conflicting authenticated heads retained"));
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
            room.history_write(store, |index| index.keep_history_context(&context))?;
            Ok(Staged::Object)
        }
        (Query::Entry { head, seq, .. } | Query::Header { head, seq }, Object::Header(bytes)) => {
            stage_header(room, store, *head, *seq, *seq, bytes, &mut work)
        }
        (Query::Page { head, lo, hi, .. }, Object::Header(bytes)) => {
            stage_header(room, store, *head, *lo, *hi, bytes, &mut work)
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
            if !room.history_write(store, |index| {
                index.keep_history_verifier_cursor(binding, &cursor)
            })? {
                return Ok(Staged::Busy);
            }
            Ok(Staged::Verifier(binding))
        }
        _ => Err(invalid("metadata is unrelated to requested object")),
    }
}

fn stage_header(
    room: &ChannelState,
    store: &Store,
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
    drop(input);
    room.history_write(store, |index| {
        index.keep_history_header(&header)?;
        index.keep_history_pending_header(&head_id, &header)
    })?;
    Ok(Staged::Header {
        entry,
        head: head_id,
    })
}

pub(super) enum Advanced {
    Progress,
    MissingContext(Digest32),
    Need(Query),
    Complete,
    Busy,
}

/// Exactly one verifier step. Generated context and the advanced cursor commit together,
/// before the actor may schedule another slice. A missing proof is never fork evidence.
pub(super) fn advance(
    room: &ChannelState,
    store: &Store,
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
    enum ResultStep {
        Context(ControlContext),
        Missing(Digest32),
        Yielded,
        Included(crate::log::history::IncludedHeader),
        Prefix(crate::log::history::ConsistentPrefix),
        Controls(crate::log::history::VerifiedControlRange),
    }
    let result = match &mut cursor {
        HistoryVerifier::Inclusion(value) => match value.advance(&input, &mut work)? {
            HistoryStep::Complete(value) => ResultStep::Included(value),
            HistoryStep::Progress(value) => ResultStep::Context(value),
            HistoryStep::MissingContext(hash) => ResultStep::Missing(hash),
            HistoryStep::Yielded => ResultStep::Yielded,
        },
        HistoryVerifier::Consistency(value) => match value.advance(&input, &mut work)? {
            HistoryStep::Complete(value) => ResultStep::Prefix(value),
            HistoryStep::Progress(value) => ResultStep::Context(value),
            HistoryStep::MissingContext(hash) => ResultStep::Missing(hash),
            HistoryStep::Yielded => ResultStep::Yielded,
        },
        HistoryVerifier::ControlRange(value) => match value.advance(&key, &input, &mut work)? {
            HistoryStep::Complete(value) => ResultStep::Controls(value),
            HistoryStep::Progress(value) => ResultStep::Context(value),
            HistoryStep::MissingContext(hash) => ResultStep::Missing(hash),
            HistoryStep::Yielded => ResultStep::Yielded,
        },
        HistoryVerifier::Validation(_) => {
            return Err(invalid("entry closure requires the admission driver"))
        }
    };
    drop(input);
    match result {
        ResultStep::Context(context) => {
            room.history_write(store, |index| {
                index.keep_history_context(&context)?;
                if !index.keep_history_verifier_cursor(*binding, &cursor)? {
                    return Err(invalid("existing verifier capacity vanished"));
                }
                Ok(())
            })?;
            Ok(Advanced::Progress)
        }
        ResultStep::Missing(hash) => {
            room.history_write(store, |index| {
                index.keep_history_verifier_cursor(*binding, &cursor)
            })?;
            Ok(Advanced::MissingContext(hash))
        }
        ResultStep::Yielded => {
            room.history_write(store, |index| {
                index.keep_history_verifier_cursor(*binding, &cursor)
            })?;
            Ok(Advanced::Progress)
        }
        ResultStep::Included(included) => {
            room.history_write(store, |index| {
                index.keep_history_inclusion_receipt(&included)?;
                index.finish_history_verifier_cursor(*binding)
            })?;
            combine_parent(room, store, binding.head, binding.author, binding.from)?;
            promote_head(room, store, binding.head)
        }
        ResultStep::Prefix(prefix) => {
            room.history_write(store, |index| {
                index.keep_history_prefix_receipt(&prefix)?;
                index.finish_history_verifier_cursor(*binding)
            })?;
            combine_parent(room, store, binding.head, binding.author, binding.from)?;
            promote_head(room, store, binding.head)
        }
        ResultStep::Controls(controls) => {
            let input = room.history_read(store)?;
            let accepted = input.history_head_committed(&controls.head_id(), controls.binding())?;
            drop(input);
            if !accepted {
                return Ok(match promote_head(room, store, binding.head)? {
                    Advanced::Complete => Advanced::Progress,
                    other => other,
                });
            }
            room.history_write(store, |index| {
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
        room.history_write(store, |index| index.keep_history_parent_receipt(&parent))?;
    }
    Ok(())
}

pub(super) fn promote_head(room: &ChannelState, store: &Store, id: Digest32) -> Result<Advanced> {
    let input = room.history_read(store)?;
    let signed = input
        .history_head(&id)?
        .ok_or(invalid("promotion head missing"))?;
    if input.history_head_committed(&id, signed.binding)? {
        return Ok(Advanced::Complete);
    }
    let baseline = match input
        .sparse_author(&signed.binding.author, signed.binding.scope)?
        .and_then(|state| state.committed)
    {
        Some(old) => {
            input
                .history_head(&old)?
                .ok_or(invalid("accepted baseline missing"))?
                .root
        }
        None => Descriptor::empty(signed.binding),
    };
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
    if input
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
    let conflict =
        room.history_write(store, |index| index.commit_history_head(&verified, &prefix))?;
    if conflict {
        return Err(invalid("conflicting authenticated heads retained"));
    }
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
pub(super) fn start_entry(
    room: &ChannelState,
    store: &Store,
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
    if !input.history_head_committed(&head, included.binding())? {
        drop(input);
        return match promote_head(room, store, head)? {
            Advanced::Need(query) => Ok(EntryStart::Need(query)),
            _ => Ok(EntryStart::Busy),
        };
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
    if !room.history_write(store, |index| {
        index.keep_history_verifier_cursor(binding, &HistoryVerifier::Validation(cursor))
    })? {
        return Ok(EntryStart::Busy);
    }
    Ok(EntryStart::Cursor(binding))
}

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
    room.history_write(store, |index| {
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
