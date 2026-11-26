//! One explicitly authorized response quantum. Continuations describe remaining work and never
//! schedule it. The caller owns admission, stream lifetime and daemon-wide worker reservation.

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::entry::Entry;
use crate::log::history::{HeadTarget, MAX_CHUNK_BYTES, MAX_HEADER_BYTES, MAX_PAYLOAD_BYTES};
use crate::node::channel::{HistoryPayload, ResolvedTarget};

use super::credit::Response;
use super::source::{Lookup, Source};
use super::transport::Transport;
use super::{Continuation, Frame, Object, Preamble, Proof, Purpose, Query, Status};

const MIB: usize = 1024 * 1024;
// ACK is fixed-shape and far smaller; reserve before sending a chunk so its acknowledgement
// cannot consume the terminal DONE credit. Duplicate ACKs are charged too, not free input.
const ACK_RESERVE: usize = 128;

/// **For proofs only.** While this marker exists, the first private key-package requested by a
/// non-recipient is deliberately served once, then the marker is renamed with `.engaged`
/// appended.  This makes a real peer hostile at the wire boundary so another shipped daemon can
/// prove it refuses the unexpected ciphertext before persistence.  It is absent from installable
/// builds (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_SERVE_PRIVATE_BODY_ENV: &str = "VOX_TEST_SERVE_NONRECIPIENT_HISTORY_BODY_FILE";

fn test_private_body_marker() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    #[cfg(feature = "test-knobs")]
    {
        let trigger = std::path::PathBuf::from(std::env::var(TEST_SERVE_PRIVATE_BODY_ENV).ok()?);
        if !trigger.is_file() {
            return None;
        }
        let mut engaged = trigger.as_os_str().to_os_string();
        engaged.push(".engaged");
        Some((trigger, engaged.into()))
    }
    #[cfg(not(feature = "test-knobs"))]
    None
}

enum Sent {
    Yes,
    Full,
    Busy,
}

/// What a bundle that stopped on `sent` answers: More when the object did not fit what is left
/// of the response quantum (the asker continues where it stopped, `Query::Range`'s `skip`),
/// Busy otherwise. A stop before any wanted position answers with the continuation naming the
/// want's first position (`next(lo, None, 0)` in `range`): a More always carries one (the
/// frame codec refuses a More without it, `history_stream.rs` `done_shape`).
fn stopped(sent: Sent) -> Status {
    match sent {
        Sent::Full => Status::More,
        _ => Status::Busy,
    }
}

/// The contexts one bundle sent, each distinct one once, and how many of its first contexts
/// the asker already holds from its last answer to the same request (`Query::Range`'s `skip`):
/// those are counted as sent, in the same order, without being sent again.
struct BundleContexts {
    sent: std::collections::HashSet<Digest32>,
    skip: u64,
}

struct EntryResult {
    status: Status,
    hash: Option<Digest32>,
    offset: u64,
    role_complete: bool,
}

impl EntryResult {
    /// The answer to an entry whose asked head this node could not resolve (ADR-053 P): the
    /// same answer as an entry it lacks, with no header sent.
    fn unresolved(status: Status, offset: u64) -> Self {
        Self {
            status,
            hash: None,
            offset,
            role_complete: false,
        }
    }
}

#[allow(clippy::too_many_arguments)] // One bound stream and the node's peer holdings.
pub(super) async fn answer(
    source: &Source,
    io: &mut Transport,
    preamble: Preamble,
    asked: super::Asked,
    holdings: &std::sync::Arc<super::pull::Holdings>,
    conn: &crate::transport::quic::VoxConnection,
    served_object: &mut bool,
) -> Result<(Status, Source, Option<u64>)> {
    let super::Asked {
        query,
        target,
        mut credit,
        holding,
        patient,
    } = asked;
    // A loop's exchange (its Have, its Range, the fork proof or unresolved head by id its
    // peer's Have listed (MP-9), its exact receipt) is answered, never refused Busy: the task
    // waits for the local admission it needs until the asker's stream or the connection ends
    // (design simple-sync §1, serving). The old flows' queries keep their refusals.
    let patient_source;
    let source = if patient {
        patient_source = source.patient();
        &patient_source
    } else {
        source
    };
    let receipt_source;
    let recovery_source;
    let source = if preamble.purpose == Purpose::Control
        && matches!(query, Query::Head(author) if author == source.peer)
    {
        receipt_source = source.for_own_head_receipt();
        &receipt_source
    } else {
        // The server clone may pass the room gate for a returning author only after this
        // exact query has been confined to that author's own authenticated public tree.
        recovery_source = source.for_own_recovery();
        let peer = source.peer;
        let check = query.clone();
        let allowed = recovery_source
            .serve_read(io.job(), 128 * 1024, move |room, store| {
                #[cfg(feature = "test-knobs")]
                let mutant = crate::node::computer::fx28_mutant("sync-departed-peer")
                    && room.has_left(&peer);
                #[cfg(not(feature = "test-knobs"))]
                let mutant = false;
                // This node left the room (ADR-023 RL-8.1a): it holds the room only so a
                // member can take its departure. A member catching up asks for whatever it
                // lacks — other authors' heads and entries too, and the departure may be the
                // last thing it reaches — and a refused query ends its whole session before
                // it gets there (measured: a member back from offline never took the
                // departure, its roster kept the leaver). So a member is still served the
                // room's public history, as it was while this node was a member a moment ago
                // and as it was while a leave waited to be heard before this ruling; what
                // stops at once is everything else: services, Sessions, relays. A stranger
                // gets the own-recovery confinement below, as before.
                let me = room.me();
                if room.has_left(&me) && !mutant && !room.is_member(&peer) {
                    return Ok(Some((false, false)));
                }
                if mutant || room.is_member(&peer) {
                    return Ok(Some((true, false)));
                }
                let allowed = match check {
                    Query::Head(author) => author == peer,
                    // A Have is the returning author's news for this node's loop toward it,
                    // which tells it only its own row (`pull::tell`); the answer is the Done.
                    // The own-recovery source's access check admits only recovery standing.
                    Query::Have => true,
                    // A Range is confined as the old own-recovery queries are: the named head
                    // is the asker's own public tree, and every context the bundle carries is
                    // authorized as exposed by that head's proofs and headers (`send_contexts`).
                    Query::Header { head, .. }
                    | Query::Proof { head, .. }
                    | Query::Entry { head, .. }
                    | Query::Page { head, .. }
                    | Query::Range { head, .. } => {
                        room.history_head_by_id(store, &head)?.is_some_and(|head| {
                            head.binding.author == peer
                                && head.binding.scope == crate::log::history::LogScope::Public
                        })
                    }
                    Query::Context(hash) => {
                        room.recovery_context_allowed(store, &peer, &hash)?
                            || room
                                .history_head(store, &peer)?
                                .is_some_and(|head| head.root.frontier == hash)
                    }
                    _ => false,
                };
                Ok(Some((allowed, true)))
            })
            .await?;
        match allowed {
            Lookup::Found(held) if held.value == (true, true) => &recovery_source,
            Lookup::Found(held) if held.value == (true, false) => source,
            Lookup::Busy => return Err(Error::Unreachable("history authorization busy")),
            _ => return Err(Error::Unreachable("history query outside own recovery")),
        }
    };
    let request = preamble.request;
    if preamble.purpose != Purpose::History && matches!(query, Query::Page { .. }) {
        return Err(Error::MalformedBundle(
            "archive page requires history reservation",
        ));
    }
    if preamble.purpose != Purpose::Live && matches!(query, Query::Range { .. }) {
        return Err(Error::MalformedBundle(
            "range bundle requires live reservation",
        ));
    }
    if let Some(incoming) = holding {
        // A peer's Have is news for this connection's loop; its one HOLDING frame, read before
        // admission (`read_ask`), shares this request's wire credit, and the answer is only the
        // Done.
        credit.charge_overhead(incoming.wire_len())?;
        match incoming.frame()? {
            Frame::Holding(authors) => {
                holdings.merge(preamble.room, source.peer, conn, &authors, None);
            }
            // The holder's private Session tip (Drive peers only): kept beside its Have.
            Frame::PrivateHolding(authors, tip) => {
                holdings.merge(preamble.room, source.peer, conn, &authors, Some(tip));
            }
            // The holder's own-release section: what it retains of this node's own sender
            // releases (`pull::tell` sends it only to their author). Only an entry naming this
            // node is ever asked (`pull::own_release`).
            Frame::Releases(releases) => {
                holdings.merge_releases(preamble.room, source.peer, conn, &releases);
            }
            _ => return Err(Error::MalformedBundle("have expected one HOLDING")),
        }
    }
    #[cfg(feature = "test-knobs")]
    let staged_unavailable = std::env::var_os("VOX_TEST_UNAVAILABLE_HEAD_FILE")
        .and_then(|path| std::fs::read_to_string(path).ok())
        .is_some_and(|text| {
            let mut ids = text.split_whitespace();
            let author = ids.next();
            let peer = ids.next();
            matches!(query, Query::Head(id) if author == Some(crate::node::link::b32_encode(&id).as_str()))
                && peer == Some(crate::node::link::b32_encode(&source.peer).as_str())
        })
        // `VOX_TEST_HEADS_ONLY_FILE` = `<peer> [floor]`: that peer gets only heads, consistency
        // proofs, contexts and inventory from this node, plus headers and inclusion proofs at
        // positions from `floor` on (none without one): it commits a head whose tip is past the
        // floor and holds no evidence below it (ADR-053 P availability act).
        || std::env::var_os("VOX_TEST_HEADS_ONLY_FILE")
            .and_then(|path| std::fs::read_to_string(path).ok())
            .is_some_and(|text| {
                let mut words = text.split_whitespace();
                let named = words.next() == Some(crate::node::link::b32_encode(&source.peer).as_str());
                let floor = words.next().and_then(|floor| floor.parse::<u64>().ok());
                let below = |seq: u64| floor.is_none_or(|floor| seq < floor);
                named
                    && match &query {
                        Query::Header { seq, .. } => below(*seq),
                        Query::Proof {
                            kind: super::ProofKind::Inclusion,
                            from,
                            ..
                        } => below(*from),
                        Query::Entry { .. }
                        | Query::Page { .. }
                        | Query::Proof {
                            kind: super::ProofKind::Control,
                            ..
                        } => true,
                        // A loop's Range: its positions from `lo` (or the body's position)
                        // below the floor are not served; control intervals never are.
                        Query::Range { want, .. } => match want {
                            super::RangeWant::Entries { lo, .. } => below(*lo),
                            super::RangeWant::Body { seq, .. } => below(*seq),
                            super::RangeWant::Controls { .. } => true,
                        },
                        _ => false,
                    }
            });
    // A holder that kept an author's accepted head but no opening of it (MP-9 staging,
    // `admission::no_accepted_opening`): nothing under that accepted head, nor under a prefix of
    // it (ADR-053 P), is served; only what it proved under the kept unresolved head is.
    #[cfg(feature = "test-knobs")]
    let staged_unavailable = staged_unavailable
        || match (query.clone(), target) {
            (
                Query::Header { head, .. }
                | Query::Proof { head, .. }
                | Query::Entry { head, .. }
                | Query::Page { head, .. }
                | Query::Range { head, .. },
                Some(target),
            ) if super::admission::no_accepted_opening(&target.binding.author) => matches!(
                source
                    .serve_read(io.job(), 0, move |room, store| {
                        Ok(Some(
                            room.history_read(store)?
                                .history_unresolved_head(&target.binding.author)?
                                != Some(head),
                        ))
                    })
                    .await?,
                Lookup::Found(found) if found.value
            ),
            _ => false,
        };
    #[cfg(not(feature = "test-knobs"))]
    let staged_unavailable = false;
    // `VOX_TEST_REFUSE_ENTRIES_FILE` = `<peer> <from> <to> [busy]`: that peer's body asks
    // (`Query::Entry`) at positions `from..=to` are answered EvidenceUnavailable, or Busy with
    // `busy`; every other ask is served as usual. Each such answer is said on stderr.
    #[cfg(feature = "test-knobs")]
    let staged_refusal = std::env::var_os("VOX_TEST_REFUSE_ENTRIES_FILE")
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| {
            let peer = crate::node::link::b32_encode(&source.peer);
            let mut words = text.split_whitespace();
            let named = words.next() == Some(peer.as_str());
            let mut bound = || words.next().and_then(|at| at.parse::<u64>().ok());
            let (from, to) = (bound(), bound());
            let busy = words.next() == Some("busy");
            match (&query, from, to) {
                (Query::Entry { seq, .. }, Some(from), Some(to))
                    if named && (from..=to).contains(seq) =>
                {
                    eprintln!(
                        "vox: VOX_TEST_REFUSE_ENTRIES_FILE answered {} peer={peer} seq={seq}",
                        if busy { "busy" } else { "evidence-unavailable" }
                    );
                    Some(if busy {
                        Status::Busy
                    } else {
                        Status::EvidenceUnavailable
                    })
                }
                _ => None,
            }
        });
    #[cfg(not(feature = "test-knobs"))]
    let staged_refusal: Option<Status> = None;
    // The size of the own-feed receipt this answer serves the peer, if it serves one.
    let mut receipt_size = None;
    let (status, continuation) = if staged_unavailable {
        (Status::EvidenceUnavailable, None)
    } else if let Some(status) = staged_refusal {
        (status, None)
    } else if credit.remaining_wire() < super::DONE_RESERVE {
        (Status::Busy, None)
    } else {
        respond(
            source,
            io,
            preamble,
            &query,
            target,
            &mut credit,
            served_object,
            &mut receipt_size,
        )
        .await?
    };
    // Source objects and their envelopes have been dropped before the terminal allocation.
    let done = Frame::Done {
        request,
        status,
        continuation,
    };
    let encoded = loop {
        match done.encode(io.job())? {
            Some(encoded) => break encoded,
            None if source.is_patient() => {
                source
                    .released(io.job().byte_pressure(4 * super::DONE_RESERVE)?)
                    .await?;
            }
            None => return Err(Error::Unreachable("history terminal buffer busy")),
        }
    };
    credit.accept(&done, encoded.as_slice().len() + 4)?;
    io.push(encoded);
    // The size of the own-feed receipt this answer carries, if complete: recorded as served
    // (`Holdings::receipt_served`) only once its frames have been written to the transport
    // (`history_stream::serve`), never here during assembly.
    let receipt = receipt_size.filter(|_| status == Status::Complete);
    // The access this answer was served under, checked again before each frame is written.
    Ok((status, source.clone(), receipt))
}

async fn send(
    source: &Source,
    io: &mut Transport,
    credit: &mut Response,
    frame: Frame<'_>,
    credit_reply_reserve: usize,
) -> Result<Sent> {
    let encoded = if source.is_patient() {
        loop {
            match frame.encode_required(io.job()) {
                Ok(encoded) => break encoded,
                Err(Error::HistoryCapacity(pressure)) => source.released(*pressure).await?,
                Err(error) => return Err(error),
            }
        }
    } else {
        let Some(encoded) = frame.encode(io.job())? else {
            return Ok(Sent::Busy);
        };
        encoded
    };
    let wire = encoded.as_slice().len() + 4;
    if !credit.fits_data(wire + credit_reply_reserve) {
        return Ok(Sent::Full);
    }
    if !source.authorize(io.job()).await? {
        return Ok(Sent::Busy);
    }
    credit.accept(&frame, wire)?;
    io.push(encoded);
    Ok(Sent::Yes)
}

async fn send_object(
    source: &Source,
    io: &mut Transport,
    credit: &mut Response,
    frame: Frame<'_>,
    credit_reply_reserve: usize,
    served_object: &mut bool,
) -> Result<Sent> {
    let sent = send(source, io, credit, frame, credit_reply_reserve).await?;
    if matches!(sent, Sent::Yes) {
        *served_object = true;
    }
    Ok(sent)
}

#[allow(clippy::too_many_arguments)]
async fn respond(
    source: &Source,
    io: &mut Transport,
    preamble: Preamble,
    query: &Query,
    target: Option<HeadTarget>,
    credit: &mut Response,
    served_object: &mut bool,
    receipt_size: &mut Option<u64>,
) -> Result<(Status, Option<Continuation>)> {
    let job = io.job().clone();
    let request = preamble.request;
    // A head-bound query is served under the asker's head resolved to this node's own committed
    // material (ADR-053 P); the codec already bound the target body to the named head.
    let target = match (query.target_head(), target) {
        (Some(_), Some(target)) => Some(target),
        (None, None) => None,
        _ => {
            return Err(Error::MalformedBundle(
                "history request target differs from query",
            ))
        }
    };
    match *query {
        Query::Have => Ok((Status::Complete, None)),
        Query::Head(author) => {
            // Only a Control Head is a role receipt; Live Head is commitment discovery.
            let receipt = preamble.purpose == Purpose::Control && author == source.peer;
            let found = source
                .serve_read(&job, 128 * 1024, move |room, store| {
                    let Some(head) = (if receipt {
                        room.history_role_head(store, &author)?
                    } else {
                        room.history_head(store, &author)?
                    }) else {
                        return Ok(None);
                    };
                    let boundary = if receipt && head.root.leaves != 0 {
                        let read = room.history_read(store)?;
                        let Some(included) =
                            read.history_inclusion_receipt(&head.id(), &author, head.root.leaves)?
                        else {
                            return Ok(None);
                        };
                        Some(included.header().entry().entry_hash())
                    } else {
                        None
                    };
                    Ok(Some((head, boundary)))
                })
                .await?;
            let held = match found {
                Lookup::Found(held) => held,
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
            };
            let (head, _boundary) = held.value;
            if receipt {
                source
                    .flush_authors_before_ack(preamble.room, vec![author])
                    .await?;
            }
            let wire = head.to_wire();
            let status = match send_object(
                source,
                io,
                credit,
                Frame::Meta {
                    request,
                    object: Object::Head(&wire),
                },
                0,
                served_object,
            )
            .await?
            {
                Sent::Yes => {
                    if receipt {
                        *receipt_size = Some(head.root.leaves);
                    }
                    Status::Complete
                }
                Sent::Busy | Sent::Full => Status::Busy,
            };
            Ok((status, None))
        }
        Query::HeadById(id) => {
            // MP-9 (rule 6): a committed head or the author's kept unresolved head, by its exact
            // id; only its signed bytes travel, to the peer that asked. Nothing else is served.
            let found = source
                .serve_read(&job, 128 * 1024, move |room, store| {
                    Ok(room
                        .history_head_by_id(store, &id)?
                        .filter(|head| head.binding.scope == crate::log::history::LogScope::Public))
                })
                .await?;
            let held = match found {
                Lookup::Found(held) => held,
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
            };
            let wire = held.value.to_wire();
            let status = match send_object(
                source,
                io,
                credit,
                Frame::Meta {
                    request,
                    object: Object::Head(&wire),
                },
                0,
                served_object,
            )
            .await?
            {
                Sent::Yes => Status::Complete,
                Sent::Busy | Sent::Full => Status::Busy,
            };
            Ok((status, None))
        }
        Query::Fork(author) => {
            // Only the proof this node verified and kept (MP-9): two signed headers, no body.
            let found = source
                .serve_read(
                    &job,
                    2 * crate::log::history::MAX_HEADER_BYTES,
                    move |room, _| Ok(room.history_fork_proof(&author)),
                )
                .await?;
            let held = match found {
                Lookup::Found(held) => held,
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
            };
            let (existing, conflicting) = &held.value;
            let status = match send_object(
                source,
                io,
                credit,
                Frame::Meta {
                    request,
                    object: Object::Fork {
                        existing,
                        conflicting,
                    },
                },
                0,
                served_object,
            )
            .await?
            {
                Sent::Yes => Status::Complete,
                Sent::Busy | Sent::Full => Status::Busy,
            };
            Ok((status, None))
        }
        Query::Context(hash) => {
            let found = source
                .serve_read(&job, 2 * MIB, move |room, store| {
                    room.history_context(store, &hash)
                })
                .await?;
            let held = match found {
                Lookup::Found(held) => held,
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
            };
            let wire = held.value.to_wire()?;
            let status = match send_object(
                source,
                io,
                credit,
                Frame::Meta {
                    request,
                    object: Object::Context(&wire),
                },
                0,
                served_object,
            )
            .await?
            {
                Sent::Yes => Status::Complete,
                Sent::Busy | Sent::Full => Status::Busy,
            };
            Ok((status, None))
        }
        Query::Header { seq, .. } => {
            let target = target.ok_or(Error::MalformedBundle("header query without target"))?;
            if seq > target.root.leaves {
                return Err(Error::MalformedBundle("requested header exceeds head"));
            }
            let resolved = match source.resolve(&job, target, "header").await? {
                Lookup::Found(held) => held,
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
            };
            let work_job = resolved.job();
            let resolved = resolved.value;
            let found = source
                .serve_read(&work_job, 128 * 1024, move |room, store| {
                    Ok(room
                        .history_proof_header(store, &resolved, seq)?
                        .map(|header| (resolved, header)))
                })
                .await?;
            let held = match found {
                Lookup::Found(held) => held,
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
            };
            let parsed = Entry::from_wire(&held.value.1.wire)?;
            let contexts = parsed
                .skeleton
                .v2
                .as_ref()
                .map(|v2| vec![v2.pre_context])
                .unwrap_or_default();
            if !source
                .authorize_recovery_contexts(&work_job, &held.value.0, contexts)
                .await?
            {
                return Ok((Status::Busy, None));
            }
            let status = match send_object(
                source,
                io,
                credit,
                Frame::Meta {
                    request,
                    object: Object::Header(&held.value.1.wire),
                },
                0,
                served_object,
            )
            .await?
            {
                Sent::Yes => Status::Complete,
                Sent::Busy | Sent::Full => Status::Busy,
            };
            Ok((status, None))
        }
        Query::Proof {
            head,
            kind,
            from,
            to,
        } => {
            let target = target.ok_or(Error::MalformedBundle("proof query without target"))?;
            let stage = match kind {
                super::ProofKind::Inclusion => "inclusion",
                super::ProofKind::Consistency => "consistency",
                super::ProofKind::Control => "control",
            };
            let held_head = match source.resolve(&job, target, stage).await? {
                Lookup::Found(held) => held,
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
            };
            let work_job = held_head.job();
            let held_proof = match source
                .proof(&work_job, &held_head.value, kind, from, to)
                .await?
            {
                Lookup::Found(held) => held,
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
            };
            let mut contexts = vec![held_head.value.target.root.frontier];
            match &held_proof.value {
                Proof::Inclusion(proof) => {
                    contexts.extend(proof.siblings.iter().map(|node| node.frontier))
                }
                Proof::Consistency { prefix, proof } => {
                    contexts.push(prefix.frontier);
                    contexts.extend(proof.nodes.iter().map(|node| node.frontier));
                }
                Proof::Control(proof) => {
                    for token in &proof.tokens {
                        match token {
                            crate::log::history::ControlToken::Collapse(node) => {
                                contexts.push(node.frontier)
                            }
                            crate::log::history::ControlToken::Leaf(entry) => {
                                if let Some(v2) = &entry.skeleton.v2 {
                                    contexts.push(v2.pre_context);
                                }
                            }
                            crate::log::history::ControlToken::Branch => {}
                        }
                    }
                }
            }
            if !source
                .authorize_recovery_contexts(&work_job, &held_head.value, contexts)
                .await?
            {
                return Ok((Status::Busy, None));
            }
            let continuation = match &held_proof.value {
                Proof::Control(proof) if proof.hi < to => Some(Continuation {
                    query_kind: 2,
                    head,
                    lo: from,
                    hi: to,
                    next_seq: proof.hi + 1,
                    entry: None,
                    offset: 0,
                    entries_remaining: 0,
                }),
                _ => None,
            };
            let frame = Frame::Meta {
                request,
                object: Object::Proof(held_proof.value),
            };
            match send_object(source, io, credit, frame, 0, served_object).await? {
                Sent::Yes if continuation.is_some() => Ok((Status::More, continuation)),
                Sent::Yes => Ok((Status::Complete, None)),
                Sent::Busy | Sent::Full => Ok((Status::Busy, None)),
            }
        }
        Query::Entry { head, seq, offset } => {
            let resolved = match target {
                Some(target) => {
                    if seq == 0 || seq > target.root.leaves {
                        return Err(Error::MalformedBundle("requested entry exceeds head"));
                    }
                    Some(source.resolve(&job, target, "entry").await?)
                }
                None => None,
            };
            let result = match &resolved {
                Some(Lookup::Found(resolved)) => {
                    entry(
                        source,
                        io,
                        preamble,
                        credit,
                        Some(resolved),
                        None,
                        seq,
                        offset,
                        false,
                        false,
                        served_object,
                    )
                    .await?
                }
                Some(Lookup::Busy) => EntryResult::unresolved(Status::Busy, offset),
                Some(Lookup::Missing) => {
                    EntryResult::unresolved(Status::EvidenceUnavailable, offset)
                }
                None => {
                    entry(
                        source,
                        io,
                        preamble,
                        credit,
                        None,
                        None,
                        seq,
                        offset,
                        false,
                        false,
                        served_object,
                    )
                    .await?
                }
            };
            let cursor = (result.status != Status::Complete
                && (result.hash.is_some() || result.offset == 0))
                .then_some(Continuation {
                    query_kind: 3,
                    head,
                    lo: seq,
                    hi: seq,
                    next_seq: seq,
                    entry: result.hash,
                    offset: result.offset,
                    entries_remaining: 0,
                });
            Ok((result.status, cursor))
        }
        Query::Page { head, lo, hi, .. } => {
            let target = target.ok_or(Error::MalformedBundle("page query without target"))?;
            if hi > target.root.leaves {
                return Err(Error::MalformedBundle("requested entry exceeds head"));
            }
            // One resolution serves the whole page: every position is under the same asked head.
            let resolved = match source.resolve(&job, target, "entry").await? {
                Lookup::Found(resolved) => resolved,
                unresolved => {
                    // The same answer as a first position this node lacks.
                    let status = if matches!(unresolved, Lookup::Busy) {
                        Status::Busy
                    } else {
                        Status::EvidenceUnavailable
                    };
                    return Ok((
                        status,
                        Some(Continuation {
                            query_kind: 4,
                            head,
                            lo,
                            hi,
                            next_seq: hi,
                            entry: None,
                            offset: 0,
                            entries_remaining: credit.headers_left(),
                        }),
                    ));
                }
            };
            // Newest first (ADR-037 R1): a page is what a reader asked for below the oldest row
            // it shows, so its rows arrive from the top down and an interrupted page leaves a
            // contiguous top and a missing bottom, never a hole. Served oldest-first, a page the
            // reader's next ask cut short left rendered rows below unrendered ones; nothing
            // refilled the hole, and the ask below the bottom row found nothing to fetch.
            for seq in (lo..=hi).rev() {
                let result = entry(
                    source,
                    io,
                    preamble,
                    credit,
                    Some(&resolved),
                    None,
                    seq,
                    0,
                    false,
                    false,
                    served_object,
                )
                .await?;
                if result.status != Status::Complete {
                    return Ok((
                        result.status,
                        Some(Continuation {
                            query_kind: 4,
                            head,
                            lo,
                            hi,
                            next_seq: seq,
                            entry: result.hash,
                            offset: result.offset,
                            entries_remaining: credit.headers_left(),
                        }),
                    ));
                }
                if result.role_complete {
                    // The receiver still has to prove inclusion and commit this authenticated
                    // header's role-specific effect. Keep the durable continuation on this
                    // exact position: only the receiver's semantic-effect transaction may move
                    // it below the header while decrementing the demand. A cancellation between
                    // this response and that transaction therefore retries rather than skips it.
                    return Ok((
                        Status::More,
                        Some(Continuation {
                            query_kind: 4,
                            head,
                            lo,
                            hi,
                            next_seq: seq,
                            entry: None,
                            offset: 0,
                            entries_remaining: credit.headers_left(),
                        }),
                    ));
                }
                if credit.headers_left() == 0 || seq == lo {
                    return Ok((Status::Complete, None));
                }
                // Each iteration consumes a header credit; the enclosing interval cannot turn
                // an authorized 128-entry page into an arbitrary-size archive traversal.
                tokio::task::yield_now().await;
            }
            Err(Error::MalformedBundle("empty history page"))
        }
        Query::Range {
            head,
            anchor,
            want,
            skip,
        } => {
            let target = target.ok_or(Error::MalformedBundle("range query without target"))?;
            if want.interval().1 > target.root.leaves || anchor > target.root.leaves {
                return Err(Error::MalformedBundle("requested range exceeds head"));
            }
            let mut unserved = Vec::new();
            let (status, next) = match source.resolve(&job, target, "range").await? {
                Lookup::Found(resolved) => {
                    range(
                        source,
                        io,
                        preamble,
                        credit,
                        head,
                        &resolved,
                        anchor,
                        want,
                        skip,
                        served_object,
                        &mut unserved,
                    )
                    .await?
                }
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => (Status::EvidenceUnavailable, None),
            };
            if status == Status::EvidenceUnavailable || !unserved.is_empty() {
                // It could not serve all it was asked inside what it told: its answer carries
                // its Have pages of this author over the asked positions as they are now,
                // without what it could not serve, which the asker takes in place of what it
                // holds there (ADR-054 PL-7.6; `AuthorHave::bodies_span`).
                let author = target.binding.author;
                let (lo, hi) = want.interval();
                let mut pages = match source
                    .serve_read(&job, 512 * 1024, move |room, _| {
                        Ok(Some(room.held_pages(&author, lo, hi)))
                    })
                    .await?
                {
                    Lookup::Found(pages) => pages.value,
                    _ => Vec::new(),
                };
                // The newest page first, then the older body pages over the asked interval:
                // at most `MAX_CORRECTION_PAGES` for Entries and Body (`history_stream.rs`). A
                // Controls answer corrects only control runs, which only the newest page holds.
                if matches!(want, super::RangeWant::Controls { .. }) {
                    pages.truncate(1);
                }
                if pages.is_empty() {
                    pages.push(super::AuthorHave {
                        author,
                        ..super::AuthorHave::default()
                    });
                }
                for have in &mut pages {
                    if status == Status::EvidenceUnavailable {
                        let from = next.as_ref().map_or(lo, |next| next.next_seq.max(lo));
                        let runs = match want {
                            super::RangeWant::Entries { .. } => super::HaveRuns::Proof,
                            super::RangeWant::Controls { .. } => super::HaveRuns::Controls,
                            super::RangeWant::Body { .. } => super::HaveRuns::Bodies,
                        };
                        *have = std::mem::take(have).without(runs, from, hi);
                    }
                    for &seq in &unserved {
                        *have = std::mem::take(have).without(super::HaveRuns::Bodies, seq, seq);
                    }
                }
                let _ = send(source, io, credit, Frame::Holding(pages), 0).await?;
            }
            Ok((status, next))
        }
    }
}

/// One Range bundle (design simple-sync §1): the existing proof forms under one resolved head,
/// each distinct context once, cut at the response quantum with an explicit next position.
/// Every entry goes through `entry`, so every recipient, removal and physical-send check of the
/// Entry path applies; a header this node holds only as inclusion evidence goes without a body.
#[allow(clippy::too_many_arguments)]
async fn range(
    source: &Source,
    io: &mut Transport,
    preamble: Preamble,
    credit: &mut Response,
    head: Digest32,
    resolved: &super::source::Held<ResolvedTarget>,
    anchor: u64,
    want: super::RangeWant,
    skip: u64,
    served_object: &mut bool,
    unserved: &mut Vec<u64>,
) -> Result<(Status, Option<Continuation>)> {
    use super::{ProofKind, RangeWant};
    let job = resolved.job();
    let target = resolved.value;
    let request = preamble.request;
    let (lo, hi) = want.interval();
    let next = |next_seq: u64, entry: Option<Digest32>, offset: u64| {
        (entry.is_some() || offset == 0).then_some(Continuation {
            query_kind: 5,
            head,
            lo,
            hi,
            next_seq,
            entry,
            offset,
            entries_remaining: 0,
        })
    };
    let mut sent = BundleContexts {
        sent: std::collections::HashSet::new(),
        skip,
    };
    // The signed head, when this node holds its object: a head served under ADR-053 P may be
    // held only by the asker, who named it.
    if let Lookup::Found(signed) = source
        .serve_read(&job, 128 * 1024, move |room, store| {
            room.history_read(store)?.history_head(&head)
        })
        .await?
    {
        let wire = signed.value.to_wire();
        let frame = Frame::Meta {
            request,
            object: Object::Head(&wire),
        };
        match send(source, io, credit, frame, 0).await? {
            Sent::Yes => {}
            other => return Ok((stopped(other), next(lo, None, 0))),
        }
    }
    let leaves = target.target.root.leaves;
    // A consistency proof from the size the asker named (0: from the empty tree), unless it
    // named the head's own size.
    if anchor < leaves {
        let proof = match source
            .proof(&job, &target, ProofKind::Consistency, anchor, leaves)
            .await?
        {
            Lookup::Found(proof) => proof.value,
            Lookup::Busy => return Ok((Status::Busy, None)),
            Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
        };
        let mut frontiers = vec![target.target.root.frontier];
        if let Proof::Consistency { prefix, proof } = &proof {
            frontiers.push(prefix.frontier);
            frontiers.extend(proof.nodes.iter().map(|node| node.frontier));
        }
        match send_contexts(source, io, credit, &job, &mut sent, &target, frontiers).await? {
            Some(Sent::Yes) => {}
            Some(other @ (Sent::Full | Sent::Busy)) => {
                return Ok((stopped(other), next(lo, None, 0)))
            }
            None => return Ok((Status::EvidenceUnavailable, None)),
        }
        let frame = Frame::Meta {
            request,
            object: Object::Proof(proof),
        };
        match send(source, io, credit, frame, 0).await? {
            Sent::Yes => {}
            other => return Ok((stopped(other), next(lo, None, 0))),
        }
        // The receipt of the head's terminal position (header and inclusion, no body), when
        // the want does not reach it: the asker has not committed this head, and commits it
        // with this receipt (it carries the tail epoch) before anything else the answer brings
        // is handed over there. Sent first, so an answer cut later still commits the head.
        if !matches!(want, RangeWant::Entries { hi, .. } if hi == leaves) {
            let author = target.target.binding.author;
            let header = match source
                .serve_read(&job, 128 * 1024, move |room, store| {
                    room.history_proof_header(store, &target, leaves)
                })
                .await?
            {
                Lookup::Found(header) => header.value,
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
            };
            let parsed = Entry::from_wire(&header.wire)?;
            if parsed.skeleton.author_id != author || parsed.skeleton.seq != leaves {
                return Err(Error::MalformedAtRest("range terminal position differs"));
            }
            let proof = match source
                .proof(&job, &target, ProofKind::Inclusion, leaves, leaves)
                .await?
            {
                Lookup::Found(proof) => proof.value,
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
            };
            let mut frontiers = vec![target.target.root.frontier];
            if let Some(v2) = &parsed.skeleton.v2 {
                frontiers.push(v2.pre_context);
            }
            if let Proof::Inclusion(proof) = &proof {
                frontiers.extend(proof.siblings.iter().map(|node| node.frontier));
            }
            match send_contexts(source, io, credit, &job, &mut sent, &target, frontiers).await? {
                Some(Sent::Yes) => {}
                Some(other @ (Sent::Full | Sent::Busy)) => {
                    return Ok((stopped(other), next(lo, None, 0)))
                }
                None => return Ok((Status::EvidenceUnavailable, None)),
            }
            let frame = Frame::Meta {
                request,
                object: Object::Proof(proof),
            };
            match send(source, io, credit, frame, 0).await? {
                Sent::Yes => {}
                other => return Ok((stopped(other), next(lo, None, 0))),
            }
            let frame = Frame::Meta {
                request,
                object: Object::Header(&header.wire),
            };
            match send_object(source, io, credit, frame, 0, served_object).await? {
                Sent::Yes => {}
                other => return Ok((stopped(other), next(lo, None, 0))),
            }
        }
    }
    match want {
        RangeWant::Entries { .. } => {
            // The page leads with the receipt of `lo - 1`: its header, inclusion and own prefix,
            // without a body (the forms the Header and Proof queries serve). The page's first
            // entry then finds its predecessor's receipt in the same bundle, as every later one
            // does: a page is admissible on arrival and needs no further position. A holder
            // without that receipt sends the page alone.
            for seq in lo.saturating_sub(1).max(1)..=hi {
                let edge = seq < lo;
                // A stop names the asker's next position, never one before `lo`.
                let at = seq.max(lo);
                let author = target.target.binding.author;
                let header = match source
                    .serve_read(&job, 128 * 1024, move |room, store| {
                        room.history_proof_header(store, &target, seq)
                    })
                    .await?
                {
                    Lookup::Found(header) => header.value,
                    Lookup::Busy => return Ok((Status::Busy, next(at, None, 0))),
                    Lookup::Missing if edge => continue,
                    Lookup::Missing => {
                        return Ok((Status::EvidenceUnavailable, next(seq, None, 0)))
                    }
                };
                let parsed = Entry::from_wire(&header.wire)?;
                if parsed.skeleton.author_id != author || parsed.skeleton.seq != seq {
                    return Err(Error::MalformedAtRest("range header position differs"));
                }
                let proof = match source
                    .proof(&job, &target, ProofKind::Inclusion, seq, seq)
                    .await?
                {
                    Lookup::Found(proof) => proof.value,
                    Lookup::Busy => return Ok((Status::Busy, next(at, None, 0))),
                    Lookup::Missing if edge => continue,
                    Lookup::Missing => {
                        return Ok((Status::EvidenceUnavailable, next(seq, None, 0)))
                    }
                };
                // The entry's own prefix [1, seq] under this head, which admission requires
                // before effects can settle it (S/admission.rs start_entry): an existing
                // consistency proof from its position, so no second ask is needed for it.
                // At the head's own size the proof is the trivial one (from = to): its prefix
                // is the root, which admission also needs as range [1, seq]. A holder that does
                // not hold it sends the entry with its header and inclusion alone (the bundle
                // takes an entry without its prefix, `bundle::check`): under a head it never
                // committed (its kept unresolved one, MP-9) what it proved is that position's
                // opening, which a comparison needs, and a prefix range of that head is not
                // kept by position (`keep_history_prefix_receipt`). The page's edge is a parent
                // receipt only with its prefix, so without one it is not sent.
                let prefix = if seq <= target.target.root.leaves {
                    match source
                        .proof(
                            &job,
                            &target,
                            ProofKind::Consistency,
                            seq,
                            target.target.root.leaves,
                        )
                        .await?
                    {
                        Lookup::Found(proof) => Some(proof.value),
                        Lookup::Busy => return Ok((Status::Busy, next(at, None, 0))),
                        Lookup::Missing if edge => continue,
                        Lookup::Missing => None,
                    }
                } else {
                    None
                };
                let mut frontiers = vec![target.target.root.frontier];
                if let Some(v2) = &parsed.skeleton.v2 {
                    frontiers.push(v2.pre_context);
                }
                if let Proof::Inclusion(proof) = &proof {
                    frontiers.extend(proof.siblings.iter().map(|node| node.frontier));
                }
                if let Some(Proof::Consistency { prefix, proof }) = &prefix {
                    frontiers.push(prefix.frontier);
                    frontiers.extend(proof.nodes.iter().map(|node| node.frontier));
                }
                match send_contexts(source, io, credit, &job, &mut sent, &target, frontiers).await?
                {
                    Some(Sent::Yes) => {}
                    Some(Sent::Full) => return Ok((Status::More, next(at, None, 0))),
                    Some(Sent::Busy) => return Ok((Status::Busy, next(at, None, 0))),
                    None if edge => continue,
                    None => return Ok((Status::EvidenceUnavailable, next(at, None, 0))),
                }
                if let Some(prefix) = prefix {
                    let frame = Frame::Meta {
                        request,
                        object: Object::Proof(prefix),
                    };
                    match send(source, io, credit, frame, 0).await? {
                        Sent::Yes => {}
                        Sent::Full => return Ok((Status::More, next(at, None, 0))),
                        Sent::Busy => return Ok((Status::Busy, next(at, None, 0))),
                    }
                }
                let frame = Frame::Meta {
                    request,
                    object: Object::Proof(proof),
                };
                match send(source, io, credit, frame, 0).await? {
                    Sent::Yes => {}
                    Sent::Full => return Ok((Status::More, next(at, None, 0))),
                    Sent::Busy => return Ok((Status::Busy, next(at, None, 0))),
                }
                if edge {
                    let frame = Frame::Meta {
                        request,
                        object: Object::Header(&header.wire),
                    };
                    match send_object(source, io, credit, frame, 0, served_object).await? {
                        Sent::Yes => continue,
                        Sent::Full => return Ok((Status::More, next(lo, None, 0))),
                        Sent::Busy => return Ok((Status::Busy, next(lo, None, 0))),
                    }
                }
                let result = entry(
                    source,
                    io,
                    preamble,
                    credit,
                    Some(resolved),
                    Some(&header.wire),
                    seq,
                    0,
                    false,
                    true,
                    served_object,
                )
                .await?;
                match result.status {
                    Status::Complete => {}
                    Status::BodyNotHeld => unserved.push(seq),
                    // No published position here: the header is this node's inclusion evidence
                    // only, served as the Header query serves it, without a body.
                    Status::EvidenceUnavailable if result.hash.is_none() => {
                        unserved.push(seq);
                        let frame = Frame::Meta {
                            request,
                            object: Object::Header(&header.wire),
                        };
                        match send_object(source, io, credit, frame, 0, served_object).await? {
                            Sent::Yes => {}
                            Sent::Full => return Ok((Status::More, next(seq, None, 0))),
                            Sent::Busy => return Ok((Status::Busy, next(seq, None, 0))),
                        }
                    }
                    status => return Ok((status, next(seq, result.hash, result.offset))),
                }
                tokio::task::yield_now().await;
            }
            Ok((Status::Complete, None))
        }
        // Control coverage is cut into proofs that each fit one whole answer with their contexts
        // (`control_fit`): the largest from `at`, halving what it covers until it fits, down to
        // one position. So an answer is self-contained, proof by proof, and stops between proofs
        // at the next uncovered position (`next(at, ..)`), which the asker's next ask starts
        // from. Only a one-position proof whose contexts do not fit a whole answer is sent cut
        // (`Query::Range`'s `skip` continues it); a proof that fits a whole answer but not what
        // is left of this one is not begun after another proof: the next answer starts with it.
        RangeWant::Controls { .. } => {
            let mut at = lo;
            let mut begun = false;
            while at <= hi {
                let mut to = hi;
                let (proof, through, frontiers, bytes) = loop {
                    let proof = match source
                        .proof(&job, &target, ProofKind::Control, at, to)
                        .await?
                    {
                        Lookup::Found(proof) => proof.value,
                        Lookup::Busy => return Ok((Status::Busy, next(at, None, 0))),
                        Lookup::Missing => {
                            return Ok((Status::EvidenceUnavailable, next(at, None, 0)))
                        }
                    };
                    let Proof::Control(control) = &proof else {
                        return Err(Error::Profile("control proof kind differs"));
                    };
                    let through = control.hi;
                    let mut frontiers = vec![target.target.root.frontier];
                    for token in &control.tokens {
                        match token {
                            crate::log::history::ControlToken::Collapse(node) => {
                                frontiers.push(node.frontier)
                            }
                            crate::log::history::ControlToken::Leaf(entry) => {
                                if let Some(v2) = &entry.skeleton.v2 {
                                    frontiers.push(v2.pre_context);
                                }
                            }
                            crate::log::history::ControlToken::Branch => {}
                        }
                    }
                    let bytes = match control_fit(source, &job, &frontiers).await? {
                        Ok(bytes) => bytes,
                        Err(status) => return Ok((status, next(at, None, 0))),
                    };
                    if bytes.is_some() || through == at {
                        break (proof, through, frontiers, bytes);
                    }
                    to = at + (through - at) / 2;
                };
                // A proof that fits a whole answer but not what is left of this one starts the
                // next answer instead; a one-position proof too large for any answer is begun
                // only before any other proof of this answer (it is then sent cut, and continued).
                let left = credit.remaining_wire().saturating_sub(super::DONE_RESERVE);
                if bytes.map_or(begun, |bytes| bytes > left) {
                    return Ok((Status::More, next(at, None, 0)));
                }
                match send_contexts(source, io, credit, &job, &mut sent, &target, frontiers).await?
                {
                    Some(Sent::Yes) => {}
                    Some(Sent::Full) => return Ok((Status::More, next(at, None, 0))),
                    Some(Sent::Busy) => return Ok((Status::Busy, next(at, None, 0))),
                    None => return Ok((Status::EvidenceUnavailable, next(at, None, 0))),
                }
                let frame = Frame::Meta {
                    request,
                    object: Object::Proof(proof),
                };
                match send_object(source, io, credit, frame, 0, served_object).await? {
                    Sent::Yes => {}
                    Sent::Full => return Ok((Status::More, next(at, None, 0))),
                    Sent::Busy => return Ok((Status::Busy, next(at, None, 0))),
                }
                begun = true;
                at = through + 1;
                tokio::task::yield_now().await;
            }
            Ok((Status::Complete, None))
        }
        // An explicit body request: the asker owes exactly this position's body, a sealed
        // package for another member included (opaque relay, `entry`'s `explicit_body`), after
        // the same recipient-cut check before any reservation or read. The first request
        // (offset 0) carries the position's inclusion under the named head before its header;
        // a later offset continues that checked assembly from the header alone.
        RangeWant::Body { seq, offset } => {
            let selected = if offset == 0 {
                let author = target.target.binding.author;
                let header = match source
                    .serve_read(&job, 128 * 1024, move |room, store| {
                        room.history_proof_header(store, &target, seq)
                    })
                    .await?
                {
                    Lookup::Found(header) => header.value,
                    Lookup::Busy => return Ok((Status::Busy, None)),
                    Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
                };
                let parsed = Entry::from_wire(&header.wire)?;
                if parsed.skeleton.author_id != author || parsed.skeleton.seq != seq {
                    return Err(Error::MalformedAtRest("range body position differs"));
                }
                let proof = match source
                    .proof(&job, &target, ProofKind::Inclusion, seq, seq)
                    .await?
                {
                    Lookup::Found(proof) => proof.value,
                    Lookup::Busy => return Ok((Status::Busy, None)),
                    Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
                };
                let mut frontiers = vec![target.target.root.frontier];
                if let Some(v2) = &parsed.skeleton.v2 {
                    frontiers.push(v2.pre_context);
                }
                if let Proof::Inclusion(proof) = &proof {
                    frontiers.extend(proof.siblings.iter().map(|node| node.frontier));
                }
                match send_contexts(source, io, credit, &job, &mut sent, &target, frontiers).await?
                {
                    Some(Sent::Yes) => {}
                    Some(other @ (Sent::Full | Sent::Busy)) => {
                        return Ok((stopped(other), next(lo, None, 0)))
                    }
                    None => return Ok((Status::EvidenceUnavailable, None)),
                }
                let frame = Frame::Meta {
                    request,
                    object: Object::Proof(proof),
                };
                match send(source, io, credit, frame, 0).await? {
                    Sent::Yes => {}
                    other => return Ok((stopped(other), next(lo, None, 0))),
                }
                Some(header)
            } else {
                None
            };
            let result = entry(
                source,
                io,
                preamble,
                credit,
                Some(resolved),
                selected.as_ref().map(|header| header.wire.as_slice()),
                seq,
                offset,
                true,
                true,
                served_object,
            )
            .await?;
            // A body not served (not held, or the recipient cut refuses it) is corrected out
            // of the asker's Have page, so it is not asked of this holder again.
            if result.status == Status::BodyNotHeld {
                unserved.push(seq);
            }
            Ok(match result.status {
                Status::Complete => (Status::Complete, None),
                // Cut before any byte of a first body: asked again from its start.
                status => (
                    status,
                    next(
                        seq,
                        result.hash.filter(|_| result.offset > 0),
                        result.offset,
                    ),
                ),
            })
        }
    }
}

/// What one whole answer holds for one control proof with the contexts it names: the response
/// quantum less its terminal reserve and less what may precede the proof in it (the request's
/// handshake, which carries the asked head, the head itself, and the terminal receipt's header
/// and two proofs of at most 49 descriptors: within six headers' size).
const CONTROL_ANSWER: usize =
    crate::log::history::MAX_RESPONSE_BYTES - super::DONE_RESERVE - 6 * MAX_HEADER_BYTES;

/// The wire bytes one control proof (counted as one whole frame) and the distinct contexts it
/// names take, when they fit [`CONTROL_ANSWER`]; `None` when they do not. Read once each, in
/// order, until past that. It depends only on the proof, never on what this bundle sent before
/// it: the same request is cut the same way however many of its contexts the asker skips.
/// `Err`: the answer's status when a context is busy or not held here.
async fn control_fit(
    source: &Source,
    job: &crate::node::history_budget::Job,
    frontiers: &[Digest32],
) -> Result<std::result::Result<Option<usize>, Status>> {
    let mut seen = std::collections::HashSet::new();
    let mut bytes = crate::log::history::MAX_FRAME_BYTES;
    for &hash in frontiers {
        if !seen.insert(hash) {
            continue;
        }
        let size = match source
            .serve_read(job, 2 * MIB, move |room, store| {
                room.history_context(store, &hash)?
                    .map(|context| context.to_wire().map(|wire| wire.len()))
                    .transpose()
            })
            .await?
        {
            Lookup::Found(size) => size.value,
            Lookup::Busy => return Ok(Err(Status::Busy)),
            Lookup::Missing => return Ok(Err(Status::EvidenceUnavailable)),
        };
        // The frame around it: request id, tags and lengths.
        bytes += size + 64;
        if bytes > CONTROL_ANSWER {
            return Ok(Ok(None));
        }
    }
    Ok(Ok(Some(bytes)))
}

/// Each context a bundle's proofs and headers name, once per bundle. A context this node lacks
/// leaves the bundle unservable from here: it is never sent as an incomplete proof. The first
/// `skip` of them the asker already holds from its last answer to the same request: they are
/// counted, in order, and not sent again, so a bundle whose contexts do not fit one quantum
/// advances by what each answer carried. To a returning author served under own-recovery
/// standing, the contexts are first authorized as exposed by its own head
/// (`authorize_recovery_contexts`, as the Proof and Header answers do); for a member that is a
/// no-op.
async fn send_contexts(
    source: &Source,
    io: &mut Transport,
    credit: &mut Response,
    job: &crate::node::history_budget::Job,
    sent: &mut BundleContexts,
    target: &ResolvedTarget,
    hashes: Vec<Digest32>,
) -> Result<Option<Sent>> {
    let hashes: Vec<Digest32> = hashes
        .into_iter()
        .filter(|hash| !sent.sent.contains(hash))
        .collect();
    if !source
        .authorize_recovery_contexts(job, target, hashes.clone())
        .await?
    {
        return Ok(Some(Sent::Busy));
    }
    for hash in hashes {
        if sent.sent.contains(&hash) {
            continue;
        }
        if sent.skip > 0 {
            sent.skip -= 1;
            sent.sent.insert(hash);
            continue;
        }
        let context = match source
            .serve_read(job, 2 * MIB, move |room, store| {
                room.history_context(store, &hash)
            })
            .await?
        {
            Lookup::Found(context) => context.value,
            Lookup::Busy => return Ok(Some(Sent::Busy)),
            Lookup::Missing => return Ok(None),
        };
        let wire = context.to_wire()?;
        let frame = Frame::Meta {
            request: credit.request(),
            object: Object::Context(&wire),
        };
        match send(source, io, credit, frame, 0).await? {
            Sent::Yes => {
                sent.sent.insert(hash);
            }
            other => return Ok(Some(other)),
        }
    }
    Ok(Some(Sent::Yes))
}

#[allow(clippy::too_many_arguments)]
async fn entry(
    source: &Source,
    io: &mut Transport,
    preamble: Preamble,
    credit: &mut Response,
    resolved: Option<&super::source::Held<ResolvedTarget>>,
    // The header the caller already selected under `resolved` (`history_proof_header`), if any.
    selected: Option<&[u8]>,
    seq: u64,
    offset: u64,
    explicit_body: bool,
    // A Range bundle's body, held by its reader in its connection's private assembly, bounded by
    // the one response quantum. Any other body (an old flow's Entry or Page, whose chunks each
    // wait for the asker's ACK) is declined: an answer never waits on its asker.
    bundle: bool,
    served_object: &mut bool,
) -> Result<EntryResult> {
    let request = preamble.request;
    let mut result = EntryResult::unresolved(Status::EvidenceUnavailable, offset);
    let head = resolved.ok_or(Error::Profile("history entry without a resolved head"))?;
    // Every dependent header/body read overlaps this held head. Keep its actual worker rather
    // than asking the original Control job to acquire another foreground permit.
    let job = head.job();
    let target = head.value;
    if seq == 0 || seq > target.target.root.leaves {
        return Err(Error::MalformedBundle("requested entry exceeds head"));
    }
    // The header is the one selected under the asked head (MP-9: under an unresolved head, only
    // what is proven under it), never the accepted chain's entry at the same position. Its body
    // is read by its own hash from the published entries only (`history_payload`): a canonical
    // body goes with it only when it is that same entry; otherwise the body is `Missing` below
    // and a Range sends this header alone, as for a position held as inclusion evidence only.
    let read;
    let wire = match selected {
        Some(wire) => wire,
        None => {
            read = match source
                .serve_read(&job, 128 * 1024, move |room, store| {
                    room.history_proof_header(store, &target, seq)
                })
                .await?
            {
                Lookup::Found(held) => held.value,
                Lookup::Busy => {
                    result.status = Status::Busy;
                    return Ok(result);
                }
                Lookup::Missing => return Ok(result),
            };
            read.wire.as_slice()
        }
    };
    let parsed = Entry::from_wire(wire)?;
    if let Some(v2) = &parsed.skeleton.v2 {
        if !source
            .authorize_recovery_contexts(&job, &target, vec![v2.pre_context])
            .await?
        {
            result.status = Status::Busy;
            return Ok(result);
        }
    }
    let hash = parsed.entry_hash();
    let length = parsed.skeleton.payload_len;
    if length > MAX_PAYLOAD_BYTES as u64 || offset > length {
        return Err(Error::MalformedBundle("requested history offset/length"));
    }
    let signed_kind = parsed
        .skeleton
        .v2
        .as_ref()
        .ok_or(Error::MalformedAtRest("bounded response has legacy header"))?
        .kind;
    if preamble.purpose == Purpose::Control && !signed_kind.is_control() {
        return Err(Error::MalformedBundle(
            "content body cannot use control reservation",
        ));
    }
    // #1171: an informed provider never emits an ordinary or key-package body that this
    // once-removed recipient may not newly receive. Decide before any body reservation or
    // read; a stale or missing projection is Busy, never permission. A
    // package for another member keeps its own header-only role path below.
    let package_for_another = signed_kind == crate::log::history::SignedEntryKind::KeyPackage
        && parsed.skeleton.v2.as_ref().and_then(|v2| v2.recipient) != Some(source.peer);
    let recipient_denied = if !bundle || (package_for_another && !explicit_body) {
        false
    } else {
        let peer = source.peer;
        loop {
            let header = parsed.clone();
            // A patient (Range) answer meeting a cut that is still refreshing waits for the
            // room's next published snapshot and reads the cut again; subscribed before the
            // read. An unknown cut is never permission.
            let published = source.next_publication();
            let found = source
                .serve_read(&job, 128 * 1024, move |room, store| {
                    Ok(Some(
                        room.recipient_body_eligibility(store, &peer, &header)?,
                    ))
                })
                .await?;
            break match found {
                Lookup::Found(held) => match held.value {
                    crate::node::channel::governance::ContentEligibility::Eligible => false,
                    crate::node::channel::governance::ContentEligibility::Ineligible => true,
                    crate::node::channel::governance::ContentEligibility::Refreshing
                        if source.is_patient() =>
                    {
                        source.published(published).await?;
                        continue;
                    }
                    crate::node::channel::governance::ContentEligibility::Refreshing => {
                        result.status = Status::Busy;
                        return Ok(result);
                    }
                },
                Lookup::Busy => {
                    result.status = Status::Busy;
                    return Ok(result);
                }
                Lookup::Missing => return Ok(result),
            };
        }
    };
    // The `strip-payload` mutant sender answers an ordinary body as not held: the stripped serve
    // (V210-74) on the history path rooms sync by, beside the legacy serve's.
    #[cfg(feature = "mutant-sender")]
    let recipient_denied = recipient_denied
        || (crate::log::mutant::strips_payload()
            && signed_kind == crate::log::history::SignedEntryKind::Content);
    // The authenticated room member may carry this sealed package for its recipient.
    // The sender and signed recipient are checked on admission; the ciphertext stays opaque.
    let private_for_another = parsed.skeleton.v2.as_ref().is_some_and(|v2| {
        v2.kind == crate::log::history::SignedEntryKind::KeyPackage
            && v2.recipient != Some(source.peer)
    });
    let mut hostile_private_body = private_for_another.then(test_private_body_marker).flatten();
    let withhold_private_body = private_for_another && !explicit_body;
    // Five worst-case record/sealing copies plus fixed work space, scaled to the signed length.
    // A small control uses the small pool; a large record must have the foreground/archive job.
    let envelope = 5 * (length as usize + MAX_HEADER_BYTES + 9) + 4 * MIB;
    // A denied recipient body, and a body outside a bundle, is answered exactly as a body this
    // provider does not hold: its authenticated header, then BodyNotHeld (ADR-038 FX-29
    // decline), with no read.
    let declined = withhold_private_body || recipient_denied || !bundle;
    let record_job = if declined {
        None
    } else {
        let Some(record_job) = job.record_job(envelope).await else {
            result.status = Status::Busy;
            return Ok(result);
        };
        Some(record_job)
    };
    let payload = if declined {
        None
    } else {
        let Some(record_job) = record_job.as_ref() else {
            return Err(Error::Profile("history body reservation disappeared"));
        };
        Some(
            match source
                .read_body(
                    record_job,
                    envelope,
                    length as usize + MAX_HEADER_BYTES + 9,
                    move |room, store| Ok(Some(room.history_payload(store, &hash)?)),
                )
                .await?
            {
                Lookup::Found(held) => held,
                Lookup::Busy => {
                    result.status = Status::Busy;
                    return Ok(result);
                }
                Lookup::Missing => return Ok(result),
            },
        )
    };
    let bytes = match payload.as_ref().map(|payload| &payload.value) {
        None => None,
        Some(HistoryPayload::Held { payload_len, bytes }) if *payload_len == length => Some(bytes),
        Some(HistoryPayload::BodyNotHeld { payload_len }) if *payload_len == length => None,
        Some(HistoryPayload::Missing) => return Ok(result),
        _ => return Err(Error::MalformedAtRest("history body/header length differs")),
    };
    match send_object(
        source,
        io,
        credit,
        Frame::Meta {
            request,
            object: Object::Header(wire),
        },
        0,
        served_object,
    )
    .await?
    {
        Sent::Yes => {}
        Sent::Full => {
            result.status = if offset == 0 {
                Status::More
            } else {
                Status::Busy
            };
            return Ok(result);
        }
        Sent::Busy => {
            result.status = Status::Busy;
            return Ok(result);
        }
    }
    result.hash = Some(hash);
    if withhold_private_body {
        // A nonrecipient's role receipt does not depend on its optional relay copy. An exact
        // Control body request still receives BodyNotHeld so only this provider is declined.
        result.status = Status::Complete;
        result.role_complete = true;
        return Ok(result);
    }
    credit.expect_body(hash, length, offset)?;
    let Some(bytes) = bytes else {
        result.status = if length == 0 {
            Status::Complete
        } else {
            Status::BodyNotHeld
        };
        return Ok(result);
    };
    while result.offset < length {
        let available = credit
            .remaining_wire()
            .saturating_sub(super::DONE_RESERVE + ACK_RESERVE + 128);
        let take = MAX_CHUNK_BYTES
            .min(available)
            .min((length - result.offset) as usize);
        if take == 0 {
            result.status = Status::More;
            return Ok(result);
        }
        let start = result.offset as usize;
        match send_object(
            source,
            io,
            credit,
            Frame::Chunk {
                request,
                entry: hash,
                offset: result.offset,
                bytes: &bytes[start..start + take],
            },
            ACK_RESERVE,
            served_object,
        )
        .await?
        {
            Sent::Yes => {
                if let Some((trigger, engaged)) = hostile_private_body.take() {
                    // The apparatus records the exact authenticated entry whose chunk crossed the
                    // sender boundary. The receiver's independent durable marker must match it.
                    std::fs::write(&trigger, hash).map_err(|_| {
                        Error::Profile("test hostile-body marker could not record the entry")
                    })?;
                    std::fs::rename(trigger, engaged).map_err(|_| {
                        Error::Profile("test hostile-body marker could not record engagement")
                    })?;
                }
            }
            Sent::Full => {
                result.status = Status::More;
                return Ok(result);
            }
            Sent::Busy => {
                result.status = Status::Busy;
                return Ok(result);
            }
        }
        result.offset += take as u64;
    }
    result.status = Status::Complete;
    Ok(result)
}
