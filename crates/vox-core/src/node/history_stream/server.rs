//! One explicitly authorized response quantum. Continuations describe remaining work and never
//! schedule it. The caller owns admission, stream lifetime and daemon-wide worker reservation.

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::entry::Entry;
use crate::log::history::{HeadTarget, MAX_CHUNK_BYTES, MAX_HEADER_BYTES, MAX_PAYLOAD_BYTES};
use crate::node::channel::{HistoryPayload, ResolvedTarget};

use super::credit::Response;
use super::source::{Lookup, Source};
use super::transport::{Read, Transport};
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

#[allow(clippy::too_many_arguments)] // One bound stream and its node-owned scalar hint sink.
pub(super) async fn answer(
    source: &Source,
    io: &mut Transport,
    preamble: Preamble,
    query: Query,
    target: Option<HeadTarget>,
    handshake_bytes: usize,
    inbox: &super::HintInbox,
    inbox_generation: u64,
    connection_serial: u64,
    inventory_added: &mut bool,
    ask_back: &mut bool,
    served_object: &mut bool,
) -> Result<Status> {
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
            .read(io.job(), 128 * 1024, move |room, store| {
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
                    Query::Header { head, .. }
                    | Query::Proof { head, .. }
                    | Query::Entry { head, .. }
                    | Query::Page { head, .. } => {
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
    if matches!(query, Query::Inventory) && preamble.purpose != Purpose::Control {
        return Err(Error::MalformedBundle("inventory requires control purpose"));
    }
    if matches!(query, Query::KeyBody { .. }) && preamble.purpose != Purpose::Control {
        return Err(Error::MalformedBundle("key body requires control purpose"));
    }
    if preamble.purpose != Purpose::History && matches!(query, Query::Page { .. }) {
        return Err(Error::MalformedBundle(
            "archive page requires history reservation",
        ));
    }
    let mut credit = Response::new(request, query.clone())?;
    credit.charge_handshake(handshake_bytes)?;
    if matches!(query, Query::Inventory) {
        // Inventory is symmetric: the requester sends its one HAVE before receiving ours.
        // Its exact encoded bytes share this request's wire credit, and the decoded Vec stays
        // inside the charged input frame until all bounded insertion slices have completed.
        let incoming = match io.read_required(credit.remaining_wire()).await? {
            Read::Frame(frame) => frame,
            Read::Busy => return Err(Error::Unreachable("inventory reader busy")),
            Read::End => return Err(Error::MalformedBundle("inventory closed before HAVE")),
        };
        credit.charge_overhead(incoming.wire_len())?;
        let Frame::Have {
            hints,
            role,
            key_catalog,
            availability,
            forks,
            unresolved,
        } = incoming.frame()?
        else {
            return Err(Error::MalformedBundle("inventory expected one HAVE"));
        };
        let work_job = incoming.job();
        // MP-9: a fork or (rule 6) an unresolved head the requester lists that this node would
        // ask it for is a reason for this node to run its own inventory exchange with it; the
        // listing itself is never evidence (`client::listing_wanted`).
        if !forks.is_empty() || !unresolved.is_empty() {
            if let Lookup::Found(wanted) = source
                .read(&work_job, 0, move |room, store| {
                    Ok(Some(super::client::listing_wanted(
                        room,
                        store,
                        &forks,
                        &unresolved,
                    )?))
                })
                .await?
            {
                #[cfg(feature = "test-knobs")]
                if wanted.value {
                    eprintln!(
                        "history listing wanted peer={}",
                        crate::node::link::b32_encode(&source.peer)
                    );
                }
                *ask_back |= wanted.value;
            }
        }
        source
            .offer_key_catalog(&work_job, key_catalog, connection_serial)
            .await?;
        let offered = source
            .offer_role(
                &work_job,
                inbox,
                inbox_generation,
                preamble.room,
                connection_serial,
                role,
            )
            .await?;
        *inventory_added |= offered.added != 0;
        if offered.full {
            return Err(Error::Unreachable("history role hint capacity busy"));
        }
        if let (Some(connection), Some(token)) = (io.availability_connection, availability) {
            source
                .observe_availability(&work_job, connection, token)
                .await?;
        }
        for slice in hints.chunks(64) {
            let offered = source
                .offer_inventory(
                    &work_job,
                    inbox,
                    inbox_generation,
                    preamble.room,
                    connection_serial,
                    slice,
                )
                .await?;
            *inventory_added |= offered.added != 0 || offered.rearmed != 0;
            if offered.full {
                return Err(Error::Unreachable("inventory pending capacity busy"));
            }
        }
        drop(hints);
        drop(incoming);
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
                        | Query::KeyBody { .. }
                        | Query::Proof {
                            kind: super::ProofKind::Control,
                            ..
                        } => true,
                        _ => false,
                    }
            });
    // A test-side withholding holder (MP-9): every header, proof, body and fork proof of the
    // author named in the file is answered EvidenceUnavailable; its head is still served. The
    // author is the asked target's, so a head this node never held (a prefix it would serve,
    // ADR-053 P) is withheld too.
    #[cfg(feature = "test-knobs")]
    let staged_unavailable = staged_unavailable || {
        let withheld = std::env::var_os("VOX_TEST_WITHHOLD_AUTHOR_FILE")
            .and_then(|path| std::fs::read_to_string(path).ok())
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty());
        match (withheld, query.clone()) {
            (Some(author), Query::Fork(id)) => crate::node::link::b32_encode(&id) == author,
            (
                Some(author),
                Query::Header { .. }
                | Query::Proof { .. }
                | Query::Entry { .. }
                | Query::Page { .. },
            ) => target.is_some_and(|target| {
                crate::node::link::b32_encode(&target.binding.author) == author
            }),
            _ => false,
        }
    };
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
                | Query::Page { head, .. },
                Some(target),
            ) if super::admission::no_accepted_opening(&target.binding.author) => matches!(
                source
                    .read(io.job(), 0, move |room, store| {
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
        )
        .await?
    };
    // Source objects and their envelopes have been dropped before the terminal allocation.
    let done = Frame::Done {
        request,
        status,
        continuation,
    };
    let Some(encoded) = done.encode(io.job())? else {
        return Err(Error::Unreachable("history terminal buffer busy"));
    };
    credit.accept(&done, encoded.as_slice().len() + 4)?;
    io.write_encoded(&encoded).await?;
    io.finish()?;
    Ok(status)
}

async fn send(
    source: &Source,
    io: &mut Transport,
    credit: &mut Response,
    frame: Frame<'_>,
    credit_reply_reserve: usize,
) -> Result<Sent> {
    let Some(encoded) = frame.encode(io.job())? else {
        return Ok(Sent::Busy);
    };
    let wire = encoded.as_slice().len() + 4;
    if !credit.fits_data(wire + credit_reply_reserve) {
        return Ok(Sent::Full);
    }
    if !source.authorize(io.job()).await? {
        return Ok(Sent::Busy);
    }
    credit.accept(&frame, wire)?;
    io.write_encoded(&encoded).await?;
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

async fn respond(
    source: &Source,
    io: &mut Transport,
    preamble: Preamble,
    query: &Query,
    target: Option<HeadTarget>,
    credit: &mut Response,
    served_object: &mut bool,
) -> Result<(Status, Option<Continuation>)> {
    let job = io.job().clone();
    let request = preamble.request;
    let explicit_key_body = matches!(query, Query::KeyBody { .. });
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
        Query::Inventory => {
            let Lookup::Found(mut inventory) = source.inventory(&job).await? else {
                return Ok((Status::Busy, None));
            };
            let status = match send(
                source,
                io,
                credit,
                Frame::Have {
                    hints: inventory.value.0,
                    role: inventory.value.1.as_ref().map(|notice| notice.head),
                    key_catalog: inventory.value.2,
                    availability: io.availability_connection.map(|_| inventory.value.4),
                    forks: std::mem::take(&mut inventory.value.5 .0),
                    unresolved: std::mem::take(&mut inventory.value.5 .1),
                },
                0,
            )
            .await?
            {
                Sent::Yes => Status::Complete,
                Sent::Busy | Sent::Full => Status::Busy,
            };
            Ok((status, None))
        }
        Query::KeyAvailability { after } => {
            if preamble.purpose != Purpose::Control {
                return Err(Error::MalformedBundle("key availability requires control"));
            }
            let (instance, page) = match source
                .read(&job, 512 * 1024, move |room, store| {
                    Ok(Some((
                        room.history_instance(store)?,
                        room.history_key_available_page(store, after)?,
                    )))
                })
                .await?
            {
                Lookup::Found(held) => held.value,
                Lookup::Busy | Lookup::Missing => return Ok((Status::Busy, None)),
            };
            let status = match send(
                source,
                io,
                credit,
                Frame::KeyAvailability {
                    request,
                    instance,
                    page,
                },
                0,
            )
            .await?
            {
                Sent::Yes => Status::Complete,
                Sent::Busy | Sent::Full => Status::Busy,
            };
            Ok((status, None))
        }
        Query::Head(author) => {
            // Only a Control Head is a role receipt; Live Head is commitment discovery.
            let receipt = preamble.purpose == Purpose::Control && author == source.peer;
            let found = source
                .read(&job, 128 * 1024, move |room, store| {
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
                Sent::Yes => Status::Complete,
                Sent::Busy | Sent::Full => Status::Busy,
            };
            Ok((status, None))
        }
        Query::HeadById(id) => {
            // MP-9 (rule 6): a committed head or the author's kept unresolved head, by its exact
            // id; only its signed bytes travel, to the peer that asked. Nothing else is served.
            let found = source
                .read(&job, 128 * 1024, move |room, store| {
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
                .read(
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
                .read(&job, 2 * MIB, move |room, store| {
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
                .read(&work_job, 128 * 1024, move |room, store| {
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
            #[cfg(feature = "mutant-sender")]
            if crate::log::sync::mutant::withholds(&parsed) {
                return Ok((Status::EvidenceUnavailable, None));
            }
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
        Query::Entry { head, seq, offset }
        | Query::KeyBody {
            head, seq, offset, ..
        } => {
            let key_identity = match query {
                Query::KeyBody { author, hash, .. } => Some((*author, *hash)),
                _ => None,
            };
            // KeyBody keeps its exact (author, seq, hash) provider source (inside `entry`).
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
                        head,
                        Some(resolved),
                        seq,
                        offset,
                        explicit_key_body,
                        key_identity,
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
                        head,
                        None,
                        seq,
                        offset,
                        explicit_key_body,
                        key_identity,
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
                    head,
                    Some(&resolved),
                    seq,
                    0,
                    false,
                    None,
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
    }
}

#[allow(clippy::too_many_arguments)]
async fn entry(
    source: &Source,
    io: &mut Transport,
    preamble: Preamble,
    credit: &mut Response,
    head: Digest32,
    resolved: Option<&super::source::Held<ResolvedTarget>>,
    seq: u64,
    offset: u64,
    explicit_key_body: bool,
    key_identity: Option<(Digest32, Digest32)>,
    served_object: &mut bool,
) -> Result<EntryResult> {
    let job = io.job().clone();
    let request = preamble.request;
    let head_id = head;
    let mut result = EntryResult::unresolved(Status::EvidenceUnavailable, offset);
    let provider;
    let head = match resolved {
        // Entry and Page: the asker's head, resolved by the caller (ADR-053 P).
        Some(resolved) => resolved,
        None => {
            // A relay may have validated this exact package under a different signed head.
            // The receiver retains its own head for admission; the provider serves only an
            // independently validated matching author, sequence, and signed entry hash.
            let Some((author, hash)) = key_identity else {
                return Err(Error::Profile("history entry without a resolved head"));
            };
            let provider_head = match source
                .read(&job, 128 * 1024, move |room, store| {
                    let read = room.history_read(store)?;
                    Ok(read
                        .history_validated_header(&author, seq)?
                        .and_then(|(head, entry)| (entry.entry_hash() == hash).then_some(head)))
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
            provider = match source
                .read(&job, 128 * 1024, move |room, store| {
                    Ok(room
                        .history_head_by_id(store, &provider_head)?
                        .map(|head| ResolvedTarget::exact(&head)))
                })
                .await?
            {
                Lookup::Found(held) => held,
                Lookup::Busy => {
                    result.status = Status::Busy;
                    return Ok(result);
                }
                Lookup::Missing => return Ok(result),
            };
            &provider
        }
    };
    // Every dependent header/body read overlaps this held head. Keep its actual worker rather
    // than asking the original Control job to acquire another foreground permit.
    let job = head.job();
    let target = head.value;
    if seq == 0 || seq > target.target.root.leaves {
        return Err(Error::MalformedBundle("requested entry exceeds head"));
    }
    let author = target.target.binding.author;
    let header = match source
        .read(&job, 128 * 1024, move |room, store| {
            room.history_header(store, &author, seq)
        })
        .await?
    {
        Lookup::Found(held) => held,
        Lookup::Busy => {
            result.status = Status::Busy;
            return Ok(result);
        }
        Lookup::Missing => return Ok(result),
    };
    let parsed = Entry::from_wire(&header.value.wire)?;
    #[cfg(feature = "mutant-sender")]
    if crate::log::sync::mutant::withholds(&parsed) {
        return Ok(result);
    }
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
    if key_identity
        .is_some_and(|(author, expected)| parsed.skeleton.author_id != author || hash != expected)
    {
        return Ok(result);
    }
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
    // once-removed recipient may not newly receive. Decide before any live grant, body
    // reservation or read; a stale or missing projection is Busy, never permission. A
    // package for another member keeps its own header-only role path below.
    let package_for_another = signed_kind == crate::log::history::SignedEntryKind::KeyPackage
        && parsed.skeleton.v2.as_ref().and_then(|v2| v2.recipient) != Some(source.peer);
    let recipient_denied = if package_for_another && !explicit_key_body {
        false
    } else {
        let peer = source.peer;
        let header = parsed.clone();
        match source
            .read(&job, 128 * 1024, move |room, store| {
                Ok(Some(
                    room.recipient_body_eligibility(store, &peer, &header)?,
                ))
            })
            .await?
        {
            Lookup::Found(held) => match held.value {
                crate::node::channel::governance::ContentEligibility::Eligible => false,
                _ if crate::node::channel::governance::send_every_body() => false,
                crate::node::channel::governance::ContentEligibility::Ineligible => true,
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
        }
    };
    // The `strip-payload` mutant sender answers an ordinary body as not held: the stripped serve
    // (V210-74) on the history path rooms sync by, beside the legacy serve's.
    #[cfg(feature = "mutant-sender")]
    let recipient_denied = recipient_denied
        || (crate::log::sync::mutant::strips_payload()
            && signed_kind == crate::log::history::SignedEntryKind::Content);
    let live = if preamble.purpose == Purpose::Live {
        let through = target.target.root.leaves;
        let latest = source
            .read(&job, 128 * 1024, move |room, store| {
                Ok(Some(room.history_head(store, &author)?.is_some_and(
                    |current| {
                        let bound = crate::log::history::MAX_PAGE_ENTRIES as u64;
                        // An exact committed head within 128 of the current head may select
                        // any position under it: a reader that follows the author asks for
                        // every position it lacks above its first window (ADR-052 RG-6).
                        // Arbitrarily old signed heads cannot turn Live into archive demand.
                        current.root.leaves >= through
                            && current.root.leaves - through < bound
                            && (current.root.leaves != through || current.id() == head_id)
                            && (!live_floor_mutant()
                                || seq >= through.saturating_sub(bound - 1).max(1))
                    },
                )))
            })
            .await?;
        let in_live_window = match latest {
            Lookup::Found(held) => held.value,
            Lookup::Busy => {
                result.status = Status::Busy;
                return Ok(result);
            }
            Lookup::Missing => return Ok(result),
        };
        let bound = crate::node::history_budget::LiveRequest {
            room: preamble.room,
            peer: source.peer,
            epoch: preamble.epoch,
            request,
            head: head_id,
            seq,
            entry: hash,
            length,
        };
        if !job.live_entry(bound, offset, in_live_window)? {
            result.status = Status::Busy;
            return Ok(result);
        }
        Some(bound)
    } else {
        None
    };
    // The authenticated room member may carry this sealed package for its recipient.
    // The sender and signed recipient are checked on admission; the ciphertext stays opaque.
    let private_for_another = parsed.skeleton.v2.as_ref().is_some_and(|v2| {
        v2.kind == crate::log::history::SignedEntryKind::KeyPackage
            && v2.recipient != Some(source.peer)
    });
    if explicit_key_body
        && !parsed
            .skeleton
            .v2
            .as_ref()
            .is_some_and(|v| v.kind == crate::log::history::SignedEntryKind::KeyPackage)
    {
        return Err(Error::MalformedBundle(
            "key body request names a non-package",
        ));
    }
    let mut hostile_private_body = private_for_another.then(test_private_body_marker).flatten();
    let withhold_private_body = private_for_another && !explicit_key_body;
    // Five worst-case record/sealing copies plus fixed work space, scaled to the signed length.
    // A small control uses the small pool; a large record must have the foreground/archive job.
    let envelope = 5 * (length as usize + MAX_HEADER_BYTES + 9) + 4 * MIB;
    // A denied recipient body is answered exactly as a body this provider does not hold:
    // its authenticated header, then BodyNotHeld (ADR-038 FX-29 decline), with no read.
    let record_job = if withhold_private_body || recipient_denied {
        None
    } else {
        let Some(record_job) = job.record_job(envelope).await else {
            result.status = Status::Busy;
            return Ok(result);
        };
        Some(record_job)
    };
    let payload = if withhold_private_body || recipient_denied {
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
            object: Object::Header(&header.value.wire),
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
        if let Some(bound) = live {
            job.finish_live(bound);
        }
        return Ok(result);
    }
    credit.expect_body(hash, length, offset)?;
    let Some(bytes) = bytes else {
        result.status = if length == 0 {
            Status::Complete
        } else {
            Status::BodyNotHeld
        };
        if let Some(bound) = live {
            job.finish_live(bound);
        }
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
        if let Some(bound) = live {
            job.live_sent(bound, result.offset, result.offset + take as u64)?;
        }
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
        loop {
            let incoming = match io.read_ack_or_cancel(credit.remaining_wire()).await? {
                Read::Frame(frame) => frame,
                Read::End => return Err(Error::Unreachable("history ended before persisted ACK")),
                Read::Busy => return Err(Error::Unreachable("history ACK reader busy")),
            };
            credit.charge_overhead(incoming.wire_len())?;
            match incoming.frame()? {
                Frame::Ack {
                    request: id,
                    entry,
                    next_offset,
                } => {
                    if credit.acknowledge(id, entry, next_offset)? {
                        if let Some(bound) = live {
                            job.live_ack(bound, next_offset)?;
                        }
                        result.offset = next_offset;
                        break;
                    }
                }
                Frame::Cancel(id) if id == request => {
                    if let Some(bound) = live {
                        job.finish_live(bound);
                    }
                    result.status = Status::Cancelled;
                    return Ok(result);
                }
                _ => return Err(Error::MalformedBundle("history expected persisted ACK")),
            }
        }
    }
    // The receiver has durably persisted the complete body before it sends this ACK.
    // Release the daemon-wide Live grant now: the receiver does not depend on the
    // final DONE, and retaining completed grants can starve fresh messages behind
    // old history until the grant expiry.
    if let Some(bound) = live {
        job.finish_live(bound);
    }
    result.status = Status::Complete;
    Ok(result)
}

/// `VOX_MUTANT_LIVE_FLOOR`: this server refuses a Live body more than 128 positions below the
/// head it is asked under, as every release from v0.4.6 to v0.4.30 did (ledger 66). Says so
/// once on stderr when the daemon first reads it.
#[cfg(feature = "test-knobs")]
fn live_floor_mutant() -> bool {
    static ON: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
        let on = std::env::var_os("VOX_MUTANT_LIVE_FLOOR").is_some();
        if on {
            eprintln!(
                "vox: VOX_MUTANT_LIVE_FLOOR engaged: Live is refused below the newest 128 \
                 positions"
            );
        }
        on
    });
    *ON
}

#[cfg(not(feature = "test-knobs"))]
const fn live_floor_mutant() -> bool {
    false
}
