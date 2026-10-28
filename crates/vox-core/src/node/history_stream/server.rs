//! One explicitly authorized response quantum. Continuations describe remaining work and never
//! schedule it. The caller owns admission, stream lifetime and daemon-wide worker reservation.

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::entry::Entry;
use crate::log::history::{MAX_CHUNK_BYTES, MAX_HEADER_BYTES, MAX_PAYLOAD_BYTES};
use crate::node::channel::HistoryPayload;

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

#[allow(clippy::too_many_arguments)] // One bound stream and its node-owned scalar hint sink.
pub(super) async fn answer(
    source: &Source,
    io: &mut Transport,
    preamble: Preamble,
    query: Query,
    handshake_bytes: usize,
    inbox: &super::HintInbox,
    inbox_generation: u64,
    connection_serial: u64,
    inventory_added: &mut bool,
    served_object: &mut bool,
) -> Result<Status> {
    let receipt_source;
    let source = if preamble.purpose == Purpose::Control
        && matches!(query, Query::Head(author) if author == source.peer)
    {
        receipt_source = source.for_own_head_receipt();
        &receipt_source
    } else {
        source
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
        } = incoming.frame()?
        else {
            return Err(Error::MalformedBundle("inventory expected one HAVE"));
        };
        let work_job = incoming.job();
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
        for slice in hints.chunks(64) {
            let offered = source
                .offer_inventory(&work_job, inbox, inbox_generation, preamble.room, slice)
                .await?;
            *inventory_added |= offered.added != 0;
            if offered.full {
                return Err(Error::Unreachable("inventory pending capacity busy"));
            }
        }
        drop(hints);
        drop(incoming);
    }
    let (status, continuation) = if credit.remaining_wire() < super::DONE_RESERVE {
        (Status::Busy, None)
    } else {
        respond(source, io, preamble, &query, &mut credit, served_object).await?
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
    credit: &mut Response,
    served_object: &mut bool,
) -> Result<(Status, Option<Continuation>)> {
    let job = io.job().clone();
    let request = preamble.request;
    let explicit_key_body = matches!(query, Query::KeyBody { .. });
    match *query {
        Query::Inventory => {
            let Lookup::Found(inventory) = source.inventory(&job).await? else {
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
        Query::Header { head, seq } => {
            let found = source
                .read(&job, 128 * 1024, move |room, store| {
                    let Some(head) = room.history_head_by_id(store, &head)? else {
                        return Ok(None);
                    };
                    if seq > head.root.leaves {
                        return Err(Error::MalformedBundle("requested header exceeds head"));
                    }
                    room.history_proof_header(store, &head, seq)
                })
                .await?;
            let held = match found {
                Lookup::Found(held) => held,
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
            };
            let status = match send_object(
                source,
                io,
                credit,
                Frame::Meta {
                    request,
                    object: Object::Header(&held.value.wire),
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
            let found = source
                .read(&job, 128 * 1024, move |room, store| {
                    room.history_head_by_id(store, &head)
                })
                .await?;
            let held_head = match found {
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
            let result = entry(
                source,
                io,
                preamble,
                credit,
                head,
                seq,
                offset,
                explicit_key_body,
                key_identity,
                served_object,
            )
            .await?;
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
                if credit.headers_left() == 0 || seq == hi {
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
    seq: u64,
    offset: u64,
    explicit_key_body: bool,
    key_identity: Option<(Digest32, Digest32)>,
    served_object: &mut bool,
) -> Result<EntryResult> {
    let job = io.job().clone();
    let request = preamble.request;
    let head_id = head;
    let mut result = EntryResult {
        status: Status::EvidenceUnavailable,
        hash: None,
        offset,
        role_complete: false,
    };
    // A relay may have validated this exact package under a different signed head.
    // The receiver retains its own head for admission; the provider serves only an
    // independently validated matching author, sequence, and signed entry hash.
    let provider_head = if let Some((author, hash)) = key_identity {
        match source
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
        }
    } else {
        head
    };
    let head = match source
        .read(&job, 128 * 1024, move |room, store| {
            room.history_head_by_id(store, &provider_head)
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
    // Every dependent header/body read overlaps this held head. Keep its actual worker rather
    // than asking the original Control job to acquire another foreground permit.
    let job = head.job();
    if seq == 0 || seq > head.value.root.leaves {
        return Err(Error::MalformedBundle("requested entry exceeds head"));
    }
    let author = head.value.binding.author;
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
    let live = if preamble.purpose == Purpose::Live {
        let through = head.value.root.leaves;
        let latest = source
            .read(&job, 128 * 1024, move |room, store| {
                Ok(Some(room.history_head(store, &author)?.is_some_and(
                    |current| {
                        let bound = crate::log::history::MAX_PAGE_ENTRIES as u64;
                        // An exact committed head may select only its newest 128 positions,
                        // and only while that head is itself within 128 of the current head.
                        // Arbitrarily old signed heads cannot turn Live into archive demand.
                        current.root.leaves >= through
                            && current.root.leaves - through < bound
                            && (current.root.leaves != through || current.id() == head_id)
                            && seq >= through.saturating_sub(bound - 1).max(1)
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
    let record_job = if withhold_private_body {
        None
    } else {
        let Some(record_job) = job.record_job(envelope).await else {
            result.status = Status::Busy;
            return Ok(result);
        };
        Some(record_job)
    };
    let payload = if withhold_private_body {
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
