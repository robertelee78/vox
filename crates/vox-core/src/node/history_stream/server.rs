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

enum Sent {
    Yes,
    Full,
    Busy,
}

struct EntryResult {
    status: Status,
    hash: Option<Digest32>,
    offset: u64,
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
    inventory_added: &mut bool,
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
        let incoming = match io.read(credit.remaining_wire()).await? {
            Read::Frame(frame) => frame,
            Read::Busy => return Err(Error::Unreachable("inventory reader busy")),
            Read::End => return Err(Error::MalformedBundle("inventory closed before HAVE")),
        };
        credit.charge_overhead(incoming.wire_len())?;
        let Frame::Have(hints) = incoming.frame()? else {
            return Err(Error::MalformedBundle("inventory expected one HAVE"));
        };
        for slice in hints.chunks(64) {
            let offered = source
                .offer_inventory(io.job(), inbox, inbox_generation, preamble.room, slice)
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
        respond(source, io, preamble, &query, &mut credit).await?
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

async fn respond(
    source: &Source,
    io: &mut Transport,
    preamble: Preamble,
    query: &Query,
    credit: &mut Response,
) -> Result<(Status, Option<Continuation>)> {
    let job = io.job().clone();
    let request = preamble.request;
    match *query {
        Query::Inventory => {
            let Lookup::Found(inventory) = source.inventory(&job).await? else {
                return Ok((Status::Busy, None));
            };
            let status = match send(source, io, credit, Frame::Have(inventory.value), 0).await? {
                Sent::Yes => Status::Complete,
                Sent::Busy | Sent::Full => Status::Busy,
            };
            Ok((status, None))
        }
        Query::Head(author) => {
            let receipt = author == source.peer;
            let exact_ack = source.received_ack_probe().map(|(_, entry)| entry);
            if exact_ack.is_some() && !receipt {
                return Ok((Status::Busy, None));
            }
            let found = source
                .read(&job, 128 * 1024, move |room, store| {
                    let Some(head) = room.history_head(store, &author)? else {
                        return Ok(None);
                    };
                    let mut boundary = None;
                    if receipt {
                        // Delivery acknowledgement cannot precede the required body/effect.
                        // Merely verifying a signed nonempty head or inclusion never proves
                        // receipt. A canonical empty head has no terminal entry: holding that
                        // exact committed head is the complete acknowledgement of an empty feed.
                        let read = room.history_read(store)?;
                        if head.root.leaves == 0 {
                            if read.history_settled_tip(&author)?.is_some() {
                                return Ok(None);
                            }
                        } else {
                            let Some(tip) = read.history_settled_tip(&author)? else {
                                return Ok(None);
                            };
                            let Some(included) = read.history_inclusion_receipt(
                                &head.id(),
                                &author,
                                head.root.leaves,
                            )?
                            else {
                                return Ok(None);
                            };
                            if tip.skeleton.seq != head.root.leaves
                                || tip.entry_hash() != included.header().entry().entry_hash()
                            {
                                return Ok(None);
                            }
                            boundary = Some(tip.entry_hash());
                        }
                    }
                    if exact_ack.as_deref().is_some_and(|expected| {
                        boundary
                            .as_ref()
                            .is_none_or(|hash| crate::node::link::b32_encode(hash) != expected)
                    }) {
                        return Ok(None);
                    }
                    let debt = room.received_debt_for_current(store, &author)?;
                    Ok(Some((head, debt, boundary)))
                })
                .await?;
            let held = match found {
                Lookup::Found(held) => held,
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
            };
            // The head was read; what it covers is on disk before the peer hears of it
            // (ADR-038 FX-30).
            let (head, debt, boundary) = held.value;
            source
                .flush_received_before_ack(debt.into_iter().collect(), boundary)
                .await?;
            let wire = head.to_wire();
            let status = match send(
                source,
                io,
                credit,
                Frame::Meta {
                    request,
                    object: Object::Head(&wire),
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
            let status = match send(
                source,
                io,
                credit,
                Frame::Meta {
                    request,
                    object: Object::Context(&wire),
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
        Query::Header { head, seq } => {
            let found = source
                .read(&job, 128 * 1024, move |room, store| {
                    let Some(head) = room.history_head_by_id(store, &head)? else {
                        return Ok(None);
                    };
                    if seq > head.root.leaves {
                        return Err(Error::MalformedBundle("requested header exceeds head"));
                    }
                    room.history_header(store, &head.binding.author, seq)
                })
                .await?;
            let held = match found {
                Lookup::Found(held) => held,
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
            };
            let status = match send(
                source,
                io,
                credit,
                Frame::Meta {
                    request,
                    object: Object::Header(&held.value.wire),
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
            let held_proof = match source.proof(&job, &held_head.value, kind, from, to).await? {
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
            match send(source, io, credit, frame, 0).await? {
                Sent::Yes if continuation.is_some() => Ok((Status::More, continuation)),
                Sent::Yes => Ok((Status::Complete, None)),
                Sent::Busy | Sent::Full => Ok((Status::Busy, None)),
            }
        }
        Query::Entry { head, seq, offset } => {
            let result = entry(source, io, preamble, credit, head, seq, offset).await?;
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
                let result = entry(source, io, preamble, credit, head, seq, 0).await?;
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

async fn entry(
    source: &Source,
    io: &mut Transport,
    preamble: Preamble,
    credit: &mut Response,
    head: Digest32,
    seq: u64,
    offset: u64,
) -> Result<EntryResult> {
    let job = io.job().clone();
    let request = preamble.request;
    let head_id = head;
    let mut result = EntryResult {
        status: Status::EvidenceUnavailable,
        hash: None,
        offset,
    };
    let head = match source
        .read(&job, 128 * 1024, move |room, store| {
            room.history_head_by_id(store, &head)
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
    // Five worst-case record/sealing copies plus fixed work space, scaled to the signed length.
    // A small control uses the small pool; a large record must have the foreground/archive job.
    let envelope = 5 * (length as usize + MAX_HEADER_BYTES + 9) + 4 * MIB;
    let Some(record_job) = job.record_job(envelope) else {
        result.status = Status::Busy;
        return Ok(result);
    };
    let payload = match source
        .read_body(
            &record_job,
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
    };
    let bytes = match &payload.value {
        HistoryPayload::Held { payload_len, bytes } if *payload_len == length => Some(bytes),
        HistoryPayload::BodyNotHeld { payload_len } if *payload_len == length => None,
        HistoryPayload::Missing => return Ok(result),
        _ => return Err(Error::MalformedAtRest("history body/header length differs")),
    };
    match send(
        source,
        io,
        credit,
        Frame::Meta {
            request,
            object: Object::Header(&header.value.wire),
        },
        0,
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
        match send(
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
        )
        .await?
        {
            Sent::Yes => {}
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
