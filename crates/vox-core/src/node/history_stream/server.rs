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

pub(super) async fn answer(
    source: &Source,
    io: &mut Transport,
    preamble: Preamble,
    query: Query,
    handshake_bytes: usize,
) -> Result<Status> {
    let request = preamble.request;
    if preamble.purpose != Purpose::History && matches!(query, Query::Page { .. }) {
        return Err(Error::MalformedBundle(
            "archive page requires history reservation",
        ));
    }
    let mut credit = Response::new(request, query.clone())?;
    credit.charge_handshake(handshake_bytes)?;
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
        Query::Head(author) => {
            let found = source
                .read(&job, 128 * 1024, move |room, store| {
                    room.history_head(store, &author)
                })
                .await?;
            let held = match found {
                Lookup::Found(held) => held,
                Lookup::Busy => return Ok((Status::Busy, None)),
                Lookup::Missing => return Ok((Status::EvidenceUnavailable, None)),
            };
            let wire = held.value.to_wire();
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
            for seq in lo..=hi {
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
        let latest = source
            .read(&job, 128 * 1024, move |room, store| {
                Ok(Some(room.history_head(store, &author)?.is_some_and(
                    |head| head.id() == head_id && head.root.leaves == seq,
                )))
            })
            .await?;
        let current_tail = match latest {
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
        if !job.live_entry(bound, offset, current_tail)? {
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
            let incoming = match io.read(ACK_RESERVE.min(credit.remaining_wire())).await? {
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
    result.status = Status::Complete;
    // Keep this bounded, expiring completed grant long enough to recover a lost final DONE.
    // It authorizes no next entry, no larger offset and no additional archive work.
    Ok(result)
}
