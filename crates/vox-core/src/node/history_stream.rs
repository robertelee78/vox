//! Explicit bounded sync requests and frames (ADR-036 H-6).
//!
//! This codec checks structure and resource bounds. It grants no authority: the caller binds
//! every object to its request, verifies author/control evidence, and rechecks current access.
//! Payload slices borrow the charged input frame rather than making another queued copy.

mod admission;
mod bundle;
mod client;
mod credit;
mod driver;
pub(crate) mod private;
pub(crate) mod pull;
pub(crate) mod runtime;
mod server;
mod serving;
mod source;
mod transport;

pub(crate) use admission::fork_mutant_is;
pub(crate) use client::{EntryPhase, LocalNeed, LocalProof, LocalStep, Receiver};
pub(crate) use serving::{OpenRoom, Place, Serving};

use super::history_budget::{BufferCharge, Job};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::feed::MAX_SEQ;
use crate::log::history::{
    ConsistencyProof, ControlRangeProof, Descriptor, HeadTarget, InclusionProof, MAX_CHUNK_BYTES,
    MAX_CONTEXT_AUTHORS, MAX_CONTEXT_BYTES, MAX_FRAME_BYTES, MAX_HEADER_BYTES, MAX_PAGE_ENTRIES,
    MAX_PAYLOAD_BYTES, MAX_RESPONSE_BYTES,
};

pub type RequestId = [u8; 16];
pub const MAX_PREAMBLE: usize = 128;
pub const DONE_RESERVE: usize = 512;
/// A captured flow grant no longer names current authorization; this is not a disk failure.
pub(crate) const AUTHORIZATION_CHANGED: &str = "history authorization changed before publication";
// One frame tag plus the canonical CBOR encoding of any u8 mode bitmap.
const MAX_HELLO_FRAME_BYTES: usize = 3;
// Conservative bound for the tag, request ID, query and canonical head target (ADR-053 P).
const MAX_WANT_FRAME_BYTES: usize = 160 + 1 + HeadTarget::MAX_BYTES;
// Conservative tag/CBOR overhead for a locally sourced byte-string frame. The peer-facing
// decoder still reserves the full attacker-sized frame and decode envelope before its prefix.
const LOCAL_BYTES_FRAME_FIXED_BYTES: usize = 128;
const CANCEL_FRAME_MAX_BYTES: usize = 64;
const ACK_FRAME_MAX_BYTES: usize = 128;

/// Exact local request incarnation. The trust nonce and the room's durable removal
/// generation invalidate queued work after either kind of authority change. This digest
/// grants no rights; current membership and body admission still apply.
pub(crate) fn authorization_generation(
    store: &super::store::Store,
    node: Digest32,
    room: Digest32,
    instance: [u8; 16],
    epoch: u64,
) -> Result<Digest32> {
    let nonce =
        store.get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(super::trust::TRUST_META_KEY)?;
    let removal = super::channel::governance::removal_generation(store, &room)?;
    Ok(generation_from_nonce(
        node, room, instance, epoch, nonce, removal,
    ))
}

/// Recheck both authority incarnations inside the accepted-entry transaction, so a concurrent
/// trust edit or applied room removal cannot slip into durable publication/ACK eligibility.
pub(crate) fn authorization_generation_in(
    batch: &super::store::Batch<'_>,
    node: Digest32,
    room: Digest32,
    instance: [u8; 16],
    epoch: u64,
) -> Result<Digest32> {
    let nonce =
        batch.get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(super::trust::TRUST_META_KEY)?;
    let removal = super::channel::governance::removal_generation_in(batch, &room)?;
    Ok(generation_from_nonce(
        node, room, instance, epoch, nonce, removal,
    ))
}

fn generation_from_nonce(
    node: Digest32,
    room: Digest32,
    instance: [u8; 16],
    epoch: u64,
    nonce: Option<[u8; crate::atrest::sek::NONCE_LEN]>,
    removal: u64,
) -> Digest32 {
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(b"vox/history-authorization/v1");
    bytes.extend_from_slice(&node);
    bytes.extend_from_slice(&room);
    bytes.extend_from_slice(&instance);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&removal.to_be_bytes());
    bytes.push(u8::from(nonce.is_some()));
    if let Some(nonce) = nonce {
        bytes.extend_from_slice(&nonce);
    }
    crate::hash::sha256(&bytes)
}

/// Run one incoming request with a fixed lifetime. This never asks for another page.
/// The answer ends when its asker's stream ends (the asker left or stopped reading, or the
/// connection closed), whether it is still waiting for its admission or already answering:
/// nothing it holds outlives its asker. Its handshake and query, and a Have's one HOLDING, are
/// read before any shared admission; the daemon-wide job of `node` is admitted only then, for
/// the local work of assembling the answer (at most the request's wire credit), and given back
/// with every shared charge before the answer is written: no shared admission is held while
/// the asker is waited on. `place` says where the query counts (`Serving::place`) and whether
/// it fits.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    room: std::sync::Arc<super::channel::RoomLock>,
    store: std::sync::Arc<super::store::Store>,
    peer: Digest32,
    preamble: Preamble,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    budget: std::sync::Arc<super::history_budget::Budget>,
    node: Digest32,
    fence: std::sync::Arc<crate::transport::stream_transport::Fence>,
    holdings: std::sync::Arc<pull::Holdings>,
    departure_receipt: std::sync::Arc<std::sync::atomic::AtomicBool>,
    snapshot: std::sync::Arc<super::channel::RoomSnapshotCell>,
    conn: std::sync::Arc<crate::transport::quic::VoxConnection>,
    place: Box<dyn FnOnce(Place) -> bool + Send>,
) -> (Result<Status>, bool) {
    // The one waiter on the asker's stream: it ends the answer if the asker leaves while it is
    // read or written, and confirms a receipt's delivery after the finish (see below).
    let mut asker_left = std::pin::pin!(send.stopped());
    let mut served_object = false;
    // An own-feed receipt this answer carries, until the asker acknowledged the whole answer.
    let mut receipt_pending: Option<u64> = None;
    let mut hand = transport::Private::new(send, recv, std::sync::Arc::clone(&fence));
    let result = tokio::select! {
        biased;
        result = async {
            let asked = match read_ask(&mut hand, preamble, peer, place).await {
                Ok(Ok(asked)) => asked,
                Ok(Err(status)) => return Ok(status),
                Err(error) => {
                    hand.abort(abort_code(&error));
                    return Err(error);
                }
            };
            // Parsed and request-bound before publication. If the peer's departure is applied
            // while this response is in flight, lifecycle cleanup may retain only this exact
            // query. The server and Source still restrict the response to the peer's own
            // settled, included head.
            if preamble.purpose == Purpose::Control
                && matches!(&asked.query, Query::Head(author) if *author == peer)
            {
                departure_receipt.store(true, std::sync::atomic::Ordering::Release);
            }
            let lane = match preamble.purpose {
                Purpose::Control => super::history_budget::Lane::Control,
                Purpose::Live => super::history_budget::Lane::Live,
                Purpose::History => super::history_budget::Lane::Archive,
            };
            let job = budget.admit_job(node, lane).await;
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
            let source = source::Source::new(
                room,
                store,
                preamble.epoch,
                peer,
                fence.clone(),
                deadline,
                None,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                None,
            )
            .serving(snapshot);
            let mut io = transport::Transport::new(job);
            let answered = server::answer(
                &source,
                &mut io,
                preamble,
                asked,
                &holdings,
                &conn,
                &mut served_object,
            )
            .await;
            // The job and every shared charge of the answer end here; what is written next is
            // the connection's own bytes, and only this write (and a receipt's acknowledgement,
            // below) waits on the asker.
            let frames = io.into_frames();
            let (status, served, receipt) = match answered {
                Ok(answered) => answered,
                Err(error) => {
                    hand.abort(abort_code(&error));
                    return Err(error);
                }
            };
            receipt_pending = receipt;
            for frame in &frames {
                // Each frame is authorized again before it goes, as each was before it was
                // written when answers streamed: a revoked snapshot (poisoned, locked or closed
                // room) or a peer's lost access ends the answer here.
                if let Err(error) = served.still_authorized().await {
                    hand.abort(abort_code(&error));
                    return Err(error);
                }
                hand.write(frame).await?;
            }
            hand.finish()?;
            Ok(status)
        } => result,
        _ = &mut asker_left => Err(Error::Unreachable("history asker left")),
    };
    // `finish` only queued the stream's end. An answer that carries a receipt waits, on the same
    // waiter, until the asker acknowledged every byte, the end included: only then does the
    // receipt count as served, and the teller toward a departed author ends once a served
    // receipt covers its departure (`pull::standing`). The asker stopping the stream, or the
    // connection ending, is a failed delivery. Nothing shared is held here: the job, the
    // answer's charges and its frames ended with the writes; the stream's unacknowledged bytes
    // are the connection's own. Every other answer returns at once.
    let result = match result {
        Ok(status) if receipt_pending.is_some() => match asker_left.await {
            Ok(None) => {
                if let Some(size) = receipt_pending.take() {
                    holdings.receipt_served(preamble.room, peer, &conn, size);
                }
                Ok(status)
            }
            Ok(Some(_)) | Err(_) => Err(Error::Unreachable("history receipt not acknowledged")),
        },
        result => result,
    };
    // A receipt that was owed and could not be delivered ends the connection, never silently:
    // the asker asks each head once per connection and the teller stays until it is served, so
    // a new connection starts both again.
    if result.is_err() && receipt_pending.is_some() {
        conn.close(crate::wire::WireError::TransportFailed);
    }
    (result, served_object)
}

fn abort_code(error: &Error) -> crate::wire::WireError {
    match error {
        Error::HistoryCapacity(_) => crate::wire::WireError::SessionBusy,
        Error::SizeLimitExceeded(_) | Error::MalformedBundle(_) => {
            crate::wire::WireError::ProtocolLimits
        }
        _ => crate::wire::WireError::TransportFailed,
    }
}

/// One incoming request as read before its admission (`read_ask`).
struct Asked {
    query: Query,
    target: Option<HeadTarget>,
    /// The request's wire credit, charged with its handshake.
    credit: credit::Response,
    /// A Have's one HOLDING.
    holding: Option<transport::Incoming>,
    /// The exchange of a connection's loop ([`Place::Loop`]): answered patiently.
    patient: bool,
}

/// Read one request's handshake and query, and a Have's one HOLDING, as the connection's
/// private input: fixed-bound frames and the HOLDING within the request's wire credit, with no
/// job and no shared byte credit, so nothing shared waits on the asker. A Have takes its
/// connection's one Have place before its HOLDING is read. `Err(status)`: answered already
/// (cancelled, or refused where its query counts).
async fn read_ask(
    hand: &mut transport::Private,
    preamble: Preamble,
    peer: Digest32,
    place: Box<dyn FnOnce(Place) -> bool + Send>,
) -> Result<std::result::Result<Asked, Status>> {
    let first = match hand.read(MAX_HELLO_FRAME_BYTES + 4, Some(&[0x01])).await? {
        transport::Read::Frame(frame) => frame,
        _ => return Err(invalid("history closed before HELLO")),
    };
    if !matches!(first.frame()?, Frame::Hello(mode) if mode == crate::wire::SYNC_MODE_BOUNDED_HISTORY)
    {
        return Err(invalid("history HELLO mode"));
    }
    let hello = Frame::Hello(crate::wire::SYNC_MODE_BOUNDED_HISTORY).encode_private()?;
    let mut overhead = first.wire_len()
        + preamble.encode().len()
        + 4
        + crate::transport::streams::StreamKind::Sync.frame().len()
        + 4
        + hello.len()
        + 4;
    drop(first);
    hand.write(&hello).await?;
    let next = match hand
        .read(MAX_WANT_FRAME_BYTES + 4, Some(&[0x03, 0x09]))
        .await?
    {
        transport::Read::Frame(frame) => frame,
        _ => return Err(invalid("history closed before WANT")),
    };
    overhead += next.wire_len();
    let (query, target) = match next.frame()? {
        Frame::Want {
            request,
            query,
            target,
        } if request == preamble.request => (query, target),
        Frame::Cancel(request) if request == preamble.request => {
            let done = Frame::Done {
                request,
                status: Status::Cancelled,
                continuation: None,
            };
            hand.write(&done.encode_private()?).await?;
            hand.finish()?;
            return Ok(Err(Status::Cancelled));
        }
        _ => return Err(invalid("history expected bound WANT")),
    };
    drop(next);
    // Decided by the holder from the query: a loop's exchanges, its Have or its one ask (with
    // the loop's exact receipt, `pull::receipt`), take their connection's one place each; any
    // other query is an old flow's.
    let placed = match &query {
        Query::Have => Place::Loop { have: true },
        Query::Range { .. } | Query::Fork(_) | Query::HeadById(_) => Place::Loop { have: false },
        Query::Head(author) if preamble.purpose == Purpose::Control && *author == peer => {
            Place::Loop { have: false }
        }
        _ => Place::OldFlow,
    };
    if !place(placed) {
        hand.abort(crate::wire::WireError::SessionBusy);
        return Ok(Err(Status::Busy));
    }
    let mut credit = credit::Response::new(preamble.request, query.clone())?;
    credit.charge_handshake(overhead)?;
    // A Have's one HOLDING follows its WANT at once (`pull::send_have`); it shares this
    // request's wire credit.
    let holding = if matches!(query, Query::Have) {
        if preamble.purpose != Purpose::Control {
            return Err(Error::MalformedBundle("have requires control purpose"));
        }
        match hand.read(credit.remaining_wire(), None).await? {
            transport::Read::Frame(frame) => Some(frame),
            _ => return Err(Error::MalformedBundle("have closed before HOLDING")),
        }
    } else {
        None
    };
    Ok(Ok(Asked {
        query,
        target,
        credit,
        holding,
        patient: placed != Place::OldFlow,
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Purpose {
    Control = 0,
    Live = 1,
    History = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preamble {
    pub room: Digest32,
    pub epoch: u64,
    pub purpose: Purpose,
    pub request: RequestId,
}

impl Preamble {
    pub fn encode(self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(6)
            .uint(2)
            .bytes(&self.room)
            .uint(self.epoch)
            .uint(0)
            .uint(self.purpose as u64)
            .bytes(&self.request);
        e.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bound(bytes, MAX_PREAMBLE)?;
        let mut d = Decoder::new(bytes);
        arity(&mut d, 6)?;
        if d.uint()? != 2 {
            return Err(invalid("history preamble version"));
        }
        let room = digest(&mut d)?;
        let epoch = d.uint()?;
        if d.uint()? != 0 {
            return Err(invalid("history public scope"));
        }
        let purpose = match d.uint()? {
            0 => Purpose::Control,
            1 => Purpose::Live,
            2 => Purpose::History,
            _ => return Err(invalid("history purpose")),
        };
        let request = request_id(&mut d)?;
        d.finish()?;
        Ok(Self {
            room,
            epoch,
            purpose,
            request,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofKind {
    Inclusion = 0,
    Consistency = 1,
    Control = 2,
}

impl ProofKind {
    fn decode(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::Inclusion),
            1 => Ok(Self::Consistency),
            2 => Ok(Self::Control),
            _ => Err(invalid("history proof kind")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Query {
    /// The asker's Have: what it holds, sent after this WANT as one HOLDING frame. The answer
    /// carries nothing but its Done; a Have is news, never a request for work.
    Have,
    Head(Digest32),
    Context(Digest32),
    /// A proof dependency's signed header, without requesting its content body.
    Header {
        head: Digest32,
        seq: u64,
    },
    Proof {
        head: Digest32,
        kind: ProofKind,
        from: u64,
        to: u64,
    },
    Entry {
        head: Digest32,
        seq: u64,
        offset: u64,
    },
    Page {
        head: Digest32,
        lo: u64,
        hi: u64,
        entries: usize,
        wire_bytes: usize,
    },
    /// MP-9: the fork proof this peer listed for one author in its inventory.
    Fork(Digest32),
    /// MP-9 (rule 6): one signed head this peer retains, by its exact id: an unresolved second
    /// head it listed. Answered with the signed head bytes; never a committed-head claim.
    HeadById(Digest32),
    /// One bundle of existing proof forms under the exact `head`: its signed head, a consistency
    /// proof from the asker's own `anchor` size (0: none), and the `want`ed entries, control
    /// coverage or body remainder, cut at one response quantum with an explicit continuation.
    /// `skip`: how many of the bundle's first contexts (in the order the holder sends them, each
    /// distinct one once) the asker already received in its last answer to this same request,
    /// which stopped on contexts that did not fit; the holder sends the rest. A bundle's proof
    /// and context material thus always advances by at least one context per answer, however
    /// large the room's contexts are. Encoded as a seventh element only when not zero.
    Range {
        head: Digest32,
        anchor: u64,
        want: RangeWant,
        skip: u64,
    },
}

/// What one Range bundle carries under its head.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RangeWant {
    /// Header, inclusion proof and body (or none: not held) of each position `lo..=hi`.
    Entries { lo: u64, hi: u64 },
    /// Control interval proofs covering `lo..=hi`, empty ones for intervals with no control.
    Controls { lo: u64, hi: u64 },
    /// The remainder of position `seq`'s body from `offset`, after its header.
    Body { seq: u64, offset: u64 },
}

impl RangeWant {
    /// The interval this want names, for its continuation.
    pub fn interval(self) -> (u64, u64) {
        match self {
            Self::Entries { lo, hi } | Self::Controls { lo, hi } => (lo, hi),
            Self::Body { seq, .. } => (seq, seq),
        }
    }
}

impl Query {
    /// The asker's head a provider resolves to answer this query (ADR-053 P). Such a request
    /// carries the head's canonical body as its target; every other query carries none.
    pub fn target_head(&self) -> Option<Digest32> {
        match self {
            Self::Header { head, .. }
            | Self::Proof { head, .. }
            | Self::Entry { head, .. }
            | Self::Page { head, .. }
            | Self::Range { head, .. } => Some(*head),
            _ => None,
        }
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Have | Self::Head(_) | Self::Context(_) | Self::Fork(_) | Self::HeadById(_) => {}
            Self::Header { seq, .. } => position(*seq)?,
            Self::Proof { kind, from, to, .. } => {
                if *from > *to
                    || *to > MAX_SEQ
                    || (*kind != ProofKind::Consistency && *from == 0)
                    || (*kind == ProofKind::Inclusion && from != to)
                {
                    return Err(invalid("history proof interval"));
                }
            }
            Self::Entry { seq, offset, .. } => {
                position(*seq)?;
                if *offset > MAX_PAYLOAD_BYTES as u64 {
                    return Err(invalid("history body offset"));
                }
            }
            Self::Page {
                lo,
                hi,
                entries,
                wire_bytes,
                ..
            } => {
                interval(*lo, *hi)?;
                if *entries == 0
                    || *entries > MAX_PAGE_ENTRIES
                    || *wire_bytes <= DONE_RESERVE
                    || *wire_bytes > MAX_RESPONSE_BYTES
                {
                    return Err(invalid("history page budget"));
                }
            }
            Self::Range { anchor, want, .. } => {
                if *anchor > MAX_SEQ {
                    return Err(invalid("history range anchor"));
                }
                match *want {
                    RangeWant::Entries { lo, hi } => {
                        interval(lo, hi)?;
                        if hi - lo >= MAX_PAGE_ENTRIES as u64 {
                            return Err(invalid("history range page"));
                        }
                    }
                    RangeWant::Controls { lo, hi } => interval(lo, hi)?,
                    // Offset 0: the first body request, which carries the position's header
                    // and its inclusion under the named head; a later offset continues it.
                    RangeWant::Body { seq, offset } => {
                        position(seq)?;
                        if offset > MAX_PAYLOAD_BYTES as u64 {
                            return Err(invalid("history body offset"));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        self.validate()?;
        match self {
            Self::Have => {
                e.array(1).uint(10);
            }
            Self::Head(author) => {
                e.array(2).uint(0).bytes(author);
            }
            Self::Fork(author) => {
                e.array(2).uint(9).bytes(author);
            }
            Self::HeadById(head) => {
                e.array(2).uint(10).bytes(head);
            }
            Self::Context(hash) => {
                e.array(2).uint(1).bytes(hash);
            }
            Self::Header { head, seq } => {
                e.array(3).uint(5).bytes(head).uint(*seq);
            }
            Self::Proof {
                head,
                kind,
                from,
                to,
            } => {
                e.array(5)
                    .uint(2)
                    .bytes(head)
                    .uint(*kind as u64)
                    .uint(*from)
                    .uint(*to);
            }
            Self::Entry { head, seq, offset } => {
                e.array(4).uint(3).bytes(head).uint(*seq).uint(*offset);
            }
            Self::Page {
                head,
                lo,
                hi,
                entries,
                wire_bytes,
            } => {
                e.array(6)
                    .uint(4)
                    .bytes(head)
                    .uint(*lo)
                    .uint(*hi)
                    .uint(*entries as u64)
                    .uint(*wire_bytes as u64);
            }
            Self::Range {
                head,
                anchor,
                want,
                skip,
            } => {
                let (kind, a, b) = match *want {
                    RangeWant::Entries { lo, hi } => (0, lo, hi),
                    RangeWant::Controls { lo, hi } => (1, lo, hi),
                    RangeWant::Body { seq, offset } => (2, seq, offset),
                };
                e.array(if *skip == 0 { 6 } else { 7 })
                    .uint(9)
                    .bytes(head)
                    .uint(*anchor)
                    .uint(kind)
                    .uint(a)
                    .uint(b);
                if *skip != 0 {
                    e.uint(*skip);
                }
            }
        }
        Ok(())
    }

    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let len = d.array()?;
        let query = match (d.uint()?, len) {
            // Query tags 6, 7 and 8 are retired and must not be reused.
            (10, 1) => Self::Have,
            (0, 2) => Self::Head(digest(d)?),
            (1, 2) => Self::Context(digest(d)?),
            (9, 2) => Self::Fork(digest(d)?),
            (10, 2) => Self::HeadById(digest(d)?),
            (5, 3) => Self::Header {
                head: digest(d)?,
                seq: d.uint()?,
            },
            (2, 5) => Self::Proof {
                head: digest(d)?,
                kind: ProofKind::decode(d.uint()?)?,
                from: d.uint()?,
                to: d.uint()?,
            },
            (3, 4) => Self::Entry {
                head: digest(d)?,
                seq: d.uint()?,
                offset: d.uint()?,
            },
            (4, 6) => Self::Page {
                head: digest(d)?,
                lo: d.uint()?,
                hi: d.uint()?,
                entries: size(d.uint()?)?,
                wire_bytes: size(d.uint()?)?,
            },
            (9, len @ (6 | 7)) => {
                let head = digest(d)?;
                let anchor = d.uint()?;
                let kind = d.uint()?;
                let (a, b) = (d.uint()?, d.uint()?);
                let want = match kind {
                    0 => RangeWant::Entries { lo: a, hi: b },
                    1 => RangeWant::Controls { lo: a, hi: b },
                    2 => RangeWant::Body { seq: a, offset: b },
                    _ => return Err(invalid("history range want")),
                };
                let skip = if len == 7 { d.uint()? } else { 0 };
                if len == 7 && skip == 0 {
                    return Err(invalid("history range skip"));
                }
                Self::Range {
                    head,
                    anchor,
                    want,
                    skip,
                }
            }
            _ => return Err(invalid("history query arity/kind")),
        };
        query.validate()?;
        Ok(query)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Complete = 0,
    More = 1,
    EvidenceUnavailable = 2,
    BodyNotHeld = 3,
    Busy = 4,
    Cancelled = 5,
    ControlPending = 6,
}

impl Status {
    fn decode(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::Complete),
            1 => Ok(Self::More),
            2 => Ok(Self::EvidenceUnavailable),
            3 => Ok(Self::BodyNotHeld),
            4 => Ok(Self::Busy),
            5 => Ok(Self::Cancelled),
            6 => Ok(Self::ControlPending),
            _ => Err(invalid("history done status")),
        }
    }
}

/// Peer-supplied continuation is only a hint until checked against the persisted local demand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Continuation {
    pub query_kind: u8,
    pub head: Digest32,
    pub lo: u64,
    pub hi: u64,
    pub next_seq: u64,
    pub entry: Option<Digest32>,
    pub offset: u64,
    pub entries_remaining: usize,
}

impl Continuation {
    fn validate(&self) -> Result<()> {
        interval(self.lo, self.hi)?;
        if self.query_kind > 5
            || self.next_seq < self.lo
            || self.next_seq > self.hi
            || self.offset > MAX_PAYLOAD_BYTES as u64
            || (self.offset != 0 && self.entry.is_none())
            || self.entries_remaining > MAX_PAGE_ENTRIES
        {
            return Err(invalid("history continuation bounds"));
        }
        Ok(())
    }

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        self.validate()?;
        e.array(8)
            .uint(self.query_kind as u64)
            .bytes(&self.head)
            .uint(self.lo)
            .uint(self.hi)
            .uint(self.next_seq)
            .array(usize::from(self.entry.is_some()));
        if let Some(hash) = self.entry {
            e.bytes(&hash);
        }
        e.uint(self.offset).uint(self.entries_remaining as u64);
        Ok(())
    }

    fn decode(d: &mut Decoder<'_>, len: usize) -> Result<Self> {
        if len != 8 {
            return Err(invalid("history continuation arity"));
        }
        let query_kind =
            u8::try_from(d.uint()?).map_err(|_| invalid("history continuation kind"))?;
        let head = digest(d)?;
        let lo = d.uint()?;
        let hi = d.uint()?;
        let next_seq = d.uint()?;
        let entry = match d.array()? {
            0 => None,
            1 => Some(digest(d)?),
            _ => return Err(invalid("history continuation entry")),
        };
        let offset = d.uint()?;
        let entries_remaining = size(d.uint()?)?;
        let result = Self {
            query_kind,
            head,
            lo,
            hi,
            next_seq,
            entry,
            offset,
            entries_remaining,
        };
        result.validate()?;
        Ok(result)
    }
}

/// The most runs of either kind one author's Have carries: the newest, oldest first. The body
/// runs of an author that has more are told as further pages of at most this many runs each.
pub const MAX_HAVE_RUNS: usize = 256;
/// The most Have pages of the asked author a Range answer's correction carries (`server.rs`
/// range answer, `credit.rs`): the newest page, plus the older body pages overlapping the asked
/// interval. Every older page but the oldest holds exactly `MAX_HAVE_RUNS` disjoint runs, so
/// it spans at least `MAX_HAVE_RUNS` positions; an Entries interval (fewer than
/// `MAX_PAGE_ENTRIES` = 128 positions) therefore overlaps at most two older pages and a Body
/// position one, and a Controls correction carries only the newest page (older pages hold
/// only body runs, which a Controls answer never corrects).
pub const MAX_CORRECTION_PAGES: usize = 3;
/// The most signed heads one author's Have carries: committed, observed and a conflict pair.
pub const MAX_HAVE_HEADS: usize = 4;

/// What a node can serve of one author, scoped to the peer it tells (design simple-sync §1,
/// ADR-054 PL-2): the signed heads it holds, unequal observations included, its committed head
/// first when it has one (`committed`); under that head, the runs of positions whose header and
/// witnesses it serves; apart from them and able to shrink, the runs whose bodies it serves,
/// sealed key packages included; and the runs inside which it answers a control interval (its
/// verified control coverage, "no control here" included). A holder that answers without what
/// it was asked for sends this again, corrected, in its answer. MP-9: whether it holds a
/// verified fork proof of the author (`fork`, a reason to ask `Query::Fork`), and the author's
/// one kept signed head whose continuity with its accepted chain is unresolved (`unresolved`,
/// id and size: a reason to ask `Query::HeadById`, never a committed head). An author whose
/// fork is listed is frozen there and has no unresolved head: its `unresolved` names the kept
/// proof instead (a digest of its two entry hashes, and its position): never trusted, it only
/// spares an asker that holds that proof a `Query::Fork` (the fork rule, `pull::FORK_ASKS`; the
/// position gates nothing); a peer that asks the fork first never reads it as a head. Neither
/// is evidence.
///
/// `bodies_span` is the interval of positions whose bodies this Have tells completely: inside
/// it a position outside `bodies` is not held; outside it this Have says nothing of bodies. The
/// author's Have proper (its heads, proof and controls) spans through `MAX_SEQ`, its newest
/// body runs; each older page of body runs is an `AuthorHave` with no heads, proof or controls
/// and a span below it. The pages of one author tile `1..=MAX_SEQ`; each replaces, inside its
/// span only, what was told before (a body no longer held shrinks it), and an omitted page is
/// not absence. A Have encoded before pages existed spans everything. Encoded as the ninth
/// element.
///
/// `role` is the holder's exact role-complete head of the author (`history_role_head`:
/// committed, exactly at its contiguous held-through, with terminal inclusion and matching
/// terminal hash), `(id, size)`: a reason for the author to ask the exact receipt
/// (`Query::Head(self)` under Control), never a receipt itself. Encoded as a tenth element only
/// when present, and only on the author's Have proper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorHave {
    pub author: Digest32,
    pub heads: Vec<Vec<u8>>,
    pub committed: bool,
    pub proof: Vec<(u64, u64)>,
    pub bodies: Vec<(u64, u64)>,
    pub controls: Vec<(u64, u64)>,
    pub fork: bool,
    pub unresolved: Option<(Digest32, u64)>,
    pub bodies_span: (u64, u64),
    pub role: Option<(Digest32, u64)>,
}

impl Default for AuthorHave {
    fn default() -> Self {
        Self {
            author: [0; 32],
            heads: Vec::new(),
            committed: false,
            proof: Vec::new(),
            bodies: Vec::new(),
            controls: Vec::new(),
            fork: false,
            unresolved: None,
            bodies_span: (1, MAX_SEQ),
            role: None,
        }
    }
}

impl AuthorHave {
    /// The author's Have proper: its newest page, which carries its heads, proof and controls.
    pub(crate) fn is_newest_page(&self) -> bool {
        self.bodies_span.1 == MAX_SEQ
    }

    fn validate(&self) -> Result<()> {
        let (span_lo, span_hi) = self.bodies_span;
        if self.heads.len() > MAX_HAVE_HEADS
            || (self.committed && self.heads.is_empty())
            || self.proof.len() > MAX_HAVE_RUNS
            || self.bodies.len() > MAX_HAVE_RUNS
            || self.controls.len() > MAX_HAVE_RUNS
            || self.heads.iter().any(|head| head.len() > MAX_HEADER_BYTES)
            || span_lo == 0
            || span_lo > span_hi
            || span_hi > MAX_SEQ
            || (!self.is_newest_page()
                && (!self.heads.is_empty()
                    || !self.proof.is_empty()
                    || !self.controls.is_empty()
                    || self.fork
                    || self.unresolved.is_some()
                    || self.role.is_some()))
            || self
                .bodies
                .iter()
                .any(|&(lo, hi)| lo < span_lo || hi > span_hi)
        {
            return Err(invalid("history have bounds"));
        }
        for runs in [&self.proof, &self.bodies, &self.controls] {
            let mut last = 0;
            for &(lo, hi) in runs {
                interval(lo, hi)?;
                if lo <= last {
                    return Err(invalid("history have runs order"));
                }
                last = hi;
            }
        }
        if self.unresolved.is_some_and(|(_, size)| size > MAX_SEQ) {
            return Err(invalid("history have unresolved size"));
        }
        Ok(())
    }

    fn wire_bound(&self) -> usize {
        // The page span (array and two sizes) and the optional role element (array, 32-byte
        // id, size).
        180 + self.heads.iter().map(|head| head.len() + 9).sum::<usize>()
            + 20 * (self.proof.len() + self.bodies.len() + self.controls.len())
    }

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        self.validate()?;
        e.array(if self.role.is_some() { 10 } else { 9 })
            .bytes(&self.author)
            .array(self.heads.len());
        for head in &self.heads {
            e.bytes(head);
        }
        e.uint(u64::from(self.committed));
        for runs in [&self.proof, &self.bodies, &self.controls] {
            e.array(runs.len());
            for &(lo, hi) in runs {
                e.array(2).uint(lo).uint(hi);
            }
        }
        e.uint(u64::from(self.fork));
        e.array(usize::from(self.unresolved.is_some()));
        if let Some((head, size)) = self.unresolved {
            e.array(2).bytes(&head).uint(size);
        }
        e.array(2).uint(self.bodies_span.0).uint(self.bodies_span.1);
        if let Some((head, size)) = self.role {
            e.array(2).bytes(&head).uint(size);
        }
        Ok(())
    }

    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let len = d.array()?;
        if !(8..=10).contains(&len) {
            return Err(invalid("history have arity"));
        }
        let author = digest(d)?;
        let count = d.array()?;
        if count > MAX_HAVE_HEADS {
            return Err(invalid("history have heads"));
        }
        let mut heads = Vec::with_capacity(count);
        for _ in 0..count {
            heads.push(bounded_bytes(d, MAX_HEADER_BYTES)?.to_vec());
        }
        let committed = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(invalid("history have committed flag")),
        };
        let mut runs = [Vec::new(), Vec::new(), Vec::new()];
        for list in &mut runs {
            let count = d.array()?;
            if count > MAX_HAVE_RUNS {
                return Err(invalid("history have runs"));
            }
            for _ in 0..count {
                arity(d, 2)?;
                list.push((d.uint()?, d.uint()?));
            }
        }
        let [proof, bodies, controls] = runs;
        let fork = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(invalid("history have fork flag")),
        };
        let unresolved = match d.array()? {
            0 => None,
            1 => {
                arity(d, 2)?;
                Some((digest(d)?, d.uint()?))
            }
            _ => return Err(invalid("history have unresolved count")),
        };
        let bodies_span = if len >= 9 {
            arity(d, 2)?;
            (d.uint()?, d.uint()?)
        } else {
            (1, MAX_SEQ)
        };
        let have = Self {
            author,
            heads,
            committed,
            proof,
            bodies,
            controls,
            fork,
            unresolved,
            bodies_span,
            role: if len == 10 {
                arity(d, 2)?;
                Some((digest(d)?, d.uint()?))
            } else {
                None
            },
        };
        have.validate()?;
        Ok(have)
    }

    /// This Have without the positions `lo..=hi` in the runs of `kind`: a holder's correction
    /// after it answered without them.
    pub(crate) fn without(mut self, kind: HaveRuns, lo: u64, hi: u64) -> Self {
        let runs = match kind {
            HaveRuns::Proof => &mut self.proof,
            HaveRuns::Bodies => &mut self.bodies,
            HaveRuns::Controls => &mut self.controls,
        };
        let mut out = Vec::with_capacity(runs.len() + 1);
        for &(a, b) in runs.iter() {
            if b < lo || a > hi {
                out.push((a, b));
                continue;
            }
            if a < lo {
                out.push((a, lo - 1));
            }
            if b > hi {
                out.push((hi + 1, b));
            }
        }
        *runs = out;
        if kind == HaveRuns::Proof {
            // A body is served only with its proofs.
            self = self.without(HaveRuns::Bodies, lo, hi);
        }
        self
    }
}

/// Which runs of an [`AuthorHave`] a correction narrows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HaveRuns {
    Proof,
    Bodies,
    Controls,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadHint {
    pub author: Digest32,
    pub size: u64,
    pub head: Digest32,
}

/// One live package body debt as the loop matched an explicit Body answer to it: the accepted
/// entry it is keyed by (its fixed validated source head, author, position and entry hash; the
/// recipient is the one that signed header names). The typed refill admits a body only for it,
/// and only while the durable debt still exists in the refill's own transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyBodyNeed {
    pub(crate) head: Digest32,
    pub(crate) author: Digest32,
    pub(crate) seq: u64,
    pub(crate) hash: Digest32,
}

/// One retained original sender release this holder can hand back to its author (ADR-054
/// adoption step 5, OwnRelease): which author, key epoch and chain, and the earliest iteration
/// it can open from. Never the key. Told ONLY to that author, as the Have's own section
/// (`Frame::Releases`, `pull::tell`); the author asks it with the sealed one-shot request
/// (`actor/own_keys.rs`) only while its native readability check lacks that key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReleaseHave {
    pub(crate) author: Digest32,
    pub(crate) epoch: u64,
    pub(crate) chain: u64,
    pub(crate) earliest: u64,
}

/// Entries in one `Frame::Releases`; a longer section goes as several frames.
pub(crate) const MAX_RELEASES_PER_FRAME: usize = 256;
const RELEASE_WIRE_BOUND: usize = 72;

pub enum Proof {
    Inclusion(InclusionProof),
    Consistency {
        prefix: Descriptor,
        proof: ConsistencyProof,
    },
    Control(ControlRangeProof),
}

pub enum Object<'a> {
    Head(&'a [u8]),
    Context(&'a [u8]),
    Proof(Proof),
    Header(&'a [u8]),
    /// MP-9: a fork proof this node verified and kept: the two signed entry headers (no
    /// body) its author signed at one position.
    Fork {
        existing: &'a [u8],
        conflicting: &'a [u8],
    },
}

pub enum Frame<'a> {
    Hello(u8),
    Want {
        request: RequestId,
        query: Query,
        /// The canonical body of the query's head when it is head-bound (`Query::target_head`).
        target: Option<HeadTarget>,
    },
    Meta {
        request: RequestId,
        object: Object<'a>,
    },
    Chunk {
        request: RequestId,
        entry: Digest32,
        offset: u64,
        bytes: &'a [u8],
    },
    Done {
        request: RequestId,
        status: Status,
        continuation: Option<Continuation>,
    },
    Cancel(RequestId),
    /// A Have (`AuthorHave` per author), or, inside a Range answer, the holder's corrected
    /// Have of the asked author.
    Holding(Vec<AuthorHave>),
    /// The Have's own-release section (`ReleaseHave`), told only to that author; each entry
    /// replaces the one of its (epoch, chain) told before. Tag 0x0D.
    Releases(Vec<ReleaseHave>),
    /// A Have that also carries the holder's private Session tip, `(donor incarnation,
    /// through)`: told only to a peer currently eligible for the room's private Sessions
    /// (Drive), never to any other peer, and never inside an answer. An observation, not a
    /// permission, a read floor or proof that earlier records are retained. Frame tag 0x0E.
    PrivateHolding(Vec<AuthorHave>, crate::node::sessionstream::Cursor),
    Ack {
        request: RequestId,
        entry: Digest32,
        next_offset: u64,
    },
}

/// Encoded bytes retain their reservation until the last transport copy is finished.
pub struct Encoded {
    bytes: Vec<u8>,
    _charge: BufferCharge,
}

impl Encoded {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl<'a> Frame<'a> {
    /// Reserve the encoder, nested proof and final-frame copies before producing any of them.
    /// The caller already owns the independently charged source objects. Lack of room is a
    /// local busy/yield result; it is not malformed peer input.
    pub fn encode(&self, job: &Job) -> Result<Option<Encoded>> {
        let (maximum, envelope) = self.encoding_envelope()?;
        let Some(charge) = job.reserve(envelope) else {
            return Ok(None);
        };
        self.encode_precharged(maximum, charge).map(Some)
    }

    /// An owned client continuation must acquire its encoding before committing the work
    /// that requires this frame. Refusal carries the exact capacity dependency to that owner.
    pub(super) fn encode_required(&self, job: &Job) -> Result<Encoded> {
        let (maximum, envelope) = self.encoding_envelope()?;
        let charge = job.reserve_or_pressure(envelope)?;
        self.encode_precharged(maximum, charge)
    }

    fn encoding_envelope(&self) -> Result<(usize, usize)> {
        let maximum = match self {
            Self::Hello(_) => MAX_HELLO_FRAME_BYTES,
            Self::Want { .. } => MAX_WANT_FRAME_BYTES,
            Self::Meta {
                object:
                    Object::Fork {
                        existing,
                        conflicting,
                    },
                ..
            } => LOCAL_BYTES_FRAME_FIXED_BYTES
                .checked_add(existing.len())
                .and_then(|bound| bound.checked_add(conflicting.len()))
                .filter(|bound| *bound <= MAX_FRAME_BYTES)
                .ok_or(Error::SizeLimitExceeded("history encoded frame"))?,
            Self::Meta {
                object: Object::Head(bytes) | Object::Context(bytes) | Object::Header(bytes),
                ..
            }
            | Self::Chunk { bytes, .. } => LOCAL_BYTES_FRAME_FIXED_BYTES
                .checked_add(bytes.len())
                .filter(|bound| *bound <= MAX_FRAME_BYTES)
                .ok_or(Error::SizeLimitExceeded("history encoded frame"))?,
            Self::Done { .. } => DONE_RESERVE,
            Self::Cancel(_) => CANCEL_FRAME_MAX_BYTES,
            Self::Holding(authors) => authors
                .iter()
                .map(AuthorHave::wire_bound)
                .sum::<usize>()
                .checked_add(16)
                .filter(|bound| *bound <= MAX_FRAME_BYTES)
                .ok_or(Error::SizeLimitExceeded("history encoded frame"))?,
            Self::Releases(releases) => {
                if releases.len() > MAX_RELEASES_PER_FRAME {
                    return Err(invalid("history releases"));
                }
                16 + RELEASE_WIRE_BOUND * releases.len()
            }
            Self::PrivateHolding(authors, _) => authors
                .iter()
                .map(AuthorHave::wire_bound)
                .sum::<usize>()
                .checked_add(16 + 48)
                .filter(|bound| *bound <= MAX_FRAME_BYTES)
                .ok_or(Error::SizeLimitExceeded("history encoded frame"))?,
            Self::Ack { .. } => ACK_FRAME_MAX_BYTES,
            Self::Meta {
                object: Object::Proof(_),
                ..
            } => MAX_FRAME_BYTES,
        };
        let envelope = maximum
            .checked_mul(4)
            .ok_or(Error::SizeLimitExceeded("history encoded frame"))?;
        Ok((maximum, envelope))
    }

    // One encoder and validation path for both optional server output and required client ACKs.
    // The owned reservation covers the same nested proof and final-frame copies in either case.
    fn encode_precharged(&self, maximum: usize, charge: BufferCharge) -> Result<Encoded> {
        Ok(Encoded {
            bytes: self.encode_bytes(maximum)?,
            _charge: charge,
        })
    }

    /// A loop's own small frames (its request, its Have) are the connection's private
    /// assembly: encoded with no job and no shared byte admission (ADR-054 PL-6).
    pub(super) fn encode_private(&self) -> Result<Vec<u8>> {
        let (maximum, _) = self.encoding_envelope()?;
        self.encode_bytes(maximum)
    }

    fn encode_bytes(&self, maximum: usize) -> Result<Vec<u8>> {
        let mut e = Encoder::new();
        let mut tail = None;
        let id = match self {
            Self::Hello(bitmap) => {
                e.uint(u64::from(*bitmap));
                0x01
            }
            Self::Want {
                request,
                query,
                target,
            } => {
                if query.target_head() != target.map(|target| target.id()) {
                    return Err(invalid("history request target differs from its head"));
                }
                e.array(3).bytes(request);
                query.encode(&mut e)?;
                e.array(usize::from(target.is_some()));
                if let Some(target) = target {
                    target.encode(&mut e);
                }
                0x03
            }
            Self::Meta { request, object } => {
                e.array(3).bytes(request);
                match object {
                    Object::Head(bytes) => {
                        bound(bytes, MAX_HEADER_BYTES)?;
                        e.uint(0).bytes(bytes);
                    }
                    Object::Context(bytes) => {
                        bound(bytes, MAX_CONTEXT_BYTES)?;
                        e.uint(1).bytes(bytes);
                    }
                    Object::Proof(proof) => {
                        e.uint(2).array(2);
                        match proof {
                            Proof::Inclusion(proof) => {
                                proof.validate()?;
                                e.uint(0);
                                proof.encode(&mut e);
                            }
                            Proof::Consistency { prefix, proof } => {
                                prefix.validate()?;
                                proof.validate()?;
                                if prefix.leaves != proof.from {
                                    return Err(invalid("history claimed prefix size"));
                                }
                                e.uint(1).array(2);
                                prefix.encode(&mut e);
                                proof.encode(&mut e);
                            }
                            Proof::Control(proof) => {
                                e.uint(2);
                                tail = Some(proof.to_bytes()?);
                            }
                        }
                    }
                    Object::Header(bytes) => {
                        bound(bytes, MAX_HEADER_BYTES)?;
                        e.uint(3).bytes(bytes);
                    }
                    Object::Fork {
                        existing,
                        conflicting,
                    } => {
                        bound(existing, MAX_HEADER_BYTES)?;
                        bound(conflicting, MAX_HEADER_BYTES)?;
                        e.uint(4).array(2).bytes(existing).bytes(conflicting);
                    }
                }
                0x06
            }
            Self::Chunk {
                request,
                entry,
                offset,
                bytes,
            } => {
                bound(bytes, MAX_CHUNK_BYTES)?;
                if bytes.is_empty()
                    || offset
                        .checked_add(bytes.len() as u64)
                        .is_none_or(|end| end > MAX_PAYLOAD_BYTES as u64)
                {
                    return Err(invalid("history chunk bounds"));
                }
                e.array(4)
                    .bytes(request)
                    .bytes(entry)
                    .uint(*offset)
                    .bytes(bytes);
                0x07
            }
            Self::Done {
                request,
                status,
                continuation,
            } => {
                done_shape(*status, continuation.as_ref())?;
                e.array(3).bytes(request).uint(*status as u64);
                if let Some(cursor) = continuation {
                    cursor.encode(&mut e)?;
                } else {
                    e.array(0);
                }
                0x08
            }
            Self::Holding(authors) => {
                if authors.len() > MAX_CONTEXT_AUTHORS {
                    return Err(invalid("history have authors"));
                }
                e.array(authors.len());
                for have in authors {
                    have.encode(&mut e)?;
                }
                0x0C
            }
            Self::Releases(releases) => {
                if releases.len() > MAX_RELEASES_PER_FRAME {
                    return Err(invalid("history releases"));
                }
                e.array(releases.len());
                for release in releases {
                    e.array(4)
                        .bytes(&release.author)
                        .uint(release.epoch)
                        .uint(release.chain)
                        .uint(release.earliest);
                }
                0x0D
            }
            Self::PrivateHolding(authors, tip) => {
                if authors.len() > MAX_CONTEXT_AUTHORS {
                    return Err(invalid("history have authors"));
                }
                e.array(3).array(authors.len());
                for have in authors {
                    have.encode(&mut e)?;
                }
                e.bytes(&tip.incarnation).uint(tip.after);
                0x0E
            }
            Self::Cancel(request) => {
                e.array(1).bytes(request);
                0x09
            }
            Self::Ack {
                request,
                entry,
                next_offset,
            } => {
                if *next_offset > MAX_PAYLOAD_BYTES as u64 {
                    return Err(invalid("history ack offset"));
                }
                e.array(3).bytes(request).bytes(entry).uint(*next_offset);
                0x0A
            }
        };
        let body = e.finish();
        let len = 1 + body.len() + tail.as_ref().map_or(0, Vec::len);
        if len > maximum {
            return Err(Error::SizeLimitExceeded("history encoded frame"));
        }
        let mut bytes = Vec::with_capacity(len);
        bytes.push(id);
        bytes.extend_from_slice(&body);
        if let Some(tail) = tail {
            bytes.extend_from_slice(&tail);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        bound(bytes, MAX_FRAME_BYTES)?;
        let (&id, body) = bytes.split_first().ok_or(invalid("history empty frame"))?;
        let mut d = Decoder::new(body);
        let frame = match id {
            0x01 => {
                Self::Hello(u8::try_from(d.uint()?).map_err(|_| invalid("history hello bitmap"))?)
            }
            // Frame tag 0x02 (the old inventory Have) is retired and must not be reused.
            0x03 => {
                arity(&mut d, 3)?;
                let request = request_id(&mut d)?;
                let query = Query::decode(&mut d)?;
                let target = match d.array()? {
                    0 => None,
                    1 => Some(HeadTarget::decode(&mut d)?),
                    _ => return Err(invalid("history request target count")),
                };
                // The body must hash to the named head: an unsigned selector, never authority.
                if query.target_head() != target.map(|target| target.id()) {
                    return Err(invalid("history request target differs from its head"));
                }
                Self::Want {
                    request,
                    query,
                    target,
                }
            }
            0x06 => {
                arity(&mut d, 3)?;
                let request = request_id(&mut d)?;
                let object = match d.uint()? {
                    0 => Object::Head(bounded_bytes(&mut d, MAX_HEADER_BYTES)?),
                    1 => Object::Context(bounded_bytes(&mut d, MAX_CONTEXT_BYTES)?),
                    2 => {
                        arity(&mut d, 2)?;
                        let kind = ProofKind::decode(d.uint()?)?;
                        // The proof is the final field. Its typed decoder consumes the exact
                        // remaining body, including end-of-input validation; no generic Value.
                        let rest = &body[body.len() - d.remaining()..];
                        let proof = match kind {
                            ProofKind::Inclusion => {
                                Proof::Inclusion(InclusionProof::from_bytes(rest)?)
                            }
                            ProofKind::Consistency => {
                                let mut body = Decoder::new(rest);
                                arity(&mut body, 2)?;
                                let prefix = Descriptor::decode(&mut body)?;
                                let proof = ConsistencyProof::decode(&mut body)?;
                                body.finish()?;
                                if prefix.leaves != proof.from {
                                    return Err(invalid("history claimed prefix size"));
                                }
                                Proof::Consistency { prefix, proof }
                            }
                            ProofKind::Control => {
                                Proof::Control(ControlRangeProof::from_bytes(rest)?)
                            }
                        };
                        return Ok(Self::Meta {
                            request,
                            object: Object::Proof(proof),
                        });
                    }
                    3 => Object::Header(bounded_bytes(&mut d, MAX_HEADER_BYTES)?),
                    4 => {
                        arity(&mut d, 2)?;
                        Object::Fork {
                            existing: bounded_bytes(&mut d, MAX_HEADER_BYTES)?,
                            conflicting: bounded_bytes(&mut d, MAX_HEADER_BYTES)?,
                        }
                    }
                    _ => return Err(invalid("history metadata kind")),
                };
                Self::Meta { request, object }
            }
            0x07 => {
                arity(&mut d, 4)?;
                let request = request_id(&mut d)?;
                let entry = digest(&mut d)?;
                let offset = d.uint()?;
                let chunk = bounded_bytes(&mut d, MAX_CHUNK_BYTES)?;
                if chunk.is_empty()
                    || offset
                        .checked_add(chunk.len() as u64)
                        .is_none_or(|end| end > MAX_PAYLOAD_BYTES as u64)
                {
                    return Err(invalid("history chunk bounds"));
                }
                Self::Chunk {
                    request,
                    entry,
                    offset,
                    bytes: chunk,
                }
            }
            0x08 => {
                arity(&mut d, 3)?;
                let request = request_id(&mut d)?;
                let status = Status::decode(d.uint()?)?;
                let len = d.array()?;
                let continuation = if len == 0 {
                    None
                } else {
                    Some(Continuation::decode(&mut d, len)?)
                };
                done_shape(status, continuation.as_ref())?;
                Self::Done {
                    request,
                    status,
                    continuation,
                }
            }
            0x0C => {
                let count = d.array()?;
                if count > MAX_CONTEXT_AUTHORS {
                    return Err(invalid("history have authors"));
                }
                let mut authors = Vec::with_capacity(count.min(64));
                for _ in 0..count {
                    authors.push(AuthorHave::decode(&mut d)?);
                }
                Self::Holding(authors)
            }
            0x0D => {
                let count = d.array()?;
                if count > MAX_RELEASES_PER_FRAME {
                    return Err(invalid("history releases"));
                }
                let mut releases = Vec::with_capacity(count);
                for _ in 0..count {
                    arity(&mut d, 4)?;
                    releases.push(ReleaseHave {
                        author: digest(&mut d)?,
                        epoch: d.uint()?,
                        chain: d.uint()?,
                        earliest: d.uint()?,
                    });
                }
                Self::Releases(releases)
            }
            0x0E => {
                arity(&mut d, 3)?;
                let count = d.array()?;
                if count > MAX_CONTEXT_AUTHORS {
                    return Err(invalid("history have authors"));
                }
                let mut authors = Vec::with_capacity(count.min(64));
                for _ in 0..count {
                    authors.push(AuthorHave::decode(&mut d)?);
                }
                let incarnation = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| invalid("history private tip incarnation"))?;
                Self::PrivateHolding(
                    authors,
                    crate::node::sessionstream::Cursor {
                        incarnation,
                        after: d.uint()?,
                    },
                )
            }
            0x09 => {
                arity(&mut d, 1)?;
                Self::Cancel(request_id(&mut d)?)
            }
            0x0A => {
                arity(&mut d, 3)?;
                let request = request_id(&mut d)?;
                let entry = digest(&mut d)?;
                let next_offset = d.uint()?;
                if next_offset > MAX_PAYLOAD_BYTES as u64 {
                    return Err(invalid("history ack offset"));
                }
                Self::Ack {
                    request,
                    entry,
                    next_offset,
                }
            }
            // Frame tag 0x0B is retired and must not be reused.
            _ => return Err(invalid("history frame kind")),
        };
        d.finish()?;
        Ok(frame)
    }
}

fn done_shape(status: Status, continuation: Option<&Continuation>) -> Result<()> {
    if (status == Status::Complete && continuation.is_some())
        || (status == Status::More && continuation.is_none())
    {
        return Err(invalid("history done continuation"));
    }
    Ok(())
}

fn invalid(reason: &'static str) -> Error {
    Error::MalformedBundle(reason)
}
fn bound(bytes: &[u8], maximum: usize) -> Result<()> {
    if bytes.len() > maximum {
        Err(Error::SizeLimitExceeded("history frame/object"))
    } else {
        Ok(())
    }
}
fn bounded_bytes<'a>(d: &mut Decoder<'a>, maximum: usize) -> Result<&'a [u8]> {
    let bytes = d.bytes()?;
    bound(bytes, maximum)?;
    Ok(bytes)
}
fn arity(d: &mut Decoder<'_>, expected: usize) -> Result<()> {
    if d.array()? != expected {
        Err(invalid("history array arity"))
    } else {
        Ok(())
    }
}
fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| invalid("history digest length"))
}
fn request_id(d: &mut Decoder<'_>) -> Result<RequestId> {
    d.bytes()?
        .try_into()
        .map_err(|_| invalid("history request length"))
}
fn size(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| invalid("history size"))
}
fn position(value: u64) -> Result<()> {
    if value == 0 || value > MAX_SEQ {
        Err(invalid("history position"))
    } else {
        Ok(())
    }
}
fn interval(lo: u64, hi: u64) -> Result<()> {
    position(lo)?;
    position(hi)?;
    if lo > hi {
        Err(invalid("history interval"))
    } else {
        Ok(())
    }
}
