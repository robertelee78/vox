//! Explicit bounded sync requests and frames (ADR-036 H-6).
//!
//! This codec checks structure and resource bounds. It grants no authority: the caller binds
//! every object to its request, verifies author/control evidence, and rechecks current access.
//! Payload slices borrow the charged input frame rather than making another queued copy.

mod admission;
mod client;
mod credit;
mod driver;
mod hints;
pub(crate) mod runtime;
mod server;
mod source;
mod transport;

pub(crate) use client::{EntryPhase, LocalNeed, LocalProof, LocalStep, Receiver, Staging};
pub(crate) use driver::exchange;
pub(crate) use hints::HintInbox;

use super::history_budget::{BufferCharge, Job};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::feed::MAX_SEQ;
use crate::log::history::{
    ConsistencyProof, ControlRangeProof, Descriptor, InclusionProof, MAX_CHUNK_BYTES,
    MAX_CONTEXT_AUTHORS, MAX_CONTEXT_BYTES, MAX_FRAME_BYTES, MAX_HEADER_BYTES, MAX_PAGE_ENTRIES,
    MAX_PAYLOAD_BYTES, MAX_RESPONSE_BYTES,
};

pub type RequestId = [u8; 16];
pub const MAX_PREAMBLE: usize = 128;
pub const DONE_RESERVE: usize = 512;
// One frame tag plus the canonical CBOR encoding of any u8 mode bitmap.
const MAX_HELLO_FRAME_BYTES: usize = 3;
// Tag + outer pair + request ID + the largest canonical Query (Page). Query's bounded u64 and
// digest fields make this an exact structural maximum, independent of peer input.
const MAX_WANT_FRAME_BYTES: usize = 160;
// Tag and a conservatively maximal CBOR array header. Each locally materialized HAVE hint is an
// array header, two 32-byte byte strings (each with a maximal CBOR length header), and one u64.
// The decoder still reserves the full attacker-sized envelope before reading any variable frame;
// this bound sizes only an encoder whose exact local hint count is already known.
const HAVE_FRAME_FIXED_BYTES: usize = 1 + 9;
const HAVE_HINT_MAX_BYTES: usize = 9 + 2 * (9 + 32) + 9;
// Conservative tag/CBOR overhead for a locally sourced byte-string frame. The peer-facing
// decoder still reserves the full attacker-sized frame and decode envelope before its prefix.
const LOCAL_BYTES_FRAME_FIXED_BYTES: usize = 128;
const CANCEL_FRAME_MAX_BYTES: usize = 64;
const ACK_FRAME_MAX_BYTES: usize = 128;

/// Exact local request incarnation. The sealed keyring nonce changes on a durable trust edit,
/// including removal followed by an otherwise identical regrant; unchanged restart preserves
/// it. This digest grants no rights. Current room membership and body admission still apply.
pub(crate) fn authorization_generation(
    store: &super::store::Store,
    node: Digest32,
    room: Digest32,
    instance: [u8; 16],
    epoch: u64,
) -> Result<Digest32> {
    let nonce =
        store.get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(super::trust::TRUST_META_KEY)?;
    Ok(generation_from_nonce(node, room, instance, epoch, nonce))
}

/// Recheck the trust incarnation inside the accepted-entry transaction, so a concurrent trust
/// edit cannot slip between an earlier read and durable publication/ACK eligibility.
pub(crate) fn authorization_generation_in(
    batch: &super::store::Batch<'_>,
    node: Digest32,
    room: Digest32,
    instance: [u8; 16],
    epoch: u64,
) -> Result<Digest32> {
    let nonce =
        batch.get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(super::trust::TRUST_META_KEY)?;
    Ok(generation_from_nonce(node, room, instance, epoch, nonce))
}

fn generation_from_nonce(
    node: Digest32,
    room: Digest32,
    instance: [u8; 16],
    epoch: u64,
    nonce: Option<[u8; crate::atrest::sek::NONCE_LEN]>,
) -> Digest32 {
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(b"vox/history-authorization/v1");
    bytes.extend_from_slice(&node);
    bytes.extend_from_slice(&room);
    bytes.extend_from_slice(&instance);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.push(u8::from(nonce.is_some()));
    if let Some(nonce) = nonce {
        bytes.extend_from_slice(&nonce);
    }
    crate::hash::sha256(&bytes)
}

/// Run one admitted incoming request with a fixed lifetime. This never asks for another page.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    room: std::sync::Arc<tokio::sync::Mutex<super::channel::ChannelState>>,
    store: std::sync::Arc<super::store::Store>,
    peer: Digest32,
    connection_serial: u64,
    preamble: Preamble,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    job: Job,
    fence: std::sync::Arc<crate::transport::stream_transport::Fence>,
    inbox: std::sync::Arc<HintInbox>,
    departure_receipt: std::sync::Arc<std::sync::atomic::AtomicBool>,
    availability_connection: Option<u64>,
) -> (Result<Status>, bool, bool) {
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
    );
    let mut io =
        transport::Transport::new(send, recv, job, fence, deadline, availability_connection);
    let generation = inbox.generation(preamble.room, peer);
    let mut inventory_added = false;
    // Whether the round moved anything: an inventory exchange that added no hint on this side
    // served the peer nothing it lacked, and is an `empty` round in `vox status --json`
    // (ADR-038 FX-29); any other query is an object the peer asked for because it lacked it.
    let mut served_object = false;
    let result = serve_request(
        &source,
        &mut io,
        preamble,
        &inbox,
        generation,
        connection_serial,
        &mut inventory_added,
        &mut served_object,
        &departure_receipt,
    )
    .await;
    if let Err(error) = &result {
        let code = match error {
            Error::HistoryCapacity(_) => crate::wire::WireError::SessionBusy,
            Error::SizeLimitExceeded(_) | Error::MalformedBundle(_) => {
                crate::wire::WireError::ProtocolLimits
            }
            _ => crate::wire::WireError::TransportFailed,
        };
        io.abort(code);
    }
    (result, inventory_added, inventory_added || served_object)
}

#[allow(clippy::too_many_arguments)]
async fn serve_request(
    source: &source::Source,
    io: &mut transport::Transport,
    preamble: Preamble,
    inbox: &HintInbox,
    inbox_generation: u64,
    connection_serial: u64,
    inventory_added: &mut bool,
    served_object: &mut bool,
    departure_receipt: &std::sync::atomic::AtomicBool,
) -> Result<Status> {
    let first = match io.read_hello().await? {
        transport::Read::Frame(frame) => frame,
        transport::Read::End => return Err(invalid("history closed before HELLO")),
        transport::Read::Busy => return Err(Error::Unreachable("history HELLO reader busy")),
    };
    if !matches!(first.frame()?, Frame::Hello(mode) if mode == crate::wire::SYNC_MODE_BOUNDED_HISTORY)
    {
        return Err(invalid("history HELLO mode"));
    }
    let mut overhead = first.wire_len()
        + preamble.encode().len()
        + 4
        + crate::transport::streams::StreamKind::Sync.frame().len()
        + 4;
    drop(first);
    let hello = Frame::Hello(crate::wire::SYNC_MODE_BOUNDED_HISTORY);
    let Some(encoded) = hello.encode(io.job())? else {
        return Err(Error::Unreachable("history HELLO writer busy"));
    };
    overhead += encoded.as_slice().len() + 4;
    io.write_encoded(&encoded).await?;
    drop(encoded);
    let next = match io.read_want_or_cancel().await? {
        transport::Read::Frame(frame) => frame,
        transport::Read::End => return Err(invalid("history closed before WANT")),
        transport::Read::Busy => return Err(Error::Unreachable("history WANT reader busy")),
    };
    overhead += next.wire_len();
    let query = match next.frame()? {
        Frame::Want { request, query } if request == preamble.request => query,
        Frame::Cancel(request) if request == preamble.request => {
            let done = Frame::Done {
                request,
                status: Status::Cancelled,
                continuation: None,
            };
            if !io.write(&done).await? {
                return Err(Error::Unreachable("history cancelled response busy"));
            }
            io.finish()?;
            return Ok(Status::Cancelled);
        }
        _ => return Err(invalid("history expected bound WANT")),
    };
    drop(next);
    // Parsed and request-bound before publication. If the peer's departure is applied while
    // this response is in flight, lifecycle cleanup may retain only this exact query. The server
    // and Source still restrict the response to the peer's own settled, included head.
    if preamble.purpose == Purpose::Control
        && matches!(&query, Query::Head(author) if *author == source.peer)
    {
        departure_receipt.store(true, std::sync::atomic::Ordering::Release);
    }
    server::answer(
        source,
        io,
        preamble,
        query,
        overhead,
        inbox,
        inbox_generation,
        connection_serial,
        inventory_added,
        served_object,
    )
    .await
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
    /// One bounded inventory of scalar authenticated-head hints; no content request.
    Inventory,
    KeyAvailability {
        after: Option<u64>,
    },
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
    /// Explicit sealed-package transfer for recipient delivery or opaque relay.
    KeyBody {
        head: Digest32,
        author: Digest32,
        hash: Digest32,
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
}

impl Query {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Inventory | Self::Head(_) | Self::Context(_) => {}
            Self::KeyAvailability { after } => {
                if *after == Some(0) {
                    return Err(invalid("key availability cursor"));
                }
            }
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
            Self::Entry { seq, offset, .. } | Self::KeyBody { seq, offset, .. } => {
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
        }
        Ok(())
    }

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        self.validate()?;
        match self {
            Self::Inventory => {
                e.array(1).uint(6);
            }
            Self::KeyAvailability { after } => {
                e.array(2).uint(8).uint(after.unwrap_or(0));
            }
            Self::Head(author) => {
                e.array(2).uint(0).bytes(author);
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
            Self::KeyBody {
                head,
                author,
                hash,
                seq,
                offset,
            } => {
                e.array(6)
                    .uint(7)
                    .bytes(head)
                    .bytes(author)
                    .bytes(hash)
                    .uint(*seq)
                    .uint(*offset);
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
        }
        Ok(())
    }

    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let len = d.array()?;
        let query = match (d.uint()?, len) {
            (6, 1) => Self::Inventory,
            (0, 2) => Self::Head(digest(d)?),
            (1, 2) => Self::Context(digest(d)?),
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
            (8, 2) => {
                let cursor = d.uint()?;
                Self::KeyAvailability {
                    after: (cursor != 0).then_some(cursor),
                }
            }
            (3, 4) => Self::Entry {
                head: digest(d)?,
                seq: d.uint()?,
                offset: d.uint()?,
            },
            (7, 6) => Self::KeyBody {
                head: digest(d)?,
                author: digest(d)?,
                hash: digest(d)?,
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
        if self.query_kind > 4
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadHint {
    pub author: Digest32,
    pub size: u64,
    pub head: Digest32,
}

/// A provider's durable acquisition of one opaque key-package body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyBodyAvailable {
    pub(crate) cursor: u64,
    pub(crate) author: Digest32,
    pub(crate) head: Digest32,
    pub(crate) seq: u64,
    pub(crate) hash: Digest32,
    pub(crate) recipient: Digest32,
}

pub(crate) type KeyAvailabilityPage = Option<(u64, Option<KeyBodyAvailable>)>;
pub(crate) type KeyAvailabilityResult = Option<([u8; 16], KeyAvailabilityPage)>;

/// Durable recipient body work, scoped to its authenticated source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyBodyNeed {
    pub(crate) head: Digest32,
    pub(crate) seq: u64,
    pub(crate) hash: Digest32,
    pub(crate) recipient: Digest32,
    pub(crate) target: HeadHint,
    pub(crate) authorization: Digest32,
}

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
}

pub enum Frame<'a> {
    Hello(u8),
    Have {
        hints: Vec<HeadHint>,
        /// An authenticated peer's progress hint for the recipient's own feed. This is
        /// a reason to query, never a receipt or an authorization decision.
        role: Option<HeadHint>,
        key_catalog: Option<([u8; 16], u64)>,
        availability: Option<super::channel::availability::Token>,
    },
    KeyAvailability {
        request: RequestId,
        instance: [u8; 16],
        page: Option<(u64, Option<KeyBodyAvailable>)>,
    },
    Want {
        request: RequestId,
        query: Query,
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
            Self::KeyAvailability { .. } => 256,
            Self::Want { .. } => MAX_WANT_FRAME_BYTES,
            Self::Have { hints, .. } => (HAVE_FRAME_FIXED_BYTES + 280 + HAVE_HINT_MAX_BYTES)
                .checked_add(
                    hints
                        .len()
                        .checked_mul(HAVE_HINT_MAX_BYTES)
                        .ok_or(Error::SizeLimitExceeded("history encoded frame"))?,
                )
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
        let mut e = Encoder::new();
        let mut tail = None;
        let id = match self {
            Self::Hello(bitmap) => {
                e.uint(u64::from(*bitmap));
                0x01
            }
            Self::Have {
                hints,
                role,
                key_catalog,
                availability,
            } => {
                if hints.len() > MAX_CONTEXT_AUTHORS {
                    return Err(invalid("history have authors"));
                }
                e.array(4).array(hints.len());
                let mut previous = None;
                for hint in hints {
                    if hint.size > MAX_SEQ || previous.is_some_and(|last| last >= hint.author) {
                        return Err(invalid("history have order/size"));
                    }
                    previous = Some(hint.author);
                    e.array(3)
                        .bytes(&hint.author)
                        .uint(hint.size)
                        .bytes(&hint.head);
                }
                e.array(usize::from(role.is_some()));
                if let Some(role) = role {
                    if role.size > MAX_SEQ {
                        return Err(invalid("history role hint size"));
                    }
                    e.array(3)
                        .bytes(&role.author)
                        .uint(role.size)
                        .bytes(&role.head);
                }
                e.array(usize::from(key_catalog.is_some()));
                if let Some((instance, tip)) = key_catalog {
                    e.array(2).bytes(instance).uint(*tip);
                }
                e.array(usize::from(availability.is_some()));
                if let Some(token) = availability {
                    if token.open == 0 {
                        return Err(invalid("availability lifetime"));
                    }
                    e.array(2).uint(token.open).uint(token.revision);
                }
                0x02
            }
            Self::Want { request, query } => {
                e.array(2).bytes(request);
                query.encode(&mut e)?;
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
            Self::KeyAvailability {
                request,
                instance,
                page,
            } => {
                e.array(3)
                    .bytes(request)
                    .bytes(instance)
                    .array(usize::from(page.is_some()));
                if let Some((cursor, body)) = page {
                    if *cursor == 0 || body.is_some_and(|body| body.cursor != *cursor) {
                        return Err(invalid("key availability page cursor"));
                    }
                    e.array(2).uint(*cursor).array(usize::from(body.is_some()));
                    if let Some(body) = body {
                        position(body.seq)?;
                        e.array(5)
                            .bytes(&body.author)
                            .bytes(&body.head)
                            .uint(body.seq)
                            .bytes(&body.hash)
                            .bytes(&body.recipient);
                    }
                }
                0x0B
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
        Ok(Encoded {
            bytes,
            _charge: charge,
        })
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        bound(bytes, MAX_FRAME_BYTES)?;
        let (&id, body) = bytes.split_first().ok_or(invalid("history empty frame"))?;
        let mut d = Decoder::new(body);
        let frame = match id {
            0x01 => {
                Self::Hello(u8::try_from(d.uint()?).map_err(|_| invalid("history hello bitmap"))?)
            }
            0x02 => {
                arity(&mut d, 4)?;
                let count = d.array()?;
                if count > MAX_CONTEXT_AUTHORS {
                    return Err(invalid("history have authors"));
                }
                let mut hints = Vec::with_capacity(count);
                let mut previous = None;
                for _ in 0..count {
                    arity(&mut d, 3)?;
                    let author = digest(&mut d)?;
                    let size = d.uint()?;
                    if size > MAX_SEQ || previous.is_some_and(|last| last >= author) {
                        return Err(invalid("history have order/size"));
                    }
                    previous = Some(author);
                    hints.push(HeadHint {
                        author,
                        size,
                        head: digest(&mut d)?,
                    });
                }
                let role = match d.array()? {
                    0 => None,
                    1 => {
                        arity(&mut d, 3)?;
                        let author = digest(&mut d)?;
                        let size = d.uint()?;
                        if size > MAX_SEQ {
                            return Err(invalid("history role hint size"));
                        }
                        Some(HeadHint {
                            author,
                            size,
                            head: digest(&mut d)?,
                        })
                    }
                    _ => return Err(invalid("history role hint count")),
                };
                let key_catalog = match d.array()? {
                    0 => None,
                    1 => {
                        arity(&mut d, 2)?;
                        Some((request_id(&mut d)?, d.uint()?))
                    }
                    _ => return Err(invalid("key catalog hint count")),
                };
                let availability = match d.array()? {
                    0 => None,
                    1 => {
                        arity(&mut d, 2)?;
                        let open = d.uint()?;
                        if open == 0 {
                            return Err(invalid("availability lifetime"));
                        }
                        Some(super::channel::availability::Token {
                            open,
                            revision: d.uint()?,
                        })
                    }
                    _ => return Err(invalid("availability count")),
                };
                Self::Have {
                    hints,
                    role,
                    key_catalog,
                    availability,
                }
            }
            0x03 => {
                arity(&mut d, 2)?;
                Self::Want {
                    request: request_id(&mut d)?,
                    query: Query::decode(&mut d)?,
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
            0x0B => {
                arity(&mut d, 3)?;
                let request = request_id(&mut d)?;
                let instance = request_id(&mut d)?;
                let page = match d.array()? {
                    0 => None,
                    1 => {
                        arity(&mut d, 2)?;
                        let cursor = d.uint()?;
                        if cursor == 0 {
                            return Err(invalid("key availability page cursor"));
                        }
                        let body = match d.array()? {
                            0 => None,
                            1 => {
                                arity(&mut d, 5)?;
                                let author = digest(&mut d)?;
                                let head = digest(&mut d)?;
                                let seq = d.uint()?;
                                position(seq)?;
                                let hash = digest(&mut d)?;
                                let recipient = digest(&mut d)?;
                                Some(KeyBodyAvailable {
                                    cursor,
                                    author,
                                    head,
                                    seq,
                                    hash,
                                    recipient,
                                })
                            }
                            _ => return Err(invalid("key availability item count")),
                        };
                        Some((cursor, body))
                    }
                    _ => return Err(invalid("key availability page count")),
                };
                Self::KeyAvailability {
                    request,
                    instance,
                    page,
                }
            }
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
