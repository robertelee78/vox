//! Anti-entropy sync (ADR-008 §"Sync = anti-entropy") — the protocol *logic* over
//! an abstract byte-stream transport.
//!
//! Two peers reconcile their per-author logs to identical state. M5 implements the
//! protocol logic; the real QUIC transport is M9 (ADR-011), so sync runs over an
//! abstract [`Transport`] — an in-memory [`DuplexTransport`] drives the tests.
//!
//! ## Frames (ADR-008, M0 [`crate::wire::FrameId`])
//! Each frame is `1-byte FrameId ‖ canonical-CBOR body`:
//! - `HELLO {mode_bitmap}` — opening frame; the mode is negotiated as the highest
//!   bit both peers set (frontier is mandatory; range-reconciliation optional).
//! - `HAVE {[(author_id, max_seq, head_hash)]}` — the feeds a peer holds.
//! - `WANT {[(author_id, from_seq, to_seq)]}` — the ranges a peer is missing.
//! - `ENTRY {entry_wire, has_payload}` — a log entry (skeleton + optional payload).
//! - `NEG {negentropy_msg}` — a Negentropy range-reconciliation message.
//!
//! ## Modes
//! - **Frontier (default, required of every peer).** `HAVE` lists each held feed's
//!   `(author, max_seq, head_hash)`; the receiver replies `WANT` for the missing
//!   `(author, from..=to)` ranges; the holder streams `ENTRY` frames. Used below
//!   ~100 authors where `HAVE` is small.
//! - **Range-reconciliation (when both peers set bit 1).** `NEG` frames carry the
//!   [`crate::log::negentropy`] v1 protocol keyed by the full 32-byte entry hash;
//!   the resolved have/need ids drive `ENTRY` exchange. Used at scale.
//!
//! ## Hard-fail signalling
//! On a hard fail a peer **closes the stream with a Vox application error code**
//! (M0 [`crate::wire::WireError`]) — never a silent downgrade. The abstract
//! transport carries a [`Transport::close`] that records the code; the QUIC
//! mapping is M9.
//!
//! ## Acceptance
//! Received entries pass through the same DAG acceptance predicate as local ones
//! ([`crate::log::dag::Dag::accept`]): admission, authenticator, quota, feed link,
//! and fork handling. A peer never trusts an entry merely because it arrived over
//! sync.

use std::collections::VecDeque;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, DIGEST_LEN};
use crate::identity::composite::CompositePublicKey;
use crate::log::dag::{AdmissionPolicy, Dag, Rejected};
use crate::log::entry::{Entry, EntryKind, MAX_AUTHENTICATOR_LEN, MAX_PAYLOAD_LEN};
use crate::log::negentropy::{self, Role, MAX_MESSAGE_LEN as MAX_NEG_MESSAGE_LEN};
use crate::wire::{FrameId, WireError, SYNC_MODE_FRONTIER, SYNC_MODE_RANGE_RECONCILIATION};

/// Hard upper bound on an `ENTRY` frame's carried wire bytes, checked **before**
/// `to_vec` so a hostile frame cannot force a large allocation ahead of
/// [`Entry::from_wire`]'s own per-field caps (ADR-008 anti-abuse). It is the sum
/// of the entry's structural maxima — the payload, the authenticator, and a
/// generous fixed overhead for the skeleton/CBOR framing.
pub const MAX_ENTRY_WIRE: usize = MAX_PAYLOAD_LEN + MAX_AUTHENTICATOR_LEN + 4096;

/// An abstract bidirectional, reliable, ordered byte-frame transport.
///
/// M5 defines this trait so the sync logic is transport-agnostic; the real QUIC
/// stream is M9 (ADR-011). A frame is an opaque byte vector (the caller frames
/// with [`FrameId`] + CBOR). `close` carries the M0 wire error code on a hard
/// fail (the QUIC application-close mapping is M9).
pub trait Transport {
    /// Send one framed message. Errors are surfaced; the sync engine treats a
    /// send error as a transport failure and aborts.
    fn send(&mut self, frame: &[u8]) -> Result<()>;

    /// Receive the next framed message, or `Ok(None)` if the peer half-closed
    /// (no more frames).
    fn recv(&mut self) -> Result<Option<Vec<u8>>>;

    /// Close the stream with a Vox application error code (ADR-008). After a
    /// close the peer must not send/receive further frames.
    fn close(&mut self, code: WireError);
}

/// An in-memory duplex transport pairing two endpoints by shared queues, for
/// tests and local reconciliation. Not used in production (QUIC is M9).
#[derive(Debug, Default)]
pub struct DuplexTransport {
    /// Frames this endpoint will read (pushed by the peer).
    inbox: VecDeque<Vec<u8>>,
    /// Frames this endpoint writes (the peer reads from here).
    outbox: VecDeque<Vec<u8>>,
    /// The last close code observed on this endpoint, if any.
    closed: Option<WireError>,
}

impl DuplexTransport {
    /// Create a connected pair `(a, b)`: `a`'s outbox feeds `b`'s inbox via
    /// [`DuplexTransport::pump`].
    #[must_use]
    pub fn pair() -> (Self, Self) {
        (Self::default(), Self::default())
    }

    /// Move all of `a`'s outbox into `b`'s inbox and vice-versa (one exchange
    /// step). Returns the number of frames moved in total.
    pub fn pump(a: &mut Self, b: &mut Self) -> usize {
        let mut moved = 0;
        while let Some(f) = a.outbox.pop_front() {
            b.inbox.push_back(f);
            moved += 1;
        }
        while let Some(f) = b.outbox.pop_front() {
            a.inbox.push_back(f);
            moved += 1;
        }
        moved
    }

    /// Whether this endpoint was closed, and with what code.
    #[must_use]
    pub fn close_code(&self) -> Option<WireError> {
        self.closed
    }
}

impl Transport for DuplexTransport {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        if self.closed.is_some() {
            return Err(Error::MalformedBundle("sync: send on closed transport"));
        }
        self.outbox.push_back(frame.to_vec());
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(self.inbox.pop_front())
    }

    fn close(&mut self, code: WireError) {
        self.closed = Some(code);
    }
}

/// One feed's frontier summary: `(author_id, max_seq, head_hash)` (ADR-008 HAVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedFrontier {
    /// The feed's author fingerprint.
    pub author_id: Digest32,
    /// The highest seq the peer holds.
    pub max_seq: u64,
    /// The hash of the head entry (for fork-head comparison).
    pub head_hash: Digest32,
}

/// A requested range `(author_id, from_seq, to_seq)` inclusive (ADR-008 WANT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WantRange {
    /// The feed's author fingerprint.
    pub author_id: Digest32,
    /// The first missing seq (inclusive).
    pub from_seq: u64,
    /// The last missing seq (inclusive).
    pub to_seq: u64,
}

// ---------------------------------------------------------------------------
// Frame encode / decode
// ---------------------------------------------------------------------------

/// Encode a `HELLO {mode_bitmap}` frame.
#[must_use]
pub fn encode_hello(mode_bitmap: u8) -> Vec<u8> {
    let mut e = Encoder::new();
    e.uint(u64::from(mode_bitmap));
    framed(FrameId::Hello, e.finish())
}

/// Encode a `HAVE` frame from a peer's feed frontiers.
#[must_use]
pub fn encode_have(frontiers: &[FeedFrontier]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(frontiers.len());
    for f in frontiers {
        e.array(3)
            .bytes(&f.author_id)
            .uint(f.max_seq)
            .bytes(&f.head_hash);
    }
    framed(FrameId::Have, e.finish())
}

/// Encode a `WANT` frame.
#[must_use]
pub fn encode_want(ranges: &[WantRange]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(ranges.len());
    for r in ranges {
        e.array(3)
            .bytes(&r.author_id)
            .uint(r.from_seq)
            .uint(r.to_seq);
    }
    framed(FrameId::Want, e.finish())
}

/// Encode an `ENTRY` frame carrying a framed entry's wire bytes.
#[must_use]
pub fn encode_entry(entry_wire: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.bytes(entry_wire);
    framed(FrameId::Entry, e.finish())
}

/// Encode a `NEG` frame carrying a Negentropy message's wire bytes.
#[must_use]
pub fn encode_neg(neg_msg: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.bytes(neg_msg);
    framed(FrameId::Neg, e.finish())
}

/// Prefix a CBOR body with its 1-byte frame id.
fn framed(id: FrameId, body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(id.as_u8());
    out.extend_from_slice(&body);
    out
}

/// A decoded sync frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncFrame {
    /// `HELLO {mode_bitmap}`.
    Hello(u8),
    /// `HAVE {frontiers}`.
    Have(Vec<FeedFrontier>),
    /// `WANT {ranges}`.
    Want(Vec<WantRange>),
    /// `ENTRY {entry_wire}` — the raw framed entry bytes (parsed by the caller).
    Entry(Vec<u8>),
    /// `NEG {negentropy_msg}` — the raw Negentropy wire bytes.
    Neg(Vec<u8>),
}

/// Decode a sync frame. Rejects an unknown frame id (→ a
/// [`WireError::SyncModeUnsupported`] close at the caller) or a malformed body.
pub fn decode_frame(bytes: &[u8]) -> Result<SyncFrame> {
    let id_byte = *bytes
        .first()
        .ok_or(Error::MalformedBundle("sync empty frame"))?;
    let id = FrameId::from_u8(id_byte).ok_or(Error::MalformedBundle("sync unknown frame id"))?;
    let body = &bytes[1..];
    match id {
        FrameId::Hello => {
            let mut d = Decoder::new(body);
            let bitmap = u8::try_from(d.uint()?)
                .map_err(|_| Error::MalformedBundle("hello bitmap range"))?;
            d.finish()?;
            Ok(SyncFrame::Hello(bitmap))
        }
        FrameId::Have => {
            let mut d = Decoder::new(body);
            let n = d.array()?;
            let mut v = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                if d.array()? != 3 {
                    return Err(Error::MalformedBundle("have tuple arity"));
                }
                let author_id = take_digest(&mut d)?;
                let max_seq = d.uint()?;
                let head_hash = take_digest(&mut d)?;
                v.push(FeedFrontier {
                    author_id,
                    max_seq,
                    head_hash,
                });
            }
            d.finish()?;
            Ok(SyncFrame::Have(v))
        }
        FrameId::Want => {
            let mut d = Decoder::new(body);
            let n = d.array()?;
            let mut v = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                if d.array()? != 3 {
                    return Err(Error::MalformedBundle("want tuple arity"));
                }
                let author_id = take_digest(&mut d)?;
                let from_seq = d.uint()?;
                let to_seq = d.uint()?;
                v.push(WantRange {
                    author_id,
                    from_seq,
                    to_seq,
                });
            }
            d.finish()?;
            Ok(SyncFrame::Want(v))
        }
        FrameId::Entry => {
            let mut d = Decoder::new(body);
            // `d.bytes()` borrows (length bounded by remaining input, no alloc);
            // check the borrowed length against the cap BEFORE `to_vec`.
            let slice = d.bytes()?;
            if slice.len() > MAX_ENTRY_WIRE {
                return Err(Error::SizeLimitExceeded("sync ENTRY frame"));
            }
            let wire = slice.to_vec();
            d.finish()?;
            Ok(SyncFrame::Entry(wire))
        }
        FrameId::Neg => {
            let mut d = Decoder::new(body);
            let slice = d.bytes()?;
            if slice.len() > MAX_NEG_MESSAGE_LEN {
                return Err(Error::SizeLimitExceeded("sync NEG frame"));
            }
            let msg = slice.to_vec();
            d.finish()?;
            Ok(SyncFrame::Neg(msg))
        }
    }
}

fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle("sync digest length"))
}

/// Negotiate the sync mode from two mode bitmaps: the highest bit both set
/// (range-reconciliation preferred over frontier). Frontier is mandatory, so if
/// both at least set frontier the result is always at least frontier; if a peer
/// sets *no* common bit, [`WireError::SyncModeUnsupported`] is returned.
pub fn negotiate_mode(local: u8, remote: u8) -> std::result::Result<u8, WireError> {
    let common = local & remote;
    if common & SYNC_MODE_RANGE_RECONCILIATION != 0 {
        Ok(SYNC_MODE_RANGE_RECONCILIATION)
    } else if common & SYNC_MODE_FRONTIER != 0 {
        Ok(SYNC_MODE_FRONTIER)
    } else {
        Err(WireError::SyncModeUnsupported)
    }
}

// ---------------------------------------------------------------------------
// Resolver — maps an author fingerprint to its composite root key.
// ---------------------------------------------------------------------------

/// Resolves an author fingerprint to that author's composite root public key and
/// entry kind, so received entries can be verified + classified. The population
/// of this mapping is the identity/consent layers' job (M1/M6); sync only
/// consumes it.
pub trait AuthorResolver {
    /// The composite root key for `author`, or `None` if unknown (an entry from an
    /// unknown author is refused — it cannot be verified).
    fn key_for(&self, author: &Digest32) -> Option<CompositePublicKey>;

    /// The entry kind for an entry, used to choose the fork remedy. M5 has no way
    /// to read encrypted payloads, so the default is [`EntryKind::Content`]; M6/M7
    /// override for governance entries.
    fn kind_for(&self, _entry: &Entry) -> EntryKind {
        EntryKind::Content
    }
}

// ---------------------------------------------------------------------------
// Frontier-mode sync.
// ---------------------------------------------------------------------------

/// Build the local `HAVE` frontiers from a [`Dag`] (one per author feed).
#[must_use]
pub fn frontiers_of(dag: &Dag) -> Vec<FeedFrontier> {
    dag.authors()
        .into_iter()
        .filter_map(|author| {
            dag.feed(&author).map(|feed| FeedFrontier {
                author_id: author,
                max_seq: feed.max_seq(),
                head_hash: feed.head_hash(),
            })
        })
        .collect()
}

/// Given the *remote* peer's `HAVE` frontiers and the local [`Dag`], compute the
/// `WANT` ranges the local peer needs:
/// - for every remote feed whose `max_seq` **exceeds** what we hold, request
///   `(local_max + 1 ..= remote_max)` (the ordinary tail-extension case);
/// - **and** — the equal-length fork case — when the remote's `max_seq` **equals**
///   our `max_seq` but its `head_hash` **differs** from ours, request the head
///   `(max_seq ..= max_seq)`. Two partitions each holding `(author, seq = N)` with
///   different valid hashes would otherwise never exchange the conflicting entry
///   and no fork proof would form (ADR-008 §"Fork / equivocation handling"). The
///   pulled conflicting entry is fed into DAG fork handling, which freezes the
///   author on an attributable proof and raises an alarm on a deniable one.
#[must_use]
pub fn wants_for(dag: &Dag, remote: &[FeedFrontier]) -> Vec<WantRange> {
    let mut wants = Vec::new();
    for rf in remote {
        let local = dag.feed(&rf.author_id);
        let local_max = local.map_or(0, |f| f.max_seq());
        if rf.max_seq > local_max {
            wants.push(WantRange {
                author_id: rf.author_id,
                from_seq: local_max + 1,
                to_seq: rf.max_seq,
            });
        } else if rf.max_seq == local_max && local_max > 0 {
            // Equal head seq: compare the gossiped head hashes. A mismatch is a
            // divergence (equal-length fork) — pull the remote head entry so the
            // conflict reaches DAG fork handling.
            let local_head = local.map_or(crate::log::entry::ZERO_HASH, |f| f.head_hash());
            if local_head != rf.head_hash {
                wants.push(WantRange {
                    author_id: rf.author_id,
                    from_seq: local_max,
                    to_seq: local_max,
                });
            }
        }
    }
    wants
}

/// Collect the `ENTRY` wire frames satisfying a peer's `WANT` ranges from the
/// local [`Dag`]. Entries the local peer does not hold are simply omitted.
#[must_use]
pub fn entries_for_wants(dag: &Dag, wants: &[WantRange]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for w in wants {
        if let Some(feed) = dag.feed(&w.author_id) {
            for seq in w.from_seq..=w.to_seq {
                if let Some(entry) = feed.get(seq) {
                    out.push(entry.to_wire());
                }
            }
        }
    }
    out
}

/// Map a parse/verify [`Error`] to the M0 wire application-error code (ADR-008
/// §"Abort / error signalling"). This is the single place the structured error
/// taxonomy is collapsed onto the coded wire contract, so an unknown struct
/// tag / unsupported version / unknown algo is **never** misreported as a generic
/// authenticator failure.
#[must_use]
pub fn wire_error_for(err: &Error) -> WireError {
    match err {
        Error::UnknownStructTag(_) => WireError::UnknownStructTag,
        Error::UnsupportedVersion { .. } => WireError::ProtocolVersionUnsupported,
        Error::UnknownAlgoId(_) | Error::UnexpectedAlgo { .. } => WireError::UnknownAlgoId,
        Error::SuiteBelowFloor { .. } => WireError::SuiteBelowFloor,
        // Signature/authenticator failures, malformed structures, the deniable
        // boundary, and oversize/CBOR malformation are all "this authenticator/
        // structure is not acceptable" → AuthenticatorInvalid. (Size limits are a
        // structural rejection; there is no dedicated size code in the M0 table.)
        _ => WireError::AuthenticatorInvalid,
    }
}

/// Map a DAG [`Rejected`] to the M0 wire application-error code.
#[must_use]
pub fn wire_error_for_rejected(rej: &Rejected) -> WireError {
    match rej {
        Rejected::NotAdmitted => WireError::EpochMismatch,
        Rejected::Quota(_) => WireError::QuotaExceeded,
        Rejected::Verification(e) => wire_error_for(e),
        Rejected::Feed(_) => WireError::AuthenticatorInvalid,
        Rejected::Fork(_) => WireError::AuthenticatorInvalid,
        Rejected::GovernanceNotAttributable => WireError::AuthenticatorInvalid,
        // A duplicate is not a hard fail; callers handle it before mapping. If it
        // ever reaches here, treat as a benign authenticator-class rejection.
        Rejected::Duplicate => WireError::AuthenticatorInvalid,
    }
}

/// The outcome of applying a received `ENTRY` frame.
#[derive(Debug)]
#[non_exhaustive]
pub enum ApplyOutcome {
    /// The entry was newly stored.
    Stored,
    /// The entry was a duplicate (idempotent — already held).
    Duplicate,
    /// The entry conflicted with a stored one at the same `(author, seq)`: a fork.
    /// This is a *local security event*, NOT a wire-protocol violation — it is
    /// recorded/surfaced (an attributable fork freezes the author; a deniable one
    /// raises an alarm) and sync **continues**. The stream is not closed for a
    /// fork (ADR-008 §"Fork / equivocation handling").
    Fork,
}

/// Apply a received `ENTRY` wire frame to the local [`Dag`] under the full
/// acceptance predicate.
///
/// Returns [`ApplyOutcome`] for the non-fatal cases (stored / duplicate / fork)
/// and `Err(WireError)` only for a *hard wire fail* that must close the stream —
/// mapped to the exact M0 code via [`wire_error_for`] / [`wire_error_for_rejected`]
/// (unknown tag, unsupported version, unknown algo, authenticator, quota, …). A
/// **fork is not a wire fail**: it is surfaced and sync continues, so two
/// partitions can exchange conflicting heads and form the proof.
pub fn apply_entry<R: AuthorResolver>(
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    entry_wire: &[u8],
    now_secs: u64,
) -> std::result::Result<ApplyOutcome, WireError> {
    let entry = Entry::from_wire(entry_wire).map_err(|e| wire_error_for(&e))?;
    let key = resolver
        .key_for(&entry.skeleton.author_id)
        .ok_or(WireError::AuthenticatorInvalid)?;
    let kind = resolver.kind_for(&entry);
    match dag.accept(entry, kind, &key, admission, now_secs) {
        Ok(_) => Ok(ApplyOutcome::Stored),
        Err(Rejected::Duplicate) => Ok(ApplyOutcome::Duplicate),
        // A fork is recorded by `accept` (freeze / proof) and surfaced; it does
        // not close the stream.
        Err(Rejected::Fork(_)) => Ok(ApplyOutcome::Fork),
        Err(other) => Err(wire_error_for_rejected(&other)),
    }
}

/// Drive a complete **frontier-mode** session between two peers, each over its
/// own [`Transport`] endpoint, to convergence — exercising the real frame path
/// (`HELLO`/`HAVE`/`WANT`/`ENTRY`) over the abstract transport. `a` is the
/// initiator. `pump` moves frames between the two endpoints (for the in-memory
/// duplex it is [`DuplexTransport::pump`]; over QUIC the network is the pump).
/// Returns `(applied_into_a, applied_into_b)`.
///
/// Protocol per side: send `HELLO` (offering frontier); both compute and send
/// `HAVE`; each replies `WANT` for what it lacks; each streams the requested
/// `ENTRY` frames; each applies the entries it receives under the full acceptance
/// predicate. A malformed/unknown frame or a hard acceptance failure closes the
/// transport with the mapped [`WireError`].
#[allow(clippy::too_many_arguments)]
pub fn frontier_session<TA, TB, R, P>(
    ta: &mut TA,
    tb: &mut TB,
    a: &mut Dag,
    b: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    now_secs: u64,
    pump: P,
) -> std::result::Result<(usize, usize), WireError>
where
    TA: Transport,
    TB: Transport,
    R: AuthorResolver,
    P: FnMut(&mut TA, &mut TB) -> usize,
{
    // Centralized fail-and-close: ANY hard fail closes BOTH endpoints with the
    // exact coded reason (ADR-008 §"Abort / error signalling" — never a silent
    // downgrade, never an unclosed stream).
    match frontier_session_inner(ta, tb, a, b, resolver, admission, now_secs, pump) {
        Ok(counts) => Ok(counts),
        Err(code) => {
            ta.close(code);
            tb.close(code);
            Err(code)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn frontier_session_inner<TA, TB, R, P>(
    ta: &mut TA,
    tb: &mut TB,
    a: &mut Dag,
    b: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    now_secs: u64,
    mut pump: P,
) -> std::result::Result<(usize, usize), WireError>
where
    TA: Transport,
    TB: Transport,
    R: AuthorResolver,
    P: FnMut(&mut TA, &mut TB) -> usize,
{
    let send_a = |t: &mut TA, f: Vec<u8>| {
        t.send(&f)
            .map_err(|_| WireError::ProtocolVersionUnsupported)
    };
    let send_b = |t: &mut TB, f: Vec<u8>| {
        t.send(&f)
            .map_err(|_| WireError::ProtocolVersionUnsupported)
    };

    // 1. HELLO exchange + mode negotiation.
    send_a(ta, encode_hello(SYNC_MODE_FRONTIER))?;
    send_b(tb, encode_hello(SYNC_MODE_FRONTIER))?;
    pump(ta, tb);
    let a_remote_hello = expect_hello(ta.recv())?;
    let b_remote_hello = expect_hello(tb.recv())?;
    negotiate_mode(SYNC_MODE_FRONTIER, a_remote_hello)?;
    negotiate_mode(SYNC_MODE_FRONTIER, b_remote_hello)?;

    // 2. HAVE exchange.
    send_a(ta, encode_have(&frontiers_of(a)))?;
    send_b(tb, encode_have(&frontiers_of(b)))?;
    pump(ta, tb);
    let a_sees = expect_have(ta.recv())?; // b's frontiers, seen by a
    let b_sees = expect_have(tb.recv())?; // a's frontiers, seen by b

    // 3. WANT exchange (each asks for what it lacks, including equal-seq forks).
    let a_wants = wants_for(a, &a_sees);
    let b_wants = wants_for(b, &b_sees);
    send_a(ta, encode_want(&a_wants))?;
    send_b(tb, encode_want(&b_wants))?;
    pump(ta, tb);
    let a_got_want = expect_want(ta.recv())?; // what b wants from a
    let b_got_want = expect_want(tb.recv())?; // what a wants from b

    // 4. ENTRY streaming (each serves the other's WANT).
    for wire in entries_for_wants(a, &a_got_want) {
        send_a(ta, encode_entry(&wire))?;
    }
    for wire in entries_for_wants(b, &b_got_want) {
        send_b(tb, encode_entry(&wire))?;
    }
    pump(ta, tb);

    // 5. Apply received entries. A fork at an equal-seq divergent head surfaces
    //    here as the conflicting entry is fed into DAG fork handling; an
    //    attributable fork freezes the equivocator (its WireError is the coded
    //    close). Both peers drain independently.
    let into_a = drain_entries(ta, a, resolver, admission, now_secs)?;
    let into_b = drain_entries(tb, b, resolver, admission, now_secs)?;
    Ok((into_a, into_b))
}

/// Read and apply every queued `ENTRY` frame on `t` into `dag`. A hard fail
/// returns the mapped [`WireError`]; the caller ([`frontier_session`]) performs
/// the coded stream close, so this function does not close itself (one central
/// fail-and-close path). An undecodable frame is a sync-protocol violation
/// (`SyncModeUnsupported`); an `ENTRY` that fails acceptance carries its own code
/// from [`apply_entry`].
fn drain_entries<T: Transport, R: AuthorResolver>(
    t: &mut T,
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    now_secs: u64,
) -> std::result::Result<usize, WireError> {
    let mut applied = 0;
    while let Some(frame) = t
        .recv()
        .map_err(|_| WireError::ProtocolVersionUnsupported)?
    {
        match decode_frame(&frame) {
            Ok(SyncFrame::Entry(wire)) => {
                if matches!(
                    apply_entry(dag, resolver, admission, &wire, now_secs)?,
                    ApplyOutcome::Stored
                ) {
                    applied += 1;
                }
            }
            Ok(_) => {} // ignore non-entry frames in the drain phase
            Err(_) => return Err(WireError::SyncModeUnsupported),
        }
    }
    Ok(applied)
}

fn expect_hello(r: Result<Option<Vec<u8>>>) -> std::result::Result<u8, WireError> {
    match r.map_err(|_| WireError::ProtocolVersionUnsupported)? {
        Some(frame) => match decode_frame(&frame) {
            Ok(SyncFrame::Hello(bitmap)) => Ok(bitmap),
            _ => Err(WireError::SyncModeUnsupported),
        },
        None => Err(WireError::ProtocolVersionUnsupported),
    }
}

fn expect_have(r: Result<Option<Vec<u8>>>) -> std::result::Result<Vec<FeedFrontier>, WireError> {
    match r.map_err(|_| WireError::ProtocolVersionUnsupported)? {
        Some(frame) => match decode_frame(&frame) {
            Ok(SyncFrame::Have(v)) => Ok(v),
            _ => Err(WireError::SyncModeUnsupported),
        },
        None => Err(WireError::ProtocolVersionUnsupported),
    }
}

fn expect_want(r: Result<Option<Vec<u8>>>) -> std::result::Result<Vec<WantRange>, WireError> {
    match r.map_err(|_| WireError::ProtocolVersionUnsupported)? {
        Some(frame) => match decode_frame(&frame) {
            Ok(SyncFrame::Want(v)) => Ok(v),
            _ => Err(WireError::SyncModeUnsupported),
        },
        None => Err(WireError::ProtocolVersionUnsupported),
    }
}

// ---------------------------------------------------------------------------
// Range-reconciliation (Negentropy) mode.
// ---------------------------------------------------------------------------

/// Drive a complete **Negentropy range-reconciliation** session between two
/// in-memory DAGs to convergence, applying the entries each side learns it needs.
/// `a` is the Negentropy initiator. Returns `(applied_into_a, applied_into_b)`.
///
/// The Negentropy engine resolves which entry *hashes* differ; the hashes drive
/// `ENTRY` exchange via the content-addressed DAG index. Acceptance is the same
/// predicate as frontier mode.
pub fn range_reconcile_exchange<R: AuthorResolver>(
    a: &mut Dag,
    b: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    now_secs: u64,
) -> std::result::Result<(usize, usize), WireError> {
    let _mode = negotiate_mode(
        SYNC_MODE_FRONTIER | SYNC_MODE_RANGE_RECONCILIATION,
        SYNC_MODE_FRONTIER | SYNC_MODE_RANGE_RECONCILIATION,
    )?;

    let a_items = negentropy::items_from_ids(&hashes_of(a));
    let b_items = negentropy::items_from_ids(&hashes_of(b));

    // a initiates; messages bounce until a's response is empty. a collects the
    // have/need diff (have = a-only hashes, need = b-only hashes).
    let mut msg = negentropy::reconcile_initiate(&a_items);
    let mut a_need = Vec::new();
    let mut a_have = Vec::new();
    let mut rounds = 0;
    loop {
        rounds += 1;
        if rounds > 64 {
            return Err(WireError::SyncModeUnsupported);
        }
        // Carry NEG over the wire frame to exercise the codec.
        let neg_wire = encode_neg(&negentropy::encode_message(&msg));
        let b_msg = decode_neg_frame(&neg_wire)?;
        let b_res = negentropy::reconcile(Role::Responder, &b_items, &b_msg);
        if b_res.response.is_empty() {
            break;
        }
        let resp_wire = encode_neg(&negentropy::encode_message(&b_res.response));
        let a_msg = decode_neg_frame(&resp_wire)?;
        let a_res = negentropy::reconcile(Role::Initiator, &a_items, &a_msg);
        a_have.extend(a_res.have);
        a_need.extend(a_res.need);
        if a_res.response.is_empty() {
            break;
        }
        msg = a_res.response;
    }

    // Apply: a pulls its `need` from b; b pulls its `need` (= a's `have`) from a.
    let applied_into_a = apply_hashes(a, b, resolver, admission, &a_need, now_secs)?;
    let applied_into_b = apply_hashes(b, a, resolver, admission, &a_have, now_secs)?;
    Ok((applied_into_a, applied_into_b))
}

/// All entry hashes in a DAG, in causal order (deterministic).
fn hashes_of(dag: &Dag) -> Vec<Digest32> {
    dag.causal_order()
}

/// Decode a `NEG` frame into a Negentropy message.
fn decode_neg_frame(frame: &[u8]) -> std::result::Result<negentropy::Message, WireError> {
    match decode_frame(frame) {
        Ok(SyncFrame::Neg(bytes)) => {
            negentropy::decode_message(&bytes).map_err(|_| WireError::SyncModeUnsupported)
        }
        _ => Err(WireError::SyncModeUnsupported),
    }
}

/// Apply, into `dst`, the entries at `hashes` fetched from `src` (content-address
/// lookup), under the full acceptance predicate. Entries `src` does not hold are
/// skipped. Entries are applied in seq order per author so feed links resolve.
fn apply_hashes<R: AuthorResolver>(
    dst: &mut Dag,
    src: &Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    hashes: &[Digest32],
    now_secs: u64,
) -> std::result::Result<usize, WireError> {
    // Gather the source entries, then order by (author, seq) so prev/lipmaa links
    // are satisfiable as they are appended.
    let mut wires: Vec<(Digest32, u64, Vec<u8>)> = hashes
        .iter()
        .filter_map(|h| {
            src.get_by_hash(h)
                .map(|e| (e.skeleton.author_id, e.skeleton.seq, e.to_wire()))
        })
        .collect();
    wires.sort_by(|x, y| x.0.cmp(&y.0).then(x.1.cmp(&y.1)));
    let mut applied = 0;
    for (_, _, wire) in wires {
        if matches!(
            apply_entry(dst, resolver, admission, &wire, now_secs)?,
            ApplyOutcome::Stored
        ) {
            applied += 1;
        }
    }
    Ok(applied)
}

const _: () = assert!(DIGEST_LEN == 32);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;
    use crate::identity::composite::{RootSigner, SoftwareRootSigner};
    use crate::log::entry::{EntrySkeleton, ZERO_HASH};
    use crate::log::feed::{lipmaa, Feed};
    use crate::suite::algo;

    const CHANNEL: Digest32 = [0xD0; 32];
    const EPOCH: u64 = 1;

    fn root(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    /// A resolver backed by a fixed set of author keys.
    struct MapResolver {
        keys: Vec<(Digest32, CompositePublicKey)>,
    }
    impl AuthorResolver for MapResolver {
        fn key_for(&self, author: &Digest32) -> Option<CompositePublicKey> {
            self.keys
                .iter()
                .find(|(a, _)| a == author)
                .map(|(_, k)| k.clone())
        }
    }

    fn next_entry(dag: &Dag, r: &SoftwareRootSigner, payload: &[u8]) -> Entry {
        let author = r.fingerprint();
        let feed = dag.feed(&author);
        let max = feed.map_or(0, Feed::max_seq);
        let seq = max + 1;
        let prev_hash = if seq == 1 {
            ZERO_HASH
        } else {
            feed.unwrap().get(seq - 1).unwrap().entry_hash()
        };
        let lipmaa_backlink = if seq == 1 {
            ZERO_HASH
        } else {
            feed.unwrap().get(lipmaa(seq)).unwrap().entry_hash()
        };
        let sk = EntrySkeleton {
            author_id: author,
            seq,
            prev_hash,
            lipmaa_backlink,
            channel_id: CHANNEL,
            epoch: EPOCH,
            algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
            payload_hash: sha256(payload),
            payload_len: payload.len() as u64,
            end_of_feed: false,
        };
        Entry::build_signed(r, sk, payload.to_vec()).unwrap()
    }

    fn admit_all(rs: &[&SoftwareRootSigner]) -> AdmissionPolicy {
        let mut a = AdmissionPolicy::new();
        for r in rs {
            a.admit(CHANNEL, EPOCH, r.fingerprint());
        }
        a
    }

    fn fill(dag: &mut Dag, r: &SoftwareRootSigner, n: usize, adm: &AdmissionPolicy) {
        for i in 0..n {
            let p = format!("e{i}");
            let e = next_entry(dag, r, p.as_bytes());
            dag.accept(e, EntryKind::Content, &r.public_key(), adm, 0)
                .unwrap();
        }
    }

    // ---- frames ----

    #[test]
    fn frame_round_trips() {
        let hello = encode_hello(SYNC_MODE_FRONTIER | SYNC_MODE_RANGE_RECONCILIATION);
        assert_eq!(decode_frame(&hello).unwrap(), SyncFrame::Hello(0b11));

        let fr = vec![FeedFrontier {
            author_id: [1; 32],
            max_seq: 7,
            head_hash: [2; 32],
        }];
        assert_eq!(
            decode_frame(&encode_have(&fr)).unwrap(),
            SyncFrame::Have(fr)
        );

        let wr = vec![WantRange {
            author_id: [3; 32],
            from_seq: 1,
            to_seq: 9,
        }];
        assert_eq!(
            decode_frame(&encode_want(&wr)).unwrap(),
            SyncFrame::Want(wr)
        );

        let ew = vec![0xAA, 0xBB];
        assert_eq!(
            decode_frame(&encode_entry(&ew)).unwrap(),
            SyncFrame::Entry(ew)
        );

        let nw = vec![0x61, 0x00];
        assert_eq!(decode_frame(&encode_neg(&nw)).unwrap(), SyncFrame::Neg(nw));
    }

    #[test]
    fn decode_rejects_unknown_frame_id() {
        assert!(decode_frame(&[0x09, 0x00]).is_err());
        assert!(decode_frame(&[]).is_err());
    }

    #[test]
    fn decode_rejects_oversized_entry_and_neg_frames_without_large_alloc() {
        use crate::error::Error;
        // ENTRY frame whose inner byte string DECLARES a huge length but carries
        // no data: rejected before any large allocation. The codec's
        // length-vs-remaining bound (Error::Cbor) fires for the declared-huge
        // case; the explicit MAX_ENTRY_WIRE check covers an actually-oversized
        // body. Either way: no large copy.
        let mut entry_frame = vec![FrameId::Entry.as_u8()];
        // CBOR byte string, 8-byte length (0x5B) claiming u64 ~ huge, no bytes.
        entry_frame.push(0x5B);
        entry_frame.extend_from_slice(&(u64::MAX).to_be_bytes());
        assert!(matches!(
            decode_frame(&entry_frame),
            Err(Error::SizeLimitExceeded("sync ENTRY frame")) | Err(Error::Cbor(_))
        ));

        // NEG frame, same construction.
        let mut neg_frame = vec![FrameId::Neg.as_u8()];
        neg_frame.push(0x5B);
        neg_frame.extend_from_slice(&(u64::MAX).to_be_bytes());
        assert!(matches!(
            decode_frame(&neg_frame),
            Err(Error::SizeLimitExceeded("sync NEG frame")) | Err(Error::Cbor(_))
        ));
    }

    #[test]
    fn mode_negotiation() {
        // Both frontier-only -> frontier.
        assert_eq!(
            negotiate_mode(SYNC_MODE_FRONTIER, SYNC_MODE_FRONTIER).unwrap(),
            SYNC_MODE_FRONTIER
        );
        // Both support range -> range (the higher bit).
        assert_eq!(
            negotiate_mode(0b11, 0b11).unwrap(),
            SYNC_MODE_RANGE_RECONCILIATION
        );
        // One supports range, the other only frontier -> frontier.
        assert_eq!(negotiate_mode(0b11, 0b01).unwrap(), SYNC_MODE_FRONTIER);
        // No common bit -> hard fail with the coded reason.
        assert_eq!(
            negotiate_mode(0b10, 0b00),
            Err(WireError::SyncModeUnsupported)
        );
    }

    // ---- duplex transport ----

    #[test]
    fn duplex_transport_carries_frames_and_close_code() {
        let (mut a, mut b) = DuplexTransport::pair();
        a.send(&encode_hello(SYNC_MODE_FRONTIER)).unwrap();
        DuplexTransport::pump(&mut a, &mut b);
        let f = b.recv().unwrap().unwrap();
        assert_eq!(
            decode_frame(&f).unwrap(),
            SyncFrame::Hello(SYNC_MODE_FRONTIER)
        );
        b.close(WireError::QuotaExceeded);
        assert_eq!(b.close_code(), Some(WireError::QuotaExceeded));
        assert!(b.send(&[0x00]).is_err());
    }

    /// Run one frontier session over a fresh in-memory duplex pair.
    fn run_frontier(
        a: &mut Dag,
        b: &mut Dag,
        resolver: &MapResolver,
        adm: &AdmissionPolicy,
    ) -> (usize, usize) {
        let (mut ta, mut tb) = DuplexTransport::pair();
        frontier_session(
            &mut ta,
            &mut tb,
            a,
            b,
            resolver,
            adm,
            0,
            DuplexTransport::pump,
        )
        .unwrap()
    }

    // ---- frontier reconciliation ----

    #[test]
    fn frontier_reconciles_two_divergent_peers() {
        let ra = root(1, 2);
        let rb = root(3, 4);
        let adm = admit_all(&[&ra, &rb]);
        let resolver = MapResolver {
            keys: vec![
                (ra.fingerprint(), ra.public_key()),
                (rb.fingerprint(), rb.public_key()),
            ],
        };

        // Peer A holds A's feed (5); peer B holds B's feed (4).
        let mut a = Dag::new();
        let mut b = Dag::new();
        fill(&mut a, &ra, 5, &adm);
        fill(&mut b, &rb, 4, &adm);

        // One session over the duplex transport: A pulls B's 4, B pulls A's 5.
        let (into_a, into_b) = run_frontier(&mut a, &mut b, &resolver, &adm);
        assert_eq!(into_a, 4);
        assert_eq!(into_b, 5);

        // Both now hold identical logs.
        assert_eq!(a.causal_order(), b.causal_order());
        assert_eq!(a.len(), 9);
        assert_eq!(b.len(), 9);
    }

    #[test]
    fn frontier_is_idempotent_when_already_synced() {
        let ra = root(5, 5);
        let adm = admit_all(&[&ra]);
        let resolver = MapResolver {
            keys: vec![(ra.fingerprint(), ra.public_key())],
        };
        let mut a = Dag::new();
        let mut b = Dag::new();
        fill(&mut a, &ra, 6, &adm);
        // First session copies a -> b.
        run_frontier(&mut a, &mut b, &resolver, &adm);
        // Second session transfers nothing.
        let (into_a, into_b) = run_frontier(&mut a, &mut b, &resolver, &adm);
        assert_eq!((into_a, into_b), (0, 0));
        assert_eq!(a.causal_order(), b.causal_order());
    }

    // ---- range reconciliation (Negentropy) ----

    #[test]
    fn range_reconcile_reconciles_two_divergent_peers() {
        let ra = root(1, 9);
        let rb = root(2, 8);
        let adm = admit_all(&[&ra, &rb]);
        let resolver = MapResolver {
            keys: vec![
                (ra.fingerprint(), ra.public_key()),
                (rb.fingerprint(), rb.public_key()),
            ],
        };
        let mut a = Dag::new();
        let mut b = Dag::new();
        fill(&mut a, &ra, 7, &adm);
        fill(&mut b, &rb, 9, &adm);

        let (into_a, into_b) =
            range_reconcile_exchange(&mut a, &mut b, &resolver, &adm, 0).unwrap();
        assert_eq!(into_a, 9); // a learns b's 9
        assert_eq!(into_b, 7); // b learns a's 7
        assert_eq!(a.causal_order(), b.causal_order());
        assert_eq!(a.len(), 16);
        assert_eq!(b.len(), 16);
    }

    #[test]
    fn both_modes_reach_identical_state() {
        // Same starting divergence reconciled by each mode yields the same result.
        let ra = root(7, 1);
        let rb = root(8, 2);
        let adm = admit_all(&[&ra, &rb]);
        let resolver = MapResolver {
            keys: vec![
                (ra.fingerprint(), ra.public_key()),
                (rb.fingerprint(), rb.public_key()),
            ],
        };

        let mut a1 = Dag::new();
        let mut b1 = Dag::new();
        fill(&mut a1, &ra, 4, &adm);
        fill(&mut b1, &rb, 6, &adm);
        run_frontier(&mut a1, &mut b1, &resolver, &adm);

        let mut a2 = Dag::new();
        let mut b2 = Dag::new();
        fill(&mut a2, &ra, 4, &adm);
        fill(&mut b2, &rb, 6, &adm);
        range_reconcile_exchange(&mut a2, &mut b2, &resolver, &adm, 0).unwrap();

        assert_eq!(a1.causal_order(), a2.causal_order());
        assert_eq!(b1.causal_order(), b2.causal_order());
        assert_eq!(a1.causal_order(), b2.causal_order());
    }

    // ---- hard-fail wire errors ----

    #[test]
    fn apply_entry_rejects_unknown_author_with_wire_error() {
        let ra = root(1, 1);
        let adm = admit_all(&[&ra]);
        // Resolver knows nobody.
        let resolver = MapResolver { keys: vec![] };
        let mut dag = Dag::new();
        let scratch = Dag::new();
        let e = next_entry(&scratch, &ra, b"x");
        let err = apply_entry(&mut dag, &resolver, &adm, &e.to_wire(), 0).unwrap_err();
        assert_eq!(err, WireError::AuthenticatorInvalid);
    }

    #[test]
    fn apply_entry_maps_quota_breach_to_wire_error() {
        let ra = root(2, 2);
        let adm = admit_all(&[&ra]);
        let resolver = MapResolver {
            keys: vec![(ra.fingerprint(), ra.public_key())],
        };
        let policy = crate::log::quota::QuotaPolicy {
            max_entries_per_hour: 1,
            max_bytes_per_epoch: u64::MAX,
        };
        let mut dag = Dag::with_quota(crate::log::quota::QuotaTracker::new(policy));
        let scratch = Dag::new();
        let e1 = next_entry(&scratch, &ra, b"a");
        // Build e2 against a scratch that has e1, so it links at seq 2.
        let mut scratch2 = Dag::new();
        scratch2
            .accept(e1.clone(), EntryKind::Content, &ra.public_key(), &adm, 0)
            .unwrap();
        let e2 = next_entry(&scratch2, &ra, b"b");

        apply_entry(&mut dag, &resolver, &adm, &e1.to_wire(), 100).unwrap();
        let err = apply_entry(&mut dag, &resolver, &adm, &e2.to_wire(), 100).unwrap_err();
        assert_eq!(err, WireError::QuotaExceeded);
    }

    #[test]
    fn apply_entry_rejects_tampered_wire() {
        let ra = root(3, 3);
        let adm = admit_all(&[&ra]);
        let resolver = MapResolver {
            keys: vec![(ra.fingerprint(), ra.public_key())],
        };
        let mut dag = Dag::new();
        let scratch = Dag::new();
        let e = next_entry(&scratch, &ra, b"orig");
        let mut wire = e.to_wire();
        *wire.last_mut().unwrap() ^= 0xff; // corrupt payload byte
        let err = apply_entry(&mut dag, &resolver, &adm, &wire, 0).unwrap_err();
        assert_eq!(err, WireError::AuthenticatorInvalid);
    }

    // ---- HIGH-3: exact M0 WireError mapping per error class ----

    #[test]
    fn wire_error_mapping_is_per_class() {
        use crate::error::Error;
        // Unknown struct tag → 0x03, not collapsed to authenticator-invalid.
        assert_eq!(
            wire_error_for(&Error::UnknownStructTag(0x9999)),
            WireError::UnknownStructTag
        );
        // Unsupported version → 0x01.
        assert_eq!(
            wire_error_for(&Error::UnsupportedVersion { tag: 1, version: 9 }),
            WireError::ProtocolVersionUnsupported
        );
        // Unknown / unexpected algo → 0x04.
        assert_eq!(
            wire_error_for(&Error::UnknownAlgoId(0x09ff)),
            WireError::UnknownAlgoId
        );
        assert_eq!(
            wire_error_for(&Error::UnexpectedAlgo {
                got: 1,
                expected: 2
            }),
            WireError::UnknownAlgoId
        );
        // Suite below floor → 0x02.
        assert_eq!(
            wire_error_for(&Error::SuiteBelowFloor {
                observed: 1,
                floor: 2
            }),
            WireError::SuiteBelowFloor
        );
        // Signature failure → 0x05.
        assert_eq!(
            wire_error_for(&Error::SignatureInvalid),
            WireError::AuthenticatorInvalid
        );
    }

    #[test]
    fn apply_entry_maps_unknown_struct_tag() {
        let ra = root(4, 5);
        let adm = admit_all(&[&ra]);
        let resolver = MapResolver {
            keys: vec![(ra.fingerprint(), ra.public_key())],
        };
        let mut dag = Dag::new();
        let scratch = Dag::new();
        let e = next_entry(&scratch, &ra, b"x");
        // Re-frame the entry body under an unknown struct tag (0x9999).
        let mut wire = e.to_wire();
        wire[0] = 0x99;
        wire[1] = 0x99;
        let err = apply_entry(&mut dag, &resolver, &adm, &wire, 0).unwrap_err();
        assert_eq!(err, WireError::UnknownStructTag);
    }

    #[test]
    fn apply_entry_maps_unsupported_version() {
        let ra = root(6, 7);
        let adm = admit_all(&[&ra]);
        let resolver = MapResolver {
            keys: vec![(ra.fingerprint(), ra.public_key())],
        };
        let mut dag = Dag::new();
        let scratch = Dag::new();
        let e = next_entry(&scratch, &ra, b"x");
        let mut wire = e.to_wire();
        wire[2] = 0xFF; // bad version byte
        let err = apply_entry(&mut dag, &resolver, &adm, &wire, 0).unwrap_err();
        assert_eq!(err, WireError::ProtocolVersionUnsupported);
    }

    #[test]
    fn apply_entry_admission_failure_maps_to_epoch_mismatch() {
        let ra = root(8, 9);
        // Author known to the resolver but NOT admitted.
        let adm = AdmissionPolicy::new();
        let resolver = MapResolver {
            keys: vec![(ra.fingerprint(), ra.public_key())],
        };
        let mut dag = Dag::new();
        let scratch = Dag::new();
        let e = next_entry(&scratch, &ra, b"x");
        let err = apply_entry(&mut dag, &resolver, &adm, &e.to_wire(), 0).unwrap_err();
        assert_eq!(err, WireError::EpochMismatch);
    }

    // ---- HIGH-2: equal-seq fork is detected and exchanged via frontier sync ----

    #[test]
    fn frontier_detects_equal_seq_divergent_head_fork() {
        // Two partitions each hold (author, seq=1) with DIFFERENT valid entries.
        // Their max_seq is equal, but head_hash differs — wants_for must request
        // the conflicting head so DAG fork handling forms the attributable proof.
        let ra = root(1, 2);
        let adm = admit_all(&[&ra]);
        let resolver = MapResolver {
            keys: vec![(ra.fingerprint(), ra.public_key())],
        };
        let mut a = Dag::new();
        let mut b = Dag::new();
        // a holds one entry at seq 1; b holds a DIFFERENT entry at seq 1.
        let ea = next_entry(&a, &ra, b"partition-A-head");
        a.accept(ea, EntryKind::Content, &ra.public_key(), &adm, 0)
            .unwrap();
        let eb = next_entry(&b, &ra, b"partition-B-head");
        b.accept(eb, EntryKind::Content, &ra.public_key(), &adm, 0)
            .unwrap();

        // Sanity: equal max_seq, different heads.
        assert_eq!(a.feed(&ra.fingerprint()).unwrap().max_seq(), 1);
        assert_eq!(b.feed(&ra.fingerprint()).unwrap().max_seq(), 1);
        assert_ne!(
            a.feed(&ra.fingerprint()).unwrap().head_hash(),
            b.feed(&ra.fingerprint()).unwrap().head_hash()
        );

        // A frontier session: each requests the other's head (equal-seq divergence)
        // and feeds the conflicting entry into fork handling. The session does NOT
        // hard-close on the fork (a fork is a local security event).
        let (mut ta, mut tb) = DuplexTransport::pair();
        let _ = frontier_session(
            &mut ta,
            &mut tb,
            &mut a,
            &mut b,
            &resolver,
            &adm,
            0,
            DuplexTransport::pump,
        )
        .unwrap();

        // Both peers now have a recorded attributable fork proof and froze the
        // equivocating author.
        assert!(a.is_frozen(&ra.fingerprint()), "A should detect the fork");
        assert!(b.is_frozen(&ra.fingerprint()), "B should detect the fork");
        assert!(a.fork_proof(&ra.fingerprint()).is_some());
        assert!(b.fork_proof(&ra.fingerprint()).is_some());
        // Transports were not closed (fork is not a wire-protocol fail).
        assert_eq!(ta.close_code(), None);
        assert_eq!(tb.close_code(), None);
    }

    #[test]
    fn frontier_closes_both_endpoints_on_hard_fail() {
        // An unknown-author ENTRY is a hard fail; the session must close BOTH
        // endpoints with the coded reason (centralized fail-and-close).
        let ra = root(2, 3);
        let rb = root(4, 5);
        let adm = admit_all(&[&ra, &rb]);
        // Resolver knows ra but NOT rb, so rb's entries fail at apply.
        let resolver = MapResolver {
            keys: vec![(ra.fingerprint(), ra.public_key())],
        };
        let mut a = Dag::new();
        let mut b = Dag::new();
        fill(&mut a, &ra, 2, &adm);
        // b holds rb's feed, which a cannot verify (unknown author).
        fill(&mut b, &rb, 2, &adm);

        let (mut ta, mut tb) = DuplexTransport::pair();
        let res = frontier_session(
            &mut ta,
            &mut tb,
            &mut a,
            &mut b,
            &resolver,
            &adm,
            0,
            DuplexTransport::pump,
        );
        assert_eq!(res, Err(WireError::AuthenticatorInvalid));
        // Both endpoints closed with the coded reason.
        assert_eq!(ta.close_code(), Some(WireError::AuthenticatorInvalid));
        assert_eq!(tb.close_code(), Some(WireError::AuthenticatorInvalid));
    }
}
