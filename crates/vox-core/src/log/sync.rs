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
//! ([`crate::log::dag::Dag::accept`]): admission, authenticator, feed link, and
//! fork handling. A peer never trusts an entry merely because it arrived over
//! sync.
//!
//! ## Serving is bounded by what is held, never by what is asked
//! A `WANT` is the peer's to write, so nothing in it is trusted for size: each
//! range is clamped to the entries this node actually holds, overlapping and
//! duplicate ranges are merged so no entry is sent twice, and one session serves
//! at most [`MAX_SERVE_ENTRIES`] entries / [`MAX_SERVE_BYTES`] bytes within
//! [`SERVE_BUDGET`]. That is correctness, not a quota (PRD-001 R4): a session that
//! stops at the bound still sends what it served, the requester applies it, and
//! because it applied something it syncs again at once and asks for the rest. A
//! history of any size therefore still catches up — in as many sessions as it
//! takes — while no single request can hold the room's lock for longer than the
//! bound.

use std::collections::VecDeque;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, DIGEST_LEN};
use crate::identity::composite::CompositePublicKey;
use crate::log::dag::{AdmissionPolicy, Dag, Rejected};
use crate::log::entry::{Entry, EntryKind, MAX_AUTHENTICATOR_LEN, MAX_PAYLOAD_LEN};
use crate::log::negentropy::{self, Role, MAX_MESSAGE_LEN as MAX_NEG_MESSAGE_LEN};
use crate::wire::{FrameId, WireError, SYNC_MODE_FRONTIER, SYNC_MODE_RANGE_RECONCILIATION};

/// The whole drain phase's budget, however many frames arrive.
///
/// Chosen absolutely, not derived from the per-frame timeout. A room's lock is held for the entire
/// session, so this is how long one member may stop every other operation on that room — a bound on
/// what the rest of the node will tolerate, which is a different question from how patient any one
/// frame should be. The two must not be tied: a per-frame bound tightened to abandon a dead peer
/// sooner would otherwise also abandon an honest sync that is merely slow.
///
/// The references bound the total as well as the gap, for this reason: go-libp2p's relay sets a
/// per-stream timeout *and* an absolute `Duration` cap on the whole relayed connection, and Tor
/// reclaims a circuit on total idle. A per-frame bound alone defends only against a peer that
/// stops, never against one that drips.
const DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// The most entries one session serves to a peer's `WANT`.
///
/// The session holds the room's lock throughout, so what one peer may ask for is
/// what every other operation on the room waits behind. This bounds one session,
/// not a catch-up: the requester applies what it got and, because it applied
/// something, syncs again at once for the rest (see the module docs). A thousand
/// entries verify and file in well under the requester's `DRAIN_BUDGET`.
pub const MAX_SERVE_ENTRIES: usize = 1024;

/// The most entry bytes one session serves, for the same reason as
/// [`MAX_SERVE_ENTRIES`]: a single entry may be up to [`MAX_PAYLOAD_LEN`], so a
/// count alone would still let one `WANT` pull gigabytes into memory. At least one
/// entry is always served, so an entry larger than this still gets through.
pub const MAX_SERVE_BYTES: usize = 64 * 1024 * 1024;

/// The serve phase's wall-clock budget. Each frame is bounded by the transport,
/// but a peer that *reads* one frame every nineteen seconds would otherwise keep
/// the room's lock for as long as there are entries to send — the drip that
/// `DRAIN_BUDGET` closes on the other direction. Stopping here is not a failure:
/// what was served is kept, and the requester comes back for the rest.
pub const SERVE_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

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

    /// Cleanly finish the **send** direction: no more frames will be sent, and the
    /// peer's [`Transport::recv`] should observe end-of-stream (`Ok(None)`) once it
    /// has drained the frames already sent. This is the *success* terminator,
    /// distinct from the hard-fail [`Transport::close`].
    ///
    /// The default is a no-op: the in-memory [`DuplexTransport`] signals
    /// end-of-stream implicitly (an empty inbox reads as `Ok(None)`), so it needs
    /// nothing here. A real ordered byte transport (the QUIC mapping, M9) overrides
    /// this to FIN its send stream so the peer's blocking read terminates.
    fn finish(&mut self) {}
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
/// local [`Dag`], in per-author seq order, up to [`MAX_SERVE_ENTRIES`] /
/// [`MAX_SERVE_BYTES`].
///
/// **The work is bounded by what this node holds, never by the ranges' numbers.**
/// This used to loop `from_seq..=to_seq` doing one lookup per number, collecting
/// into memory with the room's lock held, so a single `WANT (author, 1,
/// u64::MAX)` — any member may send one — pinned a core on a loop that would not
/// finish in the life of the machine, and nothing else could touch that room
/// again (PRD-001 D2). Now each author's ranges are merged, so duplicates and
/// overlaps cost nothing and serve nothing twice, and each merged range walks
/// only the entries the feed actually has. Entries not held are simply omitted.
#[must_use]
pub fn entries_for_wants(dag: &Dag, wants: &[WantRange]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for (author, ranges) in merged_wants(wants) {
        let Some(feed) = dag.feed(&author) else {
            continue;
        };
        for (from, to) in ranges {
            for entry in feed.range(from, to) {
                let wire = entry.to_wire();
                if !out.is_empty()
                    && (out.len() >= MAX_SERVE_ENTRIES
                        || bytes.saturating_add(wire.len()) > MAX_SERVE_BYTES)
                {
                    return out;
                }
                bytes = bytes.saturating_add(wire.len());
                out.push(wire);
            }
        }
    }
    out
}

/// A `WANT`'s ranges grouped by author (in author order) with each author's
/// ranges sorted and merged, so the ranges are disjoint and ascending. Inverted
/// ranges are dropped. The cost is `O(n log n)` in the number of ranges, which
/// the frame size already bounds.
fn merged_wants(wants: &[WantRange]) -> std::collections::BTreeMap<Digest32, Vec<(u64, u64)>> {
    let mut by_author: std::collections::BTreeMap<Digest32, Vec<(u64, u64)>> =
        std::collections::BTreeMap::new();
    for w in wants.iter().filter(|w| w.from_seq <= w.to_seq) {
        by_author
            .entry(w.author_id)
            .or_default()
            .push((w.from_seq, w.to_seq));
    }
    for ranges in by_author.values_mut() {
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for &(from, to) in ranges.iter() {
            match merged.last_mut() {
                Some(last) if from <= last.1.saturating_add(1) => last.1 = last.1.max(to),
                _ => merged.push((from, to)),
            }
        }
        *ranges = merged;
    }
    by_author
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
/// (unknown tag, unsupported version, unknown algo, authenticator, …). A
/// **fork is not a wire fail**: it is surfaced and sync continues, so two
/// partitions can exchange conflicting heads and form the proof.
pub fn apply_entry<R: AuthorResolver>(
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    entry_wire: &[u8],
) -> std::result::Result<ApplyOutcome, WireError> {
    let entry = Entry::from_wire(entry_wire).map_err(|e| wire_error_for(&e))?;
    let key = resolver
        .key_for(&entry.skeleton.author_id)
        .ok_or(WireError::AuthenticatorInvalid)?;
    let kind = resolver.kind_for(&entry);
    match dag.accept(entry, kind, &key, admission) {
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
    match frontier_session_inner(ta, tb, a, b, resolver, admission, pump) {
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
    mut pump: P,
) -> std::result::Result<(usize, usize), WireError>
where
    TA: Transport,
    TB: Transport,
    R: AuthorResolver,
    P: FnMut(&mut TA, &mut TB) -> usize,
{
    let send_a = |t: &mut TA, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
    let send_b = |t: &mut TB, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);

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
    let into_a = drain_entries(ta, a, resolver, admission)?;
    let into_b = drain_entries(tb, b, resolver, admission)?;
    Ok((into_a, into_b))
}

/// Drive **one peer's** half of a frontier-mode session over a single
/// [`Transport`] endpoint, to completion. Unlike [`frontier_session`] (which pumps
/// both in-process duplex sides in one thread), this runs a single side over a
/// real bidirectional transport — the QUIC mapping (M9), where the network moves
/// bytes, so no `pump` is needed. Both peers are protocol-symmetric, so the same
/// function serves the initiator and the responder; run one on each peer
/// concurrently and both converge.
///
/// The phases mirror [`frontier_session`]: `HELLO` → `HAVE` → `WANT` → serve the
/// peer's `WANT` with `ENTRY` frames, then drain and apply the peer's `ENTRY`
/// frames. After serving its entries the peer half-closes its send direction
/// ([`Transport::close`] is **not** called on the success path — a clean
/// end-of-stream is signalled by [`Transport::recv`] returning `Ok(None)`), so the
/// drain loop terminates. A hard fail closes the transport with the mapped
/// [`WireError`].
///
/// Returns the number of entries newly applied into `dag`.
pub fn frontier_session_peer<T, R>(
    t: &mut T,
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
) -> std::result::Result<usize, WireError>
where
    T: Transport,
    R: AuthorResolver,
{
    match frontier_session_peer_inner(t, dag, resolver, admission) {
        Ok(applied) => Ok(applied),
        Err(code) => {
            t.close(code);
            Err(code)
        }
    }
}

fn frontier_session_peer_inner<T, R>(
    t: &mut T,
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
) -> std::result::Result<usize, WireError>
where
    T: Transport,
    R: AuthorResolver,
{
    let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);

    // 1. HELLO exchange + mode negotiation.
    send(t, encode_hello(SYNC_MODE_FRONTIER))?;
    let remote_hello = expect_hello(t.recv())?;
    negotiate_mode(SYNC_MODE_FRONTIER, remote_hello)?;

    // 2. HAVE exchange.
    send(t, encode_have(&frontiers_of(dag)))?;
    let remote_have = expect_have(t.recv())?;

    // 3. WANT exchange (ask for what we lack, including equal-seq forks).
    let my_wants = wants_for(dag, &remote_have);
    send(t, encode_want(&my_wants))?;
    let their_wants = expect_want(t.recv())?;

    // 4. Serve their WANT with ENTRY frames, then signal end-of-stream by
    //    half-closing the send side via a benign close. We must NOT use
    //    `Transport::close` here (that is the hard-fail path); a clean FIN is the
    //    success terminator. The QUIC mapping finishes the send stream; the
    //    in-memory duplex relies on the drain loop observing an empty inbox.
    //    Bounded in count, bytes and time (see the module docs); stopping at the
    //    time bound is a clean end, not a failure — the peer keeps what it got.
    let serve_deadline = std::time::Instant::now() + SERVE_BUDGET;
    for wire in entries_for_wants(dag, &their_wants) {
        if std::time::Instant::now() >= serve_deadline {
            break;
        }
        send(t, encode_entry(&wire))?;
    }
    // Signal a clean end-of-stream on our send side (success terminator, not a
    // hard close), so the peer's drain loop terminates at FIN.
    t.finish();

    // 5. Drain and apply the entries the peer serves us, until the peer's clean
    //    half-close (recv → Ok(None)).
    drain_entries(t, dag, resolver, admission)
}

/// What a frontier session may do to a room, **one step at a time**. Each method takes the room's
/// lock, does its step, releases the lock and returns owned data; none of them sees the transport.
/// [`frontier_session_room`] sees the transport and never the room. So no lock can be held across a
/// network wait, and the compiler keeps it that way: there is no scope in which both exist.
///
/// This replaces a session that held the room's mutex from its first frame to its last. A peer that
/// was slow to answer then held the room for up to the frame timeout, and every other use of the
/// room — a message being posted, the node's view being published after every event — waited
/// behind it (ADR-008's own implementation note named the fix).
pub trait SessionRoom {
    /// The room's frontiers, for `HAVE`.
    ///
    /// # Errors
    /// The room is unusable (poisoned, or moved to another epoch).
    fn frontiers(&self) -> std::result::Result<Vec<FeedFrontier>, WireError>;
    /// What to ask the peer for, given its `HAVE`.
    ///
    /// # Errors
    /// As [`SessionRoom::frontiers`].
    fn wants(&self, remote: &[FeedFrontier]) -> std::result::Result<Vec<WantRange>, WireError>;
    /// The entries to serve for the peer's `WANT` — owned and bounded.
    ///
    /// # Errors
    /// As [`SessionRoom::frontiers`].
    fn entries(&self, wants: &[WantRange]) -> std::result::Result<Vec<Vec<u8>>, WireError>;
    /// Apply a batch of received entries under a fresh lock, **against the room's current rules**: an
    /// author revoked while the batch was on the wire is refused, and a room that moved to another
    /// epoch refuses the whole batch. Returns how many were newly stored.
    ///
    /// # Errors
    /// A hard sync failure from an entry, or the room is unusable.
    fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, WireError>;
}

/// How many received entries are staged before a batch is applied. Bounds what a session holds in
/// memory between locks; each batch is one short hold of the room.
pub const MAX_STAGED: usize = 256;

/// One peer's half of a frontier session, over `t`, against `room` — the same protocol as
/// [`frontier_session_peer`], with the room locked only inside each [`SessionRoom`] step and never
/// across a send or a receive.
///
/// # Errors
/// The coded [`WireError`] of a hard fail; the transport is closed with it.
pub fn frontier_session_room<T, S>(t: &mut T, room: &S) -> std::result::Result<usize, WireError>
where
    T: Transport,
    S: SessionRoom + ?Sized,
{
    match frontier_session_room_inner(t, room) {
        Ok(applied) => Ok(applied),
        Err(code) => {
            t.close(code);
            Err(code)
        }
    }
}

fn frontier_session_room_inner<T, S>(t: &mut T, room: &S) -> std::result::Result<usize, WireError>
where
    T: Transport,
    S: SessionRoom + ?Sized,
{
    let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);

    send(t, encode_hello(SYNC_MODE_FRONTIER))?;
    let remote_hello = expect_hello(t.recv())?;
    negotiate_mode(SYNC_MODE_FRONTIER, remote_hello)?;

    send(t, encode_have(&room.frontiers()?))?;
    let remote_have = expect_have(t.recv())?;

    send(t, encode_want(&room.wants(&remote_have)?))?;
    let their_wants = expect_want(t.recv())?;

    let serve_deadline = std::time::Instant::now() + SERVE_BUDGET;
    for wire in room.entries(&their_wants)? {
        if std::time::Instant::now() >= serve_deadline {
            break;
        }
        send(t, encode_entry(&wire))?;
    }
    t.finish();

    // Drained with no lock held; applied a batch at a time under a fresh one.
    let deadline = std::time::Instant::now() + DRAIN_BUDGET;
    let mut staged: Vec<Vec<u8>> = Vec::new();
    let mut applied = 0;
    while let Some(frame) = t.recv().map_err(|_| WireError::TransportFailed)? {
        if std::time::Instant::now() >= deadline {
            return Err(WireError::SyncModeUnsupported);
        }
        match decode_frame(&frame) {
            Ok(SyncFrame::Entry(wire)) => {
                staged.push(wire);
                if staged.len() >= MAX_STAGED {
                    applied += room.apply(std::mem::take(&mut staged))?;
                }
            }
            Ok(_) | Err(_) => return Err(WireError::SyncModeUnsupported),
        }
    }
    if !staged.is_empty() {
        applied += room.apply(staged)?;
    }
    Ok(applied)
}

/// Apply staged entries into `dag`, returning how many were newly stored — the apply half of
/// [`SessionRoom::apply`], for a caller that already holds its room.
///
/// # Errors
/// The first hard sync failure.
pub fn apply_staged<R: AuthorResolver>(
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    staged: &[Vec<u8>],
) -> std::result::Result<usize, WireError> {
    let mut stored = 0;
    for wire in staged {
        if matches!(
            apply_entry(dag, resolver, admission, wire)?,
            ApplyOutcome::Stored
        ) {
            stored += 1;
        }
    }
    Ok(stored)
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
) -> std::result::Result<usize, WireError> {
    let mut applied = 0;
    // **The whole phase is bounded, not just the gap between frames.**
    //
    // The transport's timeout is per frame, and this loop had no limit on how many frames it
    // would take, so a peer that sent one frame every nineteen seconds — forever — held this
    // room's lock for ever. The lock is taken for the entire session (see `sync_over`'s caller),
    // so that is every operation on the room stopped by one member, at no cost to it.
    //
    // The references bound the total as well as the gap: go-libp2p's relay sets a per-stream
    // timeout *and* an absolute `Duration` cap on the whole relayed connection, and Tor reclaims a
    // circuit on total idle. A per-frame bound alone only defends against a peer that stops, never
    // against one that drips.
    let deadline = std::time::Instant::now() + DRAIN_BUDGET;
    while let Some(frame) = t.recv().map_err(|_| WireError::TransportFailed)? {
        if std::time::Instant::now() >= deadline {
            return Err(WireError::SyncModeUnsupported);
        }
        match decode_frame(&frame) {
            Ok(SyncFrame::Entry(wire)) => {
                if matches!(
                    apply_entry(dag, resolver, admission, &wire)?,
                    ApplyOutcome::Stored
                ) {
                    applied += 1;
                }
            }
            // **A protocol violation, not something to ignore.** This phase is defined as entries
            // only, and silently accepting anything else is what made the hold above free: a
            // non-entry frame costs the sender nothing and never reaches `apply_entry`, so it
            // would buy the whole budget for free.
            Ok(_) => return Err(WireError::SyncModeUnsupported),
            Err(_) => return Err(WireError::SyncModeUnsupported),
        }
    }
    Ok(applied)
}

fn expect_hello(r: Result<Option<Vec<u8>>>) -> std::result::Result<u8, WireError> {
    match r.map_err(|_| WireError::TransportFailed)? {
        Some(frame) => match decode_frame(&frame) {
            Ok(SyncFrame::Hello(bitmap)) => Ok(bitmap),
            _ => Err(WireError::SyncModeUnsupported),
        },
        // A clean end-of-stream where a frame was due: the peer hung up mid-session.
        None => Err(WireError::TransportFailed),
    }
}

fn expect_have(r: Result<Option<Vec<u8>>>) -> std::result::Result<Vec<FeedFrontier>, WireError> {
    match r.map_err(|_| WireError::TransportFailed)? {
        Some(frame) => match decode_frame(&frame) {
            Ok(SyncFrame::Have(v)) => Ok(v),
            _ => Err(WireError::SyncModeUnsupported),
        },
        None => Err(WireError::TransportFailed),
    }
}

fn expect_want(r: Result<Option<Vec<u8>>>) -> std::result::Result<Vec<WantRange>, WireError> {
    match r.map_err(|_| WireError::TransportFailed)? {
        Some(frame) => match decode_frame(&frame) {
            Ok(SyncFrame::Want(v)) => Ok(v),
            _ => Err(WireError::SyncModeUnsupported),
        },
        None => Err(WireError::TransportFailed),
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
    let applied_into_a = apply_hashes(a, b, resolver, admission, &a_need)?;
    let applied_into_b = apply_hashes(b, a, resolver, admission, &a_have)?;
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
            apply_entry(dst, resolver, admission, &wire)?,
            ApplyOutcome::Stored
        ) {
            applied += 1;
        }
    }
    Ok(applied)
}

const _: () = assert!(DIGEST_LEN == 32);
