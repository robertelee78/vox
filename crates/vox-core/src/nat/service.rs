//! The rendezvous **service** (ADR-016 §"The rendezvous service and the member
//! bundle record"; the ADR-012 board made reachable).
//!
//! Any node serves this on its [`VoxEndpoint`](crate::transport::quic::VoxEndpoint)
//! and the configured anchors are simply the peers a client publishes to and
//! reads from. It is a request/response protocol on one bi-stream typed
//! [`StreamKind::Rendezvous`]: length-prefixed canonical-CBOR frames
//! ([`crate::transport::framing`]), each request answered in order, the client
//! half-closing when done. Two requests:
//!
//! - **`PUT <record>`** for any of the three record kinds — member address
//!   (`0x0007`), pre-join (`0x0008`), member bundle (`0x0012`) — identified by the
//!   record's own struct tag. The server answers `ACCEPTED` or `REJECTED <reason>`.
//!   Every PUT is gated by the existing [`RendezvousStore`] policy: member-only
//!   for the two member kinds (via the [`MembershipOracle`] — the channel's
//!   authenticated membership, ADR-007), self-verifying for pre-join, and the
//!   anti-replay / refresh-floor / TTL / clock-skew / capacity rules for all. The
//!   record is self-authenticating, so the connection's peer need not be its
//!   author: a member may re-publish a peer's current record to a second anchor.
//! - **`GET <channelID, epoch, kinds>`** returning every live record of the
//!   requested kinds as a sequence of `RECORD <wire>` frames terminated by `END`.
//!   Reading is open to any authenticated peer that knows the channelID (the
//!   rendezvous half of the ADR-005 link **is** the read capability; the
//!   passphrase, never in the link, gates the join). Records come back
//!   parsed-but-unverified: a member verifies them against its membership view
//!   and a joiner against the fingerprint it was given out of band.
//!
//! Frames are capped at [`MAX_RENDEZVOUS_FRAME`] (measured: a member bundle
//! record with a full one-time prekey is 18 084 bytes, a pre-join record with
//! eight IPv6 endpoints 20 211; the hard bundle cap is
//! [`MAX_PREKEY_BUNDLE_BYTES`]), and a `GET` reply at [`MAX_GET_RECORDS`] frames
//! so a hostile server cannot stream forever. A frame the server cannot parse as
//! a request resets the stream with the ADR-008 coded close
//! ([`wire_error_for`]); a record it can parse but must refuse is answered, not
//! reset, because refusal is the protocol's normal outcome.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use quinn::{RecvStream, SendStream};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::governance::genesis::Genesis;
use crate::hash::Digest32;
use crate::identity::composite::CompositePublicKey;
use crate::log::sync::wire_error_for;
use crate::nat::record::{
    MemberBundleRecord, PreJoinRecord, RendezvousRecord, MAX_PREKEY_BUNDLE_BYTES,
};
use crate::nat::store::{RendezvousStore, MAX_AUTHORS_PER_BUCKET, MAX_PREJOIN_PER_CHANNEL};
use crate::time::Clock;
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::{close_code, VoxConnection};
use crate::transport::streams::{open_typed, StreamKind};
use crate::wire::{parse_frame, StructTag};

/// The largest rendezvous frame either side will read: the bundle cap plus room
/// for the record's other fields and its composite signature (~3.5 KiB).
pub const MAX_RENDEZVOUS_FRAME: usize = MAX_PREKEY_BUNDLE_BYTES + 16 * 1024;

/// The most `RECORD` frames a client accepts for one `GET`: the store can hold at
/// most this many live records for one `(channelID, epoch)`, plus the genesis.
pub const MAX_GET_RECORDS: usize = 2 * MAX_AUTHORS_PER_BUCKET + MAX_PREJOIN_PER_CHANNEL + 1;

/// Which record kinds a `GET` asks for (a bit set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordKinds(u8);

impl RecordKinds {
    /// Member address records (`0x0007`).
    pub const MEMBERS: Self = Self(0b001);
    /// Member bundle records (`0x0012`).
    pub const BUNDLES: Self = Self(0b010);
    /// Pre-join records (`0x0008`).
    pub const PREJOINS: Self = Self(0b100);
    /// The channel genesis (`0x000D`) — what a cold joiner needs before it can
    /// build channel state at all (ADR-007).
    pub const GENESIS: Self = Self(0b1000);
    /// Every kind.
    pub const ALL: Self = Self(0b1111);

    /// Combine two sets.
    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every bit of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The wire bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Parse wire bits; a set bit outside the three kinds is malformed.
    pub fn from_bits(bits: u64) -> Result<Self> {
        if bits == 0 || bits & !u64::from(Self::ALL.0) != 0 {
            return Err(Error::MalformedRendezvous("rendezvous get kinds"));
        }
        Ok(Self(bits as u8))
    }
}

/// A client → server request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RendezvousRequest {
    /// Publish one framed record (`0x0007`, `0x0008` or `0x0012`).
    Put {
        /// The record's wire bytes (its struct tag says which kind).
        record: Vec<u8>,
    },
    /// Fetch every live record of `kinds` for `(channel_id, epoch)`.
    Get {
        /// The channel.
        channel_id: Digest32,
        /// The epoch (pre-join records are epoch-less and always match).
        epoch: u64,
        /// The kinds wanted.
        kinds: RecordKinds,
    },
}

/// Why the server refused a `PUT` — closed and coded, never free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RejectReason {
    /// A member-kind record whose author the channel's membership does not know.
    NotMember = 1,
    /// The record did not parse or verify (bad tag body, signature, binding).
    Malformed = 2,
    /// Zero/over-long TTL, expired or future-dated.
    Policy = 3,
    /// The `(channelID, epoch)` bucket is full.
    Capacity = 4,
    /// The frame's struct tag is not a rendezvous record kind.
    UnknownKind = 5,
    /// The board already holds a **newer** record from that author (a non-advancing `seq` or
    /// `timestamp`). Its own code because it means opposite things by whose record it is: for a
    /// record a node mirrors on another member's behalf it is benign — somebody got there first
    /// with fresher news — and for the node's *own* record it means the board has something newer
    /// from us than we do, which is real. Folded into `Policy` the two could not be told apart, and
    /// every stale mirror was reported to the person as a refusal.
    Stale = 6,
}

impl RejectReason {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::NotMember),
            2 => Some(Self::Malformed),
            3 => Some(Self::Policy),
            4 => Some(Self::Capacity),
            5 => Some(Self::UnknownKind),
            6 => Some(Self::Stale),
            _ => None,
        }
    }

    /// The reason as the `&'static str` the [`Error::RendezvousRejected`]
    /// taxonomy carries client-side.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotMember => "rejected: author is not a channel member",
            Self::Malformed => "rejected: malformed record",
            Self::Policy => "rejected: policy",
            Self::Capacity => "rejected: capacity",
            Self::UnknownKind => "rejected: unknown record kind",
            Self::Stale => "rejected: the board holds a newer record from that author",
        }
    }

    /// Classify a store/parse error.
    fn for_error(err: &Error) -> Self {
        match err {
            Error::RendezvousRejected("author is not a channel member") => Self::NotMember,
            Error::RendezvousRejected(s) if s.ends_with("at capacity") => Self::Capacity,
            Error::RendezvousRejected(s) if s.starts_with("non-increasing") => Self::Stale,
            Error::RendezvousRejected(_) => Self::Policy,
            _ => Self::Malformed,
        }
    }
}

/// A server → client response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RendezvousResponse {
    /// The `PUT` was admitted.
    Accepted,
    /// The `PUT` was refused.
    Rejected(RejectReason),
    /// One live record (its wire bytes) answering a `GET`.
    Record(Vec<u8>),
    /// End of a `GET` reply.
    End,
}

const OP_PUT: u64 = 1;
const OP_GET: u64 = 2;
const OP_ACCEPTED: u64 = 1;
const OP_REJECTED: u64 = 2;
const OP_RECORD: u64 = 3;
const OP_END: u64 = 4;

impl RendezvousRequest {
    /// Canonical frame: `[1, record]` or `[2, channel_id, epoch, kinds]`.
    #[must_use]
    pub fn to_frame(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Self::Put { record } => {
                e.array(2).uint(OP_PUT).bytes(record);
            }
            Self::Get {
                channel_id,
                epoch,
                kinds,
            } => {
                e.array(4)
                    .uint(OP_GET)
                    .bytes(channel_id)
                    .uint(*epoch)
                    .uint(u64::from(kinds.bits()));
            }
        }
        e.finish()
    }

    /// Parse a request frame.
    pub fn from_frame(frame: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(frame);
        let n = d.array()?;
        let op = d.uint()?;
        let req = match (op, n) {
            (OP_PUT, 2) => Self::Put {
                record: d.bytes()?.to_vec(),
            },
            (OP_GET, 4) => {
                let channel_id: Digest32 = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedRendezvous("rendezvous get channel_id length"))?;
                let epoch = d.uint()?;
                let kinds = RecordKinds::from_bits(d.uint()?)?;
                Self::Get {
                    channel_id,
                    epoch,
                    kinds,
                }
            }
            _ => return Err(Error::MalformedRendezvous("rendezvous request op")),
        };
        d.finish()?;
        Ok(req)
    }
}

impl RendezvousResponse {
    /// Canonical frame: `[1]`, `[2, reason]`, `[3, record]` or `[4]`.
    #[must_use]
    pub fn to_frame(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Self::Accepted => {
                e.array(1).uint(OP_ACCEPTED);
            }
            Self::Rejected(r) => {
                e.array(2).uint(OP_REJECTED).uint(u64::from(*r as u8));
            }
            Self::Record(w) => {
                e.array(2).uint(OP_RECORD).bytes(w);
            }
            Self::End => {
                e.array(1).uint(OP_END);
            }
        }
        e.finish()
    }

    /// Parse a response frame.
    pub fn from_frame(frame: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(frame);
        let n = d.array()?;
        let op = d.uint()?;
        let resp = match (op, n) {
            (OP_ACCEPTED, 1) => Self::Accepted,
            (OP_REJECTED, 2) => {
                let v = u8::try_from(d.uint()?)
                    .map_err(|_| Error::MalformedRendezvous("rendezvous reject reason"))?;
                Self::Rejected(
                    RejectReason::from_u8(v)
                        .ok_or(Error::MalformedRendezvous("rendezvous reject reason"))?,
                )
            }
            (OP_RECORD, 2) => Self::Record(d.bytes()?.to_vec()),
            (OP_END, 1) => Self::End,
            _ => return Err(Error::MalformedRendezvous("rendezvous response op")),
        };
        d.finish()?;
        Ok(resp)
    }
}

/// The channel-membership oracle the service gates member-kind `PUT`s with: the
/// composite public key of `author_id` **iff** it is a member of
/// `(channel_id, epoch)` (ADR-007 authenticated membership). A node answers from
/// its open channels' state; an anchor from the genesis, admin certificates and
/// stored records it has verified.
pub trait MembershipOracle: Send + Sync {
    /// The member's key, or `None` for a non-member (or an unknown channel).
    fn member_key(
        &self,
        channel_id: &Digest32,
        epoch: u64,
        author_id: &Digest32,
    ) -> Option<CompositePublicKey>;
}

/// The live records a `GET` returned, parsed by kind (unverified — see the
/// module docs; the genesis is the exception, verified and channel-bound on
/// arrival because it is self-validating).
#[derive(Debug, Clone, Default)]
pub struct RecordSet {
    /// Member address records.
    pub members: Vec<RendezvousRecord>,
    /// Member bundle records.
    pub bundles: Vec<MemberBundleRecord>,
    /// Pre-join records.
    pub prejoins: Vec<PreJoinRecord>,
    /// The channel genesis, if the board holds it.
    pub genesis: Option<Genesis>,
}

/// Told a channelID when a member-kind record **from a peer** is admitted to this board.
///
/// A plain closure rather than a typed sender because `nat` must not depend on `node`: the
/// node installs one that turns the call into an event on its actor's queue.
pub type AdmittedHook = Arc<dyn Fn(Digest32) + Send + Sync>;

/// The server side: a [`RendezvousStore`] behind a lock, the membership oracle
/// and a clock. Clone-cheap (`Arc`s) so one service serves every connection.
#[derive(Clone)]
pub struct RendezvousService {
    store: Arc<Mutex<RendezvousStore>>,
    oracle: Arc<dyn MembershipOracle>,
    clock: Clock,
    /// See [`RendezvousService::on_admitted`].
    admitted: Option<AdmittedHook>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl RendezvousService {
    /// A service over `store`, gating member-kind records with `oracle`.
    #[must_use]
    pub fn new(
        store: Arc<Mutex<RendezvousStore>>,
        oracle: Arc<dyn MembershipOracle>,
        clock: Clock,
    ) -> Self {
        Self {
            store,
            oracle,
            clock,
            admitted: None,
        }
    }

    /// Be told when a record by an author **other than this node** is admitted.
    ///
    /// This is the seam that makes learning a new member event-driven. A member's bundle only
    /// reaches an anchor because a member that already knows it **vouches** by publishing it on
    /// (see this service's `put`), and the node holding that board had no way to notice one
    /// had arrived: the record landed, nothing was told, and the onward mirror waited for whatever
    /// happened to trigger a publish next. Measured on a real three-process room, that left the
    /// anchor knowing 1 of 2 members in 2 runs of 3 — a newcomer nobody away from the room could
    /// reconcile with, for no reason a person could see.
    pub fn on_admitted(&mut self, hook: AdmittedHook) {
        self.admitted = Some(hook);
    }

    /// The shared store (for the owning node's own reads and pruning).
    #[must_use]
    pub fn store(&self) -> &Arc<Mutex<RendezvousStore>> {
        &self.store
    }

    /// Evaluate one request against the store, producing the ordered responses
    /// the stream will carry. Pure with respect to the transport, so the policy
    /// is testable without QUIC.
    #[must_use]
    pub fn handle(
        &self,
        publisher: Option<&Digest32>,
        request: &RendezvousRequest,
    ) -> Vec<RendezvousResponse> {
        let now = (self.clock)();
        match request {
            RendezvousRequest::Put { record } => vec![match self.put(publisher, record, now) {
                Ok(()) => RendezvousResponse::Accepted,
                Err(e) => RendezvousResponse::Rejected(e),
            }],
            RendezvousRequest::Get {
                channel_id,
                epoch,
                kinds,
            } => {
                let store = lock(&self.store);
                let mut out = Vec::new();
                if kinds.contains(RecordKinds::MEMBERS) {
                    out.extend(
                        store
                            .current_members(channel_id, *epoch, now)
                            .into_iter()
                            .map(|r| RendezvousResponse::Record(r.to_wire())),
                    );
                }
                if kinds.contains(RecordKinds::BUNDLES) {
                    out.extend(
                        store
                            .current_bundles(channel_id, *epoch, now)
                            .into_iter()
                            .map(|r| RendezvousResponse::Record(r.to_wire())),
                    );
                }
                if kinds.contains(RecordKinds::PREJOINS) {
                    out.extend(
                        store
                            .current_prejoins(channel_id, now)
                            .into_iter()
                            .map(|r| RendezvousResponse::Record(r.to_wire())),
                    );
                }
                if kinds.contains(RecordKinds::GENESIS) {
                    if let Some(g) = store.genesis(channel_id) {
                        out.push(RendezvousResponse::Record(g.to_wire()));
                    }
                }
                drop(store);
                out.push(RendezvousResponse::End);
                out
            }
        }
    }

    /// The authenticated key for `author` in `(channel, epoch)`, from what this node
    /// knows: its own membership view (the oracle), the **creator** named by the
    /// genesis it holds, or a **bundle record** it already holds for that author —
    /// which carries the author's key, and was admitted only because a known member
    /// published it (see `put`). This is how a node that *anchors* a channel it is not
    /// a member of comes to know that channel's members (ADR-016 M15.2a).
    fn known_key(
        &self,
        store: &RendezvousStore,
        channel: &Digest32,
        epoch: u64,
        author: &Digest32,
        now: u64,
    ) -> Option<CompositePublicKey> {
        if let Some(key) = self.oracle.member_key(channel, epoch, author) {
            return Some(key);
        }
        if let Some(g) = store.genesis(channel) {
            if g.body.creator_pubkey.fingerprint() == *author {
                return Some(g.body.creator_pubkey.clone());
            }
        }
        store
            .bundle(channel, epoch, author, now)
            .and_then(|b| CompositePublicKey::from_bytes(&b.prekey_bundle.root_pub).ok())
    }

    /// Admit one framed record by its struct tag.
    /// `publisher` is the authenticated peer the record came in from (`None` for a
    /// local publish). It matters for one case: a **bundle record from an author this
    /// node does not know**, published by a peer it knows as a member of that channel,
    /// is admitted with the key the record carries — the member is **vouching**, which
    /// is exactly the trust members already extend to one another's boards (a member
    /// learns new members from the boards of members who witnessed the join). The
    /// record's own verification binds the carried key to the author; the vouch only
    /// says "this author is one of us".
    fn put(
        &self,
        publisher: Option<&Digest32>,
        record: &[u8],
        now: u64,
    ) -> std::result::Result<(), RejectReason> {
        let tag = parse_frame(record)
            .map(|f| f.tag)
            .map_err(|e| RejectReason::for_error(&e))?;
        // Set by the arms below for a member-kind record that arrived **from a peer** rather than
        // from this node's own local publish. That is the test, and the narrower one — "the
        // publisher is not the author" — is wrong: the case that matters most is a newcomer
        // putting *its own* bundle on a member's board, which is publisher == author and is
        // precisely the record that has to travel onward for anyone else to reconcile with it.
        // A local publish is excluded because this node already mirrors its own records.
        let mut grew: Option<Digest32> = None;
        let res = match tag {
            StructTag::RendezvousRecord => {
                let rec =
                    RendezvousRecord::from_wire(record).map_err(|e| RejectReason::for_error(&e))?;
                let (cid, epoch, author) = (rec.channel_id, rec.epoch, rec.author_id);
                if publisher.is_some() {
                    grew = Some(cid);
                }
                let mut store = lock(&self.store);
                let key = self.known_key(&store, &cid, epoch, &author, now);
                store.accept_member(rec, |_| key.clone(), now)
            }
            StructTag::MemberBundleRecord => {
                let rec = MemberBundleRecord::from_wire(record)
                    .map_err(|e| RejectReason::for_error(&e))?;
                let (cid, epoch, author) = (rec.channel_id, rec.epoch, rec.author_id);
                if publisher.is_some() {
                    grew = Some(cid);
                }
                let mut store = lock(&self.store);
                let key = self
                    .known_key(&store, &cid, epoch, &author, now)
                    .or_else(|| {
                        let vouched = publisher.is_some_and(|p| {
                            *p != author && self.known_key(&store, &cid, epoch, p, now).is_some()
                        });
                        if vouched {
                            CompositePublicKey::from_bytes(&rec.prekey_bundle.root_pub).ok()
                        } else {
                            None
                        }
                    });
                store.accept_bundle(rec, |_| key.clone(), now)
            }
            StructTag::PreJoinRecord => {
                let rec =
                    PreJoinRecord::from_wire(record).map_err(|e| RejectReason::for_error(&e))?;
                lock(&self.store).accept_prejoin(rec, now)
            }
            // Self-validating: its hash is the channelID, so no author check is
            // needed or possible (ADR-007; see `accept_genesis`).
            StructTag::GenesisRecord => {
                let genesis =
                    Genesis::from_wire(record).map_err(|e| RejectReason::for_error(&e))?;
                lock(&self.store).accept_genesis(genesis)
            }
            _ => return Err(RejectReason::UnknownKind),
        };
        // Fired **after** the match, so the store guard each arm took is already gone: a hook runs
        // node code, and holding a board lock into it is how a board lock ends up inside somebody
        // else's await. Only for a record whose author is not the publisher — that is precisely
        // the "somebody new landed here" case — and only on admission, so a refreshed record
        // declined by the ADR-012 floor says nothing.
        if res.is_ok() {
            if let (Some(hook), Some(cid)) = (self.admitted.as_ref(), grew) {
                hook(cid);
            }
        }
        res.map_err(|e| RejectReason::for_error(&e))
    }

    /// Serve one already-typed rendezvous stream until the peer half-closes
    /// (`Ok`) or sends something that is not a request (the stream is reset with
    /// the coded close and the error returned). Never holds the store lock across
    /// an `await`.
    pub async fn serve_stream(
        &self,
        publisher: Digest32,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        loop {
            let frame = match read_frame(&mut recv, MAX_RENDEZVOUS_FRAME).await {
                Ok(Some(f)) => f,
                Ok(None) => {
                    // Clean FIN: the client is done. Our FIN completes the exchange.
                    let _ = send.finish();
                    return Ok(());
                }
                Err(e) => {
                    reset(&mut send, &mut recv, &e);
                    return Err(e);
                }
            };
            let request = match RendezvousRequest::from_frame(&frame) {
                Ok(r) => r,
                Err(e) => {
                    reset(&mut send, &mut recv, &e);
                    return Err(e);
                }
            };
            for response in self.handle(Some(&publisher), &request) {
                if let Err(e) = write_frame(&mut send, &response.to_frame()).await {
                    reset(&mut send, &mut recv, &e);
                    return Err(e);
                }
            }
        }
    }
}

/// Reset both halves with the ADR-008 code for `err`.
fn reset(send: &mut SendStream, recv: &mut RecvStream, err: &Error) {
    let code = close_code(wire_error_for(err));
    let _ = send.reset(code);
    let _ = recv.stop(code);
}

/// The client side of one rendezvous stream.
pub struct RendezvousClient {
    send: SendStream,
    recv: RecvStream,
}

impl RendezvousClient {
    /// Open a rendezvous stream on `conn`.
    pub async fn open(conn: &VoxConnection) -> Result<Self> {
        let (send, recv) = open_typed(conn, StreamKind::Rendezvous).await?;
        Ok(Self { send, recv })
    }

    async fn next_response(&mut self) -> Result<RendezvousResponse> {
        let frame = read_frame(&mut self.recv, MAX_RENDEZVOUS_FRAME)
            .await?
            .ok_or(Error::MalformedRendezvous("rendezvous stream closed early"))?;
        RendezvousResponse::from_frame(&frame)
    }

    /// Publish one framed record. A refusal surfaces as
    /// [`Error::RendezvousRejected`] carrying [`RejectReason::as_str`].
    pub async fn put(&mut self, record: &[u8]) -> Result<()> {
        if record.len() > MAX_RENDEZVOUS_FRAME {
            return Err(Error::SizeLimitExceeded("rendezvous record"));
        }
        let req = RendezvousRequest::Put {
            record: record.to_vec(),
        };
        write_frame(&mut self.send, &req.to_frame()).await?;
        match self.next_response().await? {
            RendezvousResponse::Accepted => Ok(()),
            RendezvousResponse::Rejected(r) => Err(Error::RendezvousRejected(r.as_str())),
            _ => Err(Error::MalformedRendezvous(
                "rendezvous put: unexpected response",
            )),
        }
    }

    /// Fetch the live records of `kinds` for `(channel_id, epoch)`, parsed by
    /// kind and **unverified**. A reply frame that does not parse as a record of
    /// a requested kind, or more than [`MAX_GET_RECORDS`] frames, is an error.
    pub async fn get(
        &mut self,
        channel_id: &Digest32,
        epoch: u64,
        kinds: RecordKinds,
    ) -> Result<RecordSet> {
        let req = RendezvousRequest::Get {
            channel_id: *channel_id,
            epoch,
            kinds,
        };
        write_frame(&mut self.send, &req.to_frame()).await?;
        let mut set = RecordSet::default();
        let mut count = 0usize;
        loop {
            match self.next_response().await? {
                RendezvousResponse::End => return Ok(set),
                RendezvousResponse::Record(wire) => {
                    count += 1;
                    if count > MAX_GET_RECORDS {
                        return Err(Error::SizeLimitExceeded("rendezvous get records"));
                    }
                    let tag = parse_frame(&wire)?.tag;
                    match tag {
                        StructTag::RendezvousRecord if kinds.contains(RecordKinds::MEMBERS) => {
                            set.members.push(RendezvousRecord::from_wire(&wire)?);
                        }
                        StructTag::MemberBundleRecord if kinds.contains(RecordKinds::BUNDLES) => {
                            set.bundles.push(MemberBundleRecord::from_wire(&wire)?);
                        }
                        StructTag::PreJoinRecord if kinds.contains(RecordKinds::PREJOINS) => {
                            set.prejoins.push(PreJoinRecord::from_wire(&wire)?);
                        }
                        StructTag::GenesisRecord if kinds.contains(RecordKinds::GENESIS) => {
                            let g = Genesis::from_wire(&wire)?;
                            // The board is only availability: verify the genesis and
                            // bind it to the channelID we asked for.
                            g.verify()?;
                            if g.channel_id() != *channel_id {
                                return Err(Error::MalformedRendezvous(
                                    "rendezvous get: genesis is not this channel's",
                                ));
                            }
                            set.genesis = Some(g);
                        }
                        _ => {
                            return Err(Error::MalformedRendezvous(
                                "rendezvous get: record of an unrequested kind",
                            ))
                        }
                    }
                }
                _ => {
                    return Err(Error::MalformedRendezvous(
                        "rendezvous get: unexpected response",
                    ))
                }
            }
        }
    }

    /// Finish: half-close the request side. The server answers with its own FIN.
    pub fn finish(mut self) {
        let _ = self.send.finish();
    }
}
