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
use crate::nat::store::{RendezvousStore, Source, MAX_AUTHORS_PER_BUCKET, MAX_PREJOIN_PER_CHANNEL};
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
    /// Who ended the room, when the board took it off at a signed end instead (V030-14). The
    /// board's word: it checked the withdraw against the room's creator or admin roster, which a
    /// joiner does not hold.
    pub ended_by: Option<Digest32>,
}

/// Which rooms a board keeps for a peer that brings their genesis — the rooms it will
/// **anchor** (see [`RendezvousService::serve_rooms`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AnchorRooms {
    /// None: this node is not an anchor. It keeps the boards of the rooms it holds, which it
    /// files itself, and takes no room from a peer.
    #[default]
    Held,
    /// Any room brought to it (`vox node --serve anyone`, the default for an anchor).
    Anyone,
    /// Only rooms whose genesis names one of these creators (`vox node --serve trusted`: the
    /// anchor profile's `vox trust` list).
    CreatedBy(std::collections::BTreeSet<Digest32>),
}

impl AnchorRooms {
    /// **May this node anchor the room `genesis` founds?** The one predicate both the board's
    /// genesis acceptance and the node's adoption of a room go through, so the two cannot
    /// disagree about which rooms this node serves.
    #[must_use]
    pub fn may_anchor(&self, genesis: &Genesis) -> bool {
        match self {
            Self::Held => false,
            Self::Anyone => true,
            Self::CreatedBy(creators) => {
                creators.contains(&genesis.body.creator_pubkey.fingerprint())
            }
        }
    }
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
    /// See [`RendezvousService::serve_rooms`].
    rooms: AnchorRooms,
}

/// Whether a record by `author` that the board took credits its room to the source it came from
/// ([`Source`]): only when the peer that put it **wrote** it — a genesis put by its creator, an
/// address or bundle record put by its member — and then whether or not the board already held it.
/// A room's records are served to anyone who asks, so putting one proves nothing about who put it:
/// credited to whoever put it, a stranger re-sent a real room's records from its own network and
/// the room was evicted with the stranger's own rooms (V210-70, c4). And the member's own put must
/// credit even when it changes nothing: credited only when it stored something new, a stranger that
/// put the records on a board first left the member's republish a no-op, the room credited to no
/// one (c5).
fn wrote(publisher: Option<&Digest32>, author: &Digest32) -> bool {
    publisher == Some(author)
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
            rooms: AnchorRooms::Held,
        }
    }

    /// Which rooms this board keeps when a peer brings their genesis — what an **anchor** is
    /// for (`vox node`: a member points `--anchor` at it and it keeps that room's board).
    /// [`AnchorRooms::Held`] by default, and for every node that is not an anchor.
    ///
    /// A board that took any peer's genesis made that genesis's creator a member here
    /// (`node::network::classify`), and a genesis is something anybody can mint: an
    /// unknown peer published one for a room it had just invented and could then open
    /// every stream a member can, relay through this node, and list its room in this
    /// node's status. A node that holds rooms files their geneses itself (see
    /// [`RendezvousService::handle_local`]); a peer never needs to give it one.
    pub fn serve_rooms(&mut self, rooms: AnchorRooms) {
        self.rooms = rooms;
    }

    /// Whether this node may anchor the room `genesis` founds (see [`AnchorRooms::may_anchor`]).
    #[must_use]
    pub fn may_anchor(&self, genesis: &Genesis) -> bool {
        self.rooms.may_anchor(genesis)
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
        source: Option<Source>,
        request: &RendezvousRequest,
    ) -> Vec<RendezvousResponse> {
        self.handle_as(publisher, source, request, false)
    }

    /// [`RendezvousService::handle`] for a request **this node** makes of its own board
    /// (`publisher` is this node). A genesis filed this way is one of the node's own rooms,
    /// or one it anchors, and is pinned: never refused for want of room, never displaced.
    #[must_use]
    pub fn handle_local(
        &self,
        publisher: &Digest32,
        request: &RendezvousRequest,
    ) -> Vec<RendezvousResponse> {
        self.handle_as(Some(publisher), None, request, true)
    }

    fn handle_as(
        &self,
        publisher: Option<&Digest32>,
        source: Option<Source>,
        request: &RendezvousRequest,
        local: bool,
    ) -> Vec<RendezvousResponse> {
        let now = (self.clock)();
        match request {
            RendezvousRequest::Put { record } => {
                vec![match self.put(publisher, source, record, now, local) {
                    Ok(()) => RendezvousResponse::Accepted,
                    Err(e) => RendezvousResponse::Rejected(e),
                }]
            }
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
                    } else if let Some(ended) = store.room_ended(channel_id) {
                        // In the genesis's place: the room was ended, and this is the withdraw
                        // that took it off (V030-14).
                        out.push(RendezvousResponse::Record(ended.to_vec()));
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
    /// which carries the author's key, and was admitted only on the evidence it carries
    /// (see `put`). This is how a node that *anchors* a channel it is not a member of
    /// comes to know that channel's members (ADR-016 M15.2a).
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

    /// The key a bundle record for an author this board does not know yet may be admitted
    /// under: the one it carries, **if its join witness holds up** — signed by a key this
    /// board already knows for that room, over this room, this epoch and this author
    /// (ADR-016 M17.6). The chain starts at the creator, whom the genesis names.
    ///
    /// It used to be enough that the record came *from* a peer this board knew as a member:
    /// the publisher was taken to vouch. So any member could put any key on another node's
    /// board, and that key was then a member there — it could open every stream a member can
    /// and relay through the node — with no evidence anyone ever admitted it. Members forward
    /// one another's bundles all the time (the mirror loop), so this happened without anyone
    /// meaning it to. A member's own node already refused such a key as an author
    /// (`ChannelState::admit_from_board`); the board now asks for the same evidence.
    fn witnessed_key(
        &self,
        store: &RendezvousStore,
        rec: &MemberBundleRecord,
        now: u64,
    ) -> Option<CompositePublicKey> {
        let witness = rec.admission.witness()?;
        let witness_key =
            self.known_key(store, &rec.channel_id, rec.epoch, &witness.witness_id, now)?;
        witness
            .verify(&witness_key, &rec.channel_id, rec.epoch, &rec.author_id)
            .ok()?;
        CompositePublicKey::from_bytes(&rec.prekey_bundle.root_pub).ok()
    }

    /// Admit one framed record by its struct tag.
    /// `publisher` is the authenticated peer the record came in from (this node itself
    /// for a local publish, `None` when nobody is named). It matters for a pre-join: a
    /// joiner announces **itself**, so a pre-join is taken only from the identity it
    /// names. `source` is where it came from, which a full board shares itself out by
    /// ([`Source`]); `local` says the request is this node's own (see
    /// [`RendezvousService::handle_local`]).
    fn put(
        &self,
        publisher: Option<&Digest32>,
        source: Option<Source>,
        record: &[u8],
        now: u64,
        local: bool,
    ) -> std::result::Result<(), RejectReason> {
        let tag = parse_frame(record)
            .map(|f| f.tag)
            .map_err(|e| RejectReason::for_error(&e))?;
        // Set by the arms below for a member-kind record that arrived **from a peer** rather than
        // from this node's own local publish, **and taught this board something**: an author it
        // held nothing for, or a changed claim. The narrower test "the publisher is not the
        // author" is wrong: the case that matters most is a newcomer putting *its own* bundle on a
        // member's board, which is publisher == author and is precisely the record that has to
        // travel onward for anyone else to reconcile with it. A local publish is excluded because
        // this node already mirrors its own records. And a member's routine refresh of a claim this
        // board already holds is not news (#179): every node told of news republishes, so counting
        // a refresh made two members' boards wake each other about a hundred times a second, and
        // each wake cost the actor 3–40 ms that a local post then queued behind.
        let mut grew: Option<Digest32> = None;
        let res = match tag {
            StructTag::RendezvousRecord => {
                let rec =
                    RendezvousRecord::from_wire(record).map_err(|e| RejectReason::for_error(&e))?;
                let (cid, epoch, author) = (rec.channel_id, rec.epoch, rec.author_id);
                let mut store = lock(&self.store);
                let key = self.known_key(&store, &cid, epoch, &author, now);
                let res = store.accept_member(rec, |_| key.clone(), now);
                if res.is_ok() && wrote(publisher, &author) {
                    store.note_source(&cid, source);
                }
                res.map(|learned| {
                    if learned && publisher.is_some() {
                        grew = Some(cid);
                    }
                })
            }
            StructTag::MemberBundleRecord => {
                let rec = MemberBundleRecord::from_wire(record)
                    .map_err(|e| RejectReason::for_error(&e))?;
                let (cid, epoch, author) = (rec.channel_id, rec.epoch, rec.author_id);
                let mut store = lock(&self.store);
                let key = self
                    .known_key(&store, &cid, epoch, &author, now)
                    .or_else(|| self.witnessed_key(&store, &rec, now));
                let res = store.accept_bundle(rec, |_| key.clone(), now);
                if res.is_ok() && wrote(publisher, &author) {
                    store.note_source(&cid, source);
                }
                res.map(|learned| {
                    if learned && publisher.is_some() {
                        grew = Some(cid);
                    }
                })
            }
            StructTag::PreJoinRecord => {
                let rec =
                    PreJoinRecord::from_wire(record).map_err(|e| RejectReason::for_error(&e))?;
                // A joiner announces itself. Taken from anyone, one connection could fill a
                // room's pre-join slots with keys it minted by the hundred (V210-70); taken
                // only from the identity it names, each slot costs an authenticated
                // connection of its own.
                if publisher.is_some_and(|p| *p != rec.asserted_id()) {
                    return Err(RejectReason::Policy);
                }
                lock(&self.store).accept_prejoin(rec, now)
            }
            // Self-validating: its hash is the channelID, so no author check is
            // needed or possible (ADR-007; see `accept_genesis`). Whether this board takes
            // it is another matter: only its own rooms, or a room it may anchor (see
            // `serve_rooms`), and a genesis it already holds is always a no-op.
            StructTag::GenesisRecord => {
                let genesis =
                    Genesis::from_wire(record).map_err(|e| RejectReason::for_error(&e))?;
                let mut store = lock(&self.store);
                if !local
                    && store.genesis(&genesis.channel_id()).is_none()
                    && !self.rooms.may_anchor(&genesis)
                {
                    return Err(RejectReason::Policy);
                }
                // Credited only to its creator: anyone can bring a room's genesis (see `wrote`).
                let creator = genesis.body.creator_pubkey.fingerprint();
                let source = source.filter(|_| wrote(publisher, &creator));
                store.accept_genesis(genesis, local, now, source)
            }
            // A signed withdraw (V030-14): a member's own records, or a whole room, off this
            // board at once — and kept off.
            StructTag::BoardWithdraw => {
                use crate::nat::withdraw::{BoardWithdraw, WithdrawScope};
                let w =
                    BoardWithdraw::from_wire(record).map_err(|e| RejectReason::for_error(&e))?;
                let mut store = lock(&self.store);
                let key = match w.scope {
                    WithdrawScope::Member => {
                        self.known_key(&store, &w.channel_id, w.epoch, &w.author_id, now)
                    }
                    // The creator, or a member its current roster names: an admin whose admin
                    // was taken back is refused.
                    WithdrawScope::Room => {
                        let creator = store
                            .genesis(&w.channel_id)
                            .map(|g| g.body.creator_pubkey.clone());
                        match creator {
                            Some(c) if c.fingerprint() == w.author_id => Some(c),
                            Some(_) if store.is_roster_admin(&w.channel_id, &w.author_id) => {
                                self.known_key(&store, &w.channel_id, w.epoch, &w.author_id, now)
                            }
                            _ => None,
                        }
                    }
                };
                let Some(key) = key else {
                    return Err(RejectReason::NotMember);
                };
                w.verify(&key).map_err(|e| RejectReason::for_error(&e))?;
                match w.scope {
                    WithdrawScope::Member => {
                        store.withdraw_member(&w.channel_id, &w.author_id, w.timestamp);
                    }
                    WithdrawScope::Room => {
                        store.withdraw_room(&w.channel_id, Some(record.to_vec()));
                    }
                }
                Ok(())
            }
            // A room's admins, from its creator (V030-14).
            StructTag::AdminRoster => {
                let r = crate::nat::withdraw::AdminRoster::from_wire(record)
                    .map_err(|e| RejectReason::for_error(&e))?;
                let mut store = lock(&self.store);
                let Some(creator) = store
                    .genesis(&r.channel_id)
                    .map(|g| g.body.creator_pubkey.clone())
                else {
                    return Err(RejectReason::NotMember);
                };
                r.verify(&creator)
                    .map_err(|e| RejectReason::for_error(&e))?;
                store.accept_roster(&r.channel_id, r.timestamp_ms, r.admins);
                Ok(())
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
        source: Source,
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
            for response in self.handle(Some(&publisher), Some(source), &request) {
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
                        StructTag::BoardWithdraw if kinds.contains(RecordKinds::GENESIS) => {
                            use crate::nat::withdraw::{BoardWithdraw, WithdrawScope};
                            let w = BoardWithdraw::from_wire(&wire)?;
                            if w.channel_id != *channel_id || w.scope != WithdrawScope::Room {
                                return Err(Error::MalformedRendezvous(
                                    "rendezvous get: withdraw is not this room's end",
                                ));
                            }
                            set.ended_by = Some(w.author_id);
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
