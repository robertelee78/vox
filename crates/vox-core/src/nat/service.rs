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
/// most this many live records for one `(channelID, epoch)`.
pub const MAX_GET_RECORDS: usize = 2 * MAX_AUTHORS_PER_BUCKET + MAX_PREJOIN_PER_CHANNEL;

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
    /// Every kind.
    pub const ALL: Self = Self(0b111);

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
    /// Replay, refresh too fast, zero/over-long TTL, expired or future-dated.
    Policy = 3,
    /// The `(channelID, epoch)` bucket is full.
    Capacity = 4,
    /// The frame's struct tag is not a rendezvous record kind.
    UnknownKind = 5,
}

impl RejectReason {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::NotMember),
            2 => Some(Self::Malformed),
            3 => Some(Self::Policy),
            4 => Some(Self::Capacity),
            5 => Some(Self::UnknownKind),
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
        }
    }

    /// Classify a store/parse error.
    fn for_error(err: &Error) -> Self {
        match err {
            Error::RendezvousRejected("author is not a channel member") => Self::NotMember,
            Error::RendezvousRejected(s) if s.ends_with("at capacity") => Self::Capacity,
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
/// module docs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordSet {
    /// Member address records.
    pub members: Vec<RendezvousRecord>,
    /// Member bundle records.
    pub bundles: Vec<MemberBundleRecord>,
    /// Pre-join records.
    pub prejoins: Vec<PreJoinRecord>,
}

/// The server side: a [`RendezvousStore`] behind a lock, the membership oracle
/// and a clock. Clone-cheap (`Arc`s) so one service serves every connection.
#[derive(Clone)]
pub struct RendezvousService {
    store: Arc<Mutex<RendezvousStore>>,
    oracle: Arc<dyn MembershipOracle>,
    clock: Clock,
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
        }
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
    pub fn handle(&self, request: &RendezvousRequest) -> Vec<RendezvousResponse> {
        let now = (self.clock)();
        match request {
            RendezvousRequest::Put { record } => vec![match self.put(record, now) {
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
                drop(store);
                out.push(RendezvousResponse::End);
                out
            }
        }
    }

    /// Admit one framed record by its struct tag.
    fn put(&self, record: &[u8], now: u64) -> std::result::Result<(), RejectReason> {
        let tag = parse_frame(record)
            .map(|f| f.tag)
            .map_err(|e| RejectReason::for_error(&e))?;
        let res = match tag {
            StructTag::RendezvousRecord => {
                let rec =
                    RendezvousRecord::from_wire(record).map_err(|e| RejectReason::for_error(&e))?;
                let (cid, epoch) = (rec.channel_id, rec.epoch);
                lock(&self.store).accept_member(
                    rec,
                    |author| self.oracle.member_key(&cid, epoch, author),
                    now,
                )
            }
            StructTag::MemberBundleRecord => {
                let rec = MemberBundleRecord::from_wire(record)
                    .map_err(|e| RejectReason::for_error(&e))?;
                let (cid, epoch) = (rec.channel_id, rec.epoch);
                lock(&self.store).accept_bundle(
                    rec,
                    |author| self.oracle.member_key(&cid, epoch, author),
                    now,
                )
            }
            StructTag::PreJoinRecord => {
                let rec =
                    PreJoinRecord::from_wire(record).map_err(|e| RejectReason::for_error(&e))?;
                lock(&self.store).accept_prejoin(rec, now)
            }
            _ => return Err(RejectReason::UnknownKind),
        };
        res.map_err(|e| RejectReason::for_error(&e))
    }

    /// Serve one already-typed rendezvous stream until the peer half-closes
    /// (`Ok`) or sends something that is not a request (the stream is reset with
    /// the coded close and the error returned). Never holds the store lock across
    /// an `await`.
    pub async fn serve_stream(&self, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
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
            for response in self.handle(&request) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::{RootSigner, SoftwareRootSigner};
    use crate::identity::keyagreement::{PrekeyBundlePublic, SignedIdentityDhKey, SignedPrekey};
    use crate::nat::multiaddr::{EndpointList, Multiaddr};
    use crate::nat::store::MAX_TTL_SECS;
    use crate::transport::quic::VoxEndpoint;
    use crate::transport::streams::accept_typed;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(10);
    const T0: u64 = 1_700_000_000;

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    fn eps(d: u8) -> EndpointList {
        EndpointList::new(vec![Multiaddr::Ip4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, d),
            4433,
        ))])
        .unwrap()
    }

    fn bundle(s: &SoftwareRootSigner) -> PrekeyBundlePublic {
        let idk = SignedIdentityDhKey::generate(s, T0).unwrap();
        let spk = SignedPrekey::generate(s, 1, T0).unwrap();
        PrekeyBundlePublic {
            root_pub: s.public_key().to_bytes(),
            identity_dh_key: idk.public().clone(),
            identity_dh_key_sig: idk.signature().to_bytes(),
            signed_prekey: spk.public().clone(),
            signed_prekey_sig: spk.signature().to_bytes(),
            one_time_prekey: None,
            one_time_prekey_sig: None,
        }
    }

    /// A fixed membership: `(channel, epoch)` → member keys.
    struct FixedMembers {
        channel_id: Digest32,
        epoch: u64,
        members: Vec<CompositePublicKey>,
    }
    impl MembershipOracle for FixedMembers {
        fn member_key(
            &self,
            channel_id: &Digest32,
            epoch: u64,
            author_id: &Digest32,
        ) -> Option<CompositePublicKey> {
            if *channel_id != self.channel_id || epoch != self.epoch {
                return None;
            }
            self.members
                .iter()
                .find(|k| k.fingerprint() == *author_id)
                .cloned()
        }
    }

    fn service(cid: Digest32, epoch: u64, members: &[&SoftwareRootSigner]) -> RendezvousService {
        RendezvousService::new(
            Arc::new(Mutex::new(RendezvousStore::new())),
            Arc::new(FixedMembers {
                channel_id: cid,
                epoch,
                members: members.iter().map(|s| s.public_key()).collect(),
            }),
            Arc::new(|| T0 + 10),
        )
    }

    #[test]
    fn request_and_response_frames_round_trip_and_reject_malformed() {
        let cid = [5u8; 32];
        for req in [
            RendezvousRequest::Put {
                record: vec![1, 2, 3],
            },
            RendezvousRequest::Get {
                channel_id: cid,
                epoch: 9,
                kinds: RecordKinds::MEMBERS.or(RecordKinds::PREJOINS),
            },
        ] {
            assert_eq!(RendezvousRequest::from_frame(&req.to_frame()).unwrap(), req);
        }
        for resp in [
            RendezvousResponse::Accepted,
            RendezvousResponse::Rejected(RejectReason::Capacity),
            RendezvousResponse::Record(vec![9; 40]),
            RendezvousResponse::End,
        ] {
            assert_eq!(
                RendezvousResponse::from_frame(&resp.to_frame()).unwrap(),
                resp
            );
        }
        // Unknown op, wrong arity, bad kinds bits, unknown reject reason.
        let mut e = Encoder::new();
        e.array(2).uint(7).bytes(&[]);
        assert!(matches!(
            RendezvousRequest::from_frame(&e.finish()),
            Err(Error::MalformedRendezvous("rendezvous request op"))
        ));
        let mut e = Encoder::new();
        e.array(3).uint(OP_GET).bytes(&cid).uint(1);
        assert!(RendezvousRequest::from_frame(&e.finish()).is_err());
        let mut e = Encoder::new();
        e.array(4).uint(OP_GET).bytes(&cid).uint(1).uint(8);
        assert!(matches!(
            RendezvousRequest::from_frame(&e.finish()),
            Err(Error::MalformedRendezvous("rendezvous get kinds"))
        ));
        assert!(RecordKinds::from_bits(0).is_err());
        let mut e = Encoder::new();
        e.array(2).uint(OP_REJECTED).uint(9);
        assert!(matches!(
            RendezvousResponse::from_frame(&e.finish()),
            Err(Error::MalformedRendezvous("rendezvous reject reason"))
        ));
        // A request frame is never mistaken for a response with the same op.
        let put = RendezvousRequest::Put { record: vec![] }.to_frame();
        assert!(RendezvousResponse::from_frame(&put).is_err());
    }

    #[test]
    fn handle_gates_every_kind_through_the_store_policy() {
        let a = signer(1, 2);
        let b = signer(3, 4);
        let stranger = signer(5, 6);
        let cid = [7u8; 32];
        let svc = service(cid, 1, &[&a, &b]);
        let put = |wire: Vec<u8>| svc.handle(&RendezvousRequest::Put { record: wire });

        // Member address record from a member: accepted; replayed: policy.
        let ma = RendezvousRecord::build(&a, &cid, 1, eps(1), 1, T0, MAX_TTL_SECS).unwrap();
        assert_eq!(put(ma.to_wire()), vec![RendezvousResponse::Accepted]);
        assert_eq!(
            put(ma.to_wire()),
            vec![RendezvousResponse::Rejected(RejectReason::Policy)]
        );
        // From a non-member: not a member — even with a valid signature.
        let ms = RendezvousRecord::build(&stranger, &cid, 1, eps(2), 1, T0, 60).unwrap();
        assert_eq!(
            put(ms.to_wire()),
            vec![RendezvousResponse::Rejected(RejectReason::NotMember)]
        );
        // Wrong epoch: the oracle knows no members there.
        let me = RendezvousRecord::build(&a, &cid, 2, eps(1), 1, T0, 60).unwrap();
        assert_eq!(
            put(me.to_wire()),
            vec![RendezvousResponse::Rejected(RejectReason::NotMember)]
        );
        // Bundle record from a member: accepted; tampered: malformed.
        let mb = MemberBundleRecord::build(&b, &cid, 1, bundle(&b), 1, T0, 3600).unwrap();
        let mut tampered = mb.to_wire();
        let n = tampered.len();
        tampered[n - 1] ^= 1;
        assert_eq!(put(mb.to_wire()), vec![RendezvousResponse::Accepted]);
        assert_eq!(
            put(tampered),
            vec![RendezvousResponse::Rejected(RejectReason::Malformed)]
        );
        // Pre-join from anyone: accepted (self-verifying).
        let pj = PreJoinRecord::build(&stranger, &cid, bundle(&stranger), eps(9), 1, T0).unwrap();
        assert_eq!(put(pj.to_wire()), vec![RendezvousResponse::Accepted]);
        // A framed struct that is not a rendezvous record: unknown kind.
        let genesis_like = crate::wire::frame(StructTag::LogEntry, &[0x80]);
        assert_eq!(
            put(genesis_like),
            vec![RendezvousResponse::Rejected(RejectReason::UnknownKind)]
        );
        // Garbage bytes: malformed (not a stream reset — it is a PUT body).
        assert_eq!(
            put(vec![0xFF; 5]),
            vec![RendezvousResponse::Rejected(RejectReason::Malformed)]
        );

        // GET by kinds.
        let get = |kinds| {
            svc.handle(&RendezvousRequest::Get {
                channel_id: cid,
                epoch: 1,
                kinds,
            })
        };
        let all = get(RecordKinds::ALL);
        assert_eq!(all.len(), 4, "member + bundle + prejoin + End");
        assert_eq!(all.last(), Some(&RendezvousResponse::End));
        let only_bundles = get(RecordKinds::BUNDLES);
        assert_eq!(
            only_bundles,
            vec![
                RendezvousResponse::Record(mb.to_wire()),
                RendezvousResponse::End
            ]
        );
        assert_eq!(
            svc.handle(&RendezvousRequest::Get {
                channel_id: [8u8; 32],
                epoch: 1,
                kinds: RecordKinds::ALL
            }),
            vec![RendezvousResponse::End]
        );
    }

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    /// The loopback exchange: a member publishes all three kinds and reads them
    /// back; a stranger reads (the channelID is the capability) but cannot
    /// publish a member record; a garbage frame resets the stream with the
    /// coded close; a clean half-close ends the server task with `Ok`.
    #[test]
    fn loopback_put_get_reject_and_reset_over_quic() {
        let rt = runtime();
        let anchor = signer(10, 11);
        let member = signer(12, 13);
        let stranger = signer(14, 15);
        let cid = [0xC1u8; 32];
        let anchor_id = anchor.fingerprint();
        let svc = service(cid, 3, &[&anchor, &member]);
        let svc_server = svc.clone();

        rt.block_on(async move {
            let server_ep = VoxEndpoint::bind(&anchor, loopback()).unwrap();
            let server_addr = server_ep.local_addr().unwrap();

            // The anchor: accept connections, dispatch typed streams, serve.
            let server = tokio::spawn(async move {
                let mut outcomes = Vec::new();
                let mut conns = Vec::new();
                for _ in 0..3 {
                    let conn = server_ep.accept(T0).await.unwrap().unwrap();
                    let (kind, send, recv) = accept_typed(&conn).await.unwrap();
                    assert_eq!(kind, StreamKind::Rendezvous);
                    outcomes.push(svc_server.serve_stream(send, recv).await);
                    conns.push(conn);
                }
                // Hand the connections and endpoint back so they outlive the
                // clients' final reads: dropping a connection closes it with code
                // 0, which would race the stream reset the last client asserts on
                // (the connection manager keeps connections open in production).
                (outcomes, conns, server_ep)
            });

            // 1. The member publishes its address, bundle and (as if joining a
            //    second time) a pre-join record, then reads everything back.
            let member_ep = VoxEndpoint::bind(&member, loopback()).unwrap();
            let conn = tokio::time::timeout(TIMEOUT, member_ep.connect(server_addr, anchor_id, T0))
                .await
                .unwrap()
                .unwrap();
            let mut client = RendezvousClient::open(&conn).await.unwrap();
            let addr =
                RendezvousRecord::build(&member, &cid, 3, eps(1), 1, T0, MAX_TTL_SECS).unwrap();
            let bund =
                MemberBundleRecord::build(&member, &cid, 3, bundle(&member), 1, T0, 3600).unwrap();
            let pre =
                PreJoinRecord::build(&stranger, &cid, bundle(&stranger), eps(2), 1, T0).unwrap();
            client.put(&addr.to_wire()).await.unwrap();
            client.put(&bund.to_wire()).await.unwrap();
            client.put(&pre.to_wire()).await.unwrap();
            // Replay is refused with the coded reason, on the same stream.
            assert!(matches!(
                client.put(&addr.to_wire()).await,
                Err(Error::RendezvousRejected("rejected: policy"))
            ));
            let set = client.get(&cid, 3, RecordKinds::ALL).await.unwrap();
            assert_eq!(set.members, vec![addr.clone()]);
            assert_eq!(set.bundles, vec![bund.clone()]);
            assert_eq!(set.prejoins, vec![pre.clone()]);
            set.members[0].verify(&member.public_key()).unwrap();
            let only = client.get(&cid, 3, RecordKinds::BUNDLES).await.unwrap();
            assert!(only.members.is_empty() && only.prejoins.is_empty());
            assert_eq!(only.bundles, vec![bund.clone()]);
            client.finish();

            // 2. A stranger who knows the channelID reads the board but cannot
            //    publish a member record.
            let stranger_ep = VoxEndpoint::bind(&stranger, loopback()).unwrap();
            let conn2 =
                tokio::time::timeout(TIMEOUT, stranger_ep.connect(server_addr, anchor_id, T0))
                    .await
                    .unwrap()
                    .unwrap();
            let mut c2 = RendezvousClient::open(&conn2).await.unwrap();
            let forged = RendezvousRecord::build(&stranger, &cid, 3, eps(7), 1, T0, 60).unwrap();
            assert!(matches!(
                c2.put(&forged.to_wire()).await,
                Err(Error::RendezvousRejected(
                    "rejected: author is not a channel member"
                ))
            ));
            let seen = c2.get(&cid, 3, RecordKinds::MEMBERS).await.unwrap();
            assert_eq!(seen.members, vec![addr]);
            c2.finish();

            // 3. A frame that is not a request: the server resets the stream with
            //    the coded close and the client's next read fails.
            let conn3 =
                tokio::time::timeout(TIMEOUT, stranger_ep.connect(server_addr, anchor_id, T0))
                    .await
                    .unwrap()
                    .unwrap();
            let (mut send, mut recv) = open_typed(&conn3, StreamKind::Rendezvous).await.unwrap();
            write_frame(&mut send, &[0xFF, 0x00]).await.unwrap();
            let mut buf = [0u8; 4];
            let res = tokio::time::timeout(TIMEOUT, recv.read_exact(&mut buf))
                .await
                .unwrap();
            // The peer observes the ADR-008 code (a CBOR-malformed request maps
            // to AuthenticatorInvalid, 0x05) — never a silent close.
            let expected = close_code(crate::wire::WireError::AuthenticatorInvalid);
            assert!(
                matches!(
                    res,
                    Err(quinn::ReadExactError::ReadError(quinn::ReadError::Reset(code))) if code == expected
                ),
                "expected a coded reset, got {res:?}"
            );

            let (outcomes, conns, server_ep) = tokio::time::timeout(TIMEOUT, server)
                .await
                .unwrap()
                .unwrap();
            assert!(outcomes[0].is_ok(), "member stream ended cleanly");
            assert!(outcomes[1].is_ok(), "stranger stream ended cleanly");
            assert!(
                matches!(
                    outcomes[2],
                    Err(Error::MalformedRendezvous(_)) | Err(Error::Cbor(_))
                ),
                "garbage frame is a coded failure: {:?}",
                outcomes[2]
            );
            // The store holds exactly what was admitted.
            let store = svc.store().lock().unwrap();
            assert_eq!(store.current_members(&cid, 3, T0 + 10).len(), 1);
            assert_eq!(store.current_bundles(&cid, 3, T0 + 10).len(), 1);
            assert_eq!(store.current_prejoins(&cid, T0 + 10).len(), 1);
            drop(store);
            drop(conns);
            server_ep.close();
        });
    }
}
