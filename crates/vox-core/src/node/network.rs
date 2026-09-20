//! The node's network surface: the board it serves, the records it publishes, and
//! the inbound streams it dispatches (ADR-016 §"Connections, reachability and
//! sync", §"Join over the network").
//!
//! This composes the pieces M14.1–M14.7b built — [`ConnectionManager`],
//! [`RendezvousService`], [`crate::node::joinstream`],
//! [`crate::node::pairwise_stream`], [`crate::node::syncstream`] — into the flows a
//! node actually performs, while keeping the actor the single writer of channel
//! state:
//!
//! - **Serving.** [`NodeNet::accept_stream`] classifies an inbound stream against
//!   [`PeerPolicy`] and serves a `rendezvous` stream itself (the board needs no
//!   channel state). Every other kind is handed back as an [`Inbound`] for the actor
//!   to handle, because a join needs the channel passphrase, a pairwise stream needs
//!   a session, and sync needs the log.
//! - **Publishing.** [`NodeNet::publish_channel_records`] puts this node's address
//!   record and prekey bundle on an anchor's board, and
//!   [`NodeNet::publish_genesis`] puts the channel there so a cold joiner can find
//!   out what the channel *is* (ADR-007).
//! - **Fetching.** [`NodeNet::fetch_channel`] reads the board: the genesis, the
//!   members' addresses and bundles, and the pre-join records.
//!
//! ## The membership oracle is a snapshot the actor refreshes
//! The board's member-only write rule needs the channel's authenticated membership,
//! which lives in channel state the actor owns — and a served stream runs on its own
//! task. [`SharedMembership`] is the seam: the actor publishes a membership snapshot
//! whenever it changes, and the service reads it under a lock. A snapshot can only
//! be *stale by one refresh*, and staleness is safe in the conservative direction:
//! a member missing from the snapshot is refused (it retries), never wrongly
//! admitted, because the key still has to verify the record's signature.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use quinn::{RecvStream, SendStream};

use crate::error::Result;
use crate::governance::genesis::Genesis;
use crate::hash::Digest32;
use crate::identity::composite::{CompositePublicKey, RootSigner};
use crate::identity::keyagreement::X25519IdentityKey;
use crate::join::pow::Difficulty;
use crate::join::session::JoinContext;
use crate::nat::multiaddr::EndpointList;
use crate::nat::record::{MemberBundleRecord, RendezvousRecord};
use crate::nat::service::{
    MembershipOracle, RecordKinds, RecordSet, RendezvousClient, RendezvousService,
};
use crate::nat::store::RendezvousStore;
use crate::node::channel::ChannelState;
use crate::node::joinstream::{run_initiator, run_responder, JoinOutcome, ResponderConfig};
use crate::node::net::{accept_authorized, ConnectionManager, PeerPolicy};
use crate::node::prekeys::PrekeyRing;
use crate::node::store::Store;
use crate::time::Clock;
use crate::transport::quic::{VoxConnection, VoxEndpoint};
use crate::transport::streams::StreamKind;

/// The peer classification the accept path reads, refreshed by the actor whenever
/// channel membership or the pending-joiner set changes.
///
/// Same seam as [`SharedMembership`] and for the same reason: a stream is served on
/// its own task, while the policy is derived from state the actor owns. Staleness
/// fails **closed** — a peer missing from the snapshot is classified `Unknown` and
/// may open only the board.
#[derive(Clone, Default)]
pub struct SharedPolicy {
    inner: Arc<Mutex<PeerPolicy>>,
}

impl std::fmt::Debug for SharedPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedPolicy").finish_non_exhaustive()
    }
}

impl SharedPolicy {
    /// An empty policy (every peer is unknown).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the policy wholesale (the actor rebuilds it from channel state).
    pub fn replace(&self, policy: PeerPolicy) {
        *lock(&self.inner) = policy;
    }

    /// Expect a join from `joiner` until it is forgotten.
    pub fn expect_joiner(&self, joiner: Digest32) {
        lock(&self.inner).expect_joiner(joiner);
    }

    /// Stop expecting a join from `joiner`.
    pub fn forget_joiner(&self, joiner: &Digest32) -> bool {
        lock(&self.inner).forget_joiner(joiner)
    }

    /// A snapshot to authorize one stream against.
    #[must_use]
    pub fn snapshot(&self) -> PeerPolicy {
        lock(&self.inner).clone()
    }
}

/// One `(channel, epoch)` bucket's members, keyed by fingerprint.
type MemberMap = BTreeMap<Digest32, CompositePublicKey>;

/// A membership snapshot shared between the actor and the served board (see the
/// module docs).
#[derive(Clone, Default)]
pub struct SharedMembership {
    inner: Arc<Mutex<HashMap<(Digest32, u64), MemberMap>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl std::fmt::Debug for SharedMembership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedMembership")
            .field("channels", &lock(&self.inner).len())
            .finish()
    }
}

impl SharedMembership {
    /// An empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the membership for `(channel_id, epoch)`.
    pub fn set_channel(&self, channel_id: Digest32, epoch: u64, members: MemberMap) {
        lock(&self.inner).insert((channel_id, epoch), members);
    }

    /// Forget every epoch of `channel_id` (the channel was closed or locked).
    pub fn clear_channel(&self, channel_id: &Digest32) {
        lock(&self.inner).retain(|(cid, _), _| cid != channel_id);
    }

    /// The `(channel, epoch)` buckets the snapshot holds.
    #[must_use]
    pub fn channels(&self) -> Vec<(Digest32, u64)> {
        lock(&self.inner).keys().copied().collect()
    }

    /// How many `(channel, epoch)` buckets the snapshot holds.
    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.inner).len()
    }

    /// Whether the snapshot is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl MembershipOracle for SharedMembership {
    fn member_key(
        &self,
        channel_id: &Digest32,
        epoch: u64,
        author_id: &Digest32,
    ) -> Option<CompositePublicKey> {
        lock(&self.inner)
            .get(&(*channel_id, epoch))
            .and_then(|m| m.get(author_id))
            .cloned()
    }
}

/// An accepted stream the actor must handle itself, with the authenticated peer it
/// came from. A `rendezvous` stream never appears here — [`NodeNet::accept_stream`]
/// serves it.
#[derive(Debug)]
#[non_exhaustive]
pub enum Inbound {
    /// The peer is starting an ADR-005 join; the actor answers with the channel's
    /// retained passphrase and its prekey ring.
    Join {
        /// The authenticated peer.
        peer: Digest32,
        /// The stream's send half.
        send: SendStream,
        /// The stream's receive half.
        recv: RecvStream,
    },
    /// The peer is delivering a sealed control message (an SKDM).
    Pairwise {
        /// The authenticated peer.
        peer: Digest32,
        /// The stream's send half.
        send: SendStream,
        /// The stream's receive half.
        recv: RecvStream,
    },
    /// The peer wants an ADR-008 sync session.
    Sync {
        /// The authenticated peer.
        peer: Digest32,
        /// The stream's send half.
        send: SendStream,
        /// The stream's receive half.
        recv: RecvStream,
    },
    /// The board was served on this stream; nothing for the actor to do.
    ServedRendezvous {
        /// The authenticated peer.
        peer: Digest32,
    },
    /// A `tunnel` or `coord` stream: accepted and authorized, but the ADR-013 /
    /// hole-punch handlers are M15. The stream is dropped (reset), never silently
    /// left open.
    NotYetSupported {
        /// The authenticated peer.
        peer: Digest32,
        /// Which kind it was.
        kind: StreamKind,
    },
}

/// The node's network surface.
pub struct NodeNet {
    manager: Arc<ConnectionManager>,
    service: RendezvousService,
    membership: SharedMembership,
    policy: SharedPolicy,
    clock: Clock,
}

impl std::fmt::Debug for NodeNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeNet")
            .field("manager", &self.manager)
            .field("membership", &self.membership)
            .finish_non_exhaustive()
    }
}

impl NodeNet {
    /// Build the surface over a bound endpoint. The board it serves is fresh
    /// in-memory state (an anchor that persists a board is M15).
    #[must_use]
    pub fn new(endpoint: Arc<VoxEndpoint>, clock: Clock) -> Self {
        let membership = SharedMembership::new();
        let service = RendezvousService::new(
            Arc::new(Mutex::new(RendezvousStore::new())),
            Arc::new(membership.clone()),
            Arc::clone(&clock),
        );
        Self {
            manager: Arc::new(ConnectionManager::new(endpoint, Arc::clone(&clock))),
            service,
            membership,
            policy: SharedPolicy::new(),
            clock,
        }
    }

    /// The connection manager (one connection per peer).
    #[must_use]
    pub fn manager(&self) -> &Arc<ConnectionManager> {
        &self.manager
    }

    /// The membership snapshot the served board reads (the actor refreshes it).
    #[must_use]
    pub fn membership(&self) -> &SharedMembership {
        &self.membership
    }

    /// The peer policy the accept path authorizes against (the actor refreshes it).
    #[must_use]
    pub fn policy(&self) -> &SharedPolicy {
        &self.policy
    }

    /// The board this node serves.
    #[must_use]
    pub fn service(&self) -> &RendezvousService {
        &self.service
    }

    /// This node's identity fingerprint.
    #[must_use]
    pub fn local_id(&self) -> Digest32 {
        self.manager.local_id()
    }

    /// The endpoints this node advertises: its bound socket address.
    pub fn local_endpoints(&self) -> Result<EndpointList> {
        let addr = self.manager.endpoint().local_addr()?;
        EndpointList::new(vec![crate::nat::multiaddr::Multiaddr::from(addr)])
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Accept the next stream on `conn`, authorize it against the shared policy, and
    /// serve it if it is the board. Anything the actor must handle comes back as an
    /// [`Inbound`].
    pub async fn accept_stream(&self, conn: &VoxConnection) -> Result<Inbound> {
        let mut snapshot = self.policy.snapshot();
        // ADR-016's "pending pre-join identity" is a *board* fact, not a list someone
        // maintains: a joiner announces itself by publishing a pre-join record
        // (`0x0008`, self-signed, which anyone may publish), and that is what makes it
        // eligible to open a `join` stream. Consulting the board here keeps open
        // passphrase joins possible (ADR-007) without the actor having to be told
        // about every PUT — and an identity with no record stays `Unknown`, so it
        // reaches the board and nothing else.
        let peer = conn.peer_id();
        if snapshot.classify(&peer) == crate::node::net::PeerClass::Unknown
            && self.peer_has_prejoin(&peer)
        {
            snapshot.expect_joiner(peer);
        }
        self.accept_stream_with(conn, &snapshot).await
    }

    /// Whether `peer` has a live pre-join record on this board for any channel this
    /// node holds.
    #[must_use]
    pub fn peer_has_prejoin(&self, peer: &Digest32) -> bool {
        let now = self.now();
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        self.membership.channels().iter().any(|(cid, _)| {
            guard
                .current_prejoins(cid, now)
                .iter()
                .any(|r| r.asserted_id() == *peer)
        })
    }

    /// [`NodeNet::accept_stream`] against an explicit policy snapshot.
    pub async fn accept_stream_with(
        &self,
        conn: &VoxConnection,
        policy: &PeerPolicy,
    ) -> Result<Inbound> {
        let peer = conn.peer_id();
        let (kind, send, recv) = accept_authorized(conn, policy).await?;
        match kind {
            StreamKind::Rendezvous => {
                self.service.serve_stream(send, recv).await?;
                Ok(Inbound::ServedRendezvous { peer })
            }
            StreamKind::Join => Ok(Inbound::Join { peer, send, recv }),
            StreamKind::Pairwise => Ok(Inbound::Pairwise { peer, send, recv }),
            StreamKind::Sync => Ok(Inbound::Sync { peer, send, recv }),
            StreamKind::Tunnel | StreamKind::Coord => Ok(Inbound::NotYetSupported { peer, kind }),
        }
    }

    /// Put a framed record on **this node's own** board, without a network round
    /// trip. A node is its own first anchor, and it would be absurd to dial itself;
    /// the record still goes through the service's full policy, so a local publish
    /// is gated exactly like a remote one.
    pub fn publish_local(&self, record: &[u8]) -> Result<()> {
        use crate::nat::service::{RendezvousRequest, RendezvousResponse};
        let responses = self.service.handle(&RendezvousRequest::Put {
            record: record.to_vec(),
        });
        match responses.first() {
            Some(RendezvousResponse::Accepted) => Ok(()),
            Some(RendezvousResponse::Rejected(r)) => {
                Err(crate::error::Error::RendezvousRejected(r.as_str()))
            }
            _ => Err(crate::error::Error::MalformedRendezvous(
                "local publish: unexpected response",
            )),
        }
    }

    /// Build this node's own address record and prekey bundle for
    /// `(channel_id, epoch)` (the records [`NodeNet::publish_channel_records`] sends
    /// to an anchor, and [`NodeNet::publish_local`] files locally).
    pub fn own_records(
        &self,
        signer: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        ring: &PrekeyRing,
        seq: u64,
    ) -> Result<(RendezvousRecord, MemberBundleRecord)> {
        let now = self.now();
        let endpoints = self.local_endpoints()?;
        let address = RendezvousRecord::build(
            signer,
            channel_id,
            epoch,
            endpoints,
            seq,
            now,
            crate::nat::store::MAX_TTL_SECS,
        )?;
        let bundle = MemberBundleRecord::build(
            signer,
            channel_id,
            epoch,
            ring.bundle(&signer.public_key())?,
            seq,
            now,
            crate::nat::store::BUNDLE_MAX_TTL_SECS,
        )?;
        Ok((address, bundle))
    }

    /// Publish this channel's genesis to a board so a cold joiner can learn what
    /// the channel is (ADR-007). Idempotent.
    pub async fn publish_genesis(&self, conn: &VoxConnection, genesis: &Genesis) -> Result<()> {
        let mut client = RendezvousClient::open(conn).await?;
        let res = client.put(&genesis.to_wire()).await;
        client.finish();
        res
    }

    /// Publish this node's **address record** and **prekey bundle** for
    /// `(channel_id, epoch)` to a board (ADR-012 / ADR-016 M14.1).
    ///
    /// `seq` must strictly increase per `(author, channel, epoch)` and refreshes are
    /// rate-floored by the board, so the caller keeps the counter.
    pub async fn publish_channel_records(
        &self,
        conn: &VoxConnection,
        signer: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        ring: &PrekeyRing,
        seq: u64,
    ) -> Result<()> {
        let (address, bundle) = self.own_records(signer, channel_id, epoch, ring, seq)?;
        let mut client = RendezvousClient::open(conn).await?;
        let res = async {
            client.put(&address.to_wire()).await?;
            client.put(&bundle.to_wire()).await
        }
        .await;
        client.finish();
        res
    }

    /// Answer an inbound [`Inbound::Join`] as the ADR-005 **responder**, using the
    /// channel's retained passphrase (the only thing it is retained for — ADR-016
    /// M14.7c) and this identity's prekey ring.
    ///
    /// The expected joiner identity is `peer`, the fingerprint the QUIC handshake
    /// proved, so the join's proof-of-possession and the transport agree on who is on
    /// the other end. Fails with [`crate::error::Error::AtRestLocked`] if the channel
    /// has been app-locked, because the passphrase was wiped with the SEK.
    ///
    /// `ctx` is passed explicitly rather than derived here: both ends must bind the
    /// *same* parameters (including the PoW parameters) or CPace will not agree, so
    /// the binding is the caller's single decision — `ChannelState::join_context` in
    /// production.
    #[allow(clippy::too_many_arguments)] // each argument is a distinct required input
    pub async fn answer_join(
        &self,
        peer: Digest32,
        send: SendStream,
        recv: RecvStream,
        ctx: JoinContext,
        channel: &ChannelState,
        signer: &(dyn RootSigner + Send + Sync),
        store: &Store,
        ring: &mut PrekeyRing,
        pending_joins: u32,
    ) -> Result<JoinOutcome> {
        let cfg = ResponderConfig {
            ctx,
            passphrase: channel.join_passphrase()?,
            root: signer,
            base_difficulty: Difficulty::DEFAULT_INVITE,
            pending_joins,
            now_secs: self.now(),
        };
        run_responder(send, recv, peer, &cfg, store, ring).await
    }

    /// Run the ADR-005 **joiner** side against a member over `conn` (which must be
    /// authenticated as the responder this node intends to join through).
    ///
    /// `passphrase` is collected out of band by the client — never from the invite
    /// link (ADR-016).
    pub async fn start_join(
        &self,
        conn: &VoxConnection,
        ctx: JoinContext,
        passphrase: &[u8],
        signer: &(dyn RootSigner + Send + Sync),
        ik: &X25519IdentityKey,
    ) -> Result<JoinOutcome> {
        run_initiator(conn, ctx, passphrase, signer, ik).await
    }

    /// Read everything the board holds for `(channel_id, epoch)`: the genesis, the
    /// members' address and bundle records, and the pre-join records.
    ///
    /// Records come back **unverified** except the genesis (which is
    /// self-validating and bound to the channelID here); a member verifies the rest
    /// against its membership view, a joiner against the fingerprint it was given.
    pub async fn fetch_channel(
        &self,
        conn: &VoxConnection,
        channel_id: &Digest32,
        epoch: u64,
    ) -> Result<RecordSet> {
        let mut client = RendezvousClient::open(conn).await?;
        let res = client.get(channel_id, epoch, RecordKinds::ALL).await;
        client.finish();
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atrest::sek::Argon2Profile;
    use crate::identity::composite::SoftwareRootSigner;
    use crate::node::channel::ChannelState;
    use crate::node::paths::Paths;
    use crate::node::profile::Profile;
    use crate::node::store::Store;
    use crate::transport::quic::Admission;
    use crate::transport::streams::open_typed;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(20);
    const T0: u64 = 1_700_000_000;

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    fn net(s: &SoftwareRootSigner) -> Arc<NodeNet> {
        let ep = Arc::new(VoxEndpoint::bind(s, "127.0.0.1:0".parse().unwrap()).unwrap());
        Arc::new(NodeNet::new(ep, Arc::new(|| T0)))
    }

    /// The board a node serves is usable end to end: a member publishes the genesis,
    /// its address record and its prekey bundle, and a peer fetches all three; the
    /// membership snapshot is what gates the member-only writes.
    #[test]
    fn a_node_serves_its_board_and_a_peer_publishes_and_fetches() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        rt.block_on(async move {
            let anchor_s = signer(1, 2);
            let member_s = signer(3, 4);
            let anchor = net(&anchor_s);
            let member = net(&member_s);
            let anchor_id = anchor.local_id();
            let anchor_eps = anchor.local_endpoints().unwrap();
            let member_fp = member_s.fingerprint();

            // The member's channel and prekey ring.
            let paths =
                Paths::resolve("m", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
            let profile =
                Profile::create_with_profile(paths, b"id-pp", T0, Argon2Profile::REDUCED).unwrap();
            let ch = ChannelState::create_with_profile(
                &profile,
                "team",
                b"ch-pp",
                T0,
                Argon2Profile::REDUCED,
            )
            .unwrap();
            let cid = ch.channel_id();
            let store = Store::open(&tmp.path().join("ring.redb")).unwrap();
            let (ring, _) =
                crate::node::prekeys::load_or_create(&store, &member_s, &[0x5C; 32], T0).unwrap();

            // The anchor knows this member for this channel (in the node, the actor
            // refreshes this snapshot from channel state).
            let mut members = BTreeMap::new();
            members.insert(member_fp, member_s.public_key());
            anchor.membership().set_channel(cid, 0, members);
            assert_eq!(anchor.membership().len(), 1);

            // The anchor serves: any authenticated peer may reach the board.
            let serving = {
                let anchor = Arc::clone(&anchor);
                tokio::spawn(async move {
                    let conn = anchor
                        .manager()
                        .accept(Admission::AcceptAnyAuthenticated)
                        .await
                        .unwrap()
                        .unwrap();
                    let policy = PeerPolicy::new(); // the member is "unknown": board only
                    let mut served = Vec::new();
                    for _ in 0..3 {
                        served.push(anchor.accept_stream_with(&conn, &policy).await.unwrap());
                    }
                    (served, conn)
                })
            };

            let conn =
                tokio::time::timeout(TIMEOUT, member.manager().connect(anchor_id, &anchor_eps))
                    .await
                    .unwrap()
                    .unwrap();

            // Publish the genesis, then this member's records, then read it all back.
            member.publish_genesis(&conn, ch.genesis()).await.unwrap();
            member
                .publish_channel_records(&conn, &member_s, &cid, 0, &ring, 1)
                .await
                .unwrap();
            let set = member.fetch_channel(&conn, &cid, 0).await.unwrap();

            assert_eq!(
                set.genesis.as_ref().map(Genesis::channel_id),
                Some(cid),
                "the board serves the genesis a cold joiner needs"
            );
            assert_eq!(set.members.len(), 1);
            assert_eq!(set.bundles.len(), 1);
            assert!(set.prejoins.is_empty());
            // Verified against the membership the fetcher already trusts.
            set.members[0].verify(&member_s.public_key()).unwrap();
            set.bundles[0].verify(&member_s.public_key()).unwrap();
            assert_eq!(
                set.bundles[0].prekey_bundle.root_pub,
                member_s.public_key().to_bytes()
            );

            let (served, _conn) = tokio::time::timeout(TIMEOUT, serving)
                .await
                .unwrap()
                .unwrap();
            assert!(served
                .iter()
                .all(|i| matches!(i, Inbound::ServedRendezvous { .. })));
            anchor.manager().close_all();
            member.manager().close_all();
        });
    }

    /// A stale membership snapshot fails closed: a member the snapshot does not name
    /// is refused, and admitted once the snapshot catches up.
    #[test]
    fn an_unknown_member_is_refused_until_the_snapshot_names_it() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        rt.block_on(async move {
            let anchor_s = signer(11, 12);
            let member_s = signer(13, 14);
            let anchor = net(&anchor_s);
            let member = net(&member_s);
            let anchor_id = anchor.local_id();
            let anchor_eps = anchor.local_endpoints().unwrap();
            let cid = [0x5A; 32];
            let store = Store::open(&tmp.path().join("ring.redb")).unwrap();
            let (ring, _) =
                crate::node::prekeys::load_or_create(&store, &member_s, &[0x5C; 32], T0).unwrap();

            let serving = {
                let anchor = Arc::clone(&anchor);
                tokio::spawn(async move {
                    let conn = anchor
                        .manager()
                        .accept(Admission::AcceptAnyAuthenticated)
                        .await
                        .unwrap()
                        .unwrap();
                    let policy = PeerPolicy::new();
                    // Two rendezvous streams: before and after the refresh.
                    let a = anchor.accept_stream_with(&conn, &policy).await;
                    let b = anchor.accept_stream_with(&conn, &policy).await;
                    (a, b, conn)
                })
            };
            let conn =
                tokio::time::timeout(TIMEOUT, member.manager().connect(anchor_id, &anchor_eps))
                    .await
                    .unwrap()
                    .unwrap();

            // Not in the snapshot: the member-only write is refused, not admitted.
            let err = member
                .publish_channel_records(&conn, &member_s, &cid, 0, &ring, 1)
                .await
                .expect_err("an unnamed member cannot publish");
            assert!(
                matches!(err, crate::error::Error::RendezvousRejected(_)),
                "{err:?}"
            );

            // The actor refreshes the snapshot; the same publish now succeeds.
            let mut members = BTreeMap::new();
            members.insert(member_s.fingerprint(), member_s.public_key());
            anchor.membership().set_channel(cid, 0, members);
            member
                .publish_channel_records(&conn, &member_s, &cid, 0, &ring, 2)
                .await
                .unwrap();

            // Clearing the channel forgets it again.
            anchor.membership().clear_channel(&cid);
            assert!(anchor.membership().is_empty());

            let (_a, _b, _conn) = tokio::time::timeout(TIMEOUT, serving)
                .await
                .unwrap()
                .unwrap();
            anchor.manager().close_all();
            member.manager().close_all();
        });
    }

    /// Streams the actor must handle come back as `Inbound`, and a kind whose
    /// handler is M15 is surfaced rather than silently ignored.
    #[test]
    fn streams_needing_channel_state_are_handed_to_the_actor() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let server_s = signer(21, 22);
            let client_s = signer(23, 24);
            let server = net(&server_s);
            let client = net(&client_s);
            let server_id = server.local_id();
            let server_eps = server.local_endpoints().unwrap();
            // The peer is a member, so every kind is authorized.
            let mut policy = PeerPolicy::new();
            policy.add_members([client.local_id()]);

            let serving = {
                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    let conn = server
                        .manager()
                        .accept(Admission::AcceptAnyAuthenticated)
                        .await
                        .unwrap()
                        .unwrap();
                    let mut out = Vec::new();
                    for _ in 0..4 {
                        out.push(server.accept_stream_with(&conn, &policy).await.unwrap());
                    }
                    (out, conn)
                })
            };
            let conn =
                tokio::time::timeout(TIMEOUT, client.manager().connect(server_id, &server_eps))
                    .await
                    .unwrap()
                    .unwrap();
            for kind in [
                StreamKind::Join,
                StreamKind::Pairwise,
                StreamKind::Sync,
                StreamKind::Coord,
            ] {
                let (mut send, _recv) = open_typed(&conn, kind).await.unwrap();
                let _ = send.write(b"x").await;
            }
            let (out, _conn) = tokio::time::timeout(TIMEOUT, serving)
                .await
                .unwrap()
                .unwrap();
            let client_fp = client.local_id();
            assert!(matches!(out[0], Inbound::Join { peer, .. } if peer == client_fp));
            assert!(matches!(out[1], Inbound::Pairwise { peer, .. } if peer == client_fp));
            assert!(matches!(out[2], Inbound::Sync { peer, .. } if peer == client_fp));
            assert!(matches!(
                out[3],
                Inbound::NotYetSupported {
                    kind: StreamKind::Coord,
                    ..
                }
            ));
            server.manager().close_all();
            client.manager().close_all();
        });
    }
    /// The whole ADR-016 §"Join over the network" flow over loopback QUIC and through
    /// the board: the member files its genesis and records on its own board, the
    /// joiner reads them, joins with the out-of-band passphrase, and both ends hold
    /// the same pairwise session. The responder answers using the passphrase it
    /// retains while the channel is open (M14.7c).
    #[test]
    fn a_joiner_finds_a_channel_on_the_board_and_completes_a_join_through_it() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        rt.block_on(async {
            // --- Alice: identity, channel, ring, and her own board ---
            let alice_paths =
                Paths::resolve("alice", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
            let alice_p =
                Profile::create_with_profile(alice_paths, b"alice-id", T0, Argon2Profile::REDUCED)
                    .unwrap();
            let alice_signer = alice_p.signer().unwrap();
            let alice_fp = alice_p.fingerprint();
            let alice_net = {
                let ep = Arc::new(
                    VoxEndpoint::bind(alice_signer, "127.0.0.1:0".parse().unwrap()).unwrap(),
                );
                NodeNet::new(ep, Arc::new(|| T0))
            };
            // The node's network identity IS the channel identity, which is what lets
            // the join's proof-of-possession and the QUIC handshake agree.
            assert_eq!(alice_net.local_id(), alice_fp);

            let channel = ChannelState::create_with_profile(
                &alice_p,
                "team",
                b"channel-pp",
                T0,
                Argon2Profile::REDUCED,
            )
            .unwrap();
            let cid = channel.channel_id();
            assert!(channel.can_answer_join());
            let dh = *alice_signer.x25519_identity_secret();
            let ring_store = Store::open(&tmp.path().join("alice-ring.redb")).unwrap();
            let (mut alice_ring, _) =
                crate::node::prekeys::load_or_create(&ring_store, alice_signer, &dh, T0).unwrap();

            // Her board must know she is a member before it accepts her records.
            let mut members = BTreeMap::new();
            members.insert(alice_fp, RootSigner::public_key(alice_signer));
            alice_net.membership().set_channel(cid, 0, members);

            // She files the genesis and her own records locally — no self-dial.
            alice_net
                .publish_local(&channel.genesis().to_wire())
                .unwrap();
            let (address, bundle) = alice_net
                .own_records(alice_signer, &cid, 0, &alice_ring, 1)
                .unwrap();
            alice_net.publish_local(&address.to_wire()).unwrap();
            alice_net.publish_local(&bundle.to_wire()).unwrap();

            // --- Bob: identity + ring, no channel yet ---
            let bob_paths =
                Paths::resolve("bob", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
            let bob_p =
                Profile::create_with_profile(bob_paths, b"bob-id", T0, Argon2Profile::REDUCED)
                    .unwrap();
            let bob_signer = bob_p.signer().unwrap();
            let bob_fp = bob_p.fingerprint();
            let bob_net = {
                let ep = Arc::new(
                    VoxEndpoint::bind(bob_signer, "127.0.0.1:0".parse().unwrap()).unwrap(),
                );
                NodeNet::new(ep, Arc::new(|| T0))
            };
            let bob_dh = *bob_signer.x25519_identity_secret();
            let bob_ring_store = Store::open(&tmp.path().join("bob-ring.redb")).unwrap();
            let (_bob_ring, _) =
                crate::node::prekeys::load_or_create(&bob_ring_store, bob_signer, &bob_dh, T0)
                    .unwrap();

            // The invite link Alice hands out: rendezvous only, no secret.
            let link = crate::node::link::InviteLink::new(
                cid,
                alice_net.local_endpoints().unwrap(),
                Some(alice_fp),
            )
            .unwrap();
            let parsed = crate::node::link::InviteLink::parse(&link.to_url()).unwrap();
            assert_eq!(parsed.channel_id, cid);
            assert_eq!(parsed.responder, Some(alice_fp));

            // Alice expects this joiner: the pending-joiner class opens `join` and the
            // board, nothing else.
            let mut policy = PeerPolicy::new();
            policy.expect_joiner(bob_fp);

            // Both ends bind the same parameters, with the PoW reduced so the debug
            // suite does not grind (200,9) — the production parameters are exercised
            // by the release-only gate.
            let ctx = {
                let mut c =
                    crate::node::channel::join_context_from_genesis(channel.genesis(), 0).unwrap();
                c.pow_params = crate::join::pow::PowParams::new(48, 5).unwrap();
                c
            };

            // Both halves on one task: the joiner's requests interleave with Alice's
            // serve loop at the await points, which is what a request/response
            // protocol needs.
            // Boxed: these futures hold bundles, records and sessions, and two of
            // them inline on the test thread's stack overflows it.
            let serve = Box::pin(async {
                let conn = alice_net
                    .manager()
                    .accept(Admission::AcceptAnyAuthenticated)
                    .await
                    .unwrap()
                    .unwrap();
                let peer = conn.peer_id();
                assert_eq!(peer, bob_fp);
                loop {
                    match alice_net.accept_stream_with(&conn, &policy).await.unwrap() {
                        Inbound::ServedRendezvous { .. } => {}
                        Inbound::Join { send, mut recv, .. } => {
                            // The joiner names the channel before we choose one.
                            let (want, epoch) =
                                crate::node::joinstream::read_join_request(&mut recv)
                                    .await
                                    .unwrap();
                            assert_eq!(want, cid);
                            assert_eq!(epoch, 0);
                            break alice_net
                                .answer_join(
                                    peer,
                                    send,
                                    recv,
                                    ctx,
                                    &channel,
                                    alice_signer,
                                    &ring_store,
                                    &mut alice_ring,
                                    0,
                                )
                                .await;
                        }
                        other => panic!("unexpected inbound {other:?}"),
                    }
                }
            });

            let join = Box::pin(async {
                let conn = bob_net
                    .manager()
                    .connect(parsed.responder.unwrap(), &parsed.anchors)
                    .await
                    .unwrap();
                let set = bob_net
                    .fetch_channel(&conn, &parsed.channel_id, 0)
                    .await
                    .unwrap();
                let genesis = set.genesis.clone().expect("the board served the genesis");
                assert_eq!(genesis.channel_id(), cid);
                assert_eq!(set.bundles.len(), 1, "Alice's bundle is on the board");
                assert_eq!(set.members.len(), 1);
                // The passphrase comes from the user out of band, never from the link.
                // Bob derives the binding from the *fetched* genesis and must land on
                // exactly the values Alice did.
                let mut bob_ctx =
                    crate::node::channel::join_context_from_genesis(&genesis, 0).unwrap();
                assert_eq!(bob_ctx.channel_id, cid);
                assert_eq!(bob_ctx.suite_id, crate::suite::VOX_SUITE_1.id);
                bob_ctx.pow_params = crate::join::pow::PowParams::new(48, 5).unwrap();
                let ik =
                    crate::identity::keyagreement::X25519IdentityKey::from_secret_bytes(bob_dh);
                let outcome = bob_net
                    .start_join(&conn, bob_ctx, b"channel-pp", bob_signer, &ik)
                    .await;
                (outcome, genesis, conn)
            });

            let (alice_out, (bob_out, genesis, _conn)) =
                tokio::time::timeout(TIMEOUT, async { tokio::join!(serve, join) })
                    .await
                    .unwrap();
            let mut alice_session = alice_out.expect("Alice answered the join").session;
            let mut bob_session = bob_out.expect("Bob completed the join").session;

            // The two ends agree, and each bound the other's identity.
            let msg = bob_session.encrypt(b"joined").unwrap();
            assert_eq!(alice_session.decrypt(&msg, T0).unwrap(), b"joined");
            let reply = alice_session.encrypt(b"welcome").unwrap();
            assert_eq!(bob_session.decrypt(&reply, T0).unwrap(), b"welcome");

            // Bob builds his local channel state from the board's genesis — and
            // joining has released no keys, so he can read nothing yet (ADR-007).
            let bob_channel = ChannelState::join_channel_with_profile(
                &bob_p,
                &genesis,
                &cid,
                "team",
                b"channel-pp",
                T0,
                Argon2Profile::REDUCED,
            )
            .unwrap();
            assert_eq!(bob_channel.channel_id(), cid);
            assert!(
                bob_channel.is_author(&alice_fp),
                "creator admitted from genesis"
            );
            assert!(bob_channel.timeline().is_empty(), "joining reads nothing");
            assert!(
                channel.can_answer_join(),
                "Alice still holds her passphrase"
            );

            alice_net.manager().close_all();
            bob_net.manager().close_all();
        });
    }
}
