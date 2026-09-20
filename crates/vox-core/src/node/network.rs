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
use tokio::task::JoinSet;

use crate::error::{Error, Result};
use crate::governance::genesis::Genesis;
use crate::hash::Digest32;
use crate::identity::composite::{CompositePublicKey, RootSigner};
use crate::identity::keyagreement::X25519IdentityKey;
use crate::join::pow::Difficulty;
use crate::join::session::JoinContext;
use crate::nat::multiaddr::{EndpointList, Multiaddr};
use crate::nat::reachability::{connect_direct, direct_candidates};
use crate::nat::record::{MemberBundleRecord, RendezvousRecord};
use crate::nat::service::{
    MembershipOracle, RecordKinds, RecordSet, RendezvousClient, RendezvousService,
};
use crate::nat::store::RendezvousStore;
use crate::node::channel::ChannelState;
use crate::node::circuitstream::{self, CircuitLedger};
use crate::node::coordstream;
use crate::node::joinstream::{run_initiator, run_responder, JoinOutcome, ResponderConfig};
use crate::node::net::{accept_authorized, ConnectionManager, PeerClass, PeerPolicy};
use crate::node::prekeys::PrekeyRing;
use crate::node::store::Store;
use crate::time::Clock;
use crate::transport::quic::{VoxConnection, VoxEndpoint};
use crate::transport::streams::accept_typed;
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
    /// A coord stream was served (a `WHOAMI` answered); nothing for the actor to do.
    ServedCoord {
        /// The authenticated peer.
        peer: Digest32,
    },
    /// A circuit stream was opened — relayed onward, or terminated here — and now
    /// runs on its own task; nothing for the actor to do. A connection that arrives
    /// through it comes in by the accept loop like any other.
    ServedCircuit {
        /// The authenticated peer.
        peer: Digest32,
    },
    /// A coordinator has relayed a punch session to this node: the DCUtR exchange is
    /// still to be run on these streams, and then the synchronized dial fired. The
    /// actor spawns it, because it takes seconds and must not block the coordinator's
    /// other streams.
    Punch {
        /// The peer on the far side of the relay — the one to punch to.
        peer: Digest32,
        /// The coordinator that carried the session.
        coordinator: Digest32,
        /// The session's send half.
        send: SendStream,
        /// The session's receive half.
        recv: RecvStream,
    },
    /// A `tunnel` stream: accepted and authorized, but the ADR-013 handler is M15.
    /// The stream is dropped (reset), never silently left open.
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
    /// The endpoints this node advertises, composed by the ADR-012 ladder's publish
    /// side rather than taken from the bound socket — a node that binds the wildcard
    /// has no single bound address to publish, and a node behind NAT needs its
    /// *mapped* address. Refreshed by [`NodeNet::refresh_advertised`].
    advertised: Mutex<Option<EndpointList>>,
    /// What each connected peer reports as this node's source address (ADR-012 rung
    /// 3's "observed address"). Kept per reporter, never published in a record: it is
    /// what this node offers a peer to dial during a punch, and a lying peer should
    /// cost a failed punch rather than a poisoned address record.
    observed: Mutex<BTreeMap<Digest32, Multiaddr>>,
    /// What this node is relaying for others (ADR-012 rung 4), so the caps hold.
    circuits: Arc<CircuitLedger>,
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
            advertised: Mutex::new(None),
            observed: Mutex::new(BTreeMap::new()),
            circuits: Arc::new(CircuitLedger::default()),
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

    /// The endpoints this node advertises.
    ///
    /// After [`NodeNet::refresh_advertised`] this is the ADR-012 ladder's composed
    /// set (routable address, port-mapped address, loopback). Before it — and if the
    /// ladder found nothing — it falls back to the bound socket, which is right for a
    /// node bound to a concrete address and merely useless for one bound to the
    /// wildcard.
    pub fn local_endpoints(&self) -> Result<EndpointList> {
        if let Some(list) = lock(&self.advertised).clone() {
            return Ok(list);
        }
        let addr = self.manager.endpoint().local_addr()?;
        EndpointList::new(vec![crate::nat::multiaddr::Multiaddr::from(addr)])
    }

    /// Run the ladder's publish side and cache what this node should advertise: its
    /// routable addresses (both families, IPv6 first), a gateway-mapped address when
    /// one can be had, and loopback. Returns every port mapping or IPv6 pinhole a
    /// gateway granted, so the caller can renew them before they expire.
    ///
    /// Best-effort by design: a node with no dialable address is not broken. It still
    /// reaches peers outbound and is reached through the ladder's later rungs, which
    /// is the ordinary case for a client inside a private network.
    pub async fn refresh_advertised(&self) -> Vec<crate::nat::portmap::PortMapping> {
        let Ok(bound) = self.manager.endpoint().local_addr() else {
            return Vec::new();
        };
        let (list, mappings) = crate::nat::reachability::advertise_endpoints(bound.port()).await;
        *lock(&self.advertised) = Some(list);
        mappings
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Accept the next stream on `conn`, authorize it against the shared policy, and
    /// serve it if it is the board. Anything the actor must handle comes back as an
    /// [`Inbound`].
    pub async fn accept_stream(&self, conn: &VoxConnection) -> Result<Inbound> {
        let peer = conn.peer_id();
        // **Authorize when the stream arrives, not before.** Accepting blocks until
        // the peer opens something, which may be long after this loop iteration began
        // — and in that window the peer can become a member (a join completes, a
        // channel opens). Classifying against a snapshot taken *before* the await
        // refused exactly the stream that mattered: a member delivering its sender key
        // on a connection we had dialled before we knew it.
        let (kind, mut send, mut recv) = accept_typed(conn).await?;
        if !PeerPolicy::allows(self.classify(&peer), kind) {
            crate::node::net::refuse_stream(&mut send, &mut recv);
            return Err(crate::error::Error::StreamRefused(
                "peer may not open this stream kind",
            ));
        }
        self.dispatch(conn, kind, send, recv).await
    }

    /// How this node classifies `peer` right now: the actor's policy where it has an
    /// answer, else what the **board** knows.
    ///
    /// ADR-016's "pending pre-join identity" is a board fact, not a list someone
    /// maintains: a joiner announces itself by publishing a pre-join record
    /// (`0x0008`, self-signed, which anyone may publish), and that is what makes it
    /// eligible to open a `join` stream. And a node that *anchors* a channel it is
    /// not a member of (M15.1) still has to serve, coordinate and relay for that
    /// channel's members, whom the board is what it knows them by — the creator
    /// through the genesis it holds, any other through a record the genesis-backed
    /// oracle admitted. Consulting the board here keeps all of that possible without
    /// the actor being told about every PUT; an identity with no record stays
    /// `Unknown`, so it reaches the board and `WHOAMI` and nothing else.
    #[must_use]
    pub fn classify(&self, peer: &Digest32) -> PeerClass {
        let class = self.policy.snapshot().classify(peer);
        if class != PeerClass::Unknown {
            return class;
        }
        if self.peer_is_member_on_board(peer) {
            PeerClass::Member
        } else if self.peer_has_prejoin(peer) {
            PeerClass::PendingJoiner
        } else {
            PeerClass::Unknown
        }
    }

    /// Whether `peer` has a live pre-join record on this board for any channel this
    /// node holds or anchors.
    #[must_use]
    pub fn peer_has_prejoin(&self, peer: &Digest32) -> bool {
        let now = self.now();
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        guard.channels_with_genesis().iter().any(|cid| {
            guard
                .current_prejoins(cid, now)
                .iter()
                .any(|r| r.asserted_id() == *peer)
        })
    }

    /// Whether the board knows `peer` as a member of some channel it anchors: the
    /// creator named by a genesis it holds, or the author of a live member record
    /// (which the board only admitted from an authenticated member).
    #[must_use]
    pub fn peer_is_member_on_board(&self, peer: &Digest32) -> bool {
        let now = self.now();
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        guard.channels_with_genesis().iter().any(|cid| {
            guard
                .genesis(cid)
                .is_some_and(|g| g.body.creator_pubkey.fingerprint() == *peer)
                || guard
                    .current_members(cid, 0, now)
                    .iter()
                    .any(|r| r.author_id == *peer)
        })
    }

    /// [`NodeNet::accept_stream`] against an explicit policy snapshot (for callers
    /// that maintain their own view; the node uses [`NodeNet::accept_stream`]).
    pub async fn accept_stream_with(
        &self,
        conn: &VoxConnection,
        policy: &PeerPolicy,
    ) -> Result<Inbound> {
        let (kind, send, recv) = accept_authorized(conn, policy).await?;
        self.dispatch(conn, kind, send, recv).await
    }

    /// Serve or hand up an authorized stream.
    async fn dispatch(
        &self,
        conn: &VoxConnection,
        kind: StreamKind,
        send: SendStream,
        recv: RecvStream,
    ) -> Result<Inbound> {
        let peer = conn.peer_id();
        match kind {
            StreamKind::Rendezvous => {
                self.service.serve_stream(send, recv).await?;
                Ok(Inbound::ServedRendezvous { peer })
            }
            StreamKind::Join => Ok(Inbound::Join { peer, send, recv }),
            StreamKind::Pairwise => Ok(Inbound::Pairwise { peer, send, recv }),
            StreamKind::Sync => Ok(Inbound::Sync { peer, send, recv }),
            StreamKind::Coord => {
                // The answer to `WHOAMI` is this connection's source address as *this*
                // node sees it — the peer's reflexive address (ADR-012 rung 3).
                let observed = Multiaddr::from(conn.quinn().remote_address());
                let manager = Arc::clone(&self.manager);
                match coordstream::serve_coord(
                    peer,
                    observed,
                    &|p| self.classify(p),
                    send,
                    recv,
                    move |p| manager.existing(p),
                )
                .await?
                {
                    coordstream::CoordInbound::Answered => Ok(Inbound::ServedCoord { peer }),
                    coordstream::CoordInbound::Punch {
                        peer: origin,
                        send,
                        recv,
                    } => Ok(Inbound::Punch {
                        peer: origin,
                        coordinator: peer,
                        send,
                        recv,
                    }),
                }
            }
            StreamKind::Circuit => {
                let manager = Arc::clone(&self.manager);
                circuitstream::serve_circuit(
                    peer,
                    &|p| self.classify(p),
                    send,
                    recv,
                    move |p| manager.existing(p),
                    &self.circuits,
                    self.manager.endpoint(),
                )
                .await?;
                Ok(Inbound::ServedCircuit { peer })
            }
            StreamKind::Tunnel => Ok(Inbound::NotYetSupported { peer, kind }),
        }
    }

    /// How many circuits this node is relaying for others right now.
    #[must_use]
    pub fn relaying(&self) -> usize {
        self.circuits.carrying()
    }

    /// Ask `peer` what source address it sees for this node and remember the answer
    /// (ADR-012 rung 3). One small round trip per connection.
    pub async fn learn_observed(&self, peer: Digest32) -> Result<Multiaddr> {
        let conn = self
            .manager
            .existing(&peer)
            .ok_or(Error::Unreachable("no connection to ask"))?;
        let addr = coordstream::ask_observed(&conn).await?;
        lock(&self.observed).insert(peer, addr);
        Ok(addr)
    }

    /// The address peers agree they see for this node, if any: the one most of them
    /// report. Behind a symmetric NAT reporters disagree (a different mapping per
    /// destination), and then the punch this feeds is the one ADR-012 says cannot
    /// work — it fails honestly rather than silently dialling the wrong port.
    #[must_use]
    pub fn observed_addr(&self) -> Option<Multiaddr> {
        // A handful of reporters at most, so a scan beats keeping an ordered index
        // (`Multiaddr` is deliberately not `Ord` — its ordering is preference, not
        // value).
        let mut tally: Vec<(Multiaddr, usize)> = Vec::new();
        for addr in lock(&self.observed).values() {
            match tally.iter_mut().find(|(a, _)| a == addr) {
                Some((_, n)) => *n += 1,
                None => tally.push((*addr, 1)),
            }
        }
        tally.into_iter().max_by_key(|(_, n)| *n).map(|(a, _)| a)
    }

    /// The agreed observed address, asking `coordinator` if no peer has reported one
    /// yet — the punch is about to offer it, so it is worth one round trip.
    async fn observed_or_ask(&self, coordinator: Digest32) -> Option<Multiaddr> {
        match self.observed_addr() {
            Some(addr) => Some(addr),
            None => self.learn_observed(coordinator).await.ok(),
        }
    }

    /// Forget what a peer reported (its connection is gone).
    pub fn forget_observed(&self, peer: &Digest32) {
        lock(&self.observed).remove(peer);
    }

    /// Reach `peer` by whatever rung lands **first** (M15.1b, relay-first / upgrade-
    /// later). A live connection is returned at once; otherwise a direct dial of the
    /// advertised endpoints (rungs 1–2) and a circuit through every connected helper
    /// (rung 4) are **raced**, and the first to produce an authenticated connection
    /// wins — through the user's own anchor that is about one round trip, not the
    /// twenty-odd seconds of waiting for a direct dial and then a punch to time out
    /// first. The connection may therefore be relayed: the caller runs
    /// [`NodeNet::upgrade`] behind it, and the manager's preference rule swaps a
    /// better path in when one lands.
    ///
    /// Exhausting every attempt is [`Error::Unreachable`]; the *last* helper's error is
    /// kept rather than a flattened one, because a peer that will not relay, one that
    /// cannot reach the target and a target that never answered are worth telling apart.
    pub async fn reach(
        &self,
        peer: Digest32,
        endpoints: &EndpointList,
    ) -> Result<Arc<VoxConnection>> {
        if let Some(conn) = self.manager.existing(&peer) {
            return Ok(conn);
        }
        let mut set: JoinSet<Result<VoxConnection>> = JoinSet::new();
        let candidates = direct_candidates(endpoints);
        if !candidates.is_empty() {
            let endpoint = Arc::clone(self.manager.endpoint());
            let now = self.now();
            set.spawn(async move { connect_direct(endpoint, &candidates, peer, now).await });
        }
        for relay in self.helpers(peer) {
            let endpoint = Arc::clone(self.manager.endpoint());
            let now = self.now();
            set.spawn(
                async move { circuitstream::connect_through(&relay, peer, &endpoint, now).await },
            );
        }
        if set.is_empty() {
            return Err(Error::Unreachable(
                "no direct candidates, and no peer is connected to carry a circuit",
            ));
        }
        let mut last: Option<Error> = None;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(Ok(conn)) => return Ok(self.manager.adopt(conn)),
                Ok(Err(e)) => last = Some(e),
                Err(_) => last = Some(Error::Unreachable("a reach attempt was cancelled")),
            }
        }
        Err(last.unwrap_or(Error::Unreachable("no path to the peer")))
    }

    /// Try for a **better path** to a peer already reached over a relayed one: a direct
    /// dial of its endpoints and a hole punch through every connected helper, raced,
    /// each with the shorter punch timeout. The winner is filed through the manager's
    /// preference rule, which retires the relayed connection underneath whatever is
    /// in flight on it; the peer's manager does the same on its side.
    ///
    /// `None` when the current path is already direct, or when nothing better lands —
    /// a peer behind a symmetric NAT stays relayed, honestly.
    pub async fn upgrade(
        &self,
        peer: Digest32,
        endpoints: &EndpointList,
    ) -> Option<Arc<VoxConnection>> {
        let current = self.manager.existing(&peer)?;
        if crate::node::net::path_class(&current) == crate::node::net::PathClass::Direct {
            return None;
        }
        let mut set: JoinSet<Result<VoxConnection>> = JoinSet::new();
        let candidates = direct_candidates(endpoints);
        if !candidates.is_empty() {
            let endpoint = Arc::clone(self.manager.endpoint());
            let now = self.now();
            set.spawn(async move {
                crate::nat::reachability::connect_direct_within(
                    endpoint,
                    &candidates,
                    peer,
                    now,
                    coordstream::PUNCH_ATTEMPT_TIMEOUT,
                )
                .await
            });
        }
        for coordinator in self.helpers(peer) {
            // The observed address is asked for before the task starts, so the punch
            // has it to offer without touching `self` from the task.
            let observed = self.observed_or_ask(coordinator.peer_id()).await;
            let Ok(local_eps) = self.local_endpoints() else {
                continue;
            };
            let local = coordstream::punch_endpoints(observed, &local_eps);
            let endpoint = Arc::clone(self.manager.endpoint());
            let now = self.now();
            set.spawn(async move {
                let (mut send, mut recv) =
                    coordstream::open_punch_session(&coordinator, peer).await?;
                let plan = coordstream::run_punch_initiator(&mut send, &mut recv, local).await?;
                coordstream::execute_punch(endpoint, plan, peer, now).await
            });
        }
        while let Some(joined) = set.join_next().await {
            if let Ok(Ok(conn)) = joined {
                let filed = self.manager.adopt(conn);
                // `adopt` keeps the better of the two; only a real replacement is an
                // upgrade.
                if !Arc::ptr_eq(&filed, &current) {
                    return Some(filed);
                }
            }
        }
        None
    }

    /// The connected peers that could help reach `peer`: every live connection but
    /// the peer's own. Whether one *will* help is its policy's business.
    fn helpers(&self, peer: Digest32) -> Vec<Arc<VoxConnection>> {
        self.manager
            .peers()
            .into_iter()
            .filter(|p| *p != peer)
            .filter_map(|p| self.manager.existing(&p))
            .collect()
    }

    /// The initiator's side of rung 3 on its own: ask `coordinator` to carry a punch
    /// session to `peer`, run the DCUtR exchange, and fire the synchronized dial.
    pub async fn punch_through(
        &self,
        coordinator: &VoxConnection,
        peer: Digest32,
    ) -> Result<Arc<VoxConnection>> {
        let (mut send, mut recv) = coordstream::open_punch_session(coordinator, peer).await?;
        let observed = self.observed_or_ask(coordinator.peer_id()).await;
        let local = coordstream::punch_endpoints(observed, &self.local_endpoints()?);
        let plan = coordstream::run_punch_initiator(&mut send, &mut recv, local).await?;
        let conn =
            coordstream::execute_punch(Arc::clone(self.manager.endpoint()), plan, peer, self.now())
                .await?;
        Ok(self.manager.adopt(conn))
    }

    /// Rung 4 on its own: ask `relay` to carry a circuit to `peer` and dial `peer`
    /// through it. The connection is pinned to and authenticated by `peer`; the relay
    /// forwards packets it cannot read.
    pub async fn circuit_through(
        &self,
        relay: &VoxConnection,
        peer: Digest32,
    ) -> Result<Arc<VoxConnection>> {
        let conn = circuitstream::connect_through(relay, peer, self.manager.endpoint(), self.now())
            .await?;
        Ok(self.manager.adopt(conn))
    }

    /// The responder's side of rung 3, on a session a coordinator relayed here: run the
    /// exchange and fire immediately, so the dial coincides with the initiator's.
    pub async fn answer_punch(
        &self,
        peer: Digest32,
        coordinator: Digest32,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<Arc<VoxConnection>> {
        let observed = self.observed_or_ask(coordinator).await;
        let local = coordstream::punch_endpoints(observed, &self.local_endpoints()?);
        let plan = coordstream::run_punch_responder(&mut send, &mut recv, local).await?;
        let conn =
            coordstream::execute_punch(Arc::clone(self.manager.endpoint()), plan, peer, self.now())
                .await?;
        Ok(self.manager.adopt(conn))
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
    /// An unknown peer may still ask what address it is seen at — that is the one coord
    /// verb open to everyone, and a NATed client has no other way to learn it. Asking
    /// the same peer to *relay* a punch is refused.
    #[test]
    fn whoami_is_answered_for_anyone_and_a_relay_is_not() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let server_s = signer(11, 12);
            let client_s = signer(13, 14);
            let server = net(&server_s);
            let client = net(&client_s);
            let server_id = server.local_id();
            let server_eps = server.local_endpoints().unwrap();
            // The server knows nobody: every peer is `Unknown`.
            let serving = {
                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    let conn = server
                        .manager()
                        .accept(Admission::AcceptAnyAuthenticated)
                        .await
                        .unwrap()
                        .unwrap();
                    let whoami = server.accept_stream(&conn).await;
                    let relay = server.accept_stream(&conn).await;
                    (whoami, relay, conn)
                })
            };
            let conn =
                tokio::time::timeout(TIMEOUT, client.manager().connect(server_id, &server_eps))
                    .await
                    .unwrap()
                    .unwrap();

            // The answer is the client's own source address as the server sees it: over
            // loopback that is the port the client bound, which is exactly the fact a
            // NATed client cannot discover by itself.
            let observed = tokio::time::timeout(TIMEOUT, client.learn_observed(server_id))
                .await
                .unwrap()
                .unwrap();
            let bound = client.manager().endpoint().local_addr().unwrap();
            assert_eq!(observed, Multiaddr::from(bound));
            assert_eq!(client.observed_addr(), Some(observed));

            // Relaying is not open: an unknown peer asking for a punch session is
            // refused, and told so rather than left hanging.
            let refused =
                tokio::time::timeout(TIMEOUT, coordstream::open_punch_session(&conn, [7u8; 32]))
                    .await
                    .unwrap();
            assert!(
                matches!(refused, Err(Error::HolePunchFailed(_))),
                "an unknown peer may not ask for a relay: {refused:?}"
            );

            let (whoami, relay, _conn) = tokio::time::timeout(TIMEOUT, serving)
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(whoami, Ok(Inbound::ServedCoord { .. })),
                "{whoami:?}"
            );
            assert!(matches!(relay, Err(Error::StreamRefused(_))), "{relay:?}");
            // Forgetting a peer forgets what it reported.
            client.forget_observed(&server_id);
            assert_eq!(client.observed_addr(), None);
        });
    }

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
                StreamKind::Tunnel,
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
            // `coord` is served in place now (ADR-012 rung 3); `tunnel` is the kind
            // still waiting on its ADR-013 handler.
            assert!(matches!(
                out[3],
                Inbound::NotYetSupported {
                    kind: StreamKind::Tunnel,
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
            // Alice is her own anchor here, so the link names her as both.
            let link = crate::node::link::InviteLink::new(
                cid,
                vec![crate::nat::bootstrap::BootstrapNode::new(
                    alice_fp,
                    alice_net.local_endpoints().unwrap(),
                )
                .unwrap()],
                Some(alice_fp),
            )
            .unwrap();
            let parsed = crate::node::link::InviteLink::parse(&link.to_url()).unwrap();
            assert_eq!(parsed.channel_id, cid);
            assert_eq!(parsed.responder, Some(alice_fp));
            assert_eq!(parsed.anchors[0].id, alice_fp);

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
                    .connect(parsed.anchors[0].id, &parsed.anchors[0].endpoints)
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
