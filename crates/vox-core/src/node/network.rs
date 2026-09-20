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
    /// A peer is opening an ADR-013 **tunnel**: the actor answers it with the named
    /// channel's evaluator and offered services, on its own task (a tunnel lives as
    /// long as the TCP connection it carries).
    Tunnel {
        /// The authenticated peer — the client whose `dial:` capability is enforced.
        peer: Digest32,
        /// The stream's send half.
        send: SendStream,
        /// The stream's receive half.
        recv: RecvStream,
    },
    /// A stream kind with no handler yet. The stream is dropped (reset), never
    /// silently left open. Every kind ADR-011 defines is served today; this remains
    /// for a kind a newer peer knows and this node does not.
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
                self.service.serve_stream(peer, send, recv).await?;
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
            StreamKind::Tunnel => Ok(Inbound::Tunnel { peer, send, recv }),
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

    /// What this node's board anchors: every channel it holds a genesis for, with
    /// how many members and pending joiners it knows of each (ADR-016 M15.2a).
    #[must_use]
    pub fn anchored_channels(&self) -> Vec<crate::node::api::AnchoredChannel> {
        let now = self.now();
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        let mut channels = guard.channels_with_genesis();
        channels.sort_unstable();
        channels
            .into_iter()
            .map(|channel_id| {
                // A member is known by a bundle (the key) or an address record (the
                // creator's, or one whose bundle came first); the creator is known by
                // the genesis alone.
                let mut members: std::collections::BTreeSet<Digest32> = guard
                    .current_bundles(&channel_id, 0, now)
                    .iter()
                    .map(|r| r.author_id)
                    .chain(
                        guard
                            .current_members(&channel_id, 0, now)
                            .iter()
                            .map(|r| r.author_id),
                    )
                    .collect();
                if let Some(g) = guard.genesis(&channel_id) {
                    members.insert(g.body.creator_pubkey.fingerprint());
                }
                crate::node::api::AnchoredChannel {
                    channel_id,
                    members: members.len(),
                    pending: guard.current_prejoins(&channel_id, now).len(),
                    entries: None,
                }
            })
            .collect()
    }

    /// The endpoints this node's board advertises for `member` in `channel_id` — the
    /// dial hints any reach starts from (the identity is pinned, so a wrong hint only
    /// fails).
    #[must_use]
    pub fn board_endpoints(&self, channel_id: &Digest32, member: &Digest32) -> EndpointList {
        let now = self.now();
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        guard
            .current_members(channel_id, 0, now)
            .into_iter()
            .find(|r| r.author_id == *member)
            .map(|r| r.endpoints.clone())
            .unwrap_or_default()
    }

    /// The genesis this node's board holds for `channel_id`, if any.
    #[must_use]
    pub fn board_genesis(&self, channel_id: &Digest32) -> Option<Genesis> {
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        guard.genesis(channel_id).cloned()
    }

    /// Every member key this node's board can vouch for in `(channel, epoch)`: the
    /// creator's from the genesis, and every author with a live bundle record (which
    /// carries its key, and was admitted only through a member).
    #[must_use]
    pub fn board_member_keys(&self, channel_id: &Digest32, epoch: u64) -> Vec<CompositePublicKey> {
        let now = self.now();
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out: Vec<CompositePublicKey> = Vec::new();
        if let Some(g) = guard.genesis(channel_id) {
            out.push(g.body.creator_pubkey.clone());
        }
        for r in guard.current_bundles(channel_id, epoch, now) {
            if let Ok(key) = CompositePublicKey::from_bytes(&r.prekey_bundle.root_pub) {
                if !out.iter().any(|k| k.fingerprint() == key.fingerprint()) {
                    out.push(key);
                }
            }
        }
        out
    }

    /// Every *other* member's live records this node's board holds for `(channel,
    /// epoch)` — bundles first, then address records — as wire frames, ready to be
    /// mirrored to an anchor.
    #[must_use]
    pub fn board_records(&self, channel_id: &Digest32, epoch: u64) -> Vec<Vec<u8>> {
        let now = self.now();
        let me = self.local_id();
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out: Vec<Vec<u8>> = guard
            .current_bundles(channel_id, epoch, now)
            .into_iter()
            .filter(|r| r.author_id != me)
            .map(MemberBundleRecord::to_wire)
            .collect();
        out.extend(
            guard
                .current_members(channel_id, epoch, now)
                .into_iter()
                .filter(|r| r.author_id != me)
                .map(RendezvousRecord::to_wire),
        );
        out
    }

    /// Put a framed record on **this node's own** board, without a network round
    /// trip. A node is its own first anchor, and it would be absurd to dial itself;
    /// the record still goes through the service's full policy, so a local publish
    /// is gated exactly like a remote one.
    pub fn publish_local(&self, record: &[u8]) -> Result<()> {
        use crate::nat::service::{RendezvousRequest, RendezvousResponse};
        // A local publish: this node is its own publisher, and it is a member of
        // every channel it publishes to.
        let me = self.local_id();
        let responses = self.service.handle(
            Some(&me),
            &RendezvousRequest::Put {
                record: record.to_vec(),
            },
        );
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
