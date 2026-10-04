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
use crate::nat::record::{Admission, MemberBundleRecord, RendezvousRecord};
use crate::nat::service::{
    MembershipOracle, RecordKinds, RecordSet, RendezvousClient, RendezvousService,
};
use crate::nat::store::RendezvousStore;
use crate::node::circuitstream;
use crate::node::coordstream;
use crate::node::joinstream::{run_initiator, run_responder, JoinOutcome, ResponderConfig};
use crate::node::net::{accept_authorized, ConnectionManager, PeerClass, PeerPolicy};
use crate::node::prekeys::PrekeyRing;
use crate::node::store::Store;
use crate::time::Clock;
use crate::transport::quic::{VoxConnection, VoxEndpoint};
use crate::transport::streams::accept_typed_on;
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

/// **For proofs only.** When set, a comma-separated list of `ip:port`: this node advertises exactly
/// those addresses instead of what the ADR-012 ladder found. The R41 throughput proof points a host at
/// a link emulator this way, so the tunnel's packets cross the same emulated link as the raw
/// transfer it is compared with. Nothing a person runs sets it; unset, nothing changes. Not compiled
/// in without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_ADVERTISE_ENV: &str = "VOX_TEST_ADVERTISE";

/// Test-only: hold every board read this node serves (a rendezvous stream) this many milliseconds
/// before answering it, saying so on stderr when it starts — so a proof can stop the node while a
/// joiner's read of it is in flight, which a stopping host otherwise does only by chance (#406).
/// **For proofs; nothing in a real deployment sets it.** Unset, empty or unparsable is no hold.
/// Not compiled in without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_HOLD_BOARD_READ_ENV: &str = "VOX_TEST_HOLD_BOARD_READ_MS";

/// How long a reach gives its direct dial before it asks any peer to carry a circuit (V210-122).
///
/// **500 ms, not 250** (#321, attempt 3). A direct dial's first answer cannot come before the peer
/// has done its post-quantum handshake crypto, and on a loaded machine that is most of the time:
/// a CI runner's direct dial over a 30 ms path took 271 ms and lost to the circuit at 250 ms
/// (run 36968701360). 500 ms is the top of the range the plan gave. A reach pays it only while a
/// direct dial to the peer is under way: one with no direct address and no dial elsewhere asks for
/// its circuit at once. Waiting on the peer's first answer instead does not help:
/// the dialling side's handshake finishes as soon as that answer arrives.
///
/// RFC 8305's connection-attempt delay, as for a join's board search. Measured: a direct join over
/// a LAN address dials its board in under 5 ms, so a reachable peer answers well inside it, and a
/// peer that cannot be reached directly costs this much and no more — its circuits start the moment
/// this reach's own direct dial fails, if that is sooner.
///
/// **Why there is one.** The ladder raced every rung at once. A host reached directly still had a
/// circuit asked of the anchor on the same instant; the circuit lost the tie-break, was retired,
/// and the anchor carried it for its 60 s grace — an anchor working for a pair that never needed
/// it, which is everything ADR-012's anchor principle says it must not do.
pub const DIRECT_HEAD_START: std::time::Duration = std::time::Duration::from_millis(500);

/// The longest a **dial-back** (V030-22) waits for the peer's word, counted from the reach's
/// start: the peer asked, through a coordinator, to dial this node directly. It races the reach's
/// circuits and holds none of them back (decider, 2026-10-03): a relay-only pair takes its circuit
/// at once, and a direct path found later replaces it. This caps a peer whose dial is still under
/// way. Measured: the peer's
/// post-quantum handshake took 150–575 ms on a machine at load 45–97.
pub const DIAL_BACK_PATIENCE: std::time::Duration = std::time::Duration::from_millis(3000);

#[cfg(feature = "test-knobs")]
fn test_advertise() -> Option<EndpointList> {
    let value = std::env::var(TEST_ADVERTISE_ENV).ok()?;
    let addrs: Vec<crate::nat::multiaddr::Multiaddr> = value
        .split(',')
        .filter_map(|a| a.trim().parse::<std::net::SocketAddr>().ok())
        .map(crate::nat::multiaddr::Multiaddr::from)
        .collect();
    EndpointList::new(addrs).ok()
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

    /// Replace the membership and anchors, **keeping** the pending joiners and join responders
    /// the policy holds at that instant — under one lock.
    ///
    /// Those two sets are not derived from channel state: a join task registers its responder
    /// from its own task, and the actor forgets joiners as their joins land. A snapshot taken
    /// under one lock and a replace under another lost whatever was registered between them,
    /// and a responder lost that way had its sender key refused, so the room just joined could
    /// not be read (V210-80).
    pub fn rebuild(&self, mut policy: PeerPolicy) {
        let mut held = lock(&self.inner);
        for joiner in held.pending_joiners() {
            policy.expect_joiner(joiner);
        }
        for responder in held.join_responders() {
            policy.expect_join_responder(responder);
        }
        *held = policy;
    }

    /// Expect a join from `joiner` until it is forgotten.
    pub fn expect_joiner(&self, joiner: Digest32) {
        lock(&self.inner).expect_joiner(joiner);
    }

    /// Stop expecting a join from `joiner`.
    pub fn forget_joiner(&self, joiner: &Digest32) -> bool {
        lock(&self.inner).forget_joiner(joiner)
    }

    /// Accept `responder`'s sender key while this node joins through it.
    pub fn expect_join_responder(&self, responder: Digest32) {
        lock(&self.inner).expect_join_responder(responder);
    }

    /// No join is in flight: stop treating anyone as a join responder.
    pub fn forget_join_responders(&self) {
        lock(&self.inner).forget_join_responders();
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
    /// The peer asks whether this node holds a claim it posted (V210-168).
    Agree {
        /// The authenticated peer, a member.
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
    /// The peer said it is stopping (V210-93): the connection is marked and closed here, so its
    /// loss reads as a stop whether or not the peer's own close arrives. Nothing for the actor
    /// to do; the connection's loss is noticed like any other.
    ServedGoodbye {
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
        /// The authenticated peer — the client the host's dial gate decides on.
        peer: Digest32,
        /// The stream's send half.
        send: SendStream,
        /// The stream's receive half.
        recv: RecvStream,
    },
    /// An app stream (ADR-022 decision 7): its `AppOpen` has not been read yet, and its
    /// gate — this node's keyring and the room's authors — is `node::app`'s to run.
    App {
        /// The authenticated peer.
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
    /// The presence this node is on (ADR-026 D-3): what it advertises — composed by the ADR-012
    /// ladder's publish side once for the presence, since every node on it publishes the same
    /// ip:port (N-46) — the reflexive addresses peers report, and the one relay ledger, whose caps
    /// hold across every node on it (N-45).
    presence: Arc<crate::node::presence::NetPresence>,
    /// The peers a [`NodeNet::reach`] is under way to, each with what its waiters are woken by.
    /// **One ladder per peer at a time.** Two at once each raced a circuit through the same
    /// relay, and the far end keeps one circuit per peer: attaching the second closed the
    /// first, whose handshake then waited out its full attempt (10 s). Measured on the v0.3.0
    /// merge, where a reopened room dialled its members beside a `vox forward`: cold relayed
    /// connections of 10.8 s instead of about 260 ms (#226).
    reaching: Mutex<HashMap<Digest32, Arc<tokio::sync::Notify>>>,
    /// Where each ladder run is counted for `vox status --json`, once the node has one.
    status: Mutex<Option<crate::node::status::SharedSyncBook>>,
    service: RendezvousService,
    membership: SharedMembership,
    policy: SharedPolicy,
    clock: Clock,
}

/// Ends a [`NodeNet::reach`]'s ownership of its peer: the entry goes, and every waiter wakes.
struct ReachOwner<'a> {
    reaching: &'a Mutex<HashMap<Digest32, Arc<tokio::sync::Notify>>>,
    peer: Digest32,
    /// Where a cancelled ladder is said (#229's diagnostics).
    manager: &'a ConnectionManager,
    /// Set when the ladder ran to its end; dropped unset, it was cancelled mid-way.
    finished: bool,
    started: std::time::Instant,
}

impl Drop for ReachOwner<'_> {
    fn drop(&mut self) {
        let woken = lock(self.reaching).remove(&self.peer);
        if !self.finished {
            self.manager.note(
                self.peer,
                format!(
                    "a reach was cancelled {} ms into its ladder; {}",
                    self.started.elapsed().as_millis(),
                    if woken.is_some() {
                        "any reach waiting for it now tries on its own"
                    } else {
                        "nothing was waiting for it"
                    }
                ),
            );
        }
        if let Some(woken) = woken {
            woken.notify_waiters();
        }
    }
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
    /// Count this node's reachability ladders in `book` (`vox status --json`'s `reach`).
    pub fn count_ladders_in(&self, book: crate::node::status::SharedSyncBook) {
        // And let the same report say which connection this node holds for each peer (#50).
        book.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .read_connections_from(&self.manager);
        *lock(&self.status) = Some(book);
    }

    /// Build the surface over a bound endpoint. The board it serves is fresh
    /// in-memory state (an anchor that persists a board is M15).
    #[must_use]
    pub fn new(
        endpoint: Arc<VoxEndpoint>,
        presence: Arc<crate::node::presence::NetPresence>,
        clock: Clock,
    ) -> Self {
        let membership = SharedMembership::new();
        let service = RendezvousService::new(
            Arc::new(Mutex::new(RendezvousStore::new())),
            Arc::new(membership.clone()),
            Arc::clone(&clock),
        );
        Self {
            manager: Arc::new(ConnectionManager::new(endpoint, Arc::clone(&clock))),
            presence,
            reaching: Mutex::new(HashMap::new()),
            status: Mutex::new(None),
            service,
            membership,
            policy: SharedPolicy::new(),
            clock,
        }
    }

    /// Be told, by channelID, when a record by another author is admitted to this node's board.
    ///
    /// Set before this is shared, which is why it takes `&mut self`: the service is cloned into
    /// every connection that serves a stream. See
    /// [`crate::nat::service::RendezvousService::on_admitted`] for why this seam exists.
    pub fn on_board_growth(&mut self, hook: crate::nat::service::AdmittedHook) {
        self.service.on_admitted(hook);
    }

    /// Be told when a signed withdraw takes records off this node's board (V030-14). Set before
    /// this is shared, like [`Self::on_board_growth`]; see
    /// [`crate::nat::service::RendezvousService::on_withdrawn`].
    pub fn on_board_withdraw(&mut self, hook: crate::nat::service::AdmittedHook) {
        self.service.on_withdrawn(hook);
    }

    /// Which rooms this node keeps a board for when a peer brings their genesis — an anchor's
    /// job, and no other node's. Set before this is shared, like [`Self::on_board_growth`];
    /// see [`crate::nat::service::RendezvousService::serve_rooms`].
    pub fn serve_rooms(&mut self, rooms: crate::nat::service::AnchorRooms) {
        self.service.serve_rooms(rooms);
    }

    /// Whether this node may anchor the room `genesis` founds: the same predicate the board's
    /// genesis acceptance uses ([`crate::nat::service::AnchorRooms::may_anchor`]).
    #[must_use]
    pub fn may_anchor(&self, genesis: &Genesis) -> bool {
        self.service.may_anchor(genesis)
    }

    /// Drop every expired record from this node's board. The store bounds its buckets by
    /// pruning when one fills, but a board nobody publishes to again kept every record it
    /// ever took, served nothing from them and freed nothing (V210-70); the tick calls this.
    pub fn prune_board(&self) -> usize {
        let now = self.now();
        lock(self.service.store()).prune_expired(now)
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
        #[cfg(feature = "test-knobs")]
        if let Some(list) = test_advertise() {
            return Ok(list);
        }
        if let Some(list) = self.presence.advertised_now() {
            return Ok(list);
        }
        // Before the ladder has run there is nothing discovered to report, and the **bind**
        // address is not a substitute. The normal way to run a node is to bind the wildcard —
        // what it advertises is supposed to come from the ladder, not from here — so this
        // fallback returned `0.0.0.0:<port>`, and that went into invite links as the
        // responder's address and into rendezvous records as this node's. A joiner then had a
        // destination it cannot dial, and the join fell entirely to the relay rung.
        //
        // Observed in the shipped product, not deduced: `vox serve --listen 0.0.0.0:0`
        // against a real anchor minted
        // `…&b=/ip4/0.0.0.0/udp/53638&r=<this node>`.
        //
        // An unspecified address is not an endpoint. Saying "I do not know my address yet" is
        // both true and useful — the ladder's later rungs do not need one — where a wildcard
        // is a lie that costs a dial attempt and, when the relay is slow, the whole join.
        // Loopback is kept: a peer on this machine can use it.
        let addr = self.manager.endpoint().local_addr()?;
        if addr.ip().is_unspecified() {
            return EndpointList::new(Vec::new());
        }
        EndpointList::new(vec![crate::nat::multiaddr::Multiaddr::from(addr)])
    }

    /// The presence this node is on.
    #[must_use]
    pub fn presence(&self) -> &Arc<crate::node::presence::NetPresence> {
        &self.presence
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Accept the next stream on `conn`, authorize it against the shared policy, and
    /// serve it if it is the board. Anything the actor must handle comes back as an
    /// [`Inbound`].
    pub async fn accept_stream(&self, conn: &Arc<VoxConnection>) -> Result<Inbound> {
        // **Authorize when the stream arrives, not before.** Accepting blocks until
        // the peer opens something, which may be long after this loop iteration began
        // — and in that window the peer can become a member (a join completes, a
        // channel opens). Classifying against a snapshot taken *before* the await
        // refused exactly the stream that mattered: a member delivering its sender key
        // on a connection we had dialled before we knew it.
        let (kind, send, recv) = self.accept_authorized(conn).await?;
        self.dispatch(conn, kind, send, recv).await
    }

    /// Wait for the next stream on `conn` and authorize it — **and nothing else**.
    ///
    /// The serving is [`Self::dispatch`], which a caller running a loop must put on its own
    /// task. Doing both in one call, which [`Self::accept_stream`] still does for callers that
    /// want one stream, makes a loop serve every stream inline and therefore serialise on them:
    /// a rendezvous, coord or circuit stream is answered *inside* `dispatch`, so one slow one
    /// delays every other stream on the same connection. That is how a hole punch loses its
    /// coordinator — the initiator's `coord` request waits behind a sync already in progress
    /// and gives up at `coordstream`'s frame timeout, which reads as "the peer went quiet" when
    /// the peer was never asked.
    pub async fn accept_authorized(
        &self,
        conn: &VoxConnection,
    ) -> Result<(StreamKind, SendStream, RecvStream)> {
        self.accept_authorized_on(conn.quinn(), conn.peer_id())
            .await
    }

    /// [`Self::accept_authorized`] on the bare quinn handle of a connection to `peer`, so the
    /// waiting does not hold the [`VoxConnection`] — see `actor::spawn_stream_loop`.
    pub async fn accept_authorized_on(
        &self,
        conn: &quinn::Connection,
        peer: Digest32,
    ) -> Result<(StreamKind, SendStream, RecvStream)> {
        let typed = accept_typed_on(conn).await?;
        self.authorize_typed(peer, typed)
    }

    /// Authorize a stream whose kind has been read: refused, with the coded answer, when `peer`
    /// may not open that kind (see [`Self::classify`]).
    ///
    /// # Errors
    /// [`crate::error::Error::StreamRefused`] when the peer may not open that kind.
    pub fn authorize_typed(
        &self,
        peer: Digest32,
        (kind, mut send, mut recv): (StreamKind, SendStream, RecvStream),
    ) -> Result<(StreamKind, SendStream, RecvStream)> {
        let class = self.classify(&peer);
        if !PeerPolicy::allows(class, kind) {
            crate::node::net::refuse_disallowed(class, kind, &mut send, &mut recv);
            return Err(crate::error::Error::StreamRefused(
                "peer may not open this stream kind",
            ));
        }
        Ok((kind, send, recv))
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

    /// Drop the pre-join record `peer` holds on this node's board for `channel_id`: it has just
    /// been admitted, so it is no longer waiting to join (V210-102).
    pub fn forget_prejoin(&self, channel_id: &Digest32, peer: &Digest32) {
        let store = self.service.store();
        store
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .forget_prejoin(channel_id, peer);
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

    /// Whether this node will carry a relay — a coord session or a circuit — between `a` and
    /// `b`: a configured anchor on either end (an anchor introduces whoever it carries), or a
    /// room this node holds or anchors that **both** belong to (V210-70).
    ///
    /// Being classed a member was enough, and a member of *any* room this node serves is a
    /// member: a peer in one room could have this node open a circuit to, or coordinate a hole
    /// punch with, a member of another it had no business reaching — learning that member's
    /// address and steering its dials. On an anchor that is anybody, since an anchor keeps a
    /// board for any room a peer gives it. A relay is for reaching somebody in a room you share.
    #[must_use]
    pub fn relays_between(&self, a: &Digest32, b: &Digest32) -> bool {
        if self.classify(a) == PeerClass::Anchor || self.classify(b) == PeerClass::Anchor {
            return true;
        }
        let of_a = self.rooms_of(a);
        self.rooms_of(b).iter().any(|room| of_a.contains(room))
    }

    /// The rooms this node holds or anchors that `peer` is known in: as an admitted member,
    /// the creator a genesis on the board names, the author of a live member record, or a
    /// joiner with a live pre-join.
    fn rooms_of(&self, peer: &Digest32) -> std::collections::BTreeSet<Digest32> {
        use crate::nat::service::MembershipOracle as _;
        let mut rooms: std::collections::BTreeSet<Digest32> = self
            .membership
            .channels()
            .into_iter()
            .filter(|(cid, epoch)| self.membership.member_key(cid, *epoch, peer).is_some())
            .map(|(cid, _)| cid)
            .collect();
        let now = self.now();
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        for cid in guard.channels_with_genesis() {
            let known = guard
                .genesis(&cid)
                .is_some_and(|g| g.body.creator_pubkey.fingerprint() == *peer)
                || guard
                    .current_members(&cid, 0, now)
                    .iter()
                    .any(|r| r.author_id == *peer)
                || guard
                    .current_prejoins(&cid, now)
                    .iter()
                    .any(|r| r.asserted_id() == *peer);
            if known {
                rooms.insert(cid);
            }
        }
        rooms
    }

    /// [`NodeNet::accept_stream`] against an explicit policy snapshot (for callers
    /// that maintain their own view; the node uses [`NodeNet::accept_stream`]).
    pub async fn accept_stream_with(
        &self,
        conn: &Arc<VoxConnection>,
        policy: &PeerPolicy,
    ) -> Result<Inbound> {
        let (kind, send, recv) = accept_authorized(conn, policy).await?;
        self.dispatch(conn, kind, send, recv).await
    }

    /// Serve or hand up an authorized stream. Put this on its own task when accepting in a
    /// loop — see [`Self::accept_authorized`].
    pub async fn dispatch(
        &self,
        conn: &Arc<VoxConnection>,
        kind: StreamKind,
        send: SendStream,
        recv: RecvStream,
    ) -> Result<Inbound> {
        let peer = conn.peer_id();
        match kind {
            StreamKind::Rendezvous => {
                // Where the records came from, for a full board to share itself by
                // (`nat::source::Source`). A relayed peer's address is this node's own mux handle,
                // so it is known by identity instead.
                let source = crate::nat::source::Source::of_conn(conn);
                #[cfg(feature = "test-knobs")]
                if let Some(ms) = std::env::var(TEST_HOLD_BOARD_READ_ENV)
                    .ok()
                    .and_then(|v| v.trim().parse::<u64>().ok())
                {
                    eprintln!(
                        "vox: test: holding a board read from {} for {ms}ms \
                         ({TEST_HOLD_BOARD_READ_ENV})",
                        short_id(peer)
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                }
                self.service.serve_stream(peer, source, send, recv).await?;
                Ok(Inbound::ServedRendezvous { peer })
            }
            StreamKind::Join => Ok(Inbound::Join { peer, send, recv }),
            StreamKind::Pairwise => Ok(Inbound::Pairwise { peer, send, recv }),
            StreamKind::Sync => Ok(Inbound::Sync { peer, send, recv }),
            StreamKind::Agree => Ok(Inbound::Agree { peer, send, recv }),
            // The exchange is over by the time a stream is dispatched: one more identity stream is
            // a second exchange on one connection, which closes it (ADR-011 requirement 33).
            StreamKind::Identity => {
                conn.close(crate::wire::WireError::NotAvailable);
                Err(Error::MalformedBundle(
                    "an identity stream after the identity exchange",
                ))
            }
            StreamKind::Coord => {
                // The answer to `WHOAMI` is this connection's source address as *this*
                // node sees it — the peer's reflexive address (ADR-012 rung 3).
                //
                // **Only when this node can actually observe it.** Over a circuit the
                // remote address is a synthetic handle belonging to this node's own mux, not
                // the peer's address, so a relayed path reveals nothing about the peer's
                // reachability and no answer is the truthful one.
                //
                // Answering anyway would hand the peer an address nobody can dial, which it
                // would advertise: every other node then spends a full `PER_ATTEMPT_TIMEOUT`
                // on a destination that cannot exist, and the address itself is a fact about
                // this node's relay topology that has no business in a published record.
                //
                // `ask_observed` returns a `Result` and its callers tolerate failure,
                // falling back to local endpoints.
                //
                // Asked of the connection, not the mux table: a circuit the table has since
                // detached still left a synthetic address here (V29-15).
                let remote = conn.quinn().remote_address();
                let observed = (!conn.via_circuit()).then(|| Multiaddr::from(remote));
                let manager = Arc::clone(&self.manager);
                match coordstream::serve_coord(
                    peer,
                    observed,
                    &|p| self.classify(p),
                    &|a, b| self.relays_between(a, b),
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
                    conn,
                    &|p| self.classify(p),
                    &|a, b| self.relays_between(a, b),
                    send,
                    recv,
                    move |p| manager.existing(p),
                    self.presence.ledger(),
                    self.manager.endpoint(),
                )
                .await?;
                Ok(Inbound::ServedCircuit { peer })
            }
            StreamKind::Tunnel => Ok(Inbound::Tunnel { peer, send, recv }),
            StreamKind::App => Ok(Inbound::App { peer, send, recv }),
            StreamKind::Goodbye => {
                // Marked before it is closed, so whoever sees it closed sees why. Closed here
                // rather than left for the peer's own close, which may never arrive (see
                // `StreamKind::Goodbye`); the peer is stopping and needs nothing more from it.
                conn.mark_peer_stopped();
                drop((send, recv));
                conn.close(crate::wire::WireError::ShuttingDown);
                Ok(Inbound::ServedGoodbye { peer })
            }
        }
    }

    /// How many circuits this node is relaying for others right now.
    #[must_use]
    pub fn relaying(&self) -> usize {
        self.presence.ledger().carrying()
    }

    /// Ask `peer` what source address it sees for this node and remember the answer
    /// (ADR-012 rung 3). One small round trip per connection.
    pub async fn learn_observed(&self, peer: Digest32) -> Result<Multiaddr> {
        let conn = self
            .manager
            .existing(&peer)
            .ok_or(Error::Unreachable("no connection to ask"))?;
        let addr = coordstream::ask_observed(&conn).await?;
        self.presence.note_observed(self.local_id(), peer, addr);
        Ok(addr)
    }

    /// The address peers agree they see for this node, if any: the one most of them
    /// report. Behind a symmetric NAT reporters disagree (a different mapping per
    /// destination), and then the punch this feeds is the one ADR-012 says cannot
    /// work — it fails honestly rather than silently dialling the wrong port.
    #[must_use]
    pub fn observed_addr(&self) -> Option<Multiaddr> {
        self.presence.observed_addr()
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
        self.presence.forget_observed(&self.local_id(), peer);
    }

    /// Discard every cached reflexive address, so the next punch asks again.
    ///
    /// A reflexive address is what a peer says this node looks like from outside, and it is
    /// only true of the network this node was on when it asked. It changes when the NAT
    /// remaps, when the machine moves between networks, when a VPN comes up. Cached and never
    /// refreshed, it makes every later hole punch offer an address that no longer routes —
    /// and a punch that offers a stale address fails in a way that looks like the NAT being
    /// hostile rather than like stale data.
    ///
    /// Called when retrying a path upgrade, because a retry exists precisely on the
    /// assumption that conditions have changed. tailscale re-STUNs on a timer and on link
    /// change for the same reason (`magicsock.go`'s `periodicReSTUN`).
    pub fn refresh_observed(&self) {
        self.presence.refresh_observed();
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
    ///
    /// **One ladder per peer at a time.** A reach that finds another under way to the same peer
    /// waits for it and takes the connection it produced; only if it produced none does this one
    /// run its own.
    pub async fn reach(
        &self,
        peer: Digest32,
        endpoints: &EndpointList,
    ) -> Result<Arc<VoxConnection>> {
        loop {
            if let Some(conn) = self.manager.existing(&peer) {
                return Ok(conn);
            }
            let under_way = {
                let mut reaching = lock(&self.reaching);
                match reaching.get(&peer) {
                    Some(woken) => Some(Arc::clone(woken)),
                    None => {
                        reaching.insert(peer, Arc::new(tokio::sync::Notify::new()));
                        None
                    }
                }
            };
            let Some(woken) = under_way else {
                // This call owns the ladder. The guard clears the entry and wakes every waiter
                // however this ends, a cancelled caller included, so nobody waits for ever.
                let mut owner = ReachOwner {
                    reaching: &self.reaching,
                    peer,
                    manager: &self.manager,
                    finished: false,
                    started: std::time::Instant::now(),
                };
                let result = self.reach_ladder(peer, endpoints).await;
                owner.finished = true;
                return result;
            };
            let notified = woken.notified();
            tokio::pin!(notified);
            // Registered before looking again, so a ladder that ends in between still wakes it.
            notified.as_mut().enable();
            if lock(&self.reaching)
                .get(&peer)
                .is_some_and(|w| Arc::ptr_eq(w, &woken))
            {
                let waited = std::time::Instant::now();
                notified.await;
                let ms = waited.elapsed().as_millis();
                // Said only after a wait worth noting (#229's diagnostics). A ladder that fails at
                // once — nobody to relay through — is said by its own "could not reach", and every
                // waiter repeating it drowned the log (seen on #243's anchor-restart proof).
                let found = self.manager.existing(&peer).is_some();
                if ms >= 250 {
                    self.manager.note(
                        peer,
                        if found {
                            format!("a reach waited {ms} ms for another under way, and took its connection")
                        } else {
                            format!(
                                "a reach waited {ms} ms for another under way, which found no \
                                 connection; it dials again"
                            )
                        },
                    );
                }
            }
        }
    }

    /// [`NodeNet::reach`]'s ladder itself, run by one caller per peer at a time.
    async fn reach_ladder(
        &self,
        peer: Digest32,
        endpoints: &EndpointList,
    ) -> Result<Arc<VoxConnection>> {
        if let Some(conn) = self.manager.existing(&peer) {
            return Ok(conn);
        }
        if let Some(book) = lock(&self.status).as_ref() {
            crate::node::status::SyncBook::note_ladder(book, peer);
        }
        // Each rung is spawned with the label it will be reported under, because a rung
        // that fails is only actionable if the operator knows *which* rung it was: a
        // dialable address that never answers and a helper that refuses to relay call for
        // opposite next steps.
        let mut set: JoinSet<(String, Result<VoxConnection>)> = JoinSet::new();
        // Only what this node's socket can send to is a direct path (V210-122): a reach whose peer
        // advertises only addresses it cannot dial has no direct rung, and asks for its circuit at
        // once rather than after a dial that could only fail.
        let advertised = direct_candidates(endpoints);
        let candidates =
            crate::nat::reachability::dialable_candidates(self.manager.endpoint(), &advertised);
        if candidates.is_empty() && !advertised.is_empty() {
            self.manager.note(
                peer,
                format!(
                    "this node's socket cannot dial any address it advertises ({})",
                    join_addrs(&advertised)
                ),
            );
        }
        // **Direct first, by a head start** (V210-122, ADR-012): every circuit waits
        // [`DIRECT_HEAD_START`] before it asks a relay for anything, and gives way at once to a
        // direct connection to the peer — this ladder's own direct rung, a dial elsewhere in the
        // node, or the peer's own connection inbound. It starts sooner once nothing direct is
        // under way: this ladder's direct rung failed, or there was none, and no dial elsewhere
        // in the node is still running.
        //
        // **A dial elsewhere counts.** A node that had not read the peer's board record yet asked
        // for a circuit at once while it dialled the peer's invite-link address (3 of 12 cold
        // `vox up`s); that dial holds the circuits back too.
        //
        // **Nothing direct under way, no wait.** Every circuit waited the whole head start even
        // with no direct dial anywhere, so a pair that can only be relayed paid it on every reach:
        // a relayed `vox forward` restart took 253–271 ms, against 7–9 ms before (V210-57's bound
        // is 150 ms). A host that cannot dial its guest may then bridge while the guest's own
        // connection is arriving; the decider rules those circuits legitimate (2026-10-02). A
        // dial-back under way (below) races them and holds nothing back: the decider rules a
        // relay-only pair takes its circuit at once (2026-10-03), and a direct path found later
        // replaces it through [`Self::upgrade`].
        let candidates_none = candidates.is_empty();
        let has_direct = !candidates_none;
        let (direct_failed, failed) = tokio::sync::watch::channel(candidates_none);
        if has_direct {
            let endpoint = Arc::clone(self.manager.endpoint());
            let now = self.now();
            // The addresses go into the label: "all direct candidates failed" is not a
            // diagnosis on its own, and which addresses this node believed in is exactly
            // what distinguishes a stale board record from a blocked path.
            let label = format!("direct to {}", join_addrs(&candidates));
            set.spawn(async move {
                let result = connect_direct(endpoint, &candidates, peer, now).await;
                if result.is_err() {
                    let _ = direct_failed.send(true);
                }
                (label, result)
            });
        }
        let started = tokio::time::Instant::now();
        // **Nobody to carry a circuit yet, but somebody being dialled** (V210-57). A one-shot verb
        // reaches its host the moment its room is open, and a restarted `vox forward` did so before
        // its anchor connection existed: no candidate, no helper, "no peer is connected to carry a
        // circuit" — and the forward's next attempt came 500 ms later (restarts of 556 and 617 ms
        // against V210-57's 150 ms). While a direct dial is under way anywhere in this node, a reach
        // with no candidate and no helper waits for it, for at most [`DIRECT_HEAD_START`].
        let mut helpers = self.helpers(peer);
        if candidates_none && helpers.is_empty() {
            self.wait_for_a_helper(peer, started + DIRECT_HEAD_START)
                .await;
            if let Some(conn) = self.manager.existing(&peer) {
                return Ok(conn);
            }
            helpers = self.helpers(peer);
        }
        // **Then ask the peer to dial back** (V030-22): a reach with no direct path of its own — no
        // candidate it can dial, or a direct rung that failed — asks the peer, through each
        // coordinator it is connected to, to dial this node directly. It is the hole-punch
        // exchange (`coordstream`): signalling only, at most a few frames, never a data path, and
        // the peer answers it under the same rule as any relayed punch session. A host that
        // cannot dial its guest at all, while the guest could dial it, bridged through the anchor
        // for every sync; now the guest dials it back, racing the circuit, and a direct
        // connection that lands replaces the relayed one.
        //
        // **Racing, not first.** The address the coordinator sees for this node is asked inside
        // the dial-back's own task: asked here, inline, it cost every circuit below one round trip
        // to the coordinator before it was even asked for (a fresh node's first relayed reach
        // asked its circuit 109–121 ms in, through an anchor 100 ms away).
        for coordinator in &helpers {
            let Ok(local_eps) = self.local_endpoints() else {
                continue;
            };
            let known = self.observed_addr();
            let presence = Arc::clone(&self.presence);
            let me = self.local_id();
            let coordinator = Arc::clone(coordinator);
            let endpoint = Arc::clone(self.manager.endpoint());
            let now = self.now();
            let label = format!("dial-back via {}", short_id(coordinator.peer_id()));
            let mut failed = failed.clone();
            let manager = Arc::clone(&self.manager);
            set.spawn(async move {
                // With a direct rung of its own, only once that rung has failed.
                if has_direct {
                    let ended = failed.wait_for(|f| *f).await.is_err();
                    if ended && !*failed.borrow() {
                        return (
                            label,
                            Err(Error::Unreachable(
                                "not asked for: a direct connection answered first",
                            )),
                        );
                    }
                }
                // What `observed_or_ask` does, here in the race: the agreed observed address, or
                // the coordinator's word on it, worth its one round trip to the punch.
                let observed = match known {
                    Some(addr) => Some(addr),
                    None => match coordstream::ask_observed(&coordinator).await {
                        Ok(addr) => {
                            presence.note_observed(me, coordinator.peer_id(), addr);
                            Some(addr)
                        }
                        Err(_) => None,
                    },
                };
                let local = coordstream::punch_endpoints(observed, &local_eps);
                let session = async {
                    let (mut send, mut recv) =
                        coordstream::open_punch_session(&coordinator, peer).await?;
                    coordstream::count_dial_back(endpoint.local_id(), peer, false);
                    let plan =
                        coordstream::run_punch_initiator(&mut send, &mut recv, local).await?;
                    coordstream::count_dial_back(endpoint.local_id(), peer, true);
                    Ok::<_, Error>((send, recv, plan))
                }
                .await;
                let result = match session {
                    Err(e) => {
                        // Said, so a pair that bridges shows why: a dial-back the coordinator could
                        // not even carry leaves the circuits nothing to wait for (V030-27).
                        manager.note(
                            peer,
                            format!(
                                "a dial-back could not be asked {} ms into the reach: {e}",
                                started.elapsed().as_millis()
                            ),
                        );
                        Err(e)
                    }
                    // **The peer's dial is the point**, not this node's: a node that cannot dial
                    // its peer fails its own half at once. So this waits for the peer's word on its
                    // own dial (`Dialled`) — not a guessed time: a post-quantum handshake on a
                    // loaded machine takes from tens to hundreds of milliseconds, and a peer that
                    // could not dial at all says so at once — and, if it connected, for its
                    // connection to be filed. Never past the dial-back's patience.
                    Ok((_send, mut recv, plan)) => {
                        let answered_at = started.elapsed();
                        let patience = started + DIAL_BACK_PATIENCE;
                        let own = coordstream::execute_punch(endpoint, plan, peer, now);
                        let word = coordstream::recv_dial_outcome(&mut recv);
                        tokio::pin!(own, word);
                        let mut own_failed: Option<Error> = None;
                        let mut peer_said: Option<bool> = None;
                        let outcome = loop {
                            if peer_said == Some(true) && manager.existing(&peer).is_some() {
                                break Err(Error::Unreachable(
                                    "not this rung's: the peer dialled back",
                                ));
                            }
                            // The peer could not dial: nothing direct is coming from it, so the
                            // circuits are held no longer. This node's own half is given up with it
                            // — fired at the same moment as the peer's, it shares its fate.
                            if peer_said == Some(false) {
                                break Err(own_failed.take().unwrap_or(Error::Unreachable(
                                    "dial-back: the peer could not dial back",
                                )));
                            }
                            tokio::select! {
                                r = &mut own, if own_failed.is_none() => match r {
                                    Ok(conn) => break Ok(conn),
                                    Err(e) => own_failed = Some(e),
                                },
                                said = &mut word, if peer_said.is_none() => {
                                    peer_said = Some(said.unwrap_or(false));
                                }
                                () = tokio::time::sleep(std::time::Duration::from_millis(10)),
                                    if peer_said == Some(true) => {}
                                () = tokio::time::sleep_until(patience) => {
                                    break Err(own_failed.take().unwrap_or(Error::Unreachable(
                                        "dial-back: no word from the peer within the patience",
                                    )));
                                }
                            }
                        };
                        // Said, so a pair that still bridges shows why: how long the peer took to
                        // answer, what it said of its dial, and whether its connection came.
                        manager.note(
                            peer,
                            format!(
                                "a dial-back was answered {} ms into the reach; the peer said its \
                                 dial {}; its connection {} by {} ms",
                                answered_at.as_millis(),
                                match peer_said {
                                    Some(true) => "connected",
                                    Some(false) => "failed",
                                    None => "was still under way",
                                },
                                if manager.existing(&peer).is_some() {
                                    "had arrived"
                                } else {
                                    "had not arrived"
                                },
                                started.elapsed().as_millis()
                            ),
                        );
                        outcome
                    }
                };
                (label, result)
            });
        }
        for relay in helpers {
            let endpoint = Arc::clone(self.manager.endpoint());
            let now = self.now();
            let label = format!("circuit via {}", short_id(relay.peer_id()));
            let mut failed = failed.clone();
            let manager = Arc::clone(&self.manager);
            set.spawn(async move {
                let deadline = started + DIRECT_HEAD_START;
                let mut elsewhere = false;
                loop {
                    // Read before the win is looked for: a dial elsewhere files its connection
                    // before it stops counting, so a dial seen ended here has filed whatever it won.
                    let dialling = manager.direct_dial_under_way(&peer);
                    elsewhere |= dialling;
                    // Its sender is dropped when the rung ends, failed or not: a rung that failed
                    // sent `true` first, so read the value again rather than take the drop for a
                    // win (`has_changed` errs on a dropped sender whatever it last sent).
                    let rung_won = failed.has_changed().is_err() && !*failed.borrow();
                    let held = manager.existing(&peer);
                    if rung_won || held.is_some() {
                        // Said, so a pair that never bridges shows what it waited for (V210-122):
                        // how long, and whether the connection that answered is direct.
                        let what = match held
                            .as_deref()
                            .map(|c| crate::node::net::path_class(manager.endpoint(), c))
                        {
                            Some(crate::node::net::PathClass::Direct) | None => {
                                "a direct connection"
                            }
                            Some(_) => "a relayed connection",
                        };
                        manager.note(
                            peer,
                            format!(
                                "not asking {} for a circuit: {what} answered first, {} ms into \
                                 the reach",
                                short_id(relay.peer_id()),
                                started.elapsed().as_millis()
                            ),
                        );
                        return (
                            label,
                            Err(Error::Unreachable(
                                "not asked for: a direct connection answered first",
                            )),
                        );
                    }
                    // This ladder's direct rung failed or there was none, and no dial elsewhere
                    // was under way: nothing direct is coming.
                    if *failed.borrow() && !dialling {
                        break;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        break;
                    }
                    tokio::select! {
                        _ = failed.changed() => {}
                        () = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
                    }
                }
                // Said, so a pair that bridges shows why (V210-122): how long the reach
                // waited, and whether its direct dial had failed or was still under way.
                manager.note(
                    peer,
                    format!(
                        "asking {} for a circuit {} ms into the reach; its direct dial {}{}",
                        short_id(relay.peer_id()),
                        started.elapsed().as_millis(),
                        if candidates_none {
                            "there was none"
                        } else if *failed.borrow() {
                            "failed"
                        } else {
                            "had not finished"
                        },
                        if elsewhere {
                            "; a direct dial elsewhere in this node held it back"
                        } else {
                            ""
                        }
                    ),
                );
                (
                    label,
                    circuitstream::connect_through(&relay, peer, &endpoint, now).await,
                )
            });
        }
        if set.is_empty() {
            return Err(Error::Unreachable(
                "no direct candidates, and no peer is connected to carry a circuit",
            ));
        }
        // Every rung's verdict is kept. `join_next` yields in *completion* order, so the
        // slowest rung finishes last — and the direct rung, which stages one dial per
        // candidate, is essentially always the slowest. Keeping "the last error" therefore
        // reported the direct timeout and threw away the circuit's answer every time.
        let mut why: Vec<String> = Vec::with_capacity(set.len());
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((_, Ok(conn))) => {
                    #[cfg(feature = "test-knobs")]
                    if let Some(ms) = test_ladder_settle_ms() {
                        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                    }
                    let won = self.manager.adopt(conn).await;
                    // **Every connection a rung made is filed, not only the first** (#335). Two
                    // circuits through two helpers connect within milliseconds of each other, and
                    // the far end accepts both and keeps the one with the lower `tie_key`. Dropped
                    // here, the second was neither weighed nor closed — the circuit's driver held
                    // it open — so the far end could keep, and send its keys on, a connection this
                    // end never read: bob read carol at 540 ms, and carol never read bob. Filed,
                    // both ends weigh the same connections and keep the same one; a loser is
                    // closed, and its close crosses. Closing every late one instead lost both
                    // ends' connections when each had kept the other's late one. The caller
                    // serves the one kept and every one retired (`NetEvent::Dialed`). Rungs still
                    // dialling are given up, as before.
                    set.abort_all();
                    while let Some(late) = set.join_next().await {
                        if let Ok((_, Ok(conn))) = late {
                            self.manager.adopt(conn).await;
                        }
                    }
                    return Ok(self.manager.existing(&peer).unwrap_or(won));
                }
                Ok((rung, Err(e))) => why.push(format!("{rung}: {e}")),
                Err(_) => why.push("a rung was cancelled".to_owned()),
            }
        }
        // A direct dial elsewhere that landed while the circuits held back is this reach's answer.
        if let Some(conn) = self.manager.existing(&peer) {
            return Ok(conn);
        }
        why.sort(); // a reason a person compares between runs must not reorder itself
        Err(Error::LadderExhausted(why.join("; ")))
    }

    /// Try for a **better path** to a peer already reached over a relayed one: a direct
    /// dial of its endpoints and a hole punch through every connected helper, raced,
    /// each with the shorter punch timeout. The winner is filed through the manager's
    /// preference rule, which retires the relayed connection underneath whatever is
    /// in flight on it; the peer's manager does the same on its side.
    ///
    /// `Ok` is a better path that was filed. `Err(LadderExhausted)` carries **why nothing
    /// better landed**, rung by rung — a peer behind a symmetric NAT staying relayed is an
    /// honest outcome, but it must be distinguishable from a rung that failed for a reason
    /// somebody could act on.
    pub async fn upgrade(
        &self,
        peer: Digest32,
        endpoints: &EndpointList,
    ) -> Result<Arc<VoxConnection>> {
        let Some(current) = self.manager.existing(&peer) else {
            return Err(Error::Unreachable("no connection to upgrade"));
        };
        if crate::node::net::path_class(self.manager.endpoint(), &current)
            == crate::node::net::PathClass::Direct
        {
            return Err(Error::Unreachable("the path is already direct"));
        }
        // **Held weakly: the ladder only needs to know which connection it is replacing.** A
        // strong hold is a claim that the path is carrying something, and the ladder runs for
        // as long as its slowest rung — seconds past the moment another rung, or the peer's own
        // ladder, has already displaced this connection. Holding it kept a retired relayed
        // connection open, and its circuit on the relay, until every rung had given up.
        let current = {
            let held = current;
            Arc::downgrade(&held)
        };
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
        let mut why: Vec<String> = Vec::with_capacity(set.len());
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(Ok(conn)) => {
                    let filed = self.manager.adopt(conn).await;
                    // `adopt` keeps the better of the two; only a real replacement is an
                    // upgrade.
                    if !std::ptr::eq(Arc::as_ptr(&filed), current.as_ptr()) {
                        return Ok(filed);
                    }
                    why.push("a better path landed but the manager kept the held one".to_owned());
                }
                Ok(Err(e)) => why.push(e.to_string()),
                Err(_) => why.push("an upgrade attempt was cancelled".to_owned()),
            }
        }
        // Nothing better landed. Which is an ordinary outcome -- a peer behind a symmetric NAT
        // stays relayed, honestly -- but "nothing landed" and "nothing was even tried" are
        // different facts, and so are the reasons each rung gave. Returning `Option` threw all
        // of that away, which made a pair that silently never upgraded impossible to diagnose
        // without a debugger (ADR-018 §8b).
        why.sort();
        Err(Error::LadderExhausted(if why.is_empty() {
            "no rung was available to try".to_owned()
        } else {
            why.join("; ")
        }))
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

    /// **Nobody connected to help reach `peer` yet, but somebody being dialled** (V210-57): wait,
    /// until `until` at most, while a direct dial is under way anywhere in this node (an anchor's,
    /// say) and neither a helper nor `peer` itself is connected. Says how long it waited.
    async fn wait_for_a_helper(&self, peer: Digest32, until: tokio::time::Instant) {
        let began = tokio::time::Instant::now();
        while self.helpers(peer).is_empty()
            && self.manager.existing(&peer).is_none()
            && self.manager.any_direct_dial_under_way()
            && tokio::time::Instant::now() < until
        {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let waited = began.elapsed().as_millis();
        if waited > 0 {
            self.manager.note(
                peer,
                format!("nobody to carry a circuit yet; waited {waited} ms for a dial under way"),
            );
        }
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
        Ok(self.manager.adopt(conn).await)
    }

    /// Rung 4 on its own: ask `relay` to carry a circuit to `peer` and dial `peer`
    /// through it. The connection is pinned to and authenticated by `peer`; the relay
    /// forwards packets it cannot read.
    pub async fn circuit_through(
        &self,
        relay: &Arc<VoxConnection>,
        peer: Digest32,
    ) -> Result<Arc<VoxConnection>> {
        let conn = circuitstream::connect_through(relay, peer, self.manager.endpoint(), self.now())
            .await?;
        Ok(self.manager.adopt(conn).await)
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
        let t0 = std::time::Instant::now();
        let observed = self.observed_or_ask(coordinator).await;
        let asked_ms = t0.elapsed().as_millis();
        let local = coordstream::punch_endpoints(observed, &self.local_endpoints()?);
        let plan = coordstream::run_punch_responder(&mut send, &mut recv, local).await?;
        let planned_ms = t0.elapsed().as_millis();
        let targets = join_addrs(&plan.targets);
        let dialled =
            coordstream::execute_punch(Arc::clone(self.manager.endpoint()), plan, peer, self.now())
                .await;
        // **Said, either way** (V030-22): this is the dial a peer that cannot reach this node asked
        // for, and when it fails that peer bridges through its coordinator; without this, nothing
        // on either side said why.
        let _ = coordstream::send_dial_outcome(&mut send, dialled.is_ok()).await;
        self.manager.note(
            peer,
            match &dialled {
                Ok(_) => format!(
                    "dialled it back at {targets} as it asked, in {} ms (its own address \
                     known at {asked_ms} ms, the exchange done at {planned_ms} ms)",
                    t0.elapsed().as_millis()
                ),
                Err(e) => format!(
                    "could not dial it back at {targets} as it asked, after {} ms (its own \
                     address known at {asked_ms} ms, the exchange done at {planned_ms} ms): {e}",
                    t0.elapsed().as_millis()
                ),
            },
        );
        Ok(self.manager.adopt(dialled?).await)
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
                    holding: guard
                        .current_members(&channel_id, 0, now)
                        .iter()
                        .map(|r| {
                            let addrs = r.endpoints.addrs().iter().map(ToString::to_string);
                            (r.author_id, addrs.collect())
                        })
                        .collect(),
                }
            })
            .collect()
    }

    /// [`NodeNet::board_endpoints`] from whichever room's board has a live record for
    /// `member` — for a dial that names a member but not a room (`vox up` across every
    /// room, PRD-001 R20).
    #[must_use]
    pub fn board_endpoints_any(&self, member: &Digest32) -> EndpointList {
        let now = self.now();
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        guard
            .channels_with_genesis()
            .iter()
            .find_map(|cid| {
                guard
                    .current_members(cid, 0, now)
                    .into_iter()
                    .find(|r| r.author_id == *member)
                    .map(|r| r.endpoints.clone())
            })
            .unwrap_or_default()
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

    /// Where to dial `member` of `channel_id`: this node's board record for it, or, when this
    /// node's board holds none yet, the record a connected board holds (V210-122, as V030-22).
    ///
    /// **Read the board before bridging.** A reach that knows no address for its peer has no
    /// direct rung, so its circuit is asked at once. A `vox forward` reached its host before its
    /// node had read the host's board record: it asked the anchor for a circuit at 0 ms and was
    /// carried by it, though the host was directly reachable and its address sat on that same
    /// anchor's board (1 of 36 forwards at load 81, #321's verdict on candidate 5). Waiting for
    /// the node's own board read instead cost every relayed restart the whole head start. So the
    /// connected boards are asked, all at once, for the member's address record, and the first
    /// answer is used. A board still being dialled is waited for while the dial is under way.
    ///
    /// **Bounded by [`DIRECT_HEAD_START`] in all.** A pair that can only be relayed pays one
    /// board read, which takes milliseconds on a live board, and never more than the head start.
    /// The identity is pinned, so a stale or wrong address only fails its dial.
    pub async fn member_endpoints(&self, channel_id: &Digest32, member: Digest32) -> EndpointList {
        let local = self.board_endpoints(channel_id, &member);
        if !local.is_empty() || self.manager.existing(&member).is_some() {
            return local;
        }
        let began = tokio::time::Instant::now();
        let until = began + DIRECT_HEAD_START;
        let mut boards = self.helpers(member);
        if boards.is_empty() {
            self.wait_for_a_helper(member, until).await;
            boards = self.helpers(member);
        }
        if boards.is_empty() || self.manager.existing(&member).is_some() {
            return local;
        }
        let mut reads: JoinSet<Option<(Digest32, EndpointList)>> = JoinSet::new();
        for board in boards {
            let channel = *channel_id;
            reads.spawn(async move {
                let mut client = RendezvousClient::open(&board).await.ok()?;
                let set = client.get(&channel, 0, RecordKinds::MEMBERS).await;
                client.finish();
                let record = set
                    .ok()?
                    .members
                    .into_iter()
                    .find(|r| r.author_id == member && !r.endpoints.is_empty())?;
                Some((board.peer_id(), record.endpoints))
            });
        }
        let found = tokio::time::timeout_at(until, async {
            while let Some(read) = reads.join_next().await {
                if let Ok(Some(hit)) = read {
                    return Some(hit);
                }
            }
            None
        })
        .await
        .ok()
        .flatten();
        let ms = began.elapsed().as_millis();
        match found {
            Some((board, endpoints)) => {
                // Said, so a person — and a proof — can see where the address came from.
                self.manager.note(
                    member,
                    format!(
                        "its address was read from board {}'s record in {ms} ms; this node held \
                         none: {}",
                        short_id(board),
                        endpoints
                            .addrs()
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                );
                endpoints
            }
            None => {
                self.manager.note(
                    member,
                    format!("no address for it on this node's board, nor on a connected board ({ms} ms)"),
                );
                local
            }
        }
    }

    /// Whether this node's board holds a live member address or bundle record for
    /// `channel_id` — somebody is in the room.
    #[must_use]
    pub fn board_has_members(&self, channel_id: &Digest32) -> bool {
        let now = self.now();
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        !guard.current_members(channel_id, 0, now).is_empty()
            || !guard.current_bundles(channel_id, 0, now).is_empty()
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

    /// Every live bundle record this node's board holds for `(channel, epoch)`, as
    /// records. Local, so cheap: it is what lets the sync gate learn a member that
    /// joined through somebody else before refusing it (`run_sync_session`).
    #[must_use]
    pub fn board_bundles(&self, channel_id: &Digest32, epoch: u64) -> Vec<MemberBundleRecord> {
        let now = self.now();
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        guard
            .current_bundles(channel_id, epoch, now)
            .into_iter()
            .cloned()
            .collect()
    }

    /// The live bundle record this node's board holds for one member of `(channel,
    /// epoch)`, if any.
    ///
    /// This is what lets a member open an ADR-004 session to another member it never
    /// met on the join path — which is what ADR-016 §"the rendezvous service and the
    /// member bundle record" says members do, and what the runtime previously could
    /// not. The record is signed by that member's composite root and was verified when
    /// it was stored, so the prekey bundle inside it is as trustworthy as the join
    /// path's was.
    #[must_use]
    pub fn board_bundle(
        &self,
        channel_id: &Digest32,
        epoch: u64,
        member: &Digest32,
    ) -> Option<MemberBundleRecord> {
        let now = self.now();
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        guard.bundle(channel_id, epoch, member, now).cloned()
    }

    /// Every *other* member's live records this node's board holds for `(channel,
    /// epoch)` — bundles first, then address records — as wire frames, ready to be
    /// mirrored to an anchor.
    #[must_use]
    /// **Bundles first, and the order is load-bearing — do not sort or merge these.**
    ///
    /// On an anchor, a newcomer's *address* record has no way in on its own: the
    /// `MemberRecord` arm of `RendezvousService::put` has no witness fallback, so it is
    /// refused outright unless the anchor can already resolve the author's key. The
    /// *bundle* arm does have one, and a bundle carries the author's key. So a member
    /// mirroring a newcomer onward gets the address record admitted only because the
    /// witnessed bundle went up first and taught the board that key.
    ///
    /// Among the bundles, **a witness before the members it witnessed** (`chain_order`):
    /// a board takes a joiner's bundle only once it knows the key that signed its witness.
    ///
    /// Reverse these two, collect them into one sorted vector, or emit them
    /// concurrently, and every mirrored address record is silently refused — the
    /// newcomer stays reachable-but-unaddressed on every anchor, which reads as an
    /// intermittent unreachable peer and attributes to nothing. Nothing outside this
    /// comment enforces the order today.
    pub fn board_records(&self, channel_id: &Digest32, epoch: u64) -> Vec<Vec<u8>> {
        let now = self.now();
        let me = self.local_id();
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        // 1. Bundles, which carry the author's key and the evidence it belongs here.
        let mut bundles = guard.current_bundles(channel_id, epoch, now);
        bundles.sort_by_key(|r| chain_order(r));
        let mut out: Vec<Vec<u8>> = bundles
            .into_iter()
            .filter(|r| r.author_id != me)
            .map(MemberBundleRecord::to_wire)
            .collect();
        // 2. Address records, which can only resolve through a key the board now has.
        out.extend(
            guard
                .current_members(channel_id, epoch, now)
                .into_iter()
                .filter(|r| r.author_id != me)
                .map(RendezvousRecord::to_wire),
        );
        out
    }

    /// This node's board's live records for `(channel, epoch)` whose **author** the given peer
    /// board holds no record of the same kind for — bundles first, then address records, in the
    /// order `board_records` explains. Includes this node's own. What a member offers a peer's
    /// board during a sync, so the peer learns of a member that joined through this node without
    /// waiting to read this node's board itself.
    #[must_use]
    pub fn board_records_missing_from(
        &self,
        channel_id: &Digest32,
        epoch: u64,
        peer: &crate::nat::service::RecordSet,
    ) -> Vec<Vec<u8>> {
        let now = self.now();
        let has_bundle: std::collections::BTreeSet<Digest32> =
            peer.bundles.iter().map(|b| b.author_id).collect();
        let has_address: std::collections::BTreeSet<Digest32> =
            peer.members.iter().map(|m| m.author_id).collect();
        let store = self.service.store();
        let guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        let mut bundles = guard.current_bundles(channel_id, epoch, now);
        bundles.sort_by_key(|r| chain_order(r));
        let mut out: Vec<Vec<u8>> = bundles
            .into_iter()
            .filter(|r| !has_bundle.contains(&r.author_id))
            .map(MemberBundleRecord::to_wire)
            .collect();
        out.extend(
            guard
                .current_members(channel_id, epoch, now)
                .into_iter()
                .filter(|r| !has_address.contains(&r.author_id))
                .map(RendezvousRecord::to_wire),
        );
        out
    }

    /// Take a member that left off **this node's own** board (V030-14): its records go, and any
    /// stamped no later than `at` are refused. This node's board is its own, so no signature is
    /// needed — the leave on the room's log is the reason, and this node holds it.
    pub fn forget_member_on_board(&self, channel_id: &Digest32, author: &Digest32, at: u64) {
        let store = self.service.store();
        store
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .withdraw_member(channel_id, author, at);
    }

    /// Take a room that ended off **this node's own** board (V030-14), for good.
    pub fn forget_room_on_board(&self, channel_id: &Digest32) {
        let store = self.service.store();
        store
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .withdraw_room(channel_id, None);
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
        let responses = self.service.handle_local(
            &me,
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
    /// `admission` is how this node came to be a member (M17.6) — it created the
    /// channel, or a member signed a witness for its join. A bundle record cannot be
    /// built without one, which is the point: a key with no evidence behind it has no
    /// business on a board.
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per published field; grouping them would hide what is sent"
    )]
    pub fn own_records(
        &self,
        signer: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        ring: &PrekeyRing,
        seq: u64,
        timestamp: u64,
        admission: Admission,
    ) -> Result<(RendezvousRecord, MemberBundleRecord)> {
        // The caller's, not the clock's: after a stale refusal it may be past the clock (V210-64).
        let now = timestamp;
        let endpoints = self.local_endpoints()?;
        let address = RendezvousRecord::build(
            signer,
            channel_id,
            epoch,
            endpoints,
            seq,
            now,
            crate::nat::store::own_record_ttl_secs(),
        )?;
        let bundle = MemberBundleRecord::build(
            signer,
            channel_id,
            epoch,
            ring.bundle(&signer.public_key())?,
            seq,
            now,
            crate::nat::store::BUNDLE_MAX_TTL_SECS,
            admission,
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
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per published field; grouping them would hide what is sent"
    )]
    pub async fn publish_channel_records(
        &self,
        conn: &VoxConnection,
        signer: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        ring: &PrekeyRing,
        seq: u64,
        admission: Admission,
    ) -> Result<()> {
        let (address, bundle) =
            self.own_records(signer, channel_id, epoch, ring, seq, self.now(), admission)?;
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
    pub async fn answer_join<F, Fut>(
        &self,
        peer: Digest32,
        send: SendStream,
        recv: RecvStream,
        ctx: JoinContext,
        passphrase: &[u8],
        signer: &(dyn RootSigner + Send + Sync),
        store: &Store,
        ring: &tokio::sync::Mutex<PrekeyRing>,
        pending_joins: u32,
        slot: Option<(
            std::sync::Arc<std::sync::atomic::AtomicBool>,
            Option<tokio::sync::oneshot::Receiver<()>>,
        )>,
        admit_before_accepting: F,
    ) -> Result<JoinOutcome>
    where
        F: FnOnce(crate::identity::composite::CompositePublicKey) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let cfg = ResponderConfig {
            ctx,
            passphrase,
            root: signer,
            base_difficulty: Difficulty::DEFAULT_INVITE,
            pending_joins,
            now_secs: self.now(),
            worked: slot
                .as_ref()
                .map(|(worked, _)| std::sync::Arc::clone(worked)),
        };
        let ended = slot.and_then(|(_, ended)| ended);
        run_responder(
            send,
            recv,
            peer,
            &cfg,
            store,
            ring,
            ended,
            admit_before_accepting,
        )
        .await
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

/// Where a bundle record goes in a batch sent to a board: the creator first, then each
/// joiner by the time it was witnessed. A member can only witness after it joined, so this
/// puts every witness ahead of the members it admitted, and a board that takes a bundle only
/// on a witness it can already check (V210-70) takes a whole batch in one pass.
fn chain_order(record: &MemberBundleRecord) -> (u8, u64) {
    match record.admission.witness() {
        None => (0, 0),
        Some(w) => (1, w.timestamp),
    }
}

/// The addresses a rung tried, rendered for a person to read.
fn join_addrs(addrs: &[std::net::SocketAddr]) -> String {
    addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// **For proofs only.** When set, a reach whose first rung connected waits this many milliseconds
/// before it files that connection, which stands for a ladder whose filing is slow (a probe of a
/// held connection, a busy machine): the other rungs finish meanwhile. A proof uses it to make a
/// member's two circuits through two relays both connect before either is filed, every run (#335).
/// Nothing a person runs sets it; unset, nothing changes. Not compiled in without the `test-knobs`
/// feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_LADDER_SETTLE_ENV: &str = "VOX_TEST_LADDER_SETTLE_MS";

/// [`TEST_LADDER_SETTLE_ENV`]'s milliseconds, if set.
#[cfg(feature = "test-knobs")]
fn test_ladder_settle_ms() -> Option<u64> {
    std::env::var(TEST_LADDER_SETTLE_ENV)
        .ok()
        .and_then(|v| v.trim().parse().ok())
}

/// A peer id shortened to the first four bytes, which is enough to tell two helpers apart
/// in a diagnostic without putting a full fingerprint in front of somebody.
pub(crate) fn short_id(id: Digest32) -> String {
    // **The same rendering the rest of the product uses for an identity**, because these
    // ids are read side by side with it and were not comparable.
    //
    // This printed four bytes as hex while `vox daemon: identity …`, `vox node: identity …`,
    // invite links and every CLI message print base32. So an operator saw
    //
    //     vox daemon: identity dv5w5nclhdyffrdcgjzghi4jsxqumlzufeoufvbljliluisy5guq
    //     vox: a board would not take our address (board c181cc9a) — not a channel member
    //     vox: cannot join: c92c1ff9: peer unreachable — circuit via c181cc9a
    //
    // and could not tell whether `c92c1ff9` was the member that was away, the one that was
    // up, or the anchor — the three cases that decide what is actually wrong. Two people
    // spent an evening inferring which peer a diagnostic referred to, from diagnostics that
    // had been made specific precisely so they would not have to.
    //
    // Twelve characters of base32, matching the CLI's own `short`, so a fingerprint printed
    // anywhere can be matched by eye against one printed anywhere else.
    crate::node::link::b32_encode(&id)
        .chars()
        .take(12)
        .collect()
}
