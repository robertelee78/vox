//! The `Node` actor and its handle (ADR-016 §"The `Node`: one actor, one writer,
//! one secrets boundary"; M13.4).
//!
//! One tokio task owns the [`Profile`] (the unlocked identity when unlocked) and
//! every open [`ChannelState`] (its SEK, DAG, chains). It is the **single
//! writer** of the store. Clients hold a [`NodeHandle`] and talk to it only
//! through the [`crate::node::api`] types:
//! - commands go in over an `mpsc` with a per-command `oneshot` reply
//!   ([`NodeHandle::apply`]);
//! - the latest [`NodeView`] comes out over a `watch` ([`NodeHandle::view`]);
//! - ordered [`NodeEvent`]s come out over an `mpsc` ([`NodeHandle::next_event`]).
//!
//! Commands are processed strictly in order; a KDF-heavy command (unlock, create
//! or open a channel — Argon2id at 256 MiB) runs inline in the actor, so later
//! commands queue behind it for the ~1 s it takes. That serialization is the
//! design, not a limitation: the actor is the one place secrets are handled.
//!
//! The clock is injected ([`Node::spawn_with`]) so tests are deterministic; the
//! default is the system clock — the node is the boundary where wall-clock time
//! legitimately enters (every library layer takes `now_secs` from its caller).
//!
//! Dropping the last [`NodeHandle`] closes the command channel; the actor then
//! locks (wiping every SEK and the signer) and exits.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch, Mutex};

use crate::atrest::sek::Argon2Profile;
use crate::error::Error;
use crate::hash::Digest32;
use crate::identity::composite::CompositePublicKey;
use crate::nat::bootstrap::{BootstrapNode, BootstrapSet};
use crate::node::api::{
    ChannelDetail, ChannelSummary, Fault, IdentityInfo, MessageRow, NodeCommand, NodeEvent,
    NodeView, Outcome, Secret,
};
use crate::node::channel::{ChannelState, Rendered};
use crate::node::net::PeerPolicy;
use crate::node::network::{Inbound, NodeNet};
use crate::node::paths::Paths;
use crate::node::prekeys::{self, PrekeyRing};
use crate::node::profile::Profile;
use crate::node::syncstream::{SyncSchedule, SyncTrigger};
use crate::transport::quic::VoxConnection;

/// Command queue depth (commands beyond it apply backpressure to the client).
const COMMAND_QUEUE: usize = 64;
/// Event queue depth. A client that stops draining events eventually blocks the
/// actor's event emission; the TUI drains continuously (ADR-015).
const EVENT_QUEUE: usize = 256;

/// A channel's state, shared so a long-running ADR-008 session can hold it without
/// making it invisible to everything else.
///
/// The actor remains the only thing that *adds or removes* channels; what changed in
/// M14.7f is that a sync session no longer takes ownership. Taking the channel out of
/// the map meant a join, a send or a key delivery arriving mid-session found no
/// channel and failed — three symptoms of one cause. A guard makes them wait the few
/// milliseconds instead, which is the behaviour a client expects.
type SharedChannel = Arc<tokio::sync::Mutex<ChannelState>>;

/// How often the actor re-evaluates its sync schedule. The ADR-016 policy itself
/// (on connect, after a local append, every 30 s otherwise) lives in
/// [`SyncSchedule`]; this is only the resolution at which it is checked, so "a push
/// immediately after a local append" means *within one tick* — authoring never waits
/// on the network.
const TICK: Duration = Duration::from_secs(1);

/// Bound on the internal network→actor queue. Inbound streams are back-pressured
/// rather than dropped: a full queue slows the accept loop, it never loses work.
const NET_QUEUE: usize = 64;

/// Put a pre-join record on the board at `conn`. A **refusal is fine**: it means our
/// previous announcement is still live (the ADR-012 refresh floor declines a faster
/// replacement), and being announced is all this is for. Only a transport failure is
/// an error.
async fn announce(conn: &VoxConnection, prejoin_wire: &[u8]) -> crate::error::Result<()> {
    let mut client = crate::nat::service::RendezvousClient::open(conn).await?;
    let res = match client.put(prejoin_wire).await {
        Ok(()) | Err(crate::error::Error::RendezvousRejected(_)) => Ok(()),
        Err(e) => Err(e),
    };
    client.finish();
    res
}

/// When granted mappings must be re-requested: half the shortest granted lifetime
/// (the renewal interval RFC 6887 §11.2.1 recommends), or `None` when no gateway
/// granted anything and so there is nothing to keep alive.
///
/// Half the *shortest* lifetime, not the requested one: a gateway may grant less than
/// asked, and the mapping that expires first is the one that governs.
fn renew_at(now: u64, mappings: &[crate::nat::portmap::PortMapping]) -> Option<u64> {
    mappings
        .iter()
        .map(|m| m.lifetime_secs)
        .min()
        // `max(2)` keeps the interval at one second or more: a zero would re-request
        // on every tick.
        .map(|l| now + u64::from(l.max(2) / 2))
}

/// Where a node's endpoint binds.
#[derive(Clone)]
pub enum Bind {
    /// A UDP address (the wildcard is the normal choice: what the node *advertises*
    /// comes from the ADR-012 ladder, not from here).
    Addr(std::net::SocketAddr),
    /// A caller-supplied datagram socket — a simulated network with NAT devices, or
    /// any other substrate (`VoxEndpoint::bind_abstract`).
    Socket(Arc<dyn quinn::AsyncUdpSocket>),
}

impl std::fmt::Debug for Bind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bind::Addr(a) => write!(f, "Bind::Addr({a})"),
            Bind::Socket(s) => write!(f, "Bind::Socket({s:?})"),
        }
    }
}

/// Everything a node is configured with. [`Node::spawn_config`] takes it; the other
/// constructors are shorthands for common shapes of it.
#[derive(Clone)]
pub struct NodeConfig {
    /// The wall clock (tests inject a fixed one).
    pub clock: Clock,
    /// The Argon2id profile for every at-rest derivation.
    pub argon2: Argon2Profile,
    /// Where to bind, or `None` for a node that does not network.
    pub bind: Option<Bind>,
    /// An override for the ADR-005 PoW parameters a join binds (tests reduce them).
    pub pow_params: Option<crate::join::pow::PowParams>,
    /// The anchors this node publishes to, reads from, climbs its ladder through and
    /// names in invite links (ADR-012 §"Bootstrap": the user's own always-on node).
    pub anchors: BootstrapSet,
}

impl std::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("bind", &self.bind)
            .field("pow_params", &self.pow_params)
            .field("anchors", &self.anchors.len())
            .finish_non_exhaustive()
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeConfig {
    /// The production shape: system clock, production Argon2id, not networked, no
    /// anchors.
    #[must_use]
    pub fn new() -> Self {
        Self {
            clock: system_clock(),
            argon2: Argon2Profile::default(),
            bind: None,
            pow_params: None,
            anchors: BootstrapSet::new(),
        }
    }

    /// Use this clock.
    #[must_use]
    pub fn clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Use this Argon2id profile.
    #[must_use]
    pub fn argon2(mut self, argon2: Argon2Profile) -> Self {
        self.argon2 = argon2;
        self
    }

    /// Network, binding here.
    #[must_use]
    pub fn bind(mut self, bind: Bind) -> Self {
        self.bind = Some(bind);
        self
    }

    /// Use these anchors.
    #[must_use]
    pub fn anchors(mut self, anchors: BootstrapSet) -> Self {
        self.anchors = anchors;
        self
    }
}

/// Work the network produced that only the actor can handle, because it needs
/// channel state (ADR-016: the actor stays the single writer).
enum NetEvent {
    /// The ladder's publish side finished: this node now knows what to advertise, and
    /// which mappings a gateway granted (each of which will need renewing).
    AddressesDiscovered {
        /// Every granted mapping or pinhole, possibly none.
        mappings: Vec<crate::nat::portmap::PortMapping>,
    },
    /// A configured anchor answered its dial (ADR-016 M15.1): it gets the ordinary
    /// bookkeeping, the `Anchor` class, and every open channel's records.
    AnchorConnected {
        /// The connection to the anchor.
        conn: Arc<VoxConnection>,
    },
    /// A better path to a peer landed — a punch answered, or an upgrade behind a
    /// relayed dial (ADR-012 rungs 3–4, M15.1b): the connection needs the same
    /// bookkeeping a dialled one gets — a stream loop and a sync schedule. The manager
    /// has already made it the peer's primary and retired the old one.
    BetterPath {
        /// The connection that landed.
        conn: Arc<VoxConnection>,
    },
    /// A peer connected inbound: it gets a sync schedule, due immediately.
    Connected {
        /// The authenticated peer.
        peer: Digest32,
    },
    /// A sync session finished and is handing the channel back.
    ///
    /// A session **cannot** be awaited inside the actor loop: two nodes that each
    /// start one at the same moment would each be waiting for the other to serve the
    /// responder side, and neither could — a deadlock the M14 gate reproduced the
    /// moment sync became automatic. So a session owns the channel on its own task
    /// and returns it here, leaving the actor free to serve the peer meanwhile.
    SyncDone {
        /// The channel that was reconciled.
        channel_id: Digest32,
        /// What the session did, or why it failed.
        outcome: crate::error::Result<crate::node::channel::SyncOutcome>,
    },
    /// A peer connected and opened a stream the actor must handle.
    Stream {
        /// The connection it arrived on, kept alive for the reply.
        conn: Arc<crate::transport::quic::VoxConnection>,
        /// The authorized stream.
        inbound: Inbound,
    },
    /// The accept loop stopped (the endpoint closed).
    Stopped,
}

// The clock lives in `crate::time` (M14.2: the rendezvous service needs it too and
// `nat` must not depend on `node`); re-exported so this path stays stable.
pub use crate::time::{system_clock, Clock};

/// Serve every stream a peer opens on one connection, forwarding to the actor the
/// ones that need channel state (the board is served inside `accept_stream`).
///
/// **Every** connection needs this, dialed or accepted: QUIC is symmetric, so a peer
/// we dialed will open streams back at us — a member we joined through has to be able
/// to deliver its sender key on the connection *we* opened.
fn spawn_stream_loop(net: Arc<NodeNet>, conn: Arc<VoxConnection>, tx: mpsc::Sender<NetEvent>) {
    let peer = conn.peer_id();
    // Ask this peer what source address it sees for us (ADR-012 rung 3's observed
    // address), on its own task so the stream loop starts serving immediately. It is
    // best-effort: a peer that will not answer costs nothing but a punch that has one
    // fewer candidate to offer.
    {
        let net = Arc::clone(&net);
        tokio::spawn(async move {
            let _ = net.learn_observed(peer).await;
        });
    }
    tokio::spawn(async move {
        // One stream failing is **not** the connection failing. A refused kind, a
        // malformed frame or a peer that abandons a stream must not stop the others
        // being served: a peer that opens a bad `coord` stream would otherwise take its
        // own sync path down with it, and the node would go quiet until it reconnected.
        // The loop ends when the connection itself is gone — or after this many
        // consecutive failures, which cannot happen without the connection being
        // unusable and which keeps a pathological peer from spinning this task.
        const MAX_CONSECUTIVE_STREAM_FAILURES: u32 = 16;
        let mut failures = 0;
        loop {
            match net.accept_stream(&conn).await {
                Ok(
                    Inbound::ServedRendezvous { .. }
                    | Inbound::ServedCoord { .. }
                    | Inbound::ServedCircuit { .. },
                ) => failures = 0,
                Ok(inbound) => {
                    failures = 0;
                    let event = NetEvent::Stream {
                        conn: Arc::clone(&conn),
                        inbound,
                    };
                    if tx.send(event).await.is_err() {
                        return; // the actor is gone
                    }
                }
                Err(_) => {
                    if conn.quinn().close_reason().is_some() {
                        break; // the peer or the network closed it
                    }
                    failures += 1;
                    if failures >= MAX_CONSECUTIVE_STREAM_FAILURES {
                        break;
                    }
                }
            }
        }
        // This peer's report of our address dies with its connection.
        net.forget_observed(&peer);
    });
}

/// Accept connections and their streams forever, forwarding to the actor the ones
/// that need channel state. Each connection gets its own task, so a slow peer
/// cannot stall the others; the board is served inside `accept_stream`.
fn spawn_accept_loop(net: Arc<NodeNet>, tx: mpsc::Sender<NetEvent>) {
    tokio::spawn(async move {
        loop {
            // Open-swarm default: any authenticated identity may connect, because a
            // node that serves the board must accept peers it does not know yet
            // (ADR-011/ADR-012). What a peer may *open* is the stream-kind gate.
            let accepted = net
                .manager()
                .accept(crate::transport::quic::Admission::AcceptAnyAuthenticated)
                .await;
            match accepted {
                Ok(Some(conn)) => {
                    let peer = conn.peer_id();
                    spawn_stream_loop(Arc::clone(&net), conn, tx.clone());
                    if tx.send(NetEvent::Connected { peer }).await.is_err() {
                        break; // the actor is gone
                    }
                }
                // The endpoint closed, or a handshake failed. `accept` returns `Err`
                // on a single failed handshake (ADR-011 known gap), so keep going on
                // an error and stop only when the endpoint is closed.
                Ok(None) => break,
                Err(_) => continue,
            }
        }
        let _ = tx.send(NetEvent::Stopped).await;
    });
}

/// A client's handle to a running node.
#[derive(Debug, Clone)]
pub struct NodeHandle {
    cmd_tx: mpsc::Sender<(NodeCommand, oneshot::Sender<Outcome>)>,
    view_rx: watch::Receiver<NodeView>,
    events: Arc<Mutex<mpsc::Receiver<NodeEvent>>>,
}

impl NodeHandle {
    /// The latest view (cheap clone of the watch value).
    #[must_use]
    pub fn view(&self) -> NodeView {
        self.view_rx.borrow().clone()
    }

    /// A receiver that resolves whenever the view changes.
    #[must_use]
    pub fn watch(&self) -> watch::Receiver<NodeView> {
        self.view_rx.clone()
    }

    /// Apply a command and await its outcome. [`Fault::ShuttingDown`] if the
    /// actor has stopped.
    pub async fn apply(&self, command: NodeCommand) -> Outcome {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send((command, tx)).await.is_err() {
            return Outcome::Failed(Fault::ShuttingDown);
        }
        rx.await.unwrap_or(Outcome::Failed(Fault::ShuttingDown))
    }

    /// The next ordered event, or `None` once the actor has stopped.
    pub async fn next_event(&self) -> Option<NodeEvent> {
        self.events.lock().await.recv().await
    }

    /// Non-blocking event poll (for a synchronous UI loop).
    pub fn try_next_event(&self) -> Option<NodeEvent> {
        self.events.try_lock().ok()?.try_recv().ok()
    }
}

/// The node actor's state (owned by its task).
pub struct Node {
    paths: Paths,
    profile: Option<Profile>,
    /// The network, present only while the identity is unlocked: binding the QUIC
    /// endpoint needs the identity's signer, so a locked node has no network
    /// identity to present and serves nothing (M14.7d).
    net: Option<Arc<NodeNet>>,
    /// Sender the actor keeps so the network queue never closes under it.
    net_tx: mpsc::Sender<NetEvent>,
    /// Where the endpoint binds, if this node networks at all.
    bind: Option<Bind>,
    /// The anchors this node is configured with (ADR-012 §"Bootstrap", ADR-016
    /// M15.1): dialled when the network starts, given the `Anchor` class, published
    /// to, and named in every invite link.
    anchors: BootstrapSet,
    /// Every identity this node treats as an anchor: the configured set plus the
    /// anchors of each open channel. The peer policy is rebuilt from channel
    /// membership whenever channels change, and these are carried into it.
    anchor_ids: std::collections::BTreeSet<Digest32>,
    /// An override for the ADR-005 PoW parameters a join binds. `None` means the
    /// channel's own (production `(200,9)`); tests reduce them so the debug suite
    /// does not grind, exactly as they reduce the Argon2 profile.
    pow_params: Option<crate::join::pow::PowParams>,
    /// Connections (by quinn's stable id) that already have a stream loop, so adopting
    /// one twice does not start a second. Keyed by connection, not by peer: an upgrade
    /// gives a peer a second connection that needs its own loop (M15.1b).
    stream_loops: std::collections::BTreeSet<usize>,
    /// The gateway port mapping in force, if one was granted. Held so it can be
    /// renewed before its lifetime elapses (RFC 6886/6887 put renewal on the client).
    port_mappings: Vec<crate::nat::portmap::PortMapping>,
    /// When the granted mappings must be renewed (unix seconds), or `None` when there
    /// is nothing to renew. A mapping a gateway grants for two hours outlives no
    /// long-running node by itself: it is re-requested at half its lifetime, the
    /// interval RFC 6887 §11.2.1 recommends.
    renew_mappings_at: Option<u64>,
    /// Per-peer ADR-008 sync clock (ADR-016 §"Sync scheduling").
    schedules: BTreeMap<Digest32, SyncSchedule>,
    /// Channels with a local append not yet pushed to peers.
    pending_push: std::collections::BTreeSet<Digest32>,
    /// Per-channel record sequence for board publishes (strictly increasing per
    /// `(author, channel, epoch)`, ADR-012).
    record_seq: BTreeMap<Digest32, u64>,
    /// Pairwise ADR-004 sessions, keyed by `(channel, peer)` — a session is bound to
    /// a `(channelID, epoch)`, so one peer may have several. In memory for this
    /// process only: persisting ratchet state is not part of M14, so a restart
    /// re-establishes a session on the next join or key exchange.
    sessions: BTreeMap<(Digest32, Digest32), crate::pairwise::session::Session>,
    /// The identity's key-agreement keys (ADR-002 §2), held only while unlocked:
    /// loaded (or generated on first use) by [`crate::node::prekeys::load_or_create`]
    /// after the identity unlocks and dropped on lock, so no prekey secret is in
    /// memory behind a lock (ADR-010/015). M14.4+ publishes its bundle.
    prekeys: Option<PrekeyRing>,
    channels: BTreeMap<Digest32, SharedChannel>,
    clock: Clock,
    argon2: Argon2Profile,
    view_tx: watch::Sender<NodeView>,
    event_tx: mpsc::Sender<NodeEvent>,
}

impl Node {
    /// Spawn the node for `paths` on the current tokio runtime with the system
    /// clock and the production Argon2id profile. An existing identity is
    /// opened **locked**; a profile without one waits for
    /// [`NodeCommand::CreateIdentity`].
    pub fn spawn(paths: Paths) -> crate::error::Result<NodeHandle> {
        Self::spawn_with(paths, system_clock(), Argon2Profile::default())
    }

    /// [`Node::spawn`] plus networking: the node binds `bind` when its identity
    /// unlocks and tears the endpoint down when it locks.
    pub fn spawn_networked(
        paths: Paths,
        bind: std::net::SocketAddr,
    ) -> crate::error::Result<NodeHandle> {
        Self::spawn_full(paths, system_clock(), Argon2Profile::default(), Some(bind))
    }

    /// [`Node::spawn`] with an injected clock and Argon2id profile (tests use the
    /// reduced profile and a fixed clock).
    pub fn spawn_with(
        paths: Paths,
        clock: Clock,
        argon2: Argon2Profile,
    ) -> crate::error::Result<NodeHandle> {
        Self::spawn_full(paths, clock, argon2, None)
    }

    /// [`Node::spawn_with`] with an optional bind address for networking.
    pub fn spawn_full(
        paths: Paths,
        clock: Clock,
        argon2: Argon2Profile,
        bind: Option<std::net::SocketAddr>,
    ) -> crate::error::Result<NodeHandle> {
        Self::spawn_configured(paths, clock, argon2, bind, None)
    }

    /// [`Node::spawn_full`] with an ADR-005 PoW-parameter override for the join
    /// responder (tests only reduce it; production passes `None`).
    pub fn spawn_configured(
        paths: Paths,
        clock: Clock,
        argon2: Argon2Profile,
        bind: Option<std::net::SocketAddr>,
        pow_params: Option<crate::join::pow::PowParams>,
    ) -> crate::error::Result<NodeHandle> {
        let mut cfg = NodeConfig::new().clock(clock).argon2(argon2);
        cfg.bind = bind.map(Bind::Addr);
        cfg.pow_params = pow_params;
        Self::spawn_config(paths, cfg)
    }

    /// Spawn the node with a full [`NodeConfig`]: the one constructor every other
    /// one is a shorthand for.
    pub fn spawn_config(paths: Paths, cfg: NodeConfig) -> crate::error::Result<NodeHandle> {
        let NodeConfig {
            clock,
            argon2,
            bind,
            pow_params,
            anchors,
        } = cfg;
        let profile = if Profile::exists(&paths) {
            Some(Profile::open(paths.clone())?)
        } else {
            None
        };
        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_QUEUE);
        let (event_tx, event_rx) = mpsc::channel(EVENT_QUEUE);
        let (net_tx, net_rx) = mpsc::channel(NET_QUEUE);
        let node = Self {
            paths,
            profile,
            net: None,
            net_tx,
            bind,
            anchor_ids: anchors.nodes().iter().map(|n| n.id).collect(),
            anchors,
            pow_params,
            stream_loops: std::collections::BTreeSet::new(),
            port_mappings: Vec::new(),
            renew_mappings_at: None,
            schedules: BTreeMap::new(),
            pending_push: std::collections::BTreeSet::new(),
            record_seq: BTreeMap::new(),
            sessions: BTreeMap::new(),
            prekeys: None,
            channels: BTreeMap::new(),
            clock,
            argon2,
            view_tx: watch::Sender::new(NodeView::default()),
            event_tx,
        };
        let view_rx = node.view_tx.subscribe();
        node.publish_initial();
        tokio::spawn(node.run(cmd_rx, net_rx));
        Ok(NodeHandle {
            cmd_tx,
            view_rx,
            events: Arc::new(Mutex::new(event_rx)),
        })
    }

    async fn run(
        mut self,
        mut cmd_rx: mpsc::Receiver<(NodeCommand, oneshot::Sender<Outcome>)>,
        mut net_rx: mpsc::Receiver<NetEvent>,
    ) {
        // Two inputs, one writer: client commands and the network's inbound work are
        // interleaved here, so channel state is only ever mutated by this task
        // (ADR-016). The actor holds a `net_tx` clone, so `net_rx` never closes and
        // this select cannot spin on a dead branch.
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                received = cmd_rx.recv() => {
                    let Some((command, reply)) = received else { break };
                    let shutdown = matches!(command, NodeCommand::Shutdown);
                    let outcome = self.handle(command).await;
                    self.publish().await;
                    // A dropped reply receiver is the caller's choice, not an error.
                    let _ = reply.send(outcome);
                    if shutdown {
                        break;
                    }
                }
                Some(event) = net_rx.recv() => {
                    self.handle_net(event).await;
                    self.publish().await;
                }
                _ = ticker.tick() => {
                    if let Some(net) = self.net.as_ref() {
                        // Connections a better path displaced are closed once their
                        // grace is up (M15.1b).
                        net.manager().retire_expired();
                    }
                    self.renew_mappings_if_due();
                    if self.run_due_syncs().await {
                        self.publish().await;
                    }
                }
            }
        }
        // Channel closed or shutdown: lock (wipe every SEK + the signer) and stop.
        self.stop_network();
        self.lock_all().await;
        self.publish().await;
        let _ = self.event_tx.send(NodeEvent::Shutdown).await;
    }

    async fn handle(&mut self, command: NodeCommand) -> Outcome {
        match command {
            NodeCommand::CreateIdentity { passphrase } => self.create_identity(&passphrase),
            NodeCommand::Unlock { passphrase } => self.unlock(&passphrase).await,
            NodeCommand::Lock => {
                self.lock_all().await;
                Outcome::Done
            }
            NodeCommand::CreateChannel {
                local_name,
                passphrase,
            } => self.create_channel(&local_name, &passphrase).await,
            NodeCommand::OpenChannel {
                channel_id,
                passphrase,
            } => self.open_channel(&channel_id, &passphrase).await,
            NodeCommand::CloseChannel { channel_id } => self.close_channel(&channel_id).await,
            NodeCommand::SendText { channel_id, text } => self.send_text(&channel_id, &text).await,
            NodeCommand::Invite { channel_id } => self.invite(&channel_id).await,
            NodeCommand::JoinChannel {
                link,
                local_name,
                passphrase,
            } => self.join_channel(&link, &local_name, &passphrase).await,
            NodeCommand::Consent { channel_id, target } => self.consent(&channel_id, target).await,
            NodeCommand::Sync { channel_id } => self.sync_channel(&channel_id).await,
            NodeCommand::Shutdown => Outcome::Done,
        }
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    fn create_identity(&mut self, passphrase: &Secret) -> Outcome {
        if self.profile.is_some() {
            return Outcome::Failed(Fault::IdentityExists);
        }
        let now = self.now();
        match Profile::create_with_profile(self.paths.clone(), passphrase, now, self.argon2) {
            Ok(p) => {
                self.profile = Some(p);
                // A fresh identity gets its prekey ring immediately: without it the
                // node has nothing to publish and cannot answer PQXDH.
                if let Err(e) = self.load_prekeys(now) {
                    return Outcome::Failed(fault_of(&e));
                }
                if let Err(e) = self.start_network() {
                    return Outcome::Failed(fault_of(&e));
                }
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    async fn unlock(&mut self, passphrase: &Secret) -> Outcome {
        let Some(profile) = self.profile.as_mut() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        match profile.unlock(passphrase) {
            Ok(()) => {
                let now = self.now();
                if let Err(e) = self.load_prekeys(now) {
                    // The identity is usable but the ring is not: lock again rather
                    // than run without key-agreement keys.
                    self.lock_all().await;
                    return Outcome::Failed(fault_of(&e));
                }
                if let Err(e) = self.start_network() {
                    self.lock_all().await;
                    return Outcome::Failed(fault_of(&e));
                }
                let _ = self.event_tx.send(NodeEvent::Unlocked).await;
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    /// Start networking for the unlocked identity: bind the endpoint as this
    /// identity and spawn the accept loop. A no-op when this node does not network,
    /// or when it is already up.
    fn start_network(&mut self) -> crate::error::Result<()> {
        let Some(bind) = self.bind.as_ref() else {
            return Ok(());
        };
        if self.net.is_some() {
            return Ok(());
        }
        let profile = self
            .profile
            .as_ref()
            .ok_or(crate::error::Error::Profile("no identity in this profile"))?;
        let endpoint = Arc::new(match bind {
            Bind::Addr(addr) => {
                crate::transport::quic::VoxEndpoint::bind(profile.signer()?, *addr)?
            }
            Bind::Socket(socket) => crate::transport::quic::VoxEndpoint::bind_abstract(
                profile.signer()?,
                Arc::clone(socket),
            )?,
        });
        let net = Arc::new(NodeNet::new(endpoint, Arc::clone(&self.clock)));
        self.net = Some(Arc::clone(&net));
        // The configured anchors are dialled at once, each on its own task: they are
        // where this node's records go and the helpers its ladder climbs through, and
        // an anchor that is down must not hold up the ones that are not.
        for anchor in self.anchors.nodes() {
            let net = Arc::clone(&net);
            let tx = self.net_tx.clone();
            let (id, endpoints) = (anchor.id, anchor.endpoints.clone());
            tokio::spawn(async move {
                if let Ok(conn) = net.manager().connect(id, &endpoints).await {
                    let _ = tx.send(NetEvent::AnchorConnected { conn }).await;
                }
            });
        }
        // No membership refresh here: the network only starts when the identity
        // unlocks, and `lock_all` cleared every channel, so there is nothing to
        // publish yet. The *address* discovery does run, on its own task, because it
        // talks to the network (a route probe and a gateway request) and must not hold
        // up the unlock.
        let discover = Arc::clone(&net);
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let mappings = discover.refresh_advertised().await;
            let _ = tx.send(NetEvent::AddressesDiscovered { mappings }).await;
        });
        spawn_accept_loop(net, self.net_tx.clone());
        Ok(())
    }

    /// Tear the network down: close every connection and the endpoint, so a locked
    /// node presents no network identity at all.
    fn stop_network(&mut self) {
        if let Some(net) = self.net.take() {
            net.manager().close_all();
            net.manager().endpoint().close();
        }
        self.stream_loops.clear();
        self.port_mappings.clear();
        self.renew_mappings_at = None;
        self.schedules.clear();
        self.pending_push.clear();
    }

    /// Put a channel's genesis and this node's records on an **anchor's** board
    /// (ADR-016: "the configured bootstrap set is simply the anchors a client
    /// publishes to and reads from").
    ///
    /// Publishing only locally is not enough and the gate proved it: a member's key is
    /// discoverable to *others* only where they will look for it, so a node that keeps
    /// its bundle to itself cannot be admitted as a log author by anyone — and an
    /// ADR-008 session then hard-fails on its first entry. A refusal is normal (the
    /// ADR-012 refresh floor declining a faster refresh), not an error.
    async fn publish_channel_to_anchor(
        &mut self,
        channel_id: &Digest32,
        conn: &Arc<VoxConnection>,
    ) {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        let seq = {
            let entry = self.record_seq.entry(*channel_id).or_insert(0);
            *entry = entry.saturating_add(1);
            *entry
        };
        let (genesis_wire, epoch) = match self.channels.get(channel_id) {
            Some(shared) => {
                let c = shared.lock().await;
                (c.genesis().to_wire(), c.epoch())
            }
            None => return,
        };
        let records = {
            let Some(profile) = self.profile.as_ref() else {
                return;
            };
            let Ok(signer) = profile.signer() else { return };
            let Some(ring) = self.prekeys.as_ref() else {
                return;
            };
            net.own_records(signer, channel_id, epoch, ring, seq)
        };
        let Ok((address, bundle)) = records else {
            return;
        };
        let Ok(mut client) = crate::nat::service::RendezvousClient::open(conn).await else {
            return;
        };
        let _ = client.put(&genesis_wire).await;
        let _ = client.put(&address.to_wire()).await;
        let _ = client.put(&bundle.to_wire()).await;
        client.finish();
    }

    /// Make a channel's anchors this node's: record `more` on the channel (persisted
    /// under its SEK) and the configured set with it, treat every one as an anchor,
    /// and dial any not yet connected. Called when a channel is created, opened or
    /// joined.
    async fn adopt_channel_anchors(&mut self, channel_id: &Digest32, more: Option<&BootstrapSet>) {
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return;
        };
        let anchors = {
            let mut channel = shared.lock().await;
            if let Some(profile) = self.profile.as_ref() {
                let mut add = self.anchors.clone();
                if let Some(more) = more {
                    let _ = add.merge(more);
                }
                let _ = channel.add_anchors(profile.store(), &add);
            }
            channel.anchors().clone()
        };
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        for anchor in anchors.nodes() {
            if anchor.id == net.local_id() {
                continue;
            }
            self.anchor_ids.insert(anchor.id);
            if net.manager().existing(&anchor.id).is_some() {
                continue;
            }
            let net = Arc::clone(&net);
            let tx = self.net_tx.clone();
            let (id, endpoints) = (anchor.id, anchor.endpoints.clone());
            tokio::spawn(async move {
                if let Ok(conn) = net.manager().connect(id, &endpoints).await {
                    let _ = tx.send(NetEvent::AnchorConnected { conn }).await;
                }
            });
        }
    }

    /// Put a channel's genesis and this node's records on every anchor this node is
    /// connected to (its configured set and the channel's own).
    async fn publish_channel_to_anchors(&mut self, channel_id: &Digest32) {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        let anchors: Vec<Arc<VoxConnection>> = self
            .anchor_ids
            .iter()
            .filter_map(|id| net.manager().existing(id))
            .collect();
        for conn in anchors {
            self.publish_channel_to_anchor(channel_id, &conn).await;
        }
    }

    /// Put a channel's genesis and this node's records on its own board, so a joiner
    /// can find out what the channel is and how to reach us (ADR-007/ADR-012). A
    /// refusal here is normal, not an error: the board already holds a current record
    /// and the ADR-012 refresh floor declines a faster one.
    async fn publish_channel_locally(&mut self, channel_id: &Digest32) {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        let seq = {
            let entry = self.record_seq.entry(*channel_id).or_insert(0);
            *entry = entry.saturating_add(1);
            *entry
        };
        let Some(profile) = self.profile.as_ref() else {
            return;
        };
        let Ok(signer) = profile.signer() else { return };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return;
        };
        let channel = shared.lock().await;
        let Some(ring) = self.prekeys.as_ref() else {
            return;
        };
        let _ = net.publish_local(&channel.genesis().to_wire());
        if let Ok((address, bundle)) =
            net.own_records(signer, channel_id, channel.epoch(), ring, seq)
        {
            let _ = net.publish_local(&address.to_wire());
            let _ = net.publish_local(&bundle.to_wire());
        }
    }

    /// Republish the membership snapshot and peer policy the served board and the
    /// accept path read (see `node::network`). Called whenever channels change.
    async fn refresh_network_view(&self) {
        let Some(net) = self.net.as_ref() else { return };
        let mut policy = PeerPolicy::new();
        for (cid, shared) in &self.channels {
            let ch = shared.lock().await;
            let members: BTreeMap<Digest32, CompositePublicKey> = ch
                .author_keys()
                .into_iter()
                .map(|k| (k.fingerprint(), k))
                .collect();
            policy.add_members(members.keys().copied());
            net.membership().set_channel(*cid, ch.epoch(), members);
        }
        // Anchors are not channel membership: they are carried in by hand.
        for anchor in &self.anchor_ids {
            policy.add_anchor(*anchor);
        }
        // Replacing wholesale would drop the pending joiners the actor is expecting,
        // so they are carried over.
        let previous = net.policy().snapshot();
        net.policy().replace(policy);
        for joiner in previous.pending_joiners() {
            net.policy().expect_joiner(joiner);
        }
    }

    /// Handle one piece of network work.
    async fn handle_net(&mut self, event: NetEvent) {
        match event {
            NetEvent::Stopped => {
                self.net = None;
            }
            NetEvent::AddressesDiscovered { mappings } => {
                // Re-publish every open channel's records: the addresses in them were
                // composed before discovery and may name only loopback.
                self.renew_mappings_at = renew_at(self.now(), &mappings);
                self.port_mappings = mappings;
                let channels: Vec<Digest32> = self.channels.keys().copied().collect();
                for channel_id in channels {
                    self.publish_channel_locally(&channel_id).await;
                    self.publish_channel_to_anchors(&channel_id).await;
                }
            }
            NetEvent::AnchorConnected { conn } => {
                let peer = conn.peer_id();
                self.anchor_ids.insert(peer);
                self.adopt_connection(Arc::clone(&conn));
                self.refresh_network_view().await;
                let channels: Vec<Digest32> = self.channels.keys().copied().collect();
                for channel_id in channels {
                    self.publish_channel_to_anchor(&channel_id, &conn).await;
                }
            }
            NetEvent::BetterPath { conn } => {
                self.adopt_connection(conn);
            }
            NetEvent::Connected { peer } => {
                // A fresh connection syncs at once (ADR-016), then on the interval.
                self.schedules
                    .entry(peer)
                    .or_insert_with(SyncSchedule::connected);
            }
            NetEvent::SyncDone {
                channel_id,
                outcome,
            } => {
                self.refresh_network_view().await;
                if let Ok(o) = outcome {
                    if o.rendered > 0 || o.governance > 0 {
                        let _ = self
                            .event_tx
                            .send(NodeEvent::Synced {
                                channel_id,
                                applied: o.applied as u64,
                                rendered: o.rendered as u64,
                            })
                            .await;
                    }
                }
            }
            NetEvent::Stream { conn, inbound } => {
                // Held for the whole handler: the connection must outlive the streams
                // opened on it, or the peer sees it close mid-exchange.
                let _connection = conn;
                match inbound {
                    Inbound::Join { peer, send, recv } => {
                        self.answer_inbound_join(peer, send, recv).await;
                    }
                    Inbound::Pairwise { peer, recv, .. } => {
                        self.take_inbound_skdm(peer, recv).await;
                    }
                    Inbound::Sync { send, recv, .. } => {
                        self.run_sync_session(send, recv).await;
                    }
                    Inbound::Punch {
                        peer,
                        coordinator,
                        send,
                        recv,
                    } => {
                        self.answer_punch(peer, coordinator, send, recv);
                    }
                    Inbound::NotYetSupported { .. }
                    | Inbound::ServedRendezvous { .. }
                    | Inbound::ServedCoord { .. }
                    | Inbound::ServedCircuit { .. } => {}
                }
            }
        }
    }

    /// Answer an inbound ADR-005 join: the joiner names the channel, and this node
    /// answers only for one it holds open and can answer for (it must still hold the
    /// channel passphrase — M14.7c).
    ///
    /// On success the joiner is admitted as a **log author** (its identity was proved
    /// by the join's PoP and it holds the channel passphrase) and the session is
    /// kept — but it is granted no read access: that waits for this user's consent
    /// (ADR-007).
    async fn answer_inbound_join(
        &mut self,
        peer: Digest32,
        send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) {
        use crate::node::joinstream::{read_join_request, refuse_join};
        let Ok((channel_id, epoch)) = read_join_request(&mut recv).await else {
            refuse_join(send).await;
            return;
        };
        let answerable = match self.channels.get(&channel_id) {
            Some(shared) => {
                let c = shared.lock().await;
                c.can_answer_join() && c.epoch() == epoch
            }
            None => false,
        };
        if !answerable || self.net.is_none() || self.prekeys.is_none() {
            refuse_join(send).await;
            return;
        }
        let now = self.now();
        let net = match self.net.as_ref() {
            Some(n) => Arc::clone(n),
            None => return,
        };
        let outcome = {
            let Some(profile) = self.profile.as_ref() else {
                refuse_join(send).await;
                return;
            };
            let Ok(signer) = profile.signer() else {
                refuse_join(send).await;
                return;
            };
            let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
                refuse_join(send).await;
                return;
            };
            let channel = shared.lock().await;
            let Ok(mut ctx) = channel.join_context() else {
                refuse_join(send).await;
                return;
            };
            if let Some(pow) = self.pow_params {
                ctx.pow_params = pow;
            }
            let Some(ring) = self.prekeys.as_mut() else {
                refuse_join(send).await;
                return;
            };
            net.answer_join(
                peer,
                send,
                recv,
                ctx,
                &channel,
                signer,
                profile.store(),
                ring,
                0,
            )
            .await
        };
        let Ok(outcome) = outcome else { return };
        // The join proved this identity; admit it as an author so its entries are
        // accepted (reading still needs consent).
        let admitted = match (self.profile.as_ref(), self.channels.get(&channel_id)) {
            (Some(profile), Some(shared)) => shared
                .lock()
                .await
                .admit_author(profile.store(), &outcome.peer.identity, now)
                .is_ok(),
            _ => false,
        };
        if admitted {
            self.refresh_network_view().await;
        }
        self.sessions.insert((channel_id, peer), outcome.session);
        if let Some(net) = self.net.as_ref() {
            net.policy().forget_joiner(&peer);
        }
        let _ = self
            .event_tx
            .send(NodeEvent::PeerJoined { channel_id, peer })
            .await;
    }

    /// Dial `peer`, reusing a live connection, and make sure a stream loop is serving
    /// it — a connection we opened must still accept the streams the peer opens back
    /// (its sender key arrives that way).
    async fn dial(
        &mut self,
        peer: Digest32,
        endpoints: &crate::nat::multiaddr::EndpointList,
    ) -> crate::error::Result<Arc<VoxConnection>> {
        let net = self
            .net
            .as_ref()
            .map(Arc::clone)
            .ok_or(crate::error::Error::Unreachable("node is not networked"))?;
        // Whatever rung lands first (M15.1b): through an anchor that is one round
        // trip, and possibly relayed — in which case a better path is tried behind it
        // and swapped in underneath by the manager's preference rule.
        let conn = net.reach(peer, endpoints).await?;
        self.adopt_connection(Arc::clone(&conn));
        if crate::node::net::path_class(&conn) == crate::node::net::PathClass::Relayed {
            let tx = self.net_tx.clone();
            let endpoints = endpoints.clone();
            tokio::spawn(async move {
                if let Some(better) = net.upgrade(peer, &endpoints).await {
                    let _ = tx.send(NetEvent::BetterPath { conn: better }).await;
                }
            });
        }
        Ok(conn)
    }

    /// Give a connection the bookkeeping every connection needs, however it arrived:
    /// a stream loop (a connection we opened must still accept the streams the peer
    /// opens back — its sender key arrives that way) and a sync schedule.
    fn adopt_connection(&mut self, conn: Arc<VoxConnection>) {
        let peer = conn.peer_id();
        if let Some(net) = self.net.as_ref().map(Arc::clone) {
            if self.stream_loops.insert(conn.quinn().stable_id()) {
                spawn_stream_loop(net, conn, self.net_tx.clone());
            }
        }
        // A new connection syncs at once, then on the interval (ADR-016).
        self.schedules
            .entry(peer)
            .or_insert_with(SyncSchedule::connected);
    }

    /// Answer a punch session a coordinator relayed here (ADR-012 rung 3), on its own
    /// task: the DCUtR exchange plus the synchronized dial takes seconds, and the
    /// actor must keep serving meanwhile.
    fn answer_punch(
        &mut self,
        peer: Digest32,
        coordinator: Digest32,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            // A punch that fails is the ADR-012 limit, not an error to report: the peer
            // keeps whatever path it had, and the coordinator keeps working.
            if let Ok(conn) = net.answer_punch(peer, coordinator, send, recv).await {
                let _ = tx.send(NetEvent::BetterPath { conn }).await;
            }
        });
    }

    /// Produce an invite link naming this node as anchor and responder.
    async fn invite(&mut self, channel_id: &Digest32) -> Outcome {
        let Some(net) = self.net.as_ref() else {
            return Outcome::Failed(Fault::NotNetworked);
        };
        if !self.channels.contains_key(channel_id) {
            return Outcome::Failed(Fault::UnknownChannel);
        }
        // The link names the swarm's anchors — the channel's own, then the configured
        // set — and this node last: an anchor is reachable by design, this node's own
        // addresses may not be, and a joiner tries them in this order.
        let mut anchors: Vec<BootstrapNode> = Vec::new();
        if let Some(shared) = self.channels.get(channel_id) {
            for n in shared.lock().await.anchors().nodes() {
                anchors.push(n.clone());
            }
        }
        for n in self.anchors.nodes() {
            if !anchors.iter().any(|a| a.id == n.id) {
                anchors.push(n.clone());
            }
        }
        if let Ok(own) = net.local_endpoints() {
            if !anchors.iter().any(|a| a.id == net.local_id()) {
                if let Ok(me) = BootstrapNode::new(net.local_id(), own) {
                    anchors.push(me);
                }
            }
        }
        anchors.truncate(crate::node::link::MAX_LINK_ANCHORS);
        let link =
            match crate::node::link::InviteLink::new(*channel_id, anchors, Some(net.local_id())) {
                Ok(l) => l,
                Err(e) => return Outcome::Failed(fault_of(&e)),
            };
        let _ = self
            .event_tx
            .send(NodeEvent::InviteLink {
                channel_id: *channel_id,
                url: link.to_url(),
            })
            .await;
        Outcome::Done
    }

    /// Join a channel from an invite link (ADR-016 §"Join over the network"): resolve
    /// the anchor, read the board, announce a pre-join record, run the ADR-005 join,
    /// then build local channel state and publish our own records.
    async fn join_channel(&mut self, link: &str, local_name: &str, passphrase: &Secret) -> Outcome {
        let parsed = match crate::node::link::InviteLink::parse(link) {
            Ok(p) => p,
            Err(e) => return Outcome::Failed(fault_of(&e)),
        };
        let (Some(net), Some(_)) = (self.net.as_ref().map(Arc::clone), self.prekeys.as_ref())
        else {
            return Outcome::Failed(Fault::NotNetworked);
        };
        if self.channels.contains_key(&parsed.channel_id) {
            return Outcome::Failed(Fault::IdentityExists);
        }
        let now = self.now();
        // First, a board: the link's anchors in its order, pinned to the identity the
        // link names for each. An anchor that does not answer is skipped.
        let me = net.local_id();
        let mut board: Option<Arc<VoxConnection>> = None;
        for anchor in parsed.anchors.iter().filter(|a| a.id != me) {
            if let Ok(conn) = self.dial(anchor.id, &anchor.endpoints).await {
                self.anchor_ids.insert(anchor.id);
                board = Some(conn);
                break;
            }
        }
        let Some(board) = board else {
            return Outcome::Failed(Fault::Unreachable);
        };
        self.refresh_network_view().await;
        // The board tells us what the channel is and who is in it.
        let set = match net.fetch_channel(&board, &parsed.channel_id, 0).await {
            Ok(s) => s,
            Err(e) => return Outcome::Failed(fault_of(&e)),
        };
        let Some(genesis) = set.genesis.clone() else {
            return Outcome::Failed(Fault::BadLink);
        };
        // The member to join through: the pinned responder, else any member the board
        // has an address record for. Its record's endpoints are dial hints — a wrong
        // one just fails, the identity is pinned — and the ladder does the rest: the
        // anchor we are connected to is exactly the helper a punch or a circuit
        // through needs when the responder is behind a NAT too.
        let responder = match parsed.responder {
            Some(r) => r,
            None => match set.members.first() {
                Some(record) => record.author_id,
                None => return Outcome::Failed(Fault::BadLink),
            },
        };
        let responder_endpoints = set
            .members
            .iter()
            .find(|r| r.author_id == responder)
            .map(|r| r.endpoints.clone())
            .unwrap_or_default();
        // Announce ourselves — **before** reaching for the responder. The pre-join
        // record is what makes an unknown peer eligible (ADR-016): on the anchor it is
        // what lets the anchor coordinate a punch or carry a circuit for us to a
        // responder behind a NAT, and on the responder it is what authorizes the join
        // stream. So it goes on the anchor's board now, and on the responder's own
        // board the moment we reach it.
        let prejoin_wire = {
            let Some(profile) = self.profile.as_ref() else {
                return Outcome::Failed(Fault::NoIdentity);
            };
            let Ok(signer) = profile.signer() else {
                return Outcome::Failed(Fault::Locked);
            };
            let ring = match self.prekeys.as_ref() {
                Some(r) => r,
                None => return Outcome::Failed(Fault::NotNetworked),
            };
            let bundle =
                match ring.bundle(&crate::identity::composite::RootSigner::public_key(signer)) {
                    Ok(b) => b,
                    Err(e) => return Outcome::Failed(fault_of(&e)),
                };
            let endpoints = match net.local_endpoints() {
                Ok(e) => e,
                Err(e) => return Outcome::Failed(fault_of(&e)),
            };
            let seq = {
                let entry = self.record_seq.entry(parsed.channel_id).or_insert(0);
                *entry = entry.saturating_add(1);
                *entry
            };
            match crate::nat::record::PreJoinRecord::build(
                signer,
                &parsed.channel_id,
                bundle,
                endpoints,
                seq,
                now,
            ) {
                Ok(r) => r.to_wire(),
                Err(e) => return Outcome::Failed(fault_of(&e)),
            }
        };
        if let Err(e) = announce(&board, &prejoin_wire).await {
            return Outcome::Failed(fault_of(&e));
        }
        let conn = if board.peer_id() == responder {
            Arc::clone(&board)
        } else {
            let conn = match self.dial(responder, &responder_endpoints).await {
                Ok(c) => c,
                Err(e) => return Outcome::Failed(fault_of(&e)),
            };
            if let Err(e) = announce(&conn, &prejoin_wire).await {
                return Outcome::Failed(fault_of(&e));
            }
            conn
        };
        let outcome = {
            let Some(profile) = self.profile.as_ref() else {
                return Outcome::Failed(Fault::NoIdentity);
            };
            let Ok(signer) = profile.signer() else {
                return Outcome::Failed(Fault::Locked);
            };
            let dh = *signer.x25519_identity_secret();
            let mut ctx = match crate::node::channel::join_context_from_genesis(&genesis, 0) {
                Ok(c) => c,
                Err(e) => return Outcome::Failed(fault_of(&e)),
            };
            if let Some(pow) = self.pow_params {
                ctx.pow_params = pow;
            }
            let ik = crate::identity::keyagreement::X25519IdentityKey::from_secret_bytes(dh);
            match net.start_join(&conn, ctx, passphrase, signer, &ik).await {
                Ok(o) => (o, genesis, set),
                Err(e) => return Outcome::Failed(fault_of(&e)),
            }
        };
        let (joined, genesis, set) = outcome;

        // Local state for the channel we just joined.
        let channel = {
            let Some(profile) = self.profile.as_ref() else {
                return Outcome::Failed(Fault::NoIdentity);
            };
            match ChannelState::join_channel_with_profile(
                profile,
                &genesis,
                &parsed.channel_id,
                local_name,
                passphrase,
                now,
                self.argon2,
            ) {
                Ok(c) => c,
                Err(e) => return Outcome::Failed(fault_of(&e)),
            }
        };
        self.channels.insert(
            parsed.channel_id,
            Arc::new(tokio::sync::Mutex::new(channel)),
        );
        // Every member whose bundle is on the board is an admitted author: the record
        // carries its full composite key and is verified against it (ADR-016). Sync
        // hard-fails on an entry from an author we never admitted, so this is what
        // makes the log reconcilable at all.
        if let (Some(profile), Some(shared)) = (
            self.profile.as_ref(),
            self.channels.get(&parsed.channel_id).map(Arc::clone),
        ) {
            let mut channel = shared.lock().await;
            for record in &set.bundles {
                if let Ok(key) = crate::identity::composite::CompositePublicKey::from_bytes(
                    &record.prekey_bundle.root_pub,
                ) {
                    if record.verify(&key).is_ok() {
                        let _ = channel.admit_author(profile.store(), &key, now);
                    }
                }
            }
        }
        self.sessions
            .insert((parsed.channel_id, responder), joined.session);
        // The link's anchors are this channel's anchors from now on (persisted, so a
        // restart still knows where the swarm's board is), together with our own.
        let mut learned = BootstrapSet::new();
        for a in parsed.anchors.iter().filter(|a| a.id != me) {
            let _ = learned.add(a.clone());
        }
        let _ = learned.merge(&self.anchors);
        self.adopt_channel_anchors(&parsed.channel_id, Some(&learned))
            .await;
        self.refresh_network_view().await;
        self.publish_channel_locally(&parsed.channel_id).await;
        // And on every anchor we hold, so every other member can find our key and
        // admit us as a log author (without which their sync sessions fail).
        self.publish_channel_to_anchors(&parsed.channel_id).await;
        if !self.anchor_ids.contains(&conn.peer_id()) {
            self.publish_channel_to_anchor(&parsed.channel_id, &conn)
                .await;
        }
        // ADR-007 step 2: the newcomer announces its **own** sender key. This is part
        // of joining rather than a separate consent decision — "it has nothing to
        // consent over" — and it must happen here for a second reason: the ADR-004
        // responder has no sending chain until it receives the initiator's first
        // message, so until the joiner speaks no member can answer at all. Step 3
        // (members consenting to the newcomer) stays human-initiated, via `Consent`.
        let released = self.release_key_to(&parsed.channel_id, responder).await;
        if !released.is_done() {
            return released;
        }
        let _ = self
            .event_tx
            .send(NodeEvent::Joined {
                channel_id: parsed.channel_id,
                responder,
            })
            .await;
        Outcome::Done
    }

    /// Release this identity's sender key to `target` and record the grant: deliver
    /// the SKDM over the pairwise session, then append the ADR-007 consent grant
    /// carrying its `skdm_ref`.
    ///
    /// Both halves matter. The key alone lets the target *decrypt*; the grant on the
    /// log is what makes a message *render*, because a reader requires both (ADR-007).
    /// Doing one without the other leaves a peer holding a key it must not use, or a
    /// grant it cannot act on.
    async fn release_key_to(&mut self, channel_id: &Digest32, target: Digest32) -> Outcome {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return Outcome::Failed(Fault::NotNetworked);
        };
        let now = self.now();
        let skdm = {
            let (Some(profile), Some(shared)) = (
                self.profile.as_ref(),
                self.channels.get(channel_id).map(Arc::clone),
            ) else {
                return Outcome::Failed(Fault::UnknownChannel);
            };
            let channel = shared.lock().await;
            if !channel.is_author(&target) {
                // We have not admitted this identity, so we hold no verified key for
                // it and cannot know we are releasing to the right party.
                return Outcome::Failed(Fault::UnknownChannel);
            }
            match channel.skdm_for_consent(profile) {
                Ok(s) => s,
                Err(e) => return Outcome::Failed(fault_of(&e)),
            }
        };
        // A session must already exist with this member (from the join, or from their
        // delivery to us); opening one from their bundle record is M15's "sessions to
        // members we have not met".
        let Some(conn) = net.manager().existing(&target) else {
            return Outcome::Failed(Fault::Unreachable);
        };
        let Some(session) = self.sessions.get_mut(&(*channel_id, target)) else {
            return Outcome::Failed(Fault::Unreachable);
        };
        if let Err(e) =
            crate::node::pairwise_stream::deliver_skdm(&conn, channel_id, session, &skdm).await
        {
            return Outcome::Failed(fault_of(&e));
        }
        let (Some(profile), Some(shared)) = (
            self.profile.as_ref(),
            self.channels.get(channel_id).map(Arc::clone),
        ) else {
            return Outcome::Failed(Fault::UnknownChannel);
        };
        if let Err(e) = shared
            .lock()
            .await
            .issue_consent(profile, target, &skdm, now)
        {
            return Outcome::Failed(fault_of(&e));
        }
        Outcome::Done
    }

    /// Consent to `target` reading this identity's messages — ADR-007 step 3, the
    /// human decision, taken per sender.
    async fn consent(&mut self, channel_id: &Digest32, target: Digest32) -> Outcome {
        let outcome = self.release_key_to(channel_id, target).await;
        if outcome.is_done() {
            let _ = self
                .event_tx
                .send(NodeEvent::Consented {
                    channel_id: *channel_id,
                    target,
                })
                .await;
        }
        outcome
    }

    /// Mark a channel as having a local append to push, and make every peer's
    /// schedule due (ADR-016: "a push immediately after a local append").
    fn note_local_append(&mut self, channel_id: &Digest32) {
        if self.net.is_none() {
            return;
        }
        self.pending_push.insert(*channel_id);
        for schedule in self.schedules.values_mut() {
            schedule.note_local_append();
        }
    }

    /// Run whatever the ADR-016 sync schedule says is due. Returns whether anything
    /// ran, so the caller only republishes the view when it might have changed.
    ///
    /// A peer with no live connection is skipped, not retried in place: it gets a
    /// fresh schedule when it reconnects.
    /// Re-run the ladder's publish side when the granted mappings are halfway through
    /// their lifetime, so a node that outlives a two-hour mapping stays dialable.
    ///
    /// Nothing happens while the network is down: the renewal instant is left in place
    /// so the next unlock's discovery supersedes it.
    ///
    /// The re-request runs on its own task (it talks to a gateway) and lands back as
    /// [`NetEvent::AddressesDiscovered`], which republishes the address records too —
    /// a renewal that came back with a *different* external port must be advertised.
    fn renew_mappings_if_due(&mut self) {
        let Some(due) = self.renew_mappings_at else {
            return;
        };
        if self.now() < due {
            return;
        }
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        // Cleared now, not when the refresh returns: one renewal in flight at a time.
        self.renew_mappings_at = None;
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let mappings = net.refresh_advertised().await;
            let _ = tx.send(NetEvent::AddressesDiscovered { mappings }).await;
        });
    }

    async fn run_due_syncs(&mut self) -> bool {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return false;
        };
        let now = self.now();
        let due: Vec<(Digest32, SyncTrigger)> = self
            .schedules
            .iter()
            .filter_map(|(peer, s)| s.due(now).map(|t| (*peer, t)))
            .collect();
        if due.is_empty() {
            return false;
        }
        let mut ran = false;
        for (peer, trigger) in due {
            if net.manager().existing(&peer).is_none() {
                continue;
            }
            // Which channels this pass covers: a local-append push touches only the
            // channels that changed; a connect or interval pass covers every channel
            // shared with this peer.
            let mut channels: Vec<Digest32> = Vec::new();
            for (cid, shared) in &self.channels {
                if trigger == SyncTrigger::LocalAppend && !self.pending_push.contains(cid) {
                    continue;
                }
                if shared.lock().await.is_author(&peer) {
                    channels.push(*cid);
                }
            }
            for channel_id in channels {
                if self.sync_one(&channel_id, peer).await {
                    ran = true;
                }
            }
            if let Some(schedule) = self.schedules.get_mut(&peer) {
                schedule.note_synced(now);
            }
        }
        self.pending_push.clear();
        ran
    }

    /// Admit every member whose prekey bundle is on `peer`'s board for this channel.
    ///
    /// This is not optional politeness: an ADR-008 session **hard-fails** on the first
    /// entry from an author this node has not admitted, because it cannot verify it. A
    /// member that joined after us is exactly such an author, and its full composite
    /// key is on the board (ADR-016) — so learning the current membership from the
    /// board is a precondition for reconciling at all, and doing it here means a node
    /// never has to be told out of band that someone new arrived.
    async fn learn_members(&mut self, channel_id: &Digest32, peer: Digest32) -> usize {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return 0;
        };
        let Some(conn) = net.manager().existing(&peer) else {
            return 0;
        };
        let epoch = match self.channels.get(channel_id) {
            Some(shared) => shared.lock().await.epoch(),
            None => return 0,
        };
        let Ok(set) = net.fetch_channel(&conn, channel_id, epoch).await else {
            return 0;
        };
        let now = self.now();
        let mut learned = 0usize;
        if let (Some(profile), Some(shared)) = (
            self.profile.as_ref(),
            self.channels.get(channel_id).map(Arc::clone),
        ) {
            let mut channel = shared.lock().await;
            for record in &set.bundles {
                let Ok(key) = crate::identity::composite::CompositePublicKey::from_bytes(
                    &record.prekey_bundle.root_pub,
                ) else {
                    continue;
                };
                // The board is availability only: the record must verify under the key
                // it carries before that key becomes an author.
                if record.verify(&key).is_ok()
                    && matches!(channel.admit_author(profile.store(), &key, now), Ok(true))
                {
                    learned += 1;
                }
            }
        }
        if learned > 0 {
            self.refresh_network_view().await;
        }
        learned
    }

    /// Start reconciling one channel with one peer: learn who else has joined, then
    /// hand the channel to a detached session task.
    ///
    /// Returns whether a session was *started*. It is deliberately not awaited — see
    /// [`NetEvent::SyncDone`] for why awaiting deadlocks two nodes that start at the
    /// same moment. While the channel is away it is invisible to commands (they answer
    /// `UnknownChannel`) and, usefully, to this function, so a second pass cannot start
    /// a concurrent session for the same channel.
    async fn sync_one(&mut self, channel_id: &Digest32, peer: Digest32) -> bool {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return false;
        };
        if net.manager().existing(&peer).is_none() {
            return false;
        }
        // Learn who else has joined before reconciling, or the first entry from a
        // newer member kills the session (ADR-008 Implementation notes).
        self.learn_members(channel_id, peer).await;
        let epoch = match self.channels.get(channel_id) {
            Some(shared) => shared.lock().await.epoch(),
            None => return false,
        };
        let Some(conn) = net.manager().existing(&peer) else {
            return false;
        };
        let handle = tokio::runtime::Handle::current();
        let transport =
            match crate::node::syncstream::open_sync(&conn, handle, channel_id, epoch).await {
                Ok(t) => t,
                Err(_) => return false,
            };
        self.start_session(*channel_id, transport);
        true
    }

    /// Take the channel out of the actor's map and run a session on its own task,
    /// returning it through [`NetEvent::SyncDone`].
    fn start_session(
        &mut self,
        channel_id: Digest32,
        transport: crate::transport::quic::QuicStreamTransport,
    ) {
        let Some(store) = self.profile.as_ref().map(Profile::store_handle) else {
            return;
        };
        let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
            return;
        };
        let now = self.now();
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let joined = tokio::task::spawn_blocking(move || {
                // `blocking_lock` is the sanctioned way to take a tokio mutex off a
                // blocking thread. Anything else wanting this channel waits for the
                // session — a few milliseconds — instead of finding it missing.
                let mut channel = shared.blocking_lock();
                let mut t = transport;
                channel.sync_over(&store, &mut t, now)
            })
            .await;
            if let Ok(outcome) = joined {
                let _ = tx
                    .send(NetEvent::SyncDone {
                        channel_id,
                        outcome,
                    })
                    .await;
            }
        });
    }

    /// Reconcile a channel with every member this node can reach, now (the `Sync`
    /// command; the schedule does this automatically — ADR-016 §"Sync scheduling").
    async fn sync_channel(&mut self, channel_id: &Digest32) -> Outcome {
        if self.net.is_none() {
            return Outcome::Failed(Fault::NotNetworked);
        }
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::UnknownChannel);
        };
        let peers: Vec<Digest32> = {
            let channel = shared.lock().await;
            let me = channel.me();
            channel.members().into_iter().filter(|m| *m != me).collect()
        };
        let mut synced = 0usize;
        for peer in peers {
            if self.sync_one(channel_id, peer).await {
                synced += 1;
            }
        }
        if synced == 0 {
            return Outcome::Failed(Fault::Unreachable);
        }
        Outcome::Done
    }

    /// Reconcile one channel's log with a peer over an inbound `sync` stream (ADR-008
    /// frontier mode), on its own task for the reason [`NetEvent::SyncDone`] gives.
    async fn run_sync_session(&mut self, send: quinn::SendStream, mut recv: quinn::RecvStream) {
        use crate::node::syncstream::{accept_sync, read_sync_request};
        let Ok((channel_id, epoch)) = read_sync_request(&mut recv).await else {
            return;
        };
        // Only a channel we hold open at that epoch can be reconciled.
        let matches_epoch = match self.channels.get(&channel_id) {
            Some(shared) => shared.lock().await.epoch() == epoch,
            None => false,
        };
        if !matches_epoch {
            return;
        }
        let transport = accept_sync(tokio::runtime::Handle::current(), send, recv);
        self.start_session(channel_id, transport);
    }

    /// Take an inbound sealed control message: an ADR-006 SKDM, which makes that
    /// author's messages readable and backfills any already held as ciphertext.
    async fn take_inbound_skdm(&mut self, peer: Digest32, mut recv: quinn::RecvStream) {
        use crate::node::pairwise_stream::{open_skdm, recv_pairwise};
        let Ok(Some((channel_id, sealed))) = recv_pairwise(&mut recv).await else {
            return;
        };
        let now = self.now();
        let Some(session) = self.sessions.get_mut(&(channel_id, peer)) else {
            // No session with this peer for that channel: nothing can open it. The
            // sender retries once a join or key exchange establishes one.
            return;
        };
        let Ok(skdm) = open_skdm(session, &sealed, now) else {
            return;
        };
        let backfilled = match (
            self.profile.as_ref(),
            self.channels.get(&channel_id).map(Arc::clone),
        ) {
            (Some(profile), Some(shared)) => shared
                .lock()
                .await
                .accept_skdm(profile.store(), &skdm, now)
                .ok(),
            _ => None,
        };
        if let Some(n) = backfilled {
            let _ = self
                .event_tx
                .send(NodeEvent::SenderKeyReceived {
                    channel_id,
                    peer,
                    backfilled: n as u64,
                })
                .await;
        }
    }

    /// Load (or, on first use, generate) the prekey ring for the unlocked
    /// identity, rotating the signed prekey and refilling the one-time pool if due
    /// (ADR-002 §2 cadence, applied on every unlock).
    fn load_prekeys(&mut self, now: u64) -> crate::error::Result<()> {
        let profile = self
            .profile
            .as_ref()
            .ok_or(crate::error::Error::Profile("no identity in this profile"))?;
        let signer = profile.signer()?;
        // The ring's identity DH key is the identity's own (ADR-002), taken from the
        // unlocked vault — never a fresh one, or a restore would change it.
        let dh_secret = *signer.x25519_identity_secret();
        let (ring, _created) = prekeys::load_or_create(profile.store(), signer, &dh_secret, now)?;
        self.prekeys = Some(ring);
        Ok(())
    }

    async fn lock_all(&mut self) {
        let was_unlocked = self.profile.as_ref().is_some_and(Profile::is_unlocked);
        for (_, shared) in std::mem::take(&mut self.channels) {
            shared.lock().await.lock_now();
        }
        // Drop the prekey ring: its secrets zeroize on drop, so a locked node holds
        // no key-agreement material (ADR-015 lock/zeroize).
        self.prekeys = None;
        // Pairwise sessions hold ratchet key material: drop them with everything else
        // (their secrets zeroize on drop).
        self.sessions.clear();
        // And take the network down: a locked node has no identity to present, so it
        // must not keep serving or holding connections (M14.7d).
        self.stop_network();
        if let Some(p) = self.profile.as_mut() {
            p.lock();
        }
        if was_unlocked {
            let _ = self.event_tx.send(NodeEvent::Locked).await;
        }
    }

    async fn create_channel(&mut self, local_name: &str, passphrase: &Secret) -> Outcome {
        let now = self.now();
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        match ChannelState::create_with_profile(profile, local_name, passphrase, now, self.argon2) {
            Ok(ch) => {
                let id = ch.channel_id();
                self.channels
                    .insert(id, Arc::new(tokio::sync::Mutex::new(ch)));
                self.adopt_channel_anchors(&id, None).await;
                self.refresh_network_view().await;
                self.publish_channel_locally(&id).await;
                self.publish_channel_to_anchors(&id).await;
                let _ = self
                    .event_tx
                    .send(NodeEvent::ChannelOpened { channel_id: id })
                    .await;
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    async fn open_channel(&mut self, channel_id: &Digest32, passphrase: &Secret) -> Outcome {
        if self.channels.contains_key(channel_id) {
            return Outcome::Done;
        }
        let now = self.now();
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        match ChannelState::open(profile, channel_id, passphrase, now) {
            Ok(ch) => {
                self.channels
                    .insert(*channel_id, Arc::new(tokio::sync::Mutex::new(ch)));
                self.adopt_channel_anchors(channel_id, None).await;
                self.refresh_network_view().await;
                self.publish_channel_locally(channel_id).await;
                self.publish_channel_to_anchors(channel_id).await;
                let _ = self
                    .event_tx
                    .send(NodeEvent::ChannelOpened {
                        channel_id: *channel_id,
                    })
                    .await;
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    async fn close_channel(&mut self, channel_id: &Digest32) -> Outcome {
        match self.channels.remove(channel_id) {
            Some(shared) => {
                shared.lock().await.lock_now();
                // The channel is gone from the view the board reads, so its members
                // are no longer classified from it and its records stop being served
                // on our behalf.
                if let Some(net) = self.net.as_ref() {
                    net.membership().clear_channel(channel_id);
                }
                self.refresh_network_view().await;
                let _ = self
                    .event_tx
                    .send(NodeEvent::ChannelClosed {
                        channel_id: *channel_id,
                    })
                    .await;
                Outcome::Done
            }
            None => Outcome::Failed(Fault::ChannelNotOpen),
        }
    }

    async fn send_text(&mut self, channel_id: &Digest32, text: &str) -> Outcome {
        let now = self.now();
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        let mut ch = shared.lock().await;
        match ch.append_text(profile, text, now) {
            Ok(r) => {
                let row = row_of(r);
                let channel_id = *channel_id;
                let _ = self
                    .event_tx
                    .send(NodeEvent::NewEntry { channel_id, row })
                    .await;
                // ADR-016: push immediately after a local append. Marking it here and
                // letting the tick do the work keeps authoring off the network path.
                self.note_local_append(&channel_id);
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    /// Publish the current view (latest wins).
    /// The view at spawn time, built without locks: nothing is open yet, so every
    /// channel the store knows is listed closed.
    fn publish_initial(&self) {
        let identity = self.profile.as_ref().map(|p| IdentityInfo {
            fingerprint: p.fingerprint(),
            created: p.created(),
        });
        let locked = !self.profile.as_ref().is_some_and(Profile::is_unlocked);
        let channels = self
            .profile
            .as_ref()
            .and_then(|p| p.store().channels().ok())
            .unwrap_or_default()
            .into_iter()
            .map(|channel_id| ChannelSummary {
                channel_id,
                local_name: None,
                open: false,
                entries: 0,
            })
            .collect();
        self.view_tx.send_replace(NodeView {
            identity,
            locked,
            mlock_active: true,
            listening: Vec::new(),
            channels,
            open_channels: Vec::new(),
        });
    }

    async fn publish(&self) {
        let view = self.view_of().await;
        self.view_tx.send_replace(view);
    }

    async fn view_of(&self) -> NodeView {
        let identity = self.profile.as_ref().map(|p| IdentityInfo {
            fingerprint: p.fingerprint(),
            created: p.created(),
        });
        let locked = !self.profile.as_ref().is_some_and(Profile::is_unlocked);
        let listening = self
            .net
            .as_ref()
            .and_then(|n| n.local_endpoints().ok())
            .map(|eps| eps.addrs().iter().map(ToString::to_string).collect())
            .unwrap_or_default();
        let known: Vec<Digest32> = self
            .profile
            .as_ref()
            .and_then(|p| p.store().channels().ok())
            .unwrap_or_default();
        let mut channels = Vec::with_capacity(known.len());
        for id in &known {
            channels.push(match self.channels.get(id) {
                Some(shared) => {
                    let ch = shared.lock().await;
                    ChannelSummary {
                        channel_id: *id,
                        local_name: Some(ch.local_name().to_owned()),
                        open: true,
                        entries: ch.entry_count() as u64,
                    }
                }
                None => ChannelSummary {
                    channel_id: *id,
                    local_name: None,
                    open: false,
                    entries: 0,
                },
            });
        }
        let mut open_channels = Vec::with_capacity(self.channels.len());
        let mut mlock_active = true;
        for shared in self.channels.values() {
            let ch = shared.lock().await;
            mlock_active &= ch.mlock_active();
            open_channels.push(ChannelDetail {
                channel_id: ch.channel_id(),
                local_name: ch.local_name().to_owned(),
                epoch: ch.epoch(),
                members: ch.members(),
                timeline: ch.timeline().iter().map(row_of).collect(),
            });
        }
        NodeView {
            identity,
            locked,
            mlock_active,
            listening,
            channels,
            open_channels,
        }
    }
}

fn row_of(r: &Rendered) -> MessageRow {
    MessageRow {
        entry_hash: r.entry_hash,
        author: r.author,
        created_secs: r.created_secs,
        text: r.text.clone(),
    }
}

/// Map a library error to the closed, redaction-safe [`Fault`] set.
fn fault_of(e: &Error) -> Fault {
    match e {
        Error::Profile("no identity in this profile") => Fault::NoIdentity,
        Error::Profile("identity already exists in this profile") => Fault::IdentityExists,
        Error::Profile("locked") => Fault::Locked,
        Error::Profile("no such channel in this profile") => Fault::UnknownChannel,
        Error::AtRestUnlockFailed => Fault::WrongPassphrase,
        Error::AtRestLocked => Fault::Locked,
        Error::SizeLimitExceeded(_) => Fault::TooLong,
        Error::MalformedLink(_) => Fault::BadLink,
        Error::Unreachable(_) => Fault::Unreachable,
        Error::JoinRefused(_) | Error::RendezvousRejected(_) => Fault::Refused,
        Error::Storage { .. } | Error::Path { .. } => Fault::Storage,
        // A join refused before the challenge (the responder does not hold that
        // channel open) reaches the joiner as a malformed exchange; report it as the
        // refusal it is rather than an internal fault.
        Error::MalformedJoin(_) => Fault::Refused,
        _ => Fault::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> Secret {
        Secret::new(s.as_bytes().to_vec())
    }

    fn mapping(lifetime_secs: u32) -> crate::nat::portmap::PortMapping {
        crate::nat::portmap::PortMapping {
            internal_port: 4433,
            external_port: 4433,
            external_ip: None,
            lifetime_secs,
            method: crate::nat::portmap::Method::Pcp,
        }
    }

    #[test]
    fn mappings_are_renewed_at_half_the_shortest_granted_lifetime() {
        // Nothing granted: nothing to renew (and no tick work forever after).
        assert_eq!(renew_at(1_000, &[]), None);
        // The ADR-012 two-hour lifetime renews after one hour.
        assert_eq!(renew_at(1_000, &[mapping(7200)]), Some(1_000 + 3600));
        // The shortest governs: a gateway may grant less than was asked.
        assert_eq!(
            renew_at(1_000, &[mapping(7200), mapping(600)]),
            Some(1_000 + 300)
        );
        // A tiny grant still moves the clock forward, or the renewal would re-fire on
        // every tick.
        assert_eq!(renew_at(1_000, &[mapping(1)]), Some(1_001));
    }

    fn fixed_clock(t: u64) -> Clock {
        Arc::new(move || t)
    }

    fn paths(tmp: &tempfile::TempDir, name: &str) -> Paths {
        Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap()
    }

    /// A node built directly (not spawned), so a test can observe private state
    /// the handle deliberately never exposes — here: that no prekey secret is
    /// retained behind a lock.
    fn unspawned(paths: Paths, t: u64) -> Node {
        let (event_tx, _event_rx) = mpsc::channel(EVENT_QUEUE);
        let (net_tx, _net_rx) = mpsc::channel(NET_QUEUE);
        Node {
            paths,
            profile: None,
            net: None,
            net_tx,
            // No bind address: this node does not network (the loopback paths are
            // covered by `node::network` and the M14 gate).
            bind: None,
            anchors: BootstrapSet::new(),
            anchor_ids: std::collections::BTreeSet::new(),
            pow_params: None,
            stream_loops: std::collections::BTreeSet::new(),
            port_mappings: Vec::new(),
            renew_mappings_at: None,
            schedules: BTreeMap::new(),
            pending_push: std::collections::BTreeSet::new(),
            record_seq: BTreeMap::new(),
            sessions: BTreeMap::new(),
            prekeys: None,
            channels: BTreeMap::new(),
            clock: fixed_clock(t),
            argon2: Argon2Profile::REDUCED,
            view_tx: watch::Sender::new(NodeView::default()),
            event_tx,
        }
    }

    /// A networked node binds as its identity when it unlocks, serves its board with
    /// its channels on it, answers a real inbound join, and tears the endpoint down
    /// when it locks.
    #[test]
    fn a_networked_node_serves_its_board_and_answers_an_inbound_join() {
        use crate::identity::composite::{RootSigner as _, SoftwareRootSigner};
        use crate::node::channel::join_context_from_genesis;
        use crate::node::network::NodeNet;
        use crate::transport::quic::VoxEndpoint;
        use std::sync::Arc as StdArc;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let t = 1_700_000_000;
        rt.block_on(async {
            let reduced_pow = crate::join::pow::PowParams::new(48, 5).unwrap();
            let h = Node::spawn_configured(
                paths(&tmp, "alice"),
                fixed_clock(t),
                Argon2Profile::REDUCED,
                Some("127.0.0.1:0".parse().unwrap()),
                Some(reduced_pow),
            )
            .unwrap();

            // Not networked until an identity exists to bind as.
            assert!(h.view().listening.is_empty());
            assert!(h
                .apply(NodeCommand::CreateIdentity {
                    passphrase: secret("id-pp")
                })
                .await
                .is_done());
            let listening = h.view().listening;
            assert_eq!(listening.len(), 1, "bound on unlock: {listening:?}");
            assert!(listening[0].starts_with("/ip4/127.0.0.1/udp/"));

            // A channel: its genesis and this node's records go on its own board.
            assert!(h
                .apply(NodeCommand::CreateChannel {
                    local_name: "team".into(),
                    passphrase: secret("ch-pp")
                })
                .await
                .is_done());
            let cid = h.view().channels[0].channel_id;
            let alice_fp = h.view().identity.unwrap().fingerprint;

            // --- a peer joins for real, through the board ---
            let bob_s = SoftwareRootSigner::from_component_seeds(&[41; 32], &[42; 32]).unwrap();
            let bob_net = {
                let ep =
                    StdArc::new(VoxEndpoint::bind(&bob_s, "127.0.0.1:0".parse().unwrap()).unwrap());
                NodeNet::new(ep, fixed_clock(t))
            };
            let anchors = crate::nat::multiaddr::EndpointList::new(vec![
                crate::nat::multiaddr::Multiaddr::parse(&listening[0]).unwrap(),
            ])
            .unwrap();
            let conn = bob_net.manager().connect(alice_fp, &anchors).await.unwrap();

            // The board hands over the genesis and Alice's bundle.
            let set = bob_net.fetch_channel(&conn, &cid, 0).await.unwrap();
            let genesis = set.genesis.expect("the node published its genesis");
            assert_eq!(genesis.channel_id(), cid);
            assert_eq!(set.bundles.len(), 1, "the node published its bundle");
            assert_eq!(set.members.len(), 1, "and its address record");

            // Bob announces himself with a pre-join record — that, not a list someone
            // maintains, is what makes him eligible to open a join stream (ADR-016).
            let bob_ring_store =
                crate::node::store::Store::open(&tmp.path().join("bob-ring.redb")).unwrap();
            let (bob_ring, _) =
                prekeys::load_or_create(&bob_ring_store, &bob_s, &[0x77; 32], t).unwrap();
            let prejoin = crate::nat::record::PreJoinRecord::build(
                &bob_s,
                &cid,
                bob_ring.bundle(&bob_s.public_key()).unwrap(),
                bob_net.local_endpoints().unwrap(),
                1,
                t,
            )
            .unwrap();
            {
                let mut client = crate::nat::service::RendezvousClient::open(&conn)
                    .await
                    .unwrap();
                client.put(&prejoin.to_wire()).await.unwrap();
                client.finish();
            }

            // Now the join itself, with the passphrase out of band.
            let mut ctx = join_context_from_genesis(&genesis, 0).unwrap();
            ctx.pow_params = reduced_pow;
            let ik =
                crate::identity::keyagreement::X25519IdentityKey::from_secret_bytes([0x77; 32]);
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                bob_net.start_join(&conn, ctx, b"ch-pp", &bob_s, &ik),
            )
            .await
            .unwrap()
            .expect("the node answered the join");
            assert_eq!(outcome.peer.fingerprint, alice_fp);

            // The node admitted him as a log author — and he can read nothing.
            let joined = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if let Some(NodeEvent::PeerJoined { channel_id, peer }) = h.next_event().await {
                        return (channel_id, peer);
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(joined, (cid, bob_s.fingerprint()));

            // Locking tears the network down: no identity to present, nothing served.
            assert!(h.apply(NodeCommand::Lock).await.is_done());
            assert!(h.view().listening.is_empty());
            assert!(h.apply(NodeCommand::Shutdown).await.is_done());
            bob_net.manager().close_all();
        });
    }

    #[tokio::test]
    async fn the_prekey_ring_is_loaded_on_unlock_and_dropped_on_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let t = 1_700_000_000;
        let mut node = unspawned(paths(&tmp, "alice"), t);

        // A created identity gets a usable, root-signed ring straight away.
        assert_eq!(node.create_identity(&secret("id-pp")), Outcome::Done);
        let root = crate::identity::composite::RootSigner::public_key(
            node.profile.as_ref().unwrap().signer().unwrap(),
        );
        let ring = node.prekeys.as_ref().expect("ring after create");
        let first_spk = ring.signed_prekey_id();
        let bundle = ring.bundle(&root).unwrap();
        bundle.verify().unwrap();
        assert_eq!(bundle.root_pub, root.to_bytes());
        assert!(bundle.one_time_prekey.is_some());

        // Lock: the ring is dropped (its secrets zeroize on drop), like the
        // identity signer and every channel SEK.
        node.lock_all().await;
        assert!(node.prekeys.is_none(), "no prekey secrets behind a lock");
        assert!(!node.profile.as_ref().unwrap().is_unlocked());

        // A wrong passphrase leaves it locked and ringless.
        assert_eq!(
            node.unlock(&secret("wrong")).await,
            Outcome::Failed(Fault::WrongPassphrase)
        );
        assert!(node.prekeys.is_none());

        // The right passphrase reloads the *same* ring — not a fresh one, which
        // would invalidate every bundle already published.
        assert_eq!(node.unlock(&secret("id-pp")).await, Outcome::Done);
        let ring = node.prekeys.as_ref().expect("ring after unlock");
        assert_eq!(ring.signed_prekey_id(), first_spk);
        assert_eq!(ring.bundle(&root).unwrap(), bundle);
    }

    #[tokio::test]
    async fn full_single_device_lifecycle_through_the_handle() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp, "alice");
        let h = Node::spawn_with(
            p.clone(),
            fixed_clock(1_700_000_000),
            Argon2Profile::REDUCED,
        )
        .unwrap();

        // Fresh profile: no identity, locked.
        let v = h.view();
        assert!(v.identity.is_none());
        assert!(v.locked);
        assert!(v.channels.is_empty());
        assert!(
            h.apply(NodeCommand::Unlock {
                passphrase: secret("x")
            })
            .await
                == Outcome::Failed(Fault::NoIdentity)
        );

        // Create identity → unlocked, identity visible.
        assert!(h
            .apply(NodeCommand::CreateIdentity {
                passphrase: secret("id-pp")
            })
            .await
            .is_done());
        assert!(matches!(
            h.apply(NodeCommand::CreateIdentity {
                passphrase: secret("id-pp")
            })
            .await,
            Outcome::Failed(Fault::IdentityExists)
        ));
        let v = h.view();
        let fp = v.identity.as_ref().unwrap().fingerprint;
        assert!(!v.locked);

        // Create a channel, send two messages, observe events and the view.
        assert!(h
            .apply(NodeCommand::CreateChannel {
                local_name: "family".into(),
                passphrase: secret("ch-pp")
            })
            .await
            .is_done());
        let v = h.view();
        assert_eq!(v.channels.len(), 1);
        let cid = v.channels[0].channel_id;
        assert_eq!(v.channels[0].local_name.as_deref(), Some("family"));
        assert!(v.channels[0].open);
        assert!(
            matches!(h.next_event().await, Some(NodeEvent::ChannelOpened { channel_id }) if channel_id == cid)
        );

        assert!(h
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "hello".into()
            })
            .await
            .is_done());
        assert!(h
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "world".into()
            })
            .await
            .is_done());
        match h.next_event().await {
            Some(NodeEvent::NewEntry { channel_id, row }) => {
                assert_eq!(channel_id, cid);
                assert_eq!(row.text, "hello");
                assert_eq!(row.author, fp);
                assert_eq!(row.created_secs, 1_700_000_000);
            }
            other => panic!("expected NewEntry, got {other:?}"),
        }
        assert!(matches!(
            h.next_event().await,
            Some(NodeEvent::NewEntry { .. })
        ));
        let v = h.view();
        assert_eq!(v.channels[0].entries, 2);
        let detail = &v.open_channels[0];
        assert_eq!(detail.local_name, "family");
        assert_eq!(detail.members, vec![fp]);
        assert_eq!(
            detail
                .timeline
                .iter()
                .map(|r| r.text.as_str())
                .collect::<Vec<_>>(),
            vec!["hello", "world"]
        );

        // Lock: channels close, identity locks, sends fail with Locked/ChannelNotOpen.
        assert!(h.apply(NodeCommand::Lock).await.is_done());
        assert!(matches!(h.next_event().await, Some(NodeEvent::Locked)));
        let v = h.view();
        assert!(v.locked);
        assert!(v.open_channels.is_empty());
        assert_eq!(v.channels.len(), 1);
        assert!(!v.channels[0].open);
        assert!(
            v.channels[0].local_name.is_none(),
            "name is under the channel lock"
        );
        assert!(matches!(
            h.apply(NodeCommand::SendText {
                channel_id: cid,
                text: "x".into()
            })
            .await,
            Outcome::Failed(Fault::ChannelNotOpen)
        ));
        assert!(matches!(
            h.apply(NodeCommand::OpenChannel {
                channel_id: cid,
                passphrase: secret("ch-pp")
            })
            .await,
            Outcome::Failed(Fault::Locked)
        ));

        // Unlock (wrong, then right), reopen the channel: timeline restored.
        assert!(matches!(
            h.apply(NodeCommand::Unlock {
                passphrase: secret("nope")
            })
            .await,
            Outcome::Failed(Fault::WrongPassphrase)
        ));
        assert!(h
            .apply(NodeCommand::Unlock {
                passphrase: secret("id-pp")
            })
            .await
            .is_done());
        assert!(matches!(h.next_event().await, Some(NodeEvent::Unlocked)));
        assert!(matches!(
            h.apply(NodeCommand::OpenChannel {
                channel_id: cid,
                passphrase: secret("wrong")
            })
            .await,
            Outcome::Failed(Fault::WrongPassphrase)
        ));
        assert!(h
            .apply(NodeCommand::OpenChannel {
                channel_id: cid,
                passphrase: secret("ch-pp")
            })
            .await
            .is_done());
        let v = h.view();
        assert_eq!(v.open_channels[0].timeline.len(), 2);
        assert!(matches!(
            h.apply(NodeCommand::OpenChannel {
                channel_id: [9u8; 32],
                passphrase: secret("ch-pp")
            })
            .await,
            Outcome::Failed(Fault::UnknownChannel)
        ));
        assert!(h
            .apply(NodeCommand::CloseChannel { channel_id: cid })
            .await
            .is_done());
        assert!(matches!(
            h.apply(NodeCommand::CloseChannel { channel_id: cid }).await,
            Outcome::Failed(Fault::ChannelNotOpen)
        ));

        // Shutdown: replies Done, then the actor stops and later commands fail.
        assert!(h.apply(NodeCommand::Shutdown).await.is_done());
        // Drain to the Shutdown event.
        let mut saw_shutdown = false;
        while let Some(ev) = h.next_event().await {
            if ev == NodeEvent::Shutdown {
                saw_shutdown = true;
                break;
            }
        }
        assert!(saw_shutdown);
        assert!(matches!(
            h.apply(NodeCommand::Lock).await,
            Outcome::Failed(Fault::ShuttingDown)
        ));
    }

    #[tokio::test]
    async fn restart_reopens_locked_with_channels_listed() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp, "alice");
        let cid;
        {
            let h = Node::spawn_with(p.clone(), fixed_clock(1), Argon2Profile::REDUCED).unwrap();
            assert!(h
                .apply(NodeCommand::CreateIdentity {
                    passphrase: secret("id")
                })
                .await
                .is_done());
            assert!(h
                .apply(NodeCommand::CreateChannel {
                    local_name: "c".into(),
                    passphrase: secret("ch")
                })
                .await
                .is_done());
            cid = h.view().channels[0].channel_id;
            assert!(h
                .apply(NodeCommand::SendText {
                    channel_id: cid,
                    text: "persisted".into()
                })
                .await
                .is_done());
            assert!(h.apply(NodeCommand::Shutdown).await.is_done());
        }
        // A new process: the identity is there, locked; the channel is listed but closed.
        let h = Node::spawn_with(p, fixed_clock(2), Argon2Profile::REDUCED).unwrap();
        let v = h.view();
        assert!(v.identity.is_some());
        assert!(v.locked);
        assert_eq!(v.channels.len(), 1);
        assert_eq!(v.channels[0].channel_id, cid);
        assert!(!v.channels[0].open);
        assert!(h
            .apply(NodeCommand::Unlock {
                passphrase: secret("id")
            })
            .await
            .is_done());
        assert!(h
            .apply(NodeCommand::OpenChannel {
                channel_id: cid,
                passphrase: secret("ch")
            })
            .await
            .is_done());
        let v = h.view();
        assert_eq!(v.open_channels[0].timeline[0].text, "persisted");
        assert_eq!(v.open_channels[0].timeline[0].created_secs, 1);
    }

    #[tokio::test]
    async fn dropping_the_last_handle_locks_and_stops_the_actor() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp, "alice");
        let h = Node::spawn_with(p.clone(), fixed_clock(1), Argon2Profile::REDUCED).unwrap();
        assert!(h
            .apply(NodeCommand::CreateIdentity {
                passphrase: secret("id")
            })
            .await
            .is_done());
        let mut w = h.watch();
        drop(h);
        // The actor observes the closed command channel, locks, publishes, exits.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if w.borrow().locked {
                    break;
                }
                if w.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(w.borrow().locked);
    }
}
