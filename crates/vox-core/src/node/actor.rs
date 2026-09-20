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

use tokio::sync::{mpsc, oneshot, watch, Mutex};

use crate::atrest::sek::Argon2Profile;
use crate::error::Error;
use crate::hash::Digest32;
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
use crate::transport::quic::VoxConnection;

/// Command queue depth (commands beyond it apply backpressure to the client).
const COMMAND_QUEUE: usize = 64;
/// Event queue depth. A client that stops draining events eventually blocks the
/// actor's event emission; the TUI drains continuously (ADR-015).
const EVENT_QUEUE: usize = 256;

/// Bound on the internal network→actor queue. Inbound streams are back-pressured
/// rather than dropped: a full queue slows the accept loop, it never loses work.
const NET_QUEUE: usize = 64;

/// Work the network produced that only the actor can handle, because it needs
/// channel state (ADR-016: the actor stays the single writer).
enum NetEvent {
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
    tokio::spawn(async move {
        loop {
            match net.accept_stream(&conn).await {
                Ok(Inbound::ServedRendezvous { .. }) => {}
                Ok(inbound) => {
                    let event = NetEvent::Stream {
                        conn: Arc::clone(&conn),
                        inbound,
                    };
                    if tx.send(event).await.is_err() {
                        return; // the actor is gone
                    }
                }
                // A refused or failed stream ends this connection's loop; the peer
                // may reconnect.
                Err(_) => return,
            }
        }
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
                Ok(Some(conn)) => spawn_stream_loop(Arc::clone(&net), conn, tx.clone()),
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
    /// The bind address for the endpoint, if this node networks at all.
    bind: Option<std::net::SocketAddr>,
    /// An override for the ADR-005 PoW parameters a join binds. `None` means the
    /// channel's own (production `(200,9)`); tests reduce them so the debug suite
    /// does not grind, exactly as they reduce the Argon2 profile.
    pow_params: Option<crate::join::pow::PowParams>,
    /// Peers whose connection already has a stream loop, so dialing again does not
    /// start a second one.
    stream_loops: std::collections::BTreeSet<Digest32>,
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
    channels: BTreeMap<Digest32, ChannelState>,
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
            pow_params,
            stream_loops: std::collections::BTreeSet::new(),
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
        node.publish();
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
        loop {
            tokio::select! {
                received = cmd_rx.recv() => {
                    let Some((command, reply)) = received else { break };
                    let shutdown = matches!(command, NodeCommand::Shutdown);
                    let outcome = self.handle(command).await;
                    self.publish();
                    // A dropped reply receiver is the caller's choice, not an error.
                    let _ = reply.send(outcome);
                    if shutdown {
                        break;
                    }
                }
                Some(event) = net_rx.recv() => {
                    self.handle_net(event).await;
                    self.publish();
                }
            }
        }
        // Channel closed or shutdown: lock (wipe every SEK + the signer) and stop.
        self.stop_network();
        self.lock_all().await;
        self.publish();
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
        let Some(bind) = self.bind else { return Ok(()) };
        if self.net.is_some() {
            return Ok(());
        }
        let profile = self
            .profile
            .as_ref()
            .ok_or(crate::error::Error::Profile("no identity in this profile"))?;
        let endpoint = Arc::new(crate::transport::quic::VoxEndpoint::bind(
            profile.signer()?,
            bind,
        )?);
        let net = Arc::new(NodeNet::new(endpoint, Arc::clone(&self.clock)));
        self.net = Some(Arc::clone(&net));
        self.refresh_network_view();
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
            Some(c) => (c.genesis().to_wire(), c.epoch()),
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

    /// Put a channel's genesis and this node's records on its own board, so a joiner
    /// can find out what the channel is and how to reach us (ADR-007/ADR-012). A
    /// refusal here is normal, not an error: the board already holds a current record
    /// and the ADR-012 refresh floor declines a faster one.
    fn publish_channel_locally(&mut self, channel_id: &Digest32) {
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
        let Some(channel) = self.channels.get(channel_id) else {
            return;
        };
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
    fn refresh_network_view(&self) {
        let Some(net) = self.net.as_ref() else { return };
        let mut policy = PeerPolicy::new();
        for (cid, ch) in &self.channels {
            let members: BTreeMap<Digest32, crate::identity::composite::CompositePublicKey> = ch
                .author_keys()
                .into_iter()
                .map(|k| (k.fingerprint(), k))
                .collect();
            policy.add_members(members.keys().copied());
            net.membership().set_channel(*cid, ch.epoch(), members);
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
                    Inbound::NotYetSupported { .. } | Inbound::ServedRendezvous { .. } => {}
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
        let answerable = self
            .channels
            .get(&channel_id)
            .is_some_and(|c| c.can_answer_join() && c.epoch() == epoch);
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
            let Some(channel) = self.channels.get(&channel_id) else {
                refuse_join(send).await;
                return;
            };
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
                channel,
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
        let admitted = match (self.profile.as_ref(), self.channels.get_mut(&channel_id)) {
            (Some(profile), Some(channel)) => channel
                .admit_author(profile.store(), &outcome.peer.identity, now)
                .is_ok(),
            _ => false,
        };
        if admitted {
            self.refresh_network_view();
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
        let conn = net.manager().connect(peer, endpoints).await?;
        if self.stream_loops.insert(peer) {
            spawn_stream_loop(net, Arc::clone(&conn), self.net_tx.clone());
        }
        Ok(conn)
    }

    /// Produce an invite link naming this node as anchor and responder.
    async fn invite(&mut self, channel_id: &Digest32) -> Outcome {
        let Some(net) = self.net.as_ref() else {
            return Outcome::Failed(Fault::NotNetworked);
        };
        if !self.channels.contains_key(channel_id) {
            return Outcome::Failed(Fault::UnknownChannel);
        }
        let Ok(anchors) = net.local_endpoints() else {
            return Outcome::Failed(Fault::NotNetworked);
        };
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
        // A pinned responder is dialled as that identity; otherwise the first anchor
        // is also the responder we join through (M15 adds anchor-only bootstrap).
        let Some(responder) = parsed.responder else {
            return Outcome::Failed(Fault::BadLink);
        };
        // Dial before borrowing the profile: the dial needs `&mut self` to record that
        // this connection now has a stream loop.
        let conn = match self.dial(responder, &parsed.anchors).await {
            Ok(c) => c,
            Err(e) => return Outcome::Failed(fault_of(&e)),
        };
        let outcome = {
            let Some(profile) = self.profile.as_ref() else {
                return Outcome::Failed(Fault::NoIdentity);
            };
            let Ok(signer) = profile.signer() else {
                return Outcome::Failed(Fault::Locked);
            };
            let dh = *signer.x25519_identity_secret();
            // The board tells us what the channel is and who is in it.
            let set = match net.fetch_channel(&conn, &parsed.channel_id, 0).await {
                Ok(s) => s,
                Err(e) => return Outcome::Failed(fault_of(&e)),
            };
            let Some(genesis) = set.genesis.clone() else {
                return Outcome::Failed(Fault::BadLink);
            };
            // Announce ourselves so the responder will accept a join stream from us
            // (ADR-016: the pre-join record is what makes an unknown peer eligible).
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
            let prejoin = match crate::nat::record::PreJoinRecord::build(
                signer,
                &parsed.channel_id,
                bundle,
                endpoints,
                seq,
                now,
            ) {
                Ok(r) => r,
                Err(e) => return Outcome::Failed(fault_of(&e)),
            };
            {
                let mut client = match crate::nat::service::RendezvousClient::open(&conn).await {
                    Ok(c) => c,
                    Err(e) => return Outcome::Failed(fault_of(&e)),
                };
                // A **refusal is fine**: it means our previous announcement is still
                // live (the ADR-012 refresh floor declines a faster replacement), and
                // being announced is all this step is for. Only a transport failure
                // aborts the join.
                match client.put(&prejoin.to_wire()).await {
                    Ok(()) | Err(crate::error::Error::RendezvousRejected(_)) => {}
                    Err(e) => {
                        client.finish();
                        return Outcome::Failed(fault_of(&e));
                    }
                }
                client.finish();
            }
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
        self.channels.insert(parsed.channel_id, channel);
        // Every member whose bundle is on the board is an admitted author: the record
        // carries its full composite key and is verified against it (ADR-016). Sync
        // hard-fails on an entry from an author we never admitted, so this is what
        // makes the log reconcilable at all.
        if let (Some(profile), Some(channel)) = (
            self.profile.as_ref(),
            self.channels.get_mut(&parsed.channel_id),
        ) {
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
        self.refresh_network_view();
        self.publish_channel_locally(&parsed.channel_id);
        // And on the anchor we joined through, so every other member can find our key
        // and admit us as a log author (without which their sync sessions fail).
        self.publish_channel_to_anchor(&parsed.channel_id, &conn)
            .await;
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
            let (Some(profile), Some(channel)) =
                (self.profile.as_ref(), self.channels.get(channel_id))
            else {
                return Outcome::Failed(Fault::UnknownChannel);
            };
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
        let (Some(profile), Some(channel)) =
            (self.profile.as_ref(), self.channels.get_mut(channel_id))
        else {
            return Outcome::Failed(Fault::UnknownChannel);
        };
        if let Err(e) = channel.issue_consent(profile, target, &skdm, now) {
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
            Some(c) => c.epoch(),
            None => return 0,
        };
        let Ok(set) = net.fetch_channel(&conn, channel_id, epoch).await else {
            return 0;
        };
        let now = self.now();
        let mut learned = 0usize;
        if let (Some(profile), Some(channel)) =
            (self.profile.as_ref(), self.channels.get_mut(channel_id))
        {
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
            self.refresh_network_view();
        }
        learned
    }

    /// Reconcile a channel with every member this node can reach.
    async fn sync_channel(&mut self, channel_id: &Digest32) -> Outcome {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return Outcome::Failed(Fault::NotNetworked);
        };
        let Some(channel) = self.channels.get(channel_id) else {
            return Outcome::Failed(Fault::UnknownChannel);
        };
        let me = channel.me();
        let epoch = channel.epoch();
        let peers: Vec<Digest32> = channel.members().into_iter().filter(|m| *m != me).collect();
        let Some(store) = self.profile.as_ref().map(Profile::store_handle) else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let mut synced = 0usize;
        for peer in peers {
            if net.manager().existing(&peer).is_none() {
                continue;
            }
            // Learn who else has joined before reconciling, or the first entry from a
            // newer member kills the session.
            self.learn_members(channel_id, peer).await;
            let Some(conn) = net.manager().existing(&peer) else {
                continue;
            };
            let handle = tokio::runtime::Handle::current();
            let transport =
                match crate::node::syncstream::open_sync(&conn, handle.clone(), channel_id, epoch)
                    .await
                {
                    Ok(t) => t,
                    Err(_) => continue,
                };
            let Some(mut ch) = self.channels.remove(channel_id) else {
                break;
            };
            let store = Arc::clone(&store);
            let now = self.now();
            let joined = tokio::task::spawn_blocking(move || {
                let mut t = transport;
                let out = ch.sync_over(&store, &mut t, now);
                (ch, out)
            })
            .await;
            if let Ok((ch, out)) = joined {
                self.channels.insert(*channel_id, ch);
                if let Ok(o) = out {
                    synced += 1;
                    if o.rendered > 0 || o.governance > 0 {
                        let _ = self
                            .event_tx
                            .send(NodeEvent::Synced {
                                channel_id: *channel_id,
                                applied: o.applied as u64,
                                rendered: o.rendered as u64,
                            })
                            .await;
                    }
                }
            }
        }
        self.refresh_network_view();
        if synced == 0 {
            return Outcome::Failed(Fault::Unreachable);
        }
        Outcome::Done
    }

    /// Reconcile one channel's log with a peer over an inbound `sync` stream
    /// (ADR-008 frontier mode).
    ///
    /// The ADR-008 engine is **synchronous**, so the session runs on a blocking task:
    /// the channel is moved out of the actor's map for the duration and put back
    /// after, and the store is a shared handle (`Profile::store_handle`). While a
    /// channel is away, commands naming it answer `UnknownChannel` — the session is
    /// short and the client retries, which is better than blocking the whole actor
    /// (its other channels keep working) or mutating channel state from two threads.
    async fn run_sync_session(&mut self, send: quinn::SendStream, mut recv: quinn::RecvStream) {
        use crate::node::syncstream::{accept_sync, read_sync_request};
        let Ok((channel_id, epoch)) = read_sync_request(&mut recv).await else {
            return;
        };
        let now = self.now();
        let Some(store) = self.profile.as_ref().map(Profile::store_handle) else {
            return;
        };
        // Only a channel we hold open at that epoch can be reconciled.
        if self
            .channels
            .get(&channel_id)
            .is_none_or(|c| c.epoch() != epoch)
        {
            return;
        }
        let Some(mut channel) = self.channels.remove(&channel_id) else {
            return;
        };
        let handle = tokio::runtime::Handle::current();
        let joined = tokio::task::spawn_blocking(move || {
            let mut transport = accept_sync(handle, send, recv);
            let outcome = channel.sync_over(&store, &mut transport, now);
            (channel, outcome)
        })
        .await;
        // A panicked blocking task loses the channel from the map rather than leaving
        // it in an unknown state; reopening rebuilds it from disk.
        if let Ok((channel, outcome)) = joined {
            self.channels.insert(channel_id, channel);
            if let Ok(out) = outcome {
                if out.rendered > 0 || out.governance > 0 {
                    let _ = self
                        .event_tx
                        .send(NodeEvent::Synced {
                            channel_id,
                            applied: out.applied as u64,
                            rendered: out.rendered as u64,
                        })
                        .await;
                }
            }
            self.refresh_network_view();
        }
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
        let backfilled = match (self.profile.as_ref(), self.channels.get_mut(&channel_id)) {
            (Some(profile), Some(channel)) => channel.accept_skdm(profile.store(), &skdm, now).ok(),
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
        for (_, mut ch) in std::mem::take(&mut self.channels) {
            ch.lock_now();
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
                self.channels.insert(id, ch);
                self.refresh_network_view();
                self.publish_channel_locally(&id);
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
                self.channels.insert(*channel_id, ch);
                self.refresh_network_view();
                self.publish_channel_locally(channel_id);
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
            Some(mut ch) => {
                ch.lock_now();
                // The channel is gone from the view the board reads, so its members
                // are no longer classified from it and its records stop being served
                // on our behalf.
                if let Some(net) = self.net.as_ref() {
                    net.membership().clear_channel(channel_id);
                }
                self.refresh_network_view();
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
        let Some(ch) = self.channels.get_mut(channel_id) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        match ch.append_text(profile, text, now) {
            Ok(r) => {
                let row = row_of(r);
                let _ = self
                    .event_tx
                    .send(NodeEvent::NewEntry {
                        channel_id: *channel_id,
                        row,
                    })
                    .await;
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    /// Publish the current view (latest wins).
    fn publish(&self) {
        let view = self.view_of();
        self.view_tx.send_replace(view);
    }

    fn view_of(&self) -> NodeView {
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
        let channels = known
            .iter()
            .map(|id| match self.channels.get(id) {
                Some(ch) => ChannelSummary {
                    channel_id: *id,
                    local_name: Some(ch.local_name().to_owned()),
                    open: true,
                    entries: ch.entry_count() as u64,
                },
                None => ChannelSummary {
                    channel_id: *id,
                    local_name: None,
                    open: false,
                    entries: 0,
                },
            })
            .collect();
        let open_channels = self
            .channels
            .values()
            .map(|ch| ChannelDetail {
                channel_id: ch.channel_id(),
                local_name: ch.local_name().to_owned(),
                epoch: ch.epoch(),
                members: ch.members(),
                timeline: ch.timeline().iter().map(row_of).collect(),
            })
            .collect();
        let mlock_active = self.channels.values().all(ChannelState::mlock_active);
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
        _ => Fault::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> Secret {
        Secret::new(s.as_bytes().to_vec())
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
            pow_params: None,
            stream_loops: std::collections::BTreeSet::new(),
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
