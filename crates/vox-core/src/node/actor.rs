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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex};

use crate::atrest::sek::Argon2Profile;
use crate::error::Error;
use crate::governance::capability::{Capability, CapabilitySet};
use crate::hash::Digest32;
use crate::identity::composite::CompositePublicKey;
use crate::nat::bootstrap::{BootstrapNode, BootstrapSet};
use crate::nat::record::{MemberBundleRecord, RendezvousRecord};
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
use crate::pairwise::init_message::InitialMessage;
use crate::transport::quic::VoxConnection;

/// Command queue depth (commands beyond it apply backpressure to the client).
const COMMAND_QUEUE: usize = 64;
/// Event buffer depth, per subscriber (ADR-020 §7).
///
/// This is a **broadcast** buffer, not a queue: emission never blocks and never
/// applies backpressure, however many clients are attached and whatever they do.
/// A subscriber that falls more than `EVENT_QUEUE` events behind is *told* it
/// lagged (`EventStreamItem::Lagged`) and resumes at the oldest retained event.
///
/// Dropping events is safe **by construction, and only because of it**: an event
/// is a wake, never the delivery mechanism. Durable state is the ADR-008 log and
/// the [`NodeView`] watch, so a lagging client re-reads instead of missing
/// anything. Before M19.1 this was an `mpsc` queue and one client that stopped
/// draining blocked the actor after exactly this many events — stalling sync and
/// every command with it.
///
/// A burst larger than this buffer drops for **every** subscriber, not merely the
/// slow one, so no client may treat the stream as complete.
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

/// How often a peer reached over a relay is retried for a direct path.
///
/// A relayed path works, so nothing forces a retry — but it costs a third party's bandwidth
/// and a round trip, and the conditions that prevented a direct path are usually temporary:
/// a NAT mapping expires, a firewall state clears, a laptop leaves a captive network. One
/// attempt at dial time is a snapshot of the worst moment, when neither side has learned the
/// other's addresses yet.
///
/// A minute, which is `upgradeUDPDirectInterval` in tailscale's magicsock — the same
/// reasoning and the same figure, chosen there because NAT conditions change on that order.
const UPGRADE_RETRY: Duration = Duration::from_secs(60);

/// How long the actor may be busy before it says so.
///
/// **Derived from the tick, not chosen.** The actor is the only writer of channel state, so while
/// it is busy the node answers nobody; anything beyond a few ticks means some peer's request is
/// queued behind it, and a peer's patience is measured in seconds. Five ticks is long enough that
/// ordinary work never reports, and short enough that a stall a person would notice always does.
const STALL_BUDGET: Duration = Duration::from_secs(5);

/// How long the actor will spend *setting up* one sync before abandoning it.
///
/// **The actor may not block on the wire, and this is the interim bound while the setup moves into
/// its own slot.** Deciding to reconcile a room with a peer is cheap; the two steps before the
/// session are not — reading that peer's board (`fetch_channel`) and opening the sync stream
/// (`open_sync`) are both round trips, and both were bounded only by `SYNC_FRAME_TIMEOUT`. So one
/// peer that went quiet mid-setup stopped the one task allowed to write channel state, for twenty
/// seconds, and the node answered nobody — including the pushes it had just marked owed.
///
/// Measured on an anchor, which is the node it hurts most:
///
/// ```text
/// vox node: took 1 entry for room 4yxukqstptuq
/// vox node: BUSY 20033ms — filing a sync that finished — nobody could be answered
/// ```
///
/// Safe to bound, unlike a publish: both steps are best-effort and their failure already means
/// "skip this one, the schedule will come round again". Nothing downstream needs them to have
/// completed, so a cut-short setup costs a tick where a cut-short publish lost a record.
///
/// This is a bound, not the fix. The fix is for the whole setup to run in a slot and report back
/// through `NetEvent::SyncDone`, which is the seam that already exists for it.
/// How many sync setups and sessions may be in flight at once.
///
/// **The actor decides; slots do the waiting.** Everything about reconciling a room with a peer that
/// touches the wire — reading that peer's board, opening the stream, the session itself — runs in one
/// of these, so the one task allowed to write channel state never waits on a network round trip. It
/// used to: `fetch_channel` and `open_sync` were awaited inline, bounded only by
/// `SYNC_FRAME_TIMEOUT`, so a peer that went quiet mid-setup stopped the node for twenty seconds and
/// it answered nobody — including the pushes it had just marked owed. Measured on an anchor, which is
/// the node it hurts most because it is the hop a message takes when two members are never online
/// together:
///
/// ```text
/// vox node: took 1 entry for room 4yxukqstptuq
/// vox node: BUSY 20033ms — filing a sync that finished — nobody could be answered
/// ```
///
/// Past the cap a sync is **skipped, not queued**: the schedule comes round again, and a queue of
/// sessions for rooms whose state has since moved on is worse than none.
const SYNCS_IN_FLIGHT: usize = 16;

/// How many inbound joins this node answers at once.
///
/// Answering a join is the one inbound thing a **stranger** can ask for: the passphrase is the
/// join credential, so anyone holding the address and the passphrase gets an exchange, and the
/// exchange waits on them three times and verifies their proof of work. Run on the actor, that
/// made one joiner — slow, malicious, or merely behind a bad link — able to stop a node from
/// answering anybody: no messages, no syncs, nothing, for as long as it cared to stall. An anchor
/// is the worst place for it, because the whole point of an anchor is being the node that is
/// always there.
///
/// So the actor decides and a slot does the waiting. Past the cap a join is **refused, not
/// queued** — the same rule as [`SYNCS_IN_FLIGHT`], and for a stronger reason here: a queue of
/// half-finished exchanges is exactly the resource a flood wants to fill, and a joiner that is
/// told "no" now retries in a second, which is cheaper for both sides than a held stream.
///
/// The count of joins actually in flight also feeds `Difficulty::adapted_for_load`, which raises
/// the proof-of-work a joiner must do as the load climbs. That knob existed all along and was
/// passed a hardcoded `0`, so it had never once adapted.
const JOINS_IN_FLIGHT: usize = 16;

/// A short name for what a command was, for the stall report.
fn command_name(c: &NodeCommand) -> &'static str {
    match c {
        NodeCommand::JoinChannel { .. } => "joining a room",
        NodeCommand::CreateChannel { .. } => "creating a room",
        NodeCommand::OpenChannel { .. } => "opening a room",
        NodeCommand::SendText { .. } => "sending a message",
        NodeCommand::Sync { .. } => "syncing",
        NodeCommand::Consent { .. } => "consenting to a member",
        NodeCommand::Revoke { .. } => "revoking a member",
        NodeCommand::Serve { .. } => "publishing a service",
        NodeCommand::Up { .. } => "bringing the proxy up",
        NodeCommand::Forward { .. } => "opening a forward",
        NodeCommand::Unlock { .. } => "unlocking the identity",
        _ => "a client command",
    }
}

/// A short name for what inbound work was, for the stall report.
fn net_event_name(e: &NetEvent) -> &'static str {
    match e {
        NetEvent::JoinRequest { .. } => "answering somebody's join",
        NetEvent::SyncRequest { .. } => "answering a sync",
        NetEvent::Stream { .. } => "serving a stream",
        NetEvent::Connected { .. } => "filing a new connection",
        NetEvent::BetterPath { .. } => "adopting a connection",
        NetEvent::ReachFailed { .. } => "filing a failed dial",
        NetEvent::UpgradeFailed { .. } => "filing a path upgrade that failed",
        NetEvent::AnchorConnected { .. } => "publishing every room to an anchor that answered",
        NetEvent::AddressesDiscovered { .. } => "publishing every room at a new address",
        NetEvent::SyncDone { .. } => "filing a sync that finished",
        NetEvent::JoinAnswered { .. } => "filing a join that finished",
        NetEvent::BoardGrew { .. } => "passing on a record that landed on our board",
        NetEvent::JoinAdmit { .. } => "admitting a joiner before accepting it",
        NetEvent::Stopped => "shutting the network down",
    }
}

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
/// asked, and the mapping that expires first is the one that governs. A lifetime of
/// zero is a **permanent** grant (UPnP routers that refuse timed leases) and never
/// needs renewing — it is deleted when the network stops instead.
fn renew_at(now: u64, mappings: &[crate::nat::portmap::PortMapping]) -> Option<u64> {
    mappings
        .iter()
        .map(|m| m.lifetime_secs)
        .filter(|l| *l > 0)
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
    /// Milliseconds since the epoch, from one read. Defaults to
    /// [`crate::time::system_millis_clock`]; pin it in a test that pins [`NodeConfig::clock`].
    pub millis_clock: crate::time::MillisClock,
    /// The Argon2id profile for every at-rest derivation.
    pub argon2: Argon2Profile,
    /// Where to bind, or `None` for a node that does not network.
    pub bind: Option<Bind>,
    /// An override for the ADR-005 PoW parameters a join binds (tests reduce them).
    pub pow_params: Option<crate::join::pow::PowParams>,
    /// The anchors this node publishes to, reads from, climbs its ladder through and
    /// names in invite links (ADR-012 §"Bootstrap": the user's own always-on node).
    pub anchors: BootstrapSet,
    /// A **headless** identity (ADR-016 `vox node`): a transport identity that is not
    /// a vault. With one, the node networks the moment it is spawned — there is no
    /// passphrase and nothing to unlock — and it holds no channel secrets, because
    /// it has no profile to hold them in: it serves the board, coordinates, relays,
    /// and stores ciphertext. The absence of secrets is structural: every path that
    /// needs a profile finds none.
    pub headless: Option<Arc<crate::identity::composite::SoftwareRootSigner>>,
    /// Keep a **ciphertext copy of the log** for every channel whose genesis lands on
    /// this node's board (ADR-016 M15.2b, `node::anchor`): the store-and-forward that
    /// lets members who are never online together converge. A role, not a secret:
    /// the copy holds nothing this node could read. `vox node` turns it on; a client
    /// leaves it off, so a stranger's genesis on its board costs it nothing.
    pub anchor_logs: bool,
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
            millis_clock: crate::time::system_millis_clock(),
            argon2: Argon2Profile::default(),
            bind: None,
            pow_params: None,
            anchors: BootstrapSet::new(),
            headless: None,
            anchor_logs: false,
        }
    }

    /// Keep a ciphertext copy of every anchored channel's log.
    #[must_use]
    pub fn anchor_logs(mut self, on: bool) -> Self {
        self.anchor_logs = on;
        self
    }

    /// Run headless as this identity: no vault, no unlock, networked from spawn.
    #[must_use]
    pub fn headless(mut self, signer: crate::identity::composite::SoftwareRootSigner) -> Self {
        self.headless = Some(Arc::new(signer));
        self
    }

    /// Use this clock.
    #[must_use]
    pub fn clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Pin the millisecond clock. A test that pins [`NodeConfig::clock`] and asserts on message
    /// timestamps wants this too — they are separate seams on purpose (see the field).
    #[must_use]
    pub fn millis_clock(mut self, millis_clock: crate::time::MillisClock) -> Self {
        self.millis_clock = millis_clock;
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

/// How often a node checks that its anchors are still connected, and redials the
/// ones that are not.
const ANCHOR_REDIAL_SECS: u64 = 30;

/// What a sync session runs against: a member's channel, or an anchor's copy.
enum SessionTarget {
    Channel(SharedChannel),
    Anchored(Arc<tokio::sync::Mutex<crate::node::anchor::AnchorState>>),
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
    /// A background dial failed. **The one thing that must never be dropped.**
    ///
    /// Every dial runs off the actor, because the actor may not await a ladder. Each of those
    /// spawns kept the connection on success and discarded the error on failure, so a node that
    /// could not reach its anchor reported nothing at all and a room stayed at an empty timeline
    /// looking like patience. Measured: a member whose own view showed `epoch-timeline=0` and no
    /// event after `ChannelOpened`.
    ReachFailed {
        /// The peer that could not be reached.
        peer: Digest32,
        /// What the attempt reported.
        why: String,
    },
    /// An upgrade off a relayed path was tried and nothing better landed, with the reason.
    ///
    /// Not an error: a pair behind symmetric NATs stays relayed and that is ADR-012's documented
    /// limit. It is an event because "relayed because the NAT says no" and "relayed because a rung
    /// failed" look identical from outside, and only one of them is somebody's problem.
    UpgradeFailed {
        /// The peer still reached over a relay.
        peer: Digest32,
        /// What each rung reported.
        reason: String,
    },
    /// A better path to a peer landed — a punch answered, or an upgrade behind a
    /// relayed dial (ADR-012 rungs 3–4, M15.1b): the connection needs the same
    /// bookkeeping a dialled one gets — a stream loop and a sync schedule. The manager
    /// has already made it the peer's primary and retired the old one.
    BetterPath {
        /// The connection that landed.
        conn: Arc<VoxConnection>,
    },
    /// A peer asked to join a channel, and its request has **already been read** on the
    /// stream's own task. Reading it in the actor was a denial of service reachable by
    /// anyone holding a valid identity and a `.vox` name — see the comment in
    /// `spawn_stream_loop`.
    JoinRequest {
        /// The authenticated peer.
        peer: Digest32,
        /// The channel it asked to join.
        channel_id: Digest32,
        /// The epoch it named.
        epoch: u64,
        /// The stream's send half.
        send: quinn::SendStream,
        /// The stream's receive half.
        recv: quinn::RecvStream,
    },
    /// A peer asked to reconcile a channel, and its request has **already been read** on
    /// the stream's own task. The actor does the reconciliation; it never waits for the
    /// peer to speak, because anything the actor awaits inline stops the whole node.
    SyncRequest {
        /// The connection the stream came in on.
        conn: Arc<VoxConnection>,
        /// The authenticated peer.
        peer: Digest32,
        /// The channel it asked to reconcile.
        channel_id: Digest32,
        /// The epoch it named.
        epoch: u64,
        /// The stream's send half.
        send: quinn::SendStream,
        /// The stream's receive half.
        recv: quinn::RecvStream,
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
    /// A join exchange finished on its own task and is handing back what the actor must
    /// apply: the admission, the session, and the event a person sees.
    ///
    /// The exchange **cannot** be awaited inside the actor loop. It waits on the joiner for
    /// the solve, the proof and the init, with a proof-of-work verification in between, and
    /// every one of those waits is a stranger's to lengthen. See [`JOINS_IN_FLIGHT`].
    JoinAnswered {
        /// The authenticated peer that joined.
        peer: Digest32,
        /// The channel it joined.
        channel_id: Digest32,
        /// What the exchange produced, or the reason it did not.
        ///
        /// Boxed because a [`crate::node::joinstream::JoinOutcome`] carries a whole session,
        /// and every other variant of this enum would otherwise pay for its size. The error is
        /// already a `String`: it is formatted where it happened, off the actor.
        outcome: Box<std::result::Result<crate::node::joinstream::JoinOutcome, String>>,
    },
    /// A join exchange has proved a joiner's identity and is **holding its acceptance** until the
    /// actor has admitted it as an author.
    ///
    /// This exists to restore an ordering that was free while the exchange ran on the actor: the
    /// admission happened in the same turn the exchange ended, before the joiner could have
    /// returned. Off the actor it became an event reached later, and the joiner — which treats
    /// `Accepted` as "I am in" — published its records into that gap, where they are refused
    /// `author is not a channel member` and never retried. The newcomer then reached no board at
    /// all. Measured: a third person joining went 6 of 10 to 0 of 10 (ADR-018 §"The admission
    /// window").
    ///
    /// Cheap and local on purpose: admit the author, answer, done. Everything that touches the
    /// network — republishing, mirroring to anchors — stays on `JoinAnswered`, *after* the joiner
    /// has been accepted, so a joiner never waits on this node's round trips to somebody else.
    JoinAdmit {
        /// The room being joined.
        channel_id: Digest32,
        /// The joiner's proven identity.
        identity: Box<crate::identity::composite::CompositePublicKey>,
        /// Answered once the admission is applied, which releases the acceptance frame. A dropped
        /// sender answers too — the slot must never wait on an actor that has moved on.
        ack: tokio::sync::oneshot::Sender<()>,
    },
    /// A record by another author was admitted to this node's board, so what this node can
    /// vouch for has grown and its anchors do not know it yet.
    BoardGrew {
        /// The room whose board grew.
        channel_id: Digest32,
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
fn spawn_stream_loop(
    net: Arc<NodeNet>,
    conn: Arc<VoxConnection>,
    tx: mpsc::Sender<NetEvent>,
) -> tokio::task::JoinHandle<()> {
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
                // A sync stream's preamble is read **here, on a task of its own**, and the
                // actor is told only once the request is in hand.
                //
                // The actor is a single task and the only writer of channel state, so
                // anything it awaits inline stops the whole node: commands, the tick, and —
                // once the network queue fills — accepting connections at all. Awaiting an
                // untrusted peer's first frame there meant one stream carrying zero bytes
                // stopped a node permanently, from any peer holding a valid identity, with an
                // anchor the worst target because it is always addressable. The connection's
                // keep-alive is no defence: quinn PINGs the connection for ever while a
                // stream on it stays silent.
                //
                // A task per stream, rather than reading in this loop, so a silent stream does
                // not even hold up the other streams on its own connection. The read is
                // bounded by `framing::FRAME_PATIENCE`. Every state mutation still happens in
                // the actor, in order.
                // A join request is read here for the same reason a sync preamble is, and the
                // exposure is worse: a peer needs only a valid identity and a `.vox` name.
                // `Unknown` may open a `Rendezvous` stream, publish a self-signed pre-join
                // record naming itself for any channel this board serves, and is then
                // classified `PendingJoiner` — which may open `Join`. So the read that used to
                // sit in the actor was reachable by anyone who had ever seen an invite link.
                Ok(Inbound::Join { peer, send, recv }) => {
                    failures = 0;
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        let mut recv = recv;
                        let Ok((channel_id, epoch)) =
                            crate::node::joinstream::read_join_request(&mut recv).await
                        else {
                            crate::node::joinstream::refuse_join(send).await;
                            return;
                        };
                        let _ = tx
                            .send(NetEvent::JoinRequest {
                                peer,
                                channel_id,
                                epoch,
                                send,
                                recv,
                            })
                            .await;
                    });
                }
                Ok(Inbound::Sync { peer, send, recv }) => {
                    failures = 0;
                    let tx = tx.clone();
                    let conn = Arc::clone(&conn);
                    tokio::spawn(async move {
                        let mut recv = recv;
                        let Ok((channel_id, epoch)) =
                            crate::node::syncstream::read_sync_request(&mut recv).await
                        else {
                            return;
                        };
                        let _ = tx
                            .send(NetEvent::SyncRequest {
                                conn,
                                peer,
                                channel_id,
                                epoch,
                                send,
                                recv,
                            })
                            .await;
                    });
                }
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
    })
}

/// Accept connections and their streams forever, forwarding to the actor the ones
/// that need channel state. The board is served inside `accept_stream`.
///
/// **Each connection's handshake runs on its own task** (M17.17). This loop used to call
/// `accept`, which performs the TLS handshake inline, so the loop serialised on handshakes:
/// one peer that opened a connection and then stalled its handshake blocked **every** other
/// inbound connection — with no credential at all, because authentication had not happened
/// yet. A pre-authentication denial of service, and worst against the node most likely to be
/// always-on and public, which is an anchor. The loop's own comment claimed a slow peer could
/// not stall the others; that was true only of the stream loop, after the handshake.
/// The node's inbound accept loop.
///
/// **This performs each handshake inline, and that is a known denial-of-service gap**
/// (finding #3): one peer that opens a connection and then stalls its TLS handshake blocks
/// every other inbound connection, with no credential of any kind, because authentication
/// has not happened yet. It matters most for an always-on node, which is what an anchor is.
///
/// The two-phase API that fixes it exists and is tested — [`ConnectionManager::accept_incoming`]
/// and [`ConnectionManager::finish_incoming`], the handshake bounded at 30 seconds — but it is
/// **deliberately not wired in here yet.** Spawning phase two per attempt makes
/// `m15_two_clients_behind_symmetric_nats_form_a_swarm_through_their_anchor` and
/// `m16_a_tcp_service_is_reached_across_the_overlay_between_two_nated_clients` time out, while
/// `m15_members_never_online_together_converge_through_the_anchor` keeps passing. Measured, not
/// suspected: serialising this loop again and changing nothing else turns both back green, and
/// clean upstream passes all three in 40s.
///
/// The two that break both carry a **relayed circuit** between peers behind symmetric NATs,
/// where no punch is possible; the one that survives converges through the anchor without a
/// live circuit. So something in circuit establishment depends on the ordering this loop
/// currently imposes, and the mechanism is not yet understood.
///
/// Shipping the split would trade a pre-authentication DoS for an overlay that cannot form a
/// swarm through an anchor, which is a worse product. The ordering is deliberate: an
/// authorization bypass outranks a DoS, and a DoS outranks not working. Those two NAT gates are
/// now the acceptance test for the real fix.
fn spawn_accept_loop(net: Arc<NodeNet>, tx: mpsc::Sender<NetEvent>) {
    tokio::spawn(async move {
        // **Experiment scaffolding, to be removed once ADR-017's open gap is settled.**
        //
        // `VOX_SPLIT_ACCEPT=1` runs phase two on its own task instead of inline. Both
        // shapes exist in one binary **on purpose**: the measurement that reverted the
        // split compared runs taken at different times, and the whole question is whether
        // the 68s/140s/247s spread belongs to the split or to a flaky long tail. One
        // binary lets the arms be interleaved A/B/A/B in a single window, which is the
        // only way to control for the box drifting underneath — this machine has carried
        // 324 orphaned processes and a wedged compiler cache in one evening.
        //
        // Whichever arm wins, this switch goes and the loser's code goes with it. A
        // permanent environment variable choosing between two security-relevant shapes is
        // a configuration bug waiting to happen.
        let split = std::env::var("VOX_SPLIT_ACCEPT").is_ok_and(|v| v == "1");
        // Bounded, because "spawn per connection" without a ceiling is the DoS the
        // serialised loop was protecting against by accident. At the cap an attempt is
        // **refused**, not queued: queueing would put the wait back in the accept path and
        // reintroduce exactly the stall being removed.
        let gate = Arc::new(tokio::sync::Semaphore::new(HANDSHAKES_IN_FLIGHT));
        loop {
            let Some(incoming) = net.manager().accept_incoming().await else {
                break;
            };
            if !split {
                // **Awaited here, not spawned — ADR-017's recorded decision.** Spawning phase
                // two is quinn's own documented shape (`finish_incoming` says "Spawn this; do
                // not await it in an accept loop") and removes a 30s serialisation window, but
                // ADR-017 "Open proof gap" records it measured: serialised 40-52s consistently
                // green on `m15_two_clients_behind_symmetric_nats`, split 68s, 140s and a
                // timeout at 247s. The unbounded case is gone either way: `finish_incoming`
                // bounds the handshake at `HANDSHAKE_TIMEOUT`.
                if let Some(filed) = finish_one(&net, incoming).await {
                    if !serve_filed(&net, &tx, filed).await {
                        break;
                    }
                }
                continue;
            }
            let Ok(permit) = Arc::clone(&gate).try_acquire_owned() else {
                // **At capacity, and what we do here decides what a flood costs.**
                //
                // This codebase has never used quinn's address-validation tools —
                // `retry`, `refuse`, `ignore` and `remote_address_validated` appear
                // nowhere else — so today a spoofed source address costs an attacker one
                // packet and costs us a whole handshake slot. Refusing at the cap keeps
                // that property: 64 spoofed packets and every real peer is turned away.
                //
                // `retry` sends a Retry packet, which makes the client prove it can
                // receive at the address it claims before we allocate anything. A spoofed
                // flood cannot answer one; a real peer pays a single round trip. So the
                // cost inverts, using quinn's own anti-amplification mechanism rather
                // than something invented here.
                //
                // An already-validated peer gets `refuse` instead, because for them the
                // honest answer is "not now" rather than another round trip.
                //
                // **The residual, stated rather than implied:** 64 *validated* handshakes
                // that stall still deny service for up to `HANDSHAKE_TIMEOUT` each. That
                // is bounded and far better than a single slot, and it is not nothing.
                if incoming.remote_address_validated() {
                    incoming.refuse();
                } else if incoming.retry().is_err() {
                    // Already a retried attempt; validating it again would loop.
                    continue;
                }
                continue;
            };
            let net = Arc::clone(&net);
            let tx = tx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Some(filed) = finish_one(&net, incoming).await {
                    let _ = serve_filed(&net, &tx, filed).await;
                }
            });
        }
        let _ = tx.send(NetEvent::Stopped).await;
    });
}

/// How many inbound handshakes may run at once when the accept loop is split.
///
/// The serialised loop's ceiling is one, which is the defect. This is the same bound in
/// spirit as [`JOINS_IN_FLIGHT`]: enough that ordinary use never reaches it, small enough
/// that an attacker cannot make a node hold unbounded state.
const HANDSHAKES_IN_FLIGHT: usize = 64;

/// Phase two for one connection: complete the handshake and admission, or drop it.
async fn finish_one(
    net: &Arc<NodeNet>,
    incoming: quinn::Incoming,
) -> Option<crate::node::net::Filed> {
    net.manager()
        .finish_incoming(
            incoming,
            crate::transport::quic::Admission::AcceptAnyAuthenticated,
        )
        .await
        .ok()
}

/// Serve a filed connection and announce it. `false` when the actor has gone away.
async fn serve_filed(
    net: &Arc<NodeNet>,
    tx: &mpsc::Sender<NetEvent>,
    filed: crate::node::net::Filed,
) -> bool {
    let peer = filed.kept.peer_id();
    // **Both connections get read.** `file_reporting` may have preferred one we already
    // held and retired the one just accepted. The peer dialled that one and does not know
    // we preferred another, so it opens streams there — and serving only the kept
    // connection leaves the retired one transport-alive and application-deaf, which is
    // worse than the close it replaced.
    if let Some(also) = filed.also_serve {
        // Bounded by the retirement grace: `retire_expired` will not close a connection
        // while anything still holds it, and a stream loop holds its `Arc` for the
        // connection's life — so an unbounded reader would pin the very thing whose
        // purpose is to be let go.
        let grace = Duration::from_secs(net.manager().retire_grace_secs());
        let loop_task = spawn_stream_loop(Arc::clone(net), also, tx.clone());
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            loop_task.abort();
        });
    }
    spawn_stream_loop(Arc::clone(net), filed.kept, tx.clone());
    tx.send(NetEvent::Connected { peer }).await.is_ok()
}

/// How long a joiner waits for the responder's **address record** to reach the board.
///
/// Separate from [`NodeActor::BOARD_PATIENCE`] because it waits on a different thing: the
/// board is already answering, and what is missing is one record propagating onto it.
const JOIN_ADDRESS_PATIENCE: Duration = Duration::from_secs(20);

/// Poll interval while waiting for it. One extra board fetch is cheap; a failed join is not.
const JOIN_ADDRESS_POLL: Duration = Duration::from_millis(250);

/// How many members a join will try when the link pins no responder.
///
/// Each attempt runs the ADR-005 join, which carries a proof of work, so walking every
/// member of a large room would turn one join into minutes of hashing. Three is enough to
/// survive the case this exists for — the first member the board lists happens to be
/// offline — without making an unreachable room expensive to fail against.
const MAX_JOIN_RESPONDERS: usize = 3;

/// How long one of **our own** records may keep being refused `author is not a channel
/// member` before the node says so.
///
/// Every join starts in that state and leaves it when a member mirrors us onward, so a
/// shorter grace reports successful joins as problems. Sixty seconds is longer than any
/// join measured here (12-21s end to end, two machines through a real anchor) and short
/// enough that a node genuinely stranded off a board is named while somebody is still
/// looking at the terminal.
const PUBLISH_REFUSAL_GRACE: u64 = 60;

/// Whether a failed join attempt is worth repeating against a different member.
///
/// **Stated as what must not be retried, not as what may be.** The first version listed the
/// two faults worth another try, which meant any fault it had not heard of stopped the walk
/// — and that is exactly what happened: a new `Error::LadderExhausted` was added elsewhere
/// with no `fault_of` arm, fell through to `Fault::Internal`, and silently turned the walk
/// back into "try one member and give up". Nothing failed loudly; joins simply stopped
/// falling through, and six single-variable reverts could not find it because every one of
/// them left the new variant in place.
///
/// A whitelist of retryable faults is the wrong default for a bounded walk. The cost of
/// retrying a fault that will not change is one more attempt out of at most
/// [`MAX_JOIN_RESPONDERS`]; the cost of *not* retrying one that would have succeeded is a
/// room that looks unreachable while a member sits there able to serve it. So the refusals
/// that genuinely cannot change are named, and anything else gets another member.
///
/// Named here because each would fail identically against every member of the room, and
/// retrying would multiply the proof-of-work cost while changing nothing — and for a
/// passphrase it would look from the outside like an attempt to guess it.
const fn worth_another_responder(fault: Fault) -> bool {
    !matches!(
        fault,
        Fault::WrongPassphrase
            | Fault::Locked
            | Fault::NoIdentity
            | Fault::BadLink
            | Fault::TooLong
            | Fault::Storage
            | Fault::ShuttingDown
            | Fault::NotNetworked
            | Fault::IdentityExists
    )
}

/// A client's handle to a running node.
///
/// Several clients may hold clones of one handle and each take its own event
/// stream with [`subscribe`](Self::subscribe); none of them can stall the actor,
/// and none of them can starve another (ADR-020 §7).
#[derive(Debug, Clone)]
pub struct NodeHandle {
    cmd_tx: mpsc::Sender<(NodeCommand, oneshot::Sender<Outcome>)>,
    view_rx: watch::Receiver<NodeView>,
    /// Kept so a client may subscribe at any time after the node started.
    event_tx: broadcast::Sender<NodeEvent>,
    /// The handle's own stream, backing [`NodeHandle::next_event`] — the
    /// single-consumer convenience the TUI and the gates use.
    events: Arc<Mutex<broadcast::Receiver<NodeEvent>>>,
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

    /// An independent event stream for this client.
    ///
    /// Every subscriber receives every event emitted after it subscribed, and a
    /// subscriber that falls behind is told so rather than silently skipped — see
    /// [`EventStreamItem`]. Taking a stream costs the actor nothing and no
    /// subscriber can slow it down or starve another (ADR-020 §7).
    #[must_use]
    pub fn subscribe(&self) -> EventStream {
        EventStream {
            rx: self.event_tx.subscribe(),
        }
    }

    /// The next ordered event, or `None` once the actor has stopped.
    ///
    /// The single-consumer convenience over this handle's own stream: it **drops
    /// a lag report and keeps going**, so a caller that falls behind silently
    /// misses events. That is right for the TUI, whose events drive unread counts
    /// and notices while the durable state comes from [`NodeHandle::view`] — but
    /// a client that must not miss anything wants [`subscribe`](Self::subscribe)
    /// instead, so it can see the lag and re-read the log from its cursor.
    pub async fn next_event(&self) -> Option<NodeEvent> {
        let mut rx = self.events.lock().await;
        loop {
            match rx.recv().await {
                Ok(ev) => return Some(ev),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    /// Non-blocking event poll (for a synchronous UI loop).
    ///
    /// Lossy on lag for the same reason as [`next_event`](Self::next_event).
    pub fn try_next_event(&self) -> Option<NodeEvent> {
        let mut rx = self.events.try_lock().ok()?;
        loop {
            match rx.try_recv() {
                Ok(ev) => return Some(ev),
                Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
                Err(_) => return None,
            }
        }
    }
}

/// One item from a [`NodeHandle::subscribe`] stream.
///
/// Deliberately **not** `#[non_exhaustive]`, unlike [`NodeEvent`]: this is a
/// closed algebra — a subscriber either received an event or missed some — and a
/// catch-all arm is precisely how a lag report would come to be silently
/// swallowed, which ADR-020 §7 forbids. If a third case is ever needed, every
/// consumer should be made to look at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventStreamItem {
    /// An event from the node.
    Event(NodeEvent),
    /// This subscriber fell behind and `missed` events were dropped for it.
    ///
    /// **Not an error, and nothing is lost that matters**: an event is a wake,
    /// not the delivery mechanism. The durable record is the ADR-008 log, so the
    /// correct response is to re-read from this client's cursor (ADR-020 §7).
    /// Emission is never slowed by a slow subscriber, which is what makes this
    /// possible — and what stops one wedged client stalling the node.
    Lagged(u64),
}

/// An independent per-client event stream (see [`NodeHandle::subscribe`]).
#[derive(Debug)]
pub struct EventStream {
    rx: broadcast::Receiver<NodeEvent>,
}

impl EventStream {
    /// The next item, or `None` once the actor has stopped and the buffer is
    /// drained.
    pub async fn next(&mut self) -> Option<EventStreamItem> {
        match self.rx.recv().await {
            Ok(ev) => Some(EventStreamItem::Event(ev)),
            Err(broadcast::error::RecvError::Lagged(n)) => Some(EventStreamItem::Lagged(n)),
            Err(broadcast::error::RecvError::Closed) => None,
        }
    }

    /// Non-blocking poll. `None` means "nothing right now", which is **not** the
    /// same as the stream having ended.
    pub fn try_next(&mut self) -> Option<EventStreamItem> {
        match self.rx.try_recv() {
            Ok(ev) => Some(EventStreamItem::Event(ev)),
            Err(broadcast::error::TryRecvError::Lagged(n)) => Some(EventStreamItem::Lagged(n)),
            Err(_) => None,
        }
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
    /// The headless transport identity, if this node runs without a vault.
    headless: Option<Arc<crate::identity::composite::SoftwareRootSigner>>,
    /// Whether this node keeps a ciphertext copy of every anchored channel's log.
    anchor_logs: bool,
    /// The store a headless node keeps its anchored logs in (a profile node uses its
    /// profile's store).
    anchor_store: Option<Arc<crate::node::store::Store>>,
    /// The anchored channels' logs, by channelID (ADR-016 M15.2b). A channel is never
    /// both here and in `channels`: a member holds the real thing.
    anchored: BTreeMap<Digest32, Arc<tokio::sync::Mutex<crate::node::anchor::AnchorState>>>,
    /// Live forwards by their bound local address (ADR-013 Dial, M16.1). Dropping one
    /// stops its listener.
    forwards: BTreeMap<std::net::SocketAddr, crate::node::tunnel::Forward>,
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
    /// When the anchors are next checked for a dropped connection (unix seconds).
    redial_anchors_at: u64,
    /// When the granted mappings must be renewed (unix seconds), or `None` when there
    /// is nothing to renew. A mapping a gateway grants for two hours outlives no
    /// long-running node by itself: it is re-requested at half its lifetime, the
    /// interval RFC 6887 §11.2.1 recommends.
    renew_mappings_at: Option<u64>,
    /// Per-peer ADR-008 sync clock (ADR-016 §"Sync scheduling").
    schedules: BTreeMap<Digest32, SyncSchedule>,
    /// Channels with a local append not yet pushed to peers.
    pending_push: std::collections::BTreeSet<Digest32>,
    /// Slots for sync setups and sessions; see [`SYNCS_IN_FLIGHT`].
    sync_slots: Arc<tokio::sync::Semaphore>,
    /// The last refusal reported per room and record kind, so a standing one is said once.
    ///
    /// Most refusals are the ADR-012 refresh floor declining a replacement that is merely too
    /// soon, which recurs every publish round for as long as the record stays live. Reported
    /// every time, that buries the refusals which mean something under the one that does not —
    /// an operator scrolling past `rejected: policy` is how a `not a channel member` goes unread.
    /// Reported on change, like every other line a node says about itself.
    last_publish_refusal: BTreeMap<(Digest32, String), String>,
    /// When we first saw a still-uncured refusal of one of **our own** records.
    ///
    /// A newcomer's own bundle and address are refused `author is not a channel member`
    /// by every board until a member vouches for it — that is M15.2a working, it is the
    /// ordinary first step of every join, and it cures itself when the responder mirrors
    /// us onward. Printing it makes a **successful** join look like a failure: the
    /// decider's first real cross-machine join showed two of these and then `joined.`,
    /// which is exactly the "scary message on a working command" that teaches people to
    /// ignore messages.
    ///
    /// So it is not suppressed, it is **deferred by time**: the first sighting is
    /// remembered silently, and the refusal is reported only if the same board still
    /// refuses the same record [`PUBLISH_REFUSAL_GRACE`] later. A join that cures itself
    /// never prints; a node that is genuinely stuck out of a room still does, which is
    /// the whole reason this event exists.
    ///
    /// **Counting publish rounds instead of seconds was tried and was wrong.** A join
    /// legitimately takes more than one round, so "report it the second time" printed on
    /// one successful join in three — less noise than before, and still noise on a
    /// command that worked. Rounds are driven by whatever else the node is doing; the
    /// question being asked here is "has this cured *yet*", which is a question about
    /// time.
    publish_refusal_first_seen: BTreeMap<(Digest32, String), u64>,
    /// Slots for answering inbound joins; see [`JOINS_IN_FLIGHT`].
    join_slots: Arc<tokio::sync::Semaphore>,
    /// The join exchanges running right now.
    ///
    /// Tracked rather than detached for one reason: each holds an `Arc<VaultRootSigner>`, and
    /// ADR-015 says a locked node holds no identity secrets. [`Node::lock_all`] aborts this set,
    /// so the last handle goes with the lock and "locked" keeps meaning *now* instead of *once
    /// this joiner gets bored*.
    join_tasks: tokio::task::JoinSet<()>,
    /// Rooms with a session in flight, so a second one cannot start for the same room.
    ///
    /// **This guard is not new, it was lost.** `sync_one`'s own doc still says "while the channel is
    /// away it is invisible to commands and, usefully, to this function, so a second pass cannot
    /// start a concurrent session for the same channel", and `start_session` is still titled "take
    /// the channel out of the actor's map" — that removal *was* the guard. The code now clones the
    /// `Arc` instead, which is better for commands (they no longer answer `UnknownChannel` mid-sync)
    /// and silently dropped the protection.
    ///
    /// Without it two nodes that reconcile at the same moment deadlock on each other: each holds its
    /// own room's lock for its initiated session and waits for frames from a peer whose lock is held
    /// by *its* initiated session. Nothing breaks it but `SYNC_FRAME_TIMEOUT`. Measured as a user, a
    /// message posted right after a join crossed in 20s or 40s — one and two frame timeouts — instead
    /// of the 0-1s it takes when the rooms are free.
    syncing: std::collections::BTreeSet<Digest32>,
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
    ///
    /// Shared, because answering a join needs it off the actor and two joins may overlap. The
    /// lock is taken twice per exchange and never across a wait — see
    /// [`crate::node::joinstream::run_responder`].
    prekeys: Option<Arc<tokio::sync::Mutex<PrekeyRing>>>,
    channels: BTreeMap<Digest32, SharedChannel>,
    clock: Clock,
    /// Milliseconds since the epoch, from **one** read — see [`crate::time::MillisClock`].
    ///
    /// A second seam rather than a change to `clock`, because ten call sites feed that into TTLs
    /// specified in seconds. Only the message timestamp uses this, and only because it becomes
    /// half the ADR-020 claim ordering key, where whole seconds put two racing agents in one
    /// bucket and let a hash decide.
    millis_clock: crate::time::MillisClock,
    argon2: Argon2Profile,
    view_tx: watch::Sender<NodeView>,
    event_tx: broadcast::Sender<NodeEvent>,
    /// The ADR-020 §3 trust keyring, loaded on unlock and empty while locked
    /// (it is sealed under the identity, so there is nothing to hold locked).
    trust: crate::node::trust::Keyring,
    /// When each peer was last tried for a better path, so a relayed connection is retried
    /// on a schedule rather than only at the moment it was made.
    last_upgrade: std::collections::BTreeMap<Digest32, u64>,
    /// The live reacher set per channel (M17.11), written here and read by serving tasks.
    /// Kept out of `Channel` because it is a *join* of channel state with the node-wide
    /// keyring, and the keyring is not a property of any one room.
    reachers: std::collections::BTreeMap<Digest32, crate::node::tunnel::Reachers>,
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
            millis_clock,
            argon2,
            bind,
            pow_params,
            anchors,
            headless,
            anchor_logs,
        } = cfg;
        let profile = if Profile::exists(&paths) {
            Some(Profile::open(paths.clone())?)
        } else {
            None
        };
        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_QUEUE);
        let (event_tx, event_rx) = broadcast::channel(EVENT_QUEUE);
        // The handle keeps the sender so any number of clients may subscribe
        // later (ADR-020 §7); the actor keeps its own clone to emit with.
        let handle_event_tx = event_tx.clone();
        let (net_tx, net_rx) = mpsc::channel(NET_QUEUE);
        let node = Self {
            paths,
            profile,
            millis_clock,
            net: None,
            net_tx,
            bind,
            anchor_ids: anchors.nodes().iter().map(|n| n.id).collect(),
            anchors,
            headless,
            anchor_logs,
            anchor_store: None,
            anchored: BTreeMap::new(),
            forwards: BTreeMap::new(),
            pow_params,
            stream_loops: std::collections::BTreeSet::new(),
            port_mappings: Vec::new(),
            redial_anchors_at: 0,
            renew_mappings_at: None,
            schedules: BTreeMap::new(),
            pending_push: std::collections::BTreeSet::new(),
            sync_slots: Arc::new(tokio::sync::Semaphore::new(SYNCS_IN_FLIGHT)),
            last_publish_refusal: BTreeMap::new(),
            publish_refusal_first_seen: BTreeMap::new(),
            join_slots: Arc::new(tokio::sync::Semaphore::new(JOINS_IN_FLIGHT)),
            join_tasks: tokio::task::JoinSet::new(),
            syncing: std::collections::BTreeSet::new(),
            record_seq: BTreeMap::new(),
            sessions: BTreeMap::new(),
            prekeys: None,
            channels: BTreeMap::new(),
            clock,
            argon2,
            view_tx: watch::Sender::new(NodeView::default()),
            event_tx,
            trust: crate::node::trust::Keyring::new(),
            last_upgrade: std::collections::BTreeMap::new(),
            reachers: std::collections::BTreeMap::new(),
        };
        let view_rx = node.view_tx.subscribe();
        // A headless node has nothing to unlock: it is on the network from the start.
        let mut node = node;
        if node.headless.is_some() {
            if node.anchor_logs {
                node.anchor_store = Some(Arc::new(crate::node::store::Store::open(
                    &node.paths.store_file(),
                )?));
            }
            node.start_network()?;
            node.reopen_anchored()?;
        }
        node.publish_initial();
        tokio::spawn(node.run(cmd_rx, net_rx));
        Ok(NodeHandle {
            cmd_tx,
            view_rx,
            event_tx: handle_event_tx,
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
                    let name = command_name(&command);
                    let started = std::time::Instant::now();
                    let outcome = self.handle(command).await;
                    self.note_if_stalled(name, started);
                    self.publish().await;
                    // A dropped reply receiver is the caller's choice, not an error.
                    let _ = reply.send(outcome);
                    if shutdown {
                        break;
                    }
                }
                Some(event) = net_rx.recv() => {
                    let name = net_event_name(&event);
                    let started = std::time::Instant::now();
                    self.handle_net(event).await;
                    self.note_if_stalled(name, started);
                    self.publish().await;
                }
                _ = ticker.tick() => {
                    if let Some(net) = self.net.as_ref() {
                        // Connections a better path displaced are closed once their
                        // grace is up (M15.1b).
                        net.manager().retire_expired();
                    }
                    self.retry_upgrades_if_due().await;
                    self.renew_mappings_if_due();
                    self.adopt_anchored_from_board().await;
                    self.redial_anchors_if_due();
                    // A rotation's re-keys go out as the remaining consenters become
                    // reachable, which is why they are retried here and not only at
                    // the moment of rotation (M18.1).
                    self.deliver_owed_rekeys().await;
                    // Auto-consent for trusted identities, retried here for the
                    // same reason: a trusted member that was unreachable a moment
                    // ago is picked up as soon as it can be reached (ADR-020 §3).
                    self.deliver_owed_consents().await;
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
        let _ = self.event_tx.send(NodeEvent::Shutdown);
    }

    async fn handle(&mut self, command: NodeCommand) -> Outcome {
        match command {
            NodeCommand::CreateIdentity { passphrase } => self.create_identity(&passphrase),
            NodeCommand::Unlock { passphrase } => self.unlock(&passphrase).await,
            NodeCommand::Lock => {
                // A headless node has no vault, so there is nothing to lock and no
                // passphrase to unlock it with: locking it would take the anchor off
                // the network permanently, until somebody noticed and restarted it.
                // Refused rather than obeyed (ADR-016 M15.2c).
                if self.headless.is_some() {
                    return Outcome::Failed(Fault::NoIdentity);
                }
                self.lock_all().await;
                Outcome::Done
            }
            NodeCommand::AddAnchors { anchors } => {
                // `merge` keeps the first entry per identity, so it would discard exactly
                // the thing a refresh carries: the same anchor at its new address.
                if self.anchors.merge_endpoints(&anchors).is_err() {
                    return Outcome::Failed(Fault::TooLong);
                }
                // Dial straight away rather than waiting for the throttle: the caller
                // refreshed because something changed, and the whole point is not to sit
                // on a stale address.
                self.redial_anchors_at = 0;
                self.redial_anchors_if_due();
                // And give the rooms the new address too. A channel keeps the anchor set
                // it adopted when it was created or joined, and that set is what an
                // invite link carries — so without this a room minted before the move
                // would go on handing out an address nobody can dial.
                let open: Vec<Digest32> = self.channels.keys().copied().collect();
                for channel_id in open {
                    self.adopt_channel_anchors(&channel_id, Some(&anchors))
                        .await;
                }
                Outcome::Done
            }
            NodeCommand::VerifyPassphrase { passphrase } => match self.profile.as_ref() {
                None => Outcome::Failed(Fault::NoIdentity),
                Some(profile) => match profile.verify_passphrase(&passphrase) {
                    Ok(()) => Outcome::Done,
                    Err(_) => Outcome::Failed(Fault::WrongPassphrase),
                },
            },
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
            NodeCommand::Revoke { channel_id, target } => {
                // A per-room revocation of a **trusted** identity does not hold: the ring
                // still names it, so `deliver_owed_consents` re-issues consent on the next
                // tick and the revocation heals itself, silently, within seconds. Found by
                // review 2026-09-21; it was a fail-open at the centre of the gate.
                //
                // Refusing rather than special-casing, because the alternative is
                // incoherent: trust is room-independent (ADR-020 decision 3), so "revoked
                // here but still trusted" is not a state the model has. `Untrust` is the
                // act that means it, and it changes the lock everywhere (M17.14).
                if self.trust.is_trusted(&target) {
                    Outcome::Failed(Fault::StillTrusted)
                } else {
                    self.revoke(&channel_id, target).await
                }
            }
            NodeCommand::Trust {
                fingerprint,
                petname,
            } => self.trust_identity(fingerprint, &petname).await,
            NodeCommand::Untrust { fingerprint } => self.untrust_identity(&fingerprint).await,
            NodeCommand::Serve {
                local_name,
                passphrase,
                port,
                at,
            } => self.serve_room(&local_name, &passphrase, port, at).await,
            NodeCommand::Up { channel_id, bind } => self.bring_up(&channel_id, bind).await,
            NodeCommand::AddService {
                channel_id,
                service_tag,
                local,
            } => self.add_service(&channel_id, &service_tag, local).await,
            NodeCommand::RemoveService {
                channel_id,
                service_tag,
            } => self.remove_service(&channel_id, &service_tag).await,
            NodeCommand::GrantTunnel {
                channel_id,
                target,
                service_tag,
                may_bind,
                expiry,
            } => {
                self.grant_tunnel(&channel_id, &target, &service_tag, may_bind, expiry)
                    .await
            }
            NodeCommand::Forward {
                channel_id,
                host,
                service_tag,
                local,
            } => self.forward(&channel_id, &host, &service_tag, local).await,
            NodeCommand::StopForward { local } => {
                // Dropping the forward aborts its listener; connections already
                // spliced run to their own end.
                if self.forwards.remove(&local).is_some() {
                    Outcome::Done
                } else {
                    Outcome::Failed(Fault::UnknownChannel)
                }
            }
            NodeCommand::Sync { channel_id } => self.sync_channel(&channel_id).await,
            NodeCommand::Shutdown => Outcome::Done,
        }
    }

    /// Say so if the actor was busy longer than a peer will wait.
    ///
    /// The actor is the only writer of channel state, so whatever it awaits stops the node
    /// answering *everyone* — and a request arriving in that window waits out its own patience and
    /// reports this node as unreachable when it was merely busy. That failure is indistinguishable
    /// from a network problem at the far end, which is why the node has to say it about itself.
    /// Say why a join failed, with what each responder that was tried reported.
    ///
    /// The walk may have tried three members and been refused by all of them for three different
    /// reasons, and all the caller ever got was one `Fault`. This is what makes a retry informed.
    fn say_why_the_join_failed(&self, why: &[String]) {
        if why.is_empty() {
            return;
        }
        let _ = self.event_tx.send(NodeEvent::JoinFailed {
            reason: why.join("; "),
        });
    }

    fn note_if_stalled(&self, what: &str, since: std::time::Instant) {
        let took = since.elapsed();
        if took < STALL_BUDGET {
            return;
        }
        let _ = self.event_tx.send(NodeEvent::Stalled {
            what: what.to_owned(),
            millis: u64::try_from(took.as_millis()).unwrap_or(u64::MAX),
        });
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
                let _ = self.event_tx.send(NodeEvent::Unlocked);
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
        // The identity to network as: the unlocked vault's, or the headless one.
        let endpoint = Arc::new(match (self.headless.as_ref(), self.profile.as_ref()) {
            (Some(signer), _) => match bind {
                Bind::Addr(addr) => crate::transport::quic::VoxEndpoint::bind(&**signer, *addr)?,
                Bind::Socket(socket) => crate::transport::quic::VoxEndpoint::bind_abstract(
                    &**signer,
                    Arc::clone(socket),
                )?,
            },
            (None, Some(profile)) => match bind {
                Bind::Addr(addr) => {
                    crate::transport::quic::VoxEndpoint::bind(profile.signer()?, *addr)?
                }
                Bind::Socket(socket) => crate::transport::quic::VoxEndpoint::bind_abstract(
                    profile.signer()?,
                    Arc::clone(socket),
                )?,
            },
            (None, None) => {
                return Err(crate::error::Error::Profile("no identity in this profile"))
            }
        });
        let mut net = NodeNet::new(endpoint, Arc::clone(&self.clock));
        // **A record landing on this node's board is an event, not something to notice later.**
        // A newcomer becomes findable to everyone away from the room only because a member that
        // already knows it publishes its bundle onward, and until now nothing told this node one
        // had arrived — the onward mirror went out when the join finished, which is *before* the
        // newcomer publishes, and then waited for whatever triggered a publish next.
        //
        // `try_send` rather than a blocking send, and the reason is **deadlock, not queue state**:
        // this runs inside the rendezvous service, on a path the actor may itself be waiting
        // behind, so a send that blocks could hold the service against its own actor. The cost when
        // the queue is full is worth stating plainly rather than implying it away — the hint is
        // dropped, and that newcomer falls back to "whatever triggers a publish next", which is
        // exactly the unbounded wait this change exists to remove. A full `NET_QUEUE` means the
        // actor is behind, not that it is about to mirror this room: the 64 items ahead of it could
        // all belong to other channels. The drop is acceptable, not harmless.
        {
            let tx = self.net_tx.clone();
            net.on_board_growth(Arc::new(move |channel_id: Digest32| {
                let _ = tx.try_send(NetEvent::BoardGrew { channel_id });
            }));
        }
        let net = Arc::new(net);
        self.net = Some(Arc::clone(&net));
        // The configured anchors are dialled at once, each on its own task: they are
        // where this node's records go and the helpers its ladder climbs through, and
        // an anchor that is down must not hold up the ones that are not.
        for anchor in self.anchors.nodes() {
            let net = Arc::clone(&net);
            let tx = self.net_tx.clone();
            let (id, endpoints) = (anchor.id, anchor.endpoints.clone());
            tokio::spawn(async move {
                match net.manager().connect(id, &endpoints).await {
                    Ok(conn) => {
                        let _ = tx.send(NetEvent::AnchorConnected { conn }).await;
                    }
                    Err(e) => {
                        let _ = tx
                            .send(NetEvent::ReachFailed {
                                peer: id,
                                why: e.to_string(),
                            })
                            .await;
                    }
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
        // A UPnP mapping the router granted only *permanently* (lifetime 0) would
        // outlive this node; it is deleted, best-effort, on its own task. Timed
        // mappings of every kind expire by themselves.
        for m in self.port_mappings.drain(..) {
            if m.method == crate::nat::portmap::Method::UpnpIgd && m.lifetime_secs == 0 {
                tokio::spawn(async move {
                    let _ = crate::nat::portmap::unmap_port_upnp(
                        crate::nat::portmap::Protocol::Udp,
                        m.internal_port,
                    )
                    .await;
                });
            }
        }
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
        // The admission goes out with the bundle: a node that cannot say how it became
        // a member publishes nothing, rather than publishing an unevidenced key (M17.6).
        let (genesis_wire, epoch, admission) = match self.channels.get(channel_id) {
            Some(shared) => {
                let c = shared.lock().await;
                let Some(admission) = c.own_admission().cloned() else {
                    return;
                };
                (c.genesis().to_wire(), c.epoch(), admission)
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
            let ring = ring.lock().await;
            net.own_records(signer, channel_id, epoch, &ring, seq, admission)
        };
        let Ok((address, bundle)) = records else {
            return;
        };
        let Ok(mut client) = crate::nat::service::RendezvousClient::open(conn).await else {
            return;
        };
        // **Said, not swallowed.** A refused bundle is a member no other member can admit as a
        // log author, and every one of these was `let _ = ...` — so the board's reason existed,
        // was specific, and was dropped on the floor at the one place that could report it.
        //
        // Each kind's outcome is carried, success as well as failure, because a refusal that
        // *stops* has to clear its memo below — otherwise a standing refusal reported once would
        // be silent the second time it mattered.
        let mut outcomes: Vec<(&'static str, Option<String>)> = Vec::new();
        outcomes.push((
            "the room's genesis",
            client.put(&genesis_wire).await.err().map(|e| e.to_string()),
        ));
        // **Our bundle before our address, for the reason this file already states about *other*
        // members' records and did not apply to its own.** An address record carries no key, so a
        // board can only verify it against a key it already holds — which is what the bundle
        // carries. Published address-first, a member whose key the board does not know yet has its
        // address refused with `author is not a channel member`, microseconds before the bundle
        // that would have made it admissible arrives on the same connection; and nothing retries
        // it until the next publish round. `network.rs` `board_records` has emitted bundles first
        // all along and says why. This did the opposite for the records that matter most — a
        // newcomer's own — so a member could be on an anchor's board with a key and no way to
        // reach it, which a joiner reports as the member being unreachable.
        outcomes.push((
            "our member bundle",
            client
                .put(&bundle.to_wire())
                .await
                .err()
                .map(|e| e.to_string()),
        ));
        outcomes.push((
            "our address",
            client
                .put(&address.to_wire())
                .await
                .err()
                .map(|e| e.to_string()),
        ));
        // And every other member's records this node's board holds: an anchor learns
        // a channel's members only from a member that vouches for them (M15.2a), and
        // a bundle carries the key an address record is verified against, so bundles
        // go first.
        //
        // **Awaited, and it has to be.** Sending this off the actor was tried: it removed the
        // measured `busy 19416ms — publishing every room at a new address` stall, and cost more
        // than it saved. Convergence depends on these records actually being on the anchor's board
        // before the next step reads it, so spawning the send dropped the anchor-convergence gate
        // from 3 runs in 5 to 1 in 6 and the user-level rehearsal from 10 in 10 to 6 in 8. The
        // stall is real and now *named* by `NodeEvent::Stalled`; removing it needs the ordering
        // made explicit, not the wait deleted.
        let mut mirrored_refused = 0usize;
        let mut mirrored_why = String::new();
        for wire in net.board_records(channel_id, epoch) {
            if let Err(e) = client.put(&wire).await {
                mirrored_refused += 1;
                if mirrored_why.is_empty() {
                    mirrored_why = e.to_string();
                }
            }
        }
        client.finish();
        outcomes.push((
            "another member's record we vouch for",
            (mirrored_refused > 0)
                .then(|| format!("{mirrored_refused} refused, first: {mirrored_why}")),
        ));
        // **Keyed per board, not per room.** A node publishes the same record to several boards and
        // they answer differently — an anchor that has not been vouched this author says "not a
        // channel member" while the node's own board says "policy" — so a memo keyed only by room
        // and record kind alternates between the two reasons and reports on every publish round,
        // which is the spam it was added to stop. It also matters to whoever reads the line: "some
        // board refused this" is not actionable and "that board refused this" is.
        let board = crate::node::network::short_id(conn.peer_id());
        for (kind, why) in outcomes {
            let what = format!("{kind} (board {board})");
            let key = (*channel_id, what.clone());
            match why {
                Some(why) => {
                    if self.last_publish_refusal.get(&key) == Some(&why) {
                        continue;
                    }
                    // Our own records, refused because nobody has vouched for us yet: the
                    // ordinary opening move of a join, which cures when a member mirrors us
                    // onward. Say nothing until it has had time to cure.
                    let curable = matches!(kind, "our member bundle" | "our address")
                        && why.contains("author is not a channel member");
                    if curable {
                        let now = self.now();
                        let first = *self
                            .publish_refusal_first_seen
                            .entry(key.clone())
                            .or_insert(now);
                        if now.saturating_sub(first) < PUBLISH_REFUSAL_GRACE {
                            continue;
                        }
                    }
                    self.publish_refusal_first_seen.remove(&key);
                    self.last_publish_refusal.insert(key, why.clone());
                    let _ = self.event_tx.send(NodeEvent::PublishRefused {
                        channel_id: *channel_id,
                        what,
                        why,
                    });
                }
                // It went on this time, so the next refusal is news again.
                None => {
                    self.last_publish_refusal.remove(&key);
                    self.publish_refusal_first_seen.remove(&key);
                }
            }
        }
    }

    /// The store anchored logs and channels live in: the profile's, or the headless
    /// node's own.
    fn log_store(&self) -> Option<Arc<crate::node::store::Store>> {
        self.profile
            .as_ref()
            .map(Profile::store_handle)
            .or_else(|| self.anchor_store.as_ref().map(Arc::clone))
    }

    /// The sealing key for the anchor's copy of `channel_id`: derived from whichever
    /// identity this node networks as.
    fn anchor_sek(&self, channel_id: &Digest32) -> Option<crate::atrest::sek::Sek> {
        if let Some(signer) = self.headless.as_ref() {
            return crate::node::anchor::anchor_sek(&**signer, channel_id).ok();
        }
        let profile = self.profile.as_ref()?;
        let signer = profile.signer().ok()?;
        crate::node::anchor::anchor_sek(signer, channel_id).ok()
    }

    /// Start keeping a log for `channel_id` if this node anchors logs, its board holds
    /// the genesis, and it is neither a member of the channel nor already keeping it.
    /// Reopens a copy the store already has (a restart), else creates one.
    async fn adopt_anchored(&mut self, channel_id: &Digest32) {
        if !self.anchor_logs
            || self.channels.contains_key(channel_id)
            || self.anchored.contains_key(channel_id)
        {
            return;
        }
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        let Some(genesis) = net.board_genesis(channel_id) else {
            return;
        };
        let (Some(store), Some(sek)) = (self.log_store(), self.anchor_sek(channel_id)) else {
            return;
        };
        let now = self.now();
        let opened =
            crate::node::anchor::AnchorState::open(&store, sek, channel_id, now).or_else(|_| {
                let sek = self
                    .anchor_sek(channel_id)
                    .ok_or(Error::Profile("no anchor key"))?;
                crate::node::anchor::AnchorState::create(&store, sek, &genesis, now)
            });
        if let Ok(state) = opened {
            self.anchored
                .insert(*channel_id, Arc::new(tokio::sync::Mutex::new(state)));
            self.refresh_anchored_authors(channel_id).await;
            self.refresh_network_view().await;
        }
    }

    /// Adopt every channel the board holds a genesis for (the tick's pass).
    async fn adopt_anchored_from_board(&mut self) {
        if !self.anchor_logs {
            return;
        }
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        let ids: Vec<Digest32> = net
            .anchored_channels()
            .into_iter()
            .map(|a| a.channel_id)
            .filter(|cid| !self.channels.contains_key(cid) && !self.anchored.contains_key(cid))
            .collect();
        for cid in ids {
            self.adopt_anchored(&cid).await;
        }
    }

    /// Admit into an anchored channel every author its board knows (the creator, and
    /// everyone a member vouched for), so their entries verify.
    async fn refresh_anchored_authors(&mut self, channel_id: &Digest32) {
        let (Some(net), Some(state), Some(store)) = (
            self.net.as_ref().map(Arc::clone),
            self.anchored.get(channel_id).map(Arc::clone),
            self.log_store(),
        ) else {
            return;
        };
        let keys = net.board_member_keys(channel_id, 0);
        let added = state.lock().await.admit_authors(&store, keys).unwrap_or(0);
        if added > 0 {
            self.refresh_network_view().await;
        }
    }

    /// After a restart, reopen every anchored channel the store holds and put its
    /// genesis back on the board, so members find the room where they left it.
    fn reopen_anchored(&mut self) -> crate::error::Result<()> {
        if !self.anchor_logs {
            return Ok(());
        }
        let (Some(store), Some(net)) = (self.log_store(), self.net.as_ref().map(Arc::clone)) else {
            return Ok(());
        };
        let now = self.now();
        for cid in store.anchored_channels()? {
            let Some(sek) = self.anchor_sek(&cid) else {
                continue;
            };
            if let Ok(state) = crate::node::anchor::AnchorState::open(&store, sek, &cid, now) {
                let _ = net.publish_local(&state.genesis().to_wire());
                self.anchored
                    .insert(cid, Arc::new(tokio::sync::Mutex::new(state)));
            }
        }
        Ok(())
    }

    /// Dial any configured or learned anchor this node is not connected to. Runs on
    /// the tick, throttled: an anchor that restarted, or a link that dropped, is
    /// re-established without anyone noticing.
    fn redial_anchors_if_due(&mut self) {
        let now = self.now();
        if now < self.redial_anchors_at {
            return;
        }
        self.redial_anchors_at = now + ANCHOR_REDIAL_SECS;
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        let known: Vec<BootstrapNode> = self.anchors.nodes().to_vec();
        for anchor in known {
            if anchor.id == net.local_id() || net.manager().existing(&anchor.id).is_some() {
                continue;
            }
            let net = Arc::clone(&net);
            let tx = self.net_tx.clone();
            tokio::spawn(async move {
                match net.manager().connect(anchor.id, &anchor.endpoints).await {
                    Ok(conn) => {
                        let _ = tx.send(NetEvent::AnchorConnected { conn }).await;
                    }
                    Err(e) => {
                        let _ = tx
                            .send(NetEvent::ReachFailed {
                                peer: anchor.id,
                                why: e.to_string(),
                            })
                            .await;
                    }
                }
            });
        }
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
                    let _ = add.merge_endpoints(more);
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
                match net.manager().connect(id, &endpoints).await {
                    Ok(conn) => {
                        let _ = tx.send(NetEvent::AnchorConnected { conn }).await;
                    }
                    Err(e) => {
                        let _ = tx
                            .send(NetEvent::ReachFailed {
                                peer: id,
                                why: e.to_string(),
                            })
                            .await;
                    }
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
        let ring = ring.lock().await;
        let _ = net.publish_local(&channel.genesis().to_wire());
        let Some(admission) = channel.own_admission().cloned() else {
            return;
        };
        if let Ok((address, bundle)) =
            net.own_records(signer, channel_id, channel.epoch(), &ring, seq, admission)
        {
            let _ = net.publish_local(&address.to_wire());
            let _ = net.publish_local(&bundle.to_wire());
        }
    }

    /// Republish the membership snapshot and peer policy the served board and the
    /// accept path read (see `node::network`). Called whenever channels change.
    /// Rebuild the network's view of who may do what.
    ///
    /// **Never waits for a room's lock, and that is the point.** This took every channel's lock in
    /// turn, and a sync session holds a room's lock across its network waits — up to
    /// `SYNC_FRAME_TIMEOUT` — so a peer that went quiet mid-exchange stopped this function, and with
    /// it the one task allowed to write channel state. Measured on an anchor, which is the node this
    /// hurts most because it is the hop a message takes when two members are never online together:
    ///
    /// ```text
    /// vox node: took 1 entry for room 4yxukqstptuq
    /// vox node: BUSY 20033ms — filing a sync that finished — nobody could be answered
    /// ```
    ///
    /// Twenty seconds and change, which is that frame timeout to the millisecond. During it the
    /// anchor could not act on the very entries it had just taken, so a message that had reached the
    /// anchor never reached the other member and the room looked quiet. This is a **view**: it is
    /// rebuilt on every tick and on every piece of network work, so abandoning one attempt costs a
    /// tick and nothing else.
    ///
    /// Abandoned whole rather than in part. A policy assembled from the rooms that happened to be
    /// free would be missing members, and this policy is what authorizes streams — a partial one
    /// would refuse a peer that is perfectly entitled. The previous policy is complete and at most
    /// one tick stale, which is the safe side of that trade.
    async fn refresh_network_view(&self) {
        let Some(net) = self.net.as_ref() else { return };
        let mut policy = PeerPolicy::new();
        for (cid, shared) in &self.channels {
            let Ok(ch) = shared.try_lock() else {
                return; // busy: a session holds it. Keep the policy we have; the tick retries.
            };
            let members: BTreeMap<Digest32, CompositePublicKey> = ch
                .author_keys()
                .into_iter()
                .map(|k| (k.fingerprint(), k))
                .collect();
            policy.add_members(members.keys().copied());
            net.membership().set_channel(*cid, ch.epoch(), members);
        }
        // An anchored channel's known authors are its members as far as this node's
        // board and streams are concerned (M15.2b): their records verify, and they may
        // open what a member may.
        for (cid, state) in &self.anchored {
            let Ok(st) = state.try_lock() else {
                return; // same: an anchored room mid-sync must not stop the actor.
            };
            let members: BTreeMap<Digest32, CompositePublicKey> = st
                .author_keys()
                .into_iter()
                .map(|k| (k.fingerprint(), k))
                .collect();
            policy.add_members(members.keys().copied());
            net.membership().set_channel(*cid, st.epoch(), members);
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
            NetEvent::JoinRequest {
                peer,
                channel_id,
                epoch,
                send,
                recv,
            } => {
                self.answer_inbound_join(peer, channel_id, epoch, send, recv)
                    .await;
            }
            NetEvent::JoinAnswered {
                peer,
                channel_id,
                outcome,
            } => {
                self.apply_join_outcome(peer, channel_id, *outcome).await;
            }
            NetEvent::JoinAdmit {
                channel_id,
                identity,
                ack,
            } => {
                // The join proved this identity; admit it as an author so its entries — and its
                // records on this node's board — are accepted. Reading still needs consent.
                let now = self.now();
                if let (Some(profile), Some(shared)) = (
                    self.profile.as_ref(),
                    self.channels.get(&channel_id).map(Arc::clone),
                ) {
                    let _ = shared
                        .lock()
                        .await
                        .admit_author(profile.store(), &identity, now);
                }
                // Answered whatever happened: a joiner waiting on this must not be left holding a
                // stream because the room closed or this node has no profile. It will find out from
                // the join's own outcome, which is the right place for it to learn.
                let _ = ack.send(());
            }
            NetEvent::BoardGrew { channel_id } => {
                // Pass it on, which for a member means its anchors. A node that is not a member of
                // this room falls out of `publish_channel_to_anchor` on its missing admission, so
                // an anchor receiving a mirror does not mirror it onward and this cannot ring
                // around a ring of anchors.
                if self.channels.contains_key(&channel_id) {
                    self.publish_channel_to_anchors(&channel_id).await;
                }
            }
            NetEvent::SyncRequest {
                conn,
                peer,
                channel_id,
                epoch,
                send,
                recv,
            } => {
                let _ = &conn;
                self.run_sync_session(peer, channel_id, epoch, send, recv)
                    .await;
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
            NetEvent::ReachFailed { peer, why } => {
                let _ = self.event_tx.send(NodeEvent::PeerUnreachable { peer, why });
            }
            NetEvent::UpgradeFailed { peer, reason } => {
                let _ = self.event_tx.send(NodeEvent::StillRelayed { peer, reason });
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
                self.syncing.remove(&channel_id);
                self.refresh_network_view().await;
                if let Ok(o) = outcome {
                    // **Event, not interval.** Propagation was event-driven in one direction only:
                    // an append here pushed at once, but a sync that *brought entries in* marked
                    // nothing, so this node sat on them until its own `SYNC_INTERVAL_SECS`. For an
                    // anchor that is the entire job undone — it holds the log for whoever is away and
                    // then forwards it a half-minute late. End to end the worst case was 30s to reach
                    // the anchor plus 30s for the next member to pull.
                    //
                    // Self-limiting rather than a storm: reconciliation is idempotent, so the peer
                    // this came from applies nothing on the way back and marks nothing onward.
                    // The actor-side half of what the slot just did: a session may have admitted
                    // authors and mirrored records onto this node's board, and both change who may
                    // reach whom and what the anchors should hold. `learn_members` used to do this
                    // inline, which is how a round trip ended up on the single writer.
                    //
                    // **Only when the session actually brought something in**, which is the guard
                    // the original had (`if learned > 0`, `if gained > 0`) and I dropped when moving
                    // this out. Without it the actor did a publish round trip after *every* sync,
                    // and syncs are frequent: measured, that turned a 0-1s crossing into 20s in
                    // seven runs of ten while removing the losses. Losses gone is the right trade;
                    // paying a publish per sync for it is not.
                    if o.applied > 0 {
                        self.note_local_append(&channel_id);
                        self.refresh_reachers().await;
                        self.publish_channel_to_anchors(&channel_id).await;
                    }
                    if o.rendered > 0 || o.governance > 0 {
                        let _ = self.event_tx.send(NodeEvent::Synced {
                            channel_id,
                            applied: o.applied as u64,
                            rendered: o.rendered as u64,
                        });
                    }
                }
            }
            NetEvent::Stream { conn, inbound } => {
                // Held for the whole handler: the connection must outlive the streams
                // opened on it, or the peer sees it close mid-exchange.
                let _connection = conn;
                match inbound {
                    Inbound::Join { .. } => {
                        // Unreachable: the stream loop turns these into
                        // `NetEvent::JoinRequest` once the request is read.
                    }
                    Inbound::Pairwise { peer, recv, .. } => {
                        self.take_inbound_skdm(peer, recv).await;
                    }
                    Inbound::Sync { .. } => {
                        // Unreachable: the stream loop converts these into
                        // `NetEvent::SyncRequest` once the preamble is read.
                    }
                    Inbound::Punch {
                        peer,
                        coordinator,
                        send,
                        recv,
                    } => {
                        self.answer_punch(peer, coordinator, send, recv);
                    }
                    Inbound::Tunnel { peer, send, recv } => {
                        // The snapshot is taken here (only the actor reads channel
                        // state) and the tunnel runs on its own task: it lives as long
                        // as the TCP connection it carries, which may be hours.
                        let snapshot = self.host_snapshot().await;
                        // The host is told who reached what, because the carried
                        // service only ever sees loopback (ADR-017 decision 6).
                        let events = self.event_tx.clone();
                        tokio::spawn(async move {
                            let _ = crate::node::tunnel::serve_reporting(
                                peer,
                                send,
                                recv,
                                snapshot,
                                Some(events),
                            )
                            .await;
                        });
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
    /// Answer a join whose request has **already been read** off the actor's task.
    /// Answer a peer's join: **decide here, wait in a slot.**
    ///
    /// Everything above the spawn is a decision this node can make on its own — is this room
    /// answerable at this epoch, is the identity unlocked, is there a free slot — and none of it
    /// waits on the joiner. Everything that does wait on the joiner runs on its own task and
    /// comes back as [`NetEvent::JoinAnswered`], so the state changes still happen on the actor,
    /// in order, while the waiting does not.
    ///
    /// The exchange used to be awaited right here. A stranger holding only the address and the
    /// passphrase — which is all joining has ever required — could therefore hold the actor for a
    /// CPace handshake, its own proof-of-work solve, and three frame waits it controlled the
    /// length of. Nothing else in the node ran meanwhile: not a message, not a sync, not another
    /// join. On an anchor that is the whole failure, because an anchor's only job is to be
    /// reachable.
    ///
    /// See [`JOINS_IN_FLIGHT`] for the cap and why a join past it is refused rather than queued.
    async fn answer_inbound_join(
        &mut self,
        peer: Digest32,
        channel_id: Digest32,
        epoch: u64,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) {
        let answerable = match self.channels.get(&channel_id) {
            Some(shared) => {
                let c = shared.lock().await;
                c.can_answer_join() && c.epoch() == epoch
            }
            None => false,
        };
        if !answerable {
            Self::spawn_refuse_join(send);
            return;
        }
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            Self::spawn_refuse_join(send);
            return;
        };
        let Some(ring) = self.prekeys.as_ref().map(Arc::clone) else {
            Self::spawn_refuse_join(send);
            return;
        };
        let Some(profile) = self.profile.as_ref() else {
            Self::spawn_refuse_join(send);
            return;
        };
        // An owned handle, not a borrow: the exchange outlives this call. `Profile::signer_arc`
        // documents what that costs and how locking still zeroizes.
        let Ok(signer) = profile.signer_arc() else {
            Self::spawn_refuse_join(send);
            return;
        };
        let store = profile.store_handle();
        let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
            Self::spawn_refuse_join(send);
            return;
        };
        // **Everything the exchange needs is taken out, and the guard dropped, before it
        // runs.** `answer_join` wanted the channel for exactly one thing — its join
        // passphrase — and holding the guard across the exchange held the whole room for
        // the duration of a CPace handshake *and* the joiner's Equihash solve. Every
        // other operation on that room queued behind it: sending a message, syncing,
        // consenting to somebody. One person joining stalled everyone already there.
        let (mut ctx, passphrase) = {
            let channel = shared.lock().await;
            let Ok(ctx) = channel.join_context() else {
                Self::spawn_refuse_join(send);
                return;
            };
            let Ok(passphrase) = channel.join_passphrase() else {
                Self::spawn_refuse_join(send);
                return;
            };
            // Copied because it outlives the guard, and zeroized on drop like every
            // other passphrase this node holds.
            (ctx, zeroize::Zeroizing::new(passphrase.to_vec()))
        };
        if let Some(pow) = self.pow_params {
            ctx.pow_params = pow;
        }
        let Ok(slot) = Arc::clone(&self.join_slots).try_acquire_owned() else {
            // Past the cap: **refused, not queued**, and said out loud. A silent drop here
            // would leave the joiner reading a stream that never answers, which is the
            // failure shape this whole change exists to remove.
            let _ = self.event_tx.send(NodeEvent::JoinFailed {
                reason: format!(
                    "refused {}: already answering {JOINS_IN_FLIGHT} joins — it should retry",
                    crate::node::network::short_id(peer)
                ),
            });
            Self::spawn_refuse_join(send);
            return;
        };
        // Including the slot just taken, so the first joiner sees a load of 1. This is what
        // `Difficulty::adapted_for_load` is for, and it was passed a literal `0` until now — so the
        // anti-flood knob ADR-005 specifies, and ADR-016 describes as adapting "against the
        // responder's live queue", had never once adapted.
        //
        // This costs an ordinary joiner nothing: `Difficulty::ADAPT_THRESHOLD` is 4, so a load of
        // 1–3 adds zero bits and one person joining a quiet room does exactly the work it did
        // before. Past four it adds a bit per doubling of the queue, capped at `Difficulty::MAX`.
        let pending_joins =
            u32::try_from(JOINS_IN_FLIGHT.saturating_sub(self.join_slots.available_permits()))
                .unwrap_or(u32::MAX);
        let tx = self.net_tx.clone();
        self.reap_join_tasks();
        let admit_tx = self.net_tx.clone();
        self.join_tasks.spawn(async move {
            let _slot = slot;
            let outcome = net
                .answer_join(
                    peer,
                    send,
                    recv,
                    ctx,
                    &passphrase,
                    &*signer,
                    &store,
                    &ring,
                    pending_joins,
                    // **The admission lands before the joiner is told it is in.** Awaited here, on
                    // this task, so the actor is never the thing waiting — which is the whole point
                    // of the slot. See `NetEvent::JoinAdmit`.
                    |identity| async move {
                        let (ack, wait) = tokio::sync::oneshot::channel();
                        if admit_tx
                            .send(NetEvent::JoinAdmit {
                                channel_id,
                                identity: Box::new(identity),
                                ack,
                            })
                            .await
                            .is_ok()
                        {
                            // A dropped sender resolves this too, so a shutting-down actor cannot
                            // strand a joiner mid-exchange.
                            let _ = wait.await;
                        }
                    },
                )
                .await
                // **Never dropped.** A responder whose exchange failed said nothing, so the
                // joiner's `Unreachable` was the only trace of it and it names the wrong side.
                // Formatted here because this is where the reason exists.
                .map_err(|e| format!("answering {}: {e}", crate::node::network::short_id(peer)));
            let _ = tx
                .send(NetEvent::JoinAnswered {
                    peer,
                    channel_id,
                    outcome: Box::new(outcome),
                })
                .await;
        });
    }

    /// Tell a joiner "no" without waiting for it to hear that.
    ///
    /// A refusal is one small frame, which is *almost* always writable at once — and "almost" is
    /// the problem. The stream belongs to the peer, so if it opens one and never reads, QUIC flow
    /// control stalls the write, and awaiting that on the actor hands a stranger the same stall
    /// this change removes from the exchange itself. Nothing here needs the result.
    fn spawn_refuse_join(send: quinn::SendStream) {
        tokio::spawn(crate::node::joinstream::refuse_join(send));
    }

    /// Drop the bookkeeping for join tasks that have already finished.
    ///
    /// [`Node::join_tasks`] exists to be aborted on lock, not to collect results, and a
    /// `JoinSet` holds an entry per task until something reaps it. Called on the way in to each
    /// spawn, which is the only place the set grows.
    fn reap_join_tasks(&mut self) {
        while self.join_tasks.try_join_next().is_some() {}
    }

    /// Apply what a finished join exchange produced. Runs **on the actor**, which is the point:
    /// the waiting happened elsewhere, the state changes happen here, in order.
    async fn apply_join_outcome(
        &mut self,
        peer: Digest32,
        channel_id: Digest32,
        outcome: std::result::Result<crate::node::joinstream::JoinOutcome, String>,
    ) {
        let outcome = match outcome {
            Ok(o) => o,
            Err(reason) => {
                let _ = self.event_tx.send(NodeEvent::JoinFailed { reason });
                return;
            }
        };
        // The room can go away while an exchange runs — it is closed, or the node locked and
        // the task was aborted late. Filing a session against a room this node no longer holds
        // would keep ratchet material for nothing and announce a join into a room that is not
        // there, so say what happened and drop it.
        let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
            let _ = self.event_tx.send(NodeEvent::JoinFailed {
                reason: format!(
                    "answered {} but the room closed before it could be filed",
                    crate::node::network::short_id(peer)
                ),
            });
            return;
        };
        // The admission already happened, on `NetEvent::JoinAdmit`, before this joiner was sent
        // its acceptance — that ordering is what lets its own records onto this node's board at
        // all. What is left is the part that touches the network, deliberately after the joiner is
        // in so it never waits on our round trips to somebody else.
        let _ = &shared;
        {
            self.refresh_network_view().await;
            // The newcomer's records reach the anchors through this node: it
            // witnessed the join, so it vouches (ADR-016 M15.2a). The joiner has
            // published to this board by the time its own join returns; whatever is
            // there now goes up, and what arrives later goes with the next mirror.
            self.publish_channel_to_anchors(&channel_id).await;
        }
        self.sessions.insert((channel_id, peer), outcome.session);
        if let Some(net) = self.net.as_ref() {
            net.policy().forget_joiner(&peer);
        }
        let _ = self
            .event_tx
            .send(NodeEvent::PeerJoined { channel_id, peer });
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
        if crate::node::net::path_class(net.manager().endpoint(), &conn)
            == crate::node::net::PathClass::Relayed
        {
            let tx = self.net_tx.clone();
            let endpoints = endpoints.clone();
            self.last_upgrade.insert(peer, self.now());
            tokio::spawn(async move {
                match net.upgrade(peer, &endpoints).await {
                    Ok(better) => {
                        let _ = tx.send(NetEvent::BetterPath { conn: better }).await;
                    }
                    // Only a ladder that tried every rung and got nowhere means "still relayed".
                    // `upgrade` also returns `Err` for "already direct" and "nothing to upgrade",
                    // which were a silently-fine `None` before this change; reporting those as
                    // `StillRelayed` would say something false about a peer that is not relayed.
                    Err(crate::error::Error::LadderExhausted(reason)) => {
                        let _ = tx.send(NetEvent::UpgradeFailed { peer, reason }).await;
                    }
                    Err(_) => {}
                }
            });
        }
        Ok(conn)
    }

    /// Retry a direct path for every peer still reached over a relay.
    ///
    /// The attempt at dial time happens at the worst possible moment: neither side has
    /// learned the other's addresses, and whatever blocked a direct path is at its most
    /// likely. Retrying on a schedule is what turns a relayed path into a direct one when
    /// the network changes underneath it — a NAT mapping expiring, a laptop leaving a
    /// captive portal — without which a pair that starts relayed stays relayed for the life
    /// of the connection, paying a third party's bandwidth and an extra hop for ever.
    ///
    /// Endpoints come from each channel's board, so a peer is retried once per channel it
    /// shares with this node, and the timestamp is written **before** the attempt so a slow
    /// one cannot stack.
    async fn retry_upgrades_if_due(&mut self) {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        let now = self.now();
        let endpoint = Arc::clone(net.manager().endpoint());
        // Collected first: the borrow of `self.channels` cannot outlive the mutation of
        // `self.last_upgrade` below.
        let mut due: Vec<(Digest32, crate::nat::multiaddr::EndpointList)> = Vec::new();
        for (cid, shared) in &self.channels {
            let authors: Vec<Digest32> = {
                let ch = shared.lock().await;
                ch.author_fingerprints()
            };
            for peer in authors {
                let Some(conn) = net.manager().existing(&peer) else {
                    continue;
                };
                if crate::node::net::path_class(&endpoint, &conn)
                    != crate::node::net::PathClass::Relayed
                {
                    continue;
                }
                let last = self.last_upgrade.get(&peer).copied().unwrap_or(0);
                if now.saturating_sub(last) < UPGRADE_RETRY.as_secs() {
                    continue;
                }
                due.push((peer, net.board_endpoints(cid, &peer)));
            }
        }
        if !due.is_empty() {
            // The reflexive address is the punch's main input and it is cached. A retry that
            // reuses a stale one asks the same failed question again.
            net.refresh_observed();
        }
        for (peer, endpoints) in due {
            self.last_upgrade.insert(peer, now);
            let net = Arc::clone(&net);
            let tx = self.net_tx.clone();
            tokio::spawn(async move {
                match net.upgrade(peer, &endpoints).await {
                    Ok(better) => {
                        let _ = tx.send(NetEvent::BetterPath { conn: better }).await;
                    }
                    // Only a ladder that tried every rung and got nowhere means "still relayed".
                    // `upgrade` also returns `Err` for "already direct" and "nothing to upgrade",
                    // which were a silently-fine `None` before this change; reporting those as
                    // `StillRelayed` would say something false about a peer that is not relayed.
                    Err(crate::error::Error::LadderExhausted(reason)) => {
                        let _ = tx.send(NetEvent::UpgradeFailed { peer, reason }).await;
                    }
                    Err(_) => {}
                }
            });
        }
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
        let _ = self.event_tx.send(NodeEvent::InviteLink {
            channel_id: *channel_id,
            url: link.to_url(),
        });
        Outcome::Done
    }

    /// How long a join keeps looking for a board before refusing.
    ///
    /// Shorter than `up::HOST_PATIENCE` on purpose: `vox up` waits on a *service host* who
    /// may be a person at another desk, while this waits on infrastructure that is either
    /// coming up now or is not there.
    const BOARD_PATIENCE: Duration = Duration::from_secs(30);

    /// Interval between rounds. A board that is ready costs a joiner one dial.
    const BOARD_RETRY: Duration = Duration::from_millis(250);

    /// A connection to something that can serve this channel's board, trying every route
    /// this node has and retrying until [`Self::BOARD_PATIENCE`] runs out.
    ///
    /// **A room address is a magnet link, and a magnet's trackers are hints, not the only
    /// route.** This used to try only the anchors embedded in the link, once each, in order,
    /// and refuse — so one hint that was stale, or merely not listening *yet*, ended the
    /// join. `invite()` builds that list as [the channel's anchors, the configured set, this
    /// node last], so a host whose only anchor is itself hands out a link naming only itself;
    /// a joiner who arrives in the second before that host is accepting gets
    /// `Failed(Unreachable)` and is told nothing useful. That is what made
    /// `node_m15_session_from_bundle_gate` fail about two runs in five, on clean `main`,
    /// long before either of the branches in flight — and it failed in under three seconds
    /// against a 35-second happy path, which is how a deterministic refusal announces itself.
    ///
    /// Two things change. **Every route is tried, not just the link's:** the link's hints
    /// first, because whoever wrote the link knows where that room lives; then this node's
    /// configured anchors, which are the routes its operator chose; then any anchor it is
    /// **already connected to** from an earlier join, which costs nothing to ask. Duplicates
    /// are dialled once. **And it retries**, because "not yet" and "not there" are different
    /// answers and only a deadline can tell them apart.
    ///
    /// The third tier carries no endpoints, deliberately: this node does not keep an address
    /// book for anchors it met once, and inventing one here would be a second feature. An
    /// empty endpoint list is exactly right for a peer that is already connected, because
    /// `NodeNet::connect` returns the live connection before it looks at addresses — and for
    /// one that is not, it fails, which is the honest answer.
    ///
    /// `None` means no route answered for the whole window, which is a refusal a person
    /// should see: the room may genuinely have nobody serving it.
    async fn reach_a_board(
        &mut self,
        parsed: &crate::node::link::InviteLink,
    ) -> Option<Arc<VoxConnection>> {
        let me = self.net.as_ref()?.local_id();
        // Ordered, de-duplicated, best hint first. Collected up front so the set does not
        // shift under the retry loop.
        let mut routes: Vec<(Digest32, crate::nat::multiaddr::EndpointList)> = Vec::new();
        let mut seen: std::collections::BTreeSet<Digest32> = [me].into_iter().collect();
        for a in parsed
            .anchors
            .iter()
            .chain(self.anchors.nodes())
            .filter(|a| seen.insert(a.id))
        {
            routes.push((a.id, a.endpoints.clone()));
        }
        // Anchors from earlier joins that this node still holds a connection to.
        let live: std::collections::BTreeSet<Digest32> =
            self.net.as_ref()?.manager().peers().into_iter().collect();
        let empty = crate::nat::multiaddr::EndpointList::new(Vec::new()).ok()?;
        let learned: Vec<Digest32> = self
            .anchor_ids
            .iter()
            .copied()
            .filter(|id| live.contains(id) && seen.insert(*id))
            .collect();
        for id in learned {
            routes.push((id, empty.clone()));
        }
        if routes.is_empty() {
            return None;
        }

        let deadline = tokio::time::Instant::now() + Self::BOARD_PATIENCE;
        loop {
            for (id, endpoints) in &routes.clone() {
                if let Ok(conn) = self.dial(*id, endpoints).await {
                    self.anchor_ids.insert(*id);
                    self.refresh_network_view().await;
                    return Some(conn);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Self::BOARD_RETRY).await;
        }
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
        let me = net.local_id();
        let Some(board) = self.reach_a_board(&parsed).await else {
            return Outcome::Failed(Fault::Unreachable);
        };
        self.refresh_network_view().await;
        // The board tells us what the channel is and who is in it.
        let mut set = match net.fetch_channel(&board, &parsed.channel_id, 0).await {
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
        // **Every member the board knows is a candidate, not just the first one.**
        //
        // A link that pins a responder names exactly one, and that is the owner's choice.
        // A link that pins none used to take `set.members.first()` and stop there, so one
        // member being offline failed a join that any other member in the room could have
        // served — and the room looked broken to the person joining it, with nothing to
        // suggest that trying again later, or from a different link, would behave any
        // differently.
        //
        // The walk is bounded. Each attempt runs the ADR-005 join, and that carries a proof
        // of work, so an unbounded list would let a room with many members turn one join
        // into minutes of hashing. `MAX_JOIN_RESPONDERS` is the bound, and an attempt is
        // only retried when the fault says *this responder* could not serve it.
        // **Sorted, because the board's order is not an order.** The members come from a
        // `HashMap`'s `values()`, so which one a join reached was effectively random — and with
        // no fallback, a room with one offline member failed joins at a rate nobody could
        // reproduce and a retry could "fix" by chance. Sorting by fingerprint makes the walk the
        // same every time, so a join that fails fails for a reason.
        //
        // **And a pinned responder is a preference, not the only candidate.** That fallback was
        // added for exactly the reason above and then applied to only one of the two branches: a
        // link naming a responder still produced a list of length one, so an invite whose author
        // had since gone offline took the whole room down for the joiner while the anchor sat
        // there reachable. Measured, with the node naming it rather than a timeout implying it:
        // `bob's join outcome: Failed(Unreachable)` beside
        // `Stalled { what: "joining a room", millis: 10005 }` — the whole dial budget spent on
        // the one peer the link happened to name, and no second attempt.
        //
        // The pin is still tried first: whoever minted the link knows who is expected to answer.
        //
        // **Every member the board knows, not only the ones it has an address for.** The list was
        // built from `set.members`, which is the *address records* — so a member the board knew by
        // its **bundle**, or the **creator named by the genesis**, was not a candidate at all. The
        // patience loop below exists precisely to wait for an address record that has not arrived
        // yet, and a member in that state could never reach it: it was filtered out one step
        // earlier, by the very condition the loop was written to tolerate.
        //
        // That is how a room with a live host became unjoinable. Measured, with the joiner naming
        // what it tried: one candidate, both its paths dead, and the host — online, on loopback,
        // the genesis creator — never in the list, because its address record had been refused on
        // the anchor while its identity was never in question. The genesis is the one record whose
        // author cannot be in doubt: its hash *is* the channelID, and it names the creator.
        //
        // **Ordered so that a member we can reach is tried before one we would have to wait for.**
        // Mixing them without that gives a 20s `JOIN_ADDRESS_PATIENCE` stall in front of a peer
        // that was dialable immediately, which is the cost this widening would otherwise add.
        let candidates: Vec<crate::hash::Digest32> = {
            use std::collections::BTreeSet;
            let with_address: BTreeSet<crate::hash::Digest32> = set
                .members
                .iter()
                .filter(|r| !r.endpoints.is_empty())
                .map(|r| r.author_id)
                .collect();
            let mut known: BTreeSet<crate::hash::Digest32> =
                set.members.iter().map(|r| r.author_id).collect();
            known.extend(set.bundles.iter().map(|b| b.author_id));
            if let Some(g) = set.genesis.as_ref() {
                known.insert(g.body.creator_pubkey.fingerprint());
            }
            // Never ourselves: a node does not join a room by asking itself to answer.
            known.remove(&me);
            let mut reachable: Vec<crate::hash::Digest32> =
                known.intersection(&with_address).copied().collect();
            let mut awaited: Vec<crate::hash::Digest32> =
                known.difference(&with_address).copied().collect();
            reachable.sort_unstable();
            awaited.sort_unstable();
            let mut ordered = Vec::with_capacity(known.len() + 1);
            if let Some(r) = parsed.responder {
                ordered.push(r);
                reachable.retain(|m| *m != r);
                awaited.retain(|m| *m != r);
            }
            ordered.extend(reachable);
            ordered.extend(awaited);
            if ordered.is_empty() {
                return Outcome::Failed(Fault::BadLink);
            }
            ordered.truncate(MAX_JOIN_RESPONDERS);
            ordered
        };

        // The pre-join record does not depend on which member answers, so it is built once
        // and announced to the board once, before any of them is reached (ADR-016): on the
        // anchor it is what lets the anchor coordinate a punch or carry a circuit for us,
        // and on the responder it is what authorizes the join stream.
        let prejoin_wire = {
            let Some(profile) = self.profile.as_ref() else {
                return Outcome::Failed(Fault::NoIdentity);
            };
            let Ok(signer) = profile.signer() else {
                return Outcome::Failed(Fault::Locked);
            };
            let ring = match self.prekeys.as_ref() {
                Some(r) => r.lock().await,
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

        let mut why: Vec<String> = Vec::new();

        let mut last_fault = Fault::Unreachable;
        let mut joined_outcome = None;
        for responder in candidates {
            let mut responder_endpoints = set
                .members
                .iter()
                .find(|r| r.author_id == responder)
                .map(|r| r.endpoints.clone())
                .unwrap_or_default();
            // **An address we do not know yet is not an address that does not exist.**
            //
            // `unwrap_or_default()` above yields an *empty* endpoint list when the responder
            // has no address record on this board, and dialling an empty list fails at once —
            // which this returned to the caller as `Fault::Unreachable`, in under three
            // seconds, for a member who was online and perfectly reachable. It made
            // `node_m15_session_from_bundle_gate` fail about two runs in five on clean `main`.
            //
            // Measured, not deduced. On a failing run the board held `members=1, bundles=2`:
            // the responder's *bundle* record had arrived but its *address* record had not.
            // The two propagate separately, so a joiner who arrives in that window sees a
            // member it has a key for and no way to reach — and concluded the member was
            // unreachable.
            //
            // A deadline is what separates "not yet" from "not there", which is the same
            // distinction `up::reach_host_with_patience` draws for a service host, and the
            // same one every peer-to-peer client draws when a peer list is incomplete: keep
            // asking the source, do not conclude absence from silence.
            if responder_endpoints.is_empty() && board.peer_id() != responder {
                let deadline = tokio::time::Instant::now() + JOIN_ADDRESS_PATIENCE;
                while tokio::time::Instant::now() < deadline {
                    tokio::time::sleep(JOIN_ADDRESS_POLL).await;
                    let Ok(fresh) = net.fetch_channel(&board, &parsed.channel_id, 0).await else {
                        continue;
                    };
                    let found = fresh
                        .members
                        .iter()
                        .find(|r| r.author_id == responder)
                        .map(|r| r.endpoints.clone())
                        .unwrap_or_default();
                    if !found.is_empty() {
                        // Take the fresher board too: it is a superset by construction, and
                        // the records that arrived alongside the address are ones we are
                        // about to want.
                        responder_endpoints = found;
                        set = fresh;
                        break;
                    }
                }
            }

            let conn = if board.peer_id() == responder {
                Arc::clone(&board)
            } else {
                match self.dial(responder, &responder_endpoints).await {
                    Ok(c) => {
                        if let Err(e) = announce(&c, &prejoin_wire).await {
                            last_fault = fault_of(&e);
                            if !worth_another_responder(last_fault) {
                                return Outcome::Failed(last_fault);
                            }
                            continue;
                        }
                        c
                    }
                    Err(e) => {
                        last_fault = fault_of(&e);
                        // **Every rung's verdict, not the fault token.** `Outcome::Failed(Fault)` is
                        // one word with no room for a reason, so a join that could not be carried
                        // reported `Unreachable` and nothing else — and "that member is offline",
                        // "no helper would relay" and "the board has not caught up" are three
                        // different problems that all render as that one word.
                        why.push(format!(
                            "{}: {e}",
                            crate::node::network::short_id(responder)
                        ));
                        if !worth_another_responder(last_fault) {
                            self.say_why_the_join_failed(&why);
                            return Outcome::Failed(last_fault);
                        }
                        continue;
                    }
                }
            };

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
                Ok(o) => {
                    joined_outcome = Some((o, responder, conn));
                    break;
                }
                Err(e) => {
                    last_fault = fault_of(&e);
                    if !worth_another_responder(last_fault) {
                        return Outcome::Failed(last_fault);
                    }
                }
            }
        }
        let Some((joined, responder, conn)) = joined_outcome else {
            self.say_why_the_join_failed(&why);
            return Outcome::Failed(last_fault);
        };

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
        // Keep the responder's witness to this join (M17.6). It is republished with
        // every bundle record this node ever puts on a board for this room, so it is
        // persisted rather than held: a node that lost it could publish nothing and
        // would fall off every board. The joiner already verified it binds its own key,
        // this room and this epoch, in `run_initiator`.
        if let (Some(profile), Some(shared)) = (
            self.profile.as_ref(),
            self.channels.get(&parsed.channel_id).map(Arc::clone),
        ) {
            let admission =
                crate::nat::record::Admission::Witnessed(Box::new(joined.witness.clone()));
            if let Err(e) = shared
                .lock()
                .await
                .set_own_admission(profile.store(), admission)
            {
                return Outcome::Failed(fault_of(&e));
            }
        }
        // Every member whose bundle is on the board is an admitted author **on the
        // M17.6 evidence its record carries** — a self-signed record proves possession
        // of a key and nothing else. Sync hard-fails on an entry from an author we
        // never admitted, so this is what makes the log reconcilable at all.
        if let (Some(profile), Some(shared)) = (
            self.profile.as_ref(),
            self.channels.get(&parsed.channel_id).map(Arc::clone),
        ) {
            // Same rule as `learn_members`: evidence, not relay (M17.6). The
            // responder's own board is no more trustworthy than any other — it is
            // where a joiner first looks, which makes it the *first* place a
            // compromised member would seed keys.
            let mut channel = shared.lock().await;
            let _ = admit_board_records(
                &mut channel,
                profile.store(),
                &set.bundles,
                ChannelState::MAX_ADMISSIONS_PER_SWEEP,
                now,
            )
            .await;
        }
        // An admission changes a room's author set, the other half of the reacher join.
        self.refresh_reachers().await;
        self.sessions
            .insert((parsed.channel_id, responder), joined.session);
        // The link's anchors are this channel's anchors from now on (persisted, so a
        // restart still knows where the swarm's board is), together with our own.
        let mut learned = BootstrapSet::new();
        for a in parsed.anchors.iter().filter(|a| a.id != me) {
            let _ = learned.add(a.clone());
        }
        // `merge_endpoints`, not `merge`: the link's anchors went in first, so with
        // keep-first semantics a link minted before the anchor moved would win and this
        // node's freshly resolved address for the same identity would be discarded —
        // the joiner would adopt the stale address and keep it.
        let _ = learned.merge_endpoints(&self.anchors);
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
        // **Joining releases no sender key** (M17.6). This is the correction to
        // ADR-007 step 2, which read "the newcomer announces its own sender key … it
        // has nothing to consent over". It does: it decides which members may read it,
        // per member, exactly as they each decide about it. Releasing automatically
        // made that decision for it, and made it in favour of whichever member happened
        // to answer the join — a member chosen from the board, so influenceable by
        // whoever supplied the link. Under ADR-017 decision 3 that consent also carries
        // service reach, so an automatic grant here handed a service to a party no
        // human approved.
        //
        // The stated reason for releasing here does not require it: the ADR-004
        // responder needs the initiator's first message, which is the PQXDH
        // `InitialMessage` the join already sent, not the SKDM. `ensure_session` builds
        // a session from a board bundle record alone, and the SKDM rides over it.
        //
        // What *is* still required is one ratchet message, and it carries nothing. A
        // PQXDH responder starts with no chains — `Ratchet::init_responder`: "with no
        // chains yet — they are established when the first inbound message triggers a
        // DH ratchet step" — and the join's `InitialMessage` creates the session
        // without delivering a message, so until the joiner speaks over it the
        // responder cannot send at all. That need is real and is what the old comment
        // was pointing at; meeting it with a *sender key* is what made it a grant.
        // `PairwiseFrame::Open` meets it with an empty plaintext.
        // The ratchet message that opens the responder's sending direction rides the
        // **join stream itself** (`JoinFrame::Open`), so the responder has processed it
        // before the join returns. Sending it afterwards on a separate stream was a
        // race: `Consent` immediately after a join would find no sending chain and fail,
        // and only luck decided whether it did.
        // Nothing else replaces the release. A joiner becomes readable when it trusts
        // someone, which is a human act, and `deliver_owed_consents` issues the grant.
        let _ = self.event_tx.send(NodeEvent::Joined {
            channel_id: parsed.channel_id,
            responder,
        });
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
        if self.net.is_none() {
            return Outcome::Failed(Fault::NotNetworked);
        }
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
        // No session need exist yet: one is opened from this member's bundle record
        // if the join path never made one (ADR-016).
        let hello = self.ensure_session(channel_id, target).await;
        let Some(conn) = self.reach_member(channel_id, target).await else {
            return Outcome::Failed(Fault::Unreachable);
        };
        let Some(session) = self.sessions.get_mut(&(*channel_id, target)) else {
            return Outcome::Failed(Fault::Unreachable);
        };
        if let Err(e) = crate::node::pairwise_stream::deliver_skdm(
            &conn,
            channel_id,
            session,
            &skdm,
            hello.as_ref(),
        )
        .await
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
            let _ = self.event_tx.send(NodeEvent::Consented {
                channel_id: *channel_id,
                target,
            });
        }
        outcome
    }

    /// Trust `fingerprint` node-wide under `petname` (ADR-020 §3), then act on it
    /// at once so the operator does not wait a tick to see the effect.
    async fn trust_identity(&mut self, fingerprint: Digest32, petname: &str) -> Outcome {
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let signer = match profile.signer() {
            Ok(s) => s,
            Err(e) => return Outcome::Failed(fault_of(&e)),
        };
        let mut next = self.trust.clone();
        if let Err(e) = next.trust(fingerprint, petname) {
            return Outcome::Failed(fault_of(&e));
        }
        // Persist BEFORE adopting it: a keyring that consented but did not survive
        // a restart would silently re-consent on every boot.
        if let Err(e) = next.save(profile.store(), signer) {
            return Outcome::Failed(fault_of(&e));
        }
        self.trust = next;
        // The reacher sets are a join of the ring with each room's author set, so both
        // inputs must push. Immediately, not on the tick: a stream parked open across
        // this instant is judged by the set as it stands when its request lands (M17.11).
        self.refresh_reachers().await;
        self.deliver_owed_consents().await;
        self.publish().await;
        Outcome::Done
    }

    /// Stop trusting `fingerprint` (ADR-020 §3).
    ///
    /// Forward-looking by construction: it changes who *future* consent is issued
    /// to and recalls nothing already granted. Recalling that is `Revoke`, per
    /// room — ADR-007's enforcement honesty, which this must not paper over.
    async fn untrust_identity(&mut self, fingerprint: &Digest32) -> Outcome {
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let signer = match profile.signer() {
            Ok(s) => s,
            Err(e) => return Outcome::Failed(fault_of(&e)),
        };
        let mut next = self.trust.clone();
        if !next.untrust(fingerprint) {
            return Outcome::Failed(Fault::NotConsented);
        }
        // The ring is written FIRST and unconditionally, exactly as a revocation's
        // log fact lands before its re-keys: if the rotations below cannot all be
        // delivered, the decision must still have been taken. A removal that were
        // undone by an unreachable peer would be a removal in name only.
        if let Err(e) = next.save(profile.store(), signer) {
            return Outcome::Failed(fault_of(&e));
        }
        self.trust = next;
        // Before the rotation, not after: rotation talks to the network and may be slow,
        // and the removal must bite the moment it is decided (M17.11).
        self.refresh_reachers().await;
        self.change_the_lock_against(fingerprint).await;
        self.publish().await;
        Outcome::Done
    }

    /// Rotate this identity's sender key and re-key everyone still in the ring, in
    /// **every** room shared with `removed` (ADR-020 §3, "removing a key from the
    /// ring MUST change the lock").
    ///
    /// Read access is a sender key already handed over, so removal cannot take it
    /// back — it can only stop the removed party reading what comes *next*. That is
    /// what rotation buys, and it is the honest limit: the history they already
    /// hold stays theirs, which no protocol can change (ADR-007 enforcement
    /// honesty).
    ///
    /// Only rooms where consent was actually granted are touched. Rotating in a
    /// room that never granted anything would burn a generation and re-key
    /// everyone to no effect.
    ///
    /// Bounded honestly: the rotation and its log fact land unconditionally, and
    /// the re-keys are best-effort and retried on the tick for whoever is offline —
    /// exactly as `revoke` does, because this reuses that machinery rather than
    /// inventing a second kind of revocation.
    async fn change_the_lock_against(&mut self, removed: &Digest32) {
        let channels: Vec<Digest32> = self.channels.keys().copied().collect();
        for channel_id in channels {
            let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
                continue;
            };
            if !shared.lock().await.has_consented(removed) {
                continue;
            }
            // `revoke` is the whole act: rotate, record the log fact, re-key the
            // members who keep consent, and emit `Revoked`.
            let _ = self.revoke(&channel_id, *removed).await;
        }
    }

    /// Issue consent to every trusted, admitted author that does not hold it yet,
    /// across every open channel (ADR-020 §3).
    ///
    /// Retried on the tick for the same reason a re-key is: consent *is* a network
    /// act — the SKDM rides a pairwise session — so a trusted member that is
    /// offline right now is skipped, not failed, and picked up when it returns.
    async fn deliver_owed_consents(&mut self) {
        if self.net.is_none() || self.trust.is_empty() {
            return;
        }
        let trusted = self.trust.trusted();
        let channels: Vec<Digest32> = self.channels.keys().copied().collect();
        for channel_id in channels {
            let owed = {
                let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
                    continue;
                };
                let owed = shared.lock().await.owed_consents(&trusted);
                owed
            };
            for target in owed {
                // `consent` emits `Consented` on success; a failure here is a peer
                // that is not reachable yet, which the next tick retries.
                let _ = self.consent(&channel_id, target).await;
            }
        }
    }

    /// Revoke `target`'s consent (ADR-007 §Revocation, M18.1): rotate this
    /// identity's sender key, record the revocation, and re-key everyone who keeps
    /// consent.
    ///
    /// The order is deliberate. The rotation and the log fact land **first** and
    /// unconditionally; the re-keys follow on a best-effort basis and are retried by
    /// the tick for whoever was unreachable. A revocation that waited for the rest of
    /// the room to be online would be a revocation in name only.
    async fn revoke(&mut self, channel_id: &Digest32, target: Digest32) -> Outcome {
        let now = self.now();
        let (Some(profile), Some(shared)) = (
            self.profile.as_ref(),
            self.channels.get(channel_id).map(Arc::clone),
        ) else {
            return Outcome::Failed(Fault::UnknownChannel);
        };
        let generation = {
            let mut channel = shared.lock().await;
            match channel.revoke_consent(profile, target, now) {
                Ok(r) => r.body.new_chain_id,
                Err(e) => return Outcome::Failed(fault_of(&e)),
            }
        };
        // The revocation is a log fact the whole channel converges on.
        self.note_local_append(channel_id);
        let rekeyed = self.deliver_rekeys_for(channel_id).await;
        let _ = self.event_tx.send(NodeEvent::Revoked {
            channel_id: *channel_id,
            target,
            generation,
            rekeyed,
        });
        Outcome::Done
    }

    /// Deliver the current sender-key generation to every member of every open
    /// channel that keeps consent and does not hold it yet.
    async fn deliver_owed_rekeys(&mut self) {
        let channels: Vec<Digest32> = self.channels.keys().copied().collect();
        for channel_id in channels {
            let _ = self.deliver_rekeys_for(&channel_id).await;
        }
    }

    /// Deliver the current generation to the members of one channel that are owed it,
    /// returning how many were re-keyed. A member with no live pairwise session is
    /// skipped, not failed: the tick tries again once there is one.
    async fn deliver_rekeys_for(&mut self, channel_id: &Digest32) -> u64 {
        if self.net.is_none() {
            return 0;
        }
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return 0;
        };
        let (owed, generation, skdm) = {
            let channel = shared.lock().await;
            let owed = channel.owed_rekeys();
            if owed.is_empty() {
                return 0;
            }
            let Some(profile) = self.profile.as_ref() else {
                return 0;
            };
            match channel.rekey_skdm(profile) {
                Ok(s) => (owed, channel.sender_generation(), s),
                Err(_) => return 0,
            }
        };
        let mut delivered = 0u64;
        for target in owed {
            // Open a session from the member's bundle record if none exists, and reach
            // them through the ladder rather than requiring a live connection: a re-key
            // that only reaches members this process happened to join with is the M15
            // gap ADR-016 recorded, and it is what made revocation undeliverable after
            // a restart.
            let hello = self.ensure_session(channel_id, target).await;
            let Some(conn) = self.reach_member(channel_id, target).await else {
                continue;
            };
            let Some(session) = self.sessions.get_mut(&(*channel_id, target)) else {
                continue;
            };
            if crate::node::pairwise_stream::deliver_skdm(
                &conn,
                channel_id,
                session,
                &skdm,
                hello.as_ref(),
            )
            .await
            .is_err()
            {
                continue;
            }
            // Recorded only after the bytes went out, so a failed delivery stays owed.
            let noted = {
                let Some(profile) = self.profile.as_ref() else {
                    return delivered;
                };
                shared
                    .lock()
                    .await
                    .note_delivered(profile.store(), target, generation)
            };
            if noted.is_ok() {
                delivered += 1;
            }
        }
        delivered
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
        // Which channels a local-append push actually got out. Everything else stays owed.
        let mut pushed: std::collections::BTreeSet<Digest32> = std::collections::BTreeSet::new();
        // Rooms any peer was skipped for because they were mid-session. Added to `pending_push`
        // only **after** the `retain` below — see there.
        let mut owed_rooms: std::collections::BTreeSet<Digest32> =
            std::collections::BTreeSet::new();
        for (peer, trigger) in due {
            if net.manager().existing(&peer).is_none() {
                continue;
            }
            // Which channels this pass covers: a local-append push touches only the
            // channels that changed; a connect or interval pass covers every channel
            // shared with this peer.
            let mut channels: Vec<Digest32> = Vec::new();
            // Rooms this pass wanted with this peer but found **already mid-session**. See the
            // `owed` handling after the loop: they are retried next tick, not forgotten.
            let mut owed: Vec<Digest32> = Vec::new();
            // A member reconciles a channel with its co-authors — and with its
            // anchors, which keep the log for whoever is away (M15.2b).
            let peer_is_anchor = self.anchor_ids.contains(&peer);

            // **Learn who this peer is before deciding we share nothing with it.**
            //
            // The filter below asks `is_author(&peer)`, and the thing that admits a newly joined
            // peer as an author — `learn_members`, reading the bundle records off this node's own
            // board — lives inside `sync_one`, which only runs for channels that already passed the
            // filter. So a peer that has just joined is skipped for having no entries, by the node
            // holding the evidence that it belongs, and the only code that would fix that sits
            // behind the check it is meant to satisfy. `learn_members`' own comment says reading
            // membership from the board "is a precondition for reconciling at all"; it was not one.
            //
            // The consequence, measured as a user: a message posted seconds after somebody joins is
            // **lost, not delayed** — the sender skips them, the connect trigger is consumed, and
            // the next chance is a full `SYNC_INTERVAL_SECS`. With the daemons settled, twelve posts
            // crossed twelve times in 0-1s; posting immediately after a join lost one in six even
            // after the owed-push fix below.
            //
            // Done only on a connect, not every tick: this reads the board and admits authors, which
            // is exactly the work a new connection warrants and would be waste on the interval.
            for (cid, shared) in &self.channels {
                if trigger == SyncTrigger::LocalAppend && !self.pending_push.contains(cid) {
                    continue;
                }
                // Checked **before** the `is_author` lock below: a session holds this room's
                // mutex for its whole run, so taking it here would park the actor behind it.
                if self.syncing.contains(cid) {
                    owed.push(*cid);
                    continue;
                }
                // **A fresh connection is never filtered out.**
                //
                // The `is_author` test below is the right question on an interval pass and the wrong
                // one here: a peer that has *just joined* is by definition not yet an author in this
                // node's view, so the node holding the evidence that it belongs skipped it for not
                // belonging. Worse, the code that admits it — `learn_members`, reading the bundle
                // records off this node's own board — runs inside `sync_one`, which only executes for
                // channels that already passed this filter. The precondition sat behind the check it
                // was the precondition for.
                //
                // So on a connect, reconcile every open channel with the peer and let the ADR-008
                // session decide: it verifies authorship per entry and hard-fails on an author it
                // cannot verify, which is a real answer. Silently skipping is not — measured as a
                // user, a message posted seconds after somebody joined was lost, not delayed.
                if trigger == SyncTrigger::Connected
                    || peer_is_anchor
                    || shared.lock().await.is_author(&peer)
                {
                    channels.push(*cid);
                }
            }
            // An anchor reconciles every channel it keeps with each of that channel's
            // known members.
            for (cid, state) in &self.anchored {
                // An anchored room takes part in a push: this skipped them on the reasoning that an
                // anchor never appends locally — true, and beside the point, because an anchor is
                // exactly the node that must forward what it was just given. The push trigger is now
                // set by entries arriving as well as by a local append.
                if trigger == SyncTrigger::LocalAppend && !self.pending_push.contains(cid) {
                    continue;
                }
                if self.syncing.contains(cid) {
                    owed.push(*cid);
                    continue;
                }
                // **An anchor does not filter out the member it is forwarding to.**
                //
                // `is_author` is the right question on an interval pass and the wrong one here, for
                // the same reason it was wrong for an open room: a member that has just joined is not
                // yet an author in this anchor's view, so the node whose entire job is holding the
                // log for whoever is away declined to hand it over. Measured, timestamped on both
                // sides: the anchor took the entry at **1s** and the member could not read it until
                // **31s** — `SYNC_INTERVAL_SECS`, i.e. it arrived by the member's own periodic pull
                // because the anchor never pushed. Not slow: not sent.
                //
                // On a connect or a push, reconcile and let the session decide — it verifies
                // authorship per entry and hard-fails on one it cannot verify, which is an answer.
                // The interval pass keeps the filter, where it costs nothing and bounds the work.
                let forwarding =
                    matches!(trigger, SyncTrigger::Connected | SyncTrigger::LocalAppend);
                if forwarding || state.lock().await.is_author(&peer) {
                    channels.push(*cid);
                }
            }
            for channel_id in channels {
                if self.sync_one(&channel_id, peer).await {
                    ran = true;
                    if trigger == SyncTrigger::LocalAppend {
                        pushed.insert(channel_id);
                    }
                }
            }
            if let Some(schedule) = self.schedules.get_mut(&peer) {
                schedule.note_synced(now);
                // **A room skipped because it was mid-session is owed, not synced.**
                //
                // The in-flight mark is per room, so when two peers came due for one room in the
                // same pass the first took it and the second was skipped — and `note_synced` above
                // then recorded the skipped peer as synced at the same `now` as the first. Both came
                // due together again, in the same `BTreeMap` order, and the same peer lost again:
                // **aligned once, aligned forever.** A local append makes every peer due at once, so
                // the alignment was the default after the first post, and which peer starved came
                // down to how the fingerprints sorted.
                //
                // Measured in `node_m15_anchor_gate` (instrumented, by the other session): in every
                // red, each member skipped the *other member* nine rounds running while its only
                // session — with the anchor — failed each time, so the one leg that could carry the
                // room never ran. Red about half the time in CI since before v0.2.5.
                //
                // Owed is not the unconditional retry the note on `pending_push` below warns
                // against: nothing here takes a lock, and it is retried only while that room is
                // mid-session, which is milliseconds. The next tick finds the room free.
                if !owed.is_empty() {
                    owed_rooms.extend(owed.iter().copied());
                    schedule.note_local_append();
                }
            }
        }
        // **Keep what did not go out.** This cleared unconditionally, which discarded the intent to
        // push an append whenever it had not actually been pushed — and the ordinary case is a peer
        // that has just joined: `note_local_append` marks "every peer's schedule due", but a peer
        // whose `NetEvent::Connected` the actor has not handled yet **has no schedule to mark**, so
        // nothing was owed to it and the entry was dropped rather than delayed. It then waited for
        // that peer's own `SYNC_INTERVAL_SECS`, and if that raced too, longer.
        //
        // Measured as a user: with the daemons settled, twelve posts crossed twelve times in 0-1s;
        // the proof that posts seconds after joining lost one in three.
        //
        // Note what is deliberately NOT changed: `note_synced` above still runs whether or not
        // anything went out. Making it conditional looks right and is wrong — it leaves the peer due
        // every tick, so one that cannot sync is retried once a second, each attempt taking the
        // room's lock. Measured: that took the same proof from 4 of 6 to 3 of 8. The backoff must
        // hold on failure; what must survive is the work owed, which is this line.
        self.pending_push.retain(|cid| !pushed.contains(cid));
        // **After** the retain, or it undoes this. The skip happens in exactly the pass where the
        // room *was* pushed — to whichever peer took it first — so an owed room added inside the loop
        // was then removed here as "pushed", and the skipped peer's retry next tick found nothing
        // owed and dropped the push. It still arrived, on the next interval: up to 30s late instead
        // of immediately, and invisible to any gate that only asks whether it arrived. Found in
        // review by the other session.
        //
        // Known and not fixed here: `pushed` means a session *started*, not that it delivered, so a
        // push to a peer whose session then fails is counted as done.
        self.pending_push.extend(owed_rooms);
        ran
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
        let Some(conn) = net.manager().existing(&peer) else {
            return false;
        };
        let Some(store) = self.log_store() else {
            return false;
        };
        let target = match (
            self.channels.get(channel_id).map(Arc::clone),
            self.anchored.get(channel_id).map(Arc::clone),
        ) {
            (Some(shared), _) => SessionTarget::Channel(shared),
            (None, Some(state)) => SessionTarget::Anchored(state),
            (None, None) => return false,
        };
        // An anchor's authors come from its own board, which is local: cheap, and it has to happen
        // before the session so the anchor can verify what arrives.
        if matches!(target, SessionTarget::Anchored(_)) {
            self.refresh_anchored_authors(channel_id).await;
        }
        if self.syncing.contains(channel_id) {
            return false; // a session already has this room; a second would deadlock against it
        }
        let Ok(slot) = Arc::clone(&self.sync_slots).try_acquire_owned() else {
            return false; // past the cap: skipped, not queued. The schedule comes round again.
        };
        self.syncing.insert(*channel_id);
        let admit_store = self.profile.as_ref().map(Profile::store_handle);
        let cid = *channel_id;
        let now = self.now();
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let _slot = slot;
            // 1. Learn who else has joined, or the first entry from a newer member kills the session
            //    (ADR-008). A round trip, so it belongs here and not on the actor.
            let epoch = match &target {
                SessionTarget::Channel(shared) => {
                    let known = shared.lock().await.epoch();
                    if let Some(pstore) = admit_store {
                        if let Ok(set) = net.fetch_channel(&conn, &cid, known).await {
                            {
                                let mut ch = shared.lock().await;
                                let _ = admit_board_records(
                                    &mut ch,
                                    &pstore,
                                    &set.bundles,
                                    ChannelState::MAX_ADMISSIONS_PER_SWEEP,
                                    now,
                                )
                                .await;
                            }
                            // What the peer's board holds is filed on this node's own, so its board
                            // carries the whole membership it knows. Bundles go first: they carry
                            // the key an address record is verified with (M15.2a). Mirroring to the
                            // anchors follows on the actor when `SyncDone` lands, because that needs
                            // channel state.
                            for wire in set
                                .bundles
                                .iter()
                                .map(MemberBundleRecord::to_wire)
                                .chain(set.members.iter().map(RendezvousRecord::to_wire))
                            {
                                let _ = net.publish_local(&wire);
                            }
                        }
                    }
                    shared.lock().await.epoch()
                }
                SessionTarget::Anchored(state) => state.lock().await.epoch(),
            };
            // 2. Open the stream. Also a round trip.
            //
            // **A stream that will not open still reports.** This returned without a word, and the
            // only thing that clears `syncing` is `SyncDone` — so one failed open left the room
            // marked mid-session for good: every later sync of it skipped, every inbound one
            // refused, and nothing said so. Every exit from this task now sends `SyncDone`.
            let handle = tokio::runtime::Handle::current();
            let transport =
                match crate::node::syncstream::open_sync(&conn, handle, &cid, epoch).await {
                    Ok(t) => t,
                    Err(e) => {
                        let _ = tx
                            .send(NetEvent::SyncDone {
                                channel_id: cid,
                                outcome: Err(e),
                            })
                            .await;
                        return;
                    }
                };
            // 3. Run the session. `blocking_lock` is the sanctioned way to take a tokio mutex off a
            //    blocking thread; anything else wanting this room waits for the session rather than
            //    finding it missing.
            let joined = tokio::task::spawn_blocking(move || {
                let mut t = transport;
                match target {
                    SessionTarget::Channel(shared) => {
                        shared.blocking_lock().sync_over(&store, &mut t, now)
                    }
                    SessionTarget::Anchored(state) => {
                        state.blocking_lock().sync_over(&store, &mut t, now)
                    }
                }
            })
            .await;
            // A session that panicked still hands the room back: `Err` from the join is the panic.
            let outcome = joined.unwrap_or(Err(crate::error::Error::MalformedGovernance(
                "sync session panicked",
            )));
            let _ = tx
                .send(NetEvent::SyncDone {
                    channel_id: cid,
                    outcome,
                })
                .await;
        });
        true
    }

    /// Take the channel out of the actor's map and run a session on its own task,
    /// returning it through [`NetEvent::SyncDone`].
    fn start_session(
        &mut self,
        channel_id: Digest32,
        transport: crate::transport::quic::QuicStreamTransport,
    ) {
        let Some(store) = self.log_store() else {
            return;
        };
        let target = match (
            self.channels.get(&channel_id).map(Arc::clone),
            self.anchored.get(&channel_id).map(Arc::clone),
        ) {
            (Some(shared), _) => SessionTarget::Channel(shared),
            (None, Some(state)) => SessionTarget::Anchored(state),
            (None, None) => return,
        };
        // Marked here, past both early returns above, so a session that never starts never
        // leaves the room marked. Its caller used to mark it first.
        self.syncing.insert(channel_id);
        let now = self.now();
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let joined = tokio::task::spawn_blocking(move || {
                // `blocking_lock` is the sanctioned way to take a tokio mutex off a
                // blocking thread. Anything else wanting this channel waits for the
                // session — a few milliseconds — instead of finding it missing.
                let mut t = transport;
                match target {
                    SessionTarget::Channel(shared) => {
                        shared.blocking_lock().sync_over(&store, &mut t, now)
                    }
                    SessionTarget::Anchored(state) => {
                        state.blocking_lock().sync_over(&store, &mut t, now)
                    }
                }
            })
            .await;
            let outcome = joined.unwrap_or(Err(crate::error::Error::MalformedGovernance(
                "sync session panicked",
            )));
            let _ = tx
                .send(NetEvent::SyncDone {
                    channel_id,
                    outcome,
                })
                .await;
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
    /// Serve one sync session for a request that has **already been read**.
    ///
    /// The preamble is read on the per-connection stream task (`node::network`), not here: the
    /// actor is the only writer of channel state and anything it awaits inline stops the whole
    /// node, so it must never wait on an untrusted peer to speak. What it does here is local
    /// and ordered, which is what the single-task design is for.
    /// **Only a member of *this* room is served its log** (PRD-001 R5). The stream-kind gate
    /// in `node::net` asks whether the peer may open a sync stream *at all*, which any member
    /// of any room this node holds may — and the preamble then names whichever channel the
    /// peer likes. Nothing here checked the two against each other, so a member of room A who
    /// had ever seen room B's `.vox` name was handed B's whole log (PRD-001 D5). See
    /// [`Self::may_sync`] for who counts.
    async fn run_sync_session(
        &mut self,
        peer: Digest32,
        channel_id: Digest32,
        epoch: u64,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) {
        use crate::node::syncstream::accept_sync;
        // Answering while our own session holds this room is the other half of the deadlock.
        //
        // **Refused explicitly, not by dropping the streams.** Letting them drop leaves the peer
        // reading for a frame that will never come until `SYNC_FRAME_TIMEOUT` expires — the
        // silent refusal that reads as a hang, which is the shape of defect this whole change
        // exists to remove. A reset reaches it on the next read, and its schedule brings it
        // back in a second.
        //
        // **Refused before the lock, not after.** A session holds this room's mutex for its whole
        // run, and this is the actor: awaiting that lock to read the epoch parked the whole node
        // behind the very session this check exists to detect.
        if self.syncing.contains(&channel_id) {
            let (mut send, mut recv) = (send, recv);
            crate::node::net::refuse_stream(&mut send, &mut recv);
            return;
        }
        // Only a channel we hold open at that epoch — or keep as an anchor — can be
        // reconciled. An anchor whose board just received the genesis adopts it here
        // rather than making the member wait for the next tick.
        if !self.channels.contains_key(&channel_id) {
            self.adopt_anchored(&channel_id).await;
            self.refresh_anchored_authors(&channel_id).await;
        }
        let matches_epoch = match (
            self.channels.get(&channel_id),
            self.anchored.get(&channel_id),
        ) {
            (Some(shared), _) => shared.lock().await.epoch() == epoch,
            (None, Some(state)) => state.lock().await.epoch() == epoch,
            (None, None) => false,
        };

        if !matches_epoch {
            return;
        }
        if !self.may_sync(&channel_id, &peer, epoch).await {
            // Refused explicitly, with the same coded reset as a stream kind the peer may not
            // open, rather than left to read for a frame that never comes.
            let (mut send, mut recv) = (send, recv);
            crate::node::net::refuse_stream(&mut send, &mut recv);
            return;
        }
        let transport = accept_sync(tokio::runtime::Handle::current(), send, recv);
        self.start_session(channel_id, transport);
    }

    /// Whether `peer` may reconcile `channel_id`'s log with this node.
    ///
    /// - An **admitted author** of that room. If it is not one yet, this node's own board is
    ///   consulted first — local, so cheap — because a member that joined through somebody
    ///   else is on the board before it is in this node's author table, and refusing it for
    ///   that would be the "precondition behind its own check" defect `run_due_syncs` documents.
    ///   Admission there takes the same M17.6 evidence as everywhere else.
    /// - An **anchor of that room** — in the room's own anchor set, which holds this node's
    ///   configured anchors and those the room's link named. It keeps the room's ciphertext by
    ///   design (ADR-016 M15.2b) for members who are away. An anchor named only by *another*
    ///   room's link is not an anchor of this one.
    ///
    /// For a room this node only anchors, the peer must be an author the board knows.
    async fn may_sync(&mut self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
        if let Some(shared) = self.channels.get(channel_id).map(Arc::clone) {
            {
                let channel = shared.lock().await;
                if channel.is_author(peer)
                    || channel.anchors().nodes().iter().any(|a| a.id == *peer)
                {
                    return true;
                }
            }
            let (Some(net), Some(store)) = (
                self.net.as_ref().map(Arc::clone),
                self.profile.as_ref().map(Profile::store_handle),
            ) else {
                return false;
            };
            let bundles = net.board_bundles(channel_id, epoch);
            if !bundles.iter().any(|b| b.author_id == *peer) {
                return false;
            }
            let now = self.now();
            let mut channel = shared.lock().await;
            let _ = admit_board_records(
                &mut channel,
                &store,
                &bundles,
                ChannelState::MAX_ADMISSIONS_PER_SWEEP,
                now,
            )
            .await;
            return channel.is_author(peer);
        }
        if let Some(state) = self.anchored.get(channel_id) {
            return state.lock().await.is_author(peer);
        }
        false
    }

    /// Accept an inbound [`PairwiseFrame::Hello`], establishing the responder half of
    /// a session a peer opened from our bundle record. `true` if a session now exists.
    ///
    /// This is the join responder's PQXDH path minus the join: the message names a
    /// signed prekey and optionally a one-time prekey **from our own ring**, so a party
    /// holding no prekey of ours cannot open a session at all. The one-time prekey is
    /// consumed and the consume persisted before the handshake completes, so a crash
    /// here cannot leave it re-offerable; a replay is graded last-resort rather than
    /// silently accepted, the same reconciliation `joinstream` performs.
    ///
    /// An existing session is never replaced: a peer cannot reset our ratchet by
    /// sending a fresh `Hello`.
    async fn accept_hello(&mut self, channel_id: Digest32, peer: Digest32, initial: &[u8]) -> bool {
        if self.sessions.contains_key(&(channel_id, peer)) {
            return true;
        }
        let Ok(init) = InitialMessage::from_wire(initial) else {
            return false;
        };
        let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
            return false;
        };
        let ctx = {
            let channel = shared.lock().await;
            // Only a member we have admitted may open a session to us.
            if !channel.is_author(&peer) {
                return false;
            }
            match channel.join_context() {
                Ok(c) => c,
                Err(_) => return false,
            }
        };
        let now = self.now();
        let mut reuse = crate::pairwise::OtpReuseTracker::new();
        let Some(profile) = self.profile.as_ref() else {
            return false;
        };
        let store = profile.store();
        let Ok(signer) = profile.signer() else {
            return false;
        };
        // The ring is taken under its lock below, so take what the save needs first. The
        // `Send + Sync` bound is load-bearing, not decoration: this function now awaits the
        // ring lock, so the actor's whole future has to stay `Send`, and a bare
        // `&dyn RootSigner` is not.
        let signer: &(dyn crate::identity::composite::RootSigner + Send + Sync) = signer;
        let Some(ring) = self.prekeys.as_ref().map(Arc::clone) else {
            return false;
        };
        let mut ring = ring.lock().await;
        if let Some(id) = init.one_time_prekey_id {
            match ring.use_one_time(id, now) {
                prekeys::OneTimeUse::Fresh => {}
                prekeys::OneTimeUse::Reused => {
                    // Seed the per-process tracker from the ring's persistent record so
                    // the downgrade is graded even after a restart (ADR-004).
                    reuse.observe(id);
                }
                prekeys::OneTimeUse::Unknown => return false,
            }
            // Persist the consume before the handshake completes: a crash here must not
            // leave the prekey re-offerable.
            if prekeys::save(store, signer, &ring).is_err() {
                return false;
            }
        }
        let Some(signed_prekey) = ring.signed_prekey_for(init.signed_prekey_id) else {
            return false;
        };
        let one_time_prekey = init
            .one_time_prekey_id
            .and_then(|id| ring.consumed_one_time(id));
        let prekeys = crate::pairwise::ResponderPrekeys {
            identity_dh_key: ring.identity_dh(),
            signed_prekey,
            one_time_prekey,
        };
        let Ok(session) = crate::pairwise::session::Session::accept(
            &init,
            &prekeys,
            &ctx.channel_id,
            ctx.epoch,
            &mut reuse,
            ctx.floor,
        ) else {
            return false;
        };
        self.sessions.insert((channel_id, peer), session);
        true
    }

    /// A connection to `target`: the live one if there is one, otherwise dialled
    /// through the ADR-012 ladder.
    ///
    /// `ConnectionManager::existing` alone means "whoever we happen to be talking to",
    /// which is not a membership property — it made delivery depend on connection
    /// history rather than on the room.
    async fn reach_member(
        &mut self,
        channel_id: &Digest32,
        target: Digest32,
    ) -> Option<Arc<crate::transport::quic::VoxConnection>> {
        let net = self.net.as_ref().map(Arc::clone)?;
        if let Some(conn) = net.manager().existing(&target) {
            return Some(conn);
        }
        let endpoints = net.board_endpoints(channel_id, &target);
        // **Through `dial`, not `net.reach`.** This called `net.reach` directly and so
        // produced a connection the actor had never adopted: no receive loop
        // (`spawn_stream_loop`), no sync schedule, and no upgrade attempt behind a
        // relayed path. A QUIC connection is bidirectional, so the peer uses that same
        // connection to reach *back* — and nothing on this side was reading it. The
        // outbound half worked, which is why the M15 bundle-record gate passed, and the
        // inbound half silently did not: this node could deliver an SKDM to a member and
        // then never see a word that member said.
        //
        // Delegating removes the divergence rather than patching it, so the two paths
        // cannot drift again.
        self.dial(target, &endpoints).await.ok()
    }

    /// The pairwise session for `(channel, target)`, opening one from that member's
    /// **bundle record** if none exists.
    ///
    /// ADR-016 §"the rendezvous service and the member bundle record" always said
    /// members open sessions to one another this way; until now the runtime only ever
    /// created them on the join path, so a re-key or a consent release could not reach
    /// a member this process never joined with — including every member, after a
    /// restart, because sessions live only in memory.
    ///
    /// Returns the [`InitialMessage`] when the session is newly opened, because the
    /// peer cannot decrypt anything until it has accepted that. `None` means a session
    /// was already there and the peer already holds it.
    ///
    /// Sessions are deliberately **not** persisted: re-deriving one from the board is
    /// safe, whereas restoring ratchet state risks reusing a chain key. This is what
    /// makes the restart case work without an at-rest ratchet.
    async fn ensure_session(
        &mut self,
        channel_id: &Digest32,
        target: Digest32,
    ) -> Option<InitialMessage> {
        if self.sessions.contains_key(&(*channel_id, target)) {
            return None;
        }
        let net = self.net.as_ref().map(Arc::clone)?;
        let shared = self.channels.get(channel_id).map(Arc::clone)?;
        let ctx = { shared.lock().await.join_context().ok()? };
        let record = net.board_bundle(channel_id, ctx.epoch, &target)?;
        let ring = self.prekeys.as_ref()?.lock().await;
        let (initial, session) = crate::pairwise::session::Session::initiate(
            ring.identity_dh(),
            &record.prekey_bundle,
            &ctx.channel_id,
            ctx.epoch,
            ctx.suite_id,
            ctx.floor,
        )
        .ok()?;
        self.sessions.insert((*channel_id, target), session);
        Some(initial)
    }

    /// Take an inbound sealed control message: an ADR-006 SKDM, which makes that
    /// author's messages readable and backfills any already held as ciphertext.
    async fn take_inbound_skdm(&mut self, peer: Digest32, mut recv: quinn::RecvStream) {
        use crate::node::pairwise_stream::{open_skdm, recv_pairwise, PairwiseFrame};
        let Ok(Some(first)) = recv_pairwise(&mut recv).await else {
            return;
        };
        // A `Hello` opens a session the join path never created (ADR-016): accept it
        // against our own prekey ring, exactly as the join responder does, then read
        // the SKDM it precedes.
        let (channel_id, sealed) = match first {
            PairwiseFrame::Skdm { channel_id, sealed } => (channel_id, sealed),
            // One ratchet message with an empty plaintext, sent to give *this* node a
            // sending chain (M17.6). Decrypt it so the ratchet steps, then stop: there
            // is nothing behind it and nothing is granted by it.
            PairwiseFrame::Open { channel_id, sealed } => {
                let now = self.now();
                if let Some(session) = self.sessions.get_mut(&(channel_id, peer)) {
                    if let Ok(message) = crate::pairwise::message::Message::from_wire(&sealed) {
                        let _ = session.decrypt(&message, now);
                    }
                }
                return;
            }
            PairwiseFrame::Hello {
                channel_id,
                initial,
            } => {
                if !self.accept_hello(channel_id, peer, &initial).await {
                    return;
                }
                match recv_pairwise(&mut recv).await {
                    Ok(Some(PairwiseFrame::Skdm { channel_id, sealed })) => (channel_id, sealed),
                    Ok(Some(PairwiseFrame::Open { channel_id, sealed })) => {
                        let now = self.now();
                        if let Some(session) = self.sessions.get_mut(&(channel_id, peer)) {
                            if let Ok(message) =
                                crate::pairwise::message::Message::from_wire(&sealed)
                            {
                                let _ = session.decrypt(&message, now);
                            }
                        }
                        return;
                    }
                    _ => {
                        // A session with nothing behind it is still progress: the peer
                        // may deliver over it later.
                        return;
                    }
                }
            }
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
            let _ = self.event_tx.send(NodeEvent::SenderKeyReceived {
                channel_id,
                peer,
                backfilled: n as u64,
            });
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
        self.prekeys = Some(Arc::new(tokio::sync::Mutex::new(ring)));
        // The keyring is sealed under this identity, so it can only be opened now
        // (ADR-020 §3). Without this the node would hold an empty keyring and
        // silently trust nobody after every restart.
        self.trust = crate::node::trust::Keyring::load(profile.store(), signer)?;
        Ok(())
    }

    async fn lock_all(&mut self) {
        let was_unlocked = self.profile.as_ref().is_some_and(Profile::is_unlocked);
        for (_, shared) in std::mem::take(&mut self.channels) {
            shared.lock().await.lock_now();
        }
        // Abort the join exchanges first. Each holds an `Arc<VaultRootSigner>` and an
        // `Arc` of the ring below, so locking while one runs would otherwise mean the
        // secrets outlive the lock — for however long a joiner felt like waiting. Aborting
        // drops both at the task's next await point, which is what makes ADR-015's
        // lock/zeroize still true now that the exchange runs off the actor.
        self.join_tasks.abort_all();
        while self.join_tasks.try_join_next().is_some() {}
        // Drop the prekey ring: its secrets zeroize on drop, so a locked node holds
        // no key-agreement material (ADR-015 lock/zeroize).
        self.prekeys = None;
        // The keyring is not secret material, but it is sealed under the identity
        // and says who this operator talks to. A locked node holds neither, and it
        // is re-opened on the next unlock (ADR-020 §3).
        self.trust = crate::node::trust::Keyring::new();
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
            let _ = self.event_tx.send(NodeEvent::Locked);
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
                    .send(NodeEvent::ChannelOpened { channel_id: id });
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    /// Create a service room and offer its one service, atomically (ADR-017).
    ///
    /// The two halves are one command because either alone is a lie: a room with a
    /// service grant and no service hands out an address for nothing, and a service in a
    /// room nobody can join is unreachable. If the service cannot be offered the room is
    /// not kept.
    async fn serve_room(
        &mut self,
        local_name: &str,
        passphrase: &Secret,
        port: u16,
        at: Option<SocketAddr>,
    ) -> Outcome {
        let now = self.now();
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let tag = port.to_string();
        let endpoint = at.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], port)));
        let grant = CapabilitySet::from_iter_caps([Capability::dial(tag.clone())]);
        let mut channel = match ChannelState::create_with_grant(
            profile,
            local_name,
            passphrase,
            grant,
            now,
            self.argon2,
        ) {
            Ok(ch) => ch,
            Err(e) => return Outcome::Failed(fault_of(&e)),
        };
        let id = channel.channel_id();
        if let Err(e) = channel.add_service(profile.store(), profile, &tag, endpoint) {
            // Drop the room rather than keep a half-made one. Nothing outside this
            // function has seen it: it is not in `self.channels` and has not been
            // published, so forgetting it here is the whole of the rollback.
            return Outcome::Failed(fault_of(&e));
        }
        self.channels
            .insert(id, Arc::new(tokio::sync::Mutex::new(channel)));
        self.adopt_channel_anchors(&id, None).await;
        self.refresh_network_view().await;
        self.publish_channel_locally(&id).await;
        self.publish_channel_to_anchors(&id).await;
        let _ = self
            .event_tx
            .send(NodeEvent::ChannelOpened { channel_id: id });
        Outcome::Done
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
                let _ = self.event_tx.send(NodeEvent::ChannelOpened {
                    channel_id: *channel_id,
                });
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
                let _ = self.event_tx.send(NodeEvent::ChannelClosed {
                    channel_id: *channel_id,
                });
                Outcome::Done
            }
            None => Outcome::Failed(Fault::ChannelNotOpen),
        }
    }

    /// Offer a local TCP service in a channel (ADR-013 Bind, M16.1). The `bind:`
    /// capability is checked by the channel, so a node cannot offer what the log does
    /// not let it offer.
    async fn add_service(
        &mut self,
        channel_id: &Digest32,
        service_tag: &str,
        local: std::net::SocketAddr,
    ) -> Outcome {
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        let outcome = {
            let mut channel = shared.lock().await;
            channel.add_service(profile.store(), profile, service_tag, local)
        };
        match outcome {
            Ok(_) => Outcome::Done,
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    /// Stop offering a service.
    async fn remove_service(&mut self, channel_id: &Digest32, service_tag: &str) -> Outcome {
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        let outcome = {
            let mut channel = shared.lock().await;
            channel.remove_service(profile.store(), service_tag)
        };
        match outcome {
            Ok(true) => Outcome::Done,
            Ok(false) => Outcome::Failed(Fault::UnknownChannel),
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    /// Grant a member `dial:<tag>` (and optionally `bind:<tag>`) in a channel, as an
    /// ADR-007 certificate on the log. The grant is pushed to peers like any other
    /// local append, so it converges without anyone being told.
    async fn grant_tunnel(
        &mut self,
        channel_id: &Digest32,
        target: &Digest32,
        service_tag: &str,
        may_bind: bool,
        expiry: u64,
    ) -> Outcome {
        use crate::governance::capability::{Capability, CapabilitySet};
        let now = self.now();
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        let mut caps = CapabilitySet::from_iter_caps([Capability::dial(service_tag)]);
        if may_bind {
            caps.insert(Capability::bind(service_tag));
        }
        let outcome = {
            let mut channel = shared.lock().await;
            // The target must be an admitted author: a certificate naming an identity
            // the channel does not know could never be verified by anyone.
            let Some(key) = channel
                .author_keys()
                .into_iter()
                .find(|k| k.fingerprint() == *target)
            else {
                return Outcome::Failed(Fault::UnknownChannel);
            };
            channel.grant_capabilities(profile, &key, caps, expiry, now)
        };
        match outcome {
            Ok(_) => {
                self.note_local_append(channel_id);
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    /// Forward a local port to a member's service (ADR-013 Dial, M16.1): reach the
    /// member through the whole ADR-012 ladder, then bind the port.
    /// Bring up the SOCKS5 entry point for one room (ADR-017 decision 5).
    ///
    /// The room's host is its genesis creator, which is why this needs nothing but the
    /// room: no advertisement to wait for, and no configuration to hold. The connection to
    /// that host is established here, through the ADR-012 ladder, so the proxy never dials
    /// a peer itself — it asks the node for a connection and refuses if there is none.
    async fn bring_up(&mut self, channel_id: &Digest32, bind: std::net::SocketAddr) -> Outcome {
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        let genesis = shared.lock().await.genesis().clone();
        let mut resolver = crate::node::resolver::VoxResolver::new();
        if !resolver.insert(&genesis) {
            // A room with no genesis service grant has no `.vox` name: its host is not
            // determined by the genesis, so there is nothing to resolve to. Such a room is
            // reached with `vox forward <member>/<tag>` instead (ADR-017 decision 4).
            return Outcome::Failed(Fault::Refused);
        }
        let hostname = crate::node::link::vox_hostname(channel_id);
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return Outcome::Failed(Fault::NotNetworked);
        };
        // Bound **once**, and the live listener is handed to `up::serve` (M17.16). This
        // used to bind, read the port, drop the listener and let `serve` re-bind it, which
        // announced an address over a window where nothing was listening — a person who
        // scripted `vox up & ssh …` got "connection refused" — and left the port stealable
        // in between, with `serve`'s failure invisible because its task's `Result` is
        // dropped. A bound socket accepts into the kernel's backlog immediately, so
        // handing it over makes the announcement truthful the moment it is made.
        let listener = match tokio::net::TcpListener::bind(bind).await {
            Ok(l) => l,
            Err(_) => return Outcome::Failed(Fault::Unreachable),
        };
        let bound = match listener.local_addr() {
            Ok(a) => a,
            Err(_) => return Outcome::Failed(Fault::Internal),
        };
        let resolver = Arc::new(resolver);
        // No dial here: the host is reached per request (see `up::HostDialer`). Dialling
        // first would refuse to start on a race — a node that has just joined has not read
        // the board — and retrying here would block the actor tick that reads it.
        let dialer = Arc::new(NodeDialer {
            net,
            channel_id: *channel_id,
        });
        // The proxy is a library and cannot print, so a session cut by a withdrawal of
        // reach comes back as an event (M17.11). A broadcast send never blocks and drops
        // when nobody is listening, which is the right trade for a notice.
        let events = self.event_tx.clone();
        tokio::spawn(crate::node::up::serve_reporting(
            listener,
            resolver,
            dialer,
            {
                let events = events.clone();
                move |room: &Digest32, port: u16| {
                    let _ = events.send(NodeEvent::ReachWithdrawn {
                        channel_id: *room,
                        port,
                    });
                }
            },
            move |reason: &str| {
                let _ = events.send(NodeEvent::ProxyRefused {
                    reason: reason.to_owned(),
                });
            },
        ));
        let _ = self.event_tx.send(NodeEvent::ProxyUp {
            channel_id: *channel_id,
            hostname,
            bind: bound,
        });
        Outcome::Done
    }

    async fn forward(
        &mut self,
        channel_id: &Digest32,
        host: &Digest32,
        service_tag: &str,
        local: std::net::SocketAddr,
    ) -> Outcome {
        if !self.channels.contains_key(channel_id) {
            return Outcome::Failed(Fault::ChannelNotOpen);
        }
        // Loopback only, and refused **before anything is dialled**: a forward hands
        // whoever reaches its local port this node's own membership of the room, so a
        // forward bound where the network can reach it exposes a room-bound service to
        // everyone on that network. `vox up` has enforced this since it was written
        // (`node::up::serve`); a forward is the same exposure with the target already
        // chosen, so it needs no name to be guessed and is strictly easier to abuse.
        // Checked here rather than only at the bind so that a refused request costs no
        // dial, leaks no traffic and tells the caller what is actually wrong.
        if !local.ip().is_loopback() {
            return Outcome::Failed(Fault::NotLoopback);
        }
        // The member's advertised endpoints, from this node's board — the same hints
        // any dial uses; the ladder does the rest.
        let endpoints = self
            .net
            .as_ref()
            .map(|net| net.board_endpoints(channel_id, host))
            .unwrap_or_default();
        // **The ladder's own words, not `Fault::Unreachable`.** `fault_of` collapses
        // `LadderExhausted` to one token, so a forward that could not be carried told the person to
        // check a permission they cannot hold. The common case here is not a refusal at all: a
        // one-shot verb dials before its anchor connection exists, so there is no helper to carry a
        // circuit and no board hint to dial directly — `no direct candidates, and no peer is
        // connected to carry a circuit`. That sentence is the whole diagnosis and it was being
        // thrown away.
        let conn = match self.dial(*host, &endpoints).await {
            Ok(c) => c,
            Err(e) => {
                let _ = self.event_tx.send(NodeEvent::PeerUnreachable {
                    peer: *host,
                    why: e.to_string(),
                });
                return Outcome::Failed(fault_of(&e));
            }
        };
        match crate::node::tunnel::Forward::bind(conn, *channel_id, service_tag.to_owned(), local)
            .await
        {
            Ok(fwd) => {
                let (channel_id, host, service_tag, bound) =
                    (fwd.channel_id, fwd.host, fwd.service_tag.clone(), fwd.local);
                self.forwards.insert(bound, fwd);
                let _ = self.event_tx.send(NodeEvent::Forwarding {
                    channel_id,
                    host,
                    service_tag,
                    local: bound,
                });
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    /// The host-side snapshot for serving tunnels: every open channel's evaluator, the
    /// services this node offers there, and **who may reach them** (ADR-013 M16.1,
    /// ADR-017 decision 3 / M17.7). Taken by the actor because only the actor holds both
    /// the node-wide trust keyring and each channel's author set; handed to the serving
    /// task whole, so a tunnel that lives for hours never reaches back in.
    async fn host_snapshot(&mut self) -> crate::node::tunnel::HostSnapshot {
        self.refresh_reachers().await;
        let mut out = crate::node::tunnel::HostSnapshot::new();
        for (cid, shared) in &self.channels {
            let ch = shared.lock().await;
            if ch.services().is_empty() {
                continue;
            }
            let Some(reachers) = self.reachers.get(cid) else {
                continue;
            };
            out.insert(
                *cid,
                crate::node::tunnel::ChannelServices {
                    evaluator: ch.evaluator_handle(),
                    services: ch.services().clone(),
                    reachers: Arc::clone(reachers),
                },
            );
        }
        out
    }

    /// Recompute every channel's live reacher set in place.
    ///
    /// In place is the point (M17.11): the handles are already held by serving tasks, some
    /// of which are parked on a stream whose request has not arrived yet. Replacing the
    /// contents of the set they hold is what makes a withdrawal of trust reach them;
    /// handing out a fresh set would leave them reading the old one forever.
    ///
    /// Called whenever either input moves — the keyring (`Trust`/`Revoke`) or a channel's
    /// author set (any board admission) — and once per accept as a backstop.
    async fn refresh_reachers(&mut self) {
        // A **locked** node is not a node that withdrew its trust. `lock` clears the keyring
        // because it is sealed under the identity (ADR-020 §3), so recomputing here would
        // produce an empty set and read as "everyone was withdrawn" — tearing down every live
        // tunnel on a SIGHUP (ADR-015). Splicing bytes needs no identity, and locking is
        // about what this node can *read*, so live tunnels are left alone and the sets keep
        // their last values until the next unlock.
        if self.profile.is_none() {
            return;
        }
        let trusted = self.trust.trusted();
        for (cid, shared) in &self.channels {
            let ch = shared.lock().await;
            // (in this node's ring) AND (a current author of this room). Neither alone:
            // trust is room-independent so it cannot name the room, and membership is a
            // passphrase and a proof of work rather than a decision about a person.
            let next: std::collections::BTreeSet<Digest32> = trusted
                .iter()
                .copied()
                .filter(|fp| ch.is_author(fp))
                .collect();
            let slot = self
                .reachers
                .entry(*cid)
                .or_insert_with(crate::node::tunnel::empty_reachers);
            // A recompute is not a decision: this wakes the serving tasks only if the set
            // really moved. The rule and its reason live in `publish_reachers`.
            crate::node::tunnel::publish_reachers(slot, next);
        }
        // A channel this node no longer holds must deny, including to tasks still holding
        // the handle: empty it before letting go, or they would read the last value forever.
        self.reachers.retain(|cid, slot| {
            let held = self.channels.contains_key(cid);
            if !held {
                crate::node::tunnel::publish_reachers(slot, std::collections::BTreeSet::new());
            }
            held
        });
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
        // One read, in milliseconds. NOT `now * 1000` and not seconds-plus-a-second-read: a value
        // composed from two clock reads can go backwards across a second boundary, which is the
        // ordering inversion this change exists to remove.
        let now_millis = (self.millis_clock)();
        let appended = match ch.append_text(profile, text, now_millis) {
            Ok(r) => row_of(r),
            Err(e) => return Outcome::Failed(fault_of(&e)),
        };
        // ADR-006's scheduled rotation: at `N` messages or `T` elapsed the sender key
        // is retired and the next message rides a generation nobody holds yet, so the
        // reach of any one compromised key is bounded in both directions. The
        // remaining consenters are re-keyed below and by the tick.
        //
        // A rotation that cannot persist poisons the channel, which the *next*
        // command reports; it does not un-send the message that just went out, so the
        // append is still reported as the success it was.
        let rotated =
            ch.should_rotate_sender(now) && ch.rotate_sender(profile.store(), now).is_ok();
        drop(ch);
        let channel_id = *channel_id;
        let _ = self.event_tx.send(NodeEvent::NewEntry {
            channel_id,
            row: appended,
        });
        // ADR-016: push immediately after a local append. Marking it here and
        // letting the tick do the work keeps authoring off the network path.
        self.note_local_append(&channel_id);
        if rotated {
            let _ = self.deliver_rekeys_for(&channel_id).await;
        }
        Outcome::Done
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
        // A headless node is networked before its first view is published, and a
        // client reads its addresses off that view: they are cheap to read and need
        // no channel lock.
        let listening = self
            .net
            .as_ref()
            .and_then(|n| n.local_endpoints().ok())
            .map(|eps| eps.addrs().iter().map(ToString::to_string).collect())
            .unwrap_or_default();
        self.view_tx.send_replace(NodeView {
            identity,
            locked,
            mlock_active: true,
            listening,
            anchoring: Vec::new(),
            channels,
            open_channels: Vec::new(),
            forwards: Vec::new(),
            trusted: self.trust_rows(),
            relayed_peers: Vec::new(),
            connected: 0,
            relaying: 0,
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
        let mut anchoring = self
            .net
            .as_ref()
            .map(|n| n.anchored_channels())
            .unwrap_or_default();
        for a in &mut anchoring {
            if let Some(state) = self.anchored.get(&a.channel_id) {
                a.entries = Some(state.lock().await.entries() as u64);
            }
        }
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
                services: ch
                    .services()
                    .iter()
                    .map(|(tag, addr)| (tag.clone(), *addr))
                    .collect(),
            });
        }
        let (relayed_peers, relaying) = self.path_view();
        NodeView {
            identity,
            locked,
            mlock_active,
            listening,
            channels,
            open_channels,
            anchoring,
            forwards: self
                .forwards
                .values()
                .map(|f| crate::node::api::ForwardInfo {
                    channel_id: f.channel_id,
                    host: f.host,
                    service_tag: f.service_tag.clone(),
                    local: f.local,
                })
                .collect(),
            trusted: self.trust_rows(),
            relayed_peers,
            relaying,
            connected: self
                .net
                .as_ref()
                .map_or(0, |net| net.manager().peers().len()),
        }
    }

    /// Which peers are reached through a relay, and how many circuits this node carries for
    /// others. Both come from the connection manager, which is the only authority on either.
    fn path_view(&self) -> (Vec<Digest32>, usize) {
        let Some(net) = self.net.as_ref() else {
            return (Vec::new(), 0);
        };
        let endpoint = net.manager().endpoint();
        let mut relayed: Vec<Digest32> = net
            .manager()
            .peers()
            .into_iter()
            .filter(|p| {
                net.manager().existing(p).is_some_and(|c| {
                    crate::node::net::path_class(endpoint, &c)
                        == crate::node::net::PathClass::Relayed
                })
            })
            .collect();
        relayed.sort_unstable();
        (relayed, net.relaying())
    }

    /// The keyring as the view carries it — empty while locked, because the
    /// keyring is sealed under the identity and there is nothing to show.
    fn trust_rows(&self) -> Vec<(Digest32, String)> {
        self.trust
            .iter()
            .map(|(fp, name)| (*fp, name.to_owned()))
            .collect()
    }
}

fn row_of(r: &Rendered) -> MessageRow {
    MessageRow {
        entry_hash: r.entry_hash,
        author: r.author,
        created_millis: r.created_millis,
        text: r.text.clone(),
    }
}

/// Map a library error to the closed, redaction-safe [`Fault`] set.
/// The node's answer to "give me a connection to this member", for the `vox up` proxy.
///
/// The proxy never dials: reaching a member is the ADR-012 ladder's job and the ladder
/// lives in the node. This hands over a connection the node already has, and answers
/// `None` otherwise — so a proxy request for an unreachable host is refused rather than
/// blocked.
struct NodeDialer {
    net: Arc<NodeNet>,
    /// The room whose board names the host's endpoints.
    channel_id: Digest32,
}

impl crate::node::up::HostDialer for NodeDialer {
    async fn connection(&self, host: &Digest32) -> crate::error::Result<Arc<VoxConnection>> {
        // `reach` returns a live connection when there is one and otherwise runs the whole
        // ADR-012 ladder, so this is both "give me the connection" and "make one". The
        // endpoint hints come from the board, which is also why this must happen per
        // request: a node that has only just joined has not read the board yet.
        let endpoints = self.net.board_endpoints(&self.channel_id, host);
        self.net.reach(*host, &endpoints).await
    }
}

/// Admit as many board records as their M17.6 evidence allows, to a fixpoint.
///
/// A witness is only evidence if its signer is **already** admitted, which roots every
/// chain in the genesis creator — and means order matters. A board hands records over
/// in whatever order it holds them, so a single pass drops a record whose witness was
/// signed by a member that appears later in the same batch. Repeating until a pass
/// admits nothing resolves a chain of any length, in any order, and terminates because
/// each pass either admits somebody or is the last.
///
/// `quota` bounds the whole call, not a pass: a witness makes an admission attributable
/// but not impossible, so without it one compromised member could still exhaust this
/// node's author table and deny admission to every legitimate member thereafter.
async fn admit_board_records(
    channel: &mut ChannelState,
    store: &crate::node::store::Store,
    records: &[crate::nat::record::MemberBundleRecord],
    quota: usize,
    now: u64,
) -> usize {
    let mut admitted = 0usize;
    let mut pending: Vec<&crate::nat::record::MemberBundleRecord> = records.iter().collect();
    while admitted < quota {
        let before = admitted;
        pending.retain(|record| {
            if admitted >= quota {
                return true;
            }
            let Ok(key) = crate::identity::composite::CompositePublicKey::from_bytes(
                &record.prekey_bundle.root_pub,
            ) else {
                return false;
            };
            // The board is availability only. The record must verify under the key it
            // carries, *and* carry the evidence that the key belongs here — a
            // self-signed record proves possession of a key and nothing else, and
            // admitting on who relayed it is the trust-on-first-use ADR-020 decision 3
            // forbids.
            if record.verify(&key).is_err() {
                return false;
            }
            match channel.admit_from_board(store, &key, &record.admission, now) {
                Ok(true) => {
                    admitted += 1;
                    false
                }
                // Already admitted: nothing to do and nothing to retry.
                Ok(false) => false,
                // The evidence does not hold up *yet* — its witness may be admitted by
                // a later pass. Kept for the next one; dropped when a pass adds nobody.
                Err(_) => true,
            }
        });
        if admitted == before {
            break;
        }
    }
    admitted
}

fn fault_of(e: &Error) -> Fault {
    match e {
        // A ladder that tried every rung and got nowhere is unreachable, not an internal
        // fault: falling through to `Internal` made the join walk stop after one responder.
        Error::LadderExhausted(_) => Fault::Unreachable,
        Error::Profile("no identity in this profile") => Fault::NoIdentity,
        Error::Profile("identity already exists in this profile") => Fault::IdentityExists,
        Error::Profile("locked") => Fault::Locked,
        Error::Profile("no such channel in this profile") => Fault::UnknownChannel,
        Error::AtRestUnlockFailed => Fault::WrongPassphrase,
        Error::AtRestLocked => Fault::Locked,
        Error::SizeLimitExceeded(_) => Fault::TooLong,
        Error::MalformedLink(_) | Error::MalformedAnchor(_) => Fault::BadLink,
        Error::Unreachable(_) => Fault::Unreachable,
        Error::JoinRefused(_) | Error::RendezvousRejected(_) => Fault::Refused,
        Error::Storage { .. } | Error::Path { .. } => Fault::Storage,
        // A join refused before the challenge (the responder does not hold that
        // channel open) reaches the joiner as a malformed exchange; report it as the
        // refusal it is rather than an internal fault.
        Error::MalformedJoin(_) => Fault::Refused,
        // A revocation the log has already settled, or one aimed at oneself: the
        // caller's request cannot be honoured, which is not an internal failure.
        Error::MalformedGovernance(
            "no consent to revoke" | "an identity cannot revoke its own consent",
        ) => Fault::NotConsented,
        _ => Fault::Internal,
    }
}
