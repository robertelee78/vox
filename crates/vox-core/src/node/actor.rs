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

use std::collections::{BTreeMap, BTreeSet};
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
use crate::node::open_rooms::OpenRooms;
use crate::node::paths::Paths;
use crate::node::prekeys::{self, PrekeyRing};
use crate::node::profile::Profile;
use crate::pairwise::init_message::InitialMessage;
use crate::transport::quic::VoxConnection;

/// A pairwise session this node opened (ADR-021 F12).
#[derive(Debug, Clone)]
struct Initiated {
    /// The hello that lets the peer accept it; `None` for a session opened on the join
    /// path, which the join protocol itself delivered.
    initial: Option<InitialMessage>,
    /// Whether the peer holds that hello: it took a key sealed under the session (V210-89).
    /// Until it has, every delivery over the session carries it again — a peer cannot open
    /// anything sealed under a session it was never offered.
    hello_delivered: bool,
}

/// **Which of two competing sessions for one pair both ends keep** (ADR-021 F12): the
/// one opened by the lower fingerprint. Two members that opened a session to each other
/// at the same moment each hold their own; both apply this rule and so keep the same
/// one. `existing_mine` says whether the session already held was opened by `me`; the
/// incoming one was opened by `peer`.
///
/// A second session from the same opener replaces the first: a peer only opens a
/// session when it holds none, so a new hello from the peer that opened ours means it
/// lost its state (a restart — sessions are not persisted), and the old one is dead.
fn incoming_session_wins(me: &Digest32, peer: &Digest32, existing_mine: bool) -> bool {
    !existing_mine || peer < me
}

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

/// How often the actor's timers run. Sync is not paced by it: a port is evaluated at the end of
/// every event that can change what it needs (ADR-025 D6a); the tick retires attempts whose
/// connection died and raises the periodic request (D7).
const TICK: Duration = Duration::from_secs(1);

/// How often automatic work (a rotation's rekeys, a trusted member's consent) may start a background
/// dial to one member it cannot currently reach. See `reach_member`.
const MEMBER_REDIAL_SECS: u64 = 30;

/// How long relayed connections' closes get to leave through their circuits before the circuits'
/// carrier connections are closed too (see `stop_network`). The frame only has to be handed to the
/// circuit's stream, which happens on the endpoint driver's next turn.
const RELAYED_CLOSE_LEAD: Duration = Duration::from_millis(50);

/// How long a `Shutdown` waits for work that outlives the actor — a sync session on a blocking
/// thread, an aborted join — to let go of the profile's store before answering. With the network
/// stopped each of them ends at its next read, so this is a ceiling, not an expected wait.
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);
/// How long building the view may wait, in total across every room, for rooms sync sessions hold
/// before using those rooms' previous entries. A session holds a room for one protocol step at a
/// time. One deadline for the whole view, not one per room: with `ports::OUTBOUND_SLOTS` outbound sessions (and their inbound peers) each
/// holding a room, a wait per room would park the actor for seconds on a single publish. See
/// `Node::view_of`.
const VIEW_LOCK_PATIENCE: Duration = Duration::from_millis(250);

/// A room's summary for the view, from its state.
fn summary_of(ch: &ChannelState) -> ChannelSummary {
    ChannelSummary {
        channel_id: ch.channel_id(),
        local_name: Some(ch.local_name().to_owned()),
        open: true,
        entries: ch.entry_count() as u64,
    }
}

/// A room's detail for the view, from its state.
fn detail_of(ch: &ChannelState) -> ChannelDetail {
    ChannelDetail {
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
        equivocations: ch.equivocations(),
        consented: ch.consented().into_iter().collect(),
    }
}

/// A room's lock if it can be had by `deadline`. A free lock is taken even once the deadline has
/// passed: only a held one is given up.
async fn by<T>(
    deadline: tokio::time::Instant,
    m: &tokio::sync::Mutex<T>,
) -> Option<tokio::sync::MutexGuard<'_, T>> {
    tokio::time::timeout_at(deadline, m.lock()).await.ok()
}
/// How long one publish round to one board may take before it is given up until the next round: a
/// live board answers each put in milliseconds. See `publish_channel_to_anchor`.
const ANCHOR_PUBLISH_PATIENCE: Duration = Duration::from_secs(5);

/// How long a join's board search keeps preferring the room's own anchors once some other route
/// has answered: the connection-attempt delay RFC 8305 recommends, long enough for a route that
/// is merely a moment slower to win, short enough that one that will never answer costs nothing a
/// person notices. See `Joiner::reach_a_board`.
const BOARD_PREFERENCE_GRACE: Duration = Duration::from_millis(250);

/// How long after its `failures`-th failure in a row a `(room, board)` publish is retried: 1, 2, 4,
/// 8, 16, then 30s for good — each **shortened** by up to a quarter at random, so rooms that failed
/// to one board together spread their retries out and the cap is never exceeded. See
/// `note_publish_round`.
fn publish_retry_after(failures: u32) -> Duration {
    let base =
        Duration::from_secs(1u64 << failures.saturating_sub(1).min(5)).min(PUBLISH_RETRY_CAP);
    let jitter = crate::identity::rng::random_array::<1>().map_or(0, |b| b[0]);
    base.mul_f64(1.0 - f64::from(jitter) / 255.0 / 4.0)
}

/// The longest a failed publish waits before it is tried again.
const PUBLISH_RETRY_CAP: Duration = Duration::from_secs(30);
/// How long a delivered sender key may go unanswered before it is counted as not taken and sent
/// again. See `pairwise_stream::refused`.
const KEY_DELIVERY_PATIENCE: Duration = Duration::from_secs(30);

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

// **The actor decides; slots do the waiting.** Everything about reconciling a room with a peer that
// touches the wire — reading that peer's board, opening the stream, the session itself — runs in a
// slot (`ports::OUTBOUND_SLOTS`), so the one task allowed to write channel state never waits on a
// network round trip. It used to: `fetch_channel` and `open_sync` were awaited inline, bounded only
// by `SYNC_FRAME_TIMEOUT`, so a peer that went quiet mid-setup stopped the node for twenty seconds:
//
// ```text
// vox node: took 1 entry for room 4yxukqstptuq
// vox node: BUSY 20033ms — filing a sync that finished — nobody could be answered
// ```
//
// Past the cap a sync used to be **skipped**, on the argument that a queue of sessions for rooms
// whose state has since moved on is worse than none. ADR-025 D6 queues the *port* instead, and a
// queued port re-checks whether it still needs a session when its turn comes, which answers that.

/// How long an outbound session's setup — reading the peer's board and offering it the records it
/// lacks — may take before the session goes on without it. Both are best-effort, and a live peer
/// answers them in milliseconds, as a board answers a publish (`ANCHOR_PUBLISH_PATIENCE`).
const SETUP_PATIENCE: Duration = Duration::from_secs(5);

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
/// queued** — the rule sync sessions followed until ADR-025, and for a stronger reason here: a queue of
/// half-finished exchanges is exactly the resource a flood wants to fill, and a joiner that is
/// told "no" now retries in a second, which is cheaper for both sides than a held stream.
///
/// The count of joins actually in flight also feeds `Difficulty::adapted_for_load`, which raises
/// the proof-of-work a joiner must do as the load climbs. That knob existed all along and was
/// passed a hardcoded `0`, so it had never once adapted.
const JOINS_IN_FLIGHT: usize = 16;

/// How many identity-passphrase checks may run at once.
///
/// A check is production Argon2id at ≥256 MiB (`sek::ADR_MIN_M_COST_KIB`). It runs off the
/// actor (V210-26), and unbounded that let any client of the control socket — an agent
/// session running model-authored code, by ADR-020 §7's own threat model — start one per
/// request: 32 concurrent `vox trust list`s with any passphrase is ~8 GiB. A wrong
/// passphrase costs as much as a right one, so nothing can refuse early. Checks beyond this
/// many wait for a slot in a task of their own, off the actor, so the node keeps serving.
const VERIFIES_IN_FLIGHT: usize = 2;

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
        NetEvent::RoomStored { .. } => "evaluating a room whose log grew",
        NetEvent::SlotFreed => "starting a queued sync",
        NetEvent::BackoffExpired { .. } => "retrying a sync whose backoff is due",
        NetEvent::SkdmRefused { .. } => "re-owing a key the recipient did not take",
        NetEvent::PublishDone { .. } => "filing what a board said to a publish",
        NetEvent::RepublishTo { .. } => "publishing a refused record again",
        NetEvent::StaleGraceOver { .. } => "naming a refusal no republish cured",
        NetEvent::PublishRetry { .. } => "retrying a publish round that failed",
        NetEvent::SkdmTaken { .. } => "noting a key the recipient took",
        NetEvent::JoinAnswered { .. } => "filing a join that finished",
        NetEvent::BoardGrew { .. } => "passing on a record that landed on our board",
        NetEvent::ChannelSealed { .. } => "finishing a room whose key was sealed",
        NetEvent::Dialed { .. } => "adopting a connection a join dialled",
        NetEvent::JoinerDone { .. } => "finishing a join",
        NetEvent::ForwardDialed { .. } => "binding a forward whose dial landed",
        NetEvent::Reopened { .. } => "holding a room that reopened",
        NetEvent::ReopenGone { .. } => "forgetting a room that no longer exists",
        NetEvent::ReopenFinished => "answering an unlock whose rooms are held again",
        NetEvent::JoinAdmit { .. } => "admitting a joiner before accepting it",
        NetEvent::Stopped { .. } => "shutting the network down",
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

/// Whether a mapping is the IPv6 pinhole (`true`) rather than the IPv4 mapping: the two address
/// families are renewed, retried and expired independently (V210-75).
fn mapping_is_v6(m: &crate::nat::portmap::PortMapping) -> bool {
    m.method == crate::nat::portmap::Method::PcpV6Pinhole
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
            clock: crate::time::clock_with_test_skew(),
            millis_clock: crate::time::millis_clock_with_test_skew(),
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

/// The longest an anchor that keeps failing waits between dials (V210-57, #243). A lost or
/// failing anchor is dialled on the next tick, then after 1, 2, 4… seconds, doubling to this.
/// It used to be the *only* redial: every anchor was checked once per 30 s, so a node whose
/// anchor closed its connection a moment after it connected — a restarted process of an
/// identity, which the anchor still knew by its dead predecessor's connection — had no helper
/// for up to 30 s (CI run 36418572653: a first relayed connection in 30065 ms, 55 attempts).
const ANCHOR_REDIAL_SECS: u64 = 30;

/// The most addresses one dial of an anchor tries (V210-75): four rooms' worth of the
/// [`MAX_ENDPOINTS`](crate::nat::multiaddr::MAX_ENDPOINTS) one room may name for it. An anchor
/// no configuration names but several rooms share is dialled at the union of their addresses,
/// taken a room at a time (each room's first, then each one's second, …) so every room's
/// best address is in the first dial. Launched at the staggered-start interval (250 ms) they
/// all start inside one per-candidate timeout (10 s). A union larger than this is walked a
/// window at a time: each failed dial moves on to the next, so no room's address is left out
/// for good — capping it at one room's eight, as it was, left a second room's working address
/// undialled whenever the first room already named eight dead ones.
const ANCHOR_DIAL_CANDIDATES: usize = 4 * crate::nat::multiaddr::MAX_ENDPOINTS;

/// An anchor connection lost within this long of being made counts as a **failure** for the
/// backoff, not as a loss to redial at once (V210-57): two live processes of one identity (a
/// copied profile, an old binary) supersede each other at the anchor, and redialling each loss at
/// once would make that a loop at the tick's rate. Backed off, it settles to one try per
/// [`ANCHOR_REDIAL_SECS`].
const ANCHOR_FLAP_SECS: u64 = 10;

/// The first wait before a port-mapping renewal that got nothing back is tried again (V210-75),
/// doubling to [`MAPPING_RETRY_MAX_SECS`]. A gateway that is restarting, or a request lost on
/// the way, must not end renewal for the life of the node.
const MAPPING_RETRY_SECS: u64 = 15;

/// The longest wait between retries of a failed port-mapping renewal.
const MAPPING_RETRY_MAX_SECS: u64 = 600;

/// What a sync session runs against: a member's channel, or an anchor's copy.
enum SessionTarget {
    Channel(SharedChannel),
    Anchored(Arc<tokio::sync::Mutex<crate::node::anchor::AnchorState>>),
}

/// Run one sync session on a blocking thread and return its report (ADR-025). The worker holds
/// `slot` (an outbound session's) until it exits, so slots bound running workers; it stops at its
/// next room step or transport operation once `fence` is retired, which an abort of the calling
/// task cannot do; and each batch it persists is reported at once as [`NetEvent::RoomStored`],
/// independently of the result, which a retired attempt's port ignores.
#[allow(clippy::too_many_arguments)]
async fn run_session_worker(
    target: SessionTarget,
    store: Arc<crate::node::store::Store>,
    transport: crate::transport::quic::QuicStreamTransport,
    now: u64,
    fence: Arc<crate::transport::stream_transport::Fence>,
    tx: mpsc::Sender<NetEvent>,
    channel_id: Digest32,
    slot: Option<crate::node::ports::Slot>,
) -> crate::node::channel::SessionReport {
    let joined = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        let mut t = transport;
        let on_stored = || {
            let _ = tx.blocking_send(NetEvent::RoomStored { channel_id });
        };
        // The room is locked inside each protocol step only, never across the network
        // (`sync_over_room`).
        match target {
            SessionTarget::Channel(shared) => crate::node::channel::ChannelState::sync_over_room(
                &shared, &store, &mut t, now, &fence, &on_stored,
            ),
            SessionTarget::Anchored(state) => crate::node::anchor::AnchorState::sync_over_room(
                &state, &store, &mut t, &fence, &on_stored,
            ),
        }
    })
    .await;
    // A session that panicked still reports: `Err` from the join is the panic.
    joined.unwrap_or_else(|_| {
        crate::node::channel::SessionReport::failed(crate::node::channel::SyncFailure::Panicked)
    })
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
        /// The connection the join arrived on, held until the exchange ends: see
        /// `Node::answer_inbound_join`.
        conn: Arc<VoxConnection>,
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
        /// The peer it was reconciled with.
        peer: Digest32,
        /// The attempt's token (ADR-025 D1a): a result for a retired one changes nothing.
        token: crate::node::ports::Token,
        /// What the session did, and why it stopped if it did not complete.
        report: crate::node::channel::SessionReport,
    },
    /// A session's worker persisted entries (ADR-025 D1a): the room's generation moved, so its
    /// ports are evaluated — reported on its own, because a retired worker's result is ignored
    /// while what it stored stays.
    RoomStored {
        /// The room.
        channel_id: Digest32,
    },
    /// An outbound slot was given back (ADR-025 D6).
    SlotFreed,
    /// A port's backoff is due (ADR-025 D5).
    BackoffExpired {
        /// The room.
        channel_id: Digest32,
        /// The peer.
        peer: Digest32,
        /// The wakeup's identity; a stale one is ignored.
        timer: u64,
    },
    /// A sender key written to `peer` was taken: it is recorded as delivered (V210-88), and any
    /// backoff on re-sending to it ends.
    SkdmTaken {
        /// The room.
        channel_id: Digest32,
        /// The member that took it.
        peer: Digest32,
        /// The generation it took.
        chain_id: u64,
        /// The serial of the session the key was sealed under: the peer holds it (V210-89).
        session: Option<u64>,
        /// Whether it was one of the keys of the history `peer` was owed.
        history: bool,
        /// The [`Node::delivery_epoch`] its watcher started in.
        epoch: u64,
    },
    /// A sender key written to `peer` was not taken (see `pairwise_stream::refused`): it is owed
    /// again, and the tick re-sends it.
    SkdmRefused {
        /// The room.
        channel_id: Digest32,
        /// The member it was for.
        peer: Digest32,
        /// The generation that did not land.
        chain_id: u64,
        /// What the recipient's side said.
        why: String,
        /// The serial of the session the key was sealed under (V210-78).
        session: Option<u64>,
        /// Whether it was one of the keys of the history `peer` was owed.
        history: bool,
        /// The [`Node::delivery_epoch`] its watcher started in.
        epoch: u64,
    },
    /// A publish round to a board ended (see `publish_channel_to_anchor`).
    PublishDone {
        /// The room.
        channel_id: Digest32,
        /// The board it went to.
        board: Digest32,
        /// Each kind of record and the board's refusal of it, if any.
        outcomes: Vec<(&'static str, Option<String>)>,
        /// Whether the round **failed** rather than finished: the stream would not open, a put
        /// died on the transport, or the board answered nothing within `ANCHOR_PUBLISH_PATIENCE`.
        /// A refusal is an answer, not a failure — retrying one would be asked the same thing.
        failed: bool,
    },
    /// A failed publish round's backoff is up: try that `(room, board)` again.
    PublishRetry {
        /// The room.
        channel_id: Digest32,
        /// The board.
        board: Digest32,
    },
    /// Publish this room's records to `board` again: sent just past the next second by the
    /// `PublishDone` handler when the board refused one of this node's **own** records as stale.
    RepublishTo {
        /// The room.
        channel_id: Digest32,
        /// The board that refused.
        board: Digest32,
    },
    /// The grace for one of this node's own records refused as stale is over: said now if no
    /// round since has cured it (see `report_publish`).
    StaleGraceOver {
        /// The room.
        channel_id: Digest32,
        /// The record and board, as `report_publish` keys them.
        what: String,
        /// The board's refusal.
        why: String,
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
    /// A joiner's task dialled a peer: adopt the connection now, so its streams are served while
    /// the join is still running over it.
    Dialed {
        /// The connection.
        conn: Arc<crate::transport::quic::VoxConnection>,
        /// The endpoints it was dialled at, for a later path upgrade.
        endpoints: crate::nat::multiaddr::EndpointList,
        /// Whether it is the board the join reads from (and so an anchor of ours).
        board: bool,
    },
    /// A room this node held open before it stopped has been reopened off the actor (#208):
    /// hold it, unless it was closed or the identity locked while it was opening.
    Reopened {
        /// The room.
        channel_id: Digest32,
        /// Its state, opened from the SEK kept sealed under the identity.
        channel: Box<ChannelState>,
    },
    /// A room in the reopen set no longer exists in the store: forget it (#208).
    ReopenGone {
        /// The room.
        channel_id: Digest32,
    },
    /// The reopening has tried every room (#208). A room still marked as reopening would not
    /// open: it stays remembered, and closed. The unlock is answered now.
    ReopenFinished,
    /// A forward's first dial finished (#215): bind the forward, or say why not, and answer the
    /// command.
    ForwardDialed {
        /// The room.
        channel_id: Digest32,
        /// The host.
        host: Digest32,
        /// The service asked for.
        service_tag: String,
        /// The local address to bind.
        local: std::net::SocketAddr,
        /// What the dial came to. Boxed: an error is larger than everything else here.
        result: Box<crate::error::Result<()>>,
        /// The `Forward` command's reply.
        reply: oneshot::Sender<Outcome>,
    },
    /// A joiner's task finished: make the room, or say why not, and answer the command.
    JoinerDone {
        /// The `JoinChannel` command's reply.
        reply: oneshot::Sender<Outcome>,
        /// The link joined with.
        parsed: Box<crate::node::link::InviteLink>,
        /// The room's local name.
        local_name: String,
        /// The passphrase, kept by the room's state.
        passphrase: Secret,
        /// When the join began.
        now: u64,
        /// This node's fingerprint.
        me: Digest32,
        /// What the join came to. Boxed: a won join carries a whole session.
        result: Box<std::result::Result<JoinerWon, JoinerLost>>,
    },
    /// A room's key was sealed under its passphrase on a blocking thread (the slow part of
    /// creating a room): finish the room and answer the command that asked for it.
    ChannelSealed {
        /// The `CreateChannel` command's reply, answered once the room exists.
        reply: oneshot::Sender<Outcome>,
        /// The room's local name.
        local_name: String,
        /// The passphrase, kept by the room's state.
        passphrase: Secret,
        /// The genesis made before the seal.
        genesis: Box<crate::governance::genesis::Genesis>,
        /// When the room was begun.
        now: u64,
        /// The room key and its sealed wrap, or why sealing failed.
        sealed: crate::error::Result<(crate::atrest::sek::Sek, crate::atrest::SekWrap)>,
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
    Stopped {
        /// The network whose accept loop it was. The event can arrive after a lock and an unlock
        /// have replaced that network with a new one, which it must leave alone (V210-80).
        net: std::sync::Weak<NodeNet>,
    },
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
    // **The loop does not hold the connection; it holds a way to reach it.** Waiting for
    // streams needs only the quinn handle, and a stream that arrives needs the
    // `VoxConnection` only for as long as it is served, so the loop keeps a `Weak` and
    // upgrades it per stream.
    //
    // Holding the `Arc` here made every connection look carried for its whole life. A
    // connection's strong count is how `ConnectionManager::retire_expired` tells a retired
    // path that is still carrying a tunnel from one that is not, and with this loop in the
    // count it was never below two: a relayed connection displaced by a direct one was
    // never closed, and its circuit held a relay slot until the relay's idle timeout. With
    // the loop out of the count, what remains is what the count is meant to measure — the
    // manager, and whatever is serving a stream or splicing a tunnel on it.
    let quic = conn.quinn().clone();
    let conn = Arc::downgrade(&conn);
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
            // **The kinds this node serves to completion get a task each.** `accept_stream`
            // served them inline — `dispatch`'s own doc says to put it on its own task when
            // accepting in a loop, and this loop did not — so while one was being served no other
            // stream from this peer was even accepted. A rendezvous stream holds its server until
            // the client finishes or a 20s frame read gives up; a circuit's opening exchange waits
            // on the *target* peer's answer, which is another node's loop. On an anchor that put a
            // member's next board `put` behind whatever that member's last stream was waiting for,
            // 20s at a time, and the member's actor — which awaits its puts — answered nobody for
            // 30s, 60s, 80s, measured through the real binaries.
            //
            // Only these three. Every other kind is handed on in the order it arrived, as before:
            // a pairwise hello and the key that follows it are separate streams, and reordering
            // them is exactly the race F12 was.
            let (kind, send, recv) = match net.accept_authorized_on(&quic, peer).await {
                Ok(accepted) => accepted,
                // **A refusal is not a failure.** The stream was typed and answered; the peer
                // may not open that kind *yet* — a joiner syncing before it is a member, a
                // responder pushing before the room is held here — and it will be allowed once
                // the view catches up. Counted, sixteen of those ended this loop while the
                // connection stayed filed, and every stream the peer opened after that, allowed
                // or not, went unserved for the connection's life (V210-80). It cannot spin:
                // each one is a stream the peer opened.
                Err(crate::error::Error::StreamRefused(_)) => continue,
                Err(_) => {
                    if quic.close_reason().is_some() {
                        break; // the peer or the network closed it
                    }
                    failures += 1;
                    if failures >= MAX_CONSECUTIVE_STREAM_FAILURES {
                        // Closed, not only abandoned: a connection nobody serves must not stay
                        // filed as this peer's, or both ends go on using it for nothing.
                        quic.close(
                            crate::transport::quic::close_code(
                                crate::wire::WireError::TransportFailed,
                            ),
                            b"stream failures",
                        );
                        break;
                    }
                    continue;
                }
            };
            // Nobody holds the connection any more: the node has let it go, and a stream
            // arriving on it has nothing to be served against.
            let Some(conn) = conn.upgrade() else {
                break;
            };
            if matches!(
                kind,
                crate::transport::streams::StreamKind::Rendezvous
                    | crate::transport::streams::StreamKind::Coord
                    | crate::transport::streams::StreamKind::Circuit
            ) {
                failures = 0;
                let net = Arc::clone(&net);
                let conn = Arc::clone(&conn);
                let tx = tx.clone();
                tokio::spawn(async move {
                    // A coordination stream can end by handing the actor a punch to run.
                    if let Ok(inbound @ Inbound::Punch { .. }) =
                        net.dispatch(&conn, kind, send, recv).await
                    {
                        let _ = tx
                            .send(NetEvent::Stream {
                                conn: Arc::clone(&conn),
                                inbound,
                            })
                            .await;
                    }
                });
                continue;
            }
            match net.dispatch(&conn, kind, send, recv).await {
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
                    let conn = Arc::clone(&conn);
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
                    if quic.close_reason().is_some() {
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
/// **Each connection's handshake runs on its own task, bounded, and the accept loop
/// never waits for one.** Phase two (`finish_incoming`: the TLS handshake and admission,
/// itself bounded at `HANDSHAKE_TIMEOUT`) is spawned per attempt, which is quinn's own
/// documented shape — `finish_incoming` says "Spawn this; do not await it in an accept
/// loop".
///
/// # What awaiting it inline cost
/// Until v0.2.8 this loop awaited phase two, so it handled one handshake at a time. Two
/// consequences, both measured:
///
/// - **A pre-authentication denial of service.** One peer that opened a connection and
///   stalled its handshake blocked every other inbound connection for up to 30s, with no
///   credential of any kind. Worst against an anchor, the node most likely to be public.
/// - **The same stall with no attacker at all.** `vox connect` exits the moment it has
///   joined, which leaves the host mid-handshake, so a second person joining right after
///   the first was locked out for 30s. `order4.sh` (a host and two back-to-back joiners)
///   locked the second joiner out 5 of 5 on a quiet box, and the stranger's join in
///   `service_rehearsal_proof` failed the same way.
///
/// # Why it stayed inline so long
/// ADR-017 recorded the split as tried and reverted: `m15_two_clients_behind_symmetric_
/// nats…` timed out at 247s with it and passed serialised. That 247s was **not** the split.
/// It was sync starvation — a room's in-flight mark let a failing anchor session take the
/// room first every round, so the direct member session never ran — and it hit the
/// serialised loop too, in 9 of ~15 CI runs on `main`. The evidence against the split was
/// a different defect with the same signature.
///
/// With that fixed (the owed-room change in the old `run_due_syncs`, now ADR-025's ports) the split exposed one real
/// dependency on the serial order, and it was not in this loop: `ConnectionManager`'s
/// duplicate tie-break was "the held connection wins", which the two ends of a pair only
/// agree on if they file the pair in the same order. Concurrent handshakes broke that, and a
/// node could be left holding a connection its peer had closed (see `tie_key` in
/// `node::net`). Measured with both ends logging each connection's exporter tag: 2 of 5
/// duplicate pairs disagreed before the tie-break became order-independent, 0 of 28 after.
///
/// # The bound, and what a flood costs
/// At most [`HANDSHAKES_IN_FLIGHT`] handshakes run at once. At the cap an attempt is never
/// queued — queueing would put the wait back into this loop:
///
/// - an attempt whose source address is **not yet validated** gets `retry()`, a QUIC Retry
///   packet that makes the client prove it can receive at the address it claims before
///   anything is allocated. A spoofed flood cannot answer one; a real peer pays one round
///   trip. Before this, one spoofed packet cost an attacker a packet and cost the node a
///   handshake slot.
/// - an attempt that **is** validated gets `refuse()`, because for a peer that has proven
///   itself the honest answer is "not now", not another round trip.
///
/// **Residual, stated rather than implied:** 64 *validated* handshakes that stall still
/// deny service for up to `HANDSHAKE_TIMEOUT` each. Bounded, and far better than a single
/// slot, but not nothing.
fn spawn_accept_loop(net: Arc<NodeNet>, tx: mpsc::Sender<NetEvent>) {
    let gone = Arc::downgrade(&net);
    tokio::spawn(async move {
        let gate = Arc::new(tokio::sync::Semaphore::new(HANDSHAKES_IN_FLIGHT));
        loop {
            let Some(incoming) = net.manager().accept_incoming().await else {
                break;
            };
            let Ok(permit) = Arc::clone(&gate).try_acquire_owned() else {
                if incoming.remote_address_validated() {
                    incoming.refuse();
                } else {
                    // `Err` means this attempt is already a retried one; retrying it again
                    // would loop, so it is simply dropped.
                    let _ = incoming.retry();
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
        if let Some(ms) = test_stopped_delay_ms() {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
        let _ = tx.send(NetEvent::Stopped { net: gone }).await;
    });
}

/// **For proofs only.** When set, the accept loop waits this many milliseconds between stopping
/// and saying so (`NetEvent::Stopped`), which stands for an actor queue that is full or a task that
/// is scheduled late. The lock-and-unlock proof uses it to land the event after an unlock started
/// a new network. Nothing a person runs sets it; unset, nothing changes.
pub const TEST_STOPPED_DELAY_ENV: &str = "VOX_TEST_STOPPED_DELAY_MS";

fn test_stopped_delay_ms() -> Option<u64> {
    std::env::var(TEST_STOPPED_DELAY_ENV).ok()?.parse().ok()
}

/// **For proofs only.** When set to `N`, the node loses the first `N` pairwise streams that
/// carry a hello: it resets them unread, as a stream lost with its connection is, so the sender
/// learns only that its key was not taken. The simultaneous-session proof uses it to force what a
/// duplicate-connection close did by chance (V210-89): each member's hello lost after it was
/// written. Nothing a person runs sets it; unset, nothing changes.
pub const TEST_LOSE_HELLOS_ENV: &str = "VOX_TEST_LOSE_HELLOS";

/// Whether this inbound hello is one [`TEST_LOSE_HELLOS_ENV`] says to lose.
fn test_lose_hello() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LEFT: std::sync::OnceLock<AtomicU64> = std::sync::OnceLock::new();
    LEFT.get_or_init(|| {
        AtomicU64::new(
            std::env::var(TEST_LOSE_HELLOS_ENV)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        )
    })
    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
    .is_ok()
}

/// How many inbound handshakes may run at once.
///
/// Inline, the ceiling was one, which was the defect. This is the same bound in spirit as
/// [`JOINS_IN_FLIGHT`]: enough that ordinary use never reaches it, small enough that an
/// attacker cannot make a node hold unbounded state.
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
    //
    // The reader needs no bound of its own: a stream loop does not hold its connection, so
    // it ends when `retire_expired` closes the retired one and cannot keep it from closing.
    if let Some(also) = filed.also_serve {
        spawn_stream_loop(Arc::clone(net), also, tx.clone());
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

/// How long this node's own record refused as stale goes unreported: long enough for the republish
/// past the next second (`NetEvent::RepublishTo`) to land, short enough that a refusal it does not
/// cure is named while somebody is still looking.
const STALE_REFUSAL_GRACE: u64 = 5;

/// How many times in a row a node republishes one of its own records to a board that refused it as
/// stale: enough to get past the second the refused one was signed in, with room for a clock that
/// steps, and few enough that a real refusal stops being retried.
const STALE_REPUBLISH_TRIES: u32 = 3;

/// How far the first republish after a stale refusal moves this process's record `seq` floor
/// past its clock, in milliseconds; each later try doubles it (see `NetEvent::PublishDone`).
const STALE_SEQ_STEP_MS: u64 = 2_000;

/// How far ahead of this process's clock a stale republish may carry its record's `seq` and
/// `timestamp` floors, in milliseconds (V210-64). Enough for three tries' steps; bounded, so two
/// live processes of one identity refusing each other in turn cannot drive the floors ever further
/// ahead — each only ever reaches this, and a real conflict is said, not outrun.
const STALE_AHEAD_MAX_MS: u64 = 16_000;

/// Whether a publish outcome is one of this node's **own** records refused by the board as stale.
fn own_stale_refusal(kind: &str, why: &Option<String>) -> bool {
    matches!(kind, "our address" | "our member bundle")
        && why
            .as_deref()
            .is_some_and(|w| w.contains(crate::nat::service::RejectReason::Stale.as_str()))
}

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
/// Everything the network half of a join needs, captured on the actor so the half can run on a
/// task of its own. See `Node::begin_join_channel`.
struct Joiner {
    net: Arc<NodeNet>,
    tx: mpsc::Sender<NetEvent>,
    me: Digest32,
    parsed: crate::node::link::InviteLink,
    routes: Vec<(Digest32, crate::nat::multiaddr::EndpointList)>,
    signer: Arc<crate::atrest::vault::VaultRootSigner>,
    ring: Arc<tokio::sync::Mutex<PrekeyRing>>,
    seq: u64,
    now: u64,
    pow_params: Option<crate::join::pow::PowParams>,
    argon2: Argon2Profile,
    passphrase: Secret,
    /// Where each step is announced as it begins: see [`NodeEvent::JoinStep`].
    events: broadcast::Sender<NodeEvent>,
}

/// A caller's reply carried by a task that [`Node::lock_all`] may abort (V210-76): answered
/// `Locked` if the task is dropped before it hands the reply on, so the caller is told what
/// happened rather than that the node went away.
struct AnsweredIfAborted(Option<oneshot::Sender<Outcome>>);

impl AnsweredIfAborted {
    /// The reply, for the task to pass on now that it was not aborted.
    fn into_reply(mut self) -> Option<oneshot::Sender<Outcome>> {
        self.0.take()
    }
}

impl Drop for AnsweredIfAborted {
    fn drop(&mut self) {
        if let Some(reply) = self.0.take() {
            let _ = reply.send(Outcome::Failed(Fault::Locked));
        }
    }
}

/// A join that got in: what the actor needs to make the room.
struct JoinerWon {
    joined: crate::node::joinstream::JoinOutcome,
    responder: Digest32,
    conn: Arc<VoxConnection>,
    set: crate::nat::service::RecordSet,
    genesis: crate::governance::genesis::Genesis,
    sealed: (crate::atrest::sek::Sek, crate::atrest::SekWrap),
    /// How long each step took: see `JoinSteps`.
    steps: JoinSteps,
}

/// A join that did not: the fault to answer with, and each responder's reason.
struct JoinerLost {
    fault: Fault,
    why: Vec<String>,
    steps: JoinSteps,
}

impl JoinerLost {
    fn of(fault: Fault) -> Self {
        Self {
            fault,
            why: Vec::new(),
            steps: JoinSteps::default(),
        }
    }
}

/// How long each step of a join took, carried on the join's own outcome so a join that failed —
/// or took 30s — says where its time went. The join ranged 1.3–33.6s end to end with the node
/// answering throughout, and "somewhere in the join" is not a diagnosis.
#[derive(Default)]
struct JoinSteps(Vec<String>);

impl JoinSteps {
    fn took(&mut self, what: &str, since: std::time::Instant) {
        self.lasted(what, since.elapsed());
    }
    fn lasted(&mut self, what: &str, d: std::time::Duration) {
        self.0.push(format!("{what} {:.2}s", d.as_secs_f64()));
    }
    fn note(&mut self, what: String) {
        self.0.push(what);
    }
    fn render(&self) -> String {
        self.0.join(", ")
    }
}

impl Joiner {
    /// Say which step the join has begun, so a join stopped part-way can name it (V210-85).
    fn begin(&self, step: String) {
        let _ = self.events.send(NodeEvent::JoinStep { step });
    }

    /// Dial a peer, and tell the actor at once so it serves the connection's streams — the
    /// responder talks to us over it during the join itself.
    async fn dial(
        &self,
        peer: Digest32,
        endpoints: &crate::nat::multiaddr::EndpointList,
        board: bool,
    ) -> crate::error::Result<Arc<VoxConnection>> {
        Self::dial_with(&self.net, &self.tx, peer, endpoints, board).await
    }

    /// [`Self::dial`] with what it needs passed in, so several can run on tasks of their own.
    async fn dial_with(
        net: &Arc<NodeNet>,
        tx: &mpsc::Sender<NetEvent>,
        peer: Digest32,
        endpoints: &crate::nat::multiaddr::EndpointList,
        board: bool,
    ) -> crate::error::Result<Arc<VoxConnection>> {
        let conn = net.reach(peer, endpoints).await?;
        let _ = tx
            .send(NetEvent::Dialed {
                conn: Arc::clone(&conn),
                endpoints: endpoints.clone(),
                board,
            })
            .await;
        Ok(conn)
    }

    /// A board for this join: every route dialled at once, the room's own anchors preferred for a
    /// short grace, then whichever has answered (Happy Eyeballs, RFC 8305).
    ///
    /// **Not one after another.** The routes were dialled in turn, so a route this node cannot
    /// use held up every route after it for its full timeout: an IPv6-only member whose address
    /// advertised the room's anchor and host on IPv4 reached its own IPv6 anchor — reachable the
    /// whole time — after `board 20.76s`, measured through the real binaries (#197; PRD-001 R42
    /// asks for under 2s).
    ///
    /// **Preferred, not waited for.** The order still matters: the link's own anchors come first
    /// because they are the boards that hold the room, and a joiner's own anchor may not. But
    /// waiting for every earlier route to *fail* would only halve a 20s wait, since a route that
    /// cannot be reached fails by timing out. So once any route has answered, an earlier one gets
    /// [`BOARD_PREFERENCE_GRACE`] to answer too; after that, the earliest route that **has**
    /// answered is taken and the slower ones are dropped.
    async fn reach_a_board(&self) -> Option<Arc<VoxConnection>> {
        let deadline = tokio::time::Instant::now() + Node::BOARD_PATIENCE;
        loop {
            let mut dials = tokio::task::JoinSet::new();
            for (at, (id, endpoints)) in self.routes.iter().enumerate() {
                let (net, tx, id, endpoints) = (
                    Arc::clone(&self.net),
                    self.tx.clone(),
                    *id,
                    endpoints.clone(),
                );
                dials.spawn(async move {
                    (
                        at,
                        Self::dial_with(&net, &tx, id, &endpoints, true).await.ok(),
                    )
                });
            }
            // Per route: `None` while it is still dialling, `Some(answer)` once it has settled.
            let mut settled: Vec<Option<Option<Arc<VoxConnection>>>> =
                vec![None; self.routes.len()];
            let mut grace_ends: Option<tokio::time::Instant> = None;
            loop {
                // The earliest route that answered, and whether any route before it is still
                // dialling (and so might yet be preferred).
                let best = settled.iter().position(|o| matches!(o, Some(Some(_))));
                if let Some(best) = best {
                    let earlier_pending = settled[..best].iter().any(Option::is_none);
                    let grace_over = grace_ends.is_some_and(|t| tokio::time::Instant::now() >= t);
                    if !earlier_pending || grace_over {
                        if let Some(Some(conn)) = &settled[best] {
                            return Some(Arc::clone(conn));
                        }
                    }
                    grace_ends.get_or_insert_with(|| {
                        tokio::time::Instant::now() + BOARD_PREFERENCE_GRACE
                    });
                }
                let next = match grace_ends {
                    Some(t) => tokio::time::timeout_at(t, dials.join_next()).await,
                    None => Ok(dials.join_next().await),
                };
                match next {
                    Ok(Some(Ok((at, conn)))) => settled[at] = Some(conn),
                    Ok(Some(Err(_))) => {} // a dial task that panicked: nothing to take
                    Ok(None) => break,     // every route settled, none answered
                    Err(_) => {}           // the grace is up: the loop takes the best answer
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Node::BOARD_RETRY).await;
        }
    }

    /// The network half of a join, and the room key's seal: the old inline `join_channel` from
    /// reaching a board to the end of the exchange, unchanged in order and in its refusals.
    async fn run(self) -> std::result::Result<JoinerWon, JoinerLost> {
        let mut steps = JoinSteps::default();
        let result = self.run_steps(&mut steps).await;
        match result {
            Ok(mut won) => {
                won.steps = steps;
                Ok(won)
            }
            Err(mut lost) => {
                lost.steps = steps;
                Err(lost)
            }
        }
    }

    async fn run_steps(&self, steps: &mut JoinSteps) -> std::result::Result<JoinerWon, JoinerLost> {
        let parsed = &self.parsed;
        let net = Arc::clone(&self.net);
        let t = std::time::Instant::now();
        self.begin(format!("reaching a board ({} route(s))", self.routes.len()));
        // **Which side was unreachable is part of the answer (#192).** A board that never answered,
        // or stopped answering while it was read, is `BoardUnreachable`; `Unreachable` below is
        // kept for a join whose board answered and whose members did not.
        let Some(board) = self.reach_a_board().await else {
            steps.took("board (unreached)", t);
            return Err(JoinerLost::of(Fault::BoardUnreachable));
        };
        steps.took("board", t);
        let t = std::time::Instant::now();
        self.begin(format!(
            "reading the room from board {}",
            crate::node::network::short_id(board.peer_id())
        ));
        let fetched = net.fetch_channel(&board, &parsed.channel_id, 0).await;
        steps.took(
            if fetched.is_ok() {
                "fetch"
            } else {
                "fetch (failed)"
            },
            t,
        );
        let mut set = fetched.map_err(|e| JoinerLost::of(on_the_board(fault_of(&e))))?;
        // **A board that does not hold the room is not a malformed address.** The link parsed and
        // named a room; the board we reached has nothing for it. That is either a room its host has
        // not published there yet, or a room id mistyped into another valid one (a link carries no
        // checksum), and the board cannot tell which. Say which board and which room, so the person
        // can check both, and let the advice name the two causes.
        let Some(genesis) = set.genesis.clone() else {
            return Err(JoinerLost {
                fault: Fault::RoomNotOnBoard,
                why: vec![format!(
                    "board {} has nothing for room {}",
                    crate::node::network::short_id(board.peer_id()),
                    crate::node::network::short_id(parsed.channel_id)
                )],
                steps: JoinSteps::default(),
            });
        };
        let me = self.me;
        let candidates: Vec<Digest32> = {
            use std::collections::BTreeSet;
            let with_address: BTreeSet<Digest32> = set
                .members
                .iter()
                .filter(|r| !r.endpoints.is_empty())
                .map(|r| r.author_id)
                .collect();
            let mut known: BTreeSet<Digest32> = set.members.iter().map(|r| r.author_id).collect();
            known.extend(set.bundles.iter().map(|b| b.author_id));
            if let Some(g) = set.genesis.as_ref() {
                known.insert(g.body.creator_pubkey.fingerprint());
            }
            known.remove(&me);
            let mut reachable: Vec<Digest32> = known.intersection(&with_address).copied().collect();
            let mut awaited: Vec<Digest32> = known.difference(&with_address).copied().collect();
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
                return Err(JoinerLost::of(Fault::BadLink));
            }
            ordered.truncate(MAX_JOIN_RESPONDERS);
            ordered
        };
        let prejoin_wire = {
            let signer: &crate::atrest::vault::VaultRootSigner = &self.signer;
            let ring = self.ring.lock().await;
            let bundle = ring
                .bundle(&crate::identity::composite::RootSigner::public_key(signer))
                .map_err(|e| JoinerLost::of(fault_of(&e)))?;
            let endpoints = net
                .local_endpoints()
                .map_err(|e| JoinerLost::of(fault_of(&e)))?;
            crate::nat::record::PreJoinRecord::build(
                signer,
                &parsed.channel_id,
                bundle,
                endpoints,
                self.seq,
                self.now,
            )
            .map_err(|e| JoinerLost::of(fault_of(&e)))?
            .to_wire()
        };
        let t = std::time::Instant::now();
        self.begin(format!(
            "announcing this joiner to board {}",
            crate::node::network::short_id(board.peer_id())
        ));
        let announced = announce(&board, &prejoin_wire).await;
        if announced.is_err() {
            steps.took("announce to the board (failed)", t);
        }
        announced.map_err(|e| JoinerLost::of(on_the_board(fault_of(&e))))?;
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
            let short = crate::node::network::short_id(responder);
            if responder_endpoints.is_empty() && board.peer_id() != responder {
                let t = std::time::Instant::now();
                self.begin(format!("waiting for member {short} to publish an address"));
                let mut polls = 0u32;
                let deadline = tokio::time::Instant::now() + JOIN_ADDRESS_PATIENCE;
                while tokio::time::Instant::now() < deadline {
                    polls += 1;
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
                        responder_endpoints = found;
                        set = fresh;
                        break;
                    }
                }
                steps.note(format!(
                    "{short}: address poll ×{polls} {:.2}s{}",
                    t.elapsed().as_secs_f64(),
                    if responder_endpoints.is_empty() {
                        " (none)"
                    } else {
                        ""
                    }
                ));
            }
            // Before the exchange: its key comes back the moment it admits us (see
            // `PeerClass::JoinResponder`).
            self.net.policy().expect_join_responder(responder);
            let conn = if board.peer_id() == responder {
                Arc::clone(&board)
            } else {
                let t = std::time::Instant::now();
                self.begin(format!("dialling member {short}"));
                let dialled = self.dial(responder, &responder_endpoints, false).await;
                steps.took(&format!("{short}: dial"), t);
                match dialled {
                    Ok(c) => {
                        if let Err(e) = announce(&c, &prejoin_wire).await {
                            last_fault = fault_of(&e);
                            // Said, as a failed dial is: a join that failed here reported no
                            // reason at all (V210-83).
                            why.push(format!("{short}: announce: {e}"));
                            if !worth_another_responder(last_fault) {
                                return Err(JoinerLost {
                                    fault: last_fault,
                                    why,
                                    steps: JoinSteps::default(),
                                });
                            }
                            continue;
                        }
                        c
                    }
                    Err(e) => {
                        last_fault = fault_of(&e);
                        why.push(format!(
                            "{}: {e}",
                            crate::node::network::short_id(responder)
                        ));
                        if !worth_another_responder(last_fault) {
                            return Err(JoinerLost {
                                fault: last_fault,
                                why,
                                steps: JoinSteps::default(),
                            });
                        }
                        continue;
                    }
                }
            };
            let signer: &crate::atrest::vault::VaultRootSigner = &self.signer;
            let dh = *signer.x25519_identity_secret();
            let mut ctx = crate::node::channel::join_context_from_genesis(&genesis, 0)
                .map_err(|e| JoinerLost::of(fault_of(&e)))?;
            if let Some(pow) = self.pow_params {
                ctx.pow_params = pow;
            }
            let ik = crate::identity::keyagreement::X25519IdentityKey::from_secret_bytes(dh);
            let t = std::time::Instant::now();
            self.begin(format!(
                "the join exchange with member {short} (this machine's proof of work, then \
                 the member's answer)"
            ));
            let exchanged = net
                .start_join(&conn, ctx, &self.passphrase, signer, &ik)
                .await;
            // **The solve apart from the rest** (V210-62): the proof of work is this machine's
            // own CPU and random in length by design, the rest is waiting on the responder. One
            // number for both left a slow join unexplained (CI: 13.3 s, which was which?).
            match &exchanged {
                Ok(o) => {
                    steps.lasted(&format!("{short}: solve"), o.solved_in);
                    steps.lasted(
                        &format!("{short}: exchange"),
                        t.elapsed().saturating_sub(o.solved_in),
                    );
                }
                Err(_) => steps.took(&format!("{short}: exchange (incl. solve)"), t),
            }
            match exchanged {
                Ok(o) => {
                    joined_outcome = Some((o, responder, conn));
                    break;
                }
                Err(e) => {
                    last_fault = fault_of(&e);
                    // Why this member did not take us, when this side knows: its patience ran out
                    // on our grind (V210-87), which the fault alone cannot carry the numbers of;
                    // or anything else the exchange met, which was left unsaid (V210-83).
                    if last_fault == Fault::SolveTooSlow {
                        why.push(format!("{short}: {e}"));
                    } else {
                        why.push(format!("{short}: exchange: {e}"));
                    }
                    if !worth_another_responder(last_fault) {
                        return Err(JoinerLost {
                            fault: last_fault,
                            why,
                            steps: JoinSteps::default(),
                        });
                    }
                }
            }
        }
        let Some((joined, responder, conn)) = joined_outcome else {
            return Err(JoinerLost {
                fault: last_fault,
                why,
                steps: JoinSteps::default(),
            });
        };
        // The room key, sealed under the passphrase with production Argon2id — seconds of CPU,
        // on a blocking thread and not the actor.
        let sek = crate::atrest::sek::Sek::generate().map_err(|e| JoinerLost::of(fault_of(&e)))?;
        let (signer, channel_id, passphrase, argon2) = (
            Arc::clone(&self.signer),
            parsed.channel_id,
            self.passphrase.clone(),
            self.argon2,
        );
        let t = std::time::Instant::now();
        self.begin("sealing the room key under the passphrase".to_owned());
        let sealed = tokio::task::spawn_blocking(move || {
            let factor = crate::atrest::idfactor::SignatureIdentityFactor::new(&*signer);
            sek.seal(&factor, &channel_id, &passphrase, argon2)
                .map(|wrap| (sek, wrap))
        })
        .await
        .unwrap_or(Err(Error::Argon2Failed))
        .map_err(|e| JoinerLost::of(fault_of(&e)))?;
        steps.took("seal", t);
        Ok(JoinerWon {
            joined,
            responder,
            conn,
            set,
            genesis,
            sealed,
            steps: JoinSteps::default(),
        })
    }
}

/// A fault met while talking to the board itself: an `Unreachable` there is the board's, not a
/// member's, and says so (#192).
const fn on_the_board(fault: Fault) -> Fault {
    match fault {
        Fault::Unreachable => Fault::BoardUnreachable,
        other => other,
    }
}

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
            | Fault::AlreadyMember
            // This device's speed, against a wait every member derives the same way: another
            // member would cost another grind as long and end the same (V210-87).
            | Fault::SolveTooSlow
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
    /// The sync counters `vox status --json` reports (ADR-025 S0b).
    sync_book: crate::node::status::SharedSyncBook,
}

impl NodeHandle {
    /// The sync counters `vox status --json` reports (ADR-025 S0b).
    #[must_use]
    pub fn sync_book(&self) -> &crate::node::status::SharedSyncBook {
        &self.sync_book
    }

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
    /// Each open room's own anchors, as the room recorded them when it was created, opened or
    /// joined: redialled after a loss like the configured set (V210-75). A room joined from an
    /// invite often has no anchor but the one its link named, and a node that dialled that
    /// anchor once and never again lost its board and its relay the first time the anchor
    /// restarted. Entries for rooms no longer open are ignored and dropped at the next redial.
    room_anchors: BTreeMap<Digest32, BootstrapSet>,
    /// An override for the ADR-005 PoW parameters a join binds. `None` means the
    /// channel's own (production `(200,9)`); tests reduce them so the debug suite
    /// does not grind, exactly as they reduce the Argon2 profile.
    pow_params: Option<crate::join::pow::PowParams>,
    /// Connections (by [`VoxConnection::serial`]) that already have a stream loop, so adopting
    /// one twice does not start a second. Keyed by connection, not by peer: an upgrade
    /// gives a peer a second connection that needs its own loop (M15.1b).
    ///
    /// **Not by quinn's stable id**, which it was: that is the address of the connection's
    /// state, reused once a closed connection is freed. A new connection that landed at a dead
    /// one's address was taken to have a loop already, nothing read the streams the peer opened
    /// on it, and a tunnel request sent there waited unanswered until the connection was closed
    /// a minute later (#243's CI red on dd78874: `vox up`'s first punched request, 61.9 s).
    /// Each entry keeps its connection weakly, so entries for connections that are gone are
    /// dropped and the map is as small as the set of live ones.
    stream_loops: std::collections::BTreeMap<u64, std::sync::Weak<VoxConnection>>,
    /// The gateway port mapping in force, if one was granted. Held so it can be
    /// renewed before its lifetime elapses (RFC 6886/6887 put renewal on the client).
    port_mappings: Vec<crate::nat::portmap::PortMapping>,
    /// Per anchor that failed to connect: when it may be dialled again (unix seconds), and the
    /// wait that set it, doubling to [`ANCHOR_REDIAL_SECS`] (V210-57). No entry: dial when
    /// needed.
    anchor_backoff: BTreeMap<Digest32, (u64, u64)>,
    /// The anchors being dialled right now, so none is dialled twice at once (V210-57): a node
    /// starting up dialled each anchor from both its start and its first tick, and the
    /// duplicate lost a tie-break against the first on every start.
    anchor_dials: Arc<std::sync::Mutex<BTreeSet<Digest32>>>,
    /// Per shared, unconfigured anchor whose rooms name more than [`ANCHOR_DIAL_CANDIDATES`]
    /// addresses: where the next dial's window starts in their union (V210-75). Moved on by
    /// each failed dial, dropped when one connects.
    anchor_window: BTreeMap<Digest32, usize>,
    /// When each anchor's current connection was made (unix seconds), so one lost soon after is
    /// told from one lost after a while ([`ANCHOR_FLAP_SECS`]).
    anchor_connected_at: BTreeMap<Digest32, u64>,
    /// The anchors this node held a connection to at the last look, so losing one is said when
    /// it happens, not only when it is next redialled (#229's diagnostics).
    anchors_up: BTreeSet<Digest32>,
    /// Peers a room's sync is dialling right now (`reach_for_sync`), so one is not dialled twice.
    sync_dials: BTreeSet<Digest32>,
    /// When the granted mappings must be renewed (unix seconds), or `None` when there
    /// is nothing to renew. A mapping a gateway grants for two hours outlives no
    /// long-running node by itself: it is re-requested at half its lifetime, the
    /// interval RFC 6887 §11.2.1 recommends.
    renew_mappings_at: Option<u64>,
    /// Per address family (`true` for the IPv6 pinhole, `false` for the IPv4 mapping), when the
    /// timed lease held for it runs out (unix seconds). Until then its mapped address is still
    /// advertised, even while its renewal is failing (V210-75).
    mapping_expires: BTreeMap<bool, u64>,
    /// Per address family, the wait set after the last renewal that got nothing back for it:
    /// doubles from [`MAPPING_RETRY_SECS`] to [`MAPPING_RETRY_MAX_SECS`], and is gone once that
    /// family is granted again (V210-75). One family's lost renewal is retried on its own clock,
    /// not at the other's half-lifetime.
    mapping_retry: BTreeMap<bool, u64>,
    /// ADR-025's sync ports, one per `(room, peer)`: see `node::ports`.
    ports: BTreeMap<(Digest32, Digest32), crate::node::ports::Port>,
    /// Ports waiting for an outbound slot (ADR-025 D6).
    port_queue: crate::node::ports::Queue,
    /// Outbound slots in use (ADR-025 D6).
    slots: crate::node::ports::SharedSlots,
    /// The next session token.
    next_token: crate::node::ports::Token,
    /// Rooms whose ports are evaluated when the current event ends (ADR-025 D6a).
    sched_rooms: std::collections::BTreeSet<Digest32>,
    /// Every port is evaluated when the current event ends.
    sched_all: bool,
    /// Peers this node has adopted a connection to; ports are discovered for them.
    connected: std::collections::BTreeSet<Digest32>,
    /// When the periodic request (ADR-025 D7) is next raised on every port, unix seconds.
    next_request_at: u64,
    /// The room instance each room's ports were last discovered for.
    discovered: BTreeMap<Digest32, crate::node::ports::RoomRef>,
    /// Rooms to discover ports for (every connected peer) when the current event ends.
    discover_rooms: std::collections::BTreeSet<Digest32>,
    /// Peers newly connected: every room is discovered for them, and their ports' backoff cleared.
    discover_peers: std::collections::BTreeSet<Digest32>,
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
    /// Slots for identity-passphrase checks; see [`VERIFIES_IN_FLIGHT`].
    verify_slots: Arc<tokio::sync::Semaphore>,
    /// The join exchanges running right now, both sides of them, and the room creations sealing
    /// their key (V210-76).
    ///
    /// Tracked rather than detached for one reason: each holds an `Arc<VaultRootSigner>`, and
    /// ADR-015 says a locked node holds no identity secrets. [`Node::lock_all`] aborts this set,
    /// so the last handle goes with the lock and "locked" keeps meaning *now* instead of *once
    /// this joiner gets bored*.
    join_tasks: tokio::task::JoinSet<()>,
    /// The sync counters `vox status --json` reports (ADR-025 S0b).
    sync_book: crate::node::status::SharedSyncBook,
    /// Rooms this node is joining right now (their join is on a `Joiner` task).
    joining: std::collections::BTreeSet<Digest32>,
    /// Rooms being reopened off the actor at unlock (#208). A room leaves this set when it is
    /// held, closed, or the identity locks; a reopened room not in it is dropped, not held.
    reopening: std::collections::BTreeSet<Digest32>,
    /// The reopening task, aborted at lock: it holds room keys, and a locked node holds none
    /// (ADR-015).
    reopen_task: Option<tokio::task::AbortHandle>,
    /// Unlock replies held until the reopening has finished (#208).
    unlock_waiters: Vec<oneshot::Sender<Outcome>>,
    /// The last `refresh_network_view` gave up on a busy room, so the view is behind and the tick
    /// rebuilds it. Atomic only because the refresh takes `&self`.
    view_stale: std::sync::atomic::AtomicBool,
    /// Pairwise streams for a room still being joined, held until the join reports back: see
    /// `take_inbound_skdm`.
    held_pairwise: Vec<(
        Digest32,
        Digest32,
        crate::node::pairwise_stream::PairwiseFrame,
        quinn::SendStream,
        quinn::RecvStream,
    )>,
    /// Per room, the members this node's board has held a bundle record for. A record from an
    /// author not in it is a member this node has just learned of, which is what
    /// `note_new_members` passes on at once; a refresh of a known member's record is not.
    board_authors: BTreeMap<Digest32, std::collections::BTreeSet<Digest32>>,
    /// `(room, board)` publish rounds in flight on their own tasks; see `publish_channel_to_anchor`.
    publishing: std::collections::BTreeSet<(Digest32, Digest32)>,
    /// Publishes asked for while that `(room, board)` round was in flight: run when it ends.
    publish_again: std::collections::BTreeSet<(Digest32, Digest32)>,
    /// How many times in a row each board has refused one of this node's own records as stale,
    /// for [`NetEvent::RepublishTo`]'s cap. Cleared by a round that went on.
    stale_retries: BTreeMap<(Digest32, Digest32), u32>,
    /// The (room, board) pairs with a `NetEvent::RepublishTo` already on its way: one at a time,
    /// so the refusals a single burst of rounds brings back arm one republish, not one each.
    republish_pending: std::collections::BTreeSet<(Digest32, Digest32)>,
    /// This node's own records a board refused as stale and has not yet taken, by
    /// `report_publish`'s key: a round that takes one says so (`NodeEvent::PublishCured`).
    stale_held: std::collections::BTreeSet<(Digest32, String)>,
    /// `(room, board)` pairs whose last publish round **failed**, with how many times in a row. A
    /// retry for each is scheduled on a backoff; see [`publish_retry_after`].
    publish_failures: std::collections::BTreeMap<(Digest32, Digest32), u32>,
    /// Creates and joins answered once their room's publish rounds have ended: see
    /// `answer_when_published`.
    publish_waiters: Vec<(Digest32, oneshot::Sender<Outcome>, Outcome)>,
    /// When a background dial to each member was last started: see `reach_member`.
    member_dialed_at: BTreeMap<Digest32, u64>,
    /// Explicit consents waiting on the network: for a member's dial (answered on `Dialed` by
    /// delivering, or on `ReachFailed` as `Unreachable`), or for that member's bundle record to
    /// reach this node's board (retried on the room's `SyncDone`). Each carries its attempts so
    /// far, so one that cannot succeed is answered rather than kept. The person gets the real
    /// outcome and the node keeps answering meanwhile.
    pending_consents: Vec<(Digest32, Digest32, oneshot::Sender<Outcome>, u8)>,
    /// Each room's view summary and detail as this node's own latest write left them, taken under the room's lock
    /// by the write itself. `view_of` uses it when a session holds the room, so a person always sees
    /// their own post in what they read straight after, however long that session holds on. A room's
    /// entry is removed once a view reads the room under its lock, since that read includes the
    /// write: an entry here is therefore always newer than the published one.
    fresh_details: BTreeMap<Digest32, (ChannelSummary, ChannelDetail)>,
    /// Per `(room, member)`: consecutive keys not taken, and the unix second before which the
    /// tick does not send it another. Without it, a pair that could not converge was sent a key
    /// once a tick for as long as both ran: 560 refusals in 3 minutes, measured.
    key_backoff: BTreeMap<(Digest32, Digest32), (u32, u64)>,
    /// Per `(room, member)`: keys written and not yet answered (V210-88). In memory only, so a
    /// key cut off by a crash is owed again after the restart; see [`Node::watch_delivery`].
    keys_in_flight: BTreeMap<(Digest32, Digest32), u32>,
    /// Per `(room, member)`: the history batch in flight, as the keys not yet answered and
    /// whether the batch fell short (a key refused, or not all of it written). The history is
    /// recorded as delivered only once every key of a whole batch was taken (V210-88).
    history_in_flight: BTreeMap<(Digest32, Digest32), (u32, bool)>,
    /// Which delivery watchers are current (V210-88): bumped when the node locks, which forgets
    /// what is in flight. A watcher started before carries the old value, and its answer arriving
    /// after an unlock does not count towards what is in flight now: it could otherwise complete a
    /// new history batch before that batch's own keys were taken.
    delivery_epoch: u64,
    /// Per-channel record sequence for board publishes (strictly increasing per
    /// `(author, channel, epoch)`, ADR-012), across restarts too: see `next_record_seq`.
    record_seq: BTreeMap<Digest32, u64>,
    /// Per channel: the earliest `timestamp` this process's next records may carry (V210-64). Moved
    /// forward, like `record_seq`, by a stale refusal; `record_timestamp` is the later of it and
    /// the clock.
    record_ts_floor: BTreeMap<Digest32, u64>,
    /// Pairwise ADR-004 sessions, keyed by `(channel, peer)` — a session is bound to
    /// a `(channelID, epoch)`, so one peer may have several. In memory for this
    /// process only: persisting ratchet state is not part of M14, so a restart
    /// re-establishes a session on the next join or key exchange.
    sessions: BTreeMap<(Digest32, Digest32), crate::pairwise::session::Session>,
    /// The sessions in [`Self::sessions`] that **this node opened**, and whether the
    /// peer has been sent the hello that lets it accept them (ADR-021 F12).
    ///
    /// Two members can open a session to each other at the same moment — both
    /// auto-consent when they trust each other, and each finds no session and opens
    /// one. Each then holds its own and ignores the other's hello, and neither can
    /// open the key the other sent. Knowing which sessions are ours is what lets both
    /// ends apply one rule and converge: [`incoming_session_wins`].
    initiated: BTreeMap<(Digest32, Digest32), Initiated>,
    /// The hello each peer-opened session was accepted from, by hash, so a peer
    /// re-sending the same hello is recognised and does not re-consume a one-time
    /// prekey or reset a session that is already in use.
    accepted_hello: BTreeMap<(Digest32, Digest32), Digest32>,
    /// Sessions this node kept against a peer's competing hello, whose peer must now
    /// be sent this node's hello so it adopts the same session; drained on the tick.
    reopen: std::collections::BTreeSet<(Digest32, Digest32)>,
    /// Which session each pair holds, by a serial drawn when it was filed, so a key refused for
    /// lack of a session forgets only the session it was sealed under (V210-78).
    session_serial: BTreeMap<(Digest32, Digest32), u64>,
    /// The last serial drawn.
    last_session_serial: u64,
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
    /// Consents decided but not yet delivered, each with the key it releases, taken at the
    /// decision (V210-30). Kept beside the keyring, sealed the same way.
    consent_keys: crate::node::pending_consent::PendingConsents,
    /// When each peer was last tried for a better path, so a relayed connection is retried
    /// on a schedule rather than only at the moment it was made.
    last_upgrade: std::collections::BTreeMap<Digest32, u64>,
    /// The live reacher set per channel (M17.11), written here and read by serving tasks.
    /// Kept out of `Channel` because it is a *join* of channel state with the node-wide
    /// keyring, and the keyring is not a property of any one room.
    reachers: std::collections::BTreeMap<Digest32, crate::node::tunnel::Reachers>,
    /// Each channel's live offer of services (PRD-001 R22), kept beside `reachers` and for
    /// the same reason: serving tasks hold these handles, so removing a service reaches
    /// the sessions it is carrying.
    offered: std::collections::BTreeMap<Digest32, crate::node::tunnel::Offered>,
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
            room_anchors: BTreeMap::new(),
            anchors,
            headless,
            anchor_logs,
            anchor_store: None,
            anchored: BTreeMap::new(),
            forwards: BTreeMap::new(),
            pow_params,
            stream_loops: std::collections::BTreeMap::new(),
            port_mappings: Vec::new(),
            anchor_backoff: BTreeMap::new(),
            anchor_dials: Arc::new(std::sync::Mutex::new(BTreeSet::new())),
            anchor_window: BTreeMap::new(),
            anchor_connected_at: BTreeMap::new(),
            anchors_up: BTreeSet::new(),
            sync_dials: BTreeSet::new(),
            renew_mappings_at: None,
            mapping_expires: BTreeMap::new(),
            mapping_retry: BTreeMap::new(),
            ports: BTreeMap::new(),
            port_queue: crate::node::ports::Queue::default(),
            slots: Arc::new(std::sync::Mutex::new(crate::node::ports::Slots::default())),
            next_token: 1,
            sched_rooms: std::collections::BTreeSet::new(),
            sched_all: false,
            connected: std::collections::BTreeSet::new(),
            next_request_at: 0,
            discovered: BTreeMap::new(),
            discover_rooms: std::collections::BTreeSet::new(),
            discover_peers: std::collections::BTreeSet::new(),
            last_publish_refusal: BTreeMap::new(),
            publish_refusal_first_seen: BTreeMap::new(),
            join_slots: Arc::new(tokio::sync::Semaphore::new(JOINS_IN_FLIGHT)),
            verify_slots: Arc::new(tokio::sync::Semaphore::new(VERIFIES_IN_FLIGHT)),
            join_tasks: tokio::task::JoinSet::new(),
            joining: std::collections::BTreeSet::new(),
            reopening: std::collections::BTreeSet::new(),
            reopen_task: None,
            unlock_waiters: Vec::new(),
            view_stale: std::sync::atomic::AtomicBool::new(false),
            held_pairwise: Vec::new(),
            board_authors: BTreeMap::new(),
            publishing: std::collections::BTreeSet::new(),
            publish_again: std::collections::BTreeSet::new(),
            stale_retries: BTreeMap::new(),
            republish_pending: std::collections::BTreeSet::new(),
            stale_held: std::collections::BTreeSet::new(),
            publish_failures: std::collections::BTreeMap::new(),
            publish_waiters: Vec::new(),
            member_dialed_at: BTreeMap::new(),
            pending_consents: Vec::new(),
            fresh_details: BTreeMap::new(),
            key_backoff: BTreeMap::new(),
            keys_in_flight: BTreeMap::new(),
            history_in_flight: BTreeMap::new(),
            delivery_epoch: 0,
            record_seq: BTreeMap::new(),
            record_ts_floor: BTreeMap::new(),
            sessions: BTreeMap::new(),
            initiated: BTreeMap::new(),
            accepted_hello: BTreeMap::new(),
            reopen: std::collections::BTreeSet::new(),
            session_serial: BTreeMap::new(),
            last_session_serial: 0,
            prekeys: None,
            channels: BTreeMap::new(),
            clock,
            argon2,
            view_tx: watch::Sender::new(NodeView::default()),
            event_tx,
            trust: crate::node::trust::Keyring::new(),
            consent_keys: crate::node::pending_consent::PendingConsents::default(),
            last_upgrade: std::collections::BTreeMap::new(),
            reachers: std::collections::BTreeMap::new(),
            offered: std::collections::BTreeMap::new(),
            sync_book: crate::node::status::SyncBook::shared(),
        };
        let view_rx = node.view_tx.subscribe();
        let sync_book = Arc::clone(&node.sync_book);
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
            sync_book,
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
        // A `Shutdown`'s reply, held until the node is actually gone: see the end of this function.
        let mut shutdown_reply: Option<oneshot::Sender<Outcome>> = None;
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                received = cmd_rx.recv() => {
                    let Some((command, reply)) = received else { break };
                    let shutdown = matches!(command, NodeCommand::Shutdown);
                    let name = command_name(&command);
                    let started = std::time::Instant::now();
                    // Proof the actor is taking commands (V210-83): it changes nothing, so nothing
                    // is published or scheduled for it.
                    if matches!(command, NodeCommand::Ping) {
                        let _ = reply.send(Outcome::Done);
                        continue;
                    }
                    // **Answered off the actor.** Checking the identity passphrase is production
                    // Argon2id, and every `vox trust add/list/remove` asks for it. Inline, it held
                    // the actor for ~0.3 s per command, and nothing on the node — posts, reads,
                    // syncs — was served meanwhile (V210-26). It changes no state, so it runs on
                    // a blocking thread and answers the caller from there.
                    if let NodeCommand::VerifyPassphrase { passphrase } = command {
                        self.begin_verify_passphrase(passphrase, reply);
                        self.note_if_stalled(name, started);
                        continue;
                    }
                    // **Answered later, not here.** Creating a room seals its key under the
                    // passphrase with production Argon2id — seconds of CPU — and this task answers
                    // nothing while it runs. So the seal goes to a blocking thread and the reply
                    // travels with it; `NetEvent::ChannelSealed` finishes the room and answers.
                    if let NodeCommand::CreateChannel {
                        local_name,
                        passphrase,
                    } = command
                    {
                        self.begin_create_channel(local_name, passphrase, reply).await;
                        self.note_if_stalled(name, started);
                        self.publish().await;
                        continue;
                    }
                    // **A forward is answered later too** (#215): its first dial runs the whole
                    // ladder, and through a relay one rung waits out its 10 s direct-attempt timeout
                    // — on the actor, so the node answered nobody (`busy 10000ms — opening a
                    // forward`), and `vox forward` retries every 500 ms. The dial goes to a task;
                    // `NetEvent::ForwardDialed` binds the forward and answers.
                    if let NodeCommand::Forward {
                        channel_id,
                        host,
                        service_tag,
                        local,
                    } = command
                    {
                        self.begin_forward(channel_id, host, service_tag, local, reply);
                        self.note_if_stalled(name, started);
                        continue;
                    }
                    // Joining is answered later for the same reason, and for a longer wait: see
                    // `begin_join_channel`.
                    if let NodeCommand::JoinChannel {
                        link,
                        local_name,
                        passphrase,
                    } = command
                    {
                        self.begin_join_channel(link, local_name, passphrase, reply).await;
                        self.note_if_stalled(name, started);
                        self.publish().await;
                        continue;
                    }
                    // A consent to a member with no connection is answered when the dial it
                    // started lands: see `pending_consents`.
                    if let NodeCommand::Consent { channel_id, target } = command {
                        let outcome = self.consent(&channel_id, target, true).await;
                        self.settle_consent(channel_id, target, reply, outcome, 0)
                            .await;
                        self.note_if_stalled(name, started);
                        self.publish().await;
                        self.schedule().await;
                        continue;
                    }
                    // **Unlock is answered once the rooms it held are held again** (#208). They
                    // reopen off the actor so the node answers everyone meanwhile, but a caller
                    // told `Done` — `vox daemon`, which then opens its control socket — must not
                    // find a room it held still closed.
                    if let NodeCommand::Unlock { passphrase } = command {
                        let outcome = self.unlock(&passphrase).await;
                        self.note_if_stalled(name, started);
                        self.publish().await;
                        if outcome.is_done() && self.reopen_task.is_some() {
                            self.unlock_waiters.push(reply);
                        } else {
                            let _ = reply.send(outcome);
                        }
                        continue;
                    }
                    let outcome = self.handle(command).await;
                    self.note_if_stalled(name, started);
                    self.publish().await;
                    if shutdown {
                        shutdown_reply = Some(reply);
                        break;
                    }
                    // A dropped reply receiver is the caller's choice, not an error.
                    let _ = reply.send(outcome);
                    self.schedule().await;
                }
                Some(event) = net_rx.recv() => {
                    let name = net_event_name(&event);
                    let started = std::time::Instant::now();
                    self.handle_net(event).await;
                    self.note_if_stalled(name, started);
                    self.publish().await;
                    self.schedule().await;
                }
                _ = ticker.tick() => {
                    if let Some(net) = self.net.as_ref() {
                        // Connections a better path displaced are closed once their
                        // grace is up (M15.1b).
                        net.manager().retire_expired();
                    }
                    self.retry_upgrades_if_due().await;
                    self.maintain_prekeys();
                    self.renew_mappings_if_due();
                    self.adopt_anchored_from_board().await;
                    if self.view_stale.load(std::sync::atomic::Ordering::Relaxed) {
                        self.refresh_network_view().await;
                    }
                    self.redial_anchors_if_due();
                    // A rotation's re-keys go out as the remaining consenters become
                    // reachable, which is why they are retried here and not only at
                    // the moment of rotation (M18.1).
                    self.deliver_owed_rekeys().await;
                    // Auto-consent for trusted identities, retried here for the
                    // same reason: a trusted member that was unreachable a moment
                    // ago is picked up as soon as it can be reached (ADR-020 §3).
                    self.deliver_owed_consents(None).await;
                    // Paths change on the tick with no event to say so — a retired connection
                    // closed, a circuit this node relayed ended — and a view published only on
                    // events kept showing them: an anchor with no rooms reported a circuit it
                    // no longer carried for as long as nothing else happened to it.
                    // ADR-025: the tick is a safety net for sync. It retires attempts whose
                    // connection died (D1a) and raises the periodic request (D7).
                    self.sync_tick().await;
                    let ran = self.schedule().await;
                    self.retry_orphaned_consents().await;
                    if ran || self.paths_moved() {
                        self.publish().await;
                    }
                }
            }
        }
        // Channel closed or shutdown: lock (wipe every SEK + the signer) and stop.
        let store = self.log_store();
        self.stop_network().await;
        self.lock_all().await;
        self.publish().await;
        let _ = self.event_tx.send(NodeEvent::Shutdown);
        // **`Done` means gone.** `Shutdown` used to be answered before any of the above ran, and
        // even after it the profile's store stayed open for a few milliseconds more — held by
        // work that outlives the actor's own fields: an aborted join exchange drops its handle at
        // its next await, and a sync session on a blocking thread when its read fails. A caller
        // that opened the same profile the moment it was told `Done` found it busy: v0.2.8's gate
        // went red on exactly that (`vox daemon` exiting `ProfileBusy` in `remote_interrupt_proof`),
        // tolerated there by a retry. So the actor gives up its own handles, waits — bounded — until
        // it holds the store's last reference, and answers only then.
        self.profile = None;
        self.anchor_store = None;
        if let Some(store) = store {
            let deadline = tokio::time::Instant::now() + SHUTDOWN_DRAIN;
            while std::sync::Arc::strong_count(&store) > 1 && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            // Dropped here: with no other holder, this closes the store.
        }
        if let Some(reply) = shutdown_reply {
            let _ = reply.send(Outcome::Done);
        }
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
                self.anchor_backoff.clear();
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
            // Answered through `begin_join_channel`, which the run loop calls instead of this; a
            // join reaching here would have to be answered inline, which is the stall that
            // function exists to remove.
            NodeCommand::JoinChannel { .. } => {
                debug_assert!(false, "JoinChannel is answered by begin_join_channel");
                Outcome::Failed(Fault::Internal)
            }
            // Answered by the run loop, which can keep the reply until a dial lands.
            NodeCommand::Consent { channel_id, target } => {
                self.consent(&channel_id, target, true).await
            }
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
                persist,
            } => {
                self.add_service(&channel_id, &service_tag, local, persist)
                    .await
            }
            NodeCommand::RemoveService {
                channel_id,
                service_tag,
            } => self.remove_service(&channel_id, &service_tag).await,
            // Answered by `begin_forward` and `NetEvent::ForwardDialed`: the command loop takes it
            // before it gets here.
            NodeCommand::Forward { .. } => {
                unreachable!("NodeCommand::Forward is answered by begin_forward")
            }
            NodeCommand::StopForward { local } => {
                // Dropping the forward aborts its listener; connections already
                // spliced run to their own end.
                if self.forwards.remove(&local).is_some() {
                    Outcome::Done
                } else {
                    Outcome::Failed(Fault::NoSuchForward)
                }
            }
            NodeCommand::Sync { channel_id } => self.sync_channel(&channel_id).await,
            NodeCommand::Shutdown | NodeCommand::Ping => Outcome::Done,
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
                    // The passphrase was just proved by the vault, so a blob that will not open
                    // is not a wrong passphrase (V210-40).
                    return Outcome::Failed(match e {
                        crate::error::Error::AtRestUnlockFailed => Fault::SealedUnreadable,
                        e => fault_of(&e),
                    });
                }
                if let Err(e) = self.start_network() {
                    self.lock_all().await;
                    return Outcome::Failed(fault_of(&e));
                }
                let _ = self.event_tx.send(NodeEvent::Unlocked);
                self.reopen_remembered().await;
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
        net.count_ladders_in(Arc::clone(&self.sync_book));
        net.manager().report_to(self.event_tx.clone());
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
        // **Liveness is tended off the actor.** A connection silent past `SILENCE_IS_DEATH` gives
        // way to a live one to the same peer, or is closed — how a restarted peer's connection
        // takes over from the dead one. That cannot ride the actor's tick, because the actor is
        // exactly what a dead connection stalls: measured with a real `vox forward` whose host was
        // killed, the actor sat 60s inside "publishing every room to an anchor that answered",
        // awaiting a stream on the dead connection, and no tick ran until QUIC's idle timeout
        // ended the wait — so the rule that would have ended it at 30s never got to run. Closing
        // the connection from here is also what ends that wait. Held weakly, so the task ends
        // with the network.
        {
            let manager = Arc::downgrade(net.manager());
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(TICK);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticker.tick().await;
                    let Some(manager) = manager.upgrade() else {
                        break;
                    };
                    manager.tend_liveness();
                }
            });
        }
        // The configured anchors are dialled at once, each on its own task: they are
        // where this node's records go and the helpers its ladder climbs through, and
        // an anchor that is down must not hold up the ones that are not.
        let configured: Vec<BootstrapNode> = self.anchors.nodes().to_vec();
        for anchor in configured {
            self.dial_anchor(&net, anchor.id, anchor.endpoints.direct_candidates());
        }
        // No membership refresh here: the network only starts when the identity
        // unlocks, and `lock_all` cleared every channel, so there is nothing to
        // publish yet. The *address* discovery does run, on its own task, because it
        // talks to the network (a route probe and a gateway request) and must not hold
        // up the unlock.
        let discover = Arc::clone(&net);
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let mappings = discover.refresh_advertised(&[]).await;
            let _ = tx.send(NetEvent::AddressesDiscovered { mappings }).await;
        });
        spawn_accept_loop(net, self.net_tx.clone());
        Ok(())
    }

    /// Tear the network down: close every connection and the endpoint, so a locked
    /// node presents no network identity at all.
    async fn stop_network(&mut self) {
        if let Some(net) = self.net.take() {
            // **Relayed connections first**, while the circuits their closes travel in still run,
            // then everything else. Closing them all at once closed each circuit's carrier in the
            // same instant, so a relayed peer never received the CONNECTION_CLOSE. It learned this
            // node was gone only by inference: from `SILENCE_IS_DEATH` (30 s), or, since V29-15,
            // from reading the severed circuit as not a direct path. Inference is the fallback for
            // a crash. A node that is stopping **says** it is leaving, which is what a close is for.
            // Measured on `m15_members_never_online_together`: 33.3 s in 10 of 12 runs without
            // either, 107–115 ms with this ordering alone.
            if net.manager().close_relayed() > 0 {
                tokio::time::sleep(RELAYED_CLOSE_LEAD).await;
            }
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
        self.mapping_expires.clear();
        self.mapping_retry.clear();
        // Every session stops with the network (ADR-025 D1a: the node shuts down).
        self.retire_all_ports();
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
        let seq = self.next_record_seq(channel_id);
        let stamp = self.record_timestamp(channel_id);
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
            net.own_records(signer, channel_id, epoch, &ring, seq, stamp, admission)
        };
        let Ok((address, bundle)) = records else {
            return;
        };
        // **Bounded, and it stops at the first dead stream.** Each put waits for the board's answer,
        // which a live board gives in milliseconds, but a connection that died without saying so waits
        // out the full frame patience (`SYNC_FRAME_TIMEOUT`, 20s) *per put*, and every one of those
        // waits is on the actor. Measured in `perf_r40_relayed_chat_gate`: a member whose room's own
        // anchor (another member) had just shut down published to it over the relayed connection still
        // in the manager. The address put, then two mirrored records, each waited 20s:
        // `busy 60s — filing a sync that finished`, one run in five, and nobody could be answered.
        // The ordering above still holds whenever the board answers. A board that answers nothing within
        // `ANCHOR_PUBLISH_PATIENCE` is given up on for this round. A transport error ends the round,
        // since the rest would ride the same dead stream; a refusal does not.
        let own = [
            ("the room's genesis", genesis_wire),
            ("our member bundle", bundle.to_wire()),
            ("our address", address.to_wire()),
        ];
        let mirrored = net.board_records(channel_id, epoch);
        // **Off the actor, and still in order.** The round awaits a board's answers, which on a
        // connection that died without saying so is `ANCHOR_PUBLISH_PATIENCE` of waiting, and that
        // was on the actor: `busy 5.0s — filing a sync that finished`, a person's post held behind
        // it (the V29-21 verdict: every run still had posts over 1s). The ordering the round exists
        // for, these records on the board before a session with that board reads it, is kept
        // explicitly instead: while a round to a board is in flight, that board's port for the room
        // (ADR-025) waits rather than starting a session (`publishing`). One round per
        // (room, board) at a time; a publish asked for meanwhile runs once the round ends.
        let board_id = conn.peer_id();
        if !self.publishing.insert((*channel_id, board_id)) {
            self.publish_again.insert((*channel_id, board_id));
            return;
        }
        crate::node::status::SyncBook::note_publish_round(&self.sync_book);
        let conn = Arc::clone(conn);
        let tx = self.net_tx.clone();
        let cid = *channel_id;
        tokio::spawn(async move {
            let conn = &conn;
            let round = async {
                let mut outcomes: Vec<(&'static str, Option<String>)> = Vec::new();
                // **A stream that will not open is a failed round, and says so.** It used to return
                // no outcomes at all — "the next round's business" — which reported nothing and, for
                // a room nothing else triggers a publish for, left it off that board indefinitely.
                let client = match crate::nat::service::RendezvousClient::open(conn).await {
                    Ok(client) => client,
                    Err(e) => {
                        outcomes.push(("this publish round", Some(format!("no stream: {e}"))));
                        return (outcomes, true);
                    }
                };
                let mut client = client;
                // **Said, not swallowed.** A refused bundle is a member no other member can admit as a
                // log author; each kind's outcome is carried, success as well as failure, so a refusal
                // that *stops* clears its memo below.
                //
                // **Our bundle before our address**: an address record carries no key, so a board can
                // only verify it against a bundle it already holds (`network.rs` `board_records` emits
                // bundles first for the same reason).
                for (kind, wire) in &own {
                    let result = client.put(wire).await;
                    let dead =
                        matches!(&result, Err(e) if !matches!(e, Error::RendezvousRejected(_)));
                    outcomes.push((kind, result.err().map(|e| e.to_string())));
                    if dead {
                        return (outcomes, true);
                    }
                }
                // And every other member's records this node's board holds: an anchor learns a
                // channel's members only from a member that vouches for them (M15.2a).
                //
                // **In order.** Convergence depends on these records being on the board before the
                // next session with it reads them: spawning the send with nothing holding that
                // session back once dropped the anchor-convergence gate from 3 runs in 5 to 1 in 6.
                // `publishing` is what holds it back now.
                let mut mirrored_refused = 0usize;
                let mut mirrored_why = String::new();
                let mut mirrored_dead = false;
                for wire in &mirrored {
                    match client.put(wire).await {
                        Ok(()) => {}
                        // A board that already holds something newer from that member has fresher news
                        // than the copy we vouch with: nothing was refused that anyone needed.
                        Err(Error::RendezvousRejected(r))
                            if r == crate::nat::service::RejectReason::Stale.as_str() => {}
                        Err(e) => {
                            let dead = !matches!(e, Error::RendezvousRejected(_));
                            mirrored_refused += 1;
                            if mirrored_why.is_empty() {
                                mirrored_why = e.to_string();
                            }
                            if dead {
                                mirrored_dead = true;
                                break;
                            }
                        }
                    }
                }
                client.finish();
                outcomes.push((
                    "another member's record we vouch for",
                    (mirrored_refused > 0)
                        .then(|| format!("{mirrored_refused} refused, first: {mirrored_why}")),
                ));
                (outcomes, mirrored_dead)
            };
            let (outcomes, failed) =
                match tokio::time::timeout(ANCHOR_PUBLISH_PATIENCE, round).await {
                    Ok(done) => done,
                    Err(_) => (
                        vec![(
                            "this publish round",
                            Some(format!(
                                "the board answered nothing within {}s",
                                ANCHOR_PUBLISH_PATIENCE.as_secs()
                            )),
                        )],
                        true,
                    ),
                };
            let _ = tx
                .send(NetEvent::PublishDone {
                    channel_id: cid,
                    board: board_id,
                    outcomes,
                    failed,
                })
                .await;
        });
    }

    /// Answer a create or join once the room's first publish rounds have ended.
    ///
    /// **`Done` has always meant "others can find it".** A create or join awaited its first publish
    /// to the anchors before answering. Once that round moved onto its own task, `vox room create`
    /// answered before the room was on any anchor's board, and a join straight after the invite
    /// found nothing: perf_r40_relayed_chat_gate, `bob's join failed: Failed(BadLink)`, 2 of 2.
    /// The reply now waits for the room's rounds, bounded by `ANCHOR_PUBLISH_PATIENCE` each, and
    /// the actor serves everyone else meanwhile.
    async fn answer_when_published(
        &mut self,
        room: Digest32,
        reply: oneshot::Sender<Outcome>,
        outcome: Outcome,
    ) {
        if outcome.is_done() && self.publishing.iter().any(|(r, _)| *r == room) {
            self.publish_waiters.push((room, reply, outcome));
            return;
        }
        self.publish().await;
        let _ = reply.send(outcome);
    }

    /// Keep a failed publish round from being the last word for that `(room, board)`.
    ///
    /// **A failed round used to be retried only if something else asked for a publish.** The next
    /// round came from a trigger — the board growing, a sync that applied entries, a join, the room
    /// reopening, the anchor connecting again — and a host that has just created a room, with nobody
    /// in it yet, has none of those. If its first round to its anchor failed (a stream that would
    /// not open, a put that died, a board that answered nothing within `ANCHOR_PUBLISH_PATIENCE`), the
    /// room stayed off that board, and a joiner reaching the board found nothing for the room.
    ///
    /// So a failed round schedules its own retry, per `(room, board)`: after 1, 2, 4 … up to 30s
    /// ([`publish_retry_after`]), jittered so many rooms failing to one board together do not retry
    /// together, until a round finishes. A round that finished — even one the board refused — clears
    /// the count: a refusal is an answer, and asking again would get the same one. One retry is
    /// pending per pair at most; the event carries only the pair, and [`NetEvent::PublishRetry`]
    /// drops it if the room or the board has gone meanwhile.
    fn note_publish_round(&mut self, channel_id: Digest32, board: Digest32, failed: bool) {
        let key = (channel_id, board);
        if !failed {
            self.publish_failures.remove(&key);
            return;
        }
        let failures = self.publish_failures.entry(key).or_insert(0);
        *failures = failures.saturating_add(1);
        let wait = publish_retry_after(*failures);
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(wait).await;
            let _ = tx.send(NetEvent::PublishRetry { channel_id, board }).await;
        });
    }

    /// What a board said to one publish round (`NetEvent::PublishDone`), reported the way a
    /// person can act on: once per standing refusal, and not while a join is still curing it.
    fn report_publish(
        &mut self,
        channel_id: &Digest32,
        board_id: Digest32,
        outcomes: Vec<(&'static str, Option<String>)>,
    ) {
        // **Keyed per board, not per room.** A node publishes the same record to several boards and
        // they answer differently — an anchor that has not been vouched this author says "not a
        // channel member" while the node's own board says "policy" — so a memo keyed only by room
        // and record kind alternates between the two reasons and reports on every publish round,
        // which is the spam it was added to stop. It also matters to whoever reads the line: "some
        // board refused this" is not actionable and "that board refused this" is.
        let board = crate::node::network::short_id(board_id);
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
                    let not_yet_vouched = matches!(kind, "our member bundle" | "our address")
                        && why.contains("author is not a channel member");
                    // Our own record refused as stale is cured by the republish past the second
                    // (`NetEvent::RepublishTo`); said only if it is still refused after that.
                    let stale = own_stale_refusal(kind, &Some(why.clone()));
                    let grace = if stale {
                        STALE_REFUSAL_GRACE
                    } else {
                        PUBLISH_REFUSAL_GRACE
                    };
                    if stale {
                        self.stale_held.insert(key.clone());
                    }
                    if not_yet_vouched || stale {
                        let now = self.now();
                        let seen_before = self.publish_refusal_first_seen.contains_key(&key);
                        let first = *self
                            .publish_refusal_first_seen
                            .entry(key.clone())
                            .or_insert(now);
                        if now.saturating_sub(first) < grace {
                            // **Held, never dropped.** A stale refusal is re-reported only by a
                            // later round, and a cured one has none; so its grace ends on a timer,
                            // and the refusal is said then unless a round has taken the record.
                            if stale && !seen_before {
                                let tx = self.net_tx.clone();
                                let (channel_id, what, why) =
                                    (*channel_id, what.clone(), why.clone());
                                tokio::spawn(async move {
                                    tokio::time::sleep(Duration::from_secs(STALE_REFUSAL_GRACE))
                                        .await;
                                    let _ = tx
                                        .send(NetEvent::StaleGraceOver {
                                            channel_id,
                                            what,
                                            why,
                                        })
                                        .await;
                                });
                            }
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
                    // A refusal as stale, cured by the republish past the second: said once, so
                    // a person — and a proof — can see the refusal happened and was mended.
                    if self.stale_held.remove(&key) {
                        let _ = self.event_tx.send(NodeEvent::PublishCured {
                            channel_id: *channel_id,
                            what,
                        });
                    }
                }
            }
        }
    }

    /// The `timestamp` for this process's next records in `channel_id`: the clock, or later if a
    /// stale refusal moved the floor past it (V210-64).
    fn record_timestamp(&self, channel_id: &Digest32) -> u64 {
        self.now()
            .max(self.record_ts_floor.get(channel_id).copied().unwrap_or(0))
    }

    /// The next board-record sequence number for `channel_id`: strictly above the last one this
    /// process used, and never below the clock in milliseconds.
    ///
    /// **It must keep rising across a restart**, because a board accepts only a higher `seq` from
    /// the same author (`non-increasing seq (replay)`). The counter started again at 1 in every
    /// process, so after a restart every record this node published was older than the one the
    /// board already held, and was refused. A member that restarted could not be reached at its
    /// new address. vox-bc's causal-order proof measured it: the second joiner, restarted, logged
    /// `a board would not take our address … the board holds a newer record from that author`,
    /// and failed 5 of 9. The clock is what survives a restart without a store write per publish.
    fn next_record_seq(&mut self, channel_id: &Digest32) -> u64 {
        let floor = (self.millis_clock)();
        let entry = self.record_seq.entry(*channel_id).or_insert(0);
        *entry = entry.saturating_add(1).max(floor);
        *entry
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
            crate::node::anchor::AnchorState::open(&store, sek, channel_id).or_else(|_| {
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
        for cid in store.anchored_channels()? {
            let Some(sek) = self.anchor_sek(&cid) else {
                continue;
            };
            if let Ok(state) = crate::node::anchor::AnchorState::open(&store, sek, &cid) {
                let _ = net.publish_local(&state.genesis().to_wire());
                self.anchored
                    .insert(cid, Arc::new(tokio::sync::Mutex::new(state)));
            }
        }
        Ok(())
    }

    /// Every anchor this node keeps a connection to, with the addresses its next dial tries:
    /// the configured set first, then each open room's own that is not configured (V210-75).
    /// One identity appears once: at the addresses the configured set gives it if it is there,
    /// and otherwise at the addresses **every** room that shares it names, a room at a time and
    /// at most [`ANCHOR_DIAL_CANDIDATES`] per dial, so one room's stale addresses for it cannot
    /// pin the redial to where it no longer is.
    fn kept_anchors(&self) -> Vec<(Digest32, Vec<std::net::SocketAddr>)> {
        let mut all: Vec<(Digest32, Vec<std::net::SocketAddr>)> = self
            .anchors
            .nodes()
            .iter()
            .map(|n| (n.id, n.endpoints.direct_candidates()))
            .collect();
        // Each unconfigured anchor's addresses, one list per room that names it.
        let mut shared: Vec<(Digest32, Vec<Vec<std::net::SocketAddr>>)> = Vec::new();
        for (room, set) in &self.room_anchors {
            if !self.channels.contains_key(room) {
                continue;
            }
            for n in set.nodes() {
                if all.iter().any(|(id, _)| *id == n.id) {
                    continue;
                }
                let addrs = n.endpoints.direct_candidates();
                match shared.iter_mut().find(|(id, _)| *id == n.id) {
                    Some((_, rooms)) => rooms.push(addrs),
                    None => shared.push((n.id, vec![addrs])),
                }
            }
        }
        for (id, rooms) in shared {
            let mut union: Vec<std::net::SocketAddr> = Vec::new();
            let deepest = rooms.iter().map(Vec::len).max().unwrap_or(0);
            for i in 0..deepest {
                for a in rooms.iter().filter_map(|r| r.get(i)) {
                    if !union.contains(a) {
                        union.push(*a);
                    }
                }
            }
            if union.len() > ANCHOR_DIAL_CANDIDATES {
                let from = self.anchor_window.get(&id).copied().unwrap_or(0) % union.len();
                union.rotate_left(from);
                union.truncate(ANCHOR_DIAL_CANDIDATES);
            }
            all.push((id, union));
        }
        all
    }

    /// Whether `peer` is one of [`Self::kept_anchors`].
    fn is_kept_anchor(&self, peer: &Digest32) -> bool {
        self.anchors.get(peer).is_some()
            || self
                .room_anchors
                .iter()
                .any(|(room, set)| self.channels.contains_key(room) && set.get(peer).is_some())
    }

    /// Dial any configured or learned anchor this node is not connected to. Runs on
    /// the tick: an anchor that restarted, or a link that dropped, is re-established on the
    /// next tick, and only one that keeps failing is backed off (V210-57).
    fn redial_anchors_if_due(&mut self) {
        let now = self.now();
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        let open = &self.channels;
        self.room_anchors.retain(|room, _| open.contains_key(room));
        let known = self.kept_anchors();
        let up: BTreeSet<Digest32> = known
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| net.manager().holds(id))
            .collect();
        let lost: Vec<Digest32> = self.anchors_up.difference(&up).copied().collect();
        for lost in lost {
            let lasted = self
                .anchor_connected_at
                .remove(&lost)
                .map(|at| now.saturating_sub(at));
            if lasted.is_some_and(|s| s < ANCHOR_FLAP_SECS) {
                // Lost almost as soon as it was made: backed off like a failed dial.
                let wait = self
                    .anchor_backoff
                    .get(&lost)
                    .map_or(1, |(_, w)| (w * 2).min(ANCHOR_REDIAL_SECS));
                self.anchor_backoff.insert(lost, (now + wait, wait));
                net.manager().note(
                    lost,
                    format!(
                        "the connection to this anchor is gone {}s after it was made; it is \
                         redialled in {wait}s",
                        lasted.unwrap_or(0)
                    ),
                );
            } else {
                self.anchor_backoff.remove(&lost);
                net.manager().note(
                    lost,
                    "the connection to this anchor is gone; it is redialled now".to_owned(),
                );
            }
        }
        self.anchors_up = up;
        for (id, candidates) in known {
            if id == net.local_id() || self.anchors_up.contains(&id) {
                continue;
            }
            // **On the next tick, not the next half-minute** (V210-57): an anchor is this node's
            // board and its relay, and a node without one reaches nobody it cannot dial directly.
            // Only an anchor that keeps failing is backed off.
            if self
                .anchor_backoff
                .get(&id)
                .is_some_and(|(at, _)| now < *at)
            {
                continue;
            }
            // Said only for a retry: a first dial, or one right after a loss (said above), is no news.
            let waited = self.anchor_backoff.get(&id).map_or(0, |(_, w)| *w);
            if self.dial_anchor(&net, id, candidates) && waited > 0 {
                net.manager().note(
                    id,
                    format!("dialling this anchor again, {waited}s after it last failed"),
                );
            }
        }
    }

    /// Dial the anchor `id` unless it is connected or already being dialled; whether a dial was
    /// started. The one place an anchor is dialled from (V210-57): the node's start, a room's
    /// anchors, and the redial each used to spawn their own, and at start two of them raced.
    fn dial_anchor(
        &mut self,
        net: &Arc<NodeNet>,
        id: Digest32,
        candidates: Vec<std::net::SocketAddr>,
    ) -> bool {
        if id == net.local_id() || net.manager().existing(&id).is_some() {
            return false;
        }
        if !self
            .anchor_dials
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id)
        {
            return false;
        }
        let (net, tx, dials) = (
            Arc::clone(net),
            self.net_tx.clone(),
            Arc::clone(&self.anchor_dials),
        );
        tokio::spawn(async move {
            let dialled = net.manager().connect_to(id, &candidates).await;
            dials
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id);
            match dialled {
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
        true
    }

    /// Make a channel's anchors this node's: record `more` on the channel (persisted
    /// under its SEK) and the configured set with it, treat every one as an anchor,
    /// and dial any not yet connected. Called when a channel is created, opened or
    /// joined.
    async fn adopt_channel_anchors(&mut self, channel_id: &Digest32, more: Option<&BootstrapSet>) {
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return;
        };
        let (anchors, own) = {
            let mut channel = shared.lock().await;
            if let Some(profile) = self.profile.as_ref() {
                let mut add = self.anchors.clone();
                if let Some(more) = more {
                    let _ = add.merge_endpoints(more);
                }
                let _ = channel.add_anchors(profile.store(), &add);
            }
            // A link names the member who issued it too, last; a member is reached at the
            // addresses its board record gives, not kept like an anchor at the link's.
            let mut own = BootstrapSet::new();
            for n in channel.anchors().nodes() {
                if !channel.is_author(&n.id) {
                    let _ = own.add(n.clone());
                }
            }
            (channel.anchors().clone(), own)
        };
        self.room_anchors.insert(*channel_id, own);
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        for anchor in anchors.nodes() {
            if anchor.id == net.local_id() {
                continue;
            }
            self.anchor_ids.insert(anchor.id);
            self.dial_anchor(&net, anchor.id, anchor.endpoints.direct_candidates());
        }
    }

    /// Put a channel's genesis and this node's records on every anchor this node is
    /// connected to (its configured set and the channel's own).
    async fn publish_channel_to_anchors(&mut self, channel_id: &Digest32) {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        // **Not deferred while a session runs.** This used to be owed until the room had no
        // session at all, because a session held the room's lock for its whole run (measured:
        // `publish waited 19.9987s for the ROOM lock`). Since 3f95b57 a session takes the lock
        // per protocol step and never across I/O, so the wait here is one step. Deferring had
        // become the hazard instead: with sessions guarded per (room, peer) (#180), sessions
        // with different members overlap, a busy room is never session-free, and the owed
        // publish could wait indefinitely while joiners read a stale board.
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
        let seq = self.next_record_seq(channel_id);
        let stamp = self.record_timestamp(channel_id);
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
        if let Ok((address, bundle)) = net.own_records(
            signer,
            channel_id,
            channel.epoch(),
            &ring,
            seq,
            stamp,
            admission,
        ) {
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
    /// anchor never reached the other member and the room looked quiet. This is a **view**: an
    /// abandoned attempt marks it stale (`view_stale`) and the next tick rebuilds it, so abandoning
    /// one costs a tick and nothing else. (It was said to be rebuilt on every tick; it was not, and
    /// an attempt abandoned with nothing after it left the view behind until something else
    /// happened to refresh it, V210-80.)
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
                // Busy: a session holds it. Keep the policy we have, and say it is behind so the
                // tick retries — nothing else is certain to come along and refresh it.
                self.view_stale
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                return;
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
                // Same: an anchored room mid-sync must not stop the actor.
                self.view_stale
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                return;
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
        // Replacing wholesale would drop the pending joiners the actor is expecting, and the
        // responders a join in flight is waiting on, so both are carried over — in the same lock
        // as the replace, because a join task registers its responder from its own task.
        net.policy().rebuild(policy);
        self.view_stale
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Handle one piece of network work.
    async fn handle_net(&mut self, event: NetEvent) {
        match event {
            NetEvent::Reopened {
                channel_id,
                channel,
            } => {
                // Held only if it is still wanted: closed while it was opening, the identity
                // locked meanwhile, or opened by hand in between — each drops it, and its keys
                // zeroize with it.
                let wanted = self.reopening.remove(&channel_id)
                    && !self.channels.contains_key(&channel_id)
                    && self.profile.as_ref().is_some_and(Profile::is_unlocked);
                if wanted {
                    crate::node::status::SyncBook::note_set_aside(
                        &self.sync_book,
                        channel_id,
                        channel.set_aside(),
                    );
                    self.channels
                        .insert(channel_id, Arc::new(tokio::sync::Mutex::new(*channel)));
                    self.mark_decisions_on_open(&channel_id).await;
                    self.adopt_channel_anchors(&channel_id, None).await;
                    self.refresh_network_view().await;
                    self.publish_channel_locally(&channel_id).await;
                    self.publish_channel_to_anchors(&channel_id).await;
                    let _ = self.event_tx.send(NodeEvent::ChannelOpened { channel_id });
                }
            }
            NetEvent::ReopenGone { channel_id } => {
                self.reopening.remove(&channel_id);
                let _ = self.forget_open(&channel_id);
            }
            NetEvent::ReopenFinished => {
                self.reopening.clear();
                self.reopen_task = None;
                for reply in std::mem::take(&mut self.unlock_waiters) {
                    let _ = reply.send(Outcome::Done);
                }
            }
            NetEvent::Stopped { net } => {
                // Only the network that stopped. A lock takes the network down and an unlock
                // starts a new one, and this event, sent from the old accept loop, can arrive
                // after both: taken as "the network stopped" it wiped the new one, and the node
                // went on unlocked with no network at all (V210-80).
                if self
                    .net
                    .as_ref()
                    .is_some_and(|held| std::ptr::eq(Arc::as_ptr(held), net.as_ptr()))
                {
                    self.net = None;
                }
            }
            NetEvent::JoinRequest {
                conn,
                peer,
                channel_id,
                epoch,
                send,
                recv,
            } => {
                self.answer_inbound_join(conn, peer, channel_id, epoch, send, recv)
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
                // And into the view the board and the stream gate read, before the joiner is
                // answered: an author only the room knows is still a stranger to the board, which
                // refused the newcomer's records until something else refreshed it (V210-80).
                self.refresh_network_view().await;
                // Answered whatever happened: a joiner waiting on this must not be left holding a
                // stream because the room closed or this node has no profile. It will find out from
                // the join's own outcome, which is the right place for it to learn.
                let _ = ack.send(());
            }
            NetEvent::Dialed {
                conn,
                endpoints,
                board,
            } => {
                let peer = conn.peer_id();
                self.sync_dials.remove(&peer);
                self.adopt_connection(Arc::clone(&conn));
                if let Some(net) = self.net.as_ref().map(Arc::clone) {
                    if crate::node::net::path_class(net.manager().endpoint(), &conn)
                        == crate::node::net::PathClass::Relayed
                    {
                        let tx = self.net_tx.clone();
                        self.last_upgrade.insert(peer, self.now());
                        tokio::spawn(async move {
                            match net.upgrade(peer, &endpoints).await {
                                Ok(better) => {
                                    let _ = tx.send(NetEvent::BetterPath { conn: better }).await;
                                }
                                Err(crate::error::Error::LadderExhausted(reason)) => {
                                    let _ = tx.send(NetEvent::UpgradeFailed { peer, reason }).await;
                                }
                                Err(_) => {}
                            }
                        });
                    }
                }
                if board {
                    self.anchor_ids.insert(peer);
                    self.refresh_network_view().await;
                }
                // Whatever this member is owed goes out now that it can be reached, rather than on
                // the next tick: a dial `reach_member` started was started for exactly this.
                self.answer_pending_consents(|_, target| *target == peer, None)
                    .await;
                self.deliver_owed_rekeys().await;
                self.deliver_owed_consents(None).await;
            }
            NetEvent::ForwardDialed {
                channel_id,
                host,
                service_tag,
                local,
                result,
                reply,
            } => {
                let outcome = self
                    .finish_forward(&channel_id, &host, &service_tag, local, *result)
                    .await;
                let _ = reply.send(outcome);
            }
            NetEvent::JoinerDone {
                reply,
                parsed,
                local_name,
                passphrase,
                now,
                me,
                result,
            } => {
                let room = parsed.channel_id;
                let outcome = match *result {
                    Ok(won) => {
                        let _ = self.event_tx.send(NodeEvent::JoinSteps {
                            joined: true,
                            steps: won.steps.render(),
                        });
                        let _ = self.event_tx.send(NodeEvent::JoinStep {
                            step: "making the room here and publishing this member on its boards"
                                .to_owned(),
                        });
                        self.finish_join_channel(*parsed, local_name, passphrase, now, me, won)
                            .await
                    }
                    Err(lost) => {
                        let _ = self.event_tx.send(NodeEvent::JoinSteps {
                            joined: false,
                            steps: lost.steps.render(),
                        });
                        if !lost.why.is_empty() {
                            self.say_why_the_join_failed(&lost.why);
                        }
                        Outcome::Failed(lost.fault)
                    }
                };
                // Whatever arrived for this room while it was being joined, in arrival order — into
                // the room if the join made one, or discarded as before if it did not.
                self.joining.remove(&room);
                if self.joining.is_empty() {
                    if let Some(net) = self.net.as_ref() {
                        net.policy().forget_join_responders();
                    }
                }
                let (held, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.held_pairwise)
                    .into_iter()
                    .partition(|(r, ..)| *r == room);
                self.held_pairwise = kept;
                for (_, peer, first, send, recv) in held {
                    self.handle_pairwise(peer, first, send, recv).await;
                }
                // **The joiner's consent at admission too, before `room join` is answered.** The same
                // ForwardOnly window f4d13d8 closed on the host's side (see `apply_join_outcome`) was
                // open on this side: a joiner that already trusted the host released its key on its
                // next tick, from the chain's position *then*, so a post made the moment the join
                // returned was sealed before the released key and unreadable to the host for good.
                // Measured through `trust_before_join_proof`: the joiner posted at +0ms and consented
                // at +743ms; `alice reads bob = false`, 3 runs of 3. Released here, the key goes out
                // before the person hears the join succeeded, so it covers everything they post next.
                if outcome.is_done() {
                    self.deliver_owed_consents(None).await;
                }
                // The view first, then the answer: whoever hears `Done` reads the view next, and a
                // room that is joined but not yet in it reads as a join that did nothing.
                self.answer_when_published(room, reply, outcome).await;
            }
            NetEvent::ChannelSealed {
                reply,
                local_name,
                passphrase,
                genesis,
                now,
                sealed,
            } => {
                let room = genesis.channel_id();
                let outcome = match sealed {
                    Err(e) => Outcome::Failed(fault_of(&e)),
                    Ok((sek, wrap)) => match self.profile.as_ref() {
                        None => Outcome::Failed(Fault::NoIdentity),
                        Some(profile) => match ChannelState::create_from_sealed(
                            profile,
                            &local_name,
                            &passphrase,
                            *genesis,
                            sek,
                            &wrap,
                            now,
                        ) {
                            Ok(ch) => self.finish_create_channel(ch).await,
                            Err(e) => Outcome::Failed(fault_of(&e)),
                        },
                    },
                };
                // The view first, then the answer — as for a join above.
                self.answer_when_published(room, reply, outcome).await;
            }
            NetEvent::BoardGrew { channel_id } => {
                // Pass it on, which for a member means its anchors. A node that is not a member of
                // this room falls out of `publish_channel_to_anchor` on its missing admission, so
                // an anchor receiving a mirror does not mirror it onward and this cannot ring
                // around a ring of anchors.
                if self.channels.contains_key(&channel_id) {
                    crate::node::status::SyncBook::note_board_news(&self.sync_book);
                    self.publish_channel_to_anchors(&channel_id).await;
                    self.note_new_members(&channel_id).await;
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
                self.run_sync_session(conn, peer, channel_id, epoch, send, recv)
                    .await;
            }
            NetEvent::AddressesDiscovered { mappings } => {
                // Re-publish every open channel's records: the addresses in them were
                // composed before discovery and may name only loopback.
                self.take_mappings(&mappings);
                let channels: Vec<Digest32> = self.channels.keys().copied().collect();
                for channel_id in channels {
                    self.publish_channel_locally(&channel_id).await;
                    self.publish_channel_to_anchors(&channel_id).await;
                }
            }
            NetEvent::ReachFailed { peer, why } => {
                // An anchor that failed to connect waits before its next dial, doubling to
                // `ANCHOR_REDIAL_SECS` (V210-57), a room's own as well as a configured one
                // (V210-75).
                if self.is_kept_anchor(&peer) {
                    // A union too large for one dial tries its next window next time (V210-75).
                    if self.anchors.get(&peer).is_none() {
                        *self.anchor_window.entry(peer).or_insert(0) += ANCHOR_DIAL_CANDIDATES;
                    }
                    let wait = self
                        .anchor_backoff
                        .get(&peer)
                        .map_or(1, |(_, w)| (w * 2).min(ANCHOR_REDIAL_SECS));
                    self.anchor_backoff.insert(peer, (self.now() + wait, wait));
                    if let Some(net) = self.net.as_ref() {
                        net.manager().note(
                            peer,
                            format!(
                                "dialling this anchor failed ({why}); the next try is in {wait}s"
                            ),
                        );
                    }
                }
                self.sync_dials.remove(&peer);
                // A member no reach could get to: its ports that have no connection back off as
                // Unreachable (ADR-025 D5), so the scheduler does not ask again at once (#246).
                let unconnected = self
                    .net
                    .as_ref()
                    .is_some_and(|n| n.manager().existing(&peer).is_none());
                if unconnected {
                    let rooms: Vec<Digest32> = self
                        .ports
                        .keys()
                        .filter(|(_, p)| *p == peer)
                        .map(|(r, _)| *r)
                        .collect();
                    for room in rooms {
                        self.enter_backoff(
                            room,
                            peer,
                            crate::node::status::BackoffKind::Unreachable,
                        );
                    }
                }
                self.answer_pending_consents(
                    |_, target| *target == peer,
                    Some(Outcome::Failed(Fault::Unreachable)),
                )
                .await;
                let _ = self.event_tx.send(NodeEvent::PeerUnreachable { peer, why });
            }
            NetEvent::UpgradeFailed { peer, reason } => {
                let _ = self.event_tx.send(NodeEvent::StillRelayed { peer, reason });
            }
            NetEvent::AnchorConnected { conn } => {
                let peer = conn.peer_id();
                // The backoff is kept until the connection has lasted (`ANCHOR_FLAP_SECS`): one
                // superseded at once is a flap, not a success.
                self.anchor_connected_at.insert(peer, self.now());
                self.anchor_window.remove(&peer);
                // Said, so a log shows a redial's outcome as well as its start (#243, a CI red
                // whose forward said it dialled and then nothing).
                if let Some(net) = self.net.as_ref() {
                    net.manager()
                        .note(peer, "connected to this anchor".to_owned());
                }
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
                // A fresh connection syncs at once (ADR-016): a request on every port it shares,
                // with any backoff cleared (ADR-025 D2, D5).
                self.connected.insert(peer);
                self.discover_peers.insert(peer);
            }
            NetEvent::SkdmRefused {
                channel_id,
                peer,
                chain_id,
                why,
                session,
                history,
                epoch,
            } => {
                // A watcher from before a lock: what it answered is no longer in flight.
                if epoch == self.delivery_epoch {
                    self.key_landed(channel_id, peer);
                    if history {
                        self.history_landed(channel_id, peer, false);
                    }
                }
                let (Some(profile), Some(shared)) = (
                    self.profile.as_ref(),
                    self.channels.get(&channel_id).map(Arc::clone),
                ) else {
                    return;
                };
                {
                    let mut channel = shared.lock().await;
                    let _ = channel.note_undelivered(profile.store(), peer, chain_id);
                    // A refused generation older than the live one is owed again as history
                    // (V210-45), from the member's recorded entitlement and never before it, so
                    // a key taken at a position is never re-owed from its origin. A refused
                    // live generation is owed by the ledger above, and its re-key respects the
                    // same entitlement (`rekey_skdm_for`).
                    if channel.entitled_from(&peer).is_some_and(|(c, _)| {
                        c <= chain_id && chain_id < channel.sender_generation()
                    }) {
                        let _ = channel.owe_history(profile.store(), peer, chain_id);
                    }
                }
                // **The member holds no session with us** (V210-78): it restarted or locked, and
                // sessions live only in memory. Ours is dead at its end, and resending under it is
                // refused the same way for good. Forget it, so the retry opens a fresh one from
                // the member's bundle and offers it — unless a newer one has been filed since the
                // key was sealed, which the member does hold.
                use crate::node::pairwise_stream::KeyRefusal;
                let key = (channel_id, peer);
                if why == KeyRefusal::describe(KeyRefusal::NoSession.code().into_inner())
                    && session.is_some()
                    && self.session_serial.get(&key).copied() == session
                {
                    self.sessions.remove(&key);
                    self.initiated.remove(&key);
                    self.accepted_hello.remove(&key);
                    self.reopen.remove(&key);
                    self.session_serial.remove(&key);
                }
                // 2, 4, 8 … 64s: a refusal that cures (a session that converges, a member learnt
                // from the board) is retried promptly, and one that does not stops costing a
                // stream every second.
                let now = self.now();
                let entry = self.key_backoff.entry((channel_id, peer)).or_insert((0, 0));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = now.saturating_add(1u64 << entry.0.min(6));
                let _ = self.event_tx.send(NodeEvent::KeyNotTaken {
                    channel_id,
                    peer,
                    why,
                });
            }
            NetEvent::StaleGraceOver {
                channel_id,
                what,
                why,
            } => {
                // Still refused: no round since took it (one that did cleared the key).
                let key = (channel_id, what.clone());
                if self.publish_refusal_first_seen.remove(&key).is_some() {
                    self.last_publish_refusal.insert(key, why.clone());
                    let _ = self.event_tx.send(NodeEvent::PublishRefused {
                        channel_id,
                        what,
                        why,
                    });
                }
            }
            NetEvent::RepublishTo { channel_id, board } => {
                self.republish_pending.remove(&(channel_id, board));
                *self.stale_retries.entry((channel_id, board)).or_insert(0) += 1;
                let conn = self.net.as_ref().and_then(|n| n.manager().existing(&board));
                if let Some(conn) = conn {
                    // Queued behind a round in flight to that board, as any other publish is.
                    self.publish_channel_to_anchor(&channel_id, &conn).await;
                }
            }
            NetEvent::PublishDone {
                channel_id,
                board,
                outcomes,
                failed,
            } => {
                self.publishing.remove(&(channel_id, board));
                // **Our own record refused as stale, from a fresh process: publish again just past
                // the next second.** A board takes a replacement only with a later `timestamp`, in
                // whole seconds (the one-change-a-second anti-spam bound, `nat::store`), and a
                // process that starts within the second the last one published in — a restart, or
                // one one-shot verb after another — signs its first record in that same second. It
                // was refused, and this node stayed at its old address on that board until its next
                // round: every cold `vox forward` logged `a board would not take our address … the
                // board holds a newer record` (integrate 1de7548). Capped, so a board that really
                // holds something newer from this identity — two live processes of one identity —
                // is not asked every second for ever.
                let own_stale = outcomes
                    .iter()
                    .any(|(kind, why)| own_stale_refusal(kind, why));
                let key = (channel_id, board);
                if own_stale {
                    // **One republish at a time, counted when it goes.** A node publishes to a board
                    // in bursts, so a stale record comes back refused several times within
                    // milliseconds. Counting each refusal spent the cap on one burst and armed a
                    // timer per refusal, all firing in the same instant a second later, into a second
                    // still refused; nothing came after (#230's verifier and the tries log: seven
                    // refusals and six republishes inside 200 ms, then silence). Now each refusal
                    // arms the next republish only if none is on its way, and a try is counted when
                    // the republish goes, so the waves are a second apart and there are three.
                    let tries = self.stale_retries.get(&key).copied().unwrap_or(0);
                    if tries < STALE_REPUBLISH_TRIES && self.republish_pending.insert(key) {
                        // **And the `seq` floor moves on, not only the clock** (V210-61). A board
                        // wants a later `seq` as well as a later second, and `seq` is floored by
                        // this process's millisecond clock: waiting a second per try let a process
                        // whose clock is behind its predecessor's catch up by one second a try, so
                        // three tries cured a lag of about three seconds and no more. #230's own
                        // proof, staged 2.5 s behind, was cured on its last try in 57 of 60 samples
                        // on integrate dd78874, and now and then not at all: the node then said a
                        // board "would not take our address" and the board kept the dead process's.
                        // Each armed republish moves the floor 2, 4, then 8 s past where it is, so
                        // three tries cover a lag of more than 15 s. `seq` is only compared, never
                        // bounded by a board, and it stays this process's own and increasing.
                        //
                        // **And the `timestamp` floor with it** (V210-64): a board wants a later
                        // second too, and a real clock step moves both clocks. **Both capped** at
                        // `STALE_AHEAD_MAX_MS` past the clock, and never moved back.
                        let clock_ms = (self.millis_clock)();
                        let ahead = STALE_SEQ_STEP_MS << tries.min(8);
                        let cap = clock_ms.saturating_add(STALE_AHEAD_MAX_MS);
                        let entry = self.record_seq.entry(channel_id).or_insert(0);
                        *entry = (*entry)
                            .max(clock_ms)
                            .saturating_add(ahead)
                            .min((*entry).max(cap));
                        let now = self.now();
                        let ts_cap = now.saturating_add(STALE_AHEAD_MAX_MS / 1_000);
                        let stamp = self.record_ts_floor.entry(channel_id).or_insert(0);
                        *stamp = (*stamp)
                            .max(now)
                            .saturating_add(ahead / 1_000)
                            .min((*stamp).max(ts_cap));
                        let past_the_second = 1_000 - (self.millis_clock)() % 1_000 + 50;
                        let tx = self.net_tx.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(past_the_second)).await;
                            let _ = tx.send(NetEvent::RepublishTo { channel_id, board }).await;
                        });
                    }
                } else if outcomes.iter().all(|(_, why)| why.is_none()) {
                    self.stale_retries.remove(&key);
                }
                self.report_publish(&channel_id, board, outcomes);
                self.note_publish_round(channel_id, board, failed);
                if !self.publishing.iter().any(|(room, _)| *room == channel_id) {
                    let (ready, waiting): (Vec<_>, Vec<_>) =
                        std::mem::take(&mut self.publish_waiters)
                            .into_iter()
                            .partition(|(room, _, _)| *room == channel_id);
                    self.publish_waiters = waiting;
                    if !ready.is_empty() {
                        self.publish().await;
                        for (_, reply, outcome) in ready {
                            let _ = reply.send(outcome);
                        }
                    }
                }
                if self.publish_again.remove(&(channel_id, board)) {
                    let conn = self.net.as_ref().and_then(|n| n.manager().existing(&board));
                    if let Some(conn) = conn {
                        self.publish_channel_to_anchor(&channel_id, &conn).await;
                    }
                }
                // A session with that board for this room was held back while the round ran.
                self.sched_rooms.insert(channel_id);
            }
            NetEvent::PublishRetry { channel_id, board } => {
                // **Cancelled if the room or the board has gone.** A room closed since, or a board
                // this node no longer holds a connection to, is not retried: the board is published
                // to again by `AnchorConnected` when it comes back, and a closed room has nothing to
                // publish. Its failure count goes with it.
                let conn = self.net.as_ref().and_then(|n| n.manager().existing(&board));
                match conn {
                    Some(conn) if self.channels.contains_key(&channel_id) => {
                        self.publish_channel_to_anchor(&channel_id, &conn).await;
                    }
                    _ => {
                        self.publish_failures.remove(&(channel_id, board));
                    }
                }
            }
            NetEvent::SkdmTaken {
                channel_id,
                peer,
                chain_id,
                session,
                history,
                epoch,
            } => {
                self.key_backoff.remove(&(channel_id, peer));
                // Taken under the session still held: the peer holds its hello (V210-89).
                if session.is_some()
                    && self.session_serial.get(&(channel_id, peer)).copied() == session
                {
                    self.hello_delivered(&channel_id, peer);
                }
                // The key was taken, and is recorded so whenever it answered. What is in flight,
                // and so a whole history batch, is counted only by a watcher of this epoch.
                let fresh = epoch == self.delivery_epoch;
                if fresh {
                    self.key_landed(channel_id, peer);
                }
                let whole_history = fresh && history && self.history_landed(channel_id, peer, true);
                let (Some(profile), Some(shared)) = (
                    self.profile.as_ref(),
                    self.channels.get(&channel_id).map(Arc::clone),
                ) else {
                    return;
                };
                // A failed write leaves the key owed, and it is sent again: never the other way.
                let mut channel = shared.lock().await;
                let _ = channel.note_delivered(profile.store(), peer, chain_id);
                if whole_history {
                    let _ = channel.note_history_delivered(profile.store(), &peer);
                }
            }
            NetEvent::RoomStored { channel_id } => {
                // A worker persisted entries: the room's generation moved, and its ports are
                // evaluated when this event ends (ADR-025 D1a, D6a).
                self.sched_rooms.insert(channel_id);
            }
            NetEvent::SlotFreed => {
                // Queued ports are evaluated at the end of every event; nothing more to do here.
            }
            NetEvent::BackoffExpired {
                channel_id,
                peer,
                timer,
            } => {
                if let Some(port) = self.ports.get_mut(&(channel_id, peer)) {
                    if let Some(b) = port.backoff.as_mut().filter(|b| b.timer == timer) {
                        b.until = None;
                        crate::node::status::SyncBook::with(
                            &self.sync_book,
                            channel_id,
                            peer,
                            |c| c.backoff = None,
                        );
                        self.sched_rooms.insert(channel_id);
                    }
                }
            }
            NetEvent::SyncDone {
                channel_id,
                peer,
                token,
                report,
            } => {
                let current = self.file_session(channel_id, peer, token, &report);
                if current {
                    if let Some(fail) = &report.fail {
                        // Said, with its reason (PRD-001 R36), so a failure that does not resolve
                        // can be told from one that does.
                        let _ = self.event_tx.send(NodeEvent::SyncFailed {
                            channel_id,
                            peer,
                            reason: fail.to_string(),
                        });
                    }
                    // Only a consent to this session's peer: a session with another member fetched
                    // nothing that consent waits for, and retrying it there used its attempts up
                    // (V210-78).
                    self.answer_pending_consents(
                        |room, target| *room == channel_id && *target == peer,
                        None,
                    )
                    .await;
                }
                self.refresh_network_view().await;
                let o = report.out;
                if current && (report.fail.is_none() || o.applied > 0) {
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
                    }
                    // **And only when it could change who reaches whom** (#179): an admission is a
                    // governance entry. A session that brought ordinary messages changed neither
                    // who may reach whom nor what this node's records say, yet it re-signed and
                    // re-sent them to every anchor on the actor: with two members posting, dozens
                    // of rounds a second, each signing on the single writer a local post queues
                    // behind. Records mirrored onto this board come through `BoardGrew`, which
                    // fires for news.
                    if o.governance > 0 {
                        self.refresh_reachers().await;
                        self.publish_channel_to_anchors(&channel_id).await;
                    }
                    // **A newcomer this session admitted is consented to now, not on the tick.** Two
                    // members who joined the same room learn of each other only here, from the board.
                    // Under ForwardOnly a post sealed before the author consents to a reader is never
                    // readable to it, so every tick of delay is a window of posts lost to the
                    // newcomer. Measured in room_of_three_keys_proof: the joiners' keys to each other
                    // landed 388ms and 846ms after their posts. This shrinks the window; it cannot
                    // close it, since nobody can consent to a member it has not yet heard of.
                    if !self.trust.is_empty() {
                        let trusted = self.trust.trusted();
                        let owes = match self.channels.get(&channel_id).map(Arc::clone) {
                            Some(shared) => !shared.lock().await.owed_consents(&trusted).is_empty(),
                            None => false,
                        };
                        if owes {
                            self.deliver_owed_consents(None).await;
                        }
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
                let connection = conn;
                match inbound {
                    Inbound::Join { .. } => {
                        // Unreachable: the stream loop turns these into
                        // `NetEvent::JoinRequest` once the request is read.
                    }
                    Inbound::Pairwise { peer, send, recv } => {
                        self.take_inbound_skdm(peer, send, recv).await;
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
                        // **The tunnel holds its connection for as long as it runs.** That
                        // is what tells `retire_expired` the path is still carrying, so a
                        // better path appearing does not close it under a live session.
                        let carried = Arc::clone(&connection);
                        tokio::spawn(async move {
                            let _carried = carried;
                            let refusals = events.clone();
                            let served = crate::node::tunnel::serve_reporting(
                                peer,
                                send,
                                recv,
                                snapshot,
                                Some(events),
                            )
                            .await;
                            // The result used to be dropped here, so a host refusing a member —
                            // untrusted, no such service, its own service down — said nothing
                            // anywhere (PRD-001 R36). Refusals only: a session that ends in an
                            // error after it was accepted is a disconnect, not a no.
                            if let Err(e @ crate::error::Error::TunnelDenied(_)) = served {
                                let who: String = crate::node::link::b32_encode(&peer)
                                    .chars()
                                    .take(12)
                                    .collect();
                                let _ = refusals.send(NodeEvent::ProxyRefused {
                                    reason: format!("refused {who} a tunnel: {e}"),
                                });
                            }
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
    ///
    /// **The exchange holds its connection** (V210-87). A connection displaced by a better path is
    /// retired, and closed once its grace is up unless something still holds it — a sync, a tunnel.
    /// A join held only its streams, so it did not count: a relayed dial displaced by a direct one
    /// was closed under a joiner still grinding its proof of work, and the join failed with
    /// `closed by the peer` whenever the grind outlasted the 60s grace. Measured through the real
    /// binaries: the unoptimized build grinds 22–194s, and a slow device is the same.
    async fn answer_inbound_join(
        &mut self,
        conn: Arc<VoxConnection>,
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
            let _carried = conn;
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
        self.adopt_join_session(channel_id, peer, outcome.session, false)
            .await;
        if let Some(net) = self.net.as_ref() {
            net.policy().forget_joiner(&peer);
        }
        // **Consent at admission, not on the tick** (ADR-021 F12). A room is ForwardOnly:
        // a newcomer reads only what is sealed after the key is released to it. With the
        // joiner already in this node's trust ring, leaving the release to the next tick
        // opened a window in which anything this node posted was unreadable to the
        // joiner for good. The actor is serial, so releasing here — before any later
        // command is served — means everything posted after the join is readable.
        self.deliver_owed_consents(None).await;
        let _ = self
            .event_tx
            .send(NodeEvent::PeerJoined { channel_id, peer });
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
            self.stream_loops.retain(|_, held| held.strong_count() > 0);
            if let std::collections::btree_map::Entry::Vacant(e) =
                self.stream_loops.entry(conn.serial())
            {
                e.insert(Arc::downgrade(&conn));
                spawn_stream_loop(net, conn, self.net_tx.clone());
            }
        }
        // A new connection syncs at once, then on the interval (ADR-016; ADR-025 D2, D5).
        self.connected.insert(peer);
        self.discover_peers.insert(peer);
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

    /// Join a channel from an invite link (ADR-016 §"Join over the network"): resolve
    /// the anchor, read the board, announce a pre-join record, run the ADR-005 join,
    /// then build local channel state and publish our own records.
    /// Begin joining a room: capture what the join needs here, run the network half and the
    /// Argon2id seal in a task, and answer through `NetEvent::JoinerDone`.
    ///
    /// **The joiner no longer holds its node still.** The whole joiner side ran on the actor —
    /// reach a board, fetch, a poll of up to `JOIN_ADDRESS_PATIENCE` with `sleep` on the actor,
    /// dial, announce, the exchange, and the room key sealed with production Argon2id — so a node
    /// that was joining a room answered nothing else meanwhile: not its other rooms, not its
    /// control socket, not the responder's own follow-ups. Measured through the real binaries:
    /// `busy 9829–28943ms — joining a room`. The caller still waits for its join; nobody else does.
    async fn begin_join_channel(
        &mut self,
        link: String,
        local_name: String,
        passphrase: Secret,
        reply: oneshot::Sender<Outcome>,
    ) {
        let parsed = match crate::node::link::InviteLink::parse(&link) {
            Ok(p) => p,
            Err(e) => {
                let _ = reply.send(Outcome::Failed(fault_of(&e)));
                return;
            }
        };
        let (Some(net), Some(ring)) = (
            self.net.as_ref().map(Arc::clone),
            self.prekeys.as_ref().map(Arc::clone),
        ) else {
            let _ = reply.send(Outcome::Failed(Fault::NotNetworked));
            return;
        };
        if self.channels.contains_key(&parsed.channel_id) {
            let _ = reply.send(Outcome::Failed(Fault::AlreadyMember));
            return;
        }
        let Some(profile) = self.profile.as_ref() else {
            let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
            return;
        };
        let Ok(signer) = profile.signer_arc() else {
            let _ = reply.send(Outcome::Failed(Fault::Locked));
            return;
        };
        let now = self.now();
        let me = net.local_id();
        // The boards to try, in the order `reach_a_board` tried them: the link's anchors, this
        // node's own, then any anchor it already holds a live connection to.
        //
        // **One route per board, with every address known for it.** The link and this node can
        // name the same anchor by different addresses — the host that minted the link reached it on
        // IPv4, this node reaches it on IPv6 — and keeping only the first entry for an identity
        // dropped this node's own addresses for it: an IPv6-only member was left dialling the
        // link's IPv4 address for its own anchor, and reached it only by a fallback after that
        // dial ran out. This node's own addresses go first — they are what it resolved for itself
        // — then the link's, and the dial races them (`connect_direct` is Happy Eyeballs).
        let mut routes: Vec<(Digest32, crate::nat::multiaddr::EndpointList)> = Vec::new();
        let mut seen: std::collections::BTreeSet<Digest32> = [me].into_iter().collect();
        for a in parsed.anchors.iter() {
            if seen.insert(a.id) {
                routes.push((a.id, a.endpoints.clone()));
            }
        }
        for a in self.anchors.nodes() {
            if seen.insert(a.id) {
                routes.push((a.id, a.endpoints.clone()));
            } else if let Some((_, known)) = routes.iter_mut().find(|(id, _)| *id == a.id) {
                let mut all: Vec<crate::nat::multiaddr::Multiaddr> = a.endpoints.addrs().to_vec();
                for m in known.addrs() {
                    if !all.contains(m) {
                        all.push(*m);
                    }
                }
                all.truncate(crate::nat::multiaddr::MAX_ENDPOINTS);
                if let Ok(merged) = crate::nat::multiaddr::EndpointList::new(all) {
                    *known = merged;
                }
            }
        }
        let live: std::collections::BTreeSet<Digest32> =
            net.manager().peers().into_iter().collect();
        if let Ok(empty) = crate::nat::multiaddr::EndpointList::new(Vec::new()) {
            for id in self.anchor_ids.iter().copied() {
                if live.contains(&id) && seen.insert(id) {
                    routes.push((id, empty.clone()));
                }
            }
        }
        if routes.is_empty() {
            let _ = reply.send(Outcome::Failed(Fault::BoardUnreachable));
            return;
        }
        let seq = self.next_record_seq(&parsed.channel_id);
        self.joining.insert(parsed.channel_id);
        let job = Joiner {
            net,
            tx: self.net_tx.clone(),
            me,
            parsed: parsed.clone(),
            routes,
            signer,
            ring,
            seq,
            now,
            pow_params: self.pow_params,
            argon2: self.argon2,
            passphrase: passphrase.clone(),
            events: self.event_tx.clone(),
        };
        let tx = self.net_tx.clone();
        // **Tracked, so a lock aborts it** (V210-76). The joiner holds the vault signer, the
        // prekey ring and the room passphrase, and signs with them for as long as the join runs;
        // detached, it went on joining for tens of seconds after the node locked.
        let reply = AnsweredIfAborted(Some(reply));
        self.reap_join_tasks();
        self.join_tasks.spawn(async move {
            let result = job.run().await;
            let Some(reply) = reply.into_reply() else {
                return;
            };
            let _ = tx
                .send(NetEvent::JoinerDone {
                    reply,
                    parsed: Box::new(parsed),
                    local_name,
                    passphrase,
                    now,
                    me,
                    result: Box::new(result),
                })
                .await;
        });
    }

    /// Everything after the join exchange: make the room from the sealed key, record how this
    /// node was admitted, learn who else is in it, and publish — the part that has to be on the
    /// actor, and was the tail of the old inline `join_channel`.
    async fn finish_join_channel(
        &mut self,
        parsed: crate::node::link::InviteLink,
        local_name: String,
        passphrase: Secret,
        now: u64,
        me: Digest32,
        won: JoinerWon,
    ) -> Outcome {
        let JoinerWon {
            joined,
            responder,
            conn,
            set,
            genesis,
            sealed,
            steps: _,
        } = won;
        let channel = {
            let Some(profile) = self.profile.as_ref() else {
                return Outcome::Failed(Fault::NoIdentity);
            };
            match ChannelState::join_channel_from_sealed(
                profile,
                &genesis,
                &parsed.channel_id,
                &local_name,
                &passphrase,
                now,
                sealed,
                // Keep the responder's witness to this join (M17.6). It is republished with
                // every bundle record this node ever puts on a board for this room, so it is
                // persisted rather than held: a node that lost it could publish nothing and
                // would fall off every board. The joiner already verified it binds its own key,
                // this room and this epoch, in `run_initiator`. Written with the room, in one
                // batch, so a join that fails here leaves no room behind (V210-80).
                Some(crate::nat::record::Admission::Witnessed(Box::new(
                    joined.witness.clone(),
                ))),
            ) {
                Ok(c) => c,
                Err(e) => return Outcome::Failed(fault_of(&e)),
            }
        };
        self.remember_or_say(&channel);
        self.channels.insert(
            parsed.channel_id,
            Arc::new(tokio::sync::Mutex::new(channel)),
        );
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
        self.adopt_join_session(parsed.channel_id, responder, joined.session, true)
            .await;
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
    async fn release_key_to(
        &mut self,
        channel_id: &Digest32,
        target: Digest32,
        asked: bool,
    ) -> Outcome {
        if self.net.is_none() {
            return Outcome::Failed(Fault::NotNetworked);
        }
        let now = self.now();
        let decision = self.trust_decision(&target);
        let plan: Option<Vec<(u64, u64)>>;
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
                // it and cannot know we are releasing to the right party. Said as that, not as
                // "no such room" (V210-78); an explicit consent waits for a sync with it.
                return Outcome::Failed(Fault::NotAdmitted);
            }
            // **Consent is dated by the decision, not the delivery** (V210-45), in the
            // profile's logical consent order, never by a clock. Every generation minted after
            // the decision goes whole; the one live at the decision goes from where it stood
            // then; nothing older. The live generation's key is delivered here, and the older
            // ones the plan covers are owed below and delivered by the re-key round, which
            // retries until each is taken. Without this a member trusted before a room existed,
            // joining after 1,500 posts, read only the 500 of the generation live at its join.
            plan = channel.history_plan(&target, decision);
            if let Some(&(live, from)) = plan.as_ref().and_then(|p| p.last()) {
                match channel.release_generation(profile, live, from) {
                    Ok(s) => s,
                    Err(e) => return Outcome::Failed(fault_of(&e)),
                }
            } else {
                // **The key is taken once, when the consent is decided** (V210-30). A member that
                // cannot be reached now gets, whenever it is reached, the key from this moment —
                // not one built then, from a later position, which would leave every post made in
                // between sealed before it and unreadable to that member for good. A key taken for
                // an earlier epoch (the passphrase was rotated since) is no key for this one.
                let held = self
                    .consent_keys
                    .get(channel_id, &target)
                    .and_then(|w| crate::group::skdm::Skdm::from_wire(w).ok())
                    .filter(|s| s.body.epoch == channel.epoch());
                match held {
                    Some(s) => s,
                    None => match channel.skdm_for_consent(profile) {
                        Ok(s) => {
                            // Past the bound nothing is held (V210-77): the key goes now if
                            // the member is reachable, and is taken again when it is.
                            let held = self.consent_keys.insert(*channel_id, target, s.to_wire());
                            if let (true, Ok(signer)) = (held, profile.signer()) {
                                if let Err(e) = self.consent_keys.save(profile.store(), signer) {
                                    return Outcome::Failed(fault_of(&e));
                                }
                            }
                            s
                        }
                        Err(e) => return Outcome::Failed(fault_of(&e)),
                    },
                }
            }
        };
        // No session need exist yet: one is opened from this member's bundle record
        // if the join path never made one (ADR-016).
        let hello = self.ensure_session(channel_id, target).await;
        let Some(conn) = self.reach_member(channel_id, target, asked).await else {
            return Outcome::Failed(Fault::Unreachable);
        };
        let Some(session) = self.sessions.get_mut(&(*channel_id, target)) else {
            return Outcome::Failed(Fault::Unreachable);
        };
        let sent = match crate::node::pairwise_stream::deliver_skdm(
            &conn,
            channel_id,
            session,
            &skdm,
            hello.as_ref(),
        )
        .await
        {
            Ok(sent) => sent,
            Err(e) => return Outcome::Failed(fault_of(&e)),
        };
        let (Some(profile), Some(shared)) = (
            self.profile.as_ref(),
            self.channels.get(channel_id).map(Arc::clone),
        ) else {
            return Outcome::Failed(Fault::UnknownChannel);
        };
        // **The held key leaves the store before the consent is recorded, never after.** Removed
        // after, a failed save left a delivered key on disk, and after a revocation and a new
        // consent that stale pre-rotation key would have been the one delivered (found in
        // verification of #203). Removed first, a key on disk means no consent was recorded for
        // it. So a failed removal is refused, loudly, with nothing recorded: the key stays held,
        // and the next attempt delivers the same key again. A failure between the removal and the
        // record can only lose the held key, so that consent is taken again from a later position:
        // narrower, never wider.
        if self.consent_keys.get(channel_id, &target).is_some() {
            let mut next = self.consent_keys.clone();
            next.remove(channel_id, &target);
            let saved = profile
                .signer()
                .and_then(|signer| next.save(profile.store(), signer));
            if let Err(e) = saved {
                return Outcome::Failed(fault_of(&e));
            }
            self.consent_keys = next;
        }
        let history_owed = {
            let mut channel = shared.lock().await;
            // What this consent releases, from its earliest position (V210-45): every later
            // release to `target` starts there and never before it.
            let entitled_from = plan
                .as_ref()
                .and_then(|p| p.first().copied())
                .unwrap_or((skdm.body.chain_id, skdm.body.iteration));
            // The generations before the live one that the decision covers (V210-45) are owed
            // in the grant's own transaction.
            match channel.issue_consent(profile, target, &skdm, entitled_from, now) {
                Ok((_, history_owed)) => history_owed,
                Err(e) => return Outcome::Failed(fault_of(&e)),
            }
        };
        // The grant is on the log now, and a reader renders nothing without it: pushed at once,
        // as every local append is, not on the next tick (V210-78).
        self.note_local_append(channel_id);
        // The generation delivered is the key's own: a key taken before a rotation is the older
        // one, and a refusal must re-owe exactly that (V210-30).
        let chain_id = skdm.body.chain_id;
        // The consent is a fact once decided; whether the key landed is learnt off the actor, and
        // it is recorded as delivered only then (V210-88).
        self.watch_delivery(sent, *channel_id, target, chain_id, false);
        if history_owed {
            // At once rather than on the tick: the connection and session are live now.
            let _ = self.deliver_rekeys_for(channel_id, asked).await;
        }
        Outcome::Done
    }

    /// Decide what an explicit consent's `outcome` means for the person waiting on it.
    ///
    /// `Unreachable` has two causes. With no connection to the member, `reach_member` has started
    /// a dial, so the consent waits for `Dialed` or `ReachFailed`. With a connection but no pairwise
    /// session, the member's bundle record is not on this node's board yet: a node that has just
    /// started holds only what its first sessions bring in. V29-19 measured this through the real
    /// `vox tui`: a consent to a member who was online failed at once, in 0.75s, with
    /// `no reachable peer`, at 0, 3, 6 and 10s after the room opened, and succeeded from 15s. So a
    /// sync with that member is started, since that is what fetches its records, and the consent
    /// is retried when the session with that member is done. `NotAdmitted` waits the same way:
    /// the same sync is what admits it.
    async fn settle_consent(
        &mut self,
        channel_id: Digest32,
        target: Digest32,
        reply: oneshot::Sender<Outcome>,
        outcome: Outcome,
        attempts: u8,
    ) {
        const MAX_CONSENT_ATTEMPTS: u8 = 3;
        if !matches!(
            outcome,
            Outcome::Failed(Fault::Unreachable | Fault::NotAdmitted)
        ) || attempts >= MAX_CONSENT_ATTEMPTS
        {
            let _ = reply.send(outcome);
            return;
        }
        let connected = self
            .net
            .as_ref()
            .is_some_and(|n| n.manager().existing(&target).is_some());
        if connected {
            // Started or not (a session with this same member may already be running), the retry
            // rides the next `SyncDone` of a session **with the target**. Checking for any session
            // on the room kept a consent waiting on sessions with other members, which, now that
            // sessions are guarded per (room, peer), need never all end.
            if self.ensure_port(&channel_id, &target).await {
                if let Some(port) = self.ports.get_mut(&(channel_id, target)) {
                    port.raise();
                }
                self.sched_rooms.insert(channel_id);
                self.schedule().await;
            }
            if !self
                .ports
                .get(&(channel_id, target))
                .is_some_and(|p| p.busy())
            {
                let _ = reply.send(outcome);
                return;
            }
        } else if attempts > 0 || matches!(outcome, Outcome::Failed(Fault::NotAdmitted)) {
            // A dial already landed once for this consent and the connection is gone again; or
            // the member is not admitted here, for which no dial was started, so none would answer.
            let _ = reply.send(outcome);
            return;
        }
        self.pending_consents
            .push((channel_id, target, reply, attempts.saturating_add(1)));
    }

    /// Retry the explicit consents `matches` selects (`Dialed` passes its peer, `SyncDone` its
    /// room), or answer them all with `failed` (`ReachFailed`).
    async fn answer_pending_consents(
        &mut self,
        matches: impl Fn(&Digest32, &Digest32) -> bool,
        failed: Option<Outcome>,
    ) {
        let (waiting, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_consents)
            .into_iter()
            .partition(|(room, target, _, _)| matches(room, target));
        self.pending_consents = rest;
        if waiting.is_empty() {
            return;
        }
        for (channel_id, target, reply, attempts) in waiting {
            match failed {
                Some(o) => {
                    let _ = reply.send(o);
                }
                None => {
                    // Still waiting on its dial: that is `Dialed`'s or `ReachFailed`'s to answer, not
                    // a session with somebody else that happened to finish first.
                    let connected = self
                        .net
                        .as_ref()
                        .is_some_and(|n| n.manager().existing(&target).is_some());
                    if !connected {
                        self.pending_consents
                            .push((channel_id, target, reply, attempts));
                        continue;
                    }
                    let outcome = self.consent(&channel_id, target, false).await;
                    self.settle_consent(channel_id, target, reply, outcome, attempts)
                        .await;
                }
            }
        }
        // The view reflects whatever was granted before anyone reads it.
        self.publish().await;
    }

    /// Retry the explicit consents waiting on a session with their member that no longer runs
    /// (V210-78). A retired attempt — its connection died, its room was held again — is aborted
    /// and reports nothing, so the `SyncDone` such a consent waits for never comes. One waiting on
    /// a dial is left to `Dialed` or `ReachFailed`.
    async fn retry_orphaned_consents(&mut self) {
        let net = self.net.as_ref().map(Arc::clone);
        let orphaned: Vec<(Digest32, Digest32)> = self
            .pending_consents
            .iter()
            .map(|(room, target, _, _)| (*room, *target))
            .filter(|key| {
                net.as_ref()
                    .is_some_and(|n| n.manager().existing(&key.1).is_some())
                    && !self.ports.get(key).is_some_and(|p| p.busy())
            })
            .collect();
        if orphaned.is_empty() {
            return;
        }
        self.answer_pending_consents(|room, target| orphaned.contains(&(*room, *target)), None)
            .await;
    }

    /// Consent to `target` reading this identity's messages — ADR-007 step 3, the
    /// human decision, taken per sender.
    async fn consent(&mut self, channel_id: &Digest32, target: Digest32, asked: bool) -> Outcome {
        let outcome = self.release_key_to(channel_id, target, asked).await;
        if outcome.is_done() {
            let _ = self.event_tx.send(NodeEvent::Consented {
                channel_id: *channel_id,
                target,
            });
        }
        outcome
    }

    /// The consent-order value of `target`'s current trust decision (V210-45), or `None` if it
    /// has none — a decision from before the order was kept entitles to no history.
    fn trust_decision(&self, target: &Digest32) -> Option<crate::node::consent_order::Stamp> {
        if !self.trust.is_trusted(target) {
            return None;
        }
        let profile = self.profile.as_ref()?;
        let signer = profile.signer().ok()?;
        crate::node::consent_order::ConsentOrder::load(profile.store(), signer)
            .ok()?
            .trusted_at(target)
    }

    /// Stamp a new trust decision for `fingerprint` in the consent order and mark where every
    /// open room's sender key stands at it (V210-45). The stamp is floored by every open room's
    /// newest generation, so a lost or rolled-back counter cannot make one of them look minted
    /// after this decision.
    async fn stamp_trust_decision(&mut self, fingerprint: Digest32) {
        let Some(profile) = self.profile.as_ref() else {
            return;
        };
        let Ok(signer) = profile.signer() else {
            return;
        };
        let shared: Vec<_> = self.channels.values().map(Arc::clone).collect();
        let mut floor = 0u64;
        for ch in &shared {
            floor = floor.max(ch.lock().await.newest_mint_seq());
        }
        let Ok(decision) =
            crate::node::consent_order::stamp_trust(profile.store(), signer, fingerprint, floor)
        else {
            return;
        };
        // **One commit for every room** (#189): each room marks and seals under its own lock,
        // and the write happens once, after, with no room's lock held. A commit per room made
        // `vox trust add` cost one durable commit per open room on the actor, about 7 s at
        // 1,600 rooms. The write transaction is never held while awaiting a room's lock: a sync
        // holds a room's lock while it waits for a write transaction, so that order would
        // deadlock. Nothing else on the actor runs between the seals and the commit, and nothing
        // off it writes a room's marks, so no newer marks can be overwritten by these.
        let mut sealed: Vec<(SharedChannel, Digest32, crate::atrest::store::SealedSegment)> =
            Vec::new();
        for ch in shared {
            let (seg, id) = {
                let mut room = ch.lock().await;
                (
                    room.mark_trust_sealed(fingerprint, decision),
                    room.channel_id(),
                )
            };
            if let Ok(Some(seg)) = seg {
                sealed.push((ch, id, seg));
            }
        }
        if sealed.is_empty() {
            return;
        }
        let written = (|| -> crate::error::Result<()> {
            let mut batch = profile.store().batch()?;
            for (_, id, seg) in &sealed {
                ChannelState::queue_marks(&mut batch, id, seg)?;
            }
            batch.commit()
        })();
        if written.is_err() {
            // As a failed per-room write always did: memory is ahead of the store.
            for (ch, _, _) in sealed {
                ch.lock().await.poison();
            }
        }
    }

    /// Mark, in a room just opened, every trust decision taken while it was closed (V210-45).
    async fn mark_decisions_on_open(&mut self, channel_id: &Digest32) {
        let (Some(profile), Some(shared)) = (
            self.profile.as_ref(),
            self.channels.get(channel_id).map(Arc::clone),
        ) else {
            return;
        };
        let Ok(signer) = profile.signer() else {
            return;
        };
        let Ok(order) = crate::node::consent_order::ConsentOrder::load(profile.store(), signer)
        else {
            return;
        };
        let _ = shared
            .lock()
            .await
            .mark_decisions_on_open(profile.store(), &order);
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
        let newly = !self.trust.is_trusted(&fingerprint);
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
        if newly {
            // The decision's place in the consent order, and where each open room's sender
            // key stands at it (V210-45). A rename is the same decision and keeps its place.
            // Nothing else runs on the actor in between, so no post is sealed between the
            // stamp and the marks. A failure here narrows what the member will read and
            // never widens it, so it does not undo the trust.
            self.stamp_trust_decision(fingerprint).await;
        }
        // The reacher sets are a join of the ring with each room's author set, so both
        // inputs must push. Immediately, not on the tick: a stream parked open across
        // this instant is judged by the set as it stands when its request lands (M17.11).
        self.refresh_reachers().await;
        self.deliver_owed_consents(Some(fingerprint)).await;
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
        // A consent decided for this identity and not yet delivered is withdrawn with the trust
        // it came from, in every room, open or not: a later re-trust takes a key of its own
        // moment, never this one's (V210-30).
        let mut pending = self.consent_keys.clone();
        if pending.forget(fingerprint) {
            if let Err(e) = pending.save(profile.store(), signer) {
                return Outcome::Failed(fault_of(&e));
            }
            self.consent_keys = pending;
        }
        // The decision goes with the trust (V210-45). Not load-bearing: a re-trust always draws
        // a new place in the consent order, and a decision is only read for a trusted identity,
        // so a failure here leaves nothing that could widen a later release.
        let _ = crate::node::consent_order::forget_trust(profile.store(), signer, fingerprint);
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
    ///
    /// `asked_for` is the identity a person just trusted: it is dialled at once rather than after
    /// the automatic spacing, and only once, since a connection is per member and not per room.
    /// Nothing here waits for a dial (see `reach_member`); consent follows on `Dialed`. Waiting
    /// made `vox trust add` freeze the node for 10s per offline trusted member per room.
    async fn deliver_owed_consents(&mut self, asked_for: Option<Digest32>) {
        if self.net.is_none() {
            return;
        }
        self.deliver_reopens().await;
        if self.trust.is_empty() {
            return;
        }
        let trusted = self.trust.trusted();
        let channels: Vec<Digest32> = self.channels.keys().copied().collect();
        let mut asked_for = asked_for;
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
                let asked = asked_for == Some(target);
                let outcome = self.consent(&channel_id, target, asked).await;
                if asked && matches!(outcome, Outcome::Failed(Fault::Unreachable)) {
                    asked_for = None;
                }
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
        let rekeyed = self.deliver_rekeys_for(channel_id, true).await;
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
            let _ = self.deliver_rekeys_for(&channel_id, false).await;
        }
    }

    /// Deliver the current generation to the members of one channel that are owed it,
    /// returning how many were re-keyed. A member with no live pairwise session is
    /// skipped, not failed: the tick tries again once there is one.
    async fn deliver_rekeys_for(&mut self, channel_id: &Digest32, asked: bool) -> u64 {
        if self.net.is_none() {
            return 0;
        }
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return 0;
        };
        let (owed, skdm, mut history) = {
            let channel = shared.lock().await;
            let owed = channel.owed_rekeys();
            let history_owed = channel.owed_history();
            if owed.is_empty() && history_owed.is_empty() {
                return 0;
            }
            let Some(profile) = self.profile.as_ref() else {
                return 0;
            };
            // A member owed history gets every generation from its floor to the live one, each
            // at its origin, oldest first (V210-45). At most `MAX_RETAINED_ORIGINS` keys: the
            // work is bounded by the history this identity holds, not by a constant.
            let mut history: BTreeMap<Digest32, Vec<crate::group::skdm::Skdm>> = BTreeMap::new();
            for (target, floor) in history_owed {
                if let Ok(batch) = channel.history_skdms(profile, &target, floor) {
                    history.insert(target, batch);
                }
            }
            // Each member's re-key from where its entitlement begins (V210-45).
            let mut skdm: BTreeMap<Digest32, crate::group::skdm::Skdm> = BTreeMap::new();
            for target in &owed {
                if let Ok(s) = channel.rekey_skdm_for(profile, target) {
                    skdm.insert(*target, s);
                }
            }
            (owed, skdm, history)
        };
        let mut delivered = 0u64;
        let now_secs = self.now();
        let targets: BTreeSet<Digest32> = owed.into_iter().chain(history.keys().copied()).collect();
        for target in targets {
            // A member whose last keys were not taken waits out its backoff, unless a person asked.
            if !asked
                && self
                    .key_backoff
                    .get(&(*channel_id, target))
                    .is_some_and(|(_, until)| now_secs < *until)
            {
                continue;
            }
            // **A key still in flight is not sent again** (V210-88): nothing is recorded as
            // delivered until the member takes it, so until it answers it stays owed here. A
            // history batch waits for the one in flight; history itself is not held back by a
            // single key, since a consent's own key is in flight when its history is sent.
            let pair = (*channel_id, target);
            if self.history_in_flight.contains_key(&pair)
                || (!history.contains_key(&target) && self.keys_in_flight.contains_key(&pair))
            {
                continue;
            }
            // Open a session from the member's bundle record if none exists, and reach
            // them through the ladder rather than requiring a live connection: a re-key
            // that only reaches members this process happened to join with is the M15
            // gap ADR-016 recorded, and it is what made revocation undeliverable after
            // a restart.
            let hello = self.ensure_session(channel_id, target).await;
            let Some(conn) = self.reach_member(channel_id, target, asked).await else {
                continue;
            };
            let batch = history.remove(&target);
            let owes_history = batch.is_some();
            let keys: Vec<&crate::group::skdm::Skdm> = match batch.as_ref() {
                Some(b) => b.iter().collect(),
                None => match skdm.get(&target) {
                    Some(k) => vec![k],
                    None => continue,
                },
            };
            let mut all_sent = true;
            let mut hello_left = hello.as_ref();
            let mut watched = 0u32;
            for key in keys {
                let Some(session) = self.sessions.get_mut(&(*channel_id, target)) else {
                    all_sent = false;
                    break;
                };
                // The hello rides the first key only: the peer holds the session after it.
                let Ok(sent) = crate::node::pairwise_stream::deliver_skdm(
                    &conn,
                    channel_id,
                    session,
                    key,
                    hello_left.take(),
                )
                .await
                else {
                    all_sent = false;
                    break;
                };
                // Each key's own generation: a refusal re-owes exactly what was refused, and it is
                // recorded as delivered only once taken (V210-88).
                self.watch_delivery(sent, *channel_id, target, key.body.chain_id, owes_history);
                watched += 1;
            }
            if owes_history && watched > 0 {
                // Answers are handled on this actor, after this returns: none is lost.
                self.history_in_flight.insert(pair, (watched, !all_sent));
            }
            if all_sent {
                delivered += 1;
            }
        }
        delivered
    }

    /// A key watched by [`Self::watch_delivery`] was answered, taken or not: one fewer in flight.
    fn key_landed(&mut self, channel_id: Digest32, peer: Digest32) {
        let key = (channel_id, peer);
        if let Some(n) = self.keys_in_flight.get_mut(&key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.keys_in_flight.remove(&key);
            }
        }
    }

    /// A key of the history batch in flight to `peer` was answered. Returns whether that was the
    /// last one and every key of the whole batch was taken, so the history is delivered.
    fn history_landed(&mut self, channel_id: Digest32, peer: Digest32, taken: bool) -> bool {
        let key = (channel_id, peer);
        let Some((left, short)) = self.history_in_flight.get_mut(&key) else {
            return false;
        };
        *left = left.saturating_sub(1);
        *short |= !taken;
        if *left > 0 {
            return false;
        }
        let whole = !*short;
        self.history_in_flight.remove(&key);
        whole
    }

    /// **A member this node has just learned of is passed on at once**, like a local append.
    ///
    /// Membership travels on boards: a member who joins through one node puts its records on
    /// that node's board, and every other member learned of it only by reading that board on
    /// its own periodic sync (`SYNC_INTERVAL_SECS`, 30 s). Measured with three real nodes: the
    /// third member saw a new one 24–28 s after the join returned; with the interval forced to
    /// 5 s, 1.9–2.6 s. So when this node's board gains a bundle record from an author it has
    /// not seen, it admits what the evidence allows and pushes the room to its connected members.
    /// That push offers their boards the records they lack (`start_outbound`), and each receiving
    /// member does the same once, when the newcomer is new to it.
    ///
    /// **Bounded, not a storm.** Only a *new author* triggers this: a member's periodic refresh of
    /// its own records does not. Each node therefore pushes at most once per newcomer, which is
    /// the same fan-out one chat message already has, and in a 500-member room it is one pass per
    /// member per join, over the connections it already holds, with nothing forwarded twice
    /// because a board that already holds the record does not grow.
    async fn note_new_members(&mut self, channel_id: &Digest32) {
        // Not deferred while a session runs; see `publish_channel_to_anchors`.
        let (Some(net), Some(shared)) = (
            self.net.as_ref().map(Arc::clone),
            self.channels.get(channel_id).map(Arc::clone),
        ) else {
            return;
        };
        let epoch = shared.lock().await.epoch();
        let bundles = net.board_bundles(channel_id, epoch);
        let known = self.board_authors.entry(*channel_id).or_default();
        let fresh = bundles.iter().filter(|b| known.insert(b.author_id)).count();
        if fresh == 0 {
            return;
        }
        if let Some(store) = self.profile.as_ref().map(Profile::store_handle) {
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
        }
        self.refresh_network_view().await;
        // New board members raise a request on the room's ports (ADR-025 D2): the outbound setup
        // offers each peer's board the records it lacks, which carries the newcomer to every
        // connected member at once.
        for ((room, _), port) in &mut self.ports {
            if room == channel_id {
                port.raise();
            }
        }
        self.note_local_append(channel_id);
    }

    /// Take what a discovery or a renewal was granted, **per address family** (V210-75).
    ///
    /// A family granted again is held anew and renewed at half its lease. A family that was held,
    /// or was already being retried, and got nothing back this time is retried after a backoff
    /// of its own ([`MAPPING_RETRY_SECS`] doubling to [`MAPPING_RETRY_MAX_SECS`]), and its mapping
    /// is kept, and still advertised, until its lease runs out: the gateway most likely still
    /// holds it, and a lost reply is not a withdrawn mapping. The next try is never later than
    /// that lease's end, so an expired mapping stops being advertised then. A permanent grant
    /// (lifetime zero) is never re-requested; it is deleted when the network stops.
    ///
    /// Both families used to come back in one list, and only an empty list was retried: one
    /// family's lost renewal was dropped, and asked again only at the other's half-lifetime,
    /// about when it expired.
    fn take_mappings(&mut self, fresh: &[crate::nat::portmap::PortMapping]) {
        let now = self.now();
        let mut held = Vec::new();
        let mut due: Option<u64> = None;
        let mut sooner = |at: u64| due = Some(due.map_or(at, |d| d.min(at)));
        for v6 in [false, true] {
            let granted = fresh.iter().find(|m| mapping_is_v6(m) == v6).copied();
            let had = self
                .port_mappings
                .iter()
                .find(|m| mapping_is_v6(m) == v6)
                .copied();
            if let Some(m) = granted {
                held.push(m);
                self.mapping_retry.remove(&v6);
                if m.lifetime_secs > 0 {
                    self.mapping_expires
                        .insert(v6, now + u64::from(m.lifetime_secs));
                    if let Some(at) = renew_at(now, &[m]) {
                        sooner(at);
                    }
                } else {
                    self.mapping_expires.remove(&v6);
                }
                continue;
            }
            if let Some(m) = had.filter(|m| m.lifetime_secs == 0) {
                held.push(m);
                continue;
            }
            if had.is_none() && !self.mapping_retry.contains_key(&v6) {
                continue; // never granted: no gateway for this family, nothing to keep alive
            }
            let wait = (self.mapping_retry.get(&v6).copied().unwrap_or(0) * 2)
                .clamp(MAPPING_RETRY_SECS, MAPPING_RETRY_MAX_SECS);
            self.mapping_retry.insert(v6, wait);
            let mut at = now + wait;
            match (had, self.mapping_expires.get(&v6).copied()) {
                (Some(m), Some(expires)) if now < expires => {
                    held.push(m);
                    at = at.min(expires);
                }
                _ => {
                    self.mapping_expires.remove(&v6);
                }
            }
            sooner(at);
        }
        self.port_mappings = held;
        self.renew_mappings_at = due;
    }

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
        // The mappings whose lease has not run out, so a family whose renewal fails this time
        // is still advertised at its mapped address until the lease ends (V210-75).
        let now = self.now();
        let leased: Vec<crate::nat::portmap::PortMapping> = self
            .port_mappings
            .iter()
            .filter(|m| {
                m.lifetime_secs == 0
                    || self
                        .mapping_expires
                        .get(&mapping_is_v6(m))
                        .is_some_and(|at| now < *at)
            })
            .copied()
            .collect();
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let mappings = net.refresh_advertised(&leased).await;
            let _ = tx.send(NetEvent::AddressesDiscovered { mappings }).await;
        });
    }

    /// ADR-025: a local append bumped the room's generation (inside the room's own write), so the
    /// room's ports are evaluated when this event ends and any peer not holding the entry gets a
    /// session. A room with a port missing for a connected peer is discovered again first.
    fn note_local_append(&mut self, channel_id: &Digest32) {
        if self.net.is_none() {
            return;
        }
        self.sched_rooms.insert(*channel_id);
        self.discover_rooms.insert(*channel_id);
    }

    /// The room instance `channel_id` names now, and its generation counter.
    async fn room_ref(
        &self,
        channel_id: &Digest32,
    ) -> Option<(
        crate::node::ports::RoomRef,
        Arc<std::sync::atomic::AtomicU64>,
    )> {
        use crate::node::ports::RoomRef;
        if let Some(shared) = self.channels.get(channel_id) {
            let gen = shared.lock().await.generation();
            return Some((RoomRef::Channel(Arc::downgrade(shared)), gen));
        }
        if let Some(state) = self.anchored.get(channel_id) {
            let gen = state.lock().await.generation();
            return Some((RoomRef::Anchored(Arc::downgrade(state)), gen));
        }
        None
    }

    /// The room instance `channel_id` names now, without its lock.
    fn current_room(&self, channel_id: &Digest32) -> Option<crate::node::ports::RoomRef> {
        use crate::node::ports::RoomRef;
        if let Some(shared) = self.channels.get(channel_id) {
            return Some(RoomRef::Channel(Arc::downgrade(shared)));
        }
        self.anchored
            .get(channel_id)
            .map(|s| RoomRef::Anchored(Arc::downgrade(s)))
    }

    /// Whether `peer` shares `channel_id` with this node: a member (or an anchor) of a room this
    /// node holds, or an author of a room it keeps as an anchor. May admit the peer from this
    /// node's own board first (see [`Self::may_sync`]): a peer that has just joined is on the
    /// board before it is in the author table, and skipping it for that lost posts made right
    /// after a join.
    async fn shares_room(&mut self, channel_id: &Digest32, peer: &Digest32) -> bool {
        if let Some(shared) = self.channels.get(channel_id).map(Arc::clone) {
            let epoch = shared.lock().await.epoch();
            return self.may_sync(channel_id, peer, epoch).await;
        }
        if self.anchored.contains_key(channel_id) {
            self.refresh_anchored_authors(channel_id).await;
            if let Some(state) = self.anchored.get(channel_id).map(Arc::clone) {
                return state.lock().await.is_author(peer);
            }
        }
        false
    }

    /// Make sure `(channel_id, peer)` has a port for the room instance held now, creating it if
    /// it shares the room. A port for an older instance of the room (closed and held again: a
    /// reopen, an unlock, a new epoch) is retired and replaced. Returns whether a port exists.
    async fn ensure_port(&mut self, channel_id: &Digest32, peer: &Digest32) -> bool {
        let Some(current) = self.current_room(channel_id) else {
            self.drop_port(channel_id, peer);
            return false;
        };
        if let Some(port) = self.ports.get(&(*channel_id, *peer)) {
            if port.room.is(&current) {
                return true;
            }
            self.drop_port(channel_id, peer);
        }
        if !self.shares_room(channel_id, peer).await {
            return false;
        }
        let Some((room, gen)) = self.room_ref(channel_id).await else {
            return false;
        };
        self.ports.insert(
            (*channel_id, *peer),
            crate::node::ports::Port::new(room, gen),
        );
        self.sched_rooms.insert(*channel_id);
        true
    }

    /// Retire a port's attempts and forget it (its room is gone or held again).
    fn drop_port(&mut self, channel_id: &Digest32, peer: &Digest32) {
        if let Some(mut port) = self.ports.remove(&(*channel_id, *peer)) {
            for a in port.take_attempts() {
                a.retire();
            }
        }
        self.port_queue.remove(channel_id, peer);
        crate::node::status::SyncBook::with(&self.sync_book, *channel_id, *peer, |c| {
            c.backoff = None;
        });
    }

    /// Retire every attempt and forget every port (ADR-025 D1a: the node shuts down or locks).
    fn retire_all_ports(&mut self) {
        let keys: Vec<(Digest32, Digest32)> = self.ports.keys().copied().collect();
        for (room, peer) in keys {
            self.drop_port(&room, &peer);
        }
        self.port_queue.clear();
        self.connected.clear();
        self.discovered.clear();
        self.discover_rooms.clear();
        self.discover_peers.clear();
    }

    /// Discover ports for what changed: rooms held or grown since, and peers newly connected.
    async fn discover(&mut self) {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        // A room held since its last discovery (a new instance included) is discovered for every
        // connected peer: this is how a room created, joined or reopened gets its ports, whichever
        // path held it.
        let rooms: Vec<Digest32> = self
            .channels
            .keys()
            .chain(self.anchored.keys())
            .copied()
            .collect();
        for room in &rooms {
            let current = self.current_room(room);
            let known = self.discovered.get(room);
            if match (known, current.as_ref()) {
                (Some(k), Some(c)) => !k.is(c),
                (None, Some(_)) => true,
                _ => false,
            } {
                self.discover_rooms.insert(*room);
                if let Some(c) = current {
                    self.discovered.insert(*room, c);
                }
            }
        }
        self.discovered.retain(|r, _| rooms.contains(r));
        let peers: Vec<Digest32> = self
            .connected
            .iter()
            .copied()
            .filter(|p| net.manager().existing(p).is_some())
            .collect();
        let mut pairs: std::collections::BTreeSet<(Digest32, Digest32)> =
            std::collections::BTreeSet::new();
        for room in std::mem::take(&mut self.discover_rooms) {
            for peer in &peers {
                pairs.insert((room, *peer));
            }
        }
        let fresh_peers = std::mem::take(&mut self.discover_peers);
        for peer in &fresh_peers {
            if net.manager().existing(peer).is_none() {
                continue;
            }
            for room in &rooms {
                pairs.insert((*room, *peer));
            }
        }
        for (room, peer) in pairs {
            let existed = self
                .ports
                .get(&(room, peer))
                .is_some_and(|p| self.current_room(&room).is_some_and(|c| p.room.is(&c)));
            if !self.ensure_port(&room, &peer).await {
                continue;
            }
            // **A new connection** raises a request and clears the backoff (ADR-025 D2, D5).
            if fresh_peers.contains(&peer) && existed {
                if let Some(port) = self.ports.get_mut(&(room, peer)) {
                    port.raise();
                    port.clear_backoff();
                }
                crate::node::status::SyncBook::with(&self.sync_book, room, peer, |c| {
                    c.backoff = None;
                });
                self.sched_rooms.insert(room);
            }
        }
    }

    /// ADR-025 D6a — **evaluate the ports**, at the end of every event that can change what one
    /// needs or free a slot: the ports of the rooms the event touched, every queued port, and
    /// every port when asked (the tick). A port that needs a session, is not backing off, and has
    /// no outbound attempt joins the queue; queued ports get free slots round-robin across peers,
    /// FIFO within a peer, re-checking their need when their turn comes. Returns whether a session
    /// started.
    async fn schedule(&mut self) -> bool {
        if self.net.is_none() {
            self.sched_rooms.clear();
            self.sched_all = false;
            return false;
        }
        self.discover().await;
        let all = std::mem::take(&mut self.sched_all);
        let rooms = std::mem::take(&mut self.sched_rooms);
        let now = std::time::Instant::now();
        // Candidates: the event's rooms' ports (or all), and everything already queued.
        let mut scope: Vec<(Digest32, Digest32)> = self
            .ports
            .keys()
            .filter(|(r, _)| all || rooms.contains(r))
            .copied()
            .collect();
        let queued_before: std::collections::BTreeSet<(Digest32, Digest32)> =
            self.port_queue.all().into_iter().collect();
        scope.extend(queued_before.iter().copied());
        scope.sort_unstable();
        scope.dedup();
        let mut newly_queued: Vec<(Digest32, Digest32)> = Vec::new();
        for key in scope {
            let (room, peer) = key;
            // A port whose room was closed or held again starts over.
            match self.current_room(&room) {
                Some(c) if self.ports.get(&key).is_some_and(|p| !p.room.is(&c)) => {
                    self.drop_port(&room, &peer);
                    self.discover_rooms.insert(room);
                    continue;
                }
                None => {
                    self.drop_port(&room, &peer);
                    continue;
                }
                Some(_) => {}
            }
            let eligible = self.port_eligible(&key, now);
            let Some(port) = self.ports.get_mut(&key) else {
                continue;
            };
            if eligible && !port.queued {
                port.queued = true;
                self.port_queue.push(room, peer);
                newly_queued.push(key);
            } else if !eligible && port.queued && port.out.is_none() {
                port.queued = false;
                self.port_queue.remove(&room, &peer);
            }
        }
        // **A port with no connection reaches its peer** (ADR-025 D2, V210-58 #246). A port runs
        // only over a connection that exists, and nothing else dials a member for sync: members are
        // dialled for key work, and through the board's anchor. So a member whose connection was
        // dropped — silent past `SILENCE_IS_DEATH` (30 s), a laptop lid, a frozen process — was
        // never synced with again once the anchor was gone too: two members with a backlog each
        // for the other sat for 150 s with neither dialling (CI run 36452063803). One reach per
        // peer at a time, off the actor, paced by the port's own backoff: a failed reach backs the
        // peer's ports off as Unreachable (`NetEvent::ReachFailed`, 200 ms doubling to 8 s). Not
        // `reach_member`'s 30 s spacing for key work: with it, two members who each tried the other
        // while the other was away could not try again for up to 30 s after both were back (#246's
        // proof: 1 run in 2 still unsynced 10 s after).
        let lacking: std::collections::BTreeMap<Digest32, Digest32> = self
            .ports
            .iter()
            .filter(|(key, port)| {
                port.out.is_none()
                    && port.needs()
                    && !port.backing_off(now)
                    && !self.publishing.contains(*key)
                    && self
                        .net
                        .as_ref()
                        .is_some_and(|n| n.manager().existing(&key.1).is_none())
            })
            .map(|((room, peer), _)| (*peer, *room))
            .collect();
        for (peer, room) in lacking {
            self.reach_for_sync(&room, peer);
        }
        let mut ran = false;
        loop {
            let slots = Arc::clone(&self.slots);
            let Some((room, peer)) = self
                .port_queue
                .pop(|p| crate::node::ports::Slots::free_for(&slots, p))
            else {
                break;
            };
            if let Some(port) = self.ports.get_mut(&(room, peer)) {
                port.queued = false;
            }
            // Its turn: does it still need a session?
            if !self.port_eligible(&(room, peer), std::time::Instant::now()) {
                continue;
            }
            if self.start_outbound(room, peer).await {
                ran = true;
            }
        }
        for key in newly_queued {
            if self.ports.get(&key).is_some_and(|p| p.queued) {
                crate::node::status::SyncBook::with(&self.sync_book, key.0, key.1, |c| {
                    c.queued += 1;
                });
            }
        }
        ran
    }

    /// Whether a port may start an outbound session now: it needs one, has none running, is not
    /// backing off, its peer is connected, and no publish round to that peer for the room is in
    /// flight (the round's records must reach the board before a session reads it). Inbound
    /// attempts are ignored (ADR-025 D4: full duplex).
    fn port_eligible(&self, key: &(Digest32, Digest32), now: std::time::Instant) -> bool {
        let Some(port) = self.ports.get(key) else {
            return false;
        };
        port.out.is_none()
            && port.needs()
            && !port.backing_off(now)
            && !self.publishing.contains(key)
            && self
                .net
                .as_ref()
                .is_some_and(|n| n.manager().existing(&key.1).is_some())
    }

    /// The tick's part in sync (ADR-025 D1a, D7): retire attempts whose connection died, and every
    /// [`SYNC_INTERVAL_SECS`](crate::node::syncstream::SYNC_INTERVAL_SECS) raise the periodic
    /// request on every port, rediscover every room and evaluate every port. Nothing else waits
    /// for the tick: every event that changes what a port needs evaluates it when it ends (D6a),
    /// and no proof passes because of the tick (D7).
    async fn sync_tick(&mut self) {
        let dead: Vec<((Digest32, Digest32), crate::node::ports::Token)> = self
            .ports
            .iter()
            .flat_map(|(k, p)| {
                p.out
                    .iter()
                    .chain(p.inbound.values())
                    .filter(|a| a.conn.quinn().close_reason().is_some())
                    .map(move |a| (*k, a.token))
            })
            .collect();
        for (key, token) in dead {
            if let Some(a) = self.ports.get_mut(&key).and_then(|p| p.take(token)) {
                a.retire();
                self.sched_rooms.insert(key.0);
            }
        }
        let now = self.now();
        if now >= self.next_request_at {
            self.next_request_at = now + crate::node::syncstream::SYNC_INTERVAL_SECS;
            for port in self.ports.values_mut() {
                port.raise();
            }
            self.discover_rooms
                .extend(self.channels.keys().chain(self.anchored.keys()).copied());
            self.sched_all = true;
        }
    }

    /// Put a port in backoff after a failed session (ADR-025 D5), and arm its wakeup.
    fn enter_backoff(
        &mut self,
        channel_id: Digest32,
        peer: Digest32,
        kind: crate::node::status::BackoffKind,
    ) {
        let Some(port) = self.ports.get_mut(&(channel_id, peer)) else {
            return;
        };
        let prior = port.backoff;
        let failures = prior.map_or(0, |b| b.failures).saturating_add(1);
        let timer = prior.map_or(0, |b| b.timer).wrapping_add(1);
        let wait = crate::node::ports::backoff_wait(kind, failures);
        port.backoff = Some(crate::node::ports::Backoff {
            until: Some(std::time::Instant::now() + wait),
            failures,
            kind,
            timer,
        });
        crate::node::status::SyncBook::with(&self.sync_book, channel_id, peer, |c| {
            c.backoff = Some((kind, failures));
        });
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(wait).await;
            let _ = tx
                .send(NetEvent::BackoffExpired {
                    channel_id,
                    peer,
                    timer,
                })
                .await;
        });
    }

    /// Start an outbound session on a port that has a slot's turn (ADR-025 D6): learn who else
    /// has joined, then run the session on a detached task, reporting through
    /// [`NetEvent::SyncDone`] with its token. Returns whether it started.
    ///
    /// Not awaited — see [`NetEvent::SyncDone`] for why awaiting deadlocks two nodes that start
    /// at the same moment.
    async fn start_outbound(&mut self, channel_id: Digest32, peer: Digest32) -> bool {
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
            self.channels.get(&channel_id).map(Arc::clone),
            self.anchored.get(&channel_id).map(Arc::clone),
        ) {
            (Some(shared), _) => SessionTarget::Channel(shared),
            (None, Some(state)) => SessionTarget::Anchored(state),
            (None, None) => return false,
        };
        // An anchor's authors come from its own board, which is local: cheap, and it has to happen
        // before the session so the anchor can verify what arrives.
        if matches!(target, SessionTarget::Anchored(_)) {
            self.refresh_anchored_authors(&channel_id).await;
        }
        let wake = self.net_tx.clone();
        let Some(slot) = crate::node::ports::Slots::take(
            &self.slots,
            peer,
            Box::new(move || {
                // The tick evaluates every port anyway, so a wake lost to a full queue costs at
                // most a second.
                let _ = wake.try_send(NetEvent::SlotFreed);
            }),
        ) else {
            return false;
        };
        let Some(port) = self.ports.get_mut(&(channel_id, peer)) else {
            return false;
        };
        let token = self.next_token;
        self.next_token += 1;
        let fence = crate::transport::stream_transport::Fence::new();
        port.out = Some(crate::node::ports::Attempt {
            token,
            dir: crate::node::ports::Dir::Out,
            conn: Arc::clone(&conn),
            req_at_start: port.req_gen,
            started: std::time::Instant::now(),
            abort: None,
            fence: Arc::clone(&fence),
        });
        crate::node::status::SyncBook::with(&self.sync_book, channel_id, peer, |c| c.opened += 1);
        let admit_store = self.profile.as_ref().map(Profile::store_handle);
        let cid = channel_id;
        let now = self.now();
        let tx = self.net_tx.clone();
        let task = tokio::spawn(async move {
            // 1. Learn who else has joined, or the first entry from a newer member is refused
            //    (ADR-008). A round trip, so it belongs here and not on the actor.
            let mut admitted_authors = 0usize;
            let epoch = match &target {
                SessionTarget::Channel(shared) => {
                    let known = shared.lock().await.epoch();
                    // **Bounded** (ADR-025 D6): the board read and the offer are best-effort, and a
                    // live peer answers them in milliseconds. Unbounded, a peer that stopped
                    // answering held this slot and the port's one outbound attempt until the
                    // connection was filed dead, past the limit D6 states (a frame timeout plus
                    // the budgets).
                    let setup = async {
                        if let Some(pstore) = admit_store {
                            if let Ok(set) = net.fetch_channel(&conn, &cid, known).await {
                                {
                                    let mut ch = shared.lock().await;
                                    let before = ch.author_keys().len();
                                    let _ = admit_board_records(
                                        &mut ch,
                                        &pstore,
                                        &set.bundles,
                                        ChannelState::MAX_ADMISSIONS_PER_SWEEP,
                                        now,
                                    )
                                    .await;
                                    admitted_authors =
                                        ch.author_keys().len().saturating_sub(before);
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
                                // **And the other way: what this node's board holds that the peer's
                                // lacks.** A member who joined through this node is on this node's
                                // board and no other, and the peer learned of it only when *it* next
                                // read this board, on its own periodic sync: 24–28 s for a third
                                // member to see a new one, measured. Offered here, a push that follows
                                // a join carries the newcomer to every connected member at once.
                                // Best-effort: a refusal (a record the peer's board already holds
                                // newer) costs nothing, and the peer's own sync still reads this board.
                                let missing = net.board_records_missing_from(&cid, known, &set);
                                if !missing.is_empty() {
                                    if let Ok(mut client) =
                                        crate::nat::service::RendezvousClient::open(&conn).await
                                    {
                                        for wire in &missing {
                                            if let Err(e) = client.put(wire).await {
                                                if !matches!(e, Error::RendezvousRejected(_)) {
                                                    break;
                                                }
                                            }
                                        }
                                        client.finish();
                                    }
                                }
                            }
                        }
                    };
                    let _ = tokio::time::timeout(SETUP_PATIENCE, setup).await;
                    shared.lock().await.epoch()
                }
                SessionTarget::Anchored(state) => state.lock().await.epoch(),
            };
            // 2. Open the stream. Also a round trip. **A stream that will not open still
            //    reports**: every exit from this task sends `SyncDone`.
            let handle = tokio::runtime::Handle::current();
            let transport =
                match crate::node::syncstream::open_sync(&conn, handle, &cid, epoch).await {
                    Ok(t) => t.fenced(Arc::clone(&fence)),
                    Err(e) => {
                        let _ = tx
                            .send(NetEvent::SyncDone {
                                channel_id: cid,
                                peer,
                                token,
                                report: crate::node::channel::SessionReport::failed(
                                    crate::node::channel::SyncFailure::Unreachable(e.to_string()),
                                ),
                            })
                            .await;
                        return;
                    }
                };
            // 3. Run the session on a blocking thread, which **holds the slot** until it exits
            //    (ADR-025 D1a): an abort stops this task, not the worker, so the worker is fenced
            //    instead and the slot bounds running workers.
            let mut report = run_session_worker(
                target,
                store,
                transport,
                now,
                fence,
                tx.clone(),
                cid,
                Some(slot),
            )
            .await;
            report.out.admitted_authors = admitted_authors;
            let _ = tx
                .send(NetEvent::SyncDone {
                    channel_id: cid,
                    peer,
                    token,
                    report,
                })
                .await;
        });
        if let Some(a) = self
            .ports
            .get_mut(&(channel_id, peer))
            .and_then(|p| p.out.as_mut())
            .filter(|a| a.token == token)
        {
            a.abort = Some(task.abort_handle());
        }
        true
    }

    /// Run an admitted inbound session on its own task (no slot: ADR-025 D6), reporting through
    /// [`NetEvent::SyncDone`] with its token.
    fn start_inbound(
        &mut self,
        channel_id: Digest32,
        peer: Digest32,
        conn: Arc<VoxConnection>,
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
        let Some(port) = self.ports.get_mut(&(channel_id, peer)) else {
            return;
        };
        let token = self.next_token;
        self.next_token += 1;
        let fence = crate::transport::stream_transport::Fence::new();
        port.inbound.insert(
            token,
            crate::node::ports::Attempt {
                token,
                dir: crate::node::ports::Dir::In,
                conn,
                req_at_start: port.req_gen,
                started: std::time::Instant::now(),
                abort: None,
                fence: Arc::clone(&fence),
            },
        );
        crate::node::status::SyncBook::with(&self.sync_book, channel_id, peer, |c| {
            c.admitted += 1;
        });
        let now = self.now();
        let tx = self.net_tx.clone();
        let transport = transport.fenced(Arc::clone(&fence));
        let task = tokio::spawn(async move {
            let report = run_session_worker(
                target,
                store,
                transport,
                now,
                fence,
                tx.clone(),
                channel_id,
                None,
            )
            .await;
            let _ = tx
                .send(NetEvent::SyncDone {
                    channel_id,
                    peer,
                    token,
                    report,
                })
                .await;
        });
        if let Some(a) = self
            .ports
            .get_mut(&(channel_id, peer))
            .and_then(|p| p.inbound.get_mut(&token))
        {
            a.abort = Some(task.abort_handle());
        }
    }

    /// File a finished session on its port (ADR-025 D1a, D2, D3, D5). A result for a retired or
    /// unknown token changes nothing on the port but the `stale` counter.
    fn file_session(
        &mut self,
        channel_id: Digest32,
        peer: Digest32,
        token: crate::node::ports::Token,
        report: &crate::node::channel::SessionReport,
    ) -> bool {
        use crate::node::channel::SyncFailure;
        let key = (channel_id, peer);
        let attempt = self.ports.get_mut(&key).and_then(|p| p.take(token));
        let Some(attempt) = attempt else {
            crate::node::status::SyncBook::with(&self.sync_book, channel_id, peer, |c| {
                c.stale += 1
            });
            return false;
        };
        let o = &report.out;
        let progress = o.progress();
        crate::node::status::SyncBook::with(&self.sync_book, channel_id, peer, |c| {
            c.refused += u64::try_from(o.refused).unwrap_or(u64::MAX);
            match &report.fail {
                None if o.complete => c.completed += 1,
                None => c.partial += 1,
                Some(f) => {
                    c.failed += 1;
                    c.last_failure = Some(f.to_string());
                }
            }
        });
        self.sched_rooms.insert(channel_id);
        if let Some(SyncFailure::Poisoned(_)) = &report.fail {
            // The room is poisoned: its ports retire their attempts and wait for a reopen, which
            // holds a new room instance and so new ports. No retry until then.
            let keys: Vec<(Digest32, Digest32)> = self
                .ports
                .keys()
                .filter(|(r, _)| *r == channel_id)
                .copied()
                .collect();
            for k in keys {
                if let Some(p) = self.ports.get_mut(&k) {
                    p.poisoned = true;
                    for a in p.take_attempts() {
                        a.retire();
                    }
                    p.queued = false;
                }
                self.port_queue.remove(&k.0, &k.1);
            }
            return true;
        }
        let Some(port) = self.ports.get_mut(&key) else {
            return true;
        };
        if progress {
            port.last_progress = Some(std::time::Instant::now());
            if let Some(b) = port.backoff.as_mut() {
                b.failures = 0;
            }
        }
        // **A clean session the peer opened releases a backoff that said the peer could not take
        // ours** (ADR-025 D5, V210-34). The peer just ran a session with this node, in this room, at
        // this epoch, over a live connection: whatever refused this side's own (`Policy`: the room
        // not held there yet, another epoch; `Busy`; `Unreachable`) no longer holds, so the port
        // syncs at once instead of waiting out the backoff. Measured through the shipped binaries
        // (P2, CI run 36389831839): a joiner refuses the push its host makes while it is still
        // sealing the room (`EpochMismatch`), the host's port took a 30 s `Policy` backoff, and a
        // post made there 6 s later reached the joiner after 24 s, although the joiner had synced
        // with the host in between. `NoProgress` is kept: a peer that syncs *from* this node says
        // nothing about whether it serves what it advertises (P10).
        if attempt.dir == crate::node::ports::Dir::In
            && report.fail.is_none()
            && port
                .backoff
                .is_some_and(|b| b.kind != crate::node::status::BackoffKind::NoProgress)
        {
            port.clear_backoff();
            crate::node::status::SyncBook::with(&self.sync_book, channel_id, peer, |c| {
                c.backoff = None;
            });
        }
        match &report.fail {
            None if o.complete => {
                // **Clean**: consume the requests this attempt saw, and credit the peer with the
                // generation read with this side's `HAVE` — or that plus what it stored from the
                // peer, when nothing else was stored meanwhile (ADR-025 D2). Monotonic.
                port.req_done = port.req_done.max(attempt.req_at_start);
                if let Some(g_have) = o.gen_have {
                    let n = u64::try_from(o.applied).unwrap_or(u64::MAX);
                    let credit = if o.gen_end == Some(g_have.saturating_add(n)) {
                        g_have.saturating_add(n)
                    } else {
                        g_have
                    };
                    port.done_gen = port.done_gen.max(credit);
                }
                if o.unadmitted > 0 {
                    // Entries from authors this side has not admitted are still owed: ask again,
                    // after learning the room's members (the outbound setup does).
                    port.raise();
                }
            }
            None => {
                // Some requested positions unfilled: the rest is fetched at once when this made
                // progress, and after a `NoProgress` backoff when it did not (a peer advertising
                // what it never serves costs a session per backoff step, never a tight loop).
                port.raise();
                if !progress {
                    self.enter_backoff(
                        channel_id,
                        peer,
                        crate::node::status::BackoffKind::NoProgress,
                    );
                }
            }
            Some(fail) => {
                // **A failure raises a request whether or not it made progress** (ADR-025 D2): what
                // it did not deliver is still owed. Nothing is credited, and the D5 backoff below
                // paces the retry, so a peer that always fails costs a session per backoff step,
                // never a loop. A concurrent completion that made progress while this attempt ran
                // wins over its failure: then the port is not put back in backoff.
                let beaten = port.last_progress.is_some_and(|t| t >= attempt.started) && !progress;
                port.raise();
                if !beaten {
                    if let Some(kind) = crate::node::ports::backoff_kind(fail) {
                        self.enter_backoff(channel_id, peer, kind);
                    }
                }
            }
        }
        true
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
        // A person's `vox room sync` raises a request on every port of the room and clears its
        // backoff (ADR-025 D2, D5). `Done` once a session runs or waits for its slot.
        let mut synced = 0usize;
        for peer in peers {
            if !self.ensure_port(channel_id, &peer).await {
                continue;
            }
            if let Some(port) = self.ports.get_mut(&(*channel_id, peer)) {
                port.raise();
                port.clear_backoff();
            }
            crate::node::status::SyncBook::with(&self.sync_book, *channel_id, peer, |c| {
                c.backoff = None;
            });
        }
        self.sched_rooms.insert(*channel_id);
        self.schedule().await;
        for ((room, _), port) in &self.ports {
            if room == channel_id && (port.out.is_some() || port.queued) {
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
        conn: Arc<VoxConnection>,
        peer: Digest32,
        channel_id: Digest32,
        epoch: u64,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) {
        use crate::node::syncstream::accept_sync;
        // **Full duplex** (ADR-025 D4, the decider's option C): an inbound session is admitted
        // beside this side's own outbound one for the same room and peer, so two members that post
        // at once no longer refuse each other and retry at random (a hub's CSMA/CD). Up to
        // `INBOUND_PER_PORT` inbound sessions per port: a correct peer holds one outbound per port,
        // and the other two cover this side still applying the peer's previous sessions at
        // turnover.
        //
        // **Past that, refused at once with `SessionBusy`, never held**: a queue of half-finished
        // exchanges is exactly the resource a flood wants to fill. Refused before the room's lock,
        // not after, because this is the actor. Said to a room peer, so its session ends as
        // `SessionBusy` (#202) and it backs off (D5 kind `Busy`).
        let inbound_now = self
            .ports
            .get(&(channel_id, peer))
            .map_or(0, |p| p.inbound.len());
        if inbound_now >= crate::node::ports::INBOUND_PER_PORT {
            crate::node::status::SyncBook::with(&self.sync_book, channel_id, peer, |c| {
                c.busy_refused += 1;
            });
            let (mut send, mut recv) = (send, recv);
            if self.owed_a_reason(&channel_id, &peer, epoch) {
                crate::node::net::refuse_stream_because(
                    &mut send,
                    &mut recv,
                    crate::wire::WireError::SessionBusy,
                );
            } else {
                crate::node::net::refuse_stream(&mut send, &mut recv);
            }
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

        // **Refused, not dropped.** A node asked for a room it does not hold — an anchor that keeps
        // no log for it, most often — or at an epoch it is not at, returned here and let the streams
        // fall, and the initiator learned only `sync failed: transport` — indistinguishable from a
        // connection that died. Every push to an anchor that keeps no log for the room read as a
        // network fault. A coded reset says what happened. (It does not recover time: a dropped
        // stream already ended the initiator's session within milliseconds, measured; the long
        // losses once blamed on this were the room-wide starvation v0.2.8 fixed.)
        if !matches_epoch {
            let (mut send, mut recv) = (send, recv);
            if self.owed_a_reason(&channel_id, &peer, epoch) {
                crate::node::net::refuse_stream_because(
                    &mut send,
                    &mut recv,
                    crate::wire::WireError::EpochMismatch,
                );
            } else {
                crate::node::net::refuse_stream(&mut send, &mut recv);
            }
            return;
        }
        if !self.may_sync(&channel_id, &peer, epoch).await {
            // Refused explicitly, with the same coded reset as a stream kind the peer may not
            // open, rather than left to read for a frame that never comes.
            let (mut send, mut recv) = (send, recv);
            crate::node::net::refuse_stream(&mut send, &mut recv);
            return;
        }
        // Admitted: the port exists for the room instance held now (it may not have been
        // discovered yet, since the peer spoke first).
        if !self.ensure_port(&channel_id, &peer).await {
            let (mut send, mut recv) = (send, recv);
            crate::node::net::refuse_stream(&mut send, &mut recv);
            return;
        }
        let transport = accept_sync(tokio::runtime::Handle::current(), send, recv);
        self.start_inbound(channel_id, peer, conn, transport);
    }

    /// Whether `peer` may reconcile `channel_id`'s log with this node.
    ///
    /// - An **admitted author** of that room. If it is not one yet, this node's own board is
    ///   consulted first — local, so cheap — because a member that joined through somebody
    ///   else is on the board before it is in this node's author table, and refusing it for
    ///   that would be the "precondition behind its own check" defect `shares_room` documents.
    ///   Admission there takes the same M17.6 evidence as everywhere else.
    /// - An **anchor of that room** — in the room's own anchor set, which holds this node's
    ///   configured anchors and those the room's link named. It keeps the room's ciphertext by
    ///   design (ADR-016 M15.2b) for members who are away. An anchor named only by *another*
    ///   room's link is not an anchor of this one.
    ///
    /// For a room this node only anchors, the peer must be an author the board knows.
    /// Whether a refusal may tell `peer` **why** (#202): it is this room's session partner, or it
    /// has a member record for the room on the board. Decided without the room's lock, because
    /// the refusals that ask run before it. Anyone else is refused with the uninformative code,
    /// so a stranger who names a room learns nothing about whether this node holds it.
    ///
    /// **And the member that is letting this node in** (#217). A joiner holds the room only once it
    /// has sealed its key — seconds of Argon2id — and the member that admitted it pushes to it the
    /// moment it has: measured, a host reported five syncs with its new member as "authenticator
    /// invalid", all refused while the joiner was still sealing. That member knows the room exists
    /// (it answered the join), so telling it "not held here yet" (`EpochMismatch`) tells it nothing.
    fn owed_a_reason(&self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
        self.ports
            .get(&(*channel_id, *peer))
            .is_some_and(crate::node::ports::Port::busy)
            || self.net.as_ref().is_some_and(|net| {
                net.board_bundles(channel_id, epoch)
                    .iter()
                    .any(|b| b.author_id == *peer)
                    || (self.joining.contains(channel_id)
                        && net.policy().snapshot().join_responders().contains(peer))
            })
    }

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
        let key = (channel_id, peer);
        let hello_hash = crate::hash::sha256(initial);
        let mut replaces = false;
        if self.sessions.contains_key(&key) {
            // The same hello again — the peer re-sending what we already accepted. The
            // session is the one we hold; accepting it twice would re-consume a one-time
            // prekey and reset a ratchet that is already in use.
            if self.accepted_hello.get(&key) == Some(&hello_hash) {
                return true;
            }
            // **Two sessions for one pair** (ADR-021 F12). Keep the one both ends will
            // keep. It used to keep whichever it held, and so did the peer — each kept its
            // own, and neither could open the key the other sent.
            let me = self.profile.as_ref().map(|p| p.fingerprint());
            let existing_mine = self.initiated.contains_key(&key);
            let mut ours_wins =
                me.is_some_and(|me| !incoming_session_wins(&me, &peer, existing_mine));
            if ours_wins
                && self
                    .initiated
                    .get(&key)
                    .is_some_and(|i| i.initial.is_none())
            {
                // Ours was opened on the join path, which delivered its hello, so it has none to
                // offer again (V210-78). A peer sending a hello holds none of ours — it restarted
                // or locked — and kept, ours would split the pair for good: neither end could
                // open what the other sealed. Replace it with a fresh one from the peer's bundle,
                // which can be offered; the rule still keeps it, since it is ours too. With no
                // bundle to open one from, take the peer's instead.
                self.sessions.remove(&key);
                self.initiated.remove(&key);
                self.accepted_hello.remove(&key);
                self.session_serial.remove(&key);
                if self.ensure_session(&channel_id, peer).await.is_some() {
                    self.forget_delivery(&channel_id, &peer).await;
                } else {
                    ours_wins = false;
                }
            }
            if ours_wins {
                // Ours wins. The peer is holding its own, so it must be offered ours
                // again: until it adopts it, nothing we seal can be opened there.
                if let Some(i) = self.initiated.get_mut(&key) {
                    i.hello_delivered = false;
                }
                self.reopen.insert(key);
                return false;
            }
            replaces = true;
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
        self.sessions.insert(key, session);
        self.stamp_session(key);
        self.initiated.remove(&key);
        self.reopen.remove(&key);
        self.accepted_hello.insert(key, hello_hash);
        if replaces {
            // Whatever this node sent under the session it just dropped was sealed where
            // the peer cannot open it: forget that it was delivered, so the tick re-sends
            // the current key over the session both ends now hold.
            self.forget_delivery(&channel_id, &peer).await;
        }
        true
    }

    /// Forget that `peer` holds this identity's current sender key in `channel_id`, so
    /// the next re-key round delivers it again (ADR-021 F12).
    async fn forget_delivery(&mut self, channel_id: &Digest32, peer: &Digest32) {
        let (Some(profile), Some(shared)) = (
            self.profile.as_ref(),
            self.channels.get(channel_id).map(Arc::clone),
        ) else {
            return;
        };
        let mut channel = shared.lock().await;
        let _ = channel.forget_delivery(profile.store(), peer);
        // The history keys went under the dropped session too (V210-45).
        if let Some((from, _)) = channel.entitled_from(peer) {
            let _ = channel.owe_history(profile.store(), *peer, from);
        }
    }

    /// File the session a join just established — `mine` when this node was the joiner,
    /// which opened it — applying the same rule as [`Self::accept_hello`] when a session
    /// for that pair already exists (ADR-021 F12).
    ///
    /// A join can race an auto-consent: the member answering a join may, on its own
    /// tick, have already opened a session to the joiner from its bundle record, because
    /// a trust entry for the joiner predates the join. Keeping whichever arrived last on
    /// one side and whichever arrived first on the other is exactly the split this rule
    /// exists to prevent.
    async fn adopt_join_session(
        &mut self,
        channel_id: Digest32,
        peer: Digest32,
        session: crate::pairwise::session::Session,
        mine: bool,
    ) {
        let key = (channel_id, peer);
        if self.sessions.contains_key(&key) {
            let me = self.profile.as_ref().map(|p| p.fingerprint());
            let existing_mine = self.initiated.contains_key(&key);
            // The rule is stated for an incoming session the PEER opened; a join session
            // this node opened wins exactly when the existing one would lose to ours.
            let incoming_wins = match me {
                Some(me) if mine => existing_mine || me < peer,
                Some(me) => incoming_session_wins(&me, &peer, existing_mine),
                None => true,
            };
            if !incoming_wins {
                if existing_mine {
                    // Ours stands: make sure the peer is offered it.
                    if let Some(i) = self.initiated.get_mut(&key) {
                        i.hello_delivered = false;
                    }
                    self.reopen.insert(key);
                }
                return;
            }
            self.forget_delivery(&channel_id, &peer).await;
        }
        self.sessions.insert(key, session);
        self.stamp_session(key);
        self.accepted_hello.remove(&key);
        self.reopen.remove(&key);
        if mine {
            self.initiated.insert(
                key,
                Initiated {
                    initial: None,
                    hello_delivered: true,
                },
            );
        } else {
            self.initiated.remove(&key);
        }
    }

    /// Offer this node's hello again to every peer that kept a competing session
    /// (ADR-021 F12), with the empty ratchet message behind it that gives the peer a
    /// sending direction — so it adopts the session both ends will keep even when this
    /// node owes it nothing else.
    async fn deliver_reopens(&mut self) {
        let pending: Vec<(Digest32, Digest32)> = self.reopen.iter().copied().collect();
        for (channel_id, peer) in pending {
            let Some(initial) = self
                .initiated
                .get(&(channel_id, peer))
                .and_then(|i| i.initial.clone())
            else {
                // Nothing to offer — a session the join protocol opened, which the peer
                // already holds.
                self.reopen.remove(&(channel_id, peer));
                continue;
            };
            let Some(conn) = self.reach_member(&channel_id, peer, false).await else {
                continue;
            };
            let Some(session) = self.sessions.get_mut(&(channel_id, peer)) else {
                self.reopen.remove(&(channel_id, peer));
                continue;
            };
            if crate::node::pairwise_stream::open_sending_direction(
                &conn,
                &channel_id,
                session,
                Some(&initial),
            )
            .await
            .is_ok()
            {
                // Offered, not delivered: an `Open` is never answered, so the hello counts as
                // held only once a key sealed under the session is taken (V210-89).
                self.reopen.remove(&(channel_id, peer));
            }
        }
    }

    /// Draw the serial of the session just filed for `key`.
    fn stamp_session(&mut self, key: (Digest32, Digest32)) {
        self.last_session_serial = self.last_session_serial.wrapping_add(1);
        self.session_serial.insert(key, self.last_session_serial);
    }

    /// Record that the peer now holds the hello for a session this node opened: it took a key
    /// sealed under it, which it cannot open without the hello (V210-89).
    ///
    /// Written is not delivered. A hello used to count as delivered once it was written, and the
    /// stream can be lost with its connection before the peer reads it. Measured through the real
    /// binaries: two members who trusted each other at once dialled each other at the same
    /// moment, each wrote its hello and key over the connection it dialled, and both streams came
    /// back `connection lost`. Each then held its own session, counted its hello delivered, and
    /// sent every later key without one; the peer, holding its own, refused each with "the key
    /// did not open under the session it holds", and neither ever read the other. Counted only
    /// once taken, every key until then carries the hello, and [`incoming_session_wins`] settles
    /// the pair at both ends however the two opens interleaved.
    fn hello_delivered(&mut self, channel_id: &Digest32, peer: Digest32) {
        if let Some(i) = self.initiated.get_mut(&(*channel_id, peer)) {
            i.hello_delivered = true;
        }
    }

    /// Learn, off the actor, whether the key just written to `target` was taken; if it was not,
    /// `NetEvent::SkdmRefused` makes it owed again. See `pairwise_stream::refused`.
    ///
    /// **Taken is when it is delivered** (V210-88): `NetEvent::SkdmTaken` records generation
    /// `chain_id` as `target`'s, and a `history` key counts towards the batch it belongs to, whose
    /// history is recorded once all of it was taken. Until then the key is only in flight, which
    /// is kept in memory, so a crash leaves it owed and the restarted node sends it again.
    fn watch_delivery(
        &mut self,
        sent: quinn::RecvStream,
        channel_id: Digest32,
        target: Digest32,
        chain_id: u64,
        history: bool,
    ) {
        *self.keys_in_flight.entry((channel_id, target)).or_default() += 1;
        let session = self.session_serial.get(&(channel_id, target)).copied();
        let epoch = self.delivery_epoch;
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let event =
                match crate::node::pairwise_stream::refused(sent, KEY_DELIVERY_PATIENCE).await {
                    Some(why) => NetEvent::SkdmRefused {
                        channel_id,
                        peer: target,
                        chain_id,
                        why,
                        session,
                        history,
                        epoch,
                    },
                    None => NetEvent::SkdmTaken {
                        channel_id,
                        peer: target,
                        chain_id,
                        session,
                        history,
                        epoch,
                    },
                };
            let _ = tx.send(event).await;
        });
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
        asked: bool,
    ) -> Option<Arc<crate::transport::quic::VoxConnection>> {
        let net = self.net.as_ref().map(Arc::clone)?;
        if let Some(conn) = net.manager().existing(&target) {
            return Some(conn);
        }
        let endpoints = net.board_endpoints(channel_id, &target);
        // **Nothing dials a member on the actor.** A dial to a member that is not there waits out
        // `PER_ATTEMPT_TIMEOUT` (10s), and the node answers nobody meanwhile. Measured through the
        // real binaries: a room that had rotated its sender key answered nothing for 10s at a time
        // while one member was offline (`busy 10013ms — sending a message`), and `vox trust add`
        // with two trusted members offline across three rooms froze the node for 31s and then 62s
        // (`busy 61545ms — a client command`) — a person's post from another shell waited 60s
        // behind a dial to somebody else.
        //
        // So the dial always runs in the background and reports `Dialed`/`ReachFailed`; `Dialed`
        // adopts the connection and delivers whatever that member is owed at once. Automatic work
        // (the tick, a post) dials at most once per `MEMBER_REDIAL_SECS`; a command the person
        // gave (`asked`) dials now whatever the spacing, and an explicit consent keeps its reply
        // until the dial's outcome is known (`pending_consents`).
        let now = self.now();
        let recent = self
            .member_dialed_at
            .get(&target)
            .is_some_and(|t| now.saturating_sub(*t) < MEMBER_REDIAL_SECS);
        if asked || !recent {
            self.member_dialed_at.insert(target, now);
            let tx = self.net_tx.clone();
            tokio::spawn(async move {
                match net.reach(target, &endpoints).await {
                    Ok(conn) => {
                        let _ = tx
                            .send(NetEvent::Dialed {
                                conn,
                                endpoints,
                                board: false,
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = tx
                            .send(NetEvent::ReachFailed {
                                peer: target,
                                why: e.to_string(),
                            })
                            .await;
                    }
                }
            });
        }
        None
    }

    /// Reach `peer` for a room's sync (ADR-025 D2, #246): one dial at a time per peer, off the
    /// actor, reporting `Dialed` (a new connection, which clears the port's backoff) or
    /// `ReachFailed` (which backs it off). Unlike [`Self::reach_member`] it keeps no spacing of its
    /// own: the port's backoff paces it.
    ///
    /// **Not an anchor.** An anchor has its own dial (`redial_anchors_if_due`, V210-57): paced by
    /// its own backoff, and announced as `AnchorConnected`, which records when it connected and
    /// publishes this node's records to it. A sync reach to an anchor would be a second dial
    /// that bypasses both, and its failure would advance the anchor's backoff as well as the
    /// port's. When the anchor path reconnects it, the new connection syncs like any other.
    fn reach_for_sync(&mut self, channel_id: &Digest32, peer: Digest32) {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        if self.is_kept_anchor(&peer) {
            return;
        }
        if net.manager().existing(&peer).is_some() || !self.sync_dials.insert(peer) {
            return;
        }
        let endpoints = net.board_endpoints(channel_id, &peer);
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            match net.reach(peer, &endpoints).await {
                Ok(conn) => {
                    let _ = tx
                        .send(NetEvent::Dialed {
                            conn,
                            endpoints,
                            board: false,
                        })
                        .await;
                }
                Err(e) => {
                    let _ = tx
                        .send(NetEvent::ReachFailed {
                            peer,
                            why: e.to_string(),
                        })
                        .await;
                }
            }
        });
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
            // Ours, and the peer has not yet been sent its hello — a delivery that failed
            // after the session was opened. Offer it again, or nothing sealed under it
            // can be opened there.
            return self
                .initiated
                .get(&(*channel_id, target))
                .filter(|i| !i.hello_delivered)
                .and_then(|i| i.initial.clone());
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
        drop(ring);
        self.sessions.insert((*channel_id, target), session);
        self.stamp_session((*channel_id, target));
        self.accepted_hello.remove(&(*channel_id, target));
        self.initiated.insert(
            (*channel_id, target),
            Initiated {
                initial: Some(initial.clone()),
                hello_delivered: false,
            },
        );
        Some(initial)
    }

    /// Take an inbound sealed control message: an ADR-006 SKDM, which makes that
    /// author's messages readable and backfills any already held as ciphertext.
    async fn take_inbound_skdm(
        &mut self,
        peer: Digest32,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) {
        use crate::node::pairwise_stream::{recv_pairwise, PairwiseFrame};
        let Ok(Some(first)) = recv_pairwise(&mut recv).await else {
            return;
        };
        let room = match &first {
            PairwiseFrame::Skdm { channel_id, .. }
            | PairwiseFrame::Open { channel_id, .. }
            | PairwiseFrame::Hello { channel_id, .. } => *channel_id,
        };
        // **Held, not dropped, while this node is still joining that room.** The join runs off the
        // actor now, so the responder's key — sent the moment it admits us — can arrive before the
        // room and the session to open it exist: the joiner's task reports back only after sealing
        // the room key, 0.3–1.5s of Argon2id after the exchange. Handled then, it found no session
        // and was silently discarded, and this node could never read the responder. While the join
        // ran on the actor the stream waited in the queue until the room existed; this puts that
        // ordering back. `JoinerDone` replays whatever was held.
        if self.joining.contains(&room) && !self.channels.contains_key(&room) {
            self.held_pairwise.push((room, peer, first, send, recv));
            return;
        }
        if matches!(first, PairwiseFrame::Hello { .. }) && test_lose_hello() {
            eprintln!("vox: {TEST_LOSE_HELLOS_ENV}: an inbound hello was lost, unread");
            let _ = send.reset(quinn::VarInt::from_u32(0));
            let _ = recv.stop(quinn::VarInt::from_u32(0));
            return;
        }
        self.handle_pairwise(peer, first, send, recv).await;
    }

    /// Act on a pairwise stream whose first frame has been read.
    async fn handle_pairwise(
        &mut self,
        peer: Digest32,
        first: crate::node::pairwise_stream::PairwiseFrame,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) {
        // **Taken, or said not to be.** A sender cannot learn from the transport whether its key
        // was taken: QUIC acknowledges the bytes before this node decides anything. So a stream
        // that carried a key is answered, one byte once the key is taken, and reset with a wire
        // code when it is not. A stream that carried no key (a bare hello, an `Open`) is finished.
        match self.take_pairwise(peer, first, &mut recv).await {
            Some(Ok(())) => {
                let _ = send
                    .write_all(&[crate::node::pairwise_stream::KEY_TAKEN])
                    .await;
                let _ = send.finish();
            }
            Some(Err(why)) => {
                let _ = send.reset(why.code());
                let _ = recv.stop(why.code());
            }
            None => {
                let _ = send.finish();
            }
        }
    }

    /// Act on a pairwise stream whose first frame has been read: `Some(Ok)` if it carried a key
    /// and the key was taken, `Some(Err(why))` if it carried one that was not, `None` if it carried
    /// none.
    async fn take_pairwise(
        &mut self,
        peer: Digest32,
        first: crate::node::pairwise_stream::PairwiseFrame,
        recv: &mut quinn::RecvStream,
    ) -> Option<Result<(), crate::node::pairwise_stream::KeyRefusal>> {
        use crate::node::pairwise_stream::KeyRefusal;
        use crate::node::pairwise_stream::{open_skdm, recv_pairwise, PairwiseFrame};
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
                return None;
            }
            PairwiseFrame::Hello {
                channel_id,
                initial,
            } => {
                if !self.accept_hello(channel_id, peer, &initial).await {
                    return Some(Err(KeyRefusal::HelloRefused));
                }
                match recv_pairwise(recv).await {
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
                        return None;
                    }
                    _ => {
                        // A session with nothing behind it is still progress: the peer
                        // may deliver over it later.
                        return None;
                    }
                }
            }
        };
        let now = self.now();
        let Some(session) = self.sessions.get_mut(&(channel_id, peer)) else {
            // No session with this peer for that channel: nothing can open it. Said, so the
            // sender sends it again once a join or key exchange establishes one.
            return Some(Err(KeyRefusal::NoSession));
        };
        let Ok(skdm) = open_skdm(session, &sealed, now) else {
            return Some(Err(KeyRefusal::CannotOpen));
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
        let Some(n) = backfilled else {
            return Some(Err(KeyRefusal::NotAccepted));
        };
        let _ = self.event_tx.send(NodeEvent::SenderKeyReceived {
            channel_id,
            peer,
            backfilled: n as u64,
        });
        Some(Ok(()))
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
        self.consent_keys =
            crate::node::pending_consent::PendingConsents::load(profile.store(), signer)?;
        Ok(())
    }

    /// Keep the prekey ring up **while the node runs** (V210-77), not only at unlock: rotate the
    /// signed prekey when its cadence is up, refill the one-time pool at its low-water mark,
    /// and drop consumed one-time prekeys whose retention is over. A node up for weeks otherwise
    /// ran out of one-time prekeys after 64 sessions and never rotated. Cheap when nothing is
    /// due; a join holding the ring is left alone, and the next tick does it.
    fn maintain_prekeys(&mut self) {
        let now = self.now();
        let (Some(profile), Some(ring)) = (self.profile.as_ref(), self.prekeys.as_ref()) else {
            return;
        };
        let Ok(signer) = profile.signer() else {
            return;
        };
        let Ok(mut ring) = ring.try_lock() else {
            return;
        };
        let Ok(done) = ring.maintain(signer, now) else {
            return;
        };
        if done.changed() {
            // A failed save is not fatal: the ring is saved with the next consume, and
            // maintained again at the next unlock.
            let _ = prekeys::save(profile.store(), signer, &ring);
        }
        crate::node::status::SyncBook::note_prekeys(
            &self.sync_book,
            ring.one_time_len(),
            ring.consumed_len(),
            ring.signed_prekey_id(),
            done.rotated,
            done.one_time_added,
            ring.previous_used(),
        );
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
        // The reopening holds room keys too: stopped, and nothing it opened is held (#208).
        if let Some(task) = self.reopen_task.take() {
            task.abort();
        }
        self.reopening.clear();
        // An aborted joiner never reports back, so nothing is being joined any more, and what was
        // held for the join goes with the network.
        self.joining.clear();
        self.held_pairwise.clear();
        // Keys still in flight stay owed, and are sent again after the next unlock (V210-88).
        self.keys_in_flight.clear();
        // And the watchers still running answer for what is no longer in flight.
        self.delivery_epoch = self.delivery_epoch.wrapping_add(1);
        self.history_in_flight.clear();
        // The unlock they wait on did happen; what it reopened is locked again with the rest.
        for reply in std::mem::take(&mut self.unlock_waiters) {
            let _ = reply.send(Outcome::Done);
        }
        // Awaited, not polled: `try_join_next` collects only tasks that have already finished, and
        // an aborted one drops its handles — the signer, the ring, the store — at its next await.
        while self.join_tasks.join_next().await.is_some() {}
        // Drop the prekey ring: its secrets zeroize on drop, so a locked node holds
        // no key-agreement material (ADR-015 lock/zeroize).
        self.prekeys = None;
        // The keyring is not secret material, but it is sealed under the identity
        // and says who this operator talks to. A locked node holds neither, and it
        // is re-opened on the next unlock (ADR-020 §3).
        self.trust = crate::node::trust::Keyring::new();
        // The sender keys held for consents not yet delivered are room secrets: dropped, and
        // zeroized as they go (V210-76). They are reloaded, sealed, at the next unlock.
        self.consent_keys = crate::node::pending_consent::PendingConsents::default();
        // Pairwise sessions hold ratchet key material: drop them with everything else
        // (their secrets zeroize on drop).
        self.sessions.clear();
        self.initiated.clear();
        self.accepted_hello.clear();
        self.reopen.clear();
        self.session_serial.clear();
        // And take the network down: a locked node has no identity to present, so it
        // must not keep serving or holding connections (M14.7d).
        self.stop_network().await;
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
            Ok(ch) => self.finish_create_channel(ch).await,
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    /// Everything after a room exists: hold it, give it anchors, publish it, say so.
    async fn finish_create_channel(&mut self, ch: ChannelState) -> Outcome {
        let id = ch.channel_id();
        self.remember_or_say(&ch);
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

    /// Begin creating a room: the genesis here, the Argon2id seal on a blocking thread, and the
    /// reply carried to `NetEvent::ChannelSealed`. Any failure before the seal answers at once.
    /// Check the identity passphrase on a blocking thread and answer `reply` from there.
    fn begin_verify_passphrase(&self, passphrase: Secret, reply: oneshot::Sender<Outcome>) {
        let Some(profile) = self.profile.as_ref() else {
            let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
            return;
        };
        let verifier = profile.passphrase_verifier();
        let slots = Arc::clone(&self.verify_slots);
        // Waiting for a slot happens here, off the actor; the check itself on a blocking
        // thread, holding the slot until it is done.
        tokio::spawn(async move {
            let Ok(slot) = slots.acquire_owned().await else {
                let _ = reply.send(Outcome::Failed(Fault::ShuttingDown));
                return;
            };
            let outcome = tokio::task::spawn_blocking(move || {
                let _slot = slot;
                match verifier.verify(&passphrase) {
                    Ok(()) => Outcome::Done,
                    Err(_) => Outcome::Failed(Fault::WrongPassphrase),
                }
            })
            .await
            .unwrap_or(Outcome::Failed(Fault::Internal));
            let _ = reply.send(outcome);
        });
    }

    async fn begin_create_channel(
        &mut self,
        local_name: String,
        passphrase: Secret,
        reply: oneshot::Sender<Outcome>,
    ) {
        let now = self.now();
        let Some(profile) = self.profile.as_ref() else {
            let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
            return;
        };
        let (genesis, sek) = match ChannelState::create_genesis(
            profile,
            &local_name,
            crate::governance::capability::CapabilitySet::new(),
            now,
        ) {
            Ok(g) => g,
            Err(e) => {
                let _ = reply.send(Outcome::Failed(fault_of(&e)));
                return;
            }
        };
        let signer = match profile.signer_arc() {
            Ok(s) => s,
            Err(e) => {
                let _ = reply.send(Outcome::Failed(fault_of(&e)));
                return;
            }
        };
        let argon2 = self.argon2;
        let tx = self.net_tx.clone();
        let channel_id = genesis.channel_id();
        let seal_passphrase = passphrase.clone();
        // Tracked, so a lock aborts it: it holds the signer (V210-76). The seal itself runs on a
        // blocking thread, which cannot be interrupted; its result is dropped with the task.
        let reply = AnsweredIfAborted(Some(reply));
        self.reap_join_tasks();
        self.join_tasks.spawn(async move {
            let sealed = tokio::task::spawn_blocking(move || {
                let factor = crate::atrest::idfactor::SignatureIdentityFactor::new(&*signer);
                sek.seal(&factor, &channel_id, &seal_passphrase, argon2)
                    .map(|wrap| (sek, wrap))
            })
            .await
            .unwrap_or(Err(Error::Argon2Failed));
            let Some(reply) = reply.into_reply() else {
                return;
            };
            let _ = tx
                .send(NetEvent::ChannelSealed {
                    reply,
                    local_name,
                    passphrase,
                    genesis: Box::new(genesis),
                    now,
                    sealed,
                })
                .await;
        });
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
        if let Err(e) = channel.add_service(profile.store(), profile, &tag, endpoint, true) {
            // Drop the room rather than keep a half-made one. Nothing outside this
            // function has seen it: it is not in `self.channels` and has not been
            // published, so forgetting it here is the whole of the rollback.
            return Outcome::Failed(fault_of(&e));
        }
        self.remember_or_say(&channel);
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

    /// Add `ch` to the rooms this node reopens by itself at unlock (#208), with the keys that
    /// reopen it, sealed under the identity ([`crate::node::open_rooms`]).
    fn remember_open(&self, ch: &ChannelState) -> crate::error::Result<()> {
        let profile = self
            .profile
            .as_ref()
            .ok_or(crate::error::Error::AtRestLocked)?;
        let signer = profile.signer()?;
        let mut set = OpenRooms::load(profile.store(), signer)?;
        if set.remember(ch.channel_id(), ch.sek_bytes()?, ch.join_passphrase()?)? {
            set.save(profile.store(), signer)?;
        }
        Ok(())
    }

    /// [`Self::remember_open`], and if it cannot, **say so and keep going**.
    ///
    /// Every caller has already made or opened the room — it is in the store, and a created
    /// room's SEK wrap is written — so failing the command here told its caller that a room did
    /// not exist which did. What failed is narrower: the room will not reopen by itself after a
    /// restart. That is what is reported ([`NodeEvent::RoomNotRemembered`]); the room is held.
    fn remember_or_say(&self, ch: &ChannelState) {
        if let Err(e) = self.remember_open(ch) {
            let _ = self.event_tx.send(NodeEvent::RoomNotRemembered {
                channel_id: ch.channel_id(),
                why: e.to_string(),
            });
        }
    }

    /// Take `channel_id` out of the rooms this node reopens by itself.
    fn forget_open(&self, channel_id: &Digest32) -> crate::error::Result<()> {
        let profile = self
            .profile
            .as_ref()
            .ok_or(crate::error::Error::AtRestLocked)?;
        let signer = profile.signer()?;
        let mut set = OpenRooms::load(profile.store(), signer)?;
        if set.forget(channel_id) {
            set.save(profile.store(), signer)?;
        }
        Ok(())
    }

    /// Reopen every room this node held open, as it was before it stopped (#208).
    ///
    /// A `vox daemon` unlocks with the identity passphrase alone, so without this it came back
    /// from every restart holding no room. Each remembered room opens from the SEK kept sealed
    /// under the identity, and then goes through exactly what [`Self::open_channel`] does after
    /// an open.
    ///
    /// A room that no longer exists in the store is forgotten. A room that exists but will not
    /// open stays remembered, so the next unlock tries it again, and stays **closed**, which
    /// the daemon reports ("N room(s) open, M still closed") — it is not a reason to refuse the
    /// identity and every other room with it.
    async fn reopen_remembered(&mut self) {
        let now = self.now();
        // Only the sealed set is read here — one small decrypt. Opening each room reads and
        // re-verifies its whole log, and that runs **off the actor**, one room at a time, each
        // held as soon as it is open: with many rooms, a reopen on the actor answered nobody until
        // the last one was open.
        let (store, rooms) = {
            let Some(profile) = self.profile.as_ref() else {
                return;
            };
            let Ok(signer) = profile.signer() else {
                return;
            };
            let Ok(set) = OpenRooms::load(profile.store(), signer) else {
                return;
            };
            let rooms: Vec<_> = set
                .rooms()
                .filter(|(id, _)| !self.channels.contains_key(*id))
                .map(|(id, keys)| (*id, keys.sek.clone(), keys.passphrase.clone()))
                .collect();
            (profile.store_handle(), rooms)
        };
        if rooms.is_empty() {
            return;
        }
        self.reopening.extend(rooms.iter().map(|(id, _, _)| *id));
        let tx = self.net_tx.clone();
        let task = tokio::spawn(async move {
            for (id, sek, passphrase) in rooms {
                let store = Arc::clone(&store);
                let opened = tokio::task::spawn_blocking(move || {
                    match store.get_sek_wrap(&id) {
                        Ok(Some(_)) => {}
                        Ok(None) => return Some(Err(())),
                        // Unreadable now: left in the set for the next unlock, and closed.
                        Err(_) => return None,
                    }
                    let sek = crate::atrest::sek::Sek::from_bytes(sek);
                    ChannelState::open_with_sek(&store, &id, sek, &passphrase, now)
                        .ok()
                        .map(Ok)
                })
                .await;
                let event = match opened {
                    Ok(Some(Ok(channel))) => NetEvent::Reopened {
                        channel_id: id,
                        channel: Box::new(channel),
                    },
                    Ok(Some(Err(()))) => NetEvent::ReopenGone { channel_id: id },
                    // A room that exists but will not open stays remembered and closed.
                    Ok(None) | Err(_) => continue,
                };
                if tx.send(event).await.is_err() {
                    return;
                }
            }
            let _ = tx.send(NetEvent::ReopenFinished).await;
        });
        self.reopen_task = Some(task.abort_handle());
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
                crate::node::status::SyncBook::note_set_aside(
                    &self.sync_book,
                    *channel_id,
                    ch.set_aside(),
                );
                self.remember_or_say(&ch);
                self.channels
                    .insert(*channel_id, Arc::new(tokio::sync::Mutex::new(ch)));
                self.mark_decisions_on_open(channel_id).await;
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
        // Closed on purpose, so not reopened at the next unlock (#208). Forgotten first: a room
        // that stayed in the set would come back by itself, which is not what closing it meant.
        // A room still reopening is closed too: it leaves `reopening`, so its state is dropped
        // when it arrives rather than held.
        let reopening = self.reopening.remove(channel_id);
        if self.channels.contains_key(channel_id) || reopening {
            if let Err(e) = self.forget_open(channel_id) {
                return Outcome::Failed(fault_of(&e));
            }
        }
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
        persist: bool,
    ) -> Outcome {
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        let outcome = {
            let mut channel = shared.lock().await;
            channel.add_service(profile.store(), profile, service_tag, local, persist)
        };
        match outcome {
            Ok(_) => {
                self.refresh_reachers().await;
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    /// Stop offering a service, and **cut every session carried on it** (PRD-001 R22).
    ///
    /// The cut is the live offer changing: each serving task watches it and resets its
    /// stream the moment its tag leaves, exactly as it does when its dialer leaves the
    /// reacher set. Removing the service used to change only the stored configuration, so
    /// a new dial was refused while an `ssh` session opened a minute earlier carried on
    /// for as long as it liked.
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
            Ok(true) => {
                self.refresh_reachers().await;
                Outcome::Done
            }
            Ok(false) => Outcome::Failed(Fault::NotOffered),
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
            return Outcome::Failed(Fault::NotAServiceRoom);
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
        // A port that cannot be bound is the person's to fix, and it said `Unreachable` — which
        // sent them to check a host that was never contacted (PRD-001 R36).
        let listener = match tokio::net::TcpListener::bind(bind).await {
            Ok(l) => l,
            Err(_) => return Outcome::Failed(Fault::AddressInUse),
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

    /// Start a forward: the checks that are this machine's business here, and the first dial —
    /// which runs the whole reachability ladder — on a task of its own (#215). The command is
    /// answered from [`NetEvent::ForwardDialed`], by [`Self::finish_forward`].
    fn begin_forward(
        &mut self,
        channel_id: Digest32,
        host: Digest32,
        service_tag: String,
        local: std::net::SocketAddr,
        reply: oneshot::Sender<Outcome>,
    ) {
        let refuse = |reply: oneshot::Sender<Outcome>, fault: Fault| {
            let _ = reply.send(Outcome::Failed(fault));
        };
        if !self.channels.contains_key(&channel_id) {
            return refuse(reply, Fault::ChannelNotOpen);
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
            return refuse(reply, Fault::NotLoopback);
        }
        // The member's advertised endpoints, from this node's board — the same hints
        // any dial uses; the ladder does the rest.
        // **The local port before the network.** A forward bound its port only after the dial,
        // so a port already in use was never reported: the dial failed first on a host that
        // was not up yet, and `vox forward` sat "waiting for a path" for five minutes about a
        // problem on this machine (PRD-001 R36). Probed and released; `Forward::bind` still
        // binds for real, and still reports if the port was taken in between.
        if local.port() != 0 && std::net::TcpListener::bind(local).is_err() {
            return refuse(reply, Fault::AddressInUse);
        }
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return refuse(reply, Fault::NotNetworked);
        };
        let endpoints = net.board_endpoints(&channel_id, &host);
        // **The ladder's own words, not `Fault::Unreachable`.** `fault_of` collapses
        // `LadderExhausted` to one token, so a forward that could not be carried told the person to
        // check a permission they cannot hold. The common case here is not a refusal at all: a
        // one-shot verb dials before its anchor connection exists, so there is no helper to carry a
        // circuit and no board hint to dial directly — `no direct candidates, and no peer is
        // connected to carry a circuit`. That sentence is the whole diagnosis and it was being
        // thrown away.
        //
        // Off the actor: the connection goes back as `NetEvent::Dialed`, which adopts it and tries a
        // better path behind a relayed one, exactly as the actor's own dial did; then
        // `ForwardDialed` binds the forward. One sender, so the two arrive in that order.
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let result = match net.reach(host, &endpoints).await {
                Ok(conn) => {
                    let _ = tx
                        .send(NetEvent::Dialed {
                            conn,
                            endpoints,
                            board: false,
                        })
                        .await;
                    Ok(())
                }
                Err(e) => Err(e),
            };
            let _ = tx
                .send(NetEvent::ForwardDialed {
                    channel_id,
                    host,
                    service_tag,
                    local,
                    result: Box::new(result),
                    reply,
                })
                .await;
        });
    }

    /// Bind a forward whose first dial has landed, or say why it could not, and answer the
    /// command (#215).
    ///
    /// The forward does not keep the dial's connection: it reaches the host afresh for every
    /// connection (PRD-001 R24), and `reach` hands back that same connection for as long as it
    /// lives. The dial is kept for what it tells the caller — a forward to a host that cannot be
    /// reached at all fails, with the ladder's words.
    async fn finish_forward(
        &mut self,
        channel_id: &Digest32,
        host: &Digest32,
        service_tag: &str,
        local: std::net::SocketAddr,
        result: crate::error::Result<()>,
    ) -> Outcome {
        if let Err(e) = result {
            let _ = self.event_tx.send(NodeEvent::PeerUnreachable {
                peer: *host,
                why: e.to_string(),
            });
            return Outcome::Failed(fault_of(&e));
        }
        // The room may have closed while the dial ran.
        if !self.channels.contains_key(channel_id) {
            return Outcome::Failed(Fault::ChannelNotOpen);
        }
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return Outcome::Failed(Fault::NotNetworked);
        };
        let dialer = Arc::new(NodeDialer {
            net,
            channel_id: *channel_id,
        });
        let events = self.event_tx.clone();
        match crate::node::tunnel::Forward::bind(
            dialer,
            *host,
            *channel_id,
            service_tag.to_owned(),
            local,
            move |reason: String| {
                let _ = events.send(NodeEvent::ProxyRefused { reason });
            },
        )
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
                Outcome::Bound(bound)
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
            if shared.lock().await.services().is_empty() {
                continue;
            }
            let (Some(reachers), Some(offered)) = (self.reachers.get(cid), self.offered.get(cid))
            else {
                continue;
            };
            out.insert(
                *cid,
                crate::node::tunnel::ChannelServices {
                    offered: Arc::clone(offered),
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
            let offer = self
                .offered
                .entry(*cid)
                .or_insert_with(crate::node::tunnel::empty_offered);
            crate::node::tunnel::publish_offered(offer, ch.services().clone());
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
        self.offered.retain(|cid, slot| {
            let held = self.channels.contains_key(cid);
            if !held {
                crate::node::tunnel::publish_offered(slot, std::collections::BTreeMap::new());
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
        let rotated = ch.should_rotate_sender(now) && ch.rotate_sender(profile, now).is_ok();
        self.fresh_details
            .insert(*channel_id, (summary_of(&ch), detail_of(&ch)));
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
            let _ = self.deliver_rekeys_for(&channel_id, false).await;
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
            connected_peers: Vec::new(),
            relaying: 0,
        });
    }

    async fn publish(&mut self) {
        let (view, read) = self.view_of().await;
        self.fresh_details
            .retain(|id, _| self.channels.contains_key(id) && !read.contains(id));
        self.view_tx.send_replace(view);
    }

    /// The node's view, built **without waiting long on any room a session holds.**
    ///
    /// `publish()` runs this after every command and every event, and it took each room's lock in
    /// turn — the lock a sync session holds for its whole run, across its network waits. So while
    /// any session was waiting on a peer, nearly every event left the actor parked here. When both
    /// ends pushed at once, each actor parked on its own room while its session waited for the other
    /// actor to answer, until the 20s frame timeout (the independent verdict on #41 traced it: an
    /// actor silent 19.9s, both sessions ending `sync failed: transport` at exactly the timeout). A
    /// room that is held now keeps its entry from the view already published — at most one event old
    /// — and is refreshed on the next publish after the session hands it back.
    ///
    /// **Briefly, not never.** Since sync sessions lock a room per protocol step (3f95b57), a holder
    /// keeps it for milliseconds, not across a network wait, so the view waits up to
    /// `VIEW_LOCK_PATIENCE`, in total across all rooms, before falling back. Falling back at once
    /// served a stale view whenever a session happened to be mid-step, and a person's own post could
    /// be missing from what they read straight after posting: `vox room post` then read back a view
    /// without its entry, reported a successful post as failed, and let two racing posts under one
    /// op both succeed (PR #14's work_op proof, on macOS and Linux).
    ///
    /// Returns the view and the rooms read under their lock.
    async fn view_of(&self) -> (NodeView, std::collections::BTreeSet<Digest32>) {
        let deadline = tokio::time::Instant::now() + VIEW_LOCK_PATIENCE;
        let prev = self.view_tx.borrow().clone();
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
                let earlier = prev.anchoring.iter().find(|p| p.channel_id == a.channel_id);
                match by(deadline, state).await {
                    Some(st) => {
                        a.entries = Some(st.entries() as u64);
                        a.equivocations = st.equivocations();
                    }
                    None => {
                        a.entries = earlier.and_then(|p| p.entries);
                        a.equivocations =
                            earlier.map(|p| p.equivocations.clone()).unwrap_or_default();
                    }
                }
            }
        }
        // Each open room's lock is taken once, for both its summary and its detail.
        let mut read = std::collections::BTreeSet::new();
        let mut summaries = BTreeMap::new();
        let mut open_channels = Vec::with_capacity(self.channels.len());
        let mut mlock_active = true;
        for (id, shared) in &self.channels {
            let Some(ch) = by(deadline, shared).await else {
                // The summary and detail taken under this room's lock by this node's own latest write,
                // if any, are newer than the ones last published (see `fresh_details`): a person reads
                // their own post (read-your-writes), and the room's entry count agrees with it.
                match self.fresh_details.get(id) {
                    Some((summary, detail)) => {
                        summaries.insert(*id, summary.clone());
                        open_channels.push(detail.clone());
                    }
                    None => {
                        if let Some(d) = prev.open_channels.iter().find(|d| d.channel_id == *id) {
                            open_channels.push(d.clone());
                        }
                    }
                }
                mlock_active &= prev.mlock_active;
                continue;
            };
            read.insert(*id);
            summaries.insert(*id, summary_of(&ch));
            mlock_active &= ch.mlock_active();
            open_channels.push(detail_of(&ch));
        }
        let mut channels = Vec::with_capacity(known.len());
        for id in &known {
            channels.push(match self.channels.get(id) {
                Some(_) => match summaries.remove(id) {
                    Some(summary) => summary,
                    None => prev
                        .channels
                        .iter()
                        .find(|c| c.channel_id == *id)
                        .cloned()
                        .unwrap_or(ChannelSummary {
                            channel_id: *id,
                            local_name: None,
                            open: true,
                            entries: 0,
                        }),
                },
                None => ChannelSummary {
                    channel_id: *id,
                    local_name: None,
                    open: false,
                    entries: 0,
                },
            });
        }
        let (relayed_peers, relaying) = self.path_view();
        let connected_peers = self.connected_peers();
        let view = NodeView {
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
            connected: connected_peers.len(),
            connected_peers,
        };
        (view, read)
    }

    /// Whether the connections and circuits the published view shows are no longer the ones
    /// the connection manager holds.
    fn paths_moved(&self) -> bool {
        let (relayed_peers, relaying) = self.path_view();
        let connected_peers = self.connected_peers();
        let shown = self.view_tx.borrow();
        shown.relayed_peers != relayed_peers
            || shown.relaying != relaying
            || shown.connected_peers != connected_peers
    }

    /// The peers the connection manager holds a connection to, in fingerprint order.
    fn connected_peers(&self) -> Vec<Digest32> {
        let mut peers = self
            .net
            .as_ref()
            .map_or_else(Vec::new, |net| net.manager().peers());
        peers.sort_unstable();
        peers.dedup();
        peers
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
        Error::LocalBind { .. } => Fault::AddressInUse,
        Error::Profile("no identity in this profile") => Fault::NoIdentity,
        Error::Profile("identity already exists in this profile") => Fault::IdentityExists,
        Error::Profile("locked") => Fault::Locked,
        Error::Profile("no such channel in this profile") => Fault::UnknownChannel,
        Error::AtRestUnlockFailed => Fault::WrongPassphrase,
        Error::AtRestLocked => Fault::Locked,
        // Before the general size arm: a full keyring is not an input that was too long.
        Error::SizeLimitExceeded("trusted identities") => Fault::KeyringFull,
        Error::SizeLimitExceeded(_) => Fault::TooLong,
        Error::MalformedLink(_) | Error::MalformedAnchor(_) => Fault::BadLink,
        Error::Unreachable(_) => Fault::Unreachable,
        Error::JoinRefused(_) | Error::RendezvousRejected(_) => Fault::Refused,
        Error::JoinSolveTooSlow { .. } => Fault::SolveTooSlow,
        Error::Path {
            op: crate::node::profile::VAULT_WRITE,
            ..
        } => Fault::IdentityFileUnwritable,
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
        // A sync that did not complete, or a peer that refused: the peer did not serve this, which
        // is reachability, not an internal fault (#202).
        Error::SyncFailed(_)
        | Error::SyncRefused(_)
        | Error::SyncRejected(_)
        | Error::PeerRefused(_) => Fault::Unreachable,
        _ => Fault::Internal,
    }
}
