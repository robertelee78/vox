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
use crate::hash::Digest32;
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
use crate::node::status::PublishCause;
use crate::pairwise::init_message::InitialMessage;
use crate::transport::quic::VoxConnection;

/// A pairwise session this node opened (ADR-004 O2, O3).
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

/// **Which of two competing sessions for one pair both ends keep** (ADR-004 O2): the
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

/// At most one read record per room in this many milliseconds (ADR-028 RR-2): what is read in
/// between waits, and the next record names all of it.
const READ_RECORD_EVERY_MS: u64 = 5_000;

/// How long a room this node holds ended keeps syncing to pass the end on, when some member
/// cannot be reached (V030-08), before this node deletes it (the decider, 2026-10-03). Each member
/// synced with after the end counts as passed on at once; a member still unreachable past this
/// learns it from the others, or an anchor.
const WIND_DOWN: Duration = Duration::from_secs(60);

/// An ended room passing its end on, before this node deletes it (V030-08).
struct Winding {
    /// The room's generation once it held the end: a member's port credited with it has been
    /// passed the end.
    gen: u64,
    /// When this node started passing it on.
    since: std::time::Instant,
}

/// How often automatic work (a rotation's rekeys, a trusted member's consent) may start a background
/// dial to one member it cannot currently reach. See `reach_member`.
const MEMBER_REDIAL_MS: u64 = 30_000;

/// How often a node holding a room with a member it is not connected to says where it listens on
/// this computer and the local network (`node::nearby`).
const NEARBY_EVERY_MS: u64 = 30_000;
/// How soon after it holds a room it did not — what a node that just started does — a node says
/// so, if a member of it is still not connected by then.
const NEARBY_FIRST_MS: u64 = 3_000;
/// How soon a member heard on `node::nearby` may be dialled for it again.
const NEARBY_REDIAL_MS: u64 = 5_000;

/// How long relayed connections' closes get to leave through their circuits before the circuits'
/// carrier connections are closed too (see `stop_network`). The frame only has to be handed to the
/// circuit's stream, which happens on the endpoint driver's next turn.
const RELAYED_CLOSE_LEAD: Duration = Duration::from_millis(50);

/// How long stopping the network waits for its connections' closes to leave (see `stop_network`).
/// They leave on the endpoint driver's next turns; this is a ceiling for one that cannot. A term
/// of the stop's budget (see `STOP_ACK_BOUND`).
const CLOSE_FLUSH: Duration = Duration::from_millis(600);

/// How long stopping the network waits for its peers to confirm they heard it is stopping (see
/// `ConnectionManager::say_goodbye`), in each of its two rounds (relayed connections, then the
/// rest). A live peer confirms within a round trip; this is spent only on one that does not
/// answer, and is a ceiling, not a wait. A term, twice, of the stop's budget (see
/// `STOP_ACK_BOUND`).
const GOODBYE_PATIENCE: Duration = Duration::from_millis(400);

/// How long a stopping node waits for tunnels that finished their stream to have their last bytes
/// acknowledged before it closes its connections (see `stop_network`). The bound still covers a
/// reply of several MiB draining over a slow path.
///
/// **The budget for the whole stop.** This is the first of the stop's waits, and all of them
/// together must end inside `vox daemon`'s 5 s stop patience. The daemon gives its node that long
/// and then leaves, dropping the node's tasks, so a stop still under way is cut short, and the
/// peers whose closes were cut learn of the stop only by inference (V210-93). Every wait spent to
/// its ceiling (a peer that vanished holding a finished tunnel's unacknowledged bytes, and peers
/// that answer neither the goodbye nor the close):
///
/// | term | bound |
/// |---|---|
/// | finished tunnels' last bytes acknowledged (this bound) | 3 s |
/// | the goodbye, relayed connections then the rest (2 × [`GOODBYE_PATIENCE`]) | 0.8 s |
/// | relayed closes' lead over their carriers ([`RELAYED_CLOSE_LEAD`]) | 0.05 s |
/// | the closes leaving ([`CLOSE_FLUSH`]) | 0.6 s |
/// | **sum** ([`STOP_WORST_CASE`]) | **4.45 s**, against 5 s |
///
/// The last term is the one a patience too short cuts: by then the goodbye is said and the closes
/// are queued, but a stop whose closes have not left has not finished. With the goodbye at 0.5 s a
/// round and the flush at 1 s, the sum was 5.05 s, and the patience ran out inside that flush. The
/// half second left over is for the daemon itself under load. A bound raised here must come out of
/// another term.
const STOP_ACK_BOUND: Duration = Duration::from_secs(3);

/// **The longest a node's network can take to stop** (`stop_network`): the sum of the whole stop's
/// budget, set out term by term in `STOP_ACK_BOUND`'s doc (4.45 s). Held at 4.5 s or less here,
/// and `vox daemon` checks at compile time that its 5 s `SHUTDOWN_PATIENCE` leaves at least half a
/// second beyond it.
pub const STOP_WORST_CASE: Duration = Duration::from_millis(
    (STOP_ACK_BOUND.as_millis()
        + 2 * GOODBYE_PATIENCE.as_millis()
        + RELAYED_CLOSE_LEAD.as_millis()
        + CLOSE_FLUSH.as_millis()) as u64,
);
const _: () = assert!(
    STOP_WORST_CASE.as_millis() <= 4_500,
    "a stop's budget is at most 4.5 s"
);

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
/// How long [`NodeHandle::open_detail`] waits for an open room's detail to reach the view.
const OPEN_DETAIL_PATIENCE: Duration = Duration::from_secs(2);

/// A room's summary for the view, from its state.
fn summary_of(ch: &ChannelState) -> ChannelSummary {
    ChannelSummary {
        channel_id: ch.channel_id(),
        name: ch.name().map(str::to_owned),
        open: true,
        entries: ch.entry_count() as u64,
        over: over_of(ch),
    }
}

/// Whether a room is over for this node, in plain words (V030-08). Read on the wall clock: it is
/// what a person is shown, and the idle end runs on the room's own entries' clock either way.
fn over_of(ch: &ChannelState) -> Option<String> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    if let Some(end) = ch.ended(now_ms) {
        return Some(format!("ended: {end}"));
    }
    ch.has_left(&ch.me()).then(|| "left".to_owned())
}

/// A room's detail for the view, from its state. `prev` is the room's detail last published: its
/// timeline is shared rather than rebuilt when the room's timeline has not changed since
/// (V210-71), since most publishes are about something else, and is **extended** by the rows
/// added since when it has (V210-120). A room's timeline only grows at its end, so the published
/// one is a prefix of it: rebuilding it whole made every message cost the room's whole history.
fn detail_of(ch: &ChannelState, prev: Option<&ChannelDetail>) -> ChannelDetail {
    let (frozen, refused_below_checkpoint) = ch.fork_watch();
    // A room with a message not received yet (V030-10) is shown with it in place, rebuilt each
    // time: filling one in changes a row inside the timeline, so the published one is no longer
    // a prefix of it. Only a timeline with none on either side may be shared or extended.
    let owed = ch.shows_owed();
    let shown;
    let rows: &[Rendered] = if owed {
        shown = ch.shown_timeline();
        &shown
    } else {
        ch.timeline()
    };
    let prefix = |p: &&ChannelDetail| {
        let n = p.timeline.len();
        !owed
            && !p.timeline.iter().any(|r| r.owed)
            && p.channel_id == ch.channel_id()
            && n <= rows.len()
            && p.timeline.first().map(|r| r.entry_hash) == rows.first().map(|r| r.entry_hash)
            && p.timeline.last().map(|r| r.entry_hash)
                == n.checked_sub(1).map(|i| rows[i].entry_hash)
    };
    // The structured-post index grows with the timeline, from the same rows (V210-120).
    let (timeline, structured) = match prev.filter(prefix) {
        Some(p) if p.timeline.len() == rows.len() => (p.timeline.clone(), p.structured.clone()),
        Some(p) => {
            let from = p.timeline.len();
            (
                p.timeline.appended(rows[from..].iter().map(row_of)),
                p.structured
                    .appended(from, rows[from..].iter().map(|r| &r.text)),
            )
        }
        None => (
            rows.iter().map(row_of).collect(),
            crate::node::api::StructuredIndex::default().appended(0, rows.iter().map(|r| &r.text)),
        ),
    };
    // Who trusts each member (ADR-028 K-7), once: this identity's own entry is `consenting`.
    let trusted_by = ch.trusted_by();
    let consenting = trusted_by.get(&ch.me()).cloned().unwrap_or_default();
    ChannelDetail {
        channel_id: ch.channel_id(),
        name: ch.name().map(str::to_owned),
        notices: ch.notices(),
        epoch: ch.epoch(),
        members: ch.members(),
        timeline,
        order: ch.order_keys(),
        structured,
        services: ch
            .services()
            .iter()
            .map(|(tag, addr)| (tag.clone(), *addr))
            .collect(),
        shares: ch.shares(),
        synced: ch.is_settled(),
        equivocations: ch.equivocations(),
        creator: ch.genesis().creator_pubkey().fingerprint(),
        consented: ch.consented().into_iter().collect(),
        admins: ch.admins(),
        consenting: consenting.into_iter().collect(),
        trusted_by: trusted_by
            .into_iter()
            .map(|(member, by)| (member, by.into_iter().collect()))
            .collect(),
        retention: ch.effective_retention(),
        retention_above_room: ch.retention_above_room(),
        key_generations: ch.key_generations(),
        received_key_generations: ch.received_key_generations(),
        frozen,
        refused_below_checkpoint,
        read_by: ch.read_by_own(),
        held: ch.held_own(),
        unread: ch.unread(),
        drive_from: ch.drive_from(),
        session_files: ch.session_files(),
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

/// How long a verb that hands out a room's address waits when the address would name **no route of
/// this node's own** — its addresses not yet discovered — for that discovery, or for an anchor to
/// take the room (V210-96). The same wait a joiner gives a board (`Node::BOARD_PATIENCE`). Past it
/// the address is withheld, and why is said (`NodeEvent::AddressWithheld`). Also how long an anchor
/// the address names has to take the room before this node says it has not.
const ADDRESS_PATIENCE: Duration = Node::BOARD_PATIENCE;

/// How long `vox room leave` waits for another member to take this node's departure (V210-164).
/// Past it the person is told, and the node keeps the room until one does: removed first, the
/// room would take the only copy of the departure with it, and nobody would ever learn of it.
const LEAVE_PATIENCE: Duration = Duration::from_secs(30);

/// How long a join waits before asking its boards again for a room none of them holds yet
/// (V210-143): a host publishes its room within a second of starting, and retries a failed dial to
/// its anchor after one.
const ROOM_RETRY: Duration = Duration::from_secs(1);

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
/// How often the node re-reads its retention file (ADR-023 decision 2: the sweep runs at
/// least every minute; the file is read on the same cadence).
const RETENTION_REREAD_MS: u64 = 60_000;

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
///
/// **Not first come, first served** (V210-92): a stranger could take every slot with joins it
/// never finished and keep everyone else out for as long as a member waits on a proof of work.
/// Past the cap the heaviest source gives up its newest slot; see [`crate::node::joinslots`].
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
        NodeCommand::Agree { .. } => "asking members to agree on a claim",
        NodeCommand::Serve { .. } => "publishing a service",
        NodeCommand::Up { .. } => "bringing the proxy up",
        NodeCommand::Forward { .. } => "opening a forward",
        NodeCommand::Unlock { .. } => "unlocking the identity",
        NodeCommand::LeaveRoom { .. } => "leaving a room",
        NodeCommand::EndRoom { .. } => "ending a room",
        _ => "a client command",
    }
}

/// A short name for what inbound work was, for the stall report.
fn net_event_name(e: &NetEvent) -> &'static str {
    match e {
        NetEvent::JoinRequest { .. } => "answering somebody's join",
        NetEvent::SyncRequest { .. } => "answering a sync",
        NetEvent::Pairwise(..) => "taking a pairwise stream",
        NetEvent::HelloUndelivered { .. } => "owing a hello that could not be written",
        NetEvent::ReopenUndelivered { .. } => "owing a reopen that could not be written",
        NetEvent::Stream { .. } => "serving a stream",
        NetEvent::Connected { .. } => "filing a new connection",
        NetEvent::BetterPath { .. } => "adopting a connection",
        NetEvent::ReachFailed { .. } => "filing a failed dial",
        NetEvent::UpgradeFailed { .. } => "filing a path upgrade that failed",
        NetEvent::AnchorConnected { .. } => "publishing every room to an anchor that answered",
        NetEvent::AddressesDiscovered => "publishing every room at a new address",
        NetEvent::NetworkChanged(_) => "acting on a change of the machine's network",
        NetEvent::Stranded(_) => "dialling again peers a network change stranded",
        NetEvent::SyncDone { .. } => "filing a sync that finished",
        NetEvent::RoomStored { .. } => "evaluating a room whose log grew",
        NetEvent::SlotFreed => "starting a queued sync",
        NetEvent::BackoffExpired { .. } => "retrying a sync whose backoff is due",
        NetEvent::SkdmRefused { .. } => "re-owing a key the recipient did not take",
        NetEvent::PublishDone { .. } => "filing what a board said to a publish",
        NetEvent::RepublishTo { .. } => "publishing a refused record again",
        NetEvent::StaleGraceOver { .. } => "naming a refusal no republish cured",
        NetEvent::PublishRetry { .. } => "retrying a publish round that failed",
        NetEvent::AddressWaitOver { .. } => "withholding an address no board holds the room for",
        NetEvent::AnchorNoteDue { .. } => "saying which anchors never took a room",
        NetEvent::SkdmTaken { .. } => "noting a key the recipient took",
        NetEvent::JoinAnswered { .. } => "filing a join that finished",
        NetEvent::BoardGrew { .. } => "passing on a record that landed on our board",
        NetEvent::LeaveWaitOver { .. } => "answering a leave nobody took",
        NetEvent::BoardWithdrew => "showing a board a withdraw took records off",
        NetEvent::ChannelSealed { .. } => "finishing a room whose key was sealed",
        NetEvent::ChannelUnsealed { .. } => "holding a room whose key was unwrapped",
        NetEvent::Dialed { .. } => "adopting a connection a join dialled",
        NetEvent::JoinerDone { .. } => "finishing a join",
        NetEvent::ForwardDialed { .. } => "binding a forward whose dial landed",
        NetEvent::Heard { .. } => "dialling a member heard nearby",
        NetEvent::AddressReached { .. } => "keeping a room address whose host answered",
        NetEvent::Reopened { .. } => "holding a room that reopened",
        NetEvent::ReopenGone { .. } => "forgetting a room that no longer exists",
        NetEvent::ReopenFailed { .. } => "saying why a room did not reopen",
        NetEvent::ReopenFinished => "answering an unlock whose rooms are held again",
        NetEvent::LockSettled => "answering a lock that has settled",
        NetEvent::JoinAdmit { .. } => "admitting a joiner before accepting it",
        NetEvent::SeatReserve { .. } => "holding a room's place for a joiner",
        NetEvent::SeatRelease { .. } => "freeing a place a joiner did not take",
        NetEvent::SeatAsk { .. } => "answering whether a member's newcomer may take a place",
        NetEvent::SeatAbort { .. } => "freeing a place promised to a member's newcomer",
        NetEvent::AgreeAsk { .. } => "answering whether this node holds a member's claim",
        NetEvent::AgreeFetch { .. } => "pulling what members hold for a claim's agreement",
        NetEvent::HandshakesQueued { .. } => "saying how a burst of connection attempts went",
        NetEvent::Stopped { .. } => "shutting the network down",
        NetEvent::AppDial(_) => "reaching a peer for an app stream",
        NetEvent::Status(_) => "reporting status",
        NetEvent::Names(_) => "resolving a .vox name",
        NetEvent::SessionRows { .. } => "reading a room's Session entries",
        NetEvent::MemberDialer(_) => "lending the proxy its dialer",
    }
}

/// A step of the actor's whose future is large, **boxed where it is made** (V210-127, #341): only
/// the box's pointer sits in the frame of the step that awaits it.
///
/// A debug build gives an async fn's poll a stack slot for every future it awaits, every arm
/// alike, and the actor's dispatchers await dozens: `handle_net`'s poll frame came to 815 KiB
/// and `Node::run`'s to 471 KiB, so `vox room create` in a debug `vox daemon` overflowed its
/// 2 MiB worker stack once the record it signs derived the ML-DSA key on top
/// ("thread 'tokio-rt-worker' has overflowed its stack"). Each step below is a plain fn that makes
/// its body's future in its own frame and boxes it, so its callers hold a pointer instead.
type Boxed<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

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

/// Where a node's endpoint binds.
#[derive(Clone)]
pub enum Bind {
    /// A UDP address (the wildcard is the normal choice: what the node *advertises*
    /// comes from the ADR-012 ladder, not from here).
    Addr(std::net::SocketAddr),
    /// A caller-supplied datagram socket — a simulated network with NAT devices, or
    /// any other substrate (`SharedEndpoint::bind_abstract`).
    Socket(Arc<dyn quinn::AsyncUdpSocket>),
    /// **The daemon's presence, shared with every node it hosts** (ADR-026 D-3): the node attaches
    /// to it instead of binding, and its detach closes only its own connections (D-5). The
    /// presence's socket, port, mapping and nearby group are the daemon's.
    Shared(Arc<crate::node::presence::NetPresence>),
}

impl std::fmt::Debug for Bind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bind::Addr(a) => write!(f, "Bind::Addr({a})"),
            Bind::Socket(s) => write!(f, "Bind::Socket({s:?})"),
            Bind::Shared(p) => write!(f, "Bind::Shared({:?})", p.shared().local_addr().ok()),
        }
    }
}

/// Everything a node is configured with. [`Node::spawn_config`] takes it; the other
/// constructors are shorthands for common shapes of it.
#[derive(Clone)]
pub struct NodeConfig {
    /// The wall clock, in milliseconds (tests inject a fixed one).
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
    /// The anchors, if any, that bridge this node to peers it cannot reach directly
    /// (ADR-012): it publishes to, reads from, climbs its ladder through and names in invite
    /// links whichever it has. Empty is a whole configuration: peers that can reach each
    /// other directly need no anchor.
    pub anchors: BootstrapSet,
    /// A **headless** identity (ADR-016 `vox node`): a transport identity that is not
    /// a vault. With one, the node networks the moment it is spawned — there is no
    /// passphrase and nothing to unlock — and it holds no channel secrets, because
    /// it has no profile to hold them in: it serves the board, coordinates, relays,
    /// and stores ciphertext. The absence of secrets is structural: every path that
    /// needs a profile finds none.
    pub headless: Option<Arc<crate::identity::composite::SoftwareRootSigner>>,
    /// Keep a **rendezvous board** for every room whose genesis a member publishes to this node,
    /// though it is not a member: an anchor's job (ADR-012). **Nothing else**: an anchor stores
    /// no log, ciphertext or otherwise, for a room it is not a member of (ADR-023 decision 6,
    /// PRD-001 R34). Members who are never online together converge through an always-on
    /// *member*, not through an anchor. `vox node` turns it on; a client leaves it off, so a
    /// stranger's genesis on its board costs it nothing.
    pub anchor_boards: bool,
    /// How long nothing new must have expired before a backlog of this identity's expired
    /// entries smaller than a checkpoint batch is checkpointed anyway (ADR-023 decision 3).
    /// Production is [`crate::node::channel::CHECKPOINT_IDLE_SECS`]; only the test-only
    /// `VOX_TEST_CHECKPOINT_IDLE_SECS` changes it, so a proof need not wait ten minutes.
    pub checkpoint_idle_secs: u64,
    /// For an anchor, which creators' rooms it serves: `None` serves any room published to
    /// it (`vox node --serve anyone`), `Some` only rooms whose genesis names one of these
    /// (`--serve trusted`, the anchor profile's `vox trust` list). Ignored unless
    /// [`NodeConfig::anchor_boards`] is on.
    pub serve_only: Option<BTreeSet<Digest32>>,
    /// Called once if opening the profile waits more than a second for another vox holding it
    /// (V210-100): before the node exists, so it cannot be an event. A CLI verb prints its words
    /// on stderr; `None` says nothing.
    pub on_profile_wait: Option<Arc<dyn Fn() + Send + Sync>>,
}

/// [`crate::node::channel::CHECKPOINT_IDLE_SECS`], unless the **test-only**
/// `VOX_TEST_CHECKPOINT_IDLE_SECS` says otherwise. Nothing in a real deployment sets it; a proof of
/// the closing checkpoint drives the shipped binary and cannot wait ten minutes per run. Without
/// the `test-knobs` feature (V210-105) it is the production value.
#[cfg(feature = "test-knobs")]
fn checkpoint_idle_from_env() -> u64 {
    std::env::var("VOX_TEST_CHECKPOINT_IDLE_SECS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(crate::node::channel::CHECKPOINT_IDLE_SECS)
}

/// The production value: the knob is not compiled in (V210-105).
#[cfg(not(feature = "test-knobs"))]
const fn checkpoint_idle_from_env() -> u64 {
    crate::node::channel::CHECKPOINT_IDLE_SECS
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
            // The system clock unless a proof set the test-only clock step (V210-64); the
            // milliseconds clock below also honours the skew alone (ADR-023 proof 2, #230).
            millis_clock: crate::time::millis_clock_with_test_skew(),
            argon2: Argon2Profile::default(),
            bind: None,
            pow_params: None,
            anchors: BootstrapSet::new(),
            headless: None,
            anchor_boards: false,
            checkpoint_idle_secs: checkpoint_idle_from_env(),
            serve_only: None,
            on_profile_wait: None,
        }
    }

    /// As an anchor, serve only rooms created by one of `creators` (`vox node --serve
    /// trusted`); see [`NodeConfig::serve_only`].
    #[must_use]
    pub fn serve_only(mut self, creators: BTreeSet<Digest32>) -> Self {
        self.serve_only = Some(creators);
        self
    }

    /// Say this (once) if opening the profile has to wait for another vox holding it.
    #[must_use]
    pub fn on_profile_wait(mut self, notice: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_profile_wait = Some(Arc::new(notice));
        self
    }

    /// Keep a rendezvous board for rooms this node is not a member of (an anchor's job); see
    /// [`NodeConfig::anchor_boards`].
    #[must_use]
    pub fn anchor_boards(mut self, on: bool) -> Self {
        self.anchor_boards = on;
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
const ANCHOR_REDIAL_MS: u64 = 30_000;

/// The longest an anchor whose **dial failed** waits before the next (V210-86, #278). Every
/// second of it is a second a member stays away after its anchor is back: doubled to
/// [`ANCHOR_REDIAL_MS`], a member whose dials failed while its anchor restarted could come back
/// up to 30 s after it. A dial that failed never became a connection, so what a shorter wait costs
/// the anchor is bounded by its handshake cap and queue (`HANDSHAKES_IN_FLIGHT`,
/// `HANDSHAKES_WAITING`). At the cap the wait is 1 or 2 s at random, so a room's members do not
/// redial in step. A connection lost as soon as it is made (a flap, [`ANCHOR_FLAP_MS`]) still
/// backs off to [`ANCHOR_REDIAL_MS`]: each of those was a whole handshake.
const ANCHOR_UNREACHED_REDIAL_MS: u64 = 2_000;

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
/// [`ANCHOR_REDIAL_MS`].
const ANCHOR_FLAP_MS: u64 = 10_000;

/// How long an anchor connection may hear nothing before every tick probes it (V210-93).
const ANCHOR_PROBE_AFTER: Duration = Duration::from_secs(3);

/// How long an anchor connection may go unanswered, probed on every tick, before its anchor is
/// taken for gone (V210-93): an anchor that was killed or crashed sends no close, and without this
/// a node learned of it only from the 60 s idle timeout. Five probes at least go unanswered first,
/// so a loaded anchor slow to ACK one is not buried. A loss is said within this and a tick.
const ANCHOR_SILENCE_IS_LOSS: Duration = Duration::from_secs(8);

/// How many probes, counted at most one a tick while this node runs, must go unanswered before
/// an anchor is taken for gone (V210-93): so a node's own stall is never read as its anchor's
/// silence.
const ANCHOR_PROBES_BEFORE_LOSS: u32 = 5;

/// Why an anchor's connection closed, as a person reads it (V210-93). A stopping node closes
/// with [`crate::wire::WireError::ShuttingDown`]: that is "the anchor stopped", not a fault.
fn anchor_close_reason(
    e: &quinn::ConnectionError,
    closed_here: Option<crate::wire::WireError>,
) -> String {
    match e {
        quinn::ConnectionError::ApplicationClosed(close) => {
            match u8::try_from(close.error_code.into_inner())
                .ok()
                .and_then(crate::wire::WireError::from_code)
            {
                Some(crate::wire::WireError::ShuttingDown) => "the anchor stopped".to_owned(),
                Some(code) => format!("the anchor closed it: {code}"),
                // What the anchor wrote, never as it wrote it (V210-154).
                None => crate::transport::quic::closed_text(e),
            }
        }
        quinn::ConnectionError::LocallyClosed => match closed_here {
            Some(code) => format!("closed here: {code}"),
            None => "closed here".to_owned(),
        },
        other => crate::transport::quic::closed_text(other),
    }
}

/// What a sync session runs against: a member's channel. An anchor holds no copy of a room it is
/// not a member of, so there is nothing else to sync (ADR-023 decision 6).
enum SessionTarget {
    Channel(SharedChannel),
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
    now_ms: crate::time::Ms,
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
                &shared, &store, &mut t, now_ms, &fence, &on_stored,
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
    /// A program asked, through the app API, to open an app stream to `peer`: reach it
    /// through the ladder and hand the connection back (ADR-022 decision 7).
    AppDial(crate::node::app::AppDial),
    /// `vox status` or the metrics endpoint asked what this node is doing (PRD-001 R35,
    /// R38): read state, answer, change nothing.
    Status(oneshot::Sender<crate::node::status::StatusReport>),
    /// A `.vox` name is being resolved (PRD-001 R20): answer with a snapshot of this
    /// node's rooms and keyring names.
    Names(oneshot::Sender<crate::node::resolver::VoxResolver>),
    /// The Session entries this node can read in a room (ADR-029 SC-2), or `None` if the room
    /// is not open.
    SessionRows {
        /// The room.
        channel_id: Digest32,
        /// Where the answer goes.
        reply: oneshot::Sender<Option<Vec<crate::node::drive::SessionRow>>>,
    },
    /// The daemon's proxy (ADR-028 S-5) wants this node's way of reaching a member, to carry a
    /// name that resolved to one of this node's rooms.
    MemberDialer(oneshot::Sender<crate::error::Result<MemberDialer>>),
    /// A held room's address was given again and a member it names answered there (V210-167):
    /// keep what it names as the room's, dial its anchors, and answer the join.
    AddressReached {
        /// The room.
        room: Digest32,
        /// Every node the address names but this one.
        named: BootstrapSet,
        /// The members that answered there.
        answered: Vec<Digest32>,
        /// The join's answer.
        reply: oneshot::Sender<Outcome>,
    },
    /// A node on this computer or the local network said where it listens, naming members by
    /// `node::nearby::entry` (V210-167).
    Heard {
        /// The address it was heard from.
        from: std::net::IpAddr,
        /// The members it named, and their ports.
        entries: Vec<crate::node::nearby::Entry>,
    },
    /// The presence's publish side composed what its nodes advertise (ADR-026 D-3): this node's
    /// records are published again with it.
    AddressesDiscovered,
    /// The machine's network changed, and the presence's publish side has run for it (ADR-012
    /// N-51): republish, and dial again whatever did not survive the move.
    NetworkChanged(Arc<crate::nat::netwatch::NetChange>),
    /// Peers whose connection the network change stranded, closed now: dialled again at once.
    Stranded(Vec<Digest32>),
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
    /// A peer's pairwise stream, its frames **already read** off the actor (V210-71).
    Pairwise(PairwiseIn),
    /// A stream that carried this node's hello to `peer` could not be written: the peer does not
    /// hold the session, so the next delivery must carry the hello again.
    HelloUndelivered {
        /// The room.
        channel_id: Digest32,
        /// The member.
        peer: Digest32,
    },
    /// A hello offered again with an `Open` behind it (ADR-004 O3) could not be written: it is
    /// offered again.
    ReopenUndelivered {
        /// The room.
        channel_id: Digest32,
        /// The member.
        peer: Digest32,
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
        /// Whether the recipient answered (a refusal it made), rather than the key being lost
        /// on its way (see `pairwise_stream::refused`).
        answered: bool,
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
        /// Whether the board holds the room as a joiner needs it now: the genesis, our bundle and
        /// our address each taken (or refused only as older than what it holds). What an address
        /// naming this board waits for (V210-96).
        holds_room: bool,
    },
    /// An address waited on since `serial` (see `Node::begin_invite`) has waited
    /// [`ADDRESS_PATIENCE`]: withheld, with its cause, if its room is still on no board it names.
    AddressWaitOver {
        /// The room.
        channel_id: Digest32,
        /// Which wait this ends.
        serial: u64,
    },
    /// The anchors an address handed out at `serial` named, and had not taken its room then, have
    /// had [`ADDRESS_PATIENCE`]: each that still has not is named, with why (V210-96).
    AnchorNoteDue {
        /// The room.
        channel_id: Digest32,
        /// Which address this is about.
        serial: u64,
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
        /// The witness this node signed for it (ADR-016 M17.6): kept, as an admission notice, so
        /// every member learns of the joiner while it is offline (#520).
        witness: Box<crate::nat::record::JoinWitness>,
        /// Answered with whether the admission was applied: `Ok` releases the acceptance frame, an
        /// error refuses the joiner instead (a full room says so). A dropped sender answers too —
        /// the slot must never wait on an actor that has moved on — and is a refusal: nothing
        /// admitted the joiner. `Ok` carries the room's shared name, which the acceptance tells
        /// the joiner (ADR-028 R-1).
        ack: tokio::sync::oneshot::Sender<crate::error::Result<Option<String>>>,
    },
    /// **The member answering a join holds a place for the joiner** (V030-30, #366), if the room
    /// has one: its authors and every place promised and not yet settled leave one. Answered with
    /// the members to ask, each a member this node holds a connection to; the place is held under
    /// this node's own name until [`NetEvent::SeatRelease`], the joiner's admission, or
    /// `seatstream::PROMISE_TTL`.
    SeatReserve {
        /// The room being joined.
        channel_id: Digest32,
        /// The joiner's fingerprint.
        joiner: Digest32,
        /// The room's epoch and the members to ask, or why there is no place: `RoomFull` at the
        /// cap, `SeatTaken` when the places left are all promised.
        ack: tokio::sync::oneshot::Sender<crate::error::Result<SeatsToAsk>>,
    },
    /// The place [`NetEvent::SeatReserve`] held for `joiner` is not taken: a member did not agree,
    /// or the admission failed.
    SeatRelease {
        /// The room.
        channel_id: Digest32,
        /// The joiner.
        joiner: Digest32,
    },
    /// Another member asks whether its newcomer may take a place in a room (V030-30, #366).
    SeatAsk {
        /// The member asking.
        peer: Digest32,
        /// Its question.
        ask: crate::node::seatstream::Ask,
        /// The stream's send half.
        send: quinn::SendStream,
        /// The stream's receive half, read for an abort.
        recv: quinn::RecvStream,
    },
    /// The member that asked frees the place promised to its newcomer.
    SeatAbort {
        /// The member that asked.
        peer: Digest32,
        /// The room and newcomer.
        abort: crate::node::seatstream::Abort,
    },
    /// Another member asks whether this node holds a post it made, and which posts of some
    /// `type`s this node holds (V210-168). The actor checks the room and the member at once; a
    /// task waits for the post and answers.
    AgreeAsk {
        /// The member asking.
        peer: Digest32,
        /// Its question.
        ask: crate::node::agreestream::Ask,
        /// The stream's send half.
        send: quinn::SendStream,
    },
    /// An agreement round needs posts these members hold and this node does not: sync the room
    /// with them now (V210-168).
    AgreeFetch {
        /// The room.
        channel_id: Digest32,
        /// The members to sync with.
        peers: Vec<Digest32>,
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
    /// A room in the reopen set would not open (#412): it stays remembered, and closed, and the
    /// operator is told why — a room that stayed closed with no word was a room nobody could
    /// tell how to get back.
    ReopenFailed {
        /// The room.
        channel_id: Digest32,
        /// What refused it.
        why: String,
    },
    /// The reopening has tried every room (#208). A room still marked as reopening would not
    /// open: it stays remembered, and closed. The unlock is answered now.
    ReopenFinished,
    /// A lock has settled: nothing it stopped holds a secret any more (V210-94).
    LockSettled,
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
        /// The passphrase, kept by the room's state.
        passphrase: Secret,
        /// When the join began.
        now: crate::time::Ms,
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
        /// The room's shared name (ADR-028 R-1).
        room_name: String,
        /// The passphrase, kept by the room's state.
        passphrase: Secret,
        /// The genesis made before the seal.
        genesis: Box<crate::governance::genesis::Genesis>,
        /// When the room was begun.
        now: crate::time::Ms,
        /// The room key and its sealed wrap, or why sealing failed.
        sealed: crate::error::Result<(crate::atrest::sek::Sek, crate::atrest::SekWrap)>,
        /// For `vox serve`: the one service the room is made for, as (tag, endpoint, the kind
        /// detected for it).
        service: Option<(String, SocketAddr, crate::governance::share::ServiceKind)>,
    },
    /// A room's key was unwrapped and its log re-verified on a blocking thread (the slow part of
    /// opening a room with its passphrase, V210-71): hold the room and answer the command.
    ChannelUnsealed {
        /// The `OpenChannel` command's reply.
        reply: oneshot::Sender<Outcome>,
        /// The room.
        channel_id: Digest32,
        /// The opened room, or why it would not open.
        opened: Box<crate::error::Result<ChannelState>>,
    },
    /// A record by another author was admitted to this node's board, so what this node can
    /// vouch for has grown and its anchors do not know it yet.
    BoardGrew {
        /// The room whose board grew.
        channel_id: Digest32,
    },
    /// A signed withdraw took records off this node's board (V030-14): what it shows changed.
    BoardWithdrew,
    /// A leave begun at `serial` (see `Node::begin_leave`) has waited [`LEAVE_PATIENCE`] and no
    /// other member has taken the departure: it is answered, and goes on waiting.
    LeaveWaitOver {
        /// The room.
        channel_id: Digest32,
        /// Which wait this ends.
        serial: u64,
    },
    /// A peer connected and opened a stream the actor must handle.
    Stream {
        /// The connection it arrived on, kept alive for the reply.
        conn: Arc<crate::transport::quic::VoxConnection>,
        /// The authorized stream.
        inbound: Inbound,
    },
    /// A burst of inbound attempts that waited for a handshake slot, or were refused, is over
    /// (V210-86).
    HandshakesQueued {
        /// How many waited.
        waited: usize,
        /// The most that waited at once.
        most_waiting: usize,
        /// The most handshakes that ran at once meanwhile.
        most_running: usize,
        /// How many were refused.
        refused: usize,
        /// The longest any waited.
        longest: Duration,
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
        let mut state = StreamLoop::default();
        // **Each stream's kind is read on a task of its own** (V210-80). Read here, in the loop,
        // a peer that opened a stream and withheld its kind frame held every stream it opened
        // after that for `FRAME_PATIENCE` (30 s) — its sync, its keys, its board puts — one
        // withheld stream at a time, for ever.
        //
        // **Still handed on in the order they arrived.** A pairwise hello and the key that
        // follows it are separate streams, and reordering them is exactly the race F12 was. So
        // a typed stream waits for the streams accepted before it — but only for
        // [`KIND_ORDER_GRACE`]. An honest peer writes a stream's kind with the stream itself
        // (`open_typed`), so its streams are all typed within a scheduling delay and keep their
        // order exactly; a stream still untyped past the grace stops holding the ones behind it,
        // and is served whenever its kind does arrive, or dropped when its read gives up.
        let mut readers = tokio::task::JoinSet::new();
        let mut typed: BTreeMap<u64, crate::error::Result<Typed>> = BTreeMap::new();
        let mut untyped_since: BTreeMap<u64, tokio::time::Instant> = BTreeMap::new();
        let (mut accepted, mut next) = (0u64, 0u64);
        'streams: loop {
            // Whatever is typed at the head of the arrival order goes on, in order.
            while let Some(stream) = typed.remove(&next) {
                next += 1;
                if serve_typed(&net, &conn, &tx, &quic, peer, stream, &mut state).await
                    == Flow::Stop
                {
                    break 'streams;
                }
            }
            let head_due = untyped_since.get(&next).map(|at| *at + KIND_ORDER_GRACE);
            tokio::select! {
                stream = quic.accept_bi() => {
                    let Ok((send, recv)) = stream else {
                        break; // the peer or the network closed it
                    };
                    let n = accepted;
                    accepted += 1;
                    untyped_since.insert(n, tokio::time::Instant::now());
                    readers.spawn(async move {
                        (n, crate::transport::streams::read_kind(send, recv).await)
                    });
                }
                Some(read) = readers.join_next(), if !readers.is_empty() => {
                    let Ok((n, stream)) = read else { continue };
                    untyped_since.remove(&n);
                    if n < next {
                        // Its turn was given up at the grace: served now, out of order.
                        if serve_typed(&net, &conn, &tx, &quic, peer, stream, &mut state).await
                            == Flow::Stop
                        {
                            break 'streams;
                        }
                    } else {
                        typed.insert(n, stream);
                    }
                }
                () = tokio::time::sleep_until(head_due.unwrap_or_else(tokio::time::Instant::now)),
                    if head_due.is_some() =>
                {
                    // The head is still untyped past the grace: the streams behind it go on.
                    untyped_since.remove(&next);
                    next += 1;
                }
            }
        }
        // This peer's report of our address dies with its connection.
        net.forget_observed(&peer);
    })
}

/// A stream whose kind has been read: the kind and both halves.
type Typed = (
    crate::transport::streams::StreamKind,
    quinn::SendStream,
    quinn::RecvStream,
);

/// How long a stream accepted on a connection may stay untyped before the streams accepted after
/// it stop waiting for it (see `spawn_stream_loop`). An honest peer's kind arrives with the stream,
/// so this is only ever reached by a peer that withholds it, or on a path slow enough that order
/// between its streams is the least of its problems.
const KIND_ORDER_GRACE: Duration = Duration::from_secs(2);

/// What one connection's stream loop keeps between streams (see `spawn_stream_loop`).
#[derive(Default)]
struct StreamLoop {
    /// Consecutive streams that failed.
    failures: u32,
    /// This connection's pairwise reader, started with its first pairwise stream.
    pairwise: Option<mpsc::Sender<(quinn::SendStream, quinn::RecvStream)>>,
}

/// Whether the stream loop goes on.
#[derive(PartialEq, Eq)]
enum Flow {
    Go,
    Stop,
}

/// Serve one stream of `peer`'s whose kind has been read: authorize it and hand it on, as the
/// stream loop always has (see `spawn_stream_loop`). `state.failures` counts consecutive failures, and
/// [`Flow::Stop`] ends the loop.
async fn serve_typed(
    net: &Arc<NodeNet>,
    conn: &std::sync::Weak<crate::transport::quic::VoxConnection>,
    tx: &mpsc::Sender<NetEvent>,
    quic: &quinn::Connection,
    peer: Digest32,
    stream: crate::error::Result<Typed>,
    state: &mut StreamLoop,
) -> Flow {
    // One stream failing is **not** the connection failing. A refused kind, a malformed frame or
    // a peer that abandons a stream must not stop the others being served: a peer that opens a
    // bad `coord` stream would otherwise take its own sync path down with it, and the node would
    // go quiet until it reconnected. The loop ends when the connection itself is gone — or after
    // this many consecutive failures, which cannot happen without the connection being unusable
    // and which keeps a pathological peer from spinning this task.
    const MAX_CONSECUTIVE_STREAM_FAILURES: u32 = 16;
    let (kind, send, recv) = match stream.and_then(|t| net.authorize_typed(peer, t)) {
        Ok(accepted) => accepted,
        // **A refusal is not a failure.** The stream was typed and answered; the peer may not
        // open that kind *yet* — a joiner syncing before it is a member, a responder pushing
        // before the room is held here — and it will be allowed once the view catches up.
        // Counted, sixteen of those ended this loop while the connection stayed filed, and every
        // stream the peer opened after that, allowed or not, went unserved for the connection's
        // life (V210-80). It cannot spin: each one is a stream the peer opened.
        Err(crate::error::Error::StreamRefused(_)) => return Flow::Go,
        Err(_) => {
            if quic.close_reason().is_some() {
                return Flow::Stop; // the peer or the network closed it
            }
            state.failures += 1;
            if state.failures >= MAX_CONSECUTIVE_STREAM_FAILURES {
                // Closed, not only abandoned: a connection nobody serves must not stay filed as
                // this peer's, or both ends go on using it for nothing.
                quic.close(
                    crate::transport::quic::close_code(crate::wire::WireError::TransportFailed),
                    b"stream failures",
                );
                return Flow::Stop;
            }
            return Flow::Go;
        }
    };
    // Nobody holds the connection any more: the node has let it go, and a stream
    // arriving on it has nothing to be served against.
    let Some(conn) = conn.upgrade() else {
        return Flow::Stop;
    };
    // **The kinds this node serves to completion get a task each.** `accept_stream` served them
    // inline — `dispatch`'s own doc says to put it on its own task when accepting in a loop, and
    // this loop did not — so while one was being served no other stream from this peer was even
    // accepted. A rendezvous stream holds its server until the client finishes or a 20s frame read
    // gives up; a circuit's opening exchange waits on the *target* peer's answer, which is another
    // node's loop. On an anchor that put a member's next board `put` behind whatever that member's
    // last stream was waiting for, 20s at a time, and the member's actor — which awaits its puts —
    // answered nobody for 30s, 60s, 80s, measured through the real binaries.
    //
    // Only these three. Every other kind is handed on in the order it arrived, as before: a
    // pairwise hello and the key that follows it are separate streams, and reordering them is
    // exactly the race F12 was.
    if matches!(
        kind,
        crate::transport::streams::StreamKind::Rendezvous
            | crate::transport::streams::StreamKind::Coord
            | crate::transport::streams::StreamKind::Circuit
    ) {
        state.failures = 0;
        let net = Arc::clone(net);
        let conn = Arc::clone(&conn);
        let tx = tx.clone();
        tokio::spawn(async move {
            // A coordination stream can end by handing the actor a punch to run.
            if let Ok(inbound @ Inbound::Punch { .. }) = net.dispatch(&conn, kind, send, recv).await
            {
                let _ = tx
                    .send(NetEvent::Stream {
                        conn: Arc::clone(&conn),
                        inbound,
                    })
                    .await;
            }
        });
        return Flow::Go;
    }
    match net.dispatch(&conn, kind, send, recv).await {
        Ok(
            Inbound::ServedRendezvous { .. }
            | Inbound::ServedCoord { .. }
            | Inbound::ServedCircuit { .. }
            | Inbound::ServedGoodbye { .. },
        ) => state.failures = 0,
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
            state.failures = 0;
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
        // Read off the actor too: a member that opens a stream and says nothing waits on itself.
        Ok(Inbound::Seat { peer, send, recv }) => {
            state.failures = 0;
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut recv = recv;
                let Ok(ask) = crate::node::seatstream::read_ask(&mut recv).await else {
                    return;
                };
                let _ = tx
                    .send(NetEvent::SeatAsk {
                        peer,
                        ask,
                        send,
                        recv,
                    })
                    .await;
            });
        }
        // The question is read off the actor, like a sync preamble: answering needs the actor,
        // waiting for a member that opened a stream and says nothing must not (V210-168).
        Ok(Inbound::Agree { peer, send, recv }) => {
            state.failures = 0;
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut recv = recv;
                let Ok(ask) = crate::node::agreestream::read_ask(&mut recv).await else {
                    return;
                };
                let _ = tx.send(NetEvent::AgreeAsk { peer, ask, send }).await;
            });
        }
        Ok(Inbound::Sync { peer, send, recv }) => {
            state.failures = 0;
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
        // A pairwise stream's frames are read **here too, off the actor** (V210-71), and for the
        // same reason as a sync preamble: acting on them needs the actor, waiting for them must
        // not. The actor used to read them inline, `FRAME_PATIENCE` per frame and two frames
        // behind a hello, so a member that opened a pairwise stream and sent nothing held the
        // whole node for 30-60 s, and could do it again.
        //
        // One reader per connection rather than a task per stream, because the order of a peer's
        // pairwise streams is load-bearing: a hello and the key that follows it can be separate
        // streams, and reordering them is the race F12 was. So a silent stream holds back only
        // the pairwise streams its own peer opened after it.
        Ok(Inbound::Pairwise { peer, send, recv }) => {
            state.failures = 0;
            let queue = state.pairwise.get_or_insert_with(|| {
                let (q, rx) = mpsc::channel(PAIRWISE_QUEUE);
                tokio::spawn(read_pairwise_streams(peer, rx, tx.clone()));
                q
            });
            // Back-pressure on this peer's own connection only: a full queue means this peer has
            // that many unread pairwise streams outstanding.
            if queue.send((send, recv)).await.is_err() {
                return Flow::Stop; // the reader ended with the actor
            }
        }
        Ok(inbound) => {
            state.failures = 0;
            let event = NetEvent::Stream {
                conn: Arc::clone(&conn),
                inbound,
            };
            if tx.send(event).await.is_err() {
                return Flow::Stop; // the actor is gone
            }
        }
        Err(_) => {
            if quic.close_reason().is_some() {
                return Flow::Stop; // the peer or the network closed it
            }
            state.failures += 1;
            if state.failures >= MAX_CONSECUTIVE_STREAM_FAILURES {
                return Flow::Stop;
            }
        }
    }
    Flow::Go
}

/// Sealed pairwise frames for one stream to one member, and what their delivery decides.
struct PairwiseJob {
    /// The connection to write on.
    conn: Arc<VoxConnection>,
    /// The frames, sealed on the actor in order.
    frames: Vec<Vec<u8>>,
    /// The room the frames are for.
    channel_id: Digest32,
    /// What the write's outcome tells the actor.
    after: AfterWrite,
}

/// What a pairwise write's outcome decides.
enum AfterWrite {
    /// The stream carried a key of this generation (and a hello in front of it, if `hello`):
    /// whether it was taken is learnt from the recipient's answer.
    Key {
        /// The key's generation.
        chain_id: u64,
        /// Whether the stream carried the hello.
        hello: bool,
        /// The serial of the session the key was sealed under (V210-78): a refusal saying the
        /// member holds no session drops that session only, never a newer one.
        session: Option<u64>,
        /// Whether the key belongs to a history batch (V210-88).
        history: bool,
        /// The `Node::delivery_epoch` it was counted in flight in (V210-88).
        epoch: u64,
    },
    /// The stream offered a hello again with an `Open` behind it (ADR-004 O3).
    Reopen,
}

/// Write one member's pairwise streams in the order they were queued (V210-71), each bounded by
/// `pairwise_stream::WRITE_PATIENCE`. A write that fails is reported so the actor owes it again.
async fn write_pairwise_jobs(
    peer: Digest32,
    mut jobs: mpsc::UnboundedReceiver<PairwiseJob>,
    tx: mpsc::Sender<NetEvent>,
) {
    while let Some(job) = jobs.recv().await {
        let written = crate::node::pairwise_stream::write_pairwise(&job.conn, &job.frames).await;
        let channel_id = job.channel_id;
        let events = match (written, job.after) {
            (
                Ok(sent),
                AfterWrite::Key {
                    chain_id,
                    session,
                    history,
                    epoch,
                    ..
                },
            ) => {
                watch_delivery(
                    tx.clone(),
                    sent,
                    Watched {
                        channel_id,
                        target: peer,
                        chain_id,
                        session,
                        history,
                        epoch,
                    },
                );
                Vec::new()
            }
            (Ok(_), AfterWrite::Reopen) => Vec::new(),
            (
                Err(e),
                AfterWrite::Key {
                    chain_id,
                    hello,
                    session,
                    history,
                    epoch,
                },
            ) => {
                let mut v = Vec::with_capacity(2);
                if hello {
                    v.push(NetEvent::HelloUndelivered { channel_id, peer });
                }
                v.push(NetEvent::SkdmRefused {
                    channel_id,
                    peer,
                    chain_id,
                    why: e.to_string(),
                    answered: false,
                    session,
                    history,
                    epoch,
                });
                v
            }
            (Err(_), AfterWrite::Reopen) => vec![NetEvent::ReopenUndelivered { channel_id, peer }],
        };
        for event in events {
            if tx.send(event).await.is_err() {
                return; // the actor is gone
            }
        }
    }
}

/// A key whose answer is being waited for: what its `SkdmTaken` or `SkdmRefused` must carry.
struct Watched {
    channel_id: Digest32,
    target: Digest32,
    chain_id: u64,
    session: Option<u64>,
    history: bool,
    epoch: u64,
}

/// Learn, off the actor, whether the key just written to `target` was taken; if it was not,
/// `NetEvent::SkdmRefused` makes it owed again. See `pairwise_stream::refused`.
///
/// **Taken is when it is delivered** (V210-88): `NetEvent::SkdmTaken` records the generation as
/// the member's. The key was counted in flight when it was queued (`Node::key_in_flight`).
fn watch_delivery(tx: mpsc::Sender<NetEvent>, sent: quinn::RecvStream, w: Watched) {
    let Watched {
        channel_id,
        target,
        chain_id,
        session,
        history,
        epoch,
    } = w;
    tokio::spawn(async move {
        let event = match crate::node::pairwise_stream::refusal(sent, KEY_DELIVERY_PATIENCE).await {
            Some((why, answered)) => NetEvent::SkdmRefused {
                channel_id,
                peer: target,
                chain_id,
                why,
                answered,
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

/// How many of one connection's pairwise streams may wait to be read.
const PAIRWISE_QUEUE: usize = 32;

/// Read one connection's pairwise streams in the order they arrived and hand each to the actor
/// as [`NetEvent::Pairwise`] once its frames are in hand (V210-71). Each read is bounded by
/// `framing::FRAME_PATIENCE`; a stream that sends nothing usable is dropped here, as the actor
/// dropped it before.
async fn read_pairwise_streams(
    peer: Digest32,
    mut streams: mpsc::Receiver<(quinn::SendStream, quinn::RecvStream)>,
    tx: mpsc::Sender<NetEvent>,
) {
    use crate::node::pairwise_stream::{recv_pairwise, PairwiseFrame};
    while let Some((send, mut recv)) = streams.recv().await {
        let Ok(Some(first)) = recv_pairwise(&mut recv).await else {
            continue;
        };
        // A hello is followed on the same stream by the frame it opens the session for, written
        // without waiting for anything, so it is read now too.
        let second = if matches!(first, PairwiseFrame::Hello { .. }) {
            recv_pairwise(&mut recv).await.ok().flatten()
        } else {
            None
        };
        let stream = PairwiseIn {
            peer,
            first,
            second,
            send,
            recv,
        };
        if tx.send(NetEvent::Pairwise(stream)).await.is_err() {
            return; // the actor is gone
        }
    }
}

/// A pairwise stream whose frames have been read off the actor.
struct PairwiseIn {
    /// The authenticated peer.
    peer: Digest32,
    /// The stream's first frame.
    first: crate::node::pairwise_stream::PairwiseFrame,
    /// The frame behind a `Hello`, if there was one; always `None` behind any other frame.
    second: Option<crate::node::pairwise_stream::PairwiseFrame>,
    /// The stream's send half, for the answer.
    send: quinn::SendStream,
    /// The stream's receive half, held until the answer is given.
    recv: quinn::RecvStream,
}

/// **Take this node's inbound connections from its presence** (ADR-026 D-3) and serve them, for
/// as long as the node is attached: each is filed and its streams served on a task of its own,
/// so one slow connection holds up no other. The handshakes and identity exchanges themselves
/// run in the presence's gate (`node::presence`), which hands over only connections already
/// proved to be for this node.
///
/// Ends when the node's queue closes (it detached: its registration and the queue's sender went
/// with it) or the presence's endpoint closes, and says so (`NetEvent::Stopped`). Also says each
/// burst of attempts the gate made wait or refused (`NodeEvent::HandshakesQueued`).
fn spawn_inbound_pump(
    net: Arc<NodeNet>,
    mut inbound: mpsc::Receiver<crate::transport::quic::VoxConnection>,
    bursts: tokio::sync::broadcast::Receiver<crate::node::presence::HandshakeBurst>,
    mut closed: watch::Receiver<bool>,
    tx: mpsc::Sender<NetEvent>,
) {
    let gone = Arc::downgrade(&net);
    tokio::spawn(async move {
        let mut bursts = Some(bursts);
        loop {
            let burst = async {
                match bursts.as_mut() {
                    Some(b) => b.recv().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                conn = inbound.recv() => {
                    let Some(conn) = conn else { break };
                    let (net, tx) = (Arc::clone(&net), tx.clone());
                    tokio::spawn(async move {
                        let filed = net.manager().take_inbound(conn).await;
                        let _ = serve_filed(&net, &tx, filed).await;
                    });
                }
                b = burst => match b {
                    Ok(b) => {
                        // Without waiting: a report lost to a full queue costs only the report.
                        let _ = tx.try_send(NetEvent::HandshakesQueued {
                            waited: b.waited,
                            most_waiting: b.most_waiting,
                            most_running: b.most_running,
                            refused: b.refused,
                            longest: b.longest,
                        });
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => bursts = None,
                },
                r = closed.wait_for(|c| *c) => {
                    let _ = r;
                    break;
                }
            }
        }
        #[cfg(feature = "test-knobs")]
        if let Some(ms) = test_stopped_delay_ms() {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
        let _ = tx.send(NetEvent::Stopped { net: gone }).await;
    });
}

/// How long, in milliseconds, the identity passphrase stays good for a keyring change once it has
/// been entered (V210-159, decider 2026-10-02). Posting and reading go on while the node runs; only
/// a trust add or remove past this needs the passphrase again, whichever client asks.
pub const KEYRING_WINDOW_MS: u64 = 30 * 60 * 1_000;

/// [`KEYRING_WINDOW_MS`], or `TEST_KEYRING_WINDOW_ENV`'s seconds in a `test-knobs` build.
fn keyring_window_ms() -> u64 {
    #[cfg(feature = "test-knobs")]
    if let Some(secs) = std::env::var(TEST_KEYRING_WINDOW_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        return secs.saturating_mul(1_000);
    }
    KEYRING_WINDOW_MS
}

/// How many seconds a keyring change still goes without the passphrase, rounded up for a person,
/// for a passphrase entered at `entered_ms` (`0`: not since the node was attached) and the time
/// `now_ms`: `None` once a change would ask for it (ADR-028 K-9). A clock that went backwards
/// counts as just entered, as a keyring change counts it.
#[must_use]
pub fn keyring_left(entered_ms: u64, now_ms: u64) -> Option<u64> {
    let window = keyring_window_ms();
    let gone = now_ms.saturating_sub(entered_ms);
    (entered_ms != 0 && gone <= window).then(|| (window - gone).div_ceil(1_000))
}

/// `ms` milliseconds as a person reads them in a note: whole seconds, rounded, as `"3s"`.
fn seconds_said(ms: u64) -> String {
    format!("{}s", ms.saturating_add(500) / 1_000)
}

/// **For proofs only.** The keyring window in seconds instead of 30 minutes, so a proof can see a
/// keyring change refused once it has passed. Nothing a person runs sets it. Not compiled in
/// without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_KEYRING_WINDOW_ENV: &str = "VOX_TEST_KEYRING_WINDOW_SECS";

/// **For proofs only.** When set, the accept loop waits this many milliseconds between stopping
/// and saying so (`NetEvent::Stopped`), which stands for an actor queue that is full or a task that
/// is scheduled late. The lock-and-unlock proof uses it to land the event after an unlock started
/// a new network. Nothing a person runs sets it; unset, nothing changes. Not compiled in without
/// the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_STOPPED_DELAY_ENV: &str = "VOX_TEST_STOPPED_DELAY_MS";

/// **For proofs only.** When set, the node does not say or hear where members listen nearby
/// (`node::nearby`), so a proof on one computer can show what a node finds its members by without
/// it. Nothing a person runs sets it. Not compiled in without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_NO_NEARBY_ENV: &str = "VOX_TEST_NO_NEARBY";

#[cfg(feature = "test-knobs")]
fn test_stopped_delay_ms() -> Option<u64> {
    std::env::var(TEST_STOPPED_DELAY_ENV).ok()?.parse().ok()
}

/// **For proofs only.** When set, this node keeps its own member **address** record off every
/// board for this many milliseconds after it first publishes a room's records (its bundle still
/// goes), which stands for an address record still on its way. V210-43's proof uses it to make a
/// just-joined member sync with its anchor while the anchor knows it only by its pre-join record
/// and the bundle that admits it: the window in which it must be told "not a member yet", never
/// refused as a stranger. Nothing a person runs sets it; unset, nothing changes. Not compiled in
/// without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_HOLD_ADDRESS_ENV: &str = "VOX_TEST_HOLD_ADDRESS_MS";

/// Whether [`TEST_HOLD_ADDRESS_ENV`] still keeps the node `me`'s address record for `channel_id`
/// off the boards: its time counts from that node's first call for that room, kept per (node,
/// room) because a process may host several nodes (ADR-026 P-1).
#[cfg(feature = "test-knobs")]
fn test_hold_address(me: &Digest32, channel_id: &Digest32) -> bool {
    static FIRST: std::sync::Mutex<BTreeMap<(Digest32, Digest32), std::time::Instant>> =
        std::sync::Mutex::new(BTreeMap::new());
    let Some(ms) = std::env::var(TEST_HOLD_ADDRESS_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    else {
        return false;
    };
    let mut first = FIRST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let since = *first
        .entry((*me, *channel_id))
        .or_insert_with(std::time::Instant::now);
    since.elapsed() < Duration::from_millis(ms)
}

/// **For proofs only.** When set, every publish round to an anchor fails, as a round whose stream
/// will not open does, for this many milliseconds after this node first publishes a room — a host
/// slow to reach its anchor (its first dial failed, the anchor is starting). Each held round is
/// tried again on its own backoff, so the room reaches the anchor once the hold has passed.
/// V210-143's proof uses it to have a guest arrive before the anchor holds the room. Nothing a
/// person runs sets it; unset, nothing changes. Not compiled in without the `test-knobs` feature
/// (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_HOLD_ROOM_FROM_ANCHORS_ENV: &str = "VOX_TEST_HOLD_ROOM_FROM_ANCHORS_MS";

/// Whether [`TEST_HOLD_ROOM_FROM_ANCHORS_ENV`] still keeps `channel_id` off the node `me`'s
/// anchors: its time counts from that node's first call for that room (ADR-026 P-1).
#[cfg(feature = "test-knobs")]
fn test_hold_room_from_anchors(me: &Digest32, channel_id: &Digest32) -> bool {
    static FIRST: std::sync::Mutex<BTreeMap<(Digest32, Digest32), std::time::Instant>> =
        std::sync::Mutex::new(BTreeMap::new());
    let Some(ms) = std::env::var(TEST_HOLD_ROOM_FROM_ANCHORS_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    else {
        return false;
    };
    let mut first = FIRST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let since = *first
        .entry((*me, *channel_id))
        .or_insert_with(std::time::Instant::now);
    since.elapsed() < Duration::from_millis(ms)
}

/// **For proofs only.** When set, each blocking task that holds a secret (`secret_blocking`)
/// waits this many milliseconds, holding what it was given, before it starts its work: a stand-in
/// for a slow Argon2id or a large room, so a proof can lock while one runs (V210-94). Nothing a
/// person runs sets it; unset, nothing changes. Not compiled in without the `test-knobs` feature
/// (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_SECRET_WORK_DELAY_ENV: &str = "VOX_TEST_SECRET_WORK_DELAY_MS";

/// **For proofs only.** When set, every room this node reopens by itself at unlock fails to
/// reopen, with the reason this says, so a proof can see that the reason is said (#412). Not
/// compiled in without the `test-knobs` feature.
#[cfg(feature = "test-knobs")]
pub const TEST_REOPEN_FAILS_ENV: &str = "VOX_TEST_REOPEN_FAILS";

/// Run `work`, which holds a secret, on a blocking thread, and hold a read guard of `secret_work`
/// until it is done and its result handed over; `None` if the thread panicked.
///
/// **A lock waits for these** (V210-94). A blocking thread cannot be aborted, so a lock that only
/// aborted the task awaiting it left the thread running on with what it was given — a passphrase
/// inside Argon2id, a room's key being opened — for up to one derivation after the node said it
/// was locked. [`Node::lock_all`] takes the write side, which it gets only once every such thread
/// has finished and dropped (zeroizing) its inputs. So each caller hands `work` only what that
/// work needs, never the identity signer or a key it does not use, and keeps the rest with the
/// task a lock aborts.
async fn secret_blocking<T: Send + 'static>(
    secret_work: &Arc<tokio::sync::RwLock<()>>,
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let held = Arc::clone(secret_work).read_owned().await;
    #[cfg(feature = "test-knobs")]
    let delay = std::env::var(TEST_SECRET_WORK_DELAY_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());
    let (done, result) = oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let _held = held;
        #[cfg(feature = "test-knobs")]
        if let Some(ms) = delay {
            std::thread::sleep(Duration::from_millis(ms));
        }
        // Handed over, or dropped right here if the task that wanted it was aborted meanwhile:
        // before the guard goes, since what `work` made may be a secret too.
        let _ = done.send(work());
    });
    result.await.ok()
}

/// The identity's half of a room key's seal for `channel_id` ([`seal_off_actor`]), taken with
/// the signer where the signer already is.
fn id_factor_for(
    signer: &crate::atrest::vault::VaultRootSigner,
    channel_id: &Digest32,
) -> crate::error::Result<zeroize::Zeroizing<[u8; crate::atrest::idfactor::FACTOR_ID_LEN]>> {
    use crate::atrest::idfactor::IdentityFactor as _;
    crate::atrest::idfactor::SignatureIdentityFactor::new(signer).factor_id(channel_id)
}

/// Seal `sek` under the identity's `factor_id` ([`id_factor_for`]) and `passphrase`, with the
/// Argon2id half on a blocking thread ([`secret_blocking`]) that is given only the passphrase and
/// the salt. No signer crosses into a thread a lock cannot stop, and the SEK stays with the
/// caller's task, sealed once the passphrase's factor is back (V210-94).
async fn seal_off_actor(
    secret_work: &Arc<tokio::sync::RwLock<()>>,
    factor_id: &[u8; crate::atrest::idfactor::FACTOR_ID_LEN],
    sek: crate::atrest::sek::Sek,
    passphrase: Secret,
    argon2: Argon2Profile,
) -> crate::error::Result<(crate::atrest::sek::Sek, crate::atrest::SekWrap)> {
    let salt = crate::atrest::sek::fresh_salt()?;
    let factor_pass = secret_blocking(secret_work, move || {
        crate::atrest::sek::factor_pass(&passphrase, &salt, argon2)
    })
    .await
    .unwrap_or(Err(Error::Argon2Failed))?;
    let wrap = sek.seal_with_factors(factor_id, &factor_pass, &salt, argon2)?;
    Ok((sek, wrap))
}

/// **For proofs only.** When set to `N`, the node loses the first `N` pairwise streams that
/// carry a hello: it resets them unread, as a stream lost with its connection is, so the sender
/// learns only that its key was not taken. The simultaneous-session proof uses it to force what a
/// duplicate-connection close did by chance (V210-89): each member's hello lost after it was
/// written. Nothing a person runs sets it; unset, nothing changes. Not compiled in without the
/// `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_LOSE_HELLOS_ENV: &str = "VOX_TEST_LOSE_HELLOS";

/// Whether this inbound hello, to the node `me` in `room`, is one [`TEST_LOSE_HELLOS_ENV`] says
/// to lose: the first `N` of each (node, room), since a process may host several nodes (ADR-026
/// P-1).
#[cfg(feature = "test-knobs")]
fn test_lose_hello(me: &Digest32, room: &Digest32) -> bool {
    static LEFT: std::sync::Mutex<BTreeMap<(Digest32, Digest32), u64>> =
        std::sync::Mutex::new(BTreeMap::new());
    let mut left = LEFT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let n = left.entry((*me, *room)).or_insert_with(|| {
        std::env::var(TEST_LOSE_HELLOS_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    });
    match n.checked_sub(1) {
        Some(rest) => {
            *n = rest;
            true
        }
        None => false,
    }
}

/// The test-only variable that makes a node **supersede a connection once it carries
/// datagrams**: it dials the peer again where it reached it, files the new connection as the
/// primary and retires the old, which keeps carrying its flows (see
/// [`crate::node::net::ConnectionManager::file_superseding`]). Read only in a build with the
/// `test-knobs` feature (V210-105); what `vox status` must then still report (R35).
#[cfg(feature = "test-knobs")]
pub const TEST_SUPERSEDE_CARRYING_ENV: &str = "VOX_TEST_SUPERSEDE_CARRYING";

/// [`TEST_SUPERSEDE_CARRYING_ENV`]'s task: once per connection, off the actor.
#[cfg(feature = "test-knobs")]
fn spawn_test_supersede(net: Arc<NodeNet>, tx: mpsc::Sender<NetEvent>, clock: Clock) {
    let net = Arc::downgrade(&net);
    tokio::spawn(async move {
        let mut done: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            ticker.tick().await;
            let Some(net) = net.upgrade() else {
                break;
            };
            let manager = net.manager();
            for (peer, conn) in manager.primaries() {
                let d = conn.datagram_stats();
                if d.sent + d.delivered == 0 || !done.insert(conn.serial()) {
                    continue;
                }
                let at = conn.quinn().remote_address();
                if manager.endpoint().is_circuit(at) {
                    continue;
                }
                let dialled = crate::nat::reachability::connect_direct(
                    Arc::clone(manager.endpoint()),
                    &[at],
                    peer,
                    clock(),
                )
                .await;
                if let Ok(fresh) = dialled {
                    // Said on stderr, so a proof can tell the staging happened.
                    eprintln!(
                        "vox: test-knob: superseded the connection to {} that carries datagrams",
                        crate::node::link::b32_encode(&peer)
                    );
                    let fresh = manager.file_superseding(fresh);
                    done.insert(fresh.serial());
                    spawn_stream_loop(Arc::clone(&net), fresh, tx.clone());
                }
            }
        }
    });
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
/// Separate from `Node::BOARD_PATIENCE` because it waits on a different thing: the
/// board is already answering, and what is missing is one record propagating onto it.
const JOIN_ADDRESS_PATIENCE: Duration = Duration::from_secs(20);

/// Poll interval while waiting for it. One extra board fetch is cheap; a failed join is not.
const JOIN_ADDRESS_POLL: Duration = Duration::from_millis(250);

/// How long after this node answers a join a failed sync with the joiner is taken for the join
/// still settling, and not said as a failed sync (#406).
///
/// This node pushes to a joiner the moment it is admitted, and the joiner is not ready for it: it
/// holds the room only once it has sealed the room's key, seconds of Argon2id ("epoch mismatch");
/// `vox connect` joins in a process that then exits ("transport failed"); the node attached after
/// it is still reopening the room ("authenticator invalid"). Each is expected, and nothing a
/// person can act on: measured, an ordinary `vox serve` and `vox connect` printed two. 60 s is an
/// order of magnitude past the seal, and two of the 30 s `Policy` backoffs a refusal takes, so a
/// retry inside it normally succeeds. A failure after it, or after the joiner has synced cleanly
/// once, is reported as before.
const JOINER_SEAL_GRACE: Duration = Duration::from_secs(60);

/// **The asker's round** (V030-30, #366): hold a place for `joiner` in `channel_id`, ask every
/// member this node holds a connection to, all at once, and come back with the streams of those
/// that promised a place, to commit or abort once the admission is known. Any member that does not
/// agree ends the round: every promise made is aborted, this node's own place freed, and the
/// joiner refused with the strongest reason heard (full, then a place lost to another newcomer,
/// then a member that did not agree), which this node's log names member by member.
async fn seat_round(
    tx: &mpsc::Sender<NetEvent>,
    channel_id: Digest32,
    joiner: Digest32,
) -> crate::error::Result<Vec<quinn::SendStream>> {
    use crate::node::seatstream::{abort, ask, Abort, Answer, Ask, Asked};
    let stopped = || Error::JoinRefused("the member stopped before it admitted the joiner");
    let (ack, wait) = tokio::sync::oneshot::channel();
    if tx
        .send(NetEvent::SeatReserve {
            channel_id,
            joiner,
            ack,
        })
        .await
        .is_err()
    {
        return Err(stopped());
    }
    let (epoch, members) = wait.await.unwrap_or_else(|_| Err(stopped()))?;
    let question = Ask {
        channel_id,
        epoch,
        joiner,
    };
    let mut asking = tokio::task::JoinSet::new();
    for (member, conn) in members {
        asking.spawn(async move { (member, ask(&conn, question).await) });
    }
    let mut promised = Vec::new();
    let (mut full, mut taken, mut unagreed): (Option<u64>, bool, Option<(Digest32, bool)>) =
        (None, false, None);
    let mut said = Vec::new();
    while let Some(done) = asking.join_next().await {
        let Ok((member, asked)) = done else { continue };
        let who = crate::node::network::short_id(member);
        match asked {
            Asked::Answered(Answer::Yes, send) => promised.push(send),
            Asked::Answered(Answer::Full { members }, _) => {
                said.push(format!("{who}: full at {members}"));
                full = Some(full.unwrap_or(0).max(members));
            }
            Asked::Answered(Answer::Taken, _) => {
                said.push(format!(
                    "{who}: its last place is promised to another newcomer"
                ));
                taken = true;
            }
            Asked::Answered(Answer::NotHeld, _) => {
                said.push(format!(
                    "{who}: does not count this node a member of the room yet"
                ));
                unagreed.get_or_insert((member, false));
            }
            Asked::Gone => {
                // Offline: its process is not there. It blocks nothing, and learns of the
                // newcomer from a board when it returns.
                said.push(format!(
                    "{who}: offline (nothing heard from it in {}s), not counted",
                    crate::node::seatstream::SILENT_IS_GONE.as_secs()
                ));
            }
            Asked::Refused => {
                // Not holding the room yet, or not counting this node a member yet: it has
                // promised nothing this node would miss.
                said.push(format!(
                    "{who}: refused the question (not yet in the room there), not counted"
                ));
            }
            Asked::Unanswered => {
                said.push(format!(
                    "{who}: no answer within {}s",
                    crate::node::seatstream::SEAT_ANSWER_WITHIN.as_secs()
                ));
                unagreed.get_or_insert((member, true));
            }
        }
    }
    let refusal = match (full, taken, unagreed) {
        (Some(members), _, _) => Some(Error::RoomFull { members }),
        (None, true, _) => Some(Error::SeatTaken),
        (None, false, Some((member, unanswered))) => {
            Some(Error::SeatNotAgreed { member, unanswered })
        }
        (None, false, None) => None,
    };
    let Some(refusal) = refusal else {
        return Ok(promised);
    };
    eprintln!(
        "vox: a newcomer to room {} was not admitted — not every member agreed: {}",
        crate::node::network::short_id(channel_id),
        said.join("; ")
    );
    for send in promised {
        abort(send, Abort { channel_id, joiner }).await;
    }
    let _ = tx.send(NetEvent::SeatRelease { channel_id, joiner }).await;
    Err(refusal)
}

/// The room's epoch, and the members to ask for a newcomer's place, each with its connection.
type SeatsToAsk = (u64, Vec<(Digest32, Arc<VoxConnection>)>);

/// A place promised in a room to a newcomer (V030-30, #366): by whom it was asked, this node or
/// another member, and until when it counts.
#[derive(Debug, Clone, Copy)]
struct SeatPromise {
    /// The member that asked; this node's own fingerprint for a place it holds itself.
    from: Digest32,
    /// When it stops counting, unless the newcomer is an author by then.
    until: std::time::Instant,
}

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
const PUBLISH_REFUSAL_GRACE_MS: u64 = 60_000;

/// How long this node's own record refused as stale goes unreported: long enough for the republish
/// past the next second (`NetEvent::RepublishTo`) to land, short enough that a refusal it does not
/// cure is named while somebody is still looking.
const STALE_REFUSAL_GRACE_MS: u64 = 5_000;

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
    /// The node's [`secret_blocking`] guard: the seal's Argon2id runs under it.
    secret_work: Arc<tokio::sync::RwLock<()>>,
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
    fn append(&mut self, other: JoinSteps) {
        self.0.extend(other.0);
    }
    fn render(&self) -> String {
        self.0.join(", ")
    }
}

impl Joiner {
    /// A board holding the room, when the boards in `tried` — starting with the one
    /// `reach_a_board` chose — had nothing for it, could not be read, or took no pre-join record:
    /// every other board the join's routes name, asked at once, and the first that holds it.
    ///
    /// **A board that does not hold the room is not a malformed address.** The link parsed and
    /// named a room; a board we reached has nothing for it. That is a room its host has not
    /// published there yet, or a room id mistyped into another valid one (a link carries no
    /// checksum), and the board cannot tell which. The join used to stop at the first such board,
    /// while the link named others — the host's own last, which always holds its room (V210-96).
    /// Only when none has it does the join fail — with `fault`, what the first board's failure
    /// meant — and then it names every board it asked and what each said (`why` carries what the
    /// boards in `tried` said), so the person can check each and the room. The same holds when the
    /// first board could not be read or took no pre-join record (C2): a board that failed is not
    /// the room failing, while the link names a host that holds it.
    async fn another_board_with_the_room(
        &self,
        tried: &std::collections::BTreeSet<Digest32>,
        mut why: Vec<String>,
        fault: Fault,
        steps: &mut JoinSteps,
    ) -> std::result::Result<(Arc<VoxConnection>, crate::nat::service::RecordSet), JoinerLost> {
        use crate::node::network::short_id;
        let room = self.parsed.channel_id;
        let t = std::time::Instant::now();
        self.begin(format!(
            "asking the address's other boards for room {}",
            short_id(room)
        ));
        let mut asked = tokio::task::JoinSet::new();
        let mut seen = tried.clone();
        for (at, (id, endpoints)) in self.routes.iter().enumerate() {
            if !seen.insert(*id) {
                continue;
            }
            let (net, tx, id, endpoints) = (
                Arc::clone(&self.net),
                self.tx.clone(),
                *id,
                endpoints.clone(),
            );
            asked.spawn(async move {
                let said = match Self::dial_with(&net, &tx, id, &endpoints, true).await {
                    Err(e) => Err(format!("board {} was not reached: {e}", short_id(id))),
                    Ok(conn) => match net.fetch_channel(&conn, &room, 0).await {
                        Err(e) => Err(match went_offline(&conn) {
                            Some(how) => format!(
                                "board {} went offline as the room was read: {how}",
                                short_id(id)
                            ),
                            None => format!("board {} could not be read: {e}", short_id(id)),
                        }),
                        Ok(set) if set.genesis.is_none() => Err(match set.ended_by {
                            Some(by) => format!(
                                "board {} says room {} has ended: {} ended it",
                                short_id(id),
                                short_id(room),
                                short_id(by)
                            ),
                            None => format!(
                                "board {} has nothing for room {}",
                                short_id(id),
                                short_id(room)
                            ),
                        }),
                        Ok(set) => Ok((conn, set)),
                    },
                };
                (at, said)
            });
        }
        let mut others: Vec<(usize, String)> = Vec::new();
        while let Some(done) = asked.join_next().await {
            match done {
                Ok((_, Ok(found))) => {
                    steps.took("another board", t);
                    return Ok(found);
                }
                Ok((at, Err(said))) => others.push((at, said)),
                Err(_) => {} // a task that panicked: nothing to take
            }
        }
        others.sort();
        why.extend(others.into_iter().map(|(_, said)| said));
        steps.took("the other boards (none held the room)", t);
        // A board that took the room off at its end says so (V030-14): that is the answer, not a
        // room nobody published.
        let ended = why.iter().any(|w| w.contains(" has ended: "));
        Err(JoinerLost {
            fault: if ended { Fault::JoinedRoomEnded } else { fault },
            why,
            steps: JoinSteps::default(),
        })
    }

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
            if tokio::time::Instant::now() >= deadline || self.no_way_to_a_board() {
                return None;
            }
            tokio::time::sleep(Node::BOARD_RETRY).await;
        }
    }

    /// **No way to any board, and none can appear** (#414): no route names an address this
    /// node's socket can dial, and nobody could carry a circuit — no connection, no dial under
    /// way, no anchor known. A link's places are fixed for the join, so waiting out
    /// [`Node::BOARD_PATIENCE`] could only end the same way: a guest on a routable IPv6 address
    /// given only `[::1]` waited 30 s and was told the host "did not answer", having asked
    /// nothing.
    fn no_way_to_a_board(&self) -> bool {
        let manager = self.net.manager();
        self.routes.iter().all(|(_, endpoints)| {
            crate::nat::reachability::dialable_candidates(
                manager.endpoint(),
                &crate::nat::reachability::direct_candidates(endpoints),
            )
            .is_empty()
        }) && manager.peers().is_empty()
            && !manager.any_direct_dial_under_way()
            && self.net.policy().snapshot().anchor_count() == 0
    }

    /// Every board this join tried, each named as the room's host or an anchor, with the
    /// addresses it was dialled at — for a person whose join reached none (V210-107). The words
    /// for that failure blamed "the anchor" and sent them to `vox node`, when the link of a host
    /// with no anchor names only the host.
    fn boards_tried(&self) -> String {
        self.routes
            .iter()
            .map(|(id, endpoints)| {
                let who = if self.parsed.responder == Some(*id) {
                    "the room's host"
                } else {
                    "anchor"
                };
                let at: Vec<String> = endpoints.addrs().iter().map(ToString::to_string).collect();
                let at = if at.is_empty() {
                    "its open connection".to_owned()
                } else {
                    at.join(", ")
                };
                format!("{who} {} at {at}", crate::node::network::short_id(*id))
            })
            .collect::<Vec<_>>()
            .join("; ")
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

    /// One search for a board that holds the room: reach a board, read the room from it, and ask
    /// the address's other boards if it has nothing (V210-96). The board found, what it holds, and
    /// every board tried. See [`Self::run_steps`] for why a search that finds the room on no board
    /// is repeated.
    async fn a_board_with_the_room(
        &self,
        steps: &mut JoinSteps,
    ) -> std::result::Result<
        (
            Arc<VoxConnection>,
            crate::nat::service::RecordSet,
            std::collections::BTreeSet<Digest32>,
        ),
        JoinerLost,
    > {
        let parsed = &self.parsed;
        let net = Arc::clone(&self.net);
        let t = std::time::Instant::now();
        self.begin(format!("reaching a board ({} route(s))", self.routes.len()));
        // **Which side was unreachable is part of the answer (#192).** A board that never answered,
        // or stopped answering while it was read, is `BoardUnreachable`; `Unreachable` below is
        // kept for a join whose board answered and whose members did not.
        let Some(board) = self.reach_a_board().await else {
            steps.took("board (unreached)", t);
            // Asked nobody: not "no answer", but why it could not ask (#414).
            let why = if self.no_way_to_a_board() {
                let local = self
                    .net
                    .manager()
                    .endpoint()
                    .local_addr()
                    .map_or_else(|_| "?".to_owned(), |a| a.to_string());
                format!(
                    "this node's socket ({local}) cannot send to any address the link gives — {} \
                     — and no anchor or member is connected to carry a circuit",
                    self.boards_tried()
                )
            } else {
                format!("no answer from {}", self.boards_tried())
            };
            return Err(JoinerLost {
                fault: Fault::BoardUnreachable,
                why: vec![why],
                steps: JoinSteps::default(),
            });
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
        // **A board that does not hold the room, or could not be read, is not the last word**
        // (V210-96): the link names others, the host's own board among them, and the host always
        // holds its room. So they are asked too before the join gives up; see
        // `another_board_with_the_room`.
        let short = crate::node::network::short_id;
        let tried: std::collections::BTreeSet<Digest32> = [board.peer_id()].into();
        let found = match fetched {
            Ok(set) if set.genesis.is_some() => (board, set),
            Ok(set) => {
                let why = vec![match set.ended_by {
                    Some(by) => format!(
                        "board {} says room {} has ended: {} ended it",
                        short(board.peer_id()),
                        short(parsed.channel_id),
                        short(by)
                    ),
                    None => format!(
                        "board {} has nothing for room {}",
                        short(board.peer_id()),
                        short(parsed.channel_id)
                    ),
                }];
                self.another_board_with_the_room(&tried, why, Fault::RoomNotOnBoard, steps)
                    .await?
            }
            Err(e) => {
                let fault = on_the_board(fault_of(&e));
                let who = if parsed.responder == Some(board.peer_id()) {
                    "the room's host"
                } else {
                    "anchor"
                };
                // **A board that stopped as it was read went offline; it did not answer** (#406).
                // A daemon finishes a node's stop after its last client has gone, and a join that
                // reached the node in that moment saw it answer and then close: "the room's host
                // answered, then its connection closed … run the join again", with every board
                // still up saying it had nothing for the room. The host had gone offline, which
                // is what leaves a room unpublished where a joiner looks; so it counts as a board
                // not reached, and the boards that were reached decide the answer.
                let offline = went_offline(&board);
                // #302's wording, which `tunnel_cli::board_unreachable_advice` reads: a board that
                // answered and then closed before the room was fetched.
                let why = vec![match &offline {
                    Some(how) => format!(
                        "{who} {} went offline as the room was read: {how}",
                        short(board.peer_id())
                    ),
                    None if fault == Fault::BoardUnreachable => format!(
                        "{who} {} answered, then its connection closed before the room was \
                         fetched: {e}{}",
                        short(board.peer_id()),
                        board
                            .quinn()
                            .close_reason()
                            .map(|c| format!(" ({})", crate::transport::quic::closed_text(&c)))
                            .unwrap_or_default()
                    ),
                    None => format!("board {} could not be read: {e}", short(board.peer_id())),
                }];
                self.another_board_with_the_room(&tried, why, fault, steps)
                    .await
                    .map_err(|mut lost| {
                        if offline.is_some()
                            && lost.fault == Fault::BoardUnreachable
                            && lost
                                .why
                                .iter()
                                .any(|w| w.contains(" has nothing for room "))
                        {
                            lost.fault = Fault::RoomNotOnBoard;
                        }
                        lost
                    })?
            }
        };
        Ok((found.0, found.1, tried))
    }

    async fn run_steps(&self, steps: &mut JoinSteps) -> std::result::Result<JoinerWon, JoinerLost> {
        let parsed = &self.parsed;
        let net = Arc::clone(&self.net);
        // **A board with nothing for the room is not the last word while the join has patience
        // left (V210-143).** A host publishes its room to its anchor moments after it starts, and
        // a guest that asks first — or a host whose first dial to its anchor failed and is tried
        // again a second later — found every board empty and was told "cannot join" in half a
        // second. Through a relay that is the only path, the circuit to the host is refused too:
        // an anchor carries circuits for a room's pending joiners, which it can only know once it
        // holds the room, and it refuses anyone else uninformatively (`0x05`), as it must. So while
        // every board the join reached says it has nothing for the room, the join asks again, for
        // as long as a join waits for a board ([`Node::BOARD_PATIENCE`]), and says what it is
        // waiting for. Any other answer ends the search as before.
        //
        // **The first search's steps and the last's, not every search's** (#406): the steps of
        // every search were kept, so a join that waited out its patience printed thirty copies of
        // "board 0.00s, fetch 0.00s, the other boards …" as its steps. The first search says how
        // long reaching a board took, the searches between are one step, and the last search's
        // steps say how it ended.
        let started = std::time::Instant::now();
        let mut searches = 0_u32;
        let mut first_done = started;
        let (mut board, mut set, mut tried) = loop {
            let mut search = JoinSteps::default();
            let t = std::time::Instant::now();
            let found = self.a_board_with_the_room(&mut search).await;
            let retry = matches!(&found, Err(lost) if lost.fault == Fault::RoomNotOnBoard
                && started.elapsed() + ROOM_RETRY < Node::BOARD_PATIENCE);
            if searches == 0 {
                steps.append(search);
                first_done = std::time::Instant::now();
            } else if !retry {
                if searches > 1 {
                    steps.lasted(
                        &format!("asked {} time(s) more", searches - 1),
                        t.saturating_duration_since(first_done),
                    );
                }
                steps.append(search);
            }
            searches += 1;
            match found {
                Ok(found) => break found,
                Err(_) if retry => {
                    self.begin(format!(
                        "waiting: no board this address names holds room {} yet — its host has \
                         not published it there; asking again (up to {}s)",
                        crate::node::network::short_id(parsed.channel_id),
                        Node::BOARD_PATIENCE.as_secs()
                    ));
                    tokio::time::sleep(ROOM_RETRY).await;
                }
                Err(lost) => return Err(lost),
            }
        };
        let short = crate::node::network::short_id;
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
        // A board that takes no pre-join record is another board's turn too (C2).
        let mut refused: Vec<String> = Vec::new();
        loop {
            let t = std::time::Instant::now();
            self.begin(format!(
                "announcing this joiner to board {}",
                short(board.peer_id())
            ));
            let Err(e) = announce(&board, &prejoin_wire).await else {
                break;
            };
            steps.took("announce to the board (failed)", t);
            refused.push(format!(
                "board {} took no pre-join record: {e}",
                short(board.peer_id())
            ));
            tried.insert(board.peer_id());
            let fault = on_the_board(fault_of(&e));
            (board, set) = self
                .another_board_with_the_room(&tried, refused.clone(), fault, steps)
                .await?;
        }
        let Some(genesis) = set.genesis.clone() else {
            return Err(JoinerLost::of(Fault::RoomNotOnBoard));
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
            // **The link's own address for it first** (V210-96, C7): the link names the host and
            // where to reach it, and a board with no current address record for it sent the join
            // to poll that board for up to `JOIN_ADDRESS_PATIENCE` instead. The board is asked
            // only if that address fails.
            let mut linked: Option<Arc<VoxConnection>> = None;
            if responder_endpoints.is_empty() && board.peer_id() != responder {
                if let Some((_, from_link)) = self
                    .routes
                    .iter()
                    .find(|(id, e)| *id == responder && !e.is_empty())
                {
                    let t = std::time::Instant::now();
                    self.begin(format!("dialling member {short} at the link's address"));
                    match self.dial(responder, from_link, false).await {
                        Ok(c) => {
                            steps.took(&format!("{short}: dial (the link's address)"), t);
                            linked = Some(c);
                        }
                        Err(e) => {
                            steps.took(&format!("{short}: dial (the link's address, failed)"), t);
                            why.push(format!("{short}: the link's address: {e}"));
                        }
                    }
                }
            }
            if linked.is_none() && responder_endpoints.is_empty() && board.peer_id() != responder {
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
                let dialled = match linked {
                    Some(c) => Ok(c),
                    None => {
                        let t = std::time::Instant::now();
                        self.begin(format!("dialling member {short}"));
                        let dialled = self.dial(responder, &responder_endpoints, false).await;
                        steps.took(&format!("{short}: dial"), t);
                        dialled
                    }
                };
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
            // **Which path the join rode** (V210-124): said with its timings, so a person — and a
            // proof that must know whether an anchor carried it — can tell a direct join from one
            // relayed through an anchor, which a timing alone does not say.
            steps.note(format!(
                "{short}: {}",
                if conn.via_circuit() {
                    "relayed"
                } else {
                    "direct"
                }
            ));
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
        // on a blocking thread and not the actor. That thread gets the passphrase and nothing
        // else (V210-94): the identity half of the key is taken here, where a lock's abort
        // reaches, and so is the SEK.
        let sek = crate::atrest::sek::Sek::generate().map_err(|e| JoinerLost::of(fault_of(&e)))?;
        let factor_id = id_factor_for(&self.signer, &parsed.channel_id)
            .map_err(|e| JoinerLost::of(fault_of(&e)))?;
        let (passphrase, argon2) = (self.passphrase.clone(), self.argon2);
        let t = std::time::Instant::now();
        self.begin("sealing the room key under the passphrase".to_owned());
        let sealed = seal_off_actor(&self.secret_work, &factor_id, sek, passphrase, argon2)
            .await
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
/// How `conn`'s peer went offline, if its connection ended because the peer stopped or no longer
/// holds the node it was dialled for: it said it was stopping (V210-93), it closed with
/// [`crate::wire::WireError::ShuttingDown`], or its daemon answered
/// [`crate::wire::WireError::NotAvailable`] (ADR-011: the node is not attached there). `None` for
/// a connection still open, or one that ended any other way.
fn went_offline(conn: &VoxConnection) -> Option<String> {
    use crate::wire::WireError;
    if conn.peer_stopped() {
        return Some("it said it was stopping".to_owned());
    }
    match conn.quinn().close_reason()? {
        quinn::ConnectionError::ApplicationClosed(close) => {
            match u8::try_from(close.error_code.into_inner())
                .ok()
                .and_then(WireError::from_code)?
            {
                WireError::ShuttingDown => Some("it stopped".to_owned()),
                WireError::NotAvailable => Some("its node is not there (not available)".to_owned()),
                _ => None,
            }
        }
        _ => None,
    }
}

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
            // Every member holds the same room: another would refuse it as full too.
            | Fault::RoomFull
            // Another member counts the same places, and asks the same members (V030-30).
            | Fault::SeatTaken
            | Fault::SeatNotAgreed
            // Every member of an ended room says the same (V030-08).
            | Fault::JoinedRoomEnded
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
    /// The app layer (ADR-022 decision 7).
    app: Arc<crate::node::app::AppHub>,
    /// Where status requests go (PRD-001 R35).
    status_tx: mpsc::Sender<oneshot::Sender<crate::node::status::StatusReport>>,
    /// The node's network queue, for the requests that go straight onto it: naming and
    /// the all-rooms proxy.
    net_tx: mpsc::Sender<NetEvent>,
    /// The sync counters `vox status --json` reports (ADR-025 S0b).
    sync_book: crate::node::status::SharedSyncBook,
    /// When the identity passphrase was last entered, shared with the actor, and the actor's
    /// clock: how long the keyring window has left (ADR-028 K-9).
    keyring: KeyringWindow,
    /// The files this node serves (ADR-028 F-2).
    shares: Arc<crate::node::shares::Shares>,
    /// Where the node's files are: its sessions' registrations among them (ADR-029 MD-2).
    paths: Paths,
}

/// When the identity passphrase was last entered, shared with the actor, and the actor's clock.
#[derive(Clone)]
struct KeyringWindow {
    entered: Arc<std::sync::atomic::AtomicU64>,
    clock: Clock,
}

impl std::fmt::Debug for KeyringWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyringWindow").finish_non_exhaustive()
    }
}

impl NodeHandle {
    /// Where the node's files are.
    #[must_use]
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// The files this node shares and serves (ADR-028 F-1, F-2).
    #[must_use]
    pub fn shares(&self) -> &Arc<crate::node::shares::Shares> {
        &self.shares
    }

    /// How many seconds a keyring change still goes without the identity passphrase, or `None`
    /// when the next one will ask for it (ADR-028 K-9, V210-159).
    #[must_use]
    pub fn keyring_open_secs(&self) -> Option<u64> {
        let KeyringWindow { entered, clock } = &self.keyring;
        keyring_left(entered.load(std::sync::atomic::Ordering::Relaxed), clock())
    }

    /// The sync counters `vox status --json` reports (ADR-025 S0b).
    #[must_use]
    pub fn sync_book(&self) -> &crate::node::status::SharedSyncBook {
        &self.sync_book
    }

    /// The app API (ADR-022 decision 7): listen for, accept and open app streams to
    /// programs on other member nodes. The in-process form of IPC protocol 6.
    #[must_use]
    pub fn app(&self) -> &Arc<crate::node::app::AppHub> {
        &self.app
    }

    /// What the node is doing and whether it is well (PRD-001 R35): rooms, peers and
    /// their paths, tunnels, datagram and app counters, and what needs attention.
    ///
    /// # Errors
    /// If the node has stopped.
    pub async fn status(&self) -> crate::error::Result<crate::node::status::StatusReport> {
        let (tx, rx) = oneshot::channel();
        self.status_tx
            .send(tx)
            .await
            .map_err(|_| crate::error::Error::Unreachable("the node has stopped"))?;
        rx.await
            .map_err(|_| crate::error::Error::Unreachable("the node has stopped"))
    }

    /// The Session entries this node can read in a room (ADR-029 SC-2): its own, and each node's
    /// that released it its drive key; `None` if the room is not open.
    pub async fn session_rows(
        &self,
        channel_id: Digest32,
    ) -> Option<Vec<crate::node::drive::SessionRow>> {
        let (reply, rx) = oneshot::channel();
        self.net_tx
            .send(NetEvent::SessionRows { channel_id, reply })
            .await
            .ok()?;
        rx.await.ok()?
    }

    /// Resolve a `.vox` name against this node's rooms and keyring (PRD-001 R20): the
    /// room and the member it leads to, or a sentence saying why it leads nowhere.
    ///
    /// # Errors
    /// The reason, for this machine's operator.
    pub async fn resolve_name(
        &self,
        name: &str,
    ) -> std::result::Result<crate::node::resolver::ServiceRoom, String> {
        NodeNames {
            net_tx: self.net_tx.clone(),
        }
        .resolve(name)
        .await
    }

    /// Say a note of the daemon's proxy (ADR-028 S-5) as this node's event, as the node's own
    /// proxy did: a refusal or a deliberate close, which the TUI, the app, `vox up --watch` and
    /// the decision record take like any other event.
    pub fn proxy_note(&self, note: crate::node::tunnel::TunnelNote) {
        let _ = self.event_tx.send(note_event(note));
    }

    /// Say that a tunnel the daemon's proxy carried into `channel_id` was cut because the host
    /// withdrew this node's reach to `port` (ADR-017 M17.11), as this node's event.
    pub fn proxy_reach_withdrawn(&self, channel_id: Digest32, port: u16) {
        let _ = self
            .event_tx
            .send(NodeEvent::ReachWithdrawn { channel_id, port });
    }

    /// This node's way of reaching a member of one of its rooms, for the daemon's proxy
    /// (ADR-028 S-5), which carries every attached node's rooms on one port and dials through
    /// the node that holds the room a name resolved to.
    ///
    /// # Errors
    /// If the node has stopped or is not networked.
    pub async fn member_dialer(&self) -> crate::error::Result<MemberDialer> {
        let (reply, rx) = oneshot::channel();
        self.net_tx
            .send(NetEvent::MemberDialer(reply))
            .await
            .map_err(|_| crate::error::Error::Unreachable("the node has stopped"))?;
        rx.await
            .map_err(|_| crate::error::Error::Unreachable("the node has stopped"))?
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

    /// The services shared in an open room (V030-25): each address readable, as **this** node
    /// writes it — its own aliases for the node and the room where it has them, the fingerprints
    /// where it has not — and canonical (ADR-028 S-1), with its sharer as this node names them,
    /// and whether the sharer trusts this node and is reachable now (ADR-028 S-3); or `None` if
    /// the room is not open.
    pub async fn shared_in(
        &self,
        channel_id: Digest32,
    ) -> Option<Vec<crate::node::ipc::SharedService>> {
        let detail = self.open_detail(channel_id).await?;
        let (tx, rx) = oneshot::channel();
        self.net_tx.send(NetEvent::Names(tx)).await.ok()?;
        let names = rx.await.ok()?;
        let (me, connected) = {
            let view = self.view_rx.borrow();
            (
                view.identity.as_ref().map(|i| i.fingerprint),
                view.connected_peers.clone(),
            )
        };
        Some(
            detail
                .shares
                .iter()
                .map(|s| {
                    let who = if Some(s.host) == me {
                        "you".to_owned()
                    } else {
                        names.alias_of(&s.host)
                    };
                    crate::node::ipc::SharedService {
                        address: names.address_of(&channel_id, &s.host, &s.name),
                        canonical: crate::node::resolver::canonical_address(
                            &channel_id,
                            &s.host,
                            &s.name,
                        ),
                        by: who,
                        udp: s.udp,
                        kind: s.kind.as_str().to_owned(),
                        // Off the room's log: the sharer consents to this node reading it, which
                        // its node does for a member it trusts (ADR-020 §3).
                        trusts_you: Some(s.host) == me || detail.consenting.contains(&s.host),
                        online: Some(s.host) == me || connected.contains(&s.host),
                    }
                })
                .collect(),
        )
    }

    /// A room's detail, or `None` if this node does not hold the room open (V210-149).
    ///
    /// A room the view counts as open can still be missing its detail for a moment: the view
    /// keeps a room's previous detail while a sync session holds its lock, and a room just opened
    /// has none yet. So that case waits, up to two seconds, for a view that carries
    /// it, rather than calling an open room "not open".
    pub async fn open_detail(&self, channel_id: Digest32) -> Option<ChannelDetail> {
        let mut rx = self.view_rx.clone();
        let deadline = tokio::time::Instant::now() + OPEN_DETAIL_PATIENCE;
        loop {
            {
                let view = rx.borrow_and_update();
                if let Some(d) = view
                    .open_channels
                    .iter()
                    .find(|d| d.channel_id == channel_id)
                {
                    return Some(d.clone());
                }
                if !view
                    .channels
                    .iter()
                    .any(|c| c.channel_id == channel_id && c.open)
                {
                    return None;
                }
            }
            match tokio::time::timeout_at(deadline, rx.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => return None,
            }
        }
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
    /// The presence the network runs on, and whether this node made it for itself (a solo
    /// presence, closed with the node) rather than attached to the daemon's.
    presence: Option<(Arc<crate::node::presence::NetPresence>, bool)>,
    /// Sender the actor keeps so the network queue never closes under it.
    net_tx: mpsc::Sender<NetEvent>,
    /// Where the endpoint binds, if this node networks at all.
    bind: Option<Bind>,
    /// The headless transport identity, if this node runs without a vault.
    headless: Option<Arc<crate::identity::composite::SoftwareRootSigner>>,
    /// See [`NodeConfig::anchor_boards`].
    anchor_boards: bool,
    /// See [`NodeConfig::serve_only`].
    serve_only: Option<BTreeSet<Digest32>>,
    /// Live forwards by their bound local address (ADR-013 Dial, M16.1). Dropping one
    /// stops its listener.
    forwards: BTreeMap<std::net::SocketAddr, crate::node::tunnel::Forward>,
    /// The anchors, if any, that bridge this node to peers it cannot reach directly
    /// (ADR-012, ADR-016 M15.1): dialled when the network starts, given the `Anchor`
    /// class, published to, and named in invite links beside this node's own addresses.
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
    /// The task telling this node each new composition of its presence's addresses.
    addresses_task: Option<tokio::task::AbortHandle>,
    /// The task telling this node each real change of the machine's network (ADR-012 N-51).
    changes_task: Option<tokio::task::AbortHandle>,
    /// Per anchor that failed to connect: when it may be dialled again (unix milliseconds), and
    /// the wait in milliseconds that set it, doubling to [`ANCHOR_REDIAL_MS`] (V210-57). No entry: dial when
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
    /// When each anchor's current connection was made (unix milliseconds), with that connection's
    /// serial, so one lost soon after is told from one lost after a while ([`ANCHOR_FLAP_MS`]).
    anchor_connected_at: BTreeMap<Digest32, (u64, u64)>,
    /// The connection held to each anchor at the last look, so losing one is said when it
    /// happens, not only when it is next redialled (#229's diagnostics). The connection, not
    /// only the anchor: one lost and replaced between two looks is still a loss (V210-93).
    anchors_up: BTreeMap<Digest32, Arc<VoxConnection>>,
    /// Per anchor this node keeps and did not hold a connection to at the last look: since when
    /// (unix milliseconds). What `vox status` and the notifier read (PRD-001 R37).
    anchor_unreached_since: BTreeMap<Digest32, u64>,
    /// Peers a room's sync is dialling right now (`reach_for_sync`), so one is not dialled twice.
    sync_dials: BTreeSet<Digest32>,
    /// When each open room's own records are next renewed on this node's board and its anchors
    /// (V210-68, #258): half their lifetime after the last round that signed them (unix
    /// milliseconds).
    records_renew_at: BTreeMap<Digest32, u64>,
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
    /// When the periodic request (ADR-025 D7) is next raised on every port, unix milliseconds.
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
    /// When we first saw a still-uncured refusal of one of **our own** records (unix
    /// milliseconds).
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
    /// refuses the same record [`PUBLISH_REFUSAL_GRACE_MS`] later. A join that cures itself
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
    join_slots: Arc<std::sync::Mutex<crate::node::joinslots::JoinSlots>>,
    /// Slots for identity-passphrase checks; see [`VERIFIES_IN_FLIGHT`].
    verify_slots: Arc<tokio::sync::Semaphore>,
    /// When the identity passphrase was last entered, in this node's clock's milliseconds: at
    /// creation, at unlock, or at a later check that passed. Zero while locked. A keyring change
    /// is refused once [`keyring_window_ms`] has passed since (V210-159). Shared, because a check
    /// passes on a blocking thread.
    passphrase_entered_at: Arc<std::sync::atomic::AtomicU64>,
    /// Set while a [`NodeCommand::Proved`] keyring change is applied: its passphrase was just
    /// checked, so the keyring window does not apply to it (V210-159).
    keyring_change_proved: bool,
    /// The join exchanges running right now, both sides of them, the room creations sealing
    /// their key (V210-76), and the identity-passphrase checks (V210-94).
    ///
    /// Tracked rather than detached for one reason: each holds an `Arc<VaultRootSigner>`, and
    /// ADR-015 says a locked node holds no identity secrets. [`Node::lock_all`] aborts this set,
    /// so the last handle goes with the lock and "locked" keeps meaning *now* instead of *once
    /// this joiner gets bored*.
    join_tasks: tokio::task::JoinSet<()>,
    /// **Places promised in each room** (V030-30, #366), `(room, newcomer)` → who asked and until
    /// when: this node's own, held while it asks the others, and those it promised a member that
    /// asked. Each counts against the room's cap until the newcomer is an author here, an abort
    /// frees it, or it expires (`seatstream::PROMISE_TTL`).
    seat_promises: BTreeMap<(Digest32, Digest32), SeatPromise>,
    /// Held for reading by every blocking thread that holds a secret ([`secret_blocking`]), and
    /// taken for writing by [`Node::lock_all`], which so waits for each to finish and wipe what
    /// it was given: an abort cannot stop a blocking thread (V210-94).
    secret_work: Arc<tokio::sync::RwLock<()>>,
    /// The sync counters `vox status --json` reports (ADR-025 S0b).
    sync_book: crate::node::status::SharedSyncBook,
    /// Rooms this node is joining right now (their join is on a `Joiner` task).
    joining: std::collections::BTreeSet<Digest32>,
    /// Joins this node answered, `(room, joiner)`, and when: until the joiner's first clean
    /// session, or [`JOINER_SEAL_GRACE`], a session with it that fails is the join still settling,
    /// not a failed sync, and is not reported (#406).
    joins_answered: BTreeMap<(Digest32, Digest32), std::time::Instant>,
    /// Rooms being reopened off the actor at unlock (#208). A room leaves this set when it is
    /// held, closed, or the identity locks; a reopened room not in it is dropped, not held.
    reopening: std::collections::BTreeSet<Digest32>,
    /// The reopening task, aborted at lock: it holds room keys, and a locked node holds none
    /// (ADR-015).
    reopen_task: Option<tokio::task::JoinHandle<()>>,
    /// Unlock replies held until the reopening has finished (#208).
    unlock_waiters: Vec<oneshot::Sender<Outcome>>,
    /// Locks begun whose settling — the wait for work still holding a secret — has not reported
    /// back yet (`NetEvent::LockSettled`, V210-94). While any is, the node is *locking*: the
    /// identity is already locked and refuses new work, but not every secret is gone yet.
    locking: usize,
    /// Unlocks asked for while locking, run once it has settled: an unlock in between would
    /// start new work beside threads still holding the old secrets.
    unlock_after_lock: Vec<(Secret, oneshot::Sender<Outcome>)>,
    /// The last `refresh_network_view` gave up on a busy room, so the view is behind and the tick
    /// rebuilds it. Atomic only because the refresh takes `&self`.
    view_stale: std::sync::atomic::AtomicBool,
    /// A member gained or lost drive in the last command (ADR-028 K-14): this node's drive keys
    /// are released or changed before its answer (ADR-029 SC-2a, SC-2b). Atomic only because
    /// `note_capability` takes `&self`.
    drive_changed: std::sync::atomic::AtomicBool,
    /// Pairwise streams for a room still being joined, held until the join reports back: see
    /// `take_inbound_skdm`.
    held_pairwise: Vec<(Digest32, PairwiseIn)>,
    /// Each member's pairwise writer (V210-71): see `write_pairwise`.
    pairwise_out: BTreeMap<Digest32, mpsc::UnboundedSender<PairwiseJob>>,
    /// Per room, the members this node's board has held a bundle record for. A record from an
    /// author not in it is a member this node has just learned of, which is what
    /// `note_new_members` passes on at once; a refresh of a known member's record is not.
    board_authors: BTreeMap<Digest32, std::collections::BTreeSet<Digest32>>,
    /// `(room, board)` publish rounds in flight on their own tasks; see `publish_channel_to_anchor`.
    publishing: std::collections::BTreeSet<(Digest32, Digest32)>,
    /// Publishes asked for while that `(room, board)` round was in flight: run when it ends, and
    /// counted under the cause that asked first (several asks while one round runs are one round).
    publish_again: BTreeMap<(Digest32, Digest32), PublishCause>,
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
    /// `(room, board)` pairs whose last publish round left the board holding the room (`holds_room`),
    /// until it reconnects: the boards an address may name (V210-96; see `Node::begin_invite`).
    on_board: std::collections::BTreeSet<(Digest32, Digest32)>,
    /// What the last failed publish round to each `(room, board)` said, for an address withheld
    /// because of it (V210-96).
    publish_trouble: BTreeMap<(Digest32, Digest32), String>,
    /// Addresses asked for before their room was on a board they name, each with its wait's serial
    /// (V210-96): handed out by `PublishDone`, or withheld by `NetEvent::AddressWaitOver`.
    address_waiters: Vec<(Digest32, oneshot::Sender<Outcome>, u64)>,
    /// The serial of the last address wait begun.
    address_serial: u64,
    /// Leaves waiting for another member to take the departure (V210-164): the room, the room's
    /// generation once the departure was written, the reply while someone waits for one, and the
    /// wait's serial.
    leave_waiters: Vec<(Digest32, u64, Option<oneshot::Sender<Outcome>>, u64)>,
    /// The serial of the last leave begun.
    leave_serial: u64,
    /// `(room, anchor)` pairs an address was handed out naming before that anchor held the room,
    /// with the address's serial: said when the anchor takes it, or when [`ADDRESS_PATIENCE`]
    /// passes without (`NetEvent::AnchorNoteDue`) (V210-96).
    anchor_owed: BTreeMap<(Digest32, Digest32), u64>,
    /// When a background dial to each member was last started (unix milliseconds): see
    /// `reach_member`.
    member_dialed_at: BTreeMap<Digest32, u64>,
    /// Where this node says it listens on this computer and the local network, and hears others
    /// say so (V210-167; `node::nearby`). `None` for an anchor, or when the group cannot be
    /// joined.
    nearby: Option<Arc<crate::node::nearby::Nearby>>,
    /// The task hearing `nearby`, aborted when the network stops.
    nearby_task: Option<tokio::task::AbortHandle>,
    /// When this node next says where it listens, while a member is not connected (unix
    /// milliseconds).
    nearby_due: u64,
    /// How many rooms were held when it last said so: a room held since is said at once.
    nearby_rooms: usize,
    /// When each member heard on `nearby` was last dialled for it (unix milliseconds).
    nearby_dialed: BTreeMap<Digest32, u64>,
    /// Each room's view summary and detail as this node's own latest write left them, taken under the room's lock
    /// by the write itself. `view_of` uses it when a session holds the room, so a person always sees
    /// their own post in what they read straight after, however long that session holds on. A room's
    /// entry is removed once a view reads the room under its lock, since that read includes the
    /// write: an entry here is therefore always newer than the published one.
    fresh_details: BTreeMap<Digest32, (ChannelSummary, ChannelDetail)>,
    /// Per room, the entries shown to this node's person or drained into its agent's turn and not
    /// yet named by a read record of its own, and when it last posted one (ms): ADR-028 RR-2's
    /// "at most one per room per 5 seconds" ([`READ_RECORD_EVERY_MS`]).
    reads_pending: BTreeMap<Digest32, (BTreeSet<Digest32>, u64)>,
    /// What this node decided, kept on its disk for 14 days (ADR-028 §7).
    decisions: crate::node::decisions::DecisionLog,
    /// Rooms this node holds ended, passing the end on before it deletes them (V030-08).
    winding: BTreeMap<Digest32, Winding>,
    /// Rooms this node took off boards (V030-14) — left, or ended — with the signed withdraw, put
    /// again on every anchor that connects. Nothing of these rooms is published again.
    withdrawn: BTreeMap<Digest32, Vec<u8>>,
    /// Per room, the members that had left as of the last tend (V030-08), to see one come back.
    departed_seen: BTreeMap<Digest32, std::collections::BTreeSet<Digest32>>,
    /// Per `(room, member)`: consecutive keys not taken, and the unix millisecond before which the
    /// tick does not send it another. Without it, a pair that could not converge was sent a key
    /// once a tick for as long as both ran: 560 refusals in 3 minutes, measured.
    key_backoff: BTreeMap<(Digest32, Digest32), (u32, u64)>,
    /// Set when this node adopted a peer's session over its own (ADR-004 O3): what it owes that
    /// peer goes out as soon as the stream that carried the hello is answered, not on the tick.
    redeliver_now: bool,
    /// Per `(room, member)`: a member that has just handed over a generation new to us, so is
    /// offered ours again once its stream is answered (V210-118).
    reoffer: BTreeSet<(Digest32, Digest32)>,
    /// Per `(room, member)`: keys written and not yet answered (V210-88). In memory only, so a
    /// key cut off by a crash is owed again after the restart; see [`watch_delivery`].
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
    /// Per channel: the earliest `timestamp_ms` this process's next records may carry (V210-64). Moved
    /// forward, like `record_seq`, by a stale refusal; `record_timestamp` is the later of it and
    /// the clock.
    record_ts_floor: BTreeMap<Digest32, u64>,
    /// Pairwise ADR-004 sessions, keyed by `(channel, peer)` — a session is bound to
    /// a `(channelID, epoch)`, so one peer may have several. In memory for this
    /// process only: persisting ratchet state is not part of M14, so a restart
    /// re-establishes a session on the next join or key exchange.
    sessions: BTreeMap<(Digest32, Digest32), crate::pairwise::session::Session>,
    /// The sessions in [`Self::sessions`] that **this node opened**, and whether the
    /// peer has been sent the hello that lets it accept them (ADR-004 O2, O3).
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
    /// See [`NodeConfig::checkpoint_idle_secs`].
    checkpoint_idle_secs: u64,
    /// How long this node gives a tunnel whose bytes wait before closing it as stuck (V030-11),
    /// from its `tunnel-stuck-after` file: set on its endpoint's [`LocalNode`] at each start.
    ///
    /// [`LocalNode`]: crate::transport::quic::LocalNode
    stuck_after: Duration,
    argon2: Argon2Profile,
    view_tx: watch::Sender<NodeView>,
    event_tx: broadcast::Sender<NodeEvent>,
    /// The ADR-020 §3 trust keyring, loaded on unlock and empty while locked
    /// (it is sealed under the identity, so there is nothing to hold locked).
    trust: crate::node::trust::Keyring,
    /// Where each member was last reached directly (`node::peer_book`), so a restart can find
    /// them again with no anchor. Sealed under the identity: empty while locked.
    peer_book: crate::node::peer_book::PeerBook,
    /// This node's own retention (ADR-023 decision 2), re-read from the config directory
    /// at most every [`RETENTION_REREAD_MS`] so an edit takes effect without a restart.
    node_retention: crate::node::retention::RetentionConfig,
    /// When `node_retention` was last read (unix milliseconds); `0` before the first read.
    retention_read_at: u64,
    /// Open rooms whose node retention must be re-applied because the file changed; applied by
    /// the sweep as each room is free. A room gets its value when it is opened, so this only
    /// ever carries an edit.
    retention_dirty: std::collections::BTreeSet<Digest32>,
    /// The `(room, node value, room value)` triples this node has already said its own retention
    /// file asks for longer than the room keeps (V030-32): said once each, not every tick.
    retention_warned: std::collections::BTreeSet<(Digest32, u64, u64)>,
    /// Consents decided but not yet delivered, each with the key it releases, taken at the
    /// decision (V210-30). Kept beside the keyring, sealed the same way.
    consent_keys: crate::node::pending_consent::PendingConsents,
    /// When each peer was last tried for a better path (unix milliseconds), so a relayed connection is retried
    /// on a schedule rather than only at the moment it was made.
    last_upgrade: std::collections::BTreeMap<Digest32, u64>,
    /// The live reacher set per channel (M17.11), written here and read by serving tasks.
    /// Kept out of `Channel` because it is a *join* of channel state with the node-wide
    /// keyring, and the keyring is not a property of any one room.
    reachers: std::collections::BTreeMap<Digest32, crate::node::tunnel::Reachers>,
    /// Every UDP flow this node holds, as host or dialer (ADR-022 decision 6): what bounds
    /// them per peer and in all.
    udp_flows: Arc<crate::tunnel::udp::UdpFlows>,
    /// Each channel's live offer of services (PRD-001 R22), kept beside `reachers` and for
    /// the same reason: serving tasks hold these handles, so removing a service reaches
    /// the sessions it is carrying.
    offered: std::collections::BTreeMap<Digest32, crate::node::tunnel::Offered>,
    /// The app layer (ADR-022 decision 7), shared with every [`NodeHandle`].
    app: Arc<crate::node::app::AppHub>,
    /// What `vox status` keeps beside the node's own state (PRD-001 R35).
    status: crate::node::status::StatusBook,
}

/// The key a from-now-on consent releases to `target` in `channel_id`: the one taken when the
/// consent was decided and held since (V210-30), or, with none held for the room's current epoch,
/// one taken now and held. Every path that delivers a consent — the pairwise stream, and the
/// room's log when the member cannot be reached (ADR-023 M23.3) — delivers this same key.
fn held_consent_key(
    consent_keys: &mut crate::node::pending_consent::PendingConsents,
    profile: &Profile,
    channel: &ChannelState,
    channel_id: &Digest32,
    target: Digest32,
) -> crate::error::Result<crate::group::skdm::Skdm> {
    let held = consent_keys
        .get(channel_id, &target)
        .and_then(|w| crate::group::skdm::Skdm::from_wire(w).ok())
        .filter(|s| s.body.epoch == channel.epoch());
    if let Some(s) = held {
        return Ok(s);
    }
    let s = channel.skdm_for_consent(profile)?;
    // Past the bound nothing is held (V210-77): the key goes now if the member is reachable, and
    // is taken again when it is.
    if consent_keys.insert(*channel_id, target, s.to_wire()) {
        consent_keys.save(profile.store(), profile.signer()?)?;
    }
    Ok(s)
}

/// Every `(chain_id, iteration)` a consent releases, oldest first (V210-45).
type ReleasePlan = Vec<(u64, u64)>;

/// What a consent to `target` releases, and the key that goes to it now — **the same whichever
/// path carries it**, the pairwise stream or the room's log (V210-45, PRD-001 R12, #226): what a
/// member may read depends on when it was trusted, never on how its key travelled.
///
/// Returns the key to deliver now (the live generation) and the plan: every `(chain_id, iteration)`
/// the consent covers, oldest first, or `None` when it covers only the delivered key's own position.
/// The plan's first position is the member's entitlement; the generations before the live one are
/// owed as history and go out as their own deliveries.
///
/// - **Full history** (R12): every generation still held, each from its origin.
/// - Otherwise, **dated by the decision** (V210-45): every generation minted after the decision
///   whole, the one live at the decision from where it stood then, nothing older.
/// - With no plan (no recorded decision), **the key held since the consent was decided**
///   (V210-30).
fn consent_release(
    consent_keys: &mut crate::node::pending_consent::PendingConsents,
    profile: &Profile,
    channel: &ChannelState,
    channel_id: &Digest32,
    target: Digest32,
    full: bool,
    decision: Option<crate::node::consent_order::Stamp>,
) -> crate::error::Result<(crate::group::skdm::Skdm, Option<ReleasePlan>)> {
    if full {
        let mut all = channel.skdms_for_full_history(profile)?;
        let plan = all
            .iter()
            .map(|s| (s.body.chain_id, s.body.iteration))
            .collect();
        let live = all.pop().ok_or(crate::error::Error::MalformedAtRest(
            "a full-history grant with no live generation",
        ))?;
        return Ok((live, Some(plan)));
    }
    let plan = channel.history_plan(&target, decision);
    if let Some(&(live, from)) = plan.as_ref().and_then(|p| p.last()) {
        return Ok((channel.release_generation(profile, live, from)?, plan));
    }
    Ok((
        held_consent_key(consent_keys, profile, channel, channel_id, target)?,
        None,
    ))
}

/// Drop the key held for a consent, **before** the consent is recorded, never after: a key left on
/// disk would be delivered again after a revocation and a new consent (found in verification of
/// #203). An error means nothing was removed, and the consent must not be recorded.
fn forget_consent_key(
    consent_keys: &mut crate::node::pending_consent::PendingConsents,
    profile: &Profile,
    channel_id: &Digest32,
    target: Digest32,
) -> crate::error::Result<()> {
    if consent_keys.get(channel_id, &target).is_none() {
        return Ok(());
    }
    let mut next = consent_keys.clone();
    next.remove(channel_id, &target);
    next.save(profile.store(), profile.signer()?)?;
    *consent_keys = next;
    Ok(())
}

/// How a node's actor task ended (ADR-026 L-6), read from the handle
/// [`Node::spawn_supervised`] returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActorEnd {
    /// It stopped on its own: `Shutdown`, or every handle to it dropped.
    Stopped,
    /// It panicked; the panic's message, when it carried one.
    Panicked(String),
    /// Its task was cancelled: the runtime is shutting down.
    Cancelled,
}

impl ActorEnd {
    /// Wait for `actor` to end, and say how.
    pub async fn of(actor: tokio::task::JoinHandle<()>) -> Self {
        match actor.await {
            Ok(()) => Self::Stopped,
            Err(e) if e.is_panic() => {
                let payload = e.into_panic();
                Self::Panicked(
                    payload
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                        .unwrap_or_else(|| "(no message)".to_owned()),
                )
            }
            Err(_) => Self::Cancelled,
        }
    }
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
    /// one is a shorthand for. The actor's task is not watched; a host that must notice its
    /// node's end uses [`Node::spawn_supervised`].
    pub fn spawn_config(paths: Paths, cfg: NodeConfig) -> crate::error::Result<NodeHandle> {
        Self::spawn_supervised(paths, cfg).map(|(handle, _actor)| handle)
    }

    /// [`Node::spawn_config`], also returning the actor's task (ADR-026 L-6).
    ///
    /// **A node's panic must not vanish.** The actor runs as its own task; tokio catches a panic
    /// in it and, with the handle dropped, nobody hears of it: every later request fails with the
    /// node's queue closed and nothing says why. The host awaits this handle, and a
    /// `JoinError::is_panic` there is that node's end, to report and detach. The task ends with
    /// `Ok(())` when the actor stops on its own (`Shutdown`, or every handle dropped).
    pub fn spawn_supervised(
        paths: Paths,
        cfg: NodeConfig,
    ) -> crate::error::Result<(NodeHandle, tokio::task::JoinHandle<()>)> {
        let NodeConfig {
            clock,
            millis_clock,
            argon2,
            bind,
            pow_params,
            anchors,
            headless,
            anchor_boards,
            checkpoint_idle_secs,
            serve_only,
            on_profile_wait,
        } = cfg;
        let profile_wait = move || {
            if let Some(notice) = &on_profile_wait {
                notice();
            }
        };
        // A headless node networks as its key file and holds no room, so it never opens the
        // profile's vault — which a `vox node --serve trusted` profile has, to keep its trust
        // list. Opening it here held the store the anchor's own logs need, and the anchor
        // refused to start: "another vox already has this node open".
        let profile = if headless.is_none() && Profile::exists(&paths) {
            Some(Profile::open_noting(paths.clone(), &profile_wait)?)
        } else {
            None
        };
        // How long a stuck tunnel is given (V030-11), from the profile's config: the node's own,
        // kept for its endpoint (ADR-026 P-1).
        let stuck_after = paths
            .tunnel_stuck_after()
            .unwrap_or(crate::tunnel::session::STUCK_AFTER)
            .max(Duration::from_secs(1));
        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_QUEUE);
        let (event_tx, event_rx) = broadcast::channel(EVENT_QUEUE);
        // The handle keeps the sender so any number of clients may subscribe
        // later (ADR-020 §7); the actor keeps its own clone to emit with.
        let handle_event_tx = event_tx.clone();
        let (net_tx, net_rx) = mpsc::channel(NET_QUEUE);
        let decisions = crate::node::decisions::DecisionLog::new(&paths.profile_dir);
        let node = Self {
            paths,
            decisions,
            profile,
            millis_clock,
            checkpoint_idle_secs,
            stuck_after,
            net: None,
            presence: None,
            net_tx,
            bind,
            anchor_ids: anchors.nodes().iter().map(|n| n.id).collect(),
            room_anchors: BTreeMap::new(),
            anchors,
            headless,
            anchor_boards,
            serve_only,
            forwards: BTreeMap::new(),
            pow_params,
            stream_loops: std::collections::BTreeMap::new(),
            addresses_task: None,
            changes_task: None,
            anchor_backoff: BTreeMap::new(),
            anchor_dials: Arc::new(std::sync::Mutex::new(BTreeSet::new())),
            anchor_window: BTreeMap::new(),
            anchor_connected_at: BTreeMap::new(),
            anchors_up: BTreeMap::new(),
            anchor_unreached_since: BTreeMap::new(),
            sync_dials: BTreeSet::new(),
            records_renew_at: BTreeMap::new(),
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
            join_slots: crate::node::joinslots::JoinSlots::new(JOINS_IN_FLIGHT),
            verify_slots: Arc::new(tokio::sync::Semaphore::new(VERIFIES_IN_FLIGHT)),
            passphrase_entered_at: Arc::default(),
            keyring_change_proved: false,
            join_tasks: tokio::task::JoinSet::new(),
            seat_promises: BTreeMap::new(),
            secret_work: Arc::new(tokio::sync::RwLock::new(())),
            joining: std::collections::BTreeSet::new(),
            joins_answered: BTreeMap::new(),
            reopening: std::collections::BTreeSet::new(),
            reopen_task: None,
            unlock_waiters: Vec::new(),
            locking: 0,
            unlock_after_lock: Vec::new(),
            view_stale: std::sync::atomic::AtomicBool::new(false),
            drive_changed: std::sync::atomic::AtomicBool::new(false),
            held_pairwise: Vec::new(),
            pairwise_out: BTreeMap::new(),
            board_authors: BTreeMap::new(),
            publishing: std::collections::BTreeSet::new(),
            publish_again: BTreeMap::new(),
            stale_retries: BTreeMap::new(),
            republish_pending: std::collections::BTreeSet::new(),
            stale_held: std::collections::BTreeSet::new(),
            publish_failures: std::collections::BTreeMap::new(),
            publish_waiters: Vec::new(),
            on_board: std::collections::BTreeSet::new(),
            publish_trouble: BTreeMap::new(),
            address_waiters: Vec::new(),
            address_serial: 0,
            leave_waiters: Vec::new(),
            leave_serial: 0,
            anchor_owed: BTreeMap::new(),
            member_dialed_at: BTreeMap::new(),
            nearby: None,
            nearby_task: None,
            nearby_due: 0,
            nearby_rooms: 0,
            nearby_dialed: BTreeMap::new(),
            fresh_details: BTreeMap::new(),
            reads_pending: BTreeMap::new(),
            winding: BTreeMap::new(),
            departed_seen: BTreeMap::new(),
            withdrawn: BTreeMap::new(),
            key_backoff: BTreeMap::new(),
            redeliver_now: false,
            reoffer: BTreeSet::new(),
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
            peer_book: crate::node::peer_book::PeerBook::new(),
            node_retention: crate::node::retention::RetentionConfig::default(),
            retention_read_at: 0,
            retention_dirty: std::collections::BTreeSet::new(),
            retention_warned: std::collections::BTreeSet::new(),
            consent_keys: crate::node::pending_consent::PendingConsents::default(),
            last_upgrade: std::collections::BTreeMap::new(),
            reachers: std::collections::BTreeMap::new(),
            udp_flows: Arc::new(crate::tunnel::udp::UdpFlows::default()),
            offered: std::collections::BTreeMap::new(),
            app: Arc::new(crate::node::app::AppHub::default()),
            status: crate::node::status::StatusBook::default(),
            sync_book: crate::node::status::SyncBook::shared(),
        };
        let mut node = node;
        node.status.started = (node.clock)();
        // The app layer asks the actor for connections through its own queue, forwarded
        // onto the network queue so they are served in order with everything else.
        {
            let (dial_tx, mut dial_rx) = mpsc::channel(COMMAND_QUEUE);
            node.app.set_dialer(dial_tx);
            let net_tx = node.net_tx.clone();
            tokio::spawn(async move {
                while let Some(dial) = dial_rx.recv().await {
                    if net_tx.send(NetEvent::AppDial(dial)).await.is_err() {
                        return;
                    }
                }
            });
        }
        let app = Arc::clone(&node.app);
        let handle_net_tx = node.net_tx.clone();
        // Status requests take the same road as app dials: onto the network queue, so
        // they are answered in order with everything else and never race a mutation.
        let (status_tx, mut status_rx) = mpsc::channel::<oneshot::Sender<_>>(COMMAND_QUEUE);
        {
            let net_tx = node.net_tx.clone();
            tokio::spawn(async move {
                while let Some(reply) = status_rx.recv().await {
                    if net_tx.send(NetEvent::Status(reply)).await.is_err() {
                        return;
                    }
                }
            });
        }
        let view_rx = node.view_tx.subscribe();
        let sync_book = Arc::clone(&node.sync_book);
        let keyring = KeyringWindow {
            entered: Arc::clone(&node.passphrase_entered_at),
            clock: Arc::clone(&node.clock),
        };
        // A headless node has nothing to unlock: it is on the network from the start.
        let mut node = node;
        if node.headless.is_some() {
            node.start_network()?;
        }
        node.publish_initial();
        let shares = crate::node::shares::Shares::spawn(
            node.paths.clone(),
            cmd_tx.downgrade(),
            node.view_tx.subscribe(),
            handle_event_tx.clone(),
        );
        crate::node::pulls::Pulls::spawn(
            node.paths.clone(),
            cmd_tx.downgrade(),
            node.view_tx.subscribe(),
            handle_event_tx.clone(),
        );
        let paths = node.paths.clone();
        let actor = tokio::spawn(node.run(cmd_rx, net_rx));
        let handle = NodeHandle {
            cmd_tx,
            view_rx,
            event_tx: handle_event_tx,
            events: Arc::new(Mutex::new(event_rx)),
            app,
            status_tx,
            net_tx: handle_net_tx,
            sync_book,
            keyring,
            shares,
            paths,
        };
        Ok((handle, actor))
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
                        name: room_name,
                        passphrase,
                    } = command
                    {
                        self.begin_create_channel(room_name, passphrase, None, reply)
                            .await;
                        self.note_if_stalled(name, started);
                        self.publish().await;
                        continue;
                    }
                    // **`vox serve` and `vox room open` too** (V210-71): serving seals a new
                    // room's key and opening unwraps one, each production Argon2id, and opening
                    // also re-verifies the room's whole log. Both ran on the actor, so a post on
                    // any other room waited seconds behind them.
                    if let NodeCommand::Serve {
                        room: room_name,
                        passphrase,
                        name: service,
                        port,
                        udp,
                        at,
                    } = command
                    {
                        let endpoint =
                            at.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], port)));
                        // A UDP service is served as `udp/<name>` (ADR-022 decision 6).
                        let tag = if udp {
                            format!("udp/{service}")
                        } else {
                            service
                        };
                        self.begin_create_channel(
                            room_name,
                            passphrase,
                            Some((tag, endpoint)),
                            reply,
                        )
                        .await;
                        self.note_if_stalled(name, started);
                        self.publish().await;
                        continue;
                    }
                    if let NodeCommand::OpenChannel {
                        channel_id,
                        passphrase,
                    } = command
                    {
                        self.begin_open_channel(channel_id, passphrase, reply);
                        self.note_if_stalled(name, started);
                        continue;
                    }
                    // **An agreement is answered later too** (V210-168): it waits on every member
                    // of the room, up to `agreestream::ASK_PATIENCE`, which the actor must not.
                    if let NodeCommand::Agree {
                        channel_id,
                        entry,
                        types,
                        report,
                    } = command
                    {
                        self.begin_agree(channel_id, entry, types, report, reply)
                            .await;
                        self.note_if_stalled(name, started);
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
                    if let NodeCommand::JoinChannel { link, passphrase } = command {
                        self.begin_join_channel(link, passphrase, reply).await;
                        self.note_if_stalled(name, started);
                        self.publish().await;
                        continue;
                    }
                    // **A leave is answered once another member has the departure** (V210-164):
                    // see `begin_leave`.
                    if let NodeCommand::LeaveRoom { channel_id } = command {
                        self.begin_leave(channel_id, reply).await;
                        self.note_if_stalled(name, started);
                        self.publish().await;
                        self.schedule().await;
                        continue;
                    }
                    // **An address is answered once its room can be joined through it** (V210-96):
                    // see `begin_invite`.
                    if let NodeCommand::Invite { channel_id } = command {
                        self.begin_invite(channel_id, reply).await;
                        self.note_if_stalled(name, started);
                        self.publish().await;
                        continue;
                    }
                    // **Unlock is answered once the rooms it held are held again** (#208). They
                    // reopen off the actor so the node answers everyone meanwhile, but a caller
                    // told `Done` — `vox daemon`, which then opens its control socket — must not
                    // find a room it held still closed.
                    if let NodeCommand::Unlock { passphrase } = command {
                        if self.locking > 0 {
                            self.unlock_after_lock.push((passphrase, reply));
                        } else {
                            self.unlock_and_answer(&passphrase, reply).await;
                        }
                        self.note_if_stalled(name, started);
                        self.publish().await;
                        continue;
                    }
                    let outcome = self.handle(command).await;
                    if self
                        .drive_changed
                        .swap(false, std::sync::atomic::Ordering::Relaxed)
                    {
                        self.tend_drive_keys().await;
                    }
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
                        net.prune_board();
                    }
                    self.note_peers_seen();
                    self.retry_upgrades_if_due().await;
                    self.maintain_prekeys();
                    self.renew_records_if_due().await;
                    if self.view_stale.load(std::sync::atomic::Ordering::Relaxed) {
                        self.refresh_network_view().await;
                    }
                    self.redial_anchors_if_due();
                    self.say_where_if_due().await;
                    // A room forgotten, gone quiet, or back from a join changes what a person is
                    // shown: the view is published for it below, not left until the next event.
                    let tended = self.tend_lifecycle().await;
                    // A rotation's re-keys go out as the remaining consenters become
                    // reachable, which is why they are retried here and not only at
                    // the moment of rotation (M18.1).
                    self.deliver_owed_rekeys().await;
                    // Auto-consent for trusted identities, retried here for the
                    // same reason: a trusted member that was unreachable a moment
                    // ago is picked up as soon as it can be reached (ADR-020 §3).
                    self.deliver_owed_consents(None).await;
                    // Drive keys too (ADR-029 SC-2a, SC-2b): changed if a holder lost drive,
                    // and released to whoever is owed one.
                    self.tend_drive_keys().await;
                    // R14: a superseded generation's key goes once no full-history grant
                    // still has to release it.
                    let pruned = self.prune_superseded_keys().await;
                    // Paths change on the tick with no event to say so — a retired connection
                    // closed, a circuit this node relayed ended — and a view published only on
                    // events kept showing them: an anchor with no rooms reported a circuit it
                    // no longer carried for as long as nothing else happened to it.
                    // ADR-025: the tick is a safety net for sync. It retires attempts whose
                    // connection died (D1a) and raises the periodic request (D7).
                    self.sync_tick().await;
                    let ran = self.schedule().await;
                    if ran || tended || pruned || self.paths_moved() {
                        self.publish().await;
                    }
                    // Retention on every tick: the index is ordered by age, so a pass that
                    // prunes nothing costs one comparison per open room.
                    if self.sweep_retention().await {
                        self.publish().await;
                    }
                    // A read record held back by the 5-second batch goes out when it is due.
                    self.flush_reads().await;
                    // A folded decision's count is written once its hour is over (ADR-028 D-1).
                    self.decisions.flush_folded((self.millis_clock)());
                }
            }
        }
        // Channel closed or shutdown: lock (wipe every SEK + the signer) and stop.
        let store = self.log_store();
        self.stop_network().await;
        // Here the actor does wait for the lock to settle: it is stopping, and `Done` means gone.
        let _ = self.lock_all().await.await;
        for (_, reply) in std::mem::take(&mut self.unlock_after_lock) {
            let _ = reply.send(Outcome::Failed(Fault::ShuttingDown));
        }
        self.settle_lock().await;
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

    fn handle(&mut self, command: NodeCommand) -> Boxed<'_, Outcome> {
        Box::pin(self.handle_unboxed(command))
    }

    /// [`Self::handle`], unboxed: see [`Boxed`].
    async fn handle_unboxed(&mut self, command: NodeCommand) -> Outcome {
        match command {
            NodeCommand::CreateIdentity { passphrase } => self.create_identity(&passphrase),
            NodeCommand::Unlock { passphrase } => self.unlock(&passphrase).await,
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
                // A check opens no window (ADR-028 K-12): only the keyring change it proves does,
                // as `Proved`.
                Some(profile) => match profile.verify_passphrase(&passphrase) {
                    Ok(()) => Outcome::Done,
                    Err(_) => Outcome::Failed(Fault::WrongPassphrase),
                },
            },
            NodeCommand::CreateChannel { name, passphrase } => {
                self.create_channel(&name, &passphrase).await
            }
            NodeCommand::RenameRoom { channel_id, name } => {
                self.rename_room(&channel_id, &name).await
            }
            NodeCommand::AppendSession {
                channel_id,
                session_id,
                body,
            } => self.append_session(&channel_id, &session_id, &body).await,
            // Answered through `begin_open_channel`, which the run loop calls instead of this.
            NodeCommand::OpenChannel { .. } => Outcome::Failed(Fault::Internal),
            NodeCommand::CloseChannel { channel_id } => self.close_channel(&channel_id).await,
            NodeCommand::EndRoom { channel_id } => self.end_room(&channel_id).await,
            NodeCommand::SetAdmin {
                channel_id,
                member,
                admin,
            } => self.set_admin(&channel_id, &member, admin).await,
            NodeCommand::ChooseIdleEnd {
                channel_id,
                idle_secs,
            } => self.choose_idle_end(&channel_id, idle_secs).await,
            NodeCommand::SendText { channel_id, text } => {
                #[cfg(feature = "test-knobs")]
                test_panic_on_text(&text);
                self.send_text(&channel_id, &text).await
            }
            NodeCommand::MarkRead {
                channel_id,
                entries,
            } => self.mark_read(&channel_id, entries).await,
            NodeCommand::Invite { channel_id } => self.invite(&channel_id).await,
            // Answered through `begin_join_channel`, which the run loop calls instead of this; a
            // join reaching here would have to be answered inline, which is the stall that
            // function exists to remove.
            NodeCommand::JoinChannel { .. } => {
                debug_assert!(false, "JoinChannel is answered by begin_join_channel");
                Outcome::Failed(Fault::Internal)
            }
            // A change whose passphrase was just checked: made, and the window starts again (the
            // only thing that starts it, ADR-028 K-12). Not through the window: the change must
            // never refuse the passphrase it had just been given.
            NodeCommand::Proved { change } => {
                if !matches!(
                    *change,
                    NodeCommand::Trust { .. }
                        | NodeCommand::TrustWith { .. }
                        | NodeCommand::SetCapability { .. }
                        | NodeCommand::Rename { .. }
                        | NodeCommand::Untrust { .. }
                ) {
                    return Outcome::Failed(Fault::Internal);
                }
                if self.profile.as_ref().is_some_and(Profile::is_unlocked) {
                    self.note_passphrase_entered();
                }
                self.keyring_change_proved = true;
                let outcome = self.handle(*change).await;
                self.keyring_change_proved = false;
                outcome
            }
            // Only an unlocked node asks for the passphrase again. One with no identity or a
            // locked one falls through, and says that: a passphrase would not make the change.
            NodeCommand::Trust { .. }
            | NodeCommand::TrustWith { .. }
            | NodeCommand::SetCapability { .. }
            | NodeCommand::Rename { .. }
            | NodeCommand::Untrust { .. }
                if self.profile.as_ref().is_some_and(Profile::is_unlocked)
                    && !self.keyring_change_proved
                    && !self.passphrase_entered_recently() =>
            {
                Outcome::Failed(Fault::PassphraseNeeded)
            }
            NodeCommand::Trust {
                fingerprint,
                petname,
            } => {
                let was = self.trust.is_trusted(&fingerprint);
                let out = self
                    .trust_identity(
                        fingerprint,
                        &petname,
                        crate::node::trust::HistoryGrant::Now,
                        None,
                    )
                    .await;
                self.decided_trust(was, fingerprint, &out);
                out
            }
            NodeCommand::TrustWith {
                fingerprint,
                petname,
                history,
                capability,
            } => {
                let was = self.trust.is_trusted(&fingerprint);
                let out = self
                    .trust_identity(fingerprint, &petname, history, capability)
                    .await;
                self.decided_trust(was, fingerprint, &out);
                out
            }
            NodeCommand::SetCapability {
                fingerprint,
                capability,
            } => self.set_capability(fingerprint, capability).await,
            NodeCommand::Rename {
                fingerprint,
                petname,
            } => {
                if self.trust.is_trusted(&fingerprint) {
                    let history = self.trust.history(&fingerprint);
                    self.trust_identity(fingerprint, &petname, history, None)
                        .await
                } else {
                    Outcome::Failed(Fault::NotConsented)
                }
            }
            NodeCommand::Untrust { fingerprint } => {
                let alias = self.trust.petname(&fingerprint).map(str::to_owned);
                let out = self.untrust_identity(&fingerprint).await;
                if matches!(out, Outcome::Done) && alias.is_some() {
                    self.decisions.record(
                        (self.millis_clock)(),
                        &crate::node::decisions::Decision {
                            asked: "to stop trusting a member",
                            by: fingerprint,
                            alias,
                            decided: crate::node::decisions::Decided::Untrusted,
                            why: "this node's person removed them from the keyring: they read \
                                  nothing new from it and reach none of its services"
                                .to_owned(),
                            room: None,
                        },
                    );
                }
                out
            }
            // Answered through `begin_create_channel`, which the run loop calls instead of this.
            NodeCommand::Serve { .. } => Outcome::Failed(Fault::Internal),
            NodeCommand::Up { channel_id, bind } => self.bring_up(&channel_id, bind).await,
            NodeCommand::AddService {
                channel_id,
                service_tag,
                local,
                kind,
                persist,
            } => {
                self.add_service(&channel_id, &service_tag, local, kind, persist)
                    .await
            }
            NodeCommand::RemoveService {
                channel_id,
                service_tag,
            } => {
                let out = self.remove_service(&channel_id, &service_tag).await;
                if let (Outcome::Done, Some(me)) =
                    (&out, self.profile.as_ref().map(Profile::fingerprint))
                {
                    self.decided(
                        "to stop sharing a service",
                        me,
                        Some(channel_id),
                        crate::node::decisions::Decided::Stopped,
                        format!(
                            "this node's person stopped sharing {service_tag} in room {}: nobody \
                             reaches it from now on",
                            crate::node::network::short_id(channel_id)
                        ),
                    );
                }
                out
            }
            // Answered by `begin_forward` and `NetEvent::ForwardDialed`: the command loop takes it
            // before it gets here.
            NodeCommand::Forward { .. } => {
                unreachable!("NodeCommand::Forward is answered by begin_forward")
            }
            NodeCommand::LeaveRoom { .. } => {
                unreachable!("NodeCommand::LeaveRoom is answered by begin_leave")
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
            NodeCommand::SetRetention { channel_id, ttl } => {
                self.set_retention(&channel_id, ttl).await
            }
            // Answered by `begin_agree`: the command loop takes it before it gets here.
            NodeCommand::Agree { .. } => Outcome::Failed(Fault::Internal),
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

    /// Whole seconds since the Unix epoch, from [`Self::now_ms`]: for what is still kept in
    /// seconds.
    fn now(&self) -> u64 {
        self.now_ms().secs()
    }

    /// The node's clock (ADR: every time is milliseconds).
    fn now_ms(&self) -> crate::time::Ms {
        crate::time::Ms((self.clock)())
    }

    /// The identity passphrase was just entered for a keyring change, and proved: further keyring
    /// changes are allowed without it for [`keyring_window_ms`] from now (V210-159). Only a keyring
    /// change opens the window; attaching never does (ADR-028 K-12).
    fn note_passphrase_entered(&self) {
        self.passphrase_entered_at.store(
            self.now_ms().get().max(1),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Whether the identity passphrase was entered within [`keyring_window_ms`]. Never, while
    /// locked. A clock that went backwards counts as recent: the passphrase was entered, and the
    /// window is kept by the next change of the clock forward, not by a wrong reading.
    fn passphrase_entered_recently(&self) -> bool {
        let at = self
            .passphrase_entered_at
            .load(std::sync::atomic::Ordering::Relaxed);
        keyring_left(at, self.now_ms().get()).is_some()
    }

    fn create_identity(&mut self, passphrase: &Secret) -> Outcome {
        if self.profile.is_some() {
            return Outcome::Failed(Fault::IdentityExists);
        }
        let now = self.now();
        let events = self.event_tx.clone();
        let waiting = move || {
            let _ = events.send(NodeEvent::WaitingForProfile);
        };
        match Profile::create_noting(self.paths.clone(), passphrase, now, self.argon2, &waiting) {
            Ok(p) => {
                // Made, not entered for a keyring change: no window opens (ADR-028 K-12).
                self.profile = Some(p);
                // A fresh identity gets its prekey ring immediately: without it the
                // node has nothing to publish and cannot answer PQXDH.
                if let Err(e) = self.load_prekeys(self.now_ms().get()) {
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
                if let Err(e) = self.load_prekeys(self.now_ms().get()) {
                    // The identity is usable but the ring is not: lock again rather
                    // than run without key-agreement keys.
                    drop(self.lock_all().await);
                    // The passphrase was just proved by the vault, so a blob that will not open
                    // is not a wrong passphrase (V210-40).
                    return Outcome::Failed(match e {
                        crate::error::Error::AtRestUnlockFailed => Fault::SealedUnreadable,
                        e => fault_of(&e),
                    });
                }
                if let Err(e) = self.start_network() {
                    drop(self.lock_all().await);
                    return Outcome::Failed(fault_of(&e));
                }
                // **Attaching opens no keyring window** (ADR-028 K-12): only a passphrase
                // entered for a keyring change does.
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
        let signer: Arc<dyn crate::identity::composite::RootSigner + Send + Sync> =
            match (self.headless.as_ref(), self.profile.as_ref()) {
                (Some(signer), _) => Arc::clone(signer) as _,
                (None, Some(profile)) => profile.signer_arc()? as _,
                (None, None) => {
                    return Err(crate::error::Error::Profile("no identity on this node"))
                }
            };
        // The daemon's presence, or one of this node's own.
        let (presence, owned, moved) = match bind {
            Bind::Shared(presence) => (Arc::clone(presence), false, None),
            other => {
                let (shared, moved) = self.bind_endpoint(other)?;
                (
                    crate::node::presence::NetPresence::start(shared),
                    true,
                    moved,
                )
            }
        };
        let link = presence.attach(signer)?;
        let endpoint = link.endpoint;
        // How long a stuck tunnel is given (V030-11): this node's setting, on this node.
        endpoint.local().set_stuck_after(self.stuck_after);
        let mut net = NodeNet::new(endpoint, Arc::clone(&presence), Arc::clone(&self.clock));
        // Only an anchor keeps a board for a room it does not hold, and `--serve trusted`
        // narrows that to rooms its operator's trust list created (V210-70).
        net.serve_rooms(match (self.anchor_boards, self.serve_only.as_ref()) {
            (false, _) => crate::nat::service::AnchorRooms::Held,
            (true, None) => crate::nat::service::AnchorRooms::Anyone,
            (true, Some(creators)) => crate::nat::service::AnchorRooms::CreatedBy(creators.clone()),
        });
        net.count_ladders_in(Arc::clone(&self.sync_book));
        net.record_decisions_in(self.decisions.clone());
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
            // A withdraw changes what the board shows (V030-14): an event, so the view is
            // published for it. `try_send` for the same reason as above.
            let tx = self.net_tx.clone();
            net.on_board_withdraw(Arc::new(move |_: Digest32| {
                let _ = tx.try_send(NetEvent::BoardWithdrew);
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
        #[cfg(feature = "test-knobs")]
        if std::env::var_os(TEST_SUPERSEDE_CARRYING_ENV).is_some() {
            spawn_test_supersede(
                Arc::clone(&net),
                self.net_tx.clone(),
                Arc::clone(&self.clock),
            );
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
        // The presence discovers, maps and renews once for every node on it (ADR-026 D-3): this
        // node is told each composition, the one already made included.
        {
            let mut addresses = presence.advertised();
            if addresses.borrow().is_some() {
                addresses.mark_changed();
            }
            let tx = self.net_tx.clone();
            let task = tokio::spawn(async move {
                while addresses.changed().await.is_ok() {
                    if tx.send(NetEvent::AddressesDiscovered).await.is_err() {
                        break;
                    }
                }
            });
            if let Some(old) = self.addresses_task.replace(task.abort_handle()) {
                old.abort();
            }
        }
        // Each real change of the machine's network, told once the presence has composed the new
        // addresses (ADR-012 N-51, N-52).
        {
            let mut changes = presence.changes();
            let tx = self.net_tx.clone();
            let task = tokio::spawn(async move {
                loop {
                    match changes.recv().await {
                        Ok(change) => {
                            if tx.send(NetEvent::NetworkChanged(change)).await.is_err() {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
            if let Some(old) = self.changes_task.replace(task.abort_handle()) {
                old.abort();
            }
        }
        spawn_inbound_pump(
            net,
            link.inbound,
            presence.bursts(),
            presence.shared().closed(),
            self.net_tx.clone(),
        );
        self.presence = Some((presence, owned));
        // Members on this computer or the local network are found by what they say there, an
        // anchor holds no room and has nobody to find. Without the group, a node is found only
        // where its records say, as before.
        // On the daemon's presence the group is the daemon's (ADR-026 D-3, ADR-012 N-44).
        #[cfg(feature = "test-knobs")]
        let unheard = std::env::var_os(TEST_NO_NEARBY_ENV).is_some();
        #[cfg(not(feature = "test-knobs"))]
        let unheard = false;
        let nearby = if self.headless.is_none() && !unheard {
            self.presence.as_ref().and_then(|(p, _)| p.nearby())
        } else {
            None
        };
        {
            if let Some((nearby, mut heard)) = nearby {
                let tx = self.net_tx.clone();
                let task = tokio::spawn(async move {
                    loop {
                        match heard.recv().await {
                            // Dropped when the actor is behind: the next one is said within
                            // `NEARBY_EVERY_MS`.
                            Ok((from, entries)) => {
                                let _ = tx.try_send(NetEvent::Heard { from, entries });
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });
                self.nearby = Some(nearby);
                self.nearby_task = Some(task.abort_handle());
                self.nearby_rooms = 0;
            }
        }
        // Who finds a node whose port moved depends on whether it says where it listens nearby,
        // so the note waits until that is known.
        if let Some(moved) = moved {
            let who = if self.nearby.is_some() {
                "members on this computer or the local network find it here, others through an \
                 anchor or when it reaches them"
            } else if self.headless.is_some() {
                "anyone given its old address needs the new one"
            } else {
                "members find it only through an anchor or when it reaches them"
            };
            let _ = self.event_tx.send(NodeEvent::NodeNote {
                note: format!("{moved}; {who}"),
            });
        }
        Ok(())
    }

    /// Bind this node's own presence's endpoint (a solo presence; the daemon's is bound once).
    ///
    /// **A node keeps its port** (V210-167). Asked for port 0, it bound a new random port on every
    /// start, and a member finds another only at the address its board record last gave: with no
    /// anchor to carry a new record, two members that both restarted dialled each other's dead
    /// ports for ever. So the port a node first binds is written to the profile ([`PORT_FILE`])
    /// and bound again on every start. If another program holds it now, the node binds another
    /// for this run, and the second value is what to say about it; the file keeps the first,
    /// which the next start tries again. A port given explicitly is bound as given and not
    /// recorded.
    ///
    /// [`PORT_FILE`]: crate::node::paths::PORT_FILE
    fn bind_endpoint(
        &self,
        bind: &Bind,
    ) -> crate::error::Result<(Arc<crate::transport::quic::SharedEndpoint>, Option<String>)> {
        use crate::transport::quic::SharedEndpoint as VoxEndpoint;
        let addr = match bind {
            Bind::Addr(addr) => *addr,
            Bind::Socket(socket) => {
                return Ok((VoxEndpoint::bind_abstract(Arc::clone(socket))?, None))
            }
            Bind::Shared(presence) => return Ok((Arc::clone(presence.shared()), None)),
        };
        // The node's own port, else the data root's (ADR-026 D-3), so it binds where members last
        // saw it.
        crate::node::presence::NetPresence::bind_kept(
            addr,
            &self.paths.port_file(),
            Some(&self.paths.account_port_file()),
        )
    }

    /// Tear the network down: close every connection and the endpoint, so a locked
    /// node presents no network identity at all.
    async fn stop_network(&mut self) {
        if let Some(task) = self.nearby_task.take() {
            task.abort();
        }
        if let Some(task) = self.addresses_task.take() {
            task.abort();
        }
        if let Some(task) = self.changes_task.take() {
            task.abort();
        }
        self.nearby = None;
        if let Some(net) = self.net.take() {
            // **A finished tunnel's last bytes first.** A close drops what the peer has not yet
            // acknowledged, so a node stopped right after a reply was finished cut it short at
            // the far end (V210-81).
            crate::tunnel::session::all_acknowledged(
                &net.manager().endpoint().local_id(),
                STOP_ACK_BOUND,
            )
            .await;
            // **Relayed connections first**, while the circuits their closes travel in still run,
            // then everything else. Closing them all at once closed each circuit's carrier in the
            // same instant, so a relayed peer never received the CONNECTION_CLOSE. It learned this
            // node was gone only by inference: from `SILENCE_IS_DEATH` (30 s), or, since V29-15,
            // from reading the severed circuit as not a direct path. Inference is the fallback for
            // a crash. A node that is stopping **says** it is leaving, which is what a close is for.
            // Measured on `m15_members_never_online_together`: 33.3 s in 10 of 12 runs without
            // either, 107–115 ms with this ordering alone.
            //
            // **Said first, while every connection still runs** (V210-93): a close cannot be relied
            // on to arrive (see `ConnectionManager::say_goodbye`), so each peer is told this node
            // is stopping, and each has it before the closes go.
            let _ = net.manager().say_goodbye(GOODBYE_PATIENCE).await;
            if net.manager().close_relayed() > 0 {
                tokio::time::sleep(RELAYED_CLOSE_LEAD).await;
            }
            net.manager().close_all();
            // Off the exchange: nothing more is answered as this node.
            net.manager().endpoint().unregister();
        }
        // **Only this node's** (ADR-026 D-5): on the daemon's presence the endpoint and every
        // other node's connections stay as they are. A presence this node made for itself goes
        // with it, and the closes leave before the node goes on (V210-93): `close` only queues
        // each CONNECTION_CLOSE, and a process that exits straight after can take them with it.
        // Bounded inside: a close that cannot leave is not worth a stuck shutdown.
        if let Some((presence, owned)) = self.presence.take() {
            if owned {
                let _ = presence.close().await;
            }
        }
        self.stream_loops.clear();
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
        cause: PublishCause,
    ) {
        // Taken off boards (V030-14): published nowhere again.
        if self.withdrawn.contains_key(channel_id) {
            return;
        }
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
                (c.genesis().to_wire(), c.epoch(), c.own_admission().clone())
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
        #[cfg_attr(not(feature = "test-knobs"), allow(unused_mut))]
        let mut own = vec![
            ("the room's genesis", genesis_wire),
            ("our member bundle", bundle.to_wire()),
            ("our address", address.to_wire()),
        ];
        #[cfg(feature = "test-knobs")]
        if test_hold_address(&conn.local_id(), channel_id) {
            own.pop();
        }
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
            match self.publish_again.entry((*channel_id, board_id)) {
                std::collections::btree_map::Entry::Vacant(waiting) => {
                    waiting.insert(cause);
                }
                std::collections::btree_map::Entry::Occupied(_) => {
                    crate::node::status::SyncBook::note_publish_merged(&self.sync_book, cause);
                }
            }
            return;
        }
        crate::node::status::SyncBook::note_publish_round(&self.sync_book, cause);
        #[cfg(feature = "test-knobs")]
        let held = test_hold_room_from_anchors(&conn.local_id(), channel_id);
        let conn = Arc::clone(conn);
        let tx = self.net_tx.clone();
        let cid = *channel_id;
        tokio::spawn(async move {
            let conn = &conn;
            let round = async {
                let mut outcomes: Vec<(&'static str, Option<String>)> = Vec::new();
                #[cfg(feature = "test-knobs")]
                if held {
                    outcomes.push((
                        "this publish round",
                        Some(format!(
                            "held for a proof ({TEST_HOLD_ROOM_FROM_ANCHORS_ENV})"
                        )),
                    ));
                    return (outcomes, true, false);
                }
                // **A stream that will not open is a failed round, and says so.** It used to return
                // no outcomes at all — "the next round's business" — which reported nothing and, for
                // a room nothing else triggers a publish for, left it off that board indefinitely.
                let client = match crate::nat::service::RendezvousClient::open(conn).await {
                    Ok(client) => client,
                    Err(e) => {
                        outcomes.push(("this publish round", Some(format!("no stream: {e}"))));
                        return (outcomes, true, false);
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
                // Whether the board holds the room as a joiner needs it — genesis, bundle and
                // address — once this round ends: each put taken, or refused only as older than what
                // the board already holds (V210-96).
                let mut holds_room = true;
                for (kind, wire) in &own {
                    let result = client.put(wire).await;
                    let dead =
                        matches!(&result, Err(e) if !matches!(e, Error::RendezvousRejected(_)));
                    holds_room &= match &result {
                        Ok(()) => true,
                        Err(Error::RendezvousRejected(r)) => {
                            *r == crate::nat::service::RejectReason::Stale.as_str()
                        }
                        Err(_) => false,
                    };
                    outcomes.push((kind, result.err().map(|e| e.to_string())));
                    if dead {
                        return (outcomes, true, false);
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
                (outcomes, mirrored_dead, holds_room)
            };
            let (outcomes, failed, holds_room) =
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
                        false,
                    ),
                };
            let _ = tx
                .send(NetEvent::PublishDone {
                    channel_id: cid,
                    board: board_id,
                    outcomes,
                    failed,
                    holds_room,
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
    ///
    /// **A node with no anchor answers at once:** it has no round to wait for, and its own board
    /// holds the room for anyone who reaches it directly (V210-107).
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
                        && why.contains("author is not a room member");
                    // Our own record refused as stale is cured by the republish past the second
                    // (`NetEvent::RepublishTo`); said only if it is still refused after that.
                    let stale = own_stale_refusal(kind, &Some(why.clone()));
                    let grace = if stale {
                        STALE_REFUSAL_GRACE_MS
                    } else {
                        PUBLISH_REFUSAL_GRACE_MS
                    };
                    if stale {
                        self.stale_held.insert(key.clone());
                    }
                    if not_yet_vouched || stale {
                        let now = self.now_ms().get();
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
                                    tokio::time::sleep(Duration::from_millis(
                                        STALE_REFUSAL_GRACE_MS,
                                    ))
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
        self.now_ms()
            .get()
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

    /// The store channels live in: the profile's. A headless node (an anchor) holds no room and
    /// keeps no store for one (ADR-023 decision 6).
    fn log_store(&self) -> Option<Arc<crate::node::store::Store>> {
        self.profile.as_ref().map(Profile::store_handle)
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

    /// **Act on a change of the machine's network** (ADR-012 N-51, N-52), after the presence has
    /// forgotten its reflexive addresses and composed the new ones: publish every open room's
    /// records to this node's board and to every anchor now, without waiting for their renewal;
    /// say the change; and probe, off the actor, every connection this node accepted and every
    /// anchor's, dialling again whatever did not survive ([`NetEvent::Stranded`]).
    async fn network_changed(&mut self, change: &crate::nat::netwatch::NetChange) {
        let channels: Vec<Digest32> = self.channels.keys().copied().collect();
        for channel_id in &channels {
            self.publish_channel_locally(channel_id).await;
            self.publish_channel_to_anchors(channel_id, PublishCause::Addresses)
                .await;
        }
        let advertised = self
            .presence
            .as_ref()
            .and_then(|(p, _)| p.advertised_now())
            .map(|list| {
                list.addrs()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "nothing".to_owned());
        let _ = self.event_tx.send(NodeEvent::NetworkChanged {
            summary: format!(
                "{}; this node now advertises {advertised}, and republished {} room(s) to its \
                 board and its anchors",
                change.summary(),
                channels.len()
            ),
        });
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        let anchors: std::collections::BTreeSet<Digest32> =
            self.kept_anchors().into_iter().map(|(id, _)| id).collect();
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let stranded = net.manager().close_stranded(&anchors).await;
            if !stranded.is_empty() {
                let _ = tx.send(NetEvent::Stranded(stranded)).await;
            }
        });
    }

    /// Dial again, now, each peer whose connection a network change stranded: an anchor through
    /// the anchors' own redial, a member through a room it is in.
    async fn dial_stranded(&mut self, peers: &[Digest32]) {
        self.redial_anchors_if_due();
        for peer in peers {
            let mut room = None;
            for (cid, shared) in &self.channels {
                if shared.lock().await.members().contains(peer) {
                    room = Some(*cid);
                    break;
                }
            }
            if let Some(room) = room {
                let _ = self.reach_member(&room, *peer, true).await;
            }
        }
    }

    /// Dial any configured or learned anchor this node is not connected to. Runs on
    /// the tick: an anchor that restarted, or a link that dropped, is re-established on the
    /// next tick, and only one that keeps failing is backed off (V210-57).
    fn redial_anchors_if_due(&mut self) {
        let now = self.now_ms().get();
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        let open = &self.channels;
        self.room_anchors.retain(|room, _| open.contains_key(room));
        let known = self.kept_anchors();
        // **A loss is noticed however the anchor went** (V210-93), in every build. A clean stop
        // closes the connection; a kill or a crash closes nothing, so the connection held is also
        // probed once it falls quiet, and closed here when nothing answers.
        let mut silent: BTreeMap<Digest32, Duration> = BTreeMap::new();
        // **A connection whose only path ran through a relay that stopped is gone** (V210-93): its
        // circuit went with the relay, so it can carry nothing, however long its silence takes to
        // reach a probe's verdict — and a severed circuit, no longer the held connection, could sit
        // unjudged past the probe. Closed here now, it is said lost on this look as the relay's
        // stop.
        for conn in self.anchors_up.values() {
            if conn.carrier_stopped().is_some() && conn.quinn().close_reason().is_none() {
                conn.close(crate::wire::WireError::Unresponsive);
            }
        }
        for (id, conn) in &self.anchors_up {
            if let Some(s) = net.manager().close_if_unanswering(
                conn,
                ANCHOR_PROBE_AFTER,
                ANCHOR_SILENCE_IS_LOSS,
                ANCHOR_PROBES_BEFORE_LOSS,
            ) {
                silent.insert(*id, s);
            }
        }
        let up: BTreeMap<Digest32, Arc<VoxConnection>> = known
            .iter()
            .filter_map(|(id, _)| net.manager().held(id).map(|c| (*id, c)))
            .collect();
        // Lost: the connection seen at the last look has closed — **whether or not another has
        // replaced it since**. Asking only whether *a* connection was held missed an anchor that
        // came back between two looks: a restarted anchor's new connection supersedes the old one
        // at once, and the loss was never said. A duplicate to the same process, closed while the
        // other is kept, is no loss.
        //
        // One that is still open but no longer held is **watched on**, not called lost: it is a
        // duplicate the manager let go, or one whose close is still on its way, and saying "gone"
        // for it now would give no reason. Its close (or the probe, if nothing answers) says how
        // it ended.
        let mut lost: Vec<(Digest32, Arc<VoxConnection>)> = Vec::new();
        let mut watched = up.clone();
        for (id, conn) in &self.anchors_up {
            let replaced = up
                .get(id)
                .is_some_and(|now| now.peer_process() == conn.peer_process());
            if conn.quinn().close_reason().is_some() {
                if !replaced {
                    lost.push((*id, Arc::clone(conn)));
                }
            } else if !up.contains_key(id) {
                watched.insert(*id, Arc::clone(conn));
            }
        }
        for (id, conn) in lost {
            self.say_anchor_lost(&net, id, &conn, silent.get(&id).copied());
        }
        self.anchors_up = watched;
        let me = net.local_id();
        self.anchor_unreached_since
            .retain(|id, _| known.iter().any(|(k, _)| k == id) && !up.contains_key(id));
        for (id, _) in &known {
            if *id != me && !up.contains_key(id) {
                self.anchor_unreached_since.entry(*id).or_insert(now);
            }
        }
        for (id, candidates) in known {
            if id == net.local_id() || up.contains_key(&id) {
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
                    format!(
                        "dialling this anchor again, {} after it last failed",
                        seconds_said(waited)
                    ),
                );
            }
        }
    }

    /// Say that the connection `conn` to the anchor `id` is gone, and when it is redialled: at
    /// once, or backed off like a failed dial if it was lost soon after it was made
    /// ([`ANCHOR_FLAP_MS`]). `silent` is how long it answered nothing, if that is why it went.
    fn say_anchor_lost(
        &mut self,
        net: &Arc<NodeNet>,
        id: Digest32,
        conn: &VoxConnection,
        silent: Option<Duration>,
    ) {
        let now = self.now_ms().get();
        let lasted = match self.anchor_connected_at.get(&id) {
            Some((serial, at)) if *serial == conn.serial() => {
                let at = *at;
                self.anchor_connected_at.remove(&id);
                Some(now.saturating_sub(at))
            }
            _ => None,
        };
        // A peer that said it was stopping stopped, however the connection then ended: by its
        // close, by this end's close on hearing it, or by a close that never arrived.
        let why = match (silent, conn.quinn().close_reason()) {
            _ if conn.peer_stopped() => format!("the {} stopped", self.board_word(&id)),
            // Its peer is still running, but its only path ran through a relay that stopped: that
            // is the cause, not the probe's verdict on a path that no longer exists (V210-93).
            _ if conn.carrier_stopped().is_some() => format!(
                "its path ran through {}, which stopped",
                crate::node::link::b32_encode(&conn.carrier_stopped().unwrap_or_default())
                    .chars()
                    .take(12)
                    .collect::<String>()
            ),
            (Some(s), _) => format!("it answered nothing for {}s", s.as_secs()),
            (None, Some(e)) => anchor_close_reason(&e, conn.closed_here()),
            (None, None) => "it is no longer held".to_owned(),
        };
        if lasted.is_some_and(|s| s < ANCHOR_FLAP_MS) {
            // Lost almost as soon as it was made: backed off like a failed dial.
            let wait = self
                .anchor_backoff
                .get(&id)
                .map_or(1_000, |(_, w)| (w * 2).min(ANCHOR_REDIAL_MS));
            self.anchor_backoff.insert(id, (now + wait, wait));
            net.manager().note(
                id,
                format!(
                    "the connection to this {} is gone {} after it was made ({why}); it is \
                     redialled in {}",
                    self.board_word(&id),
                    seconds_said(lasted.unwrap_or(0)),
                    seconds_said(wait)
                ),
            );
        } else {
            self.anchor_backoff.remove(&id);
            net.manager().note(
                id,
                format!(
                    "the connection to this {} is gone ({why}); it is redialled now",
                    self.board_word(&id)
                ),
            );
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
        let (anchors, own, members, settled) = {
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
            let mut members = std::collections::BTreeSet::new();
            for n in channel.anchors().nodes() {
                if channel.is_known_member(&n.id) {
                    members.insert(n.id);
                } else {
                    let _ = own.add(n.clone());
                }
            }
            (
                channel.anchors().clone(),
                own,
                members,
                channel.is_settled(),
            )
        };
        self.room_anchors.insert(*channel_id, own);
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        for anchor in anchors.nodes() {
            // **A member is never dialled as an anchor** (V030-51, AGENTS.md "Anchors"): an
            // anchor's dial is direct only, and its failure backed off the member's sync, so a
            // member only a circuit reaches — the room's host, named by its link — was not
            // reached at all. A member is reached by the sync, which asks a relay when it must.
            if anchor.id == net.local_id() || members.contains(&anchor.id) {
                continue;
            }
            self.anchor_ids.insert(anchor.id);
            self.dial_anchor(&net, anchor.id, anchor.endpoints.direct_candidates());
        }
        // **A member the room's address names is reached as a member** (V030-51): left out of the
        // anchors' dial above, it must still be dialled, through the member ladder, which asks a
        // relay when it must. Nothing else dials it when a room that has synced is opened again
        // (a restart): a room with an anchor is left to its board (`reach_members_of`), and the
        // board need not name it. A room not yet synced reaches every member already
        // (`reach_members_of`), and a dial here would race the joiner's own.
        for member in members.into_iter().filter(|_| settled) {
            if member != net.local_id() && net.manager().existing(&member).is_none() {
                let _ = self.reach_member(channel_id, member, false).await;
            }
        }
    }

    /// Put a channel's genesis and this node's records on every anchor this node is
    /// connected to (its configured set and the channel's own).
    async fn publish_channel_to_anchors(&mut self, channel_id: &Digest32, cause: PublishCause) {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        // Taken off boards (V030-14): published nowhere again.
        if self.withdrawn.contains_key(channel_id) {
            return;
        }
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
            self.publish_channel_to_anchor(channel_id, &conn, cause)
                .await;
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
        if self.withdrawn.contains_key(channel_id) {
            return;
        }
        // Armed before the round rather than after it: the records are signed below. **Only here**:
        // every full round (this, then every anchor) comes through here, and a round to one anchor
        // must not re-arm it, or an anchor reconnecting more often than every half-lifetime put
        // the renewal off for good, and the own board and every other anchor lapsed.
        self.arm_record_renewal(channel_id);
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
        let admission = channel.own_admission().clone();
        if let Ok((address, bundle)) = net.own_records(
            signer,
            channel_id,
            channel.epoch(),
            &ring,
            seq,
            stamp,
            admission,
        ) {
            #[cfg(feature = "test-knobs")]
            let held = test_hold_address(&net.manager().endpoint().local_id(), channel_id);
            #[cfg(not(feature = "test-knobs"))]
            let held = false;
            if !held {
                let _ = net.publish_local(&address.to_wire());
            }
            let _ = net.publish_local(&bundle.to_wire());
        }
        // The room's admission notices and members' withdraws this node keeps (#520): a board
        // starts empty, and these are what tell every member of a newcomer that is offline, and of
        // none that left.
        for wire in channel.board_kept() {
            let _ = net.publish_local(&wire);
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
        let mut departed: std::collections::BTreeSet<Digest32> = std::collections::BTreeSet::new();
        for (cid, shared) in &self.channels {
            let Ok(ch) = shared.try_lock() else {
                // Busy: a session holds it. Keep the policy we have, and say it is behind so the
                // tick retries — nothing else is certain to come along and refresh it.
                self.view_stale
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                return;
            };
            // Who left is not a member to the network (V030-08); it is classed a joiner below.
            let members: BTreeMap<_, _> = ch
                .author_map()
                .into_iter()
                .filter(|(a, _)| !ch.has_left(a))
                .collect();
            policy.add_members(members.keys().copied());
            // A member that left may join again, like anyone with the passphrase (V030-08), and
            // nothing else: it is classed a joiner, not left in whatever class it last held (a
            // node it once let in still knew it as that node's join responder, which may not
            // open a join, and its join was refused at the stream).
            for left in ch
                .author_fingerprints()
                .into_iter()
                .filter(|a| ch.has_left(a))
            {
                policy.expect_joiner(left);
                departed.insert(left);
            }
            net.membership().set_channel(*cid, ch.epoch(), members);
        }
        // A room this node anchors but is not a member of: the members its **board** knows (the
        // creator, and everyone a member vouched for) are its members as far as the board and the
        // streams are concerned — their records verify, and they may open what a member may (a
        // circuit through this anchor among them). Read from the board, which an anchor keeps;
        // it keeps nothing else for the room (ADR-023 decision 6).
        if self.anchor_boards {
            for room in net.anchored_channels() {
                let cid = room.channel_id;
                if self.channels.contains_key(&cid) || !net.board_has_members(&cid) {
                    continue;
                }
                if !net.board_genesis(&cid).is_some_and(|g| net.may_anchor(&g)) {
                    continue;
                }
                let members: BTreeMap<Digest32, crate::identity::CompositePublicKey> = net
                    .board_member_keys(&cid, 0)
                    .into_iter()
                    .map(|k| (k.fingerprint(), k))
                    .collect();
                policy.add_members(members.keys().copied());
                net.membership().set_channel(cid, 0, members);
            }
        }
        // Anchors are not channel membership: they are carried in by hand. A member that left is
        // not one either, though a link named its board: it is a joiner now (above), and as an
        // anchor its join was refused at the stream (an anchor may not open one).
        for anchor in self.anchor_ids.iter().filter(|a| !departed.contains(*a)) {
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
    fn handle_net(&mut self, event: NetEvent) -> Boxed<'_, ()> {
        Box::pin(self.handle_net_unboxed(event))
    }

    /// [`Self::handle_net`], unboxed: see [`Boxed`].
    async fn handle_net_unboxed(&mut self, event: NetEvent) {
        match event {
            NetEvent::Heard { from, entries } => self.heard_nearby(from, &entries).await,
            NetEvent::AddressReached {
                room,
                named,
                answered,
                reply,
            } => {
                self.keep_room_address(room, &named, &answered, reply).await;
            }
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
                    // Everything `open_channel` does to a room it opens: a room reopened after an
                    // unlock is the same room, and a restart is exactly when its members have to
                    // be dialled from where they were last reached (`node::peer_book`).
                    let mut channel = *channel;
                    channel.set_node_retention(self.node_retention_for(&channel_id));
                    crate::node::status::SyncBook::note_set_aside(
                        &self.sync_book,
                        channel_id,
                        channel.set_aside(),
                    );
                    self.channels
                        .insert(channel_id, Arc::new(tokio::sync::Mutex::new(channel)));
                    self.mark_decisions_on_open(&channel_id).await;
                    self.resume_leave(&channel_id).await;
                    self.act_on_removals_while_closed(&channel_id).await;
                    self.adopt_channel_anchors(&channel_id, None).await;
                    self.refresh_network_view().await;
                    // Who may reach this room's services and apps: the app gate holds no room it
                    // was not told about, and refused every dial here with "this node does not
                    // hold that room" until a sync happened to refresh it (#227, family-LAN proof).
                    self.refresh_reachers().await;
                    self.publish_channel_locally(&channel_id).await;
                    self.publish_channel_to_anchors(&channel_id, PublishCause::Opened)
                        .await;
                    self.install_key_packages(&channel_id).await;
                    self.reach_members_of(&channel_id).await;
                    let _ = self.event_tx.send(NodeEvent::ChannelOpened { channel_id });
                }
            }
            NetEvent::ReopenGone { channel_id } => {
                self.reopening.remove(&channel_id);
                let _ = self.forget_open(&channel_id);
            }
            NetEvent::ReopenFailed { channel_id, why } => {
                let _ = self.event_tx.send(NodeEvent::NodeNote {
                    note: format!(
                        "room {} did not reopen: {why}; it stays closed",
                        crate::node::link::b32_encode(&channel_id)
                            .chars()
                            .take(12)
                            .collect::<String>()
                    ),
                });
            }
            NetEvent::LockSettled => self.settle_lock().await,
            NetEvent::ReopenFinished => {
                self.reopening.clear();
                self.reopen_task = None;
                for reply in std::mem::take(&mut self.unlock_waiters) {
                    let _ = reply.send(Outcome::Done);
                }
            }
            NetEvent::HandshakesQueued {
                waited,
                most_waiting,
                most_running,
                refused,
                longest,
            } => {
                let _ = self.event_tx.send(NodeEvent::HandshakesQueued {
                    waited,
                    most_waiting,
                    most_running,
                    refused,
                    longest_ms: u64::try_from(longest.as_millis()).unwrap_or(u64::MAX),
                });
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
            NetEvent::AgreeAsk { peer, ask, send } => self.answer_agree(peer, ask, send).await,
            NetEvent::SeatReserve {
                channel_id,
                joiner,
                ack,
            } => {
                let held = self.reserve_seat(channel_id, joiner).await;
                let _ = ack.send(held);
            }
            NetEvent::SeatRelease { channel_id, joiner } => {
                let me = self.profile.as_ref().map(Profile::fingerprint);
                if self
                    .seat_promises
                    .get(&(channel_id, joiner))
                    .is_some_and(|p| Some(p.from) == me)
                {
                    self.seat_promises.remove(&(channel_id, joiner));
                }
            }
            NetEvent::SeatAsk {
                peer,
                ask,
                send,
                recv,
            } => self.answer_seat(peer, ask, send, recv).await,
            NetEvent::SeatAbort { peer, abort } => {
                if self
                    .seat_promises
                    .get(&(abort.channel_id, abort.joiner))
                    .is_some_and(|p| p.from == peer)
                {
                    self.seat_promises.remove(&(abort.channel_id, abort.joiner));
                }
            }
            NetEvent::AgreeFetch { channel_id, peers } => {
                self.sync_with(&channel_id, &peers).await;
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
                witness,
                ack,
            } => {
                // The join proved this identity; admit it as an author so its entries — and its
                // records on this node's board — are accepted. Reading still needs consent.
                let now_ms = self.now_ms();
                // **Test-only** (`test-knobs`): this node fails every joiner's admission as a node
                // locked mid-join does — admitting nothing — so a proof can see what the joiner is
                // told.
                #[cfg(feature = "test-knobs")]
                let fails = std::env::var_os(TEST_ADMISSION_FAILS_ENV).is_some();
                #[cfg(not(feature = "test-knobs"))]
                let fails = false;
                let mut notice = None;
                let admitted = match (
                    self.profile.as_ref().filter(|_| !fails),
                    self.channels.get(&channel_id).map(Arc::clone),
                ) {
                    (Some(profile), Some(shared)) => {
                        let mut ch = shared.lock().await;
                        let admitted = ch
                            .admit_author(profile.store(), &identity, now_ms)
                            .map(|_| ch.name().map(str::to_owned));
                        // A member that left and proved the passphrase again is in again here,
                        // until its own return reaches the others through this node (V030-08).
                        if admitted.is_ok() {
                            ch.readmit(identity.fingerprint());
                            // Its admission, as this node witnessed it, kept and put on this
                            // node's board, so every member learns of the joiner while it is
                            // offline (#520).
                            if let Ok(n) = crate::nat::notice::AdmissionNotice::new(
                                (*identity).clone(),
                                (*witness).clone(),
                            ) {
                                let _ = ch.keep_notice(profile.store(), &n);
                                notice = Some(n.to_wire());
                            }
                        }
                        admitted
                    }
                    (None, _) => Err(Error::Profile("locked")),
                    (_, None) => Err(Error::Profile("no such room on this node")),
                };
                // **Not admitted, not accepted.** This was dropped, and the joiner was told it was
                // in whatever happened: a room already full took nobody, and its joiner exited 0.
                if admitted.is_ok() {
                    // And into the view the board and the stream gate read, before the joiner is
                    // answered: an author only the room knows is still a stranger to the board,
                    // which refused the newcomer's records until something else refreshed it
                    // (V210-80).
                    self.refresh_network_view().await;
                    // No longer waiting to join, so its pre-join record goes, and this node's
                    // board stops counting it as pending (V210-102).
                    if let Some(net) = self.net.as_ref() {
                        net.forget_prejoin(&channel_id, &identity.fingerprint());
                        if let Some(wire) = &notice {
                            let _ = net.publish_local(wire);
                        }
                    }
                }
                let _ = ack.send(admitted);
            }
            NetEvent::Dialed {
                conn,
                endpoints,
                board,
            } => {
                let peer = conn.peer_id();
                self.sync_dials.remove(&peer);
                self.adopt_connection(Arc::clone(&conn));
                // **And every connection the dial left retired** (#335): a reach files each
                // connection its rungs made, and one it filed first can have been displaced by a
                // later one. The peer may have filed it first too, and sent on it, so it is read
                // until its grace ends, as a retired connection the peer dialled is.
                if let Some(net) = self.net.as_ref().map(Arc::clone) {
                    for retired in net.manager().retiring_to(&peer) {
                        self.adopt_connection(retired);
                    }
                }
                if let Some(net) = self.net.as_ref().map(Arc::clone) {
                    if crate::node::net::path_class(net.manager().endpoint(), &conn)
                        == crate::node::net::PathClass::Relayed
                    {
                        let tx = self.net_tx.clone();
                        self.last_upgrade.insert(peer, self.now_ms().get());
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
                        self.finish_join_channel(*parsed, passphrase, now, me, won)
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
                for (_, stream) in held {
                    self.handle_pairwise(stream).await;
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
                room_name,
                passphrase,
                genesis,
                now,
                sealed,
                service,
            } => {
                let room = genesis.channel_id();
                // Asked again here: another room may have taken the name while the key sealed.
                let taken = self.room_named(&room_name).is_some();
                let outcome = match sealed {
                    Err(e) => Outcome::Failed(fault_of(&e)),
                    Ok(_) if taken => Outcome::Failed(Fault::RoomNameTaken),
                    Ok((sek, wrap)) => match self.profile.as_ref() {
                        None => Outcome::Failed(Fault::NoIdentity),
                        Some(profile) => match ChannelState::create_from_sealed(
                            profile,
                            &room_name,
                            &passphrase,
                            *genesis,
                            sek,
                            &wrap,
                            now,
                        ) {
                            Ok(ch) => match service {
                                None => self.finish_create_channel(ch).await,
                                Some((tag, endpoint, kind)) => {
                                    self.finish_serve_room(ch, &tag, endpoint, kind).await
                                }
                            },
                            Err(e) => Outcome::Failed(fault_of(&e)),
                        },
                    },
                };
                // The view first, then the answer — as for a join above.
                self.answer_when_published(room, reply, outcome).await;
            }
            NetEvent::ChannelUnsealed {
                reply,
                channel_id,
                opened,
            } => {
                let outcome = match *opened {
                    // Opened meanwhile by another command, or by the reopening: that one is held.
                    _ if self.channels.contains_key(&channel_id) => Outcome::Done,
                    // Locked meanwhile: a locked node holds no room key (ADR-015).
                    _ if !self.profile.as_ref().is_some_and(Profile::is_unlocked) => {
                        Outcome::Failed(Fault::NoIdentity)
                    }
                    Ok(ch) => self.finish_open_channel(ch).await,
                    Err(e) => Outcome::Failed(fault_of(&e)),
                };
                self.answer_when_published(channel_id, reply, outcome).await;
            }
            // Nothing to do but publish the view, which every event does once handled.
            NetEvent::BoardWithdrew => {}
            NetEvent::BoardGrew { channel_id } => {
                // Pass it on, which for a member means its anchors. A node that is not a member of
                // this room falls out of `publish_channel_to_anchor` on its missing admission, so
                // an anchor receiving a mirror does not mirror it onward and this cannot ring
                // around a ring of anchors.
                if self.channels.contains_key(&channel_id) {
                    crate::node::status::SyncBook::note_board_news(&self.sync_book);
                    self.publish_channel_to_anchors(&channel_id, PublishCause::BoardNews)
                        .await;
                    self.note_new_members(&channel_id).await;
                }
            }
            NetEvent::Pairwise(stream) => {
                self.take_inbound_skdm(stream).await;
            }
            NetEvent::HelloUndelivered { channel_id, peer } => {
                if let Some(i) = self.initiated.get_mut(&(channel_id, peer)) {
                    i.hello_delivered = false;
                }
            }
            NetEvent::ReopenUndelivered { channel_id, peer } => {
                if let Some(i) = self.initiated.get_mut(&(channel_id, peer)) {
                    i.hello_delivered = false;
                }
                self.reopen.insert((channel_id, peer));
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
            NetEvent::AddressesDiscovered => {
                // Re-publish every open channel's records: the addresses in them were
                // composed before discovery and may name only loopback.
                let channels: Vec<Digest32> = self.channels.keys().copied().collect();
                for channel_id in channels {
                    self.publish_channel_locally(&channel_id).await;
                    self.publish_channel_to_anchors(&channel_id, PublishCause::Addresses)
                        .await;
                }
                // An address waiting for this node's own routes can name them now (V210-96).
                let waiting: std::collections::BTreeSet<Digest32> =
                    self.address_waiters.iter().map(|(r, _, _)| *r).collect();
                for room in waiting {
                    self.answer_addresses(room).await;
                }
            }
            NetEvent::NetworkChanged(change) => self.network_changed(&change).await,
            NetEvent::Stranded(peers) => self.dial_stranded(&peers).await,
            NetEvent::ReachFailed { peer, why } => {
                // An anchor that failed to connect waits before its next dial, doubling to
                // `ANCHOR_UNREACHED_REDIAL_MS` (V210-57, V210-86), jittered once it is there, a
                // room's own as well as a configured one (V210-75).
                if self.is_kept_anchor(&peer) {
                    // A union too large for one dial tries its next window next time (V210-75).
                    if self.anchors.get(&peer).is_none() {
                        *self.anchor_window.entry(peer).or_insert(0) += ANCHOR_DIAL_CANDIDATES;
                    }
                    let wait = self
                        .anchor_backoff
                        .get(&peer)
                        .map_or(1_000, |(_, w)| (w * 2).min(ANCHOR_UNREACHED_REDIAL_MS));
                    let wait = if wait == ANCHOR_UNREACHED_REDIAL_MS {
                        let coin = crate::identity::rng::random_array::<1>().map_or(0, |b| b[0]);
                        wait - u64::from(coin & 1) * 1_000
                    } else {
                        wait
                    };
                    self.anchor_backoff
                        .insert(peer, (self.now_ms().get() + wait, wait));
                    if let Some(net) = self.net.as_ref() {
                        net.manager().note(
                            peer,
                            format!(
                                "dialling this anchor failed ({why}); the next try is in {}",
                                seconds_said(wait)
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
                // The fast path failed: what this node owes that member goes into the log,
                // where an always-on member carries it (ADR-023 decision 4).
                self.deliver_through_log(peer).await;
                // A joiner this node just let in is often gone from where it joined: `vox connect`
                // joins in a process that then exits, and the node attached after it answers
                // elsewhere. Said only once its join is past `JOINER_SEAL_GRACE` (#406).
                if !self.joiner_settling(&peer) {
                    let _ = self.event_tx.send(NodeEvent::PeerUnreachable { peer, why });
                }
            }
            NetEvent::UpgradeFailed { peer, reason } => {
                let _ = self.event_tx.send(NodeEvent::StillRelayed { peer, reason });
            }
            NetEvent::AnchorConnected { conn } => {
                let peer = conn.peer_id();
                // **Watched from the moment it is made** (V210-93), not from the next tick's look:
                // a connection lost before any tick had seen it was never said to be gone. In a
                // debug build a `vox forward` spends 5 s unlocking its identity, connects to its
                // anchor, and an anchor stopped a moment later went unreported for good. One this
                // replaces that has closed is a loss, said now.
                // The connection the manager holds for the anchor, which is this one unless it lost
                // a tie-break to another to the same process.
                let tracked = self
                    .net
                    .as_ref()
                    .and_then(|n| n.manager().held(&peer))
                    .unwrap_or_else(|| Arc::clone(&conn));
                if let Some(old) = self.anchors_up.insert(peer, Arc::clone(&tracked)) {
                    if old.serial() != tracked.serial()
                        && old.peer_process() != tracked.peer_process()
                        && old.quinn().close_reason().is_some()
                    {
                        if let Some(net) = self.net.as_ref().map(Arc::clone) {
                            self.say_anchor_lost(&net, peer, &old, None);
                        }
                    }
                }
                // The backoff is kept until the connection has lasted (`ANCHOR_FLAP_MS`): one
                // superseded at once is a flap, not a success.
                self.anchor_connected_at
                    .insert(peer, (tracked.serial(), self.now_ms().get()));
                self.anchor_window.remove(&peer);
                // Said, so a log shows a redial's outcome as well as its start (#243, a CI red
                // whose forward said it dialled and then nothing).
                //
                // **Named for what it is** (V210-107). A room's own host is dialled the same way —
                // its link entry is a board too — and was noted "connected to this anchor", which
                // told a person reaching a host directly that they were using an anchor. An anchor
                // is one this node was given (`--anchor`, the anchors file) or a room names that is
                // not one of its members.
                if let Some(net) = self.net.as_ref() {
                    net.manager().note(peer, self.board_note(&peer).to_owned());
                }
                self.anchor_ids.insert(peer);
                // In the view at once, for a client subscribing after this note went (#407).
                self.publish().await;
                // A new connection may be to a board that restarted and lost what it held: what it
                // holds is learnt again from the round below, before an address names it (V210-96).
                self.on_board.retain(|(_, b)| *b != peer);
                self.adopt_connection(Arc::clone(&conn));
                self.refresh_network_view().await;
                let channels: Vec<Digest32> = self.channels.keys().copied().collect();
                for channel_id in channels {
                    self.publish_channel_to_anchor(
                        &channel_id,
                        &conn,
                        PublishCause::AnchorReturned,
                    )
                    .await;
                }
                // An anchor that was away when a room was left or ended is told now, and is given
                // each room's admin roster this node signs (V030-14).
                let mut puts: Vec<Vec<u8>> = Vec::new();
                let rooms: Vec<Digest32> = self.channels.keys().copied().collect();
                for room in rooms {
                    if let Some(r) = self.admin_roster(&room).await {
                        puts.push(r);
                    }
                }
                puts.extend(self.withdrawn.values().cloned());
                Self::put_withdraws(&conn, puts);
                self.read_anchor_boards(Some(peer)).await;
                // A room that has not had its first sync reaches its members now that a relay is
                // here to carry what its direct dials cannot (V030-51).
                let unsynced: Vec<Digest32> = {
                    let mut rooms = Vec::new();
                    for (id, ch) in &self.channels {
                        if !ch.lock().await.is_settled() {
                            rooms.push(*id);
                        }
                    }
                    rooms
                };
                for channel_id in unsynced {
                    self.reach_members_of(&channel_id).await;
                }
            }
            NetEvent::BetterPath { conn } => {
                self.adopt_connection(conn);
            }
            NetEvent::Connected { peer } => {
                if let Some(conn) = self
                    .net
                    .as_ref()
                    .and_then(|net| net.manager().existing(&peer))
                {
                    self.note_peer_endpoint(&conn);
                }
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
                answered,
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
                    // **Refused because its owner does not trust us** (V210-118): the member holds
                    // none of what it refused, and by the time it trusts us the generation refused
                    // may be retired. Everything it is entitled to is owed again, so the re-key
                    // round, which retries until taken, delivers the retired generations too.
                    use crate::node::pairwise_stream::KeyRefusal;
                    if why == KeyRefusal::describe(KeyRefusal::NotTrusted.code().into_inner()) {
                        let _ = channel.owe_entitled_history(profile.store(), &peer);
                    }
                }
                // **The member holds no session with us** (V210-78): it restarted or locked, and
                // sessions live only in memory. Ours is dead at its end, and resending under it is
                // refused the same way for good. Forget it, so the retry opens a fresh one from
                // the member's bundle and offers it — unless a newer one has been filed since the
                // key was sealed, which the member does hold.
                //
                // **Or the key did not open under the session it holds** (V210-71): the two ends
                // hold different sessions, or ours ran more than `MAX_SKIP` messages ahead of it.
                // Every key is sealed before its write, so each write that failed used a message of
                // the session up, and a member whose writes kept failing was pushed past the gap it
                // accepts. Either way every later key under this session fails the same way, and a
                // fresh one is the cure, as for no session at all.
                use crate::node::pairwise_stream::KeyRefusal;
                let key = (channel_id, peer);
                // **Refused under a session already superseded** (V210-80): this node has adopted
                // the peer's since it sealed the key (two members trusting each other at once),
                // so the refusal says nothing about the session held now. Resend at once, under
                // it, with no backoff.
                if session.is_some() && self.session_serial.get(&key).copied() != session {
                    let _ = self.event_tx.send(NodeEvent::KeyNotTaken {
                        channel_id,
                        peer,
                        why,
                    });
                    self.deliver_owed_consents(None).await;
                    return;
                }
                let dead_session = [KeyRefusal::NoSession, KeyRefusal::CannotOpen]
                    .iter()
                    .any(|r| why == KeyRefusal::describe(r.code().into_inner()));
                if dead_session
                    && session.is_some()
                    && self.session_serial.get(&key).copied() == session
                {
                    self.sessions.remove(&key);
                    self.initiated.remove(&key);
                    self.accepted_hello.remove(&key);
                    self.reopen.remove(&key);
                    self.session_serial.remove(&key);
                }
                // **Lost, not refused** (V210-80): the key never reached the member's decision —
                // its connection closed under it (a tie-break retiring one of two crossed
                // connections does exactly that), or no answer came. Nothing says the member
                // would refuse it, so it is resent on the next tick over the connection held
                // then, with no backoff. A backoff here held two members who had just connected
                // 2 s and then 4 s more, seen through the shipped binary as a read at 6.2 s.
                if !answered {
                    let _ = self.event_tx.send(NodeEvent::KeyNotTaken {
                        channel_id,
                        peer,
                        why,
                    });
                    return;
                }
                // 2, 4, 8 … 64s: a refusal that cures (a session that converges, a member learnt
                // from the board) is retried promptly, and one that does not stops costing a
                // stream every second.
                //
                // A refused hello is cured by the peer's own, which it offers on its next tick,
                // and adopting it resends at once (`accept_hello`). Should that offer be lost
                // with its connection, the retry here is what brings the next one: it stays at
                // the first step rather than doubling, so one lost offer costs 2 s, not 2 + 4 + 8.
                let now = self.now_ms().get();
                let hello_refused =
                    why == KeyRefusal::describe(KeyRefusal::HelloRefused.code().into_inner());
                let entry = self.key_backoff.entry((channel_id, peer)).or_insert((0, 0));
                entry.0 = if hello_refused {
                    1
                } else {
                    entry.0.saturating_add(1)
                };
                entry.1 = now.saturating_add(1_000u64 << entry.0.min(6));
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
                    self.publish_channel_to_anchor(&channel_id, &conn, PublishCause::AskedAgain)
                        .await;
                }
            }
            NetEvent::PublishDone {
                channel_id,
                board,
                outcomes,
                failed,
                holds_room,
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
                        // wants a later `seq` as well as a later timestamp, and `seq` is floored by
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
                        // **And the `timestamp_ms` floor with it** (V210-64): a board wants a later
                        // timestamp too, and a real clock step moves both clocks. **Both capped** at
                        // `STALE_AHEAD_MAX_MS` past the clock, and never moved back.
                        let clock_ms = (self.millis_clock)();
                        let ahead = STALE_SEQ_STEP_MS << tries.min(8);
                        let cap = clock_ms.saturating_add(STALE_AHEAD_MAX_MS);
                        let entry = self.record_seq.entry(channel_id).or_insert(0);
                        *entry = (*entry)
                            .max(clock_ms)
                            .saturating_add(ahead)
                            .min((*entry).max(cap));
                        let now = self.now_ms().get();
                        let ts_cap = now.saturating_add(STALE_AHEAD_MAX_MS);
                        let stamp = self.record_ts_floor.entry(channel_id).or_insert(0);
                        *stamp = (*stamp)
                            .max(now)
                            .saturating_add(ahead)
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
                // Which boards hold the room, for an address that names them (V210-96).
                if holds_room {
                    self.publish_trouble.remove(&(channel_id, board));
                    self.on_board.insert((channel_id, board));
                } else {
                    let said: Vec<String> = outcomes
                        .iter()
                        .filter_map(|(what, why)| why.as_ref().map(|w| format!("{what}: {w}")))
                        .collect();
                    self.publish_trouble
                        .insert((channel_id, board), said.join("; "));
                }
                self.report_publish(&channel_id, board, outcomes);
                self.note_publish_round(channel_id, board, failed);
                self.answer_addresses(channel_id).await;
                if holds_room && self.anchor_owed.remove(&(channel_id, board)).is_some() {
                    let short = crate::node::network::short_id;
                    let _ = self.event_tx.send(NodeEvent::AddressNote {
                        channel_id,
                        note: format!(
                            "anchor {} has taken room {}: a guest who cannot reach this host \
                             directly can join through it now",
                            short(board),
                            short(channel_id)
                        ),
                    });
                }
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
                if let Some(cause) = self.publish_again.remove(&(channel_id, board)) {
                    let conn = self.net.as_ref().and_then(|n| n.manager().existing(&board));
                    if let Some(conn) = conn {
                        self.publish_channel_to_anchor(&channel_id, &conn, cause)
                            .await;
                    }
                }
                // A session with that board for this room was held back while the round ran.
                self.sched_rooms.insert(channel_id);
            }
            NetEvent::AddressWaitOver { channel_id, serial } => {
                self.withhold_address(channel_id, serial).await;
            }
            NetEvent::LeaveWaitOver { channel_id, serial } => {
                // Answered, and still leaving: the room goes once a member has the departure.
                if let Some((_, _, reply, _)) = self
                    .leave_waiters
                    .iter_mut()
                    .find(|(r, _, _, s)| *r == channel_id && *s == serial)
                {
                    if let Some(reply) = reply.take() {
                        let _ = reply.send(Outcome::Failed(Fault::LeaveNotHeard));
                    }
                }
            }
            NetEvent::AnchorNoteDue { channel_id, serial } => {
                self.say_anchors_that_never_took(channel_id, serial);
            }
            NetEvent::PublishRetry { channel_id, board } => {
                // **Cancelled if the room or the board has gone.** A room closed since, or a board
                // this node no longer holds a connection to, is not retried: the board is published
                // to again by `AnchorConnected` when it comes back, and a closed room has nothing to
                // publish. Its failure count goes with it.
                let conn = self.net.as_ref().and_then(|n| n.manager().existing(&board));
                match conn {
                    Some(conn) if self.channels.contains_key(&channel_id) => {
                        self.publish_channel_to_anchor(&channel_id, &conn, PublishCause::Retry)
                            .await;
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
                // Sender keys the log delivered in this session (ADR-023 decision 4). Whatever the
                // outcome, current or not: a session that failed late may have applied some entries
                // first.
                self.install_key_packages(&channel_id).await;
                // A session that sent this node's HAVE from at least the generation its departure
                // was written at, and ended cleanly, handed that peer the departure (V210-164).
                let heard = report.out.gen_have.filter(|_| report.fail.is_none());
                if report.fail.is_none() && report.out.complete {
                    self.settle_room(&channel_id).await;
                }
                // A joiner this node let in, not ready for the room yet, fails a session with
                // it: the join still settling, not a failure (#406). Its first clean session ends
                // the grace; so does `JOINER_SEAL_GRACE`.
                let settling = if report.fail.is_none() {
                    self.joins_answered.remove(&(channel_id, peer));
                    false
                } else {
                    self.joins_answered
                        .get(&(channel_id, peer))
                        .is_some_and(|at| at.elapsed() < JOINER_SEAL_GRACE)
                };
                if current && !settling {
                    if let Some(fail) = &report.fail {
                        // Said, with its reason (PRD-001 R36), so a failure that does not resolve
                        // can be told from one that does.
                        let _ = self.event_tx.send(NodeEvent::SyncFailed {
                            channel_id,
                            peer,
                            reason: fail.to_string(),
                        });
                    }
                }
                // How far the peer holds this node's feed, by its own frontier (ADR-028 R-6):
                // whatever became of the session, that is what it said.
                if let (Some(seq), Some(shared), Some(store)) = (
                    report.out.mine_held,
                    self.channels.get(&channel_id).map(Arc::clone),
                    self.profile.as_ref().map(Profile::store_handle),
                ) {
                    shared.lock().await.note_held(&store, peer, seq);
                }
                self.refresh_network_view().await;
                if report.fail.is_none() {
                    // When this room, and this peer, last completed a sync, for `vox status`
                    // (PRD-001 R35).
                    let now = self.now_ms().get();
                    self.status.room_synced.insert(channel_id, now);
                    self.status.member_synced.insert(peer, now);
                }
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
                        self.publish_channel_to_anchors(&channel_id, PublishCause::Governance)
                            .await;
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
                    self.say_session_news(&channel_id).await;
                }
                if let Some(sent) = heard {
                    self.finish_leave_if_heard(channel_id, sent).await;
                }
            }
            NetEvent::Status(reply) => {
                let _ = reply.send(self.status_report());
            }
            NetEvent::SessionRows { channel_id, reply } => {
                let rows = match self.channels.get(&channel_id).map(Arc::clone) {
                    Some(shared) => Some(shared.lock().await.session_rows().to_vec()),
                    None => None,
                };
                let _ = reply.send(rows);
            }
            NetEvent::Names(reply) => {
                let _ = reply.send(self.resolver_snapshot().await);
            }
            NetEvent::MemberDialer(reply) => {
                let _ = reply.send(
                    self.net
                        .as_ref()
                        .map(|net| {
                            MemberDialer(NodeDialer {
                                net: Arc::clone(net),
                                channel_id: None,
                            })
                        })
                        .ok_or(crate::error::Error::Unreachable(
                            "the node is not networked",
                        )),
                );
            }
            NetEvent::AppDial(crate::node::app::AppDial {
                channel_id,
                peer,
                reply,
            }) => {
                // Off the actor, as a forward's first dial is (#215): the ladder can take as long
                // as a peer that is gone takes to time out, and the daemon answers nothing else
                // meanwhile. The connection goes back as `NetEvent::Dialed`, which adopts it and
                // tries a better path behind a relayed one, as the actor's own dial did.
                let Some(net) = self.net.as_ref().map(Arc::clone) else {
                    let _ = reply.send(Err(crate::error::Error::Unreachable(
                        "node is not networked",
                    )));
                    return;
                };
                let endpoints = net.board_endpoints(&channel_id, &peer);
                let tx = self.net_tx.clone();
                tokio::spawn(async move {
                    let reached = net.reach(peer, &endpoints).await;
                    if let Ok(conn) = &reached {
                        let _ = tx
                            .send(NetEvent::Dialed {
                                conn: Arc::clone(conn),
                                endpoints,
                                board: false,
                            })
                            .await;
                    }
                    let _ = reply.send(reached);
                });
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
                    Inbound::Pairwise { .. } => {
                        // Unreachable: the stream loop reads these and sends
                        // `NetEvent::Pairwise` once the frames are in hand.
                    }
                    Inbound::Sync { .. } => {
                        // Unreachable: the stream loop converts these into
                        // `NetEvent::SyncRequest` once the preamble is read.
                    }
                    Inbound::Agree { .. } => {
                        // Unreachable: the stream loop reads these and sends
                        // `NetEvent::AgreeAsk` once the question is in hand.
                    }
                    Inbound::Seat { .. } => {
                        // Unreachable: the stream loop reads these and sends
                        // `NetEvent::SeatAsk` once the question is in hand.
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
                        // A UDP service binds its flow to this connection, so the task
                        // holds it for the flow's life.
                        let conn = Arc::clone(&connection);
                        let flows = Arc::clone(&self.udp_flows);
                        // The snapshot is taken here (only the actor reads channel
                        // state) and the tunnel runs on its own task: it lives as long
                        // as the TCP connection it carries, which may be hours.
                        let snapshot = self.host_snapshot().await;
                        // The host is told who reached what, because the carried
                        // service only ever sees loopback (ADR-017 decision 6).
                        let events = self.event_tx.clone();
                        let decisions = self.decisions.clone();
                        let alias = self.trust.petname(&peer).map(str::to_owned);
                        let clock = Arc::clone(&self.millis_clock);
                        // **The tunnel holds its connection for as long as it runs.** That
                        // is what tells `retire_expired` the path is still carrying, so a
                        // better path appearing does not close it under a live session.
                        let carried = Arc::clone(&connection);
                        // `vox status` lists the tunnel while it runs from the one list of live
                        // tunnels the credit keeps (V210-81): not a second list of its own.
                        tokio::spawn(async move {
                            let served = crate::node::tunnel::serve_reporting(
                                peer,
                                send,
                                recv,
                                snapshot,
                                Some(events.clone()),
                                Some(crate::tunnel::session::UdpHost { conn: &conn, flows }),
                                Some(&*carried),
                            )
                            .await;
                            let who: String = crate::node::link::b32_encode(&peer)
                                .chars()
                                .take(12)
                                .collect();
                            // The result used to be dropped here, so a host refusing a member —
                            // untrusted, no such service, its own service down — said nothing
                            // anywhere (PRD-001 R36).
                            // What this node decided about it, for its own record (ADR-028 D-1).
                            let decided = |d: crate::node::decisions::Decided, why: &str| {
                                decisions.record(
                                    clock(),
                                    &crate::node::decisions::Decision {
                                        asked: "a tunnel to a service",
                                        by: peer,
                                        alias: alias.clone(),
                                        decided: d,
                                        why: why.to_owned(),
                                        // The request names a service; which room serves it is
                                        // decided past here, and a refusal may come before any.
                                        room: None,
                                    },
                                );
                            };
                            match served {
                                // Refusals only: a session that ends in an error after it was
                                // accepted is a disconnect, not a no.
                                Err(crate::error::Error::TunnelDenied(why)) => {
                                    decided(crate::node::decisions::Decided::Refused, why);
                                    let e = crate::error::Error::TunnelDenied(why);
                                    let _ = events.send(NodeEvent::ProxyRefused {
                                        reason: format!("refused {who} a tunnel: {e}"),
                                    });
                                }
                                // Cut by a decision about reach: trust withdrawn, or the service
                                // no longer offered (M17.11, R22).
                                Err(crate::error::Error::TunnelRevoked(why)) => {
                                    decided(crate::node::decisions::Decided::Cut, why);
                                }
                                // Past the member's tunnel cap (#272): refused, by this node.
                                Err(crate::error::Error::TunnelLimit(why)) => {
                                    decided(crate::node::decisions::Decided::Refused, &why);
                                }
                                // Closed on purpose (V030-11): the host is told too, as a close.
                                Err(crate::error::Error::TunnelClosed(why)) => {
                                    // Cut here — by this node's person, or as stuck on this side —
                                    // is this node's decision; closed at the other end is not.
                                    if !why.contains(crate::tunnel::session::AT_THE_OTHER_END) {
                                        decided(crate::node::decisions::Decided::Cut, &why);
                                    }
                                    let e = crate::error::Error::TunnelClosed(why);
                                    let _ = events.send(NodeEvent::TunnelClosed {
                                        reason: format!("a session from {who}: {e}"),
                                    });
                                }
                                _ => {}
                            }
                        });
                    }
                    Inbound::App { peer, send, recv } => {
                        // The gate is read live by the serving task; refreshing here is the
                        // same backstop the tunnel path takes on every accept.
                        self.refresh_reachers().await;
                        tokio::spawn(crate::node::app::serve_inbound(
                            Arc::clone(&self.app),
                            Arc::clone(&connection),
                            peer,
                            send,
                            recv,
                        ));
                    }
                    Inbound::NotYetSupported { .. }
                    | Inbound::ServedRendezvous { .. }
                    | Inbound::ServedCoord { .. }
                    | Inbound::ServedCircuit { .. }
                    | Inbound::ServedGoodbye { .. } => {}
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
        let now_ms = (self.millis_clock)();
        // A room that ended takes nobody in, and a node that left it answers for it no more
        // (V030-08); each is said as what it is, before the challenge, so the joiner is not told its
        // passphrase is probably wrong. A member that left may join again, like anyone with the
        // passphrase.
        let (answerable, refusal) = match self.channels.get(&channel_id) {
            Some(shared) => {
                let c = shared.lock().await;
                if c.ended(now_ms).is_some() {
                    (false, Some(crate::node::joinstream::JoinReject::RoomEnded))
                } else if c.has_left(&c.me()) {
                    (
                        false,
                        Some(crate::node::joinstream::JoinReject::ResponderLeft),
                    )
                } else {
                    (c.can_answer_join() && c.epoch() == epoch, None)
                }
            }
            None => (false, None),
        };
        if !answerable {
            match refusal {
                Some(reason) => {
                    tokio::spawn(crate::node::joinstream::refuse_join_as(send, reason));
                }
                None => Self::spawn_refuse_join(send),
            }
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
        let source = crate::nat::source::Source::of_conn(&conn);
        let Some((mut slot, ended)) =
            crate::node::joinslots::JoinSlots::take(&self.join_slots, peer, source)
        else {
            // Past the cap: **refused, not queued**, and said out loud. A silent drop here
            // would leave the joiner reading a stream that never answers, which is the
            // failure shape this whole change exists to remove.
            let _ = self.event_tx.send(NodeEvent::JoinFailed {
                reason: format!(
                    "refused {}: already answering {JOINS_IN_FLIGHT} joins — it should retry",
                    crate::node::network::short_id(peer)
                ),
            });
            self.decided(
                "to join a room",
                peer,
                Some(channel_id),
                crate::node::decisions::Decided::Refused,
                format!("this node was already answering {JOINS_IN_FLIGHT} joins"),
            );
            // Told why (V210-92): a bare refusal reads to the joiner as a wrong passphrase.
            tokio::spawn(crate::node::joinstream::refuse_join_as(
                send,
                crate::node::joinstream::JoinReject::Busy,
            ));
            return;
        };
        if let Some(ended) = ended {
            // Said as plainly as a refusal: this is the one place a join already under way is
            // ended by this node rather than by its joiner or its patience.
            let _ = self.event_tx.send(NodeEvent::JoinFailed {
                reason: format!(
                    "ended {}'s join to answer {}: all {JOINS_IN_FLIGHT} join slots were held, \
                     {}/{}/{} from its source (coarse to fine) and {} by it; it is told the \
                     member is busy",
                    crate::node::network::short_id(ended.peer),
                    crate::node::network::short_id(peer),
                    ended.weight.0,
                    ended.weight.1,
                    ended.weight.2,
                    ended.weight.3,
                ),
            });
            self.decided(
                "to join a room",
                ended.peer,
                Some(channel_id),
                crate::node::decisions::Decided::Cut,
                format!(
                    "all {JOINS_IN_FLIGHT} join slots were held, and its join gave way to {}'s",
                    crate::node::network::short_id(peer)
                ),
            );
        }
        // Including the slot just taken, so the first joiner sees a load of 1. This is what
        // `Difficulty::adapted_for_load` is for, and it was passed a literal `0` until now — so the
        // anti-flood knob ADR-005 specifies, and ADR-016 describes as adapting "against the
        // responder's live queue", had never once adapted.
        //
        // This costs an ordinary joiner nothing: `Difficulty::ADAPT_THRESHOLD` is 4, so a load of
        // 1–3 adds zero bits and one person joining a quiet room does exactly the work it did
        // before. Past four it adds a bit per doubling of the queue, capped at `Difficulty::MAX`.
        let pending_joins = u32::try_from(crate::node::joinslots::JoinSlots::in_flight(
            &self.join_slots,
        ))
        .unwrap_or(u32::MAX);
        let tx = self.net_tx.clone();
        self.reap_join_tasks();
        let admit_tx = self.net_tx.clone();
        let signals = Some((slot.worked(), slot.take_ended()));
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
                    signals,
                    // **The admission lands before the joiner is told it is in.** Awaited here, on
                    // this task, so the actor is never the thing waiting — which is the whole point
                    // of the slot. See `NetEvent::JoinAdmit`.
                    |identity, witness| async move {
                        #[cfg(feature = "test-knobs")]
                        test_admission_gate().await;
                        // **Every online member agrees first** (V030-30, #366): the place is held
                        // here and promised by each member this node holds a connection to, or the
                        // joiner is refused, saying why, before anything is admitted.
                        let joiner = identity.fingerprint();
                        let promised = seat_round(&admit_tx, channel_id, joiner).await?;
                        let (ack, wait) = tokio::sync::oneshot::channel();
                        let admitted = if admit_tx
                            .send(NetEvent::JoinAdmit {
                                channel_id,
                                identity: Box::new(identity),
                                witness: Box::new(witness),
                                ack,
                            })
                            .await
                            .is_ok()
                        {
                            // A dropped sender resolves this too, so a shutting-down actor cannot
                            // strand a joiner mid-exchange; nothing admitted it, so it is refused.
                            wait.await.unwrap_or(Err(Error::JoinRefused(
                                "the member stopped before it admitted the joiner",
                            )))
                        } else {
                            Err(Error::JoinRefused(
                                "the member stopped before it admitted the joiner",
                            ))
                        };
                        let abort = crate::node::seatstream::Abort { channel_id, joiner };
                        if admitted.is_ok() {
                            // Committed: each promise stands until the newcomer reaches that
                            // member from a board.
                            promised
                                .into_iter()
                                .for_each(crate::node::seatstream::commit);
                        } else {
                            for send in promised {
                                crate::node::seatstream::abort(send, abort).await;
                            }
                            let _ = admit_tx
                                .send(NetEvent::SeatRelease { channel_id, joiner })
                                .await;
                        }
                        admitted
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
                // The exchange's reason is this node's own words: the joiner and the step that
                // failed, never what it offered.
                self.decided(
                    "to join a room",
                    peer,
                    Some(channel_id),
                    crate::node::decisions::Decided::Refused,
                    reason.clone(),
                );
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
            self.publish_channel_to_anchors(&channel_id, PublishCause::Join)
                .await;
        }
        self.adopt_join_session(channel_id, peer, outcome.session, false)
            .await;
        if let Some(net) = self.net.as_ref() {
            net.policy().forget_joiner(&peer);
        }
        // **Consent at admission, not on the tick** (ADR-007 G-15a). A room is ForwardOnly:
        // a newcomer reads only what is sealed after the key is released to it. With the
        // joiner already in this node's trust ring, leaving the release to the next tick
        // opened a window in which anything this node posted was unreadable to the
        // joiner for good. The actor is serial, so releasing here — before any later
        // command is served — means everything posted after the join is readable.
        self.deliver_owed_consents(None).await;
        self.joins_answered
            .retain(|_, at| at.elapsed() < JOINER_SEAL_GRACE);
        self.joins_answered
            .insert((channel_id, peer), std::time::Instant::now());
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
        let now = self.now_ms().get();
        let endpoint = Arc::clone(net.manager().endpoint());
        // Collected first: the borrow of `self.channels` cannot outlive the mutation of
        // `self.last_upgrade` below.
        let mut due: Vec<(Digest32, crate::nat::multiaddr::EndpointList)> = Vec::new();
        for (cid, shared) in &self.channels {
            let authors: Vec<Digest32> = {
                let ch = shared.lock().await;
                ch.members()
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
                if u128::from(now.saturating_sub(last)) < UPGRADE_RETRY.as_millis() {
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
    /// Remember where `conn`'s peer was reached, if the path is direct (`node::peer_book`),
    /// and save the book when that is news. A relay circuit's address means nothing to a
    /// later process and is never kept.
    fn note_peer_endpoint(&mut self, conn: &VoxConnection) {
        let Some(net) = self.net.as_ref() else {
            return;
        };
        if crate::node::net::path_class(net.manager().endpoint(), conn)
            == crate::node::net::PathClass::Relayed
        {
            return;
        }
        let now = self.now_ms().get();
        if !self
            .peer_book
            .note(conn.peer_id(), conn.quinn().remote_address(), now)
        {
            return;
        }
        if let Some(profile) = self.profile.as_ref() {
            if let Ok(signer) = profile.signer() {
                let _ = self.peer_book.save(profile.store(), signer);
            }
        }
    }

    fn adopt_connection(&mut self, conn: Arc<VoxConnection>) {
        self.note_peer_endpoint(&conn);
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

    /// Produce an invite link naming this node, and any anchors the room uses, as where to
    /// reach the room, with this node as responder.
    async fn invite(&mut self, channel_id: &Digest32) -> Outcome {
        let Some(net) = self.net.as_ref() else {
            return Outcome::Failed(Fault::NotNetworked);
        };
        if !self.channels.contains_key(channel_id) {
            return Outcome::Failed(Fault::UnknownChannel);
        }
        let anchors = self.link_boards(channel_id).await;
        // Each entry that is a member of the room — this node, and any other whose address the
        // room keeps — is marked one, so a joiner never keeps it as an anchor (V030-51).
        let me = net.local_id();
        let members: Vec<Digest32> = match self.channels.get(channel_id).map(Arc::clone) {
            Some(shared) => {
                let channel = shared.lock().await;
                anchors
                    .iter()
                    .map(|a| a.id)
                    .filter(|id| *id == me || channel.is_known_member(id))
                    .collect()
            }
            None => Vec::new(),
        };
        let link = match crate::node::link::InviteLink::new(*channel_id, anchors, Some(me), members)
        {
            Ok(l) => l,
            Err(e) => return Outcome::Failed(fault_of(&e)),
        };
        let _ = self.event_tx.send(NodeEvent::InviteLink {
            channel_id: *channel_id,
            url: link.to_url(),
        });
        Outcome::Done
    }

    /// The boards a link to `channel_id` names, in the order a joiner tries them.
    async fn link_boards(&self, channel_id: &Digest32) -> Vec<BootstrapNode> {
        let Some(net) = self.net.as_ref() else {
            return Vec::new();
        };
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
        // **This node always survives the cap** (V210-96, C6): it was appended last and then
        // truncated with the rest, so four anchors left the link naming no route to the host itself,
        // which always holds its room, and a guest who could reach it directly had no way to.
        anchors.retain(|a| a.id != net.local_id());
        let me = net
            .local_endpoints()
            .ok()
            .and_then(|own| BootstrapNode::new(net.local_id(), own).ok());
        anchors.truncate(crate::node::link::MAX_LINK_ANCHORS - usize::from(me.is_some()));
        anchors.extend(me);
        anchors
    }

    /// **An address is handed out at once whenever a guest could find the host through it**
    /// (V210-96), and says what it leaves out.
    ///
    /// `vox serve` printed its address while the room's first publish round to its anchor had not
    /// landed, or not started (a round goes only to an anchor this node is already connected to),
    /// and a guest who reached the anchor was told "board … has nothing for room …": CI macOS at
    /// 1a648c9, `a_first_direct_connection_is_prompt_proof`, 1 of 77 probes. That join could have
    /// reached the host itself — the link names it — and now does (`another_board_with_the_room`).
    ///
    /// **An anchor bridges hosts that cannot otherwise find each other, and nothing else needs
    /// one** (the decider, 2026-10-01). This node's own board always holds its room and the link
    /// names it, so an address that names any route of this node's own — a public address, a
    /// router's mapping, the local network or this machine — is handed out at once, and a note
    /// says which kinds it carries and which named anchors have not taken the room yet (and later,
    /// whether they did: `anchor_owed`). This node cannot know where its guests are.
    ///
    /// Only an address naming **no** route of this node's own — its addresses not yet discovered —
    /// waits: for that discovery, or for an anchor to take the room, up to [`ADDRESS_PATIENCE`].
    /// Past it the address is withheld and the reason given, board by board: an address that
    /// leads nowhere is worse than none, because the person hands it out and only learns later.
    async fn begin_invite(&mut self, channel_id: Digest32, reply: oneshot::Sender<Outcome>) {
        if self.net.is_none()
            || !self.channels.contains_key(&channel_id)
            || self.room_on_a_named_board(&channel_id).await
        {
            let outcome = self.hand_out_address(channel_id).await;
            let _ = reply.send(outcome);
            return;
        }
        self.address_serial += 1;
        let serial = self.address_serial;
        self.address_waiters.push((channel_id, reply, serial));
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(ADDRESS_PATIENCE).await;
            let _ = tx
                .send(NetEvent::AddressWaitOver { channel_id, serial })
                .await;
        });
    }

    /// The anchors a link to `room` names: every board it names but this node.
    async fn named_anchors(&self, room: &Digest32) -> Vec<Digest32> {
        let me = self.net.as_ref().map(|n| n.local_id());
        self.link_boards(room)
            .await
            .into_iter()
            .map(|b| b.id)
            .filter(|id| Some(*id) != me)
            .collect()
    }

    /// The anchors `room`'s address names: [`Self::named_anchors`] less the members it names.
    /// **A member the address names is a member at an address, never an anchor** (V030-51,
    /// AGENTS.md "Anchors"): the address carries members' addresses too (V210-167), and a member
    /// was said to be an anchor that "has not taken" the room it is in.
    async fn named_anchors_not_members(&self, room: &Digest32) -> Vec<Digest32> {
        let named = self.named_anchors(room).await;
        let Some(shared) = self.channels.get(room) else {
            return named;
        };
        let channel = shared.lock().await;
        named
            .into_iter()
            .filter(|id| !channel.is_known_member(id))
            .collect()
    }

    /// The routes of this node's own an address would name: what it advertises.
    fn own_routes(&self) -> Vec<crate::nat::multiaddr::Multiaddr> {
        self.net
            .as_ref()
            .and_then(|n| n.local_endpoints().ok())
            .map(|e| e.addrs().to_vec())
            .unwrap_or_default()
    }

    /// Whether `room` can be found through its link now: the link names a route of this node's
    /// own — whose board always holds the room — or an anchor it names holds it (see `on_board`).
    /// Neither, and the link would name nowhere a guest could find the room (C5: before address
    /// discovery, a node bound to a wildcard knows no address of its own).
    async fn room_on_a_named_board(&self, room: &Digest32) -> bool {
        if !self.own_routes().is_empty() {
            return true;
        }
        let named = self.named_anchors(room).await;
        named.iter().any(|b| self.on_board.contains(&(*room, *b)))
    }

    /// What kinds of route of this node's own an address carries, in plain words, each once. This
    /// node can classify an address; it cannot confirm that anyone outside can reach it.
    fn route_kinds(&self, routes: &[crate::nat::multiaddr::Multiaddr]) -> Vec<&'static str> {
        let mut kinds: Vec<&'static str> = Vec::new();
        for sa in routes
            .iter()
            .filter_map(crate::nat::multiaddr::Multiaddr::socket_addr)
        {
            let ip = sa.ip().to_canonical();
            let kind = if ip.is_loopback() {
                "this machine"
            } else if self
                .presence
                .as_ref()
                .map(|(p, _)| p.port_mappings())
                .unwrap_or_default()
                .iter()
                .any(|m| m.external_ip == Some(ip) && m.external_port == sa.port())
            {
                "a port mapping the router granted (nobody has confirmed it reachable)"
            } else if crate::nat::reachability::is_routable(&ip) {
                "a public address"
            } else {
                "the local network"
            };
            if !kinds.contains(&kind) {
                kinds.push(kind);
            }
        }
        kinds
    }

    /// Mint the address, then say what it carries: which kinds of route to this node, and which
    /// anchors it names that have not taken the room yet — each said again when it does, or when
    /// [`ADDRESS_PATIENCE`] passes without (`NetEvent::AnchorNoteDue`).
    async fn hand_out_address(&mut self, room: Digest32) -> Outcome {
        let outcome = self.invite(&room).await;
        if !outcome.is_done() {
            return outcome;
        }
        let short = crate::node::network::short_id;
        let routes = self.own_routes();
        let pending: Vec<Digest32> = self
            .named_anchors_not_members(&room)
            .await
            .into_iter()
            .filter(|b| !self.on_board.contains(&(room, *b)))
            .collect();
        let mut note = if routes.is_empty() {
            "this node does not know an address of its own yet, so the address names only its \
             anchors"
                .to_owned()
        } else {
            format!(
                "the address names this host directly — {} — and a guest who can reach that joins \
                 without an anchor",
                self.route_kinds(&routes).join(", ")
            )
        };
        if !pending.is_empty() {
            let names: Vec<String> = pending.iter().map(|b| short(*b)).collect();
            note.push_str(&format!(
                "; anchor {} has not taken room {} yet, so a guest who cannot reach this host \
                 directly must wait for it (this node will say when it has)",
                names.join(", "),
                short(room)
            ));
            self.address_serial += 1;
            let serial = self.address_serial;
            for b in pending {
                self.anchor_owed.insert((room, b), serial);
            }
            let tx = self.net_tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(ADDRESS_PATIENCE).await;
                let _ = tx
                    .send(NetEvent::AnchorNoteDue {
                        channel_id: room,
                        serial,
                    })
                    .await;
            });
        }
        let _ = self.event_tx.send(NodeEvent::AddressNote {
            channel_id: room,
            note,
        });
        outcome
    }

    /// Hand out every address waiting on `room`, if a guest could find the room through it now.
    async fn answer_addresses(&mut self, room: Digest32) {
        if !self.address_waiters.iter().any(|(r, _, _)| *r == room)
            || !self.room_on_a_named_board(&room).await
        {
            return;
        }
        let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.address_waiters)
            .into_iter()
            .partition(|(r, _, _)| *r == room);
        self.address_waiters = waiting;
        for (_, reply, _) in ready {
            let outcome = self.hand_out_address(room).await;
            let _ = reply.send(outcome);
        }
    }

    /// Why `board` does not hold `room`, as far as this node knows.
    fn why_not_on(&self, room: Digest32, board: Digest32) -> String {
        let connected = self
            .net
            .as_ref()
            .is_some_and(|n| n.manager().existing(&board).is_some());
        match (connected, self.publish_trouble.get(&(room, board))) {
            (_, Some(trouble)) => format!("its publish round failed: {trouble}"),
            (true, None) => "connected, and no publish round to it has finished".to_owned(),
            (false, None) => "this node has not reached it".to_owned(),
        }
    }

    /// Name each anchor an address handed out at `serial` named that has still not taken `room`.
    fn say_anchors_that_never_took(&mut self, room: Digest32, serial: u64) {
        let late: Vec<Digest32> = self
            .anchor_owed
            .iter()
            .filter(|((r, _), s)| *r == room && **s == serial)
            .map(|((_, b), _)| *b)
            .collect();
        let short = crate::node::network::short_id;
        for b in late {
            // Kept, as said: the anchor taking the room later is still worth saying (serial 0
            // matches no wait).
            self.anchor_owed.insert((room, b), 0);
            let _ = self.event_tx.send(NodeEvent::AddressNote {
                channel_id: room,
                note: format!(
                    "anchor {} has not taken room {} after {}s ({}): only a guest who can reach \
                     this host directly can join",
                    short(b),
                    short(room),
                    ADDRESS_PATIENCE.as_secs(),
                    self.why_not_on(room, b)
                ),
            });
        }
    }

    /// Withhold the address waited on since `serial`, if it is still waiting, and say why: this
    /// node has no address of its own to put in it, and for each anchor it names, whether this node
    /// reached it and what its last publish round said.
    async fn withhold_address(&mut self, room: Digest32, serial: u64) {
        let Some(at) = self
            .address_waiters
            .iter()
            .position(|(r, _, s)| *r == room && *s == serial)
        else {
            return;
        };
        let (_, reply, _) = self.address_waiters.remove(at);
        let short = crate::node::network::short_id;
        let boards: Vec<String> = self
            .named_anchors(&room)
            .await
            .into_iter()
            .map(|b| format!("board {}: {}", short(b), self.why_not_on(room, b)))
            .collect();
        // No anchor named is said as that, not as an anchor that failed: none was needed until
        // this node turned out to know no address of its own.
        let anchors = if boards.is_empty() {
            "it names no anchor".to_owned()
        } else {
            format!("no anchor it names holds the room — {}", boards.join("; "))
        };
        let _ = self.event_tx.send(NodeEvent::AddressWithheld {
            channel_id: room,
            reason: format!(
                "after {}s this node still knows no address of its own to put in the address of \
                 room {}, and {anchors}, so it would lead nowhere",
                ADDRESS_PATIENCE.as_secs(),
                short(room),
            ),
        });
        let _ = reply.send(Outcome::Failed(Fault::BoardUnreachable));
    }

    /// How long a join keeps looking for a board before refusing.
    ///
    /// Shorter than `up::HOST_PATIENCE` on purpose: `vox up` waits on a *service host* who
    /// may be a person at another desk, while this waits on infrastructure that is either
    /// coming up now or is not there.
    const BOARD_PATIENCE: Duration = Duration::from_secs(30);

    /// Interval between rounds. A board that is ready costs a joiner one dial.
    const BOARD_RETRY: Duration = Duration::from_millis(250);

    /// Join a channel from an invite link (ADR-016 §"Join over the network"): reach a
    /// board (the link's entries, the room's host among them, and this node's anchors), read
    /// it, announce a pre-join record, run the ADR-005 join, then build local channel state
    /// and publish our own records.
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
        // A room this identity left is joined again from scratch (V030-08: rejoining is just
        // joining again): what this node still holds of it goes first.
        if let Some(shared) = self.channels.get(&parsed.channel_id).map(Arc::clone) {
            let left = {
                let ch = shared.lock().await;
                ch.has_left(&ch.me())
            };
            if left {
                if let Outcome::Failed(f) = self.purge_room(&parsed.channel_id).await {
                    let _ = reply.send(Outcome::Failed(f));
                    return;
                }
            }
        }
        if self.channels.contains_key(&parsed.channel_id) {
            // A held room's address is where its host is now (V210-167), not a refusal: see
            // `reach_by_address`.
            self.reach_by_address(&parsed, net, reply).await;
            return;
        }
        let Some(profile) = self.profile.as_ref() else {
            let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
            return;
        };
        // **A room this profile holds, closed, is opened by its passphrase** (#412): joining it
        // again found it in the profile and failed as an internal error, so a member whose room
        // stayed closed could not get back in. Its address and passphrase are what open it.
        if matches!(
            profile.store().get_sek_wrap(&parsed.channel_id),
            Ok(Some(_))
        ) {
            self.begin_open_channel(parsed.channel_id, passphrase, reply);
            return;
        }
        let Ok(signer) = profile.signer_arc() else {
            let _ = reply.send(Outcome::Failed(Fault::Locked));
            return;
        };
        let now_ms = self.now_ms();
        // The pre-join record is stamped in milliseconds.
        let now = now_ms.get();
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
            // Nothing was tried, so say so rather than leave the person to read "did not answer"
            // about a board nobody dialled (V210-107).
            let _ = self.event_tx.send(NodeEvent::JoinFailed {
                reason: "the address names only this node, and this node has no anchor: there \
                         was no board to ask"
                    .to_owned(),
            });
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
            secret_work: Arc::clone(&self.secret_work),
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
                    passphrase,
                    now: now_ms,
                    me,
                    result: Box::new(result),
                })
                .await;
        });
    }

    /// A room's address given for a room this node already holds: **the address is where its host
    /// is now** (V210-167). It was refused ("already holds that room"), so a member whose host
    /// had moved had no way to say where it went. The members it names are dialled there, even
    /// when a connection to one is held elsewhere; the members that answer there, and the anchors
    /// it names, are kept as the room's (`keep_room_address`), so the next start dials them there
    /// too. An address nobody answers at changes nothing: a stale
    /// one from chat history must not overwrite where the room's members really are. `Done` once
    /// a member answered; `Unreachable` (said with why) when none did; `BadLink` when the address
    /// names no other member of the room, which is so when this node is its host.
    async fn reach_by_address(
        &mut self,
        parsed: &crate::node::link::InviteLink,
        net: Arc<NodeNet>,
        reply: oneshot::Sender<Outcome>,
    ) {
        let room = parsed.channel_id;
        let me = net.local_id();
        let mut named = BootstrapSet::new();
        for a in parsed.anchors.iter().filter(|a| a.id != me) {
            let _ = named.add(a.clone());
        }
        let mut members: Vec<(Digest32, Vec<std::net::SocketAddr>)> = Vec::new();
        if let Some(shared) = self.channels.get(&room).map(Arc::clone) {
            let channel = shared.lock().await;
            for n in named.nodes() {
                if channel.is_known_member(&n.id) {
                    members.push((n.id, n.endpoints.direct_candidates()));
                }
            }
        }
        if members.is_empty() {
            let why = if parsed.anchors.iter().any(|a| a.id == me) {
                "the address names this node as the room's host, and no other member, so there \
                 is nobody to reach"
            } else {
                "the address names no member of this room, so there is nobody to reach"
            };
            let _ = self.event_tx.send(NodeEvent::JoinFailed {
                reason: why.to_owned(),
            });
            let _ = reply.send(Outcome::Failed(Fault::BadLink));
            return;
        }
        let tx = self.net_tx.clone();
        let events = self.event_tx.clone();
        tokio::spawn(async move {
            let mut dials = tokio::task::JoinSet::new();
            for (peer, candidates) in members {
                let net = Arc::clone(&net);
                dials.spawn(async move {
                    // Not `connect_to`: it hands back a connection held on another port or
                    // through a relay without dialling, and that says nothing about this
                    // address.
                    let got = net.manager().answers_at(peer, &candidates).await;
                    (peer, candidates, got)
                });
            }
            let mut answered: Vec<Digest32> = Vec::new();
            let mut missed: Vec<String> = Vec::new();
            while let Some(Ok((peer, candidates, got))) = dials.join_next().await {
                match got {
                    Ok(conn) => {
                        answered.push(peer);
                        let endpoints = crate::nat::multiaddr::EndpointList::new(
                            candidates.into_iter().map(Into::into).collect(),
                        )
                        .unwrap_or_default();
                        let _ = tx
                            .send(NetEvent::Dialed {
                                conn,
                                endpoints,
                                board: false,
                            })
                            .await;
                    }
                    Err(e) => {
                        missed.push(format!("{} — {e}", crate::node::network::short_id(peer)));
                    }
                }
            }
            if answered.is_empty() {
                let _ = events.send(NodeEvent::JoinFailed {
                    reason: format!("nobody answered at that address: {}", missed.join("; ")),
                });
                let _ = reply.send(Outcome::Failed(Fault::Unreachable));
            } else {
                let _ = tx
                    .send(NetEvent::AddressReached {
                        room,
                        named,
                        answered,
                        reply,
                    })
                    .await;
            }
        });
    }

    /// A held room's address that a member answered at: keep, as the room's, the members that
    /// answered there and the anchors it names, dial those anchors, and answer the join `Done`
    /// (V210-167). A member it names that did not answer keeps the address this node had for it:
    /// only an answer shows a member is where the address says.
    async fn keep_room_address(
        &mut self,
        room: Digest32,
        named: &BootstrapSet,
        answered: &[Digest32],
        reply: oneshot::Sender<Outcome>,
    ) {
        let mut anchors: Vec<(Digest32, Vec<std::net::SocketAddr>)> = Vec::new();
        if let Some(shared) = self.channels.get(&room).map(Arc::clone) {
            let mut channel = shared.lock().await;
            let mut kept = BootstrapSet::new();
            for n in named.nodes() {
                if answered.contains(&n.id) || !channel.is_known_member(&n.id) {
                    let _ = kept.add(n.clone());
                }
            }
            if let Some(profile) = self.profile.as_ref() {
                let _ = channel.add_anchors(profile.store(), &kept);
            }
            let mut own = BootstrapSet::new();
            for n in channel.anchors().nodes() {
                if !channel.is_known_member(&n.id) {
                    let _ = own.add(n.clone());
                }
            }
            self.room_anchors.insert(room, own);
            for n in named.nodes() {
                if !channel.is_known_member(&n.id) {
                    anchors.push((n.id, n.endpoints.direct_candidates()));
                }
            }
        }
        if let Some(net) = self.net.clone() {
            for (id, candidates) in anchors {
                self.anchor_ids.insert(id);
                self.dial_anchor(&net, id, candidates);
            }
        }
        let _ = self.event_tx.send(NodeEvent::NodeNote {
            note: format!(
                "room {}: a member answered at the address given, which is kept as the room's \
                 from now on",
                crate::node::network::short_id(room)
            ),
        });
        let _ = reply.send(Outcome::Done);
    }

    /// Everything after the join exchange: make the room from the sealed key, record how this
    /// node was admitted, learn who else is in it, and publish — the part that has to be on the
    /// actor, and was the tail of the old inline `join_channel`.
    async fn finish_join_channel(
        &mut self,
        parsed: crate::node::link::InviteLink,
        passphrase: Secret,
        now_ms: crate::time::Ms,
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
        // **One room of a name** (ADR-028 R-3): a room joined under a name a room here already
        // has is refused, naming the room that holds it. Only a name the member said is known
        // yet; one the log brings later shows both rooms by their ids until one is renamed.
        if let Some(holder) = joined
            .room_name
            .as_deref()
            .and_then(|name| self.room_named(name).map(|id| (name, id)))
        {
            let _ = self.event_tx.send(NodeEvent::JoinFailed {
                reason: format!(
                    "the room is called {}, and the room {} on this node already is",
                    holder.0,
                    crate::node::link::b32_encode(&holder.1)
                        .chars()
                        .take(12)
                        .collect::<String>()
                ),
            });
            return Outcome::Failed(Fault::RoomNameTaken);
        }
        let channel = {
            let Some(profile) = self.profile.as_ref() else {
                return Outcome::Failed(Fault::NoIdentity);
            };
            match ChannelState::join_channel_from_sealed(
                profile,
                &genesis,
                &parsed.channel_id,
                joined.room_name.as_deref(),
                &passphrase,
                now_ms,
                sealed,
                // Keep the responder's witness to this join (M17.6). It is republished with
                // every bundle record this node ever puts on a board for this room, so it is
                // persisted rather than held: a node that lost it could publish nothing and
                // would fall off every board. The joiner already verified it binds its own key,
                // this room and this epoch, in `run_initiator`. Written with the room, in one
                // batch, so a join that fails here leaves no room behind (V210-80).
                crate::nat::record::Admission::Witnessed(Box::new(joined.witness.clone())),
            ) {
                Ok(c) => c,
                Err(e) => return Outcome::Failed(fault_of(&e)),
            }
        };
        let mut channel = channel;
        channel.set_node_retention(self.node_retention_for(&parsed.channel_id));
        // A room joined again is published again (V030-14): its withdraw is kept no longer.
        self.withdrawn.remove(&parsed.channel_id);
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
            let _ = admit_board_records(
                &shared,
                profile.store(),
                &set.bundles,
                ChannelState::MAX_ADMISSIONS_PER_SWEEP,
                now_ms,
                self.net.as_deref(),
            )
            .await;
        }
        // An admission changes a room's author set, the other half of the reacher join.
        self.refresh_reachers().await;
        self.adopt_join_session(parsed.channel_id, responder, joined.session, true)
            .await;
        // **The member that answered the join is a member, not an anchor** (V030-51): the link
        // names it with an address, as it names the room's anchors, and its record may not be
        // among those admitted yet. Recorded first, so the anchors adopted below leave it out.
        if let (Some(profile), Some(shared)) = (
            self.profile.as_ref(),
            self.channels.get(&parsed.channel_id).map(Arc::clone),
        ) {
            let mut channel = shared.lock().await;
            let _ = channel.note_member(profile.store(), responder);
            // And every member the link marks one (`m=`).
            for member in parsed.members.iter().filter(|m| **m != me) {
                let _ = channel.note_member(profile.store(), *member);
            }
        }
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
        self.publish_channel_to_anchors(&parsed.channel_id, PublishCause::Join)
            .await;
        if !self.anchor_ids.contains(&conn.peer_id()) {
            self.publish_channel_to_anchor(&parsed.channel_id, &conn, PublishCause::Join)
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
        history: crate::node::trust::HistoryGrant,
    ) -> Outcome {
        let full = history == crate::node::trust::HistoryGrant::Full;
        // **A key goes only to a member the owner's keyring trusts** (V210-148), checked here,
        // where the key leaves, whatever asked for it. No client — the TUI, the CLI, the control
        // socket — can hand this identity's key to someone its owner never trusted: a client
        // that could would be a hole in the core, not a choice in the client.
        if !self.trust.is_trusted(&target) {
            return Outcome::Failed(Fault::NotTrusted);
        }
        if self.net.is_none() {
            return Outcome::Failed(Fault::NotNetworked);
        }
        let now_ms = self.now_ms();
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
            // The grant is written to the log, which a room just joined waits for (V210-164):
            // checked before the key goes, not after.
            if !channel.is_settled() {
                return Outcome::Failed(Fault::RoomNotSynced);
            }
            // PRD-001 R12's full history, or V210-45's decision-dated plan (`consent_release`).
            match consent_release(
                &mut self.consent_keys,
                profile,
                &channel,
                channel_id,
                target,
                full,
                decision,
            ) {
                Ok((skdm, p)) => {
                    plan = p;
                    skdm
                }
                Err(e) => return Outcome::Failed(fault_of(&e)),
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
        // Sealed here, where the session lives; written by this member's writer, off the actor
        // (V210-71). A write that fails is a key not taken, re-owed like any other.
        let mut frames = Vec::with_capacity(2);
        if let Some(initial) = hello.as_ref() {
            frames.push(crate::node::pairwise_stream::hello_frame(
                channel_id, initial,
            ));
        }
        match crate::node::pairwise_stream::skdm_frame(channel_id, session, &skdm) {
            Ok(f) => frames.push(f),
            Err(e) => return Outcome::Failed(fault_of(&e)),
        }
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
        if let Err(e) = forget_consent_key(&mut self.consent_keys, profile, channel_id, target) {
            return Outcome::Failed(fault_of(&e));
        }
        let history_owed = {
            let mut channel = shared.lock().await;
            // What this consent releases, from its earliest position (V210-45): every later
            // release to `target` starts there and never before it.
            let entitled_from = plan
                .as_ref()
                .and_then(|p| p.first().copied())
                .unwrap_or((skdm.body.chain_id, skdm.body.iteration));
            // The generations before the live one that the decision — or a full-history grant —
            // covers (V210-45, PRD-001 R12) are owed in the grant's own transaction (V210-88).
            match channel.issue_consent(profile, target, &skdm, full, entitled_from, now_ms) {
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
        // In flight from here until the member answers (V210-88): a crash before then leaves it owed.
        let epoch = self.key_in_flight(*channel_id, target);
        self.write_pairwise(
            target,
            PairwiseJob {
                conn,
                frames,
                channel_id: *channel_id,
                after: AfterWrite::Key {
                    chain_id,
                    hello: hello.is_some(),
                    session: self.session_serial.get(&(*channel_id, target)).copied(),
                    history: false,
                    epoch,
                },
            },
        );
        if history_owed {
            // At once rather than on the tick: the connection and session are live now.
            let _ = self.deliver_rekeys_for(channel_id, asked).await;
        }
        Outcome::Done
    }

    /// Release this identity's key to `target`, a member its owner's keyring trusts (ADR-020 §3).
    /// The trust decision is the human one; nothing consents per room (V210-148).
    fn consent<'a>(
        &'a mut self,
        channel_id: &'a Digest32,
        target: Digest32,
        asked: bool,
    ) -> Boxed<'a, Outcome> {
        Box::pin(self.consent_unboxed(channel_id, target, asked))
    }

    /// [`Self::consent`], unboxed: see [`Boxed`].
    async fn consent_unboxed(
        &mut self,
        channel_id: &Digest32,
        target: Digest32,
        asked: bool,
    ) -> Outcome {
        let history = self.trust.history(&target);
        let outcome = self
            .release_key_to(channel_id, target, asked, history)
            .await;
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

    /// Draw `fingerprint`'s place in the consent order for a new trust decision and persist it
    /// (V210-45): what [`Self::trust_decision`] reads. Floored by every open room's newest
    /// generation, so a lost or rolled-back counter cannot make one of them look minted after
    /// this decision. `None` if it could not be drawn: the decision then entitles to no history,
    /// narrower and never wider.
    async fn draw_trust_stamp(
        &mut self,
        fingerprint: Digest32,
    ) -> Option<crate::node::consent_order::Stamp> {
        let profile = self.profile.as_ref()?;
        let signer = profile.signer().ok()?;
        let shared: Vec<_> = self.channels.values().map(Arc::clone).collect();
        let mut floor = 0u64;
        for ch in &shared {
            floor = floor.max(ch.lock().await.newest_mint_seq());
        }
        crate::node::consent_order::stamp_trust(profile.store(), signer, fingerprint, floor).ok()
    }

    /// Mark where every open room's sender key stands at `fingerprint`'s trust decision, drawn by
    /// [`Self::draw_trust_stamp`] (V210-45).
    async fn mark_trust_decision(
        &mut self,
        fingerprint: Digest32,
        decision: crate::node::consent_order::Stamp,
    ) {
        let Some(profile) = self.profile.as_ref() else {
            return;
        };
        let shared: Vec<_> = self.channels.values().map(Arc::clone).collect();
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

    /// Drop, in a room just opened, every sender key held from a member this owner does not trust
    /// (V210-118): one stopped being trusted while the room was closed, or a key taken before this
    /// node refused untrusted keys. Rendered messages stay; nothing more of theirs opens.
    /// Act, in a room just opened, on every removal from the ring made while it was closed
    /// (V210-118 amendment): drop the member's keys and change the lock — revoke and rotate, as a
    /// removal does in an open room — then clear the record. Every consent to a member the ring
    /// does not name is withdrawn too (V210-148): a key goes only to a member the owner trusts.
    async fn act_on_removals_while_closed(&mut self, channel_id: &Digest32) {
        self.forget_untrusted_keys(channel_id).await;
        self.revoke_untrusted_consents(channel_id).await;
        let (Some(profile), Some(shared)) = (
            self.profile.as_ref(),
            self.channels.get(channel_id).map(Arc::clone),
        ) else {
            return;
        };
        let Ok(signer) = profile.signer() else {
            return;
        };
        let Ok(mut locks) = crate::node::pending_lock::PendingLocks::load(profile.store(), signer)
        else {
            return;
        };
        let removed = locks.for_room(channel_id);
        if removed.is_empty() {
            return;
        }
        let mut owed = Vec::new();
        {
            let channel = shared.lock().await;
            for member in removed {
                if !self.trust.is_trusted(&member) && channel.has_consented(&member) {
                    owed.push(member);
                }
            }
        }
        // The lock changes before the record goes: a failure in between changes it again on the
        // next open, which narrows nothing that should be read.
        for member in owed {
            let _ = self.revoke(channel_id, member).await;
        }
        let Some(profile) = self.profile.as_ref() else {
            return;
        };
        let Ok(signer) = profile.signer() else {
            return;
        };
        if locks.clear_room(channel_id) {
            let _ = locks.save(profile.store(), signer);
        }
    }

    /// Withdraw every consent this identity holds in `channel_id` for a member its keyring does
    /// not trust (V210-148). A key goes only to a member the owner trusts, so a consent outside
    /// the keyring — one a room-only grant made before that grant was removed, or one the ring
    /// lost while the room was closed — changes the lock against that member. What it already
    /// holds cannot be taken back; it reads nothing written from now on.
    async fn revoke_untrusted_consents(&mut self, channel_id: &Digest32) {
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return;
        };
        let untrusted: Vec<Digest32> = shared
            .lock()
            .await
            .consented()
            .into_iter()
            .filter(|m| !self.trust.is_trusted(m))
            .collect();
        for member in untrusted {
            let _ = self.revoke(channel_id, member).await;
        }
    }

    async fn forget_untrusted_keys(&mut self, channel_id: &Digest32) {
        let (Some(profile), Some(shared)) = (
            self.profile.as_ref(),
            self.channels.get(channel_id).map(Arc::clone),
        ) else {
            return;
        };
        let trusted = self.trust.trusted();
        let _ = shared
            .lock()
            .await
            .forget_keys_except(profile.store(), &trusted);
    }

    /// Trust `fingerprint` node-wide under `petname` (ADR-020 §3), then act on it
    /// at once so the operator does not wait a tick to see the effect.
    fn trust_identity<'a>(
        &'a mut self,
        fingerprint: Digest32,
        petname: &'a str,
        history: crate::node::trust::HistoryGrant,
        capability: Option<crate::node::trust::Capability>,
    ) -> Boxed<'a, Outcome> {
        Box::pin(self.trust_identity_unboxed(fingerprint, petname, history, capability))
    }

    /// [`Self::trust_identity`], unboxed: see [`Boxed`].
    async fn trust_identity_unboxed(
        &mut self,
        fingerprint: Digest32,
        petname: &str,
        history: crate::node::trust::HistoryGrant,
        capability: Option<crate::node::trust::Capability>,
    ) -> Outcome {
        match self.profile.as_ref().map(Profile::signer) {
            None => return Outcome::Failed(Fault::NoIdentity),
            Some(Err(e)) => return Outcome::Failed(fault_of(&e)),
            Some(Ok(_)) => {}
        }
        let newly = !self.trust.is_trusted(&fingerprint);
        let had_drive = self.trust.has_drive(&fingerprint);
        let capability = capability
            .or_else(|| self.trust.capability(&fingerprint))
            .unwrap_or_default();
        let mut next = self.trust.clone();
        if let Err(e) = next.trust_as(fingerprint, petname, history, capability) {
            return Outcome::Failed(fault_of(&e));
        }
        // **The decision's place in the consent order is drawn before the trust is saved**
        // (V210-45, V210-88). Drawn after, a crash between the two left a trusted member with no
        // place, read on the restart as a decision from before the order was kept: its key was
        // released from wherever the sender stood when the consent at last went out, and every
        // post made since the restart was lost to it. Drawn first, a crash before the save leaves
        // a place for an identity not trusted, which counts for nothing and is drawn again by
        // the next trust; a crash after it leaves both, and each room marks the decision as it
        // reopens, before anything is posted there.
        let decision = if newly {
            self.draw_trust_stamp(fingerprint).await
        } else {
            None
        };
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let signer = match profile.signer() {
            Ok(s) => s,
            Err(e) => return Outcome::Failed(fault_of(&e)),
        };
        // Persist BEFORE adopting it: a keyring that consented but did not survive
        // a restart would silently re-consent on every boot.
        if let Err(e) = next.save(profile.store(), signer) {
            return Outcome::Failed(fault_of(&e));
        }
        self.trust = next;
        self.note_capability(fingerprint, had_drive);
        // A removal still waiting on a closed room is withdrawn with this decision (V210-118
        // amendment). Not load-bearing: left behind, it would change the lock on the reopen, and
        // the consent owed to a trusted member would then be released again.
        if let Ok(mut locks) =
            crate::node::pending_lock::PendingLocks::load(profile.store(), signer)
        {
            if locks.forget(&fingerprint) {
                let _ = locks.save(profile.store(), signer);
            }
        }
        if let Some(decision) = decision {
            // Where each open room's sender key stands at the decision (V210-45). A rename is
            // the same decision and keeps its place. Nothing else runs on the actor in between,
            // so no post is sealed between the place and the marks. A failure here narrows what
            // the member will read and never widens it, so it does not undo the trust.
            self.mark_trust_decision(fingerprint, decision).await;
        }
        // The reacher sets are a join of the ring with each room's author set, so both
        // inputs must push. Immediately, not on the tick: a stream parked open across
        // this instant is judged by the set as it stands when its request lands (M17.11).
        self.refresh_reachers().await;
        self.deliver_owed_consents(Some(fingerprint)).await;
        // A key that reached this node by the log from the member just trusted was held
        // (V210-118): taken now.
        let rooms: Vec<Digest32> = self.channels.keys().copied().collect();
        for channel_id in rooms {
            if let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) {
                shared.lock().await.release_held_packages();
            }
            self.install_key_packages(&channel_id).await;
        }
        self.publish().await;
        Outcome::Done
    }

    /// Stop trusting `fingerprint` (ADR-020 §3).
    ///
    /// Forward-looking by construction: it changes who *future* consent is issued
    /// to and recalls nothing already granted. Recalling that is `Revoke`, per
    /// room — ADR-007's enforcement honesty, which this must not paper over.
    fn untrust_identity<'a>(&'a mut self, fingerprint: &'a Digest32) -> Boxed<'a, Outcome> {
        Box::pin(self.untrust_identity_unboxed(fingerprint))
    }

    /// [`Self::untrust_identity`], unboxed: see [`Boxed`].
    async fn untrust_identity_unboxed(&mut self, fingerprint: &Digest32) -> Outcome {
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let signer = match profile.signer() {
            Ok(s) => s,
            Err(e) => return Outcome::Failed(fault_of(&e)),
        };
        let had_drive = self.trust.has_drive(fingerprint);
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
        // **A room that is closed now acts on the removal when it opens** (V210-118 amendment):
        // its key is not held while it is closed, so neither the lock change nor the key drop
        // below can reach it. Recorded before the ring is written, so a removal whose record
        // cannot be kept is refused whole rather than left undone in the closed rooms.
        let closed: Vec<Digest32> = profile
            .store()
            .channels()
            .unwrap_or_default()
            .into_iter()
            .filter(|c| !self.channels.contains_key(c))
            .collect();
        if !closed.is_empty() {
            let mut locks =
                match crate::node::pending_lock::PendingLocks::load(profile.store(), signer) {
                    Ok(l) => l,
                    Err(e) => return Outcome::Failed(fault_of(&e)),
                };
            for room in closed {
                if !locks.insert(room, *fingerprint) {
                    return Outcome::Failed(Fault::Internal);
                }
            }
            if let Err(e) = locks.save(profile.store(), signer) {
                return Outcome::Failed(fault_of(&e));
            }
        }
        // The ring is written FIRST and unconditionally, exactly as a revocation's
        // log fact lands before its re-keys: if the rotations below cannot all be
        // delivered, the decision must still have been taken. A removal that were
        // undone by an unreachable peer would be a removal in name only.
        if let Err(e) = next.save(profile.store(), signer) {
            return Outcome::Failed(fault_of(&e));
        }
        self.trust = next;
        self.note_capability(*fingerprint, had_drive);
        // **It stops being read here too** (V210-118): its keys are dropped in every open room, so
        // nothing it posts from now opens on this node. A closed room drops them, and changes its
        // lock, when it opens (recorded above). What was already read stays read. A re-trust is
        // offered its key again, as any member whose key this node does not hold.
        let trusted = self.trust.trusted();
        let shared: Vec<_> = self.channels.values().map(Arc::clone).collect();
        for ch in shared {
            let _ = ch
                .lock()
                .await
                .forget_keys_except(profile.store(), &trusted);
        }
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
            if shared.lock().await.has_consented(removed) {
                // `revoke` is the whole act: rotate, record the log fact, re-key the
                // members who keep consent, and emit `Revoked`.
                let _ = self.revoke(&channel_id, *removed).await;
            }
            // And any other consent outside the keyring (V210-148): a key goes only to a member
            // the owner trusts, so nothing the ring does not name keeps one past this.
            self.revoke_untrusted_consents(&channel_id).await;
        }
    }

    /// Delete every superseded sender-key generation this node no longer needs
    /// (ADR-023 decision 4, PRD-001 R14), room by room. Kept: every generation while a
    /// trusted identity with a **full-history** grant is still owed its consent there; and
    /// otherwise every generation from the oldest a decision-dated release still owes
    /// (V210-45) — a trusted identity not yet consented to, joined or not, and history not
    /// yet delivered. Deleting those left a member trusted before it joined unable to read
    /// what was posted after its trust (found by #226's log-path proof: 3 of 6).
    ///
    /// Returns whether any generation went, so the view `vox status` reads is published again:
    /// it carries the counts, and nothing else on a quiet tick republishes it.
    async fn prune_superseded_keys(&mut self) -> bool {
        let Some(store) = self.profile.as_ref().map(Profile::store_handle) else {
            return false;
        };
        let mut pruned = false;
        let full: std::collections::BTreeSet<Digest32> = self
            .trust
            .trusted()
            .into_iter()
            .filter(|fp| self.trust.history(fp) == crate::node::trust::HistoryGrant::Full)
            .collect();
        let trusted: BTreeSet<Digest32> = self.trust.trusted().into_iter().collect();
        let now_ms = self.now_ms();
        for shared in self.channels.values() {
            // A room mid-session is skipped, not waited for; the next tick comes round.
            let Ok(mut channel) = shared.try_lock() else {
                continue;
            };
            // Other members' generations this node has read to the end go too (R14 on the
            // receiving side), whatever this node still owes with its own.
            pruned |= channel
                .prune_superseded_receivers(&store)
                .is_ok_and(|n| n > 0);
            if channel.key_generations() <= 1 || !channel.owed_consents(&full).is_empty() {
                continue;
            }
            let keep_from = channel
                .oldest_generation_needed(&trusted, now_ms)
                .unwrap_or(u64::MAX);
            pruned |= channel
                .prune_superseded_origins(&store, keep_from)
                .is_ok_and(|n| n > 0);
        }
        pruned
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
            let (owed, waits) = {
                let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
                    continue;
                };
                let ch = shared.lock().await;
                let owed = ch.owed_consents(&trusted);
                // **A consent the person just asked for that cannot go yet is said, with why**
                // (#335). It was left out of what is owed in silence, so a `vox trust add` whose
                // key could not go — this node has not synced the room since it joined, or has
                // not admitted the member — read as one that dialled and found nobody: no dial
                // and no word.
                let waits = asked_for.filter(|t| !owed.contains(t)).and_then(|t| {
                    if !ch.is_settled() {
                        Some((t, "this node has not synced the room since it joined, so writes nothing there yet"))
                    } else if !ch.is_author(&t) && ch.me() != t {
                        Some((t, "this node has not admitted it to the room yet, so holds no key of its to check"))
                    } else {
                        None
                    }
                });
                (owed, waits)
            };
            if let (Some((t, why)), Some(net)) = (waits, self.net.as_ref()) {
                net.manager().note(
                    t,
                    format!(
                        "your key for it in room {} waits: {why}; it is sent once that changes",
                        crate::node::network::short_id(channel_id)
                    ),
                );
            }
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
    fn revoke<'a>(&'a mut self, channel_id: &'a Digest32, target: Digest32) -> Boxed<'a, Outcome> {
        Box::pin(self.revoke_unboxed(channel_id, target))
    }

    /// [`Self::revoke`], unboxed: see [`Boxed`].
    async fn revoke_unboxed(&mut self, channel_id: &Digest32, target: Digest32) -> Outcome {
        let now_ms = self.now_ms();
        let (Some(profile), Some(shared)) = (
            self.profile.as_ref(),
            self.channels.get(channel_id).map(Arc::clone),
        ) else {
            return Outcome::Failed(Fault::UnknownChannel);
        };
        let generation = {
            let mut channel = shared.lock().await;
            match channel.revoke_consent(profile, target, now_ms) {
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
    fn deliver_owed_rekeys(&mut self) -> Boxed<'_, ()> {
        Box::pin(self.deliver_owed_rekeys_unboxed())
    }

    /// [`Self::deliver_owed_rekeys`], unboxed: see [`Boxed`].
    async fn deliver_owed_rekeys_unboxed(&mut self) {
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
        let now_ms = self.now_ms().get();
        let targets: BTreeSet<Digest32> = owed.into_iter().chain(history.keys().copied()).collect();
        for target in targets {
            // A member whose last keys were not taken waits out its backoff, unless a person asked.
            if !asked
                && self
                    .key_backoff
                    .get(&(*channel_id, target))
                    .is_some_and(|(_, until)| now_ms < *until)
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
            let mut jobs = Vec::with_capacity(keys.len());
            let mut watched = 0u32;
            for key in keys {
                let Some(session) = self.sessions.get_mut(&(*channel_id, target)) else {
                    all_sent = false;
                    break;
                };
                // The hello rides the first key only: the peer holds the session after it.
                let mut frames = Vec::with_capacity(2);
                let carries_hello = match hello_left.take() {
                    Some(initial) => {
                        frames.push(crate::node::pairwise_stream::hello_frame(
                            channel_id, initial,
                        ));
                        true
                    }
                    None => false,
                };
                let Ok(frame) = crate::node::pairwise_stream::skdm_frame(channel_id, session, key)
                else {
                    all_sent = false;
                    break;
                };
                frames.push(frame);
                // Each key's own generation: a refusal re-owes exactly what was refused, and it is
                // recorded as delivered only once taken (V210-88).
                let epoch = self.key_in_flight(*channel_id, target);
                jobs.push(PairwiseJob {
                    conn: Arc::clone(&conn),
                    frames,
                    channel_id: *channel_id,
                    after: AfterWrite::Key {
                        chain_id: key.body.chain_id,
                        hello: carries_hello,
                        session: self.session_serial.get(&(*channel_id, target)).copied(),
                        history: owes_history,
                        epoch,
                    },
                });
                watched += 1;
            }
            if owes_history && watched > 0 {
                // Answers are handled on this actor, after this returns: none is lost.
                self.history_in_flight.insert(pair, (watched, !all_sent));
            }
            // Written in order by this member's writer, off the actor (V210-71); whether each key
            // was taken comes back as `NetEvent::SkdmTaken` or `SkdmRefused`, and only a taken key
            // is recorded as delivered (V210-88).
            for job in jobs {
                self.write_pairwise(target, job);
            }
            if all_sent {
                delivered += 1;
            }
        }
        delivered
    }

    /// A key watched by [`watch_delivery`] was answered, taken or not: one fewer in flight.
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
        let Some(store) = self.profile.as_ref().map(Profile::store_handle) else {
            return;
        };
        let now_ms = self.now_ms();
        if fresh > 0 {
            let _ = admit_board_records(
                &shared,
                &store,
                &bundles,
                ChannelState::MAX_ADMISSIONS_PER_SWEEP,
                now_ms,
                self.net.as_deref(),
            )
            .await;
        }
        // A newcomer learned of from its admission notice is news as its bundle is (#520).
        let from_notices = admit_board_notices(
            &shared,
            &store,
            &net,
            channel_id,
            ChannelState::MAX_ADMISSIONS_PER_SWEEP,
            now_ms,
        )
        .await;
        if fresh == 0 && from_notices == 0 {
            return;
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

    /// Renew each open room's own records when half their lifetime has passed (V210-68, #258).
    ///
    /// A node's address record lives two hours on a board ([`crate::nat::store::MAX_TTL_SECS`]),
    /// and nothing renewed it on a schedule: a round went out only when something happened (the
    /// room opened, a join, a board learned news, a sync applied a governance entry). Until #179 a
    /// round also went out after every sync that brought messages, which renewed it by accident;
    /// an idle room lost its record after two hours either way, and then a joiner or a restarted
    /// member that finds this node through the board did not find it. So, whatever the traffic,
    /// a round goes out at half the lifetime: to this node's own board and every anchor. It is
    /// armed by every full round ([`Self::arm_record_renewal`], from `publish_channel_locally`), so
    /// a node that published everywhere for another reason is not asked again sooner: at most one
    /// renewal per room per half-lifetime. A round to one anchor does not arm it.
    async fn renew_records_if_due(&mut self) {
        let now = self.now_ms().get();
        let due: Vec<Digest32> = self
            .records_renew_at
            .iter()
            .filter(|(room, at)| **at <= now && self.channels.contains_key(*room))
            .map(|(room, _)| *room)
            .collect();
        for room in due {
            self.records_renew_at.remove(&room);
            crate::node::status::SyncBook::note_renewal(&self.sync_book);
            self.publish_channel_locally(&room).await;
            self.publish_channel_to_anchors(&room, PublishCause::Renewal)
                .await;
        }
        // A room closed since it was armed is not renewed.
        let open = &self.channels;
        self.records_renew_at
            .retain(|room, _| open.contains_key(room));
    }

    /// Arm `room`'s next renewal at half its records' lifetime from now.
    fn arm_record_renewal(&mut self, room: &Digest32) {
        let half = crate::nat::store::own_record_ttl_ms() / 2;
        self.records_renew_at
            .insert(*room, self.now_ms().get().saturating_add(half.max(1_000)));
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
        None
    }

    /// The room instance `channel_id` names now, without its lock.
    fn current_room(&self, channel_id: &Digest32) -> Option<crate::node::ports::RoomRef> {
        use crate::node::ports::RoomRef;
        self.channels
            .get(channel_id)
            .map(|shared| RoomRef::Channel(Arc::downgrade(shared)))
    }

    /// Whether `peer` shares `channel_id` with this node: a member (or an anchor) of a room this
    /// node holds. May admit the peer from this
    /// node's own board first (see [`Self::may_sync`]): a peer that has just joined is on the
    /// board before it is in the author table, and skipping it for that lost posts made right
    /// after a join.
    async fn shares_room(&mut self, channel_id: &Digest32, peer: &Digest32) -> bool {
        if let Some(shared) = self.channels.get(channel_id).map(Arc::clone) {
            let epoch = shared.lock().await.epoch();
            return self.may_sync(channel_id, peer, epoch).await;
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
        let rooms: Vec<Digest32> = self.channels.keys().copied().collect();
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
    /// request on every port nothing has served lately, rediscover every room and evaluate every
    /// port. Nothing else waits for the tick: every event that changes what a port needs evaluates
    /// it when it ends (D6a), and no proof passes because of the tick (D7).
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
        let now = self.now_ms().get();
        if now >= self.next_request_at {
            self.next_request_at =
                now + crate::node::syncstream::SYNC_INTERVAL_SECS.saturating_mul(1_000);
            // Every port nothing has served lately: one whose own session ran clean within half
            // the interval, or is running now, is passed over (V210-97). Half, so an idle port,
            // served by the previous request, is still raised by every one.
            let at = std::time::Instant::now();
            let fresh =
                std::time::Duration::from_secs(crate::node::syncstream::SYNC_INTERVAL_SECS / 2);
            for port in self.ports.values_mut() {
                if port.periodic_due(at, fresh) {
                    port.raise();
                }
            }
            self.discover_rooms.extend(self.channels.keys().copied());
            self.sched_all = true;
            self.read_anchor_boards(None).await;
        }
    }

    /// **Read the boards of the anchors this node is connected to**, for every room naming them
    /// ([`exchange_boards`]), each on a task of its own: `only` for one anchor that just
    /// connected, or every connected one on the tick. A member of the room is not read here: its
    /// board is read in every sync session with it.
    async fn read_anchor_boards(&self, only: Option<Digest32>) {
        let (Some(net), Some(store)) = (
            self.net.as_ref().map(Arc::clone),
            self.profile.as_ref().map(Profile::store_handle),
        ) else {
            return;
        };
        let now_ms = self.now_ms();
        for (cid, shared) in &self.channels {
            let (anchors, known) = {
                let ch = shared.lock().await;
                let anchors: Vec<Digest32> = ch
                    .anchors()
                    .nodes()
                    .iter()
                    .map(|a| a.id)
                    .filter(|a| !ch.is_member(a))
                    .filter(|a| only.is_none_or(|o| o == *a))
                    .collect();
                (anchors, ch.epoch())
            };
            for anchor in anchors {
                let Some(conn) = self
                    .anchors_up
                    .get(&anchor)
                    .filter(|c| c.quinn().close_reason().is_none())
                    .map(Arc::clone)
                else {
                    continue;
                };
                let (net, store, shared, cid) = (
                    Arc::clone(&net),
                    Arc::clone(&store),
                    Arc::clone(shared),
                    *cid,
                );
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(
                        SETUP_PATIENCE,
                        exchange_boards(&net, &conn, &shared, &store, cid, known, now_ms),
                    )
                    .await;
                });
            }
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
        let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
            return false;
        };
        // **Not with a member that left** (V210-164): it holds no room to sync, and refused every
        // session for it. Its port is marked served; a member that joins again syncs from its own
        // side, and is synced with again once it says it is back.
        if shared.lock().await.has_left(&peer) {
            if let Some(port) = self.ports.get_mut(&(channel_id, peer)) {
                port.req_done = port.req_gen;
                port.done_gen = port.gen.load(std::sync::atomic::Ordering::Relaxed);
            }
            return false;
        }
        let target = SessionTarget::Channel(shared);
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
        let running = crate::node::status::Running::start(
            &self.sync_book,
            channel_id,
            peer,
            token,
            true,
            crate::node::status::SyncStep::Setup,
        );
        let stepper = running.stepper();
        port.out = Some(crate::node::ports::Attempt {
            token,
            dir: crate::node::ports::Dir::Out,
            conn: Arc::clone(&conn),
            req_at_start: port.req_gen,
            started: std::time::Instant::now(),
            abort: None,
            fence: Arc::clone(&fence),
            running,
        });
        crate::node::status::SyncBook::with(&self.sync_book, channel_id, peer, |c| c.opened += 1);
        let admit_store = self.profile.as_ref().map(Profile::store_handle);
        let cid = channel_id;
        let now_ms = self.now_ms();
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
                            admitted_authors =
                                exchange_boards(&net, &conn, shared, &pstore, cid, known, now_ms)
                                    .await;
                        }
                    };
                    let _ = tokio::time::timeout(SETUP_PATIENCE, setup).await;
                    shared.lock().await.epoch()
                }
            };
            stepper.step(crate::node::status::SyncStep::Opening);
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
            stepper.step(crate::node::status::SyncStep::Exchanging);
            // 3. Run the session on a blocking thread, which **holds the slot** until it exits
            //    (ADR-025 D1a): an abort stops this task, not the worker, so the worker is fenced
            //    instead and the slot bounds running workers.
            let mut report = run_session_worker(
                target,
                store,
                transport,
                now_ms,
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
        let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
            return;
        };
        let target = SessionTarget::Channel(shared);
        let Some(port) = self.ports.get_mut(&(channel_id, peer)) else {
            return;
        };
        let token = self.next_token;
        self.next_token += 1;
        let fence = crate::transport::stream_transport::Fence::new();
        let running = crate::node::status::Running::start(
            &self.sync_book,
            channel_id,
            peer,
            token,
            false,
            crate::node::status::SyncStep::Exchanging,
        );
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
                running,
            },
        );
        crate::node::status::SyncBook::with(&self.sync_book, channel_id, peer, |c| {
            c.admitted += 1;
        });
        let now_ms = self.now_ms();
        let tx = self.net_tx.clone();
        let transport = transport.fenced(Arc::clone(&fence));
        let task = tokio::spawn(async move {
            let report = run_session_worker(
                target,
                store,
                transport,
                now_ms,
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
            // A session of a room this node has since left is not counted: its counts went
            // with the room (V210-164).
            if self.current_room(&channel_id).is_some() {
                crate::node::status::SyncBook::with(&self.sync_book, channel_id, peer, |c| {
                    c.stale += 1
                });
            }
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
                if attempt.dir == crate::node::ports::Dir::Out {
                    port.last_clean_out = Some(std::time::Instant::now());
                }
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
        self.sync_with(channel_id, &peers).await;
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

    /// Raise a sync request on the room's port to each of `peers`, clearing its backoff, and run
    /// the schedule: what `vox room sync` does for every member, and an agreement round for the
    /// members it needs posts from (V210-168).
    async fn sync_with(&mut self, channel_id: &Digest32, peers: &[Digest32]) {
        for peer in peers {
            if !self.ensure_port(channel_id, peer).await {
                continue;
            }
            if let Some(port) = self.ports.get_mut(&(*channel_id, *peer)) {
                port.raise();
                port.clear_backoff();
            }
            crate::node::status::SyncBook::with(&self.sync_book, *channel_id, *peer, |c| {
                c.backoff = None;
            });
        }
        self.sched_rooms.insert(*channel_id);
        self.schedule().await;
    }

    /// **Ask every other member whether it holds this node's post** (V210-168,
    /// [`NodeCommand::Agree`]): the room's members, and where the board says they are, are read
    /// here; the asking runs on a task ([`agree_round`]), which sends the report and answers.
    async fn begin_agree(
        &mut self,
        channel_id: Digest32,
        entry: Digest32,
        types: Vec<String>,
        report: oneshot::Sender<crate::node::agreestream::Report>,
        reply: oneshot::Sender<Outcome>,
    ) {
        let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
            let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
            return;
        };
        let (epoch, others, skipped) = {
            let c = shared.lock().await;
            let me = c.me();
            let others: Vec<Digest32> = c.members().into_iter().filter(|m| *m != me).collect();
            (c.epoch(), others, c.skipped_when_stamped(&entry))
        };
        let net = self.net.as_ref().map(Arc::clone);
        let members: Vec<(Digest32, crate::nat::multiaddr::EndpointList)> = others
            .into_iter()
            .map(|m| {
                let at = net
                    .as_ref()
                    .map(|n| n.board_endpoints(&channel_id, &m))
                    .unwrap_or_default();
                (m, at)
            })
            .collect();
        let question = crate::node::agreestream::Ask {
            channel_id,
            epoch,
            entry,
            sent_millis: (self.millis_clock)(),
            types,
        };
        let view = self.view_tx.subscribe();
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let r = agree_round(net, tx, view, question, members, skipped).await;
            let _ = report.send(r);
            let _ = reply.send(Outcome::Done);
        });
    }

    /// **A member's answer to another member's [`crate::node::agreestream::Ask`]** (V210-168):
    /// the room and the asker are checked here, at once; if the asked post has not reached this
    /// node, a sync with the asker is raised to pull it; a task waits for it and answers.
    /// **Whether `channel_id` has a place for `joiner`** (V030-30, #366), counted the one way every
    /// member counts it: its authors, and every place promised and not yet settled, other than
    /// `joiner`'s own. `RoomFull` at the cap, `SeatTaken` when promises fill what is left. Expired
    /// promises go first.
    fn seat_count(
        &mut self,
        c: &ChannelState,
        channel_id: &Digest32,
        joiner: &Digest32,
    ) -> crate::error::Result<()> {
        let now = std::time::Instant::now();
        self.seat_promises.retain(|_, p| p.until > now);
        let authors = c.author_count();
        let cap = crate::node::channel::max_authors();
        if authors >= cap {
            return Err(Error::RoomFull {
                members: authors as u64,
            });
        }
        let promised = self
            .seat_promises
            .keys()
            .filter(|(room, j)| room == channel_id && j != joiner && !c.is_author(j))
            .count();
        if authors + promised >= cap {
            return Err(Error::SeatTaken);
        }
        Ok(())
    }

    /// **The asker's first step** (V030-30, #366): hold a place for `joiner` under this node's own
    /// name, and say which members to ask: every other member of the room this node holds a
    /// connection to. A joiner already an author needs no place and no one asked.
    async fn reserve_seat(
        &mut self,
        channel_id: Digest32,
        joiner: Digest32,
    ) -> crate::error::Result<SeatsToAsk> {
        let Some(me) = self.profile.as_ref().map(Profile::fingerprint) else {
            return Err(Error::Profile("locked"));
        };
        let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
            return Err(Error::Profile("no such room on this node"));
        };
        let c = shared.lock().await;
        if c.is_author(&joiner) {
            return Ok((c.epoch(), Vec::new()));
        }
        self.seat_count(&c, &channel_id, &joiner)?;
        self.seat_promises.insert(
            (channel_id, joiner),
            SeatPromise {
                from: me,
                until: std::time::Instant::now() + crate::node::seatstream::PROMISE_TTL,
            },
        );
        // Online is a connection held: a member not connected is not asked and blocks nothing; it
        // learns of the newcomer from a board when it returns. Anchors are not members, so never
        // asked.
        let members = match self.net.as_ref() {
            Some(net) => c
                .members()
                .into_iter()
                .filter(|m| *m != me && *m != joiner)
                .filter_map(|m| net.manager().existing(&m).map(|conn| (m, conn)))
                .collect(),
            None => Vec::new(),
        };
        Ok((c.epoch(), members))
    }

    /// **A member's answer to another's newcomer** (V030-30, #366): a place promised, or why not.
    /// A promised place waits, off the actor, for the asker's abort, which frees it.
    async fn answer_seat(
        &mut self,
        peer: Digest32,
        ask: crate::node::seatstream::Ask,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) {
        use crate::node::seatstream::{answer_and_wait, Answer};
        let answer = match self.channels.get(&ask.channel_id).map(Arc::clone) {
            Some(shared) => {
                let c = shared.lock().await;
                if c.epoch() != ask.epoch || !c.is_member(&peer) {
                    Answer::NotHeld
                } else if c.is_author(&ask.joiner) {
                    Answer::Yes
                } else {
                    match self.seat_count(&c, &ask.channel_id, &ask.joiner) {
                        Ok(()) => {
                            self.seat_promises.insert(
                                (ask.channel_id, ask.joiner),
                                SeatPromise {
                                    from: peer,
                                    until: std::time::Instant::now()
                                        + crate::node::seatstream::PROMISE_TTL,
                                },
                            );
                            Answer::Yes
                        }
                        Err(Error::RoomFull { members }) => Answer::Full { members },
                        Err(_) => Answer::Taken,
                    }
                }
            }
            None => Answer::NotHeld,
        };
        // **Test-only** (`test-knobs`): a member online that never answers, its stream held open.
        #[cfg(feature = "test-knobs")]
        if std::env::var_os(crate::node::seatstream::TEST_SEAT_SILENT_ENV).is_some() {
            tokio::spawn(async move {
                let _held = (send, recv);
                tokio::time::sleep(crate::node::seatstream::PROMISE_TTL).await;
            });
            return;
        }
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            if let Some(abort) = answer_and_wait(send, recv, answer, ask).await {
                let _ = tx.send(NetEvent::SeatAbort { peer, abort }).await;
            }
        });
    }

    async fn answer_agree(
        &mut self,
        peer: Digest32,
        ask: crate::node::agreestream::Ask,
        send: quinn::SendStream,
    ) {
        use crate::node::agreestream::{answer, Answer};
        let member = match self.channels.get(&ask.channel_id).map(Arc::clone) {
            Some(shared) => {
                let c = shared.lock().await;
                c.epoch() == ask.epoch && c.members().contains(&peer)
            }
            None => false,
        };
        if !member {
            tokio::spawn(async move { answer(send, &Answer::NotHeld).await });
            return;
        }
        let mut view = self.view_tx.subscribe();
        let clock = Arc::clone(&self.millis_clock);
        let held = listed(&view.borrow_and_update(), &ask, clock()).is_some();
        if !held {
            self.sync_with(&ask.channel_id, &[peer]).await;
        }
        tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + crate::node::agreestream::HOLD_PATIENCE;
            let a = loop {
                let now = listed(&view.borrow_and_update(), &ask, clock());
                if let Some(a) = now {
                    break a;
                }
                match tokio::time::timeout_at(deadline, view.changed()).await {
                    Ok(Ok(())) => {}
                    _ => break Answer::NotReceived,
                }
            };
            answer(send, &a).await;
        });
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
        // The mutant build's `refuse-sessions` (#85): every inbound session refused, with a reason.
        #[cfg(feature = "mutant-sender")]
        if let Some(code) = crate::log::sync::mutant::refuses() {
            let (mut send, mut recv) = (send, recv);
            crate::node::net::refuse_stream_because(&mut send, &mut recv, code);
            return;
        }
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
        // Only a channel we hold open at that epoch can be reconciled. An anchor holds no copy
        // of a room it is not a member of (ADR-023 decision 6), so it refuses every one.
        let matches_epoch = match self.channels.get(&channel_id) {
            Some(shared) => shared.lock().await.epoch() == epoch,
            None => false,
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

    /// Whether `peer` is a joiner this node let in, into any room, whose join is still settling:
    /// no clean session with it yet, and within [`JOINER_SEAL_GRACE`] (#406).
    fn joiner_settling(&self, peer: &Digest32) -> bool {
        self.joins_answered
            .iter()
            .any(|((_, p), at)| p == peer && at.elapsed() < JOINER_SEAL_GRACE)
    }

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

    /// Whether `peer` may reconcile `channel_id`'s log with this node: an **admitted author** of
    /// that room. If it is not one yet, this node's own board is consulted first — local, so
    /// cheap — because a member that joined through somebody else is on the board before it is
    /// in this node's author table, and refusing it for that would be the "precondition behind
    /// its own check" defect `shares_room` documents. Admission there takes the same M17.6
    /// evidence as everywhere else.
    ///
    /// **Not an anchor for being one.** An anchor that is not a member holds nothing for the
    /// room and runs no sync session (ADR-023 RL-6.1, RL-6.2), so it refuses every one. Counting
    /// the room's anchors here, a leftover of the anchor log M23.5 deleted, gave every member a
    /// port to each anchor: a session opened on every connection and tick, refused "epoch
    /// mismatch", and printed as a sync that did not complete. An anchor that is a member
    /// syncs as a member.
    async fn may_sync(&mut self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
        if let Some(shared) = self.channels.get(channel_id).map(Arc::clone) {
            {
                let channel = shared.lock().await;
                // A member that left is nobody this node syncs with (V030-08).
                if channel.has_left(peer) {
                    return false;
                }
                if channel.is_member(peer) {
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
            let now_ms = self.now_ms();
            let _ = admit_board_records(
                &shared,
                &store,
                &bundles,
                ChannelState::MAX_ADMISSIONS_PER_SWEEP,
                now_ms,
                self.net.as_deref(),
            )
            .await;
            return shared.lock().await.is_member(peer);
        }
        false
    }

    /// **Store-and-forward for a member the direct path could not reach** (ADR-023 decision 4,
    /// M23.3).
    ///
    /// Sender keys go to a member on a pairwise stream, and that stays the fast path. But a
    /// member who is never online with this node could not be given a key at all: two members
    /// converged on each other's ciphertext and neither could read it. So when a dial to a
    /// member fails, whatever this node owes it — the key a trust decision released, or the new
    /// generation after a rotation — is sealed to that member and posted to the room's log as a
    /// key-package. Every member replicates the log, so an always-on member carries it to them.
    ///
    /// The consent is issued exactly as the direct path issues it: the key is delivered by the
    /// log instead of the stream, and it is the same key.
    async fn deliver_through_log(&mut self, peer: Digest32) {
        if self.net.is_none() {
            return;
        }
        let trusted = self.trust.trusted();
        let channels: Vec<Digest32> = self.channels.keys().copied().collect();
        for channel_id in channels {
            let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
                continue;
            };
            let owes_consent = shared.lock().await.owed_consents(&trusted).contains(&peer);
            if owes_consent {
                // **The same release the pairwise stream would have carried** (`consent_release`):
                // what this member may read depends on when it was trusted, never on the path its
                // key took (V210-45, #226). A key taken now, when the dial failed, would start
                // after every post made since the decision, which that member could then never
                // read: the defect V210-30 closed, back through this path.
                let full = self.trust.history(&peer) == crate::node::trust::HistoryGrant::Full;
                let decision = self.trust_decision(&peer);
                let (skdm, plan) = {
                    let Some(profile) = self.profile.as_ref() else {
                        return;
                    };
                    let channel = shared.lock().await;
                    let Ok(release) = consent_release(
                        &mut self.consent_keys,
                        profile,
                        &channel,
                        &channel_id,
                        peer,
                        full,
                        decision,
                    ) else {
                        continue;
                    };
                    release
                };
                if !self.post_key_package(&channel_id, peer, &skdm).await {
                    continue;
                }
                let now_ms = self.now_ms();
                let issued = {
                    let Some(profile) = self.profile.as_ref() else {
                        return;
                    };
                    // Forgotten before the consent is recorded, as on the direct path.
                    if forget_consent_key(&mut self.consent_keys, profile, &channel_id, peer)
                        .is_err()
                    {
                        continue;
                    }
                    // Recorded exactly as the direct path records it: the entitlement from the
                    // plan's first position, and the generations before the live one owed as
                    // history, which go out below.
                    let entitled_from = plan
                        .as_ref()
                        .and_then(|p| p.first().copied())
                        .unwrap_or((skdm.body.chain_id, skdm.body.iteration));
                    let mut channel = shared.lock().await;
                    channel
                        .issue_consent(profile, peer, &skdm, full, entitled_from, now_ms)
                        .is_ok()
                        && (entitled_from.0 >= skdm.body.chain_id
                            || channel
                                .owe_history(profile.store(), peer, entitled_from.0)
                                .is_ok())
                };
                if issued {
                    self.note_local_append(&channel_id);
                    let _ = self.event_tx.send(NodeEvent::Consented {
                        channel_id,
                        target: peer,
                    });
                }
            }
            // What this member is still owed — history from its floor, or the live generation
            // after a rotation — each from where its entitlement begins and never before it
            // (V210-45, #224), exactly as the direct re-key round releases it.
            let (history, rekey, generation) = {
                let Some(profile) = self.profile.as_ref() else {
                    return;
                };
                let channel = shared.lock().await;
                let history = channel
                    .owed_history()
                    .get(&peer)
                    .and_then(|floor| channel.history_skdms(profile, &peer, *floor).ok())
                    .filter(|batch| !batch.is_empty());
                let rekey = if history.is_none() && channel.owed_rekeys().contains(&peer) {
                    channel.rekey_skdm_for(profile, &peer).ok()
                } else {
                    None
                };
                (history, rekey, channel.sender_generation())
            };
            let owed_history = history.is_some();
            let keys: Vec<crate::group::skdm::Skdm> = match (history, rekey) {
                (Some(batch), _) => batch,
                (None, Some(k)) => vec![k],
                (None, None) => continue,
            };
            let mut all_posted = true;
            for key in &keys {
                if !self.post_key_package(&channel_id, peer, key).await {
                    all_posted = false;
                    break;
                }
            }
            if !all_posted {
                continue;
            }
            // Recorded only after every package went out, so a failed post stays owed.
            let Some(profile) = self.profile.as_ref() else {
                return;
            };
            let mut channel = shared.lock().await;
            let history_noted = if owed_history {
                channel.note_history_delivered(profile.store(), &peer)
            } else {
                Ok(())
            };
            let _ = history_noted
                .and_then(|()| channel.note_delivered(profile.store(), peer, generation));
        }
    }

    /// Seal `skdm` to `target` and post it to the room's log as a key-package (ADR-023
    /// decision 4, M23.3). Returns whether it was posted.
    ///
    /// Needs the target's published prekey bundle, which this node holds once it has read a
    /// board that carries it. Without one there is nothing to seal to, and the key stays owed.
    async fn post_key_package(
        &mut self,
        channel_id: &Digest32,
        target: Digest32,
        skdm: &crate::group::skdm::Skdm,
    ) -> bool {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return false;
        };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return false;
        };
        let Ok(ctx) = shared.lock().await.join_context() else {
            return false;
        };
        let Some(record) = net.board_bundle(channel_id, ctx.epoch, &target) else {
            return false;
        };
        let package = {
            let Some(ring) = self.prekeys.as_ref().map(Arc::clone) else {
                return false;
            };
            let ring = ring.lock().await;
            match crate::node::keypackage::KeyPackage::seal(
                ring.identity_dh(),
                &record.prekey_bundle,
                &ctx,
                target,
                skdm,
            ) {
                Ok(p) => p,
                Err(_) => return false,
            }
        };
        let posted = {
            let Some(profile) = self.profile.as_ref() else {
                return false;
            };
            shared
                .lock()
                .await
                .append_key_package(profile, &package, (self.millis_clock)())
                .is_ok()
        };
        if posted {
            // An entry like any other: it goes out on the next push.
            self.note_local_append(channel_id);
        }
        posted
    }

    /// Install the key-packages the log has delivered to this identity in `channel_id`: open
    /// each with a one-shot PQXDH against this node's own prekeys and hand the sender key to
    /// the channel, which verifies it against its author and backfills what it opens.
    async fn install_key_packages(&mut self, channel_id: &Digest32) {
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return;
        };
        let (packages, ctx) = {
            let mut channel = shared.lock().await;
            let packages = channel.take_inbound_packages();
            if packages.is_empty() {
                return;
            }
            let Ok(ctx) = channel.join_context() else {
                return;
            };
            (packages, ctx)
        };
        let now_ms = self.now_ms();
        let now = now_ms.secs();
        for package in packages {
            let Ok(init) = package.initial_message() else {
                continue;
            };
            let Some(mut session) = self.respond_to_initial(&init, &ctx).await else {
                continue;
            };
            let Ok(skdm) = package.open(&mut session, now) else {
                continue;
            };
            let author = skdm.body.author_id;
            // **A node reads only the members its owner trusts** (V210-118), whichever path the
            // key took. The pairwise path refused a key from an untrusted author, and this one,
            // the log's, took it: a member trusted by someone whose node was down when trusted
            // (its key then goes by the log) was read by a node that never trusted it. Held, not
            // dropped, so the key is taken once the owner trusts its author.
            if !self.trust.is_trusted(&author) {
                shared.lock().await.hold_package(package);
                continue;
            }
            let installed = {
                let Some(profile) = self.profile.as_ref() else {
                    return;
                };
                shared
                    .lock()
                    .await
                    .accept_skdm(profile.store(), &skdm, now_ms)
            };
            if let Ok(backfilled) = installed {
                let _ = self.event_tx.send(NodeEvent::SenderKeyReceived {
                    channel_id: *channel_id,
                    peer: author,
                    backfilled: backfilled as u64,
                });
            }
        }
    }

    /// The responder half of an ADR-004 PQXDH opening message: consume the one-time prekey it
    /// names (persisted before the handshake completes, graded last-resort on reuse) and build
    /// the session from this node's own prekey ring. Shared by a pairwise `Hello` and a
    /// key-package (ADR-023 decision 4), which is the same opening message kept in the log.
    async fn respond_to_initial(
        &mut self,
        init: &InitialMessage,
        ctx: &crate::join::session::JoinContext,
    ) -> Option<crate::pairwise::session::Session> {
        let now = self.now_ms().get();
        let mut reuse = crate::pairwise::OtpReuseTracker::new();
        let profile = self.profile.as_ref()?;
        let store = profile.store();
        let Ok(signer) = profile.signer() else {
            return None;
        };
        // The ring is taken under its lock below, so take what the save needs first. The
        // `Send + Sync` bound is load-bearing, not decoration: this function now awaits the
        // ring lock, so the actor's whole future has to stay `Send`, and a bare
        // `&dyn RootSigner` is not.
        let signer: &(dyn crate::identity::composite::RootSigner + Send + Sync) = signer;
        let ring = self.prekeys.as_ref().map(Arc::clone)?;
        let mut ring = ring.lock().await;
        if let Some(id) = init.one_time_prekey_id {
            match ring.use_one_time(id, now) {
                prekeys::OneTimeUse::Fresh => {}
                prekeys::OneTimeUse::Reused => {
                    // Seed the per-process tracker from the ring's persistent record so
                    // the downgrade is graded even after a restart (ADR-004).
                    reuse.observe(id);
                }
                prekeys::OneTimeUse::Unknown => return None,
            }
            // Persist the consume before the handshake completes: a crash here must not
            // leave the prekey re-offerable.
            if prekeys::save(store, signer, &ring).is_err() {
                return None;
            }
        }
        let signed_prekey = ring.signed_prekey_for(init.signed_prekey_id)?;
        let one_time_prekey = init
            .one_time_prekey_id
            .and_then(|id| ring.consumed_one_time(id));
        let prekeys = crate::pairwise::ResponderPrekeys {
            identity_dh_key: ring.identity_dh(),
            signed_prekey,
            one_time_prekey,
        };
        let Ok(session) = crate::pairwise::session::Session::accept(
            init,
            &prekeys,
            &ctx.channel_id,
            ctx.epoch,
            &mut reuse,
            ctx.floor,
        ) else {
            return None;
        };
        Some(session)
    }

    /// Accept an inbound [`crate::node::pairwise_stream::PairwiseFrame::Hello`], establishing the responder half of
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
            // **Two sessions for one pair** (ADR-004 O2). Keep the one both ends will
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
            // Only a member we have admitted may open a session to us, and not one that left
            // (V030-08).
            if !channel.is_member(&peer) {
                return false;
            }
            match channel.join_context() {
                Ok(c) => c,
                Err(_) => return false,
            }
        };
        let Some(session) = self.respond_to_initial(&init, &ctx).await else {
            return false;
        };
        self.sessions.insert(key, session);
        self.stamp_session(key);
        self.initiated.remove(&key);
        self.reopen.remove(&key);
        self.accepted_hello.insert(key, hello_hash);
        if replaces {
            // Whatever this node sent under the session it just dropped was sealed where
            // the peer cannot open it: forget that it was delivered, and send the current
            // key over the session both ends now hold at once. A backoff earned by a key
            // sealed under the dropped session is not this one's (V210-80): it held the
            // resend back 2 s, and more after a second refusal.
            self.forget_delivery(&channel_id, &peer).await;
            self.key_backoff.remove(&key);
            self.redeliver_now = true;
        }
        true
    }

    /// Forget that `peer` holds this identity's current sender key in `channel_id`, so
    /// the next re-key round delivers it again (ADR-004 O4).
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
    /// for that pair already exists (ADR-004 O2).
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
    /// (ADR-004 O3), with the empty ratchet message behind it that gives the peer a
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
            let Ok(open) = crate::node::pairwise_stream::open_frame(&channel_id, session) else {
                continue;
            };
            let frames = vec![
                crate::node::pairwise_stream::hello_frame(&channel_id, &initial),
                open,
            ];
            // Queued, not awaited (V210-71): a write that fails puts the offer back
            // (`NetEvent::ReopenUndelivered`).
            // Offered, not delivered: an `Open` is never answered, so the hello counts as held only
            // once a key sealed under the session is taken (V210-89).
            self.reopen.remove(&(channel_id, peer));
            self.write_pairwise(
                peer,
                PairwiseJob {
                    conn,
                    frames,
                    channel_id,
                    after: AfterWrite::Reopen,
                },
            );
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

    /// Hand `job` to `peer`'s pairwise writer, starting one if it has none (V210-71).
    ///
    /// One writer per member, so the streams to that member are opened in the order their frames
    /// were sealed: a hello and the keys behind it, and the ratchet messages of one session, must
    /// arrive in order (F12). The actor only seals and queues; it never waits on the peer.
    fn write_pairwise(&mut self, peer: Digest32, job: PairwiseJob) {
        let job = match self.pairwise_out.get(&peer) {
            Some(q) => match q.send(job) {
                Ok(()) => return,
                Err(mpsc::error::SendError(job)) => job,
            },
            None => job,
        };
        let (q, rx) = mpsc::unbounded_channel();
        tokio::spawn(write_pairwise_jobs(peer, rx, self.net_tx.clone()));
        let _ = q.send(job);
        self.pairwise_out.insert(peer, q);
    }

    /// Count one key to `target` as **in flight** and return the [`Self::delivery_epoch`] its
    /// answer must carry (V210-88). From here until `NetEvent::SkdmTaken` or `SkdmRefused` the key
    /// is only in flight, kept in memory: a crash leaves it owed and the restarted node sends it
    /// again. Taken is when it is delivered; a `history` key counts towards the batch it belongs
    /// to, whose history is recorded once all of it was taken.
    fn key_in_flight(&mut self, channel_id: Digest32, target: Digest32) -> u64 {
        *self.keys_in_flight.entry((channel_id, target)).or_default() += 1;
        self.delivery_epoch
    }

    /// Dial every other member of a room this node has just opened, in the background — what
    /// a restart needs to find them again (`node::peer_book`). `reach_member` dials off the
    /// actor, and a connection it makes is adopted with a sync due at once.
    async fn reach_members_of(&mut self, channel_id: &Digest32) {
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return;
        };
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        let (me, members, anchored, settled) = {
            let ch = shared.lock().await;
            let anchored = ch.anchors().nodes().iter().any(|a| a.id != net.local_id());
            (ch.me(), ch.members(), anchored, ch.is_settled())
        };
        // **A room with an anchor is left to its board.** The board says where every member is
        // within moments of opening, and a dial started before it from where a member was last
        // reached races a circuit through that anchor against the direct path: whichever
        // landed, the circuit stayed on the anchor for its idle timeout, and anything else that
        // reached the member meanwhile took the relayed path (#226: a `vox forward` beside a
        // reopened room left a circuit on the anchor in 5 of 5 runs, where v0.2.10 left none).
        // This dial is for a room with no anchor, whose members are found nowhere else — and for
        // a room that has not had its first sync (V030-51): a joiner that stopped before it owes
        // no member a key, and nothing else dials a member it holds no connection to, so a member
        // only a circuit reaches, the room's host, was never reached and the room never synced.
        if anchored && settled {
            return;
        }
        for member in members.into_iter().filter(|m| *m != me) {
            // Only a member there is an address for: with none in the book either, there is
            // nothing to dial.
            // A room that has synced reaches only a member there is an address for. One that has
            // not reaches every member, addressed or not, now: the joiner held no address for a
            // member it reached only through a relay, and the ladder asks a relay for it (reading
            // a connected board first), which is the one path such a member has.
            if settled
                && net.board_endpoints(channel_id, &member).is_empty()
                && self.peer_book.endpoints(&member).is_empty()
            {
                continue;
            }
            if net.manager().existing(&member).is_some() {
                continue;
            }
            let _ = self.reach_member(channel_id, member, !settled).await;
        }
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
        // The board first — it is current. After a restart it is empty, and where the member
        // was last reached (`node::peer_book`) is the only address this node has.
        let mut endpoints = net.board_endpoints(channel_id, &target);
        if endpoints.is_empty() {
            endpoints = self.peer_book.endpoints(&target);
        }
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
        // (the tick, a post) dials at most once per `MEMBER_REDIAL_MS`; a command the person
        // gave (`asked`, a member just trusted) dials now whatever the spacing.
        let now = self.now_ms().get();
        let recent = self
            .member_dialed_at
            .get(&target)
            .is_some_and(|t| now.saturating_sub(*t) < MEMBER_REDIAL_MS);
        if asked || !recent {
            self.member_dialed_at.insert(target, now);
            let tx = self.net_tx.clone();
            let room = *channel_id;
            tokio::spawn(async move {
                // Nothing known for it here: read a connected board before bridging (V210-122,
                // V030-22).
                let endpoints = if endpoints.is_empty() {
                    net.member_endpoints(&room, target).await
                } else {
                    endpoints
                };
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

    /// Say where this node listens on this computer and the local network (`node::nearby`):
    /// [`NEARBY_FIRST_MS`] after it holds a room it did not, then every [`NEARBY_EVERY_MS`],
    /// each time only if a member of a room it holds is not connected.
    async fn say_where_if_due(&mut self) {
        let (Some(nearby), Some(net)) = (self.nearby.clone(), self.net.clone()) else {
            return;
        };
        let now = self.now_ms().get();
        let rooms = self.channels.len();
        if rooms > self.nearby_rooms {
            // The dials a newly held room makes from what it knows get their moment first.
            self.nearby_rooms = rooms;
            self.nearby_due = now + NEARBY_FIRST_MS;
            return;
        }
        self.nearby_rooms = rooms;
        if now < self.nearby_due {
            return;
        }
        self.nearby_due = now + NEARBY_EVERY_MS;
        let me = net.local_id();
        let Ok(at) = net.manager().endpoint().local_addr() else {
            return;
        };
        let mut entries = Vec::with_capacity(rooms);
        let mut missing = false;
        for (room, channel) in &self.channels {
            entries.push(crate::node::nearby::entry(room, &me, at.port(), now));
            if !missing {
                missing = channel
                    .lock()
                    .await
                    .members()
                    .iter()
                    .any(|m| *m != me && net.manager().existing(m).is_none());
            }
        }
        if missing {
            nearby.say(&entries);
        }
    }

    /// A node at `from` named `entries`: dial every member of a held room it names that this node
    /// is not connected to, at the port it gave (`node::nearby`). The dial is authenticated as
    /// that member, so a datagram that lies costs one failed dial.
    async fn heard_nearby(
        &mut self,
        from: std::net::IpAddr,
        entries: &[crate::node::nearby::Entry],
    ) {
        let Some(net) = self.net.clone() else {
            return;
        };
        let me = net.local_id();
        let now = self.now_ms().get();
        let mut found: BTreeMap<Digest32, u16> = BTreeMap::new();
        for (room, channel) in &self.channels {
            for m in channel.lock().await.members() {
                if m == me || found.contains_key(&m) || net.manager().existing(&m).is_some() {
                    continue;
                }
                if let Some(port) = crate::node::nearby::port_of(entries, room, &m, now) {
                    found.insert(m, port);
                }
            }
        }
        for (peer, port) in found {
            if self
                .nearby_dialed
                .get(&peer)
                .is_some_and(|t| now.saturating_sub(*t) < NEARBY_REDIAL_MS)
            {
                continue;
            }
            self.nearby_dialed.insert(peer, now);
            let at = std::net::SocketAddr::new(from, port);
            let candidates = crate::node::nearby::dial_at(at);
            let Ok(endpoints) = crate::nat::multiaddr::EndpointList::new(
                candidates.iter().copied().map(Into::into).collect(),
            ) else {
                continue;
            };
            net.manager().note(
                peer,
                format!("heard on this computer or the local network at {at}; dialling it there"),
            );
            let (net, tx) = (Arc::clone(&net), self.net_tx.clone());
            tokio::spawn(async move {
                match net.manager().connect_to(peer, &candidates).await {
                    Ok(conn) => {
                        let _ = tx
                            .send(NetEvent::Dialed {
                                conn,
                                endpoints,
                                board: false,
                            })
                            .await;
                    }
                    // **Said, not filed as a failed reach.** This is one direct dial at one heard
                    // address, often one this node's socket cannot use at all (an IPv4 address
                    // heard on an `[::1]`-only socket: "no direct candidates"). It says nothing of
                    // the member's other paths: filed as `ReachFailed`, it backed off the member's
                    // sync ports as Unreachable, and the reach that would have asked the anchor
                    // for a circuit did not come for seconds. A member no path reaches still backs
                    // off: its sync reach, the whole ladder, files its own failure.
                    Err(e) => net.manager().note(
                        peer,
                        format!("the dial at the address heard nearby ({at}) failed: {e}"),
                    ),
                }
            });
        }
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
        let room = *channel_id;
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            // This node's board record, or a connected board's when it holds none yet (V210-122,
            // V030-22).
            let endpoints = net.member_endpoints(&room, peer).await;
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
    /// author's messages readable and backfills any already held as ciphertext. Its frames were
    /// read off the actor (see `read_pairwise_streams`); nothing here waits on the peer.
    async fn take_inbound_skdm(&mut self, stream: PairwiseIn) {
        use crate::node::pairwise_stream::PairwiseFrame;
        let room = match &stream.first {
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
            self.held_pairwise.push((room, stream));
            return;
        }
        #[cfg(feature = "test-knobs")]
        if matches!(stream.first, PairwiseFrame::Hello { .. })
            && test_lose_hello(
                &self
                    .net
                    .as_ref()
                    .map(|n| n.manager().endpoint().local_id())
                    .unwrap_or_default(),
                &room,
            )
        {
            eprintln!("vox: {TEST_LOSE_HELLOS_ENV}: an inbound hello was lost, unread");
            let PairwiseIn {
                mut send, mut recv, ..
            } = stream;
            let _ = send.reset(quinn::VarInt::from_u32(0));
            let _ = recv.stop(quinn::VarInt::from_u32(0));
            return;
        }
        self.handle_pairwise(stream).await;
    }

    /// Act on a pairwise stream whose frames have been read.
    fn handle_pairwise(&mut self, stream: PairwiseIn) -> Boxed<'_, ()> {
        Box::pin(self.handle_pairwise_unboxed(stream))
    }

    /// [`Self::handle_pairwise`], unboxed: see [`Boxed`].
    async fn handle_pairwise_unboxed(&mut self, stream: PairwiseIn) {
        let PairwiseIn {
            peer,
            first,
            second,
            mut send,
            recv,
        } = stream;
        // **Taken, or said not to be.** A sender cannot learn from the transport whether its key
        // was taken: QUIC acknowledges the bytes before this node decides anything. So a stream
        // that carried a key is answered, one byte once the key is taken, and reset with a wire
        // code when it is not. A stream that carried no key (a bare hello, an `Open`) is finished.
        match self.take_pairwise(peer, first, second).await {
            Some(Ok(())) => {
                // Written on its own task, bounded (V210-71): a peer that grants no flow credit
                // would otherwise hold the actor on this one byte for as long as it liked.
                tokio::spawn(async move {
                    let _recv = recv;
                    let _ = tokio::time::timeout(
                        crate::transport::framing::FRAME_PATIENCE,
                        send.write_all(&[crate::node::pairwise_stream::KEY_TAKEN]),
                    )
                    .await;
                    let _ = send.finish();
                });
            }
            Some(Err(why)) => {
                let mut recv = recv;
                let _ = send.reset(why.code());
                let _ = recv.stop(why.code());
            }
            None => {
                let _ = send.finish();
            }
        }
        // The race between two sessions is resolved: send what is owed under the one both ends
        // now hold, rather than leave it to a tick and a backoff that were for the dropped one.
        if std::mem::take(&mut self.redeliver_now) {
            self.deliver_owed_consents(None).await;
        }
        // After the answer, never before it: the sender waits on that answer, and this goes to the
        // network. Offered again at once, its backoff cleared, rather than up to a minute later on
        // the tick: a member just trusted reads from the moment its owner decided (V210-118).
        let owed: Vec<(Digest32, Digest32)> =
            std::mem::take(&mut self.reoffer).into_iter().collect();
        for (channel_id, member) in owed {
            let (Some(profile), Some(shared)) = (
                self.profile.as_ref(),
                self.channels.get(&channel_id).map(Arc::clone),
            ) else {
                continue;
            };
            if shared
                .lock()
                .await
                .reoffer(profile.store(), &member)
                .is_err()
            {
                continue;
            }
            self.key_backoff.remove(&(channel_id, member));
            let _ = self.deliver_rekeys_for(&channel_id, false).await;
        }
    }

    /// Act on a pairwise stream whose first frame has been read: `Some(Ok)` if it carried a key
    /// and the key was taken, `Some(Err(why))` if it carried one that was not, `None` if it carried
    /// none.
    async fn take_pairwise(
        &mut self,
        peer: Digest32,
        first: crate::node::pairwise_stream::PairwiseFrame,
        second: Option<crate::node::pairwise_stream::PairwiseFrame>,
    ) -> Option<Result<(), crate::node::pairwise_stream::KeyRefusal>> {
        use crate::node::pairwise_stream::KeyRefusal;
        use crate::node::pairwise_stream::{open_skdm, PairwiseFrame};
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
                match second {
                    Some(PairwiseFrame::Skdm { channel_id, sealed }) => (channel_id, sealed),
                    Some(PairwiseFrame::Open { channel_id, sealed }) => {
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
        let now_ms = self.now_ms();
        let now = now_ms.secs();
        let Some(session) = self.sessions.get_mut(&(channel_id, peer)) else {
            // No session with this peer for that channel: nothing can open it. Said, so the
            // sender sends it again once a join or key exchange establishes one.
            return Some(Err(KeyRefusal::NoSession));
        };
        let Ok(skdm) = open_skdm(session, &sealed, now) else {
            return Some(Err(KeyRefusal::CannotOpen));
        };
        // **A node reads only the members its owner trusts** (V210-118). Trust is decided by each
        // node for itself: the author trusting us releases its key, and that alone must not make
        // it readable here. A key from an author this owner has not trusted is refused, so nothing
        // of theirs opens anywhere on this node; the author's re-key round offers it again, and it
        // is taken once the owner trusts them. A locked node holds no keyring, and is refused as
        // not accepting rather than read as trusting nobody.
        let author = skdm.body.author_id;
        if !self.profile.as_ref().is_some_and(Profile::is_unlocked) {
            return Some(Err(KeyRefusal::NotAccepted));
        }
        if !self.trust.is_trusted(&author) {
            return Some(Err(KeyRefusal::NotTrusted));
        }
        let mut fresh = false;
        let backfilled = match (
            self.profile.as_ref(),
            self.channels.get(&channel_id).map(Arc::clone),
        ) {
            (Some(profile), Some(shared)) => {
                let mut channel = shared.lock().await;
                fresh = !channel.holds_generation(&author, skdm.body.chain_id);
                channel.accept_skdm(profile.store(), &skdm, now_ms).ok()
            }
            _ => None,
        };
        let Some(n) = backfilled else {
            return Some(Err(KeyRefusal::NotAccepted));
        };
        // A generation new to us: the author may have refused ours while we were untrusted, or
        // dropped it when its owner stopped trusting us. Ours is offered again once this stream
        // is answered (see `handle_pairwise`).
        if fresh {
            self.reoffer.insert((channel_id, author));
        }
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
    fn load_prekeys(&mut self, now_ms: u64) -> crate::error::Result<()> {
        let profile = self
            .profile
            .as_ref()
            .ok_or(crate::error::Error::Profile("no identity on this node"))?;
        let signer = profile.signer()?;
        // The ring's identity DH key is the identity's own (ADR-002), taken from the
        // unlocked vault — never a fresh one, or a restore would change it.
        let dh_secret = *signer.x25519_identity_secret();
        let (ring, _created) =
            prekeys::load_or_create(profile.store(), signer, &dh_secret, now_ms)?;
        self.prekeys = Some(Arc::new(tokio::sync::Mutex::new(ring)));
        // The keyring is sealed under this identity, so it can only be opened now
        // (ADR-020 §3). Without this the node would hold an empty keyring and
        // silently trust nobody after every restart.
        self.trust = crate::node::trust::Keyring::load(profile.store(), signer)?;
        // Where members were last reached. A book that will not open is started afresh rather
        // than refusing the unlock: it is a cache of addresses, and the next connection to
        // each member fills it again.
        self.peer_book =
            crate::node::peer_book::PeerBook::load(profile.store(), signer).unwrap_or_default();
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
        let now = self.now_ms().get();
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

    /// Lock now, and settle off the actor.
    ///
    /// Everything the actor holds goes at once: the rooms' keys, the tasks holding the identity
    /// (aborted), the network, the identity itself. What no abort reaches — a blocking thread
    /// still holding a secret, an aborted task not yet polled — is waited for by a task of its
    /// own, which then reports `NetEvent::LockSettled` (V210-94). The actor does not wait for it:
    /// up to one Argon2id derivation, it would answer nobody meanwhile (V210-71). Until then the
    /// node is *locking* ([`NodeView::locking`]). The returned receiver fires once it has settled.
    async fn lock_all(&mut self) -> oneshot::Receiver<()> {
        self.passphrase_entered_at
            .store(0, std::sync::atomic::Ordering::Relaxed);
        for (_, shared) in std::mem::take(&mut self.channels) {
            shared.lock().await.lock_now();
        }
        // Abort the join exchanges and the reopening (#208): each holds the identity or room keys.
        // An aborted task drops what it holds only when it is next polled, so they are collected
        // by the settling task below, not here.
        self.join_tasks.abort_all();
        let aborted = std::mem::take(&mut self.join_tasks);
        let reopening = self.reopen_task.take();
        if let Some(task) = &reopening {
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
        // What the boards held was learnt over the network that goes down with the lock; an address
        // asked for meanwhile is not handed out by a locked node (V210-96).
        self.on_board.clear();
        self.publish_trouble.clear();
        self.anchor_owed.clear();
        for (_, reply, _) in std::mem::take(&mut self.address_waiters) {
            let _ = reply.send(Outcome::Failed(Fault::Locked));
        }
        // A room still leaving resumes when it is held again (`resume_leave`).
        for (_, _, reply, _) in std::mem::take(&mut self.leave_waiters) {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(Fault::Locked));
            }
        }
        // The unlock they wait on did happen; what it reopened is locked again with the rest.
        for reply in std::mem::take(&mut self.unlock_waiters) {
            let _ = reply.send(Outcome::Done);
        }
        // Drop the prekey ring: its secrets zeroize on drop, so a locked node holds
        // no key-agreement material (ADR-015 lock/zeroize).
        self.prekeys = None;
        // The keyring is not secret material, but it is sealed under the identity
        // and says who this operator talks to. A locked node holds neither, and it
        // is re-opened on the next unlock (ADR-020 §3).
        self.trust = crate::node::trust::Keyring::new();
        self.peer_book = crate::node::peer_book::PeerBook::new();
        // The sender keys held for consents not yet delivered are room secrets: dropped, and
        // zeroized as they go (V210-76). They are reloaded, sealed, at the next unlock.
        self.consent_keys = crate::node::pending_consent::PendingConsents::default();
        // Pairwise sessions hold ratchet key material: drop them with everything else
        // (their secrets zeroize on drop).
        self.sessions.clear();
        self.initiated.clear();
        // Their writers end with their queues; what they hold is sealed bytes, no key material.
        self.pairwise_out.clear();
        self.accepted_hello.clear();
        self.reopen.clear();
        self.session_serial.clear();
        // The identity and its signer go before the network does (V210-93, V210-94): stopping
        // the network now says goodbye to every peer and waits, boundedly, for each to hear it and
        // for the closes to leave — up to a couple of seconds for a peer that does not answer —
        // and none of that needs a secret, since a connection's keys are its own. A lock wipes
        // every secret at once; it does not hold the identity while the network winds down.
        // Off the exchange first (ADR-011 requirement 34, ADR-026 L-3): the endpoint holds the
        // signer to sign each PROVE, so it lets go of it before the keys are wiped.
        if let Some(net) = &self.net {
            net.manager().endpoint().unregister();
        }
        if let Some(p) = self.profile.as_mut() {
            p.lock();
        }
        // And take the network down: a locked node has no identity to present, so it
        // must not keep serving or holding connections (M14.7d).
        self.stop_network().await;
        self.locking += 1;
        let (settled, on_settled) = oneshot::channel();
        let secret_work = Arc::clone(&self.secret_work);
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let mut aborted = aborted;
            if let Some(task) = reopening {
                let _ = task.await;
            }
            while aborted.join_next().await.is_some() {}
            // And the blocking threads those tasks started, which no abort reaches: an Argon2id
            // seal with the room passphrase, a passphrase check, a room being reopened with its
            // key. Each holds the read side until it has finished and dropped what it was given,
            // so taking the write side is waiting for the last of them. Nothing new starts
            // meanwhile: the identity is locked, and an unlock waits for this.
            drop(secret_work.write().await);
            let _ = settled.send(());
            let _ = tx.send(NetEvent::LockSettled).await;
        });
        on_settled
    }

    /// A lock's settling reported back ([`Self::lock_all`]): once the last has, the node is
    /// locked. Its lock commands are answered, `Locked` is said, and the unlocks asked for
    /// meanwhile run.
    async fn settle_lock(&mut self) {
        self.locking = self.locking.saturating_sub(1);
        if self.locking > 0 {
            return;
        }
        // The view first: whoever is told the lock is done reads a locked view.
        self.publish().await;
        for (passphrase, reply) in std::mem::take(&mut self.unlock_after_lock) {
            self.unlock_and_answer(&passphrase, reply).await;
        }
    }

    /// Unlock, and answer `reply` — at once, or once the rooms it held are held again (#208):
    /// they reopen off the actor so the node answers everyone meanwhile, but a caller told `Done`
    /// — `vox daemon`, which then opens its control socket — must not find a room it held still
    /// closed.
    async fn unlock_and_answer(&mut self, passphrase: &Secret, reply: oneshot::Sender<Outcome>) {
        let outcome = self.unlock(passphrase).await;
        // The view first, as for every command: a caller told `Done` reads the view at once (the
        // trust keyring, the rooms) and must find the unlock in it.
        self.publish().await;
        if outcome.is_done() && self.reopen_task.is_some() {
            self.unlock_waiters.push(reply);
        } else {
            let _ = reply.send(outcome);
        }
    }

    fn create_channel<'a>(
        &'a mut self,
        room_name: &'a str,
        passphrase: &'a Secret,
    ) -> Boxed<'a, Outcome> {
        Box::pin(self.create_channel_unboxed(room_name, passphrase))
    }

    /// [`Self::create_channel`], unboxed: see [`Boxed`].
    async fn create_channel_unboxed(&mut self, room_name: &str, passphrase: &Secret) -> Outcome {
        if self.room_named(room_name).is_some() {
            return Outcome::Failed(Fault::RoomNameTaken);
        }
        let now_ms = self.now_ms();
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        match ChannelState::create_with_profile(profile, room_name, passphrase, now_ms, self.argon2)
        {
            Ok(ch) => self.finish_create_channel(ch).await,
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    /// Everything after a room exists: hold it, give it anchors, publish it, say so.
    fn finish_create_channel(&mut self, ch: ChannelState) -> Boxed<'_, Outcome> {
        Box::pin(self.finish_create_channel_unboxed(ch))
    }

    /// [`Self::finish_create_channel`], unboxed: see [`Boxed`].
    async fn finish_create_channel_unboxed(&mut self, mut ch: ChannelState) -> Outcome {
        // The node's own retention before the room is visible to anything that can start a
        // session on it (the retention fix, e2a74b9): every creation path comes through here.
        let id = ch.channel_id();
        ch.set_node_retention(self.node_retention_for(&id));
        self.remember_or_say(&ch);
        self.channels
            .insert(id, Arc::new(tokio::sync::Mutex::new(ch)));
        self.adopt_channel_anchors(&id, None).await;
        self.refresh_network_view().await;
        self.publish_channel_locally(&id).await;
        self.publish_channel_to_anchors(&id, PublishCause::Opened)
            .await;
        let _ = self
            .event_tx
            .send(NodeEvent::ChannelOpened { channel_id: id });
        Outcome::Done
    }

    /// Begin creating a room: the genesis here, the Argon2id seal on a blocking thread, and the
    /// reply carried to `NetEvent::ChannelSealed`. Any failure before the seal answers at once.
    /// Check the identity passphrase on a blocking thread and answer `reply` from there.
    fn begin_verify_passphrase(&mut self, passphrase: Secret, reply: oneshot::Sender<Outcome>) {
        let Some(profile) = self.profile.as_ref() else {
            let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
            return;
        };
        let verifier = profile.passphrase_verifier();
        let slots = Arc::clone(&self.verify_slots);
        let secret_work = Arc::clone(&self.secret_work);
        // Waiting for a slot happens here, off the actor; the check itself on a blocking
        // thread, holding the slot until it is done. Tracked, so a lock stops a check still
        // waiting for its slot, and waits for one running (V210-94): each holds the identity
        // passphrase, and a running one the identity it unlocks to compare.
        let reply = AnsweredIfAborted(Some(reply));
        self.reap_join_tasks();
        self.join_tasks.spawn(async move {
            let Ok(slot) = slots.acquire_owned().await else {
                if let Some(reply) = reply.into_reply() {
                    let _ = reply.send(Outcome::Failed(Fault::ShuttingDown));
                }
                return;
            };
            let outcome = secret_blocking(&secret_work, move || {
                let _slot = slot;
                // A check opens no window (ADR-028 K-12): only the keyring change it proves does,
                // as `NodeCommand::Proved`.
                match verifier.verify(&passphrase) {
                    Ok(()) => Outcome::Done,
                    Err(_) => Outcome::Failed(Fault::WrongPassphrase),
                }
            })
            .await
            .unwrap_or(Outcome::Failed(Fault::Internal));
            if let Some(reply) = reply.into_reply() {
                let _ = reply.send(outcome);
            }
        });
    }

    async fn begin_create_channel(
        &mut self,
        room_name: String,
        passphrase: Secret,
        service: Option<(String, SocketAddr)>,
        reply: oneshot::Sender<Outcome>,
    ) {
        // A node holds one room of a name (ADR-028 R-3): it is the room part of every address.
        if self.room_named(&room_name).is_some() {
            let _ = reply.send(Outcome::Failed(Fault::RoomNameTaken));
            return;
        }
        let now_ms = self.now_ms();
        let Some(profile) = self.profile.as_ref() else {
            let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
            return;
        };
        // A service room's genesis is like any other room's: it carries no grant (PRD-001 R44).
        // The service is the host's to offer, and its gate decides who reaches it.
        let (genesis, sek) = match ChannelState::create_genesis(profile, &room_name, now_ms) {
            Ok(g) => g,
            Err(e) => {
                let _ = reply.send(Outcome::Failed(fault_of(&e)));
                return;
            }
        };
        // The identity's half of the seal is taken here, on the actor, so the task below never
        // holds the signer (V210-94).
        let factor_id = match profile
            .signer()
            .and_then(|signer| id_factor_for(signer, &genesis.channel_id()))
        {
            Ok(f) => f,
            Err(e) => {
                let _ = reply.send(Outcome::Failed(fault_of(&e)));
                return;
            }
        };
        let argon2 = self.argon2;
        let tx = self.net_tx.clone();
        let secret_work = Arc::clone(&self.secret_work);
        let seal_passphrase = passphrase.clone();
        // Tracked, so a lock aborts it: it holds the room key (V210-76). The Argon2id half runs
        // on a blocking thread, which cannot be interrupted, so the lock waits for that
        // (`secret_blocking`); it holds the passphrase alone.
        let reply = AnsweredIfAborted(Some(reply));
        self.reap_join_tasks();
        self.join_tasks.spawn(async move {
            // What the service is (ADR-028 S-2), detected while the key is sealed.
            let detect = async {
                match service {
                    Some((tag, endpoint)) => {
                        let udp = crate::tunnel::udp::is_udp(&tag);
                        let kind = crate::node::probe::detect(endpoint, udp).await;
                        Some((tag, endpoint, kind))
                    }
                    None => None,
                }
            };
            let (sealed, service) = tokio::join!(
                seal_off_actor(&secret_work, &factor_id, sek, seal_passphrase, argon2),
                detect
            );
            let Some(reply) = reply.into_reply() else {
                return;
            };
            let _ = tx
                .send(NetEvent::ChannelSealed {
                    reply,
                    room_name,
                    passphrase,
                    genesis: Box::new(genesis),
                    now: now_ms,
                    sealed,
                    service,
                })
                .await;
        });
    }

    /// Finish a service room whose key was sealed off the actor, and offer its one service,
    /// atomically (ADR-017).
    ///
    /// The two halves are one command because either alone is a lie: a service room with
    /// no service hands out an address for nothing, and a service in a room nobody can
    /// join is unreachable. If the service cannot be offered the room is
    /// not kept.
    fn finish_serve_room<'a>(
        &'a mut self,
        channel: ChannelState,
        tag: &'a str,
        endpoint: SocketAddr,
        kind: crate::governance::share::ServiceKind,
    ) -> Boxed<'a, Outcome> {
        Box::pin(self.finish_serve_room_unboxed(channel, tag, endpoint, kind))
    }

    /// [`Self::finish_serve_room`], unboxed: see [`Boxed`].
    async fn finish_serve_room_unboxed(
        &mut self,
        mut channel: ChannelState,
        tag: &str,
        endpoint: SocketAddr,
        kind: crate::governance::share::ServiceKind,
    ) -> Outcome {
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let id = channel.channel_id();
        let now_ms = self.now_ms();
        // Offered and said to the room (V030-25) together: a share its members cannot list is
        // half a share.
        if let Err(e) = channel
            .add_service(profile.store(), profile, tag, endpoint, kind, true)
            .and_then(|_| channel.say_share(profile, tag, true, now_ms))
        {
            // Drop the room rather than keep a half-made one. Nothing outside this
            // function has seen it: it is not in `self.channels` and has not been
            // published, so forgetting it here is the whole of the rollback.
            return Outcome::Failed(fault_of(&e));
        }
        channel.set_node_retention(self.node_retention_for(&id));
        self.remember_or_say(&channel);
        self.channels
            .insert(id, Arc::new(tokio::sync::Mutex::new(channel)));
        self.adopt_channel_anchors(&id, None).await;
        self.refresh_network_view().await;
        self.publish_channel_locally(&id).await;
        self.publish_channel_to_anchors(&id, PublishCause::Opened)
            .await;
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
    /// under the identity, and then goes through exactly what [`Self::begin_open_channel`] does after
    /// an open.
    ///
    /// A room that no longer exists in the store is forgotten. A room that exists but will not
    /// open stays remembered, so the next unlock tries it again, and stays **closed**, which
    /// the daemon reports ("N room(s) open, M still closed") — it is not a reason to refuse the
    /// identity and every other room with it.
    async fn reopen_remembered(&mut self) {
        let now_ms = self.now_ms();
        // Only the sealed set is read here — one small decrypt. Opening each room reads and
        // re-verifies its whole log, and that runs **off the actor**, one room at a time, each
        // held as soon as it is open: with many rooms, a reopen on the actor answered nobody until
        // the last one was open.
        let (store, rooms, me) = {
            let Some(profile) = self.profile.as_ref() else {
                return;
            };
            let Ok(signer) = profile.signer() else {
                return;
            };
            let me = crate::identity::composite::RootSigner::fingerprint(signer);
            let Ok(set) = OpenRooms::load(profile.store(), signer) else {
                return;
            };
            let rooms: Vec<_> = set
                .rooms()
                .filter(|(id, _)| !self.channels.contains_key(*id))
                .map(|(id, keys)| (*id, keys.sek.clone(), keys.passphrase.clone()))
                .collect();
            (profile.store_handle(), rooms, me)
        };
        if rooms.is_empty() {
            return;
        }
        self.reopening.extend(rooms.iter().map(|(id, _, _)| *id));
        let tx = self.net_tx.clone();
        let secret_work = Arc::clone(&self.secret_work);
        let task = tokio::spawn(async move {
            for (id, sek, passphrase) in rooms {
                let store = Arc::clone(&store);
                // The room's key and passphrase go to a blocking thread, which a lock waits for
                // (V210-94).
                let opened = secret_blocking(&secret_work, move || {
                    match store.get_sek_wrap(&id) {
                        Ok(Some(_)) => {}
                        Ok(None) => return Err(None),
                        // Unreadable now: left in the set for the next unlock, and closed.
                        Err(e) => return Err(Some(e.to_string())),
                    }
                    let sek = crate::atrest::sek::Sek::from_bytes(sek);
                    #[cfg(feature = "test-knobs")]
                    if let Ok(why) = std::env::var(TEST_REOPEN_FAILS_ENV) {
                        return Err(Some(why));
                    }
                    ChannelState::open_with_sek(&store, &id, sek, &passphrase, me, now_ms)
                        .map_err(|e| Some(e.to_string()))
                })
                .await;
                let event = match opened {
                    Some(Ok(channel)) => NetEvent::Reopened {
                        channel_id: id,
                        channel: Box::new(channel),
                    },
                    Some(Err(None)) => NetEvent::ReopenGone { channel_id: id },
                    // A room that exists but will not open stays remembered and closed, and why
                    // is said (#412).
                    Some(Err(Some(why))) => NetEvent::ReopenFailed {
                        channel_id: id,
                        why,
                    },
                    None => NetEvent::ReopenFailed {
                        channel_id: id,
                        why: "the reopening stopped before it was tried".to_owned(),
                    },
                };
                if tx.send(event).await.is_err() {
                    return;
                }
            }
            let _ = tx.send(NetEvent::ReopenFinished).await;
        });
        self.reopen_task = Some(task);
    }

    /// Open a room with its passphrase: **unwrap its key and re-verify its log off the actor**
    /// (V210-71), then hold it through `NetEvent::ChannelUnsealed`.
    ///
    /// The unwrap is production Argon2id and the open re-verifies every entry of the room's log;
    /// on the actor, every other room's posts, reads and syncs waited behind both.
    fn begin_open_channel(
        &mut self,
        channel_id: Digest32,
        passphrase: Secret,
        reply: oneshot::Sender<Outcome>,
    ) {
        if self.channels.contains_key(&channel_id) {
            let _ = reply.send(Outcome::Done);
            return;
        }
        let now_ms = self.now_ms();
        let Some(profile) = self.profile.as_ref() else {
            let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
            return;
        };
        let signer = match profile.signer_arc() {
            Ok(s) => s,
            Err(e) => {
                let _ = reply.send(Outcome::Failed(fault_of(&e)));
                return;
            }
        };
        let me = crate::identity::composite::RootSigner::fingerprint(&*signer);
        let store = profile.store_handle();
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let opened = tokio::task::spawn_blocking(move || {
                let wrap = store
                    .get_sek_wrap(&channel_id)?
                    .ok_or(Error::Profile("no such room on this node"))?;
                let factor = crate::atrest::idfactor::SignatureIdentityFactor::new(&*signer);
                let sek = wrap.unwrap_sek(&factor, &channel_id, &passphrase)?;
                ChannelState::open_with_sek(&store, &channel_id, sek, &passphrase, me, now_ms)
            })
            .await
            .unwrap_or(Err(Error::Argon2Failed));
            let _ = tx
                .send(NetEvent::ChannelUnsealed {
                    reply,
                    channel_id,
                    opened: Box::new(opened),
                })
                .await;
        });
    }

    /// Hold a room opened off the actor: everything [`Self::begin_open_channel`] leaves.
    fn finish_open_channel(&mut self, ch: ChannelState) -> Boxed<'_, Outcome> {
        Box::pin(self.finish_open_channel_unboxed(ch))
    }

    /// [`Self::finish_open_channel`], unboxed: see [`Boxed`].
    async fn finish_open_channel_unboxed(&mut self, mut ch: ChannelState) -> Outcome {
        let channel_id = ch.channel_id();
        // The node's own retention before the room is visible to anything that can start a
        // session on it (the retention fix, e2a74b9).
        ch.set_node_retention(self.node_retention_for(&channel_id));
        // What the open set aside is reported (V210-74), as a reopen reports it.
        crate::node::status::SyncBook::note_set_aside(&self.sync_book, channel_id, ch.set_aside());
        self.remember_or_say(&ch);
        self.channels
            .insert(channel_id, Arc::new(tokio::sync::Mutex::new(ch)));
        self.mark_decisions_on_open(&channel_id).await;
        self.resume_leave(&channel_id).await;
        self.act_on_removals_while_closed(&channel_id).await;
        self.adopt_channel_anchors(&channel_id, None).await;
        self.refresh_network_view().await;
        // As a reopened room: the app gate must know the room before anything dials it.
        self.refresh_reachers().await;
        self.publish_channel_locally(&channel_id).await;
        self.publish_channel_to_anchors(&channel_id, PublishCause::Opened)
            .await;
        self.install_key_packages(&channel_id).await;
        self.reach_members_of(&channel_id).await;
        let _ = self.event_tx.send(NodeEvent::ChannelOpened { channel_id });
        Outcome::Done
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
                // And no address to it is handed out now (V210-96).
                self.on_board.retain(|(r, _)| r != channel_id);
                self.publish_trouble.retain(|(r, _), _| r != channel_id);
                self.anchor_owed.retain(|(r, _), _| r != channel_id);
                let (closed, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.address_waiters)
                    .into_iter()
                    .partition(|(r, _, _)| r == channel_id);
                self.address_waiters = waiting;
                for (_, reply, _) in closed {
                    let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
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

    /// Leave a room (V210-164): write this identity's departure into it, take this identity's
    /// records off boards (V030-14), push the departure to the room's other members, and answer
    /// once one of them has it — then the room is deleted from this node
    /// ([`Self::finish_leave_if_heard`]). Waiting is what makes the leave seen: a room deleted
    /// first would take the only copy of the departure with it.
    async fn begin_leave(&mut self, channel_id: Digest32, reply: oneshot::Sender<Outcome>) {
        let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
            let held = self
                .profile
                .as_ref()
                .and_then(|p| p.store().channels().ok())
                .is_some_and(|c| c.contains(&channel_id));
            let _ = reply.send(Outcome::Failed(if held {
                Fault::ChannelNotOpen
            } else {
                Fault::UnknownChannel
            }));
            return;
        };
        if self.net.is_none() {
            let _ = reply.send(Outcome::Failed(Fault::NotNetworked));
            return;
        }
        let now_ms = self.now_ms();
        let written = {
            let Some(profile) = self.profile.as_ref() else {
                let _ = reply.send(Outcome::Failed(Fault::Locked));
                return;
            };
            let mut ch = shared.lock().await;
            let written = ch.say_presence(profile, false, now_ms).map(|_| {
                (
                    ch.generation().load(std::sync::atomic::Ordering::Relaxed),
                    ch.members().into_iter().all(|m| m == ch.me()),
                )
            });
            if written.is_ok() {
                self.fresh_details
                    .insert(channel_id, (summary_of(&ch), detail_of(&ch, None)));
            }
            written
        };
        let (gen, alone) = match written {
            Ok(w) => w,
            Err(e) => {
                let _ = reply.send(Outcome::Failed(fault_of(&e)));
                return;
            }
        };
        self.withdraw_from_boards(&channel_id, crate::nat::withdraw::WithdrawScope::Member)
            .await;
        // Nobody else is in the room: there is nobody to tell.
        if alone {
            let _ = reply.send(self.purge_room(&channel_id).await);
            return;
        }
        self.wait_for_leave(channel_id, gen, Some(reply)).await;
    }

    /// Push a written departure to the room's members, and delete the room once one has it.
    async fn wait_for_leave(
        &mut self,
        channel_id: Digest32,
        gen: u64,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        self.note_local_append(&channel_id);
        let _ = self.sync_channel(&channel_id).await;
        self.leave_serial += 1;
        let serial = self.leave_serial;
        self.leave_waiters.push((channel_id, gen, reply, serial));
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(LEAVE_PATIENCE).await;
            let _ = tx
                .send(NetEvent::LeaveWaitOver { channel_id, serial })
                .await;
        });
    }

    /// A room held again whose own feed ends in this identity's departure was being left when
    /// the node stopped or locked, before any member had it (V210-164): go on leaving it.
    async fn resume_leave(&mut self, channel_id: &Digest32) {
        if self
            .leave_waiters
            .iter()
            .any(|(r, _, _, _)| r == channel_id)
        {
            return;
        }
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return;
        };
        let gen = {
            let ch = shared.lock().await;
            // A room joined and not yet synced is one this node came back to: it says so once
            // settled (`settle_room`), however its feed ended before.
            if !ch.is_settled() || !ch.has_left(&ch.me()) {
                return;
            }
            ch.generation().load(std::sync::atomic::Ordering::Relaxed)
        };
        self.wait_for_leave(*channel_id, gen, None).await;
    }

    /// A sync session of `channel_id` ended cleanly having sent this node's HAVE at generation
    /// `sent`: a leave whose departure was written at or before it has been heard, and the room
    /// is deleted.
    async fn finish_leave_if_heard(&mut self, channel_id: Digest32, sent: u64) {
        let (heard, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.leave_waiters)
            .into_iter()
            .partition(|(r, gen, _, _)| *r == channel_id && *gen <= sent);
        self.leave_waiters = waiting;
        if heard.is_empty() {
            return;
        }
        // Written in the room since — it posted, or said it is back — and so not leaving.
        let still_left = match self.channels.get(&channel_id) {
            Some(shared) => {
                let ch = shared.lock().await;
                ch.has_left(&ch.me())
            }
            None => false,
        };
        let outcome = if still_left {
            self.purge_room(&channel_id).await
        } else {
            // In the room again: its records go on boards again.
            self.withdrawn.remove(&channel_id);
            Outcome::Failed(Fault::LeaveUndone)
        };
        for reply in heard.into_iter().filter_map(|(_, _, reply, _)| reply) {
            let _ = reply.send(outcome);
        }
    }

    /// Take a room off boards (V030-14): sign a withdraw — this identity's own records after a
    /// leave, the whole room after an end — and put it on this node's board and every anchor
    /// connected now, and say how many those were. One that connects later is told when it does
    /// (`withdrawn`).
    async fn withdraw_from_boards(
        &mut self,
        channel_id: &Digest32,
        scope: crate::nat::withdraw::WithdrawScope,
    ) -> usize {
        let now_ms = self.now_ms().get();
        let (Some(net), Some(profile)) = (self.net.as_ref().map(Arc::clone), self.profile.as_ref())
        else {
            return 0;
        };
        let Ok(signer) = profile.signer() else {
            return 0;
        };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return 0;
        };
        let epoch = shared.lock().await.epoch();
        let Ok(w) =
            crate::nat::withdraw::BoardWithdraw::build(signer, channel_id, epoch, scope, now_ms)
        else {
            return 0;
        };
        let wire = w.to_wire();
        let _ = net.publish_local(&wire);
        self.withdrawn.insert(*channel_id, wire.clone());
        let anchors: Vec<Arc<VoxConnection>> = self
            .anchor_ids
            .iter()
            .filter_map(|id| net.manager().existing(id))
            .collect();
        for conn in &anchors {
            Self::put_withdraws(conn, vec![wire.clone()]);
        }
        anchors.len()
    }

    /// The room's admin roster, signed (V030-14), when this node is its creator: who besides it a
    /// board takes the room off from. Stamped with the newest admin change on the log, so putting
    /// it again changes nothing on a board that holds it.
    async fn admin_roster(&self, channel_id: &Digest32) -> Option<Vec<u8>> {
        let profile = self.profile.as_ref()?;
        let signer = profile.signer().ok()?;
        let shared = self.channels.get(channel_id).map(Arc::clone)?;
        let ch = shared.lock().await;
        let me = ch.me();
        if me != ch.genesis().creator_pubkey().fingerprint() {
            return None;
        }
        let stamp = ch.admin_change_clock()?;
        let admins: Vec<Digest32> = ch.admins().into_iter().filter(|a| *a != me).collect();
        crate::nat::withdraw::AdminRoster::build(signer, channel_id, stamp, admins)
            .ok()
            .map(|r| r.to_wire())
    }

    /// Put the room's admin roster on this node's board and every anchor connected now (V030-14).
    async fn publish_admin_roster(&mut self, channel_id: &Digest32) {
        let Some(wire) = self.admin_roster(channel_id).await else {
            return;
        };
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        let _ = net.publish_local(&wire);
        for conn in self
            .anchor_ids
            .iter()
            .filter_map(|id| net.manager().existing(id))
        {
            Self::put_withdraws(&conn, vec![wire.clone()]);
        }
    }

    /// Put `withdraws` on the board at `conn`, off the actor. A put the board never answered —
    /// a stream that would not open, or broke — is tried again a few times while the connection
    /// lasts, so a leave or end made just after this node reconnected still reaches the board at
    /// once, not at its next reconnect. A board's refusal is its answer and is not retried.
    fn put_withdraws(conn: &Arc<VoxConnection>, withdraws: Vec<Vec<u8>>) {
        if withdraws.is_empty() {
            return;
        }
        let conn = Arc::clone(conn);
        tokio::spawn(async move {
            let mut pending = withdraws;
            for wait_ms in [0_u64, 250, 1_000, 2_000, 4_000] {
                tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await;
                let Ok(mut client) = crate::nat::service::RendezvousClient::open(&conn).await
                else {
                    continue;
                };
                let mut unanswered = Vec::new();
                for w in pending {
                    let said = client.put(&w).await;
                    #[cfg(feature = "mutant-sender")]
                    eprintln!(
                        "{}: a board answered a withdraw: {}",
                        crate::log::sync::mutant::MARKER,
                        match &said {
                            Ok(()) => "taken".to_owned(),
                            Err(crate::error::Error::RendezvousRejected(r)) => {
                                format!("refused ({r})")
                            }
                            Err(e) => format!("no answer ({e})"),
                        }
                    );
                    match said {
                        Ok(()) | Err(crate::error::Error::RendezvousRejected(_)) => {}
                        Err(_) => unanswered.push(w),
                    }
                }
                client.finish();
                if unanswered.is_empty() {
                    return;
                }
                pending = unanswered;
            }
        });
    }

    /// End a room for everyone (V030-08): its creator's signed end, passed on like a leave.
    async fn end_room(&mut self, channel_id: &Digest32) -> Outcome {
        let now_ms = self.now_ms();
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        {
            let mut ch = shared.lock().await;
            if ch.ended((self.millis_clock)()).is_some() {
                return Outcome::Failed(Fault::RoomEnded);
            }
            if let Err(e) = ch.end(profile, now_ms) {
                // The faulty peer a board must not obey (V030-14's proof): it takes the room off
                // boards though it may not end it.
                #[cfg(feature = "mutant-sender")]
                if crate::log::sync::mutant::withdraws_unentitled() {
                    drop(ch);
                    let anchors = self
                        .withdraw_from_boards(channel_id, crate::nat::withdraw::WithdrawScope::Room)
                        .await;
                    eprintln!(
                        "{}: put a room withdraw for {} to {anchors} anchor(s) though this node \
                         may not end it",
                        crate::log::sync::mutant::MARKER,
                        crate::node::network::short_id(*channel_id)
                    );
                }
                return Outcome::Failed(fault_of(&e));
            }
            self.fresh_details
                .insert(*channel_id, (summary_of(&ch), detail_of(&ch, None)));
        }
        self.note_local_append(channel_id);
        self.withdraw_from_boards(channel_id, crate::nat::withdraw::WithdrawScope::Room)
            .await;
        // `tend_lifecycle` starts the wind-down: the room is ended from here on, on this node.
        let _ = self.tend_lifecycle().await;
        Outcome::Done
    }

    /// Make a member an admin, or take it back (V030-08).
    async fn set_admin(
        &mut self,
        channel_id: &Digest32,
        member: &Digest32,
        admin: bool,
    ) -> Outcome {
        let now_ms = self.now_ms();
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        {
            let mut ch = shared.lock().await;
            let done = if admin {
                ch.add_admin(profile, member, now_ms).map(|_| ())
            } else {
                ch.remove_admin(profile, member, now_ms).map(|_| ())
            };
            if let Err(e) = done {
                return Outcome::Failed(fault_of(&e));
            }
            self.fresh_details
                .insert(*channel_id, (summary_of(&ch), detail_of(&ch, None)));
        }
        self.note_local_append(channel_id);
        // The boards learn who may take the room off them (V030-14).
        self.publish_admin_roster(channel_id).await;
        Outcome::Done
    }

    /// Choose a room's idle end (V030-08).
    async fn choose_idle_end(&mut self, channel_id: &Digest32, idle_secs: u64) -> Outcome {
        let now_ms = self.now_ms();
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        {
            let mut ch = shared.lock().await;
            if let Err(e) = ch.choose_idle_end(profile, idle_secs, now_ms) {
                return Outcome::Failed(fault_of(&e));
            }
            self.fresh_details
                .insert(*channel_id, (summary_of(&ch), detail_of(&ch, None)));
        }
        self.note_local_append(channel_id);
        Outcome::Done
    }

    /// Delete everything this node holds of a room, now (V030-08): its state, every stored row
    /// and its key, its place among the rooms reopened at unlock, the consents pending in it,
    /// and then the store is rewritten so none of the deleted bytes stay in the file. A room left
    /// (V210-164) or ended (the decider, 2026-10-03) goes this way.
    async fn purge_room(&mut self, channel_id: &Digest32) -> Outcome {
        // A leave still waiting for this room is overtaken: the room is joined again from scratch.
        let (overtaken, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.leave_waiters)
            .into_iter()
            .partition(|(r, _, _, _)| r == channel_id);
        self.leave_waiters = waiting;
        for reply in overtaken.into_iter().filter_map(|(_, _, reply, _)| reply) {
            let _ = reply.send(Outcome::Failed(Fault::LeaveUndone));
        }
        let mut name = String::new();
        if let Some(shared) = self.channels.remove(channel_id) {
            let mut ch = shared.lock().await;
            name = crate::node::resolver::room_shown(ch.name(), channel_id);
            ch.lock_now();
        }
        // The read cursors and held-claim records agent sessions kept for it go too: nothing
        // filed under the room outlives it.
        self.paths
            .remove_room_cursors(&crate::node::link::b32_encode(channel_id), &name);
        self.reopening.remove(channel_id);
        if let Err(e) = self.forget_open(channel_id) {
            return Outcome::Failed(fault_of(&e));
        }
        if let Some(net) = self.net.as_ref() {
            net.membership().clear_channel(channel_id);
        }
        let peers: Vec<Digest32> = self
            .ports
            .keys()
            .filter(|(r, _)| r == channel_id)
            .map(|(_, p)| *p)
            .collect();
        for peer in peers {
            self.drop_port(channel_id, &peer);
        }
        self.winding.remove(channel_id);
        self.records_renew_at.remove(channel_id);
        self.departed_seen.remove(channel_id);
        self.fresh_details.remove(channel_id);
        // Kept: an anchor away now is still told when it connects. A join of the room again
        // (`begin_join_channel`) takes it out.
        self.room_anchors.remove(channel_id);
        self.reachers.remove(channel_id);
        crate::node::status::SyncBook::forget_room(&self.sync_book, channel_id);
        self.sched_rooms.remove(channel_id);
        self.discover_rooms.remove(channel_id);
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        // What was kept for the room beside the keyring goes with it: the sender keys owed to its
        // members, and the members owed a new key.
        if let Ok(signer) = profile.signer() {
            if self.consent_keys.forget_room(channel_id) {
                let _ = self.consent_keys.save(profile.store(), signer);
            }
            if let Ok(mut locks) =
                crate::node::pending_lock::PendingLocks::load(profile.store(), signer)
            {
                if locks.clear_room(channel_id) {
                    let _ = locks.save(profile.store(), signer);
                }
            }
        }
        if let Err(e) = profile.store().purge_channel(channel_id) {
            return Outcome::Failed(fault_of(&e));
        }
        if let Err(e) = profile.store().rewrite_fresh() {
            return Outcome::Failed(fault_of(&e));
        }
        self.refresh_network_view().await;
        // Published before it is said: whoever is told the room is deleted and then looks
        // (`vox room list`) must not still see it.
        self.publish().await;
        let _ = self.event_tx.send(NodeEvent::RoomRemoved {
            channel_id: *channel_id,
        });
        Outcome::Done
    }

    /// Tend every room's lifecycle (V030-08), each tick and after a leave or an end:
    /// - a member that left is synced with no more and delivered nothing: it is simply not in the
    ///   room (the decider, 2026-10-01: no key rotation — "the node that left is no longer in the
    ///   swarm/room");
    /// - a room this node holds ended passes the end on — each member synced with after it
    ///   counts, up to [`WIND_DOWN`] — and is then deleted (the decider, 2026-10-03: "a room the
    ///   admin ended should not need a forget"). A room left is deleted by the leave itself.
    async fn tend_lifecycle(&mut self) -> bool {
        let mut changed = false;
        let now_ms = (self.millis_clock)();
        let rooms: Vec<(Digest32, Arc<tokio::sync::Mutex<ChannelState>>)> = self
            .channels
            .iter()
            .map(|(c, s)| (*c, Arc::clone(s)))
            .collect();
        let store = self.profile.as_ref().map(Profile::store_handle);
        for (cid, shared) in rooms {
            let Ok(mut ch) = shared.try_lock() else {
                continue; // a session holds it; the next tick tends it
            };
            let me = ch.me();
            let departed: Vec<Digest32> = ch
                .author_fingerprints()
                .into_iter()
                .filter(|a| *a != me && ch.has_left(a))
                .collect();
            // A member that left and came back joined from scratch and holds none of this
            // identity's keys: they are delivered to it again.
            let seen = self.departed_seen.entry(cid).or_default();
            let back: Vec<Digest32> = seen
                .iter()
                .filter(|d| !departed.contains(d))
                .copied()
                .collect();
            let newly: Vec<Digest32> = departed
                .iter()
                .filter(|d| !seen.contains(*d))
                .copied()
                .collect();
            let ended_here = ch.ended(now_ms).is_some();
            *seen = departed.iter().copied().collect();
            if let Some(store) = store.as_ref() {
                for b in back {
                    let _ = ch.forget_delivery(store, &b);
                }
            }
            let over = ch.ended(now_ms).is_some();
            // An idle end has nobody to sign it: the creator's node takes the room off boards
            // when it sees it run out (V030-14).
            let idle_ended_here = me == ch.genesis().creator_pubkey().fingerprint()
                && matches!(
                    ch.ended(now_ms),
                    Some(crate::node::channel::RoomEnd::Idle { .. })
                );
            let members: Vec<Digest32> = ch.members().into_iter().filter(|m| *m != me).collect();
            let gen = ch.generation().load(std::sync::atomic::Ordering::Relaxed);
            drop(ch);
            for d in &departed {
                if self.ports.contains_key(&(cid, *d)) {
                    self.drop_port(&cid, d);
                }
            }
            // This node's own board no longer offers what the room's log says is gone (V030-14):
            // a member that left, or the whole room once it ended. A joiner reading it, or an
            // anchor this node mirrors to, would otherwise be handed them.
            if let Some(net) = self.net.as_ref() {
                let now_ms = self.now_ms().get();
                for d in &newly {
                    net.forget_member_on_board(&cid, d, now_ms);
                }
                if ended_here {
                    net.forget_room_on_board(&cid);
                }
            }
            if idle_ended_here && !self.withdrawn.contains_key(&cid) {
                self.withdraw_from_boards(&cid, crate::nat::withdraw::WithdrawScope::Room)
                    .await;
            }
            if !over {
                continue;
            }
            let winding = self.winding.entry(cid).or_insert(Winding {
                gen,
                since: std::time::Instant::now(),
            });
            let (want, since) = (winding.gen, winding.since);
            let mut handed = 0usize;
            for m in &members {
                if self.ensure_port(&cid, m).await
                    && self
                        .ports
                        .get(&(cid, *m))
                        .is_some_and(|p| p.done_gen >= want)
                {
                    handed += 1;
                }
            }
            if handed < members.len() && since.elapsed() < WIND_DOWN {
                continue;
            }
            self.winding.remove(&cid);
            let _ = self.event_tx.send(NodeEvent::RoomEnded {
                channel_id: cid,
                handed,
                members: members.len(),
            });
            let _ = self.purge_room(&cid).await;
            changed = true;
        }
        changed
    }

    /// A sync of `channel_id` with another member ended cleanly: a room joined here now holds its
    /// own feed as the room does, and may be written to (V210-164). A feed that already holds
    /// entries means this identity was in the room before: it moves to a sender generation the
    /// others do not hold yet, and, if its feed ends in its departure, says it is back, so the
    /// other members list it again before it says anything else.
    async fn settle_room(&mut self, channel_id: &Digest32) {
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return;
        };
        let now_ms = self.now_ms();
        let back = {
            let Some(profile) = self.profile.as_ref() else {
                return;
            };
            let mut ch = shared.lock().await;
            if !matches!(ch.settle(profile.store()), Ok(true)) {
                return;
            }
            ch.catch_up_generation(profile, now_ms)
                .and_then(|_| ch.say_presence(profile, true, now_ms))
                .map(|back| {
                    // Shares made while the room was unsettled are said now (V030-25). A share
                    // left unsaid is offered but unlisted, which is not worth failing the room.
                    let said = ch.say_unsaid_shares(profile, now_ms).unwrap_or(false);
                    back || said
                })
        };
        match back {
            Ok(true) => self.note_local_append(channel_id),
            Ok(false) => {}
            Err(e) => {
                let _ = self.event_tx.send(NodeEvent::JoinFailed {
                    reason: format!(
                        "joined room {} again, but could not start a new sender key in it: {e}",
                        crate::node::network::short_id(*channel_id)
                    ),
                });
            }
        }
    }

    /// Offer a local TCP service in a channel (ADR-013 Bind, M16.1). Offering needs no
    /// capability (ADR-017 M17.7); who may reach it is the host's dial gate.
    async fn add_service(
        &mut self,
        channel_id: &Digest32,
        service_tag: &str,
        local: std::net::SocketAddr,
        kind: crate::governance::share::ServiceKind,
        persist: bool,
    ) -> Outcome {
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        let now_ms = self.now_ms();
        let outcome = {
            let mut channel = shared.lock().await;
            channel
                .add_service(profile.store(), profile, service_tag, local, kind, persist)
                .and_then(|_| {
                    // A share is said to the room so its members can list it (V030-25); a
                    // transient offer — a file being handed over — is not a share. If it cannot
                    // be said, the service is not offered either.
                    if !persist {
                        return Ok(());
                    }
                    // A room joined and not yet synced cannot be written to (V210-164): the share
                    // is offered now and said when the room settles (`say_unsaid_shares`).
                    match channel.say_share(profile, service_tag, true, now_ms) {
                        Err(crate::error::Error::RoomNotSynced) => Ok(()),
                        Err(e) => {
                            let _ = channel.remove_service(profile.store(), service_tag);
                            Err(e)
                        }
                        Ok(()) => Ok(()),
                    }
                })
        };
        match outcome {
            Ok(()) => {
                if persist {
                    self.note_local_append(channel_id);
                }
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
        let now_ms = self.now_ms();
        let outcome = {
            let mut channel = shared.lock().await;
            let was_shared = channel.is_shared(service_tag);
            let removed = channel.remove_service(profile.store(), service_tag);
            // The room is told it is no longer shared (V030-25). Not saying so leaves it listed
            // where nothing answers — a wrong listing, not a failed removal: the service is gone
            // either way.
            if matches!(removed, Ok(true)) && was_shared {
                let _ = channel.say_share(profile, service_tag, false, now_ms);
            }
            removed
        };
        match outcome {
            Ok(true) => {
                self.note_local_append(channel_id);
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
    /// Names resolve as `<service>.<node>.<room>.vox` (V030-25) against this node's rooms and
    /// keyring as they stand when each connection asks. The connection to the sharing node is
    /// established per request, through the ADR-012 ladder, so the proxy never dials a peer
    /// itself — it asks the node for a connection and refuses if there is none.
    async fn bring_up(&mut self, channel_id: &Digest32, bind: std::net::SocketAddr) -> Outcome {
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        let name = shared.lock().await.name().map(str::to_owned);
        let room = {
            let view = self.view_tx.borrow();
            crate::node::resolver::room_shown_here(
                name.as_deref(),
                channel_id,
                view.channels.iter().map(|c| c.name.as_deref()),
            )
        };
        // The name to tell the person: a service shared in the room is
        // `<service>.<node>.<room>.vox` (V030-25), and nothing shorter is an address.
        let hostname = format!("<service>.<node>.{room}.vox");
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return Outcome::Failed(Fault::NotNetworked);
        };
        // Loopback only, refused **before the bind and before `Done`** (V210-152). `up::serve`
        // refuses it too, but on its own task after this has answered: a non-loopback `--bind`
        // printed "vox up on 0.0.0.0:…" and the ssh hint while nothing was listening.
        if !bind.ip().is_loopback() {
            return Outcome::Failed(Fault::NotLoopback);
        }
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
            Err(e) => return Outcome::Failed(Fault::of_bind(crate::error::BindCause::of(&e))),
        };
        let bound = match listener.local_addr() {
            Ok(a) => a,
            Err(_) => return Outcome::Failed(Fault::Internal),
        };
        let resolver = Arc::new(NodeNames {
            net_tx: self.net_tx.clone(),
        });
        // No dial here: the host is reached per request (see `up::HostDialer`). Dialling
        // first would refuse to start on a race — a node that has just joined has not read
        // the board — and retrying here would block the actor tick that reads it.
        let dialer = Arc::new(NodeDialer {
            net,
            channel_id: None,
        });
        // The proxy is a library and cannot print, so a session cut by a withdrawal of
        // reach comes back as an event (M17.11). A broadcast send never blocks and drops
        // when nobody is listening, which is the right trade for a notice.
        let events = self.event_tx.clone();
        tokio::spawn(crate::node::up::serve_reporting(
            listener,
            resolver,
            dialer,
            Arc::clone(&self.udp_flows),
            {
                let events = events.clone();
                move |room: &Digest32, port: u16| {
                    let _ = events.send(NodeEvent::ReachWithdrawn {
                        channel_id: *room,
                        port,
                    });
                }
            },
            move |_room: Option<Digest32>, note: crate::node::tunnel::TunnelNote| {
                let _ = events.send(note_event(note));
            },
        ));
        let _ = self.event_tx.send(NodeEvent::ProxyUp {
            channel_id: *channel_id,
            hostname,
            bind: bound,
        });
        Outcome::Done
    }

    /// A snapshot of every `.vox` name this node can resolve: its open rooms under their
    /// local names with their members, its keyring's names, and — for the older
    /// `<room-id>.vox` form — each service room's creator.
    async fn resolver_snapshot(&self) -> crate::node::resolver::VoxResolver {
        let mut names = crate::node::resolver::VoxResolver::new();
        let view = self.view_tx.borrow().clone();
        for room in &view.open_channels {
            names.add_room(room.channel_id, room.name.as_deref(), &room.members);
            names.set_synced(room.channel_id, room.synced);
            for share in &room.shares {
                names.add_share(room.channel_id, share.host, &share.name, share.udp);
            }
        }
        for (fp, petname) in self.trust.iter() {
            names.name(*fp, petname);
        }
        names
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
        if local.port() != 0 {
            if let Err(e) = std::net::TcpListener::bind(local) {
                return refuse(reply, Fault::of_bind(crate::error::BindCause::of(&e)));
            }
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
            // Nothing known for the host here: read a connected board before bridging (V210-122,
            // V030-22).
            let endpoints = if endpoints.is_empty() {
                net.member_endpoints(&channel_id, host).await
            } else {
                endpoints
            };
            let result = match net.reach(host, &endpoints).await {
                Ok(conn) => {
                    // A forward whose every connection would be refused is refused now, in
                    // words, rather than bound and then resetting each connection (V210-81).
                    let room = conn.room_for_a_tunnel();
                    let _ = tx
                        .send(NetEvent::Dialed {
                            conn,
                            endpoints,
                            board: false,
                        })
                        .await;
                    room
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
            // A member reached, whose connection carries all the tunnels it may, is not one
            // that could not be reached.
            if !matches!(e, Error::TunnelLimit(_)) {
                let _ = self.event_tx.send(NodeEvent::PeerUnreachable {
                    peer: *host,
                    why: e.to_string(),
                });
            }
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
            channel_id: Some(*channel_id),
        });
        let events = self.event_tx.clone();
        let report = move |note: crate::node::tunnel::TunnelNote| {
            let _ = events.send(note_event(note));
        };
        let bound = if crate::tunnel::udp::is_udp(service_tag) {
            crate::node::tunnel::Forward::bind_udp(
                dialer,
                *host,
                *channel_id,
                service_tag.to_owned(),
                local,
                Arc::clone(&self.udp_flows),
                report,
            )
            .await
        } else {
            crate::node::tunnel::Forward::bind(
                dialer,
                *host,
                *channel_id,
                service_tag.to_owned(),
                local,
                report,
            )
            .await
        };
        match bound {
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
        let Some(me) = self.net.as_ref().map(|n| n.local_id()) else {
            return out;
        };
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
                    me,
                },
            );
        }
        out
    }

    /// File every peer this node is connected to as seen now, for `vox status`'s
    /// last-seen column and its unreachable flag.
    fn note_peers_seen(&mut self) {
        let Some(net) = self.net.as_ref() else { return };
        let now = self.now_ms().get();
        for peer in net.manager().peers() {
            self.status.last_seen.insert(peer, now);
        }
    }

    /// The status report (PRD-001 R35): read from the published view, the connection
    /// manager, the sync schedules, the app layer and the ledgers in [`StatusBook`],
    /// changing none of them.
    ///
    /// [`StatusBook`]: crate::node::status::StatusBook
    fn status_report(&mut self) -> crate::node::status::StatusReport {
        use crate::node::status::{
            add_stats, ForwardStatus, MemberStatus, PeerStatus, RoomStatus, StatusReport,
        };
        self.note_peers_seen();
        let now = self.now_ms().get();
        let view = self.view_tx.borrow().clone();
        let me = view.identity.as_ref().map(|i| i.fingerprint);
        let trusted: std::collections::BTreeSet<Digest32> =
            view.trusted.iter().map(|(fp, _)| *fp).collect();
        let connected: std::collections::BTreeSet<Digest32> = self
            .net
            .as_ref()
            .map(|n| n.manager().peers().into_iter().collect())
            .unwrap_or_default();
        let mut report = StatusReport {
            now,
            refusals: self.decisions.recent(
                crate::node::decisions::REFUSALS_SHOWN,
                Some(crate::node::decisions::Decided::Refused),
            ),
            keyring_open_secs: keyring_left(
                self.passphrase_entered_at
                    .load(std::sync::atomic::Ordering::Relaxed),
                now,
            ),
            started: self.status.started,
            identity: me,
            networked: self.net.is_some(),
            network_changed: self
                .presence
                .as_ref()
                .and_then(|(p, _)| p.last_change())
                .map(|c| (c.at, c.summary())),
            listening: view.listening.clone(),
            relaying: view.relaying,
            app: self.app.stats(),
            udp_flows: self.udp_flows.snapshot(),
            tunnel_stuck_after: self.stuck_after,
            // The default routes, as the operating system says them now (N-53).
            gateway: {
                // What the presence's last discovery or renewal asked and what answered (N-54).
                let asks = self
                    .presence
                    .as_ref()
                    .map(|(p, _)| p.gateway_asks())
                    .unwrap_or_default();
                crate::node::status::GatewayStatus {
                    ipv4: crate::node::status::GatewayFamily {
                        next_hop: crate::nat::portmap::gateway::default_hop(false),
                        ask: asks.ipv4,
                    },
                    ipv6: crate::node::status::GatewayFamily {
                        next_hop: crate::nat::portmap::gateway::default_hop(true),
                        ask: asks.ipv6,
                    },
                }
            },
            ..StatusReport::default()
        };
        for room in &view.open_channels {
            let members = room
                .members
                .iter()
                .map(|m| MemberStatus {
                    id: *m,
                    me: Some(*m) == me,
                    trusted: trusted.contains(m),
                    connected: connected.contains(m),
                    last_seen: self.status.last_seen.get(m).copied(),
                    last_sync: self.status.member_synced.get(m).copied(),
                })
                .collect();
            // From the room as last published, never its lock: a sync session holds that lock
            // while it runs, and a status read must not wait on it or come back blank (#58).
            report.rooms.push(RoomStatus {
                id: room.channel_id,
                name: crate::node::resolver::room_shown_here(
                    room.name.as_deref(),
                    &room.channel_id,
                    view.channels.iter().map(|c| c.name.as_deref()),
                ),
                epoch: room.epoch,
                last_sync: self.status.room_synced.get(&room.channel_id).copied(),
                retention: room.retention,
                key_generations: room.key_generations,
                received_key_generations: room.received_key_generations,
                frozen: room.frozen.clone(),
                refused_below_checkpoint: room.refused_below_checkpoint,
                entries: view
                    .channels
                    .iter()
                    .find(|c| c.channel_id == room.channel_id)
                    .map_or(0, |c| c.entries),
                members,
            });
        }
        if let Some(net) = self.net.as_ref() {
            let endpoint = net.manager().endpoint();
            for peer in &connected {
                let Some(conn) = net.manager().existing(peer) else {
                    continue;
                };
                let relayed = crate::node::net::path_class(endpoint, &conn)
                    == crate::node::net::PathClass::Relayed;
                // **Every connection to the peer that still carries traffic** (R35): a flow stays
                // on the connection it began on when a better path displaces it, and the
                // displaced one is retired, not closed, until that traffic is done. Counting only
                // the primary said no datagram moved while a flow carried thousands.
                let mut datagrams = conn.datagram_stats();
                for retired in net.manager().retiring_to(peer) {
                    add_stats(&mut datagrams, &retired.datagram_stats());
                }
                add_stats(&mut report.datagrams, &datagrams);
                report.peers.push(PeerStatus {
                    id: *peer,
                    path: if relayed { "relayed" } else { "direct" },
                    relay: if relayed {
                        endpoint.circuit_relay_of(peer)
                    } else {
                        None
                    },
                    rtt_ms: u64::try_from(conn.quinn().rtt().as_millis()).unwrap_or(u64::MAX),
                    datagrams,
                    tls_group: conn.negotiated_group(),
                    overflow: conn.overflow_stats(),
                });
            }
        }
        report.forwards = view
            .forwards
            .iter()
            .map(|f| ForwardStatus {
                channel_id: f.channel_id,
                host: f.host,
                service_tag: f.service_tag.clone(),
                local: f.local,
            })
            .collect();
        let me_net = self.net.as_ref().map(|n| n.local_id());
        report.anchors = self
            .kept_anchors()
            .into_iter()
            .filter(|(id, _)| Some(*id) != me_net)
            .map(|(id, _)| crate::node::status::AnchorStatus {
                id,
                unreached_since: self.anchor_unreached_since.get(&id).copied(),
            })
            .collect();
        report.diagnose();
        report
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
                .filter(|fp| ch.is_member(fp))
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
        // The app layer reads the same live sets, for both halves of its gate.
        self.app.set_reachers(&self.reachers);
    }

    /// Set a room's retention, then apply it here at once and push the policy-update to the
    /// other members, whose own sweeps apply it as it arrives (ADR-023 decision 2).
    /// `vox room retention` (V030-32): the room's creator or an admin sets the **room's**
    /// retention, on every member. Any other member sets **their own node's** retention for the
    /// room, at or below the room's — it changes nothing anywhere else — and is refused above it.
    /// Name a room for every member (ADR-028 R-1): its creator or an admin appends a room-name
    /// statement; anyone else is refused, and told who may.
    async fn rename_room(&mut self, channel_id: &Digest32, name: &str) -> Outcome {
        if crate::governance::name::room_name(name).as_deref() != Ok(name) {
            return Outcome::Failed(Fault::NotARoomName);
        }
        let now_ms = self.now_ms();
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        if let Err(e) = shared.lock().await.set_name(profile, name, now_ms) {
            return Outcome::Failed(fault_of(&e));
        }
        self.note_local_append(channel_id);
        Outcome::Done
    }

    async fn set_retention(&mut self, channel_id: &Digest32, ttl: u64) -> Outcome {
        let now_ms = self.now_ms();
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        let me = match profile.signer() {
            Ok(s) => crate::identity::composite::RootSigner::fingerprint(s),
            Err(e) => return Outcome::Failed(fault_of(&e)),
        };
        let (governs, room) = {
            let ch = shared.lock().await;
            (ch.governs_retention(&me), ch.room_retention())
        };
        if !governs {
            // Longer than the room keeps is refused; `0` is forever, the longest of all.
            if room != 0 && (ttl == 0 || ttl > room) {
                return Outcome::Failed(Fault::AboveRoomRetention);
            }
            // The room's own value is "follow the room": the member's line is cleared, so a later
            // change to the room's retention reaches this node too.
            let own = (ttl != room).then_some(ttl);
            // Written to the node's own file (ADR-026 F-2), seeded from the account's when the
            // node has none, so the other rooms' lines it was reading are kept.
            let written = self
                .paths
                .own_config_path(crate::node::paths::RETENTION_FILE)
                .and_then(|file| {
                    crate::node::retention::RetentionConfig::write_room(&file, channel_id, own)
                });
            if written.is_err() {
                return Outcome::Failed(Fault::RetentionFileUnwritable);
            }
            self.retention_read_at = 0;
            self.refresh_node_retention(now_ms);
            self.sweep_retention().await;
            return Outcome::OwnRetention { own: ttl, room };
        }
        if let Err(e) = shared.lock().await.set_retention(profile, ttl, now_ms) {
            return Outcome::Failed(fault_of(&e));
        }
        self.note_local_append(channel_id);
        self.retention_read_at = 0; // re-read the node's own file too: an explicit act
        self.sweep_retention().await;
        Outcome::Done
    }

    /// Re-read the node's own retention file when it is due (first use, then every
    /// [`RETENTION_REREAD_MS`]). An unreadable file keeps the last policy read rather than
    /// dropping to "no node limit", which would keep more than the operator asked for.
    fn refresh_node_retention(&mut self, now_ms: crate::time::Ms) {
        let now = now_ms.get();
        if self.retention_read_at == 0
            || now.saturating_sub(self.retention_read_at) >= RETENTION_REREAD_MS
        {
            if let Ok(cfg) =
                crate::node::retention::RetentionConfig::load(&self.paths.retention_file())
            {
                if cfg != self.node_retention {
                    self.node_retention = cfg;
                    self.retention_dirty = self.channels.keys().copied().collect();
                }
            }
            self.retention_read_at = now.max(1);
        }
    }

    /// This node's own retention for a room it is **about to open**, to be set on the room
    /// before it is shared with anything that can start a session.
    ///
    /// **Not left to the sweep.** The sweep sets it on the tick, and skips a room whose lock a
    /// session holds; since sessions start the moment a connection comes up (v0.2.8), a freshly
    /// opened room could sync before any tick reached it. An entry that arrived then was judged
    /// against the room's retention alone — a week — rendered, and pruned a second later by
    /// the node's own minute: an expired message shown (measured: `node_retention=0` at render
    /// in the failing run, `=60` in the passing ones).
    fn node_retention_for(&mut self, channel_id: &Digest32) -> u64 {
        let now_ms = self.now_ms();
        self.refresh_node_retention(now_ms);
        self.node_retention.for_room(channel_id)
    }

    /// Prune every open room to its effective retention — the shorter of the room's policy and
    /// this node's own (ADR-023 decision 2). `true` when anything was pruned, so the view is
    /// republished and `vox room read` stops showing it.
    async fn sweep_retention(&mut self) -> bool {
        let now_ms = self.now_ms();
        self.refresh_node_retention(now_ms);
        let Some(store) = self.profile.as_ref().map(Profile::store_handle) else {
            return false;
        };
        let mut pruned = 0usize;
        let mut checkpointed: Vec<Digest32> = Vec::new();
        // A node retention applied here changes what `vox status` reports from the published
        // view, so it is published even when it prunes nothing yet.
        let mut applied = false;
        for (cid, shared) in &self.channels {
            // A room mid-session is skipped, not waited for: the actor must not park behind a
            // sync, and the next tick comes round in a second.
            let Ok(mut ch) = shared.try_lock() else {
                continue;
            };
            if self.retention_dirty.remove(cid) {
                ch.set_node_retention(self.node_retention.for_room(cid));
                applied = true;
            }
            // **A node may keep less than its room, never more** (V030-32). A file value above the
            // room's is ignored — the shorter wins — and the node says so, once.
            if let Some((node, room)) = ch
                .retention_above_room()
                .filter(|&(node, room)| self.retention_warned.insert((*cid, node, room)))
            {
                let _ = self.event_tx.send(NodeEvent::RetentionAboveRoom {
                    channel_id: *cid,
                    node,
                    room,
                });
            }
            let here = ch.sweep_retention(&store, now_ms).unwrap_or(0);
            pruned += here;
            // Asked every tick, not only after a prune: a room opened with an expired backlog
            // (after a restart) or one idle with a backlog under the batch size is checkpointed
            // without waiting for another prune. The check stops at this identity's first entry
            // still holding a body, so it costs almost nothing. Then every checkpoint held sheds
            // the signatures below it (ADR-023 decision 3).
            let _ = here;
            ch.set_checkpoint_idle(self.checkpoint_idle_secs);
            if let Some(profile) = self.profile.as_ref() {
                if ch.checkpoint_if_due(profile, now_ms).unwrap_or(false) {
                    checkpointed.push(*cid);
                }
            }
            let _ = ch.drop_checkpointed_signatures(&store);
        }
        // A checkpoint is a local append: pushed like a post, so the other members can shed
        // their copies' signatures too.
        for cid in &checkpointed {
            self.note_local_append(cid);
        }
        pruned > 0 || !checkpointed.is_empty() || applied
    }

    /// Note that `entries` of a room were shown to this node's person or drained into its agent's
    /// turn (ADR-028 RR-1), and post a read record for them if one is due (RR-2).
    async fn mark_read(&mut self, channel_id: &Digest32, entries: Vec<Digest32>) -> Outcome {
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        // A room that is over takes no record (one after a leave would undo it, V210-164), so
        // the client is told and asks no more: it is not left to retry what can never be posted.
        {
            let ch = shared.lock().await;
            if ch.ended((self.millis_clock)()).is_some() {
                return Outcome::Failed(Fault::RoomEnded);
            }
            if ch.has_left(&ch.me()) {
                return Outcome::Failed(Fault::RoomLeft);
            }
        }
        if !entries.is_empty() {
            self.reads_pending
                .entry(*channel_id)
                .or_insert_with(|| (BTreeSet::new(), 0))
                .0
                .extend(entries);
            self.flush_reads().await;
        }
        Outcome::Done
    }

    /// Post a read record in each room whose pending reads are due: the last record is
    /// [`READ_RECORD_EVERY_MS`] old. A room not synced yet keeps its reads for a later tick; one
    /// that refuses the record (ended, left) drops them.
    async fn flush_reads(&mut self) {
        let now_millis = (self.millis_clock)();
        let due: Vec<Digest32> = self
            .reads_pending
            .iter()
            .filter(|(_, (pending, last))| {
                !pending.is_empty() && now_millis >= last.saturating_add(READ_RECORD_EVERY_MS)
            })
            .map(|(cid, _)| *cid)
            .collect();
        for cid in due {
            let Some(profile) = self.profile.as_ref() else {
                return;
            };
            let Some(shared) = self.channels.get(&cid).map(Arc::clone) else {
                self.reads_pending.remove(&cid);
                continue;
            };
            // A room mid-session is left for the next tick, as the sweep does.
            let Ok(mut ch) = shared.try_lock() else {
                continue;
            };
            let me = profile.fingerprint();
            let Some((pending, last)) = self.reads_pending.get_mut(&cid) else {
                continue;
            };
            let shown: Vec<Digest32> = pending.iter().copied().collect();
            let mut read = ch.unrecorded_reads(&me, &shown);
            read.truncate(crate::node::content::MAX_READ_HASHES);
            if read.is_empty() {
                pending.clear();
                continue;
            }
            match ch.append_read(profile, read.clone(), now_millis) {
                Ok(_) => {
                    for h in &read {
                        pending.remove(h);
                    }
                    *last = now_millis;
                }
                Err(crate::error::Error::RoomNotSynced) => continue,
                Err(_) => {
                    pending.clear();
                    continue;
                }
            }
            drop(ch);
            // Pushed like a post, so the members it trusts learn of it promptly; no event, since
            // a read record wakes nobody and is no row (RR-4).
            self.note_local_append(&cid);
        }
    }

    /// The members this node's keyring trusts with drive (ADR-028 K-14): who its drive keys are
    /// for (ADR-029 SC-2).
    fn drive_holders(&self) -> BTreeSet<Digest32> {
        self.trust
            .trusted()
            .into_iter()
            .filter(|f| self.trust.has_drive(f))
            .collect()
    }

    /// Append one Session entry under this node's drive key (ADR-029 SC-1, SC-2), then release
    /// that key to whoever with drive is owed it, so a member owed it from the entry reads it.
    async fn append_session(
        &mut self,
        channel_id: &Digest32,
        session_id: &str,
        body: &str,
    ) -> Outcome {
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        let holders = self.drive_holders();
        let now_millis = (self.millis_clock)();
        let entry = {
            let mut ch = shared.lock().await;
            // **Never sealed under a key a member that lost drive still holds** (SC-2b): the key
            // changes here, before the entry, whatever the tick has not got to yet.
            match ch.rotate_drive_if_lost(profile.store(), &holders, crate::time::Ms(now_millis)) {
                Ok(_) => ch.append_session(profile, session_id, body, &holders, now_millis),
                Err(e) => Err(e),
            }
        };
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => return Outcome::Failed(fault_of(&e)),
        };
        self.note_local_append(channel_id);
        self.tend_drive_keys_in(channel_id, &holders).await;
        self.say_session_news(channel_id).await;
        Outcome::Appended(entry)
    }

    /// Say [`NodeEvent::SessionEntry`] once for each session of the room `channel_id` with an
    /// entry placed since it was last said (ADR-029 CL-2): its entries are not room messages, so no
    /// other event tells a client of them.
    async fn say_session_news(&self, channel_id: &Digest32) {
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return;
        };
        let news = shared.lock().await.take_session_news();
        for session_id in news {
            let _ = self.event_tx.send(NodeEvent::SessionEntry {
                channel_id: *channel_id,
                session_id,
            });
        }
    }

    /// [`Self::tend_drive_keys_in`] in every open room.
    async fn tend_drive_keys(&mut self) {
        let holders = self.drive_holders();
        let channels: Vec<Digest32> = self.channels.keys().copied().collect();
        for channel_id in channels {
            self.tend_drive_keys_in(&channel_id, &holders).await;
        }
    }

    /// This node's drive key in one room (ADR-029 SC-2a, SC-2b): **changed first** if a member it
    /// was released to is no longer in `holders` (downgraded to read, or untrusted), then released
    /// to each member with drive that is owed it, as a key-package in the room's log, sealed to
    /// that member's prekeys. A member whose prekeys this node has not read yet stays owed, and the
    /// tick tries again.
    async fn tend_drive_keys_in(&mut self, channel_id: &Digest32, holders: &BTreeSet<Digest32>) {
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return;
        };
        let now_ms = self.now_ms();
        let releases = {
            let Some(profile) = self.profile.as_ref() else {
                return;
            };
            let mut ch = shared.lock().await;
            if ch
                .rotate_drive_if_lost(profile.store(), holders, now_ms)
                .is_err()
            {
                return;
            }
            let Ok(owed) = ch.owed_drive(profile.store(), holders) else {
                return;
            };
            let mut releases = Vec::new();
            for member in owed {
                if let Ok((skdm, generation)) = ch.drive_skdm_for(profile, &member) {
                    releases.push((member, skdm, generation));
                }
            }
            releases
        };
        for (member, skdm, generation) in releases {
            if !self.post_key_package(channel_id, member, &skdm).await {
                continue;
            }
            let Some(profile) = self.profile.as_ref() else {
                return;
            };
            let _ = shared
                .lock()
                .await
                .note_drive_delivered(profile.store(), member, generation);
        }
    }

    async fn send_text(&mut self, channel_id: &Digest32, text: &str) -> Outcome {
        let now_ms = self.now_ms();
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
        let rotated = ch.should_rotate_sender(now_ms) && ch.rotate_sender(profile, now_ms).is_ok();
        let detail = {
            let published = self.view_tx.borrow();
            detail_of(
                &ch,
                published
                    .open_channels
                    .iter()
                    .find(|d| d.channel_id == *channel_id),
            )
        };
        self.fresh_details
            .insert(*channel_id, (summary_of(&ch), detail));
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
        // Locked once the lock has settled; until then, locking (V210-94).
        let locked = !self.profile.as_ref().is_some_and(Profile::is_unlocked) && self.locking == 0;
        let channels = self
            .profile
            .as_ref()
            .and_then(|p| p.store().channels().ok())
            .unwrap_or_default()
            .into_iter()
            .map(|channel_id| ChannelSummary {
                channel_id,
                name: None,
                open: false,
                entries: 0,
                over: None,
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
            locking: self.locking > 0,
            mlock_active: true,
            listening,
            anchoring: Vec::new(),
            channels,
            open_channels: Vec::new(),
            forwards: Vec::new(),
            trusted: self.trust_rows(),
            drive: self
                .trust
                .iter()
                .map(|(fp, _)| *fp)
                .filter(|fp| self.trust.has_drive(fp))
                .collect(),
            relayed_peers: Vec::new(),
            connected: 0,
            connected_peers: Vec::new(),
            boards_connected: Vec::new(),
            relaying: 0,
        });
    }

    /// The room this node holds under `name`, as last published (ADR-028 R-3).
    fn room_named(&self, name: &str) -> Option<Digest32> {
        self.view_tx
            .borrow()
            .channels
            .iter()
            .find(|c| c.name.as_deref() == Some(name))
            .map(|c| c.channel_id)
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
        // Locked once the lock has settled; until then, locking (V210-94).
        let locked = !self.profile.as_ref().is_some_and(Profile::is_unlocked) && self.locking == 0;
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
        let anchoring = self
            .net
            .as_ref()
            .map(|n| n.anchored_channels())
            .unwrap_or_default();
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
            open_channels.push(detail_of(
                &ch,
                prev.open_channels.iter().find(|d| d.channel_id == *id),
            ));
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
                            name: None,
                            open: true,
                            entries: 0,
                            over: None,
                        }),
                },
                None => ChannelSummary {
                    channel_id: *id,
                    name: None,
                    open: false,
                    entries: 0,
                    over: None,
                },
            });
        }
        let (relayed_peers, relaying) = self.path_view();
        let connected_peers = self.connected_peers();
        let trusted = self.trust_rows();
        let drive = trusted
            .iter()
            .map(|(fp, _)| *fp)
            .filter(|fp| self.trust.has_drive(fp))
            .collect();
        // What the decision record names members as where the keyring is not at hand.
        self.decisions.set_aliases(&trusted);
        let view = NodeView {
            identity,
            locked,
            locking: self.locking > 0,
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
            trusted,
            drive,
            relayed_peers,
            relaying,
            connected: connected_peers.len(),
            connected_peers,
            boards_connected: self.boards_connected(),
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
            || shown.boards_connected != self.boards_connected()
    }

    /// What is said of a connection to the board `peer`: an anchor is one this node was given
    /// (`--anchor`, the anchors file) or a room names that is not one of its members; any other
    /// board is a room host's own (V210-107).
    fn board_note(&self, peer: &Digest32) -> &'static str {
        if self.board_word(peer) == "anchor" {
            "connected to this anchor"
        } else {
            "connected to this room host's board"
        }
    }

    /// What the board `peer` is called, by [`Self::board_note`]'s rule: `anchor`, or `room host's
    /// board` (V030-51: a room host is never called an anchor, made or lost).
    fn board_word(&self, peer: &Digest32) -> &'static str {
        let anchor = self.anchors.get(peer).is_some()
            || self
                .room_anchors
                .values()
                .any(|set| set.get(peer).is_some());
        if anchor {
            "anchor"
        } else {
            "room host's board"
        }
    }

    /// The boards this node holds an open connection to now, each with [`Self::board_note`].
    fn boards_connected(&self) -> Vec<(Digest32, String)> {
        self.anchors_up
            .iter()
            .filter(|(_, conn)| conn.quinn().close_reason().is_none())
            .map(|(peer, _)| (*peer, self.board_note(peer).to_owned()))
            .collect()
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

    /// Record a decision about `by` (ADR-028 D-1), naming them as this node's keyring does.
    fn decided(
        &self,
        asked: &'static str,
        by: Digest32,
        room: Option<Digest32>,
        decided: crate::node::decisions::Decided,
        why: String,
    ) {
        self.decisions.record(
            (self.millis_clock)(),
            &crate::node::decisions::Decision {
                asked,
                by,
                alias: self.trust.petname(&by).map(str::to_owned),
                decided,
                why,
                room,
            },
        );
    }

    /// Change what `fingerprint`'s keyring entry grants (ADR-028 K-14): saved before it is adopted,
    /// as every keyring change is, and said to the node's Sessions when drive moved.
    async fn set_capability(
        &mut self,
        fingerprint: Digest32,
        capability: crate::node::trust::Capability,
    ) -> Outcome {
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let signer = match profile.signer() {
            Ok(s) => s,
            Err(e) => return Outcome::Failed(fault_of(&e)),
        };
        let had_drive = self.trust.has_drive(&fingerprint);
        let mut next = self.trust.clone();
        if !next.set_capability(&fingerprint, capability) {
            return Outcome::Failed(Fault::NotConsented);
        }
        if let Err(e) = next.save(profile.store(), signer) {
            return Outcome::Failed(fault_of(&e));
        }
        self.trust = next;
        self.note_capability(fingerprint, had_drive);
        self.publish().await;
        Outcome::Done
    }

    /// Raise [`NodeEvent::CapabilityChanged`] when `fingerprint`'s drive is no longer what it was
    /// (`had_drive`) before a keyring change.
    fn note_capability(&self, fingerprint: Digest32, had_drive: bool) {
        let drive = self.trust.has_drive(&fingerprint);
        if drive != had_drive {
            self.drive_changed
                .store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = self
                .event_tx
                .send(NodeEvent::CapabilityChanged { fingerprint, drive });
        }
    }

    /// A trust just asked for: recorded when it added someone who was not trusted before.
    fn decided_trust(&self, was: bool, fingerprint: Digest32, out: &Outcome) {
        if !was && matches!(out, Outcome::Done) {
            self.decided(
                "to trust a member",
                fingerprint,
                None,
                crate::node::decisions::Decided::Trusted,
                "this node's person added them to the keyring".to_owned(),
            );
        }
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
        arrival: r.arrival,
        late: r.late,
        owed: r.owed,
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
    /// The room whose board names the host's endpoints; `None` for a proxy across every
    /// room, which looks the host up on whichever board has it.
    channel_id: Option<Digest32>,
}

impl crate::node::up::HostDialer for NodeDialer {
    async fn connection(
        &self,
        host: &Digest32,
        _channel_id: &Digest32,
    ) -> crate::error::Result<Arc<VoxConnection>> {
        // `reach` returns a live connection when there is one and otherwise runs the whole
        // ADR-012 ladder, so this is both "give me the connection" and "make one". The
        // endpoint hints come from the board, which is also why this must happen per
        // request: a node that has only just joined has not read the board yet.
        let endpoints = match &self.channel_id {
            // A connected board's record when this node's board holds none yet (V210-122,
            // V030-22).
            Some(cid) => self.net.member_endpoints(cid, *host).await,
            None => self.net.board_endpoints_any(host),
        };
        self.net.reach(*host, &endpoints).await
    }
}

/// A node's way of reaching a member, lent to the daemon's proxy ([`NodeHandle::member_dialer`]):
/// the same ladder `vox forward` and the node's own proxy dial through.
pub struct MemberDialer(NodeDialer);

impl crate::node::up::HostDialer for MemberDialer {
    async fn connection(
        &self,
        host: &Digest32,
        channel_id: &Digest32,
    ) -> crate::error::Result<Arc<VoxConnection>> {
        self.0.connection(host, channel_id).await
    }
}

/// How the proxy resolves names from a running node: a fresh snapshot of its rooms and
/// keyring for every lookup, so a room joined or a node renamed a moment ago resolves.
struct NodeNames {
    net_tx: mpsc::Sender<NetEvent>,
}

impl NodeNames {
    async fn resolve(
        &self,
        name: &str,
    ) -> std::result::Result<crate::node::resolver::ServiceRoom, String> {
        let (tx, rx) = oneshot::channel();
        self.net_tx
            .send(NetEvent::Names(tx))
            .await
            .map_err(|_| "the node has stopped".to_owned())?;
        let names = rx.await.map_err(|_| "the node has stopped".to_owned())?;
        names.lookup(name)
    }
}

impl crate::node::up::Names for NodeNames {
    async fn lookup(
        &self,
        name: &str,
    ) -> std::result::Result<crate::node::resolver::ServiceRoom, String> {
        self.resolve(name).await
    }
}

/// **Exchange `conn`'s board for room `cid` with this node's** (ADR-008, ADR-016): read the
/// members it knows and admit them, file its records on this node's board, and offer it the
/// records this node's board holds that it lacks. Returns the authors admitted.
///
/// Run at the start of every outbound sync session, and with each anchor of the room this node is
/// connected to ([`Node::read_anchor_boards`]). An anchor runs no sync session (ADR-023 RL-6.2),
/// but its board is the one place a member that restarted learns where the others are and the
/// bundles it opens pairwise sessions with: its own board starts empty. Without this a restarted
/// member could release no key to a member it had not synced with since (#410:
/// a_taken_first_key_is_not_sent_again's positive control, after the anchor stopped being a sync
/// partner).
async fn exchange_boards(
    net: &NodeNet,
    conn: &crate::transport::quic::VoxConnection,
    shared: &tokio::sync::Mutex<ChannelState>,
    pstore: &crate::node::store::Store,
    cid: Digest32,
    known: u64,
    now: crate::time::Ms,
) -> usize {
    let Ok(set) = net.fetch_channel(conn, &cid, known).await else {
        return 0;
    };
    let admitted_authors = admit_board_records(
        shared,
        pstore,
        &set.bundles,
        ChannelState::MAX_ADMISSIONS_PER_SWEEP,
        now,
        Some(net),
    )
    .await;
    // What the peer's board holds is filed on this node's own, so its board carries the whole
    // membership it knows. Bundles go first: they carry the key an address record is verified
    // with (M15.2a). Mirroring to the anchors follows on the actor when `SyncDone` lands, because
    // that needs channel state.
    for wire in set
        .bundles
        .iter()
        .map(MemberBundleRecord::to_wire)
        .chain(set.members.iter().map(RendezvousRecord::to_wire))
        // The members' withdraws, then the admission notices (#520): a withdraw first, so this
        // node's board refuses a notice of a member that left.
        .chain(
            set.withdraws
                .iter()
                .map(crate::nat::withdraw::BoardWithdraw::to_wire),
        )
        .chain(
            set.notices
                .iter()
                .map(crate::nat::notice::AdmissionNotice::to_wire),
        )
    {
        let _ = net.publish_local(&wire);
    }
    let admitted_authors = admitted_authors
        + admit_board_notices(
            shared,
            pstore,
            net,
            &cid,
            ChannelState::MAX_ADMISSIONS_PER_SWEEP,
            now,
        )
        .await;
    // **And the other way: what this node's board holds that the peer's lacks.** A member who
    // joined through this node is on this node's board and no other, and the peer learned of it
    // only when *it* next read this board, on its own periodic sync: 24–28 s for a third member to
    // see a new one, measured. Offered here, a push that follows a join carries the newcomer to
    // every connected member at once. Best-effort: a refusal (a record the peer's board already
    // holds newer) costs nothing, and the peer's own sync still reads this board.
    let missing = net.board_records_missing_from(&cid, known, &set);
    if !missing.is_empty() {
        if let Ok(mut client) = crate::nat::service::RendezvousClient::open(conn).await {
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
    admitted_authors
}

/// **Admit the newcomers this node's board holds notices of** (#520), to a fixpoint, as
/// [`admit_board_records`] does records: the board's members' withdraws are kept first, so no
/// notice of a member that left is taken, then each notice whose witness's signer is an author
/// here admits its joiner, past the room's cap only as another member decided. The notices of
/// authors already held are kept too, to pass on. `quota` bounds the call. Returns the authors
/// admitted.
async fn admit_board_notices(
    shared: &tokio::sync::Mutex<ChannelState>,
    store: &crate::node::store::Store,
    net: &NodeNet,
    channel_id: &Digest32,
    quota: usize,
    now_ms: crate::time::Ms,
) -> usize {
    let withdraws = net.board_member_withdraws(channel_id);
    let notices = net.board_notices(channel_id);
    if withdraws.is_empty() && notices.is_empty() {
        return 0;
    }
    let mut channel = shared.lock().await;
    for w in &withdraws {
        let _ = channel.keep_withdraw(store, w);
    }
    let mut pending: Vec<crate::nat::notice::AdmissionNotice> = Vec::new();
    for n in notices {
        if channel.is_author(&n.joiner()) {
            let _ = channel.keep_notice(store, &n);
        } else {
            pending.push(n);
        }
    }
    // Witnessed before witnessing: a member admitted early in the batch can be the witness of one
    // later in it.
    pending.sort_by_key(|n| n.witness.timestamp_ms);
    let mut admitted = 0usize;
    while admitted < quota {
        let before = admitted;
        pending.retain(|n| {
            if admitted >= quota {
                return true;
            }
            match channel.admit_from_notice(store, n, now_ms) {
                Ok(true) => {
                    admitted += 1;
                    let (members, cap) =
                        (channel.author_count(), crate::node::channel::max_authors());
                    if members > cap {
                        net.manager().note(
                            n.joiner(),
                            format!(
                                "admitted to room {} past its cap of {cap}, now {members} \
                                 members: another member admitted it",
                                crate::node::network::short_id(channel.channel_id())
                            ),
                        );
                    }
                    false
                }
                Ok(false) => false,
                Err(_) => true,
            }
        });
        if admitted == before {
            break;
        }
    }
    admitted
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
    shared: &tokio::sync::Mutex<ChannelState>,
    store: &crate::node::store::Store,
    records: &[crate::nat::record::MemberBundleRecord],
    quota: usize,
    now_ms: crate::time::Ms,
    net: Option<&NodeNet>,
) -> usize {
    // **Only records for keys not yet admitted are verified, and outside the room's lock**
    // (V210-71). Every record on a board was verified again on every outbound session, under the
    // lock, though a record for an admitted key can change nothing (`admit_author` of a known key
    // is a no-op): a room of N members paid N signature checks per session, and every post and
    // read of that room waited behind them.
    let known: std::collections::BTreeSet<Digest32> = shared
        .lock()
        .await
        .author_fingerprints()
        .into_iter()
        .collect();
    let mut pending: Vec<(
        &crate::nat::record::MemberBundleRecord,
        crate::identity::composite::CompositePublicKey,
    )> = records
        .iter()
        .filter_map(|record| {
            let key = crate::identity::composite::CompositePublicKey::from_bytes(
                &record.prekey_bundle.root_pub,
            )
            .ok()?;
            if known.contains(&key.fingerprint()) {
                return None;
            }
            // The board is availability only. The record must verify under the key it
            // carries, *and* carry the evidence that the key belongs here — a
            // self-signed record proves possession of a key and nothing else, and
            // admitting on who relayed it is the trust-on-first-use ADR-020 decision 3
            // forbids.
            record.verify(&key).is_ok().then_some((record, key))
        })
        .collect();
    if pending.is_empty() {
        return 0;
    }
    let mut channel = shared.lock().await;
    let mut admitted = 0usize;
    while admitted < quota {
        let before = admitted;
        pending.retain(|(record, key)| {
            if admitted >= quota {
                return true;
            }
            match channel.admit_from_board(store, key, &record.admission, now_ms) {
                Ok(true) => {
                    admitted += 1;
                    // **Past the cap only when another member admitted it on its own view**
                    // (V210-128): said, so a room that went past its cap shows how.
                    let (members, cap) =
                        (channel.author_count(), crate::node::channel::max_authors());
                    if members > cap {
                        if let Some(net) = net {
                            net.manager().note(
                                key.fingerprint(),
                                format!(
                                    "admitted to room {} past its cap of {cap}, now {members} \
                                     members: another member admitted it",
                                    crate::node::network::short_id(channel.channel_id())
                                ),
                            );
                        }
                    }
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

/// The event a [`crate::node::tunnel::TunnelNote`] is said as.
fn note_event(note: crate::node::tunnel::TunnelNote) -> NodeEvent {
    match note {
        crate::node::tunnel::TunnelNote::Refused(reason) => NodeEvent::ProxyRefused { reason },
        crate::node::tunnel::TunnelNote::Closed(reason) => NodeEvent::TunnelClosed { reason },
    }
}

/// **For proofs only.** A marker: a message posted through this node whose text contains it
/// makes the node's actor panic as it takes the post, which stands for a bug in one node
/// (ADR-026 L-6). The panic-isolation proof uses it to show the host hears of the panic and every
/// other node keeps running. Nothing a person runs sets it; unset or empty, nothing changes. Not
/// compiled in without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_PANIC_ON_TEXT_ENV: &str = "VOX_TEST_PANIC_ON_TEXT";

#[cfg(feature = "test-knobs")]
fn test_panic_on_text(text: &str) {
    if let Some(marker) = std::env::var(TEST_PANIC_ON_TEXT_ENV)
        .ok()
        .filter(|m| !m.is_empty())
    {
        assert!(
            !text.contains(&marker),
            "{TEST_PANIC_ON_TEXT_ENV}: the posted text holds the marker {marker:?}"
        );
    }
}

/// **Test-only**: set, this node fails every joiner's admission after the exchange, as a node
/// locked or closing mid-join does (V210-128), so a proof can see what the joiner is told. Not
/// compiled in without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_ADMISSION_FAILS_ENV: &str = "VOX_TEST_ADMISSION_FAILS";

/// **Test-only**: a path. While no file is there, every joiner this node answers waits at its
/// admission, with `<path>.reached.<pid>` written to say so, so a proof can hold joins answered by
/// two members until both are about to admit, then let them go at once (V210-128's race). Bounded
/// at a minute. Not compiled in without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_ADMISSION_GATE_ENV: &str = "VOX_TEST_ADMISSION_GATE";

#[cfg(feature = "test-knobs")]
async fn test_admission_gate() {
    let Some(gate) = std::env::var_os(TEST_ADMISSION_GATE_ENV).map(std::path::PathBuf::from) else {
        return;
    };
    if gate.exists() {
        return;
    }
    let mut reached = gate.clone().into_os_string();
    reached.push(format!(".reached.{}", std::process::id()));
    let _ = std::fs::write(&reached, b"");
    let t0 = std::time::Instant::now();
    while !gate.exists() && t0.elapsed() < std::time::Duration::from_secs(60) {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// The posts of `ask.types` this node's view of a room holds, once it holds `ask.entry`; `None`
/// while it does not (V210-168).
///
/// **Not agreed when the clocks are too far apart, either way**: an entry stamped more than
/// [`crate::node::agreestream::STAMP_LEAD_LIMIT_MILLIS`] ahead of `now_millis` does not move this
/// node's next stamp past it, so a claim this node made next could sort first; and an asker whose
/// clock is more than that behind this node's skipped this node's posts when it stamped, so its
/// claim can sort before one this node already holds. Agreeing then could tell two claimants "you
/// hold it"; the answer says the clocks are apart instead.
fn listed(
    view: &crate::node::api::NodeView,
    ask: &crate::node::agreestream::Ask,
    now_millis: u64,
) -> Option<crate::node::agreestream::Answer> {
    use crate::node::agreestream::{Answer, MAX_LISTED, STAMP_LEAD_LIMIT_MILLIS};
    if now_millis.abs_diff(ask.sent_millis) > STAMP_LEAD_LIMIT_MILLIS {
        return Some(Answer::ClocksApart);
    }
    let d = view
        .open_channels
        .iter()
        .find(|d| d.channel_id == ask.channel_id)?;
    let asked = d
        .timeline
        .iter()
        .rev()
        .find(|r| r.entry_hash == ask.entry)?;
    if asked.created_millis > now_millis.saturating_add(STAMP_LEAD_LIMIT_MILLIS) {
        return Some(Answer::ClocksApart);
    }
    let at = d.structured.positions(&ask.types, &[]);
    if at.len() > MAX_LISTED {
        return Some(Answer::TooMany);
    }
    Some(Answer::Holds(
        at.iter()
            .filter_map(|i| d.timeline.get(*i as usize).map(|r| r.entry_hash))
            .collect(),
    ))
}

/// The posts of `types` this node's view of a room holds.
fn own_listed(
    view: &crate::node::api::NodeView,
    channel_id: &Digest32,
    types: &[String],
) -> Vec<Digest32> {
    view.open_channels
        .iter()
        .find(|d| d.channel_id == *channel_id)
        .map(|d| {
            d.structured
                .positions(types, &[])
                .iter()
                .filter_map(|i| d.timeline.get(*i as usize).map(|r| r.entry_hash))
                .collect()
        })
        .unwrap_or_default()
}

/// **One agreement round** (V210-168; see [`crate::node::agreestream`]): reach and ask every
/// member at once, bounded by [`crate::node::agreestream::ASK_PATIENCE`]; pull what members hold
/// that this node does not, bounded by [`crate::node::agreestream::FETCH_PATIENCE`]; and report
/// where each member stands against this node's own posts.
///
/// **Reached is what this node can observe**: a member it holds a connection to, or reaches —
/// directly or through a relay, which only carries the bytes — within
/// [`crate::node::agreestream::REACH_PATIENCE`]. One it cannot is reported unreachable, and the
/// claim is not called agreed.
async fn agree_round(
    net: Option<Arc<NodeNet>>,
    tx: mpsc::Sender<NetEvent>,
    mut view: watch::Receiver<crate::node::api::NodeView>,
    question: crate::node::agreestream::Ask,
    members: Vec<(Digest32, crate::nat::multiaddr::EndpointList)>,
    skipped: Vec<Digest32>,
) -> crate::node::agreestream::Report {
    use crate::node::agreestream::{self as agree, Agreement, Answer, Asking};
    let deadline = tokio::time::Instant::now() + agree::ASK_PATIENCE;
    let mut asking = tokio::task::JoinSet::new();
    for (member, endpoints) in members {
        let question = question.clone();
        let net = net.clone();
        let tx = tx.clone();
        asking.spawn(async move {
            let Some(net) = net else {
                return (member, Asking::Gone);
            };
            let conn = if let Some(conn) = net.manager().existing(&member) {
                conn
            } else {
                let by = std::cmp::min(
                    deadline,
                    tokio::time::Instant::now() + agree::REACH_PATIENCE,
                );
                match tokio::time::timeout_at(by, net.reach(member, &endpoints)).await {
                    Ok(Ok(conn)) => {
                        let _ = tx
                            .send(NetEvent::Dialed {
                                conn: Arc::clone(&conn),
                                endpoints,
                                board: false,
                            })
                            .await;
                        conn
                    }
                    Ok(Err(e)) => {
                        net.manager()
                            .note(member, format!("not reached for a claim's agreement: {e}"));
                        return (member, Asking::Gone);
                    }
                    Err(_) => {
                        net.manager().note(
                            member,
                            "not reached for a claim's agreement within the bound".to_owned(),
                        );
                        return (member, Asking::Gone);
                    }
                }
            };
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            (member, agree::ask(&conn, &question, left).await)
        });
    }
    let mut asked: Vec<(Digest32, Asking)> = Vec::new();
    while let Some(done) = asking.join_next().await {
        if let Ok(a) = done {
            asked.push(a);
        }
    }
    asked.sort_by(|a, b| a.0.cmp(&b.0));

    // **Pull what members hold and this node does not**, so the client can fold their sets: a
    // claim that crossed this one is usually exactly that.
    let lacking = |view: &crate::node::api::NodeView| -> Vec<Digest32> {
        let mine: BTreeSet<Digest32> = own_listed(view, &question.channel_id, &question.types)
            .into_iter()
            .collect();
        asked
            .iter()
            .filter(|(_, a)| {
                matches!(a, Asking::Answered(Answer::Holds(list))
                    if list.iter().any(|h| !mine.contains(h)))
            })
            .map(|(m, _)| *m)
            .collect()
    };
    let peers = lacking(&view.borrow_and_update());
    if !peers.is_empty() {
        let _ = tx
            .send(NetEvent::AgreeFetch {
                channel_id: question.channel_id,
                peers,
            })
            .await;
        let by = tokio::time::Instant::now() + agree::FETCH_PATIENCE;
        while !lacking(&view.borrow_and_update()).is_empty() {
            if !matches!(
                tokio::time::timeout_at(by, view.changed()).await,
                Ok(Ok(()))
            ) {
                break;
            }
        }
    }

    let mine = own_listed(&view.borrow(), &question.channel_id, &question.types);
    let mut members: Vec<(Digest32, Agreement)> = asked
        .into_iter()
        .map(|(m, a)| {
            let stands = match a {
                Asking::Answered(Answer::Holds(list)) => agree::compare(&mine, &list),
                Asking::Answered(Answer::NotReceived) => Agreement::NotReceived,
                Asking::Answered(Answer::NotHeld) => Agreement::NotHeld,
                Asking::Answered(Answer::TooMany) => Agreement::TooDifferent,
                Asking::Answered(Answer::ClocksApart) => Agreement::ClocksApart,
                Asking::Gone => Agreement::Unreachable,
                Asking::Unanswered => Agreement::Unanswered,
            };
            (m, stands)
        })
        .collect();
    // **A post this node held and did not stamp the claim after** (`stamp_after_held`): the claim
    // can sort before it although it was made after, so whatever the members answered, the claim
    // is not agreed. Its author is named, this node itself included, beside its answer.
    members.extend(skipped.into_iter().map(|a| (a, Agreement::StampedAhead)));
    agree::Report {
        mine: mine.len() as u64,
        members,
    }
}

/// The [`Fault`] a person is told for `e`: one mapping, shared by the actor and by a client verb
/// that does the same work itself (`vox id` making an identity, ADR-026 C-5).
#[must_use]
pub fn fault_of(e: &Error) -> Fault {
    match e {
        // A ladder that tried every rung and got nowhere is unreachable, not an internal
        // fault: falling through to `Internal` made the join walk stop after one responder.
        Error::LadderExhausted(_) => Fault::Unreachable,
        Error::LocalBind { cause, .. } => Fault::of_bind(*cause),
        Error::TunnelLimit(_) => Fault::TunnelLimit,
        Error::ServiceNameTaken(..) => Fault::NameTaken,
        Error::RoomNotSynced => Fault::RoomNotSynced,
        Error::Profile("no identity on this node") => Fault::NoIdentity,
        Error::Profile("identity already exists on this node") => Fault::IdentityExists,
        Error::Profile(crate::node::profile::EMPTY_PASSPHRASE) => Fault::PassphraseEmpty,
        Error::Profile("locked") => Fault::Locked,
        Error::Profile("no such room on this node") => Fault::UnknownChannel,
        Error::AtRestUnlockFailed => Fault::WrongPassphrase,
        Error::AtRestLocked => Fault::Locked,
        Error::ProfileBusy => Fault::ProfileBusy,
        // Before the general size arm: a full keyring is not an input that was too long.
        Error::SizeLimitExceeded("trusted identities") => Fault::KeyringFull,
        Error::SizeLimitExceeded(_) => Fault::TooLong,
        Error::MalformedLink(_) | Error::MalformedAnchor(_) => Fault::BadLink,
        Error::Unreachable(_) => Fault::Unreachable,
        Error::JoinRefused(_) | Error::RendezvousRejected(_) => Fault::Refused,
        Error::JoinSolveTooSlow { .. } => Fault::SolveTooSlow,
        Error::JoinResponderBusy | Error::JoinEndedForNewcomer => Fault::MembersBusy,
        Error::RoomFull { .. } => Fault::RoomFull,
        Error::SeatTaken => Fault::SeatTaken,
        Error::SeatNotAgreed { .. } => Fault::SeatNotAgreed,
        Error::JoinNotAdmitted => Fault::NotAdmittedAfterJoin,
        Error::JoinRoomEnded => Fault::JoinedRoomEnded,
        Error::JoinResponderLeft => Fault::ResponderLeft,
        Error::Path {
            op: crate::node::profile::VAULT_WRITE,
            ..
        } => Fault::IdentityFileUnwritable,
        // Retention is the admin's to set; anyone else is refused, and told why. It was mapped to
        // `Refused`, which reads "the other side refused" — for a check this node made itself,
        // about its own identity, with nobody on any other side (found by the R7 gate).
        Error::MalformedGovernance("only the room's admin may set its retention") => {
            Fault::NotAdmin
        }
        Error::MalformedGovernance("only the room's creator or an admin may rename it") => {
            Fault::NotAdmin
        }
        Error::MalformedGovernance("room name is not a DNS label") => Fault::NotARoomName,
        // A room's lifecycle (V030-08): said as what it is, not as an internal fault.
        Error::Profile("this room has ended") => Fault::RoomEnded,
        Error::Profile(
            "only the room's creator or an admin may end it"
            | "only the room's creator may choose its idle end",
        ) => Fault::NotCreator,
        Error::Profile("only the room's creator may add or remove an admin") => {
            Fault::NotRoomCreator
        }
        Error::Profile("that member is not an admin of the room") => Fault::NotAnAdmin,
        Error::Profile(
            "that identity is not a member of the room" | "the room's creator is its admin already",
        ) => Fault::NotAdmitted,
        Error::Storage { .. } | Error::Path { .. } => Fault::Storage,
        // A join refused before the challenge (the responder does not hold that
        // channel open) reaches the joiner as a malformed exchange; report it as the
        // refusal it is rather than an internal fault.
        Error::MalformedJoin(_) => Fault::Refused,
        // A revocation the log has already settled, or one aimed at oneself: the
        // caller's request cannot be honoured, which is not an internal failure.
        Error::MalformedGovernance(
            "no trust to withdraw" | "an identity cannot withdraw trust in itself",
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
