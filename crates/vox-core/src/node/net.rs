//! The connection manager (ADR-016 §"Connections, reachability and sync"): one
//! authenticated QUIC connection per peer, and the authorization gate on what a
//! peer may open over it.
//!
//! ## One connection per peer fingerprint
//! [`ConnectionManager`] keeps at most one live [`VoxConnection`] per peer
//! fingerprint, whichever side dialed. [`ConnectionManager::connect`] reuses a live
//! connection and otherwise dials the peer's advertised endpoints through the
//! ADR-012 ladder ([`connect_direct`], Happy-Eyeballs over the record's
//! candidates); [`ConnectionManager::accept`] takes an inbound connection and files
//! it under the identity the M9 handshake authenticated. Closed connections are
//! reaped by [`ConnectionManager::prune_closed`], so a peer that comes back is
//! redialled rather than served a dead handle.
//!
//! ## Authorization is a stream-kind gate, not a transport gate
//! ADR-016's Decision says inbound connections are accepted with
//! `Admission::Callback` over the union of the channels' memberships "plus the
//! anchors and any pending pre-join identity **for the join stream only**". Taken
//! literally at the transport, that would also reject the peers ADR-012 requires a
//! rendezvous server to serve: reading the board is open to **any authenticated
//! peer that knows the channelID**, and a joiner must be able to publish its
//! pre-join record before anyone knows it. The two ADRs are reconciled by putting
//! the rule where ADR-011 says authorization belongs — *above* the transport:
//!
//! - A node that serves rendezvous accepts any authenticated identity
//!   ([`Admission::AcceptAnyAuthenticated`], ADR-011's open-swarm default); a node
//!   that does not can still be closed with [`Admission::Callback`] over
//!   [`PeerPolicy`].
//! - Every accepted stream is then classified by *who opened it* and refused if the
//!   peer's class may not open that kind ([`PeerPolicy::allows`],
//!   [`accept_authorized`]). So "pending pre-join identity, for the join stream
//!   only" is enforced exactly, and an unknown peer reaches the rendezvous service
//!   and nothing else.
//!
//! A refused stream is reset with [`WireError::AuthenticatorInvalid`] — the same
//! coded rejection an unauthenticated peer gets, so a peer cannot distinguish "not
//! a member" from "not authenticated" by probing stream kinds.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use quinn::{RecvStream, SendStream};

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::nat::multiaddr::EndpointList;
use crate::nat::reachability::{connect_direct, direct_candidates};
use crate::time::Clock;
use crate::transport::quic::{close_code, Admission, VoxConnection, VoxEndpoint, KEEP_ALIVE};
use crate::transport::streams::{accept_typed, StreamKind};
use crate::wire::WireError;

/// How a peer is known to this node, which decides what it may open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerClass {
    /// A member of at least one channel this node holds (ADR-007 membership).
    Member,
    /// A configured anchor: it stores and forwards for us and syncs as an ordinary
    /// peer, but it is not a member of our channels.
    Anchor,
    /// An identity this node is currently expecting a join from (its pre-join
    /// record was accepted, or a link names it).
    PendingJoiner,
    /// A member this node is joining a room *through* right now. It sends its sender key the
    /// moment it admits us, before this node holds the room or knows it as a member.
    JoinResponder,
    /// Authenticated, but otherwise unknown to us.
    Unknown,
}

/// Who this node knows, for classifying inbound peers. Rebuilt from the node's
/// channel memberships (and its configured anchors) whenever they change, so the
/// view a stream is judged against is never stale by more than one rebuild.
#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    members: HashSet<Digest32>,
    anchors: HashSet<Digest32>,
    pending_joiners: HashSet<Digest32>,
    join_responders: HashSet<Digest32>,
}

impl PeerPolicy {
    /// An empty policy (every peer is [`PeerClass::Unknown`]).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the members of a channel (the union across channels is what matters).
    pub fn add_members(&mut self, members: impl IntoIterator<Item = Digest32>) {
        self.members.extend(members);
    }

    /// Add a configured anchor.
    pub fn add_anchor(&mut self, anchor: Digest32) {
        self.anchors.insert(anchor);
    }

    /// Expect a join from `joiner` (until [`PeerPolicy::forget_joiner`]).
    pub fn expect_joiner(&mut self, joiner: Digest32) {
        self.pending_joiners.insert(joiner);
    }

    /// Stop expecting a join from `joiner` (it joined, or the attempt lapsed).
    pub fn forget_joiner(&mut self, joiner: &Digest32) -> bool {
        self.pending_joiners.remove(joiner)
    }

    /// Accept a join responder's sender key while this node joins through it (until
    /// [`PeerPolicy::forget_join_responders`]).
    pub fn expect_join_responder(&mut self, responder: Digest32) {
        self.join_responders.insert(responder);
    }

    /// No join is in flight any more: its responders are members now, or were never admitted.
    pub fn forget_join_responders(&mut self) {
        self.join_responders.clear();
    }

    /// The members this node is joining through right now.
    #[must_use]
    pub fn join_responders(&self) -> Vec<Digest32> {
        self.join_responders.iter().copied().collect()
    }

    /// Classify a peer. Membership wins over every other class: a member that is
    /// also an anchor or a pending joiner is a member.
    #[must_use]
    pub fn classify(&self, peer: &Digest32) -> PeerClass {
        if self.members.contains(peer) {
            PeerClass::Member
        } else if self.anchors.contains(peer) {
            PeerClass::Anchor
        } else if self.pending_joiners.contains(peer) {
            PeerClass::PendingJoiner
        } else if self.join_responders.contains(peer) {
            PeerClass::JoinResponder
        } else {
            PeerClass::Unknown
        }
    }

    /// How many members this policy knows.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// How many anchors this policy knows.
    #[must_use]
    pub fn anchor_count(&self) -> usize {
        self.anchors.len()
    }

    /// The identities this policy is currently expecting a join from.
    #[must_use]
    pub fn pending_joiners(&self) -> Vec<Digest32> {
        self.pending_joiners.iter().copied().collect()
    }

    /// Whether a peer of `class` may open a `kind` stream.
    ///
    /// - **Member**: everything. It is in the channel; the log, consent and
    ///   render gates (ADR-007/008) govern what it can actually *read*.
    /// - **Anchor**: `rendezvous` (the board), `sync` (it replicates ciphertext it
    ///   can never read) and `coord` (it relays hole-punch signalling). Never
    ///   `join` or `pairwise`: it has no channel authority.
    /// - **PendingJoiner**: `join`, `rendezvous` and `pairwise`. ADR-016's Decision
    ///   says "for the join stream only", which is one stream too few: the moment a
    ///   join completes, the newcomer must deliver its **own** sender key (ADR-007
    ///   step 2), and it cannot wait to be reclassified — the responder only admits
    ///   it as a member *after* the join's final frame, and the ADR-004 responder
    ///   cannot speak first on the new session anyway. Allowing `pairwise` costs
    ///   nothing: a sealed message from a peer we hold no session with cannot be
    ///   opened and is dropped. Never `sync` (no log authority) and never `tunnel`.
    /// - **Unknown**: `rendezvous` only, gated further by the service's own policy
    ///   (ADR-012: reads open, member-only writes refused there).
    #[must_use]
    pub fn allows(class: PeerClass, kind: StreamKind) -> bool {
        // **Any peer may say it is stopping** (V210-93): it speaks only of the connection it
        // arrives on, which the peer is about to close anyway.
        if kind == StreamKind::Goodbye {
            return true;
        }
        match class {
            PeerClass::Member => true,
            PeerClass::Anchor => matches!(
                kind,
                StreamKind::Rendezvous | StreamKind::Sync | StreamKind::Coord | StreamKind::Circuit
            ),
            PeerClass::PendingJoiner => matches!(
                kind,
                StreamKind::Join
                    | StreamKind::Rendezvous
                    | StreamKind::Pairwise
                    | StreamKind::Coord
                    | StreamKind::Circuit
            ),
            // **Its sender key, and nothing an unknown peer could not already open.** The responder
            // releases its key the moment it admits us, which is before this node holds the room
            // or knows the responder as a member. Judged as `Unknown`, that pairwise stream was
            // refused at accept — `stream refused: peer may not open this stream kind` — while
            // the responder counted the write as delivered and never sent it again. So a trusted
            // member could never read the first room it joined: measured through the real
            // binaries, both members had nothing in the first of two rooms after 90s, 3 runs of 3,
            // while the second room — joined when the responder was already a member — worked.
            PeerClass::JoinResponder => matches!(
                kind,
                StreamKind::Pairwise | StreamKind::Rendezvous | StreamKind::Coord
            ),
            // An unknown peer reaches the board — and the coord stream, where the only
            // verb open to it is `WHOAMI`, whose answer is its own address (enforced in
            // `node::coordstream`). A NATed client cannot learn its reflexive address
            // any other way, and this ADR exists for that client.
            PeerClass::Unknown => matches!(kind, StreamKind::Rendezvous | StreamKind::Coord),
        }
    }

    /// The transport admission for a node that does **not** serve rendezvous: only
    /// identities this policy knows may connect at all. A node that serves
    /// rendezvous must use [`Admission::AcceptAnyAuthenticated`] instead (see the
    /// module docs).
    #[must_use]
    pub fn closed_admission(&self) -> Admission {
        let known: HashSet<Digest32> = self
            .members
            .iter()
            .chain(self.anchors.iter())
            .chain(self.pending_joiners.iter())
            .chain(self.join_responders.iter())
            .copied()
            .collect();
        Admission::Pinned(known)
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How a connection reaches its peer, in preference order (ADR-012: prefer direct).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathClass {
    /// Set up over a relay circuit that this node **no longer has**: the mux detached it (a
    /// second circuit to the same peer replaces the first) or its driver ended. Nothing this
    /// node sends on it leaves the socket, so it is dead whatever it last heard, and it is never
    /// kept over anything — least of all read as direct, which is what asking the mux's table
    /// alone made of it (V29-15).
    Severed,
    /// Through a relay circuit (rung 4): works anywhere, costs a third party.
    Relayed,
    /// Straight to the peer — dialled, or punched (rungs 1–3).
    Direct,
}

/// The path a connection is on.
///
/// **Relayed or direct is the connection's own, fixed fact** ([`VoxConnection::via_circuit`]),
/// recorded when it was made and identical at both ends. Only whether a relayed connection's
/// circuit is *still attached* is asked of the endpoint's mux table — the only authority on
/// which addresses are circuits, since a circuit's address is random and a guess from its shape
/// would be wrong in both directions.
///
/// Asking the table for the whole answer was the defect (V29-15): a circuit detached by a second
/// circuit to the same peer left its connection's address in nobody's table, so a relayed
/// connection that could no longer send read as **direct**, beat the live circuit on "better
/// path", and was kept by both ends.
#[must_use]
pub fn path_class(endpoint: &VoxEndpoint, conn: &VoxConnection) -> PathClass {
    if !conn.via_circuit() {
        PathClass::Direct
    } else if endpoint.is_circuit(conn.quinn().remote_address()) {
        PathClass::Relayed
    } else {
        PathClass::Severed
    }
}

/// An ordering key for one connection that **both ends compute identically**: 16 bytes of
/// the TLS 1.3 exporter (RFC 5705 / RFC 8446 §7.5) under a Vox-specific label. Two
/// duplicate connections on an equal path are resolved by it, so the two ends agree on
/// which one survives regardless of the order either end filed them in.
///
/// If the exporter is unavailable the key is all-ones, which sorts last: a connection that
/// cannot produce one never displaces a held connection that can, and two that both cannot
/// fall back to "the held one wins" — the old behaviour, and no worse than it was.
fn tie_key(conn: &VoxConnection) -> [u8; 16] {
    let mut key = [0u8; 16];
    if conn
        .quinn()
        .export_keying_material(&mut key, b"vox/connection-tie-break/v1", b"")
        .is_err()
    {
        key = [0xff; 16];
    }
    key
}

/// The first four bytes of [`tie_key`], in hex: **the same connection's name at both ends**, so
/// two ends' notes can be read against each other, and the tie-break each end made can be seen.
fn conn_tag(conn: &VoxConnection) -> String {
    tie_key(conn)[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// How long a connection displaced by a better one stays open before it is closed:
/// long enough for anything in flight on it — a join exchange, a sync session (whose
/// frames are bounded at 20 s) — to finish, because the peer's streams do not move.
pub const RETIRE_GRACE_SECS: u64 = 60;

/// How long a connection may receive **nothing at all** before it is treated as dead: one and
/// a half keep-alive intervals, 30s.
///
/// # Why silence, and not the address a newcomer came from
/// A peer that restarts leaves this node holding a connection to a process that no longer
/// exists. Nothing tells us: the old process's close never left the box if it crashed, and a
/// restarted process answers the old connection's packets with a stateless reset this node
/// cannot authenticate. So the held connection looks live until QUIC's idle timeout (60s), and
/// the tie-break keeps it over the new process's connection half the time. An anchor then
/// relays onto a dead connection — "relay cannot reach the peer" — for up to a minute.
///
/// The address the newcomer came from was tried as the signal and withdrawn, because it is
/// wrong in all three directions that matter: NAT rebinding under a **live** process gives the
/// same IP a new port for a live duplicate; a restart on a fixed port gives the **same** IP and
/// port; and a restart onto a different network gives a different IP. An address says where a
/// packet came from, not whether the process behind the old connection is still there. And
/// because only one end of a live duplicate sees the address change, a rule on it makes the two
/// ends keep different connections — each then uses one the other has retired.
///
/// Silence is the evidence that the process is gone. A live peer is heard from at least every
/// `KEEP_ALIVE`: quinn re-arms the keep-alive on every packet it *receives*, so the side that
/// has heard nothing for 20s sends a PING, and a live peer ACKs it within a round trip and its
/// ACK delay (25ms). Both ends run the same timer, so on an idle path each hears from the other
/// at most about 20s apart. 30s leaves 10s for the round trip, a lost PING and its PTO
/// retransmit, and the 1s sampling — and is still half the idle timeout, which is the whole
/// point: a restart is recognised in 30s instead of 60s.
///
/// A dead connection cannot vote, which is why this needs no protocol. The end that restarted
/// holds only the new connection; the end that kept the old one stops hearing from it; so both
/// ends agree on the new one. Two **live** connections both keep hearing keep-alives, so a
/// live duplicate still goes to `tie_key`, which both ends compute identically.
///
/// **Only what authenticates is heard** (V210-140, #359): see [`heard_count`]. The count was of
/// datagrams routed to the connection, before authentication, so an on-path attacker that knew a
/// connection ID could keep a dead connection looking alive with garbage, until the idle timeout.
pub const SILENCE_IS_DEATH: Duration = Duration::from_secs(KEEP_ALIVE.as_secs() * 3 / 2);

/// How much `quic` has received **that authenticated**: the frames of every packet that decrypted
/// on it and was not a replay (V210-140, #359). Every liveness verdict here reads this, never the
/// datagram count, which quinn takes before it decrypts anything: a datagram that carries a known
/// connection ID and garbage counted there, so anyone on the path could keep a dead connection
/// looking alive. A live peer's every packet carries at least an ACK or a PING.
fn heard_count(quic: &quinn::Connection) -> u64 {
    let f = quic.stats().frame_rx;
    [
        f.acks,
        f.ack_frequency,
        f.crypto,
        f.connection_close,
        f.data_blocked,
        f.datagram,
        u64::from(f.handshake_done),
        f.immediate_ack,
        f.max_data,
        f.max_stream_data,
        f.max_streams_bidi,
        f.max_streams_uni,
        f.new_connection_id,
        f.new_token,
        f.path_challenge,
        f.path_response,
        f.ping,
        f.reset_stream,
        f.retire_connection_id,
        f.stream_data_blocked,
        f.streams_blocked_bidi,
        f.streams_blocked_uni,
        f.stop_sending,
        f.stream,
    ]
    .iter()
    .fold(0u64, |sum, n| sum.wrapping_add(*n))
}

/// The one byte a liveness probe carries. Too short to be a framed datagram (which starts with an
/// 8-byte sequence number), so the far end drops it unread; what matters is that the frame is
/// ack-eliciting.
const PROBE_BYTE: u8 = 0;

/// The least time between two probes [`ConnectionManager::close_if_unanswering`] counts.
const PROBE_SPACING: Duration = Duration::from_millis(900);

/// How often a probe checks whether anything came back.
const PROBE_POLL: Duration = Duration::from_millis(10);

/// How long a probe waits for an answer: three round trips of the held connection's own RTT
/// estimate — one for the probe and its ACK, the rest for an ACK delay and a loss — but never
/// less than 250ms, where a loopback RTT of microseconds would make scheduling noise look like
/// death, and never more than 2s, past which a newcomer is kept waiting for a path that is too
/// slow to be the one worth keeping.
fn probe_patience(rtt: Duration) -> Duration {
    (rtt * 3).clamp(Duration::from_millis(250), Duration::from_secs(2))
}

/// Send one probe on `conn` and wait [`probe_patience`] for anything at all to arrive on it.
///
/// `None` is an answer, or a connection that cannot be probed (no datagram support) or that
/// closed on its own meanwhile — none of which is evidence that a live peer is absent.
/// `Some(before)` is no answer, with the [`heard_count`] the probe started from, so the
/// verdict can be re-checked at the moment it is acted on (see [`ConnectionManager::file_inner`]).
async fn probe_unanswered(conn: &VoxConnection) -> Option<u64> {
    let quic = conn.quinn();
    let before = heard_count(quic);
    if quic
        .send_datagram(bytes::Bytes::from_static(&[PROBE_BYTE]))
        .is_err()
    {
        return None;
    }
    let deadline = tokio::time::Instant::now() + probe_patience(quic.rtt());
    loop {
        if heard_count(quic) != before || !is_live(conn) {
            return None;
        }
        if tokio::time::Instant::now() >= deadline {
            return Some(before);
        }
        tokio::time::sleep(PROBE_POLL).await;
    }
}

/// Connections a probe found unanswered, each with the [`heard_count`] its probe started
/// from. Closed only inside [`ConnectionManager::file_inner`], under the connection lock.
type Unanswered = Vec<(Arc<VoxConnection>, u64)>;

/// One QUIC connection per peer fingerprint (see the module docs).
pub struct ConnectionManager {
    endpoint: Arc<VoxEndpoint>,
    conns: Mutex<HashMap<Digest32, Arc<VoxConnection>>>,
    /// Connections a better path displaced, with the time each may be closed. They
    /// keep serving what is already on them; nothing new is opened on them.
    retiring: Mutex<Vec<(Arc<VoxConnection>, u64)>>,
    /// Per connection (by [`VoxConnection::serial`]): its [`heard_count`] when
    /// last sampled, and when that count last moved. The evidence [`SILENCE_IS_DEATH`] reads.
    /// Not keyed by quinn's stable id, which a new connection can reuse from a freed one and
    /// so inherit its silence.
    heard: Mutex<HashMap<u64, (u64, Instant)>>,
    /// Per connection (by serial) that [`Self::close_if_unanswering`] is probing: how many probes
    /// have gone unanswered, and when the last was counted.
    probing: Mutex<HashMap<u64, (u32, Instant)>>,
    retire_grace_secs: u64,
    clock: Clock,
    /// Where [`NodeEvent::ConnectionNote`](crate::node::api::NodeEvent::ConnectionNote)s go,
    /// once the node that owns this manager says.
    notes: Mutex<Option<tokio::sync::broadcast::Sender<crate::node::api::NodeEvent>>>,
    /// Direct dials under way, per peer (V210-122): a reach that knows no address of its own
    /// holds its circuits back while one of these may yet land (see `NodeNet::reach_ladder`).
    dialling: Arc<Mutex<HashMap<Digest32, usize>>>,
}

/// A direct dial counted in [`ConnectionManager::direct_dial_under_way`] until dropped.
pub struct DirectDial {
    dialling: Arc<Mutex<HashMap<Digest32, usize>>>,
    peer: Digest32,
}

impl Drop for DirectDial {
    fn drop(&mut self) {
        let mut dialling = lock(&self.dialling);
        if let Some(n) = dialling.get_mut(&self.peer) {
            *n -= 1;
            if *n == 0 {
                dialling.remove(&self.peer);
            }
        }
    }
}

impl std::fmt::Debug for ConnectionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionManager")
            .field("local_id", &crate::hash::Hex(&self.endpoint.local_id()))
            .field("connections", &lock(&self.conns).len())
            .finish_non_exhaustive()
    }
}

impl ConnectionManager {
    /// A manager over a bound endpoint.
    #[must_use]
    pub fn new(endpoint: Arc<VoxEndpoint>, clock: Clock) -> Self {
        Self::with_retire_grace(endpoint, clock, RETIRE_GRACE_SECS)
    }

    /// [`ConnectionManager::new`] with an explicit retirement grace (tests shorten it).
    #[must_use]
    pub fn with_retire_grace(endpoint: Arc<VoxEndpoint>, clock: Clock, grace_secs: u64) -> Self {
        Self {
            endpoint,
            conns: Mutex::new(HashMap::new()),
            retiring: Mutex::new(Vec::new()),
            heard: Mutex::new(HashMap::new()),
            probing: Mutex::new(HashMap::new()),
            retire_grace_secs: grace_secs,
            clock,
            notes: Mutex::new(None),
            dialling: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Count a direct dial to `peer` as under way until the returned guard is dropped.
    #[must_use]
    pub fn direct_dial(&self, peer: Digest32) -> DirectDial {
        *lock(&self.dialling).entry(peer).or_insert(0) += 1;
        DirectDial {
            dialling: Arc::clone(&self.dialling),
            peer,
        }
    }

    /// Whether a direct dial to `peer` is under way anywhere in this node (V210-122).
    #[must_use]
    pub fn direct_dial_under_way(&self, peer: &Digest32) -> bool {
        lock(&self.dialling).contains_key(peer)
    }

    /// Whether any direct dial is under way in this node — to an anchor, say, that a reach with
    /// nobody to carry its circuit is waiting for (V210-57).
    #[must_use]
    pub fn any_direct_dial_under_way(&self) -> bool {
        !lock(&self.dialling).is_empty()
    }

    /// Say what happens to this manager's connections on `events`, as
    /// [`NodeEvent::ConnectionNote`](crate::node::api::NodeEvent::ConnectionNote)s.
    pub fn report_to(&self, events: tokio::sync::broadcast::Sender<crate::node::api::NodeEvent>) {
        *lock(&self.notes) = Some(events);
    }

    /// Whether a live connection to `peer` is held, **looking only**: unlike [`Self::existing`]
    /// this neither drops a dead connection nor promotes a retired one, so a diagnostic can ask
    /// without changing what it observes.
    #[must_use]
    pub fn holds(&self, peer: &Digest32) -> bool {
        lock(&self.conns).get(peer).is_some_and(|c| is_live(c))
    }

    /// The live connection held for `peer`, **looking only**, like [`Self::holds`].
    #[must_use]
    pub fn held(&self, peer: &Digest32) -> Option<Arc<VoxConnection>> {
        lock(&self.conns)
            .get(peer)
            .filter(|c| is_live(c))
            .map(Arc::clone)
    }

    /// Keep asking whether the process behind `conn` is still there, and close `conn` once it has
    /// not answered for `loss_after`; how long it was silent, if it was closed.
    ///
    /// **A process that stops without a close — SIGKILL, a crash, a pulled cable — must still be
    /// noticed** (V210-93). Nothing arrives to say so, and the idle timeout (60 s) and even
    /// [`SILENCE_IS_DEATH`] (30 s) are measured against a keep-alive every 20 s. So once `conn`
    /// has heard nothing for `probe_after`, every call sends a probe, which a live peer ACKs
    /// within a round trip; a peer that answers none of the probes sent across `loss_after` is
    /// gone. A connection that cannot carry a probe is never judged by its silence, since a live
    /// peer on it could be quiet for a whole keep-alive.
    pub fn close_if_unanswering(
        &self,
        conn: &VoxConnection,
        probe_after: Duration,
        loss_after: Duration,
        probes_needed: u32,
    ) -> Option<Duration> {
        if !is_live(conn) {
            return None;
        }
        let silent = self.silent_for(conn);
        if silent < probe_after {
            lock(&self.probing).remove(&conn.serial());
            return None;
        }
        if conn
            .quinn()
            .send_datagram(bytes::Bytes::from_static(&[PROBE_BYTE]))
            .is_err()
        {
            return None;
        }
        // **Silence counts only across probes sent while this node was running** (V210-93). A node
        // that was itself stalled — a debug build's proof of work holds its runtime for a minute —
        // read nothing in that time, and its first look afterwards saw a long silence that was its
        // own. So a verdict also needs `probes_needed` probes, at most one a `PROBE_SPACING`, all
        // unanswered: a live peer answers the first one sent after the stall within a round trip,
        // and that resets the count.
        let now = Instant::now();
        let mut probing = lock(&self.probing);
        let (sent, last) = probing
            .entry(conn.serial())
            .or_insert((0, now.checked_sub(PROBE_SPACING).unwrap_or(now)));
        if now.saturating_duration_since(*last) >= PROBE_SPACING {
            *sent += 1;
            *last = now;
        }
        if *sent >= probes_needed && silent >= loss_after {
            probing.remove(&conn.serial());
            drop(probing);
            conn.close(WireError::Unresponsive);
            return Some(silent);
        }
        None
    }

    /// One [`NodeEvent::ConnectionNote`](crate::node::api::NodeEvent::ConnectionNote), if
    /// anyone is listening.
    pub fn note(&self, peer: Digest32, note: String) {
        if let Some(tx) = lock(&self.notes).as_ref() {
            let _ = tx.send(crate::node::api::NodeEvent::ConnectionNote { peer, note });
        }
    }

    /// This node's identity fingerprint.
    #[must_use]
    pub fn local_id(&self) -> Digest32 {
        self.endpoint.local_id()
    }

    /// The shared local endpoint (for the reachability ladder and for binding
    /// advertisements).
    #[must_use]
    pub fn endpoint(&self) -> &Arc<VoxEndpoint> {
        &self.endpoint
    }

    /// The connection this node holds for each peer, as `vox status --json` reports it: the
    /// peer, the connection's tag (the first bytes of its TLS exporter, the same at both ends, as
    /// the connection notes name it) and its path. Only connections not yet closed.
    #[must_use]
    pub fn held_connections(&self) -> Vec<(Digest32, String, PathClass)> {
        let mut held: Vec<(Digest32, String, PathClass)> = lock(&self.conns)
            .iter()
            .filter(|(_, c)| is_live(c))
            .map(|(peer, c)| (*peer, conn_tag(c), path_class(&self.endpoint, c)))
            .collect();
        held.sort_by(|a, b| a.0.cmp(&b.0));
        held
    }

    /// The live connection to `peer`, if any.
    ///
    /// **Live means heard from**, not merely unclosed: a connection silent past
    /// [`SILENCE_IS_DEATH`] is not handed out, because what is behind it is a process that has
    /// gone (see there). If a connection this node retired for the peer *is* still being heard
    /// from, it becomes the peer's connection here — that is how a restarted peer's connection
    /// takes over when it lost the tie-break to the dead one. Otherwise the answer is `None`,
    /// so a caller dials afresh rather than opening streams into nothing for half a minute.
    #[must_use]
    pub fn existing(&self, peer: &Digest32) -> Option<Arc<VoxConnection>> {
        let conn = lock(&self.conns).get(peer).cloned()?;
        if !is_live(&conn) {
            // Only if it is still the one held: the lock was let go since it was read, and a
            // fresh connection filed for the peer in between is live and must stay (V210-80).
            let mut map = lock(&self.conns);
            if map.get(peer).is_some_and(|held| Arc::ptr_eq(held, &conn)) {
                map.remove(peer);
            }
            drop(map);
            return self.promote_heard(peer);
        }
        if self.is_dead(&conn) {
            return self.promote_heard(peer);
        }
        Some(conn)
    }

    /// How long `conn` has received nothing, sampling its [`heard_count`] now. A connection
    /// never sampled before counts as heard this instant: the first sample is the baseline.
    fn silent_for(&self, conn: &VoxConnection) -> Duration {
        let received = heard_count(conn.quinn());
        let now = Instant::now();
        let mut heard = lock(&self.heard);
        let entry = heard.entry(conn.serial()).or_insert((received, now));
        if entry.0 != received {
            *entry = (received, now);
        }
        now.saturating_duration_since(entry.1)
    }

    /// Whether `conn` has been silent past [`SILENCE_IS_DEATH`].
    fn is_silent(&self, conn: &VoxConnection) -> bool {
        self.silent_for(conn) > SILENCE_IS_DEATH
    }

    /// Whether `conn` can no longer be used, though it may not be closed: silent past
    /// [`SILENCE_IS_DEATH`], or relayed over a circuit this node no longer has
    /// ([`PathClass::Severed`]), which can send nothing however recently it heard something.
    fn is_dead(&self, conn: &VoxConnection) -> bool {
        path_class(&self.endpoint, conn) == PathClass::Severed || self.is_silent(conn)
    }

    /// Replace `peer`'s silent (or closed) primary with a retired connection to the same peer
    /// that is still being heard from, if there is one. The dead primary is closed: if anything
    /// is still behind it the close tells it which connection this end chose, and if nothing is
    /// there it costs a packet. Among several candidates the best [`PathClass`] wins and then the
    /// lowest [`tie_key`], the order filing uses and so the one the far end kept.
    ///
    /// **Path class first (V210-110, #306).** By tie key alone, a node whose primary to a peer
    /// had died promoted the relayed connection a join started on over the direct one both ends
    /// had settled on, because its key happened to be lower. Its sessions to that peer then ran
    /// through the anchor while the peer used the direct path: measured with three real daemons,
    /// bob promoted relayed `34eff6fe` over direct `3d6af8fa`, which carol held, and when the
    /// anchor stopped, bob's session to carol waited out its 5 s setup, and carol read none of
    /// what bob held until the anchor came back. An anchor only bridges hosts that cannot
    /// otherwise reach each other (ADR-012).
    ///
    /// This is the half of the rule the filing cannot do alone. A restarted peer's connection
    /// arrives while the old one has been silent only a few seconds, so it goes to the
    /// tie-break, and loses it half the time: it is retired and served, and the far end — which
    /// holds nothing else — uses it. Once the old one passes [`SILENCE_IS_DEATH`] the two ends
    /// must converge on the survivor, and this is where they do.
    fn promote_heard(&self, peer: &Digest32) -> Option<Arc<VoxConnection>> {
        let mut map = lock(&self.conns);
        if let Some(held) = map.get(peer) {
            if is_live(held) && !self.is_dead(held) {
                return Some(Arc::clone(held)); // somebody else promoted it first
            }
        }
        let mut retiring = lock(&self.retiring);
        let best = retiring
            .iter()
            .enumerate()
            .filter(|(_, (c, _))| c.peer_id() == *peer && is_live(c) && !self.is_dead(c))
            .min_by_key(|(_, (c, _))| {
                (std::cmp::Reverse(path_class(&self.endpoint, c)), tie_key(c))
            })
            .map(|(i, _)| i)?;
        let (conn, _) = retiring.swap_remove(best);
        drop(retiring);
        if let Some(dead) = map.insert(*peer, Arc::clone(&conn)) {
            dead.close(WireError::Unresponsive);
        }
        Some(conn)
    }

    /// Whether `conn` is the connection currently filed for its peer. A reader serving a
    /// retired connection asks this before it gives up at the grace: a retired connection can be
    /// promoted (see [`Self::existing`]), and then it is the peer's connection and must be read
    /// for as long as it lives.
    #[must_use]
    pub fn is_primary(&self, conn: &Arc<VoxConnection>) -> bool {
        lock(&self.conns)
            .get(&conn.peer_id())
            .is_some_and(|c| Arc::ptr_eq(c, conn))
    }

    /// Sample every connection's liveness, let a heard connection take over from a silent one,
    /// and close a silent one nothing can replace. A task of its own calls this every second —
    /// not the actor's tick, which a dead connection can stall. Sampling on a clock is what keeps
    /// the silence measurement honest: a connection sampled only when somebody asks for it would
    /// look freshly heard after any gap, and its death would be noticed one [`SILENCE_IS_DEATH`]
    /// late. Returns how many peers changed connection.
    pub fn tend_liveness(&self) -> usize {
        let peers: Vec<(Digest32, Arc<VoxConnection>)> = lock(&self.conns)
            .iter()
            .map(|(p, c)| (*p, Arc::clone(c)))
            .collect();
        let retired: Vec<Arc<VoxConnection>> = lock(&self.retiring)
            .iter()
            .map(|(c, _)| Arc::clone(c))
            .collect();
        let mut changed = 0;
        for (peer, conn) in &peers {
            if is_live(conn) && !self.is_dead(conn) {
                continue;
            }
            match self.promote_heard(peer) {
                Some(now) => {
                    if !Arc::ptr_eq(&now, conn) {
                        changed += 1;
                    }
                }
                // Nothing live to take over: close the dead one anyway. Hiding it from
                // `existing` is not enough, because whatever is **already** waiting on it — a
                // tunnel's stream open, a request sent into it — waits for the 60s idle
                // timeout otherwise, and an application that sent a request just before the
                // peer restarted is kept waiting twice as long as the rule says it should be.
                // Closing ends those waits now, with an error their callers already handle
                // by dialling again.
                None => {
                    let mut map = lock(&self.conns);
                    if map.get(peer).is_some_and(|held| Arc::ptr_eq(held, conn)) {
                        map.remove(peer);
                        drop(map);
                        conn.close(WireError::Unresponsive);
                        changed += 1;
                    }
                }
            }
        }
        // A retired connection that has gone silent is as dead as a primary one, and anything
        // still carried on it is waiting on nothing.
        for c in &retired {
            if is_live(c) && self.is_dead(c) {
                c.close(WireError::Unresponsive);
            }
        }
        // Forget connections that are gone, so the table is bounded by what is held.
        let present: HashSet<u64> = peers
            .iter()
            .map(|(_, c)| c.serial())
            .chain(retired.iter().map(|c| c.serial()))
            .collect();
        lock(&self.heard).retain(|id, _| present.contains(id));
        lock(&self.probing).retain(|id, _| present.contains(id));
        changed
    }

    /// The live connection to `peer`, dialling its advertised `endpoints` if there
    /// is none. Concurrent callers for the same peer may race one extra dial; the
    /// loser's connection is closed so the invariant (one per peer) holds.
    pub async fn connect(
        &self,
        peer: Digest32,
        endpoints: &EndpointList,
    ) -> Result<Arc<VoxConnection>> {
        if let Some(conn) = self.existing(&peer) {
            return Ok(conn);
        }
        self.connect_to(peer, &direct_candidates(endpoints)).await
    }

    /// [`Self::connect`] at a list of direct addresses rather than one peer's advertised
    /// [`EndpointList`], which is bounded at eight: an anchor several rooms name is dialled at
    /// the union of their addresses (V210-75).
    pub async fn connect_to(
        &self,
        peer: Digest32,
        candidates: &[std::net::SocketAddr],
    ) -> Result<Arc<VoxConnection>> {
        if let Some(conn) = self.existing(&peer) {
            return Ok(conn);
        }
        // Counted until the connection is filed, so a reach waiting on it never sees neither.
        let dial = self.direct_dial(peer);
        let conn =
            connect_direct(Arc::clone(&self.endpoint), candidates, peer, (self.clock)()).await?;
        let filed = self.file(conn).await;
        drop(dial);
        Ok(filed)
    }

    /// Whether `peer` answers at `candidates` (V210-167): `Ok` only if a connection authenticated
    /// as `peer` is held on one of them, or one dialled there now completes. Unlike
    /// [`Self::connect_to`], a connection held elsewhere — another port, a relay — does not count:
    /// the question is whether these addresses are where the peer is.
    ///
    /// # Errors
    /// Why no candidate answered as `peer`.
    pub async fn answers_at(
        &self,
        peer: Digest32,
        candidates: &[std::net::SocketAddr],
    ) -> Result<Arc<VoxConnection>> {
        let same = |a: &std::net::SocketAddr, b: &std::net::SocketAddr| {
            a.port() == b.port() && a.ip().to_canonical() == b.ip().to_canonical()
        };
        if let Some(conn) = self.existing(&peer) {
            let at = conn.quinn().remote_address();
            if candidates.iter().any(|c| same(c, &at)) {
                return Ok(conn);
            }
        }
        let conn =
            connect_direct(Arc::clone(&self.endpoint), candidates, peer, (self.clock)()).await?;
        Ok(self.file(conn).await)
    }

    /// Accept the next inbound connection under `admission` and file it under the
    /// authenticated peer identity. `Ok(None)` when the endpoint is closed.
    ///
    /// **Performs the handshake inline**, so this is for a caller that wants exactly one
    /// connection. An accept *loop* must use [`Self::accept_incoming`] and
    /// [`Self::finish_incoming`] instead, or it serialises on handshakes and one stalled
    /// unauthenticated peer blocks every other inbound connection.
    pub async fn accept(&self, admission: Admission) -> Result<Option<Arc<VoxConnection>>> {
        let Some(conn) = self
            .endpoint
            .accept_with_admission((self.clock)(), admission)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(self.file(conn).await))
    }

    /// Phase one for an accept loop: the next inbound attempt, with no handshake.
    /// `None` when the endpoint is closed.
    pub async fn accept_incoming(&self) -> Option<quinn::Incoming> {
        self.endpoint.accept_incoming().await
    }

    /// Phase two: complete one attempt's handshake and admission, then file it. Spawn this.
    pub async fn finish_incoming(
        &self,
        incoming: quinn::Incoming,
        admission: Admission,
    ) -> Result<Filed> {
        let conn = self
            .endpoint
            .finish_incoming(incoming, (self.clock)(), admission)
            .await?;
        Ok(self.file_reporting(conn).await)
    }

    /// Take ownership of a connection this manager did not dial — one a hole punch
    /// produced (ADR-012 rung 3) — under the same one-per-peer rule.
    pub async fn adopt(&self, conn: VoxConnection) -> Arc<VoxConnection> {
        self.file(conn).await
    }

    /// File a connection under its peer id. One connection per peer is a
    /// **preference**, not a first-come rule (M15.1b, relay-first / upgrade-later):
    ///
    /// - a newcomer on a *better* path than the one held — direct where the held one
    ///   is relayed — **replaces** it, and the old one is retired: kept open for
    ///   [`RETIRE_GRACE_SECS`], and beyond it for as long as anything is still carried on
    ///   it, so a tunnel that took the old path is not cut when a better one appears;
    /// - on an **equal** path, the one with the lower [`tie_key`] is kept and the other is
    ///   the loser (a simultaneous dial from both sides, or two dials from one side, lands
    ///   here);
    /// - except that a held connection **silent past [`SILENCE_IS_DEATH`]** is no rival at
    ///   all: its process is gone, so the newcomer is filed and the dead one closed. A held
    ///   connection that is still being heard from is live, whatever address the newcomer came
    ///   from, and goes to the rules above. A restarted peer whose connection arrives *before*
    ///   the old one has been silent that long can still lose the tie-break; it is retired and
    ///   served, and [`Self::existing`] / [`Self::tend_liveness`] promote it once the old one
    ///   crosses the line.
    ///
    /// Both ends apply the same rule, which is what lets an upgrade land without a
    /// protocol: the side that punched files the direct connection as an improvement,
    /// and the side that accepted it does too.
    ///
    /// **The equal-path case must not depend on arrival order**, and it used to: "the held
    /// one wins". That agreed across the two ends only while the accept loop handled one
    /// handshake at a time, so both ends filed a pair in the same order. With handshakes
    /// concurrent (v0.2.8) the acceptor could file a node's second dial first. Measured
    /// with both ends logging the same connection's exporter tag: the dialer kept `6352…`
    /// and closed `97c8…` while the anchor kept `97c8…` — a dead connection it went on
    /// using, with the dialer seeing a live one and never redialling. Relaying to that
    /// node then failed ("relay cannot reach the peer") until the grace ran out. This is
    /// the "cross-connection interaction in circuit establishment" ADR-017 recorded as
    /// unidentified: the serial loop was hiding an order-dependent tie-break.
    async fn file(&self, conn: VoxConnection) -> Arc<VoxConnection> {
        // **Closes the loser, because this caller will not serve it.** Retiring a duplicate is only
        // safe where somebody keeps reading it; retiring it here and dropping the handle would
        // leave it transport-alive and application-deaf, which is strictly worse than the close it
        // replaced. `connect`, the one-shot `accept` and `adopt` all arrive through here and none of
        // them serves a second connection, so for them the old behaviour is the correct one.
        let unanswered = self.probe_held(&conn).await;
        let filed = self.file_inner(conn, false, unanswered);
        debug_assert!(filed.also_serve.is_none());
        filed.kept
    }

    /// [`Self::file`], also handing back a duplicate it **retired rather than closed**.
    ///
    /// The tie-break is unchanged: the held connection still wins when the newcomer is no
    /// better. What changes is what happens to the loser. Closing it reset whatever the peer
    /// already had in flight on it — the peer dialled that connection and was never told we
    /// preferred another, so it opens streams there and reads back a reset it had every reason
    /// to expect to work. Measured at the product level: a real SOCKS5 client through a real
    /// `vox up` wrote its bytes and then got `ConnectionReset` reading the echo, and the same
    /// close showed up on `vox forward` as `malformed identity bundle: quic stream read len`.
    ///
    /// So the loser is retired on the ordinary grace instead, and returned here so the caller
    /// can keep reading it until that grace is up. `retire_expired` closes it after that.
    /// Retiring without serving it would be worse than the close it replaces: the connection
    /// would be transport-alive and application-deaf, and the peer's request would never be
    /// answered at all.
    async fn file_reporting(&self, conn: VoxConnection) -> Filed {
        let unanswered = self.probe_held(&conn).await;
        self.file_inner(conn, true, unanswered)
    }

    /// **Ask the connections held for a peer whether anyone is there**, before a newcomer for
    /// the same peer is filed against them — and retire each one nobody answers on.
    ///
    /// Silence ([`SILENCE_IS_DEATH`]) tells a dead connection from a live one, but only after
    /// 30s, and a restarted peer's new connection usually arrives within a second or two of the
    /// crash. In that window the tie-break keeps the dead one half the time, and the restarted
    /// peer is unreachable through this node until the silence rule catches up: measured with
    /// `vox`'s two-daemon harness as 23–27s before anything crossed.
    ///
    /// So the question is asked instead of waited for. One datagram goes out on each held
    /// connection — one byte, deliberately unframed, which the far end's
    /// [`VoxConnection::recv_datagram`] discards before any application sees it — and a
    /// datagram frame is ack-eliciting, so a live peer ACKs it within its ACK delay (25ms)
    /// whether or not anything reads datagrams. Anything at all arriving on a held connection
    /// within [`probe_patience`] of its probe is an answer. Nothing is a connection whose far
    /// end is gone, or busy: it is retired (V210-104, see [`Self::file_inner`]), and the newcomer
    /// is then filed against no rival.
    ///
    /// Measured against `a_restarted_host_is_reached_through_its_anchor` (real nodes, a relayed
    /// client, the host crashed and restarted): reachable again within 0.1s of being back, where
    /// without the probe 5 of 12 restarts waited 28.0–28.6s for the silence rule.
    ///
    /// **Both ends still decide alike.** A restarted peer holds nothing to probe, and the dead
    /// side cannot vote, so only this end decides. Two *live* connections — a member whose NAT
    /// rebound dialling again — are both probed, one from each end, and each end's probe is
    /// traffic the other end hears: the member's probe even migrates the old connection onto
    /// its new port at the anchor, where the anchor's own probe could not reach. Both ends see
    /// an answer and both go to [`tie_key`], as before. `a_live_duplicate_is_decided_alike`
    /// is the gate for that.
    ///
    /// A held connection that cannot carry a datagram (the peer disabled them) is assumed live:
    /// that is the old behaviour, and silence still catches it.
    async fn probe_held(&self, newcomer: &VoxConnection) -> Unanswered {
        let peer = newcomer.peer_id();
        // **Every** connection held for the peer, not only the primary. A retired one — the
        // loser of an earlier tie-break, still served for its grace — is as dead as the primary
        // when the peer's process is, and it is exactly what [`Self::promote_heard`] reaches for
        // when a primary closes: measured, an anchor promoted the connection to a process two
        // restarts old, because it had been silent for only 3s of the 30s silence needs, and
        // relayed a client onto it for 28s. Probing them here closes them while the evidence is
        // fresh.
        let mut held: Vec<Arc<VoxConnection>> = Vec::new();
        if let Some(primary) = lock(&self.conns).get(&peer) {
            held.push(Arc::clone(primary));
        }
        held.extend(
            lock(&self.retiring)
                .iter()
                .filter(|(c, _)| c.peer_id() == peer)
                .map(|(c, _)| Arc::clone(c)),
        );
        // A closed or already-dead (silent, or severed) connection is no rival to `file_inner` or
        // to a promotion; nor is one to **another process** of the identity, which the newcomer
        // supersedes outright (see `file_inner`) — so a restarted peer is not made to wait out a
        // probe of its dead predecessor, which it paid on every restart (V210-57: 250 ms, the
        // floor of `probe_patience`).
        held.retain(|c| {
            is_live(c) && !self.is_dead(c) && c.peer_process() == newcomer.peer_process()
        });
        // Probed at once, so a peer with a dead primary and a dead retired connection costs one
        // patience, not two.
        //
        // **Nothing is closed here.** The probes are awaited, and while they are another newcomer
        // for the same peer can be filed and a retired connection promoted; closing on the spot
        // would act on a verdict about a table that has since changed. The verdicts go to
        // `file_inner`, which acts on them under the lock, re-checked (see there).
        let mut probes = tokio::task::JoinSet::new();
        for c in held {
            probes.spawn(async move { probe_unanswered(&c).await.map(|before| (c, before)) });
        }
        let mut unanswered = Vec::new();
        while let Some(done) = probes.join_next().await {
            if let Ok(Some(dead)) = done {
                unanswered.push(dead);
            }
        }
        unanswered
    }

    /// [`Self::file_reporting`]'s body. `serve_loser` says whether the caller will read a duplicate
    /// this keeps alive: with it the loser is retired and handed back, without it the loser is
    /// closed. There is no third option — a retired connection nobody reads is the worst of both.
    ///
    /// `unanswered` is what [`Self::probe_held`] found, and it is acted on **here, under the
    /// lock**, not where it was found: the probes were awaited, and during that await another
    /// newcomer can have been filed or a retired connection promoted. A connection is closed only
    /// if it is still live and has received **nothing since its probe was sent** — so one that
    /// answered late, or that became the peer's connection because it is live, is spared.
    /// Newcomers filed during the await were never probed, so they cannot be closed by it.
    /// `a_live_duplicate_is_decided_alike` covers the case this protects: two live newcomers
    /// for one peer, filed concurrently at both ends, each probing the other's.
    fn file_inner(&self, conn: VoxConnection, serve_loser: bool, unanswered: Unanswered) -> Filed {
        let peer = conn.peer_id();
        let mut map = lock(&self.conns);
        // **Unanswered is retired, not closed** (V210-104). Only a connection to the newcomer's own
        // process is probed (see [`Self::probe_held`]), and that process has just completed a
        // handshake: it is alive. A probe it did not answer in time is a busy process or a path
        // that has gone, and closing on it reset whatever was in flight there. Measured: an anchor
        // dialling a room's hundreds of offline members answered late, its joiners closed the
        // connection their room fetch was riding, and 1–2% of joins into a 200-member room failed
        // `quic stream: closed by the peer`; both ends did it to each other. Retired, the
        // connection leaves the newcomer's way exactly as a close did, and what it carries
        // finishes; [`Self::retire_expired`] closes it once nothing does.
        for (dead, before) in unanswered {
            if is_live(&dead) && heard_count(dead.quinn()) == before {
                let held = map.get(&peer).is_some_and(|c| Arc::ptr_eq(c, &dead));
                if held {
                    map.remove(&peer);
                    let retire_at = (self.clock)().saturating_add(self.retire_grace_secs);
                    lock(&self.retiring).push((Arc::clone(&dead), retire_at));
                    self.note(
                        peer,
                        format!(
                            "the connection held {} did not answer a probe in time when a new one \
                             {} arrived; retired, not closed, so what it carries finishes",
                            conn_tag(&dead),
                            conn_tag(&conn)
                        ),
                    );
                } else {
                    // Said, not silent (V210-93, #287): it is already retiring, and stays so.
                    self.note(
                        dead.peer_id(),
                        format!(
                            "the connection {} did not answer a probe when a new one {} arrived; \
                             it is already retiring, and is left to finish",
                            conn_tag(&dead),
                            conn_tag(&conn)
                        ),
                    );
                }
            }
        }
        // **A newcomer from another process of the identity supersedes every connection to the
        // one before** (V210-57). One profile is held by one process at a time and an identity is
        // one device's, so a connection to a different process of the same identity is to a
        // predecessor: dead, or on its way out. It is closed, not weighed. Weighed, it could win:
        // the tie-break and the probe both ask whether a connection is *live*, and a dead
        // process's connection can look live for a moment — and then a restarted process's anchor
        // kept its predecessor's connection, closed the one the restarted process was using, and
        // left it with no helper (CI run 36418572653: 30065 ms). Both ends agree without a vote:
        // the restarted process holds only the newcomer.
        //
        // **No new power.** `conn` exists only because its leaf certificate was verified as signed
        // by `peer`'s identity key (`identity_cert::verify_peer_certificate`, ADR-011): only the
        // identity's holder can present a new process of it, and that holder can already speak as
        // it. **Two live processes of one identity** (a copied profile, an old binary) would each
        // supersede the other: that is bounded by the dialler's anchor backoff, which counts a
        // connection lost soon after it was made as a failure (`ANCHOR_FLAP_SECS`), not a loop.
        let process = conn.peer_process();
        if let Some(existing) = map.get(&peer).filter(|e| e.peer_process() != process) {
            let existing = Arc::clone(existing);
            map.remove(&peer);
            if is_live(&existing) {
                existing.close(WireError::Unresponsive);
                self.note(
                    peer,
                    "a new connection is from a new process of this identity: the connection to \
                     the one before is closed"
                        .to_owned(),
                );
            }
        }
        lock(&self.retiring).retain(|(c, _)| {
            let superseded = c.peer_id() == peer && c.peer_process() != process;
            if superseded && is_live(c) {
                c.close(WireError::Unresponsive);
            }
            !superseded
        });
        if let Some(existing) = map.get(&peer) {
            // **A held connection that is dead is not a rival.** Silent: the process behind it
            // is gone (see [`SILENCE_IS_DEATH`]). Severed: its circuit is gone, so it can send
            // nothing — and a second circuit to this peer is exactly what severs it, so it is
            // severed at both ends by the time either files the newcomer that replaced it. The
            // newcomer is filed and the dead one closed, whatever the tie-break would have said.
            // Everything else is decided by path class and then by `tie_key`, which both ends
            // compute identically; the class is the connection's own recorded fact (see
            // [`path_class`]), not a reading of a table that changes underneath it.
            if is_live(existing) && self.is_dead(existing) {
                let silent = self.silent_for(existing).as_secs();
                existing.close(WireError::Unresponsive);
                self.note(
                    peer,
                    format!(
                        "a new connection {} replaced the one held {}, which was dead (silent \
                         {silent}s or its circuit gone) and is closed",
                        conn_tag(&conn),
                        conn_tag(existing)
                    ),
                );
            } else if is_live(existing) {
                let existing = Arc::clone(existing);
                let (new_class, held_class) = (
                    path_class(&self.endpoint, &conn),
                    path_class(&self.endpoint, &existing),
                );
                let newcomer_loses = new_class < held_class
                    || (new_class == held_class && tie_key(&conn) >= tie_key(&existing));
                let heard = self.silent_for(&existing).as_secs();
                if newcomer_loses {
                    drop(map);
                    if !serve_loser {
                        conn.close(WireError::Superseded);
                        self.note(
                            peer,
                            format!(
                                "a new connection {} lost the tie-break to the one held {} (last \
                                 heard {heard}s ago, {held_class:?} against {new_class:?}) and was \
                                 closed",
                                conn_tag(&conn),
                                conn_tag(&existing)
                            ),
                        );
                        return Filed {
                            kept: existing,
                            also_serve: None,
                        };
                    }
                    let retire_at = (self.clock)().saturating_add(self.retire_grace_secs);
                    let retired = Arc::new(conn);
                    lock(&self.retiring).push((Arc::clone(&retired), retire_at));
                    self.note(
                        peer,
                        format!(
                            "a new connection {} lost the tie-break to the one held {} (last heard \
                             {heard}s ago, {held_class:?} against {new_class:?}); retired, closed \
                             in {}s unless still carried",
                            conn_tag(&retired),
                            conn_tag(&existing),
                            self.retire_grace_secs
                        ),
                    );
                    return Filed {
                        kept: existing,
                        also_serve: Some(retired),
                    };
                }
                let retire_at = (self.clock)().saturating_add(self.retire_grace_secs);
                lock(&self.retiring).push((Arc::clone(&existing), retire_at));
                self.note(
                    peer,
                    format!(
                        "a new connection {} ({new_class:?}) displaced the one held {} (last \
                         heard {heard}s ago, {held_class:?}); the old one is retired",
                        conn_tag(&conn),
                        conn_tag(&existing)
                    ),
                );
            }
        }
        let conn = Arc::new(conn);
        // The baseline for its silence: it has just completed a handshake, so it was heard now.
        let _ = self.silent_for(&conn);
        map.insert(peer, Arc::clone(&conn));
        Filed {
            kept: conn,
            also_serve: None,
        }
    }

    /// How long a retired connection is kept readable before it is closed.
    #[must_use]
    pub fn retire_grace_secs(&self) -> u64 {
        self.retire_grace_secs
    }

    /// Close every retired connection whose grace has elapsed (or that the peer
    /// already closed). Returns how many were closed. The node's tick calls this.
    pub fn retire_expired(&self) -> usize {
        let now = (self.clock)();
        let mut retiring = lock(&self.retiring);
        let before = retiring.len();
        retiring.retain(|(conn, at)| {
            // **Still carried** means somebody other than this list holds the connection:
            // a tunnel task splicing bytes, a sync in progress. Those hold an `Arc` for as
            // long as they run, so the strong count is the liveness signal, and it needs no
            // bookkeeping that could disagree with reality.
            //
            // The grace alone is not enough to close on. It is sized for a request finishing
            // — but what rides a connection here is a *tunnel*, and an `ssh` session or a
            // file transfer is in flight for hours. Closing on the timer killed live sessions
            // mid-stream whenever a better path displaced the one they were on, which reached
            // the person as `Connection reset by peer` in the middle of their work.
            let still_carried = Arc::strong_count(conn) > 1;
            if (now >= *at && !still_carried) || !is_live(conn) {
                let why = if is_live(conn) {
                    "its grace was over and nothing was carried on it"
                } else {
                    "the peer had closed it"
                };
                conn.close(WireError::Superseded);
                self.note(
                    conn.peer_id(),
                    format!("a retired connection {} was closed: {why}", conn_tag(conn)),
                );
                false
            } else {
                true
            }
        });
        before - retiring.len()
    }

    /// How many displaced connections are still within their grace.
    #[must_use]
    pub fn retiring_count(&self) -> usize {
        lock(&self.retiring).len()
    }

    /// Drop every connection the peer or the network has closed. Returns how many
    /// were reaped.
    pub fn prune_closed(&self) -> usize {
        let mut map = lock(&self.conns);
        let before = map.len();
        map.retain(|_, c| is_live(c));
        before - map.len()
    }

    /// The peers with a live connection, in unspecified order.
    #[must_use]
    pub fn peers(&self) -> Vec<Digest32> {
        let held: Vec<(Digest32, Arc<VoxConnection>)> = lock(&self.conns)
            .iter()
            .map(|(p, c)| (*p, Arc::clone(c)))
            .collect();
        held.into_iter()
            .filter(|(_, c)| is_live(c) && !self.is_dead(c))
            .map(|(p, _)| p)
            .collect()
    }

    /// Close and forget the connection to `peer`, with the coded reason.
    pub fn close_peer(&self, peer: &Digest32, err: WireError) -> bool {
        match lock(&self.conns).remove(peer) {
            Some(conn) => {
                conn.close(err);
                true
            }
            None => false,
        }
    }

    /// Close every connection that runs **over a relay circuit**, and hand back how many.
    ///
    /// Done before the others at shutdown: a relayed connection's CONNECTION_CLOSE travels inside
    /// a circuit on another connection (the one to the relay), so closing that carrier at the same
    /// moment loses the frame, and the far peer learns only from `SILENCE_IS_DEATH`.
    pub fn close_relayed(&self) -> usize {
        let relayed = |c: &VoxConnection| path_class(&self.endpoint, c) == PathClass::Relayed;
        let mut n = 0;
        for (conn, _) in lock(&self.retiring).iter() {
            if relayed(conn) {
                conn.close(WireError::ShuttingDown);
                n += 1;
            }
        }
        for conn in lock(&self.conns).values() {
            if relayed(conn) {
                conn.close(WireError::ShuttingDown);
                n += 1;
            }
        }
        n
    }

    /// **Tell every peer this node is stopping, and wait — at most `patience` for each of two
    /// rounds — until each has received it** (V210-93); how many confirmed it.
    ///
    /// Said before any connection is closed, while each still runs, because the close itself
    /// cannot be relied on to arrive: it is one datagram, never sent again, and quinn does not
    /// send it at all while congestion control or pacing holds back stream data still queued on
    /// the connection (see [`StreamKind::Goodbye`]). An anchor stopped while it was still sending
    /// to a node that had just reached it closed in silence that way, and the node reported its
    /// clean stop as an anchor that answered nothing for 8 s. A [`StreamKind::Goodbye`] stream is
    /// delivered like any data, and "received" is the peer's acknowledgement of it.
    ///
    /// **Relayed connections first, as with the closes** ([`Self::close_relayed`]): a peer that
    /// hears the goodbye closes that connection, and a direct connection to a relay carries this
    /// node's circuits. Told all at once, the relay closed the carrier as soon as it heard, and the
    /// goodbye on every relayed connection behind it was never delivered: measured on `vox
    /// connect`, the relayed connection to the host went unconfirmed for the whole `patience` on
    /// every stop, while the anchor's confirmed in a quarter of a millisecond.
    ///
    /// Bounded, and spent only on a peer that does not answer: a stop is never held up for long
    /// by a peer that is gone.
    pub async fn say_goodbye(&self, patience: Duration) -> usize {
        let live: Vec<Arc<VoxConnection>> = lock(&self.retiring)
            .iter()
            .map(|(c, _)| Arc::clone(c))
            .chain(lock(&self.conns).values().cloned())
            .filter(|c| is_live(c))
            .collect();
        let (relayed, direct): (Vec<_>, Vec<_>) = live
            .into_iter()
            .partition(|c| path_class(&self.endpoint, c) == PathClass::Relayed);
        goodbye_to(relayed, patience).await + goodbye_to(direct, patience).await
    }

    /// Close every connection (node shutdown).
    pub fn close_all(&self) {
        for (conn, _) in lock(&self.retiring).drain(..) {
            conn.close(WireError::ShuttingDown);
        }
        for (_, conn) in lock(&self.conns).drain() {
            conn.close(WireError::ShuttingDown);
        }
    }
}

/// Say goodbye on each of `conns` at once (see [`ConnectionManager::say_goodbye`]), and wait at
/// most `patience` for the peers to confirm it; how many did.
async fn goodbye_to(conns: Vec<Arc<VoxConnection>>, patience: Duration) -> usize {
    if conns.is_empty() {
        return 0;
    }
    let mut saying = tokio::task::JoinSet::new();
    for conn in conns {
        saying.spawn(async move {
            let (mut send, _recv) =
                crate::transport::streams::open_typed(&conn, StreamKind::Goodbye).await?;
            let _ = send.finish();
            // `None`: every byte of it acknowledged. A stream the peer stopped, or one on a
            // connection that closed meanwhile, ends the wait too, uncounted.
            Ok::<bool, Error>(matches!(send.stopped().await, Ok(None)))
        });
    }
    let mut heard = 0;
    let _ = tokio::time::timeout(patience, async {
        while let Some(done) = saying.join_next().await {
            if matches!(done, Ok(Ok(true))) {
                heard += 1;
            }
        }
    })
    .await;
    heard
}

/// Whether a connection is still usable.
fn is_live(conn: &VoxConnection) -> bool {
    conn.quinn().close_reason().is_none()
}

/// What filing one connection decided: which one is the peer's primary, and whether a duplicate was
/// retired rather than closed and so still needs reading.
pub struct Filed {
    /// The connection that is now this peer's primary.
    pub kept: Arc<VoxConnection>,
    /// A duplicate that was retired rather than closed, and still needs reading for its grace.
    pub also_serve: Option<Arc<VoxConnection>>,
}

/// Accept the next stream on `conn` and authorize it against `policy`: the peer's
/// class must be allowed to open that kind, or the stream is reset with the coded
/// rejection and [`Error::StreamRefused`] is returned (see the module docs).
pub async fn accept_authorized(
    conn: &VoxConnection,
    policy: &PeerPolicy,
) -> Result<(StreamKind, SendStream, RecvStream)> {
    let (kind, mut send, mut recv) = accept_typed(conn).await?;
    let class = policy.classify(&conn.peer_id());
    if !PeerPolicy::allows(class, kind) {
        refuse_disallowed(class, kind, &mut send, &mut recv);
        return Err(Error::StreamRefused("peer may not open this stream kind"));
    }
    Ok((kind, send, recv))
}

/// Refuse a stream `class` may not open as `kind`: uninformatively, except that a **pending joiner
/// asking to sync** is told it is not a member here yet ([`WireError::NotYetMember`], #217), and a
/// **join responder asking to sync** that the room is not held here yet
/// ([`WireError::EpochMismatch`]).
///
/// A pending joiner holds the room's invitation, so "not a member yet" tells it nothing it did not
/// know; told `0x05`, a member that had just joined reported an integrity failure for a record
/// still on its way to this board. Anyone else learns nothing from the refusal.
pub fn refuse_disallowed(
    class: PeerClass,
    kind: StreamKind,
    send: &mut SendStream,
    recv: &mut RecvStream,
) {
    match (class, kind) {
        (PeerClass::PendingJoiner, StreamKind::Sync) => {
            refuse_stream_because(send, recv, WireError::NotYetMember);
        }
        // **The member letting this node in, asking to sync before the room is held here**: this
        // node is still sealing the room's key, and that member pushes the moment it has admitted
        // us. Measured: alice reported seven syncs with a joiner as "authenticator invalid", every
        // one refused at the joiner's gate with alice classed `JoinResponder`. She answered the
        // join, so "not held here yet" (`EpochMismatch`, as the actor says it) tells her nothing.
        (PeerClass::JoinResponder, StreamKind::Sync) => {
            refuse_stream_because(send, recv, WireError::EpochMismatch);
        }
        _ => refuse_stream(send, recv),
    }
}

/// Reset both halves of a stream with the coded rejection — the same code an
/// unauthenticated peer gets, so probing stream kinds reveals nothing.
pub fn refuse_stream(send: &mut SendStream, recv: &mut RecvStream) {
    let code = close_code(WireError::AuthenticatorInvalid);
    let _ = send.reset(code);
    let _ = recv.stop(code);
}

/// Reset both halves of a stream with a **specific** coded reason, for a peer that is owed one
/// (#202). Use [`refuse_stream`] for anyone who must learn nothing from the refusal.
pub fn refuse_stream_because(send: &mut SendStream, recv: &mut RecvStream, why: WireError) {
    let code = close_code(why);
    let _ = send.reset(code);
    let _ = recv.stop(code);
}
