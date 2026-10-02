//! ADR-025 — **sync is scheduled like a switch, not a hub**: one port per `(room, peer)`.
//!
//! This module holds the port's state and the pure rules over it; the actor owns the ports and
//! does everything that touches the network.
//!
//! - **D1.** A port holds at most one outbound attempt and up to [`INBOUND_PER_PORT`] inbound
//!   ones, its backoff, and its requests and credit. It *needs a session* iff it is not poisoned,
//!   and the room's generation has passed what was last credited to the peer, or a request was
//!   raised that no clean completion has consumed yet. This replaced seven maps and a flag
//!   (`pushed_to`, `pending_push`, `owed_first`, `push_failures`, `syncing`, `push_now` and the
//!   per-peer schedules), which past defects came from disagreeing.
//! - **D1a.** An attempt carries its task's abort handle and its **fence**. Retiring one removes
//!   it, aborts its task and retires its fence, so a worker already running on a blocking thread
//!   stops at its next room step or transport operation. Its slot is held by the worker itself
//!   and freed when the worker exits, so slots bound running workers. A result for a retired or
//!   unknown token changes nothing but the `stale` counter.
//! - **D4.** Full duplex: an inbound session is admitted beside this side's own outbound one; the
//!   outbound decision ignores inbound attempts.
//! - **D5.** Backoff by kind, with its own wakeup.
//! - **D6.** Outbound slots: [`OUTBOUND_SLOTS`] in all and [`OUTBOUND_PER_PEER`] per peer; ports
//!   waiting for one are served round-robin across peers and FIFO within a peer, and a port that
//!   still needs a session after its turn goes to the tail.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use crate::hash::Digest32;
use crate::node::channel::{ChannelState, SyncFailure};
use crate::node::status::BackoffKind;
use crate::transport::quic::VoxConnection;
use crate::transport::stream_transport::Fence;
use crate::wire::WireError;

/// Inbound sessions a port admits at once (ADR-025 D4). A correct peer holds one outbound per
/// port; the other two cover this side still applying the peer's previous sessions at turnover.
/// Past it an inbound session is refused at once with `SessionBusy`, never held.
pub const INBOUND_PER_PORT: usize = 3;

/// Outbound sessions in flight at once, across every peer (ADR-025 D6). Inbound sessions take
/// none.
pub const OUTBOUND_SLOTS: usize = 16;

/// Outbound sessions in flight at once to one peer (ADR-025 D6), so a few stalled peers cannot
/// hold every slot... up to the stated limit: four stalled peers can still occupy all sixteen
/// until their sessions time out, and round-robin decides admission without pre-empting.
pub const OUTBOUND_PER_PEER: usize = 4;

/// A session attempt's identity within this node's life.
pub type Token = u64;

/// Which end opened the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// This node opened it.
    Out,
    /// The peer opened it.
    In,
}

/// One running session (ADR-025 D1).
pub struct Attempt {
    /// Its token.
    pub token: Token,
    /// Which end opened it.
    pub dir: Dir,
    /// The connection it runs on. Its death retires the attempt; a connection displaced but still
    /// carrying is not a death.
    pub conn: Arc<VoxConnection>,
    /// The port's `req_gen` when the attempt was admitted: a clean completion consumes requests up
    /// to here, never one raised after it started.
    pub req_at_start: u64,
    /// When it started.
    pub started: Instant,
    /// Its task, aborted on retirement (a task not spawned yet has none).
    pub abort: Option<tokio::task::AbortHandle>,
    /// Its fence (ADR-025 D1a).
    pub fence: Arc<Fence>,
    /// Its place among the port's running sessions in `vox status`, removed when it drops.
    pub running: crate::node::status::Running,
}

impl Attempt {
    /// Stop it: the fence first, so a worker already running stops at its next step, then the
    /// task. Consumes the attempt, so this happens once.
    pub fn retire(self) {
        self.fence.retire();
        if let Some(a) = self.abort {
            a.abort();
        }
    }
}

/// A port's backoff (ADR-025 D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// Until when no outbound session starts; `None` once it has expired.
    pub until: Option<Instant>,
    /// Consecutive failures, which set the next wait.
    pub failures: u32,
    /// Its kind.
    pub kind: BackoffKind,
    /// The wakeup armed for it; a wakeup carrying another is stale.
    pub timer: u64,
}

/// How long a port waits after its `failures`th consecutive failure of `kind` (ADR-025 D5).
#[must_use]
pub fn backoff_wait(kind: BackoffKind, failures: u32) -> Duration {
    let doubling = |from_ms: u64, cap_ms: u64| {
        let shift = failures.saturating_sub(1).min(16);
        Duration::from_millis(from_ms.saturating_mul(1 << shift).min(cap_ms))
    };
    match kind {
        BackoffKind::Unreachable | BackoffKind::Busy => doubling(200, 8_000),
        BackoffKind::NoProgress => doubling(1_000, 30_000),
        // An anchor that keeps no log for the room is asked once per interval, as before, not
        // every few seconds.
        BackoffKind::Policy => Duration::from_secs(30),
    }
}

/// The backoff a failed session puts its port in (ADR-025 D5), or `None` for a poisoned room,
/// which is not retried until it is reopened. **Exhaustive over every hard-fail path**, settled
/// in the implementation:
///
/// - the peer unreachable, the stream not opening, the transport failing or timing out, the
///   peer resetting with `TransportFailed`/`Unresponsive` → `Unreachable`;
/// - the peer's `SessionBusy`, and its `NotYetMember` (#217: it has not yet admitted this
///   just-joined member) → `Busy`;
/// - the peer's `EpochMismatch`, or its uninformative refusal (`AuthenticatorInvalid`: not a
///   member, the room not held, or it found our entries unacceptable), and this side's own room
///   having moved to another epoch mid-session → `Policy`;
/// - this side failing a frame or entry the peer sent (authenticator, feed link, unknown
///   tag/algorithm/version, suite floor, a malformed frame or unsupported mode, the drain
///   budget), the peer's other codes, a protocol violation, and a panicked worker →
///   `NoProgress`.
#[must_use]
pub fn backoff_kind(fail: &SyncFailure) -> Option<BackoffKind> {
    use crate::log::sync::SessionError;
    Some(match fail {
        SyncFailure::Poisoned(_) => return None,
        SyncFailure::Unreachable(_) => BackoffKind::Unreachable,
        SyncFailure::Panicked
        | SyncFailure::Session(SessionError::ProtocolViolation | SessionError::DrainBudget(_)) => {
            BackoffKind::NoProgress
        }
        // Every code is named, in both arms, with no catch-all: a code added to `WireError` does not
        // compile until it is given a kind here.
        SyncFailure::Session(SessionError::Peer(code)) => match code {
            WireError::SessionBusy => BackoffKind::Busy,
            // The peer does not know this node as a member yet (#217): it clears within seconds,
            // so it is paced like `Busy`, never by the 30 s `Policy` interval.
            WireError::NotYetMember => BackoffKind::Busy,
            WireError::TransportFailed
            | WireError::Unresponsive
            | WireError::ShuttingDown
            | WireError::Superseded => BackoffKind::Unreachable,
            WireError::EpochMismatch | WireError::AuthenticatorInvalid => BackoffKind::Policy,
            WireError::ProtocolVersionUnsupported
            | WireError::SuiteBelowFloor
            | WireError::UnknownStructTag
            | WireError::UnknownAlgoId
            | WireError::SyncModeUnsupported => BackoffKind::NoProgress,
        },
        SyncFailure::Session(SessionError::Local(code)) => match code {
            WireError::TransportFailed
            | WireError::Unresponsive
            | WireError::ShuttingDown
            | WireError::Superseded => BackoffKind::Unreachable,
            WireError::SessionBusy | WireError::NotYetMember => BackoffKind::Busy,
            WireError::EpochMismatch => BackoffKind::Policy,
            WireError::ProtocolVersionUnsupported
            | WireError::SuiteBelowFloor
            | WireError::UnknownStructTag
            | WireError::UnknownAlgoId
            | WireError::AuthenticatorInvalid
            | WireError::SyncModeUnsupported => BackoffKind::NoProgress,
        },
    })
}

/// Which room instance a port belongs to. Held weakly, so a port never keeps a locked room's
/// state alive, and compared by pointer: a room closed and held again is a new instance, and its
/// ports start over (a reopen after a poison, an unlock, a new epoch).
#[derive(Debug, Clone)]
pub enum RoomRef {
    /// A room this node is a member of: the only kind it syncs (ADR-023 decision 6).
    Channel(Weak<tokio::sync::Mutex<ChannelState>>),
}

impl RoomRef {
    /// Whether this is the instance `current` names.
    #[must_use]
    pub fn is(&self, current: &RoomRef) -> bool {
        match (self, current) {
            (Self::Channel(a), Self::Channel(b)) => a.ptr_eq(b),
        }
    }
}

/// One `(room, peer)`'s sync port (ADR-025 D1).
pub struct Port {
    /// The room instance it belongs to.
    pub room: RoomRef,
    /// The room's generation.
    pub gen: Arc<AtomicU64>,
    /// At most one outbound attempt.
    pub out: Option<Attempt>,
    /// Up to [`INBOUND_PER_PORT`] inbound attempts.
    pub inbound: BTreeMap<Token, Attempt>,
    /// Whether it is waiting for an outbound slot.
    pub queued: bool,
    /// Its backoff, if it has failed since its last progress.
    pub backoff: Option<Backoff>,
    /// The room is poisoned: no session until it is reopened.
    pub poisoned: bool,
    /// Requests raised.
    pub req_gen: u64,
    /// Requests consumed by clean completions.
    pub req_done: u64,
    /// The room generation credited to the peer: monotonic within the room instance.
    pub done_gen: u64,
    /// When a completion last made progress, for concurrent completions (progress wins).
    pub last_progress: Option<Instant>,
    /// When this node's own outbound session last completed cleanly, so the periodic request
    /// passes over a port that was just served (ADR-025 D7, V210-97).
    pub last_clean_out: Option<Instant>,
}

impl Port {
    /// A fresh port for `room`, with a request raised: a new port syncs at once.
    #[must_use]
    pub fn new(room: RoomRef, gen: Arc<AtomicU64>) -> Self {
        Self {
            room,
            gen,
            out: None,
            inbound: BTreeMap::new(),
            queued: false,
            backoff: None,
            poisoned: false,
            req_gen: 1,
            req_done: 0,
            done_gen: 0,
            last_progress: None,
            last_clean_out: None,
        }
    }

    /// Whether the port needs a session (ADR-025 D1).
    #[must_use]
    pub fn needs(&self) -> bool {
        !self.poisoned
            && (self.gen.load(Ordering::Relaxed) > self.done_gen || self.req_gen > self.req_done)
    }

    /// Raise a request (ADR-025 D2).
    pub fn raise(&mut self) {
        self.req_gen = self.req_gen.saturating_add(1);
    }

    /// Whether the periodic request (ADR-025 D7) has anything to add at `now`: not while this
    /// node's own session on the port is running, nor within `fresh` of its last clean completion.
    /// The request is a safety net for a port nothing has served lately. Raised on a port that had
    /// just carried a post, or was carrying one, it made that port open a second session for the
    /// same post, and when it fell due inside a burst every port of the burst was queued and opened
    /// twice (V210-97: `queued 72, opened 80` for 40 posts).
    #[must_use]
    pub fn periodic_due(&self, now: Instant, fresh: Duration) -> bool {
        self.out.is_none()
            && self
                .last_clean_out
                .is_none_or(|t| now.saturating_duration_since(t) >= fresh)
    }

    /// Whether a backoff holds new outbound sessions back at `now`.
    #[must_use]
    pub fn backing_off(&self, now: Instant) -> bool {
        self.backoff
            .and_then(|b| b.until)
            .is_some_and(|until| now < until)
    }

    /// Clear the backoff: a new connection, a new epoch, or a person's `vox room sync`.
    pub fn clear_backoff(&mut self) {
        self.backoff = None;
    }

    /// Whether it holds any attempt.
    #[must_use]
    pub fn busy(&self) -> bool {
        self.out.is_some() || !self.inbound.is_empty()
    }

    /// Take every attempt out, to be retired.
    pub fn take_attempts(&mut self) -> Vec<Attempt> {
        let mut all: Vec<Attempt> = self.out.take().into_iter().collect();
        all.extend(std::mem::take(&mut self.inbound).into_values());
        all
    }

    /// Take the attempt with `token`, if the port still holds it.
    pub fn take(&mut self, token: Token) -> Option<Attempt> {
        if self.out.as_ref().is_some_and(|a| a.token == token) {
            return self.out.take();
        }
        self.inbound.remove(&token)
    }
}

/// The ports waiting for an outbound slot: round-robin across peers, FIFO within a peer
/// (ADR-025 D6).
#[derive(Debug, Default)]
pub struct Queue {
    per_peer: BTreeMap<Digest32, VecDeque<Digest32>>,
    turn: VecDeque<Digest32>,
}

impl Queue {
    /// Put `(room, peer)` at the tail of its peer's queue.
    pub fn push(&mut self, room: Digest32, peer: Digest32) {
        let q = self.per_peer.entry(peer).or_default();
        if q.is_empty() && !self.turn.contains(&peer) {
            self.turn.push_back(peer);
        }
        q.push_back(room);
    }

    /// Remove `(room, peer)` wherever it is.
    pub fn remove(&mut self, room: &Digest32, peer: &Digest32) {
        if let Some(q) = self.per_peer.get_mut(peer) {
            q.retain(|r| r != room);
            if q.is_empty() {
                self.per_peer.remove(peer);
                self.turn.retain(|p| p != peer);
            }
        }
    }

    /// The next port whose peer `may_take`: the first peer in turn order with a slot free, its
    /// oldest port. That peer's turn moves to the back.
    pub fn pop(&mut self, may_take: impl Fn(&Digest32) -> bool) -> Option<(Digest32, Digest32)> {
        let n = self.turn.len();
        for _ in 0..n {
            let peer = self.turn.pop_front()?;
            if !may_take(&peer) {
                self.turn.push_back(peer);
                continue;
            }
            let q = self.per_peer.get_mut(&peer)?;
            let room = q.pop_front()?;
            if q.is_empty() {
                self.per_peer.remove(&peer);
            } else {
                self.turn.push_back(peer);
            }
            return Some((room, peer));
        }
        None
    }

    /// Every queued port.
    #[must_use]
    pub fn all(&self) -> Vec<(Digest32, Digest32)> {
        self.per_peer
            .iter()
            .flat_map(|(p, q)| q.iter().map(move |r| (*r, *p)))
            .collect()
    }

    /// Empty it.
    pub fn clear(&mut self) {
        self.per_peer.clear();
        self.turn.clear();
    }
}

/// The outbound slots in use, overall and per peer (ADR-025 D6). Shared with the workers: each
/// holds a [`Slot`] until it exits.
#[derive(Debug, Default)]
pub struct Slots {
    in_use: usize,
    per_peer: BTreeMap<Digest32, usize>,
}

/// The slot table as the actor and the workers share it.
pub type SharedSlots = Arc<Mutex<Slots>>;

impl Slots {
    /// Whether an outbound session to `peer` may start.
    #[must_use]
    pub fn free_for(slots: &SharedSlots, peer: &Digest32) -> bool {
        let s = slots.lock().unwrap_or_else(PoisonError::into_inner);
        s.in_use < OUTBOUND_SLOTS && s.per_peer.get(peer).copied().unwrap_or(0) < OUTBOUND_PER_PEER
    }

    /// Whether any slot is free.
    #[must_use]
    pub fn any_free(slots: &SharedSlots) -> bool {
        slots.lock().unwrap_or_else(PoisonError::into_inner).in_use < OUTBOUND_SLOTS
    }

    /// Take a slot for `peer`, if one is free; `on_free` runs when it is given back.
    pub fn take(
        slots: &SharedSlots,
        peer: Digest32,
        on_free: Box<dyn FnOnce() + Send>,
    ) -> Option<Slot> {
        let mut s = slots.lock().unwrap_or_else(PoisonError::into_inner);
        let mine = s.per_peer.get(&peer).copied().unwrap_or(0);
        if s.in_use >= OUTBOUND_SLOTS || mine >= OUTBOUND_PER_PEER {
            return None;
        }
        s.in_use += 1;
        s.per_peer.insert(peer, mine + 1);
        Some(Slot {
            slots: Arc::clone(slots),
            peer,
            on_free: Some(on_free),
        })
    }
}

/// One outbound slot, held by the session's task and then its worker, and given back when the
/// last of them lets go of it — so slots bound running workers, not attempts the port still
/// counts (ADR-025 D1a).
pub struct Slot {
    slots: SharedSlots,
    peer: Digest32,
    on_free: Option<Box<dyn FnOnce() + Send>>,
}

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slot").finish_non_exhaustive()
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        {
            let mut s = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
            s.in_use = s.in_use.saturating_sub(1);
            if let Some(n) = s.per_peer.get_mut(&self.peer) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    s.per_peer.remove(&self.peer);
                }
            }
        }
        if let Some(f) = self.on_free.take() {
            f();
        }
    }
}
