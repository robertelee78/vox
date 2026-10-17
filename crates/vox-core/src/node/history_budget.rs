//! Shared daemon admission and transient-buffer ownership for requested history (ADR-036 H-7).
//!
//! A worker owns its slot until its last charged buffer is gone, including buffers handed back
//! to an actor. Acquire outside actor/room locks and charge before allocation. These are working
//! buffer limits, not a claim about total process RSS or the separately bounded disk caches.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::Notify;

use crate::hash::Digest32;

const MIB: usize = 1024 * 1024;
const QUEUED_PER_LANE: usize = 64;
const ARCHIVE_JOBS: usize = 2;
const FOREGROUND_JOBS: usize = 64;
const RETAINED_FLOWS: usize = 16;
pub(crate) const FLOW_STATE_BYTES: usize = 128 * 1024;
const CONTROL_TURNS_BEFORE_LIVE: usize = 3;
const LIVE_GRANTS: usize = 64;
const LIVE_GRANT_LIFETIME: std::time::Duration = std::time::Duration::from_secs(300);
const LIVE_GRANT_IDLE: std::time::Duration = std::time::Duration::from_secs(30);

/// Exact body selected within a bounded newest window. A later tip cannot widen it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LiveRequest {
    pub(crate) room: Digest32,
    pub(crate) peer: Digest32,
    pub(crate) epoch: u64,
    pub(crate) request: [u8; 16],
    pub(crate) head: Digest32,
    pub(crate) seq: u64,
    pub(crate) entry: Digest32,
    pub(crate) length: u64,
}

type LiveKey = (Digest32, Digest32, Digest32, [u8; 16]);

struct LiveGrant {
    request: LiveRequest,
    persisted: u64,
    pending: Option<u64>,
    expires: std::time::Instant,
    idle: std::time::Instant,
}

/// Independent reservations prevent archive work from consuming live/control capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    /// At most two workers across the daemon and one per node; 96 MiB each.
    Archive,
    /// Small essential-control work has its own 8 MiB reservation.
    Control,
    /// A legal large control record uses the 88 MiB foreground reservation with priority.
    /// At most three control quanta precede queued live work, so another room can still talk.
    LargeControl,
    /// Live content shares the foreground reservation, never the archive reservation.
    Live,
}

impl Lane {
    const fn index(self) -> usize {
        match self {
            Self::Archive => 0,
            Self::Control => 1,
            Self::LargeControl => 2,
            Self::Live => 3,
        }
    }

    /// Maximum simultaneous charged buffers held by one admitted worker.
    #[must_use]
    pub const fn buffer_limit(self) -> usize {
        match self {
            Self::Archive => 96 * MIB,
            Self::Control => 8 * MIB,
            Self::LargeControl | Self::Live => 88 * MIB,
        }
    }
}

#[derive(Clone, Copy)]
struct Waiting {
    ticket: u64,
    node: Digest32,
}

#[derive(Default)]
struct State {
    queues: [VecDeque<Waiting>; 4],
    archive_nodes: BTreeSet<Digest32>,
    control: usize,
    foreground: usize,
    foreground_control_turns: usize,
    next_ticket: u64,
    live_grants: BTreeMap<LiveKey, LiveGrant>,
}

impl State {
    fn available(&self, node: Digest32, lane: Lane) -> bool {
        match lane {
            Lane::Archive => {
                self.archive_nodes.len() < ARCHIVE_JOBS && !self.archive_nodes.contains(&node)
            }
            Lane::Control => self.control < FOREGROUND_JOBS,
            Lane::LargeControl => {
                self.foreground < FOREGROUND_JOBS
                    && (self.queues[Lane::Live.index()].is_empty()
                        || self.foreground_control_turns < CONTROL_TURNS_BEFORE_LIVE)
            }
            Lane::Live => {
                self.foreground < FOREGROUND_JOBS
                    && (self.queues[Lane::LargeControl.index()].is_empty()
                        || self.foreground_control_turns >= CONTROL_TURNS_BEFORE_LIVE)
            }
        }
    }
}

/// One instance belongs to the daemon and is shared by every hosted node.
#[derive(Default)]
pub struct Budget {
    state: Mutex<State>,
    changed: Arc<Notify>,
    control_bytes: AtomicUsize,
    retained_flows: AtomicUsize,
    foreground_bytes: AtomicUsize,
}

impl Budget {
    /// Create the one shared set of reservations owned by a daemon.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queue one bounded operation. The caller coalesces repeated requests for the same node;
    /// refusal means busy, never permission to start an unaccounted worker. No actor lock may
    /// be held while awaiting the returned ticket. Dropping it cancels the queued operation.
    pub fn enqueue(self: &Arc<Self>, node: Digest32, lane: Lane) -> Option<Ticket> {
        let mut state = self.state();
        let queue = &state.queues[lane.index()];
        if queue.len() >= QUEUED_PER_LANE || queue.iter().any(|entry| entry.node == node) {
            return None;
        }
        let ticket = state.next_ticket.checked_add(1)?;
        state.next_ticket = ticket;
        state.queues[lane.index()].push_back(Waiting { ticket, node });
        drop(state);
        self.changed.notify_waiters();
        Some(Ticket {
            budget: Arc::clone(self),
            node,
            lane,
            ticket,
            queued: true,
        })
    }

    /// Nonblocking admission for an actor: queued workers retain their place ahead of it.
    pub fn try_start(self: &Arc<Self>, node: Digest32, lane: Lane) -> Option<Job> {
        self.enqueue(node, lane)?.try_admit()
    }
}

/// A bounded fair queue position, cancelled on drop unless it has become a worker.
pub struct Ticket {
    budget: Arc<Budget>,
    node: Digest32,
    lane: Lane,
    ticket: u64,
    queued: bool,
}

impl Ticket {
    /// Register before attempting admission, so a permit released between the check and the
    /// actor's wake task cannot be missed. This future owns only the notification subscription;
    /// the controller retains the queue ticket and can cancel it synchronously.
    pub(crate) fn wake(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        let mut wake = Box::pin(Arc::clone(&self.budget.changed).notified_owned());
        wake.as_mut().enable();
        wake
    }

    pub(crate) fn try_admit(&mut self) -> Option<Job> {
        let mut state = self.budget.state();
        if !self.queued || !state.available(self.node, self.lane) {
            return None;
        }
        let at = match self.lane {
            Lane::Archive => state.queues[self.lane.index()]
                .iter()
                .position(|waiting| !state.archive_nodes.contains(&waiting.node))?,
            _ => 0,
        };
        if state.queues[self.lane.index()].get(at)?.ticket != self.ticket {
            return None;
        }
        state.queues[self.lane.index()].remove(at);
        match self.lane {
            Lane::Archive => {
                state.archive_nodes.insert(self.node);
            }
            Lane::Control => state.control += 1,
            Lane::LargeControl => {
                state.foreground += 1;
                state.foreground_control_turns =
                    (state.foreground_control_turns + 1).min(CONTROL_TURNS_BEFORE_LIVE);
            }
            Lane::Live => {
                state.foreground += 1;
                state.foreground_control_turns = 0;
            }
        }
        self.queued = false;
        drop(state);
        // A second archive slot or another reserved lane may also be available.
        self.budget.changed.notify_waiters();
        Some(Job(Arc::new(Worker {
            budget: Arc::clone(&self.budget),
            node: self.node,
            lane: self.lane,
            bytes: AtomicUsize::new(0),
        })))
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if self.queued {
            self.budget.state().queues[self.lane.index()]
                .retain(|entry| entry.ticket != self.ticket);
            self.budget.changed.notify_waiters();
        }
    }
}

struct Worker {
    budget: Arc<Budget>,
    node: Digest32,
    lane: Lane,
    bytes: AtomicUsize,
}

impl Worker {
    fn shared_bytes(&self) -> Option<&AtomicUsize> {
        match self.lane {
            Lane::Archive => None,
            Lane::Control => Some(&self.budget.control_bytes),
            Lane::LargeControl | Lane::Live => Some(&self.budget.foreground_bytes),
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let mut state = self.budget.state();
        match self.lane {
            Lane::Archive => {
                state.archive_nodes.remove(&self.node);
            }
            Lane::Control => state.control -= 1,
            Lane::LargeControl | Lane::Live => state.foreground -= 1,
        }
        drop(state);
        self.budget.changed.notify_waiters();
    }
}

/// The running worker's ownership. Moving or cloning this handle cannot create extra capacity.
#[derive(Clone)]
pub struct Job(Arc<Worker>);

impl Job {
    /// Persistent flow metadata may occupy at most two MiB and sixteen small-control
    /// worker slots across the whole daemon. Leave the remaining control capacity available
    /// for current requests that free or advance this retained work.
    pub(crate) fn reserve_flow_state(&self) -> Option<FlowStateCharge> {
        if self.0.lane != Lane::Control {
            return None;
        }
        self.0
            .budget
            .retained_flows
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                held.checked_add(1).filter(|next| *next <= RETAINED_FLOWS)
            })
            .ok()?;
        let Some(charge) = self.reserve(FLOW_STATE_BYTES) else {
            self.0.budget.retained_flows.fetch_sub(1, Ordering::AcqRel);
            return None;
        };
        Some(FlowStateCharge {
            budget: self.0.budget.clone(),
            _charge: charge,
        })
    }

    /// Start only within a currently eligible bounded newest window. Later quanta may finish
    /// that exact body at the last durable ACK even after the window ages out. If a volatile
    /// grant expired or the server restarted, a saved offset may resume only if the exact
    /// body still passes the newest-window predicate; no grant authorizes an older archive.
    pub(crate) fn live_entry(
        &self,
        request: LiveRequest,
        offset: u64,
        in_live_window: bool,
    ) -> crate::error::Result<bool> {
        use crate::error::Error;
        if self.0.lane != Lane::Live {
            return Err(Error::MalformedBundle(
                "live request in another reservation",
            ));
        }
        let key = (self.0.node, request.room, request.peer, request.request);
        let now = std::time::Instant::now();
        let mut state = self.0.budget.state();
        state
            .live_grants
            .retain(|_, grant| now < grant.expires && now < grant.idle);
        if let Some(grant) = state.live_grants.get_mut(&key) {
            if grant.request != request
                || (grant.persisted != offset && grant.pending != Some(offset))
            {
                return Err(Error::MalformedBundle(
                    "live continuation changes authorized body",
                ));
            }
            // The receiver may have persisted the outstanding chunk before its ACK was
            // lost with the stream. It may resume only at that sent boundary or replay it.
            if offset > grant.persisted {
                grant.idle = now + LIVE_GRANT_IDLE;
            }
            grant.persisted = offset;
            grant.pending = None;
            return Ok(true);
        }
        if !in_live_window || offset > request.length {
            return Err(Error::MalformedBundle(
                "live request is outside the bounded newest window",
            ));
        }
        if state.live_grants.len() >= LIVE_GRANTS {
            return Ok(false);
        }
        state.live_grants.insert(
            key,
            LiveGrant {
                request,
                persisted: offset,
                pending: None,
                expires: now + LIVE_GRANT_LIFETIME,
                idle: now + LIVE_GRANT_IDLE,
            },
        );
        Ok(true)
    }

    /// Reserve the sole outgoing chunk boundary before I/O, so cancellation after a write
    /// cannot strand a receiver whose durable ACK did not reach this process.
    pub(crate) fn live_sent(
        &self,
        request: LiveRequest,
        offset: u64,
        next: u64,
    ) -> crate::error::Result<()> {
        use crate::error::Error;
        let key = (self.0.node, request.room, request.peer, request.request);
        let now = std::time::Instant::now();
        let mut state = self.0.budget.state();
        let grant = state
            .live_grants
            .get_mut(&key)
            .ok_or(Error::MalformedBundle("live grant expired"))?;
        if grant.request != request
            || now >= grant.expires
            || now >= grant.idle
            || offset != grant.persisted
            || grant.pending.is_some()
            || next <= offset
            || next > request.length
            || next - offset > crate::log::history::MAX_CHUNK_BYTES as u64
        {
            return Err(Error::MalformedBundle(
                "live outgoing chunk changed or expired",
            ));
        }
        grant.pending = Some(next);
        Ok(())
    }

    /// Called only after the response ledger accepted the exact outstanding chunk's ACK.
    pub(crate) fn live_ack(&self, request: LiveRequest, next: u64) -> crate::error::Result<()> {
        use crate::error::Error;
        let key = (self.0.node, request.room, request.peer, request.request);
        let now = std::time::Instant::now();
        let mut state = self.0.budget.state();
        let grant = state
            .live_grants
            .get_mut(&key)
            .ok_or(Error::MalformedBundle("live grant expired"))?;
        if grant.request != request
            || now >= grant.expires
            || now >= grant.idle
            || grant.pending != Some(next)
        {
            return Err(Error::MalformedBundle("live grant ACK changed or expired"));
        }
        grant.persisted = next;
        grant.pending = None;
        grant.idle = now + LIVE_GRANT_IDLE;
        Ok(())
    }

    pub(crate) fn finish_live(&self, request: LiveRequest) {
        let key = (self.0.node, request.room, request.peer, request.request);
        let mut state = self.0.budget.state();
        if state
            .live_grants
            .get(&key)
            .is_some_and(|grant| grant.request == request)
        {
            state.live_grants.remove(&key);
        }
    }

    /// A large control work envelope uses the foreground reservation, preserving the small
    /// control pool for wire metadata. This admits a separately accounted worker; it never
    /// widens a charge on the existing worker. The caller drops it with the last actual buffer.
    pub(crate) fn record_job(&self, envelope: usize) -> Option<Self> {
        if self.0.lane == Lane::Control && envelope >= 4 * MIB {
            self.0.budget.try_start(self.0.node, Lane::LargeControl)
        } else {
            Some(self.clone())
        }
    }

    /// Reserve before allocating a frame, record copy or plaintext/encoded buffer. Hold the
    /// returned charge for that buffer's lifetime, including across worker/actor handoffs.
    /// Exhaustion is an explicit yield/refusal; a valid large record never bypasses the bound.
    pub fn reserve(&self, bytes: usize) -> Option<BufferCharge> {
        self.0
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|total| *total <= self.0.lane.buffer_limit())
            })
            .ok()?;
        // Foreground workers share the byte reservation, not one exclusive worker slot.
        // Otherwise a node's outgoing request prevents a cohosted peer from answering it,
        // even when both small requests fit comfortably inside the reservation.
        if let Some(shared) = self.0.shared_bytes() {
            if shared
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current
                        .checked_add(bytes)
                        .filter(|total| *total <= self.0.lane.buffer_limit())
                })
                .is_err()
            {
                self.0.bytes.fetch_sub(bytes, Ordering::AcqRel);
                return None;
            }
        }
        Some(BufferCharge {
            worker: Arc::clone(&self.0),
            bytes,
        })
    }

    /// Allocate only after admission and byte reservation. The buffer carries its charge when
    /// sent to another task, so a cancelled reader cannot release memory still in a queue.
    pub fn zeroed(&self, bytes: usize) -> Option<Buffer> {
        let charge = self.reserve(bytes)?;
        Some(Buffer {
            bytes: vec![0; bytes],
            _charge: charge,
        })
    }
}

/// An owned frame or staging buffer whose reservation cannot be detached accidentally.
pub struct Buffer {
    // Fields drop in declaration order: free the allocation before returning its capacity.
    bytes: Vec<u8>,
    _charge: BufferCharge,
}

impl Buffer {
    /// Borrow bytes while retaining their allocation charge.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Fill admitted storage without separating it from its allocation charge.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

/// A live buffer keeps both its byte reservation and the originating worker slot alive.
pub struct BufferCharge {
    worker: Arc<Worker>,
    bytes: usize,
}

impl Drop for BufferCharge {
    fn drop(&mut self) {
        self.worker.bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        if let Some(shared) = self.worker.shared_bytes() {
            shared.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
}

/// One daemon-wide retained-flow admission, inseparable from its real Control byte charge.
/// The Flow stores it after its state fields so allocations die before capacity is returned.
pub(crate) struct FlowStateCharge {
    budget: Arc<Budget>,
    _charge: BufferCharge,
}
impl Drop for FlowStateCharge {
    fn drop(&mut self) {
        self.budget.retained_flows.fetch_sub(1, Ordering::AcqRel);
    }
}
