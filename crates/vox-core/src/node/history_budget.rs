//! Shared daemon admission and transient-buffer ownership for requested history (ADR-036 H-7).
//!
//! A worker owns its slot until its last charged buffer is gone, including buffers handed back
//! to an actor. Acquire outside actor/room locks and charge before allocation. These are working
//! buffer limits, not a claim about total process RSS or the separately bounded disk caches.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::Notify;

use crate::hash::Digest32;

const MIB: usize = 1024 * 1024;
/// Archive rounds the daemon may run together. Exported so shipped-binary proofs derive their
/// hosted-node pressure from the same admission rule instead of copying a count.
pub const ARCHIVE_JOBS: usize = 2;
const FOREGROUND_JOBS: usize = 64;
#[cfg(feature = "test-knobs")]
/// Proof-only foreground capacity override; absent from a production build.
pub const TEST_FOREGROUND_JOBS_ENV: &str = "VOX_TEST_FOREGROUND_JOBS";
#[cfg(feature = "test-knobs")]
/// Proof-only file whose presence holds an admitted Live job; absent from production.
pub const TEST_HOLD_LIVE_JOB_ENV: &str = "VOX_TEST_HOLD_LIVE_JOB_FILE";
#[cfg(feature = "test-knobs")]
/// Proof-only file whose presence holds an admitted Control job; absent from production.
pub const TEST_HOLD_CONTROL_JOB_ENV: &str = "VOX_TEST_HOLD_CONTROL_JOB_FILE";
#[cfg(feature = "test-knobs")]
/// Proof-only file whose presence holds an admitted Archive job; absent from production.
pub const TEST_HOLD_ARCHIVE_JOB_ENV: &str = "VOX_TEST_HOLD_ARCHIVE_JOB_FILE";
#[cfg(feature = "test-knobs")]
/// Proof-only file whose presence holds the pool at its source-defined floor. This stages the
/// otherwise impossible retained-continuation path without copying a capacity count.
pub const TEST_FLOW_STATE_FLOOR_ENV: &str = "VOX_TEST_FLOW_STATE_FLOOR_FILE";
/// Historical fixed capacity used only to stage the old full-pool failure in optional proofs.
/// Production capacity is exactly the running slots times active-or-retiring identities.
pub const FLOW_STATE_CAPACITY: usize = 16;
/// The running bounded-sync slots one hosted node owns. This is the source of truth for both
/// the controller's array and the daemon pool's per-node capacity (ADR-038 FX-35).
pub const BOUNDED_SYNC_RUNNING_SLOTS: usize = 2;
/// One running bounded-sync quantum's product contract; proofs wait on this source-owned edge,
/// never a copied timeout.
pub const BOUNDED_ROUND_PATIENCE: std::time::Duration = std::time::Duration::from_secs(30);
pub(crate) const FLOW_STATE_BYTES: usize = 128 * 1024;
const CONTROL_TURNS_BEFORE_LIVE: usize = 3;
const LIVE_GRANTS: usize = 64;
const LIVE_GRANT_LIFETIME: std::time::Duration = std::time::Duration::from_secs(300);
const LIVE_GRANT_IDLE: std::time::Duration = std::time::Duration::from_secs(30);

fn flow_state_limit(hosted: usize) -> usize {
    #[cfg(feature = "test-knobs")]
    if std::env::var_os(TEST_FLOW_STATE_FLOOR_ENV)
        .is_some_and(|path| std::path::Path::new(&path).exists())
    {
        return FLOW_STATE_CAPACITY;
    }
    BOUNDED_SYNC_RUNNING_SLOTS * hosted
}

#[cfg(feature = "test-knobs")]
fn foreground_jobs() -> usize {
    std::env::var(TEST_FOREGROUND_JOBS_ENV)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(FOREGROUND_JOBS)
}

#[cfg(not(feature = "test-knobs"))]
const fn foreground_jobs() -> usize {
    FOREGROUND_JOBS
}

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
    pub(crate) const fn index(self) -> usize {
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

struct State {
    queues: [VecDeque<Waiting>; 4],
    archive_nodes: BTreeSet<Digest32>,
    control: usize,
    foreground: usize,
    foreground_control_turns: usize,
    next_ticket: u64,
    live_grants: BTreeMap<LiveKey, LiveGrant>,
    foreground_jobs: usize,
}

impl Default for State {
    fn default() -> Self {
        Self {
            queues: Default::default(),
            archive_nodes: Default::default(),
            control: 0,
            foreground: 0,
            foreground_control_turns: 0,
            next_ticket: 0,
            live_grants: Default::default(),
            foreground_jobs: foreground_jobs(),
        }
    }
}

impl State {
    /// Allocate an identity not held by another waiter in this lane. Serial wrap is ordinary:
    /// the queue can hold fewer identities than the `u64` space on every supported target, so
    /// walking past the finite live set always finds a free value and never refuses exact work.
    fn allocate_ticket(&mut self, lane: Lane) -> u64 {
        loop {
            self.next_ticket = self.next_ticket.wrapping_add(1);
            if !self.queues[lane.index()]
                .iter()
                .any(|waiting| waiting.ticket == self.next_ticket)
            {
                return self.next_ticket;
            }
        }
    }

    fn available(&self, node: Digest32, lane: Lane) -> bool {
        match lane {
            Lane::Archive => {
                self.archive_nodes.len() < ARCHIVE_JOBS && !self.archive_nodes.contains(&node)
            }
            // The proof-only capacity override applies to both foreground reservations. In a
            // production build `foreground_jobs()` is the same source constant, so this does not
            // change shipped admission; it lets a real daemon causally stage Control pressure.
            Lane::Control => self.control < self.foreground_jobs,
            Lane::LargeControl => {
                self.foreground < self.foreground_jobs
                    && (self.queues[Lane::Live.index()].is_empty()
                        || self.foreground_control_turns < CONTROL_TURNS_BEFORE_LIVE)
            }
            Lane::Live => {
                self.foreground < self.foreground_jobs
                    && (self.queues[Lane::LargeControl.index()].is_empty()
                        || self.foreground_control_turns >= CONTROL_TURNS_BEFORE_LIVE)
            }
        }
    }

    fn admissible_waiter(&self, lane: Lane) -> bool {
        if self.queues[lane.index()].is_empty() {
            return false;
        }
        match lane {
            Lane::Archive => self.queues[lane.index()]
                .iter()
                .any(|waiting| self.available(waiting.node, lane)),
            Lane::Control | Lane::LargeControl | Lane::Live => self.queues[lane.index()]
                .front()
                .is_some_and(|waiting| self.available(waiting.node, lane)),
        }
    }

    fn admission_changed_waiter(&self, lane: Lane) -> bool {
        match lane {
            Lane::Archive | Lane::Control => self.admissible_waiter(lane),
            Lane::LargeControl | Lane::Live => {
                self.admissible_waiter(Lane::LargeControl) || self.admissible_waiter(Lane::Live)
            }
        }
    }
}

/// One exact cleanup obligation. The actor registration and request ID distinguish a retired
/// actor's work from a replacement using the same node fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RetirementKey {
    pub(crate) actor: Option<u64>,
    pub(crate) request: [u8; 16],
    pub(crate) node: Digest32,
    pub(crate) room: Digest32,
    pub(crate) peer: Digest32,
    pub(crate) archive: bool,
    pub(crate) instance: [u8; 16],
    pub(crate) generation: Digest32,
}

pub(crate) struct RetirementEntry {
    pub(crate) flow: Arc<tokio::sync::Mutex<Option<crate::node::history_stream::runtime::Flow>>>,
    pub(crate) running: AtomicBool,
    pub(crate) failed: AtomicBool,
    pub(crate) recovery_changed: Arc<Notify>,
    pub(crate) task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Default)]
pub(crate) struct RetirementLedger {
    pub(crate) entries: Mutex<BTreeMap<RetirementKey, Arc<RetirementEntry>>>,
    pub(crate) errors: Mutex<BTreeMap<RetirementKey, String>>,
}

/// One instance belongs to the daemon and is shared by every hosted node.
#[derive(Default)]
pub struct Budget {
    state: Mutex<State>,
    /// Capacity-change notifications are scoped to the reservation they can unblock. Archive
    /// and Control are independent; LargeControl and Live notify each other because they share
    /// the foreground reservation and alternate priority.
    changed: [Arc<Notify>; 4],
    bytes_changed: [Arc<Notify>; 2],
    control_bytes: AtomicUsize,
    /// The daemon's flow-state pool, one record under one lock (ADR-038 FX-35).
    pool: Mutex<Pool>,
    /// Owed retirement ownership belongs to the daemon, not one actor incarnation. An actor
    /// panic therefore cannot lose a Flow or its visible failure, and a replacement resumes the
    /// same exact request.
    retirements: Arc<RetirementLedger>,
    foreground_bytes: AtomicUsize,
}

impl Budget {
    /// Create the one shared set of reservations owned by a daemon.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Admit one exact daemon job without borrowing an already-admitted worker. Retirement and
    /// other local cleanup use this so a parked flow retains only durable demand, never a lane
    /// slot. The ticket subscribes before each attempt; capacity release is the only wake.
    pub(crate) async fn admit_job(self: &Arc<Self>, node: Digest32, lane: Lane) -> Job {
        let mut ticket = self.enqueue(node, lane);
        loop {
            let wake = ticket.wake();
            if let Some(job) = ticket.try_admit() {
                return job;
            }
            wake.await;
        }
    }

    pub(crate) fn retirement_ledger(&self) -> Arc<RetirementLedger> {
        Arc::clone(&self.retirements)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn notify_lane(&self, lane: Lane) {
        match lane {
            Lane::Archive | Lane::Control => self.changed[lane.index()].notify_waiters(),
            Lane::LargeControl | Lane::Live => {
                self.changed[Lane::LargeControl.index()].notify_waiters();
                self.changed[Lane::Live.index()].notify_waiters();
            }
        }
    }

    /// Queue one bounded operation. Ticket identities wrap past the finite active set, so serial
    /// exhaustion cannot refuse or dispose exact work. No actor lock may be held while awaiting
    /// the returned ticket. Dropping it cancels the queued operation.
    pub fn enqueue(self: &Arc<Self>, node: Digest32, lane: Lane) -> Ticket {
        let mut state = self.state();
        let ticket = state.allocate_ticket(lane);
        state.queues[lane.index()].push_back(Waiting { ticket, node });
        drop(state);
        Ticket {
            budget: Arc::clone(self),
            node,
            lane,
            ticket,
            queued: true,
        }
    }

    /// Nonblocking admission for an actor: queued workers retain their place ahead of it.
    pub fn try_start(self: &Arc<Self>, node: Digest32, lane: Lane) -> Option<Job> {
        self.enqueue(node, lane).try_admit()
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
    /// Stable FIFO identity exposed only through the owning shipped status snapshot. This is not
    /// a retry count or progress proxy: it identifies the exact retained admission owner.
    pub(crate) fn sequence(&self) -> u64 {
        self.ticket
    }

    /// Register before attempting admission, so a permit released between the check and the
    /// actor's wake task cannot be missed. This future owns only the notification subscription;
    /// the controller retains the queue ticket and can cancel it synchronously.
    pub(crate) fn wake(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        let mut wake =
            Box::pin(Arc::clone(&self.budget.changed[self.lane.index()]).notified_owned());
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
        let notify_next = state.admission_changed_waiter(self.lane);
        drop(state);
        // Admission is a wake only when removing this queue head or changing foreground priority
        // made another retained ticket actually admissible. Consuming the final slot broadcasts
        // nothing; that spurious edge used to strand one-shot waiters before the real release.
        if notify_next {
            self.budget.notify_lane(self.lane);
        }
        let flow_owner = self
            .budget
            .pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .active
            .get(&self.node)
            .copied();
        Some(Job(Arc::new(Worker {
            budget: Arc::clone(&self.budget),
            node: self.node,
            lane: self.lane,
            bytes: AtomicUsize::new(0),
            flow_owner,
        })))
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if self.queued {
            self.budget.state().queues[self.lane.index()]
                .retain(|entry| entry.ticket != self.ticket);
            self.budget.notify_lane(self.lane);
        }
    }
}

struct Worker {
    budget: Arc<Budget>,
    node: Digest32,
    lane: Lane,
    bytes: AtomicUsize,
    /// Registration generation that admitted this actor's work. A retired actor's running
    /// charge and a replacement actor with the same fingerprint therefore retain distinct pool
    /// capacity until the old round really returns it.
    flow_owner: Option<u64>,
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
        self.budget.notify_lane(self.lane);
    }
}

/// The running worker's ownership. Moving or cloning this handle cannot create extra capacity.
#[derive(Clone)]
pub struct Job(Arc<Worker>);

type ByteWake = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>;

/// A failed record allocation's exact capacity dependency. It retains no worker slot or
/// allocation charge; poll it only after the refused step's temporary buffers have dropped.
pub struct BytePressure {
    budget: Arc<Budget>,
    lane: Lane,
    required: usize,
    wake: ByteWake,
}

impl std::fmt::Debug for BytePressure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BytePressure")
            .field("lane", &self.lane)
            .field("required", &self.required)
            .finish_non_exhaustive()
    }
}

fn byte_wake(budget: &Budget, lane: Lane) -> ByteWake {
    let index = usize::from(matches!(lane, Lane::LargeControl | Lane::Live));
    let mut wake = Box::pin(Arc::clone(&budget.bytes_changed[index]).notified_owned());
    wake.as_mut().enable();
    wake
}

impl BytePressure {
    pub(crate) fn lane(&self) -> Lane {
        self.lane
    }

    pub(crate) async fn released(self) {
        // Archive bytes belong to one worker, not a shared pool. After that worker exits,
        // the ordinary archive admission gate supplies a fresh worker with the validated cap.
        if self.lane == Lane::Archive {
            return;
        }
        let mut wake = self.wake;
        loop {
            let used = match self.lane {
                Lane::Control => self.budget.control_bytes.load(Ordering::Acquire),
                Lane::LargeControl | Lane::Live => {
                    self.budget.foreground_bytes.load(Ordering::Acquire)
                }
                Lane::Archive => return,
            };
            if used
                .checked_add(self.required)
                .is_some_and(|total| total <= self.lane.buffer_limit())
            {
                return;
            }
            // Own temporary releases may have made the original notification ready. They
            // authorize no retry unless the complete reconstruction peak now fits. Subscribe
            // again before the next predicate so an intervening external release is not lost.
            wake.await;
            wake = byte_wake(&self.budget, self.lane);
        }
    }
}

impl Job {
    pub(crate) fn lane(&self) -> Lane {
        self.0.lane
    }

    /// Subscribe before attempting the record reservation. The dependency is transferred to
    /// the actor only on refusal, and starts waiting after the worker has released its buffers.
    pub(crate) fn byte_pressure(&self, required: usize) -> crate::error::Result<BytePressure> {
        if required > self.0.lane.buffer_limit() {
            return Err(crate::error::Error::SizeLimitExceeded(
                "history record reconstruction envelope",
            ));
        }
        Ok(BytePressure {
            budget: Arc::clone(&self.0.budget),
            lane: self.0.lane,
            required,
            wake: byte_wake(&self.0.budget, self.0.lane),
        })
    }

    /// Successful demand work allocates no waiter. On refusal subscribe and retry once before
    /// retaining the exact dependency: a release between the first check and enrollment is
    /// observed by the second check. Control's running Flow-state charge is included in the
    /// fresh envelope; independent pools are never summed.
    pub(crate) fn reserve_or_pressure(&self, bytes: usize) -> crate::error::Result<BufferCharge> {
        if let Some(charge) = self.reserve(bytes) {
            return Ok(charge);
        }
        let required = self
            .0
            .bytes
            .load(Ordering::Acquire)
            .checked_add(bytes)
            .ok_or(crate::error::Error::SizeLimitExceeded(
                "history working envelope",
            ))?;
        let pressure = self.byte_pressure(required)?;
        self.reserve(bytes)
            .ok_or_else(|| crate::error::Error::HistoryCapacity(Box::new(pressure)))
    }

    pub(crate) fn flow_owner(&self) -> Option<u64> {
        self.0.flow_owner
    }

    /// Record one exact retained Flow after the impossible pool/source-slot refusal. Enrollment
    /// carries the refusing reservation's release-edge identity, so only an intervening running
    /// release can grant it while closing the check/enroll race.
    pub(crate) fn flow_wait_ticket(
        &self,
        room: Digest32,
        peer: Digest32,
        request: [u8; 16],
        instance: [u8; 16],
        token: u64,
        refused_at: &FlowReleaseEdge,
    ) -> Result<FlowReleaseTicket, FlowWaitError> {
        let owner = self.0.flow_owner.ok_or(FlowWaitError::OwnerMissing)?;
        let budget = Arc::clone(&self.0.budget);
        let mut pool = budget.pool.lock().unwrap_or_else(PoisonError::into_inner);
        if !pool.owners.contains_key(&owner) {
            return Err(FlowWaitError::OwnerMissing);
        }
        // Never recycle a low numeric order while an older continuation can still exist. At
        // exhaustion the operator sees the exact invariant failure instead of new work jumping
        // ahead of retained old work.
        let id = pool
            .next_continuation
            .checked_add(1)
            .ok_or(FlowWaitError::OrderExhausted)?;
        pool.next_continuation = id;
        let Some(owner_state) = pool.owners.get_mut(&owner) else {
            return Err(FlowWaitError::OwnerMissing);
        };
        owner_state.continuations.insert(
            id,
            FlowContinuation {
                id,
                room,
                peer,
                request,
                instance,
                token,
                granted: false,
            },
        );
        // Enrollment itself is not a wake. It dispatches only when a running-round release
        // happened after the refusing snapshot, closing that exact check/enroll race without
        // letting registration, resizing or a tick stand in for the release edge.
        if !Arc::ptr_eq(&pool.release_edge, &refused_at.0) {
            pool.handoff_continuations();
        }
        drop(pool);
        Ok(FlowReleaseTicket { budget, owner, id })
    }

    /// Subscribe before a shared byte reservation attempt so its exact release cannot be lost.
    pub(crate) fn bytes_wake(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        let index = usize::from(matches!(self.0.lane, Lane::LargeControl | Lane::Live));
        let mut wake = Box::pin(Arc::clone(&self.0.budget.bytes_changed[index]).notified_owned());
        wake.as_mut().enable();
        wake
    }

    /// Proof-only: keep one admitted Control, Live or Archive job until apparatus removes its lane's
    /// named file. The caller invokes this only after it exclusively owns the charged Flow.
    /// A `<hold>.entered.<actor>.<job>` file containing the node, room and peer is the apparatus
    /// edge which proves that exact ownership; observing admission/status before this edge is
    /// insufficient because the controller can still adopt a Flow whose worker has not locked
    /// it. Production builds contain neither variable, marker nor pause.
    #[cfg(feature = "test-knobs")]
    pub(crate) async fn hold_for_proof(&self, room: Digest32, peer: Digest32) {
        let variable = match self.0.lane {
            Lane::Archive => TEST_HOLD_ARCHIVE_JOB_ENV,
            Lane::Control => TEST_HOLD_CONTROL_JOB_ENV,
            Lane::Live => TEST_HOLD_LIVE_JOB_ENV,
            Lane::LargeControl => return,
        };
        let Some(path) = std::env::var_os(variable) else {
            return;
        };
        if !std::path::Path::new(&path).exists() {
            return;
        }
        let Some(owner) = self.0.flow_owner else {
            return;
        };
        let job = Arc::as_ptr(&self.0) as usize;
        let entered = std::path::PathBuf::from(format!(
            "{}.entered.{owner}.{job}",
            std::path::Path::new(&path).display()
        ));
        let identity = format!(
            "{}\nroom={}\npeer={}\n",
            crate::node::link::b32_encode(&self.0.node),
            crate::node::link::b32_encode(&room),
            crate::node::link::b32_encode(&peer),
        );
        if std::fs::write(&entered, identity.as_bytes()).is_err() {
            return;
        }
        while std::path::Path::new(&path).exists() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let _ = std::fs::remove_file(entered);
    }

    #[cfg(not(feature = "test-knobs"))]
    pub(crate) async fn hold_for_proof(&self, _room: Digest32, _peer: Digest32) {}

    /// Reserve flow state for a port's round (ADR-038 FX-35), the Control bytes it costs already
    /// reserved by the caller (the control budget's refusal is its own gate, never the pool's).
    /// The charge is the round's: it is recorded as running in the same step, under the one
    /// lock, and is given back when the charge drops. `NodeBusy` when this fingerprint's current
    /// and retiring generations already hold its source-owned running slots. `PoolFull` when
    /// every pool charge is held by a running round, which the per-fingerprint limit and pool
    /// capacity is currently occupied; the bytes go back on either refusal.
    pub(crate) fn reserve_flow_state(
        &self,
        room: Digest32,
        peer: Digest32,
        request: [u8; 16],
        instance: [u8; 16],
        bytes: BufferCharge,
        waiter: Option<&mut FlowReleaseTicket>,
    ) -> FlowStateTry {
        let budget = Arc::clone(&self.0.budget);
        let mut p = budget.pool.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(owner) = self.0.flow_owner else {
            return FlowStateTry::OwnerMissing;
        };
        let key = FlowStateOwner {
            actor: owner,
            node: self.0.node,
            room,
            peer,
            request,
            instance,
        };
        let Some(node) = p.owners.get(&owner).map(|owner| owner.node) else {
            return FlowStateTry::OwnerMissing;
        };
        let granted = waiter.as_ref().is_some_and(|waiter| {
            waiter.take_grant_locked(&mut p, owner, room, peer, request, instance)
        });
        // Actor replacement does not create a second pair of bounded slots for one hosted
        // fingerprint. Retiring and current generations share the same source-owned slot count;
        // the old charge's exact Drop wakes the replacement without a tick or elapsed escape.
        let node_in_use: usize = p
            .owners
            .values()
            .filter(|pool_owner| pool_owner.node == node)
            .map(|pool_owner| pool_owner.charges)
            .sum();
        let promised_for_node = p
            .owners
            .values()
            .filter(|owner| owner.node == node)
            .flat_map(|owner| owner.continuations.values())
            .filter(|continuation| continuation.granted)
            .count();
        if !granted && node_in_use + promised_for_node >= BOUNDED_SYNC_RUNNING_SLOTS {
            return FlowStateTry::NodeBusy(FlowReleaseEdge(Arc::clone(&p.release_edge)));
        }
        let promised = p
            .owners
            .values()
            .flat_map(|owner| owner.continuations.values())
            .filter(|continuation| continuation.granted)
            .count();
        let occupied = p.in_use + promised;
        if !granted && occupied > p.limit {
            return FlowStateTry::PoolOvercommitted(FlowReleaseEdge(Arc::clone(&p.release_edge)));
        }
        if !granted && occupied == p.limit {
            return FlowStateTry::PoolFull(FlowReleaseEdge(Arc::clone(&p.release_edge)));
        }
        let Some(pool_owner) = p.owners.get_mut(&owner) else {
            return FlowStateTry::OwnerMissing;
        };
        pool_owner.charges += 1;
        p.in_use += 1;
        *p.running.entry(key).or_insert(0) += 1;
        drop(p);
        FlowStateTry::Reserved(FlowStateCharge {
            budget,
            key,
            owner,
            charge: Some(bytes),
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

    /// A control work envelope larger than one MiB uses the foreground reservation, preserving
    /// the small control pool for fixed wire metadata and staging state. This admits a separately
    /// accounted worker; it never widens a charge on the existing worker. The caller drops it
    /// with the last actual buffer.
    pub(crate) async fn record_job(&self, envelope: usize) -> Option<Self> {
        if self.0.lane == Lane::Control && envelope > MIB {
            let mut ticket = self.0.budget.enqueue(self.0.node, Lane::LargeControl);
            loop {
                // Subscribe first: a release between the failed admission and the await cannot
                // be lost. The retained ticket keeps its fair position; no periodic retry is
                // part of this admission path.
                let wake = ticket.wake();
                if let Some(job) = ticket.try_admit() {
                    return Some(job);
                }
                wake.await;
            }
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

impl BufferCharge {
    /// Split an already-accounted reservation without touching either byte counter. Both pieces
    /// retain the same worker, and their drops return exactly the original total.
    pub(crate) fn split_off(&mut self, bytes: usize) -> Option<Self> {
        self.bytes = self.bytes.checked_sub(bytes)?;
        Some(Self {
            worker: Arc::clone(&self.worker),
            bytes,
        })
    }
}

impl Drop for BufferCharge {
    fn drop(&mut self) {
        self.worker.bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        if let Some(shared) = self.worker.shared_bytes() {
            shared.fetch_sub(self.bytes, Ordering::AcqRel);
            let index = usize::from(matches!(self.worker.lane, Lane::LargeControl | Lane::Live));
            self.worker.budget.bytes_changed[index].notify_waiters();
        }
    }
}

/// The daemon's flow-state pool (ADR-038 FX-35), one record under one lock, so that what
/// `vox status --json` shows of it is one coordinated view: how many flow states it allows;
/// which running rounds hold one (actor, node, room, peer); and the current actor's count per
/// hosted node (one member per hosted node, 0 until it holds one). Retiring generations remain
/// visible separately. The limit is exactly two per active-or-retiring hosted identity;
/// it bounds only running rounds. A parked continuation holds no pool slot.
struct Pool {
    limit: usize,
    in_use: usize,
    /// A port can run its live and archive slots together, so retain multiplicity here while
    /// status needs only the key to say that the port has a running round.
    running: BTreeMap<FlowStateOwner, usize>,
    next_owner: u64,
    /// The current actor generation for each hosted fingerprint.
    active: BTreeMap<Digest32, u64>,
    /// Active and retiring actor generations. A replacement with the same fingerprint gets its
    /// own owner for exact attribution, but both generations count as one hosted node. Impossible
    /// continuations remain actor-owned here, never in a daemon-wide wait queue.
    owners: BTreeMap<u64, PoolOwner>,
    next_continuation: u64,
    /// Identity of the most recent running-round charge release. Pointer identity cannot wrap.
    release_edge: Arc<()>,
}

struct FlowContinuation {
    id: u64,
    room: Digest32,
    peer: Digest32,
    request: [u8; 16],
    instance: [u8; 16],
    token: u64,
    granted: bool,
}

struct PoolOwner {
    node: Digest32,
    registered: bool,
    charges: usize,
    /// Exact Flows remain in this actor generation's controller. These records only bind their
    /// monotonic release order and causal actor handoff; they are not a daemon-wide work queue.
    continuations: BTreeMap<u64, FlowContinuation>,
    release: tokio::sync::mpsc::UnboundedSender<FlowRelease>,
}

/// A charge release synchronously puts this exact retained continuation on its owning actor's
/// runnable queue. The actor processes this queue before reporting status, so a shipped snapshot
/// cannot mistake a pending handoff for a wedge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FlowRelease {
    pub(crate) order: u64,
    pub(crate) token: u64,
    pub(crate) room: Digest32,
    pub(crate) peer: Digest32,
}

/// Exact running-round ownership published in the same pool snapshot as its charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowStateOwner {
    pub(crate) actor: u64,
    pub(crate) node: Digest32,
    pub(crate) room: Digest32,
    pub(crate) peer: Digest32,
    pub(crate) request: [u8; 16],
    pub(crate) instance: [u8; 16],
}

impl Default for Pool {
    fn default() -> Self {
        Self {
            limit: 0,
            in_use: 0,
            running: BTreeMap::new(),
            next_owner: 0,
            active: BTreeMap::new(),
            owners: BTreeMap::new(),
            next_continuation: 0,
            release_edge: Arc::new(()),
        }
    }
}

impl Pool {
    /// Active registrations and a retired generation whose round is still returning both count
    /// as hosted until that exact charge is gone. Distinct generations of one fingerprint never
    /// widen its two legal running slots or its contribution to the daemon limit.
    fn resize(&mut self) {
        let hosted = self
            .owners
            .values()
            .map(|owner| owner.node)
            .collect::<BTreeSet<_>>()
            .len();
        self.limit = flow_state_limit(hosted);
    }

    /// Select the earliest actor-owned continuation which can use a daemon charge and one of its
    /// node's two source-owned running slots. A successful synchronous send is a promise counted
    /// ahead of new contenders until consumed or cancelled. The pool scans the continuations of
    /// its already-registered actor generations; it owns no daemon-wide work queue.
    fn handoff_continuations(&mut self) {
        loop {
            let promised = self
                .owners
                .values()
                .flat_map(|owner| owner.continuations.values())
                .filter(|continuation| continuation.granted)
                .count();
            if self.in_use + promised >= self.limit {
                return;
            }
            let candidate = self
                .owners
                .iter()
                .filter(|(_, owner)| owner.registered)
                .flat_map(|(generation, owner)| {
                    owner
                        .continuations
                        .values()
                        .filter(|continuation| !continuation.granted)
                        .map(move |continuation| (*generation, owner.node, continuation.id))
                })
                .filter(|(_, node, _)| {
                    let in_use: usize = self
                        .owners
                        .values()
                        .filter(|owner| owner.node == *node)
                        .map(|owner| owner.charges)
                        .sum();
                    let promised = self
                        .owners
                        .values()
                        .filter(|owner| owner.node == *node)
                        .flat_map(|owner| owner.continuations.values())
                        .filter(|continuation| continuation.granted)
                        .count();
                    in_use + promised < BOUNDED_SYNC_RUNNING_SLOTS
                })
                .min_by_key(|(_, _, order)| *order);
            let Some((generation, _, order)) = candidate else {
                return;
            };
            let sent = {
                let Some(owner) = self.owners.get_mut(&generation) else {
                    continue;
                };
                let Some(continuation) = owner.continuations.get_mut(&order) else {
                    continue;
                };
                continuation.granted = true;
                owner
                    .release
                    .send(FlowRelease {
                        order,
                        token: continuation.token,
                        room: continuation.room,
                        peer: continuation.peer,
                    })
                    .is_ok()
            };
            if !sent {
                if let Some(owner) = self.owners.get_mut(&generation) {
                    owner.continuations.remove(&order);
                }
            }
        }
    }
}

/// Exact ownership of an impossible flow-state admission wait. It retains no worker, bytes,
/// outbound slot or flow-state charge. Dropping it removes ineligible work immediately and, when
/// it owned a release-edge grant, passes that grant to the next earliest eligible continuation.
pub(crate) struct FlowReleaseTicket {
    budget: Arc<Budget>,
    owner: u64,
    id: u64,
}

/// Why an exact retained continuation could not acquire monotonic release-edge ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlowWaitError {
    /// Its admitted worker no longer belongs to a registered or retiring actor generation.
    OwnerMissing,
    /// The process-lifetime monotonic identity space is exhausted; identities never wrap.
    OrderExhausted,
}

/// Snapshot of the last running-round release when a reservation was refused. A later
/// enrollment may dispatch only if pointer identity proves such a release intervened.
#[derive(Clone)]
pub(crate) struct FlowReleaseEdge(Arc<()>);

impl FlowReleaseTicket {
    fn take_grant_locked(
        &self,
        pool: &mut Pool,
        owner: u64,
        room: Digest32,
        peer: Digest32,
        request: [u8; 16],
        instance: [u8; 16],
    ) -> bool {
        let Some(owner_state) = pool.owners.get_mut(&owner) else {
            return false;
        };
        let Some(continuation) = owner_state.continuations.get(&self.id) else {
            return false;
        };
        if self.owner != owner
            || !continuation.granted
            || continuation.room != room
            || continuation.peer != peer
            || continuation.request != request
            || continuation.instance != instance
        {
            return false;
        }
        owner_state.continuations.remove(&self.id);
        true
    }

    pub(crate) fn granted(&self) -> bool {
        self.budget
            .pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .owners
            .get(&self.owner)
            .and_then(|owner| owner.continuations.get(&self.id))
            .is_some_and(|continuation| continuation.granted)
    }

    pub(crate) fn sequence(&self) -> u64 {
        self.id
    }
}

impl Drop for FlowReleaseTicket {
    fn drop(&mut self) {
        let mut pool = self
            .budget
            .pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let returned_grant = pool
            .owners
            .get_mut(&self.owner)
            .and_then(|owner| owner.continuations.remove(&self.id))
            .is_some_and(|continuation| continuation.granted);
        if pool.owners.get(&self.owner).is_some_and(|owner| {
            !owner.registered && owner.charges == 0 && owner.continuations.is_empty()
        }) {
            pool.owners.remove(&self.owner);
            pool.resize();
        }
        // Cancelling ungranted work creates no release edge. A granted ticket, however, returns
        // the exact earlier release promise, which remains causal when passed to the next owner.
        if returned_grant {
            pool.handoff_continuations();
        }
    }
}

/// One hosted node's ownership of its daemon flow-state capacity. Kept in the node actor, so
/// unwinding an actor panic requests the same unregister as a graceful lock. If a worker charge
/// outlives the actor, the pool defers removal until that charge's `Drop`.
pub(crate) struct FlowPoolRegistration {
    budget: Arc<Budget>,
    node: Digest32,
    owner: u64,
}

impl Drop for FlowPoolRegistration {
    fn drop(&mut self) {
        let mut p = self
            .budget
            .pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if p.active.get(&self.node) == Some(&self.owner) {
            p.active.remove(&self.node);
        }
        if let Some(owner) = p.owners.get_mut(&self.owner) {
            owner.registered = false;
        }
        if p.owners
            .get(&self.owner)
            .is_some_and(|owner| owner.charges == 0 && owner.continuations.is_empty())
        {
            p.owners.remove(&self.owner);
        }
        p.resize();
    }
}

/// What a port's reservation of flow state came to (ADR-038 FX-35).
pub(crate) enum FlowStateTry {
    /// The round holds its flow state.
    Reserved(FlowStateCharge),
    /// Every dynamically sized position is occupied by a running charge or an earlier
    /// release-edge promise. This is an invariant failure: the exact parked continuation waits
    /// for the causally matching charge release without retaining a worker or flow-state slot.
    PoolFull(FlowReleaseEdge),
    /// Accounting already exceeds the current limit. This is not falsely called PoolFull,
    /// whose displayed contract is exact equality.
    PoolOvercommitted(FlowReleaseEdge),
    /// Both bounded running slots of this fingerprint belong to its current or retiring actor
    /// generation. The retiring charge's release wakes the exact retained replacement work.
    NodeBusy(FlowReleaseEdge),
    /// The admitted worker no longer belongs to a pool actor generation. Pool occupancy says
    /// nothing about this lifecycle invariant failure.
    OwnerMissing,
}

/// One running round's flow state, inseparable from its real Control byte charge. The Flow
/// stores it after its state fields so allocations die before capacity is returned; the bytes
/// go back first, then the pool is told.
pub(crate) struct FlowStateCharge {
    budget: Arc<Budget>,
    key: FlowStateOwner,
    owner: u64,
    charge: Option<BufferCharge>,
}
impl Drop for FlowStateCharge {
    fn drop(&mut self) {
        drop(self.charge.take());
        let mut p = self
            .budget
            .pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        p.in_use = p.in_use.saturating_sub(1);
        if let Some(count) = p.running.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                p.running.remove(&self.key);
            }
        }
        if let Some(owner) = p.owners.get_mut(&self.owner) {
            owner.charges = owner.charges.saturating_sub(1);
        }
        if p.owners.get(&self.owner).is_some_and(|owner| {
            !owner.registered && owner.charges == 0 && owner.continuations.is_empty()
        }) {
            p.owners.remove(&self.owner);
        }
        p.resize();
        // This is the only edge which creates a new grant: a running round stopped owning its
        // charge. Registration and pool resizing update accounting but dispatch no work.
        p.release_edge = Arc::new(());
        p.handoff_continuations();
    }
}

/// The budget's lanes as they stand, for `vox status --json` (`lanes.budget`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetSnapshot {
    /// The nodes holding an archive job now (at most `ARCHIVE_JOBS`).
    pub archive_nodes: Vec<Digest32>,
    /// The archive jobs the daemon allows at once.
    pub archive_jobs: usize,
    /// Control jobs in flight.
    pub control: usize,
    /// Foreground (large control and live) jobs in flight.
    pub foreground: usize,
    /// The foreground jobs the daemon allows at once.
    pub foreground_jobs: usize,
    /// Tickets waiting per lane, in `Lane::index` order: archive, control, large control, live.
    pub queued: [usize; 4],
    /// Flow states held now, each by one running round (ADR-038 FX-35).
    pub flow_state_in_use: usize,
    /// Release-edge grants not consumed by their owning actors yet.
    pub flow_state_promised: usize,
    /// Running charges plus release-edge grants: capacity unavailable to a new contender.
    pub flow_state_occupied: usize,
    /// The running flow states the daemon allows at once.
    pub flow_state_limit: usize,
    /// Charges by hosted node: one member per fingerprint across its active and retiring actor
    /// generations. The member values sum exactly to `flow_state_in_use`.
    pub flow_state_by_node: Vec<(Digest32, usize)>,
    /// Running charges plus release-edge grants per hosted node.
    pub flow_state_occupied_by_node: Vec<(Digest32, usize)>,
    /// Every active or retiring actor generation and its exact charge count.
    pub flow_state_actors: Vec<(u64, Digest32, bool, usize)>,
    /// Nodes whose actor registration ended while a running charge was still returning.
    pub flow_state_retiring_nodes: Vec<Digest32>,
    /// The running rounds holding a flow state (node, room, peer), from the same view.
    pub flow_state_running: Vec<FlowStateOwner>,
    /// Exact retained impossible-path continuations in monotonic enrollment order.
    pub flow_state_waiting: Vec<FlowContinuationSnapshot>,
}

/// Monotonic order, actor, node, room, peer, request, incarnation and release grant.
pub type FlowContinuationSnapshot = (
    u64,
    u64,
    Digest32,
    Digest32,
    Digest32,
    [u8; 16],
    [u8; 16],
    bool,
);

impl Budget {
    /// A hosted node lists itself in the flow-state pool when it starts networking, at 0 until
    /// it holds one (`by_node` has one member per hosted node, ADR-038 FX-35).
    pub(crate) fn register_node(
        self: &Arc<Self>,
        node: Digest32,
        release: tokio::sync::mpsc::UnboundedSender<FlowRelease>,
    ) -> FlowPoolRegistration {
        let mut p = self.pool.lock().unwrap_or_else(PoisonError::into_inner);
        let mut owner = p.next_owner.wrapping_add(1);
        while p.owners.contains_key(&owner) {
            owner = owner.wrapping_add(1);
        }
        p.next_owner = owner;
        if let Some(replaced_owner) = p.active.insert(node, owner) {
            if let Some(replaced) = p.owners.get_mut(&replaced_owner) {
                replaced.registered = false;
            }
            // The replacement owns new work for this fingerprint. An old generation may keep
            // an already-running charge until its task returns. Its continuations cease to be
            // eligible at replacement, but remain until their actor-owned tickets drop: that
            // returns an existing grant causally instead of letting registration create a wake.
        }
        p.owners.insert(
            owner,
            PoolOwner {
                node,
                registered: true,
                charges: 0,
                continuations: BTreeMap::new(),
                release,
            },
        );
        p.owners.retain(|_, owner| {
            owner.registered || owner.charges > 0 || !owner.continuations.is_empty()
        });
        p.resize();
        drop(p);
        FlowPoolRegistration {
            budget: Arc::clone(self),
            node,
            owner,
        }
    }

    /// The lanes as they stand now.
    #[must_use]
    pub fn snapshot(&self) -> BudgetSnapshot {
        let state = self.state();
        let p = self.pool.lock().unwrap_or_else(PoisonError::into_inner);
        BudgetSnapshot {
            archive_nodes: state.archive_nodes.iter().copied().collect(),
            archive_jobs: ARCHIVE_JOBS,
            control: state.control,
            foreground: state.foreground,
            foreground_jobs: state.foreground_jobs,
            queued: [
                state.queues[0].len(),
                state.queues[1].len(),
                state.queues[2].len(),
                state.queues[3].len(),
            ],
            // One locked view of the pool: the running rounds and their count per node, as
            // they stand together.
            flow_state_in_use: p.in_use,
            flow_state_promised: p
                .owners
                .values()
                .flat_map(|owner| owner.continuations.values())
                .filter(|continuation| continuation.granted)
                .count(),
            flow_state_occupied: p.in_use
                + p.owners
                    .values()
                    .flat_map(|owner| owner.continuations.values())
                    .filter(|continuation| continuation.granted)
                    .count(),
            flow_state_limit: p.limit,
            flow_state_by_node: {
                let mut by_node = BTreeMap::new();
                for owner in p.owners.values() {
                    *by_node.entry(owner.node).or_insert(0) += owner.charges;
                }
                by_node.into_iter().collect()
            },
            flow_state_occupied_by_node: {
                let mut by_node = BTreeMap::new();
                for owner in p.owners.values() {
                    *by_node.entry(owner.node).or_insert(0) += owner.charges
                        + owner
                            .continuations
                            .values()
                            .filter(|continuation| continuation.granted)
                            .count();
                }
                by_node.into_iter().collect()
            },
            flow_state_actors: p
                .owners
                .iter()
                .map(|(generation, owner)| {
                    (*generation, owner.node, owner.registered, owner.charges)
                })
                .collect(),
            flow_state_retiring_nodes: p
                .owners
                .values()
                .filter(|owner| !owner.registered)
                .map(|owner| owner.node)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            flow_state_running: p
                .running
                .iter()
                .flat_map(|(owner, count)| std::iter::repeat_n(*owner, *count))
                .collect(),
            flow_state_waiting: {
                let mut waiting = p
                    .owners
                    .iter()
                    .flat_map(|(generation, owner)| {
                        owner.continuations.values().map(|continuation| {
                            (
                                continuation.id,
                                *generation,
                                owner.node,
                                continuation.room,
                                continuation.peer,
                                continuation.request,
                                continuation.instance,
                                continuation.granted,
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                waiting.sort_by_key(|continuation| continuation.0);
                waiting
            },
        }
    }
}
