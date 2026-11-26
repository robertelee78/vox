//! Shared daemon admission and transient-buffer ownership for requested history (ADR-036 H-7).
//!
//! Working buffers retain their worker, including actor handoffs. After physical work ends,
//! completed output may retain only its shared byte debit while its consumer finishes. Acquire
//! outside actor/room locks and charge before allocation. These are working buffer limits, not
//! a claim about total process RSS or the separately bounded disk caches.

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
pub(crate) const FLOW_STATE_BYTES: usize = 128 * 1024;
const CONTROL_TURNS_BEFORE_LIVE: usize = 3;

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
            foreground_jobs: FOREGROUND_JOBS,
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
            Lane::Control => self.control < FOREGROUND_JOBS,
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

    fn ticket_position(&self, node: Digest32, lane: Lane, ticket: u64) -> Option<usize> {
        if !self.available(node, lane) {
            return None;
        }
        let at = match lane {
            Lane::Archive => self.queues[lane.index()]
                .iter()
                .position(|waiting| !self.archive_nodes.contains(&waiting.node))?,
            Lane::Control | Lane::LargeControl | Lane::Live => 0,
        };
        self.queues[lane.index()]
            .get(at)
            .is_some_and(|waiting| waiting.ticket == ticket)
            .then_some(at)
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
        if !self.queued {
            return None;
        }
        let at = state.ticket_position(self.node, self.lane, self.ticket)?;
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
            self.budget.notify_lane(self.lane);
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
    /// The shared-pool ceiling this exact refused operation may use. Most work uses the lane's
    /// full limit; work which depends on a peer response can retain derived serving headroom.
    shared_limit: usize,
    wake: ByteWake,
}

impl std::fmt::Debug for BytePressure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BytePressure")
            .field("lane", &self.lane)
            .field("required", &self.required)
            .field("shared_limit", &self.shared_limit)
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
                .is_some_and(|total| total <= self.shared_limit)
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
        self.byte_pressure_with_limit(required, self.0.lane.buffer_limit())
    }

    fn byte_pressure_with_limit(
        &self,
        required: usize,
        shared_limit: usize,
    ) -> crate::error::Result<BytePressure> {
        if required > shared_limit || shared_limit > self.0.lane.buffer_limit() {
            return Err(crate::error::Error::SizeLimitExceeded(
                "history record reconstruction envelope",
            ));
        }
        Ok(BytePressure {
            budget: Arc::clone(&self.0.budget),
            lane: self.0.lane,
            required,
            shared_limit,
            wake: byte_wake(&self.0.budget, self.0.lane),
        })
    }

    /// Successful demand work allocates no waiter. On refusal subscribe and retry once before
    /// retaining the exact dependency: a release between the first check and enrollment is
    /// observed by the second check. Control's running Flow-state charge is included in the
    /// fresh envelope; independent pools are never summed.
    pub(crate) fn reserve_or_pressure(&self, bytes: usize) -> crate::error::Result<BufferCharge> {
        self.reserve_or_pressure_with_limit(bytes, self.0.lane.buffer_limit())
    }

    /// Reserve a complete operation while retaining exact shared-pool headroom for the response
    /// which can let that operation finish. The total lane cap is unchanged. Both the atomic
    /// reservation and a retained byte-pressure dependency use the same derived ceiling, so a
    /// woken requester cannot steal its own server's response envelope.
    pub(crate) fn reserve_or_pressure_with_headroom(
        &self,
        bytes: usize,
        headroom: usize,
    ) -> crate::error::Result<BufferCharge> {
        let shared_limit = self.0.lane.buffer_limit().checked_sub(headroom).ok_or(
            crate::error::Error::SizeLimitExceeded("history serving headroom"),
        )?;
        self.reserve_or_pressure_with_limit(bytes, shared_limit)
    }

    fn reserve_or_pressure_with_limit(
        &self,
        bytes: usize,
        shared_limit: usize,
    ) -> crate::error::Result<BufferCharge> {
        if let Some(charge) = self.reserve_with_shared_limit(bytes, shared_limit) {
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
        let pressure = self.byte_pressure_with_limit(required, shared_limit)?;
        self.reserve_with_shared_limit(bytes, shared_limit)
            .ok_or_else(|| crate::error::Error::HistoryCapacity(Box::new(pressure)))
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
        self.reserve_with_shared_limit(bytes, self.0.lane.buffer_limit())
    }

    fn reserve_with_shared_limit(&self, bytes: usize, shared_limit: usize) -> Option<BufferCharge> {
        if shared_limit > self.0.lane.buffer_limit() {
            return None;
        }
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
                        .filter(|total| *total <= shared_limit)
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
    /// Transfer completed work's output to byte-only ownership without releasing its
    /// shared debit. Call only after its physical reader and scratch have been destroyed.
    /// Remaining Job/BufferCharge clones still retain execution until their normal drop;
    /// a slow output consumer cannot retain an otherwise finished execution slot.
    /// Archive has no shared byte counter and cannot use this handoff.
    pub(crate) fn into_output(mut self) -> Result<OutputCharge, Self> {
        let pool = match self.worker.lane {
            Lane::Archive => return Err(self),
            Lane::Control => OutputPool::Control,
            Lane::LargeControl | Lane::Live => OutputPool::Foreground,
        };
        let output = OutputCharge {
            budget: Arc::clone(&self.worker.budget),
            node: self.worker.node,
            pool,
            bytes: self.bytes,
        };
        // Shared bytes have not changed. Remove only this charge's execution-local
        // debit, then let self's Worker reference drop normally. Never recreate a Job.
        self.worker.bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        self.bytes = 0;
        Ok(output)
    }

    /// Reuse the worker that actually owns this allocation. A dependent operation must not
    /// request another permit from the same finite pool while this charge retains the first.
    pub(crate) fn job(&self) -> Job {
        Job(Arc::clone(&self.worker))
    }

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
        if self.bytes == 0 {
            return;
        }
        self.worker.bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        if let Some(shared) = self.worker.shared_bytes() {
            shared.fetch_sub(self.bytes, Ordering::AcqRel);
            let index = usize::from(matches!(self.worker.lane, Lane::LargeControl | Lane::Live));
            self.worker.budget.bytes_changed[index].notify_waiters();
        }
    }
}

#[derive(Debug)]
enum OutputPool {
    Control,
    Foreground,
}

/// Completed output retains its original shared byte credit, independently of
/// execution. This owns no worker, cannot admit work, and introduces no new allowance.
pub(crate) struct OutputCharge {
    budget: Arc<Budget>,
    node: Digest32,
    pool: OutputPool,
    bytes: usize,
}

impl std::fmt::Debug for OutputCharge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputCharge")
            .field("node", &self.node)
            .field("pool", &self.pool)
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl Drop for OutputCharge {
    fn drop(&mut self) {
        if self.bytes == 0 {
            return;
        }
        let index = match self.pool {
            OutputPool::Control => {
                self.budget
                    .control_bytes
                    .fetch_sub(self.bytes, Ordering::AcqRel);
                0
            }
            OutputPool::Foreground => {
                self.budget
                    .foreground_bytes
                    .fetch_sub(self.bytes, Ordering::AcqRel);
                1
            }
        };
        self.budget.bytes_changed[index].notify_waiters();
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
}

impl Budget {
    /// The lanes as they stand now.
    #[must_use]
    pub fn snapshot(&self) -> BudgetSnapshot {
        let state = self.state();
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
        }
    }
}
