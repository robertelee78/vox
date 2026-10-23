//! Bounded current-message work and explicitly requested archive work share the existing ports.
//! Events carry tokens only; private slots retain capabilities until workers actually finish.
use super::*;
use crate::node::history_stream::{self as stream, runtime::Flow, Purpose, RequestId};
use crate::node::store::Store;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::Mutex as StdMutex;

type RetirementKey = crate::node::history_budget::RetirementKey;
type RetirementLedger = crate::node::history_budget::RetirementLedger;
type RetirementEntry = crate::node::history_budget::RetirementEntry;

fn retirement_key(flow: &Flow) -> RetirementKey {
    RetirementKey {
        actor: flow.actor_incarnation(),
        request: flow.retirement_request(),
        node: flow.node,
        room: flow.room,
        peer: flow.peer,
        archive: flow.archive,
        instance: flow.instance,
        generation: flow.generation,
    }
}

fn note_retirement_error(ledger: &RetirementLedger, key: RetirementKey, error: &str) {
    if let Ok(mut errors) = ledger.errors.lock() {
        errors.insert(key, error.to_owned());
    }
}

fn clear_retirement_error(ledger: &RetirementLedger, key: RetirementKey) {
    if let Ok(mut errors) = ledger.errors.lock() {
        errors.remove(&key);
    }
}

struct RetirementRunner {
    entry: Arc<RetirementEntry>,
    ledger: Arc<RetirementLedger>,
    key: RetirementKey,
    complete: bool,
}

impl Drop for RetirementRunner {
    fn drop(&mut self) {
        self.entry.running.store(false, Ordering::Release);
        if !self.complete {
            let message = "history retirement task ended before durable cleanup";
            note_retirement_error(&self.ledger, self.key, message);
            eprintln!(
                "vox: {message} for {}/{}/{}",
                crate::node::link::b32_encode(&self.key.room),
                crate::node::link::b32_encode(&self.key.peer),
                if self.key.archive { "archive" } else { "live" }
            );
        }
    }
}

async fn finish_owed_retirement(
    ledger: Arc<RetirementLedger>,
    entry: Arc<RetirementEntry>,
    key: RetirementKey,
) {
    let mut runner = RetirementRunner {
        entry,
        ledger,
        key,
        complete: false,
    };
    loop {
        let outcome = {
            let mut held = runner.entry.flow.lock().await;
            let Some(flow) = held.as_mut() else {
                runner.complete = true;
                return;
            };
            // A worker panic can return ownership before its normal end-of-round park. Cleanup
            // is not a running round and must release that charge before doing anything else.
            flow.park();
            flow.retire_slice().await
        };
        match outcome {
            Ok(true) => {
                clear_retirement_error(&runner.ledger, key);
                runner.entry.flow.lock().await.take();
                if let Ok(mut entries) = runner.ledger.entries.lock() {
                    if entries
                        .get(&key)
                        .is_some_and(|entry| Arc::ptr_eq(entry, &runner.entry))
                    {
                        entries.remove(&key);
                    }
                }
                runner.complete = true;
                return;
            }
            // A bounded durable slice made progress or awaits local reclamation. Retain exact
            // ownership and retry forever under the named backoff; never spin on yield_now.
            Ok(false) => {
                tokio::time::sleep(crate::node::history_budget::RETIRE_RETRY_BACKOFF).await;
            }
            Err(error) => {
                note_retirement_error(&runner.ledger, key, &error.to_string());
                eprintln!(
                    "vox: history retirement for {}/{}/{} remains owed: {error}",
                    crate::node::link::b32_encode(&key.room),
                    crate::node::link::b32_encode(&key.peer),
                    if key.archive { "archive" } else { "live" }
                );
                tokio::time::sleep(crate::node::history_budget::RETIRE_RETRY_BACKOFF).await;
            }
        }
    }
}

fn start_retirement(
    ledger: &Arc<RetirementLedger>,
    key: RetirementKey,
    entry: Arc<RetirementEntry>,
) {
    if entry.running.swap(true, Ordering::AcqRel) {
        return;
    }
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            let task = handle.spawn(finish_owed_retirement(
                Arc::clone(ledger),
                Arc::clone(&entry),
                key,
            ));
            if let Ok(mut retained) = entry.task.lock() {
                *retained = Some(task);
            }
        }
        Err(error) => {
            let message = format!("no runtime can finish owed history retirement: {error}");
            entry.running.store(false, Ordering::Release);
            note_retirement_error(ledger, key, &message);
            eprintln!("vox: {message}");
        }
    }
}

fn adopt_retirement_cell(
    ledger: &Arc<RetirementLedger>,
    mut key: RetirementKey,
    flow: Arc<tokio::sync::Mutex<Option<Flow>>>,
) {
    let (entry, collision) = {
        let mut entries = ledger
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut collision = false;
        loop {
            match entries.get(&key) {
                Some(entry) if Arc::ptr_eq(&entry.flow, &flow) => {
                    break (Arc::clone(entry), collision);
                }
                Some(_) => {
                    // A malformed duplicate key must never discard either owned Flow. Retain
                    // the incoming obligation under a deterministic collision suffix and make
                    // the condition visible until that obligation finishes.
                    collision = true;
                    for byte in key.request.iter_mut().rev() {
                        let (next, carry) = byte.overflowing_add(1);
                        *byte = next;
                        if !carry {
                            break;
                        }
                    }
                }
                None => {
                    let entry = Arc::new(RetirementEntry {
                        flow: Arc::clone(&flow),
                        running: std::sync::atomic::AtomicBool::new(false),
                        task: StdMutex::new(None),
                    });
                    entries.insert(key, Arc::clone(&entry));
                    break (entry, collision);
                }
            }
        }
    };
    if collision {
        eprintln!(
            "vox: distinct history retirements collided for {}/{}, retaining both obligations",
            crate::node::link::b32_encode(&key.room),
            crate::node::link::b32_encode(&key.peer)
        );
        note_retirement_error(
            ledger,
            key,
            "distinct history retirements collided; both were retained",
        );
    }
    start_retirement(ledger, key, entry);
}

fn spawn_owed_retirement(mut flow: Flow, ledger: Arc<RetirementLedger>) {
    flow.park();
    let key = retirement_key(&flow);
    adopt_retirement_cell(&ledger, key, Arc::new(tokio::sync::Mutex::new(Some(flow))));
}

fn resume_owed_retirements(ledger: &Arc<RetirementLedger>) {
    let entries = ledger
        .entries
        .lock()
        .map(|entries| {
            entries
                .iter()
                .map(|(key, entry)| (*key, Arc::clone(entry)))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for (key, entry) in entries {
        start_retirement(ledger, key, entry);
    }
}

struct Returned {
    error: Option<String>,
    panic: Option<String>,
}
struct Running {
    room: Digest32,
    peer: Digest32,
    token: u64,
    generation: u64,
    request: u64,
    archive: Option<(stream::RequestId, Digest32)>,
    lane: crate::node::history_budget::Lane,
    retirement_key: RetirementKey,
    fence: Arc<crate::transport::stream_transport::Fence>,
    /// Exclusive ownership stays outside the fallible worker future. The supervised outer task
    /// observes its JoinError and the actor reclaims this exact Flow even when the worker panics.
    flow: Arc<tokio::sync::Mutex<Option<Flow>>>,
    result: Arc<StdMutex<Option<Returned>>>,
    task: tokio::task::JoinHandle<()>,
    started: std::time::Instant,
}
/// Retained flows are real bounded demand, not running pool charges. Once full, the exact port
/// remains needed and is retried by the completion/release event that frees one.
pub(crate) const RETAINED_FLOW_LIMIT: usize = 12;

struct Cleanup {
    key: RetirementKey,
    /// The task borrows the flow through shared ownership. If that task panics, the controller
    /// still owns the only durable cell and can retry instead of silently dropping the flow.
    flow: Arc<tokio::sync::Mutex<Option<Flow>>>,
    result: Arc<StdMutex<Option<crate::error::Result<bool>>>>,
    task: tokio::task::JoinHandle<()>,
    cancellations: Vec<crate::node::history_demand::Cancellation>,
}
#[derive(Clone, Copy)]
pub(super) struct AdmissionWork {
    root: &'static str,
    lane: crate::node::history_budget::Lane,
}
impl AdmissionWork {
    fn from_flow(flow: &Flow) -> Self {
        Self {
            root: flow.root_name(),
            lane: flow.lane(),
        }
    }
}
struct ArchiveAdmission {
    token: u64,
    room: Digest32,
    peer: Digest32,
    request: stream::RequestId,
    generation: Digest32,
    instance: [u8; 16],
    ticket: crate::node::history_budget::Ticket,
    task: tokio::task::JoinHandle<()>,
}
struct ForegroundAdmission {
    token: u64,
    room: Digest32,
    peer: Digest32,
    root: &'static str,
    lane: crate::node::history_budget::Lane,
    ticket: crate::node::history_budget::Ticket,
    task: tokio::task::JoinHandle<()>,
}
struct SecretAdmission {
    token: u64,
    root: &'static str,
    lane: crate::node::history_budget::Lane,
    task: tokio::task::JoinHandle<()>,
}
struct ByteAdmission {
    token: u64,
    root: &'static str,
    lane: crate::node::history_budget::Lane,
    owner: Option<ByteOwner>,
    /// Scheduling need captured by the ended worker, never the port's newer current need.
    port_request: Option<u64>,
    task: tokio::task::JoinHandle<()>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct ByteOwner {
    request: stream::RequestId,
    instance: [u8; 16],
    generation: Digest32,
}
impl ByteOwner {
    fn of(flow: &Flow) -> Self {
        Self {
            request: flow.retirement_request(),
            instance: flow.instance,
            generation: flow.generation,
        }
    }
}
struct ByteWait {
    wake: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    owner: Option<ByteOwner>,
    port_request: Option<u64>,
}
impl ByteWait {
    fn unowned(wake: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) -> Self {
        Self {
            wake,
            owner: None,
            port_request: None,
        }
    }
}
struct PoolAdmission {
    token: u64,
    gate: &'static str,
    root: &'static str,
    lane: crate::node::history_budget::Lane,
    ticket: crate::node::history_budget::FlowReleaseTicket,
    /// Set only by the exact release handoff. Unrelated actor events cannot consume a granted
    /// continuation before this owner has received its causal edge.
    handed_off: bool,
}
#[derive(Clone, Copy)]
struct PoolWait {
    gate: &'static str,
    work: AdmissionWork,
    request: stream::RequestId,
    instance: [u8; 16],
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct RequiredOwner {
    room: Digest32,
    peer: Digest32,
    head: Digest32,
    seq: u64,
    request: stream::RequestId,
    instance: [u8; 16],
}
enum ArchiveTurn {
    Ready(crate::node::history_budget::Job),
    Waiting,
}
enum ForegroundTurn {
    Ready(crate::node::history_budget::Job),
    Waiting,
}

const fn lane_name(lane: crate::node::history_budget::Lane) -> &'static str {
    match lane {
        crate::node::history_budget::Lane::Archive => "archive",
        crate::node::history_budget::Lane::Control => "control",
        crate::node::history_budget::Lane::LargeControl => "large_control",
        crate::node::history_budget::Lane::Live => "live",
    }
}

#[derive(Default)]
pub(super) struct Controller {
    running: [Option<Running>; crate::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS],
    ready: [Option<Flow>; crate::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS],
    /// The one queued archive turn for this node. The controller owns its daemon-wide fair-queue
    /// ticket; the task waits only for a wake, without an actor or room lock.
    archive_admission: Option<ArchiveAdmission>,
    /// One retained ticket per startable foreground lane. A release wakes the exact waiting
    /// port; the scheduler tick is neither its notifier nor a correctness fallback.
    foreground_admission: [Option<ForegroundAdmission>; 4],
    secret_admission: BTreeMap<(Digest32, Digest32), SecretAdmission>,
    byte_admission: BTreeMap<(Digest32, Digest32), ByteAdmission>,
    pool_admission: BTreeMap<(Digest32, Digest32), PoolAdmission>,
    deferred: VecDeque<Flow>,
    body_slots: Arc<stream::runtime::BodySlots>,
    required: VecDeque<RequiredOwner>,
    retiring: VecDeque<Flow>,
    cleanup: Option<Cleanup>,
    /// Per-flow retirement failures outlive controller replacement and remain visible until that
    /// exact flow reaches its durable end. An unrelated cleanup can never clear another's error.
    retirement_ledger: Arc<RetirementLedger>,
    /// Workers publish their durable result before notifying this coalesced edge. `Notify`
    /// retains a permit while the actor is elsewhere; one wake audits every result slot, so no
    /// completion can be stranded behind the actor's bounded event queue.
    completion_wake: Arc<tokio::sync::Notify>,
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.cancel_archive_admission();
        for index in 0..self.foreground_admission.len() {
            self.cancel_foreground_admission(index);
        }
        for (_, admission) in std::mem::take(&mut self.secret_admission) {
            admission.task.abort();
        }
        for (_, admission) in std::mem::take(&mut self.byte_admission) {
            admission.task.abort();
        }
        self.pool_admission.clear();
        let mut flows = Vec::new();
        flows.extend(self.ready.iter_mut().filter_map(Option::take));
        flows.extend(self.deferred.drain(..));
        flows.extend(self.retiring.drain(..));
        let cleanup = self.cleanup.take();
        let running = self
            .running
            .iter_mut()
            .filter_map(Option::take)
            .collect::<Vec<_>>();
        for flow in &mut flows {
            flow.cancel();
            flow.park();
        }
        if let Some(cleanup) = &cleanup {
            for cancellation in &cleanup.cancellations {
                cancellation.cancel();
            }
        }
        for work in &running {
            work.fence.retire();
        }
        let ledger = Arc::clone(&self.retirement_ledger);
        let message = "actor ended with durable history retirement still owed";
        for flow in flows {
            let key = retirement_key(&flow);
            note_retirement_error(&ledger, key, message);
            spawn_owed_retirement(flow, Arc::clone(&ledger));
        }
        if let Some(cleanup) = cleanup {
            note_retirement_error(&ledger, cleanup.key, message);
            adopt_retirement_cell(&ledger, cleanup.key, cleanup.flow);
            // Dropping the handle detaches an already-running bounded slice, but ownership is
            // now in the daemon ledger; its runner waits on the same cell and cannot race it.
            drop(cleanup.task);
        }
        for work in running {
            note_retirement_error(&ledger, work.retirement_key, message);
            adopt_retirement_cell(&ledger, work.retirement_key, work.flow);
            drop(work.task);
        }
    }
}

impl Controller {
    pub(super) fn set_completion_wake(&mut self, wake: Arc<tokio::sync::Notify>) {
        self.completion_wake = wake;
    }

    pub(super) fn set_retirement_ledger(&mut self, ledger: Arc<RetirementLedger>) {
        self.retirement_ledger = ledger;
        resume_owed_retirements(&self.retirement_ledger);
    }

    pub(super) fn completion_wake(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.completion_wake)
    }
    /// A retained current/archive continuation is itself demand on its exact room/peer port.
    /// Port request generations describe external wakes; an independent clean exchange may
    /// consume one while this continuation is between bounded slices. Do not let that scalar
    /// acknowledgement strand work whose ownership is still here.
    pub(super) fn needs_port(&self, room: Digest32, peer: Digest32) -> bool {
        self.ready
            .iter()
            .flatten()
            .any(|flow| flow.room == room && flow.peer == peer)
            || self
                .deferred
                .iter()
                .any(|flow| flow.room == room && flow.peer == peer)
            || self
                .required
                .iter()
                .any(|required| required.room == room && required.peer == peer)
            || self
                .foreground_admission
                .iter()
                .flatten()
                .any(|admission| admission.room == room && admission.peer == peer)
            || self.secret_admission.contains_key(&(room, peer))
            || self.byte_admission.contains_key(&(room, peer))
            || self.pool_admission.contains_key(&(room, peer))
    }

    fn cancel_archive_admission(&mut self) {
        if let Some(admission) = self.archive_admission.take() {
            admission.task.abort();
        }
    }
    pub(super) fn release_archive_admission(&mut self, token: u64, room: Digest32, peer: Digest32) {
        if self.archive_admission.as_ref().is_some_and(|admission| {
            admission.token == token && admission.room == room && admission.peer == peer
        }) {
            self.cancel_archive_admission();
        }
    }
    fn cancel_foreground_admission(&mut self, index: usize) {
        if let Some(admission) = self.foreground_admission[index].take() {
            admission.task.abort();
        }
    }
    fn cancel_foreground_port(&mut self, room: Digest32, peer: Digest32) {
        for index in 0..self.foreground_admission.len() {
            if self.foreground_admission[index]
                .as_ref()
                .is_some_and(|admission| admission.room == room && admission.peer == peer)
            {
                self.cancel_foreground_admission(index);
            }
        }
    }
    pub(super) fn release_foreground_admission(
        &mut self,
        token: u64,
        room: Digest32,
        peer: Digest32,
    ) {
        for index in 0..self.foreground_admission.len() {
            if self.foreground_admission[index]
                .as_ref()
                .is_some_and(|admission| {
                    admission.token == token && admission.room == room && admission.peer == peer
                })
            {
                self.cancel_foreground_admission(index);
                return;
            }
        }
    }
    fn cancel_secret_admission(&mut self, room: Digest32, peer: Digest32) {
        if let Some(admission) = self.secret_admission.remove(&(room, peer)) {
            admission.task.abort();
        }
    }
    pub(super) fn release_secret_admission(
        &mut self,
        token: u64,
        room: Digest32,
        peer: Digest32,
    ) -> bool {
        if self
            .secret_admission
            .get(&(room, peer))
            .is_some_and(|admission| admission.token == token)
        {
            self.cancel_secret_admission(room, peer);
            true
        } else {
            false
        }
    }
    fn wait_for_secret(
        &mut self,
        net_tx: &mpsc::Sender<NetEvent>,
        next_token: &mut u64,
        room: Digest32,
        peer: Digest32,
        work: AdmissionWork,
        secret_work: Arc<tokio::sync::RwLock<()>>,
    ) {
        if self.secret_admission.contains_key(&(room, peer)) {
            return;
        }
        let token = *next_token;
        *next_token += 1;
        let tx = net_tx.clone();
        let task = tokio::spawn(async move {
            let guard = secret_work.read_owned().await;
            drop(guard);
            let _ = tx
                .send(NetEvent::BoundedSecretReady { token, room, peer })
                .await;
        });
        self.secret_admission.insert(
            (room, peer),
            SecretAdmission {
                token,
                root: work.root,
                lane: work.lane,
                task,
            },
        );
    }
    fn cancel_byte_admission(&mut self, room: Digest32, peer: Digest32) {
        if let Some(admission) = self.byte_admission.remove(&(room, peer)) {
            admission.task.abort();
        }
    }
    pub(super) fn release_byte_admission(
        &mut self,
        token: u64,
        room: Digest32,
        peer: Digest32,
    ) -> Option<bool> {
        if self
            .byte_admission
            .get(&(room, peer))
            .is_some_and(|admission| admission.token == token)
        {
            let record = self.byte_admission.get(&(room, peer))?.owner.is_some();
            if record && !self.record_bytes_blocked(room, peer) {
                return None;
            }
            self.cancel_byte_admission(room, peer);
            Some(record)
        } else {
            None
        }
    }
    fn record_bytes_blocked(&mut self, room: Digest32, peer: Digest32) -> bool {
        let Some(owner) = self.byte_admission.get(&(room, peer)).and_then(|a| a.owner) else {
            return false;
        };
        let retained = self
            .ready
            .iter()
            .filter_map(Option::as_ref)
            .chain(self.deferred.iter())
            .any(|flow| flow.room == room && flow.peer == peer && ByteOwner::of(flow) == owner);
        if !retained {
            // A retired room/generation must not park its replacement behind an old release.
            self.cancel_byte_admission(room, peer);
        }
        retained
    }
    fn take_superseded_byte_hint(
        &mut self,
        room: Digest32,
        peer: Digest32,
        inbox: &stream::HintInbox,
    ) -> Option<(Flow, u64)> {
        let admission = self.byte_admission.get(&(room, peer))?;
        let owner = admission.owner?;
        let port_request = admission.port_request?;
        let superseded = |flow: &Flow| {
            flow.room == room
                && flow.peer == peer
                && ByteOwner::of(flow) == owner
                && !flow.archive
                && flow.archive_request.is_none()
                && flow.required_root.is_none()
                && flow.hint.is_some_and(|hint| {
                    inbox.newer_pending(room, flow.hint_peer, hint.author, hint.size)
                })
        };
        // Only the exact byte waiter's parked hinted owner can be replaced. Archive and
        // required roots, other ports and replacement generations keep their continuations.
        let flow = if let Some(index) = self
            .ready
            .iter()
            .position(|slot| slot.as_ref().is_some_and(superseded))
        {
            self.ready[index].take()?
        } else {
            let index = self.deferred.iter().position(superseded)?;
            self.deferred.remove(index)?
        };
        // No await occurs between identity selection and cancellation. A queued old ready
        // event cannot consume a future replacement, because its unique token no longer exists.
        self.cancel_byte_admission(room, peer);
        Some((flow, port_request))
    }
    fn wait_for_bytes(
        &mut self,
        net_tx: &mpsc::Sender<NetEvent>,
        next_token: &mut u64,
        room: Digest32,
        peer: Digest32,
        work: AdmissionWork,
        waiting: ByteWait,
    ) {
        if self.byte_admission.contains_key(&(room, peer)) {
            return;
        }
        let token = *next_token;
        *next_token += 1;
        let tx = net_tx.clone();
        let ByteWait {
            wake,
            owner,
            port_request,
        } = waiting;
        let task = tokio::spawn(async move {
            wake.await;
            let _ = tx
                .send(NetEvent::BoundedBytesReady { token, room, peer })
                .await;
        });
        self.byte_admission.insert(
            (room, peer),
            ByteAdmission {
                token,
                root: work.root,
                lane: work.lane,
                owner,
                port_request,
                task,
            },
        );
    }

    pub(super) fn cancel_pool_admission(&mut self, room: Digest32, peer: Digest32) {
        self.pool_admission.remove(&(room, peer));
    }

    /// A real connection-close edge retires every exact continuation for that peer before the
    /// scheduler publishes or considers other work. Return the rooms whose parked Flows remain
    /// owned and must be reconsidered after reach/reconnect.
    pub(super) fn cancel_peer_pool_admissions(&mut self, peer: Digest32) -> BTreeSet<Digest32> {
        let waiting: Vec<(Digest32, Digest32)> = self
            .pool_admission
            .keys()
            .filter(|(_, waiting_peer)| *waiting_peer == peer)
            .copied()
            .collect();
        let rooms = waiting.iter().map(|(room, _)| *room).collect();
        for (room, peer) in waiting {
            self.cancel_pool_admission(room, peer);
        }
        rooms
    }

    pub(super) fn accept_pool_release(
        &mut self,
        release: crate::node::history_budget::FlowRelease,
    ) -> bool {
        let Some(admission) = self.pool_admission.get_mut(&(release.room, release.peer)) else {
            return false;
        };
        if admission.token != release.token
            || admission.ticket.sequence() != release.order
            || !admission.ticket.granted()
        {
            return false;
        }
        admission.handed_off = true;
        true
    }

    pub(super) fn pool_admission_blocked(&self, room: Digest32, peer: Digest32) -> bool {
        self.pool_admission
            .get(&(room, peer))
            .is_some_and(|admission| !admission.handed_off)
    }

    /// Rooms whose exact parked Flow is retained until its source-owned release edge. This is
    /// the actor-owned half of the flow-state snapshot rendered under `lanes`; health diagnosis
    /// consumes the same ownership rather than inferring a cause from a pool count.
    pub(super) fn retained_pool_rooms(&self) -> std::collections::BTreeSet<Digest32> {
        self.pool_admission.keys().map(|(room, _)| *room).collect()
    }

    fn wait_for_pool(
        &mut self,
        next_token: &mut u64,
        room: Digest32,
        peer: Digest32,
        waiting: PoolWait,
        job: &crate::node::history_budget::Job,
        refused_at: &crate::node::history_budget::FlowReleaseEdge,
    ) -> Result<(), crate::node::history_budget::FlowWaitError> {
        if self.pool_admission.contains_key(&(room, peer)) {
            return Ok(());
        }
        let token = *next_token;
        *next_token += 1;
        let ticket = job.flow_wait_ticket(
            room,
            peer,
            waiting.request,
            waiting.instance,
            token,
            refused_at,
        )?;
        self.pool_admission.insert(
            (room, peer),
            PoolAdmission {
                token,
                gate: waiting.gate,
                root: waiting.work.root,
                lane: waiting.work.lane,
                ticket,
                handed_off: false,
            },
        );
        Ok(())
    }
    /// Retiring work stays inside the same twelve-flow limit and retains its charge/lease.
    /// Other rooms may progress while one room waits for its next bounded cleanup slice.
    fn flow_count(&self) -> usize {
        self.ready.iter().flatten().count()
            + self.running.iter().flatten().count()
            + self.deferred.len()
            + self.retiring.len()
            + usize::from(self.cleanup.is_some())
    }
    fn dispose(&mut self, flow: Flow) {
        // Exclusive ownership moves to the retirement queue. Its only permitted next work is
        // Flow::retire_slice's exact local cleanup; that slice cancels every capability before
        // returning. Controller::fence still cancels queued cleanup immediately on node lock.
        self.retiring.push_back(flow);
        self.poll_cleanup();
    }
    fn poll_cleanup(&mut self) {
        if let Some(cleanup) = &self.cleanup {
            if !cleanup.task.is_finished() {
                return;
            }
            let result = cleanup
                .result
                .lock()
                .ok()
                .and_then(|mut value| value.take());
            let flow = cleanup
                .flow
                .try_lock()
                .ok()
                .and_then(|mut flow| flow.take());
            let Some(cleanup) = self.cleanup.take() else {
                return;
            };
            if let Some(flow) = flow {
                let key = retirement_key(&flow);
                match result.unwrap_or(Err(crate::error::Error::Profile(
                    "history retirement worker stopped",
                ))) {
                    Ok(true) => clear_retirement_error(&self.retirement_ledger, key),
                    Ok(false) => {
                        self.retiring.push_back(flow);
                    }
                    Err(error) => {
                        eprintln!("vox: history retirement is pending: {error}");
                        note_retirement_error(&self.retirement_ledger, key, &error.to_string());
                        self.retiring.push_back(flow);
                    }
                }
            } else {
                note_retirement_error(
                    &self.retirement_ledger,
                    cleanup.key,
                    "history retirement owner unavailable",
                );
            }
        }
        if self.cleanup.is_some() {
            return;
        }
        let awaited_publications = self
            .ready
            .iter()
            .flatten()
            .chain(self.deferred.iter())
            .chain(self.retiring.iter())
            .filter_map(|flow| {
                flow.publication_owner_wait()
                    .map(|owner| (flow.room, owner))
            })
            .collect::<Vec<_>>();
        // First run an exact owner named by any parked/retiring waiter. Otherwise run the oldest
        // retirement that is not itself publication-blocked. Cleanup is off-actor and joins the
        // room mutex FIFO for one bounded local slice; a live Flow in the room no longer forbids
        // cleanup and therefore cannot pin all twelve retained positions forever.
        let owner = self.retiring.iter().position(|candidate| {
            awaited_publications.iter().any(|(waiting_room, owner)| {
                *waiting_room == candidate.room && candidate.owns_request(*owner)
            })
        });
        let Some(at) = owner.or_else(|| {
            self.retiring
                .iter()
                .position(|candidate| candidate.publication_owner_wait().is_none())
        }) else {
            return;
        };
        let Some(flow) = self.retiring.remove(at) else {
            return;
        };
        let cancellations = flow.cancellation_handles();
        let key = retirement_key(&flow);
        let flow = Arc::new(tokio::sync::Mutex::new(Some(flow)));
        let result = Arc::new(StdMutex::new(None));
        let task_flow = Arc::clone(&flow);
        let output = result.clone();
        let wake = self.completion_wake();
        let task = tokio::spawn(async move {
            let outcome = {
                let mut flow = task_flow.lock().await;
                match flow.as_mut() {
                    Some(flow) => flow.retire_slice().await,
                    None => Err(crate::error::Error::Profile(
                        "history retirement owner vanished",
                    )),
                }
            };
            if let Ok(mut result) = output.lock() {
                *result = Some(outcome);
            }
            wake.notify_one();
        });
        self.cleanup = Some(Cleanup {
            key,
            flow,
            result,
            task,
            cancellations,
        });
    }
    async fn join_cleanup(&mut self) -> crate::error::Result<()> {
        if let Some(cleanup) = self.cleanup.take() {
            let key = cleanup.key;
            let joined = cleanup.task.await;
            let result = cleanup
                .result
                .lock()
                .ok()
                .and_then(|mut value| value.take());
            let flow = cleanup.flow.lock().await.take();
            if let Some(flow) = flow {
                let key = retirement_key(&flow);
                match result.unwrap_or_else(|| {
                    Err(crate::error::Error::Profile(if joined.is_err() {
                        "history retirement worker stopped"
                    } else {
                        "history retirement result vanished"
                    }))
                }) {
                    Ok(true) => clear_retirement_error(&self.retirement_ledger, key),
                    Ok(false) => self.retiring.push_back(flow),
                    Err(error) => {
                        note_retirement_error(&self.retirement_ledger, key, &error.to_string());
                        self.retiring.push_back(flow);
                        return Err(error);
                    }
                }
            } else {
                note_retirement_error(
                    &self.retirement_ledger,
                    key,
                    "history retirement owner vanished",
                );
                return Err(crate::error::Error::Profile(
                    "history retirement owner vanished",
                ));
            }
        }
        Ok(())
    }
    pub(super) async fn retire_room(&mut self, room: Digest32) -> crate::error::Result<()> {
        if self
            .archive_admission
            .as_ref()
            .is_some_and(|admission| admission.room == room)
        {
            self.cancel_archive_admission();
        }
        for index in 0..self.foreground_admission.len() {
            if self.foreground_admission[index]
                .as_ref()
                .is_some_and(|admission| admission.room == room)
            {
                self.cancel_foreground_admission(index);
            }
        }
        let waiting: Vec<(Digest32, Digest32)> = self
            .secret_admission
            .keys()
            .filter(|(waiting_room, _)| *waiting_room == room)
            .copied()
            .collect();
        for (room, peer) in waiting {
            self.cancel_secret_admission(room, peer);
        }
        let waiting: Vec<(Digest32, Digest32)> = self
            .byte_admission
            .keys()
            .filter(|(waiting_room, _)| *waiting_room == room)
            .copied()
            .collect();
        for (room, peer) in waiting {
            self.cancel_byte_admission(room, peer);
        }
        let waiting: Vec<(Digest32, Digest32)> = self
            .pool_admission
            .keys()
            .filter(|(waiting_room, _)| *waiting_room == room)
            .copied()
            .collect();
        for (room, peer) in waiting {
            self.cancel_pool_admission(room, peer);
        }
        for slot in &mut self.ready {
            if let Some(flow) = slot.take_if(|flow| flow.room == room) {
                self.retiring.push_back(flow);
            }
        }
        let mut keep = VecDeque::new();
        while let Some(flow) = self.deferred.pop_front() {
            if flow.room == room {
                self.retiring.push_back(flow);
            } else {
                keep.push_back(flow);
            }
        }
        self.deferred = keep;
        for slot in &mut self.running {
            if let Some(work) = slot.take_if(|work| work.room == room) {
                work.fence.retire();
                let _ = work.task.await;
                if let Some(flow) = work.flow.lock().await.take() {
                    self.retiring.push_back(flow);
                }
            }
        }
        self.required.retain(|required| required.room != room);
        self.join_cleanup().await?;
        while let Some(at) = self.retiring.iter().position(|flow| flow.room == room) {
            let Some(mut flow) = self.retiring.remove(at) else {
                return Err(crate::error::Error::Profile(
                    "retiring history flow vanished",
                ));
            };
            match flow.retire_slice().await {
                Ok(true) => {}
                Ok(false) => {
                    self.retiring.push_back(flow);
                    tokio::time::sleep(crate::node::history_budget::RETIRE_RETRY_BACKOFF).await;
                }
                Err(error) => {
                    self.retiring.push_back(flow);
                    return Err(error);
                }
            }
        }
        self.poll_cleanup();
        Ok(())
    }

    pub(super) fn archive_for_port(
        &self,
        room: Digest32,
        peer: Digest32,
    ) -> Option<(stream::RequestId, Digest32)> {
        self.ready
            .iter()
            .flatten()
            .find(|flow| flow.room == room && flow.peer == peer && flow.archive)
            .and_then(|flow| {
                flow.archive_request
                    .map(|request| (request, flow.generation))
            })
            .or_else(|| {
                self.archive_admission.as_ref().and_then(|admission| {
                    (admission.room == room && admission.peer == peer)
                        .then_some((admission.request, admission.generation))
                })
            })
            .or_else(|| {
                self.running
                    .iter()
                    .flatten()
                    .find(|work| work.room == room && work.peer == peer && work.archive.is_some())
                    .and_then(|work| work.archive)
            })
    }

    pub(super) fn retire_port(&mut self, room: Digest32, peer: Digest32) {
        if self
            .archive_admission
            .as_ref()
            .is_some_and(|admission| admission.room == room && admission.peer == peer)
        {
            self.cancel_archive_admission();
        }
        self.cancel_foreground_port(room, peer);
        self.cancel_secret_admission(room, peer);
        self.cancel_byte_admission(room, peer);
        self.cancel_pool_admission(room, peer);
        for slot in &mut self.ready {
            if slot
                .as_ref()
                .is_some_and(|flow| flow.room == room && flow.peer == peer)
            {
                if let Some(flow) = slot.take() {
                    self.retiring.push_back(flow);
                }
            }
        }
        for running in self
            .running
            .iter()
            .flatten()
            .filter(|r| r.room == room && r.peer == peer)
        {
            running.fence.retire();
        }
        let mut keep = VecDeque::new();
        while let Some(flow) = self.deferred.pop_front() {
            if flow.room == room && flow.peer == peer {
                self.retiring.push_back(flow);
            } else {
                keep.push_back(flow);
            }
        }
        self.deferred = keep;
        self.required
            .retain(|required| required.room != room || required.peer != peer);
        self.poll_cleanup();
    }
    pub(super) fn fence(&mut self) {
        self.cancel_archive_admission();
        for index in 0..self.foreground_admission.len() {
            self.cancel_foreground_admission(index);
        }
        for (_, admission) in std::mem::take(&mut self.secret_admission) {
            admission.task.abort();
        }
        for (_, admission) in std::mem::take(&mut self.byte_admission) {
            admission.task.abort();
        }
        self.pool_admission.clear();
        for flow in self
            .deferred
            .iter()
            .chain(self.ready.iter().flatten())
            .chain(self.retiring.iter())
        {
            flow.cancel();
        }
        if let Some(cleanup) = &self.cleanup {
            for cancellation in &cleanup.cancellations {
                cancellation.cancel();
            }
        }
        for work in self.running.iter().flatten() {
            work.fence.retire();
        }
    }
    pub(super) async fn retire(&mut self) {
        self.fence();
        for slot in &mut self.ready {
            if let Some(flow) = slot.take() {
                self.retiring.push_back(flow);
            }
        }
        self.retiring.extend(self.deferred.drain(..));
        self.required.clear();
        for slot in &mut self.running {
            if let Some(work) = slot.take() {
                let joined = work.task.await;
                if joined.is_err() {
                    eprintln!("vox: bounded history supervisor stopped during retirement");
                }
                if let Some(flow) = work.flow.lock().await.take() {
                    self.retiring.push_back(flow);
                }
            }
        }
        if let Err(error) = self.join_cleanup().await {
            eprintln!("vox: history retirement is pending: {error}");
        }
        while let Some(mut flow) = self.retiring.pop_front() {
            // lock_all has already erased room SEK. Such work exits without writes;
            // bounded reopen recovery owns any durable cursor/publication still present.
            // Memory admission may still be held by a fenced actual worker. Keep this
            // owner until a later bounded slice observes the erased key.
            match flow.retire_slice().await {
                Ok(true) => clear_retirement_error(&self.retirement_ledger, retirement_key(&flow)),
                Ok(false) => {
                    self.retiring.push_back(flow);
                    tokio::time::sleep(crate::node::history_budget::RETIRE_RETRY_BACKOFF).await;
                }
                Err(error) => {
                    eprintln!("vox: history retirement is pending: {error}");
                    note_retirement_error(
                        &self.retirement_ledger,
                        retirement_key(&flow),
                        &error.to_string(),
                    );
                    // A permanent local error must not hold lock/unlock or shutdown forever.
                    // Ownership moves to the daemon runtime, which keeps retrying under the
                    // named policy while the stable status ledger remains visible.
                    spawn_owed_retirement(flow, Arc::clone(&self.retirement_ledger));
                }
            }
        }
    }

    pub(super) fn cancel_archive(
        &mut self,
        room: Digest32,
        instance: [u8; 16],
        request: stream::RequestId,
    ) {
        if self.archive_admission.as_ref().is_some_and(|admission| {
            admission.room == room && admission.instance == instance && admission.request == request
        }) {
            self.cancel_archive_admission();
        }
        if self.ready[1].as_ref().is_some_and(|flow| {
            flow.room == room && flow.instance == instance && flow.archive_request == Some(request)
        }) {
            self.cancel_archive_admission();
            if let Some(flow) = self.ready[1].take() {
                self.dispose(flow);
            }
        }
        if let Some(work) = self.running[1].as_ref().filter(|work| {
            work.room == room
                && work
                    .archive
                    .is_some_and(|(running_request, _)| running_request == request)
        }) {
            work.fence.retire();
        }
    }

    // The queue ticket binds one exact node, room, peer and retained request.
    #[allow(clippy::too_many_arguments)]
    fn archive_turn(
        &mut self,
        budget: &Arc<crate::node::history_budget::Budget>,
        net_tx: &mpsc::Sender<NetEvent>,
        next_token: &mut u64,
        node: Digest32,
        room: Digest32,
        peer: Digest32,
        request: stream::RequestId,
        generation: Digest32,
        instance: [u8; 16],
    ) -> ArchiveTurn {
        if self.archive_admission.as_ref().is_some_and(|admission| {
            admission.room != room
                || admission.peer != peer
                || admission.request != request
                || admission.generation != generation
                || admission.instance != instance
        }) {
            self.cancel_archive_admission();
        }
        if let Some(mut admission) = self.archive_admission.take() {
            // Register again before rechecking. The event that scheduled this actor may have been
            // a same-lane eligibility edge won by another ticket; the later real release still
            // needs an enabled listener owned by this exact retained admission.
            let wake = admission.ticket.wake();
            if let Some(job) = admission.ticket.try_admit() {
                admission.task.abort();
                return ArchiveTurn::Ready(job);
            }
            admission.task.abort();
            let tx = net_tx.clone();
            let wake_token = *next_token;
            *next_token += 1;
            admission.token = wake_token;
            admission.task = tokio::spawn(async move {
                wake.await;
                let _ = tx
                    .send(NetEvent::ArchiveAdmissionReady {
                        token: wake_token,
                        room,
                        peer,
                    })
                    .await;
            });
            self.archive_admission = Some(admission);
            return ArchiveTurn::Waiting;
        }

        let mut ticket = budget.enqueue(node, crate::node::history_budget::Lane::Archive);
        let wake = ticket.wake();
        if let Some(job) = ticket.try_admit() {
            return ArchiveTurn::Ready(job);
        }
        let tx = net_tx.clone();
        let wake_token = *next_token;
        *next_token += 1;
        let task = tokio::spawn(async move {
            wake.await;
            let _ = tx
                .send(NetEvent::ArchiveAdmissionReady {
                    token: wake_token,
                    room,
                    peer,
                })
                .await;
        });
        self.archive_admission = Some(ArchiveAdmission {
            token: wake_token,
            room,
            peer,
            request,
            generation,
            instance,
            ticket,
            task,
        });
        ArchiveTurn::Waiting
    }

    /// Retain an exact foreground queue position until its capacity family changes. A pending
    /// ticket belongs to its original port; another port cannot steal or cancel it while the
    /// actor happens to visit that port first.
    #[allow(clippy::too_many_arguments)]
    fn foreground_turn(
        &mut self,
        budget: &Arc<crate::node::history_budget::Budget>,
        net_tx: &mpsc::Sender<NetEvent>,
        next_token: &mut u64,
        node: Digest32,
        room: Digest32,
        peer: Digest32,
        root: &'static str,
        lane: crate::node::history_budget::Lane,
    ) -> ForegroundTurn {
        let index = lane.index();
        if let Some(admission) = self.foreground_admission[index].as_ref() {
            if admission.room != room || admission.peer != peer || admission.lane != lane {
                return ForegroundTurn::Waiting;
            }
        }
        if let Some(mut admission) = self.foreground_admission[index].take() {
            let wake = admission.ticket.wake();
            if let Some(job) = admission.ticket.try_admit() {
                admission.task.abort();
                return ForegroundTurn::Ready(job);
            }
            admission.task.abort();
            let tx = net_tx.clone();
            let wake_token = *next_token;
            *next_token += 1;
            admission.token = wake_token;
            admission.task = tokio::spawn(async move {
                wake.await;
                let _ = tx
                    .send(NetEvent::ForegroundAdmissionReady {
                        token: wake_token,
                        room,
                        peer,
                    })
                    .await;
            });
            self.foreground_admission[index] = Some(admission);
            return ForegroundTurn::Waiting;
        }

        let mut ticket = budget.enqueue(node, lane);
        let wake = ticket.wake();
        if let Some(job) = ticket.try_admit() {
            return ForegroundTurn::Ready(job);
        }
        let tx = net_tx.clone();
        let wake_token = *next_token;
        *next_token += 1;
        let task = tokio::spawn(async move {
            wake.await;
            let _ = tx
                .send(NetEvent::ForegroundAdmissionReady {
                    token: wake_token,
                    room,
                    peer,
                })
                .await;
        });
        self.foreground_admission[index] = Some(ForegroundAdmission {
            token: wake_token,
            room,
            peer,
            root,
            lane,
            ticket,
            task,
        });
        ForegroundTurn::Waiting
    }
}
/// Why a foreground round runs (ADR-038 FX-15, #996), from what selected it: the own head
/// offered for acknowledgement, a head the peer told this node of (or the follow-up such a
/// fetch needs), an own append owed to the peer, the periodic request, or another request.
fn foreground_reason(
    node: Digest32,
    hint: Option<stream::HeadHint>,
    required: bool,
    announce_owed: bool,
    periodic_pending: bool,
) -> crate::node::status::RoundReason {
    use crate::node::status::RoundReason;
    match hint {
        Some(hint) if hint.author == node => RoundReason::Offer,
        Some(_) => RoundReason::Hint,
        None if required => RoundReason::Hint,
        None if announce_owed => RoundReason::Announce,
        None if periodic_pending => RoundReason::Periodic,
        None => RoundReason::Request,
    }
}

impl Node {
    /// Name the exact bounded root whose next attempt is stopped before a `Flow` exists. This
    /// mirrors the starter's selection order so status can identify a retained admission rather
    /// than reporting only that some port is waiting.
    pub(super) fn bounded_pending_identity(&self, room: Digest32, peer: Digest32) -> AdmissionWork {
        if let Some(flow) = self
            .bounded_sync
            .ready
            .iter()
            .flatten()
            .chain(self.bounded_sync.deferred.iter())
            .find(|flow| flow.room == room && flow.peer == peer)
        {
            return AdmissionWork::from_flow(flow);
        }
        if self
            .ports
            .get(&(room, peer))
            .is_some_and(crate::node::ports::Port::announce_owed)
        {
            return AdmissionWork {
                root: "inventory",
                lane: crate::node::history_budget::Lane::Control,
            };
        }
        if self.history_demand.ready_binding(room, peer).is_some() {
            return AdmissionWork {
                root: "archive",
                lane: crate::node::history_budget::Lane::Archive,
            };
        }
        if self
            .bounded_sync
            .required
            .iter()
            .any(|required| required.room == room && required.peer == peer)
        {
            return AdmissionWork {
                root: "required",
                lane: crate::node::history_budget::Lane::Control,
            };
        }
        if self
            .leave_waiters
            .iter()
            .any(|(left_room, generation, _, _)| {
                *left_room == room
                    && self
                        .ports
                        .get(&(room, peer))
                        .is_some_and(|port| port.done_gen >= *generation)
            })
        {
            return AdmissionWork {
                root: "departure",
                lane: crate::node::history_budget::Lane::Control,
            };
        }
        if self.history_hints.pending(room, peer) {
            return AdmissionWork {
                root: "hint",
                lane: crate::node::history_budget::Lane::Control,
            };
        }
        AdmissionWork {
            root: "inventory",
            lane: crate::node::history_budget::Lane::Control,
        }
    }

    /// Retire every operation for a departed member except an already decoded
    /// `Control/Head(peer)` response. That response is bounded by its existing fence and
    /// deadline and can return only the peer's own semantic departure receipt.
    pub(super) fn retire_departed_port(&mut self, room: Digest32, peer: Digest32) {
        let keep_receipt = self.ports.get(&(room, peer)).is_some_and(|port| {
            port.inbound
                .values()
                .any(|attempt| attempt.is_departure_receipt())
        });
        if !keep_receipt {
            if self.ports.contains_key(&(room, peer)) {
                self.drop_port(&room, &peer);
            }
            return;
        }

        self.bounded_sync.retire_port(room, peer);
        self.history_hints.retire_port(room, peer);
        let mut retired = Vec::new();
        if let Some(port) = self.ports.get_mut(&(room, peer)) {
            if let Some(attempt) = port.out.take() {
                retired.push(attempt);
            }
            let ordinary: Vec<_> = port
                .inbound
                .iter()
                .filter_map(|(token, attempt)| (!attempt.is_departure_receipt()).then_some(*token))
                .collect();
            for token in ordinary {
                if let Some(attempt) = port.inbound.remove(&token) {
                    retired.push(attempt);
                }
            }
            port.queued = false;
            port.poisoned = true;
        }
        for attempt in retired {
            attempt.retire();
        }
        self.port_queue.remove(&room, &peer);
    }

    /// Retire bounded workers for `room` and release the exact actor attempts they owned.
    /// The controller removes a running work item before awaiting it, so its ordinary
    /// completion can no longer reach `accept_bounded_sync` to take the matching port token.
    /// Capture those tokens first and clear them after the worker lifetime ends, including
    /// the cleanup-error path; unrelated inbound and later attempts keep their own tokens.
    pub(super) async fn retire_bounded_room(&mut self, room: Digest32) -> crate::error::Result<()> {
        let attempts: Vec<_> = self
            .bounded_sync
            .running
            .iter()
            .flatten()
            .filter(|work| work.room == room)
            .map(|work| (work.peer, work.token))
            .collect();
        let result = self.bounded_sync.retire_room(room).await;
        for (peer, token) in attempts {
            if let Some(attempt) = self
                .ports
                .get_mut(&(room, peer))
                .and_then(|port| port.take(token))
            {
                attempt.retire();
            }
        }
        result
    }

    /// A flow whose start ended before its round retains the exact work already consumed while
    /// constructing it: an archive dispatch, required dependency, or scalar hint. Park it in its
    /// lane so the relevant admission/release event retries that same work; reconstructing only a
    /// hint loses the other two forms and can leave a shipped archive request marked running.
    fn shelve_exact(&mut self, mut flow: Flow, index: usize) {
        flow.park();
        debug_assert!(self.bounded_sync.ready[index].is_none());
        self.bounded_sync.ready[index] = Some(flow);
    }

    /// Abandoning a flow retires its local capabilities, not the unauthoritative scalar hint it
    /// selected. Re-arm that exact hint while its inbox scope is still live; room/peer retirement
    /// removes it first, making this a no-op for teardown rather than leaving an in-flight orphan.
    fn dispose_rearming_hint(&mut self, mut flow: Flow) {
        if let Some(hint) = flow.hint.take() {
            self.history_hints
                .retry(flow.room, flow.hint_peer, hint.author, hint.head);
        }
        self.bounded_sync.dispose(flow);
    }

    /// Resume the exact retained Flow that owns a durable room publication. A waiter knows the
    /// request identity from disk; routing that causal edge to the owner's port avoids both a
    /// room-wide wake storm and retrying the waiter while the only productive Flow sleeps.
    fn wake_publication_owner(&mut self, room: Digest32, owner: RequestId) {
        let mut peer = None;
        if let Some(flow) = self
            .bounded_sync
            .ready
            .iter_mut()
            .flatten()
            .find(|flow| flow.room == room && flow.owns_request(owner))
        {
            flow.waiting = false;
            peer = Some(flow.peer);
        } else if let Some(at) = self
            .bounded_sync
            .deferred
            .iter()
            .position(|flow| flow.room == room && flow.owns_request(owner))
        {
            if let Some(mut flow) = self.bounded_sync.deferred.remove(at) {
                flow.waiting = false;
                peer = Some(flow.peer);
                if let Some(displaced) = self.bounded_sync.ready[0].replace(flow) {
                    self.bounded_sync.deferred.push_front(displaced);
                }
            }
        }
        if let Some(peer) = peer {
            if let Some(port) = self.ports.get_mut(&(room, peer)) {
                port.raise();
                port.clear_backoff();
            }
            crate::node::status::SyncBook::with(&self.sync_book, room, peer, |counts| {
                counts.backoff = None;
            });
            self.sched_rooms.insert(room);
        }
        // When the exact owner is retiring, its next cleanup slice rolls back or completes the
        // publication. poll_cleanup recognizes the live waiter's owner edge and admits it even
        // though another Flow in the same room remains retained.
        self.bounded_sync.poll_cleanup();
    }

    pub(super) fn accept_bounded_sync(&mut self) {
        self.bounded_sync.poll_cleanup();
        for index in 0..crate::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS {
            let Some(work) = self.bounded_sync.running[index].as_ref() else {
                continue;
            };
            let returned = match work.result.try_lock() {
                Ok(mut result) => result.take(),
                Err(_) => None,
            };
            let Some(mut returned) = returned else {
                continue;
            };
            let flow = work.flow.try_lock().ok().and_then(|mut flow| flow.take());
            let Some(flow) = flow else {
                if let Ok(mut result) = work.result.lock() {
                    *result = Some(returned);
                }
                continue;
            };
            let Some(work) = self.bounded_sync.running[index].take() else {
                self.dispose_rearming_hint(flow);
                continue;
            };
            let mut flow = flow;
            if let Some(panic) = returned.panic.take() {
                returned.error = Some(format!("bounded history worker panicked: {panic}"));
            }
            // These facts were committed by the worker before it returned. Account for them
            // before deciding whether its attempt is still current: cancellation, retirement,
            // an error after the store callback, or a newer scalar head must not turn durable
            // work into a false zero in the user-visible lane.
            let fetched = u64::from(
                flow.work_committed
                    .swap(false, std::sync::atomic::Ordering::AcqRel),
            );
            let declined = std::mem::take(&mut flow.declined);
            let offered = std::mem::take(&mut flow.offered);
            let rearmed = std::mem::take(&mut flow.rearmed);
            let refusal_stale = flow.refusal_stale.take();
            let refusal_saved = flow.refusal_saved.take();
            if fetched != 0
                || declined != 0
                || offered != 0
                || rearmed != 0
                || refusal_stale.is_some()
                || refusal_saved.is_some()
            {
                crate::node::status::SyncBook::with(
                    &self.sync_book,
                    work.room,
                    work.peer,
                    |counts| {
                        counts.history_fetched = counts.history_fetched.saturating_add(fetched);
                        counts.history_declined = counts.history_declined.saturating_add(declined);
                        counts.history_offered = counts.history_offered.saturating_add(offered);
                        counts.history_rearmed = counts.history_rearmed.saturating_add(rearmed);
                        if refusal_stale.is_some() {
                            counts.history_refusal_stale = refusal_stale;
                        }
                        if refusal_saved.is_some() {
                            counts.history_refusal_saved = refusal_saved;
                        }
                    },
                );
            }
            let current = self
                .ports
                .get_mut(&(work.room, work.peer))
                .and_then(|port| port.take(work.token))
                .is_some();
            let valid = current
                && !work.fence.is_retired()
                && self
                    .channels
                    .get(&work.room)
                    .is_some_and(|room| Arc::ptr_eq(room, &flow.shared));
            // Authorization and local-durability exits carry ownership themselves. Handle them
            // even when the trust edit also retired the port/fence; generic stale disposal would
            // otherwise discard the only hint, required root, or archive controller dispatch.
            if flow.authorization_changed || flow.local_retry.is_some() {
                if let Some(seq) = flow.mine_held.take() {
                    self.held_notes.push((work.room, work.peer, seq));
                }
                if flow.admitted_authors > 0 {
                    flow.admitted_authors = 0;
                    let _ = self.net_tx.try_send(NetEvent::BoardGrew {
                        channel_id: work.room,
                    });
                }
                if flow.published {
                    flow.published = false;
                    if flow.governance {
                        self.governance_work.wake_room(work.room);
                    } else {
                        self.governance_work.pending = true;
                    }
                    self.key_package_rooms.entry(work.room).or_insert(false);
                    let _ = self.net_tx.try_send(NetEvent::BoundedRoomAdvanced {
                        channel_id: work.room,
                        rendered: flow.rendered,
                        governance: flow.governance,
                    });
                    if let Some(archive) = self.bounded_sync.ready[1].as_mut() {
                        archive.waiting = false;
                        self.sched_rooms.insert(archive.room);
                    }
                }
                if let Some((head, seq)) = flow.external.take() {
                    let need = RequiredOwner {
                        room: work.room,
                        peer: work.peer,
                        head,
                        seq,
                        request: flow.retirement_request(),
                        instance: flow.instance,
                    };
                    if !self.bounded_sync.required.contains(&need) {
                        self.bounded_sync.required.push_back(need);
                    }
                }
            }
            if flow.authorization_changed {
                let retry_peer = flow.route_origin.unwrap_or(flow.hint_peer);
                let archive = flow.archive_request.map(|request| {
                    self.history_demand.failed(
                        request,
                        flow.generation,
                        "Authorization changed while this history page was running; the exact request is being resumed.",
                    );
                    (request, flow.instance)
                });
                if let Some(hint) = flow.hint {
                    self.history_hints
                        .retry(work.room, flow.hint_peer, hint.author, hint.head);
                }
                if let Some((head, seq)) = flow.required_root {
                    let need = RequiredOwner {
                        room: work.room,
                        peer: flow.hint_peer,
                        head,
                        seq,
                        request: flow.retirement_request(),
                        instance: flow.instance,
                    };
                    if !self.bounded_sync.required.contains(&need) {
                        self.bounded_sync.required.push_front(need);
                    }
                }
                self.bounded_sync.dispose(flow);
                crate::node::status::SyncBook::with(
                    &self.sync_book,
                    work.room,
                    work.peer,
                    |counts| {
                        counts.stale += 1;
                        counts.backoff = None;
                    },
                );
                if let Some(port) = self.ports.get_mut(&(work.room, retry_peer)) {
                    port.raise();
                    port.clear_backoff();
                }
                if let Some((request, instance)) = archive {
                    // `failed` retired the stale running generation. Retain the exact Resume as
                    // its replacement owner before any fallible profile/room/admission preflight;
                    // `schedule` either installs preparation or keeps its fair Control ticket.
                    self.history_demand.owe_resume(work.room, instance, request);
                }
                self.sched_rooms.insert(work.room);
                continue;
            }
            if let Some(error) = flow.local_retry.take() {
                let retry_peer = flow.route_origin.unwrap_or(flow.hint_peer);
                if let Some(hint) = flow.hint {
                    self.history_hints
                        .retry(work.room, flow.hint_peer, hint.author, hint.head);
                }
                if let Some((head, seq)) = flow.required_root {
                    let need = RequiredOwner {
                        room: work.room,
                        peer: flow.hint_peer,
                        head,
                        seq,
                        request: flow.retirement_request(),
                        instance: flow.instance,
                    };
                    if !self.bounded_sync.required.contains(&need) {
                        self.bounded_sync.required.push_front(need);
                    }
                }
                self.bounded_sync.dispose(flow);
                if let Some(port) = self.ports.get_mut(&(work.room, retry_peer)) {
                    // Keep the exact work requested, but do not immediately schedule it: an
                    // unrelated actor event or the ordinary maintenance pass may retry after the
                    // local store fault clears. Immediate re-scheduling would spin on a durable
                    // local failure, while peer Busy/Unreachable backoff would blame the wire.
                    port.raise();
                    port.clear_backoff();
                }
                eprintln!("vox: {error}");
                continue;
            }
            if !valid {
                self.dispose_rearming_hint(flow);
                continue;
            }
            if let Some(receipt) = flow.take_announcement_receipt() {
                if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                    // Only this completed inventory response names what the peer actually saw.
                    // An append racing it remains greater and owes the next announcement.
                    port.announced_seq = port.announced_seq.max(receipt.through);
                }
                crate::node::status::SyncBook::with(
                    &self.sync_book,
                    work.room,
                    work.peer,
                    |counts| {
                        counts.completed += 1;
                        counts
                            .reasons
                            .count(crate::node::status::RoundReason::Announce);
                        counts.fetched_completed += 1;
                        if !receipt.brought {
                            counts.empty += 1;
                            counts.fetched_empty += 1;
                        }
                    },
                );
                self.note_lane_sync(work.room, work.peer);
            }
            if let Some(seq) = flow.mine_held.take() {
                // The peer's word on how far it holds this node's feed (ADR-028 R-6), recorded
                // on the actor's next turn; the settlement tick then stops offering the own
                // head to that peer (ADR-038 FX-15).
                self.held_notes.push((work.room, work.peer, seq));
            }
            if flow.admitted_authors > 0 {
                flow.admitted_authors = 0;
                let _ = self.net_tx.try_send(NetEvent::BoardGrew {
                    channel_id: work.room,
                });
            }
            if flow.published {
                flow.published = false;
                // Ordinary content publication has no governance work. The history worker's
                // signed-kind result names the causal control publication that does.
                if flow.governance {
                    self.governance_work.wake_room(work.room);
                }
                self.sched_rooms.insert(work.room);
                // A bounded publication may have made an addressed key-package durable. Its
                // catalog is authoritative even when the best-effort presentation event below
                // cannot fit in the actor queue, so make package installation runnable here.
                // A turn that finds no package is bounded and clears the room again; a crash
                // between publication and this mark is recovered by the room-open scan.
                self.key_package_rooms.entry(work.room).or_insert(false);
                let _ = self.net_tx.try_send(NetEvent::BoundedRoomAdvanced {
                    channel_id: work.room,
                    rendered: flow.rendered,
                    governance: flow.governance,
                });
                flow.rendered = false;
                flow.governance = false;
                // A required control finished: the archive's next local slice can recheck its
                // exact dependency. No archive wire request is created by this wake.
                if let Some(flow) = self.bounded_sync.ready[1].as_mut() {
                    flow.waiting = false;
                    self.sched_rooms.insert(flow.room);
                }
            }
            if let Some((head, seq)) = flow.external.take() {
                let need = RequiredOwner {
                    room: work.room,
                    peer: work.peer,
                    head,
                    seq,
                    request: flow.retirement_request(),
                    instance: flow.instance,
                };
                if !self.bounded_sync.required.contains(&need)
                    && self.bounded_sync.required.len() < 128
                {
                    self.bounded_sync.required.push_back(need);
                }
            }
            if let Some(target) = flow.reroute.take() {
                // EvidenceUnavailable named the author of the exact missing signed dependency.
                // Keep this flow, its in-flight hint owner and its exact query/continuation
                // intact; only the next wire turn moves to the authoritative port.
                let more_for_peer =
                    self.bounded_sync
                        .ready
                        .iter()
                        .flatten()
                        .any(|flow| flow.room == work.room && flow.peer == work.peer)
                        || self
                            .bounded_sync
                            .deferred
                            .iter()
                            .any(|flow| flow.room == work.room && flow.peer == work.peer)
                        || self.history_hints.pending(work.room, work.peer)
                        || self
                            .leave_waiters
                            .iter()
                            .any(|(room, _, _, _)| *room == work.room)
                        || self.bounded_sync.required.iter().any(|required| {
                            required.room == work.room && required.peer == work.peer
                        });
                flow.peer = target;
                flow.route_origin = Some(work.peer);
                flow.route_origin_brought = flow.brought;
                flow.brought = false;
                flow.route_complete = false;
                debug_assert!(self.bounded_sync.ready[0].is_none());
                if self.bounded_sync.ready[0].is_some() {
                    self.dispose_rearming_hint(flow);
                    continue;
                }
                self.bounded_sync.ready[0] = Some(flow);
                crate::node::status::SyncBook::with(
                    &self.sync_book,
                    work.room,
                    work.peer,
                    |counts| counts.partial += 1,
                );
                if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                    // Consume only the scheduling request this attempt captured. A later raise
                    // remains greater, and retained work receives a new raise below.
                    port.req_done = port.req_done.max(work.request);
                    if more_for_peer {
                        port.raise();
                    }
                }
                if let Some(port) = self.ports.get_mut(&(work.room, target)) {
                    port.raise();
                    port.clear_backoff();
                } else {
                    self.discover_rooms.insert(work.room);
                }
                crate::node::status::SyncBook::with(&self.sync_book, work.room, target, |counts| {
                    counts.backoff = None
                });
                self.sched_rooms.insert(work.room);
                continue;
            }
            if let Some(error) = returned.error {
                if flow.announcement_failed() && flow.retain_failed_announcement().is_ok() {
                    // The announcement used its own scalar task. A refused/broken stream keeps
                    // the ordinary hint/required stack and retries this prefix through the port's
                    // existing transport backoff; it does not finish or re-arm that root.
                    self.bounded_sync.deferred.push_back(flow);
                    crate::node::status::SyncBook::with(
                        &self.sync_book,
                        work.room,
                        work.peer,
                        |counts| {
                            counts.failed += 1;
                            counts.last_failure = Some(error);
                        },
                    );
                    self.enter_backoff(
                        work.room,
                        work.peer,
                        crate::node::status::BackoffKind::Unreachable,
                    );
                    continue;
                }
                // A peer that does not yet hold a selected current body or a required current
                // evidence, and a room whose Session-readiness facts are still refreshing, are
                // bounded waiting conditions, not peer failures: this same port's next round
                // re-selects the work and advances it. Failing the round would put this healthy
                // port in Unreachable backoff — growing past one retry per half minute — and
                // strand the pair's live window and control closure behind it. Dispose the flow
                // so its next selection is fresh, and retry at the Busy cadence without
                // counting a failure or arming the persistent-failure escalation.
                let transient = matches!(
                    error.as_str(),
                    "peer unreachable: selected current body is unavailable or cancelled"
                        | "peer unreachable: required current evidence is unavailable"
                ) || crate::node::sessions::opening_refreshing(&error);
                // A worker this actor cancelled (its ask was replaced, paused or stopped) stopped
                // at its next store step: a local decision, so its port is neither failed nor
                // backed off, and the replacing ask's own flow runs next.
                let cancelled = error
                    == crate::error::Error::Profile(crate::node::history_demand::CANCELLED)
                        .to_string();
                if let Some(request) = flow.archive_request {
                    self.history_demand.failed(request, flow.generation, &error);
                }

                if let Some(hint) = flow.hint {
                    self.history_hints
                        .finish(work.room, flow.hint_peer, hint.author, hint.head);
                }
                self.bounded_sync.dispose(flow);
                if cancelled {
                    self.sched_rooms.insert(work.room);
                    continue;
                }
                if transient {
                    self.enter_backoff(
                        work.room,
                        work.peer,
                        crate::node::status::BackoffKind::Busy,
                    );
                    self.sched_rooms.insert(work.room);
                    continue;
                }
                crate::node::status::SyncBook::with(
                    &self.sync_book,
                    work.room,
                    work.peer,
                    |counts| {
                        counts.failed += 1;
                        counts.last_failure = Some(error);
                    },
                );
                self.enter_backoff(
                    work.room,
                    work.peer,
                    crate::node::status::BackoffKind::Unreachable,
                );
                continue;
            }
            if flow.route_complete {
                let Some(origin) = flow.route_origin.take() else {
                    self.dispose_rearming_hint(flow);
                    continue;
                };
                flow.route_complete = false;
                let more_for_target =
                    self.history_hints.pending(work.room, work.peer)
                        || self.bounded_sync.required.iter().any(|required| {
                            required.room == work.room && required.peer == work.peer
                        });
                if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                    port.req_done = port.req_done.max(work.request);
                    if more_for_target {
                        port.raise();
                    }
                    port.clear_backoff();
                }
                let reason = flow.reason;
                crate::node::status::SyncBook::with(
                    &self.sync_book,
                    work.room,
                    work.peer,
                    |counts| {
                        counts.completed += 1;
                        counts.reasons.count(reason);
                        counts.fetched_completed += 1;
                        // Returning one dependency turn to its advertising source is a lane
                        // completion too. If the whole retained flow has brought nothing, this
                        // completion is empty by the same user-visible accounting rule.
                        if !flow.brought {
                            counts.empty += 1;
                            counts.fetched_empty += 1;
                        }
                        counts.backoff = None;
                    },
                );
                flow.brought = std::mem::take(&mut flow.route_origin_brought);
                // A round the lane completed is a completed sync for `vox status` (PRD-001
                // R35), as a session's clean report was before ADR-037. Without this every
                // lane-served room read "last sync never" and, after ten minutes, "no completed
                // sync" while its counters climbed into the thousands (the decider's daemon,
                // 2026-10-19).
                self.note_lane_sync(work.room, work.peer);
                let origin_room =
                    crate::node::ports::RoomRef::Channel(Arc::downgrade(&flow.shared));
                let origin_live = self
                    .ports
                    .get(&(work.room, origin))
                    .is_some_and(|port| !port.poisoned && port.room.is(&origin_room));
                if !origin_live {
                    // The advertising peer departed or its room instance was poisoned while the
                    // exact author turn was in flight. Its inbox scope has already retired (or
                    // this hint is safely re-armed for a later reopen); never strand the sole
                    // foreground lane on an absent/unschedulable origin port.
                    self.dispose_rearming_hint(flow);
                    self.sched_rooms.insert(work.room);
                    continue;
                }
                flow.peer = origin;
                debug_assert!(self.bounded_sync.ready[0].is_none());
                if self.bounded_sync.ready[0].is_some() {
                    self.dispose_rearming_hint(flow);
                    continue;
                }
                self.bounded_sync.ready[0] = Some(flow);
                if let Some(port) = self.ports.get_mut(&(work.room, origin)) {
                    port.raise();
                    port.clear_backoff();
                }
                crate::node::status::SyncBook::with(&self.sync_book, work.room, origin, |counts| {
                    counts.backoff = None
                });
                self.sched_rooms.insert(work.room);
                continue;
            }
            let superseded = flow.hint.is_some_and(|hint| {
                self.history_hints
                    .newer_pending(work.room, flow.hint_peer, hint.author, hint.size)
            });
            if superseded {
                // The worker has returned from its bounded slice, so no in-flight state is
                // mutated. Retire its transient capabilities; signed headers, receipts, cursors
                // and missing-body facts already committed by earlier slices remain durable.
                // `retry` drops this obsolete owner because the inbox holds a newer successor,
                // which resumes the same live window instead of waiting behind up to 128 bodies.
                self.dispose_rearming_hint(flow);
                if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                    port.req_done = port.req_done.max(work.request);
                    port.raise();
                    port.clear_backoff();
                }
                crate::node::status::SyncBook::with(
                    &self.sync_book,
                    work.room,
                    work.peer,
                    |counts| {
                        counts.partial += 1;
                        counts.backoff = None;
                    },
                );
                self.sched_rooms.insert(work.room);
                continue;
            }
            // A successful local slice disproves only an earlier capacity yield. Do this for a
            // completed flow too: the completion can reveal another authenticated head waiting
            // on the same port, and leaving its old Busy backoff intact spaces that real work at
            // the exponential cap even though capacity has just made progress. Transport, policy
            // and no-progress backoffs retain their distinct meaning.
            if let Some(pressure) = flow.byte_pressure.take() {
                let admission = AdmissionWork {
                    root: flow.root_name(),
                    lane: pressure.lane(),
                };
                let waiting = ByteWait {
                    owner: Some(ByteOwner::of(&flow)),
                    port_request: Some(work.request),
                    wake: Box::pin(pressure.released()),
                };
                if index == 0 {
                    self.bounded_sync.deferred.push_back(flow);
                } else {
                    self.bounded_sync.ready[index] = Some(flow);
                }
                // The worker has finished and parked: neither this future nor the retained
                // Flow owns reconstruction buffers or a worker slot. Subscribe/recheck the
                // full retry peak, without turning byte pressure into a timed Busy retry.
                self.bounded_sync
                    .cancel_byte_admission(work.room, work.peer);
                self.bounded_sync.wait_for_bytes(
                    &self.net_tx,
                    &mut self.next_token,
                    work.room,
                    work.peer,
                    admission,
                    waiting,
                );
                continue;
            }
            let local_progress = flow.done() || !flow.waiting || flow.body_progress;
            let cleared_busy = local_progress
                && self
                    .ports
                    .get_mut(&(work.room, work.peer))
                    .is_some_and(|port| {
                        if port.backoff.is_some_and(|backoff| {
                            backoff.kind == crate::node::status::BackoffKind::Busy
                        }) {
                            port.clear_backoff();
                            true
                        } else {
                            false
                        }
                    });
            if cleared_busy {
                crate::node::status::SyncBook::with(
                    &self.sync_book,
                    work.room,
                    work.peer,
                    |counts| counts.backoff = None,
                );
            }
            if flow.done() {
                if !flow.archive && !flow.inventory {
                    if let Some(head) = flow.authenticated_head {
                        let event = NetEvent::BoundedHeadCompleted {
                            channel_id: work.room,
                            instance: Arc::downgrade(&flow.shared),
                            head,
                            epoch: flow.epoch,
                            room_instance: flow.instance,
                            generation: flow.generation,
                        };
                        if self.net_tx.try_send(event).is_err() {
                            // Retain the charged completed flow and its in-flight hint until
                            // the actor can receive the exact completion; never lose this edge.
                            self.bounded_sync.ready[index] = Some(flow);
                            self.sched_rooms.insert(work.room);
                            continue;
                        }
                    }
                }
                if let Some(status) = flow.archive_status.take() {
                    if let Some(request) = status.request {
                        self.history_demand
                            .completed(request, flow.generation, status);
                    }
                }
                if let Some(hint) = flow.hint {
                    self.history_hints
                        .finish(work.room, flow.hint_peer, hint.author, hint.head);
                }
                let mut raised = false;
                if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                    if flow.inventory {
                        port.done_gen = port.done_gen.max(work.generation);
                    }
                    if flow.inventory || flow.hint.is_some() {
                        // This attempt consumed the request that selected its inventory or
                        // scalar hint. Leaving it outstanding immediately schedules another
                        // inventory and recreates the feedback churn the bounded inbox removed.
                        port.req_done = port.req_done.max(work.request);
                    }
                    if self
                        .bounded_sync
                        .ready
                        .iter()
                        .flatten()
                        .any(|flow| flow.room == work.room && flow.peer == work.peer)
                        || self.history_hints.pending(work.room, work.peer)
                        || self
                            .leave_waiters
                            .iter()
                            .any(|(r, _, _, _)| *r == work.room)
                        || self.bounded_sync.required.iter().any(|required| {
                            required.room == work.room && required.peer == work.peer
                        })
                    {
                        port.raise();
                        raised = true;
                    }
                }
                // A completed inventory can reveal the next exact departure/receipt work.
                // Raising the port changes its need, but `schedule` only examines touched
                // rooms. Wake this room now instead of leaving the raised port asleep until
                // the periodic all-ports tick consumes most of the leave deadline.
                if raised {
                    self.sched_rooms.insert(work.room);
                }
                let reason = flow.reason;
                // A round that fetched nothing this node did not hold is an `empty` one: in a
                // quiet room every round is, and a person sees a re-pull as `completed`
                // climbing faster than `empty` (ADR-038 FX-29).
                let brought = flow.brought;
                crate::node::status::SyncBook::with(
                    &self.sync_book,
                    work.room,
                    work.peer,
                    |counts| {
                        counts.completed += 1;
                        counts.reasons.count(reason);
                        counts.fetched_completed += 1;
                        if !brought {
                            counts.empty += 1;
                            counts.fetched_empty += 1;
                        }
                    },
                );
                // A round the lane completed is a completed sync for `vox status` (PRD-001
                // R35), as a session's clean report was before ADR-037. Without this every
                // lane-served room read "last sync never" and, after ten minutes, "no completed
                // sync" while its counters climbed into the thousands (the decider's daemon,
                // 2026-10-19).
                self.note_lane_sync(work.room, work.peer);
            } else {
                let waiting = flow.waiting;
                let body_progress = flow.body_progress;
                let publication_owner = flow.publication_owner_wait();
                if flow.governance_wait {
                    // The flow found the fold pending: the actor's fold hook drives it (ADR-037
                    // R2 b), and the flow's next round finds it ready.
                    self.governance_work.wake_room(work.room);
                }
                if index == 0 {
                    // The controller-wide retained-flow permit already bounds this collection.
                    // Never evict an exact required/hint/inventory root merely because some
                    // arbitrary number of other ports are also deferred.
                    self.bounded_sync.deferred.push_back(flow);
                } else {
                    self.bounded_sync.ready[index] = Some(flow);
                }
                if waiting {
                    if body_progress {
                        // A waiting slice that moved a durable body chunk is progress on real
                        // remaining work, not a busy wait: the port's next round runs now at
                        // the base cadence instead of doubling a Busy backoff against the very
                        // backlog it is draining (an 18-slice drain was spaced past the
                        // person-facing bounds by the exponential cap alone).
                        self.sched_rooms.insert(work.room);
                    } else {
                        self.enter_backoff(
                            work.room,
                            work.peer,
                            crate::node::status::BackoffKind::Busy,
                        );
                    }
                } else {
                    self.sched_rooms.insert(work.room);
                }
                if let Some(owner) = publication_owner {
                    self.wake_publication_owner(work.room, owner);
                }
            }
        }
        // Completion may have removed the last live publication owner in a room whose retired
        // flows were ineligible at the beginning of this audit. Start its exact cleanup now;
        // the retained completion wake is the causal edge, not a scheduler tick.
        self.bounded_sync.poll_cleanup();
    }

    /// Records a lane round that completed cleanly as this room's, and this peer's, last
    /// completed sync, for `vox status` (PRD-001 R35).
    fn note_lane_sync(&mut self, room: Digest32, peer: Digest32) {
        let now = self.now_ms().get();
        self.status.room_synced.insert(room, now);
        self.status.member_synced.insert(peer, now);
    }

    pub(super) async fn start_bounded_outbound(
        &mut self,
        room: Digest32,
        peer: Digest32,
        epoch: u64,
        shared: Arc<tokio::sync::Mutex<ChannelState>>,
        store: Arc<Store>,
        conn: Arc<VoxConnection>,
    ) -> bool {
        self.accept_bounded_sync();
        if let Some((flow, ended_request)) =
            self.bounded_sync
                .take_superseded_byte_hint(room, peer, &self.history_hints)
        {
            // The newer scalar head hint is already pending; it is the causal replacement
            // edge, not permission to retry the refused old allocation. Retirement preserves
            // durable facts and re-arms only the exact obsolete hint through the existing path.
            self.dispose_rearming_hint(flow);
            let mut cleared_busy = false;
            if let Some(port) = self.ports.get_mut(&(room, peer)) {
                port.req_done = port.req_done.max(ended_request);
                port.raise();
                if port
                    .backoff
                    .is_some_and(|backoff| backoff.kind == crate::node::status::BackoffKind::Busy)
                {
                    port.clear_backoff();
                    cleared_busy = true;
                }
            }
            crate::node::status::SyncBook::with(&self.sync_book, room, peer, |counts| {
                counts.partial += 1;
                if cleared_busy {
                    counts.backoff = None;
                }
            });
            self.sched_rooms.insert(room);
        }
        // Only the exact release handoff may make an impossible-path continuation runnable.
        // Generic actor traffic still evaluates queued ports, but cannot stand in for that edge.
        if self.bounded_sync.pool_admission_blocked(room, peer)
            || self.bounded_sync.record_bytes_blocked(room, peer)
        {
            return false;
        }
        let Some(profile) = self.profile.as_ref() else {
            return false;
        };
        let node = profile.fingerprint();
        let pending_work = self.bounded_pending_identity(room, peer);
        if self.bounded_sync.ready[0].is_none() && self.bounded_sync.running[0].is_none() {
            if let Some(at) = self
                .bounded_sync
                .deferred
                .iter()
                .position(|flow| flow.room == room && flow.peer == peer)
            {
                self.bounded_sync.ready[0] = self.bounded_sync.deferred.remove(at);
            }
        }
        // An own append is announced before the next hinted continuation (ADR-037 R7). The
        // inventory exchange is the only exchange that carries this node's heads to the peer,
        // and it runs only on a flow with no hint; a parked hinted flow draining the peer's
        // backlog would otherwise be reused round after round, so the peer learned of this
        // node's post only when the drain ended (measured: 53–58 s for a 150-post window).
        // The hinted flow waits one round in the deferred queue and resumes after.
        let announce_first = self.bounded_sync.running[0].is_none()
            && self
                .ports
                .get(&(room, peer))
                .is_some_and(crate::node::ports::Port::announce_owed);
        // Why a round would run now (ADR-038 FX-15, #996): read before the flow is chosen,
        // because choosing it consumes what it reads.
        let (announce_owed, periodic_pending) = self
            .ports
            .get(&(room, peer))
            .map_or((false, false), |port| {
                (port.announce_owed(), port.periodic_pending())
            });
        // A reader's page is served on its own stream (#996): a port whose only want is that
        // page runs the page, and no live round beside it. Before this the page's dispatch
        // raised the port, and the raise outlived the page, so every page a reader asked for
        // ran an inventory exchange after it that fetched nothing.
        let page_only = self.history_demand.ready_binding(room, peer).is_some()
            && !self.bounded_sync.needs_port(room, peer)
            && !self.history_hints.pending(room, peer)
            && !self
                .ports
                .get(&(room, peer))
                .is_some_and(crate::node::ports::Port::needs);
        // A retained hint/required flow prepends the announcement on that same owner. Parking it
        // and allocating a fresh inventory Flow deadlocks when all retained positions are full:
        // the inventory is the producer that would let those retained flows finish. A successful
        // prefix gives its ordinary root one real quantum before another append can preempt it.
        let announcement_preempts = self.bounded_sync.ready[0].as_ref().is_some_and(|flow| {
            flow.room == room
                && flow.peer == peer
                && !flow.inventory
                && flow.announcement_can_run()
                && (flow.announcement_pending() || (announce_first && !flow.ordinary_turn_due()))
        });
        let existing = (0..crate::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS).find(|index| {
            self.bounded_sync.running[*index].is_none()
                && self.bounded_sync.ready[*index]
                    .as_ref()
                    .is_some_and(|flow| {
                        flow.room == room
                            && flow.peer == peer
                            && (!flow.waiting || announcement_preempts)
                    })
        });
        let mut admitted_archive = None;
        let mut admitted_control = None;
        let mut flow = if let Some(index) = existing {
            let Some(flow) = self.bounded_sync.ready[index].take() else {
                return false;
            };
            flow
        } else {
            // A retained waiting slice is retried by the existing bounded port backoff. It
            // cannot monopolize the other lane or cause an archive continuation to run.
            if let Some(index) =
                (0..crate::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS).find(|i| {
                    !announcement_preempts
                        && self.bounded_sync.running[*i].is_none()
                        && self.bounded_sync.ready[*i].as_ref().is_some_and(|flow| {
                            flow.room == room
                                && flow.peer == peer
                                && (!flow.archive || self.bounded_sync.required.is_empty())
                        })
                })
            {
                let Some(flow) = self.bounded_sync.ready[index].take() else {
                    return false;
                };
                flow
            } else {
                if self.bounded_sync.flow_count() >= RETAINED_FLOW_LIMIT {
                    // This is controller retention preflight, before a Flow/start attempt owns
                    // the port. Its release is driven by the exact retiring/completion owner;
                    // do not overwrite the last ended attempt with a start_reason ADR-038 does
                    // not define.
                    return false;
                }
                if self.bounded_sync.ready[1].is_none() && self.bounded_sync.running[1].is_none() {
                    if let Some((request, generation, instance)) =
                        self.history_demand.ready_binding(room, peer)
                    {
                        match self.bounded_sync.archive_turn(
                            &self.history_budget,
                            &self.net_tx,
                            &mut self.next_token,
                            node,
                            room,
                            peer,
                            request,
                            generation,
                            instance,
                        ) {
                            ArchiveTurn::Ready(job) => admitted_archive = Some(job),
                            ArchiveTurn::Waiting => {
                                self.note_start(room, peer, "archive_budget_busy");
                                return false;
                            }
                        }
                    }
                }
                let Ok(lease) = self.secret_work.clone().try_read_owned() else {
                    self.bounded_sync.wait_for_secret(
                        &self.net_tx,
                        &mut self.next_token,
                        room,
                        peer,
                        pending_work,
                        self.secret_work.clone(),
                    );
                    // Secret-work admission is preflight, before the documented start gates.
                    // Its exact waiter wakes this port; the latest ended attempt stays intact.
                    return false;
                };
                let lease = Arc::new(lease);
                let state_job = match self.bounded_sync.foreground_turn(
                    &self.history_budget,
                    &self.net_tx,
                    &mut self.next_token,
                    node,
                    room,
                    peer,
                    pending_work.root,
                    crate::node::history_budget::Lane::Control,
                ) {
                    ForegroundTurn::Ready(job) => job,
                    ForegroundTurn::Waiting => {
                        self.note_start(room, peer, "control_budget_busy");
                        return false;
                    }
                };
                let actor_incarnation = state_job.flow_owner();
                admitted_control = Some(state_job.clone());

                // Inventory must first advertise the new local departure. Once that fixed
                // exchange completes, probe only our own exact head; no archive is followed.
                let departure_hint = if self.leave_waiters.iter().any(|(r, generation, _, _)| {
                    *r == room
                        && self
                            .ports
                            .get(&(room, peer))
                            .is_some_and(|p| p.done_gen >= *generation)
                }) {
                    let bytes_wake = state_job.bytes_wake();
                    let Some(_read_charge) = state_job.reserve(4 * 1024 * 1024) else {
                        self.bounded_sync.wait_for_bytes(
                            &self.net_tx,
                            &mut self.next_token,
                            room,
                            peer,
                            pending_work,
                            ByteWait::unowned(bytes_wake),
                        );
                        self.note_start(room, peer, "control_budget_busy");
                        return false;
                    };
                    if let Ok(channel) = shared.try_lock() {
                        match channel.history_head(&store, &node) {
                            Ok(Some(head)) => {
                                let hint = stream::HeadHint {
                                    author: node,
                                    head: head.id(),
                                    size: head.root.leaves,
                                };
                                channel
                                    .history_departure_matches(&store, hint)
                                    .ok()
                                    .filter(|yes| *yes)
                                    .map(|_| hint)
                            }
                            _ => None,
                        }
                    } else {
                        // This is an optional exact-head shortcut after the inventory that
                        // advertises the departure. Room contention cannot block starting that
                        // inventory; the peer's later receipt event offers the shortcut again.
                        None
                    }
                } else {
                    None
                };

                let control = match crate::node::history_demand::Context::current_unlocked(
                    profile,
                    Purpose::Control,
                    lease.clone(),
                ) {
                    Ok(value) => Arc::new(value),
                    Err(_) => return false,
                };
                if self.bounded_sync.ready[1].is_none() && self.bounded_sync.running[1].is_none() {
                    if let Some(dispatch) = self.history_demand.take_ready(room, peer) {
                        Flow::archive(
                            room,
                            peer,
                            node,
                            epoch,
                            dispatch.instance,
                            dispatch.generation,
                            shared.clone(),
                            control,
                            dispatch.staging,
                            dispatch.query,
                            dispatch.request,
                            dispatch.fence,
                            self.bounded_sync.body_slots.clone(),
                            store.clone(),
                            Arc::clone(&self.history_budget),
                            actor_incarnation,
                        )
                    } else {
                        if page_only
                            || self.bounded_sync.ready[0].is_some()
                            || self.bounded_sync.running[0].is_some()
                        {
                            self.note_start(room, peer, "live_lane_busy");
                            return false;
                        }
                        let live = match crate::node::history_demand::Context::current_unlocked(
                            profile,
                            Purpose::Live,
                            lease,
                        ) {
                            Ok(value) => Arc::new(value),
                            Err(_) => return false,
                        };
                        let required_at = (!announce_first)
                            .then(|| {
                                self.bounded_sync.required.iter().position(|required| {
                                    required.room == room && required.peer == peer
                                })
                            })
                            .flatten();
                        let required = required_at
                            .and_then(|at| self.bounded_sync.required.get(at))
                            .map(|required| (required.head, required.seq));
                        let hint = if announce_first || required.is_some() {
                            None
                        } else {
                            departure_hint.or_else(|| self.history_hints.take(room, peer, node))
                        };
                        let reason = foreground_reason(
                            node,
                            hint,
                            required.is_some(),
                            announce_owed,
                            periodic_pending,
                        );
                        match Flow::foreground(
                            room,
                            peer,
                            node,
                            epoch,
                            shared.clone(),
                            live,
                            control,
                            hint,
                            departure_hint.is_some() && required.is_none(),
                            required,
                            self.bounded_sync.body_slots.clone(),
                            store.clone(),
                            Arc::clone(&self.history_budget),
                            actor_incarnation,
                        ) {
                            Ok(mut flow) => {
                                flow.reason = reason;
                                if let Some(at) = required_at {
                                    let _ = self.bounded_sync.required.remove(at);
                                }
                                flow
                            }
                            Err(_) => {
                                if let Some(hint) = hint {
                                    self.history_hints.retry(room, peer, hint.author, hint.head);
                                }
                                return false;
                            }
                        }
                    }
                } else {
                    if page_only
                        || self.bounded_sync.ready[0].is_some()
                        || self.bounded_sync.running[0].is_some()
                    {
                        self.note_start(room, peer, "live_lane_busy");
                        return false;
                    }
                    let live = match crate::node::history_demand::Context::current_unlocked(
                        profile,
                        Purpose::Live,
                        lease,
                    ) {
                        Ok(value) => Arc::new(value),
                        Err(_) => return false,
                    };
                    let required_at = (!announce_first)
                        .then(|| {
                            self.bounded_sync
                                .required
                                .iter()
                                .position(|required| required.room == room && required.peer == peer)
                        })
                        .flatten();
                    let required = required_at
                        .and_then(|at| self.bounded_sync.required.get(at))
                        .map(|required| (required.head, required.seq));
                    let hint = if announce_first || required.is_some() {
                        None
                    } else {
                        departure_hint.or_else(|| self.history_hints.take(room, peer, node))
                    };
                    let reason = foreground_reason(
                        node,
                        hint,
                        required.is_some(),
                        announce_owed,
                        periodic_pending,
                    );
                    match Flow::foreground(
                        room,
                        peer,
                        node,
                        epoch,
                        shared.clone(),
                        live,
                        control,
                        hint,
                        departure_hint.is_some() && required.is_none(),
                        required,
                        self.bounded_sync.body_slots.clone(),
                        store.clone(),
                        Arc::clone(&self.history_budget),
                        actor_incarnation,
                    ) {
                        Ok(mut flow) => {
                            flow.reason = reason;
                            if let Some(at) = required_at {
                                let _ = self.bounded_sync.required.remove(at);
                            }
                            flow
                        }
                        Err(_) => {
                            if let Some(hint) = hint {
                                self.history_hints.retry(room, peer, hint.author, hint.head);
                            }
                            return false;
                        }
                    }
                }
            }
        };
        let index = usize::from(flow.archive);
        let announcement = flow.announcement_can_run()
            && (flow.announcement_pending()
                || (announce_first && !flow.inventory && !flow.ordinary_turn_due()));
        let lane = if announcement {
            crate::node::history_budget::Lane::Control
        } else {
            flow.lane()
        };
        // From here on this Flow is the sole owner of any consumed archive dispatch, required
        // dependency or hint. Every refusal parks this exact owner until its admission edge.
        let job = if lane == crate::node::history_budget::Lane::Archive {
            if let Some(job) = admitted_archive.take() {
                job
            } else {
                let Some(request) = flow.archive_request else {
                    self.bounded_sync.dispose(flow);
                    return false;
                };
                match self.bounded_sync.archive_turn(
                    &self.history_budget,
                    &self.net_tx,
                    &mut self.next_token,
                    node,
                    flow.room,
                    flow.peer,
                    request,
                    flow.generation,
                    flow.instance,
                ) {
                    ArchiveTurn::Ready(job) => job,
                    ArchiveTurn::Waiting => {
                        self.note_start(room, peer, "archive_budget_busy");
                        self.shelve_exact(flow, index);
                        return false;
                    }
                }
            }
        } else if lane == crate::node::history_budget::Lane::Control {
            if let Some(job) = admitted_control.take() {
                job
            } else {
                match self.bounded_sync.foreground_turn(
                    &self.history_budget,
                    &self.net_tx,
                    &mut self.next_token,
                    node,
                    room,
                    peer,
                    flow.root_name(),
                    lane,
                ) {
                    ForegroundTurn::Ready(job) => job,
                    ForegroundTurn::Waiting => {
                        self.note_start(room, peer, "control_budget_busy");
                        self.shelve_exact(flow, index);
                        return false;
                    }
                }
            }
        } else {
            match self.bounded_sync.foreground_turn(
                &self.history_budget,
                &self.net_tx,
                &mut self.next_token,
                node,
                room,
                peer,
                flow.root_name(),
                lane,
            ) {
                ForegroundTurn::Ready(job) => job,
                ForegroundTurn::Waiting => {
                    // The retained lane ticket wakes this exact port on a relevant release.
                    self.note_start(room, peer, "control_budget_busy");
                    self.shelve_exact(flow, index);
                    return false;
                }
            }
        };
        // Flow-state bytes always come from Control. A newly created flow reuses the construction
        // job; a resumed non-Control flow admits a fresh Control job for this round only. Neither
        // worker survives `Flow::park` because the state charge owns its final reference.
        let state_job = if lane == crate::node::history_budget::Lane::Control {
            job.clone()
        } else if let Some(job) = admitted_control.take() {
            job
        } else {
            match self.bounded_sync.foreground_turn(
                &self.history_budget,
                &self.net_tx,
                &mut self.next_token,
                node,
                room,
                peer,
                flow.root_name(),
                crate::node::history_budget::Lane::Control,
            ) {
                ForegroundTurn::Ready(job) => job,
                ForegroundTurn::Waiting => {
                    self.note_start(room, peer, "control_budget_busy");
                    self.shelve_exact(flow, index);
                    return false;
                }
            }
        };
        // The Control bytes the flow state costs, from the same budget gate (ADR-038 FX-35):
        // their refusal is the control budget's, never the pool's, and they go back with the
        // flow if a later gate ends the attempt.
        let bytes_wake = Flow::state_bytes_wake(&state_job);
        let Some(state_bytes) = flow.reserve_state_bytes(&state_job) else {
            self.bounded_sync.wait_for_bytes(
                &self.net_tx,
                &mut self.next_token,
                room,
                peer,
                AdmissionWork::from_flow(&flow),
                ByteWait::unowned(bytes_wake),
            );
            self.note_start(room, peer, "control_budget_busy");
            self.shelve_exact(flow, index);
            return false;
        };
        let wake = self.net_tx.clone();
        let Some(slot) = crate::node::ports::Slots::take(
            &self.slots,
            peer,
            Box::new(move || {
                tokio::spawn(async move {
                    let _ = wake.send(NetEvent::SlotFreed).await;
                });
            }),
        ) else {
            self.note_start(room, peer, "no_outbound_slot");
            self.shelve_exact(flow, index);
            return false;
        };
        // The last gate (ADR-038 FX-35): a flow holds the daemon's flow state only while its
        // round runs, and takes it here, in the step that makes the round run. A full fixed pool
        // parks the exact flow, gives back the lane job and slot, and wakes only from a running
        // charge's release; the port keeps its need.
        let resumed = {
            let waiter = self
                .bounded_sync
                .pool_admission
                .get_mut(&(room, peer))
                .map(|admission| &mut admission.ticket);
            flow.resume(&state_job, state_bytes, waiter)
        };
        let refused = match resumed {
            crate::node::history_stream::runtime::Resumed::Held => {
                self.bounded_sync.cancel_pool_admission(room, peer);
                None
            }
            crate::node::history_stream::runtime::Resumed::PoolFull(edge) => {
                Some(("pool", "flow_state_pool_full", Some(edge)))
            }
            crate::node::history_stream::runtime::Resumed::PoolOvercommitted(edge) => {
                Some(("overcommitted", "flow_state_pool_overcommitted", Some(edge)))
            }
            crate::node::history_stream::runtime::Resumed::NodeBusy(edge) => {
                Some(("node_slots", "flow_state_node_busy", Some(edge)))
            }
            crate::node::history_stream::runtime::Resumed::OwnerMissing => {
                Some(("owner", "flow_state_owner_missing", None))
            }
        };
        if let Some((gate, reason, refused_at)) = refused {
            // Both refusals are impossible under the legal running-work bound, but they are
            // different first gates. Do not call two occupied source-owned slots a full
            // daemon pool: operators need the same cause here and on the retained admission.
            self.note_start(room, peer, reason);
            // This ordinary admission wait still owns all work consumed while constructing
            // the Flow: archive dispatch, exact required dependency, or scalar hint. Retain
            // it in its lane until a running completion releases capacity and wakes the
            // actor; never reconstruct only the hint and strand the other two forms.
            let mut flow = flow;
            let root = flow.root_name();
            let retirement_request = flow.retirement_request();
            let instance = flow.instance;
            flow.park();
            debug_assert!(self.bounded_sync.ready[index].is_none());
            self.bounded_sync.ready[index] = Some(flow);
            // A granted claim was consumed by this failed attempt, if one existed. Replace
            // its actor-owned record with the exact still-retained Flow and a later order.
            self.bounded_sync.cancel_pool_admission(room, peer);
            if let Some(refused_at) = refused_at {
                if let Err(error) = self.bounded_sync.wait_for_pool(
                    &mut self.next_token,
                    room,
                    peer,
                    PoolWait {
                        gate,
                        work: AdmissionWork { root, lane },
                        request: retirement_request,
                        instance,
                    },
                    &state_job,
                    &refused_at,
                ) {
                    self.note_start(
                        room,
                        peer,
                        match error {
                            crate::node::history_budget::FlowWaitError::OwnerMissing => {
                                "flow_state_owner_missing"
                            }
                            crate::node::history_budget::FlowWaitError::OrderExhausted => {
                                "flow_state_order_exhausted"
                            }
                        },
                    );
                }
            }
            return false;
        }
        let Some(own_seq) = self.ports.get(&(room, peer)).map(|port| port.own_seq) else {
            self.dispose_rearming_hint(flow);
            return false;
        };
        if announcement && flow.arm_announcement(own_seq).is_err() {
            self.shelve_exact(flow, index);
            return false;
        }
        let Some(port) = self.ports.get_mut(&(room, peer)) else {
            self.dispose_rearming_hint(flow);
            return false;
        };
        if flow.inventory {
            // This exchange carries every own append so far; one landing after this mark
            // makes the port owe the peer again, and the round after announces it.
            port.announced_seq = port.own_seq;
        }
        let token = self.next_token;
        self.next_token += 1;
        let fence = flow
            .request_fence
            .clone()
            .unwrap_or_else(crate::transport::stream_transport::Fence::new);
        let generation = port.gen.load(std::sync::atomic::Ordering::Relaxed);
        let request = port.req_gen;
        let running = crate::node::status::Running::start(
            &self.sync_book,
            room,
            peer,
            token,
            true,
            crate::node::status::SyncStep::Exchanging,
        );
        // Fence-only retirement: aborting this async owner could detach a blocking worker and
        // release the port's actual-worker slot early. Every local helper is awaited to exit.
        port.out = Some(crate::node::ports::Attempt {
            token,
            dir: crate::node::ports::Dir::Out,
            conn: conn.clone(),
            req_at_start: request,
            started: std::time::Instant::now(),
            abort: None,
            fence: fence.clone(),
            running,
            departure_receipt: None,
            reason: if announcement {
                crate::node::status::RoundReason::Announce
            } else {
                flow.reason
            },
        });
        let archive = flow
            .archive_request
            .map(|request| (request, flow.generation));
        let running_retirement_key = retirement_key(&flow);
        // A key to this peer waiting on its bundle makes this round read the peer's board,
        // hinted or not (ADR-038 FX-35); once the bundle is held the fact is gone.
        flow.wants_board = self.key_waiting.contains_key(&(room, peer));
        let flow = Arc::new(tokio::sync::Mutex::new(Some(flow)));
        let result = Arc::new(StdMutex::new(None));
        let worker_flow = Arc::clone(&flow);
        let settlement_flow = Arc::clone(&flow);
        let output = result.clone();
        let worker_fence = fence.clone();
        let completion_wake = self.bounded_sync.completion_wake();
        let inbox = self.history_hints.clone();
        let inbox_generation = inbox.generation(room, peer);
        let now = self.now_ms().get();
        let net = self.net.as_ref().cloned();
        let pstore = profile.store_handle();
        let tx = self.net_tx.clone();
        let authority = self.computer_authority();
        let worker = tokio::spawn(async move {
            let _slot = slot;
            let deadline =
                tokio::time::Instant::now() + crate::node::history_budget::BOUNDED_ROUND_PATIENCE;
            let mut flow = worker_flow.lock().await;
            let Some(flow) = flow.as_mut() else {
                return Some("bounded history supervisor retained no Flow".to_owned());
            };
            // The proof barrier belongs after exclusive Flow ownership. While it is held, an
            // actor panic can retire the controller but cannot adopt/park this Flow; its charge
            // therefore remains truthfully attributed to the retiring actor generation.
            job.hold_for_proof(room, peer).await;
            if flow.needs_board() && !worker_fence.is_retired() {
                if let (Some(net), Some(authority)) = (net, authority.as_ref()) {
                    flow.admitted_authors = tokio::select! {
                        biased;
                        ()=worker_fence.retired()=>0,
                        result=tokio::time::timeout(SETUP_PATIENCE,exchange_boards(&net,&conn,&flow.shared,&pstore,authority,&tx,room,epoch,crate::time::Ms(now)))=>result.unwrap_or(0),
                    };
                }
            }
            let error = flow
                .turn(
                    store,
                    &conn,
                    &job,
                    worker_fence,
                    deadline,
                    &inbox,
                    inbox_generation,
                    now,
                )
                .await
                .err()
                .map(|e| e.to_string());
            // The round is over: its flow state goes back here, in the step that ends it
            // (ADR-038 FX-35), not when the actor next looks; a finished task holds no charge.
            flow.park();
            error
        });
        let task = tokio::spawn(async move {
            let (error, panic) = match worker.await {
                Ok(error) => (error, None),
                Err(error) => (None, Some(error.to_string())),
            };
            // The inner task can unwind before its normal `park`. Its supervisor owns the exact
            // settlement edge and releases the running charge before publishing completion.
            if let Some(flow) = settlement_flow.lock().await.as_mut() {
                flow.park();
            }
            if let Ok(mut result) = output.lock() {
                *result = Some(Returned { error, panic });
            }
            completion_wake.notify_one();
        });
        self.bounded_sync.running[index] = Some(Running {
            room,
            peer,
            token,
            generation,
            request,
            archive,
            lane,
            retirement_key: running_retirement_key,
            fence,
            flow,
            result,
            task,
            started: std::time::Instant::now(),
        });
        self.note_start(room, peer, "started");
        true
    }
}

impl Controller {
    /// The lane's flow slots as they stand, for `vox status --json` (`lanes.bounded`): a live
    /// flow that never returns holds slot 0 and silences every room of the node, so a person
    /// must be able to see it.
    pub(super) fn lanes_json(&self) -> String {
        use crate::node::link::b32_encode;
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let retirement_errors = self
            .retirement_ledger
            .errors
            .lock()
            .map(|errors| errors.clone())
            .unwrap_or_default();
        let cleanup_errors = retirement_errors
            .iter()
            .map(|(key, error)| {
                format!(
                    "{{\"actor\":{},\"request\":\"{}\",\"instance\":\"{}\",\"generation\":\"{}\",\"room\":\"{}\",\"peer\":\"{}\",\"archive\":{},\"error\":{}}}",
                    key.actor.map_or_else(|| "null".to_owned(), |actor| actor.to_string()),
                    hex(&key.request),
                    hex(&key.instance),
                    b32_encode(&key.generation),
                    b32_encode(&key.room),
                    b32_encode(&key.peer),
                    key.archive,
                    serde_json::to_string(error).unwrap_or_else(|_| "null".to_owned())
                )
            })
            .collect::<Vec<_>>();
        let cleanup_error = retirement_errors.values().next().cloned();
        let flow = |f: &Flow| {
            let key = retirement_key(f);
            format!(
                "{{\"actor\":{},\"request\":\"{}\",\"instance\":\"{}\",\"generation\":\"{}\",\"room\":\"{}\",\"peer\":\"{}\",\"root\":\"{}\",\"lane\":\"{}\",\"archive\":{},\"waiting\":{},\"inventory\":{}}}",
                key.actor.map_or_else(|| "null".to_owned(), |actor| actor.to_string()),
                hex(&key.request),
                hex(&key.instance),
                b32_encode(&key.generation),
                b32_encode(&f.room),
                b32_encode(&f.peer),
                f.root_name(),
                lane_name(f.lane()),
                f.archive,
                f.waiting,
                f.inventory
            )
        };
        let ready: Vec<String> = self
            .ready
            .iter()
            .map(|r| r.as_ref().map_or_else(|| "null".to_owned(), flow))
            .collect();
        let running: Vec<String> = self
            .running
            .iter()
            .map(|r| {
                r.as_ref().map_or_else(
                    || "null".to_owned(),
                    |r| {
                        format!(
                            "{{\"actor\":{},\"request\":\"{}\",\"instance\":\"{}\",\"generation\":\"{}\",\"room\":\"{}\",\"peer\":\"{}\",\"token\":{},\"archive\":{},\"lane\":\"{}\",\"age_ms\":{},\"finished\":{}}}",
                            r.retirement_key.actor.map_or_else(|| "null".to_owned(), |actor| actor.to_string()),
                            hex(&r.retirement_key.request),
                            hex(&r.retirement_key.instance),
                            b32_encode(&r.retirement_key.generation),
                            b32_encode(&r.room),
                            b32_encode(&r.peer),
                            r.token,
                            r.archive.is_some(),
                            lane_name(r.lane),
                            u64::try_from(r.started.elapsed().as_millis()).unwrap_or(u64::MAX),
                            r.task.is_finished()
                        )
                    },
                )
            })
            .collect();
        let deferred = self.deferred.iter().map(flow).collect::<Vec<_>>();
        let retiring = self.retiring.iter().map(flow).collect::<Vec<_>>();
        let required = self.required.iter().map(|required| {
            format!(
                "{{\"request\":\"{}\",\"instance\":\"{}\",\"room\":\"{}\",\"peer\":\"{}\",\"head\":\"{}\",\"seq\":{}}}",
                hex(&required.request),
                hex(&required.instance),
                b32_encode(&required.room),
                b32_encode(&required.peer),
                b32_encode(&required.head),
                required.seq
            )
        }).collect::<Vec<_>>();
        let cleanup = self.cleanup.as_ref().map_or_else(|| "null".to_owned(), |cleanup| {
            let key = cleanup.key;
            format!(
                "{{\"actor\":{},\"request\":\"{}\",\"instance\":\"{}\",\"generation\":\"{}\",\"room\":\"{}\",\"peer\":\"{}\",\"archive\":{}}}",
                key.actor.map_or_else(|| "null".to_owned(), |actor| actor.to_string()),
                hex(&key.request),
                hex(&key.instance),
                b32_encode(&key.generation),
                b32_encode(&key.room),
                b32_encode(&key.peer),
                key.archive
            )
        });
        let admission = |gate: &str,
                         token: u64,
                         room: Digest32,
                         peer: Digest32,
                         root: &str,
                         lane: crate::node::history_budget::Lane,
                         request: Option<stream::RequestId>,
                         wait_order: Option<u64>,
                         handed_off: Option<bool>| {
            let request = request.map_or_else(
                || "null".to_owned(),
                |request| {
                    format!(
                        "\"{}\"",
                        request
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>()
                    )
                },
            );
            format!(
                "{{\"admission\":{},\"gate\":\"{}\",\"room\":\"{}\",\"peer\":\"{}\",\"root\":\"{}\",\"lane\":\"{}\",\"request\":{},\"wait_order\":{},\"handed_off\":{}}}",
                token,
                gate,
                b32_encode(&room),
                b32_encode(&peer),
                root,
                lane_name(lane),
                request,
                wait_order.map_or_else(|| "null".to_owned(), |order| order.to_string()),
                handed_off.map_or_else(|| "null".to_owned(), |value| value.to_string())
            )
        };
        let mut admissions = Vec::new();
        if let Some(waiting) = &self.archive_admission {
            admissions.push(admission(
                "archive",
                waiting.token,
                waiting.room,
                waiting.peer,
                "archive",
                crate::node::history_budget::Lane::Archive,
                Some(waiting.request),
                None,
                None,
            ));
        }
        admissions.extend(self.foreground_admission.iter().flatten().map(|waiting| {
            admission(
                "foreground",
                waiting.token,
                waiting.room,
                waiting.peer,
                waiting.root,
                waiting.lane,
                None,
                None,
                None,
            )
        }));
        admissions.extend(self.secret_admission.iter().map(|((room, peer), waiting)| {
            admission(
                "secret",
                waiting.token,
                *room,
                *peer,
                waiting.root,
                waiting.lane,
                None,
                None,
                None,
            )
        }));
        admissions.extend(self.byte_admission.iter().map(|((room, peer), waiting)| {
            admission(
                "bytes",
                waiting.token,
                *room,
                *peer,
                waiting.root,
                waiting.lane,
                None,
                None,
                None,
            )
        }));
        admissions.extend(self.pool_admission.iter().map(|((room, peer), waiting)| {
            admission(
                waiting.gate,
                waiting.token,
                *room,
                *peer,
                waiting.root,
                waiting.lane,
                None,
                Some(waiting.ticket.sequence()),
                Some(waiting.handed_off),
            )
        }));
        format!(
            "{{\"ready\":[{}],\"running\":[{}],\"deferred\":[{}],\"retiring\":[{}],\"required\":[{}],\"admissions\":[{}],\"archive_admission\":{},\"foreground_admissions\":{},\"room_admissions\":{},\"secret_admissions\":{},\"byte_admissions\":{},\"pool_admissions\":{},\"cleanup\":{},\"cleanup_error\":{},\"cleanup_errors\":[{}]}}",
            ready.join(","),
            running.join(","),
            deferred.join(","),
            retiring.join(","),
            required.join(","),
            admissions.join(","),
            self.archive_admission.is_some(),
            self.foreground_admission.iter().flatten().count(),
            0,
            self.secret_admission.len(),
            self.byte_admission.len(),
            self.pool_admission.len(),
            cleanup,
            serde_json::to_string(&cleanup_error).unwrap_or_else(|_| "null".to_owned()),
            cleanup_errors.join(",")
        )
    }
}
