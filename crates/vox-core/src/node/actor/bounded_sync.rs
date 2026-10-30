//! Bounded current-message work and explicitly requested archive work share the existing ports.
//! Events carry tokens only; private slots retain capabilities until workers actually finish.
use super::*;
use crate::node::history_stream::{
    self as stream,
    runtime::{Flow, RetirementStep},
    Purpose, RequestId,
};
use crate::node::ports::{OutboundService, PhysicalSlot};
use crate::node::store::Store;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::Mutex as StdMutex;

/// The native recovery-fence write belongs to a retained physical worker, not the actor's
/// BoundedHeadCompleted callback. Only its matching reservation may install the durable fence.
pub(super) async fn refresh_own_recovery_owned(
    shared: Arc<tokio::sync::Mutex<ChannelState>>,
    store: Arc<Store>,
) -> crate::error::Result<bool> {
    let mut room = shared.lock().await;
    let Some(pending) = room.prepare_own_recovery(&store)? else {
        return Ok(false);
    };
    let instance = room.history_instance(&store)?;
    let owner = Arc::new(());
    let pin = room.reserve_pending_write(&store, Arc::clone(&owner))?;
    drop(room);
    tokio::task::spawn_blocking(move || {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pending.commit(&store)));
        let mut room = shared.blocking_lock();
        let owns = room.owns_pending_history_write(&owner);
        let result = match result {
            Ok(Ok(())) => {
                if owns {
                    (|| {
                        if room.history_instance(&store)? != instance {
                            return Err(Error::Unreachable("own recovery room changed"));
                        }
                        room.install_own_recovery(pending).map(|()| true)
                    })()
                } else {
                    Err(Error::Unreachable("own recovery publication owner changed"))
                }
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(Error::Profile("own recovery save worker stopped")),
        };
        room.release_pending_text(&owner, false);
        drop(room);
        drop(pin);
        result
    })
    .await
    .map_err(|_| Error::Profile("own recovery completion worker stopped"))?
}

/// Prepare one immutable automatic page using the same durable admission and body machinery as
/// a user Archive. The namespace is private to this node/room; it never replaces a user's page.
#[allow(clippy::too_many_arguments)]
async fn own_recovery_flow(
    profile: &Profile,
    room: Digest32,
    peer: Digest32,
    epoch: u64,
    instance: [u8; 16],
    page: crate::node::channel::OwnRecoveryPage,
    shared: Arc<tokio::sync::Mutex<ChannelState>>,
    control: Arc<crate::node::history_demand::Context>,
    lease: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    slots: Arc<stream::runtime::BodySlots>,
    store: Arc<Store>,
    budget: Arc<crate::node::history_budget::Budget>,
    state_job: &crate::node::history_budget::Job,
    trigger: Digest32,
) -> crate::error::Result<Flow> {
    use crate::node::history_demand::{self as demand, Binding, Bounds, Progress};
    use crate::node::history_stream::{Query, Staging};
    let node = profile.fingerprint();
    let generation = stream::authorization_generation(&store, node, room, instance, epoch)?;
    let context = Arc::new(demand::Context::own_recovery_unlocked(
        profile, room, lease,
    )?);
    let binding = Binding {
        room,
        instance,
        epoch,
        audience: [0; 32],
        grant: generation,
    };
    let work = context.clone();
    let job = state_job.clone();
    let (request, query, active, checkpoint, cleanup) =
        tokio::task::spawn_blocking(move || -> crate::error::Result<_> {
            let snapshot = demand::inspect(&work, &job)?;
            if let Some(snapshot) = &snapshot {
                let state = snapshot.state();
                // Disposal reclaims each unfinished body before this namespace may be reused.
                // A crash during cleanup leaves exactly that bounded continuation, not permission
                // to overwrite it with a new request.
                if state.reclaiming()
                    || (!matches!(
                        state.progress(None),
                        Progress::Complete | Progress::Cancelled
                    ) && (state.binding.room != binding.room
                        || state.binding.instance != binding.instance
                        || state.binding.epoch != binding.epoch))
                {
                    let active = demand::own_recovery_cleanup(&work, state)?;
                    let query = Query::Page {
                        head: state.bounds.head,
                        lo: state.bounds.lo,
                        hi: state.bounds.hi,
                        entries: state.remaining,
                        wire_bytes: 1024 * 1024,
                    };
                    return Ok((
                        state.request,
                        query,
                        active,
                        stream::runtime::OwnRecoveryCheckpoint::of(state),
                        true,
                    ));
                }
                if !matches!(
                    state.progress(None),
                    Progress::Complete | Progress::Cancelled
                ) {
                    let request = state.request;
                    let query = if let Some(body) = &state.body {
                        Query::Entry {
                            head: state.bounds.head,
                            seq: body.seq,
                            offset: body.offset,
                        }
                    } else {
                        Query::Page {
                            head: state.bounds.head,
                            lo: state.bounds.lo,
                            hi: state
                                .cursor
                                .as_ref()
                                .map_or(state.bounds.hi, |c| c.next_seq),
                            entries: state.remaining,
                            wire_bytes: 1024 * 1024,
                        }
                    };
                    let active = demand::resume_own_recovery(&work, request, binding, &job)?;
                    let checkpoint = stream::runtime::OwnRecoveryCheckpoint::of(state);
                    return Ok((request, query, active, checkpoint, false));
                }
            }
            let entries = usize::try_from(page.hi - page.lo + 1)
                .map_err(|_| Error::MalformedAtRest("own recovery page size"))?;
            let bounds = Bounds {
                head: page.head,
                lo: page.lo,
                hi: page.hi,
                entries,
            };
            let request = crate::identity::rng::random_array::<16>()?;
            let active = demand::start(&work, request, binding, bounds, &job)?;
            let saved = demand::inspect(&work, &job)?.ok_or(Error::OwnHistoryBehind)?;
            let checkpoint = stream::runtime::OwnRecoveryCheckpoint::of(saved.state());
            Ok((
                request,
                Query::Page {
                    head: page.head,
                    lo: page.lo,
                    hi: page.hi,
                    entries,
                    wire_bytes: 1024 * 1024,
                },
                active,
                checkpoint,
                false,
            ))
        })
        .await
        .map_err(|_| Error::Profile("own recovery preparation worker stopped"))??;
    let mut flow = Flow::archive(
        room,
        peer,
        node,
        epoch,
        instance,
        generation,
        shared,
        control,
        Staging {
            context,
            active: Arc::new(StdMutex::new(active)),
        },
        query,
        request,
        crate::transport::stream_transport::Fence::new(),
        slots,
        store,
        budget,
        state_job.flow_owner(),
    );
    flow.automatic_own_recovery = true;
    flow.own_recovery_trigger = Some(trigger);
    flow.own_recovery_page = (!cleanup).then_some((page.head, page.lo));
    flow.own_recovery_checkpoint = Some(checkpoint);
    if cleanup {
        flow.mark_own_recovery_cleanup();
    }
    Ok(flow)
}

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
        if !self.complete && !self.entry.failed.load(Ordering::Acquire) {
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
        if runner.entry.failed.load(Ordering::Acquire) {
            let mut recovery =
                Box::pin(Arc::clone(&runner.entry.recovery_changed).notified_owned());
            recovery.as_mut().enable();
            let erased = {
                let held = runner.entry.flow.lock().await;
                let Some(flow) = held.as_ref() else {
                    runner.complete = true;
                    return;
                };
                flow.retirement_erasure()
            };
            if runner.entry.failed.load(Ordering::Acquire) {
                tokio::select! { ()=erased=>{}, ()=recovery=>{} }
            }
            runner.entry.failed.store(false, Ordering::Release);
        }
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
            Ok(RetirementStep::Done) => {
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
            Ok(RetirementStep::Progress) => tokio::task::yield_now().await,
            Ok(RetirementStep::Wait(wait)) => wait.released().await,
            Err(error) => {
                note_retirement_error(&runner.ledger, key, &error.to_string());
                eprintln!(
                    "vox: history retirement for {}/{}/{} remains owed: {error}",
                    crate::node::link::b32_encode(&key.room),
                    crate::node::link::b32_encode(&key.peer),
                    if key.archive { "archive" } else { "live" }
                );
                runner.entry.failed.store(true, Ordering::Release);
                // The obligation remains in the ledger. A permanent fault is visible recovery
                // work, never permission to resubmit it on a timer or unrelated actor event.
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
    failed: bool,
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
                        failed: std::sync::atomic::AtomicBool::new(failed),
                        recovery_changed: Arc::new(tokio::sync::Notify::new()),
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

fn spawn_owed_retirement(mut flow: Flow, ledger: Arc<RetirementLedger>, failed: bool) {
    flow.park();
    let key = retirement_key(&flow);
    adopt_retirement_cell(
        &ledger,
        key,
        Arc::new(tokio::sync::Mutex::new(Some(flow))),
        failed,
    );
}

fn resume_owed_retirements(ledger: &Arc<RetirementLedger>, node: Digest32) {
    let entries = ledger
        .entries
        .lock()
        .map(|entries| {
            entries
                .iter()
                .filter(|(key, _)| key.node == node)
                .map(|(key, entry)| (*key, Arc::clone(entry)))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for (key, entry) in entries {
        // Controller restoration is an explicit recovery boundary, not a periodic retry.
        entry.failed.store(false, Ordering::Release);
        entry.recovery_changed.notify_waiters();
        start_retirement(ledger, key, entry);
    }
}

/// Explicit node locking also erases rooms retained by an earlier actor incarnation. The
/// replacement actor's room instances cannot erase those old instances or their Context leases.
pub(super) async fn erase_retired_node(ledger: &Arc<RetirementLedger>, node: Digest32) {
    let entries = ledger
        .entries
        .lock()
        .map(|entries| {
            entries
                .iter()
                .filter(|(key, _)| key.node == node)
                .map(|(key, entry)| (*key, Arc::clone(entry)))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for (key, entry) in entries {
        // Every actual retirement slice holds this cell through its blocking worker's join.
        // A queued original worker sees None after we take the Flow and cannot borrow its keys.
        let mut held = entry.flow.lock().await;
        entry.failed.store(true, Ordering::Release);
        let task = entry.task.lock().ok().and_then(|mut task| task.take());
        if let Some(task) = &task {
            // Only dependency waiting can remain once we own the actual worker's cell.
            task.abort();
        }
        if let Some(flow) = held.take() {
            flow.cancel();
            flow.shared.lock().await.lock_now();
            // Locked-room reopen recovery owns any remaining durable staging cleanup. Drop
            // every Context here; never restore its cancellation or retain copied room keys.
            drop(flow);
        }
        drop(held);
        if let Some(task) = task {
            let _ = task.await;
        }
        if let Ok(mut entries) = ledger.entries.lock() {
            if entries
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &entry))
            {
                // Keep the pointer check and error removal under the same map lock, so a
                // replacement entry cannot have its error removed by this old owner.
                clear_retirement_error(ledger, key);
                entries.remove(&key);
            }
        }
    }
}

struct ReturnedFailure {
    text: String,
    classification: crate::node::channel::SyncFailure,
}
impl ReturnedFailure {
    fn from_error(error: Error) -> Self {
        let text = error.to_string();
        let classification = match error {
            Error::PeerRefused(code) => crate::node::channel::SyncFailure::Session(
                crate::log::sync::SessionError::Peer(code),
            ),
            _ => crate::node::channel::SyncFailure::Unreachable(text.clone()),
        };
        Self {
            text,
            classification,
        }
    }

    fn unreachable(text: String) -> Self {
        Self {
            classification: crate::node::channel::SyncFailure::Unreachable(text.clone()),
            text,
        }
    }

    fn panicked(panic: String) -> Self {
        Self {
            text: format!("bounded history worker panicked: {panic}"),
            classification: crate::node::channel::SyncFailure::Panicked,
        }
    }

    fn retryable_peer_busy(&self) -> bool {
        matches!(
            &self.classification,
            crate::node::channel::SyncFailure::Session(crate::log::sync::SessionError::Peer(
                crate::wire::WireError::SessionBusy | crate::wire::WireError::NotYetMember
            ))
        )
    }
}
struct Returned {
    failure: Option<ReturnedFailure>,
}
struct Running {
    room: Digest32,
    peer: Digest32,
    service: crate::node::ports::OutboundService,
    slot: crate::node::ports::PhysicalSlot,
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
    result: Arc<StdMutex<Option<crate::error::Result<RetirementStep>>>>,
    task: tokio::task::JoinHandle<()>,
    cancellations: Vec<crate::node::history_demand::Cancellation>,
}
struct RetirementWaiting {
    ready: Arc<std::sync::atomic::AtomicBool>,
    recover: bool,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for RetirementWaiting {
    fn drop(&mut self) {
        self.task.abort();
    }
}
type PortKey = (Digest32, Digest32, crate::node::ports::OutboundService);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct WorkKey {
    room: Digest32,
    peer: Digest32,
    service: crate::node::ports::OutboundService,
    request: stream::RequestId,
    instance: [u8; 16],
    authorization: Digest32,
}
impl WorkKey {
    fn of(flow: &Flow) -> Self {
        Self {
            room: flow.room,
            peer: flow.peer,
            service: flow.service,
            request: flow.retirement_request(),
            instance: flow.instance,
            authorization: flow.generation,
        }
    }
}

fn foreground_index(
    service: crate::node::ports::OutboundService,
    lane: crate::node::history_budget::Lane,
) -> usize {
    service.index() * 4 + lane.index()
}

#[derive(Clone, Copy)]
pub(super) struct AdmissionWork {
    root: &'static str,
    lane: crate::node::history_budget::Lane,
    service: crate::node::ports::OutboundService,
    key: Option<WorkKey>,
    /// Pre-Flow Public request and room generation; authorization is captured only by a Flow.
    demand: Option<(u64, u64)>,
}
impl AdmissionWork {
    fn unowned(
        root: &'static str,
        lane: crate::node::history_budget::Lane,
        service: crate::node::ports::OutboundService,
    ) -> Self {
        Self {
            root,
            lane,
            service,
            key: None,
            demand: None,
        }
    }

    fn from_flow(flow: &Flow) -> Self {
        Self {
            root: flow.root_name(),
            lane: flow.lane(),
            service: flow.service,
            key: Some(WorkKey::of(flow)),
            demand: None,
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
    service: crate::node::ports::OutboundService,
    key: Option<WorkKey>,
    demand: Option<(u64, u64)>,
    ticket: crate::node::history_budget::Ticket,
    task: tokio::task::JoinHandle<()>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum LocalAdmissionKind {
    Secret,
    Room,
}
struct LocalAdmission {
    kind: LocalAdmissionKind,
    token: u64,
    root: &'static str,
    lane: crate::node::history_budget::Lane,
    key: Option<WorkKey>,
    task: tokio::task::JoinHandle<()>,
}
struct ByteAdmission {
    root: &'static str,
    lane: crate::node::history_budget::Lane,
    owner: Option<WorkKey>,
    /// Scheduling need captured by the ended worker, never the port's newer current need.
    port_request: Option<u64>,
    task: tokio::task::JoinHandle<()>,
}
struct ByteWait {
    wake: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    owner: Option<WorkKey>,
    port_request: Option<u64>,
}
struct PoolAdmission {
    token: u64,
    gate: &'static str,
    root: &'static str,
    lane: crate::node::history_budget::Lane,
    key: WorkKey,
    ticket: crate::node::history_budget::FlowReleaseTicket,
    /// Set only by the exact release handoff. Unrelated actor events cannot consume a granted
    /// continuation before this owner has received its causal edge.
    handed_off: bool,
}
#[derive(Clone, Copy)]
struct PoolWait {
    gate: &'static str,
    root: &'static str,
    lane: crate::node::history_budget::Lane,
    key: WorkKey,
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

struct DetachedFlowCharge {
    count: Arc<std::sync::atomic::AtomicUsize>,
    held: usize,
}
impl Drop for DetachedFlowCharge {
    fn drop(&mut self) {
        self.count.fetch_sub(self.held, Ordering::AcqRel);
    }
}

/// Only one room's physical owners move here; the live node controller remains on actor.
pub(super) struct RoomRetirement {
    driver: Controller,
    room: Digest32,
    epoch: u64,
    instance: Option<std::sync::Weak<tokio::sync::Mutex<ChannelState>>>,
    attempts: Vec<(Digest32, u64)>,
    inbound: Vec<(
        Digest32,
        u64,
        Arc<crate::transport::stream_transport::Fence>,
        Option<tokio::task::AbortHandle>,
    )>,
    _charge: Option<DetachedFlowCharge>,
}
pub(super) struct RetiredRoom {
    owned: RoomRetirement,
    result: crate::error::Result<()>,
}
impl RetiredRoom {
    pub(super) fn succeeded(&self) -> bool {
        self.result.is_ok()
    }
    pub(super) fn failure(&self) -> Option<&Error> {
        self.result.as_ref().err()
    }
}
impl RoomRetirement {
    /// Run on the existing lifecycle gate worker, never the actor or a cancellable select arm.
    pub(super) async fn run(mut self) -> RetiredRoom {
        for slot in &mut self.driver.running {
            if let Some(work) = slot.take() {
                let _ = work.task.await;
                if let Some(flow) = work.flow.lock().await.take() {
                    self.driver.retiring.push_back(flow);
                }
            }
        }
        let mut result = self.drain().await;
        // A failed slice must not leave a second physical cleanup in an occupied actor slot.
        if let Err(error) = self.driver.join_cleanup().await {
            if result.is_ok() {
                result = Err(error);
            }
        }
        if result.is_ok() {
            for (_, _, fence, abort) in &self.inbound {
                fence.retire();
                if let Some(abort) = abort {
                    abort.abort();
                }
            }
        }
        RetiredRoom {
            owned: self,
            result,
        }
    }

    async fn drain(&mut self) -> crate::error::Result<()> {
        loop {
            self.driver.join_cleanup().await?;
            self.driver.poll_cleanup();
            if self.driver.retiring.iter().any(|flow| {
                self.driver
                    .retirement_failed
                    .contains(&retirement_key(flow))
            }) {
                return Err(Error::Profile(
                    "history retirement requires recovery; see status",
                ));
            }
            if self.driver.cleanup.is_some() {
                continue;
            }
            if self.driver.retiring.is_empty() {
                return Ok(());
            }
            // Transferred waiters retain their original notification tasks. Poll those exact
            // handles directly, so no second controller competes for a Notify's single permit.
            let waited = std::future::poll_fn(|cx| {
                for (key, waiting) in &mut self.driver.retirement_waiting {
                    if waiting.ready.load(Ordering::Acquire) {
                        return std::task::Poll::Ready(Ok(()));
                    }
                    if let std::task::Poll::Ready(joined) =
                        std::pin::Pin::new(&mut waiting.task).poll(cx)
                    {
                        return std::task::Poll::Ready(joined.map_err(|_| *key));
                    }
                }
                std::task::Poll::Pending
            })
            .await;
            if let Err(key) = waited {
                let error = Error::Profile("history retirement waiter stopped");
                note_retirement_error(&self.driver.retirement_ledger, key, &error.to_string());
                self.driver.retirement_failed.insert(key);
                self.driver.retirement_waiting.remove(&key);
                let erased = self
                    .driver
                    .retiring
                    .iter()
                    .find(|flow| retirement_key(flow) == key)
                    .map(Flow::retirement_erasure);
                if let Some(erased) = erased {
                    self.driver.wait_for_retirement(key, erased, true);
                }
                return Err(error);
            }
        }
    }
}

#[derive(Default)]
pub(super) struct Controller {
    running: [Option<Running>; crate::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS],
    ready: [Option<Flow>; 3],
    background_next: Option<crate::node::ports::OutboundService>,
    /// The one queued archive turn for this node. The controller owns its daemon-wide fair-queue
    /// ticket; the task waits only for a wake, without an actor or room lock.
    archive_admission: Option<ArchiveAdmission>,
    /// One retained ticket per logical service/lane. A release wakes the exact waiting
    /// owner; ticket metadata does not add a worker or physical running position.
    foreground_admission: [Option<ForegroundAdmission>; 12],
    local_admission: BTreeMap<PortKey, LocalAdmission>,
    byte_admission:
        BTreeMap<(Digest32, Digest32, crate::node::ports::OutboundService, u64), ByteAdmission>,
    pool_admission: BTreeMap<PortKey, PoolAdmission>,
    deferred: VecDeque<Flow>,
    body_slots: Arc<stream::runtime::BodySlots>,
    required: VecDeque<RequiredOwner>,
    retiring: VecDeque<Flow>,
    cleanup: Option<Cleanup>,
    retirement_waiting: BTreeMap<RetirementKey, RetirementWaiting>,
    retirement_failed: std::collections::BTreeSet<RetirementKey>,
    /// The synchronous old-controller driver must not compete with the replacement actor
    /// for the shared actor Notify's single retained permit.
    retirement_changed: Arc<tokio::sync::Notify>,
    /// Per-flow retirement failures outlive controller replacement and remain visible until that
    /// exact flow reaches its durable end. An unrelated cleanup can never clear another's error.
    retirement_ledger: Arc<RetirementLedger>,
    /// Workers publish their durable result before notifying this coalesced edge. `Notify`
    /// retains a permit while the actor is elsewhere; one wake audits every result slot, so no
    /// completion can be stranded behind the actor's bounded event queue.
    completion_wake: Arc<tokio::sync::Notify>,
    detached_flows: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.retirement_waiting.clear();
        self.cancel_archive_admission();
        for index in 0..self.foreground_admission.len() {
            self.cancel_foreground_admission(index);
        }
        for (_, admission) in std::mem::take(&mut self.local_admission) {
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
            let failed = self.retirement_failed.contains(&key);
            if !failed {
                note_retirement_error(&ledger, key, message);
            }
            spawn_owed_retirement(flow, Arc::clone(&ledger), failed);
        }
        if let Some(cleanup) = cleanup {
            note_retirement_error(&ledger, cleanup.key, message);
            adopt_retirement_cell(&ledger, cleanup.key, cleanup.flow, false);
            // Dropping the handle detaches an already-running bounded slice, but ownership is
            // now in the daemon ledger; its runner waits on the same cell and cannot race it.
            drop(cleanup.task);
        }
        for work in running {
            note_retirement_error(&ledger, work.retirement_key, message);
            adopt_retirement_cell(&ledger, work.retirement_key, work.flow, false);
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
    }

    pub(super) fn recover_node_retirements(&self, node: Digest32) {
        resume_owed_retirements(&self.retirement_ledger, node);
    }

    fn owns_archive_room(&self, room: Digest32) -> bool {
        self.ready
            .iter()
            .flatten()
            .chain(self.deferred.iter())
            .chain(self.retiring.iter())
            .any(|flow| flow.archive && flow.room == room)
            || self
                .running
                .iter()
                .flatten()
                .any(|work| work.room == room && work.archive.is_some())
            || self
                .cleanup
                .as_ref()
                .is_some_and(|work| work.key.room == room && work.key.archive)
            || self
                .retirement_ledger
                .entries
                .lock()
                .map_or(true, |entries| {
                    entries.keys().any(|key| key.room == room && key.archive)
                })
    }

    pub(super) fn completion_wake(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.completion_wake)
    }
    /// A retained current/archive continuation is itself demand on its exact room/peer port.
    /// Port request generations describe external wakes; an independent clean exchange may
    /// consume one while this continuation is between bounded slices. Do not let that scalar
    /// acknowledgement strand work whose ownership is still here.
    pub(super) fn needs_port_for(
        &self,
        room: Digest32,
        peer: Digest32,
        service: crate::node::ports::OutboundService,
    ) -> bool {
        self.ready
            .iter()
            .flatten()
            .chain(self.deferred.iter())
            .any(|flow| flow.room == room && flow.peer == peer && flow.service == service)
            || (service == crate::node::ports::OutboundService::Public
                && self
                    .required
                    .iter()
                    .any(|owner| owner.room == room && owner.peer == peer))
            || self
                .foreground_admission
                .iter()
                .flatten()
                .any(|a| a.room == room && a.peer == peer && a.service == service)
            || self.local_admission.contains_key(&(room, peer, service))
            || self
                .byte_admission
                .range((room, peer, service, 0)..=(room, peer, service, u64::MAX))
                .next()
                .is_some()
            || self.pool_admission.contains_key(&(room, peer, service))
    }

    fn retains_work(&self, key: WorkKey) -> bool {
        self.ready
            .iter()
            .flatten()
            .chain(self.deferred.iter())
            .any(|flow| WorkKey::of(flow) == key)
    }

    fn cancel_archive_admission(&mut self) {
        if let Some(admission) = self.archive_admission.take() {
            admission.task.abort();
        }
    }
    pub(super) fn cancel_unstarted_archive_admission(
        &mut self,
        room: Digest32,
        peer: Digest32,
        instance: [u8; 16],
        request: stream::RequestId,
        generation: Digest32,
    ) {
        if self.archive_admission.as_ref().is_some_and(|admission| {
            admission.room == room
                && admission.peer == peer
                && admission.instance == instance
                && admission.request == request
                && admission.generation == generation
        }) {
            self.cancel_archive_admission();
        }
    }
    pub(super) fn release_archive_admission(
        &mut self,
        token: u64,
        room: Digest32,
        peer: Digest32,
        service: crate::node::ports::OutboundService,
    ) {
        if service == crate::node::ports::OutboundService::Archive
            && self.archive_admission.as_ref().is_some_and(|admission| {
                admission.token == token && admission.room == room && admission.peer == peer
            })
        {
            self.cancel_archive_admission();
        }
    }
    fn cancel_foreground_admission(&mut self, index: usize) {
        if let Some(admission) = self.foreground_admission[index].take() {
            admission.task.abort();
        }
    }
    fn cancel_matching_control_admission(
        &mut self,
        room: Digest32,
        peer: Digest32,
        service: crate::node::ports::OutboundService,
    ) {
        let index = foreground_index(service, crate::node::history_budget::Lane::Control);
        if self.foreground_admission[index]
            .as_ref()
            .is_some_and(|admission| {
                admission.room == room && admission.peer == peer && admission.service == service
            })
        {
            self.cancel_foreground_admission(index);
        }
    }
    fn control_would_admit(
        &self,
        budget: &crate::node::history_budget::Budget,
        node: Digest32,
        room: Digest32,
        peer: Digest32,
        service: crate::node::ports::OutboundService,
    ) -> bool {
        let index = foreground_index(service, crate::node::history_budget::Lane::Control);
        match self.foreground_admission[index].as_ref() {
            Some(admission)
                if admission.room == room
                    && admission.peer == peer
                    && admission.service == service =>
            {
                admission.ticket.would_admit()
            }
            Some(_) => false,
            None => budget.fresh_control_would_admit(node),
        }
    }
    /// Give the daemon's retained fair-queue owner a runnable local lane before it tries to
    /// consume capacity. The displaced Flow remains whole and keeps the exact deque position
    /// this owner held; no root, cursor, context, announcement or backoff state is rebuilt.
    fn prioritize_control_admission_owner(
        &mut self,
        room: Digest32,
        peer: Digest32,
        service: crate::node::ports::OutboundService,
    ) {
        if self.running[service.slot().index()].is_some() {
            return;
        }
        let index = foreground_index(service, crate::node::history_budget::Lane::Control);
        let Some(admission) = self.foreground_admission[index]
            .as_ref()
            .filter(|a| a.room == room && a.peer == peer && a.service == service)
        else {
            return;
        };
        let key = admission.key;
        let ready_index = service.index();
        if self.ready[ready_index].as_ref().is_some_and(|flow| {
            flow.room == room
                && flow.peer == peer
                && !self.record_bytes_blocked(flow)
                && key.is_none_or(|key| WorkKey::of(flow) == key)
        }) {
            return;
        }
        let Some(at) = self.deferred.iter().position(|flow| {
            flow.service == service
                && flow.room == room
                && flow.peer == peer
                && !self.record_bytes_blocked(flow)
                && key.is_none_or(|key| WorkKey::of(flow) == key)
        }) else {
            return;
        };
        let Some(flow) = self.deferred.remove(at) else {
            return;
        };
        if let Some(displaced) = self.ready[ready_index].replace(flow) {
            self.deferred.insert(at, displaced);
        }
    }
    fn cancel_foreground_port(
        &mut self,
        room: Digest32,
        peer: Digest32,
        service: crate::node::ports::OutboundService,
    ) {
        for index in 0..self.foreground_admission.len() {
            if self.foreground_admission[index]
                .as_ref()
                .is_some_and(|admission| {
                    admission.room == room && admission.peer == peer && admission.service == service
                })
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
        service: crate::node::ports::OutboundService,
    ) {
        for index in 0..self.foreground_admission.len() {
            if self.foreground_admission[index]
                .as_ref()
                .is_some_and(|admission| {
                    admission.token == token
                        && admission.room == room
                        && admission.peer == peer
                        && admission.service == service
                        && admission.key.is_none_or(|key| self.retains_work(key))
                })
            {
                self.cancel_foreground_admission(index);
                return;
            }
        }
    }
    fn cancel_local_admission(
        &mut self,
        room: Digest32,
        peer: Digest32,
        service: crate::node::ports::OutboundService,
    ) {
        if let Some(admission) = self.local_admission.remove(&(room, peer, service)) {
            admission.task.abort();
        }
    }
    fn release_local_admission_kind(
        &mut self,
        token: u64,
        room: Digest32,
        peer: Digest32,
        service: crate::node::ports::OutboundService,
        kind: LocalAdmissionKind,
    ) -> bool {
        if self
            .local_admission
            .get(&(room, peer, service))
            .is_some_and(|entry| {
                entry.token == token
                    && entry.kind == kind
                    && entry.key.is_none_or(|key| self.retains_work(key))
            })
        {
            self.cancel_local_admission(room, peer, service);
            true
        } else {
            false
        }
    }
    pub(super) fn release_secret_admission(
        &mut self,
        token: u64,
        room: Digest32,
        peer: Digest32,
        service: crate::node::ports::OutboundService,
    ) -> bool {
        self.release_local_admission_kind(token, room, peer, service, LocalAdmissionKind::Secret)
    }
    pub(super) fn release_room_admission(
        &mut self,
        token: u64,
        room: Digest32,
        node: Digest32,
    ) -> bool {
        self.release_local_admission_kind(
            token,
            room,
            node,
            crate::node::ports::OutboundService::Archive,
            LocalAdmissionKind::Room,
        )
    }
    pub(super) fn cancel_own_recovery_admission(&mut self, room: Digest32, node: Digest32) {
        if self
            .local_admission
            .get(&(room, node, crate::node::ports::OutboundService::Archive))
            .is_some_and(|entry| entry.kind == LocalAdmissionKind::Room)
        {
            self.cancel_local_admission(room, node, crate::node::ports::OutboundService::Archive);
        }
    }

    /// One actual room-lock release edge, coalesced in the existing cancellable admission
    /// owner. The self-node key cannot collide with a remote peer's secret admission.
    pub(super) fn wait_for_own_recovery_room(
        &mut self,
        net_tx: &mpsc::Sender<NetEvent>,
        next_token: &mut u64,
        node: Digest32,
        room: Digest32,
        shared: Arc<tokio::sync::Mutex<ChannelState>>,
    ) {
        let waiting = Arc::clone(&shared);
        self.wait_for_own_recovery_release(
            net_tx,
            next_token,
            (room, node),
            shared,
            "own_recovery",
            async move {
                drop(waiting.lock_owned().await);
            },
        );
    }

    pub(super) fn wait_for_support_discovery_publication(
        &mut self,
        net_tx: &mpsc::Sender<NetEvent>,
        next_token: &mut u64,
        node: Digest32,
        room: Digest32,
        shared: Arc<tokio::sync::Mutex<ChannelState>>,
        released: std::pin::Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
    ) {
        self.wait_for_own_recovery_release(
            net_tx,
            next_token,
            (room, node),
            shared,
            "private_support",
            released,
        );
    }

    pub(super) fn is_support_discovery_waiter(
        &self,
        token: u64,
        room: Digest32,
        node: Digest32,
    ) -> bool {
        self.local_admission
            .get(&(room, node, crate::node::ports::OutboundService::Archive))
            .is_some_and(|entry| {
                entry.token == token
                    && entry.kind == LocalAdmissionKind::Room
                    && entry.root == "private_support"
            })
    }

    fn wait_for_own_recovery_release(
        &mut self,
        net_tx: &mpsc::Sender<NetEvent>,
        next_token: &mut u64,
        key: (Digest32, Digest32),
        shared: Arc<tokio::sync::Mutex<ChannelState>>,
        root: &'static str,
        released: impl Future<Output = ()> + Send + 'static,
    ) {
        let (room, node) = key;
        if self.local_admission.contains_key(&(
            room,
            node,
            crate::node::ports::OutboundService::Archive,
        )) {
            return;
        }
        let token = *next_token;
        *next_token += 1;
        let tx = net_tx.clone();
        let instance = Arc::downgrade(&shared);
        let task = tokio::spawn(async move {
            released.await;
            let _ = tx
                .send(NetEvent::OwnRecoveryRoomReady {
                    token,
                    room,
                    node,
                    instance,
                })
                .await;
        });
        self.local_admission.insert(
            (room, node, crate::node::ports::OutboundService::Archive),
            LocalAdmission {
                kind: LocalAdmissionKind::Room,
                token,
                root,
                lane: crate::node::history_budget::Lane::Control,
                key: None,
                task,
            },
        );
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
        if self
            .local_admission
            .contains_key(&(room, peer, work.service))
        {
            return;
        }
        let token = *next_token;
        *next_token += 1;
        let tx = net_tx.clone();
        let task = tokio::spawn(async move {
            let guard = secret_work.read_owned().await;
            drop(guard);
            let _ = tx
                .send(NetEvent::BoundedSecretReady {
                    token,
                    room,
                    peer,
                    service: work.service,
                })
                .await;
        });
        self.local_admission.insert(
            (room, peer, work.service),
            LocalAdmission {
                kind: LocalAdmissionKind::Secret,
                token,
                root: work.root,
                lane: work.lane,
                key: work.key,
                task,
            },
        );
    }
    fn cancel_byte_admission(&mut self, room: Digest32, peer: Digest32, service: OutboundService) {
        self.byte_admission.retain(
            |(waiting_room, waiting_peer, waiting_service, _), admission| {
                let keep =
                    *waiting_room != room || *waiting_peer != peer || *waiting_service != service;
                if !keep {
                    admission.task.abort();
                }
                keep
            },
        );
    }
    pub(super) fn release_byte_admission(
        &mut self,
        token: u64,
        room: Digest32,
        peer: Digest32,
        service: crate::node::ports::OutboundService,
    ) -> Option<bool> {
        let admission = self.byte_admission.remove(&(room, peer, service, token))?;
        admission.task.abort();
        if let Some(owner) = admission.owner {
            self.retains_work(owner).then_some(true)
        } else {
            Some(false)
        }
    }
    fn record_bytes_blocked(&self, flow: &Flow) -> bool {
        self.byte_admission
            .range(
                (flow.room, flow.peer, flow.service, 0)
                    ..=(flow.room, flow.peer, flow.service, u64::MAX),
            )
            .any(|(_, admission)| admission.owner == Some(WorkKey::of(flow)))
    }
    fn prune_byte_admissions(&mut self, room: Digest32, peer: Digest32, service: OutboundService) {
        let ready = &self.ready;
        let deferred = &self.deferred;
        self.byte_admission.retain(
            |(waiting_room, waiting_peer, waiting_service, _), admission| {
                let stale = *waiting_room == room
                    && *waiting_peer == peer
                    && *waiting_service == service
                    && admission.owner.is_some_and(|owner| {
                        !ready
                            .iter()
                            .flatten()
                            .chain(deferred.iter())
                            .any(|flow| WorkKey::of(flow) == owner)
                    });
                if stale {
                    admission.task.abort();
                }
                !stale
            },
        );
    }
    fn take_superseded_byte_hint(
        &mut self,
        room: Digest32,
        peer: Digest32,
        service: crate::node::ports::OutboundService,
        inbox: &stream::HintInbox,
    ) -> Option<(Flow, u64)> {
        let superseded = |flow: &Flow, owner: WorkKey| {
            flow.room == room
                && flow.peer == peer
                && WorkKey::of(flow) == owner
                && flow.service == crate::node::ports::OutboundService::Public
                && flow.archive_request.is_none()
                && flow.required_root.is_none()
                && !flow.local_own_root()
                && flow.hint.is_some_and(|hint| {
                    inbox.newer_pending(room, flow.hint_peer, hint.author, hint.size)
                })
        };
        let (key, admission) = self
            .byte_admission
            .range((room, peer, service, 0)..=(room, peer, service, u64::MAX))
            .find(|(_, admission)| {
                admission.owner.is_some_and(|owner| {
                    self.ready
                        .iter()
                        .flatten()
                        .chain(self.deferred.iter())
                        .any(|flow| superseded(flow, owner))
                })
            })?;
        let token = key.3;
        let owner = admission.owner?;
        let port_request = admission.port_request?;
        // Only the exact byte waiter's parked hinted owner can be replaced. Archive and
        // required roots, other ports and replacement generations keep their continuations.
        let flow = if let Some(index) = self
            .ready
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|flow| superseded(flow, owner)))
        {
            self.ready[index].take()?
        } else {
            let index = self
                .deferred
                .iter()
                .position(|flow| superseded(flow, owner))?;
            self.deferred.remove(index)?
        };
        // No await occurs between identity selection and cancellation. A queued old ready
        // event cannot consume a future replacement, because its unique token no longer exists.
        self.byte_admission
            .remove(&(room, peer, service, token))?
            .task
            .abort();
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
        if self
            .byte_admission
            .range((room, peer, work.service, 0)..=(room, peer, work.service, u64::MAX))
            .any(|(_, admission)| admission.owner == waiting.owner.or(work.key))
        {
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
                .send(NetEvent::BoundedBytesReady {
                    token,
                    room,
                    peer,
                    service: work.service,
                })
                .await;
        });
        self.byte_admission.insert(
            (room, peer, work.service, token),
            ByteAdmission {
                root: work.root,
                lane: work.lane,
                owner: owner.or(work.key),
                port_request,
                task,
            },
        );
    }

    pub(super) fn cancel_pool_admission_for(
        &mut self,
        room: Digest32,
        peer: Digest32,
        service: crate::node::ports::OutboundService,
    ) {
        self.pool_admission.remove(&(room, peer, service));
    }

    /// A real connection-close edge retires every exact continuation for that peer before the
    /// scheduler publishes or considers other work. Return the rooms whose parked Flows remain
    /// owned and must be reconsidered after reach/reconnect.
    pub(super) fn cancel_peer_pool_admissions(&mut self, peer: Digest32) -> BTreeSet<Digest32> {
        let mut rooms = BTreeSet::new();
        self.pool_admission.retain(|(room, waiting_peer, _), _| {
            if *waiting_peer == peer {
                rooms.insert(*room);
                false
            } else {
                true
            }
        });
        rooms
    }

    pub(super) fn accept_pool_release(
        &mut self,
        release: crate::node::history_budget::FlowRelease,
    ) -> bool {
        let Some((key, owner)) = self.pool_admission.iter().find_map(|(key, admission)| {
            (key.0 == release.room
                && key.1 == release.peer
                && key.2.slot() == release.slot
                && admission.token == release.token
                && admission.ticket.sequence() == release.order
                && admission.ticket.granted())
            .then_some((*key, admission.key))
        }) else {
            return false;
        };
        if !self.retains_work(owner) {
            self.pool_admission.remove(&key);
            return false;
        }
        let Some(admission) = self.pool_admission.get_mut(&key) else {
            return false;
        };
        if admission.token != release.token
            || admission.ticket.sequence() != release.order
            || !admission.ticket.granted()
        {
            return false;
        }
        admission.handed_off = true;
        let index = owner.service.index();
        if self.ready[index]
            .as_ref()
            .is_none_or(|flow| WorkKey::of(flow) != owner)
        {
            if let Some(at) = self
                .deferred
                .iter()
                .position(|flow| WorkKey::of(flow) == owner)
            {
                if let Some(flow) = self.deferred.remove(at) {
                    if let Some(displaced) = self.ready[index].replace(flow) {
                        self.deferred.insert(at, displaced);
                    }
                }
            }
        }
        true
    }

    pub(super) fn pool_admission_blocked_for(
        &self,
        room: Digest32,
        peer: Digest32,
        service: crate::node::ports::OutboundService,
    ) -> bool {
        self.pool_admission
            .get(&(room, peer, service))
            .is_some_and(|admission| !admission.handed_off)
    }

    /// Rooms whose exact parked Flow is retained until its source-owned release edge. This is
    /// the actor-owned half of the flow-state snapshot rendered under `lanes`; health diagnosis
    /// consumes the same ownership rather than inferring a cause from a pool count.
    pub(super) fn retained_pool_rooms(&self) -> std::collections::BTreeSet<Digest32> {
        self.pool_admission
            .keys()
            .map(|(room, _, _)| *room)
            .collect()
    }

    fn wait_for_pool(
        &mut self,
        next_token: &mut u64,
        waiting: PoolWait,
        job: &crate::node::history_budget::Job,
        refused_at: &crate::node::history_budget::FlowReleaseEdge,
    ) -> Result<(), crate::node::history_budget::FlowWaitError> {
        let key = waiting.key;
        let (room, peer, service) = (key.room, key.peer, key.service);
        if self.pool_admission.contains_key(&(room, peer, service)) {
            return Ok(());
        }
        let token = *next_token;
        *next_token += 1;
        let ticket = job.flow_wait_ticket(
            (room, peer, service.slot()),
            key.request,
            key.instance,
            token,
            refused_at,
        )?;
        self.pool_admission.insert(
            (room, peer, service),
            PoolAdmission {
                token,
                gate: waiting.gate,
                root: waiting.root,
                lane: waiting.lane,
                key,
                ticket,
                handed_off: false,
            },
        );
        Ok(())
    }
    /// Retiring work stays inside the same twelve-flow limit and retains its charge/lease.
    /// Other rooms may progress while one room waits for its next bounded cleanup slice.
    fn local_flow_count(&self) -> usize {
        self.ready.iter().flatten().count()
            + self.running.iter().flatten().count()
            + self.deferred.len()
            + self.retiring.len()
            + usize::from(self.cleanup.is_some())
    }
    fn flow_count(&self) -> usize {
        self.local_flow_count() + self.detached_flows.load(Ordering::Acquire)
    }
    fn can_retain_new(&self, service: OutboundService) -> bool {
        let count = self.flow_count();
        if count >= RETAINED_FLOW_LIMIT {
            return false;
        }
        if count + 1 < RETAINED_FLOW_LIMIT {
            return true;
        }
        // The last unowned retained position remains available to the other physical family.
        // An opaque detached/cleanup owner is not evidence that its opportunity is available.
        self.ready
            .iter()
            .flatten()
            .chain(self.deferred.iter())
            .chain(self.retiring.iter())
            .any(|flow| flow.service.slot() != service.slot())
            || self
                .running
                .iter()
                .flatten()
                .any(|running| running.slot != service.slot())
    }
    pub(super) fn physical_available(&self, service: OutboundService) -> bool {
        self.running[service.slot().index()].is_none()
    }

    pub(super) fn background_preference(&self) -> OutboundService {
        self.background_next.unwrap_or(OutboundService::Private)
    }

    pub(super) fn note_background_started(&mut self, service: OutboundService) {
        match service {
            OutboundService::Private => self.background_next = Some(OutboundService::Archive),
            OutboundService::Archive => self.background_next = Some(OutboundService::Private),
            OutboundService::Public => {}
        }
    }

    fn dispose(&mut self, flow: Flow) {
        // Exclusive ownership moves to the retirement queue. Its only permitted next work is
        // Flow::retire_slice's exact local cleanup; that slice cancels every capability before
        // returning. Controller::fence still cancels queued cleanup immediately on node lock.
        self.retiring.push_back(flow);
        self.poll_cleanup();
    }
    fn accept_retirement_slice(
        &mut self,
        flow: Flow,
        outcome: crate::error::Result<RetirementStep>,
    ) -> crate::error::Result<()> {
        let key = retirement_key(&flow);
        match outcome {
            Ok(RetirementStep::Done) => {
                self.retirement_waiting.remove(&key);
                self.retirement_failed.remove(&key);
                clear_retirement_error(&self.retirement_ledger, key);
            }
            Ok(RetirementStep::Progress) => self.retiring.push_back(flow),
            Ok(RetirementStep::Wait(wait)) => {
                self.wait_for_retirement(key, Box::pin(wait.released()), false);
                self.retiring.push_back(flow);
            }
            Err(error) => {
                note_retirement_error(&self.retirement_ledger, key, &error.to_string());
                self.retirement_failed.insert(key);
                self.wait_for_retirement(key, flow.retirement_erasure(), true);
                self.retiring.push_back(flow);
                return Err(error);
            }
        }
        Ok(())
    }
    fn wait_for_retirement(
        &mut self,
        key: RetirementKey,
        wait: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>,
        recover: bool,
    ) {
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&ready);
        let wake = self.completion_wake();
        let changed = Arc::clone(&self.retirement_changed);
        let task = tokio::spawn(async move {
            wait.await;
            flag.store(true, Ordering::Release);
            changed.notify_one();
            wake.notify_one();
        });
        self.retirement_waiting.insert(
            key,
            RetirementWaiting {
                ready,
                recover,
                task,
            },
        );
    }
    fn poll_cleanup(&mut self) {
        self.retirement_waiting.retain(|key, waiting| {
            if !waiting.ready.load(Ordering::Acquire) {
                return true;
            }
            if waiting.recover {
                self.retirement_failed.remove(key);
            }
            false
        });
        if let Some(cleanup) = &self.cleanup {
            let result = cleanup
                .result
                .lock()
                .ok()
                .and_then(|mut value| value.take());
            // Completion is published before its notification. The task's final return may
            // race this actor wake, so JoinHandle::is_finished is not the causal predicate.
            if result.is_none() && !cleanup.task.is_finished() {
                return;
            }
            let flow = cleanup
                .flow
                .try_lock()
                .ok()
                .and_then(|mut flow| flow.take());
            let Some(cleanup) = self.cleanup.take() else {
                return;
            };
            if let Some(flow) = flow {
                if let Err(error) = self.accept_retirement_slice(
                    flow,
                    result.unwrap_or(Err(crate::error::Error::Profile(
                        "history retirement worker stopped",
                    ))),
                ) {
                    eprintln!("vox: history retirement is pending: {error}");
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
            let key = retirement_key(candidate);
            !self.retirement_waiting.contains_key(&key)
                && !self.retirement_failed.contains(&key)
                && awaited_publications.iter().any(|(waiting_room, owner)| {
                    *waiting_room == candidate.room && candidate.owns_request(*owner)
                })
        });
        let Some(at) = owner.or_else(|| {
            self.retiring.iter().position(|candidate| {
                let key = retirement_key(candidate);
                !self.retirement_waiting.contains_key(&key)
                    && !self.retirement_failed.contains(&key)
            })
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
        let changed = Arc::clone(&self.retirement_changed);
        let worker = tokio::spawn(async move {
            {
                let mut flow = task_flow.lock().await;
                match flow.as_mut() {
                    Some(flow) => flow.retire_slice().await,
                    None => Err(crate::error::Error::Profile(
                        "history retirement owner vanished",
                    )),
                }
            }
        });
        let task = tokio::spawn(async move {
            let outcome = worker.await.unwrap_or(Err(crate::error::Error::Profile(
                "history retirement worker stopped",
            )));
            if let Ok(mut result) = output.lock() {
                *result = Some(outcome);
            }
            changed.notify_one();
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
                self.accept_retirement_slice(
                    flow,
                    result.unwrap_or_else(|| {
                        Err(crate::error::Error::Profile(if joined.is_err() {
                            "history retirement worker stopped"
                        } else {
                            "history retirement result vanished"
                        }))
                    }),
                )?;
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
    async fn drain_retiring(&mut self, room: Option<Digest32>) -> crate::error::Result<()> {
        loop {
            // Enable before examining results/eligibility, closing worker/waiter completion
            // races. A blocked waiter owns no cleanup slot; another exact owner can run now.
            let mut wake = Box::pin(Arc::clone(&self.retirement_changed).notified_owned());
            wake.as_mut().enable();
            self.poll_cleanup();
            let selected = |flow: &Flow| room.is_none_or(|room| flow.room == room);
            if self
                .retiring
                .iter()
                .filter(|flow| selected(flow))
                .any(|flow| self.retirement_failed.contains(&retirement_key(flow)))
            {
                // The exact storage error remains in the shipped retirement ledger.
                return Err(crate::error::Error::Profile(
                    "history retirement requires recovery; see status",
                ));
            }
            let pending = self.retiring.iter().any(selected)
                || self
                    .cleanup
                    .as_ref()
                    .is_some_and(|cleanup| room.is_none_or(|room| cleanup.key.room == room));
            if !pending {
                return Ok(());
            }
            wake.await;
            tokio::task::yield_now().await;
        }
    }
    fn take_room(&mut self, room: Digest32) -> Self {
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
        let waiting: Vec<PortKey> = self
            .local_admission
            .keys()
            .filter(|(waiting_room, _, _)| *waiting_room == room)
            .copied()
            .collect();
        for (room, peer, service) in waiting {
            self.cancel_local_admission(room, peer, service);
        }
        self.byte_admission
            .retain(|(waiting_room, _, _, _), admission| {
                let keep = *waiting_room != room;
                if !keep {
                    admission.task.abort();
                }
                keep
            });
        let waiting: Vec<PortKey> = self
            .pool_admission
            .keys()
            .filter(|(waiting_room, _, _)| *waiting_room == room)
            .copied()
            .collect();
        for (room, peer, service) in waiting {
            self.cancel_pool_admission_for(room, peer, service);
        }
        let mut retired = Self {
            running: std::array::from_fn(|_| None),
            ready: std::array::from_fn(|_| None),
            background_next: None,
            archive_admission: None,
            foreground_admission: std::array::from_fn(|_| None),
            local_admission: BTreeMap::new(),
            byte_admission: BTreeMap::new(),
            pool_admission: BTreeMap::new(),
            deferred: VecDeque::new(),
            body_slots: Arc::clone(&self.body_slots),
            required: VecDeque::new(),
            retiring: VecDeque::new(),
            cleanup: None,
            retirement_waiting: BTreeMap::new(),
            retirement_failed: BTreeSet::new(),
            retirement_changed: Arc::clone(&self.retirement_changed),
            retirement_ledger: Arc::clone(&self.retirement_ledger),
            completion_wake: Arc::clone(&self.completion_wake),
            detached_flows: Arc::clone(&self.detached_flows),
        };
        for slot in &mut self.ready {
            if let Some(flow) = slot.take_if(|flow| flow.room == room) {
                retired.retiring.push_back(flow);
            }
        }
        let mut keep = VecDeque::new();
        while let Some(flow) = self.deferred.pop_front() {
            if flow.room == room {
                retired.retiring.push_back(flow);
            } else {
                keep.push_back(flow);
            }
        }
        self.deferred = keep;
        for (index, slot) in self.running.iter_mut().enumerate() {
            if let Some(work) = slot.take_if(|work| work.room == room) {
                work.fence.retire();
                retired.running[index] = Some(work);
            }
        }
        let mut keep = VecDeque::new();
        while let Some(flow) = self.retiring.pop_front() {
            if flow.room == room {
                retired.retiring.push_back(flow);
            } else {
                keep.push_back(flow);
            }
        }
        self.retiring = keep;
        if self
            .cleanup
            .as_ref()
            .is_some_and(|cleanup| cleanup.key.room == room)
        {
            retired.cleanup = self.cleanup.take();
        }
        let waiting: Vec<_> = self
            .retirement_waiting
            .keys()
            .filter(|key| key.room == room)
            .copied()
            .collect();
        for key in waiting {
            if let Some(waiting) = self.retirement_waiting.remove(&key) {
                retired.retirement_waiting.insert(key, waiting);
            }
        }
        let failed: Vec<_> = self
            .retirement_failed
            .iter()
            .filter(|key| key.room == room)
            .copied()
            .collect();
        for key in failed {
            self.retirement_failed.remove(&key);
            retired.retirement_failed.insert(key);
        }
        self.required.retain(|required| required.room != room);
        retired
    }

    fn restore_room_retirement(&mut self, retired: &mut Self) {
        self.retiring.append(&mut retired.retiring);
        self.retirement_waiting
            .append(&mut retired.retirement_waiting);
        self.retirement_failed
            .append(&mut retired.retirement_failed);
    }

    /// A physical archive Flow carries its own fence; its scalar request may have been reused.
    pub(super) fn physical_archive_for_port(
        &self,
        room: Digest32,
        peer: Digest32,
    ) -> Option<(
        stream::RequestId,
        Digest32,
        Arc<crate::transport::stream_transport::Fence>,
    )> {
        self.ready
            .iter()
            .flatten()
            .find(|flow| flow.room == room && flow.peer == peer && flow.archive)
            .and_then(|flow| {
                Some((
                    flow.archive_request?,
                    flow.generation,
                    Arc::clone(flow.request_fence.as_ref()?),
                ))
            })
            .or_else(|| {
                self.running
                    .iter()
                    .flatten()
                    .find(|work| work.room == room && work.peer == peer && work.archive.is_some())
                    .and_then(|work| {
                        work.archive.map(|(request, generation)| {
                            (request, generation, Arc::clone(&work.fence))
                        })
                    })
            })
    }

    /// Admission is separate from a physical Flow; its owner includes the room incarnation.
    pub(super) fn archive_admission_for_port(
        &self,
        room: Digest32,
        peer: Digest32,
    ) -> Option<(stream::RequestId, Digest32, [u8; 16])> {
        self.archive_admission
            .as_ref()
            .filter(|admission| admission.room == room && admission.peer == peer)
            .map(|admission| (admission.request, admission.generation, admission.instance))
    }

    pub(super) fn retire_port(&mut self, room: Digest32, peer: Digest32) {
        if self
            .archive_admission
            .as_ref()
            .is_some_and(|admission| admission.room == room && admission.peer == peer)
        {
            self.cancel_archive_admission();
        }
        for service in [
            OutboundService::Public,
            OutboundService::Private,
            OutboundService::Archive,
        ] {
            self.cancel_foreground_port(room, peer, service);
            self.cancel_local_admission(room, peer, service);
            self.cancel_byte_admission(room, peer, service);
            self.cancel_pool_admission_for(room, peer, service);
        }
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
        self.retirement_waiting.clear();
        // Fencing revokes network work; it is not recovery of a failed storage operation.
        // Keep exact failures until teardown transfers their owners to ledger key erasure.
        self.cancel_archive_admission();
        for index in 0..self.foreground_admission.len() {
            self.cancel_foreground_admission(index);
        }
        for (_, admission) in std::mem::take(&mut self.local_admission) {
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
    fn transfer_failed_retirements(&mut self) {
        let mut keep = VecDeque::new();
        while let Some(flow) = self.retiring.pop_front() {
            let key = retirement_key(&flow);
            if self.retirement_failed.remove(&key) {
                self.retirement_waiting.remove(&key);
                // No slice may run first: this Flow can hold a superseded, still-unlocked
                // room Arc which the current actor's room map no longer contains.
                spawn_owed_retirement(flow, Arc::clone(&self.retirement_ledger), true);
            } else {
                keep.push_back(flow);
            }
        }
        self.retiring = keep;
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
        // Joining may itself publish a new exact failure. Transfer both earlier failures and
        // that result before drain_retiring/poll_cleanup can dispatch another storage slice.
        self.transfer_failed_retirements();
        if let Err(error) = self.drain_retiring(None).await {
            eprintln!("vox: history retirement is pending: {error}");
            // Join any different bounded cleanup already dispatched before moving its peers
            // to the daemon ledger. Its real worker/secret leases cannot outlive ownership.
            let _ = self.join_cleanup().await;
            self.retirement_waiting.clear();
            while let Some(flow) = self.retiring.pop_front() {
                let failed = self.retirement_failed.contains(&retirement_key(&flow));
                spawn_owed_retirement(flow, Arc::clone(&self.retirement_ledger), failed);
            }
        }
    }

    fn cancel_work_admissions(&mut self, key: WorkKey) {
        for index in 0..self.foreground_admission.len() {
            if self.foreground_admission[index]
                .as_ref()
                .is_some_and(|admission| admission.key == Some(key))
            {
                self.cancel_foreground_admission(index);
            }
        }
        let port = (key.room, key.peer, key.service);
        if self
            .local_admission
            .get(&port)
            .is_some_and(|admission| admission.key == Some(key))
        {
            self.cancel_local_admission(key.room, key.peer, key.service);
        }
        self.byte_admission.retain(|_, admission| {
            let keep = admission.owner != Some(key);
            if !keep {
                admission.task.abort();
            }
            keep
        });
        if self
            .pool_admission
            .get(&port)
            .is_some_and(|admission| admission.key == key)
        {
            self.cancel_pool_admission_for(key.room, key.peer, key.service);
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
        if self.ready[OutboundService::Archive.index()]
            .as_ref()
            .is_some_and(|flow| {
                flow.service == OutboundService::Archive
                    && flow.room == room
                    && flow.instance == instance
                    && flow.archive_request == Some(request)
            })
        {
            if let Some(flow) = self.ready[OutboundService::Archive.index()].take() {
                self.cancel_work_admissions(WorkKey::of(&flow));
                self.dispose(flow);
            }
        }
        let mut keep = VecDeque::new();
        while let Some(flow) = self.deferred.pop_front() {
            if flow.service == OutboundService::Archive
                && flow.room == room
                && flow.instance == instance
                && flow.archive_request == Some(request)
            {
                self.cancel_work_admissions(WorkKey::of(&flow));
                self.retiring.push_back(flow);
            } else {
                keep.push_back(flow);
            }
        }
        self.deferred = keep;
        if let Some(work) = self.running[PhysicalSlot::Background.index()]
            .as_ref()
            .filter(|work| {
                work.service == OutboundService::Archive
                    && work.room == room
                    && work.retirement_key.instance == instance
                    && work
                        .archive
                        .is_some_and(|(running_request, _)| running_request == request)
            })
        {
            work.fence.retire();
        }
        self.poll_cleanup();
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
                    .send(NetEvent::BoundedAdmissionReady {
                        token: wake_token,
                        room,
                        peer,
                        service: OutboundService::Archive,
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
                .send(NetEvent::BoundedAdmissionReady {
                    token: wake_token,
                    room,
                    peer,
                    service: OutboundService::Archive,
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
        work: AdmissionWork,
    ) -> ForegroundTurn {
        let AdmissionWork {
            root,
            lane,
            service,
            key,
            demand,
        } = work;
        let index = foreground_index(service, lane);
        if let Some(admission) = self.foreground_admission[index].as_ref() {
            if admission.room != room || admission.peer != peer || admission.lane != lane {
                return ForegroundTurn::Waiting;
            }
            if admission
                .key
                .zip(key)
                .is_some_and(|(old, current)| old != current)
            {
                self.cancel_foreground_admission(index);
            }
        }
        if let Some(mut admission) = self.foreground_admission[index].take() {
            if key.is_some() {
                admission.key = key;
            }
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
                    .send(NetEvent::BoundedForegroundReady {
                        token: wake_token,
                        room,
                        peer,
                        service,
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
                .send(NetEvent::BoundedForegroundReady {
                    token: wake_token,
                    room,
                    peer,
                    service,
                })
                .await;
        });
        self.foreground_admission[index] = Some(ForegroundAdmission {
            token: wake_token,
            room,
            peer,
            root,
            lane,
            service,
            key,
            demand,
            ticket,
            task,
        });
        ForegroundTurn::Waiting
    }
}
/// Removing a parked scalar is not permission to start inventory. The bounded inbox
/// itself is scheduler need, so continue to another eligible hint without raising a request.
fn take_foreground_hint(
    inbox: &stream::HintInbox,
    room: Digest32,
    peer: Digest32,
    node: Digest32,
    parked_receipt: Option<Digest32>,
    connection: Option<u64>,
) -> Option<stream::HeadHint> {
    // Inbound producers may replenish the inbox while this scalar selection runs.
    // Bound this turn by the existing inventory quantum; remaining hints keep their
    // ordinary inbox/port-queue ownership and their producer's completion wake.
    for _ in 0..crate::log::history::MAX_CONTEXT_AUTHORS {
        let (hint, role_signal, role_connection) = inbox.take(room, peer, node)?;
        if (role_signal && role_connection != connection)
            || (!role_signal && hint.author == node && parked_receipt == Some(hint.head))
        {
            inbox.finish(room, peer, hint.author, hint.head);
        } else {
            return Some(hint);
        }
    }
    None
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
    /// A previously unavailable own body can become readable after its receiver changes.
    /// Spend that edge once per donor and exact staged position; the normal Page still checks
    /// its grant and settles the sparse effect before any role-complete receipt advances.
    pub(super) fn retry_readable_own_effect(&mut self, room: Digest32) {
        let current = self
            .channels
            .get(&room)
            .zip(self.own_readable_effects.get(&room))
            .is_some_and(|(channel, ready)| {
                ready
                    .instance
                    .upgrade()
                    .is_some_and(|held| Arc::ptr_eq(channel, &held))
            });
        if !current {
            self.own_readable_effects.remove(&room);
            return;
        }
        let Some(ready) = self.own_readable_effects.get_mut(&room) else {
            return;
        };
        let mut woken = false;
        for ((id, peer), port) in &mut self.ports {
            if *id == room
                && !ready.woken.contains(peer)
                && port.own_recovery_parked.take().is_some()
            {
                ready.woken.insert(*peer);
                port.own_recovery_checked = false;
                woken = true;
            }
        }
        if woken {
            self.sched_rooms.insert(room);
        }
    }

    /// Name the exact bounded root whose next attempt is stopped before a `Flow` exists. This
    /// mirrors the starter's selection order so status can identify a retained admission rather
    /// than reporting only that some port is waiting.
    pub(super) fn bounded_pending_identity(
        &self,
        room: Digest32,
        peer: Digest32,
        service: OutboundService,
    ) -> AdmissionWork {
        use crate::node::history_budget::Lane;
        if let Some(flow) = self
            .bounded_sync
            .ready
            .iter()
            .flatten()
            .chain(self.bounded_sync.deferred.iter())
            .find(|flow| flow.room == room && flow.peer == peer && flow.service == service)
        {
            return AdmissionWork::from_flow(flow);
        }
        if service == OutboundService::Private {
            return AdmissionWork::unowned("required", Lane::Control, service);
        }
        if service == OutboundService::Archive {
            return AdmissionWork::unowned("archive", Lane::Archive, service);
        }
        if self
            .ports
            .get(&(room, peer))
            .is_some_and(crate::node::ports::Port::announce_owed)
        {
            return AdmissionWork::unowned("inventory", Lane::Control, service);
        }
        if self
            .bounded_sync
            .required
            .iter()
            .any(|required| required.room == room && required.peer == peer)
        {
            return AdmissionWork::unowned("required", Lane::Control, service);
        }
        if self
            .leave_waiters
            .iter()
            .any(|(left_room, generation, _, _, _)| {
                *left_room == room
                    && self
                        .ports
                        .get(&(room, peer))
                        .is_some_and(|port| port.done_gen >= *generation)
            })
        {
            return AdmissionWork::unowned("departure", Lane::Control, service);
        }
        if self.history_hints.pending(room, peer) {
            return AdmissionWork::unowned("hint", Lane::Control, service);
        }
        AdmissionWork::unowned("inventory", Lane::Control, service)
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
                self.drop_departed_port(&room, &peer);
            }
            return;
        }

        self.bounded_sync.retire_port(room, peer);
        self.history_hints.retire_port(room, peer);
        let mut retired = Vec::new();
        if let Some(port) = self.ports.get_mut(&(room, peer)) {
            retired.extend(port.out.take_all().map(|out| out.attempt));
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
            port.queued = [false; 3];
            port.poisoned = true;
        }
        for attempt in retired {
            attempt.retire();
        }
        for queue in &mut self.port_queue {
            queue.remove(&room, &peer);
        }
    }

    /// Detach exact physical owners before the existing lifecycle gate task waits for them.
    pub(super) fn take_bounded_room(
        &mut self,
        room: Digest32,
        retire_inbound: bool,
    ) -> RoomRetirement {
        let attempts = self
            .bounded_sync
            .running
            .iter()
            .flatten()
            .filter(|work| work.room == room)
            .map(|work| (work.peer, work.token))
            .collect();
        let driver = self.bounded_sync.take_room(room);
        let held = driver.local_flow_count();
        let charge = if held == 0 {
            None
        } else {
            self.bounded_sync
                .detached_flows
                .fetch_add(held, Ordering::AcqRel);
            Some(DetachedFlowCharge {
                count: Arc::clone(&self.bounded_sync.detached_flows),
                held,
            })
        };
        let inbound = if retire_inbound {
            self.ports
                .iter()
                .filter(|((id, _), _)| *id == room)
                .flat_map(|((_, peer), port)| {
                    port.inbound.iter().map(move |(token, attempt)| {
                        (
                            *peer,
                            *token,
                            Arc::clone(&attempt.fence),
                            attempt.abort.clone(),
                        )
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        RoomRetirement {
            driver,
            room,
            epoch: self.delivery_epoch,
            instance: self.channels.get(&room).map(Arc::downgrade),
            attempts,
            inbound,
            _charge: charge,
        }
    }

    /// Only a matching physical terminal can retire its captured actor attempt token.
    pub(super) fn finish_bounded_room_retirement(
        &mut self,
        retired: RetiredRoom,
        gate_retired: bool,
    ) -> crate::error::Result<()> {
        let RetiredRoom { mut owned, result } = retired;
        let current = owned.epoch == self.delivery_epoch
            && match owned.instance.as_ref() {
                Some(instance) => instance.upgrade().is_some_and(|instance| {
                    self.channels
                        .get(&owned.room)
                        .is_some_and(|current| Arc::ptr_eq(current, &instance))
                }),
                None => !self.channels.contains_key(&owned.room),
            };
        if current {
            self.bounded_sync.restore_room_retirement(&mut owned.driver);
            for (peer, token) in &owned.attempts {
                if let Some(attempt) = self
                    .ports
                    .get_mut(&(owned.room, *peer))
                    .and_then(|port| port.out.take_token(*token))
                {
                    attempt.attempt.retire();
                }
            }
            if result.is_ok() && gate_retired {
                for (peer, token, _, _) in &owned.inbound {
                    if let Some(attempt) = self
                        .ports
                        .get_mut(&(owned.room, *peer))
                        .and_then(|port| port.inbound.remove(token))
                    {
                        attempt.retire();
                    }
                }
            }
        }
        // A stale driver's Drop retains its remaining exact debt in the existing daemon ledger.
        result
    }

    /// A flow whose start ended before its round retains the exact work already consumed while
    /// constructing it: an archive dispatch, required dependency, or scalar hint. Park it in its
    /// lane so the relevant admission/release event retries that same work; reconstructing only a
    /// hint loses the other two forms and can leave a shipped archive request marked running.
    fn shelve_exact(&mut self, mut flow: Flow, _index: usize) {
        flow.park();
        let key = WorkKey::of(&flow);
        if self
            .bounded_sync
            .pool_admission
            .get(&(key.room, key.peer, key.service))
            .is_some_and(|admission| admission.key == key && admission.ticket.granted())
        {
            // This exact owner cannot use its promise at an earlier gate. Keep its Flow and
            // real release waiter, but let another eligible Background owner take capacity.
            self.bounded_sync
                .cancel_pool_admission_for(key.room, key.peer, key.service);
        }
        let index = flow.service.index();
        if self.bounded_sync.ready[index].is_none() {
            self.bounded_sync.ready[index] = Some(flow);
        } else {
            self.bounded_sync.deferred.push_back(flow);
        }
    }

    fn rearm_required(&mut self, flow: &Flow) {
        let Some((head, seq)) = flow.required_root else {
            return;
        };
        let live = self
            .channels
            .get(&flow.room)
            .is_some_and(|room| Arc::ptr_eq(room, &flow.shared))
            && self
                .ports
                .get(&(flow.room, flow.hint_peer))
                .is_some_and(|port| !port.poisoned);
        if !live {
            return;
        }
        let need = RequiredOwner {
            room: flow.room,
            peer: flow.hint_peer,
            head,
            seq,
            request: flow
                .required_owner_request
                .unwrap_or(flow.retirement_request()),
            instance: flow.instance,
        };
        if !self.bounded_sync.required.contains(&need) {
            self.bounded_sync.required.push_front(need);
            self.sched_rooms.insert(flow.room);
        }
    }

    /// Abandoning a flow retires its local capabilities, not the unauthoritative scalar hint it
    /// selected. Re-arm that exact hint while its inbox scope is still live; room/peer retirement
    /// removes it first, making this a no-op for teardown rather than leaving an in-flight orphan.
    fn dispose_rearming_hint(&mut self, mut flow: Flow) {
        self.rearm_required(&flow);
        if let Some(hint) = flow.hint.take().filter(|_| !flow.local_own_root()) {
            self.history_hints
                .retry(flow.room, flow.hint_peer, hint.author, hint.head);
        }
        self.bounded_sync.dispose(flow);
    }

    /// Settle the exact archive operation before retiring a Flow which can no longer return
    /// through its port attempt. A durable More/Complete/Paused checkpoint owns the result even
    /// if the connection retires just before actor acceptance; otherwise the same saved request
    /// becomes Paused and requires the person's explicit Resume.
    fn settle_archive_exit(&mut self, flow: &mut Flow, failure: &str) -> bool {
        let Some(request) = flow.archive_request else {
            return false;
        };
        let Some(fence) = flow.request_fence.as_ref() else {
            return false;
        };
        if !self
            .history_demand
            .owns_running_fence(request, flow.generation, fence)
        {
            return false;
        }
        if let Some(status) = flow.archive_status.take() {
            if self.history_demand.completed_current(
                flow.room,
                flow.instance,
                request,
                flow.generation,
                status,
            ) {
                return true;
            }
        }
        self.history_demand.failed_current(
            flow.room,
            flow.instance,
            request,
            flow.generation,
            failure,
        )
    }

    /// Resume the exact retained Flow that owns a durable room publication. A waiter knows the
    /// request identity from disk; routing that causal edge to the owner's port avoids both a
    /// room-wide wake storm and retrying the waiter while the only productive Flow sleeps.
    fn wake_publication_owner(&mut self, room: Digest32, owner: RequestId) {
        let mut target = None;
        if let Some(flow) = self
            .bounded_sync
            .ready
            .iter_mut()
            .flatten()
            .find(|flow| flow.room == room && flow.owns_request(owner))
        {
            flow.waiting = false;
            target = Some((flow.peer, flow.service));
        } else if let Some(at) = self
            .bounded_sync
            .deferred
            .iter()
            .position(|flow| flow.room == room && flow.owns_request(owner))
        {
            if let Some(mut flow) = self.bounded_sync.deferred.remove(at) {
                flow.waiting = false;
                target = Some((flow.peer, flow.service));
                let index = flow.service.index();
                if let Some(displaced) = self.bounded_sync.ready[index].replace(flow) {
                    self.bounded_sync.deferred.push_front(displaced);
                }
            }
        }
        if let Some((peer, service)) = target {
            if let Some(port) = self.ports.get_mut(&(room, peer)) {
                if service == OutboundService::Public {
                    port.raise();
                }
                port.clear_service_backoff(service);
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
            let Some(returned) = returned else {
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
            debug_assert_eq!(work.slot.index(), index);
            debug_assert_eq!(work.service.slot(), work.slot);
            debug_assert_eq!(flow.service, work.service);
            // These facts were committed by the worker before it returned. Account for them
            // before deciding whether its attempt is still current: cancellation, retirement,
            // an error after the store callback, or a newer scalar head must not turn durable
            // work into a false zero in the user-visible lane.
            let fetched = u64::from(
                flow.work_committed
                    .swap(false, std::sync::atomic::Ordering::AcqRel),
            );
            if flow.own_head_observed.swap(false, Ordering::AcqRel)
                && self
                    .channels
                    .get(&work.room)
                    .is_some_and(|room| Arc::ptr_eq(room, &flow.shared))
            {
                // The physical callback committed this narrowing knowledge. A later wire
                // error, cancellation or changed peer grant cannot erase it; a replacement
                // room must never receive it. Reuse the existing bounded governance owner.
                self.governance_work.wake_room(work.room);
            }
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
                .is_some_and(|port| {
                    if port
                        .out
                        .get_token_mut(work.token)
                        .is_some_and(|out| out.service == work.service)
                    {
                        port.out.take_token(work.token).is_some()
                    } else {
                        false
                    }
                });
            // The physical Background position is free on every returned outcome, including
            // stale, failed and local-retry exits. Reconsider only the eligible opposite service;
            // this is a capacity wake, not Public request or generation credit.
            let background_sibling = match work.service {
                OutboundService::Public => None,
                OutboundService::Private => Some(OutboundService::Archive),
                OutboundService::Archive => Some(OutboundService::Private),
            };
            if background_sibling.is_some_and(|service| {
                self.port_eligible(&(work.room, work.peer), service, std::time::Instant::now())
            }) {
                self.sched_rooms.insert(work.room);
            }
            let valid = current
                && !work.fence.is_retired()
                && self
                    .channels
                    .get(&work.room)
                    .is_some_and(|room| Arc::ptr_eq(room, &flow.shared));
            if valid {
                if let Some(response) = flow.unavailable_response.take() {
                    if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                        port.last_recorded_unavailable_response = Some(response);
                    }
                }
                // An older completed inventory cannot clear a newer role obligation. Audit
                // the current owner after the physical worker exits and keep its port ready.
                if let Some(owner) = self.role_wake.owner(work.room) {
                    if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                        port.role_owed = owner.pending(work.peer);
                        port.key_catalog_owed = owner.key_catalog_announcement(work.peer).is_some();
                        if port.role_owed || port.key_catalog_owed {
                            self.sched_rooms.insert(work.room);
                        }
                    }
                }
                if let Some(token) = flow.availability_ack.take() {
                    if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                        let current_connection = self
                            .net
                            .as_ref()
                            .and_then(|net| net.manager().existing(&work.peer))
                            .is_some_and(|c| {
                                c.serial() == flow.availability_connection
                                    && c.supports_availability()
                            });
                        if current_connection
                            && port.availability_acked.is_none_or(|old| old < token)
                        {
                            port.availability_connection = Some(flow.availability_connection);
                            port.availability_acked = Some(token);
                        }
                    }
                }
                if let Some(hint) = flow.hint {
                    if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                        let scope = |connection| crate::node::ports::SupportDiscovery {
                            connection,
                            instance: flow.instance,
                            epoch: flow.epoch,
                            authorization: flow.generation,
                        };
                        if let Some(((connection, availability), incarnations)) = flow
                            .discovery_unavailable
                            .take()
                            .zip(flow.discovery_incarnations)
                        {
                            if port.availability.remote(connection) == availability {
                                port.support_discovery_unavailable =
                                    Some(crate::node::ports::OwnProbe {
                                        scope: scope(connection),
                                        head: hint.head,
                                        incarnations,
                                    });
                            }
                        }
                        if let Some((connection, incarnations)) = flow.receipt_lower.take() {
                            port.own_receipt_lower = Some(crate::node::ports::OwnProbe {
                                scope: scope(connection),
                                head: hint.head,
                                incarnations,
                            });
                        }
                    }
                }
            }
            // Authorization and local-durability exits carry ownership themselves. Handle them
            // even when the trust edit also retired the port/fence; generic stale disposal would
            // otherwise discard the only hint, required root, or archive controller dispatch.
            if flow.authorization_changed || flow.local_retry.is_some() {
                if let Some(seq) = flow.mine_held.take() {
                    self.held_notes.push((work.room, work.peer, seq));
                }
                if flow.admitted_authors > 0 {
                    flow.admitted_authors = 0;
                    self.role_wake.board_growth(work.room);
                    let _ = self.net_tx.try_send(NetEvent::BoardGrew {
                        channel_id: work.room,
                    });
                }
                if flow.published {
                    flow.published = false;
                    if flow.governance {
                        #[cfg(feature = "test-knobs")]
                        super::governance::ready_sweep_after(&work.room);
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
                    if let Some(owner) = flow.required_owner_request {
                        self.wake_publication_owner(work.room, owner);
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
                if let Some(token) = flow.key_body_token.as_ref() {
                    if let Some(port) = self.ports.get_mut(&(work.room, flow.hint_peer)) {
                        if port
                            .key_body_token
                            .as_ref()
                            .is_some_and(|owner| Arc::ptr_eq(owner, token))
                        {
                            port.key_body = None;
                            port.key_body_instance = None;
                            port.key_body_token = None;
                            port.key_body_after = None;
                            port.key_body_initialized = false;
                        }
                    }
                }
                let archive = flow.archive_request.and_then(|request| {
                    let fence = flow.request_fence.as_ref()?;
                    if !self.history_demand.owns_running_fence(request, flow.generation, fence) {
                        return None;
                    }
                    let other_resume = self.history_demand.has_other_resume(work.room, flow.instance, request);
                    let detail = if other_resume {
                        "Authorization changed; the saved history request can be resumed."
                    } else {
                        "Authorization changed while this history page was running; the exact request is being resumed."
                    };
                    self.history_demand.failed_current(
                        work.room,
                        flow.instance,
                        request,
                        flow.generation,
                        detail,
                    ).then_some((request, flow.instance)).filter(|_| !other_resume)
                });
                if let Some(hint) = flow.hint.filter(|_| !flow.local_own_root()) {
                    self.history_hints
                        .retry(work.room, flow.hint_peer, hint.author, hint.head);
                }
                if let Some((head, seq)) = flow.required_root {
                    let need = RequiredOwner {
                        room: work.room,
                        peer: flow.hint_peer,
                        head,
                        seq,
                        request: flow
                            .required_owner_request
                            .unwrap_or(flow.retirement_request()),
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
                    if work.service == OutboundService::Public {
                        port.raise();
                    }
                    port.clear_service_backoff(work.service);
                }
                if let Some((request, instance)) = archive {
                    // `failed_current` retired the still-owned running generation. Retain the exact Resume as
                    // its replacement owner before any fallible profile/room/admission preflight;
                    // `schedule` either installs preparation or keeps its fair Control ticket.
                    self.history_demand.owe_resume(work.room, instance, request);
                }
                self.sched_rooms.insert(work.room);
                continue;
            }
            if let Some(error) = flow.local_retry.take() {
                let retry_peer = flow.route_origin.unwrap_or(flow.hint_peer);
                self.settle_archive_exit(&mut flow, &error);
                if let Some(hint) = flow.hint.filter(|_| !flow.local_own_root()) {
                    self.history_hints
                        .retry(work.room, flow.hint_peer, hint.author, hint.head);
                }
                if let Some((head, seq)) = flow.required_root {
                    let need = RequiredOwner {
                        room: work.room,
                        peer: flow.hint_peer,
                        head,
                        seq,
                        request: flow
                            .required_owner_request
                            .unwrap_or(flow.retirement_request()),
                        instance: flow.instance,
                    };
                    if !self.bounded_sync.required.contains(&need) {
                        self.bounded_sync.required.push_front(need);
                    }
                }
                self.bounded_sync.dispose(flow);
                let retry_port = if work.archive.is_none() {
                    self.ports.get_mut(&(work.room, retry_peer))
                } else {
                    None
                };
                if let Some(port) = retry_port {
                    // Keep the exact work requested, but do not immediately schedule it: an
                    // unrelated actor event or the ordinary maintenance pass may retry after the
                    // local store fault clears. Immediate re-scheduling would spin on a durable
                    // local failure, while peer Busy/Unreachable backoff would blame the wire.
                    // An archive request instead stays truthfully Paused under its durable request;
                    // only the person's explicit Resume may authorize another archive quantum.
                    if work.service == OutboundService::Public {
                        port.raise();
                    }
                    port.clear_service_backoff(work.service);
                }
                eprintln!("vox: {error}");
                continue;
            }
            if !valid {
                let failure = returned.failure.as_ref().map_or(
                    "History round ended before completion; resume the saved request explicitly.",
                    |failure| failure.text.as_str(),
                );
                self.settle_archive_exit(&mut flow, failure);
                self.dispose_rearming_hint(flow);
                continue;
            }
            if let Some(receipt) = (work.service == OutboundService::Public)
                .then(|| flow.take_announcement_receipt())
                .flatten()
            {
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
                        counts.consecutive_failures = 0;
                        counts.failing_since = None;
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
                self.role_wake.board_growth(work.room);
                let _ = self.net_tx.try_send(NetEvent::BoardGrew {
                    channel_id: work.room,
                });
            }
            if flow.published {
                flow.published = false;
                // Ordinary content publication has no governance work. The history worker's
                // signed-kind result names the causal control publication that does.
                if flow.governance {
                    #[cfg(feature = "test-knobs")]
                    super::governance::ready_sweep_after(&work.room);
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
                if let Some(owner) = flow.required_owner_request {
                    self.wake_publication_owner(work.room, owner);
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
                            .any(|(room, _, _, _, _)| *room == work.room)
                        || self.bounded_sync.required.iter().any(|required| {
                            required.room == work.room && required.peer == work.peer
                        });
                flow.peer = target;
                flow.route_origin = Some(work.peer);
                flow.route_origin_brought = flow.brought;
                flow.brought = false;
                flow.route_complete = false;
                // The author can be offline. Keep the exact continuation in the
                // peer-selectable deferred queue rather than occupying the single live
                // slot while no connection can run it. A current author port promotes
                // this same flow; unrelated connected peers keep their foreground turn.
                self.bounded_sync.deferred.push_back(flow);
                crate::node::status::SyncBook::with(
                    &self.sync_book,
                    work.room,
                    work.peer,
                    |counts| counts.partial += 1,
                );
                if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                    // Consume only the scheduling request this attempt captured. A later raise
                    // remains greater, and retained work receives a new raise below.
                    if work.service == OutboundService::Public {
                        port.req_done = port.req_done.max(work.request);
                        if more_for_peer {
                            port.raise();
                        }
                    }
                }
                if let Some(port) = self.ports.get_mut(&(work.room, target)) {
                    if work.service == OutboundService::Public {
                        port.raise();
                    }
                    port.clear_service_backoff(work.service);
                } else {
                    self.discover_rooms.insert(work.room);
                }
                crate::node::status::SyncBook::with(&self.sync_book, work.room, target, |counts| {
                    counts.backoff = None
                });
                self.sched_rooms.insert(work.room);
                continue;
            }
            if let Some(failure) = returned.failure {
                let backoff = crate::node::ports::backoff_kind(&failure.classification);
                let retryable_peer_busy = failure.retryable_peer_busy();
                let error = failure.text;
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
                    if let Some(backoff) = backoff {
                        self.enter_backoff(work.room, work.peer, work.service, backoff);
                    }
                    continue;
                }
                if retryable_peer_busy && flow.take_peer_busy_retry() {
                    // The peer named a transient session collision or has not admitted this
                    // just-joined member yet. Keep the exact restored ResumeWire/local owner;
                    // rebuilding from inventory would discard its durable cursor and root.
                    self.shelve_exact(flow, work.service.index());
                    crate::node::status::SyncBook::with(
                        &self.sync_book,
                        work.room,
                        work.peer,
                        |counts| {
                            counts.failed += 1;
                            counts.last_failure = Some(error);
                        },
                    );
                    if let Some(backoff) = backoff {
                        self.enter_backoff(work.room, work.peer, work.service, backoff);
                    }
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
                self.settle_archive_exit(&mut flow, &error);

                if let Some(hint) = flow.hint.filter(|_| !flow.local_own_root()) {
                    if !self.history_hints.retry_role(
                        work.room,
                        flow.hint_peer,
                        hint.author,
                        hint.head,
                    ) {
                        self.history_hints.finish(
                            work.room,
                            flow.hint_peer,
                            hint.author,
                            hint.head,
                        );
                    }
                }
                if !cancelled {
                    self.rearm_required(&flow);
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
                        work.service,
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
                if let Some(backoff) = backoff {
                    self.enter_backoff(work.room, work.peer, work.service, backoff);
                }
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
                    if work.service == OutboundService::Public {
                        port.req_done = port.req_done.max(work.request);
                        if more_for_target {
                            port.raise();
                        }
                    }
                    port.clear_service_backoff(work.service);
                }
                let reason = flow.reason;
                crate::node::status::SyncBook::with(
                    &self.sync_book,
                    work.room,
                    work.peer,
                    |counts| {
                        counts.completed += 1;
                        counts.consecutive_failures = 0;
                        counts.failing_since = None;
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
                self.shelve_exact(flow, work.service.index());
                if let Some(port) = self.ports.get_mut(&(work.room, origin)) {
                    if work.service == OutboundService::Public {
                        port.raise();
                    }
                    port.clear_service_backoff(work.service);
                }
                crate::node::status::SyncBook::with(&self.sync_book, work.room, origin, |counts| {
                    counts.backoff = None
                });
                self.sched_rooms.insert(work.room);
                continue;
            }
            let superseded = !flow.local_own_root()
                && flow.hint.is_some_and(|hint| {
                    self.history_hints.newer_pending(
                        work.room,
                        flow.hint_peer,
                        hint.author,
                        hint.size,
                    )
                });
            if superseded {
                // The worker has returned from its bounded slice, so no in-flight state is
                // mutated. Retire its transient capabilities; signed headers, receipts, cursors
                // and missing-body facts already committed by earlier slices remain durable.
                // `retry` drops this obsolete owner because the inbox holds a newer successor,
                // which resumes the same live window instead of waiting behind up to 128 bodies.
                self.dispose_rearming_hint(flow);
                if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                    if work.service == OutboundService::Public {
                        port.req_done = port.req_done.max(work.request);
                        port.raise();
                    }
                    port.clear_service_backoff(work.service);
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
            if let Some(wake) = flow.slot_wait.take() {
                let mut admission = AdmissionWork::from_flow(&flow);
                admission.lane = crate::node::history_budget::Lane::Control;
                let waiting = ByteWait {
                    owner: Some(WorkKey::of(&flow)),
                    port_request: (work.service == OutboundService::Public).then_some(work.request),
                    wake,
                };
                if work.service == OutboundService::Public {
                    self.bounded_sync.deferred.push_back(flow);
                } else {
                    self.shelve_exact(flow, work.service.index());
                }

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
            if let Some(pressure) = flow.byte_pressure.take() {
                let mut admission = AdmissionWork::from_flow(&flow);
                admission.lane = pressure.lane();
                let waiting = ByteWait {
                    owner: Some(WorkKey::of(&flow)),
                    port_request: (work.service == OutboundService::Public).then_some(work.request),
                    wake: Box::pin(pressure.released()),
                };
                if work.service == OutboundService::Public {
                    self.bounded_sync.deferred.push_back(flow);
                } else {
                    self.shelve_exact(flow, work.service.index());
                }
                // The worker has finished and parked: neither this future nor the retained
                // Flow owns reconstruction buffers or a worker slot. Subscribe/recheck the
                // full retry peak, without turning byte pressure into a timed Busy retry.

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
                        if port
                            .backoff(crate::node::ports::BackoffScope::Service(work.service))
                            .is_some_and(|backoff| {
                                backoff.kind == crate::node::status::BackoffKind::Busy
                            })
                        {
                            port.clear_service_backoff(work.service);
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
                if let Some(owner) = flow.required_owner_request {
                    self.wake_publication_owner(work.room, owner);
                }
                if let Some(token) = flow.key_availability_token.as_ref() {
                    if let Some(port) = self.ports.get_mut(&(work.room, flow.hint_peer)) {
                        if port
                            .key_availability_request
                            .as_ref()
                            .is_some_and(|(_, owner, _, _)| Arc::ptr_eq(owner, token))
                        {
                            if let (Some((_, _, expected_instance, tip)), Some((instance, page))) = (
                                port.key_availability_request.take(),
                                flow.key_availability_result.take(),
                            ) {
                                port.key_availability_page =
                                    Some((expected_instance, tip, instance, page));
                                port.key_body_initialized = false;
                                self.bounded_completion_wake.notify_one();
                            }
                        }
                    }
                }
                if let Some(need) = flow.key_body_root {
                    if let Some(port) = self.ports.get_mut(&(work.room, flow.hint_peer)) {
                        if port.key_body == Some(need)
                            && port.key_body_instance == Some(flow.instance)
                            && port
                                .key_body_token
                                .as_ref()
                                .zip(flow.key_body_token.as_ref())
                                .is_some_and(|(owner, token)| Arc::ptr_eq(owner, token))
                        {
                            // The physical Flow and its staging cleanup have both completed.
                            // Continue the same bounded local scan; an older Flow cannot clear
                            // a replacement port's different exact root. A missing body or
                            // source remains an outstanding local debt; a later acquisition
                            // announces its exact catalog entry without rewinding other work.
                            port.key_body = None;
                            port.key_body_instance = None;
                            port.key_body_token = None;
                            port.key_debt_advance = port.key_debt_selected.take();
                            port.key_remote_advance = port.key_remote_selected.take();
                            port.key_body_initialized = false;
                            self.bounded_completion_wake.notify_one();
                            self.sched_rooms.insert(work.room);
                        }
                    }
                }
                if flow.automatic_own_recovery {
                    if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                        port.own_recovery_checked = !flow.own_recovery_progress;
                        if flow.own_recovery_progress {
                            port.own_recovery_parked = None;
                        } else {
                            port.own_recovery_parked = flow.own_recovery_trigger;
                        }
                    }
                    if !flow.own_recovery_progress
                        && flow.own_recovery_page.is_some_and(|(target, seq)| {
                            self.own_readable_effects
                                .get(&work.room)
                                .is_some_and(|ready| {
                                    ready.target == target
                                        && ready.seq == seq
                                        && ready
                                            .instance
                                            .upgrade()
                                            .is_some_and(|room| Arc::ptr_eq(&room, &flow.shared))
                                })
                        })
                    {
                        // Readability can change while this Page still owns the port. Its
                        // no-progress completion is the first point a new Page may run.
                        self.retry_readable_own_effect(work.room);
                    }
                    if flow.own_recovery_progress {
                        self.governance_work.wake_room(work.room);
                        self.sched_rooms.insert(work.room);
                    }
                }
                if !flow.archive && !flow.inventory {
                    if let Some(head) = flow.authenticated_head {
                        let event = NetEvent::BoundedHeadCompleted {
                            channel_id: work.room,
                            instance: Arc::downgrade(&flow.shared),
                            head,
                            epoch: flow.epoch,
                            room_instance: flow.instance,
                            generation: flow.generation,
                            peer: work.peer,
                            discovery_connection: flow.completed_support_discovery(),
                            availability: flow.completed_support_availability(),
                        };
                        if self.net_tx.try_send(event).is_err() {
                            // Retain the charged completed flow and its in-flight hint until
                            // the actor can receive the exact completion; never lose this edge.
                            self.shelve_exact(flow, work.service.index());
                            self.sched_rooms.insert(work.room);
                            continue;
                        }
                    }
                }
                if !flow.automatic_own_recovery {
                    if let (Some(request), Some(fence)) =
                        (flow.archive_request, flow.request_fence.as_ref())
                    {
                        if self
                            .history_demand
                            .owns_running_fence(request, flow.generation, fence)
                        {
                            if let Some(status) = flow.archive_status.take() {
                                self.history_demand.completed_current(
                                    flow.room,
                                    flow.instance,
                                    request,
                                    flow.generation,
                                    status,
                                );
                            }
                        }
                    }
                }
                if let Some(hint) = flow.hint.filter(|_| !flow.local_own_root()) {
                    self.history_hints
                        .finish(work.room, flow.hint_peer, hint.author, hint.head);
                }
                let mut raised = false;
                if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                    if work.service == OutboundService::Public && flow.inventory {
                        port.done_gen = port.done_gen.max(work.generation);
                    }
                    if work.service == OutboundService::Public
                        && (flow.inventory || flow.hint.is_some())
                    {
                        // This attempt consumed the request that selected its inventory or
                        // scalar hint. Leaving it outstanding immediately schedules another
                        // inventory and recreates the feedback churn the bounded inbox removed.
                        port.req_done = port.req_done.max(work.request);
                    }
                    if work.service == OutboundService::Public && flow.local_own_after_inventory {
                        // This completed inventory was the producer that deferred an eligible
                        // local metadata root. Refused/equal roots never set this scalar, so
                        // ordinary inventories cannot turn parked debt into periodic reoffers.
                        port.raise();
                        raised = true;
                    }
                    if work.service == OutboundService::Public
                        && (self.bounded_sync.ready.iter().flatten().any(|flow| {
                            flow.service == OutboundService::Public
                                && flow.room == work.room
                                && flow.peer == work.peer
                        }) || self
                            .leave_waiters
                            .iter()
                            .any(|(r, _, _, _, _)| *r == work.room)
                            || self.bounded_sync.required.iter().any(|required| {
                                required.room == work.room && required.peer == work.peer
                            }))
                    {
                        port.raise();
                        raised = true;
                    }
                }
                // A completed Public inventory can expose exact departure/receipt work.
                if raised || self.history_hints.pending(work.room, work.peer) {
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
                        counts.consecutive_failures = 0;
                        counts.failing_since = None;
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
                if work.service == OutboundService::Public {
                    // The controller-wide retained-flow permit bounds this fair queue.
                    self.bounded_sync.deferred.push_back(flow);
                } else {
                    self.shelve_exact(flow, work.service.index());
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
                            work.service,
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
        port: PortKey,
        epoch: u64,
        shared: Arc<tokio::sync::Mutex<ChannelState>>,
        store: Arc<Store>,
        conn: Arc<VoxConnection>,
    ) -> bool {
        let (room, peer, service) = port;
        if self.own_key_leave_pending.contains_key(&room)
            || self.own_key_ended_pending.contains_key(&room)
        {
            return false;
        }
        self.accept_bounded_sync();
        if !self
            .ports
            .get(&(room, peer))
            .is_some_and(|port| port.out.can_start(service))
        {
            return false;
        }
        if let Some((flow, ended_request)) =
            self.bounded_sync
                .take_superseded_byte_hint(room, peer, service, &self.history_hints)
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
                    .backoff(crate::node::ports::BackoffScope::Service(service))
                    .is_some_and(|backoff| backoff.kind == crate::node::status::BackoffKind::Busy)
                {
                    port.clear_service_backoff(service);
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
        if self
            .bounded_sync
            .pool_admission_blocked_for(room, peer, service)
        {
            return false;
        }
        self.bounded_sync.prune_byte_admissions(room, peer, service);
        let record_waiting = self
            .bounded_sync
            .byte_admission
            .range((room, peer, service, 0)..=(room, peer, service, u64::MAX))
            .any(|(_, admission)| admission.owner.is_some());
        // The release belongs to one retained record, not every continuation on its port.
        // A runnable sibling must drain: it can occupy the ready position needed by the
        // body-slot owner whose release the blocked record is waiting for.
        let Some(profile) = self.profile.as_ref() else {
            return false;
        };
        let node = profile.fingerprint();
        let ready_index = service.index();
        let physical_index = service.slot().index();
        if !self.bounded_sync.physical_available(service) {
            return false;
        }
        let mut pending_work = self.bounded_pending_identity(room, peer, service);
        if pending_work.key.is_none() && service == OutboundService::Public {
            pending_work.demand = self.ports.get(&(room, peer)).map(|port| {
                (
                    port.req_gen,
                    port.gen.load(std::sync::atomic::Ordering::Relaxed),
                )
            });
        }
        let pending_public_request = (service == OutboundService::Public)
            .then(|| self.ports.get(&(room, peer)).map(|port| port.req_gen))
            .flatten();
        self.bounded_sync
            .prioritize_control_admission_owner(room, peer, service);
        if self.bounded_sync.ready[ready_index]
            .as_ref()
            .is_none_or(|flow| self.bounded_sync.record_bytes_blocked(flow))
        {
            if let Some(at) = self.bounded_sync.deferred.iter().position(|flow| {
                flow.service == service
                    && flow.room == room
                    && flow.peer == peer
                    && !self.bounded_sync.record_bytes_blocked(flow)
            }) {
                if let Some(flow) = self.bounded_sync.deferred.remove(at) {
                    if let Some(displaced) = self.bounded_sync.ready[ready_index].replace(flow) {
                        self.bounded_sync.deferred.insert(at, displaced);
                    }
                }
            }
        }
        // An own append is announced before the next hinted continuation (ADR-037 R7). The
        // inventory exchange is the only exchange that carries this node's heads to the peer,
        // and it runs only on a flow with no hint; a parked hinted flow draining the peer's
        // backlog would otherwise be reused round after round, so the peer learned of this
        // node's post only when the drain ended (measured: 53–58 s for a 150-post window).
        // The hinted flow waits one round in the deferred queue and resumes after.
        let announce_first = service == OutboundService::Public
            && self.bounded_sync.running[PhysicalSlot::Public.index()].is_none()
            && self
                .ports
                .get(&(room, peer))
                .is_some_and(crate::node::ports::Port::announce_owed);
        // Why a round would run now (ADR-038 FX-15, #996): read before the flow is chosen,
        // because choosing it consumes what it reads.
        let (announce_owed, periodic_pending) =
            self.ports
                .get(&(room, peer))
                .map_or((false, false), |port| {
                    (
                        service == OutboundService::Public && port.announce_owed(),
                        service == OutboundService::Public && port.periodic_pending(),
                    )
                });
        // A reader's page is served on its own stream (#996): a port whose only want is that
        // page runs the page, and no live round beside it. Before this the page's dispatch
        // raised the port, and the raise outlived the page, so every page a reader asked for
        // ran an inventory exchange after it that fetched nothing.
        let page_only = service == OutboundService::Public
            && !self
                .ports
                .get(&(room, peer))
                .is_some_and(|port| port.needs_public())
            && !self.history_hints.pending(room, peer)
            && !self.bounded_sync.needs_port_for(room, peer, service);
        // A retained hint/required flow prepends the announcement on that same owner. Parking it
        // and allocating a fresh inventory Flow deadlocks when all retained positions are full:
        // the inventory is the producer that would let those retained flows finish. A successful
        // prefix gives its ordinary root one real quantum before another append can preempt it.
        let announcement_preempts =
            self.bounded_sync.ready[ready_index]
                .as_ref()
                .is_some_and(|flow| {
                    flow.room == room
                        && flow.peer == peer
                        && !self.bounded_sync.record_bytes_blocked(flow)
                        && !flow.inventory
                        && flow.announcement_can_run()
                        && (flow.announcement_pending()
                            || (announce_first && !flow.ordinary_turn_due()))
                });
        let existing = self.bounded_sync.ready[ready_index]
            .as_ref()
            .filter(|flow| {
                flow.service == service
                    && flow.room == room
                    && flow.peer == peer
                    && !self.bounded_sync.record_bytes_blocked(flow)
                    && (!flow.waiting || announcement_preempts)
            })
            .map(|_| ready_index);
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
            if let Some(index) = self.bounded_sync.ready[ready_index]
                .as_ref()
                .filter(|flow| {
                    flow.service == service
                        && flow.room == room
                        && flow.peer == peer
                        && !self.bounded_sync.record_bytes_blocked(flow)
                        && !(flow.service == OutboundService::Archive
                            && flow.waiting
                            && self.bounded_sync.required.iter().any(|required| {
                                required.room == flow.room
                                    && required.peer == flow.peer
                                    && required.instance == flow.instance
                                    && flow.owns_request(required.request)
                            }))
                })
                .map(|_| ready_index)
            {
                let Some(flow) = self.bounded_sync.ready[index].take() else {
                    return false;
                };
                flow
            } else {
                if record_waiting {
                    return false;
                }
                if !self.bounded_sync.can_retain_new(service) {
                    // This is controller retention preflight, before a Flow/start attempt owns
                    // the port. Its release is driven by the exact retiring/completion owner;
                    // do not overwrite the last ended attempt with a start_reason ADR-038 does
                    // not define.
                    self.bounded_sync
                        .cancel_matching_control_admission(room, peer, service);
                    return false;
                }
                if page_only || self.bounded_sync.ready[ready_index].is_some() {
                    let control_ready = self.bounded_sync.control_would_admit(
                        &self.history_budget,
                        node,
                        room,
                        peer,
                        service,
                    );
                    self.bounded_sync
                        .cancel_matching_control_admission(room, peer, service);
                    self.note_start(
                        room,
                        peer,
                        service,
                        if control_ready {
                            "live_lane_busy"
                        } else {
                            "control_budget_busy"
                        },
                    );
                    return false;
                }
                if service == OutboundService::Archive {
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
                                self.note_start(room, peer, service, "archive_budget_busy");
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
                    AdmissionWork {
                        lane: crate::node::history_budget::Lane::Control,
                        ..pending_work
                    },
                ) {
                    ForegroundTurn::Ready(job) => job,
                    ForegroundTurn::Waiting => {
                        self.note_start(room, peer, service, "control_budget_busy");
                        return false;
                    }
                };
                let actor_incarnation = state_job.flow_owner();
                admitted_control = Some(state_job.clone());

                // Inventory must first advertise the new local departure. Once that fixed
                // exchange completes, probe only our own exact head; no archive is followed.
                let departure_hint = if service == OutboundService::Public
                    && self.leave_waiters.iter().any(|(r, generation, _, _, _)| {
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
                            ByteWait {
                                owner: pending_work.key,
                                port_request: pending_public_request,
                                wake: bytes_wake,
                            },
                        );
                        self.note_start(room, peer, service, "control_budget_busy");
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
                let needs_own_state = service != OutboundService::Private
                    && (self.own_recovery_rooms.contains_key(&room)
                        || self.ports.get(&(room, peer)).is_some_and(|port| {
                            port.support_discovery_check || port.own_receipt_lower.is_some()
                        }));
                let own_state =
                    if needs_own_state {
                        let bytes_wake = state_job.bytes_wake();
                        let Some(_read) = state_job.reserve(4 * 1024 * 1024) else {
                            self.bounded_sync.wait_for_bytes(
                                &self.net_tx,
                                &mut self.next_token,
                                room,
                                peer,
                                pending_work,
                                ByteWait {
                                    owner: pending_work.key,
                                    port_request: pending_public_request,
                                    wake: bytes_wake,
                                },
                            );
                            return false;
                        };
                        match shared.try_lock() {
                            Ok(channel) => {
                                let instance = match channel.history_instance(&store) {
                                    Ok(i) => i,
                                    Err(_) => return false,
                                };
                                let authorization = match stream::authorization_generation(
                                    &store, node, room, instance, epoch,
                                ) {
                                    Ok(a) => a,
                                    Err(_) => return false,
                                };
                                let verification =
                                    match channel.own_recovery_discovery_hint(
                                        &store,
                                        &peer,
                                        authorization,
                                    ) {
                                        Ok(hint) => hint.map(|(author, head, size)| {
                                            stream::HeadHint { author, head, size }
                                        }),
                                        Err(_) => return false,
                                    };
                                let discovery_pending = channel.private_support_discovery_pending();
                                if !discovery_pending {
                                    if let Some(port) = self.ports.get_mut(&(room, peer)) {
                                        port.support_discovery_check = false;
                                    }
                                }
                                let scope = crate::node::ports::SupportDiscovery {
                                    connection: conn.serial(),
                                    instance,
                                    epoch,
                                    authorization,
                                };
                                let already_checked = self
                                    .ports
                                    .get(&(room, peer))
                                    .is_some_and(|port| port.support_discovery == Some(scope));
                                let discovery =
                                    match if already_checked {
                                        Ok(None)
                                    } else {
                                        channel.private_support_discovery_hint(&store, &peer)
                                    } {
                                        Ok(hint) => hint.map(|(author, head, size)| {
                                            stream::HeadHint { author, head, size }
                                        }),
                                        Err(_) => return false,
                                    };
                                let probe_incarnations = channel
                                    .history_inventory_incarnation(&peer)
                                    .zip(channel.history_author_inventory_incarnation(&node));
                                let discovery = discovery.filter(|hint| {
                                    !self
                                        .ports
                                        .get(&(room, peer))
                                        .and_then(|port| port.support_discovery_unavailable)
                                        .is_some_and(|probe| {
                                            probe.matches(scope, hint.head, probe_incarnations)
                                        })
                                });
                                let parked_receipt = self
                                    .ports
                                    .get(&(room, peer))
                                    .and_then(|port| port.own_receipt_lower)
                                    .filter(|probe| {
                                        probe.matches(scope, probe.head, probe_incarnations)
                                    })
                                    .map(|probe| probe.head);
                                let page = if service == OutboundService::Archive
                                    && !self.bounded_sync.owns_archive_room(room)
                                    && self.history_demand.ready_binding(room, peer).is_none()
                                    && self.bounded_sync.ready[OutboundService::Archive.index()]
                                        .is_none()
                                    && self.bounded_sync.running[1].is_none()
                                {
                                    match channel.own_recovery_page(
                                        &store,
                                        &peer,
                                        self.own_recovery_body_debts.get(&room).copied(),
                                    ) {
                                        Ok(page) => page.map(|p| (instance, p)),
                                        Err(_) => return false,
                                    }
                                } else {
                                    None
                                };
                                (
                                    page,
                                    verification,
                                    discovery,
                                    probe_incarnations,
                                    parked_receipt,
                                )
                            }
                            Err(_) => {
                                // Keep the producer edge through the actual release, without a
                                // Control permit, buffers, or secret-work capture parked on it.
                                drop(_read);
                                drop(control);
                                drop(lease);
                                drop(state_job);
                                drop(admitted_control.take());
                                drop(admitted_archive.take());
                                self.bounded_sync.wait_for_own_recovery_room(
                                    &self.net_tx,
                                    &mut self.next_token,
                                    node,
                                    room,
                                    shared.clone(),
                                );
                                return false;
                            }
                        }
                    } else {
                        (None, None, None, None, None)
                    };
                let (own_page, own_verification, own_discovery, probe_incarnations, parked_receipt) =
                    own_state;
                let own_page = own_page.and_then(|(instance, page)| {
                    let generation =
                        match stream::authorization_generation(&store, node, room, instance, epoch)
                        {
                            Ok(generation) => generation,
                            Err(_) => return None,
                        };
                    let mut encoded = crate::cbor::Encoder::new();
                    encoded
                        .array(9)
                        .bytes(&page.head)
                        .uint(page.lo)
                        .uint(page.donor_through)
                        .bytes(&generation)
                        .bytes(&instance)
                        .uint(epoch)
                        .uint(conn.serial());
                    let availability = self
                        .ports
                        .get(&(room, peer))
                        .and_then(|p| p.availability.remote(conn.serial()));
                    encoded
                        .uint(availability.map_or(0, |t| t.open))
                        .uint(availability.map_or(0, |t| t.revision));
                    let trigger = crate::hash::sha256(&encoded.finish());
                    if self
                        .ports
                        .get(&(room, peer))
                        .is_some_and(|port| port.own_recovery_parked == Some(trigger))
                    {
                        return None;
                    }
                    Some((instance, page, trigger))
                });
                if let Some((instance, page, trigger)) = own_page {
                    match own_recovery_flow(
                        profile,
                        room,
                        peer,
                        epoch,
                        instance,
                        page,
                        shared.clone(),
                        control,
                        lease,
                        self.bounded_sync.body_slots.clone(),
                        store.clone(),
                        Arc::clone(&self.history_budget),
                        &state_job,
                        trigger,
                    )
                    .await
                    {
                        Ok(flow) if flow.own_recovery_cleanup => {
                            self.bounded_sync.dispose(flow);
                            return false;
                        }
                        Ok(flow) => flow,
                        Err(_) => return false,
                    }
                } else if service == OutboundService::Archive {
                    if let Some(dispatch) = self
                        .trust
                        .is_trusted(&peer)
                        .then(|| self.history_demand.take_ready(room, peer))
                        .flatten()
                    {
                        let mut flow = Flow::archive(
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
                        );
                        flow.archive_selected_author = Some(dispatch.selected_author);
                        flow
                    } else {
                        if self.own_recovery_rooms.contains_key(&room)
                            && !self.bounded_sync.owns_archive_room(room)
                        {
                            if let Some(port) = self.ports.get_mut(&(room, peer)) {
                                port.own_recovery_checked = true;
                            }
                        }
                        return false;
                    }
                } else {
                    let live = match crate::node::history_demand::Context::current_unlocked(
                        profile,
                        Purpose::Live,
                        lease.clone(),
                    ) {
                        Ok(value) => Arc::new(value),
                        Err(_) => return false,
                    };
                    let required_at = (service == OutboundService::Public && !announce_first)
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
                    let required_owner_request = required_at
                        .and_then(|at| self.bounded_sync.required.get(at))
                        .map(|required| required.request);
                    // Classify before any Entry future starts. Private may consume only its
                    // addressed recipient-key debt/catalog; Public never consumes those roots.
                    let selected_key_body = (service == OutboundService::Private)
                        .then(|| {
                            self.ports.get(&(room, peer)).and_then(|port| {
                                Some((
                                    port.key_body?,
                                    port.key_body_instance?,
                                    port.key_body_token.clone()?,
                                ))
                            })
                        })
                        .flatten();
                    let selected_key_availability = (service == OutboundService::Private
                        && selected_key_body.is_none())
                    .then(|| {
                        self.ports
                            .get(&(room, peer))
                            .and_then(|port| port.key_availability_request.clone())
                    })
                    .flatten();
                    let hint = if service != OutboundService::Public
                        || announce_first
                        || required.is_some()
                    {
                        None
                    } else if let Some(priority) =
                        departure_hint.or(own_verification).or(own_discovery)
                    {
                        Some(priority)
                    } else {
                        take_foreground_hint(
                            &self.history_hints,
                            room,
                            peer,
                            node,
                            parked_receipt,
                            self.net
                                .as_ref()
                                .and_then(|net| net.manager().existing(&peer))
                                .map(|conn| conn.serial()),
                        )
                    };
                    let class_owed = if service == OutboundService::Private {
                        selected_key_body.is_some() || selected_key_availability.is_some()
                    } else {
                        hint.is_some()
                            || required.is_some()
                            || self
                                .ports
                                .get(&(room, peer))
                                .is_some_and(|port| port.needs_public())
                    };
                    if !class_owed {
                        self.bounded_sync
                            .cancel_matching_control_admission(room, peer, service);
                        return false;
                    }
                    let reason = foreground_reason(
                        node,
                        hint,
                        required.is_some()
                            || selected_key_body.is_some()
                            || selected_key_availability.is_some(),
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
                        own_verification.is_some()
                            && hint == own_verification
                            && departure_hint.is_none()
                            && required.is_none(),
                        own_discovery.is_some()
                            && hint == own_discovery
                            && own_verification.is_none()
                            && departure_hint.is_none()
                            && required.is_none(),
                        departure_hint.is_some() && required.is_none(),
                        required,
                        self.bounded_sync.body_slots.clone(),
                        store.clone(),
                        Arc::clone(&self.history_budget),
                        actor_incarnation,
                    ) {
                        Ok(mut flow) => {
                            flow.required_owner_request = required_owner_request;
                            if let Some((after, token, _, _)) = selected_key_availability {
                                flow = flow.with_key_availability(after, token);
                            }
                            if let Some((need, instance, token)) = selected_key_body {
                                let context =
                                    match crate::node::history_demand::Context::key_body_unlocked(
                                        profile,
                                        lease.clone(),
                                    ) {
                                        Ok(value) => Arc::new(value),
                                        Err(_) => return false,
                                    };
                                flow = flow.with_key_body(need, instance, context, token);
                            }
                            flow.reason = reason;
                            flow.discovery_incarnations = probe_incarnations;
                            flow.local_own_after_inventory = flow.inventory
                                && announce_first
                                && (own_verification.is_some() || own_discovery.is_some());
                            if let Some(at) = required_at {
                                let _ = self.bounded_sync.required.remove(at);
                            }
                            flow
                        }
                        Err(_) => {
                            if let Some(hint) = hint.filter(|_| {
                                departure_hint.is_some()
                                    || (hint != own_verification && hint != own_discovery)
                            }) {
                                self.history_hints.retry(room, peer, hint.author, hint.head);
                            }
                            return false;
                        }
                    }
                }
            }
        };
        let index = flow.service.index();
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
                        self.note_start(room, peer, service, "archive_budget_busy");
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
                    AdmissionWork {
                        lane,
                        ..AdmissionWork::from_flow(&flow)
                    },
                ) {
                    ForegroundTurn::Ready(job) => job,
                    ForegroundTurn::Waiting => {
                        self.note_start(room, peer, service, "control_budget_busy");
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
                AdmissionWork {
                    lane,
                    ..AdmissionWork::from_flow(&flow)
                },
            ) {
                ForegroundTurn::Ready(job) => job,
                ForegroundTurn::Waiting => {
                    // The retained lane ticket wakes this exact port on a relevant release.
                    self.note_start(room, peer, service, "control_budget_busy");
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
                AdmissionWork {
                    lane: crate::node::history_budget::Lane::Control,
                    ..AdmissionWork::from_flow(&flow)
                },
            ) {
                ForegroundTurn::Ready(job) => job,
                ForegroundTurn::Waiting => {
                    self.note_start(room, peer, service, "control_budget_busy");
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
                ByteWait {
                    owner: Some(WorkKey::of(&flow)),
                    port_request: (service == OutboundService::Public)
                        .then(|| self.ports.get(&(room, peer)).map(|port| port.req_gen))
                        .flatten(),
                    wake: bytes_wake,
                },
            );
            self.note_start(room, peer, service, "control_budget_busy");
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
            self.note_start(room, peer, service, "no_outbound_slot");
            self.shelve_exact(flow, index);
            return false;
        };
        // The last gate (ADR-038 FX-35): a flow holds the daemon's flow state only while its
        // round runs, and takes it here, in the step that makes the round run. A full fixed pool
        // parks the exact flow, gives back the lane job and slot, and wakes only from a running
        // charge's release; the port keeps its need.
        let work_key = WorkKey::of(&flow);
        if self
            .bounded_sync
            .pool_admission
            .get(&(room, peer, service))
            .is_some_and(|admission| admission.key != work_key)
        {
            self.bounded_sync
                .cancel_pool_admission_for(room, peer, service);
        }
        let resumed = {
            let waiter = self
                .bounded_sync
                .pool_admission
                .get_mut(&(room, peer, service))
                .map(|admission| &mut admission.ticket);
            flow.resume(&state_job, state_bytes, waiter)
        };
        let refused = match resumed {
            crate::node::history_stream::runtime::Resumed::Held => {
                self.bounded_sync
                    .cancel_pool_admission_for(room, peer, service);
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
            self.note_start(room, peer, service, reason);
            // This ordinary admission wait still owns all work consumed while constructing
            // the Flow: archive dispatch, exact required dependency, or scalar hint. Retain
            // it in its lane until a running completion releases capacity and wakes the
            // actor; never reconstruct only the hint and strand the other two forms.
            let waiting = PoolWait {
                gate,
                root: flow.root_name(),
                lane,
                key: WorkKey::of(&flow),
            };
            self.shelve_exact(flow, index);
            // A granted claim was consumed by this failed attempt, if one existed. Replace
            // its actor-owned record with the exact still-retained Flow and a later order.
            self.bounded_sync
                .cancel_pool_admission_for(room, peer, service);
            if let Some(refused_at) = refused_at {
                if let Err(error) = self.bounded_sync.wait_for_pool(
                    &mut self.next_token,
                    waiting,
                    &state_job,
                    &refused_at,
                ) {
                    self.note_start(
                        room,
                        peer,
                        service,
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
        let token = self.next_token;
        self.next_token += 1;
        let fence = flow
            .request_fence
            .clone()
            .unwrap_or_else(crate::transport::stream_transport::Fence::new);
        let generation = if service == OutboundService::Public {
            port.gen.load(std::sync::atomic::Ordering::Relaxed)
        } else {
            0
        };
        let request = if service == OutboundService::Public {
            port.req_gen
        } else {
            0
        };
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
        let mut attempt = Some(crate::node::ports::Attempt {
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
        if !port.out.install(service, &mut attempt) {
            drop(attempt);
            self.shelve_exact(flow, index);
            return false;
        }
        if service == OutboundService::Public && flow.inventory {
            port.announced_seq = port.own_seq;
        }
        if service == OutboundService::Public {
            port.note_foreground_attempt(generation);
        }
        let archive = flow
            .archive_request
            .map(|request| (request, flow.generation));
        let running_retirement_key = retirement_key(&flow);
        // A key to this peer waiting on its bundle makes this round read the peer's board,
        // hinted or not (ADR-038 FX-35); once the bundle is held the fact is gone.
        flow.wants_board =
            service == OutboundService::Public && self.key_waiting.contains_key(&(room, peer));
        flow.availability_connection = conn.serial();
        flow.availability_captured = self
            .ports
            .get(&(room, peer))
            .and_then(|p| p.availability.remote(conn.serial()));
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
        let board_scope = if self.board_exchange_allowed(&room) {
            net.as_ref()
                .map(|net| net.activate_board_exchange_room(room, epoch))
        } else {
            None
        };
        let board_observations = Arc::clone(&self.sync_book);
        let pstore = profile.store_handle();
        let board_signer = board_scope.as_ref().and_then(|_| profile.signer_arc().ok());
        let authority = self.computer_authority();
        let worker = tokio::spawn(async move {
            let _slot = slot;
            #[cfg(not(feature = "test-knobs"))]
            let deadline =
                tokio::time::Instant::now() + crate::node::history_budget::BOUNDED_ROUND_PATIENCE;
            let mut flow = worker_flow.lock().await;
            let Some(flow) = flow.as_mut() else {
                return Some(ReturnedFailure::unreachable(
                    "bounded history supervisor retained no Flow".to_owned(),
                ));
            };
            // The proof barrier belongs after exclusive Flow ownership. While it is held, an
            // actor panic can retire the controller but cannot adopt/park this Flow; its charge
            // therefore remains truthfully attributed to the retiring actor generation.
            #[cfg(feature = "test-knobs")]
            let _proof_round = job.round_for_proof(
                room,
                peer,
                running_retirement_key.request,
                running_retirement_key.instance,
                token,
            );
            job.hold_for_proof(room, peer).await;
            // Proof staging is not part of the product operation's elapsed budget. Start the
            // existing round deadline only once the admitted worker is allowed to do real work.
            #[cfg(feature = "test-knobs")]
            let deadline =
                tokio::time::Instant::now() + crate::node::history_budget::BOUNDED_ROUND_PATIENCE;
            if flow.needs_board() && !worker_fence.is_retired() {
                if let (Some(net), Some(authority), Some(scope), Some(signer)) =
                    (net, authority, board_scope, board_signer)
                {
                    let publication = tokio::select! {
                        biased;
                        () = worker_fence.retired() => None,
                        publication = authority.acquire_publication() => publication,
                    };
                    if let Some(publication) = publication {
                        let lifetime = Arc::new(maintenance_save::Lifetime {
                            authority,
                            publication: Some(publication),
                            exclusive: None,
                            secret: flow.secret_work(),
                            store: Arc::clone(&pstore),
                            signer,
                        });
                        flow.admitted_authors = tokio::select! {
                            biased;
                            () = worker_fence.retired() => 0,
                            result = tokio::time::timeout(SETUP_PATIENCE,
                                exchange_boards(&net, &conn, &flow.shared, &lifetime, scope,
                                    crate::time::Ms(now), (&board_observations, false))) =>
                                result.unwrap_or(0),
                        };
                    }
                }
            }
            let mut failure = flow
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
                .map(ReturnedFailure::from_error);
            if failure.is_none()
                && flow.done()
                && !flow.archive
                && !flow.inventory
                && flow.authenticated_head.is_some()
                && flow.completed_support_discovery().is_some()
            {
                if let Err(error) =
                    refresh_own_recovery_owned(Arc::clone(&flow.shared), pstore).await
                {
                    failure = Some(ReturnedFailure::from_error(error));
                }
            }
            // The round is over: its flow state goes back here, in the step that ends it
            // (ADR-038 FX-35), not when the actor next looks; a finished task holds no charge.
            flow.park();
            failure
        });
        let task = tokio::spawn(async move {
            let failure = match worker.await {
                Ok(failure) => failure,
                Err(error) => Some(ReturnedFailure::panicked(error.to_string())),
            };
            // The inner task can unwind before its normal `park`. Its supervisor owns the exact
            // settlement edge and releases the running charge before publishing completion.
            if let Some(flow) = settlement_flow.lock().await.as_mut() {
                flow.park();
            }
            if let Ok(mut result) = output.lock() {
                *result = Some(Returned { failure });
            }
            completion_wake.notify_one();
        });
        self.bounded_sync.running[physical_index] = Some(Running {
            room,
            peer,
            service,
            slot: service.slot(),
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
        self.bounded_sync.note_background_started(service);
        self.note_start(room, peer, service, "started");
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
                "{{\"actor\":{},\"request\":\"{}\",\"instance\":\"{}\",\"generation\":\"{}\",\"room\":\"{}\",\"peer\":\"{}\",\"root\":\"{}\",\"lane\":\"{}\",\"service\":\"{:?}\",\"slot\":{},\"archive\":{},\"waiting\":{},\"inventory\":{}}}",
                key.actor.map_or_else(|| "null".to_owned(), |actor| actor.to_string()),
                hex(&key.request),
                hex(&key.instance),
                b32_encode(&key.generation),
                b32_encode(&f.room),
                b32_encode(&f.peer),
                f.root_name(),
                lane_name(f.lane()),
                f.service,
                f.service.slot().index(),
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
                            "{{\"actor\":{},\"request\":\"{}\",\"instance\":\"{}\",\"generation\":\"{}\",\"room\":\"{}\",\"peer\":\"{}\",\"token\":{},\"archive\":{},\"lane\":\"{}\",\"service\":\"{:?}\",\"slot\":{},\"age_ms\":{},\"finished\":{}}}",
                            r.retirement_key.actor.map_or_else(|| "null".to_owned(), |actor| actor.to_string()),
                            hex(&r.retirement_key.request),
                            hex(&r.retirement_key.instance),
                            b32_encode(&r.retirement_key.generation),
                            b32_encode(&r.room),
                            b32_encode(&r.peer),
                            r.token,
                            r.archive.is_some(),
                            lane_name(r.lane),
                            r.service,
                            r.slot.index(),
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
                         service: OutboundService,
                         request: Option<stream::RequestId>,
                         demand: Option<(u64, u64)>,
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
                "{{\"admission\":{},\"gate\":\"{}\",\"room\":\"{}\",\"peer\":\"{}\",\"root\":\"{}\",\"lane\":\"{}\",\"service\":\"{:?}\",\"slot\":{},\"request\":{},\"preflow_request\":{},\"preflow_generation\":{},\"wait_order\":{},\"handed_off\":{}}}",
                token,
                gate,
                b32_encode(&room),
                b32_encode(&peer),
                root,
                lane_name(lane),
                service,
                service.slot().index(),
                request,
                demand.map_or_else(|| "null".to_owned(), |(request, _)| request.to_string()),
                demand.map_or_else(|| "null".to_owned(), |(_, generation)| generation.to_string()),
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
                OutboundService::Archive,
                Some(waiting.request),
                None,
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
                waiting.service,
                waiting.key.map(|key| key.request),
                waiting.demand,
                None,
                None,
            )
        }));
        admissions.extend(
            self.local_admission
                .iter()
                .map(|((room, peer, _service), waiting)| {
                    admission(
                        match waiting.kind {
                            LocalAdmissionKind::Secret => "secret",
                            LocalAdmissionKind::Room => "room",
                        },
                        waiting.token,
                        *room,
                        *peer,
                        waiting.root,
                        waiting.lane,
                        *_service,
                        waiting.key.map(|key| key.request),
                        None,
                        None,
                        None,
                    )
                }),
        );
        admissions.extend(self.byte_admission.iter().map(
            |((room, peer, _service, token), waiting)| {
                admission(
                    "bytes",
                    *token,
                    *room,
                    *peer,
                    waiting.root,
                    waiting.lane,
                    *_service,
                    waiting.owner.map(|key| key.request),
                    None,
                    None,
                    None,
                )
            },
        ));
        admissions.extend(
            self.pool_admission
                .iter()
                .map(|((room, peer, _service), waiting)| {
                    admission(
                        waiting.gate,
                        waiting.token,
                        *room,
                        *peer,
                        waiting.root,
                        waiting.lane,
                        *_service,
                        Some(waiting.key.request),
                        None,
                        Some(waiting.ticket.sequence()),
                        Some(waiting.handed_off),
                    )
                }),
        );
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
            self.local_admission.values().filter(|a| a.kind == LocalAdmissionKind::Room).count(),
            self.local_admission.values().filter(|a| a.kind == LocalAdmissionKind::Secret).count(),
            self.byte_admission.len(),
            self.pool_admission.len(),
            cleanup,
            serde_json::to_string(&cleanup_error).unwrap_or_else(|_| "null".to_owned()),
            cleanup_errors.join(",")
        )
    }
}
