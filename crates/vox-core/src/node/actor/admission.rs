//! Local history admission and durable retirement.
use super::*;
use crate::node::history_stream::{
    runtime::{Flow, RetirementStep},
    Purpose,
};
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
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
        archive: false,
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

/// One room's admission (design simple-sync §3): a task of its own runs the admission flow
/// over the room's ready set, and waits only for local edges.
struct Admitting {
    fence: Arc<crate::transport::stream_transport::Fence>,
    flow: Arc<tokio::sync::Mutex<Option<Flow>>>,
    ended: Arc<std::sync::atomic::AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}
impl Admitting {
    /// Its task's end, then its flow: one that did not finish keeps its owed cleanup.
    async fn join(self) -> Option<Flow> {
        self.fence.retire();
        let _ = self.task.await;
        self.flow.lock().await.take()
    }
}

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
struct LocalAdmission {
    token: u64,
    root: &'static str,
    task: tokio::task::JoinHandle<()>,
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
    instance: Option<std::sync::Weak<crate::node::channel::RoomLock>>,
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
        for (_, admitting) in std::mem::take(&mut self.driver.admitting) {
            if let Some(flow) = admitting.join().await {
                self.driver.retiring.push_back(flow);
            }
        }
        let mut result = self.drain().await;
        // Join physical workers before lifecycle admission. A failed local cleanup
        // stays owed, but cannot veto leaving, closing, or deleting its room.
        if let Err(error) = self.driver.join_cleanup().await {
            result = Err(error);
        }
        if result.is_err() && !self.driver.retirement_failed.is_empty() {
            result = Ok(());
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
    admitting: BTreeMap<Digest32, Admitting>,
    local_admission: BTreeMap<(Digest32, Digest32), LocalAdmission>,
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
        for (_, admission) in std::mem::take(&mut self.local_admission) {
            admission.task.abort();
        }
        let mut flows = Vec::new();
        flows.extend(self.retiring.drain(..));
        let cleanup = self.cleanup.take();
        for flow in &mut flows {
            flow.cancel();
            flow.park();
        }
        if let Some(cleanup) = &cleanup {
            for cancellation in &cleanup.cancellations {
                cancellation.cancel();
            }
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            for (_, admitting) in std::mem::take(&mut self.admitting) {
                let ledger = Arc::clone(&self.retirement_ledger);
                handle.spawn(async move {
                    if let Some(flow) = admitting.join().await {
                        spawn_owed_retirement(flow, ledger, false);
                    }
                });
            }
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

    pub(super) fn recover_room_retirements(&mut self, room: Digest32) {
        self.retirement_waiting
            .retain(|key, _| key.room != room || !self.retirement_failed.contains(key));
        self.retirement_failed.retain(|key| key.room != room);
        self.poll_cleanup();
    }

    pub(super) fn completion_wake(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.completion_wake)
    }

    pub(super) fn release_room_admission(
        &mut self,
        token: u64,
        room: Digest32,
        node: Digest32,
    ) -> bool {
        if self
            .local_admission
            .get(&(room, node))
            .is_some_and(|entry| entry.token == token)
        {
            self.cancel_own_recovery_admission(room, node);
            true
        } else {
            false
        }
    }
    pub(super) fn cancel_own_recovery_admission(&mut self, room: Digest32, node: Digest32) {
        if let Some(admission) = self.local_admission.remove(&(room, node)) {
            admission.task.abort();
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
        shared: SharedChannel,
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
        shared: SharedChannel,
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
            .get(&(room, node))
            .is_some_and(|entry| entry.token == token && entry.root == "private_support")
    }

    fn wait_for_own_recovery_release(
        &mut self,
        net_tx: &mpsc::Sender<NetEvent>,
        next_token: &mut u64,
        key: (Digest32, Digest32),
        shared: SharedChannel,
        root: &'static str,
        released: impl Future<Output = ()> + Send + 'static,
    ) {
        let (room, node) = key;
        if self.local_admission.contains_key(&(room, node)) {
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
        self.local_admission
            .insert((room, node), LocalAdmission { token, root, task });
    }

    /// Failed cleanups retain their room's debt, not another room's admission.
    fn local_flow_count(&self) -> usize {
        self.admitting.len()
            + self
                .retiring
                .iter()
                .filter(|flow| !self.retirement_failed.contains(&retirement_key(flow)))
                .count()
            + usize::from(self.cleanup.is_some())
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
        let awaited = self
            .retiring
            .iter()
            .filter_map(|flow| {
                flow.publication_owner_wait()
                    .map(|owner| (flow.room, owner))
            })
            .collect::<Vec<_>>();
        let eligible = |candidate: &Flow| {
            let key = retirement_key(candidate);
            !self.retirement_waiting.contains_key(&key) && !self.retirement_failed.contains(&key)
        };
        let owner = self.retiring.iter().position(|candidate| {
            eligible(candidate)
                && awaited
                    .iter()
                    .any(|(room, owner)| *room == candidate.room && candidate.owns_request(*owner))
        });
        let Some(at) = owner.or_else(|| self.retiring.iter().position(eligible)) else {
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
        self.local_admission.retain(|(waiting_room, _), admission| {
            if *waiting_room == room {
                admission.task.abort();
                false
            } else {
                true
            }
        });
        let mut retired = Self {
            admitting: BTreeMap::new(),
            local_admission: BTreeMap::new(),
            retiring: VecDeque::new(),
            cleanup: None,
            retirement_waiting: BTreeMap::new(),
            retirement_failed: BTreeSet::new(),
            retirement_changed: Arc::clone(&self.retirement_changed),
            retirement_ledger: Arc::clone(&self.retirement_ledger),
            completion_wake: Arc::clone(&self.completion_wake),
            detached_flows: Arc::clone(&self.detached_flows),
        };
        if let Some(admitting) = self.admitting.remove(&room) {
            admitting.fence.retire();
            retired.admitting.insert(room, admitting);
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
        retired
    }

    fn restore_room_retirement(&mut self, retired: &mut Self) {
        self.retiring.append(&mut retired.retiring);
        self.retirement_waiting
            .append(&mut retired.retirement_waiting);
        self.retirement_failed
            .append(&mut retired.retirement_failed);
    }

    pub(super) fn fence(&mut self) {
        self.retirement_waiting.clear();
        // Fencing revokes network work; it is not recovery of a failed storage operation.
        // Keep exact failures until teardown transfers their owners to ledger key erasure.
        for (_, admission) in std::mem::take(&mut self.local_admission) {
            admission.task.abort();
        }
        for flow in &self.retiring {
            flow.cancel();
        }
        if let Some(cleanup) = &self.cleanup {
            for cancellation in &cleanup.cancellations {
                cancellation.cancel();
            }
        }
        for admitting in self.admitting.values() {
            admitting.fence.retire();
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
        for (_, admitting) in std::mem::take(&mut self.admitting) {
            if let Some(flow) = admitting.join().await {
                self.retiring.push_back(flow);
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
}

impl Node {
    /// Whether the connection's loop toward `peer` in `room` has standing now
    /// (`history_stream::pull::standing`, the one rule `start_pull_loops` and the loop's
    /// `current` use): a departed author's port then stays for its tell-only loop.
    fn loop_stands(&self, room: Digest32, peer: Digest32) -> bool {
        let (Some(store), Some(cell), Some(conn)) = (
            self.log_store(),
            self.serving
                .room(&room)
                .and_then(|open| open.snapshot.upgrade()),
            self.net
                .as_ref()
                .and_then(|net| net.manager().existing(&peer)),
        ) else {
            return false;
        };
        cell.current().is_some_and(|snapshot| {
            matches!(
                crate::node::history_stream::pull::standing(
                    &snapshot,
                    &self.history_holdings,
                    &store,
                    peer,
                    conn.serial(),
                ),
                Ok(Some(_))
            )
        })
    }

    /// Retire ordinary departed-member traffic while preserving independently scoped,
    /// already admitted own-recovery responses and exact departure receipts. While the loop
    /// toward the peer still has standing (a departed author still owed its departure receipt
    /// on this connection, or a returning author), its port stays, unpoisoned, for that loop;
    /// once the standing ends, the next lifecycle tend retires it here.
    pub(super) fn retire_departed_port(&mut self, room: Digest32, peer: Digest32) {
        #[cfg(feature = "test-knobs")]
        if crate::node::computer::fx28_mutant("sync-departed-peer") {
            return;
        }
        let stands = self.loop_stands(room, peer);
        let keep_receipt = self.ports.get(&(room, peer)).is_some_and(|port| {
            port.inbound
                .values()
                .any(|attempt| attempt.is_departure_receipt() || attempt.limited_recovery)
        });
        if !keep_receipt && !stands {
            if self.ports.contains_key(&(room, peer)) {
                self.drop_departed_port(&room, &peer);
            }
            return;
        }

        let mut retired = Vec::new();
        if let Some(port) = self.ports.get_mut(&(room, peer)) {
            let ordinary: Vec<_> = port
                .inbound
                .iter()
                .filter_map(|(token, attempt)| {
                    (!attempt.is_departure_receipt() && !attempt.limited_recovery).then_some(*token)
                })
                .collect();
            for token in ordinary {
                if let Some(attempt) = port.inbound.remove(&token) {
                    retired.push(attempt);
                }
            }
            if !stands {
                port.poisoned = true;
            }
        }
        for attempt in retired {
            attempt.retire();
        }
    }

    /// Detach exact physical owners before the existing lifecycle gate task waits for them.
    pub(super) fn take_bounded_room(
        &mut self,
        room: Digest32,
        retire_inbound: bool,
    ) -> RoomRetirement {
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

    /// Each room's ready set is admitted by one task of its own (design simple-sync §3, ADR-054
    /// PL-3), beside the connections' pull loops and never through the port scheduler: the
    /// room's admission flow runs the validator's local steps back to back, takes the ready
    /// set again whenever its roots are done and, where one stops, waits for the local edge it
    /// named (`Flow::admission_wait`) and runs again. A connection's end does not end it.
    /// Nothing here parks, backs off or retries on a clock. A flow that fails keeps its owed
    /// cleanup (retirement), which starts at once; its room's admission stays the failed one's
    /// until the one recovery edge that can change its outcome since it began
    /// (`Frontier::failed_admission_news`): only then does its task end and free the room for a
    /// new admission. A root it failed on goes back to the room's ready set when that
    /// retirement ends (`Flow`'s `Drop`).
    pub(super) fn start_admissions(&mut self) {
        // A failed admission's parked flow, handed back while its task waits for the edge, and
        // whatever an ended task left, go to retirement; only an ended task frees its room.
        let mut failed = Vec::new();
        self.bounded_sync.admitting.retain(|_, admitting| {
            if let Some(flow) = admitting
                .flow
                .try_lock()
                .ok()
                .and_then(|mut flow| flow.take())
            {
                failed.push(flow);
            }
            !admitting.ended.load(Ordering::Acquire)
        });
        for flow in failed {
            self.bounded_sync.dispose(flow);
        }
        let (Some(store), Some(profile)) = (self.log_store(), self.profile.as_ref()) else {
            return;
        };
        let node = profile.fingerprint();
        for room in self.history_frontier.ready_rooms() {
            if self.bounded_sync.admitting.contains_key(&room) {
                continue;
            }
            let record = self
                .serving
                .room(&room)
                .and_then(|open| open.snapshot.upgrade());
            let epoch = record
                .as_ref()
                .and_then(|cell| cell.current())
                .map(|snapshot| snapshot.epoch());
            let (Some(shared), Some(epoch), Some(record)) =
                (self.channels.get(&room).map(Arc::clone), epoch, record)
            else {
                continue;
            };
            // Only a lock in progress holds the secret work, and nothing starts until the unlock.
            let Ok(lease) = self.secret_work.clone().try_read_owned() else {
                return;
            };
            let lease = Arc::new(lease);
            let contexts = crate::node::history_demand::Context::current_unlocked(
                profile,
                Purpose::Live,
                Arc::clone(&lease),
            )
            .and_then(|live| {
                crate::node::history_demand::Context::current_unlocked(
                    profile,
                    Purpose::Control,
                    lease,
                )
                .map(|control| (Arc::new(live), Arc::new(control)))
            });
            let Ok((live, control)) = contexts else {
                continue;
            };
            let fence = crate::transport::stream_transport::Fence::new();
            let cell = Arc::new(tokio::sync::Mutex::new(None::<Flow>));
            let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (task_fence, task_cell, task_ended) =
                (Arc::clone(&fence), Arc::clone(&cell), Arc::clone(&ended));
            let (budget, frontier, store) = (
                Arc::clone(&self.history_budget),
                Arc::clone(&self.history_frontier),
                Arc::clone(&store),
            );
            let clock = Arc::clone(&self.clock);
            let ledger = Arc::clone(&self.bounded_sync.retirement_ledger);
            let news_record = Arc::clone(&record);
            self.history_frontier.admission_began(room);
            let task = tokio::spawn(async move {
                let mut cell = task_cell.lock().await;
                let result: crate::error::Result<()> = async {
                    let mut job = tokio::select! {
                        biased;
                        // Fenced before it began: what is ready stays ready.
                        () = task_fence.retired() => return Ok(()),
                        job = budget.admit_job(node, crate::node::history_budget::Lane::Control) => job,
                    };
                    let renew = (
                        Arc::clone(&shared),
                        Arc::clone(&live),
                        Arc::clone(&control),
                        Arc::clone(&record),
                    );
                    let flow = cell.insert(Flow::admit(
                        room,
                        node,
                        epoch,
                        shared,
                        live,
                        control,
                        Arc::clone(&store),
                        Arc::clone(&budget),
                        None,
                        Arc::clone(&frontier),
                        record,
                    )?);
                    let far = tokio::time::Instant::now()
                        + std::time::Duration::from_secs(365 * 24 * 3600);
                    loop {
                        let turned = flow
                            .turn(Arc::clone(&store), &job, Arc::clone(&task_fence), far, clock())
                            .await;
                        drop(job);
                        // What the actor does with a publication is marked for it, never waited
                        // for: its own save keeps it from taking events (ADR-054 PL-7).
                        if std::mem::take(&mut flow.published) {
                            frontier.advanced(
                                room,
                                std::mem::take(&mut flow.rendered),
                                std::mem::take(&mut flow.governance),
                            );
                        }
                        // An author's Session controls became current in a control-effects
                        // step of this turn: permission news for the room's tellers, once.
                        if std::mem::take(&mut flow.controls_ready) {
                            frontier.private_permission(room);
                        }
                        turned?;
                        if flow.authorization_changed {
                            // The new authorization is read by a fresh admission, which takes
                            // the root this one had not settled back from the room's ready set
                            // with the entry it held: nothing is dropped or fetched again. This
                            // one retires as any ended flow does.
                            flow.give_back_admission();
                            let fresh = Flow::admit(
                                room,
                                node,
                                epoch,
                                Arc::clone(&renew.0),
                                Arc::clone(&renew.1),
                                Arc::clone(&renew.2),
                                Arc::clone(&store),
                                Arc::clone(&budget),
                                None,
                                Arc::clone(&frontier),
                                Arc::clone(&renew.3),
                            )?;
                            spawn_owed_retirement(
                                std::mem::replace(flow, fresh),
                                Arc::clone(&ledger),
                                false,
                            );
                        }
                        if flow.done() {
                            return Ok(());
                        }
                        let _waited_on = flow.admission_wait(&store, &task_fence).await?;
                        job = tokio::select! {
                            biased;
                            () = task_fence.retired() => {
                                return Err(Error::Unreachable("history request cancelled"));
                            }
                            job = budget.admit_job(node, crate::node::history_budget::Lane::Control) => job,
                        };
                    }
                }
                .await;
                let failed = result.is_err();
                match result {
                    // A finished flow ends here; one that failed is retired by the actor.
                    Ok(()) => drop(cell.take()),
                    // Unless its own fence cancelled it, it keeps the root it held unsettled.
                    Err(_error) => {
                        if let Some(flow) = cell.as_mut() {
                            if task_fence.is_retired() {
                                flow.park();
                            } else {
                                flow.fail();
                            }
                        }
                    }
                }
                drop(cell);
                if failed {
                    // Its flow goes to retirement now (`start_admissions`); the room's
                    // admission stays this task's until news that can change the outcome.
                    frontier.wake();
                    frontier
                        .failed_admission_news(room, epoch, &news_record, &task_fence)
                        .await;
                }
                task_ended.store(true, Ordering::Release);
                frontier.wake();
            });
            self.bounded_sync.admitting.insert(
                room,
                Admitting {
                    fence,
                    flow: cell,
                    ended,
                    task,
                },
            );
        }
    }

    pub(super) fn accept_bounded_sync(&mut self) {
        self.bounded_sync.poll_cleanup();
    }

    /// A clean transport round is not a completed sync unless it brought something in. The one
    /// rule for `last sync`: the old flows' rounds and the loops' saved history (each loop's
    /// exchange and each entry the room admission published from it) both come here.
    pub(super) fn note_lane_sync(&mut self, room: Digest32, peer: Digest32, brought: bool) {
        if !brought {
            return;
        }
        let now = self.now_ms().get();
        self.status.room_synced.insert(room, now);
        self.status.member_synced.insert(peer, now);
    }
}

impl Controller {
    pub(super) fn lanes_json(&self) -> String {
        use crate::node::link::b32_encode;
        let running = self
            .admitting
            .iter()
            .map(|(room, admitting)| {
                format!(
                    "{{\"room\":\"{}\",\"admission\":true,\"finished\":{}}}",
                    b32_encode(room),
                    admitting.ended.load(Ordering::Acquire)
                )
            })
            .collect::<Vec<_>>();
        let describe = |key: RetirementKey| {
            let hex = |bytes: &[u8]| {
                bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            };
            format!("\"actor\":{},\"request\":\"{}\",\"instance\":\"{}\",\"generation\":\"{}\",\"room\":\"{}\",\"peer\":\"{}\",\"archive\":{}",
                key.actor.map_or_else(|| "null".to_owned(), |actor| actor.to_string()),
                hex(&key.request), hex(&key.instance), b32_encode(&key.generation),
                b32_encode(&key.room), b32_encode(&key.peer), key.archive)
        };
        let retiring = self
            .retiring
            .iter()
            .map(|flow| format!("{{{}}}", describe(retirement_key(flow))))
            .collect::<Vec<_>>();
        let cleanup = self.cleanup.as_ref().map_or_else(
            || "null".to_owned(),
            |cleanup| format!("{{{}}}", describe(cleanup.key)),
        );
        let errors = self
            .retirement_ledger
            .errors
            .lock()
            .map(|errors| {
                errors
                    .iter()
                    .map(|(key, error)| {
                        format!(
                            "{{{},\"error\":{}}}",
                            describe(*key),
                            serde_json::to_string(error).unwrap_or_else(|_| "null".to_owned())
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        format!(
            "{{\"running\":[{}],\"retiring\":[{}],\"cleanup\":{},\"cleanup_errors\":[{}]}}",
            running.join(","),
            retiring.join(","),
            cleanup,
            errors.join(",")
        )
    }
}
