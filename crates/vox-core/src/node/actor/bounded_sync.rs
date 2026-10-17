//! Bounded current-message work and explicitly requested archive work share the existing ports.
//! Events carry tokens only; private slots retain capabilities until workers actually finish.
use super::*;
use crate::node::history_stream::{self as stream, runtime::Flow, Purpose};
use crate::node::store::Store;
use std::collections::VecDeque;
use std::sync::Mutex as StdMutex;

// The daemon admits sixteen retained flows in total. Limit one hosted identity to a quarter of
// that reservation so a burst from one node cannot prevent the other directly reachable nodes
// from starting the control flow that settles their rooms.
const RETAINED_FLOWS_PER_NODE: usize = 4;

struct Returned {
    flow: Flow,
    error: Option<String>,
}
struct Running {
    room: Digest32,
    peer: Digest32,
    token: u64,
    generation: u64,
    request: u64,
    archive: Option<(stream::RequestId, Digest32)>,
    fence: Arc<crate::transport::stream_transport::Fence>,
    result: Arc<StdMutex<Option<Returned>>>,
    task: tokio::task::JoinHandle<()>,
}
type CleanupResult = (Flow, crate::error::Result<bool>);

struct Cleanup {
    result: Arc<StdMutex<Option<CleanupResult>>>,
    task: tokio::task::JoinHandle<()>,
    cancellations: Vec<crate::node::history_demand::Cancellation>,
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
enum ArchiveTurn {
    Ready(crate::node::history_budget::Job),
    Waiting,
    Full,
}
#[derive(Default)]
pub(super) struct Controller {
    running: [Option<Running>; 2],
    ready: [Option<Flow>; 2],
    /// The one queued archive turn for this node. The controller owns its daemon-wide fair-queue
    /// ticket; the task waits only for a wake, without an actor or room lock.
    archive_admission: Option<ArchiveAdmission>,
    deferred: VecDeque<Flow>,
    body_slots: Arc<stream::runtime::BodySlots>,
    required: VecDeque<(Digest32, Digest32, Digest32, u64)>,
    retiring: VecDeque<Flow>,
    cleanup: Option<Cleanup>,
    cleanup_due: Option<std::time::Instant>,
}
impl Controller {
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
            if let Some((flow, result)) = result {
                self.cleanup.take();
                match result {
                    Ok(true) => {}
                    Ok(false) => self.retiring.push_back(flow),
                    Err(error) => {
                        eprintln!("vox: history retirement is pending: {error}");
                        self.retiring.push_back(flow);
                        self.cleanup_due = Some(std::time::Instant::now() + Duration::from_secs(1));
                    }
                }
            }
        }
        if self.cleanup.is_some()
            || self
                .cleanup_due
                .is_some_and(|due| std::time::Instant::now() < due)
        {
            return;
        }
        self.cleanup_due = None;
        let Some(mut flow) = self.retiring.pop_front() else {
            return;
        };
        let cancellations = flow.cancellation_handles();
        let result = Arc::new(StdMutex::new(None));
        let output = result.clone();
        let task = tokio::spawn(async move {
            let outcome = flow.retire_slice().await;
            if let Ok(mut result) = output.lock() {
                *result = Some((flow, outcome));
            }
        });
        self.cleanup = Some(Cleanup {
            result,
            task,
            cancellations,
        });
    }
    async fn join_cleanup(&mut self) -> crate::error::Result<()> {
        if let Some(cleanup) = self.cleanup.take() {
            let _ = cleanup.task.await;
            let result = cleanup
                .result
                .lock()
                .ok()
                .and_then(|mut value| value.take());
            if let Some((flow, result)) = result {
                match result {
                    Ok(true) => {}
                    Ok(false) => self.retiring.push_back(flow),
                    Err(error) => {
                        self.retiring.push_back(flow);
                        return Err(error);
                    }
                }
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
                if let Ok(mut result) = work.result.lock() {
                    if let Some(returned) = result.take() {
                        self.retiring.push_back(returned.flow);
                    }
                };
            }
        }
        self.required.retain(|(r, _, _, _)| *r != room);
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
                    tokio::task::yield_now().await;
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
            .retain(|(r, p, _, _)| *r != room || *p != peer);
        self.poll_cleanup();
    }
    pub(super) fn fence(&mut self) {
        self.cancel_archive_admission();
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
                let _ = work.task.await;
                if let Ok(mut result) = work.result.lock() {
                    if let Some(returned) = result.take() {
                        self.retiring.push_back(returned.flow);
                    }
                };
            }
        }
        let _ = self.join_cleanup().await;
        while let Some(mut flow) = self.retiring.pop_front() {
            // lock_all has already erased room SEK. Such work exits without writes;
            // bounded reopen recovery owns any durable cursor/publication still present.
            // Memory admission may still be held by a fenced actual worker. Keep this
            // owner until a later bounded slice observes the erased key.
            if matches!(flow.retire_slice().await, Ok(false)) {
                self.retiring.push_back(flow);
                tokio::task::yield_now().await;
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
            let wake = admission.ticket.wake();
            if let Some(job) = admission.ticket.try_admit() {
                admission.task.abort();
                return ArchiveTurn::Ready(job);
            }
            // Replace the completed or superseded notifier with a freshly registered one. A new
            // token makes a late event from the old task harmless.
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

        let Some(mut ticket) = budget.enqueue(node, crate::node::history_budget::Lane::Archive)
        else {
            return ArchiveTurn::Full;
        };
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
}
impl Node {
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
        self.history_hints.retire_peer(room, peer);
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

    pub(super) fn accept_bounded_sync(&mut self) {
        self.bounded_sync.poll_cleanup();
        for index in 0..2 {
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
            let Some(work) = self.bounded_sync.running[index].take() else {
                self.bounded_sync.dispose(returned.flow);
                continue;
            };
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
                    .is_some_and(|room| Arc::ptr_eq(room, &returned.flow.shared));
            if !valid {
                self.bounded_sync.dispose(returned.flow);
                continue;
            }
            if returned.flow.admitted_authors > 0 {
                returned.flow.admitted_authors = 0;
                let _ = self.net_tx.try_send(NetEvent::BoardGrew {
                    channel_id: work.room,
                });
            }
            if returned.flow.published {
                returned.flow.published = false;
                self.governance_work.pending = true;
                self.sched_rooms.insert(work.room);
                let _ = self.net_tx.try_send(NetEvent::BoundedRoomAdvanced {
                    channel_id: work.room,
                    rendered: returned.flow.rendered,
                    governance: returned.flow.governance,
                });
                returned.flow.rendered = false;
                returned.flow.governance = false;
                // A required control finished: the archive's next local slice can recheck its
                // exact dependency. No archive wire request is created by this wake.
                if let Some(flow) = self.bounded_sync.ready[1].as_mut() {
                    flow.waiting = false;
                    self.sched_rooms.insert(flow.room);
                }
            }
            if let Some((head, seq)) = returned.flow.external.take() {
                let need = (work.room, work.peer, head, seq);
                if !self.bounded_sync.required.contains(&need)
                    && self.bounded_sync.required.len() < 128
                {
                    self.bounded_sync.required.push_back(need);
                }
            }
            if returned.flow.hint_unavailable {
                if let Some(hint) = returned.flow.hint {
                    self.history_hints
                        .finish(work.room, work.peer, hint.author, hint.head);
                }
                let more_for_peer = self
                    .bounded_sync
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
                    || self
                        .bounded_sync
                        .required
                        .iter()
                        .any(|(room, peer, _, _)| *room == work.room && *peer == work.peer);
                self.bounded_sync.dispose(returned.flow);
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
                self.sched_rooms.insert(work.room);
                continue;
            }
            if let Some(error) = returned.error {
                if let Some(request) = returned.flow.archive_request {
                    self.history_demand
                        .failed(request, returned.flow.generation, &error);
                }

                if let Some(hint) = returned.flow.hint {
                    self.history_hints
                        .finish(work.room, work.peer, hint.author, hint.head);
                }
                self.bounded_sync.dispose(returned.flow);
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
            // A successful local slice disproves only an earlier capacity yield. Do this for a
            // completed flow too: the completion can reveal another authenticated head waiting
            // on the same port, and leaving its old Busy backoff intact spaces that real work at
            // the exponential cap even though capacity has just made progress. Transport, policy
            // and no-progress backoffs retain their distinct meaning.
            let local_progress = returned.flow.done() || !returned.flow.waiting;
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
            if returned.flow.done() {
                if !returned.flow.archive && !returned.flow.inventory {
                    if let Some(head) = returned.flow.authenticated_head {
                        let event = NetEvent::BoundedHeadCompleted {
                            channel_id: work.room,
                            instance: Arc::downgrade(&returned.flow.shared),
                            head,
                            epoch: returned.flow.epoch,
                            room_instance: returned.flow.instance,
                            generation: returned.flow.generation,
                        };
                        if self.net_tx.try_send(event).is_err() {
                            // Retain the charged completed flow and its in-flight hint until
                            // the actor can receive the exact completion; never lose this edge.
                            self.bounded_sync.ready[index] = Some(returned.flow);
                            self.sched_rooms.insert(work.room);
                            continue;
                        }
                    }
                }
                if let Some(status) = returned.flow.archive_status.take() {
                    if let Some(request) = status.request {
                        self.history_demand
                            .completed(request, returned.flow.generation, status);
                    }
                }
                if let Some(hint) = returned.flow.hint {
                    self.history_hints
                        .finish(work.room, work.peer, hint.author, hint.head);
                }
                let mut raised = false;
                if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                    if returned.flow.inventory {
                        port.done_gen = port.done_gen.max(work.generation);
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
                        || self
                            .bounded_sync
                            .required
                            .iter()
                            .any(|(r, p, _, _)| *r == work.room && *p == work.peer)
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
                crate::node::status::SyncBook::with(
                    &self.sync_book,
                    work.room,
                    work.peer,
                    |counts| counts.completed += 1,
                );
            } else {
                let waiting = returned.flow.waiting;
                if index == 0 {
                    if self.bounded_sync.deferred.len() == 8 {
                        if let Some(old) = self.bounded_sync.deferred.pop_front() {
                            if let Some(hint) = old.hint {
                                self.history_hints.finish(
                                    old.room,
                                    old.peer,
                                    hint.author,
                                    hint.head,
                                );
                            }
                            self.bounded_sync.dispose(old);
                        }
                    }
                    self.bounded_sync.deferred.push_back(returned.flow);
                } else {
                    self.bounded_sync.ready[index] = Some(returned.flow);
                }
                if waiting {
                    self.enter_backoff(
                        work.room,
                        work.peer,
                        crate::node::status::BackoffKind::Busy,
                    );
                } else {
                    self.sched_rooms.insert(work.room);
                }
            }
        }
    }

    pub(super) async fn start_bounded_outbound(
        &mut self,
        room: Digest32,
        peer: Digest32,
        shared: Arc<tokio::sync::Mutex<ChannelState>>,
        store: Arc<Store>,
        conn: Arc<VoxConnection>,
    ) -> bool {
        self.accept_bounded_sync();
        let Some(profile) = self.profile.as_ref() else {
            return false;
        };
        let node = profile.fingerprint();
        let epoch = match shared.try_lock() {
            Ok(channel) => channel.epoch(),
            Err(_) => return false,
        };
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
        let existing = (0..2).find(|index| {
            self.bounded_sync.running[*index].is_none()
                && self.bounded_sync.ready[*index]
                    .as_ref()
                    .is_some_and(|flow| flow.room == room && flow.peer == peer && !flow.waiting)
        });
        let mut admitted_archive = None;
        let mut flow = if let Some(index) = existing {
            let Some(flow) = self.bounded_sync.ready[index].take() else {
                return false;
            };
            flow
        } else {
            // A retained waiting slice is retried by the existing bounded port backoff. It
            // cannot monopolize the other lane or cause an archive continuation to run.
            if let Some(index) = (0..2).find(|i| {
                self.bounded_sync.running[*i].is_none()
                    && self.bounded_sync.ready[*i].as_ref().is_some_and(|flow| {
                        flow.room == room
                            && flow.peer == peer
                            && (!flow.archive || self.bounded_sync.required.is_empty())
                    })
            }) {
                let Some(flow) = self.bounded_sync.ready[index].take() else {
                    return false;
                };
                flow
            } else {
                if self.bounded_sync.flow_count() >= RETAINED_FLOWS_PER_NODE {
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
                            ArchiveTurn::Waiting => return false,
                            ArchiveTurn::Full => {
                                self.history_demand.busy(
                                    request,
                                    generation,
                                    "The daemon archive queue is full; resume this request later.",
                                );
                                return false;
                            }
                        }
                    }
                }
                let Ok(lease) = self.secret_work.clone().try_read_owned() else {
                    return false;
                };
                let lease = Arc::new(lease);
                let Some(state_job) = self
                    .history_budget
                    .try_start(node, crate::node::history_budget::Lane::Control)
                else {
                    return false;
                };
                let Some(state_charge) = state_job.reserve_flow_state() else {
                    return false;
                };

                // Inventory must first advertise the new local departure. Once that fixed
                // exchange completes, probe only our own exact head; no archive is followed.
                let departure_hint = if self.leave_waiters.iter().any(|(r, generation, _, _)| {
                    *r == room
                        && self
                            .ports
                            .get(&(room, peer))
                            .is_some_and(|p| p.done_gen >= *generation)
                }) {
                    let Some(_read_charge) = state_job.reserve(4 * 1024 * 1024) else {
                        return false;
                    };
                    let Ok(channel) = shared.try_lock() else {
                        return false;
                    };
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
                            state_charge,
                            self.bounded_sync.body_slots.clone(),
                            store.clone(),
                            state_job.clone(),
                        )
                    } else {
                        if self.bounded_sync.ready[0].is_some()
                            || self.bounded_sync.running[0].is_some()
                        {
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
                        let required = self
                            .bounded_sync
                            .required
                            .iter()
                            .position(|(r, p, _, _)| *r == room && *p == peer)
                            .and_then(|at| self.bounded_sync.required.remove(at))
                            .map(|(_, _, head, seq)| (head, seq));
                        let hint = if required.is_none() {
                            departure_hint.or_else(|| self.history_hints.take(room, peer, node))
                        } else {
                            None
                        };
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
                            state_charge,
                            self.bounded_sync.body_slots.clone(),
                            store.clone(),
                            state_job.clone(),
                        ) {
                            Ok(flow) => flow,
                            Err(_) => {
                                if let Some(hint) = hint {
                                    self.history_hints
                                        .finish(room, peer, hint.author, hint.head);
                                }
                                return false;
                            }
                        }
                    }
                } else {
                    if self.bounded_sync.ready[0].is_some()
                        || self.bounded_sync.running[0].is_some()
                    {
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
                    let required = self
                        .bounded_sync
                        .required
                        .iter()
                        .position(|(r, p, _, _)| *r == room && *p == peer)
                        .and_then(|at| self.bounded_sync.required.remove(at))
                        .map(|(_, _, head, seq)| (head, seq));
                    let hint = if required.is_none() {
                        departure_hint.or_else(|| self.history_hints.take(room, peer, node))
                    } else {
                        None
                    };
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
                        state_charge,
                        self.bounded_sync.body_slots.clone(),
                        store.clone(),
                        state_job.clone(),
                    ) {
                        Ok(flow) => flow,
                        Err(_) => {
                            if let Some(hint) = hint {
                                self.history_hints
                                    .finish(room, peer, hint.author, hint.head);
                            }
                            return false;
                        }
                    }
                }
            }
        };
        let index = usize::from(flow.archive);
        let lane = flow.lane();
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
                        self.bounded_sync.ready[index] = Some(flow);
                        return false;
                    }
                    ArchiveTurn::Full => {
                        self.history_demand.busy(
                            request,
                            flow.generation,
                            "The daemon archive queue is full; resume this request later.",
                        );
                        self.bounded_sync.dispose(flow);
                        return false;
                    }
                }
            }
        } else {
            let Some(job) = self.history_budget.try_start(node, lane) else {
                self.bounded_sync.ready[index] = Some(flow);
                return false;
            };
            job
        };
        let wake = self.net_tx.clone();
        let Some(slot) = crate::node::ports::Slots::take(
            &self.slots,
            peer,
            Box::new(move || {
                let _ = wake.try_send(NetEvent::SlotFreed);
            }),
        ) else {
            self.bounded_sync.ready[index] = Some(flow);
            return false;
        };
        let Some(port) = self.ports.get_mut(&(room, peer)) else {
            self.bounded_sync.dispose(flow);
            return false;
        };
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
        });
        let archive = flow
            .archive_request
            .map(|request| (request, flow.generation));
        let result = Arc::new(StdMutex::new(None));
        let output = result.clone();
        let worker_fence = fence.clone();
        let tx = self.net_tx.clone();
        let inbox = self.history_hints.clone();
        let inbox_generation = inbox.generation();
        let now = self.now_ms().get();
        let net = self.net.as_ref().cloned();
        let pstore = profile.store_handle();
        let task = tokio::spawn(async move {
            let _slot = slot;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            if flow.needs_board() && !worker_fence.is_retired() {
                if let Some(net) = net {
                    flow.admitted_authors = tokio::select! {
                        biased;
                        ()=worker_fence.retired()=>0,
                        result=tokio::time::timeout(SETUP_PATIENCE,exchange_boards(&net,&conn,&flow.shared,&pstore,room,epoch,crate::time::Ms(now)))=>result.unwrap_or(0),
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
            if let Ok(mut result) = output.lock() {
                *result = Some(Returned { flow, error });
            }
            let _ = tx.try_send(NetEvent::BoundedSyncProgress { token });
        });
        self.bounded_sync.running[index] = Some(Running {
            room,
            peer,
            token,
            generation,
            request,
            archive,
            fence,
            result,
            task,
        });
        true
    }
}
