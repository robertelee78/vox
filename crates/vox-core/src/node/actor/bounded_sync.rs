//! Bounded current-message work and explicitly requested archive work share the existing ports.
//! Events carry tokens only; private slots retain capabilities until workers actually finish.
use super::*;
use crate::node::history_stream::{self as stream, runtime::Flow, Purpose};
use crate::node::store::Store;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex as StdMutex;

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
    started: std::time::Instant,
}
type CleanupResult = (Flow, crate::error::Result<bool>);
/// Retained flows are real bounded demand, not running pool charges. Once full, the exact port
/// remains needed and is retried by the completion/release event that frees one.
pub(crate) const RETAINED_FLOW_LIMIT: usize = 12;

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
struct ForegroundAdmission {
    token: u64,
    room: Digest32,
    peer: Digest32,
    lane: crate::node::history_budget::Lane,
    ticket: crate::node::history_budget::Ticket,
    task: tokio::task::JoinHandle<()>,
}
struct RoomAdmission {
    token: u64,
    task: tokio::task::JoinHandle<()>,
}
struct SecretAdmission {
    token: u64,
    task: tokio::task::JoinHandle<()>,
}
struct ByteAdmission {
    token: u64,
    task: tokio::task::JoinHandle<()>,
}
enum ArchiveTurn {
    Ready(crate::node::history_budget::Job),
    Waiting,
    Full,
}
enum ForegroundTurn {
    Ready(crate::node::history_budget::Job),
    Waiting,
    Full,
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
    /// Exact room-lock release waits for ports that met an off-actor holder. The waiter briefly
    /// acquires and releases the same mutex, then wakes the port; no scheduler tick guesses.
    room_admission: BTreeMap<(Digest32, Digest32), RoomAdmission>,
    secret_admission: BTreeMap<(Digest32, Digest32), SecretAdmission>,
    byte_admission: BTreeMap<(Digest32, Digest32), ByteAdmission>,
    deferred: VecDeque<Flow>,
    body_slots: Arc<stream::runtime::BodySlots>,
    required: VecDeque<(Digest32, Digest32, Digest32, u64)>,
    retiring: VecDeque<Flow>,
    cleanup: Option<Cleanup>,
    cleanup_due: Option<std::time::Instant>,
    cleanup_error: Option<String>,
    event_tx: Option<mpsc::Sender<NetEvent>>,
}
impl Controller {
    fn set_event_tx(&mut self, tx: &mpsc::Sender<NetEvent>) {
        if self.event_tx.is_none() {
            self.event_tx = Some(tx.clone());
        }
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
                .any(|(needed_room, needed_peer, _, _)| {
                    *needed_room == room && *needed_peer == peer
                })
            || self
                .foreground_admission
                .iter()
                .flatten()
                .any(|admission| admission.room == room && admission.peer == peer)
            || self.room_admission.contains_key(&(room, peer))
            || self.secret_admission.contains_key(&(room, peer))
            || self.byte_admission.contains_key(&(room, peer))
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
    fn cancel_room_admission(&mut self, room: Digest32, peer: Digest32) {
        if let Some(admission) = self.room_admission.remove(&(room, peer)) {
            admission.task.abort();
        }
    }
    pub(super) fn release_room_admission(
        &mut self,
        token: u64,
        room: Digest32,
        peer: Digest32,
    ) -> bool {
        if self
            .room_admission
            .get(&(room, peer))
            .is_some_and(|admission| admission.token == token)
        {
            self.cancel_room_admission(room, peer);
            true
        } else {
            false
        }
    }
    fn wait_for_room(
        &mut self,
        net_tx: &mpsc::Sender<NetEvent>,
        next_token: &mut u64,
        room: Digest32,
        peer: Digest32,
        shared: Arc<tokio::sync::Mutex<ChannelState>>,
    ) {
        if self.room_admission.contains_key(&(room, peer)) {
            return;
        }
        let token = *next_token;
        *next_token += 1;
        let tx = net_tx.clone();
        let task = tokio::spawn(async move {
            let guard = shared.lock_owned().await;
            drop(guard);
            let _ = tx
                .send(NetEvent::BoundedRoomReady { token, room, peer })
                .await;
        });
        self.room_admission
            .insert((room, peer), RoomAdmission { token, task });
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
        self.secret_admission
            .insert((room, peer), SecretAdmission { token, task });
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
    ) -> bool {
        if self
            .byte_admission
            .get(&(room, peer))
            .is_some_and(|admission| admission.token == token)
        {
            self.cancel_byte_admission(room, peer);
            true
        } else {
            false
        }
    }
    fn wait_for_bytes(
        &mut self,
        net_tx: &mpsc::Sender<NetEvent>,
        next_token: &mut u64,
        room: Digest32,
        peer: Digest32,
        wake: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    ) {
        if self.byte_admission.contains_key(&(room, peer)) {
            return;
        }
        let token = *next_token;
        *next_token += 1;
        let tx = net_tx.clone();
        let task = tokio::spawn(async move {
            wake.await;
            let _ = tx
                .send(NetEvent::BoundedBytesReady { token, room, peer })
                .await;
        });
        self.byte_admission
            .insert((room, peer), ByteAdmission { token, task });
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
                    Ok(true) => self.cleanup_error = None,
                    Ok(false) => {
                        self.cleanup_error = None;
                        self.retiring.push_back(flow);
                    }
                    Err(error) => {
                        eprintln!("vox: history retirement is pending: {error}");
                        self.cleanup_error = Some(error.to_string());
                        self.retiring.push_back(flow);
                        self.cleanup_due = Some(
                            std::time::Instant::now()
                                + crate::node::history_budget::RETIRE_RETRY_BACKOFF,
                        );
                        if let Some(tx) = self.event_tx.clone() {
                            tokio::spawn(async move {
                                tokio::time::sleep(
                                    crate::node::history_budget::RETIRE_RETRY_BACKOFF,
                                )
                                .await;
                                let _ = tx.send(NetEvent::BoundedCleanupRetry).await;
                            });
                        }
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
        let event_tx = self.event_tx.clone();
        let task = tokio::spawn(async move {
            let outcome = flow.retire_slice().await;
            if let Ok(mut result) = output.lock() {
                *result = Some((flow, outcome));
            }
            if let Some(tx) = event_tx {
                let _ = tx.send(NetEvent::BoundedCleanupProgress).await;
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
        for index in 0..self.foreground_admission.len() {
            if self.foreground_admission[index]
                .as_ref()
                .is_some_and(|admission| admission.room == room)
            {
                self.cancel_foreground_admission(index);
            }
        }
        let waiting: Vec<(Digest32, Digest32)> = self
            .room_admission
            .keys()
            .filter(|(waiting_room, _)| *waiting_room == room)
            .copied()
            .collect();
        for (room, peer) in waiting {
            self.cancel_room_admission(room, peer);
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
        self.cancel_foreground_port(room, peer);
        self.cancel_room_admission(room, peer);
        self.cancel_secret_admission(room, peer);
        self.cancel_byte_admission(room, peer);
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
        for index in 0..self.foreground_admission.len() {
            self.cancel_foreground_admission(index);
        }
        for (_, admission) in std::mem::take(&mut self.room_admission) {
            admission.task.abort();
        }
        for (_, admission) in std::mem::take(&mut self.secret_admission) {
            admission.task.abort();
        }
        for (_, admission) in std::mem::take(&mut self.byte_admission) {
            admission.task.abort();
        }
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

        let Some(mut ticket) = budget.enqueue(node, lane) else {
            return ForegroundTurn::Full;
        };
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
            lane,
            ticket,
            task,
        });
        ForegroundTurn::Waiting
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

    /// Abandoning a flow retires its local capabilities, not the unauthoritative scalar hint it
    /// selected. Re-arm that exact hint while its inbox scope is still live; room/peer retirement
    /// removes it first, making this a no-op for teardown rather than leaving an in-flight orphan.
    /// A flow whose start ended before its round: back into the ready slot it was taken from,
    /// parked, if it has run before; let go with its outstanding work re-armed if it is fresh
    /// (ADR-038 FX-35: the ready slot holds only flows that have run, so a flow waiting for a
    /// slot, a budget or the pool never holds the node's live lane against its other ports).
    fn shelve_or_let_go(&mut self, mut flow: Flow, index: usize, fresh: bool) {
        if fresh {
            self.dispose_rearming_hint(flow);
        } else {
            flow.park();
            self.bounded_sync.ready[index] = Some(flow);
        }
    }

    fn dispose_rearming_hint(&mut self, mut flow: Flow) {
        if let Some(hint) = flow.hint.take() {
            self.history_hints
                .retry(flow.room, flow.hint_peer, hint.author, hint.head);
        }
        self.bounded_sync.dispose(flow);
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
            let Some(work) = self.bounded_sync.running[index].take() else {
                self.dispose_rearming_hint(returned.flow);
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
                self.dispose_rearming_hint(returned.flow);
                continue;
            }
            if let Some(seq) = returned.flow.mine_held.take() {
                // The peer's word on how far it holds this node's feed (ADR-028 R-6), recorded
                // on the actor's next turn; the settlement tick then stops offering the own
                // head to that peer (ADR-038 FX-15).
                self.held_notes.push((work.room, work.peer, seq));
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
                // A bounded publication may have made an addressed key-package durable. Its
                // catalog is authoritative even when the best-effort presentation event below
                // cannot fit in the actor queue, so make package installation runnable here.
                // A turn that finds no package is bounded and clears the room again; a crash
                // between publication and this mark is recovered by the room-open scan.
                self.key_package_rooms.entry(work.room).or_insert(false);
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
            if let Some(target) = returned.flow.reroute.take() {
                // EvidenceUnavailable named the author of the exact missing signed dependency.
                // Keep this flow, its in-flight hint owner and its exact query/continuation
                // intact; only the next wire turn moves to the authoritative port.
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
                returned.flow.peer = target;
                returned.flow.route_origin = Some(work.peer);
                returned.flow.route_complete = false;
                debug_assert!(self.bounded_sync.ready[0].is_none());
                if self.bounded_sync.ready[0].is_some() {
                    self.dispose_rearming_hint(returned.flow);
                    continue;
                }
                self.bounded_sync.ready[0] = Some(returned.flow);
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
            if returned.flow.authorization_changed {
                let retry_peer = returned
                    .flow
                    .route_origin
                    .unwrap_or(returned.flow.hint_peer);
                if let Some(hint) = returned.flow.hint {
                    self.history_hints.retry(
                        work.room,
                        returned.flow.hint_peer,
                        hint.author,
                        hint.head,
                    );
                }
                self.bounded_sync.dispose(returned.flow);
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
                self.sched_rooms.insert(work.room);
                continue;
            }
            if let Some(error) = returned.error {
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
                if let Some(request) = returned.flow.archive_request {
                    self.history_demand
                        .failed(request, returned.flow.generation, &error);
                }

                if let Some(hint) = returned.flow.hint {
                    self.history_hints.finish(
                        work.room,
                        returned.flow.hint_peer,
                        hint.author,
                        hint.head,
                    );
                }
                self.bounded_sync.dispose(returned.flow);
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
            if returned.flow.route_complete {
                let Some(origin) = returned.flow.route_origin.take() else {
                    self.dispose_rearming_hint(returned.flow);
                    continue;
                };
                returned.flow.route_complete = false;
                let more_for_target = self.history_hints.pending(work.room, work.peer)
                    || self
                        .bounded_sync
                        .required
                        .iter()
                        .any(|(room, peer, _, _)| *room == work.room && *peer == work.peer);
                if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                    port.req_done = port.req_done.max(work.request);
                    if more_for_target {
                        port.raise();
                    }
                    port.clear_backoff();
                }
                crate::node::status::SyncBook::with(
                    &self.sync_book,
                    work.room,
                    work.peer,
                    |counts| {
                        counts.completed += 1;
                        counts.backoff = None;
                    },
                );
                // A round the lane completed is a completed sync for `vox status` (PRD-001
                // R35), as a session's clean report was before ADR-037. Without this every
                // lane-served room read "last sync never" and, after ten minutes, "no completed
                // sync" while its counters climbed into the thousands (the decider's daemon,
                // 2026-10-19).
                self.note_lane_sync(work.room, work.peer);
                let origin_room =
                    crate::node::ports::RoomRef::Channel(Arc::downgrade(&returned.flow.shared));
                let origin_live = self
                    .ports
                    .get(&(work.room, origin))
                    .is_some_and(|port| !port.poisoned && port.room.is(&origin_room));
                if !origin_live {
                    // The advertising peer departed or its room instance was poisoned while the
                    // exact author turn was in flight. Its inbox scope has already retired (or
                    // this hint is safely re-armed for a later reopen); never strand the sole
                    // foreground lane on an absent/unschedulable origin port.
                    self.dispose_rearming_hint(returned.flow);
                    self.sched_rooms.insert(work.room);
                    continue;
                }
                returned.flow.peer = origin;
                debug_assert!(self.bounded_sync.ready[0].is_none());
                if self.bounded_sync.ready[0].is_some() {
                    self.dispose_rearming_hint(returned.flow);
                    continue;
                }
                self.bounded_sync.ready[0] = Some(returned.flow);
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
            let superseded = returned.flow.hint.is_some_and(|hint| {
                self.history_hints.newer_pending(
                    work.room,
                    returned.flow.hint_peer,
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
                self.dispose_rearming_hint(returned.flow);
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
            let local_progress =
                returned.flow.done() || !returned.flow.waiting || returned.flow.body_progress;
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
                    self.history_hints.finish(
                        work.room,
                        returned.flow.hint_peer,
                        hint.author,
                        hint.head,
                    );
                }
                let mut raised = false;
                if let Some(port) = self.ports.get_mut(&(work.room, work.peer)) {
                    if returned.flow.inventory {
                        port.done_gen = port.done_gen.max(work.generation);
                    }
                    if returned.flow.inventory || returned.flow.hint.is_some() {
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
                // A round the lane completed is a completed sync for `vox status` (PRD-001
                // R35), as a session's clean report was before ADR-037. Without this every
                // lane-served room read "last sync never" and, after ten minutes, "no completed
                // sync" while its counters climbed into the thousands (the decider's daemon,
                // 2026-10-19).
                self.note_lane_sync(work.room, work.peer);
            } else {
                let waiting = returned.flow.waiting;
                let body_progress = returned.flow.body_progress;
                if returned.flow.governance_wait {
                    // The flow found the fold pending: the actor's fold hook drives it (ADR-037
                    // R2 b), and the flow's next round finds it ready.
                    self.governance_work.pending = true;
                }
                if index == 0 {
                    if self.bounded_sync.deferred.len() == 8 {
                        if let Some(old) = self.bounded_sync.deferred.pop_front() {
                            if let Some(hint) = old.hint {
                                self.history_hints.finish(
                                    old.room,
                                    old.hint_peer,
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
            }
        }
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
        shared: Arc<tokio::sync::Mutex<ChannelState>>,
        store: Arc<Store>,
        conn: Arc<VoxConnection>,
    ) -> bool {
        self.bounded_sync.set_event_tx(&self.net_tx);
        self.accept_bounded_sync();
        let Some(profile) = self.profile.as_ref() else {
            return false;
        };
        let node = profile.fingerprint();
        let epoch = match shared.try_lock() {
            Ok(channel) => channel.epoch(),
            Err(_) => {
                self.bounded_sync.wait_for_room(
                    &self.net_tx,
                    &mut self.next_token,
                    room,
                    peer,
                    shared.clone(),
                );
                self.note_start(room, peer, "room_busy");
                return false;
            }
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
        if announce_first {
            if let Some(parked) = self.bounded_sync.ready[0]
                .take_if(|flow| flow.room == room && flow.peer == peer && !flow.inventory)
            {
                self.bounded_sync.deferred.push_back(parked);
            }
        }
        let existing = (0..crate::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS).find(|index| {
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
            if let Some(index) =
                (0..crate::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS).find(|i| {
                    !announce_first
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
                    self.note_start(room, peer, "retained_flow_limit");
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
                            ArchiveTurn::Full => {
                                self.history_demand.busy(
                                    request,
                                    generation,
                                    "The daemon archive queue is full; resume this request later.",
                                );
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
                        self.secret_work.clone(),
                    );
                    self.note_start(room, peer, "identity_busy");
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
                    crate::node::history_budget::Lane::Control,
                ) {
                    ForegroundTurn::Ready(job) => job,
                    ForegroundTurn::Waiting | ForegroundTurn::Full => {
                        self.note_start(room, peer, "control_budget_busy");
                        return false;
                    }
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
                    let bytes_wake = state_job.bytes_wake();
                    let Some(_read_charge) = state_job.reserve(4 * 1024 * 1024) else {
                        self.bounded_sync.wait_for_bytes(
                            &self.net_tx,
                            &mut self.next_token,
                            room,
                            peer,
                            bytes_wake,
                        );
                        self.note_start(room, peer, "control_budget_busy");
                        return false;
                    };
                    let Ok(channel) = shared.try_lock() else {
                        self.bounded_sync.wait_for_room(
                            &self.net_tx,
                            &mut self.next_token,
                            room,
                            peer,
                            shared.clone(),
                        );
                        self.note_start(room, peer, "room_busy");
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
                            self.bounded_sync.body_slots.clone(),
                            store.clone(),
                            state_job.clone(),
                        )
                    } else {
                        if self.bounded_sync.ready[0].is_some()
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
                        let required = if announce_first {
                            None
                        } else {
                            self.bounded_sync
                                .required
                                .iter()
                                .position(|(r, p, _, _)| *r == room && *p == peer)
                                .and_then(|at| self.bounded_sync.required.remove(at))
                                .map(|(_, _, head, seq)| (head, seq))
                        };
                        let hint = if announce_first || required.is_some() {
                            None
                        } else {
                            departure_hint.or_else(|| self.history_hints.take(room, peer, node))
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
                    let required = if announce_first {
                        None
                    } else {
                        self.bounded_sync
                            .required
                            .iter()
                            .position(|(r, p, _, _)| *r == room && *p == peer)
                            .and_then(|at| self.bounded_sync.required.remove(at))
                            .map(|(_, _, head, seq)| (head, seq))
                    };
                    let hint = if announce_first || required.is_some() {
                        None
                    } else {
                        departure_hint.or_else(|| self.history_hints.take(room, peer, node))
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
        // A flow that has never run has nothing to resume: the ready slot is for flows that have
        // run, and only those (ADR-038 FX-35). A fresh flow that cannot start is let go, its
        // outstanding work re-armed, and the port keeps its need; one taken from the ready slot
        // goes back where it was.
        let fresh = existing.is_none();
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
                        self.shelve_or_let_go(flow, index, fresh);
                        return false;
                    }
                    ArchiveTurn::Full => {
                        self.history_demand.busy(
                            request,
                            flow.generation,
                            "The daemon archive queue is full; resume this request later.",
                        );
                        self.note_start(room, peer, "archive_budget_busy");
                        self.bounded_sync.dispose(flow);
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
                lane,
            ) {
                ForegroundTurn::Ready(job) => job,
                ForegroundTurn::Waiting | ForegroundTurn::Full => {
                    // The retained lane ticket wakes this exact port on a relevant release.
                    self.note_start(room, peer, "control_budget_busy");
                    self.shelve_or_let_go(flow, index, fresh);
                    return false;
                }
            }
        };
        // The Control bytes the flow state costs, from the same budget gate (ADR-038 FX-35):
        // their refusal is the control budget's, never the pool's, and they go back with the
        // flow if a later gate ends the attempt.
        let bytes_wake = flow.state_bytes_wake();
        let Some(state_bytes) = flow.reserve_state_bytes() else {
            self.bounded_sync.wait_for_bytes(
                &self.net_tx,
                &mut self.next_token,
                room,
                peer,
                bytes_wake,
            );
            self.note_start(room, peer, "control_budget_busy");
            self.shelve_or_let_go(flow, index, fresh);
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
            self.shelve_or_let_go(flow, index, fresh);
            return false;
        };
        // The last gate (ADR-038 FX-35): a flow holds the daemon's flow state only while its
        // round runs, and takes it here, in the step that makes the round run. The pool is
        // sized to every hosted node's rounds, so this gate never fails while every held charge
        // is a running round's; if it ever does, the attempt ends like any other gate's: the
        // flow shelved or let go with its work re-armed, the lane job and the slot taken above
        // given back on return, and the port keeps its need.
        match flow.resume(state_bytes) {
            crate::node::history_stream::runtime::Resumed::Held => {}
            crate::node::history_stream::runtime::Resumed::PoolFull => {
                self.note_start(room, peer, "flow_state_pool_full");
                self.shelve_or_let_go(flow, index, fresh);
                return false;
            }
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
        });
        let archive = flow
            .archive_request
            .map(|request| (request, flow.generation));
        // A key to this peer waiting on its bundle makes this round read the peer's board,
        // hinted or not (ADR-038 FX-35); once the bundle is held the fact is gone.
        flow.wants_board = self.key_waiting.contains_key(&(room, peer));
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
            job.hold_live_for_proof().await;
            let deadline =
                tokio::time::Instant::now() + crate::node::history_budget::BOUNDED_ROUND_PATIENCE;
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
            // The round is over: its flow state goes back here, in the step that ends it
            // (ADR-038 FX-35), not when the actor next looks; a finished task holds no charge.
            flow.park();
            if let Ok(mut result) = output.lock() {
                *result = Some(Returned { flow, error });
            }
            let _ = tx.send(NetEvent::BoundedSyncProgress { token }).await;
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
        let flow = |f: &Flow| {
            format!(
                "{{\"room\":\"{}\",\"peer\":\"{}\",\"archive\":{},\"waiting\":{},\"inventory\":{}}}",
                b32_encode(&f.room),
                b32_encode(&f.peer),
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
                            "{{\"room\":\"{}\",\"peer\":\"{}\",\"token\":{},\"archive\":{},\"age_ms\":{},\"finished\":{}}}",
                            b32_encode(&r.room),
                            b32_encode(&r.peer),
                            r.token,
                            r.archive.is_some(),
                            u64::try_from(r.started.elapsed().as_millis()).unwrap_or(u64::MAX),
                            r.task.is_finished()
                        )
                    },
                )
            })
            .collect();
        format!(
            "{{\"ready\":[{}],\"running\":[{}],\"deferred\":{},\"retiring\":{},\"required\":{},\"archive_admission\":{},\"foreground_admissions\":{},\"room_admissions\":{},\"secret_admissions\":{},\"byte_admissions\":{},\"cleanup\":{},\"cleanup_error\":{}}}",
            ready.join(","),
            running.join(","),
            self.deferred.len(),
            self.retiring.len(),
            self.required.len(),
            self.archive_admission.is_some(),
            self.foreground_admission.iter().flatten().count(),
            self.room_admission.len(),
            self.secret_admission.len(),
            self.byte_admission.len(),
            self.cleanup.is_some(),
            serde_json::to_string(&self.cleanup_error).unwrap_or_else(|_| "null".to_owned())
        )
    }
}
