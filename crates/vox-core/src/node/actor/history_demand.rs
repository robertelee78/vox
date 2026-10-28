//! Explicit archive selection and activation. Cache reads never enter this module.

use super::{NetEvent, Node};
use crate::hash::Digest32;
use crate::node::api::{
    HistoryDemandAction as Action, HistoryDemandPhase as Phase, HistoryDemandStatus as Status,
};
use crate::node::channel::legacy_provisional::LegacyProvisionalOwner;
use crate::node::channel::{entry_store::sparse::ObjectKind, ChannelState};
use crate::node::history_budget::{Job, Lane, Ticket};
use crate::node::history_demand::{self as demand, Binding, Bounds, Context};
use crate::node::history_stream::{self as stream, Query, RequestId, Staging};
use crate::node::store::Store;
use crate::transport::stream_transport::Fence;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use tokio::sync::Mutex;

const PREPARATION_SCRATCH: usize = 5 * 1024 * 1024;

pub(super) struct Dispatch {
    pub room: Digest32,
    pub instance: [u8; 16],
    pub peer: Digest32,
    pub request: RequestId,
    pub generation: Digest32,
    pub query: Query,
    pub staging: Staging,
    pub fence: Arc<Fence>,
    /// Set only after the actor checks the current connected donor's room membership.
    eligible: bool,
    /// A disconnected current member still owns a reconnect need.
    dial_eligible: bool,
}

struct PrivateDispatch {
    room: Digest32,
    instance: [u8; 16],
    peer: Digest32,
    request: RequestId,
    generation: Digest32,
    bounds: Bounds,
    plan: demand::PrivatePlan,
    staging: Staging,
    fence: Arc<Fence>,
}
struct PrivateWork {
    legacy_owner: Option<(Digest32, LegacyProvisionalOwner)>,
    result: Arc<StdMutex<Option<Result<Status, String>>>>,
    request: RequestId,
    generation: Digest32,
    task: tokio::task::JoinHandle<()>,
}
struct Prepared {
    node: Digest32,
    room: Weak<Mutex<ChannelState>>,
    epoch: u64,
    generation: Digest32,
    status: Status,
    dispatch: Option<Dispatch>,
    private: Option<PrivateDispatch>,
    legacy_cancelled: Option<LegacyProvisionalOwner>,
    local_only: bool,
    local_boundary: LocalBoundary,
    /// A locally recovered exact request durably reached Complete without a dispatch.
    terminal_checkpoint: bool,
    /// A validated explicit selection can complete locally without a durable request.
    accepted_selection: bool,
    selection_after: Option<Option<Digest32>>,
    /// Sizing only. Classification owns no authority or durable mutation.
    resume_kind: Option<bool>,
}

/// A real follow-up failure cannot erase an activation which already committed. No driver is
/// dispatched; without an Active, the durable request is observed as saved/Paused on recovery.
fn committed_resume_failure(mut prepared: Prepared, error: impl std::fmt::Display) -> Prepared {
    prepared.local_boundary = LocalBoundary::Durable;
    prepared.status.phase = Phase::Unavailable;
    prepared.status.detail = format!("History operation committed; {error}")
        .chars()
        .take(128)
        .collect();
    prepared
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LocalBoundary {
    Observed,
    Durable,
    Superseded,
}
pub(super) struct Preparation {
    pub(super) token: u64,
    origin: PreparationOrigin,
    action: Action,
    user_intent: bool,
    room: Digest32,
    instance: [u8; 16],
    fence: Arc<Fence>,
    cancellation: demand::Cancellation,
    result: Arc<StdMutex<Option<Result<Prepared, String>>>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PreparationOrigin {
    Explicit,
    Observation,
}
struct Running {
    request: RequestId,
    generation: Digest32,
    fence: Arc<Fence>,
    cancellation: demand::Cancellation,
    /// The page this quantum fetches (head, lo, hi), when it is a page.
    page: Option<(Digest32, u64, u64)>,
}

/// One exact durable archive request whose stale running generation has been retired but whose
/// replacement preparation has not yet been installed. The fair Control ticket and its wake
/// task are retained here, so a busy admission edge cannot turn a saved Resume into an
/// unowned paused status. Once `preparing`, `running` or `ready` owns the request, this owner is
/// removed.
struct ResumeOwed {
    room: Digest32,
    instance: [u8; 16],
    request: RequestId,
    ticket: Option<Ticket>,
    wake_task: Option<tokio::task::JoinHandle<()>>,
    wake_fence: Option<Arc<Fence>>,
    waiting_bytes: bool,
    private: Option<bool>,
    local_admitted: Option<demand::AdmittedEntry>,
}

impl Drop for ResumeOwed {
    fn drop(&mut self) {
        if let Some(fence) = self.wake_fence.take() {
            fence.retire();
        }
        if let Some(task) = self.wake_task.take() {
            task.abort();
        }
    }
}

fn page_of(query: &Query) -> Option<(Digest32, u64, u64)> {
    match query {
        Query::Page { head, lo, hi, .. } => Some((*head, *lo, *hi)),
        _ => None,
    }
}
struct RouteLockWait {
    fence: Arc<Fence>,
    done: Arc<std::sync::atomic::AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for RouteLockWait {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct AutoProbe {
    room: Digest32,
    shared: Weak<Mutex<ChannelState>>,
    intent: u64,
    fence: Arc<Fence>,
    result: Arc<
        StdMutex<
            Option<
                Result<
                    Option<([u8; 16], RequestId, demand::AdmittedEntry)>,
                    (Option<[u8; 16]>, String),
                >,
            >,
        >,
    >,
    task: Option<tokio::task::JoinHandle<()>>,
}
struct AutoWait {
    done: Arc<std::sync::atomic::AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for AutoWait {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
pub(super) struct Controller {
    next: u64,
    pub(super) preparing: Option<Preparation>,
    ready: Option<Dispatch>,
    running: Option<Running>,
    private_work: Option<PrivateWork>,
    cancelled_legacy: Option<(Digest32, LegacyProvisionalOwner)>,
    /// The actual operation and the last accepted explicit action result. Request ownership,
    /// cancellation and worker completion consult only this slot.
    owner_status: Option<Status>,
    /// One replaceable read-only Status result. Observing another room never replaces the actual
    /// operation or a person's explicit action result.
    observation: Option<Status>,
    /// An event may accept an observation between CLI polls. Deliver that exact result once before
    /// a refreshable Unavailable/Paused observation starts another storage read.
    observation_unread: bool,
    selection: Option<(Digest32, [u8; 16], Option<Digest32>)>,
    resume_owed: Option<ResumeOwed>,
    route_lock_wait: Option<RouteLockWait>,
    auto_intent: u64,
    auto_pending: std::collections::BTreeMap<Digest32, u64>,
    auto_ticket: Option<Ticket>,
    auto_wait: Option<AutoWait>,
    auto_probe: Option<AutoProbe>,
}
impl Controller {
    /// Retire only the exact unstarted page when its captured trust generation changes.
    pub(super) fn note_route_trust_change(
        &mut self,
    ) -> Option<(Digest32, Digest32, [u8; 16], RequestId, Digest32)> {
        let dispatch = self.ready.as_ref()?;
        let (room, peer, instance, request, generation) = (
            dispatch.room,
            dispatch.peer,
            dispatch.instance,
            dispatch.request,
            dispatch.generation,
        );
        if !self.owns_running_fence(request, generation, &dispatch.fence) {
            return None;
        }
        self.failed_current(
            room,
            instance,
            request,
            generation,
            "Authorization changed. Request this history page again under current access.",
        )
        .then_some((room, peer, instance, request, generation))
    }

    fn cancel_auto_recovery(&mut self) {
        self.auto_intent = self.auto_intent.wrapping_add(1);
        self.auto_pending.clear();
        self.auto_ticket = None;
        self.auto_wait = None;
        if let Some(probe) = &self.auto_probe {
            probe.fence.retire();
        }
    }

    fn clear_resume_owed(&mut self) {
        if let Some(mut owed) = self.resume_owed.take() {
            if let Some(task) = owed.wake_task.take() {
                task.abort();
            }
        }
    }

    pub(super) fn owe_resume(&mut self, room: Digest32, instance: [u8; 16], request: RequestId) {
        #[cfg(feature = "test-knobs")]
        if std::env::var("VOX_TEST_FX29_MUTANT").as_deref() == Ok("drop-resume-owed") {
            return;
        }
        if self.resume_owed.as_ref().is_some_and(|owed| {
            owed.room == room && owed.instance == instance && owed.request == request
        }) {
            return;
        }
        self.clear_resume_owed();
        self.resume_owed = Some(ResumeOwed {
            room,
            instance,
            request,
            ticket: None,
            wake_task: None,
            wake_fence: None,
            waiting_bytes: false,
            private: None,
            local_admitted: None,
        });
    }

    pub(super) fn accept_resume_wake(
        &mut self,
        room: Digest32,
        instance: [u8; 16],
        request: RequestId,
        fence: &Arc<Fence>,
    ) -> bool {
        let Some(owed) = self.resume_owed.as_mut().filter(|owed| {
            owed.room == room
                && owed.instance == instance
                && owed.request == request
                && !fence.is_retired()
                && owed
                    .wake_fence
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, fence))
        }) else {
            return false;
        };
        owed.wake_task = None;
        if let Some(fence) = owed.wake_fence.take() {
            fence.retire();
        }
        owed.waiting_bytes = false;
        true
    }

    pub(super) fn owns_running_fence(
        &self,
        request: RequestId,
        generation: Digest32,
        fence: &Arc<Fence>,
    ) -> bool {
        self.running.as_ref().is_some_and(|running| {
            running.request == request
                && running.generation == generation
                && Arc::ptr_eq(&running.fence, fence)
        })
    }

    pub(super) fn has_other_resume(
        &self,
        room: Digest32,
        instance: [u8; 16],
        request: RequestId,
    ) -> bool {
        self.resume_owed.as_ref().is_some_and(|owed| {
            owed.room != room || owed.instance != instance || owed.request != request
        })
    }

    fn resume_owed_matches(&self, room: Digest32, instance: [u8; 16], request: RequestId) -> bool {
        self.resume_owed.as_ref().is_some_and(|owed| {
            owed.room == room && owed.instance == instance && owed.request == request
        })
    }

    pub(super) fn ready_binding(
        &self,
        room: Digest32,
        peer: Digest32,
    ) -> Option<(RequestId, Digest32, [u8; 16])> {
        self.ready
            .as_ref()
            .filter(|dispatch| {
                dispatch.room == room
                    && dispatch.peer == peer
                    && dispatch.eligible
                    && !dispatch.fence.is_retired()
            })
            .map(|dispatch| (dispatch.request, dispatch.generation, dispatch.instance))
    }

    /// Identify an unconsumed dispatch even while its membership check is pending.
    pub(super) fn unstarted_binding(
        &self,
        room: Digest32,
        peer: Digest32,
    ) -> Option<(RequestId, Digest32, [u8; 16])> {
        self.ready
            .as_ref()
            .filter(|dispatch| {
                dispatch.room == room
                    && dispatch.peer == peer
                    && !dispatch.fence.is_retired()
                    && self.owns_running_fence(
                        dispatch.request,
                        dispatch.generation,
                        &dispatch.fence,
                    )
            })
            .map(|dispatch| (dispatch.request, dispatch.generation, dispatch.instance))
    }

    pub(super) fn unstarted_dial_binding(&self, room: Digest32, peer: Digest32) -> bool {
        self.ready.as_ref().is_some_and(|dispatch| {
            dispatch.room == room
                && dispatch.peer == peer
                && dispatch.dial_eligible
                && !dispatch.fence.is_retired()
                && self.owns_running_fence(dispatch.request, dispatch.generation, &dispatch.fence)
        })
    }

    pub(super) fn take_legacy_cleanup(&mut self) -> Option<(Digest32, LegacyProvisionalOwner)> {
        self.cancelled_legacy.take()
    }
    pub(super) fn take_ready(&mut self, room: Digest32, peer: Digest32) -> Option<Dispatch> {
        if self.ready.as_ref().is_some_and(|d| {
            d.room == room && d.peer == peer && d.eligible && !d.fence.is_retired()
        }) {
            self.ready.take()
        } else {
            None
        }
    }
    /// The driver has durably checkpointed its exact original bounds before this callback.
    /// A returned continuation never queues another archive quantum.
    pub(super) fn completed(&mut self, request: RequestId, generation: Digest32, status: Status) {
        if self
            .running
            .as_ref()
            .is_some_and(|r| r.request == request && r.generation == generation)
            && status.request == Some(request)
        {
            self.running = None;
            self.ready = None;
            self.owner_status = Some(status);
        }
    }

    /// Install a durable result only for the exact operation still owned by this controller.
    /// A late Flow from a cancelled request, replaced room or retired node cannot complete the
    /// replacement merely because it reused the same actor.
    pub(super) fn completed_current(
        &mut self,
        room: Digest32,
        instance: [u8; 16],
        request: RequestId,
        generation: Digest32,
        status: Status,
    ) -> bool {
        if !self
            .running
            .as_ref()
            .is_some_and(|running| running.request == request && running.generation == generation)
            || !self.owner_status.as_ref().is_some_and(|current| {
                current.room == room
                    && current.instance == instance
                    && current.request == Some(request)
            })
            || status.room != room
            || status.instance != instance
            || status.request != Some(request)
        {
            return false;
        }
        self.completed(request, generation, status);
        true
    }
    /// A failed quantum leaves its durable request available for an explicit resume.
    pub(super) fn failed(&mut self, request: RequestId, generation: Digest32, detail: &str) {
        if !self
            .running
            .as_ref()
            .is_some_and(|r| r.request == request && r.generation == generation)
        {
            return;
        }
        if let Some(running) = self.running.take() {
            running.fence.retire();
            running.cancellation.cancel();
        }
        self.ready = None;
        if let Some(status) = self
            .owner_status
            .as_mut()
            .filter(|s| s.request == Some(request))
        {
            status.phase = Phase::Paused;
            status.detail = detail.chars().take(128).collect();
        }
    }

    /// Settle only the exact public archive owner named by a returned bounded Flow.
    ///
    /// A cancelled/replaced request, a retired room or node, and a later generation have already
    /// moved `running` or `owner_status`; an old worker must not pause or recreate any of them.
    /// The caller receives whether this Flow still owned the operation, so it can distinguish a
    /// truthful saved Pause from disposal of an already superseded capability.
    pub(super) fn failed_current(
        &mut self,
        room: Digest32,
        instance: [u8; 16],
        request: RequestId,
        generation: Digest32,
        detail: &str,
    ) -> bool {
        if !self
            .running
            .as_ref()
            .is_some_and(|running| running.request == request && running.generation == generation)
            || !self.owner_status.as_ref().is_some_and(|status| {
                status.room == room
                    && status.instance == instance
                    && status.request == Some(request)
            })
        {
            return false;
        }
        self.failed(request, generation, detail);
        true
    }
    fn stop_request(&mut self, room: Digest32, instance: [u8; 16], request: RequestId) -> bool {
        if !self
            .owner_status
            .as_ref()
            .is_some_and(|s| s.room == room && s.instance == instance && s.request == Some(request))
        {
            return false;
        }
        if let Some(running) = self.running.as_ref().filter(|r| r.request == request) {
            running.fence.retire();
            running.cancellation.cancel();
            self.running = None;
            self.ready = None;
        }
        true
    }
    pub(super) fn retire_room(&mut self, room: Digest32) {
        self.auto_pending.remove(&room);
        if let Some(probe) = self.auto_probe.as_ref().filter(|probe| probe.room == room) {
            probe.fence.retire();
        }
        if self.auto_pending.is_empty() && self.auto_probe.is_none() {
            self.auto_ticket = None;
            self.auto_wait = None;
        }

        if self
            .resume_owed
            .as_ref()
            .is_some_and(|owed| owed.room == room)
        {
            self.clear_resume_owed();
        }
        let owner_matches = self
            .owner_status
            .as_ref()
            .is_some_and(|status| status.room == room);
        let preparation_matches = self
            .preparing
            .as_ref()
            .is_some_and(|preparation| preparation.room == room);
        if !owner_matches && !preparation_matches {
            if self
                .observation
                .as_ref()
                .is_some_and(|status| status.room == room)
            {
                self.observation = None;
                self.observation_unread = false;
            }
            return;
        }
        if preparation_matches {
            if let Some(preparing) = &self.preparing {
                preparing.fence.retire();
                preparing.cancellation.cancel();
            }
        }
        if owner_matches {
            if let Some(running) = &self.running {
                running.fence.retire();
                running.cancellation.cancel();
            }
            self.running = None;
            self.ready = None;
        }
        if let Some(status) = self
            .owner_status
            .as_mut()
            .filter(|status| status.room == room)
        {
            status.phase = Phase::Paused;
            status.detail = "This room is no longer active; its saved history request can be cancelled locally.".into();
        }
        if self
            .observation
            .as_ref()
            .is_some_and(|status| status.room == room)
        {
            self.observation = None;
            self.observation_unread = false;
        }
    }

    /// Stop admission synchronously; the lock settling task then owns and retires this controller.
    pub(super) fn fence(&self) {
        if let Some(probe) = &self.auto_probe {
            probe.fence.retire();
        }
        if let Some(fence) = self
            .resume_owed
            .as_ref()
            .and_then(|owed| owed.wake_fence.as_ref())
        {
            fence.retire();
        }
        if let Some(running) = &self.running {
            running.fence.retire();
            running.cancellation.cancel();
        }
        if let Some(preparing) = &self.preparing {
            preparing.fence.retire();
            preparing.cancellation.cancel();
        }
    }

    /// Called before lock/shutdown reports completion. No queued event owns a secret context.
    pub(super) async fn retire(&mut self) {
        self.cancel_auto_recovery();
        if let Some(mut probe) = self.auto_probe.take() {
            if let Some(task) = probe.task.take() {
                let _ = task.await;
            }
        }
        self.clear_resume_owed();
        if let Some(running) = self.running.take() {
            running.fence.retire();
            running.cancellation.cancel();
        }
        self.ready = None;
        if let Some(preparing) = self.preparing.take() {
            preparing.fence.retire();
            preparing.cancellation.cancel();
            let _ = preparing.task.await;
            if let Ok(mut result) = preparing.result.lock() {
                *result = None;
            }
        }
        if let Some(work) = self.private_work.take() {
            let _ = work.task.await;
        }
        self.owner_status = None;
        self.observation = None;
        self.observation_unread = false;
    }
}
fn status(room: Digest32, instance: [u8; 16], phase: Phase, detail: &str) -> Status {
    Status {
        private_peer: None,
        private_lo: None,
        private_hi: None,
        room,
        instance,
        request: None,
        phase,
        author: None,
        head: None,
        remaining: 0,
        offset: 0,
        headers: 128,
        wire_bytes: 1024 * 1024,
        detail: detail.into(),
    }
}
pub(crate) fn saved_status(
    state: &demand::State,
    author: Option<Digest32>,
    active: Option<&demand::Active>,
) -> Status {
    let phase = match state.progress(active) {
        demand::Progress::Paused => Phase::Paused,
        demand::Progress::Pending => Phase::Pending,
        demand::Progress::More => Phase::More,
        demand::Progress::Unavailable => Phase::Unavailable,
        demand::Progress::Complete => Phase::Complete,
        demand::Progress::Cancelled => Phase::Cancelled,
    };
    Status {
        private_peer: state.private.as_ref().map(|p| p.donor),
        private_lo: state.private.as_ref().map(|_| state.bounds.lo),
        private_hi: state.private.as_ref().map(|_| state.bounds.hi),
        room: state.binding.room,
        instance: state.binding.instance,
        request: Some(state.request),
        phase,
        author,
        head: Some(state.bounds.head),
        remaining: state.remaining,
        offset: state
            .private
            .as_ref()
            .map(|p| p.positions.first().map_or(state.bounds.lo, |v| v.id))
            .unwrap_or_else(|| {
                state
                    .body
                    .as_ref()
                    .map_or_else(|| state.cursor.map_or(0, |c| c.offset), |body| body.offset)
            }),
        headers: state.bounds.entries,
        wire_bytes: if state.legacy.is_some() {
            crate::log::sync::LEGACY_QUANTUM_BYTES
        } else {
            1024 * 1024
        },
        detail: if state.reclaiming() {
            "Provisional history cleanup is pending."
        } else {
            "This operation covers only its selected bounded history interval."
        }
        .into(),
    }
}

impl Node {
    /// Inspect the single saved archive slot once for each newly opened room.
    pub(super) fn request_admitted_recovery(&mut self, room: Digest32) {
        self.history_demand
            .auto_pending
            .insert(room, self.history_demand.auto_intent);
    }

    fn wait_admitted_recovery(
        &mut self,
        wait: impl std::future::Future<Output = ()> + Send + 'static,
    ) {
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finished = Arc::clone(&done);
        let wake = Arc::clone(&self.bounded_completion_wake);
        let task = tokio::spawn(async move {
            wait.await;
            finished.store(true, std::sync::atomic::Ordering::Release);
            wake.notify_one();
        });
        self.history_demand.auto_wait = Some(AutoWait { done, task });
    }

    /// Report an admission error against the room instance without waiting on the actor.
    fn report_admitted_recovery_error(
        &mut self,
        room: Digest32,
        shared: Arc<Mutex<ChannelState>>,
        store: Arc<Store>,
        intent: u64,
        reason: String,
    ) {
        let fence = Fence::new();
        let worker_fence = Arc::clone(&fence);
        let weak = Arc::downgrade(&shared);
        let result = Arc::new(StdMutex::new(None));
        let output = Arc::clone(&result);
        let wake = Arc::clone(&self.bounded_completion_wake);
        let task = tokio::spawn(async move {
            let channel = tokio::select! {
                biased;
                () = worker_fence.retired() => { if let Ok(mut out) = output.lock() { *out = Some(Ok(None)); } wake.notify_one(); return; },
                channel = shared.lock() => channel,
            };
            let instance = channel.history_instance(&store).ok();
            if let Ok(mut out) = output.lock() {
                *out = Some(Err((instance, reason)));
            }
            drop(channel);
            wake.notify_one();
        });
        self.history_demand.auto_pending.remove(&room);
        self.history_demand.auto_probe = Some(AutoProbe {
            room,
            shared: weak,
            intent,
            fence,
            result,
            task: Some(task),
        });
    }

    /// Accept an exact local recovery or admit one bounded off-actor inspection.
    pub(super) fn advance_admitted_recovery(&mut self) {
        if let Some(probe) = self.history_demand.auto_probe.as_ref() {
            if !probe.fence.is_retired()
                && probe.intent == self.history_demand.auto_intent
                && (self.history_demand.preparing.is_some()
                    || self.history_demand.running.is_some()
                    || self.history_demand.ready.is_some()
                    || self.history_demand.private_work.is_some()
                    || self.history_demand.resume_owed.is_some())
            {
                return;
            }
            let result = probe
                .result
                .lock()
                .ok()
                .and_then(|mut result| result.take());
            let Some(result) = result else {
                return;
            };
            let room = probe.room;
            let current_probe =
                !probe.fence.is_retired() && probe.intent == self.history_demand.auto_intent;
            let old_room = probe.shared.upgrade();
            self.history_demand.auto_probe = None;
            let current = self.channels.get(&room);
            if current_probe
                && old_room
                    .as_ref()
                    .zip(current)
                    .is_some_and(|(old, current)| Arc::ptr_eq(old, current))
                && self.history_demand.preparing.is_none()
                && self.history_demand.running.is_none()
                && self.history_demand.ready.is_none()
                && self.history_demand.private_work.is_none()
                && self.history_demand.resume_owed.is_none()
            {
                match result {
                    Ok(Some((instance, request, admitted))) => {
                        let mut pending = status(
                            room,
                            instance,
                            Phase::Preparing,
                            "Recovering the admitted history entry locally.",
                        );
                        pending.request = Some(request);
                        self.history_demand.owner_status = Some(pending);
                        self.history_demand.owe_resume(room, instance, request);
                        if let Some(owed) = self.history_demand.resume_owed.as_mut() {
                            owed.private = Some(false);
                            owed.local_admitted = Some(admitted);
                        }
                        self.retry_owed_history_resume();
                    }
                    Ok(None) => {}
                    Err((Some(instance), reason)) => {
                        let detail =
                            format!("Saved history recovery could not be inspected: {reason}");
                        self.history_demand.observation =
                            Some(status(room, instance, Phase::Unavailable, &detail));
                        self.history_demand.observation_unread = true;
                    }
                    Err((None, reason)) => {
                        eprintln!("vox: saved history recovery could not be inspected: {reason}");
                    }
                }
            }
        }
        if self.history_demand.auto_probe.is_some()
            || self.history_demand.auto_pending.is_empty()
            || self.history_demand.preparing.is_some()
            || self.history_demand.running.is_some()
            || self.history_demand.ready.is_some()
            || self.history_demand.private_work.is_some()
            || self.history_demand.resume_owed.is_some()
        {
            return;
        }
        if let Some(wait) = self.history_demand.auto_wait.as_ref() {
            if !wait.done.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            self.history_demand.auto_wait = None;
        }
        let Some(profile) = self.profile.as_ref() else {
            return;
        };
        let node = profile.fingerprint();
        let store = profile.store_handle();
        let Some((&room, &intent)) = self.history_demand.auto_pending.first_key_value() else {
            return;
        };
        let Some(shared) = self.channels.get(&room).cloned() else {
            self.history_demand.auto_pending.remove(&room);
            self.bounded_completion_wake.notify_one();
            return;
        };
        if self.history_demand.auto_ticket.is_none() {
            self.history_demand.auto_ticket =
                Some(self.history_budget.enqueue(node, Lane::Control));
        }
        let ticket = self
            .history_demand
            .auto_ticket
            .as_mut()
            .expect("ticket was installed");
        let wake = ticket.wake();
        let Some(job) = ticket.try_admit() else {
            self.wait_admitted_recovery(wake);
            return;
        };
        self.history_demand.auto_ticket = None;
        let charge = match demand::AdmissionCharge::reserve(&job) {
            Ok(charge) => charge,
            Err(crate::error::Error::HistoryCapacity(pressure)) => {
                drop(job);
                self.wait_admitted_recovery(async move { (*pressure).released().await });
                return;
            }
            Err(error) => {
                self.report_admitted_recovery_error(room, shared, store, intent, error.to_string());
                return;
            }
        };
        let secret = match self.secret_work.clone().try_read_owned() {
            Ok(secret) => Arc::new(secret),
            Err(_) => {
                drop(charge);
                drop(job);
                let secret = self.secret_work.clone();
                self.wait_admitted_recovery(async move {
                    drop(secret.read_owned().await);
                });
                return;
            }
        };
        let context = match Context::unlocked(profile, secret) {
            Ok(context) => Arc::new(context),
            Err(error) => {
                self.report_admitted_recovery_error(room, shared, store, intent, error.to_string());
                return;
            }
        };
        let weak = Arc::downgrade(&shared);
        let fence = Fence::new();
        let worker_fence = Arc::clone(&fence);
        let result = Arc::new(StdMutex::new(None));
        let output = Arc::clone(&result);
        let wake = Arc::clone(&self.bounded_completion_wake);
        let task = tokio::spawn(async move {
            let inspected = tokio::task::spawn_blocking(move || {
                let saved = demand::inspect_precharged(&context, charge)
                    .map_err(|error| error.to_string())?;
                let value = saved.as_ref().and_then(|saved| {
                    let state = saved.state();
                    (state.binding.room == room
                        && !matches!(
                            state.progress(None),
                            demand::Progress::Complete | demand::Progress::Cancelled
                        ))
                    .then_some((
                        state.binding.instance,
                        state.request,
                        state.admitted?,
                    ))
                });
                drop(saved);
                drop(job);
                Ok::<_, String>(value)
            })
            .await
            .map_err(|_| "History recovery inspection stopped.".to_owned())
            .and_then(|result| result);
            let checked = match inspected {
                Ok(None) => Ok(None),
                inspected => {
                    let channel = tokio::select! {
                        biased;
                        () = worker_fence.retired() => { if let Ok(mut out) = output.lock() { *out = Some(Ok(None)); } wake.notify_one(); return; },
                        channel = shared.lock() => channel,
                    };
                    match (channel.history_instance(&store), inspected) {
                        (Ok(current), Ok(Some((instance, request, admitted))))
                            if current == instance =>
                        {
                            Ok(Some((instance, request, admitted)))
                        }
                        (Ok(_), Ok(_)) => Ok(None),
                        (Ok(current), Err(error)) => Err((Some(current), error)),
                        (Err(error), _) => Err((None, error.to_string())),
                    }
                }
            };
            if let Ok(mut out) = output.lock() {
                *out = Some(checked);
            }
            wake.notify_one();
        });
        self.history_demand.auto_pending.remove(&room);
        self.history_demand.auto_probe = Some(AutoProbe {
            room,
            shared: weak,
            intent,
            fence,
            result,
            task: Some(task),
        });
    }

    /// Move an unstarted public page to a connected trusted room member without replacing
    /// its exact request, authorization, staging or bounds. No physical Flow has consumed it.
    pub(super) fn reroute_unstarted_history(&mut self) {
        let Some(dispatch) = self.history_demand.ready.as_ref() else {
            self.history_demand.route_lock_wait = None;
            return;
        };
        let dispatch_fence = Arc::clone(&dispatch.fence);
        let (room, instance, request, generation, peer) = (
            dispatch.room,
            dispatch.instance,
            dispatch.request,
            dispatch.generation,
            dispatch.peer,
        );
        if dispatch.fence.is_retired()
            || !self
                .history_demand
                .owns_running_fence(request, generation, &dispatch.fence)
            || self
                .history_demand
                .has_other_resume(room, instance, request)
        {
            return;
        }
        let Some(current) = self.current_room(&room) else {
            return;
        };
        let connected = |candidate: Digest32| {
            if !self.trust.is_trusted(&candidate)
                || !self
                    .ports
                    .get(&(room, candidate))
                    .is_some_and(|port| port.room.is(&current))
            {
                return None;
            }
            self.net
                .as_ref()
                .and_then(|net| net.manager().existing(&candidate))
                .filter(|conn| conn.quinn().close_reason().is_none())
        };
        let original_connected = connected(peer).is_some();
        let mut candidates: Vec<_> = self
            .ports
            .keys()
            .filter_map(|(r, candidate)| {
                if *r != room || *candidate == peer {
                    return None;
                }
                connected(*candidate).map(|conn| (*candidate, conn.serial()))
            })
            .collect();
        candidates.sort_unstable();
        let was_eligible = self
            .history_demand
            .ready
            .as_ref()
            .is_some_and(|dispatch| dispatch.eligible);
        let Some(shared) = self.channels.get(&room).cloned() else {
            return;
        };
        let ch = match shared.try_lock() {
            Ok(ch) => ch,
            Err(_) => {
                if let Some(dispatch) = self.history_demand.ready.as_mut() {
                    dispatch.eligible = false;
                    dispatch.dial_eligible = false;
                }
                self.bounded_sync
                    .cancel_unstarted_archive_admission(room, peer, instance, request, generation);
                let needs_wait = self
                    .history_demand
                    .route_lock_wait
                    .as_ref()
                    .is_none_or(|wait| {
                        !Arc::ptr_eq(&wait.fence, &dispatch_fence)
                            || wait.done.load(std::sync::atomic::Ordering::Acquire)
                    });
                if needs_wait {
                    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let finished = Arc::clone(&done);
                    let fence = Arc::clone(&dispatch_fence);
                    let worker_fence = Arc::clone(&fence);
                    let wake = Arc::clone(&self.bounded_completion_wake);
                    let waiting_room = Arc::clone(&shared);
                    let task = tokio::spawn(async move {
                        tokio::select! {
                            biased;
                            () = worker_fence.retired() => return,
                            guard = waiting_room.lock_owned() => drop(guard),
                        }
                        finished.store(true, std::sync::atomic::Ordering::Release);
                        wake.notify_one();
                    });
                    self.history_demand.route_lock_wait = Some(RouteLockWait { fence, done, task });
                }
                return;
            }
        };
        let original_member = self.trust.is_trusted(&peer)
            && self
                .ports
                .get(&(room, peer))
                .is_some_and(|port| port.room.is(&current))
            && ch.history_inventory_incarnation(&peer).is_some();
        let original_ready = original_connected && original_member;
        let candidates: Vec<_> = candidates
            .into_iter()
            .map(|(peer, serial)| (peer, serial, ch.history_inventory_incarnation(&peer)))
            .collect();
        drop(ch);
        self.history_demand.route_lock_wait = None;
        if let Some(dispatch) = self.history_demand.ready.as_mut() {
            dispatch.dial_eligible = original_member;
        }
        if original_ready {
            if let Some(dispatch) = self.history_demand.ready.as_mut() {
                dispatch.eligible = true;
            }
            if !was_eligible {
                self.sched_rooms.insert(room);
            }
            if let Some(status) = self.history_demand.owner_status.as_mut().filter(|status| {
                status.room == room
                    && status.instance == instance
                    && status.request == Some(request)
            }) {
                status.detail = "One bounded history quantum is queued. Further history requires an explicit resume.".into();
            }
            return;
        }
        if let Some(dispatch) = self.history_demand.ready.as_mut() {
            dispatch.eligible = false;
        }
        self.bounded_sync
            .cancel_unstarted_archive_admission(room, peer, instance, request, generation);
        if !candidates
            .iter()
            .any(|(_, _, incarnation)| incarnation.is_some())
        {
            if let Some(status) = self.history_demand.owner_status.as_mut().filter(|status| {
                status.room == room
                    && status.instance == instance
                    && status.request == Some(request)
            }) {
                status.detail = "History is waiting for a trusted connected room member.".into();
            }
            return;
        }
        // The public page binding is independent of its transport donor. Move the same
        // unconsumed dispatch and exact activation, rather than retiring it for a fallible
        // asynchronous Resume which could lose the request if this peer disconnects.
        let Some((next, _, _)) = candidates.into_iter().find(|(_, _, life)| life.is_some()) else {
            return;
        };
        if let Some(dispatch) = self.history_demand.ready.as_mut() {
            dispatch.peer = next;
            dispatch.eligible = true;
            dispatch.dial_eligible = true;
        }
        if let Some(status) = self.history_demand.owner_status.as_mut().filter(|status| {
            status.room == room && status.instance == instance && status.request == Some(request)
        }) {
            status.detail = "One bounded history quantum is queued with a connected member.".into();
        }
        self.sched_rooms.insert(room);
    }

    /// Whether the running quantum's page already covers the position below `before`.
    fn running_page_covers(&self, room: Digest32, before: &Digest32) -> bool {
        let Some((head, lo, hi)) = self.history_demand.running.as_ref().and_then(|r| r.page) else {
            return false;
        };
        let Some(profile) = self.profile.as_ref() else {
            return false;
        };
        let Some(shared) = self.channels.get(&room) else {
            return false;
        };
        let Ok(ch) = shared.try_lock() else {
            return false;
        };
        let store = profile.store();
        let Ok(read) = ch.history_read(store) else {
            return false;
        };
        let Ok(Some(bytes)) = read.history_object(ObjectKind::Header, before) else {
            return false;
        };
        let Ok(entry) = crate::log::entry::Entry::from_wire(&bytes) else {
            return false;
        };
        let Ok(Some(current)) = ch.history_head(store, &entry.skeleton.author_id) else {
            return false;
        };
        let wanted = entry.skeleton.seq.saturating_sub(1);
        current.id() == head && wanted >= lo && wanted <= hi
    }

    pub(super) fn begin_history_demand(
        &mut self,
        room: Digest32,
        instance: [u8; 16],
        action: Action,
    ) -> Result<Status, String> {
        let retained_resume = match &action {
            Action::Resume { request } => self
                .history_demand
                .resume_owed_matches(room, instance, *request),
            _ => false,
        };
        if retained_resume {
            // The command names the already-retained exact owner. Advance that owner rather
            // than canceling its fair ticket and creating a second admission attempt.
            self.retry_owed_history_resume();
            return Ok(self.history_demand.owner_status.clone().unwrap_or_else(|| {
                status(
                    room,
                    instance,
                    Phase::Busy,
                    "The exact saved history resume is retained locally.",
                )
            }));
        }
        if matches!(action, Action::Resume { .. }) && self.history_demand.resume_owed.is_some() {
            // A stale selector cannot cancel the exact accepted action already waiting here.
            return Err("The requested resume does not match the retained history request.".into());
        }
        self.begin_history_demand_with_job(room, instance, action, None, None, None)
    }

    fn begin_history_demand_with_job(
        &mut self,
        room: Digest32,
        instance: [u8; 16],
        action: Action,
        admitted: Option<Job>,
        resume_private: Option<bool>,
        local_admitted: Option<demand::AdmittedEntry>,
    ) -> Result<Status, String> {
        self.accept_history_demand();
        if matches!(action, Action::Status) {
            if let Some(current) = self
                .history_demand
                .owner_status
                .as_ref()
                .filter(|status| status.room == room && status.instance == instance)
            {
                return Ok(current.clone());
            }
            if let Some(current) = self
                .history_demand
                .observation
                .as_ref()
                .filter(|status| status.room == room && status.instance == instance)
                .cloned()
            {
                let unread = std::mem::take(&mut self.history_demand.observation_unread);
                let preparing = self
                    .history_demand
                    .preparing
                    .as_ref()
                    .is_some_and(|preparation| {
                        preparation.origin == PreparationOrigin::Observation
                            && preparation.room == room
                            && preparation.instance == instance
                    });
                if unread
                    || preparing
                    || current.request.is_some()
                    || !matches!(current.phase, Phase::Unavailable | Phase::Paused)
                {
                    return Ok(current);
                }
            }
        }
        if self.history_demand.preparing.is_some() {
            return Ok(status(
                room,
                instance,
                Phase::Busy,
                "A local history request is being prepared.",
            ));
        }
        // A retained local cleanup owns a committed entry. Finish or explicitly cancel
        // that exact request before a new page can replace its recovery wake.
        if local_admitted.is_none()
            && matches!(
                action,
                Action::Newest | Action::Older { .. } | Action::PrivateRecover { .. }
            )
            && self
                .history_demand
                .resume_owed
                .as_ref()
                .is_some_and(|owed| owed.local_admitted.is_some())
        {
            return Ok(status(room, instance, Phase::Busy,
                "The saved history entry is recovering locally; retry this request when it finishes."));
        }
        let cancel_request = if let Action::Cancel { request } = action {
            if (self.history_demand.running.is_some() || self.history_demand.private_work.is_some())
                && !self.history_demand.owner_status.as_ref().is_some_and(|s| {
                    s.room == room && s.instance == instance && s.request == Some(request)
                })
            {
                return Err(
                    "The active history request belongs to a different room, instance or request."
                        .into(),
                );
            }
            if self
                .history_demand
                .resume_owed
                .as_ref()
                .is_some_and(|owed| {
                    owed.room != room || owed.instance != instance || owed.request != request
                })
            {
                return Err(
                    "The retained history request belongs to a different room, instance or request."
                        .into(),
                );
            }
            Some(request)
        } else if self.history_demand.running.is_some() {
            // An explicit new page ask is the person's newer intent: it ends the quantum still
            // running for an earlier ask (what it published stays) and takes its place. Status
            // and Resume answer the running one as before. Measured before this: a newcomer
            // paging back was told "one bounded history quantum is queued" while nothing was
            // queued, and the page below his live window was never asked for.
            // An ask for the page below a row that the page in flight is already bringing is
            // that same ask: it gets the running quantum's status and lets it finish. Measured:
            // a reader re-asking as each row showed cancelled its own page every 500 ms and got
            // two rows per ask.
            let covered = match action {
                Action::Older { before } => self.running_page_covers(room, &before),
                _ => false,
            };
            let replaceable = !covered
                && matches!(action, Action::Newest | Action::Older { .. })
                && self
                    .history_demand
                    .running
                    .as_ref()
                    .zip(self.history_demand.owner_status.as_ref())
                    .is_some_and(|(running, current)| {
                        current.room == room
                            && current.instance == instance
                            && current.request == Some(running.request)
                    });
            if replaceable {
                if let Some(request) = self.history_demand.running.as_ref().map(|r| r.request) {
                    if self.history_demand.stop_request(room, instance, request) {
                        self.bounded_sync.cancel_archive(room, instance, request);
                    }
                }
            } else {
                return Ok(self
                    .history_demand
                    .owner_status
                    .clone()
                    .filter(|s| s.room == room && s.instance == instance)
                    .unwrap_or_else(|| {
                        status(
                            room,
                            instance,
                            Phase::Busy,
                            "A history operation is active; cancel it before starting another.",
                        )
                    }));
            }
            None
        } else {
            None
        };
        if cancel_request.is_none() && self.history_demand.private_work.is_some() {
            return Ok(self
                .history_demand
                .owner_status
                .clone()
                .filter(|status| status.room == room && status.instance == instance)
                .unwrap_or_else(|| {
                    status(
                        room,
                        instance,
                        Phase::Busy,
                        "Private history work is settling.",
                    )
                }));
        }
        let profile = self.profile.as_ref().ok_or("node is locked")?;
        let node = profile.fingerprint();
        let local_only = matches!(action, Action::Status | Action::Cancel { .. });
        let shared = self.channels.get(&room).cloned();
        if !local_only && shared.is_none() {
            return Err("room is not open".into());
        }
        let selection_after = self
            .history_demand
            .selection
            .filter(|(r, i, _)| *r == room && *i == instance)
            .and_then(|(_, _, after)| after);
        let job = match admitted {
            Some(job) => job,
            None => {
                let Some(job) = self.history_budget.try_start(node, Lane::Control) else {
                    return Ok(status(
                        room,
                        instance,
                        Phase::Busy,
                        "History preparation is busy; cached messages remain available.",
                    ));
                };
                job
            }
        };
        let mut resume_admission = None;
        let mut resume_inspect = None;
        if let Action::Resume { request } = action {
            let admission = if let Some(private) = resume_private {
                demand::ResumeAdmission::reserve(&job, PREPARATION_SCRATCH, private)
                    .map(|credit| resume_admission = Some(credit))
            } else {
                demand::AdmissionCharge::reserve(&job).map(|credit| resume_inspect = Some(credit))
            };
            match admission {
                Ok(()) => {}
                Err(crate::error::Error::HistoryCapacity(pressure)) => {
                    drop(job);
                    return Ok(self.retain_resume_wait(
                        room,
                        instance,
                        request,
                        resume_private,
                        local_admitted,
                        Box::pin(async move { (*pressure).released().await }),
                        "Waiting for local history preparation buffer capacity.",
                    ));
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        let local_admission = match action {
            Action::Status => demand::LocalAdmission::status(&job).map(Some),
            Action::Cancel { .. } => demand::LocalAdmission::cancel(&job).map(Some),
            _ => Ok(None),
        };
        let local_admission = match local_admission {
            Ok(admission) => admission,
            Err(crate::error::Error::HistoryCapacity(_)) => {
                return Ok(status(
                    room,
                    instance,
                    Phase::Busy,
                    "History preparation buffers are busy; cached messages remain available.",
                ));
            }
            Err(error) => return Err(error.to_string()),
        };
        let preparation_scratch = if local_admission.is_none()
            && resume_admission.is_none()
            && resume_inspect.is_none()
        {
            let Some(charge) = job.reserve(PREPARATION_SCRATCH) else {
                return Ok(status(
                    room,
                    instance,
                    Phase::Busy,
                    "History preparation buffers are busy; cached messages remain available.",
                ));
            };
            Some(charge)
        } else {
            None
        };
        let secret_work = match self.secret_work.clone().try_read_owned() {
            Ok(guard) => Arc::new(guard),
            Err(_) => {
                if let (Action::Resume { request }, Some(expected)) = (action, local_admitted) {
                    drop(resume_admission);
                    drop(job);
                    let secret = self.secret_work.clone();
                    return Ok(self.retain_resume_wait(
                        room,
                        instance,
                        request,
                        resume_private,
                        Some(expected),
                        Box::pin(async move {
                            drop(secret.read_owned().await);
                        }),
                        "Waiting for the node's local history access.",
                    ));
                }
                return Err("Node secret work is settling; history was not started.".into());
            }
        };
        let context = Arc::new(Context::unlocked(profile, secret_work).map_err(|e| e.to_string())?);
        let store = profile.store_handle();
        let preserve_local_owed = cancel_request.is_some_and(|request| {
            self.history_demand
                .resume_owed
                .as_ref()
                .is_some_and(|owed| {
                    owed.room == room
                        && owed.instance == instance
                        && owed.request == request
                        && owed.local_admitted.is_some()
                })
        });
        let prior_private = if let Some(request) = cancel_request {
            if !preserve_local_owed {
                self.history_demand.clear_resume_owed();
            }
            if self.history_demand.stop_request(room, instance, request) {
                self.bounded_sync.cancel_archive(room, instance, request);
            }
            self.history_demand.private_work.take()
        } else {
            None
        };
        let peers: Vec<_> = self
            .ports
            .keys()
            .filter(|(r, p)| *r == room && *p != node && self.trust.is_trusted(p))
            .map(|(_, p)| *p)
            .collect();
        let connected_peers: std::collections::BTreeSet<_> = peers
            .iter()
            .copied()
            .filter(|peer| {
                self.net
                    .as_ref()
                    .and_then(|net| net.manager().existing(peer))
                    .is_some_and(|conn| conn.quinn().close_reason().is_none())
            })
            .collect();
        self.history_demand.next = self
            .history_demand
            .next
            .checked_add(1)
            .ok_or("history preparation serial exhausted")?;
        let token = self.history_demand.next;
        let fence = Fence::new();
        let cancellation = context.cancellation();
        let result = Arc::new(StdMutex::new(None));
        let result_out = result.clone();
        let worker_fence = fence.clone();
        let tx = self.net_tx.clone();
        let weak = shared.as_ref().map(Arc::downgrade).unwrap_or_default();
        let now = self.now_ms().get();
        let local_cancel = matches!(action, Action::Cancel { .. });
        let task = tokio::spawn(async move {
            let work = async {
                if let Some(prior) = prior_private { let _ = prior.task.await; }
                // Reclaim only an already-admitted exact public entry before taking the room
                // lock. Each slice removes durable pages; interruption leaves the locator and
                // remaining pages for the same explicit request.
                if let Action::Resume { request } = action {
                    if let Some(admission) = resume_admission.take() {
                        let cleanup_context = Arc::clone(&context);
                        let cleanup_fence = Arc::clone(&worker_fence);
                        let admission = tokio::task::spawn_blocking(move || -> Result<demand::ResumeAdmission, String> {
                            let recover = demand::has_admitted_recovery(
                                &cleanup_context, admission.mutation(), room, instance, request, local_admitted,
                            ).map_err(|error| error.to_string())?;
                            if recover {
                                loop {
                                    if cleanup_fence.is_retired() {
                                        return Err("History recovery was cancelled.".into());
                                    }
                                    if demand::reclaim_precharged(&cleanup_context, request, admission.mutation())
                                        .map_err(|error| error.to_string())? { break; }
                                    std::thread::yield_now();
                                }
                            }
                            Ok(admission)
                        }).await.map_err(|_| "History cleanup worker stopped.".to_owned())??;
                        resume_admission = Some(admission);
                    }
                }
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
                let room_guard = if local_only || resume_inspect.is_some() { None } else {
                    let shared = shared.ok_or("room is not open")?;
                    Some(tokio::select! {
                        biased;
                        () = worker_fence.retired() => return Err("history preparation cancelled".into()),
                        guard = tokio::time::timeout_at(deadline, shared.lock_owned()) => guard.map_err(|_| "history room is busy".to_owned())?,
                    })
                };
                let read_fence = worker_fence.clone();
                // Do not detach this read on cancellation: retire() awaits its bounded completion.
                tokio::task::spawn_blocking(move || {
                    let _charge = preparation_scratch;
                    if read_fence.is_retired()
                        || (!local_cancel && tokio::time::Instant::now() >= deadline)
                    {
                        return Err("history preparation cancelled or expired".into());
                    }
                    let answer = match (room_guard, resume_inspect) {
                        (_, Some(credit)) => classify_resume(node, room, instance, action, context, credit),
                        (Some(guard), None) => prepare(&guard, &store, node, instance, action, context, &job, peers, connected_peers, weak, read_fence.clone(), now, deadline, selection_after, resume_admission, local_admitted),
                        (None, None) => prepare_local(
                            node,
                            room,
                            instance,
                            action,
                            context,
                            local_admission.ok_or("local history admission is missing")?,
                            &read_fence,
                        ),
                    };
                    let durable = answer.as_ref().is_ok_and(|prepared| {
                        prepared.local_boundary != LocalBoundary::Observed
                    });
                    if !durable
                        && (read_fence.is_retired()
                            || tokio::time::Instant::now() >= deadline)
                    {
                        return Err("history preparation cancelled or expired".into());
                    }
                    answer
                }).await.map_err(|_| "history preparation worker stopped".to_owned())?
            }.await;
            if let Ok(mut output) = result_out.lock() {
                *output = Some(work);
            }
            // A full inbox does not strand the result: schedule() and status also check this slot.
            let _ = tx.try_send(NetEvent::HistoryDemandPrepared { token });
        });
        let mut pending = status(
            room,
            instance,
            Phase::Preparing,
            "Checking cached history and preparing one bounded request.",
        );
        pending.request = match action {
            Action::Cancel { request } | Action::Resume { request } => Some(request),
            _ => None,
        };
        // Only an operation which reached accepted preparation owns public status. Direct
        // Busy/refusal paths above leave the previous operation's status and ownership intact,
        // so they cannot relabel an old result as the newer attempted action.
        if !matches!(action, Action::Status) && !preserve_local_owed {
            // A confirmed exact cancel retires a retained local recovery only after its durable
            // outcome; other fully admitted replacement actions retire their older waiter here.
            self.history_demand.clear_resume_owed();
        }
        let origin = if matches!(action, Action::Status) {
            self.history_demand.observation = Some(pending.clone());
            self.history_demand.observation_unread = false;
            PreparationOrigin::Observation
        } else {
            self.history_demand.observation = None;
            self.history_demand.observation_unread = false;
            self.history_demand.owner_status = Some(pending.clone());
            PreparationOrigin::Explicit
        };
        self.history_demand.preparing = Some(Preparation {
            token,
            origin,
            action,
            user_intent: local_admitted.is_none() && !matches!(action, Action::Status),
            room,
            instance,
            fence,
            cancellation,
            result,
            task,
        });
        Ok(pending)
    }

    /// A refused complete Resume admission retains only identity and a resource dependency.
    /// No Context, room lock, Job or allocation can cross into this waiter.
    fn retain_resume_wait(
        &mut self,
        room: Digest32,
        instance: [u8; 16],
        request: RequestId,
        private: Option<bool>,
        local_admitted: Option<demand::AdmittedEntry>,
        wait: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
        detail: &str,
    ) -> Status {
        self.history_demand.clear_resume_owed();
        let mut pending = self
            .history_demand
            .owner_status
            .as_ref()
            .filter(|status| {
                status.room == room
                    && status.instance == instance
                    && status.request == Some(request)
            })
            .cloned()
            .unwrap_or_else(|| status(room, instance, Phase::Preparing, ""));
        pending.request = Some(request);
        pending.phase = Phase::Preparing;
        pending.detail = detail.into();
        self.history_demand.owner_status = Some(pending.clone());
        self.history_demand.observation = None;
        self.history_demand.observation_unread = false;
        let fence = Fence::new();
        let wake_fence = fence.clone();
        let tx = self.net_tx.clone();
        let task = tokio::spawn(async move {
            tokio::select! {
                biased;
                () = wake_fence.retired() => return,
                () = wait => {}
            }
            let _ = tx
                .send(NetEvent::HistoryResumeReady {
                    room,
                    instance,
                    request,
                    fence: wake_fence,
                })
                .await;
        });
        self.history_demand.resume_owed = Some(ResumeOwed {
            room,
            instance,
            request,
            ticket: None,
            wake_task: Some(task),
            wake_fence: Some(fence),
            waiting_bytes: true,
            private,
            local_admitted,
        });
        pending
    }

    /// Attempt the one retained archive Resume owner once. A busy Control lane keeps its fair
    /// ticket and receives the exact capacity-release wake. A byte-blocked owner is retried only
    /// by its exact dependency event; real preflight errors remain terminal action results.
    /// Successful preparation atomically replaces this owner without another user action.
    pub(super) fn retry_owed_history_resume(&mut self) {
        let Some(mut owed) = self.history_demand.resume_owed.take() else {
            return;
        };
        if owed.waiting_bytes
            || self.history_demand.preparing.is_some()
            || self.history_demand.running.is_some()
            || self.history_demand.ready.is_some()
            || self.history_demand.private_work.is_some()
        {
            self.history_demand.resume_owed = Some(owed);
            return;
        }
        let Some(node) = self.profile.as_ref().map(|profile| profile.fingerprint()) else {
            self.history_demand.resume_owed = Some(owed);
            return;
        };
        if owed.ticket.is_none() {
            owed.ticket = Some(self.history_budget.enqueue(node, Lane::Control));
        }
        let Some(ticket) = owed.ticket.as_mut() else {
            self.history_demand.resume_owed = Some(owed);
            return;
        };
        // Subscribe before the attempt so a release between the failed admission and task spawn
        // cannot be lost. Keeping the Ticket in `ResumeOwed` preserves FIFO position.
        let wake = ticket.wake();
        if let Some(job) = ticket.try_admit() {
            owed.ticket = None;
            if let Some(task) = owed.wake_task.take() {
                task.abort();
            }
            if let Some(fence) = owed.wake_fence.take() {
                fence.retire();
            }
            let result = self.begin_history_demand_with_job(
                owed.room,
                owed.instance,
                Action::Resume {
                    request: owed.request,
                },
                Some(job),
                owed.private,
                owed.local_admitted,
            );
            if self.history_demand.preparing.is_none() && self.history_demand.resume_owed.is_none()
            {
                if let Err(error) = result {
                    if let Some(status) = self
                        .history_demand
                        .owner_status
                        .as_mut()
                        .filter(|status| status.request == Some(owed.request))
                    {
                        status.phase = Phase::Unavailable;
                        status.detail = error.chars().take(128).collect();
                    }
                } else {
                    self.history_demand.resume_owed = Some(owed);
                }
            }
            return;
        }
        if owed.wake_task.is_none() {
            let tx = self.net_tx.clone();
            let room = owed.room;
            let instance = owed.instance;
            let request = owed.request;
            let fence = Fence::new();
            owed.wake_fence = Some(fence.clone());
            owed.wake_task = Some(tokio::spawn(async move {
                tokio::select! {
                    biased;
                    () = fence.retired() => return,
                    () = wake => {}
                }
                let _ = tx
                    .send(NetEvent::HistoryResumeReady {
                        room,
                        instance,
                        request,
                        fence,
                    })
                    .await;
            }));
        }
        self.history_demand.resume_owed = Some(owed);
    }

    fn start_private_history(&mut self, dispatch: PrivateDispatch) {
        let Some(profile) = self.profile.as_ref() else {
            self.history_demand.failed(
                dispatch.request,
                dispatch.generation,
                "Node locked; private recovery is paused.",
            );
            return;
        };
        let node = profile.fingerprint();
        let store = profile.store_handle();
        let Some(shared) = self.channels.get(&dispatch.room).cloned() else {
            self.history_demand.failed(
                dispatch.request,
                dispatch.generation,
                "Room closed; private recovery is paused.",
            );
            return;
        };
        let Some(conn) = self
            .net
            .as_ref()
            .and_then(|net| net.manager().existing(&dispatch.peer))
        else {
            self.history_demand.failed(
                dispatch.request,
                dispatch.generation,
                "Private donor is offline; resume after it reconnects.",
            );
            return;
        };
        let Some(job) = self.history_budget.try_start(node, Lane::Archive) else {
            self.history_demand.failed(
                dispatch.request,
                dispatch.generation,
                "Archive worker is busy; resume this request later.",
            );
            return;
        };
        let Some(slot) =
            crate::node::ports::Slots::take(&self.slots, dispatch.peer, Box::new(|| {}))
        else {
            self.history_demand.failed(
                dispatch.request,
                dispatch.generation,
                "Peer transfer slots are busy; resume this request later.",
            );
            return;
        };
        let request = dispatch.request;
        let generation = dispatch.generation;
        let result = Arc::new(StdMutex::new(None));
        let output = result.clone();
        let tx = self.net_tx.clone();
        let now = self.now_ms().get();
        let task = tokio::spawn(async move {
            let _slot = slot;
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
            let work = async {
                let bounds = dispatch.bounds;
                let plan = dispatch.plan.clone();
                let check = PrivateGuard { node, room: dispatch.room, instance: dispatch.instance, generation, context: dispatch.staging.context.clone(), fence: dispatch.fence.clone(), deadline };
                let (ask, trust_nonce) = private_room(shared.clone(), store.clone(), job.clone(), check.clone(), move |room, store| {
                    let nonce = store.get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(crate::node::trust::TRUST_META_KEY).map_err(|e| e.to_string())?;
                    let ask = room.private_history_ask(store, bounds, &plan).map_err(|e| e.to_string())?;
                    Ok((ask, nonce))
                }).await?;
                let page = tokio::select! {
                    biased;
                    () = dispatch.fence.retired() => return Err("Private recovery cancelled.".into()),
                    answer = tokio::time::timeout_at(deadline, crate::node::sessionstream::pull(&conn, ask, job.clone())) => answer.map_err(|_| "Private recovery deadline elapsed.")?.map_err(|e| e.to_string())?,
                };
                let context = dispatch.staging.context.clone();
                let active = dispatch.staging.active.clone();
                let expected = dispatch.plan;
                let checkpoint_job = job.clone();
                private_room(shared, store, job, check, move |room, store| {
                    let mut next = expected.clone();
                    room.finish_private_history(store, bounds, &mut next, page, now, trust_nonce).map_err(|e| e.to_string())?;
                    let remaining = next.positions.len();
                    let progress = if next.inventory_done && remaining == 0 { demand::Progress::Complete } else { demand::Progress::More };
                    let mut active = active.lock().map_err(|_| "Private recovery state poisoned.")?;
                    demand::checkpoint_private(&context, &mut active, &expected, next, remaining, progress, &checkpoint_job).map_err(|e| e.to_string())?;
                    let saved = demand::inspect(&context, &checkpoint_job).map_err(|e| e.to_string())?.ok_or("Private recovery state disappeared.")?;
                    let mut status = saved_status(saved.state(), None, Some(&active));
                    status.detail = if progress == demand::Progress::Complete {
                        "The selected donor interval was examined. This does not prove complete private history; another interval requires an explicit request."
                    } else {
                        "This private recovery quantum is retained. Resume explicitly to continue the same interval."
                    }.into();
                    Ok(status)
                }).await
            }.await;
            if let Ok(mut result) = output.lock() {
                *result = Some(work);
            }
            let _ = tx.try_send(NetEvent::HistoryDemandPrepared { token: 0 });
        });
        self.history_demand.private_work = Some(PrivateWork {
            legacy_owner: None,
            result,
            request,
            generation,
            task,
        });
    }

    /// Metadata-only event; a single private result slot owns any not-yet-dispatched context.
    pub(super) fn accept_history_demand(&mut self) -> bool {
        let completed = self.history_demand.private_work.as_ref().and_then(|work| {
            let answer = work.result.try_lock().ok()?.take()?;
            Some((work.request, work.generation, work.legacy_owner, answer))
        });
        if let Some((request, generation, legacy_owner, answer)) = completed {
            self.history_demand.private_work = None;
            if answer
                .as_ref()
                .is_ok_and(|status| status.phase == Phase::Cancelled)
            {
                self.history_demand.cancelled_legacy = legacy_owner;
            }
            match answer {
                Ok(status) => self.history_demand.completed(request, generation, status),
                Err(reason) => self.history_demand.failed(request, generation, &reason),
            }
            return true;
        }
        let Some(preparation) = self.history_demand.preparing.as_ref() else {
            return false;
        };
        let origin = preparation.origin;
        let action = preparation.action;
        let user_intent = preparation.user_intent;
        let target_room = preparation.room;
        let target_instance = preparation.instance;
        let retired = preparation.fence.is_retired();
        let Ok(mut result) = preparation.result.try_lock() else {
            return false;
        };
        let Some(ready) = result.as_ref() else {
            return false;
        };
        if let Ok(prepared) = ready {
            if prepared.resume_kind.is_some() && retired {
                drop(result);
                self.history_demand.preparing = None;
                return true;
            }
            let local_boundary = prepared.local_boundary;
            if local_boundary == LocalBoundary::Superseded
                || (local_boundary == LocalBoundary::Durable && retired)
            {
                let completed = result.take();
                drop(result);
                self.history_demand.preparing = None;
                if let Some(Ok(prepared)) = completed {
                    if let Some(owner) = prepared.legacy_cancelled {
                        self.history_demand.cancelled_legacy = Some((prepared.status.room, owner));
                    }
                }
                if local_boundary == LocalBoundary::Superseded
                    && !retired
                    && self
                        .history_demand
                        .owner_status
                        .as_ref()
                        .is_some_and(|status| {
                            status.room == target_room && status.instance == target_instance
                        })
                {
                    self.history_demand.owner_status = None;
                }
                return true;
            }
            let target_matches =
                prepared.status.room == target_room && prepared.status.instance == target_instance;
            let current = self
                .profile
                .as_ref()
                .filter(|p| p.fingerprint() == prepared.node)
                .and_then(|profile| {
                    self.channels
                        .get(&prepared.status.room)
                        .map(|room| (profile, room))
                });
            // A completed local checkpoint is an outcome, not authority to dispatch. Preserve
            // it across a later trust edit only while the exact current request and room still
            // own this result; the normal current-authority checks remain mandatory for work.
            let committed_terminal = prepared.terminal_checkpoint
                && prepared.local_boundary == LocalBoundary::Durable
                && prepared.status.phase == Phase::Complete
                && prepared.dispatch.is_none()
                && prepared.private.is_none()
                && matches!(action, Action::Resume { request } if prepared.status.request == Some(request))
                && self
                    .history_demand
                    .owner_status
                    .as_ref()
                    .is_some_and(|status| {
                        status.room == target_room
                            && status.instance == target_instance
                            && status.request == prepared.status.request
                    });
            let mut same_room = false;
            let valid = target_matches
                && if prepared.local_only {
                    self.profile
                        .as_ref()
                        .is_some_and(|p| p.fingerprint() == prepared.node)
                } else if let Some((profile, shared)) = current {
                    let Ok(room) = shared.try_lock() else {
                        return false;
                    };
                    same_room = prepared
                        .room
                        .upgrade()
                        .is_some_and(|old| Arc::ptr_eq(&old, shared))
                        && room.epoch() == prepared.epoch
                        && room.history_instance(profile.store()).ok()
                            == Some(prepared.status.instance);
                    same_room && (committed_terminal
                            || (room.is_member(&prepared.node)
                                && !room.has_left(&prepared.node)
                                && room.ended(self.now_ms().get()).is_none()
                                && stream::authorization_generation(
                                    profile.store(),
                                    prepared.node,
                                    prepared.status.room,
                                    prepared.status.instance,
                                    prepared.epoch,
                                )
                                .ok()
                                    == Some(prepared.generation)))
                } else {
                    false
                };
            if !valid {
                // A later authorization change must prevent dispatch, but it cannot undo a
                // newer action already committed in this same room. Retire an older recovery
                // probe before it can replace that action's status.
                let committed_intent = user_intent
                    && same_room
                    && prepared.local_boundary == LocalBoundary::Durable;
                if let Some(Ok(prepared)) = result.take() {
                    if let Some(dispatch) = prepared.dispatch {
                        dispatch.fence.retire();
                        dispatch.staging.context.cancellation().cancel();
                    }
                }
                drop(result);
                self.history_demand.preparing = None;
                if committed_intent {
                    self.history_demand.cancel_auto_recovery();
                }
                let status = match origin {
                    PreparationOrigin::Explicit => self.history_demand.owner_status.as_mut(),
                    PreparationOrigin::Observation => self.history_demand.observation.as_mut(),
                };
                let mut installed = false;
                if let Some(status) = status.filter(|status| {
                    status.room == target_room && status.instance == target_instance
                }) {
                    status.phase = Phase::Paused;
                    status.detail =
                        "The room or authorization changed; request history again.".into();
                    installed = true;
                }
                if origin == PreparationOrigin::Observation && installed {
                    self.history_demand.observation_unread = true;
                }
                return true;
            }
        }
        let Some(ready) = result.take() else {
            return false;
        };
        drop(result);
        self.history_demand.preparing = None;
        match ready {
            Err(reason) => {
                let status = match origin {
                    PreparationOrigin::Explicit => self.history_demand.owner_status.as_mut(),
                    PreparationOrigin::Observation => self.history_demand.observation.as_mut(),
                };
                let mut installed = false;
                if let Some(status) = status.filter(|status| {
                    status.room == target_room && status.instance == target_instance
                }) {
                    status.phase = Phase::Unavailable;
                    status.detail = reason.chars().take(128).collect();
                    installed = true;
                }
                if origin == PreparationOrigin::Observation && installed {
                    self.history_demand.observation_unread = true;
                }
            }
            Ok(prepared) => {
                // Do not discard automatic local recovery merely because an unvalidated
                // request reached a worker. Only a validated newer action supersedes it.
                let accepted_intent = match action {
                    Action::Cancel { .. } => prepared.local_boundary == LocalBoundary::Durable,
                    Action::Resume { .. } => {
                        prepared.resume_kind.is_some()
                            || prepared.local_boundary == LocalBoundary::Durable
                            || prepared.dispatch.is_some()
                            || prepared.private.is_some()
                    }
                    Action::Newest | Action::Older { .. } | Action::PrivateRecover { .. } => {
                        prepared.local_boundary == LocalBoundary::Durable
                            || prepared.accepted_selection
                            || prepared.dispatch.is_some()
                            || prepared.private.is_some()
                    }
                    Action::Status => false,
                };
                if user_intent && accepted_intent {
                    self.history_demand.cancel_auto_recovery();
                    if matches!(action, Action::Cancel { .. }) {
                        self.history_demand.clear_resume_owed();
                    }
                }
                if let Some(private) = prepared.resume_kind {
                    if let Some(request) = prepared.status.request {
                        self.history_demand.owner_status = Some(prepared.status);
                        self.history_demand
                            .owe_resume(target_room, target_instance, request);
                        if let Some(owed) = self.history_demand.resume_owed.as_mut() {
                            owed.private = Some(private);
                        }
                        self.retry_owed_history_resume();
                    }
                    return true;
                }
                if origin == PreparationOrigin::Observation {
                    self.history_demand.observation = Some(prepared.status);
                    self.history_demand.observation_unread = true;
                    return true;
                }
                if let Some(after) = prepared.selection_after {
                    self.history_demand.selection =
                        Some((prepared.status.room, prepared.status.instance, after));
                }
                if let Some(owner) = prepared.legacy_cancelled {
                    self.history_demand.cancelled_legacy = Some((prepared.status.room, owner));
                }
                self.history_demand.owner_status = Some(prepared.status);
                if let Some(dispatch) = prepared.private {
                    self.history_demand.running = Some(Running {
                        request: dispatch.request,
                        generation: dispatch.generation,
                        fence: dispatch.fence.clone(),
                        cancellation: dispatch.staging.context.cancellation(),
                        page: None,
                    });
                    self.start_private_history(dispatch);
                }
                if let Some(dispatch) = prepared.dispatch {
                    self.history_demand.running = Some(Running {
                        request: dispatch.request,
                        generation: dispatch.generation,
                        fence: dispatch.fence.clone(),
                        cancellation: dispatch.staging.context.cancellation(),
                        page: page_of(&dispatch.query),
                    });
                    // The page is a want of its own on its port (`port_eligible` reads
                    // `ready_binding`), served on its own stream (#996). Raising the port here
                    // outlived the page: the archive round consumed no request, so every page a
                    // reader asked for ran a live inventory round after it that fetched nothing.
                    self.sched_rooms.insert(dispatch.room);
                    self.history_demand.ready = Some(dispatch);
                }
            }
        }
        true
    }
}

#[derive(Clone)]
struct PrivateGuard {
    node: Digest32,
    room: Digest32,
    instance: [u8; 16],
    generation: Digest32,
    context: Arc<Context>,
    fence: Arc<Fence>,
    deadline: tokio::time::Instant,
}
impl PrivateGuard {
    fn check(&self, room: &ChannelState, store: &Store) -> Result<(), String> {
        if self.fence.is_retired()
            || self.context.cancellation().is_cancelled()
            || tokio::time::Instant::now() >= self.deadline
            || room.channel_id() != self.room
            || room.history_instance(store).ok() != Some(self.instance)
            || !room.is_member(&self.node)
            || room.has_left(&self.node)
            || stream::authorization_generation(
                store,
                self.node,
                self.room,
                self.instance,
                room.epoch(),
            )
            .ok()
                != Some(self.generation)
        {
            return Err("Private recovery authority changed or request cancelled.".into());
        }
        Ok(())
    }
}
async fn private_room<T: Send + 'static>(
    room: Arc<Mutex<ChannelState>>,
    store: Arc<Store>,
    job: Job,
    guard: PrivateGuard,
    work: impl FnOnce(&mut ChannelState, &Store) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let charge = job
        .reserve(4 * 1024 * 1024)
        .ok_or("Private recovery disk buffers are busy.")?;
    let mut room = tokio::select! {
        biased;
        () = guard.fence.retired() => return Err("Private recovery cancelled.".into()),
        room = tokio::time::timeout_at(guard.deadline, room.lock_owned()) => room.map_err(|_| "Private recovery room lock deadline elapsed.")?,
    };
    // The context/secret-work lease, charge and slot stay held until the actual disk call ends.
    tokio::task::spawn_blocking(move || {
        let _job = job;
        let _charge = charge;
        guard.check(&room, &store)?;
        let result = work(&mut room, &store)?;
        guard.check(&room, &store)?;
        Ok(result)
    })
    .await
    .map_err(|_| "Private recovery disk worker stopped.".to_owned())?
}

/// Existing current private delivery is tracked by join_tasks. Its blocking work retains the
/// secret-work lease and daemon reservation even when its async caller is aborted at lock.
#[derive(Clone)]
pub(super) struct CurrentPrivateGuard {
    lease: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    pub(super) nonce: Option<[u8; crate::atrest::sek::NONCE_LEN]>,
    deadline: tokio::time::Instant,
}

#[derive(Clone, Copy)]
pub(super) enum CurrentPrivateBoundary {
    /// A page or request intent has not committed local semantic work. It may leave this worker
    /// only if the same authority and observation deadline still hold after preparation.
    Observing,
    /// The callback performs its own captured-authority check inside each durable transaction.
    /// Its committed result is not replaced by a later observation of elapsed time.
    Applying,
}
impl Node {
    pub(super) fn current_private_context(&self) -> Option<(Arc<Store>, CurrentPrivateGuard)> {
        let profile = self.profile.as_ref().filter(|p| p.is_unlocked())?;
        let lease = Arc::new(self.secret_work.clone().try_read_owned().ok()?);
        let store = profile.store_handle();
        let nonce = store
            .get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(
                crate::node::trust::TRUST_META_KEY,
            )
            .ok()?;
        Some((
            store,
            CurrentPrivateGuard {
                lease,
                nonce,
                deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(30),
            },
        ))
    }
}
pub(super) async fn current_private_room<T: Send + 'static>(
    room: Arc<Mutex<ChannelState>>,
    store: Arc<Store>,
    charge: crate::node::history_budget::BufferCharge,
    guard: CurrentPrivateGuard,
    boundary: CurrentPrivateBoundary,
    work: impl FnOnce(&mut ChannelState, &Store) -> crate::error::Result<T> + Send + 'static,
) -> crate::error::Result<(crate::node::history_budget::BufferCharge, T)> {
    use crate::error::Error;
    let mut room = tokio::time::timeout_at(guard.deadline, room.lock_owned())
        .await
        .map_err(|_| Error::StreamRefused("private room lock deadline elapsed"))?;
    tokio::task::spawn_blocking(move || {
        let _lease = guard.lease;
        if tokio::time::Instant::now() >= guard.deadline
            || store.get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(
                crate::node::trust::TRUST_META_KEY,
            )? != guard.nonce
        {
            return Err(Error::StreamRefused(
                "private authority changed or request expired",
            ));
        }
        let result = work(&mut room, &store)?;
        if matches!(boundary, CurrentPrivateBoundary::Observing)
            && (tokio::time::Instant::now() >= guard.deadline
                || store.get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(
                    crate::node::trust::TRUST_META_KEY,
                )? != guard.nonce)
        {
            return Err(Error::StreamRefused(
                "private authority changed or request expired",
            ));
        }
        // Applying callbacks own their durable result. finish_private_pull checks the captured
        // trust nonce inside every record/cursor Batch before commit; a later observation cannot
        // truthfully replace that committed outcome with a refusal.
        Ok((charge, result))
    })
    .await
    .map_err(|_| Error::StreamRefused("private disk worker stopped"))?
}

fn cancel_exact(
    context: &Context,
    request: RequestId,
    job: &Job,
    fence: &Fence,
    deadline: tokio::time::Instant,
) -> Result<(), String> {
    if fence.is_retired() || tokio::time::Instant::now() >= deadline {
        return Err("History cleanup cancelled or expired.".into());
    }
    demand::cancel(context, request, job).map_err(|e| e.to_string())?;
    while !demand::reclaim(context, request, job).map_err(|e| e.to_string())? {
        if fence.is_retired() || tokio::time::Instant::now() >= deadline {
            return Err(
                "History cleanup cancelled or expired; retry cancel to finish cleanup.".into(),
            );
        }
        std::thread::yield_now();
    }
    Ok(())
}

enum CancelCompletion {
    Cancelled,
    CleanupPending(String),
    Complete,
    Superseded,
}

fn cancel_owned_precharged(
    context: &Context,
    request: RequestId,
    charge: &demand::AdmissionCharge,
    fence: &Fence,
) -> Result<CancelCompletion, String> {
    if fence.is_retired() {
        return Err("History cleanup was cancelled before it committed.".into());
    }
    let committed = match demand::cancel_owned_precharged(context, request, charge)
        .map_err(|e| e.to_string())?
    {
        demand::LocalCancelOutcome::NewlyCancelled(committed)
        | demand::LocalCancelOutcome::AlreadyCancelled(committed) => committed,
        demand::LocalCancelOutcome::AlreadyComplete => return Ok(CancelCompletion::Complete),
    };
    loop {
        match demand::reclaim_committed(context, committed.as_ref(), charge) {
            Ok(demand::CommittedReclaim::More) => std::thread::yield_now(),
            Ok(demand::CommittedReclaim::Complete) => {
                return Ok(CancelCompletion::Cancelled);
            }
            Ok(demand::CommittedReclaim::Superseded) => {
                return Ok(CancelCompletion::Superseded);
            }
            Err(error) => {
                return Ok(CancelCompletion::CleanupPending(error.to_string()));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)] // One exact locally authorized cleanup/status operation.
fn prepare_local(
    node: Digest32,
    room: Digest32,
    instance: [u8; 16],
    action: Action,
    context: Arc<Context>,
    admission: demand::LocalAdmission,
    fence: &Fence,
) -> Result<Prepared, String> {
    let mut answer = Prepared {
        node,
        room: Weak::new(),
        epoch: 0,
        generation: [0; 32],
        status: status(
            room,
            instance,
            Phase::Idle,
            "No history request is saved for this room.",
        ),
        dispatch: None,
        private: None,
        legacy_cancelled: None,
        local_only: true,
        local_boundary: LocalBoundary::Observed,
        terminal_checkpoint: false,
        accepted_selection: false,
        selection_after: None,
        resume_kind: None,
    };
    let request = match action {
        Action::Cancel { request } => Some(request),
        Action::Status => None,
        _ => return Err("The saved history request changed.".into()),
    };
    if demand::obsolete_legacy_request(&context, room, instance, request)
        .map_err(|error| error.to_string())?
    {
        answer.status.phase = Phase::Unavailable;
        answer.status.detail = crate::node::channel::UNSUPPORTED_ROOM_FORMAT.into();
        return Ok(answer);
    }
    let (saved, mutation) = admission.inspect(&context).map_err(|e| e.to_string())?;
    let Some(saved) = saved else {
        return Ok(answer);
    };
    let state = saved.state();
    if state.binding.room != room || state.binding.instance != instance {
        return Err("The saved history request belongs to a different room or instance.".into());
    }
    // The live actor retains Cancelled long enough for the command that performed cancellation to
    // observe its terminal result. Once that actor is gone, a fully reclaimed terminal header is
    // only a durable fence and binding record, not an active request to reconstruct after restart.
    // Exposing it again made a cleanly reopened room look permanently cancelled instead of Idle.
    if matches!(action, Action::Status)
        && matches!(state.progress(None), demand::Progress::Cancelled)
        && !state.reclaiming()
    {
        return Ok(answer);
    }
    answer.status = saved_status(state, None, None);
    match action {
        Action::Status => {}
        Action::Cancel { request } if request == state.request => {
            let legacy_cancelled = state.legacy.as_ref().map(|plan| LegacyProvisionalOwner {
                request,
                instance,
                author: plan.author,
            });
            let mutation = mutation
                .as_ref()
                .ok_or("local history cancellation admission is missing")?;
            match cancel_owned_precharged(&context, request, mutation, fence)? {
                CancelCompletion::Cancelled => {
                    answer.legacy_cancelled = legacy_cancelled;
                    answer.local_boundary = LocalBoundary::Durable;
                    answer.status.phase = Phase::Cancelled;
                    answer.status.detail =
                        "History request cancelled; provisional bytes reclaimed.".into();
                }
                CancelCompletion::CleanupPending(error) => {
                    answer.legacy_cancelled = legacy_cancelled;
                    answer.local_boundary = LocalBoundary::Durable;
                    answer.status.phase = Phase::Cancelled;
                    answer.status.detail = format!(
                        "History request cancelled; provisional cleanup remains: {}",
                        error.chars().take(72).collect::<String>()
                    );
                }
                CancelCompletion::Complete => {
                    answer.local_boundary = LocalBoundary::Durable;
                    answer.status.phase = Phase::Complete;
                    answer.status.detail =
                        "History request was already complete; there is nothing to cancel.".into();
                }
                CancelCompletion::Superseded => {
                    answer.local_boundary = LocalBoundary::Superseded;
                }
            }
        }
        Action::Cancel { .. } => {
            answer.status.phase = Phase::Unavailable;
            answer.status.detail =
                "The requested cancellation does not match the saved history request.".into();
        }
        _ => return Err("The saved history request changed.".into()),
    }
    Ok(answer)
}

fn classify_resume(
    node: Digest32,
    room: Digest32,
    instance: [u8; 16],
    action: Action,
    context: Arc<Context>,
    credit: demand::AdmissionCharge,
) -> Result<Prepared, String> {
    let Action::Resume { request } = action else {
        return Err("History Resume classification action changed.".into());
    };
    if demand::obsolete_legacy_request(&context, room, instance, Some(request))
        .map_err(|error| error.to_string())?
    {
        return Err(crate::node::channel::UNSUPPORTED_ROOM_FORMAT.into());
    }
    let saved = demand::inspect_precharged(&context, credit).map_err(|error| error.to_string())?;
    let Some(saved) = saved else {
        return Err("No history request is saved to resume.".into());
    };
    let state = saved.state();
    if state.request != request || state.binding.room != room || state.binding.instance != instance
    {
        return Err("The requested resume does not match the saved history request.".into());
    }
    let mut pending = saved_status(state, None, None);
    pending.phase = Phase::Preparing;
    pending.detail = "Admitting the saved history request's complete preparation.".into();
    Ok(Prepared {
        node,
        room: Weak::new(),
        epoch: 0,
        generation: [0; 32],
        status: pending,
        dispatch: None,
        private: None,
        legacy_cancelled: None,
        local_only: true,
        local_boundary: LocalBoundary::Observed,
        terminal_checkpoint: false,
        accepted_selection: false,
        selection_after: None,
        resume_kind: Some(state.private.is_some()),
    })
}

#[allow(clippy::too_many_arguments)] // One explicit local activation and its fixed captured guards.
fn prepare(
    room: &ChannelState,
    store: &Store,
    node: Digest32,
    instance: [u8; 16],
    action: Action,
    context: Arc<Context>,
    job: &Job,
    mut peers: Vec<Digest32>,
    connected_peers: std::collections::BTreeSet<Digest32>,
    weak: Weak<Mutex<ChannelState>>,
    fence: Arc<Fence>,
    now: u64,
    deadline: tokio::time::Instant,
    selection_after: Option<Digest32>,
    mut resume_admission: Option<demand::ResumeAdmission>,
    local_admitted: Option<demand::AdmittedEntry>,
) -> Result<Prepared, String> {
    let id = room.channel_id();
    if room.history_instance(store).map_err(|e| e.to_string())? != instance
        || !room.is_member(&node)
        || room.has_left(&node)
        || room.ended(now).is_some()
    {
        return Err("The saved room or membership changed.".into());
    }
    let generation = stream::authorization_generation(store, node, id, instance, room.epoch())
        .map_err(|e| e.to_string())?;
    let binding = Binding {
        room: id,
        instance,
        epoch: room.epoch(),
        audience: [0; 32],
        grant: generation,
    };
    let mut answer = Prepared {
        node,
        room: weak,
        epoch: room.epoch(),
        generation,
        status: status(id, instance, Phase::Idle, "No history request is saved."),
        dispatch: None,
        private: None,
        legacy_cancelled: None,
        local_only: false,
        local_boundary: LocalBoundary::Observed,
        terminal_checkpoint: false,
        accepted_selection: false,
        selection_after: None,
        resume_kind: None,
    };
    let mut saved = match resume_admission.as_mut() {
        Some(admission) => admission.inspect(&context),
        None => demand::inspect(&context, job),
    }
    .map_err(|error| error.to_string())?;
    if let Some(admission) = resume_admission.as_ref() {
        if saved
            .as_ref()
            .is_some_and(|saved| saved.state().private.is_some() != admission.is_private())
        {
            return Err("The saved history request kind changed.".into());
        }
    }
    if saved.as_ref().is_some_and(|s| {
        (s.state().binding.room != id || s.state().binding.instance != instance)
            && matches!(
                s.state().progress(None),
                demand::Progress::Complete | demand::Progress::Cancelled
            )
            && !s.state().reclaiming()
    }) {
        saved = None;
    }
    if let Some(previous) = saved.as_ref() {
        let state = previous.state();
        let replaced = state.binding.room == id && state.binding.instance != instance;
        let removed = store
            .get_sek_wrap(&state.binding.room)
            .map_err(|e| e.to_string())?
            .is_none();
        if (replaced || removed)
            && matches!(
                action,
                Action::Newest | Action::Older { .. } | Action::PrivateRecover { .. }
            )
        {
            cancel_exact(&context, state.request, job, &fence, deadline)?;
            saved = None;
        }
    }
    if let Some(expected) = local_admitted {
        if !saved.as_ref().is_some_and(|saved| {
            saved.state().admitted == Some(expected)
                && matches!(action, Action::Resume { request } if saved.state().request == request)
                && saved.state().binding.room == id
                && saved.state().binding.instance == instance
        }) {
            return Err("The local history recovery selection changed.".into());
        }
    }
    if let Some(saved) = saved.as_ref() {
        if saved.state().binding.room != id || saved.state().binding.instance != instance {
            return Err(
                "Another room owns this node's unfinished history request; cancel it there first."
                    .into(),
            );
        }
        answer.status = saved_status(saved.state(), None, None);
    }
    if matches!(action, Action::PrivateRecover { .. })
        || (matches!(action, Action::Resume { .. })
            && saved.as_ref().is_some_and(|s| s.state().private.is_some()))
    {
        return prepare_private(
            room,
            store,
            node,
            instance,
            action,
            context,
            job,
            peers,
            answer,
            saved.as_ref().map(|s| s.state()),
            fence,
            resume_admission,
        );
    }
    if !room.uses_sparse_history(store).map_err(|e| e.to_string())? {
        return Err(crate::node::channel::UNSUPPORTED_ROOM_FORMAT.into());
    }
    // Public pages prefer an already connected peer; private and legacy selection above
    // keep their own donor contracts.
    peers.sort_by_key(|peer| !connected_peers.contains(peer));
    // This immutable room snapshot determines whether activation must be followed by
    // a durable pause. Reserve that follow-up before start/resume can commit an Active;
    // cached/no-selection paths never acquire an unnecessary pause credit.
    enum PeerAdmission {
        Available(Digest32),
        Unavailable(Option<demand::AdmissionCharge>),
    }
    let peer = peers
        .into_iter()
        .find(|peer| room.is_member(peer) && !room.has_left(peer));
    let admit_peer = || {
        peer.map_or_else(
            || {
                if resume_admission.is_some() {
                    Ok(PeerAdmission::Unavailable(None))
                } else {
                    demand::AdmissionCharge::reserve(job)
                        .map(|credit| PeerAdmission::Unavailable(Some(credit)))
                        .map_err(|e| e.to_string())
                }
            },
            |peer| Ok(PeerAdmission::Available(peer)),
        )
    };
    let (bounds, author, query, active, remaining, peer) = if let Action::Resume { request } =
        action
    {
        let Some(saved) = saved.as_ref() else {
            answer.status.phase = Phase::Unavailable;
            answer.status.detail = "No history request is saved to resume.".into();
            return Ok(answer);
        };
        let state = saved.state();
        if state.request != request {
            answer.status.phase = Phase::Unavailable;
            answer.status.detail =
                "The requested resume does not match the saved history request.".into();
            return Ok(answer);
        }
        if let Some(admitted) = state.admitted {
            if state.reclaiming() {
                return Err("The admitted history entry still has cleanup pending.".into());
            }
            let bounds = state.bounds;
            let remaining = state.remaining;
            let head = room
                .history_head_by_id(store, &bounds.head)
                .map_err(|error| error.to_string())?
                .ok_or("The original authenticated head is unavailable.")?;
            let read = room
                .history_read(store)
                .map_err(|error| error.to_string())?;
            let (_, header) = read
                .history_validated_header(&head.binding.author, admitted.seq)
                .map_err(|error| error.to_string())?
                .ok_or("The admitted history entry is unavailable.")?;
            if header.entry_hash() != admitted.entry
                || !read
                    .history_effect_finished(&admitted.entry)
                    .map_err(|error| error.to_string())?
            {
                return Err("The admitted history entry changed or is not settled.".into());
            }
            drop(read);
            let continuation = if remaining == 0 {
                None
            } else {
                let next_seq = admitted
                    .seq
                    .checked_sub(1)
                    .filter(|next| *next >= bounds.lo)
                    .ok_or("The admitted history continuation is inconsistent.")?;
                Some(stream::Continuation {
                    query_kind: 4,
                    head: bounds.head,
                    lo: bounds.lo,
                    hi: bounds.hi,
                    next_seq,
                    entry: None,
                    offset: 0,
                    entries_remaining: remaining,
                })
            };
            let admission = resume_admission
                .as_ref()
                .ok_or("History Resume admission is missing.")?;
            answer.status = saved_status(state, Some(head.binding.author), None);
            let mut active =
                demand::resume_precharged(&context, request, binding, admission.mutation())
                    .map_err(|error| error.to_string())?;
            answer.local_boundary = LocalBoundary::Durable;
            if let Err(error) = demand::checkpoint_precharged(
                &context,
                &mut active,
                if continuation.is_some() {
                    demand::Progress::More
                } else {
                    demand::Progress::Complete
                },
                continuation.as_ref(),
                admission.mutation(),
            ) {
                return Ok(committed_resume_failure(
                    answer,
                    format!("history checkpoint outcome is unknown: {error}"),
                ));
            }
            // The committed checkpoint only changes progress and the cursor; the exact request,
            // bounds and remaining count were checked above and cannot be changed by this commit.
            // Report that durable outcome without a second, fallible memory admission.
            answer.status.phase = if continuation.is_some() {
                Phase::More
            } else {
                Phase::Complete
            };
            answer.terminal_checkpoint = continuation.is_none();
            answer.status.offset = 0;
            answer.status.detail =
                "This operation covers only its selected bounded history interval.".into();
            answer.local_boundary = LocalBoundary::Durable;
            return Ok(answer);
        }
        if state.body.is_none()
            && (state.remaining == 0 || state.cursor.is_some_and(|c| c.next_seq < state.bounds.lo))
        {
            return Err("This history interval has no remaining entries.".into());
        }
        let head = room
            .history_head_by_id(store, &state.bounds.head)
            .map_err(|e| e.to_string())?
            .ok_or("The original authenticated head is unavailable.")?;
        let query = if let Some(body) = &state.body {
            Query::Entry {
                head: state.bounds.head,
                seq: body.seq,
                offset: body.offset,
            }
        } else if let Some(cursor) = state.cursor {
            Query::Page {
                head: state.bounds.head,
                lo: state.bounds.lo,
                hi: cursor.next_seq,
                entries: state.remaining,
                wire_bytes: 1024 * 1024,
            }
        } else {
            Query::Page {
                head: state.bounds.head,
                lo: state.bounds.lo,
                hi: state.bounds.hi,
                entries: state.remaining,
                wire_bytes: 1024 * 1024,
            }
        };
        let peer = admit_peer()?;
        let admission = resume_admission
            .as_ref()
            .ok_or("History Resume admission is missing.")?;
        let active = demand::resume_precharged(&context, request, binding, admission.mutation())
            .map_err(|error| error.to_string())?;
        (
            state.bounds,
            head.binding.author,
            query,
            active,
            state.remaining,
            peer,
        )
    } else {
        // Validate the user's new selection and reserve its follow-up before retiring any
        // saved request. A stale cursor must not cancel the recovery it failed to replace.
        let selected = select(room, store, action, &fence, deadline, selection_after)
            .map_err(|e| e.to_string())?;
        if matches!(action, Action::Newest) {
            answer.selection_after = Some(selected.after);
        }
        let fresh = if let Some((bounds, author)) = selected.found {
            let request = crate::identity::rng::random_array::<16>().map_err(|e| e.to_string())?;
            Some((bounds, author, request, admit_peer()?))
        } else {
            None
        };
        let paused = saved
            .as_ref()
            .map(|previous| previous.state())
            .filter(|state| {
                !matches!(
                    state.progress(None),
                    demand::Progress::Complete | demand::Progress::Cancelled
                ) || state.reclaiming()
            })
            .map(|state| state.request);
        if let Some(request) = paused {
            let charge =
                demand::AdmissionCharge::reserve(job).map_err(|error| error.to_string())?;
            match cancel_owned_precharged(&context, request, &charge, &fence)? {
                CancelCompletion::Cancelled => {
                    answer.local_boundary = LocalBoundary::Durable;
                }
                CancelCompletion::Complete => {
                    answer.local_boundary = LocalBoundary::Durable;
                    loop {
                        match demand::reclaim_precharged(&context, request, &charge) {
                            Ok(true) => break,
                            Ok(false) => std::thread::yield_now(),
                            Err(error) => {
                                answer.status.phase = Phase::Unavailable;
                                answer.status.detail = format!("The completed history request still has cleanup pending: {error}");
                                return Ok(answer);
                            }
                        }
                    }
                }
                CancelCompletion::CleanupPending(error) => {
                    answer.local_boundary = LocalBoundary::Durable;
                    answer.status.phase = Phase::Unavailable;
                    answer.status.detail = format!(
                        "The previous history request was cancelled; cleanup remains: {error}"
                    );
                    return Ok(answer);
                }
                CancelCompletion::Superseded => {
                    answer.local_boundary = LocalBoundary::Superseded;
                    return Ok(answer);
                }
            }
        }
        let Some((bounds, author, request, peer)) = fresh else {
            answer.accepted_selection = true;
            answer.status = if selected.more {
                status(id, instance, Phase::More, "This bounded scan is cached. Request newest again to check the next authors; unchecked history remains.")
            } else {
                status(id, instance, Phase::Cached, "The selected bounded content is already cached; older history may still exist.")
            };
            return Ok(answer);
        };
        let active = match demand::start(&context, request, binding, bounds, job) {
            Ok(active) => active,
            Err(error) if answer.local_boundary == LocalBoundary::Durable => {
                return Ok(committed_resume_failure(
                    answer,
                    format!("new history request outcome is unknown: {error}"),
                ));
            }
            Err(error) => return Err(error.to_string()),
        };
        let query = Query::Page {
            head: bounds.head,
            lo: bounds.lo,
            hi: bounds.hi,
            entries: bounds.entries,
            wire_bytes: 1024 * 1024,
        };
        (bounds, author, query, active, bounds.entries, peer)
    };
    answer.local_boundary = LocalBoundary::Durable;
    let request = active.request();
    answer.status.request = Some(request);
    answer.status.head = Some(bounds.head);
    answer.status.author = Some(author);
    answer.status.remaining = remaining;
    let peer = match peer {
        PeerAdmission::Available(peer) => peer,
        PeerAdmission::Unavailable(credit) => {
            let mut active = active;
            let Some(credit) = credit.as_ref().or_else(|| {
                resume_admission
                    .as_ref()
                    .map(|admission| admission.mutation())
            }) else {
                return Ok(committed_resume_failure(
                    answer,
                    "History pause admission is missing.",
                ));
            };
            if let Err(error) = demand::pause_precharged(&context, &mut active, credit) {
                return Ok(committed_resume_failure(answer, error));
            }
            answer.status = status(
                id,
                instance,
                Phase::Unavailable,
                "No trusted room peer is available; this request is saved and paused.",
            );
            answer.status.request = Some(request);
            answer.status.head = Some(bounds.head);
            answer.status.author = Some(author);
            answer.status.remaining = remaining;
            return Ok(answer);
        }
    };
    answer.status = status(
        id,
        instance,
        Phase::Pending,
        "One bounded history quantum is queued. Further history requires an explicit resume.",
    );
    answer.status.request = Some(request);
    answer.status.head = Some(bounds.head);
    answer.status.author = Some(author);
    answer.status.remaining = remaining;
    answer.status.headers = bounds.entries;
    answer.dispatch = Some(Dispatch {
        room: id,
        instance,
        peer,
        request,
        generation,
        query,
        staging: Staging {
            context,
            active: Arc::new(StdMutex::new(active)),
        },
        fence,
        eligible: false,
        dial_eligible: false,
    });
    Ok(answer)
}

#[allow(clippy::too_many_arguments)]
fn prepare_private(
    room: &ChannelState,
    store: &Store,
    node: Digest32,
    instance: [u8; 16],
    action: Action,
    context: Arc<Context>,
    job: &Job,
    peers: Vec<Digest32>,
    mut answer: Prepared,
    saved: Option<&demand::State>,
    fence: Arc<Fence>,
    mut resume_admission: Option<demand::ResumeAdmission>,
) -> Result<Prepared, String> {
    let peer = match action {
        Action::PrivateRecover { peer } => peer,
        Action::Resume { request } => {
            let Some(state) = saved else {
                answer.status.phase = Phase::Unavailable;
                answer.status.detail = "No private history request is saved to resume.".into();
                return Ok(answer);
            };
            if state.request != request {
                answer.status.phase = Phase::Unavailable;
                answer.status.detail =
                    "The requested resume does not match the saved private history request.".into();
                return Ok(answer);
            }
            state
                .private
                .as_ref()
                .ok_or("The saved request is public history.")?
                .donor
        }
        _ => return Err("Private history needs an explicit selection or resume.".into()),
    };
    let (boundary, private_grant) = room
        .private_history_scope(store, &peer)
        .map_err(|e| e.to_string())?;
    let binding = Binding {
        room: room.channel_id(),
        instance,
        epoch: room.epoch(),
        audience: peer,
        grant: answer.generation,
    };
    let donor_unavailable = !peers.contains(&peer) || peer == node;
    let admit_followup = || {
        // Preserve the fresh durable status read after activation, without allowing its
        // byte reservation (or an unavailable donor's pause) to hide that committed result.
        let inspect_credit = demand::AdmissionCharge::reserve(job).map_err(|e| e.to_string())?;
        let pause_credit = donor_unavailable
            .then(|| demand::AdmissionCharge::reserve(job))
            .transpose()
            .map_err(|e| e.to_string())?;
        Ok::<_, String>((inspect_credit, pause_credit))
    };
    let (bounds, plan, mut active, inspect_credit, pause_credit) = if let Action::Resume {
        request,
    } = action
    {
        let state = saved.ok_or("No saved private history request.")?;
        let plan = state
            .private
            .clone()
            .ok_or("The saved request is public history.")?;
        if state.binding != binding
            || plan.grant != private_grant
            || state.bounds.head != boundary.incarnation
        {
            return Err(
                "Private history authorization or donor incarnation changed; cancel this request."
                    .into(),
            );
        }
        let admission = resume_admission
            .as_mut()
            .ok_or("Private Resume admission is missing.")?;
        let inspect_credit = admission
            .take_followup()
            .map_err(|error| error.to_string())?;
        let pause_credit = None;
        let active = demand::resume_precharged(&context, request, binding, admission.mutation())
            .map_err(|error| error.to_string())?;
        (state.bounds, plan, active, inspect_credit, pause_credit)
    } else {
        if let Some(state) = saved.filter(|s| {
            !matches!(
                s.progress(None),
                demand::Progress::Complete | demand::Progress::Cancelled
            ) || s.reclaiming()
        }) {
            answer.status = saved_status(state, None, None);
            answer.status.detail = "A saved request exists. Resume or cancel it explicitly.".into();
            return Ok(answer);
        }
        let mut after = room.private_recovery_after(&peer, boundary.incarnation);
        if let Some(prior) = saved.filter(|s| {
            s.progress(None) == demand::Progress::Complete
                && s.bounds.head == boundary.incarnation
                && s.private
                    .as_ref()
                    .is_some_and(|p| p.donor == peer && p.grant == private_grant)
        }) {
            after = after.max(prior.bounds.hi);
        }
        if after >= boundary.after {
            answer.accepted_selection = true;
            answer.status = status(room.channel_id(), instance, Phase::Cached, "The currently advertised private interval has been examined; this is not proof of donor completeness.");
            return Ok(answer);
        }
        let lo = after
            .checked_add(1)
            .ok_or("Private arrival position exhausted.")?;
        let hi = after.saturating_add(32).min(boundary.after);
        let bounds = Bounds {
            head: boundary.incarnation,
            lo,
            hi,
            entries: (hi - lo + 1) as usize,
        };
        let plan = demand::PrivatePlan {
            donor: peer,
            grant: private_grant,
            inventory_done: false,
            positions: Vec::new(),
        };
        let request = crate::identity::rng::random_array::<16>().map_err(|e| e.to_string())?;
        let (inspect_credit, pause_credit) = admit_followup()?;
        let active = demand::start_private(&context, request, binding, bounds, plan.clone(), job)
            .map_err(|e| e.to_string())?;
        (bounds, plan, active, inspect_credit, pause_credit)
    };
    answer.local_boundary = LocalBoundary::Durable;
    answer.status.request = Some(active.request());
    answer.status.head = Some(bounds.head);
    answer.status.remaining = if matches!(action, Action::Resume { .. }) {
        saved.map_or(bounds.entries, |state| state.remaining)
    } else {
        bounds.entries
    };
    let snapshot = match demand::inspect_precharged(&context, inspect_credit) {
        Ok(Some(snapshot)) => snapshot,
        result => {
            let detail = match result {
                Err(error) => error.to_string(),
                Ok(_) => "Private history state disappeared.".into(),
            };
            return Ok(committed_resume_failure(answer, detail));
        }
    };
    answer.status = saved_status(snapshot.state(), None, Some(&active));
    if donor_unavailable {
        let Some(credit) = pause_credit.as_ref().or_else(|| {
            resume_admission
                .as_ref()
                .map(|admission| admission.mutation())
        }) else {
            return Ok(committed_resume_failure(
                answer,
                "Private pause admission is missing.",
            ));
        };
        if let Err(error) = demand::pause_precharged(&context, &mut active, credit) {
            return Ok(committed_resume_failure(answer, error));
        }
        answer.status.phase = Phase::Paused;
        answer.status.detail =
            "The selected private donor is unavailable; resume explicitly after it reconnects."
                .into();
        return Ok(answer);
    }
    answer.status.phase = Phase::Pending;
    answer.status.detail =
        "One bounded private history quantum is queued; another requires explicit resume.".into();
    answer.private = Some(PrivateDispatch {
        room: room.channel_id(),
        instance,
        peer,
        request: active.request(),
        generation: answer.generation,
        bounds,
        plan,
        staging: Staging {
            context,
            active: Arc::new(StdMutex::new(active)),
        },
        fence,
    });
    Ok(answer)
}

struct Selection {
    found: Option<(Bounds, Digest32)>,
    after: Option<Digest32>,
    more: bool,
}

/// Only signed headers and retained-body facts are read; a held body is never decoded to select it.
fn select(
    room: &ChannelState,
    store: &Store,
    action: Action,
    fence: &Fence,
    deadline: tokio::time::Instant,
    after: Option<Digest32>,
) -> crate::error::Result<Selection> {
    use crate::log::history::SignedEntryKind;
    let read = room.history_read(store)?;
    let mut page_after = None;
    let candidates = match action {
        Action::Older { before } => {
            let bytes = read.history_object(ObjectKind::Header, &before)?.ok_or(
                crate::error::Error::Profile("The older-history cursor is not retained."),
            )?;
            let entry = crate::log::entry::Entry::from_wire(&bytes)?;
            if entry.entry_hash() != before
                || entry.skeleton.channel_id != room.channel_id()
                || entry.skeleton.v2.is_none()
            {
                return Err(crate::error::Error::Profile(
                    "The older-history cursor binding is invalid.",
                ));
            }
            let Some(head) = room.history_head(store, &entry.skeleton.author_id)? else {
                return Err(crate::error::Error::Profile(
                    "The cursor's authenticated head is unavailable.",
                ));
            };
            vec![(
                head.id(),
                entry.skeleton.author_id,
                entry.skeleton.seq.saturating_sub(1),
            )]
        }
        Action::Newest => {
            let heads = room.history_head_hints(store, after)?;
            page_after = heads.next;
            if heads.heads.is_empty() && (after.is_some() || heads.next.is_some()) {
                return Ok(Selection {
                    found: None,
                    after: heads.next,
                    more: heads.next.is_some(),
                });
            }
            if heads.heads.is_empty() {
                return Err(crate::error::Error::Profile("Authenticated history heads are not available yet; cached messages remain available."));
            }
            heads
                .heads
                .into_iter()
                .map(|h| (h.head, h.author, h.leaves))
                .collect()
        }
        _ => {
            return Err(crate::error::Error::Profile(
                "History selection requires newest or older.",
            ))
        }
    };
    let mut examined = 0;
    let count = candidates.len();
    let mut next = page_after;
    for (position, (head, author, hi)) in candidates.into_iter().enumerate() {
        // Never skip an author's unchecked suffix when the aggregate slice is nearly spent.
        // The next explicit request starts that author with its full bounded window.
        if examined != 0 && hi.min(64) as usize > 64 - examined {
            return Ok(Selection {
                found: None,
                after: next,
                more: true,
            });
        }
        next = if position + 1 < count || page_after.is_some() {
            Some(author)
        } else {
            None
        };
        if hi == 0 {
            continue;
        }
        let mut missing = None;
        for seq in (hi.saturating_sub(63).max(1)..=hi).rev() {
            if examined == 64 {
                break;
            }
            if fence.is_retired() || tokio::time::Instant::now() >= deadline {
                return Err(crate::error::Error::Profile(
                    "History selection cancelled or expired.",
                ));
            }
            examined += 1;
            let header = read.history_position_header(&author, seq)?;
            let held = match header {
                Some(header)
                    if header
                        .skeleton
                        .v2
                        .as_ref()
                        .is_some_and(|v| v.kind != SignedEntryKind::Content) =>
                {
                    true
                }
                // Held means rendered: a body a cut-short page stored but never applied is
                // fetched again, not counted.
                Some(header) => {
                    let hash = header.entry_hash();
                    read.history_effect_finished(&hash)? && read.retention(&hash)?.is_some()
                }
                None => false,
            };
            if held {
                if missing.is_some() {
                    break;
                }
            } else {
                let (lo, _) = missing.get_or_insert((seq, seq));
                *lo = seq;
            }
        }
        if let Some((lo, hi)) = missing {
            return Ok(Selection {
                found: Some((
                    Bounds {
                        head,
                        lo,
                        hi,
                        entries: (hi - lo + 1) as usize,
                    },
                    author,
                )),
                after: next,
                more: next.is_some(),
            });
        }
        if examined == 64 {
            break;
        }
    }
    Ok(Selection {
        found: None,
        after: next,
        more: next.is_some(),
    })
}

impl Controller {
    /// The history request as it stands, for `vox status --json` (`lanes.history`).
    pub(super) fn lanes_json(&self) -> String {
        use crate::node::link::b32_encode;
        fn js(s: &str) -> String {
            let mut o = String::from("\"");
            for c in s.chars() {
                match c {
                    '"' => o.push_str("\\\""),
                    '\\' => o.push_str("\\\\"),
                    '\n' => o.push_str("\\n"),
                    c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
                    c => o.push(c),
                }
            }
            o.push('"');
            o
        }
        let preparation_status = self.preparing.as_ref().and_then(|preparation| {
            let status = match preparation.origin {
                PreparationOrigin::Explicit => self.owner_status.as_ref(),
                PreparationOrigin::Observation => self.observation.as_ref(),
            }?;
            (status.room == preparation.room && status.instance == preparation.instance)
                .then_some(status)
        });
        let operation_active = self.private_work.is_some()
            || self.running.is_some()
            || self.ready.is_some()
            || self.resume_owed.is_some();
        let shown_status = if self.preparing.is_some() {
            preparation_status
        } else if operation_active {
            self.owner_status.as_ref()
        } else {
            self.owner_status.as_ref().or(self.observation.as_ref())
        };
        let (phase, detail) = shown_status.map_or_else(
            || ("null".to_owned(), "null".to_owned()),
            |s| (js(&format!("{:?}", s.phase)), js(&s.detail)),
        );
        let active_stage = if self.preparing.is_some() {
            Some("preparing")
        } else if self.private_work.is_some() {
            Some("private_work")
        } else if self.ready.is_some() {
            // An unstarted public dispatch already has logical running ownership,
            // but it has not been consumed by a physical archive Flow yet.
            Some("ready")
        } else if self.running.is_some() {
            Some("running")
        } else {
            None
        };
        let render_owner = |status: &Status, stage: &str| {
            let peer = if stage == "preparing" {
                status.private_peer
            } else {
                self.ready
                    .as_ref()
                    .map(|dispatch| dispatch.peer)
                    .or(status.private_peer)
            }
            .map_or_else(
                || "null".to_owned(),
                |peer| format!("\"{}\"", b32_encode(&peer)),
            );
            let request = status.request.map_or_else(
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
            let instance = status
                .instance
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!(
                "{{\"stage\":\"{stage}\",\"room\":\"{}\",\"peer\":{peer},\"request\":{request},\"instance\":\"{instance}\"}}",
                b32_encode(&status.room)
            )
        };
        let owner = if self.preparing.is_some() {
            preparation_status.map_or_else(
                || "null".to_owned(),
                |status| render_owner(status, "preparing"),
            )
        } else if let Some(owed) = self.resume_owed.as_ref() {
            let peer = self
                .owner_status
                .as_ref()
                .filter(|status| status.request == Some(owed.request))
                .and_then(|status| status.private_peer)
                .map_or_else(
                    || "null".to_owned(),
                    |peer| format!("\"{}\"", b32_encode(&peer)),
                );
            let request = owed
                .request
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let instance = owed
                .instance
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let ticket = owed
                .ticket
                .as_ref()
                .map_or_else(|| "null".to_owned(), |ticket| ticket.sequence().to_string());
            format!(
                "{{\"stage\":\"resume_owed\",\"room\":\"{}\",\"peer\":{peer},\"request\":\"{request}\",\"instance\":\"{instance}\",\"ticket\":{ticket},\"wake\":{},\"waiting_bytes\":{}}}",
                b32_encode(&owed.room),
                owed.wake_task.is_some(),
                owed.waiting_bytes
            )
        } else {
            self.owner_status.as_ref().zip(active_stage).map_or_else(
                || "null".to_owned(),
                |(status, stage)| render_owner(status, stage),
            )
        };
        format!(
            "{{\"phase\":{phase},\"detail\":{detail},\"owner\":{owner},\"preparing\":{},\"ready\":{},\"running\":{},\"private_work\":{}}}",
            self.preparing.is_some(),
            self.ready.is_some(),
            self.running.is_some(),
            self.private_work.is_some()
        )
    }
}
