//! Explicit archive selection and activation. Cache reads never enter this module.

use super::{NetEvent, Node};
use crate::hash::Digest32;
use crate::node::api::{
    HistoryDemandAction as Action, HistoryDemandPhase as Phase, HistoryDemandStatus as Status,
};
use crate::node::channel::legacy_provisional::LegacyProvisionalOwner;
use crate::node::channel::{ChannelState, ServedRoom};
use crate::node::history_budget::{Job, Lane, Ticket};
use crate::node::history_demand::{self as demand, Binding, Bounds, Context};
use crate::node::history_stream::{self as stream, RequestId};
use crate::node::store::Store;
use crate::transport::stream_transport::Fence;
use std::sync::{Arc, Mutex as StdMutex, Weak};

const PREPARATION_SCRATCH: usize = 5 * 1024 * 1024;

/// A person's saved public older-history request (ruling correction 4): its original bounds,
/// `lo` to `hi` of `author`, owed by every connection's loop from the step that saved, restored or
/// resumed it, while `fence` is live. Its status counts what the room admitted of those bounds.
struct Public {
    status: Status,
    author: Digest32,
    lo: u64,
    hi: u64,
    /// The room epoch it was owed under: another epoch pauses it.
    epoch: u64,
    fence: Arc<Fence>,
    /// When it was accepted or restored here: Status answers a room's newest request.
    order: u64,
    /// Its record's completion is being written.
    settling: bool,
    /// A private request: its original donor, Drive grant, bounds and binding.
    private: Option<PrivateHeld>,
}

/// What the actor keeps of a person's saved private request (ruling (b), build order 6): owed
/// to its original donor's connection only, under its original binding (room, instance,
/// epoch, donor audience, authorization), Drive grant and bounds (the donor incarnation is
/// `bounds.head`). Its pages are asked by that connection's loop and admitted natively.
#[derive(Clone, Copy)]
struct PrivateHeld {
    donor: Digest32,
    grant: Digest32,
    bounds: Bounds,
    binding: Binding,
}

/// What a task that saves, restores, resumes or settles public requests found, for the actor.
enum Found {
    /// Saved, with its author, original bounds and room epoch; owed under the fence, or paused
    /// (no fence) until an explicit Resume.
    Saved {
        status: Status,
        author: Digest32,
        lo: u64,
        hi: u64,
        epoch: u64,
        fence: Option<Arc<Fence>>,
        private: Option<Box<PrivateHeld>>,
    },
    /// Its record ended: complete, or cancelled.
    Ended(Status),
    /// A newest-history scan's cursor in the room.
    Selection(Digest32, [u8; 16], Option<Digest32>),
}

type Reply = tokio::sync::oneshot::Sender<Result<Status, String>>;

struct Prepared {
    node: Digest32,
    room: Weak<crate::node::channel::RoomLock>,
    epoch: u64,
    generation: Digest32,
    status: Status,
    legacy_cancelled: Option<LegacyProvisionalOwner>,
    local_only: bool,
    local_boundary: LocalBoundary,
    /// A locally recovered exact request durably reached Complete without a dispatch.
    terminal_checkpoint: bool,
    /// A validated explicit private selection can complete locally without a durable request.
    accepted_selection: bool,
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

type AutoProbeResult =
    Result<Option<([u8; 16], RequestId, demand::AdmittedEntry)>, (Option<[u8; 16]>, String)>;

struct AutoProbe {
    room: Digest32,
    shared: Weak<crate::node::channel::RoomLock>,
    intent: u64,
    fence: Arc<Fence>,
    result: Arc<StdMutex<Option<AutoProbeResult>>>,
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
    auto_intent: u64,
    auto_pending: std::collections::BTreeMap<Digest32, u64>,
    auto_ticket: Option<Ticket>,
    auto_wait: Option<AutoWait>,
    auto_probe: Option<AutoProbe>,
    /// A person's saved public older-history requests, by request: never in the slots above.
    public: std::collections::BTreeMap<RequestId, Public>,
    /// What their tasks found, taken by the actor (`take_public_found`).
    public_found: Arc<StdMutex<Vec<Found>>>,
    /// Their tasks: awaited before lock or shutdown reports completion.
    public_tasks: Vec<tokio::task::JoinHandle<()>>,
    /// Retired by lock or shutdown: every public task stops at its next step.
    lifecycle: Option<Arc<Fence>>,
    /// The last order handed out (`Public::order`).
    public_order: u64,
}
impl Controller {
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

    fn resume_owed_matches(&self, room: Digest32, instance: [u8; 16], request: RequestId) -> bool {
        self.resume_owed.as_ref().is_some_and(|owed| {
            owed.room == room && owed.instance == instance && owed.request == request
        })
    }

    pub(super) fn take_legacy_cleanup(&mut self) -> Option<(Digest32, LegacyProvisionalOwner)> {
        self.cancelled_legacy.take()
    }
    pub(super) fn retire_room(&mut self, room: Digest32) {
        for public in self.public.values_mut().filter(|p| p.status.room == room) {
            if !public.fence.is_retired() {
                public.fence.retire();
                public.status.phase = Phase::Paused;
                public.status.detail =
                    "This room is no longer active; its saved history request is owed again when it opens."
                        .into();
            }
        }
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
        if let Some(lifecycle) = &self.lifecycle {
            lifecycle.retire();
        }
        for public in self.public.values() {
            public.fence.retire();
        }
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
        if let Some(lifecycle) = self.lifecycle.take() {
            lifecycle.retire();
        }
        for public in std::mem::take(&mut self.public).into_values() {
            public.fence.retire();
        }
        for task in std::mem::take(&mut self.public_tasks) {
            let _ = task.await;
        }
        let found = std::mem::take(
            &mut *self
                .public_found
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for found in found {
            if let Found::Saved {
                fence: Some(fence), ..
            } = found
            {
                fence.retire();
            }
        }
        if let Some(preparing) = self.preparing.take() {
            preparing.fence.retire();
            preparing.cancellation.cancel();
            let _ = preparing.task.await;
            if let Ok(mut result) = preparing.result.lock() {
                *result = None;
            }
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
            crate::node::api::MAX_HISTORY_STATUS_WIRE_BYTES
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
    /// Inspect the single saved archive slot once for each newly opened room, and owe the room's
    /// saved public requests again (ruling correction 4).
    pub(super) fn request_admitted_recovery(&mut self, room: Digest32) {
        self.history_demand
            .auto_pending
            .insert(room, self.history_demand.auto_intent);
        self.restore_public_history(room);
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
        shared: Arc<crate::node::channel::RoomLock>,
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
        let Some(ticket) = self.history_demand.auto_ticket.as_mut() else {
            return;
        };
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
        } else {
            None
        };
        let profile = self.profile.as_ref().ok_or("node is locked")?;
        let node = profile.fingerprint();
        let local_only = matches!(action, Action::Status | Action::Cancel { .. });
        let shared = self.channels.get(&room).cloned();
        if !local_only && shared.is_none() {
            return Err("room is not open".into());
        }
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
                        (
                            Box::pin(async move { (*pressure).released().await }),
                            "Waiting for local history preparation buffer capacity.",
                        ),
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
                        (
                            Box::pin(async move {
                                drop(secret.read_owned().await);
                            }),
                            "Waiting for the node's local history access.",
                        ),
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
        if cancel_request.is_some() && !preserve_local_owed {
            self.history_demand.clear_resume_owed();
        }
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
                        (Some(guard), None) => prepare(&guard, &store, node, instance, action, context, &job, weak, read_fence.clone(), now, deadline, resume_admission, local_admitted),
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
        wait_and_detail: (
            std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
            &str,
        ),
    ) -> Status {
        let (wait, detail) = wait_and_detail;
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
        if owed.waiting_bytes || self.history_demand.preparing.is_some() {
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

    /// Metadata-only event: what the saved requests' tasks found, then the one preparation of
    /// the archive slot (an entry an earlier build admitted, legacy cleanup, Status and Cancel).
    pub(super) fn accept_history_demand(&mut self) -> bool {
        self.take_public_found();
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
                    same_room
                        && (committed_terminal
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
                let committed_intent =
                    user_intent && same_room && prepared.local_boundary == LocalBoundary::Durable;
                let _ = result.take();
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
                    }
                    Action::Newest | Action::Older { .. } | Action::PrivateRecover { .. } => {
                        prepared.local_boundary == LocalBoundary::Durable
                            || prepared.accepted_selection
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
                if let Some(owner) = prepared.legacy_cancelled {
                    self.history_demand.cancelled_legacy = Some((prepared.status.room, owner));
                }
                self.history_demand.owner_status = Some(prepared.status);
            }
        }
        true
    }

    /// What the room has admitted of each public request it owes, read from the room's record
    /// (after an admission published into the room, and when a request is owed): its status
    /// counts what remains of its original bounds, and once nothing does its record is completed
    /// off the actor and the loops owe it no more. A request owed under another room epoch is
    /// paused until an explicit Resume.
    pub(super) fn settle_archive_progress(&mut self, room: Digest32) {
        let Some(record) = self
            .serving
            .room(&room)
            .and_then(|open| open.snapshot.upgrade())
            .and_then(|cell| cell.current())
        else {
            return;
        };
        let mut settled = Vec::new();
        for (request, public) in self.history_demand.public.iter_mut().filter(|(_, p)| {
            p.status.room == room && p.private.is_none() && !p.settling && !p.fence.is_retired()
        }) {
            if record.epoch() != public.epoch {
                public.status.phase = Phase::Paused;
                public.status.detail =
                    "The room's epoch changed; resume this request to fetch it again.".into();
                settled.push((*request, demand::Progress::Paused, public.status.clone()));
                continue;
            }
            // What remains is what the room does not hold yet: a position published with its
            // body (the store's runs, whatever the walk's floor), or whose admission completed.
            let row = record
                .history()
                .and_then(|history| history.author(&public.author));
            let remaining = (public.lo..=public.hi)
                .filter(|seq| !row.is_some_and(|row| row.held(*seq) || row.walked(*seq)))
                .count();
            if remaining != public.status.remaining {
                public.status.remaining = remaining;
                public.status.detail = fetching(public.lo, public.hi, &public.author, remaining);
            }
            if remaining == 0 {
                public.status.phase = Phase::Complete;
                public.status.detail =
                    "This operation covers only its selected bounded history interval.".into();
                settled.push((*request, demand::Progress::Complete, public.status.clone()));
            }
        }
        for (request, progress, status) in settled {
            self.settle_public(request, progress, status, None);
        }
    }

    /// A person's public older-history request (`--history newest`/`older`), or the person's
    /// Status, Resume or Cancel of a public request this node holds (ruling correction 4).
    /// `reply` is answered once the request is saved and owed, or with what stopped it. Every
    /// other action returns `reply` for the older controller (private recovery, an entry an
    /// earlier build still recovers locally).
    pub(super) fn begin_public_history(
        &mut self,
        room: Digest32,
        instance: [u8; 16],
        action: Action,
        reply: Reply,
    ) -> Option<Reply> {
        self.take_public_found();
        let held = |request: &RequestId| {
            self.history_demand
                .public
                .get(request)
                .is_some_and(|p| p.status.room == room && p.status.instance == instance)
        };
        match action {
            Action::Newest | Action::Older { .. } => {
                self.accept_public(room, instance, action, reply);
                None
            }
            Action::PrivateRecover { peer } => {
                self.accept_private(room, instance, peer, reply);
                None
            }
            Action::Status => {
                let newest = self
                    .history_demand
                    .public
                    .values()
                    .filter(|p| p.status.room == room && p.status.instance == instance)
                    .max_by_key(|p| p.order)
                    .map(|p| p.status.clone());
                match newest {
                    Some(status) => {
                        let _ = reply.send(Ok(status));
                        None
                    }
                    None => Some(reply),
                }
            }
            Action::Resume { request } if held(&request) => {
                match self
                    .history_demand
                    .public
                    .get(&request)
                    .and_then(|p| p.private)
                {
                    Some(private) => self.resume_private(room, instance, request, private, reply),
                    None => self.resume_public(room, instance, request, reply),
                }
                None
            }
            Action::Cancel { request } if held(&request) => {
                let Some(public) = self.history_demand.public.get_mut(&request) else {
                    return Some(reply);
                };
                public.fence.retire();
                public.status.phase = Phase::Cancelled;
                public.status.detail = "The saved history request is cancelled.".into();
                let status = public.status.clone();
                self.settle_public(request, demand::Progress::Cancelled, status, Some(reply));
                None
            }
            _ => Some(reply),
        }
    }

    /// What a public request's task needs: this node, the room, its unlocked archive context, the
    /// store and the lifecycle fence that lock or shutdown retires.
    fn public_inputs(&mut self, room: Digest32) -> Result<PublicInputs, String> {
        let profile = self.profile.as_ref().ok_or("node is locked")?;
        let shared = self
            .channels
            .get(&room)
            .cloned()
            .ok_or("room is not open")?;
        let secret = self
            .secret_work
            .clone()
            .try_read_owned()
            .map_err(|_| "Node secret work is settling; history was not started.".to_owned())?;
        let context = Context::unlocked(profile, Arc::new(secret)).map_err(|e| e.to_string())?;
        let lifecycle = match &self.history_demand.lifecycle {
            Some(fence) if !fence.is_retired() => Arc::clone(fence),
            _ => {
                let fence = Fence::new();
                self.history_demand.lifecycle = Some(Arc::clone(&fence));
                fence
            }
        };
        Ok(PublicInputs {
            node: profile.fingerprint(),
            shared,
            context: Arc::new(context),
            store: profile.store_handle(),
            lifecycle,
            frontier: Arc::clone(&self.history_frontier),
            found: Arc::clone(&self.history_demand.public_found),
        })
    }

    /// Run `work` under the room's lock off the actor (a public request's selection, restore or
    /// resume), hand what it found to the actor and answer `reply` with its status.
    fn public_task(
        &mut self,
        inputs: PublicInputs,
        reply: Option<Reply>,
        work: impl FnOnce(
                crate::node::channel::OwnedRoomGuard,
                &PublicInputs,
            ) -> Result<(Status, Vec<Found>), String>
            + Send
            + 'static,
    ) {
        let tx = self.net_tx.clone();
        let task = tokio::spawn(async move {
            let answer = async {
                let room = tokio::select! {
                    biased;
                    () = inputs.lifecycle.retired() => return Err("History request cancelled.".to_owned()),
                    room = Arc::clone(&inputs.shared).lock_owned() => room,
                };
                tokio::task::spawn_blocking(move || {
                    let (status, found) = work(room, &inputs)?;
                    inputs
                        .found
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .extend(found);
                    Ok(status)
                })
                .await
                .map_err(|_| "History request worker stopped.".to_owned())?
            }
            .await;
            if let Some(reply) = reply {
                let _ = reply.send(answer);
            }
            let _ = tx.try_send(NetEvent::HistoryDemandPrepared { token: 0 });
        });
        self.history_demand
            .public_tasks
            .retain(|task| !task.is_finished());
        self.history_demand.public_tasks.push(task);
    }

    /// Select what a person asked for, save it and owe it in that same step: nothing (no other
    /// request, slot, lease or event) stands between them. Older history extends each member's
    /// held history downward (`ChannelState::history_older_page`): one saved request per author
    /// with positions below its held run, beside any already owed.
    fn accept_public(&mut self, room: Digest32, instance: [u8; 16], action: Action, reply: Reply) {
        let inputs = match self.public_inputs(room) {
            Ok(inputs) => inputs,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        let now = self.now_ms().get();
        if let Action::Older { before } = action {
            // What the room's record holds now settles the requests it completed, so that what
            // the person is told below counts only what is still owed.
            self.settle_archive_progress(room);
            // The room's authors already owed an older page, the lowest position those pages
            // owe (a private request's positions are its donor's: its author gets no page here),
            // and what those pages still lack.
            let owed: Vec<(Digest32, u64, usize, Status)> = self
                .history_demand
                .public
                .values()
                .filter(|p| p.status.room == room && !p.settling && !p.fence.is_retired())
                .map(|p| {
                    let lo = if p.private.is_some() { 1 } else { p.lo };
                    (p.author, lo, p.status.remaining, p.status.clone())
                })
                .collect();
            // Each page is one saved request; never ask for more than this node may keep.
            let limit = demand::PUBLIC_REQUESTS.saturating_sub(self.history_demand.public.len());
            self.public_task(inputs, Some(reply), move |guard, inputs| {
                let binding = public_binding(&guard, inputs, instance, now)?;
                let mut fetching = std::collections::BTreeMap::<Digest32, u64>::new();
                for (author, lo, _, _) in &owed {
                    let at = fetching.entry(*author).or_insert(*lo);
                    *at = (*at).min(*lo);
                }
                let page = guard
                    .history_older_page(&inputs.store, &before, &fetching, limit)
                    .map_err(|e| e.to_string())?;
                drop(guard);
                let mut found = Vec::new();
                let mut newest = None;
                let mut fetched = 0usize;
                for (head, author, lo, hi) in &page.owed {
                    let bounds = Bounds {
                        head: *head,
                        lo: *lo,
                        hi: *hi,
                        entries: usize::try_from(hi - lo + 1).map_err(|e| e.to_string())?,
                    };
                    let fresh =
                        crate::identity::rng::random_array::<16>().map_err(|e| e.to_string())?;
                    let request = demand::owe_public(&inputs.context, fresh, binding, bounds)
                        .map_err(|e| e.to_string())?;
                    let (status, saved) =
                        owe_saved(inputs, request, binding, bounds, *author, bounds.entries);
                    fetched += bounds.entries;
                    newest.get_or_insert(status);
                    found.push(saved);
                }
                let members = page
                    .owed
                    .iter()
                    .map(|(_, author, _, _)| *author)
                    .chain(owed.iter().map(|(author, _, _, _)| *author))
                    .collect::<std::collections::BTreeSet<_>>()
                    .len();
                let remaining = fetched + owed.iter().map(|(_, _, r, _)| r).sum::<usize>();
                let mut status = newest
                    .or_else(|| owed.last().map(|(_, _, _, s)| s.clone()))
                    .unwrap_or_else(|| status(room, instance, Phase::Complete, ""));
                status.remaining = remaining;
                // Owed is what extends each member's held history downward, down to its first
                // post. Completion is said when nothing is owed, arriving, unknown or left out for
                // want of a request. A member whose oldest held post no key here opens is not
                // owed here (its run reaches position 1, or it would have a page or be left out):
                // the request is finished, and the person is told so beside the key sentence.
                let mut detail = if members > 0 {
                    status.phase = Phase::Pending;
                    format!(
                        "Fetching {remaining} older posts of {members} member(s) from the members that hold them."
                    )
                } else if page.unknown > 0 || page.arriving > 0 || page.left_out > 0 {
                    // Not everything is here yet: say what is still coming, never that all is
                    // shown.
                    status.phase = Phase::More;
                    String::new()
                } else {
                    "Nothing older to fetch: every member's history here reaches back to its first post."
                        .to_owned()
                };
                let mut say = |sentence: String| {
                    if !detail.is_empty() {
                        detail.push(' ');
                    }
                    detail.push_str(&sentence);
                };
                if page.arriving > 0 {
                    say(format!(
                        "Posts of {} member(s) are still arriving.",
                        page.arriving
                    ));
                }
                if page.unreadable > 0 {
                    say(format!(
                        "The oldest posts held here of {} member(s) cannot be read with the keys this node retains. Coming back to a room does not restore earlier keys.",
                        page.unreadable
                    ));
                }
                if page.left_out > 0 {
                    say(format!(
                        "Older posts of {} member(s) were not asked for: this node already keeps {} older-history requests, in all rooms; ask again when some have finished.",
                        page.left_out,
                        demand::PUBLIC_REQUESTS
                    ));
                }
                if page.unknown > 0 {
                    say(format!(
                        "The history of {} member(s) is not known here yet.",
                        page.unknown
                    ));
                }
                status.detail = detail;
                Ok((status, found))
            });
            return;
        }
        let after = self
            .history_demand
            .selection
            .filter(|(r, i, _)| *r == room && *i == instance)
            .and_then(|(_, _, after)| after);
        self.public_task(inputs, Some(reply), move |guard, inputs| {
            let binding = public_binding(&guard, inputs, instance, now)?;
            let selected = select(&guard, &inputs.store, &inputs.lifecycle, after)
                .map_err(|e| e.to_string())?;
            drop(guard);
            let mut found = vec![Found::Selection(room, instance, selected.after)];
            let Some((bounds, author)) = selected.found else {
                let status = if selected.more {
                    status(room, instance, Phase::More, "This bounded scan is cached. Request newest again to check the next authors; unchecked history remains.")
                } else {
                    status(room, instance, Phase::Cached, "The selected bounded content is already cached; older history may still exist.")
                };
                return Ok((status, found));
            };
            let fresh = crate::identity::rng::random_array::<16>().map_err(|e| e.to_string())?;
            let request = demand::owe_public(&inputs.context, fresh, binding, bounds)
                .map_err(|e| e.to_string())?;
            let (status, saved) = owe_saved(inputs, request, binding, bounds, author, bounds.entries);
            found.push(saved);
            Ok((status, found))
        });
    }

    /// The room opened: each public request saved for it is owed again in the step that reads
    /// it, under the room's current binding; one saved under another instance, epoch or
    /// authorization is shown paused until an explicit Resume. A public request an earlier build
    /// saved in the archive slot joins the saved requests first, and its staging is reclaimed.
    fn restore_public_history(&mut self, room: Digest32) {
        let Ok(inputs) = self.public_inputs(room) else {
            return;
        };
        let budget = Arc::clone(&self.history_budget);
        let reclaim = (
            Arc::clone(&inputs.context),
            Arc::clone(&inputs.lifecycle),
            inputs.node,
        );
        let now = self.now_ms().get();
        self.public_task(inputs, None, move |guard, inputs| {
            let migrated =
                demand::migrate_public_slot(&inputs.context).map_err(|e| e.to_string())?;
            let current = guard
                .history_instance(&inputs.store)
                .ok()
                .and_then(|instance| public_binding(&guard, inputs, instance, now).ok());
            let mut found = Vec::new();
            for saved in demand::public_requests(&inputs.context)
                .map_err(|e| e.to_string())?
                .into_iter()
                .filter(|saved| saved.binding.room == room)
            {
                if let Some(plan) = saved.private.clone() {
                    // A private request is owed again only under exactly the binding it was
                    // saved with (its donor audience included); its donor, incarnation and
                    // grant are checked again by its loop before each ask.
                    let donor = plan.donor;
                    let held = PrivateHeld {
                        donor,
                        grant: plan.grant,
                        bounds: saved.bounds,
                        binding: saved.binding,
                    };
                    let owed = current
                        .map(|binding| Binding {
                            audience: donor,
                            ..binding
                        })
                        .filter(|binding| *binding == saved.binding);
                    match owed {
                        Some(binding) if !saved.paused => {
                            owe_saved_private(inputs, saved.request, binding, saved.bounds, plan);
                        }
                        _ => {
                            if !saved.paused {
                                demand::settle_public(
                                    &inputs.context,
                                    saved.request,
                                    demand::Progress::Paused,
                                    saved.remaining,
                                )
                                .map_err(|e| e.to_string())?;
                            }
                            let mut status = private_status(saved.binding, saved.request, saved.bounds, donor);
                            status.phase = Phase::Paused;
                            status.detail = "The room or its authorization changed since this private request was saved; resume it to fetch it again.".into();
                            found.push(Found::Saved {
                                status,
                                author: donor,
                                lo: saved.bounds.lo,
                                hi: saved.bounds.hi,
                                epoch: saved.binding.epoch,
                                fence: None,
                                private: Some(Box::new(held)),
                            });
                        }
                    }
                    continue;
                }
                let author = guard
                    .history_head_by_id(&inputs.store, &saved.bounds.head)
                    .ok()
                    .flatten()
                    .map(|head| head.binding.author);
                let owed = current.filter(|binding| *binding == saved.binding);
                match (author, owed) {
                    (Some(author), Some(binding)) if !saved.paused => {
                        found.push(
                            owe_saved(inputs, saved.request, binding, saved.bounds, author, saved.remaining).1,
                        );
                    }
                    (author, _) => {
                        if !saved.paused {
                            demand::settle_public(
                                &inputs.context,
                                saved.request,
                                demand::Progress::Paused,
                                saved.remaining,
                            )
                            .map_err(|e| e.to_string())?;
                        }
                        let mut status = saved_public_status(
                            saved.binding.instance,
                            saved.request,
                            saved.bounds,
                            author,
                            saved.remaining,
                        );
                        status.room = room;
                        status.phase = Phase::Paused;
                        status.detail = "The room or its authorization changed since this request was saved; resume it to fetch it again.".into();
                        found.push(Found::Saved {
                            status,
                            author: author.unwrap_or_default(),
                            lo: saved.bounds.lo,
                            hi: saved.bounds.hi,
                            epoch: saved.binding.epoch,
                            fence: None,
                            private: None,
                        });
                    }
                }
            }
            drop(guard);
            if let Some(request) = migrated {
                // The earlier build's staged body, reclaimed in bounded slices off this step.
                let (context, lifecycle, node) = reclaim;
                tokio::runtime::Handle::current().spawn(async move {
                    let job = tokio::select! {
                        biased;
                        () = lifecycle.retired() => return,
                        job = budget.admit_job(node, Lane::Control) => job,
                    };
                    let _ = tokio::task::spawn_blocking(move || {
                        let Ok(charge) = demand::AdmissionCharge::reserve(&job) else {
                            return;
                        };
                        while !lifecycle.is_retired() {
                            match demand::reclaim_precharged(&context, request, &charge) {
                                Ok(false) => std::thread::yield_now(),
                                Ok(true) | Err(_) => break,
                            }
                        }
                    })
                    .await;
                });
            }
            Ok((status(room, [0; 16], Phase::Idle, ""), found))
        });
    }

    /// An explicit Resume of a held public request: the same request and original bounds, owed
    /// again under the room's current binding.
    fn resume_public(
        &mut self,
        room: Digest32,
        instance: [u8; 16],
        request: RequestId,
        reply: Reply,
    ) {
        let inputs = match self.public_inputs(room) {
            Ok(inputs) => inputs,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        if let Some(public) = self.history_demand.public.get(&request) {
            public.fence.retire();
        }
        self.history_frontier.forgive_archive(request);
        let now = self.now_ms().get();
        self.public_task(inputs, Some(reply), move |guard, inputs| {
            let binding = public_binding(&guard, inputs, instance, now)?;
            let saved = demand::resume_public(&inputs.context, request, binding)
                .map_err(|e| e.to_string())?;
            let author = guard
                .history_head_by_id(&inputs.store, &saved.bounds.head)
                .map_err(|e| e.to_string())?
                .ok_or("The original authenticated head is unavailable.")?
                .binding
                .author;
            drop(guard);
            let (status, found) = owe_saved(
                inputs,
                request,
                binding,
                saved.bounds,
                author,
                saved.remaining,
            );
            Ok((status, vec![found]))
        });
    }

    /// Write a public request's new standing to its record off the actor: Complete or Cancelled
    /// end it, Paused keeps it for an explicit Resume. The loops owe it no more from now.
    fn settle_public(
        &mut self,
        request: RequestId,
        progress: demand::Progress,
        status: Status,
        reply: Option<Reply>,
    ) {
        let room = status.room;
        let inputs = match self.public_inputs(room) {
            Ok(inputs) => inputs,
            Err(error) => {
                // Tried again at the room's next admission or the person's next action.
                if let Some(reply) = reply {
                    let _ = reply.send(Err(error));
                }
                return;
            }
        };
        if let Some(public) = self.history_demand.public.get_mut(&request) {
            public.fence.retire();
            public.settling = true;
        }
        self.history_frontier.forgive_archive(request);
        let remaining = status.remaining;
        let tx = self.net_tx.clone();
        let task = tokio::spawn(async move {
            let context = Arc::clone(&inputs.context);
            let answer = tokio::task::spawn_blocking(move || {
                demand::settle_public(&context, request, progress, remaining)
                    .map_err(|e| e.to_string())
            })
            .await
            .map_err(|_| "History request worker stopped.".to_owned())
            .and_then(|result| result);
            let answer = answer.map(|_| {
                inputs
                    .found
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(Found::Ended(status.clone()));
                status
            });
            if let Some(reply) = reply {
                let _ = reply.send(answer);
            }
            let _ = tx.try_send(NetEvent::HistoryDemandPrepared { token: 0 });
        });
        self.history_demand
            .public_tasks
            .retain(|task| !task.is_finished());
        self.history_demand.public_tasks.push(task);
    }

    /// A person's request for a private Session interval of `donor` (`private-recover`): the
    /// interval past this node's live cursor for the donor, within the donor's current boundary
    /// and past what this node already asked of the same donor incarnation and grant, saved and
    /// owed to that donor's connection in the same step (ruling build order 6). Its original
    /// donor, incarnation, bounds and Drive grant never change; another donor never serves it.
    fn accept_private(
        &mut self,
        room: Digest32,
        instance: [u8; 16],
        donor: Digest32,
        reply: Reply,
    ) {
        let inputs = match self.public_inputs(room) {
            Ok(inputs) => inputs,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        // Intervals already asked of a donor, as (incarnation, grant, through).
        let asked: Vec<(Digest32, Digest32, u64)> = self
            .history_demand
            .public
            .values()
            .filter_map(|p| p.private)
            .filter(|held| held.binding.room == room && held.donor == donor)
            .map(|held| (held.bounds.head, held.grant, held.bounds.hi))
            .collect();
        let now = self.now_ms().get();
        self.public_task(inputs, Some(reply), move |guard, inputs| {
            if donor == inputs.node {
                return Err("Private history needs another member's computer as its donor.".into());
            }
            let binding = Binding {
                audience: donor,
                ..public_binding(&guard, inputs, instance, now)?
            };
            let (boundary, grant) = guard
                .private_history_scope(&inputs.store, &donor)
                .map_err(|e| e.to_string())?;
            let after = asked
                .iter()
                .filter(|(head, held, _)| *head == boundary.incarnation && *held == grant)
                .map(|(_, _, hi)| *hi)
                .fold(guard.private_recovery_after(&donor, boundary.incarnation), u64::max);
            drop(guard);
            if after >= boundary.after {
                return Ok((status(room, instance, Phase::Cached, "The currently advertised private interval has been examined; this is not proof of donor completeness."), Vec::new()));
            }
            let lo = after + 1;
            let hi = after.saturating_add(32).min(boundary.after);
            let bounds = Bounds {
                head: boundary.incarnation,
                lo,
                hi,
                entries: (hi - lo + 1) as usize,
            };
            let plan = demand::PrivatePlan {
                donor,
                grant,
                inventory_done: false,
                positions: Vec::new(),
            };
            let fresh = crate::identity::rng::random_array::<16>().map_err(|e| e.to_string())?;
            let request = demand::owe_private(&inputs.context, fresh, binding, bounds, plan.clone())
                .map_err(|e| e.to_string())?;
            let status = owe_saved_private(inputs, request, binding, bounds, plan);
            Ok((status, Vec::new()))
        });
    }

    /// An explicit Resume of a held private request: owed again to its original donor only
    /// while its exact binding, Drive grant and donor incarnation still hold.
    fn resume_private(
        &mut self,
        room: Digest32,
        instance: [u8; 16],
        request: RequestId,
        held: PrivateHeld,
        reply: Reply,
    ) {
        let inputs = match self.public_inputs(room) {
            Ok(inputs) => inputs,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        if let Some(public) = self.history_demand.public.get(&request) {
            public.fence.retire();
        }
        self.history_frontier.forgive_archive(request);
        let now = self.now_ms().get();
        self.public_task(inputs, Some(reply), move |guard, inputs| {
            let binding = Binding {
                audience: held.donor,
                ..public_binding(&guard, inputs, instance, now)?
            };
            let (boundary, grant) = guard
                .private_history_scope(&inputs.store, &held.donor)
                .map_err(|e| e.to_string())?;
            drop(guard);
            if binding != held.binding
                || grant != held.grant
                || boundary.incarnation != held.bounds.head
            {
                return Err(
                    "Private history authorization or donor incarnation changed; cancel this request."
                        .into(),
                );
            }
            let saved = demand::resume_public(&inputs.context, request, binding)
                .map_err(|e| e.to_string())?;
            let plan = saved.private.ok_or("The saved request is public history.")?;
            let status = owe_saved_private(inputs, request, binding, saved.bounds, plan);
            Ok((status, Vec::new()))
        });
    }

    /// A private request's loop finished it (its interval examined) or could not go on as saved
    /// (`reason`): Complete ends its record, otherwise it is paused for the person to resume or
    /// cancel. The loops owe it no more either way.
    pub(super) fn settle_private(&mut self, request: RequestId, outcome: Result<(), String>) {
        let Some(public) = self
            .history_demand
            .public
            .get_mut(&request)
            .filter(|p| p.private.is_some() && !p.settling)
        else {
            return;
        };
        let progress = match outcome {
            Ok(()) => {
                public.status.phase = Phase::Complete;
                public.status.remaining = 0;
                public.status.detail = "The selected donor interval was examined. This does not prove complete private history; another interval requires an explicit request.".into();
                demand::Progress::Complete
            }
            Err(reason) => {
                public.status.phase = Phase::Paused;
                public.status.detail = format!("Private history paused: {reason}")
                    .chars()
                    .take(128)
                    .collect();
                demand::Progress::Paused
            }
        };
        let status = public.status.clone();
        self.settle_public(request, progress, status, None);
    }

    /// A private page a connection's loop fetched goes to the native private admission
    /// (`PageFlow`, unchanged receive checks): live and automatic pages under the current
    /// private guard; a saved request's page under the capability it was owed with
    /// (`PrivateOwed`: its original binding, bounds and fence, published with its debt), while
    /// that fence stands, whether or not this actor has installed the request yet.
    pub(super) async fn private_loop_page(&mut self, page: stream::private::PrivatePage) {
        use stream::private::Delivered;
        let stream::private::PrivatePage {
            room,
            instance,
            peer,
            revision,
            page,
            job,
            charge,
            archive,
            answer,
        } = page;
        if !self
            .channels
            .get(&room)
            .is_some_and(|current| Arc::ptr_eq(current, &instance))
        {
            let _ = answer.send(Err(
                "The room changed before its private page was saved.".into()
            ));
            return;
        }
        let frontier = Arc::clone(&self.history_frontier);
        let Some((_, owed)) = archive else {
            let Some((_, guard)) = self.current_private_context() else {
                let _ = answer.send(Err("Node locked; the private page was not saved.".into()));
                return;
            };
            let (done, wait) = tokio::sync::oneshot::channel();
            let now = self.now_ms().get();
            self.begin_owned_private_live(
                room, instance, peer, revision, page, now, charge, guard, done,
            )
            .await;
            tokio::spawn(async move {
                let result = match wait.await {
                    Ok(Ok(result)) => Ok(Delivered::Live(result)),
                    Ok(Err(error)) => Err(error.to_string()),
                    Err(_) => Err("The private page's admission stopped.".to_owned()),
                };
                drop(job);
                // What follows an admission on the actor: the Session news a person sees.
                frontier.advanced(room, false, false);
                let _ = answer.send(result);
            });
            return;
        };
        if owed.room != room || owed.donor != peer || owed.fence.is_retired() {
            let _ = answer.send(Err("The private history request is no longer owed.".into()));
            return;
        }
        let page = match page {
            Ok(page) => page,
            Err(error) => {
                let _ = answer.send(Err(error.to_string()));
                return;
            }
        };
        let inputs = match self.public_inputs(room) {
            Ok(inputs) => inputs,
            Err(error) => {
                let _ = answer.send(Err(error));
                return;
            }
        };
        let nonce = match inputs
            .store
            .get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(
                crate::node::trust::TRUST_META_KEY,
            ) {
            Ok(nonce) => nonce,
            Err(error) => {
                let _ = answer.send(Err(error.to_string()));
                return;
            }
        };
        let guard = PrivateGuard {
            node: inputs.node,
            room,
            instance: owed.binding.instance,
            generation: owed.binding.grant,
            context: Arc::clone(&inputs.context),
            fence: owed.fence,
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(30),
        };
        let (done, wait) = tokio::sync::oneshot::channel();
        self.begin_owned_private_archive(
            room,
            instance,
            owed.bounds,
            owed.plan,
            page,
            nonce,
            guard,
            job,
            charge,
            done,
        )
        .await;
        tokio::spawn(async move {
            let result = match wait.await {
                Ok(Ok(receipt)) => Ok(Delivered::Archive(receipt.plan)),
                Ok(Err(error)) => Err(error),
                Err(_) => Err("The private page's admission stopped.".to_owned()),
            };
            frontier.advanced(room, false, false);
            let _ = answer.send(result);
        });
    }

    /// Take what the public requests' tasks found: owed and paused requests join the held set,
    /// ended ones keep their last status for Status. A request owed for a room no longer open,
    /// or after lock, is owed no more.
    pub(super) fn take_public_found(&mut self) {
        let found = std::mem::take(
            &mut *self
                .history_demand
                .public_found
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let live = self
            .history_demand
            .lifecycle
            .as_ref()
            .is_some_and(|fence| !fence.is_retired());
        let mut owed = std::collections::BTreeSet::new();
        for found in found {
            match found {
                Found::Saved {
                    status,
                    author,
                    lo,
                    hi,
                    epoch,
                    fence,
                    private,
                } => {
                    let Some(request) = status.request else {
                        continue;
                    };
                    let fence = match fence {
                        Some(fence) if live && self.channels.contains_key(&status.room) => {
                            owed.insert(status.room);
                            fence
                        }
                        fence => {
                            let retired = fence.unwrap_or_else(Fence::new);
                            retired.retire();
                            self.history_frontier.forgive_archive(request);
                            retired
                        }
                    };
                    self.history_demand.public_order += 1;
                    let public = Public {
                        status,
                        author,
                        lo,
                        hi,
                        epoch,
                        fence: Arc::clone(&fence),
                        order: self.history_demand.public_order,
                        settling: false,
                        private: private.map(|held| *held),
                    };
                    if let Some(was) = self.history_demand.public.insert(request, public) {
                        if !Arc::ptr_eq(&was.fence, &fence) {
                            was.fence.retire();
                        }
                    }
                }
                Found::Ended(status) => {
                    if let Some(public) = status
                        .request
                        .and_then(|request| self.history_demand.public.get_mut(&request))
                    {
                        public.status = status;
                        public.settling = false;
                    }
                }
                Found::Selection(room, instance, after) => {
                    self.history_demand.selection = Some((room, instance, after));
                }
            }
        }
        // Ended requests keep their last status for Status, the newest few only.
        let mut ended: Vec<(u64, RequestId)> = self
            .history_demand
            .public
            .iter()
            .filter(|(_, p)| matches!(p.status.phase, Phase::Complete | Phase::Cancelled))
            .map(|(request, p)| (p.order, *request))
            .collect();
        if ended.len() > 8 {
            ended.sort_unstable();
            for (_, request) in &ended[..ended.len() - 8] {
                self.history_demand.public.remove(request);
            }
        }
        for room in owed {
            self.settle_archive_progress(room);
        }
    }
}

#[derive(Clone)]
pub(super) struct PrivateGuard {
    node: Digest32,
    room: Digest32,
    instance: [u8; 16],
    generation: Digest32,
    context: Arc<Context>,
    fence: Arc<Fence>,
    deadline: tokio::time::Instant,
}
impl PrivateGuard {
    pub(super) fn check(&self, room: &ChannelState, store: &Store) -> Result<(), String> {
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

    pub(super) fn secret(&self) -> Arc<tokio::sync::OwnedRwLockReadGuard<()>> {
        self.context.secret_work()
    }

    pub(super) fn check_native(&self, store: &Store, epoch: u64) -> Result<(), String> {
        if self.fence.is_retired()
            || self.context.cancellation().is_cancelled()
            || tokio::time::Instant::now() >= self.deadline
            || stream::authorization_generation(store, self.node, self.room, self.instance, epoch)
                .map_err(|error| error.to_string())?
                != self.generation
        {
            return Err("Private recovery authority changed or request cancelled.".into());
        }
        Ok(())
    }
}

/// Existing current private delivery is tracked by join_tasks. Its blocking work retains the
/// secret-work lease and daemon reservation even when its async caller is aborted at lock.
#[derive(Clone)]
pub(super) struct CurrentPrivateGuard {
    lease: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    pub(super) nonce: Option<[u8; crate::atrest::sek::NONCE_LEN]>,
    deadline: tokio::time::Instant,
}

impl CurrentPrivateGuard {
    pub(super) fn secret(&self) -> Arc<tokio::sync::OwnedRwLockReadGuard<()>> {
        Arc::clone(&self.lease)
    }

    pub(super) fn check_native(&self, store: &Store) -> crate::error::Result<()> {
        if tokio::time::Instant::now() >= self.deadline
            || store.get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(
                crate::node::trust::TRUST_META_KEY,
            )? != self.nonce
        {
            return Err(crate::error::Error::StreamRefused(
                "private authority changed or request expired",
            ));
        }
        Ok(())
    }
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
        legacy_cancelled: None,
        local_only: true,
        local_boundary: LocalBoundary::Observed,
        terminal_checkpoint: false,
        accepted_selection: false,
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
        legacy_cancelled: None,
        local_only: true,
        local_boundary: LocalBoundary::Observed,
        terminal_checkpoint: false,
        accepted_selection: false,
        resume_kind: Some(state.private.is_some()),
    })
}

/// What every public request's task holds (`Node::public_inputs`).
struct PublicInputs {
    node: Digest32,
    shared: Arc<crate::node::channel::RoomLock>,
    context: Arc<Context>,
    store: Arc<Store>,
    lifecycle: Arc<Fence>,
    frontier: Arc<stream::pull::Frontier>,
    found: Arc<StdMutex<Vec<Found>>>,
}

/// The room's current public binding for this node, while it is a member of the room at the
/// saved incarnation and the room syncs by bounded history.
fn public_binding(
    room: &ChannelState,
    inputs: &PublicInputs,
    instance: [u8; 16],
    now: u64,
) -> Result<Binding, String> {
    let id = room.channel_id();
    if room
        .history_instance(&inputs.store)
        .map_err(|e| e.to_string())?
        != instance
        || !room.is_member(&inputs.node)
        || room.has_left(&inputs.node)
        || room.ended(now).is_some()
    {
        return Err("The saved room or membership changed.".into());
    }
    if !room
        .uses_sparse_history(&inputs.store)
        .map_err(|e| e.to_string())?
    {
        return Err(crate::node::channel::UNSUPPORTED_ROOM_FORMAT.into());
    }
    let epoch = room.epoch();
    Ok(Binding {
        room: id,
        instance,
        epoch,
        audience: [0; 32],
        grant: stream::authorization_generation(&inputs.store, inputs.node, id, instance, epoch)
            .map_err(|e| e.to_string())?,
    })
}

/// A saved public request is owed: it enters the frontier's set of owed requests now, under a
/// fresh fence, keyed by the request, with its original bounds.
fn owe_saved(
    inputs: &PublicInputs,
    request: RequestId,
    binding: Binding,
    bounds: Bounds,
    author: Digest32,
    remaining: usize,
) -> (Status, Found) {
    let fence = Fence::new();
    inputs.frontier.owe_archive(
        request,
        stream::pull::ArchiveOwed {
            room: binding.room,
            author,
            lo: bounds.lo,
            hi: bounds.hi,
            fence: Arc::clone(&fence),
        },
    );
    let mut status =
        saved_public_status(binding.instance, request, bounds, Some(author), remaining);
    status.room = binding.room;
    let found = Found::Saved {
        status: status.clone(),
        author,
        lo: bounds.lo,
        hi: bounds.hi,
        epoch: binding.epoch,
        fence: Some(fence),
        private: None,
    };
    (status, found)
}

/// What a person reads of a public request being fetched (`--history older` answers it).
fn saved_public_status(
    instance: [u8; 16],
    request: RequestId,
    bounds: Bounds,
    author: Option<Digest32>,
    remaining: usize,
) -> Status {
    let detail = author.map_or_else(
        || "The selected history interval is owed.".to_owned(),
        |author| fetching(bounds.lo, bounds.hi, &author, remaining),
    );
    let mut status = status([0; 32], instance, Phase::Pending, &detail);
    status.request = Some(request);
    status.author = author;
    status.head = Some(bounds.head);
    status.remaining = remaining;
    status.headers = bounds.entries;
    status
}

/// "Fetching what remains of positions `lo` to `hi` of `author`".
fn fetching(lo: u64, hi: u64, author: &Digest32, remaining: usize) -> String {
    format!(
        "Fetching {remaining} older entries of {} (positions {lo} to {hi}) from the members that hold them.",
        &crate::node::link::b32_encode(author)[..12]
    )
}

/// A saved private request is owed: its registration (`Found::Saved`, for the actor's request
/// set) is published first, then it enters the frontier's set of private requests under the
/// same fresh fence, owed to its original donor's connection only, with its original bounds
/// and plan. The actor takes published registrations before it settles what the loops
/// finished (`actor.rs`), so an outcome can never precede the request it ends.
fn owe_saved_private(
    inputs: &PublicInputs,
    request: RequestId,
    binding: Binding,
    bounds: Bounds,
    plan: demand::PrivatePlan,
) -> Status {
    let fence = Fence::new();
    let donor = plan.donor;
    let status = private_status(binding, request, bounds, donor);
    inputs
        .found
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(Found::Saved {
            status: status.clone(),
            author: donor,
            lo: bounds.lo,
            hi: bounds.hi,
            epoch: binding.epoch,
            fence: Some(Arc::clone(&fence)),
            private: Some(Box::new(PrivateHeld {
                donor,
                grant: plan.grant,
                bounds,
                binding,
            })),
        });
    inputs.frontier.owe_private(
        request,
        stream::pull::PrivateOwed {
            room: binding.room,
            donor,
            binding,
            bounds,
            plan,
            fence,
        },
    );
    status
}

/// What a person reads of a private request being fetched.
fn private_status(binding: Binding, request: RequestId, bounds: Bounds, donor: Digest32) -> Status {
    let detail = format!(
        "Waiting for {} to send its private Session positions {} to {}; only that donor serves them.",
        &crate::node::link::b32_encode(&donor)[..12],
        bounds.lo,
        bounds.hi
    );
    let mut status = status(binding.room, binding.instance, Phase::Pending, &detail);
    status.private_peer = Some(donor);
    status.private_lo = Some(bounds.lo);
    status.private_hi = Some(bounds.hi);
    status.request = Some(request);
    status.head = Some(bounds.head);
    status.remaining = bounds.entries;
    status.headers = bounds.entries;
    status
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
    weak: Weak<crate::node::channel::RoomLock>,
    fence: Arc<Fence>,
    now: u64,
    deadline: tokio::time::Instant,
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
        legacy_cancelled: None,
        local_only: false,
        local_boundary: LocalBoundary::Observed,
        terminal_checkpoint: false,
        accepted_selection: false,
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
        || saved.as_ref().is_some_and(|s| s.state().private.is_some())
    {
        return Err(
            "This private history request is owed by its donor's connection; ask for its status again."
                .into(),
        );
    }
    if !room.uses_sparse_history(store).map_err(|e| e.to_string())? {
        return Err(crate::node::channel::UNSUPPORTED_ROOM_FORMAT.into());
    }
    // A public request is owed by the loops from its own saved record (`begin_public_history`);
    // this archive slot keeps only an entry an earlier build admitted and still recovers locally.
    let Action::Resume { request } = action else {
        return Err("History selection requires newest or older.".into());
    };
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
        Err(
            "This saved request is owed by its room's connections; ask for its status again."
                .into(),
        )
    }
}

struct Selection {
    found: Option<(Bounds, Digest32)>,
    after: Option<Digest32>,
    more: bool,
}

/// `--history newest`: the newest bounded run of an author's positions not rendered here, across
/// the heads this node holds. Only signed headers and retained-body facts are read; a held body
/// is never decoded to select it. (`--history older` is the room's older page,
/// `ChannelState::history_older_page`.)
fn select(
    room: &ChannelState,
    store: &Store,
    fence: &Fence,
    after: Option<Digest32>,
) -> crate::error::Result<Selection> {
    use crate::log::history::SignedEntryKind;
    let read = room.history_read(store)?;
    let heads = room.history_head_hints(store, after)?;
    let page_after = heads.next;
    if heads.heads.is_empty() && (after.is_some() || heads.next.is_some()) {
        return Ok(Selection {
            found: None,
            after: heads.next,
            more: heads.next.is_some(),
        });
    }
    if heads.heads.is_empty() {
        return Err(crate::error::Error::Profile(
            "Authenticated history heads are not available yet; cached messages remain available.",
        ));
    }
    let candidates: Vec<(Digest32, Digest32, u64)> = heads
        .heads
        .into_iter()
        .map(|h| (h.head, h.author, h.leaves))
        .collect();
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
            if fence.is_retired() {
                return Err(crate::error::Error::Profile("History selection cancelled."));
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
        let operation_active = self.resume_owed.is_some();
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
        let active_stage = self.preparing.is_some().then_some("preparing");
        let render_owner = |status: &Status, stage: &str| {
            let peer = status.private_peer.map_or_else(
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
            self.owner_status
                .as_ref()
                .zip(active_stage)
                .map(|(status, stage)| render_owner(status, stage))
                .or_else(|| {
                    // A person's newest public request the loops owe.
                    self.public
                        .values()
                        .filter(|p| !p.fence.is_retired())
                        .max_by_key(|p| p.order)
                        .map(|p| render_owner(&p.status, "owed"))
                })
                .unwrap_or_else(|| "null".to_owned())
        };
        let owed = self
            .public
            .values()
            .filter(|p| !p.fence.is_retired())
            .count();
        format!(
            "{{\"phase\":{phase},\"detail\":{detail},\"owner\":{owner},\"preparing\":{},\"owed\":{owed}}}",
            self.preparing.is_some(),
        )
    }
}
