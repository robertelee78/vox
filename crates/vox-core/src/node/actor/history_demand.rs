//! Explicit archive selection and activation. Cache reads never enter this module.

use super::{NetEvent, Node};
mod legacy;
use crate::hash::Digest32;
use crate::node::api::{
    HistoryDemandAction as Action, HistoryDemandPhase as Phase, HistoryDemandStatus as Status,
};
use crate::node::channel::legacy_provisional::LegacyProvisionalOwner;
use crate::node::channel::{entry_store::sparse::ObjectKind, ChannelState};
use crate::node::history_budget::{Job, Lane};
use crate::node::history_demand::{self as demand, Binding, Bounds, Context};
use crate::node::history_stream::{self as stream, Query, RequestId, Staging};
use crate::node::store::Store;
use crate::transport::stream_transport::Fence;
use legacy::LegacyDispatch;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use tokio::sync::Mutex;

pub(super) struct Dispatch {
    pub room: Digest32,
    pub instance: [u8; 16],
    pub peer: Digest32,
    pub request: RequestId,
    pub generation: Digest32,
    pub query: Query,
    pub staging: Staging,
    pub fence: Arc<Fence>,
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
    legacy: Option<LegacyDispatch>,
    legacy_cancelled: Option<LegacyProvisionalOwner>,
    local_only: bool,
    selection_after: Option<Option<Digest32>>,
}
pub(super) struct Preparation {
    pub(super) token: u64,
    fence: Arc<Fence>,
    cancellation: demand::Cancellation,
    result: Arc<StdMutex<Option<Result<Prepared, String>>>>,
    task: tokio::task::JoinHandle<()>,
}
struct Running {
    request: RequestId,
    generation: Digest32,
    fence: Arc<Fence>,
    cancellation: demand::Cancellation,
    /// The page this quantum fetches (head, lo, hi), when it is a page.
    page: Option<(Digest32, u64, u64)>,
}

fn page_of(query: &Query) -> Option<(Digest32, u64, u64)> {
    match query {
        Query::Page { head, lo, hi, .. } => Some((*head, *lo, *hi)),
        _ => None,
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
    status: Option<Status>,
    selection: Option<(Digest32, [u8; 16], Option<Digest32>)>,
}
impl Controller {
    pub(super) fn ready_binding(
        &self,
        room: Digest32,
        peer: Digest32,
    ) -> Option<(RequestId, Digest32, [u8; 16])> {
        self.ready
            .as_ref()
            .filter(|dispatch| {
                dispatch.room == room && dispatch.peer == peer && !dispatch.fence.is_retired()
            })
            .map(|dispatch| (dispatch.request, dispatch.generation, dispatch.instance))
    }

    pub(super) fn take_legacy_cleanup(&mut self) -> Option<(Digest32, LegacyProvisionalOwner)> {
        self.cancelled_legacy.take()
    }
    pub(super) fn take_ready(&mut self, room: Digest32, peer: Digest32) -> Option<Dispatch> {
        if self
            .ready
            .as_ref()
            .is_some_and(|d| d.room == room && d.peer == peer && !d.fence.is_retired())
        {
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
            self.status = Some(status);
        }
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
        if let Some(status) = self.status.as_mut().filter(|s| s.request == Some(request)) {
            status.phase = Phase::Paused;
            status.detail = detail.chars().take(128).collect();
        }
    }
    fn stop_request(&mut self, room: Digest32, instance: [u8; 16], request: RequestId) -> bool {
        if !self
            .status
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
    /// The daemon's bounded archive queue could not retain this request. Keep its durable
    /// identity available for an explicit retry, but report the capacity refusal honestly.
    pub(super) fn busy(&mut self, request: RequestId, generation: Digest32, detail: &str) {
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
        if let Some(status) = self.status.as_mut().filter(|s| s.request == Some(request)) {
            status.phase = Phase::Busy;
            status.detail = detail.chars().take(128).collect();
        }
    }
    pub(super) fn retire_room(&mut self, room: Digest32) {
        if self.status.as_ref().is_none_or(|s| s.room != room) {
            return;
        }
        self.fence();
        self.running = None;
        self.ready = None;
        if let Some(status) = &mut self.status {
            status.phase = Phase::Paused;
            status.detail = "This room is no longer active; its saved history request can be cancelled locally.".into();
        }
    }

    /// Stop admission synchronously; the lock settling task then owns and retires this controller.
    pub(super) fn fence(&self) {
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
        self.status = None;
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
        let completed = self.accept_history_demand();
        if let Some(current) = &self.history_demand.status {
            if current.room == room
                && current.instance == instance
                && matches!(action, Action::Status)
                && (completed
                    || self.history_demand.preparing.is_some()
                    || self.history_demand.running.is_some()
                    || current.request.is_some()
                    || !matches!(current.phase, Phase::Unavailable | Phase::Paused))
            {
                return Ok(current.clone());
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
        if let Action::Cancel { request } = action {
            if self.history_demand.running.is_some()
                && !self.history_demand.status.as_ref().is_some_and(|s| {
                    s.room == room && s.instance == instance && s.request == Some(request)
                })
            {
                return Err(
                    "The running history request belongs to a different room, instance or request."
                        .into(),
                );
            }
            if self.history_demand.stop_request(room, instance, request) {
                self.bounded_sync.cancel_archive(room, instance, request);
            }
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
                    .zip(self.history_demand.status.as_ref())
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
                    .status
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
        }
        let prior_private = if matches!(action, Action::Cancel { .. }) {
            self.history_demand.private_work.take()
        } else {
            if self.history_demand.private_work.is_some() {
                return Ok(self.history_demand.status.clone().unwrap_or_else(|| {
                    status(
                        room,
                        instance,
                        Phase::Busy,
                        "Private history work is settling.",
                    )
                }));
            }
            None
        };
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
        let secret_work = Arc::new(
            self.secret_work
                .clone()
                .try_read_owned()
                .map_err(|_| "Node secret work is settling; history was not started.")?,
        );
        let context = Arc::new(Context::unlocked(profile, secret_work).map_err(|e| e.to_string())?);
        let store = profile.store_handle();
        let Some(job) = self.history_budget.try_start(node, Lane::Control) else {
            return Ok(status(
                room,
                instance,
                Phase::Busy,
                "History preparation is busy; cached messages remain available.",
            ));
        };
        let peers: Vec<_> = self
            .ports
            .keys()
            .filter(|(r, p)| *r == room && *p != node && self.trust.is_trusted(p))
            .map(|(_, p)| *p)
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
        let task = tokio::spawn(async move {
            let work = async {
                if let Some(prior) = prior_private { let _ = prior.task.await; }
                let Some(charge) = job.reserve(5 * 1024 * 1024) else { return Err("history preparation buffers are busy".into()); };
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
                let room_guard = if local_only { None } else {
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
                    let _charge = charge;
                    if read_fence.is_retired() || tokio::time::Instant::now() >= deadline { return Err("history preparation cancelled or expired".into()); }
                    let answer = match room_guard {
                        Some(guard) => prepare(&guard, &store, node, instance, action, context, &job, peers, weak, read_fence.clone(), now, deadline, selection_after),
                        None => prepare_local(node, room, instance, action, context, &job, &read_fence, deadline),
                    };
                    if read_fence.is_retired() || tokio::time::Instant::now() >= deadline { return Err("history preparation cancelled or expired".into()); }
                    answer
                }).await.map_err(|_| "history preparation worker stopped".to_owned())?
            }.await;
            if let Ok(mut output) = result_out.lock() {
                *output = Some(work);
            }
            // A full inbox does not strand the result: schedule() and status also check this slot.
            let _ = tx.try_send(NetEvent::HistoryDemandPrepared { token });
        });
        let pending = status(
            room,
            instance,
            Phase::Preparing,
            "Checking cached history and preparing one bounded request.",
        );
        self.history_demand.status = Some(pending.clone());
        self.history_demand.preparing = Some(Preparation {
            token,
            fence,
            cancellation,
            result,
            task,
        });
        Ok(pending)
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
        let Ok(mut result) = preparation.result.try_lock() else {
            return false;
        };
        let Some(ready) = result.as_ref() else {
            return false;
        };
        if let Ok(prepared) = ready {
            let current = self
                .profile
                .as_ref()
                .filter(|p| p.fingerprint() == prepared.node)
                .and_then(|profile| {
                    self.channels
                        .get(&prepared.status.room)
                        .map(|room| (profile, room))
                });
            let valid = if prepared.local_only {
                self.profile
                    .as_ref()
                    .is_some_and(|p| p.fingerprint() == prepared.node)
            } else if let Some((profile, shared)) = current {
                let Ok(room) = shared.try_lock() else {
                    return false;
                };
                prepared
                    .room
                    .upgrade()
                    .is_some_and(|old| Arc::ptr_eq(&old, shared))
                    && room.epoch() == prepared.epoch
                    && room.history_instance(profile.store()).ok() == Some(prepared.status.instance)
                    && room.is_member(&prepared.node)
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
                        == Some(prepared.generation)
            } else {
                false
            };
            if !valid {
                if let Some(Ok(prepared)) = result.take() {
                    if let Some(dispatch) = prepared.dispatch {
                        dispatch.fence.retire();
                        dispatch.staging.context.cancellation().cancel();
                    }
                }
                drop(result);
                self.history_demand.preparing = None;
                if let Some(status) = &mut self.history_demand.status {
                    status.phase = Phase::Paused;
                    status.detail =
                        "The room or authorization changed; request history again.".into();
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
                if let Some(status) = &mut self.history_demand.status {
                    status.phase = Phase::Unavailable;
                    status.detail = reason.chars().take(128).collect();
                }
            }
            Ok(prepared) => {
                if let Some(after) = prepared.selection_after {
                    self.history_demand.selection =
                        Some((prepared.status.room, prepared.status.instance, after));
                }
                if let Some(owner) = prepared.legacy_cancelled {
                    self.history_demand.cancelled_legacy = Some((prepared.status.room, owner));
                }
                self.history_demand.status = Some(prepared.status);
                if let Some(dispatch) = prepared.legacy {
                    self.history_demand.running = Some(Running {
                        request: dispatch.request,
                        generation: dispatch.generation,
                        fence: dispatch.fence.clone(),
                        cancellation: dispatch.staging.context.cancellation(),
                        page: None,
                    });
                    self.start_legacy_history(dispatch);
                }
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
                    if let Some(port) = self.ports.get_mut(&(dispatch.room, dispatch.peer)) {
                        port.raise();
                    }
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
    job: Job,
    guard: CurrentPrivateGuard,
    work: impl FnOnce(&mut ChannelState, &Store) -> crate::error::Result<T> + Send + 'static,
) -> crate::error::Result<T> {
    use crate::error::Error;
    let charge = job
        .reserve(4 * 1024 * 1024)
        .ok_or(Error::StreamRefused("private disk buffers are busy"))?;
    let mut room = tokio::time::timeout_at(guard.deadline, room.lock_owned())
        .await
        .map_err(|_| Error::StreamRefused("private room lock deadline elapsed"))?;
    tokio::task::spawn_blocking(move || {
        let _lease = guard.lease;
        let _job = job;
        let _charge = charge;
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
        if tokio::time::Instant::now() >= guard.deadline
            || store.get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(
                crate::node::trust::TRUST_META_KEY,
            )? != guard.nonce
        {
            return Err(Error::StreamRefused(
                "private authority changed or request expired",
            ));
        }
        Ok(result)
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

#[allow(clippy::too_many_arguments)] // One exact locally authorized cleanup/status operation.
fn prepare_local(
    node: Digest32,
    room: Digest32,
    instance: [u8; 16],
    action: Action,
    context: Arc<Context>,
    job: &Job,
    fence: &Fence,
    deadline: tokio::time::Instant,
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
        legacy: None,
        legacy_cancelled: None,
        local_only: true,
        selection_after: None,
    };
    let saved = demand::inspect(&context, job).map_err(|e| e.to_string())?;
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
            if let Some(plan) = &state.legacy {
                answer.legacy_cancelled = Some(LegacyProvisionalOwner {
                    request,
                    instance,
                    author: plan.author,
                });
            }
            cancel_exact(&context, request, job, fence, deadline)?;
            answer.status.phase = Phase::Cancelled;
            answer.status.detail = "History request cancelled; provisional bytes reclaimed.".into();
        }
        _ => return Err("The saved history request changed.".into()),
    }
    Ok(answer)
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
    peers: Vec<Digest32>,
    weak: Weak<Mutex<ChannelState>>,
    fence: Arc<Fence>,
    now: u64,
    deadline: tokio::time::Instant,
    selection_after: Option<Digest32>,
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
        legacy: None,
        legacy_cancelled: None,
        local_only: false,
        selection_after: None,
    };
    let mut saved = demand::inspect(&context, job).map_err(|e| e.to_string())?;
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
        );
    }
    if !room.uses_sparse_history(store).map_err(|e| e.to_string())? {
        return legacy::prepare_legacy(
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
        );
    }
    let (bounds, author, query, active, remaining) = if let Action::Resume { request } = action {
        let saved = saved.as_ref().ok_or("No history request is saved.")?;
        let state = saved.state();
        if state.request != request {
            return Err("The history request changed.".into());
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
        let active = demand::resume(&context, request, binding, job).map_err(|e| e.to_string())?;
        (
            state.bounds,
            head.binding.author,
            query,
            active,
            state.remaining,
        )
    } else {
        // An explicit new ask is the person's newer intent: it ends a paused earlier quantum
        // instead of being turned away by it; `--history resume` continues one on purpose.
        // Measured before this: a newcomer paging back was told "A saved request exists" for
        // 60 s after one quantum paused, and the page below his window never came.
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
            cancel_exact(&context, request, job, &fence, deadline)?;
        }
        let selected = select(room, store, action, &fence, deadline, selection_after)
            .map_err(|e| e.to_string())?;
        if matches!(action, Action::Newest) {
            answer.selection_after = Some(selected.after);
        }
        let Some((bounds, author)) = selected.found else {
            answer.status = if selected.more {
                status(id, instance, Phase::More, "This bounded scan is cached. Request newest again to check the next authors; unchecked history remains.")
            } else {
                status(id, instance, Phase::Cached, "The selected bounded content is already cached; older history may still exist.")
            };
            return Ok(answer);
        };
        let request = crate::identity::rng::random_array::<16>().map_err(|e| e.to_string())?;
        let active =
            demand::start(&context, request, binding, bounds, job).map_err(|e| e.to_string())?;
        let query = Query::Page {
            head: bounds.head,
            lo: bounds.lo,
            hi: bounds.hi,
            entries: bounds.entries,
            wire_bytes: 1024 * 1024,
        };
        (bounds, author, query, active, bounds.entries)
    };
    let request = active.request();
    let Some(peer) = peers
        .into_iter()
        .find(|peer| room.is_member(peer) && !room.has_left(peer))
    else {
        let mut active = active;
        demand::pause(&context, &mut active, job).map_err(|e| e.to_string())?;
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
) -> Result<Prepared, String> {
    let peer = match action {
        Action::PrivateRecover { peer } => peer,
        Action::Resume { request } => {
            let state = saved
                .filter(|s| s.request == request)
                .ok_or("The private history request changed.")?;
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
    let (bounds, plan, mut active) = if let Action::Resume { request } = action {
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
        let active = demand::resume(&context, request, binding, job).map_err(|e| e.to_string())?;
        (state.bounds, plan, active)
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
        let active = demand::start_private(&context, request, binding, bounds, plan.clone(), job)
            .map_err(|e| e.to_string())?;
        (bounds, plan, active)
    };
    let snapshot = demand::inspect(&context, job)
        .map_err(|e| e.to_string())?
        .ok_or("Private history state disappeared.")?;
    answer.status = saved_status(snapshot.state(), None, Some(&active));
    if !peers.contains(&peer) || peer == node {
        demand::pause(&context, &mut active, job).map_err(|e| e.to_string())?;
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
