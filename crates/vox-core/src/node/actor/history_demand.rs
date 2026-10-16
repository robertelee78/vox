//! Explicit archive selection and activation. Cache reads never enter this module.

use super::{NetEvent, Node};
use crate::hash::Digest32;
use crate::node::api::{
    HistoryDemandAction as Action, HistoryDemandPhase as Phase, HistoryDemandStatus as Status,
};
use crate::node::channel::{entry_store::sparse::ObjectKind, ChannelState};
use crate::node::history_budget::{Job, Lane};
use crate::node::history_demand::{self as demand, Binding, Bounds, Context};
use crate::node::history_stream::{self as stream, Query, RequestId, Staging};
use crate::node::store::Store;
use crate::transport::stream_transport::Fence;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use tokio::sync::Mutex;

pub(super) struct Dispatch {
    pub room: Digest32,
    pub instance: [u8; 16],
    pub peer: Digest32,
    pub request: RequestId,
    pub generation: Digest32,
    pub query: Query,
    pub bounds: Bounds,
    pub staging: Staging,
    pub fence: Arc<Fence>,
}

struct Prepared {
    node: Digest32,
    room: Weak<Mutex<ChannelState>>,
    epoch: u64,
    generation: Digest32,
    status: Status,
    dispatch: Option<Dispatch>,
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
}
#[derive(Default)]
pub(super) struct Controller {
    next: u64,
    pub(super) preparing: Option<Preparation>,
    ready: Option<Dispatch>,
    running: Option<Running>,
    status: Option<Status>,
    selection: Option<(Digest32, [u8; 16], Option<Digest32>)>,
}
impl Controller {
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
    fn stop_request(&mut self, room: Digest32, instance: [u8; 16], request: RequestId) {
        if !self
            .status
            .as_ref()
            .is_some_and(|s| s.room == room && s.instance == instance && s.request == Some(request))
        {
            return;
        }
        if let Some(running) = self.running.as_ref().filter(|r| r.request == request) {
            running.fence.retire();
            running.cancellation.cancel();
            self.running = None;
            self.ready = None;
        }
    }
    pub(super) fn retire_room(&mut self, room: Digest32) {
        if !self.status.as_ref().is_some_and(|s| s.room == room) {
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
        self.status = None;
    }
}
fn status(room: Digest32, instance: [u8; 16], phase: Phase, detail: &str) -> Status {
    Status {
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
pub(super) fn saved_status(
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
        room: state.binding.room,
        instance: state.binding.instance,
        request: Some(state.request),
        phase,
        author,
        head: Some(state.bounds.head),
        remaining: state.remaining,
        offset: state
            .body
            .as_ref()
            .map_or_else(|| state.cursor.map_or(0, |c| c.offset), |body| body.offset),
        headers: state.bounds.entries,
        wire_bytes: 1024 * 1024,
        detail: if state.reclaiming() {
            "Provisional history cleanup is pending."
        } else {
            "This operation covers only its selected bounded history interval."
        }
        .into(),
    }
}

impl Node {
    pub(super) fn begin_history_demand(
        &mut self,
        room: Digest32,
        instance: [u8; 16],
        action: Action,
    ) -> Result<Status, String> {
        let completed = self.accept_history_demand();
        if let Some(current) = &self.history_demand.status {
            if current.room == room && current.instance == instance {
                if matches!(action, Action::Status)
                    && (completed
                        || self.history_demand.preparing.is_some()
                        || self.history_demand.running.is_some()
                        || current.request.is_some()
                        || !matches!(current.phase, Phase::Unavailable | Phase::Paused))
                {
                    return Ok(current.clone());
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
            self.history_demand.stop_request(room, instance, request);
        } else if self.history_demand.running.is_some() {
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

    /// Metadata-only event; a single private result slot owns any not-yet-dispatched context.
    pub(super) fn accept_history_demand(&mut self) -> bool {
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
        let ready = result.take().expect("checked history preparation");
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
                self.history_demand.status = Some(prepared.status);
                if let Some(dispatch) = prepared.dispatch {
                    self.history_demand.running = Some(Running {
                        request: dispatch.request,
                        generation: dispatch.generation,
                        fence: dispatch.fence.clone(),
                        cancellation: dispatch.staging.context.cancellation(),
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
    answer.status = saved_status(state, None, None);
    match action {
        Action::Status => {}
        Action::Cancel { request } if request == state.request => {
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
        if (replaced || removed) && matches!(action, Action::Newest | Action::Older { .. }) {
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
    let (bounds, author, query, active, remaining) = if let Action::Resume { request } = action {
        let saved = saved.as_ref().ok_or("No history request is saved.")?;
        let state = saved.state();
        if state.request != request {
            return Err("The history request changed.".into());
        }
        if state.remaining == 0 || state.cursor.is_some_and(|c| c.next_seq > state.bounds.hi) {
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
                lo: cursor.next_seq,
                hi: state.bounds.hi,
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
        if let Some(saved) = saved.as_ref() {
            if !matches!(
                saved.state().progress(None),
                demand::Progress::Complete | demand::Progress::Cancelled
            ) || saved.state().reclaiming()
            {
                answer.status.detail =
                    "A saved request exists. Resume or cancel it explicitly.".into();
                return Ok(answer);
            }
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
        bounds,
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
                Some(header) => read.retention(&header.entry_hash())?.is_some(),
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
