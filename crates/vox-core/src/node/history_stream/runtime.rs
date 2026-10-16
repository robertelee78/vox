//! One bounded outgoing work slice. The actor owns scheduling; this state contains only
//! bounded cursors and the three existing staging capabilities, never a retained entry body.

use super::source::{Lookup, Source};
use super::{
    EntryPhase, LocalNeed, LocalStep, Preamble, Purpose, Query, Receiver, RequestId, Staging,
    Status,
};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::channel::ChannelState;
use crate::node::history_budget::Job;
use crate::node::history_demand::{self as demand, Binding, Bounds, Context};
use crate::node::store::Store;
use crate::transport::quic::VoxConnection;
use crate::transport::stream_transport::Fence;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;

const MAX_TASKS: usize = 128;
#[derive(Clone)]
enum Operation {
    Tail { head: Digest32, seq: u64 },
    Wire(Query),
    Local(LocalStep),
    Reclaim(Purpose),
    Governance,
}
#[derive(Clone)]
struct Task {
    request: RequestId,
    purpose: Purpose,
    operation: Operation,
}

/// Scalar ownership of the existing fixed body slots. A progressing transfer keeps its slot
/// across quanta; another deferred flow may advance metadata but cannot reset that body.
#[derive(Default)]
pub(crate) struct BodySlots(StdMutex<[Option<RequestId>; 2]>);
impl BodySlots {
    fn claim(&self, purpose: Purpose, request: RequestId) -> bool {
        let Some(index) = body_slot(purpose) else {
            return true;
        };
        let mut slots = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slots[index].is_some_and(|owner| owner != request) {
            return false;
        }
        slots[index] = Some(request);
        true
    }
    fn release(&self, purpose: Purpose, request: RequestId) {
        let Some(index) = body_slot(purpose) else {
            return;
        };
        let mut slots = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slots[index] == Some(request) {
            slots[index] = None;
        }
    }
}
fn body_slot(purpose: Purpose) -> Option<usize> {
    match purpose {
        Purpose::Live => Some(0),
        Purpose::Control => Some(1),
        Purpose::History => None,
    }
}

pub(crate) struct Flow {
    pub(crate) room: Digest32,
    pub(crate) peer: Digest32,
    pub(crate) node: Digest32,
    pub(crate) epoch: u64,
    pub(crate) instance: [u8; 16],
    pub(crate) generation: Digest32,
    pub(crate) shared: Arc<Mutex<ChannelState>>,
    pub(crate) archive: bool,
    pub(crate) inventory: bool,
    pub(crate) archive_request: Option<RequestId>,
    _state_charge: crate::node::history_budget::BufferCharge,
    pub(crate) hint: Option<super::HeadHint>,
    pub(crate) waiting: bool,
    pub(crate) published: bool,
    pub(crate) rendered: bool,
    pub(crate) governance: bool,
    pub(crate) admitted_authors: usize,
    pub(crate) external: Option<(Digest32, u64)>,
    pub(crate) archive_status: Option<crate::node::api::HistoryDemandStatus>,
    tasks: Vec<Task>,
    slots: Arc<BodySlots>,
    owners: [Option<RequestId>; 2],
    busy_body: u8,
    live_context: Option<Arc<Context>>,
    control_context: Arc<Context>,
    live: Option<Staging>,
    control: Option<Staging>,
    history: Option<Staging>,
    archive_wire_used: bool,
    archive_next: Option<u64>,
    pub(crate) request_fence: Option<Arc<Fence>>,
    initialized: bool,
}
impl Flow {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn foreground(
        room: Digest32,
        peer: Digest32,
        node: Digest32,
        epoch: u64,
        shared: Arc<Mutex<ChannelState>>,
        live: Arc<Context>,
        control: Arc<Context>,
        hint: Option<super::HeadHint>,
        required: Option<(Digest32, u64)>,
        state_charge: crate::node::history_budget::BufferCharge,
        slots: Arc<BodySlots>,
    ) -> Result<Self> {
        let request = request_id()?;
        let mut flow = Self {
            room,
            peer,
            node,
            epoch,
            instance: [0; 16],
            generation: [0; 32],
            shared,
            archive: false,
            inventory: hint.is_none() && required.is_none(),
            archive_request: None,
            _state_charge: state_charge,
            hint,
            waiting: false,
            published: false,
            rendered: false,
            governance: false,
            admitted_authors: 0,
            external: None,
            archive_status: None,
            tasks: Vec::new(),
            slots,
            owners: [None, None],
            busy_body: 0,
            live_context: Some(live),
            control_context: control,
            live: None,
            control: None,
            history: None,
            archive_wire_used: false,
            archive_next: None,
            request_fence: None,
            initialized: false,
        };
        if let Some((head, seq)) = required {
            flow.push(Task {
                request,
                purpose: Purpose::Control,
                operation: Operation::Local(LocalStep::Entry {
                    request,
                    head,
                    seq,
                    body: false,
                    phase: EntryPhase::Start,
                }),
            })?;
        } else if let Some(hint) = flow.hint {
            flow.push(Task {
                request,
                purpose: Purpose::Control,
                operation: Operation::Tail {
                    head: hint.head,
                    seq: hint.size,
                },
            })?;
            flow.push(Task {
                request,
                purpose: Purpose::Control,
                operation: Operation::Wire(Query::Head(hint.author)),
            })?;
        } else {
            flow.push(Task {
                request,
                purpose: Purpose::Control,
                operation: Operation::Wire(Query::Inventory),
            })?;
        }
        Ok(flow)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn archive(
        room: Digest32,
        peer: Digest32,
        node: Digest32,
        epoch: u64,
        instance: [u8; 16],
        generation: Digest32,
        shared: Arc<Mutex<ChannelState>>,
        control: Arc<Context>,
        staging: Staging,
        query: Query,
        request: RequestId,
        fence: Arc<Fence>,
        state_charge: crate::node::history_budget::BufferCharge,
        slots: Arc<BodySlots>,
    ) -> Self {
        Self {
            room,
            peer,
            node,
            epoch,
            instance,
            generation,
            shared,
            archive: true,
            inventory: false,
            archive_request: Some(request),
            _state_charge: state_charge,
            hint: None,
            waiting: false,
            published: false,
            rendered: false,
            governance: false,
            admitted_authors: 0,
            external: None,
            archive_status: None,
            slots,
            owners: [None, None],
            busy_body: 0,
            tasks: vec![Task {
                request,
                purpose: Purpose::History,
                operation: Operation::Wire(query),
            }],
            live_context: None,
            control_context: control,
            live: None,
            control: None,
            history: Some(staging),
            archive_wire_used: false,
            archive_next: None,
            request_fence: Some(fence),
            initialized: true,
        }
    }
    fn push(&mut self, task: Task) -> Result<()> {
        if self.tasks.len() >= MAX_TASKS {
            return Err(Error::SizeLimitExceeded("history dependency stack"));
        }
        self.tasks.push(task);
        Ok(())
    }
    pub(crate) fn needs_board(&self) -> bool {
        self.inventory && !self.initialized
    }
    pub(crate) fn done(&self) -> bool {
        self.tasks.is_empty()
    }
    pub(crate) fn lane(&self) -> crate::node::history_budget::Lane {
        use crate::node::history_budget::Lane;
        match self
            .tasks
            .last()
            .map(|task| (&task.operation, task.purpose))
        {
            Some((Operation::Wire(Query::Entry { .. } | Query::Page { .. }), Purpose::History)) => {
                Lane::Archive
            }
            Some((_, Purpose::Live)) => Lane::Live,
            _ => Lane::Control,
        }
    }
    pub(crate) fn cancel(&self) {
        for (index, owner) in self.owners.iter().enumerate() {
            if let Some(request) = owner {
                self.slots.release(
                    if index == 0 {
                        Purpose::Live
                    } else {
                        Purpose::Control
                    },
                    *request,
                );
            }
        }

        if let Some(context) = &self.live_context {
            context.cancellation().cancel();
        }
        self.control_context.cancellation().cancel();
        if let Some(staging) = &self.history {
            staging.context.cancellation().cancel();
        }
    }
    fn stage(&self, purpose: Purpose) -> Option<Staging> {
        match purpose {
            Purpose::Live => self.live.clone(),
            Purpose::Control => self.control.clone(),
            Purpose::History => self.history.clone(),
        }
    }
    fn receiver(
        &self,
        store: Arc<Store>,
        purpose: Purpose,
        fence: Arc<Fence>,
        deadline: tokio::time::Instant,
    ) -> Receiver {
        Receiver::new(
            self.shared.clone(),
            store,
            self.peer,
            self.epoch,
            self.generation,
            self.node,
            self.stage(purpose),
            fence,
            deadline,
        )
    }
    fn binding(&self) -> Binding {
        Binding {
            room: self.room,
            instance: self.instance,
            epoch: self.epoch,
            audience: self.node,
            grant: self.generation,
        }
    }

    /// Exactly one local slice or one response quantum. The caller retains its worker/port slot
    /// through this return, including every spawned blocking worker, even after cancellation.
    pub(crate) async fn turn(
        &mut self,
        store: Arc<Store>,
        conn: &VoxConnection,
        job: &Job,
        fence: Arc<Fence>,
        deadline: tokio::time::Instant,
        inbox: &super::HintInbox,
        inbox_generation: u64,
        now: u64,
    ) -> Result<()> {
        self.waiting = false;
        self.external = None;
        let source = Source::new(
            self.shared.clone(),
            store.clone(),
            self.epoch,
            self.peer,
            fence.clone(),
            deadline,
        );
        if !self.initialized {
            let room = self.room;
            let node = self.node;
            let epoch = self.epoch;
            let value = source
                .read(job, 128, move |channel, store| {
                    let instance = channel.history_instance(store)?;
                    let generation =
                        super::authorization_generation(store, node, room, instance, epoch)?;
                    Ok(Some((instance, generation)))
                })
                .await?;
            let Lookup::Found(value) = value else {
                self.waiting = true;
                return Ok(());
            };
            (self.instance, self.generation) = value.value;
            self.initialized = true;
            return Ok(());
        }
        let Some(task) = self.tasks.pop() else {
            return Ok(());
        };
        let receiver = self.receiver(store.clone(), task.purpose, fence.clone(), deadline);
        match task.operation.clone() {
            Operation::Tail { head, seq } => {
                let found = source
                    .read(job, 128, move |room, store| {
                        let input = room.history_read(store)?;
                        let entry = input.history_pending_header(&head, seq)?;
                        Ok(entry.and_then(|entry| entry.skeleton.v2.map(|v2| v2.kind)))
                    })
                    .await?;
                match found {
                    Lookup::Found(value) => {
                        let content = value.value == crate::log::history::SignedEntryKind::Content;
                        self.push(Task {
                            request: task.request,
                            purpose: if content {
                                Purpose::Live
                            } else {
                                Purpose::Control
                            },
                            operation: Operation::Local(LocalStep::Entry {
                                request: task.request,
                                head,
                                seq,
                                body: content,
                                phase: EntryPhase::Start,
                            }),
                        })?;
                    }
                    Lookup::Missing => {
                        self.push(task.clone())?;
                        self.push(Task {
                            request: task.request,
                            purpose: Purpose::Control,
                            operation: Operation::Wire(Query::Header { head, seq }),
                        })?;
                    }
                    Lookup::Busy => {
                        self.push(task)?;
                        self.waiting = true;
                    }
                }
            }
            Operation::Wire(mut query) => {
                let body = matches!(query, Query::Entry { .. } | Query::Page { .. });
                if task.purpose == Purpose::History && body && self.archive_wire_used {
                    self.finish_archive(job).await?;
                    self.tasks.clear();
                    return Ok(());
                }
                if let Query::Entry { head, seq, .. } = query {
                    if task.purpose != Purpose::History {
                        if !self
                            .ensure_stage(task.purpose, task.request, head, seq, job)
                            .await?
                        {
                            self.push(task)?;
                            self.waiting = true;
                            return Ok(());
                        }
                        let staging = self
                            .stage(task.purpose)
                            .ok_or(Error::Profile("current history staging missing"))?;
                        let snapshot = inspect(&staging.context, job).await?;
                        let snapshot =
                            snapshot.ok_or(Error::Profile("current history operation missing"))?;
                        let offset = snapshot.state().body.as_ref().map_or(0, |body| body.offset);
                        query = Query::Entry { head, seq, offset };
                    }
                }
                let receiver = self.receiver(store.clone(), task.purpose, fence.clone(), deadline);
                let wire_request = if body {
                    self.stage(task.purpose)
                        .map(|s| {
                            s.active
                                .lock()
                                .map(|a| a.request())
                                .map_err(|_| Error::Profile("history activation lock failed"))
                        })
                        .transpose()?
                        .unwrap_or(task.request)
                } else {
                    task.request
                };
                if task.purpose == Purpose::History && body {
                    self.archive_wire_used = true;
                }
                let result = super::exchange(
                    &receiver,
                    conn,
                    job.clone(),
                    Preamble {
                        room: self.room,
                        epoch: self.epoch,
                        purpose: task.purpose,
                        request: wire_request,
                    },
                    query.clone(),
                    fence,
                    deadline,
                )
                .await?;
                // Inventory is a hint. The first signed Head(author) response selects the
                // exact live tail before any entry/body work; a concurrent post may replace
                // the hinted head. Never retarget an already selected dependency or proof.
                if let Query::Head(author) = query {
                    for head in &result.heads {
                        if head.author == author
                            && self.hint.is_some_and(|hint| hint.author == author)
                        {
                            for pending in &mut self.tasks {
                                if matches!(pending.operation, Operation::Tail { .. }) {
                                    pending.operation = Operation::Tail {
                                        head: head.head,
                                        seq: head.size,
                                    };
                                }
                            }
                        }
                    }
                }
                if let Some(inventory) = result.inventory {
                    for page in inventory.hints.chunks(64) {
                        source
                            .offer_inventory(job, inbox, inbox_generation, self.room, page)
                            .await?;
                    }
                }
                if matches!(result.status, Status::BodyNotHeld | Status::Cancelled) {
                    if self.archive && body {
                        self.finish_archive(job).await?;
                        self.tasks.clear();
                        return Ok(());
                    }
                    return Err(Error::Unreachable(
                        "selected current body is unavailable or cancelled",
                    ));
                }
                if result.status == Status::EvidenceUnavailable && !self.archive {
                    return Err(Error::Unreachable(
                        "required current evidence is unavailable",
                    ));
                }
                if body && task.purpose != Purpose::History && result.status == Status::Busy {
                    self.busy_body = self.busy_body.saturating_add(1);
                    if self.busy_body >= 3 {
                        return Err(Error::Unreachable(
                            "current body repeatedly busy; yielding its slot",
                        ));
                    }
                } else if body {
                    self.busy_body = 0;
                }
                if matches!(result.status, Status::Busy | Status::EvidenceUnavailable) {
                    if self.archive && body {
                        self.finish_archive(job).await?;
                        self.tasks.clear();
                    } else {
                        self.push(task)?;
                        self.waiting = true;
                    }
                    return Ok(());
                }
                if self.archive && body {
                    if result.body_ready.is_none() {
                        // The one requested quantum ended. Its exact body/page continuation is
                        // already durable; only a new explicit Resume may request more bytes.
                        self.finish_archive(job).await?;
                        self.tasks.clear();
                        return Ok(());
                    }
                    let staging = self
                        .history
                        .as_ref()
                        .ok_or(Error::Profile("archive staging missing"))?;
                    let state = inspect(&staging.context, job)
                        .await?
                        .ok_or(Error::Profile("archive state missing"))?;
                    if let Some(body) = &state.state().body {
                        self.archive_next = body.seq.checked_add(1);
                        self.push(Task {
                            request: wire_request,
                            purpose: Purpose::History,
                            operation: Operation::Local(LocalStep::Entry {
                                request: wire_request,
                                head: state.state().bounds.head,
                                seq: body.seq,
                                body: true,
                                phase: EntryPhase::Start,
                            }),
                        })?;
                    }
                }
                for query in result.needs.into_iter().rev() {
                    self.push(Task {
                        request: task.request,
                        purpose: Purpose::Control,
                        operation: Operation::Wire(query),
                    })?;
                }
                for binding in result.verifiers.into_iter().rev() {
                    self.push(Task {
                        request: binding.request,
                        purpose: Purpose::Control,
                        operation: Operation::Local(LocalStep::Verify(binding)),
                    })?;
                }
            }
            Operation::Local(step) => {
                let result = receiver.local_step(job, step, crate::time::Ms(now)).await?;
                if let Some(next) = result.next {
                    self.push(Task {
                        operation: Operation::Local(next),
                        ..task.clone()
                    })?;
                }
                if result.busy {
                    self.waiting = true;
                    return Ok(());
                }
                if result.published.is_some() {
                    self.published = true;
                    self.rendered |= result.rendered;
                    self.governance |= result.governance;
                    if self.stage(task.purpose).is_some() {
                        self.push(Task {
                            operation: Operation::Reclaim(task.purpose),
                            ..task.clone()
                        })?;
                    }
                }
                match result.need {
                    Some(LocalNeed::Wire(query)) => {
                        let purpose = if matches!(query, Query::Entry { .. }) {
                            task.purpose
                        } else {
                            Purpose::Control
                        };
                        self.push(Task {
                            request: task.request,
                            purpose,
                            operation: Operation::Wire(query),
                        })?;
                    }
                    Some(LocalNeed::StagedBody) => {
                        let LocalStep::Entry { head, seq, .. } = step else {
                            return Err(Error::MalformedAtRest("body dependency has no entry"));
                        };
                        if task.purpose == Purpose::History {
                            self.finish_archive(job).await?;
                            self.tasks.clear();
                        } else {
                            self.push(Task {
                                operation: Operation::Wire(Query::Entry {
                                    head,
                                    seq,
                                    offset: 0,
                                }),
                                ..task
                            })?;
                        }
                    }
                    Some(LocalNeed::Entry { head, seq }) if self.archive => {
                        self.external = Some((head, seq));
                        self.waiting = true;
                    }
                    Some(LocalNeed::Entry { head, seq }) => {
                        let request = request_id()?;
                        self.push(Task {
                            request,
                            purpose: Purpose::Control,
                            operation: Operation::Local(LocalStep::Entry {
                                request,
                                head,
                                seq,
                                body: false,
                                phase: EntryPhase::Start,
                            }),
                        })?;
                    }
                    Some(LocalNeed::Control {
                        head,
                        through,
                        effects,
                    }) => {
                        self.push(Task {
                            request: task.request,
                            purpose: Purpose::Control,
                            operation: Operation::Local(LocalStep::Control {
                                head,
                                through,
                                effects,
                            }),
                        })?;
                    }
                    Some(LocalNeed::Governance) => self.push(Task {
                        operation: Operation::Governance,
                        ..task
                    })?,
                    None => {}
                }
            }
            Operation::Reclaim(purpose) => {
                if !self.reclaim_stage(purpose, job).await? {
                    self.push(task)?;
                } else if self.archive && self.tasks.is_empty() {
                    self.finish_archive(job).await?;
                }
            }
            Operation::Governance => {
                let generation = self.generation;
                let node = self.node;
                let instance = self.instance;
                let room = self.room;
                let epoch = self.epoch;
                let advanced = source
                    .read(job, 128, move |channel, store| {
                        if super::authorization_generation(store, node, room, instance, epoch)?
                            != generation
                        {
                            return Err(Error::Profile("history authorization changed"));
                        }
                        channel
                            .advance_governance(store, crate::time::Ms(now))
                            .map(|_| Some(()))
                    })
                    .await?;
                if !matches!(advanced, Lookup::Found(_)) {
                    self.push(task)?;
                    self.waiting = true;
                }
            }
        }
        Ok(())
    }
    async fn ensure_stage(
        &mut self,
        purpose: Purpose,
        request: RequestId,
        head: Digest32,
        seq: u64,
        job: &Job,
    ) -> Result<bool> {
        if !self.slots.claim(purpose, request) {
            return Ok(false);
        }
        if let Some(index) = body_slot(purpose) {
            self.owners[index] = Some(request);
        }
        if let Some(staging) = self.stage(purpose) {
            let snapshot = inspect(&staging.context, job)
                .await?
                .ok_or(Error::Profile("current history state missing"))?;
            if snapshot.state().bounds.head == head && snapshot.state().bounds.lo == seq {
                return Ok(true);
            }
            return Err(Error::Profile("current body slot belongs to another entry"));
        }
        let context = match purpose {
            Purpose::Live => self
                .live_context
                .clone()
                .ok_or(Error::Profile("live context missing"))?,
            Purpose::Control => self.control_context.clone(),
            Purpose::History => return Err(Error::Profile("archive activation missing")),
        };
        let binding = self.binding();
        let job = job.clone();
        let context_work = context.clone();
        let active = tokio::task::spawn_blocking(move || {
            if let Some(previous) = demand::inspect(&context_work, &job)? {
                let request = previous.state().request;
                if !matches!(
                    previous.state().progress(None),
                    demand::Progress::Complete | demand::Progress::Cancelled
                ) {
                    demand::cancel(&context_work, request, &job)?;
                }
                if !demand::reclaim(&context_work, request, &job)? {
                    return Ok(None);
                }
            }
            demand::start(
                &context_work,
                request,
                binding,
                Bounds {
                    head,
                    lo: seq,
                    hi: seq,
                    entries: 1,
                },
                &job,
            )
            .map(Some)
        })
        .await
        .map_err(|_| Error::Profile("current history staging worker stopped"))??;
        let Some(active) = active else {
            return Ok(false);
        };
        let staging = Staging {
            context,
            active: Arc::new(StdMutex::new(active)),
        };
        match purpose {
            Purpose::Live => self.live = Some(staging),
            Purpose::Control => self.control = Some(staging),
            Purpose::History => unreachable!(),
        };
        Ok(true)
    }
    async fn reclaim_stage(&mut self, purpose: Purpose, job: &Job) -> Result<bool> {
        let Some(staging) = self.stage(purpose) else {
            return Ok(true);
        };
        let job = job.clone();
        let complete = tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut active = staging
                .active
                .lock()
                .map_err(|_| Error::Profile("history activation lock failed"))?;
            if !demand::reclaim(&staging.context, active.request(), &job)? {
                return Ok(false);
            }
            if purpose != Purpose::History {
                demand::checkpoint(
                    &staging.context,
                    &mut active,
                    demand::Progress::Complete,
                    None,
                    &job,
                )?;
            }
            Ok(true)
        })
        .await
        .map_err(|_| Error::Profile("history reclamation worker stopped"))??;
        if complete {
            if let Some(index) = body_slot(purpose) {
                if let Some(request) = self.owners[index].take() {
                    self.slots.release(purpose, request);
                }
            }
            match purpose {
                Purpose::Live => self.live = None,
                Purpose::Control => self.control = None,
                Purpose::History => {}
            }
        }
        Ok(complete)
    }
    async fn finish_archive(&mut self, job: &Job) -> Result<()> {
        let Some(staging) = self.history.clone() else {
            return Ok(());
        };
        let job = job.clone();
        let next = self.archive_next;
        self.archive_status = Some(
            tokio::task::spawn_blocking(
                move || -> Result<crate::node::api::HistoryDemandStatus> {
                    let mut snapshot = demand::inspect(&staging.context, &job)?
                        .ok_or(Error::Profile("archive state missing"))?;
                    let mut active = staging
                        .active
                        .lock()
                        .map_err(|_| Error::Profile("history activation lock failed"))?;
                    if snapshot.state().body.is_none() && !snapshot.state().reclaiming() {
                        if let Some(next) = next {
                            let state = snapshot.state();
                            let cursor = (next <= state.bounds.hi && state.remaining > 0)
                                .then_some(super::Continuation {
                                    query_kind: 4,
                                    head: state.bounds.head,
                                    lo: state.bounds.lo,
                                    hi: state.bounds.hi,
                                    next_seq: next,
                                    entry: None,
                                    offset: 0,
                                    entries_remaining: state.remaining,
                                });
                            demand::checkpoint(
                                &staging.context,
                                &mut active,
                                if cursor.is_some() {
                                    demand::Progress::More
                                } else {
                                    demand::Progress::Complete
                                },
                                cursor.as_ref(),
                                &job,
                            )?;
                            snapshot = demand::inspect(&staging.context, &job)?
                                .ok_or(Error::Profile("archive state missing"))?;
                        }
                    }
                    if snapshot.state().progress(Some(&active)) == demand::Progress::Pending {
                        // This explicit quantum has ended; no worker will silently retry it.
                        // Keep its exact body/cursor and make Resume the next action.
                        demand::pause(&staging.context, &mut active, &job)?;
                        snapshot = demand::inspect(&staging.context, &job)?
                            .ok_or(Error::Profile("archive state missing"))?;
                    }
                    Ok(crate::node::actor::saved_history_status(
                        snapshot.state(),
                        None,
                        Some(&active),
                    ))
                },
            )
            .await
            .map_err(|_| Error::Profile("history status worker stopped"))??,
        );
        Ok(())
    }
}
impl Drop for Flow {
    fn drop(&mut self) {
        self.cancel();
    }
}

async fn inspect(context: &Arc<Context>, job: &Job) -> Result<Option<demand::Snapshot>> {
    let context = context.clone();
    let job = job.clone();
    tokio::task::spawn_blocking(move || demand::inspect(&context, &job))
        .await
        .map_err(|_| Error::Profile("history inspect worker stopped"))?
}
fn request_id() -> Result<RequestId> {
    crate::identity::rng::random_array::<16>()
}
