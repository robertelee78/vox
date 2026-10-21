//! One bounded outgoing work slice. The actor owns scheduling; this state contains only
//! bounded cursors and the three existing staging capabilities, never a retained entry body.

use super::source::{Lookup, Source};
use super::{
    EntryPhase, LocalNeed, LocalProof, LocalStep, Preamble, Purpose, Query, Receiver, RequestId,
    Staging, Status,
};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::channel::entry_store::sparse::LiveWindow;
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
    LiveWindow {
        author: Digest32,
        head: Digest32,
    },
    LiveAdvance {
        author: Digest32,
        target: Digest32,
        window: LiveWindow,
        retry: bool,
    },
    LiveRetry {
        author: Digest32,
        window: LiveWindow,
    },
    Tail {
        head: Digest32,
        seq: u64,
    },
    Wire(Query),
    LocalProof(Query),
    Local(LocalStep),
    Reclaim(Purpose),
    ReclaimUnavailable,
    Governance,
}
/// How long one turn keeps running local slices before it yields to the actor.
const LOCAL_TURN_BUDGET: std::time::Duration = std::time::Duration::from_millis(20);
/// How many local slices one turn runs at most.
const LOCAL_SLICES_PER_TURN: u32 = 64;
/// Fold steps an entry slice may take in one turn before it waits for the actor's fold hook
/// (ADR-037 R11): a hold on the fold cycled the need 32 times a turn, 77 turns a second.
const GOVERNANCE_STEPS_PER_TURN: u8 = 4;
/// The body bytes one explicit history quantum fetches at most; past it the request pauses and
/// `vox room read --history resume` asks for the rest.
const ARCHIVE_QUANTUM_BYTES: u64 = 1024 * 1024;
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
    /// This node has a key delivery to the peer waiting on its prekey bundle (ADR-038 FX-35):
    /// the round reads the peer's board whatever kind of flow this is, until the bundle is
    /// held. Set by the actor at each start from the fact `vox status` reports as `key_waits`.
    pub(crate) wants_board: bool,
    departure_probe: bool,
    pub(crate) archive_request: Option<RequestId>,
    pub(crate) hint: Option<super::HeadHint>,
    /// The advertising peer that owns `hint` in the inbox, even while one exact dependency is
    /// temporarily routed over its author's port.
    pub(crate) hint_peer: Digest32,
    /// Exact signed head selected for this hinted flow, not the inventory claim.
    pub(crate) authenticated_head: Option<super::HeadHint>,
    /// How far the peer said, in this round, it holds this node's own feed: its answer to
    /// the own-author head probe, or its inventory naming an own head this node accepted
    /// (ADR-028 R-6). The actor records it, and the settlement tick stops offering the own
    /// head to a peer that holds it (ADR-038 FX-15).
    pub(crate) mine_held: Option<u64>,
    /// Why this flow's rounds run (ADR-038 FX-15, #996), set when the actor selects it and
    /// kept across its slices; counted on the lane when a round completes.
    pub(crate) reason: crate::node::status::RoundReason,
    pub(crate) waiting: bool,
    pub(crate) published: bool,
    pub(crate) rendered: bool,
    pub(crate) governance: bool,
    /// An exchange of this flow fetched something this node did not hold (an object it saved,
    /// a body chunk, a hint it did not have): a completed flow that brought nothing is an
    /// `empty` round in `vox status --json` (ADR-038 FX-29).
    pub(crate) brought: bool,
    /// Exact unavailable advertised heads declined during this retained flow. The actor reports
    /// the outcome through the lane in `vox status --json`.
    pub(crate) declined: u64,
    pub(crate) admitted_authors: usize,
    pub(crate) external: Option<(Digest32, u64)>,
    pub(crate) archive_status: Option<crate::node::api::HistoryDemandStatus>,
    /// A healthy advertising peer did not retain the exact current wire dependency. The actor
    /// moves this same flow to the named author's port; no second root or volatile copy exists.
    pub(crate) reroute: Option<Digest32>,
    /// Original peer while the next exact wire dependency runs against its author.
    pub(crate) route_origin: Option<Digest32>,
    /// The routed wire response completed and the retained continuation must return to origin.
    pub(crate) route_complete: bool,
    /// A local trust edit invalidated this flow's grant. Retire it without blaming the peer;
    /// the controller re-arms its exact scalar hint under the new generation.
    pub(crate) authorization_changed: bool,
    tasks: Vec<Task>,
    // One exact suspended foreground root. Intermediate pre-body continuations
    // are re-derived from durable receipts after the current dependency finishes.
    replay: Option<Task>,
    slots: Arc<BodySlots>,
    owners: [Option<RequestId>; 2],
    /// A durable body chunk moved in this flow's last turn: the waiting slice is
    /// progress, not a busy wait, and its port must not grow a Busy backoff.
    pub(crate) body_progress: bool,
    /// This turn's slice waits on the room's governance fold, which is not ready yet (ADR-037
    /// R2): a local wait, not a body slot held against a busy peer, so it never retires the slot,
    /// and the actor's fold hook is asked to drive the fold.
    pub(crate) governance_wait: bool,
    governance_cycles: u8,
    last_head: Option<super::HeadHint>,
    /// Immutable identity of this cleanup obligation. `request` changes as continuations are
    /// derived; retirement ownership must not.
    retirement_request: RequestId,
    request: RequestId,
    cleanup_store: Arc<Store>,
    cleanup_budget: Arc<crate::node::history_budget::Budget>,
    actor_incarnation: Option<u64>,
    cleanup_after: Option<[u8; 64]>,
    live_context: Option<Arc<Context>>,
    control_context: Arc<Context>,
    live: Option<Staging>,
    control: Option<Staging>,
    history: Option<Staging>,
    /// Body bytes this explicit history quantum has fetched so far (ADR-036: one bounded ask).
    archive_wire_bytes: u64,
    archive_next: Option<u64>,
    pub(crate) request_fence: Option<Arc<Fence>>,
    initialized: bool,
    live_unavailable: Option<(Digest32, u64)>,
    // One hinted flow either advances the main window or retries missing newest positions.
    // A peer's BodyNotHeld never rewinds the main cursor or suppresses another peer's retry.
    live_visited: bool,
    // Exact head whose independent control closure is already retained by this flow. A later
    // authenticated successor schedules its own closure without mutating the in-flight work.
    control_head: Option<Digest32>,
    // Declared last: actual state/capabilities die before the shared admission is returned.
    // `None` while the flow is parked (ADR-038 FX-35): a flow that is not running holds no
    // daemon-wide flow state; [`Flow::resume`] reserves it again before a round.
    state_charge: Option<crate::node::history_budget::FlowStateCharge>,
}
// The retained-flow permit includes the exact Vec allocation, the scalar replay root,
// and conservative room for the one-object receiver handoff and small staging handles.
// Dependency depth cannot increase this allocation: pre-body ancestry is replayed above.
const _: () = assert!(
    std::mem::size_of::<Flow>() + MAX_TASKS * std::mem::size_of::<Task>() + 4096
        <= crate::node::history_budget::FLOW_STATE_BYTES
);
/// What [`Flow::resume`] came to (ADR-038 FX-35).
pub(crate) enum Resumed {
    /// The round holds its flow state.
    Held,
    /// Every pool position is occupied by a running charge or earlier release-edge promise. The
    /// exact flow remains parked until a charge release wakes it.
    PoolFull(crate::node::history_budget::FlowReleaseEdge),
    /// Pool accounting already exceeds its limit; exact equality is reserved for `PoolFull`.
    PoolOvercommitted(crate::node::history_budget::FlowReleaseEdge),
    /// The current and retiring actor generations already occupy this fingerprint's two shared
    /// running slots. Exact charge release, not a tick, wakes the retained round.
    NodeBusy(crate::node::history_budget::FlowReleaseEdge),
    /// The admitted worker's actor generation no longer owns pool capacity.
    OwnerMissing,
}

impl Flow {
    pub(crate) fn root_name(&self) -> &'static str {
        if self.archive {
            "archive"
        } else if self.hint.is_some() {
            "hint"
        } else if self.departure_probe {
            "departure"
        } else if self.inventory {
            "inventory"
        } else {
            "required"
        }
    }

    pub(crate) fn retirement_request(&self) -> RequestId {
        self.retirement_request
    }

    pub(crate) fn actor_incarnation(&self) -> Option<u64> {
        self.actor_incarnation
    }

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
        departure_probe: bool,
        required: Option<(Digest32, u64)>,
        slots: Arc<BodySlots>,
        cleanup_store: Arc<Store>,
        cleanup_budget: Arc<crate::node::history_budget::Budget>,
        actor_incarnation: Option<u64>,
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
            wants_board: false,
            departure_probe,
            archive_request: None,
            state_charge: None,
            hint,
            hint_peer: peer,
            authenticated_head: None,
            mine_held: None,
            reason: crate::node::status::RoundReason::Request,
            waiting: false,
            published: false,
            rendered: false,
            governance: false,
            brought: false,
            declined: 0,
            admitted_authors: 0,
            external: None,
            archive_status: None,
            reroute: None,
            route_origin: None,
            route_complete: false,
            authorization_changed: false,
            tasks: Vec::with_capacity(MAX_TASKS),
            replay: None,
            slots,
            owners: [None, None],
            body_progress: false,
            governance_wait: false,
            governance_cycles: 0,
            last_head: None,
            retirement_request: request,
            request,
            cleanup_store,
            cleanup_budget,
            actor_incarnation,
            cleanup_after: None,
            live_context: Some(live),
            control_context: control,
            live: None,
            control: None,
            history: None,
            archive_wire_bytes: 0,
            archive_next: None,
            request_fence: None,
            initialized: false,
            live_unavailable: None,
            live_visited: false,
            control_head: None,
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
                    role_header: false,
                    phase: EntryPhase::Start,
                }),
            })?;
        } else if let Some(hint) = flow.hint {
            if !departure_probe {
                flow.push(Task {
                    request,
                    purpose: Purpose::Control,
                    operation: Operation::LiveWindow {
                        author: hint.author,
                        head: hint.head,
                    },
                })?;
            }
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
        slots: Arc<BodySlots>,
        cleanup_store: Arc<Store>,
        cleanup_budget: Arc<crate::node::history_budget::Budget>,
        actor_incarnation: Option<u64>,
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
            wants_board: false,
            departure_probe: false,
            archive_request: Some(request),
            state_charge: None,
            hint: None,
            hint_peer: peer,
            authenticated_head: None,
            mine_held: None,
            reason: crate::node::status::RoundReason::Page,
            waiting: false,
            published: false,
            rendered: false,
            governance: false,
            brought: false,
            declined: 0,
            admitted_authors: 0,
            external: None,
            archive_status: None,
            reroute: None,
            route_origin: None,
            route_complete: false,
            authorization_changed: false,
            slots,
            owners: [None, None],
            body_progress: false,
            governance_wait: false,
            governance_cycles: 0,
            last_head: None,
            retirement_request: request,
            request,
            cleanup_store,
            cleanup_budget,
            actor_incarnation,
            cleanup_after: None,
            tasks: {
                let mut tasks = Vec::with_capacity(MAX_TASKS);
                tasks.push(Task {
                    request,
                    purpose: Purpose::History,
                    operation: Operation::Wire(query),
                });
                tasks
            },
            replay: None,
            live_context: None,
            control_context: control,
            live: None,
            control: None,
            history: Some(staging),
            archive_wire_bytes: 0,
            archive_next: None,
            request_fence: Some(fence),
            initialized: true,
            live_unavailable: None,
            live_visited: false,
            control_head: None,
        }
    }
    fn push(&mut self, task: Task) -> Result<()> {
        if self.tasks.len() >= MAX_TASKS {
            return Err(Error::SizeLimitExceeded("history dependency stack"));
        }
        self.tasks.push(task);
        Ok(())
    }
    /// Retain exact control closure above any ordinary-body work already on the LIFO stack.
    /// Source proof runs before effect application; a successor gets a distinct pair of tasks.
    fn push_control_closure(&mut self, task: &Task, window: LiveWindow) -> Result<()> {
        if window.through == 0 || self.control_head == Some(window.head) {
            return Ok(());
        }
        if self.tasks.len() > MAX_TASKS.saturating_sub(2) {
            return Err(Error::SizeLimitExceeded("history dependency stack"));
        }
        self.tasks.push(Task {
            operation: Operation::Local(LocalStep::Control {
                head: window.head,
                through: window.through,
                effects: true,
            }),
            ..task.clone()
        });
        self.tasks.push(Task {
            operation: Operation::Local(LocalStep::Control {
                head: window.head,
                through: window.through,
                effects: false,
            }),
            ..task.clone()
        });
        self.control_head = Some(window.head);
        Ok(())
    }
    /// Park (ADR-038 FX-35): a flow that is ready but not running, deferred, retiring or
    /// awaiting cleanup holds none of the daemon's flow-state pool. Measured before this: four
    /// hosted nodes' parked hinted flows held all sixteen, and the inventory round that would
    /// have let them resume could never be started.
    pub(crate) fn park(&mut self) {
        self.state_charge = None;
    }

    /// The Control bytes one flow state costs, reserved on this flow's own control job before
    /// the pool is asked (ADR-038 FX-35): `None` is the control budget's refusal, never the
    /// pool's, and the caller names it so.
    pub(crate) fn reserve_state_bytes(
        &self,
        job: &Job,
    ) -> Option<crate::node::history_budget::BufferCharge> {
        job.reserve(crate::node::history_budget::FLOW_STATE_BYTES)
    }

    pub(crate) fn state_bytes_wake(
        job: &Job,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        job.bytes_wake()
    }

    /// Reserve the flow state as the round begins, its bytes already held: the last gate before
    /// running, so a held charge always belongs to a running round. [`Resumed::NodeBusy`] when
    /// this fingerprint's current and retiring generations already hold its source-owned slots;
    /// [`Resumed::PoolFull`] when every pool position is occupied by a charge or release-edge
    /// promise. A flow already holding its state keeps it, and the bytes go back.
    pub(crate) fn resume(
        &mut self,
        job: &Job,
        bytes: crate::node::history_budget::BufferCharge,
        waiter: Option<&mut crate::node::history_budget::FlowReleaseTicket>,
    ) -> Resumed {
        if self.state_charge.is_some() {
            return Resumed::Held;
        }
        match job.reserve_flow_state(
            self.room,
            self.peer,
            self.retirement_request,
            self.instance,
            bytes,
            waiter,
        ) {
            crate::node::history_budget::FlowStateTry::Reserved(charge) => {
                self.state_charge = Some(charge);
                Resumed::Held
            }
            crate::node::history_budget::FlowStateTry::PoolFull(edge) => Resumed::PoolFull(edge),
            crate::node::history_budget::FlowStateTry::PoolOvercommitted(edge) => {
                Resumed::PoolOvercommitted(edge)
            }
            crate::node::history_budget::FlowStateTry::NodeBusy(edge) => Resumed::NodeBusy(edge),
            crate::node::history_budget::FlowStateTry::OwnerMissing => Resumed::OwnerMissing,
        }
    }

    /// Whether this round begins by exchanging boards with the peer: a fresh inventory flow's
    /// first round, or any round while a key to the peer waits on its bundle (ADR-038 FX-35):
    /// the bundle a key delivery opens its session against travels only on that exchange.
    pub(crate) fn needs_board(&self) -> bool {
        (self.inventory && !self.initialized) || self.wants_board
    }
    /// The author of a retained signed head, for the record of a peer that could not fill a
    /// body under it; `None` when the head is not retained or the room is busy, and then no
    /// record is made (the next period asks once more).
    async fn head_author(
        &self,
        source: &super::source::Source,
        job: &Job,
        head: Digest32,
    ) -> Result<Option<Digest32>> {
        let found = source
            .read(
                job,
                std::mem::size_of::<Option<Digest32>>(),
                move |room, store| {
                    Ok(Some(
                        room.history_read(store)?
                            .history_head(&head)?
                            .map(|signed| signed.binding.author),
                    ))
                },
            )
            .await?;
        Ok(match found {
            Lookup::Found(found) => found.value,
            Lookup::Busy | Lookup::Missing => None,
        })
    }
    async fn decline(
        &mut self,
        source: &super::source::Source,
        job: &Job,
        inbox: &super::hints::HintInbox,
        author: Digest32,
        head: Digest32,
    ) -> Result<()> {
        let remembered = source.remember_decline(job, author, head).await?;
        inbox.decline(self.room, source.peer, author, head);
        self.declined = self.declined.saturating_add(u64::from(remembered));
        Ok(())
    }
    pub(crate) fn done(&self) -> bool {
        self.tasks.is_empty() && self.replay.is_none()
    }
    /// Whether the next task is a local slice, with no wire exchange, so this turn may run it.
    fn next_slice_is_local(&self) -> bool {
        let next = self.tasks.last().or(self.replay.as_ref());
        matches!(
            next.map(|task| &task.operation),
            Some(
                Operation::Local(_)
                    | Operation::LiveWindow { .. }
                    | Operation::LiveAdvance { .. }
                    | Operation::LiveRetry { .. }
                    | Operation::Tail { .. }
                    | Operation::Reclaim(_)
                    | Operation::ReclaimUnavailable
                    | Operation::Governance
            )
        )
    }
    pub(crate) fn lane(&self) -> crate::node::history_budget::Lane {
        use crate::node::history_budget::Lane;
        match self
            .tasks
            .last()
            .or(self.replay.as_ref())
            .map(|task| (&task.operation, task.purpose))
        {
            Some((Operation::Wire(Query::Entry { .. } | Query::Page { .. }), Purpose::History)) => {
                Lane::Archive
            }
            Some((_, Purpose::Live)) => Lane::Live,
            _ => Lane::Control,
        }
    }
    pub(crate) fn cancellation_handles(&self) -> Vec<demand::Cancellation> {
        let mut handles = Vec::with_capacity(3);
        if let Some(context) = &self.live_context {
            handles.push(context.cancellation());
        }
        handles.push(self.control_context.cancellation());
        if let Some(staging) = &self.history {
            handles.push(staging.context.cancellation());
        }
        handles
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

        for cancellation in self.cancellation_handles() {
            cancellation.cancel();
        }
    }
    /// The Controller owns this future and awaits it before dropping an abandoned flow.
    /// Each transaction is bounded; no transport or authority effect runs during retirement.
    pub(crate) async fn retire_slice(&mut self) -> Result<bool> {
        if !self.initialized {
            self.cancel();
            return Ok(true);
        }
        // A published current body queues only local exact-request reclamation. If its peer
        // departs before the next network turn, finish that bounded cleanup here; membership is
        // never restored and no archive, wire request or new effect is run.
        let reclaim_live = self.tasks.iter().any(|task| {
            matches!(
                task.operation,
                Operation::Reclaim(Purpose::Live) | Operation::ReclaimUnavailable
            )
        });
        let reclaim_control = self
            .tasks
            .iter()
            .any(|task| matches!(task.operation, Operation::Reclaim(Purpose::Control)));
        // A parked flow owns no worker. Retirement admits one independent large-control job for
        // this bounded local slice and gives it back before the flow is retained again.
        let cleanup_job = self
            .cleanup_budget
            .admit_job(self.node, crate::node::history_budget::Lane::LargeControl)
            .await;
        if reclaim_live
            && !self
                .reclaim_stage(Purpose::Live, &cleanup_job, true)
                .await?
        {
            return Ok(false);
        }
        if reclaim_control
            && !self
                .reclaim_stage(Purpose::Control, &cleanup_job, true)
                .await?
        {
            return Ok(false);
        }
        // No worker owns this Flow while it is retiring. Retain its already-fenced local
        // capability only through the exact queued reclamation above, then cancel it before
        // any general publication/verifier cleanup. Nothing here opens a stream or schedules
        // another turn.
        self.cancel();
        // Cleanup uses the independently admitted foreground-control envelope above; no parked
        // flow retains a Control worker merely so it can eventually retire.
        const CLEANUP_ENVELOPE: usize = 6 * 1024 * 1024;
        let Some(charge) = cleanup_job.reserve(CLEANUP_ENVELOPE) else {
            return Ok(false);
        };
        let room = self.shared.clone();
        let store = self.cleanup_store.clone();
        let request = self.request;
        let instance = self.instance;
        let after = self.cleanup_after;
        let step = tokio::task::spawn_blocking(move || {
            let _charge = charge;
            let mut channel = room.blocking_lock();
            // Lock erases keys immediately. Reopen owns the bounded crash cleanup;
            // no retired worker may keep/recreate an unlocked room to finish work.
            match channel.history_instance(&store) {
                Err(Error::AtRestLocked) => return Ok((true, None)),
                Err(error) => return Err(error),
                Ok(current) if current != instance => return Ok((true, None)),
                Ok(_) => {}
            }
            if !channel.cleanup_history_source_owned(&store, request)? {
                return Ok((false, after));
            }
            channel.cleanup_history_verifiers(&store, request, after)
        })
        .await
        .map_err(|_| Error::Profile("history retirement worker stopped"))??;
        self.cleanup_after = step.1;
        if !step.0 {
            return Ok(false);
        }

        // A foreground flow may suspend an older root while a freshly identified entry uses
        // another request ID. Retirement must clean both exact owners, without weakening the
        // demand replay guard or retaining another collection. The bounded task stack and scalar
        // replay root already hold every suspended continuation; the current scalar covers the
        // operation that was popped when an error interrupted it.
        self.cleanup_after = None;
        self.tasks.retain(|task| task.request != request);
        if self
            .replay
            .as_ref()
            .is_some_and(|task| task.request == request)
        {
            self.replay = None;
        }
        let next = self
            .tasks
            .last()
            .map(|task| task.request)
            .or_else(|| self.replay.as_ref().map(|task| task.request));
        if let Some(next) = next {
            self.request = next;
            Ok(false)
        } else {
            Ok(true)
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
            purpose == Purpose::History,
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

    /// Local slices back to back, or one response quantum (ADR-037 R11). The caller retains its
    /// worker/port slot through this return, including every spawned blocking worker, even after
    /// cancellation.
    #[allow(clippy::too_many_arguments)]
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
        self.body_progress = false;
        self.governance_wait = false;
        self.governance_cycles = 0;
        self.external = None;
        // Local slices run back to back inside one turn; a slice that needs the wire, waits,
        // errs or spends the slice budget ends it. Each slice used to be a turn of its own,
        // and a turn costs an actor round trip (~10 ms): one body took ~30 slices, so a
        // 128-position live window drained at three positions a second (40 s), and a creator
        // serving three joiners at once read their first posts after 30 s (#934).
        let started = tokio::time::Instant::now();
        let mut slices = 0u32;
        let result = loop {
            let result = self
                .turn_inner(
                    store.clone(),
                    conn,
                    job,
                    fence.clone(),
                    deadline,
                    inbox,
                    inbox_generation,
                    now,
                )
                .await;
            slices += 1;
            if result.is_err()
                || self.waiting
                || self.external.is_some()
                || slices >= LOCAL_SLICES_PER_TURN
                || started.elapsed() >= LOCAL_TURN_BUDGET
                || tokio::time::Instant::now() >= deadline
                || !self.next_slice_is_local()
            {
                break result;
            }
        };
        if result.as_ref().is_err_and(|error| {
            matches!(
                error,
                Error::Profile(
                    "history authorization changed"
                        | "history authorization changed before publication"
                        | "live window authorization changed"
                        | "live retry authorization changed"
                )
            )
        }) {
            self.authorization_changed = true;
            return Ok(());
        }
        // Busy is a retained exact need. A count of turns can neither revoke the body slot nor
        // dispose its root; the semantic response/progress edge is the only thing that advances
        // it, while the actor's named Busy backoff prevents spinning between those edges.
        result
    }

    // One bounded turn uses the same stream, job, hint inbox and deadline throughout.
    #[allow(clippy::too_many_arguments)]
    async fn turn_inner(
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
        if self.tasks.is_empty() {
            if let Some(root) = self.replay.take() {
                self.tasks.push(root);
            }
        }
        let Some(task) = self.tasks.pop() else {
            return Ok(());
        };
        // Retirement's scalar always names the operation that can disappear from the bounded
        // stack while this fallible turn executes. Suspended owners remain in tasks/replay.
        if !self.archive {
            self.request = task.request;
        }
        let receiver = self.receiver(store.clone(), task.purpose, fence.clone(), deadline);
        match task.operation.clone() {
            Operation::LiveWindow { author, head } => {
                if author == self.node {
                    // This node's own log needs no window: every position is held, and a
                    // peer holding more of it is the own-history conflict the detector stops
                    // the node on (ADR-037 R5), not something to fetch. The authenticated head
                    // still settles the join. Measured before this: a creator walked her own
                    // 10-entry log through a joiner's port for 8 s, 103 rounds, while two
                    // other joiners' first posts waited behind it.
                    let found = source
                        .read(job, 256, move |channel, store| {
                            let input = channel.history_read(store)?;
                            Ok(input
                                .history_head(&head)?
                                .filter(|signed| signed.binding.author == author)
                                .map(|signed| signed.root.leaves))
                        })
                        .await?;
                    match found {
                        Lookup::Found(found) => {
                            self.authenticated_head = Some(super::HeadHint {
                                author,
                                head,
                                size: found.value,
                            });
                        }
                        Lookup::Busy => {
                            self.push(task)?;
                            self.waiting = true;
                        }
                        Lookup::Missing => {}
                    }
                    return Ok(());
                }
                let instance = self.instance;
                let generation = self.generation;
                let node = self.node;
                let room = self.room;
                let epoch = self.epoch;
                let found = source
                    .read(job, 256, move |channel, store| {
                        if channel.history_instance(store)? != instance
                            || super::authorization_generation(store, node, room, instance, epoch)?
                                != generation
                        {
                            return Err(Error::Profile("live window authorization changed"));
                        }
                        if channel.history_publication_busy(store)? {
                            return Ok(None);
                        }
                        let input = channel.history_read(store)?;
                        let target = input
                            .history_head(&head)?
                            .ok_or(Error::MalformedAtRest("live window head missing"))?;
                        if target.binding.author != author
                            || target.binding.scope != crate::log::history::LogScope::Public
                        {
                            return Err(Error::MalformedAtRest("live window head binding differs"));
                        }
                        let state = input
                            .sparse_author(&author, crate::log::history::LogScope::Public)?
                            .ok_or(Error::MalformedAtRest("live window author missing"))?;
                        if state.observed_conflict.is_some() {
                            return Err(Error::MalformedBundle(
                                "live window author has conflicting heads",
                            ));
                        }
                        // A head no newer than the window's top resumes it. A newer head
                        // selects a new window at once, even over an unfinished one: fresh
                        // messages never wait for old bodies (ADR-036; the decider, #934), and
                        // the selector keeps the unfinished positions inside the new window,
                        // walked newest first after the fresh ones, held positions passing
                        // locally. Measured before this: a joiner read the creator's next post
                        // only when his drain of her 150-post window ended, 51–59 s on.
                        if let Some(window) = state.live {
                            if window.through >= target.root.leaves {
                                return Ok(Some((window, target.root.leaves)));
                            }
                        }
                        let through = target.root.leaves;
                        drop(input);
                        channel
                            .history_write(store, |index| {
                                index.select_history_live_window(&author, head)
                            })
                            .map(|window| Some((window, through)))
                    })
                    .await?;
                let Lookup::Found(found) = found else {
                    self.push(task)?;
                    self.waiting = true;
                    return Ok(());
                };
                let (window, target_through) = found.value;
                // Report the exact authenticated Head(author) response that selected this
                // operation, not a newer locally retained window that may supersede it. Join
                // settlement must never turn an older peer echo into acknowledgement of the
                // current own head.
                self.authenticated_head = Some(super::HeadHint {
                    author,
                    head,
                    size: target_through,
                });
                if !window.complete() {
                    self.live_visited = true;
                    // Each staged body needs a fresh demand ID, even though its enclosing
                    // live window is unchanged. The previous position has released both
                    // body slots and finished its verifier work before this operation runs.
                    let request = request_id()?;
                    self.request = request;
                    self.push(Task {
                        request,
                        operation: Operation::LiveAdvance {
                            author,
                            target: head,
                            window,
                            retry: false,
                        },
                        ..task.clone()
                    })?;
                    self.push(Task {
                        request,
                        operation: Operation::Tail {
                            head: window.head,
                            seq: window.next,
                        },
                        ..task.clone()
                    })?;
                } else {
                    if !self.live_visited {
                        self.live_visited = true;
                        // This is a peer-local retry pass over only the authenticated peer's
                        // newest window. It changes neither the durable main cursor nor the
                        // missing-position fact until normal body admission fills that fact.
                        // Retain it below the exact-head control work on this LIFO stack: omitted
                        // ordinary bodies are best-effort live recovery and cannot delay Session
                        // authorization. Any addressed key-package in the same window is a
                        // control dependency and is fetched by that work before the retry begins.
                        self.push(Task {
                            operation: Operation::LiveRetry {
                                author,
                                window: LiveWindow {
                                    head,
                                    from: target_through
                                        .saturating_sub(
                                            crate::log::history::MAX_PAGE_ENTRIES as u64 - 1,
                                        )
                                        .max(1),
                                    next: target_through,
                                    through: target_through,
                                },
                            },
                            ..task.clone()
                        })?;
                    }
                }
                // Head commitment independently authorizes bounded control closure. Run it above
                // the ordinary-body work just retained on this LIFO stack, so governance,
                // Session floors/support and addressed key delivery do not wait for 128 unrelated
                // Content bodies. Collapsed proof ranges fetch none of those omitted bodies.
                self.push_control_closure(&task, window)?;
            }
            Operation::LiveRetry { author, window } => {
                if window.complete() {
                    return Ok(());
                }
                let instance = self.instance;
                let generation = self.generation;
                let node = self.node;
                let room = self.room;
                let epoch = self.epoch;
                let found = source
                    .read(job, 128, move |channel, store| {
                        if channel.history_instance(store)? != instance
                            || super::authorization_generation(store, node, room, instance, epoch)?
                                != generation
                        {
                            return Err(Error::Profile("live retry authorization changed"));
                        }
                        let input = channel.history_read(store)?;
                        if input.publication_busy() {
                            return Ok(None);
                        }
                        Ok(Some(input.missing_contains(&author, window.next)?))
                    })
                    .await?;
                let Lookup::Found(found) = found else {
                    self.push(task)?;
                    self.waiting = true;
                    return Ok(());
                };
                if found.value {
                    let request = request_id()?;
                    self.request = request;
                    self.push(Task {
                        request,
                        operation: Operation::LiveAdvance {
                            author,
                            target: window.head,
                            window,
                            retry: true,
                        },
                        ..task.clone()
                    })?;
                    self.push(Task {
                        request,
                        operation: Operation::Tail {
                            head: window.head,
                            seq: window.next,
                        },
                        ..task
                    })?;
                } else {
                    self.push(Task {
                        operation: Operation::LiveRetry {
                            author,
                            window: LiveWindow {
                                next: window.next - 1,
                                ..window
                            },
                        },
                        ..task
                    })?;
                }
            }
            Operation::LiveAdvance {
                author,
                target,
                window,
                retry,
            } => {
                // A compacted root still owns its entry. Proof completion alone must not
                // move the window past a body whose admission has not finished.
                if let Some(root) = self.replay.take() {
                    self.push(task)?;
                    self.push(root)?;
                    return Ok(());
                }
                let instance = self.instance;
                let generation = self.generation;
                let node = self.node;
                let room = self.room;
                let epoch = self.epoch;
                let unavailable = self.live_unavailable == Some((window.head, window.next));
                let advanced = source
                    .read(job, 128, move |channel, store| {
                        if channel.history_instance(store)? != instance
                            || super::authorization_generation(store, node, room, instance, epoch)?
                                != generation
                        {
                            return Err(Error::Profile("live window authorization changed"));
                        }
                        let input = channel.history_read(store)?;
                        if input.publication_busy() {
                            return Ok(None);
                        }
                        let Some(header) = input.history_position_header(&author, window.next)?
                        else {
                            return Err(Error::MalformedAtRest(
                                "live window position was not published",
                            ));
                        };
                        let hash = header.entry_hash();
                        let content = header.skeleton.v2.as_ref().is_some_and(|v| {
                            v.kind == crate::log::history::SignedEntryKind::Content
                        });
                        let missing = unavailable
                            && content
                            && input.missing_contains(&author, window.next)?;
                        let finished = input.history_effect_finished(&hash)?;
                        let body = !content
                            || input.retention(&hash)?.is_some()
                            || channel
                                .body_expired(header.skeleton.claimed_ms, crate::time::Ms(now));
                        if !(missing || finished && body) {
                            return Err(Error::MalformedAtRest(
                                "live window position is not complete or explicitly missing",
                            ));
                        }
                        if retry {
                            return Ok(Some(true));
                        }
                        drop(input);
                        channel
                            .history_write(store, |index| {
                                index.advance_history_live_window(&author, window)
                            })
                            .map(Some)
                    })
                    .await?;
                if !matches!(advanced, Lookup::Found(_)) {
                    self.push(task)?;
                    self.waiting = true;
                    return Ok(());
                }
                self.live_unavailable = None;
                self.push(Task {
                    operation: if retry {
                        Operation::LiveRetry {
                            author,
                            window: LiveWindow {
                                next: window.next - 1,
                                ..window
                            },
                        }
                    } else {
                        Operation::LiveWindow {
                            author,
                            head: target,
                        }
                    },
                    ..task
                })?;
            }
            Operation::Tail { head, seq } => {
                let found = source
                    .read(job, 128, move |room, store| {
                        let input = room.history_read(store)?;
                        let Some(signed) = input.history_head(&head)? else {
                            return Ok(None);
                        };
                        let entry = input
                            .history_position_header(&signed.binding.author, seq)?
                            .or(input.history_pending_header(&head, seq)?);
                        let Some(entry) = entry else {
                            return Ok(None);
                        };
                        let Some(v2) = entry.skeleton.v2.as_ref() else {
                            return Ok(None);
                        };
                        let content = v2.kind == crate::log::history::SignedEntryKind::Content;
                        let expired = content
                            && room.body_expired(entry.skeleton.claimed_ms, crate::time::Ms(now));
                        let held = input.history_effect_finished(&entry.entry_hash())?
                            && (!content
                                || input.retention(&entry.entry_hash())?.is_some()
                                || expired);
                        Ok(Some((content, held, expired)))
                    })
                    .await?;
                match found {
                    Lookup::Found(value) => {
                        let (content, held, expired) = value.value;
                        if held {
                            return Ok(());
                        }
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
                                body: content && !expired,
                                role_header: false,
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
                if task.purpose == Purpose::History
                    && body
                    && self.archive_wire_bytes >= ARCHIVE_QUANTUM_BYTES
                {
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
                self.body_progress |= result.body_progress;
                self.brought |= result.brought || result.body_progress;
                if self.route_origin.is_some()
                    && !matches!(result.status, Status::Busy | Status::EvidenceUnavailable)
                {
                    self.route_complete = true;
                }
                if self.departure_probe {
                    // A stale/absent echo is not receipt. Keep the room and retry only this
                    // bounded head request through the existing port backoff.
                    if result.status != Status::Complete || result.departure_receipt != self.hint {
                        return Err(Error::Unreachable(
                            "peer has not acknowledged the current departure head",
                        ));
                    }
                    self.authenticated_head = result.departure_receipt;
                    return Ok(());
                }
                // Inventory is a hint. The first signed Head(author) response selects the
                // newest window before any entry/body work. The durable selector resumes an
                // unfinished window while live-eligible; aging retires demand, never saved
                // evidence. No hint retargets an in-progress entry dependency or proof.
                if let Query::Head(author) = query {
                    for head in &result.heads {
                        if head.author == author {
                            if author == self.node {
                                self.mine_held =
                                    Some(self.mine_held.map_or(head.size, |m| m.max(head.size)));
                            }
                            // A repeated signed head remains the peer's exact current answer.
                            // Busy handling below retains the dependency and applies the named
                            // port backoff; no count of identical answers may dispose its root.
                            self.last_head = Some(*head);
                        }
                        if head.author == author
                            && self.hint.is_some_and(|hint| hint.author == author)
                        {
                            let receipt = result.departure_receipt == Some(*head);
                            for pending in &mut self.tasks {
                                if matches!(pending.operation, Operation::LiveWindow { .. }) {
                                    pending.operation = Operation::LiveWindow {
                                        author,
                                        head: head.head,
                                    };
                                }
                            }
                            if receipt {
                                self.authenticated_head = Some(*head);
                                // Only a verified echo matching our already accepted departure.
                                // It must not request Header/Proof/Body from a peer we have left.
                                self.tasks.retain(|pending| {
                                    !matches!(pending.operation, Operation::LiveWindow { .. })
                                });
                            }
                        }
                    }
                }
                if let Some(inventory) = result.inventory {
                    for page in inventory.hints.chunks(64) {
                        let offered = source
                            .offer_inventory(job, inbox, inbox_generation, self.room, page)
                            .await?;
                        self.brought |= offered.added != 0;
                    }
                }
                if result.status == Status::BodyNotHeld && task.purpose == Purpose::Live {
                    let Query::Entry { head, seq, .. } = query else {
                        return Err(Error::MalformedBundle(
                            "live body refusal has no exact entry",
                        ));
                    };
                    // The peer does not hold a missing body of this author's newest window:
                    // an answer that says it cannot fill the hint. Its inventory's same head
                    // is not pulled from it again until it names another (ADR-038 FX-29), in
                    // a required flow as in a hinted one: an author whose missing bodies no
                    // peer held any more was pulled from every peer every period, about 370
                    // commits a sync, for bodies none of them had.
                    let author = self
                        .tasks
                        .iter()
                        .find_map(|pending| match pending.operation {
                            Operation::LiveAdvance { author, window, .. }
                                if window.head == head && window.next == seq =>
                            {
                                Some(author)
                            }
                            _ => None,
                        });
                    if let Some(author) = author {
                        self.decline(&source, job, inbox, author, head).await?;
                    }
                    if let Some(hint) = self.hint {
                        self.decline(&source, job, inbox, hint.author, hint.head)
                            .await?;
                    }
                    if !self.tasks.iter().any(|pending| matches!(pending.operation,
                        Operation::LiveAdvance { window, .. } if window.head == head && window.next == seq)) {
                        return Err(Error::MalformedBundle("live body refusal is outside the selected window"));
                    }
                    // Keep the authenticated header as a missing position, without applying
                    // a content effect or treating the peer's refusal as authenticated expiry.
                    // Busy, cancellation and transport failure never enter this path.
                    self.live_unavailable = Some((head, seq));
                    let is_entry = |pending: &Task| {
                        matches!(pending.operation,
                        Operation::Local(LocalStep::Entry { head: at, seq: position, .. }) if at == head && position == seq)
                    };
                    self.tasks.retain(|pending| !is_entry(pending));
                    if self.replay.as_ref().is_some_and(is_entry) {
                        self.replay = None;
                    }
                    self.push(Task {
                        operation: Operation::ReclaimUnavailable,
                        ..task.clone()
                    })?;
                    self.push(Task {
                        purpose: Purpose::Control,
                        operation: Operation::Local(LocalStep::Entry {
                            request: task.request,
                            head,
                            seq,
                            body: false,
                            role_header: false,
                            phase: EntryPhase::Start,
                        }),
                        ..task
                    })?;
                    return Ok(());
                }
                if matches!(result.status, Status::BodyNotHeld | Status::Cancelled) {
                    if self.archive && body {
                        self.finish_archive(job).await?;
                        self.tasks.clear();
                        return Ok(());
                    }
                    if result.status == Status::BodyNotHeld {
                        // The peer said it cannot fill this body: not asked for it again until
                        // its inventory names another head of the author (ADR-038 FX-29).
                        if let Query::Entry { head, .. } | Query::Page { head, .. } = &query {
                            let head = *head;
                            if let Some(author) = self.head_author(&source, job, head).await? {
                                self.decline(&source, job, inbox, author, head).await?;
                            }
                        }
                    }
                    return Err(Error::Unreachable(
                        "selected current body is unavailable or cancelled",
                    ));
                }
                if result.status == Status::EvidenceUnavailable && !self.archive {
                    if matches!(query, Query::Head(author) if (author == self.peer || author == self.node) && self.hint.is_some_and(|hint| hint.author == author))
                        && !self.departure_probe
                        && self.last_head.is_none()
                        && self.replay.is_none()
                    {
                        // Inventory is an unauthoritative scalar hint. A peer that no longer
                        // holds its initially named head, or has not yet completed our echo,
                        // retires only this hint. Neither is a transport failure, and backing off
                        // the healthy room/peer port can strand a later fresh head behind it.
                        // Third-party heads route to their author below; dependency failures
                        // after a head was selected remain hard failures.
                        // A peer that cannot serve the head it advertised, its own feed's or
                        // this node's own (the echo settlement asks for), is not asked for that
                        // hint again until its inventory names another head of the author
                        // (ADR-038 FX-29): the asking side stops, whatever the serving side does.
                        if let (Query::Head(author), Some(hint)) = (&query, self.hint) {
                            if hint.author == *author {
                                self.decline(&source, job, inbox, *author, hint.head)
                                    .await?;
                            }
                        }
                        self.tasks.clear();
                        return Ok(());
                    }
                    if !self.departure_probe {
                        let dependency = match query {
                            Query::Head(author) => self.hint.filter(|hint| hint.author == author),
                            Query::Header { head, .. }
                            | Query::Proof { head, .. }
                            | Query::Entry { head, .. }
                            | Query::Page { head, .. } => {
                                match source
                                    .read(
                                        job,
                                        std::mem::size_of::<Option<Digest32>>(),
                                        move |room, store| {
                                            Ok(Some(
                                                room.history_read(store)?.history_head(&head)?.map(
                                                    |signed| super::HeadHint {
                                                        author: signed.binding.author,
                                                        head,
                                                        size: signed.root.leaves,
                                                    },
                                                ),
                                            ))
                                        },
                                    )
                                    .await?
                                {
                                    Lookup::Found(found) => found.value,
                                    Lookup::Busy => {
                                        self.push(task)?;
                                        self.waiting = true;
                                        return Ok(());
                                    }
                                    Lookup::Missing => None,
                                }
                            }
                            Query::Inventory | Query::Context(_) => None,
                        };
                        // The peer said it cannot serve this header or proof: the hint that
                        // depends on it is not pulled from that peer again until its inventory
                        // names another head of the author (ADR-038 FX-29), whether the flow
                        // was hinted or required. The route to the author's port below still
                        // runs once for this exact query.
                        if let Some(dependency) = dependency {
                            self.decline(&source, job, inbox, dependency.author, dependency.head)
                                .await?;
                        }
                        if dependency.is_some_and(|head| {
                            head.author != self.peer && head.author != self.node
                        }) {
                            // Keep the exact refused query and its full continuation owned by
                            // this flow. The actor moves it to the dependency author's port for
                            // one wire turn, then returns the same flow to this advertising peer.
                            // No missing evidence is accepted and no whole-head surrogate can
                            // complete without satisfying this exact query.
                            self.push(task)?;
                            self.reroute = dependency.map(|head| head.author);
                            return Ok(());
                        }
                    }
                    return Err(Error::Unreachable(
                        "required current evidence is unavailable",
                    ));
                }
                if result.status == Status::Busy {
                    // Busy did not end the admitted request. Keep the exact body/page and its
                    // continuation in this Flow; the actor parks the round and the port's Busy
                    // edge retries this same owner. In particular, do not checkpoint/pause the
                    // shipped archive request and require a person to resume work the peer only
                    // deferred.
                    self.push(task)?;
                    self.waiting = true;
                    return Ok(());
                }
                if result.status == Status::EvidenceUnavailable {
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
                    if let Some((head, seq, _)) = result.role_ready {
                        self.archive_next = seq
                            .checked_sub(1)
                            .filter(|next| matches!(query, Query::Page { lo, .. } if *next >= lo));
                        self.push(Task {
                            request: wire_request,
                            purpose: Purpose::History,
                            operation: Operation::Local(LocalStep::Entry {
                                request: wire_request,
                                head,
                                seq,
                                body: false,
                                role_header: true,
                                phase: EntryPhase::Start,
                            }),
                        })?;
                    } else if result.body_ready.is_none() {
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
                        self.archive_next = body.seq.checked_sub(1).filter(|next| *next >= 1);
                        self.archive_wire_bytes =
                            self.archive_wire_bytes.saturating_add(body.length);
                        self.push(Task {
                            request: wire_request,
                            purpose: Purpose::History,
                            operation: Operation::Local(LocalStep::Entry {
                                request: wire_request,
                                head: state.state().bounds.head,
                                seq: body.seq,
                                body: true,
                                role_header: false,
                                phase: EntryPhase::Start,
                            }),
                        })?;
                    }
                }
                for query in result.needs.into_iter().rev() {
                    self.push(Task {
                        request: task.request,
                        purpose: Purpose::Control,
                        operation: if matches!(query, Query::Proof { .. }) {
                            Operation::LocalProof(query)
                        } else {
                            Operation::Wire(query)
                        },
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
            Operation::LocalProof(query) => {
                match receiver
                    .local_proof(job, task.request, query.clone())
                    .await?
                {
                    LocalProof::Verified(binding) => self.push(Task {
                        request: binding.request,
                        purpose: Purpose::Control,
                        operation: Operation::Local(LocalStep::Verify(binding)),
                    })?,
                    LocalProof::Missing => self.push(Task {
                        request: task.request,
                        purpose: Purpose::Control,
                        operation: Operation::Wire(query),
                    })?,
                    LocalProof::Busy => {
                        self.push(task)?;
                        self.waiting = true;
                    }
                }
            }
            Operation::Local(step) => {
                let result = receiver.local_step(job, step, crate::time::Ms(now)).await?;
                if let Some(next) = result.next {
                    if matches!(next, LocalStep::Entry { head, seq, phase: EntryPhase::Effect(_), .. }
                        if self.live_unavailable == Some((head, seq)))
                    {
                        // Header publication and its missing-body index are durable. Do not
                        // manufacture a completed effect for a body this peer did not supply.
                        self.published = true;
                        return Ok(());
                    }
                    let continuation = Task {
                        operation: Operation::Local(next),
                        ..task.clone()
                    };
                    let rederive = matches!(
                        next,
                        LocalStep::Entry {
                            phase: EntryPhase::Start | EntryPhase::Preflight { .. },
                            ..
                        } | LocalStep::Control { .. }
                    );
                    if !self.archive && result.need.is_some() && rederive {
                        // Keep the oldest exact root in the scalar replay slot. Once that slot is
                        // occupied, retain each nested continuation on the existing bounded task
                        // stack: the dependency pushed below executes first, then the exact entry
                        // or control operation that requested it can publish its durable result.
                        // Dropping a nested continuation would finish its proofs but leave no work
                        // able to apply them, causing the root to repeat the same dependency cycle.
                        // Verify/Validate, Body, publication, effects, reclaim and explicit archive
                        // continuations are never compacted.
                        if self.replay.is_none() {
                            self.replay = Some(continuation);
                        } else {
                            self.push(continuation)?;
                        }
                    } else {
                        self.push(continuation)?;
                    }
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
                            operation: if matches!(query, Query::Proof { .. }) {
                                Operation::LocalProof(query)
                            } else {
                                Operation::Wire(query)
                            },
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
                        // A distinct dependency starts a distinct staging activation. Reusing
                        // the parent request after an earlier dependency reached Complete would
                        // correctly trip history_demand's replay guard and strand the remaining
                        // current work. Keep this ID as the source-owned cleanup boundary, just
                        // as each new live-window position does above.
                        let request = request_id()?;
                        self.request = request;
                        self.push(Task {
                            request,
                            purpose: Purpose::Control,
                            operation: Operation::Local(LocalStep::Entry {
                                request,
                                head,
                                seq,
                                body: false,
                                role_header: false,
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
                if !self.reclaim_stage(purpose, job, false).await? {
                    self.push(task)?;
                } else if self.archive
                    && self.tasks.is_empty()
                    && !self.archive_continue(job).await?
                {
                    self.finish_archive(job).await?;
                }
            }
            Operation::ReclaimUnavailable => {
                if let Some(root) = self.replay.take() {
                    self.push(task)?;
                    self.push(root)?;
                    return Ok(());
                }
                if !self.reclaim_stage(Purpose::Live, job, true).await? {
                    self.push(task)?;
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
                // A bounded fold step, then the entry slice is re-derived and decides for itself
                // whether the fold now serves it. A fold that is held or slow left that cycle
                // running against the same fold, 32 slices a turn and 77 turns a second, and
                // because the one foreground lane went back to this flow every round, the node's
                // other peer never got a round (a post made while the fold was held reached no
                // one in 30 s; ADR-037 R11). After a few steps the flow waits at the port's Busy
                // cadence and the actor's fold hook drives the fold (R2 b).
                match advanced {
                    Lookup::Found(_) if self.governance_cycles < GOVERNANCE_STEPS_PER_TURN => {
                        self.governance_cycles += 1;
                    }
                    Lookup::Found(_) => {
                        self.push(task)?;
                        self.waiting = true;
                        self.governance_wait = true;
                    }
                    Lookup::Busy | Lookup::Missing => {
                        self.push(task)?;
                        self.waiting = true;
                    }
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
    async fn reclaim_stage(&mut self, purpose: Purpose, job: &Job, retiring: bool) -> Result<bool> {
        let Some(staging) = self.stage(purpose) else {
            return Ok(true);
        };
        let job = job.clone();
        let complete = tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut active = staging
                .active
                .lock()
                .map_err(|_| Error::Profile("history activation lock failed"))?;
            if retiring {
                // The entry/effect is already admitted. End only this exact current staging
                // request, without consulting a peer grant that may have changed during
                // departure; cancel creates no network or archive authority.
                demand::cancel(&staging.context, active.request(), &job)?;
            }
            if !demand::reclaim(&staging.context, active.request(), &job)? {
                return Ok(false);
            }
            if !retiring && purpose != Purpose::History {
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
    /// After a body of an explicit history quantum is applied: the next page of the same bounded
    /// interval, while entries remain and the quantum's byte budget does. A page response is
    /// consumed up to its first complete body (one body slot), so one ask fetches its page body
    /// by body. Returns whether a page was pushed. Measured before this: `vox room read
    /// --history older` delivered one body and paused, and the newcomer proof's page below the
    /// live window never arrived.
    async fn archive_continue(&mut self, job: &Job) -> Result<bool> {
        let Some(staging) = self.history.clone() else {
            return Ok(false);
        };
        let Some(next) = self.archive_next else {
            return Ok(false);
        };
        if self.archive_wire_bytes >= ARCHIVE_QUANTUM_BYTES {
            return Ok(false);
        }
        let snapshot = inspect(&staging.context, job)
            .await?
            .ok_or(Error::Profile("archive state missing"))?;
        let state = snapshot.state();
        if state.body.is_some()
            || state.reclaiming()
            || state.remaining == 0
            || next < state.bounds.lo
        {
            return Ok(false);
        }
        let request = staging
            .active
            .lock()
            .map(|active| active.request())
            .map_err(|_| Error::Profile("history activation lock failed"))?;
        let query = Query::Page {
            head: state.bounds.head,
            lo: state.bounds.lo,
            hi: next,
            entries: state.remaining,
            wire_bytes: 1024 * 1024,
        };
        self.push(Task {
            request,
            purpose: Purpose::History,
            operation: Operation::Wire(query),
        })?;
        Ok(true)
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
                            let cursor = (next >= state.bounds.lo && state.remaining > 0)
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
