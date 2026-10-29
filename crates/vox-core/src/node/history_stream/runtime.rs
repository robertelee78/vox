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
use crate::node::channel::{ChannelState, HistoryAdmissionRoom};
use crate::node::history_budget::Job;
use crate::node::history_demand::{self as demand, Binding, Bounds, Context};
use crate::node::store::{ReceivedFlow, Store};
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
    /// A refused local allocation may follow a durable body append/checkpoint. Rebind from
    /// the exact saved staging cursor before another network request, rather than replaying
    /// an old offset or forgetting a complete body's remaining semantic application.
    ResumeWire(Query),
    LocalProof(Query),
    Local(LocalStep),
    Reclaim(Purpose),
    ReclaimUnavailable,
    ReclaimKeyUnavailable,
    FinishArchive,
    Governance,
}
enum StageStart {
    Ready,
    Waiting,
    Reclaimed,
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

pub(crate) enum RetirementStep {
    Done,
    Progress,
    Wait(RetirementWait),
}
pub(crate) enum RetirementWait {
    Bytes(crate::node::history_budget::BytePressure),
    Publication {
        wake: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>,
    },
}
impl RetirementWait {
    pub(crate) async fn released(self) {
        match self {
            Self::Bytes(pressure) => pressure.released().await,
            Self::Publication { wake } => wake.await,
        }
    }
}
#[derive(Clone)]
struct Task {
    request: RequestId,
    purpose: Purpose,
    operation: Operation,
}

/// One inventory exchange prepended to an already-retained foreground flow. It is deliberately
/// outside `tasks`/`replay`: announcing an own append must not need a thirteenth retained Flow or
/// a spare dependency-stack position, and it must not replace the hint/required owner already in
/// this Flow.
struct Announcement {
    request: RequestId,
    prior_request: RequestId,
    task: Option<Task>,
    through: u64,
    brought: bool,
    complete: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct AnnouncementReceipt {
    pub(crate) through: u64,
    pub(crate) brought: bool,
}

/// Scalar ownership of the existing fixed body slots. A progressing transfer keeps its slot
/// across quanta; another deferred flow may advance metadata but cannot reset that body.
#[derive(Default)]
pub(crate) struct BodySlots {
    owners: StdMutex<[Option<RequestId>; 3]>,
    key_wake: Arc<tokio::sync::Notify>,
}
impl BodySlots {
    fn claim(&self, purpose: Purpose, request: RequestId, key_body: bool) -> bool {
        let Some(index) = body_slot(purpose, key_body) else {
            return true;
        };
        let mut slots = self
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slots[index].is_some_and(|owner| owner != request) {
            return false;
        }
        slots[index] = Some(request);
        true
    }
    fn release(&self, purpose: Purpose, request: RequestId, key_body: bool) {
        let Some(index) = body_slot(purpose, key_body) else {
            return;
        };
        let mut slots = self
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slots[index] == Some(request) {
            slots[index] = None;
            drop(slots);
            if index == 2 {
                self.key_wake.notify_waiters();
            }
        }
    }
    fn key_released(&self) -> std::pin::Pin<Box<tokio::sync::futures::OwnedNotified>> {
        let mut wake = Box::pin(Arc::clone(&self.key_wake).notified_owned());
        wake.as_mut().enable();
        wake
    }
}
fn body_slot(purpose: Purpose, key_body: bool) -> Option<usize> {
    if key_body && purpose == Purpose::Control {
        return Some(2);
    }
    match purpose {
        Purpose::Live => Some(0),
        Purpose::Control => Some(1),
        Purpose::History => None,
    }
}

/// Only persisted cursor/body progress counts; activating a request or serial changes do not.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct OwnRecoveryCheckpoint {
    remaining: usize,
    next: u64,
    body: Option<(u64, u64)>,
}
impl OwnRecoveryCheckpoint {
    pub(crate) fn of(state: &demand::State) -> Self {
        Self {
            remaining: state.remaining,
            next: state
                .cursor
                .as_ref()
                .map_or(state.bounds.hi, |cursor| cursor.next_seq),
            body: state.body.as_ref().map(|body| (body.seq, body.offset)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct UnavailableResponse {
    pub(crate) author: Option<Digest32>,
    pub(crate) head: Digest32,
    pub(crate) lo: u64,
    pub(crate) hi: u64,
    pub(crate) reason: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyBodyUnavailable {
    Body,
    Evidence,
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
    pub(crate) automatic_own_recovery: bool,
    pub(crate) own_recovery_cleanup: bool,
    pub(crate) own_recovery_trigger: Option<Digest32>,
    pub(crate) own_recovery_page: Option<(Digest32, u64)>,
    pub(crate) own_recovery_checkpoint: Option<OwnRecoveryCheckpoint>,
    pub(crate) own_recovery_progress: bool,
    pub(crate) inventory: bool,
    pub(crate) availability_captured: Option<crate::node::channel::availability::Token>,
    pub(crate) availability_connection: u64,
    pub(crate) availability_ack: Option<crate::node::channel::availability::Token>,
    /// This node has a key delivery to the peer waiting on its prekey bundle (ADR-038 FX-35):
    /// the round reads the peer's board whatever kind of flow this is, until the bundle is
    /// held. Set by the actor at each start from the fact `vox status` reports as `key_waits`.
    pub(crate) wants_board: bool,
    departure_probe: bool,
    pub(crate) archive_request: Option<RequestId>,
    /// Exact required control root removed from the actor queue when this foreground flow was
    /// built. An authorization retirement must return this owner just as it returns a hint.
    pub(crate) required_root: Option<(Digest32, u64)>,
    pub(crate) key_body_root: Option<super::KeyBodyNeed>,
    pub(crate) key_body_token: Option<Arc<()>>,
    pub(crate) key_body_unavailable: Option<KeyBodyUnavailable>,
    pub(crate) unavailable_response: Option<UnavailableResponse>,
    pub(crate) archive_selected_author: Option<(Digest32, Digest32)>,
    pub(crate) key_availability_token: Option<Arc<()>>,
    pub(crate) key_availability_result: super::KeyAvailabilityResult,
    key_body_checked: bool,
    pub(crate) hint: Option<super::HeadHint>,
    /// Canonical local recovery proof root, not a consumed advisory inbox item.
    pub(crate) local_own_verification: bool,
    pub(crate) local_own_discovery: bool,
    /// A newly constructed inventory took precedence over an already eligible local probe.
    /// Its real completion owns exactly one subsequent port request.
    pub(crate) local_own_after_inventory: bool,
    discovery_reply: Option<(
        super::HeadHint,
        u64,
        Option<crate::node::channel::availability::Token>,
    )>,
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
    pub(crate) byte_pressure: Option<crate::node::history_budget::BytePressure>,
    pub(crate) slot_wait:
        Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>>,
    pub(crate) published: bool,
    pub(crate) rendered: bool,
    pub(crate) governance: bool,
    /// An exchange of this flow fetched something this node did not hold (an object it saved,
    /// a body chunk, a hint it did not have): a completed flow that brought nothing is an
    /// `empty` round in `vox status --json` (ADR-038 FX-29).
    pub(crate) brought: bool,
    /// Set at the durable/user-visible work edge and drained by the actor before it classifies
    /// the worker result. This survives any later cancellation, error or supersession.
    pub(crate) work_committed: Arc<std::sync::atomic::AtomicBool>,
    /// Changed, signature-verified own observation committed by the physical receiver.
    pub(crate) own_head_observed: Arc<std::sync::atomic::AtomicBool>,
    /// Exact connection which returned unavailable for this startup metadata probe.
    pub(crate) discovery_unavailable:
        Option<(u64, Option<crate::node::channel::availability::Token>)>,
    pub(crate) discovery_incarnations: Option<(u64, u64)>,
    pub(crate) receipt_lower: Option<(u64, (u64, u64))>,
    /// Exact unavailable advertised heads declined during this retained flow. The actor reports
    /// the outcome through the lane in `vox status --json`.
    pub(crate) declined: u64,
    /// Newly eligible scalar hints and durable refusal relationships invalidated this turn.
    /// The actor publishes them even if the enclosing attempt is later retired or stale.
    pub(crate) offered: u64,
    pub(crate) rearmed: u64,
    /// Exact refusal transaction outcomes are published even when the enclosing flow is retired.
    pub(crate) refusal_stale: Option<crate::node::status::HistoryRefusalStatus>,
    pub(crate) refusal_saved: Option<crate::node::status::HistoryRefusalStatus>,
    pub(crate) admitted_authors: usize,
    pub(crate) external: Option<(Digest32, u64)>,
    pub(crate) archive_status: Option<crate::node::api::HistoryDemandStatus>,
    /// A healthy advertising peer did not retain the exact current wire dependency. The actor
    /// moves this same flow to the named author's port; no second root or volatile copy exists.
    pub(crate) reroute: Option<Digest32>,
    /// Original peer while the next exact wire dependency runs against its author.
    pub(crate) route_origin: Option<Digest32>,
    /// Fetch progress accumulated on the advertising source's lane before a dependency is routed
    /// to its author. The routed lane gets a fresh directional account; returning restores only
    /// the origin's progress, so one fetched object cannot make both lanes non-empty.
    pub(crate) route_origin_brought: bool,
    /// The routed wire response completed and the retained continuation must return to origin.
    pub(crate) route_complete: bool,
    /// A local trust edit invalidated this flow's grant. Retire it without blaming the peer;
    /// the controller re-arms its exact scalar hint under the new generation.
    pub(crate) authorization_changed: bool,
    /// Durability debt created by this flow alone. It follows every receiver handoff and is
    /// detached whenever the flow returns to the actor.
    received: ReceivedFlow,
    /// A refusal reached the peer successfully but could not be recorded in the local store.
    /// The actor re-arms the exact owner without charging this failure to the peer.
    pub(crate) local_retry: Option<String>,
    tasks: Vec<Task>,
    // One exact suspended foreground root. Intermediate pre-body continuations
    // are re-derived from durable receipts after the current dependency finishes.
    replay: Option<Task>,
    announcement: Option<Announcement>,
    /// The returned error came from the prefix itself, not an ordinary task that ran while a
    /// prefix was pending behind a publication owner.
    announcement_error: bool,
    /// True only while the worker owns the scalar prefix task. A supervisor-observed panic can
    /// therefore reconstruct that task without guessing from a merely pending announcement.
    announcement_active: bool,
    /// A post arriving while the announcement exchange is in flight must not make announcements
    /// starve the retained root. One actual ordinary worker quantum runs before another prefix.
    ordinary_turn_due: bool,
    /// This turn returned one of the two retryable coded peer refusals after restoring its exact
    /// ordinary continuation. The announcement scalar is deliberately separate provenance.
    peer_busy_retry: bool,
    slots: Arc<BodySlots>,
    owners: [Option<RequestId>; 3],
    /// A durable body chunk moved in this flow's last turn: the waiting slice is
    /// progress, not a busy wait, and its port must not grow a Busy backoff.
    pub(crate) body_progress: bool,
    /// This turn's slice waits on the room's governance fold, which is not ready yet (ADR-037
    /// R2): a local wait, not a body slot held against a busy peer, so it never retires the slot,
    /// and the actor's fold hook is asked to drive the fold.
    pub(crate) governance_wait: bool,
    /// The last local slice found an unfinished sparse publication. Before retrying that newer
    /// slice, select the exact older request in this Flow that owns the publication.
    publication_wait: bool,
    /// Exact durable publication owner when it belongs to another retained Flow. The actor uses
    /// this causal edge to resume that owner, rather than retrying this waiter on an unrelated
    /// port cadence.
    publication_owner_wait: Option<RequestId>,
    governance_cycles: u8,
    last_head: Option<super::HeadHint>,
    /// Immutable identity of this cleanup obligation. `request` changes as continuations are
    /// derived; retirement ownership must not.
    retirement_request: RequestId,
    request: RequestId,
    cleanup_store: Arc<Store>,
    failed_settlement: Option<crate::node::store::ReceivedSettlement>,
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
    pub(crate) fn local_own_root(&self) -> bool {
        self.local_own_verification || self.local_own_discovery
    }
    pub(crate) fn completed_support_discovery(&self) -> Option<u64> {
        self.discovery_reply
            .filter(|(head, _, _)| {
                self.local_own_discovery && Some(*head) == self.authenticated_head
            })
            .map(|(_, connection, _)| connection)
    }
    pub(crate) fn completed_support_availability(
        &self,
    ) -> Option<crate::node::channel::availability::Token> {
        self.discovery_reply
            .filter(|(head, _, _)| {
                self.local_own_discovery && Some(*head) == self.authenticated_head
            })
            .and_then(|(_, _, availability)| availability)
    }
    pub(crate) fn root_name(&self) -> &'static str {
        if self.announcement_pending() && self.announcement_can_run() {
            "inventory"
        } else if self.archive {
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
        local_own_verification: bool,
        local_own_discovery: bool,
        departure_probe: bool,
        required: Option<(Digest32, u64)>,
        slots: Arc<BodySlots>,
        cleanup_store: Arc<Store>,
        cleanup_budget: Arc<crate::node::history_budget::Budget>,
        actor_incarnation: Option<u64>,
    ) -> Result<Self> {
        if (local_own_verification || local_own_discovery)
            && (hint.is_none_or(|hint| hint.author != node)
                || departure_probe
                || required.is_some())
        {
            return Err(Error::Profile(
                "own verification root is not an exact local head",
            ));
        }
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
            automatic_own_recovery: false,
            own_recovery_cleanup: false,
            own_recovery_trigger: None,
            own_recovery_page: None,
            own_recovery_checkpoint: None,
            own_recovery_progress: false,
            inventory: hint.is_none() && required.is_none(),
            wants_board: false,
            departure_probe,
            archive_request: None,
            required_root: required,
            key_body_root: None,
            key_body_token: None,
            key_body_unavailable: None,
            unavailable_response: None,
            archive_selected_author: None,
            key_availability_token: None,
            key_availability_result: None,
            key_body_checked: false,
            state_charge: None,
            hint,
            local_own_verification,
            local_own_discovery,
            local_own_after_inventory: false,
            availability_captured: None,
            availability_connection: 0,
            availability_ack: None,
            discovery_reply: None,
            hint_peer: peer,
            authenticated_head: None,
            mine_held: None,
            reason: crate::node::status::RoundReason::Request,
            waiting: false,
            byte_pressure: None,
            slot_wait: None,
            published: false,
            rendered: false,
            governance: false,
            brought: false,
            work_committed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            own_head_observed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            discovery_unavailable: None,
            discovery_incarnations: None,
            receipt_lower: None,
            declined: 0,
            offered: 0,
            rearmed: 0,
            refusal_stale: None,
            refusal_saved: None,
            admitted_authors: 0,
            external: None,
            archive_status: None,
            reroute: None,
            route_origin: None,
            route_origin_brought: false,
            route_complete: false,
            authorization_changed: false,
            received: ReceivedFlow::new(room),
            local_retry: None,
            tasks: Vec::with_capacity(MAX_TASKS),
            replay: None,
            announcement: None,
            announcement_error: false,
            announcement_active: false,
            ordinary_turn_due: false,
            peer_busy_retry: false,
            slots,
            owners: [None, None, None],
            body_progress: false,
            governance_wait: false,
            publication_wait: false,
            publication_owner_wait: None,
            governance_cycles: 0,
            last_head: None,
            retirement_request: request,
            request,
            cleanup_store,
            failed_settlement: None,
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
                purpose: if local_own_discovery {
                    Purpose::Live
                } else {
                    Purpose::Control
                },
                // Ordinary inventory hints ask which head the peer currently serves. A
                // recovery root already names a locally verified signed Head: asking Head
                // here could retarget it to a lower reply forever. Start its existing exact
                // header/inclusion/consistency promotion path instead; no body is requested.
                operation: Operation::Wire(if local_own_verification {
                    if hint.size == 0 {
                        Query::Proof {
                            head: hint.head,
                            kind: super::ProofKind::Consistency,
                            from: 0,
                            to: 0,
                        }
                    } else {
                        Query::Header {
                            head: hint.head,
                            seq: hint.size,
                        }
                    }
                } else {
                    Query::Head(hint.author)
                }),
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
            automatic_own_recovery: false,
            own_recovery_cleanup: false,
            own_recovery_trigger: None,
            own_recovery_page: None,
            own_recovery_checkpoint: None,
            own_recovery_progress: false,
            inventory: false,
            wants_board: false,
            departure_probe: false,
            archive_request: Some(request),
            required_root: None,
            key_body_root: None,
            key_body_token: None,
            key_body_unavailable: None,
            unavailable_response: None,
            archive_selected_author: None,
            key_availability_token: None,
            key_availability_result: None,
            key_body_checked: false,
            state_charge: None,
            hint: None,
            local_own_verification: false,
            local_own_discovery: false,
            local_own_after_inventory: false,
            availability_captured: None,
            availability_connection: 0,
            availability_ack: None,
            discovery_reply: None,
            hint_peer: peer,
            authenticated_head: None,
            mine_held: None,
            reason: crate::node::status::RoundReason::Page,
            waiting: false,
            byte_pressure: None,
            slot_wait: None,
            published: false,
            rendered: false,
            governance: false,
            brought: false,
            work_committed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            own_head_observed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            discovery_unavailable: None,
            discovery_incarnations: None,
            receipt_lower: None,
            declined: 0,
            offered: 0,
            rearmed: 0,
            refusal_stale: None,
            refusal_saved: None,
            admitted_authors: 0,
            external: None,
            archive_status: None,
            reroute: None,
            route_origin: None,
            route_origin_brought: false,
            route_complete: false,
            authorization_changed: false,
            received: ReceivedFlow::new(room),
            local_retry: None,
            slots,
            owners: [None, None, None],
            body_progress: false,
            governance_wait: false,
            publication_wait: false,
            publication_owner_wait: None,
            governance_cycles: 0,
            last_head: None,
            retirement_request: request,
            request,
            cleanup_store,
            failed_settlement: None,
            cleanup_budget,
            actor_incarnation,
            cleanup_after: None,
            tasks: {
                let mut tasks = Vec::with_capacity(MAX_TASKS);
                tasks.push(Task {
                    request,
                    purpose: Purpose::History,
                    // A resumed archive Entry may have a durably complete body but no room
                    // effect yet. Re-enter its local admission instead of asking the donor
                    // for an empty suffix and parking an unchanged request.
                    operation: if matches!(&query, Query::Entry { .. }) {
                        Operation::ResumeWire(query)
                    } else {
                        Operation::Wire(query)
                    },
                });
                tasks
            },
            replay: None,
            announcement: None,
            announcement_error: false,
            announcement_active: false,
            ordinary_turn_due: false,
            peer_busy_retry: false,
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
    /// Own one recipient body without consuming the peer's public hint.
    pub(crate) fn with_key_body(
        mut self,
        need: super::KeyBodyNeed,
        instance: [u8; 16],
        context: Arc<Context>,
        token: Arc<()>,
    ) -> Self {
        self.tasks.clear();
        self.tasks.push(Task {
            request: self.request,
            purpose: Purpose::Control,
            operation: Operation::Local(LocalStep::Entry {
                request: self.request,
                head: need.head,
                seq: need.seq,
                body: true,
                role_header: false,
                phase: EntryPhase::Start,
            }),
        });
        self.inventory = false;
        self.initialized = true;
        self.instance = instance;
        self.generation = need.authorization;
        self.key_body_root = Some(need);
        self.key_body_token = Some(token);
        self.control_context = context;
        self
    }

    /// An exact receiver-owned cursor asks for one provider catalog page.
    pub(crate) fn with_key_availability(mut self, after: Option<u64>, token: Arc<()>) -> Self {
        self.tasks.clear();
        self.tasks.push(Task {
            request: self.request,
            purpose: Purpose::Control,
            operation: Operation::Wire(Query::KeyAvailability { after }),
        });
        self.inventory = false;
        self.key_availability_token = Some(token);
        self
    }

    fn push(&mut self, task: Task) -> Result<()> {
        if self.tasks.len() >= MAX_TASKS {
            return Err(Error::SizeLimitExceeded("history dependency stack"));
        }
        self.tasks.push(task);
        Ok(())
    }
    /// Move this Flow's exact durable publication owner to the top of its bounded LIFO stack.
    /// An owner outside the retained task/replay set belongs to another Flow and is untouched.
    fn prioritize_publication_owner(&mut self, owner: RequestId) -> bool {
        if let Some(at) = self.tasks.iter().rposition(|task| task.request == owner) {
            let task = self.tasks.remove(at);
            self.tasks.push(task);
            return true;
        }
        if self
            .replay
            .as_ref()
            .is_some_and(|task| task.request == owner)
        {
            if let Some(task) = self.replay.take() {
                self.tasks.push(task);
                return true;
            }
        }
        false
    }

    pub(crate) fn publication_owner_wait(&self) -> Option<RequestId> {
        self.publication_owner_wait
    }

    pub(crate) fn owns_request(&self, request: RequestId) -> bool {
        self.request == request
            || self.retirement_request == request
            || self.tasks.iter().any(|task| task.request == request)
            || self
                .replay
                .as_ref()
                .is_some_and(|task| task.request == request)
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

    pub(crate) fn secret_work(&self) -> Arc<tokio::sync::OwnedRwLockReadGuard<()>> {
        self.control_context.secret_work()
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
    ) -> Result<bool> {
        self.decline_exact(source, job, inbox, author, head).await
    }
    async fn decline_exact(
        &mut self,
        source: &super::source::Source,
        job: &Job,
        inbox: &super::hints::HintInbox,
        author: Digest32,
        head: Digest32,
    ) -> Result<bool> {
        if self.local_own_discovery {
            // Startup metadata discovery is scoped to the selected connection, not the old
            // durable receipt/proof operation. Actor retains its unavailable disposition on
            // that Port; a genuine reconnect can obtain newly available signed metadata.
            return Ok(true);
        }
        // A metadata root is a separate operation from the old ambiguous body/inventory
        // decision. Retain one exact disposition for its whole immutable verification chain.
        let (author, head) = if self.local_own_root() {
            let hint = self
                .hint
                .ok_or(Error::Profile("own metadata refusal root missing"))?;
            (hint.author, hint.head)
        } else {
            (author, head)
        };
        let remembered = match source
            .remember_decline(job, author, head, self.request, self.local_own_root())
            .await
        {
            Ok(super::source::DeclineResult::Stored {
                remembered,
                captured,
                current,
            }) => {
                self.refusal_saved = Some(crate::node::status::HistoryRefusalStatus {
                    peer: source.peer,
                    author,
                    head,
                    request: self.request,
                    captured_generation: captured,
                    current_generation: current,
                    remembered,
                });
                remembered
            }
            Ok(super::source::DeclineResult::AuthorizationChanged { captured, current }) => {
                self.refusal_stale = Some(crate::node::status::HistoryRefusalStatus {
                    peer: source.peer,
                    author,
                    head,
                    request: self.request,
                    captured_generation: captured,
                    current_generation: current,
                    remembered: false,
                });
                self.authorization_changed = true;
                self.waiting = true;
                return Ok(false);
            }
            Err(error) => {
                self.local_retry = Some(format!(
                    "local history refusal was not durably recorded: {error}"
                ));
                self.waiting = true;
                return Ok(false);
            }
        };
        if !self.local_own_root() {
            inbox.finish(self.room, source.peer, author, head);
        }
        self.declined = self.declined.saturating_add(u64::from(remembered));
        Ok(true)
    }
    pub(crate) fn done(&self) -> bool {
        self.tasks.is_empty() && self.replay.is_none() && self.announcement.is_none()
    }

    /// Whether an ordinary operation, rather than the separate announcement prefix, remains
    /// owned by this Flow. A peer-Busy settlement may retain the Flow only when the exact popped
    /// operation was restored here; an announcement alone is not provenance for retrying it.
    #[must_use]
    pub(crate) fn ordinary_pending(&self) -> bool {
        !self.tasks.is_empty() || self.replay.is_some()
    }

    /// Consume the proof that this returned peer-Busy result still owns its exact ordinary task.
    /// A pending announcement alone can never satisfy this predicate.
    pub(crate) fn take_peer_busy_retry(&mut self) -> bool {
        std::mem::take(&mut self.peer_busy_retry) && self.ordinary_pending()
    }

    /// Prepend one real inventory exchange to this retained foreground owner. A failed prefix
    /// remains this same scalar; it never consumes, rebuilds or retires the ordinary root.
    pub(crate) fn arm_announcement(&mut self, through: u64) -> Result<()> {
        if self.archive || self.inventory {
            return Err(Error::Profile(
                "history announcement prefix requires a retained foreground root",
            ));
        }
        if self.announcement.is_some() {
            return Ok(());
        }
        let request = request_id()?;
        self.announcement = Some(Announcement {
            request,
            prior_request: self.request,
            task: Some(Task {
                request,
                purpose: Purpose::Control,
                operation: Operation::Wire(Query::Inventory),
            }),
            through,
            brought: false,
            complete: false,
        });
        Ok(())
    }

    #[must_use]
    pub(crate) fn announcement_pending(&self) -> bool {
        self.announcement
            .as_ref()
            .is_some_and(|announcement| !announcement.complete)
    }

    #[must_use]
    pub(crate) fn announcement_can_run(&self) -> bool {
        !self.archive
            && !self.inventory
            && !self.publication_wait
            && self.active_publication_owner().is_none()
    }

    #[must_use]
    pub(crate) fn announcement_failed(&self) -> bool {
        self.announcement_error || self.announcement_active
    }

    pub(crate) fn retain_failed_announcement(&mut self) -> Result<()> {
        let Some(announcement) = self.announcement.as_mut() else {
            return Err(Error::Profile("history announcement owner missing"));
        };
        if !announcement.complete && announcement.task.is_none() {
            announcement.task = Some(Task {
                request: announcement.request,
                purpose: Purpose::Control,
                operation: Operation::Wire(Query::Inventory),
            });
        }
        self.request = announcement.prior_request;
        self.announcement_error = false;
        self.announcement_active = false;
        self.peer_busy_retry = false;
        Ok(())
    }

    #[must_use]
    pub(crate) fn ordinary_turn_due(&self) -> bool {
        self.ordinary_turn_due
    }

    pub(crate) fn take_announcement_receipt(&mut self) -> Option<AnnouncementReceipt> {
        let announcement = self
            .announcement
            .take_if(|announcement| announcement.complete)?;
        self.ordinary_turn_due = true;
        Some(AnnouncementReceipt {
            through: announcement.through,
            brought: announcement.brought,
        })
    }

    fn restore_announcement_task(&mut self, task: Task) -> Result<()> {
        let Some(announcement) = self.announcement.as_mut() else {
            return Err(Error::Profile("history announcement owner missing"));
        };
        if announcement.complete || announcement.task.is_some() {
            return Err(Error::Profile("history announcement task already retained"));
        }
        announcement.task = Some(task);
        Ok(())
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
                    | Operation::ReclaimKeyUnavailable
                    | Operation::FinishArchive
                    | Operation::Governance
            )
        )
    }

    /// The exact request whose sparse publication is between Begin and Cleanup in the next
    /// local slice. This is a durable room-wide exclusion, not ordinary retained Flow state: it
    /// must reach Cleanup (or explicit retirement rollback) before this Flow can be parked.
    fn active_publication_owner(&self) -> Option<RequestId> {
        let next = self.tasks.last().or(self.replay.as_ref())?;
        match &next.operation {
            Operation::Local(LocalStep::Entry {
                request,
                phase: EntryPhase::Prepare(_) | EntryPhase::Commit(_) | EntryPhase::Cleanup(_),
                ..
            }) => Some(*request),
            _ => None,
        }
    }
    /// Only the controller retirement owner may execute a recovered deletion capability.
    pub(crate) fn mark_own_recovery_cleanup(&mut self) {
        self.own_recovery_cleanup = true;
        self.initialized = true;
        self.tasks.clear();
    }

    pub(crate) fn lane(&self) -> crate::node::history_budget::Lane {
        use crate::node::history_budget::Lane;
        match self
            .tasks
            .last()
            .or(self.replay.as_ref())
            .map(|task| (&task.operation, task.purpose))
        {
            Some((
                Operation::Wire(Query::Entry { .. } | Query::Page { .. })
                | Operation::ResumeWire(Query::Entry { .. } | Query::Page { .. }),
                Purpose::History,
            )) => Lane::Archive,
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
            // The key slot remains owned until physical retirement or the Flow is dropped.
            if index == 2 {
                continue;
            }
            if let Some(request) = owner {
                self.slots.release(
                    if index == 0 {
                        Purpose::Live
                    } else {
                        Purpose::Control
                    },
                    *request,
                    index == 2,
                );
            }
        }

        for cancellation in self.cancellation_handles() {
            cancellation.cancel();
        }
    }
    /// The Controller owns this future and awaits it before dropping an abandoned flow.
    /// Each transaction is bounded; no transport or authority effect runs during retirement.
    pub(crate) async fn retire_slice(&mut self) -> Result<RetirementStep> {
        self.publication_owner_wait = None;
        self.failed_settlement = None;
        let room_unavailable =
            !self.initialized || self.shared.lock().await.history_retirement_locked();
        let store = Arc::clone(&self.cleanup_store);
        let received = self.received.clone();
        let target = tokio::task::spawn_blocking(move || store.received_settlement(&received))
            .await
            .map_err(|_| Error::Unreachable("history settlement snapshot worker stopped"))?;
        let result = if let Some(debt) = target.debt.clone() {
            self.settle_received_debt(Arc::clone(&self.cleanup_store), debt)
                .await
        } else if target.replacement_pending {
            let store = Arc::clone(&self.cleanup_store);
            tokio::task::spawn_blocking(move || store.finish_received_replacement())
                .await
                .map_err(|_| Error::Unreachable("history replacement worker stopped"))?
        } else {
            Ok(())
        };
        if let Err(error) = result {
            if room_unavailable {
                // Store retains the exact debt after this flow drops. Reopened-room receipts
                // collect that debt before acknowledging; key erasure must not wedge teardown.
                eprintln!("vox: received history remains unflushed after room lock: {error}");
                self.cancel();
                return Ok(RetirementStep::Done);
            }
            let store = Arc::clone(&self.cleanup_store);
            let received = self.received.clone();
            match tokio::task::spawn_blocking(move || store.received_settlement(&received)).await {
                Ok(mut failed) => {
                    failed.debt = target.debt;
                    self.failed_settlement = Some(failed);
                }
                Err(snapshot_error) => {
                    // The attempted settlement error is the primary failure. Without a fresh
                    // snapshot we cannot know which replacement must complete, so retain the
                    // existing explicit recovery/erasure wait instead of claiming a wake.
                    eprintln!(
                        "vox: history settlement recovery snapshot worker stopped: {snapshot_error}"
                    );
                }
            }
            return Err(error);
        }
        if room_unavailable {
            self.cancel();
            return Ok(RetirementStep::Done);
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
        let reclaim_control = self.tasks.iter().any(|task| {
            matches!(
                task.operation,
                Operation::Reclaim(Purpose::Control) | Operation::ReclaimKeyUnavailable
            )
        });
        let staging = if reclaim_live && self.live.is_some() {
            self.live.clone().map(|stage| (Purpose::Live, stage))
        } else if reclaim_control && self.control.is_some() {
            self.control.clone().map(|stage| (Purpose::Control, stage))
        } else if self.automatic_own_recovery {
            self.history.clone().map(|stage| (Purpose::History, stage))
        } else {
            None
        };
        // A parked flow owns no worker. Retirement admits one independent large-control job for
        // this bounded local slice and gives it back before the flow is retained again.
        let cleanup_job = self
            .cleanup_budget
            .admit_job(self.node, crate::node::history_budget::Lane::LargeControl)
            .await;
        // No worker owns this Flow while it is retiring. Retain its already-fenced local
        // capability only through the exact queued reclamation above, then cancel it before
        // any general publication/verifier cleanup. Nothing here opens a stream or schedules
        // another turn.
        if staging.is_none() {
            self.cancel();
        }
        // Cleanup uses the independently admitted foreground-control envelope above; no parked
        // flow retains a Control worker merely so it can eventually retire.
        const CLEANUP_ENVELOPE: usize = 6 * 1024 * 1024;
        let envelope = if staging.is_some() {
            demand::AdmissionCharge::total(CLEANUP_ENVELOPE)?
        } else {
            CLEANUP_ENVELOPE
        };
        let mut charge = match cleanup_job.reserve_or_pressure(envelope) {
            Ok(charge) => charge,
            Err(Error::HistoryCapacity(pressure)) => {
                return Ok(RetirementStep::Wait(RetirementWait::Bytes(*pressure)));
            }
            Err(error) => return Err(error),
        };
        let admission = if staging.is_some() {
            Some(demand::AdmissionCharge::split_from(&mut charge)?)
        } else {
            None
        };
        let room = self.shared.clone();
        let store = self.cleanup_store.clone();
        let request = self.request;
        let instance = self.instance;
        let after = self.cleanup_after;
        let committed = Arc::clone(&self.work_committed);
        enum Slice {
            Gone,
            Staging(Purpose, bool),
            Source(bool, Option<[u8; 64]>),
            Publication(
                Option<RequestId>,
                std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>,
            ),
        }
        let step = tokio::task::spawn_blocking(move || {
            let _charge = charge;
            let mut channel = room.blocking_lock();
            if channel.history_retirement_locked() {
                return Ok(Slice::Gone);
            }
            // Lock erases keys immediately. Reopen owns the bounded crash cleanup;
            // no retired worker may keep/recreate an unlocked room to finish work.
            match channel.history_instance(&store) {
                Err(Error::AtRestLocked) => return Ok(Slice::Gone),
                Err(error) => return Err(error),
                Ok(current) if current != instance => return Ok(Slice::Gone),
                Ok(_) => {}
            }
            if let Some((purpose, staging)) = staging {
                // Same room->Active lock order as semantic completion. Observer cancellation
                // remains set: this route can only delete the captured abandoned staging.
                let mut active = staging
                    .active
                    .lock()
                    .map_err(|_| Error::Profile("history activation lock failed"))?;
                let admission = admission
                    .as_ref()
                    .ok_or(Error::Profile("history retirement admission missing"))?;
                // This deletion touches only the exact request's staging namespace and Active
                // serial, never the room projection. Context retains its existing secret lease.
                // Preserve room->Active acquisition order, then release the room before writer
                // acquisition; no room reacquisition occurs while Active is held.
                drop(channel);
                let done =
                    demand::retire_staging(&staging.context, &mut active, admission, &committed)?;
                return Ok(Slice::Staging(purpose, done));
            }
            let wake = channel.history_publication_wake();
            let publication_owner = channel.history_publication_request(&store)?;
            if channel.post_pending()
                || (channel.history_publication_busy(&store)? && publication_owner != Some(request))
            {
                return Ok(Slice::Publication(publication_owner, wake));
            }
            let pending = channel.prepare_history_publication(&store, None, Some(request))?;
            let owner = Arc::new(());
            let pin = channel.reserve_pending_history_write(&store, Arc::clone(&owner), true)?;
            drop(channel);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pending.cleanup(&store, &committed, None, Some((request, after)))
            }));
            let mut channel = room.blocking_lock();
            let owns = channel.owns_pending_history_write(&owner);
            if owns {
                channel.history_index_committed();
            }
            let result = match result {
                Ok(completed) => (|| {
                    if !owns {
                        return Err(Error::Unreachable("history retirement owner changed"));
                    }
                    if channel.history_instance(&store)? != instance {
                        return Err(Error::Unreachable("history retirement room changed"));
                    }
                    let (done, next) = channel.finish_history_publication(completed)?;
                    Ok(Slice::Source(done, next))
                })(),
                Err(_) => Err(Error::Profile("history retirement save worker stopped")),
            };
            channel.release_pending_text(&owner, false);
            let publication = if owns {
                channel.history_write_released(&store)
            } else {
                Ok(())
            };
            let result = result.and_then(|slice| publication.map(|()| slice));
            drop(channel);
            drop(pin);
            result
        })
        .await
        .map_err(|_| Error::Profile("history retirement worker stopped"))??;
        let (done, next) = match step {
            Slice::Gone => {
                self.cancel();
                return Ok(RetirementStep::Done);
            }
            Slice::Staging(purpose, done) => {
                if done {
                    if let Some(index) = body_slot(purpose, self.key_body_root.is_some()) {
                        if let Some(request) = self.owners[index].take() {
                            self.slots
                                .release(purpose, request, self.key_body_root.is_some());
                        }
                    }
                    match purpose {
                        Purpose::Live => self.live = None,
                        Purpose::Control => self.control = None,
                        // Automatic own recovery owns a real History staging slot too.
                        // Drop it only after exact-request retirement finished; the next
                        // slice can then clean this Flow's source/verifier owners.
                        Purpose::History => self.history = None,
                    }
                }
                return Ok(RetirementStep::Progress);
            }
            Slice::Source(done, next) => (done, next),
            Slice::Publication(owner, wake) => {
                // A foreground flow may suspend publication A while a freshly derived request B is
                // its current scalar. Verifier cleanup for B correctly waits while A is publishing,
                // but retirement must first select A when this same Flow still owns it. Otherwise
                // B waits for A forever and the actor retains a room-busy Flow with no running
                // worker. The task/replay stack is the exact ownership set; an unrelated owner's
                // publication remains untouched and is retried after its own causal completion.
                if let Some(owner) = owner.filter(|owner| *owner != request) {
                    let owned = self.retirement_request == owner
                        || self.tasks.iter().any(|task| task.request == owner)
                        || self
                            .replay
                            .as_ref()
                            .is_some_and(|task| task.request == owner);
                    if owned {
                        self.request = owner;
                        self.cleanup_after = None;
                        return Ok(RetirementStep::Progress);
                    } else {
                        // This retirement is causally blocked by one exact publication owner. The
                        // controller runs that owner first and retries this flow from the owner's
                        // completion, never from a wall-clock backoff.
                        self.publication_owner_wait = Some(owner);
                    }
                }
                return Ok(RetirementStep::Wait(RetirementWait::Publication { wake }));
            }
        };
        self.cleanup_after = next;
        if !done {
            return Ok(RetirementStep::Progress);
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
            Ok(RetirementStep::Progress)
        } else {
            Ok(RetirementStep::Done)
        }
    }

    /// Permanent cleanup faults wait only for actual key erasure (or explicit controller
    /// recovery). Publication notifications while unlocked never retry a broken store.
    pub(crate) fn retirement_erasure(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>> {
        let shared = Arc::clone(&self.shared);
        let settlement = self.failed_settlement.clone();
        Box::pin(async move {
            if let Some(settlement) = settlement {
                tokio::select! {
                    () = settlement.settled() => return,
                    () = async {
                        loop {
                            let wake = {
                                let room = shared.lock().await;
                                let wake = room.history_publication_wake();
                                if room.history_retirement_locked() { return; }
                                wake
                            };
                            wake.await;
                        }
                    } => return,
                }
            }
            loop {
                let wake = {
                    let room = shared.lock().await;
                    let wake = room.history_publication_wake();
                    if room.history_retirement_locked() {
                        return;
                    }
                    wake
                };
                wake.await;
            }
        })
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
            self.received.clone(),
            self.stage(purpose),
            purpose == Purpose::History,
            self.key_body_root,
            fence,
            deadline,
            Arc::clone(&self.work_committed),
            Arc::clone(&self.own_head_observed),
        )
    }

    async fn settle_received(&self, store: Arc<Store>) -> Result<()> {
        let Some(debt) = self.received.debt(&store)? else {
            return Ok(());
        };
        self.settle_received_debt(store, debt).await
    }

    async fn settle_received_debt(
        &self,
        store: Arc<Store>,
        debt: crate::node::store::ReceivedDebt,
    ) -> Result<()> {
        tokio::task::spawn_blocking(move || store.flush_received_through(debt).map(|_| ()))
            .await
            .map_err(|_| Error::Unreachable("history received flush worker stopped"))?
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
        self.byte_pressure = None;
        self.body_progress = false;
        self.governance_wait = false;
        self.governance_cycles = 0;
        self.external = None;
        self.announcement_error = false;
        self.announcement_active = false;
        self.peer_busy_retry = false;
        // Local slices run back to back inside one turn; a slice that needs the wire, waits,
        // errs or spends the slice budget ends it. Each slice used to be a turn of its own,
        // and a turn costs an actor round trip (~10 ms): one body took ~30 slices, so a
        // 128-position live window drained at three positions a second (40 s), and a creator
        // serving three joiners at once read their first posts after 30 s (#934).
        let mut quantum_started = tokio::time::Instant::now();
        let mut slices = 0u32;
        let mut result = loop {
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
            let result = match result {
                Err(Error::HistoryCapacity(pressure)) => {
                    // Initialization/publication-owner reads precede task selection. Their
                    // allocation refusal retains the unchanged stack; no popped task exists
                    // to reconstruct here. Post-selection helpers retain their own phase.
                    self.byte_pressure = Some(*pressure);
                    self.waiting = true;
                    Ok(())
                }
                result => result,
            };
            slices += 1;
            let publication_active = self.active_publication_owner().is_some();
            if result.is_err()
                || self.waiting
                || self.external.is_some()
                // The actor owns the separate announcement receipt/accounting boundary. Do not
                // let an ordinary local phase run behind it in this worker return.
                || self
                    .announcement
                    .as_ref()
                    .is_some_and(|announcement| announcement.complete)
                || (!publication_active
                    && (slices >= LOCAL_SLICES_PER_TURN
                        || quantum_started.elapsed() >= LOCAL_TURN_BUDGET
                        || tokio::time::Instant::now() >= deadline))
                || !self.next_slice_is_local()
            {
                break result;
            }
            if publication_active
                && (slices >= LOCAL_SLICES_PER_TURN
                    || quantum_started.elapsed() >= LOCAL_TURN_BUDGET)
            {
                // The quantum protects executor fairness, not correctness. Yield the worker
                // without returning its Flow to the actor, then finish the publication under
                // the same running ownership.
                tokio::task::yield_now().await;
                slices = 0;
                quantum_started = tokio::time::Instant::now();
            }
        };
        if result.as_ref().is_err_and(|error| {
            matches!(
                error,
                Error::Profile(
                    "history authorization changed"
                        | "history authorization changed before publication"
                        | "history authorization changed before refusal"
                        | "live window authorization changed"
                        | "live retry authorization changed"
                ) | Error::StreamRefused(super::AUTHORIZATION_CHANGED)
            )
        }) {
            self.authorization_changed = true;
            result = Ok(());
        }
        // Busy is a retained exact need. A count of turns can neither revoke the body slot nor
        // dispose its root; the semantic response/progress edge is the only thing that advances
        // it, while the actor's named Busy backoff prevents spinning between those edges.
        // A successful partial turn keeps this exact owner inside the returned Flow, allowing a
        // sparse source and its later semantic effect to share one durability debt. Every path
        // which stops carrying the flow forward settles first; a failure keeps the Flow owned by
        // retirement, which retries this same debt instead of lending it to a later transaction.
        if result.is_err() || self.authorization_changed || self.done() {
            let settlement = self.settle_received(store).await;
            if settlement.is_err() {
                // A stale actor callback must not publish a saved archive completion whose
                // received bytes did not cross their durable boundary.
                self.archive_status = None;
            }
            if result.is_ok() {
                settlement?;
            }
        }
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
            Some((self.node, self.generation)),
            Arc::clone(&self.work_committed),
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
        if self.publication_wait {
            let owner = source
                .read(job, 0, |channel, store| {
                    Ok(Some(channel.history_publication_request(store)?))
                })
                .await?;
            match owner {
                Lookup::Found(owner) => match owner.value {
                    None => {
                        self.publication_wait = false;
                        self.publication_owner_wait = None;
                    }
                    Some(owner) if self.prioritize_publication_owner(owner) => {
                        self.publication_wait = false;
                        self.publication_owner_wait = None;
                    }
                    Some(owner) => {
                        // Another live Flow owns the room's publication. Keep this exact task
                        // parked and name that owner so the actor can resume its exact port.
                        self.publication_owner_wait = Some(owner);
                        self.waiting = true;
                        return Ok(());
                    }
                },
                Lookup::Busy | Lookup::Missing => {
                    self.waiting = true;
                    return Ok(());
                }
            }
        }
        if let Some(need) = self.key_body_root.filter(|_| !self.key_body_checked) {
            let found = source
                .read(job, 64 * 1024, move |room, store| {
                    let read = room.history_read(store)?;
                    if read.publication_busy() {
                        return Ok(Some((true, true, room.history_publication_request(store)?)));
                    }
                    Ok(Some((
                        read.history_key_body_owed(need, room.me())?,
                        false,
                        None,
                    )))
                })
                .await?;
            let Lookup::Found(owed) = found else {
                self.waiting = true;
                return Ok(());
            };
            let (owed, busy, owner) = owed.value;
            if busy {
                self.publication_owner_wait = owner;
                self.publication_wait = true;
                self.waiting = true;
                return Ok(());
            }
            if !owed {
                self.tasks.clear();
                self.replay = None;
                return Ok(());
            }
            self.key_body_checked = true;
        }
        if self.tasks.is_empty() {
            if let Some(root) = self.replay.take() {
                self.tasks.push(root);
            }
        }
        // A publication Begin..Cleanup owner is correctness-critical and remains ahead of the
        // announcement prefix. Once no exact publication phase is active, the scalar inventory
        // task gets one response quantum ahead of the ordinary retained stack.
        let announcement_task = if self.active_publication_owner().is_none() {
            self.announcement
                .as_mut()
                .and_then(|announcement| announcement.task.take())
        } else {
            None
        };
        let (task, announcement_task) = if let Some(task) = announcement_task {
            self.announcement_active = true;
            (task, true)
        } else if let Some(task) = self.tasks.pop() {
            // Initialization, publication-owner lookup and worker admission do not spend the
            // fairness quantum. Only selecting an actual ordinary task does.
            self.ordinary_turn_due = false;
            (task, false)
        } else {
            return Ok(());
        };
        // Retirement's scalar always names the operation that can disappear from the bounded
        // stack while this fallible turn executes. Suspended owners remain in tasks/replay.
        if !self.archive {
            self.request = task.request;
        }
        let original_task = task.clone();
        let mut retry_task = Some(Task {
            operation: match &task.operation {
                Operation::Wire(query) => Operation::ResumeWire(query.clone()),
                operation => operation.clone(),
            },
            ..task.clone()
        });
        // Prefix work has its own empty/nonempty account. Preserve progress already made by the
        // ordinary root, then restore it after the inventory exchange.
        let ordinary_brought = announcement_task.then(|| std::mem::take(&mut self.brought));
        let ordinary_request = announcement_task.then(|| {
            self.announcement
                .as_ref()
                .map_or(self.retirement_request, |announcement| {
                    announcement.prior_request
                })
        });
        let result = self
            .execute_task(
                task,
                source,
                store,
                conn,
                job,
                fence,
                deadline,
                inbox,
                inbox_generation,
                now,
                announcement_task,
                &mut retry_task,
            )
            .await;
        if let Some(request) = ordinary_request {
            self.request = request;
        }
        let announcement_brought = announcement_task.then(|| {
            let brought = self.brought;
            self.brought = ordinary_brought.unwrap_or(false);
            brought
        });
        match result {
            Err(Error::HistoryCapacity(pressure)) => {
                if let Some(task) = retry_task {
                    if announcement_task {
                        self.restore_announcement_task(task)?;
                    } else {
                        self.push(task)?;
                    }
                }
                self.byte_pressure = Some(*pressure);
                self.waiting = true;
                self.announcement_active = false;
                if let Some(brought) = announcement_brought {
                    if let Some(announcement) = self.announcement.as_mut() {
                        announcement.brought |= brought;
                    }
                }
                Ok(())
            }
            Err(error) if announcement_task => {
                // A new stream retries the inventory prefix. The ordinary stack and every local
                // continuation remain exactly where they were when this prefix began.
                self.restore_announcement_task(original_task)?;
                if let Some(brought) = announcement_brought {
                    if let Some(announcement) = self.announcement.as_mut() {
                        announcement.brought |= brought;
                    }
                }
                self.announcement_error = true;
                self.announcement_active = false;
                Err(error)
            }
            Err(
                error @ Error::PeerRefused(
                    crate::wire::WireError::SessionBusy | crate::wire::WireError::NotYetMember,
                ),
            ) => {
                // These are the two coded, transient peer refusals paced as Busy by the port.
                // Restore the exact popped operation before returning it to the actor: a Wire
                // operation resumes from durable staging/cursor state, never from offset zero.
                // If a helper consumed the retry owner, do not fabricate a replacement.
                if let Some(task) = retry_task {
                    self.push(task)?;
                    self.peer_busy_retry = true;
                }
                Err(error)
            }
            Ok(()) if announcement_task => {
                let Some(announcement) = self.announcement.as_mut() else {
                    return Err(Error::Profile("history announcement owner missing"));
                };
                announcement.brought |= announcement_brought.unwrap_or(false);
                if announcement.task.is_none() {
                    announcement.complete = true;
                }
                self.announcement_active = false;
                Ok(())
            }
            result => result,
        }
    }

    /// Each fallible helper owns either the still-popped task or a more precise finalization
    /// continuation. Successfully derived tasks remain on the stack and are never rolled back.
    #[allow(clippy::too_many_arguments)]
    async fn execute_task(
        &mut self,
        task: Task,
        source: Source,
        store: Arc<Store>,
        conn: &VoxConnection,
        job: &Job,
        fence: Arc<Fence>,
        deadline: tokio::time::Instant,
        inbox: &super::HintInbox,
        inbox_generation: u64,
        now: u64,
        announcement_task: bool,
        retry_task: &mut Option<Task>,
    ) -> Result<()> {
        let receiver = self.receiver(store.clone(), task.purpose, fence.clone(), deadline);
        let resuming_wire = matches!(task.operation, Operation::ResumeWire(_));
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
                let committed = Arc::clone(&self.work_committed);
                enum Selection<P> {
                    Held(LiveWindow, u64),
                    Write(P, u64),
                }
                let found = source
                    .write_owned(
                        job,
                        (256, 4 * 1024 * 1024, false),
                        move |channel, store| {
                            if channel.history_instance(store)? != instance
                                || super::authorization_generation(
                                    store, node, room, instance, epoch,
                                )? != generation
                            {
                                return Err(Error::Profile("live window authorization changed"));
                            }
                            let input = channel.history_read(store)?;
                            let target = input
                                .history_head(&head)?
                                .ok_or(Error::MalformedAtRest("live window head missing"))?;
                            if target.binding.author != author
                                || target.binding.scope != crate::log::history::LogScope::Public
                            {
                                return Err(Error::MalformedAtRest(
                                    "live window head binding differs",
                                ));
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
                                    return Ok(Selection::Held(window, target.root.leaves));
                                }
                            }
                            let through = target.root.leaves;
                            drop(input);
                            let pending = channel
                                .prepare_history_admission(store, Some((node, generation)))?;
                            Ok(Selection::Write(pending, through))
                        },
                        move |selection, store| match selection {
                            Selection::Held(window, through) => Ok((window, through)),
                            Selection::Write(pending, through) => pending.with(|channel| {
                                channel
                                    .history_write_tracked(store, &committed, |index| {
                                        index.select_history_live_window(&author, head)
                                    })
                                    .map(|window| (window, through))
                            }),
                        },
                        |_, _, value| Ok(value),
                    )
                    .await?;
                let found = match found {
                    Lookup::Found(found) => found,
                    Lookup::Missing => {
                        self.publication_wait = true;
                        self.publication_owner_wait = None;
                        self.push(task)?;
                        self.waiting = true;
                        return Ok(());
                    }
                    Lookup::Busy => {
                        self.push(task)?;
                        self.waiting = true;
                        return Ok(());
                    }
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
                let found = match found {
                    Lookup::Found(found) => found,
                    Lookup::Missing => {
                        self.publication_wait = true;
                        self.publication_owner_wait = None;
                        self.push(task)?;
                        self.waiting = true;
                        return Ok(());
                    }
                    Lookup::Busy => {
                        self.push(task)?;
                        self.waiting = true;
                        return Ok(());
                    }
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
                let committed = Arc::clone(&self.work_committed);
                let advanced = source
                    .write_owned(
                        job,
                        (128, 4 * 1024 * 1024, false),
                        move |channel, store| {
                            if channel.history_instance(store)? != instance
                                || super::authorization_generation(
                                    store, node, room, instance, epoch,
                                )? != generation
                            {
                                return Err(Error::Profile("live window authorization changed"));
                            }
                            let input = channel.history_read(store)?;
                            let Some(header) =
                                input.history_position_header(&author, window.next)?
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
                                return Ok(None);
                            }
                            drop(input);
                            channel
                                .prepare_history_admission(store, Some((node, generation)))
                                .map(Some)
                        },
                        move |pending, store| match pending {
                            None => Ok(true),
                            Some(pending) => pending.with(|channel| {
                                channel.history_write_tracked(store, &committed, |index| {
                                    index.advance_history_live_window(&author, window)
                                })
                            }),
                        },
                        |_, _, value| Ok(value),
                    )
                    .await?;
                match advanced {
                    Lookup::Found(_) => {}
                    Lookup::Missing => {
                        self.publication_wait = true;
                        self.publication_owner_wait = None;
                        self.push(task)?;
                        self.waiting = true;
                        return Ok(());
                    }
                    Lookup::Busy => {
                        self.push(task)?;
                        self.waiting = true;
                        return Ok(());
                    }
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
            Operation::Wire(mut query) | Operation::ResumeWire(mut query) => {
                let body = matches!(query, Query::Entry { .. } | Query::Page { .. });
                if resuming_wire && body {
                    if let Some(staging) = self.stage(task.purpose) {
                        let snapshot = inspect(&staging.context, job)
                            .await?
                            .ok_or(Error::Profile("history retry state missing"))?;
                        let active = staging
                            .active
                            .lock()
                            .map_err(|_| Error::Profile("history activation lock failed"))?;
                        let state = snapshot.state();
                        // Own recovery has a private, donor-independent audience; ordinary
                        // archive and live/control stages remain bound to this node.
                        let expected_binding = Binding {
                            audience: if self.automatic_own_recovery
                                && task.purpose == Purpose::History
                            {
                                [0; 32]
                            } else {
                                self.node
                            },
                            ..self.binding()
                        };
                        if !active.matches(state)
                            || active.request() != task.request
                            || active.binding() != expected_binding
                        {
                            return Err(Error::Profile("history retry activation changed"));
                        }
                        if let Some(saved) = &state.body {
                            let exact = match query {
                                Query::Entry { head, seq, .. } => {
                                    head == state.bounds.head && seq == saved.seq
                                }
                                Query::Page { head, lo, hi, .. } => {
                                    head == state.bounds.head && saved.seq >= lo && saved.seq <= hi
                                }
                                _ => false,
                            };
                            if !exact {
                                return Err(Error::Profile(
                                    "history retry body differs from request",
                                ));
                            }
                            if saved.offset == saved.length {
                                // Bytes alone establish no room effect. Resume the normal opaque
                                // inclusion/control/authority checks under the original request.
                                if task.purpose == Purpose::History {
                                    self.archive_next = saved
                                        .seq
                                        .checked_sub(1)
                                        .filter(|next| *next >= state.bounds.lo);
                                    self.archive_wire_bytes =
                                        self.archive_wire_bytes.saturating_add(saved.length);
                                    self.push(Task {
                                        operation: Operation::Local(LocalStep::Entry {
                                            request: task.request,
                                            head: state.bounds.head,
                                            seq: saved.seq,
                                            body: true,
                                            role_header: false,
                                            phase: EntryPhase::Start,
                                        }),
                                        ..task.clone()
                                    })?;
                                } else {
                                    // Current body requests are dependencies of an already
                                    // retained Local phase. As with normal body_ready delivery,
                                    // resume that exact owner instead of adding a second Start.
                                    // A nested dependency may live on tasks while an older,
                                    // different root occupies the scalar replay slot.
                                    let owns_body = |pending: &Task| {
                                        pending.request == task.request
                                            && pending.purpose == task.purpose
                                            && matches!(pending.operation,
                                                Operation::Local(LocalStep::Entry { request, head, seq, body: true, role_header: false, .. })
                                                if request == task.request
                                                    && head == state.bounds.head
                                                    && seq == saved.seq)
                                    };
                                    if !self.tasks.iter().any(owns_body)
                                        && !self.replay.as_ref().is_some_and(owns_body)
                                    {
                                        return Err(Error::Profile(
                                            "completed current body has no retained local owner",
                                        ));
                                    }
                                }
                                return Ok(());
                            }
                            query = Query::Entry {
                                head: state.bounds.head,
                                seq: saved.seq,
                                offset: saved.offset,
                            };
                        }
                    }
                }
                if task.purpose == Purpose::History
                    && body
                    && self.archive_wire_bytes >= ARCHIVE_QUANTUM_BYTES
                {
                    self.finish_archive_owned(job, &task, retry_task).await?;
                    self.tasks.clear();
                    return Ok(());
                }
                if let Query::Entry { head, seq, .. } = query {
                    if task.purpose != Purpose::History {
                        match self
                            .ensure_stage(task.purpose, task.request, head, seq, job)
                            .await?
                        {
                            StageStart::Ready => {}
                            StageStart::Waiting => {
                                self.push(task)?;
                                self.waiting = true;
                                return Ok(());
                            }
                            StageStart::Reclaimed => {
                                // One bounded committed cleanup slice moved the retained
                                // owner forward. Yield to the actor, then continue immediately.
                                self.push(task)?;
                                return Ok(());
                            }
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
                if let (Some(need), Query::Entry { head, seq, offset }) =
                    (self.key_body_root, &query)
                {
                    if *head == need.head && *seq == need.seq {
                        query = Query::KeyBody {
                            head: *head,
                            author: need.target.author,
                            hash: need.hash,
                            seq: *seq,
                            offset: *offset,
                        };
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
                let mut result = super::exchange(
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
                if matches!(
                    result.status,
                    Status::BodyNotHeld | Status::EvidenceUnavailable
                ) {
                    let reason = if result.status == Status::BodyNotHeld {
                        "body_not_held"
                    } else {
                        "evidence_unavailable"
                    };
                    let known_author = |head| {
                        self.authenticated_head
                            .filter(|known| known.head == head)
                            .map(|known| known.author)
                            .or_else(|| {
                                self.archive_selected_author
                                    .filter(|(selected_head, _)| *selected_head == head)
                                    .map(|(_, author)| author)
                            })
                    };
                    self.unavailable_response = match &query {
                        Query::Entry { head, seq, .. } => Some(UnavailableResponse {
                            author: known_author(*head),
                            head: *head,
                            lo: *seq,
                            hi: *seq,
                            reason,
                        }),
                        Query::Page { head, lo, hi, .. } => Some(UnavailableResponse {
                            author: known_author(*head),
                            head: *head,
                            lo: *lo,
                            hi: *hi,
                            reason,
                        }),
                        Query::KeyBody {
                            head, author, seq, ..
                        } => Some(UnavailableResponse {
                            author: Some(*author),
                            head: *head,
                            lo: *seq,
                            hi: *seq,
                            reason,
                        }),
                        _ => None,
                    };
                }
                if let Some(token) = result.offered_availability {
                    self.availability_ack = Some(token);
                }
                self.body_progress |= result.body_progress;
                if let Some(inventory) = result.inventory.as_ref() {
                    source
                        .offer_key_catalog(job, inventory.key_catalog, conn.serial())
                        .await?;
                    let offered = source
                        .offer_role(
                            job,
                            inbox,
                            inbox_generation,
                            self.room,
                            conn.serial(),
                            inventory.role,
                        )
                        .await?;
                    self.offered = self.offered.saturating_add(offered.added as u64);
                    if offered.full {
                        return Err(Error::Unreachable("history role hint capacity busy"));
                    }
                }
                let brought_now = result.brought || result.body_progress;
                self.brought |= brought_now;
                if brought_now {
                    self.work_committed
                        .store(true, std::sync::atomic::Ordering::Release);
                }
                if announcement_task {
                    if result.status == Status::Busy {
                        self.restore_announcement_task(task)?;
                        self.waiting = true;
                        return Ok(());
                    }
                    if result.status != Status::Complete
                        || result.continuation.is_some()
                        || !result.needs.is_empty()
                        || !result.verifiers.is_empty()
                        || result.body_ready.is_some()
                        || result.role_ready.is_some()
                        || !result.heads.is_empty()
                        || result.departure_receipt.is_some()
                    {
                        return Err(Error::MalformedBundle(
                            "history announcement inventory response",
                        ));
                    }
                    let Some(inventory) = result.inventory.take() else {
                        return Err(Error::MalformedBundle(
                            "history announcement inventory missing",
                        ));
                    };
                    for page in inventory.hints.chunks(64) {
                        let offered = source
                            .offer_inventory(job, inbox, inbox_generation, self.room, page)
                            .await?;
                        self.offered = self.offered.saturating_add(offered.added as u64);
                        self.rearmed = self.rearmed.saturating_add(offered.rearmed as u64);
                        let added = offered.added != 0;
                        self.brought |= added;
                        if added {
                            self.work_committed
                                .store(true, std::sync::atomic::Ordering::Release);
                        }
                    }
                    *retry_task = None;
                    return Ok(());
                }
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
                                if self.local_own_discovery {
                                    self.discovery_reply =
                                        Some((*head, conn.serial(), self.availability_captured));
                                }
                                if task.purpose == Purpose::Control && !self.local_own_discovery {
                                    if self.hint.is_some_and(|hint| {
                                        hint.author == author && hint.size > head.size
                                    }) {
                                        self.receipt_lower = result
                                            .own_head_incarnations
                                            .map(|incarnations| (conn.serial(), incarnations));
                                    }
                                    self.mine_held = Some(
                                        self.mine_held.map_or(head.size, |m| m.max(head.size)),
                                    );
                                }
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
                if matches!(query, Query::KeyAvailability { .. })
                    && result.status == Status::Complete
                {
                    self.key_availability_result = result.key_availability;
                }
                if let Some(inventory) = result.inventory {
                    for page in inventory.hints.chunks(64) {
                        let offered = source
                            .offer_inventory(job, inbox, inbox_generation, self.room, page)
                            .await?;
                        self.offered = self.offered.saturating_add(offered.added as u64);
                        self.rearmed = self.rearmed.saturating_add(offered.rearmed as u64);
                        let added = offered.added != 0;
                        self.brought |= added;
                        if added {
                            self.work_committed
                                .store(true, std::sync::atomic::Ordering::Release);
                        }
                    }
                }
                if matches!(result.status, Status::BodyNotHeld | Status::EvidenceUnavailable)
                    && self.key_body_root.is_some_and(|debt| {
                        matches!(query, Query::KeyBody { head, seq, .. } if head == debt.head && seq == debt.seq)
                    })
                {
                    self.key_body_unavailable = Some(if result.status == Status::BodyNotHeld {
                        KeyBodyUnavailable::Body
                    } else {
                        KeyBodyUnavailable::Evidence
                    });
                    self.tasks.clear();
                    self.replay = None;
                    self.push(Task { operation: Operation::ReclaimKeyUnavailable, ..task })?;
                    return Ok(());
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
                        if !self.decline(&source, job, inbox, author, head).await? {
                            return Ok(());
                        }
                    }
                    if let Some(hint) = self.hint {
                        if !self
                            .decline(&source, job, inbox, hint.author, hint.head)
                            .await?
                        {
                            return Ok(());
                        }
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
                        self.finish_archive_owned(job, &task, retry_task).await?;
                        self.tasks.clear();
                        return Ok(());
                    }
                    if result.status == Status::BodyNotHeld {
                        // The peer said it cannot fill this body: not asked for it again until
                        // its inventory names another head of the author (ADR-038 FX-29).
                        if let Query::Entry { head, .. } | Query::Page { head, .. } = &query {
                            let head = *head;
                            if let Some(author) = self.head_author(&source, job, head).await? {
                                if !self.decline(&source, job, inbox, author, head).await? {
                                    return Ok(());
                                }
                            }
                        }
                    }
                    return Err(Error::Unreachable(
                        "selected current body is unavailable or cancelled",
                    ));
                }
                if result.status == Status::EvidenceUnavailable && !self.archive {
                    if self.local_own_discovery {
                        self.discovery_unavailable =
                            Some((conn.serial(), self.availability_captured));
                    }
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
                        match (&query, self.hint) {
                            (Query::Head(author), Some(hint)) if hint.author == *author => {
                                if !self
                                    .decline(&source, job, inbox, *author, hint.head)
                                    .await?
                                {
                                    return Ok(());
                                }
                            }
                            _ => {}
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
                            | Query::KeyBody { head, .. }
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
                            Query::Inventory
                            | Query::KeyAvailability { .. }
                            | Query::Context(_) => None,
                        };
                        // The peer said it cannot serve this header or proof: the hint that
                        // depends on it is not pulled from that peer again until its inventory
                        // names another head of the author (ADR-038 FX-29), whether the flow
                        // was hinted or required. The route to the author's port below still
                        // runs once for this exact query.
                        if let Some(dependency) = dependency {
                            if !self
                                .decline(&source, job, inbox, dependency.author, dependency.head)
                                .await?
                            {
                                return Ok(());
                            }
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
                    // A Busy delivery may follow a committed body append but precede its
                    // body_ready handoff (authorization/ACK metadata can yield). Preserve Busy
                    // pacing and rebind this exact body from disk on the next allowed turn.
                    let retry = Task {
                        operation: if body {
                            Operation::ResumeWire(query)
                        } else {
                            task.operation.clone()
                        },
                        ..task
                    };
                    self.push(retry)?;
                    self.waiting = true;
                    return Ok(());
                }
                if result.status == Status::EvidenceUnavailable {
                    if self.archive && body {
                        self.finish_archive_owned(job, &task, retry_task).await?;
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
                        self.finish_archive_owned(job, &task, retry_task).await?;
                        self.tasks.clear();
                        return Ok(());
                    } else {
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
                }
                // No demand helper follows these derived tasks. In particular a role-only
                // header needs no body inspect after its exact Local continuation was pushed.
                *retry_task = None;
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
                    LocalProof::AlreadyHeld => {}
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
                if let Some(debt) = self.key_body_root {
                    if matches!(step, LocalStep::Entry { head, seq, .. } if head == debt.head && seq == debt.seq)
                        && result.published.is_some_and(|hash| hash != debt.hash)
                    {
                        return Err(Error::MalformedAtRest(
                            "recipient body completion changed entry",
                        ));
                    }
                }
                // The returned next/need now owns the continuation. Archive finalization
                // installs its own retry instead of duplicating a next phase pushed below.
                *retry_task = None;
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
                if let Some(pressure) = result.byte_pressure {
                    // The exact local continuation was retained above. Its worker and temporary
                    // buffers must leave before the actor starts the byte-release handoff.
                    self.byte_pressure = Some(pressure);
                    self.waiting = true;
                    return Ok(());
                }
                if result.busy {
                    // Local admission deliberately collapses disk pressure and an occupied
                    // sparse publication into `busy`. Recover the durable distinction here,
                    // after retaining this exact continuation: a newer local task must not
                    // park ahead of an older task in this Flow that owns the publication.
                    // No-owner remains ordinary capacity waiting; another Flow's owner is
                    // left untouched and its completion is the causal room wake.
                    let owner = source
                        .read(job, 0, |channel, store| {
                            Ok(Some(channel.history_publication_request(store)?))
                        })
                        .await?;
                    if let Lookup::Found(owner) = owner {
                        if let Some(owner) = owner.value.filter(|owner| *owner != task.request) {
                            if self.prioritize_publication_owner(owner) {
                                self.publication_owner_wait = None;
                                return Ok(());
                            }
                            self.publication_wait = true;
                            self.publication_owner_wait = Some(owner);
                        }
                    }
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
                    Some(LocalNeed::KeyBodyRetired) => {
                        if self.key_body_root.is_none() {
                            return Err(Error::MalformedAtRest("retired key body has no owner"));
                        }
                        self.tasks.clear();
                        self.replay = None;
                        self.push(Task {
                            operation: Operation::ReclaimKeyUnavailable,
                            ..task
                        })?;
                    }
                    Some(LocalNeed::StagedBody) => {
                        let LocalStep::Entry { head, seq, .. } = step else {
                            return Err(Error::MalformedAtRest("body dependency has no entry"));
                        };
                        if task.purpose == Purpose::History {
                            self.finish_archive_owned(job, &task, retry_task).await?;
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
                    self.finish_archive_owned(job, &task, retry_task).await?;
                }
            }
            Operation::ReclaimKeyUnavailable => {
                if !self.reclaim_stage(Purpose::Control, job, true).await? {
                    self.push(task)?;
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
            Operation::FinishArchive => {
                self.finish_archive(job).await?;
                self.tasks.clear();
            }
            Operation::Governance => {
                let generation = self.generation;
                let node = self.node;
                let instance = self.instance;
                let room = self.room;
                let epoch = self.epoch;
                let advanced = source
                    .write_owned(
                        job,
                        (128, 4 * 1024 * 1024, false),
                        move |channel, store| {
                            if super::authorization_generation(store, node, room, instance, epoch)?
                                != generation
                            {
                                return Err(Error::Profile("history authorization changed"));
                            }
                            channel.prepare_history_governance_projection(crate::time::Ms(now))
                        },
                        |pending, store| Ok(pending.run(store)),
                        |channel, store, completed| {
                            channel.finish_history_governance_projection(store, completed)
                        },
                    )
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
    ) -> Result<StageStart> {
        let is_key = self.key_body_root.is_some() && purpose == Purpose::Control;
        let wake = is_key.then(|| self.slots.key_released());
        if !self.slots.claim(purpose, request, is_key) {
            self.slot_wait = wake.map(|wake| {
                wake as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>
            });
            return Ok(StageStart::Waiting);
        }
        if let Some(index) = body_slot(purpose, self.key_body_root.is_some()) {
            self.owners[index] = Some(request);
        }
        if let Some(staging) = self.stage(purpose) {
            let snapshot = inspect(&staging.context, job)
                .await?
                .ok_or(Error::Profile("current history state missing"))?;
            if snapshot.state().bounds.head == head && snapshot.state().bounds.lo == seq {
                return Ok(StageStart::Ready);
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
            return Ok(if is_key {
                StageStart::Reclaimed
            } else {
                StageStart::Waiting
            });
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
        Ok(StageStart::Ready)
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
            if let Some(index) = body_slot(purpose, self.key_body_root.is_some()) {
                if let Some(request) = self.owners[index].take() {
                    self.slots
                        .release(purpose, request, self.key_body_root.is_some());
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

    async fn finish_archive_owned(
        &mut self,
        job: &Job,
        task: &Task,
        retry_task: &mut Option<Task>,
    ) -> Result<()> {
        *retry_task = Some(Task {
            operation: Operation::FinishArchive,
            ..task.clone()
        });
        self.finish_archive(job).await
    }

    async fn finish_archive(&mut self, job: &Job) -> Result<()> {
        let Some(staging) = self.history.clone() else {
            return Ok(());
        };
        let job = job.clone();
        let next = self.archive_next;
        let initial = self.own_recovery_checkpoint;
        let (status, progressed) = tokio::task::spawn_blocking(
            move || -> Result<(crate::node::api::HistoryDemandStatus, bool)> {
                let mut snapshot = demand::inspect(&staging.context, &job)?
                    .ok_or(Error::Profile("archive state missing"))?;
                let mut active = staging
                    .active
                    .lock()
                    .map_err(|_| Error::Profile("history activation lock failed"))?;
                if snapshot.state().request != active.request()
                    || snapshot.state().binding != active.binding()
                {
                    return Err(Error::Profile("archive finalization activation changed"));
                }
                // Role-only admission can already have completed this request. A terminal
                // or deliberately paused activation is a durable result, never permission
                // to checkpoint again through an invalid live handle.
                if active.matches(snapshot.state())
                    && snapshot.state().body.is_none()
                    && !snapshot.state().reclaiming()
                {
                    if let Some(next) = next {
                        // This branch ends More/Complete, so it never needs a subsequent
                        // pause. Prepay only its work and single reload before the commit.
                        let work = demand::AdmissionCharge::reserve(&job)?;
                        let reload = demand::AdmissionCharge::reserve(&job)?;
                        let state = snapshot.state();
                        let cursor = (next >= state.bounds.lo && state.remaining > 0).then_some(
                            super::Continuation {
                                query_kind: 4,
                                head: state.bounds.head,
                                lo: state.bounds.lo,
                                hi: state.bounds.hi,
                                next_seq: next,
                                entry: None,
                                offset: 0,
                                entries_remaining: state.remaining,
                            },
                        );
                        demand::checkpoint_precharged(
                            &staging.context,
                            &mut active,
                            if cursor.is_some() {
                                demand::Progress::More
                            } else {
                                demand::Progress::Complete
                            },
                            cursor.as_ref(),
                            &work,
                        )?;
                        snapshot = demand::inspect_precharged(&staging.context, reload)?
                            .ok_or(Error::Profile("archive state missing"))?;
                    }
                }
                if snapshot.state().progress(Some(&active)) == demand::Progress::Pending {
                    let work = demand::AdmissionCharge::reserve(&job)?;
                    let reload = demand::AdmissionCharge::reserve(&job)?;
                    // This explicit quantum has ended; no worker will silently retry it.
                    // Keep its exact body/cursor and make Resume the next action.
                    demand::pause_precharged(&staging.context, &mut active, &work)?;
                    snapshot = demand::inspect_precharged(&staging.context, reload)?
                        .ok_or(Error::Profile("archive state missing"))?;
                }
                let progressed =
                    initial.is_some_and(|old| old != OwnRecoveryCheckpoint::of(snapshot.state()));
                Ok((
                    crate::node::actor::saved_history_status(snapshot.state(), None, Some(&active)),
                    progressed,
                ))
            },
        )
        .await
        .map_err(|_| Error::Profile("history status worker stopped"))??;
        self.archive_status = Some(status);
        self.own_recovery_progress = progressed;
        Ok(())
    }
}
impl Drop for Flow {
    fn drop(&mut self) {
        self.cancel();
        if let Some(request) = self.owners[2].take() {
            self.slots.release(Purpose::Control, request, true);
        }
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
