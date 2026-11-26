//! Local bounded admission slices and their durable retirement.

use super::source::{Lookup, Source};
use super::{EntryPhase, LocalNeed, LocalProof, LocalStep, Query, Receiver, RequestId};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::history_budget::Job;
use crate::node::history_demand::{self as demand, Context};
use crate::node::store::{ReceivedFlow, Store};
use crate::transport::stream_transport::Fence;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

const MAX_TASKS: usize = 128;
/// A local edge an admission flow waits for.
type Wake = Pin<Box<dyn Future<Output = ()> + Send>>;
#[derive(Clone)]
enum Operation {
    LocalProof(Query),
    Local(LocalStep),
    Governance,
}

/// How long one turn keeps running local slices before it yields to the actor.
const LOCAL_TURN_BUDGET: std::time::Duration = std::time::Duration::from_millis(20);
/// How many local slices one turn runs at most.
const LOCAL_SLICES_PER_TURN: u32 = 64;
/// Fold steps an entry slice may take in one turn before it waits for the actor's fold hook
/// (ADR-037 R11): a hold on the fold cycled the need 32 times a turn, 77 turns a second.
const GOVERNANCE_STEPS_PER_TURN: u8 = 4;

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
    operation: Operation,
}

pub(crate) struct Flow {
    pub(crate) room: Digest32,
    pub(crate) peer: Digest32,
    pub(crate) node: Digest32,
    pub(crate) epoch: u64,
    pub(crate) instance: [u8; 16],
    pub(crate) generation: Digest32,
    pub(crate) shared: Arc<crate::node::channel::RoomLock>,
    pub(crate) waiting: bool,
    pub(crate) byte_pressure: Option<crate::node::history_budget::BytePressure>,
    pub(crate) slot_wait:
        Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>>,
    pub(crate) published: bool,
    pub(crate) rendered: bool,
    pub(crate) governance: bool,
    /// A control-effects step made an author's Session controls current (`LocalResult::
    /// controls_ready`): its admission task raises permission news for the room's tellers.
    pub(crate) controls_ready: bool,
    /// Set at the durable/user-visible work edge and drained by the actor before it classifies
    /// the worker result. This survives any later cancellation, error or supersession.
    pub(crate) work_committed: Arc<std::sync::atomic::AtomicBool>,
    /// Changed, signature-verified own observation committed by the physical receiver.
    pub(crate) own_head_observed: Arc<std::sync::atomic::AtomicBool>,
    /// A local trust edit invalidated this flow's grant. Retire it without blaming the peer;
    /// the controller re-arms its exact scalar hint under the new generation.
    pub(crate) authorization_changed: bool,
    /// Durability debt created by this flow alone. It follows every receiver handoff and is
    /// detached whenever the flow returns to the actor.
    received: ReceivedFlow,
    tasks: Vec<Task>,
    // One exact suspended foreground root. Intermediate pre-body continuations
    // are re-derived from durable receipts after the current dependency finishes.
    replay: Option<Task>,
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
    /// Immutable identity of this cleanup obligation. `request` changes as continuations are
    /// derived; retirement ownership must not.
    retirement_request: RequestId,
    request: RequestId,
    /// A popped task remains owned even while an archive keeps `request` at its demand root.
    selected_request: Option<RequestId>,
    cleanup_store: Arc<Store>,
    failed_settlement: Option<crate::node::store::ReceivedSettlement>,
    cleanup_budget: Arc<crate::node::history_budget::Budget>,
    actor_incarnation: Option<u64>,
    cleanup_after: Option<[u8; 64]>,
    live_context: Option<Arc<Context>>,
    control_context: Arc<Context>,
    initialized: bool,
    /// An admission flow (design simple-sync §3): the node's frontier, whose room ready set it
    /// takes its roots from one at a time. Such a flow fetches nothing: a need ends its root.
    frontier: Option<Arc<super::pull::Frontier>>,
    /// An admission flow's room record: read before each local step, so a need for a newer
    /// head of an author names the committed head that step could have seen (`resolve_need`).
    record: Option<Arc<crate::node::channel::RoomSnapshotCell>>,
    /// An admission flow's current root, the checked entry the delivering connection holds in
    /// memory, and whether it is settled (`settle_root`).
    admit_root: Option<(super::pull::Ready, bool)>,
    /// The root this admission held unsettled when it failed (`fail`): owned here, neither
    /// waiting for a head nor fetched again, until the failed flow's retirement ends, then given
    /// back to the room's ready set (`Drop`). The room's admission meanwhile waits for its
    /// recovery edge (`actor/admission.rs` `start_admissions`).
    failed: Option<super::pull::Ready>,
}
// The retained-flow permit includes the exact Vec allocation, the scalar replay root,
// and conservative room for the one-object receiver handoff and small staging handles.
// Dependency depth cannot increase this allocation: pre-body ancestry is replayed above.
const _: () = assert!(
    std::mem::size_of::<Flow>() + MAX_TASKS * std::mem::size_of::<Task>() + 4096
        <= crate::node::history_budget::FLOW_STATE_BYTES
);

impl Flow {
    pub(crate) fn retirement_request(&self) -> RequestId {
        self.retirement_request
    }

    pub(crate) fn actor_incarnation(&self) -> Option<u64> {
        self.actor_incarnation
    }

    /// The room's one local admission, taking its ready entries in frontier order.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit(
        room: Digest32,
        node: Digest32,
        epoch: u64,
        shared: Arc<crate::node::channel::RoomLock>,
        live: Arc<Context>,
        control: Arc<Context>,
        cleanup_store: Arc<Store>,
        cleanup_budget: Arc<crate::node::history_budget::Budget>,
        actor_incarnation: Option<u64>,
        frontier: Arc<super::pull::Frontier>,
        record: Arc<crate::node::channel::RoomSnapshotCell>,
    ) -> Result<Self> {
        let request = request_id()?;
        Ok(Self {
            room,
            peer: node,
            node,
            epoch,
            instance: [0; 16],
            generation: [0; 32],
            shared,
            waiting: false,
            byte_pressure: None,
            slot_wait: None,
            published: false,
            rendered: false,
            governance: false,
            controls_ready: false,
            work_committed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            own_head_observed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            authorization_changed: false,
            received: ReceivedFlow::new(room),
            tasks: Vec::with_capacity(MAX_TASKS),
            replay: None,
            governance_wait: false,
            publication_wait: false,
            publication_owner_wait: None,
            governance_cycles: 0,
            retirement_request: request,
            request,
            selected_request: None,
            cleanup_store,
            failed_settlement: None,
            cleanup_budget,
            actor_incarnation,
            cleanup_after: None,
            live_context: Some(live),
            control_context: control,
            initialized: false,
            frontier: Some(frontier),
            record: Some(record),
            admit_root: None,
            failed: None,
        })
    }

    /// An admission's next root, once the previous one's work has left the stack: the previous
    /// root, if neither published nor dropped for a need, is owed again; the next is ONE entry
    /// of the room's ready set (`Frontier::take`): urgent (a control, or a position an
    /// admission waiter waits for) and ordinary alternating when both are ready, each class
    /// taking one entry of each author that has one, in rotation, before a second of any (an
    /// author's urgent entries oldest first; its ordinary ones newest and oldest in turn,
    /// `pull::ReadySet`). No batch and no order by id; controls do not drain ahead of posts: an
    /// ordinary author's next entry waits for at most one root of each other ordinary author
    /// and one urgent root before each (journey-6, y1: the author whose id sorted first kept
    /// every newly ready batch ahead of the roots not tried yet; why-j16: a newcomer's grant
    /// queued behind every member's posts).
    fn next_admission_root(&mut self) -> Result<()> {
        let Some(frontier) = self.frontier.clone() else {
            return Ok(());
        };
        self.settle_root(None, None, None);
        let Some(ready) = frontier.take(self.room) else {
            self.admit_root = None;
            return Ok(());
        };
        let (head, seq) = (ready.head, ready.entry.skeleton.seq);
        let body = ready.entry.payload.is_some();
        self.admit_root = Some((ready, false));
        let request = request_id()?;
        self.push(Task {
            request,
            operation: Operation::Local(LocalStep::Entry {
                request,
                head,
                seq,
                body,
                role_header: false,
                phase: EntryPhase::Start,
            }),
        })
    }

    /// An admission's current root ends, if not settled yet: as published when `published`
    /// names its author and position, under whatever head (the entries waiting for that
    /// position go to the ready set); with `need`, dropped for it, waiting for position `at`
    /// when the need is the entry of a position not admitted here yet, and owed again when it is
    /// met; with neither, owed again. A publication of any other position (a nested dependency)
    /// releases that position's waiters at once.
    fn settle_root(
        &mut self,
        published: Option<(Digest32, u64)>,
        need: Option<(
            super::pull::Need,
            Option<Arc<crate::log::history::SignedHead>>,
        )>,
        at: Option<(Digest32, u64)>,
    ) {
        let Some(frontier) = self.frontier.clone() else {
            return;
        };
        let root = self.admit_root.as_mut().filter(|(_, settled)| !settled);
        let position = root
            .as_ref()
            .map(|(ready, _)| (ready.entry.skeleton.author_id, ready.entry.skeleton.seq));
        if let Some((author, seq)) = published.filter(|p| Some(*p) != position) {
            frontier.published(self.room, author, seq);
            return;
        }
        let Some((ready, settled)) = root else {
            return;
        };
        let (author, seq) = (ready.entry.skeleton.author_id, ready.entry.skeleton.seq);
        *settled = true;
        if published.is_some() {
            frontier.published(self.room, author, seq);
            return;
        }
        let kept = need.as_ref().map(|_| (self.peer, ready.clone()));
        frontier.settled(self.room, author, seq, need, kept, at);
    }

    /// The frontier's need for a wire dependency of an admission flow's `step`, with what it
    /// names read once, here, so that no loop reads it again. Every need is keyed by the author
    /// and position it is about (`pull::Need`), never by the head the step found it missing
    /// under; the head the step named is kept beside it only as a fallback to ask under.
    ///
    /// - A header, an inclusion proof or an entry: the receipt of that position.
    /// - A control proof: the author's control coverage through its end.
    /// - A consistency proof from `from` under this node's committed head of the author (an
    ///   entry's or a parent's own prefix [1, from]: `from` is at most that head's size, and at
    ///   its size the prefix is that very head): the receipt of position `from`, which any
    ///   committed head of the author proves. Nothing newer is missing (a departure naming
    ///   another author's last entry waited for a head of carol past 7 while carol's history was
    ///   7 on every node: fjw8).
    /// - A consistency proof under another head (a promotion from this node's committed head):
    ///   below the committed size, the receipt of position `from`, as above; at or above it, a
    ///   newer committed head of the author, met by ANY being reached (the step that asked it
    ///   then compares with that head).
    /// - A newer head of an author: a committed head past the author's committed size in the
    ///   room's record read BEFORE the step that found it missing (`before`). Read after the
    ///   step, a head committed meanwhile (by a connection's answer) would be the anchor, and the
    ///   need, already met by that head, would wait for one beyond it that may never come (r18:
    ///   gyde62/9 waited for a head of r3dtvp past 12, committed 1 ms after the validator
    ///   looked; nine entries waited for gyde62/9 and no loop asked). Read before, the anchor is
    ///   at most what the step saw: a head committed meanwhile meets the need at the next plan
    ///   and the step runs again with it.
    fn resolve_need(
        read: &crate::node::channel::entry_store::Read<'_>,
        before: Option<&crate::node::channel::RoomSnapshot>,
        step: Option<&LocalStep>,
        query: Option<&Query>,
    ) -> Result<
        Option<(
            super::pull::Need,
            Option<Arc<crate::log::history::SignedHead>>,
        )>,
    > {
        use super::pull::Need;
        let (head, seq, controls) = match query {
            Some(Query::Head(author)) => {
                let size = before
                    .and_then(crate::node::channel::RoomSnapshot::history)
                    .and_then(|history| history.author(author))
                    .map_or(
                        0,
                        crate::node::channel::held_history::HeldAuthor::committed_size,
                    );
                return Ok(Some((
                    Need::Head {
                        author: *author,
                        size,
                    },
                    None,
                )));
            }
            Some(Query::Proof {
                head,
                kind: super::ProofKind::Control,
                from,
                to,
            }) => (*head, *to, Some(*from)),
            Some(
                Query::Proof {
                    head, from: seq, ..
                }
                | Query::Header { head, seq }
                | Query::Entry { head, seq, .. },
            ) => (*head, *seq, None),
            _ => match step {
                Some(LocalStep::Entry { head, seq, .. }) => (*head, *seq, None),
                _ => return Ok(None),
            },
        };
        let Some(signed) = read.history_head(&head)? else {
            return Ok(None);
        };
        let author = signed.binding.author;
        let need = match (query, controls) {
            (_, Some(lo)) => Need::Controls {
                author,
                lo,
                hi: seq,
            },
            (
                Some(Query::Proof {
                    kind: super::ProofKind::Consistency,
                    ..
                }),
                None,
            ) => {
                let committed = read
                    .sparse_author(&author, signed.binding.scope)?
                    .and_then(|state| state.committed);
                if committed == Some(head) {
                    Need::Position { author, seq }
                } else {
                    let size = match committed {
                        Some(id) => read.history_head(&id)?.map_or(0, |head| head.root.leaves),
                        None => 0,
                    };
                    if seq >= size {
                        return Ok(Some((Need::Head { author, size }, None)));
                    }
                    Need::Position { author, seq }
                }
            }
            _ => Need::Position { author, seq },
        };
        Ok(Some((need, Some(Arc::new(signed)))))
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
            || self.selected_request == Some(request)
            || self.tasks.iter().any(|task| task.request == request)
            || self
                .replay
                .as_ref()
                .is_some_and(|task| task.request == request)
    }
    /// When authorization changed: the root this admission has not settled goes back to the
    /// room's ready set with the entry it holds, still in admission, and the room's fresh
    /// admission takes it under the new authorization; nothing is dropped or fetched again.
    pub(crate) fn give_back_admission(&mut self) {
        let Some(frontier) = self.frontier.clone() else {
            return;
        };
        if let Some((ready, false)) = self.admit_root.take() {
            frontier.give_back(self.room, ready);
        }
    }

    /// A failed admission (any error its task ends with, except its own cancellation): the root
    /// it held unsettled stays in admission inside this flow (`failed`), and the flow stops
    /// before it is retired. Every failure, before initialization, in any phase or between
    /// roots, ends here and nowhere else; the room's admission then waits for its recovery
    /// edge (`pull::Frontier::failed_admission_news`).
    pub(crate) fn fail(&mut self) {
        if self
            .admit_root
            .as_ref()
            .is_some_and(|(_, settled)| !settled)
        {
            self.failed = self.admit_root.take().map(|(ready, _)| ready);
        }
        self.park();
    }

    /// Stop a failed admission before its flow is retired.
    pub(crate) fn park(&mut self) {
        self.cancel();
        self.byte_pressure = None;
        self.slot_wait = None;
    }

    pub(crate) fn done(&self) -> bool {
        self.tasks.is_empty()
            && self.replay.is_none()
            && self
                .frontier
                .as_ref()
                .is_none_or(|frontier| !frontier.has_ready(self.room))
    }

    /// The exact request whose sparse publication is between Begin and Cleanup in the next
    /// local slice. This is a durable room-wide exclusion, not ordinary retained Flow state: it
    /// must reach Cleanup (or explicit retirement rollback) before this Flow can be parked.
    fn active_publication_owner(&self) -> Option<RequestId> {
        let next = self.tasks.last().or(self.replay.as_ref())?;
        match &next.operation {
            Operation::Local(LocalStep::Entry {
                request,
                phase: EntryPhase::Publish(_) | EntryPhase::Cleanup(_),
                ..
            }) => Some(*request),
            _ => None,
        }
    }

    pub(crate) fn cancellation_handles(&self) -> Vec<demand::Cancellation> {
        let mut handles = Vec::with_capacity(2);
        if let Some(context) = &self.live_context {
            handles.push(context.cancellation());
        }
        handles.push(self.control_context.cancellation());
        handles
    }
    pub(crate) fn cancel(&self) {
        if let Some(context) = &self.live_context {
            context.cancellation().cancel();
        }
        self.control_context.cancellation().cancel();
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
        self.cancel();
        // A parked flow owns no worker. Retirement admits one independent large-control job for
        // this bounded local slice and gives it back before the flow is retained again.
        let cleanup_job = self
            .cleanup_budget
            .admit_job(self.node, crate::node::history_budget::Lane::LargeControl)
            .await;
        const CLEANUP_ENVELOPE: usize = 6 * 1024 * 1024;
        let charge = match cleanup_job.reserve_or_pressure(CLEANUP_ENVELOPE) {
            Ok(charge) => charge,
            Err(Error::HistoryCapacity(pressure)) => {
                return Ok(RetirementStep::Wait(RetirementWait::Bytes(*pressure)));
            }
            Err(error) => return Err(error),
        };
        let room = self.shared.clone();
        let store = self.cleanup_store.clone();
        let request = self.request;
        let retirement_request = self.retirement_request;
        let instance = self.instance;
        let after = self.cleanup_after;
        let committed = Arc::clone(&self.work_committed);
        enum Slice {
            Gone,
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
            let wake = channel.history_publication_wake();
            let publication_owner = channel.history_publication_request(&store)?;
            if channel.post_pending()
                || (channel.history_publication_busy(&store)? && publication_owner != Some(request))
            {
                return Ok(Slice::Publication(publication_owner, wake));
            }
            let pending = channel.prepare_history_publication(&store, None, Some(request))?;
            let owner = Arc::new(());
            let mut pin =
                channel.reserve_pending_history_write(&store, Arc::clone(&owner), true)?;
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
            let settled =
                channel.settle_history_publication_flow(&store, request, retirement_request);
            let result = result.and_then(|slice| settled.map(|()| slice));
            channel.release_pending_text(&owner, false);
            let publication = if owns {
                let published = channel.publish_history_read(Arc::clone(&store)).map(|_| ());
                if published.is_err() {
                    pin.retain_saved_read();
                }
                published
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
            Slice::Source(done, next) => (done, next),
            Slice::Publication(owner, wake) => {
                // A foreground flow may suspend publication A while a freshly derived request B is
                // its current scalar. Verifier cleanup for B correctly waits while A is publishing,
                // but retirement must first select A when this same Flow still owns it. Otherwise
                // B waits for A forever and the actor retains a room-busy Flow with no running
                // worker. The task/replay stack is the exact ownership set; an unrelated owner's
                // publication remains untouched and is retried after its own causal completion.
                if let Some(owner) = owner.filter(|owner| *owner != request) {
                    let owned = self.owns_request(owner);
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
        if self.selected_request == Some(request) {
            self.selected_request = None;
        }
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
            .or_else(|| self.replay.as_ref().map(|task| task.request))
            .or(self.selected_request);
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

    fn receiver(
        &self,
        store: Arc<Store>,
        fence: Arc<Fence>,
        deadline: tokio::time::Instant,
    ) -> Receiver {
        let receiver = Receiver::new(
            self.shared.clone(),
            store,
            self.peer,
            self.epoch,
            self.generation,
            self.node,
            self.received.clone(),
            None,
            false,
            // The admission's root carries the live package body debt an explicit Body
            // answer fills (`pull::Ready::key_body`): its typed refill checks it again.
            self.admit_root.as_ref().and_then(|(held, _)| held.key_body),
            fence,
            deadline,
            Arc::clone(&self.work_committed),
            Arc::clone(&self.own_head_observed),
            self.retirement_request,
        );
        match &self.admit_root {
            Some((held, _)) => receiver.with_held(held.clone()),
            None => receiver,
        }
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

    /// Local slices back to back, or one response quantum (ADR-037 R11). The caller retains its
    /// worker/port slot through this return, including every spawned blocking worker, even after
    /// cancellation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn turn(
        &mut self,
        store: Arc<Store>,
        job: &Job,
        fence: Arc<Fence>,
        deadline: tokio::time::Instant,
        now: u64,
    ) -> Result<()> {
        self.waiting = false;
        self.byte_pressure = None;
        self.governance_wait = false;
        self.governance_cycles = 0;
        // Local slices run back to back until a wait, completion, error, or fairness budget.
        let mut quantum_started = tokio::time::Instant::now();
        let mut slices = 0u32;
        let mut result = loop {
            let result = self
                .turn_inner(store.clone(), job, fence.clone(), deadline, now)
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
                || self.done()
                || (!publication_active
                    && (slices >= LOCAL_SLICES_PER_TURN
                        || quantum_started.elapsed() >= LOCAL_TURN_BUDGET
                        || tokio::time::Instant::now() >= deadline))
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
        if result.as_ref().is_err_and(authorization_changed) {
            self.authorization_changed = true;
            result = Ok(());
        }
        // Busy is a retained exact need. A count of turns cannot dispose its root; the semantic
        // response/progress edge is the only thing that advances it, while the actor's named
        // Busy backoff prevents spinning between those edges.
        // A successful partial turn keeps this exact owner inside the returned Flow, allowing a
        // sparse source and its later semantic effect to share one durability debt. Every path
        // which stops carrying the flow forward settles first; a failure keeps the Flow owned by
        // retirement, which retries this same debt instead of lending it to a later transaction.
        if result.is_err() || self.authorization_changed || self.done() {
            let settlement = self.settle_received(store).await;
            if result.is_ok() {
                settlement?;
            }
        }
        result
    }

    /// An admission flow that stopped short of done waits for exactly the local edge its stop
    /// named, then runs again (design simple-sync §3): a body slot's or a publication's release,
    /// a byte release, or the room's publication or save when another owns it. A spent slice
    /// budget or a governance fold still folding waits for nothing: the next turn continues it.
    /// Returns what it waited on, for diagnostics.
    pub(crate) async fn admission_wait(
        &mut self,
        store: &Store,
        fence: &Fence,
    ) -> Result<&'static str> {
        let (what, wake): (&'static str, Option<Wake>) = if let Some(wake) = self.slot_wait.take() {
            ("slot", Some(wake))
        } else if let Some(pressure) = self.byte_pressure.take() {
            ("bytes", Some(Box::pin(pressure.released())))
        } else if self.waiting && self.active_publication_owner().is_none() {
            let room = self.shared.lock().await;
            if room.post_pending() {
                ("post_pending", Some(room.history_publication_wake()))
            } else if room.history_publication_busy(store)? {
                ("publication_busy", Some(room.history_publication_wake()))
            } else {
                ("none", None)
            }
        } else {
            ("none", None)
        };
        if let Some(wake) = wake {
            tokio::select! {
                biased;
                () = fence.retired() => return Err(Error::Unreachable("history request cancelled")),
                () = wake => {}
            }
        }
        Ok(what)
    }

    // One bounded turn uses the same stream, job and deadline throughout.
    #[allow(clippy::too_many_arguments)]
    async fn turn_inner(
        &mut self,
        store: Arc<Store>,
        job: &Job,
        fence: Arc<Fence>,
        deadline: tokio::time::Instant,
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
            None,
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
            let owner = source.publication_owner(job).await?;
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
        if self.tasks.is_empty() {
            if let Some(root) = self.replay.take() {
                self.tasks.push(root);
            } else {
                self.next_admission_root()?;
            }
        }
        let Some(task) = self.tasks.pop() else {
            return Ok(());
        };
        self.selected_request = Some(task.request);
        self.request = task.request;
        let mut retry_task = Some(task.clone());
        let result = self
            .execute_task(
                task,
                source,
                store,
                job,
                fence,
                deadline,
                now,
                &mut retry_task,
            )
            .await;
        let result = match result {
            Err(Error::HistoryCapacity(pressure)) => {
                if let Some(task) = retry_task {
                    self.push(task)?;
                }
                self.byte_pressure = Some(*pressure);
                self.waiting = true;
                Ok(())
            }
            // What the validator refuses in an admission root's evidence (`MalformedBundle`), or
            // a fork it records (`MalformedGovernance`), is about its author's own history: it
            // fails that root alone, and the room's admission goes on with its next root
            // (journey-6, y1: one entry the validator refused ended the room's whole admission
            // and 28 roots were fetched again). The root is not fetched again: it was fetched
            // and verified, so it stays held, waiting for the one thing that can change such a
            // refusal, a newer committed head of its author (its next positions, their
            // controls, its promotion), and is tried again then (r24: a failure settled as owed
            // again was asked again at once, answered, failed again: 1,830 asks).
            Err(Error::MalformedBundle(_) | Error::MalformedGovernance(_))
                if self
                    .admit_root
                    .as_ref()
                    .is_some_and(|(_, settled)| !settled) =>
            {
                self.tasks.clear();
                self.replay = None;
                let record = self.record.as_ref().and_then(|cell| cell.current());
                let wait = self.admit_root.as_ref().map(|(ready, _)| {
                    let author = ready.entry.skeleton.author_id;
                    let size = record
                        .as_deref()
                        .and_then(crate::node::channel::RoomSnapshot::history)
                        .and_then(|history| history.author(&author))
                        .map_or(
                            0,
                            crate::node::channel::held_history::HeldAuthor::committed_size,
                        );
                    (super::pull::Need::Head { author, size }, None)
                });
                self.settle_root(None, wait, None);
                Ok(())
            }
            // Any other failure is this node's, not the root's: a store fault, a local
            // precondition or race, the dependency stack's bound. It ends the room's admission
            // as a failed flow (`Flow::fail`), whose retirement owns its publication and
            // cleanup (`actor/admission.rs`). A changed authorization renews the admission
            // instead (`turn`).
            result => result,
        };
        if result.is_ok() {
            self.selected_request = None;
        }
        result
    }

    /// Each fallible helper owns either the still-popped task or a more precise finalization
    /// continuation. Successfully derived tasks remain on the stack and are never rolled back.
    #[allow(clippy::too_many_arguments)]
    async fn execute_task(
        &mut self,
        task: Task,
        source: Source,
        store: Arc<Store>,
        job: &Job,
        fence: Arc<Fence>,
        deadline: tokio::time::Instant,
        now: u64,
        retry_task: &mut Option<Task>,
    ) -> Result<()> {
        let receiver = self.receiver(store, fence, deadline);
        match task.operation.clone() {
            Operation::LocalProof(query) => {
                let before = self.record.as_ref().and_then(|cell| cell.current());
                match receiver
                    .local_proof(job, task.request, query.clone())
                    .await?
                {
                    LocalProof::Verified(binding) => self.push(Task {
                        request: binding.request,
                        operation: Operation::Local(LocalStep::Verify(binding)),
                    })?,
                    LocalProof::Missing => {
                        // Not provable from this node's own rows: the frontier keeps the need.
                        let room = Arc::clone(&self.shared).lock_owned().await;
                        let need = Self::resolve_need(
                            &room.history_read(&self.cleanup_store)?,
                            before.as_deref(),
                            None,
                            Some(&query),
                        )?;
                        self.tasks.clear();
                        self.replay = None;
                        self.settle_root(None, need, None);
                        drop(room);
                        return Ok(());
                    }
                    LocalProof::Busy => {
                        self.push(task)?;
                        *retry_task = None;
                        // A local proof can meet a publication owned by another flow.
                        // Retain its causal wake just as for a local wire admission.
                        let readiness = source.publication_readiness(job).await?;
                        self.waiting = true;
                        self.publication_owner_wait = None;
                        if let Lookup::Found(readiness) = readiness {
                            let readiness = readiness.value;
                            if !readiness.busy {
                                self.waiting = false;
                            } else if readiness
                                .owner
                                .is_some_and(|owner| self.prioritize_publication_owner(owner))
                            {
                                self.publication_wait = false;
                                self.waiting = false;
                            } else {
                                self.publication_wait = readiness.owner.is_some();
                                self.publication_owner_wait = readiness.owner;
                                self.slot_wait = Some(readiness.wake);
                            }
                        }
                    }
                }
            }
            Operation::Local(step) => {
                let before = self.record.as_ref().and_then(|cell| cell.current());
                let result = receiver.local_step(job, step, crate::time::Ms(now)).await?;
                self.controls_ready |= result.controls_ready;
                if self.frontier.is_some() {
                    // An admission flow fetches nothing: a dependency on evidence or a body this
                    // node does not hold ends it, and its entries wait for that need, held by the
                    // node's frontier, which a connection's loop asks for (design §1).
                    // A proof is first built from this node's own rows (`LocalProof`, below).
                    let wire = match &result.need {
                        Some(LocalNeed::Wire(Query::Proof { .. })) => None,
                        Some(LocalNeed::Wire(query)) => Some(Some(query.clone())),
                        Some(LocalNeed::StagedBody | LocalNeed::KeyBodyRetired) => Some(None),
                        _ => None,
                    };
                    if let Some(query) = wire {
                        // The entry of a position this node has not admitted (a control
                        // source's entry or body): the root waits for that position's admission.
                        // It is registered under the room's lock, so the position is either not
                        // admitted yet (its admission moves the root to the ready set) or
                        // admitted (then its need is the ordinary one, met at once by the next
                        // plan). A header, a proof or coverage is waited for as itself.
                        let room = Arc::clone(&self.shared).lock_owned().await;
                        let root = self.admit_root.as_ref().map(|(ready, _)| {
                            (ready.entry.skeleton.author_id, ready.entry.skeleton.seq)
                        });
                        let entry = match (&query, &step, &result.need) {
                            (Some(Query::Entry { head, seq, .. }), _, _)
                            | (
                                None,
                                LocalStep::Entry { head, seq, .. },
                                Some(LocalNeed::StagedBody),
                            ) => Some((*head, *seq)),
                            _ => None,
                        };
                        let at = match entry {
                            Some((head, seq)) => {
                                let read = room.history_read(&self.cleanup_store)?;
                                match read.history_head(&head)? {
                                    Some(target)
                                        if Some((target.binding.author, seq)) != root
                                            && read
                                                .history_position_header(
                                                    &target.binding.author,
                                                    seq,
                                                )?
                                                .is_none() =>
                                    {
                                        Some((target.binding.author, seq))
                                    }
                                    _ => None,
                                }
                            }
                            None => None,
                        };
                        let need = Self::resolve_need(
                            &room.history_read(&self.cleanup_store)?,
                            before.as_deref(),
                            Some(&step),
                            query.as_ref(),
                        )?;
                        self.tasks.clear();
                        self.replay = None;
                        self.settle_root(None, need, at);
                        drop(room);
                        return Ok(());
                    }
                    // Every publication settles by author and position, whatever head its step
                    // named: the root's own, or a nested dependency's (a control source or a
                    // checkpoint target), whose waiters it releases at once.
                    if let (Some(_), LocalStep::Entry { head, seq, .. }) = (result.published, step)
                    {
                        let author = match self
                            .admit_root
                            .as_ref()
                            .filter(|(ready, _)| ready.head == head)
                        {
                            Some((ready, _)) => Some(ready.entry.skeleton.author_id),
                            None => {
                                let room = Arc::clone(&self.shared).lock_owned().await;
                                let read = room.history_read(&self.cleanup_store)?;
                                read.history_head(&head)?.map(|head| head.binding.author)
                            }
                        };
                        if let Some(author) = author {
                            self.settle_root(Some((author, seq)), None, None);
                        }
                    }
                }
                // The returned next/need now owns the continuation. Archive finalization
                // installs its own retry instead of duplicating a next phase pushed below.
                *retry_task = None;
                if let Some(next) = result.next {
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
                    if result.need.is_some() && rederive {
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
                    // Retain the exact continuation before distinguishing capacity waiting
                    // from a physical publication, which may have no sparse request owner.
                    let readiness = source.publication_readiness(job).await?;
                    self.waiting = true;
                    if let Lookup::Found(readiness) = readiness {
                        let readiness = readiness.value;
                        if readiness.busy && readiness.owner != Some(task.request) {
                            if readiness
                                .owner
                                .is_some_and(|owner| self.prioritize_publication_owner(owner))
                            {
                                self.publication_wait = false;
                                self.publication_owner_wait = None;
                                self.waiting = false;
                                return Ok(());
                            }
                            self.publication_wait = readiness.owner.is_some();
                            self.publication_owner_wait = readiness.owner;
                            self.slot_wait = Some(readiness.wake);
                        }
                    }
                    return Ok(());
                }
                if result.published.is_some() {
                    self.published = true;
                    self.rendered |= result.rendered;
                    self.governance |= result.governance;
                }
                match result.need {
                    Some(LocalNeed::Wire(query)) => {
                        self.push(Task {
                            request: task.request,
                            operation: Operation::LocalProof(query),
                        })?;
                    }
                    Some(LocalNeed::KeyBodyRetired) => {
                        if self
                            .admit_root
                            .as_ref()
                            .and_then(|(held, _)| held.key_body)
                            .is_none()
                        {
                            return Err(Error::MalformedAtRest("retired key body has no owner"));
                        }
                        self.tasks.clear();
                        self.replay = None;
                    }
                    Some(LocalNeed::StagedBody) => {
                        return Err(Error::MalformedAtRest(
                            "admission body need was not settled",
                        ));
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
                        |pending, store, _| Ok(pending.run(store)),
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
}

/// The errors by which a step finds the room's authorization changed under it: the flow is
/// renewed under the new one (`turn`), never failed.
fn authorization_changed(error: &Error) -> bool {
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
}
impl Drop for Flow {
    fn drop(&mut self) {
        self.cancel();
        // A root this admission failed on goes back to the room's ready set, still in
        // admission, now that its failed flow's retirement has ended: the room's next
        // admission takes it, with nothing fetched again, once the failed one's recovery edge
        // has passed (`start_admissions`). The wake lets a room whose edge passed meanwhile
        // start. Other entries this flow did not publish stay owed.
        if let (Some(frontier), Some(ready)) = (self.frontier.clone(), self.failed.take()) {
            frontier.give_back(self.room, ready);
            frontier.wake();
        }
        self.settle_root(None, None, None);
    }
}

fn request_id() -> Result<RequestId> {
    crate::identity::rng::random_array::<16>()
}
