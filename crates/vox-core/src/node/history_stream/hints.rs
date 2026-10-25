//! One node-owned inventory of pending scalar head hints. Hints carry no authority or charge.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::history::MAX_CONTEXT_AUTHORS;
use crate::node::history_budget::Job;

use super::{HeadHint, RequestId};

pub(super) const OWN_PROBE_CONNECTION_CHANGED: &str = "own-history observation connection changed";

/// Actor-owned lifetime handle into this inbox's existing per-port scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnProbePort {
    pub(crate) room: Digest32,
    pub(crate) peer: Digest32,
    generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnProbeContext {
    pub(crate) node: Digest32,
    pub(crate) instance: RequestId,
    pub(crate) epoch: u64,
    pub(crate) authorization: Digest32,
    pub(crate) connection: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnProbeClaim {
    pub(crate) port: OwnProbePort,
    pub(crate) context: OwnProbeContext,
    pub(crate) facts: RequestId,
    pub(crate) target: HeadHint,
    pub(crate) request: RequestId,
}
#[derive(Clone, Copy)]
struct CompletedProbe {
    claim: OwnProbeClaim,
    answer: OwnProbeAnswer,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnProbeAnswer {
    Complete(HeadHint),
    /// The peer's actual terminal wire answer, never an acknowledgement or a fake head.
    Unavailable,
}
#[derive(Clone, Copy)]
enum ProbeCause {
    Scope,
    Advertisement(HeadHint),
    Answer {
        request: RequestId,
        answer: OwnProbeAnswer,
    },
    Receipt {
        request: RequestId,
        before: Option<u64>,
        after: Option<u64>,
    },
}
struct OwnProbe {
    context: OwnProbeContext,
    local: Option<HeadHint>,
    advertised: Option<HeadHint>,
    receipt: Option<OwnProbeAnswer>,
    /// Changes only with a real scoped fact, including A -> B -> A. Not an attempt counter.
    facts: RequestId,
    cause: ProbeCause,
    completed: Option<CompletedProbe>,
    started: Option<OwnProbeClaim>,
}
impl OwnProbe {
    fn new(context: OwnProbeContext, local: Option<HeadHint>) -> Result<Self> {
        Ok(Self {
            context,
            local,
            advertised: None,
            receipt: None,
            facts: crate::identity::rng::random_array()?,
            cause: ProbeCause::Scope,
            completed: None,
            started: None,
        })
    }
    fn invalidate(&mut self) -> Result<()> {
        let facts = crate::identity::rng::random_array()?;
        self.facts = facts;
        self.completed = None;
        self.started = None;
        Ok(())
    }
}
#[derive(Default)]
struct PortScope {
    generation: u64,
    connection: Option<u64>,
    own: Option<Box<OwnProbe>>,
}

#[derive(Clone, Copy)]
struct Pending {
    room: Digest32,
    peer: Digest32,
    hint: HeadHint,
    in_flight: bool,
}
#[derive(Default)]
struct State {
    /// Retirement belongs to one room/peer lane. A stopped room or peer must not invalidate an
    /// unrelated worker that happened to read inventory concurrently.
    generations: BTreeMap<(Digest32, Digest32), PortScope>,
    pending: Vec<Pending>,
}
#[derive(Default)]
pub(crate) struct HintInbox(Mutex<State>);

#[derive(Clone, Copy, Default)]
pub(crate) struct Offer {
    pub(crate) added: usize,
    /// Durable exact refusal relationships invalidated before these hints became eligible.
    pub(crate) rearmed: usize,
    pub(crate) full: bool,
}

impl HintInbox {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub(crate) fn generation(&self, room: Digest32, peer: Digest32) -> u64 {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state
            .generations
            .entry((room, peer))
            .or_default()
            .generation
    }
    pub(crate) fn port_scope(&self, room: Digest32, peer: Digest32) -> OwnProbePort {
        OwnProbePort {
            room,
            peer,
            generation: self.generation(room, peer),
        }
    }
    pub(crate) fn bind_connection(&self, port: OwnProbePort, connection: u64) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let scope = state.generations.entry((port.room, port.peer)).or_default();
        if scope.generation == port.generation && scope.connection != Some(connection) {
            scope.connection = Some(connection);
            scope.own = None;
        }
    }
    /// Called under the current room guard, after store IO, by the actor rearming an
    /// existing scalar. This supplies no hint/advertisement and cannot replace a connection.
    pub(crate) fn refresh_own_scope(
        &self,
        port: OwnProbePort,
        context: OwnProbeContext,
        local: Option<HeadHint>,
    ) -> Result<bool> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(scope) = state.generations.get_mut(&(port.room, port.peer)) else {
            return Ok(false);
        };
        if scope.generation != port.generation || scope.connection != Some(context.connection) {
            return Ok(false);
        }
        if scope
            .own
            .as_ref()
            .is_none_or(|own| own.context != context || own.local != local)
        {
            scope.own = None;
            scope.own = Some(Box::new(OwnProbe::new(context, local)?));
        }
        Ok(true)
    }
    pub(crate) fn offer_local_own(
        &self,
        job: &Job,
        port: OwnProbePort,
        context: OwnProbeContext,
        local: HeadHint,
    ) -> Result<Offer> {
        self.offer_scoped(
            job,
            port.generation,
            port.room,
            port.peer,
            &[local],
            Some((context, Some(local), false)),
        )
    }
    #[allow(clippy::too_many_arguments)] // Exact current room/peer scope and one bounded slice.
    pub(crate) fn offer_peer_inventory(
        &self,
        job: &Job,
        generation: u64,
        room: Digest32,
        peer: Digest32,
        hints: &[HeadHint],
        context: OwnProbeContext,
        local: Option<HeadHint>,
    ) -> Result<Offer> {
        self.offer_scoped(
            job,
            generation,
            room,
            peer,
            hints,
            Some((context, local, true)),
        )
    }
    /// Completed observations survive an empty pending queue, but never the exact
    /// Port/room/connection/authority lifetime. Both producers use this ONE gate.
    #[allow(clippy::too_many_arguments)]
    fn offer_scoped(
        &self,
        _job: &Job,
        generation: u64,
        room: Digest32,
        peer: Digest32,
        hints: &[HeadHint],
        probe: Option<(OwnProbeContext, Option<HeadHint>, bool)>,
    ) -> Result<Offer> {
        if hints.len() > 64 {
            return Err(Error::SizeLimitExceeded("inventory insertion slice"));
        }
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if generation == u64::MAX
            || generation
                != state
                    .generations
                    .entry((room, peer))
                    .or_default()
                    .generation
        {
            return Err(Error::Unreachable("history inventory retired"));
        }
        if let Some((context, local, _)) = probe {
            let scope = state
                .generations
                .get_mut(&(room, peer))
                .ok_or(Error::Profile("history inventory scope missing"))?;
            // Only the actor binds the filed connection. A late retired stream cannot
            // replace that owner; its ordinary non-own hints remain unauthoritative input.
            if scope.connection == Some(context.connection)
                && scope
                    .own
                    .as_ref()
                    .is_none_or(|own| own.context != context || own.local != local)
            {
                // Retire the old completion before any fallible fresh-identity allocation.
                scope.own = None;
                scope.own = Some(Box::new(OwnProbe::new(context, local)?));
            }
        }
        let mut outcome = Offer::default();
        for hint in hints {
            if let Some((context, _, from_peer)) = probe {
                if hint.author == context.node {
                    let scope = state
                        .generations
                        .get_mut(&(room, peer))
                        .ok_or(Error::Profile("history inventory scope missing"))?;
                    if scope.connection != Some(context.connection) {
                        // The caller retains/refuses this exact input as local scope Busy;
                        // an old stream cannot silently Complete-drop a higher own head.
                        return Err(Error::Profile(OWN_PROBE_CONNECTION_CHANGED));
                    }
                    let Some(own) = scope.own.as_mut() else {
                        continue;
                    };
                    if own.context != context {
                        continue;
                    }
                    if from_peer && own.advertised != Some(*hint) {
                        if let Err(error) = own.invalidate() {
                            scope.own = None;
                            return Err(error);
                        }
                        own.advertised = Some(*hint);
                        own.cause = ProbeCause::Advertisement(*hint);
                    }
                    // One shared suppression point for unchanged local and incoming own
                    // hints. New facts invalidate above; a scalar never acknowledges a feed.
                    // Query::Head(own_author) asks one canonical question. Trigger
                    // hints may differ under the SAME local/peer facts; a new peer
                    // hash/size already invalidated above, before this comparison.
                    if own
                        .completed
                        .is_some_and(|done| done.claim.facts == own.facts)
                    {
                        continue;
                    }
                }
            }
            if state.pending.iter().any(|p| {
                p.room == room
                    && p.peer == peer
                    && p.hint.author == hint.author
                    && p.hint.head == hint.head
            }) {
                continue;
            }
            // Inventory heads are scalar successors, not a work log. Keep an owner already in
            // flight immutable, but collapse strictly older queued versions for this source and
            // author behind the newest successor. Equal-size distinct heads remain separate so
            // an attributable fork is still examined instead of being hidden by coalescing.
            let same_source = |pending: &&Pending| {
                pending.room == room && pending.peer == peer && pending.hint.author == hint.author
            };
            if state
                .pending
                .iter()
                .filter(same_source)
                .any(|pending| pending.hint.size > hint.size)
            {
                continue;
            }
            state.pending.retain(|pending| {
                pending.room != room
                    || pending.peer != peer
                    || pending.hint.author != hint.author
                    || pending.in_flight
                    || pending.hint.size >= hint.size
            });
            // The inventory bound belongs to this exact port. A busy or hostile room must not
            // consume a node-wide scalar-hint quota and refuse unrelated rooms. Pending scalar
            // values are parked scheduler input, not an admitted lane buffer: retaining the
            // Job (through BufferCharge) here kept its worker, byte reservation and lane slot
            // until every port's hint was gone, contrary to ADR-038 FX-35.
            if state
                .pending
                .iter()
                .filter(|pending| pending.room == room && pending.peer == peer)
                .count()
                == MAX_CONTEXT_AUTHORS
            {
                outcome.full = true;
                break;
            }
            state.pending.push(Pending {
                room,
                peer,
                hint: *hint,
                in_flight: false,
            });
            outcome.added += 1;
        }
        Ok(outcome)
    }
    /// Called only after actual admission of this exact root. Departure probes bypass this
    /// observation; they retain their separate exact acknowledgement retry contract.
    pub(crate) fn started(
        &self,
        port: OwnProbePort,
        target: HeadHint,
        request: RequestId,
    ) -> Option<OwnProbeClaim> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let scope = state.generations.get_mut(&(port.room, port.peer))?;
        if scope.generation != port.generation {
            return None;
        }
        let own = scope.own.as_mut()?;
        if target.author != own.context.node {
            return None;
        }
        let claim = OwnProbeClaim {
            port,
            context: own.context,
            facts: own.facts,
            target,
            request,
        };
        own.started = Some(claim);
        Some(claim)
    }
    /// Actor has validated the current root and applies this SAME real receipt immediately.
    /// A changed answer joins the resulting facts atomically, not as a self-trigger; only a
    /// fully completed root records completion. Old facts cannot complete a replacement need.
    pub(crate) fn observed(
        &self,
        claim: OwnProbeClaim,
        answer: OwnProbeAnswer,
        complete: bool,
    ) -> Result<Option<OwnProbeClaim>> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(scope) = state
            .generations
            .get_mut(&(claim.port.room, claim.port.peer))
        else {
            return Ok(None);
        };
        if scope.generation != claim.port.generation
            || scope.connection != Some(claim.context.connection)
        {
            return Ok(None);
        }
        let Some(own) = scope.own.as_mut() else {
            return Ok(None);
        };
        if own.context != claim.context
            || own.facts != claim.facts
            || matches!(answer, OwnProbeAnswer::Complete(head) if head.author != claim.context.node)
            || (!complete && answer == OwnProbeAnswer::Unavailable)
        {
            return Ok(None);
        }
        if own.receipt != Some(answer) {
            let started = own.started;
            if let Err(error) = own.invalidate() {
                scope.own = None;
                return Err(error);
            }
            // last_started remains the ACTUAL admission's input fence. The completed
            // observation below names the resulting facts after this same reply.
            own.started = started;
            own.receipt = Some(answer);
            own.cause = ProbeCause::Answer {
                request: claim.request,
                answer,
            };
        }
        let claim = OwnProbeClaim {
            facts: own.facts,
            ..claim
        };
        if complete {
            if own.completed.is_none() {
                own.completed = Some(CompletedProbe { claim, answer });
            }
            // Every queued own-author trigger asks the SAME canonical Head(author)
            // question under these facts, including equal-size conflicting hints. None
            // may bypass the offer gate after this completion. A later real fact change
            // is serialized by this mutex and can enqueue its new observation normally.
            state.pending.retain(|pending| {
                pending.room != claim.port.room
                    || pending.peer != claim.port.peer
                    || pending.hint.author != claim.context.node
            });
            Self::release_empty(&mut state);
        }
        Ok(Some(claim))
    }
    pub(crate) fn receipt_changed(
        &self,
        port: OwnProbePort,
        request: RequestId,
        before: Option<u64>,
        after: Option<u64>,
    ) -> Result<()> {
        if before == after {
            return Ok(());
        }
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(scope) = state.generations.get_mut(&(port.room, port.peer)) {
            if scope.generation == port.generation {
                if let Some(own) = scope.own.as_mut() {
                    // Fresh identity plus the real transition witness fences A -> B -> A;
                    // the same retained root may legitimately report more than one change.
                    if let Err(error) = own.invalidate() {
                        scope.own = None;
                        return Err(error);
                    }
                    own.receipt = None;
                    own.cause = ProbeCause::Receipt {
                        request,
                        before,
                        after,
                    };
                }
            }
        }
        Ok(())
    }
    pub(crate) fn probe_status(&self, port: OwnProbePort) -> serde_json::Value {
        let state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(scope) = state.generations.get(&(port.room, port.peer)) else {
            return serde_json::Value::Null;
        };
        if scope.generation != port.generation {
            return serde_json::Value::Null;
        }
        let Some(own) = scope.own.as_ref() else {
            return serde_json::Value::Null;
        };
        let digest = |value: &Digest32| crate::node::link::b32_encode(value);
        let request =
            |value: RequestId| value.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let head = |hint: HeadHint| serde_json::json!({"author":digest(&hint.author),"head":digest(&hint.head),"size":hint.size});
        let claim = |value: OwnProbeClaim| serde_json::json!({"request":request(value.request),"facts":request(value.facts),"target":head(value.target)});
        let answer_head = |answer: OwnProbeAnswer| match answer {
            OwnProbeAnswer::Complete(value) => Some(value),
            OwnProbeAnswer::Unavailable => None,
        };
        let cause = match own.cause {
            ProbeCause::Scope => {
                serde_json::json!({"kind":"current-room-head-authority-connection"})
            }
            ProbeCause::Advertisement(value) => {
                serde_json::json!({"kind":"changed-peer-advertisement","advertisement":head(value)})
            }
            ProbeCause::Answer {
                request: root,
                answer,
            } => match answer {
                OwnProbeAnswer::Complete(value) => {
                    serde_json::json!({"kind":"validated-role-complete-answer","request":request(root),"answer":head(value)})
                }
                OwnProbeAnswer::Unavailable => {
                    serde_json::json!({"kind":"unavailable-own-head-answer","request":request(root)})
                }
            },
            ProbeCause::Receipt {
                request: root,
                before,
                after,
            } => {
                serde_json::json!({"kind":"changed-peer-held-fact","request":request(root),"before":before,"after":after})
            }
        };
        serde_json::json!({"node":digest(&own.context.node),"instance":request(own.context.instance),
            "epoch":own.context.epoch,"authorization":digest(&own.context.authorization),"connection":own.context.connection,
            "facts":request(own.facts),"port_generation":port.generation,"state":match own.completed {Some(done) if done.answer == OwnProbeAnswer::Unavailable => "unavailable",Some(_) => "observed",None => "unobserved"},"cause":cause,"local_head":own.local.map(head),"peer_advertisement":own.advertised.map(head),
            "peer_receipt":own.receipt.and_then(answer_head).map(head),"last_started":own.started.map(claim),
            "completed":own.completed.map(|done| serde_json::json!({"root":claim(done.claim),"disposition":if done.answer == OwnProbeAnswer::Unavailable {"unavailable"} else {"complete"},"answer":answer_head(done.answer).map(head)}))})
    }
    pub(crate) fn pending(&self, room: Digest32, peer: Digest32) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pending
            .iter()
            .any(|p| p.room == room && p.peer == peer && !p.in_flight)
    }
    /// Whether an immutable in-flight owner has a strictly newer queued successor. Equal-size
    /// distinct heads remain fork evidence and never supersede each other by scalar ordering.
    pub(crate) fn newer_pending(
        &self,
        room: Digest32,
        peer: Digest32,
        author: Digest32,
        size: u64,
    ) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pending
            .iter()
            .any(|pending| {
                pending.room == room
                    && pending.peer == peer
                    && pending.hint.author == author
                    && !pending.in_flight
                    && pending.hint.size > size
            })
    }
    pub(crate) fn take(&self, room: Digest32, peer: Digest32, local: Digest32) -> Option<HeadHint> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let pending = state
            .pending
            .iter_mut()
            .filter(|p| p.room == room && p.peer == peer && !p.in_flight)
            // The author is the authoritative live-body source. Prefer its own head, then our
            // exact echo needed for settlement/departure; third-party gossip remains fallback
            // when the author is absent or has no pending successor on this port.
            .min_by_key(|pending| {
                if pending.hint.author == peer {
                    0
                } else if pending.hint.author == local {
                    1
                } else {
                    2
                }
            })?;
        pending.in_flight = true;
        Some(pending.hint)
    }
    pub(crate) fn finish(&self, room: Digest32, peer: Digest32, author: Digest32, head: Digest32) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.pending.retain(|p| {
            p.room != room || p.peer != peer || p.hint.author != author || p.hint.head != head
        });
        Self::release_empty(&mut state);
    }
    /// A local authorization edit retires the old flow, not its unauthoritative scalar hint.
    /// Release that exact hint for a new flow bound to the current authorization generation.
    pub(crate) fn retry(&self, room: Digest32, peer: Digest32, author: Digest32, head: Digest32) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        Self::retry_locked(&mut state, room, peer, author, head);
    }
    /// Release only a scalar already owned by this still-current Port generation. Never
    /// recreate work erased by room/peer retirement or stamp a rejected completion.
    pub(crate) fn retry_probe(&self, port: OwnProbePort, target: HeadHint) -> bool {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if state
            .generations
            .get(&(port.room, port.peer))
            .is_none_or(|scope| scope.generation != port.generation)
            || !state.pending.iter().any(|pending| {
                pending.room == port.room && pending.peer == port.peer && pending.hint == target
            })
        {
            return false;
        }
        Self::retry_locked(&mut state, port.room, port.peer, target.author, target.head);
        true
    }
    fn retry_locked(
        state: &mut State,
        room: Digest32,
        peer: Digest32,
        author: Digest32,
        head: Digest32,
    ) {
        let Some(owner) = state.pending.iter().find(|pending| {
            pending.room == room
                && pending.peer == peer
                && pending.hint.author == author
                && pending.hint.head == head
        }) else {
            return;
        };
        let owner_size = owner.hint.size;
        if state.pending.iter().any(|pending| {
            pending.room == room
                && pending.peer == peer
                && pending.hint.author == author
                && pending.hint.head != head
                && pending.hint.size > owner_size
        }) {
            // Authorization/port turnover abandoned this owner after a newer successor arrived.
            // Retrying the obsolete scalar first recreates the backlog coalescing removed.
            state.pending.retain(|pending| {
                pending.room != room
                    || pending.peer != peer
                    || pending.hint.author != author
                    || pending.hint.head != head
            });
            Self::release_empty(state);
        } else if let Some(pending) = state.pending.iter_mut().find(|pending| {
            pending.room == room
                && pending.peer == peer
                && pending.hint.author == author
                && pending.hint.head == head
        }) {
            pending.in_flight = false;
        }
    }
    /// Retire work bound to a port incarnation. Refusals describe the member's advertised
    /// inventory, not its socket or port: an ordinary reconnect does not make the bodies exist.
    pub(crate) fn retire_port(&self, room: Digest32, peer: Digest32) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        // MAX is a permanently retired generation: offer refuses it rather than wrapping.
        let generation = state.generations.entry((room, peer)).or_default();
        generation.generation = generation.generation.saturating_add(1);
        generation.connection = None;
        generation.own = None;
        state.pending.retain(|p| p.room != room || p.peer != peer);
        Self::release_empty(&mut state);
    }
    pub(crate) fn retire_room(&self, room: Digest32) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        // Retire workers that could still return hints for the removed room. Other lanes keep
        // their exact generation and remain valid.
        // MAX is a permanently retired generation: offer refuses it rather than wrapping.
        for ((candidate, _), generation) in &mut state.generations {
            if *candidate == room {
                generation.generation = generation.generation.saturating_add(1);
                generation.connection = None;
                generation.own = None;
            }
        }
        state.pending.retain(|p| p.room != room);
        Self::release_empty(&mut state);
    }
    pub(crate) fn clear(&self) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        // Every captured scope has an entry because `generation` registers it before a worker
        // starts. Retire those exact workers without a global scalar that can alias after clear.
        for generation in state.generations.values_mut() {
            generation.generation = generation.generation.saturating_add(1);
            generation.connection = None;
            generation.own = None;
        }
        state.pending = Vec::new();
    }
    fn release_empty(state: &mut State) {
        if state.pending.is_empty() {
            state.pending = Vec::new();
        }
    }
}
