//! One node-owned inventory of pending scalar head hints. Hints carry no authority or charge.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::history::MAX_CONTEXT_AUTHORS;
use crate::node::history_budget::Job;

use super::HeadHint;

#[derive(Clone, Copy)]
struct Pending {
    room: Digest32,
    peer: Digest32,
    hint: HeadHint,
    in_flight: bool,
    role_signal: bool,
    role_connection: Option<u64>,
    owner: Option<u64>,
}
type RoleSeen = (crate::node::ports::SupportDiscovery, (u64, u64), HeadHint);
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransientScope {
    pub(crate) connection: u64,
    pub(crate) authorization: Digest32,
    pub(crate) incarnations: Option<(u64, u64)>,
}
struct Transient {
    room: Digest32,
    peer: Digest32,
    author: Digest32,
    head: Digest32,
    scope: TransientScope,
    availability: Option<crate::node::channel::availability::Token>,
    _charge: crate::node::history_budget::OutputCharge,
}

#[derive(Default)]
struct LaneGeneration {
    epoch: u64,
    availability: Option<(u64, crate::node::channel::availability::Token)>,
}

#[derive(Default)]
struct State {
    /// Retirement belongs to one room/peer lane. A stopped room or peer must not invalidate an
    /// unrelated worker that happened to read inventory concurrently.
    generations: BTreeMap<(Digest32, Digest32), LaneGeneration>,
    pending: Vec<Pending>,
    role_seen: BTreeMap<(Digest32, Digest32), RoleSeen>,
    /// Transient refusals scoped to one room, source, author, head and connection.
    transient: Vec<Transient>,
    next_owner: u64,
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

#[derive(Clone, Copy)]
pub(crate) enum RefusalRetry {
    Advanced,
    Busy,
}

pub(crate) enum RefusalDisposition {
    Parked,
    Retry(RefusalRetry),
}

impl HintInbox {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub(crate) fn generation(&self, room: Digest32, peer: Digest32) -> u64 {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.generations.entry((room, peer)).or_default().epoch
    }
    pub(crate) fn transient_decline(
        &self,
        job: &Job,
        generation: u64,
        (room, peer): (Digest32, Digest32),
        (author, head): (Digest32, Digest32),
        scope: TransientScope,
        availability: Option<crate::node::channel::availability::Token>,
    ) -> Result<RefusalDisposition> {
        let Some(charge) = job.reserve(2 * std::mem::size_of::<Transient>()) else {
            return Ok(RefusalDisposition::Retry(RefusalRetry::Busy));
        };
        let Ok(charge) = charge.into_output() else {
            return Ok(RefusalDisposition::Retry(RefusalRetry::Busy));
        };
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if generation == u64::MAX
            || generation != state.generations.entry((room, peer)).or_default().epoch
        {
            return Err(Error::Unreachable("history inventory retired"));
        }
        if state.generations[&(room, peer)]
            .availability
            .is_some_and(|(connection, current)| {
                connection == scope.connection && availability.is_none_or(|old| old < current)
            })
        {
            return Ok(RefusalDisposition::Retry(RefusalRetry::Advanced));
        }
        state.transient.retain(|entry| {
            entry.room != room || entry.peer != peer || entry.author != author || entry.head != head
        });
        if state
            .transient
            .iter()
            .filter(|entry| entry.room == room && entry.peer == peer)
            .count()
            >= 64
        {
            return Err(Error::SizeLimitExceeded("transient history refusals"));
        }
        state.transient.push(Transient {
            room,
            peer,
            author,
            head,
            scope,
            availability,
            _charge: charge,
        });
        Ok(RefusalDisposition::Parked)
    }

    /// A changed connection or authority incarnation rearms an exact declined head.
    pub(crate) fn transient_blocked(
        &self,
        generation: u64,
        room: Digest32,
        peer: Digest32,
        hint: HeadHint,
        scope: TransientScope,
    ) -> Result<(bool, bool)> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if generation == u64::MAX
            || generation != state.generations.entry((room, peer)).or_default().epoch
        {
            return Err(Error::Unreachable("history inventory retired"));
        }
        let Some(index) = state.transient.iter().position(|entry| {
            entry.room == room
                && entry.peer == peer
                && entry.author == hint.author
                && entry.head == hint.head
        }) else {
            return Ok((false, false));
        };
        if state.transient[index].scope == scope {
            Ok((true, false))
        } else {
            #[cfg(feature = "test-knobs")]
            eprintln!("history transient rearm reason=scope-changed peer={} author={} head={} old_connection={} new_connection={}", crate::node::link::b32_encode(&peer), crate::node::link::b32_encode(&hint.author), crate::node::link::b32_encode(&hint.head), state.transient[index].scope.connection, scope.connection);
            state.transient.swap_remove(index);
            Ok((false, true))
        }
    }
    pub(crate) fn own_verification_allowed(
        &self,
        room: Digest32,
        peer: Digest32,
        hint: HeadHint,
        scope: crate::node::ports::SupportDiscovery,
        incarnations: Option<(u64, u64)>,
    ) -> bool {
        let generation = self.generation(room, peer);
        let scope = TransientScope {
            connection: scope.connection,
            authorization: scope.authorization,
            incarnations,
        };
        self.transient_blocked(generation, room, peer, hint, scope)
            .is_ok_and(|(blocked, _)| !blocked)
    }

    /// An authenticated serving-progress token invalidates only this source lane.
    /// Fence older workers before dropping the connection's refusals.
    pub(crate) fn rearm_source_progress(
        &self,
        room: Digest32,
        peer: Digest32,
        connection: u64,
        token: crate::node::channel::availability::Token,
    ) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let lane = state.generations.entry((room, peer)).or_default();
        lane.availability = Some((connection, token));
        state.transient.retain(|entry| {
            entry.room != room
                || entry.peer != peer
                || entry.scope.connection != connection
                || entry.availability.is_some_and(|captured| captured >= token)
        });
    }
    pub(crate) fn retire_connection(&self, peer: Digest32, connection: u64) -> bool {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        // A worker that received a refusal before closure must not publish it after
        // this connection's entries have been retired.
        for ((_, member), generation) in &mut state.generations {
            if *member == peer {
                generation.epoch = generation.epoch.saturating_add(1);
                generation.availability = None;
            }
        }
        let before = state.transient.len();
        state
            .transient
            .retain(|entry| entry.peer != peer || entry.scope.connection != connection);
        let removed = before != state.transient.len();
        #[cfg(feature = "test-knobs")]
        eprintln!(
            "history transient rearm reason=connection-closed peer={} connection={} removed={}",
            crate::node::link::b32_encode(&peer),
            connection,
            removed
        );
        if state.transient.is_empty() {
            state.transient = Vec::new();
        }
        removed
    }
    /// An authenticated held-through advance can rearm this node's exact offered head.
    pub(crate) fn rearm_held(&self, room: Digest32, peer: Digest32, author: Digest32, seq: u64) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let State {
            pending, transient, ..
        } = &mut *state;
        transient.retain(|entry| {
            entry.room != room
                || entry.peer != peer
                || entry.author != author
                || !pending.iter().any(|hint| {
                    hint.room == room
                        && hint.peer == peer
                        && hint.hint.author == author
                        && hint.hint.head == entry.head
                        && hint.hint.size <= seq
                })
        });
    }

    /// Capture generation before any worker read. A lock/retirement clears it atomically,
    /// so a late, otherwise valid read cannot repopulate the newly empty inventory.
    pub(crate) fn offer(
        &self,
        _job: &Job,
        generation: u64,
        room: Digest32,
        peer: Digest32,
        hints: &[HeadHint],
    ) -> Result<Offer> {
        if hints.len() > 64 {
            return Err(Error::SizeLimitExceeded("inventory insertion slice"));
        }
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if generation == u64::MAX
            || generation != state.generations.entry((room, peer)).or_default().epoch
        {
            return Err(Error::Unreachable("history inventory retired"));
        }
        let mut outcome = Offer::default();
        for hint in hints {
            if state.pending.iter().any(|p| {
                p.room == room
                    && p.peer == peer
                    && !p.role_signal
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
                pending.room == room
                    && pending.peer == peer
                    && !pending.role_signal
                    && pending.hint.author == hint.author
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
                    || pending.role_signal
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
                role_signal: false,
                role_connection: None,
                owner: None,
            });
            outcome.added += 1;
        }
        Ok(outcome)
    }
    pub(crate) fn pending(&self, room: Digest32, peer: Digest32) -> bool {
        let state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.pending.iter().any(|p| {
            p.room == room && p.peer == peer && !p.in_flight && !Self::blocked(&state.transient, p)
        })
    }

    fn blocked(transient: &[Transient], pending: &Pending) -> bool {
        transient.iter().any(|entry| {
            entry.room == pending.room
                && entry.peer == pending.peer
                && entry.author == pending.hint.author
                && entry.head == pending.hint.head
        })
    }

    /// A changed peer role is only a reason to query that peer. The hint never advances a
    /// receipt, and one queued successor survives an older in-flight query.
    pub(crate) fn offer_role(
        &self,
        generation: u64,
        room: Digest32,
        peer: Digest32,
        scope: crate::node::ports::SupportDiscovery,
        incarnations: (u64, u64),
        hint: HeadHint,
    ) -> Result<Offer> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if generation == u64::MAX
            || generation != state.generations.entry((room, peer)).or_default().epoch
        {
            return Err(Error::Unreachable("history inventory retired"));
        }
        let previous = state.role_seen.get(&(room, peer)).copied();
        if previous == Some((scope, incarnations, hint)) {
            return Ok(Offer::default());
        }
        // A successor head is not new evidence that this peer can serve an older one.
        if previous.is_some_and(|(old_scope, old_incarnations, _)| {
            old_scope != scope || old_incarnations != incarnations
        }) {
            state.transient.retain(|entry| {
                entry.room != room || entry.peer != peer || entry.author != hint.author
            });
        }
        if let Some(pending) = state.pending.iter_mut().find(|pending| {
            pending.room == room
                && pending.peer == peer
                && pending.role_signal
                && !pending.in_flight
        }) {
            pending.hint = hint;
            pending.role_connection = Some(scope.connection);
        } else {
            if state
                .pending
                .iter()
                .filter(|p| p.room == room && p.peer == peer)
                .count()
                >= MAX_CONTEXT_AUTHORS
            {
                return Ok(Offer {
                    full: true,
                    ..Offer::default()
                });
            }
            state.pending.push(Pending {
                room,
                peer,
                hint,
                in_flight: false,
                role_signal: true,
                role_connection: Some(scope.connection),
                owner: None,
            });
        }
        state
            .role_seen
            .insert((room, peer), (scope, incarnations, hint));
        Ok(Offer {
            added: 1,
            ..Offer::default()
        })
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
    pub(crate) fn take(
        &self,
        room: Digest32,
        peer: Digest32,
        local: Digest32,
    ) -> Option<(HeadHint, bool, Option<u64>, u64)> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.next_owner = state.next_owner.checked_add(1)?;
        let owner = state.next_owner;
        let State {
            pending, transient, ..
        } = &mut *state;
        let pending = pending
            .iter_mut()
            .filter(|p| {
                p.room == room && p.peer == peer && !p.in_flight && !Self::blocked(transient, p)
            })
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
        pending.owner = Some(owner);
        Some((
            pending.hint,
            pending.role_signal,
            pending.role_connection,
            owner,
        ))
    }
    /// Finalize only the selected incarnation, never a replacement or a retried owner.
    pub(crate) fn finish_owned(&self, room: Digest32, peer: Digest32, owner: u64, retry: bool) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(index) = state
            .pending
            .iter()
            .position(|p| p.room == room && p.peer == peer && p.in_flight && p.owner == Some(owner))
        {
            let selected = state.pending[index];
            let superseded = state.pending.iter().any(|pending| {
                pending.room == room
                    && pending.peer == peer
                    && pending.hint.author == selected.hint.author
                    && pending.hint.head != selected.hint.head
                    && pending.hint.size > selected.hint.size
            });
            if retry && !superseded {
                state.pending[index].in_flight = false;
                state.pending[index].owner = None;
            } else {
                // A strictly newer queued successor owns the scalar work. The separate exact
                // refusal remains parked; a new head does not rearm the old relationship.
                state.pending.remove(index);
            }
        }
        Self::release_empty(&mut state);
    }
    pub(crate) fn fail_owned(&self, room: Digest32, peer: Digest32, owner: u64, transient: bool) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(index) = state
            .pending
            .iter()
            .position(|p| p.room == room && p.peer == peer && p.in_flight && p.owner == Some(owner))
        {
            let selected = state.pending[index];
            let role = selected.role_signal;
            let successor = state.pending.iter().any(|pending| {
                pending.room == room
                    && pending.peer == peer
                    && ((role && pending.role_signal && !pending.in_flight)
                        || (pending.hint.author == selected.hint.author
                            && pending.hint.head != selected.hint.head
                            && pending.hint.size > selected.hint.size))
            });
            if (transient || role) && !successor {
                state.pending[index].in_flight = false;
                state.pending[index].owner = None;
            } else {
                state.pending.remove(index);
            }
        }
        Self::release_empty(&mut state);
    }
    /// Retire all hints and temporary refusals bound to a port incarnation.
    pub(crate) fn retire_port(&self, room: Digest32, peer: Digest32) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        // MAX is a permanently retired generation: offer refuses it rather than wrapping.
        let generation = state.generations.entry((room, peer)).or_default();
        generation.epoch = generation.epoch.saturating_add(1);
        generation.availability = None;
        state.pending.retain(|p| p.room != room || p.peer != peer);
        state
            .transient
            .retain(|entry| entry.room != room || entry.peer != peer);
        state.role_seen.remove(&(room, peer));
        Self::release_empty(&mut state);
    }
    pub(crate) fn retire_room(&self, room: Digest32) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        // Retire workers that could still return hints for the removed room. Other lanes keep
        // their exact generation and remain valid.
        // MAX is a permanently retired generation: offer refuses it rather than wrapping.
        for ((candidate, _), generation) in &mut state.generations {
            if *candidate == room {
                generation.epoch = generation.epoch.saturating_add(1);
                generation.availability = None;
            }
        }
        state.pending.retain(|p| p.room != room);
        state.transient.retain(|entry| entry.room != room);
        state
            .role_seen
            .retain(|(candidate, _), _| *candidate != room);
        Self::release_empty(&mut state);
    }
    pub(crate) fn clear(&self) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        // Every captured scope has an entry because `generation` registers it before a worker
        // starts. Retire those exact workers without a global scalar that can alias after clear.
        for generation in state.generations.values_mut() {
            generation.epoch = generation.epoch.saturating_add(1);
            generation.availability = None;
        }
        state.pending = Vec::new();
        state.transient.clear();
        state.role_seen.clear();
    }
    fn release_empty(state: &mut State) {
        if state.pending.is_empty() {
            state.pending = Vec::new();
        }
    }
}
