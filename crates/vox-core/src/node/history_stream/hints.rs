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
}
type RoleSeen = (crate::node::ports::SupportDiscovery, (u64, u64), HeadHint);

#[derive(Default)]
struct State {
    /// Retirement belongs to one room/peer lane. A stopped room or peer must not invalidate an
    /// unrelated worker that happened to read inventory concurrently.
    generations: BTreeMap<(Digest32, Digest32), u64>,
    pending: Vec<Pending>,
    role_seen: BTreeMap<(Digest32, Digest32), RoleSeen>,
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
        *state.generations.entry((room, peer)).or_default()
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
            || generation != *state.generations.entry((room, peer)).or_default()
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
            });
            outcome.added += 1;
        }
        Ok(outcome)
    }
    pub(crate) fn pending(&self, room: Digest32, peer: Digest32) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pending
            .iter()
            .any(|p| p.room == room && p.peer == peer && !p.in_flight)
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
            || generation != *state.generations.entry((room, peer)).or_default()
        {
            return Err(Error::Unreachable("history inventory retired"));
        }
        if state.role_seen.get(&(room, peer)) == Some(&(scope, incarnations, hint)) {
            return Ok(Offer::default());
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
    ) -> Option<(HeadHint, bool, Option<u64>)> {
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
        Some((pending.hint, pending.role_signal, pending.role_connection))
    }
    pub(crate) fn finish(&self, room: Digest32, peer: Digest32, author: Digest32, head: Digest32) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.pending.retain(|p| {
            p.room != room
                || p.peer != peer
                || p.hint.author != author
                || p.hint.head != head
                || (p.role_signal && !p.in_flight)
        });
        Self::release_empty(&mut state);
    }
    /// A local authorization edit retires the old flow, not its unauthoritative scalar hint.
    /// Release that exact hint for a new flow bound to the current authorization generation.
    pub(crate) fn retry(&self, room: Digest32, peer: Digest32, author: Digest32, head: Digest32) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(owner) = state.pending.iter().find(|pending| {
            pending.room == room
                && pending.peer == peer
                && pending.hint.author == author
                && pending.hint.head == head
                && pending.in_flight
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
            if let Some(index) = state.pending.iter().position(|pending| {
                pending.room == room
                    && pending.peer == peer
                    && pending.hint.author == author
                    && pending.hint.head == head
                    && pending.in_flight
            }) {
                state.pending.remove(index);
            }
            Self::release_empty(&mut state);
        } else if let Some(pending) = state.pending.iter_mut().find(|pending| {
            pending.room == room
                && pending.peer == peer
                && pending.hint.author == author
                && pending.hint.head == head
                && pending.in_flight
        }) {
            pending.in_flight = false;
        }
    }

    /// Preserve the exact role-triggered query through a transient failed exchange.
    pub(crate) fn retry_role(
        &self,
        room: Digest32,
        peer: Digest32,
        author: Digest32,
        head: Digest32,
    ) -> bool {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(index) = state.pending.iter().position(|pending| {
            pending.room == room
                && pending.peer == peer
                && pending.hint.author == author
                && pending.hint.head == head
                && pending.role_signal
                && pending.in_flight
        }) else {
            return false;
        };
        if state.pending.iter().any(|pending| {
            pending.room == room
                && pending.peer == peer
                && pending.role_signal
                && !pending.in_flight
        }) {
            state.pending.remove(index);
        } else {
            state.pending[index].in_flight = false;
        }
        true
    }
    /// Retire work bound to a port incarnation. Refusals describe the member's advertised
    /// inventory, not its socket or port: an ordinary reconnect does not make the bodies exist.
    pub(crate) fn retire_port(&self, room: Digest32, peer: Digest32) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        // MAX is a permanently retired generation: offer refuses it rather than wrapping.
        let generation = state.generations.entry((room, peer)).or_default();
        *generation = generation.saturating_add(1);
        state.pending.retain(|p| p.room != room || p.peer != peer);
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
                *generation = generation.saturating_add(1);
            }
        }
        state.pending.retain(|p| p.room != room);
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
            *generation = generation.saturating_add(1);
        }
        state.pending = Vec::new();
        state.role_seen.clear();
    }
    fn release_empty(state: &mut State) {
        if state.pending.is_empty() {
            state.pending = Vec::new();
        }
    }
}
