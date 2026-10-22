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
}
#[derive(Default)]
struct State {
    /// Retirement belongs to one room/peer lane. A stopped room or peer must not invalidate an
    /// unrelated worker that happened to read inventory concurrently.
    generations: BTreeMap<(Digest32, Digest32), u64>,
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
            Self::release_empty(&mut state);
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
        *generation = generation.saturating_add(1);
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
                *generation = generation.saturating_add(1);
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
            *generation = generation.saturating_add(1);
        }
        state.pending = Vec::new();
    }
    fn release_empty(state: &mut State) {
        if state.pending.is_empty() {
            state.pending = Vec::new();
        }
    }
}
