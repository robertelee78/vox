//! One charged, node-owned inventory of pending scalar head hints. Hints carry no authority.

use std::sync::{Arc, Mutex, PoisonError};

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::history::MAX_CONTEXT_AUTHORS;
use crate::node::history_budget::{BufferCharge, Job};

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
    generation: u64,
    pending: Vec<Pending>,
    charge: Option<BufferCharge>,
}
#[derive(Default)]
pub(crate) struct HintInbox(Mutex<State>);

#[derive(Clone, Copy, Default)]
pub(crate) struct Offer {
    pub(crate) added: usize,
    pub(crate) full: bool,
}

impl HintInbox {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub(crate) fn generation(&self) -> u64 {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .generation
    }
    /// Capture generation before any worker read. A lock/retirement clears it atomically,
    /// so a late, otherwise valid read cannot repopulate the newly empty inventory.
    pub(crate) fn offer(
        &self,
        job: &Job,
        generation: u64,
        room: Digest32,
        peer: Digest32,
        hints: &[HeadHint],
    ) -> Result<Offer> {
        if hints.len() > 64 {
            return Err(Error::SizeLimitExceeded("inventory insertion slice"));
        }
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if generation != state.generation {
            return Err(Error::Unreachable("history inventory retired"));
        }
        let mut outcome = Offer::default();
        for hint in hints {
            if state
                .pending
                .iter()
                .any(|p| p.room == room && p.hint.author == hint.author && p.hint.head == hint.head)
            {
                continue;
            }
            if state.pending.len() == MAX_CONTEXT_AUTHORS {
                outcome.full = true;
                break;
            }
            if state.charge.is_none() {
                let Some(charge) =
                    job.reserve(MAX_CONTEXT_AUTHORS * std::mem::size_of::<Pending>())
                else {
                    outcome.full = true;
                    break;
                };
                state.pending = Vec::with_capacity(MAX_CONTEXT_AUTHORS);
                state.charge = Some(charge);
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
    pub(crate) fn take(&self, room: Digest32, peer: Digest32) -> Option<HeadHint> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let pending = state
            .pending
            .iter_mut()
            .find(|p| p.room == room && p.peer == peer && !p.in_flight)?;
        pending.in_flight = true;
        Some(pending.hint)
    }
    pub(crate) fn finish(&self, room: Digest32, author: Digest32, head: Digest32) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state
            .pending
            .retain(|p| p.room != room || p.hint.author != author || p.hint.head != head);
        Self::release_empty(&mut state);
    }
    pub(crate) fn retire_peer(&self, room: Digest32, peer: Digest32) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.generation = state
            .generation
            .checked_add(1)
            .expect("inventory generation exhausted");
        state.pending.retain(|p| p.room != room || p.peer != peer);
        Self::release_empty(&mut state);
    }
    pub(crate) fn retire_room(&self, room: Digest32) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        // Retire workers that could still return hints for the removed room. Other retained
        // hints remain useful; their next worker captures the new inventory generation.
        state.generation = state
            .generation
            .checked_add(1)
            .expect("inventory generation exhausted");
        state.pending.retain(|p| p.room != room);
        Self::release_empty(&mut state);
    }
    /// Includes in-flight hints: settlement must not outrun recovery of our own feed.
    pub(crate) fn pending_author(&self, room: Digest32, author: Digest32) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pending
            .iter()
            .any(|p| p.room == room && p.hint.author == author)
    }
    pub(crate) fn clear(&self) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.generation = state
            .generation
            .checked_add(1)
            .expect("inventory generation exhausted");
        state.pending = Vec::new();
        state.charge = None;
    }
    fn release_empty(state: &mut State) {
        if state.pending.is_empty() {
            state.pending = Vec::new();
            state.charge = None;
        }
    }
}
