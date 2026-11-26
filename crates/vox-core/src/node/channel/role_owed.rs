//! Coalesced board-growth edges for the own-key worker.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

use crate::hash::Digest32;
use tokio::sync::Notify;

#[derive(Default)]
pub(crate) struct BoardOwner;

/// Coalesces producer edges without losing a wake to the actor's bounded inbox.
#[derive(Default)]
pub(crate) struct BoardWake {
    current: Mutex<BTreeMap<Digest32, Weak<BoardOwner>>>,
    board_pending: Mutex<BTreeMap<Digest32, Weak<BoardOwner>>>,
    pub(crate) notify: Notify,
}

impl BoardWake {
    pub(crate) fn install(self: &Arc<Self>, room: Digest32, owner: &Arc<BoardOwner>) {
        let mut current = self.current.lock().unwrap_or_else(|e| e.into_inner());
        current.retain(|_, owner| owner.strong_count() != 0);
        current.insert(room, Arc::downgrade(owner));
    }
    /// Retain one board-change edge for an installed room without using the bounded actor queue.
    pub(crate) fn board_growth(&self, room: Digest32) {
        let current = self.current.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(owner) = current.get(&room).and_then(Weak::upgrade) {
            self.board_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(room, Arc::downgrade(&owner));
            self.notify.notify_one();
        }
    }
    pub(crate) fn take_board(&self) -> Vec<(Digest32, Arc<BoardOwner>)> {
        std::mem::take(&mut *self.board_pending.lock().unwrap_or_else(|e| e.into_inner()))
            .into_iter()
            .filter_map(|(room, owner)| owner.upgrade().map(|owner| (room, owner)))
            .collect()
    }
    pub(crate) fn current(&self, room: Digest32, owner: &Arc<BoardOwner>) -> bool {
        self.current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&room)
            .and_then(Weak::upgrade)
            .is_some_and(|v| Arc::ptr_eq(&v, owner))
    }
}
