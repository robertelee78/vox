//! Exact per-author role announcements retained until their exchange completes.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

use crate::hash::Digest32;
use crate::node::history_stream::HeadHint;
use tokio::sync::Notify;

#[derive(Default)]
struct Entry {
    head: Option<HeadHint>,
    token: Arc<()>,
    sent: bool,
    dirty: bool,
}

/// A room instance owns this map; a replacement room gets a different Arc.
#[derive(Default)]
pub(crate) struct RoleOwed {
    entries: Mutex<BTreeMap<Digest32, Entry>>,
    key_dirty: Mutex<BTreeMap<Digest32, Arc<()>>>,
    wake: Mutex<Option<Weak<RoleWake>>>,
    room: Mutex<Option<Digest32>>,
}

/// Coalesces producer edges without losing a wake to the actor's bounded inbox.
#[derive(Default)]
pub(crate) struct RoleWake {
    current: Mutex<BTreeMap<Digest32, Weak<RoleOwed>>>,
    pending: Mutex<BTreeMap<(Digest32, Digest32), Weak<RoleOwed>>>,
    pub(crate) notify: Notify,
}

impl RoleWake {
    pub(crate) fn install(self: &Arc<Self>, room: Digest32, owner: &Arc<RoleOwed>) {
        let mut current = self.current.lock().unwrap_or_else(|e| e.into_inner());
        current.retain(|_, owner| owner.strong_count() != 0);
        current.insert(room, Arc::downgrade(owner));
        drop(current);
        *owner.room.lock().unwrap_or_else(|e| e.into_inner()) = Some(room);
        *owner.wake.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::downgrade(self));
    }
    fn signal(&self, room: Digest32, peer: Digest32, owner: &Arc<RoleOwed>) {
        let current = self.current.lock().unwrap_or_else(|e| e.into_inner());
        if !current
            .get(&room)
            .and_then(Weak::upgrade)
            .is_some_and(|v| Arc::ptr_eq(&v, owner))
        {
            return;
        }
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((room, peer), Arc::downgrade(owner));
        drop(current);
        self.notify.notify_one();
    }
    pub(crate) fn take(&self) -> Vec<((Digest32, Digest32), Arc<RoleOwed>)> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *pending)
            .into_iter()
            .filter_map(|(key, owner)| owner.upgrade().map(|owner| (key, owner)))
            .collect()
    }
    pub(crate) fn current(&self, room: Digest32, owner: &Arc<RoleOwed>) -> bool {
        self.current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&room)
            .and_then(Weak::upgrade)
            .is_some_and(|v| Arc::ptr_eq(&v, owner))
    }
    pub(crate) fn owner(&self, room: Digest32) -> Option<Arc<RoleOwed>> {
        self.current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&room)
            .and_then(Weak::upgrade)
    }
}

impl RoleOwed {
    fn signal(self: &Arc<Self>, peer: Digest32) {
        let wake = self
            .wake
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .and_then(Weak::upgrade);
        let room = *self.room.lock().unwrap_or_else(|e| e.into_inner());
        if let (Some(wake), Some(room)) = (wake, room) {
            wake.signal(room, peer, self);
        }
    }
    /// Retain an exact per-author discovery edge until its bounded scan finishes.
    pub(crate) fn mark_key_dirty(self: &Arc<Self>, peer: Digest32) {
        self.key_dirty
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(peer, Arc::new(()));
        self.signal(peer);
    }
    pub(crate) fn clear_key(self: &Arc<Self>, peer: Digest32) {
        self.key_dirty
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&peer);
    }
    pub(crate) fn key_token(&self, peer: Digest32) -> Option<Arc<()>> {
        self.key_dirty
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&peer)
            .cloned()
    }
    pub(crate) fn ack_key(self: &Arc<Self>, peer: Digest32, token: &Arc<()>) {
        let mut dirty = self.key_dirty.lock().unwrap_or_else(|e| e.into_inner());
        if dirty
            .get(&peer)
            .is_some_and(|current| Arc::ptr_eq(current, token))
        {
            dirty.remove(&peer);
        }
    }
    pub(crate) fn observe(self: &Arc<Self>, peer: Digest32, head: HeadHint) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.entry(peer).or_default();
        if entry.head == Some(head) {
            if !entry.dirty {
                return;
            }
            entry.dirty = false;
            drop(entries);
            self.signal(peer);
            return;
        }
        let was_dirty = entry.dirty;
        entry.head = Some(head);
        entry.dirty = false;
        entry.token = Arc::new(());
        entry.sent = false;
        drop(entries);
        if !was_dirty {
            self.signal(peer);
        }
    }
    /// A committed role-producing fact changed. Resolution is left to the owned
    /// inventory worker; the producer never does a fallible read after committing it.
    pub(crate) fn mark_dirty(self: &Arc<Self>, peer: Digest32) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.entry(peer).or_default();
        if entry.dirty {
            return;
        }
        entry.dirty = true;
        drop(entries);
        self.signal(peer);
    }
    pub(crate) fn clear(self: &Arc<Self>, peer: Digest32) {
        let removed = self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&peer)
            .is_some();
        if removed {
            self.signal(peer);
        }
    }
    pub(crate) fn unavailable(self: &Arc<Self>, peer: Digest32) {
        self.clear(peer);
    }
    pub(crate) fn retain_authors(self: &Arc<Self>, keep: impl Fn(&Digest32) -> bool) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let removed: Vec<_> = entries.keys().filter(|peer| !keep(peer)).copied().collect();
        entries.retain(|peer, _| keep(peer));
        drop(entries);
        let mut key_dirty = self.key_dirty.lock().unwrap_or_else(|e| e.into_inner());
        key_dirty.retain(|peer, _| keep(peer));
        drop(key_dirty);
        for peer in removed {
            self.signal(peer);
        }
    }
    pub(crate) fn snapshot(&self, peer: Digest32) -> Option<(Arc<()>, HeadHint)> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.get(&peer)?;
        if entry.dirty {
            return None;
        }
        Some((Arc::clone(&entry.token), entry.head?))
    }
    pub(crate) fn ack(self: &Arc<Self>, peer: Digest32, token: &Arc<()>) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let changed = entries.get_mut(&peer).is_some_and(|entry| {
            if Arc::ptr_eq(&entry.token, token) && !entry.dirty && !entry.sent {
                entry.sent = true;
                true
            } else {
                false
            }
        });
        drop(entries);
        if changed {
            self.signal(peer);
        }
    }
    pub(crate) fn pending(&self, peer: Digest32) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&peer)
            .is_some_and(|entry| entry.dirty || (entry.head.is_some() && !entry.sent))
    }
    pub(crate) fn on_connect(self: &Arc<Self>, peer: Digest32) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = entries.get_mut(&peer) else {
            return;
        };
        if entry.head.is_none() {
            return;
        }
        entry.token = Arc::new(());
        entry.sent = false;
        drop(entries);
        self.signal(peer);
    }
}
