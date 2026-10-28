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
type CatalogState = (u64, [u8; 16], Option<([u8; 16], u64)>);

#[derive(Default)]
pub(crate) struct RoleOwed {
    entries: Mutex<BTreeMap<Digest32, Entry>>,
    key_dirty: Mutex<BTreeMap<Digest32, Arc<()>>>,
    key_catalogs: Mutex<BTreeMap<Digest32, CatalogState>>,
    key_catalog_changed: Mutex<BTreeMap<Digest32, Arc<()>>>,
    provider_prune_dirty: std::sync::atomic::AtomicBool,
    key_retention_dirty: std::sync::atomic::AtomicBool,
    wake: Mutex<Option<Weak<RoleWake>>>,
    room: Mutex<Option<Digest32>>,
}

/// Coalesces producer edges without losing a wake to the actor's bounded inbox.
#[derive(Default)]
pub(crate) struct RoleWake {
    current: Mutex<BTreeMap<Digest32, Weak<RoleOwed>>>,
    pending: Mutex<BTreeMap<(Digest32, Digest32), Weak<RoleOwed>>>,
    board_pending: Mutex<BTreeMap<Digest32, Weak<RoleOwed>>>,
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
    pub(crate) fn take_board(&self) -> Vec<(Digest32, Arc<RoleOwed>)> {
        std::mem::take(&mut *self.board_pending.lock().unwrap_or_else(|e| e.into_inner()))
            .into_iter()
            .filter_map(|(room, owner)| owner.upgrade().map(|owner| (room, owner)))
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
    /// An authenticated inventory hint is a reason to inspect new catalog entries, not
    /// evidence that a body exists or a grant to fetch it.
    pub(crate) fn key_catalog_on_connect(
        &self,
        peer: Digest32,
        serial: u64,
    ) -> crate::error::Result<()> {
        let mut catalogs = self.key_catalogs.lock().unwrap_or_else(|e| e.into_inner());
        if catalogs
            .get(&peer)
            .is_some_and(|(current, _, _)| *current == serial)
        {
            return Ok(());
        }
        let incarnation = crate::identity::rng::random_array::<16>()?;
        catalogs.insert(peer, (serial, incarnation, None));
        Ok(())
    }
    pub(crate) fn key_catalog_connection(&self, peer: Digest32) -> Option<(u64, [u8; 16])> {
        self.key_catalogs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&peer)
            .map(|(serial, incarnation, _)| (*serial, *incarnation))
    }
    pub(crate) fn observe_key_catalog(
        self: &Arc<Self>,
        peer: Digest32,
        instance: [u8; 16],
        tip: u64,
        serial: u64,
    ) {
        let mut catalogs = self.key_catalogs.lock().unwrap_or_else(|e| e.into_inner());
        let Some((current, _, previous)) = catalogs.get_mut(&peer) else {
            return;
        };
        if *current != serial {
            return;
        }
        if previous
            .is_some_and(|(old_instance, old_tip)| old_instance == instance && old_tip >= tip)
        {
            return;
        }
        *previous = Some((instance, tip));
        drop(catalogs);
        self.signal(peer);
    }
    /// An actual local acquisition retains an exact inventory obligation until the
    /// current peer completes the exchange. A later acquisition replaces its token.
    pub(crate) fn mark_key_catalog_changed(self: &Arc<Self>, peer: Digest32) {
        self.key_catalog_changed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(peer, Arc::new(()));
        self.signal(peer);
    }
    pub(crate) fn key_catalog_announcement(&self, peer: Digest32) -> Option<Arc<()>> {
        self.key_catalog_changed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&peer)
            .cloned()
    }
    pub(crate) fn ack_key_catalog_announcement(
        self: &Arc<Self>,
        peer: Digest32,
        token: &Arc<()>,
        serial: u64,
    ) {
        let catalogs = self.key_catalogs.lock().unwrap_or_else(|e| e.into_inner());
        if catalogs
            .get(&peer)
            .is_none_or(|(current, _, _)| *current != serial)
        {
            return;
        }
        let mut entries = self
            .key_catalog_changed
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if entries
            .get(&peer)
            .is_some_and(|current| Arc::ptr_eq(current, token))
        {
            entries.remove(&peer);
            drop(entries);
            drop(catalogs);
            self.signal(peer);
        }
    }
    pub(crate) fn key_catalog(&self, peer: Digest32) -> Option<([u8; 16], u64)> {
        self.key_catalogs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&peer)
            .and_then(|(_, _, catalog)| *catalog)
    }

    pub(crate) fn mark_key_retention_dirty(self: &Arc<Self>, local: Digest32) {
        self.key_retention_dirty
            .store(true, std::sync::atomic::Ordering::Release);
        self.signal(local);
    }
    pub(crate) fn key_retention_dirty(&self) -> bool {
        self.key_retention_dirty
            .load(std::sync::atomic::Ordering::Acquire)
    }
    pub(crate) fn take_key_retention_dirty(&self) -> bool {
        self.key_retention_dirty
            .swap(false, std::sync::atomic::Ordering::AcqRel)
    }

    pub(crate) fn mark_key_provider_prune(self: &Arc<Self>, peer: Digest32) {
        self.provider_prune_dirty
            .store(true, std::sync::atomic::Ordering::Release);
        self.signal(peer);
    }
    pub(crate) fn key_provider_prune_pending(&self) -> bool {
        self.provider_prune_dirty
            .load(std::sync::atomic::Ordering::Acquire)
    }
    pub(crate) fn take_key_provider_prune(&self) -> bool {
        self.provider_prune_dirty
            .swap(false, std::sync::atomic::Ordering::AcqRel)
    }

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
        let mut catalogs = self.key_catalogs.lock().unwrap_or_else(|e| e.into_inner());
        catalogs.retain(|peer, _| keep(peer));
        drop(catalogs);
        self.key_catalog_changed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|peer, _| keep(peer));
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
