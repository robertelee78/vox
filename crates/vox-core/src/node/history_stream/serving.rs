//! The rooms this node answers other members' bounded requests for, on each connection's own
//! task rather than the node actor's. The actor installs a room when it opens it and retires
//! the answers in flight when it retires the room or a peer's port, as it retires its own.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};

use crate::hash::Digest32;
use crate::node::channel::{ChannelState, RoomSnapshotCell};
use crate::node::history_budget::Budget;
use crate::node::status::SharedSyncBook;
use crate::node::store::Store;
use crate::transport::stream_transport::Fence;

use super::HintInbox;

/// What an answer needs of one open room. Weak: a closed room is not kept alive by serving.
#[derive(Clone)]
pub(crate) struct OpenRoom {
    pub(crate) channel: Weak<tokio::sync::Mutex<ChannelState>>,
    pub(crate) snapshot: Weak<RoomSnapshotCell>,
    pub(crate) store: Weak<Store>,
    /// This node's identity, whose daemon-wide serving budget an answer is admitted under.
    pub(crate) node: Digest32,
}

struct Live {
    peer: Digest32,
    fence: Arc<Fence>,
    abort: Option<tokio::task::AbortHandle>,
}

struct Entry {
    room: OpenRoom,
    live: BTreeMap<u64, Live>,
}

/// Node-wide: the open rooms and the answers running for them.
pub(crate) struct Serving {
    rooms: StdMutex<BTreeMap<Digest32, Entry>>,
    next: AtomicU64,
    pub(crate) budget: Arc<Budget>,
    pub(crate) book: SharedSyncBook,
    pub(crate) inbox: Arc<HintInbox>,
    /// The members answered since the actor last took them, by room and member; `true` when an
    /// answer accepted a new inventory hint. See [`Self::answered`].
    answered: StdMutex<BTreeMap<(Digest32, Digest32), bool>>,
    /// Woken when a member is marked answered; the actor takes the marks when it next runs.
    pub(crate) answered_wake: tokio::sync::Notify,
}

impl Serving {
    pub(crate) fn new(budget: Arc<Budget>, book: SharedSyncBook, inbox: Arc<HintInbox>) -> Self {
        Self {
            rooms: StdMutex::new(BTreeMap::new()),
            next: AtomicU64::new(0),
            budget,
            book,
            inbox,
            answered: StdMutex::new(BTreeMap::new()),
            answered_wake: tokio::sync::Notify::new(),
        }
    }

    fn rooms(&self) -> std::sync::MutexGuard<'_, BTreeMap<Digest32, Entry>> {
        self.rooms.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A finished answer marks its member and wakes the actor, never waiting for it. What the
    /// actor does with answers (make sure of the member's port, wake the room for a new
    /// inventory hint) is the same for one as for many, so the marks coalesce: one per room and
    /// member however many answers finish while the actor is busy, and no task is left waiting.
    pub(crate) fn answered(&self, id: Digest32, peer: Digest32, inventory_added: bool) {
        *self
            .answered
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry((id, peer))
            .or_default() |= inventory_added;
        self.answered_wake.notify_one();
    }

    /// The members answered since the last take (see [`Self::answered`]).
    pub(crate) fn take_answered(&self) -> BTreeMap<(Digest32, Digest32), bool> {
        std::mem::take(&mut *self.answered.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Answer `id` from this room instance from now on; answers for a replaced instance end.
    pub(crate) fn install(&self, id: Digest32, room: OpenRoom) {
        let replaced = self.rooms().insert(
            id,
            Entry {
                room,
                live: BTreeMap::new(),
            },
        );
        if let Some(replaced) = replaced {
            replaced.live.into_values().for_each(Live::retire);
        }
    }

    pub(crate) fn room(&self, id: &Digest32) -> Option<OpenRoom> {
        self.rooms().get(id).map(|entry| entry.room.clone())
    }

    /// Admit one answer to `peer`, or `None` when it already has
    /// [`crate::node::ports::INBOUND_PER_PORT`] in flight: past that a request is refused at
    /// once, never held, as the actor refused it. The token also names the answer in
    /// `vox status`, apart from the actor's own tokens.
    pub(crate) fn begin(&self, id: Digest32, peer: Digest32, fence: Arc<Fence>) -> Option<u64> {
        let mut rooms = self.rooms();
        let entry = rooms.get_mut(&id)?;
        let running = entry.live.values().filter(|live| live.peer == peer).count();
        if running >= crate::node::ports::INBOUND_PER_PORT {
            return None;
        }
        let token = (1 << 63) | self.next.fetch_add(1, Ordering::Relaxed);
        entry.live.insert(
            token,
            Live {
                peer,
                fence,
                abort: None,
            },
        );
        Some(token)
    }

    /// The task running answer `token`, so a retirement can end it.
    pub(crate) fn running(&self, id: Digest32, token: u64, abort: tokio::task::AbortHandle) {
        match self
            .rooms()
            .get_mut(&id)
            .and_then(|entry| entry.live.get_mut(&token))
        {
            Some(live) => live.abort = Some(abort),
            None => abort.abort(),
        }
    }

    /// Whether answer `token` is still the room's: a retired answer is not counted.
    pub(crate) fn end(&self, id: Digest32, token: u64) -> bool {
        self.rooms()
            .get_mut(&id)
            .and_then(|entry| entry.live.remove(&token))
            .is_some()
    }

    /// End the answers in flight for the room, or for one peer of it.
    pub(crate) fn retire(&self, id: Digest32, peer: Option<Digest32>) {
        let retired: Vec<Live> = {
            let mut rooms = self.rooms();
            let Some(entry) = rooms.get_mut(&id) else {
                return;
            };
            let tokens: Vec<u64> = entry
                .live
                .iter()
                .filter(|(_, live)| peer.is_none_or(|peer| live.peer == peer))
                .map(|(token, _)| *token)
                .collect();
            tokens
                .into_iter()
                .filter_map(|token| entry.live.remove(&token))
                .collect()
        };
        retired.into_iter().for_each(Live::retire);
    }

    /// Stop answering for the room: it is closing, being left or purged.
    pub(crate) fn withdraw(&self, id: Digest32) {
        if let Some(entry) = self.rooms().remove(&id) {
            entry.live.into_values().for_each(Live::retire);
        }
    }
}

impl Live {
    fn retire(self) {
        self.fence.retire();
        if let Some(abort) = self.abort {
            abort.abort();
        }
    }
}
