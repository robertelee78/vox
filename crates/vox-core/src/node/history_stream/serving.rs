//! The rooms this node answers other members' bounded requests for, on each connection's own
//! task rather than the node actor's. The actor installs a room when it opens it and retires
//! the answers in flight when it retires the room or a peer's port, as it retires its own.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};

use crate::hash::Digest32;
use crate::node::channel::RoomSnapshotCell;
use crate::node::history_budget::Budget;
use crate::node::status::SharedSyncBook;
use crate::node::store::Store;
use crate::transport::stream_transport::Fence;

use super::pull::Holdings;

/// What an answer needs of one open room. Weak: a closed room is not kept alive by serving.
#[derive(Clone)]
pub(crate) struct OpenRoom {
    pub(crate) channel: Weak<crate::node::channel::RoomLock>,
    pub(crate) snapshot: Weak<RoomSnapshotCell>,
    pub(crate) store: Weak<Store>,
    /// This node's identity, whose daemon-wide serving budget an answer is admitted under.
    pub(crate) node: Digest32,
}

struct Live {
    peer: Digest32,
    /// The connection the request came on.
    serial: u64,
    fence: Arc<Fence>,
    abort: Option<tokio::task::AbortHandle>,
    /// Where its query counts, once read ([`Serving::place`]).
    place: Option<Place>,
}

/// Where an answer counts once its query is read, decided by the holder from the query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Place {
    /// One of the old flows' queries, counted against the per-peer limit.
    OldFlow,
    /// The exchange of a connection's one loop: its Have (`have`), or its one ask (a Range, a
    /// listed fork or head, its own receipt). One of each per connection and room.
    Loop { have: bool },
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
    /// Every connected peer's last Have, which a peer's Have request updates.
    pub(crate) holdings: Arc<Holdings>,
    /// Members answered since the actor last took them, by room and member.
    answered: StdMutex<BTreeSet<(Digest32, Digest32)>>,
    /// Woken when a member is marked answered; the actor takes the marks when it next runs.
    pub(crate) answered_wake: tokio::sync::Notify,
    /// What the private Session serve needs of this node, off the actor: its keyring's Drive
    /// holders, the secret-work lease and the policy authority, as the actor last published
    /// them while unlocked (`actor::private_serve`). `None` while locked.
    private: StdMutex<Option<Arc<crate::node::actor::PrivateServing>>>,
}

impl Serving {
    pub(crate) fn new(budget: Arc<Budget>, book: SharedSyncBook, holdings: Arc<Holdings>) -> Self {
        Self {
            rooms: StdMutex::new(BTreeMap::new()),
            next: AtomicU64::new(0),
            budget,
            book,
            holdings,
            answered: StdMutex::new(BTreeSet::new()),
            answered_wake: tokio::sync::Notify::new(),
            private: StdMutex::new(None),
        }
    }

    pub(crate) fn private(&self) -> Option<Arc<crate::node::actor::PrivateServing>> {
        self.private
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub(crate) fn set_private(&self, private: Option<Arc<crate::node::actor::PrivateServing>>) {
        *self.private.lock().unwrap_or_else(|e| e.into_inner()) = private;
    }

    fn rooms(&self) -> std::sync::MutexGuard<'_, BTreeMap<Digest32, Entry>> {
        self.rooms.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A finished answer marks its member and wakes the actor, without waiting for it.
    pub(crate) fn answered(&self, id: Digest32, peer: Digest32) {
        self.answered
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((id, peer));
        self.answered_wake.notify_one();
    }

    /// The members answered since the last take (see [`Self::answered`]).
    pub(crate) fn take_answered(&self) -> BTreeSet<(Digest32, Digest32)> {
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

    /// Register one answer to `peer` on connection `serial`, so a retirement can end it; `None`
    /// when the room is not served. The token also names the answer in `vox status`, apart from
    /// the actor's own.
    pub(crate) fn begin(
        &self,
        id: Digest32,
        peer: Digest32,
        serial: u64,
        fence: Arc<Fence>,
    ) -> Option<u64> {
        let mut rooms = self.rooms();
        let entry = rooms.get_mut(&id)?;
        let token = (1 << 63) | self.next.fetch_add(1, Ordering::Relaxed);
        entry.live.insert(
            token,
            Live {
                peer,
                serial,
                fence,
                abort: None,
                place: None,
            },
        );
        Some(token)
    }

    /// Count answer `token` where its query puts it, or `false` when it does not fit (or was
    /// retired). An old flow's query past [`crate::node::ports::INBOUND_PER_PORT`] of its
    /// peer's in flight is refused at once, never held, as the actor refuses it. A loop's
    /// exchange takes its connection's one place of that kind in the room: its asker sends the
    /// next only once the last ended or was abandoned, so an earlier answer still in that place
    /// is over and is retired here. So, whatever the asker claims, one Have and one ask per
    /// connection and room are answered at a time.
    pub(crate) fn place(&self, id: Digest32, token: u64, place: Place) -> bool {
        let retired: Vec<Live> = {
            let mut rooms = self.rooms();
            let Some(entry) = rooms.get_mut(&id) else {
                return false;
            };
            let Some((peer, serial)) = entry.live.get(&token).map(|live| (live.peer, live.serial))
            else {
                return false;
            };
            let earlier: Vec<u64> = entry
                .live
                .iter()
                .filter(|(_, live)| live.peer == peer && live.place == Some(place))
                .filter(|(_, live)| place == Place::OldFlow || live.serial == serial)
                .map(|(token, _)| *token)
                .collect();
            if place == Place::OldFlow && earlier.len() >= crate::node::ports::INBOUND_PER_PORT {
                return false;
            }
            if let Some(live) = entry.live.get_mut(&token) {
                live.place = Some(place);
            }
            if place == Place::OldFlow {
                Vec::new()
            } else {
                earlier
                    .into_iter()
                    .filter_map(|token| entry.live.remove(&token))
                    .collect()
            }
        };
        retired.into_iter().for_each(Live::retire);
        true
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

    /// Whether answer `token` is still the room's (a retired answer is not counted), and if so
    /// whether it answered one of the old flows' queries: a round of the peer's that `vox status`
    /// counts, where a loop's exchange is not.
    pub(crate) fn end(&self, id: Digest32, token: u64) -> Option<bool> {
        self.rooms()
            .get_mut(&id)
            .and_then(|entry| entry.live.remove(&token))
            .map(|live| live.place == Some(Place::OldFlow))
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
