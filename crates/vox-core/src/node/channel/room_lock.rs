//! A room's lock, and how many times it has been granted.
//!
//! Nothing changes a room's state but a holder of its lock. A room whose lock has not been
//! granted since a reader last held it is therefore exactly as that reader left it: the status
//! publication (`Node::view_of`) reads a room again only when its count moved, and keeps what it
//! published of a room nobody has held since.
use super::ChannelState;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard, OwnedMutexGuard, TryLockError};

/// A room's state behind its lock (see the module).
pub struct RoomLock {
    /// Only [`OwnedRoomGuard`]s clone it, and each also holds this room's own `Arc`.
    state: Arc<Mutex<ChannelState>>,
    granted: AtomicU64,
}

/// The room held through an owned handle. It keeps the room's own `Arc` alive as tokio's
/// owned guard keeps its mutex's: a room is the same instance for as long as anyone holds it.
pub struct OwnedRoomGuard {
    guard: OwnedMutexGuard<ChannelState>,
    _room: Arc<RoomLock>,
}

impl std::ops::Deref for OwnedRoomGuard {
    type Target = ChannelState;
    fn deref(&self) -> &ChannelState {
        &self.guard
    }
}

impl std::ops::DerefMut for OwnedRoomGuard {
    fn deref_mut(&mut self) -> &mut ChannelState {
        &mut self.guard
    }
}

impl RoomLock {
    pub(crate) fn new(state: ChannelState) -> Self {
        Self {
            state: Arc::new(Mutex::new(state)),
            granted: AtomicU64::new(0),
        }
    }

    /// Counted once the lock is held and before the holder can change anything.
    fn grant(&self) {
        self.granted.fetch_add(1, Ordering::SeqCst);
    }

    /// How many times this lock has been granted. Read while holding it, it counts that hold.
    pub(crate) fn granted(&self) -> u64 {
        self.granted.load(Ordering::SeqCst)
    }

    pub(crate) async fn lock(&self) -> MutexGuard<'_, ChannelState> {
        let guard = self.state.lock().await;
        self.grant();
        guard
    }

    pub(crate) fn try_lock(&self) -> Result<MutexGuard<'_, ChannelState>, TryLockError> {
        let guard = self.state.try_lock()?;
        self.grant();
        Ok(guard)
    }

    pub(crate) fn blocking_lock(&self) -> MutexGuard<'_, ChannelState> {
        let guard = self.state.blocking_lock();
        self.grant();
        guard
    }

    pub(crate) async fn lock_owned(self: Arc<Self>) -> OwnedRoomGuard {
        let guard = Arc::clone(&self.state).lock_owned().await;
        self.grant();
        OwnedRoomGuard { guard, _room: self }
    }

    pub(crate) fn try_lock_owned(self: Arc<Self>) -> Result<OwnedRoomGuard, TryLockError> {
        let guard = Arc::clone(&self.state).try_lock_owned()?;
        self.grant();
        Ok(OwnedRoomGuard { guard, _room: self })
    }

    /// The room's state, when `this` is its only handle; `this` back otherwise.
    pub(crate) fn try_unwrap(this: Arc<Self>) -> Result<ChannelState, Arc<Self>> {
        let room = Arc::try_unwrap(this)?;
        // Every other handle on `state` is an owned guard, which holds `this` too: none is left.
        match Arc::try_unwrap(room.state) {
            Ok(state) => Ok(state.into_inner()),
            Err(state) => Err(Arc::new(Self {
                state,
                granted: room.granted,
            })),
        }
    }
}
