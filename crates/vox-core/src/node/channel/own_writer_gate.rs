//! Physical own-key response writers and the room authority transitions that retire them.
use std::sync::Arc;
use tokio::sync::{
    watch, Mutex, OwnedMutexGuard, OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock,
};

pub(crate) struct Gate {
    admission: Arc<Mutex<()>>,
    writers: Arc<RwLock<()>>,
    cancel: watch::Sender<()>,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            admission: Arc::new(Mutex::new(())),
            writers: Arc::new(RwLock::new(())),
            cancel: watch::channel(()).0,
        }
    }
}

/// Owns the writer until the physical send task drops it, including cancellation.
pub(crate) struct Writer {
    _lease: OwnedRwLockReadGuard<()>,
    pub(crate) cancel: watch::Receiver<()>,
}

/// Closes writer admission and keeps it closed through the physical authority commit.
pub(crate) struct Transition {
    _writers: OwnedRwLockWriteGuard<()>,
    _admission: OwnedMutexGuard<()>,
}

impl Gate {
    /// Called while the actor holds the current room and has checked authority.
    pub(crate) fn try_writer(&self) -> Option<Writer> {
        let _admission = Arc::clone(&self.admission).try_lock_owned().ok()?;
        let lease = Arc::clone(&self.writers).try_read_owned().ok()?;
        let cancel = self.cancel.subscribe();
        Some(Writer {
            _lease: lease,
            cancel,
        })
    }

    /// Wait for a transition to reopen admission; the caller revalidates its room afterwards.
    pub(crate) async fn wait_open(&self) {
        drop(Arc::clone(&self.admission).lock_owned().await);
    }

    /// Wait off actor: no writer admitted before this fence may outlive its acquisition.
    pub(crate) async fn transition(&self) -> Transition {
        let admission = Arc::clone(&self.admission).lock_owned().await;
        self.cancel.send_replace(());
        let writers = Arc::clone(&self.writers).write_owned().await;
        Transition {
            _writers: writers,
            _admission: admission,
        }
    }
}
