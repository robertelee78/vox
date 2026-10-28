//! Physical own-key response writers and the authority transitions that retire them.
use crate::hash::Digest32;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use tokio::sync::{
    watch, Mutex, OwnedMutexGuard, OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock,
};

struct Peer {
    _connection: Arc<crate::transport::quic::VoxConnection>,
    writers: Arc<RwLock<()>>,
    cancel: watch::Sender<()>,
    interrupted: std::sync::atomic::AtomicBool,
}

pub(crate) struct Gate {
    admission: Arc<Mutex<()>>,
    peers: StdMutex<BTreeMap<(Digest32, usize), Weak<Peer>>>,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            admission: Arc::new(Mutex::new(())),
            peers: StdMutex::new(BTreeMap::new()),
        }
    }
}

/// Owns the writer until the physical send task drops it, including cancellation.
pub(crate) struct Writer {
    peer: Arc<Peer>,
    gate: Arc<Gate>,
    _lease: OwnedRwLockReadGuard<()>,
    pub(crate) cancel: watch::Receiver<()>,
}

/// One coalesced, physically interrupted response to re-evaluate after admission reopens.
pub(crate) struct Interrupted {
    peer: Arc<Peer>,
    pub(crate) gate: Arc<Gate>,
}

impl Drop for Interrupted {
    fn drop(&mut self) {
        self.peer
            .interrupted
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

impl Writer {
    pub(crate) fn interrupted(&self) -> Option<Interrupted> {
        if self
            .peer
            .interrupted
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            None
        } else {
            Some(Interrupted {
                peer: Arc::clone(&self.peer),
                gate: Arc::clone(&self.gate),
            })
        }
    }
}

/// Closes admission and holds the exact affected writers through the authority commit.
pub(crate) struct Transition {
    _writers: Vec<OwnedRwLockWriteGuard<()>>,
    _admission: OwnedMutexGuard<()>,
}

impl Gate {
    fn selected(&self, targets: Option<&[Digest32]>) -> Vec<Arc<Peer>> {
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        peers.retain(|_, peer| peer.strong_count() != 0);
        peers
            .iter()
            .filter(|(id, _)| targets.is_none_or(|targets| targets.contains(&id.0)))
            .filter_map(|(_, peer)| peer.upgrade())
            .collect()
    }

    /// Called while the actor holds the current room and has checked authority.
    pub(crate) fn try_writer(
        self: &Arc<Self>,
        id: Digest32,
        connection: &Arc<crate::transport::quic::VoxConnection>,
    ) -> Option<Writer> {
        let _admission = Arc::clone(&self.admission).try_lock_owned().ok()?;
        let peer = {
            let mut peers = self
                .peers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            peers.retain(|_, peer| peer.strong_count() != 0);
            // The strong connection lease prevents pointer reuse while this owner exists.
            let key = (id, Arc::as_ptr(connection) as usize);
            if let Some(peer) = peers.get(&key).and_then(Weak::upgrade) {
                peer
            } else {
                let peer = Arc::new(Peer {
                    _connection: Arc::clone(connection),
                    writers: Arc::new(RwLock::new(())),
                    cancel: watch::channel(()).0,
                    interrupted: std::sync::atomic::AtomicBool::new(false),
                });
                peers.insert(key, Arc::downgrade(&peer));
                peer
            }
        };
        let lease = Arc::clone(&peer.writers).try_read_owned().ok()?;
        let cancel = peer.cancel.subscribe();
        Some(Writer {
            peer,
            gate: Arc::clone(self),
            _lease: lease,
            cancel,
        })
    }

    /// Try without waiting on actor. Only affected writers receive cancellation.
    pub(crate) fn try_transition(&self, targets: Option<&[Digest32]>) -> Option<Transition> {
        let admission = Arc::clone(&self.admission).try_lock_owned().ok()?;
        let peers = self.selected(targets);
        for peer in &peers {
            peer.cancel.send_replace(());
        }
        let mut writers = Vec::with_capacity(peers.len());
        for peer in peers {
            writers.push(Arc::clone(&peer.writers).try_write_owned().ok()?);
        }
        Some(Transition {
            _writers: writers,
            _admission: admission,
        })
    }

    /// Hold admission briefly while rechecking authority and publishing a resumed edge.
    pub(crate) fn try_open(&self) -> Option<OwnedMutexGuard<()>> {
        Arc::clone(&self.admission).try_lock_owned().ok()
    }

    /// Wait for a transition to reopen admission; the caller revalidates its room afterwards.
    pub(crate) async fn wait_open(&self) {
        drop(Arc::clone(&self.admission).lock_owned().await);
    }

    /// Cancel and join only affected writers off actor, retaining admission until commit.
    pub(crate) async fn transition(&self, targets: Option<&[Digest32]>) -> Transition {
        let admission = Arc::clone(&self.admission).lock_owned().await;
        let peers = self.selected(targets);
        for peer in &peers {
            peer.cancel.send_replace(());
        }
        let mut writers = Vec::with_capacity(peers.len());
        for peer in peers {
            writers.push(Arc::clone(&peer.writers).write_owned().await);
        }
        Transition {
            _writers: writers,
            _admission: admission,
        }
    }
}
