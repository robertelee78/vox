//! Retained physical completion of independently owned own-key requests.
use crate::hash::Digest32;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::Notify;

#[derive(Clone, Copy)]
pub(super) struct Identity {
    pub room: Digest32,
    pub peer: Digest32,
    pub request: [u8; 16],
}

#[derive(Default)]
pub(super) struct Completions {
    pending: Mutex<BTreeSet<(Digest32, Digest32, [u8; 16])>>,
    pub notify: Notify,
}

impl Completions {
    pub fn lease(self: &Arc<Self>, identity: Identity) -> Arc<Lease> {
        Arc::new(Lease {
            identity,
            owner: Arc::downgrade(self),
        })
    }
    pub fn take(&self) -> Vec<Identity> {
        std::mem::take(&mut *self.pending.lock().unwrap_or_else(|e| e.into_inner()))
            .into_iter()
            .map(|(room, peer, request)| Identity {
                room,
                peer,
                request,
            })
            .collect()
    }
}

/// The final clone is dropped only after the task, blocking work, and handed-off output exit.
pub(super) struct Lease {
    identity: Identity,
    owner: Weak<Completions>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.upgrade() {
            owner
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert((
                    self.identity.room,
                    self.identity.peer,
                    self.identity.request,
                ));
            owner.notify.notify_one();
        }
    }
}
