//! Retained physical own-key completion and the lifecycle work waiting for its retirement.
use crate::hash::Digest32;
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::Notify;

#[derive(Clone, Copy)]
pub(super) struct Identity {
    pub room: Digest32,
    pub peer: Digest32,
    pub request: [u8; 16],
}

pub(super) enum Completed {
    Request(Identity),
    Lifecycle(Box<super::leave_save::Ready>),
}

#[derive(Default)]
struct State {
    pending: Vec<Completed>,
    lifecycle_epoch: u64,
}

#[derive(Default)]
pub(super) struct Completions {
    state: Mutex<State>,
    pub notify: Notify,
}

impl Completions {
    pub fn lease(self: &Arc<Self>, identity: Identity) -> Arc<Lease> {
        Arc::new(Lease {
            identity,
            owner: Arc::downgrade(self),
        })
    }
    pub fn take(&self) -> Vec<Completed> {
        std::mem::take(&mut self.state.lock().unwrap_or_else(|e| e.into_inner()).pending)
    }

    pub fn lifecycle_epoch(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .lifecycle_epoch
    }

    pub fn complete_lifecycle(&self, epoch: u64, ready: super::leave_save::Ready) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.lifecycle_epoch == epoch {
            state.pending.push(Completed::Lifecycle(Box::new(ready)));
            drop(state);
            self.notify.notify_one();
        } else {
            drop(state);
            ready.retire();
        }
    }

    /// Lock clears the own-key schedulers as well as lifecycle admission. Retire their
    /// old completions without dropping secret-bearing results under the book's mutex.
    pub fn retire_lifecycle(&self) {
        let completed = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.lifecycle_epoch = state.lifecycle_epoch.wrapping_add(1);
            std::mem::take(&mut state.pending)
        };
        for completed in completed {
            if let Completed::Lifecycle(ready) = completed {
                ready.retire();
            }
        }
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
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pending
                .push(Completed::Request(self.identity));
            owner.notify.notify_one();
        }
    }
}
