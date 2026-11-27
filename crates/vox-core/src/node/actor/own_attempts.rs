//! Lifecycle work (the lifecycle saves that share this book) waiting for the actor, fenced by
//! the lock's lifecycle epoch.
use std::sync::Mutex;
use tokio::sync::Notify;

#[derive(Default)]
struct State {
    pending: Vec<super::leave_save::Ready>,
    lifecycle_epoch: u64,
}

#[derive(Default)]
pub(super) struct Completions {
    state: Mutex<State>,
    pub notify: Notify,
}

impl Completions {
    pub fn take(&self) -> Vec<super::leave_save::Ready> {
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
            state.pending.push(ready);
            drop(state);
            self.notify.notify_one();
        } else {
            drop(state);
            ready.retire();
        }
    }

    /// Lock retires lifecycle admission. Retire the old completions without dropping
    /// secret-bearing results under the book's mutex.
    pub fn retire_lifecycle(&self) {
        let completed = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.lifecycle_epoch = state.lifecycle_epoch.wrapping_add(1);
            std::mem::take(&mut state.pending)
        };
        for ready in completed {
            ready.retire();
        }
    }
}
