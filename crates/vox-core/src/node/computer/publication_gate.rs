//! Owned physical leases with synchronous writer waits and asynchronous off-actor admission.
//! No guard borrows a task or OS thread, so cancellation only drops ownership: it cannot revoke
//! an irreversible operation. Waiting writers close reader admission before draining readers.
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

#[derive(Default)]
struct State {
    readers: usize,
    waiting: usize,
    writing: bool,
}

#[derive(Default)]
pub(super) struct Gate {
    state: Mutex<State>,
    drained: Condvar,
    changed: tokio::sync::Notify,
}

pub(super) struct Reader {
    gate: Arc<Gate>,
}

pub(super) struct Writer {
    gate: Arc<Gate>,
}

struct WaitingWriter {
    gate: Arc<Gate>,
    waiting: bool,
}

impl Gate {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn wake(&self) {
        self.drained.notify_all();
        self.changed.notify_waiters();
    }

    pub(super) fn writer_pending(&self) -> bool {
        let state = self.state();
        state.writing || state.waiting != 0
    }
    pub(super) fn try_read(self: &Arc<Self>) -> Option<Reader> {
        let mut state = self.state();
        if state.writing || state.waiting != 0 {
            return None;
        }
        state.readers += 1;
        Some(Reader {
            gate: Arc::clone(self),
        })
    }

    pub(super) async fn read(self: &Arc<Self>) -> Reader {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(reader) = self.try_read() {
                return reader;
            }
            notified.await;
        }
    }

    pub(super) fn try_write(self: &Arc<Self>) -> Option<Writer> {
        let mut state = self.state();
        if state.writing || state.readers != 0 || state.waiting != 0 {
            return None;
        }
        state.writing = true;
        Some(Writer {
            gate: Arc::clone(self),
        })
    }

    fn waiting_writer(self: &Arc<Self>) -> WaitingWriter {
        self.state().waiting += 1;
        WaitingWriter {
            gate: Arc::clone(self),
            waiting: true,
        }
    }

    pub(super) async fn write(self: &Arc<Self>) -> Writer {
        let mut waiting = self.waiting_writer();
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.state();
                if !state.writing && state.readers == 0 {
                    state.waiting -= 1;
                    state.writing = true;
                    waiting.waiting = false;
                    return Writer {
                        gate: Arc::clone(self),
                    };
                }
            }
            notified.await;
        }
    }

    /// The caller is already on a blocking transaction thread and owns no state/room guard.
    /// A Condvar also preserves synchronous/current-thread-runtime callers, unlike Tokio's
    /// `blocking_write`, which rejects calls from a current-thread runtime.
    pub(super) fn blocking_write(self: &Arc<Self>) -> Writer {
        let mut state = self.state();
        state.waiting += 1;
        while state.writing || state.readers != 0 {
            state = self
                .drained
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        state.waiting -= 1;
        state.writing = true;
        Writer {
            gate: Arc::clone(self),
        }
    }
}

impl Writer {
    pub(super) fn belongs_to(&self, gate: &Arc<Gate>) -> bool {
        Arc::ptr_eq(&self.gate, gate)
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        let drained = {
            let mut state = self.gate.state();
            state.readers -= 1;
            state.readers == 0
        };
        if drained {
            self.gate.wake();
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.gate.state().writing = false;
        self.gate.wake();
    }
}

impl Drop for WaitingWriter {
    fn drop(&mut self) {
        if self.waiting {
            self.gate.state().waiting -= 1;
            self.gate.wake();
        }
    }
}
