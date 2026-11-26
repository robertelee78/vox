//! Cancellation fences and frame deadlines shared by history streams.

use std::time::Duration;

/// Per-frame deadline for a history stream.
pub const SYNC_FRAME_TIMEOUT: Duration = Duration::from_secs(20);

/// A session's **fence** (ADR-025 D1a): once retired, a session stops at its next room step or
/// transport operation. Aborting the task that started a session does not stop a worker already
/// running it on a blocking thread, so the worker is told this way instead, and a transport
/// operation it is blocked in returns at once, resetting the stream.
#[derive(Debug, Default)]
pub struct Fence {
    retired: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl Fence {
    /// A new, unretired fence.
    #[must_use]
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    /// Retire the session: every later check fails, and a wait in progress ends.
    pub fn retire(&self) {
        self.retired
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Whether the session has been retired.
    #[must_use]
    pub fn is_retired(&self) -> bool {
        self.retired.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Resolves once the session is retired.
    pub async fn retired(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_retired() {
                return;
            }
            notified.await;
        }
    }
}
