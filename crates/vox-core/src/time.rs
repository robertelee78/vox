//! The wall-clock source shared by every component that judges freshness: the
//! node actor (ADR-016), the rendezvous service (ADR-012) and the transport's
//! session records (ADR-011).
//!
//! A [`Clock`] is injected rather than read from `SystemTime` in place, so tests
//! drive time deterministically (record expiry, refresh floors, idle locks) and
//! production uses [`system_clock`].

use std::sync::Arc;

/// A wall-clock source (seconds since the Unix epoch).
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The system clock.
#[must_use]
pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    })
}
