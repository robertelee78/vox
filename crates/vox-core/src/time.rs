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

/// A wall-clock source in **milliseconds** since the Unix epoch.
///
/// Deliberately a second seam rather than a change to [`Clock`]. Ten call sites feed `Clock`
/// straight into ADR-012 record TTLs, ADR-011 session records and connection retirement grace, all
/// specified in seconds; repurposing it would make every one of them silently wrong by a factor of
/// a thousand — no compiler error, records expiring a thousand times too early or too late.
///
/// Injected for the same reason `Clock` is: so a test can pin it.
pub type MillisClock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The system clock in milliseconds, from a **single** read.
///
/// # Why one read matters
/// The first version of this composed the value from two reads — whole seconds from the injected
/// [`Clock`] and the sub-second part from a fresh `SystemTime::now()`. That is not monotonic. If the
/// second rolls over between the two reads, the seconds come from before the boundary and the
/// milliseconds from after it:
///
/// ```text
/// seconds read at 1000.998 -> 1000      milliseconds read at 1001.003 -> 003
/// composed: 1_000_003, which is 955ms BEHIND a value composed 5ms earlier
/// ```
///
/// An ordering key that can go backwards reintroduces the inversion this whole change exists to
/// remove, and it needs a boundary crossing between two reads — so it would appear once in a few
/// thousand operations and be unattributable, which is worse than a frequent bug, not better. One
/// read of one clock cannot disagree with itself.
#[must_use]
pub fn system_millis_clock() -> MillisClock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    })
}
