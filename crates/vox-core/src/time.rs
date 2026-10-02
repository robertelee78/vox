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

/// [`system_clock`], shifted by `VOX_TEST_CLOCK_SKEW_MS` in whole seconds (rounded down).
/// **Test-only: for proofs; nothing in a real deployment sets it**, and without the `test-knobs`
/// feature (V210-105) it is the system clock.
///
/// **Both clocks move** (V210-64): a real clock step moves the seconds a record is stamped with as
/// well as the milliseconds that floor its `seq`, and a board refuses a record that is behind on
/// either. Moving only the milliseconds proved half the cure.
#[must_use]
pub fn clock_with_test_skew() -> Clock {
    let skew = test_skew_ms();
    let system = system_clock();
    if skew == 0 {
        return system;
    }
    let secs = skew.div_euclid(1000);
    Arc::new(move || system().saturating_add_signed(secs))
}

/// The signed skew [`TEST_CLOCK_SKEW_ENV`] names, in milliseconds; zero when unset or unparsable.
#[cfg(feature = "test-knobs")]
fn test_skew_ms() -> i64 {
    std::env::var(TEST_CLOCK_SKEW_ENV)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

/// No skew: the knob is not compiled in (V210-105).
#[cfg(not(feature = "test-knobs"))]
const fn test_skew_ms() -> i64 {
    0
}

/// The environment variable [`millis_clock_with_test_skew`] reads. **Test-only.**
#[cfg(feature = "test-knobs")]
pub const TEST_CLOCK_SKEW_ENV: &str = "VOX_TEST_CLOCK_SKEW_MS";

/// [`system_millis_clock`], shifted by a signed number of milliseconds read once from
/// `VOX_TEST_CLOCK_SKEW_MS`. **Test-only: for proofs; nothing in a real deployment sets it**, and
/// without the `test-knobs` feature (V210-105) it is the system clock.
///
/// It lets a proof drive the shipped binary with a node whose millisecond clock is wrong, which
/// a proof that pinned the clock inside the process could not: that would not be the binary a
/// person runs. The node's seconds [`Clock`] moves with it ([`clock_with_test_skew`], V210-64), as
/// both do in a real clock step. Ported from the v0.3.0 line (c065a37) for #230's proof, which starts a node a moment
/// behind so its first record is refused as stale, deterministically.
///
/// Unset, empty or unparsable is no skew: an operator who never heard of it gets the system clock.
#[must_use]
pub fn millis_clock_with_test_skew() -> MillisClock {
    let skew = test_skew_ms();
    let system = system_millis_clock();
    if skew == 0 {
        return system;
    }
    Arc::new(move || system().saturating_add_signed(skew))
}
