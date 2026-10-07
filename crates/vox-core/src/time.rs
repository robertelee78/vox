//! The wall-clock source shared by every component that judges freshness: the
//! node actor (ADR-016), the rendezvous service (ADR-012) and the transport's
//! session records (ADR-011).
//!
//! A [`Clock`] is injected rather than read from `SystemTime` in place, so tests
//! drive time deterministically (record expiry, refresh floors, idle locks) and
//! production uses [`system_clock`].

use std::sync::Arc;

/// A wall-clock source, **milliseconds** since the Unix epoch (the decider, 2026-10-07: every time
/// Vox stores, sends, compares, orders or expires is in milliseconds; it is rounded only when shown
/// to a person). A format that is specified in seconds (OpenPGP's key creation time) converts at
/// that boundary, with [`Ms::secs`].
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// A wall-clock instant, milliseconds since the Unix epoch: what the node's APIs take, so a value
/// in seconds cannot be passed for one in milliseconds without the compiler seeing it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ms(pub u64);

impl Ms {
    /// Whole seconds, rounded down: for a format specified in seconds, never to compare.
    #[must_use]
    pub fn secs(self) -> u64 {
        self.0 / 1_000
    }

    /// The milliseconds.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

/// The system clock, in milliseconds, from a single read.
#[must_use]
pub fn system_clock() -> Clock {
    system_millis_clock()
}

/// The node's second clock, also in milliseconds: the one a message's claimed time is read from,
/// which [`TEST_CLOCK_SKEW_ENV`] moves while [`Clock`] stays (a skewed author, not a skewed node).
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

/// [`system_clock`], shifted by [`TEST_CLOCK_STEP_ENV`] milliseconds.
/// **Test-only: for proofs; nothing in a real deployment sets it**, and without the `test-knobs`
/// feature (V210-105) it is the system clock.
///
/// **A clock step moves both clocks** (V210-64): this one, which stamps records, as well as the
/// one that floors a record's `seq`; a board refuses a record that is behind on either. It has
/// its own knob, apart from [`TEST_CLOCK_SKEW_ENV`], because the proofs that skew a message's
/// claimed time by an hour or by ten years must not move this clock: that would make the node
/// unreachable, which is a different test.
#[must_use]
pub fn clock_with_test_skew() -> Clock {
    let step = env_ms(TEST_CLOCK_STEP_ENV);
    let system = system_clock();
    if step == 0 {
        return system;
    }
    Arc::new(move || system().saturating_add_signed(step))
}

/// The signed milliseconds `var` names; zero when unset or unparsable.
#[cfg(feature = "test-knobs")]
fn env_ms(var: &str) -> i64 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

/// No skew and no step: the knobs are not compiled in (V210-105).
#[cfg(not(feature = "test-knobs"))]
const fn env_ms(_var: &str) -> i64 {
    0
}

/// The environment variable that moves only the millisecond clock ([`millis_clock_with_test_skew`]).
/// **Test-only.**
pub const TEST_CLOCK_SKEW_ENV: &str = "VOX_TEST_CLOCK_SKEW_MS";

/// The environment variable for a whole **clock step**: both clocks move ([`clock_with_test_skew`],
/// [`millis_clock_with_test_skew`]). **Test-only.**
pub const TEST_CLOCK_STEP_ENV: &str = "VOX_TEST_CLOCK_STEP_MS";

/// [`system_millis_clock`], shifted by a signed number of milliseconds read once from
/// [`TEST_CLOCK_SKEW_ENV`] and [`TEST_CLOCK_STEP_ENV`] together. **Test-only: for proofs; nothing
/// in a real deployment sets them**, and without the `test-knobs` feature (V210-105) it is the
/// system clock.
///
/// It lets a proof drive the shipped binary with a node whose millisecond clock is wrong, which
/// a proof that pinned the clock inside the process could not: that would not be the binary a
/// person runs. ADR-023 proof 2 posts a reply from a node an hour behind and asserts the reply is
/// still ordered after what it answered (the skew alone: the seconds clock stays); #230's proof
/// starts a node a moment behind on both clocks (a step, V210-64) so its first board record is
/// refused as stale, deterministically.
///
/// Unset, empty or unparsable is no skew: an operator who never heard of it gets the system clock.
#[must_use]
pub fn millis_clock_with_test_skew() -> MillisClock {
    let skew = env_ms(TEST_CLOCK_SKEW_ENV).saturating_add(env_ms(TEST_CLOCK_STEP_ENV));
    let system = system_millis_clock();
    if skew == 0 {
        return system;
    }
    Arc::new(move || system().saturating_add_signed(skew))
}
