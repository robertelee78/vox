//! V29-05 / #40 (relayed case), driven through the shipped binary — **a host whose only path to
//! its guest is a relay circuit is reachable again promptly after it crashes and comes back**, not
//! after `SILENCE_IS_DEATH` (30s).
//!
//! **This gate is red today, on purpose, and that red is its baseline.** Measured on `bdabf39`: the
//! first echo through the guest's forward arrives ≈29.5s after the crash in 10/10 trials, with
//! near-identical durations — a fixed window. The restarted host does not reach the guest back
//! through the anchor any sooner, so the guest keeps its dead connection to the crashed process
//! until that connection has been silent for 30s. It is the acceptance test for the restart
//! liveness probe (#40); it turns green when a restarted relayed host is reached within
//! [`REACHED_AGAIN_WITHIN`].
//!
//! It also cannot tell V29-15's fix (#50) from its bug yet: that defect only shows once a second
//! circuit forms, and on this path none does within the 30s. Once #40 makes the host dial back
//! promptly, re-run it with V29-15's `path_class` reverted.
//!
//! **How a relay is forced without a switch in the product:** `support/relay.rs` splits host and
//! guest by address family with their own `--listen`, so the anchor's circuit is the only path
//! (its control, without the split, goes direct). The relay is asserted before the crash — the
//! guest says `still relayed`, and the anchor reports a circuit carried — and again once the
//! restarted host has been reached, so a direct path can never pass this silently.
//!
//! Each of [`RESTARTS`] trials builds a fresh world, carries an echo through the forward, crashes
//! the host (`SIGKILL` by PID — its QUIC close never leaves), brings the same identity and room
//! back as `vox daemon` on the same family, and times the first echo through the **same** forward.
//! The bound is asserted on every trial and the times are printed.
//!
//! `#[ignore]`d: production Argon2id and a real PoW per trial. Run it in release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::time::Duration;

use relay::{RelayWorld, Split};
use world::round_trip;

/// Trials; each is a fresh anchor, host and guest.
const RESTARTS: usize = 5;

/// From the restarted daemon holding its room to the first echo through the guest's forward.
/// Under the old rule the guest kept the dead connection until it had been silent for
/// `SILENCE_IS_DEATH` (30s) and only then used the new one, so the bound sits well below that.
const REACHED_AGAIN_WITHIN: Duration = Duration::from_secs(10);

/// How long one attempt through the forward may wait before the next is made.
const ATTEMPT: Duration = Duration::from_secs(3);

/// Give up on a trial after this: long past the silence rule, so a trial that never recovers is
/// reported as such and not as a hang.
const GIVE_UP: Duration = Duration::from_secs(90);

/// The restarted daemon holding its room, to the first echo.
fn trial(n: usize) -> Duration {
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "CANNOT PROVE (trial {n}): the guest could not join over the relay ({took:?}).\n{out}\n{err}"
    );
    let at = w.forward();
    let before =
        round_trip(at, b"before the crash", Duration::from_secs(120)).unwrap_or_else(|e| {
            panic!(
                "CANNOT PROVE (trial {n}): no echo before the crash ({e}).\n{}",
                w.fwd.as_mut().unwrap().transcript()
            )
        });
    assert_eq!(before, b"before the crash");
    w.expect_still_relayed();
    w.assert_relayed("before the crash");

    let (crashed, ready) = w.crash_and_restart_host();
    let mut attempts = 0;
    loop {
        attempts += 1;
        if let Ok(back) = round_trip(at, b"after the crash", ATTEMPT) {
            assert_eq!(back, b"after the crash");
            break;
        }
        assert!(
            crashed.elapsed() < GIVE_UP,
            "trial {n}: the forward never reached the restarted host ({attempts} attempts in \
             {:?}).\nforward:\n{}",
            crashed.elapsed(),
            w.fwd.as_mut().unwrap().transcript()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let (from_crash, from_ready) = (crashed.elapsed(), ready.elapsed());
    w.assert_relayed("after the restarted host was reached");
    eprintln!(
        "[test] trial {n}: reached again {:.1}s after the crash, {:.1}s after the daemon held the \
         room ({attempts} attempts)",
        from_crash.as_secs_f64(),
        from_ready.as_secs_f64()
    );
    from_ready
}

#[test]
#[ignore = "5 relayed host crashes on the shipped binary with production Argon2id; run in release"]
fn a_relayed_host_that_restarts_is_reached_again_through_the_same_forward() {
    watchdog::arm();
    let from_ready: Vec<Duration> = (0..RESTARTS).map(trial).collect();
    let over: Vec<String> = from_ready
        .iter()
        .filter(|d| **d > REACHED_AGAIN_WITHIN)
        .map(|d| format!("{:.1}s", d.as_secs_f64()))
        .collect();
    eprintln!(
        "[test] {RESTARTS} restarts, daemon-ready to first echo: {}; {} over the {:?} bound",
        from_ready
            .iter()
            .map(|d| format!("{:.1}s", d.as_secs_f64()))
            .collect::<Vec<_>>()
            .join(", "),
        over.len(),
        REACHED_AGAIN_WITHIN
    );
    assert!(
        over.is_empty(),
        "{}/{RESTARTS} restarts took longer than {REACHED_AGAIN_WITHIN:?} to be reached again \
         through the relay: {}",
        over.len(),
        over.join(", ")
    );
}
