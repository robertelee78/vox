//! V29-05 / #40 (relayed case), driven through the shipped binary — **a host whose only path to
//! its guest is a relay circuit is reachable again promptly after it crashes and comes back**, not
//! after `SILENCE_IS_DEATH` (30s).
//!
//! **Before #40 it was red on every trial**: measured on `bdabf39`, the first echo through the
//! guest's forward arrived ≈29.5s after the crash in 10/10 trials, with near-identical durations —
//! a fixed window. The restarted host did not reach the guest back through the anchor any sooner,
//! so the guest kept its dead connection to the crashed process until that connection had been
//! silent for 30s. It is the acceptance test for the restart liveness probe (#40): a restarted
//! relayed host is reached within [`REACHED_AGAIN_WITHIN`].
//!
//! **It is also V29-15's (#50) gate**, now that #40 makes the restarted host dial back promptly:
//! the host's new process reaches the guest over a **second** circuit, which detaches the first,
//! and the guest's connection to the crashed process is left relayed over a circuit it no longer
//! has. The guest must not take that severed connection for a direct path: kept, it beats the live
//! newcomer on "better path", the guest's requests go into it, and nothing is reached until
//! `SILENCE_IS_DEATH`. Measured on integrate/v0.2.10 39c3884 with `path_class` reverted to asking
//! the mux table alone (the pre-V29-15 rule): 5/5 restarts reached again only after 25.7–32.1s,
//! red on [`REACHED_AGAIN_WITHIN`], in both of two runs; with the fix, 0.8–1.3s in each of three.
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
//! **The apparatus's own time is measured on the same timeline**, so a slow runner is never read
//! as a slow product: while it waits, the proof records how far each of its 200 ms sleeps
//! overshot, and once the echo is back it times `/usr/bin/true`, a process that is not vox (a vox
//! slow even only to start reads as the product's). A trial over the bound
//! whose apparatus took more than [`APPARATUS_BUDGET`] says `APPARATUS (runner stalled): apparatus took X`;
//! otherwise an over-bound trial is `PRODUCT: took X (apparatus Y)`.
//!
//! `#[ignore]`d: production Argon2id and a real PoW per trial. Run it in release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::time::{Duration, Instant};

use relay::{RelayWorld, Split};
use world::{round_trip, VoxProc};

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

/// The most the apparatus may take on a trial's timeline — its sleeps' overshoot plus a no-op
/// `vox` — before a trial over the bound is the runner's, not the product's.
const APPARATUS_BUDGET: Duration = Duration::from_secs(2);

/// The apparatus clock: how long this machine takes, now, to start a process that is **not**
/// vox (`/usr/bin/true`), spawned as vox is. A stalled runner stalls this too; a vox that is slow,
/// even only to start, does not, so it reads as the product's (the #332 trap).
fn apparatus_spawn() -> Duration {
    let t = Instant::now();
    let ok = std::process::Command::new("/usr/bin/true")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("APPARATUS: spawn /usr/bin/true for the apparatus clock: {e}"))
        .success();
    assert!(
        ok,
        "APPARATUS: /usr/bin/true failed, so the apparatus clock cannot be read"
    );
    t.elapsed()
}

/// The restarted daemon holding its room, to the first echo; and what the apparatus took on that
/// timeline.
fn trial(n: usize) -> (Duration, Duration) {
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    eprintln!("[join] trial {n}: joined = {ok} in {took:.1?}");
    if !ok {
        // #182: a join that found the anchor's board without the room. What the host said about
        // its publish rounds, and what the anchor's board held, name the cause.
        let host = w.host.as_mut().map(VoxProc::transcript).unwrap_or_default();
        let anchor = w.anchor.proc.transcript();
        panic!(
            "PRODUCT (staging, trial {n}): the guest could not join over the relay ({took:?}).\n{out}\n\
             {err}\n--- host:\n{host}\n--- anchor:\n{anchor}"
        );
    }
    let at = w.forward();
    let before =
        round_trip(at, b"before the crash", Duration::from_secs(120)).unwrap_or_else(|e| {
            panic!(
                "PRODUCT (staging, trial {n}): no echo before the crash ({e}).\n{}",
                w.fwd
                    .as_mut()
                    .expect("APPARATUS: a process the proof started")
                    .transcript()
            )
        });
    assert_eq!(
        before, b"before the crash",
        "PRODUCT (trial {n}): the forward returned other bytes than were sent"
    );
    w.expect_still_relayed();
    w.assert_relayed("before the crash");

    let (crashed, ready) = w.crash_and_restart_host();
    let mut attempts = 0;
    let mut overshoot = Duration::ZERO;
    loop {
        attempts += 1;
        if let Ok(back) = round_trip(at, b"after the crash", ATTEMPT) {
            assert_eq!(
                back, b"after the crash",
                "PRODUCT (trial {n}): the forward returned other bytes than were sent"
            );
            break;
        }
        assert!(
            crashed.elapsed() < GIVE_UP,
            "PRODUCT (trial {n}): the forward never reached the restarted host ({attempts} \
             attempts in {:?}).\nforward:\n{}",
            crashed.elapsed(),
            w.fwd
                .as_mut()
                .expect("APPARATUS: a process the proof started")
                .transcript()
        );
        let slept = Instant::now();
        std::thread::sleep(Duration::from_millis(200));
        overshoot = overshoot.max(slept.elapsed().saturating_sub(Duration::from_millis(200)));
    }
    let (from_crash, from_ready) = (crashed.elapsed(), ready.elapsed());
    let apparatus = overshoot + apparatus_spawn();
    w.assert_relayed("after the restarted host was reached");
    eprintln!(
        "[test] trial {n}: reached again {:.1}s after the crash, {:.1}s after the daemon held the \
         room ({attempts} attempts; apparatus {:?})",
        from_crash.as_secs_f64(),
        from_ready.as_secs_f64(),
        apparatus
    );
    (from_ready, apparatus)
}

#[test]
#[ignore = "5 relayed host crashes on the shipped binary with production Argon2id; run in release"]
fn a_relayed_host_that_restarts_is_reached_again_through_the_same_forward() {
    watchdog::arm();
    let trials: Vec<(Duration, Duration)> = (0..RESTARTS).map(trial).collect();
    let over: Vec<&(Duration, Duration)> = trials
        .iter()
        .filter(|(took, _)| *took > REACHED_AGAIN_WITHIN)
        .collect();
    let said = |t: &[&(Duration, Duration)]| {
        t.iter()
            .map(|(took, app)| format!("took {:.1}s (apparatus {:?})", took.as_secs_f64(), app))
            .collect::<Vec<_>>()
            .join(", ")
    };
    eprintln!(
        "[test] {RESTARTS} restarts, daemon-ready to first echo: {}; {} over the {:?} bound",
        said(&trials.iter().collect::<Vec<_>>()),
        over.len(),
        REACHED_AGAIN_WITHIN
    );
    let stalled: Vec<&(Duration, Duration)> = over
        .iter()
        .copied()
        .filter(|(_, app)| *app > APPARATUS_BUDGET)
        .collect();
    assert!(
        stalled.is_empty(),
        "APPARATUS (runner stalled): apparatus took over {APPARATUS_BUDGET:?} on {} trial(s) over the bound: {}",
        stalled.len(),
        said(&stalled)
    );
    assert!(
        over.is_empty(),
        "PRODUCT: {}/{RESTARTS} restarts were reached again through the relay only after more \
         than {REACHED_AGAIN_WITHIN:?}: {}",
        over.len(),
        said(&over)
    );
}
