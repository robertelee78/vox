//! **A `vox node` stops on Ctrl-C even when the signal lands in the same turn as its tick**,
//! through the shipped binary.
//!
//! The anchor's loop made a new Ctrl-C listener on every turn of its `select!`. A listener sees
//! only signals that arrive after it starts listening, so a SIGINT that became ready in the same
//! turn as the 500 ms status tick went to a listener the tick's win then dropped, and the anchor
//! served on, deaf to Ctrl-C. CI's macOS runner met it as "CANNOT MEASURE: the anchor did not stop
//! within 10 s of SIGINT" in `an_anchor_that_restarts_is_redialled_promptly_proof`.
//!
//! **The scene:** an anchor is started and settles; it is then stopped (SIGSTOP) for longer than
//! one tick, which is what a loaded box does to a process it does not schedule, sent SIGINT, and
//! resumed. On waking the tick and the signal are ready together. Each of [`TRIALS`] anchors must
//! say it is shutting down and exit within [`STOP_WITHIN`].
//!
//! **Which side a red is on.** The wait for each exit is polled every 50 ms, and the proof measures
//! its own poll loop on the same timeline: the longest gap between two polls, and how far the
//! deschedule's sleep overshot. A runner that stalled past [`APPARATUS_BUDGET`] while an anchor was
//! being waited on cannot tell a slow anchor from a slow proof, and says `CANNOT MEASURE:
//! apparatus took X`; otherwise an anchor still running is `PRODUCT: … (apparatus Y)`. A signal
//! that could not be sent is `APPARATUS:`.
//!
//! Mutation: the listener made inside the `select!` again → red (13 of 20 anchors never exited).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::time::{Duration, Instant};

use world::{args, VoxProc};

/// How many anchors are signalled. On the unfixed code 13 of 20 missed the signal, so ten that all
/// stop is not luck.
const TRIALS: usize = 10;
/// Longer than the anchor's 500 ms tick, so a tick is due when it wakes.
const DESCHEDULED: Duration = Duration::from_millis(1200);
/// A clean stop takes well under a second.
const STOP_WITHIN: Duration = Duration::from_secs(10);
/// The most the proof's own clock may stall (the longest gap between two 50 ms polls, or the
/// deschedule's sleep overshooting) before a missed exit is the runner's, not the anchor's.
const APPARATUS_BUDGET: Duration = Duration::from_secs(2);

fn signal(pid: u32, sig: &str) {
    let status = std::process::Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run kill {sig} {pid}: {e}"));
    assert!(
        status.success(),
        "APPARATUS: kill {sig} {pid} did not take ({status})"
    );
}

#[test]
#[ignore = "real binaries; CI runs it in release"]
fn an_anchor_stops_on_ctrl_c_when_a_tick_is_due() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let mut stuck = Vec::new();
    let mut stalled = Vec::new();
    for trial in 0..TRIALS {
        let dir = tmp.path().join(format!("anchor{trial}"));
        std::fs::create_dir_all(dir.join("cfg"))
            .expect("APPARATUS: cannot make the anchor's profile directory");
        let mut anchor =
            VoxProc::spawn("anchor", &dir, &args(&["node", "--listen", "127.0.0.1:0"]));
        anchor.expect_line("the anchors file written", |l| {
            l.starts_with("vox node: wrote ")
        });
        let pid = anchor.child.id();
        signal(pid, "-STOP");
        let slept = Instant::now();
        std::thread::sleep(DESCHEDULED);
        let overshoot = slept.elapsed().saturating_sub(DESCHEDULED);
        signal(pid, "-INT");
        signal(pid, "-CONT");
        let signalled = Instant::now();
        let mut last_poll = signalled;
        let mut widest_gap = Duration::ZERO;
        while anchor.child.try_wait().ok().flatten().is_none() && signalled.elapsed() < STOP_WITHIN
        {
            std::thread::sleep(Duration::from_millis(50));
            widest_gap = widest_gap.max(last_poll.elapsed());
            last_poll = Instant::now();
        }
        let exited = anchor.child.try_wait().ok().flatten().is_some();
        let apparatus = widest_gap.max(overshoot);
        let said = anchor.transcript();
        let shut = said.lines().any(|l| l == "vox node: shutting down");
        eprintln!(
            "[proof] anchor {trial}: exited {exited} after {:?}, said it was shutting down: {shut} \
             (apparatus: widest poll gap {widest_gap:?}, sleep overshoot {overshoot:?})",
            signalled.elapsed()
        );
        if !exited {
            let _ = anchor.child.kill();
            let _ = anchor.child.wait();
            if apparatus > APPARATUS_BUDGET {
                stalled.push(format!("anchor {trial}: apparatus took {apparatus:?}"));
            } else {
                stuck.push(format!("anchor {trial} (apparatus {apparatus:?}):\n{said}"));
            }
        } else {
            assert!(
                shut,
                "PRODUCT: anchor {trial} exited without saying \"vox node: shutting down\":\n{said}"
            );
        }
    }
    eprintln!(
        "[proof] {} of {TRIALS} anchors stopped on Ctrl-C; {} still running; {} not measurable \
         (the proof's clock stalled)",
        TRIALS - stuck.len() - stalled.len(),
        stuck.len(),
        stalled.len()
    );
    assert!(
        stuck.is_empty(),
        "PRODUCT: {} of {TRIALS} anchors were still running {STOP_WITHIN:?} after a SIGINT that \
         landed with a tick:\n{}",
        stuck.len(),
        stuck.join("\n")
    );
    assert!(
        stalled.is_empty(),
        "CANNOT MEASURE: the proof's own clock stalled past {APPARATUS_BUDGET:?} while an anchor \
         was being waited on, so its running on cannot be laid on the anchor: {}",
        stalled.join("; ")
    );
}
