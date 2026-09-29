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

fn signal(pid: u32, sig: &str) {
    let status = std::process::Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .expect("kill");
    assert!(status.success(), "kill {sig} {pid} failed");
}

#[test]
#[ignore = "real binaries; CI runs it in release"]
fn an_anchor_stops_on_ctrl_c_when_a_tick_is_due() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let mut stuck = Vec::new();
    for trial in 0..TRIALS {
        let dir = tmp.path().join(format!("anchor{trial}"));
        std::fs::create_dir_all(dir.join("cfg")).unwrap();
        let mut anchor =
            VoxProc::spawn("anchor", &dir, &args(&["node", "--listen", "127.0.0.1:0"]));
        anchor.expect_line("the anchors file written", |l| {
            l.starts_with("vox node: wrote ")
        });
        let pid = anchor.child.id();
        signal(pid, "-STOP");
        std::thread::sleep(DESCHEDULED);
        signal(pid, "-INT");
        signal(pid, "-CONT");
        let signalled = Instant::now();
        while anchor.child.try_wait().ok().flatten().is_none() && signalled.elapsed() < STOP_WITHIN
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        let exited = anchor.child.try_wait().ok().flatten().is_some();
        let said = anchor.transcript();
        let shut = said.lines().any(|l| l == "vox node: shutting down");
        eprintln!(
            "[proof] anchor {trial}: exited {exited} after {:?}, said it was shutting down: {shut}",
            signalled.elapsed()
        );
        if !exited {
            let _ = anchor.child.kill();
            let _ = anchor.child.wait();
            stuck.push(format!("anchor {trial}:\n{said}"));
        } else {
            assert!(
                shut,
                "anchor {trial} exited without saying it was shutting down:\n{said}"
            );
        }
    }
    eprintln!(
        "[proof] {} of {TRIALS} anchors stopped on Ctrl-C",
        TRIALS - stuck.len()
    );
    assert!(
        stuck.is_empty(),
        "{} of {TRIALS} anchors did not stop within {STOP_WITHIN:?} of a SIGINT that landed with a \
         tick:\n{}",
        stuck.len(),
        stuck.join("\n")
    );
}
