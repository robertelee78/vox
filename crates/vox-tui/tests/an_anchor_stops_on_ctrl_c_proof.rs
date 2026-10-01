//! **A `vox node` stops on Ctrl-C even when the signal lands in the same turn as its tick**,
//! through the shipped binary.
//!
//! The anchor's loop made a new Ctrl-C listener on every turn of its `select!`. A listener sees
//! only signals that arrive after it starts listening, so a SIGINT that became ready in the same
//! turn as the 500 ms status tick went to a listener the tick's win then dropped, and the anchor
//! served on, deaf to Ctrl-C. CI's macOS runner met it as "CANNOT MEASURE: the anchor did not stop
//! within 10 s of SIGINT" in `an_anchor_that_restarts_is_redialled_promptly_proof`.
//!
//! **And on every stop signal, not only Ctrl-C** (V210-85, #277): SIGTERM (a service manager,
//! `kill`), SIGHUP (its terminal closed, its ssh session gone) and SIGQUIT (`Ctrl-\`) stop it the
//! same way. Left to their defaults they killed it on the spot — SIGQUIT with a core dump — its
//! closes unsent.
//!
//! **The scene:** an anchor is started and settles; it is then stopped (SIGSTOP) for longer than
//! one tick, which is what a loaded box does to a process it does not schedule, sent a stop signal,
//! and resumed. On waking the tick and the signal are ready together. The [`TRIALS`] anchors take
//! SIGINT, SIGTERM, SIGHUP and SIGQUIT in turn. Each must exit within [`STOP_WITHIN`] with status 0,
//! not by the signal, and say which signal stopped it and that it is shutting down.
//!
//! **A red names its side.** An anchor that never wrote its anchors file, or a `kill` that failed,
//! is CANNOT MEASURE (the scene was not staged). Anything after the signal is the product's: it
//! did not exit, died by the signal, or exited without saying why.
//!
//! Mutations: the listener made inside the `select!` again → red (13 of 20 anchors never exited);
//! SIGHUP or SIGQUIT not taken → those trials die by the signal → red.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::os::unix::process::ExitStatusExt;
use std::time::{Duration, Instant};

use world::{args, VoxProc};

/// How many anchors are signalled. On the unfixed code 13 of 20 missed the signal, so ten that all
/// stop is not luck.
const TRIALS: usize = 10;
/// The stop signals, taken in turn, with the name `vox node` gives each.
const SIGNALS: [(&str, &str); 4] = [
    ("-INT", "SIGINT"),
    ("-TERM", "SIGTERM"),
    ("-HUP", "SIGHUP"),
    ("-QUIT", "SIGQUIT"),
];
/// Longer than the anchor's 500 ms tick, so a tick is due when it wakes.
const DESCHEDULED: Duration = Duration::from_millis(1200);
/// A clean stop takes well under a second.
const STOP_WITHIN: Duration = Duration::from_secs(10);
/// How long an anchor may take to start and write its anchors file.
const LINE_PATIENCE: Duration = Duration::from_secs(60);

fn signal(pid: u32, sig: &str) {
    let sent = std::process::Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(sent, "CANNOT MEASURE: `kill {sig} {pid}` failed");
}

#[test]
#[ignore = "real binaries; CI runs it in release"]
fn an_anchor_stops_on_ctrl_c_when_a_tick_is_due() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let mut stuck = Vec::new();
    for trial in 0..TRIALS {
        let (sig, name) = SIGNALS[trial % SIGNALS.len()];
        let dir = tmp.path().join(format!("anchor{trial}"));
        std::fs::create_dir_all(dir.join("cfg")).unwrap();
        let mut anchor =
            VoxProc::spawn("anchor", &dir, &args(&["node", "--listen", "127.0.0.1:0"]));
        if let Err(why) = anchor.try_expect_within(LINE_PATIENCE, "the anchors file written", |l| {
            l.starts_with("vox node: wrote ")
        }) {
            panic!("CANNOT MEASURE: anchor {trial} never settled: {why}");
        }
        let pid = anchor.child.id();
        signal(pid, "-STOP");
        std::thread::sleep(DESCHEDULED);
        signal(pid, sig);
        signal(pid, "-CONT");
        let signalled = Instant::now();
        while anchor.child.try_wait().ok().flatten().is_none() && signalled.elapsed() < STOP_WITHIN
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        let status = anchor.child.try_wait().ok().flatten();
        let said = anchor.transcript();
        let shut = said.lines().any(|l| l == "vox node: shutting down");
        let named = said
            .lines()
            .any(|l| l == format!("vox node: stopped by {name}"));
        eprintln!(
            "[proof] anchor {trial}, {name}: exited {status:?} after {:?}, said it was stopped by \
             {name}: {named}, shutting down: {shut}",
            signalled.elapsed()
        );
        let Some(status) = status else {
            let _ = anchor.child.kill();
            let _ = anchor.child.wait();
            stuck.push(format!("anchor {trial} ({name}):\n{said}"));
            continue;
        };
        assert_eq!(
            status.signal(),
            None,
            "anchor {trial}: `vox node` died by {name} instead of stopping:\n{said}"
        );
        assert_eq!(
            status.code(),
            Some(0),
            "anchor {trial}: `vox node` stopped by {name} ended with {status}:\n{said}"
        );
        assert!(
            named && shut,
            "anchor {trial} exited on {name} without saying it was stopped by {name} and is \
             shutting down:\n{said}"
        );
    }
    eprintln!(
        "[proof] {} of {TRIALS} anchors stopped (SIGINT, SIGTERM, SIGHUP and SIGQUIT in turn)",
        TRIALS - stuck.len()
    );
    assert!(
        stuck.is_empty(),
        "{} of {TRIALS} anchors did not stop within {STOP_WITHIN:?} of a stop signal that landed \
         with a tick:\n{}",
        stuck.len(),
        stuck.join("\n")
    );
}
