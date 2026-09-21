//! Proof: a hung test process is killed, loudly, instead of running forever.
//!
//! That sentence is the feature — the one that was missing when two gate processes ran for 21
//! hours — so it is what gets measured, by actually hanging a process and watching it die.
//!
//! The hang has to be real, so this re-executes **this same test binary** with
//! `VOX_TEST_WATCHDOG_SELFTEST=1`, which selects a test that spins forever on purpose. The
//! parent then asserts the child died, died by `SIGABRT` (so the OS recorded its stacks), died
//! inside its budget, and said why. A unit test over the timing arithmetic would prove none of
//! that: the thing that can break is whether the process actually ends.

#[path = "support/watchdog.rs"]
mod watchdog;

use std::process::Command;
use std::time::{Duration, Instant};

/// The child's budget. Short, because the point is to wait for it.
const SELFTEST_BUDGET_SECS: u64 = 5;
/// How long the parent will wait before declaring the watchdog itself broken.
const PARENT_PATIENCE: Duration = Duration::from_secs(60);

/// The hang. Selected only by the proof below, via the environment: it spins without yielding,
/// which is the case a `tokio::time::timeout` cannot save, because it starves the timer that
/// would have to fire.
#[test]
#[ignore = "selected by watchdog_kills_a_hung_test; hangs on purpose"]
fn selftest_hangs_forever() {
    if std::env::var("VOX_TEST_WATCHDOG_SELFTEST").is_err() {
        return;
    }
    watchdog::arm();
    // A spin, deliberately: no sleep, no await, no yield.
    let mut n: u64 = 0;
    loop {
        n = n.wrapping_add(1);
        std::hint::black_box(n);
    }
}

#[test]
fn watchdog_kills_a_hung_test() {
    watchdog::arm();
    let me = std::env::current_exe().expect("this test binary's own path");
    let started = Instant::now();
    let mut child = Command::new(&me)
        .args([
            "--exact",
            "selftest_hangs_forever",
            "--ignored",
            "--nocapture",
        ])
        .env("VOX_TEST_WATCHDOG_SELFTEST", "1")
        .env("VOX_TEST_WATCHDOG_SECS", SELFTEST_BUDGET_SECS.to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawned a hanging child");

    // Wait, but never forever: if the watchdog is broken this test must fail, not inherit the
    // hang it exists to prevent.
    let mut outcome = None;
    while started.elapsed() < PARENT_PATIENCE {
        match child.try_wait().expect("polled the child") {
            Some(status) => {
                outcome = Some(status);
                break;
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    let elapsed = started.elapsed();
    let Some(status) = outcome else {
        let _ = child.kill();
        panic!(
            "the watchdog did not kill a deliberately hung test within {PARENT_PATIENCE:?} \
             (budget was {SELFTEST_BUDGET_SECS}s) — the bound is not real"
        );
    };
    let output = child
        .wait_with_output()
        .expect("collected the child's output");
    let said = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        !status.success(),
        "a hung test exited successfully, which is the silent failure this exists to prevent"
    );
    // SIGABRT specifically: it is what makes the OS record every thread's stack, which is the
    // only evidence a hang leaves behind.
    let signal = std::os::unix::process::ExitStatusExt::signal(&status);
    assert_eq!(
        signal,
        Some(libc_sigabrt()),
        "expected SIGABRT so the OS records the stacks; got status {status:?}, stderr: {said}"
    );
    assert!(
        elapsed < PARENT_PATIENCE,
        "the child took {elapsed:?}, beyond the parent's patience"
    );
    assert!(
        elapsed >= Duration::from_secs(SELFTEST_BUDGET_SECS),
        "the child died in {elapsed:?}, before its {SELFTEST_BUDGET_SECS}s budget — \
         that is not the watchdog firing, it is something else killing it"
    );
    // The message is part of the feature: a bound that fires without explaining itself leaves
    // the next person exactly where the 21-hour processes left us.
    for expected in [
        "vox test watchdog",
        "hung, not slow",
        "DiagnosticReports",
        "VOX_TEST_WATCHDOG_SECS=0",
    ] {
        assert!(
            said.contains(expected),
            "the watchdog's message does not mention {expected:?}; it said: {said}"
        );
    }
    println!("watchdog killed a hung test in {elapsed:?} with SIGABRT, and explained why");
}

/// `SIGABRT` is 6 on every platform vox targets; vox-core takes no libc dependency for tests.
fn libc_sigabrt() -> i32 {
    6
}
