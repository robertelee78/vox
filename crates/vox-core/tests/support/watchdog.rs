//! A wall-clock bound on the whole gate process.
//!
//! ## Why this exists
//! On 2026-09-20 two `node_m15_anchor_gate` processes were found still running **21 hours**
//! after they started, each burning about 1.5 cores. They were left behind by a debugging
//! session: the gate hung, the run was abandoned, the defect was fixed, and nothing ever
//! reaped the processes. Nobody noticed, because **a hung test is silent** — it produces no
//! failure, no output and no exit status, so no gate can catch it. It looks exactly like a test
//! that is still running.
//!
//! ## Why `tokio::time::timeout` is not enough
//! The gates already wrap every wait in `tokio::time::timeout`. That bounds **one await inside
//! a working runtime**, and nothing else. It cannot bound:
//!
//! - a task spinning without yielding, which starves the timer it would have to fire on;
//! - a blocking call on a runtime thread;
//! - anything after `block_on` returns — a leaked task, a stuck `Drop`, a non-exiting runtime;
//! - the process itself, once libtest thinks the test is over.
//!
//! Each of those looks identical from outside: a process that never ends. So the bound has to
//! be outside the runtime, on the clock, and it has to end the **process**.
//!
//! ## Why `abort` rather than `exit`
//! `std::process::abort` raises `SIGABRT`, which makes the OS write a crash report naming every
//! thread and its stack — on macOS into `~/Library/Logs/DiagnosticReports`. A hang's whole
//! difficulty is that there is nothing to look at; this leaves something to look at. A clean
//! `exit` would discard exactly the evidence the next person needs.
//!
//! The budget is deliberately generous: it is not a performance assertion, it is the line past
//! which "slow" is no longer a credible explanation. Override with `VOX_TEST_WATCHDOG_SECS`,
//! and `VOX_TEST_WATCHDOG_SECS=0` disables it — for attaching a debugger, which is the one
//! case where an unbounded hang is what you want.

use std::sync::Once;
use std::time::{Duration, Instant};

/// Past this, a gate is hung rather than slow. The longest gate observed is ~53 s.
const DEFAULT_BUDGET: Duration = Duration::from_secs(600);

static ARMED: Once = Once::new();

/// Bound this test process's total wall-clock time. Idempotent, so every test in a binary may
/// call it; the budget covers the binary, not one test, because libtest runs tests in parallel
/// threads of one process and a per-test bound would abort a healthy neighbour.
pub fn arm() {
    ARMED.call_once(|| {
        let budget = match std::env::var("VOX_TEST_WATCHDOG_SECS") {
            Ok(v) => match v.parse::<u64>() {
                Ok(0) => return,
                Ok(secs) => Duration::from_secs(secs),
                Err(_) => DEFAULT_BUDGET,
            },
            Err(_) => DEFAULT_BUDGET,
        };
        let started = Instant::now();
        std::thread::Builder::new()
            .name("vox-test-watchdog".to_owned())
            .spawn(move || {
                std::thread::sleep(budget);
                eprintln!(
                    "\n\
                     ==================== vox test watchdog ====================\n\
                     This test process has been running for {:?} and is being aborted.\n\
                     \n\
                     It is hung, not slow: the budget is {:?}. A `tokio::time::timeout` did\n\
                     not save it, which means the runtime is not making progress — a task\n\
                     spinning without yielding, a blocking call on a runtime thread, or a\n\
                     leaked task after `block_on` returned.\n\
                     \n\
                     SIGABRT follows so the OS records every thread's stack. On macOS look in\n\
                     ~/Library/Logs/DiagnosticReports for the newest report naming this\n\
                     binary; the spinning thread is the one with a stack that makes no sense\n\
                     for a test that should have finished.\n\
                     \n\
                     To hold it open for a debugger instead: VOX_TEST_WATCHDOG_SECS=0\n\
                     ===========================================================\n",
                    started.elapsed(),
                    budget,
                );
                std::process::abort();
            })
            .ok();
    });
}
