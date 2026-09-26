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
//! ## Why it prints the stacks itself, and writes past libtest
//! The first version said why it was aborting with `eprintln!` and left the stacks to the OS's
//! crash report. On CI that produced **nothing at all**, twice (R41 on macOS, 2026-09-25): the
//! log shows only `signal: 6, SIGABRT`. Two separate losses:
//!
//! - libtest captures a test's output, and a thread spawned from a capturing test thread
//!   **inherits the capture**. The watchdog is spawned from inside the first test that arms it,
//!   so its `eprintln!` went into that test's buffer — which libtest prints only when the test
//!   finishes, and an aborted process finishes nothing. Its own proof never saw this because it
//!   ran the hung child with `--nocapture`. So the message is written to file descriptor 2
//!   directly, which no capture intercepts.
//! - A crash report lands in `~/Library/Logs/DiagnosticReports` **on the runner**, which is
//!   discarded with it, and Linux writes none. So before aborting, the watchdog puts every
//!   thread's stack into the log itself: `/usr/bin/sample` on macOS (a few hundred samples per
//!   thread, so a spinning frame stands out by its count, not a single snapshot); on Linux, a
//!   census of every thread from `/proc` with its state and the CPU it burned in the last second
//!   (a spinning thread is the `R` one with ~100 ticks), plus `gdb`'s backtraces where it is
//!   installed and allowed to attach.
//!
//! It also names the tests still running: every test arms the watchdog, and each arming is
//! struck off when that test's thread ends, so what is left is the test that hung.
//!
//! ## Why `abort` rather than `exit`
//! `std::process::abort` raises `SIGABRT`, which makes the OS write a crash report naming every
//! thread and its stack — on macOS into `~/Library/Logs/DiagnosticReports`. On a developer's
//! machine that is a second copy of the evidence; a clean `exit` would discard it.
//!
//! ## Why it kills the test's children first
//! `abort` runs no destructors, so every `vox node` and `vox daemon` a gate had started — each
//! normally killed by its handle's `Drop` — kept running, reparented to init, after the gate
//! was aborted. Aborted runs on 2026-09-26 left three at a time behind (V210-28), and a leak
//! like that is how the 21-hour processes above began. So before it aborts, the watchdog
//! kills every descendant of this process, found by parent pid, deepest first.
//!
//! ## Why it dumps the test's children too, before it kills them
//! Every real-binary proof spends its time waiting on `vox` child processes, so the test
//! process's own stacks show only that it is waiting: the process that is actually stuck is a
//! `vox daemon` it started. The first version sampled the test process alone and then killed the
//! children, so the one dump a hang produced held no evidence of the cause (V210-36, #213). So
//! each live descendant is dumped the same way, named by pid and command line, **before** any is
//! killed — a dead process has no stacks to show. The descendants' dumps share one bound,
//! [`DESCENDANTS_PATIENCE`], so a tree of many processes cannot undo the watchdog's own bound.
//!
//! The budget is deliberately generous: it is not a performance assertion, it is the line past
//! which "slow" is no longer a credible explanation. Override with `VOX_TEST_WATCHDOG_SECS`,
//! and `VOX_TEST_WATCHDOG_SECS=0` disables it — for attaching a debugger, which is the one
//! case where an unbounded hang is what you want.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant};

/// Past this, a gate is hung rather than slow. The longest gate observed is ~53 s.
const DEFAULT_BUDGET: Duration = Duration::from_secs(600);

/// How long the stack dump may take before the abort goes ahead without it. Symbolicating a
/// large test binary is the slow part; a dump that itself hangs must not undo the bound.
const DUMP_PATIENCE: Duration = Duration::from_secs(90);

/// How long the descendants' dumps may take between them. Past it the rest are named but not
/// dumped, and the kill goes ahead.
const DESCENDANTS_PATIENCE: Duration = Duration::from_secs(180);

static ARMED: Once = Once::new();

/// The tests that armed the watchdog and have not finished, by libtest's thread name — which is
/// the test's name.
static RUNNING: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Struck off [`RUNNING`] when the test's thread ends, which is when libtest is done with it.
struct Running(String);

impl Drop for Running {
    fn drop(&mut self) {
        if let Ok(mut running) = RUNNING.lock() {
            if let Some(i) = running.iter().position(|n| *n == self.0) {
                running.remove(i);
            }
        }
    }
}

thread_local! {
    static THIS_TEST: std::cell::RefCell<Option<Running>> = const { std::cell::RefCell::new(None) };
}

/// Bound this test process's total wall-clock time. Idempotent, so every test in a binary may
/// call it; the budget covers the binary, not one test, because libtest runs tests in parallel
/// threads of one process and a per-test bound would abort a healthy neighbour.
pub fn arm() {
    let name = std::thread::current()
        .name()
        .unwrap_or("<unnamed thread>")
        .to_owned();
    THIS_TEST.with(|t| {
        let mut t = t.borrow_mut();
        if t.is_none() {
            if let Ok(mut running) = RUNNING.lock() {
                running.push(name.clone());
            }
            *t = Some(Running(name));
        }
    });
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
                fire(started.elapsed(), budget);
            })
            .ok();
    });
}

/// Every descendant of this process, parents before children. Found with `ps`, which macOS and
/// Linux both have, so the support code needs no platform crate.
fn descendants() -> Vec<u32> {
    let Ok(out) = std::process::Command::new("ps")
        .args(["-A", "-o", "pid=,ppid="])
        .output()
    else {
        return Vec::new();
    };
    let pairs: Vec<(u32, u32)> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
        })
        .collect();
    // Breadth first from this process, so the list runs parents before children.
    let mut found = vec![std::process::id()];
    let mut i = 0;
    while i < found.len() {
        let parent = found[i];
        found.extend(
            pairs
                .iter()
                .filter(|(_, pp)| *pp == parent)
                .map(|(p, _)| *p),
        );
        i += 1;
    }
    found.remove(0);
    found
}

/// Kill `pids`, deepest first (they come parents first), and say how many.
fn kill_descendants(pids: &[u32]) -> usize {
    let mut killed = 0;
    for pid in pids.iter().rev() {
        let ok = std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .is_ok_and(|s| s.success());
        killed += usize::from(ok);
    }
    killed
}

/// Say why, dump every thread, and abort.
fn fire(elapsed: Duration, budget: Duration) -> ! {
    let running = RUNNING
        .lock()
        .map(|r| r.join("\n    "))
        .unwrap_or_else(|_| "<unknown: the list's lock was poisoned>".to_owned());
    say(&format!(
        "\n\
         ==================== vox test watchdog ====================\n\
         This test process has been running for {elapsed:?} and is being aborted.\n\
         \n\
         It is hung, not slow: the budget is {budget:?}. A `tokio::time::timeout` did\n\
         not save it, which means the runtime is not making progress — a task\n\
         spinning without yielding, a blocking call on a runtime thread, or a\n\
         leaked task after `block_on` returned.\n\
         \n\
         Tests still running:\n    {running}\n\
         \n\
         Every thread's stack follows. The spinning thread is the one whose frames\n\
         are not a wait (a condvar, kevent/epoll, a sleep) and carry nearly every\n\
         sample; a deadlock shows as threads parked in a mutex's lock. Then each\n\
         process this test started, under its pid and command line: in a proof\n\
         that drives `vox`, the hung one is usually there, not here. SIGABRT\n\
         follows too, so on macOS ~/Library/Logs/DiagnosticReports keeps a copy.\n\
         \n\
         To hold it open for a debugger instead: VOX_TEST_WATCHDOG_SECS=0\n\
         ===========================================================\n"
    ));
    dump_threads(std::process::id());
    // Found once, before any diagnostic runs: `ps` and `sample` are children of this process too,
    // and are waited for, so they are never in the list.
    let children = descendants();
    dump_descendants(&children);
    say("==================== vox test watchdog: end of thread dump; aborting ====================\n");
    let killed = kill_descendants(&children);
    say(&format!(
        "vox test watchdog: killed {killed} descendant process(es) before aborting\n"
    ));
    std::process::abort();
}

/// Dump every descendant's threads, each under a header naming its pid and command line, within
/// [`DESCENDANTS_PATIENCE`] between them.
fn dump_descendants(pids: &[u32]) {
    let deadline = Instant::now() + DESCENDANTS_PATIENCE;
    for pid in pids {
        let command = Command::new("ps")
            .args(["-o", "command=", "-p", &pid.to_string()])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default();
        say(&format!(
            "\n==================== vox test watchdog: descendant {pid}: {command} ====================\n"
        ));
        if Instant::now() >= deadline {
            say(&format!(
                "(not dumped: the descendants' dumps already took {DESCENDANTS_PATIENCE:?})\n"
            ));
            continue;
        }
        dump_threads(*pid);
    }
}

/// Write straight to file descriptor 2. `eprintln!` from this thread lands in libtest's capture
/// buffer for the test that spawned it, and an aborted process never prints that buffer.
fn say(text: &str) {
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(text.as_bytes());
    let _ = err.flush();
}

#[cfg(target_os = "macos")]
fn dump_threads(pid: u32) {
    let pid = pid.to_string();
    // Per-thread state and CPU, then a sampled call graph of every thread.
    run_bounded(Command::new("/bin/ps").args(["-M", "-p", &pid]));
    // `-file /dev/stdout`: into the log, and not also a stray report in /tmp for every abort.
    run_bounded(Command::new("/usr/bin/sample").args([
        pid.as_str(),
        "3",
        "-mayDie",
        "-file",
        "/dev/stdout",
    ]));
}

#[cfg(target_os = "linux")]
fn dump_threads(pid: u32) {
    let before = census(pid);
    std::thread::sleep(Duration::from_secs(1));
    let after = census(pid);
    if after.is_empty() {
        say(&format!("(no threads to show: process {pid} is gone)\n"));
        return;
    }
    let mut out = String::from("threads (tid, state, CPU ticks in the last second, name):\n");
    for (tid, state, ticks, name) in &after {
        let was = before
            .iter()
            .find(|(t, ..)| t == tid)
            .map_or(0, |(_, _, b, _)| *b);
        out.push_str(&format!(
            "  {tid:>8}  {state}  {:>4}  {name}\n",
            ticks.saturating_sub(was)
        ));
    }
    say(&out);
    let pid = pid.to_string();
    // Where gdb is installed and the kernel's ptrace policy lets a child attach to its parent.
    run_bounded(Command::new("gdb").args([
        "-p",
        &pid,
        "-batch",
        "-nx",
        "-ex",
        "thread apply all bt",
    ]));
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn dump_threads(_pid: u32) {
    say("(no thread dump on this platform)\n");
}

/// `(tid, state, utime + stime, name)` for every thread of process `pid`.
#[cfg(target_os = "linux")]
fn census(pid: u32) -> Vec<(u64, char, u64, String)> {
    let mut threads = Vec::new();
    let Ok(dir) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return threads;
    };
    for entry in dir.flatten() {
        let Ok(tid) = entry.file_name().to_string_lossy().parse::<u64>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // `pid (comm) state ...`: the name may hold spaces and parentheses, so split at the last `)`.
        let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else {
            continue;
        };
        let name = stat[open + 1..close].to_owned();
        let rest: Vec<&str> = stat[close + 1..].split_whitespace().collect();
        let state = rest.first().and_then(|s| s.chars().next()).unwrap_or('?');
        // Fields 14 and 15 (utime, stime) are rest[11] and rest[12].
        let ticks = rest
            .get(11)
            .and_then(|u| u.parse::<u64>().ok())
            .unwrap_or(0)
            + rest
                .get(12)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
        threads.push((tid, state, ticks, name));
    }
    threads.sort();
    threads
}

/// Run a diagnostic with its output on our stderr, and give up on it after [`DUMP_PATIENCE`].
fn run_bounded(cmd: &mut Command) {
    let spawned = cmd
        .stdin(Stdio::null())
        .stdout(std::io::stderr())
        .stderr(std::io::stderr())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            say(&format!("(could not run {cmd:?}: {e})\n"));
            return;
        }
    };
    let deadline = Instant::now() + DUMP_PATIENCE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                say(&format!("({cmd:?} did not finish in {DUMP_PATIENCE:?})\n"));
                return;
            }
        }
    }
}
