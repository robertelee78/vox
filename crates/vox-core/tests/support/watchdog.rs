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
//! ## Why it does not say "hung"
//! It used to say "It is hung, not slow … the runtime is not making progress" every time. In a
//! real-binary proof the test process is only waiting on its children, and a runner that stopped
//! scheduling it — or a machine that slept — looks the same from here. So it says what it can
//! measure (V210-106): how long the process ran by the monotonic and the wall clock, how far its
//! own sleeps overran (a stall of this process), and how much CPU this process and each one it
//! started used over the last two seconds (a spinning or a waiting product) — and that the budget
//! was exceeded by **a product hang or an apparatus stall**, which only that evidence can tell
//! apart.
//!
//! The budget is deliberately generous: it is not a performance assertion, it is the line past
//! which "slow" is no longer a credible explanation. Override with `VOX_TEST_WATCHDOG_SECS`,
//! and `VOX_TEST_WATCHDOG_SECS=0` disables it — for attaching a debugger, which is the one
//! case where an unbounded hang is what you want.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant, SystemTime};

/// Past this, a gate is stuck — a product hang or an apparatus stall — rather than slow. The
/// longest gate observed is ~53 s.
const DEFAULT_BUDGET: Duration = Duration::from_secs(600);

/// The watchdog's own tick: it sleeps this long at a time, and measures how far each sleep overran.
const TICK: Duration = Duration::from_secs(5);

/// A tick that overran by more than this means this process was not scheduled for that long — the
/// runner stalled it, or the machine slept.
const STALL: Duration = Duration::from_secs(5);

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
#[allow(dead_code)] // a proof that needs a longer bound calls `arm_for` instead
pub fn arm() {
    arm_for(DEFAULT_BUDGET);
}

/// [`arm`], with `budget` in place of the default: for a proof whose product bounds are longer
/// than [`DEFAULT_BUDGET`] (a debug-build join may take minutes). `VOX_TEST_WATCHDOG_SECS` still
/// overrides it.
pub fn arm_for(default_budget: Duration) {
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
                Err(_) => default_budget,
            },
            Err(_) => default_budget,
        };
        let started = Instant::now();
        let wall = SystemTime::now();
        std::thread::Builder::new()
            .name("vox-test-watchdog".to_owned())
            .spawn(move || {
                // Its own clock: the largest overrun of one tick, and when it happened.
                let mut overslept = (Duration::ZERO, Duration::ZERO);
                while started.elapsed() < budget {
                    let ask = TICK.min(budget.saturating_sub(started.elapsed()));
                    let asked = Instant::now();
                    std::thread::sleep(ask);
                    let over = asked.elapsed().saturating_sub(ask);
                    if over > overslept.0 {
                        overslept = (over, started.elapsed());
                    }
                }
                let by_wall = wall.elapsed().unwrap_or_default();
                fire(started.elapsed(), by_wall, overslept, budget);
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

/// Say what is known, dump every thread, and abort.
fn fire(
    elapsed: Duration,
    by_wall: Duration,
    (overslept, overslept_at): (Duration, Duration),
    budget: Duration,
) -> ! {
    let running = RUNNING
        .lock()
        .map(|r| r.join("\n    "))
        .unwrap_or_else(|_| "<unknown: the list's lock was poisoned>".to_owned());
    let stall = if overslept > STALL {
        format!(
            "THIS PROCESS STALLED: one {TICK:?} sleep came back {overslept:?} late, {overslept_at:?} \
             in.\n  The runner did not schedule it for that long, so an APPARATUS STALL is likely."
        )
    } else {
        format!(
            "this process was scheduled throughout: no {TICK:?} sleep came back more than \
             {overslept:?} late."
        )
    };
    let slept = by_wall.saturating_sub(elapsed);
    let slept = if slept > STALL {
        format!(
            "THE MACHINE SLEPT: the wall clock ran {slept:?} ahead of the monotonic one. A run that \
             overlapped a sleep is NO RESULT."
        )
    } else {
        format!(
            "the wall clock agrees with the monotonic one (within {slept:?}): no machine sleep."
        )
    };
    let children = descendants();
    let cpu = cpu_census(&children);
    say(&format!(
        "\n\
         ==================== vox test watchdog ====================\n\
         This test process has run for {elapsed:?} ({by_wall:?} by the wall clock) against a\n\
         budget of {budget:?}, and is being aborted.\n\
         \n\
         BUDGET EXCEEDED: a PRODUCT HANG or an APPARATUS STALL. The clock alone cannot\n\
         say which; what this watchdog measured can:\n\
         \n\
         - {stall}\n\
         - {slept}\n\
         - CPU over the last 2 s, this test process and every process it started (a\n  \
         product near 0 is waiting on something; one near 100% is spinning; a\n  \
         process in state T was stopped by the proof itself):\n\
         {cpu}\n\
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
    dump_descendants(&children);
    say("==================== vox test watchdog: end of thread dump; aborting ====================\n");
    let killed = kill_descendants(&children);
    say(&format!(
        "vox test watchdog: killed {killed} descendant process(es) before aborting\n"
    ));
    std::process::abort();
}

/// One line per process — this one, then `pids` — with its state, its CPU over the last 2 s, and
/// its command line, from two `ps` samples 2 s apart.
fn cpu_census(pids: &[u32]) -> String {
    let all: Vec<u32> = std::iter::once(std::process::id())
        .chain(pids.iter().copied())
        .collect();
    let sample = || -> Vec<(u32, String, Option<f64>, String)> {
        let list = all.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        let Ok(out) = Command::new("ps")
            .args(["-o", "pid=,state=,time=,command=", "-p", &list])
            .output()
        else {
            return Vec::new();
        };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| {
                let mut w = l.split_whitespace();
                let pid = w.next()?.parse().ok()?;
                let state = w.next()?.to_owned();
                let time = cpu_secs(w.next()?);
                Some((pid, state, time, w.collect::<Vec<_>>().join(" ")))
            })
            .collect()
    };
    let before = sample();
    std::thread::sleep(Duration::from_secs(2));
    let after = sample();
    if after.is_empty() {
        return "    (ps reported nothing: CPU unknown)".to_owned();
    }
    after
        .iter()
        .map(|(pid, state, time, command)| {
            let was = before.iter().find(|(p, ..)| p == pid).and_then(|b| b.2);
            let used = match (was, time) {
                (Some(a), Some(b)) => format!("{:>5.0}%", (b - a).max(0.0) / 2.0 * 100.0),
                _ => "    ?%".to_owned(),
            };
            let command: String = command.chars().take(100).collect();
            format!("    {pid:>7} {state:<4} {used}  {command}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `ps`'s cumulative CPU time in seconds: `[[dd-]hh:]mm:ss[.ff]`.
fn cpu_secs(t: &str) -> Option<f64> {
    let (days, rest) = match t.split_once('-') {
        Some((d, r)) => (d.parse::<f64>().ok()?, r),
        None => (0.0, t),
    };
    let mut secs = days * 86_400.0;
    let mut unit = 1.0;
    for part in rest.rsplit(':') {
        secs += part.parse::<f64>().ok()? * unit;
        unit *= 60.0;
    }
    Some(secs)
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
