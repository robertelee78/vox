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
//! kills every descendant of this process, found by parent pid, deepest first — and looks again
//! until it finds none, because the test's threads go on starting processes while it dumps
//! (V210-99).
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
//! ## Why a debug build's budget is larger, by a measured amount
//! A debug build's `vox` spends 10–100 times as long in production Argon2id and in the join's
//! proof of work as a release build does: every unlock (any verb that opens a profile, a daemon
//! starting, a room created) and every join. A proof that sets up a room of five members passed in
//! 500 s of its 600 s on one tree, and was aborted 3 runs of 3 on the next (V210-99, #295), with
//! nothing wrong but that cost. Those costs are the product's, never weakened for a test. So a
//! proof that pays them arms with [`arm_for_setup`], naming how many joins and unlocks its setup makes, and a debug build adds
//! [`DEBUG_JOIN`] per join and [`DEBUG_UNLOCK`] per unlock to the budget: twice the most each was
//! measured to cost a debug build on a machine doing its ordinary concurrent work. Twice, because
//! the next run may be slower than any measured (a fill sized to its slowest add met a slower one
//! on the next run), and a hang is minutes or hours over, so the headroom costs the watchdog
//! nothing. A release build's budget is unchanged.
//!
//! ## Why it does not say "hung"
//! It used to say "It is hung, not slow … the runtime is not making progress" every time. In a
//! real-binary proof the test process is only waiting on its children, and a runner that stopped
//! scheduling it — or a machine that slept — looks the same from here. So it says what it can
//! measure (V210-106): how long the process ran by the monotonic and the wall clock, how far its
//! own sleeps overran (a stall of this process), and how much CPU this process and each one it
//! started used over the last two seconds (a spinning or a waiting product) — and from that, which
//! side the budget was exceeded on: a PRODUCT HANG, an APPARATUS STALL, or NO RESULT.
//!
//! ## Why its verdict is the first red line, and the process ends by its abort
//! Killing a proof's processes kills the `vox` verb a test thread is waiting on. That thread used
//! to panic on the verb's empty stderr ("bob joins: ", or "ipc closed before reply" when it was the
//! daemon under the join that died), and libtest exited 101 — an ordinary red with no cause, or a
//! false one — before the kill had looked again (V210-99, 4 of 5 staged aborts). So once it fires,
//! a test thread that panics parks, and a process exit (libtest's on a red, or `main` returning)
//! waits: nothing but the watchdog's abort ends the process, and nothing but its verdict and dumps
//! precedes it.
//!
//! The budget is deliberately generous: it is not a performance assertion, it is the line past
//! which "slow" is no longer a credible explanation. Override with `VOX_TEST_WATCHDOG_SECS`,
//! and `VOX_TEST_WATCHDOG_SECS=0` disables it — for attaching a debugger, which is the one
//! case where an unbounded hang is what you want.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant, SystemTime};

/// Past this, a gate is stuck — a product hang or an apparatus stall — rather than slow. The
/// longest gate observed is ~53 s.
const DEFAULT_BUDGET: Duration = Duration::from_secs(600);

/// A sleep of the watchdog's that overran by more than this means this process was not scheduled
/// for that long — the runner stalled it, or the machine slept.
const STALL: Duration = Duration::from_secs(5);

/// A process this test started that used at least this much CPU over the census's last 2 s is
/// still working, so a budget that ran out on it is not a hang (V210-106): a debug `trust add`
/// hashing a passphrase ran at 78%.
const BUSY_PCT: f64 = 25.0;

/// Twice the most one join cost a debug build: `vox room join` returning, its proof of work solved by the
/// joining node, measured on the equivocation proof's staging (an anchor, five daemons, four
/// joins in turn) on a machine doing its ordinary concurrent work, at load 10 to 77 (V210-99): 36
/// joins over nine runs, on three builds (bb636f78, 4abf8307, and this branch) side by side, median
/// 47.8 s, least 26.0 s, most 142.0 s. Nearly all of it is the solve, whose cost is random: it
/// varied fivefold from one join to the next within one run.
#[allow(dead_code)]
pub const DEBUG_JOIN: Duration = Duration::from_millis(2 * 142_000);

/// Twice the most one production-Argon2id unlock cost a debug build — `vox id` on a profile, measured in
/// the same nine runs as [`DEBUG_JOIN`] (V210-99): 45 of them, median 6.5 s, most 14.1 s. The other
/// verbs that unlock cost no more there: a daemon answering after it starts, at most 12.7 s of 45,
/// and a `trust add`, at most 9.9 s on average over a run's 20.
#[allow(dead_code)]
pub const DEBUG_UNLOCK: Duration = Duration::from_millis(2 * 14_100);

/// What [`DEBUG_JOIN`] rests on, printed when a debug build arms for its setup.
const DEBUG_JOIN_MEASURED: &str = "a join: 36 measured, median 47.8s, most 142.0s";

/// What [`DEBUG_UNLOCK`] rests on, printed when a debug build arms for its setup.
const DEBUG_UNLOCK_MEASURED: &str = "an unlock: 45 measured, median 6.5s, most 14.1s";

/// The budget, in seconds: the largest any test of this binary asked for through [`arm_for`] or
/// [`arm_for_setup`], and never less than [`DEFAULT_BUDGET`]. Tests run in parallel threads of one
/// process, so the largest covers every one of them.
static BUDGET_SECS: AtomicU64 = AtomicU64::new(DEFAULT_BUDGET.as_secs());

/// What `joins` joins and `unlocks` unlocks cost this build beyond a release build's: in a
/// release build nothing, in a debug build twice their measured most ([`DEBUG_JOIN`],
/// [`DEBUG_UNLOCK`]). For a driver's own budget that waits on them, as for the watchdog's.
#[allow(dead_code)]
pub fn debug_cost(joins: u32, unlocks: u32) -> Duration {
    if cfg!(debug_assertions) {
        DEBUG_JOIN * joins + DEBUG_UNLOCK * unlocks
    } else {
        Duration::ZERO
    }
}

/// [`arm`], for a test whose setup makes `joins` joins and `unlocks` production-Argon2id unlocks:
/// a debug build's budget grows by their measured cost ([`debug_cost`]), and says so.
#[allow(dead_code)]
pub fn arm_for_setup(joins: u32, unlocks: u32) {
    let extra = debug_cost(joins, unlocks);
    if !extra.is_zero() {
        say(&format!(
            "[watchdog] debug build: budget {}s = {}s + {joins} join(s) x {:.1}s + {unlocks} \
             unlock(s) x {:.1}s (each twice the most measured: {DEBUG_JOIN_MEASURED}; \
             {DEBUG_UNLOCK_MEASURED})\n",
            (DEFAULT_BUDGET + extra).as_secs(),
            DEFAULT_BUDGET.as_secs(),
            DEBUG_JOIN.as_secs_f64(),
            DEBUG_UNLOCK.as_secs_f64(),
        ));
    }
    arm_for(DEFAULT_BUDGET + extra);
}

/// [`arm`], for a proof whose debug-build budget is sized on its own whole run rather than on its
/// steps (whose most-measured costs, summed, would come past what any run is given): twice
/// `slowest`, the slowest of `runs` measured debug runs of that proof, and never less than
/// [`DEFAULT_BUDGET`]. A release build's budget is unchanged.
#[allow(dead_code)]
pub fn arm_for_debug_total(slowest: Duration, runs: u32) {
    if cfg!(debug_assertions) {
        let budget = (slowest * 2).max(DEFAULT_BUDGET);
        say(&format!(
            "[watchdog] debug build: budget {}s = twice the slowest of {runs} measured debug \
             runs of this proof ({:.1}s)\n",
            budget.as_secs(),
            slowest.as_secs_f64()
        ));
        arm_for(budget);
    } else {
        arm();
    }
}

/// How long the stack dump may take before the abort goes ahead without it. Symbolicating a
/// large test binary is the slow part; a dump that itself hangs must not undo the bound.
const DUMP_PATIENCE: Duration = Duration::from_secs(90);

/// How long the descendants' dumps may take between them. Past it the rest are named but not
/// dumped, and the kill goes ahead.
const DESCENDANTS_PATIENCE: Duration = Duration::from_secs(180);

/// How long the kill may go on finding new descendants before the abort goes ahead regardless.
const KILL_PATIENCE: Duration = Duration::from_secs(10);

/// How often the census records this process's descendants while the watchdog waits.
const CENSUS_EVERY: Duration = Duration::from_secs(2);

static ARMED: Once = Once::new();

/// Set once [`fire`] begins. From then on a test thread that panics parks instead of finishing
/// (see [`arm_for`]).
static FIRING: AtomicBool = AtomicBool::new(false);

/// Every descendant [`record_descendants`] has seen: `(pid, start time)`.
static SEEN: Mutex<Vec<(u32, String)>> = Mutex::new(Vec::new());

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
/// than [`DEFAULT_BUDGET`] (a debug-build join may take minutes). The binary's budget is the
/// largest any of its tests asked for, whichever armed first. `VOX_TEST_WATCHDOG_SECS` still
/// overrides it.
pub fn arm_for(default_budget: Duration) {
    BUDGET_SECS.fetch_max(default_budget.as_secs(), Ordering::Relaxed);
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
        // An explicit budget is taken as given; otherwise the largest any test asked for, read
        // afresh on every look, since a test may arm after the first did.
        let fixed = match std::env::var("VOX_TEST_WATCHDOG_SECS") {
            Ok(v) => match v.parse::<u64>() {
                Ok(0) => return,
                Ok(secs) => Some(Duration::from_secs(secs)),
                Err(_) => None,
            },
            Err(_) => None,
        };
        let budget = move || {
            fixed.unwrap_or_else(|| Duration::from_secs(BUDGET_SECS.load(Ordering::Relaxed)))
        };
        // **Once the watchdog fires, the test cannot end the process first** (#295; see the
        // module's docs). A test thread that panics parks instead of reporting, and an exit —
        // libtest's `exit(101)` on a red, or `main` returning — waits for the abort.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let watchdog = std::thread::current().name() == Some("vox-test-watchdog");
            if FIRING.load(Ordering::SeqCst) && !watchdog {
                hold();
            }
            previous(info);
        }));
        // SAFETY: `atexit` is the C library's, which every Rust program on these platforms links;
        // `hold_exit` takes no arguments, never unwinds, and touches only an atomic.
        unsafe {
            atexit(hold_exit);
        }
        let started = Instant::now();
        let wall = SystemTime::now();
        std::thread::Builder::new()
            .name("vox-test-watchdog".to_owned())
            .spawn(move || {
                // Its own clock: the largest overrun of one of its sleeps, and when it happened.
                let mut overslept = (Duration::ZERO, Duration::ZERO);
                while started.elapsed() < budget() {
                    record_descendants();
                    let ask = CENSUS_EVERY.min(budget().saturating_sub(started.elapsed()));
                    let asked = Instant::now();
                    std::thread::sleep(ask);
                    let over = asked.elapsed().saturating_sub(ask);
                    if over > overslept.0 {
                        overslept = (over, started.elapsed());
                    }
                }
                let by_wall = wall.elapsed().unwrap_or_default();
                fire(started.elapsed(), by_wall, overslept, budget());
            })
            .ok();
    });
}

extern "C" {
    fn atexit(callback: extern "C" fn()) -> std::ffi::c_int;
}

/// Run at the process's exit: while the watchdog fires, the exit waits for its abort.
extern "C" fn hold_exit() {
    if FIRING.load(Ordering::SeqCst) {
        hold();
    }
}

/// Park this thread for good: the watchdog's abort ends the process.
fn hold() -> ! {
    loop {
        std::thread::park();
    }
}

/// One row of the process table.
struct Row {
    pid: u32,
    ppid: u32,
    pgid: u32,
    zombie: bool,
    /// Seconds since it started (`etime`).
    age: u64,
    /// When it started (`lstart`): with the pid, one process, never a later one given its pid.
    started: String,
}

/// The whole process table, from `ps`, which macOS and Linux both have, so the support code needs
/// no platform crate — less the `ps` itself, which is this process's child while it runs, and
/// would otherwise be found, and "killed" after it has exited, on every look.
fn table() -> Vec<Row> {
    let Ok(child) = std::process::Command::new("ps")
        .args(["-A", "-o", "pid=,ppid=,pgid=,stat=,etime=,lstart="])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return Vec::new();
    };
    let ps = child.id();
    let Ok(out) = child.wait_with_output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let pid = it.next()?.parse().ok()?;
            let ppid = it.next()?.parse().ok()?;
            let pgid = it.next()?.parse().ok()?;
            let zombie = it.next()?.starts_with('Z');
            let age = etime_secs(it.next()?)?;
            let started = it.collect::<Vec<_>>().join(" ");
            (pid != ps).then_some(Row {
                pid,
                ppid,
                pgid,
                zombie,
                age,
                started,
            })
        })
        .collect()
}

/// `[[dd-]hh:]mm:ss` in seconds.
fn etime_secs(etime: &str) -> Option<u64> {
    let (days, clock) = match etime.split_once('-') {
        Some((d, rest)) => (d.parse::<u64>().ok()?, rest),
        None => (0, etime),
    };
    let secs = clock
        .split(':')
        .try_fold(0u64, |acc, part| Some(acc * 60 + part.parse::<u64>().ok()?))?;
    Some(days * 86_400 + secs)
}

/// Every live process this test process started, parents before children:
///
/// - its descendants, found by parent pid;
/// - every process [`record_descendants`] saw as a descendant and that still runs as the same
///   process, though its parent has since died and it was reparented to init;
/// - every orphan (reparented to init) in this process's group that started after this process
///   did — a process started under a `sh` that has exited, or that daemonized, before the
///   census ever saw it;
///
/// and the descendants of each. A zombie is left out: it is already dead, and it stays in the
/// table until this process — which is about to abort — reaps it, so counting it would make a
/// kill never look finished.
fn ours() -> Vec<u32> {
    let rows: Vec<Row> = table().into_iter().filter(|r| !r.zombie).collect();
    let me = std::process::id();
    let Some(mine) = rows.iter().find(|r| r.pid == me) else {
        return Vec::new();
    };
    // This process's ancestors share its group and may be orphans started before it; never them.
    let mut ancestors = Vec::new();
    let mut up = mine.ppid;
    while let Some(r) = rows
        .iter()
        .find(|r| r.pid == up && !ancestors.contains(&r.pid))
    {
        ancestors.push(r.pid);
        up = r.ppid;
    }
    let seen = SEEN.lock().map(|s| s.clone()).unwrap_or_default();
    let mut found = vec![me];
    for r in &rows {
        let reparented = r.ppid == 1 && r.pid != me && !ancestors.contains(&r.pid);
        let recorded = seen.iter().any(|(p, st)| *p == r.pid && *st == r.started);
        let orphan_of_ours = r.pgid == mine.pgid && r.age <= mine.age;
        if reparented && (recorded || orphan_of_ours) {
            found.push(r.pid);
        }
    }
    // Breadth first, so the list runs parents before children.
    let mut i = 0;
    while i < found.len() {
        let parent = found[i];
        for r in &rows {
            if r.ppid == parent && !found.contains(&r.pid) {
                found.push(r.pid);
            }
        }
        i += 1;
    }
    found.remove(0);
    found
}

/// Record every descendant this process has now, by pid and start time, for [`ours`]: a process
/// whose parent dies is reparented to init and is no longer found by parent pid.
fn record_descendants() {
    let rows = table();
    let me = std::process::id();
    let mut found = vec![me];
    let mut i = 0;
    while i < found.len() {
        let parent = found[i];
        found.extend(rows.iter().filter(|r| r.ppid == parent).map(|r| r.pid));
        i += 1;
    }
    if let Ok(mut seen) = SEEN.lock() {
        for r in rows
            .iter()
            .filter(|r| r.pid != me && found.contains(&r.pid))
        {
            if !seen.iter().any(|(p, st)| *p == r.pid && *st == r.started) {
                seen.push((r.pid, r.started.clone()));
            }
        }
    }
}

/// Kill `pids`, deepest first (they come parents first), and say how many.
fn kill_all(pids: &[u32]) -> usize {
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
    FIRING.store(true, Ordering::SeqCst);
    let running = RUNNING
        .lock()
        .map(|r| r.join("\n    "))
        .unwrap_or_else(|_| "<unknown: the list's lock was poisoned>".to_owned());
    let stalled = overslept > STALL;
    let stall = if stalled {
        format!(
            "THIS PROCESS STALLED: one {CENSUS_EVERY:?} sleep came back {overslept:?} late, \
             {overslept_at:?} in.\n  The runner did not schedule it for that long, so an \
             APPARATUS STALL is likely."
        )
    } else {
        format!(
            "this process was scheduled throughout: no {CENSUS_EVERY:?} sleep came back more than \
             {overslept:?} late."
        )
    };
    let slept = by_wall.saturating_sub(elapsed);
    let asleep = slept > STALL;
    let slept = if asleep {
        format!(
            "THE MACHINE SLEPT: the wall clock ran {slept:?} ahead of the monotonic one. A run that \
             overlapped a sleep is NO RESULT."
        )
    } else {
        format!(
            "the wall clock agrees with the monotonic one (within {slept:?}): no machine sleep."
        )
    };
    // Found once, before any diagnostic runs: `ps` and `sample` are children of this process too,
    // and are waited for, so they are never in the list.
    let children = ours();
    let (cpu, busiest) = cpu_census(&children);
    // The side, from what was measured: a machine that slept or a process that was not scheduled
    // is the apparatus's. A process that ran throughout on an awake machine and still did not
    // finish was held up by what it waits on — the product it drives — unless that product is
    // still working: then the budget, not the product, is what ran out.
    let working = busiest.filter(|(_, pct)| *pct >= BUSY_PCT);
    let verdict = if asleep {
        "NO RESULT: the machine slept during the run (below), so the budget measured nothing."
            .to_owned()
    } else if stalled {
        "APPARATUS STALL: this process was not scheduled for longer than the stall line (below)."
            .to_owned()
    } else if let Some((pid, pct)) = working {
        format!(
            "CANNOT MEASURE: the budget ran out while the product was still working (CPU {pct:.0}%,\n\
             pid {pid}, below). A budget too short for this machine and a product spinning look\n\
             the same from here; the stacks below tell them apart."
        )
    } else {
        "PRODUCT HANG: this process was scheduled throughout, the machine did not sleep, and no\n\
         process it started was working (CPU below), so the time went to what it waits on — a\n\
         `vox` process stuck waiting."
            .to_owned()
    };
    say(&format!(
        "\n\
         ==================== vox test watchdog ====================\n\
         This test process has run for {elapsed:?} ({by_wall:?} by the wall clock) against a\n\
         budget of {budget:?}, and is being aborted.\n\
         \n\
         BUDGET EXCEEDED. {verdict}\n\
         \n\
         What this watchdog measured:\n\
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
    dump_descendants(&children);
    say("==================== vox test watchdog: end of thread dump; aborting ====================\n");
    let (killed, left) = kill_every_descendant();
    say(&format!(
        "vox test watchdog: killed {killed} descendant process(es) before aborting; {} remain{}\n",
        left.len(),
        if left.is_empty() {
            String::new()
        } else {
            format!(" (still running: {left:?})")
        }
    ));
    std::process::abort();
}

/// One line per process — this one, then `pids` — with its state, its CPU over the last 2 s, and
/// its command line, from two `ps` samples 2 s apart; and the busiest of `pids` (not this one),
/// with its CPU percentage, if any was measured.
fn cpu_census(pids: &[u32]) -> (String, Option<(u32, f64)>) {
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
        return ("    (ps reported nothing: CPU unknown)".to_owned(), None);
    }
    let mut busiest: Option<(u32, f64)> = None;
    let lines = after
        .iter()
        .map(|(pid, state, time, command)| {
            let was = before.iter().find(|(p, ..)| p == pid).and_then(|b| b.2);
            let used = match (was, time) {
                (Some(a), Some(b)) => {
                    let pct = (b - a).max(0.0) / 2.0 * 100.0;
                    if *pid != std::process::id() && busiest.is_none_or(|(_, top)| pct > top) {
                        busiest = Some((*pid, pct));
                    }
                    format!("{pct:>5.0}%")
                }
                _ => "    ?%".to_owned(),
            };
            let command: String = command.chars().take(100).collect();
            format!("    {pid:>7} {state:<4} {used}  {command}")
        })
        .collect::<Vec<_>>()
        .join("\n");
    (lines, busiest)
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

/// Kill every process this test process started ([`ours`]) until a fresh look finds none, and
/// say how many were killed and which, if any, are still there.
///
/// The list the dumps used is minutes old by now: the test's own threads are not stopped while
/// the watchdog dumps, so a proof still in its setup goes on starting `vox` processes. Killing
/// only that list left each one started since then to be reparented to init by the abort — a
/// `vox daemon` outlived a watchdog that said it had killed 4 (V210-99). So the kill looks again
/// after every round, until a look finds nothing, within [`KILL_PATIENCE`]. And a look is not
/// only down the parent-pid tree: a process whose parent has died is reparented to init and
/// leaves that tree, so [`ours`] also finds what the census recorded and this group's orphans.
fn kill_every_descendant() -> (usize, Vec<u32>) {
    let deadline = Instant::now() + KILL_PATIENCE;
    let mut killed = 0;
    loop {
        let found = ours();
        if found.is_empty() || Instant::now() >= deadline {
            return (killed, found);
        }
        killed += kill_all(&found);
        // Let the kernel reap them, so the next look does not count the dying.
        std::thread::sleep(Duration::from_millis(100));
    }
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
