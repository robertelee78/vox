//! Run a `tests/pty/*.py` driver of the shipped `vox tui`, **with a bound** (V210-54, #240).
//!
//! `tui_member_names_proof` waited on its driver with `Command::output()`, which has no deadline:
//! the driver hung for 40 minutes on the macOS CI runner (run 36397085576) and took the whole job
//! past its limit, with nothing in the log to say where. So:
//!
//! - the driver's **stderr is passed through live** — its `[pty …] <stage>` lines, and the stack it
//!   prints if it hangs, reach the log as they happen, whatever becomes of this process after —
//!   and kept, so that a driver that **crashed** (an uncaught Python exception: exit 1, a
//!   traceback, no verdict) is an `APPARATUS:` red quoting its traceback, never mistaken for a
//!   driver stopped by its backstop or for a verdict about the product;
//! - its **stdout** (the verdict lines) is collected and returned;
//! - past [`BOUND`] it is sent SIGTERM, on which it prints `HUNG at <stage>` with its stack and
//!   stops every process it started; if it still runs [`GRACE`] later it is killed;
//! - **however the driver ends** — a pass, a red, its own `faulthandler` backstop hard-exiting, or
//!   this bound — every process it was seen to start (found by parent pid, every
//!   [`SNAPSHOT_EVERY`]) that is still alive, now orphaned, **and still the same process** — the
//!   same start time as when it was seen — is killed. A driver that dies without its own cleanup
//!   (SIGTERM with no handler kills Python outright, measured; so does `faulthandler`'s exit)
//!   leaves no `vox` daemon behind, reparented to init. The start time is what makes this safe on
//!   a busy machine: a run keeps its pids for up to [`BOUND`] + [`GRACE`], which is longer than
//!   the pid space can take to wrap under load, and every launchd job has parent 1 too — a pid
//!   reused by one of them has another start time and is never touched;
//! - the driver's last stage is read back (from a file it writes, `VOX_PTY_STAGE_FILE`), so a
//!   driver that ended with no verdict is reported by where it stopped.
//!
//! The driver's own budget (`VOX_PTY_BUDGET_SECS`, 240 s by default) comes first; this bound is
//! the backstop for a driver that cannot run its own.

use std::io::{BufRead as _, Read as _, Write as _};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Past this the driver is stopped from outside: beyond its own budget and its `faulthandler`
/// backstop, and well inside the proof watchdog's 600 s.
pub const BOUND: Duration = Duration::from_secs(360);
/// How long a driver told to stop has to clean up before it is killed.
pub const GRACE: Duration = Duration::from_secs(30);
/// How often the driver's processes are looked up, so that whatever it leaves behind, however it
/// ends, is known.
pub const SNAPSHOT_EVERY: Duration = Duration::from_secs(1);

/// What a driver run came to: its exit code (`None` if it was killed or killed by a signal), and
/// everything it printed on stdout.
pub struct Driven {
    pub code: Option<i32>,
    pub stdout: String,
    pub took: Duration,
    /// The last stage the driver named, if it named any.
    pub stage: Option<String>,
    /// Everything the driver printed on stderr (it also went to the log live).
    pub stderr: String,
}

/// The words a driver's verdict line carries, after its tag.
const VERDICTS: [&str; 7] = [
    "PASS",
    "REFUSED",
    "RED",
    "APPARATUS",
    "HUNG at",
    "the TUI said done",
    "the TUI said what",
];

impl Driven {
    /// Whether the driver printed a verdict line of `tag`'s: a pass, a red, an apparatus
    /// failure or its own hang report. A driver with none was stopped before it could say.
    #[must_use]
    pub fn has_verdict(&self, tag: &str) -> bool {
        VERDICTS
            .iter()
            .any(|v| self.stdout.contains(&format!("{tag} {v}")))
    }

    /// The traceback of a driver that **crashed** — Python's exit 1 on an uncaught exception, with
    /// no verdict line of any tag — or `None`. A crash is the driver's fault, not the product's.
    #[must_use]
    pub fn crash(&self) -> Option<&str> {
        let at = self.stderr.rfind("Traceback (most recent call last):")?;
        let verdict = VERDICTS
            .iter()
            .any(|v| self.stdout.contains(&format!(" {v}")));
        (self.code == Some(1) && !verdict).then(|| &self.stderr[at..])
    }
}

/// Run `python3 <script> <args…>`, bounded; see the module docs.
#[allow(dead_code)] // a proof that needs a longer bound calls `run_within` or `run_for` instead
pub fn run(script: &str, args: &[&str]) -> Driven {
    checked(script, drive(script, args, BOUND, Duration::ZERO))
}

/// [`run`], stopped from outside past `bound` rather than [`BOUND`]: for a driver whose own
/// budget is longer, because the product bounds it waits on are (a debug-build join).
///
/// A driver that crashed (see [`Driven::crash`]) is an `APPARATUS:` red here, with its traceback,
/// before any caller can read its silence as a verdict.
#[allow(dead_code)]
pub fn run_within(script: &str, args: &[&str], bound: Duration) -> Driven {
    checked(script, drive(script, args, bound, Duration::ZERO))
}

/// [`run`], for a driver that waits on work a debug build is slower at: its bound is [`BOUND`]
/// plus `debug_cost` (the watchdog's `debug_cost` of that work, which is zero in a release build),
/// and the driver's own waits grow by it too (`VOX_PTY_DEBUG_EXTRA_SECS`, `vox_pty.DEBUG_EXTRA`).
/// A crashed driver is an `APPARATUS:` red, as in [`run_within`].
#[allow(dead_code)]
pub fn run_for(script: &str, args: &[&str], debug_cost: Duration) -> Driven {
    checked(script, drive(script, args, BOUND + debug_cost, debug_cost))
}

/// `driven`, unless the driver crashed: then an `APPARATUS:` red with its traceback.
fn checked(script: &str, driven: Driven) -> Driven {
    if let Some(traceback) = driven.crash() {
        panic!(
            "APPARATUS: the TUI driver {script} crashed (exit 1, an uncaught Python exception) at \
             stage {:?} after {:?}, so it gave no verdict on the product.\n{traceback}\nIts stdout:\n{}",
            driven.stage.as_deref().unwrap_or("(before its first stage)"),
            driven.took,
            driven.stdout
        );
    }
    driven
}

fn drive(script: &str, args: &[&str], bound: Duration, debug_cost: Duration) -> Driven {
    let t0 = Instant::now();
    let stage_file = std::env::temp_dir().join(format!(
        "vox-pty-stage-{}-{}",
        std::process::id(),
        t0.elapsed().as_nanos() ^ u128::from(std::process::id())
    ));
    let _ = std::fs::remove_file(&stage_file);
    let mut child = Command::new("python3")
        .arg(script)
        .args(args)
        .env("VOX_PTY_STAGE_FILE", &stage_file)
        .env("VOX_PTY_DEBUG_EXTRA_SECS", debug_cost.as_secs().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run python3 to drive the TUI: {e}"));
    let mut out = child.stdout.take().expect("APPARATUS: a piped stdout");
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    // Passed through to file descriptor 2 directly — no test capture holds it back, so it reaches
    // the log however this process ends — and kept for a crash's red. Read on its own thread and
    // never joined: a process the driver started may hold the pipe open.
    let err = child.stderr.take().expect("APPARATUS: a piped stderr");
    let said = Arc::new(Mutex::new(String::new()));
    let err_reader = {
        let said = Arc::clone(&said);
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(err).lines().map_while(Result::ok) {
                let _ = writeln!(std::io::stderr().lock(), "{line}");
                let mut s = said
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.push_str(&line);
                s.push('\n');
            }
        })
    };
    let mut stopped = None;
    // pid → its start time, as first seen.
    let mut seen: std::collections::BTreeMap<u32, String> = std::collections::BTreeMap::new();
    let mut looked = Instant::now() - SNAPSHOT_EVERY;
    let status = loop {
        if looked.elapsed() >= SNAPSHOT_EVERY {
            for (pid, start) in descendants(child.id()) {
                seen.entry(pid).or_insert(start);
            }
            looked = Instant::now();
        }
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|e| panic!("APPARATUS: could not wait for the TUI driver: {e}"))
        {
            break Some(status);
        }
        match stopped {
            None if t0.elapsed() >= bound => {
                for (pid, start) in descendants(child.id()) {
                    seen.entry(pid).or_insert(start);
                }
                eprintln!(
                    "[pty] the driver still runs after {bound:?}: sending it SIGTERM (pid {}; it \
                     started {:?})",
                    child.id(),
                    seen.keys().collect::<Vec<_>>()
                );
                let _ = Command::new("kill")
                    .args(["-TERM", &child.id().to_string()])
                    .status();
                stopped = Some(Instant::now());
            }
            Some(at) if at.elapsed() >= GRACE => {
                eprintln!("[pty] the driver did not stop within {GRACE:?} of SIGTERM: killing it");
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    // Whatever the driver started and left behind, however it ended, goes now: alive, and
    // orphaned — its parent gone, so nothing else will ever stop it.
    let left: Vec<u32> = seen
        .iter()
        .filter(|(pid, start)| left_behind(**pid, start))
        .map(|(pid, _)| *pid)
        .collect();
    if !left.is_empty() {
        eprintln!("[pty] the driver left {left:?} running: killing them");
        for pid in &left {
            let _ = Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status();
        }
    }
    // The driver is gone; its pipe closes with it unless a process it started still holds it, so
    // the collected stdout is waited for with a bound too.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !reader.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let stdout = if reader.is_finished() {
        reader.join().unwrap_or_default()
    } else {
        "(the driver's stdout was still held open by a process it left behind)".to_owned()
    };
    let stage = std::fs::read_to_string(&stage_file)
        .ok()
        .map(|s| s.trim().to_owned());
    let _ = std::fs::remove_file(&stage_file);
    // The driver has exited; its stderr closes with it unless a process it started holds it.
    let deadline = Instant::now() + Duration::from_secs(2);
    while !err_reader.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let stderr = said
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Driven {
        code: status.and_then(|s| s.code()),
        stdout,
        took: t0.elapsed(),
        stage,
        stderr,
    }
}

/// Every process below `root`, deepest first, with its start time, from `ps`.
fn descendants(root: u32) -> Vec<(u32, String)> {
    let Ok(out) = Command::new("ps")
        .args(["-A", "-o", "pid=,ppid=,lstart="])
        .output()
    else {
        return Vec::new();
    };
    let rows: Vec<(u32, u32, String)> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let pid = w.next()?.parse().ok()?;
            let ppid = w.next()?.parse().ok()?;
            Some((pid, ppid, w.collect::<Vec<_>>().join(" ")))
        })
        .collect();
    let mut found: Vec<(u32, String)> = Vec::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for (pid, ppid, start) in &rows {
            if *ppid == parent && !found.iter().any(|(p, _)| p == pid) {
                found.push((*pid, start.clone()));
                frontier.push(*pid);
            }
        }
    }
    found.reverse();
    found
}

/// Whether `pid` is a process the driver left behind: still running, reparented to init, and
/// **the same process that was seen** — started at `start`. A pid that exited and was reused,
/// even by another orphan (every launchd job has parent 1), has another start time.
fn left_behind(pid: u32, start: &str) -> bool {
    let Ok(out) = Command::new("ps")
        .args(["-o", "ppid=,lstart=", "-p", &pid.to_string()])
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    let now = String::from_utf8_lossy(&out.stdout);
    let mut w = now.split_whitespace();
    w.next() == Some("1") && w.collect::<Vec<_>>().join(" ") == start
}
