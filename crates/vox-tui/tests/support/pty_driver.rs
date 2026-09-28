//! Run a `tests/pty/*.py` driver of the shipped `vox tui`, **with a bound** (V210-54, #240).
//!
//! `tui_member_names_proof` waited on its driver with `Command::output()`, which has no deadline:
//! the driver hung for 40 minutes on the macOS CI runner (run 36397085576) and took the whole job
//! past its limit, with nothing in the log to say where. So:
//!
//! - the driver's **stderr is passed through live** — its `[pty …] <stage>` lines, and the stack it
//!   prints if it hangs, reach the log as they happen, whatever becomes of this process after;
//! - its **stdout** (the verdict lines) is collected and returned;
//! - past [`BOUND`] it is sent SIGTERM, on which it prints `HUNG at <stage>` with its stack and
//!   stops every process it started; if it still runs [`GRACE`] later it is killed;
//! - **however the driver ends** — a pass, a red, its own `faulthandler` backstop hard-exiting, or
//!   this bound — every process it was seen to start (found by parent pid, every
//!   [`SNAPSHOT_EVERY`]) that is still alive and now orphaned is killed. A driver that dies
//!   without its own cleanup (SIGTERM with no handler kills Python outright, measured; so does
//!   `faulthandler`'s exit) leaves no `vox` daemon behind, reparented to init.
//!
//! The driver's own budget (`VOX_PTY_BUDGET_SECS`, 240 s by default) comes first; this bound is
//! the backstop for a driver that cannot run its own.

use std::io::Read as _;
use std::process::{Command, Stdio};
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
}

/// Run `python3 <script> <args…>`, bounded; see the module docs.
pub fn run(script: &str, args: &[&str]) -> Driven {
    let t0 = Instant::now();
    let mut child = Command::new("python3")
        .arg(script)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("python3 must be on PATH to drive the TUI");
    let mut out = child.stdout.take().expect("stdout");
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    let mut stopped = None;
    let mut seen: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    let mut looked = Instant::now() - SNAPSHOT_EVERY;
    let status = loop {
        if looked.elapsed() >= SNAPSHOT_EVERY {
            seen.extend(descendants(child.id()));
            looked = Instant::now();
        }
        if let Some(status) = child.try_wait().expect("wait for the driver") {
            break Some(status);
        }
        match stopped {
            None if t0.elapsed() >= BOUND => {
                seen.extend(descendants(child.id()));
                eprintln!(
                    "[pty] the driver still runs after {BOUND:?}: sending it SIGTERM (pid {}; it \
                     started {seen:?})",
                    child.id()
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
    let left: Vec<u32> = seen.iter().copied().filter(|&p| orphaned(p)).collect();
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
    Driven {
        code: status.and_then(|s| s.code()),
        stdout,
        took: t0.elapsed(),
    }
}

/// Every process below `root`, deepest first, from `ps`'s parent pids.
fn descendants(root: u32) -> Vec<u32> {
    let Ok(out) = Command::new("ps").args(["-A", "-o", "pid=,ppid="]).output() else {
        return Vec::new();
    };
    let pairs: Vec<(u32, u32)> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace().map(str::parse::<u32>);
            Some((w.next()?.ok()?, w.next()?.ok()?))
        })
        .collect();
    let mut found = Vec::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for &(pid, ppid) in &pairs {
            if ppid == parent && !found.contains(&pid) {
                found.push(pid);
                frontier.push(pid);
            }
        }
    }
    found.reverse();
    found
}

/// Whether `pid` is still running and has been reparented to init: a process the driver left
/// behind. A pid that exited (and was perhaps reused by something with a live parent) is not.
fn orphaned(pid: u32) -> bool {
    Command::new("ps")
        .args(["-o", "ppid=", "-p", &pid.to_string()])
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "1")
}
