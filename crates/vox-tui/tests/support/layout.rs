//! Where the shipped `vox` keeps a node's files and its daemon's, for the proofs that look at them
//! (ADR-026 §7), and the harness's safety net for a daemon a proof leaves running.
//!
//! **The layout is written here from the ADR, not asked of `vox-core`**, so a proof that looks in
//! a node's directory measures where the product put a file against where the ADR says it goes:
//! `<data root>/nodes/<name>/` for a node, `<data root>/.daemon/` for the daemon. Before v0.3.0 a
//! node was `<data root>/<name>/`; a proof that still looked there found nothing — or found
//! nothing *left*, which read as "deleted" when the migration had only moved it.
//!
//! Included with `#[path]` by a proof, or by `world.rs`, `room.rs`, `sync_pair.rs` and
//! `relay.rs`, which is why not every item is used by every includer.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The node a verb acts as when none is named.
pub const DEFAULT_NODE: &str = "default";

/// `<data>/nodes/<name>`: node `name`'s directory under data root `data` (ADR-026 §7).
pub fn node_dir(data: &Path, name: &str) -> PathBuf {
    data.join("nodes").join(name)
}

/// `<data>/.daemon`: the daemon's directory under data root `data`.
pub fn daemon_dir(data: &Path) -> PathBuf {
    data.join(".daemon")
}

/// `<data>/.daemon/lock`: held by the data root's daemon for its whole life (ADR-026 D-1).
pub fn daemon_lock(data: &Path) -> PathBuf {
    daemon_dir(data).join("lock")
}

/// How long a daemon has to stop after SIGTERM before it is killed.
const REAP_GRACE: Duration = Duration::from_secs(10);

/// **Stop the daemon of data root `data`, if one still runs** — the safety net in `Drop` of the
/// harness's worlds, so no proof leaves a daemon behind however it ends.
///
/// The daemon is found by **the pid in `<data>/.daemon/lock`, never by pattern** (ADR-018 §6): a
/// path pattern matches nothing (a daemon's argv names no data root) or another proof's process.
/// **Only a lock that is held is believed**: a lock this process can take has no daemon behind
/// it, and the pid in it may since belong to an unrelated process, so nothing is signalled. A held
/// lock's pid is sent SIGTERM; it is released when the daemon's last descriptor closes — which a
/// zombie child has already done — so the wait is on the lock, not the pid. Past [`REAP_GRACE`] it
/// is sent SIGKILL. Silent when there is nothing to do; says what it stopped, since a daemon left
/// to this net is worth a line in the proof's output.
pub fn reap_daemon(data: &Path) {
    let path = daemon_lock(data);
    let Ok(file) = std::fs::File::open(&path) else {
        return;
    };
    if lock_is_free(&file) {
        return;
    }
    let Some(pid) = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| t.split_whitespace().next()?.parse::<i32>().ok())
        .and_then(rustix::process::Pid::from_raw)
    else {
        eprintln!(
            "[harness] {} is held but names no pid: cannot stop its daemon",
            path.display()
        );
        return;
    };
    eprintln!(
        "[harness] a daemon still holds {} (pid {}): sending it SIGTERM",
        path.display(),
        pid.as_raw_nonzero()
    );
    let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
    let t0 = Instant::now();
    while t0.elapsed() < REAP_GRACE {
        if lock_is_free(&file) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!(
        "[harness] pid {} did not stop within {REAP_GRACE:?} of SIGTERM: killing it",
        pid.as_raw_nonzero()
    );
    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
    let t1 = Instant::now();
    while t1.elapsed() < REAP_GRACE && !lock_is_free(&file) {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Whether no process holds `file`'s lock: taken and at once released if so. A lock that cannot
/// be asked about counts as free, so nothing is signalled on a guess.
fn lock_is_free(file: &std::fs::File) -> bool {
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            true
        }
        Err(std::fs::TryLockError::WouldBlock) => false,
        Err(std::fs::TryLockError::Error(_)) => true,
    }
}

/// Every file or directory named `name` anywhere under `root`, for a proof that asserts a file is
/// gone from a data root whichever layout would hold it.
pub fn find_named(root: &Path, name: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut todo = vec![root.to_path_buf()];
    while let Some(dir) = todo.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.filter_map(Result::ok) {
            let p = e.path();
            if e.file_name() == name {
                out.push(p.clone());
            }
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                todo.push(p);
            }
        }
    }
    out.sort();
    out
}

/// [`reap_daemon`] for each data root it names, when it drops: a field of a harness world that is
/// declared **first**, so it runs before the world's processes and temp dir go, and leaves the
/// other fields free to be moved out (a world with a `Drop` of its own could not be taken apart).
pub struct Reaper(pub Vec<PathBuf>);

impl Drop for Reaper {
    fn drop(&mut self) {
        for d in &self.0 {
            reap_daemon(d);
        }
    }
}

/// The pid of the daemon that holds data root `data`'s lock (the first token of
/// `<data>/.daemon/lock`), or `None` when no daemon holds it. Since ADR-026 a held verb is a
/// client: a proof that freezes or stops "the host" signals this pid, not the verb's own.
pub fn daemon_pid(data: &Path) -> Option<u32> {
    let path = daemon_lock(data);
    let file = std::fs::File::open(&path).ok()?;
    if lock_is_free(&file) {
        return None;
    }
    std::fs::read_to_string(&path)
        .ok()?
        .split_whitespace()
        .next()?
        .parse::<u32>()
        .ok()
        .filter(|p| *p > 0)
}

/// **Crash** the daemon of data root `data`: SIGKILL to the pid in its held lock, and wait until the
/// lock is free — a host machine losing power, where [`reap_daemon`] is a clean stop. Since
/// ADR-026 a held verb (`vox serve`, `vox connect`, …) is a client, and stopping it leaves its
/// node running in the daemon; a proof that means "the host went away" stops the daemon. Returns
/// the pid it killed, if a daemon held the lock.
pub fn kill_daemon(data: &Path) -> Option<i32> {
    let file = std::fs::File::open(daemon_lock(data)).ok()?;
    let pid = daemon_pid(data).and_then(|p| rustix::process::Pid::from_raw(p.cast_signed()))?;
    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
    let t0 = Instant::now();
    while t0.elapsed() < REAP_GRACE && !lock_is_free(&file) {
        std::thread::sleep(Duration::from_millis(20));
    }
    Some(pid.as_raw_nonzero().get())
}
