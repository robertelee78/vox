//! **V210-28 — a gate the watchdog aborts leaves nothing running**, with the shipped `vox`
//! binary.
//!
//! The test watchdog (`vox-core/tests/support/watchdog.rs`) ends a hung gate with `abort`,
//! which runs no destructors — so every `vox node` and `vox daemon` the gate had started kept
//! running, reparented to init. The watchdog now kills every descendant of the test process
//! before it aborts.
//!
//! What this drives: this binary runs its own hidden `inner` test as a child process, with a
//! 3 s watchdog. The inner test starts a real `vox node` as its child, and a second one as a
//! grandchild (under `sh`, so the kill has to recurse), writes both pids, and hangs. After the
//! watchdog has aborted it, both pids must be gone.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// Set by the outer test: the directory the inner one works in.
const INNER: &str = "VOX_WATCHDOG_PROOF_INNER";

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The hung gate. Does nothing unless the outer test started it; it proves nothing alone.
#[test]
#[ignore = "helper: only meaningful as a_watchdog_abort_leaves_nothing_running's child"]
fn inner_a_hung_gate_with_children() {
    let Ok(dir) = std::env::var(INNER) else {
        return; // only ever meaningful as the outer test's child
    };
    let dir = std::path::PathBuf::from(dir);
    watchdog::arm();
    let child = Command::new(VOX)
        .args(["node", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir.join("child"))
        .env("VOX_CONFIG_DIR", dir.join("child-cfg"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vox node");
    // A grandchild: `sh` starts a node in the background and waits on it.
    let sh = Command::new("sh")
        .args([
            "-c",
            "\"$VOX\" node --listen 127.0.0.1:0 >/dev/null 2>&1 & echo $! > \"$D/grandchild.pid\"; wait",
        ])
        .env("VOX", VOX)
        .env("D", &dir)
        .env("VOX_DATA_DIR", dir.join("grand"))
        .env("VOX_CONFIG_DIR", dir.join("grand-cfg"))
        .spawn()
        .expect("spawn sh");
    std::fs::write(dir.join("child.pid"), child.id().to_string()).unwrap();
    std::fs::write(dir.join("sh.pid"), sh.id().to_string()).unwrap();
    std::fs::write(dir.join("ready"), "").unwrap();
    // Hung: the watchdog is the only way out. The handles are kept alive on purpose.
    let _keep = (child, sh);
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[test]
#[ignore = "runs a real vox node under an aborted child test; CI runs it in release"]
fn a_watchdog_abort_leaves_nothing_running() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let started = Instant::now();
    // The inner test's output goes to files, never pipes: a process it leaked would hold a
    // pipe open, and waiting for its end would hang this test instead of failing it.
    let log = dir.join("inner.stderr");
    let mut inner = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "inner_a_hung_gate_with_children",
            "--ignored",
            "--nocapture",
        ])
        .env(INNER, dir)
        .env("VOX_TEST_WATCHDOG_SECS", "3")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .expect("run the inner test");
    let status = loop {
        if let Some(s) = inner.try_wait().unwrap() {
            break s;
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = inner.kill();
            panic!("the inner test was never ended by its 3 s watchdog");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let said = std::fs::read_to_string(&log).unwrap_or_default();
    eprintln!(
        "[proof] inner test ended after {:?}: {status:?}",
        started.elapsed()
    );
    assert!(
        dir.join("ready").exists(),
        "CANNOT MEASURE: the inner test never started its children: {said}"
    );
    assert!(
        status.code().is_none(),
        "the inner test must end by the watchdog's abort, not exit: {status:?}\n{said}"
    );
    let read = |name: &str| -> u32 {
        std::fs::read_to_string(dir.join(name))
            .unwrap_or_else(|e| panic!("{name}: {e}"))
            .trim()
            .parse()
            .unwrap()
    };
    let pids = [
        ("vox node (child)", read("child.pid")),
        ("sh (child)", read("sh.pid")),
        ("vox node (grandchild)", read("grandchild.pid")),
    ];
    // Killing is asynchronous: give the kernel a moment to reap.
    let deadline = Instant::now() + Duration::from_secs(5);
    while pids.iter().any(|(_, p)| alive(*p)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let left: Vec<_> = pids.iter().filter(|(_, p)| alive(*p)).collect();
    eprintln!("[proof] still running after the abort: {left:?}");
    // Never leave them behind ourselves, whatever the verdict.
    for (_, p) in &left {
        let _ = Command::new("kill")
            .args(["-KILL", &p.to_string()])
            .status();
    }
    assert!(
        left.is_empty(),
        "an aborted gate left processes running: {left:?}\ninner said:\n{said}"
    );
    assert!(
        said.contains("killed") && said.contains("descendant"),
        "the watchdog must say what it killed: {said}"
    );
}
