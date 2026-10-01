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
//!
//! **V210-36 (#213) — and the dump shows the child, not only the test.** A real-binary proof's
//! test process only waits; the stuck process is a `vox` it started. So the child `vox node` is
//! stopped (SIGSTOP) to stand in for a hung daemon, and the watchdog's output must hold that
//! pid's own thread stacks, under a header naming its pid and command line, **before** it says
//! what it killed. Mutation: kill the descendants before dumping them, and the child's section
//! holds no stacks — red.
//!
//! **V210-99 (#295) — and a process started while the watchdog dumps is killed too.** The test's
//! threads are not stopped while the watchdog dumps, so a proof still in its setup goes on
//! starting `vox` processes for minutes. A `vox daemon` outlived an abort whose watchdog said it
//! had killed 4: the kill used the list taken before the dumps. So the inner test starts one more
//! `vox node` once the watchdog is dumping its descendants — after that list was taken — and it
//! must be gone too, with the watchdog saying `0 remain`. And one `vox node` is started under a
//! `sh` that exits at once, so it is reparented to init (launchd) **before** the abort and is no
//! longer anyone's descendant — the way a process leaves the parent-pid tree. After the abort,
//! every listed pid must be gone, and a count of the inner test's process group's orphans (`ps`, as
//! `pgrep -g` would) must be 0. Mutation: the old kill (the parent-pid tree, as listed before the dumps)
//! — the late node and the reparented one outlive the abort — red.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// Set by the outer test: the directory the inner one works in.
const INNER: &str = "VOX_WATCHDOG_PROOF_INNER";

/// Every live process reparented to init in process group `group` — the inner test's own group,
/// which it leads: what an aborted inner test left behind, counted as `pgrep -g <group>` would,
/// not by the pids it wrote down.
fn group_orphans(group: u32) -> Vec<u32> {
    let out = Command::new("ps")
        .args(["-A", "-o", "pid=,ppid=,pgid=,stat="])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let pid: u32 = it.next()?.parse().ok()?;
            let ppid: u32 = it.next()?.parse().ok()?;
            let pgid: u32 = it.next()?.parse().ok()?;
            let zombie = it.next()?.starts_with('Z');
            (pgid == group && ppid == 1 && !zombie).then_some(pid)
        })
        .collect()
}

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
    // A setup that goes on: once the watchdog is dumping its descendants, start one more node,
    // as a proof's setup does while the watchdog's dumps run.
    let (vox, late_dir) = (VOX, dir.clone());
    std::thread::spawn(move || {
        let said = late_dir.join("inner.stderr");
        while !std::fs::read_to_string(&said)
            .unwrap_or_default()
            .contains("vox test watchdog: descendant ")
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        let late = Command::new(vox)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", late_dir.join("late"))
            .env("VOX_CONFIG_DIR", late_dir.join("late-cfg"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the late vox node");
        std::fs::write(late_dir.join("late.pid"), late.id().to_string()).unwrap();
        // Kept, like the others: only the watchdog may end it.
        std::mem::forget(late);
    });
    // Reparented before the abort: `sh` starts a node in the background and exits at once.
    let ok = Command::new("sh")
        .args([
            "-c",
            "\"$VOX\" node --listen 127.0.0.1:0 >/dev/null 2>&1 & echo $! > \"$D/orphan.pid\"",
        ])
        .env("VOX", VOX)
        .env("D", &dir)
        .env("VOX_DATA_DIR", dir.join("orphan"))
        .env("VOX_CONFIG_DIR", dir.join("orphan-cfg"))
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "could not start the reparented node");
    // The stand-in for a hung daemon: let it get past start-up, then stop it where it is.
    std::thread::sleep(Duration::from_secs(1));
    let stopped = Command::new("kill")
        .args(["-STOP", &child.id().to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(stopped, "could not stop the child vox node");
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
        // Its own process group, so what it leaves behind is counted by group, apart from every
        // other process this test's own group holds.
        .process_group(0)
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
    assert!(
        dir.join("late.pid").exists(),
        "CANNOT MEASURE: the inner test never started its late node while the watchdog dumped: {said}"
    );
    let pids = [
        ("vox node (child)", read("child.pid")),
        ("sh (child)", read("sh.pid")),
        ("vox node (grandchild)", read("grandchild.pid")),
        (
            "vox node (started while the watchdog dumped)",
            read("late.pid"),
        ),
        (
            "vox node (reparented to init before the abort)",
            read("orphan.pid"),
        ),
    ];
    // Killing is asynchronous: give the kernel a moment to reap.
    let deadline = Instant::now() + Duration::from_secs(5);
    while pids.iter().any(|(_, p)| alive(*p)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let left: Vec<_> = pids.iter().filter(|(_, p)| alive(*p)).collect();
    let orphans = group_orphans(inner.id());
    eprintln!(
        "[proof] {} of {} listed processes still running after the abort: {left:?}; orphans of \
         its process group: {} {orphans:?}",
        left.len(),
        pids.len(),
        orphans.len()
    );
    for p in &orphans {
        let _ = Command::new("kill")
            .args(["-KILL", &p.to_string()])
            .status();
    }
    // Never leave them behind ourselves, whatever the verdict.
    for (_, p) in &left {
        let _ = Command::new("kill")
            .args(["-KILL", &p.to_string()])
            .status();
    }
    assert!(
        left.is_empty() && orphans.is_empty(),
        "an aborted gate left processes running: {left:?}, and orphans of its group {orphans:?}\n\
         inner said:\n{said}"
    );
    assert!(
        said.contains("killed") && said.contains("descendant"),
        "the watchdog must say what it killed: {said}"
    );
    assert!(
        said.contains("0 remain"),
        "the watchdog must say it looked again and found none left: {said}"
    );

    // ---- V210-36: the hung child's own stacks are in the dump, before the kill ----
    let child = pids[0].1;
    let header = format!("vox test watchdog: descendant {child}: ");
    let at = said.find(&header).unwrap_or_else(|| {
        panic!("the dump never names the hung child (pid {child}) — only the test process was dumped:\n{said}")
    });
    let line_end = said[at..].find('\n').map_or(said.len(), |n| at + n);
    assert!(
        said[at..line_end].contains("vox") && said[at..line_end].contains("node"),
        "the child's header must carry its command line: {:?}",
        &said[at..line_end]
    );
    // Its section runs to the next header, or to the end of the dump.
    let section_end = said[line_end..]
        .find("====================")
        .map_or(said.len(), |n| line_end + n);
    let section = &said[line_end..section_end];
    // The platform's evidence of stacks for THAT pid: `sample`'s call graph on macOS, the
    // per-thread census on Linux.
    let stacks = if cfg!(target_os = "macos") {
        "Call graph:"
    } else {
        "threads (tid"
    };
    assert!(
        section.contains(stacks),
        "the hung child's section holds no thread stacks ({stacks:?} missing) — dumped after it \
         was killed, or not at all:\n{section}"
    );
    let killed_at = said.find("killed ").expect("the kill line");
    assert!(
        at < killed_at,
        "the child must be dumped before the descendants are killed"
    );
    eprintln!(
        "[proof] the hung child {child} was dumped before the kill ({} bytes of stacks)",
        section.len()
    );
}
