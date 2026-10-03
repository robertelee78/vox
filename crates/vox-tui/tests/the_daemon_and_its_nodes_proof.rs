//! ADR-026 §10 proofs 5–8, as far as the verbs allow today (#405): the account's one daemon, run as
//! a person and an agent's hook run it, every participant the shipped `vox` binary.
//!
//! 1. **Panic isolation (proof 5, L-6).** A daemon holding two nodes, one in the foreground and
//!    one attached by an agent's hook. A post through node `a` that hits the test-only panic
//!    marker kills `a`'s actor; the daemon says `a` detached because its actor panicked, and
//!    node `b` still answers.
//! 2. **Lifecycle races (proof 6, L-2, L-3).** Two hooks of two sessions of one node, with no
//!    daemon running, start at once: both succeed, one daemon starts, and the node attaches once.
//!    Then one session's `SessionEnd` races the other's next turn: the node is attached while a
//!    session is registered. The last `SessionEnd` detaches it, and the daemon the hooks started
//!    exits (L-8).
//! 3. **Keep (proof 7, L-4).** `vox daemon --keep` records its node; after the daemon stops, a
//!    daemon started in the background attaches it again with its room open.
//! 4. **Two clients, one daemon (proof 8, D-1, S-2).** Two `vox daemon --detach` at once end with
//!    one daemon: one process holds `.daemon/lock`, and it exits on its own once idle.
//!
//! Not yet here (the verbs are clients only from #406): a foreground `vox serve` exiting when the
//! daemon stops, and a request in flight answered "node detached" over the CLI.

#![allow(clippy::unwrap_used)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const PASS: &str = "identity passphrase";
const ROOM_PASS: &str = "room passphrase for the daemon proof";

/// One account: a data root and a config directory, short enough for a socket path.
struct Account {
    _tmp: tempfile::TempDir,
    data: PathBuf,
    cfg: PathBuf,
}

impl Account {
    fn new() -> Self {
        let tmp = tempfile::Builder::new()
            .prefix("vd")
            .tempdir_in("/private/tmp")
            .unwrap();
        let data = tmp.path().join("d");
        let cfg = tmp.path().join("c");
        std::fs::create_dir_all(&cfg).unwrap();
        Self {
            _tmp: tmp,
            data,
            cfg,
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(VOX);
        c.env_clear();
        for key in ["PATH", "HOME", "TMPDIR"] {
            if let Some(v) = std::env::var_os(key) {
                c.env(key, v);
            }
        }
        c.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env("VOX_LISTEN", "127.0.0.1:0")
            .env("VOX_IDENTITY_PASSPHRASE", PASS);
        c
    }

    /// Run `vox args` to its end with `stdin`.
    fn run(&self, args: &[&str], stdin: &str) -> (bool, String, String) {
        let mut child = self
            .cmd(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: spawn vox {args:?}: {e}"));
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        let out = child.wait_with_output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// Make node `name` with an identity, as a person does: `vox id --node <name>`.
    fn make_node(&self, name: &str) -> String {
        let (ok, out, err) = self.run(&["id", "--node", name], "");
        assert!(ok, "APPARATUS: vox id for {name}: {out}{err}");
        out.trim().to_owned()
    }

    /// An agent hook turn of `session`, as node `node`.
    fn hook(&self, node: &str, session: &str, event: &str) -> (bool, String, String) {
        let input = format!(r#"{{"hook_event_name":"{event}","session_id":"{session}"}}"#);
        self.run(&["agent", "hook", "--node", node], &input)
    }

    fn lock_pid(&self) -> Option<u32> {
        std::fs::read_to_string(self.data.join(".daemon/lock"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.data.join(".daemon/log")).unwrap_or_default()
    }
}

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// SIGTERM to `pid`, a process this proof started, then wait for it to go.
fn stop_pid(pid: u32) {
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    let t0 = Instant::now();
    while alive(pid) && t0.elapsed() < Duration::from_secs(15) {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Every `vox daemon` process serving `data`, by its command line.
fn daemons_of(data: &Path) -> Vec<u32> {
    let out = Command::new("ps")
        .args(["-axo", "pid=,command="])
        .output()
        .unwrap();
    let data = data.to_string_lossy().into_owned();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains(" daemon ") && l.contains(&data))
        .filter_map(|l| l.split_whitespace().next()?.parse().ok())
        .collect()
}

fn wait_until(within: Duration, mut f: impl FnMut() -> bool) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < within {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    f()
}

/// A foreground `vox daemon` of `node`, its output in a file.
struct Daemon {
    child: Child,
    out: PathBuf,
}

impl Daemon {
    fn start(a: &Account, args: &[&str], env: &[(&str, &str)]) -> Self {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let out = a.data.with_extension(format!("daemon-{n}.out"));
        let f = std::fs::File::create(&out).unwrap();
        let mut c = a.cmd(&[&["daemon"], args].concat());
        for (k, v) in env {
            c.env(k, v);
        }
        let child = c
            .stdin(Stdio::null())
            .stdout(f.try_clone().unwrap())
            .stderr(f)
            .spawn()
            .unwrap();
        eprintln!("[test] vox daemon {args:?} pid {}", child.id());
        Self { child, out }
    }

    fn said(&self) -> String {
        std::fs::read_to_string(&self.out).unwrap_or_default()
    }

    fn expect(&self, what: &str, within: Duration, f: impl Fn(&str) -> bool) {
        assert!(
            wait_until(within, || self.said().lines().any(&f)),
            "PRODUCT (staging): the daemon never said {what}:\n{}",
            self.said()
        );
    }

    fn stop(mut self) -> String {
        stop_pid(self.child.id());
        let _ = self.child.wait();
        self.said()
    }
}

/// A room on `node`, made through the daemon that holds it: its id.
fn make_room(a: &Account, node: &str) -> String {
    let (ok, out, err) = a.run(
        &[
            "room",
            "create",
            "--node",
            node,
            "--passphrase-file",
            "-",
            "--name",
            "r",
        ],
        ROOM_PASS,
    );
    assert!(ok, "APPARATUS: room create on {node}: {out}{err}");
    let (ok, list, err) = a.run(&["room", "list", "--node", node], "");
    assert!(ok, "APPARATUS: room list on {node}: {err}");
    list.lines()
        .find_map(|l| l.split_whitespace().next().map(str::to_owned))
        .unwrap_or_else(|| panic!("APPARATUS: no room listed on {node}: {list}"))
}

#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn one_nodes_panic_detaches_it_and_the_other_node_goes_on() {
    watchdog::arm();
    let a = Account::new();
    a.make_node("a");
    a.make_node("b");
    let pass = a.data.with_extension("pass");
    std::fs::write(&pass, format!("{PASS}\n")).unwrap();
    let d = Daemon::start(
        &a,
        &["--node", "a", "--passphrase-file", pass.to_str().unwrap()],
        &[("VOX_TEST_PANIC_ON_TEXT", "BOOM-MARKER")],
    );
    d.expect("its identity", Duration::from_secs(60), |l| {
        l.starts_with("vox daemon: identity")
    });
    let room = make_room(&a, "a");
    // Node b, attached by its agent's hook.
    let (ok, _, err) = a.hook("b", "s-b", "UserPromptSubmit");
    assert!(ok, "PRODUCT: b's hook failed: {err}");
    d.expect("node b attached", Duration::from_secs(30), |l| {
        l.starts_with("vox daemon: node b attached")
    });
    let (posted, _, _) = a.run(
        &[
            "room",
            "post",
            "--node",
            "a",
            &room,
            "this holds BOOM-MARKER",
        ],
        "",
    );
    eprintln!("[proof] the post that panics node a exited ok={posted}");
    d.expect(
        "that node a detached because its actor panicked",
        Duration::from_secs(20),
        |l| l.starts_with("vox daemon: node a detached (its actor panicked"),
    );
    let (b_ok, b_out, b_err) = a.run(&["room", "list", "--node", "b"], "");
    assert!(
        b_ok,
        "PRODUCT: node b stopped answering after node a's panic: {b_out}{b_err}\ndaemon:\n{}",
        d.said()
    );
    let (a_ok, _, _) = a.run(&["room", "list", "--node", "a"], "");
    assert!(
        !a_ok,
        "PRODUCT: node a still answers after its actor panicked"
    );
    let _ = a.hook("b", "s-b", "SessionEnd");
    let said = d.stop();
    eprintln!("[proof] the daemon said:\n{said}");
}

#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn two_hooks_start_one_daemon_attach_once_and_the_last_end_detaches() {
    watchdog::arm();
    let a = Account::new();
    a.make_node("agent");
    let (h1, h2) = std::thread::scope(|s| {
        let one = s.spawn(|| a.hook("agent", "s-1", "UserPromptSubmit"));
        let two = s.spawn(|| a.hook("agent", "s-2", "UserPromptSubmit"));
        (one.join().unwrap(), two.join().unwrap())
    });
    for (n, (ok, out, err)) in [(1, &h1), (2, &h2)] {
        assert!(
            *ok && !out.contains("could not read your rooms"),
            "PRODUCT: hook {n} did not get its node: {out}{err}\nlog:\n{}",
            a.log()
        );
    }
    let pid = a
        .lock_pid()
        .unwrap_or_else(|| panic!("PRODUCT: no daemon holds the lock\nlog:\n{}", a.log()));
    let daemons = daemons_of(&a.data);
    assert_eq!(
        daemons,
        vec![pid],
        "PRODUCT: two hooks with no daemon must end with exactly one daemon\nlog:\n{}",
        a.log()
    );
    let attaches = a
        .log()
        .lines()
        .filter(|l| l.starts_with("vox daemon: node agent attached"))
        .count();
    assert_eq!(
        attaches,
        1,
        "PRODUCT: two hooks at once must attach the node once\nlog:\n{}",
        a.log()
    );
    // A session's end racing the other's next turn, a few times: the node stays attached while
    // a session is registered.
    for round in 0..3 {
        let (end, next) = std::thread::scope(|s| {
            let end = s.spawn(|| a.hook("agent", "s-1", "SessionEnd"));
            let next = s.spawn(|| a.hook("agent", "s-2", "UserPromptSubmit"));
            (end.join().unwrap(), next.join().unwrap())
        });
        assert!(end.0 && next.0, "PRODUCT: round {round}: a hook failed");
        assert!(
            !next.1.contains("could not read your rooms"),
            "PRODUCT: round {round}: a turn racing another session's end lost its node: {}{}",
            next.1,
            next.2
        );
        let (ok, _, err) = a.run(&["room", "list", "--node", "agent"], "");
        assert!(
            ok,
            "PRODUCT: round {round}: the node is not attached with session s-2 registered: \
             {err}\nlog:\n{}",
            a.log()
        );
        let _ = a.hook("agent", "s-1", "UserPromptSubmit");
    }
    for s in ["s-1", "s-2"] {
        let _ = a.hook("agent", s, "SessionEnd");
    }
    assert!(
        wait_until(Duration::from_secs(10), || !alive(pid)),
        "PRODUCT: the daemon the hooks started did not exit once its last session ended\nlog:\n{}",
        a.log()
    );
    assert!(
        a.log()
            .lines()
            .any(|l| l.starts_with("vox daemon: node agent detached (its last holder went)")),
        "PRODUCT: the node's detach was not said\nlog:\n{}",
        a.log()
    );
}

#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn a_kept_node_and_its_room_come_back_after_a_restart() {
    watchdog::arm();
    let a = Account::new();
    a.make_node("default");
    let pass = a.data.with_extension("pass");
    std::fs::write(&pass, format!("{PASS}\n")).unwrap();
    let d = Daemon::start(&a, &["--passphrase-file", pass.to_str().unwrap()], &[]);
    d.expect("its identity", Duration::from_secs(60), |l| {
        l.starts_with("vox daemon: identity")
    });
    let room = make_room(&a, "default");
    d.stop();
    // Kept, with the room's passphrase in its file.
    std::fs::write(&pass, format!("{PASS}\n{ROOM_PASS}\n")).unwrap();
    let d = Daemon::start(
        &a,
        &["--keep", "--passphrase-file", pass.to_str().unwrap()],
        &[],
    );
    d.expect("the room held open", Duration::from_secs(60), |l| {
        l.starts_with("vox daemon: holding room")
    });
    let (ok, _, _) = a.run(&["room", "post", &room, "before the restart"], "");
    assert!(ok, "APPARATUS: post before the restart");
    d.stop();
    let (ok, out, err) = a.run(&["daemon", "--detach"], "");
    assert!(ok, "PRODUCT: vox daemon --detach failed: {out}{err}");
    let pid = a.lock_pid().expect("PRODUCT: no daemon holds the lock");
    let back = wait_until(Duration::from_secs(60), || {
        a.run(&["room", "read", &room], "")
            .1
            .contains("before the restart")
    });
    let log = a.log();
    stop_pid(pid);
    assert!(
        back,
        "PRODUCT: the kept node's room did not come back after the restart\nlog:\n{log}"
    );
    assert!(
        log.contains("vox daemon: attached kept node default"),
        "PRODUCT: the restart did not say it attached the kept node\nlog:\n{log}"
    );
}

#[test]
#[ignore = "real binaries; run in release"]
fn two_clients_with_no_daemon_end_with_one_and_it_exits_when_idle() {
    watchdog::arm();
    let a = Account::new();
    let (one, two) = std::thread::scope(|s| {
        let one = s.spawn(|| a.run(&["daemon", "--detach"], ""));
        let two = s.spawn(|| a.run(&["daemon", "--detach"], ""));
        (one.join().unwrap(), two.join().unwrap())
    });
    assert!(
        one.0 && two.0,
        "PRODUCT: a client's start failed: {one:?} {two:?}\nlog:\n{}",
        a.log()
    );
    let pid = a.lock_pid().expect("PRODUCT: no daemon holds the lock");
    let seen = daemons_of(&a.data);
    eprintln!("[proof] daemons serving the account: {seen:?}; lock holder {pid}");
    assert!(
        seen.iter().all(|p| *p == pid)
            || wait_until(Duration::from_secs(3), || daemons_of(&a.data) == vec![pid]),
        "PRODUCT: two clients with no daemon ended with more than one: {seen:?}\nlog:\n{}",
        a.log()
    );
    assert!(
        wait_until(Duration::from_secs(10), || !alive(pid)),
        "PRODUCT: the auto-started daemon with no node and no client did not exit\nlog:\n{}",
        a.log()
    );
}

/// ADR-026 D-2: a daemon runs with zero nodes. On an empty data root, `vox daemon` with stdin
/// closed and no passphrase anywhere starts, asks for nothing, and answers on the account socket.
#[test]
#[ignore = "real binaries; run in release"]
fn a_daemon_on_an_empty_root_starts_with_no_node() {
    watchdog::arm();
    let a = Account::new();
    let out = a.data.with_extension("empty.out");
    let f = std::fs::File::create(&out).unwrap();
    let mut child = a
        .cmd(&["daemon"])
        .env_remove("VOX_IDENTITY_PASSPHRASE")
        .stdin(Stdio::null())
        .stdout(f.try_clone().unwrap())
        .stderr(f)
        .spawn()
        .unwrap();
    let said = || std::fs::read_to_string(&out).unwrap_or_default();
    let up = wait_until(Duration::from_secs(20), || {
        said().contains("vox daemon: control socket")
    });
    let exited = child.try_wait().ok().flatten();
    assert!(
        up && exited.is_none(),
        "PRODUCT: on an empty data root `vox daemon` must start with no node (ADR-026 D-2); it \
         exited {exited:?} saying:\n{}",
        said()
    );
    // A client finds it answering on the account socket: `--detach` starts nothing when one
    // answers.
    let (ok, stdout, stderr) = a.run(&["daemon", "--detach"], "");
    assert!(
        ok && stdout.contains("already running"),
        "PRODUCT: the daemon with no node does not answer on the account socket: \
         {stdout}{stderr}\ndaemon:\n{}",
        said()
    );
    assert!(
        child.try_wait().ok().flatten().is_none(),
        "PRODUCT: the daemon with no node stopped on its own:\n{}",
        said()
    );
    stop_pid(child.id());
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "PRODUCT: the daemon with no node did not stop cleanly on SIGTERM ({status}):\n{}",
        said()
    );
}

/// ADR-026 L-3: a detach is done only when the node's keys are wiped and its directory let go.
/// A room seal still working (staged to take 12 s) holds the node's stop; the last session's
/// `SessionEnd`, which detaches the node, answers only after the seal ends, never at the daemon's
/// 5 s stop patience, and the daemon answers other clients meanwhile.
#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn a_detach_answers_only_after_the_seal_in_flight_ends() {
    const SEAL_MS: u64 = 12_000;
    watchdog::arm();
    let a = Account::new();
    a.make_node("agent");
    let knob = ("VOX_TEST_SECRET_WORK_DELAY_MS", SEAL_MS.to_string());
    let run = |args: &[&str], stdin: &str| {
        let mut child = a
            .cmd(args)
            .env(knob.0, &knob.1)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        let out = child.wait_with_output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let hook = |event: &str| {
        run(
            &["agent", "hook", "--node", "agent"],
            &format!(r#"{{"hook_event_name":"{event}","session_id":"s-1"}}"#),
        )
    };
    // The session attaches the node (its unlock is held by the knob too).
    let (ok, out, err) = hook("UserPromptSubmit");
    assert!(
        ok && !out.contains("could not read your rooms"),
        "PRODUCT (staging): the hook did not attach its node: {out}{err}\nlog:\n{}",
        a.log()
    );
    let pid = a
        .lock_pid()
        .expect("PRODUCT (staging): no daemon holds the lock");
    std::thread::scope(|s| {
        let seal = s.spawn(|| {
            let r = run(
                &[
                    "room",
                    "create",
                    "--profile",
                    "agent",
                    "--passphrase-file",
                    "-",
                    "--name",
                    "r",
                ],
                ROOM_PASS,
            );
            (r, Instant::now())
        });
        // The seal has started.
        std::thread::sleep(Duration::from_secs(1));
        let t0 = Instant::now();
        let probe = s.spawn(|| {
            std::thread::sleep(Duration::from_millis(500));
            let t = Instant::now();
            let r = a.run(&["daemon", "--detach"], "");
            (r, t.elapsed())
        });
        let end = hook("SessionEnd");
        let ended_at = Instant::now();
        let took = t0.elapsed();
        let ((created, made_at), (probe_r, probe_took)) =
            (seal.join().unwrap(), probe.join().unwrap());
        eprintln!(
            "[proof] SessionEnd (the detach) answered after {:.2} s; the seal's room create ok={}; \
             a client probe answered in {:.3} s; the create said {:?}",
            took.as_secs_f64(),
            created.0,
            probe_took.as_secs_f64(),
            created.2.trim()
        );
        assert!(
            end.0,
            "PRODUCT (staging): the SessionEnd hook failed: {end:?}"
        );
        assert!(
            took >= Duration::from_millis(SEAL_MS - 3_000) && made_at <= ended_at,
            "PRODUCT: the detach answered after {:.2} s, before the {} s seal in flight ended \
             (room create ok={}), so the room's passphrase could still be in the daemon's memory \
             (ADR-026 L-3)\nlog:\n{}",
            took.as_secs_f64(),
            SEAL_MS / 1000,
            created.0,
            a.log()
        );
        assert!(
            probe_r.0
                && probe_r.1.contains("already running")
                && probe_took < Duration::from_secs(3),
            "PRODUCT: while a node detached, the daemon stopped answering other clients: \
             {probe_r:?} after {probe_took:?}"
        );
    });
    assert!(
        a.log()
            .lines()
            .any(|l| l.starts_with("vox daemon: node agent detached (its last holder went)")),
        "PRODUCT: the detach was not said\nlog:\n{}",
        a.log()
    );
    // Idle now: the daemon the hook started leaves.
    assert!(
        wait_until(Duration::from_secs(10), || !alive(pid)),
        "PRODUCT: the daemon did not leave once idle\nlog:\n{}",
        a.log()
    );
}
