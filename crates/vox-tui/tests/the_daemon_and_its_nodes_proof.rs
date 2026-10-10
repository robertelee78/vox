//! ADR-026 §10 proofs 5–8, as far as the verbs allow today (#405): the account's one daemon, run as
//! a person and an agent's hook run it, every participant the shipped `vox` binary.
//!
//! 1. **Panic isolation (proof 5, L-6).** A daemon holding two nodes, one in the foreground and
//!    one attached by its operator (`vox node attach`), with an agent's session on it. A post through node `a` that hits the test-only panic
//!    marker kills `a`'s actor; the daemon says `a` detached because its actor panicked, and
//!    node `b` still answers.
//! 2. **Lifecycle races (proof 6, L-3; ADR-028 K-13).** Two hooks of two sessions of one detached
//!    node, with no daemon running, start at once: both exit 0, telling the agent the node is not
//!    attached and the command for the operator, `vox node attach agent`; a session's next turn
//!    says nothing more, and the person is notified once per session; a hook naming a node not
//!    on this Mac says so with `vox setup` and makes no `nodes/<it>` directory (#666; mutants:
//!    the node-on-disk check skipped, red at that line; the hook resolving its paths by making
//!    them, red at the directory; the
//!    once-per-session record ignored, red as PRODUCT at the second turn); one daemon starts, and
//!    the node stays detached (a hook never attaches it). The operator attaches it; then one
//!    session's `SessionEnd` races the other's next turn, and the node stays attached throughout;
//!    the last `SessionEnd` leaves it attached too, since the operator attached it. Detached by
//!    hand, the daemon the hooks started exits (L-8).
//! 3. **Keep (proof 7, L-4).** `vox daemon --keep` records its node; after the daemon stops, a
//!    daemon started in the background attaches it again with its room open.
//!    **Sign out (ADR-028 E-4).** `vox node signout` then detaches it and forgets what would bring
//!    it back without the person: its `.daemon/attach` line and the app's remembered node; a
//!    daemon started again leaves it detached, and attached by hand its room still holds what was
//!    posted. Mutations: a signout that does not detach turns it red at "detached and not kept"; one
//!    that leaves the app's choice turns it red at "must be forgotten".
//! 4. **Two clients, one daemon (proof 8, D-1, S-2).** Two `vox daemon --detach` at once end with
//!    one daemon: one process holds `.daemon/lock`. With no client, it is still there 3 s after it
//!    serves (the 10 s start grace, L-8) and answers `vox node list`, and it exits on its own once
//!    idle after the grace. Mutation: no grace turns it red at the 3 s check.
//!
//! 5. **Root is told at once (C-1).** The daemon admits no uid 0, so a person running vox as root
//!    (a container's default user) must be told that, at once, with what to do — not left to
//!    wait out the 15 s start bound and read "the daemon did not start within 15 s" of a daemon
//!    that was running. As root (uid 0 in a Linux user namespace, `unshare --user
//!    --map-root-user`: no sudo), `vox serve` and `vox daemon` each end within 10 s saying vox is
//!    running as root and to run it as an ordinary user. Linux only: elsewhere root needs sudo,
//!    which no proof uses, and the case is CANNOT MEASURE. Mutation: the root checks taken out of
//!    the client and the daemon turns it red with the old wait and its message.
//!
//! 6. **The login item's daemon waits its turn (ADR-014 M-9).** `vox daemon --no-node`, what
//!    Vox.app's launch agent runs, started while a daemon a client started is running, is still
//!    there 3 s later, and once that daemon stops it holds `.daemon/lock` and answers `vox node
//!    list`. launchd restarts the agent only after a crash, so one that exited 0 left Vox.app,
//!    waiting for the login item's daemon, with none. Mutation: `--no-node` exits 0 when a daemon
//!    is running, as before, turns it red at the 3 s check.
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
            // Short, for the socket path: macOS's /private/tmp, else /tmp (Linux).
            .tempdir_in(if Path::new("/private/tmp").is_dir() {
                "/private/tmp"
            } else {
                "/tmp"
            })
            .unwrap();
        let data = tmp.path().join("d");
        let cfg = tmp.path().join("c");
        std::fs::create_dir_all(&cfg).unwrap();
        // Notifications go to a file of this test's, never to the desktop (`VOX_NOTIFY_COMMAND`).
        let notify = tmp.path().join("notify");
        std::fs::write(
            &notify,
            format!(
                "#!/bin/sh\nprintf '%s | %s\\n' \"$1\" \"$2\" >> {}\n",
                tmp.path().join("notified").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(
            &notify,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        )
        .unwrap();
        Self {
            _tmp: tmp,
            data,
            cfg,
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(VOX);
        c.env_clear()
            // A proof's daemon never takes port 1080 (.cargo/config.toml).
            .env("VOX_PROXY", "127.0.0.1:0");
        for key in ["PATH", "HOME", "TMPDIR"] {
            if let Some(v) = std::env::var_os(key) {
                c.env(key, v);
            }
        }
        c.args(args)
            .env("VOX_NOTIFY_COMMAND", self._tmp.path().join("notify"))
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

    /// The notifications raised so far, one `title | body` a line.
    fn notified(&self) -> String {
        std::fs::read_to_string(self._tmp.path().join("notified")).unwrap_or_default()
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
    // Node b, attached by its operator (a hook never attaches it, ADR-028 K-13), with its agent's
    // session on it.
    let (ok, out, err) = a.run(
        &[
            "node",
            "attach",
            "b",
            "--passphrase-file",
            pass.to_str().unwrap(),
        ],
        "",
    );
    assert!(
        ok,
        "PRODUCT (staging): vox node attach b failed: {out}{err}"
    );
    d.expect("node b attached", Duration::from_secs(30), |l| {
        l.starts_with("vox daemon: node b attached")
    });
    let (ok, _, err) = a.hook("b", "s-b", "UserPromptSubmit");
    assert!(ok, "PRODUCT: b's hook failed: {err}");
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
fn two_hooks_start_one_daemon_and_never_attach_its_node() {
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
            *ok && out.contains("node agent is not attached")
                && out.contains("vox node attach agent"),
            "PRODUCT: hook {n} must exit 0 telling the agent its node is not attached and the \
             command for the operator (ADR-028 K-13): {out}{err}\nlog:\n{}",
            a.log()
        );
    }
    // **A hook naming a node that is not here says so, with `vox setup`** (#666), in one sentence.
    let (ok, out, err) = a.hook("ghost", "s-9", "UserPromptSubmit");
    assert!(
        ok && out.contains(
            "Claude Code has no Vox node on this Mac (its hook names node ghost, which is not \
             here); ask the operator to run `vox setup` in a terminal."
        ),
        "PRODUCT: a hook naming a node not on this Mac must say, in one sentence, that Claude \
         Code has no Vox node here and to run `vox setup`: {out}{err}"
    );
    // ...and makes nothing: only making a node makes its directory.
    let ghost = a.data.join("nodes").join("ghost");
    assert!(
        !ghost.exists(),
        "PRODUCT: a hook naming a node not on this Mac must create nothing, but {} exists",
        ghost.display()
    );
    // **Said once per session, not every turn** (#666): session 1's next turn tells the agent
    // nothing more, and the person was told once per session, with the command.
    let (ok, out, err) = a.hook("agent", "s-1", "UserPromptSubmit");
    assert!(
        ok && !out.contains("not attached") && !out.contains("could not read your rooms"),
        "PRODUCT: a session's second turn must not say again that its node is not attached \
         (once per session): {out}{err}"
    );
    let notified = a.notified();
    assert!(
        notified
            .lines()
            .filter(|l| l.contains("node agent needs its passphrase")
                && l.contains("vox node attach agent"))
            .count()
            == 2,
        "PRODUCT: the person must be notified once per session (two sessions, three turns) that \
         node agent needs its passphrase, with the command; notified:\n{notified}"
    );
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
    assert!(
        !a.log()
            .lines()
            .any(|l| l.starts_with("vox daemon: node agent attached")),
        "PRODUCT: a hook attached its node (ADR-028 K-13)\nlog:\n{}",
        a.log()
    );
    // The operator attaches it, outside the sessions.
    let (ok, out, err) = a.run(&["node", "attach", "agent"], "");
    assert!(
        ok,
        "PRODUCT (staging): vox node attach agent failed: {out}{err}"
    );
    // A session's end racing the other's next turn, a few times: the node stays attached.
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
    let (ok, _, err) = a.run(&["room", "list", "--node", "agent"], "");
    assert!(
        ok,
        "PRODUCT: the node its operator attached detached when its last session ended: \
         {err}\nlog:\n{}",
        a.log()
    );
    let (ok, out, err) = a.run(&["node", "detach", "agent"], "");
    assert!(
        ok,
        "PRODUCT (staging): vox node detach agent failed: {out}{err}"
    );
    assert!(
        wait_until(Duration::from_secs(15), || !alive(pid)),
        "PRODUCT: the daemon the hooks started did not exit once its node was detached\nlog:\n{}",
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
    assert!(
        back,
        "PRODUCT: the kept node's room did not come back after the restart\nlog:\n{log}"
    );
    assert!(
        log.contains("vox daemon: attached kept node default"),
        "PRODUCT: the restart did not say it attached the kept node\nlog:\n{log}"
    );

    // **Sign out (ADR-028 E-4).** The app remembers the node it opens; `vox node signout` detaches
    // the node and forgets all that would bring it back without the person: its keep line and the
    // app's choice. Its rooms and messages stay.
    let chosen = a.cfg.join("app").join("node");
    std::fs::create_dir_all(chosen.parent().unwrap()).unwrap();
    std::fs::write(&chosen, "default\n").unwrap();
    let (ok, out, err) = a.run(&["node", "signout", "default"], "");
    assert!(ok, "PRODUCT: vox node signout default failed: {out}{err}");
    let attach = std::fs::read_to_string(a.data.join(".daemon/attach")).unwrap_or_default();
    let (_, listed, _) = a.run(&["node", "list"], "");
    let line = listed
        .lines()
        .find(|l| l.starts_with("default "))
        .unwrap_or("")
        .to_owned();
    assert!(
        !attach
            .lines()
            .any(|l| l.split_whitespace().next() == Some("default")),
        "PRODUCT: signed out, node default must no longer be kept; .daemon/attach still has it:\n\
         {attach}"
    );
    assert!(
        !line.contains(" attached") && !line.contains("(kept)"),
        "PRODUCT: signed out, `vox node list` must say default is detached and not kept: {line:?}"
    );
    assert!(
        !chosen.exists(),
        "PRODUCT: signed out, the app's remembered node ({}) must be forgotten",
        chosen.display()
    );
    stop_pid(pid);
    // Nothing brings it back: a daemon started again does not attach it.
    let (ok, out, err) = a.run(&["daemon", "--detach"], "");
    assert!(
        ok,
        "PRODUCT: vox daemon --detach failed after signout: {out}{err}"
    );
    let pid = a
        .lock_pid()
        .expect("PRODUCT: no daemon holds the lock after signout");
    std::thread::sleep(Duration::from_secs(3));
    let (_, listed, _) = a.run(&["node", "list"], "");
    let again = listed
        .lines()
        .find(|l| l.starts_with("default "))
        .unwrap_or("")
        .to_owned();
    // Still on disk: attached by hand, its room has what was posted before.
    let pass_arg = pass.to_str().unwrap().to_owned();
    std::fs::write(&pass, format!("{PASS}\n")).unwrap();
    let (ok, out, err) = a.run(
        &["node", "attach", "default", "--passphrase-file", &pass_arg],
        "",
    );
    let kept_room = ok
        && wait_until(Duration::from_secs(60), || {
            a.run(&["room", "read", &room], "")
                .1
                .contains("before the restart")
        });
    let log = a.log();
    stop_pid(pid);
    assert!(
        !again.contains(" attached"),
        "PRODUCT: signed out, node default must not be attached again by a daemon's start: \
         {again:?}\nlog:\n{log}"
    );
    assert!(
        kept_room,
        "PRODUCT: signed out, node default's rooms and messages must stay: attached again by hand \
         ({ok}: {out}{err}) its room must still read \"before the restart\"\nlog:\n{log}"
    );
}

#[test]
#[ignore = "real binaries; run in release"]
fn two_clients_with_no_daemon_end_with_one_and_it_exits_when_idle() {
    watchdog::arm();
    let a = Account::new();
    // **Both clients start a daemon, and one start loses** (D-1): each daemon holds the lock 1.5 s
    // before it serves (a test knob), so both clients find no socket and start one, and the
    // loser's daemon exits saying another is running while the winner serves nothing yet. The
    // losing client must wait for the winner's socket (S-2), not report a failed start. Unstaged,
    // the winner bound its socket before the loser looked, and a client that gave up passed.
    let start = || {
        let out = a
            .cmd(&["daemon", "--detach"])
            .env("VOX_TEST_DAEMON_SERVE_DELAY_MS", "1500")
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: spawn vox daemon --detach: {e}"));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let barrier = std::sync::Barrier::new(2);
    let (one, two) = std::thread::scope(|s| {
        let one = s.spawn(|| {
            barrier.wait();
            start()
        });
        let two = s.spawn(|| {
            barrier.wait();
            start()
        });
        (one.join().unwrap(), two.join().unwrap())
    });
    // Both clients have returned, so the winner serves from about now.
    let served = Instant::now();
    assert!(
        one.0 && two.0,
        "PRODUCT: two clients started a daemon together and one start lost the lock; that client \
         must wait for the winner's socket (ADR-026 S-2), not fail: {one:?} {two:?}\nlog:\n{}",
        a.log()
    );
    assert!(
        a.log().contains("a daemon is already running"),
        "CANNOT MEASURE: no daemon start lost the race (both clients found a socket, or only one \
         started a daemon), so a losing client's wait was not exercised: {one:?} {two:?}\nlog:\n{}",
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
    // **The start grace** (L-8): the daemon takes no idle exit within 10 s of serving, so a client
    // slow to connect on a loaded machine still finds the daemon it started. At 3 s, past the 1 s
    // linger and inside the grace, with no client ever connected, it is still there and answers.
    let at = Duration::from_secs(3);
    assert!(
        served.elapsed() < at,
        "APPARATUS: the staging took {:?}, past the 3 s mark it measures at",
        served.elapsed()
    );
    std::thread::sleep(at - served.elapsed());
    assert!(
        alive(pid),
        "PRODUCT: the auto-started daemon exited idle within 3 s of serving, inside its 10 s start \
         grace (ADR-026 L-8), so a client slow to connect would not find it\nlog:\n{}",
        a.log()
    );
    let (ok, out, err) = a.run(&["node", "list"], "");
    assert!(
        ok && a.lock_pid() == Some(pid),
        "PRODUCT: `vox node list` 3 s after the start was not answered by the daemon the clients \
         started ({pid}; the lock now names {:?}): {out}{err}\nlog:\n{}",
        a.lock_pid(),
        a.log()
    );
    // Once the grace has passed with no node and no client, it exits as before.
    assert!(
        wait_until(
            Duration::from_secs(20).saturating_sub(served.elapsed()),
            || !alive(pid)
        ),
        "PRODUCT: the auto-started daemon with no node and no client did not exit within 20 s of \
         serving\nlog:\n{}",
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

/// ADR-014 M-9: the login item's daemon, started while another daemon serves the account, waits
/// for it and then serves (proof 6 in this file's list).
#[test]
#[ignore = "real binaries; run in release"]
fn the_login_items_daemon_waits_for_the_running_one_and_then_serves() {
    watchdog::arm();
    let a = Account::new();
    let (ok, out, err) = a.run(&["daemon", "--detach"], "");
    assert!(ok, "APPARATUS: vox daemon --detach: {out}{err}");
    let first = a
        .lock_pid()
        .unwrap_or_else(|| panic!("APPARATUS: no daemon holds the lock after --detach: {out}"));
    let mut managed = Daemon::start(&a, &["--no-node"], &[]);
    managed.expect(
        "that a daemon is already running",
        Duration::from_secs(20),
        |l| l.contains("a daemon is already running"),
    );
    let pid = managed.child.id();
    std::thread::sleep(Duration::from_secs(3));
    if let Some(status) = managed.child.try_wait().unwrap() {
        stop_pid(first);
        panic!(
            "PRODUCT: `vox daemon --no-node`, the login item's daemon, exited ({status}) while \
             another daemon ran; launchd restarts it only after a crash, so Vox.app finds no \
             daemon once the running one stops. It said:\n{}",
            managed.said()
        );
    }
    // The running daemon stops, as one a client started does once nothing uses it.
    stop_pid(first);
    assert!(
        !alive(first),
        "APPARATUS: the first daemon ({first}) did not stop on SIGTERM within 15 s"
    );
    let took = wait_until(Duration::from_secs(20), || a.lock_pid() == Some(pid));
    let (answered, list, list_err) = a.run(&["node", "list"], "");
    let lock = a.lock_pid();
    let said = managed.stop();
    assert!(
        took && answered && lock == Some(pid),
        "PRODUCT: once the running daemon stopped, the login item's daemon ({pid}) did not serve \
         the account within 20 s (the lock names {lock:?}; `vox node list` answered {answered}: \
         {list}{list_err}). It said:\n{said}"
    );
}

/// ADR-026 D-1: **a daemon started while another stops takes over once it has.** Daemon A serves
/// node `agent` and is stopped; its stop is held open (staged to take 6 s). `vox daemon --node
/// agent` started meanwhile is told no "the daemon is stopping" and does not give up: it says it
/// serves once A has stopped, and then it holds the account lock and serves the node. Mutant: give
/// up on a stopping daemon, as before (red: B exits and nothing holds the lock).
#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn a_daemon_started_while_another_stops_takes_over() {
    const HOLD_MS: u64 = 6_000;
    watchdog::arm();
    let a = Account::new();
    a.make_node("agent");
    let mut first = a
        .cmd(&["daemon", "--node", "agent"])
        .env("VOX_TEST_STOP_HOLD_MS", HOLD_MS.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("APPARATUS: spawn the first vox daemon");
    let up = wait_until(Duration::from_secs(60), || {
        a.run(&["node", "list"], "").1.contains("agent") && a.lock_pid() == Some(first.id())
    });
    assert!(
        up,
        "PRODUCT (staging): the first daemon did not serve node agent within 60 s\nlog:\n{}",
        a.log()
    );
    // A is asked to stop (SIGTERM, by its PID), and stays stopping for HOLD_MS.
    let _ = Command::new("kill")
        .args(["-TERM", &first.id().to_string()])
        .status();
    std::thread::sleep(Duration::from_millis(500));
    let (still, said) = (alive(first.id()), a.run(&["node", "list"], ""));
    assert!(
        still,
        "APPARATUS (staging not achieved): the first daemon was gone before the second started, so \
         nothing was stopping: {said:?}"
    );
    let second_err = a._tmp.path().join("second.err");
    let mut second = a
        .cmd(&["daemon", "--node", "agent"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&second_err).unwrap()))
        .spawn()
        .expect("APPARATUS: spawn the second vox daemon");
    let took_over = wait_until(Duration::from_secs(60), || {
        a.lock_pid() == Some(second.id()) && a.run(&["node", "list"], "").1.contains("agent")
    });
    let _ = first.wait();
    let gone = second.try_wait().ok().flatten();
    let told = std::fs::read_to_string(&second_err).unwrap_or_default();
    eprintln!(
        "[proof] the second daemon took over: {took_over}; exited: {gone:?}; it said:\n{told}"
    );
    let _ = second.kill();
    let _ = second.wait();
    assert!(
        took_over && gone.is_none() && told.contains("is stopping; this one serves once it has"),
        "PRODUCT: a daemon started while another stopped must wait for it and then serve, saying \
         so; it took over {took_over}, exited {gone:?}, and said:\n{told}"
    );
}

/// ADR-026 L-3: a detach is done only when the node's keys are wiped and its directory let go.
/// A room seal still working (staged to take 12 s) holds the node's stop; `vox node detach`
/// answers only after the seal ends, never at the daemon's
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
    // The operator attaches the node (a hook never does, ADR-028 K-13); its daemon, started by the
    // attach, holds secret work by the knob.
    let (ok, out, err) = run(&["node", "attach", "agent"], "");
    assert!(
        ok,
        "PRODUCT (staging): vox node attach agent failed: {out}{err}\nlog:\n{}",
        a.log()
    );
    let (ok, out, err) = hook("UserPromptSubmit");
    assert!(
        ok && !out.contains("could not read your rooms"),
        "PRODUCT (staging): the hook did not read with its node attached: {out}{err}\nlog:\n{}",
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
                    "--node",
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
        let end = run(&["node", "detach", "agent"], "");
        let ended_at = Instant::now();
        let took = t0.elapsed();
        let ((created, made_at), (probe_r, probe_took)) =
            (seal.join().unwrap(), probe.join().unwrap());
        eprintln!(
            "[proof] the detach answered after {:.2} s; the seal's room create ok={}; \
             a client probe answered in {:.3} s; the create said {:?}",
            took.as_secs_f64(),
            created.0,
            probe_took.as_secs_f64(),
            created.2.trim()
        );
        assert!(
            end.0,
            "PRODUCT (staging): vox node detach agent failed: {end:?}"
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
            .any(|l| l.starts_with("vox daemon: node agent detached (asked to)")),
        "PRODUCT: the detach was not said\nlog:\n{}",
        a.log()
    );
    // Idle now: the daemon the attach started leaves.
    assert!(
        wait_until(Duration::from_secs(10), || !alive(pid)),
        "PRODUCT: the daemon did not leave once idle\nlog:\n{}",
        a.log()
    );
}

/// #408: **an agent's hook never waits without a bound.** A node's detach waits for the secret
/// work it is doing (here a room seal staged to take 25 s, ADR-026 L-3). A hook that asks for the
/// node meanwhile is answered within its bound, about 10 s, saying in one line that the node is
/// still detaching and this turn reads nothing, and exits so the turn goes on.
#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn a_hook_is_answered_within_its_bound_while_its_node_detaches() {
    const SEAL_MS: u64 = 25_000;
    const HOOK_BOUND: Duration = Duration::from_secs(10);
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
    // Attached by hand (which starts the daemon, with the knob): the unlock is held too.
    let (ok, out, err) = run(&["node", "attach", "agent"], "");
    assert!(
        ok,
        "APPARATUS: vox node attach agent: {out}{err}\nlog:\n{}",
        a.log()
    );
    let pid = a
        .lock_pid()
        .expect("PRODUCT (staging): no daemon holds the lock");
    std::thread::scope(|s| {
        // A seal in flight, then the detach that waits for it.
        let seal = s.spawn(|| {
            run(
                &[
                    "room",
                    "create",
                    "--node",
                    "agent",
                    "--passphrase-file",
                    "-",
                    "--name",
                    "r",
                ],
                ROOM_PASS,
            )
        });
        std::thread::sleep(Duration::from_secs(1));
        let detach = s.spawn(|| run(&["node", "detach", "agent"], ""));
        std::thread::sleep(Duration::from_secs(1));
        let t0 = Instant::now();
        let (ok, out, err) = a.hook("agent", "s-1", "UserPromptSubmit");
        let took = t0.elapsed();
        eprintln!(
            "[proof] the hook during the detach answered in {:.2} s (exit ok={ok}): {}",
            took.as_secs_f64(),
            out.trim()
        );
        assert!(
            ok && took <= HOOK_BOUND + Duration::from_secs(1),
            "PRODUCT: an agent's hook waited {:.2} s on a node that is detaching; its bound is \
             {} s (#408)\nstdout: {out}\nstderr: {err}\nlog:\n{}",
            took.as_secs_f64(),
            HOOK_BOUND.as_secs(),
            a.log()
        );
        assert!(
            out.contains("node agent is still detaching; this turn reads nothing"),
            "PRODUCT: the hook's one line does not say the node is still detaching: {out}"
        );
        let (_, _, _) = seal.join().unwrap();
        let (dok, dout, derr) = detach.join().unwrap();
        assert!(dok, "PRODUCT (staging): the detach failed: {dout}{derr}");
    });
    stop_pid(pid);
}

/// One hook turn run as a harness runs it, with its output also on descriptors 3 and 4 (what a
/// harness's pipe that reaches the hook without close-on-exec looks like), read to its end.
/// `Some(stdout)` once its stdout and stderr both closed within `within`, `None` if they did not.
fn hook_read_to_end(a: &Account, session: &str, within: Duration) -> (Option<String>, Child) {
    use std::io::Read as _;
    let input = format!(r#"{{"hook_event_name":"UserPromptSubmit","session_id":"{session}"}}"#);
    // The hook through the shell, so its stdout and stderr are also on 3 and 4, inherited.
    let template = a.cmd(&[]);
    let mut sh = Command::new("/bin/sh");
    sh.args(["-c", r#"exec "$0" agent hook --node agent 3>&1 4>&2"#, VOX])
        .env_clear()
        // A proof's daemon never takes port 1080 (.cargo/config.toml).
        .env("VOX_PROXY", "127.0.0.1:0");
    for (k, v) in template.get_envs() {
        if let Some(v) = v {
            sh.env(k, v);
        }
    }
    let mut child = sh
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: spawn the hook through sh");
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let tx2 = tx.clone();
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        let _ = tx.send((0, s));
    });
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = err.read_to_string(&mut s);
        let _ = tx2.send((1, s));
    });
    let deadline = Instant::now() + within;
    let (mut stdout, mut stderr) = (None, None);
    while stdout.is_none() || stderr.is_none() {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok((0, s)) => stdout = Some(s),
            Ok((_, s)) => stderr = Some(s),
            Err(_) => return (None, child),
        }
    }
    (stdout, child)
}

/// **A hook answers within a second while the daemon it starts attaches its kept nodes** (#666,
/// the decider's bound for a hook: under 1 s). Eight kept nodes (made with no passphrase, so the
/// daemon attaches each at its start, each an Argon2id unlock) and one node not attached; no
/// daemon runs. A hook turn as the node not attached answers within 1 s, saying it is not
/// attached; a hook turn as a kept node answers within 1 s, saying the node is attaching and the
/// rooms show from the next turn; the daemon keeps that first turn's registration, and once the
/// node is attached the session's Session is in its room with no second turn; a later turn says
/// nothing of attaching. Mutants: the unlock's Argon2id back inline on the daemon's runtime (red:
/// the not-attached node's hook waits on the unlocks); the daemon waiting for a node still
/// attaching before it answers (red: the kept node's hook past 1 s); the queued registration
/// dropped (red: no Session). Timing: run under `timing-lock.sh`.
#[test]
#[ignore = "real binaries with production Argon2id; a timing claim: run in release under timing-lock"]
fn a_hook_answers_within_a_second_while_the_daemon_attaches_its_kept_nodes() {
    watchdog::arm();
    let a = Account::new();
    let empty = a.data.with_extension("empty");
    std::fs::write(&empty, "\n").unwrap();
    let empty = empty.to_str().unwrap().to_owned();
    let kept: Vec<String> = (1..=8).map(|i| format!("kept{i}")).collect();
    for n in kept.iter().map(String::as_str).chain(["plain"]) {
        let (ok, out, err) = a.run(&["node", "create", n, "--passphrase-file", &empty], "");
        assert!(ok, "APPARATUS: vox node create {n}: {out}{err}");
    }
    for n in &kept {
        let (ok, out, err) = a.run(&["node", "attach", n, "--passphrase-file", &empty], "");
        assert!(
            ok && out.contains("attaches it again by itself"),
            "APPARATUS (staging): node {n} must be attached and remembered: {out}{err}"
        );
    }
    // kept1 works in a room, made with no passphrase, so the Session its hook opens is seen.
    let (ok, out, err) = a.run(
        &[
            "room",
            "create",
            "--node",
            "kept1",
            "--passphrase-file",
            &empty,
            "--name",
            "work",
        ],
        "",
    );
    assert!(ok, "APPARATUS (staging): kept1's room: {out}{err}");
    let (_, list, _) = a.run(&["room", "list", "--node", "kept1"], "");
    let room = list
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    let pid = a
        .lock_pid()
        .expect("APPARATUS: no daemon after the attaches");
    stop_pid(pid);
    assert!(!alive(pid), "APPARATUS: the staging daemon did not stop");

    let timed = |node: &str, session: &str| {
        let t0 = Instant::now();
        let (ok, out, err) = a.hook(node, session, "UserPromptSubmit");
        (t0.elapsed(), ok, format!("{out}{err}"))
    };
    let (took, ok, said) = timed("plain", "s-plain");
    println!("[proof] cold hook as plain (not attached): {took:?}");
    assert!(
        ok && took < Duration::from_secs(1) && said.contains("node plain is not attached"),
        "PRODUCT: with no daemon running and 8 kept nodes to attach, a hook as a node not \
         attached must answer within 1 s, saying so; it took {took:?} and said: {said}\nlog:\n{}",
        a.log()
    );
    let pid = a.lock_pid().expect("PRODUCT: the hook started no daemon");
    stop_pid(pid);
    let t0 = Instant::now();
    let input = r#"{"hook_event_name":"UserPromptSubmit","session_id":"s-kept"}"#;
    let (ok, out, err) = a.run(
        &["agent", "hook", "--node", "kept1", "--room", &room],
        input,
    );
    let (took, said) = (t0.elapsed(), format!("{out}{err}"));
    println!("[proof] cold hook as kept1 (attaching): {took:?}: {said}");
    assert!(
        ok && took < Duration::from_secs(1)
            && said.contains(
                "Vox: node kept1 is attaching (the vox daemon has just started); this session \
                 joins it once it is attached, and your rooms show from your next turn."
            ),
        "PRODUCT: with no daemon running, a hook as a kept node must answer within 1 s, saying \
         the node is attaching and the rooms show from the next turn; it took {took:?} and \
         said: {said}\nlog:\n{}",
        a.log()
    );
    let attached = wait_until(Duration::from_secs(60), || {
        a.run(&["node", "list"], "")
            .1
            .lines()
            .any(|l| l.starts_with("kept1 ") && l.contains(" attached"))
    });
    assert!(
        attached,
        "PRODUCT: kept1 was not attached by the daemon's start\nlog:\n{}",
        a.log()
    );
    // **The first turn's registration is kept** (#666): with no second turn, the Session of
    // s-kept is in kept1's room once kept1 is attached.
    let mut sessions = String::new();
    let opened = wait_until(Duration::from_secs(30), || {
        sessions = a
            .run(
                &["room", "sessions", &room, "--node", "kept1", "--json"],
                "",
            )
            .1;
        sessions.contains("s-kept")
    });
    println!("[proof] kept1's room's Sessions, after its first turn only: {sessions}");
    assert!(
        opened,
        "PRODUCT: the session whose first turn found kept1 attaching must be registered once kept1 \
         is attached, its Session in kept1's room, with no second turn: `vox room sessions` says \
         {sessions}\nlog:\n{}",
        a.log()
    );
    let (_, ok, said) = timed("kept1", "s-kept");
    assert!(
        ok && !said.contains("attaching") && !said.contains("could not read"),
        "PRODUCT: once kept1 is attached, the next turn must read its rooms, not say it is \
         attaching: {said}"
    );
    stop_pid(a.lock_pid().expect("PRODUCT: no daemon at the end"));
}

/// ADR-026 S-2, #405: **a daemon a hook starts keeps none of the hook's descriptors.** Two hooks
/// at once, five times, each run as a harness runs one and read to the end of its output, while
/// one of them starts the daemon. Each hook's output closes when the hook exits, though the daemon
/// it started runs on, and the daemon holds no pipe.
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn a_hooks_output_closes_while_the_daemon_it_started_runs() {
    watchdog::arm();
    for round in 1..=5 {
        let a = Account::new();
        a.make_node("agent");
        let results = std::thread::scope(|s| {
            let one = s.spawn(|| hook_read_to_end(&a, "s-1", Duration::from_secs(40)));
            let two = s.spawn(|| hook_read_to_end(&a, "s-2", Duration::from_secs(40)));
            [one.join().unwrap(), two.join().unwrap()]
        });
        let pid = a.lock_pid();
        let lsof = pid
            .map(|p| {
                Command::new("lsof")
                    .args(["-n", "-P", "-p", &p.to_string()])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let pipes: Vec<&str> = lsof
            .lines()
            .filter(|l| l.contains("PIPE") || l.contains(" pipe"))
            .collect();
        let mut closed = true;
        for (i, (got, mut child)) in results.into_iter().enumerate() {
            match got {
                Some(out) => {
                    let _ = child.wait();
                    // Its node is not attached, and a hook never attaches it (ADR-028 K-13): the
                    // hook answers with the command for the operator, and ends.
                    assert!(
                        out.contains("vox node attach agent"),
                        "PRODUCT (staging): round {round}, hook {}: {out}",
                        i + 1
                    );
                }
                None => {
                    closed = false;
                    eprintln!(
                        "[proof] round {round}: hook {}'s output did not close in 40 s",
                        i + 1
                    );
                    let _ = child.kill();
                }
            }
        }
        println!(
            "[proof] round {round}: both hooks' output closed: {closed}; daemon {pid:?} holds {} \
             pipe(s)",
            pipes.len()
        );
        if let Some(p) = pid {
            if !closed || !pipes.is_empty() {
                stop_pid(p);
            }
        }
        assert!(
            closed && pipes.is_empty(),
            "PRODUCT: round {round}: a daemon a hook started holds the hook's descriptors, so a \
             harness reading its hook to the end waits for the daemon (#405). Its pipes:\n{}\n\
             log:\n{}",
            pipes.join("\n"),
            a.log()
        );
        for s in ["s-1", "s-2"] {
            let _ = a.hook("agent", s, "SessionEnd");
        }
        if let Some(p) = pid {
            assert!(
                wait_until(Duration::from_secs(15), || !alive(p)),
                "PRODUCT (staging): round {round}: the daemon did not leave once idle"
            );
        }
    }
}

/// Run `vox args` as root — uid 0 in a new user namespace, which needs no sudo — to its end, or
/// until `within` has passed (then it is killed by its pid). `None` when this machine has no
/// unprivileged user namespaces.
fn as_root(a: &Account, args: &[&str], within: Duration) -> Option<(Duration, String)> {
    let probe = Command::new("unshare")
        .args(["--user", "--map-root-user", "id", "-u"])
        .output()
        .ok()?;
    if String::from_utf8_lossy(&probe.stdout).trim() != "0" {
        return None;
    }
    let vox = a.cmd(args);
    let mut c = Command::new("unshare");
    c.env_clear()
        // A proof's daemon never takes port 1080 (.cargo/config.toml).
        .env("VOX_PROXY", "127.0.0.1:0");
    for (k, v) in vox.get_envs() {
        if let Some(v) = v {
            c.env(k, v);
        }
    }
    c.args(["--user", "--map-root-user", "--", VOX])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let t0 = Instant::now();
    let mut child = c.spawn().ok()?;
    while t0.elapsed() < within && child.try_wait().ok().flatten().is_none() {
        std::thread::sleep(Duration::from_millis(100));
    }
    let took = t0.elapsed();
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let out = child.wait_with_output().ok()?;
    Some((
        took,
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    ))
}

/// ADR-026 C-1, said: root is refused by every daemon, and told so at once (case 5 above).
#[test]
#[ignore = "real binaries; run in release"]
fn root_is_told_at_once_that_it_cannot_use_the_daemon() {
    watchdog::arm();
    if !cfg!(target_os = "linux") {
        panic!(
            "CANNOT MEASURE: running vox as root without sudo needs a Linux user namespace; this \
             is not Linux"
        );
    }
    const WITHIN: Duration = Duration::from_secs(10);
    let a = Account::new();
    for args in [&["serve", "web=8080"][..], &["daemon"]] {
        let Some((took, said)) = as_root(&a, args, Duration::from_secs(40)) else {
            panic!(
                "CANNOT MEASURE: this machine refuses an unprivileged user namespace \
                 (`unshare --user --map-root-user`), so vox cannot be run as root without sudo"
            );
        };
        println!(
            "[proof] as root, `vox {}` ended after {took:?}: {said}",
            args.join(" ")
        );
        assert!(
            took < WITHIN
                && said.contains("as root (uid 0)")
                && said.contains("ordinary user")
                && !said.contains("did not start within"),
            "PRODUCT: as root, `vox {}` must say at once (within {WITHIN:?}) that vox is running \
             as root and to run it as an ordinary user; it took {took:?} and said: {said}",
            args.join(" ")
        );
    }
}
