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
//!    on this Mac says so with `vox setup` and makes no `nodes/<it>` directory; with no daemon,
//!    a verb says to open Vox (or run `vox daemon`) on a Mac (#666; mutants: the old `vox
//!    daemon`-only words, red at that line;
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

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[cfg(target_os = "linux")]
#[path = "support/optional_proof.rs"]
mod optional_proof;
#[path = "support/typed.rs"]
mod typed;
#[cfg(target_os = "linux")]
optional_proof::not_run!(a_systemd_user_unit_recovers_foreign_signals_and_honors_product_stop);

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
        std::fs::create_dir_all(tmp.path().join("home")).unwrap();
        // Every new unlock remembers: use only this proof's private Keychain on a Mac.
        if cfg!(target_os = "macos") {
            test_knobs::require(&["VOX_TEST_KEYCHAIN"]);
            let status = Command::new("/usr/bin/security")
                .args(["create-keychain", "-p", ""])
                .arg(tmp.path().join("k.keychain-db"))
                .status()
                .expect("APPARATUS: create scratch Keychain");
            assert!(
                status.success(),
                "APPARATUS: scratch Keychain creation failed: {status}"
            );
        }
        std::fs::write(tmp.path().join("identity.pass"), format!("{PASS}\n"))
            .expect("APPARATUS: persistent identity passphrase file");
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
        for key in ["PATH", "TMPDIR"] {
            if let Some(v) = std::env::var_os(key) {
                c.env(key, v);
            }
        }
        c.args(args);
        // Existing staging callers use the persistent file on platforms without a Keychain.
        if !cfg!(target_os = "macos")
            && args.starts_with(&["node", "attach"])
            && !args.contains(&"--passphrase-file")
        {
            c.arg("--passphrase-file")
                .arg(self._tmp.path().join("identity.pass"));
        }
        c.env("VOX_TEST_KEYCHAIN", self._tmp.path().join("k.keychain-db"))
            .env("HOME", self._tmp.path().join("home"))
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

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
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

/// The generated extension runs in a small native-event driver, using real hooks and watcher.
/// Its notifications are exactly the strings OMP's UI receives.
struct OmpConversation {
    child: Child,
    frames: std::sync::mpsc::Receiver<serde_json::Value>,
    notices: Vec<String>,
    trace: PathBuf,
}

impl OmpConversation {
    fn start(a: &Account) -> Self {
        let (ok, extension, err) = a.run(&["agent", "plugin", "omp", "--node", "agent"], "");
        assert!(ok, "APPARATUS: generated native extension: {err}");
        std::fs::write(a._tmp.path().join("extension.mjs"), extension).unwrap();
        let wrapper = a._tmp.path().join("vox-traced");
        std::fs::write(&wrapper, "#!/bin/bash\nset -o pipefail\nif [[ \"$1 $2\" == 'agent omp-watch' ]]; then\n  \"$VOX_PROOF_BINARY\" \"$@\" | tee -a \"$VOX_PROOF_WATCH_TRACE\"\nelse\n  exec \"$VOX_PROOF_BINARY\" \"$@\"\nfi\n").unwrap();
        std::fs::set_permissions(
            &wrapper,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        )
        .unwrap();
        let trace = a._tmp.path().join("watcher.jsonl");
        let driver = a._tmp.path().join("conversation.mjs");
        std::fs::write(
            &driver,
            r#"
import extension from "./extension.mjs";
import { createInterface } from "node:readline";
const events = new Map();
const say = value => console.log(JSON.stringify(value));
const pi = {
  on: (name, handler) => events.set(name, handler),
  getSessionName: () => "identity-proof",
  sendMessage: () => {}, appendEntry: () => {}
};
const context = {
  mode: "tui", agent: {kind: "main"}, cwd: process.cwd(),
  isIdle: () => true,
  getAsyncJobSnapshot: () => ({running: [], recent: []}),
  sessionManager: {getSessionId: () => "identity-proof", getLeafId: () => null,
    getBranch: () => [], getEntries: () => []},
  ui: {notify: text => say({notice: text})}
};
extension(pi);
await events.get("session_start")({}, context);
say({started: true});
for await (const line of createInterface({input: process.stdin})) {
  if (line === "quit") {
    await events.get("session_shutdown")();
    process.exit(0);
  }
  await events.get("before_agent_start")({reason: "prompt"});
  say({barrier: line});
}
"#,
        )
        .unwrap();
        let environment = a.cmd(&[]);
        let mut command = Command::new("node");
        command.env_clear();
        for (key, value) in environment.get_envs() {
            if let Some(value) = value {
                command.env(key, value);
            }
        }
        let mut child = command
            .arg(driver)
            .env("VOX_BIN", wrapper)
            .env("VOX_PROOF_BINARY", VOX)
            .env("VOX_PROOF_WATCH_TRACE", &trace)
            .env("VOX_TEST_WATCH_READY_INTERVAL_SECS", "1")
            .current_dir(a._tmp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("APPARATUS: native event driver (node)");
        let stdout = child.stdout.take().unwrap();
        let (tx, frames) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::BufRead as _;
            for line in std::io::BufReader::new(stdout).lines() {
                let line = line.expect("APPARATUS: native driver output");
                let value = serde_json::from_str(&line)
                    .unwrap_or_else(|_| panic!("APPARATUS: native driver said {line}"));
                if tx.send(value).is_err() {
                    break;
                }
            }
        });
        let mut conversation = Self {
            child,
            frames,
            notices: Vec::new(),
            trace,
        };
        conversation.until(|frame| frame["started"] == true);
        assert!(
            wait_until(Duration::from_secs(30), || std::fs::read_to_string(
                &conversation.trace
            )
            .unwrap_or_default()
            .contains("\"type\":\"ready\"")),
            "APPARATUS: conversation never observed its attached node"
        );
        assert!(
            a.data
                .join("nodes/agent/sessions/identity-proof.json")
                .is_file(),
            "APPARATUS: native conversation was not registered before the transition"
        );
        conversation
    }

    fn until(&mut self, done: impl Fn(&serde_json::Value) -> bool) {
        loop {
            let frame = self
                .frames
                .recv_timeout(Duration::from_secs(45))
                .expect("APPARATUS: native event driver did not reach its requested observation");
            if let Some(text) = frame["notice"].as_str() {
                println!("OMP notification: {text}");
                self.notices.push(text.into());
            }
            if done(&frame) {
                break;
            }
        }
    }

    fn prompt(&mut self, id: &str) {
        writeln!(self.child.stdin.as_mut().unwrap(), "{id}").unwrap();
        self.until(|frame| frame["barrier"] == id);
    }

    fn observations(&self) -> usize {
        std::fs::read_to_string(&self.trace)
            .unwrap_or_default()
            .lines()
            .count()
    }

    fn observe_after(&self, before: usize) {
        assert!(
            wait_until(Duration::from_secs(45), || self.observations() > before
                || std::fs::read_to_string(&self.trace)
                    .unwrap_or_default()
                    .contains("identity-changed")),
            "APPARATUS: no watcher snapshot after the staged node replacement"
        );
    }

    fn observed_frame_after(&self, before: usize, kind: &str) -> bool {
        // The watcher caps its availability backoff at 30 s. Three capped intervals
        // cover a probe already in flight and the replacement's next subscription.
        wait_until(Duration::from_secs(90), || {
            std::fs::read_to_string(&self.trace)
                .unwrap_or_default()
                .lines()
                .skip(before)
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .any(|frame| frame["type"] == kind)
        })
    }
}

impl Drop for OmpConversation {
    fn drop(&mut self) {
        if let Some(stdin) = self.child.stdin.as_mut() {
            let _ = writeln!(stdin, "quit");
        }
        let _ = self.child.wait();
        println!(
            "watcher observations:\n{}",
            std::fs::read_to_string(&self.trace).unwrap_or_default()
        );
    }
}

#[test]
#[ignore = "native extension, real daemon and production Argon2id; run in release with test-knobs"]
fn a_conversation_reports_one_reconnecting_line_when_its_daemon_restarts() {
    watchdog::arm();
    // Both event orders, a timer before either event, and a slot removed before its event.
    reconnect_with_held_stop("agent", "detaching");
    reconnect_with_held_stop("*", "detaching");
    reconnect_with_held_stop("agent", "event");
    reconnect_with_held_stop("held", "detaching");
}

fn reconnect_with_held_stop(held_node: &str, phase: &str) {
    test_knobs::require(&[
        "VOX_TEST_STOP_HOLD_NODE",
        "VOX_TEST_STOP_HOLD_FILE",
        "VOX_TEST_WATCH_READY_INTERVAL_SECS",
        "VOX_TEST_STOP_HOLD_PHASE",
        "VOX_TEST_ATTACH_HOLD_NODE",
        "VOX_TEST_ATTACH_HOLD_FILE",
    ]);
    let a = Account::new();
    a.make_node("agent");
    a.make_node("held");
    let stop_hold = a._tmp.path().join("hold-node-stop");
    std::fs::write(&stop_hold, "").expect("APPARATUS: node stop hold");
    let mut daemon = Daemon::start(
        &a,
        &["--node", "agent"],
        &[
            ("VOX_TEST_STOP_HOLD_NODE", held_node),
            ("VOX_TEST_STOP_HOLD_FILE", stop_hold.to_str().unwrap()),
            ("VOX_TEST_STOP_HOLD_PHASE", phase),
        ],
    );
    daemon.expect("node agent is Ready", Duration::from_secs(30), |line| {
        line.contains("node agent is Ready")
    });
    let (ok, out, err) = a.run(&["node", "attach", "held"], "");
    assert!(ok, "APPARATUS: second node did not attach: {out}{err}");
    // Keep agent too: the replacement must actually attach it from remembered credentials.
    let (ok, out, err) = a.run(&["node", "attach", "agent"], "");
    assert!(
        ok,
        "APPARATUS: agent was not remembered for restart: {out}{err}"
    );
    let mut conversation = OmpConversation::start(&a);
    let stop_started = Instant::now();
    let signalled = Command::new("/bin/kill")
        .args(["-TERM", &daemon.child.id().to_string()])
        .status()
        .expect("APPARATUS: signal the proof's daemon");
    assert!(signalled.success(), "APPARATUS: daemon stop signal failed");
    let agent_state = if phase != "event" && held_node != "held" {
        "Detaching"
    } else {
        "Locked"
    };
    let sibling_state = if phase != "event" && held_node != "agent" {
        "Detaching"
    } else {
        "Locked"
    };
    let mut stopping_nodes = String::new();
    assert!(
        wait_until(Duration::from_secs(15), || {
            let (ok, out, err) = a.run(&["node", "list"], "");
            let staged = ok
                && out
                    .lines()
                    .any(|line| line.starts_with("agent ") && line.contains(agent_state))
                && out
                    .lines()
                    .any(|line| line.starts_with("held ") && line.contains(sibling_state));
            stopping_nodes = format!("{out}{err}");
            staged
        }),
        "APPARATUS: daemon did not answer with agent {agent_state} and held {sibling_state}: \
         {stopping_nodes}; {}",
        daemon.said()
    );
    println!(
        "stopping pid {}, held node {held_node} at {phase}, still answers:\n{stopping_nodes}",
        daemon.child.id()
    );
    // A new timer probe must see this stable held phase, not the preceding transition.
    let before_probe = conversation.observations();
    assert!(
        wait_until(Duration::from_secs(90), || {
            std::fs::read_to_string(&conversation.trace)
                .unwrap_or_default()
                .lines()
                .skip(before_probe)
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .any(|frame| {
                    frame["type"] == "unavailable"
                        && frame["pid"] == daemon.child.id()
                        && matches!(
                            frame["reason"].as_str(),
                            Some("reconnecting" | "node-not-ready")
                        )
                })
        }) && daemon.child.try_wait().unwrap().is_none(),
        "APPARATUS: watcher did not probe while the stopping daemon still answered:\n{}",
        std::fs::read_to_string(&conversation.trace).unwrap_or_default()
    );
    conversation.until(|frame| frame.get("notice").is_some());
    conversation.prompt("while-stopping");
    std::fs::remove_file(&stop_hold).expect("APPARATUS: release node stop");
    let held_for = stop_started.elapsed();
    assert!(
        held_for < Duration::from_secs(5),
        "APPARATUS: hold {held_node} at {phase} released after {held_for:?}, beyond the \
         daemon's five-second shutdown patience; its exit is not a product verdict"
    );
    let during_stop = conversation.notices.join("\n");
    assert!(
        during_stop
            .lines()
            .filter(|line| line.contains("reconnecting"))
            .count()
            == 1
            && !during_stop.contains("is unavailable")
            && !during_stop.contains("vox node create"),
        "PRODUCT: while agent is {agent_state} and held is {sibling_state} (hold {held_node} at \
         {phase}), the stopping daemon must give exactly one reconnecting line and never blame \
         the node: {during_stop}"
    );
    let stopped = daemon.child.wait().expect("APPARATUS: reap stopped daemon");
    assert!(
        stopped.success(),
        "PRODUCT: daemon failed to finish stopping: {}",
        daemon.said()
    );
    let before_restart = conversation.observations();
    let attach_hold = a._tmp.path().join("hold-replacement-attach");
    std::fs::write(&attach_hold, "").expect("APPARATUS: replacement attach hold");
    let daemon = Daemon::start(
        &a,
        &["--no-node"],
        &[
            ("VOX_TEST_ATTACH_HOLD_NODE", "agent"),
            ("VOX_TEST_ATTACH_HOLD_FILE", attach_hold.to_str().unwrap()),
        ],
    );
    daemon.expect("serving", Duration::from_secs(30), |line| {
        line.contains("serving")
    });
    let (ok, out, err) = a.run(&["node", "list"], "");
    assert!(
        ok && out
            .lines()
            .any(|line| line.starts_with("agent ") && line.contains("Attaching")),
        "APPARATUS: replacement did not report agent Attaching: {out}{err}"
    );
    println!(
        "replacement pid {} is still attaching:\n{out}",
        daemon.child.id()
    );
    let before_attach_probe = conversation.observations();
    assert!(
        wait_until(Duration::from_secs(90), || {
            std::fs::read_to_string(&conversation.trace)
                .unwrap_or_default()
                .lines()
                .skip(before_attach_probe)
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .any(|frame| {
                    frame["type"] == "unavailable"
                        && frame["pid"] == daemon.child.id()
                        && matches!(
                            frame["reason"].as_str(),
                            Some("reconnecting" | "node-not-ready")
                        )
                })
        }),
        "APPARATUS: no watcher frame from the attaching replacement pid {}:\n{}",
        daemon.child.id(),
        std::fs::read_to_string(&conversation.trace).unwrap_or_default()
    );
    conversation.prompt("replacement-attaching");
    let during_attach = conversation.notices.join("\n");
    assert!(
        during_attach.lines().filter(|line| line.contains("reconnecting")).count() == 1
            && !during_attach.contains("is unavailable") && !during_attach.contains("vox node create"),
        "PRODUCT: an attaching replacement must keep one reconnecting line and never blame the node: {during_attach}"
    );
    std::fs::remove_file(&attach_hold).expect("APPARATUS: release replacement attach");
    daemon.expect("node agent is Ready", Duration::from_secs(30), |line| {
        line.contains("node agent is Ready")
    });
    // PRODUCT, not apparatus: this already-ready conversation must reconnect to the
    // replacement daemon. Counting its one notice without resumed readiness proves nothing.
    assert!(
        conversation.observed_frame_after(before_restart, "ready"),
        "PRODUCT: watcher never became ready within 90 s after restart despite its 30 s \
         backoff cap:\n{}",
        std::fs::read_to_string(&conversation.trace).unwrap_or_default()
    );
    conversation.prompt("after-restart");
    let notices = conversation.notices.join("\n");
    drop(conversation);
    daemon.stop();
    assert!(
        notices
            .lines()
            .filter(|line| line.contains("reconnecting"))
            .count()
            == 1
            && !notices.contains("is unavailable")
            && !notices.contains("vox node create"),
        "PRODUCT: a daemon restart must say reconnecting once, not blame the node: {notices}"
    );
}

#[test]
#[ignore = "native extension and a node locked after restart; run in release with test-knobs"]
fn a_conversation_explains_a_locked_node_after_its_daemon_restarts() {
    watchdog::arm();
    let a = Account::new();
    a.make_node("agent");
    let daemon = Daemon::start(&a, &["--node", "agent"], &[]);
    daemon.expect("node agent is Ready", Duration::from_secs(30), |line| {
        line.contains("node agent is Ready")
    });
    let mut conversation = OmpConversation::start(&a);
    daemon.stop();
    conversation.until(|frame| frame.get("notice").is_some());
    // Start the replacement without unlocking a node, then lock through the public CLI.
    // This stages the same answered-but-not-ready state as a missing restart credential.
    let daemon = Daemon::start(&a, &["--no-node"], &[]);
    daemon.expect("serving", Duration::from_secs(30), |line| {
        line.contains("serving")
    });
    let (ok, out, err) = a.run(&["node", "lock", "agent"], "");
    assert!(
        ok,
        "APPARATUS: could not lock the replacement's node: {out}{err}"
    );
    let (ok, out, err) = a.run(&["node", "list"], "");
    assert!(
        ok && out.contains("agent") && out.contains("Locked"),
        "APPARATUS: replacement did not report its locked node: {out}{err}"
    );
    let before = conversation.observations();
    assert!(
        conversation.observed_frame_after(before, "unavailable"),
        "PRODUCT: watcher did not report the replacement's locked node:\n{}",
        std::fs::read_to_string(&conversation.trace).unwrap_or_default()
    );
    conversation.prompt("locked-after-restart");
    let notices = conversation.notices.join("\n");
    drop(conversation);
    daemon.stop();
    assert!(
        notices.contains("vox node unlock -- agent"),
        "PRODUCT: a daemon that answers with a locked node must explain how to unlock it, \
         even after its reconnecting notice: {notices}"
    );
}

#[test]
#[ignore = "native extension, real daemon and rebuilt node; run in release with test-knobs"]
fn a_conversation_refuses_a_rebuilt_node_under_the_same_name() {
    watchdog::arm();
    let a = Account::new();
    let original = a.make_node("agent");
    let daemon = Daemon::start(&a, &["--node", "agent"], &[]);
    daemon.expect("node agent is Ready", Duration::from_secs(30), |line| {
        line.contains("node agent is Ready")
    });
    let mut conversation = OmpConversation::start(&a);
    daemon.stop();
    conversation.until(|frame| frame.get("notice").is_some());
    // No daemon is left on the old directory: this is identity fencing, not store rewriting.
    std::fs::rename(a.data.join("nodes/agent"), a.data.join("nodes/original")).unwrap();
    let rebuilt = a.make_node("agent");
    assert_ne!(
        original, rebuilt,
        "APPARATUS: rebuilt node did not get a fresh identity"
    );
    let daemon = Daemon::start(&a, &["--node", "agent"], &[]);
    daemon.expect("node agent is Ready", Duration::from_secs(30), |line| {
        line.contains("node agent is Ready")
    });
    let before = conversation.observations();
    conversation.observe_after(before);
    conversation.prompt("rebuilt");
    conversation.prompt("refused-again");
    let notices = conversation.notices.join("\n");
    let registered = a
        .data
        .join("nodes/agent/sessions/identity-proof.json")
        .exists();
    drop(conversation);
    daemon.stop();
    assert!(notices.contains("identity changed") && notices.contains("conversation is refused")
        && notices.contains("new OMP conversation") && !registered,
        "PRODUCT: a rebuilt node must not adopt the old conversation; registered={registered}; {notices}");
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
        l.starts_with("vox daemon: node b is Ready")
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
        "that node a finished its work because its actor panicked",
        Duration::from_secs(20),
        |l| l.starts_with("vox daemon: node a finished its work (its actor panicked"),
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
            *ok && out.contains("node agent is Locked") && out.contains("vox node unlock agent"),
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
        ok && !out.contains("Locked") && !out.contains("could not read your rooms"),
        "PRODUCT: a session's second turn must not say again that its node is not attached \
         (once per session): {out}{err}"
    );
    let notified = a.notified();
    assert!(
        notified
            .lines()
            .filter(|l| l.contains("node agent needs its passphrase")
                && l.contains("vox node unlock agent"))
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
            .any(|l| l.starts_with("vox daemon: node agent is Ready")),
        "PRODUCT: a hook attached its node (ADR-028 K-13)\nlog:\n{}",
        a.log()
    );
    if cfg!(target_os = "macos") {
        // Presence is staged; no app is launched. The shipped hook chooses the actual wording.
        let bundle = a._tmp.path().join("Vox.app");
        std::fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
        std::fs::write(bundle.join("Contents/MacOS/Vox"), b"not executed").unwrap();
        std::fs::create_dir_all(a.cfg.join("app")).unwrap();
        std::fs::write(
            a.cfg.join("app/bundle.json"),
            serde_json::json!({"bundle":bundle}).to_string(),
        )
        .unwrap();
        let (ok, out, err) = a.hook("agent", "locked-app", "UserPromptSubmit");
        assert!(ok && out.contains("Open Vox to unlock agent") && !out.contains("vox node unlock"),
            "PRODUCT: the Locked hook on a Mac with Vox must direct the operator to Vox: {out}{err}");
        let mut ssh = a.cmd(&["agent", "hook", "--node", "agent"]);
        ssh.env("SSH_CONNECTION", "127.0.0.1 1 127.0.0.1 2")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = ssh.spawn().expect("APPARATUS: SSH hook");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(br#"{"hook_event_name":"UserPromptSubmit","session_id":"locked-ssh"}"#)
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let words = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success()
                && words.contains("vox node unlock agent")
                && !words.contains("Open Vox"),
            "PRODUCT: the SSH hook must give the terminal unlock command: {words}"
        );
    }
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
    // Observe the saved-credential outcome through macOS's public Keychain tool. Never request
    // the password (-w/-g), and never search a real or default Keychain.
    fn saved_item(a: &Account, keychain: &Path) -> std::process::Output {
        let accessible = Command::new("/usr/bin/security")
            .args(["unlock-keychain", "-p", ""])
            .arg(keychain)
            .output()
            .expect("APPARATUS: open this proof's private Keychain");
        assert!(
            accessible.status.success(),
            "APPARATUS: private Keychain is not accessible: {}",
            String::from_utf8_lossy(&accessible.stderr)
        );
        Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", "us.vox.node", "-a"])
            .arg(a.data.join("nodes/default"))
            .arg(keychain)
            .output()
            .expect("APPARATUS: query saved credential in private Keychain")
    }
    // Keep the old attach file readable while refusing atomic replacement on a Mac. Elsewhere
    // a directory at the destination stages unreadable-record refusal; its old file is restored
    // before retry. Drop restores either fixture even if a PRODUCT assertion panics.
    struct UnwritableAttach {
        path: PathBuf,
        backup: Option<PathBuf>,
    }
    impl UnwritableAttach {
        fn new(path: PathBuf, unreadable: bool) -> Self {
            let fixture = if cfg!(target_os = "macos") && !unreadable {
                let status = Command::new("chflags")
                    .arg("uchg")
                    .arg(&path)
                    .status()
                    .expect("APPARATUS: make scratch attach file immutable");
                assert!(status.success(), "APPARATUS: cannot protect attach fixture");
                Self { path, backup: None }
            } else {
                let backup = path.with_extension("saved");
                std::fs::rename(&path, &backup).expect("APPARATUS: save attach fixture");
                let fixture = Self {
                    path,
                    backup: Some(backup),
                };
                std::fs::create_dir(&fixture.path).expect("APPARATUS: block attach destination");
                fixture
            };
            let probe = fixture.path.with_extension("probe");
            std::fs::write(&probe, "probe").expect("APPARATUS: attach replacement probe");
            let blocked = std::fs::rename(&probe, &fixture.path).is_err();
            let _ = std::fs::remove_file(&probe);
            assert!(
                blocked,
                "APPARATUS: attach destination accepted replacement; write failure was not staged"
            );
            fixture
        }
    }
    impl Drop for UnwritableAttach {
        fn drop(&mut self) {
            if let Some(backup) = &self.backup {
                let _ = std::fs::remove_dir(&self.path);
                std::fs::rename(backup, &self.path)
                    .expect("APPARATUS: restore scratch attach file");
            } else {
                let status = Command::new("chflags")
                    .arg("nouchg")
                    .arg(&self.path)
                    .status()
                    .expect("APPARATUS: clear scratch immutable flag");
                assert!(
                    status.success(),
                    "APPARATUS: cannot clear scratch immutable flag"
                );
            }
        }
    }
    watchdog::arm();
    let a = Account::new();
    a.make_node("default");
    let pass = a.data.with_extension("pass");
    std::fs::write(&pass, format!("{PASS}\n")).unwrap();
    let (ok, out, err) = a.run(&["daemon", "--detach"], "");
    assert!(
        ok,
        "APPARATUS: daemon before persistence failure: {out}{err}"
    );
    let attach_file = a.data.join(".daemon/attach");
    std::fs::write(&attach_file, "").expect("APPARATUS: empty remembered-state file");
    {
        let _blocked = UnwritableAttach::new(attach_file.clone(), false);
        let (ok, out, err) = a.run(
            &[
                "node",
                "unlock",
                "default",
                "--passphrase-file",
                pass.to_str().unwrap(),
            ],
            "",
        );
        let truthful = if cfg!(target_os = "macos") {
            err.contains("Ready, but remembering could not be confirmed")
                && err.contains("could not write")
        } else {
            err.contains("could not read remembered state") && err.contains("it was not changed")
        };
        assert!(
            !ok && truthful && !out.contains("Ready and remembered"),
            "PRODUCT: failed persistence must fail unlock and name its partial state: {out}{err}"
        );
        let (_, shown, err) = a.run(&["node", "list"], "");
        assert!(
            shown.lines().any(|l| l.starts_with("default ")
                && l.contains("Ready")
                && !l.contains("(remembered)")),
            "PRODUCT: a failed first remember must not appear kept: {shown}{err}"
        );
    }
    // The ordinary successful unlock below is also the retry after storage is restored.
    let (ok, out, err) = a.run(
        &[
            "node",
            "unlock",
            "default",
            "--passphrase-file",
            pass.to_str().unwrap(),
        ],
        "",
    );
    assert!(
        ok && out.contains("Ready and remembered"),
        "PRODUCT: unlock must make the node Ready and remembered: {out}{err}"
    );
    let room = make_room(&a, "default");
    let (ok, out, err) = a.run(&["room", "post", &room, "before the restart"], "");
    assert!(ok, "APPARATUS: post before restart: {out}{err}");
    let (ok, out, err) = a.run(&["node", "forget-passphrase", "default"], "");
    assert!(
        ok,
        "APPARATUS: temporarily forget the Ready node: {out}{err}"
    );
    let (_, listed, err) = a.run(&["node", "list"], "");
    assert!(listed.lines().any(|l| l.starts_with("default ") && l.contains("Ready") && !l.contains("(remembered)")),
        "APPARATUS: empty-input refusal needs a protected Ready but unremembered node: {listed}{err}");
    let empty = pass.with_extension("empty");
    std::fs::write(&empty, "\n").expect("APPARATUS: empty passphrase input");
    let (ok, out, err) = a.run(
        &[
            "node",
            "unlock",
            "default",
            "--passphrase-file",
            empty.to_str().unwrap(),
        ],
        "",
    );
    assert!(!ok && err.contains("identity passphrase") && !out.contains("Ready and remembered"),
        "PRODUCT: a Ready protected node must reject empty input instead of remembering no passphrase: {out}{err}");
    let (_, listed, err) = a.run(&["node", "list"], "");
    assert!(
        listed.lines().any(|l| l.starts_with("default ")
            && l.contains("Ready")
            && !l.contains("(remembered)")),
        "PRODUCT: rejected empty input must leave the Ready node unremembered: {listed}{err}"
    );
    let (ok, out, err) = a.run(
        &[
            "node",
            "unlock",
            "default",
            "--passphrase-file",
            pass.to_str().unwrap(),
        ],
        "",
    );
    assert!(
        ok && out.contains("Ready and remembered"),
        "PRODUCT: correct passphrase retry must remember the Ready node: {out}{err}"
    );
    let wrong = pass.with_extension("wrong");
    std::fs::write(&wrong, "wrong identity passphrase\n")
        .expect("APPARATUS: wrong persistent input");
    let (ok, out, err) = a.run(
        &[
            "node",
            "unlock",
            "default",
            "--passphrase-file",
            wrong.to_str().unwrap(),
        ],
        "",
    );
    assert!(!ok && err.contains("identity passphrase") && !out.contains("Ready and remembered"),
        "PRODUCT: wrong input must not replace an already-Ready node's usable restart secret: {out}{err}");
    // The restart and room read below prove the rejected replacement left usable material.
    stop_pid(a.lock_pid().expect("APPARATUS: unlocked node's daemon"));
    let supplied = pass.with_extension("supplied");
    if cfg!(target_os = "macos") {
        std::fs::rename(&pass, &supplied).expect("APPARATUS: remove one-time input file");
    }
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
        log.contains("vox daemon: node default is Ready"),
        "PRODUCT: the restart did not say it attached the kept node\nlog:\n{log}"
    );

    if cfg!(target_os = "macos") {
        std::fs::rename(&supplied, &pass).expect("APPARATUS: restore one-time input file");
    }
    // Lock must forget restart state without deleting the room, message or app selection.
    let (ok, out, err) = a.run(&["node", "lock", "default"], "");
    assert!(
        ok && out.contains("Locked and forgotten"),
        "PRODUCT: lock must forget the node and close it: {out}{err}"
    );
    stop_pid(pid);
    let (ok, out, err) = a.run(&["daemon", "--detach"], "");
    assert!(ok, "APPARATUS: restart after lock: {out}{err}");
    let (_, listed, err) = a.run(&["node", "list"], "");
    assert!(
        listed.lines().any(|l| l.starts_with("default ")
            && l.contains("Locked")
            && !l.contains("(remembered)")),
        "PRODUCT: lock must survive a daemon restart: {listed}{err}"
    );
    let (ok, out, err) = a.run(
        &[
            "node",
            "attach",
            "default",
            "--keep",
            "--passphrase-file",
            pass.to_str().unwrap(),
        ],
        "",
    );
    assert!(
        ok && err.contains("`vox node attach` is now `vox node unlock`")
            && out.contains("Ready and remembered"),
        "PRODUCT: attach --keep must be the remembering unlock alias: {out}{err}"
    );
    let (ok, out, err) = a.run(&["room", "read", &room], "");
    assert!(
        ok && out.contains("before the restart"),
        "PRODUCT: lock/unlock must preserve the room and its messages: {out}{err}"
    );

    // A remembered node whose secret is unavailable is already stopped. A missing Keychain
    // cannot confirm deletion: Lock must report that failure, then permit a retry after it is
    // restored even though the restart entry was already removed.
    stop_pid(
        a.lock_pid()
            .expect("APPARATUS: daemon before missing secret"),
    );
    let remembered = if cfg!(target_os = "macos") {
        a._tmp.path().join("k.keychain-db")
    } else {
        pass.clone()
    };
    let away = remembered.with_extension("away");
    if cfg!(target_os = "macos") {
        let item = saved_item(&a, &remembered);
        assert!(
            item.status.success(),
            "APPARATUS: the saved credential to forget is absent: {}",
            String::from_utf8_lossy(&item.stderr)
        );
    }
    std::fs::rename(&remembered, &away).expect("APPARATUS: temporarily remove remembered secret");
    let (ok, out, err) = a.run(&["daemon", "--detach"], "");
    assert!(
        ok,
        "APPARATUS: restart with missing remembered secret: {out}{err}"
    );
    assert!(
        wait_until(Duration::from_secs(30), || {
            let (_, shown, _) = a.run(&["node", "list"], "");
            shown.lines().any(|l| {
                l.starts_with("default ") && l.contains("Locked") && l.contains("(remembered)")
            })
        }),
        "APPARATUS: the missing secret did not leave a remembered, stopped node: {}",
        a.log()
    );
    if !cfg!(target_os = "macos") {
        assert!(
            a.log()
                .contains("restore the file, then run `vox node unlock default --passphrase-file"),
            "PRODUCT: a missing remembered file must say how to recover: {}",
            a.log()
        );
    }
    let (ok, out, err) = a.run(&["node", "detach", "default"], "");
    if cfg!(target_os = "macos") {
        assert!(!ok && err.contains("could not forget") && err.contains("keychain")
            && err.contains("retry") && !out.contains("Locked and forgotten"),
            "PRODUCT: an unavailable Keychain must refuse full forgotten success and explain retry: {out}{err}");
        let (_, shown, err) = a.run(&["node", "list"], "");
        assert!(shown.lines().any(|l| l.starts_with("default ") && l.contains("Locked") && !l.contains("(remembered)")),
            "PRODUCT: failed secret deletion must show that the restart entry was removed: {shown}{err}");
    } else {
        assert!(
            ok && out.contains("Locked and forgotten"),
            "PRODUCT: detach must forget an already-stopped node's restart file: {out}{err}"
        );
    }
    assert!(
        err.contains("`vox node detach` is now `vox node lock`"),
        "PRODUCT: detach must print the lock alias: {out}{err}"
    );
    std::fs::rename(&away, &remembered).expect("APPARATUS: restore remembered secret");
    if cfg!(target_os = "macos") {
        let item = saved_item(&a, &remembered);
        assert!(
            item.status.success(),
            "APPARATUS: restore did not make the saved credential available: {}",
            String::from_utf8_lossy(&item.stderr)
        );
    }
    let (ok, out, err) = a.run(&["node", "lock", "default"], "");
    assert!(ok && out.contains("Locked and forgotten"),
        "PRODUCT: after restoring secret storage, Lock must retry cleanup without a restart entry: {out}{err}");
    if cfg!(target_os = "macos") {
        let item = saved_item(&a, &remembered);
        // security exposes errSecItemNotFound (-25300) as exit status 44. An access/OS error
        // is not absence, and finding the item means Vox falsely claimed it was forgotten.
        assert_eq!(item.status.code(), Some(44),
            "PRODUCT: successful Lock must delete the saved Keychain credential, not only its restart entry: status={} {}",
            item.status, String::from_utf8_lossy(&item.stderr));
    }
    stop_pid(a.lock_pid().expect("APPARATUS: stopped node's daemon"));
    let (ok, out, err) = a.run(&["daemon", "--detach"], "");
    assert!(ok, "APPARATUS: restart after restoring secret: {out}{err}");
    let (_, shown, err) = a.run(&["node", "list"], "");
    assert!(shown.lines().any(|l| l.starts_with("default ") && l.contains("Locked") && !l.contains("(remembered)")),
        "PRODUCT: locking an already-stopped node must survive secret restoration and restart: {shown}{err}");
    let (ok, out, err) = a.run(
        &[
            "node",
            "unlock",
            "default",
            "--passphrase-file",
            pass.to_str().unwrap(),
        ],
        "",
    );
    assert!(
        ok,
        "PRODUCT: unlock after locking a stopped node: {out}{err}"
    );
    let (ok, out, err) = a.run(&["room", "read", &room], "");
    assert!(
        ok && out.contains("before the restart"),
        "PRODUCT: locking an already-stopped node must preserve messages: {out}{err}"
    );
    {
        let _blocked = UnwritableAttach::new(attach_file.clone(), true);
        for args in [
            vec![
                "node",
                "unlock",
                "default",
                "--passphrase-file",
                pass.to_str().unwrap(),
            ],
            vec!["node", "lock", "default"],
        ] {
            let (ok, out, err) = a.run(&args, "");
            assert!(!ok && err.contains("could not read remembered state") && err.contains("it was not changed")
                && !out.contains("Ready and remembered") && !out.contains("Locked and forgotten"),
                "PRODUCT: unreadable remembered state must be refused without claiming a change: {out}{err}");
        }
        let (ok, shown, err) = a.run(&["node", "list"], "");
        assert!(!ok && err.contains("cannot read remembered nodes")
            && err.contains("the saved file was not changed") && !shown.contains("Ready"),
            "PRODUCT: an unreadable remembered-state file must refuse a public listing rather than guess: {shown}{err}");
    }
    let (ok, shown, err) = a.run(&["node", "list"], "");
    assert!(ok && shown.lines().any(|l| l.starts_with("default ") && l.contains("Ready") && l.contains("(remembered)")),
        "PRODUCT: restoring the unreadable fixture must show the unchanged Ready and remembered node: {shown}{err}");
    {
        let _blocked = UnwritableAttach::new(attach_file.clone(), false);
        let (ok, out, err) = a.run(&["node", "lock", "default"], "");
        let truthful = if cfg!(target_os = "macos") {
            err.contains("could not forget") && err.contains("could not write")
        } else {
            err.contains("could not read remembered state") && err.contains("it was not changed")
        };
        assert!(
            !ok && truthful && !out.contains("Locked and forgotten"),
            "PRODUCT: failed persistence must not claim lock forgot the node: {out}{err}"
        );
        let (_, shown, err) = a.run(&["node", "list"], "");
        assert!(shown.lines().any(|l| l.starts_with("default ") && l.contains("Ready")
            && (!cfg!(target_os = "macos") || l.contains("(remembered)"))),
            "PRODUCT: failed forgetting must leave the node Ready and show its surviving remembered state: {shown}{err}");
    }
    stop_pid(a.lock_pid().expect("APPARATUS: daemon after failed lock"));
    let (ok, out, err) = a.run(&["daemon", "--detach"], "");
    assert!(ok, "APPARATUS: restart after failed lock: {out}{err}");
    assert!(wait_until(Duration::from_secs(60), || a.run(&["room", "read", &room], "").1.contains("before the restart")),
        "PRODUCT: failed forgetting must preserve the saved secret needed by the surviving entry: {}", a.log());
    let (ok, out, err) = a.run(&["node", "lock", "default"], "");
    assert!(
        ok && out.contains("Locked and forgotten"),
        "PRODUCT: restoring storage must let lock retry succeed: {out}{err}"
    );
    let (ok, out, err) = a.run(
        &[
            "node",
            "unlock",
            "default",
            "--passphrase-file",
            pass.to_str().unwrap(),
        ],
        "",
    );
    assert!(
        ok && out.contains("Ready and remembered"),
        "PRODUCT: unlock after the repaired lock must succeed: {out}{err}"
    );
    let (ok, out, err) = a.run(&["node", "attach", "default", "--no-remember"], "");
    assert!(
        !ok && err.contains("--no-remember"),
        "PRODUCT: attach must not offer an unremembered unlock exception: {out}{err}"
    );
    if cfg!(target_os = "macos") {
        // A store failure on an already-remembered Ready node must not retain stale keep state.
        std::fs::rename(&remembered, &away).expect("APPARATUS: make scratch Keychain unavailable");
        let (ok, out, err) = a.run(
            &[
                "node",
                "unlock",
                "default",
                "--passphrase-file",
                pass.to_str().unwrap(),
            ],
            "",
        );
        assert!(
            !ok && err.contains("Ready, but remembering could not be confirmed")
                && err.contains("keychain")
                && !out.contains("Ready and remembered"),
            "PRODUCT: a failed remember must fail unlock and name its partial state: {out}{err}"
        );
        let (_, listed, err) = a.run(&["node", "list"], "");
        assert!(listed.lines().any(|l| l.starts_with("default ") && l.contains("Ready") && !l.contains("(remembered)")),
            "PRODUCT: failed Keychain storage must clear the previous remembered state: {listed}{err}");
        stop_pid(
            a.lock_pid()
                .expect("APPARATUS: daemon after failed remember"),
        );
        std::fs::rename(&away, &remembered).expect("APPARATUS: restore scratch Keychain");
        let (ok, out, err) = a.run(&["daemon", "--detach"], "");
        assert!(ok, "APPARATUS: restart after failed remember: {out}{err}");
        let (_, listed, err) = a.run(&["node", "list"], "");
        assert!(
            listed.lines().any(|l| l.starts_with("default ")
                && l.contains("Locked")
                && !l.contains("(remembered)")),
            "PRODUCT: the cleared remembered state must survive restart: {listed}{err}"
        );
        let (ok, out, err) = a.run(
            &[
                "node",
                "unlock",
                "default",
                "--passphrase-file",
                pass.to_str().unwrap(),
            ],
            "",
        );
        assert!(
            ok,
            "PRODUCT: correcting the Keychain problem must permit unlock: {out}{err}"
        );
    } else {
        let (ok, out, err) = a.run(
            &["node", "unlock", "default", "--passphrase-file", "-"],
            PASS,
        );
        assert!(
            !ok && err.contains("stdin") && err.contains("persistent"),
            "PRODUCT: stdin must not be recorded as a persistent passphrase file: {out}{err}"
        );
    }
    let pid = a.lock_pid().expect("APPARATUS: daemon before signout");
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
        !line.contains(" Ready") && !line.contains("(remembered)"),
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
        !again.contains(" Ready"),
        "PRODUCT: signed out, node default must not be attached again by a daemon's start: \
         {again:?}\nlog:\n{log}"
    );
    assert!(
        kept_room,
        "PRODUCT: signed out, node default's rooms and messages must stay: attached again by hand \
         ({ok}: {out}{err}) its room must still read \"before the restart\"\nlog:\n{log}"
    );
}

/// A kernel without keyrings never refuses typed unlock, lock or forgetting.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "Linux namespace, seccomp or emulator with an unavailable user keyring; run in release"]
fn a_linux_unavailable_keyring_keeps_unlock_ready_without_a_disk_secret() {
    typed::require_disposable_keyring();
    watchdog::arm();
    let probe_name = format!("vox-rg11-unavailable-probe-{}", std::process::id());
    let probe = Command::new("keyctl")
        .args(["add", "user", &probe_name, "scratch", "@u"])
        .output()
        .expect("APPARATUS: probe the unavailable user keyring");
    if probe.status.success() {
        let key = String::from_utf8_lossy(&probe.stdout).trim().to_owned();
        let _ = Command::new("keyctl").args(["revoke", &key]).status();
        let _ = Command::new("keyctl").args(["unlink", &key, "@u"]).status();
    }
    let refusal = String::from_utf8_lossy(&probe.stderr);
    eprintln!("Unavailable kernel keyring prerequisite: {refusal}");
    assert!(
        !probe.status.success()
            && ["Function not implemented", "Operation not supported",]
                .iter()
                .any(|reason| refusal.contains(reason)),
        "APPARATUS: this preservation proof needs an unavailable user keyring: {refusal}"
    );
    let a = Account::new();
    struct Cleanup<'a>(&'a Account);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            if let Some(pid) = self.0.lock_pid() {
                let _ = Command::new("/bin/kill")
                    .args(["-TERM", &pid.to_string()])
                    .status();
            }
        }
    }
    let _cleanup = Cleanup(&a);
    a.make_node("default");
    std::fs::remove_file(a._tmp.path().join("identity.pass")).unwrap();
    let mut unlock = a.cmd(&["node", "unlock", "default"]);
    unlock.env_remove("VOX_IDENTITY_PASSPHRASE");
    let (ok, text) = typed::typed(&unlock, PASS);
    eprintln!(
        "Typed unlock without a keyring: {}",
        text.replace(PASS, "[redacted]")
    );
    assert!(
        ok && text.contains("Ready") && text.contains("not remembered") && text.contains("kernel keyring"),
        "PRODUCT: an unavailable keyring must leave typed unlock successful and Ready, saying it is not remembered: {}",
        text.replace(PASS, "[redacted]")
    );
    let mut status = a.cmd(&["status", "--node", "default", "--json"]);
    status.env_remove("VOX_IDENTITY_PASSPHRASE");
    let out = status.output().unwrap();
    assert!(
        out.status.success()
            && serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["status"]
                == "Ready",
        "PRODUCT: failed remembering must not lock this daemon's Ready node"
    );
    fn no_plaintext(path: &Path) -> bool {
        std::fs::read_dir(path).unwrap().all(|entry| {
            let path = entry.unwrap().path();
            if path.is_dir() {
                no_plaintext(&path)
            } else if path.is_file() {
                !std::fs::read(path)
                    .unwrap()
                    .windows(PASS.len())
                    .any(|w| w == PASS.as_bytes())
            } else {
                true
            }
        })
    }
    assert!(
        no_plaintext(a._tmp.path()),
        "PRODUCT: unavailable keyring must not fall back to a plaintext secret on disk"
    );
    stop_pid(a.lock_pid().unwrap());
    let mut restart = a.cmd(&["daemon", "--detach"]);
    restart.env_remove("VOX_IDENTITY_PASSPHRASE");
    assert!(
        restart.output().unwrap().status.success(),
        "APPARATUS: scratch daemon restart"
    );
    let mut status = a.cmd(&["status", "--node", "default"]);
    status.env_remove("VOX_IDENTITY_PASSPHRASE");
    let out = status.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("Restart without a keyring: {text}");
    assert!(
        out.status.success() && text.contains("Locked") && text.contains("vox node unlock"),
        "PRODUCT: without a kernel key or chosen file, restart must say Locked and the unlock command: {text}"
    );
    for args in [
        ["node", "lock", "default"],
        ["node", "forget-passphrase", "default"],
    ] {
        let mut command = a.cmd(&args);
        command.env_remove("VOX_IDENTITY_PASSPHRASE");
        let out = command.output().unwrap();
        assert!(
            out.status.success(),
            "PRODUCT: an unavailable keyring must not refuse {args:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// RG-11: a daemon from another login session reads a uid-owned, not possessed, kernel key.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "Linux kernel keyring and real typed unlock; run in release"]
fn a_linux_typed_unlock_survives_another_sessions_daemon() {
    typed::require_disposable_keyring();
    fn fresh_session(a: &Account, args: &[&str]) -> Command {
        let base = a.cmd(args);
        let mut command = Command::new("/usr/bin/keyctl");
        command
            .args([
                "session",
                "-",
                "/bin/sh",
                "-c",
                "keyctl clear @s && exec \"$@\"",
                "sh",
            ])
            .arg(VOX)
            .args(args)
            .env_clear();
        for (key, value) in base.get_envs() {
            if let Some(value) = value {
                command.env(key, value);
            }
        }
        command.env_remove("VOX_IDENTITY_PASSPHRASE");
        command
    }
    fn ready(a: &Account) -> (bool, String) {
        let out = fresh_session(a, &["status", "--node", "default", "--json"])
            .output()
            .expect("APPARATUS: status in a new session");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let ready = out.status.success()
            && serde_json::from_slice::<serde_json::Value>(&out.stdout)
                .ok()
                .is_some_and(|value| value["status"] == "Ready");
        (ready, text)
    }
    fn settled_ready(a: &Account) -> bool {
        let started = Instant::now();
        loop {
            let (ready, text) = ready(a);
            if ready {
                return true;
            }
            if text
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .any(|value| value["status"] == "Locked")
            {
                return false;
            }
            assert!(started.elapsed() < Duration::from_secs(60),
                "APPARATUS: daemon never reported terminal Ready or Locked; no product verdict: {text}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    watchdog::arm();
    let a = Account::new();
    struct Cleanup<'a>(&'a Account);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            if let Some(pid) = self.0.lock_pid() {
                let _ = Command::new("/bin/kill")
                    .args(["-TERM", &pid.to_string()])
                    .status();
            }
            use sha2::{Digest as _, Sha256};
            let account = self
                .0
                .data
                .join("nodes/default")
                .to_string_lossy()
                .into_owned();
            let name = format!("us.vox.node:{:x}", Sha256::digest(account.as_bytes()));
            if let Ok(found) = Command::new("keyctl")
                .args(["search", "@u", "user", &name])
                .output()
            {
                if found.status.success() {
                    let key = String::from_utf8_lossy(&found.stdout).trim().to_owned();
                    let _ = Command::new("keyctl").args(["revoke", &key]).status();
                    let _ = Command::new("keyctl").args(["unlink", &key, "@u"]).status();
                }
            }
        }
    }
    let _cleanup = Cleanup(&a);
    a.make_node("default");
    // Account's general staging file is not selected or available to this typed unlock.
    std::fs::remove_file(a._tmp.path().join("identity.pass")).unwrap();
    let (ok, text) = typed::typed(&fresh_session(&a, &["node", "unlock", "default"]), PASS);
    eprintln!("Typed unlock: {}", text.replace(PASS, "[redacted]"));
    assert!(
        ok && text.contains("Ready"),
        "APPARATUS: typed Linux unlock did not become Ready: {text}"
    );
    let pid = a.lock_pid().expect("APPARATUS: typed unlock daemon");
    stop_pid(pid);
    let out = fresh_session(&a, &["daemon", "--detach"]).output().unwrap();
    assert!(
        out.status.success(),
        "APPARATUS: new-session daemon start: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        settled_ready(&a),
        "PRODUCT: typed unlock must survive a daemon in a new, empty session keyring: {}; {}",
        ready(&a).1,
        a.log()
    );
    eprintln!(
        "PASS linux.typed_unlock_survives_new_session_daemon: {}",
        ready(&a).1
    );

    // A crash has the same key lifetime as an orderly restart.
    let pid = a.lock_pid().unwrap();
    Command::new("/bin/kill")
        .args(["-KILL", &pid.to_string()])
        .status()
        .unwrap();
    assert!(
        wait_until(Duration::from_secs(15), || !alive(pid)),
        "APPARATUS: crashed daemon is still running"
    );
    let out = fresh_session(&a, &["daemon", "--detach"]).output().unwrap();
    assert!(
        out.status.success(),
        "APPARATUS: daemon after crash: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        settled_ready(&a),
        "PRODUCT: typed unlock must survive a crashed daemon: {}; {}",
        ready(&a).1,
        a.log()
    );
    eprintln!("PASS linux.typed_unlock_survives_crash: {}", ready(&a).1);

    stop_pid(a.lock_pid().unwrap());
    // Remove only this scratch node's key, never another key of the container user. Losing
    // this boot-scoped credential stages what reboot does without rebooting the shared VM.
    use sha2::{Digest as _, Sha256};
    let account = a.data.join("nodes/default").to_string_lossy().into_owned();
    let name = format!("us.vox.node:{:x}", Sha256::digest(account.as_bytes()));
    let found = Command::new("keyctl")
        .args(["search", "@u", "user", &name])
        .output()
        .unwrap();
    assert!(
        found.status.success(),
        "APPARATUS: this node's boot-scoped key was not found: {}",
        String::from_utf8_lossy(&found.stderr)
    );
    let key = String::from_utf8_lossy(&found.stdout).trim().to_owned();
    let removed = Command::new("keyctl")
        .args(["unlink", &key, "@u"])
        .output()
        .unwrap();
    assert!(
        removed.status.success(),
        "APPARATUS: could not clear this scratch boot credential"
    );
    let out = fresh_session(&a, &["daemon", "--detach"]).output().unwrap();
    assert!(out.status.success(), "APPARATUS: daemon after key loss");
    let out = fresh_session(&a, &["status", "--node", "default"])
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("Locked") && text.contains("vox node unlock") && text.contains("default"),
        "PRODUCT: after reboot without a chosen file, status must say Locked and how to unlock: {text}");
    eprintln!("PASS linux.lost_boot_key_says_locked_and_unlock_command: {text}");
    let pass = a._tmp.path().join("chosen.pass");
    std::fs::write(&pass, format!("{PASS}\n")).unwrap();
    let out = fresh_session(
        &a,
        &[
            "node",
            "unlock",
            "default",
            "--passphrase-file",
            pass.to_str().unwrap(),
        ],
    )
    .output()
    .unwrap();
    assert!(
        out.status.success(),
        "APPARATUS: chosen-file unlock: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    stop_pid(a.lock_pid().unwrap());
    let out = fresh_session(&a, &["daemon", "--detach"]).output().unwrap();
    assert!(
        out.status.success(),
        "APPARATUS: daemon with chosen-file recovery"
    );
    assert!(
        settled_ready(&a),
        "PRODUCT: after losing the boot key, the chosen file must restore Ready: {}; {}",
        ready(&a).1,
        a.log()
    );
    eprintln!(
        "PASS linux.chosen_file_restores_ready_after_boot_key_loss: {}",
        ready(&a).1
    );
    let _ = a.run(&["node", "lock", "default"], "");
    stop_pid(a.lock_pid().unwrap());
}

/// RG-9: real systemd in the authorized disposable container, not an in-process supervisor.
#[cfg(all(target_os = "linux", feature = "optional-proofs"))]
#[test]
#[ignore = "optional: a systemd user session in the authorized vox-rg9 container"]
fn a_systemd_user_unit_recovers_foreign_signals_and_honors_product_stop() {
    use std::collections::BTreeMap;
    use vox_core::node::daemonipc::{DaemonClient, DaemonFrame, DaemonRequest};
    fn manager(args: &[&str]) -> std::process::Output {
        Command::new("systemctl")
            .arg("--user")
            .args(args)
            .output()
            .expect("APPARATUS: run the scratch user's systemctl")
    }
    fn properties(unit: &str) -> BTreeMap<String, String> {
        let output = manager(&[
            "show",
            unit,
            "--property=MainPID,ActiveState,SubState,ExecMainStatus,Result,NRestarts,Job",
        ]);
        assert!(
            output.status.success(),
            "APPARATUS: inspect our user unit: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                line.split_once('=')
                    .map(|(key, value)| (key.to_owned(), value.to_owned()))
            })
            .collect()
    }
    fn pid(state: &BTreeMap<String, String>) -> Option<u32> {
        state
            .get("MainPID")?
            .parse::<u32>()
            .ok()
            .filter(|pid| *pid > 1)
    }
    fn serving(a: &Account, unit: &str, old: Option<u32>, recovery: bool) -> u32 {
        let began = Instant::now();
        loop {
            let state = properties(unit);
            if let Some(current) = pid(&state).filter(|current| Some(*current) != old) {
                if a.log().contains(&format!("serving (pid {current})")) {
                    eprintln!("[proof] manager owns serving pid {current}: {state:?}");
                    return current;
                }
            }
            assert!(!(recovery && state.get("ActiveState").is_some_and(|s| s == "inactive")
                && state.get("ExecMainStatus").is_some_and(|s| s == "0")),
                "PRODUCT: a foreign TERM was reported as a successful stop, so Restart=on-failure left no daemon: {state:?}\n{}", a.log());
            assert!(
                began.elapsed() < Duration::from_secs(60),
                "APPARATUS: user unit never reached a new serving generation: {state:?}\n{}",
                a.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn stop(a: &Account, unit: &str) {
        let account = vox_core::node::paths::Account::of(Some(&a.data), Some(&a.cfg)).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let reply = runtime.block_on(async {
            let mut client = DaemonClient::open(&account.socket())
                .await
                .expect("APPARATUS: reach the unit's serving daemon");
            client
                .request(DaemonRequest::Stop)
                .await
                .expect("PRODUCT: explicit Stop was not acknowledged")
        });
        assert!(
            matches!(reply, DaemonFrame::Ok),
            "PRODUCT: explicit Stop was refused: {reply:?}"
        );
        let mut final_state = BTreeMap::new();
        assert!(
            wait_until(Duration::from_secs(30), || {
                final_state = properties(unit);
                final_state
                    .get("ActiveState")
                    .is_some_and(|s| s == "inactive")
            }),
            "APPARATUS: explicit Stop did not finish: {final_state:?}\n{}",
            a.log()
        );
        assert!(pid(&final_state).is_none()
            && final_state.get("ExecMainStatus").is_some_and(|s| s == "0")
            && final_state.get("Result").is_some_and(|s| s == "success")
            && final_state.get("Job").is_none_or(|s| s.is_empty() || s == "0"),
            "PRODUCT: explicit Stop must leave the on-failure unit stopped with no queued restart: {final_state:?}\n{}", a.log());
        eprintln!("[proof] explicit product Stop leaves the unit stopped: {final_state:?}");
    }
    struct Unit {
        name: String,
        path: PathBuf,
        data: PathBuf,
    }
    impl Drop for Unit {
        fn drop(&mut self) {
            // All these processes were started for this proof's private profile, including its worker.
            for pid in daemons_of(&self.data) {
                let _ = Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .status();
            }
            let _ = manager(&["stop", &self.name]);
            let _ = std::fs::remove_file(&self.path);
            let _ = manager(&["daemon-reload"]);
        }
    }
    watchdog::arm();
    assert!(
        Path::new("/run/.containerenv").exists()
            && std::env::var("VOX_PROOF_SYSTEMD_CONTAINER")
                .is_ok_and(|name| name.starts_with("vox-rg9-")),
        "APPARATUS: this proof runs only in its authorized disposable podman container"
    );
    let a = Account::new();
    a.make_node("default");
    let name = format!("vox-rg9-{}.service", std::process::id());
    let runtime = PathBuf::from(
        std::env::var_os("XDG_RUNTIME_DIR").expect("APPARATUS: container user runtime directory"),
    );
    let directory = runtime.join("systemd/user");
    std::fs::create_dir_all(&directory).expect("APPARATUS: user unit directory");
    let path = directory.join(&name);
    assert!(
        !path.exists(),
        "APPARATUS: refusing an existing unit {}",
        path.display()
    );
    // Vox ships no unit. This proof enrolls only its private on-failure unit.
    std::fs::write(&path, format!(
        "[Unit]\nDescription=Vox RG-9 proof\n[Service]\nExecStart={VOX} daemon --no-node --listen 127.0.0.1:0 --data-dir {} --config-dir {}\nEnvironment=VOX_DATA_DIR={} VOX_CONFIG_DIR={} VOX_PROXY=127.0.0.1:0 HOME={}\nRestart=on-failure\nRestartSec=1\n",
        a.data.display(), a.cfg.display(), a.data.display(), a.cfg.display(), a._tmp.path().join("home").display()
    )).expect("APPARATUS: write our scratch unit");
    let unit = Unit {
        name,
        path,
        data: a.data.clone(),
    };
    for args in [vec!["daemon-reload"], vec!["start", unit.name.as_str()]] {
        let output = manager(&args);
        assert!(
            output.status.success(),
            "APPARATUS: enroll our user unit: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let first = serving(&a, &unit.name, None, false);
    let (ok, out, err) = a.run(&["node", "attach", "default"], "");
    assert!(
        ok,
        "APPARATUS: attach the scratch node before TERM: {out}{err}"
    );
    let (ok, out, err) = a.run(&["status", "--json"], "");
    assert!(ok, "APPARATUS: initial vox status failed: {out}{err}");
    assert!(
        Command::new("kill")
            .args(["-TERM", &first.to_string()])
            .status()
            .unwrap()
            .success(),
        "APPARATUS: send TERM only to the unit daemon this proof started"
    );
    // No vox client has run: manager state plus the product's own serving line decide recovery.
    let recovered = serving(&a, &unit.name, Some(first), true);
    assert_ne!(
        first, recovered,
        "PRODUCT: foreign TERM left the same daemon generation"
    );
    let (ok, out, err) = a.run(&["node", "attach", "default"], "");
    assert!(
        ok,
        "PRODUCT: attach after manager recovery failed: {out}{err}"
    );
    let (ok, out, err) = a.run(&["status", "--json"], "");
    assert!(
        ok,
        "PRODUCT: vox status after manager recovery failed: {out}{err}"
    );
    let report: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: vox status was not JSON: {e}: {out}"));
    assert_eq!(
        report["log_path"].as_str(),
        a.data.join(".daemon/log").to_str(),
        "PRODUCT: recovered vox status did not report this daemon's log: {out}"
    );
    assert!(
        pid(&properties(&unit.name)) == Some(recovered) && a.lock_pid() == Some(recovered),
        "PRODUCT: vox status did not use the manager's replacement: {out}{err}"
    );
    eprintln!("[proof] vox status after TERM: {out}");
    stop(&a, &unit.name);
}

/// RG-9: an explicit product Stop is final; a foreign signal remains a clean but failed exit.
#[test]
#[ignore = "real daemon processes; run in release with test-knobs on macOS"]
fn a_product_stop_exits_zero_and_foreign_signals_exit_for_the_manager() {
    use vox_core::node::daemonipc::{DaemonClient, DaemonFrame, DaemonRequest};
    struct Owned(Daemon);
    impl Drop for Owned {
        fn drop(&mut self) {
            if self.0.child.try_wait().ok().flatten().is_none() {
                let _ = self.0.child.kill();
                let _ = self.0.child.wait();
            }
        }
    }
    fn start(a: &Account, args: &[&str]) -> Owned {
        let daemon = Owned(Daemon::start(a, args, &[]));
        assert!(
            wait_until(Duration::from_secs(30), || daemon
                .0
                .said()
                .contains("control socket")),
            "APPARATUS: the daemon did not start serving: {}",
            daemon.0.said()
        );
        daemon
    }
    watchdog::arm();
    let a = Account::new();
    let account = vox_core::node::paths::Account::of(Some(&a.data), Some(&a.cfg))
        .expect("APPARATUS: scratch account paths");
    let mut daemon = start(&a, &["--login-item", "--no-node"]);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let stopped = runtime.block_on(async {
        let mut client = DaemonClient::open(&account.socket())
            .await
            .expect("APPARATUS: connect to the serving daemon");
        client
            .request(DaemonRequest::Stop)
            .await
            .expect("PRODUCT: the explicit product stop was not acknowledged")
    });
    assert!(
        matches!(stopped, DaemonFrame::Ok),
        "PRODUCT: the product's explicit Stop was refused: {stopped:?}"
    );
    let status = daemon
        .0
        .child
        .wait()
        .expect("APPARATUS: reap explicitly stopped daemon");
    eprintln!("[proof] explicit Stop: {status}\n{}", daemon.0.said());
    assert!(
        status.success()
            && daemon
                .0
                .said()
                .contains("stop requested by the product's control client"),
        "PRODUCT: an explicit product Stop must exit zero after clean shutdown: {status}\n{}",
        daemon.0.said()
    );
    drop(daemon);

    for (signal, code) in [("TERM", 71), ("HUP", 71), ("INT", 71), ("QUIT", 71)] {
        let mut daemon = start(&a, &["--login-item", "--no-node"]);
        let pid = daemon.0.child.id();
        let sent = Command::new("kill")
            .args([&format!("-{signal}"), &pid.to_string()])
            .status()
            .expect("APPARATUS: signal the daemon this proof started");
        assert!(
            sent.success(),
            "APPARATUS: could not send SIG{signal} to owned pid {pid}"
        );
        let status = daemon
            .0
            .child
            .wait()
            .expect("APPARATUS: reap signal-stopped daemon");
        let said = daemon.0.said();
        eprintln!("[proof] foreign SIG{signal} stopped pid {pid}: {status}\n{said}");
        assert!(status.code() == Some(code) && said.contains(&format!("stopped by SIG{signal}"))
            && !said.contains("did not finish stopping"),
            "PRODUCT: SIG{signal} must finish clean shutdown then exit {code}, so a service manager can recover it; got {status}:\n{said}");
    }

    let mut daemon = start(&a, &["--no-node"]);
    let pid = daemon.0.child.id();
    let sent = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("APPARATUS: signal the hand-run daemon this proof started");
    assert!(
        sent.success(),
        "APPARATUS: could not send SIGTERM to owned pid {pid}"
    );
    let status = daemon
        .0
        .child
        .wait()
        .expect("APPARATUS: reap hand-run daemon");
    let said = daemon.0.said();
    eprintln!("[proof] hand-run SIGTERM stopped pid {pid}: {status}\n{said}");
    assert!(
        status.success()
            && said.contains("vox daemon: stopped by SIGTERM")
            && !said.contains("a service manager may start it again")
            && !said.contains("did not finish stopping"),
        "PRODUCT: a hand-run daemon stopped by SIGTERM must exit zero with its old words and no service-manager claim; got {status}:\n{said}"
    );
}

/// RG-9: a client arriving in a restart waits for its owner, even if the caller dies.
#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn a_restart_owns_its_replacement_while_a_client_waits() {
    struct Children(Vec<Child>);
    impl Drop for Children {
        fn drop(&mut self) {
            for child in &mut self.0 {
                if child.try_wait().ok().flatten().is_none() {
                    let _ = Command::new("kill")
                        .args(["-CONT", &child.id().to_string()])
                        .status();
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }
    watchdog::arm();
    let a = Account::new();
    a.make_node("default");
    let pass = a._tmp.path().join("identity.pass");
    // `Daemon` ends its own child when it is dropped, so it is kept whole here; `children` holds
    // only the restart callers, which may be stopped and must be continued before they are killed.
    // Declared first, the daemon is dropped last.
    let mut daemon = Daemon::start(
        &a,
        &[
            "--node",
            "default",
            "--keep",
            "--passphrase-file",
            pass.to_str().unwrap(),
        ],
        &[("VOX_TEST_STOP_HOLD_MS", "3000")],
    );
    let foreground_output = daemon.out.clone();
    let mut children = Children(Vec::new());
    assert!(
        wait_until(Duration::from_secs(60), || std::fs::read_to_string(
            &foreground_output
        )
        .unwrap_or_default()
        .contains("Ready")),
        "APPARATUS: foreground daemon never became Ready: {}",
        std::fs::read_to_string(&foreground_output).unwrap_or_default()
    );
    let room = make_room(&a, "default");
    let (ok, out, err) = a.run(&["room", "post", &room, "news across the restart"], "");
    assert!(ok, "APPARATUS: post before restart: {out}{err}");

    for killed in [false, true] {
        let old = a
            .lock_pid()
            .expect("APPARATUS: serving daemon before restart");
        let log_before = a.log().len();
        let output = a._tmp.path().join(format!("restart-{killed}.out"));
        let file = std::fs::File::create(&output).unwrap();
        let caller = a
            .cmd(&["daemon", "--restart"])
            .env("VOX_TEST_DAEMON_SERVE_DELAY_MS", "5000")
            .env("VOX_TEST_STOP_HOLD_MS", "3000")
            .stdout(file.try_clone().unwrap())
            .stderr(file)
            .spawn()
            .unwrap();
        children.0.push(caller);
        let caller_pid = children.0[0].id();
        assert!(
            wait_until(Duration::from_secs(30), || a
                .log()
                .get(log_before..)
                .unwrap_or("")
                .contains("shutting down")),
            "APPARATUS: restart never reached the old daemon's shutdown: {}",
            std::fs::read_to_string(&output).unwrap_or_default()
        );
        let signal = if killed { "-KILL" } else { "-STOP" };
        assert!(
            Command::new("kill")
                .args([signal, &caller_pid.to_string()])
                .status()
                .unwrap()
                .success(),
            "APPARATUS: could not hold/kill the restarter we started"
        );
        assert!(
            wait_until(Duration::from_secs(30), || {
                if old == daemon.child.id() {
                    daemon.child.try_wait().unwrap().is_some()
                } else {
                    !alive(old) || a.lock_pid() != Some(old)
                }
            }),
            "APPARATUS: old daemon did not release its account: {}",
            a.log()
        );
        let (client, hook) = std::thread::scope(|scope| {
            let hook = scope.spawn(|| {
                a.hook(
                    "default",
                    if killed {
                        "restart-killed"
                    } else {
                        "restart-held"
                    },
                    "UserPromptSubmit",
                )
            });
            let client = a.run(&["daemon", "--detach"], "");
            (
                client,
                hook.join().expect("APPARATUS: hook worker panicked"),
            )
        });
        let (client_ok, out, err) = client;
        if !killed {
            let _ = Command::new("kill")
                .args(["-CONT", &caller_pid.to_string()])
                .status();
        }
        let status = children.0[0].wait().unwrap();
        children.0.pop();
        let restart = std::fs::read_to_string(&output).unwrap_or_default();
        eprintln!("restart killed={killed}, old={old}, status={status}: {restart}\nclient: {out}{err}\nhook: {}{}\n{}", hook.1, hook.2, a.log());
        let replacement = a.lock_pid().expect("PRODUCT: no daemon after restart");
        let (read_ok, news, read_err) = a.run(&["room", "read", &room], "");
        // Clean up before a failed assertion; never leave a proof's daemon behind.
        if killed
            || !client_ok
            || !out.contains("already running")
            || !hook.0
            || !err.contains("waiting for the daemon restart")
            || !hook.2.contains("waiting for the daemon restart")
        {
            stop_pid(replacement);
        }
        assert!(client_ok && out.contains("already running"),
            "PRODUCT: a client during restart started a competing daemon instead of waiting: {out}{err}; restart: {restart}");
        assert!(
            err.contains("waiting for the daemon restart"),
            "APPARATUS: the client did not arrive during the restart: {out}{err}"
        );
        assert!(
            hook.0,
            "PRODUCT: a hook turn during restart failed: {}{}\n{}",
            hook.1,
            hook.2,
            a.log()
        );
        assert!(
            hook.2.contains("waiting for the daemon restart"),
            "APPARATUS: the hook did not arrive during the restart: {}{}",
            hook.1,
            hook.2
        );
        assert!(
            killed || status.success(),
            "PRODUCT: restart failed: {restart}"
        );
        assert!(replacement != old && read_ok && news.contains("news across the restart"),
            "PRODUCT: the replacement did not serve the kept room after caller killed={killed}: {news}{read_err}\n{}", a.log());
        let generations = a
            .log()
            .get(log_before..)
            .unwrap_or("")
            .matches("vox daemon: serving (pid ")
            .count();
        assert_eq!(
            generations,
            1,
            "PRODUCT: expected exactly one replacement generation, got {generations}:\n{}",
            a.log()
        );
        assert!(
            a.log()
                .get(log_before..)
                .unwrap_or("")
                .contains(&format!("sender pid {replacement} ")),
            "PRODUCT: the process that owned the stop did not become the serving replacement:\n{}",
            a.log()
        );
    }
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
            .any(|l| l.starts_with("vox daemon: node agent finished its work (asked to)")),
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
            out.contains("node agent's work is still stopping; this turn reads nothing"),
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
        ok && took < Duration::from_secs(1) && said.contains("node plain is Locked"),
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
                "Vox is preparing node kept1; this session joins it once it is Ready, and your rooms show from your next turn."
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
            .any(|l| l.starts_with("kept1 ") && l.contains(" Ready"))
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
                        out.contains("vox node unlock agent"),
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

/// ADR-034 LG-1–LG-3: a real daemon replaces an old unbounded log and counts repeat lifecycle
/// messages in place. Mutants: remove Log::open's old-file bound, or append repeated lines
/// instead of updating their count; each fails its own PRODUCT assertion below.
#[test]
#[ignore = "real daemon and encrypted node profiles; run in release"]
fn the_daemons_log_is_bounded_counted_and_named_in_status() {
    watchdog::arm();
    let a = Account::new();
    a.make_node("default");
    let log_path = a.data.join(".daemon/log");
    std::fs::create_dir_all(log_path.parent().unwrap()).expect("APPARATUS: make daemon directory");
    std::fs::write(&log_path, vec![b'x'; 3 * 1024 * 1024])
        .expect("APPARATUS: stage a previous version's oversized daemon log");
    let pass = a.data.with_extension("log-pass");
    std::fs::write(&pass, format!("{PASS}\n")).expect("APPARATUS: passphrase file");
    let d = Daemon::start(&a, &["--no-node"], &[]);
    d.expect("its control socket", Duration::from_secs(30), |l| {
        l.contains("control socket")
    });
    for turn in 0..3 {
        let (ok, out, err) = a.run(
            &[
                "node",
                "attach",
                "default",
                "--passphrase-file",
                pass.to_str().unwrap(),
            ],
            "",
        );
        assert!(ok, "PRODUCT: attach {turn} failed: {out}{err}");
        if turn == 0 {
            let (ok, out, err) = a.run(&["status", "--json"], "");
            assert!(ok, "PRODUCT: status failed: {out}{err}");
            let report: serde_json::Value = serde_json::from_str(&out)
                .unwrap_or_else(|e| panic!("PRODUCT: status was not JSON: {e}: {out}"));
            assert_eq!(
                report["log_path"].as_str(),
                log_path.to_str(),
                "PRODUCT: status did not name the daemon log: {out}"
            );
            let (ok, out, err) = a.run(&["status"], "");
            assert!(
                ok && out.contains(log_path.to_str().unwrap()),
                "PRODUCT: readable status omitted the log: {out}{err}"
            );
        }
        let (ok, out, err) = a.run(&["node", "detach", "default"], "");
        assert!(ok, "PRODUCT: detach {turn} failed: {out}{err}");
    }
    d.stop();
    let log =
        std::fs::read_to_string(&log_path).expect("PRODUCT: the named daemon log was not readable");
    assert!(
        log.len() <= 1024 * 1024,
        "PRODUCT: daemon log exceeded one MiB: {} bytes",
        log.len()
    );
    let detached: Vec<_> = log
        .lines()
        .filter(|l| l.contains("node default finished its work"))
        .collect();
    assert_eq!(
        detached.len(),
        1,
        "PRODUCT: repeat detach warnings were not collapsed into one line:\n{log}"
    );
    assert!(
        detached[0].ends_with("[count=00000000000000000003]"),
        "PRODUCT: the repeated line did not count its three occurrences:\n{log}"
    );
    // Room/peer context is exercised with an actual failing peer in the sync-health journey.
    for line in log.lines() {
        let stamp = line.split_whitespace().next().unwrap_or_default();
        assert!(
            stamp.len() == 24 && stamp.as_bytes()[10] == b'T' && stamp.ends_with('Z'),
            "PRODUCT: a daemon log line has no UTC timestamp: {line}"
        );
    }
    // The next real daemon output must cross the bound, not just trim a legacy log.
    let mut near_bound = b"2026-10-10T00:00:00.000Z ".to_vec();
    near_bound.resize(1024 * 1024 - 1, b'x');
    near_bound.push(b'\n');
    std::fs::write(&log_path, near_bound).expect("APPARATUS: stage rotation boundary");
    let port: u16 = std::fs::read_to_string(a.data.join(".daemon/port"))
        .expect("APPARATUS: read kept port")
        .trim()
        .parse()
        .expect("APPARATUS: numeric port");
    let _busy = std::net::UdpSocket::bind(("127.0.0.1", port))
        .expect("APPARATUS: occupy the stopped daemon's kept port");
    let (ok, out, err) = a.run(
        &[
            "node",
            "attach",
            "default",
            "--passphrase-file",
            pass.to_str().unwrap(),
        ],
        "",
    );
    assert!(
        ok,
        "PRODUCT: automatic start with a busy kept port failed: {out}{err}"
    );
    let pid = a
        .lock_pid()
        .expect("PRODUCT: the automatic daemon holds no lock");
    // A second detached start loses the lock race and must not write an unstamped line.
    let (ok, out, err) = a.run(&["daemon", "--as-detached"], "");
    assert!(ok, "PRODUCT: a second detached start failed: {out}{err}");
    stop_pid(pid);
    let current = std::fs::read_to_string(&log_path).expect("PRODUCT: rotated log unreadable");
    let previous = std::fs::metadata(log_path.with_extension("log.1"))
        .expect("PRODUCT: daemon output crossed the bound without keeping a predecessor");
    assert!(
        current.len() <= 1024 * 1024 && previous.len() <= 1024 * 1024,
        "PRODUCT: rotation exceeded its bounds: current {}, predecessor {}",
        current.len(),
        previous.len()
    );
    assert!(
        current.contains("another program holds it"),
        "PRODUCT: startup's moved-port explanation disappeared from the log: {current}"
    );
    for line in current.lines() {
        let stamp = line.split_whitespace().next().unwrap_or_default();
        assert!(
            stamp.len() == 24 && stamp.as_bytes()[10] == b'T' && stamp.ends_with('Z'),
            "PRODUCT: startup or losing-start log line lacks a UTC timestamp: {line}"
        );
    }
}
