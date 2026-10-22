//! ADR-026 §10 host proofs beside `the_daemon_and_its_nodes_proof.rs` (whose helpers this file
//! copies, as `Account`, `Daemon`, `make_room`, `wait_until`, `stop_pid`): the account's one daemon,
//! every participant the shipped `vox` binary.
//!
//! 1. **D-1, starts at once.** `vox daemon --node <n>` for three nodes, started at the same moment
//!    with no daemon running, end with every node held: one is the daemon, the others hand their
//!    node to it.
//! 2. **Proof 1, nodes handed to a running daemon at once all serve, each as itself, at one
//!    address.** A member on another account joins a room on each, and everyone posts at once.
//! 3. **Proof 7, from a member's side.** A kept node comes back after a daemon restart at the
//!    address its member holds, and they read each other again.

#![allow(clippy::unwrap_used)]
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;
use world::{attach as unlock_staging, typed};

#[path = "support/relay.rs"]
mod relay;

#[path = "support/port_forward.rs"]
mod port_forward;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(
    computer_pairing_uses_an_anchor_without_room_membership_and_reconnects,
    computer_preview_and_approval_survive_a_crash,
    two_paired_computers_that_are_idle_exchange_nothing,
);

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
#[cfg(feature = "optional-proofs")]
use vox_core::node::computer::{
    computer_exchange_backoff, COMPUTER_QUIET_EXCHANGE_AFTER as FALLBACK_NAMED,
};
use vox_core::node::computer::{
    COMPUTER_CHANGE_SHOWN_WITHIN as CHANGE_SHOWN_WITHIN, COMPUTER_PAIR_WITHIN as PAIR_WITHIN,
    COMPUTER_RETURN_SHOWN_WITHIN as RETURN_WITHIN,
};
use vox_core::node::ipc::ACTOR_WITHIN;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const PASS: &str = "identity passphrase";
const ROOM_PASS: &str = "room passphrase for the daemon proof";
/// Deliberately larger than both the one-minute return contract and ten-minute pairing command.
/// A receiver that reconstructs a sender deadline from Unix time expires immediately under this
/// skew; duration-budget transport remains governed by each daemon's monotonic clock.
const REMOTE_CLOCK_SKEW_MS: &str = "3600000";

/// One account: a data root and a config directory, short enough for a socket path.
struct Account {
    _tmp: tempfile::TempDir,
    data: PathBuf,
    cfg: PathBuf,
}

impl Drop for Account {
    /// A daemon a client started for this account (no child of this proof) is stopped by the pid
    /// in its lock, however the proof ends.
    fn drop(&mut self) {
        world::reap_daemon(&self.data);
    }
}

impl Account {
    fn new() -> Self {
        let tmp = tempfile::Builder::new()
            .prefix("vd")
            // Short, for the socket path: macOS's /private/tmp, else /tmp (Linux).
            .tempdir_in(if cfg!(target_os = "macos") {
                "/private/tmp"
            } else {
                "/tmp"
            })
            .expect("APPARATUS: create isolated account directory");
        let data = tmp.path().join("d");
        let cfg = tmp.path().join("c");
        std::fs::create_dir_all(&cfg).expect("APPARATUS: create isolated config directory");
        std::fs::create_dir_all(tmp.path().join("home"))
            .expect("APPARATUS: create isolated home directory");
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
        c.args(unlock_staging::persistent_args(&self.data, args, PASS))
            .env("VOX_TEST_KEYCHAIN", unlock_staging::keychain(&self.data))
            .env("HOME", self._tmp.path().join("home"))
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env("VOX_LISTEN", "127.0.0.1:0")
            .env("VOX_IDENTITY_PASSPHRASE", PASS);
        c
    }

    /// Run `vox args` to its end with `stdin`.
    fn run(&self, args: &[&str], stdin: &str) -> (bool, String, String) {
        let mut cmd = self.cmd(args);
        // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028
        // K-13).
        if typed::is_keyring_change(args) || args.starts_with(&["node", "rename"]) {
            let (ok, shown) = typed::keyring(&cmd);
            return (ok, shown.clone(), shown);
        }
        let started = Instant::now();
        let bound = if args.starts_with(&["computer", "pair"]) {
            PAIR_WITHIN
        } else {
            ACTOR_WITHIN
        };
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: spawn vox {args:?}: {e}"));
        let mut input = child
            .stdin
            .take()
            .expect("APPARATUS: shipped vox command had no staged stdin");
        input
            .write_all(stdin.as_bytes())
            .expect("APPARATUS: write staged input to shipped vox command");
        drop(input);
        while child
            .try_wait()
            .unwrap_or_else(|e| panic!("APPARATUS: inspect shipped vox {args:?}: {e}"))
            .is_none()
        {
            if started.elapsed() >= bound {
                let _ = child.kill();
                let out = child.wait_with_output().unwrap_or_else(|e| {
                    panic!("APPARATUS: collect timed-out shipped vox {args:?}: {e}")
                });
                panic!(
                    "PRODUCT: shipped `vox {}` was still running after its source-owned \
                     {bound:?} {} contract; stdout: {}; stderr: {}",
                    args.join(" "),
                    if bound == PAIR_WITHIN {
                        "pairing"
                    } else {
                        "actor-liveness"
                    },
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let out = child
            .wait_with_output()
            .expect("APPARATUS: collect shipped vox command output");
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
        .expect("APPARATUS: list processes serving the isolated account");
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
    started: Instant,
}

impl Drop for Daemon {
    /// By its own handle, never by pattern: a proof that fails leaves no daemon behind.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    fn start(a: &Account, args: &[&str], env: &[(&str, &str)]) -> Self {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let out = a.data.with_extension(format!("daemon-{n}.out"));
        let f = std::fs::File::create(&out).expect("APPARATUS: create isolated daemon transcript");
        let mut c = a.cmd(&[&["daemon"], args].concat());
        for (k, v) in env {
            c.env(k, v);
        }
        if !env.iter().any(|(key, _)| *key == "VOX_TEST_FX28_MUTANT") {
            if let Ok(mutant) = std::env::var("VOX_TEST_FX28_MUTANT") {
                c.env("VOX_TEST_FX28_MUTANT", mutant);
            }
        }
        let started = Instant::now();
        let child = c
            .stdin(Stdio::null())
            .stdout(
                f.try_clone()
                    .expect("APPARATUS: clone scratch anchor transcript"),
            )
            .stderr(f)
            .spawn()
            .expect("APPARATUS: start shipped vox daemon");
        eprintln!("[test] vox daemon {args:?} pid {}", child.id());
        Self {
            child,
            out,
            started,
        }
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

    /// Wait for a causal setup event, not an elapsed-time proxy. An exited producer is an
    /// attributable apparatus fault; an operator-requested watchdog remains available for a
    /// genuinely wedged process.
    fn expect_apparatus_event(&mut self, what: &str, f: impl Fn(&str) -> bool) {
        self.expect_event_until(self.started + ACTOR_WITHIN, what, f);
    }

    fn expect_event_until(&mut self, deadline: Instant, what: &str, f: impl Fn(&str) -> bool) {
        loop {
            if self.said().lines().any(&f) {
                return;
            }
            if let Some(status) = self
                .child
                .try_wait()
                .unwrap_or_else(|e| panic!("APPARATUS: could not inspect daemon: {e}"))
            {
                panic!(
                    "APPARATUS: the daemon exited {status} before it said {what}:\n{}",
                    self.said()
                );
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT: the shipped process remained live but did not say {what} before its \
                 source-owned product deadline; it said:\n{}",
                self.said()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn stop(mut self) -> String {
        stop_pid(self.child.id());
        let _ = self.child.wait();
        self.said()
    }

    fn crash(mut self) -> String {
        let status = Command::new("kill")
            .args(["-KILL", &self.child.id().to_string()])
            .status()
            .expect("APPARATUS: send SIGKILL to scratch daemon");
        assert!(status.success(), "APPARATUS: SIGKILL scratch daemon");
        self.child
            .wait()
            .expect("APPARATUS: reap SIGKILLed scratch daemon");
        self.said()
    }
}

/// Wait for test apparatus produced by one shipped command. No elapsed time decides the result:
/// either the marker establishes the exact boundary, or an exited command/daemon names the
/// apparatus fault. An operator can opt into the suite watchdog when diagnosing a real wedge.
fn wait_for_command_marker(
    marker: &Path,
    command: &mut Child,
    daemon_pid: u32,
    deadline: Instant,
    what: &str,
) {
    loop {
        if marker.is_file() {
            return;
        }
        if let Some(status) = command
            .try_wait()
            .unwrap_or_else(|e| panic!("APPARATUS: could not inspect shipped command: {e}"))
        {
            panic!("APPARATUS: shipped command exited {status} before {what}");
        }
        assert!(
            daemon_alive(daemon_pid),
            "APPARATUS: daemon {daemon_pid} exited before {what}"
        );
        assert!(
            Instant::now() < deadline,
            "APPARATUS: the shipped command and daemon remained live but the test-knob marker \
             never established {what} before the staging deadline"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn read_daemon_marker(marker: &Path, daemon_pid: u32, what: &str) -> String {
    let deadline = Instant::now() + RETURN_WITHIN;
    loop {
        if let Ok(contents) = std::fs::read_to_string(marker) {
            return contents;
        }
        let fault = marker.with_extension("fault");
        if let Ok(contents) = std::fs::read_to_string(&fault) {
            panic!("APPARATUS: daemon could not publish {what}: {contents}");
        }
        assert!(
            daemon_alive(daemon_pid),
            "APPARATUS: daemon {daemon_pid} exited before {what}"
        );
        assert!(
            Instant::now() < deadline,
            "APPARATUS: the daemon remained live but did not publish {what} before the staging deadline"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Wait for a file boundary created by the daemon-side apparatus. Process death is attributable;
/// elapsed wall time is deliberately not the verdict.
fn wait_for_daemon_marker(marker: &Path, daemon: &mut Daemon, deadline: Instant, what: &str) {
    loop {
        if marker.is_file() {
            return;
        }
        if let Some(status) = daemon
            .child
            .try_wait()
            .unwrap_or_else(|e| panic!("APPARATUS: could not inspect daemon: {e}"))
        {
            panic!(
                "APPARATUS: daemon exited {status} before {what}:\n{}",
                daemon.said()
            );
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS: the shipped daemon remained live but the test-knob marker never \
             established {what} before the staging deadline; it said:\n{}",
            daemon.said()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Wait until the anchor's latest event-driven view names these exact live identities. An older
/// aggregate count cannot establish this precondition, and a later connection-state line
/// supersedes every earlier one.
fn wait_for_current_anchor_peers(anchor: &mut Daemon, peers: &[&str]) {
    loop {
        let transcript = anchor.said();
        let current = transcript
            .lines()
            .rev()
            .find(|line| line.starts_with("vox node:") && line.contains("peer(s) connected ["));
        if current.is_some_and(|line| peers.iter().all(|peer| line.contains(peer))) {
            return;
        }
        if let Some(status) = anchor
            .child
            .try_wait()
            .unwrap_or_else(|e| panic!("APPARATUS: could not inspect restored anchor: {e}"))
        {
            panic!(
                "APPARATUS: restored anchor exited {status} before its current view named the exact computer identities {peers:?}:\n{transcript}"
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn anchor_currently_has(anchor: &Daemon, peers: &[&str]) -> bool {
    anchor
        .said()
        .lines()
        .rev()
        .find(|line| line.starts_with("vox node:") && line.contains("peer(s) connected ["))
        .is_some_and(|line| peers.iter().all(|peer| line.contains(peer)))
}

/// A room on `node`, named after it (a node may hold one room of a name), made through the daemon
/// that holds it: its id.
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
            node,
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

/// LT-1–6 (#724): the app's saved personal-node choice is apparatus; every grant, join,
/// displayed alias, decision and restart is exercised through the shipped binary. No app runs.
/// Mutant: grant the personal node only Read; the personal-drive assertion must turn PRODUCT red.
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn local_nodes_trust_each_other_without_a_prompt_and_remember_removals() {
    watchdog::arm();
    let a = Account::new();
    let names = ["personal", "agent-one", "agent-two", "agent-three"];
    let fps: Vec<String> = names.iter().map(|name| a.make_node(name)).collect();
    let elsewhere = Account::new();
    // Management exists before any chat node, and cancelling a fresh code grants nothing.
    let empty_identity = computer(&elsewhere, &["status"])["this_computer"].clone();
    let empty_invite = computer(&elsewhere, &["invite"]);
    let cancel = empty_invite["invite_id"]
        .as_str()
        .expect("PRODUCT: Add Computer omitted its cancel identifier");
    assert_eq!(
        computer(&elsewhere, &["cancel", cancel])["state"],
        "individual",
        "PRODUCT: cancelling a node-free invitation left an enrollment"
    );
    let remote = elsewhere.make_node("remote");
    assert_eq!(
        computer(&elsewhere, &["status"])["this_computer"],
        empty_identity,
        "PRODUCT: creating a chat node replaced the computer identity"
    );
    let start = || {
        let mut daemons = Vec::new();
        for name in names {
            let daemon = Daemon::start(&a, &["--node", name], &[]);
            daemon.expect("its node attached", Duration::from_secs(90), |line| {
                line.starts_with("vox daemon: identity")
                    || line.contains(&format!(
                        "node {name} is held by the daemon already running"
                    ))
            });
            daemons.push(daemon);
        }
        daemons
    };
    let mut daemons = start();
    let person = names[0];
    let manual = |args: &[&str]| {
        let (ok, out, err) = a.run(args, "");
        assert!(
            ok,
            "APPARATUS: staging manual keyring choice {args:?}: {out}{err}"
        );
    };
    // Manual alias/capability and an alias collision must survive automation.
    manual(&[
        "trust",
        "add",
        &fps[2],
        "--name",
        "my-teammate",
        "--drive",
        "--node",
        names[1],
    ]);
    manual(&[
        "trust", "add", &remote, "--name", names[1], "--node", person,
    ]);
    manual(&[
        "trust", "add", &fps[3], "--name", names[3], "--node", names[2],
    ]);
    manual(&["trust", "remove", &fps[3], "--node", names[2]]);

    let room = make_room(&a, person);
    let (ok, link, err) = a.run(&["room", "link", &room, "--node", person], "");
    assert!(ok, "APPARATUS: personal node's invite: {err}");
    let link = link
        .lines()
        .find(|line| line.starts_with("vox://"))
        .expect("APPARATUS: the personal node printed a room link");
    let join = |node: &str| {
        let (ok, out, err) = a.run(
            &[
                "room",
                "join",
                link,
                "--node",
                node,
                "--passphrase-file",
                "-",
            ],
            ROOM_PASS,
        );
        assert!(ok, "PRODUCT: local node {node} could not join: {out}{err}");
        assert!(
            !out.contains("Your name for") && !err.contains("Your name for"),
            "PRODUCT: a known local node asked for its name: {out}{err}"
        );
    };
    join(names[1]);
    join(names[2]);

    let ring = |node: &str| {
        let (ok, out, err) = a.run(&["trust", "list", "--node", node], "");
        assert!(
            ok,
            "PRODUCT: {node}'s keyring could not be read: {out}{err}"
        );
        assert!(
            !out.contains("Your name for") && !err.contains("passphrase:"),
            "PRODUCT: local trust required a prompt: {out}{err}"
        );
        out
    };
    let absent = |node: &str, fp: &str| {
        let shown = ring(node);
        assert!(
            !shown.contains(fp),
            "PRODUCT: {node} unexpectedly trusts {fp}: {shown}"
        );
    };
    let has = |node: &str, fp: &str, alias: &str, drive: bool| {
        ring(node).lines().any(|line| {
            line.contains(fp) && line.contains(alias) && line.contains("read + drive") == drive
        })
    };
    // Joining rooms without any saved personal node must not enable local trust.
    absent(person, &fps[1]);
    absent(names[1], &fps[0]);
    absent(names[2], &fps[1]);
    absent(names[3], &fps[1]);
    // A detached passphrase-protected node is Locked in the app's vocabulary (ADR-031 CW-1).
    let (ok, out, err) = a.run(&["node", "detach", names[3]], "");
    assert!(ok, "APPARATUS: locking the late local node: {out}{err}");

    // Stage exactly the setting Vox.app persists when the person selects their node.
    std::fs::create_dir_all(a.cfg.join("app")).expect("APPARATUS: app choice directory");
    std::fs::write(a.cfg.join("app/node"), format!("{person}\n"))
        .expect("APPARATUS: saved personal-node choice");
    assert!(
        wait_until(Duration::from_secs(45), || {
            has(names[1], &fps[0], person, true) && has(names[2], &fps[0], person, true)
        }),
        "PRODUCT: personal drive was not granted; {} said: {}; {} said: {}; log: {}",
        names[1],
        ring(names[1]),
        names[2],
        ring(names[2]),
        a.log()
    );
    assert!(
        has(names[1], &fps[2], "my-teammate", true),
        "PRODUCT: local trust overwrote a custom alias or stronger manual grant: {}",
        ring(names[1])
    );
    let collision = format!("{}#{}", names[1], &fps[1][..6]);
    assert!(
        has(person, &fps[1], &collision, false),
        "PRODUCT: the known local name did not get the displayed fingerprint suffix: {}",
        ring(person)
    );
    absent(names[2], &fps[3]);
    let (ok, out, err) = a.run(&["trust", "list", "--node", names[3]], "");
    assert!(
        !ok,
        "PRODUCT: local trust unlocked a node by itself: {out}{err}"
    );
    let (ok, out, err) = a.run(
        &["node", "attach", names[3], "--passphrase-file", "-"],
        PASS,
    );
    assert!(
        ok,
        "PRODUCT: the person could not make their local node Ready: {out}{err}"
    );
    assert!(
        wait_until(Duration::from_secs(30), || has(
            names[3], &fps[1], names[1], false
        )),
        "PRODUCT: a formerly Locked node did not receive its local trust when Ready: {}",
        ring(names[3])
    );
    absent(names[3], &fps[2]);
    absent(names[3], &fps[0]); // It reads another local node, but does not share the personal room yet.
    join(names[3]);
    assert!(
        wait_until(Duration::from_secs(30), || has(
            names[3], &fps[0], person, true
        )),
        "PRODUCT: joining the personal room did not grant personal drive: {}",
        ring(names[3])
    );
    // This node has had no manual keyring operation. Its automatic grants must not open the
    // passphrase window, which is a permission the person sees in status.
    let (ok, out, err) = a.run(&["status", "--json", "--node", names[3]], "");
    assert!(
        ok,
        "PRODUCT: could not inspect the node's keyring window: {out}{err}"
    );
    let status: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: status was not JSON: {e}: {out}"));
    assert!(
        status
            .get("keyring_open_secs")
            .is_some_and(serde_json::Value::is_null),
        "PRODUCT: automatic local trust opened the keyring passphrase window: {out}"
    );
    for (i, node) in names.iter().enumerate() {
        for (j, other) in names.iter().enumerate() {
            if i == j || matches!((i, j), (2, 3) | (3, 2)) {
                continue;
            }
            let alias: &str = if (i, j) == (1, 2) {
                "my-teammate"
            } else if (i, j) == (0, 1) {
                &collision
            } else {
                other
            };
            let drive = j == 0 || (i, j) == (1, 2);
            assert!(
                wait_until(Duration::from_secs(30), || has(node, &fps[j], alias, drive)),
                "PRODUCT: {node}'s entry for {other} must say {alias} and drive={drive}: {}",
                ring(node)
            );
        }
        let (ok, out, err) = a.run(&["decisions", "--node", node, "--json"], "");
        assert!(
            ok && out.contains("local trust rule"),
            "PRODUCT: {node}'s decision record omitted automatic local trust: {out}{err}"
        );
    }
    // A public keyring entry is useful only if the nodes can read a real room message.
    let text = "local trust lets us work together";
    let (ok, out, err) = a.run(&["room", "post", &room, text, "--node", names[3]], "");
    assert!(
        ok,
        "PRODUCT: automatically trusted node could not post: {out}{err}"
    );
    assert!(
        wait_until(Duration::from_secs(30), || {
            let (ok, out, _) = a.run(&["room", "read", &room, "--node", person], "");
            ok && out.contains(text)
        }),
        "PRODUCT: personal node could not read its automatically trusted local member"
    );

    manual(&["trust", "remove", &fps[3], "--node", names[1]]);
    absent(names[1], &fps[3]);
    // Stop only this proof's daemon, then reopen the same identities, room and keyrings.
    let pid = a.lock_pid().expect("APPARATUS: the scratch daemon pid");
    stop_pid(pid);
    daemons.clear();
    daemons = start();
    // A saved grant only proves the keyring loaded. Join a new local node and wait for its
    // first personal-drive grant, so removal assertions run after automation has resumed.
    let fresh = "new-after-restart";
    let fresh_fp = a.make_node(fresh);
    let daemon = Daemon::start(&a, &["--node", fresh], &[]);
    daemon.expect("the new node attached", Duration::from_secs(90), |line| {
        line.contains(&format!(
            "node {fresh} is held by the daemon already running"
        ))
    });
    daemons.push(daemon);
    let (ok, link, err) = a.run(&["room", "link", &room, "--node", person], "");
    assert!(ok, "APPARATUS: the restarted room's link: {link}{err}");
    let link = link
        .lines()
        .find(|line| line.starts_with("vox://"))
        .expect("APPARATUS: the restarted room printed no link");
    let (ok, out, err) = a.run(
        &[
            "room",
            "join",
            link,
            "--node",
            fresh,
            "--passphrase-file",
            "-",
        ],
        ROOM_PASS,
    );
    assert!(ok, "PRODUCT: the new local node could not join: {out}{err}");
    assert!(
        wait_until(Duration::from_secs(45), || {
            has(fresh, &fps[0], person, true) && has(person, &fresh_fp, fresh, false)
        }),
        "PRODUCT: local trust did not resume for the new node after restart: {}; {}",
        ring(fresh),
        ring(person)
    );
    assert!(
        wait_until(Duration::from_secs(45), || has(
            names[3], &fps[0], person, true
        )),
        "PRODUCT: personal drive was lost after restart: {}",
        ring(names[3])
    );
    absent(names[1], &fps[3]);
    absent(names[2], &fps[3]);
    absent(names[3], &fps[2]);
    assert!(
        has(names[1], &fps[2], "my-teammate", true),
        "PRODUCT: restart lost the pre-existing custom alias or drive grant: {}",
        ring(names[1])
    );
    manual(&[
        "trust",
        "add",
        &fps[3],
        "--name",
        "back-by-choice",
        "--node",
        names[1],
    ]);
    assert!(
        has(names[1], &fps[3], "back-by-choice", false),
        "PRODUCT: the person could not restore a removed local peer by hand: {}",
        ring(names[1])
    );
    pair_computers(
        &a,
        &elsewhere,
        &fps,
        &remote,
        fresh,
        &fresh_fp,
        &room,
        &mut daemons,
    );
    close_expired_pairing();
}

/// #799 extends the same real account/keyring/room journey: computer mode is explicit, consumes
/// covered individual grants, and survives restart without changing any room membership.
fn computer(a: &Account, args: &[&str]) -> serde_json::Value {
    let args: Vec<_> = [vec!["computer"], args.to_vec(), vec!["--json"]].concat();
    let (ok, out, err) = a.run(&args, "");
    assert!(ok, "PRODUCT: computer {} failed: {err}", args[1]);
    serde_json::from_str(&out).unwrap_or_else(|e| {
        panic!(
            "PRODUCT: computer {} did not show readable status: {e}: {out}",
            args[1]
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn pair_computers(
    a: &Account,
    b: &Account,
    local: &[String],
    remote: &str,
    late: &str,
    late_fp: &str,
    room: &str,
    daemons: &mut Vec<Daemon>,
) {
    computer(a, &["personal", "personal"]);
    let other_agent = b.make_node("remote-agent");
    for node in ["remote", "remote-agent"] {
        let (ok, out, err) = b.run(&["node", "attach", node, "--passphrase-file", "-"], PASS);
        assert!(ok, "APPARATUS: attach remote pairing node: {out}{err}");
    }
    std::fs::create_dir_all(b.cfg.join("app")).unwrap();
    std::fs::write(b.cfg.join("app/node"), "remote\n").unwrap();
    computer(b, &["personal", "remote"]);
    let ring = |account: &Account, node: &str| {
        let (ok, out, err) = account.run(&["trust", "list", "--node", node], "");
        assert!(ok, "PRODUCT: {node}'s keyring was unavailable: {out}{err}");
        out
    };
    // A stronger individual grant must be consumed before this protected node comes online
    // under computer policy, even when its remote computer is offline at that moment.
    let (ok, out, err) = a.run(&["trust", "drive", &local[2], "--node", late], "");
    assert!(
        ok,
        "APPARATUS: stage the late node's stronger manual drive: {out}{err}"
    );
    assert!(
        ring(a, late)
            .lines()
            .any(|line| line.contains(&local[2]) && line.contains("read + drive")),
        "APPARATUS: the late node did not retain the stronger manual grant"
    );
    let individual = ring(a, "agent-one");
    let rooms_before = a.run(&["room", "list", "--node", "personal"], "").1;
    let foreign_rooms_before = b.run(&["room", "list", "--node", "remote"], "").1;
    let original_identity = computer(a, &["status"])["this_computer"].clone();
    let remote_identity = computer(b, &["status"])["this_computer"].clone();
    assert_ne!(
        original_identity["fingerprint"].as_str(),
        Some(local[0].as_str()),
        "PRODUCT: management reused a chat identity"
    );
    assert_ne!(
        original_identity["fingerprint"], remote_identity["fingerprint"],
        "PRODUCT: separate data roots shared a computer identity"
    );
    let mut marked = b.cmd(&["computer", "invite", "--json"]);
    let refused = marked
        .env("CODEX_THREAD_ID", "proof-agent")
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "PRODUCT: a marked agent began computer trust"
    );
    assert_eq!(
        computer(b, &["status"])["state"],
        "individual",
        "PRODUCT: refused agent request changed pairing state"
    );
    let offered = computer(a, &["invite"]);
    let link = offered["invite_link"]
        .as_str()
        .expect("PRODUCT: Add Computer did not show a pairing link");
    let (ok, _, err) = a.run(&["computer", "pair", link, "--preview", "--json"], "");
    assert!(
        !ok && err.contains("this installation"),
        "PRODUCT: a computer accepted its own pairing invitation: {err}"
    );
    // Test-side attacker: alter only the PAKE secret, preserving a canonical, reachable link.
    use base64::Engine as _;
    let mut wrong = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(link.strip_prefix("vox-computer://").unwrap())
        .unwrap();
    let secret = {
        let mut d = vox_core::cbor::Decoder::new(&wrong);
        d.array().unwrap();
        d.uint().unwrap();
        d.bytes().unwrap();
        d.bytes().unwrap();
        d.bytes().unwrap().to_vec()
    };
    let at = wrong
        .windows(secret.len())
        .position(|w| w == secret)
        .expect("APPARATUS: pairing secret in canonical link");
    wrong[at] ^= 1;
    let wrong = format!(
        "vox-computer://{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wrong)
    );
    let (ok, _, err) = b.run(&["computer", "pair", &wrong, "--preview", "--json"], "");
    assert!(
        !ok,
        "PRODUCT: incorrect computer pairing code was accepted: {err}"
    );
    assert_eq!(
        computer(b, &["status"])["state"],
        "individual",
        "PRODUCT: incorrect code created an authenticated approval candidate"
    );
    let preview = computer(b, &["pair", link, "--preview"]);
    assert_eq!(preview["pairing"]["peer"], original_identity, "PRODUCT: preview did not show the authenticated computer fingerprint/name/install discriminator");
    let operation = preview["pairing"]["operation_id"].as_str().unwrap();
    assert_eq!(
        ring(a, "agent-one"),
        individual,
        "PRODUCT: preview changed individual trust before approval"
    );
    let first = computer(b, &["approve", operation]);
    assert!(
        first["state"] != "confirmed" && first["computers"].as_array().unwrap().is_empty(),
        "PRODUCT: one operator's approval established computer trust: {first}"
    );
    let (ok, out, err) = a.run(&["node", "detach", late], "");
    assert!(
        ok,
        "APPARATUS: detaching the late protected node: {out}{err}"
    );
    computer(a, &["approve", operation]);
    assert!(
        wait_until(Duration::from_secs(45), || computer(a, &["status"])
            ["state"]
            == "applying"
            && computer(a, &["status"])["pending_nodes"]
                .to_string()
                .contains(late)),
        "PRODUCT: protected node was silently unlocked or reported applied"
    );
    // Observe the complete current roster on an already attached node, then take the remote
    // computer offline. Neither a later remote roster nor a late local binding can repair an
    // attach that falsely reports its policy applied. This is staging, not a timing assertion.
    let current_peers = [
        ("personal", local[0].as_str(), true),
        ("agent-one", local[1].as_str(), false),
        ("agent-two", local[2].as_str(), false),
        ("agent-three", local[3].as_str(), false),
        ("remote", remote, true),
        ("remote-agent", other_agent.as_str(), false),
    ];
    assert!(wait_until(Duration::from_secs(45), || {
        let (ok, shown, _) = a.run(&["trust", "list", "--node", "agent-one"], "");
        ok && current_peers.iter().filter(|(_, fp, _)| *fp != local[1]).all(|(_, fp, drive)| shown.lines().any(|line| line.contains(fp) && line.contains("read + drive") == *drive))
    }), "PRODUCT: the complete current local/remote roster was not visible before offline attach; agent-one: {}", ring(a, "agent-one"));
    let remote_pid = b
        .lock_pid()
        .expect("APPARATUS: remote scratch daemon before offline attach");
    stop_pid(remote_pid);
    assert!(
        !alive(remote_pid),
        "APPARATUS: remote scratch daemon did not stop before offline attach"
    );
    let (ok, out, err) = a.run(&["node", "attach", late, "--passphrase-file", "-"], PASS);
    assert!(
        ok,
        "PRODUCT: ordinary attach could not apply pending computer trust: {out}{err}"
    );
    // Read the attached node's actual effective keyring now, without polling for a later repair.
    // A skipped keyring application can neither omit a managed peer nor keep manual drive to a
    // non-personal peer behind a successful attach/receipt.
    let attached = ring(a, late);
    for (name, fp, drive) in current_peers {
        assert!(attached.lines().any(|line| line.contains(fp) && line.contains("read + drive") == drive), "PRODUCT: {late} attached while its paired computer was offline but its effective grant for {name} was not read with drive={drive}: {attached}");
    }
    for node in ["remote", "remote-agent"] {
        let (ok, out, err) = b.run(&["node", "attach", node, "--passphrase-file", "-"], PASS);
        assert!(
            ok,
            "APPARATUS: restore the paired computer after the offline attach assertion: {out}{err}"
        );
    }
    assert!(
        wait_until(Duration::from_secs(60), || computer(a, &["status"])
            ["state"]
            == "confirmed"
            && computer(b, &["status"])["state"] == "confirmed"),
        "PRODUCT: both approved computers did not confirm applied policy: {}; {}; logs: {}; {}",
        computer(a, &["status"]),
        computer(b, &["status"]),
        a.log(),
        b.log()
    );
    // Both personal nodes grant read only; non-personal nodes grant drive to both personal nodes.
    let nodes = [
        (a, "personal", local[0].as_str(), true),
        (a, "agent-one", local[1].as_str(), false),
        (a, "agent-two", local[2].as_str(), false),
        (a, late, late_fp, false),
        (b, "remote", remote, true),
        (b, "remote-agent", other_agent.as_str(), false),
    ];
    for (account, name, fp, personal) in nodes {
        let shown = ring(account, name);
        for (_, other, peer, peer_personal) in nodes {
            if peer == fp {
                continue;
            }
            let expected_drive = !personal && peer_personal;
            assert!(shown.lines().any(|line| line.contains(peer) && line.contains("read + drive") == expected_drive), "PRODUCT: fixed computer policy {name} → {other} drive={expected_drive} was not applied: {shown}");
        }
    }
    assert!(ring(a, "agent-one").lines().any(|line| line.contains(&local[2]) && line.contains("my-teammate") && !line.contains("read + drive")), "PRODUCT: computer mode failed to consume stronger covered manual drive while preserving its alias");
    let (ok, _, err) = a.run(&["trust", "drive", &local[2], "--node", "agent-one"], "");
    assert!(
        !ok && err.contains("computer"),
        "PRODUCT: individual grant silently overrode computer mode: {err}"
    );
    assert_eq!(
        a.run(&["room", "list", "--node", "personal"], "").1,
        rooms_before,
        "PRODUCT: pairing changed local room membership"
    );
    assert_eq!(
        b.run(&["room", "list", "--node", "remote"], "").1,
        foreign_rooms_before,
        "PRODUCT: pairing joined a foreign room without its passphrase"
    );
    let (ok, link, err) = a.run(&["room", "link", room, "--node", "personal"], "");
    assert!(ok, "APPARATUS: get existing room's invitation: {err}");
    let link = link.lines().find(|l| l.starts_with("vox://")).unwrap();
    let (ok, out, err) = b.run(
        &[
            "room",
            "join",
            link,
            "--node",
            "remote-agent",
            "--passphrase-file",
            "-",
        ],
        ROOM_PASS,
    );
    assert!(
        ok,
        "PRODUCT: paired node could not separately join with the room passphrase: {out}{err}"
    );
    let text = "computer trust works after explicit room admission";
    let (ok, out, err) = b.run(&["room", "post", room, text, "--node", "remote-agent"], "");
    assert!(ok, "PRODUCT: paired member could not post: {out}{err}");
    assert!(
        wait_until(Duration::from_secs(30), || a
            .run(&["room", "read", room, "--node", "agent-one"], "")
            .1
            .contains(text)),
        "PRODUCT: computer-trusted member's room message did not become readable"
    );
    let before = ring(a, "agent-one");
    stop_pid(a.lock_pid().expect("APPARATUS: local scratch daemon"));
    stop_pid(b.lock_pid().expect("APPARATUS: remote scratch daemon"));
    for (account, node, _, _) in nodes {
        let (ok, out, err) = account.run(&["node", "attach", node, "--passphrase-file", "-"], PASS);
        assert!(ok, "PRODUCT: restart could not attach {node}: {out}{err}");
    }
    // agent-three participates in the retained roster too.
    let (ok, out, err) = a.run(
        &["node", "attach", "agent-three", "--passphrase-file", "-"],
        PASS,
    );
    assert!(
        ok,
        "PRODUCT: restart could not attach agent-three: {out}{err}"
    );
    assert_eq!(
        computer(a, &["status"])["this_computer"],
        original_identity,
        "PRODUCT: computer identity changed on restart"
    );
    assert_eq!(
        computer(b, &["status"])["this_computer"],
        remote_identity,
        "PRODUCT: other computer identity changed on restart"
    );
    assert_eq!(
        ring(a, "agent-one"),
        before,
        "PRODUCT: restart changed applied policy or local names"
    );
    assert!(
        wait_until(Duration::from_secs(60), || computer(a, &["status"])
            ["state"]
            == "confirmed"
            && computer(b, &["status"])["state"] == "confirmed"),
        "PRODUCT: paired computer confirmation did not recover after restart"
    );
    let retried = computer(a, &["approve", operation]);
    assert!(retried["state"]=="confirmed" && retried["pairing"].is_null(),
        "PRODUCT: retrying the completed approval reopened a ceremony or lost confirmation: {retried}");
    enroll_third(
        a,
        b,
        local,
        remote,
        late,
        late_fp,
        &other_agent,
        room,
        daemons,
    );
    // A policy write failure must stop previously working computer-derived authority, not leave
    // the old receipt looking confirmed. Make only this scratch management directory unwritable.
    a.make_node("storage-failure-node");
    use std::os::unix::fs::PermissionsExt as _;
    let management = a.data.join(".daemon/computer");
    std::fs::set_permissions(&management, std::fs::Permissions::from_mode(0o500)).unwrap();
    let (ok, out, err) = a.run(
        &[
            "node",
            "attach",
            "storage-failure-node",
            "--passphrase-file",
            "-",
        ],
        PASS,
    );
    std::fs::set_permissions(&management, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        !ok,
        "PRODUCT: a managed node attached although its new policy could not be saved: {out}{err}"
    );
    let failed = computer(a, &["status"]);
    assert!(
        failed["state"] == "quarantined"
            && failed["problem"]
                .as_str()
                .is_some_and(|p| p.contains("storage")),
        "PRODUCT: failed policy persistence retained a confirmed success: {failed}"
    );
    let (ok, out, err) = a.run(
        &[
            "room",
            "post",
            room,
            "must not use stale computer grants",
            "--node",
            "agent-one",
        ],
        "",
    );
    assert!(!ok, "PRODUCT: previously attached node still posted under stale computer policy after a failed write: {out}{err}");
}

// This scenario measures a computer being unavailable, not graceful shutdown timing. Keep
// the daemon's log if SIGTERM does not establish staging, then use the existing scratch crash
// helper and verify that no daemon holds this account's lock before continuing.
fn offline_for_enrollment(account: &Account, label: &str) {
    if let Some(pid) = world::daemon_pid(&account.data) {
        stop_pid(pid);
    }
    if world::daemon_pid(&account.data).is_some() {
        eprintln!("APPARATUS: {label} did not release its lock after SIGTERM; staging a scratch host loss. Daemon log: {}",account.log());
        world::kill_daemon(&account.data);
    }
    assert!(
        world::daemon_pid(&account.data).is_none(),
        "APPARATUS: {label} still holds its daemon lock after scratch hard-stop"
    );
}

// #800 extends this same trust journey through a non-founding member. The first computer is
// deliberately offline for enrollment; its eventual application must come from signed history.
#[allow(clippy::too_many_arguments)]
fn enroll_third(
    a: &Account,
    b: &Account,
    local: &[String],
    remote: &str,
    late: &str,
    late_fp: &str,
    other_agent: &str,
    room: &str,
    daemons: &mut Vec<Daemon>,
) {
    let c = Account::new();
    let beast = c.make_node("codex-beast");
    let helper = c.make_node("opencode-beast");
    for name in ["codex-beast", "opencode-beast"] {
        let (ok, out, err) = c.run(&["node", "attach", name, "--passphrase-file", "-"], PASS);
        assert!(
            ok,
            "APPARATUS: attach the third installation's nodes: {out}{err}"
        );
    }
    let a_id = computer(a, &["status"])["this_computer"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    let b_id = computer(b, &["status"])["this_computer"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    let c_id = computer(&c, &["status"])["this_computer"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    // Retire every owned foreground holder only after the founder's last command. A holder
    // takes over when its daemon stops; dropping it can also stop the daemon if it now owns it.
    // Nothing starts on this account again until the explicit catch-up attach below.
    daemons.clear();
    offline_for_enrollment(a, "founder");
    let invite = computer(b, &["invite"]);
    let link = invite["invite_link"]
        .as_str()
        .expect("PRODUCT: enrolled member did not offer Add Computer");
    let preview = computer(&c, &["pair", link, "--preview"]);
    let op = preview["pairing"]["operation_id"].as_str().unwrap();
    assert!(preview["computers"].as_array().unwrap().is_empty(),"PRODUCT: receiving an existing group's history enrolled the third computer before approval: {preview}");
    computer(&c, &["approve", op]);
    computer(b, &["approve", op]);
    let ring = |account: &Account, name: &str| {
        let (ok, out, err) = account.run(&["trust", "list", "--node", name], "");
        assert!(
            ok,
            "PRODUCT: group member {name}'s keyring unavailable: {out}{err}"
        );
        out
    };
    let has = |shown: &str, fp: &str, drive: bool| {
        shown
            .lines()
            .any(|line| line.contains(fp) && line.contains("read + drive") == drive)
    };
    assert!(wait_until(Duration::from_secs(60),|| {
        let bs=computer(b,&["status"]);let cs=computer(&c,&["status"]);
        bs["computers"].as_array().is_some_and(|v|v.len()==3)&&cs["computers"].as_array().is_some_and(|v|v.len()==3)
            &&has(&ring(b,"remote-agent"),&beast,false)&&has(&ring(&c,"codex-beast"),remote,true)&&has(&ring(&c,"codex-beast"),&local[0],true)
    }),"PRODUCT: third computer did not join the existing group through its non-founding member while the founder was offline: {}; {}",computer(b,&["status"]),computer(&c,&["status"]));
    let pending = computer(b, &["status"]);
    assert!(
        pending["state"] != "confirmed"
            && pending["applications"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["computer"]["fingerprint"] == a_id && v["confirmed"] == false),
        "PRODUCT: unreachable founder was reported as having applied the new enrollment: {pending}"
    );
    assert!(
        c.run(&["room", "list", "--node", "codex-beast"], "")
            .1
            .trim()
            == "no rooms",
        "PRODUCT: group enrollment admitted the third computer to a room"
    );
    // Stop the sponsor too. Catch-up must be possible from the new equal member's authenticated
    // retained history, not an online founder/sponsor vote or a second pairing ceremony.
    offline_for_enrollment(b, "sponsor");
    for name in ["personal", "agent-one", "agent-two", "agent-three", late] {
        let (ok, out, err) = a.run(&["node", "attach", name, "--passphrase-file", "-"], PASS);
        assert!(
            ok,
            "PRODUCT: original member could not resume for group catch-up: {out}{err}"
        );
    }
    assert!(wait_until(Duration::from_secs(60),||has(&ring(a,"agent-one"),&beast,false)&&has(&ring(a,"agent-one"),&helper,false)),"PRODUCT: the third computer's signed enrollment did not propagate to the original member without the sponsor: {}",ring(a,"agent-one"));
    for (account, name, personal) in [
        (a, "personal", true),
        (a, "agent-one", false),
        (&c, "codex-beast", false),
        (&c, "opencode-beast", false),
    ] {
        let own = if name == "personal" {
            local[0].as_str()
        } else if name == "agent-one" {
            local[1].as_str()
        } else if name == "codex-beast" {
            beast.as_str()
        } else {
            helper.as_str()
        };
        let peers = [
            (local[0].as_str(), true),
            (local[1].as_str(), false),
            (late_fp, false),
            (remote, true),
            (other_agent, false),
            (beast.as_str(), false),
            (helper.as_str(), false),
        ];
        let shown = ring(account, name);
        for (fp, peer_personal) in peers {
            if fp != own {
                assert!(has(&shown,fp,!personal&&peer_personal),"PRODUCT: propagated group policy for {name} has wrong read/drive for {fp}: {shown}");
            }
        }
    }
    let (ok, link, err) = a.run(&["room", "link", room, "--node", "personal"], "");
    assert!(
        ok,
        "APPARATUS: existing room invitation after restart: {err}"
    );
    let link = link.lines().find(|s| s.starts_with("vox://")).unwrap();
    let (ok, out, err) = c.run(
        &[
            "room",
            "join",
            link,
            "--node",
            "codex-beast",
            "--passphrase-file",
            "-",
        ],
        ROOM_PASS,
    );
    assert!(ok,"PRODUCT: third computer could not independently join the room after group enrollment: {out}{err}");
    let text = "third computer communicates while its enrolling sponsor is offline";
    let (ok, out, err) = c.run(&["room", "post", room, text, "--node", "codex-beast"], "");
    assert!(
        ok,
        "PRODUCT: third enrolled computer could not post without sponsor: {out}{err}"
    );
    assert!(
        wait_until(Duration::from_secs(30), || a
            .run(&["room", "read", room, "--node", "agent-one"], "")
            .1
            .contains(text)),
        "PRODUCT: original member could not read the third computer without its sponsor"
    );
    for name in ["remote", "remote-agent"] {
        let (ok, out, err) = b.run(&["node", "attach", name, "--passphrase-file", "-"], PASS);
        assert!(ok, "PRODUCT: sponsor restart failed: {out}{err}");
    }
    assert!(
        wait_until(Duration::from_secs(60), || [a, b, &c].into_iter().all(
            |account| {
                let st = computer(account, &["status"]);
                st["state"] == "confirmed"
                    && st["applications"]
                        .as_array()
                        .is_some_and(|v| v.len() == 3 && v.iter().all(|v| v["confirmed"] == true))
            }
        )),
        "PRODUCT: group confirmations did not converge after all three reconnected: {}; {}; {}",
        computer(a, &["status"]),
        computer(b, &["status"]),
        computer(&c, &["status"])
    );
    for account in [a, b, &c] {
        let st = computer(account, &["status"]);
        for id in [&a_id, &b_id, &c_id] {
            assert!(
                st["computers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v["fingerprint"] == *id),
                "PRODUCT: group identity changed during catch-up: {st}"
            );
        }
    }
}

// A signed but incomplete ceremony can be closed after its authenticated deadline, without
// claiming to withdraw the signature from an offline peer. A later old result cannot replace a
// fresh local invitation. The existing release/test-knobs clock step avoids sleeping ten minutes.
fn close_expired_pairing() {
    let a = Account::new();
    let b = Account::new();
    let invitation = computer(&a, &["invite"]);
    let link = invitation["invite_link"].as_str().unwrap();
    let preview = computer(&b, &["pair", link, "--preview"]);
    let op = preview["pairing"]["operation_id"].as_str().unwrap();
    computer(&a, &["approve", op]);
    assert!(
        wait_until(Duration::from_secs(15), || computer(&b, &["status"])
            ["pairing"]["approved_there"]
            == true),
        "APPARATUS: joiner has not yet received the signed one-sided approval"
    );
    for id in [op, invitation["invite_id"].as_str().unwrap()] {
        let (ok, out, err) = a.run(&["computer", "cancel", id, "--json"], "");
        assert!(!ok && err.contains("already signed"), "PRODUCT: live signed approval was described as withdrawn using its operation or saved invite ID: {out}{err}");
    }
    stop_pid(a.lock_pid().expect("APPARATUS: expiring scratch daemon"));
    let stepped = Daemon::start(&a, &["--no-node"], &[("VOX_TEST_CLOCK_STEP_MS", "700000")]);
    stepped.expect("its control socket", Duration::from_secs(30), |l| {
        l.contains("control socket")
    });
    let closed = computer(&a, &["cancel", op]);
    assert!(
        closed["state"] == "individual"
            && closed["problem"]
                .as_str()
                .is_some_and(|p| p.contains("does not remove trust there")),
        "PRODUCT: closing an expired attempt did not explain its local-only outcome: {closed}"
    );
    let fresh = computer(&a, &["invite"]);
    assert!(
        fresh["invite_id"] != invitation["invite_id"] && fresh["pairing"].is_null(),
        "PRODUCT: an expired one-sided approval stranded this computer: {fresh}"
    );
    computer(&b, &["approve", op]);
    assert!(
        wait_until(Duration::from_secs(15), || computer(&b, &["status"])
            ["problem"]
            .as_str()
            .is_some_and(|p| p.contains("closed locally"))),
        "PRODUCT: late completed intent was not refused after the other computer closed it: {}",
        computer(&b, &["status"])
    );
    let after = computer(&a, &["status"]);
    assert!(
        after["state"] == "waiting"
            && after["invite_id"] == fresh["invite_id"]
            && after["computers"].as_array().unwrap().is_empty(),
        "PRODUCT: late old approval activated or replaced the fresh local pairing: {after}"
    );
    computer(&a, &["cancel", op]);
    assert_eq!(
        computer(&a, &["status"])["invite_id"],
        fresh["invite_id"],
        "PRODUCT: retrying close of the old attempt cancelled the new invitation"
    );
    drop(stepped);
}

/// **The exact pairing preview and local approval survive a daemon crash** (ADR-038 FX-28;
/// #1020). Two real shipped daemons reach an authenticated preview, beta approves the displayed
/// operation, and beta is terminated before the other operator approves. After restart, shipped
/// status must show that same peer, operation and local approval. The mutant which omits the
/// preview and approval-bearing enrollment from the saved snapshot loses this user-visible
/// intent at the crash boundary.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional two real vox daemons with production Argon2id; run in release with optional-proofs"]
fn computer_preview_and_approval_survive_a_crash() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_FX28_MUTANT"]);
    let a = Account::new();
    let b = Account::new();
    let alpha = a.make_node("alpha");
    let beta = b.make_node("beta");
    let mut da = Daemon::start(&a, &["--node", "alpha"], &[]);
    let mut db = Daemon::start(&b, &["--node", "beta"], &[]);
    da.expect_apparatus_event("node alpha is Ready", |line| {
        line.contains("alpha is Ready")
    });
    db.expect_apparatus_event("node beta is Ready", |line| line.contains("beta is Ready"));
    computer(&a, &["personal", "alpha"]);
    computer(&b, &["personal", "beta"]);
    let invitation = computer(&a, &["invite"]);
    let link = invitation["invite_link"]
        .as_str()
        .expect("PRODUCT: Add Computer did not show a pairing link");
    let preview = computer(&b, &["pair", link, "--preview"]);
    let operation = preview["pairing"]["operation_id"]
        .as_str()
        .expect("PRODUCT: pairing preview names no operation")
        .to_owned();
    let peer = preview["pairing"]["peer"].clone();
    let approved = computer(&b, &["approve", &operation]);
    assert!(
        approved["pairing"]["operation_id"] == operation
            && approved["pairing"]["approved_here"] == true,
        "APPARATUS: shipped approval did not stage the displayed operation before crash: {approved}"
    );
    println!(
        "[proof] FX-28 preview-approval-crash apparatus staged: beta durably recorded the exact authenticated preview and local approval before its daemon crash"
    );
    let _ = db.crash();
    let restarted = Instant::now();
    let mut db = Daemon::start(&b, &["--node", "beta"], &[]);
    db.expect_event_until(
        restarted + RETURN_WITHIN,
        "node beta is Ready after the preview/approval crash",
        |line| line.contains("beta is Ready"),
    );
    let after = computer(&b, &["status"]);
    assert!(
        restarted.elapsed() <= RETURN_WITHIN
            && after["pairing"]["operation_id"] == operation
            && after["pairing"]["peer"] == peer
            && after["pairing"]["approved_here"] == true,
        "PRODUCT [FX28 preview-approval-crash]: after beta crashed with the authenticated preview and its local approval recorded, restarted shipped status did not show the same peer, operation and approval within {RETURN_WITHIN:?}: before {approved}; after {after}; daemon {}",
        db.said()
    );
    // Keep both identities live through the verdict; setup never substitutes an in-process node.
    assert!(
        !alpha.is_empty() && !beta.is_empty() && daemon_alive(da.child.id()),
        "APPARATUS: a staged shipped identity or the other daemon disappeared before the crash verdict"
    );
}

/// CT-11, CT-9 and FX-28: two installations on opposite address families pair through a public
/// anchor. With the remote daemon and anchor gone there is no retained computer connection; two
/// local policy revisions overlap the failed exchange. The remote daemon returns while the anchor
/// remains gone, then only the remote anchor returns. Both revisions still cross within the first
/// revision's causal return contract. The split-family staging makes direct packets impossible
/// without firewall/root.
/// A final outage is held until shipped status names the causal deadline miss; restoration repairs
/// that revision late, and the miss remains visible through a same-state failed preview and daemon
/// restart.
///
/// Independent mutants: removing the stale-flight deadline handoff makes the first revision's
/// deadline move; omitting `retry_ready` from operator takeover lets the shipped preview outlive
/// that deadline; omitting the post-reservation supersession check lets a stale operator pairing
/// survive the newer policy revision; requiring a retained peer connection strands the repair;
/// discarding failed transport work means the remote anchor's return never causes registration;
/// ignoring a marker-only authorization change leaves the causally staged grant in the shipped
/// effective keyring; clearing a late success hides the missed contract before preview/restart;
/// dropping the prepared rollback set from an expired plan leaves its exact grant effective;
/// bypassing only the final state-locked Ready fence publishes the applied receipt after its
/// revision durably expired;
/// omitting the durable pre-keyring recovery record leaves a newly committed grant effective
/// after an exact commit-boundary crash and restart.
/// Each reaches a PRODUCT deadline/roster assertion, while inability to stage an exact race is
/// APPARATUS.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional real binaries with production Argon2id; run in release with optional-proofs"]
fn computer_pairing_uses_an_anchor_without_room_membership_and_reconnects() {
    watchdog::arm();
    test_knobs::require(&[
        "VOX_TEST_HOLD_FIRST_COMPUTER_EXCHANGE_FILE",
        "VOX_TEST_HOLD_COMPUTER_RETRY_READY_FILE",
        "VOX_TEST_HOLD_COMPUTER_OPERATOR_RESERVED_FILE",
        "VOX_TEST_HOLD_COMPUTER_ANSWER_AFTER_MERGE_FILE",
        "VOX_TEST_HOLD_AFTER_COMPUTER_APPLICATION_PREPARED_FILE",
        "VOX_TEST_HOLD_AFTER_COMPUTER_APPLICATION_RECEIPT_FILE",
        "VOX_TEST_HOLD_COMPUTER_RECONCILE_SEND_FILE",
        "VOX_TEST_CRASH_AFTER_COMPUTER_KEYRING_COMMIT_FILE",
    ]);
    let anchor = Account::new();
    let a = Account::new();
    let b = Account::new();
    let start_anchor = |listen: &str| {
        let out = anchor.data.with_extension("anchor.out");
        let f = std::fs::File::create(&out).expect("APPARATUS: anchor transcript");
        let started = Instant::now();
        let child = anchor
            .cmd(&["node", "--listen", listen, "--serve", "anyone"])
            .stdin(Stdio::null())
            .stdout(
                f.try_clone()
                    .expect("APPARATUS: clone scratch anchor transcript"),
            )
            .stderr(f)
            .spawn()
            .expect("APPARATUS: start scratch anchor");
        let mut process = Daemon {
            child,
            out,
            started,
        };
        process.expect_apparatus_event("its advertised anchor address", |line| {
            line.contains('@') && line.contains("/udp/")
        });
        process
    };
    let mut relay = start_anchor("[::]:0");
    let transcript = relay.said();
    let spec = transcript
        .lines()
        .map(str::trim)
        .find(|line| line.contains('@') && line.contains("/udp/"))
        .expect("APPARATUS: anchor address");
    let (fp, addr) = spec
        .split_once('@')
        .expect("APPARATUS: advertised anchor address had no identity separator");
    let port = addr
        .rsplit('/')
        .next()
        .expect("APPARATUS: advertised anchor address had no UDP port");
    let v4 = format!("{fp}@/ip4/127.0.0.1/udp/{port}");
    let v6 = format!("{fp}@/ip6/::1/udp/{port}");
    let anchor_listen = format!("[::]:{port}");
    let first_flight_arm = a.data.join("hold-first-computer-exchange");
    let first_flight_engaged = a.data.join("held-first-computer-exchange");
    let first_flight_spec = format!(
        "{}\t{}",
        first_flight_arm.display(),
        first_flight_engaged.display()
    );
    let retry_ready_arm = a.data.join("hold-computer-retry-ready");
    let retry_ready_engaged = a.data.join("held-computer-retry-ready");
    let retry_ready_fault = a.data.join("fault-computer-retry-ready");
    let retry_ready_release = a.data.join("release-computer-retry-ready.sock");
    let retry_ready_spec = format!(
        "{}\t{}\t{}\t{}",
        retry_ready_arm.display(),
        retry_ready_engaged.display(),
        retry_ready_release.display(),
        retry_ready_fault.display()
    );
    let operator_reserved_arm = a.data.join("hold-computer-operator-reserved");
    let operator_reserved_engaged = a.data.join("held-computer-operator-reserved");
    let operator_superseded = a.data.join("superseded-computer-operator-reserved");
    let operator_reserved_release = a.data.join("release-computer-operator-reserved.sock");
    let operator_reserved_spec = format!(
        "{}\t{}\t{}\t{}",
        operator_reserved_arm.display(),
        operator_reserved_engaged.display(),
        operator_superseded.display(),
        operator_reserved_release.display()
    );
    let answer_after_merge_arm = b.data.join("hold-computer-answer-after-merge");
    let answer_after_merge_engaged = b.data.join("held-computer-answer-after-merge");
    let answer_after_merge_release = b.data.join("release-computer-answer-after-merge.sock");
    let answer_after_merge_spec = format!(
        "{}\t{}\t{}",
        answer_after_merge_arm.display(),
        answer_after_merge_engaged.display(),
        answer_after_merge_release.display()
    );
    let application_prepared_arm = b.data.join("hold-after-computer-application-prepared");
    let application_prepared_engaged = b.data.join("held-after-computer-application-prepared");
    let application_prepared_release = b
        .data
        .join("release-after-computer-application-prepared.sock");
    let application_prepared_fault = b.data.join("fault-after-computer-application-prepared");
    let application_prepared_spec = format!(
        "{}\t{}\t{}\t{}",
        application_prepared_arm.display(),
        application_prepared_engaged.display(),
        application_prepared_release.display(),
        application_prepared_fault.display()
    );
    let receipt_answer_arm = b.data.join("hold-receipt-race-answer-after-merge");
    let receipt_answer_engaged = b.data.join("held-receipt-race-answer-after-merge");
    let receipt_answer_release = b.data.join("release-receipt-race-answer-after-merge.sock");
    let receipt_answer_spec = format!(
        "{}\t{}\t{}",
        receipt_answer_arm.display(),
        receipt_answer_engaged.display(),
        receipt_answer_release.display()
    );
    let application_receipt_arm = b.data.join("hold-after-computer-application-receipt");
    let application_receipt_engaged = b.data.join("held-after-computer-application-receipt");
    let application_receipt_release = b
        .data
        .join("release-after-computer-application-receipt.sock");
    let application_receipt_fault = b.data.join("fault-after-computer-application-receipt");
    let application_receipt_spec = format!(
        "{}\t{}\t{}\t{}",
        application_receipt_arm.display(),
        application_receipt_engaged.display(),
        application_receipt_release.display(),
        application_receipt_fault.display()
    );
    let reconcile_send_arm = b.data.join("hold-computer-reconcile-send");
    let reconcile_send_engaged = b.data.join("held-computer-reconcile-send");
    let reconcile_send_release = b.data.join("release-computer-reconcile-send.sock");
    let reconcile_send_fault = b.data.join("fault-computer-reconcile-send");
    let reconcile_send_spec = format!(
        "{}\t{}\t{}\t{}",
        reconcile_send_arm.display(),
        reconcile_send_engaged.display(),
        reconcile_send_release.display(),
        reconcile_send_fault.display()
    );
    let receipt_reconcile_arm = b.data.join("hold-receipt-race-reconcile-send");
    let receipt_reconcile_engaged = b.data.join("held-receipt-race-reconcile-send");
    let receipt_reconcile_release = b.data.join("release-receipt-race-reconcile-send.sock");
    let receipt_reconcile_fault = b.data.join("fault-receipt-race-reconcile-send");
    let receipt_reconcile_spec = format!(
        "{}\t{}\t{}\t{}",
        receipt_reconcile_arm.display(),
        receipt_reconcile_engaged.display(),
        receipt_reconcile_release.display(),
        receipt_reconcile_fault.display()
    );
    let keyring_commit_crash_arm = b.data.join("crash-after-keyring-commit-arm");
    let keyring_commit_crash_committed = b.data.join("crash-after-keyring-commit-durable");
    let keyring_commit_crash_fault = b.data.join("crash-after-keyring-commit-fault");
    let keyring_commit_crash_spec = format!(
        "{}\t{}\t{}",
        keyring_commit_crash_arm.display(),
        keyring_commit_crash_committed.display(),
        keyring_commit_crash_fault.display()
    );
    let start = |account: &Account, listen: &str, anchor: &str, env: &[(&str, &str)]| {
        let mut daemon = Daemon::start(
            account,
            &["--no-node", "--listen", listen, "--anchor", anchor],
            env,
        );
        daemon.expect_apparatus_event("its control socket", |line| line.contains("control socket"));
        daemon
    };
    let mut left = start(
        &a,
        "127.0.0.1:0",
        &v4,
        &[
            (
                "VOX_TEST_HOLD_FIRST_COMPUTER_EXCHANGE_FILE",
                &first_flight_spec,
            ),
            ("VOX_TEST_HOLD_COMPUTER_RETRY_READY_FILE", &retry_ready_spec),
            (
                "VOX_TEST_HOLD_COMPUTER_OPERATOR_RESERVED_FILE",
                &operator_reserved_spec,
            ),
        ],
    );
    let mut right = start(
        &b,
        "[::1]:0",
        &v6,
        &[(
            "VOX_TEST_HOLD_COMPUTER_ANSWER_AFTER_MERGE_FILE",
            &answer_after_merge_spec,
        )],
    );
    let invitation = computer(&a, &["invite"]);
    let link = invitation["invite_link"]
        .as_str()
        .expect("PRODUCT: node-free computer invitation missing");
    let preview = computer(&b, &["pair", link, "--preview"]);
    let op = preview["pairing"]["operation_id"]
        .as_str()
        .expect("PRODUCT: pairing preview omitted its operation identity");
    computer(&a, &["approve", op]);
    computer(&b, &["approve", op]);
    loop {
        if computer(&a, &["status"])["state"] == "confirmed"
            && computer(&b, &["status"])["state"] == "confirmed"
        {
            break;
        }
        assert!(
            daemon_alive(left.child.id())
                && daemon_alive(right.child.id())
                && daemon_alive(relay.child.id()),
            "PRODUCT: a process exited before two computers with only an anchor path confirmed: {}; {}; anchor: {}",
            computer(&a, &["status"]),
            computer(&b, &["status"]),
            relay.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        relay
            .said()
            .lines()
            .any(|l| l.contains("0 room(s) on the board")),
        "APPARATUS: anchor did not report its empty room board: {}",
        relay.said()
    );
    assert!(
        !relay.said().contains("board —"),
        "PRODUCT: pairing fabricated room membership on its anchor: {}",
        relay.said()
    );
    // Give the returning computer one attached node while the anchor path is healthy. Its shipped
    // trust listing is the eventual observation of both revisions from the other computer.
    let bob = b.make_node("after-remote-anchor-b");
    let (ok, out, err) = b.run(
        &[
            "node",
            "attach",
            "after-remote-anchor-b",
            "--passphrase-file",
            "-",
        ],
        PASS,
    );
    assert!(ok, "APPARATUS: attach the remote observer: {out}{err}");
    loop {
        if computer(&a, &["status"])["state"] == "confirmed"
            && computer(&b, &["status"])["state"] == "confirmed"
        {
            break;
        }
        assert!(
            daemon_alive(left.child.id())
                && daemon_alive(right.child.id())
                && daemon_alive(relay.child.id()),
            "PRODUCT: a process exited before the remote observer's policy revision settled: {}; {}",
            computer(&a, &["status"]),
            computer(&b, &["status"])
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // Stop the remote daemon and the only bridge, then bring only the remote daemon back. There
    // is no retained peer connection and no direct path between address families.
    stop_pid(b.lock_pid().expect("APPARATUS: right scratch daemon"));
    stop_pid(anchor.lock_pid().expect("APPARATUS: scratch anchor daemon"));
    right
        .child
        .wait()
        .expect("APPARATUS: stopped remote daemon did not exit");
    relay
        .child
        .wait()
        .expect("APPARATUS: stopped anchor did not exit");
    right = start(&b, "[::1]:0", &v6, &[]);

    let a_id = computer_id(&a);
    let b_id = computer_id(&b);
    let before = application_toward(&a, &b_id);
    let attempts_before = before["exchange_attempts"].as_u64().unwrap_or(0);
    let failures_before = before["exchange_failures"].as_u64().unwrap_or(0);
    let revision_before = computer(&a, &["status"])["revision"].as_u64().unwrap_or(0);
    let first = a.make_node("anchor-return-first");
    let second = a.make_node("anchor-return-second");
    let third = a.make_node("anchor-return-third");
    std::fs::write(&first_flight_arm, format!("{revision_before}\n"))
        .expect("APPARATUS: arm the first causal exchange hold");
    let first_changed = Instant::now();
    let first_deadline = first_changed + RETURN_WITHIN;
    let (ok, out, err) = a.run(
        &[
            "node",
            "attach",
            "anchor-return-first",
            "--passphrase-file",
            "-",
        ],
        PASS,
    );
    assert!(ok, "PRODUCT: attach the first outage node: {out}{err}");
    wait_for_daemon_marker(
        &first_flight_engaged,
        &mut left,
        first_deadline,
        "the first revision's exchange entered its exact held flight",
    );
    let staged = application_toward(&a, &b_id);
    assert!(
        computer(&a, &["status"])["revision"]
            .as_u64()
            .is_some_and(|revision| revision > revision_before)
            && staged["exchange_attempts"]
                .as_u64()
                .is_some_and(|attempts| attempts > attempts_before)
            && staged["exchange_failures"].as_u64() == Some(failures_before),
        "PRODUCT: after the first shipped policy change, status did not show its held exchange as a new attempt without a fabricated failure: before {before}; after {staged}"
    );
    let first_revision = computer(&a, &["status"])["revision"].as_u64().unwrap_or(0);
    std::fs::write(&retry_ready_arm, b"armed\n")
        .expect("APPARATUS: arm the retry-ready scheduler boundary");
    let (ok, out, err) = a.run(
        &[
            "node",
            "attach",
            "anchor-return-second",
            "--passphrase-file",
            "-",
        ],
        PASS,
    );
    assert!(
        ok,
        "PRODUCT: attach the superseding outage node: {out}{err}"
    );
    assert!(
        wait_until(CHANGE_SHOWN_WITHIN, || computer(&a, &["status"])["revision"]
            .as_u64()
            .is_some_and(|revision| revision > first_revision)),
        "PRODUCT: the second attached node did not create a later policy revision than {first_revision}: {}",
        computer(&a, &["status"])
    );
    loop {
        if retry_ready_fault.is_file() {
            panic!(
                "APPARATUS: retry-ready was not the sole deadline source: {}",
                std::fs::read_to_string(&retry_ready_fault).unwrap_or_default()
            );
        }
        if retry_ready_engaged.is_file() {
            break;
        }
        if let Some(status) = left
            .child
            .try_wait()
            .expect("APPARATUS: inspect left daemon")
        {
            panic!(
                "APPARATUS: left daemon exited {status} before the exact retry-ready boundary: {}",
                left.said()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        std::fs::read_to_string(&retry_ready_engaged)
            .ok()
            .as_deref(),
        Some(b_id.as_str()),
        "APPARATUS: retry-ready held a peer other than the operator takeover target"
    );

    // Exercise the operator takeover race itself while every path is still down. B's fresh
    // invitation is a shipped operator request targeting the same computer. The apparatus marker
    // above is created only after the superseded retry released its reservation and while the
    // scheduler is parked before consuming retry_ready, so this command can inherit the first
    // deadline from no other source. Run it concurrently so only the remote anchor's later return
    // can answer it. Mutant seam: omit retry_ready from the operator's causal-deadline lookup.
    let takeover_invitation = computer(&b, &["invite"]);
    let expected_local = computer(&a, &["status"])["this_computer"].clone();
    let expected_peer = takeover_invitation["this_computer"].clone();
    let takeover_link = takeover_invitation["invite_link"]
        .as_str()
        .expect("PRODUCT: takeover invitation named no invite_link")
        .to_owned();
    let takeover_invite_id = takeover_invitation["invite_id"]
        .as_str()
        .expect("PRODUCT: takeover invitation named no invite_id")
        .to_owned();
    let takeover_attempts_before = application_toward(&a, &b_id)["exchange_attempts"]
        .as_u64()
        .unwrap_or(0);
    let mut takeover = a
        .cmd(&["computer", "pair", &takeover_link, "--preview", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: could not start shipped operator takeover command");
    loop {
        if application_toward(&a, &b_id)["exchange_attempts"]
            .as_u64()
            .is_some_and(|attempts| attempts > takeover_attempts_before)
        {
            break;
        }
        if let Some(status) = takeover
            .try_wait()
            .expect("APPARATUS: inspect shipped operator takeover")
        {
            panic!(
                "PRODUCT: while the retry scheduler was held at retry-ready, the shipped operator command exited {status} without reserving the exact peer as a new exchange: before {takeover_attempts_before}; status {}",
                application_toward(&a, &b_id)
            );
        }
        assert!(
            daemon_alive(left.child.id()),
            "APPARATUS: left daemon exited before the retry-ready operator reserved its peer"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    std::os::unix::net::UnixStream::connect(&retry_ready_release).unwrap_or_else(|e| {
        panic!(
            "APPARATUS: could not release the scheduler's exact retry-ready boundary at {}: {e}",
            retry_ready_release.display()
        )
    });

    // Keep the only path down until a failed replacement's source-owned ordinary backoff would
    // pass the first revision's absolute deadline. Correct code backstops that retry by the first
    // deadline; a replacement that minted a new deadline cannot. Failure-count changes are the
    // shipped status observation; this wait is only APPARATUS staging.
    let mut observed_failures = u32::try_from(failures_before).unwrap_or(u32::MAX);
    assert!(
        wait_until(first_deadline.saturating_duration_since(Instant::now()), || {
            let failures = application_toward(&a, &b_id)["exchange_failures"]
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .unwrap_or(0);
            if failures <= observed_failures {
                return false;
            }
            observed_failures = failures;
            computer_exchange_backoff(failures)
                > first_deadline.saturating_duration_since(Instant::now())
        }),
        "APPARATUS: shipped exchange status never staged a failed replacement whose source-owned backoff crossed the causal first deadline; application: {}; left: {}",
        application_toward(&a, &b_id),
        left.said()
    );

    // No local command, daemon restart or network transition follows: the anchor process alone
    // returns. First establish the apparatus precondition from the restarted anchor's own
    // event-driven connection view: both daemons have registered there. Starting a listener is
    // not evidence that either registration completed. A broken/late anchor never reaches a
    // PRODUCT verdict; the suite watchdog, when an operator enables it, names NO RESULT.
    relay = start_anchor(&anchor_listen);
    wait_for_current_anchor_peers(&mut relay, &[&a_id, &b_id]);
    assert!(
        Instant::now() < first_deadline,
        "APPARATUS: both computer daemons registered at the restored anchor only after the first revision's causal deadline; the recovery precondition was staged too late: {}",
        relay.said()
    );
    // Failed registration is durable work and must cause its own retry. Only now that the anchor
    // says both endpoints are registered may a miss of the retained local deadline name PRODUCT.
    loop {
        if takeover
            .try_wait()
            .expect("APPARATUS: inspect shipped operator takeover")
            .is_some()
        {
            break;
        }
        assert!(
            anchor_currently_has(&relay, &[&a_id, &b_id]),
            "APPARATUS: the restored anchor's current view stopped naming both exact computer identities before the PRODUCT retry verdict:\n{}",
            relay.said()
        );
        assert!(
            Instant::now() < first_deadline,
            "PRODUCT: the shipped operator takeover did not yield by the first superseded revision's {RETURN_WITHIN:?} causal deadline"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        anchor_currently_has(&relay, &[&a_id, &b_id]),
        "APPARATUS: after the shipped takeover completed, the restored anchor's latest view no longer named both exact computer identities; no PRODUCT verdict follows:\n{}",
        relay.said()
    );
    let takeover_output = takeover
        .wait_with_output()
        .expect("APPARATUS: could not collect the completed operator takeover command");
    assert!(
        anchor_currently_has(&relay, &[&a_id, &b_id]),
        "APPARATUS: the restored anchor's latest view changed while the completed takeover output was collected; no PRODUCT verdict follows:\n{}",
        relay.said()
    );
    assert!(
        takeover_output.status.success(),
        "PRODUCT: the retry-ready-only operator takeover exited unsuccessfully: stdout {}; stderr {}",
        String::from_utf8_lossy(&takeover_output.stdout),
        String::from_utf8_lossy(&takeover_output.stderr)
    );
    let takeover_preview: serde_json::Value = serde_json::from_slice(&takeover_output.stdout)
        .unwrap_or_else(|e| {
            panic!(
                "PRODUCT: the successful retry-ready-only `computer pair --preview --json` did not return readable JSON: {e}: {}",
                String::from_utf8_lossy(&takeover_output.stdout)
            )
        });
    assert!(
        takeover_preview["this_computer"] == expected_local
            && takeover_preview["pairing"]["peer"] == expected_peer
            && takeover_preview["pairing"]["operation_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty())
            && takeover_preview["pairing"]["approved_here"] == false
            && takeover_preview["pairing"]["approved_there"] == false
            && takeover_preview["pairing"]["expires_ms"]
                == takeover_invitation["invite_expires_ms"],
        "PRODUCT: the successful retry-ready-only preview did not show the exact authenticated local computer, inviting peer, unapproved operation and expiry: {takeover_preview}"
    );
    println!(
        "[proof] shipped operator takeover completed successfully from retry-ready alone before the inherited deadline: {takeover_preview}"
    );
    computer(&b, &["cancel", &takeover_invite_id]);
    let expected_roster_before_race = [
        ("anchor-return-first", first.as_str()),
        ("anchor-return-second", second.as_str()),
        ("after-remote-anchor-b", bob.as_str()),
    ];
    let expected_bob_grants_before_race = [(first.as_str(), "read"), (second.as_str(), "read")];
    println!(
        "[proof] FX-28 stale-flight-newer-obligation apparatus staged: the first exact flight was superseded by two durable revisions, its source-owned retry crossed the retained causal deadline, and the restored anchor named both exact computers"
    );
    let converged = wait_until(
        first_deadline.saturating_duration_since(Instant::now()),
        || {
            let left_status = computer(&a, &["status"]);
            let status = computer(&b, &["status"]);
            exact_roster(&left_status, &expected_roster_before_race)
                && exact_roster(&status, &expected_roster_before_race)
                && exact_grants(
                    &b,
                    "after-remote-anchor-b",
                    &expected_bob_grants_before_race,
                )
                && computer(&a, &["status"])["state"] == "confirmed"
                && status["state"] == "confirmed"
        },
    );
    let returned_after = first_changed.elapsed();
    assert!(
        converged && returned_after <= RETURN_WITHIN,
        "PRODUCT [FX28 stale-flight-newer-obligation]: after only the remote anchor returned, the computer with no retained connection did not show both superseding policy revisions within the first revision's {RETURN_WITHIN:?} causal deadline (observed after {returned_after:?}); left: {}; right: {}; anchor: {}",
        computer(&a, &["status"]),
        computer(&b, &["status"]),
        relay.said()
    );
    println!(
        "[proof] after {returned_after:?}, remote-anchor-only recovery carried both revisions through a new peer connection before the first revision's {RETURN_WITHIN:?} deadline"
    );

    // Stage the other operator race independently. The shipped preview owns a reservation but has
    // no task handle yet; attaching a node is a newer policy revision, and the retry must mark that
    // exact handle-less flight superseded before the apparatus releases it. The user-visible
    // command must then refuse its stale preview rather than installing stale work.
    let race_invitation = computer(&b, &["invite"]);
    let race_link = race_invitation["invite_link"]
        .as_str()
        .expect("PRODUCT: reserve-to-install race invitation named no invite_link")
        .to_owned();
    let race_invite_id = race_invitation["invite_id"]
        .as_str()
        .expect("PRODUCT: reserve-to-install race invitation named no invite_id")
        .to_owned();
    std::fs::write(&operator_reserved_arm, b"armed\n")
        .expect("APPARATUS: arm the operator reserve-to-handle-install boundary");
    let race_preview_started = Instant::now();
    let mut raced_preview = a
        .cmd(&["computer", "pair", &race_link, "--preview", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: start shipped reserve-to-install operator preview");
    wait_for_command_marker(
        &operator_reserved_engaged,
        &mut raced_preview,
        left.child.id(),
        race_preview_started + PAIR_WITHIN,
        "the operator held its exact reservation before handle installation",
    );
    assert_eq!(
        std::fs::read_to_string(&operator_reserved_engaged)
            .ok()
            .as_deref(),
        Some(b_id.as_str()),
        "APPARATUS: operator reserve-to-install hold engaged for the wrong peer"
    );
    let race_changed = Instant::now();
    let (ok, out, err) = a.run(
        &[
            "node",
            "attach",
            "anchor-return-third",
            "--passphrase-file",
            "-",
        ],
        PASS,
    );
    assert!(ok, "PRODUCT: attach the reserve-race node: {out}{err}");
    wait_for_daemon_marker(
        &operator_superseded,
        &mut left,
        race_changed + RETURN_WITHIN,
        "the newer policy revision superseded the held operator reservation",
    );
    assert_eq!(
        std::fs::read_to_string(&operator_superseded)
            .ok()
            .as_deref(),
        Some(b_id.as_str()),
        "APPARATUS: a peer other than the held operator target was marked superseded"
    );
    std::os::unix::net::UnixStream::connect(&operator_reserved_release).unwrap_or_else(|e| {
        panic!(
            "APPARATUS: could not release the operator reserve-to-install boundary at {}: {e}",
            operator_reserved_release.display()
        )
    });
    let raced_output = raced_preview
        .wait_with_output()
        .expect("APPARATUS: collect shipped reserve-to-install operator preview");
    let raced_stdout = String::from_utf8_lossy(&raced_output.stdout);
    let raced_stderr = String::from_utf8_lossy(&raced_output.stderr);
    assert!(
        !raced_output.status.success()
            && format!("{raced_stdout}{raced_stderr}").contains("superseded"),
        "PRODUCT: after a newer policy revision causally superseded its held reservation, the shipped operator preview did not refuse the stale operation as superseded: status {}; stdout {raced_stdout}; stderr {raced_stderr}",
        raced_output.status
    );
    computer(&b, &["cancel", &race_invite_id]);
    let expected_roster = [
        ("anchor-return-first", first.as_str()),
        ("anchor-return-second", second.as_str()),
        ("anchor-return-third", third.as_str()),
        ("after-remote-anchor-b", bob.as_str()),
    ];
    let expected_bob_grants = [
        (first.as_str(), "read"),
        (second.as_str(), "read"),
        (third.as_str(), "read"),
    ];
    let race_converged = wait_until(RETURN_WITHIN, || {
        let left_status = computer(&a, &["status"]);
        let right_status = computer(&b, &["status"]);
        exact_roster(&left_status, &expected_roster)
            && exact_roster(&right_status, &expected_roster)
            && exact_grants(&b, "after-remote-anchor-b", &expected_bob_grants)
            && left_status["state"] == "confirmed"
            && right_status["state"] == "confirmed"
    });
    assert!(
        race_converged,
        "PRODUCT: after the newer revision superseded the handle-less operator reservation, the attached node did not converge within {RETURN_WITHIN:?} (observed after {:?}); left: {}; right: {}",
        race_changed.elapsed(),
        computer(&a, &["status"]),
        computer(&b, &["status"])
    );

    // Establish an older computer-managed capability upgrade. The next expired revision must
    // revoke this too, not merely the grant introduced by that next revision.
    computer(&a, &["personal", "anchor-return-first"]);
    let expected_bob_grants_with_drive = [
        (first.as_str(), "read + drive"),
        (second.as_str(), "read"),
        (third.as_str(), "read"),
    ];
    assert!(
        wait_until(RETURN_WITHIN, || {
            exact_grants(
                &b,
                "after-remote-anchor-b",
                &expected_bob_grants_with_drive,
            ) && computer(&a, &["status"])["state"] == "confirmed"
                && computer(&b, &["status"])["state"] == "confirmed"
        }),
        "PRODUCT: the deliberate computer capability change did not converge before the late-marker race: left {}; right {}",
        computer(&a, &["status"]),
        computer(&b, &["status"])
    );

    // Principal FX-28 race: the answerer durably merges and applies this grant before its reply
    // is allowed to leave. Shipped trust output must first show that effective grant. The
    // initiator then names the missed causal revision; after releasing the exact parked answer,
    // its later marker must revoke the already-published grant on the answerer. Mutant: ignore a
    // marker-only change in `change_until`; the final effective-keyring assertion stays granted
    // and turns PRODUCT red.
    std::fs::write(&answer_after_merge_arm, b"armed")
        .expect("APPARATUS: arm post-merge answer hold");
    let applied_then_late = a.make_node("applied-before-late-marker");
    let revision_before_applied_late = computer(&a, &["status"])["revision"].as_u64().unwrap_or(0);
    let (ok, out, err) = a.run(
        &[
            "node",
            "attach",
            "applied-before-late-marker",
            "--passphrase-file",
            "-",
        ],
        PASS,
    );
    assert!(ok, "PRODUCT: attach post-merge-held node: {out}{err}");
    let applied_late_revision = computer(&a, &["status"])["revision"]
        .as_u64()
        .filter(|revision| *revision > revision_before_applied_late)
        .unwrap_or_else(|| {
            panic!("PRODUCT: attaching the post-merge-held node moved no policy revision")
        });
    assert!(
        wait_until(CHANGE_SHOWN_WITHIN, || answer_after_merge_engaged.is_file()),
        "APPARATUS: answerer never reached the exact durable-merge-before-reply boundary; left {}; right {}; anchor {}",
        computer(&a, &["status"]),
        computer(&b, &["status"]),
        relay.said()
    );
    let mut applied_grants = expected_bob_grants_with_drive.to_vec();
    applied_grants.push((applied_then_late.as_str(), "read"));
    assert!(
        wait_until(CHANGE_SHOWN_WITHIN, || {
            exact_grants(&b, "after-remote-anchor-b", &applied_grants)
        }),
        "PRODUCT: the answerer merged revision {applied_late_revision} but its shipped effective keyring never showed the grant before the held reply: {}",
        computer(&b, &["status"])
    );
    loop {
        let left_status = computer(&a, &["status"]);
        let application = application_toward(&a, &b_id);
        if application["missed_revision"] == applied_late_revision
            && application["convergence_state"] == "expired"
        {
            break;
        }
        assert!(
            daemon_alive(left.child.id()) && daemon_alive(right.child.id()),
            "APPARATUS: a daemon exited before shipped status named the post-merge held reply's missed revision: {left_status}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    std::os::unix::net::UnixStream::connect(&answer_after_merge_release)
        .unwrap_or_else(|error| panic!("APPARATUS: release post-merge answer hold: {error}"));
    loop {
        let remote = application_toward(&b, &a_id);
        if matches!(
            remote["convergence_state"].as_str(),
            Some("expired" | "repaired-late")
        ) {
            let (_, grants, grant_error) =
                b.run(&["trust", "list", "--node", "after-remote-anchor-b"], "");
            assert!(
                exact_grants(&b, "after-remote-anchor-b", &[]),
                "PRODUCT: after shipped status named the received operator-policy revision expired, the managed node retained computer authority in its effective keyring: status {}; shipped trust output {grants}; error {grant_error}",
                computer(&b, &["status"]),
            );
            break;
        }
        assert!(
            anchor_currently_has(&relay, &[&a_id, &b_id]),
            "APPARATUS: exact anchor registrations disappeared before the later marker's shipped effective-keyring verdict"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // Exercise the late-repair branch itself. The anchor goes away, a real policy revision is
    // made, and shipped status—not a sleep—causally says that revision missed its retained
    // convergence deadline. After the exact anchor identities return, the late exchange repairs
    // the roster but MUST keep the missed contract visible. Mutant: clear the late-success branch
    // in `record_exchange`; the failure count/problem assertions below turn PRODUCT red.
    stop_pid(anchor.lock_pid().expect("APPARATUS: scratch anchor daemon"));
    relay
        .child
        .wait()
        .expect("APPARATUS: stopped anchor did not exit");
    let before_late_right = full_roster(&computer(&b, &["status"]))
        .expect("APPARATUS: right status did not expose its pre-expiry binding evidence");
    let late = a.make_node("anchor-return-late");
    let revision_before_late = computer(&a, &["status"])["revision"].as_u64().unwrap_or(0);
    let (ok, out, err) = a.run(
        &[
            "node",
            "attach",
            "anchor-return-late",
            "--passphrase-file",
            "-",
        ],
        PASS,
    );
    assert!(ok, "PRODUCT: attach the late-repair node: {out}{err}");
    let late_revision = computer(&a, &["status"])["revision"]
        .as_u64()
        .filter(|revision| *revision > revision_before_late)
        .unwrap_or_else(|| {
            panic!("PRODUCT: attaching the late-repair node moved no policy revision")
        });
    loop {
        let status = computer(&a, &["status"]);
        let application = application_toward(&a, &b_id);
        if application["exchange_failures"].as_u64().unwrap_or(0) > 0
            && status["problem"]
                .as_str()
                .is_some_and(|problem| problem.contains("causal convergence deadline"))
        {
            break;
        }
        assert!(
            daemon_alive(left.child.id()),
            "APPARATUS: left daemon exited before shipped status named the deliberately staged missed causal deadline"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    relay = start_anchor(&anchor_listen);
    wait_for_current_anchor_peers(&mut relay, &[&a_id, &b_id]);
    loop {
        let left_status = computer(&a, &["status"]);
        let right_status = computer(&b, &["status"]);
        let application = application_toward(&a, &b_id);
        let remote_application = application_toward(&b, &a_id);
        let repaired = application["last_started_exchange"]["sent_revision"]
            .as_u64()
            .is_some_and(|revision| revision >= late_revision)
            && application["missed_revision"] == late_revision
            && application["repaired_late"] == true
            && application["convergence_state"] == "repaired-late"
            && remote_application["missed_revision"] == right_status["revision"]
            && remote_application["convergence_state"] == "expired"
            && right_status["state"] == "expired";
        if repaired {
            assert!(
                application["exchange_failures"].as_u64().unwrap_or(0) > 0
                    && left_status["problem"]
                        .as_str()
                        .is_some_and(|problem| problem.contains("repaired state only after")),
                "PRODUCT: the late exchange repaired revision {late_revision} but cleared its missed causal contract: status {left_status}; application {application}"
            );
            let after_late_right = full_roster(&right_status).unwrap_or_else(|| {
                panic!("PRODUCT: the expired remote status lost its structural binding evidence: {right_status}")
            });
            assert_eq!(
                after_late_right.get("after-remote-anchor-b"),
                before_late_right.get("after-remote-anchor-b"),
                "PRODUCT: the remote actor derived or saved ordinary trust from expired revision {late_revision}: before {before_late_right:?}; after {after_late_right:?}"
            );
            break;
        }
        assert!(
            anchor_currently_has(&relay, &[&a_id, &b_id]),
            "APPARATUS: exact restored anchor registrations were lost before the late-repair verdict"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let (preview_ok, preview_out, preview_err) =
        a.run(&["computer", "pair", &race_link, "--preview", "--json"], "");
    assert!(
        !preview_ok,
        "PRODUCT: the cancelled same-state preview unexpectedly succeeded after a missed contract: {preview_out}{preview_err}"
    );
    let after_preview = computer(&a, &["status"]);
    assert!(
        after_preview["problem"]
            .as_str()
            .is_some_and(|problem| problem.contains("repaired state only after"))
            && application_toward(&a, &b_id)["exchange_failures"]
                .as_u64()
                .unwrap_or(0)
                > 0,
        "PRODUCT: a same-state failed preview cleared or re-enabled the durable missed contract: {after_preview}"
    );
    let before_restart = (
        full_roster(&computer(&a, &["status"])).unwrap_or_else(|| {
            panic!(
                "PRODUCT: before restart the left status did not expose every user-visible roster field: {}",
                computer(&a, &["status"])
            )
        }),
        full_roster(&computer(&b, &["status"])).unwrap_or_else(|| {
            panic!(
                "PRODUCT: before restart the right status did not expose every user-visible roster field: {}",
                computer(&b, &["status"])
            )
        }),
    );

    // Persistence remains part of the same journey: restart both managers and the anchor, then
    // read every field of the exact already-applied roster rather than manufacturing a fresh
    // revision or accepting a name/fingerprint-only projection.
    stop_pid(a.lock_pid().expect("APPARATUS: left scratch daemon"));
    stop_pid(b.lock_pid().expect("APPARATUS: right scratch daemon"));
    stop_pid(anchor.lock_pid().expect("APPARATUS: scratch anchor daemon"));
    left.child
        .wait()
        .expect("APPARATUS: left daemon did not exit");
    right
        .child
        .wait()
        .expect("APPARATUS: right daemon did not exit");
    relay.child.wait().expect("APPARATUS: anchor did not exit");
    relay = start_anchor(&anchor_listen);
    left = start(
        &a,
        "127.0.0.1:0",
        &v4,
        &[
            (
                "VOX_TEST_HOLD_FIRST_COMPUTER_EXCHANGE_FILE",
                &first_flight_spec,
            ),
            ("VOX_TEST_HOLD_COMPUTER_RETRY_READY_FILE", &retry_ready_spec),
            (
                "VOX_TEST_HOLD_COMPUTER_OPERATOR_RESERVED_FILE",
                &operator_reserved_spec,
            ),
        ],
    );
    right = start(&b, "[::1]:0", &v6, &[]);
    loop {
        if full_roster(&computer(&a, &["status"])) == Some(before_restart.0.clone())
            && full_roster(&computer(&b, &["status"])) == Some(before_restart.1.clone())
            && exact_grants(&b, "after-remote-anchor-b", &[])
        {
            break;
        }
        assert!(
            daemon_alive(left.child.id())
                && daemon_alive(right.child.id())
                && daemon_alive(relay.child.id()),
            "PRODUCT: a restarted process exited before the exact recovered user-visible roster fields (name, fingerprint, computer, personal role, binding revision and derived moment) and grants were shown; expected left {:?}; expected right {:?}; left: {}; right: {}; anchor: {}",
            before_restart.0,
            before_restart.1,
            a.log(),
            b.log(),
            relay.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let restarted_late = computer(&a, &["status"]);
    let restarted_remote = computer(&b, &["status"]);
    assert!(
        restarted_late["problem"]
            .as_str()
            .is_some_and(|problem| problem.contains("repaired state only after"))
            && application_toward(&a, &b_id)["exchange_failures"]
                .as_u64()
                .unwrap_or(0)
                > 0
            && application_toward(&a, &b_id)["missed_revision"] == late_revision
            && application_toward(&a, &b_id)["convergence_state"] == "repaired-late"
            && application_toward(&b, &a_id)["missed_revision"]
                == restarted_remote["revision"]
            && matches!(
                application_toward(&b, &a_id)["convergence_state"].as_str(),
                Some("expired" | "repaired-late")
            ),
        "PRODUCT: restarting the daemons cleared the exact durable missed causal contract without a newer policy revision: left {restarted_late}; right {restarted_remote}"
    );

    // A newer operator change is the only replacement cause. Before its exchange, status names
    // the old miss as replaced; after its own timely exchange both computers name convergence
    // and only then may the remote actor derive the formerly-late grant.
    stop_pid(anchor.lock_pid().expect("APPARATUS: scratch anchor daemon"));
    relay
        .child
        .wait()
        .expect("APPARATUS: stopped anchor did not exit before replacement staging");
    let replacement = a.make_node("after-expired-revision");
    let (ok, out, err) = a.run(
        &[
            "node",
            "attach",
            "after-expired-revision",
            "--passphrase-file",
            "-",
        ],
        PASS,
    );
    assert!(ok, "PRODUCT: attach replacement-cause node: {out}{err}");
    let replaced = application_toward(&a, &b_id);
    assert!(
        replaced["missed_revision"] == late_revision
            && replaced["convergence_state"] == "replaced",
        "PRODUCT: a newer policy cause did not structurally replace exact expired revision {late_revision}: {replaced}"
    );
    relay = start_anchor(&anchor_listen);
    wait_for_current_anchor_peers(&mut relay, &[&a_id, &b_id]);
    let final_roster = [
        ("anchor-return-first", first.as_str()),
        ("anchor-return-second", second.as_str()),
        ("anchor-return-third", third.as_str()),
        ("applied-before-late-marker", applied_then_late.as_str()),
        ("anchor-return-late", late.as_str()),
        ("after-expired-revision", replacement.as_str()),
        ("after-remote-anchor-b", bob.as_str()),
    ];
    let final_grants = [
        (first.as_str(), "read + drive"),
        (second.as_str(), "read"),
        (third.as_str(), "read"),
        (applied_then_late.as_str(), "read"),
        (late.as_str(), "read"),
        (replacement.as_str(), "read"),
    ];
    assert!(
        wait_until(RETURN_WITHIN, || {
            let left_status = computer(&a, &["status"]);
            let right_status = computer(&b, &["status"]);
            exact_roster(&left_status, &final_roster)
                && exact_roster(&right_status, &final_roster)
                && exact_grants(&b, "after-remote-anchor-b", &final_grants)
                && application_toward(&a, &b_id)["convergence_state"] == "converged"
                && application_toward(&b, &a_id)["convergence_state"] == "converged"
        }),
        "PRODUCT: the newer cause did not converge after replacing expired revision {late_revision}: left {}; right {}",
        computer(&a, &["status"]),
        computer(&b, &["status"])
    );
    for (account, node) in [(&a, "anchor-return-first"), (&b, "after-remote-anchor-b")] {
        let (ok, out, err) = account.run(&["room", "list", "--node", node], "");
        assert!(
            ok && out.trim() == "no rooms",
            "PRODUCT: computer transport introduced a room: {out}{err}"
        );
    }

    // Exact live two-store race: keep the answerer's managed node Locked while a new policy
    // revision merges, then start its shipped attach. The actor durably prepares that revision's
    // rollback set and is held before its node-keyring commit. While held, the initiating
    // computer names the same revision missed and its late exchange makes the answerer's durable
    // status name it expired. Releasing the commit boundary may write the formerly-live grant,
    // but attach may say Ready only after the receipt notices expiry and durably revokes it.
    // Mutant: omit the durable prepared rollback set from the expired plan. The just-committed
    // grant then survives to Ready and the immediate shipped trust assertion turns PRODUCT red
    // without an elapsed-time verdict.
    let (locked, locked_out, locked_err) = b.run(&["node", "lock", "after-remote-anchor-b"], "");
    assert!(
        locked,
        "APPARATUS: could not Lock the managed node for the exact prepare/expiry race: {locked_out}{locked_err}"
    );
    stop_pid(right.child.id());
    right
        .child
        .wait()
        .expect("APPARATUS: right daemon did not stop before exact prepare/expiry staging");
    right = start(
        &b,
        "[::1]:0",
        &v6,
        &[
            (
                "VOX_TEST_HOLD_COMPUTER_ANSWER_AFTER_MERGE_FILE",
                &answer_after_merge_spec,
            ),
            (
                "VOX_TEST_HOLD_AFTER_COMPUTER_APPLICATION_PREPARED_FILE",
                &application_prepared_spec,
            ),
            (
                "VOX_TEST_HOLD_COMPUTER_RECONCILE_SEND_FILE",
                &reconcile_send_spec,
            ),
        ],
    );
    assert!(
        !answer_after_merge_engaged.exists()
            && !application_prepared_engaged.exists()
            && !application_prepared_fault.exists()
            && !reconcile_send_engaged.exists()
            && !reconcile_send_fault.exists(),
        "APPARATUS: an earlier hook invocation left an exact prepare/expiry marker"
    );
    std::fs::write(&answer_after_merge_arm, b"armed")
        .expect("APPARATUS: arm merge-before-reply hold for exact prepare/expiry race");
    let expired_during_commit = a.make_node("expired-between-prepare-and-commit");
    let before_prepare_race = computer(&a, &["status"])["revision"].as_u64().unwrap_or(0);
    let (ok, out, err) = a.run(
        &[
            "node",
            "attach",
            "expired-between-prepare-and-commit",
            "--passphrase-file",
            "-",
        ],
        PASS,
    );
    assert!(ok, "PRODUCT: attach prepare/expiry race node: {out}{err}");
    let prepare_race_revision = computer(&a, &["status"])["revision"]
        .as_u64()
        .filter(|revision| *revision > before_prepare_race)
        .unwrap_or_else(|| {
            panic!("PRODUCT: attaching the prepare/expiry race node moved no policy revision")
        });
    assert!(
        wait_until(CHANGE_SHOWN_WITHIN, || answer_after_merge_engaged.is_file()),
        "APPARATUS: answerer never reached merge-before-reply for exact prepare/expiry revision {prepare_race_revision}"
    );
    std::fs::write(&application_prepared_arm, &expired_during_commit)
        .expect("APPARATUS: arm exact durable-prepare/node-keyring-commit boundary");
    std::fs::write(
        &reconcile_send_arm,
        format!("{bob}\t{prepare_race_revision}"),
    )
    .expect("APPARATUS: arm exact post-Ready reconciliation-send boundary");
    let mut attaching = b
        .cmd(&[
            "node",
            "attach",
            "after-remote-anchor-b",
            "--passphrase-file",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: start shipped managed-node attach for prepare/expiry race");
    attaching
        .stdin
        .take()
        .expect("APPARATUS: prepare/expiry attach stdin")
        .write_all(PASS.as_bytes())
        .expect("APPARATUS: type prepare/expiry attach passphrase");
    wait_for_command_marker(
        &application_prepared_engaged,
        &mut attaching,
        right.child.id(),
        Instant::now() + RETURN_WITHIN,
        "the exact policy application was durably prepared before its node-keyring commit",
    );
    if application_prepared_fault.is_file() {
        panic!(
            "APPARATUS: exact prepared-application hold failed: {}",
            std::fs::read_to_string(&application_prepared_fault).unwrap_or_default()
        );
    }
    assert_eq!(
        std::fs::read_to_string(&application_prepared_engaged)
            .expect("APPARATUS: read exact prepared-application identity"),
        format!("{bob}\t{prepare_race_revision}\t{expired_during_commit}"),
        "APPARATUS: prepared-application boundary named another node, revision, or grant"
    );
    // The initiator durably owns the in-flight obligation before opening the stream. Crashing and
    // restarting it is the causal, non-timing way to make that exact unanswered revision missed:
    // startup recovery promotes the pending obligation, then its authenticated exchange carries
    // the expiry to the answerer while the node-keyring commit remains held.
    let _ = left.crash();
    left = start(&a, "127.0.0.1:0", &v4, &[]);
    loop {
        let application = application_toward(&a, &b_id);
        if application["missed_revision"] == prepare_race_revision
            && application["convergence_state"] == "expired"
        {
            break;
        }
        assert!(
            daemon_alive(left.child.id()) && daemon_alive(right.child.id()),
            "APPARATUS: a daemon exited before restart recovery durably named exact prepared revision {prepare_race_revision} expired"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    loop {
        let remote = application_toward(&b, &a_id);
        if remote["missed_revision"] == prepare_race_revision
            && matches!(
                remote["convergence_state"].as_str(),
                Some("expired" | "repaired-late")
            )
        {
            break;
        }
        assert!(
            daemon_alive(left.child.id()) && daemon_alive(right.child.id()),
            "APPARATUS: a daemon exited before the answerer durably received expiry for exact prepared revision {prepare_race_revision}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    println!(
        "[proof] FX-28 expiry-before-keyring-commit apparatus staged: revision {prepare_race_revision}, node {bob}, grant {expired_during_commit}"
    );
    std::os::unix::net::UnixStream::connect(&answer_after_merge_release)
        .unwrap_or_else(|error| panic!("APPARATUS: release prepare/expiry held answer: {error}"));
    std::os::unix::net::UnixStream::connect(&application_prepared_release).unwrap_or_else(
        |error| {
            panic!("APPARATUS: release exact durable-prepare/node-keyring-commit boundary: {error}")
        },
    );
    let attached = attaching
        .wait_with_output()
        .expect("APPARATUS: collect prepare/expiry managed-node attach");
    let attached_out = String::from_utf8_lossy(&attached.stdout);
    let attached_err = String::from_utf8_lossy(&attached.stderr);
    assert!(
        attached.status.success(),
        "PRODUCT [FX28 expiry-before-keyring-ready]: after exact prepared revision {prepare_race_revision} expired, the managed node did not become Ready through durable revocation: {attached_out}{attached_err}"
    );
    right.expect_apparatus_event(
        "managed node Ready after exact prepare/expiry reconciliation",
        |line| line.contains("after-remote-anchor-b is Ready"),
    );
    let reconcile_deadline = Instant::now() + RETURN_WITHIN;
    loop {
        if reconcile_send_fault.is_file() {
            panic!(
                "APPARATUS: exact post-Ready reconciliation hold failed: {}",
                std::fs::read_to_string(&reconcile_send_fault).unwrap_or_default()
            );
        }
        if reconcile_send_engaged.is_file() {
            break;
        }
        assert!(
            daemon_alive(right.child.id()),
            "APPARATUS: answerer exited before holding the exact post-Ready asynchronous reconciliation"
        );
        assert!(
            Instant::now() < reconcile_deadline,
            "APPARATUS: the answerer remained live but did not reach the exact post-Ready reconciliation-send boundary"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        std::fs::read_to_string(&reconcile_send_engaged)
            .expect("APPARATUS: read exact held reconciliation identity"),
        format!("{bob}\t{prepare_race_revision}"),
        "APPARATUS: post-Ready reconciliation hold named another node or revision"
    );
    let remote = application_toward(&b, &a_id);
    let (_, grants, grant_error) = b.run(&["trust", "list", "--node", "after-remote-anchor-b"], "");
    assert!(
        exact_grants(&b, "after-remote-anchor-b", &[]),
        "PRODUCT [FX28 expiry-before-keyring-commit]: Ready preceded durable revocation of exact expired revision {prepare_race_revision}: status {remote}; shipped trust output {grants}; error {grant_error}"
    );

    // A second exact revision stages the final Ready fence on the other side of the applied
    // receipt. The receipt has removed `prepared` and recorded the grant before the hold. Only
    // then does the initiating computer durably expire that same revision. Live authority gates
    // already fail closed; the daemon must reconcile the stale receipt before publishing Ready.
    // Its isolated mutant bypasses only that final state-locked fence. The later Attached-event
    // reconciliation is held independently so it cannot rescue the shipped trust assertion.
    stop_pid(right.child.id());
    right
        .child
        .wait()
        .expect("APPARATUS: stop right daemon before exact post-receipt expiry staging");
    right = start(
        &b,
        "[::1]:0",
        &v6,
        &[
            (
                "VOX_TEST_HOLD_COMPUTER_ANSWER_AFTER_MERGE_FILE",
                &receipt_answer_spec,
            ),
            (
                "VOX_TEST_HOLD_AFTER_COMPUTER_APPLICATION_RECEIPT_FILE",
                &application_receipt_spec,
            ),
            (
                "VOX_TEST_HOLD_COMPUTER_RECONCILE_SEND_FILE",
                &receipt_reconcile_spec,
            ),
        ],
    );
    assert!(
        !receipt_answer_engaged.exists()
            && !application_receipt_engaged.exists()
            && !application_receipt_fault.exists()
            && !receipt_reconcile_engaged.exists()
            && !receipt_reconcile_fault.exists(),
        "APPARATUS: an earlier hook invocation left an exact post-receipt expiry marker"
    );
    std::fs::write(&receipt_answer_arm, b"armed")
        .expect("APPARATUS: arm merge-before-reply hold for exact post-receipt expiry race");
    let expired_after_receipt = a.make_node("expired-after-applied-receipt");
    let before_receipt_race = computer(&a, &["status"])["revision"].as_u64().unwrap_or(0);
    let (ok, out, err) = a.run(
        &[
            "node",
            "attach",
            "expired-after-applied-receipt",
            "--passphrase-file",
            "-",
        ],
        PASS,
    );
    assert!(
        ok,
        "PRODUCT: attach post-receipt expiry race node: {out}{err}"
    );
    let receipt_race_revision = computer(&a, &["status"])["revision"]
        .as_u64()
        .filter(|revision| *revision > before_receipt_race)
        .unwrap_or_else(|| {
            panic!("PRODUCT: attaching the post-receipt expiry race node moved no policy revision")
        });
    assert!(
        wait_until(CHANGE_SHOWN_WITHIN, || receipt_answer_engaged.is_file()),
        "APPARATUS: answerer never reached merge-before-reply for exact post-receipt revision {receipt_race_revision}"
    );
    std::fs::write(&application_receipt_arm, &expired_after_receipt)
        .expect("APPARATUS: arm exact successful-applied-receipt/startup-settlement boundary");
    std::fs::write(
        &receipt_reconcile_arm,
        format!("{bob}\t{receipt_race_revision}"),
    )
    .expect("APPARATUS: arm exact later reconciliation after final Ready fence");
    let mut receipt_attach = b
        .cmd(&[
            "node",
            "attach",
            "after-remote-anchor-b",
            "--passphrase-file",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: start shipped managed-node attach for post-receipt expiry race");
    receipt_attach
        .stdin
        .take()
        .expect("APPARATUS: post-receipt expiry attach stdin")
        .write_all(PASS.as_bytes())
        .expect("APPARATUS: type post-receipt expiry attach passphrase");
    wait_for_command_marker(
        &application_receipt_engaged,
        &mut receipt_attach,
        right.child.id(),
        Instant::now() + RETURN_WITHIN,
        "the exact policy application receipt succeeded before startup settlement",
    );
    if application_receipt_fault.is_file() {
        panic!(
            "APPARATUS: exact applied-receipt hold failed: {}",
            std::fs::read_to_string(&application_receipt_fault).unwrap_or_default()
        );
    }
    assert_eq!(
        std::fs::read_to_string(&application_receipt_engaged)
            .expect("APPARATUS: read exact applied-receipt identity"),
        format!("{bob}\t{receipt_race_revision}\t{expired_after_receipt}"),
        "APPARATUS: applied-receipt boundary named another node, revision, or grant"
    );

    let _ = left.crash();
    left = start(&a, "127.0.0.1:0", &v4, &[]);
    loop {
        let application = application_toward(&a, &b_id);
        if application["missed_revision"] == receipt_race_revision
            && application["convergence_state"] == "expired"
        {
            break;
        }
        assert!(
            daemon_alive(left.child.id()) && daemon_alive(right.child.id()),
            "APPARATUS: a daemon exited before restart recovery durably expired exact post-receipt revision {receipt_race_revision}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    loop {
        let remote = application_toward(&b, &a_id);
        if remote["missed_revision"] == receipt_race_revision
            && matches!(
                remote["convergence_state"].as_str(),
                Some("expired" | "repaired-late")
            )
        {
            break;
        }
        assert!(
            daemon_alive(left.child.id()) && daemon_alive(right.child.id()),
            "APPARATUS: answerer did not durably receive expiry after exact applied receipt for revision {receipt_race_revision}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    println!(
        "[proof] FX-28 expiry-after-applied-receipt apparatus staged: revision {receipt_race_revision}, node {bob}, grant {expired_after_receipt}"
    );
    std::os::unix::net::UnixStream::connect(&receipt_answer_release)
        .unwrap_or_else(|error| panic!("APPARATUS: release post-receipt held answer: {error}"));
    std::os::unix::net::UnixStream::connect(&application_receipt_release).unwrap_or_else(|error| {
        panic!("APPARATUS: release exact applied-receipt/startup-settlement boundary: {error}")
    });
    println!(
        "[proof] FX-28 startup Ready state-lock apparatus staged: node {bob}, applied revision {receipt_race_revision}, expired grant {expired_after_receipt}"
    );
    let receipt_attached = receipt_attach
        .wait_with_output()
        .expect("APPARATUS: collect post-receipt expiry managed-node attach");
    let receipt_attached_out = String::from_utf8_lossy(&receipt_attached.stdout);
    let receipt_attached_err = String::from_utf8_lossy(&receipt_attached.stderr);
    assert!(
        receipt_attached.status.success(),
        "PRODUCT [FX28 startup-ready-reconcile]: after exact applied revision {receipt_race_revision} expired, the managed node did not become Ready through final startup reconciliation: {receipt_attached_out}{receipt_attached_err}"
    );
    right.expect_apparatus_event(
        "managed node Ready after exact post-receipt expiry reconciliation",
        |line| line.contains("after-remote-anchor-b is Ready"),
    );
    let reconcile_deadline = Instant::now() + RETURN_WITHIN;
    loop {
        if receipt_reconcile_fault.is_file() {
            panic!(
                "APPARATUS: exact later post-receipt reconciliation hold failed: {}",
                std::fs::read_to_string(&receipt_reconcile_fault).unwrap_or_default()
            );
        }
        if receipt_reconcile_engaged.is_file() {
            break;
        }
        assert!(
            daemon_alive(right.child.id()),
            "APPARATUS: answerer exited before holding later reconciliation after post-receipt Ready"
        );
        assert!(
            Instant::now() < reconcile_deadline,
            "APPARATUS: answerer remained live but did not reach later reconciliation after post-receipt Ready"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        std::fs::read_to_string(&receipt_reconcile_engaged)
            .expect("APPARATUS: read exact later post-receipt reconciliation identity"),
        format!("{bob}\t{receipt_race_revision}"),
        "APPARATUS: later post-receipt reconciliation hold named another node or revision"
    );
    let remote = application_toward(&b, &a_id);
    let (_, grants, grant_error) = b.run(&["trust", "list", "--node", "after-remote-anchor-b"], "");
    assert!(
        exact_grants(&b, "after-remote-anchor-b", &[]),
        "PRODUCT [FX28 startup-ready-state-lock]: Ready published stale authority from exact expired applied revision {receipt_race_revision}: status {remote}; shipped trust output {grants}; error {grant_error}"
    );

    // Extend the same merge-before-reply journey through the exact crash window the durable
    // stores cannot make atomic. The answerer first parks its reply after the merge. Its managed
    // actor then durably prepares the exact rollback set, commits the node keyring, publishes the
    // causal boundary marker and exits before the ordinary applied receipt. On restart, shipped
    // status must name the unresolved exchange expired and shipped trust must show no authority.
    // Mutant: omit only the durable pre-keyring record; the new grant survives recovery and this
    // assertion turns red on its own user-visible output.
    stop_pid(right.child.id());
    right
        .child
        .wait()
        .expect("APPARATUS: stop right daemon before exact keyring-commit crash staging");
    right = start(
        &b,
        "[::1]:0",
        &v6,
        &[
            (
                "VOX_TEST_HOLD_COMPUTER_ANSWER_AFTER_MERGE_FILE",
                &answer_after_merge_spec,
            ),
            (
                "VOX_TEST_CRASH_AFTER_COMPUTER_KEYRING_COMMIT_FILE",
                &keyring_commit_crash_spec,
            ),
        ],
    );
    assert!(
        !answer_after_merge_engaged.exists()
            && !keyring_commit_crash_committed.exists()
            && !keyring_commit_crash_fault.exists(),
        "APPARATUS: an earlier hook invocation left an exact-boundary marker in the scratch account"
    );
    std::fs::write(&answer_after_merge_arm, b"armed")
        .expect("APPARATUS: arm exact merge-before-reply hold for crash recovery");
    let committed_then_crashed = a.make_node("committed-before-receipt-crash");
    std::fs::write(&keyring_commit_crash_arm, &committed_then_crashed)
        .expect("APPARATUS: arm exact post-keyring/pre-receipt crash");
    let before_commit_crash = computer(&a, &["status"])["revision"].as_u64().unwrap_or(0);
    let (ok, out, err) = a.run(
        &[
            "node",
            "attach",
            "committed-before-receipt-crash",
            "--passphrase-file",
            "-",
        ],
        PASS,
    );
    assert!(
        ok,
        "PRODUCT: attach exact keyring-commit crash node: {out}{err}"
    );
    let committed_revision = computer(&a, &["status"])["revision"]
        .as_u64()
        .filter(|revision| *revision > before_commit_crash)
        .unwrap_or_else(|| {
            panic!("PRODUCT: attaching the keyring-commit crash node moved no policy revision")
        });
    let staging_deadline = Instant::now() + RETURN_WITHIN;
    loop {
        if keyring_commit_crash_fault.is_file() {
            panic!(
                "APPARATUS: exact keyring-commit crash hook failed: {}",
                std::fs::read_to_string(&keyring_commit_crash_fault).unwrap_or_default()
            );
        }
        if keyring_commit_crash_committed.is_file() {
            break;
        }
        if let Some(status) = right
            .child
            .try_wait()
            .expect("APPARATUS: inspect exact keyring-commit crash daemon")
        {
            panic!(
                "APPARATUS: answerer exited {status} without publishing the exact durable keyring-commit boundary: {}",
                right.said()
            );
        }
        assert!(
            Instant::now() < staging_deadline,
            "APPARATUS: answerer remained live but never reached the exact durable keyring-commit boundary"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let crash_marker = std::fs::read_to_string(&keyring_commit_crash_committed)
        .expect("APPARATUS: read exact durable keyring-commit marker");
    assert_eq!(
        crash_marker,
        format!("{bob}\t{committed_revision}\t{committed_then_crashed}"),
        "APPARATUS: keyring-commit crash marker named a different node, revision, or grant"
    );
    assert!(
        answer_after_merge_engaged.is_file(),
        "APPARATUS: keyring commit occurred without the exchange parked at merge-before-reply"
    );
    let crash_status = right
        .child
        .wait()
        .expect("APPARATUS: reap exact keyring-commit crash daemon");
    assert_eq!(
        crash_status.code(),
        Some(86),
        "APPARATUS: exact keyring-commit hook did not own the staged process exit"
    );
    println!(
        "[proof] FX-28 keyring-commit recovery apparatus staged: revision {committed_revision}, node {bob}, grant {committed_then_crashed}"
    );
    right = start(&b, "[::1]:0", &v6, &[]);
    right.expect_apparatus_event(
        "node after-remote-anchor-b is Ready after exact keyring-commit recovery",
        |line| line.contains("after-remote-anchor-b is Ready"),
    );
    // Ready is published only after startup reconciles computer policy, and Management recovers
    // pending exchanges before that actor starts. Status therefore owes the exact durable miss
    // now; polling would add no causal event and could hide a missing publication indefinitely.
    let recovered_status = computer(&b, &["status"]);
    let recovered = recovered_status["applications"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|application| application["computer"]["fingerprint"] == a_id)
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    assert!(
        recovered["missed_revision"] == committed_revision
            && matches!(
                recovered["convergence_state"].as_str(),
                Some("expired" | "repaired-late")
            ),
        "PRODUCT [FX28 keyring-commit-crash]: after the restarted managed node became Ready, shipped status did not retain exact interrupted revision {committed_revision} as expired or repaired-late: {recovered_status}"
    );
    let (_, grants, grant_error) = b.run(&["trust", "list", "--node", "after-remote-anchor-b"], "");
    assert!(
        exact_grants(&b, "after-remote-anchor-b", &[]),
        "PRODUCT [FX28 keyring-commit-crash]: after restart made exact merged revision {committed_revision} expired, the managed node retained authority committed before its missing applied receipt: status {recovered_status}; shipped trust output {grants}; error {grant_error}"
    );
    drop((left, right, relay));
}

/// The addresses an room link gives for identity `fp` (its `b=` values after `a=<fp>`).
fn addresses_for(link: &str, fp: &str) -> Vec<String> {
    let Some((_, query)) = link.split_once('?') else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut current = "";
    for pair in query.split('&') {
        if let Some(a) = pair.strip_prefix("a=") {
            current = a;
        } else if let Some(b) = pair.strip_prefix("b=") {
            if current == fp {
                out.push(b.to_owned());
            }
        }
    }
    out
}

/// **D-1: `vox daemon`s started at once, naming a node each, end with one daemon holding every
/// node.** Three nodes of one account, each started by its own `vox daemon --node <n>` at the same
/// moment with no daemon running: one takes the lock and becomes the account's daemon; the other
/// two MUST hand their node to it (D-1), not fail because it is not answering yet.
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn daemons_started_at_once_hand_their_nodes_to_one() {
    const N: usize = 3;
    watchdog::arm();
    let a = Account::new();
    let names: Vec<String> = (0..N).map(|i| format!("n{i}")).collect();
    for n in &names {
        a.make_node(n);
    }
    let daemons: Vec<Daemon> = std::thread::scope(|s| {
        let hs: Vec<_> = names
            .iter()
            .map(|n| {
                let a = &a;
                s.spawn(move || Daemon::start(a, &["--node", n], &[]))
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let held: Vec<bool> = names
        .iter()
        .zip(&daemons)
        .map(|(n, d)| {
            wait_until(Duration::from_secs(90), || {
                d.said().lines().any(|l| {
                    l.starts_with("vox daemon: identity")
                        || l.contains(&format!("node {n} is held by the daemon already running"))
                })
            })
        })
        .collect();
    let said: Vec<String> = daemons.into_iter().map(Daemon::stop).collect();
    eprintln!("[proof] each start held its node: {held:?}");
    assert!(
        held.iter().all(|h| *h),
        "PRODUCT: of {N} `vox daemon --node` started at once, not every one held its node          (D-1: one is the daemon, the others hand their node to it): {held:?}
{}",
        names
            .iter()
            .zip(&said)
            .map(|(n, s)| format!("--- vox daemon --node {n} said:\n{s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// **Proof 1 (ADR-026 §10, C-3, D-3): nodes attached at once all serve, at one address, each as
/// itself.** Three nodes of one account: `n0`'s `vox daemon` is the account's daemon, and `n1` and
/// `n2` are handed to it **at the same moment**, each by its own `vox daemon --node <n>`. Each node
/// makes a room at once; every invite gives the
/// same address for its node. A member on another account joins all three rooms — each join
/// reaching its node through that one ip:port, which must prove it is that node — and all four
/// post at once: the member reads each node's post and each node reads the member's.
///
/// What is reused from this file: `Account`, `Daemon`, `make_room`, `lock_pid`, `daemons_of`.
///
/// Mutation: the shared endpoint answering an `ASK` with **another** registered node's key
/// (`Answering::host` in `transport/quic.rs`): a join to any node but that one is refused, red.
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn nodes_attached_at_once_all_serve_at_one_address_each_as_itself() {
    const N: usize = 3;
    watchdog::arm();
    let a = Account::new();
    let names: Vec<String> = (0..N).map(|i| format!("n{i}")).collect();
    let fps: Vec<String> = names.iter().map(|n| a.make_node(n)).collect();

    // n0's daemon first; then n1 and n2 handed to it at once.
    let first = Daemon::start(&a, &["--node", "n0"], &[]);
    first.expect("its identity", Duration::from_secs(60), |l| {
        l.starts_with("vox daemon: identity")
    });
    let rest: Vec<Daemon> = std::thread::scope(|s| {
        let hs: Vec<_> = names[1..]
            .iter()
            .map(|n| {
                let a = &a;
                s.spawn(move || Daemon::start(a, &["--node", n], &[]))
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let daemons: Vec<Daemon> = std::iter::once(first).chain(rest).collect();
    for (n, d) in names.iter().zip(&daemons) {
        d.expect(
            &format!("node {n} held (as the daemon or by it)"),
            Duration::from_secs(90),
            |l| {
                l.starts_with("vox daemon: identity")
                    || l.contains(&format!(
                        "node {n} is held by the daemon already running here"
                    ))
            },
        );
    }
    let pid = a.lock_pid().unwrap_or_else(|| {
        panic!(
            "PRODUCT: no daemon holds the account's lock\nlog:\n{}",
            a.log()
        )
    });
    let held: Vec<bool> = names
        .iter()
        .map(|n| a.run(&["room", "list", "--node", n], "").0)
        .collect();
    let serving = daemons_of(&a.data);
    eprintln!("[proof] lock holder {pid}; daemons serving the account {serving:?}; each node answers {held:?}");
    assert!(
        held.iter().all(|h| *h),
        "PRODUCT: not every node attached at once answers: {held:?}"
    );

    // A room on each node, made at once.
    let rooms: Vec<String> = std::thread::scope(|s| {
        let hs: Vec<_> = names
            .iter()
            .map(|n| {
                let a = &a;
                s.spawn(move || make_room(a, n))
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let links: Vec<String> = names
        .iter()
        .zip(&rooms)
        .map(|(n, r)| {
            let (ok, out, err) = a.run(&["room", "link", "--node", n, r], "");
            assert!(ok, "APPARATUS: room link on {n}: {out}{err}");
            out.lines()
                .find(|l| l.starts_with("vox://"))
                .unwrap_or_else(|| panic!("APPARATUS: no room link from {n}: {out}"))
                .trim()
                .to_owned()
        })
        .collect();
    let addrs: Vec<Vec<String>> = links
        .iter()
        .zip(&fps)
        .map(|(l, fp)| addresses_for(l, fp))
        .collect();
    eprintln!("[proof] each node's invite gives it at: {addrs:?}");
    let shared: Vec<&String> = addrs[0]
        .iter()
        .filter(|x| addrs.iter().all(|v| v.contains(x)))
        .collect();
    // Asserted last, so a red here still says whether every node served.
    let one_address = !shared.is_empty();

    // The member, on an account of its own.
    let m = Account::new();
    let m_fp = m.make_node("default");
    let mpass = m.data.with_extension("pass");
    std::fs::write(&mpass, format!("{PASS}\n")).unwrap();
    let md = Daemon::start(&m, &["--passphrase-file", mpass.to_str().unwrap()], &[]);
    md.expect("its identity", Duration::from_secs(60), |l| {
        l.starts_with("vox daemon: identity")
    });
    for (n, fp) in names.iter().zip(&fps) {
        let (ok, out, err) = a.run(&["trust", "add", "--node", n, &m_fp, "--name", "m"], "");
        assert!(ok, "APPARATUS: {n} trusts the member: {out}{err}");
        let (ok, out, err) = m.run(&["trust", "add", fp, "--name", n], "");
        assert!(ok, "APPARATUS: the member trusts {n}: {out}{err}");
    }
    // Every join at once, through the one address.
    let joined: Vec<(bool, String, String)> = std::thread::scope(|s| {
        let hs: Vec<_> = links
            .iter()
            .map(|link| {
                let m = &m;
                s.spawn(move || m.run(&["room", "join", "--passphrase-file", "-", link], ROOM_PASS))
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for (n, (ok, out, err)) in names.iter().zip(&joined) {
        assert!(
            *ok,
            "PRODUCT: the member's join of {n}'s room, at the daemon's one address, failed: \
             {out}{err}\nhost log:\n{}\nfirst daemon said:\n{}",
            a.log(),
            daemons[0].said()
        );
    }

    // Everyone posts at once.
    std::thread::scope(|s| {
        for (n, r) in names.iter().zip(&rooms) {
            let (a, m) = (&a, &m);
            s.spawn(move || {
                let _ = a.run(&["room", "post", "--node", n, r, &format!("from-{n}")], "");
            });
            s.spawn(move || {
                let _ = m.run(&["room", "post", r, &format!("to-{n}")], "");
            });
        }
    });
    let mut missing = Vec::new();
    for (n, r) in names.iter().zip(&rooms) {
        let member_read = wait_until(Duration::from_secs(90), || {
            m.run(&["room", "read", r], "")
                .1
                .contains(&format!("from-{n}"))
        });
        let node_read = wait_until(Duration::from_secs(90), || {
            a.run(&["room", "read", "--node", n, r], "")
                .1
                .contains(&format!("to-{n}"))
        });
        eprintln!("[proof] {n}: the member read its post = {member_read}; it read the member's = {node_read}");
        if !member_read {
            missing.push(format!("the member did not read {n}'s post"));
        }
        if !node_read {
            missing.push(format!("{n} did not read the member's post"));
        }
    }
    let said: Vec<String> = daemons.into_iter().map(Daemon::stop).collect();
    md.stop();
    assert!(
        missing.is_empty(),
        "PRODUCT: nodes attached at once on one daemon do not all serve: {missing:?}\n\
         host log:\n{}\ndaemons said:\n{}",
        a.log(),
        said.join("\n---\n")
    );
    assert!(
        one_address,
        "PRODUCT: every node served, but the nodes of one daemon are not at one address (D-3): \
         {addrs:?}"
    );
}

/// **Proof 7, from a member's side (ADR-026 L-4, D-3): a kept node comes back after a daemon
/// restart at the address its members hold, and they reach it there.** A kept node with a room a
/// member on another account joined; the daemon stops and a daemon started in the background
/// attaches the node again. Its invite gives the same address as before the restart, and the
/// member and the node each read what the other posts after it.
///
/// What is reused from this file: `Account`, `Daemon`, `make_room`, `lock_pid`, `stop_pid`, and
/// the keep staging of `a_kept_node_and_its_room_come_back_after_a_restart`.
///
/// Mutation: the daemon binding a new port at each start (`.daemon/port` not read): the address
/// changes, red.
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn a_kept_node_is_reached_again_at_its_address_after_a_restart() {
    watchdog::arm();
    let a = Account::new();
    let fp = a.make_node("default");
    let pass = a.data.with_extension("pass");
    std::fs::write(&pass, format!("{PASS}\n")).unwrap();
    let d = Daemon::start(&a, &["--passphrase-file", pass.to_str().unwrap()], &[]);
    d.expect("its identity", Duration::from_secs(60), |l| {
        l.starts_with("vox daemon: identity")
    });
    let room = make_room(&a, "default");
    d.stop();
    std::fs::write(&pass, format!("{PASS}\n{ROOM_PASS}\n")).unwrap();
    let d = Daemon::start(
        &a,
        &["--keep", "--passphrase-file", pass.to_str().unwrap()],
        &[],
    );
    d.expect("the room held open", Duration::from_secs(60), |l| {
        l.starts_with("vox daemon: holding room")
    });
    let invite = |a: &Account| {
        let (ok, out, err) = a.run(&["room", "link", &room], "");
        assert!(ok, "PRODUCT: room link: {out}{err}");
        out.lines()
            .find(|l| l.starts_with("vox://"))
            .unwrap_or_else(|| panic!("PRODUCT: no room link: {out}"))
            .trim()
            .to_owned()
    };
    let link = invite(&a);
    let before = addresses_for(&link, &fp);

    let m = Account::new();
    let m_fp = m.make_node("default");
    let mpass = m.data.with_extension("pass");
    std::fs::write(&mpass, format!("{PASS}\n")).unwrap();
    let md = Daemon::start(&m, &["--passphrase-file", mpass.to_str().unwrap()], &[]);
    md.expect("its identity", Duration::from_secs(60), |l| {
        l.starts_with("vox daemon: identity")
    });
    assert!(
        a.run(&["trust", "add", &m_fp, "--name", "m"], "").0,
        "APPARATUS: trust m"
    );
    assert!(
        m.run(&["trust", "add", &fp, "--name", "a"], "").0,
        "APPARATUS: trust a"
    );
    let (ok, out, err) = m.run(
        &["room", "join", "--passphrase-file", "-", &link],
        ROOM_PASS,
    );
    assert!(ok, "PRODUCT (staging): the member's join: {out}{err}");

    // The restart.
    d.stop();
    let (ok, out, err) = a.run(&["daemon", "--detach"], "");
    assert!(ok, "PRODUCT: vox daemon --detach failed: {out}{err}");
    let pid = a.lock_pid().expect("PRODUCT: no daemon holds the lock");
    let attached = wait_until(Duration::from_secs(60), || {
        a.log().contains("vox daemon: node default is Ready")
    });
    let after = if attached {
        addresses_for(&invite(&a), &fp)
    } else {
        Vec::new()
    };
    eprintln!("[proof] the node's address before the restart {before:?}, after {after:?}");
    let _ = a.run(&["room", "post", &room, "after-the-restart-from-a"], "");
    let _ = m.run(&["room", "post", &room, "after-the-restart-from-m"], "");
    let m_read = wait_until(Duration::from_secs(90), || {
        m.run(&["room", "read", &room], "")
            .1
            .contains("after-the-restart-from-a")
    });
    let a_read = wait_until(Duration::from_secs(90), || {
        a.run(&["room", "read", &room], "")
            .1
            .contains("after-the-restart-from-m")
    });
    let log = a.log();
    stop_pid(pid);
    md.stop();
    assert!(
        attached,
        "PRODUCT: the restart did not attach the kept node\nlog:\n{log}"
    );
    assert!(
        !before.is_empty() && before == after,
        "PRODUCT: the kept node is at another address after the restart (D-3): {before:?} → \
         {after:?}"
    );
    assert!(
        m_read && a_read,
        "PRODUCT: after the restart the member read the node = {m_read}, the node read the \
         member = {a_read}\nlog:\n{log}"
    );
}

/// #801/#802: use the existing account/CLI journey's staging without replaying #799/#800's
/// pairing, anchor, expired-invitation or storage-failure assertions. These three computers
/// exercise only the changed roster, selection, removal and explicit binding outcomes.
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn enrolled_computers_follow_node_changes_and_retire_removed_authority() {
    watchdog::arm();
    let a = Account::new();
    let b = Account::new();
    let c = Account::new();
    let ready = |account: &Account, name: &str| {
        let (ok, out, err) = account.run(&["node", "unlock", name, "--passphrase-file", "-"], PASS);
        assert!(ok, "PRODUCT: ready {name}: {out}{err}");
    };
    let create = |account: &Account, name: &str| {
        let id = account.make_node(name);
        let (ok, out, err) = account.run(&["node", "unlock", name, "--passphrase-file", "-"], PASS);
        assert!(
            ok,
            "APPARATUS: create/ready scratch node {name}: {out}{err}"
        );
        id
    };
    let old = create(&a, "old-personal");
    let new = create(&a, "new-personal");
    let remote = create(&b, "remote-personal");
    let worker = create(&b, "worker");
    let moving = create(&b, "moving");
    create(&c, "observer");
    let ring = |account: &Account, name: &str| {
        let (ok, out, err) = account.run(&["trust", "list", "--node", name], "");
        assert!(
            ok,
            "PRODUCT: {name}'s effective keyring unavailable: {out}{err}"
        );
        out
    };
    let has = |shown: &str, fp: &str, drive: bool| {
        shown
            .lines()
            .any(|line| line.contains(fp) && line.contains("read + drive") == drive)
    };
    // This earlier individual exception must not survive removal of its computer.
    for (account, name) in [(&a, "old-personal"), (&c, "observer")] {
        let (ok, out, err) = account.run(
            &[
                "trust",
                "add",
                &remote,
                "--name",
                "my-remote",
                "--drive",
                "--node",
                name,
            ],
            "",
        );
        assert!(ok, "APPARATUS: earlier individual drive: {out}{err}");
    }
    computer(&a, &["personal", "old-personal"]);
    computer(&b, &["personal", "remote-personal"]);
    let enroll = |sponsor: &Account, incoming: &Account, verdict: &str| {
        let staging = |account: &Account, args: &[&str]| {
            let args: Vec<_> = [vec!["computer"], args.to_vec(), vec!["--json"]].concat();
            let (ok, out, err) = account.run(&args, "");
            assert!(ok, "{verdict}: enrollment command {args:?}: {out}{err}");
            serde_json::from_str::<serde_json::Value>(&out)
                .unwrap_or_else(|e| panic!("{verdict}: enrollment status: {e}: {out}"))
        };
        let offer = staging(sponsor, &["invite"]);
        let preview = staging(
            incoming,
            &["pair", offer["invite_link"].as_str().unwrap(), "--preview"],
        );
        let op = preview["pairing"]["operation_id"].as_str().unwrap();
        staging(incoming, &["approve", op]);
        staging(sponsor, &["approve", op]);
        assert!(
            wait_until(Duration::from_secs(60), || {
                [sponsor, incoming].into_iter().all(|account| {
                    let status = staging(account, &["status"]);
                    status["pairing"].is_null()
                        && status["computers"].as_array().is_some_and(|v| v.len() >= 2)
                })
            }),
            "{verdict}: enrollment did not complete before the next operation"
        );
    };
    enroll(&a, &b, "APPARATUS");
    enroll(&b, &c, "APPARATUS");
    assert!(
        wait_until(Duration::from_secs(60), || has(
            &ring(&b, "worker"),
            &old,
            true
        ) && has(
            &ring(&b, "worker"),
            &new,
            false
        ) && has(
            &ring(&c, "observer"),
            &worker,
            false
        )),
        "APPARATUS: three-computer fixed-policy staging never completed"
    );
    let a_id = computer(&a, &["status"])["this_computer"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    let b_id = computer(&b, &["status"])["this_computer"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    let c_id = computer(&c, &["status"])["this_computer"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();

    let room = make_room(&b, "worker");
    let link = b.run(&["room", "link", &room, "--node", "worker"], "").1;
    let link = link
        .lines()
        .find(|l| l.starts_with("vox://"))
        .expect("APPARATUS: room link");
    for (account, node) in [
        (&a, "old-personal"),
        (&a, "new-personal"),
        (&b, "remote-personal"),
        (&c, "observer"),
    ] {
        let (ok, out, err) = account.run(
            &[
                "room",
                "join",
                link,
                "--node",
                node,
                "--passphrase-file",
                "-",
            ],
            ROOM_PASS,
        );
        assert!(
            ok,
            "APPARATUS: shared room for changed drive outcome: {out}{err}"
        );
    }
    // The real harness hook opens a real Session. Driving a file needs no terminal stand-in:
    // success means the peer actually receives the exact bytes; refusal must leave no file.
    let hook = |account: &Account, node: &str, session: &str| {
        let payload = format!(
            r#"{{"session_id":"{session}","hook_event_name":"UserPromptSubmit","cwd":"{}","prompt":"computer policy update"}}"#,
            account._tmp.path().display()
        );
        let (ok, out, err) = account.run(
            &["agent", "hook", "--node", node, "--room", &room],
            &payload,
        );
        assert!(ok, "APPARATUS: Session hook for {node}: {out}{err}");
    };
    hook(&b, "worker", "computer-policy-worker");
    hook(&a, "old-personal", "computer-policy-local");
    let files = |account: &Account, node: &str, name: &str| -> bool {
        let root = account.data.join("nodes").join(node).join("files");
        std::fs::read_dir(root)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .any(|entry| {
                std::fs::read(entry.path().join(name)).ok().as_deref()
                    == Some(b"computer-policy-payload")
            })
    };
    let drive = |from: &Account,
                 node: &str,
                 to: &Account,
                 target: &str,
                 session: &str,
                 name: &str,
                 allowed: bool| {
        let file = from._tmp.path().join(name);
        std::fs::write(&file, b"computer-policy-payload").unwrap();
        let (ok, out, err) = from.run(
            &[
                "room",
                "session",
                &room,
                session,
                "--file",
                file.to_str().unwrap(),
                "--node",
                node,
            ],
            "",
        );
        if allowed {
            assert!(
                ok && out.contains("pulling"),
                "PRODUCT: {node}'s current automatic drive did not deliver its file: {out}{err}"
            );
            assert!(
                wait_until(Duration::from_secs(30), || files(to, target, name)),
                "PRODUCT: accepted drive file from {node} did not arrive byte-for-byte"
            );
        } else {
            assert!(!ok, "PRODUCT: {node} retained revoked drive: {out}{err}");
            assert!(
                !files(to, target, name),
                "PRODUCT: refused drive from {node} still delivered a file"
            );
        }
    };
    assert!(
        wait_until(Duration::from_secs(30), || a
            .run(
                &[
                    "room",
                    "sessions",
                    &room,
                    "--node",
                    "old-personal",
                    "--json"
                ],
                ""
            )
            .1
            .contains("computer-policy-worker")),
        "APPARATUS: initial driver did not discover the target Session"
    );
    drive(
        &a,
        "old-personal",
        &b,
        "worker",
        "computer-policy-worker",
        "before-selection",
        true,
    );

    offline_for_enrollment(&c, "selection observer");
    computer(&a, &["personal", "new-personal"]);
    assert!(
        wait_until(Duration::from_secs(30), || has(
            &ring(&b, "worker"),
            &new,
            true
        ) && has(
            &ring(&b, "worker"),
            &old,
            false
        )),
        "PRODUCT: personal selection did not move drive from old to new"
    );
    let pending = computer(&a, &["status"]);
    assert!(
        pending["applications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["computer"]["fingerprint"] == c_id && v["confirmed"] == false),
        "PRODUCT: offline computer falsely acknowledged the selection: {pending}"
    );
    drive(
        &a,
        "old-personal",
        &b,
        "worker",
        "computer-policy-worker",
        "old-after-selection",
        false,
    );
    assert!(
        wait_until(Duration::from_secs(30), || a
            .run(
                &[
                    "room",
                    "sessions",
                    &room,
                    "--node",
                    "new-personal",
                    "--json"
                ],
                ""
            )
            .1
            .contains("computer-policy-worker")),
        "PRODUCT: new personal node could not discover its newly authorized Session"
    );
    drive(
        &a,
        "new-personal",
        &b,
        "worker",
        "computer-policy-worker",
        "new-after-selection",
        true,
    );
    offline_for_enrollment(&a, "saved selection");
    ready(&a, "new-personal");
    ready(&a, "old-personal");
    assert_eq!(
        computer(&a, &["status"])["selected_node"],
        new,
        "PRODUCT: daemon restart forgot the saved personal identity"
    );
    ready(&c, "observer");
    assert!(
        wait_until(Duration::from_secs(30), || has(
            &ring(&c, "observer"),
            &new,
            true
        ) && has(
            &ring(&c, "observer"),
            &old,
            false
        )),
        "PRODUCT: reconnect restored stale personal drive"
    );
    computer(&a, &["personal", "--clear"]);
    assert!(
        wait_until(Duration::from_secs(30), || has(
            &ring(&b, "worker"),
            &new,
            false
        )),
        "PRODUCT: headless selection retained personal drive"
    );
    computer(&a, &["personal", "new-personal"]);
    assert!(
        wait_until(Duration::from_secs(30), || has(
            &ring(&b, "worker"),
            &new,
            true
        )),
        "PRODUCT: headless computer could not select a personal node without re-pairing"
    );

    let added = create(&a, "added");
    assert!(
        wait_until(Duration::from_secs(30), || has(
            &ring(&b, "worker"),
            &added,
            false
        ) && has(
            &ring(&c, "observer"),
            &added,
            false
        )),
        "PRODUCT: new node did not acquire the group read policy"
    );
    // Each person's alias stays theirs. Choose it through the real terminal before changing
    // the presented node name; this also supplies the required keyring passphrase premise.
    for (account, node) in [(&b, "worker"), (&a, "old-personal"), (&a, "new-personal")] {
        let (ok, out, err) = account.run(
            &["trust", "rename", &added, "my-stable-alias", "--node", node],
            "",
        );
        assert!(ok, "APPARATUS: chosen local alias: {out}{err}");
    }
    let (ok, out, err) = a.run(&["node", "rename", "added", "renamed"], "");
    assert!(ok, "PRODUCT: managed-node rename: {out}{err}");
    ready(&a, "renamed");
    assert!(
        wait_until(Duration::from_secs(30), || {
            let status = computer(&c, &["status"]);
            status["computers"].as_array().is_some_and(|v| v.len() == 3)
                && status["nodes"].as_array().unwrap().iter().any(|n| {
                    n["fingerprint"] == added && n["computer"] == a_id && n["name"] == "renamed"
                })
        }),
        "PRODUCT: authenticated rename did not preserve its fingerprint, manager and membership"
    );
    assert!(
        ring(&b, "worker")
            .lines()
            .any(|l| l.contains(&added) && l.contains("my-stable-alias")),
        "PRODUCT: presented rename replaced the person's alias"
    );
    let (ok, out, err) = a.run(&["node", "lock", "renamed"], "");
    assert!(
        ok,
        "APPARATUS: stop owned node before deleting its scratch directory: {out}{err}"
    );
    std::fs::remove_dir_all(a.data.join("nodes/renamed")).unwrap();
    assert!(
        wait_until(Duration::from_secs(30), || !ring(&b, "worker")
            .contains(&added)
            && !ring(&c, "observer").contains(&added)),
        "PRODUCT: removed node retained roster grants"
    );
    let replacement = create(&a, "renamed");
    assert_ne!(
        replacement, added,
        "APPARATUS: replacement needs a fresh identity"
    );
    assert!(
        wait_until(Duration::from_secs(30), || has(
            &ring(&b, "worker"),
            &replacement,
            false
        )),
        "PRODUCT: replacement identity was not published"
    );
    assert!(
        !ring(&b, "worker")
            .lines()
            .any(|l| l.contains(&replacement) && l.contains("my-stable-alias")),
        "PRODUCT: a replacement fingerprint silently inherited the old identity's alias"
    );

    let binding = |account: &Account, action: &str, node: &str, destination: &str| {
        let status = computer(account, &["status"]);
        computer(
            account,
            &[
                "binding",
                action,
                node,
                "--destination",
                destination,
                "--confirm",
                status["frontier"].as_str().unwrap(),
            ],
        )
    };
    let copy_node = |from: &Account, to: &Account, name: &str| {
        let (ok, out, err) = from.run(&["node", "lock", name], "");
        assert!(ok, "APPARATUS: close owned transfer vault: {out}{err}");
        let copied = Command::new("cp")
            .arg("-R")
            .arg(from.data.join("nodes").join(name))
            .arg(to.data.join("nodes").join(name))
            .status()
            .unwrap();
        assert!(
            copied.success(),
            "APPARATUS: copy only the owned scratch node vault"
        );
    };
    copy_node(&b, &a, "moving");
    let (ok, out, err) = a.run(
        &["node", "unlock", "moving", "--passphrase-file", "-"],
        PASS,
    );
    assert!(
        !ok,
        "PRODUCT: copied vault silently changed managers: {out}{err}"
    );
    binding(&b, "release", &moving, &a_id);
    assert!(
        wait_until(Duration::from_secs(30), || computer(&a, &["status"])
            ["binding_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["node"] == moving && v["action"] == "transfer")),
        "PRODUCT: signed release did not reach its chosen destination"
    );
    binding(&a, "transfer", &moving, "");
    ready(&a, "moving");
    assert!(
        wait_until(Duration::from_secs(30), || computer(&c, &["status"])
            ["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["fingerprint"] == moving && n["computer"] == a_id)),
        "PRODUCT: approved node+destination binding did not transfer management"
    );

    // A previously stronger individual grant is already consumed by policy; changing A's
    // personal node makes old-personal a drive target for B's personal node.
    hook(&a, "old-personal", "computer-policy-local");
    assert!(
        wait_until(Duration::from_secs(30), || b
            .run(
                &[
                    "room",
                    "sessions",
                    &room,
                    "--node",
                    "remote-personal",
                    "--json"
                ],
                ""
            )
            .1
            .contains("computer-policy-local")),
        "APPARATUS: remote personal Session discovery before removal"
    );
    drive(
        &b,
        "remote-personal",
        &a,
        "old-personal",
        "computer-policy-local",
        "before-removal",
        true,
    );
    offline_for_enrollment(&c, "removal observer");
    let status = computer(&a, &["status"]);
    computer(
        &a,
        &[
            "remove",
            &b_id,
            "--confirm",
            status["frontier"].as_str().unwrap(),
        ],
    );
    assert!(
        wait_until(Duration::from_secs(30), || !ring(&a, "old-personal")
            .contains(&remote)
            && !ring(&a, "new-personal").contains(&worker)),
        "PRODUCT: removal preserved pre-pairing individual or group trust"
    );
    let pending = computer(&a, &["status"]);
    assert!(
        pending["removed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["fingerprint"] == b_id)
            && pending["applications"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["computer"]["fingerprint"] == c_id && v["confirmed"] == false),
        "PRODUCT: removal/remaining offline application was not shown truthfully: {pending}"
    );
    drive(
        &b,
        "remote-personal",
        &a,
        "old-personal",
        "computer-policy-local",
        "after-removal",
        false,
    );
    ready(&c, "observer");
    assert!(
        wait_until(Duration::from_secs(30), || !ring(&c, "observer")
            .contains(&remote)
            && !ring(&c, "observer").contains(&worker)),
        "PRODUCT: reconnect kept the removed computer's old grants"
    );
    offline_for_enrollment(&b, "removed computer");
    ready(&b, "remote-personal");
    assert!(
        wait_until(Duration::from_secs(30), || computer(&b, &["status"])
            ["state"]
            == "removed"),
        "PRODUCT: removed computer's restart/old view restored membership"
    );
    for (account, node, peer, name) in [
        (&a, "old-personal", remote.as_str(), "my-remote"),
        (&b, "remote-personal", old.as_str(), "old-personal"),
    ] {
        let (ok, out, err) = account.run(
            &[
                "trust", "add", peer, "--name", name, "--drive", "--node", node,
            ],
            "",
        );
        assert!(
            ok,
            "PRODUCT: later explicit individual trust was refused: {out}{err}"
        );
    }
    offline_for_enrollment(&a, "later individual trust");
    ready(&a, "old-personal");
    ready(&a, "new-personal");
    assert!(
        has(&ring(&a, "old-personal"), &remote, true),
        "PRODUCT: replay/restart purged a deliberate post-removal individual grant"
    );

    // Lost-manager recovery uses the retained former binding and removal frontier, and the
    // destination still needs the node's real unlocked key. Copying alone remains insufficient.
    copy_node(&b, &c, "worker");
    binding(&c, "recover", &worker, "");
    ready(&c, "worker");
    assert!(
        wait_until(Duration::from_secs(30), || computer(&a, &["status"])
            ["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["fingerprint"] == worker && n["computer"] == c_id)),
        "PRODUCT: explicit recovery did not publish its successor management binding"
    );
    enroll(&a, &b, "PRODUCT");
    assert!(
        wait_until(Duration::from_secs(30), || computer(&b, &["status"])
            ["computers"]
            .as_array()
            .is_some_and(|v| v.len() == 3)
            && has(&ring(&a, "old-personal"), &remote, true)),
        "PRODUCT: fresh deliberate re-enrollment failed"
    );
    assert!(
        computer(&a, &["status"])["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["fingerprint"] == worker)
            .all(|n| n["computer"] == c_id),
        "PRODUCT: re-enrollment restored the former manager's superseded node binding"
    );
    // Explicitly abandoning a group after the last manager is removed retains retirement
    // evidence, clears covered grants, and permits a fresh ceremony only by operator choice.
    for target in [&a_id, &c_id, &b_id] {
        let status = computer(&b, &["status"]);
        computer(
            &b,
            &[
                "remove",
                target,
                "--confirm",
                status["frontier"].as_str().unwrap(),
            ],
        );
        if target == &a_id {
            assert!(
                wait_until(Duration::from_secs(30), || computer(&a, &["status"])
                    ["state"]
                    == "removed"),
                "PRODUCT: removed A did not receive its signed retirement"
            );
        }
    }
    binding(&b, "recover-group", "group", "");
    assert!(
        computer(&b, &["status"])["computers"]
            .as_array()
            .unwrap()
            .is_empty(),
        "PRODUCT: local group abandonment retained membership"
    );
    assert!(
        !ring(&b, "remote-personal").contains(&old),
        "PRODUCT: local abandonment preserved covered grants"
    );
    assert!(
        wait_until(Duration::from_secs(30), || computer(&a, &["status"])
            ["state"]
            == "removed"),
        "PRODUCT: locally removed manager did not retain retirement evidence"
    );
    binding(&a, "recover-group", "group", "");
    enroll(&b, &a, "PRODUCT");
    assert!(
        wait_until(Duration::from_secs(30), || computer(&a, &["status"])
            ["computers"]
            .as_array()
            .is_some_and(|v| v.len() == 2)),
        "PRODUCT: deliberate fresh group after abandonment failed"
    );
    eprintln!("[proof] #801/#802 changed roster, personal drive, removal, transfer, recovery and deliberate re-enrollment outcomes passed");
}

/// **Two paired computers follow each other's changes and are idle otherwise** (ADR-038 FX-15,
/// FX-28; #989, #1020): alpha and beta, two data roots with a daemon each, pair as computers
/// (`vox computer invite`, `pair --preview`, `approve` on both) and both report `confirmed`.
///
/// A change made on either shows on both: gamma is made and attached on alpha's computer, and
/// within [`CHANGE_SHOWN_WITHIN`] of the attach alpha's `vox computer status` names gamma with
/// every binding derived at the policy revision the change made and every node there trusting
/// every node of both computers (`vox trust list`); within [`CHANGE_SHOWN_WITHIN`] of the
/// same proof-process monotonic clock, begun before the attach command, beta's status names gamma under alpha's
/// computer with every binding there derived at beta's new revision, and every node there trusts
/// every node of both computers. Then
/// delta is attached on beta's computer and the same holds the other way. Both confirm each
/// other again each time.
///
/// A restart derives nothing: beta's daemon is stopped and started again on the same port with
/// nothing changed and its Unix clock one hour ahead. Every binding there shows the same policy
/// revision and the same derived moment as before; later cross-daemon changes still converge, so
/// neither daemon reconstructs a deadline from the other's wall clock.
///
/// A change made while the computers' only userspace path is closed arrives when that path is
/// opened and its exact apparatus path proves a round trip, with both daemon PIDs alive
/// throughout. Within [`RETURN_WITHIN`] of that causal restoration boundary, after every final
/// status and trust observation finishes, beta shows gamma personal, every binding current and
/// every expected keyring grant, and both computers confirmed. The exported broader
/// [`RETURN_WITHIN`] contract still names a peer that must reconnect.
///
/// With all staged nodes hosted and nothing changing, the proof waits for each side's shipped status to
/// name its next completed, dated fallback exchange. Across that causal boundary it MUST count
/// exactly that one attempt/exchange, no earlier round, and every node's binding MUST stand derived
/// at the current policy revision at the same durable moment as before the unchanged-state
/// exchange. There is no arbitrary quiet window: the source-owned fallback cadence plus its
/// existing return contract bounds the named boundary, and the status observations name
/// unnecessary work directly. A machine-dependent CPU cutoff is not a product verdict. Measured
/// before this (2026-10-20, the decider's work Mac): the pairing
/// manager exchanged the whole signed history with every computer every 2 s and re-verified it,
/// and a 1 s tick re-derived every attached node's binding with nothing changed.
/// A test-only causal hold parks delta's exact admitted remote pause at its final publication
/// boundary while durable Computer policy moves; releasing it must make the shipped command
/// refuse, never publish with stale drive. Finally, another causal release keeps delta's exact
/// policy message queued while eta attaches.
/// Within [`CHANGE_SHOWN_WITHIN`], after all final observations finish, beta has applied eta
/// on its healthy node and `vox node list` shows delta no longer attached. Cleanup may continue;
/// queued room/node work cannot turn a late observation into an apparent pass.
///
/// Every elapsed verdict begins before the shipped command or path-restoration action which owns
/// it. Observing a completed exchange is evidence about progress, never permission to restart the
/// stopwatch; a quick final apply therefore cannot conceal an exchange which was already late.
///
/// Independent mutants: (1) remove the need filter in `Management::retry`: extra attempts before
/// the fallback boundary turn PRODUCT red (unchanged means no network); (2) remove the
/// `computer_current` short circuit: the binding-derived moments move across that causal boundary
/// and turn PRODUCT red (unchanged means no re-derive); (3) discard the remote merge before publishing its change: the remote
/// roster/keyring claim turns PRODUCT red; (4) suppress the authenticated reachability wake:
/// the saturated-backoff live heal misses [`RETURN_WITHIN`] and turns PRODUCT red; (5) give
/// reconciliation a fresh timeout or delay `Detaching`: held delta remains Ready past
/// [`CHANGE_SHOWN_WITHIN`] and turns PRODUCT red; (6) serialize siblings behind held delta:
/// beta's binding/keyring claim misses that same bound and turns PRODUCT red; (7) remove the
/// reconciliation ownership checks: an old delayed result detaches either replacement delta or
/// the same attachment applying a newer revision and turns PRODUCT red; (8) bypass the current-authority publication fence: the causally held shipped
/// remote pause publishes after its actor revision becomes stale and turns PRODUCT red. The stuck-node phase begins behind
/// saturated backoff, so resetting either exchange or apply clocks turns its return bound red.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional five minutes of two real vox daemons paired as computers; run in release with optional-proofs"]
fn two_paired_computers_that_are_idle_exchange_nothing() {
    watchdog::arm();
    test_knobs::require(&[
        "VOX_TEST_ADVERTISE",
        "VOX_TEST_CLOCK_STEP_MS",
        "VOX_TEST_HOLD_COMPUTER_POLICY",
        "VOX_TEST_HOLD_COMPUTER_POLICY_REPLY",
        "VOX_TEST_HOLD_ROOM_PAUSE_PUBLICATION",
        "VOX_TEST_HOLD_TEXT_APPEND_PUBLICATION",
        "VOX_TEST_HOLD_ROOM_CREATE_PUBLICATION",
        "VOX_TEST_HOLD_REKEY_ENQUEUE",
        "VOX_TEST_FX28_END_KEY_UNANSWERED_FILE",
        "VOX_TEST_FX28_MARK_ENDED_UNANSWERED_FILE",
        "VOX_TEST_FX28_ROTATE_AFTER_POST",
        "VOX_TEST_MARK_COMPUTER_STATUS_FILE",
        "VOX_TEST_FX28_MUTANT",
        "VOX_TEST_FX28_STOPPED_READER_ARM_FILE",
        "VOX_TEST_FX28_STOPPED_READER_ANSWERED_FILE",
    ]);
    let a = Account::new();
    let b = Account::new();
    let alpha = a.make_node("alpha");
    let beta = b.make_node("beta");
    // Split loopback address families make this userspace forward the only direct path. Its
    // open/close switch changes reachability without stopping either shipped daemon.
    let listen_a = format!("127.0.0.1:{}", port_forward::free_v4_udp_port());
    let forward = port_forward::PortForward::start(
        listen_a
            .parse()
            .unwrap_or_else(|e| panic!("APPARATUS: constructed listen address is invalid: {e}")),
        true,
    );
    let advertised = forward.public.to_string();
    // Beta keeps one endpoint for the whole proof, restart included. A reach that moved would be
    // a change of its own, and the restart claim is that nothing is derived with none.
    let listen_b = format!("[::1]:{}", free_v6_udp_port());
    let hold_arm = b.data.join("hold-delta-computer-policy-arm");
    let hold_engaged = b.data.join("hold-delta-computer-policy-engaged");
    let hold_release = b.data.join("hold-delta-computer-policy-release.sock");
    let hold_spec = format!(
        "delta\t{}\t{}\t{}",
        hold_arm.display(),
        hold_engaged.display(),
        hold_release.display()
    );
    let reply_marker = b.data.join("hold-delta-computer-policy-reply");
    let reply_spec = format!("delta\t15000\t{}", reply_marker.display());
    let stale_pause_arm = b.data.join("hold-delta-stale-pause-arm");
    let stale_pause_engaged = b.data.join("hold-delta-stale-pause-engaged");
    let stale_pause_release = b.data.join("hold-delta-stale-pause-release.sock");
    let stale_pause_spec = format!(
        "delta\t{}\t{}\t{}",
        stale_pause_arm.display(),
        stale_pause_engaged.display(),
        stale_pause_release.display()
    );
    let stale_post_arm = b.data.join("hold-delta-stale-post-arm");
    let stale_post_engaged = b.data.join("hold-delta-stale-post-engaged");
    let stale_post_release = b.data.join("hold-delta-stale-post-release.sock");
    let stale_post_spec = format!(
        "delta\t{}\t{}\t{}",
        stale_post_arm.display(),
        stale_post_engaged.display(),
        stale_post_release.display()
    );
    let stale_create_arm = b.data.join("hold-delta-stale-create-arm");
    let stale_create_engaged = b.data.join("hold-delta-stale-create-engaged");
    let stale_create_release = b.data.join("hold-delta-stale-create-release.sock");
    let stale_create_spec = format!(
        "delta\t{}\t{}\t{}",
        stale_create_arm.display(),
        stale_create_engaged.display(),
        stale_create_release.display()
    );
    let stale_rekey_arm = b.data.join("hold-delta-stale-rekey-arm");
    let stale_rekey_engaged = b.data.join("hold-delta-stale-rekey-engaged");
    let stale_rekey_release = b.data.join("hold-delta-stale-rekey-release.sock");
    let stale_rekey_decision = b.data.join("hold-delta-stale-rekey-decision");
    let stale_rekey_spec = format!(
        "delta\t{}\t{}\t{}\t{}",
        stale_rekey_arm.display(),
        stale_rekey_engaged.display(),
        stale_rekey_release.display(),
        stale_rekey_decision.display()
    );
    let older_arm = a.data.join("fx28-end-key-unanswered-arm");
    let older_marker = a.data.join("fx28-end-key-unanswered-marker");
    let older_spec = format!(
        "epsilon\t{}\t{}",
        older_arm.display(),
        older_marker.display()
    );
    let older_selected_arm = b.data.join("fx28-mark-ended-unanswered-arm");
    let older_selected_marker = b.data.join("fx28-mark-ended-unanswered-marker");
    let older_selected_spec = format!(
        "delta\t{}\t{}",
        older_selected_arm.display(),
        older_selected_marker.display()
    );
    let status_arm = a.data.join("mark-computer-status");
    let status_accepted = a.data.join("accepted-computer-status");
    let status_returned = a.data.join("returned-computer-status");
    let status_spec = format!(
        "{}\t{}\t{}",
        status_arm.display(),
        status_accepted.display(),
        status_returned.display()
    );
    let stopped_reader_arm = a.data.join("fx28-stopped-reader-arm");
    let stopped_reader_generation = b.data.join("fx28-stopped-reader-generation");
    let stopped_reader_answered = b.data.join("fx28-stopped-reader-all-answers");
    let stopped_reader_arm_spec = format!(
        "{}\t{}\t{}",
        stopped_reader_arm.display(),
        stopped_reader_generation.display(),
        stopped_reader_answered.display()
    );
    let stopped_reader_answered_spec = format!(
        "{}\t{}",
        stopped_reader_generation.display(),
        stopped_reader_answered.display()
    );
    let mut da = Daemon::start(
        &a,
        &["--node", "alpha"],
        &[
            ("VOX_LISTEN", &listen_a),
            ("VOX_TEST_ADVERTISE", &advertised),
            ("VOX_TEST_FX28_END_KEY_UNANSWERED_FILE", &older_spec),
            ("VOX_TEST_MARK_COMPUTER_STATUS_FILE", &status_spec),
            (
                "VOX_TEST_FX28_STOPPED_READER_ARM_FILE",
                &stopped_reader_arm_spec,
            ),
        ],
    );
    let mut db = Daemon::start(
        &b,
        &["--node", "beta"],
        &[
            ("VOX_LISTEN", &listen_b),
            ("VOX_TEST_HOLD_COMPUTER_POLICY", &hold_spec),
            ("VOX_TEST_HOLD_COMPUTER_POLICY_REPLY", &reply_spec),
            ("VOX_TEST_HOLD_ROOM_PAUSE_PUBLICATION", &stale_pause_spec),
            ("VOX_TEST_HOLD_TEXT_APPEND_PUBLICATION", &stale_post_spec),
            ("VOX_TEST_HOLD_ROOM_CREATE_PUBLICATION", &stale_create_spec),
            ("VOX_TEST_HOLD_REKEY_ENQUEUE", &stale_rekey_spec),
            (
                "VOX_TEST_FX28_MARK_ENDED_UNANSWERED_FILE",
                &older_selected_spec,
            ),
            ("VOX_TEST_FX28_ROTATE_AFTER_POST", "1"),
            (
                "VOX_TEST_FX28_STOPPED_READER_ANSWERED_FILE",
                &stopped_reader_answered_spec,
            ),
        ],
    );
    // Each node is Ready before it is chosen as its computer's personal node.
    da.expect_apparatus_event("node alpha is Ready", |l| l.contains("alpha is Ready"));
    db.expect_apparatus_event("node beta is Ready", |l| l.contains("beta is Ready"));
    // A status accepted by the shipped daemon must return before a later independent shipped
    // command can overtake it. The marker brackets the synchronous status read, so restoring the
    // recursive state-lock mutant becomes an immediate PRODUCT red after `node list` completes,
    // not an arbitrary wait followed by an unattributed deadman.
    std::fs::write(&status_arm, b"armed\n")
        .expect("APPARATUS: arm the computer-status progress boundary");
    let status_started = Instant::now();
    let mut status_command = a
        .cmd(&["computer", "status", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: start shipped computer status progress probe");
    wait_for_command_marker(
        &status_accepted,
        &mut status_command,
        da.child.id(),
        status_started + ACTOR_WITHIN,
        "the daemon accepted the computer status read",
    );
    let (listed_ok, listed, listed_err) = a.run(&["node", "list"], "");
    assert!(
        listed_ok,
        "PRODUCT: a later shipped `vox node list` did not return after the daemon accepted `vox computer status`: {listed}{listed_err}"
    );
    if !status_returned.is_file() {
        let _ = status_command.kill();
        let _ = status_command.wait();
        panic!(
            "PRODUCT: the daemon accepted `vox computer status`, a later independent shipped `vox node list` returned, but status never left its synchronous read"
        );
    }
    let status_output = status_command
        .wait_with_output()
        .expect("APPARATUS: collect completed computer status progress probe");
    assert!(
        status_output.status.success()
            && serde_json::from_slice::<serde_json::Value>(&status_output.stdout).is_ok(),
        "PRODUCT: the causally completed `vox computer status --json` was not successful readable JSON: stdout {}; stderr {}",
        String::from_utf8_lossy(&status_output.stdout),
        String::from_utf8_lossy(&status_output.stderr)
    );
    assert!(
        b.run(&["computer", "status", "--json"], "").0,
        "APPARATUS: beta's daemon did not answer its staging computer status:\n{}",
        db.said()
    );
    computer(&a, &["personal", "alpha"]);
    computer(&b, &["personal", "beta"]);
    let offered = computer(&a, &["invite"]);
    let link = offered["invite_link"]
        .as_str()
        .expect("PRODUCT: Add Computer did not show a pairing link")
        .to_owned();
    let preview = computer(&b, &["pair", &link, "--preview"]);
    let operation = preview["pairing"]["operation_id"]
        .as_str()
        .expect("PRODUCT: the pairing preview names no operation")
        .to_owned();
    let approval_started = Instant::now();
    computer(&b, &["approve", &operation]);
    computer(&a, &["approve", &operation]);
    loop {
        if computer(&a, &["status"])["state"] == "confirmed"
            && computer(&b, &["status"])["state"] == "confirmed"
        {
            break;
        }
        assert!(
            approval_started.elapsed() < RETURN_WITHIN,
            "PRODUCT: {RETURN_WITHIN:?} after the first shipped approval was asked, the two \
             computers were not both confirmed: alpha {}, beta {}\n{}\n{}",
            computer(&a, &["status"])["state"],
            computer(&b, &["status"])["state"],
            da.said(),
            db.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // ---- restart under skew before proving changes in both directions --------------------
    let db = a_restart_derives_nothing(
        (&a, &da),
        RestartComputerSide {
            account: &b,
            daemon: db,
            nodes: &[("beta", beta.as_str())],
            listen: &listen_b,
            hold_spec: &hold_spec,
            reply_spec: &reply_spec,
            stale_pause_spec: &stale_pause_spec,
            stale_post_spec: &stale_post_spec,
            stale_create_spec: &stale_create_spec,
            stale_rekey_spec: &stale_rekey_spec,
            older_selected_spec: &older_selected_spec,
            stopped_reader_answered: &stopped_reader_answered_spec,
        },
    );

    // ---- a change on either daemon shows on both despite the clock skew (#1020) -----------
    let gamma = a.make_node("gamma");
    let nodes_a = [("alpha", alpha.as_str()), ("gamma", gamma.as_str())];
    for stale in [&stopped_reader_generation, &stopped_reader_answered] {
        if stale.exists() {
            std::fs::remove_file(stale)
                .expect("APPARATUS: clear an earlier stopped-reader generation marker");
        }
    }
    std::fs::write(
        &stopped_reader_arm,
        b"open real management streams and stop reading\n",
    )
    .expect("APPARATUS: arm the real stopped-reader peer");
    change_shows_on_both(
        (&a, &da, &nodes_a),
        (&b, &db, &[("beta", beta.as_str())]),
        "gamma",
        Some(&stopped_reader_answered),
    );
    assert!(
        stopped_reader_answered.is_file(),
        "APPARATUS: the answering shipped daemon did not observe one unread error response in every bounded management slot"
    );
    let delta = b.make_node("delta");
    let nodes_b = [("beta", beta.as_str()), ("delta", delta.as_str())];
    change_shows_on_both((&b, &db, &nodes_b), (&a, &da, &nodes_a), "delta", None);

    // ---- a stale actor cannot publish a remote drive mutation -----------------------------
    let (epsilon, stale_room, stale_room_link) = stale_remote_pause_is_refused(
        (&a, &da),
        (&b, &db),
        &stale_pause_arm,
        &stale_pause_engaged,
        &stale_pause_release,
        &stale_post_arm,
        &stale_post_engaged,
        &stale_post_release,
        &stale_create_arm,
        &stale_create_engaged,
        &stale_create_release,
        (&beta, &delta),
    );
    let nodes_a = [
        ("alpha", alpha.as_str()),
        ("gamma", gamma.as_str()),
        ("epsilon", epsilon.as_str()),
    ];

    // ---- stale reconciliation cannot detach a replacement generation or revision ----------
    replacement_generation_survives((&a, &da), (&b, &db), &reply_marker);

    // ---- both live daemons converge when their userspace path is restored -----------------
    change_reaches_a_live_computer((&a, &da, &nodes_a), (&b, &db, &nodes_b), &forward);

    // What `vox computer status --json` shows: the sum of `exchanges` over the computers listed,
    // the latest `last_exchange_ms`, whether every one is confirmed, and the listing itself for a
    // red to quote.
    let exchanges = |acct: &Account| {
        let status = computer(acct, &["status"]);
        let apps = status["applications"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let total: u64 = apps
            .iter()
            .map(|p| p["exchanges"].as_u64().unwrap_or(0))
            .sum();
        // Rounds, completed or not: a failed round is a round (ADR-038 FX-15).
        let attempts: u64 = apps
            .iter()
            .map(|p| {
                p["exchange_attempts"].as_u64().unwrap_or_else(|| {
                    panic!("PRODUCT: `vox computer status --json` counts no exchange attempts: {p}")
                })
            })
            .sum();
        let last = apps
            .iter()
            .filter_map(|p| p["last_exchange_ms"].as_u64())
            .max();
        let confirmed = apps.iter().all(|p| p["confirmed"] == true);
        (
            total,
            attempts,
            last,
            confirmed,
            status["applications"].to_string(),
            bindings_shown(&status),
        )
    };
    let (ea0, aa0, last_a0, _, shown_a0, derived_a0) = exchanges(&a);
    let (eb0, ab0, last_b0, _, shown_b0, derived_b0) = exchanges(&b);
    // Every binding stands derived at the current policy revision before the next structural
    // boundary. Its moment must not move when the named fallback exchange carries the unchanged
    // revision: derivation follows policy revision events, not elapsed time or network activity.
    let derived0 = (derived_a0, derived_b0);
    for (who, nodes, (revision, shown)) in [
        ("alpha", ["alpha", "gamma"], &derived0.0),
        ("beta", ["beta", "delta"], &derived0.1),
    ] {
        for node in nodes {
            assert!(
                shown.get(node).is_some_and(|(at, _)| *at == Some(*revision)),
                "PRODUCT: before the quiet fallback boundary {who}'s `vox computer status` does not show {node}'s \
                 binding derived at its policy revision {revision} (ADR-038 FX-28): {shown:?}"
            );
        }
    }
    // Do not choose an observation window. Wait for each shipped status to name the next
    // completed fallback exchange it started. That status transition is the causal boundary: a
    // timer restored anywhere in binding derivation crosses it and moves the durable derivation
    // record; a too-eager exchange moves attempts before this boundary and is counted below.
    // A fallback is itself a product cadence. If its named interval plus the product's existing
    // return contract passes without one, that is a PRODUCT wrong-state verdict, not a watchdog
    // or a made-up harness timeout.
    let fallback_deadline = Instant::now() + FALLBACK_NAMED + RETURN_WITHIN;
    let (
        (ea1, aa1, last_a, confirmed_a, shown_a1, derived_a1),
        (eb1, ab1, last_b, confirmed_b, shown_b1, derived_b1),
    ) = loop {
        let after_a = exchanges(&a);
        let after_b = exchanges(&b);
        if after_a.0 > ea0 && after_a.1 > aa0 && after_b.0 > eb0 && after_b.1 > ab0 {
            break (after_a, after_b);
        }
        assert!(
            Instant::now() < fallback_deadline,
            "PRODUCT: after the named {FALLBACK_NAMED:?} quiet cadence plus its existing \
                 {RETURN_WITHIN:?} return contract, shipped status still named no next completed \
                 fallback exchange: alpha {}; beta {}\n{}\n{}",
            after_a.4,
            after_b.4,
            da.said(),
            db.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    for (who, before, after) in [("alpha", last_a0, last_a), ("beta", last_b0, last_b)] {
        let (Some(before), Some(after)) = (before, after) else {
            panic!(
                "PRODUCT: {who}'s shipped status did not date both sides of its quiet fallback exchange"
            );
        };
        let gap = after.saturating_sub(before);
        assert!(
            gap >= FALLBACK_NAMED.as_millis() as u64,
            "PRODUCT: {who} completed a quiet exchange {} s after its previous exchange \
             (ADR-038 FX-15, #989), before the named {FALLBACK_NAMED:?} fallback: before \
             {before}, after {after}",
            gap / 1000
        );
    }
    let derived1 = (derived_a1, derived_b1);
    // The count is "since the daemon started" and the daemons ran throughout: it never shrinks.
    let grew = |before: u64, after: u64, who: &str, shown0: &str, shown1: &str| -> u64 {
        after.checked_sub(before).unwrap_or_else(|| {
            panic!(
                "PRODUCT: {who}'s `vox computer status` exchange count went backwards across the \
                 quiet fallback boundary, from {before} to {after}; it showed {shown0} before and {shown1} after"
            )
        })
    };
    let during_a = grew(ea0, ea1, "alpha", &shown_a0, &shown_a1);
    let during_b = grew(eb0, eb1, "beta", &shown_b0, &shown_b1);
    // Every round is counted from its start, completed or not. We stopped on exactly the first
    // completed fallback boundary from each side, so a failed round and its retry (two), or an
    // eager round before the fallback, are red even when a later success hides the failure.
    let tried_a = grew(aa0, aa1, "alpha", &shown_a0, &shown_a1);
    let tried_b = grew(ab0, ab1, "beta", &shown_b0, &shown_b1);
    assert!(
        tried_a == 1 && tried_b == 1 && during_a == 1 && during_b == 1,
        "PRODUCT: before each computer completed its one named quiet fallback, it started or completed extra rounds (a failed round and its retry are two) (ADR-038 FX-15, #989): \
         alpha {tried_a} attempt(s) for {during_a} exchange(s), beta {tried_b} for {during_b}\n{shown_a1}\n{shown_b1}"
    );
    println!(
        "[proof] at each side's next named quiet fallback boundary with all staged nodes hosted: alpha exchanged {during_a} time(s) with beta (last at {last_a:?}, confirmed {confirmed_a}), beta {during_b} with alpha (last at {last_b:?}, confirmed {confirmed_b}); bindings: alpha's computer at policy revision {} {:?}, beta's at {} {:?}, derived again across the boundary: {}",
        derived1.0 .0,
        derived1.0 .1,
        derived1.1 .0,
        derived1.1 .1,
        derived0 != derived1
    );
    // Nothing was derived again: every binding names the same revision and the same moment on
    // both sides of a real unchanged-state exchange, and that revision is still the policy's.
    for (who, (revision0, before), (revision1, after)) in [
        ("alpha", &derived0.0, &derived1.0),
        ("beta", &derived0.1, &derived1.1),
    ] {
        assert!(
            revision0 == revision1 && before == after,
            "PRODUCT: {who}'s computer derived a node's binding again with nothing changed \
             (ADR-038 FX-28, #1020): before the quiet fallback policy revision {revision0}, bindings \
             (revision, derived at ms) {before:?}; after its completed unchanged-state exchange revision {revision1}, {after:?}"
        );
    }
    assert!(
        confirmed_a && confirmed_b && last_a.is_some() && last_b.is_some(),
        "PRODUCT: `vox computer status` does not say the peer is confirmed and when it was last exchanged with: alpha {confirmed_a} {last_a:?}, beta {confirmed_b} {last_b:?}"
    );
    // The plain `vox computer status` says the same to a person.
    for (who, acct, n, total, tried, (revision, nodes)) in [
        ("alpha", &a, during_a, ea1, aa1, &derived1.0),
        ("beta", &b, during_b, eb1, ab1, &derived1.1),
    ] {
        let (ok, text, err) = acct.run(&["computer", "status"], "");
        assert!(ok, "PRODUCT: `vox computer status` failed for {who}: {err}");
        // The numbers a person reads are the JSON's: completed exchanges and attempts.
        assert!(
            text.contains(&format!("exchanged {total} time(s) in {tried} attempt(s)"))
                && text.contains("last ")
                && text.contains("last exchange started ")
                && text.contains("last exchange answered "),
            "PRODUCT: {who}'s `vox computer status` does not say how often it exchanged \
             ({total} time(s) in {tried} attempt(s)), when, and what the last exchange it started \
             and the last it answered carried (#989, ADR-038 FX-28); it said: {text}"
        );
        assert!(
            !text.contains("failed in a row"),
            "PRODUCT: {who}'s `vox computer status` reports failures on an idle pair ({n} exchanges): {text}"
        );
        // And, per node of this computer, the revision its binding was derived at and that it
        // is the current one (ADR-038 FX-28).
        let current = format!("binding derived at policy revision {revision} (current)");
        assert!(
            text.contains(&format!("policy revision {revision}"))
                && text.matches(&current).count() == nodes.len(),
            "PRODUCT: {who}'s `vox computer status` does not say, for each of its {} nodes, that \
             its binding was derived at the current policy revision {revision} (ADR-038 FX-28); \
             it said: {text}",
            nodes.len()
        );
    }
    // ---- one queued node applies or becomes non-attached without a late apparent pass -------
    delayed_node_does_not_make_a_late_pass(
        (&a, &da, &nodes_a),
        (&b, &db, &nodes_b),
        &hold_arm,
        &hold_engaged,
        &hold_release,
        &forward,
    );
    stale_rekey_is_not_delivered(
        (&a, &da),
        (&b, &db),
        &stale_room,
        &stale_room_link,
        &epsilon,
        &hold_arm,
        &hold_engaged,
        &hold_release,
        &stale_rekey_arm,
        &stale_rekey_engaged,
        &stale_rekey_release,
        &stale_rekey_decision,
        &older_arm,
        &older_marker,
        &older_selected_arm,
        &older_selected_marker,
        &delta,
    );
}

/// What `vox computer status --json` says of this computer's own nodes: the policy revision,
/// and per node name the revision its binding was derived at and when (ADR-038 FX-28).
#[allow(clippy::type_complexity)]
fn bindings_shown(
    status: &serde_json::Value,
) -> (
    u64,
    std::collections::BTreeMap<String, (Option<u64>, Option<u64>)>,
) {
    let me = status["this_computer"]["fingerprint"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let revision = status["revision"].as_u64().unwrap_or_else(|| {
        panic!("PRODUCT: `vox computer status --json` names no policy revision: {status}")
    });
    let nodes = status["nodes"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|n| n["computer"] == me)
        .map(|n| {
            (
                n["name"].as_str().unwrap_or_default().to_owned(),
                (
                    n["binding_revision"].as_u64(),
                    n["binding_derived_ms"].as_u64(),
                ),
            )
        })
        .collect();
    (revision, nodes)
}

/// Whether `status` (one computer's) lists every node in `names` as its own with a binding
/// derived at its current policy revision.
fn roster_current(status: &serde_json::Value, names: &[&str]) -> bool {
    let (revision, nodes) = bindings_shown(status);
    names.iter().all(|name| {
        nodes
            .get(*name)
            .is_some_and(|(at, _)| *at == Some(revision))
    })
}

/// Whether shipped `vox computer status --json` shows exactly these authenticated node
/// identities: no stale extra name, substituted fingerprint, or missing member can satisfy it.
fn exact_roster(status: &serde_json::Value, expected: &[(&str, &str)]) -> bool {
    let Some(nodes) = status["nodes"].as_array() else {
        return false;
    };
    let shown: std::collections::BTreeMap<_, _> = nodes
        .iter()
        .filter_map(|node| Some((node["name"].as_str()?, node["fingerprint"].as_str()?)))
        .collect();
    let expected: std::collections::BTreeMap<_, _> = expected.iter().copied().collect();
    nodes.len() == shown.len() && shown == expected
}

/// Every user-visible field of one `computer status --json` roster entry. A restart comparison
/// uses the exact pre-restart values, including ownership, personal role and both binding-current
/// fields; neither a default nor a missing/wrong-typed field can compare equal.
#[derive(Clone, Debug, PartialEq, Eq)]
struct VisibleRosterNode {
    computer: String,
    fingerprint: String,
    personal: bool,
    binding_revision: Option<u64>,
    binding_derived_ms: Option<u64>,
}

fn nullable_u64(value: &serde_json::Value, field: &str) -> Option<Option<u64>> {
    match value.get(field)? {
        serde_json::Value::Null => Some(None),
        value => value.as_u64().map(Some),
    }
}

fn full_roster(
    status: &serde_json::Value,
) -> Option<std::collections::BTreeMap<String, VisibleRosterNode>> {
    let nodes = status.get("nodes")?.as_array()?;
    let shown: std::collections::BTreeMap<_, _> = nodes
        .iter()
        .map(|node| {
            Some((
                node.get("name")?.as_str()?.to_owned(),
                VisibleRosterNode {
                    computer: node.get("computer")?.as_str()?.to_owned(),
                    fingerprint: node.get("fingerprint")?.as_str()?.to_owned(),
                    personal: node.get("personal")?.as_bool()?,
                    binding_revision: nullable_u64(node, "binding_revision")?,
                    binding_derived_ms: nullable_u64(node, "binding_derived_ms")?,
                },
            ))
        })
        .collect::<Option<_>>()?;
    (shown.len() == nodes.len()).then_some(shown)
}

/// Whether one shipped `vox trust list` shows exactly these fingerprint/capability grants.
fn exact_grants(acct: &Account, node: &str, expected: &[(&str, &str)]) -> bool {
    let (ok, out, _) = acct.run(&["trust", "list", "--node", node], "");
    if !ok {
        return false;
    }
    let shown: std::collections::BTreeMap<_, _> = out
        .lines()
        .filter_map(|line| {
            let (fingerprint, rest) = line.split_once("  ")?;
            Some((fingerprint.trim(), rest.rsplit("  ").next()?.trim()))
        })
        .collect();
    let expected: std::collections::BTreeMap<_, _> = expected.iter().copied().collect();
    shown == expected
}

/// The shipped journey a person checks a node's trust with, `vox trust list --node <node>`:
/// every node in `mine` (name, fingerprint) on `acct` names every other node in `all`, or the
/// first that does not, with what its keyring showed.
fn keyrings_complete(
    acct: &Account,
    mine: &[(&str, &str)],
    all: &[(&str, &str)],
) -> Result<(), String> {
    for (node, fp) in mine {
        let (ok, out, err) = acct.run(&["trust", "list", "--node", node], "");
        if !ok {
            return Err(format!("{node}'s keyring could not be read: {out}{err}"));
        }
        for (peer, peer_fp) in all {
            if peer_fp == fp {
                continue;
            }
            if !out.lines().any(|line| line.contains(peer_fp)) {
                return Err(format!(
                    "{node}'s keyring does not name {peer} ({peer_fp}); it shows:\n{out}"
                ));
            }
        }
    }
    Ok(())
}

/// What `node`'s keyring on `acct` grants `fp`, in the words of `vox trust list` ("read" or
/// "read + drive"); `None` when it does not name `fp`.
fn grant_words(acct: &Account, node: &str, fp: &str) -> Option<String> {
    let (ok, out, _) = acct.run(&["trust", "list", "--node", node], "");
    if !ok {
        return None;
    }
    out.lines()
        .find(|line| line.contains(fp))
        .and_then(|line| line.rsplit("  ").next())
        .map(str::trim)
        .map(str::to_owned)
}

/// `acct`'s `vox computer status` record for the computer `other_id`.
fn application_toward(acct: &Account, other_id: &str) -> serde_json::Value {
    computer(acct, &["status"])["applications"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["computer"]["fingerprint"] == other_id)
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

/// The management fingerprint `acct`'s computer presents.
fn computer_id(acct: &Account) -> String {
    computer(acct, &["status"])["this_computer"]["fingerprint"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// **A change made on one computer shows on both** (ADR-038 FX-28; #1020). `new_node`, already
/// made on the changer's account and listed in its nodes, is attached there. Within
/// [`CHANGE_SHOWN_WITHIN`] of the attach being asked, the changer's `vox computer status` lists
/// every node of its own with a binding derived at the policy revision the change made, and
/// every node there trusts every node of both computers. Within the same
/// [`CHANGE_SHOWN_WITHIN`] clock, begun before the attach command, the other's status lists the new node under the changer's
/// computer with every binding of its own derived at its new revision, and every node there
/// trusts every node of both computers. Then both computers confirm each other again.
fn change_shows_on_both(
    (changer, changer_daemon, here): (&Account, &Daemon, &[(&str, &str)]),
    (other, other_daemon, there): (&Account, &Daemon, &[(&str, &str)]),
    new_node: &str,
    stopped_reader_answered: Option<&Path>,
) {
    let changer_id = computer_id(changer);
    let other_id = computer_id(other);
    let all: Vec<(&str, &str)> = here.iter().chain(there).copied().collect();
    let names_here: Vec<&str> = here.iter().map(|(n, _)| *n).collect();
    let names_there: Vec<&str> = there.iter().map(|(n, _)| *n).collect();
    let mut stopped_reader_staged = stopped_reader_answered.is_none();
    // The clock starts with the command a person types, not when it returns.
    let attached = Instant::now();
    let (ok, out, err) = changer.run(
        &["node", "attach", new_node, "--passphrase-file", "-"],
        PASS,
    );
    assert!(
        ok,
        "APPARATUS: attach {new_node} on {}'s computer: {out}{err}",
        names_here[0]
    );
    // On the daemon where the change was made. The clock is read after each status/trust look,
    // and a success seen past the bound is as red as none.
    let shown_here = loop {
        let status = computer(changer, &["status"]);
        let keyrings = keyrings_complete(changer, here, &all);
        let shown = roster_current(&status, &names_here) && keyrings.is_ok();
        let elapsed = attached.elapsed();
        if !stopped_reader_staged && stopped_reader_answered.is_some_and(std::path::Path::is_file) {
            println!(
                "[proof] FX-28 stopped-reader apparatus staged: every bounded management slot reached an unread reply"
            );
            stopped_reader_staged = true;
        }
        if shown && elapsed <= CHANGE_SHOWN_WITHIN {
            break status;
        }
        assert!(
            elapsed < CHANGE_SHOWN_WITHIN || stopped_reader_staged,
            "APPARATUS: the answering shipped daemon did not reach an unread reply in every bounded management slot before the change verdict"
        );
        assert!(
            !shown && elapsed < CHANGE_SHOWN_WITHIN,
            "PRODUCT: {CHANGE_SHOWN_WITHIN:?} after `vox node attach {new_node}` was asked of {}'s \
             computer, `vox computer status` there did not show the change applied in time \
             (ADR-038 FX-28, #1020; shown {shown} when looked at after {elapsed:?}): it should \
             list {names_here:?} with bindings derived at its policy revision, and every node \
             there should trust every node of both computers; status: revision {} nodes {}; \
             keyrings: {}\nits daemon said: {}",
            names_here[0],
            status["revision"],
            status["nodes"],
            keyrings.err().unwrap_or_else(|| "complete".into()),
            changer_daemon.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let revision_here = shown_here["revision"].as_u64().unwrap_or(0);
    println!(
        "[proof] {:?} after `vox node attach {new_node}` was asked, {}'s computer lists {names_here:?} with every binding derived at policy revision {revision_here} and every keyring complete",
        attached.elapsed(),
        names_here[0]
    );
    // On the other daemon the status must both name an exchange which carried this revision and
    // show the applied result. The same clock began before the triggering attach; observing an
    // exchange later cannot reset it and turn a late product result green.
    loop {
        let toward = application_toward(changer, &other_id);
        let carried = toward["last_started_exchange"]["sent_revision"]
            .as_u64()
            .is_some_and(|revision| revision >= revision_here);
        let status = computer(other, &["status"]);
        let names_it = status["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|n| n["name"] == new_node && n["computer"] == changer_id.as_str());
        let keyrings = keyrings_complete(other, there, &all);
        let shown =
            carried && names_it && roster_current(&status, &names_there) && keyrings.is_ok();
        let elapsed = attached.elapsed();
        if !stopped_reader_staged && stopped_reader_answered.is_some_and(std::path::Path::is_file) {
            println!(
                "[proof] FX-28 stopped-reader apparatus staged: every bounded management slot reached an unread reply"
            );
            stopped_reader_staged = true;
        }
        if shown && elapsed <= CHANGE_SHOWN_WITHIN {
            println!(
                "[proof] {new_node} shown applied on {}'s computer {elapsed:?} after the attach was asked; shipped status names revision {revision_here} carried (bound {CHANGE_SHOWN_WITHIN:?})",
                names_there[0]
            );
            break;
        }
        assert!(
            elapsed < CHANGE_SHOWN_WITHIN || stopped_reader_staged,
            "APPARATUS: the answering shipped daemon did not reach an unread reply in every bounded management slot before the change verdict"
        );
        assert!(
            !shown && elapsed < CHANGE_SHOWN_WITHIN,
            "{}: {CHANGE_SHOWN_WITHIN:?} after `vox node attach {new_node}` was asked, {}'s \
             daemon had not both carried revision {revision_here} to {} and applied it there \
             (ADR-038 FX-28, #1020; shown {shown} after {elapsed:?}): carried {carried}; remote \
             names node {names_it}; remote bindings current {}; keyrings {}; exchange {}; remote \
             nodes {}\nchanger daemon: {}\nremote daemon: {}",
            if new_node == "gamma" {
                "PRODUCT [FX28 stopped-reader-write]"
            } else {
                "PRODUCT"
            },
            names_here[0],
            names_there[0],
            roster_current(&status, &names_there),
            keyrings.err().unwrap_or_else(|| "complete".into()),
            toward,
            status["nodes"],
            changer_daemon.said(),
            other_daemon.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // Both confirm each other again: the other's receipt for the new state comes back.
    loop {
        let here_state = computer(changer, &["status"])["state"].clone();
        let there_state = computer(other, &["status"])["state"].clone();
        if !stopped_reader_staged && stopped_reader_answered.is_some_and(std::path::Path::is_file) {
            println!(
                "[proof] FX-28 stopped-reader apparatus staged: every bounded management slot reached an unread reply"
            );
            stopped_reader_staged = true;
        }
        if here_state == "confirmed" && there_state == "confirmed" {
            break;
        }
        assert!(
            attached.elapsed() < RETURN_WITHIN || stopped_reader_staged,
            "APPARATUS: the answering shipped daemon did not reach an unread reply in every bounded management slot before the confirmation verdict"
        );
        assert!(
            attached.elapsed() < RETURN_WITHIN,
            "PRODUCT: {RETURN_WITHIN:?} after `vox node attach {new_node}` was asked on {}'s \
             computer, the pair was still not confirmed: {}'s {here_state}, {}'s {there_state}\n{}\n{}",
            names_here[0],
            names_here[0],
            names_there[0],
            changer_daemon.said(),
            other_daemon.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    if !stopped_reader_staged && stopped_reader_answered.is_some_and(std::path::Path::is_file) {
        println!(
            "[proof] FX-28 stopped-reader apparatus staged: every bounded management slot reached an unread reply"
        );
        stopped_reader_staged = true;
    }
    assert!(
        stopped_reader_staged,
        "APPARATUS: the answering shipped daemon did not observe one unread error response in every bounded management slot"
    );
}

/// A UDP port nothing holds right now, for a daemon to listen on for the whole proof.
fn free_v6_udp_port() -> u16 {
    std::net::UdpSocket::bind("[::1]:0")
        .and_then(|socket| socket.local_addr())
        .map(|addr| addr.port())
        .unwrap_or_else(|e| panic!("APPARATUS: no free UDP port on [::1]: {e}"))
}

/// **A restart derives nothing across unsynchronized host clocks** (ADR-038 FX-28; #1020): with
/// nothing changed, beta's daemon is stopped and started again on the same port with its Unix
/// clock one hour ahead, its attached nodes come back Ready, and its `vox computer status` shows
/// every binding at the same policy revision and the same derived
/// moment as before the restart: the record survived, and nothing was derived again. Both
/// computers confirm each other again (staging). Returns beta's new daemon.
struct RestartComputerSide<'a> {
    account: &'a Account,
    daemon: Daemon,
    nodes: &'a [(&'a str, &'a str)],
    listen: &'a str,
    hold_spec: &'a str,
    reply_spec: &'a str,
    stale_pause_spec: &'a str,
    stale_post_spec: &'a str,
    stale_create_spec: &'a str,
    stale_rekey_spec: &'a str,
    older_selected_spec: &'a str,
    stopped_reader_answered: &'a str,
}

fn a_restart_derives_nothing(
    (a, da): (&Account, &Daemon),
    side: RestartComputerSide<'_>,
) -> Daemon {
    let RestartComputerSide {
        account: b,
        daemon: db,
        nodes: nodes_b,
        listen: listen_b,
        hold_spec,
        reply_spec,
        stale_pause_spec,
        stale_post_spec,
        stale_create_spec,
        stale_rekey_spec,
        older_selected_spec,
        stopped_reader_answered,
    } = side;
    let names_b: Vec<&str> = nodes_b.iter().map(|(n, _)| *n).collect();
    let before = bindings_shown(&computer(b, &["status"]));
    assert!(
        roster_current(&computer(b, &["status"]), &names_b),
        "APPARATUS: before the restart beta's bindings are not all current: {before:?}"
    );
    let _stopped_said = db.stop();
    let restarted = Instant::now();
    let mut db = Daemon::start(
        b,
        &["--node", "beta"],
        &[
            ("VOX_LISTEN", listen_b),
            ("VOX_TEST_CLOCK_STEP_MS", REMOTE_CLOCK_SKEW_MS),
            ("VOX_TEST_HOLD_COMPUTER_POLICY", hold_spec),
            ("VOX_TEST_HOLD_COMPUTER_POLICY_REPLY", reply_spec),
            ("VOX_TEST_HOLD_ROOM_PAUSE_PUBLICATION", stale_pause_spec),
            ("VOX_TEST_HOLD_TEXT_APPEND_PUBLICATION", stale_post_spec),
            ("VOX_TEST_HOLD_ROOM_CREATE_PUBLICATION", stale_create_spec),
            ("VOX_TEST_HOLD_REKEY_ENQUEUE", stale_rekey_spec),
            (
                "VOX_TEST_FX28_MARK_ENDED_UNANSWERED_FILE",
                older_selected_spec,
            ),
            ("VOX_TEST_FX28_ROTATE_AFTER_POST", "1"),
            (
                "VOX_TEST_FX28_STOPPED_READER_ANSWERED_FILE",
                stopped_reader_answered,
            ),
        ],
    );
    for name in &names_b {
        let ready = format!("{name} is Ready");
        db.expect_event_until(
            restarted + RETURN_WITHIN,
            &format!("node {name} is Ready after restart"),
            |line| line.contains(&ready),
        );
    }
    let after = bindings_shown(&computer(b, &["status"]));
    assert!(
        restarted.elapsed() <= RETURN_WITHIN,
        "PRODUCT: {RETURN_WITHIN:?} after beta's daemon restart was triggered, its Ready nodes \
         and shipped computer status had still not exposed the unchanged durable bindings: \
         before {before:?}; after {after:?}; daemon {}",
        db.said()
    );
    assert!(
        after == before,
        "PRODUCT: a restart of beta's daemon with nothing changed derived a binding again, or lost \
         the record of when it was derived (ADR-038 FX-28, #1020): before the restart policy \
         revision {}, bindings (revision, derived at ms) {:?}; after it, with both nodes Ready, \
         revision {}, {:?}\nbeta's daemon said: {}",
        before.0,
        before.1,
        after.0,
        after.1,
        db.said()
    );
    println!(
        "[proof] {:?} after beta's daemon was restarted with nothing changed, its attached nodes are Ready and every binding stands at policy revision {} with the same derived moment as before: {:?}",
        restarted.elapsed(),
        after.0,
        after.1
    );
    loop {
        let alpha = computer(a, &["status"])["state"].clone();
        let beta = computer(b, &["status"])["state"].clone();
        if alpha == "confirmed" && beta == "confirmed" {
            break;
        }
        assert!(
            restarted.elapsed() < RETURN_WITHIN,
            "PRODUCT: {RETURN_WITHIN:?} after beta's daemon restart was triggered, the \
             computers were still not confirmed: alpha {alpha}, beta {beta}\n{}\n{}",
            da.said(),
            db.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    db
}

/// A reconciliation result belongs to one attachment generation and one exact policy revision.
/// First, an old delta actor applies a change but its reply is held while a person detaches and
/// re-attaches delta. Then, on that replacement attachment, R1's reply is held while R2 starts and
/// applies. Neither old five-second waiter may detach the attachment that superseded its work.
fn replacement_generation_survives(
    (a, da): (&Account, &Daemon),
    (b, db): (&Account, &Daemon),
    reply_marker: &Path,
) {
    let zeta = a.make_node("zeta");
    std::fs::write(reply_marker, b"hold the old generation's reply")
        .unwrap_or_else(|e| panic!("APPARATUS: could not stage delayed old-generation reply: {e}"));
    let changed = Instant::now();
    let (ok, out, err) = a.run(&["node", "attach", "zeta", "--passphrase-file", "-"], PASS);
    assert!(
        ok,
        "APPARATUS: attach zeta to stage replacement race: {out}{err}"
    );
    while reply_marker.is_file() {
        assert!(
            changed.elapsed() < CHANGE_SHOWN_WITHIN,
            "PRODUCT: {CHANGE_SHOWN_WITHIN:?} after `vox node attach zeta` was asked, delta's \
             actor had not accepted the policy event whose reply the proof was to hold\n{}\n{}",
            da.said(),
            db.said()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let old_reply_held = Instant::now();
    let (ok, out, err) = b.run(&["node", "detach", "delta"], "");
    assert!(ok, "APPARATUS: detach old delta generation: {out}{err}");
    let (ok, out, err) = b.run(&["node", "attach", "delta", "--passphrase-file", "-"], PASS);
    assert!(
        ok,
        "APPARATUS: attach replacement delta generation: {out}{err}"
    );
    std::thread::sleep(
        CHANGE_SHOWN_WITHIN
            .saturating_add(Duration::from_secs(1))
            .saturating_sub(old_reply_held.elapsed()),
    );
    let status = computer(b, &["status"]);
    let (listed_ok, listed, listed_err) = b.run(&["node", "list"], "");
    let delta_ready = listed_ok
        && listed
            .lines()
            .any(|line| line.split_whitespace().next() == Some("delta") && line.contains("Ready"));
    let delta_reads_zeta = grant_words(b, "delta", &zeta).as_deref() == Some("read");
    let alive = daemon_alive(da.child.id()) && daemon_alive(db.child.id());
    assert!(
        delta_ready
            && roster_current(&status, &["beta", "delta"])
            && delta_reads_zeta
            && alive,
        "PRODUCT: after the old generation's reconciliation deadline, replacement delta did not remain Ready with current computer trust (ADR-038 FX-28, #1020): Ready {delta_ready}, current {}, zeta grant {:?}, daemons alive {alive}; node list error {listed_err}; nodes {}; applications {}\n{}\n{}",
        roster_current(&status, &["beta", "delta"]),
        grant_words(b, "delta", &zeta),
        status["nodes"],
        status["applications"],
        da.said(),
        db.said()
    );

    // Same attachment, two policy revisions: attachment generation alone cannot own this result.
    std::fs::write(reply_marker, b"hold revision R1's reply")
        .unwrap_or_else(|e| panic!("APPARATUS: stage delayed R1 reply: {e}"));
    let theta = a.make_node("theta");
    let r1_started = Instant::now();
    let (ok, out, err) = a.run(&["node", "attach", "theta", "--passphrase-file", "-"], PASS);
    assert!(ok, "APPARATUS: attach theta to stage R1: {out}{err}");
    while reply_marker.is_file() {
        assert!(
            r1_started.elapsed() < CHANGE_SHOWN_WITHIN,
            "PRODUCT: delta did not accept R1 before its causal apply deadline\n{}\n{}",
            da.said(),
            db.said()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let r1_reply_held = Instant::now();
    let iota = a.make_node("iota");
    let (ok, out, err) = a.run(&["node", "attach", "iota", "--passphrase-file", "-"], PASS);
    assert!(
        ok,
        "APPARATUS: attach iota to begin superseding R2: {out}{err}"
    );
    assert!(
        wait_until(CHANGE_SHOWN_WITHIN, || {
            let status = computer(b, &["status"]);
            roster_current(&status, &["beta", "delta"])
                && grant_words(b, "delta", &iota).as_deref() == Some("read")
        }),
        "PRODUCT: R2 did not apply to delta while R1's reconciliation result was held\n{}\n{}",
        da.said(),
        db.said()
    );
    std::thread::sleep(
        CHANGE_SHOWN_WITHIN
            .saturating_add(Duration::from_secs(1))
            .saturating_sub(r1_reply_held.elapsed()),
    );
    let status = computer(b, &["status"]);
    let (listed_ok, listed, listed_err) = b.run(&["node", "list"], "");
    let delta_ready = listed_ok
        && listed
            .lines()
            .any(|line| line.split_whitespace().next() == Some("delta") && line.contains("Ready"));
    assert!(
        delta_ready
            && roster_current(&status, &["beta", "delta"])
            && grant_words(b, "delta", &theta).as_deref() == Some("read")
            && grant_words(b, "delta", &iota).as_deref() == Some("read"),
        "PRODUCT: after superseding R2 began and applied on the same attachment, R1's older waiter detached or displaced delta (ADR-038 FX-28, #1020): Ready {delta_ready}, current {}, theta grant {:?}, iota grant {:?}; node list error {listed_err}; nodes {}; applications {}\n{}\n{}",
        roster_current(&status, &["beta", "delta"]),
        grant_words(b, "delta", &theta),
        grant_words(b, "delta", &iota),
        status["nodes"],
        status["applications"],
        da.said(),
        db.said()
    );
}

/// **A change made across a failed live path arrives on its authenticated restoration** (ADR-038
/// FX-28; #1020). The userspace forward is the pair's only path. It closes while both daemons
/// stay alive; gamma becomes alpha's personal node and alpha reaches six failed exchanges,
/// saturating its ordinary backoff. Opening that same path lets the one retained authenticated
/// wake stream land. The forward adds one second each way so restoration remains observable while
/// the five-second product clock still starts before restoration is triggered. Only after beta's final
/// status and trust observations, and both computers' final confirmation observations, is the
/// elapsed time sampled.
fn change_reaches_a_live_computer(
    (a, da, nodes_a): (&Account, &Daemon, &[(&str, &str)]),
    (b, db, nodes_b): (&Account, &Daemon, &[(&str, &str)]),
    forward: &port_forward::PortForward,
) {
    let a_id = computer_id(a);
    let b_id = computer_id(b);
    let fp = |nodes: &[(&str, &str)], name: &str| -> String {
        nodes
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, fp)| (*fp).to_owned())
            .unwrap_or_else(|| panic!("APPARATUS: no node {name} staged"))
    };
    let (alpha, gamma) = (fp(nodes_a, "alpha"), fp(nodes_a, "gamma"));
    let names_b: Vec<&str> = nodes_b.iter().map(|(n, _)| *n).collect();
    forward.close();
    assert!(
        daemon_alive(da.child.id()) && daemon_alive(db.child.id()),
        "APPARATUS: closing the userspace path stopped a daemon: alpha pid {}, beta pid {}",
        da.child.id(),
        db.child.id()
    );
    // The change, on alpha's computer: gamma becomes its personal node.
    let changed = Instant::now();
    computer(a, &["personal", "gamma"]);
    let shown = loop {
        let status = computer(a, &["status"]);
        let personal = status["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|n| n["name"] == "gamma" && n["personal"] == true);
        let alpha_drives_gamma = grant_words(a, "alpha", &gamma).as_deref() == Some("read + drive");
        let gamma_reads_alpha = grant_words(a, "gamma", &alpha).as_deref() == Some("read");
        let shown = personal
            && roster_current(&status, &["alpha", "gamma"])
            && alpha_drives_gamma
            && gamma_reads_alpha;
        // The verdict's clock is sampled only after every status/trust observation above.
        let elapsed = changed.elapsed();
        if shown && elapsed <= CHANGE_SHOWN_WITHIN {
            break status;
        }
        assert!(
            !shown && elapsed < CHANGE_SHOWN_WITHIN,
            "PRODUCT: {CHANGE_SHOWN_WITHIN:?} after `vox computer personal gamma`, alpha's computer \
             did not show it applied in time (ADR-038 FX-28, #1020; shown {shown} when looked at \
             after {elapsed:?}): gamma personal {personal}, bindings \
             current {}, alpha grants gamma {:?} (read + drive expected), gamma grants alpha {:?} \
             (read expected); status: revision {} nodes {}\nits daemon said: {}",
            roster_current(&status, &["alpha", "gamma"]),
            grant_words(a, "alpha", &gamma),
            grant_words(a, "gamma", &alpha),
            status["revision"],
            status["nodes"],
            da.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let revision = shown["revision"].as_u64().unwrap_or(0);
    println!(
        "[proof] {:?} after `vox computer personal gamma` with the live path closed, alpha's computer shows it applied at policy revision {revision}",
        changed.elapsed()
    );
    // The exchange alpha's daemon starts for it cannot complete: its status says so.
    loop {
        if application_toward(a, &b_id)["exchange_failures"]
            .as_u64()
            .is_some_and(|n| n >= 6)
        {
            break;
        }
        assert!(
            changed.elapsed() < RETURN_WITHIN,
            "PRODUCT: {RETURN_WITHIN:?} after `vox computer personal gamma` was asked with the \
             live path closed, shipped status had not exposed the sixth failed exchange toward \
             beta needed to show bounded retry progress: {}\nits daemon said: {}",
            application_toward(a, &b_id),
            da.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    println!(
        "[proof] alpha's status counts the exchange toward beta that could not complete: {} failed in a row",
        application_toward(a, &b_id)["exchange_failures"]
    );
    assert!(
        forward.dropped() > 0,
        "APPARATUS: the closed userspace path dropped no datagram, so unreachability was not staged"
    );
    assert!(
        daemon_alive(da.child.id()) && daemon_alive(db.child.id()),
        "APPARATUS: a daemon stopped during the live path outage: alpha pid {}, beta pid {}",
        da.child.id(),
        db.child.id()
    );

    // Opening a boolean switch is not yet a restored-path precondition. The apparatus first sends
    // a private probe through both legs of this exact forward (never to Vox); only its round trip
    // establishes that the userspace path is carrying traffic. A broken/late emulator is
    // APPARATUS. The forward returns a monotonic instant sampled after that causal probe succeeds;
    // the clock is not sampled again until every
    // final product observation below has returned.
    forward.set_delay(Duration::from_secs(1));
    // The person's causal action is opening the path. The product clock begins before the
    // apparatus verifies that action, so even a slow verification cannot make a late heal green.
    let restored = Instant::now();
    let _verified = forward.open_and_verify();
    let applied_at = loop {
        let status = computer(b, &["status"]);
        let gamma_personal = status["nodes"].as_array().into_iter().flatten().any(|n| {
            n["name"] == "gamma" && n["computer"] == a_id.as_str() && n["personal"] == true
        });
        let delta_drives_gamma = grant_words(b, "delta", &gamma).as_deref() == Some("read + drive");
        let delta_reads_alpha = grant_words(b, "delta", &alpha).as_deref() == Some("read");
        let beta_reads_gamma = grant_words(b, "beta", &gamma).as_deref() == Some("read");
        let alive = daemon_alive(da.child.id()) && daemon_alive(db.child.id());
        let shown = gamma_personal
            && roster_current(&status, &names_b)
            && delta_drives_gamma
            && delta_reads_alpha
            && beta_reads_gamma
            && computer(a, &["status"])["state"] == "confirmed"
            && computer(b, &["status"])["state"] == "confirmed"
            && alive;
        // This is deliberately after the final status and trust commands: a late observation is
        // red even if the product became current before the command that exposed it returned.
        let elapsed = restored.elapsed();
        if shown && elapsed <= RETURN_WITHIN {
            break elapsed;
        }
        assert!(
            !shown && elapsed < RETURN_WITHIN,
            "PRODUCT: {RETURN_WITHIN:?} after the live authenticated path was \
             restored, the change made while it was unreachable was not applied there in time \
             (ADR-038 FX-28, #1020; shown {shown} \
             when looked at after {elapsed:?}): gamma personal under alpha's \
             computer {gamma_personal}, bindings current {}, delta grants gamma {:?} (read + drive \
             expected), delta grants alpha {:?} (read expected), beta grants gamma {:?} (read \
             expected); status: revision {} nodes {}; applications {}\nbeta's daemon said: {}\n\
             alpha's daemon said: {}; daemons alive {alive}",
            roster_current(&status, &names_b),
            grant_words(b, "delta", &gamma),
            grant_words(b, "delta", &alpha),
            grant_words(b, "beta", &gamma),
            status["revision"],
            status["nodes"],
            status["applications"],
            db.said(),
            da.said()
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    forward.set_delay(Duration::ZERO);
    println!(
        "[proof] {applied_at:?} after the live authenticated path was restored, the change made meanwhile is applied on every node of beta's computer and both computers confirm (return bound {RETURN_WITHIN:?})"
    );
    assert!(
        daemon_alive(da.child.id()) && daemon_alive(db.child.id()),
        "PRODUCT: a daemon stopped across userspace path restoration: alpha pid {}, beta pid {}",
        da.child.id(),
        db.child.id()
    );
}

/// Hold one real remote drive mutation at its final publication boundary, move durable Computer
/// policy through another shipped action, then judge the released request by what shipped
/// `vox room pause` tells its caller. The marker proves causal staging; no elapsed silence is a
/// PRODUCT verdict.
#[allow(clippy::too_many_arguments)]
fn stale_remote_pause_is_refused(
    (a, da): (&Account, &Daemon),
    (b, db): (&Account, &Daemon),
    hold_arm: &Path,
    hold_engaged: &Path,
    hold_release: &Path,
    post_arm: &Path,
    post_engaged: &Path,
    post_release: &Path,
    create_arm: &Path,
    create_engaged: &Path,
    create_release: &Path,
    (beta, delta): (&str, &str),
) -> (String, String, String) {
    let room = make_room(b, "delta");
    let (ok, link, err) = b.run(&["room", "link", &room, "--node", "delta"], "");
    assert!(ok, "APPARATUS: link delta's stale-publication room: {err}");
    let (ok, out, err) = b.run(
        &[
            "room",
            "join",
            "--node",
            "beta",
            "--passphrase-file",
            "-",
            link.trim(),
        ],
        ROOM_PASS,
    );
    assert!(
        ok,
        "APPARATUS: join beta to delta's stale-publication room: {out}{err}"
    );
    assert!(
        wait_until(RETURN_WITHIN, || {
            ["beta", "delta"].iter().all(|node| {
                let (ok, roster, _) = b.run(&["room", "roster", &room, "--node", node], "");
                ok && roster.contains(beta) && roster.contains(delta)
            })
        }),
        "APPARATUS: beta and delta did not both expose the staged room roster"
    );

    std::fs::write(hold_arm, b"hold delta's admitted remote pause\n")
        .expect("APPARATUS: arm the stale remote-pause publication hold");
    let mut pause = b
        .cmd(&["room", "pause", &room, "delta", "--node", "beta", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: start the shipped remote room-pause command");
    wait_for_command_marker(
        hold_engaged,
        &mut pause,
        db.child.id(),
        Instant::now() + RETURN_WITHIN,
        "delta's admitted remote pause at its final publication boundary",
    );

    // A real user action moves durable Computer policy while that exact room mutation is held.
    // Epsilon is attached on alpha's healthy actor; beta applies the new revision while delta's
    // old projection remains parked at the publication fence.
    let before = computer(b, &["status"])["revision"].as_u64().unwrap_or(0);
    let epsilon = a.make_node("epsilon");
    let (ok, out, err) = a.run(
        &["node", "attach", "epsilon", "--passphrase-file", "-"],
        PASS,
    );
    assert!(
        ok,
        "APPARATUS: attach epsilon for stale-publication staging: {out}{err}"
    );
    assert!(
        wait_until(RETURN_WITHIN, || {
            let status = computer(b, &["status"]);
            status["revision"].as_u64().is_some_and(|r| r > before)
                && grant_words(b, "beta", &epsilon).is_some()
        }),
        "APPARATUS: durable policy did not move and apply on beta while delta's exact publication was held\n{}\n{}",
        da.said(),
        db.said()
    );
    assert!(
        hold_engaged.is_file(),
        "APPARATUS: delta's exact remote pause was not still held after durable policy moved"
    );
    println!(
        "[proof] FX-28 stale-tick-authority apparatus staged: durable Computer policy moved while delta's exact admitted remote pause remained held at its final publication boundary"
    );
    std::os::unix::net::UnixStream::connect(hold_release).unwrap_or_else(|e| {
        panic!(
            "APPARATUS: release delta's held remote pause at {}: {e}",
            hold_release.display()
        )
    });
    let paused = pause
        .wait_with_output()
        .expect("APPARATUS: collect the causally released room-pause command");
    assert!(
        !paused.status.success(),
        "PRODUCT [FX28 stale-tick-authority]: after durable Computer policy moved while its exact admitted remote pause was held, shipped `vox room pause` still published and acknowledged the stale drive mutation: stdout {}; stderr {}",
        String::from_utf8_lossy(&paused.stdout),
        String::from_utf8_lossy(&paused.stderr)
    );
    println!(
        "[proof] after durable policy moved, releasing the exact admitted stale-authority publication made shipped `vox room pause` refuse it: {}",
        String::from_utf8_lossy(&paused.stderr).trim()
    );
    assert!(
        wait_until(RETURN_WITHIN, || {
            roster_current(&computer(a, &["status"]), &["alpha", "gamma", "epsilon"])
                && roster_current(&computer(b, &["status"]), &["beta", "delta"])
        }),
        "APPARATUS: nodes did not settle after the stale-publication refusal"
    );

    // The same final-use rule covers an ordinary local post. Hold it after its room lock and all
    // awaits, move durable policy through a shipped personal-node change, then release it. The
    // command itself is the terminal product observation; elapsed silence is never a verdict.
    std::fs::write(post_arm, b"hold delta's exact text append\n")
        .expect("APPARATUS: arm the stale text-append publication hold");
    let mut post = b
        .cmd(&[
            "room",
            "post",
            &room,
            "STALE-AUTHORITY-TEXT",
            "--node",
            "delta",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: start the shipped stale-authority text post");
    wait_for_command_marker(
        post_engaged,
        &mut post,
        db.child.id(),
        Instant::now() + RETURN_WITHIN,
        "delta's ordinary text append at its final publication boundary",
    );
    let before = computer(b, &["status"])["revision"].as_u64().unwrap_or(0);
    computer(a, &["personal", "gamma"]);
    assert!(
        wait_until(RETURN_WITHIN, || {
            computer(b, &["status"])["revision"]
                .as_u64()
                .is_some_and(|revision| revision > before)
                && grant_words(b, "beta", &epsilon).is_some()
        }),
        "APPARATUS: durable policy did not move on beta while delta's text append was held"
    );
    assert!(
        post_engaged.is_file(),
        "APPARATUS: delta's exact text append was not held through durable policy movement"
    );
    println!(
        "[proof] FX-28 stale-trust-projection apparatus staged: durable Computer policy moved while delta retained an unreconciled keyring projection"
    );
    let (trust_ok, stale_trust, trust_error) = b.run(&["trust", "list", "--node", "delta"], "");
    assert!(
        trust_ok
            && stale_trust.contains("no trusted identities")
            && !stale_trust.contains(&epsilon),
        "PRODUCT [FX28 stale-trust-projection]: after durable Computer policy moved but before delta reconciled it, shipped `vox trust list --node delta` exposed or failed to suppress the old trusted rows: stdout {stale_trust}; stderr {trust_error}"
    );
    println!(
        "[proof] FX-28 stale-post-authority apparatus staged: durable Computer policy moved while delta's exact ordinary text append remained held at its final publication boundary"
    );
    std::os::unix::net::UnixStream::connect(post_release).unwrap_or_else(|error| {
        panic!(
            "APPARATUS: release delta's held text append at {}: {error}",
            post_release.display()
        )
    });
    let posted = post
        .wait_with_output()
        .expect("APPARATUS: collect the causally released text-post command");
    assert!(
        !posted.status.success(),
        "PRODUCT [FX28 stale-post-authority]: after durable Computer policy moved while its exact ordinary append was held, shipped `vox room post` still published and acknowledged stale-authority text: stdout {}; stderr {}",
        String::from_utf8_lossy(&posted.stdout),
        String::from_utf8_lossy(&posted.stderr)
    );
    let (_, read, read_error) = b.run(&["room", "read", &room, "--node", "beta"], "");
    assert!(
        !read.contains("STALE-AUTHORITY-TEXT"),
        "PRODUCT [FX28 stale-post-authority]: beta's shipped room read exposed text appended after its author's durable Computer authority became stale: {read}{read_error}"
    );
    computer(a, &["personal", "alpha"]);
    assert!(
        wait_until(RETURN_WITHIN, || {
            roster_current(&computer(a, &["status"]), &["alpha", "gamma", "epsilon"])
                && roster_current(&computer(b, &["status"]), &["beta", "delta"])
        }),
        "APPARATUS: nodes did not settle after the stale text-append refusal"
    );

    // Room sealing is off actor and can finish after durable policy moved. Hold the exact sealed
    // create at its first store commit, move policy through a shipped personal-node command, and
    // require both the create answer and room list to remain fail closed.
    std::fs::write(create_arm, b"hold delta's sealed room create\n")
        .expect("APPARATUS: arm the stale room-create publication hold");
    let mut create = b
        .cmd(&[
            "room",
            "create",
            "--node",
            "delta",
            "--passphrase-file",
            "-",
            "--name",
            "stale-create",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: start the shipped stale-authority room create");
    create
        .stdin
        .take()
        .expect("APPARATUS: room create stdin")
        .write_all(ROOM_PASS.as_bytes())
        .expect("APPARATUS: give the room create its passphrase");
    wait_for_command_marker(
        create_engaged,
        &mut create,
        db.child.id(),
        Instant::now() + RETURN_WITHIN,
        "delta's sealed room create at its first durable commit",
    );
    let before = computer(b, &["status"])["revision"].as_u64().unwrap_or(0);
    computer(a, &["personal", "gamma"]);
    assert!(
        wait_until(RETURN_WITHIN, || computer(b, &["status"])["revision"]
            .as_u64()
            .is_some_and(|revision| revision > before)),
        "APPARATUS: durable policy did not move on beta while delta's sealed room create was held"
    );
    assert!(
        create_engaged.is_file(),
        "APPARATUS: delta's exact sealed room create was not held through policy movement"
    );
    println!(
        "[proof] FX-28 stale-room-create-authority apparatus staged: durable Computer policy moved while delta's exact sealed room create remained held at its first durable commit"
    );
    std::os::unix::net::UnixStream::connect(create_release).unwrap_or_else(|error| {
        panic!(
            "APPARATUS: release delta's held room create at {}: {error}",
            create_release.display()
        )
    });
    let created = create
        .wait_with_output()
        .expect("APPARATUS: collect the causally released room-create command");
    assert!(
        !created.status.success(),
        "PRODUCT [FX28 stale-room-create-authority]: after durable Computer policy moved while its exact sealed room was held, shipped `vox room create` still committed and acknowledged it: stdout {}; stderr {}",
        String::from_utf8_lossy(&created.stdout),
        String::from_utf8_lossy(&created.stderr)
    );
    let (listed, rooms, list_error) = b.run(&["room", "list", "--node", "delta"], "");
    assert!(
        listed && !rooms.contains("stale-create"),
        "PRODUCT [FX28 stale-room-create-authority]: delta's shipped room list exposed the stale-authority room after its create was refused: {rooms}{list_error}"
    );
    computer(a, &["personal", "alpha"]);
    assert!(
        wait_until(RETURN_WITHIN, || {
            roster_current(&computer(a, &["status"]), &["alpha", "gamma", "epsilon"])
                && roster_current(&computer(b, &["status"]), &["beta", "delta"])
        }),
        "APPARATUS: nodes did not settle after the stale room-create refusal"
    );

    (epsilon, room, link.trim().to_owned())
}

#[allow(clippy::too_many_arguments)]
fn stale_rekey_is_not_delivered(
    (a, _da): (&Account, &Daemon),
    (b, db): (&Account, &Daemon),
    room: &str,
    link: &str,
    epsilon: &str,
    hold_arm: &Path,
    hold_engaged: &Path,
    hold_release: &Path,
    rekey_arm: &Path,
    rekey_engaged: &Path,
    rekey_release: &Path,
    rekey_decision: &Path,
    older_arm: &Path,
    older_marker: &Path,
    older_selected_arm: &Path,
    older_selected_marker: &Path,
    delta: &str,
) {
    assert!(
        wait_until(RETURN_WITHIN, || {
            roster_current(&computer(b, &["status"]), &["beta", "delta"])
                && b.run(&["node", "list"], "").1.lines().any(|line| {
                    line.split_whitespace().next() == Some("delta")
                        && line.starts_with("delta Ready")
                })
        }),
        "APPARATUS: delta did not become current before final rekey-authority staging"
    );
    let (ok, out, err) = a.run(
        &[
            "room",
            "join",
            "--node",
            "epsilon",
            "--passphrase-file",
            "-",
            link,
        ],
        ROOM_PASS,
    );
    assert!(ok, "APPARATUS: join epsilon for rekey staging: {out}{err}");
    let (ok, out, err) = b.run(
        &["room", "post", room, "REKEY-BASELINE", "--node", "delta"],
        "",
    );
    assert!(ok, "APPARATUS: post the rekey baseline: {out}{err}");
    assert!(
        wait_until(RETURN_WITHIN, || a
            .run(&["room", "read", room, "--node", "epsilon"], "")
            .1
            .contains("REKEY-BASELINE")),
        "APPARATUS: epsilon did not read the baseline through the staged sender-key path"
    );
    // Select the compatibility route through the real protocol result which owns it. Epsilon's
    // test-only peer apparatus closes exactly one modern delivery without an answer; delta's
    // shipped roster must then say it runs an older Vox. The stale-authority rejection below is
    // consequently after `key_frames` sealed into the long-lived session, not the modern cached
    // delivery path.
    let _ = std::fs::remove_file(older_marker);
    let _ = std::fs::remove_file(older_selected_marker);
    std::fs::write(older_arm, format!("{delta}\t{room}\n"))
        .expect("APPARATUS: arm epsilon's exact unanswered modern key delivery");
    std::fs::write(older_selected_arm, format!("{epsilon}\t{room}\n"))
        .expect("APPARATUS: arm delta's exact ENDED_UNANSWERED route selection");
    let (ok, out, err) = b.run(
        &[
            "room",
            "post",
            room,
            "LEGACY-ROUTE-BASELINE",
            "--node",
            "delta",
        ],
        "",
    );
    assert!(
        ok,
        "APPARATUS: post the key rotation which selects the older route: {out}{err}"
    );
    let exact_older = read_daemon_marker(
        older_marker,
        _da.child.id(),
        "epsilon's exact modern delivery ended unanswered",
    );
    assert_eq!(
        exact_older.trim(),
        format!("epsilon\t{delta}\t{room}"),
        "APPARATUS: unanswered key-delivery marker named another node, sender, or room"
    );
    let exact_selection = read_daemon_marker(
        older_selected_marker,
        db.child.id(),
        "delta's exact ENDED_UNANSWERED route selection",
    );
    assert_eq!(
        exact_selection.trim(),
        format!("delta\t{epsilon}\t{room}"),
        "APPARATUS: ENDED_UNANSWERED route marker named another node, peer, or room"
    );
    println!(
        "[proof] FX-28 legacy rekey route apparatus staged: epsilon ended delta's exact modern delivery unanswered"
    );
    let (ok, roster, roster_error) = b.run(&["room", "roster", room, "--node", "delta"], "");
    assert!(
        ok && roster.contains(epsilon) && roster.contains("runs an older Vox"),
        "PRODUCT [FX28 legacy-rekey-route]: after delta admitted epsilon's exact unanswered modern delivery, its shipped roster did not expose the selected legacy sender-key route: {roster}{roster_error}"
    );
    let rekey_fault = rekey_decision.with_extension("fault");
    for stale in [rekey_engaged, rekey_decision, &rekey_fault] {
        let _ = std::fs::remove_file(stale);
    }
    std::fs::write(rekey_arm, format!("{epsilon}\n"))
        .expect("APPARATUS: arm epsilon's exact stale rekey enqueue");
    std::fs::write(hold_arm, b"hold delta's revocation policy message\n")
        .expect("APPARATUS: arm delta's reconciliation behind the rekey decision");
    let mut rotating_post = b
        .cmd(&[
            "room",
            "post",
            room,
            "STALE-AUTHORITY-REKEY",
            "--node",
            "delta",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: start the shipped post which rotates epsilon's sender key");
    wait_for_command_marker(
        rekey_engaged,
        &mut rotating_post,
        db.child.id(),
        Instant::now() + RETURN_WITHIN,
        "epsilon's prepared sender-key batch at final queue admission",
    );
    let before = computer(b, &["status"])["revision"].as_u64().unwrap_or(0);
    let a_id = computer_id(a);
    let status = computer(b, &["status"]);
    computer(
        b,
        &[
            "remove",
            &a_id,
            "--confirm",
            status["frontier"].as_str().unwrap_or_default(),
        ],
    );
    assert!(
        wait_until(RETURN_WITHIN, || {
            computer(b, &["status"])["revision"]
                .as_u64()
                .is_some_and(|revision| revision > before)
                && grant_words(b, "beta", epsilon).is_none()
        }),
        "APPARATUS: beta did not expose epsilon's durable revocation while delta's exact rekey was held"
    );
    assert!(
        rekey_engaged.is_file(),
        "APPARATUS: epsilon's exact rekey was not still held after durable revocation"
    );
    println!(
        "[proof] FX-28 stale-rekey-authority apparatus staged: epsilon was durably revoked while its exact prepared sender-key batch remained held at final queue admission"
    );
    std::os::unix::net::UnixStream::connect(rekey_release).unwrap_or_else(|error| {
        panic!(
            "APPARATUS: release epsilon's held rekey at {}: {error}",
            rekey_release.display()
        )
    });
    let post_result = rotating_post
        .wait_with_output()
        .expect("APPARATUS: collect the shipped sender-rotation post");
    assert!(
        post_result.status.success(),
        "APPARATUS: the pre-revocation append did not complete after its rekey decision: {}{}",
        String::from_utf8_lossy(&post_result.stdout),
        String::from_utf8_lossy(&post_result.stderr)
    );
    let decision = read_daemon_marker(
        rekey_decision,
        db.child.id(),
        "the exact rekey authority decision",
    );
    if decision.trim() == "enqueued" {
        assert!(
            wait_until(RETURN_WITHIN, || a
                .run(&["room", "read", room, "--node", "epsilon"], "")
                .1
                .contains("STALE-AUTHORITY-REKEY")),
            "APPARATUS: the mutant enqueued epsilon's exact key but the shipped recipient never exposed its delivery"
        );
        panic!("PRODUCT [FX28 stale-rekey-authority]: after epsilon's durable revocation, its shipped room read exposed text unlocked by the stale sender-key batch");
    }
    assert_eq!(
        decision.trim(),
        "rejected",
        "APPARATUS: the rekey authority boundary published an unknown decision: {decision}"
    );
    let read = a.run(&["room", "read", room, "--node", "epsilon"], "").1;
    assert!(
        !read.contains("STALE-AUTHORITY-REKEY"),
        "PRODUCT [FX28 stale-rekey-authority]: epsilon's shipped room read exposed text whose sender key was prepared before its durable revocation: {read}"
    );
    read_daemon_marker(
        hold_engaged,
        db.child.id(),
        "delta's held revocation reconciliation",
    );
    std::os::unix::net::UnixStream::connect(hold_release).unwrap_or_else(|error| {
        panic!(
            "APPARATUS: release delta's held revocation reconciliation at {}: {error}",
            hold_release.display()
        )
    });
}

/// One node whose actor queue is held must be visibly non-attached within FX-28's five seconds;
/// its healthy sibling applies the same revision inside that bound. The elapsed time is sampled
/// after both computer statuses, the sibling's shipped `vox trust list`, and `vox node list`.
fn delayed_node_does_not_make_a_late_pass(
    (a, da, nodes_a): (&Account, &Daemon, &[(&str, &str)]),
    (b, db, _nodes_b): (&Account, &Daemon, &[(&str, &str)]),
    hold_arm: &Path,
    hold_engaged: &Path,
    hold_release: &Path,
    forward: &port_forward::PortForward,
) {
    let eta = a.make_node("eta");
    let b_id = computer_id(b);
    let before_revision = computer(a, &["status"])["revision"].as_u64().unwrap_or(0);
    std::fs::write(hold_arm, b"hold delta's next policy message")
        .unwrap_or_else(|e| panic!("APPARATUS: could not stage the held delta marker: {e}"));
    forward.close();
    let changed = Instant::now();
    let (ok, out, err) = a.run(&["node", "attach", "eta", "--passphrase-file", "-"], PASS);
    assert!(ok, "APPARATUS: attach eta on alpha's computer: {out}{err}");
    loop {
        if application_toward(a, &b_id)["exchange_failures"]
            .as_u64()
            .is_some_and(|n| n >= 6)
        {
            break;
        }
        assert!(
            changed.elapsed() < RETURN_WITHIN,
            "PRODUCT: {RETURN_WITHIN:?} after `vox node attach eta` was asked with the path \
             closed, shipped status had not exposed the sixth failed exchange needed to show \
             bounded retry progress: {}\n{}",
            application_toward(a, &b_id),
            da.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    forward.set_delay(Duration::from_secs(1));
    let restored = Instant::now();
    let _verified = forward.open_and_verify();

    loop {
        let status_a = computer(a, &["status"]);
        let sent_revision = status_a["revision"].as_u64().unwrap_or(0);
        let record = application_toward(a, &b_id)["last_started_exchange"].clone();
        let carried = sent_revision > before_revision
            && record["sent_revision"]
                .as_u64()
                .is_some_and(|revision| revision >= sent_revision);
        let status_b = computer(b, &["status"]);
        let beta_grant = grant_words(b, "beta", &eta);
        let (listed_ok, listed, listed_err) = b.run(&["node", "list"], "");
        assert!(
            listed_ok,
            "PRODUCT: `vox node list` did not answer while delta's policy work was held: {listed_err}"
        );
        let delta_line = listed
            .lines()
            .find(|line| line.split_whitespace().next() == Some("delta"))
            .unwrap_or("");
        let delta_non_attached = !delta_line.is_empty() && !delta_line.starts_with("delta Ready");
        let mut local_names: Vec<&str> = nodes_a.iter().map(|(name, _)| *name).collect();
        local_names.push("eta");
        let local_current = roster_current(&status_a, &local_names);
        let beta_current = roster_current(&status_b, &["beta"]);
        let alive = daemon_alive(da.child.id()) && daemon_alive(db.child.id());
        let shown =
            local_current && beta_current && beta_grant.is_some() && delta_non_attached && alive;
        // All final status/trust/list observations are complete before this sample.
        let elapsed = restored.elapsed();
        if carried {
            if shown && elapsed <= CHANGE_SHOWN_WITHIN {
                assert!(
                    hold_engaged.is_file(),
                    "APPARATUS: delta was not causally held in its computer-policy actor before the non-attached verdict"
                );
                println!(
                    "[proof] {elapsed:?} after path restoration was triggered, shipped status names eta carried, beta applied it on its healthy node and lists held delta non-attached ({delta_line:?}); bound {CHANGE_SHOWN_WITHIN:?}"
                );
                break;
            }
            assert!(
                !shown && elapsed < CHANGE_SHOWN_WITHIN,
                "PRODUCT: {CHANGE_SHOWN_WITHIN:?} after path restoration was triggered, \
                 beta did not apply-or-detach every attached node (ADR-038 FX-28, #1020; shown \
                 {shown} only after {elapsed:?}): alpha bindings current {local_current}; beta \
                 binding current {beta_current}; beta's grant for eta {beta_grant:?}; delta \
                 line {delta_line:?}; daemons alive {alive}; alpha status nodes {}; beta status nodes {}\nalpha \
                 daemon:\n{}\nbeta daemon:\n{}",
                status_a["nodes"],
                status_b["nodes"],
                da.said(),
                db.said()
            );
        } else {
            assert!(
                elapsed < CHANGE_SHOWN_WITHIN,
                "PRODUCT: {CHANGE_SHOWN_WITHIN:?} after path restoration was triggered, alpha \
                 completed no exchange carrying eta to beta: {}\nalpha daemon:\n{}\nbeta daemon:\n{}",
                application_toward(a, &b_id),
                da.said(),
                db.said()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    std::os::unix::net::UnixStream::connect(hold_release).unwrap_or_else(|e| {
        panic!(
            "APPARATUS: could not release delta's held computer-policy actor at {}: {e}",
            hold_release.display()
        )
    });
    while hold_engaged.is_file() {
        assert!(
            restored.elapsed() < RETURN_WITHIN,
            "PRODUCT: delta did not consume its causally released computer-policy work before \
             the restoration action's {RETURN_WITHIN:?} contract ended"
        );
        std::thread::yield_now();
    }
    forward.set_delay(Duration::ZERO);
}

fn daemon_alive(pid: u32) -> bool {
    let out = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not inspect daemon pid {pid}: {e}"));
    out.status.success() && !out.stdout.is_empty()
}
