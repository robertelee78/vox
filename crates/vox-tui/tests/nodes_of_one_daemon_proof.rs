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

#[path = "support/hostile.rs"]
mod hostile;

#[path = "support/ports.rs"]
mod ports;

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(
    computer_pairing_uses_an_anchor_without_room_membership_and_reconnects,
    computer_preview_and_approval_survive_a_crash,
    two_paired_computers_that_are_idle_exchange_nothing,
);

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
#[cfg(feature = "optional-proofs")]
use vox_core::node::computer::COMPUTER_QUIET_EXCHANGE_AFTER as FALLBACK_NAMED;
use vox_core::node::computer::{
    COMPUTER_CHANGE_SHOWN_WITHIN as CHANGE_SHOWN_WITHIN, COMPUTER_PAIR_WITHIN as PAIR_WITHIN,
    COMPUTER_RETURN_SHOWN_WITHIN as RETURN_WITHIN,
};
use vox_core::node::ipc::ACTOR_WITHIN;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const PASS: &str = "identity passphrase";
const ROOM_PASS: &str = "room passphrase for the daemon proof";
const FX28_ROTATE_AFTER_POST_ARM: &str = "fx28-rotate-after-post-arm";
const FX28_CONTROL_PARTITION_ARM: &str = "fx28-rekey-control-partition-arm";
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
            // The shared pre-main isolation removes every inherited product knob. Keep the
            // operator's selector under the existing proof-run VOX_MUTANT_ prefix, then map it
            // explicitly onto each isolated daemon; the product never reads the run setting.
            if let Ok(mutant) = std::env::var("VOX_MUTANT_FX28") {
                c.env("VOX_TEST_FX28_MUTANT", &mutant);
                eprintln!("[proof] FX-28 mutant {mutant} selected for this scratch daemon");
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
        if let Ok(fault) = std::fs::read_to_string(marker.with_extension("fault")) {
            panic!("APPARATUS: could not stage {what}: {fault}");
        }
        if let Some(status) = command
            .try_wait()
            .unwrap_or_else(|e| panic!("APPARATUS: could not inspect shipped command: {e}"))
        {
            let mut stdout = String::new();
            let mut stderr = String::new();
            if let Some(mut pipe) = command.stdout.take() {
                let _ = pipe.read_to_string(&mut stdout);
            }
            if let Some(mut pipe) = command.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!(
                "APPARATUS: shipped command exited {status} before {what}; stdout {stdout}; stderr {stderr}"
            );
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
        if let Ok(fault) = std::fs::read_to_string(marker.with_extension("fault")) {
            panic!("APPARATUS: {what}: {fault}");
        }
        if marker.is_file() {
            assert!(
                Instant::now() < deadline,
                "APPARATUS: {what} was observed only after its retained staging boundary"
            );
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
    assert!(
        ok,
        "APPARATUS: room create on {node}: {out}{err}; Computer status after refusal: {}",
        computer(a, &["status"])
    );
    let (ok, list, err) = a.run(&["room", "list", "--node", node], "");
    assert!(ok, "APPARATUS: room list on {node}: {err}");
    list.lines()
        .find_map(|l| l.split_whitespace().next().map(str::to_owned))
        .unwrap_or_else(|| panic!("APPARATUS: no room listed on {node}: {list}"))
}

/// The CLI deliberately accepts/displays a short room prefix, while daemon-side causal hooks
/// match the full fingerprint carried by the invite link.
fn full_room_id(link: &str, shown: &str) -> String {
    let full = link
        .trim()
        .strip_prefix("vox://")
        .and_then(|rest| rest.split('?').next())
        .unwrap_or_else(|| panic!("APPARATUS: no full room fingerprint in invite link {link}"));
    assert!(
        full.starts_with(shown),
        "APPARATUS: invite link room {full} does not extend the CLI room prefix {shown}"
    );
    full.to_owned()
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
/// Independent mutants: omitting the post-reservation supersession check lets a stale operator
/// pairing survive the newer policy revision; requiring a retained peer connection strands the
/// repair; discarding failed transport work means the remote anchor's return never causes
/// registration; clearing a late success hides the missed contract before preview/restart;
/// making a fresh preview inherit an older missed deadline refuses its authenticated code;
/// decoding a tagged owner refusal as enrollment data hides why a cancelled code was refused;
/// bypassing only the final state-locked Ready fence exposes an old projection after a real
/// later operator policy changed the personal-node role. Historical transport lateness does not
/// revoke the receiver's authenticated current policy.
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
        "VOX_TEST_HOLD_AFTER_COMPUTER_APPLICATION_RECEIPT_FILE",
        "VOX_TEST_HOLD_COMPUTER_RECONCILE_SEND_FILE",
        "VOX_TEST_HOLD_COMPUTER_REGISTRATION_FILE",
        "VOX_TEST_FX28_MUTANT",
    ]);
    let anchor = Account::new();
    let a = Account::new();
    let b = Account::new();
    let registration_arm = anchor.data.join("registration.arm");
    let registration_held = anchor.data.join("registration.held");
    let registration_release = anchor.data.join("registration.release.sock");
    let registration_waiting = anchor.data.join("registration.waiting");
    let registration_fault = anchor.data.join("registration.fault");
    let registration_spec = format!(
        "{}\t{}\t{}\t{}\t{}",
        registration_arm.display(),
        registration_held.display(),
        registration_release.display(),
        registration_waiting.display(),
        registration_fault.display()
    );
    let start_anchor = |listen: &str| {
        let out = anchor.data.with_extension("anchor.out");
        let f = std::fs::File::create(&out).expect("APPARATUS: anchor transcript");
        let started = Instant::now();
        let mut command = anchor.cmd(&["node", "--listen", listen, "--serve", "anyone"]);
        command.env(
            "VOX_TEST_HOLD_COMPUTER_REGISTRATION_FILE",
            &registration_spec,
        );
        #[cfg(feature = "test-knobs")]
        if let Ok(mutant) = std::env::var("VOX_MUTANT_FX28") {
            command.env("VOX_TEST_FX28_MUTANT", mutant);
        }
        let child = command
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
    let a_id = computer_id(&a);
    let b_id = computer_id(&b);
    let owner_key = vox_core::node::link::b32_decode(&a_id, "apparatus computer owner")
        .expect("APPARATUS: decode the inviter's shipped identity");
    std::fs::write(&registration_arm, owner_key)
        .expect("APPARATUS: arm the exact inviter registration hold");
    let publication_started = Instant::now();
    let invitation = computer(&a, &["invite"]);
    let link = invitation["invite_link"]
        .as_str()
        .expect("PRODUCT: node-free computer invitation missing");
    let registration_key = vox_core::node::link::b32_decode(
        invitation["invite_id"]
            .as_str()
            .expect("PRODUCT: invitation omitted its id"),
        "apparatus invitation id",
    )
    .expect("APPARATUS: decode the shipped invitation id");
    let exact_registration = [owner_key.as_slice(), registration_key.as_slice()].concat();
    wait_for_daemon_marker(
        &registration_held,
        &mut relay,
        publication_started + RETURN_WITHIN,
        "the exact inviter publication before anchor insertion",
    );
    assert_eq!(
        std::fs::read(&registration_held).expect("APPARATUS: read held registration"),
        exact_registration,
        "APPARATUS: anchor held a different owner/invitation publication"
    );
    let pairing_started = Instant::now();
    let mut initial_preview = b
        .cmd(&["computer", "pair", link, "--preview", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: start the exact registration-late preview");
    wait_for_command_marker(
        &registration_waiting,
        &mut initial_preview,
        right.child.id(),
        pairing_started + PAIR_WITHIN,
        "the exact missing-inviter redemption branch",
    );
    assert!(
        std::fs::read(&registration_waiting).ok().as_deref() == Some(exact_registration.as_slice())
            && std::fs::read(&registration_held).ok().as_deref()
                == Some(exact_registration.as_slice())
            && !registration_fault.exists(),
        "APPARATUS: redemption and held publication did not name the same exact owner/invitation"
    );
    println!("[proof] FX-28 registration-handoff apparatus staged: the exact missing-inviter redemption arrived while only its owner's real anchor insertion remained held");
    std::os::unix::net::UnixStream::connect(&registration_release)
        .expect("APPARATUS: release the exact inviter registration");
    let initial_output = initial_preview
        .wait_with_output()
        .expect("APPARATUS: collect the same registration-late preview command");
    assert!(initial_output.status.success(),
        "PRODUCT [FX28 registration-handoff]: the same valid-code pairing command failed instead of waiting for its exact inviter publication: stdout {}; stderr {}",
        String::from_utf8_lossy(&initial_output.stdout), String::from_utf8_lossy(&initial_output.stderr));
    let preview: serde_json::Value =
        serde_json::from_slice(&initial_output.stdout).unwrap_or_else(|error| {
            panic!("PRODUCT: registration-late preview returned unreadable JSON: {error}")
        });
    assert!(preview["this_computer"]["fingerprint"] == b_id
        && preview["pairing"]["peer"]["fingerprint"] == a_id
        && preview["pairing"]["approved_here"] == false
        && preview["pairing"]["approved_there"] == false,
        "PRODUCT: registration-late preview did not authenticate the exact still-unapproved computers: {preview}");
    let op = preview["pairing"]["operation_id"]
        .as_str()
        .expect("PRODUCT: pairing preview omitted its operation identity");
    // Cancellation must stay a known refusal, even after the active registration is removed.
    // The anchor marker is emitted only for this exact already-published owner's revocation;
    // it supplies no fabricated expiry and retains the original admission reservation.
    computer(&a, &["cancel", op]);
    computer(&b, &["cancel", op]);
    let known_revoked = registration_waiting.with_extension("revoked");
    wait_for_daemon_marker(
        &known_revoked,
        &mut relay,
        Instant::now() + RETURN_WITHIN,
        "the exact known registration revocation",
    );
    assert_eq!(
        std::fs::read(&known_revoked).expect("APPARATUS: read known revocation"),
        exact_registration,
        "APPARATUS: revocation marker named another owner/invitation"
    );
    println!("[proof] FX-28 known-revocation apparatus staged: the anchor processed this exact already-published registration's authenticated cancellation");
    // A circuit already closing after cancellation can still be returned by the old process's
    // connection cache. Restart this same scratch redeemer so this claim necessarily asks the
    // still-running anchor about the known registration, rather than racing that teardown.
    stop_pid(right.child.id());
    right
        .child
        .wait()
        .expect("APPARATUS: stop the cancelled-code redeemer");
    right = start(
        &b,
        "[::1]:0",
        &v6,
        &[(
            "VOX_TEST_HOLD_COMPUTER_ANSWER_AFTER_MERGE_FILE",
            &answer_after_merge_spec,
        )],
    );
    assert_eq!(
        computer_id(&b),
        b_id,
        "PRODUCT: restarting the cancelled-code redeemer changed its persistent computer identity"
    );
    let (closed_ok, closed_out, closed_err) =
        b.run(&["computer", "pair", link, "--preview", "--json"], "");
    let closed_shown = format!("{closed_out}{closed_err}");
    assert!(
        !closed_ok && !closed_shown.contains("deadline") && !closed_shown.contains("timed out"),
        "PRODUCT [FX28 cancelled-code]: the cancelled code was accepted or left waiting until a deadline instead of returning a terminal refusal: stdout {closed_out}; stderr {closed_err}"
    );
    let anchor_refusal =
        closed_shown.contains("rendezvous record rejected by store policy: rejected: policy");
    let owner_refusal = closed_shown.contains(
        "computer pairing code expired, cancelled, or unknown; no new trust was established",
    ) || closed_shown
        .contains("computer pairing code expired or was cancelled");
    assert!(
        anchor_refusal || owner_refusal,
        "APPARATUS: the cancelled-code command failed without an attributable terminal anchor or owner refusal; dial, IPC, malformed response, or other errors cannot establish cancellation: stdout {closed_out}; stderr {closed_err}"
    );
    // A new invitation still fits the existing retention budget and must not resurrect the
    // cancelled operation. Establish the computers only from this new operation.
    let invitation = computer(&a, &["invite"]);
    let link = invitation["invite_link"]
        .as_str()
        .expect("PRODUCT: replacement node-free invitation missing");
    let preview = computer(&b, &["pair", link, "--preview"]);
    let op = preview["pairing"]["operation_id"]
        .as_str()
        .expect("PRODUCT: replacement pairing preview omitted its operation identity");
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

    let before = application_toward(&a, &b_id);
    let attempts_before = before["exchange_attempts"].as_u64().unwrap_or(0);
    let failures_before = before["exchange_failures"].as_u64().unwrap_or(0);
    let revision_before = computer(&a, &["status"])["revision"].as_u64().unwrap_or(0);
    let first = a.make_node("anchor-return-first");
    let second = a.make_node("anchor-return-second");
    let third = a.make_node("anchor-return-third");
    std::fs::write(&first_flight_arm, format!("{b_id}\t{revision_before}\n"))
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
    let entered = std::fs::read_to_string(&first_flight_engaged)
        .expect("APPARATUS: read exact first flight ownership");
    let entered: Vec<_> = entered.trim().split('\t').collect();
    assert!(
        entered.len() == 3
            && entered[0] == b_id
            && entered[1].parse::<u64>().is_ok_and(|serial| serial > 0)
            && entered[2].parse::<u64>().is_ok_and(|policy| policy > revision_before),
        "APPARATUS: first flight did not name the exact peer, owned serial and later policy: {entered:?}"
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
        "APPARATUS: retry-ready held a peer other than the unfinished first cause's target"
    );

    // The replacement owns the same unfinished first cause. Do not wait for an incidental
    // failure count, backoff crossing, or a separate explicit command: an ordinary attempt may
    // legitimately remain in flight for its whole retained return interval. The later outage
    // separately proves the missed ordinary cause and fresh operator command boundaries.
    let expected_roster_before_race = [
        ("anchor-return-first", first.as_str()),
        ("anchor-return-second", second.as_str()),
        ("after-remote-anchor-b", bob.as_str()),
    ];
    let expected_bob_grants_before_race = [(first.as_str(), "read"), (second.as_str(), "read")];

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
    // Release the exact owned cause only after both daemons have a real path again. The
    // restored anchor and this apparatus release contribute no new operator policy or deadline.
    std::os::unix::net::UnixStream::connect(&retry_ready_release).unwrap_or_else(|e| {
        panic!(
            "APPARATUS: could not release the scheduler's exact retry-ready boundary at {}: {e}",
            retry_ready_release.display()
        )
    });
    // Failed registration remains durable work. The restored path alone must now carry both
    // superseding policy revisions and their grants under the first cause's retained deadline.
    let recovered_automatically = wait_until(
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
                && left_status["state"] == "confirmed"
                && status["state"] == "confirmed"
        },
    );
    let recovered_after = first_changed.elapsed();
    assert!(
        anchor_currently_has(&relay, &[&a_id, &b_id]),
        "APPARATUS: the restored anchor stopped naming both exact computer identities before automatic recovery reached its PRODUCT verdict:\n{}",
        relay.said()
    );
    assert!(
        recovered_automatically && recovered_after <= RETURN_WITHIN,
        "PRODUCT: after only the remote anchor returned, automatic computer convergence did not show both superseding policy revisions within the first revision's {RETURN_WITHIN:?} causal deadline (observed after {recovered_after:?}); left: {}; right: {}; anchor: {}",
        computer(&a, &["status"]),
        computer(&b, &["status"]),
        relay.said()
    );
    println!(
        "[proof] after {recovered_after:?}, remote-anchor-only recovery carried both revisions through a new peer connection before the first revision's {RETURN_WITHIN:?} deadline"
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

    // Establish an older computer-managed capability upgrade. Later sender transport lateness
    // must preserve this and the new grants on a receiver which applied authenticated policy.
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

    // The answerer applies authenticated policy before its reply leaves. Observe the actual
    // effective grant while that reply is held, then complete the same cause. A separate reverse
    // exchange can legitimately cover it too; delaying one reply is not evidence of a miss.
    std::fs::write(&answer_after_merge_arm, b"armed")
        .expect("APPARATUS: arm post-merge answer hold");
    let applied_then_late = a.make_node("applied-before-late-marker");
    let revision_before_applied_late = computer(&a, &["status"])["revision"].as_u64().unwrap_or(0);
    let held_reply_started = Instant::now();
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
    let held_reply_deadline = held_reply_started + RETURN_WITHIN;
    assert!(
        Instant::now() < held_reply_deadline,
        "APPARATUS: the held-reply observation consumed the attach's original return interval before release"
    );
    std::os::unix::net::UnixStream::connect(&answer_after_merge_release)
        .unwrap_or_else(|error| panic!("APPARATUS: release post-merge answer hold: {error}"));
    assert!(
        wait_until(held_reply_deadline.saturating_duration_since(Instant::now()), || {
            exact_grants(&b, "after-remote-anchor-b", &applied_grants)
                && computer(&a, &["status"])["state"] == "confirmed"
                && computer(&b, &["status"])["state"] == "confirmed"
        }),
        "PRODUCT: after the exact post-merge reply was released, authenticated policy revision {applied_late_revision} did not finish its original return contract with current receiver grants: left {}; right {}",
        computer(&a, &["status"]), computer(&b, &["status"])
    );

    // Exercise the late-repair branch itself. The anchor goes away, a real policy revision is
    // made, and shipped status—not a sleep—causally says that revision missed its retained
    // convergence deadline. After the exact anchor identities return, the late exchange repairs
    // the roster but MUST keep the missed contract visible. Mutant: clear the late-success branch
    // in `record_exchange`; the durable missed-revision/repair assertions turn PRODUCT red.
    stop_pid(anchor.lock_pid().expect("APPARATUS: scratch anchor daemon"));
    relay
        .child
        .wait()
        .expect("APPARATUS: stopped anchor did not exit");
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
        if application["missed_revision"] == late_revision
            && application["convergence_state"] == "expired"
        {
            break;
        }
        assert!(
            daemon_alive(left.child.id()),
            "APPARATUS: left daemon exited before shipped status named the deliberately staged missed causal deadline: {status}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // This old miss is not this next explicit request's clock. Admit a fresh invocation while
    // its only bridge is still down, park its exact reservation, and restore the path before
    // allowing that same process to authenticate. No command retry or replacement clock is used.
    let fresh_invitation = computer(&b, &["invite"]);
    let fresh_link = fresh_invitation["invite_link"]
        .as_str()
        .expect("PRODUCT: fresh-boundary invitation named no link")
        .to_owned();
    let fresh_invite_id = fresh_invitation["invite_id"]
        .as_str()
        .expect("PRODUCT: fresh-boundary invitation named no id")
        .to_owned();
    let fresh_local = computer(&a, &["status"])["this_computer"].clone();
    let fresh_peer = fresh_invitation["this_computer"].clone();
    for previous in [&operator_reserved_engaged, &operator_superseded] {
        let _ = std::fs::remove_file(previous);
    }
    std::fs::write(&operator_reserved_arm, b"fresh-boundary\n")
        .expect("APPARATUS: arm the fresh command's existing reservation hold");
    let fresh_started = Instant::now();
    let mut fresh_preview = a
        .cmd(&["computer", "pair", &fresh_link, "--preview", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: start the fresh-boundary shipped preview");
    wait_for_command_marker(
        &operator_reserved_engaged,
        &mut fresh_preview,
        left.child.id(),
        fresh_started + PAIR_WITHIN,
        "the fresh command reserved its exact peer after the old ordinary deadline missed",
    );
    let fresh_admitted_by = Instant::now();
    let old_miss = application_toward(&a, &b_id);
    assert!(
        std::fs::read_to_string(&operator_reserved_engaged).ok().as_deref()
            == Some(b_id.as_str())
            && old_miss["missed_revision"] == late_revision
            && old_miss["convergence_state"] == "expired"
            && fresh_preview.try_wait().expect("APPARATUS: inspect the held fresh preview").is_none(),
        "APPARATUS: the exact fresh command was not live and reserved while its peer's earlier revision {late_revision} already showed the old miss: {old_miss}"
    );
    println!(
        "[proof] FX-28 fresh-preview-boundary apparatus staged: the same fresh command holds its exact peer reservation while shipped status already names old revision {late_revision} expired"
    );
    relay = start_anchor(&anchor_listen);
    wait_for_current_anchor_peers(&mut relay, &[&a_id, &b_id]);
    assert!(
        fresh_started.elapsed() < PAIR_WITHIN,
        "APPARATUS: restoring and verifying the path consumed the fresh invocation's entire pairing interval before its release"
    );
    std::os::unix::net::UnixStream::connect(&operator_reserved_release).unwrap_or_else(|error| {
        panic!("APPARATUS: release the fresh command's exact reservation: {error}")
    });
    let fresh_output = fresh_preview
        .wait_with_output()
        .expect("APPARATUS: collect the same fresh-boundary command");
    let fresh_completed = Instant::now();
    let fresh_stdout = String::from_utf8_lossy(&fresh_output.stdout);
    let fresh_stderr = String::from_utf8_lossy(&fresh_output.stderr);
    assert!(
        anchor_currently_has(&relay, &[&a_id, &b_id]),
        "APPARATUS: verified anchor registrations disappeared before the fresh-boundary verdict"
    );
    assert!(
        fresh_output.status.success(),
        "PRODUCT [FX28 fresh-preview-boundary]: after its exact peer path was restored inside this fresh invocation's original pairing interval, the same shipped preview did not authenticate its code independently of old revision {late_revision}'s already-missed deadline: stdout {fresh_stdout}; stderr {fresh_stderr}"
    );
    assert!(
        fresh_completed <= fresh_admitted_by + PAIR_WITHIN,
        "PRODUCT [FX28 fresh-preview-boundary]: the fresh command succeeded only after even the conservative upper bracket of its original admission-owned pairing interval"
    );
    assert!(
        fresh_completed <= fresh_started + PAIR_WITHIN,
        "APPARATUS: fresh command completion landed inside admission-clock observation ambiguity; no timing verdict is possible"
    );
    let fresh: serde_json::Value = serde_json::from_str(&fresh_stdout).unwrap_or_else(|error| {
        panic!("PRODUCT: fresh preview returned unreadable JSON: {error}: {fresh_stdout}")
    });
    let fresh_operation = fresh["pairing"]["operation_id"]
        .as_str()
        .filter(|operation| !operation.is_empty())
        .unwrap_or_else(|| {
            panic!("PRODUCT: fresh preview omitted its authenticated operation: {fresh}")
        });
    assert!(
        fresh["this_computer"] == fresh_local
            && fresh["pairing"]["peer"] == fresh_peer
            && fresh["pairing"]["approved_here"] == false
            && fresh["pairing"]["approved_there"] == false
            && fresh["pairing"]["expires_ms"] == fresh_invitation["invite_expires_ms"],
        "PRODUCT: the fresh command did not show its exact authenticated, still-unapproved invitation: {fresh}"
    );
    let retained_miss = application_toward(&a, &b_id);
    assert!(
        retained_miss["missed_revision"] == late_revision
            && matches!(retained_miss["convergence_state"].as_str(), Some("expired" | "repaired-late")),
        "PRODUCT: fresh pairing erased or renewed the old ordinary miss instead of retaining its history (a real ordinary exchange may repair it): before {old_miss}; after {retained_miss}"
    );
    computer(&a, &["cancel", fresh_operation]);
    computer(&b, &["cancel", &fresh_invite_id]);
    let mut late_grants = applied_grants.clone();
    late_grants.push((late.as_str(), "read"));
    let late_roster = [
        ("anchor-return-first", first.as_str()),
        ("anchor-return-second", second.as_str()),
        ("anchor-return-third", third.as_str()),
        ("applied-before-late-marker", applied_then_late.as_str()),
        ("anchor-return-late", late.as_str()),
        ("after-remote-anchor-b", bob.as_str()),
    ];
    loop {
        let left_status = computer(&a, &["status"]);
        let right_status = computer(&b, &["status"]);
        let application = application_toward(&a, &b_id);
        let completed_snapshot = ["last_started_exchange", "last_answered_exchange"]
            .iter()
            .any(|field| {
                application[*field]["sent_revision"]
                    .as_u64()
                    .is_some_and(|revision| revision >= late_revision)
            });
        let repaired = completed_snapshot
            && left_status["state"] == "confirmed"
            && right_status["state"] == "confirmed"
            && exact_roster(&left_status, &late_roster)
            && exact_roster(&right_status, &late_roster)
            && roster_current(&right_status, &["after-remote-anchor-b"])
            && exact_grants(&b, "after-remote-anchor-b", &late_grants);
        if repaired {
            assert!(
                application["missed_revision"] == late_revision
                    && application["repaired_late"] == true
                    && application["convergence_state"] == "repaired-late"
                    && application["exchange_failures"] == 0
                    && left_status["problem"].is_null(),
                "PRODUCT: actual late ordinary coverage restored the roster and receiver grants but failed to retain revision {late_revision}'s repaired historical miss or clear its operational failure: status {left_status}; application {application}"
            );
            println!("[proof] late ordinary coverage repaired revision {late_revision}, cleared operational failure, retained its historical miss, and left the receiver current with every authenticated grant");
            break;
        }
        assert!(
            anchor_currently_has(&relay, &[&a_id, &b_id]),
            "APPARATUS: exact restored anchor registrations were lost before the late-repair verdict"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // Real ordinary coverage has just confirmed both installations and every grant through
    // their still-running anchor. The cancelled invitation must now receive the owner's real
    // refusal, rather than interpreting its tagged error as a malformed enrollment payload.
    println!("[proof] FX-28 owner-refusal apparatus staged: both installations just confirmed actual ordinary coverage on the live anchor path before retrying the cancelled invitation");
    let (preview_ok, preview_out, preview_err) =
        a.run(&["computer", "pair", &race_link, "--preview", "--json"], "");
    let preview_shown = format!("{preview_out}{preview_err}");
    assert!(
        !preview_ok
            && preview_shown.contains("computer peer refused the request:")
            && (preview_shown.contains(
                "computer pairing code expired, cancelled, or unknown; no new trust was established",
            ) || preview_shown.contains("computer pairing code expired or was cancelled")),
        "PRODUCT [FX28 owner-refusal]: on the already-confirmed live computer path, the cancelled same-state preview did not return the owner's genuine cancellation refusal: stdout {preview_out}; stderr {preview_err}"
    );
    let after_preview = computer(&a, &["status"]);
    let after_failed_preview = application_toward(&a, &b_id);
    assert!(
        after_preview["problem"].is_null()
            && after_failed_preview["exchange_failures"] == 0
            && after_failed_preview["missed_revision"] == late_revision
            && after_failed_preview["repaired_late"] == true
            && after_failed_preview["convergence_state"] == "repaired-late"
            && exact_grants(&b, "after-remote-anchor-b", &late_grants),
        "PRODUCT: a same-state failed preview changed repaired operational state, erased the historical miss, or revoked receiver trust: {after_preview}; application {after_failed_preview}"
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
    wait_for_current_anchor_peers(&mut relay, &[&a_id, &b_id]);
    loop {
        let restarted_application = application_toward(&a, &b_id);
        let completed_after_restart = ["last_started_exchange", "last_answered_exchange"]
            .iter()
            .any(|field| {
                restarted_application[*field]["sent_revision"]
                    .as_u64()
                    .is_some()
            });
        if completed_after_restart
            && full_roster(&computer(&a, &["status"])) == Some(before_restart.0.clone())
            && full_roster(&computer(&b, &["status"])) == Some(before_restart.1.clone())
            && exact_grants(&b, "after-remote-anchor-b", &late_grants)
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
        restarted_late["problem"].is_null()
            && application_toward(&a, &b_id)["exchange_failures"]
                .as_u64()
                == Some(0)
            && application_toward(&a, &b_id)["missed_revision"] == late_revision
            && application_toward(&a, &b_id)["convergence_state"] == "repaired-late"
            && application_toward(&a, &b_id)["repaired_late"] == true
            && roster_current(&restarted_remote, &["after-remote-anchor-b"])
            && exact_grants(&b, "after-remote-anchor-b", &late_grants),
        "PRODUCT: restart lost the exact repaired miss or current receiver grants, or resurrected an operational failure: left {restarted_late}; right {restarted_remote}"
    );

    // A newer operator change is the only replacement cause. Before its exchange, status names
    // the old miss as replaced; after its own timely exchange both computers name convergence.
    // The receiver already keeps the earlier authenticated grants throughout this transition.
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

    // Policy reconciliation preserves ordinary, unrelated manual trust. Keep one such trust
    // in the returning node so every Ready assertion below distinguishes a correctly reconciled
    // keyring from both (a) a stale managed grant and (b) the empty held-back projection shown
    // while reconciliation is unfinished. This makes the final Ready-fence mutant observable in
    // the shipped `vox trust list`, rather than mistaking an empty fail-closed view for success.
    let outsider = Account::new();
    let manual_outsider = outsider.make_node("manual-outsider");
    let (ok, out, err) = b.run(
        &[
            "trust",
            "add",
            &manual_outsider,
            "--name",
            "manual-outsider",
            "--node",
            "after-remote-anchor-b",
        ],
        "",
    );
    assert!(
        ok,
        "PRODUCT: unrelated manual trust was refused while Computer policy was current: {out}{err}"
    );

    // The exact applied receipt for R is held before Ready. A real later operator change
    // supplies R+1 while the node is still attaching. Its final Ready fence must reconcile the
    // current policy, including the new personal-node role, without losing unrelated manual
    // trust. A sender's historical missed exchange is not authority over this receiver.
    let (locked, locked_out, locked_err) = b.run(&["node", "lock", "after-remote-anchor-b"], "");
    assert!(
        locked,
        "APPARATUS: Lock bob before applied-receipt supersession: {locked_out}{locked_err}"
    );
    stop_pid(right.child.id());
    right
        .child
        .wait()
        .expect("APPARATUS: stop right before applied-receipt supersession");
    right = start(
        &b,
        "[::1]:0",
        &v6,
        &[
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
        !application_receipt_engaged.exists()
            && !application_receipt_fault.exists()
            && !receipt_reconcile_engaged.exists()
            && !receipt_reconcile_fault.exists(),
        "APPARATUS: earlier receipt supersession staging left a marker"
    );
    let receipt_node = a.make_node("applied-before-policy-superseded");
    let receipt_policy_started = Instant::now();
    let (ok, out, err) = a.run(
        &[
            "node",
            "attach",
            "applied-before-policy-superseded",
            "--passphrase-file",
            "-",
        ],
        PASS,
    );
    assert!(ok, "PRODUCT: attach receipt supersession node: {out}{err}");
    let receipt_policy_deadline = receipt_policy_started + RETURN_WITHIN;
    loop {
        let status = computer(&b, &["status"]);
        if status["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|node| {
                node["computer"] == a_id
                    && node["name"] == "applied-before-policy-superseded"
                    && node["fingerprint"] == receipt_node
            })
        {
            break;
        }
        assert!(
            daemon_alive(left.child.id()) && daemon_alive(right.child.id())
                && Instant::now() < receipt_policy_deadline,
            "APPARATUS: receiver did not show the exact policy needed to stage the held receipt: {status}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    std::fs::write(&application_receipt_arm, &receipt_node)
        .expect("APPARATUS: arm exact successful receipt before Ready");
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
        .expect("APPARATUS: start bob attach for receipt supersession");
    receipt_attach
        .stdin
        .take()
        .expect("APPARATUS: receipt attach stdin")
        .write_all(PASS.as_bytes())
        .expect("APPARATUS: type receipt attach passphrase");
    wait_for_command_marker(
        &application_receipt_engaged,
        &mut receipt_attach,
        right.child.id(),
        Instant::now() + RETURN_WITHIN,
        "the exact R application receipt before Ready",
    );
    if application_receipt_fault.is_file() {
        panic!(
            "APPARATUS: applied-receipt hold failed: {}",
            std::fs::read_to_string(&application_receipt_fault).unwrap_or_default()
        );
    }
    let receipt_race_revision = computer(&b, &["status"])["revision"]
        .as_u64()
        .expect("APPARATUS: receiver status omitted its local policy revision");
    assert_eq!(
        std::fs::read_to_string(&application_receipt_engaged)
            .expect("APPARATUS: read exact applied receipt"),
        format!("{bob}\t{receipt_race_revision}\t{receipt_node}"),
        "APPARATUS: receipt marker named another node, receiver revision or grant"
    );
    let replacement_started = Instant::now();
    computer(&a, &["personal", "anchor-return-second"]);
    let replacement_deadline = replacement_started + RETURN_WITHIN;
    let ready_revision = loop {
        let status = computer(&b, &["status"]);
        let second_personal = status["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|node| {
                node["computer"] == a_id
                    && node["name"] == "anchor-return-second"
                    && node["personal"] == true
            });
        let revision = status["revision"].as_u64().unwrap_or(0);
        if second_personal && revision > receipt_race_revision {
            break revision;
        }
        assert!(
            daemon_alive(left.child.id()) && daemon_alive(right.child.id())
                && Instant::now() < replacement_deadline,
            "APPARATUS: later operator personal-node policy did not reach the receiver while R's Ready was held: {status}"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    // Only the mutant may need the post-Attached reconciliation. Keep its exact R+1 send
    // parked so it cannot repair a prematurely published Ready before the shipped trust read.
    // A correct startup is already current and need not consume this arm.
    std::fs::write(&receipt_reconcile_arm, format!("{bob}\t{ready_revision}"))
        .expect("APPARATUS: arm exact later reconciliation after Ready");
    std::os::unix::net::UnixStream::connect(&application_receipt_release)
        .expect("APPARATUS: release R receipt into the final current-policy Ready fence");
    println!(
        "[proof] FX-28 startup Ready state-lock apparatus staged: node {bob}, receipt revision {receipt_race_revision}, current receiver revision {ready_revision}, personal node anchor-return-second"
    );
    let receipt_attached = receipt_attach
        .wait_with_output()
        .expect("APPARATUS: collect receipt-superseded attach");
    assert!(
        receipt_attached.status.success(),
        "PRODUCT [FX28 startup-ready-reconcile]: bob did not become Ready under the later operator policy: {}{}",
        String::from_utf8_lossy(&receipt_attached.stdout),
        String::from_utf8_lossy(&receipt_attached.stderr)
    );
    let mut current_grants: Vec<(&str, &str)> = final_grants
        .iter()
        .map(|(fp, grant)| {
            (
                *fp,
                if *fp == second.as_str() {
                    "read + drive"
                } else if *fp == first.as_str() {
                    "read"
                } else {
                    *grant
                },
            )
        })
        .collect();
    current_grants.push((receipt_node.as_str(), "read"));
    current_grants.push((manual_outsider.as_str(), "read"));
    let ready_status = computer(&b, &["status"]);
    let (_, grants, grant_error) = b.run(&["trust", "list", "--node", "after-remote-anchor-b"], "");
    if receipt_reconcile_fault.is_file() {
        panic!(
            "APPARATUS: later reconciliation hold failed: {}",
            std::fs::read_to_string(&receipt_reconcile_fault).unwrap_or_default()
        );
    }
    if receipt_reconcile_engaged.is_file() {
        assert_eq!(
            std::fs::read_to_string(&receipt_reconcile_engaged)
                .expect("APPARATUS: read exact later reconciliation marker"),
            format!("{bob}\t{ready_revision}"),
            "APPARATUS: later reconciliation marker named another node or policy revision"
        );
    }
    let role_current = ready_status["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|node| node["computer"] == a_id && node["personal"] == true)
        .map(|node| node["name"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert!(
        ready_status["revision"].as_u64() == Some(ready_revision)
            && roster_current(&ready_status, &["after-remote-anchor-b"])
            && role_current.as_slice() == ["anchor-return-second"]
            && exact_grants(&b, "after-remote-anchor-b", &current_grants),
        "PRODUCT [FX28 startup-ready-state-lock]: Ready did not expose current receiver revision {ready_revision}, exact later personal role, and all managed/manual grants: status {ready_status}; trust {grants}; error {grant_error}"
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

/// #1020: manual trust is local to the person even while Computer policy is active, and removing
/// a computer retires its group authority without detaching that computer's nodes from their own
/// local keyrings. This deliberately has no room or Session premise: the verdict is exactly what
/// the shipped computer/trust commands show before and after restart.
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn active_and_removed_computers_keep_local_manual_trust() {
    watchdog::arm();
    let a = Account::new();
    let b = Account::new();
    let outsider = Account::new();
    let _ = a.make_node("alpha");
    let _ = b.make_node("beta");
    let before_removal = outsider.make_node("before-removal");
    let after_removal = outsider.make_node("after-removal");
    for (account, node) in [(&a, "alpha"), (&b, "beta")] {
        let (ok, out, err) = account.run(&["node", "unlock", node, "--passphrase-file", "-"], PASS);
        assert!(ok, "APPARATUS: ready scratch node {node}: {out}{err}");
        computer(account, &["personal", node]);
    }

    let offered = computer(&a, &["invite"]);
    let link = offered["invite_link"]
        .as_str()
        .expect("PRODUCT: Add Computer did not show a pairing link");
    let preview = computer(&b, &["pair", link, "--preview"]);
    let operation = preview["pairing"]["operation_id"]
        .as_str()
        .expect("PRODUCT: pairing preview named no operation");
    let approvals_started = Instant::now();
    computer(&b, &["approve", operation]);
    computer(&a, &["approve", operation]);
    loop {
        let status_a = computer(&a, &["status"]);
        let status_b = computer(&b, &["status"]);
        if status_a["state"] == "confirmed" && status_b["state"] == "confirmed" {
            break;
        }
        assert!(
            approvals_started.elapsed() < CHANGE_SHOWN_WITHIN,
            "PRODUCT: approved computers did not apply and confirm within the Computer change contract: alpha {status_a}; beta {status_b}; alpha daemon:\n{}\nbeta daemon:\n{}",
            a.log(),
            b.log()
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let a_frontier = computer(&a, &["status"])["frontier"]
        .as_str()
        .unwrap()
        .to_owned();
    let b_frontier = computer(&b, &["status"])["frontier"]
        .as_str()
        .unwrap()
        .to_owned();
    for (account, node) in [(&a, "alpha"), (&b, "beta")] {
        let (ok, out, err) = account.run(
            &[
                "trust",
                "add",
                &before_removal,
                "--name",
                "chosen-before-removal",
                "--node",
                node,
            ],
            "",
        );
        assert!(
            ok,
            "PRODUCT: active computer refused unrelated manual trust on {node}: {out}{err}"
        );
        let (ok, shown, err) = account.run(&["trust", "list", "--node", node], "");
        assert!(
            ok && shown.contains(&before_removal) && shown.contains("chosen-before-removal"),
            "PRODUCT: active computer did not show its manual trust on {node}: {shown}{err}"
        );
    }
    assert_eq!(
        computer(&a, &["status"])["frontier"],
        a_frontier,
        "PRODUCT: alpha's local manual trust changed the Computer policy frontier"
    );
    assert_eq!(
        computer(&b, &["status"])["frontier"],
        b_frontier,
        "PRODUCT: beta's local manual trust changed the Computer policy frontier"
    );

    let a_id = computer(&a, &["status"])["this_computer"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    let b_id = computer(&b, &["status"])["this_computer"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    let frontier = computer(&a, &["status"])["frontier"]
        .as_str()
        .unwrap()
        .to_owned();
    computer(&a, &["remove", &b_id, "--confirm", &frontier]);
    assert!(
        wait_until(CHANGE_SHOWN_WITHIN, || {
            computer(&a, &["status"])["removed"]
                .as_array()
                .is_some_and(|removed| removed.iter().any(|entry| entry["fingerprint"] == b_id))
                && computer(&b, &["status"])["state"] == "removed"
        }),
        "PRODUCT: removal did not reach both running computers"
    );

    for (account, node) in [(&a, "alpha"), (&b, "beta")] {
        let (ok, out, err) = account.run(
            &[
                "trust",
                "add",
                &after_removal,
                "--name",
                "chosen-after-removal",
                "--drive",
                "--node",
                node,
            ],
            "",
        );
        assert!(
            ok,
            "PRODUCT: active/removed computer refused later manual trust on {node}: {out}{err}\ndaemon:\n{}",
            account.log()
        );
    }
    offline_for_enrollment(&a, "active computer manual-trust restart");
    offline_for_enrollment(&b, "removed computer manual-trust restart");
    for (account, node) in [(&a, "alpha"), (&b, "beta")] {
        let (ok, out, err) = account.run(&["node", "unlock", node, "--passphrase-file", "-"], PASS);
        assert!(ok, "PRODUCT: restart detached {node}: {out}{err}");
        let (ok, shown, err) = account.run(&["trust", "list", "--node", node], "");
        assert!(
            ok && shown.lines().any(|line| {
                line.contains(&after_removal)
                    && line.contains("chosen-after-removal")
                    && line.contains("read + drive")
            }),
            "PRODUCT: restart lost later manual trust on {node}: {shown}{err}"
        );
    }
    assert_eq!(
        computer(&a, &["status"])["this_computer"]["fingerprint"],
        a_id,
        "PRODUCT: active computer identity changed across restart"
    );
    assert_eq!(
        computer(&b, &["status"])["state"],
        "removed",
        "PRODUCT: removed computer's restart restored membership"
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
/// With all staged nodes hosted and nothing changing, the proof waits for shipped status to name
/// the pair's next completed, dated bidirectional fallback exchange. It permits only a second
/// attempt already overlapping that round; each completion must appear as the peer's answered
/// exchange, and a covered attempt without its own completion must retain no failure. Across that
/// causal boundary every node's binding MUST stand derived at the current policy revision at the
/// same durable moment as before the unchanged-state exchange. There is no arbitrary quiet window:
/// the source-owned fallback cadence plus its existing return contract bounds the named boundary,
/// and the status observations name unnecessary work directly. A machine-dependent CPU cutoff is
/// not a product verdict. Measured before this (2026-10-20, the decider's work Mac): the pairing
/// manager exchanged the whole signed history with every computer every 2 s and re-verified it,
/// and a 1 s tick re-derived every attached node's binding with nothing changed.
/// A test-only causal hold parks delta's exact admitted remote pause at its final publication
/// boundary while durable Computer policy moves; releasing it must make the shipped command
/// refuse, never publish with stale drive. Finally, another causal release keeps delta's exact
/// policy message queued while eta attaches.
/// Within [`CHANGE_SHOWN_WITHIN`], after all final observations finish, beta has applied eta
/// on its healthy node while `vox node list` still shows held delta Ready and delta's shipped trust
/// view has not adopted the new grant. The stale projection remains non-authoritative behind the
/// Computer policy fence; keeping the actor lets a later policy event recover it without unlock.
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
/// the causal-miss live heal misses [`RETURN_WITHIN`] and turns PRODUCT red; (5) give
/// reconciliation bypass the current-policy fence: held delta can use its stale projection and
/// turns PRODUCT red; (6) serialize siblings behind held delta:
/// beta's binding/keyring claim misses that same bound and turns PRODUCT red; (7) remove the
/// reconciliation ownership checks: an old delayed result detaches either replacement delta or
/// the same attachment applying a newer revision and turns PRODUCT red; (8) bypass the current-authority publication fence: the causally held shipped
/// remote pause publishes after its actor revision becomes stale and turns PRODUCT red. The stuck-node phase begins after
/// shipped status names the exact causal miss, so resetting either exchange or apply clocks turns its return bound red.
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
        "VOX_TEST_HOLD_COMPUTER_STATE_COMMIT",
        "VOX_TEST_HOLD_ROOM_PAUSE_PUBLICATION",
        "VOX_TEST_HOLD_TEXT_APPEND_PUBLICATION",
        "VOX_TEST_HOLD_ROOM_CREATE_PUBLICATION",
        "VOX_TEST_HOLD_ROOM_JOIN_AFTER_BOARD",
        "VOX_TEST_HOLD_REKEY_ENQUEUE",
        "VOX_TEST_FX28_END_KEY_UNANSWERED_FILE",
        "VOX_TEST_FX28_MARK_ENDED_UNANSWERED_FILE",
        "VOX_TEST_FX28_MARK_DELIVERY_DRAINED_FILE",
        "VOX_TEST_FX28_ROTATE_AFTER_POST",
        "VOX_TEST_MARK_COMPUTER_STATUS_FILE",
        "VOX_TEST_FX28_MUTANT",
        "VOX_TEST_PARTITION_COMPUTER_PEER_FILE",
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
    let reply_hold = Duration::from_secs(15);
    let reply_spec = format!(
        "delta\t{}\t{}",
        reply_hold.as_millis(),
        reply_marker.display()
    );
    let state_commit_arm = b.data.join("hold-computer-state-commit-arm");
    let state_commit_engaged = b.data.join("hold-computer-state-commit-engaged");
    let state_commit_release = b.data.join("hold-computer-state-commit-release.sock");
    let state_commit_spec = format!(
        "{}\t{}\t{}",
        state_commit_arm.display(),
        state_commit_engaged.display(),
        state_commit_release.display()
    );
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
    let stale_join_arm = b.data.join("hold-delta-stale-join-arm");
    let stale_join_engaged = b.data.join("hold-delta-stale-join-engaged");
    let stale_join_release = b.data.join("hold-delta-stale-join-release.sock");
    let stale_join_spec = format!(
        "delta\t{}\t{}\t{}",
        stale_join_arm.display(),
        stale_join_engaged.display(),
        stale_join_release.display()
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
    let control_partition_arm = a.data.join(FX28_CONTROL_PARTITION_ARM);
    let control_partition_spec = format!(
        "{}\t{}",
        control_partition_arm.display(),
        control_partition_arm.with_extension("marker").display()
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
    let stopped_reader_release = b.data.join("fx28-stopped-reader-release");
    let stopped_reader_answered = b.data.join("fx28-stopped-reader-all-answers");
    let stopped_reader_arm_spec = format!(
        "{}\t{}\t{}\t{}",
        stopped_reader_arm.display(),
        stopped_reader_generation.display(),
        stopped_reader_release.display(),
        stopped_reader_answered.display()
    );
    let stopped_reader_answered_spec = format!(
        "{}\t{}\t{}",
        stopped_reader_generation.display(),
        stopped_reader_release.display(),
        stopped_reader_answered.display()
    );
    let rotate_after_post_arm = b.data.join(FX28_ROTATE_AFTER_POST_ARM);
    let rotate_after_post_spec = rotate_after_post_arm.to_string_lossy().into_owned();
    let mut da = Daemon::start(
        &a,
        &["--node", "alpha"],
        &[
            ("VOX_LISTEN", &listen_a),
            ("VOX_TEST_ADVERTISE", &advertised),
            ("VOX_TEST_FX28_END_KEY_UNANSWERED_FILE", &older_spec),
            (
                "VOX_TEST_PARTITION_COMPUTER_PEER_FILE",
                &control_partition_spec,
            ),
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
            ("VOX_TEST_HOLD_COMPUTER_STATE_COMMIT", &state_commit_spec),
            ("VOX_TEST_HOLD_ROOM_PAUSE_PUBLICATION", &stale_pause_spec),
            ("VOX_TEST_HOLD_TEXT_APPEND_PUBLICATION", &stale_post_spec),
            ("VOX_TEST_HOLD_ROOM_CREATE_PUBLICATION", &stale_create_spec),
            ("VOX_TEST_HOLD_ROOM_JOIN_AFTER_BOARD", &stale_join_spec),
            ("VOX_TEST_HOLD_REKEY_ENQUEUE", &stale_rekey_spec),
            (
                "VOX_TEST_FX28_MARK_ENDED_UNANSWERED_FILE",
                &older_selected_spec,
            ),
            ("VOX_TEST_FX28_ROTATE_AFTER_POST", &rotate_after_post_spec),
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
        let status_a = computer(&a, &["status"]);
        let status_b = computer(&b, &["status"]);
        if status_a["state"] == "confirmed" && status_b["state"] == "confirmed" {
            break;
        }
        assert!(
            approval_started.elapsed() < RETURN_WITHIN,
            "PRODUCT: {RETURN_WITHIN:?} after the first shipped approval was asked, the two \
             computers were not both confirmed: alpha {}; beta {}\n{}\n{}",
            status_a,
            status_b,
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
            state_commit_spec: &state_commit_spec,
            stale_pause_spec: &stale_pause_spec,
            stale_post_spec: &stale_post_spec,
            stale_create_spec: &stale_create_spec,
            stale_join_spec: &stale_join_spec,
            stale_rekey_spec: &stale_rekey_spec,
            older_selected_spec: &older_selected_spec,
            stopped_reader_answered: &stopped_reader_answered_spec,
        },
    );

    // ---- a change on either daemon shows on both despite the clock skew (#1020) -----------
    let gamma = a.make_node("gamma");
    let nodes_a = [("alpha", alpha.as_str()), ("gamma", gamma.as_str())];
    for stale in [
        &stopped_reader_generation,
        &stopped_reader_release,
        &stopped_reader_answered,
    ] {
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

    // ---- a durable Computer write cannot wedge status or fabricate storage failure -------
    computer_write_expiry_keeps_status_live(
        (&a, &da, &nodes_a),
        (&b, &db, &nodes_b),
        &state_commit_arm,
        &state_commit_engaged,
        &state_commit_release,
    );

    // ---- rejected join records leave the answering member's board across restart ---------
    let db = rejected_join_records_leave_remote_board(
        (&a, &da),
        RestartComputerSide {
            account: &b,
            daemon: db,
            nodes: &nodes_b,
            listen: &listen_b,
            hold_spec: &hold_spec,
            reply_spec: &reply_spec,
            state_commit_spec: &state_commit_spec,
            stale_pause_spec: &stale_pause_spec,
            stale_post_spec: &stale_post_spec,
            stale_create_spec: &stale_create_spec,
            stale_join_spec: &stale_join_spec,
            stale_rekey_spec: &stale_rekey_spec,
            older_selected_spec: &older_selected_spec,
            stopped_reader_answered: &stopped_reader_answered_spec,
        },
        &stale_join_arm,
        &stale_join_engaged,
        &stale_join_release,
    );

    // ---- a stale actor cannot publish a remote drive mutation -----------------------------
    let epsilon = stale_remote_pause_is_refused(
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
    replacement_generation_survives((&a, &da), (&b, &db), (&reply_marker, reply_hold, &delta));

    // ---- both live daemons converge when their userspace path is restored -----------------
    change_reaches_a_live_computer((&a, &da, &nodes_a), (&b, &db, &nodes_b), &forward);

    // What one exact `vox computer status --json` snapshot shows. Attempts and completions cannot
    // establish an idle baseline by themselves: an attempt can start before the snapshot and
    // complete after it.
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
        let in_flight = apps.iter().any(|p| {
            p["exchange_in_flight"].as_bool().unwrap_or_else(|| {
                panic!(
                    "PRODUCT: `vox computer status --json` does not say whether an exchange is in flight: {p}"
                )
            })
        });
        let latest_record = |field: &str| {
            apps.iter()
                .filter_map(|p| {
                    Some((
                        p[field]["at_ms"].as_u64()?,
                        p[field]["sent_revision"].as_u64()?,
                        p[field]["merged_revision"].as_u64()?,
                    ))
                })
                .max_by_key(|record| record.0)
        };
        let failures: u64 = apps
            .iter()
            .map(|p| p["exchange_failures"].as_u64().unwrap_or(0))
            .sum();
        (
            total,
            attempts,
            last,
            confirmed,
            status["applications"].to_string(),
            bindings_shown(&status),
            in_flight,
            latest_record("last_started_exchange"),
            latest_record("last_answered_exchange"),
            failures,
        )
    };
    // Late recovery can legitimately leave its symmetric receipt/application tail in flight.
    // Stage the pair at a product-observable idle boundary, retaining counters, exchange records,
    // bindings and the idle bit from the same responses. Alpha brackets beta's snapshot: because
    // every complete exchange is bidirectional, an exchange which crosses beta's read also moves
    // one of alpha's two records; an attempt which has not reached alpha yet began after beta's
    // snapshot and is the next event under observation. A new attempt while current/confirmed is
    // extra work; an unchanged attempt which remains reserved for its whole return contract is
    // wedged work.
    let settling_deadline = Instant::now() + RETURN_WITHIN;
    let mut first_attempts_a = None;
    let mut first_attempts_b = None;
    let ((baseline_a_at, baseline_a), (baseline_b_at, baseline_b)) = loop {
        let before_a = exchanges(&a);
        let snapshot_b = exchanges(&b);
        let after_a = exchanges(&a);
        for (who, snapshot) in [
            ("alpha", &before_a),
            ("beta", &snapshot_b),
            ("alpha", &after_a),
        ] {
            let current = snapshot
                .5
                 .1
                .values()
                .all(|(revision, _)| *revision == Some(snapshot.5 .0));
            assert!(
                snapshot.3 && current && snapshot.9 == 0,
                "PRODUCT: after live-path recovery {who} did not remain confirmed and failure-free with every own binding at current policy revision {} while staging the quiet boundary: {} / {:?}",
                snapshot.5 .0,
                snapshot.4,
                snapshot.5 .1
            );
        }
        let first_a = *first_attempts_a.get_or_insert(before_a.1);
        let first_b = *first_attempts_b.get_or_insert(snapshot_b.1);
        assert!(
            before_a.1 == first_a && after_a.1 == first_a,
            "PRODUCT: while alpha remained current and confirmed, it started an extra exchange before reaching the bracketed idle boundary and before the named {FALLBACK_NAMED:?} fallback: {}",
            after_a.4
        );
        assert!(
            snapshot_b.1 == first_b,
            "PRODUCT: while beta remained current and confirmed, it started an extra exchange before reaching the bracketed idle boundary and before the named {FALLBACK_NAMED:?} fallback: {}",
            snapshot_b.4
        );
        let alpha_stable = before_a.0 == after_a.0
            && before_a.1 == after_a.1
            && before_a.5 == after_a.5
            && before_a.7 == after_a.7
            && before_a.8 == after_a.8
            && before_a.9 == after_a.9;
        if !before_a.6 && !snapshot_b.6 && !after_a.6 && alpha_stable {
            let boundary = Instant::now();
            break ((boundary, after_a), (boundary, snapshot_b));
        }
        assert!(
            Instant::now() < settling_deadline,
            "PRODUCT: after a full {RETURN_WITHIN:?} exchange return contract, shipped status still showed an unchanged current/confirmed exchange in flight (wedged work), rather than an idle quiet boundary: alpha {}; beta {}",
            after_a.4,
            snapshot_b.4
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let (ea0, aa0, _, _, shown_a0, derived_a0, _, started_a0, answered_a0, _) = baseline_a;
    let (eb0, ab0, _, _, shown_b0, derived_b0, _, started_b0, answered_b0, _) = baseline_b;
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
    // Do not choose an observation window. One full exchange is bidirectional: the starter sends
    // its snapshot and the answerer returns its own, and `last_answered_exchange` is the shipped
    // evidence of that return. The answer deliberately repaces the answerer's fallback, so
    // requiring both daemons to start another round would assert redundant work. Wait instead for
    // the next pair exchange, then let only a fallback already racing it settle. These status
    // transitions are the structural boundary: a timer restored anywhere in binding derivation
    // crosses it and moves the durable derivation record.
    //
    // The pair's earliest idle baseline plus the named cadence and existing return contract bounds
    // its first completed round. An already-racing flight retains its own return contract; the
    // proof does not renew a stopwatch merely because it observed the other completion.
    let pair_deadline = baseline_a_at.min(baseline_b_at) + FALLBACK_NAMED + RETURN_WITHIN;
    let (
        (
            ea1,
            aa1,
            last_a,
            confirmed_a,
            shown_a1,
            derived_a1,
            _,
            started_a1,
            answered_a1,
            failures_a1,
        ),
        (
            eb1,
            ab1,
            last_b,
            confirmed_b,
            shown_b1,
            derived_b1,
            _,
            started_b1,
            answered_b1,
            failures_b1,
        ),
    ) = loop {
        let after_a = exchanges(&a);
        let after_b = exchanges(&b);
        let tried_a = after_a.1.saturating_sub(aa0);
        let tried_b = after_b.1.saturating_sub(ab0);
        let completed_a = after_a.0.saturating_sub(ea0);
        let completed_b = after_b.0.saturating_sub(eb0);
        assert!(
            tried_a <= 1 && tried_b <= 1 && completed_a <= 1 && completed_b <= 1,
            "PRODUCT: before the unchanged pair reached its next fallback boundary, it started or completed extra rounds (a failed round and its retry are two): alpha {tried_a} attempt(s) for {completed_a} exchange(s), beta {tried_b} for {completed_b}\n{}\n{}",
            after_a.4,
            after_b.4
        );
        let answered_a = after_a.8 != answered_a0;
        let answered_b = after_b.8 != answered_b0;
        let pair_completed = completed_a + completed_b > 0;
        let every_completion_returned_peer_state =
            (completed_a == 0 || answered_b) && (completed_b == 0 || answered_a);
        if pair_completed && every_completion_returned_peer_state && !after_a.6 && !after_b.6 {
            break (after_a, after_b);
        }
        let now = Instant::now();
        assert!(
            now < pair_deadline,
            "PRODUCT: measured from the pair's bracketed idle status snapshots, after the named \
                 {FALLBACK_NAMED:?} quiet cadence plus its existing {RETURN_WITHIN:?} return \
                 contract, shipped status had not completed and settled one bidirectional fallback exchange: \
                 alpha {}; beta {}\n{}\n{}",
            after_a.4,
            after_b.4,
            da.said(),
            db.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    for (who, completed, before_started, before_answered, after_started) in [
        ("alpha", ea1 - ea0, started_a0, answered_a0, started_a1),
        ("beta", eb1 - eb0, started_b0, answered_b0, started_b1),
    ] {
        if completed == 0 {
            continue;
        }
        let Some(after) = after_started.map(|record| record.0) else {
            panic!("PRODUCT: {who}'s shipped status did not date the quiet fallback it completed");
        };
        let Some(before) = before_started
            .map(|record| record.0)
            .into_iter()
            .chain(before_answered.map(|record| record.0))
            .max()
        else {
            panic!("PRODUCT: {who}'s shipped status did not date the exchange which paced its quiet fallback");
        };
        let gap = after.saturating_sub(before);
        assert!(
            gap >= FALLBACK_NAMED.as_millis() as u64,
            "PRODUCT: {who} completed a quiet exchange {} s after the previous exchange it started or answered \
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
    // Every round is counted from its start, completed or not. One side normally starts the
    // bidirectional exchange. Both may start only when their named fallback instants race. A
    // covered overlapping attempt may end without its own completion; that is valid only when
    // this daemon answered the peer's successful round and retained no failure.
    let tried_a = grew(aa0, aa1, "alpha", &shown_a0, &shown_a1);
    let tried_b = grew(ab0, ab1, "beta", &shown_b0, &shown_b1);
    assert!(
        failures_a1 == 0 && failures_b1 == 0,
        "PRODUCT: the reachable unchanged pair retained an operational exchange failure at its quiet boundary: alpha {failures_a1}, beta {failures_b1}\n{shown_a1}\n{shown_b1}"
    );
    assert!(
        (1..=2).contains(&(tried_a + tried_b))
            && (1..=2).contains(&(during_a + during_b))
            && tried_a >= during_a
            && tried_b >= during_b
            && (tried_a == during_a || (answered_a1 != answered_a0 && failures_a1 == 0))
            && (tried_b == during_b || (answered_b1 != answered_b0 && failures_b1 == 0)),
        "PRODUCT: the unchanged pair did not complete exactly one bidirectional quiet fallback, apart from one documented simultaneous-start overlap (a failed round and its retry are two) (ADR-038 FX-15, #989): \
         alpha {tried_a} attempt(s) for {during_a} exchange(s), beta {tried_b} for {during_b}\n{shown_a1}\n{shown_b1}"
    );
    assert!(
        (during_a == 0 || answered_b1 != answered_b0)
            && (during_b == 0 || answered_a1 != answered_a0),
        "PRODUCT: a completed quiet fallback did not show the peer's bidirectional answer: alpha started {during_a}, beta answered {answered_b0:?} -> {answered_b1:?}; beta started {during_b}, alpha answered {answered_a0:?} -> {answered_a1:?}"
    );
    println!(
        "[proof] at the pair's next named bidirectional quiet fallback boundary with all staged nodes hosted: alpha started {during_a} exchange(s) with beta (last at {last_a:?}, confirmed {confirmed_a}), beta started {during_b} with alpha (last at {last_b:?}, confirmed {confirmed_b}); bindings: alpha's computer at policy revision {} {:?}, beta's at {} {:?}, derived again across the boundary: {}",
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
        confirmed_a && confirmed_b && (last_a.is_some() || last_b.is_some()),
        "PRODUCT: `vox computer status` does not say the peer is confirmed and date the pair's completed fallback: alpha {confirmed_a} {last_a:?}, beta {confirmed_b} {last_b:?}"
    );
    // The plain `vox computer status` exposes the same fields to a person. Do not compare its
    // numbers with an earlier JSON command: the two sides' named fallbacks can be phase-shifted,
    // so one side can legitimately reach its next cadence while the proof waits for the other's
    // first boundary. The exact per-boundary numbers were asserted above from each coherent JSON
    // snapshot; this independent command proves the plain surface renders those records.
    for (who, acct, (revision, nodes)) in [("alpha", &a, &derived1.0), ("beta", &b, &derived1.1)] {
        let (ok, text, err) = acct.run(&["computer", "status"], "");
        assert!(ok, "PRODUCT: `vox computer status` failed for {who}: {err}");
        let exchange_line = text.lines().find(|line| {
            line.contains("exchanged ")
                && line.contains(" time(s) in ")
                && line.contains(" attempt(s) since the daemon started")
        });
        assert!(
            exchange_line.is_some_and(|line| {
                line.contains(", last ")
                    && line.contains("last exchange started ")
                    && line.contains("last exchange answered ")
                    && line.matches("sent revision ").count() == 2
                    && line.matches("merged to revision ").count() == 2
            }),
            "PRODUCT: {who}'s `vox computer status` does not say how many exchanges and attempts \
             it currently records, when, and what the last exchange it started and the last it \
             answered carried (#989, ADR-038 FX-28); it said: {text}"
        );
        assert!(
            !text.contains("failed in a row"),
            "PRODUCT: {who}'s `vox computer status` reports failures on the reachable quiet pair: {text}"
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
    // ---- a late accepted actor completes without another user action -----------------------
    delayed_node_completes_without_another_policy_action(
        (&a, &da, &nodes_a),
        (&b, &db, &nodes_b),
        &hold_arm,
        &hold_engaged,
        &hold_release,
        &forward,
    );
    stale_rekey_is_not_delivered(
        (&a, &da),
        (&b, db),
        &epsilon,
        &listen_b,
        &hold_spec,
        &stale_rekey_spec,
        &older_selected_spec,
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
            let fingerprint = fingerprint.trim();
            // The empty-keyring help line is indented and contains repeated spaces.  It is
            // explanation, not a zero-length identity entry.
            if fingerprint.is_empty() {
                return None;
            }
            Some((fingerprint, rest.rsplit("  ").next()?.trim()))
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

/// Park the responder's exact durable Computer-state write, prove a shipped status read still
/// returns while that filesystem work is parked, then release only after the originating
/// change's exported return boundary. The refused pre-rename commit leaves the responder's prior
/// policy intact; it must never be reported as a permanent storage quarantine. A later ordinary
/// shipped policy change then proves the pair can converge without a daemon restart.
fn computer_write_expiry_keeps_status_live(
    (a, da, nodes_a): (&Account, &Daemon, &[(&str, &str)]),
    (b, db, nodes_b): (&Account, &Daemon, &[(&str, &str)]),
    arm: &Path,
    engaged: &Path,
    release: &Path,
) {
    for stale in [engaged, release] {
        let _ = std::fs::remove_file(stale);
    }
    std::fs::write(arm, b"hold the next remote Computer state commit\n")
        .expect("APPARATUS: arm the durable Computer-state commit hold");
    let a_id = computer_id(a);
    let before_b = computer(b, &["status"]);
    let changed = Instant::now();
    computer(a, &["personal", "gamma"]);
    let marker = read_daemon_marker(
        engaged,
        db.child.id(),
        "the responder's exact durable Computer-state commit hold",
    );
    assert!(
        marker.contains("computer state commit held"),
        "APPARATUS: durable-write marker did not name its boundary: {marker}"
    );

    // This command is the product observation. Under the lock-through-write mutant it wedges on
    // the parked filesystem work and Account::run names that exact PRODUCT liveness failure.
    let during = computer(b, &["status"]);
    assert_eq!(
        during["revision"], before_b["revision"],
        "PRODUCT [FX28 status-during-write]: shipped status exposed an uncommitted Computer revision while its durable write was parked: before {before_b}; during {during}"
    );
    println!(
        "[proof] FX-28 status-during-write: shipped `vox computer status` returned readable state while the exact durable Computer write remained parked"
    );

    // The clock belongs to the change made above. Waiting to that exported boundary stages a
    // causal refusal; it is not the verdict and does not give a wedged command permission to pass.
    std::thread::sleep(RETURN_WITHIN.saturating_sub(changed.elapsed()));
    std::os::unix::net::UnixStream::connect(release).unwrap_or_else(|error| {
        panic!(
            "APPARATUS: release the held Computer-state commit at {}: {error}",
            release.display()
        )
    });
    let after = computer(b, &["status"]);
    assert!(
        after["state"] != "quarantined"
            && !after["problem"]
                .as_str()
                .is_some_and(|problem| problem.contains("storage")),
        "PRODUCT [FX28 deadline-as-storage-failure]: the pre-rename causal refusal left the prior Computer policy intact, but shipped status reported permanent storage quarantine: {after}"
    );
    println!(
        "[proof] FX-28 deadline classification: after the expired pre-rename write was released, shipped status did not report storage quarantine (an independent reverse exchange may carry the same signed policy)"
    );

    // A newer real operator action supersedes the missed cause. Recovery must not require a
    // restart merely because the previous write's causal clock elapsed before its rename.
    let recovering = Instant::now();
    computer(a, &["personal", "alpha"]);
    let names_a: Vec<&str> = nodes_a.iter().map(|(name, _)| *name).collect();
    let names_b: Vec<&str> = nodes_b.iter().map(|(name, _)| *name).collect();
    let all: Vec<(&str, &str)> = nodes_a.iter().chain(nodes_b).copied().collect();
    loop {
        let status_a = computer(a, &["status"]);
        let status_b = computer(b, &["status"]);
        let current = status_a["state"] == "confirmed"
            && status_b["state"] == "confirmed"
            && roster_current(&status_a, &names_a)
            && roster_current(&status_b, &names_b)
            && keyrings_complete(a, nodes_a, &all).is_ok()
            && keyrings_complete(b, nodes_b, &all).is_ok();
        if current {
            break;
        }
        assert!(
            recovering.elapsed() < RETURN_WITHIN,
            "PRODUCT: a newer shipped Computer policy did not recover the causally refused prior write within {RETURN_WITHIN:?}: alpha {status_a}; beta {status_b}; peer {a_id}\n{}\n{}",
            da.said(),
            db.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    println!(
        "[proof] a newer shipped policy change converged both computers after the causally refused write, without restarting either daemon"
    );
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
        "APPARATUS: attach {new_node} on {}'s computer: {out}{err}\nactor log:\n{}\ndaemon transcript:\n{}",
        names_here[0],
        changer.log(),
        changer_daemon.said(),
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
    state_commit_spec: &'a str,
    stale_pause_spec: &'a str,
    stale_post_spec: &'a str,
    stale_create_spec: &'a str,
    stale_join_spec: &'a str,
    stale_rekey_spec: &'a str,
    older_selected_spec: &'a str,
    stopped_reader_answered: &'a str,
}

/// Ask a real running node's board, as test-side apparatus, whether it still exposes both of one
/// member's join records. The verdict is always made from shipped command output or this remote
/// board; no local store or actor value is inspected.
fn remote_board_serves_member(
    rt: &hostile::Rt,
    address: std::net::SocketAddr,
    board: vox_core::hash::Digest32,
    room: vox_core::hash::Digest32,
    member: vox_core::hash::Digest32,
) -> (bool, bool) {
    use vox_core::nat::service::{RecordKinds, RendezvousClient};

    let reader = hostile::stranger(0xC7);
    rt.block_on(async {
        let (_endpoint, connection) = hostile::connect(&reader, address, board).await;
        let mut client = RendezvousClient::open(&connection)
            .await
            .expect("APPARATUS: open the real responder's board stream");
        let records = client
            .get(&room, 0, RecordKinds::ALL)
            .await
            .expect("APPARATUS: read the real responder's board");
        client.finish();
        (
            records.members.iter().any(|r| r.author_id == member),
            records.bundles.iter().any(|r| r.author_id == member),
        )
    })
}

/// A join can publish to the member that answered it before the final Computer-policy fence.
/// Hold that exact join, observe both accepted records on the responder's real board, move policy,
/// take the responder's path offline, and release the join. The refused join must survive neither
/// local room listing nor the responder's board after the joining daemon restarts. Reopening the
/// responder's exact userspace path while the joiner is stopped proves its in-memory stale records
/// persisted; only the joining daemon's durable cleanup can remove them.
#[allow(clippy::too_many_arguments)]
fn rejected_join_records_leave_remote_board(
    (a, da): (&Account, &Daemon),
    side: RestartComputerSide<'_>,
    join_arm: &Path,
    join_engaged: &Path,
    join_release: &Path,
) -> Daemon {
    let RestartComputerSide {
        account: b,
        daemon: db,
        nodes: nodes_b,
        listen: listen_b,
        hold_spec,
        reply_spec,
        state_commit_spec,
        stale_pause_spec,
        stale_post_spec,
        stale_create_spec,
        stale_join_spec,
        stale_rekey_spec,
        older_selected_spec,
        stopped_reader_answered,
    } = side;
    let c = Account::new();
    let host = c.make_node("host");
    let listen_c = format!("127.0.0.1:{}", port_forward::free_v4_udp_port());
    let board_forward = port_forward::PortForward::start(
        listen_c
            .parse()
            .expect("APPARATUS: constructed hidden board address"),
        true,
    );
    let board_address = board_forward.public;
    let advertised_c = board_address.to_string();
    let board_id = vox_core::node::link::b32_decode(&host, "host fingerprint")
        .expect("APPARATUS: host printed its full fingerprint");
    let member_id = vox_core::node::link::b32_decode(
        nodes_b
            .iter()
            .find_map(|(name, id)| (*name == "delta").then_some(*id))
            .expect("APPARATUS: delta is among beta's attached nodes"),
        "delta fingerprint",
    )
    .expect("APPARATUS: delta printed its full fingerprint");
    let mut dc = Daemon::start(
        &c,
        &["--node", "host"],
        &[
            ("VOX_LISTEN", &listen_c),
            ("VOX_TEST_ADVERTISE", &advertised_c),
            ("VOX_TEST_CLOCK_STEP_MS", REMOTE_CLOCK_SKEW_MS),
        ],
    );
    dc.expect_apparatus_event("node host is Ready", |line| line.contains("host is Ready"));
    let room = make_room(&c, "host");
    let (linked, link, link_error) = c.run(&["room", "link", &room, "--node", "host"], "");
    assert!(
        linked,
        "APPARATUS: host did not mint the direct room link: {link}{link_error}"
    );
    let link = link.trim().to_owned();
    let full_room = link
        .strip_prefix("vox://")
        .and_then(|rest| rest.get(..52))
        .unwrap_or_else(|| panic!("APPARATUS: host printed no full room id in {link:?}"));
    let room_id = vox_core::node::link::b32_decode(full_room, "room fingerprint")
        .expect("APPARATUS: host printed a full room id");

    std::fs::write(join_arm, b"hold delta after its board records land\n")
        .expect("APPARATUS: arm the stale join publication hold");
    let mut join = b
        .cmd(&[
            "room",
            "join",
            "--node",
            "delta",
            "--passphrase-file",
            "-",
            &link,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: start the shipped held room join");
    join.stdin
        .take()
        .expect("APPARATUS: held room join stdin")
        .write_all(ROOM_PASS.as_bytes())
        .expect("APPARATUS: give the held room join its passphrase");
    wait_for_command_marker(
        join_engaged,
        &mut join,
        db.child.id(),
        Instant::now() + RETURN_WITHIN,
        "delta's completed join after its real board publication was queued",
    );
    let rt = hostile::Rt::new();
    let accepted_by = Instant::now() + RETURN_WITHIN;
    loop {
        let exposed = remote_board_serves_member(&rt, board_address, board_id, room_id, member_id);
        if exposed == (true, true) {
            break;
        }
        assert!(
            Instant::now() < accepted_by,
            "APPARATUS: the responder's real board never accepted both delta join records before the policy-change claim was measured; member {}, bundle {}",
            exposed.0,
            exposed.1
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let before = computer(b, &["status"])["revision"].as_u64().unwrap_or(0);
    computer(a, &["personal", "gamma"]);
    assert!(
        wait_until(RETURN_WITHIN, || computer(b, &["status"])["revision"]
            .as_u64()
            .is_some_and(|revision| revision > before)),
        "APPARATUS: durable Computer policy did not move on beta while delta's join was held\n{}\n{}",
        da.said(),
        db.said()
    );
    assert!(
        join_engaged.is_file(),
        "APPARATUS: delta's join was not still held after durable policy moved"
    );
    println!("[proof] FX-28 stale-join-authority apparatus staged: the responder serves both exact join records while delta's completed join remains held across durable Computer policy movement");
    board_forward.close();
    std::os::unix::net::UnixStream::connect(join_release).unwrap_or_else(|error| {
        panic!(
            "APPARATUS: release delta's held join at {}: {error}",
            join_release.display()
        )
    });
    let joined = join
        .wait_with_output()
        .expect("APPARATUS: collect the causally released room join");
    assert!(
        !joined.status.success(),
        "PRODUCT [FX28 stale-join-authority]: after durable Computer policy moved while its accepted board records were visible, shipped `vox room join` still acknowledged the stale join: stdout {}; stderr {}",
        String::from_utf8_lossy(&joined.stdout),
        String::from_utf8_lossy(&joined.stderr)
    );
    assert!(
        board_forward.dropped() > 0,
        "APPARATUS: the closed responder path dropped no datagram, so board unreachability was not staged"
    );
    let _beta_before_restart = db.stop();
    let _verified = board_forward.open_and_verify();
    let still_exposed =
        remote_board_serves_member(&rt, board_address, board_id, room_id, member_id);
    assert!(
        still_exposed == (true, true),
        "APPARATUS: after the answering board's exact path reopened while beta was stopped, it did not still expose both accepted stale join records, so durable withdrawal recovery cannot be measured; member {}, bundle {}",
        still_exposed.0,
        still_exposed.1
    );

    let rotate_after_post_spec = b
        .data
        .join(FX28_ROTATE_AFTER_POST_ARM)
        .to_string_lossy()
        .into_owned();
    let restarted = Instant::now();
    let mut db = Daemon::start(
        b,
        &["--node", "beta"],
        &[
            ("VOX_LISTEN", listen_b),
            ("VOX_TEST_CLOCK_STEP_MS", REMOTE_CLOCK_SKEW_MS),
            ("VOX_TEST_HOLD_COMPUTER_POLICY", hold_spec),
            ("VOX_TEST_HOLD_COMPUTER_POLICY_REPLY", reply_spec),
            ("VOX_TEST_HOLD_COMPUTER_STATE_COMMIT", state_commit_spec),
            ("VOX_TEST_HOLD_ROOM_PAUSE_PUBLICATION", stale_pause_spec),
            ("VOX_TEST_HOLD_TEXT_APPEND_PUBLICATION", stale_post_spec),
            ("VOX_TEST_HOLD_ROOM_CREATE_PUBLICATION", stale_create_spec),
            ("VOX_TEST_HOLD_ROOM_JOIN_AFTER_BOARD", stale_join_spec),
            ("VOX_TEST_HOLD_REKEY_ENQUEUE", stale_rekey_spec),
            (
                "VOX_TEST_FX28_MARK_ENDED_UNANSWERED_FILE",
                older_selected_spec,
            ),
            ("VOX_TEST_FX28_ROTATE_AFTER_POST", &rotate_after_post_spec),
            (
                "VOX_TEST_FX28_STOPPED_READER_ANSWERED_FILE",
                stopped_reader_answered,
            ),
        ],
    );
    for (name, _) in nodes_b {
        let ready = format!("{name} is Ready");
        db.expect_event_until(
            restarted + RETURN_WITHIN,
            &format!("node {name} is Ready after durable-withdrawal restart"),
            |line| line.contains(&ready),
        );
    }
    let (listed, rooms, list_error) = b.run(&["room", "list", "--node", "delta"], "");
    assert!(
        listed && !rooms.contains(&room),
        "PRODUCT [FX28 stale-join-authority]: after the joining daemon restarted and delta was Ready, its shipped room list exposed the refused stale-authority join: {rooms}{list_error}"
    );
    loop {
        let exposed = remote_board_serves_member(&rt, board_address, board_id, room_id, member_id);
        if exposed == (false, false) {
            break;
        }
        assert!(
            restarted.elapsed() < RETURN_WITHIN,
            "PRODUCT [FX28 withdrawal-not-durable]: after delta's refused join and daemon restart, the answering member's real board still exposed its stale records: member {}, bundle {}; beta daemon {}; host daemon {}",
            exposed.0,
            exposed.1,
            db.said(),
            dc.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    println!(
        "[proof] after a refused join, offline responder and joining-daemon restart, the responder's real board exposes neither stale member nor stale bundle record"
    );
    computer(a, &["personal", "alpha"]);
    assert!(
        wait_until(RETURN_WITHIN, || {
            roster_current(&computer(a, &["status"]), &["alpha", "gamma"])
                && roster_current(&computer(b, &["status"]), &["beta", "delta"])
        }),
        "APPARATUS: both Computers did not settle after the durable board-withdrawal phase"
    );
    db
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
        state_commit_spec,
        stale_pause_spec,
        stale_post_spec,
        stale_create_spec,
        stale_join_spec,
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
    let rotate_after_post_spec = b
        .data
        .join(FX28_ROTATE_AFTER_POST_ARM)
        .to_string_lossy()
        .into_owned();
    let restarted = Instant::now();
    let mut db = Daemon::start(
        b,
        &["--node", "beta"],
        &[
            ("VOX_LISTEN", listen_b),
            ("VOX_TEST_CLOCK_STEP_MS", REMOTE_CLOCK_SKEW_MS),
            ("VOX_TEST_HOLD_COMPUTER_POLICY", hold_spec),
            ("VOX_TEST_HOLD_COMPUTER_POLICY_REPLY", reply_spec),
            ("VOX_TEST_HOLD_COMPUTER_STATE_COMMIT", state_commit_spec),
            ("VOX_TEST_HOLD_ROOM_PAUSE_PUBLICATION", stale_pause_spec),
            ("VOX_TEST_HOLD_TEXT_APPEND_PUBLICATION", stale_post_spec),
            ("VOX_TEST_HOLD_ROOM_CREATE_PUBLICATION", stale_create_spec),
            ("VOX_TEST_HOLD_ROOM_JOIN_AFTER_BOARD", stale_join_spec),
            ("VOX_TEST_HOLD_REKEY_ENQUEUE", stale_rekey_spec),
            (
                "VOX_TEST_FX28_MARK_ENDED_UNANSWERED_FILE",
                older_selected_spec,
            ),
            ("VOX_TEST_FX28_ROTATE_AFTER_POST", &rotate_after_post_spec),
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
/// applies. Detach retires the old pending result; neither old result may change its successor.
fn replacement_generation_survives(
    (a, da): (&Account, &Daemon),
    (b, db): (&Account, &Daemon),
    (reply_marker, reply_hold, delta): (&Path, Duration, &str),
) {
    let zeta = a.make_node("zeta");
    let reply_armed_at = Instant::now();
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
    let return_deadline = changed + RETURN_WITHIN;
    // The reply delay starts only after this event computes its result, hence no earlier than
    // its arm. Its existing fixture interval is staging only: obtain the actual public miss
    // and pending row before the earliest possible reply release, or this race is not staged.
    let reply_cannot_have_returned_before = reply_armed_at + reply_hold;
    let (held_revision, old_miss) = loop {
        let status = computer(b, &["status"]);
        let revision = status["revision"]
            .as_u64()
            .expect("APPARATUS: held delta status omitted its policy revision");
        let pending = status["pending_nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .any(|words| {
                words.starts_with("delta:")
                    && words.contains("missed its local application boundary")
            });
        let miss = status["application_misses"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|miss| miss["node"] == delta && miss["revision"].as_u64() == Some(revision))
            .cloned();
        let applied = roster_current(&status, &["beta", "delta"])
            && grant_words(b, "delta", &zeta).as_deref() == Some("read");
        assert!(
            Instant::now() < reply_cannot_have_returned_before.min(return_deadline),
            "APPARATUS: the exact public pending miss was not observed before the old reply could return; no detach-ownership verdict is possible: {status}"
        );
        if pending && applied {
            if let Some(miss) = miss {
                break (revision, miss);
            }
        }
        assert!(
            daemon_alive(da.child.id()) && daemon_alive(db.child.id()),
            "APPARATUS: a daemon exited while staging delta's exact pending result before detach"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    println!("[proof] FX-28 detach-reconciliation apparatus staged: delta's exact applied target {held_revision} has public pending status and historical miss {old_miss} before its held old-generation reply can return");
    let (ok, out, err) = b.run(&["node", "detach", "delta"], "");
    assert!(ok, "APPARATUS: detach old delta generation: {out}{err}");
    assert!(
        Instant::now() < reply_cannot_have_returned_before,
        "APPARATUS: detach did not complete before the old reply could return; the pending-result retirement race was not staged"
    );
    let (ok, out, err) = b.run(&["node", "attach", "delta", "--passphrase-file", "-"], PASS);
    assert!(
        ok,
        "APPARATUS: attach replacement delta generation: {out}{err}"
    );
    assert!(
        wait_until(return_deadline.saturating_duration_since(Instant::now()), || {
            let status = computer(b, &["status"]);
            let grant = grant_words(b, "delta", &zeta);
            let observed_at = Instant::now();
            let complete = status["revision"].as_u64() == Some(held_revision)
                && !status["pending_nodes"].as_array().into_iter().flatten()
                    .filter_map(serde_json::Value::as_str).any(|words| words.starts_with("delta:"))
                && status["application_misses"].as_array().is_some_and(|misses| misses.contains(&old_miss))
                && status["state"] == "confirmed"
                && roster_current(&status, &["beta", "delta"])
                && grant.as_deref() == Some("read");
            complete && observed_at <= return_deadline
        }),
        "PRODUCT [FX28 detach-reconciliation]: reattaching the same-policy delta did not clear the departing attachment's pending result and confirm its actual grant while preserving the historical miss within the original return boundary: {}",
        computer(b, &["status"])
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
/// stay alive; gamma becomes alpha's personal node and shipped status names that exact policy
/// revision's causal exchange expired. Opening that same path lets the one retained authenticated
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
    // The exchange alpha's daemon starts for it cannot complete: wait for the shipped status to
    // say that exact policy revision missed its causal convergence boundary. A retry count is not
    // the claim—exponential backoff and scheduling cost can reach the boundary with different
    // counts, while the durable missed revision is the product consequence recovery must heal.
    let missed_visible_by = changed + RETURN_WITHIN + CHANGE_SHOWN_WITHIN;
    loop {
        let application = application_toward(a, &b_id);
        if application["missed_revision"].as_u64() == Some(revision)
            && application["convergence_state"] == "expired"
        {
            break;
        }
        assert!(
            Instant::now() < missed_visible_by,
            "PRODUCT: after policy revision {revision}'s {RETURN_WITHIN:?} remote convergence \
             deadline and the existing {CHANGE_SHOWN_WITHIN:?} local observation contract, \
             shipped status had not exposed its missed causal exchange toward beta: \
             {application}\nits daemon said: {}",
            da.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let missed = application_toward(a, &b_id);
    println!(
        "[proof] alpha's status names policy revision {revision} expired toward beta after {} cumulative journey attempts ({} currently failed); recovery is measured from path restoration, not that incidental count",
        missed["exchange_attempts"],
        missed["exchange_failures"]
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
/// policy through another shipped action, then read the saved pause state through a real Session.
/// The marker proves causal staging; neither an unknown command reply nor elapsed silence is a
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
) -> String {
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

    // A real harness hook opens the Session whose shipped read below observes the room's durable
    // pause state. Prove the exact owner and Session are present before staging the stale write;
    // otherwise a later missing-session error could be mistaken for an unpaused room.
    const PAUSE_SESSION: &str = "fx28-stale-pause-session";
    let payload = format!(
        r#"{{"session_id":"{PAUSE_SESSION}","hook_event_name":"UserPromptSubmit","cwd":"{}","prompt":"observe the saved room pause state"}}"#,
        b._tmp.path().display()
    );
    let (ok, out, err) = b.run(
        &["agent", "hook", "--node", "delta", "--room", &room],
        &payload,
    );
    assert!(
        ok,
        "APPARATUS: delta's shipped Session hook for stale-pause observation failed: {out}{err}"
    );
    assert!(
        wait_until(RETURN_WITHIN, || {
            let (ok, listed, _) = b.run(
                &["room", "sessions", &room, "--node", "delta", "--json"],
                "",
            );
            ok && listed
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .any(|session| {
                    session["id"] == PAUSE_SESSION
                        && session["node"] == delta
                        && session["open"] == true
                })
        }),
        "APPARATUS: delta's exact shipped Session was not registered in the stale-pause room"
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
    let pause_stdout = String::from_utf8_lossy(&paused.stdout);
    println!(
        "[proof] after durable policy moved, the released stale-authority `vox room pause` command was diagnostic only (exit {}): stdout {}; stderr {}",
        paused.status,
        pause_stdout.trim(),
        String::from_utf8_lossy(&paused.stderr).trim()
    );
    let pause_read_deadline = Instant::now() + RETURN_WITHIN;
    assert!(
        wait_until(
            pause_read_deadline.saturating_duration_since(Instant::now()),
            || {
                roster_current(&computer(a, &["status"]), &["alpha", "gamma", "epsilon"])
                    && roster_current(&computer(b, &["status"]), &["beta", "delta"])
            }
        ),
        "APPARATUS: nodes did not settle after the stale-publication refusal"
    );
    let observe_session = || loop {
        assert!(
            Instant::now() < pause_read_deadline,
            "APPARATUS: exact Session listing did not settle within the retained pause-read/convergence boundary"
        );
        let (ok, listed, err) = b.run(
            &["room", "sessions", &room, "--node", "delta", "--json"],
            "",
        );
        const LISTING_CHANGED: &str =
            "the room's Sessions changed while listing; run the command again";
        let refusal = err.trim().strip_prefix("vox: ").unwrap_or(err.trim());
        if !ok && refusal == LISTING_CHANGED {
            // Discard any partial listing and select again only because Vox explicitly says
            // its selection changed. This spends the same retained observation boundary.
            continue;
        }
        assert!(
            ok,
            "APPARATUS: reobserve delta's exact registered Session before reading saved pause: stdout {listed}; stderr {err}"
        );
        let sessions: Vec<serde_json::Value> = listed
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line).unwrap_or_else(|error| {
                    panic!("APPARATUS: shipped Session listing was not JSON: {error}: {line}")
                })
            })
            .filter(|session: &serde_json::Value| session["id"] == PAUSE_SESSION)
            .collect();
        assert!(
            sessions.len() == 1 && sessions[0]["node"] == delta && sessions[0]["open"] == true,
            "APPARATUS: saved-pause read lost its exact open Session or owner: stdout {listed}; stderr {err}"
        );
        break sessions[0]["opened_millis"].as_u64().unwrap_or_else(|| {
            panic!("APPARATUS: exact Session listing omitted its opening: {listed}")
        });
    };
    let expected_opening = observe_session();
    let session_shown = loop {
        assert!(
            Instant::now() < pause_read_deadline,
            "APPARATUS: exact Session selection did not settle within the retained pause-read/convergence boundary"
        );
        assert_eq!(
            observe_session(),
            expected_opening,
            "APPARATUS: the staged Session reopened while selecting the saved pause read"
        );
        let (ok, session_out, session_err) = b.run(
            &[
                "room",
                "session",
                &room,
                PAUSE_SESSION,
                "--node",
                "delta",
                "--json",
            ],
            "",
        );
        // A changing published selection asks a person to select again. Only that exact
        // refusal can reobserve/reselect; no other failure gets an automatic retry or new clock.
        const SELECTION_CHANGED: &str = "the room's Sessions changed while selecting; try again";
        let refusal = session_err
            .trim()
            .strip_prefix("vox: ")
            .unwrap_or(session_err.trim());
        if !ok && session_out.trim().is_empty() && refusal == SELECTION_CHANGED {
            continue;
        }
        assert!(
            ok,
            "APPARATUS: delta's exact registered Session could not read the stale-pause room after reconciliation: stdout {session_out}; stderr {session_err}"
        );
        assert!(
            !session_out.trim().is_empty()
                && session_out.lines().filter(|line| !line.trim().is_empty()).all(|line| {
                    serde_json::from_str::<serde_json::Value>(line)
                        .is_ok_and(|row| row["line"].is_string() && row["kind"].is_string())
                }),
            "APPARATUS: exact Session activity was unavailable, so saved pause is unknown: stdout {session_out}; stderr {session_err}"
        );
        assert_eq!(
            observe_session(),
            expected_opening,
            "APPARATUS: saved pause was read across a replacement Session opening"
        );
        assert!(
            Instant::now() < pause_read_deadline,
            "APPARATUS: saved pause read completed after its retained read/convergence boundary"
        );
        break format!("{session_out}{session_err}");
    };
    assert!(
        !session_shown.contains("Pause status unknown:"),
        "APPARATUS: shipped `vox room session` could not establish the saved pause state after reconciliation: {session_shown}"
    );
    assert!(
        !session_shown.contains("Paused by "),
        "PRODUCT [FX28 stale-tick-authority]: after durable Computer policy moved while its exact admitted remote pause was held, shipped `vox room session` says the stale mutation was durably saved: {session_shown}"
    );
    println!(
        "[proof] shipped `vox room session` read the reconciled room's saved state and did not report the stale remote pause"
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

    epsilon
}

#[allow(clippy::too_many_arguments)]
fn stale_rekey_is_not_delivered(
    (a, _da): (&Account, &Daemon),
    (b, db): (&Account, Daemon),
    epsilon: &str,
    listen_b: &str,
    hold_spec: &str,
    stale_rekey_spec: &str,
    older_selected_spec: &str,
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
    let status = computer(b, &["status"]);
    let delta_ready = b.run(&["node", "list"], "").1.lines().any(|line| {
        line.split_whitespace().next() == Some("delta") && line.starts_with("delta Ready")
    });
    assert!(
        roster_current(&status, &["beta", "delta"]) && delta_ready,
        "PRODUCT: after the explicit later-event recovery, delta regressed before the final rekey-authority claim: ready {delta_ready}, status {status}"
    );
    // The remote-clock phase deliberately runs beta one hour ahead: larger than the rendezvous
    // board's documented five-minute future-date tolerance, so an absolute remote timestamp can
    // never masquerade as a causal Computer deadline. Exercise the resulting real join refusal
    // once. The board must reject delta's future-dated pre-join and the shipped command must name
    // that publication cause; it must not proceed without the authorization record and invent the
    // downstream `authenticator invalid` refusal which exposed this missing handoff.
    let room_id = make_room(a, "epsilon");
    let room = room_id.as_str();
    let (ok, link, err) = a.run(&["room", "link", room, "--node", "epsilon"], "");
    assert!(ok, "APPARATUS: link epsilon's rekey room: {err}");
    let full_room = full_room_id(&link, room);
    let (ok, out, err) = b.run(
        &[
            "room",
            "join",
            "--node",
            "delta",
            "--passphrase-file",
            "-",
            link.trim(),
        ],
        ROOM_PASS,
    );
    assert!(
        !ok
            && err.contains("timestamp is outside the board's accepted clock window")
            && err.contains("took no pre-join record")
            && !err.contains("authenticator invalid"),
        "PRODUCT [FX28 prejoin-refusal-cause]: a board which rejected delta's future-dated pre-join did not stop the join at that exact cause, or the shipped command blamed authentication instead: stdout {out}; stderr {err}"
    );
    println!(
        "[proof] the skewed daemon's shipped join stopped at its rejected pre-join publication and named the board's clock window, without inventing an authenticator failure"
    );

    // That deliberate remote-clock condition has now proved its claim and cannot stage an
    // unrelated room join by design. Restart the same scratch daemon on the same address without
    // the test-only clock step; current-version durable Computer state and both attached nodes
    // must survive. This is a causal phase boundary, not a retry of the refused join under the
    // same condition.
    let _skewed_daemon = db.stop();
    let rotate_after_post_arm = b.data.join(FX28_ROTATE_AFTER_POST_ARM);
    let rotate_after_post_result = rotate_after_post_arm.with_extension("result");
    let rotate_after_post_spec = rotate_after_post_arm.to_string_lossy().into_owned();
    let baseline_drained_arm = b.data.join("fx28-baseline-delivery-drained-arm");
    let baseline_drained_marker = baseline_drained_arm.with_extension("marker");
    let baseline_drained_spec = format!(
        "delta\t{}\t{}",
        baseline_drained_arm.display(),
        baseline_drained_marker.display()
    );
    for stale in [&rotate_after_post_arm, &rotate_after_post_result] {
        let _ = std::fs::remove_file(stale);
    }
    let restarted = Instant::now();
    let restart_deadline = restarted + RETURN_WITHIN;
    let mut db = Daemon::start(
        b,
        &["--node", "beta"],
        &[
            ("VOX_LISTEN", listen_b),
            ("VOX_TEST_HOLD_COMPUTER_POLICY", hold_spec),
            ("VOX_TEST_HOLD_REKEY_ENQUEUE", stale_rekey_spec),
            (
                "VOX_TEST_FX28_MARK_ENDED_UNANSWERED_FILE",
                older_selected_spec,
            ),
            (
                "VOX_TEST_FX28_MARK_DELIVERY_DRAINED_FILE",
                &baseline_drained_spec,
            ),
            ("VOX_TEST_FX28_ROTATE_AFTER_POST", &rotate_after_post_spec),
        ],
    );
    for name in ["beta", "delta"] {
        let ready = format!("{name} is Ready");
        db.expect_event_until(restart_deadline, &ready, |line| line.contains(&ready));
    }
    loop {
        let status = computer(b, &["status"]);
        let epsilon_grant = grant_words(b, "delta", epsilon);
        let shown = roster_current(&status, &["beta", "delta"])
            && status["state"] == "confirmed"
            && epsilon_grant.is_some();
        let observed_at = Instant::now();
        if shown {
            assert!(
                observed_at <= restart_deadline,
                "PRODUCT: beta's same durable Computer first returned current, confirmed and trusted only after the retained {RETURN_WITHIN:?} restart boundary: status {status}; delta's epsilon grant {epsilon_grant:?}"
            );
            break;
        }
        assert!(
            observed_at < restart_deadline,
            "PRODUCT: after ending the deliberate clock-skew phase, beta's same durable Computer did not return confirmed with beta/delta current and epsilon trusted inside the retained {RETURN_WITHIN:?} restart boundary: status {status}; delta's epsilon grant {epsilon_grant:?}\n{}",
            db.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = std::fs::remove_file(&baseline_drained_marker);
    std::fs::write(&baseline_drained_arm, format!("{epsilon}\t{full_room}\n"))
        .expect("APPARATUS: arm delta's exact baseline-delivery drain boundary");
    let (ok, out, err) = b.run(
        &[
            "room",
            "join",
            "--node",
            "delta",
            "--passphrase-file",
            "-",
            link.trim(),
        ],
        ROOM_PASS,
    );
    assert!(
        ok,
        "PRODUCT: with both daemons on their ordinary clocks and directly reachable, delta could not join epsilon's fresh rekey room: {out}{err}\nalpha daemon:\n{}\nbeta daemon:\n{}",
        _da.said(),
        db.said()
    );
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
    let baseline_drained = read_daemon_marker(
        &baseline_drained_marker,
        db.child.id(),
        "delta's exact baseline sender-key delivery to drain",
    );
    assert_eq!(
        baseline_drained.trim(),
        format!("delta\t{epsilon}\t{full_room}"),
        "APPARATUS: baseline-drain marker named another node, peer, or room"
    );
    // Select the compatibility route through the real protocol result which owns it. Epsilon's
    // test-only peer apparatus closes every exact modern delivery without an answer while armed,
    // faithfully emulating an older peer even if modern jobs overlap. Delta
    // atomically pauses that exact pair's automatic re-key and publishes the selected route; its
    // shipped roster must then say epsilon runs an older Vox. The target post below releases that
    // same still-owed key into the real long-lived-session preparation and durable-policy fence.
    let _ = std::fs::remove_file(older_marker);
    let _ = std::fs::remove_file(older_selected_marker);
    std::fs::write(older_arm, format!("{delta}\t{full_room}\n"))
        .expect("APPARATUS: arm epsilon's exact legacy-peer modern-delivery behavior");
    std::fs::write(older_selected_arm, format!("{epsilon}\t{full_room}\n"))
        .expect("APPARATUS: arm delta's exact ENDED_UNANSWERED route selection");
    std::fs::write(&rotate_after_post_arm, format!("delta\t{full_room}\n"))
        .expect("APPARATUS: arm the exact legacy-route sender-key rotation");
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
    let rotation = read_daemon_marker(
        &rotate_after_post_result,
        db.child.id(),
        "delta's exact forced sender-key rotation result",
    );
    assert!(
        rotation.trim().starts_with(&format!(
            "delta\t{full_room}\trotated=true\trelease_requested=false\treleased_paused=false\tcomplete_target_batches="
        )),
        "APPARATUS: the exact legacy-route staging post did not consume its arm and rotate: {rotation}"
    );
    let exact_older = read_daemon_marker(
        older_marker,
        _da.child.id(),
        "epsilon's exact modern delivery ended unanswered",
    );
    assert_eq!(
        exact_older.trim(),
        format!("epsilon\t{delta}\t{full_room}"),
        "APPARATUS: unanswered key-delivery marker named another node, sender, or room"
    );
    let exact_selection = read_daemon_marker(
        older_selected_marker,
        db.child.id(),
        "delta's exact ENDED_UNANSWERED route selection and re-key pause",
    );
    assert_eq!(
        exact_selection.trim(),
        format!("delta\t{epsilon}\t{full_room}"),
        "APPARATUS: ENDED_UNANSWERED route-selection marker named another node, peer, or room"
    );
    println!(
        "[proof] FX-28 legacy rekey route apparatus staged: epsilon ended delta's exact modern delivery unanswered and delta paused that pair's owed re-key"
    );
    let (ok, roster, roster_error) = b.run(&["room", "roster", room, "--node", "delta"], "");
    let roster_shown = format!("{roster}{roster_error}");
    assert!(
        ok && roster_shown.contains(epsilon) && roster_shown.contains("runs an older Vox"),
        "PRODUCT [FX28 legacy-rekey-route]: after delta admitted epsilon's exact unanswered modern delivery, its shipped roster did not expose the selected legacy sender-key route: {roster_shown}"
    );
    // Stage the protected ciphertext before holding this actor at key admission. A post marks
    // sync as owed, but sync runs on a later actor turn; holding within that same post would
    // prevent its payload from reaching epsilon at all. The shipped hash view includes sealed
    // entries even when their sender key is missing, so check this exact post, not a row count.
    let (ok, posted, err) = b.run(
        &[
            "room",
            "post",
            room,
            "STALE-AUTHORITY-REKEY",
            "--node",
            "delta",
            "--json",
        ],
        "",
    );
    assert!(
        ok,
        "APPARATUS: append the protected ciphertext while its key is paused: {posted}{err}"
    );
    let posted: serde_json::Value = serde_json::from_str(posted.trim())
        .expect("APPARATUS: protected post returned no structured receipt");
    let protected_hash = posted["entry_hash"]
        .as_str()
        .expect("APPARATUS: protected post receipt has no entry hash");
    assert!(
        wait_until(RETURN_WITHIN, || {
            let (ok, hashes, _) =
                a.run(&["room", "read", room, "--node", "epsilon", "--hashes"], "");
            ok && hashes
                .lines()
                .any(|line| line.split_whitespace().next() == Some(protected_hash))
        }),
        "APPARATUS: epsilon never held the exact protected ciphertext before sender revocation"
    );
    let (ok, unreadable, err) = a.run(&["room", "read", room, "--node", "epsilon"], "");
    assert!(ok && !unreadable.contains("STALE-AUTHORITY-REKEY"),
        "APPARATUS: the exact ciphertext was not staged unreadable while its key remained paused: {unreadable}{err}");
    println!("[proof] epsilon holds the exact protected post through shipped read --hashes, while its ordinary room read cannot display it without the paused sender key");
    let rekey_fault = rekey_decision.with_extension("fault");
    for stale in [rekey_engaged, rekey_decision, &rekey_fault] {
        let _ = std::fs::remove_file(stale);
    }
    std::fs::write(rekey_arm, format!("{epsilon}\t{full_room}\n"))
        .expect("APPARATUS: arm epsilon's exact stale rekey enqueue");
    std::fs::write(hold_arm, b"hold delta's revocation policy message\n")
        .expect("APPARATUS: arm delta's reconciliation behind the rekey decision");
    let _ = std::fs::remove_file(&rotate_after_post_result);
    std::fs::write(
        &rotate_after_post_arm,
        format!("delta\t{full_room}\trelease-paused\t{epsilon}\n"),
    )
    .expect("APPARATUS: arm the target post to release the exact paused sender-key delivery");
    let mut rotating_post = b
        .cmd(&[
            "room",
            "post",
            room,
            "RELEASE-STAGED-REKEY",
            "--node",
            "delta",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: start the shipped post whose key remains paused for epsilon");
    wait_for_command_marker(
        rekey_engaged,
        &mut rotating_post,
        db.child.id(),
        Instant::now() + RETURN_WITHIN,
        "epsilon's prepared sender-key batch at final queue admission",
    );
    let (read_ok, held_read, held_error) = a.run(&["room", "read", room, "--node", "epsilon"], "");
    assert!(
        read_ok && !held_read.contains("STALE-AUTHORITY-REKEY"),
        "APPARATUS: before revocation epsilon already exposed the protected text while its exact sender-key batch was held, or its room could not be read: {held_read}{held_error}"
    );
    let before = computer(b, &["status"])["revision"].as_u64().unwrap_or(0);
    let a_id = computer_id(a);
    let b_id = computer_id(b);
    let receiver_before = computer(a, &["status"]);
    let control_partition_arm = a.data.join(FX28_CONTROL_PARTITION_ARM);
    let control_partition_marker = control_partition_arm.with_extension("marker");
    std::fs::write(&control_partition_arm, &b_id)
        .expect("APPARATUS: stage only the recipient's exact computer-management path loss");
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
    let partitioned_peer = read_daemon_marker(
        &control_partition_marker,
        _da.child.id(),
        "the recipient refused the exact computer-management update before merging it",
    );
    assert_eq!(
        partitioned_peer, b_id,
        "APPARATUS: the management-path partition named a different computer peer"
    );
    let receiver_current = computer(a, &["status"]);
    assert!(
        receiver_before["state"] == "confirmed"
            && receiver_current["state"] == "confirmed"
            && receiver_current["revision"] == receiver_before["revision"]
            && grant_words(a, "epsilon", delta).is_some(),
        "APPARATUS: epsilon no longer trusts delta before the held sender-key batch is released, so receiver-side revocation would mask the sender-authority mutant; receiver computer status: {}",
        receiver_current
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
    let released = read_daemon_marker(
        &rotate_after_post_result,
        db.child.id(),
        "the target post's exact paused sender-key release",
    );
    assert!(
        released.trim().starts_with(&format!(
            "delta\t{full_room}\trotated=false\trelease_requested=true\treleased_paused=true\tcomplete_target_batches="
        )),
        "APPARATUS: the target post did not release the exact paused sender-key obligation: {released}"
    );
    let decision = read_daemon_marker(
        rekey_decision,
        db.child.id(),
        "the exact rekey authority decision",
    );
    let expected_batches = if decision.trim() == "enqueued" { 1 } else { 0 };
    assert!(
        released
            .trim()
            .ends_with(&format!("complete_target_batches={expected_batches}")),
        "APPARATUS: the exact legacy re-key boundary reported {decision:?} but its post-side result did not name the corresponding complete-batch count: {released}"
    );
    if decision.trim() == "enqueued" {
        assert!(
            wait_until(RETURN_WITHIN, || a
                .run(&["room", "read", room, "--node", "epsilon"], "")
                .1
                .contains("STALE-AUTHORITY-REKEY")),
            "APPARATUS: the mutant enqueued epsilon's exact key but the shipped recipient never exposed its delivery; receiver grant {:?}; receiver status {}; recipient daemon {}; sender daemon {}",
            grant_words(a, "epsilon", delta),
            computer(a, &["status"]),
            _da.said(),
            db.said()
        );
        assert!(
            grant_words(a, "epsilon", delta).is_some()
                && computer(a, &["status"])["revision"] == receiver_before["revision"],
            "APPARATUS: recipient management state moved during the isolated sender-revocation verdict"
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

/// One node whose actor queue is held remains attached but must not claim the new trust projection;
/// its healthy sibling applies the same revision inside the bound. The elapsed time is sampled
/// after both computer statuses and both nodes' shipped trust views and `vox node list`.
fn delayed_node_completes_without_another_policy_action(
    (a, da, nodes_a): (&Account, &Daemon, &[(&str, &str)]),
    (b, db, nodes_b): (&Account, &Daemon, &[(&str, &str)]),
    hold_arm: &Path,
    hold_engaged: &Path,
    hold_release: &Path,
    forward: &port_forward::PortForward,
) {
    let eta = a.make_node("eta");
    let delta = nodes_b
        .iter()
        .find_map(|(name, fingerprint)| (*name == "delta").then_some(*fingerprint))
        .expect("APPARATUS: delayed application has no delta node identity");
    let b_id = computer_id(b);
    let before_status_b = computer(b, &["status"]);
    let prior_miss = before_status_b["application_misses"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|record| record["node"] == delta)
        .cloned();
    let before_revision = computer(a, &["status"])["revision"].as_u64().unwrap_or(0);
    std::fs::write(hold_arm, b"hold delta's next policy message")
        .unwrap_or_else(|e| panic!("APPARATUS: could not stage the held delta marker: {e}"));
    forward.close();
    let changed = Instant::now();
    let (ok, out, err) = a.run(&["node", "attach", "eta", "--passphrase-file", "-"], PASS);
    assert!(ok, "APPARATUS: attach eta on alpha's computer: {out}{err}");
    let changed_revision = computer(a, &["status"])["revision"].as_u64().unwrap_or(0);
    let missed_visible_by = changed + RETURN_WITHIN + CHANGE_SHOWN_WITHIN;
    loop {
        let application = application_toward(a, &b_id);
        if application["missed_revision"].as_u64() == Some(changed_revision)
            && application["convergence_state"] == "expired"
        {
            break;
        }
        assert!(
            Instant::now() < missed_visible_by,
            "PRODUCT: after policy revision {changed_revision}'s {RETURN_WITHIN:?} remote \
             convergence deadline and the existing {CHANGE_SHOWN_WITHIN:?} local observation \
             contract, shipped status had not exposed its missed causal exchange: \
             {application}\n{}",
            da.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    forward.set_delay(Duration::from_secs(1));
    let restored = Instant::now();
    let return_deadline = restored + RETURN_WITHIN;
    // Start the retained product clock before the restoration action. The userspace round trip
    // only proves the apparatus precondition; it never resets or shortens that clock.
    let _verified = forward.open_and_verify();
    // Conservative lower bracket for exchange completion: the last instant sampled before a
    // shipped status observation which still did not name the carrying exchange.
    let mut last_not_carried_at = restored;
    let mut carried_bracket = None;

    let (held_deadline, held_policy_revision) = loop {
        let observation_started = Instant::now();
        let status_a = computer(a, &["status"]);
        let record = application_toward(a, &b_id)["last_started_exchange"].clone();
        let carried = changed_revision > before_revision
            && record["sent_revision"]
                .as_u64()
                .is_some_and(|revision| revision >= changed_revision);
        let carrying_observed_at = Instant::now();
        if carried && carrying_observed_at >= return_deadline {
            panic!(
                "PRODUCT: {RETURN_WITHIN:?} after path restoration began, shipped status first \
                 named an exchange carrying eta only after the retained remote-return boundary: {}\nalpha daemon:\n{}\nbeta daemon:\n{}",
                application_toward(a, &b_id),
                da.said(),
                db.said()
            );
        }
        if carried && carried_bracket.is_none() {
            carried_bracket = Some((last_not_carried_at, carrying_observed_at));
        }
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
        let delta_ready = delta_line.starts_with("delta Ready");
        let delta_grant = grant_words(b, "delta", &eta);
        let mut local_names: Vec<&str> = nodes_a.iter().map(|(name, _)| *name).collect();
        local_names.push("eta");
        let local_current = roster_current(&status_a, &local_names);
        let beta_current = roster_current(&status_b, &["beta"]);
        let alive = daemon_alive(da.child.id()) && daemon_alive(db.child.id());
        let shown = local_current
            && beta_current
            && beta_grant.is_some()
            && delta_ready
            && delta_grant.is_none()
            && alive;
        // All final status/trust/list observations are complete before this sample.
        let elapsed = restored.elapsed();
        if carried {
            let (completion_after, completion_before) = carried_bracket.unwrap();
            let green_deadline = (completion_after + CHANGE_SHOWN_WITHIN).min(return_deadline);
            let red_deadline = (completion_before + CHANGE_SHOWN_WITHIN).min(return_deadline);
            let held = hold_engaged.is_file();
            if shown && held {
                if Instant::now() <= green_deadline {
                    println!(
                        "[proof] {elapsed:?} after path restoration began, shipped status names eta carried; within the conservatively bracketed local {CHANGE_SHOWN_WITHIN:?} interval beta applied it on its healthy node, and held delta remains Ready without eta's new grant"
                    );
                    break (
                        green_deadline,
                        status_b["revision"]
                            .as_u64()
                            .expect("PRODUCT: held actor status has no policy revision"),
                    );
                }
                panic!(
                    "APPARATUS: the held-node state was first observed inside the polling ambiguity \
                     band between the carrying exchange's lower and upper completion bounds; no \
                     PRODUCT timing verdict is possible"
                );
            }
            if Instant::now() >= red_deadline {
                if !held {
                    panic!(
                        "APPARATUS: delta's exact computer-policy actor hold was not staged before the retained local application boundary"
                    );
                }
                panic!(
                    "PRODUCT: inside the retained return boundary, {CHANGE_SHOWN_WITHIN:?} after the \
                     conservative upper bracket for the completed exchange, beta's healthy node \
                     had not applied eta or held delta did not remain attached and fail closed \
                     (ADR-038 FX-28, #1020; shown {shown}; exchange was observed within {elapsed:?} \
                     of the restoration action): alpha bindings current {local_current}; beta \
                     binding current {beta_current}; beta's grant for eta {beta_grant:?}; delta \
                     line {delta_line:?}; delta's grant for eta {delta_grant:?}; daemons alive \
                     {alive}; alpha status nodes {}; beta status nodes {}\nalpha daemon:\n{}\nbeta daemon:\n{}",
                    status_a["nodes"],
                    status_b["nodes"],
                    da.said(),
                    db.said()
                );
            }
        } else {
            last_not_carried_at = observation_started;
            assert!(
                Instant::now() < return_deadline,
                "PRODUCT: {RETURN_WITHIN:?} after path restoration began, alpha \
                 completed no exchange carrying eta to beta: {}\nalpha daemon:\n{}\nbeta daemon:\n{}",
                application_toward(a, &b_id),
                da.said(),
                db.said()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // Wait for the shipped status to acknowledge this local observation miss. The apparatus
    // deliberately withholds the event; its release must not create a replacement policy action.
    // Keep the original path-restoration return boundary throughout this claim.
    let late_record = loop {
        assert!(
            hold_engaged.is_file() && daemon_alive(db.child.id()),
            "APPARATUS: delta's exact actor hold or its daemon disappeared before the local miss observation"
        );
        let status = computer(b, &["status"]);
        assert_eq!(
            status["revision"].as_u64(), Some(held_policy_revision),
            "APPARATUS: another policy superseded the exact held application before its miss could be judged: {status}"
        );
        let record = status["application_misses"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|record| {
                record["node"] == delta
                    && record["revision"].as_u64() == Some(held_policy_revision)
                    && prior_miss.as_ref() != Some(*record)
            })
            .cloned();
        if let Some(record) = record {
            assert!(
                hold_engaged.is_file(),
                "APPARATUS: delta's exact actor hold disappeared while reading its application miss"
            );
            assert!(
                status["pending_nodes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                    .any(|pending| pending.starts_with("delta:") && pending.contains("missed its local application boundary")),
                "PRODUCT [FX28 late-application]: delta's held late application was not reported as pending: {status}"
            );
            assert!(
                Instant::now() <= return_deadline,
                "PRODUCT [FX28 late-application]: delta's local application miss first became visible after the retained {RETURN_WITHIN:?} return boundary: {status}"
            );
            assert!(
                roster_current(&status, &["beta"])
                    && grant_words(b, "beta", &eta).is_some(),
                "PRODUCT [FX28 late-application]: holding delta prevented its healthy beta sibling from remaining current with eta's grant: {status}"
            );
            assert!(
                !roster_current(&status, &["delta"])
                    && grant_words(b, "delta", &eta).is_none(),
                "PRODUCT [FX28 late-application]: while its exact accepted event remained held, delta claimed the unapplied grant or current authority: {status}"
            );
            break record;
        }
        assert!(
            Instant::now() < return_deadline,
            "PRODUCT [FX28 late-application]: while its exact accepted event remained held, shipped status did not expose delta's local application miss by the retained {RETURN_WITHIN:?} return boundary: {status}"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    println!(
        "[proof] FX-28 late-application apparatus staged: delta remains attached and fail-closed while shipped status records its local observation miss {late_record}; releasing the accepted event causes no policy action"
    );
    std::os::unix::net::UnixStream::connect(hold_release).unwrap_or_else(|e| {
        panic!(
            "APPARATUS: could not release delta's held computer-policy actor at {}: {e}",
            hold_release.display()
        )
    });
    // This watchdog diagnoses only the apparatus release acknowledgement. Product recovery below
    // keeps the original return deadline, never a fresh five-second application clock.
    let cleanup_deadline = held_deadline.max(Instant::now()) + CHANGE_SHOWN_WITHIN;
    while hold_engaged.is_file() {
        assert!(
            Instant::now() < cleanup_deadline,
            "APPARATUS: delta's exact computer-policy actor hold did not clear after its release"
        );
        std::thread::yield_now();
    }
    forward.set_delay(Duration::ZERO);
    loop {
        let status = computer(b, &["status"]);
        let ready = b.run(&["node", "list"], "").1.lines().any(|line| {
            line.split_whitespace().next() == Some("delta") && line.starts_with("delta Ready")
        });
        let grant = grant_words(b, "delta", &eta);
        assert_eq!(
            status["revision"], late_record["revision"],
            "APPARATUS: another policy superseded the exact delayed application before its same-revision recovery could be judged: miss {late_record}, status {status}"
        );
        let current = roster_current(&status, &["beta", "delta"]);
        let pending = status["pending_nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .any(|pending| pending.starts_with("delta:"));
        let observed_at = Instant::now();
        // The status snapshot precedes the separate node/grant reads. A new grant can become
        // visible between them while this earlier snapshot still reports accepted work running.
        // Wait for the complete observed state; a partial observation is not a wedge verdict.
        if ready && current && grant.is_some() && !pending {
            assert!(
                observed_at <= return_deadline,
                "PRODUCT [FX28 late-application]: delta first became Ready/current with eta's grant only after the retained {RETURN_WITHIN:?} return boundary: {status}"
            );
            assert!(
                status["application_misses"]
                    .as_array()
                    .is_some_and(|records| records.contains(&late_record)),
                "PRODUCT [FX28 late-application]: completing the accepted late application erased its recorded miss: before {late_record}, after {status}"
            );
            break;
        }
        assert!(
            observed_at < return_deadline,
            "PRODUCT [FX28 late-application]: after releasing its accepted local application, delta did not become Ready/current with eta's grant inside the retained {RETURN_WITHIN:?} return boundary; no policy toggle, detach, unlock or restart was performed: ready {ready}, grant {grant:?}, status {status}\n{}",
            db.said()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    println!(
        "[proof] delta's accepted late application completed automatically: the same actor is Ready/current with eta's grant, pending cleared, and its historical miss retained; no policy toggle, detach, unlock or restart"
    );
}

fn daemon_alive(pid: u32) -> bool {
    let out = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not inspect daemon pid {pid}: {e}"));
    out.status.success() && !out.stdout.is_empty()
}
