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

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use vox_core::node::computer::{
    COMPUTER_CHANGE_SHOWN_WITHIN as CHANGE_SHOWN_WITHIN,
    COMPUTER_QUIET_EXCHANGE_AFTER as FALLBACK_NAMED, COMPUTER_RETURN_SHOWN_WITHIN as RETURN_WITHIN,
};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const PASS: &str = "identity passphrase";
const ROOM_PASS: &str = "room passphrase for the daemon proof";

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
            .unwrap();
        let data = tmp.path().join("d");
        let cfg = tmp.path().join("c");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::create_dir_all(tmp.path().join("home")).unwrap();
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
        let mut child = cmd
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

    /// Wait for a condition that only establishes this proof's process/network setup.
    fn expect_apparatus(&self, what: &str, within: Duration, f: impl Fn(&str) -> bool) {
        assert!(
            wait_until(within, || self.said().lines().any(&f)),
            "APPARATUS: the daemon never said {what}:\n{}",
            self.said()
        );
    }

    fn stop(mut self) -> String {
        stop_pid(self.child.id());
        let _ = self.child.wait();
        self.said()
    }
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

/// CT-11, CT-9 and FX-28: two installations on opposite address families pair through a public
/// anchor. With the remote daemon and anchor gone there is no retained computer connection; two
/// local policy revisions overlap the failed exchange. The remote daemon returns while the anchor
/// remains gone, then only the remote anchor returns. Both revisions still cross within the first
/// revision's causal return contract. The split-family staging makes direct packets impossible
/// without firewall/root.
///
/// Independent mutants: removing the stale-flight deadline handoff makes the first revision's
/// deadline move; requiring a retained peer connection strands the repair; discarding failed
/// transport work means the remote anchor's return never causes registration. Each reaches the
/// final PRODUCT roster assertion, while inability to stage the in-flight first exchange is
/// APPARATUS.
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn computer_pairing_uses_an_anchor_without_room_membership_and_reconnects() {
    watchdog::arm();
    let anchor = Account::new();
    let a = Account::new();
    let b = Account::new();
    let start_anchor = |listen: &str| {
        let out = anchor.data.with_extension("anchor.out");
        let f = std::fs::File::create(&out).expect("APPARATUS: anchor transcript");
        let child = anchor
            .cmd(&["node", "--listen", listen, "--serve", "anyone"])
            .stdin(Stdio::null())
            .stdout(f.try_clone().unwrap())
            .stderr(f)
            .spawn()
            .expect("APPARATUS: start scratch anchor");
        let process = Daemon { child, out };
        process.expect_apparatus("its advertised anchor address", RETURN_WITHIN, |line| {
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
    let (fp, addr) = spec.split_once('@').unwrap();
    let port = addr.rsplit('/').next().unwrap();
    let v4 = format!("{fp}@/ip4/127.0.0.1/udp/{port}");
    let v6 = format!("{fp}@/ip6/::1/udp/{port}");
    let anchor_listen = format!("[::]:{port}");
    let start = |account: &Account, listen: &str, anchor: &str| {
        let daemon = Daemon::start(
            account,
            &["--no-node", "--listen", listen, "--anchor", anchor],
            &[],
        );
        daemon.expect_apparatus("its control socket", RETURN_WITHIN, |line| {
            line.contains("control socket")
        });
        daemon
    };
    let mut left = start(&a, "127.0.0.1:0", &v4);
    let mut right = start(&b, "[::1]:0", &v6);
    let invitation = computer(&a, &["invite"]);
    let link = invitation["invite_link"]
        .as_str()
        .expect("PRODUCT: node-free computer invitation missing");
    let preview = computer(&b, &["pair", link, "--preview"]);
    let op = preview["pairing"]["operation_id"].as_str().unwrap();
    computer(&a, &["approve", op]);
    computer(&b, &["approve", op]);
    assert!(wait_until(RETURN_WITHIN, || computer(&a, &["status"])["state"] == "confirmed" && computer(&b, &["status"])["state"] == "confirmed"), "PRODUCT: two computers with only an anchor path did not confirm their pairing: {}; {}; anchor: {}", computer(&a, &["status"]), computer(&b, &["status"]), relay.said());
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
    let _bob = b.make_node("after-remote-anchor-b");
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
    assert!(
        wait_until(RETURN_WITHIN, || computer(&a, &["status"])["state"]
            == "confirmed"
            && computer(&b, &["status"])["state"] == "confirmed"),
        "PRODUCT: the remote observer's policy revision did not settle before the outage: {}; {}",
        computer(&a, &["status"]),
        computer(&b, &["status"])
    );

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
    right = start(&b, "[::1]:0", &v6);

    let b_id = computer_id(&b);
    let before = application_toward(&a, &b_id);
    let attempts_before = before["exchange_attempts"].as_u64().unwrap_or(0);
    let failures_before = before["exchange_failures"].as_u64().unwrap_or(0);
    let revision_before = computer(&a, &["status"])["revision"].as_u64().unwrap_or(0);
    let first = a.make_node("anchor-return-first");
    let second = a.make_node("anchor-return-second");
    let first_changed = Instant::now();
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
    assert!(ok, "APPARATUS: attach the first outage node: {out}{err}");
    assert!(
        wait_until(CHANGE_SHOWN_WITHIN, || {
            let toward = application_toward(&a, &b_id);
            computer(&a, &["status"])["revision"]
                .as_u64()
                .is_some_and(|revision| revision > revision_before)
                && toward["exchange_attempts"]
                    .as_u64()
                    .is_some_and(|attempts| attempts > attempts_before)
                && toward["exchange_failures"].as_u64() == Some(failures_before)
        }),
        "APPARATUS: the first revision was not observed in an in-flight exchange before it could be superseded: before {before}; after {}",
        application_toward(&a, &b_id)
    );
    let first_revision = computer(&a, &["status"])["revision"].as_u64().unwrap_or(0);
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
        "APPARATUS: attach the superseding outage node: {out}{err}"
    );
    assert!(
        wait_until(CHANGE_SHOWN_WITHIN, || computer(&a, &["status"])["revision"]
            .as_u64()
            .is_some_and(|revision| revision > first_revision)),
        "APPARATUS: the second attached node did not create a later policy revision than {first_revision}: {}",
        computer(&a, &["status"])
    );

    // No local command, daemon restart or network transition follows: the anchor process alone
    // returns. Failed registration is durable work and must cause its own retry.
    relay = start_anchor(&anchor_listen);
    let converged = wait_until(RETURN_WITHIN, || {
        let (_, trust, _) = b.run(&["trust", "list", "--node", "after-remote-anchor-b"], "");
        let status = computer(&b, &["status"]);
        let names_both = status["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|node| node["name"] == "anchor-return-first")
            && status["nodes"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|node| node["name"] == "anchor-return-second");
        trust.contains(&first)
            && trust.contains(&second)
            && names_both
            && computer(&a, &["status"])["state"] == "confirmed"
            && status["state"] == "confirmed"
    });
    let returned_after = first_changed.elapsed();
    assert!(
        converged && returned_after <= RETURN_WITHIN,
        "PRODUCT: after only the remote anchor returned, the computer with no retained connection did not show both superseding policy revisions within the first revision's {RETURN_WITHIN:?} causal deadline (observed after {returned_after:?}); left: {}; right: {}; anchor: {}",
        computer(&a, &["status"]),
        computer(&b, &["status"]),
        relay.said()
    );
    println!(
        "[proof] after {returned_after:?}, remote-anchor-only recovery carried both revisions through a new peer connection before the first revision's {RETURN_WITHIN:?} deadline"
    );

    // Persistence remains part of the same journey: restart both managers and the anchor, then
    // read the exact already-applied identities rather than manufacturing a fresh revision.
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
    left = start(&a, "127.0.0.1:0", &v4);
    right = start(&b, "[::1]:0", &v6);
    assert!(wait_until(RETURN_WITHIN, || b.run(&["trust", "list", "--node", "after-remote-anchor-b"], "").1.contains(&first) && b.run(&["trust", "list", "--node", "after-remote-anchor-b"], "").1.contains(&second)), "PRODUCT: the exact recovered roster did not survive all three process restarts; left: {}; right: {}; anchor: {}", a.log(), b.log(), relay.said());
    for (account, node) in [(&a, "anchor-return-first"), (&b, "after-remote-anchor-b")] {
        let (ok, out, err) = account.run(&["room", "list", "--node", node], "");
        assert!(
            ok && out.trim() == "no rooms",
            "PRODUCT: computer transport introduced a room: {out}{err}"
        );
    }
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

/// How long two paired computers sit idle while their exchanges are counted.
const PAIRED_IDLE: Duration = Duration::from_secs(60);
/// Exchanges a computer may run with a peer over [`PAIRED_IDLE`] when nothing changed: the
/// fallback one (every 60 s) and the one that may straddle the window's start.
const IDLE_EXCHANGES: u64 = 1;
/// How often the idle minute samples each side's status for a new dated exchange.
const SAMPLE_EVERY: Duration = Duration::from_secs(5);
/// CPU time a daemon may spend over [`PAIRED_IDLE`] with nothing to settle: the quiet bound of
/// a paired computer (ADR-038 FX-15, FX-28).
const IDLE_CPU: Duration = Duration::from_secs(3);
/// **Two paired computers follow each other's changes and are idle otherwise** (ADR-038 FX-15,
/// FX-28; #989, #1020): alpha and beta, two data roots with a daemon each, pair as computers
/// (`vox computer invite`, `pair --preview`, `approve` on both) and both report `confirmed`.
///
/// A change made on either shows on both: gamma is made and attached on alpha's computer, and
/// within [`CHANGE_SHOWN_WITHIN`] of the attach alpha's `vox computer status` names gamma with
/// every binding derived at the policy revision the change made and every node there trusting
/// every node of both computers (`vox trust list`); within [`CHANGE_SHOWN_WITHIN`] of the
/// exchange alpha's daemon started for beta that sent that revision completing (the status
/// names it), beta's status names gamma under alpha's computer with every binding there derived
/// at beta's new revision, and every node there trusts every node of both computers. Then
/// delta is attached on beta's computer and the same holds the other way. Both confirm each
/// other again each time.
///
/// A restart derives nothing: beta's daemon is stopped and started again on the same port with
/// nothing changed, and every binding there shows the same policy revision and the same derived
/// moment as before.
///
/// A change made while the computers' only userspace path is closed arrives when that path is
/// opened, with both daemon PIDs alive throughout. Within [`RETURN_WITHIN`] of
/// the open, after every final status and trust observation finishes, beta shows gamma personal,
/// every binding current and every expected keyring grant, and both computers confirmed. The
/// exported broader [`RETURN_WITHIN`] contract still names a peer that must reconnect.
///
/// Over [`PAIRED_IDLE`] of nothing changing, with four nodes hosted, each side's `vox computer
/// status --json` MUST count at most [`IDLE_EXCHANGES`] more exchanges with the other and name
/// when the last one was, every node's binding MUST stand derived at the current policy
/// revision at the same moment as before the minute (nothing was derived again), and each
/// daemon's CPU time MUST grow by at most [`IDLE_CPU`]. Measured before this (2026-10-20, the
/// decider's work Mac): the pairing manager exchanged the whole signed history with every
/// computer every 2 s and re-verified it, 47–95% of a core while nothing changed; and a 1 s tick
/// re-derived every attached node's binding (an ML-DSA verification of every management event)
/// with nothing changed, 21–24% of the busy CPU of a daemon idling at 0.63 of a core.
/// Finally, a test-only held actor message keeps delta queued for 15 s while epsilon attaches.
/// Within [`CHANGE_SHOWN_WITHIN`], after all final observations finish, beta has applied epsilon
/// on its healthy node and `vox node list` shows delta no longer attached. Cleanup may continue;
/// queued room/node work cannot turn a late observation into an apparent pass.
///
/// Independent mutants: (1) remove the need filter in `Management::retry`: the idle
/// exchange-attempt count turns PRODUCT red (unchanged means no network); (2) remove the
/// `computer_current` short circuit: the binding-derived moments turn PRODUCT red (unchanged
/// means no re-derive); (3) discard the remote merge before publishing its change: the remote
/// roster/keyring claim turns PRODUCT red; (4) suppress the authenticated reachability wake:
/// the saturated-backoff live heal misses [`RETURN_WITHIN`] and turns PRODUCT red; (5) give
/// reconciliation a fresh timeout or delay `Detaching`: held delta remains Ready past
/// [`CHANGE_SHOWN_WITHIN`] and turns PRODUCT red; (6) serialize siblings behind held delta:
/// beta's binding/keyring claim misses that same bound and turns PRODUCT red; (7) remove the
/// attachment-generation checks: the old delayed result detaches replacement delta and turns
/// PRODUCT red; (8) restore actor-tick policy application and bypass its current-revision guard:
/// the idle binding-derived moments move and turn PRODUCT red. The stuck-node phase begins behind
/// saturated backoff, so resetting either exchange or apply clocks turns its return bound red.
#[test]
#[ignore = "five minutes of two real vox daemons paired as computers; run in release"]
fn two_paired_computers_that_are_idle_exchange_nothing() {
    test_knobs::require(&[
        "VOX_TEST_ADVERTISE",
        "VOX_TEST_HOLD_COMPUTER_POLICY",
        "VOX_TEST_HOLD_COMPUTER_POLICY_REPLY",
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
    let hold_marker = b.data.join("hold-delta-computer-policy");
    let hold_spec = format!("delta\t15000\t{}", hold_marker.display());
    let reply_marker = b.data.join("hold-delta-computer-policy-reply");
    let reply_spec = format!("delta\t15000\t{}", reply_marker.display());
    let da = Daemon::start(
        &a,
        &["--node", "alpha"],
        &[
            ("VOX_LISTEN", &listen_a),
            ("VOX_TEST_ADVERTISE", &advertised),
        ],
    );
    let db = Daemon::start(
        &b,
        &["--node", "beta"],
        &[
            ("VOX_LISTEN", &listen_b),
            ("VOX_TEST_HOLD_COMPUTER_POLICY", &hold_spec),
            ("VOX_TEST_HOLD_COMPUTER_POLICY_REPLY", &reply_spec),
        ],
    );
    // Each node is Ready before it is chosen as its computer's personal node.
    da.expect("node alpha is Ready", Duration::from_secs(90), |l| {
        l.contains("alpha is Ready")
    });
    db.expect("node beta is Ready", Duration::from_secs(90), |l| {
        l.contains("beta is Ready")
    });
    assert!(
        wait_until(RETURN_WITHIN, || {
            a.run(&["computer", "status", "--json"], "").0
                && b.run(&["computer", "status", "--json"], "").0
        }),
        "APPARATUS: a daemon never answered `vox computer status` while staging the paired-computer journey:\n{}\n{}",
        da.said(),
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
    computer(&b, &["approve", &operation]);
    computer(&a, &["approve", &operation]);
    assert!(
        wait_until(Duration::from_secs(90), || {
            computer(&a, &["status"])["state"] == "confirmed"
                && computer(&b, &["status"])["state"] == "confirmed"
        }),
        "PRODUCT: the two computers never both reached `confirmed`: alpha {}, beta {}\n{}\n{}",
        computer(&a, &["status"])["state"],
        computer(&b, &["status"])["state"],
        da.said(),
        db.said()
    );

    // ---- a change on either daemon shows on both (ADR-038 FX-28; #1020) ------------------
    let gamma = a.make_node("gamma");
    let nodes_a = [("alpha", alpha.as_str()), ("gamma", gamma.as_str())];
    change_shows_on_both(
        (&a, &da, &nodes_a),
        (&b, &db, &[("beta", beta.as_str())]),
        "gamma",
    );
    let delta = b.make_node("delta");
    let nodes_b = [("beta", beta.as_str()), ("delta", delta.as_str())];
    change_shows_on_both((&b, &db, &nodes_b), (&a, &da, &nodes_a), "delta");

    // ---- a restart derives nothing: each binding's (revision, when) survives it -----------
    let db = a_restart_derives_nothing(
        (&a, &da),
        (&b, db, &nodes_b, &listen_b, &hold_spec, &reply_spec),
    );

    // ---- a stale reconciliation cannot detach a replacement attachment -------------------
    replacement_generation_survives((&a, &da), (&b, &db), &reply_marker);

    // ---- both live daemons converge when their userspace path is restored -----------------
    change_reaches_a_live_computer((&a, &da, &nodes_a), (&b, &db, &nodes_b), &forward);

    // Let the confirmation's own exchanges settle before the idle minute is counted.
    std::thread::sleep(Duration::from_secs(10));
    // What `vox computer status --json` shows: the sum of `exchanges` over the computers listed,
    // the latest `last_exchange_ms`, whether every one is confirmed, and the listing itself for a
    // red to quote.
    let exchanges = |acct: &Account| -> (u64, u64, Option<u64>, bool, String) {
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
        )
    };
    let (ea0, aa0, last_a0, _, shown_a0) = exchanges(&a);
    let (eb0, ab0, last_b0, _, shown_b0) = exchanges(&b);
    // Every binding stands derived at the current policy revision before the minute, and the
    // moment it was derived must not move during it: nothing is derived with nothing changed.
    let derived0 = (
        bindings_shown(&computer(&a, &["status"])),
        bindings_shown(&computer(&b, &["status"])),
    );
    for (who, nodes, (revision, shown)) in [
        ("alpha", ["alpha", "gamma"], &derived0.0),
        ("beta", ["beta", "delta"], &derived0.1),
    ] {
        for node in nodes {
            assert!(
                shown.get(node).is_some_and(|(at, _)| *at == Some(*revision)),
                "PRODUCT: before the idle minute {who}'s `vox computer status` does not show {node}'s \
                 binding derived at its policy revision {revision} (ADR-038 FX-28): {shown:?}"
            );
        }
    }
    let cpu0 = (cpu_time(da.child.id()), cpu_time(db.child.id()));
    // Every SAMPLE_EVERY, each side's dated last exchange: a new one must be at least the
    // fallback after the one before it, or the round had no need the status names.
    let mut dated: Vec<Vec<u64>> =
        vec![last_a0.into_iter().collect(), last_b0.into_iter().collect()];
    let idle_from = Instant::now();
    while idle_from.elapsed() < PAIRED_IDLE {
        std::thread::sleep(SAMPLE_EVERY.min(PAIRED_IDLE.saturating_sub(idle_from.elapsed())));
        for (i, acct) in [&a, &b].into_iter().enumerate() {
            if let (_, _, Some(last), _, _) = exchanges(acct) {
                if dated[i].last() != Some(&last) {
                    dated[i].push(last);
                }
            }
        }
    }
    for (who, times) in [("alpha", &dated[0]), ("beta", &dated[1])] {
        for pair in times.windows(2) {
            let gap = pair[1].saturating_sub(pair[0]);
            assert!(
                gap >= FALLBACK_NAMED.as_millis() as u64,
                "PRODUCT: {who} exchanged {} s after its previous exchange with nothing to say \
                 (ADR-038 FX-15, #989): a quiet computer is exchanged with only every {FALLBACK_NAMED:?}; \
                 its dated exchanges: {times:?}",
                gap / 1000
            );
        }
    }
    let (ea1, aa1, last_a, confirmed_a, shown_a1) = exchanges(&a);
    let (eb1, ab1, last_b, confirmed_b, shown_b1) = exchanges(&b);
    let cpu1 = (cpu_time(da.child.id()), cpu_time(db.child.id()));
    let derived1 = (
        bindings_shown(&computer(&a, &["status"])),
        bindings_shown(&computer(&b, &["status"])),
    );
    let spent = (cpu1.0.saturating_sub(cpu0.0), cpu1.1.saturating_sub(cpu0.1));
    // The count is "since the daemon started" and the daemons ran throughout: it never shrinks.
    let grew = |before: u64, after: u64, who: &str, shown0: &str, shown1: &str| -> u64 {
        after.checked_sub(before).unwrap_or_else(|| {
            panic!(
                "PRODUCT: {who}'s `vox computer status` exchange count went backwards over the \
                 idle minute, from {before} to {after}; it showed {shown0} before and {shown1} after"
            )
        })
    };
    let during_a = grew(ea0, ea1, "alpha", &shown_a0, &shown_a1);
    let during_b = grew(eb0, eb1, "beta", &shown_b0, &shown_b1);
    // Every round counted from its start, completed or not: the idle minute allows one per
    // computer, so a failed round and its retry (two) are red even when a later success hides
    // the failure from the completed count. Starts and completions are not equated: an
    // exchange in flight at either sample would make them differ for no fault.
    let tried_a = grew(aa0, aa1, "alpha", &shown_a0, &shown_a1);
    let tried_b = grew(ab0, ab1, "beta", &shown_b0, &shown_b1);
    assert!(
        tried_a <= IDLE_EXCHANGES && tried_b <= IDLE_EXCHANGES,
        "PRODUCT: idle computers started rounds beyond the fallback (a failed round and its retry are two) (ADR-038 FX-15, #989): \
         alpha {tried_a} attempt(s) for {during_a} exchange(s), beta {tried_b} for {during_b} over {PAIRED_IDLE:?} (at most {IDLE_EXCHANGES} each)\n{shown_a1}\n{shown_b1}"
    );
    println!(
        "[proof] over {PAIRED_IDLE:?} idle with four nodes hosted: alpha exchanged {during_a} time(s) with beta (last at {last_a:?}, confirmed {confirmed_a}), beta {during_b} with alpha (last at {last_b:?}, confirmed {confirmed_b}); bindings: alpha's computer at policy revision {} {:?}, beta's at {} {:?}, derived again during the minute: {}; CPU: alpha's daemon +{:?}, beta's +{:?} (bound {IDLE_CPU:?})",
        derived1.0 .0,
        derived1.0 .1,
        derived1.1 .0,
        derived1.1 .1,
        derived0 != derived1,
        spent.0,
        spent.1
    );
    // Nothing was derived again: every binding names the same revision and the same moment as
    // before the minute, and that revision is still the policy's.
    for (who, (revision0, before), (revision1, after)) in [
        ("alpha", &derived0.0, &derived1.0),
        ("beta", &derived0.1, &derived1.1),
    ] {
        assert!(
            revision0 == revision1 && before == after,
            "PRODUCT: {who}'s computer derived a node's binding again with nothing changed \
             (ADR-038 FX-28, #1020): before the idle minute policy revision {revision0}, bindings \
             (revision, derived at ms) {before:?}; after it revision {revision1}, {after:?}"
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
    assert!(
        during_a <= IDLE_EXCHANGES && during_b <= IDLE_EXCHANGES,
        "PRODUCT: idle computers kept exchanging state (ADR-038 FX-15, #989): alpha {} and beta {} exchanges over {PAIRED_IDLE:?} (at most {IDLE_EXCHANGES} each)\n{}\n{}",
        during_a,
        during_b,
        da.said(),
        db.said()
    );
    assert!(
        spent.0 <= IDLE_CPU && spent.1 <= IDLE_CPU,
        "PRODUCT: idle paired computers spent CPU (ADR-038 FX-15, FX-28; #989, #1020): alpha's daemon +{:?}, beta's +{:?} over {PAIRED_IDLE:?} (bound {IDLE_CPU:?})",
        spent.0,
        spent.1
    );

    // ---- one queued node applies or becomes non-attached without a late apparent pass -------
    delayed_node_does_not_make_a_late_pass(
        (&a, &da, &nodes_a),
        (&b, &db, &nodes_b),
        &hold_marker,
        &forward,
    );
}

/// Unix milliseconds now, the clock `vox computer status` dates exchanges and bindings with.
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
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
/// every node there trusts every node of both computers. Within [`CHANGE_SHOWN_WITHIN`] of the
/// exchange the changer's daemon started for the other that sent that revision completing (the
/// changer's status names it), the other's status lists the new node under the changer's
/// computer with every binding of its own derived at its new revision, and every node there
/// trusts every node of both computers. Then both computers confirm each other again.
fn change_shows_on_both(
    (changer, changer_daemon, here): (&Account, &Daemon, &[(&str, &str)]),
    (other, other_daemon, there): (&Account, &Daemon, &[(&str, &str)]),
    new_node: &str,
) {
    let changer_id = computer_id(changer);
    let other_id = computer_id(other);
    let all: Vec<(&str, &str)> = here.iter().chain(there).copied().collect();
    let names_here: Vec<&str> = here.iter().map(|(n, _)| *n).collect();
    let names_there: Vec<&str> = there.iter().map(|(n, _)| *n).collect();
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
        if shown && elapsed <= CHANGE_SHOWN_WITHIN {
            break status;
        }
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
    // On the other daemon: the change travels in an exchange the changer's daemon starts for
    // it, the one its status names as started with that revision sent. Its completion is dated
    // by the changer's status; the showing by this proof's clock.
    let started = Instant::now();
    let mut exchanged: Option<u64> = None;
    let mut shown_there: Option<u64> = None;
    loop {
        if exchanged.is_none() {
            let toward = application_toward(changer, &other_id);
            let record = &toward["last_started_exchange"];
            if record["sent_revision"]
                .as_u64()
                .is_some_and(|r| r >= revision_here)
            {
                exchanged = record["at_ms"].as_u64();
            }
        }
        if shown_there.is_none() {
            let status = computer(other, &["status"]);
            let names_it = status["nodes"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|n| n["name"] == new_node && n["computer"] == changer_id.as_str());
            if names_it
                && roster_current(&status, &names_there)
                && keyrings_complete(other, there, &all).is_ok()
            {
                shown_there = Some(unix_ms());
            }
        }
        if let (Some(at), Some(seen)) = (exchanged, shown_there) {
            assert!(
                seen <= at + CHANGE_SHOWN_WITHIN.as_millis() as u64,
                "PRODUCT: {}'s computer showed {new_node} applied {} ms after the exchange that \
                 carried it completed (ADR-038 FX-28, #1020; at most {CHANGE_SHOWN_WITHIN:?})",
                names_there[0],
                seen.saturating_sub(at)
            );
            println!(
                "[proof] {new_node} shown applied on {}'s computer {} ms after the exchange {}'s daemon started with revision {revision_here} sent completed (bound {CHANGE_SHOWN_WITHIN:?})",
                names_there[0],
                seen as i64 - at as i64,
                names_here[0]
            );
            break;
        }
        if let Some(at) = exchanged {
            let status = computer(other, &["status"]);
            assert!(
                unix_ms() <= at + CHANGE_SHOWN_WITHIN.as_millis() as u64,
                "PRODUCT: {CHANGE_SHOWN_WITHIN:?} after the exchange {}'s daemon started for {}'s \
                 with revision {revision_here} sent completed, {}'s `vox computer status` does not \
                 show the change applied (ADR-038 FX-28, #1020): it should list {new_node} under \
                 {}'s computer with {names_there:?} derived at its policy revision, and every node \
                 there should trust every node of both computers; status: revision {} nodes {}; \
                 keyrings: {}\nits daemon said: {}",
                names_here[0],
                names_there[0],
                names_there[0],
                names_here[0],
                status["revision"],
                status["nodes"],
                keyrings_complete(other, there, &all)
                    .err()
                    .unwrap_or_else(|| "complete".into()),
                other_daemon.said()
            );
        }
        assert!(
            started.elapsed() < RETURN_WITHIN,
            "APPARATUS: within {RETURN_WITHIN:?} of {new_node} attaching, {}'s daemon \
             completed no exchange it started toward {}'s computer with revision {revision_here} \
             sent: {}\nits daemon said: {}",
            names_here[0],
            names_there[0],
            application_toward(changer, &other_id),
            changer_daemon.said()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // Both confirm each other again: the other's receipt for the new state comes back.
    assert!(
        wait_until(RETURN_WITHIN, || {
            computer(changer, &["status"])["state"] == "confirmed"
                && computer(other, &["status"])["state"] == "confirmed"
        }),
        "PRODUCT: after {new_node} attached on {}'s computer the two computers did not both \
         confirm again within {RETURN_WITHIN:?}: {}'s {}, {}'s {}\n{}\n{}",
        names_here[0],
        names_here[0],
        computer(changer, &["status"])["state"],
        names_there[0],
        computer(other, &["status"])["state"],
        changer_daemon.said(),
        other_daemon.said()
    );
}

/// A UDP port nothing holds right now, for a daemon to listen on for the whole proof.
fn free_v6_udp_port() -> u16 {
    std::net::UdpSocket::bind("[::1]:0")
        .and_then(|socket| socket.local_addr())
        .map(|addr| addr.port())
        .unwrap_or_else(|e| panic!("APPARATUS: no free UDP port on [::1]: {e}"))
}

/// **A restart derives nothing** (ADR-038 FX-28; #1020): with nothing changed, beta's daemon
/// is stopped and started again on the same port, its two nodes come back Ready, and its
/// `vox computer status` shows every binding at the same policy revision and the same derived
/// moment as before the restart: the record survived, and nothing was derived again. Both
/// computers confirm each other again (staging). Returns beta's new daemon.
fn a_restart_derives_nothing(
    (a, da): (&Account, &Daemon),
    (b, db, nodes_b, listen_b, hold_spec, reply_spec): (
        &Account,
        Daemon,
        &[(&str, &str)],
        &str,
        &str,
        &str,
    ),
) -> Daemon {
    let names_b: Vec<&str> = nodes_b.iter().map(|(n, _)| *n).collect();
    let before = bindings_shown(&computer(b, &["status"]));
    assert!(
        roster_current(&computer(b, &["status"]), &names_b),
        "APPARATUS: before the restart beta's bindings are not all current: {before:?}"
    );
    let _stopped_said = db.stop();
    let restarted = Instant::now();
    let db = Daemon::start(
        b,
        &["--node", "beta"],
        &[
            ("VOX_LISTEN", listen_b),
            ("VOX_TEST_HOLD_COMPUTER_POLICY", hold_spec),
            ("VOX_TEST_HOLD_COMPUTER_POLICY_REPLY", reply_spec),
        ],
    );
    db.expect("node beta is Ready", RETURN_WITHIN, |l| {
        l.contains("beta is Ready")
    });
    db.expect("node delta is Ready", RETURN_WITHIN, |l| {
        l.contains("delta is Ready")
    });
    let after = bindings_shown(&computer(b, &["status"]));
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
        "[proof] {:?} after beta's daemon was restarted with nothing changed, both nodes are Ready and every binding stands at policy revision {} with the same derived moment as before: {:?}",
        restarted.elapsed(),
        after.0,
        after.1
    );
    assert!(
        wait_until(RETURN_WITHIN, || {
            computer(a, &["status"])["state"] == "confirmed"
                && computer(b, &["status"])["state"] == "confirmed"
        }),
        "PRODUCT: after beta's daemon restarted the two computers did not both confirm again \
         within {RETURN_WITHIN:?}: alpha's {}, beta's {}\n{}\n{}",
        computer(a, &["status"])["state"],
        computer(b, &["status"])["state"],
        da.said(),
        db.said()
    );
    db
}

/// A reconciliation result belongs to one attachment generation. The old delta actor applies a
/// change but its reply is held while a person detaches and re-attaches delta. When the old
/// five-second waiter expires, the replacement must remain Ready and current.
fn replacement_generation_survives(
    (a, da): (&Account, &Daemon),
    (b, db): (&Account, &Daemon),
    reply_marker: &Path,
) {
    let zeta = a.make_node("zeta");
    std::fs::write(reply_marker, b"hold the old generation's reply")
        .unwrap_or_else(|e| panic!("APPARATUS: could not stage delayed old-generation reply: {e}"));
    let (ok, out, err) = a.run(&["node", "attach", "zeta", "--passphrase-file", "-"], PASS);
    assert!(
        ok,
        "APPARATUS: attach zeta to stage replacement race: {out}{err}"
    );
    assert!(
        wait_until(RETURN_WITHIN, || !reply_marker.is_file()),
        "APPARATUS: delta's old actor never accepted the policy event whose reply was to be held\n{}\n{}",
        da.said(),
        db.said()
    );
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
}

/// **A change made across a failed live path arrives on its authenticated restoration** (ADR-038
/// FX-28; #1020). The userspace forward is the pair's only path. It closes while both daemons
/// stay alive; gamma becomes alpha's personal node and alpha reaches six failed exchanges,
/// saturating its ordinary backoff. Opening that same path lets the one retained authenticated
/// wake stream land. The forward adds three seconds each way so a mutant that waits out that
/// saturated backoff cannot squeeze a late exchange under the return bound. Only after beta's final
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
    assert!(
        wait_until(RETURN_WITHIN.saturating_mul(2), || {
            application_toward(a, &b_id)["exchange_failures"]
                .as_u64()
                .is_some_and(|n| n >= 6)
        }),
        "APPARATUS: with the live path closed, alpha's `vox computer status` counted no \
         sixth failed exchange toward it within {:?}: {}\nits daemon said: {}",
        RETURN_WITHIN.saturating_mul(2),
        application_toward(a, &b_id),
        da.said()
    );
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

    // Opening the only path is the restoration event. The clock is not sampled until every final
    // product observation below has returned.
    forward.set_delay(Duration::from_secs(3));
    let restored = Instant::now();
    forward.open();
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

/// One node whose actor queue is held must be visibly non-attached within FX-28's five seconds;
/// its healthy sibling applies the same revision inside that bound. The elapsed time is sampled
/// after both computer statuses, the sibling's shipped `vox trust list`, and `vox node list`.
fn delayed_node_does_not_make_a_late_pass(
    (a, da, _nodes_a): (&Account, &Daemon, &[(&str, &str)]),
    (b, db, _nodes_b): (&Account, &Daemon, &[(&str, &str)]),
    hold_marker: &Path,
    forward: &port_forward::PortForward,
) {
    let epsilon = a.make_node("epsilon");
    let b_id = computer_id(b);
    let before_revision = computer(a, &["status"])["revision"].as_u64().unwrap_or(0);
    std::fs::write(hold_marker, b"hold delta's next policy message")
        .unwrap_or_else(|e| panic!("APPARATUS: could not stage the held delta marker: {e}"));
    forward.close();
    let (ok, out, err) = a.run(
        &["node", "attach", "epsilon", "--passphrase-file", "-"],
        PASS,
    );
    assert!(
        ok,
        "APPARATUS: attach epsilon on alpha's computer: {out}{err}"
    );
    assert!(
        wait_until(RETURN_WITHIN.saturating_mul(2), || {
            application_toward(a, &b_id)["exchange_failures"]
                .as_u64()
                .is_some_and(|n| n >= 6)
        }),
        "APPARATUS: the closed path did not saturate exchange backoff before the stuck-apply heal: {}\n{}",
        application_toward(a, &b_id),
        da.said()
    );
    forward.set_delay(Duration::from_secs(3));
    let restored = Instant::now();
    forward.open();

    let mut carried_at = None;
    loop {
        let status_a = computer(a, &["status"]);
        if carried_at.is_none()
            && status_a["revision"]
                .as_u64()
                .is_some_and(|revision| revision > before_revision)
        {
            let sent_revision = status_a["revision"].as_u64().unwrap_or(0);
            let record = application_toward(a, &b_id)["last_started_exchange"].clone();
            if record["sent_revision"]
                .as_u64()
                .is_some_and(|revision| revision >= sent_revision)
            {
                carried_at = record["at_ms"].as_u64();
            }
        }
        let status_b = computer(b, &["status"]);
        let beta_grant = grant_words(b, "beta", &epsilon);
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
        let local_current = roster_current(&status_a, &["alpha", "gamma", "epsilon"]);
        let beta_current = roster_current(&status_b, &["beta"]);
        let alive = daemon_alive(da.child.id()) && daemon_alive(db.child.id());
        let shown =
            local_current && beta_current && beta_grant.is_some() && delta_non_attached && alive;
        // All final status/trust/list observations are complete before this sample.
        let seen = unix_ms();
        if let Some(at) = carried_at {
            let elapsed = Duration::from_millis(seen.saturating_sub(at));
            let returned = restored.elapsed();
            if shown && elapsed <= CHANGE_SHOWN_WITHIN && returned <= RETURN_WITHIN {
                println!(
                    "[proof] after {returned:?} from saturated-backoff heal and {elapsed:?} from exchange, beta applied epsilon on its healthy node and lists held delta non-attached ({delta_line:?}); bounds {RETURN_WITHIN:?}/{CHANGE_SHOWN_WITHIN:?}"
                );
                break;
            }
            assert!(
                !shown && elapsed < CHANGE_SHOWN_WITHIN && returned < RETURN_WITHIN,
                "PRODUCT: {CHANGE_SHOWN_WITHIN:?} after the exchange carrying epsilon completed, \
                 beta did not apply-or-detach every attached node (ADR-038 FX-28, #1020; shown \
                 {shown} only after {elapsed:?} from exchange/{returned:?} from heal): alpha bindings current {local_current}; beta \
                 binding current {beta_current}; beta's grant for epsilon {beta_grant:?}; delta \
                 line {delta_line:?}; daemons alive {alive}; alpha status nodes {}; beta status nodes {}\nalpha \
                 daemon:\n{}\nbeta daemon:\n{}",
                status_a["nodes"],
                status_b["nodes"],
                da.said(),
                db.said()
            );
        } else {
            assert!(
                restored.elapsed() < RETURN_WITHIN,
                "APPARATUS: alpha completed no exchange carrying epsilon to beta within \
                 {RETURN_WITHIN:?}: {}\nalpha daemon:\n{}\nbeta daemon:\n{}",
                application_toward(a, &b_id),
                da.said(),
                db.said()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
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

/// A process's CPU time so far, as Activity Monitor shows it (`ps -o cputime`).
fn cpu_time(pid: u32) -> Duration {
    let out = Command::new("ps")
        .args(["-o", "cputime=", "-p", &pid.to_string()])
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: ps: {e}"));
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    // `[[HH:]MM:]SS.ss`; anything else is an apparatus fault, never a zero that reads as cheap.
    let parts: Vec<f64> = text
        .split(':')
        .map(|s| {
            s.parse().unwrap_or_else(|_| {
                panic!("APPARATUS: `ps -o cputime= -p {pid}` printed {text:?}, not a CPU time")
            })
        })
        .collect();
    assert!(
        (1..=3).contains(&parts.len()),
        "APPARATUS: `ps -o cputime= -p {pid}` printed {text:?}, not a CPU time"
    );
    let secs = parts.iter().fold(0.0, |acc, part| acc * 60.0 + part);
    Duration::from_secs_f64(secs)
}
