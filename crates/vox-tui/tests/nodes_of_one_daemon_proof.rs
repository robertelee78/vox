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

#[path = "support/attach.rs"]
mod unlock_staging;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/layout.rs"]
mod layout;

#[path = "support/typed.rs"]
mod typed;

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

impl Drop for Account {
    /// A daemon a client started for this account (no child of this proof) is stopped by the pid
    /// in its lock, however the proof ends.
    fn drop(&mut self) {
        layout::reap_daemon(&self.data);
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
        c.args(crate::unlock_staging::persistent_args(
            &self.data, args, PASS,
        ))
        .env(
            "VOX_TEST_KEYCHAIN",
            crate::unlock_staging::keychain(&self.data),
        )
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
    if let Some(pid) = layout::daemon_pid(&account.data) {
        stop_pid(pid);
    }
    if layout::daemon_pid(&account.data).is_some() {
        eprintln!("APPARATUS: {label} did not release its lock after SIGTERM; staging a scratch host loss. Daemon log: {}",account.log());
        layout::kill_daemon(&account.data);
    }
    assert!(
        layout::daemon_pid(&account.data).is_none(),
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

/// CT-11 and CT-9: two zero-node installations on opposite address families pair through a
/// public anchor, then still exchange approved roster changes after all three daemons restart.
/// The existing split-family staging makes direct packets impossible without firewall/root.
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
        process.expect(
            "its advertised anchor address",
            Duration::from_secs(30),
            |line| line.contains('@') && line.contains("/udp/"),
        );
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
        daemon.expect("its control socket", Duration::from_secs(30), |line| {
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
    assert!(wait_until(Duration::from_secs(60), || computer(&a, &["status"])["state"] == "confirmed" && computer(&b, &["status"])["state"] == "confirmed"), "PRODUCT: two computers with only an anchor path did not confirm their pairing: {}; {}; anchor: {}", computer(&a, &["status"]), computer(&b, &["status"]), relay.said());
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
    // Restart both managers and the anchor: ephemeral relay registrations are gone. An actual
    // new managed node, not a cached status receipt, demonstrates re-registration/reconnection.
    stop_pid(a.lock_pid().expect("APPARATUS: left scratch daemon"));
    stop_pid(b.lock_pid().expect("APPARATUS: right scratch daemon"));
    stop_pid(anchor.lock_pid().expect("APPARATUS: scratch anchor daemon"));
    let _ = left.child.wait();
    let _ = right.child.wait();
    let _ = relay.child.wait();
    relay = start_anchor(&anchor_listen);
    left = start(&a, "127.0.0.1:0", &v4);
    right = start(&b, "[::1]:0", &v6);
    let alice = a.make_node("after-restart-a");
    let bob = b.make_node("after-restart-b");
    for (account, name) in [(&a, "after-restart-a"), (&b, "after-restart-b")] {
        let (ok, out, err) = account.run(&["node", "attach", name, "--passphrase-file", "-"], PASS);
        assert!(
            ok,
            "PRODUCT: post-restart managed node could not attach: {out}{err}"
        );
    }
    assert!(wait_until(Duration::from_secs(60), || a.run(&["trust", "list", "--node", "after-restart-a"], "").1.contains(&bob) && b.run(&["trust", "list", "--node", "after-restart-b"], "").1.contains(&alice)), "PRODUCT: computer trust roster did not cross the anchor after all three daemons restarted; left: {}; right: {}; anchor: {}", a.log(), b.log(), relay.said());
    assert!(
        wait_until(Duration::from_secs(30), || computer(&a, &["status"])
            ["state"]
            == "confirmed"
            && computer(&b, &["status"])["state"] == "confirmed"),
        "PRODUCT: restarted computers did not acknowledge the newly applied roster"
    );
    for (account, node) in [(&a, "after-restart-a"), (&b, "after-restart-b")] {
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
