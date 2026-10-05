//! ADR-026 F-1–F-3 (#399, V030-35 D1) — **a data root written by the previous release becomes
//! this build's nodes, each keeping its identity, its rooms and its settings**, through the
//! shipped binaries.
//!
//! **The scene.** [`PREVIOUS`] (`support/previous_release.rs`, its published binary checked
//! against its SHA-256) writes one data root as a person using it would have:
//! - `default`: a vault (`vox id`), whose daemon makes a room;
//! - `anchor`: a headless anchor (`vox node`), its key and its store;
//! - `both`: a vault (`vox id`) and, from a `vox node` run in the same profile, an anchor's key.
//!   v0.2.9's `vox node` refuses to run there ("another vox already has this node open") but
//!   writes the key first; which identity that key is, [`PREVIOUS`] itself says, run on a copy of
//!   the key alone in a data root of its own.
//!
//! Beside them, the account's settings file says `notify = off`, and `default` holds a `port`
//! file and a `node.sock` as a release from v0.2.10 leaves them (v0.2.9 wrote neither; the port is
//! one this proof found free).
//!
//! **What is asserted**, each as a person sees it (`PRODUCT:` otherwise), the layout last:
//! - the first command of this build (`vox id`) moves every profile under `nodes/`: `default`,
//!   `anchor`, `both`, and `both`'s anchor key into `both-anchor`; nothing is left where it was,
//!   the stale `node.sock` is gone, and `.daemon/port` holds `default`'s port;
//! - `vox id` says the same fingerprint for `default` and `both`;
//! - this build's daemon for `default` lists the room v0.2.9 made, and reads the account's
//!   `notify = off` (the node has no settings file of its own);
//! - this build's `vox node` says the same anchor fingerprint for `anchor` and for `both-anchor`.
//!
//! A second test meets the same data root with **this build's `vox daemon`** first (ADR-026 §10
//! proof 10, through the real daemon): it says it moved `default` and split `both`'s key, runs
//! `default` as v0.2.9's identity with its room listed, and the rest is asserted as above.
//!
//! The previous release failing to stage the scene is `CANNOT MEASURE`.
//!
//! **Mutation.** The migration moving only directories with a vault: `anchor` stays where it was,
//! this build's `vox node` makes a new key in `nodes/anchor`, and its fingerprint changes (red).

#![cfg(unix)]

#[path = "support/previous_release.rs"]
mod previous_release;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use previous_release::{previous_release, PREVIOUS};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "identity passphrase";
const ROOMPASS: &str = "the room passphrase";

/// One data root and its config directory.
#[derive(Clone)]
struct Root {
    data: PathBuf,
    cfg: PathBuf,
}

fn cmd(exe: &Path, root: &Root, profile: &str, argv: &[&str]) -> Command {
    let mut c = Command::new(exe);
    c.args(argv)
        .env("VOX_DATA_DIR", &root.data)
        .env("VOX_CONFIG_DIR", &root.cfg)
        .env("VOX_PROFILE", profile)
        // This build names a node by `VOX_NODE` (ADR-026 C-3); the previous release reads only
        // `VOX_PROFILE`.
        .env("VOX_NODE", profile)
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .env_remove("VOX_NOTIFY_COMMAND");
    c
}

/// A long-running process, killed and reaped by its own PID however the proof ends, with its
/// stdout and stderr collected.
struct Proc {
    name: String,
    child: Child,
    out: Arc<Mutex<Vec<String>>>,
}

impl Proc {
    fn start(exe: &Path, root: &Root, profile: &str, argv: &[&str]) -> Self {
        let name = format!("{} {profile} {argv:?}", exe.display());
        let mut child = cmd(exe, root, profile, argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: spawn {name}: {e}"));
        let out = Arc::new(Mutex::new(Vec::new()));
        for pipe in [
            Box::new(child.stdout.take().expect("APPARATUS: stdout"))
                as Box<dyn std::io::Read + Send>,
            Box::new(child.stderr.take().expect("APPARATUS: stderr")),
        ] {
            let lines = Arc::clone(&out);
            std::thread::spawn(move || {
                for l in BufReader::new(pipe).lines().map_while(Result::ok) {
                    lines.lock().unwrap().push(l);
                }
            });
        }
        Self { name, child, out }
    }

    /// The first line matching `pred` within a minute; a red labelled `side` otherwise.
    fn wait_for(&mut self, side: &str, what: &str, pred: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(l) = self.out.lock().unwrap().iter().find(|l| pred(l)) {
                return l.clone();
            }
            let exited = self.child.try_wait().ok().flatten().is_some();
            assert!(
                Instant::now() < deadline && !exited,
                "{side}: {} never said {what}{}; it said:\n{}",
                self.name,
                if exited { " (it exited)" } else { "" },
                self.said()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn said(&self) -> String {
        self.out.lock().unwrap().join("\n")
    }

    /// Stop it with SIGINT, as a person does, and wait until it is gone, so its files are let go.
    fn stop(mut self) -> String {
        let _ = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        self.said()
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A one-shot verb that must succeed (a red labelled `side` otherwise): its stdout, and its
/// stderr.
fn ok(
    side: &str,
    exe: &Path,
    root: &Root,
    profile: &str,
    argv: &[&str],
    stdin: &str,
) -> (String, String) {
    let mut child = cmd(exe, root, profile, argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: run vox {argv:?}: {e}"));
    child
        .stdin
        .take()
        .expect("APPARATUS: a piped stdin")
        .write_all(stdin.as_bytes())
        .expect("APPARATUS: write stdin");
    let out = child.wait_with_output().expect("APPARATUS: vox ran");
    let (o, e) = (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    );
    assert!(
        out.status.success(),
        "{side}: {} {argv:?} in profile {profile} failed: {o}{e}",
        exe.display()
    );
    (o, e)
}

/// The fingerprint `vox id` prints first.
fn fingerprint(side: &str, exe: &Path, root: &Root, profile: &str) -> String {
    ok(side, exe, root, profile, &["id"], "")
        .0
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// The identity a `vox node` says it runs as.
fn anchor_fingerprint(side: &str, exe: &Path, root: &Root, profile: &str) -> String {
    let mut n = Proc::start(exe, root, profile, &["node", "--listen", "127.0.0.1:0"]);
    let line = n.wait_for(side, "its identity", |l| {
        l.starts_with("vox node: identity ")
    });
    n.stop();
    line.trim_start_matches("vox node: identity ")
        .trim()
        .to_owned()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("APPARATUS: a free UDP port")
        .port()
}

/// Which command of this build meets the old data root first.
#[derive(Clone, Copy, PartialEq, Eq)]
enum First {
    /// `vox id`, a one-shot verb.
    Id,
    /// `vox daemon`, the account's daemon, which moves the data root under its lock at its start
    /// (ADR-026 F-3, ADR-026 §10 proof 10).
    Daemon,
}

#[test]
#[ignore = "fetches the previous release and runs real daemons with production Argon2id; run it in release"]
fn profiles_of_the_previous_release_become_nodes_keeping_identity_rooms_and_settings() {
    migrate(First::Id);
}

/// The same data root, met first by the account's daemon: it says what it moved, runs `default`
/// as itself with v0.2.9's room listed, and everything lands where the verb's move puts it.
/// Mutation: the daemon not moving the data root at its start (`migrate_held` skipped): `default`
/// is a new identity and the room is gone.
#[test]
#[ignore = "fetches the previous release and runs real daemons with production Argon2id; run it in release"]
fn the_daemon_moves_the_previous_releases_profiles_into_nodes() {
    migrate(First::Daemon);
}

fn migrate(first: First) {
    watchdog::arm();
    let old = previous_release();
    let new = Path::new(VOX);
    let tmp = tempfile::Builder::new()
        .prefix("lay")
        .tempdir_in("/tmp")
        .expect("APPARATUS: a temp dir");
    let root = Root {
        data: tmp.path().join("d"),
        cfg: tmp.path().join("cfg"),
    };
    std::fs::create_dir_all(&root.cfg).expect("APPARATUS: make the config directory");
    let pass = tmp.path().join("pass");
    std::fs::write(&pass, format!("{IDPASS}\n{ROOMPASS}\n")).expect("APPARATUS: passphrase file");
    let pass = pass.to_str().expect("APPARATUS: a UTF-8 path").to_owned();
    let stage = "CANNOT MEASURE (staging)";

    // ---- the previous release writes the data root ----
    let fp_default = fingerprint(stage, &old, &root, "default");
    let mut d = Proc::start(
        &old,
        &root,
        "default",
        &[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            &pass,
        ],
    );
    d.wait_for(stage, "its control socket", |l| {
        l.contains("control socket")
    });
    // v0.2.9 reads a piped room passphrase unasked.
    ok(
        stage,
        &old,
        &root,
        "default",
        &["room", "create", "--name", "r"],
        &format!("{ROOMPASS}\n"),
    );
    let room = ok(stage, &old, &root, "default", &["room", "list"], "")
        .0
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("{stage}: {PREVIOUS} lists no room"))
        .to_owned();
    d.stop();
    let fp_anchor = anchor_fingerprint(stage, &old, &root, "anchor");
    let fp_both = fingerprint(stage, &old, &root, "both");
    // v0.2.9's `vox node` in a profile with a vault writes its key, then refuses to run.
    let b = Proc::start(&old, &root, "both", &["node", "--listen", "127.0.0.1:0"]);
    let key = root.data.join("both").join("node-identity.key");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !key.is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(500));
    b.stop();
    assert!(
        key.is_file(),
        "{stage}: {PREVIOUS}'s `vox node` wrote no key in `both`"
    );
    // Which identity that key is, as the previous release says, from a copy of the key alone.
    let probe = Root {
        data: tmp.path().join("probe"),
        cfg: tmp.path().join("probe-cfg"),
    };
    std::fs::create_dir_all(probe.data.join("p")).expect("APPARATUS: probe directory");
    std::fs::copy(&key, probe.data.join("p").join("node-identity.key"))
        .expect("APPARATUS: copy the key");
    let fp_both_anchor = anchor_fingerprint(stage, &old, &probe, "p");
    // What a v0.2.10 leaves beside a profile, and the account's setting.
    let port = free_udp_port();
    std::fs::write(root.data.join("default").join("port"), format!("{port}\n"))
        .expect("APPARATUS: write the port file");
    std::fs::write(root.data.join("default").join("node.sock"), b"")
        .expect("APPARATUS: write a stale socket file");
    std::fs::write(root.cfg.join("config"), "notify = off\n").expect("APPARATUS: write settings");
    for p in ["default", "anchor", "both"] {
        assert!(
            root.data.join(p).is_dir(),
            "{stage}: {PREVIOUS} made no profile {p}"
        );
    }
    println!(
        "[proof] {PREVIOUS} wrote default {fp_default} (room {room}), anchor {fp_anchor}, both \
         {fp_both} with anchor key {fp_both_anchor}"
    );

    // ---- this build, first command: the data root moves ----
    if first == First::Id {
        let (said, moved) = ok("PRODUCT", new, &root, "default", &["id"], "");
        println!("[proof] this build's first `vox id` said:\n{moved}");
        // Each move said once (#399): one line per directory, never two.
        let told = |what: &str| moved.lines().filter(|l| l.contains(what)).count();
        for (what, name) in [
            ("/default to ", "default"),
            ("/anchor to ", "anchor"),
            ("/both to ", "both"),
        ] {
            assert_eq!(
                told(what),
                1,
                "PRODUCT: `vox id` must say once that it moved {name}; it said:\n{moved}"
            );
        }
        assert_eq!(
            told("anchor key is now node both-anchor"),
            1,
            "PRODUCT: `vox id` must say once that both's anchor key became a node; it said:\n{moved}"
        );
        let got = said.lines().next().unwrap_or_default().trim().to_owned();
        assert_eq!(
            got, fp_default,
            "PRODUCT: default's fingerprint changed across the move"
        );
    }

    // ---- its rooms and the account's settings ----
    let mut d = Proc::start(
        new,
        &root,
        "default",
        &[
            "daemon",
            "--node",
            "default",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            &pass,
        ],
    );
    // The node is attached once the daemon says its identity: since ADR-026 the account's
    // control socket is announced before the foreground node attaches.
    d.wait_for("PRODUCT", "its identity", |l| {
        l.starts_with("vox daemon: identity ")
    });
    let rooms = ok("PRODUCT", new, &root, "default", &["room", "list"], "").0;
    let notify = d.wait_for("PRODUCT", "that notifications are off", |l| {
        l.contains("notifications off")
    });
    if first == First::Daemon {
        // The daemon met the old layout first: it moved it, said so, and runs `default` as the
        // identity v0.2.9 made.
        let ran_as = d.wait_for("PRODUCT", "its identity", |l| {
            l.starts_with("vox daemon: identity ")
        });
        let moved = d.wait_for("PRODUCT", "that it moved default", |l| {
            l.starts_with("vox daemon: moved ") && l.ends_with("to node default")
        });
        let split = d.wait_for("PRODUCT", "that both's anchor key became a node", |l| {
            l.contains("node both's anchor key is now node both-anchor")
        });
        println!("[proof] the daemon said: {moved} / {split} / {ran_as}");
        // Each move said once (#399): by the daemon, in its words, not a second time beside it.
        let all = d.said();
        let count = |pred: &dyn Fn(&str) -> bool| all.lines().filter(|l| pred(l)).count();
        let moves_of_default = count(&|l| l.contains("moved ") && l.contains("default"));
        let splits = count(&|l| l.contains("anchor key is now node both-anchor"));
        assert!(
            moves_of_default == 1 && splits == 1,
            "PRODUCT: every move must be said once; the daemon said the move of default \
             {moves_of_default} times and the split of both {splits} times:\n{all}"
        );
        assert_eq!(
            ran_as.trim_start_matches("vox daemon: identity ").trim(),
            fp_default,
            "PRODUCT: the daemon runs default as another identity than v0.2.9 made:\n{}",
            d.said()
        );
    }
    d.stop();
    assert_eq!(
        fingerprint("PRODUCT", new, &root, "both"),
        fp_both,
        "PRODUCT: both's vault fingerprint changed across the move"
    );
    println!("[proof] this build's daemon lists:\n{rooms}\nand says: {notify}");
    assert!(
        rooms.contains(&room),
        "PRODUCT: the room {PREVIOUS} made ({room}) is not listed after the move:\n{rooms}"
    );
    assert!(
        notify.contains(&root.cfg.join("config").display().to_string()),
        "PRODUCT: the node, with no settings file of its own, must read the account's: {notify}"
    );

    // ---- the anchors ----
    let now_anchor = anchor_fingerprint("PRODUCT", new, &root, "anchor");
    let now_both_anchor = anchor_fingerprint("PRODUCT", new, &root, "both-anchor");
    println!("[proof] this build's anchors: anchor {now_anchor}, both-anchor {now_both_anchor}");
    assert_eq!(
        now_anchor, fp_anchor,
        "PRODUCT: the anchor's fingerprint changed across the move — its --anchor spec no \
         longer names it"
    );
    assert_eq!(
        now_both_anchor, fp_both_anchor,
        "PRODUCT: both's anchor key, split into both-anchor, is another identity"
    );

    // ---- where everything now is ----
    let nodes = root.data.join("nodes");
    for (node, file) in [
        ("default", "vault.cbor"),
        ("default", "store.redb"),
        ("anchor", "node-identity.key"),
        ("both", "vault.cbor"),
        ("both-anchor", "node-identity.key"),
    ] {
        assert!(
            nodes.join(node).join(file).is_file(),
            "PRODUCT: after the move, nodes/{node}/{file} is missing; the data root holds:\n{}",
            listing(&root.data)
        );
    }
    for gone in [
        root.data.join("default"),
        root.data.join("anchor"),
        root.data.join("both"),
        nodes.join("both").join("node-identity.key"),
        nodes.join("default").join("node.sock"),
    ] {
        assert!(
            !gone.exists(),
            "PRODUCT: {} is still there after the move; the data root holds:\n{}",
            gone.display(),
            listing(&root.data)
        );
    }
    let daemon_port =
        std::fs::read_to_string(root.data.join(".daemon").join("port")).unwrap_or_default();
    assert_eq!(
        daemon_port.trim(),
        port.to_string(),
        "PRODUCT: .daemon/port must hold the port default bound ({port})"
    );
}

fn listing(dir: &Path) -> String {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                out.push(p.strip_prefix(dir).unwrap_or(&p).display().to_string());
                if p.is_dir() {
                    stack.push(p);
                }
            }
        }
    }
    out.sort();
    out.join("\n")
}
