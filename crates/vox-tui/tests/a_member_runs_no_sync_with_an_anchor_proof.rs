//! ADR-023 RL-6.1, RL-6.2 (#75) — a member runs no sync session with an anchor that is not a
//! member: the anchor holds nothing for the room, so every such session is refused. Until this
//! was fixed every member opened one on each connection to the anchor and each sync tick, and
//! printed it as `sync of room … with <anchor> did not complete — the peer refused: epoch
//! mismatch`. Driven through the shipped `vox` binary, as a person types it:
//!
//! ```text
//! vox node --listen 127.0.0.1:0                                   (data root N: the anchor)
//! vox node create alice; vox serve web=<echo> --anchor <N> …      (data root A)
//! vox node create bob; vox connect <address> --anchor <N> …; vox node attach bob   (root B)
//! vox trust add … (alice and bob trust each other); vox room post … (bob)
//! vox status --json (alice, bob)
//! ```
//!
//! The claim: once both members are connected to the anchor and have completed a session with
//! each other, neither status has a sync row for the anchor that opened a session, and neither
//! printed a sync with it. Mutant: the room's anchors counted again in `may_sync`, red as
//! `PRODUCT: alice opened a sync session with the anchor`.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/typed.rs"]
mod typed;

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// A child `vox`, killed by its own PID when dropped.
struct Kid(Child);

impl Drop for Kid {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Stops the daemon of a data root by the pid it writes in its lock, when dropped, and waits for
/// it to go (never by a pattern).
struct Reaper(PathBuf);

impl Drop for Reaper {
    fn drop(&mut self) {
        let Some(pid) = std::fs::read_to_string(self.0.join(".daemon").join("lock"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
        else {
            return;
        };
        let _ = Command::new("kill").arg(pid.to_string()).status();
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline
            && Command::new("kill")
                .args(["-0", &pid.to_string()])
                .status()
                .is_ok_and(|s| s.success())
        {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    }
}

/// One data root, holding one node of the same name.
struct Root {
    dir: PathBuf,
    node: &'static str,
}

impl Root {
    fn new(base: &Path, node: &'static str) -> Self {
        let dir = base.join(node);
        std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: harness file I/O");
        std::fs::write(
            dir.join("id.pass"),
            format!("{node}'s identity passphrase\n"),
        )
        .expect("APPARATUS: harness file I/O");
        Self { dir, node }
    }

    fn pass(&self) -> String {
        self.dir.join("id.pass").to_string_lossy().into_owned()
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(VOX);
        cmd.args(args)
            .env("VOX_DATA_DIR", &self.dir)
            .env("VOX_CONFIG_DIR", self.dir.join("cfg"))
            .env("VOX_NODE", self.node)
            .env_remove("VOX_NODE")
            .env_remove("VOX_IDENTITY_PASSPHRASE")
            .env_remove("VOX_ANCHORS")
            .env_remove("VOX_LISTEN");
        cmd
    }

    /// Run `vox args` that must succeed; its stdout. `side` labels a failure.
    fn ok(&self, side: &str, args: &[&str]) -> String {
        let mut cmd = self.cmd(args);
        // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028 K-13).
        if typed::is_keyring_change(args) {
            let (ok, shown) = typed::keyring(&cmd);
            assert!(ok, "{side} `vox {}` failed:\n{shown}", args.join(" "));
            return shown;
        }
        let out = cmd
            .stdin(Stdio::null())
            .output()
            .expect("APPARATUS: run vox");
        assert!(
            out.status.success(),
            "{side} `vox {}` failed:\n{}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Start a long-running `vox args`, its stdout and stderr both in `<tag>.log`.
    fn spawn(&self, tag: &str, args: &[&str]) -> Kid {
        let log = std::fs::File::create(self.dir.join(format!("{tag}.log")))
            .expect("APPARATUS: harness file I/O");
        let err = log.try_clone().expect("APPARATUS: harness file I/O");
        Kid(self
            .cmd(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("APPARATUS: spawn vox"))
    }

    fn said(&self, tag: &str) -> String {
        std::fs::read_to_string(self.dir.join(format!("{tag}.log"))).unwrap_or_default()
    }

    /// The first line of `<tag>.log` that, trimmed, starts with `needle` (or holds it, for a
    /// needle starting `@`), waiting up to `within`.
    fn line(&self, tag: &str, needle: &str, within: Duration, side: &str) -> String {
        let deadline = Instant::now() + within;
        let hit = |l: &str| {
            if needle.starts_with('@') {
                l.contains(needle)
            } else {
                l.trim_start().starts_with(needle)
            }
        };
        loop {
            if let Some(l) = self.said(tag).lines().find(|l| hit(l)) {
                return l.trim().to_owned();
            }
            assert!(
                Instant::now() < deadline,
                "{side} no line holding {needle:?} within {within:?}:\n{}",
                self.said(tag)
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// `vox status --json`'s `"sync"` rows.
    fn sync_rows(&self) -> Vec<serde_json::Value> {
        let json = self.ok("PRODUCT:", &["status", "--json"]);
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("PRODUCT: vox status --json is not JSON");
        v["sync"].as_array().cloned().unwrap_or_default()
    }

    /// Wait until `vox node list` shows this root's node attached.
    fn attached(&self, side: &str) {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let out = self.ok(side, &["node", "list"]);
            if out
                .lines()
                .any(|l| l.split_whitespace().take(2).eq([self.node, "attached"]))
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{side} node {} never showed attached:\n{out}",
                self.node
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// A TCP echo service on loopback: its port.
fn echo_service() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("APPARATUS: bind the echo service");
    let port = l.local_addr().expect("APPARATUS: echo address").port();
    std::thread::spawn(move || {
        for s in l.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// The row for `peer` among `rows`, if there is one.
fn row<'a>(rows: &'a [serde_json::Value], peer: &str) -> Option<&'a serde_json::Value> {
    rows.iter().find(|r| r["peer"].as_str() == Some(peer))
}

#[test]
#[ignore = "real vox daemons and production Argon2id; run on demand in release"]
fn a_member_runs_no_sync_session_with_an_anchor_that_is_not_a_member() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let anchor = Root::new(tmp.path(), "anchor");
    let alice = Root::new(tmp.path(), "alice");
    let bob = Root::new(tmp.path(), "bob");

    // ---- the anchor: its own process, holding no room -------------------------------------
    let _anchor = anchor.spawn("anchor", &["node", "--listen", "127.0.0.1:0"]);
    let anchor_line = anchor.line(
        "anchor",
        "@/ip4/",
        Duration::from_secs(120),
        "PRODUCT (staging): vox node printed no address:",
    );
    let anchor_fp = anchor_line.split('@').next().unwrap_or_default().to_owned();

    // ---- alice serves a room that names the anchor -----------------------------------------
    let fp = |root: &Root| {
        root.ok(
            "PRODUCT (staging):",
            &[
                "node",
                "create",
                root.node,
                "--passphrase-file",
                &root.pass(),
            ],
        )
        .lines()
        .last()
        .unwrap_or_default()
        .trim()
        .to_owned()
    };
    let (alice_fp, bob_fp) = (fp(&alice), fp(&bob));
    assert!(
        anchor_fp.len() == 52 && alice_fp.len() == 52 && bob_fp.len() == 52,
        "PRODUCT (staging): three fingerprints: {anchor_fp} {alice_fp} {bob_fp}"
    );
    let _alice_daemon = Reaper(alice.dir.clone());
    let _bob_daemon = Reaper(bob.dir.clone());
    let spec = format!("web={}", echo_service());
    let _serve = alice.spawn(
        "serve",
        &[
            "serve",
            &spec,
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            &anchor_line,
            "--identity-passphrase-file",
            &alice.pass(),
        ],
    );
    let address = alice
        .line(
            "serve",
            "address ",
            Duration::from_secs(180),
            "PRODUCT (staging): vox serve printed no address:",
        )
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let passphrase = alice
        .line(
            "serve",
            "passphrase ",
            Duration::from_secs(10),
            "PRODUCT (staging):",
        )
        .split_once(' ')
        .map(|(_, p)| p.trim().to_owned())
        .unwrap_or_default();
    let room_pass = bob.dir.join("room.pass");
    std::fs::write(&room_pass, format!("{passphrase}\n")).expect("APPARATUS: harness file I/O");

    // ---- bob joins through the same anchor, and they trust each other ----------------------
    bob.ok(
        "PRODUCT (staging):",
        &[
            "connect",
            &address,
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            &anchor_line,
            "--passphrase-file",
            room_pass.to_str().unwrap(),
            "--identity-passphrase-file",
            &bob.pass(),
        ],
    );
    bob.ok(
        "PRODUCT (staging):",
        &["node", "attach", "bob", "--passphrase-file", &bob.pass()],
    );
    bob.attached("PRODUCT (staging):");
    for (root, who, name) in [(&alice, &bob_fp, "bob"), (&bob, &alice_fp, "alice")] {
        root.ok(
            "PRODUCT (staging):",
            &[
                "trust",
                "add",
                who,
                "--name",
                name,
                "--identity-passphrase-file",
                &root.pass(),
            ],
        );
    }
    let room = address
        .trim_start_matches("vox://")
        .split('?')
        .next()
        .unwrap_or_default()
        .to_owned();
    bob.ok("PRODUCT (staging):", &["room", "post", &room, "from bob"]);

    // ---- premise: both members are on the anchor, and have synced with each other ---------
    anchor.line(
        "anchor",
        "vox node: 2 peer(s) connected",
        Duration::from_secs(60),
        "CANNOT MEASURE: the anchor never had both members connected:",
    );
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let done = |root: &Root, peer: &str| {
            row(&root.sync_rows(), peer)
                .and_then(|r| r["completed"].as_u64())
                .unwrap_or(0)
                > 0
        };
        if done(&alice, &bob_fp) && done(&bob, &alice_fp) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: alice and bob never completed a sync with each other: alice {:?}, \
             bob {:?}",
            alice.sync_rows(),
            bob.sync_rows()
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // Past the moments a session with the anchor used to start: each connection, each join, and
    // the next sync tick.
    std::thread::sleep(Duration::from_secs(20));

    // ---- the claim ------------------------------------------------------------------------
    for (root, who) in [(&alice, "alice"), (&bob, "bob")] {
        let rows = root.sync_rows();
        println!("[proof] {who}'s sync rows: {rows:?}");
        if let Some(r) = row(&rows, &anchor_fp) {
            assert!(
                r["opened"].as_u64().unwrap_or(0) == 0,
                "PRODUCT: {who} opened a sync session with the anchor, which holds nothing for the \
                 room (ADR-023 RL-6.2): {r}"
            );
        }
    }
    let short = &anchor_fp[..26];
    for (root, tag, who) in [
        (&alice, "serve", "alice's vox serve"),
        (&alice, ".daemon/log", "alice's daemon"),
        (&bob, ".daemon/log", "bob's daemon"),
    ] {
        let said =
            std::fs::read_to_string(
                root.dir
                    .join(if tag == "serve" { "serve.log" } else { tag }),
            )
            .unwrap_or_default();
        let synced: Vec<&str> = said
            .lines()
            .filter(|l| l.contains("sync of room") && l.contains(short))
            .collect();
        assert!(
            synced.is_empty(),
            "PRODUCT: {who} printed a sync with the anchor: {synced:?}"
        );
    }
    println!(
        "[proof] neither member opened a sync session with the anchor {short}; they completed theirs"
    );
}
