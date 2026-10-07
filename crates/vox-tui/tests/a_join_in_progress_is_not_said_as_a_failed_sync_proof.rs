//! **A join is not a failed sync** (#406). The member that lets a joiner in pushes to it the
//! moment it is admitted, and the joiner is not ready: it is still sealing the room's key ("epoch
//! mismatch"), its `vox connect` process exits after the join ("transport failed"), the node
//! attached after it is still reopening the room ("authenticator invalid"). The host's `vox serve`
//! printed each as `sync of room … with <joiner> did not complete — …` although the join, and
//! everything after it, succeeded. Driven through the shipped `vox` binary, as a person types it:
//!
//! ```text
//! vox node create alice; vox serve web=<echo> --listen 127.0.0.1:0          (data root A)
//! vox node create bob; vox connect <address> --listen 127.0.0.1:0 …          (data root B)
//! vox node attach bob; vox trust add … (each the other); vox room post … (bob)
//! ```
//!
//! **Observed, not assumed.** Premise, from alice's own `vox status --json`: her sync row for bob
//! records a failed session (CANNOT MEASURE otherwise: there was nothing to stay quiet about), and
//! she then completed one with him.
//!
//! **Asserted:** alice's `vox serve` printed no line saying something did not complete, and no
//! line saying it could not reach bob (his `vox connect` exits after the join, so the address it
//! joined from answers no more).
//!
//! **Mutant:** `JOINER_SEAL_GRACE` of 0 s in the actor, red as `PRODUCT: alice's vox serve
//! reported a failure during an ordinary join`.

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
fn a_join_in_progress_is_not_said_as_a_failed_sync() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: temp dir");
    let alice = Root::new(tmp.path(), "alice");
    let bob = Root::new(tmp.path(), "bob");
    let _alice_daemon = Reaper(alice.dir.clone());
    let _bob_daemon = Reaper(bob.dir.clone());
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

    // ---- alice serves a room; bob joins it ----------------------------------------------------
    let spec = format!("web={}", echo_service());
    let _serve = alice.spawn(
        "serve",
        &[
            "serve",
            &spec,
            "--listen",
            "127.0.0.1:0",
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
    let joined = bob
        .cmd(&[
            "connect",
            &address,
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            room_pass.to_str().unwrap(),
            "--identity-passphrase-file",
            &bob.pass(),
        ])
        .stdin(Stdio::null())
        .output()
        .expect("APPARATUS: run vox");
    assert!(
        joined.status.success(),
        "PRODUCT (staging): bob's vox connect failed:\n{}{}",
        String::from_utf8_lossy(&joined.stdout),
        String::from_utf8_lossy(&joined.stderr)
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

    // ---- premise: a session with bob failed during his join, then one completed ---------------
    let deadline = Instant::now() + Duration::from_secs(120);
    let alice_row = loop {
        let rows = alice.sync_rows();
        if let Some(r) = row(&rows, &bob_fp).filter(|r| r["completed"].as_u64().unwrap_or(0) > 0) {
            break r.clone();
        }
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: alice never completed a sync with bob: {rows:?}"
        );
        std::thread::sleep(Duration::from_millis(300));
    };
    // Past the moments a refusal would be said: the sync after the backoff, and the next tick.
    std::thread::sleep(Duration::from_secs(20));
    let failed_during_join = alice_row["failed"].as_u64().unwrap_or(0) > 0;
    println!("[proof] alice's sync row for bob: {alice_row}");
    assert!(
        failed_during_join,
        "CANNOT MEASURE: no session of alice's with bob failed during his join, so there was nothing \
         to stay quiet about: {alice_row}\nalice's vox serve:\n{}",
        alice.said("serve")
    );

    // ---- the claim ------------------------------------------------------------------------
    let serve_said = alice.said("serve");
    let failed: Vec<&str> = serve_said
        .lines()
        .filter(|l| {
            l.contains("did not complete")
                || (l.contains("could not reach") && l.contains(&bob_fp[..26]))
        })
        .collect();
    println!(
        "[proof] {} of alice's sessions with bob failed during his join (last: {}); her vox serve \
         said {} line(s) of something that did not complete or of bob it could not reach",
        alice_row["failed"],
        alice_row["last_failure"],
        failed.len()
    );
    assert!(
        failed.is_empty(),
        "PRODUCT: alice's vox serve reported a failure during an ordinary join: {failed:?}"
    );
}
