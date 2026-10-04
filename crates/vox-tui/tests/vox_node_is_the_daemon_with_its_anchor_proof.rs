//! ADR-026 N-5 (#407, V030-35-D9) — `vox node` is the daemon with one headless node in the anchor
//! role, and one data root holds a person's node beside it in that same daemon. Driven through the
//! shipped `vox` binary, as a person types it:
//!
//! ```text
//! vox node create anchor --headless                 (a key file, no passphrase)
//! vox node --node anchor --listen 127.0.0.1:0       (the daemon, the anchor attached)
//! vox node create person; vox node attach person    (attached to that same daemon)
//! vox node list                                     (both attached)
//! vox room create --node person; vox room invite    (the room's address names the anchor)
//! ```
//!
//! Claims: `vox node` holds the account's lock itself (it is the daemon, not a process of its
//! own kind); the person's node attaches to it; the person's room is on the anchor's board.
//! Mutant: the router attaches a headless node without its anchor board (`anchor_boards(false)`):
//! red as `PRODUCT: the anchor never held person's room on its board`.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
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

fn vox(dir: &Path) -> Command {
    let mut cmd = Command::new(VOX);
    cmd.env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_NODE")
        .env_remove("VOX_PROFILE")
        .env_remove("VOX_IDENTITY_PASSPHRASE")
        .env_remove("VOX_ANCHORS")
        .env_remove("VOX_LISTEN")
        .stdin(Stdio::null());
    cmd
}

/// Run `vox args` that must succeed; its stdout. `side` labels a failure.
fn ok(dir: &Path, side: &str, args: &[&str]) -> String {
    let out = vox(dir).args(args).output().expect("APPARATUS: run vox");
    assert!(
        out.status.success(),
        "{side} `vox {}` failed:\n{}{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
#[ignore = "a real vox node and production Argon2id; run on demand in release"]
fn vox_node_is_the_daemon_and_a_person_node_shares_it() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let d: PathBuf = tmp.path().join("d");
    std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: harness file I/O");

    let anchor_fp = ok(&d, "PRODUCT:", &["node", "create", "anchor", "--headless"])
        .lines()
        .last()
        .unwrap_or_default()
        .trim()
        .to_owned();
    assert_eq!(
        anchor_fp.len(),
        52,
        "PRODUCT: vox node create --headless printed no fingerprint: {anchor_fp:?}"
    );

    // ---- the anchor: `vox node` --------------------------------------------------------------
    let mut child = vox(&d)
        .args(["node", "--node", "anchor", "--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: spawn vox node");
    let out = child.stdout.take().expect("APPARATUS: vox node stdout");
    let err = child.stderr.take().expect("APPARATUS: vox node stderr");
    let anchor = Kid(child);
    let (tx, rx) = mpsc::channel::<String>();
    for pipe in [
        Box::new(out) as Box<dyn std::io::Read + Send>,
        Box::new(err) as Box<dyn std::io::Read + Send>,
    ] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    let mut said: Vec<String> = Vec::new();
    let mut wait_for = |want: &dyn Fn(&str) -> bool, within: Duration, why: &str| {
        let deadline = Instant::now() + within;
        loop {
            if said.iter().any(|l| want(l)) {
                return;
            }
            match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(line) => said.push(line),
                Err(_) => panic!("{why}:\n{}", said.join("\n")),
            }
        }
    };
    wait_for(
        &|l| l == format!("vox node: identity {anchor_fp}"),
        Duration::from_secs(60),
        "PRODUCT: vox node never ran as its headless node",
    );
    wait_for(
        &|l| l.starts_with(&format!("  {anchor_fp}@")),
        Duration::from_secs(60),
        "PRODUCT: vox node never printed its anchor spec",
    );

    // `vox node` holds the account itself: it is the daemon.
    let lock = std::fs::read_to_string(d.join(".daemon").join("lock")).unwrap_or_default();
    assert_eq!(
        lock.trim(),
        anchor.0.id().to_string(),
        "PRODUCT: the account's daemon is not the `vox node` process (lock says {lock:?})"
    );

    // ---- a person's node in the same daemon --------------------------------------------------
    let pf = d.join("person.pass");
    std::fs::write(&pf, "the person's passphrase\n").expect("APPARATUS: harness file I/O");
    let pfs = pf.to_str().expect("APPARATUS: path");
    ok(
        &d,
        "PRODUCT (staging):",
        &["node", "create", "person", "--passphrase-file", pfs],
    );
    ok(
        &d,
        "PRODUCT:",
        &["node", "attach", "person", "--passphrase-file", pfs],
    );
    let list = ok(&d, "PRODUCT:", &["node", "list"]);
    for node in ["anchor", "person"] {
        assert!(
            list.lines()
                .any(|l| l.split_whitespace().take(2).eq([node, "attached"])),
            "PRODUCT: node {node} is not attached to the one daemon:\n{list}"
        );
    }
    let lock = std::fs::read_to_string(d.join(".daemon").join("lock")).unwrap_or_default();
    assert_eq!(
        lock.trim(),
        anchor.0.id().to_string(),
        "PRODUCT: attaching the person started another daemon (lock says {lock:?})"
    );

    // ---- the person's room is on the anchor's board --------------------------------------
    let rf = d.join("room.pass");
    std::fs::write(&rf, "the room's passphrase\n").expect("APPARATUS: harness file I/O");
    ok(
        &d,
        "PRODUCT:",
        &[
            "room",
            "create",
            "--name",
            "r",
            "--passphrase-file",
            rf.to_str().expect("APPARATUS: path"),
            "--node",
            "person",
        ],
    );
    let room = ok(&d, "PRODUCT:", &["room", "list", "--node", "person"])
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().next())
        .expect("PRODUCT: the person's room list is empty")
        .to_owned();
    let link = ok(
        &d,
        "PRODUCT:",
        &["room", "invite", &room, "--node", "person"],
    );
    assert!(
        link.contains(&format!("a={anchor_fp}")),
        "PRODUCT: the person's room address does not name the anchor of its own daemon: {link}"
    );
    wait_for(
        &|l| l.contains("1 room(s) on the board"),
        Duration::from_secs(90),
        "PRODUCT: the anchor never held person's room on its board",
    );
    drop(anchor);
}
