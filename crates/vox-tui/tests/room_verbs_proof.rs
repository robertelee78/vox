//! ADR-020 §8 — `vox room` driven as a **real binary against a real node**.
//!
//! It replaced the in-process gate `node_m19_ipc_requests_gate` (deleted in V29-17), which only
//! proved the socket answers.
//! This proves the thing an agent actually runs: the `vox` binary, as a separate
//! process, attaching to a node it did not start.
//!
//! That distinction is the whole reason this file exists. M17's rehearsal found
//! three defects that no library gate could catch, every one of them in CLI
//! composition — a passphrase that did not match itself, an address printed that
//! could not be dialled, a race between binding and dialling. Those live in the
//! seam between a binary and a node, which is exactly this seam.
//!
//! What it proves:
//!
//! - `room list` names the room, and `room post` puts a message in it that the
//!   **node's own view** shows — so the post went through the log;
//! - `room read` prints the entry hash first, and **that hash works as a cursor**
//!   for a second `read --since`, which is the loop an agent's drain does;
//! - `--limit` caps;
//! - **posting from stdin works**, which is how an agent sends a JSON envelope
//!   without fighting shell quoting;
//! - `room roster` names the member;
//! - the failures an operator will actually hit say something useful: no node
//!   running, an unknown room, a malformed cursor.
//!
//! Production Argon2id once at setup; `#[ignore]`d in the debug suite.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// A real `vox daemon`, killed however the test ends.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start `vox daemon` on the profile and wait until its control socket answers.
fn daemon(data: &Path, cfg: &Path, pass: &Path, err: &Path) -> Daemon {
    let child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0", "--passphrase-file"])
        .arg(pass)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(err).unwrap_or_else(
            |e| panic!("APPARATUS: cannot create {}: {e}", err.display()),
        )))
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox daemon: {e}"));
    let mut d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (ok, _, list_err) = vox(data, cfg, &["room", "list"], None);
        if ok {
            break;
        }
        if let Ok(Some(status)) = d.0.try_wait() {
            panic!(
                "PRODUCT: vox daemon exited ({status}) before its control socket answered; \
                 stderr:\n{}",
                std::fs::read_to_string(err).unwrap_or_default()
            );
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: the daemon's control socket never answered `vox room list` within 60 s; \
             last `room list` said: {list_err}\ndaemon stderr:\n{}",
            std::fs::read_to_string(err).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    d
}

/// Run `vox room …` against the profile rooted at `data`/`cfg`.
fn vox(
    data: &std::path::Path,
    cfg: &std::path::Path,
    args: &[&str],
    stdin: Option<&str>,
) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox {args:?}: {e}"));
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("APPARATUS: the piped stdin was not opened")
            .write_all(text.as_bytes())
            .unwrap_or_else(|e| panic!("APPARATUS: cannot write vox {args:?}'s stdin: {e}"));
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot wait for vox {args:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
#[ignore = "production Argon2id at setup + drives the real binary; CI runs it in release"]
fn vox_room_speaks_to_a_node_it_did_not_start() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");
    std::fs::create_dir_all(&cfg).expect("APPARATUS: create the config dir");
    let pass = tmp.path().join("identity.pass");
    std::fs::write(&pass, "identity passphrase").expect("APPARATUS: write the passphrase file");

    // ---- the failure an operator hits first, before anything is running ----
    let (ok, _, err) = vox(&data, &cfg, &["room", "list"], None);
    assert!(
        !ok,
        "PRODUCT: `vox room list` succeeded with no node running; stderr: {err}"
    );
    assert!(
        err.contains("no node is running"),
        "PRODUCT: the no-node error must say so plainly, got: {err}"
    );

    // ---- stand up a node with a room, as a person does: vox id, vox daemon, vox room create ----
    let (ok, me, err) = vox(
        &data,
        &cfg,
        &[
            "id",
            "--identity-passphrase-file",
            pass.to_str().expect("APPARATUS: a non-UTF-8 temp path"),
        ],
        None,
    );
    assert!(ok, "PRODUCT: vox id failed: {err}");
    let me = me.trim().to_owned();
    let _daemon = daemon(&data, &cfg, &pass, &tmp.path().join("daemon.err"));
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "create", "--name", "agents"],
        Some("channel passphrase"),
    );
    assert!(ok, "PRODUCT: vox room create failed: {err}");
    // The CLI identifies a room by its base32 rendering, as every other verb
    // does, so the prefix must be taken from that — not from hex.
    let (_, listed, list_err) = vox(&data, &cfg, &["room", "list"], None);
    let room_prefix: String = listed
        .split_whitespace()
        .next()
        .unwrap_or_else(|| {
            panic!("PRODUCT: `room list` named no room after `room create`: {listed:?} {list_err}")
        })
        .chars()
        .take(8)
        .collect();

    // ---- list ----
    let (ok, out, err) = vox(&data, &cfg, &["room", "list"], None);
    assert!(ok, "PRODUCT: room list failed: {err}");
    assert!(
        out.contains("agents"),
        "PRODUCT: list did not name the room: {out}"
    );

    // ---- post, and check the NODE's view rather than trusting the exit code ----
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "post", &room_prefix, "first from the cli"],
        None,
    );
    assert!(ok, "PRODUCT: room post failed: {err}");

    // ---- post from stdin: how an agent sends JSON without quoting trouble ----
    let envelope = r#"{"v":1,"type":"assign","to":["codex@host2"],"body":"port the codec"}"#;
    let (ok, _, err) = vox(&data, &cfg, &["room", "post", &room_prefix], Some(envelope));
    assert!(ok, "PRODUCT: room post from stdin failed: {err}");

    // ---- the posts are in the node, not only in the exit code: a separate `vox` process reads
    // them back from the daemon ----
    let (ok, stored, err) = vox(&data, &cfg, &["room", "read", &room_prefix], None);
    assert!(ok, "PRODUCT: room read failed: {err}");
    assert!(
        stored.lines().any(|l| l.ends_with(" first from the cli")),
        "PRODUCT: the node does not have the posted message: {stored}"
    );
    assert!(
        stored.lines().any(|l| l.ends_with(envelope)),
        "PRODUCT: the stdin-posted envelope did not arrive intact: {stored}"
    );

    // ---- read, and use the printed hash as a cursor ----
    let (ok, out, err) = vox(&data, &cfg, &["room", "read", &room_prefix], None);
    assert!(ok, "PRODUCT: room read failed: {err}");
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines.len() >= 2,
        "PRODUCT: read printed {} lines: {out}",
        lines.len()
    );
    let first_hash = lines[0]
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("PRODUCT: read's first line has no hash column: {out}"));
    assert_eq!(
        first_hash.len(),
        52,
        "PRODUCT: the first column must be a full entry hash in the CLI's own encoding, got: {out}"
    );

    let (ok, out2, err) = vox(
        &data,
        &cfg,
        &["room", "read", &room_prefix, "--since", first_hash],
        None,
    );
    assert!(ok, "PRODUCT: room read --since failed: {err}");
    let after: Vec<&str> = out2.lines().collect();
    assert_eq!(
        after.len(),
        lines.len() - 1,
        "PRODUCT: a cursor must return only what follows it; all:\n{out}\n--since {first_hash}:\n{out2}"
    );
    assert!(
        !out2.contains(first_hash),
        "PRODUCT: the cursor entry itself came back: {out2}"
    );

    // ---- limit ----
    let (ok, out, err) = vox(
        &data,
        &cfg,
        &["room", "read", &room_prefix, "--limit", "1"],
        None,
    );
    assert!(ok, "PRODUCT: room read --limit failed: {err}");
    assert_eq!(
        out.lines().count(),
        1,
        "PRODUCT: `--limit 1` printed more or less than one entry: {out}"
    );

    // ---- roster ----
    let (ok, out, err) = vox(&data, &cfg, &["room", "roster", &room_prefix], None);
    assert!(ok, "PRODUCT: room roster failed: {err}");
    // The roster names this node's own member, by its whole fingerprint (agent_comms's review
    // of acc5dc0: "not empty" let a roster that printed "(roster unavailable)" pass).
    assert!(
        out.lines().any(|l| l.trim() == me),
        "PRODUCT: the roster must list this member ({me}), got: {out:?}"
    );

    // ---- the remaining failures say something useful ----
    let (ok, _, err) = vox(&data, &cfg, &["room", "read", "zzzzzzzz"], None);
    assert!(!ok, "PRODUCT: reading an unknown room succeeded: {err}");
    assert!(
        err.contains("nothing here matches") && err.contains("zzzzzzzz"),
        "PRODUCT: an unknown room must say that nothing matches it, naming it, got: {err:?}"
    );

    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "read", &room_prefix, "--since", "not-a-hash"],
        None,
    );
    assert!(!ok, "PRODUCT: a malformed cursor was accepted: {err}");
    assert!(
        err.contains("52-character"),
        "PRODUCT: a malformed cursor must say what a cursor looks like, got: {err}"
    );

    let (ok, _, err) = vox(&data, &cfg, &["room", "post", &room_prefix, "   "], None);
    assert!(!ok, "PRODUCT: an empty message was posted: {err}");
    assert!(
        err.contains("empty"),
        "PRODUCT: an empty message's refusal must say it is empty, got: {err}"
    );
}
