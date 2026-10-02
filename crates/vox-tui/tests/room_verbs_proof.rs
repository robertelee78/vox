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
//!
//! **A room is made in a debug build too** ([`a_debug_daemon_makes_a_room_and_keeps_running`],
//! not ignored, so the debug suite runs it): a debug `vox daemon` aborted on `vox room create` with
//! "thread 'tokio-rt-worker' has overflowed its stack". A debug build gives every future an async
//! fn awaits a stack slot of its own, and the actor's dispatchers await dozens, so their poll
//! frames came to about 790 KiB and 490 KiB, and signing the new room's records on top of them
//! passed the 2 MiB worker stack. The actor's large steps are boxed where they are made (`Boxed`
//! in `node/actor.rs`). Mutation that must turn it red: those steps awaited unboxed again.

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
        .stderr(Stdio::from(std::fs::File::create(err).unwrap()))
        .spawn()
        .expect("spawn vox daemon");
    let d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !vox(data, cfg, &["room", "list"], None).0 {
        assert!(Instant::now() < deadline, "the daemon never answered");
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
    let mut child = cmd.spawn().expect("spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(text.as_bytes())
            .expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait");
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
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");
    std::fs::create_dir_all(&cfg).unwrap();
    let pass = tmp.path().join("identity.pass");
    std::fs::write(&pass, "identity passphrase").unwrap();

    // ---- the failure an operator hits first, before anything is running ----
    let (ok, _, err) = vox(&data, &cfg, &["room", "list"], None);
    assert!(!ok, "room list should fail with no node running");
    assert!(
        err.contains("no node is running"),
        "the no-node error must say so plainly, got: {err}"
    );

    // ---- stand up a node with a room, as a person does: vox id, vox daemon, vox room create ----
    let (ok, me, err) = vox(
        &data,
        &cfg,
        &["id", "--identity-passphrase-file", pass.to_str().unwrap()],
        None,
    );
    assert!(ok, "vox id: {err}");
    let me = me.trim().to_owned();
    let _daemon = daemon(&data, &cfg, &pass, &tmp.path().join("daemon.err"));
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "create", "--name", "agents"],
        Some("channel passphrase"),
    );
    assert!(ok, "vox room create: {err}");
    // The CLI identifies a room by its base32 rendering, as every other verb
    // does, so the prefix must be taken from that — not from hex.
    let room_prefix: String = vox(&data, &cfg, &["room", "list"], None)
        .1
        .split_whitespace()
        .next()
        .expect("a room")
        .chars()
        .take(8)
        .collect();

    // ---- list ----
    let (ok, out, err) = vox(&data, &cfg, &["room", "list"], None);
    assert!(ok, "room list failed: {err}");
    assert!(out.contains("agents"), "list did not name the room: {out}");

    // ---- post, and check the NODE's view rather than trusting the exit code ----
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "post", &room_prefix, "first from the cli"],
        None,
    );
    assert!(ok, "room post failed: {err}");

    // ---- post from stdin: how an agent sends JSON without quoting trouble ----
    let envelope = r#"{"v":1,"type":"assign","to":["codex@host2"],"body":"port the codec"}"#;
    let (ok, _, err) = vox(&data, &cfg, &["room", "post", &room_prefix], Some(envelope));
    assert!(ok, "room post from stdin failed: {err}");

    // ---- the posts are in the node, not only in the exit code: a separate `vox` process reads
    // them back from the daemon ----
    let (ok, stored, err) = vox(&data, &cfg, &["room", "read", &room_prefix], None);
    assert!(ok, "room read failed: {err}");
    assert!(
        stored.lines().any(|l| l.ends_with(" first from the cli")),
        "the node does not have the posted message: {stored}"
    );
    assert!(
        stored.lines().any(|l| l.ends_with(envelope)),
        "the stdin-posted envelope did not arrive intact: {stored}"
    );

    // ---- read, and use the printed hash as a cursor ----
    let (ok, out, err) = vox(&data, &cfg, &["room", "read", &room_prefix], None);
    assert!(ok, "room read failed: {err}");
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines.len() >= 2,
        "read printed {} lines: {out}",
        lines.len()
    );
    let first_hash = lines[0].split_whitespace().next().expect("hash column");
    assert_eq!(
        first_hash.len(),
        52,
        "the first column must be a full entry hash in the CLI's own encoding"
    );

    let (ok, out2, err) = vox(
        &data,
        &cfg,
        &["room", "read", &room_prefix, "--since", first_hash],
        None,
    );
    assert!(ok, "room read --since failed: {err}");
    let after: Vec<&str> = out2.lines().collect();
    assert_eq!(
        after.len(),
        lines.len() - 1,
        "a cursor must return only what follows it"
    );
    assert!(
        !out2.contains(first_hash),
        "the cursor entry itself came back"
    );

    // ---- limit ----
    let (ok, out, err) = vox(
        &data,
        &cfg,
        &["room", "read", &room_prefix, "--limit", "1"],
        None,
    );
    assert!(ok, "room read --limit failed: {err}");
    assert_eq!(out.lines().count(), 1);

    // ---- roster ----
    let (ok, out, err) = vox(&data, &cfg, &["room", "roster", &room_prefix], None);
    assert!(ok, "room roster failed: {err}");
    // The roster names this node's own member, by its whole fingerprint (agent_comms's review
    // of acc5dc0: "not empty" let a roster that printed "(roster unavailable)" pass).
    assert!(
        out.lines().any(|l| l.trim() == me),
        "the roster must list this member ({me}), got: {out:?}"
    );

    // ---- the remaining failures say something useful ----
    let (ok, _, err) = vox(&data, &cfg, &["room", "read", "zzzzzzzz"], None);
    assert!(!ok, "an unknown room should fail");
    assert!(
        err.contains("nothing here matches") && err.contains("zzzzzzzz"),
        "an unknown room must say that nothing matches it, naming it, got: {err:?}"
    );

    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "read", &room_prefix, "--since", "not-a-hash"],
        None,
    );
    assert!(!ok, "a malformed cursor should fail");
    assert!(
        err.contains("52-character"),
        "a malformed cursor must say what a cursor looks like, got: {err}"
    );

    let (ok, _, err) = vox(&data, &cfg, &["room", "post", &room_prefix, "   "], None);
    assert!(!ok, "an empty message should be refused");
    assert!(err.contains("empty"), "got: {err}");
}

/// A debug `vox daemon` makes a room and is still running afterwards. A red is PRODUCT and quotes
/// the daemon's own stderr (an abort there says "has overflowed its stack").
#[test]
fn a_debug_daemon_makes_a_room_and_keeps_running() {
    // `vox id` and the daemon's unlock, and the room key's seal: three Argon2id runs.
    watchdog::arm_for_setup(0, 3);
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");
    std::fs::create_dir_all(&cfg).unwrap();
    let pass = tmp.path().join("identity.pass");
    std::fs::write(&pass, "identity passphrase").unwrap();
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["id", "--identity-passphrase-file", pass.to_str().unwrap()],
        None,
    );
    assert!(ok, "CANNOT MEASURE (staging not achieved): vox id: {err}");
    let daemon_err = tmp.path().join("daemon.err");
    let mut node = daemon(&data, &cfg, &pass, &daemon_err);
    let said = |what: &str| {
        format!(
            "{what}. The daemon said:\n{}",
            std::fs::read_to_string(&daemon_err).unwrap_or_default()
        )
    };

    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "create", "--name", "made-in-debug"],
        Some("channel passphrase"),
    );
    assert!(
        ok,
        "{}",
        said(&format!("PRODUCT: vox room create failed: {err}"))
    );
    let exited = node.0.try_wait().ok().flatten();
    assert!(
        exited.is_none(),
        "{}",
        said(&format!(
            "PRODUCT: vox daemon exited ({exited:?}) after making a room"
        ))
    );
    let (ok, out, err) = vox(&data, &cfg, &["room", "list"], None);
    assert!(
        ok && out.contains("made-in-debug"),
        "{}",
        said(&format!(
            "PRODUCT: the daemon does not list the room it made: {out}{err}"
        ))
    );
}
