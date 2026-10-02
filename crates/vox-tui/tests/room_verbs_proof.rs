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
//! - **`room post` refuses every raw claim-protocol message** (`claim`, `release`, `handoff`,
//!   `renew`, and a `decline` naming a resource) and says which verb to use, and the room and its
//!   work board are unchanged by them; **prose that only sounds like a claim** ("I'll
//!   take the deploy") is posted and claims nothing; a `decline` with no resource, which refuses
//!   an `assign` in conversation, is posted, not refused (ADR-021 §4);
//! - the failures an operator will actually hit say something useful: no node
//!   running, an unknown room, a malformed cursor.
//!
//! **Mutation.** Drop the raw-claim refusal from `post_cmd` and this goes red on the refusal:
//! the claim is posted. Let `is_claim_protocol` match `claim` alone and it goes red on the raw
//! `release`: it is posted. Let `is_claim_protocol` count any `decline` as a claim operation and
//! it goes red on the conversational decline: it is refused.
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

    // ---- every raw claim-protocol operation is refused: it would lack the session, op id and
    // version stamp that make it valid, and `vox room <kind>` sets them. All five kinds, a
    // `decline` counting only when it names a resource ----
    let raw_ops: Vec<(&str, String)> = ["claim", "release", "handoff", "renew", "decline"]
        .iter()
        .map(|kind| {
            (
                *kind,
                format!(
                    r#"{{"v":1,"type":"{kind}","from":"s","data":{{"resource":"deploy","op":"op-12345678"}}}}"#
                ),
            )
        })
        .collect();
    for (kind, raw) in &raw_ops {
        let (ok, _, err) = vox(&data, &cfg, &["room", "post", &room_prefix], Some(raw));
        assert!(
            !ok,
            "PRODUCT: `vox room post` accepted a raw `{kind}` operation; it must refuse it"
        );
        assert!(
            err.contains(&format!("refusing a raw `{kind}`"))
                && err.contains(&format!("vox room {kind}")),
            "PRODUCT: the refusal must say it refused a raw `{kind}` and name `vox room {kind}`, \
             got: {err:?}"
        );
    }
    // ---- prose that sounds like a claim is a message, and claims nothing ----
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "post", &room_prefix, "I'll take the deploy"],
        None,
    );
    assert!(ok, "PRODUCT: a prose post was refused: {err}");
    // ---- a decline with no resource refuses an `assign` in conversation: not a claim
    // operation, so it is posted ----
    let decline = r#"{"v":1,"type":"decline","body":"not me"}"#;
    let (ok, _, err) = vox(&data, &cfg, &["room", "post", &room_prefix], Some(decline));
    assert!(
        ok,
        "PRODUCT: a decline with no resource is conversation, not a claim operation, and must \
         be posted; got: {err:?}"
    );
    let (ok, board, err) = vox(
        &data,
        &cfg,
        &["room", "board", &room_prefix, "--json"],
        None,
    );
    assert!(ok, "PRODUCT: room board failed: {err}");
    let board: serde_json::Value = serde_json::from_str(&board)
        .unwrap_or_else(|e| panic!("PRODUCT: room board --json is not JSON ({e}): {board}"));
    println!("[proof] the work board after a refused raw claim and a prose 'claim': {board}");
    assert_eq!(
        board["resources"].as_array().map(Vec::len),
        Some(0),
        "PRODUCT: nothing was claimed, yet the board shows a resource: {board}"
    );

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
    for (kind, raw) in &raw_ops {
        assert!(
            !stored.contains(raw.as_str()),
            "PRODUCT: the refused raw `{kind}` is in the room anyway: {stored}"
        );
    }
    assert!(
        stored.lines().any(|l| l.ends_with(" I'll take the deploy"))
            && stored.lines().any(|l| l.ends_with(decline)),
        "PRODUCT: the prose post or the conversational decline is missing: {stored}"
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
