//! ADR-020 §8 — `vox room` driven as a **real binary against a real node**.
//!
//! The library gate (`node_m19_ipc_requests_gate`) proves the socket answers.
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
use std::process::{Command, Stdio};
use std::sync::Arc;

use vox_core::node::actor::{Clock, Node, NodeHandle};
use vox_core::node::api::{NodeCommand, Secret};
use vox_core::node::paths::Paths;

const VOX: &str = env!("CARGO_BIN_EXE_vox");

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
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

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

#[test]
#[ignore = "production Argon2id at setup + drives the real binary; CI runs it in release"]
fn vox_room_speaks_to_a_node_it_did_not_start() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");
    let paths = Paths::resolve("default", Some(&data), Some(&cfg)).unwrap();

    // ---- the failure an operator hits first, before anything is running ----
    let (ok, _, err) = vox(&data, &cfg, &["room", "list"], None);
    assert!(!ok, "room list should fail with no node running");
    assert!(
        err.contains("no node is running"),
        "the no-node error must say so plainly, got: {err}"
    );

    // ---- stand up a node with a room, and bind the socket ----
    let rt = runtime();
    let clock: Clock = Arc::new(|| 1_800_000_000);
    let node: NodeHandle = rt
        .block_on(async {
            Node::spawn_with(
                paths.clone(),
                clock,
                vox_core::atrest::sek::Argon2Profile::default(),
            )
        })
        .unwrap();
    let cid = rt.block_on(async {
        assert!(node
            .apply(NodeCommand::CreateIdentity {
                passphrase: secret("identity passphrase"),
            })
            .await
            .is_done());
        assert!(node
            .apply(NodeCommand::CreateChannel {
                local_name: "agents".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        node.view().channels[0].channel_id
    });
    let _server = rt
        .block_on(async { vox_core::node::ipc::bind(node.clone(), &paths) })
        .expect("bind control socket");
    // The CLI identifies a room by its base32 rendering, as every other verb
    // does, so the prefix must be taken from that — not from hex.
    let room_prefix: String = vox_core::node::link::b32_encode(&cid)
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

    let in_the_node = node
        .view()
        .open_channels
        .iter()
        .find(|d| d.channel_id == cid)
        .map(|d| {
            d.timeline
                .iter()
                .map(|r| r.text.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(
        in_the_node.iter().any(|t| t == "first from the cli"),
        "the node's own view is missing the posted message: {in_the_node:?}"
    );
    assert!(
        in_the_node.iter().any(|t| t == envelope),
        "the stdin-posted envelope did not arrive intact: {in_the_node:?}"
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
        vox_core::node::link::B32_DIGEST_LEN,
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
    assert!(!out.trim().is_empty(), "roster printed nothing");

    // ---- the remaining failures say something useful ----
    let (ok, _, err) = vox(&data, &cfg, &["room", "read", "zzzzzzzz"], None);
    assert!(!ok, "an unknown room should fail");
    assert!(!err.trim().is_empty(), "an unknown room said nothing");

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
