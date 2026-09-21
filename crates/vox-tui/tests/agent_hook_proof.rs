//! ADR-020 §6 — `vox agent hook` driven as a **real binary**, in both harness
//! shapes.
//!
//! This is the piece that makes agent comms mechanical rather than cooperative:
//! the harness runs it at the top of every turn whether or not the model would
//! have thought to read its room.
//!
//! The design is **harness-agnostic on purpose**. Attaching, resolving the room,
//! the cursor and what counts as unread are one code path; the only difference
//! between harnesses is the shape of the injected context on stdout. This proof
//! drives the real binary with the real input shapes, measured from live
//! harnesses on this machine rather than taken from documentation:
//!
//! - **Claude Code 2.1.278** — a project-local hook probe under `claude -p`
//!   showed `UserPromptSubmit` fires headless and carries `cwd`,
//!   `hook_event_name`, `permission_mode`, `prompt`, `prompt_id`, `session_id`,
//!   `transcript_path`. Output is `hookSpecificOutput.additionalContext`.
//! - **Codex 0.155.1** — `~/.codex/hooks.json` on this machine confirms the same
//!   nesting plus `async` and `timeout`. Output is **plain stdout**, and the hook
//!   must be registered `async: false` or the output is observed and discarded.
//!
//! What it proves:
//!
//! 1. an unread message reaches the harness in **Claude Code's** shape, with the
//!    text inside `additionalContext`;
//! 2. the same message reaches **Codex's** shape as plain stdout with no JSON
//!    wrapper — and `auto` picks correctly between the two from the input alone,
//!    which is what lets one installed command serve both;
//! 3. **the cursor advances**: a second run after the first delivers nothing, so
//!    an agent is not told the same thing every turn;
//! 4. **cursors are per session**: a second session id still gets the backlog,
//!    because it has not read it;
//! 5. a quiet room **emits nothing at all** — not "no new messages" — so a quiet
//!    room costs zero tokens per turn;
//! 6. **every failure still exits 0**: no node running, an unknown room, no room
//!    given. A hook that breaks the turn it rides on is worse than one that does
//!    nothing.
//!
//! Not proved here, and stated rather than implied: that a harness actually
//! *shows* the model what it injects. The probe could not confirm it because this
//! machine's API key returned 401, so no model ran. That is the rehearsal's job.

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

/// A Claude Code `UserPromptSubmit` payload, in the shape the spike measured.
fn claude_input(session: &str) -> String {
    format!(
        r#"{{"session_id":"{session}","hook_event_name":"UserPromptSubmit","cwd":"/tmp","permission_mode":"default","prompt":"hi","prompt_id":"p-1","transcript_path":"/tmp/t.jsonl"}}"#
    )
}

/// A Codex payload: same nesting, but without Claude Code's `hook_event_name`,
/// which is exactly what `auto` keys off.
fn codex_input(session: &str) -> String {
    format!(r#"{{"session_id":"{session}","cwd":"/tmp"}}"#)
}

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

fn hook(
    data: &std::path::Path,
    cfg: &std::path::Path,
    args: &[&str],
    stdin: &str,
) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
#[ignore = "production Argon2id at setup + drives the real binary; CI runs it in release"]
fn the_hook_feeds_an_agent_its_room_in_either_harness_shape() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");
    let paths = Paths::resolve("default", Some(&data), Some(&cfg)).unwrap();

    // (6) with nothing running at all, the hook still exits 0.
    let (ok, out, _) = hook(
        &data,
        &cfg,
        &["agent", "hook", "--room", "aaaa"],
        &claude_input("s1"),
    );
    assert!(ok, "a hook must exit 0 even with no node running");
    assert!(out.is_empty(), "it must inject nothing when it cannot read");

    // ---- a node, a room, and one message waiting ----
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
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
        assert!(node
            .apply(NodeCommand::SendText {
                channel_id: node.view().channels[0].channel_id,
                text: "PLAN: port the wire codec".into(),
            })
            .await
            .is_done());
        node.view().channels[0].channel_id
    });
    let _server = rt
        .block_on(async { vox_core::node::ipc::bind(node.clone(), &paths) })
        .expect("bind");
    let room: String = vox_core::node::link::b32_encode(&cid)
        .chars()
        .take(8)
        .collect();

    // (1) Claude Code's shape.
    let (ok, out, err) = hook(
        &data,
        &cfg,
        &["agent", "hook", "--room", &room],
        &claude_input("claude-session-1"),
    );
    assert!(ok, "hook failed: {err}");
    let v: serde_json::Value = serde_json::from_str(out.trim())
        .unwrap_or_else(|_| panic!("Claude Code needs JSON on stdout, got: {out:?}"));
    let injected = v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("additionalContext");
    assert_eq!(
        v["hookSpecificOutput"]["hookEventName"], "UserPromptSubmit",
        "the event must be echoed back"
    );
    assert!(
        injected.contains("PLAN: port the wire codec"),
        "the message did not reach the injected context: {injected}"
    );

    // (3) the cursor advanced: the same session is not told again.
    let (ok, out, err) = hook(
        &data,
        &cfg,
        &["agent", "hook", "--room", &room],
        &claude_input("claude-session-1"),
    );
    assert!(ok, "second hook failed: {err}");
    assert!(
        out.trim().is_empty(),
        "an agent must not be told the same message every turn, got: {out}"
    );

    // (4) a different session still has the backlog — cursors are per session.
    let (ok, out, err) = hook(
        &data,
        &cfg,
        &["agent", "hook", "--room", &room],
        &claude_input("claude-session-2"),
    );
    assert!(ok, "hook for a second session failed: {err}");
    assert!(
        out.contains("PLAN: port the wire codec"),
        "a second session must still see what it has not read: {out}"
    );

    // (2) Codex's shape: plain stdout, no JSON wrapper, chosen by `auto` from the
    // input alone — which is what lets one installed command serve both.
    let (ok, out, err) = hook(
        &data,
        &cfg,
        &["agent", "hook", "--room", &room],
        &codex_input("codex-session-1"),
    );
    assert!(ok, "codex-shaped hook failed: {err}");
    assert!(
        !out.trim_start().starts_with('{'),
        "Codex takes plain stdout; a JSON wrapper would be injected literally: {out}"
    );
    assert!(
        out.contains("PLAN: port the wire codec"),
        "the message did not reach Codex's plain output: {out}"
    );

    // …and `--format` forces it either way, for a harness `auto` cannot place.
    let (ok, out, _) = hook(
        &data,
        &cfg,
        &["agent", "hook", "--room", &room, "--format", "text"],
        &claude_input("forced-text"),
    );
    assert!(ok);
    assert!(
        !out.trim_start().starts_with('{') && out.contains("PLAN:"),
        "--format text must override detection: {out}"
    );
    let (ok, out, _) = hook(
        &data,
        &cfg,
        &["agent", "hook", "--room", &room, "--format", "claude"],
        &codex_input("forced-claude"),
    );
    assert!(ok);
    assert!(
        serde_json::from_str::<serde_json::Value>(out.trim()).is_ok(),
        "--format claude must override detection: {out}"
    );

    // (5) a quiet room emits nothing at all — not a heartbeat.
    let (ok, out, _) = hook(
        &data,
        &cfg,
        &["agent", "hook", "--room", &room],
        &claude_input("codex-session-1"),
    );
    assert!(ok);
    assert!(
        out.is_empty(),
        "a quiet room must cost nothing per turn, got: {out:?}"
    );

    // (6) the remaining failures: still exit 0, still inject nothing.
    for (args, why) in [
        (vec!["agent", "hook", "--room", "zzzzzzzz"], "unknown room"),
        (vec!["agent", "hook"], "no room given"),
    ] {
        let (ok, out, err) = hook(&data, &cfg, &args, &claude_input("s9"));
        assert!(ok, "{why}: a hook must exit 0");
        assert!(out.is_empty(), "{why}: must inject nothing");
        assert!(!err.trim().is_empty(), "{why}: must say why on stderr");
    }
}
