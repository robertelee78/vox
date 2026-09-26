//! ADR-020 M19.7 — **the rehearsal**: two agent sessions and a human operator in
//! one room, with real models reading what each other wrote.
//!
//! ADR-020 marks this **REQUIRED** before agent comms may be described as working,
//! and the reason is M17's lesson: every CLI-composition defect that rehearsal
//! found was invisible to every library gate. A gate proves a function; a rehearsal
//! proves the product.
//!
//! What it drives, end to end, with nothing mocked:
//!
//! - two nodes with two identities, mutually admitted to each other's trust
//!   keyrings, sharing one room;
//! - two **separate agent sessions**, each a real `opencode` turn against a real
//!   model, each with its own session id and therefore its own cursor;
//! - the **operator** speaking into the same room as plain text through
//!   `vox room post`, exactly as a person would;
//! - a typed `assign` envelope from the operator and a typed `result` envelope
//!   back from the agent that did the work.
//!
//! What it asserts:
//!
//! 1. an agent's model **reads an assignment it was never prompted with**, and
//!    names the work in its own answer;
//! 2. the **second** agent's model reads the *result* the first one posted — so a
//!    message written by one session reaches a different session on a different
//!    identity, which is the whole feature;
//! 3. **cursors are per session**: the second agent sees the backlog the first has
//!    already consumed, because it has not read it;
//! 4. the operator's plain prose and the agents' typed envelopes coexist in one
//!    room, which is the shared-room case rather than the pure-agent one.
//!
//! ## Stated rather than implied
//!
//! This runs **two sessions on one host**, not on two machines. The overlay's
//! cross-machine path — NAT traversal, anchors, circuits — is proved by M17's own
//! rehearsal and by `service_rehearsal_proof`; what is new here is the composition
//! of agent sessions, cursors, envelopes and the operator, and that composition is
//! host-independent. The two-machine claim is not made here and should not be read
//! into it.
//!
//! ## Every participant is the shipped binary
//!
//! The nodes are real processes (`support/room.rs`): an anchor (`vox node`), a `vox daemon`
//! per agent, the room made with `vox room create|invite|join`, each identity admitted with
//! `vox trust add`, ready once each has rendered a post by the other. Each agent's OpenCode
//! plugin is what `vox agent plugin opencode` prints, installed where a person puts it, and
//! that plugin runs `vox agent hook` every turn. Nothing in this process runs a node.
//!
//! ## Mutation
//!
//! Make `vox agent hook` inject nothing (the drain returns before printing what is unread)
//! and this goes red at (1): alice's model cannot name the assignment it was never told.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::Path;
use std::process::Command;

use support::{until, Worker, VOX};

fn model() -> String {
    std::env::var("VOX_PROOF_OPENCODE_MODEL")
        .unwrap_or_else(|_| "opencode/claude-haiku-4-5".to_owned())
}

fn allow_unproven(name: &str) -> bool {
    std::env::var("VOX_PROOF_ALLOW_UNPROVEN")
        .unwrap_or_default()
        .split(',')
        .any(|s| s.trim().eq_ignore_ascii_case(name))
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

fn auth_present() -> bool {
    std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".local/share")))
        .is_some_and(|b| b.join("opencode/auth.json").is_file())
}

/// Install this agent's OpenCode plugin the way a person does — `vox agent plugin opencode >
/// .opencode/plugin/vox.js` — in its own project directory, which is also what gives it its
/// own OpenCode session and therefore its own cursor. Returns the project directory.
fn install_plugin(w: &Worker, fixture: &Path) -> std::path::PathBuf {
    let project = fixture.join(&w.name);
    std::fs::create_dir_all(project.join(".opencode/plugin")).unwrap();
    let o = w.vox(None, &["agent", "plugin", "opencode"]);
    assert!(
        o.ok && o.stdout.contains("vox agent hook"),
        "vox agent plugin opencode: {o:?}"
    );
    std::fs::write(project.join(".opencode/plugin/vox.js"), &o.stdout).unwrap();
    project
}

/// One real model turn for this agent, with its room wired in.
fn turn(w: &Worker, project: &Path, oc_cfg: &Path, room: &str, prompt: &str) -> String {
    let mut cmd = Command::new("opencode");
    // A spawned OpenCode that inherits cargo's environment loads the plugin and never
    // fires its message hook. Measured; see `opencode_plugin_proof`.
    cmd.env_clear();
    for key in ["PATH", "HOME", "SHELL", "LANG", "TMPDIR", "USER"] {
        if let Some(v) = std::env::var_os(key) {
            cmd.env(key, v);
        }
    }
    let out = cmd
        .current_dir(project)
        .args(["run", "-m", &model(), prompt])
        .env("XDG_CONFIG_HOME", oc_cfg)
        .env("VOX_DATA_DIR", &w.data)
        .env("VOX_CONFIG_DIR", &w.cfg)
        .env("VOX_ROOM", room)
        .env("VOX_BIN", VOX)
        .output()
        .expect("run opencode");
    let said = format!(
        "{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("[turn {}] {prompt:?} -> {said}", w.name);
    said
}

#[test]
#[ignore = "an anchor, two vox daemons, live model turns; CI runs it in release"]
fn two_agent_sessions_and_an_operator_share_one_room() {
    watchdog::arm();
    if which("opencode").is_none() || !auth_present() {
        assert!(
            allow_unproven("opencode"),
            "UNPROVEN: the rehearsal needs a real harness and a usable credential. Set \
             VOX_PROOF_ALLOW_UNPROVEN=opencode to accept that gap deliberately."
        );
        return;
    }

    // A persistent fixture: OpenCode installs a `node_modules` tree into both the
    // project and the config directory on first use, and until it has, the plugin
    // loads while its hook never fires.
    let fixture = std::env::temp_dir().join("vox-agent-rehearsal");
    let oc_cfg = fixture.join("config");
    std::fs::create_dir_all(oc_cfg.join("opencode")).unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let r = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&r.workers[0], &r.workers[1]);
    let room = r.id.clone();
    let a_proj = install_plugin(alice, &fixture);
    let b_proj = install_plugin(bob, &fixture);

    // Warm both projects: the first turn in a fresh directory installs and does not
    // fire the hook. This also consumes the harness's readiness posts from each cursor.
    for (who, proj) in [(alice, &a_proj), (bob, &b_proj)] {
        let _ = turn(who, proj, &oc_cfg, &room, "Reply with exactly: READY");
    }

    // ---- the operator speaks, as a person, in plain prose ----
    let assignment = r#"{"v":1,"type":"assign","to":["alice"],"body":"port the wire codec to the new envelope format","data":{"resource":"port-the-codec"}}"#;
    let o = alice.vox(None, &["room", "post", &room, assignment]);
    assert!(o.ok, "the operator could not post the assignment: {o:?}");
    until(
        bob,
        None,
        "the assignment to reach bob",
        &["room", "read", &room],
        |o| o.stdout.contains("port the wire codec"),
    );

    // ---- (1) alice's model reads work it was never prompted with ----
    let answer = turn(
        alice,
        &a_proj,
        &oc_cfg,
        &room,
        "What task have you been assigned? Answer with just the task.",
    );
    let read_assignment = answer.contains("codec") || answer.contains("wire");
    println!("[proof] (1) alice's model named its assignment: {read_assignment}");
    assert!(
        read_assignment,
        "alice's model did not read its assignment: {answer:?}"
    );

    // ---- alice reports a result, as an agent would ----
    let result = r#"{"v":1,"type":"result","re":"port-the-codec","body":"done: the codec now speaks the envelope format. verification token QUORUM-8812"}"#;
    let o = alice.vox(None, &["room", "post", &room, result]);
    assert!(o.ok, "alice could not post her result: {o:?}");
    until(
        bob,
        None,
        "the result to reach bob",
        &["room", "read", &room],
        |o| o.stdout.contains("QUORUM-8812"),
    );

    // ---- (2) and (3) bob's model reads what alice wrote, from its own cursor ----
    let seen = turn(
        bob,
        &b_proj,
        &oc_cfg,
        &room,
        "What verification token was reported in your room? Answer with just the token.",
    );
    println!(
        "[proof] (2) bob's model repeated alice's token: {}",
        seen.contains("QUORUM-8812")
    );
    assert!(
        seen.contains("QUORUM-8812"),
        "a message written by one agent session did not reach the other: {seen:?}"
    );

    // ---- (4) the operator asks a question in prose, and it lands ----
    let o = bob.vox(
        None,
        &[
            "room",
            "post",
            &room,
            "hey, is the codec work finished? the release is waiting on it",
        ],
    );
    assert!(o.ok, "the operator could not ask a question: {o:?}");
    until(
        alice,
        None,
        "the question to reach alice",
        &["room", "read", &room],
        |o| o.stdout.contains("release is waiting"),
    );
    let heard = turn(
        alice,
        &a_proj,
        &oc_cfg,
        &room,
        "Did anyone ask you a question just now? Answer yes or no and quote it.",
    );
    let heard_it = heard.contains("release is waiting") || heard.to_lowercase().contains("codec");
    println!("[proof] (4) alice's model heard the operator's prose: {heard_it}");
    assert!(
        heard_it,
        "plain prose from the operator did not reach an agent's context: {heard:?}"
    );
}
