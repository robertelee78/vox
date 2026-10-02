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
//! 3. **cursors are per session**, measured on one daemon: two sessions of the *same*
//!    identity each run the drain the OpenCode plugin runs (`vox agent hook --format text
//!    --room <room> --session <id>`). After session `s1` has consumed a post carrying a
//!    per-run nonce, `s1`'s next drain no longer shows it (the cursor moved) and session
//!    `s2`'s first drain still does (it has not read it). A cursor kept per identity or
//!    per room would hide the nonce from `s2`;
//! 4. the operator's plain prose and the agents' typed envelopes coexist in one
//!    room, which is the shared-room case rather than the pure-agent one. The operator's
//!    question carries a **per-run nonce**, and alice's model must quote that nonce. The
//!    backlog every fresh `opencode run` session is re-shown also holds the `assign`
//!    about the codec, so any check that the assignment could satisfy (such as the word
//!    "codec") measures nothing; only the question's own nonce proves the prose arrived.
//!    Only the model's stdout is searched, never OpenCode's stderr.
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
//! ## Mutations that must turn it red
//!
//! - Make `vox agent hook` inject nothing (the drain returns before printing what is
//!   unread): red at (1), alice's model cannot name the assignment it was never told.
//! - Make `vox agent hook` drop plain prose from what it emits (every row that parses as a
//!   `say` is filtered out of the drain, so only typed envelopes are injected): (1) and (2)
//!   stay green, and it goes red at (4), alice's answer does not carry the question's nonce.
//!   (Filtering on `Envelope::parse(..).is_ok()` is not this mutant: prose parses as a
//!   `say`, so that filter drops nothing.)
//! - Key the hook's cursor by room alone, ignoring the session: red at (3), `s2` is shown
//!   nothing because `s1` already read it.

// Optional (decider, 2026-10-01): it blocks nothing and CI only compiles it. Without
// `--features optional-proofs` a stand-in takes its place and says it was not run
// (`support/optional_proof.rs`). How to run it: docs/release/optional-proofs.md.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(two_agent_sessions_and_an_operator_share_one_room);

#[path = "support/oc_sandbox.rs"]
mod oc_sandbox;
#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::Path;

use support::{until, Worker, VOX};

fn model() -> String {
    oc_sandbox::model()
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
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
fn turn(
    sb: &oc_sandbox::OcSandbox,
    profile: &Path,
    w: &Worker,
    project: &Path,
    oc_cfg: &Path,
    room: &str,
    prompt: &str,
) -> String {
    turn_split(sb, profile, w, project, oc_cfg, room, prompt).1
}

/// As [`turn`], also returning the model's stdout alone (the answer, without OpenCode's
/// stderr), for a check that must not be satisfied by a log line.
fn turn_split(
    sb: &oc_sandbox::OcSandbox,
    profile: &Path,
    w: &Worker,
    project: &Path,
    oc_cfg: &Path,
    room: &str,
    prompt: &str,
) -> (String, String) {
    // Confined, with a fixed environment (`OcSandbox::opencode`, support/oc_sandbox.rs): a
    // spawned OpenCode that inherits cargo's environment never fires its message hook, and the
    // operator's would name their files to the model.
    let mut cmd = sb.opencode(profile, &[], project);
    let out = cmd
        .args(["run", "-m", &model(), prompt])
        .env("XDG_CONFIG_HOME", oc_cfg)
        .env("VOX_DATA_DIR", &w.data)
        .env("VOX_CONFIG_DIR", &w.cfg)
        .env("VOX_ROOM", room)
        .env("VOX_BIN", VOX)
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run opencode in its sandbox: {e}"));
    let said = format!(
        "{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    sb.check(&said, "an `opencode run` turn");
    eprintln!("[turn {}] {prompt:?} -> {said}", w.name);
    (String::from_utf8_lossy(&out.stdout).into_owned(), said)
}

/// A per-run token, unguessable by a model and absent from every prompt.
fn nonce(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{tag}-{}{:06}", std::process::id(), nanos % 1_000_000)
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "an anchor, two vox daemons, live model turns; optional, run it in release"]
fn two_agent_sessions_and_an_operator_share_one_room() {
    watchdog::arm();
    if !oc_sandbox::live_model_allowed(
        "agent_rehearsal_proof::two_agent_sessions_and_an_operator_share_one_room",
    ) {
        return;
    }
    assert!(
        which("opencode").is_some(),
        "CANNOT MEASURE: the rehearsal needs `opencode` on PATH"
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let r = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&r.workers[0], &r.workers[1]);
    let room = r.id.clone();
    // **Every model turn runs confined** (support/oc_sandbox.rs): a throwaway HOME, a fixed
    // environment, a whitelist of readable paths, a canary in the real HOME it must never
    // see. The plugins' hooks need the two agents' vox profiles; nothing else outside the
    // sandbox is readable. A missing credential is CANNOT MEASURE there.
    let sb = oc_sandbox::OcSandbox::new(tmp.path());
    let profile = sb.profile(
        "rehearsal",
        &[&alice.data, &alice.cfg, &bob.data, &bob.cfg],
        &[Path::new(VOX)],
    );
    // **This run's own fixture, inside its sandbox**: OpenCode installs a `node_modules` tree
    // into the project and the config directory on first use (the warm-up turns below).
    let fixture = sb.root.join("fixture");
    let oc_cfg = fixture.join("config");
    std::fs::create_dir_all(oc_cfg.join("opencode"))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make the fixture: {e}"));
    let a_proj = install_plugin(alice, &fixture);
    let b_proj = install_plugin(bob, &fixture);

    // Warm both projects: the first turn in a fresh directory installs and does not
    // fire the hook. This also consumes the harness's readiness posts from each cursor.
    for (who, proj) in [(alice, &a_proj), (bob, &b_proj)] {
        let _ = turn(
            &sb,
            &profile,
            who,
            proj,
            &oc_cfg,
            &room,
            "Reply with exactly: READY",
        );
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
        &sb,
        &profile,
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

    // ---- (2) bob's model reads what alice wrote, from its own session ----
    let seen = turn(
        &sb,
        &profile,
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
    let ask = nonce("ORCHID");
    let question =
        format!("hey, is the codec work finished? the release is waiting on it (ref {ask})");
    let o = bob.vox(None, &["room", "post", &room, &question]);
    assert!(o.ok, "the operator could not ask a question: {o:?}");
    until(
        alice,
        None,
        "the question to reach alice",
        &["room", "read", &room],
        |o| o.stdout.contains(&ask),
    );
    let (answer4, heard) = turn_split(
        &sb,
        &profile,
        alice,
        &a_proj,
        &oc_cfg,
        &room,
        "Did anyone ask you a question just now? Answer yes or no and quote it exactly, \
         including any reference code in it.",
    );
    let heard_it = answer4.contains(&ask);
    println!("[proof] (4) alice's model quoted the operator's prose nonce {ask}: {heard_it}");
    assert!(
        heard_it,
        "plain prose from the operator did not reach an agent's context: the answer does \
         not carry the question's nonce {ask}. The answer: {heard:?}"
    );

    // ---- (3) cursors are per session: two sessions of one identity, one daemon ----
    // The drain the OpenCode plugin runs, with two session ids of alice's. A fresh post
    // by the operator (bob) carries its own nonce.
    let mark = nonce("LANTERN");
    let o = bob.vox(
        None,
        &["room", "post", &room, &format!("cursor check {mark}")],
    );
    assert!(o.ok, "the operator could not post the cursor check: {o:?}");
    until(
        alice,
        None,
        "the cursor check to reach alice",
        &["room", "read", &room],
        |o| o.stdout.contains(&mark),
    );
    let (s1, s2) = (nonce("rehearsal-s1"), nonce("rehearsal-s2"));
    let drain = |session: &str| {
        let o = alice.vox(
            None,
            &[
                "agent",
                "hook",
                "--format",
                "text",
                "--room",
                &room,
                "--session",
                session,
            ],
        );
        assert!(o.ok, "vox agent hook --session {session}: {o:?}");
        o.stdout
    };
    let s1_first = drain(&s1);
    let s1_again = drain(&s1);
    let s2_first = drain(&s2);
    let (a, b, c) = (
        s1_first.contains(&mark),
        s1_again.contains(&mark),
        s2_first.contains(&mark),
    );
    println!(
        "[proof] (3) per-session cursors on one daemon: s1 first shows the post: {a}, s1 again: \
         {b}, s2 first: {c} (drain bytes {} / {} / {})",
        s1_first.len(),
        s1_again.len(),
        s2_first.len()
    );
    assert!(
        a,
        "CANNOT MEASURE: session s1's first drain did not show the operator's post {mark}: \
         {s1_first:?}"
    );
    assert!(
        !b,
        "session s1 was shown the same post twice, so the drain keeps no cursor for it: \
         {s1_again:?}"
    );
    assert!(
        c,
        "session s2, on the same identity and daemon, was not shown a post it never read \
         ({mark}) because session s1 had consumed it: the cursor is not per session. s2's \
         drain: {s2_first:?}"
    );
}
