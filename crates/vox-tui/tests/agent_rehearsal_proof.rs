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
//! Each verdict at (1), (2) and (4) is read from what the plugin logged on that turn and what
//! `vox agent hook` handed it (recorded by the `VOX_BIN` the plugin runs), not from the answer
//! alone: the drain's text missing the row, or the plugin injecting nothing, is PRODUCT; the
//! model not repeating what it was given, or OpenCode never calling the hook, is
//! APPARATUS.
//!
//! - Make `vox agent hook` inject nothing (the drain returns before printing what is
//!   unread): red at (1) as PRODUCT, the plugin said "nothing to inject".
//! - Make `vox agent hook` drop plain prose from what it emits (every row that parses as a
//!   `say` is filtered out of the drain, so only typed envelopes are injected): (1) and (2)
//!   stay green, and it goes red at (4) as PRODUCT: the plugin injected the room, but what the
//!   drain gave it does not hold the question's nonce.
//!   (Filtering on `Envelope::parse(..).is_ok()` is not this mutant: prose parses as a
//!   `say`, so that filter drops nothing.)
//! - Key the hook's cursor by room alone, ignoring the session: red at (3), `s2` is shown
//!   nothing because `s1` already read it.
//!
//! **Known limit:** the plugin, the recorder and the model's shell run in one sandbox, so the
//! shell could write the plugin's log and the recorder's log, which the verdicts read. A tighter
//! sandbox for the shell alone is not possible: macOS refuses a sandbox inside a sandbox
//! (`sandbox_apply: Operation not permitted`, measured). The recorder itself is outside the
//! sandbox's writable root, so it cannot be replaced. Forging a log takes a model set on deceiving
//! the proof, not one exploring.

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
    std::fs::create_dir_all(project.join(".opencode/plugin"))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make {}'s project: {e}", w.name));
    let o = w.vox(None, &["agent", "plugin", "opencode", "--node", "default"]);
    assert!(
        o.ok && o.stdout.contains("vox agent hook"),
        "PRODUCT: `vox agent plugin opencode` did not print the plugin: {o:?}"
    );
    std::fs::write(project.join(".opencode/plugin/vox.js"), &o.stdout)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot install {}'s plugin: {e}", w.name));
    project
}

/// What one turn shows: the model's answer (its stdout alone), everything OpenCode printed,
/// what the plugin logged, and what `vox agent hook` handed the plugin.
struct Turn {
    answer: String,
    said: String,
    plugin_log: String,
    hook_out: String,
}

/// An agent's plugin log, and the recording `VOX_BIN` its plugin runs (`hook_recorder`), one set
/// per agent. The recorder is outside the sandbox's writable root, readable only, so a model's
/// shell cannot replace it; the two logs are inside it, as their writers run in the sandbox (see
/// the module docs' known limit).
struct Wiring {
    plugin_log: std::path::PathBuf,
    vox_bin: std::path::PathBuf,
    hook_log: std::path::PathBuf,
}

/// **What the drain handed the plugin is recorded**, so a turn's verdict knows whether the
/// room's text was put in front of the model: `VOX_BIN`, the binary the plugin runs as
/// `vox agent hook`, is a wrapper that runs the real `vox` and appends what it printed to
/// `hook_log`. The model's own `vox`, if it runs one, is the real binary.
fn hook_recorder(bin_dir: &Path, log_dir: &Path, name: &str) -> Wiring {
    std::fs::create_dir_all(bin_dir)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make the recorders' directory: {e}"));
    let vox_bin = bin_dir.join(format!("vox-hook-{name}"));
    let hook_log = log_dir.join(format!("hook-{name}.log"));
    let plugin_log = log_dir.join(format!("plugin-{name}.log"));
    std::fs::write(
        &vox_bin,
        format!(
            "#!/bin/sh\nout=$('{vox}' \"$@\")\nrc=$?\nprintf '%s\\n' \"$out\" >> '{log}'\n\
             printf '%s\\n' \"$out\"\nexit $rc\n",
            vox = VOX,
            log = hook_log.display()
        ),
    )
    .unwrap_or_else(|e| panic!("APPARATUS: cannot write the hook recorder: {e}"));
    std::fs::set_permissions(
        &vox_bin,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap_or_else(|e| panic!("APPARATUS: cannot make the hook recorder runnable: {e}"));
    Wiring {
        plugin_log,
        vox_bin,
        hook_log,
    }
}

/// One real model turn for this agent, with its room wired in, confined.
#[allow(clippy::too_many_arguments)]
fn turn(
    sb: &oc_sandbox::OcSandbox,
    profile: &Path,
    w: &Worker,
    wiring: &Wiring,
    project: &Path,
    oc_cfg: &Path,
    room: &str,
    prompt: &str,
) -> Turn {
    for f in [&wiring.plugin_log, &wiring.hook_log] {
        let _ = std::fs::write(f, "");
    }
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
        .env("VOX_BIN", &wiring.vox_bin)
        .env("VOX_PLUGIN_LOG", &wiring.plugin_log)
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run opencode in its sandbox: {e}"));
    let said = format!(
        "{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    sb.check(&said, "an `opencode run` turn");
    eprintln!("[turn {}] {prompt:?} -> {said}", w.name);
    Turn {
        answer: String::from_utf8_lossy(&out.stdout).into_owned(),
        said,
        plugin_log: std::fs::read_to_string(&wiring.plugin_log).unwrap_or_default(),
        hook_out: std::fs::read_to_string(&wiring.hook_log).unwrap_or_default(),
    }
}

/// **The verdict on a turn is what the plugin says it did, and what the drain gave it**, not
/// the answer alone: a model may decline to repeat what it was given, and a drain may hand the
/// plugin text without the row that matters.
///
/// - injected, the drain's text holding `target`, and the answer holding it: green;
/// - injected and the drain's text holding `target`, but not the answer: APPARATUS (the
///   model chose not to repeat it);
/// - injected without `target` in the drain's text, or "nothing to inject", "threw" or "no
///   text part": PRODUCT, whatever the answer;
/// - VOX_ROOM unset: APPARATUS; no `chat.message` at all: APPARATUS.
fn judge(t: &Turn, target: &str, step: &str, answer_has: bool) {
    let hooked: Vec<&str> = t
        .plugin_log
        .lines()
        .filter(|l| l.contains("chat.message:"))
        .collect();
    let said_of = |what: &str| hooked.iter().find(|l| l.contains(what)).copied();
    if said_of("chat.message: injected").is_some() {
        assert!(
            t.hook_out.contains(target),
            "PRODUCT: {step}: the plugin injected the room, but what `vox agent hook` gave it \
             does not hold {target:?}: {:?}",
            t.hook_out
        );
        assert!(
            answer_has,
            "APPARATUS (the model, not vox): {step}: the plugin injected the room with {target:?}, and the model \
             did not repeat it. The answer: {:?}",
            t.answer
        );
    } else if let Some(line) = said_of("nothing to inject")
        .or_else(|| said_of("threw"))
        .or_else(|| said_of("no text part"))
    {
        panic!("PRODUCT: {step}: the room never reached the model: the plugin said {line:?}");
    } else if let Some(line) = said_of("VOX_ROOM is unset") {
        panic!(
            "APPARATUS: {step}: the proof did not give OpenCode the room: the plugin said {line:?}"
        );
    } else {
        panic!(
            "APPARATUS (OpenCode, not vox): {step}: OpenCode never called the plugin's chat.message on this \
             turn ({}). OpenCode printed: {:?}",
            if hooked.is_empty() {
                "no chat.message line".to_owned()
            } else {
                format!("it said {hooked:?}")
            },
            t.said
        );
    }
}

/// A per-run token, unguessable by a model and absent from every prompt.
fn nonce(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|e| panic!("APPARATUS: the clock is before 1970: {e}"))
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
        "APPARATUS (precondition not met): the rehearsal needs `opencode` on PATH"
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot build the runtime: {e}"));
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make a temp directory: {e}"));
    let r = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&r.workers[0], &r.workers[1]);
    let room = r.id.clone();
    // **Every model turn runs confined** (support/oc_sandbox.rs): a throwaway HOME, a fixed
    // environment, a whitelist of readable paths, a canary in the real HOME it must never
    // see. The plugins' hooks need the two agents' vox profiles; nothing else outside the
    // sandbox is readable. A missing credential is CANNOT MEASURE there.
    let sb = oc_sandbox::OcSandbox::new(tmp.path());
    // The recorders are outside the writable root and only readable in the sandbox; their logs
    // are inside it.
    let recorders = tmp.path().join("recorders");
    let (a_wire, b_wire) = (
        hook_recorder(&recorders, &sb.root, "alice"),
        hook_recorder(&recorders, &sb.root, "bob"),
    );
    let profile = sb.profile(
        "rehearsal",
        &[&alice.data, &alice.cfg, &bob.data, &bob.cfg],
        &[Path::new(VOX), &recorders],
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
    for (who, wire, proj) in [(alice, &a_wire, &a_proj), (bob, &b_wire, &b_proj)] {
        let _ = turn(
            &sb,
            &profile,
            who,
            wire,
            proj,
            &oc_cfg,
            &room,
            "Reply with exactly: READY",
        );
    }

    // ---- the operator speaks, as a person, in plain prose ----
    // Addressed to alice's node by its whole fingerprint, as `vox room roster` prints it: an
    // envelope's `to` names nodes, and a name is the reader's own, which only `--to` resolves.
    let assignment = serde_json::json!({
        "v": 1,
        "type": "assign",
        "to": [vox_core::node::link::b32_encode(&alice.fp)],
        "body": "port the wire codec to the new envelope format",
        "data": {"resource": "port-the-codec"},
    })
    .to_string();
    let o = alice.vox(None, &["room", "post", &room, &assignment]);
    assert!(
        o.ok,
        "PRODUCT: the operator could not post the assignment: {o:?}"
    );
    until(
        bob,
        None,
        "the assignment to reach bob",
        &["room", "read", &room],
        |o| o.stdout.contains("port the wire codec"),
    );

    // ---- (1) alice's model reads work it was never prompted with ----
    let t1 = turn(
        &sb,
        &profile,
        alice,
        &a_wire,
        &a_proj,
        &oc_cfg,
        &room,
        "What task have you been assigned? Answer with just the task.",
    );
    let read_assignment = t1.answer.contains("codec") || t1.answer.contains("wire");
    println!("[proof] (1) alice's model named its assignment: {read_assignment}");
    judge(
        &t1,
        "port the wire codec",
        "(1) alice's model reads the assignment it was never prompted with",
        read_assignment,
    );

    // ---- alice reports a result, as an agent would ----
    let result = r#"{"v":1,"type":"result","re":"port-the-codec","body":"done: the codec now speaks the envelope format. verification token QUORUM-8812"}"#;
    let o = alice.vox(None, &["room", "post", &room, result]);
    assert!(o.ok, "PRODUCT: alice could not post her result: {o:?}");
    until(
        bob,
        None,
        "the result to reach bob",
        &["room", "read", &room],
        |o| o.stdout.contains("QUORUM-8812"),
    );

    // ---- (2) bob's model reads what alice wrote, from its own session ----
    let t2 = turn(
        &sb,
        &profile,
        bob,
        &b_wire,
        &b_proj,
        &oc_cfg,
        &room,
        "What verification token was reported in your room? Answer with just the token.",
    );
    println!(
        "[proof] (2) bob's model repeated alice's token: {}",
        t2.answer.contains("QUORUM-8812")
    );
    judge(
        &t2,
        "QUORUM-8812",
        "(2) a message one agent session wrote reaches the other",
        t2.answer.contains("QUORUM-8812"),
    );

    // ---- (4) the operator asks a question in prose, and it lands ----
    let ask = nonce("ORCHID");
    let question =
        format!("hey, is the codec work finished? the release is waiting on it (ref {ask})");
    let o = bob.vox(None, &["room", "post", &room, &question]);
    assert!(
        o.ok,
        "PRODUCT: the operator could not ask a question: {o:?}"
    );
    until(
        alice,
        None,
        "the question to reach alice",
        &["room", "read", &room],
        |o| o.stdout.contains(&ask),
    );
    let t4 = turn(
        &sb,
        &profile,
        alice,
        &a_wire,
        &a_proj,
        &oc_cfg,
        &room,
        "Did anyone ask you a question just now? Answer yes or no and quote it exactly, \
         including any reference code in it.",
    );
    let heard_it = t4.answer.contains(&ask);
    println!("[proof] (4) alice's model quoted the operator's prose nonce {ask}: {heard_it}");
    judge(
        &t4,
        &ask,
        "(4) the operator's plain prose reaches an agent's context",
        heard_it,
    );

    // ---- (3) cursors are per session: two sessions of one identity, one daemon ----
    // The drain the OpenCode plugin runs, with two session ids of alice's. A fresh post
    // by the operator (bob) carries its own nonce.
    let mark = nonce("LANTERN");
    let o = bob.vox(
        None,
        &["room", "post", &room, &format!("cursor check {mark}")],
    );
    assert!(
        o.ok,
        "PRODUCT: the operator could not post the cursor check: {o:?}"
    );
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
                "--node",
                "default",
                "--format",
                "text",
                "--room",
                &room,
                "--session",
                session,
            ],
        );
        assert!(
            o.ok,
            "PRODUCT: `vox agent hook --session {session}` failed: {o:?}"
        );
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
        "PRODUCT (staging): session s1's first drain did not show the operator's post {mark}: \
         {s1_first:?}"
    );
    assert!(
        !b,
        "PRODUCT: session s1 was shown the same post twice, so the drain keeps no cursor for \
         it: {s1_again:?}"
    );
    assert!(
        c,
        "PRODUCT: session s2, on the same identity and daemon, was not shown a post it never read \
         ({mark}) because session s1 had consumed it: the cursor is not per session. s2's \
         drain: {s2_first:?}"
    );
}
