//! ADR-021 F15 / ADR-020 §6 — **an urgent message from ANOTHER node interrupts its
//! addressee**, through a real `vox daemon`.
//!
//! The daemon's wake loop once woke sessions only on `NodeEvent::NewEntry`, which the node
//! emits for its own appends and never for an entry synced from a peer. So an urgent
//! message from another agent on another machine — the case the interrupt path exists
//! for — could not interrupt anybody, and no gate could see it.
//!
//! **Every participant is the shipped binary** (`support/room.rs`): an anchor (`vox node`),
//! alice's and bob's `vox daemon`, the room made with `vox room create|invite|join`, each
//! admitted with `vox trust add`, ready once each has rendered a post by the other. Bob's
//! session registers with his daemon **the way a harness does it**: its turn-start hook
//! runs `vox agent hook --room …` with Claude Code's hook JSON on stdin and the harness's
//! `CLAUDE_CODE_MESSAGING_SOCKET`/`_TOKEN` and `VOX_AGENT_NAME` in its environment. The one
//! thing that is not `vox` is that messaging socket: a stand-in for Claude Code's, recording
//! what the daemon writes to it, because no `vox` command plays a harness session. Alice
//! posts with `vox room post` on her own daemon; nothing reaches bob but by sync.
//!
//! **The hook runs in a cleared environment.** This test may itself run inside Claude Code,
//! whose `CLAUDE_CODE_MESSAGING_SOCKET` names a *real* session: inherited, it registers that
//! session as bob's, and the urgent messages below interrupt a live Claude session on the
//! machine (it happened, 2026-09-26). So `vox agent hook` gets only `PATH`, `HOME`, the
//! profile directories and the harness variables each case sets, and each registration is
//! read back and required to name the test's own endpoint before anything is posted.
//!
//! It asserts, **each for a message that arrived by sync**:
//!
//! 1. addressed to bob and urgent — bob's session is woken, exactly once;
//! 2. urgent but addressed to someone else — nothing;
//! 3. addressed to bob but not urgent — nothing;
//! 4. a wedged session (an OpenCode plugin's wake socket, registered by `vox agent hook
//!    --session` with `VOX_OPENCODE_WAKE_SOCKET`/`_TOKEN`, that accepts and never answers) does
//!    not stall bob's wakes;
//! 5. **the wake is not given to the model a second time** (V210-112). Claude Code runs its
//!    `UserPromptSubmit` hook for a message written to its messaging socket, with that message
//!    as the hook's `prompt` (measured against a live Claude Code 2.1.287). So bob's hook runs
//!    again with the wake it received as `prompt`, exactly as his harness would, and its room
//!    read must carry the two messages that woke nothing, and not the one the wake delivered.
//!
//! **Mutation.** Put the pre-F15 loop back — the daemon judges only `NewEntry`, treating
//! `Synced`/`SenderKeyReceived` and its two-second sweep as nothing to do — and this goes red
//! at (1): the urgent message reaches bob's node and his session is never woken. Drop the
//! drain's reading of its own prompt (`woken_by_prompt`) and it goes red at (5), the woken
//! message in the room read too.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Read as _;
use std::os::unix::net::UnixListener;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use support::{until, Worker};

/// A stand-in Claude Code messaging socket: every connection's bytes, as they are written.
fn listen(path: &std::path::Path) -> mpsc::Receiver<String> {
    let listener = UnixListener::bind(path).expect("bind the stand-in session socket");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf);
            if tx.send(buf).is_err() {
                return;
            }
        }
    });
    rx
}

/// `vox agent hook …` as bob's harness runs it, in a **cleared** environment: `PATH`, `HOME`,
/// bob's profile directories, and exactly the harness variables in `env`. Nothing this test
/// process inherited — a real Claude Code session's messaging socket above all — reaches it.
fn hook(bob: &Worker, env: &[(&str, &str)], args: &[&str], stdin: Option<&str>) -> String {
    use std::io::Write as _;
    let mut cmd = std::process::Command::new(support::VOX);
    cmd.env_clear();
    for key in ["PATH", "HOME", "TMPDIR"] {
        if let Some(v) = std::env::var_os(key) {
            cmd.env(key, v);
        }
    }
    cmd.args(args)
        .env("VOX_DATA_DIR", &bob.data)
        .env("VOX_CONFIG_DIR", &bob.cfg)
        .envs(env.iter().copied())
        .stdin(if stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("spawn vox agent hook");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().expect("vox agent hook ran");
    eprintln!(
        "[receipt] vox {} -> {:?}; stderr: {}",
        args.join(" "),
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    assert!(out.status.success(), "`vox agent hook` must exit 0");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The endpoint bob's daemon will wake `session` at, as the hook registered it.
fn registered_endpoint(bob: &Worker, session: &str) -> (String, String) {
    let body = std::fs::read(bob.paths.session_file(session)).unwrap_or_else(|e| {
        panic!("CANNOT MEASURE: `vox agent hook` registered no session {session}: {e}")
    });
    let v: serde_json::Value = serde_json::from_slice(&body).expect("a session registration");
    (
        v["harness"].as_str().unwrap_or_default().to_owned(),
        v["endpoint"].as_str().unwrap_or_default().to_owned(),
    )
}

/// Alice posts `text` exactly as given, through `vox room post <room> -` on her daemon.
fn post(alice: &Worker, room: &str, text: &str) {
    let o = alice.vox_in(None, &["room", "post", room, "-"], Some(text));
    assert!(o.ok, "alice could not post: {o:?}");
}

/// Everything bob's stand-in session receives within `within`, stopping early once `done`.
fn collect(
    inbox: &mpsc::Receiver<String>,
    within: Duration,
    done: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut got = Vec::new();
    let deadline = Instant::now() + within;
    while Instant::now() < deadline && !done(&got.join("\n")) {
        if let Ok(frames) = inbox.recv_timeout(Duration::from_millis(500)) {
            eprintln!("[receipt] bob's session received: {frames}");
            got.push(frames);
        }
    }
    got
}

#[test]
#[ignore = "an anchor and two vox daemons with production Argon2id; CI runs it in release"]
fn an_urgent_message_from_another_node_interrupts_its_addressee() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let r = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&r.workers[0], &r.workers[1]);
    let room = r.id.clone();
    let err_path = tmp.path().join("bob.daemon.err");

    // ---- bob's session registers with his daemon, as its harness hook does every turn ----
    let sock = tmp.path().join("session.sock");
    let inbox = listen(&sock);
    let hook_input = r#"{"session_id":"session-bob","hook_event_name":"UserPromptSubmit","cwd":"/tmp","permission_mode":"default","prompt":"hi","prompt_id":"p-1","transcript_path":"/tmp/t.jsonl"}"#;
    let sock_s = sock.to_string_lossy().into_owned();
    hook(
        bob,
        &[
            ("CLAUDE_CODE_MESSAGING_SOCKET", sock_s.as_str()),
            ("CLAUDE_CODE_MESSAGING_TOKEN", "a-token"),
            ("VOX_AGENT_NAME", "bob"),
        ],
        &["agent", "hook", "--room", &room],
        Some(hook_input),
    );
    let reg = registered_endpoint(bob, "session-bob");
    assert_eq!(
        reg,
        ("claude".to_owned(), sock_s.clone()),
        "CANNOT MEASURE: bob's session must be registered at the test's own socket, never a \
         real session's"
    );

    // Bob's daemon must be in sync with alice before the cases mean anything.
    post(alice, &room, "SYNC-MARKER");
    until(
        bob,
        None,
        "alice's marker to reach bob",
        &["room", "read", &room],
        |o| o.stdout.contains("SYNC-MARKER"),
    );

    // ---- (2) urgent, addressed to someone else: nothing ----
    post(
        alice,
        &room,
        r#"{"v":1,"type":"ask","to":["carol"],"urgent":true,"body":"carol: OTHER-ADDRESSEE"}"#,
    );
    // ---- (3) addressed to bob, not urgent: nothing ----
    post(
        alice,
        &room,
        r#"{"v":1,"type":"ask","to":["bob"],"body":"bob: NOT-URGENT"}"#,
    );
    // ---- (1) addressed to bob and urgent: woken ----
    post(
        alice,
        &room,
        r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: WAKE-UP-FROM-ALICE"}"#,
    );
    until(
        bob,
        None,
        "the urgent message to reach bob's node",
        &["room", "read", &room],
        |o| o.stdout.contains("WAKE-UP-FROM-ALICE"),
    );
    // Twenty seconds after it landed: ten sweeps of the daemon's two-second tick, and long
    // enough for a wrongly-woken or twice-woken session to show.
    let woken = collect(&inbox, Duration::from_secs(20), |_| false);
    let all = woken.join("\n");
    let wakes = woken
        .iter()
        .filter(|f| f.contains("WAKE-UP-FROM-ALICE"))
        .count();
    println!(
        "[proof] bob's session got {} frame(s) in 20s: {wakes} wake(s) for the urgent message, \
         other-addressee {}, not-urgent {}",
        woken.len(),
        all.contains("OTHER-ADDRESSEE"),
        all.contains("NOT-URGENT")
    );
    assert!(
        all.contains("WAKE-UP-FROM-ALICE"),
        "an urgent message addressed to bob, from another node, must interrupt bob's session; \
         received {woken:?}; bob's daemon stderr:\n{}",
        std::fs::read_to_string(&err_path).unwrap_or_default()
    );
    assert!(
        all.contains("a-token"),
        "the wake must authenticate with the token the harness registered: {woken:?}"
    );
    assert!(
        !all.contains("OTHER-ADDRESSEE"),
        "a message addressed to another agent must not interrupt bob"
    );
    assert!(
        !all.contains("NOT-URGENT"),
        "an addressed message that is not urgent must wait for the next turn"
    );
    assert_eq!(
        wakes, 1,
        "one urgent message wakes the session once: {woken:?}"
    );

    // ---- (5) the wake's own turn: the drain does not give the model the wake again ----
    let wake_text = woken
        .iter()
        .flat_map(|f| f.lines())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["type"] == "user")
        .and_then(|v| v["message"]["content"].as_str().map(str::to_owned))
        .unwrap_or_else(|| {
            panic!("CANNOT MEASURE (5): no user message among the frames bob's session received: {woken:?}")
        });
    let wake_turn = serde_json::json!({
        "session_id": "session-bob",
        "hook_event_name": "UserPromptSubmit",
        "cwd": "/tmp",
        "permission_mode": "default",
        "prompt": wake_text,
        "prompt_id": "p-2",
        "transcript_path": "/tmp/t.jsonl",
    })
    .to_string();
    let read = hook(
        bob,
        &[
            ("CLAUDE_CODE_MESSAGING_SOCKET", sock_s.as_str()),
            ("CLAUDE_CODE_MESSAGING_TOKEN", "a-token"),
            ("VOX_AGENT_NAME", "bob"),
        ],
        &["agent", "hook", "--room", &room],
        Some(&wake_turn),
    );
    println!(
        "[proof] the wake's own turn read: woken message {} time(s), other-addressee {}, \
         not-urgent {}",
        read.matches("WAKE-UP-FROM-ALICE").count(),
        read.matches("OTHER-ADDRESSEE").count(),
        read.matches("NOT-URGENT").count()
    );
    assert!(
        read.matches("OTHER-ADDRESSEE").count() == 1 && read.matches("NOT-URGENT").count() == 1,
        "CANNOT MEASURE (5): the wake's turn must read the two messages that woke nothing, once \
         each, or the read did not reach them: {read}"
    );
    assert_eq!(
        read.matches("WAKE-UP-FROM-ALICE").count(),
        0,
        "PRODUCT (5): the message a wake delivered must not be given to the model again in the \
         room read of the turn that wake started: {read}"
    );

    // ---- (4) a wedged session must not stall anybody else's wake ----
    // An OpenCode plugin's wake socket that accepts and never answers: its wake would wait
    // for ever.
    let wedge_path = tmp.path().join("wedge.sock");
    let wedge = UnixListener::bind(&wedge_path).expect("bind the wedged session socket");
    let wedge_url = wedge_path.to_str().unwrap().to_owned();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in wedge.incoming().flatten() {
            held.push(s); // accepted, never read, never answered
        }
    });
    hook(
        bob,
        &[
            ("VOX_OPENCODE_WAKE_SOCKET", wedge_url.as_str()),
            ("VOX_OPENCODE_WAKE_TOKEN", "wedge-token"),
            ("VOX_AGENT_NAME", "bob"),
        ],
        &[
            "agent",
            "hook",
            "--room",
            &room,
            "--session",
            "session-wedged",
        ],
        None,
    );
    let reg = registered_endpoint(bob, "session-wedged");
    assert_eq!(
        reg,
        ("opencode".to_owned(), wedge_url.clone()),
        "CANNOT MEASURE: the wedged session must be registered at the test's own endpoint, \
         never a real session's"
    );
    let registered = std::fs::read_dir(bob.paths.session_dir())
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(
        registered, 2,
        "CANNOT MEASURE: exactly two sessions registered"
    );
    for n in 1..=2 {
        post(
            alice,
            &room,
            &format!(
                r#"{{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: WEDGE-TEST-{n}"}}"#
            ),
        );
    }
    let got = collect(&inbox, Duration::from_secs(45), |g| {
        g.contains("WEDGE-TEST-1") && g.contains("WEDGE-TEST-2")
    })
    .join("\n");
    println!(
        "[proof] with a wedged session registered, bob's session got WEDGE-TEST-1 {} and \
         WEDGE-TEST-2 {}",
        got.contains("WEDGE-TEST-1"),
        got.contains("WEDGE-TEST-2")
    );
    assert!(
        got.contains("WEDGE-TEST-1") && got.contains("WEDGE-TEST-2"),
        "a wedged session stalled another session's wakes; received: {got}"
    );
}
