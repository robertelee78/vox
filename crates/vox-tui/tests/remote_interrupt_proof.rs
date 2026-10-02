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
//! **A wake announces; the message arrives once, through the room read** (V030-15). The wake
//! is a notice — how many urgent messages, from whom, in which room — and no byte of any
//! message. Claude Code runs its `UserPromptSubmit` hook for a message written to its messaging
//! socket, with that message as the hook's `prompt`, idle, mid-generation or between tool calls
//! (measured against a live Claude Code 2.1.287), so the drain runs in the turn the wake starts.
//! Here bob's hook runs on the wake it received exactly as his harness would.
//!
//! `an_urgent_message_from_another_node_interrupts_its_addressee` asserts, **each for a message
//! that arrived by sync**:
//!
//! 1. addressed to bob and urgent — bob's session is woken, exactly once, by a notice naming
//!    one urgent message from alice; **no byte of any message body** reaches the wake endpoint
//!    (each body carries a canary);
//! 2. urgent but addressed to someone else — nothing;
//! 3. addressed to bob but not urgent — nothing;
//! 5. the turn the wake starts reads the urgent message **once**, first, ahead of the two older
//!    ones that woke nothing, which it also reads once each;
//! 6. **one notice outstanding at a time**: a second urgent message, while the first one's notice
//!    is unread, wakes nothing, and the daemon says it held it;
//! 7. **recounted before it fires**: once the session's read has taken that message, nothing
//!    is sent for it, and the daemon says it was already read;
//! 4. a wedged session (an OpenCode plugin's wake socket, registered by `vox agent hook
//!    --session` with `VOX_OPENCODE_WAKE_SOCKET`/`_TOKEN`, that accepts and never answers) does
//!    not stall bob's wakes;
//! 9. **a notice that is not taken stays owed**: a plugin socket that refuses the first prompt
//!    gets the notice again once the hold (the profile's `agent_wake_hold`, here 6 s) has passed.
//!
//! `an_idle_agent_is_told_when_a_reply_to_it_is_waiting` (V030-20): bob's session `asker` asks
//! alice something, and alice answers (`--re`), each answer carrying a canary. The schedule is
//! the profile's real setting, shortened here (`agent_reply_nudges = 4s 8s 12s` in bob's
//! settings file); its default is 5, 20 and 60 minutes.
//!
//! 1. while the session is **busy** (its turn started and has not ended) — no notice;
//! 2. at its **end of turn** (Claude Code's `Stop` hook, run as `vox agent hook`, printing
//!    nothing) — exactly one notice, naming one reply from alice, with no canary byte;
//! 3. then one after each wait of the schedule, 4 s and then 8 s, and no more: four in all;
//! 4. **a daemon restart resumes the series**: restarted after the third notice, the fourth still
//!    comes, no sooner than 12 s after the third, and no fifth;
//! 5. **a fresh reply starts it again**: one more notice;
//! 6. the turn that notice starts reads each answer **once**; and an answer the session read
//!    before going idle again is **never announced**;
//! 7. `SessionEnd` removes the registration: a later answer wakes nothing;
//! 8. `vox agent plugin claude` prints the `UserPromptSubmit`, `Stop` and `SessionEnd` entries;
//! 9. **what lands while the daemon is down is announced when it starts**: bob's daemon stopped,
//!    alice answers an idle session's question and sends it an urgent message; once the daemon
//!    is back, both are counted in a notice. They reach bob's node by sync after it starts, so
//!    this does not exercise the daemon's startup count (which guards only a crash between a row
//!    landing and the next sweep, and is unproven by mutant); it goes red if what arrives after a
//!    restart is not announced.
//!
//! (8) of the first test: sixty older messages and one urgent, more than one turn's 50: the turn
//! the wake starts shows the urgent one first and 49 others, a second urgent wake counts only the
//! new one (the first was shown ahead of the cursor), and over three turns every message is shown
//! exactly once.
//!
//! `two_sessions_answering_each_other_stop_being_told_at_the_hop_budget` (ADR-020 §9): a session
//! on each node answers every answer it is told of. Each answer spends a hop, and an answer with
//! none left is announced to nobody: seven notices (hops 7 down to 1), then the exchange stops.
//!
//! Every red says PRODUCT, with what the product sent or said, or APPARATUS, naming the
//! staging that was not achieved.
//!
//! **Mutation**, one per claim, each red at its own assertion: the message put back in the wake
//! (V030-15 (1), V030-20 (2)); no recount — the daemon counting from the start of the room rather
//! than the cursor (V030-15 (7), V030-20 (6)); no outstanding-notice rule (V030-15 (6)); no idle
//! gate (V030-20 (1)); no generation, so a fresh reply is not announced (V030-20 (5)); the
//! series held in memory (V030-20 (4)); a reply announced with no hops left (the exchange runs to
//! its bound of twenty rounds); and the delivered-ahead record never written, ignored by the
//! drain, ignored by the count, or a cursor moved past rows not shown ((8)). The pre-F15 loop — the daemon judging only `NewEntry` —
//! goes red at V030-15 (1).

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
    assert!(
        out.status.success(),
        "PRODUCT: `vox agent hook` must exit 0 whatever happens, so it never breaks a turn; it \
         exited {:?}",
        out.status.code()
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The endpoint bob's daemon will wake `session` at, as the hook registered it.
fn registered_endpoint(bob: &Worker, session: &str) -> (String, String) {
    let body = std::fs::read(bob.paths.session_file(session)).unwrap_or_else(|e| {
        panic!("APPARATUS: `vox agent hook` registered no session {session}: {e}")
    });
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_else(|e| {
        panic!("PRODUCT: the session record `vox agent hook` wrote does not parse: {e}")
    });
    (
        v["harness"].as_str().unwrap_or_default().to_owned(),
        v["endpoint"].as_str().unwrap_or_default().to_owned(),
    )
}

/// `w` posts `text` exactly as given, through `vox room post <room> -` on its daemon.
fn post_text(w: &Worker, room: &str, text: &str) {
    let o = w.vox_in(None, &["room", "post", room, "-"], Some(text));
    assert!(o.ok, "APPARATUS: {} could not post: {o:?}", w.name);
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

/// The user message each stand-in frame carries: what the harness would put before the model.
fn contents(frames: &[String]) -> Vec<String> {
    frames
        .iter()
        .flat_map(|f| f.lines())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["type"] == "user")
        .filter_map(|v| v["message"]["content"].as_str().map(str::to_owned))
        .collect()
}

/// A stand-in for the Vox OpenCode plugin's wake socket that **refuses** its first `refuse`
/// prompts, as the plugin does when OpenCode will not take one (`{"error":…}`, not gone), and
/// takes the rest. Each prompt's text, when it arrived, and whether it was taken.
fn flaky(path: &std::path::Path, refuse: usize) -> mpsc::Receiver<(Instant, String, bool)> {
    use std::io::{BufRead as _, Write as _};
    let listener = UnixListener::bind(path).expect("bind the stand-in plugin socket");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for (n, stream) in listener.incoming().enumerate() {
            let Ok(stream) = stream else { continue };
            let mut reader = std::io::BufReader::new(&stream);
            let (mut auth, mut prompt) = (String::new(), String::new());
            if reader.read_line(&mut auth).is_err() || reader.read_line(&mut prompt).is_err() {
                continue;
            }
            let text = serde_json::from_str::<serde_json::Value>(prompt.trim())
                .ok()
                .and_then(|v| v["text"].as_str().map(str::to_owned))
                .unwrap_or_default();
            let taken = n >= refuse;
            let answer = if taken {
                r#"{"ok":true}"#
            } else {
                r#"{"error":"the session would not take it"}"#
            };
            let _ = writeln!(&stream, "{answer}");
            eprintln!("[receipt] the plugin socket got (taken {taken}): {text}");
            if tx.send((Instant::now(), text, taken)).is_err() {
                return;
            }
        }
    });
    rx
}

/// The next notice `inbox` receives within `within`, and when it arrived.
fn next_notice(inbox: &mpsc::Receiver<String>, within: Duration) -> Option<(Instant, String)> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(frame) = inbox.recv_timeout(Duration::from_millis(50)) {
            let at = Instant::now();
            eprintln!("[receipt] the session received: {frame}");
            if let Some(c) = contents(&[frame]).into_iter().next() {
                return Some((at, c));
            }
        }
    }
    None
}

/// A Claude Code hook input for `event`, for `session`, carrying `prompt` when the event has one.
fn hook_json(event: &str, session: &str, prompt: Option<&str>) -> String {
    let mut v = serde_json::json!({
        "session_id": session,
        "hook_event_name": event,
        "cwd": "/tmp",
        "transcript_path": "/tmp/t.jsonl",
    });
    if let Some(p) = prompt {
        v["prompt"] = p.into();
        v["permission_mode"] = "default".into();
        v["prompt_id"] = "p".into();
    }
    if event == "Stop" {
        v["stop_reason"] = "end_turn".into();
        v["last_assistant_message"] = "done".into();
    }
    v.to_string()
}

/// The `additionalContext` a Claude Code drain injected, or nothing.
fn injected(stdout: &str) -> String {
    serde_json::from_str::<serde_json::Value>(stdout.trim())
        .ok()
        .and_then(|v| {
            v["hookSpecificOutput"]["additionalContext"]
                .as_str()
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

/// Record a failed claim and carry on, so one mutant shows every red.
fn check(failures: &mut Vec<String>, ok: bool, what: String) {
    if !ok {
        eprintln!("[red] {what}");
        failures.push(what);
    }
}

fn daemon_err(tmp: &std::path::Path, name: &str) -> String {
    ["daemon.err", "daemon.restart.err"]
        .iter()
        .map(|f| std::fs::read_to_string(tmp.join(format!("{name}.{f}"))).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
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
    let bob_err = || daemon_err(tmp.path(), "bob");
    let mut failures = Vec::new();

    // ---- bob's session registers with his daemon, as its harness hook does every turn ----
    let sock = tmp.path().join("session.sock");
    let inbox = listen(&sock);
    let sock_s = sock.to_string_lossy().into_owned();
    let bob_env = [
        ("CLAUDE_CODE_MESSAGING_SOCKET", sock_s.as_str()),
        ("CLAUDE_CODE_MESSAGING_TOKEN", "a-token"),
        ("VOX_AGENT_NAME", "bob"),
    ];
    // bob's harness, starting a turn on `prompt`: its drain's injection.
    let turn = |prompt: &str| {
        injected(&hook(
            bob,
            &bob_env,
            &["agent", "hook", "--room", &room],
            Some(&hook_json("UserPromptSubmit", "session-bob", Some(prompt))),
        ))
    };
    let _ = turn("hi");
    let reg = registered_endpoint(bob, "session-bob");
    assert_eq!(
        reg,
        ("claude".to_owned(), sock_s.clone()),
        "APPARATUS: bob's session must be registered at the test's own socket, never a \
         real session's"
    );

    // Bob's daemon must be in sync with alice, and his session must have read everything so far,
    // before the cases mean anything.
    post(alice, &room, "SYNC-MARKER");
    until(
        bob,
        None,
        "alice's marker to reach bob",
        &["room", "read", &room],
        |o| o.stdout.contains("SYNC-MARKER"),
    );
    let _ = turn("hi");

    // ---- (2) urgent, addressed to someone else; (3) addressed to bob, not urgent ----
    post(
        alice,
        &room,
        r#"{"v":1,"type":"ask","to":["carol"],"urgent":true,"body":"carol: OTHER-ADDRESSEE"}"#,
    );
    post(
        alice,
        &room,
        r#"{"v":1,"type":"ask","to":["bob"],"body":"bob: NOT-URGENT"}"#,
    );
    // ---- (1) addressed to bob and urgent: woken, by a notice that carries none of it ----
    post(
        alice,
        &room,
        r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: CANARY-URGENT-1 wake up"}"#,
    );
    until(
        bob,
        None,
        "the urgent message to reach bob's node",
        &["room", "read", &room],
        |o| o.stdout.contains("CANARY-URGENT-1"),
    );
    // Twenty seconds after it landed: ten sweeps of the daemon's two-second tick, and long
    // enough for a wrongly-woken or twice-woken session to show.
    let frames = collect(&inbox, Duration::from_secs(20), |_| false);
    let all = frames.join("\n");
    let wakes = contents(&frames);
    println!(
        "[proof] (1)-(3) bob's session got {} frame(s) in 20s, {} notice(s): {wakes:?}; \
         canary/other/not-urgent bytes at the endpoint: {} {} {}",
        frames.len(),
        wakes.len(),
        all.contains("CANARY-URGENT"),
        all.contains("OTHER-ADDRESSEE"),
        all.contains("NOT-URGENT")
    );
    check(
        &mut failures,
        wakes.len() == 1
            && wakes[0].contains("1 urgent message addressed to you from alice")
            && all.contains("a-token"),
        format!(
            "PRODUCT (1): one urgent message from alice must wake bob's session once, with a \
             notice naming one urgent message from alice and the registered token; received \
             {frames:?}; bob's daemon:\n{}",
            bob_err()
        ),
    );
    check(
        &mut failures,
        !all.contains("CANARY-URGENT") && !all.contains("wake up"),
        format!("PRODUCT (1): no byte of the message may reach the wake endpoint: {frames:?}"),
    );
    check(
        &mut failures,
        !all.contains("OTHER-ADDRESSEE") && !all.contains("NOT-URGENT"),
        format!("PRODUCT (2)/(3): only the urgent message to bob may wake him: {frames:?}"),
    );

    // ---- (5) the wake's own turn reads the message once, first ----
    let Some(wake_text) = wakes.first().cloned() else {
        panic!(
            "APPARATUS (5)-(7): bob's session was never woken; {} claim(s) failed:\n- {}",
            failures.len(),
            failures.join("\n- ")
        );
    };
    let read = turn(&wake_text);
    let at = |m: &str| read.find(m).unwrap_or(usize::MAX);
    println!(
        "[proof] (5) the wake's own turn read: the urgent message {} time(s), other-addressee \
         {}, not-urgent {}; the urgent one first {}",
        read.matches("CANARY-URGENT-1").count(),
        read.matches("OTHER-ADDRESSEE").count(),
        read.matches("NOT-URGENT").count(),
        at("CANARY-URGENT-1") < at("OTHER-ADDRESSEE").min(at("NOT-URGENT"))
    );
    assert!(
        read.matches("OTHER-ADDRESSEE").count() == 1 && read.matches("NOT-URGENT").count() == 1,
        "APPARATUS (5): the wake's turn must read the two messages that woke nothing, once \
         each, or the read did not reach them: {read}"
    );
    check(
        &mut failures,
        read.matches("CANARY-URGENT-1").count() == 1,
        format!(
            "PRODUCT (5): the turn the wake started must give the model the urgent message \
             exactly once: {read}"
        ),
    );
    check(
        &mut failures,
        at("CANARY-URGENT-1") < at("OTHER-ADDRESSEE").min(at("NOT-URGENT")),
        format!("PRODUCT (5): the urgent message must come first in the read: {read}"),
    );

    // ---- (6) one notice outstanding at a time ----
    post(
        alice,
        &room,
        r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: CANARY-URGENT-2"}"#,
    );
    let got = contents(&collect(&inbox, Duration::from_secs(30), |g| {
        g.contains("\"user\"")
    }));
    assert!(
        got.len() == 1,
        "APPARATUS (6): a second urgent message, after the first was read, must wake bob \
         for the outstanding-notice case to mean anything; got {got:?}; bob's daemon:\n{}",
        bob_err()
    );
    let second = got[0].clone();
    post(
        alice,
        &room,
        r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: CANARY-URGENT-3"}"#,
    );
    until(
        bob,
        None,
        "the third urgent message to reach bob's node",
        &["room", "read", &room],
        |o| o.stdout.contains("CANARY-URGENT-3"),
    );
    let held = contents(&collect(&inbox, Duration::from_secs(10), |_| false));
    let said_held = bob_err().contains("not waking session session-bob again yet");
    println!(
        "[proof] (6) with a notice outstanding, a further urgent message woke bob {} time(s); \
         the daemon said it held it: {said_held}",
        held.len()
    );
    check(
        &mut failures,
        held.is_empty(),
        format!(
            "PRODUCT (6): no further wake while the first notice is outstanding (unread, inside \
             the hold); got {held:?}"
        ),
    );
    check(
        &mut failures,
        said_held,
        format!(
            "PRODUCT (6): the daemon must say it held the notice for the third message; its \
             stderr:\n{}",
            bob_err()
        ),
    );

    // ---- (7) recounted before it fires: read first, nothing sent ----
    let read = turn(&second);
    assert!(
        read.contains("CANARY-URGENT-2") && read.contains("CANARY-URGENT-3"),
        "APPARATUS (7): the session's read must take both held messages first: {read}"
    );
    let after = contents(&collect(&inbox, Duration::from_secs(10), |_| false));
    let said_read = bob_err().contains("it already read the urgent message(s)");
    println!(
        "[proof] (7) once the session had read them, the daemon woke it {} time(s); it said \
         they were already read: {said_read}",
        after.len()
    );
    check(
        &mut failures,
        after.is_empty() && said_read,
        format!(
            "PRODUCT (7): a held urgent message the session read first must wake nothing, and \
             the daemon must say it was already read; got {after:?}; bob's daemon:\n{}",
            bob_err()
        ),
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
        "APPARATUS: the wedged session must be registered at the test's own endpoint, \
         never a real session's"
    );
    let registered = std::fs::read_dir(bob.paths.session_dir())
        .map(|d| {
            d.filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(registered, 2, "APPARATUS: exactly two sessions registered");
    post(
        alice,
        &room,
        r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: WEDGE-TEST"}"#,
    );
    let got = contents(&collect(&inbox, Duration::from_secs(45), |g| {
        g.contains("\"user\"")
    }));
    println!("[proof] (4) with a wedged session registered, bob's session got {got:?}");
    check(
        &mut failures,
        got.iter()
            .any(|c| c.contains("1 urgent message addressed to you from alice")),
        format!(
            "PRODUCT (4): a wedged session stalled another session's wake; received {got:?}; \
             bob's daemon:\n{}",
            bob_err()
        ),
    );

    // ---- (8) a bounded read shows the urgent message first, and loses nothing behind it ----
    // Sixty older messages and one urgent: more than one turn's 50. The turn the wake starts
    // shows the urgent one first and 49 of the others; the next shows the rest. Each once.
    let _ = turn("catch up");
    let _ = collect(&inbox, Duration::from_secs(3), |_| false);
    for i in 0..60 {
        post(alice, &room, &format!("BULK-{i:02}-ROW"));
    }
    post(
        alice,
        &room,
        r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: CANARY-AHEAD-1"}"#,
    );
    until(
        bob,
        None,
        "the sixty messages and the urgent one to reach bob's node",
        &["room", "read", &room],
        |o| o.stdout.contains("CANARY-AHEAD-1") && o.stdout.contains("BULK-59-ROW"),
    );
    let w1 = contents(&collect(&inbox, Duration::from_secs(30), |g| {
        g.contains("\"user\"")
    }));
    assert!(
        w1.len() == 1,
        "APPARATUS (8): the urgent message must wake bob for the bounded read to be staged; got \
         {w1:?}; bob's daemon:\n{}",
        bob_err()
    );
    let turn1 = turn(&w1[0]);
    let bulk = |t: &str| {
        (0..60)
            .filter(|i| t.contains(&format!("BULK-{i:02}-ROW")))
            .count()
    };
    let first_row = turn1.lines().find(|l| l.starts_with('[')).unwrap_or("");
    println!(
        "[proof] (8) turn 1: the urgent message first {}, older messages {}, said the rest \
         follow {}",
        first_row.contains("CANARY-AHEAD-1"),
        bulk(&turn1),
        turn1.contains("more unread message(s) not shown")
    );
    assert!(
        turn1.contains("more unread message(s) not shown"),
        "APPARATUS (8): the first read must be bounded, or nothing is shown ahead of the cursor: \
         {turn1}"
    );
    check(
        &mut failures,
        first_row.contains("CANARY-AHEAD-1") && bulk(&turn1) == 49,
        format!(
            "PRODUCT (8): a bounded read must show the urgent message first, then 49 older ones: \
             {turn1}"
        ),
    );
    // A second urgent message: the first was already shown, so the wake counts one.
    post(
        alice,
        &room,
        r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: CANARY-AHEAD-2"}"#,
    );
    let w2 = contents(&collect(&inbox, Duration::from_secs(30), |g| {
        g.contains("\"user\"")
    }));
    println!("[proof] (8) the wake after turn 1: {w2:?}");
    check(
        &mut failures,
        w2.len() == 1 && w2[0].contains("1 urgent message addressed to you"),
        format!(
            "PRODUCT (8): a message already shown ahead of the cursor must not be counted again: \
             {w2:?}; bob's daemon:\n{}",
            bob_err()
        ),
    );
    let turn2 = turn(w2.first().map_or("go on", String::as_str));
    let turn3 = turn("and again");
    let all3 = format!("{turn1}\n{turn2}\n{turn3}");
    let once: Vec<String> = (0..60)
        .map(|i| format!("BULK-{i:02}-ROW"))
        .chain(["CANARY-AHEAD-1".to_owned(), "CANARY-AHEAD-2".to_owned()])
        .filter(|m| all3.matches(m.as_str()).count() != 1)
        .collect();
    println!(
        "[proof] (8) over three turns: turn 2 older {}, turn 3 older {}; messages not shown \
         exactly once: {once:?}",
        bulk(&turn2),
        bulk(&turn3)
    );
    check(
        &mut failures,
        once.is_empty()
            && turn2
                .lines()
                .find(|l| l.starts_with('['))
                .is_some_and(|l| l.contains("CANARY-AHEAD-2")),
        format!(
            "PRODUCT (8): every message must be shown exactly once over the turns, the new \
             urgent one first; not once: {once:?}; turn 2: {turn2}; turn 3: {turn3}"
        ),
    );

    // ---- (9) a notice that does not arrive stays owed, and is sent again after the hold ----
    // The hold is the profile's own setting, shortened to 6 s (its default is 10 minutes).
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(bob.paths.config_file())
            .expect("APPARATUS: open bob's settings file");
        writeln!(f, "\nagent_wake_hold = 6s").unwrap();
    }
    let flaky_path = tmp.path().join("flaky.sock");
    let attempts = flaky(&flaky_path, 1);
    let flaky_s = flaky_path.to_string_lossy().into_owned();
    hook(
        bob,
        &[
            ("VOX_OPENCODE_WAKE_SOCKET", flaky_s.as_str()),
            ("VOX_OPENCODE_WAKE_TOKEN", "flaky-token"),
            ("VOX_AGENT_NAME", "flaky"),
        ],
        &[
            "agent",
            "hook",
            "--room",
            &room,
            "--session",
            "session-flaky",
        ],
        None,
    );
    assert_eq!(
        registered_endpoint(bob, "session-flaky"),
        ("opencode".to_owned(), flaky_s.clone()),
        "APPARATUS: session-flaky must be registered at the test's own socket"
    );
    post(
        alice,
        &room,
        r#"{"v":1,"type":"ask","to":["flaky"],"urgent":true,"body":"flaky: CANARY-RETRY"}"#,
    );
    let Ok(refused) = attempts.recv_timeout(Duration::from_secs(30)) else {
        panic!(
            "APPARATUS (9): the urgent message never reached session-flaky's socket, so its \
             refusal was never staged; bob's daemon:\n{}",
            bob_err()
        );
    };
    let retried = attempts.recv_timeout(Duration::from_secs(30)).ok();
    let gap = retried.as_ref().map(|r| (r.0 - refused.0).as_secs_f64());
    println!(
        "[proof] (9) the first notice was refused; tried again {}s later, taken {}; the daemon \
         said it stays owed: {}",
        gap.map_or("never".to_owned(), |g| format!("{g:.1}")),
        retried.as_ref().is_some_and(|r| r.2),
        bob_err().contains("it stays owed")
    );
    check(
        &mut failures,
        retried.as_ref().is_some_and(|r| {
            r.2 && r.1.contains("1 urgent message addressed to you from alice")
                && !r.1.contains("CANARY-RETRY")
        }) && gap.is_some_and(|g| g >= 5.5),
        format!(
            "PRODUCT (9): a notice that was not taken must stay owed and be sent again once the \
             6 s hold has passed; refused at once, then {:?} after {gap:?} s; bob's daemon:\n{}",
            retried.map(|r| r.1),
            bob_err()
        ),
    );

    assert!(
        failures.is_empty(),
        "{} claim(s) failed:\n- {}",
        failures.len(),
        failures.join("\n- ")
    );
}

#[test]
#[ignore = "an anchor and two vox daemons with production Argon2id, and a daemon restart; CI runs it in release"]
fn an_idle_agent_is_told_when_a_reply_to_it_is_waiting() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let mut r = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let room = r.id.clone();
    let bob_err = || daemon_err(tmp.path(), "bob");
    let mut failures = Vec::new();

    // The schedule is the profile's own setting, shortened: 4, 8 and 12 s, not 5, 20 and 60
    // minutes. Three different waits, so a notice sent on the wrong step's wait shows.
    {
        use std::io::Write as _;
        let cfg = r.workers[1].paths.config_file();
        std::fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg)
            .expect("APPARATUS: open bob's settings file");
        writeln!(f, "\nagent_reply_nudges = 4s 8s 12s").unwrap();
    }

    // ---- (8) the entries a person merges into Claude Code's settings ----
    let printed = r.workers[1].vox(None, &["agent", "plugin", "claude"]);
    let entries: serde_json::Value =
        serde_json::from_str(&printed.stdout).unwrap_or(serde_json::Value::Null);
    let runs_hook = |event: &str| {
        entries["hooks"][event][0]["hooks"][0]["command"] == "vox agent hook"
            && entries["hooks"][event][0]["hooks"][0]["type"] == "command"
    };
    println!(
        "[proof] (8) `vox agent plugin claude`: UserPromptSubmit {}, Stop {}, SessionEnd {}",
        runs_hook("UserPromptSubmit"),
        runs_hook("Stop"),
        runs_hook("SessionEnd")
    );
    check(
        &mut failures,
        printed.ok && runs_hook("UserPromptSubmit") && runs_hook("Stop") && runs_hook("SessionEnd"),
        format!(
            "PRODUCT (8): `vox agent plugin claude` must print UserPromptSubmit, Stop and \
             SessionEnd entries running `vox agent hook`: {printed:?}"
        ),
    );

    // ---- bob's session `asker` registers, as its harness hook does at the top of a turn ----
    let sock = tmp.path().join("asker.sock");
    let inbox = listen(&sock);
    let sock_s = sock.to_string_lossy().into_owned();
    let env = [
        ("CLAUDE_CODE_MESSAGING_SOCKET", sock_s.as_str()),
        ("CLAUDE_CODE_MESSAGING_TOKEN", "asker-token"),
        ("VOX_AGENT_NAME", "asker"),
    ];
    let event = |bob: &Worker, name: &str, prompt: Option<&str>| {
        hook(
            bob,
            &env,
            &["agent", "hook", "--room", &room],
            Some(&hook_json(name, "asker", prompt)),
        )
    };
    let _ = event(&r.workers[1], "UserPromptSubmit", Some("ask alice"));
    assert_eq!(
        registered_endpoint(&r.workers[1], "asker"),
        ("claude".to_owned(), sock_s.clone()),
        "APPARATUS: asker must be registered at the test's own socket"
    );
    // It asks alice, as its model would with `vox room post`.
    let o = r.workers[1].vox_in(
        Some("asker"),
        &[
            "room", "post", &room, "--type", "ask", "--to", "alice", "--json", "-",
        ],
        Some("What is the build number?"),
    );
    assert!(o.ok, "APPARATUS: asker could not post its question: {o:?}");
    let q = o.json()["entry_hash"]
        .as_str()
        .expect("`vox room post --json` names the entry")
        .to_owned();
    until(
        &r.workers[0],
        None,
        "the question to reach alice",
        &["room", "read", &room],
        |o| o.stdout.contains("What is the build number?"),
    );
    let answer = |alice: &Worker, bob: &Worker, canary: &str| {
        let o = alice.vox_in(
            Some("alice-s"),
            &["room", "post", &room, "--type", "answer", "--re", &q, "-"],
            Some(&format!("{canary}: build 42")),
        );
        assert!(o.ok, "APPARATUS: alice could not answer: {o:?}");
        until(
            bob,
            None,
            "alice's answer to reach bob",
            &["room", "read", &room],
            |o| o.stdout.contains(canary),
        );
    };

    // ---- (1) busy: an answer waits, and nothing is sent ----
    answer(&r.workers[0], &r.workers[1], "CANARY-REPLY-1");
    let busy = contents(&collect(&inbox, Duration::from_secs(10), |_| false));
    println!("[proof] (1) while busy, asker got {} notice(s)", busy.len());
    check(
        &mut failures,
        busy.is_empty(),
        format!("PRODUCT (1): a busy session must get no reply notice: {busy:?}"),
    );

    // ---- (2) its turn ends: exactly one notice, carrying no canary byte ----
    let stop = event(&r.workers[1], "Stop", None);
    check(
        &mut failures,
        stop.is_empty(),
        format!("PRODUCT (2): the Stop hook must print nothing: {stop:?}"),
    );
    let Some((t1, first)) = next_notice(&inbox, Duration::from_secs(15)) else {
        panic!(
            "PRODUCT (2): an idle session with an unread reply got no notice; {} claim(s) \
             failed:\n- {}\nbob's daemon:\n{}",
            failures.len(),
            failures.join("\n- "),
            bob_err()
        );
    };
    println!("[proof] (2) at the end of its turn, asker got {first:?}");
    check(
        &mut failures,
        first.contains("1 reply to your messages from alice"),
        format!("PRODUCT (2): the notice must name one reply from alice: {first:?}"),
    );
    check(
        &mut failures,
        !first.contains("CANARY-REPLY") && !first.contains("build 42"),
        format!("PRODUCT (2): no byte of the reply may reach the wake endpoint: {first:?}"),
    );

    // ---- (3)/(4) one notice after each wait of the schedule, and a restart resumes it ----
    let (t2, t3) = match (
        next_notice(&inbox, Duration::from_secs(15)),
        next_notice(&inbox, Duration::from_secs(20)),
    ) {
        (Some((t2, _)), Some((t3, _))) => (t2, t3),
        other => panic!(
            "PRODUCT (3): the second and third notices of the series must come; got {other:?}; \
             bob's daemon:\n{}",
            bob_err()
        ),
    };
    r.restart(1);
    let fourth = next_notice(&inbox, Duration::from_secs(45));
    let fifth = fourth
        .as_ref()
        .and_then(|_| next_notice(&inbox, Duration::from_secs(20)));
    let gaps: Vec<f64> = [Some(t1), Some(t2), Some(t3), fourth.as_ref().map(|f| f.0)]
        .windows(2)
        .filter_map(|w| Some((w[1]? - w[0]?).as_secs_f64()))
        .collect();
    println!(
        "[proof] (3)/(4) gaps between notices {gaps:.1?} s (4, 8, 12 due; the daemon restarted \
         after the third); a fourth {}, a fifth {}",
        fourth.is_some(),
        fifth.is_some()
    );
    // The tick is 2 s, so a notice comes up to 2 s after it is due.
    let within = |g: f64, due: f64| (due - 0.5..due + 3.0).contains(&g);
    check(
        &mut failures,
        gaps.len() >= 2 && within(gaps[0], 4.0) && within(gaps[1], 8.0),
        format!("PRODUCT (3): the notices must follow the schedule, 4 s then 8 s: {gaps:?}"),
    );
    check(
        &mut failures,
        gaps.len() == 3 && gaps[2] >= 11.5 && fifth.is_none(),
        format!(
            "PRODUCT (3)/(4): a restarted daemon must resume the series — the fourth notice no \
             sooner than 12 s after the third, then no more; gaps {gaps:?}, a fifth {:?}; \
             bob's daemon:\n{}",
            fifth.map(|f| f.1),
            bob_err()
        ),
    );

    // ---- (5) a fresh reply starts the series again ----
    answer(&r.workers[0], &r.workers[1], "CANARY-REPLY-2");
    let fresh = contents(&collect(&inbox, Duration::from_secs(15), |g| {
        g.contains("\"user\"")
    }));
    println!("[proof] (5) after a fresh reply, asker got {fresh:?}");
    check(
        &mut failures,
        fresh.len() == 1 && fresh[0].contains("2 replies to your messages from alice"),
        format!(
            "PRODUCT (5): a fresh reply must start the series again with a notice naming both \
             replies; got {fresh:?}; bob's daemon:\n{}",
            bob_err()
        ),
    );

    // ---- (6) the notice's turn reads each answer once; one read before idling is never told ----
    let prompt = fresh.first().cloned().unwrap_or_else(|| "a notice".into());
    let read = injected(&event(&r.workers[1], "UserPromptSubmit", Some(&prompt)));
    println!(
        "[proof] (6) the notice's turn read reply 1 {} time(s), reply 2 {} time(s)",
        read.matches("CANARY-REPLY-1").count(),
        read.matches("CANARY-REPLY-2").count()
    );
    check(
        &mut failures,
        read.matches("CANARY-REPLY-1").count() == 1 && read.matches("CANARY-REPLY-2").count() == 1,
        format!("PRODUCT (6): the turn a notice starts must read each answer once: {read}"),
    );
    // Busy now. Another answer lands, and the session reads it before its turn ends.
    answer(&r.workers[0], &r.workers[1], "CANARY-REPLY-3");
    let read = injected(&event(&r.workers[1], "UserPromptSubmit", Some("go on")));
    assert!(
        read.contains("CANARY-REPLY-3"),
        "APPARATUS (6): the session's own read must take the third answer: {read}"
    );
    let _ = event(&r.workers[1], "Stop", None);
    let after = contents(&collect(&inbox, Duration::from_secs(12), |_| false));
    println!(
        "[proof] (6) answers read, then idle: asker got {} notice(s)",
        after.len()
    );
    check(
        &mut failures,
        after.is_empty(),
        format!(
            "PRODUCT (6): an idle session that has read every answer must get no notice; got \
             {after:?}"
        ),
    );

    // ---- (7) SessionEnd removes the registration ----
    let end = event(&r.workers[1], "SessionEnd", None);
    let gone = !r.workers[1].paths.session_file("asker").exists();
    answer(&r.workers[0], &r.workers[1], "CANARY-REPLY-4");
    let ended = contents(&collect(&inbox, Duration::from_secs(10), |_| false));
    println!(
        "[proof] (7) after SessionEnd: registration gone {gone}, notices {}",
        ended.len()
    );
    check(
        &mut failures,
        end.is_empty() && gone && ended.is_empty(),
        format!(
            "PRODUCT (7): SessionEnd must print nothing and remove the registration, and a \
             later answer must wake nothing; printed {end:?}, gone {gone}, got {ended:?}"
        ),
    );

    // ---- (9) what lands while the daemon is down is announced when it starts ----
    let late_path = tmp.path().join("late.sock");
    let late_inbox = listen(&late_path);
    let late_s = late_path.to_string_lossy().into_owned();
    let late_env = [
        ("CLAUDE_CODE_MESSAGING_SOCKET", late_s.as_str()),
        ("CLAUDE_CODE_MESSAGING_TOKEN", "late-token"),
        ("VOX_AGENT_NAME", "late"),
    ];
    let late = |w: &Worker, name: &str| {
        hook(
            w,
            &late_env,
            &["agent", "hook", "--room", &room],
            Some(&hook_json(
                name,
                "late",
                (name == "UserPromptSubmit").then_some("hi"),
            )),
        )
    };
    let _ = late(&r.workers[1], "UserPromptSubmit");
    let o = r.workers[1].vox_in(
        Some("late"),
        &[
            "room", "post", &room, "--type", "ask", "--to", "alice", "--json", "-",
        ],
        Some("Is the late build out?"),
    );
    assert!(o.ok, "APPARATUS: late could not post its question: {o:?}");
    let q2 = o.json()["entry_hash"]
        .as_str()
        .expect("`vox room post --json` names the entry")
        .to_owned();
    until(
        &r.workers[0],
        None,
        "late's question to reach alice",
        &["room", "read", &room],
        |o| o.stdout.contains("Is the late build out?"),
    );
    let _ = late(&r.workers[1], "Stop");
    r.stop(1);
    let o = r.workers[0].vox_in(
        Some("alice-s"),
        &["room", "post", &room, "--type", "answer", "--re", &q2, "-"],
        Some("CANARY-START-R: it is out"),
    );
    assert!(
        o.ok,
        "APPARATUS: alice could not answer while bob was down: {o:?}"
    );
    post_text(
        &r.workers[0],
        &room,
        r#"{"v":1,"type":"ask","to":["late"],"urgent":true,"body":"late: CANARY-START-U"}"#,
    );
    // Long enough for both to reach the anchor, from which bob's node takes them when it starts.
    std::thread::sleep(Duration::from_secs(3));
    let started = Instant::now();
    r.restart(1);
    let up = started.elapsed().as_secs_f64();
    let frames = collect(&late_inbox, Duration::from_secs(20), |g| {
        g.contains("urgent message") && g.contains("repl")
    });
    let told = contents(&frames).join("\n");
    println!(
        "[proof] (9) after a restart ({up:.1}s to come back): urgent counted {}, reply counted {}, \
         message bytes at the socket {}",
        told.contains("urgent message addressed to you from alice"),
        told.contains("repl"),
        frames.join("\n").contains("CANARY-START")
    );
    check(
        &mut failures,
        told.contains("urgent message addressed to you from alice")
            && told.contains("repl")
            && !frames.join("\n").contains("CANARY-START"),
        format!(
            "PRODUCT (9): an urgent message and a reply that landed while the daemon was down \
             must be announced once it is back; got {told:?}; bob's daemon:\n{}",
            bob_err()
        ),
    );

    assert!(
        failures.is_empty(),
        "{} claim(s) failed:\n- {}",
        failures.len(),
        failures.join("\n- ")
    );
}

#[test]
#[ignore = "an anchor and two vox daemons with production Argon2id; CI runs it in release"]
fn two_sessions_answering_each_other_stop_being_told_at_the_hop_budget() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let r = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let room = r.id.clone();
    let errs = || {
        format!(
            "{}\n{}",
            daemon_err(tmp.path(), "alice"),
            daemon_err(tmp.path(), "bob")
        )
    };

    // One stand-in Claude Code session on each node: `pa` on alice's, `pb` on bob's.
    let sides: Vec<(&Worker, &str, &str, std::path::PathBuf)> = vec![
        (&r.workers[0], "pa", "pb", tmp.path().join("pa.sock")),
        (&r.workers[1], "pb", "pa", tmp.path().join("pb.sock")),
    ];
    let inboxes: Vec<mpsc::Receiver<String>> = sides.iter().map(|s| listen(&s.3)).collect();
    let socks: Vec<String> = sides
        .iter()
        .map(|s| s.3.to_string_lossy().into_owned())
        .collect();
    let event = |i: usize, name: &str, prompt: Option<&str>| {
        let (w, me, _, _) = &sides[i];
        let env = [
            ("CLAUDE_CODE_MESSAGING_SOCKET", socks[i].as_str()),
            ("CLAUDE_CODE_MESSAGING_TOKEN", "pp-token"),
            ("VOX_AGENT_NAME", *me),
        ];
        hook(
            w,
            &env,
            &["agent", "hook", "--room", &room],
            Some(&hook_json(name, me, prompt)),
        )
    };
    // Each side answers what it was told, addressed back, as its model would; then its turn ends.
    let answer = |i: usize, re: Option<&str>, body: &str| -> String {
        let (w, me, other, _) = &sides[i];
        let mut args = vec![
            "room", "post", &room, "--type", "answer", "--to", other, "--json",
        ];
        if let Some(re) = re {
            args.extend(["--re", re]);
        }
        args.push("-");
        let o = w.vox_in(Some(me), &args, Some(body));
        assert!(o.ok, "APPARATUS: {me} could not post: {o:?}");
        o.json()["entry_hash"]
            .as_str()
            .expect("`vox room post --json` names the entry")
            .to_owned()
    };
    for i in 0..2 {
        let _ = event(i, "UserPromptSubmit", Some("hi"));
        assert_eq!(
            registered_endpoint(sides[i].0, sides[i].1),
            ("claude".to_owned(), socks[i].clone()),
            "APPARATUS: {} must be registered at the test's own socket",
            sides[i].1
        );
    }

    // pa asks pb (8 hops); pb answers; from then on each side answers the answer it is told of.
    let mut last = answer(0, None, "PING-0");
    let _ = event(0, "Stop", None);
    until(
        sides[1].0,
        None,
        "pa's question to reach bob",
        &["room", "read", &room],
        |o| o.stdout.contains("PING-0"),
    );
    let _ = event(1, "UserPromptSubmit", Some("read"));
    last = answer(1, Some(&last), "PING-1");
    let _ = event(1, "Stop", None);
    let mut told = 0;
    let mut turn = 0usize; // whose notice is awaited next: pa
                           // At most twenty rounds: an exchange that never ends is the defect, and this bounds it.
    for round in 2..22 {
        let Some((_, notice)) = next_notice(&inboxes[turn], Duration::from_secs(20)) else {
            break;
        };
        told += 1;
        println!(
            "[proof] round {round}: {} was told {notice:?}",
            sides[turn].1
        );
        let _ = event(turn, "UserPromptSubmit", Some(&notice));
        last = answer(turn, Some(&last), &format!("PING-{round}"));
        let _ = event(turn, "Stop", None);
        turn = 1 - turn;
    }
    let hops: Vec<i64> = sides[0]
        .0
        .vox(None, &["room", "read", &room, "--json"])
        .ndjson()
        .into_iter()
        .filter(|x| x["text"].as_str().is_some_and(|t| t.contains("PING-")))
        .map(|x| x["envelope"]["hops"].as_i64().unwrap_or(-1))
        .collect();
    println!(
        "[proof] the exchange: {told} notice(s); hops in the log {hops:?} (8 down to 0: each \
         answer told while it has hops left, the one at 0 to nobody)"
    );
    assert_eq!(
        hops.first(),
        Some(&8),
        "APPARATUS: the first question must start with the default budget of 8: {hops:?}"
    );
    assert_eq!(
        told,
        7,
        "PRODUCT: answers to answers must be announced only while they have hops left — the \
         answers carrying 7 down to 1 — and the one at 0 to nobody; {told} notices, hops in the \
         log {hops:?}; the daemons:\n{}",
        errs()
    );
}
