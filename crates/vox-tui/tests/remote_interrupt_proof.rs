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
//! `CLAUDE_CODE_MESSAGING_SOCKET`/`_TOKEN` in its environment, with the
//! `VOX_CLAUDE_NATIVE_ATTENTION` that `vox agent plugin claude` puts in Claude's settings: since
//! ADR-020 §6.15 RA-5 (8cade3da0) only a session registered with that live native route is sent a
//! notice. The one thing that is not `vox` is
//! that messaging socket: a stand-in for Claude Code's, recording what the daemon writes to it,
//! because no `vox` command plays a harness session. Alice posts with `vox room post` on her own
//! daemon; nothing reaches bob but by sync.
//!
//! **Messages address nodes** (v0.2.10, the decider 2026-10-02): `--to` takes the poster's name
//! for a member, a raw envelope's `to` that member's whole fingerprint (`to_node`), and an urgent
//! message wakes every session registered on the node it addresses. There is no per-session
//! name (`VOX_AGENT_NAME` is gone): "addressed to someone else" below is addressed to alice's
//! node, and the hop-budget exchange addresses the other side's node.
//!
//! **The hook runs in a cleared environment.** This test may itself run inside Claude Code,
//! whose `CLAUDE_CODE_MESSAGING_SOCKET` names a *real* session: inherited, it registers that
//! session as bob's, and the urgent messages below interrupt a live Claude session on the
//! machine (it happened, 2026-09-26). So `vox agent hook` gets only `PATH`, `HOME`, the
//! profile directories and the harness variables each case sets, and each registration is
//! read back and required to name the test's own endpoint before anything is posted.
//!
//! **A wake announces; the message arrives once, through the room read** (V030-15). The wake
//! is a notice — how many messages, from whom, in which room — and no byte of any
//! message. Claude Code runs its `UserPromptSubmit` hooks for a message written to its messaging
//! socket, with that message as the hooks' `prompt`, idle, mid-generation or between tool calls
//! (measured against a live Claude Code 2.1.287), so the drain runs in the turn the wake starts.
//! Here bob's hooks run on the wake it received exactly as his harness runs the two Vox installs:
//! the ordinary drain and `--native-attention`, which admits a Vox notice and drains for it.
//!
//! Since ADR-020 §6.15 (d1dec07b3, #812) a person's ordinary message addressed to bob or to
//! nobody (RA-1) and a session's directed `ask`/`assign` (RA-2a) are offered to his session too,
//! urgent or not; so the messages below that must wake nothing, and the filler, are said by
//! alice's registered session.
//!
//! `an_urgent_message_from_another_node_interrupts_its_addressee` asserts, **each for a message
//! that arrived by sync**:
//!
//! 1. addressed to bob and urgent — bob's session is woken, exactly once, by a notice naming
//!    one message from alice; **no byte of any message body** reaches the wake endpoint
//!    (each body carries a canary);
//! 2. urgent but addressed to someone else — nothing;
//! 3. addressed to bob but not urgent, and neither ordinary conversation nor a directed request —
//!    nothing;
//! 5. the turn the wake starts reads the urgent message **once**, first, ahead of the two older
//!    ones that woke nothing, which it also reads once each;
//! 6. **one notice outstanding at a time**: a second urgent message, while the first one's notice
//!    has not been taken by a turn, wakes nothing (RA-8);
//! 7. **recounted before it fires**: once the session's read has taken that message, nothing
//!    is sent for it;
//! 4. a wedged session (an OpenCode client listed by the Vox TUI plugin whose attention socket
//!    accepts and never answers) does not stall bob's wakes;
//! 10. **an urgent message addressed to nobody wakes nobody** (RP-01, ADR-020 §6): posted the way a
//!     person does it, `vox room post --urgent` with no `--to`, it reaches bob's node and his
//!     session gets no notice — or one agent could interrupt the whole room.
//!
//! `an_idle_agent_is_told_when_a_reply_to_it_is_waiting` (V030-20): bob's session `asker` asks
//! alice something, and alice answers (`--re`), each answer carrying a canary. An answer to a
//! session's addressed question is offered to it (ADR-020 §6.15, `attention_eligible`'s
//! `answers`). V030-20's busy gate and its repeated series of notices (`agent_reply_nudges`,
//! `agent_wake_hold`) left the product with `d1dec07b3` (#812): RA-8 presents a request once per
//! recipient and lets no timeout start another turn, and RA-5 leaves a busy Claude session's
//! boundary to Claude (`priority: later`).
//!
//! 2. once alice has answered (its turn over: Claude Code's `Stop` hook, run as `vox agent hook`,
//!    printing nothing) — exactly one notice, naming one message from alice, with no canary byte;
//! 6. the turn that notice starts reads the answer **once**;
//! 7. `SessionEnd` removes the registration: a later answer wakes nothing;
//! 8. `vox agent plugin claude` prints the `UserPromptSubmit`, `Stop` and `SessionEnd` entries;
//! 9. **what lands while the daemon is down is announced when it starts**: bob's daemon stopped,
//!    alice answers an idle session's question and sends it an urgent message; once the daemon
//!    is back, the session is woken and the turns its notices start read each once (one notice
//!    is outstanding at a time, RA-8). They reach bob's node by sync after it starts, so
//!    this does not exercise the daemon's startup count (which guards only a crash between a row
//!    landing and the next sweep, and is unproven by mutant); it goes red if what arrives after a
//!    restart is not announced;
//! 10. **what is not a reply**: an `ack`, `status`, `hello`, `bye`, `ping` or `pong` answering
//!     the session's question is never announced, and a real answer after them counts one.
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
//! Every red names its side: `PRODUCT:` with what the product sent or said; `PRODUCT (staging)`
//! for a `vox` step of the staging that failed (it is the product's); `APPARATUS:` for this
//! proof's own fault, and `APPARATUS, CANNOT MEASURE:` when the collecting loop itself stalled
//! for a large part of a window in which a missing wake is judged.
//!
//! **Mutation**, one per claim, each red at its own assertion: the message put back in the wake
//! (V030-15 (1), V030-20 (2)); no recount — the daemon counting from the start of the room rather
//! than the cursor (V030-15 (7), V030-20 (6)); no outstanding-notice rule (V030-15 (6)); no idle
//! gate (V030-20 (1)); no generation, so a fresh reply is not announced (V030-20 (5)); the
//! series held in memory (V030-20 (4)); a reply announced with no hops left (the exchange runs to
//! its bound of twenty rounds); and the delivered-ahead record never written, ignored by the
//! drain, ignored by the count, or a cursor moved past rows not shown ((8)). An urgent broadcast let wake
//! goes red at (10): the rule is held in three places, so the mutant drops all three (the empty-`to`
//! checks in `node_tasks::may_wake` and `judge`, and `Envelope::may_interrupt` taking a broadcast as
//! addressed); dropping it from `may_wake` alone stays green, as `judge` still refuses. The pre-F15 loop — the daemon judging only `NewEntry` —
//! goes red at V030-15 (1).

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Read as _;
use std::os::unix::net::UnixListener;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use support::{until, Worker};

/// A stand-in Claude Code messaging socket: every connection's bytes, as they are written.
fn listen(path: &std::path::Path) -> mpsc::Receiver<String> {
    let listener = UnixListener::bind(path)
        .unwrap_or_else(|e| panic!("APPARATUS: bind the stand-in session socket: {e}"));
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
    cmd.env_clear()
        // A proof's daemon never takes port 1080 (.cargo/config.toml).
        .env("VOX_PROXY", "127.0.0.1:0");
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
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: spawn vox agent hook: {e}"));
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("APPARATUS: the hook's stdin")
            .write_all(input.as_bytes())
            .unwrap_or_else(|e| panic!("PRODUCT (staging): `vox agent hook` exited without reading its stdin (the write failed: {e})"));
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: wait for vox agent hook: {e}"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!(
        "[receipt] vox {} -> {:?}; stderr: {}",
        args.join(" "),
        out.status.code(),
        stderr.trim()
    );
    assert!(
        out.status.success(),
        "PRODUCT: `vox agent hook` must exit 0; it exited {:?} and said: {}",
        out.status.code(),
        stderr.trim()
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The endpoint bob's daemon will wake `session` at, as the hook registered it.
fn registered_endpoint(bob: &Worker, session: &str) -> (String, String) {
    let body = std::fs::read(bob.paths.session_file(session)).unwrap_or_else(|e| {
        panic!("PRODUCT (staging): `vox agent hook` registered no session {session}: {e}")
    });
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_else(|e| {
        panic!(
            "PRODUCT: `vox agent hook` wrote a session registration that is not JSON ({e}): {}",
            String::from_utf8_lossy(&body)
        )
    });
    (
        v["harness"].as_str().unwrap_or_default().to_owned(),
        v["endpoint"].as_str().unwrap_or_default().to_owned(),
    )
}

/// `w` posts `text` exactly as given, through `vox room post <room> -` on its daemon.
fn post_text(w: &Worker, room: &str, text: &str) {
    let o = w.vox_in(None, &["room", "post", room, "-"], Some(text));
    assert!(o.ok, "PRODUCT (staging): {} could not post: {o:?}", w.name);
}

/// `envelope` with its `"to":["<to's name>"]` written as `to`'s whole fingerprint. Since v0.2.10 a
/// raw envelope addresses **nodes**, each by its fingerprint (`--to` takes the poster's names for
/// them), and an urgent one wakes every session of the node addressed.
fn to_node(envelope: &str, to: &Worker) -> String {
    let named = format!("\"to\":[\"{}\"]", to.name);
    assert!(
        envelope.contains(&named),
        "APPARATUS: the proof's envelope does not address {}: {envelope}",
        to.name
    );
    envelope.replacen(&named, &format!("\"to\":[\"{}\"]", to.b32()), 1)
}

/// Alice posts `text` exactly as given, through `vox room post <room> -` on her daemon.
fn post(alice: &Worker, room: &str, text: &str) {
    let o = alice.vox_in(None, &["room", "post", room, "-"], Some(text));
    assert!(o.ok, "PRODUCT (staging): alice could not post: {o:?}");
}

/// `w`'s registered Session `session` posts `text` exactly as given: a post with session origin
/// (ADR-020 §6.15 RA-2, RA-3), which no other session is offered unless it is addressed and urgent,
/// or a directed `ask`/`assign` (RA-2a).
fn post_as(w: &Worker, session: &str, room: &str, text: &str) {
    let o = w.vox_in(Some(session), &["room", "post", room, "-"], Some(text));
    assert!(
        o.ok,
        "PRODUCT (staging): {}'s session {session} could not post: {o:?}",
        w.name
    );
}

/// What Claude Code gives Vox's hooks once `vox agent plugin claude` is installed: its settings'
/// `VOX_CLAUDE_NATIVE_ATTENTION`. A Claude session is offered automatic notices only when its hook
/// registered it with that live native route (8cade3da0; ADR-020 §6.15 RA-5).
fn native_attention(w: &Worker) -> String {
    let o = w.vox(None, &["agent", "plugin", "claude", "--node", "default"]);
    assert!(o.ok, "PRODUCT (staging): `vox agent plugin claude`: {o:?}");
    o.json()["env"]["VOX_CLAUDE_NATIVE_ATTENTION"]
        .as_str()
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT (staging): Claude's generated settings must enable native attention: {}",
                o.stdout
            )
        })
        .to_owned()
}

/// A Claude Code turn starting on `prompt`, as Vox's installed settings run it: both of its
/// `UserPromptSubmit` commands, the ordinary drain and `--native-attention`, which admits a Vox
/// attention notice and drains for it (each prints nothing for the other's prompts). What they
/// inject.
fn claude_turn(
    w: &Worker,
    env: &[(&str, &str)],
    room: &str,
    session: &str,
    prompt: &str,
) -> String {
    let input = hook_json("UserPromptSubmit", session, Some(prompt));
    let ordinary = ["agent", "hook", "--node", "default", "--room", room];
    let native = [&ordinary[..], &["--native-attention"]].concat();
    let mut given = injected(&hook(w, env, &ordinary, Some(&input)));
    let out = hook(w, env, &native, Some(&input));
    if out.contains("\"decision\"") {
        eprintln!(
            "[receipt] the native-attention hook blocked the turn: {}",
            out.trim()
        );
    }
    given.push_str(&injected(&out));
    given
}

/// Everything bob's stand-in session receives within `within`, stopping early once `done`, and
/// the apparatus clock: the longest the collecting loop itself went between two of its own
/// half-second waits. A loop that stalled for a large part of the window cannot say a wake did
/// not come in it.
fn collect(
    inbox: &mpsc::Receiver<String>,
    within: Duration,
    done: impl Fn(&str) -> bool,
) -> (Vec<String>, Duration) {
    const WAIT: Duration = Duration::from_millis(500);
    let mut got = Vec::new();
    let mut stall = Duration::ZERO;
    let deadline = Instant::now() + within;
    while Instant::now() < deadline && !done(&got.join("\n")) {
        let asked = Instant::now();
        if let Ok(frames) = inbox.recv_timeout(WAIT) {
            eprintln!("[receipt] bob's session received: {frames}");
            got.push(frames);
        }
        stall = stall.max(asked.elapsed().saturating_sub(WAIT));
    }
    (got, stall)
}

/// Whether a stall of the collecting loop leaves too little of `window` to judge a miss.
fn stalled(stall: Duration, window: Duration) -> bool {
    stall * 4 > window
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

/// A stand-in for an OpenCode client of the Vox TUI plugin (`assets/opencode-tui-plugin.js`)
/// that is **wedged**: its descriptor is listed where the plugin lists the clients of `node`'s
/// sessions started in `directory` (`/tmp/vox-oc-clients-<scope>/client-<id>/client.json`), and
/// its attention socket accepts and never answers. Removed when dropped.
struct WedgedClient(std::path::PathBuf);
impl Drop for WedgedClient {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn wedged_client(node: &str, directory: &std::path::Path) -> WedgedClient {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    let directory = std::fs::canonicalize(directory).expect("APPARATUS: canonical directory");
    let directory = directory
        .to_str()
        .expect("APPARATUS: a UTF-8 directory")
        .to_owned();
    let scope = serde_json::to_vec(&[node, directory.as_str()]).expect("APPARATUS: scope");
    let scope: String = vox_core::hash::sha256(&scope)[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let registry = std::path::PathBuf::from("/tmp").join(format!("vox-oc-clients-{scope}"));
    let mut private = std::fs::DirBuilder::new();
    private.mode(0o700);
    if !registry.exists() {
        private
            .create(&registry)
            .expect("APPARATUS: the client registry");
    }
    let dir = registry.join(format!("client-w{:05}", std::process::id() % 100_000));
    private
        .create(&dir)
        .expect("APPARATUS: the wedged client's directory");
    let guard = WedgedClient(dir.clone());
    let socket = dir.join("attention.sock");
    let listener = UnixListener::bind(&socket).expect("APPARATUS: bind the wedged client socket");
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in listener.incoming().flatten() {
            held.push(s); // accepted, never read, never answered
        }
    });
    let descriptor = serde_json::json!({
        "version": 1, "node": node, "directory": directory,
        "socket": socket.to_str().expect("APPARATUS: a UTF-8 socket path"),
        "token": "a".repeat(64), "client": "b".repeat(64),
    });
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("client.json"))
        .and_then(|mut f| {
            use std::io::Write as _;
            f.write_all(descriptor.to_string().as_bytes())
        })
        .expect("APPARATUS: write the wedged client's descriptor");
    guard
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

/// **Every red names its kind** (decider rule 1). A product verdict says `PRODUCT:` (a staging step
/// the shipped binary fails says `PRODUCT (staging)`: it is the product's); a harness failure or a
/// staging not achieved says `APPARATUS`. Anything else that panics (an `unwrap` or `expect` on a
/// socket, a file, a process) is this proof's own failure, and this hook says so first.
fn label_reds() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let payload = info.payload();
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("");
            // `assert_eq!` and `assert_ne!` put their own words before the message, so the
            // label is read after them.
            let message = [
                "assertion `left == right` failed: ",
                "assertion `left != right` failed: ",
            ]
            .iter()
            .find_map(|p| message.strip_prefix(p))
            .unwrap_or(message);
            if !(message.starts_with("PRODUCT") || message.starts_with("APPARATUS")) {
                eprintln!(
                    "APPARATUS (harness error): the panic below is this proof's own, not a \
                     verdict on the product"
                );
            }
            previous(info);
        }));
    });
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
    label_reds();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: a tokio runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let r = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&r.workers[0], &r.workers[1]);
    let room = r.id.clone();
    let bob_err = || daemon_err(tmp.path(), "bob");
    let mut failures = Vec::new();

    // ---- bob's session registers with his daemon, as its harness hook does every turn ----
    let sock = tmp.path().join("session.sock");
    let inbox = listen(&sock);
    let sock_s = sock.to_string_lossy().into_owned();
    let native = native_attention(bob);
    let bob_env = [
        ("CLAUDE_CODE_MESSAGING_SOCKET", sock_s.as_str()),
        ("CLAUDE_CODE_MESSAGING_TOKEN", "a-token"),
        ("VOX_CLAUDE_NATIVE_ATTENTION", native.as_str()),
    ];
    // bob's harness, starting a turn on `prompt`: its drains' injection.
    let turn = |prompt: &str| claude_turn(bob, &bob_env, &room, "session-bob", prompt);
    let _ = turn("hi");
    let reg = registered_endpoint(bob, "session-bob");
    assert_eq!(
        reg,
        ("claude".to_owned(), sock_s.clone()),
        "PRODUCT (staging): bob's session must be registered at the test's own socket, never a \
         real session's"
    );

    // Bob's daemon must be in sync with alice, and his session must have read everything so far,
    // before the cases mean anything. Alice's session posts the marker: a person's bare post to
    // nobody is ordinary room conversation, offered to every session in the room (ADR-020 §6.15
    // RA-1), and its notice is not what these cases measure.
    // A Session posts only once its node has registered it, as its harness's hook does at the
    // start of a turn (ADR-020 §6.15 RA-3).
    support::register_sending_session(alice, &room, "session-alice");
    post_as(alice, "session-alice", &room, "SYNC-MARKER");
    until(
        bob,
        None,
        "alice's marker to reach bob",
        &["room", "read", &room],
        |o| o.stdout.contains("SYNC-MARKER"),
    );
    let _ = turn("hi");

    // ---- (10) urgent and addressed to nobody: nothing. Posted with the CLI's own flags, as a
    // person marks a message urgent; judged alone, before anything else is urgent ----
    let o = alice.vox_in(
        Some("session-alice"),
        &["room", "post", &room, "--urgent", "--type", "ask", "-"],
        Some("everyone: URGENT-BROADCAST is anyone there?"),
    );
    assert!(
        o.ok,
        "PRODUCT (staging): `vox room post --urgent` with no `--to` must post a broadcast; it \
         said {o:?}"
    );
    until(
        bob,
        None,
        "the urgent broadcast to reach bob's node",
        &["room", "read", &room],
        |o| o.stdout.contains("URGENT-BROADCAST"),
    );
    // Ten seconds after it landed: five sweeps of the daemon's two-second tick.
    let (frames, stall) = collect(&inbox, Duration::from_secs(10), |_| false);
    println!(
        "[proof] (10) bob's session got {} frame(s) in 10s after an urgent broadcast: {:?}",
        frames.len(),
        contents(&frames)
    );
    assert!(
        !(frames.is_empty() && stalled(stall, Duration::from_secs(10))),
        "APPARATUS, CANNOT MEASURE: the collecting loop itself stalled {stall:?} of its 10 s \
         window, so no wake cannot be judged"
    );
    check(
        &mut failures,
        frames.is_empty(),
        format!(
            "PRODUCT (10): an urgent message addressed to nobody must wake nobody; bob's session \
             was sent {frames:?}; bob's daemon:\n{}",
            bob_err()
        ),
    );
    // bob's session reads it, as its next turn would, so the cases below start from a read room.
    let _ = turn("hi");

    // ---- (2) urgent, addressed to someone else; (3) addressed to bob, not urgent ----
    post(
        alice,
        &room,
        &to_node(
            r#"{"v":1,"type":"ask","to":["alice"],"urgent":true,"body":"alice: OTHER-ADDRESSEE"}"#,
            alice,
        ),
    );
    // (3) is said by alice's session: since ADR-020 §6.15 (d1dec07b3) a person's ordinary message
    // to bob (RA-1) and a session's directed `ask`/`assign` (RA-2a) are offered to his session
    // without urgency; every other message waits for its next turn (§6.2 as amended).
    post_as(
        alice,
        "session-alice",
        &room,
        &to_node(
            r#"{"v":1,"type":"say","to":["bob"],"body":"bob: NOT-URGENT"}"#,
            bob,
        ),
    );
    // ---- (1) addressed to bob and urgent: woken, by a notice that carries none of it ----
    post(
        alice,
        &room,
        &to_node(
            r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: CANARY-URGENT-1 wake up"}"#,
            bob,
        ),
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
    let (frames, stall) = collect(&inbox, Duration::from_secs(20), |_| false);
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
    // No wake at all is judged only when the collecting loop was itself awake for the window.
    assert!(
        !(wakes.is_empty() && stalled(stall, Duration::from_secs(20))),
        "APPARATUS, CANNOT MEASURE: the collecting loop itself stalled {stall:?} of its 20 s \
         window, so a missing wake cannot be judged; received {frames:?}; bob's daemon:\n{}",
        bob_err()
    );
    check(
        &mut failures,
        wakes.len() == 1
            && wakes[0].contains("1 unread room message(s) from alice")
            && all.contains("a-token"),
        format!(
            "PRODUCT (1): one urgent message from alice must wake bob's session once, with a \
             notice naming one message from alice and the registered token; received \
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
        // What failed already is the product's; (5)-(7) only could not be staged after it.
        panic!(
            "{} (5)-(7): bob's session was never woken, so they could not be staged; {} claim(s) \
             failed:\n- {}",
            if failures.is_empty() {
                "APPARATUS"
            } else {
                "PRODUCT"
            },
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
        "PRODUCT (staging): (5) the wake's turn must read the two messages that woke nothing, once \
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
        &to_node(
            r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: CANARY-URGENT-2"}"#,
            bob,
        ),
    );
    let got = contents(&collect(&inbox, Duration::from_secs(30), |g| g.contains("\"user\"")).0);
    println!(
        "[proof] (6) after the session read the first notice, a second urgent message woke it \
         {} time(s)",
        got.len()
    );
    assert!(
        got.len() == 1,
        "PRODUCT (6): a session whose turn took its notice must be woken by the next urgent \
         message at once; got {got:?}; bob's daemon:\n{}",
        bob_err()
    );
    let second = got[0].clone();
    post(
        alice,
        &room,
        &to_node(
            r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: CANARY-URGENT-3"}"#,
            bob,
        ),
    );
    until(
        bob,
        None,
        "the third urgent message to reach bob's node",
        &["room", "read", &room],
        |o| o.stdout.contains("CANARY-URGENT-3"),
    );
    let held = contents(&collect(&inbox, Duration::from_secs(10), |_| false).0);
    println!(
        "[proof] (6) with a notice outstanding, a further urgent message woke bob {} time(s)",
        held.len()
    );
    check(
        &mut failures,
        held.is_empty(),
        format!(
            "PRODUCT (6): no further wake while the first notice is outstanding (its turn has \
             not taken it); got {held:?}"
        ),
    );

    // ---- (7) recounted before it fires: read first, nothing sent ----
    let read = turn(&second);
    assert!(
        read.contains("CANARY-URGENT-2") && read.contains("CANARY-URGENT-3"),
        "PRODUCT (staging) (7): the session's read must take both held messages first: {read}"
    );
    let after = contents(&collect(&inbox, Duration::from_secs(10), |_| false).0);
    println!(
        "[proof] (7) once the session had read them, the daemon woke it {} time(s)",
        after.len()
    );
    check(
        &mut failures,
        after.is_empty(),
        format!(
            "PRODUCT (7): a held urgent message the session read first must wake nothing; got \
             {after:?}; bob's daemon:\n{}",
            bob_err()
        ),
    );

    // ---- (4) a wedged session must not stall anybody else's wake ----
    // An OpenCode session whose client accepts and never answers: its wake would wait for ever.
    // Since ADR-020 §6.15 RA-5 (d1dec07b3, 0a45c7c0c) an OpenCode wake goes only to the client
    // the Vox TUI plugin lists for the session's node and directory, never to the server
    // plugin's socket; the wedged one is that client.
    let _wedged = wedged_client("default", &std::env::current_dir().expect("APPARATUS: cwd"));
    let wedge_path = tmp.path().join("wedge.sock");
    let wedge = UnixListener::bind(&wedge_path)
        .unwrap_or_else(|e| panic!("APPARATUS: bind the wedged session socket: {e}"));
    let wedge_url = wedge_path
        .to_str()
        .expect("APPARATUS: a UTF-8 temp path")
        .to_owned();
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
        ],
        &[
            "agent",
            "hook",
            "--node",
            "default",
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
        "PRODUCT (staging): the wedged session must be registered at the test's own endpoint, \
         never a real session's"
    );
    let registered = std::fs::read_dir(bob.paths.session_dir())
        .map(|d| {
            d.filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        registered, 2,
        "PRODUCT: after two hooks, bob's daemon must hold exactly two session registrations"
    );
    post(
        alice,
        &room,
        &to_node(
            r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: WEDGE-TEST"}"#,
            bob,
        ),
    );
    let (frames, stall) = collect(&inbox, Duration::from_secs(45), |g| g.contains("\"user\""));
    let got = contents(&frames);
    println!("[proof] (4) with a wedged session registered, bob's session got {got:?}");
    assert!(
        !(got.is_empty() && stalled(stall, Duration::from_secs(45))),
        "APPARATUS, CANNOT MEASURE: the collecting loop itself stalled {stall:?} of its 45 s \
         window, so a missing wake cannot be judged; received {frames:?}; bob's daemon:\n{}",
        bob_err()
    );
    check(
        &mut failures,
        got.iter()
            .any(|c| c.contains("1 unread room message(s) from alice")),
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
    // Alice's session posts them: a person's bare posts would each be offered (RA-1).
    for i in 0..60 {
        post_as(alice, "session-alice", &room, &format!("BULK-{i:02}-ROW"));
    }
    post(
        alice,
        &room,
        &to_node(
            r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: CANARY-AHEAD-1"}"#,
            bob,
        ),
    );
    until(
        bob,
        None,
        "the sixty messages and the urgent one to reach bob's node",
        &["room", "read", &room],
        |o| o.stdout.contains("CANARY-AHEAD-1") && o.stdout.contains("BULK-59-ROW"),
    );
    let w1 = contents(&collect(&inbox, Duration::from_secs(30), |g| g.contains("\"user\"")).0);
    assert!(
        w1.len() == 1,
        "PRODUCT (staging) (8): the urgent message must wake bob for the bounded read to be staged; got \
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
        turn1.contains("more unread message(s) in this room not shown")
    );
    assert!(
        turn1.contains("more unread message(s) in this room not shown"),
        "PRODUCT (staging) (8): the first read must be bounded, or nothing is shown ahead of the cursor: \
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
        &to_node(
            r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: CANARY-AHEAD-2"}"#,
            bob,
        ),
    );
    let w2 = contents(&collect(&inbox, Duration::from_secs(30), |g| g.contains("\"user\"")).0);
    println!("[proof] (8) the wake after turn 1: {w2:?}");
    check(
        &mut failures,
        w2.len() == 1 && w2[0].contains("1 unread room message(s) from alice"),
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

    assert!(
        failures.is_empty(),
        "PRODUCT: {} claim(s) failed:\n- {}",
        failures.len(),
        failures.join("\n- ")
    );
}

#[test]
#[ignore = "an anchor and two vox daemons with production Argon2id, and a daemon restart; CI runs it in release"]
fn an_idle_agent_is_told_when_a_reply_to_it_is_waiting() {
    watchdog::arm();
    label_reds();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: a tokio runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let mut r = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let room = r.id.clone();
    let bob_err = || daemon_err(tmp.path(), "bob");
    let mut failures = Vec::new();

    // ---- (8) the entries a person merges into Claude Code's settings ----
    let printed = r.workers[1].vox(None, &["agent", "plugin", "claude", "--node", "default"]);
    let entries: serde_json::Value =
        serde_json::from_str(&printed.stdout).unwrap_or(serde_json::Value::Null);
    let runs_hook = |event: &str| {
        entries["hooks"][event][0]["hooks"][0]["command"] == "vox agent hook --node default"
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
    let native = native_attention(&r.workers[1]);
    let env = [
        ("CLAUDE_CODE_MESSAGING_SOCKET", sock_s.as_str()),
        ("CLAUDE_CODE_MESSAGING_TOKEN", "asker-token"),
        ("VOX_CLAUDE_NATIVE_ATTENTION", native.as_str()),
    ];
    // A turn starts as Claude Code starts it with Vox installed (both prompt hooks, their
    // injection); every other event is one hook (its stdout).
    let event = |bob: &Worker, name: &str, prompt: Option<&str>| match prompt {
        Some(prompt) => claude_turn(bob, &env, &room, "asker", prompt),
        None => hook(
            bob,
            &env,
            &["agent", "hook", "--node", "default", "--room", &room],
            Some(&hook_json(name, "asker", None)),
        ),
    };
    let _ = event(&r.workers[1], "UserPromptSubmit", Some("ask alice"));
    assert_eq!(
        registered_endpoint(&r.workers[1], "asker"),
        ("claude".to_owned(), sock_s.clone()),
        "PRODUCT (staging): asker must be registered at the test's own socket"
    );
    // It asks alice, as its model would with `vox room post`.
    let o = r.workers[1].vox_in(
        Some("asker"),
        &[
            "room", "post", &room, "--type", "ask", "--to", "alice", "--json", "-",
        ],
        Some("What is the build number?"),
    );
    assert!(
        o.ok,
        "PRODUCT (staging): asker could not post its question: {o:?}"
    );
    let q = o.json()["entry_hash"]
        .as_str()
        .expect("PRODUCT: `vox room post --json` must name the entry it posted")
        .to_owned();
    until(
        &r.workers[0],
        None,
        "the question to reach alice",
        &["room", "read", &room],
        |o| o.stdout.contains("What is the build number?"),
    );
    // A Session posts only once its node has registered it, as its harness's hook does at the
    // start of a turn (ADR-020 §6.15 RA-3).
    support::register_sending_session(&r.workers[0], &room, "alice-s");
    let answer = |alice: &Worker, bob: &Worker, canary: &str| {
        let o = alice.vox_in(
            Some("alice-s"),
            &["room", "post", &room, "--type", "answer", "--re", &q, "-"],
            Some(&format!("{canary}: build 42")),
        );
        assert!(o.ok, "PRODUCT (staging): alice could not answer: {o:?}");
        until(
            bob,
            None,
            "alice's answer to reach bob",
            &["room", "read", &room],
            |o| o.stdout.contains(canary),
        );
    };

    // ---- (2) an answer to its question, its turn ended: exactly one notice, carrying no
    // canary byte ----
    answer(&r.workers[0], &r.workers[1], "CANARY-REPLY-1");
    let stop = event(&r.workers[1], "Stop", None);
    check(
        &mut failures,
        stop.is_empty(),
        format!("PRODUCT (2): the Stop hook must print nothing: {stop:?}"),
    );
    let Some((_, first)) = next_notice(&inbox, Duration::from_secs(15)) else {
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
        first.contains("1 unread room message(s) from alice"),
        format!("PRODUCT (2): the notice must name one reply from alice: {first:?}"),
    );
    check(
        &mut failures,
        !first.contains("CANARY-REPLY") && !first.contains("build 42"),
        format!("PRODUCT (2): no byte of the reply may reach the wake endpoint: {first:?}"),
    );

    // ---- (6) the notice's turn reads each answer once; one read before idling is never told ----
    let read = event(&r.workers[1], "UserPromptSubmit", Some(&first));
    println!(
        "[proof] (6) the notice's turn read reply 1 {} time(s)",
        read.matches("CANARY-REPLY-1").count()
    );
    check(
        &mut failures,
        read.matches("CANARY-REPLY-1").count() == 1,
        format!("PRODUCT (6): the turn a notice starts must read the answer once: {read}"),
    );
    let _ = event(&r.workers[1], "Stop", None);

    // ---- (10) acknowledgements, progress and presence are not replies ----
    // The session is idle and has read everything; each of these answers its question with `re`.
    for kind in ["ack", "status", "hello", "bye", "ping", "pong"] {
        post_text(
            &r.workers[0],
            &room,
            &format!(
                r#"{{"v":1,"from":"alice-s","type":"{kind}","re":"{q}","body":"NOT-A-REPLY-{kind}"}}"#
            ),
        );
    }
    until(
        &r.workers[1],
        None,
        "the six to reach bob",
        &["room", "read", &room],
        |o| o.stdout.contains("NOT-A-REPLY-pong"),
    );
    let quiet = contents(&collect(&inbox, Duration::from_secs(10), |_| false).0);
    // Then a real answer, so a notice is seen to come at all, and it counts one reply.
    answer(&r.workers[0], &r.workers[1], "CANARY-REPLY-X");
    let control = next_notice(&inbox, Duration::from_secs(20)).map(|f| f.1);
    println!(
        "[proof] (10) ack/status/hello/bye/ping/pong answering the question: {} notice(s); then a \
         real answer: {control:?}",
        quiet.len()
    );
    assert!(
        control.is_some(),
        "PRODUCT (staging) (10): a real answer must bring a notice, or the quiet before it proves \
         nothing; bob's daemon:\n{}",
        bob_err()
    );
    check(
        &mut failures,
        quiet.is_empty()
            && control
                .as_ref()
                .is_some_and(|c| c.contains("1 unread room message(s) from alice")),
        format!(
            "PRODUCT (10): an ack, status, hello, bye, ping or pong is never announced as a reply, \
             nor counted in one; got {quiet:?}, then {control:?}"
        ),
    );
    let _ = event(&r.workers[1], "UserPromptSubmit", control.as_deref());
    let _ = event(&r.workers[1], "Stop", None);

    // ---- (7) SessionEnd removes the registration ----
    let end = event(&r.workers[1], "SessionEnd", None);
    let gone = !r.workers[1].paths.session_file("asker").exists();
    answer(&r.workers[0], &r.workers[1], "CANARY-REPLY-4");
    let ended = contents(&collect(&inbox, Duration::from_secs(10), |_| false).0);
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
        ("VOX_CLAUDE_NATIVE_ATTENTION", native.as_str()),
    ];
    let late = |w: &Worker, name: &str, prompt: &str| {
        if name == "UserPromptSubmit" {
            return claude_turn(w, &late_env, &room, "late", prompt);
        }
        hook(
            w,
            &late_env,
            &["agent", "hook", "--node", "default", "--room", &room],
            Some(&hook_json(name, "late", None)),
        )
    };
    let _ = late(&r.workers[1], "UserPromptSubmit", "hi");
    let o = r.workers[1].vox_in(
        Some("late"),
        &[
            "room", "post", &room, "--type", "ask", "--to", "alice", "--json", "-",
        ],
        Some("Is the late build out?"),
    );
    assert!(
        o.ok,
        "PRODUCT (staging): late could not post its question: {o:?}"
    );
    let q2 = o.json()["entry_hash"]
        .as_str()
        .expect("PRODUCT: `vox room post --json` must name the entry it posted")
        .to_owned();
    until(
        &r.workers[0],
        None,
        "late's question to reach alice",
        &["room", "read", &room],
        |o| o.stdout.contains("Is the late build out?"),
    );
    let _ = late(&r.workers[1], "Stop", "");
    r.stop(1);
    let o = r.workers[0].vox_in(
        Some("alice-s"),
        &["room", "post", &room, "--type", "answer", "--re", &q2, "-"],
        Some("CANARY-START-R: it is out"),
    );
    assert!(
        o.ok,
        "PRODUCT (staging): alice could not answer while bob was down: {o:?}"
    );
    post_text(
        &r.workers[0],
        &room,
        &to_node(
            r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"late: CANARY-START-U"}"#,
            &r.workers[1],
        ),
    );
    // Long enough for both to reach the anchor, from which bob's node takes them when it starts.
    std::thread::sleep(Duration::from_secs(3));
    let started = Instant::now();
    r.restart(1);
    let up = started.elapsed().as_secs_f64();
    // The two may reach bob's restarted node in separate syncs, and one notice is outstanding at
    // a time (ADR-020 §6.15 RA-8): what lands behind an outstanding notice is counted in the next,
    // or read by the turn the first one starts. So each notice's turn is taken, as its harness
    // takes it, until those turns have read both.
    let (mut frames, mut told, mut read) = (Vec::new(), Vec::new(), String::new());
    while !(read.contains("CANARY-START-R") && read.contains("CANARY-START-U")) {
        let (got, _stall) = collect(&late_inbox, Duration::from_secs(20), |g| {
            g.contains("Notice reference")
        });
        let Some(notice) = contents(&got).into_iter().next() else {
            break;
        };
        frames.extend(got);
        read.push_str(&late(&r.workers[1], "UserPromptSubmit", &notice));
        told.push(notice);
    }
    println!(
        "[proof] (9) after a restart ({up:.1}s to come back): notices {told:?}; their turns read \
         the reply {} and the urgent message {}; message bytes at the socket {}",
        read.matches("CANARY-START-R").count(),
        read.matches("CANARY-START-U").count(),
        frames.join("\n").contains("CANARY-START")
    );
    check(
        &mut failures,
        !told.is_empty()
            && told
                .iter()
                .all(|n| n.contains("unread room message(s) from alice"))
            && read.matches("CANARY-START-R").count() == 1
            && read.matches("CANARY-START-U").count() == 1
            && !frames.join("\n").contains("CANARY-START"),
        format!(
            "PRODUCT (9): an urgent message and a reply that landed while the daemon was down \
             must be announced once it is back, and the turns the notices start must read each \
             once; got {told:?}, read {read:?}; bob's daemon:\n{}",
            bob_err()
        ),
    );

    assert!(
        failures.is_empty(),
        "PRODUCT: {} claim(s) failed:\n- {}",
        failures.len(),
        failures.join("\n- ")
    );
}

#[test]
#[ignore = "an anchor and two vox daemons with production Argon2id; CI runs it in release"]
fn two_sessions_answering_each_other_stop_being_told_at_the_hop_budget() {
    watchdog::arm();
    label_reds();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: a tokio runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
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
    let native = native_attention(&r.workers[0]);
    // A turn starts as Claude Code starts it with Vox installed (both prompt hooks); `Stop` is one
    // hook.
    let event = |i: usize, name: &str, prompt: Option<&str>| {
        let (w, me, _, _) = &sides[i];
        let env = [
            ("CLAUDE_CODE_MESSAGING_SOCKET", socks[i].as_str()),
            ("CLAUDE_CODE_MESSAGING_TOKEN", "pp-token"),
            ("VOX_CLAUDE_NATIVE_ATTENTION", native.as_str()),
        ];
        match prompt {
            Some(prompt) => claude_turn(w, &env, &room, me, prompt),
            None => hook(
                w,
                &env,
                &["agent", "hook", "--node", "default", "--room", &room],
                Some(&hook_json(name, me, None)),
            ),
        }
    };
    // Each side answers what it was told, addressed back, as its model would; then its turn ends.
    let answer = |i: usize, re: Option<&str>, body: &str| -> String {
        let (w, me, _, _) = &sides[i];
        // `--to` names the other side's node, by this node's name for it (v0.2.10).
        let other = sides[1 - i].0.name.as_str();
        let mut args = vec![
            "room", "post", &room, "--type", "answer", "--to", other, "--json",
        ];
        if let Some(re) = re {
            args.extend(["--re", re]);
        }
        args.push("-");
        let o = w.vox_in(Some(me), &args, Some(body));
        assert!(o.ok, "PRODUCT (staging): {me} could not post: {o:?}");
        o.json()["entry_hash"]
            .as_str()
            .expect("PRODUCT: `vox room post --json` must name the entry it posted")
            .to_owned()
    };
    for i in 0..2 {
        let _ = event(i, "UserPromptSubmit", Some("hi"));
        assert_eq!(
            registered_endpoint(sides[i].0, sides[i].1),
            ("claude".to_owned(), socks[i].clone()),
            "PRODUCT (staging): {} must be registered at the test's own socket",
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
        "PRODUCT (staging): the first question must start with the default budget of 8: {hops:?}"
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

/// V030-17 — **a sender is told how each node it addresses can be reached.** Three profiles in
/// one room. On bob's node a Codex-shaped session (a session id, `VOX_HARNESS=codex`, and no wake
/// endpoint, which is how Codex runs) takes part in work coordination, so its `hello` is posted,
/// and alice's node receives it by sync. Carol's node never announces a session. Alice then posts
/// an urgent `ask` with `vox room post --to bob --to carol`. Asserted, from what the shipped
/// binaries print:
///
/// 1. the `hello` alice reads says `data.wake` is `turn`, and which machine bob's node runs on:
///    `data.os`, `data.os_version` and `data.arch`, this machine's, filled by Vox (ADR-020 §4.9b);
/// 2. alice is told, for bob, "urgent will not interrupt it", that each side trusts the other,
///    when it last posted, and the machine it says it runs on;
/// 3. for carol, "none of its sessions has announced itself in this room";
/// 4. nothing she is told says "overdue": her node cannot see another node's reads.
///
/// **Mutation.** Drop `data.wake` from the `hello` (`coord::participate`), and (1) and (2) go red:
/// alice is told the hello does not say whether it can be interrupted. Drop the machine fields
/// (`platform::insert` there), and (1) goes red.
#[test]
#[ignore = "an anchor and three vox daemons with production Argon2id; CI runs it in release"]
fn a_sender_is_told_how_each_addressee_can_be_reached() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("APPARATUS: could not build a runtime: {e}"));
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let r = rt.block_on(support::room(tmp.path(), &["alice", "bob", "carol"]));
    let (alice, bob) = (&r.workers[0], &r.workers[1]);
    let room = r.id.clone();

    // ---- bob's Codex-shaped session takes part in work coordination, so it says hello ----
    // A Session posts only once its node has registered it, as its harness's hook does at the
    // start of a turn (ADR-020 §6.15 RA-3); so does alice's below.
    support::register_sending_session(bob, &room, "codex-thread-1");
    let o = bob.vox_env(
        Some("codex-thread-1"),
        &[("VOX_HARNESS", "codex")],
        &[
            "room",
            "post",
            &room,
            "--type",
            "status",
            "--work",
            "test:v030-17",
            "-",
        ],
        Some("looking at the reach report"),
    );
    assert!(
        o.ok,
        "PRODUCT (staging): the Codex-shaped session's `vox room post --work` failed: {o:?}"
    );

    // ---- (1) alice's node reads bob's hello, which says how that session is reached ----
    let is_hello = |row: &serde_json::Value| {
        row["envelope"]["type"] == "hello" && row["envelope"]["from"] == "codex-thread-1"
    };
    let read = until(
        alice,
        None,
        "bob's Codex-shaped session's hello to reach alice",
        &["room", "read", &room, "--json"],
        |o| o.ok && o.ndjson().iter().any(is_hello),
    );
    let hello = read
        .ndjson()
        .into_iter()
        .find(is_hello)
        .unwrap_or_else(|| panic!("APPARATUS: the hello `until` found is gone: {read:?}"));
    println!("[proof] alice reads bob's hello: {}", hello["envelope"]);
    assert_eq!(
        hello["envelope"]["data"]["wake"].as_str(),
        Some("turn"),
        "PRODUCT: a session with no wake endpoint must say in its hello that it is reached at its \
         turn (data.wake = turn); alice reads: {}",
        hello["envelope"]
    );
    // Which machine: the same one this proof runs on, since every node here does.
    let os = if cfg!(target_os = "macos") {
        "macOS"
    } else {
        "Linux"
    };
    let data = &hello["envelope"]["data"];
    assert!(
        data["os"].as_str() == Some(os)
            && data["arch"].as_str() == Some(std::env::consts::ARCH)
            && data["os_version"].as_str().is_some_and(|v| !v.is_empty()),
        "PRODUCT: a hello must say which machine its node runs on, filled by Vox: os {os:?}, \
         arch {:?} and its OS version (ADR-020 §4.9b); alice reads: {data}",
        std::env::consts::ARCH
    );
    let machine = format!(
        "{os} {} ({})",
        data["os_version"].as_str().unwrap_or_default(),
        std::env::consts::ARCH
    );

    // ---- (2)-(4) alice addresses bob's node, and carol's, where no session announced itself ----
    support::register_sending_session(alice, &room, "alice-session");
    let o = alice.vox_in(
        Some("alice-session"),
        &[
            "room", "post", &room, "--type", "ask", "--to", "bob", "--to", "carol", "--urgent", "-",
        ],
        Some("can you look at this now?"),
    );
    assert!(
        o.ok,
        "PRODUCT: alice's urgent `vox room post --to` failed: {o:?}"
    );
    let told = |name: &str| {
        o.stderr
            .lines()
            .find(|l| l.starts_with(&format!("vox: to {name}: ")))
            .unwrap_or_else(|| {
                panic!(
                    "PRODUCT: `vox room post --to {name}` told alice nothing about {name}; its \
                     stderr: {}",
                    o.stderr
                )
            })
            .to_owned()
    };
    let (to_bob, to_carol) = (told("bob"), told("carol"));
    println!("[proof] alice is told:\n  {to_bob}\n  {to_carol}");
    assert!(
        to_bob.contains("urgent will not interrupt it"),
        "PRODUCT: an urgent message to a node whose sessions cannot be interrupted must say so: \
         {to_bob}"
    );
    assert!(
        to_bob.contains("you trust it") && to_bob.contains("it trusts you"),
        "PRODUCT: alice and bob trust each other, and alice must be told so in both directions: \
         {to_bob}"
    );
    assert!(
        to_bob.contains("last posted "),
        "PRODUCT: bob's session posted, and alice must be told when: {to_bob}"
    );
    assert!(
        to_bob.contains(&format!("it says it runs on {machine}")),
        "PRODUCT: alice must be told which machine bob's node says it runs on ({machine}), as its \
         claim (ADR-020 §4.9b): {to_bob}"
    );
    assert!(
        to_carol.contains("none of its sessions has announced itself in this room"),
        "PRODUCT: a node none of whose sessions announced itself must be reported so: {to_carol}"
    );
    assert!(
        !o.stderr.to_lowercase().contains("overdue"),
        "PRODUCT: a sender cannot see another node's reads, so nothing may say overdue: {}",
        o.stderr
    );
}

/// **A wake owed when the daemon died is sent once it is back** (V030-15's startup count;
/// V030-31, #368). At start the daemon counts every session from its cursors: a row that reached
/// the node's store but that the wake loop never looked at before the daemon was killed is
/// history to the restarted loop, and nothing new marks it.
///
/// **Staged every run, with a test-only knob.** Bob's daemon runs with `VOX_TEST_WAKE_DEAF=1`:
/// its node syncs and stores alice's urgent message to bob, and its wake loop judges and sends
/// nothing (`vox daemon` says so at start). Bob's daemon is then killed (SIGKILL, by its own pid)
/// and started again without the knob, as an operator restarts it after a crash. Asserted: bob's
/// session, which never read the message, is woken by the restarted daemon, once, with a notice
/// naming one urgent message from alice and none of its bytes.
///
/// **Mutant:** delete the startup count (`if starting && urgent > 0 { n.urgent_due = true }` in
/// `node_tasks::tend`): the restarted daemon owes nothing, and this goes red as PRODUCT at its own
/// assertion.
#[test]
#[ignore = "an anchor and two vox daemons with production Argon2id; CI runs it in release"]
fn a_wake_owed_when_the_daemon_died_is_sent_after_it_restarts() {
    test_knobs::require(&["VOX_TEST_WAKE_DEAF"]);
    watchdog::arm();
    label_reds();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: a tokio runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let mut r = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let room = r.id.clone();
    let bob_err = || daemon_err(tmp.path(), "bob");

    // bob's session registers and reads everything so far, as in the cases above.
    let sock = tmp.path().join("session.sock");
    let inbox = listen(&sock);
    let sock_s = sock.to_string_lossy().into_owned();
    let native = native_attention(&r.workers[1]);
    let bob_env = [
        ("CLAUDE_CODE_MESSAGING_SOCKET", sock_s.as_str()),
        ("CLAUDE_CODE_MESSAGING_TOKEN", "a-token"),
        ("VOX_CLAUDE_NATIVE_ATTENTION", native.as_str()),
    ];
    let turn =
        |bob: &Worker, prompt: &str| claude_turn(bob, &bob_env, &room, "session-bob", prompt);
    let _ = turn(&r.workers[1], "hi");
    assert_eq!(
        registered_endpoint(&r.workers[1], "session-bob"),
        ("claude".to_owned(), sock_s.clone()),
        "PRODUCT (staging): bob's session must be registered at the test's own socket, never a \
         real session's"
    );
    // Said by alice's session, so that it is not ordinary conversation offered to bob's session
    // (ADR-020 §6.15 RA-1): the only notice this measures is the one owed after the restart.
    support::register_sending_session(&r.workers[0], &room, "session-alice");
    post_as(&r.workers[0], "session-alice", &room, "SYNC-MARKER");
    until(
        &r.workers[1],
        None,
        "alice's marker to reach bob",
        &["room", "read", &room],
        |o| o.stdout.contains("SYNC-MARKER"),
    );
    let _ = turn(&r.workers[1], "hi");

    // ---- bob's daemon, deaf: the message is stored, and nothing judges it ----
    let deaf_err = tmp.path().join("bob.daemon.deaf.err");
    r.workers[1].restart_daemon_as(support::VOX, &[("VOX_TEST_WAKE_DEAF", "1")], &deaf_err);
    // The wake loop says it is off once it starts, which can be after the daemon serves its
    // socket: the line is waited for, never read once.
    let said = {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let said = std::fs::read_to_string(&deaf_err).unwrap_or_default();
            if said.contains("the wake loop judges and sends nothing") || Instant::now() >= deadline
            {
                break said;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    assert!(
        said.contains("the wake loop judges and sends nothing"),
        "CANNOT MEASURE (staging not achieved): bob's daemon did not say within 30 s that its \
         wake loop is off, so the window is not staged; it said:\n{said}"
    );
    post(
        &r.workers[0],
        &room,
        &to_node(
            r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: CANARY-OWED wake up"}"#,
            &r.workers[1],
        ),
    );
    until(
        &r.workers[1],
        None,
        "the urgent message to reach bob's node",
        &["room", "read", &room],
        |o| o.stdout.contains("CANARY-OWED"),
    );
    // Ten seconds, five of the daemon's sweeps: the deaf loop must have sent nothing, or the
    // window is not what this measures.
    let (early, _) = collect(&inbox, Duration::from_secs(10), |_| false);
    assert!(
        contents(&early).is_empty(),
        "CANNOT MEASURE (staging not achieved): bob's deaf daemon woke the session anyway, so \
         the restart has nothing to owe: {early:?}"
    );

    // ---- killed, and started again as an operator does ----
    let err = tmp.path().join("bob.daemon.restart.err");
    r.workers[1].restart_daemon_as(support::VOX, &[], &err);
    let (frames, stall) = collect(&inbox, Duration::from_secs(20), |all| {
        !contents(&[all.to_owned()]).is_empty()
    });
    let wakes = contents(&frames);
    let all = frames.join("\n");
    println!(
        "[proof] after the restart bob's session got {} notice(s): {wakes:?}",
        wakes.len()
    );
    assert!(
        !(wakes.is_empty() && stalled(stall, Duration::from_secs(20))),
        "APPARATUS, CANNOT MEASURE: the collecting loop itself stalled {stall:?} of its 20 s \
         window, so a missing wake cannot be judged; bob's daemon:\n{}",
        bob_err()
    );
    assert!(
        wakes.len() == 1
            && wakes[0].contains("1 unread room message(s) from alice")
            && !all.contains("CANARY-OWED"),
        "PRODUCT: an urgent message bob's node stored but never judged before its daemon was \
         killed must wake his session once its daemon is back — the startup count — with a \
         notice naming one urgent message from alice and none of its bytes; received \
         {frames:?}; bob's daemon:\n{}",
        bob_err()
    );
}
