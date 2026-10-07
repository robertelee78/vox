//! ADR-029 SC-1, DR-1–DR-7 (#541, #542, #544) — **a Codex session and an OpenCode session reach
//! their Sessions, and a member with drive steers each, reaching exactly that session or told why
//! not.**
//!
//! One journey per harness, each driven the way a person drives it: the agent's node registers
//! the session through its hook as the harness runs it; the person, a member with drive, reads the
//! Session with `vox room session` and drives it with the same verb.
//!
//! The harnesses are stand-ins, as apparatus:
//!
//! - **Codex**: an app-server on `<CODEX_HOME>/app-server-control/app-server-control.sock`
//!   speaking Codex 0.160.1's JSON-RPC over a WebSocket, its frames shaped as recorded from a real
//!   sandboxed session (2026-10-06): a thread is subscribed with `thread/resume`, refused with "no
//!   rollout found" until its first turn starts, and only a subscriber hears its items and
//!   requests; a closed thread loses its subscribers.
//! - **OpenCode**: the shipped plugin (`vox agent plugin opencode`) hosted under node
//!   (`support/opencode_plugin_host.mjs`) with no OpenCode and no model: its `event` hook is fed
//!   OpenCode's bus events, and its in-process client records the calls the plugin makes.
//!
//! **Codex** (`a_codex_session_is_mirrored_and_driven`):
//!
//! 1. One daemon, three nodes: `person` (whose room it is), `codex-a` (the agent's node, which
//!    trusts `person` with drive) and `watcher` (a member `codex-a` trusts to read only).
//! 2. Two Codex sessions of `codex-a` register through its hook, S1 then S2, so S2 is the newer.
//! 3. S1's first turn: a command that asks approval, then the reply and the turn's end. `person`
//!    reads the approval waiting in Session S1 and approves it with `vox room session --approve`;
//!    the app-server is answered `accept` on that request's id, and the Session reads "approved
//!    here" once Codex says the request was settled.
//! 4. S1 closes and is resumed under its id (`codex resume`): its second turn's reply reaches the
//!    Session.
//! 5. `person --say` to S1 reaches S1's thread alone as `turn/start`; `--slash /clear` is refused
//!    (it would start a new thread, DR-7); `watcher --say` is refused (no drive, DR-2), naming
//!    the agent's node as the watcher knows it, never by the node's own name.
//! 6. The app-server goes away: `--say` to S1 is refused and says why (DR-5, DR-6).
//!
//! **OpenCode** (`an_opencode_session_is_mirrored_and_driven`): one session of `oc-a` through the
//! hosted plugin: its prompt, a tool call, a question asked and answered by `person` with
//! `--answer` (the plugin replies to that question on OpenCode's API), the reply and the turn's
//! end, all in its Session; `--interrupt` reaches it as OpenCode's abort of that session.
//!
//! **Which side a red is on.** What `vox room session` printed, what the stand-in app-server
//! received, and the calls the hosted plugin made are `PRODUCT:`. Setup the product refused (`vox
//! node create`, the room, trust) is `APPARATUS (staging):` with what it said; a fixture this proof
//! could not make, or `node` missing, is `APPARATUS:` / `CANNOT MEASURE`.
//!
//! **Mutations that must turn it red**, one per claim: a closed thread not subscribed again (#541,
//! "miss events after a resume") → no second reply; the plugin's `question.asked` not forwarded
//! (#542, "drop a question event") → no question line; drive input handed to the node's newest
//! session instead of the named one (#544) → `turn/start` on S2's thread.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/typed.rs"]
mod typed;

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

/// A short root for the run's directories: a Unix socket's path must fit the platform's bound
/// (104 bytes on macOS), which the system's temporary directory does not leave room for.
#[cfg(target_os = "macos")]
const SHORT_ROOT: &str = "/private/tmp/vc";
#[cfg(not(target_os = "macos"))]
const SHORT_ROOT: &str = "/tmp/vc";

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const PERSON: &str = "person";
const WATCHER: &str = "watcher";
const CODEX: &str = "codex-a";
const OPENCODE: &str = "oc-a";
/// Codex's thread ids, which are its session ids.
const S1: &str = "01a113e7-0028-7e11-b029-4f938182ea15";
const S2: &str = "01a113e7-6929-78f2-b2ab-cf24c3d40c85";
/// OpenCode's session id.
const OC: &str = "ses_vox_drive_proof_0001";

/// The daemon `vox node attach` started for the run's data root, stopped by its own PID (the
/// one in `.daemon/lock`) when dropped.
struct Daemon(PathBuf);

impl Drop for Daemon {
    fn drop(&mut self) {
        let pid = std::fs::read_to_string(self.0.join(".daemon/lock"))
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok());
        if let Some(pid) = pid {
            let _ = Command::new("/bin/kill")
                .args(["-TERM", &pid.to_string()])
                .status();
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_secs(15)
                && Command::new("/bin/kill")
                    .args(["-0", &pid.to_string()])
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success())
            {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// A child killed by its PID when dropped.
struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct World {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    data: PathBuf,
    cfg: PathBuf,
    room: String,
}

impl World {
    fn command(&self, node: &str, args: &[&str]) -> Command {
        let mut c = Command::new(VOX);
        c.env_clear()
            // A proof's daemon never takes port 1080 (.cargo/config.toml).
            .env("VOX_PROXY", "127.0.0.1:0")
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.root.join("home"))
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env("VOX_IDENTITY_PASSPHRASE", format!("pass of {node}"))
            .env("VOX_NODE", node)
            .env("VOX_LISTEN", "127.0.0.1:0")
            .args(args);
        c
    }

    fn vox(&self, node: &str, args: &[&str], input: Option<&str>) -> (bool, String, String) {
        // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028
        // K-13).
        if typed::is_keyring_change(args) {
            let (ok, shown) = typed::keyring(&self.command(node, args));
            return (ok, shown.clone(), shown);
        }
        let mut child = self
            .command(node, args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot start `vox {}`: {e}", args.join(" ")));
        if let Some(text) = input {
            if let Some(mut pipe) = child.stdin.take() {
                let _ = pipe.write_all(text.as_bytes());
            }
        }
        let out = child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("APPARATUS: `vox {}`: {e}", args.join(" ")));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn staged(&self, node: &str, args: &[&str], input: Option<&str>) -> String {
        let (ok, out, err) = self.vox(node, args, input);
        assert!(
            ok,
            "APPARATUS (staging): `vox {}` as {node} failed: {out}{err}",
            args.join(" ")
        );
        out
    }

    /// `node`'s whole fingerprint.
    fn fp(&self, node: &str) -> String {
        self.staged(node, &["id"], None).trim().to_owned()
    }

    /// Read `session`'s Session as `PERSON` until it shows `want`, within `within`.
    fn read_until(&self, session: &str, want: &str, within: Duration) -> String {
        let deadline = Instant::now() + within;
        loop {
            let (ok, plain, err) =
                self.vox(PERSON, &["room", "session", &self.room, session], None);
            if ok && plain.contains(want) {
                return plain;
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT: within {within:?}, {PERSON} (with drive) never read {want:?} in Session \
                 {session}; `vox room session` said:\n{plain}{err}"
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    /// `node` drives `session` with `args` (`--say …` and the like): (delivered, what it said).
    fn drive(&self, node: &str, session: &str, args: &[&str]) -> (bool, String) {
        let mut argv = vec!["room", "session", self.room.as_str(), session];
        argv.extend_from_slice(args);
        let (ok, out, err) = self.vox(node, &argv, None);
        (ok, format!("{out}{err}"))
    }
}

/// One daemon and the nodes named, all in one room `PERSON` made, each agent node trusting
/// `PERSON` with drive and `WATCHER` to read, and trusted back by them.
fn world(agents: &[&str]) -> (World, Daemon) {
    std::fs::create_dir_all(SHORT_ROOT)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make {SHORT_ROOT}: {e}"));
    let tmp = tempfile::Builder::new()
        .prefix("cd-")
        .tempdir_in(SHORT_ROOT)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make a temp directory: {e}"));
    let root = tmp.path().to_path_buf();
    for d in ["home", "work", "cx", "oc"] {
        std::fs::create_dir_all(root.join(d))
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make {d}: {e}"));
    }
    let mut w = World {
        data: root.join("vd"),
        cfg: root.join("vc"),
        root,
        _tmp: tmp,
        room: String::new(),
    };
    let mut nodes = vec![PERSON, WATCHER];
    nodes.extend_from_slice(agents);
    for node in &nodes {
        w.staged(node, &["node", "create", node], None);
    }
    let (ok, out, err) = w.vox(PERSON, &["node", "attach", PERSON], None);
    let daemon = Daemon(w.data.clone());
    assert!(
        ok,
        "APPARATUS (staging): `vox node attach {PERSON}` failed: {out}{err}"
    );
    for node in &nodes[1..] {
        w.staged(node, &["node", "attach", node], None);
    }
    w.staged(
        PERSON,
        &["room", "create", "--passphrase-file", "-", "--name", "work"],
        Some("room passphrase\n"),
    );
    let list = w.staged(PERSON, &["room", "list"], None);
    w.room = list
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("APPARATUS (staging): `vox room list` shows no room: {list:?}"))
        .to_owned();
    let link = w
        .staged(PERSON, &["room", "link", &w.room], None)
        .trim()
        .to_owned();
    let person = w.fp(PERSON);
    let watcher = w.fp(WATCHER);
    for node in &nodes[1..] {
        let fp = w.fp(node);
        w.staged(PERSON, &["trust", "add", &fp, "--name", node], None);
        w.staged(
            node,
            &["room", "join", "--passphrase-file", "-", &link],
            Some("room passphrase\n"),
        );
    }
    for agent in agents {
        let fp = w.fp(agent);
        // The watcher's own name for the agent's node, not the node's name for itself: what the
        // watcher is told names it so (#544).
        w.staged(
            WATCHER,
            &["trust", "add", &fp, "--name", &format!("seen-{agent}")],
            None,
        );
        w.staged(
            agent,
            &["trust", "add", &person, "--name", PERSON, "--drive"],
            None,
        );
        w.staged(agent, &["trust", "add", &watcher, "--name", WATCHER], None);
    }
    println!(
        "[proof] (1) room {}: {agents:?} trust {PERSON} with drive, {WATCHER} to read",
        w.room
    );
    (w, daemon)
}

// ---- the Codex app-server stand-in ------------------------------------------------------------

/// What the stand-in holds: its clients, who is subscribed to what, and what it was sent.
#[derive(Default)]
struct AppState {
    clients: Vec<(u64, tokio::sync::mpsc::UnboundedSender<Value>)>,
    subscribed: BTreeSet<(u64, String)>,
    /// Threads whose rollout exists: their first turn has started.
    rollout: BTreeSet<String>,
    /// Every request and answer a client sent, in order.
    received: Vec<Value>,
    next_client: u64,
}

/// A Codex app-server, as apparatus.
struct AppServer {
    rt: tokio::runtime::Runtime,
    state: Arc<Mutex<AppState>>,
    path: PathBuf,
}

impl AppServer {
    fn start(codex_home: &Path) -> Self {
        let dir = codex_home.join("app-server-control");
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make {dir:?}: {e}"));
        let path = dir.join("app-server-control.sock");
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap_or_else(|e| panic!("APPARATUS: no runtime for the app-server: {e}"));
        let state: Arc<Mutex<AppState>> = Arc::default();
        let listener = {
            let _g = rt.enter();
            tokio::net::UnixListener::bind(&path)
                .unwrap_or_else(|e| panic!("APPARATUS: cannot listen on {path:?}: {e}"))
        };
        let st = Arc::clone(&state);
        rt.spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let st = Arc::clone(&st);
                tokio::spawn(async move {
                    let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    let (mut tx_ws, mut rx_ws) = ws.split();
                    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
                    let me = {
                        let mut s = st.lock().unwrap();
                        s.next_client += 1;
                        let me = s.next_client;
                        s.clients.push((me, tx.clone()));
                        me
                    };
                    loop {
                        tokio::select! {
                            out = rx.recv() => {
                                let Some(v) = out else { break };
                                if tx_ws.send(Message::text(v.to_string())).await.is_err() {
                                    break;
                                }
                            }
                            got = rx_ws.next() => {
                                let Some(Ok(Message::Text(t))) = got else {
                                    if matches!(got, Some(Ok(_))) { continue }
                                    break;
                                };
                                let Ok(v) = serde_json::from_str::<Value>(t.as_str()) else {
                                    continue;
                                };
                                if let Some(reply) = answer(&st, me, &v) {
                                    let _ = tx.send(reply);
                                }
                            }
                        }
                    }
                    let mut s = st.lock().unwrap();
                    s.clients.retain(|(c, _)| *c != me);
                    s.subscribed.retain(|(c, _)| *c != me);
                });
            }
        });
        Self { rt, state, path }
    }

    /// A notification every client hears, subscribed or not.
    fn tell_all(&self, method: &str, params: Value) {
        let v = json!({"jsonrpc": "2.0", "method": method, "params": params});
        for (_, c) in &self.state.lock().unwrap().clients {
            let _ = c.send(v.clone());
        }
    }

    /// A notification, or a request with `id`, that only `thread`'s subscribers hear. How many
    /// heard it.
    fn tell_subscribers(
        &self,
        thread: &str,
        method: &str,
        params: Value,
        id: Option<u64>,
    ) -> usize {
        let mut v = json!({"jsonrpc": "2.0", "method": method, "params": params});
        if let Some(id) = id {
            v["id"] = json!(id);
        }
        let s = self.state.lock().unwrap();
        let mut n = 0;
        for (c, tx) in &s.clients {
            if s.subscribed.contains(&(*c, thread.to_owned())) {
                let _ = tx.send(v.clone());
                n += 1;
            }
        }
        n
    }

    fn subscribers(&self, thread: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .subscribed
            .iter()
            .filter(|(_, t)| t == thread)
            .count()
    }

    /// A thread's first turn begins: its rollout exists, and every client hears it go active.
    fn activate(&self, thread: &str) {
        self.state.lock().unwrap().rollout.insert(thread.to_owned());
        self.tell_all(
            "thread/status/changed",
            json!({"threadId": thread, "status": {"type": "active", "activeFlags": []}}),
        );
    }

    /// Wait until `thread` has a subscriber, within `within`.
    fn wait_subscribed(&self, thread: &str, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if self.subscribers(thread) > 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    /// The first thing a client sent that `pred` takes, within `within`.
    fn received(&self, within: Duration, pred: impl Fn(&Value) -> bool) -> Option<Value> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(v) = self.state.lock().unwrap().received.iter().find(|v| pred(v)) {
                return Some(v.clone());
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The thread closes (its TUI quit and Codex unloaded it): its subscriptions end.
    fn close(&self, thread: &str) {
        {
            let mut s = self.state.lock().unwrap();
            s.subscribed.retain(|(_, t)| t != thread);
        }
        self.tell_all("thread/closed", json!({"threadId": thread}));
    }

    fn stop(self) {
        let path = self.path.clone();
        self.rt.shutdown_background();
        let _ = std::fs::remove_file(path);
    }
}

/// The stand-in's answer to what a client sent, recorded first.
fn answer(st: &Arc<Mutex<AppState>>, me: u64, v: &Value) -> Option<Value> {
    let mut s = st.lock().unwrap();
    s.received.push(v.clone());
    let id = v.get("id")?.clone();
    let method = v.get("method").and_then(Value::as_str)?;
    let result = match method {
        "initialize" => json!({"userAgent": "codex-standin/0.160.1", "platformOs": "macos"}),
        "thread/resume" => {
            let thread = v.pointer("/params/threadId").and_then(Value::as_str)?;
            if !s.rollout.contains(thread) {
                return Some(json!({"id": id, "error": {
                    "code": -32600, "message": format!("no rollout found for thread id {thread}")
                }}));
            }
            s.subscribed.insert((me, thread.to_owned()));
            json!({"thread": {"id": thread}})
        }
        _ => json!({}),
    };
    Some(json!({"id": id, "result": result}))
}

// ---- Codex ------------------------------------------------------------------------------------

/// Codex running its hook for a prompt in `thread`, as Codex 0.160.1 sends it: synchronous, with
/// the thread's rollout as its transcript and its turn.
fn codex_prompt(w: &World, thread: &str, prompt: &str) {
    let input = json!({
        "session_id": thread,
        "transcript_path": w.root.join(format!("cx/sessions/rollout-2026-10-06-{thread}.jsonl")).display().to_string(),
        "cwd": w.root.join("work").display().to_string(),
        "hook_event_name": "UserPromptSubmit",
        "model": "gpt-5.5-codex",
        "permission_mode": "default",
        "turn_id": format!("turn-{thread}"),
        "prompt": prompt,
    });
    let mut child = w
        .command(
            CODEX,
            &["agent", "hook", "--node", CODEX, "--room", &w.room],
        )
        .env("CODEX_HOME", w.root.join("cx"))
        .current_dir(w.root.join("work"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start `vox agent hook`: {e}"));
    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(input.to_string().as_bytes())
            .unwrap_or_else(|e| panic!("APPARATUS: cannot give the hook its input: {e}"));
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: the hook: {e}"));
    assert!(
        out.status.success(),
        "PRODUCT: Codex's UserPromptSubmit hook exited {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn item(kind: &str, id: &str, extra: Value) -> Value {
    let mut v = json!({"type": kind, "id": id});
    if let (Some(m), Some(e)) = (v.as_object_mut(), extra.as_object()) {
        for (k, x) in e {
            m.insert(k.clone(), x.clone());
        }
    }
    v
}

#[test]
#[ignore = "real binary; run in release"]
fn a_codex_session_is_mirrored_and_driven() {
    watchdog::arm_for(Duration::from_secs(600));
    let (w, _daemon) = world(&[CODEX]);
    let app = AppServer::start(&w.root.join("cx"));
    let within = Duration::from_secs(60);

    // ---- (2) two sessions register, S1 then S2; every client hears each thread start ----
    for (thread, prompt) in [(S1, "Make e1."), (S2, "Nothing yet.")] {
        app.tell_all(
            "thread/started",
            json!({"thread": {"id": thread, "sessionId": thread}}),
        );
        codex_prompt(&w, thread, prompt);
    }
    // The first turn of each starts: its rollout exists, and Vox subscribes.
    for thread in [S1, S2] {
        app.activate(thread);
        assert!(
            app.wait_subscribed(thread, within),
            "PRODUCT: within {within:?} of thread {thread} going active, Vox never subscribed to \
             it on Codex's app-server (no successful thread/resume)"
        );
    }
    println!("[proof] (2) Vox subscribed to S1 and S2 on the app-server");

    // ---- (3) S1's turn: a command asks approval; person approves it from the Session ----
    let turn = "turn-s1-1";
    let exec = "exec-54df30bc-e896-4ded-9f43-7fd5e54d4edf";
    let cmd = "/bin/zsh -lc 'printf %s vox > e1'";
    app.tell_subscribers(
        S1,
        "turn/started",
        json!({"threadId": S1, "turn": {"id": turn}}),
        None,
    );
    app.tell_subscribers(
        S1,
        "item/started",
        json!({"threadId": S1, "turnId": turn, "item": item("commandExecution", exec,
            json!({"command": cmd, "status": "inProgress", "aggregatedOutput": null, "exitCode": null}))}),
        None,
    );
    app.tell_subscribers(
        S1,
        "item/commandExecution/requestApproval",
        json!({"threadId": S1, "turnId": turn, "itemId": exec, "command": cmd,
               "reason": "May I create e1 outside the read-only sandbox?",
               "availableDecisions": ["accept", "cancel"]}),
        Some(7),
    );
    let waiting = w.read_until(S1, "approve or reject?", within);
    println!("[proof] (3) Session S1 while the approval waits:\n{waiting}");
    let (ok, said) = w.drive(PERSON, S1, &["--approve", exec]);
    println!("[proof] (3) person --approve: {said}");
    assert!(
        ok,
        "PRODUCT: {PERSON}, with drive, approving the request waiting in S1 must be handed to \
         the session; `vox room session --approve` said: {said}"
    );
    let accepted = app.received(within, |v| {
        v.get("id") == Some(&json!(7)) && v.get("result").is_some()
    });
    println!("[proof] (3) the app-server received: {accepted:?}");
    assert_eq!(
        accepted
            .as_ref()
            .and_then(|v| v.pointer("/result/decision")),
        Some(&json!("accept")),
        "PRODUCT: the approval must reach Codex as `accept` on that request's id (7); the \
         app-server received {accepted:?}"
    );
    // Codex settles the request, runs the command, replies and ends the turn.
    app.tell_subscribers(
        S1,
        "serverRequest/resolved",
        json!({"threadId": S1, "requestId": 7}),
        None,
    );
    app.tell_subscribers(
        S1,
        "item/completed",
        json!({"threadId": S1, "turnId": turn, "item": item("commandExecution", exec,
            json!({"command": cmd, "status": "completed", "aggregatedOutput": "", "exitCode": 0}))}),
        None,
    );
    app.tell_subscribers(
        S1,
        "item/completed",
        json!({"threadId": S1, "turnId": turn, "item": item("agentMessage", "msg-1",
            json!({"text": "first reply: e1 is made", "phase": "final_answer"}))}),
        None,
    );
    app.tell_subscribers(
        S1,
        "turn/completed",
        json!({"threadId": S1, "turn": {"id": turn}}),
        None,
    );
    let turn1 = w.read_until(S1, "reply: first reply: e1 is made", within);
    println!("[proof] (3) Session S1 after the turn:\n{turn1}");
    assert!(
        turn1.contains("approved here") && turn1.contains("— turn ended —"),
        "PRODUCT: Session S1 must show the approval as approved here (Codex settled it with \
         Vox's answer) and the turn's end; it showed:\n{turn1}"
    );

    // ---- (4) S1 closes and is resumed under its id: its next turn reaches the Session ----
    app.close(S1);
    std::thread::sleep(Duration::from_millis(500));
    app.tell_all(
        "thread/started",
        json!({"thread": {"id": S1, "sessionId": S1}}),
    );
    app.tell_all(
        "thread/status/changed",
        json!({"threadId": S1, "status": {"type": "active", "activeFlags": []}}),
    );
    let resumed = app.wait_subscribed(S1, within);
    let heard = app.tell_subscribers(
        S1,
        "item/completed",
        json!({"threadId": S1, "turnId": "turn-s1-2", "item": item("agentMessage", "msg-2",
            json!({"text": "second reply, after the resume", "phase": "final_answer"}))}),
        None,
    );
    app.tell_subscribers(
        S1,
        "turn/completed",
        json!({"threadId": S1, "turn": {"id": "turn-s1-2"}}),
        None,
    );
    assert!(
        resumed && heard > 0,
        "PRODUCT: after S1 was closed and resumed under its id, Vox never subscribed to it again \
         within {within:?}, so its second turn reached no one (#541: events after a resume)"
    );
    let turn2 = w.read_until(S1, "reply: second reply, after the resume", within);
    println!("[proof] (4) Session S1 after the resume:\n{turn2}");

    // ---- (5) person types into S1: S1's thread alone gets the turn; /clear and watcher refused --
    let (ok, said) = w.drive(PERSON, S1, &["--say", "carry on with e2"]);
    println!("[proof] (5) person --say to S1: {said}");
    assert!(
        ok,
        "PRODUCT: {PERSON}'s typed text to idle S1 must be delivered; it said: {said}"
    );
    let started = app.received(within, |v| v["method"] == "turn/start");
    println!("[proof] (5) the app-server received: {started:?}");
    let started = started.unwrap_or_else(|| {
        panic!("PRODUCT: no turn/start reached the app-server for {PERSON}'s typed text")
    });
    assert_eq!(
        started.pointer("/params/threadId"),
        Some(&json!(S1)),
        "PRODUCT: typed text for S1 must start a turn on S1's thread alone, never another \
         session's (DR-5); turn/start named {:?}",
        started.pointer("/params/threadId")
    );
    assert_eq!(
        started.pointer("/params/input/0/text"),
        Some(&json!("carry on with e2")),
        "PRODUCT: the turn must carry the typed text; it carried {started}"
    );
    w.read_until(S1, "typed in Vox by", within);
    let (ok, said) = w.drive(PERSON, S1, &["--slash", "/clear"]);
    println!("[proof] (5) person --slash /clear: {said}");
    assert!(
        !ok && said.contains("new Codex thread"),
        "PRODUCT: /clear must be refused, saying it would start a new Codex thread (DR-7); it \
         said: {said}"
    );
    let (ok, said) = w.drive(WATCHER, S1, &["--say", "may I?"]);
    println!("[proof] (5) watcher --say: {said}");
    assert!(
        !ok && said.contains(&format!("seen-{CODEX} does not trust you with drive")),
        "PRODUCT: {WATCHER}, trusted to read only, must be refused and told it lacks drive \
         (DR-2), naming {CODEX}'s node as the watcher knows it (seen-{CODEX}), never by the \
         node's own name; it said: {said}"
    );
    let stray = app.received(Duration::from_secs(2), |v| {
        v["method"] == "turn/start" && v.pointer("/params/input/0/text") == Some(&json!("may I?"))
    });
    assert!(
        stray.is_none(),
        "PRODUCT: {WATCHER}'s refused text reached the app-server: {stray:?}"
    );

    // ---- (6) Codex's app-server goes away: driving S1 is refused, and says why ----
    app.stop();
    std::thread::sleep(Duration::from_millis(500));
    let (ok, said) = w.drive(PERSON, S1, &["--say", "are you there?"]);
    println!("[proof] (6) person --say with the app-server gone: {said}");
    assert!(
        !ok && said.contains("app-server"),
        "PRODUCT: with Codex's app-server gone, typing into S1 must be refused and say that \
         the app-server cannot be reached (DR-5, DR-6); it said: {said}"
    );
}

// ---- OpenCode ---------------------------------------------------------------------------------

/// The plugin as OpenCode runs it (`support/opencode_plugin_host.mjs`), one JSON line per command.
struct Host {
    child: Killed,
    lines: std::sync::mpsc::Receiver<String>,
}

impl Host {
    fn ask(&mut self, command: &str, within: Duration) -> Value {
        let stdin = self
            .child
            .0
            .stdin
            .as_mut()
            .expect("APPARATUS: the host's stdin");
        writeln!(stdin, "{command}").expect("APPARATUS: write to the host");
        let line = self.lines.recv_timeout(within).unwrap_or_else(|e| {
            panic!("APPARATUS: the plugin host did not answer {command:?} within {within:?}: {e}")
        });
        let v: Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("APPARATUS: the plugin host said {line:?}: {e}"));
        assert_ne!(
            v["kind"], "apparatus",
            "APPARATUS: the plugin host could not do {command:?}: {v}"
        );
        v
    }

    fn event(&mut self, ev: Value) {
        self.ask(&format!("event {ev}"), Duration::from_secs(10));
    }
}

fn which(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(bin))
            .find(|p| p.is_file())
    })
}

#[test]
#[ignore = "real binary and the shipped plugin under node; run in release"]
fn an_opencode_session_is_mirrored_and_driven() {
    watchdog::arm_for(Duration::from_secs(600));
    let Some(node) = which("node") else {
        panic!(
            "CANNOT MEASURE: `node` is not installed, so the shipped OpenCode plugin cannot be \
             hosted; install Node.js"
        );
    };
    let (w, _daemon) = world(&[OPENCODE]);
    let within = Duration::from_secs(60);
    let plugin = w.staged(
        OPENCODE,
        &["agent", "plugin", "opencode", "--node", OPENCODE],
        None,
    );
    let plugin_path = w.root.join("oc/vox.mjs");
    std::fs::write(&plugin_path, plugin).expect("APPARATUS: install the plugin");
    let host_js =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/opencode_plugin_host.mjs");
    let tmpdir = w.root.join("oc");
    let mut child = Command::new(&node)
        .arg(&host_js)
        .arg(&plugin_path)
        .arg(OC)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", w.root.join("home"))
        .env("TMPDIR", &tmpdir)
        .env("VOX_BIN", VOX)
        .env("VOX_DATA_DIR", &w.data)
        .env("VOX_CONFIG_DIR", &w.cfg)
        .env("VOX_PROXY", "127.0.0.1:0")
        .env("VOX_IDENTITY_PASSPHRASE", format!("pass of {OPENCODE}"))
        // The session's room, as the room map gives it (ADR-029 RB-2).
        .env("VOX_ROOM", &w.room)
        .current_dir(w.root.join("work"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("APPARATUS: start node");
    let out = child.stdout.take().expect("APPARATUS: the host's stdout");
    let (tx, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead as _;
        for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut host = Host {
        child: Killed(child),
        lines,
    };

    // ---- (2) the operator's prompt: the plugin's drain registers the session ----
    host.ask("turn Paint e1 the colour I pick.", within);
    // Its events, as OpenCode's bus gives them to the plugin's `event` hook. Vox follows the
    // session once it registered; the first events may land before it does, so the prompt is
    // given again as OpenCode updates it.
    let user = json!({"type": "message.updated", "properties": {"info": {"id": "msg_u1", "sessionID": OC, "role": "user"}}});
    let typed = json!({"type": "message.part.updated", "properties": {"part": {"id": "prt_u1", "messageID": "msg_u1", "sessionID": OC, "type": "text", "text": "Paint e1 the colour I pick."}}});
    let deadline = Instant::now() + within;
    loop {
        host.event(user.clone());
        host.event(typed.clone());
        let (_, plain, _) = w.vox(PERSON, &["room", "session", &w.room, OC], None);
        if plain.contains("typed at the terminal: Paint e1") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: within {within:?}, the OpenCode session's prompt never reached its \
             Session; `vox room session` said:\n{plain}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    // ---- (3) a tool call, a question answered by person, the reply, the turn's end ----
    host.event(json!({"type": "message.updated", "properties": {"info": {"id": "msg_a1", "sessionID": OC, "role": "assistant", "providerID": "opencode", "modelID": "kimi-k3"}}}));
    host.event(json!({"type": "message.part.updated", "properties": {"part": {"id": "prt_t1", "messageID": "msg_a1", "sessionID": OC, "type": "tool", "tool": "bash", "callID": "call_1", "state": {"status": "running", "input": {"command": "ls e1"}}}}}));
    host.event(json!({"type": "message.part.updated", "properties": {"part": {"id": "prt_t1", "messageID": "msg_a1", "sessionID": OC, "type": "tool", "tool": "bash", "callID": "call_1", "state": {"status": "completed", "input": {"command": "ls e1"}, "output": "e1\n", "title": "ls e1"}}}}));
    let qid = "que_01";
    host.event(json!({"type": "question.asked", "properties": {"id": qid, "sessionID": OC, "questions": [
        {"question": "Which colour?", "header": "Colour", "options": [
            {"label": "blue", "description": "calm"}, {"label": "red", "description": "loud"}], "multiple": false}
    ]}}));
    let asked = w.read_until(OC, "question: Which colour?", within);
    println!("[proof] (3) Session {OC} with the question waiting:\n{asked}");
    let (ok, said) = w.drive(PERSON, OC, &["--answer", qid, "Which colour?=blue"]);
    println!("[proof] (3) person --answer: {said}");
    assert!(
        ok,
        "PRODUCT: {PERSON}'s answer to the question waiting in {OC} must be handed to it; it \
         said: {said}"
    );
    let calls = host.ask("calls 30 1", within)["calls"].clone();
    println!("[proof] (3) the plugin called OpenCode: {calls}");
    let reply = calls.as_array().into_iter().flatten().find(|c| {
        c["url"]
            .as_str()
            .is_some_and(|u| u.starts_with("/question/"))
    });
    assert!(
        reply.is_some_and(|c| c["url"] == format!("/question/{qid}/reply")
            && c["body"]["answers"] == json!([["blue"]])),
        "PRODUCT: the answer must reach OpenCode as a reply to question {qid} with [[\"blue\"]]; \
         the plugin made {calls}"
    );
    host.event(json!({"type": "question.replied", "properties": {"sessionID": OC, "requestID": qid, "answers": [["blue"]]}}));
    host.event(json!({"type": "message.part.updated", "properties": {"part": {"id": "prt_r1", "messageID": "msg_a1", "sessionID": OC, "type": "text", "text": "e1 is blue now."}}}));
    host.event(json!({"type": "session.idle", "properties": {"sessionID": OC}}));
    let done = w.read_until(OC, "— turn ended —", within);
    println!("[proof] (3) Session {OC} after the turn:\n{done}");
    let lines: Vec<&str> = done.lines().collect();
    let at = |needle: &str| lines.iter().position(|l| l.contains(needle));
    let (called, question, replied, ended) = (
        at("bash: ls e1 → ls e1"),
        at("question: Which colour?"),
        at("reply: e1 is blue now."),
        at("— turn ended —"),
    );
    assert!(
        called.is_some() && question.is_some() && replied.is_some() && ended.is_some(),
        "PRODUCT: Session {OC} must show the tool call, the question, the reply and the turn's \
         end; it showed:\n{done}"
    );
    assert!(
        done.lines()
            .any(|l| l.contains("question: Which colour?") && l.contains("blue")),
        "PRODUCT: the question must read as answered with blue; the Session showed:\n{done}"
    );
    assert!(
        called < question && question < replied && replied < ended,
        "PRODUCT: Session {OC} must keep the turn's order; it showed:\n{done}"
    );

    // ---- (4) person interrupts it: OpenCode's abort of that session alone ----
    let (ok, said) = w.drive(PERSON, OC, &["--interrupt"]);
    println!("[proof] (4) person --interrupt: {said}");
    assert!(
        ok,
        "PRODUCT: {PERSON}'s interrupt must be delivered; it said: {said}"
    );
    let calls = host.ask("calls 30 2", within)["calls"].clone();
    assert!(
        calls
            .as_array()
            .into_iter()
            .flatten()
            .any(|c| c["method"] == "POST" && c["url"] == format!("/session/{OC}/abort")),
        "PRODUCT: an interrupt must reach OpenCode as the abort of session {OC}; the plugin made \
         {calls}"
    );
}
