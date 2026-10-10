//! ADR-029 §2–§3 — **a Codex session's activity, read from Codex's app-server as a peer client**
//! (#541), and the way a member with drive steers it (#544).
//!
//! Codex keeps one app-server per `CODEX_HOME`, reached at
//! `<CODEX_HOME>/app-server-control/app-server-control.sock`: JSON-RPC over a WebSocket on a Unix
//! socket. A `codex` TUI started while it runs joins it, whether or not it was started with
//! `--remote` (measured on Codex 0.160.1, 2026-10-06), so its thread is visible to any other
//! client. The daemon is such a client: one connection per app-server, shared by every Codex
//! session of every node that registered from that `CODEX_HOME`.
//!
//! **Subscribing.** An unsubscribed client hears `thread/started`, `thread/status/changed`,
//! `thread/name/updated` and `thread/closed`; only a subscriber hears a thread's turns, items and
//! requests. A subscription (`thread/resume`) fails with "no rollout found" until the thread's
//! first turn has begun, and a turn's beginning is exactly a `thread/status/changed` to active.
//! So a thread is (re)subscribed whenever the server mentions one Vox watches and is not yet
//! subscribed to: no timer. The same holds after a resume (`codex resume` reopens the thread
//! under its old id) and after the daemon reconnects: every watched thread is subscribed again.
//!
//! **What reaches the Session** (SC-1), in the format every harness shares
//! ([`crate::session_mirror`]): each tool call (`commandExecution`, `fileChange`,
//! `mcpToolCall`, and any other tool item) as `tool` and `tool-done`, `ref` the item's id; each
//! reply (`agentMessage`) as `reply`; each turn's end as `turn-end`; each approval request and
//! question as `approval` or `question`, held for the first answer ([`Sink::request`]) and
//! retired by Codex's own `serverRequest/resolved` (DR-4). The operator's prompt is not taken from
//! here: Vox's `UserPromptSubmit` hook posts it for every Codex session, subscribed or not, so it
//! appears once.
//!
//! **Never a run nobody opened** (DR-7). `turn/start` and `turn/steer` are sent only for a
//! thread whose session is registered and has not ended, whose app-server says it is loaded; a
//! wake never comes here. A Codex session whose TUI quit keeps its thread loaded in the
//! app-server (ADR-020 6.12), so its `SessionEnd` ([`CodexMirror::end`]) is what stops driving.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{json, Map, Value};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use vox_core::node::paths::NodeName;

use vox_agentcomms::activity::{one_line, VERSION};
use vox_core::node::content::MAX_TEXT_LEN;

fn split(m: Map<String, Value>, big: &str) -> Vec<String> {
    vox_agentcomms::activity::split(m, big, MAX_TEXT_LEN)
}
use crate::session_sink::{Given, Sink};

/// Where a `CODEX_HOME`'s app-server listens.
#[must_use]
pub fn control_socket(codex_home: &Path) -> PathBuf {
    codex_home.join("app-server-control/app-server-control.sock")
}

/// The `CODEX_HOME` a Codex hook runs under: its own variable, else Codex's default.
#[must_use]
pub fn codex_home_from_env() -> String {
    match std::env::var("CODEX_HOME") {
        Ok(h) if !h.trim().is_empty() => h,
        _ => std::env::var("HOME")
            .map(|h| format!("{h}/.codex"))
            .unwrap_or_default(),
    }
}

/// Keep Codex's app-server running (the decider, 2026-10-06, as ctm does): `codex app-server
/// daemon start`, which starts it only when it is not running. A `codex` started while it runs
/// joins it, so Vox can read and drive that session; one started before runs on its own and is
/// mirrored through its hooks alone. Never waited on: a hook must not hold Codex up, and nothing
/// here depends on the answer.
pub fn ensure_app_server() {
    let _ = std::process::Command::new("codex")
        .args(["app-server", "daemon", "start"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// What a member with drive asks of a Codex session (DR-1.2, 1.3, 1.6). Answers to approvals and
/// questions go through the sink ([`Sink::answer`]), which hands them to the request's waiter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Steer {
    /// Typed text, as the operator's input.
    Text(String),
    /// Esc: stop the turn running now.
    Interrupt,
    /// Ctrl-C: for Codex the same as Esc. The session itself is never closed from Vox.
    Stop,
    /// A slash command: `compact`, `rename <name>`, `clear`, …
    Slash { cmd: String, args: String },
}

/// The daemon's Codex observers, one per app-server.
pub struct CodexMirror {
    sink: Arc<Sink>,
    conns: Mutex<BTreeMap<PathBuf, mpsc::UnboundedSender<Cmd>>>,
    /// Sessions a connection is subscribed to now: their hook activity is not posted again.
    subscribed: Arc<Mutex<BTreeSet<String>>>,
}

enum Cmd {
    Watch {
        node: NodeName,
        session: String,
    },
    End {
        session: String,
    },
    Steer {
        session: String,
        steer: Steer,
        reply: oneshot::Sender<Result<String, String>>,
    },
}

impl CodexMirror {
    /// Observers posting through `sink`.
    #[must_use]
    pub fn new(sink: Arc<Sink>) -> Arc<Self> {
        Arc::new(Self {
            sink,
            conns: Mutex::new(BTreeMap::new()),
            subscribed: Arc::default(),
        })
    }

    fn conn(&self, codex_home: &Path) -> mpsc::UnboundedSender<Cmd> {
        let socket = control_socket(codex_home);
        let mut conns = self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(tx) = conns.get(&socket).filter(|tx| !tx.is_closed()) {
            return tx.clone();
        }
        let (tx, rx) = mpsc::unbounded_channel();
        conns.insert(socket.clone(), tx.clone());
        let (answers, answers_rx) = mpsc::unbounded_channel();
        let conn = Conn {
            told: BTreeSet::new(),
            answers,
            socket,
            sink: Arc::clone(&self.sink),
            subscribed: Arc::clone(&self.subscribed),
            threads: BTreeMap::new(),
            next_id: 1,
            calls: BTreeMap::new(),
            asks: BTreeMap::new(),
        };
        tokio::spawn(conn.run(rx, answers_rx));
        tx
    }

    /// A Codex session of `node` registered from `codex_home` (ADR-020 6.10): watch its thread.
    pub fn watch(&self, codex_home: &Path, node: &NodeName, session: &str) {
        let _ = self.conn(codex_home).send(Cmd::Watch {
            node: node.clone(),
            session: session.to_owned(),
        });
    }

    /// The session ended (its `SessionEnd`): stop watching and driving it.
    pub fn end(&self, session: &str) {
        let conns = self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for tx in conns.values() {
            let _ = tx.send(Cmd::End {
                session: session.to_owned(),
            });
        }
    }

    /// Whether `session`'s activity arrives over the app-server now, so its hooks' copy of the
    /// same activity is not posted again.
    #[must_use]
    pub fn subscribed(&self, session: &str) -> bool {
        self.subscribed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(session)
    }

    /// Steer `session` (#544): what was done, in words, or why it was refused (DR-6).
    ///
    /// # Errors
    /// Why nothing reached the session.
    pub async fn steer(
        &self,
        codex_home: &Path,
        session: &str,
        steer: Steer,
    ) -> Result<String, String> {
        let (reply, rx) = oneshot::channel();
        self.conn(codex_home)
            .send(Cmd::Steer {
                session: session.to_owned(),
                steer,
                reply,
            })
            .map_err(|_| "Vox's connection to Codex's app-server has stopped".to_owned())?;
        rx.await
            .unwrap_or_else(|_| Err("Vox's connection to Codex's app-server stopped".to_owned()))
    }
}

/// One watched thread.
struct Thread {
    node: NodeName,
    subscribed: bool,
    /// The app-server's last word on it: `idle`, `active`, `notLoaded`, `systemError`, `closed`.
    status: String,
    /// The turn running now, from `turn/started`.
    turn: Option<String>,
    /// Tool items whose start was posted, so a completion seen alone still posts one.
    started: BTreeSet<String>,
    /// Subscriptions refused since the thread last changed status. A refusal that crossed the
    /// status change to active (the moment its rollout appears) is retried, at most a few times.
    refused: u8,
}

/// An approval or a question Codex asked, held until it settles.
struct Ask {
    session: String,
    /// The JSON-RPC id Codex is waiting on.
    rpc: Value,
    of: &'static str,
    method: String,
    params: Value,
    /// What Vox answered, if it did, so a refusal shows as such.
    answered: Option<Given>,
    /// `serverRequest/resolved` arrived; for an approval the outcome waits for its item.
    resolved: bool,
}

/// What a JSON-RPC call Vox made is waiting for.
enum Pending {
    Resume(String),
    Steer(oneshot::Sender<Result<String, String>>, String),
    Ignore,
}

struct Conn {
    socket: PathBuf,
    sink: Arc<Sink>,
    subscribed: Arc<Mutex<BTreeSet<String>>>,
    threads: BTreeMap<String, Thread>,
    next_id: u64,
    calls: BTreeMap<u64, Pending>,
    /// By the ref the Session shows: the item id Codex's request names.
    asks: BTreeMap<String, Ask>,
    /// Where a member's first answer to a request comes back to this connection's loop.
    answers: mpsc::UnboundedSender<(String, Given)>,
    /// Sessions already told that Codex's app-server could not be reached.
    told: BTreeSet<String>,
}

type Ws = tokio_tungstenite::WebSocketStream<tokio::net::UnixStream>;

/// Why Codex's app-server could not be reached, in words a driver reads.
fn unreachable(socket: &Path, e: impl std::fmt::Display) -> String {
    format!(
        "Codex's app-server is not reachable at {} ({e}); a Codex session started without it \
         running cannot be steered from Vox",
        socket.display()
    )
}

impl Conn {
    async fn connect(&self) -> Result<Ws, String> {
        let stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .map_err(|e| unreachable(&self.socket, e))?;
        let (ws, _) = tokio_tungstenite::client_async("ws://localhost/", stream)
            .await
            .map_err(|e| unreachable(&self.socket, e))?;
        Ok(ws)
    }

    /// Serve commands; connect when there is something to watch or steer, and again after the
    /// app-server goes away, at the next command.
    async fn run(
        mut self,
        mut rx: mpsc::UnboundedReceiver<Cmd>,
        mut answers: mpsc::UnboundedReceiver<(String, Given)>,
    ) {
        let mut ws: Option<Ws> = None;
        loop {
            let Some(ws_now) = ws.as_mut() else {
                let Some(cmd) = rx.recv().await else { return };
                match self.connect().await {
                    Ok(mut w) => {
                        if self.hello(&mut w).await.is_ok() {
                            ws = Some(w);
                        }
                    }
                    Err(why) => {
                        if let Cmd::Steer { reply, .. } = cmd {
                            let _ = reply.send(Err(why));
                            continue;
                        }
                    }
                }
                let Some(w) = ws.as_mut() else {
                    self.apply_offline(cmd);
                    continue;
                };
                self.command(w, cmd).await;
                self.resubscribe(w).await;
                continue;
            };
            tokio::select! {
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else { return };
                    self.command(ws_now, cmd).await;
                }
                Some((r, given)) = answers.recv() => self.answer(ws_now, &r, given).await,
                frame = ws_now.next() => {
                    match frame {
                        Some(Ok(Message::Text(t))) => {
                            if let Ok(v) = serde_json::from_str::<Value>(t.as_str()) {
                                self.frame(ws_now, v).await;
                            }
                        }
                        Some(Ok(_)) => {}
                        Some(Err(_)) | None => {
                            ws = None;
                            self.gone();
                        }
                    }
                }
            }
        }
    }

    /// The app-server went away: nothing is subscribed, every pending call and request fails.
    fn gone(&mut self) {
        for (_, p) in std::mem::take(&mut self.calls) {
            if let Pending::Steer(reply, _) = p {
                let _ = reply.send(Err(unreachable(&self.socket, "the connection closed")));
            }
        }
        for t in self.threads.values_mut() {
            t.subscribed = false;
            t.turn = None;
        }
        let mut s = self
            .subscribed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in self.threads.keys() {
            s.remove(id);
        }
    }

    /// A command while the app-server cannot be reached: watching is remembered for the next
    /// connection; an end is applied.
    fn apply_offline(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Watch { node, session } => {
                // Said once in the Session: what it shows comes from the session's hooks alone,
                // and what cannot be done from Vox (the decider, 2026-10-06).
                if self.told.insert(session.clone()) {
                    let mut e = Map::new();
                    e.insert("v".into(), json!(VERSION));
                    e.insert("session".into(), json!(session));
                    e.insert("kind".into(), json!("notice"));
                    e.insert("ts".into(), json!(now_ms()));
                    e.insert(
                        "text".into(),
                        json!(
                            "Codex's app-server was not running when this session started, so \
                             Vox reads it from its hooks alone: its tool calls, replies and turn \
                             ends show here, but its approvals and questions can be answered only \
                             at its terminal, and it cannot be driven from Vox. Sessions started \
                             from now on join the app-server Vox keeps running."
                        ),
                    );
                    self.sink.activity(&node, &session, split(e, "text"), None);
                }
                self.watch(node, session);
            }
            Cmd::End { session } => self.end(&session),
            Cmd::Steer { reply, .. } => {
                let _ = reply.send(Err(unreachable(&self.socket, "no connection")));
            }
        }
    }

    fn watch(&mut self, node: NodeName, session: String) {
        self.threads.entry(session).or_insert(Thread {
            node,
            subscribed: false,
            status: String::new(),
            turn: None,
            started: BTreeSet::new(),
            refused: 0,
        });
    }

    fn end(&mut self, session: &str) {
        self.threads.remove(session);
        self.subscribed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(session);
        self.asks.retain(|_, a| a.session != session);
    }

    async fn hello(&mut self, ws: &mut Ws) -> Result<(), ()> {
        let id = self
            .call(
                ws,
                "initialize",
                json!({"clientInfo": {"name": "vox", "version": env!("CARGO_PKG_VERSION")}}),
                Pending::Ignore,
            )
            .await;
        // `initialize` must be answered before anything else is asked.
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(t))) => {
                    let v: Value = serde_json::from_str(t.as_str()).unwrap_or(Value::Null);
                    if v.get("id").and_then(Value::as_u64) == id && v.get("method").is_none() {
                        self.calls.remove(&id.unwrap_or_default());
                        break;
                    }
                }
                Some(Ok(_)) => {}
                _ => return Err(()),
            }
        }
        send(ws, &json!({"jsonrpc": "2.0", "method": "initialized"}))
            .await
            .map_err(|_| ())
    }

    async fn call(&mut self, ws: &mut Ws, method: &str, params: Value, p: Pending) -> Option<u64> {
        let id = self.next_id;
        self.next_id += 1;
        let ok = send(
            ws,
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        )
        .await
        .is_ok();
        if ok {
            self.calls.insert(id, p);
            Some(id)
        } else {
            if let Pending::Steer(reply, _) = p {
                let _ = reply.send(Err(unreachable(&self.socket, "the send failed")));
            }
            None
        }
    }

    async fn resubscribe(&mut self, ws: &mut Ws) {
        let want: Vec<String> = self
            .threads
            .iter()
            .filter(|(_, t)| !t.subscribed)
            .map(|(id, _)| id.clone())
            .collect();
        for id in want {
            self.subscribe(ws, &id).await;
        }
    }

    async fn subscribe(&mut self, ws: &mut Ws, thread: &str) {
        let already = self
            .calls
            .values()
            .any(|p| matches!(p, Pending::Resume(t) if t == thread));
        if already {
            return;
        }
        self.call(
            ws,
            "thread/resume",
            json!({"threadId": thread, "excludeTurns": true}),
            Pending::Resume(thread.to_owned()),
        )
        .await;
    }

    async fn command(&mut self, ws: &mut Ws, cmd: Cmd) {
        match cmd {
            Cmd::Watch { node, session } => {
                self.watch(node, session.clone());
                if !self.threads.get(&session).is_some_and(|t| t.subscribed) {
                    self.subscribe(ws, &session).await;
                }
            }
            Cmd::End { session } => self.end(&session),
            Cmd::Steer {
                session,
                steer,
                reply,
            } => self.steer(ws, &session, steer, reply).await,
        }
    }

    async fn steer(
        &mut self,
        ws: &mut Ws,
        session: &str,
        steer: Steer,
        reply: oneshot::Sender<Result<String, String>>,
    ) {
        let Some(t) = self.threads.get(session) else {
            let _ = reply.send(Err(
                "this Codex session is not open here: it ended, or never registered with this \
                 node"
                    .into(),
            ));
            return;
        };
        if !t.subscribed || matches!(t.status.as_str(), "notLoaded" | "closed") {
            let _ = reply.send(Err(format!(
                "Codex's app-server does not hold this session's thread open ({}); nothing was \
                 sent",
                if t.status.is_empty() {
                    "it has not run a turn yet"
                } else {
                    t.status.as_str()
                }
            )));
            return;
        }
        let turn = t.turn.clone();
        let (method, params, done) = match steer {
            Steer::Text(text) => {
                let input = json!([{"type": "text", "text": text, "text_elements": []}]);
                match turn {
                    Some(turn) => (
                        "turn/steer",
                        json!({"threadId": session, "expectedTurnId": turn, "input": input}),
                        "typed into the turn running now".to_owned(),
                    ),
                    None => (
                        "turn/start",
                        json!({"threadId": session, "input": input}),
                        "typed; it starts the session's next turn".to_owned(),
                    ),
                }
            }
            Steer::Interrupt | Steer::Stop => {
                let Some(turn) = turn else {
                    let _ = reply.send(Err(
                        "nothing to interrupt: the session is not running a turn".into(),
                    ));
                    return;
                };
                (
                    "turn/interrupt",
                    json!({"threadId": session, "turnId": turn}),
                    "the running turn was interrupted".to_owned(),
                )
            }
            Steer::Slash { cmd, args } => match cmd.as_str() {
                "compact" => (
                    "thread/compact/start",
                    json!({"threadId": session}),
                    "/compact started".to_owned(),
                ),
                "rename" if !args.trim().is_empty() => (
                    "thread/name/set",
                    json!({"threadId": session, "name": args.trim()}),
                    format!("renamed to {}", args.trim()),
                ),
                "rename" => {
                    let _ = reply.send(Err("/rename needs a name".into()));
                    return;
                }
                "clear" => {
                    let _ = reply.send(Err(
                        "/clear would start a new Codex thread, and driving never starts a \
                         session; type /clear at its terminal"
                            .into(),
                    ));
                    return;
                }
                other => {
                    let _ = reply.send(Err(format!(
                        "Codex takes no /{other} from outside its terminal; Vox sends /compact \
                         and /rename"
                    )));
                    return;
                }
            },
        };
        self.call(ws, method, params, Pending::Steer(reply, done))
            .await;
    }

    async fn frame(&mut self, ws: &mut Ws, v: Value) {
        let method = v.get("method").and_then(Value::as_str).map(str::to_owned);
        match (method, v.get("id")) {
            // A reply to a call Vox made.
            (None, Some(id)) => {
                let Some(p) = id.as_u64().and_then(|id| self.calls.remove(&id)) else {
                    return;
                };
                let err = v.get("error").map(|e| {
                    e.get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("an error")
                        .to_owned()
                });
                match p {
                    Pending::Resume(thread) => {
                        if err.is_none() {
                            // The thread's name as Codex has it now, set before Vox watched it.
                            if let (Some(t), Some(name)) = (
                                self.threads.get(&thread),
                                v.pointer("/result/thread/name").and_then(Value::as_str),
                            ) {
                                self.sink.renamed(&t.node, &thread, name, true);
                            }
                            if let Some(t) = self.threads.get_mut(&thread) {
                                t.subscribed = true;
                                self.subscribed
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .insert(thread.clone());
                            }
                        }
                        // "no rollout found" before the first turn: retried when the server
                        // next mentions the thread, or now if it went active meanwhile.
                        let retry = err.is_some()
                            && self.threads.get_mut(&thread).is_some_and(|t| {
                                t.refused += 1;
                                t.status == "active" && t.refused <= 3
                            });
                        if retry {
                            self.subscribe(ws, &thread).await;
                        }
                    }
                    Pending::Steer(reply, done) => {
                        let _ = reply.send(match err {
                            None => Ok(done),
                            Some(e) => Err(format!("Codex refused it: {e}")),
                        });
                    }
                    Pending::Ignore => {}
                }
            }
            // A request from Codex: an approval or a question.
            (Some(m), Some(id)) => self.request(&m, id.clone(), v["params"].clone()),
            (Some(m), None) => self.notification(ws, &m, &v["params"]).await,
            (None, None) => {}
        }
    }

    fn thread_of(params: &Value) -> Option<&str> {
        params
            .get("threadId")
            .and_then(Value::as_str)
            .or_else(|| params.pointer("/thread/id").and_then(Value::as_str))
    }

    async fn notification(&mut self, ws: &mut Ws, method: &str, p: &Value) {
        let Some(thread) = Self::thread_of(p).map(str::to_owned) else {
            return;
        };
        let Some(t) = self.threads.get_mut(&thread) else {
            return; // a thread no registered session owns: Codex's own helpers among them
        };
        let node = t.node.clone();
        match method {
            // **A rename is the Session's name at once** (ADR-029 MD-1): `/rename` in Codex, or
            // Vox's own `thread/name/set`, is said here, and nothing else carries it.
            "thread/name/updated" => {
                if let Some(name) = p.get("threadName").and_then(Value::as_str) {
                    self.sink.renamed(&node, &thread, name, true);
                }
            }
            "thread/started" => {
                if let Some(name) = p.pointer("/thread/name").and_then(Value::as_str) {
                    self.sink.renamed(&node, &thread, name, true);
                }
            }
            "thread/status/changed" => {
                t.refused = 0;
                t.status = p
                    .pointer("/status/type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                if t.status == "notLoaded" {
                    unsubscribed(t, &self.subscribed, &thread);
                }
            }
            // Unloaded or closed, the thread's subscription is gone with it: a resume (`codex
            // resume`, under the same id) opens it again, and it is subscribed again when the
            // server next mentions it.
            "thread/closed" => {
                t.status = "closed".into();
                unsubscribed(t, &self.subscribed, &thread);
            }
            "turn/started" => {
                t.turn = p
                    .pointer("/turn/id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                t.status = "active".into();
            }
            "turn/completed" => {
                t.turn = None;
                let e = envelope(&thread, "turn-end", None);
                self.sink.activity(&node, &thread, split(e, ""), None);
            }
            "item/started" => {
                if let Some(e) = tool_start(&thread, &p["item"]) {
                    t.started.insert(item_id(&p["item"]));
                    self.sink.activity(&node, &thread, e, None);
                }
            }
            "item/completed" => self.item_completed(&node, &thread, &p["item"]),
            "serverRequest/resolved" => self.resolved_request(&node, &thread, p),
            _ => {}
        }
        let unsubscribed = self.threads.get(&thread).is_some_and(|t| !t.subscribed);
        if unsubscribed {
            self.subscribe(ws, &thread).await;
        }
    }

    fn item_completed(&mut self, node: &NodeName, thread: &str, item: &Value) {
        let id = item_id(item);
        let kind = item.get("type").and_then(Value::as_str).unwrap_or_default();
        match kind {
            "agentMessage" => {
                let text = item.get("text").and_then(Value::as_str).unwrap_or_default();
                if !text.trim().is_empty() {
                    let mut e = envelope(thread, "reply", None);
                    e.insert("text".into(), json!(text));
                    self.sink.activity(node, thread, split(e, "text"), None);
                }
            }
            // The prompt comes from the hook (see the module's notes); reasoning and plans are
            // not what SC-1 carries.
            "userMessage" | "reasoning" | "plan" | "contextCompaction" => {}
            _ => {
                let Some(t) = self.threads.get_mut(thread) else {
                    return;
                };
                // A completion whose start this connection never saw (it subscribed mid-call):
                // the start is posted first, so the call is not lost.
                if !t.started.remove(&id) {
                    if let Some(e) = tool_start(thread, item) {
                        self.sink.activity(node, thread, e, None);
                    }
                }
                self.sink
                    .activity(node, thread, tool_done(thread, item), None);
                // An approval of this call settles with the call: Codex's item says what took
                // effect.
                if self
                    .asks
                    .get(&id)
                    .is_some_and(|a| a.resolved && a.of == "approval")
                {
                    let outcome = match item.get("status").and_then(Value::as_str) {
                        Some("declined") => "denied",
                        _ => "allowed",
                    };
                    self.asks.remove(&id);
                    self.sink.resolved(node, thread, &id, outcome, None);
                }
            }
        }
    }

    /// Codex asks: post it and hold it for the first answer from a member with drive. The
    /// terminal shows it too and may answer first (DR-3); `serverRequest/resolved` says so.
    fn request(&mut self, method: &str, rpc: Value, params: Value) {
        let Some(thread) = Self::thread_of(&params).map(str::to_owned) else {
            return;
        };
        let Some(node) = self.threads.get(&thread).map(|t| t.node.clone()) else {
            return;
        };
        let of = if method == "item/tool/requestUserInput" {
            "question"
        } else if method.ends_with("requestApproval") {
            "approval"
        } else {
            return; // not one of the requests SC-1 carries; Codex's other clients answer it
        };
        let r = params
            .get("itemId")
            .and_then(Value::as_str)
            .map_or_else(|| format!("rpc-{rpc}"), str::to_owned);
        let entry = if of == "question" {
            question_entry(&thread, &r, &params)
        } else {
            approval_entry(&thread, &r, method, &params)
        };
        let Some(rx) = self.sink.request(&node, &thread, entry) else {
            return;
        };
        self.asks.insert(
            r.clone(),
            Ask {
                session: thread,
                rpc: rpc.clone(),
                of,
                method: method.to_owned(),
                params: params.clone(),
                answered: None,
                resolved: false,
            },
        );
        // The first answer from a member with drive comes back to this connection's loop,
        // which gives it to Codex ([`Conn::answer`]).
        let tx = self.answers.clone();
        tokio::spawn(async move {
            if let Ok(given) = rx.await {
                let _ = tx.send((r, given));
            }
        });
    }

    /// Give Codex a member's answer to request `r`. Whether it took effect is Codex's to say
    /// (`serverRequest/resolved`, then the item), never this send's (DR-4).
    async fn answer(&mut self, ws: &mut Ws, r: &str, given: Given) {
        let Some(a) = self.asks.get_mut(r) else {
            return; // settled meanwhile
        };
        let result = response(&a.method, &a.params, &given);
        let rpc = a.rpc.clone();
        a.answered = Some(given);
        let _ = send(ws, &json!({"jsonrpc": "2.0", "id": rpc, "result": result})).await;
    }

    fn resolved_request(&mut self, node: &NodeName, thread: &str, p: &Value) {
        let rpc = p.get("requestId").cloned().unwrap_or(Value::Null);
        let Some((r, a)) = self.asks.iter_mut().find(|(_, a)| a.rpc == rpc) else {
            return;
        };
        let r = r.clone();
        if a.of == "question" {
            let answers = a.answered.as_ref().and_then(|g| match g {
                Given::Answer(m) => Some(json!(m)),
                Given::Approve { .. } => None,
            });
            self.asks.remove(&r);
            self.sink.resolved(node, thread, &r, "answered", answers);
        } else if a.method == "item/permissions/requestApproval" {
            // No item follows a permissions grant: what Vox answered is all there is to say,
            // and when Vox did not answer, the terminal did.
            let outcome = match &a.answered {
                Some(Given::Approve { allow: false, .. }) => "denied",
                _ => "allowed",
            };
            self.asks.remove(&r);
            self.sink.resolved(node, thread, &r, outcome, None);
        } else {
            a.resolved = true; // its item's completion says allowed or denied
        }
    }
}

/// `t`'s subscription has ended with its thread's load.
fn unsubscribed(t: &mut Thread, subscribed: &Mutex<BTreeSet<String>>, thread: &str) {
    t.subscribed = false;
    t.turn = None;
    subscribed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(thread);
}

async fn send(ws: &mut Ws, v: &Value) -> Result<(), tokio_tungstenite::tungstenite::Error> {
    ws.send(Message::text(v.to_string())).await
}

fn item_id(item: &Value) -> String {
    item.get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn envelope(session: &str, kind: &str, r: Option<&str>) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("v".into(), json!(VERSION));
    m.insert("session".into(), json!(session));
    m.insert("kind".into(), json!(kind));
    m.insert("ts".into(), json!(now_ms()));
    if let Some(r) = r {
        m.insert("ref".into(), json!(r));
    }
    m
}

/// The tool a Codex item is, and its input as text: `None` for an item that is not a tool call.
fn tool_of(item: &Value) -> Option<(String, String)> {
    let kind = item.get("type").and_then(Value::as_str)?;
    Some(match kind {
        "commandExecution" => (
            "command".into(),
            item.get("command")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        ),
        "fileChange" => (
            "edit".into(),
            item.get("changes")
                .and_then(Value::as_array)
                .map(|cs| {
                    cs.iter()
                        .map(|c| {
                            format!(
                                "{} {}\n{}",
                                c.pointer("/kind/type")
                                    .or_else(|| c.get("kind"))
                                    .and_then(Value::as_str)
                                    .unwrap_or("change"),
                                c.get("path").and_then(Value::as_str).unwrap_or_default(),
                                c.get("diff").and_then(Value::as_str).unwrap_or_default()
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default(),
        ),
        "mcpToolCall" => (
            format!(
                "{}.{}",
                item.get("server").and_then(Value::as_str).unwrap_or("mcp"),
                item.get("tool").and_then(Value::as_str).unwrap_or("tool")
            ),
            item.get("arguments")
                .map(|a| serde_json::to_string_pretty(a).unwrap_or_default())
                .unwrap_or_default(),
        ),
        "userMessage" | "agentMessage" | "reasoning" | "plan" | "contextCompaction" => return None,
        other => (
            other.to_owned(),
            serde_json::to_string_pretty(item).unwrap_or_default(),
        ),
    })
}

fn tool_start(session: &str, item: &Value) -> Option<Vec<String>> {
    let (tool, input) = tool_of(item)?;
    let id = item_id(item);
    let mut e = envelope(session, "tool", Some(&id));
    e.insert("tool".into(), json!(tool));
    e.insert("summary".into(), json!(one_line(&input)));
    e.insert("input".into(), json!(input));
    Some(split(e, "input"))
}

fn tool_done(session: &str, item: &Value) -> Vec<String> {
    let (tool, _) = tool_of(item).unwrap_or_default();
    let status = item
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let exit = item.get("exitCode").and_then(Value::as_i64);
    let ok = status == "completed" && exit.is_none_or(|c| c == 0);
    let output = match item.get("type").and_then(Value::as_str) {
        Some("commandExecution") => item
            .get("aggregatedOutput")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        Some("mcpToolCall") => item
            .get("result")
            .or_else(|| item.get("error"))
            .map(|r| serde_json::to_string_pretty(r).unwrap_or_default())
            .unwrap_or_default(),
        _ => String::new(),
    };
    let summary = match (status, exit) {
        ("declined", _) => "declined".to_owned(),
        (_, Some(c)) if output.trim().is_empty() => format!("exit {c}"),
        (_, Some(c)) => format!("exit {c}: {}", one_line(&output)),
        _ if output.trim().is_empty() => status.to_owned(),
        _ => one_line(&output),
    };
    let mut e = envelope(session, "tool-done", Some(&item_id(item)));
    e.insert("tool".into(), json!(tool));
    e.insert("ok".into(), json!(ok));
    e.insert("summary".into(), json!(one_line(&summary)));
    e.insert("output".into(), json!(output));
    split(e, "output")
}

fn approval_entry(session: &str, r: &str, method: &str, p: &Value) -> String {
    let (tool, input) = match method {
        "item/commandExecution/requestApproval" => (
            "command",
            p.get("command")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        ),
        "item/fileChange/requestApproval" => (
            "edit",
            p.get("grantRoot")
                .and_then(Value::as_str)
                .map_or_else(|| "file changes".to_owned(), |g| format!("write under {g}")),
        ),
        _ => (
            "permissions",
            serde_json::to_string_pretty(p.get("permissions").unwrap_or(p)).unwrap_or_default(),
        ),
    };
    let reason = p.get("reason").and_then(Value::as_str).unwrap_or_default();
    let mut e = envelope(session, "approval", Some(r));
    e.insert("tool".into(), json!(tool));
    e.insert(
        "summary".into(),
        json!(one_line(if reason.is_empty() { &input } else { reason })),
    );
    e.insert("input".into(), json!(input));
    // One entry: a request is never split, so its parts cannot be answered apart.
    let mut whole = Value::Object(e).to_string();
    if whole.len() > vox_core::node::content::MAX_TEXT_LEN {
        let Ok(Value::Object(mut m)) = serde_json::from_str::<Value>(&whole) else {
            return whole;
        };
        m.insert(
            "input".into(),
            json!("(too long to show; see the terminal)"),
        );
        whole = Value::Object(m).to_string();
    }
    whole
}

fn question_entry(session: &str, r: &str, p: &Value) -> String {
    let questions: Vec<Value> = p
        .get("questions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|q| {
            json!({
                "id": q.get("id").cloned().unwrap_or(Value::Null),
                "text": q.get("question").cloned().unwrap_or(Value::Null),
                "header": q.get("header").cloned().unwrap_or(Value::Null),
                "options": q.get("options").and_then(Value::as_array).map(|os| os.iter().map(|o| json!({
                    "label": o.get("label").cloned().unwrap_or(Value::Null),
                    "description": o.get("description").cloned().unwrap_or(Value::Null),
                })).collect::<Vec<_>>()).unwrap_or_default(),
                "multi": false,
            })
        })
        .collect();
    let mut e = envelope(session, "question", Some(r));
    e.insert("questions".into(), json!(questions));
    Value::Object(e).to_string()
}

/// Codex's answer to its request `method`, from what a member with drive gave.
fn response(method: &str, params: &Value, given: &Given) -> Value {
    match (method, given) {
        ("item/tool/requestUserInput", Given::Answer(a)) => {
            let answers: Map<String, Value> = a
                .iter()
                .map(|(k, v)| {
                    // Keyed by the question's id; a key that is a question's text is mapped
                    // to its id.
                    let id = params
                        .get("questions")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .find(|q| q.get("question").and_then(Value::as_str) == Some(k.as_str()))
                        .and_then(|q| q.get("id").and_then(Value::as_str))
                        .unwrap_or(k);
                    (id.to_owned(), json!({"answers": [v]}))
                })
                .collect();
            json!({ "answers": answers })
        }
        ("item/permissions/requestApproval", Given::Approve { allow, .. }) => {
            if *allow {
                json!({"permissions": params.get("permissions").cloned().unwrap_or(json!({})), "scope": "turn"})
            } else {
                json!({"permissions": {}, "scope": "turn"})
            }
        }
        (_, Given::Approve { allow: true, .. }) => json!({"decision": "accept"}),
        (_, Given::Approve { allow: false, .. }) => {
            // Reject without ending the turn where Codex offers it; otherwise its cancel.
            let offers_decline = params
                .get("availableDecisions")
                .and_then(Value::as_array)
                .is_none_or(|d| d.iter().any(|x| x == "decline"));
            json!({"decision": if offers_decline { "decline" } else { "cancel" }})
        }
        (_, Given::Answer(_)) => json!({"decision": "cancel"}),
    }
}
