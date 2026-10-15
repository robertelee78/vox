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
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{json, Map, Value};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use vox_core::node::paths::NodeName;

use vox_agentcomms::activity::{one_line, VERSION};
use vox_core::node::content::MAX_TEXT_LEN;

fn split(m: Map<String, Value>, big: &str) -> Vec<String> {
    vox_agentcomms::activity::split(m, big, MAX_TEXT_LEN)
}
use crate::session_sink::{Given, RequestTicket, Sink};

const MAX_CONNECTIONS: usize = 64;
const MAX_THREADS: usize = 64;
const MAX_COMMANDS: usize = 32;
const MAX_COMMAND_BYTES: usize = 64 << 10;
const MAX_MESSAGE_BYTES: usize = 4 << 20;
const MAX_ASKS: usize = 64;
const MAX_ASK_BYTES: usize = 4 << 20;
const MAX_STARTED: usize = 128;
const MAX_ID_BYTES: usize = 4096;
const CALL_WITHIN: Duration = Duration::from_secs(30);

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
    conns: Mutex<BTreeMap<PathBuf, Connection>>,
    /// Includes stopped connections still reporting their final notice.
    live: Arc<Semaphore>,
    /// Sessions a connection is subscribed to now: their hook activity is not posted again.
    subscribed: Arc<Mutex<BTreeSet<String>>>,
}

#[derive(Clone)]
struct Connection {
    tx: mpsc::Sender<Cmd>,
    stop: CancellationToken,
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
        guard: Option<crate::host::room_pause::InterruptGuard>,
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
            live: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            subscribed: Arc::default(),
        })
    }

    fn conn(&self, codex_home: &Path) -> Result<Connection, String> {
        let socket = control_socket(codex_home);
        if socket.as_os_str().len() > MAX_ID_BYTES {
            return Err("Codex socket path exceeds 4 KiB; observation was not started".into());
        }
        let mut conns = self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        conns.retain(|_, conn| !conn.tx.is_closed());
        if let Some(conn) = conns.get(&socket) {
            if conn.stop.is_cancelled() {
                return Err("Codex observation is stopping; nothing was queued".into());
            }
            return Ok(conn.clone());
        }
        if conns.len() >= MAX_CONNECTIONS {
            return Err(
                "Vox already observes 64 Codex app-servers; observation was not started".into(),
            );
        }
        let permit = Arc::clone(&self.live).try_acquire_owned().map_err(|_| {
            "Vox already has 64 active Codex observers; observation was not started".to_owned()
        })?;
        let (tx, rx) = mpsc::channel(MAX_COMMANDS);
        let control = Connection {
            tx,
            stop: CancellationToken::new(),
        };
        conns.insert(socket.clone(), control.clone());
        let conn = Conn {
            _permit: permit,
            socket,
            sink: Arc::clone(&self.sink),
            subscribed: Arc::clone(&self.subscribed),
            threads: BTreeMap::new(),
            next_id: 1,
            calls: BTreeMap::new(),
            asks: BTreeMap::new(),
            failed: None,
        };
        tokio::spawn(conn.run(rx, control.stop.clone()));
        Ok(control)
    }

    /// A Codex session of `node` registered from `codex_home` (ADR-020 6.10): watch its thread.
    pub fn watch(&self, codex_home: &Path, node: &NodeName, session: &str) {
        if session.is_empty() || session.len() > MAX_ID_BYTES {
            eprintln!(
                "vox daemon: {node}: Codex observation refused: invalid or oversized session ID"
            );
            return;
        }
        let conn = match self.conn(codex_home) {
            Ok(conn) => conn,
            Err(why) => {
                eprintln!("vox daemon: {node}: Codex Session {session}: {why}");
                return;
            }
        };
        if conn
            .tx
            .try_send(Cmd::Watch {
                node: node.clone(),
                session: session.to_owned(),
            })
            .is_err()
        {
            eprintln!("vox daemon: {node}: Codex Session {session}: observation stopped because its command queue is full or closed; hooks remain available");
            conn.stop.cancel();
        }
    }

    /// The session ended (its `SessionEnd`): stop watching and driving it.
    pub fn end(&self, session: &str) {
        // An ID outside this bound could never enter a watched thread or command queue.
        if session.len() > MAX_ID_BYTES {
            return;
        }
        let conns = self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for conn in conns.values() {
            if conn
                .tx
                .try_send(Cmd::End {
                    session: session.to_owned(),
                })
                .is_err()
            {
                conn.stop.cancel();
            }
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
        self.steer_guarded(codex_home, session, steer, None).await
    }

    pub(crate) async fn steer_guarded(
        &self,
        codex_home: &Path,
        session: &str,
        steer: Steer,
        guard: Option<crate::host::room_pause::InterruptGuard>,
    ) -> Result<String, String> {
        let bytes = match &steer {
            Steer::Text(text) => text.len(),
            Steer::Slash { cmd, args } => cmd.len().saturating_add(args.len()),
            Steer::Interrupt | Steer::Stop => 0,
        };
        if session.len() > MAX_ID_BYTES || bytes > MAX_COMMAND_BYTES {
            return Err("Codex control exceeds its byte bound; nothing was sent".into());
        }
        let (reply, rx) = oneshot::channel();
        self.conn(codex_home)?
            .tx
            .try_send(Cmd::Steer {
                session: session.to_owned(),
                steer,
                guard,
                reply,
            })
            .map_err(|_| "Codex's control queue is full or closed; nothing was sent".to_owned())?;
        rx.await
            .unwrap_or_else(|_| Err("Codex's connection stopped; the control outcome is unknown, do not assume it is safe to repeat".to_owned()))
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
    /// At most 128 unmatched starts, each ID at most 4 KiB. Preserve across reconnect and
    /// unload so a late completion does not synthesize a second start; End retires the set.
    started: BTreeSet<String>,
    /// The offline notice is scoped to this live thread and retires with it.
    told: bool,
    /// Subscriptions refused since the thread last changed status. A refusal that crossed the
    /// status change to active (the moment its rollout appears) is retried, at most a few times.
    refused: u8,
}

/// An approval or a question Codex asked, held until it settles.
struct Ask {
    node: NodeName,
    session: String,
    ticket: RequestTicket,
    /// The JSON-RPC id Codex is waiting on.
    rpc: Value,
    of: &'static str,
    method: String,
    params: Value,
    /// What Vox answered, if it did, so a refusal shows as such.
    answered: Option<Given>,
    /// `serverRequest/resolved` arrived; for an approval the outcome waits for its item.
    resolved: bool,
    receiver: Option<oneshot::Receiver<Given>>,
    /// Serialized metadata and bounded answer bytes retained for this request.
    bytes: usize,
}

/// What a JSON-RPC call Vox made is waiting for.
enum Pending {
    Resume(String),
    Steer(oneshot::Sender<Result<String, String>>, String, String),
    Ignore,
}

struct Conn {
    _permit: OwnedSemaphorePermit,
    socket: PathBuf,
    sink: Arc<Sink>,
    subscribed: Arc<Mutex<BTreeSet<String>>>,
    threads: BTreeMap<String, Thread>,
    next_id: u64,
    calls: BTreeMap<u64, (tokio::time::Instant, Pending)>,
    /// By the ref the Session shows: the item id Codex's request names.
    asks: BTreeMap<String, Ask>,
    /// A capacity or uncertain-write failure stops observation explicitly.
    failed: Option<String>,
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
        let connect = async {
            let stream = tokio::net::UnixStream::connect(&self.socket)
                .await
                .map_err(|e| unreachable(&self.socket, e))?;
            let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                .read_buffer_size(8 * 1024)
                .write_buffer_size(0)
                .max_write_buffer_size(2 * MAX_COMMAND_BYTES)
                .max_message_size(Some(MAX_MESSAGE_BYTES))
                .max_frame_size(Some(MAX_MESSAGE_BYTES));
            tokio_tungstenite::client_async_with_config("ws://localhost/", stream, Some(config))
                .await
                .map(|(ws, _)| ws)
                .map_err(|e| unreachable(&self.socket, e))
        };
        tokio::time::timeout(CALL_WITHIN, connect)
            .await
            .map_err(|_| unreachable(&self.socket, "connection timed out"))?
    }

    /// Each connection retains only bounded active work. A stopped observation reports the
    /// gap and leaves already admitted Session activity intact; queued controls are not sent.
    async fn run(mut self, mut rx: mpsc::Receiver<Cmd>, stop: CancellationToken) {
        let mut ws: Option<Ws> = None;
        let mut timer = tokio::time::interval(Duration::from_millis(250));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if self.failed.is_some() || stop.is_cancelled() {
                break;
            }
            let Some(ws_now) = ws.as_mut() else {
                let cmd = tokio::select! {
                    () = stop.cancelled() => break,
                    cmd = rx.recv() => match cmd { Some(cmd) => cmd, None => break },
                };
                // End always retires immediately, even while the app-server is offline.
                if let Cmd::End { session } = cmd {
                    self.end(&session).await;
                    if self.threads.is_empty() {
                        break;
                    }
                    continue;
                }
                match self.connect().await {
                    Ok(mut w) => {
                        if matches!(
                            tokio::time::timeout(CALL_WITHIN, self.hello(&mut w)).await,
                            Ok(Ok(()))
                        ) {
                            ws = Some(w);
                        } else {
                            self.gone().await;
                        }
                    }
                    Err(why) => {
                        if let Cmd::Steer { reply, .. } = cmd {
                            let _ = reply.send(Err(format!("{why}; the control was not sent")));
                            continue;
                        }
                    }
                }
                let Some(w) = ws.as_mut() else {
                    self.apply_offline(cmd).await;
                    continue;
                };
                self.command(w, cmd).await;
                self.resubscribe(w).await;
                continue;
            };
            tokio::select! {
                () = stop.cancelled() => break,
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    self.command(ws_now, cmd).await;
                    if self.threads.is_empty() { break; }
                }
                _ = timer.tick(), if !self.calls.is_empty() || !self.asks.is_empty() => {
                    if self.calls.values().any(|(expires, _)| *expires <= tokio::time::Instant::now()) {
                        self.failed = Some("Codex did not answer within 30 seconds; pending control outcomes are unknown, do not assume it is safe to repeat".into());
                    } else if let Some((id, given)) = self.take_answer() {
                        self.answer(ws_now, &id, given).await;
                    }
                }
                frame = ws_now.next() => {
                    match frame {
                        Some(Ok(Message::Text(text))) => {
                            match serde_json::from_str::<Value>(text.as_str()) {
                                Ok(value) => self.frame(ws_now, value).await,
                                Err(_) => self.failed = Some("Codex supplied malformed event JSON".into()),
                            }
                            self.resubscribe(ws_now).await;
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            ws = None;
                            self.gone().await;
                            self.notice_all("Codex disconnected; pending request/control outcomes are unknown; hooks remain available").await;
                        }
                        Some(Err(error)) => {
                            self.failed = Some(format!("Codex event transport failed: {error}; pending outcomes are unknown"));
                        }
                        Some(Ok(_)) => {}
                    }
                }
            }
        }
        rx.close();
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                Cmd::Steer { reply, .. } => {
                    let _ = reply.send(Err(
                        "Codex observation stopped before this queued control was sent".into(),
                    ));
                }
                Cmd::Watch { node, session } => {
                    eprintln!("vox daemon: {node}: Codex Session {session}: observation stopped before this subscription was admitted; hooks remain available");
                }
                Cmd::End { .. } => {}
            }
        }
        self.gone().await;
        let why = self.failed.take().unwrap_or_else(|| {
            "the observation command queue closed or could not accept lifecycle work".into()
        });
        self.notice_all(&format!("Codex observation stopped: {why}"))
            .await;
    }

    /// Pending controls have unknown outcomes after disconnect. Drop exact ask waiters so a
    /// later drive cannot claim delivery through them; bounded unmatched starts survive reconnect.
    fn disconnected(&mut self) {
        for (_, (_, pending)) in std::mem::take(&mut self.calls) {
            if let Pending::Steer(reply, _, _) = pending {
                let _ = reply.send(Err("Codex disconnected; the control outcome is unknown, do not assume it is safe to repeat".into()));
            }
        }
        for t in self.threads.values_mut() {
            t.subscribed = false;
            t.turn = None;
            t.refused = 0;
        }
        let mut subscribed = self
            .subscribed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in self.threads.keys() {
            subscribed.remove(id);
        }
    }

    async fn gone(&mut self) {
        self.disconnected();
        self.retire_asks(
            None,
            "Codex disconnected before the request outcome was observed",
        )
        .await;
    }

    async fn retire_asks(&mut self, session: Option<&str>, why: &str) {
        // At most MAX_ASKS exact tickets; cleanup retains this observer's live permit.
        let ids: Vec<_> = self
            .asks
            .iter()
            .filter(|(_, ask)| session.is_none_or(|id| ask.session == id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            let Some(ask) = self.asks.remove(&id) else {
                continue;
            };
            self.sink
                .retire_observation(&ask.node, &ask.session, &id, &ask.ticket, why)
                .await;
        }
    }

    async fn notice_all(&self, why: &str) {
        eprintln!("vox daemon: {why}");
        for (session, thread) in &self.threads {
            let mut entry = envelope(session, "notice", None);
            entry.insert("text".into(), json!(why));
            self.sink
                .activity(&thread.node, session, split(entry, "text"), None)
                .await;
        }
    }

    fn take_answer(&mut self) -> Option<(String, Given)> {
        let mut answer = None;
        self.asks.retain(|id, ask| {
            if answer.is_some() {
                return true;
            }
            let Some(receiver) = ask.receiver.as_mut() else {
                return true;
            };
            match receiver.try_recv() {
                Ok(given) => {
                    ask.receiver = None;
                    answer = Some((id.clone(), given));
                    true
                }
                Err(oneshot::error::TryRecvError::Empty) => true,
                Err(oneshot::error::TryRecvError::Closed) => false,
            }
        });
        answer
    }

    async fn post(&mut self, node: &NodeName, session: &str, bodies: Vec<String>) -> bool {
        use vox_core::node::daemonipc::SessionAdmission;
        match self.sink.activity(node, session, bodies, None).await {
            SessionAdmission::Refused(why) | SessionAdmission::Unconfirmed(why) => {
                self.failed = Some(format!("Session activity admission failed: {why}; already admitted activity is retained"));
                false
            }
            _ => true,
        }
    }

    /// A command while the app-server cannot be reached: watching is remembered for the next
    /// connection; an end is applied.
    async fn apply_offline(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Watch { node, session } => {
                // Said once in the Session: what it shows comes from the session's hooks alone,
                // and what cannot be done from Vox (the decider, 2026-10-06).
                if !self.watch(node.clone(), session.clone()) {
                    return;
                }
                let tell = self.threads.get_mut(&session).is_some_and(|thread| {
                    let tell = !thread.told;
                    thread.told = true;
                    tell
                });
                if tell {
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
                    self.sink
                        .activity(&node, &session, split(e, "text"), None)
                        .await;
                }
            }
            Cmd::End { session } => self.end(&session).await,
            Cmd::Steer { reply, .. } => {
                let _ = reply.send(Err(unreachable(&self.socket, "no connection")));
            }
        }
    }

    fn watch(&mut self, node: NodeName, session: String) -> bool {
        if self
            .threads
            .get(&session)
            .is_some_and(|thread| thread.node != node)
        {
            self.failed = Some("Codex reused a live session ID for a different node".into());
            return false;
        }
        if !self.threads.contains_key(&session) && self.threads.len() >= MAX_THREADS {
            self.failed =
                Some("Codex has 64 watched threads; observation cannot admit another".into());
            return false;
        }
        self.threads.entry(session).or_insert(Thread {
            node,
            subscribed: false,
            status: String::new(),
            turn: None,
            started: BTreeSet::new(),
            told: false,
            refused: 0,
        });
        true
    }

    async fn end(&mut self, session: &str) {
        self.retire_asks(
            Some(session),
            "the Session ended before Codex's request outcome was observed",
        )
        .await;
        self.threads.remove(session);
        self.subscribed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(session);
        let calls: Vec<_> = self
            .calls
            .iter()
            .filter_map(|(id, (_, pending))| match pending {
                Pending::Resume(thread) | Pending::Steer(_, _, thread) if thread == session => {
                    Some(*id)
                }
                _ => None,
            })
            .collect();
        for id in calls {
            if let Some((_, Pending::Steer(reply, _, _))) = self.calls.remove(&id) {
                let _ = reply.send(Err(
                    "the Session ended while Codex's control outcome was unknown".into(),
                ));
            }
        }
    }

    async fn hello(&mut self, ws: &mut Ws) -> Result<(), ()> {
        let id = self
            .call(
                ws,
                "initialize",
                json!({"clientInfo": {"name": "vox", "version": env!("CARGO_PKG_VERSION")}}),
                Pending::Ignore,
            )
            .await
            .ok_or(())?;
        // `initialize` must be answered before anything else is asked.
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(t))) => {
                    let v: Value = serde_json::from_str(t.as_str()).unwrap_or(Value::Null);
                    if v.get("id").and_then(Value::as_u64) == Some(id) && v.get("method").is_none()
                    {
                        self.calls.remove(&id);
                        if v.get("error").is_some() {
                            return Err(());
                        }
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
        self.call_guarded(ws, method, params, p, None).await
    }

    async fn call_guarded(
        &mut self,
        ws: &mut Ws,
        method: &str,
        params: Value,
        p: Pending,
        guard: Option<crate::host::room_pause::InterruptGuard>,
    ) -> Option<u64> {
        if guard.as_ref().is_some_and(|guard| !guard.allowed()) {
            if let Pending::Steer(reply, _, _) = p {
                let _ = reply.send(Err(
                    "room pause, authority or Session changed; the interrupt was not sent".into(),
                ));
            }
            return None;
        }
        let id = self.next_id;
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let why = if self.calls.len() >= MAX_COMMANDS {
            Some("Codex has 32 unanswered controls; nothing was sent")
        } else if id == u64::MAX {
            Some("Codex control sequence exhausted; nothing was sent")
        } else if body.to_string().len() > MAX_COMMAND_BYTES {
            Some("encoded Codex control exceeds 64 KiB; nothing was sent")
        } else {
            None
        };
        if let Some(why) = why {
            if let Pending::Steer(reply, _, _) = p {
                let _ = reply.send(Err(why.into()));
            } else {
                self.failed = Some(why.into());
            }
            return None;
        }
        self.next_id += 1;
        let sent = if let Some(guard) = guard {
            tokio::select! {
                biased;
                () = guard.cancelled() => Err("room pause changed during the control write; its outcome is unknown".into()),
                sent = send(ws, &body) => sent,
            }
        } else {
            send(ws, &body).await
        };
        match sent {
            Ok(()) => {
                self.calls
                    .insert(id, (tokio::time::Instant::now() + CALL_WITHIN, p));
                Some(id)
            }
            Err(why) => {
                if let Pending::Steer(reply, _, _) = p {
                    let _ = reply.send(Err(why.clone()));
                }
                self.failed = Some(why);
                None
            }
        }
    }

    async fn resubscribe(&mut self, ws: &mut Ws) {
        let want: Vec<String> = self
            .threads
            .iter()
            .filter(|(_, t)| !t.subscribed && t.refused == 0)
            .map(|(id, _)| id.clone())
            .collect();
        for id in want {
            if self.calls.len() >= MAX_COMMANDS || self.failed.is_some() {
                break;
            }
            self.subscribe(ws, &id).await;
        }
    }

    async fn subscribe(&mut self, ws: &mut Ws, thread: &str) {
        let already = self
            .calls
            .values()
            .any(|(_, p)| matches!(p, Pending::Resume(t) if t == thread));
        if already || self.calls.len() >= MAX_COMMANDS || self.failed.is_some() {
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
                if !self.watch(node, session.clone()) {
                    return;
                }
                if !self.threads.get(&session).is_some_and(|t| t.subscribed) {
                    self.subscribe(ws, &session).await;
                }
            }
            Cmd::End { session } => self.end(&session).await,
            Cmd::Steer {
                session,
                steer,
                guard,
                reply,
            } => self.steer(ws, &session, steer, guard, reply).await,
        }
    }

    async fn steer(
        &mut self,
        ws: &mut Ws,
        session: &str,
        steer: Steer,
        guard: Option<crate::host::room_pause::InterruptGuard>,
        reply: oneshot::Sender<Result<String, String>>,
    ) {
        if guard.as_ref().is_some_and(|guard| !guard.allowed()) {
            let _ = reply.send(Err(
                "room pause, authority or Session changed; the interrupt was not sent".into(),
            ));
            return;
        }
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
        self.call_guarded(
            ws,
            method,
            params,
            Pending::Steer(reply, done, session.to_owned()),
            guard,
        )
        .await;
    }

    async fn frame(&mut self, ws: &mut Ws, v: Value) {
        let method = v.get("method").and_then(Value::as_str).map(str::to_owned);
        match (method, v.get("id")) {
            // A reply to a call Vox made.
            (None, Some(id)) => {
                let Some((_, p)) = id.as_u64().and_then(|id| self.calls.remove(&id)) else {
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
                                self.sink.renamed(&t.node, &thread, name);
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
                                t.refused = t.refused.saturating_add(1);
                                t.status == "active" && t.refused <= 3
                            });
                        if retry {
                            self.subscribe(ws, &thread).await;
                        }
                    }
                    Pending::Steer(reply, done, _) => {
                        let _ = reply.send(match err {
                            None => Ok(done),
                            Some(e) => Err(format!("Codex refused it: {e}")),
                        });
                    }
                    Pending::Ignore => {}
                }
            }
            // A request from Codex: an approval or a question.
            (Some(m), Some(id)) => self.request(&m, id.clone(), v["params"].clone()).await,
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
                    self.sink.renamed(&node, &thread, name);
                }
            }
            "thread/started" => {
                if let Some(name) = p.pointer("/thread/name").and_then(Value::as_str) {
                    self.sink.renamed(&node, &thread, name);
                }
            }
            "thread/status/changed" => {
                t.refused = 0;
                t.status = p
                    .pointer("/status/type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                if t.status.len() > MAX_ID_BYTES {
                    self.failed = Some("Codex supplied an oversized thread status".into());
                    return;
                }
                if t.status == "notLoaded" {
                    unsubscribed(t, &self.subscribed, &thread);
                    self.retire_asks(
                        Some(&thread),
                        "Codex unloaded the thread before its request outcome was observed",
                    )
                    .await;
                }
            }
            // Unloaded or closed, the thread's subscription is gone with it: a resume (`codex
            // resume`, under the same id) opens it again, and it is subscribed again when the
            // server next mentions it.
            "thread/closed" => {
                t.status = "closed".into();
                unsubscribed(t, &self.subscribed, &thread);
                self.retire_asks(
                    Some(&thread),
                    "Codex unloaded the thread before its request outcome was observed",
                )
                .await;
            }
            "turn/started" => {
                t.turn = p
                    .pointer("/turn/id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if t.turn.as_ref().is_some_and(|id| id.len() > MAX_ID_BYTES) {
                    self.failed = Some("Codex supplied an oversized turn ID".into());
                    return;
                }
                t.status = "active".into();
            }
            "turn/completed" => {
                t.turn = None;
                let e = envelope(&thread, "turn-end", None);
                self.post(&node, &thread, split(e, "")).await;
            }
            "item/started" => {
                if let Some(e) = tool_start(&thread, &p["item"]) {
                    let id = item_id(&p["item"]);
                    if id.is_empty() || id.len() > MAX_ID_BYTES {
                        self.failed =
                            Some("Codex supplied an invalid or oversized tool item ID".into());
                        return;
                    }
                    if t.started.contains(&id) {
                        return;
                    }
                    if t.started.len() >= MAX_STARTED {
                        self.failed = Some("Codex has 128 unmatched tool starts; observation stopped before another start was admitted".into());
                        return;
                    }
                    t.started.insert(id);
                    self.post(&node, &thread, e).await;
                }
            }
            "item/completed" => self.item_completed(&node, &thread, &p["item"]).await,
            "serverRequest/resolved" => self.resolved_request(&node, &thread, p).await,
            _ => {}
        }
        let unsubscribed = self.threads.get(&thread).is_some_and(|t| !t.subscribed);
        if unsubscribed {
            self.subscribe(ws, &thread).await;
        }
    }

    async fn item_completed(&mut self, node: &NodeName, thread: &str, item: &Value) {
        let id = item_id(item);
        if id.is_empty() || id.len() > MAX_ID_BYTES {
            self.failed = Some("Codex supplied an invalid or oversized completed item ID".into());
            return;
        }
        let kind = item.get("type").and_then(Value::as_str).unwrap_or_default();
        match kind {
            "agentMessage" => {
                let text = item.get("text").and_then(Value::as_str).unwrap_or_default();
                if !text.trim().is_empty() {
                    let mut e = envelope(thread, "reply", None);
                    e.insert("text".into(), json!(text));
                    self.post(node, thread, split(e, "text")).await;
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
                        if !self.post(node, thread, e).await {
                            return;
                        }
                    }
                }
                if !self.post(node, thread, tool_done(thread, item)).await {
                    return;
                }
                // An approval of this call settles with the call: Codex's item says what took
                // effect.
                if self
                    .asks
                    .get(&id)
                    .is_some_and(|a| a.session == thread && a.resolved && a.of == "approval")
                {
                    let outcome = match item.get("status").and_then(Value::as_str) {
                        Some("declined") => "denied",
                        _ => "allowed",
                    };
                    self.asks.remove(&id);
                    self.sink.resolved(node, thread, &id, outcome, None).await;
                }
            }
        }
    }

    /// Codex asks: post it and hold it for the first answer from a member with drive. The
    /// terminal shows it too and may answer first (DR-3); `serverRequest/resolved` says so.
    async fn request(&mut self, method: &str, rpc: Value, params: Value) {
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
        // Never replace an active receiver with another request sharing only its item ID.
        if let Some(old) = self.asks.get(&r) {
            if old.session != thread
                || old.rpc != rpc
                || old.method != method
                || old.params != params
            {
                self.failed =
                    Some("Codex reused an active request identity with different contents".into());
            }
            return;
        }
        let bytes = r
            .len()
            .saturating_add(thread.len())
            .saturating_add(method.len())
            .saturating_add(rpc.to_string().len())
            .saturating_add(params.to_string().len());
        let retained: usize = self.asks.values().map(|ask| ask.bytes).sum();
        if r.is_empty()
            || r.len() > MAX_ID_BYTES
            || self.asks.len() >= MAX_ASKS
            || bytes > MAX_ASK_BYTES.saturating_sub(retained)
        {
            self.failed = Some("Codex pending requests exceed 64 requests or 4 MiB; the new request was not admitted".into());
            return;
        }
        let entry = if of == "question" {
            question_entry(&thread, &r, &params)
        } else {
            approval_entry(&thread, &r, method, &params)
        };
        let Some((receiver, ticket)) = self.sink.request_observed(&node, &thread, entry).await
        else {
            self.failed = Some("Codex request could not be admitted to the Session".into());
            return;
        };
        self.asks.insert(
            r,
            Ask {
                node,
                session: thread,
                ticket,
                rpc,
                of,
                method: method.to_owned(),
                params,
                answered: None,
                resolved: false,
                receiver: Some(receiver),
                bytes,
            },
        );
    }

    /// A written answer is still waiting for Codex's resolution; a failed write is uncertain.
    async fn answer(&mut self, ws: &mut Ws, r: &str, given: Given) {
        let bytes = given_bytes(&given);
        let retained: usize = self.asks.values().map(|ask| ask.bytes).sum();
        if bytes > MAX_COMMAND_BYTES || bytes > MAX_ASK_BYTES.saturating_sub(retained) {
            self.failed = Some("Codex answer exceeds its byte bound; it was not sent".into());
            return;
        }
        let Some(ask) = self.asks.get_mut(r) else {
            return;
        };
        let result = response(&ask.method, &ask.params, &given);
        let body = json!({"jsonrpc": "2.0", "id": ask.rpc, "result": result});
        if body.to_string().len() > MAX_COMMAND_BYTES {
            self.failed = Some("encoded Codex answer exceeds 64 KiB; it was not sent".into());
            return;
        }
        ask.bytes += bytes;
        ask.answered = Some(given);
        if let Err(why) = send(ws, &body).await {
            self.failed = Some(why);
        }
    }

    async fn resolved_request(&mut self, node: &NodeName, thread: &str, p: &Value) {
        let rpc = p.get("requestId").cloned().unwrap_or(Value::Null);
        let Some((r, a)) = self
            .asks
            .iter_mut()
            .find(|(_, a)| a.session == thread && a.rpc == rpc)
        else {
            return;
        };
        let r = r.clone();
        if a.of == "question" {
            let answers = a.answered.as_ref().and_then(|g| match g {
                Given::Answer(m) => Some(json!(m)),
                Given::Approve { .. } => None,
            });
            self.asks.remove(&r);
            self.sink
                .resolved(node, thread, &r, "answered", answers)
                .await;
        } else if a.method == "item/permissions/requestApproval" {
            // No item follows a permissions grant: what Vox answered is all there is to say,
            // and when Vox did not answer, the terminal did.
            let outcome = match &a.answered {
                Some(Given::Approve { allow: false, .. }) => "denied",
                _ => "allowed",
            };
            self.asks.remove(&r);
            self.sink.resolved(node, thread, &r, outcome, None).await;
        } else {
            a.resolved = true; // its item's completion says allowed or denied
        }
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.disconnected();
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

async fn send(ws: &mut Ws, value: &Value) -> Result<(), String> {
    let text = value.to_string();
    if text.len() > MAX_COMMAND_BYTES {
        return Err("encoded Codex control exceeds 64 KiB; nothing was sent".into());
    }
    match tokio::time::timeout(CALL_WITHIN, ws.send(Message::text(text))).await {
        Ok(Ok(())) => Ok(()),
        _ => Err("Codex control write failed or timed out; its outcome is unknown, do not assume it is safe to repeat".into()),
    }
}

fn given_bytes(given: &Given) -> usize {
    match given {
        Given::Approve { why, .. } => why.as_ref().map_or(0, String::len),
        Given::Answer(answers) => answers.iter().fold(0usize, |n, (q, a)| {
            n.saturating_add(q.len()).saturating_add(a.len())
        }),
    }
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
