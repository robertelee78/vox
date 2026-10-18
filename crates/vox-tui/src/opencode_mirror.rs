//! ADR-029 §2–§3 — **an OpenCode session's activity, read through Vox's OpenCode plugin** (#542),
//! and the way a member with drive steers it (#544).
//!
//! The plugin (`assets/opencode-plugin.js`) owns a private directory per OpenCode, holding its
//! wake socket (ADR-020 6.13) and, beside it, its mirror socket, both behind one token, which
//! its session registers on every turn. The daemon connects to the mirror socket, authenticates,
//! and subscribes to the session: the plugin then writes every event of OpenCode's bus that
//! belongs to the session or to a sub-agent's session under it, and runs the daemon's calls on
//! that session alone. What the events mean is decided here, so the plugin stays a pipe.
//!
//! **What reaches the Session** (SC-1), in the format every harness shares
//! ([`crate::session_mirror`]):
//!
//! - the operator's prompt (`user`): a user message's text part, without the room block the
//!   drain put in front of it; a wake notice Vox relayed is Vox's, not the operator's, and is
//!   not shown;
//! - each tool call (`tool`, `tool-done`, `ref` its `callID`): a tool part once it runs, and
//!   once it completes or fails; a completion seen alone posts its start first;
//! - each reply (`reply`): an assistant message's text, posted before the next tool call and at
//!   the turn's end, so replies and calls keep their order;
//! - each turn's end (`turn-end`): `session.idle` (or `session.status` at rest);
//! - each approval (`permission.asked`), held for the first answer
//!   ([`Sink::request`]) and retired by OpenCode's own `permission.replied` (DR-4). OpenCode
//!   2.x asks no questions: its forms reach only the client, and a reply is a client action.
//!
//! A sub-agent's entries carry `agent_id` and its authoritative name when available;
//! otherwise its exact session id is also the displayed label.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::sync::{mpsc, oneshot, Notify, Semaphore};
use vox_core::node::paths::NodeName;

use crate::codex_mirror::Steer;
use vox_agentcomms::activity::{one_line, VERSION};
use vox_core::node::content::MAX_TEXT_LEN;

fn split(m: Map<String, Value>, big: &str) -> Vec<String> {
    vox_agentcomms::activity::split(m, big, MAX_TEXT_LEN)
}
use crate::session_sink::{Given, Sink};

/// A larger event stops observation explicitly; accepted activity is never quietly truncated.
const MAX_LINE: usize = 4 << 20;
const MAX_FOLLOWS: usize = 64;
const MAX_TEXT_PARTS: usize = 128;
const MAX_TEXT_BYTES: usize = 8 << 20;
const MAX_ASKS: usize = 64;
const MAX_ASK_BYTES: usize = 4 << 20;
const MAX_COMMANDS: usize = 32;
const MAX_COMMAND_BYTES: usize = 64 << 10;
const CALL_WITHIN: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct Connection {
    commands: mpsc::Sender<Cmd>,
    stop: Arc<Notify>,
}

/// The daemon's OpenCode followers, one connection per session.
pub struct OpenCodeMirror {
    sink: Arc<Sink>,
    conns: Mutex<BTreeMap<String, Connection>>,
    live: Arc<Semaphore>,
}

enum Cmd {
    Steer {
        steer: Steer,
        guard: Option<crate::host::room_pause::InterruptGuard>,
        reply: oneshot::Sender<Result<String, String>>,
    },
}

impl OpenCodeMirror {
    /// Followers posting through `sink`.
    #[must_use]
    pub fn new(sink: Arc<Sink>) -> Arc<Self> {
        Arc::new(Self {
            sink,
            conns: Mutex::new(BTreeMap::new()),
            live: Arc::new(Semaphore::new(MAX_FOLLOWS)),
        })
    }

    fn conns(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Connection>> {
        self.conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// An OpenCode session of `node` registered its plugin's socket: follow it, unless already
    /// followed.
    pub fn watch(self: &Arc<Self>, node: &NodeName, session: &str, endpoint: &str, token: &str) {
        let mut conns = self.conns();
        conns.retain(|_, conn| !conn.commands.is_closed());
        if conns.contains_key(session) {
            return;
        }
        let Ok(permit) = Arc::clone(&self.live).try_acquire_owned() else {
            eprintln!("vox daemon: {node}: OpenCode Session {session} observation refused: {MAX_FOLLOWS} live followers already active");
            return;
        };
        let (tx, rx) = mpsc::channel(MAX_COMMANDS);
        let stop = Arc::new(Notify::new());
        conns.insert(
            session.to_owned(),
            Connection {
                commands: tx.clone(),
                stop: Arc::clone(&stop),
            },
        );
        let follow = Follow {
            node: node.clone(),
            session: session.to_owned(),
            sink: Arc::clone(&self.sink),
            mirror_endpoint: endpoint.to_owned(),
            mirror_token: token.to_owned(),
            agent: None,
            texts: Vec::new(),
            tools: BTreeMap::new(),
            asks: BTreeMap::new(),
            ended: false,
            failed: false,
            title: None,
            next_id: 1,
            calls: BTreeMap::new(),
        };
        let (endpoint, token) = (endpoint.to_owned(), token.to_owned());
        let owner = Arc::downgrade(self);
        let session = session.to_owned();
        tokio::spawn(async move {
            // end() may remove its registration while a durable post/write is finishing.
            // The live-work slot belongs to the task, not that replaceable map entry.
            let _permit = permit;
            follow.run(endpoint, token, rx, stop).await;
            if let Some(owner) = owner.upgrade() {
                let mut conns = owner.conns();
                if conns
                    .get(&session)
                    .is_some_and(|conn| conn.commands.same_channel(&tx))
                {
                    conns.remove(&session);
                }
            }
        });
    }

    /// The session ended: stop following it.
    pub fn end(&self, session: &str) {
        if let Some(conn) = self.conns().remove(session) {
            conn.stop.notify_one();
        }
    }

    /// Steer `session` (#544): what was done, in words, or why it was refused (DR-6).
    ///
    /// # Errors
    /// Why the control was refused, or why its outcome could not be confirmed.
    pub async fn steer(&self, session: &str, steer: Steer) -> Result<String, String> {
        self.steer_guarded(session, steer, None).await
    }

    pub(crate) async fn steer_guarded(
        &self,
        session: &str,
        steer: Steer,
        guard: Option<crate::host::room_pause::InterruptGuard>,
    ) -> Result<String, String> {
        let tx = self.conns().get(session).cloned().ok_or_else(|| {
            "Vox is not connected to this OpenCode session: it ended, or its OpenCode has not run \
             a turn since Vox started"
                .to_owned()
        })?;
        let size = match &steer {
            Steer::Text(text) => text.len(),
            Steer::Slash { cmd, args } => cmd.len().saturating_add(args.len()),
            Steer::Interrupt | Steer::Stop => 0,
        };
        if size > MAX_COMMAND_BYTES {
            return Err(format!(
                "OpenCode control exceeds {MAX_COMMAND_BYTES} bytes; nothing was sent"
            ));
        }
        let (reply, rx) = oneshot::channel();
        tx.commands
            .try_send(Cmd::Steer {
                steer,
                guard,
                reply,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    "OpenCode's control queue is full; nothing was sent".to_owned()
                }
                mpsc::error::TrySendError::Closed(_) => {
                    "Vox's connection to this OpenCode session has closed; nothing was sent"
                        .to_owned()
                }
            })?;
        rx.await.unwrap_or_else(|_| Err("OpenCode's connection closed; the control outcome is unknown, do not assume it is safe to repeat".to_owned()))
    }
}

/// An approval OpenCode asked.
struct Ask {
    of: &'static str,
    answered: Option<Given>,
    /// Exactly this request's first-answer waiter; no detached forwarding task survives it.
    receiver: Option<oneshot::Receiver<Given>>,
}

struct Follow {
    node: NodeName,
    session: String,
    sink: Arc<Sink>,
    mirror_endpoint: String,
    mirror_token: String,
    /// Current authoritative sub-agent label. An unavailable label falls back to exact agent_id.
    agent: Option<(String, String)>,
    /// Live assistant text parts not yet posted: (session, part id, text, agent label).
    texts: Vec<(String, String, String, Option<String>)>,
    asks: BTreeMap<String, Ask>,
    /// Tool names of running calls: (session, assistant message, call) → the tool's name,
    /// remembered from `session.tool.input.started`, which carries what `called` does not.
    tools: BTreeMap<(String, String, String), String>,
    /// Whether the last thing posted was a turn's end: OpenCode reports a session idle more than
    /// once around an abort, and one turn ends once.
    ended: bool,
    /// An explicit producer failure ends this observation rather than guessing missing roles.
    failed: bool,
    /// The session's title as last said: OpenCode 2.x says a rename only in
    /// `session.renamed`, and only a new title renames the Session.
    title: Option<String>,
    next_id: u64,
    calls: BTreeMap<u64, PendingCall>,
}

struct PendingCall {
    reply: oneshot::Sender<Result<String, String>>,
    done: String,
    expires: tokio::time::Instant,
}

fn given_bytes(given: &Given) -> usize {
    match given {
        Given::Approve { why, .. } => why.as_ref().map_or(0, String::len),
        Given::Answer(answers) => answers.iter().fold(0usize, |n, (q, a)| {
            n.saturating_add(q.len()).saturating_add(a.len())
        }),
    }
}

fn ask_bytes(id: &str, ask: &Ask) -> usize {
    id.len()
        .saturating_add(ask.answered.as_ref().map_or(0, given_bytes))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Text the operator typed, without the blocks the drain put in front of it (Vox's notice, the
/// room's fence). `None` for a wake notice Vox relayed: it is Vox's, not the operator's. A
/// notice arrives as the inbox item's own text ("Vox-generated attention notice; not the
/// operator's message:"), which the TUI receiver wrote, so it is recognized by its own words.
fn typed(text: &str) -> Option<&str> {
    if text.starts_with("Vox-generated attention notice; not the operator's message:") {
        return None;
    }
    if !text.starts_with("<vox-room-") && !text.starts_with("<vox-notice-") {
        return Some(text);
    }
    for (label, mine) in [
        ("\nThe user's message:\n", true),
        ("\nRelayed by Vox; not the user's message:\n", false),
    ] {
        if let Some(i) = text.find(label) {
            return mine.then(|| &text[i + label.len()..]);
        }
    }
    Some(text)
}

impl Follow {
    async fn run(
        mut self,
        endpoint: String,
        token: String,
        mut rx: mpsc::Receiver<Cmd>,
        stop: Arc<Notify>,
    ) {
        let stream =
            match tokio::time::timeout(CALL_WITHIN, tokio::net::UnixStream::connect(&endpoint))
                .await
            {
                Ok(Ok(stream)) => stream,
                _ => {
                    self.fail("the plugin connection could not be opened").await;
                    return;
                }
            };
        let (read, mut write) = stream.into_split();
        let hello = format!(
            "{}\n{}\n",
            json!({"type": "auth", "token": token}),
            json!({"type": "subscribe", "session": self.session})
        );
        if !Self::write(&mut write, &hello).await {
            self.fail("the plugin handshake failed").await;
            return;
        }
        let mut lines = BufReader::new(read);
        let mut line = Vec::new();
        let mut timer = tokio::time::interval(Duration::from_millis(250));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if line.len() > MAX_LINE {
                self.fail("an OpenCode event exceeds the 4 MiB line bound")
                    .await;
                break;
            }
            let remaining = (MAX_LINE + 1 - line.len()) as u64;
            tokio::select! {
                _ = stop.notified() => break,
                cmd = rx.recv() => match cmd {
                    None => break,
                    Some(Cmd::Steer { steer, guard, reply }) => {
                        if guard.as_ref().is_some_and(|guard| !guard.allowed()) {
                            let _ = reply.send(Err("room pause, authority or Session changed; the interrupt was not sent".into()));
                            continue;
                        }
                        if let Some(call) = self.steer_call(steer, reply) {
                            let written = if let Some(guard) = guard {
                                tokio::select! {
                                    biased;
                                    () = guard.cancelled() => false,
                                    written = Self::write(&mut write, &call) => written,
                                }
                            } else { Self::write(&mut write, &call).await };
                            if !written {
                                self.fail("a control write failed; its outcome is unknown, do not assume it is safe to repeat").await;
                                break;
                            }
                        }
                    }
                },
                _ = timer.tick(), if !self.asks.is_empty() || !self.calls.is_empty() => {
                    if self.calls.values().any(|call| call.expires <= tokio::time::Instant::now()) {
                        self.fail("OpenCode did not answer a control within 30 seconds; its outcome is unknown, do not assume it is safe to repeat").await;
                        break;
                    }
                    // At most 64 exact waiters examined and one answer sent per turn.
                    if let Some((id, given)) = self.take_answer() {
                        if given_bytes(&given) > MAX_COMMAND_BYTES {
                            self.fail("an answer exceeds the control byte bound; it was not sent to OpenCode").await;
                            break;
                        }
                        let Some(call) = self.answer_call(&id, given) else {
                            self.fail("an accepted answer could not enter the bounded control queue; it was not sent to OpenCode").await;
                            break;
                        };
                        if !Self::write(&mut write, &call).await {
                            self.fail("an answer write failed; its outcome is unknown").await;
                            break;
                        }
                    }
                },
                n = async { (&mut lines).take(remaining).read_until(b'\n', &mut line).await } => {
                    match n {
                        Ok(0) | Err(_) => { self.fail("the plugin connection closed; pending control outcomes are unknown").await; break; }
                        Ok(_) if line.len() > MAX_LINE => {
                            self.fail("an OpenCode event exceeds the 4 MiB line bound").await;
                            break;
                        }
                        Ok(_) => {
                            match serde_json::from_slice::<Value>(&line) {
                                Ok(v) => self.line(&v).await,
                                Err(_) => self.fail("the plugin supplied malformed event JSON").await,
                            }
                            if self.failed { break; }
                        }
                    }
                    line.clear();
                }
            }
        }
        for (_, call) in std::mem::take(&mut self.calls) {
            let _ = call.reply.send(Err("the OpenCode connection closed; the control outcome is unknown, do not assume it is safe to repeat".into()));
        }
    }

    async fn write(write: &mut tokio::net::unix::OwnedWriteHalf, line: &str) -> bool {
        matches!(
            tokio::time::timeout(CALL_WITHIN, write.write_all(line.as_bytes())).await,
            Ok(Ok(()))
        )
    }

    fn take_answer(&mut self) -> Option<(String, Given)> {
        let mut answer = None;
        self.asks.retain(|id, ask| {
            let Some(receiver) = ask.receiver.as_mut() else {
                return true;
            };
            if answer.is_some() {
                return true;
            }
            match receiver.try_recv() {
                Ok(given) => {
                    ask.receiver = None;
                    answer = Some((id.clone(), given));
                    true
                }
                Err(oneshot::error::TryRecvError::Empty) => true,
                // Sink retired this exact waiter; no later same-ID request is touched.
                Err(oneshot::error::TryRecvError::Closed) => false,
            }
        });
        answer
    }

    fn call(
        &mut self,
        mut body: Map<String, Value>,
        reply: oneshot::Sender<Result<String, String>>,
        done: String,
    ) -> Option<String> {
        if self.calls.len() >= MAX_COMMANDS {
            let _ = reply.send(Err(
                "OpenCode has 32 unanswered controls; nothing was sent".into()
            ));
            return None;
        }
        let id = self.next_id;
        let Some(next) = id.checked_add(1) else {
            let _ = reply.send(Err(
                "OpenCode control sequence exhausted; nothing was sent".into()
            ));
            return None;
        };
        self.next_id = next;
        body.insert("type".into(), json!("call"));
        body.insert("id".into(), json!(id));
        let line = format!("{}\n", Value::Object(body));
        if line.len() > MAX_COMMAND_BYTES {
            let _ = reply.send(Err(
                "encoded OpenCode control exceeds 64 KiB; nothing was sent".into(),
            ));
            return None;
        }
        self.calls.insert(
            id,
            PendingCall {
                reply,
                done,
                expires: tokio::time::Instant::now() + CALL_WITHIN,
            },
        );
        Some(line)
    }

    fn steer_call(
        &mut self,
        steer: Steer,
        reply: oneshot::Sender<Result<String, String>>,
    ) -> Option<String> {
        let mut m = Map::new();
        let done = match steer {
            Steer::Text(text) => {
                m.insert("action".into(), json!("prompt"));
                m.insert("text".into(), json!(text));
                "typed".to_owned()
            }
            Steer::Interrupt | Steer::Stop => {
                m.insert("action".into(), json!("abort"));
                "the running turn was stopped".to_owned()
            }
            Steer::Slash { cmd, args } => match cmd.as_str() {
                "rename" if !args.trim().is_empty() => {
                    m.insert("action".into(), json!("rename"));
                    m.insert("title".into(), json!(args.trim()));
                    format!("renamed to {}", args.trim())
                }
                "rename" => {
                    let _ = reply.send(Err("/rename needs a name".into()));
                    return None;
                }
                "compact" => {
                    m.insert("action".into(), json!("summarize"));
                    "/compact started".to_owned()
                }
                "clear" | "new" => {
                    let _ = reply.send(Err(format!(
                        "/{cmd} would start a new OpenCode session, and driving never starts a \
                         session; type it at its terminal"
                    )));
                    return None;
                }
                other => {
                    m.insert("action".into(), json!("command"));
                    m.insert("command".into(), json!(other));
                    m.insert("arguments".into(), json!(args));
                    format!("/{other} sent")
                }
            },
        };
        self.call(m, reply, done)
    }

    fn answer_call(&mut self, request: &str, given: Given) -> Option<String> {
        let ask = self.asks.get_mut(request)?;
        let mut m = Map::new();
        match (&given, ask.of) {
            (Given::Approve { allow, why }, "approval") => {
                m.insert("action".into(), json!("permission"));
                m.insert("request".into(), json!(request));
                m.insert(
                    "reply".into(),
                    json!(if *allow { "once" } else { "reject" }),
                );
                if let Some(w) = why.as_ref().filter(|w| !w.trim().is_empty()) {
                    m.insert("message".into(), json!(w));
                }
            }
            _ => return None,
        }
        ask.answered = Some(given);
        if self
            .asks
            .iter()
            .fold(0usize, |n, (id, ask)| n.saturating_add(ask_bytes(id, ask)))
            > MAX_ASK_BYTES
        {
            return None;
        }
        // Its result is OpenCode's `permission.replied`, not this call's.
        let (reply, _) = oneshot::channel();
        self.call(m, reply, String::new())
    }

    async fn line(&mut self, v: &Value) {
        match v.get("type").and_then(Value::as_str) {
            Some("mirror-error") => {
                let why = v
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("OpenCode could not supply authoritative message metadata");
                self.fail(why).await;
            }
            Some("result") => {
                let Some(call) = v
                    .get("id")
                    .and_then(Value::as_u64)
                    .and_then(|id| self.calls.remove(&id))
                else {
                    return;
                };
                let result = if v.get("ok").and_then(Value::as_bool) == Some(true) {
                    Ok(call.done.clone())
                } else {
                    Err(format!(
                        "OpenCode did not confirm the control: {}",
                        v.get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("no reason given")
                    ))
                };
                if call.done.is_empty() {
                    if let Err(why) = &result {
                        self.fail(why).await;
                    }
                }
                let _ = call.reply.send(result);
            }
            Some("event") => self.event(&v["event"]).await,
            _ => {}
        }
    }

    fn envelope(&self, sid: &str, kind: &str, r: Option<&str>) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("v".into(), json!(VERSION));
        m.insert("session".into(), json!(self.session));
        m.insert("kind".into(), json!(kind));
        m.insert("ts".into(), json!(now_ms()));
        if let Some(r) = r {
            m.insert("ref".into(), json!(r));
        }
        // A sub-agent's entries belong to its parent's Session, labelled (SE-2).
        if sid != self.session {
            m.insert("agent_id".into(), json!(sid));
            let label = self
                .agent
                .as_ref()
                .filter(|(of, _)| of == sid)
                .map_or(sid, |(_, name)| name.as_str());
            m.insert("agent".into(), json!(label));
        }
        m
    }

    async fn post(&mut self, bodies: Vec<String>) {
        if !bodies.is_empty() {
            self.ended = false;
            self.sink
                .activity(&self.node, &self.session, bodies, None)
                .await;
        }
    }

    async fn fail(&mut self, why: &str) {
        eprintln!(
            "vox daemon: {}: OpenCode Session {} observation stopped: {why}",
            self.node, self.session
        );
        let mut entry = self.envelope(&self.session, "notice", None);
        entry.insert(
            "summary".into(),
            json!(format!("OpenCode observation stopped: {why}")),
        );
        self.post(split(entry, "summary")).await;
        self.failed = true;
    }

    /// The ingress transaction remembers exact source identities, including split parts.
    /// Timestamp changes on a repeated bus event do not change its source content revision.
    async fn post_source(&mut self, sid: &str, id: &str, mut entry: Map<String, Value>, big: &str) {
        if id.is_empty() {
            self.fail("an activity event has no source identity").await;
            return;
        }
        let source = vox_core::hash::sha256(
            json!(["opencode", sid, entry["kind"], id])
                .to_string()
                .as_bytes(),
        );
        let echo = (entry["kind"] == "user")
            .then(|| entry.get("text").and_then(Value::as_str).map(str::to_owned))
            .flatten();
        let timestamp = entry.remove("ts");
        let revision = vox_core::hash::sha256(Value::Object(entry.clone()).to_string().as_bytes());
        if let Some(timestamp) = timestamp {
            entry.insert("ts".into(), timestamp);
        }
        let mut bodies = split(entry, big);
        let parts = bodies.len();
        for (part, body) in bodies.iter_mut().enumerate() {
            let Ok(Value::Object(mut object)) = serde_json::from_str::<Value>(body) else {
                unreachable!("split returns objects")
            };
            object.insert(
                "_vox_source".into(),
                json!({"id": source, "revision": revision, "part": part + 1, "parts": parts}),
            );
            *body = Value::Object(object).to_string();
        }
        let posted = self
            .sink
            .source_activity(&self.node, &self.session, bodies, echo.as_deref())
            .await;
        if let vox_core::node::daemonipc::SessionAdmission::Refused(why)
        | vox_core::node::daemonipc::SessionAdmission::Unconfirmed(why) = &posted.admission
        {
            self.fail(why).await;
            return;
        }
        if posted.fresh
            || matches!(
                posted.admission,
                vox_core::node::daemonipc::SessionAdmission::Held(_)
            )
        {
            self.ended = false;
        }
    }

    /// Post the assistant's text not yet posted, as one reply per session it came from.
    async fn flush_replies(&mut self) {
        let texts = std::mem::take(&mut self.texts);
        let mut by: Vec<(String, String, Option<String>)> = Vec::new();
        for (sid, _, t, agent) in texts {
            if t.trim().is_empty() {
                continue;
            }
            match by.iter_mut().find(|(s, _, _)| *s == sid) {
                Some((_, all, _)) => {
                    all.push_str("\n\n");
                    all.push_str(&t);
                }
                None => by.push((sid, t, agent)),
            }
        }
        for (sid, text, agent) in by {
            let mut e = self.envelope(&sid, "reply", None);
            if let Some(agent) = agent {
                e.insert("agent".into(), json!(agent));
            }
            e.insert("text".into(), json!(text));
            self.post(split(e, "text")).await;
        }
    }

    async fn event(&mut self, ev: &Value) {
        let d = &ev["data"];
        let sid = d
            .get("sessionID")
            .and_then(Value::as_str)
            .unwrap_or(&self.session)
            .to_owned();
        match ev.get("type").and_then(Value::as_str).unwrap_or_default() {
            // The lineage of a sub-agent's session and its authoritative agent label (SE-2).
            "session.created" => {
                if sid != self.session {
                    if let Some(agent) = d.get("agent").and_then(Value::as_str) {
                        self.agent = Some((sid.clone(), agent.to_owned()));
                    }
                }
            }
            // **A rename is the Session's name at once** (ADR-029 MD-1): OpenCode's title, set by
            // `/rename`, by Vox's own rename, or made by OpenCode itself, arrives only here.
            "session.renamed" => {
                if sid == self.session {
                    if let Some(title) = d.get("title").and_then(Value::as_str) {
                        if self.title.as_deref() != Some(title) {
                            self.title = Some(title.to_owned());
                            self.sink.renamed(&self.node, &self.session, title);
                        }
                    }
                }
            }
            // The operator's prompt (`user`): the delivered inbox item's payload text. A
            // sub-agent's prompt is its parent's tool call, already shown.
            "session.inbox.delivered" | "session.inbox.enqueued" => {
                if sid != self.session {
                    return;
                }
                if d.pointer("/item/type").and_then(Value::as_str) != Some("user") {
                    return;
                }
                let Some(text) = d.pointer("/item/payload/text").and_then(Value::as_str) else {
                    return;
                };
                let Some(text) = typed(text) else {
                    return;
                };
                if text.trim().is_empty() {
                    return;
                }
                let mut e = self.envelope(&sid, "user", None);
                e.insert("text".into(), json!(text));
                let id = d.get("inboxID").and_then(Value::as_str).unwrap_or_default();
                self.post_source(&sid, id, e, "text").await;
            }
            // The step a reply is made in: its agent, and an attention observation the
            // plugin attached from the receipts its drain stamped on this turn's input.
            "session.step.started" => {
                if let Some(agent) = d.get("agent").and_then(Value::as_str) {
                    self.agent = Some((sid.clone(), agent.to_owned()));
                }
                if let Some(observed) = d.get("voxAttention").filter(|v| !v.is_null()) {
                    let result = async {
                        if sid != self.session {
                            return Err(
                                "attention observation is not this Session's running step".into()
                            );
                        }
                        let bytes = serde_json::to_vec(observed).map_err(|e| e.to_string())?;
                        if bytes.len() > vox_core::node::attention::MAX_BYTES {
                            return Err("attention observation exceeds its byte bound".into());
                        }
                        let observation: vox_core::node::attention::InputObservation =
                            serde_json::from_slice(&bytes)
                                .map_err(|e| format!("invalid attention observation: {e}"))?;
                        if Some(observation.assistant.as_str())
                            != d.get("assistantMessageID").and_then(Value::as_str)
                            || Some(observation.step.as_str())
                                != d.get("assistantMessageID").and_then(Value::as_str)
                        {
                            return Err(
                                "attention observation names a different assistant step".into()
                            );
                        }
                        self.sink
                            .attention_observed(
                                &self.node,
                                &self.session,
                                &self.mirror_endpoint,
                                &self.mirror_token,
                                observation,
                            )
                            .await
                    }
                    .await;
                    if let Err(why) = result {
                        self.fail(&why).await;
                    }
                }
            }
            "session.text.ended" => {
                let Some(text) = d.get("text").and_then(Value::as_str) else {
                    return;
                };
                let pid = format!(
                    "{}:{}",
                    d.get("assistantMessageID")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    d.get("ordinal").and_then(Value::as_u64).unwrap_or_default()
                );
                self.assistant_text(&sid, &pid, text).await;
            }
            "session.tool.input.started" => {
                let key = (
                    sid.clone(),
                    d.get("assistantMessageID")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    d.get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                );
                if let Some(name) = d.get("name").and_then(Value::as_str) {
                    self.tools.insert(key, name.to_owned());
                    if self.tools.len() > MAX_COMMANDS {
                        let first = self.tools.keys().next().cloned();
                        if let Some(first) = first {
                            self.tools.remove(&first);
                        }
                    }
                }
            }
            "session.tool.called" => {
                let id = d.get("id").and_then(Value::as_str).unwrap_or_default();
                let key = (
                    sid.clone(),
                    d.get("assistantMessageID")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    id.to_owned(),
                );
                let tool = self
                    .tools
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| "tool".into());
                // Admit earlier reply text before this call, without spawning an unbounded waiter.
                self.flush_replies().await;
                let input = d.get("input").cloned().unwrap_or(json!({}));
                let text = input_text(&tool, &input);
                let mut e = self.envelope(&sid, "tool", Some(id));
                e.insert("tool".into(), json!(tool));
                e.insert("summary".into(), json!(one_line(&text)));
                e.insert("input".into(), json!(text));
                self.post_source(&sid, id, e, "input").await;
            }
            "session.tool.success" | "session.tool.failed" => {
                let id = d.get("id").and_then(Value::as_str).unwrap_or_default();
                let key = (
                    sid.clone(),
                    d.get("assistantMessageID")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    id.to_owned(),
                );
                let tool = self
                    .tools
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| "tool".into());
                let ok = ev.get("type").and_then(Value::as_str) == Some("session.tool.success");
                self.tool_settled(&sid, id, &tool, ok, d).await;
            }
            "session.idle" if sid == self.session => {
                self.flush_replies().await;
                if !self.ended {
                    self.post(split(self.envelope(&sid, "turn-end", None), ""))
                        .await;
                    self.ended = true;
                }
            }
            "session.status" if sid == self.session => {
                if d.pointer("/status/type").and_then(Value::as_str) == Some("idle") {
                    self.flush_replies().await;
                    if !self.ended {
                        self.post(split(self.envelope(&sid, "turn-end", None), ""))
                            .await;
                        self.ended = true;
                    }
                }
            }
            "permission.asked" => {
                self.permission(&sid, d).await;
            }
            "permission.replied" => {
                let Some(r) = d.get("requestID").and_then(Value::as_str) else {
                    return;
                };
                if self.asks.remove(r).is_some() {
                    let outcome = match d.get("reply").and_then(Value::as_str) {
                        Some("reject") => "denied",
                        _ => "allowed",
                    };
                    self.sink
                        .resolved(&self.node, &self.session, r, outcome, None)
                        .await;
                }
            }
            _ => {}
        }
    }

    /// Accumulate one finished assistant text part of a reply, posted before the next
    /// tool call and at the turn's end, so replies and calls keep their order.
    async fn assistant_text(&mut self, sid: &str, pid: &str, text: &str) {
        let agent = self
            .agent
            .as_ref()
            .filter(|(of, _)| of == sid)
            .map(|(_, name)| name.clone());
        let slot = self
            .texts
            .iter()
            .position(|(of, id, _, _)| of == sid && id == pid);
        let used = self
            .texts
            .iter()
            .enumerate()
            .filter(|(i, _)| Some(*i) != slot)
            .fold(0usize, |n, (_, (s, p, t, a))| {
                n.saturating_add(s.len())
                    .saturating_add(p.len())
                    .saturating_add(t.len())
                    .saturating_add(a.as_ref().map_or(0, String::len))
            });
        let added = sid
            .len()
            .saturating_add(pid.len())
            .saturating_add(text.len())
            .saturating_add(agent.as_ref().map_or(0, String::len));
        if (slot.is_none() && self.texts.len() >= MAX_TEXT_PARTS)
            || added > MAX_TEXT_BYTES.saturating_sub(used)
        {
            self.fail("live assistant text exceeds 128 parts or 8 MiB; observation must restart")
                .await;
            return;
        }
        let part = (sid.to_owned(), pid.to_owned(), text.to_owned(), agent);
        if let Some(slot) = slot {
            self.texts[slot] = part;
        } else {
            self.texts.push(part);
        }
    }

    /// A tool call's settlement: its completion or failure, in the shape every harness
    /// shares. A completion seen alone posts its start first.
    async fn tool_settled(&mut self, sid: &str, call: &str, tool: &str, ok: bool, d: &Value) {
        self.flush_replies().await;
        let output = if ok {
            d.get("content")
                .and_then(Value::as_array)
                .map(|cs| {
                    cs.iter()
                        .filter_map(|c| c.get("text").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join("\n\n")
                })
                .unwrap_or_default()
        } else {
            d.get("error")
                .map(|e| {
                    e.get("message")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .unwrap_or_else(|| e.to_string())
                })
                .unwrap_or_default()
        };
        let summary = if ok {
            one_line(&output)
        } else {
            format!("error: {}", one_line(&output))
        };
        let mut e = self.envelope(sid, "tool-done", Some(call));
        e.insert("tool".into(), json!(tool));
        e.insert("ok".into(), json!(ok));
        e.insert("summary".into(), json!(one_line(&summary)));
        e.insert("output".into(), json!(output));
        self.post_source(sid, call, e, "output").await;
    }

    async fn permission(&mut self, sid: &str, d: &Value) {
        let Some(id) = d.get("id").and_then(Value::as_str).map(str::to_owned) else {
            return;
        };
        let action = d.get("action").and_then(Value::as_str).unwrap_or("tool");
        let patterns = d
            .get("resources")
            .and_then(Value::as_array)
            .map(|ps| {
                ps.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let input = d
            .get("metadata")
            .map(|m| serde_json::to_string_pretty(m).unwrap_or_default())
            .unwrap_or_default();
        let mut e = self.envelope(sid, "approval", Some(&id));
        e.insert("tool".into(), json!(action));
        e.insert(
            "summary".into(),
            json!(one_line(if patterns.is_empty() {
                &input
            } else {
                &patterns
            })),
        );
        e.insert("input".into(), json!(input));
        self.ask(id, "approval", Value::Object(e).to_string()).await;
    }

    async fn ask(&mut self, id: String, of: &'static str, entry: String) {
        if self.asks.contains_key(&id) {
            return;
        }
        let used = self
            .asks
            .iter()
            .fold(0usize, |n, (id, ask)| n.saturating_add(ask_bytes(id, ask)));
        let added = id.len();
        if self.asks.len() >= MAX_ASKS
            || added > MAX_ASK_BYTES.saturating_sub(used)
            || entry.len() > MAX_LINE
        {
            self.fail("pending requests exceed 64 requests or 4 MiB; no permission was answered, observation must restart").await;
            return;
        }
        let Some(rx) = self.sink.request(&self.node, &self.session, entry).await else {
            self.fail("a pending request could not be admitted; no permission was answered")
                .await;
            return;
        };
        self.asks.insert(
            id,
            Ask {
                of,
                answered: None,
                receiver: Some(rx),
            },
        );
    }
}

/// A tool call's input as text: a command for `bash`, the path for a file tool, else its JSON.
fn input_text(tool: &str, input: &Value) -> String {
    let field = |k: &str| input.get(k).and_then(Value::as_str).map(str::to_owned);
    match tool {
        "bash" => field("command"),
        "read" | "write" | "edit" | "list" => field("filePath").or_else(|| field("path")),
        _ => None,
    }
    .unwrap_or_else(|| serde_json::to_string_pretty(input).unwrap_or_default())
}
