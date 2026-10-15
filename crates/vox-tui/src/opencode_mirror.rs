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
//! - each turn's end (`turn-end`): `session.idle`;
//! - each approval (`permission.asked`) and question (`question.asked`), held for the first answer
//!   ([`Sink::request`]) and retired by OpenCode's own `permission.replied`, `question.replied`
//!   or `question.rejected` (DR-4).
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
            agent: None,
            texts: Vec::new(),
            asks: BTreeMap::new(),
            model: None,
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

/// An approval or question OpenCode asked.
struct Ask {
    of: &'static str,
    /// The questions, in order, to put answers back in OpenCode's shape.
    questions: Vec<Value>,
    answered: Option<Given>,
    /// The answers sent to OpenCode, in its shape.
    sent: Option<Value>,
    /// Exactly this request's first-answer waiter; no detached forwarding task survives it.
    receiver: Option<oneshot::Receiver<Given>>,
}

struct Follow {
    node: NodeName,
    session: String,
    sink: Arc<Sink>,
    /// Current authoritative sub-agent label. An unavailable label falls back to exact agent_id.
    agent: Option<(String, String)>,
    /// Live assistant text parts not yet posted: (session, part id, text, agent label).
    texts: Vec<(String, String, String, Option<String>)>,
    asks: BTreeMap<String, Ask>,
    /// The provider and model of the session's last assistant message, which /compact needs.
    model: Option<(String, String)>,
    /// Whether the last thing posted was a turn's end: OpenCode reports a session idle more than
    /// once around an abort, and one turn ends once.
    ended: bool,
    /// An explicit producer failure ends this observation rather than guessing missing roles.
    failed: bool,
    /// The session's title as last said: OpenCode sends `session.updated` for much besides a
    /// rename, and only a new title renames the Session.
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
        .saturating_add(serde_json::to_vec(&ask.questions).map_or(MAX_ASK_BYTES, |v| v.len()))
        .saturating_add(ask.answered.as_ref().map_or(0, given_bytes))
        .saturating_add(ask.sent.as_ref().map_or(0, |value| {
            serde_json::to_vec(value).map_or(MAX_ASK_BYTES, |v| v.len())
        }))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Text the operator typed, without the blocks the drain put in front of it (Vox's notice, the
/// room's fence). `None` for a wake notice Vox relayed: it is Vox's, not the operator's.
fn typed(text: &str) -> Option<&str> {
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
                    let Some((provider, model)) = self.model.clone() else {
                        let _ = reply.send(Err(
                            "/compact needs the session's model, and it has not answered since \
                             Vox began following it"
                                .into(),
                        ));
                        return None;
                    };
                    m.insert("action".into(), json!("summarize"));
                    m.insert("providerID".into(), json!(provider));
                    m.insert("modelID".into(), json!(model));
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
            (Given::Answer(a), "question") => {
                let answers: Vec<Value> = ask
                    .questions
                    .iter()
                    .map(|q| {
                        let text = q
                            .get("question")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        let given = a.get(text).cloned().unwrap_or_default();
                        json!(labels(q, &given))
                    })
                    .collect();
                m.insert("action".into(), json!("question"));
                m.insert("request".into(), json!(request));
                ask.sent = Some(json!(answers));
                m.insert("answers".into(), json!(answers));
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
        // Its result is OpenCode's `permission.replied` / `question.replied`, not this call's.
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
        let p = &ev["properties"];
        let sid = p
            .get("sessionID")
            .or_else(|| p.pointer("/part/sessionID"))
            .or_else(|| p.pointer("/info/sessionID"))
            .and_then(Value::as_str)
            .unwrap_or(&self.session)
            .to_owned();
        match ev.get("type").and_then(Value::as_str).unwrap_or_default() {
            "message.updated" => {
                let info = &p["info"];
                if info.get("role").and_then(Value::as_str) == Some("assistant") {
                    if sid != self.session {
                        if let Some(a) = info.get("agent").and_then(Value::as_str) {
                            self.agent = Some((sid.clone(), a.to_owned()));
                        }
                    } else if let (Some(pr), Some(mo)) = (
                        info.get("providerID").and_then(Value::as_str),
                        info.get("modelID").and_then(Value::as_str),
                    ) {
                        self.model = Some((pr.to_owned(), mo.to_owned()));
                    }
                }
            }
            "message.part.updated" => {
                let info = &p["voxMessage"];
                let part = &p["part"];
                let Some(role @ ("user" | "assistant")) = info.get("role").and_then(Value::as_str)
                else {
                    self.fail("a part arrived without its authoritative message role")
                        .await;
                    return;
                };
                if info.get("id").and_then(Value::as_str)
                    != part.get("messageID").and_then(Value::as_str)
                    || info.get("sessionID").and_then(Value::as_str) != Some(sid.as_str())
                {
                    self.fail("a part arrived without its authoritative message role")
                        .await;
                    return;
                }
                self.agent = info
                    .get("agent")
                    .and_then(Value::as_str)
                    .map(|agent| (sid.clone(), agent.to_owned()));
                if sid == self.session && info["role"] == "assistant" {
                    if let (Some(provider), Some(model)) = (
                        info.get("providerID").and_then(Value::as_str),
                        info.get("modelID").and_then(Value::as_str),
                    ) {
                        self.model = Some((provider.to_owned(), model.to_owned()));
                    }
                }
                self.part(&sid, part, role).await;
            }
            // **A rename is the Session's name at once** (ADR-029 MD-1): OpenCode's title, set by
            // `/rename`, by Vox's own rename, or made by OpenCode itself, arrives only here.
            "session.updated" => {
                let info = &p["info"];
                if info.get("id").and_then(Value::as_str) == Some(self.session.as_str()) {
                    if let Some(title) = info.get("title").and_then(Value::as_str) {
                        if self.title.as_deref() != Some(title) {
                            self.title = Some(title.to_owned());
                            self.sink.renamed(&self.node, &self.session, title);
                        }
                    }
                }
            }
            "session.idle" if sid == self.session => {
                self.flush_replies().await;
                if !self.ended {
                    self.post(split(self.envelope(&sid, "turn-end", None), ""))
                        .await;
                    self.ended = true;
                }
            }
            "permission.asked" => {
                self.permission(&sid, p).await;
            }
            "question.asked" => {
                self.question(&sid, p).await;
            }
            "permission.replied" => {
                let Some(r) = p.get("requestID").and_then(Value::as_str) else {
                    return;
                };
                if self.asks.remove(r).is_some() {
                    let outcome = match p.get("reply").and_then(Value::as_str) {
                        Some("reject") => "denied",
                        _ => "allowed",
                    };
                    self.sink
                        .resolved(&self.node, &self.session, r, outcome, None)
                        .await;
                }
            }
            t @ ("question.replied" | "question.rejected") => {
                let Some(r) = p.get("requestID").and_then(Value::as_str) else {
                    return;
                };
                if let Some(ask) = self.asks.remove(r) {
                    if t == "question.rejected" {
                        self.sink
                            .resolved(&self.node, &self.session, r, "cancelled", None)
                            .await;
                    } else {
                        // What OpenCode took, in the shape the member gave it when it is the
                        // member's answer, so the sink can say who answered (DR-4).
                        let took = p.get("answers").cloned();
                        let answers = match (&ask.answered, &ask.sent) {
                            (Some(Given::Answer(m)), Some(sent)) if took.as_ref() == Some(sent) => {
                                Some(json!(m))
                            }
                            _ => took,
                        };
                        self.sink
                            .resolved(&self.node, &self.session, r, "answered", answers)
                            .await;
                    }
                }
            }
            _ => {}
        }
    }

    async fn part(&mut self, sid: &str, part: &Value, role: &str) {
        let pid = part.get("id").and_then(Value::as_str).unwrap_or_default();
        match part.get("type").and_then(Value::as_str).unwrap_or_default() {
            "text" => {
                let text = part.get("text").and_then(Value::as_str).unwrap_or_default();
                match role {
                    "user" => {
                        // A user message's text, once, when it is final; a sub-agent's prompt
                        // is its parent's tool call, already shown.
                        if sid != self.session {
                            return;
                        }
                        let Some(text) = typed(text) else { return };
                        if text.trim().is_empty() {
                            return;
                        }
                        let mut e = self.envelope(sid, "user", None);
                        e.insert("text".into(), json!(text));
                        self.post_source(sid, pid, e, "text").await;
                    }
                    "assistant" => {
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
                            self.fail("live assistant text exceeds 128 parts or 8 MiB; observation must restart").await;
                            return;
                        }
                        let part = (sid.to_owned(), pid.to_owned(), text.to_owned(), agent);
                        if let Some(slot) = slot {
                            self.texts[slot] = part;
                        } else {
                            self.texts.push(part);
                        }
                    }
                    _ => unreachable!("checked role"),
                }
            }
            "tool" => self.tool(sid, part).await,
            _ => {}
        }
    }

    async fn tool(&mut self, sid: &str, part: &Value) {
        let call = part
            .get("callID")
            .or_else(|| part.get("id"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let tool = part
            .get("tool")
            .and_then(Value::as_str)
            .unwrap_or("tool")
            .to_owned();
        let state = &part["state"];
        let status = state
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let input = state.get("input").cloned().unwrap_or(json!({}));
        if matches!(status, "running" | "completed" | "error") {
            // Admit earlier reply text before this call, without spawning an unbounded waiter.
            self.flush_replies().await;
            let text = input_text(&tool, &input);
            let mut e = self.envelope(sid, "tool", Some(&call));
            e.insert("tool".into(), json!(tool));
            e.insert("summary".into(), json!(one_line(&text)));
            e.insert("input".into(), json!(text));
            self.post_source(sid, &call, e, "input").await;
            if self.failed {
                return;
            }
        }
        match status {
            "running" => {}
            "completed" | "error" => {
                let ok = status == "completed";
                let output = if ok {
                    state
                        .get("output")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                } else {
                    state
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                let summary = if ok {
                    state
                        .get("title")
                        .and_then(Value::as_str)
                        .filter(|t| !t.is_empty())
                        .map_or_else(|| one_line(&output), one_line)
                } else {
                    format!("error: {}", one_line(&output))
                };
                let mut e = self.envelope(sid, "tool-done", Some(&call));
                e.insert("tool".into(), json!(tool));
                e.insert("ok".into(), json!(ok));
                e.insert("summary".into(), json!(one_line(&summary)));
                e.insert("output".into(), json!(output));
                self.post_source(sid, &call, e, "output").await;
            }
            _ => {}
        }
    }

    async fn permission(&mut self, sid: &str, p: &Value) {
        let Some(id) = p.get("id").and_then(Value::as_str).map(str::to_owned) else {
            return;
        };
        let what = p
            .get("permission")
            .and_then(Value::as_str)
            .unwrap_or("tool");
        let patterns = p
            .get("patterns")
            .and_then(Value::as_array)
            .map(|ps| {
                ps.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let input = p
            .get("metadata")
            .map(|m| serde_json::to_string_pretty(m).unwrap_or_default())
            .unwrap_or_default();
        let mut e = self.envelope(sid, "approval", Some(&id));
        e.insert("tool".into(), json!(what));
        e.insert(
            "summary".into(),
            json!(one_line(if patterns.is_empty() {
                &input
            } else {
                &patterns
            })),
        );
        e.insert("input".into(), json!(input));
        self.ask(id, "approval", Vec::new(), Value::Object(e).to_string())
            .await;
    }

    async fn question(&mut self, sid: &str, p: &Value) {
        let Some(id) = p.get("id").and_then(Value::as_str).map(str::to_owned) else {
            return;
        };
        let questions: Vec<Value> = p
            .get("questions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let shown: Vec<Value> = questions
            .iter()
            .map(|q| {
                json!({
                    "text": q.get("question").cloned().unwrap_or(Value::Null),
                    "header": q.get("header").cloned().unwrap_or(Value::Null),
                    "options": q.get("options").cloned().unwrap_or(json!([])),
                    "multi": q.get("multiple").and_then(Value::as_bool).unwrap_or(false),
                })
            })
            .collect();
        let mut e = self.envelope(sid, "question", Some(&id));
        e.insert("questions".into(), json!(shown));
        self.ask(id, "question", questions, Value::Object(e).to_string())
            .await;
    }

    async fn ask(&mut self, id: String, of: &'static str, questions: Vec<Value>, entry: String) {
        if self.asks.contains_key(&id) {
            return;
        }
        let used = self
            .asks
            .iter()
            .fold(0usize, |n, (id, ask)| n.saturating_add(ask_bytes(id, ask)));
        let added = id
            .len()
            .saturating_add(serde_json::to_vec(&questions).map_or(MAX_ASK_BYTES, |v| v.len()));
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
                questions,
                answered: None,
                sent: None,
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

/// A member's answer to question `q` as OpenCode's list of chosen labels. A multiple-choice
/// answer arrives joined with ", "; it is split only when every piece is one of the question's
/// labels, so a label or a typed answer holding ", " is never cut apart.
fn labels(q: &Value, given: &str) -> Vec<String> {
    let options: Vec<&str> = q
        .get("options")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|o| o.get("label").and_then(Value::as_str))
        .collect();
    if given.is_empty() {
        return Vec::new();
    }
    if options.contains(&given) {
        return vec![given.to_owned()];
    }
    let pieces: Vec<&str> = given.split(", ").collect();
    if q.get("multiple").and_then(Value::as_bool) == Some(true)
        && pieces.iter().all(|p| options.contains(p))
    {
        return pieces.into_iter().map(str::to_owned).collect();
    }
    vec![given.to_owned()]
}
