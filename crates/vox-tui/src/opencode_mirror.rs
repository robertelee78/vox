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

use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::sync::{mpsc, oneshot};
use vox_core::node::paths::NodeName;

use crate::codex_mirror::Steer;
use vox_agentcomms::activity::{one_line, VERSION};
use vox_core::node::content::MAX_TEXT_LEN;

fn split(m: Map<String, Value>, big: &str) -> Vec<String> {
    vox_agentcomms::activity::split(m, big, MAX_TEXT_LEN)
}
use crate::session_sink::{Given, Sink};

/// The longest line the plugin may write; an event longer than this is dropped, not buffered.
const MAX_LINE: usize = 4 << 20;

/// The daemon's OpenCode followers, one connection per session.
pub struct OpenCodeMirror {
    sink: Arc<Sink>,
    conns: Mutex<BTreeMap<String, mpsc::UnboundedSender<Cmd>>>,
}

enum Cmd {
    Steer {
        steer: Steer,
        reply: oneshot::Sender<Result<String, String>>,
    },
    Answer {
        request: String,
        given: Given,
    },
    End,
}

impl OpenCodeMirror {
    /// Followers posting through `sink`.
    #[must_use]
    pub fn new(sink: Arc<Sink>) -> Arc<Self> {
        Arc::new(Self {
            sink,
            conns: Mutex::new(BTreeMap::new()),
        })
    }

    fn conns(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, mpsc::UnboundedSender<Cmd>>> {
        self.conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// An OpenCode session of `node` registered its plugin's socket: follow it, unless already
    /// followed.
    pub fn watch(self: &Arc<Self>, node: &NodeName, session: &str, endpoint: &str, token: &str) {
        let mut conns = self.conns();
        if conns.get(session).is_some_and(|tx| !tx.is_closed()) {
            return;
        }
        let (tx, rx) = mpsc::unbounded_channel();
        conns.insert(session.to_owned(), tx.clone());
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
            answers: tx,
        };
        let (endpoint, token) = (endpoint.to_owned(), token.to_owned());
        tokio::spawn(follow.run(endpoint, token, rx));
    }

    /// The session ended: stop following it.
    pub fn end(&self, session: &str) {
        if let Some(tx) = self.conns().remove(session) {
            let _ = tx.send(Cmd::End);
        }
    }

    /// Steer `session` (#544): what was done, in words, or why it was refused (DR-6).
    ///
    /// # Errors
    /// Why nothing reached the session.
    pub async fn steer(&self, session: &str, steer: Steer) -> Result<String, String> {
        let tx = self.conns().get(session).cloned().ok_or_else(|| {
            "Vox is not connected to this OpenCode session: it ended, or its OpenCode has not run \
             a turn since Vox started"
                .to_owned()
        })?;
        let (reply, rx) = oneshot::channel();
        tx.send(Cmd::Steer { steer, reply })
            .map_err(|_| "Vox's connection to this OpenCode session has closed".to_owned())?;
        rx.await
            .unwrap_or_else(|_| Err("Vox's connection to this OpenCode session closed".to_owned()))
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
    calls: BTreeMap<u64, (oneshot::Sender<Result<String, String>>, String)>,
    /// Where a member's first answer comes back to this loop.
    answers: mpsc::UnboundedSender<Cmd>,
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
    async fn run(mut self, endpoint: String, token: String, mut rx: mpsc::UnboundedReceiver<Cmd>) {
        let Ok(stream) = tokio::net::UnixStream::connect(&endpoint).await else {
            return;
        };
        let (read, mut write) = stream.into_split();
        let hello = format!(
            "{}\n{}\n",
            json!({"type": "auth", "token": token}),
            json!({"type": "subscribe", "session": self.session})
        );
        if write.write_all(hello.as_bytes()).await.is_err() {
            return;
        }
        let mut lines = BufReader::new(read);
        let mut line = Vec::new();
        let mut oversized = false;
        loop {
            // A cancelled read may already have filled its bounded prefix. Retire it here
            // before constructing the next Take, so zero remaining bytes is not read as EOF.
            if line.len() > MAX_LINE {
                oversized = !line.ends_with(b"\n");
                line.clear();
            }
            let remaining = (MAX_LINE + 1 - line.len()) as u64;
            tokio::select! {
                cmd = rx.recv() => match cmd {
                    None | Some(Cmd::End) => break,
                    Some(Cmd::Steer { steer, reply }) => {
                        if let Some(call) = self.steer_call(steer, reply) {
                            if write.write_all(call.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Cmd::Answer { request, given }) => {
                        if let Some(call) = self.answer_call(&request, given) {
                            if write.write_all(call.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    }
                },
                n = async { (&mut lines).take(remaining).read_until(b'\n', &mut line).await } => {
                    match n {
                        Ok(0) | Err(_) => break,
                        Ok(_) if line.len() > MAX_LINE || oversized => {
                            oversized = !line.ends_with(b"\n");
                        }
                        Ok(_) => {
                            if let Ok(v) = serde_json::from_slice::<Value>(&line) {
                                self.line(&v).await;
                                if self.failed { break; }
                            }
                        }
                    }
                    line.clear();
                }
            }
        }
        // OpenCode exited, or the session ended: every call waiting is told.
        for (_, (reply, _)) in std::mem::take(&mut self.calls) {
            let _ = reply.send(Err("the OpenCode session's connection closed".into()));
        }
    }

    fn call(
        &mut self,
        mut body: Map<String, Value>,
        reply: oneshot::Sender<Result<String, String>>,
        done: String,
    ) -> String {
        let id = self.next_id;
        self.next_id += 1;
        body.insert("type".into(), json!("call"));
        body.insert("id".into(), json!(id));
        self.calls.insert(id, (reply, done));
        format!("{}\n", Value::Object(body))
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
        Some(self.call(m, reply, done))
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
        // Its result is OpenCode's `permission.replied` / `question.replied`, not this call's.
        let (reply, _) = oneshot::channel();
        Some(self.call(m, reply, String::new()))
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
                let Some((reply, done)) = v
                    .get("id")
                    .and_then(Value::as_u64)
                    .and_then(|id| self.calls.remove(&id))
                else {
                    return;
                };
                let _ = reply.send(if v.get("ok").and_then(Value::as_bool) == Some(true) {
                    Ok(done)
                } else {
                    Err(format!(
                        "OpenCode refused it: {}",
                        v.get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("no reason given")
                    ))
                });
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
                if info.get("id").and_then(Value::as_str)
                    != part.get("messageID").and_then(Value::as_str)
                    || info.get("sessionID").and_then(Value::as_str) != Some(sid.as_str())
                    || !matches!(
                        info.get("role").and_then(Value::as_str),
                        Some("user" | "assistant")
                    )
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
                self.part(&sid, part, info["role"].as_str().expect("checked role"))
                    .await;
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
                    "assistant" => match self
                        .texts
                        .iter_mut()
                        .find(|(of, id, _, _)| of == sid && id == pid)
                    {
                        Some(slot) => {
                            slot.2 = text.to_owned();
                            slot.3 = self
                                .agent
                                .as_ref()
                                .filter(|(of, _)| of == sid)
                                .map(|(_, name)| name.clone());
                        }
                        None => self.texts.push((
                            sid.to_owned(),
                            pid.to_owned(),
                            text.to_owned(),
                            self.agent
                                .as_ref()
                                .filter(|(of, _)| of == sid)
                                .map(|(_, name)| name.clone()),
                        )),
                    },
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
        let Some(rx) = self.sink.request(&self.node, &self.session, entry).await else {
            return;
        };
        self.asks.insert(
            id.clone(),
            Ask {
                of,
                questions,
                answered: None,
                sent: None,
            },
        );
        let tx = self.answers.clone();
        tokio::spawn(async move {
            if let Ok(given) = rx.await {
                let _ = tx.send(Cmd::Answer { request: id, given });
            }
        });
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
