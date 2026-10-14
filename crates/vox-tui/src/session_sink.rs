//! ADR-029 §2–§3 — **the daemon's Session sink**: where a harness session's activity is numbered
//! and posted to its Session, and where an approval or a question waits for the first answer
//! (#540, #545).
//!
//! Every harness feeds it the same way: Claude Code through `vox agent hook`
//! ([`crate::session_mirror`]), Codex and OpenCode through their adapters. It owns three things.
//!
//! 1. **Order and numbering.** Entries are posted in the order they arrive, each numbered per
//!    (node, session) (`seq`). A split entry's parts arrive together and keep their order.
//! 2. **Open tool calls.** A harness's permission request does not name its tool call (Claude
//!    Code 2.1.292's `PermissionRequest` carries no `tool_use_id`), so each started call is kept
//!    until it ends, and a request is tied to the **one** open call with the same tool, sub-agent
//!    and input. Two or none: the request is shown, marked not answerable from Vox, and the
//!    terminal alone answers it (DR-5: never guess).
//! 3. **Who answered.** A request is retired only by the harness's own record of how it was
//!    settled: the call's `tool_result` in the session's transcript (DR-4). An answer from a
//!    member with drive is handed to the waiting hook, and the harness's first-claim rule decides
//!    between it and the terminal; the transcript then says which took effect. Never the send.
//!
//! **A stated limit.** When the terminal and a member both *allow* within milliseconds, the
//! transcript records "allowed" and not by whom. The outcome is right, and exactly one decision
//! took effect; `by` is then the side whose answer reached the harness first as far as Vox can
//! see: the member, if Vox handed the hook the answer before the result appeared. (The lead
//! accepted this limit, 2026-10-06.)

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Map, Value};
use tokio::sync::oneshot;
use vox_core::node::daemonipc::{NodeName, SessionAdmission, ToolCall};

/// How long text a driver typed into a session is remembered, so the harness's prompt event for
/// it is not also shown as typed at the terminal.
const DELIVERED_FOR: Duration = Duration::from_secs(30);

/// How often a waiting request's transcript is read for its result.
const TRANSCRIPT_POLL: Duration = Duration::from_millis(250);

/// The text Vox's rejection carries to the model, and how the transcript tells it apart from a
/// rejection at the terminal.
pub const REJECTED_IN_VOX: &str = "rejected in Vox by";

/// Internal admission detail: a repeated source receipt must not repeat control side effects.
pub struct Posted {
    /// Existing public outcome; the daemon wire format is unchanged.
    pub admission: SessionAdmission,
    /// A new source activity began, or an unkeyed activity was durably admitted.
    pub fresh: bool,
}

impl From<SessionAdmission> for Posted {
    fn from(admission: SessionAdmission) -> Self {
        Self {
            admission,
            fresh: false,
        }
    }
}

/// Commit a bounded batch into the node's sealed inbox, returning its durable receipt.
pub type Poster = Arc<
    dyn Fn(
            NodeName,
            String,
            vox_core::hash::Digest32,
            Vec<String>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Posted> + Send>>
        + Send
        + Sync,
>;

/// Capture one activity's destination before its bounded parts are admitted.
pub type RoomOf = Arc<dyn Fn(&NodeName, &str) -> Option<vox_core::hash::Digest32> + Send + Sync>;

/// Where a session's new name goes (ADR-029 MD-1): its registration, and its Session's record.
pub type Renamer = Arc<dyn Fn(&NodeName, &str, &str) + Send + Sync>;

/// The sink. One per daemon.
pub struct Sink {
    state: Mutex<BTreeMap<(NodeName, String), Session>>,
    post: Poster,
    room_of: RoomOf,
    rename: Renamer,
}

/// What the sink holds for one session.
#[derive(Default)]
struct Session {
    /// Started tool calls not yet ended.
    open: Vec<ToolCall>,
    /// Requests waiting, by the call they are tied to.
    asks: BTreeMap<String, Ask>,
    /// Text drivers typed into the session lately, and when (see [`Sink::delivered_text`]).
    delivered: Vec<(String, std::time::Instant)>,
    /// Requests settled lately, with what a late answer to each is told.
    settled: std::collections::VecDeque<(String, String)>,
}

/// One approval or question waiting.
struct Ask {
    /// Distinguishes a replacement using the same harness id across an admission await.
    ticket: Arc<()>,
    /// `approval` or `question`.
    of: String,
    /// Who waits for the first answer, until it is handed one or released.
    waiter: Option<Waiter>,
    /// The member whose answer Vox handed over, and what it was.
    given: Option<(String, Given)>,
    /// Where the harness records how the request was settled, for a harness that says so only
    /// there (Claude Code). `None` when its adapter reports it ([`Sink::resolved`]).
    transcript: Option<PathBuf>,
}

/// Who waits for a request's first answer.
enum Waiter {
    /// Claude Code's `PermissionRequest` hook: given the answer in no harness's shape
    /// ([`decision`]), or nothing once the harness settled the request itself.
    Hook(oneshot::Sender<Option<String>>),
    /// An adapter that holds the request itself (Codex, OpenCode): given the answer.
    Adapter(oneshot::Sender<Given>),
}

/// How many settled requests a session remembers, to tell a late answer why it was refused.
const SETTLED_KEPT: usize = 256;
const ASKS_KEPT: usize = 256;

/// An answer a member with drive gave in the Session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Given {
    /// Approve (`true`) or reject an approval, with the reason a rejection gives.
    Approve { allow: bool, why: Option<String> },
    /// Answer a question: question text (or id) → the chosen labels, or free text.
    Answer(BTreeMap<String, String>),
}

/// What became of an answer a member gave: the drive's result (DR-6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handed {
    /// Handed to the harness, which decides; the transcript will say whether it took effect.
    ToHarness,
    /// Not handed: the reason, in words.
    Refused(String),
}

impl Sink {
    /// A sink posting through `post`, and naming a session anew through `rename`.
    #[must_use]
    pub fn new(post: Poster, room_of: RoomOf, rename: Renamer) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(BTreeMap::new()),
            post,
            room_of,
            rename,
        })
    }

    /// The harness renamed `session` (Codex's thread name, OpenCode's session title): its
    /// Session takes the name now, without waiting for its next message (ADR-029 MD-1).
    pub fn renamed(&self, node: &NodeName, session: &str, name: &str) {
        let name = name.trim();
        if !name.is_empty() {
            (self.rename)(node, session, name);
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut BTreeMap<(NodeName, String), Session>) -> R) -> R {
        let mut g = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut g)
    }

    /// Admit bounded batches in order. Numbering belongs to the durable node transaction;
    /// no in-memory counter can claim acceptance before its bodies are saved.
    async fn post_numbered(
        &self,
        node: &NodeName,
        session: &str,
        bodies: Vec<String>,
    ) -> SessionAdmission {
        self.post_numbered_result(node, session, bodies)
            .await
            .admission
    }

    async fn post_numbered_result(
        &self,
        node: &NodeName,
        session: &str,
        bodies: Vec<String>,
    ) -> Posted {
        use vox_core::node::session_ingress::{MAX_BATCH_BYTES, MAX_BATCH_ITEMS};
        let invalid = bodies.iter().find_map(|body| {
            if !serde_json::from_str::<Value>(body).is_ok_and(|v| v.is_object()) {
                Some("Session activity must be a JSON object")
            } else if body.len() > MAX_BATCH_BYTES {
                Some("one Session activity item exceeds the batch bound")
            } else {
                None
            }
        });
        if let Some(why) = invalid {
            return reported(node, session, SessionAdmission::Refused(why.into())).into();
        }
        let Some(room) = (self.room_of)(node, session) else {
            return SessionAdmission::Skipped.into();
        };
        let mut batch = Vec::new();
        let mut bytes = 0usize;
        let mut result = SessionAdmission::Skipped;
        let mut fresh = false;
        for body in bodies {
            if !batch.is_empty()
                && (bytes + body.len() > MAX_BATCH_BYTES || batch.len() == MAX_BATCH_ITEMS)
            {
                let next = (self.post)(
                    node.clone(),
                    session.to_owned(),
                    room,
                    std::mem::take(&mut batch),
                )
                .await;
                fresh |= next.fresh;
                result = combine(result, next.admission);
                if !result.taken() {
                    return Posted {
                        admission: reported(node, session, result),
                        fresh,
                    };
                }
                bytes = 0;
            }
            bytes += body.len();
            batch.push(body);
        }
        if !batch.is_empty() {
            let next = (self.post)(node.clone(), session.to_owned(), room, batch).await;
            fresh |= next.fresh;
            result = combine(result, next.admission);
        }
        Posted {
            admission: reported(node, session, result),
            fresh,
        }
    }

    /// An adapter source has durable deduplication. Only a newly stored activity may settle
    /// current requests; an old user/tool event must not expire a later turn's authority.
    pub async fn source_activity(
        self: &Arc<Self>,
        node: &NodeName,
        session: &str,
        mut bodies: Vec<String>,
        echo: Option<&str>,
    ) -> Posted {
        let Some(first) = bodies
            .first()
            .and_then(|body| serde_json::from_str::<Value>(body).ok())
        else {
            return reported(
                node,
                session,
                SessionAdmission::Refused("invalid source activity".into()),
            )
            .into();
        };
        let valid = first
            .get("_vox_source")
            .and_then(Value::as_object)
            .is_some_and(|source| {
                source.get("parts").and_then(Value::as_u64) == Some(bodies.len() as u64)
                    && !source.contains_key("suppressed")
                    && bodies.iter().enumerate().all(|(index, body)| {
                        serde_json::from_str::<Value>(body).is_ok_and(|value| {
                            value.get("kind") == first.get("kind")
                                && value.pointer("/_vox_source/id") == source.get("id")
                                && value.pointer("/_vox_source/revision") == source.get("revision")
                                && value.pointer("/_vox_source/parts") == source.get("parts")
                                && value.pointer("/_vox_source/part").and_then(Value::as_u64)
                                    == Some(index as u64 + 1)
                                && value.pointer("/_vox_source/suppressed").is_none()
                        })
                    })
            });
        if !valid {
            return reported(
                node,
                session,
                SessionAdmission::Refused("inconsistent source activity parts".into()),
            )
            .into();
        }
        let suppressed = echo.is_some_and(|text| {
            self.delivered_match(node, session, &json!({"kind": "user", "text": text}), false)
        });
        if suppressed {
            for body in &mut bodies {
                let Ok(mut value) = serde_json::from_str::<Value>(body) else {
                    return reported(
                        node,
                        session,
                        SessionAdmission::Refused("invalid source activity".into()),
                    )
                    .into();
                };
                let Some(source) = value.get_mut("_vox_source").and_then(Value::as_object_mut)
                else {
                    return reported(
                        node,
                        session,
                        SessionAdmission::Refused("invalid source identity".into()),
                    )
                    .into();
                };
                source.insert("suppressed".into(), json!(true));
                *body = value.to_string();
            }
        }
        let mut result = self.post_numbered_result(node, session, bodies).await;
        if suppressed && result.fresh {
            if let Some(text) = echo {
                self.delivered_match(node, session, &json!({"kind": "user", "text": text}), true);
            }
            result.fresh = false;
            return result;
        }
        if !result.fresh {
            return result;
        }
        let settled = match first.get("kind").and_then(Value::as_str) {
            Some("user") => self.expired_entries(node, session),
            Some("tool-done") => first
                .get("ref")
                .and_then(Value::as_str)
                .and_then(|id| self.settled_entry(node, session, id).1)
                .into_iter()
                .collect(),
            _ => Vec::new(),
        };
        if !settled.is_empty() {
            result.admission = combine(
                result.admission,
                self.post_numbered(node, session, settled).await,
            );
        }
        result
    }

    /// A harness's activity ([`vox_core::node::daemonipc::DaemonRequest::SessionActivity`]).
    /// `call` is the tool call `bodies` start; a `tool-done` ends the call it names, and a
    /// `turn-end` ends the turn, which retires every request still waiting in it.
    pub async fn activity(
        self: &Arc<Self>,
        node: &NodeName,
        session: &str,
        bodies: Vec<String>,
        call: Option<ToolCall>,
    ) -> SessionAdmission {
        // Source identities have the same deduplication and control semantics at the public
        // ingress seam as at the in-daemon adapter; never pass them through the eager path.
        if bodies.iter().any(|body| {
            serde_json::from_str::<Value>(body)
                .is_ok_and(|value| value.get("_vox_source").is_some())
        }) {
            if call.is_some() {
                return reported(
                    node,
                    session,
                    SessionAdmission::Refused(
                        "source activity cannot replace an open tool call".into(),
                    ),
                );
            }
            let echo = bodies
                .first()
                .and_then(|body| serde_json::from_str::<Value>(body).ok())
                .filter(|value| {
                    value.get("kind").and_then(Value::as_str) == Some("user")
                        && value.get("part").is_none()
                })
                .and_then(|value| value.get("text").and_then(Value::as_str).map(str::to_owned));
            return self
                .source_activity(node, session, bodies, echo.as_deref())
                .await
                .admission;
        }
        if bodies
            .iter()
            .any(|body| !serde_json::from_str::<Value>(body).is_ok_and(|v| v.is_object()))
        {
            return reported(
                node,
                session,
                SessionAdmission::Refused("Session activity must be a JSON object".into()),
            );
        }
        let mut ended: Vec<String> = Vec::new();
        let mut turn_end = false;
        let mut kept = Vec::with_capacity(bodies.len());
        for b in bodies {
            let Ok(v) = serde_json::from_str::<Value>(&b) else {
                continue;
            };
            if self.was_delivered(node, session, &v) {
                continue;
            }
            match v.get("kind").and_then(Value::as_str) {
                Some("tool-done") => {
                    if let Some(r) = v.get("ref").and_then(Value::as_str) {
                        ended.push(r.to_owned());
                    }
                }
                // A new prompt starts a new turn: one interrupted by Esc or Ctrl-C at the terminal
                // fires no Stop (Claude Code 2.1.292, live spike 2026-10-06), so its requests are
                // settled or expired here.
                Some("turn-end" | "user") => turn_end = true,
                _ => {}
            }
            kept.push(b);
        }
        let bodies = kept;
        self.with(|all| {
            let s = all.entry((node.clone(), session.to_owned())).or_default();
            if let Some(c) = call {
                s.open.push(c);
            }
            s.open.retain(|c| !ended.contains(&c.id));
        });
        // Revoke answer authority as soon as the harness reports settlement. Saving its
        // transcript must never keep a stale approval waiter alive.
        let mut bodies = bodies;
        for r in ended {
            let (_, entry) = self.settled_entry(node, session, &r);
            bodies.extend(entry);
        }
        if turn_end {
            bodies.extend(self.expired_entries(node, session));
        }
        self.post_numbered(node, session, bodies).await
    }

    /// A driver's text was delivered to `session` as its input (#544): its `drive` entry already
    /// shows it as typed in Vox by that driver, so the harness's own prompt event for the same
    /// text, if it fires one, is not shown again as typed at the terminal. A limit, stated: the
    /// same text typed at the terminal within 30 s (`DELIVERED_FOR`) is shown once, as typed in Vox.
    pub fn delivered_text(&self, node: &NodeName, session: &str, text: &str) {
        self.with(|all| {
            let s = all.entry((node.clone(), session.to_owned())).or_default();
            s.delivered.retain(|(_, at)| at.elapsed() < DELIVERED_FOR);
            s.delivered
                .push((text.trim().to_owned(), std::time::Instant::now()));
        });
    }

    /// Whether `body` is the harness's prompt event for text a driver delivered; that delivery is
    /// then used up.
    fn was_delivered(&self, node: &NodeName, session: &str, body: &Value) -> bool {
        self.delivered_match(node, session, body, true)
    }

    fn delivered_match(&self, node: &NodeName, session: &str, body: &Value, consume: bool) -> bool {
        if body.get("kind").and_then(Value::as_str) != Some("user") || body.get("part").is_some() {
            return false;
        }
        let Some(text) = body.get("text").and_then(Value::as_str) else {
            return false;
        };
        self.with(|all| {
            let Some(s) = all.get_mut(&(node.clone(), session.to_owned())) else {
                return false;
            };
            s.delivered.retain(|(_, at)| at.elapsed() < DELIVERED_FOR);
            match s.delivered.iter().position(|(t, _)| t == text.trim()) {
                Some(i) => {
                    if consume {
                        s.delivered.remove(i);
                    }
                    true
                }
                None => false,
            }
        })
    }

    /// The session ended (ADR-029 SE-4): every request still waiting expires, and its calls are
    /// forgotten.
    pub async fn session_end(&self, node: &NodeName, session: &str) {
        self.expire_all(node, session).await;
        self.with(|all| all.remove(&(node.clone(), session.to_owned())));
    }

    /// A harness asks ([`vox_core::node::daemonipc::DaemonRequest::SessionAsk`]). Returns what the
    /// hook gives its harness: the first answer a member with drive gave, or `None` once the
    /// harness settled the request itself (or Vox could not tie it to one call).
    pub async fn ask(
        self: &Arc<Self>,
        node: &NodeName,
        session: &str,
        body: String,
        call: ToolCall,
        transcript: String,
    ) -> Option<String> {
        let Ok(Value::Object(mut entry)) = serde_json::from_str::<Value>(&body) else {
            return None;
        };
        let of = entry
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("approval")
            .to_owned();
        let transcript = PathBuf::from(transcript);
        let usable =
            transcript.is_absolute() && transcript.extension().is_some_and(|e| e == "jsonl");
        let (tx, rx) = oneshot::channel();
        let ticket = Arc::new(());
        let tied = self.with(|all| {
            let s = all.entry((node.clone(), session.to_owned())).or_default();
            let matching: Vec<&ToolCall> = s
                .open
                .iter()
                .filter(|c| {
                    c.tool == call.tool
                        && c.agent == call.agent
                        && c.input == call.input
                        && !s.asks.contains_key(&c.id)
                })
                .collect();
            if s.asks.len() >= ASKS_KEPT {
                return Err("Vox has too many pending requests; answer at the terminal");
            }
            match (usable, matching.as_slice()) {
                (false, _) => Err("Vox cannot read where the session records its answers"),
                (true, [one]) => {
                    let id = one.id.clone();
                    s.asks.insert(
                        id.clone(),
                        Ask {
                            ticket: Arc::clone(&ticket),
                            of: of.clone(),
                            waiter: Some(Waiter::Hook(tx)),
                            given: None,
                            transcript: Some(transcript.clone()),
                        },
                    );
                    Ok(id)
                }
                (true, []) => Err("Vox cannot tell which tool call this request is for"),
                (true, _) => {
                    Err("more than one tool call matches this request; Vox does not guess")
                }
            }
        });
        match tied {
            Err(why) => {
                // Shown, so the person knows it is there, but answered only at the terminal.
                entry.insert("answerable".into(), json!(false));
                entry.insert("why".into(), json!(why));
                self.post_numbered(node, session, crate::session_mirror::split(entry, "input"))
                    .await;
                None
            }
            Ok(id) => {
                entry.insert("ref".into(), json!(id));
                let admission = self
                    .post_numbered(node, session, crate::session_mirror::split(entry, "input"))
                    .await;
                if !matches!(
                    admission,
                    SessionAdmission::Committed { .. } | SessionAdmission::Held(_)
                ) {
                    self.with(|all| {
                        if let Some(s) = all.get_mut(&(node.clone(), session.to_owned())) {
                            if s.asks
                                .get(&id)
                                .is_some_and(|ask| Arc::ptr_eq(&ask.ticket, &ticket))
                            {
                                s.asks.remove(&id);
                            }
                        }
                    });
                    return None;
                }
                self.watch(node, session, &id);
                rx.await.ok().flatten()
            }
        }
    }

    /// Read the transcript for `id`'s result until it appears or the request is gone.
    fn watch(self: &Arc<Self>, node: &NodeName, session: &str, id: &str) {
        let me = Arc::clone(self);
        let (node, session, id) = (node.clone(), session.to_owned(), id.to_owned());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(TRANSCRIPT_POLL).await;
                if !me.settle(&node, &session, &id).await {
                    return;
                }
            }
        });
    }

    /// Retire `id`'s request if the transcript records its result. Returns whether it is still
    /// waiting.
    fn settled_entry(&self, node: &NodeName, session: &str, id: &str) -> (bool, Option<String>) {
        let path = self.with(|all| {
            all.get(&(node.clone(), session.to_owned()))
                .and_then(|s| s.asks.get(id))
                .map(|a| a.transcript.clone())
        });
        let Some(path) = path else {
            return (false, None);
        };
        let Some(path) = path else {
            return (true, None);
        };
        let Some(r) = tool_result(&path, id) else {
            return (true, None);
        };
        let outcome = if r.is_error { "denied" } else { "" };
        (
            false,
            self.retired_entry(node, session, id, outcome, r.answers, &r.text),
        )
    }

    async fn settle(&self, node: &NodeName, session: &str, id: &str) -> bool {
        let (waiting, entry) = self.settled_entry(node, session, id);
        if let Some(entry) = entry {
            self.post_numbered(node, session, vec![entry]).await;
        }
        waiting
    }

    /// An adapter's harness settled `id` (Codex `serverRequest/resolved`, OpenCode
    /// `permission.replied` / `question.replied`): `outcome` is `allowed`, `denied` or
    /// `answered`, with the answers that took effect when the harness says them.
    pub async fn resolved(
        &self,
        node: &NodeName,
        session: &str,
        id: &str,
        outcome: &str,
        answers: Option<Value>,
    ) {
        if let Some(entry) = self.retired_entry(node, session, id, outcome, answers, "") {
            self.post_numbered(node, session, vec![entry]).await;
        }
    }

    /// Retire `id`'s request as settled by its harness, post its `resolved` entry, release its
    /// waiter, and remember what a late answer is told. `outcome` empty means "the harness took
    /// it": allowed, or answered for a question. `said` is the harness's own text of a refusal.
    fn retired_entry(
        &self,
        node: &NodeName,
        session: &str,
        id: &str,
        outcome: &str,
        answers: Option<Value>,
        said: &str,
    ) -> Option<String> {
        let ask = self.with(|all| {
            all.get_mut(&(node.clone(), session.to_owned()))
                .and_then(|s| s.asks.remove(id))
        });
        let mut ask = ask?;
        let outcome = match outcome {
            "" if ask.of == "question" => "answered",
            "" => "allowed",
            o => o,
        };
        let by = by_whom(&ask, outcome, answers.as_ref(), said);
        let entry = resolved(session, id, &ask.of, outcome, answers, by.as_deref());
        // The waiter, if still waiting, has nothing to give: the harness has settled it.
        if let Some(Waiter::Hook(h)) = ask.waiter.take() {
            let _ = h.send(None);
        }
        let late = if by.is_some() {
            "already answered in Vox"
        } else {
            "already answered at the terminal"
        };
        self.remember(node, session, id, late);
        Some(entry)
    }

    fn remember(&self, node: &NodeName, session: &str, id: &str, late: &str) {
        self.with(|all| {
            let s = all.entry((node.clone(), session.to_owned())).or_default();
            s.settled.push_back((id.to_owned(), late.to_owned()));
            while s.settled.len() > SETTLED_KEPT {
                s.settled.pop_front();
            }
        });
    }

    /// An adapter holds a request from its harness (Codex, OpenCode): `entry` is its `approval`
    /// or `question` entry, with its `ref` (the harness's request id). It is posted, and the
    /// first answer a member with drive gives arrives on the receiver; once the harness settles
    /// it, the adapter calls [`Sink::resolved`].
    pub async fn request(
        &self,
        node: &NodeName,
        session: &str,
        entry: String,
    ) -> Option<oneshot::Receiver<Given>> {
        let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&entry) else {
            return None;
        };
        let id = m.get("ref").and_then(Value::as_str)?.to_owned();
        let of = m
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("approval")
            .to_owned();
        let (tx, rx) = oneshot::channel();
        let ticket = Arc::new(());
        let installed = self.with(|all| {
            let s = all.entry((node.clone(), session.to_owned())).or_default();
            if s.asks.len() >= ASKS_KEPT || s.asks.contains_key(&id) {
                return false;
            }
            s.asks.insert(
                id.clone(),
                Ask {
                    ticket: Arc::clone(&ticket),
                    of,
                    waiter: Some(Waiter::Adapter(tx)),
                    given: None,
                    transcript: None,
                },
            );
            true
        });
        if !installed {
            return None;
        }
        let admission = self.post_numbered(node, session, vec![entry]).await;
        if !matches!(
            admission,
            SessionAdmission::Committed { .. } | SessionAdmission::Held(_)
        ) {
            self.with(|all| {
                if let Some(s) = all.get_mut(&(node.clone(), session.to_owned())) {
                    if s.asks
                        .get(&id)
                        .is_some_and(|ask| Arc::ptr_eq(&ask.ticket, &ticket))
                    {
                        s.asks.remove(&id);
                    }
                }
            });
            return None;
        }
        Some(rx)
    }

    /// Every request still waiting in `session` expires: the harness moved on without settling it
    /// in its transcript (an interrupted turn, the session's end).
    fn expired_entries(&self, node: &NodeName, session: &str) -> Vec<String> {
        let ids: Vec<_> = self.with(|all| {
            all.get(&(node.clone(), session.to_owned()))
                .map(|s| s.asks.keys().cloned().collect())
                .unwrap_or_default()
        });
        let mut entries = Vec::new();
        for id in ids {
            let (waiting, settled) = self.settled_entry(node, session, &id);
            entries.extend(settled);
            if !waiting {
                continue;
            }
            let ask = self.with(|all| {
                all.get_mut(&(node.clone(), session.to_owned()))
                    .and_then(|s| s.asks.remove(&id))
            });
            if let Some(mut ask) = ask {
                if let Some(Waiter::Hook(h)) = ask.waiter.take() {
                    let _ = h.send(None);
                }
                self.remember(node, session, &id, "the request expired before an answer");
                entries.push(
                    json!({"v": crate::session_mirror::VERSION, "session": session,
                    "kind":"resolved", "ref":id, "of":ask.of, "outcome":"expired"})
                    .to_string(),
                );
            }
        }
        entries
    }

    async fn expire_all(&self, node: &NodeName, session: &str) {
        let entries = self.expired_entries(node, session);
        self.post_numbered(node, session, entries).await;
    }

    /// A member with drive answered `id` in the Session (the drive router calls this once it has
    /// checked drive and the session, DR-2, DR-5). The first answer is handed to the waiting
    /// hook; any later one is refused with the reason.
    pub fn answer(
        &self,
        node: &NodeName,
        session: &str,
        id: &str,
        by: &str,
        alias: &str,
        given: Given,
    ) -> Handed {
        self.with(|all| {
            let Some(s) = all.get_mut(&(node.clone(), session.to_owned())) else {
                return Handed::Refused(NOT_WAITING.into());
            };
            let Some(ask) = s.asks.get_mut(id) else {
                let late = s
                    .settled
                    .iter()
                    .rev()
                    .find(|(r, _)| r == id)
                    .map_or(NOT_WAITING, |(_, why)| why.as_str());
                return Handed::Refused(late.to_owned());
            };
            let Some(waiter) = ask.waiter.take() else {
                return Handed::Refused("another answer was already given".into());
            };
            let sent = match waiter {
                Waiter::Hook(h) => h.send(Some(decision(&given, alias))).is_ok(),
                Waiter::Adapter(a) => a.send(given.clone()).is_ok(),
            };
            if sent {
                ask.given = Some((by.to_owned(), given));
                Handed::ToHarness
            } else {
                Handed::Refused("the session stopped waiting for an answer".into())
            }
        })
    }
}

/// What an answer to a request Vox does not hold is told.
const NOT_WAITING: &str =
    "this request is not waiting for an answer from Vox; answer it at the terminal";

/// The answer handed to the waiting hook, in no harness's shape: `{"allow": bool, "message"?}`
/// for an approval, `{"answers": {question: answer}}` for a question. The hook writes it the way
/// its harness reads it. A rejection's message names the member, which is how the transcript
/// tells Vox's rejection from the terminal's.
fn decision(given: &Given, alias: &str) -> String {
    match given {
        Given::Approve { allow: true, .. } => json!({ "allow": true }),
        Given::Approve { allow: false, why } => json!({
            "allow": false,
            "message": match why {
                Some(w) if !w.trim().is_empty() => format!("{REJECTED_IN_VOX} {alias}: {w}"),
                _ => format!("{REJECTED_IN_VOX} {alias}"),
            },
        }),
        Given::Answer(a) => json!({ "answers": a }),
    }
    .to_string()
}

/// A call's result as the transcript records it.
#[derive(Debug, Clone)]
struct ToolResult {
    is_error: bool,
    text: String,
    /// `toolUseResult.answers`, for a question.
    answers: Option<Value>,
}

/// The `tool_result` for `id` in the transcript at `path`, if it is there yet.
fn tool_result(path: &Path, id: &str) -> Option<ToolResult> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines().rev() {
        if !line.contains(id) {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let content = v
            .pointer("/message/content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten();
        for c in content {
            if c.get("type").and_then(Value::as_str) != Some("tool_result")
                || c.get("tool_use_id").and_then(Value::as_str) != Some(id)
            {
                continue;
            }
            let text = match c.get("content") {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Array(parts)) => parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("\n"),
                _ => String::new(),
            };
            return Some(ToolResult {
                is_error: c.get("is_error").and_then(Value::as_bool) == Some(true),
                text,
                answers: v.pointer("/toolUseResult/answers").cloned(),
            });
        }
    }
    None
}

/// Who settled `ask`, by the harness's own record of it: the member whose answer Vox handed
/// over, when that answer is the one that took effect, else `None`: the terminal.
///
/// A rejection from Vox carries [`REJECTED_IN_VOX`] in the text the harness records (`said`);
/// an adapter's harness reports the outcome alone, so there a rejection matches the member's
/// when the member rejected. An allow from Vox and one from the terminal leave the same record:
/// the member's counts when Vox handed it over before the request was settled (the stated limit
/// in this module's notes).
fn by_whom(ask: &Ask, outcome: &str, answers: Option<&Value>, said: &str) -> Option<String> {
    let (by, given) = ask.given.as_ref()?;
    let took = match (outcome, given) {
        ("denied", Given::Approve { allow: false, .. }) => {
            ask.transcript.is_none() || said.contains(REJECTED_IN_VOX)
        }
        ("allowed", Given::Approve { allow: true, .. }) => true,
        ("answered", Given::Answer(given)) => answers.is_some_and(|a| {
            given
                .iter()
                .all(|(q, ans)| a.get(q).and_then(Value::as_str) == Some(ans.as_str()))
        }),
        _ => false,
    };
    took.then(|| by.clone())
}

/// The `resolved` entry.
fn resolved(
    session: &str,
    id: &str,
    of: &str,
    outcome: &str,
    answers: Option<Value>,
    by: Option<&str>,
) -> String {
    let mut m = Map::new();
    m.insert("v".into(), json!(crate::session_mirror::VERSION));
    m.insert("session".into(), json!(session));
    m.insert("kind".into(), json!("resolved"));
    m.insert("ref".into(), json!(id));
    m.insert("of".into(), json!(of));
    m.insert("outcome".into(), json!(outcome));
    if let Some(a) = answers {
        m.insert("answers".into(), a);
    }
    m.insert("by".into(), json!(by.unwrap_or("terminal")));
    Value::Object(m).to_string()
}

// Every producer gets truthful logging even if it has no replay cursor and cannot retain a
// refused event. Earlier accepted batches are never described as rolled back by a later refusal.
fn reported(node: &NodeName, session: &str, result: SessionAdmission) -> SessionAdmission {
    match &result {
        SessionAdmission::Held(why) => eprintln!("vox daemon: {node}: session {session}: some activity is held only in memory, not saved: {why}"),
        SessionAdmission::Refused(why) => eprintln!("vox daemon: {node}: session {session}: this batch was refused and following activity was not submitted; earlier source receipts still stand: {why}"),
        SessionAdmission::Unconfirmed(why) => eprintln!("vox daemon: {node}: session {session}: acceptance is unknown; do not replay this batch; following unsubmitted activity was not retained: {why}"),
        _ => {}
    }
    result
}

// A split activity is committed only when every constituent batch is committed.
fn combine(before: SessionAdmission, next: SessionAdmission) -> SessionAdmission {
    let prior = match &before {
        SessionAdmission::Committed { first, last } => {
            format!(" Earlier sequences {first} through {last} are committed.")
        }
        SessionAdmission::Held(_) => {
            " Earlier activity was taken, but some remains only in memory.".into()
        }
        _ => String::new(),
    };
    match (before, next) {
        (_, SessionAdmission::Unconfirmed(why)) => {
            SessionAdmission::Unconfirmed(format!("{why}{prior}"))
        }
        (u @ SessionAdmission::Unconfirmed(_), _) => u,
        (_, SessionAdmission::Refused(why)) => SessionAdmission::Refused(format!("{why}{prior}")),
        (r @ SessionAdmission::Refused(_), _) => r,
        (_, h @ SessionAdmission::Held(_)) => h,
        (h @ SessionAdmission::Held(_), _) => h,
        (
            SessionAdmission::Committed { first: a, last: b },
            SessionAdmission::Committed { first: c, last: d },
        ) => SessionAdmission::Committed {
            first: a.min(c),
            last: b.max(d),
        },
        (s, SessionAdmission::Skipped) => s,
        (_, s) => s,
    }
}
