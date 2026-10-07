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
use vox_core::node::daemonipc::{NodeName, ToolCall};

/// How long text a driver typed into a session is remembered, so the harness's prompt event for
/// it is not also shown as typed at the terminal.
const DELIVERED_FOR: Duration = Duration::from_secs(30);

/// How often a waiting request's transcript is read for its result.
const TRANSCRIPT_POLL: Duration = Duration::from_millis(250);

/// The text Vox's rejection carries to the model, and how the transcript tells it apart from a
/// rejection at the terminal.
pub const REJECTED_IN_VOX: &str = "rejected in Vox by";

/// Where entries go once numbered: the node's Session append (reads2's `AppendSession`).
pub type Poster = Arc<dyn Fn(&NodeName, &str, Vec<String>) + Send + Sync>;

/// The sink. One per daemon.
pub struct Sink {
    state: Mutex<BTreeMap<(NodeName, String), Session>>,
    post: Poster,
}

/// What the sink holds for one session.
#[derive(Default)]
struct Session {
    seq: u64,
    /// Started tool calls not yet ended.
    open: Vec<ToolCall>,
    /// Requests waiting, by the call they are tied to.
    asks: BTreeMap<String, Ask>,
    /// Text drivers typed into the session lately, and when (see [`Sink::delivered_text`]).
    delivered: Vec<(String, std::time::Instant)>,
}

/// One approval or question waiting.
struct Ask {
    /// `approval` or `question`.
    of: String,
    /// The waiting hook, until it is handed an answer or released.
    hook: Option<oneshot::Sender<Option<String>>>,
    /// The member whose answer Vox handed the hook, and what it was.
    given: Option<(String, Given)>,
    transcript: PathBuf,
}

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
    /// A sink posting through `post`.
    #[must_use]
    pub fn new(post: Poster) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(BTreeMap::new()),
            post,
        })
    }

    fn with<R>(&self, f: impl FnOnce(&mut BTreeMap<(NodeName, String), Session>) -> R) -> R {
        let mut g = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut g)
    }

    /// Number `bodies` and post them, in order. A body that is not a JSON object is dropped:
    /// only the shared format reaches a Session.
    fn post_numbered(&self, node: &NodeName, session: &str, bodies: Vec<String>) {
        let numbered = self.with(|all| {
            let s = all.entry((node.clone(), session.to_owned())).or_default();
            bodies
                .into_iter()
                .filter_map(|b| {
                    let Ok(Value::Object(mut m)) = serde_json::from_str::<Value>(&b) else {
                        return None;
                    };
                    s.seq += 1;
                    m.insert("seq".into(), json!(s.seq));
                    Some(Value::Object(m).to_string())
                })
                .collect::<Vec<_>>()
        });
        if !numbered.is_empty() {
            (self.post)(node, session, numbered);
        }
    }

    /// A harness's activity ([`vox_core::node::daemonipc::DaemonRequest::SessionActivity`]).
    /// `call` is the tool call `bodies` start; a `tool-done` ends the call it names, and a
    /// `turn-end` ends the turn, which retires every request still waiting in it.
    pub fn activity(
        self: &Arc<Self>,
        node: &NodeName,
        session: &str,
        bodies: Vec<String>,
        call: Option<ToolCall>,
    ) {
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
                Some("turn-end") => turn_end = true,
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
        self.post_numbered(node, session, bodies);
        // A call that ended settles its request: read the transcript now rather than at the next
        // poll, so the request is retired beside the call's result.
        for r in ended {
            self.settle(node, session, &r);
        }
        if turn_end {
            self.expire_all(node, session);
        }
    }

    /// A driver's text was delivered to `session` as its input (#544): its `drive` entry already
    /// shows it as typed in Vox by that driver, so the harness's own prompt event for the same
    /// text, if it fires one, is not shown again as typed at the terminal. A limit, stated: the
    /// same text typed at the terminal within [`DELIVERED_FOR`] is shown once, as typed in Vox.
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
                    s.delivered.remove(i);
                    true
                }
                None => false,
            }
        })
    }

    /// The session ended (ADR-029 SE-4): every request still waiting expires, and its calls are
    /// forgotten.
    pub fn session_end(&self, node: &NodeName, session: &str) {
        self.expire_all(node, session);
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
            match (usable, matching.as_slice()) {
                (false, _) => Err("Vox cannot read where the session records its answers"),
                (true, [one]) => {
                    let id = one.id.clone();
                    s.asks.insert(
                        id.clone(),
                        Ask {
                            of: of.clone(),
                            hook: Some(tx),
                            given: None,
                            transcript: transcript.clone(),
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
                self.post_numbered(node, session, vec![Value::Object(entry).to_string()]);
                None
            }
            Ok(id) => {
                entry.insert("ref".into(), json!(id));
                self.post_numbered(node, session, vec![Value::Object(entry).to_string()]);
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
                if !me.settle(&node, &session, &id) {
                    return;
                }
            }
        });
    }

    /// Retire `id`'s request if the transcript records its result. Returns whether it is still
    /// waiting.
    fn settle(&self, node: &NodeName, session: &str, id: &str) -> bool {
        let path = self.with(|all| {
            all.get(&(node.clone(), session.to_owned()))
                .and_then(|s| s.asks.get(id))
                .map(|a| a.transcript.clone())
        });
        let Some(path) = path else {
            return false;
        };
        let Some(result) = tool_result(&path, id) else {
            return true;
        };
        let ask = self.with(|all| {
            all.get_mut(&(node.clone(), session.to_owned()))
                .and_then(|s| s.asks.remove(id))
        });
        let Some(mut ask) = ask else {
            return false;
        };
        let entry = resolved(session, id, &ask, &result);
        // The hook, if still waiting, has nothing to give: the harness has settled it.
        if let Some(h) = ask.hook.take() {
            let _ = h.send(None);
        }
        self.post_numbered(node, session, vec![entry]);
        false
    }

    /// Every request still waiting in `session` expires: the harness moved on without settling it
    /// in its transcript (an interrupted turn, the session's end).
    fn expire_all(&self, node: &NodeName, session: &str) {
        let ids: Vec<String> = self.with(|all| {
            all.get(&(node.clone(), session.to_owned()))
                .map(|s| s.asks.keys().cloned().collect())
                .unwrap_or_default()
        });
        for id in ids {
            // A result written just before the turn ended is still the answer.
            if !self.settle(node, session, &id) {
                continue;
            }
            let ask = self.with(|all| {
                all.get_mut(&(node.clone(), session.to_owned()))
                    .and_then(|s| s.asks.remove(&id))
            });
            if let Some(mut ask) = ask {
                if let Some(h) = ask.hook.take() {
                    let _ = h.send(None);
                }
                let e = json!({
                    "v": crate::session_mirror::VERSION, "session": session, "kind": "resolved",
                    "ref": id, "of": ask.of, "outcome": "expired",
                });
                self.post_numbered(node, session, vec![e.to_string()]);
            }
        }
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
            let Some(ask) = all
                .get_mut(&(node.clone(), session.to_owned()))
                .and_then(|s| s.asks.get_mut(id))
            else {
                return Handed::Refused(
                    "this request is not waiting for an answer from Vox; answer it at the terminal"
                        .into(),
                );
            };
            let Some(hook) = ask.hook.take() else {
                return Handed::Refused("another answer was already given".into());
            };
            let out = decision(&given, alias);
            match hook.send(Some(out)) {
                Ok(()) => {
                    ask.given = Some((by.to_owned(), given));
                    Handed::ToHarness
                }
                Err(_) => Handed::Refused("the session stopped waiting for an answer".into()),
            }
        })
    }
}

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

/// The `resolved` entry for `ask`, from the harness's record of it.
fn resolved(session: &str, id: &str, ask: &Ask, r: &ToolResult) -> String {
    let given_by = ask.given.as_ref().map(|(by, _)| by.clone());
    let (outcome, by) = if r.is_error {
        // Only Vox's rejection carries its words; any other refusal was the terminal's.
        let vox = r.text.contains(REJECTED_IN_VOX)
            && matches!(ask.given, Some((_, Given::Approve { allow: false, .. })));
        ("denied", if vox { given_by } else { None })
    } else {
        let outcome = if ask.of == "question" {
            "answered"
        } else {
            "allowed"
        };
        // An allow from Vox and one from the terminal leave the same record; the member's counts
        // when Vox handed it over before the result appeared (the stated limit above).
        let vox = match &ask.given {
            Some((_, Given::Approve { allow: true, .. })) => true,
            Some((_, Given::Answer(given))) => r.answers.as_ref().is_some_and(|a| {
                given
                    .iter()
                    .all(|(q, ans)| a.get(q).and_then(Value::as_str) == Some(ans.as_str()))
            }),
            _ => false,
        };
        (outcome, if vox { given_by } else { None })
    };
    let mut m = Map::new();
    m.insert("v".into(), json!(crate::session_mirror::VERSION));
    m.insert("session".into(), json!(session));
    m.insert("kind".into(), json!("resolved"));
    m.insert("ref".into(), json!(id));
    m.insert("of".into(), json!(ask.of));
    m.insert("outcome".into(), json!(outcome));
    if let Some(a) = &r.answers {
        m.insert("answers".into(), a.clone());
    }
    m.insert("by".into(), json!(by.unwrap_or_else(|| "terminal".into())));
    Value::Object(m).to_string()
}
