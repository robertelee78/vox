//! ADR-029 §2 SC-1 — **a Claude Code session's activity, as Session entries** (#540).
//!
//! Claude Code runs `vox agent hook` on each of its hook events; this module turns one event's
//! JSON into the entries its Session carries, in the activity format the three harnesses share
//! (one JSON object per entry: `v`, `session`, `kind`, `ts`, `ref`, the sub-agent's `agent` and
//! `agent_id` when one acted, and the kind's own fields). The daemon numbers them and seals them
//! into the Session; nothing here touches the log.
//!
//! ## What each event becomes, read from Claude Code 2.1.292
//!
//! - `UserPromptSubmit` → `user` {text}: what the operator typed at the terminal (the lead's
//!   ruling, 2026-10-06: the Session is how the person follows the session, so it shows what
//!   was asked).
//! - `PreToolUse` → `tool` {tool, summary, input}, `ref` = its `tool_use_id`.
//! - `PostToolUse` → `tool-done` {tool, ok: true, summary, output}; `PostToolUseFailure` →
//!   `tool-done` {ok: false, interrupted, output: its error}. Same `ref`.
//! - `Stop` → `reply` {text: `last_assistant_message`} when there is one, then `turn-end`.
//! - `PermissionRequest` → `approval` or, for `AskUserQuestion`, `question`: built here, posted
//!   by the daemon once it has tied the request to its `tool_use_id` (the event carries none).
//!
//! A sub-agent's events carry the parent's `session_id` with `agent_id` and `agent_type`, so its
//! entries land in the parent's Session, labelled (SE-2). Its completion is the parent's
//! `Agent` tool's `tool-done`, whose output is the sub-agent's result.
//!
//! ## Long content (SC-1)
//!
//! An entry is at most [`MAX_TEXT_LEN`] once serialized. A longer one is cut, on character
//! boundaries and by its **serialized** size (JSON escaping can double a byte), into parts that
//! share `kind` and `ref` and carry `part: [i, n]`; a reader joins them into one Details view.

use serde_json::{json, Map, Value};
use vox_core::node::content::MAX_TEXT_LEN;

/// The format's version.
pub const VERSION: u64 = 1;

/// The longest one-line summary, in characters, before it is cut with "…".
pub const SUMMARY_CHARS: usize = 160;

/// Room left in each part for `"part":[i,n]` and the separators around it.
const PART_ROOM: usize = 48;

/// One event of Claude Code's, as `vox agent hook` read it from stdin.
#[derive(Debug, Clone)]
pub struct Event {
    /// `hook_event_name`.
    pub name: String,
    /// The whole input.
    pub v: Value,
}

impl Event {
    /// The event in `raw`, if `raw` is Claude Code's hook JSON.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let v: Value = serde_json::from_str(raw).ok()?;
        let name = v.get("hook_event_name")?.as_str()?.to_owned();
        Some(Self { name, v })
    }

    fn str(&self, key: &str) -> Option<&str> {
        self.v.get(key).and_then(Value::as_str)
    }

    /// The tool the event is about.
    #[must_use]
    pub fn tool(&self) -> &str {
        self.str("tool_name").unwrap_or_default()
    }

    /// The tool call's id, on the events that carry one.
    #[must_use]
    pub fn tool_use_id(&self) -> Option<&str> {
        self.str("tool_use_id").filter(|s| !s.is_empty())
    }

    /// The sub-agent that acted, if one did.
    #[must_use]
    pub fn agent_id(&self) -> Option<&str> {
        self.str("agent_id").filter(|s| !s.is_empty())
    }

    /// The session's transcript, where Claude Code records what it did.
    #[must_use]
    pub fn transcript(&self) -> Option<&str> {
        self.str("transcript_path").filter(|s| !s.is_empty())
    }

    /// The tool's input, as Claude Code passed it.
    #[must_use]
    pub fn tool_input(&self) -> &Value {
        self.v.get("tool_input").unwrap_or(&Value::Null)
    }

    /// The envelope every entry of this event starts from.
    fn envelope(&self, session: &str, kind: &str, now_ms: u64) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("v".into(), json!(VERSION));
        m.insert("session".into(), json!(session));
        m.insert("kind".into(), json!(kind));
        m.insert("ts".into(), json!(now_ms));
        if let Some(r) = self.tool_use_id() {
            m.insert("ref".into(), json!(r));
        }
        // A sub-agent's entries are labelled with its type, and grouped by its id (SE-2).
        if let Some(id) = self.agent_id() {
            m.insert("agent_id".into(), json!(id));
            if let Some(t) = self.str("agent_type").filter(|s| !s.is_empty()) {
                m.insert("agent".into(), json!(t));
            }
        }
        m
    }

    /// The entries this event puts in the Session, split to fit; empty for an event the Session
    /// does not show. `PermissionRequest` is [`Self::request`]'s.
    #[must_use]
    pub fn entries(&self, session: &str, now_ms: u64) -> Vec<String> {
        let mut out = Vec::new();
        match self.name.as_str() {
            "UserPromptSubmit" => {
                if let Some(p) = self.str("prompt").filter(|p| !p.trim().is_empty()) {
                    let mut m = self.envelope(session, "user", now_ms);
                    m.insert("text".into(), json!(p));
                    out.extend(split(m, "text"));
                }
            }
            "PreToolUse" => {
                let mut m = self.envelope(session, "tool", now_ms);
                m.insert("tool".into(), json!(self.tool()));
                m.insert(
                    "summary".into(),
                    json!(one_line(&input_summary(self.tool(), self.tool_input()))),
                );
                m.insert("input".into(), json!(input_text(self.tool(), self.tool_input())));
                out.extend(split(m, "input"));
            }
            "PostToolUse" => {
                let response = self.v.get("tool_response").unwrap_or(&Value::Null);
                let mut m = self.envelope(session, "tool-done", now_ms);
                m.insert("tool".into(), json!(self.tool()));
                m.insert("ok".into(), json!(true));
                m.insert(
                    "summary".into(),
                    json!(one_line(&output_summary(self.tool(), response))),
                );
                m.insert("output".into(), json!(output_text(self.tool(), response)));
                out.extend(split(m, "output"));
            }
            "PostToolUseFailure" => {
                let error = self.str("error").unwrap_or_default();
                let mut m = self.envelope(session, "tool-done", now_ms);
                m.insert("tool".into(), json!(self.tool()));
                m.insert("ok".into(), json!(false));
                if self.v.get("is_interrupt").and_then(Value::as_bool) == Some(true) {
                    m.insert("interrupted".into(), json!(true));
                }
                m.insert("summary".into(), json!(one_line(error)));
                m.insert("output".into(), json!(error));
                out.extend(split(m, "output"));
            }
            "Stop" => {
                if let Some(text) = self
                    .str("last_assistant_message")
                    .filter(|t| !t.trim().is_empty())
                {
                    let mut m = self.envelope(session, "reply", now_ms);
                    m.insert("text".into(), json!(text));
                    out.extend(split(m, "text"));
                }
                out.extend(split(self.envelope(session, "turn-end", now_ms), ""));
            }
            _ => {}
        }
        out
    }

    /// For `PermissionRequest`: the `approval` (or, for `AskUserQuestion`, `question`) entry,
    /// without its `ref`, which the daemon adds once it has tied the request to its tool call.
    #[must_use]
    pub fn request(&self, session: &str, now_ms: u64) -> Option<Map<String, Value>> {
        if self.name != "PermissionRequest" {
            return None;
        }
        let input = self.tool_input();
        if self.tool() == ASK_USER_QUESTION {
            let mut m = self.envelope(session, "question", now_ms);
            m.insert("questions".into(), Value::Array(questions(input)));
            return Some(m);
        }
        let mut m = self.envelope(session, "approval", now_ms);
        m.insert("tool".into(), json!(self.tool()));
        m.insert(
            "summary".into(),
            json!(one_line(&input_summary(self.tool(), input))),
        );
        m.insert("input".into(), json!(input_text(self.tool(), input)));
        Some(m)
    }
}

/// Claude Code's question tool. Its answers come back through the permission path: an `allow`
/// whose `updatedInput` carries `answers` answers it while the terminal still shows it.
pub const ASK_USER_QUESTION: &str = "AskUserQuestion";

/// `AskUserQuestion`'s questions, in the shared shape: Claude Code gives no id, so `text` is the
/// key its answers are given under.
fn questions(input: &Value) -> Vec<Value> {
    input
        .get("questions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|q| {
            let options: Vec<Value> = q
                .get("options")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|o| {
                    let mut m = Map::new();
                    m.insert("label".into(), o.get("label").cloned().unwrap_or_default());
                    if let Some(d) = o.get("description").filter(|d| d.is_string()) {
                        m.insert("description".into(), d.clone());
                    }
                    Value::Object(m)
                })
                .collect();
            let mut m = Map::new();
            m.insert("text".into(), q.get("question").cloned().unwrap_or_default());
            if let Some(h) = q.get("header").filter(|h| h.is_string()) {
                m.insert("header".into(), h.clone());
            }
            m.insert("options".into(), Value::Array(options));
            m.insert(
                "multi".into(),
                json!(q.get("multiSelect").and_then(Value::as_bool) == Some(true)),
            );
            Value::Object(m)
        })
        .collect()
}

/// What a tool call is about, in words, before it is cut to one line.
fn input_summary(tool: &str, input: &Value) -> String {
    let field = |k: &str| input.get(k).and_then(Value::as_str).map(str::to_owned);
    let named = match tool {
        "Bash" => field("command"),
        "Read" | "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => {
            field("file_path").or_else(|| field("notebook_path"))
        }
        "Glob" | "Grep" => field("pattern").map(|p| match field("path") {
            Some(path) => format!("{p} in {path}"),
            None => p,
        }),
        "WebFetch" => field("url"),
        "WebSearch" => field("query"),
        "Agent" | "Task" => field("description").map(|d| match field("subagent_type") {
            Some(t) => format!("{d} ({t})"),
            None => d,
        }),
        _ => None,
    };
    named.unwrap_or_else(|| compact(input))
}

/// The full input, as Details shows it: a command as the command, anything else as JSON.
fn input_text(tool: &str, input: &Value) -> String {
    match (tool, input.get("command").and_then(Value::as_str)) {
        ("Bash", Some(c)) => c.to_owned(),
        _ => pretty(input),
    }
}

/// What a tool call returned, in words, before it is cut to one line.
fn output_summary(tool: &str, response: &Value) -> String {
    if tool == "Bash" {
        let out = response.get("stdout").and_then(Value::as_str).unwrap_or("");
        let err = response.get("stderr").and_then(Value::as_str).unwrap_or("");
        let first = out
            .lines()
            .chain(err.lines())
            .find(|l| !l.trim().is_empty());
        return first.map_or_else(|| "(no output)".to_owned(), str::to_owned);
    }
    match response {
        Value::String(s) => s.lines().find(|l| !l.trim().is_empty()).unwrap_or("").to_owned(),
        Value::Null => "(no output)".to_owned(),
        other => compact(other),
    }
}

/// The full output, as Details shows it.
fn output_text(tool: &str, response: &Value) -> String {
    if tool == "Bash" {
        let out = response.get("stdout").and_then(Value::as_str).unwrap_or("");
        let err = response.get("stderr").and_then(Value::as_str).unwrap_or("");
        return match (out.is_empty(), err.is_empty()) {
            (_, true) => out.to_owned(),
            (true, false) => err.to_owned(),
            (false, false) => format!("{out}\n{err}"),
        };
    }
    match response {
        Value::String(s) => s.clone(),
        other => pretty(other),
    }
}

fn compact(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

/// `text` on one line: runs of whitespace (newlines included) become one space, and past
/// [`SUMMARY_CHARS`] it is cut with "…".
#[must_use]
pub fn one_line(text: &str) -> String {
    let folded = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if folded.chars().count() <= SUMMARY_CHARS {
        return folded;
    }
    let mut cut: String = folded.chars().take(SUMMARY_CHARS - 1).collect();
    cut.push('…');
    cut
}

/// How many bytes `c` takes inside a JSON string, as serde_json writes it.
fn escaped_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{08}' | '\u{0c}' => 2,
        c if (c as u32) < 0x20 => 6,
        c => c.len_utf8(),
    }
}

/// `m` as entries of at most [`MAX_TEXT_LEN`] bytes each: one when it fits, else parts that cut
/// the string field `big` and carry `part: [i, n]`.
#[must_use]
pub fn split(m: Map<String, Value>, big: &str) -> Vec<String> {
    let whole = Value::Object(m.clone()).to_string();
    if whole.len() <= MAX_TEXT_LEN {
        return vec![whole];
    }
    let Some(text) = m.get(big).and_then(Value::as_str).map(str::to_owned) else {
        // Nothing to cut: the fields other than `big` are bounded (a summary is one line), so
        // this is an entry no harness event produces. Said, not dropped.
        let mut short = m;
        short.insert("summary".into(), json!("(this entry was too large to keep)"));
        return vec![Value::Object(short).to_string()];
    };
    let mut empty = m.clone();
    empty.insert(big.into(), json!(""));
    let budget = MAX_TEXT_LEN
        .saturating_sub(Value::Object(empty).to_string().len() + PART_ROOM)
        .max(1024);
    let mut chunks: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut used = 0;
    for c in text.chars() {
        let n = escaped_len(c);
        if used + n > budget && !cur.is_empty() {
            chunks.push(std::mem::take(&mut cur));
            used = 0;
        }
        cur.push(c);
        used += n;
    }
    chunks.push(cur);
    let n = chunks.len();
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let mut p = m.clone();
            p.insert(big.into(), json!(chunk));
            p.insert("part".into(), json!([i + 1, n]));
            Value::Object(p).to_string()
        })
        .collect()
}
