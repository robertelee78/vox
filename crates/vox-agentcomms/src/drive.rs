//! ADR-029 §3 — **the drive protocol**: what a member with drive sends a session's node, and what
//! it answers (#544). One request line and one answer line, JSON, on an ADR-022 app stream
//! speaking [`LABEL`] from the driver's node to the session's node, in the Session's room.
//! Shared by the CLI, the TUI and the app, so none holds a copy of its own.

use serde::{Deserialize, Serialize};

/// The app-stream label a node listens for drive input on.
pub const LABEL: &str = "vox-drive/v1";

/// The longest request line: typed text up to the log's text limit, with room for the rest.
pub const MAX_REQUEST: usize = 80 * 1024;

/// How long the session's node waits for the request line, and the driver for the answer. The
/// harness's own delivery (Claude Code's pane polling) is inside it.
pub const PATIENCE: std::time::Duration = std::time::Duration::from_secs(20);

/// What a driver asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// The protocol's version: 1.
    pub v: u64,
    /// The harness's session id, whole.
    pub session: String,
    /// The input.
    #[serde(flatten)]
    pub action: Action,
}

/// One input (DR-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum Action {
    /// Typed as the operator's input (DR-1.2).
    Text {
        /// What is typed.
        text: String,
    },
    /// Esc (DR-1.3).
    Interrupt,
    /// Ctrl-C (DR-1.3).
    Stop,
    /// A slash command (DR-1.6): `/compact`, `/clear`, `/rename <name>`.
    Slash {
        /// The command and its arguments, as typed.
        text: String,
    },
    /// Approve a tool call (DR-1.4).
    Approve {
        /// The request's `ref`.
        r#ref: String,
    },
    /// Reject a tool call (DR-1.4), with the reason the model is given.
    Reject {
        /// The request's `ref`.
        r#ref: String,
        /// Why, for the model.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        why: Option<String>,
    },
    /// Answer a question (DR-1.5): question (its id, or its text) → the answer.
    Answer {
        /// The request's `ref`.
        r#ref: String,
        /// Each question's answer.
        answers: std::collections::BTreeMap<String, String>,
    },
    /// Send the session a file (DR-1.7, #546). Its bytes do not travel here: the driver's node
    /// serves them as a share only the session's node may fetch, once, on `tag`.
    File {
        /// Its name.
        name: String,
        /// Its size, bytes.
        size: u64,
        /// Its SHA-256, hex: what the session's node checks before it keeps it.
        sha256: String,
        /// The driver's service it is served on: also what pairs its two outcomes (`of`).
        tag: String,
        /// A note the session is told with it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
}

impl Action {
    /// The action's name, as the Session's `drive` entry says it.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Action::Text { .. } => "text",
            Action::Interrupt => "interrupt",
            Action::Stop => "stop",
            Action::Slash { .. } => "slash",
            Action::Approve { .. } => "approve",
            Action::Reject { .. } => "reject",
            Action::Answer { .. } => "answer",
            Action::File { .. } => "file",
        }
    }
}

/// What the session's node answers: delivered, in words, or refused, and why (DR-6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    /// Whether the input reached the session.
    pub ok: bool,
    /// What happened, or why not.
    pub said: String,
    /// Why not, when the driver words it itself: [`NO_DRIVE`]. The session's node knows itself
    /// only by its own name, which the driver may not; the driver names it as it knows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// The session's node does not trust the driver with drive (DR-2).
pub const NO_DRIVE: &str = "no-drive";

/// What a driver reads for [`NO_DRIVE`], `node` being its own name for the session's node: its
/// alias for it, or its short fingerprint.
#[must_use]
pub fn no_drive(node: &str) -> String {
    format!("{node} does not trust you with drive; it trusts you to read only, or not at all")
}

impl Answer {
    /// What the driver reads, naming the session's node as `node`.
    #[must_use]
    pub fn said_to(&self, node: &str) -> String {
        match self.code.as_deref() {
            Some(NO_DRIVE) => no_drive(node),
            _ => self.said.clone(),
        }
    }
}

/// A slash command as typed, `/rename new name`, split into its name and arguments.
#[must_use]
pub fn slash(text: &str) -> (String, String) {
    let t = text.trim().trim_start_matches('/');
    match t.split_once(char::is_whitespace) {
        Some((c, a)) => (c.to_owned(), a.trim().to_owned()),
        None => (t.to_owned(), String::new()),
    }
}
