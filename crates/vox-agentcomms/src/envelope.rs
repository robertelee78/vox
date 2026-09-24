//! The agent-comms message envelope (ADR-020 §4).

use serde::{Deserialize, Serialize};

/// Envelope version this build writes.
pub const VERSION: u64 = 1;

/// Reserved: a session announcing itself, with the card the roster is built from.
pub const HELLO: &str = "hello";
/// Reserved: a session leaving.
pub const BYE: &str = "bye";
/// Reserved: plain text from a human. Text with no envelope at all **is** a `say`.
pub const SAY: &str = "say";

/// Default hop budget, decremented on every relay and dropped at zero.
///
/// 8, following ruflo's ADR-097, whose own note is the argument: the default
/// "alone closes the recursion-loop class", legitimate chains are typically ≤ 3,
/// and a hard cap is the only loop guard that provably terminates. A flag saying
/// "do not auto-reply" is not enough on its own — Matrix has `m.notice` and
/// agents looped there anyway.
pub const DEFAULT_HOPS: u32 = 8;

/// Longest petname accepted in [`Envelope::to`], matching the keyring's bound.
pub const MAX_NAME: usize = 64;

/// The data key naming the work item a message is about (ADR-021 §2). Its **shape** is
/// checked ([`is_valid_work`]); its meaning never is — carried, compared byte for byte
/// and filtered by, never interpreted, never looked up in any tracker.
pub const WORK_KEY: &str = "work";

/// Longest id after the scheme in a work reference.
pub const MAX_WORK_ID: usize = 112;

/// Whether `s` is a work reference: `<scheme>:<id>`, the scheme matching
/// `[a-z][a-z0-9-]{0,15}` and the id `[A-Za-z0-9._~/#:-]{1,112}` (ADR-021 §3).
///
/// The id may itself contain `:`, so a tracker whose keys are colon-separated (for
/// example `OWNER/REPO:SOURCE:ITEM`) carries them unchanged; the scheme is everything
/// before the **first** colon.
#[must_use]
pub fn is_valid_work(s: &str) -> bool {
    let Some((scheme, id)) = s.split_once(':') else {
        return false;
    };
    let mut sb = scheme.bytes();
    let scheme_ok = matches!(sb.next(), Some(b'a'..=b'z'))
        && scheme.len() <= 16
        && sb.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'));
    let id_ok = !id.is_empty()
        && id.len() <= MAX_WORK_ID
        && id.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'/' | b'#' | b':' | b'-')
        });
    scheme_ok && id_ok
}

/// The suggested work vocabulary, shipped as convention rather than enforced.
///
/// Shaped to map onto A2A's `TaskState` so a bridge is mechanical later. Nothing
/// in this crate requires an agent to use these — an unknown type is carried
/// unchanged — but a room whose agents agree on them gets a board view for free.
pub mod work {
    /// Offer a unit of work to someone.
    pub const ASSIGN: &str = "assign";
    /// Take it.
    pub const ACCEPT: &str = "accept";
    /// Refuse it.
    pub const DECLINE: &str = "decline";
    /// In progress.
    pub const WORKING: &str = "working";
    /// Stuck, and why. A Health observation for a tracker — never a Work phase.
    pub const BLOCKED: &str = "blocked";
    /// A progress note. Supersedes the same `(author, from, data.work)`'s previous
    /// `status` in any rendering; it changes no state (ADR-020 §9, ADR-021 §3).
    pub const STATUS: &str = "status";
    /// A candidate exists, and the sender **asserts** it meets the item's criteria.
    /// An assertion, not an acceptance verdict (ADR-021 §3).
    pub const RESULT: &str = "result";
    /// This attempt ended without success. The work item stays retryable.
    pub const FAILED: &str = "failed";
    /// A question put to someone.
    pub const ASK: &str = "ask";
    /// Its answer.
    pub const ANSWER: &str = "answer";
    /// Acknowledgement. A terminal ack MUST NOT beget another.
    pub const ACK: &str = "ack";
    /// The mandatory fallback: addressed, understood as a message, not actionable.
    pub const NOT_UNDERSTOOD: &str = "not-understood";
}

/// Where a session is working. Volatile, so it rides **every** message.
///
/// Host and harness are deliberately absent: they are proven by the signing key
/// (ADR-020 §2, identity is per `(host, harness)`), and repeating them here would
/// create a claim that can contradict a proof. What changes mid-session — and
/// what makes a planning message meaningful under a branch-per-item workflow —
/// is this.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    /// Repository root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// The worktree, which is not the repo when several are checked out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree: Option<String>,
    /// Current branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

/// One agent-comms message, carried as JSON in a log entry's text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Envelope version.
    pub v: u64,
    /// The sending **session**'s name. The author key is already signed by the
    /// log, so this says *which session* under that identity spoke.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub from: String,
    /// Where that session is working.
    #[serde(default, skip_serializing_if = "is_default_context")]
    pub at: Context,
    /// Petnames addressed. **Empty addresses the room.**
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<String>,
    /// The message type. `hello`, `bye` and `say` are reserved; anything else is
    /// an application's own and is carried unchanged.
    #[serde(rename = "type")]
    pub kind: String,
    /// Whether this may interrupt a recipient that is mid-task. Declared by the
    /// sender, never inferred from [`Envelope::kind`].
    #[serde(default, skip_serializing_if = "is_false")]
    pub urgent: bool,
    /// The entry hash of the message this replies to, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub re: Option<String>,
    /// The entry hash of the conversation root, hex. Distinct from
    /// [`Envelope::re`]: one correlates a reply, the other names the thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    /// Remaining hop budget.
    #[serde(default = "default_hops")]
    pub hops: u32,
    /// Markdown, for a human reading the room.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body: String,
    /// Application payload, opaque here.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub data: serde_json::Value,
}

fn default_hops() -> u32 {
    DEFAULT_HOPS
}

// `serde`'s `skip_serializing_if` takes `fn(&T) -> bool`, so the reference is the
// signature serde requires, not a choice.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

fn is_default_context(c: &Context) -> bool {
    *c == Context::default()
}

/// Why a message could not be read as an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Valid JSON, but not an envelope this build understands.
    NotAnEnvelope,
    /// An envelope from a newer format version.
    UnsupportedVersion(u64),
    /// A field is present but unusable (an over-long petname, an empty type).
    Malformed(&'static str),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::NotAnEnvelope => write!(f, "not an agent-comms envelope"),
            ParseError::UnsupportedVersion(v) => write!(f, "unsupported envelope version {v}"),
            ParseError::Malformed(what) => write!(f, "malformed envelope: {what}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl Envelope {
    /// A plain message of `kind` with `body`.
    #[must_use]
    pub fn new(kind: &str, body: &str) -> Self {
        Self {
            v: VERSION,
            from: String::new(),
            at: Context::default(),
            to: Vec::new(),
            kind: kind.to_owned(),
            urgent: false,
            re: None,
            thread: None,
            hops: DEFAULT_HOPS,
            body: body.to_owned(),
            data: serde_json::Value::Null,
        }
    }

    /// What a human typing into the room produces.
    #[must_use]
    pub fn say(body: &str) -> Self {
        Self::new(SAY, body)
    }

    /// Address this message to `names`.
    #[must_use]
    pub fn addressed_to(mut self, names: &[&str]) -> Self {
        self.to = names.iter().map(|n| (*n).to_owned()).collect();
        self
    }

    /// Mark it as able to interrupt.
    #[must_use]
    pub fn urgent(mut self) -> Self {
        self.urgent = true;
        self
    }

    /// Read a log entry's text as an envelope.
    ///
    /// **Text that is not JSON is a [`SAY`]**, not an error: a human types prose
    /// into the room and it is a message like any other. That is what lets the
    /// operator share a room with agents without learning a format.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnsupportedVersion`] for an envelope from a newer build —
    /// refused rather than guessed at. [`ParseError::NotAnEnvelope`] for JSON that
    /// claims a `type` but cannot be read as one, and [`ParseError::Malformed`]
    /// for a field this crate polices (an empty or over-long type, an addressee
    /// name of unusable length).
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let trimmed = text.trim_start();
        if !trimmed.starts_with('{') {
            return Ok(Self::say(text));
        }
        let value: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|_| ParseError::NotAnEnvelope)?;
        // A JSON object that is not an envelope is also prose as far as this room
        // is concerned — an agent may legitimately paste JSON into a `say`.
        if value.get("type").is_none() {
            return Ok(Self::say(text));
        }
        if let Some(v) = value.get("v").and_then(serde_json::Value::as_u64) {
            if v > VERSION {
                return Err(ParseError::UnsupportedVersion(v));
            }
        }
        let env: Self = serde_json::from_value(value).map_err(|_| ParseError::NotAnEnvelope)?;
        env.validate()?;
        Ok(env)
    }

    /// Check the fields this crate is entitled to police.
    fn validate(&self) -> Result<(), ParseError> {
        if self.kind.is_empty() {
            return Err(ParseError::Malformed("empty type"));
        }
        if self.kind.len() > MAX_NAME {
            return Err(ParseError::Malformed("type too long"));
        }
        if self.to.iter().any(|n| n.is_empty() || n.len() > MAX_NAME) {
            return Err(ParseError::Malformed("addressee name length"));
        }
        Ok(())
    }

    /// Render for a log entry's text.
    ///
    /// A bare [`SAY`] with no addressing, no payload and no thread is written as
    /// **plain text**, so a room stays readable to a human and to `grep`. An
    /// envelope is only spent where it carries something.
    #[must_use]
    pub fn to_text(&self) -> String {
        if self.is_bare_say() {
            return self.body.clone();
        }
        serde_json::to_string(self).unwrap_or_else(|_| self.body.clone())
    }

    fn is_bare_say(&self) -> bool {
        self.kind == SAY
            && self.to.is_empty()
            && !self.urgent
            && self.re.is_none()
            && self.thread.is_none()
            && self.data.is_null()
            && self.from.is_empty()
            && self.at == Context::default()
            && !self.body.trim_start().starts_with('{')
    }

    /// Whether this message names `me`.
    #[must_use]
    pub fn is_addressed_to(&self, me: &str) -> bool {
        self.to.iter().any(|n| n == me)
    }

    /// Whether this message is to the room rather than to anyone in particular.
    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        self.to.is_empty()
    }

    /// Whether this may interrupt `me` mid-task.
    ///
    /// Addressed **and** urgent — both, deliberately. An urgent broadcast does not
    /// interrupt anybody: if it were allowed to, one agent could stop the whole
    /// room, which is the wall-of-noise failure this design exists to avoid.
    #[must_use]
    pub fn may_interrupt(&self, me: &str) -> bool {
        self.urgent && self.is_addressed_to(me)
    }

    /// Whether `me` may answer this without being asked (ADR-020 §9).
    ///
    /// Only when addressed. A broadcast is read, not answered — otherwise every
    /// agent answers every message and the room is unusable with more than two.
    /// `hello`, `bye`, `ack` and `not-understood` are never auto-answered even
    /// when addressed: a terminal acknowledgement must not beget another, which is
    /// the acknowledgement loop other systems hit.
    #[must_use]
    pub fn may_auto_reply(&self, me: &str) -> bool {
        if !self.is_addressed_to(me) {
            return false;
        }
        !matches!(
            self.kind.as_str(),
            HELLO | BYE | work::ACK | work::NOT_UNDERSTOOD
        )
    }

    /// This message as relayed one hop further, or `None` once the budget is out.
    ///
    /// `None` means **drop it**, not "send it anyway": the cap is the only loop
    /// guard that provably terminates.
    #[must_use]
    pub fn relayed(&self) -> Option<Self> {
        if self.hops == 0 {
            return None;
        }
        let mut next = self.clone();
        next.hops -= 1;
        Some(next)
    }
}
