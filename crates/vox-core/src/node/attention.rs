//! Bounded, private observations of room attention (ADR-020 RA-7/RA-8).
//! Transport acceptance is not a context receipt or an answer.

pub(crate) mod ledger;
mod transport;
pub use transport::{local, page_checked, OwnRequest};

use crate::hash::Digest32;
use serde::{Deserialize, Serialize};

/// Private app-stream query, guarded by the existing room and drive authority.
pub const LABEL: &str = "vox-attention/v1";
/// Maximum records inspected by one attention operation.
pub const PAGE_SIZE: usize = 64;
/// Maximum encoded private page or request.
pub const MAX_BYTES: usize = 128 * 1024;
/// The hook's existing maximum number of attributed messages in one output.
pub const MAX_RECEIPT_SOURCES: usize = 50;

/// Exact sources reserved for one native input. Metadata alone grants no authority:
/// every source must still match this binding in the sealed ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputReceipt {
    /// Exact selected recipient incarnation.
    pub recipient: Recipient,
    /// Domain-separated native input identity, not a content hash.
    pub input: Digest32,
    /// The hook's pre-output reservation.
    pub ticket: [u8; 16],
    /// At most six exact prepared sources in this descriptor.
    pub sources: Vec<Digest32>,
}

/// A running OpenCode step and the receipts on its authoritative parent input.
/// The authenticated mirror resolves both messages before constructing this value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputObservation {
    /// Exact native Session, never a descendant mapped to its owner.
    pub session: String,
    /// Authoritative user message id.
    pub input: String,
    /// Authoritative assistant message whose parent is `input`.
    pub assistant: String,
    /// Actual step-start part in that assistant message.
    pub step: String,
    /// Compact descriptors; no transcript bodies.
    pub receipts: Vec<InputReceipt>,
}

/// Bind a native input to its exact OpenCode Session using bounded opaque ids.
///
/// # Errors
/// Either identifier is empty, too long or contains a control character.
pub fn opencode_input(session: &str, input: &str) -> Result<Digest32, String> {
    let valid = |id: &str| {
        !id.is_empty()
            && id.len() <= crate::node::content::MAX_SESSION_ID_LEN
            && !id.chars().any(char::is_control)
    };
    if !valid(session) || !valid(input) {
        return Err("invalid OpenCode attention input identity".into());
    }
    Ok(crate::hash::sha256_concat(&[
        b"vox/attention/opencode-input/v1\0",
        session.as_bytes(),
        b"\0",
        input.as_bytes(),
    ]))
}

impl InputObservation {
    /// Validate the bounded association before any owned mutation.
    ///
    /// # Errors
    /// Identities, digest, descriptor shape or aggregate bounds do not agree.
    pub fn validate(&self) -> Result<(), String> {
        let input = opencode_input(&self.session, &self.input)?;
        opencode_input(&self.session, &self.assistant)?;
        opencode_input(&self.session, &self.step)?;
        if self.receipts.is_empty()
            || self.receipts.len() > MAX_RECEIPT_SOURCES
            || self.receipts.iter().map(|r| r.sources.len()).sum::<usize>() > MAX_RECEIPT_SOURCES
            || self.receipts.iter().any(|r| {
                r.input != input
                    || r.recipient.session != self.session
                    || r.recipient.validate().is_err()
                    || r.sources.is_empty()
                    || r.sources.len() > 6
            })
        {
            return Err("invalid OpenCode attention receipt association".into());
        }
        Ok(())
    }
}

/// An exact local Session incarnation in one saved room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    /// Room identity.
    pub room: Digest32,
    /// Receiver-local saved room incarnation.
    pub instance: [u8; 16],
    /// Complete harness Session id.
    pub session: String,
    /// Authenticated Session opening, never a replacement Session.
    pub opening: Digest32,
    /// Local original opening identity, retained across metadata refresh copies.
    pub identity: Digest32,
}
impl Recipient {
    pub(crate) fn key(&self) -> Digest32 {
        Self::selection_key(self.room, self.instance, &self.session, self.identity)
    }
    pub(crate) fn selection_key(
        room: Digest32,
        instance: [u8; 16],
        session: &str,
        opening: Digest32,
    ) -> Digest32 {
        crate::hash::sha256_concat(&[
            b"vox/attention/recipient/v1",
            &room,
            &instance,
            session.as_bytes(),
            &opening,
        ])
    }
    pub(crate) fn validate(&self) -> crate::error::Result<()> {
        if self.session.is_empty()
            || self.session.len() > crate::node::content::MAX_SESSION_ID_LEN
            || self.session.chars().any(char::is_control)
        {
            return Err(crate::error::Error::Profile("invalid attention Session"));
        }
        Ok(())
    }
}

/// Observations, not promises of model execution or relevance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// The source remains owed to the exact recipient.
    Queued,
    /// The attributed context was emitted by that Session's hook.
    Delivered,
    /// A running harness turn was observed consuming that receipt.
    Answering,
    /// The recipient posted its correlated answer.
    Answered,
    /// Delivery is no longer possible, or its adapter is unavailable.
    Unavailable,
}

/// Why queued attention has not been delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Wait {
    /// Room pause holds news and its cursor.
    Paused,
    /// Codex receives news only on its next ordinary hook turn.
    NextCodexTurn,
    /// Resume does not autonomously wake for older ordinary news.
    NextTurnAfterResume,
    /// The adapter cannot establish exact live-conversation admission.
    AdapterUnavailable,
    /// Input may have been accepted; only a receipt/reconciliation can resolve it.
    Unknown,
}

/// Current observation for one source and the selected private recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    /// Durable room source entry.
    pub source: Digest32,
    /// Receiver arrival position of that source.
    pub arrival: u64,
    /// Explicit source urgency; resume's ordinary cutoff does not suppress addressed urgency.
    pub urgent: bool,
    /// Most recent proven observation.
    pub state: State,
    /// Explicit wait or uncertainty, when present.
    pub wait: Option<Wait>,
    /// Receiver time of the observation.
    pub at_millis: u64,
    /// Exact correlated answer, when observed.
    pub answer: Option<Digest32>,
    /// Bounded explanation of an unavailable adapter/source.
    pub reason: Option<String>,
}

/// A cursor cannot cross room, Session incarnation or publication revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// Saved room incarnation.
    pub instance: [u8; 16],
    /// Bound recipient digest.
    pub recipient: Digest32,
    /// Current sealed attention revision.
    pub revision: u64,
    /// Last examined ordinal, not an offset into a collected history.
    pub after: u64,
}

/// One bounded page, visible only to the node or a current drive-authorized member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    /// Saved room incarnation.
    pub instance: [u8; 16],
    /// Exact Session opening supplied by the selected view.
    pub opening: Digest32,
    /// Current sealed attention revision.
    pub revision: u64,
    /// Thread audiences are still being checked; an empty page is not a complete absence.
    pub preparing: bool,
    /// At most [`PAGE_SIZE`] current records.
    pub rows: Vec<Row>,
    /// Explicit continuation; an empty page can still have work remaining.
    pub next: Option<Cursor>,
}

/// A selected-Session private query. It never opens or wakes that Session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {
    /// Exact selected Session id.
    pub session: String,
    /// Exact authenticated opening selected by the caller.
    pub opening: Digest32,
    /// Continue the same private selection.
    pub after: Option<Cursor>,
}

/// One durable reservation made before attempting external input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    /// Exact intended recipient.
    pub recipient: Recipient,
    /// Idempotent identity of this one notice.
    pub notice_id: [u8; 16],
    /// Exact client/registration route generation.
    pub route: Digest32,
    /// Number of queued source records covered by this notice.
    pub count: u64,
    /// Last covered ordinal; a later arrival is not retrospectively dispatched.
    pub through: u64,
    /// Exact bounded source set; later rows and held sources are never included retroactively.
    pub sources: Vec<Digest32>,
}

/// Adapter acceptance is kept distinct from receipt and ambiguous delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DispatchOutcome {
    /// Pause/publication admission held the notice before any adapter write; no route failed.
    Held(String),
    /// No input bytes could have been accepted.
    NotSent(String),
    /// The exact receiver explicitly rejected before acceptance.
    Rejected(String),
    /// The receiver accepted a notice; context delivery is still unobserved.
    Accepted,
    /// Acceptance may have occurred; do not start another turn on a timer.
    Unknown(String),
    /// No supported exact live-conversation admission is available.
    Unavailable(String),
}

/// Local daemon operations. Remote streams accept only [`Query`], never mutations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    /// Reclaim one bounded page whose source expired or exact Session ended.
    Maintain,
    /// One bounded page of current own open Session identities, without title/activity bodies.
    Recipients {
        /// Last examined Session opening; never an array offset.
        after: Option<Digest32>,
    },
    /// Inspect one bounded arrival/thread page for this exact registered Session.
    Scan {
        /// Exact selected recipient incarnation.
        recipient: Recipient,
        /// Actual registered harness, not a caller-selected delivery method.
        harness: String,
        /// Current client capability, absent when automatic admission is unavailable.
        route: Option<Digest32>,
    },
    /// One fair page of queued sources, including explicit wait reasons.
    Pending {
        /// Exact selected recipient incarnation.
        recipient: Recipient,
    },
    /// Resolve a currently open local Session and its persisted source cursor.
    Resolve {
        /// Complete registered Session identity.
        session: String,
    },
    /// Read one exact selected page under current drive authority.
    Page(Query),
    /// Reserve one notice over selected queued sources before any external write.
    Begin {
        /// Exact selected recipient incarnation.
        recipient: Recipient,
        /// Exact registered client route generation.
        route: Digest32,
        /// Bounded exact source set; Prepare accepts six and other operations at most 64.
        sources: Vec<Digest32>,
    },
    /// Record the exact attempt's adapter outcome; acceptance is not delivery.
    Dispatch {
        /// Previously sealed exact notice reservation.
        attempt: Attempt,
        /// Observed adapter outcome, kept separate from context delivery.
        outcome: DispatchOutcome,
    },
    /// Admit an opaque notice inside the actual native prompt hook, once, before reading news.
    Admit {
        /// Native hook's exact selected recipient incarnation.
        recipient: Recipient,
        /// Previously sealed notice identity; never a caller-created turn.
        notice_id: [u8; 16],
        /// Route that reserved the notice.
        route: Digest32,
    },
    /// Reserve exact context sources before stdout; a crash leaves an explicit unknown receipt.
    Prepare {
        /// Exact selected recipient incarnation.
        recipient: Recipient,
        /// Bounded exact source set; Prepare accepts six and other operations at most 64.
        sources: Vec<Digest32>,
        /// Identity of this particular hook output attempt.
        ticket: [u8; 16],
        /// Native input association, when the hook is inside an OpenCode input.
        input: Option<Digest32>,
    },
    /// Retire only this hook's reservation when publication was definitely cancelled.
    CancelPrepared {
        /// Exact selected recipient incarnation.
        recipient: Recipient,
        /// Bounded exact source set; Prepare accepts six and other operations at most 64.
        sources: Vec<Digest32>,
        /// Identity of this particular hook output attempt.
        ticket: [u8; 16],
    },
    /// Exact hook context receipt, after successful stdout flush.
    Received {
        /// Exact selected recipient incarnation.
        recipient: Recipient,
        /// Bounded exact source set; Prepare accepts six and other operations at most 64.
        sources: Vec<Digest32>,
        /// Only this emitted output's pending accounting may be settled.
        ticket: [u8; 16],
    },
    /// Authoritative persisted input and its actual running step were observed.
    Observed(InputReceipt),
}
impl Operation {
    pub(crate) fn session(&self) -> &str {
        match self {
            Self::Maintain | Self::Recipients { .. } => "",
            Self::Resolve { session } => session,
            Self::Page(query) => &query.session,
            Self::Scan { recipient, .. }
            | Self::Pending { recipient }
            | Self::Begin { recipient, .. }
            | Self::Admit { recipient, .. }
            | Self::Prepare { recipient, .. }
            | Self::CancelPrepared { recipient, .. }
            | Self::Received { recipient, .. } => &recipient.session,
            Self::Dispatch { attempt, .. } => &attempt.recipient.session,
            Self::Observed(receipt) => &receipt.recipient.session,
        }
    }
    pub(crate) fn recipient(&self) -> Option<&Recipient> {
        match self {
            Self::Scan { recipient, .. }
            | Self::Pending { recipient }
            | Self::Begin { recipient, .. }
            | Self::Admit { recipient, .. }
            | Self::Prepare { recipient, .. }
            | Self::CancelPrepared { recipient, .. }
            | Self::Received { recipient, .. } => Some(recipient),
            Self::Dispatch { attempt, .. } => Some(&attempt.recipient),
            Self::Observed(receipt) => Some(&receipt.recipient),
            _ => None,
        }
    }
}

/// The bounded result of one local operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Reply {
    /// A page of current own Session identities; continuation may follow a filtered empty page.
    Recipients {
        /// At most 16 current own Session identities.
        recipients: Vec<Recipient>,
        /// Explicit continuation over the existing Session index.
        next: Option<Digest32>,
    },
    /// Current exact Session and inspected arrival high-water mark.
    Resolved {
        /// Exact selected recipient incarnation.
        recipient: Recipient,
        /// Last inspected source arrival.
        through: u64,
        /// A sealed notice or hook-output reservation still awaits its context receipt.
        notice_pending: bool,
    },
    /// Requested private page.
    Page(Page),
    /// A newly sealed single notice, or no eligible work.
    Attempt(Option<Attempt>),
    /// Exact newly or resumably reserved sources; excludes already-bound other inputs.
    Prepared(Vec<Digest32>),
    /// Mutation sealed, including an idempotent no-op.
    Done,
}
