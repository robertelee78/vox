//! ADR-029 §3, §8 (#553) — **driving a Session from the TUI**: the actions a member with drive takes
//! on a Session it is shown, and the Details of an entry, as plain words for the TUI to draw.
//!
//! No TUI type crosses this boundary: each action takes the node's [`Paths`], the Session it acts
//! on ([`Target`]) and the action's own input, and returns the sentence to show, `Ok` and `Err`
//! alike, in the words the CLI uses (tui2's steps and words for #553, CL-1). Each sends through
//! [`crate::drive::send`], the one sender `vox room session` uses, so the TUI, the CLI and the app
//! drive the same way; each is `async`, run off the render path.
//!
//! **A member without drive is refused here too** (CL-3): the TUI does not offer the actions
//! without drive, and this is the backstop. Whether the input may be taken is still the session's
//! node's to say, from its own keyring (DR-2), for a driver with drive.

use std::collections::BTreeMap;

use vox_core::hash::Digest32;
use vox_core::node::paths::Paths;

use crate::drive::{Action, Request};

/// The Session an action is for, as the TUI holds it from the room's Sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The room it is in.
    pub room: Digest32,
    /// Its node, whose session it is.
    pub node: Digest32,
    /// The harness's session id.
    pub session: String,
    /// Its label (`vox_agentcomms::envelope::session_label`), as the TUI shows it.
    pub label: String,
    /// Whether this node may drive it (the Session row's `can_drive`).
    pub can_drive: bool,
}

/// Type `text` into the session as its operator (DR-1.2).
///
/// # Errors
/// The sentence to show: not delivered, not sent, no answer, or no drive.
pub async fn say(paths: &Paths, t: &Target, text: &str) -> Result<String, String> {
    if text.trim().is_empty() {
        return Err(format!("not sent to {}: there is no text to send", t.label));
    }
    act(
        paths,
        t,
        Action::Text {
            text: text.to_owned(),
        },
    )
    .await
}

/// Send a slash command (`/compact`, `/clear`, `/rename <name>`, DR-1.6).
///
/// # Errors
/// As [`say`].
pub async fn slash(paths: &Paths, t: &Target, command: &str) -> Result<String, String> {
    let text = command.trim();
    if !text.starts_with('/') || text.len() < 2 {
        return Err(format!(
            "not sent to {}: a slash command starts with / and names a command",
            t.label
        ));
    }
    act(
        paths,
        t,
        Action::Slash {
            text: text.to_owned(),
        },
    )
    .await
}

/// Interrupt the session (Esc, DR-1.3).
///
/// # Errors
/// As [`say`].
pub async fn interrupt(paths: &Paths, t: &Target) -> Result<String, String> {
    act(paths, t, Action::Interrupt).await
}

/// Stop the session (Ctrl-C, DR-1.3).
///
/// # Errors
/// As [`say`].
pub async fn stop(paths: &Paths, t: &Target) -> Result<String, String> {
    act(paths, t, Action::Stop).await
}

/// Approve the approval request `reference` (its entry's `ref`, DR-1.4).
///
/// # Errors
/// As [`say`].
pub async fn approve(paths: &Paths, t: &Target, reference: &str) -> Result<String, String> {
    act(
        paths,
        t,
        Action::Approve {
            r#ref: reference.to_owned(),
        },
    )
    .await
}

/// Reject the approval request `reference`, with the reason the model is given, if any.
///
/// # Errors
/// As [`say`].
pub async fn reject(
    paths: &Paths,
    t: &Target,
    reference: &str,
    why: Option<&str>,
) -> Result<String, String> {
    act(
        paths,
        t,
        Action::Reject {
            r#ref: reference.to_owned(),
            why: why
                .map(str::trim)
                .filter(|w| !w.is_empty())
                .map(str::to_owned),
        },
    )
    .await
}

/// One question of a question request, as its entry carries it: its key (its id, else its text)
/// and its options' labels, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// What the answer is given under: the question's id, or its text when it has none.
    pub key: String,
    /// The options' labels, numbered from 1 as the TUI shows them.
    pub options: Vec<String>,
}

/// Answer the question request `reference` (DR-1.5): for each question, `choice` is an option's
/// number as shown (`1`…), or text typed as the answer.
///
/// # Errors
/// A number no option has, or, as [`say`].
pub async fn answer(
    paths: &Paths,
    t: &Target,
    reference: &str,
    questions: &[(Question, String)],
) -> Result<String, String> {
    let mut answers = BTreeMap::new();
    for (q, choice) in questions {
        let choice = choice.trim();
        let picked = match choice.parse::<usize>() {
            Ok(n) => q.options.get(n.wrapping_sub(1)).cloned().ok_or_else(|| {
                format!(
                    "not sent to {}: the question has no option {n}; it has {}",
                    t.label,
                    q.options.len()
                )
            })?,
            Err(_) if choice.is_empty() => {
                return Err(format!("not sent to {}: there is no answer", t.label))
            }
            Err(_) => choice.to_owned(),
        };
        answers.insert(q.key.clone(), picked);
    }
    act(
        paths,
        t,
        Action::Answer {
            r#ref: reference.to_owned(),
            answers,
        },
    )
    .await
}

/// The questions a question entry's body (the shared activity format) asks, for [`answer`].
#[must_use]
pub fn questions(entry: &serde_json::Value) -> Vec<Question> {
    entry["questions"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|q| Question {
            key: q["id"]
                .as_str()
                .or_else(|| q["text"].as_str())
                .unwrap_or_default()
                .to_owned(),
            options: q["options"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|o| o["label"].as_str().map(str::to_owned))
                .collect(),
        })
        .collect()
}

/// Details of one entry, as plain lines for the TUI's pane: each part's label, then its text,
/// indented (the same text `vox room session --details` prints).
#[must_use]
pub fn details(parts: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (label, body) in parts {
        out.push(format!("{label}:"));
        out.extend(body.lines().map(|l| format!("  {l}")));
    }
    out
}

/// Send `action` to the Session `t`, refusing first without drive or trust (CL-3), and say what
/// came of it in the CLI's words.
async fn act(paths: &Paths, t: &Target, action: Action) -> Result<String, String> {
    let node = crate::ident::name_of(&t.node);
    if !t.can_drive {
        return Err(format!(
            "you cannot drive this Session: {node} has not given you drive"
        ));
    }
    let request = Request {
        v: 1,
        session: t.session.clone(),
        action,
    };
    match crate::drive::send(paths, t.room, t.node, &request).await {
        Ok(said) => Ok(format!("{}: {said}", t.label)),
        Err(e) => Err(e.sentence(&t.label)),
    }
}
