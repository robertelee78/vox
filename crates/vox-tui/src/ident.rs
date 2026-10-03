//! How a member is named on screen.
//!
//! A member is its fingerprint, and every surface used to show a short prefix of it: 8 hex
//! characters in the TUI (32 bits), 8 base32 in the agent drain (40 bits), 12 base32 in the
//! CLI and the work board (60 bits). A prefix that short can be matched by grinding keys: 2^40
//! attempts is an afternoon, so a member could post under a name that reads as another's (#198).
//!
//! Where the keyring's petnames are at hand (the TUI holds the node's view), a trusted member is
//! shown by the name the operator gave it, and anyone else by [`AUTHOR_CHARS`] of its fingerprint,
//! marked as not in the keyring. Surfaces that speak to a node over its control socket read the
//! same names from it ([`load_names`], V210-162) and show a member by [`name_of`]: the reader's own
//! name for it, or its fingerprint at [`AUTHOR_CHARS`] when it has none.

use std::sync::OnceLock;

use vox_core::hash::Digest32;
use vox_core::node::ipc::{Frame, IpcClient};
use vox_core::node::link::b32_encode;

/// Base32 characters of a fingerprint shown wherever a member is named without a keyring name:
/// 26, i.e. 130 bits, past the reach of anyone grinding keys for a lookalike.
pub const AUTHOR_CHARS: usize = 26;

/// What marks a member that is not in this node's trust keyring, where the keyring is known.
/// Short enough that 26 characters, a space and this fit the TUI's members pane (46 columns):
/// the longer "(not in your keyring)" was cut off there, which the proof caught.
pub const NOT_IN_KEYRING: &str = "(not in keyring)";

/// A member's fingerprint as shown on screen: its first [`AUTHOR_CHARS`] base32 characters.
#[must_use]
pub fn author_id(fp: &Digest32) -> String {
    b32_encode(fp).chars().take(AUTHOR_CHARS).collect()
}

/// What a person is told about a member this node holds back for equivocating (V210-63):
/// `name` signed two different messages at one position, `seq`, in the room being read. The
/// wording is the decider's (2026-09-28).
#[must_use]
pub fn equivocation_notice(name: &str, seq: u64) -> String {
    format!(
        "{name} signed two different messages at the same place in this room (their message \
         {seq}). Their later messages are held back."
    )
}

/// A member's name where the keyring is known: the petname the operator gave it, or its
/// fingerprint at [`AUTHOR_CHARS`] followed by [`NOT_IN_KEYRING`].
#[must_use]
pub fn member_name(trusted: &[(Digest32, String)], fp: &Digest32) -> String {
    match trusted.iter().find(|(id, _)| id == fp) {
        Some((_, petname)) if !petname.trim().is_empty() => petname.clone(),
        _ => format!("{} {NOT_IN_KEYRING}", author_id(fp)),
    }
}

/// This process's copy of the node's names for its members: `(fingerprint, name)`.
static NAMES: OnceLock<Vec<(Digest32, String)>> = OnceLock::new();

/// Read the node's names for its members once, for [`name_of`] (V210-162).
///
/// Best effort: a node that does not answer leaves every member shown by fingerprint, as every
/// surface showed them before.
pub async fn load_names(client: &mut IpcClient) {
    if NAMES.get().is_some() {
        return;
    }
    if let Ok(Frame::Trusted { entries }) = client.trusted("").await {
        let _ = NAMES.set(entries);
    }
}

/// The names [`load_names`] read, or none.
#[must_use]
pub fn names() -> &'static [(Digest32, String)] {
    NAMES.get().map_or(&[], Vec::as_slice)
}

/// A member as the reader knows it (V210-162): the name this node gave it, on one line, or its
/// fingerprint at [`AUTHOR_CHARS`] when it gave none.
#[must_use]
pub fn name_of(fp: &Digest32) -> String {
    name_in(names(), fp)
}

/// [`name_of`] against `trusted`.
#[must_use]
pub fn name_in(trusted: &[(Digest32, String)], fp: &Digest32) -> String {
    match trusted.iter().find(|(id, _)| id == fp) {
        Some((_, n)) if !n.trim().is_empty() => {
            vox_agentcomms::envelope::shown(n.trim(), vox_agentcomms::envelope::SHOWN_NAME)
        }
        _ => author_id(fp),
    }
}

/// Whether `name` may be this node's name for `target` (V210-162): on one line, and not already
/// its name for another member, since a name is how a person addresses a member.
///
/// # Errors
/// Saying which rule `name` breaks.
pub fn check_new_name(
    trusted: &[(Digest32, String)],
    target: &Digest32,
    name: &str,
) -> Result<(), crate::app::AppError> {
    let name = name.trim();
    if !vox_agentcomms::envelope::is_valid_name(name, vox_agentcomms::envelope::MAX_NAME) {
        return Err(crate::app::AppError::Usage(format!(
            "a name must be 1–{} bytes on one line",
            vox_agentcomms::envelope::MAX_NAME
        )));
    }
    match trusted
        .iter()
        .find(|(fp, n)| fp != target && n.trim() == name)
    {
        Some((fp, _)) => Err(crate::app::AppError::Usage(format!(
            "{name:?} is already your name for {}; give this one another",
            author_id(fp)
        ))),
        None => Ok(()),
    }
}

/// The fewest fingerprint characters a member may be named by: fewer is too easily a mistyped
/// name that happens to begin a fingerprint.
pub const MIN_PREFIX: usize = 8;

/// The member of `members` that `word` names (V210-161): the reader's own name for it, or its
/// fingerprint, whole or a unique prefix of at least [`MIN_PREFIX`] characters.
///
/// # Errors
/// A sentence saying why `word` names no one, or more than one, in this room.
pub fn resolve_member(
    word: &str,
    members: &[Digest32],
    trusted: &[(Digest32, String)],
) -> Result<Digest32, String> {
    let w = word.trim();
    let named: Vec<Digest32> = trusted
        .iter()
        .filter(|(_, n)| n.trim() == w)
        .map(|(fp, _)| *fp)
        .collect();
    match named.as_slice() {
        [fp] if members.contains(fp) => return Ok(*fp),
        [_] => return Err(format!("{w:?} is not a member of this room")),
        [] => {}
        many => {
            return Err(format!(
                "{w:?} is your name for {} members; name one by fingerprint",
                many.len()
            ))
        }
    }
    let needle = w.to_ascii_lowercase();
    let hits: Vec<Digest32> = members
        .iter()
        .copied()
        .filter(|m| needle.len() >= MIN_PREFIX && b32_encode(m).starts_with(&needle))
        .collect();
    match hits.as_slice() {
        [fp] => Ok(*fp),
        [] => Err(format!(
            "no member of this room is called {w:?}. Name one by your name for it (`vox trust \
             list`) or by its fingerprint, at least {MIN_PREFIX} characters (`vox room roster`)"
        )),
        many => Err(format!(
            "{w:?} begins {} members' fingerprints; use more characters",
            many.len()
        )),
    }
}

/// Who a message is addressed to, as the reader knows them (V210-161): each recipient by
/// [`name_in`], the reader itself as `you`. A recipient that is not a fingerprint (an older
/// build addressed sessions by name) is shown as written, on one line.
#[must_use]
pub fn recipients(to: &[String], me: Option<&Digest32>, trusted: &[(Digest32, String)]) -> String {
    to.iter()
        .map(
            |t| match vox_core::node::link::b32_decode(t.trim(), "recipient") {
                Ok(fp) if Some(&fp) == me => "you".to_owned(),
                Ok(fp) => name_in(trusted, &fp),
                Err(_) => vox_agentcomms::envelope::shown(t, vox_agentcomms::envelope::SHOWN_NAME),
            },
        )
        .collect::<Vec<_>>()
        .join(", ")
}
