//! How a member is named on screen.
//!
//! A member is its fingerprint, and every surface used to show a short prefix of it: 8 hex
//! characters in the TUI (32 bits), 8 base32 in the agent drain (40 bits), 12 base32 in the
//! CLI and the work board (60 bits). A prefix that short can be matched by grinding keys: 2^40
//! attempts is an afternoon, so a member could post under a name that reads as another's (#198).
//!
//! Where the keyring's petnames are at hand (the TUI holds the node's view), a trusted member is
//! shown by the name the operator gave it, and anyone else by [`AUTHOR_CHARS`] of its fingerprint,
//! marked as not in the keyring. Surfaces that speak to a node over its control socket cannot read
//! the keyring (it is sealed under the identity passphrase, ADR-020 §3), so they show the
//! fingerprint at [`AUTHOR_CHARS`] and make no claim about trust either way.

use vox_core::hash::Digest32;
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

/// A member as named beside a message where the keyring is known: `you` for this node, the
/// petname the operator gave it, or its fingerprint at [`AUTHOR_CHARS`].
#[must_use]
pub fn keyring_name(trusted: &[(Digest32, String)], me: Option<&Digest32>, fp: &Digest32) -> String {
    if me == Some(fp) {
        return "you".to_owned();
    }
    match trusted.iter().find(|(id, _)| id == fp) {
        Some((_, petname)) if !petname.trim().is_empty() => petname.clone(),
        _ => author_id(fp),
    }
}

/// Who a message is addressed to, as this reader is shown it (PRD-001 R15): each addressee by
/// `name` of its fingerprint — the reader's own keyring name where the reader has the keyring,
/// otherwise the fingerprint at [`AUTHOR_CHARS`] — followed by `/<agent name or session>` when
/// the sender named one. Empty for prose and for a message to the whole room.
///
/// The wire carries only fingerprints, so two readers who name a member differently are each
/// shown their own name, and neither is shown the sender's. An entry that is not a fingerprint
/// (a petname from a build before R15) addresses nobody; it is counted, never printed, because
/// its text is the author's and could pass for a name.
#[must_use]
pub fn addressed(text: &str, name: impl Fn(&Digest32) -> String) -> String {
    let Ok(env) = vox_agentcomms::envelope::Envelope::parse(text) else {
        return String::new();
    };
    if env.to.is_empty() {
        return String::new();
    }
    let whom = env.addressees();
    let mut out: Vec<String> = whom
        .iter()
        .map(|a| match &a.sub {
            Some(s) => format!("{}/{s}", name(&a.fp)),
            None => name(&a.fp),
        })
        .collect();
    let unreadable = env.to.len() - whom.len();
    if unreadable > 0 {
        out.push(format!("(+{unreadable} not a fingerprint)"));
    }
    out.join(", ")
}
