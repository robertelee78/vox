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
pub const NOT_IN_KEYRING: &str = "(not in your keyring)";

/// A member's fingerprint as shown on screen: its first [`AUTHOR_CHARS`] base32 characters.
#[must_use]
pub fn author_id(fp: &Digest32) -> String {
    b32_encode(fp).chars().take(AUTHOR_CHARS).collect()
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
