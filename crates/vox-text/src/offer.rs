//! What a client says of a node offered to the keyring, word for word in the TUI and the app
//! (ADR-028 CL-1, K-7, K-15, K-17): one function each, so the two never drift apart.

/// How a node is named where the keyring has no alias for it: its fingerprint's first
/// [`FINGERPRINT_CHARS`] base32 characters, marked as not in the keyring (ADR-028 K-3).
pub const FINGERPRINT_CHARS: usize = 26;

/// The mark after a node named by its fingerprint.
pub const NOT_IN_KEYRING: &str = "(not in keyring)";

/// A node as a client names it: `alias` when the keyring has one, else its fingerprint (base32)
/// shortened and marked as not in the keyring.
#[must_use]
pub fn name(alias: Option<&str>, fingerprint: &str) -> String {
    match alias.map(str::trim).filter(|a| !a.is_empty()) {
        Some(a) => a.to_owned(),
        None => format!(
            "{} {NOT_IN_KEYRING}",
            fingerprint
                .chars()
                .take(FINGERPRINT_CHARS)
                .collect::<String>()
        ),
    }
}

/// Which of the nodes in the keyring trust a node (K-7), by their names: "No one you trust trusts
/// it yet.", "ann trusts it.", "ann and bo trust it.".
#[must_use]
pub fn trusted_by(trusters: &[String]) -> String {
    match trusters {
        [] => "No one you trust trusts it yet.".to_owned(),
        [one] => format!("{one} trusts it."),
        [rest @ .., last] => format!("{} and {last} trust it.", rest.join(", ")),
    }
}

/// The sentence for an offer of the node named `who` (K-15, K-17): that it joined, that it trusts
/// you, or both, then [`trusted_by`].
#[must_use]
pub fn said(who: &str, joined: bool, trusts_you: bool, trusters: &[String]) -> String {
    let what = match (joined, trusts_you) {
        (true, true) => "joined, and trusts you.",
        (false, true) => "trusts you.",
        _ => "joined.",
    };
    format!("{who} {what} {}", trusted_by(trusters))
}
