//! The Vox version a message was written by (`data.vox`).
//!
//! Every structured post carries its writer's version, and a session's `hello` announces it,
//! so a reader can say which version each member runs. It gates nothing: Vox holds no task
//! state, so there is no claim protocol whose rules two versions could fold differently
//! (V030-26; the gate ADR-021 §5 described was removed with the claims).

use crate::envelope::Envelope;

/// The `data` key that carries a worker's Vox version.
pub const VOX_KEY: &str = "vox";

/// What a message's version stamp says, relative to the reading worker's version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stamp {
    /// Exactly the reader's version.
    Match,
    /// A valid version that is not the reader's.
    Other(String),
    /// No stamp at all — what every binary predating ADR-021 writes.
    Missing,
    /// A stamp that is not a semantic version.
    Unknown(String),
}

/// Whether `s` is a semantic version: `MAJOR.MINOR.PATCH`, each a number without a
/// leading zero, optionally followed by `-prerelease` and/or `+build`.
#[must_use]
pub fn is_semver(s: &str) -> bool {
    let core = s.split(['-', '+']).next().unwrap_or("");
    if core.len() != s.len() {
        let rest = &s[core.len()..];
        let ok = rest.len() > 1
            && rest
                .chars()
                .skip(1)
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+');
        if !ok {
            return false;
        }
    }
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
}

/// What `env`'s stamp says relative to `mine`. **Exact string equality** is the
/// rule; development builds between two tags share a version, and that is accepted
/// because the operator upgrades together.
#[must_use]
pub fn stamp_of(env: &Envelope, mine: &str) -> Stamp {
    match env.data.get(VOX_KEY) {
        None | Some(serde_json::Value::Null) => Stamp::Missing,
        Some(serde_json::Value::String(v)) if v == mine => Stamp::Match,
        Some(serde_json::Value::String(v)) if is_semver(v) => Stamp::Other(v.clone()),
        Some(serde_json::Value::String(v)) => Stamp::Unknown(v.clone()),
        Some(other) => Stamp::Unknown(other.to_string()),
    }
}
