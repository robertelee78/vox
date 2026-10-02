//! The closed capability vocabulary and attenuation lattice (ADR-007
//! §"Capability vocabulary"), as trimmed by V030-32.
//!
//! **A room's governance is only "the creator or an admin sets the room's retention"** (the
//! decider, 2026-10-02). The genesis creator holds [`Capability::Admin`]; the creator may name
//! admins (#319), whose certificates carry `admin`; and `admin` implies [`Capability::Policy`],
//! the one capability a governance entry needs (a retention update). The evaluator recognizes
//! **exactly** the capabilities defined here: an unknown capability is a verification failure,
//! never silently ignored, so the evaluator's domain is closed.
//!
//! ## The lattice
//! ```text
//!            admin           (implies every capability below)
//!         ┌────┴──────────────────┐
//!       policy        bind:<svc> / dial:<svc>   (the genesis service grant, ADR-017)
//! ```
//! `x ≤ y` iff `y == admin`, or `x == y`.
//!
//! **Removed, tokens reserved** (V030-32): `delegate`, `invite`, `passphrase-rotate` and `#role`
//! attributes. No command ever issued them, and nothing read them but the evaluator. A token of
//! theirs is refused as [`Error::UnknownCapability`], like any other word outside the vocabulary.
//!
//! ## Wire encoding
//! A capability is a CBOR text string in a capability-set array (the cert body,
//! [`crate::governance::cert`]). The scalar capabilities use their fixed ASCII tokens; the
//! service capabilities use a `kind:tag` lexical form. The set is canonicalized (sorted,
//! deduplicated) so two implementations encode identical bytes for the identical logical set.

use std::collections::BTreeSet;

use crate::error::{Error, Result};

/// The ASCII token for [`Capability::Admin`].
pub const TOKEN_ADMIN: &str = "admin";
/// The ASCII token for [`Capability::Policy`].
pub const TOKEN_POLICY: &str = "policy";
/// The lexical prefix for a [`Capability::Bind`] tunnel capability.
pub const PREFIX_BIND: &str = "bind:";
/// The lexical prefix for a [`Capability::Dial`] tunnel capability.
pub const PREFIX_DIAL: &str = "dial:";

/// The longest capability token text string accepted on decode. Service tags are
/// short labels (ADR-013); this bound rejects a hostile multi-megabyte
/// "capability" before it is interned (anti-abuse, ADR-008).
pub const MAX_CAPABILITY_LEN: usize = 256;

/// A capability from the closed ADR-007 vocabulary.
///
/// The `String` payloads of [`Capability::Bind`] / [`Capability::Dial`] hold the
/// *tag* only (the prefix is stripped on parse and re-applied on encode), so two
/// equal logical tags are one value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Capability {
    /// `admin` — full governance; implies every capability below. Held by the
    /// root admin from genesis (ADR-007).
    Admin,
    /// `policy` — may author policy-update entries: the room's retention.
    Policy,
    /// `bind:<service-tag>` — advertise / host a tunnel service (ADR-013).
    Bind(String),
    /// `dial:<service-tag>` — consume a tunnel service (ADR-013).
    Dial(String),
}

impl Capability {
    /// A `bind:<tag>` tunnel capability.
    #[must_use]
    pub fn bind(tag: impl Into<String>) -> Self {
        Capability::Bind(tag.into())
    }

    /// A `dial:<tag>` tunnel capability.
    #[must_use]
    pub fn dial(tag: impl Into<String>) -> Self {
        Capability::Dial(tag.into())
    }

    /// Serialize to the canonical capability token (the exact text encoded in a
    /// cert body).
    #[must_use]
    pub fn to_token(&self) -> String {
        match self {
            Capability::Admin => TOKEN_ADMIN.to_owned(),
            Capability::Policy => TOKEN_POLICY.to_owned(),
            Capability::Bind(tag) => format!("{PREFIX_BIND}{tag}"),
            Capability::Dial(tag) => format!("{PREFIX_DIAL}{tag}"),
        }
    }

    /// Parse a capability from its canonical token.
    ///
    /// An unrecognized token — including a `bind:`/`dial:` with an empty tag, the
    /// removed `delegate`, `invite`, `passphrase-rotate` and `#role` tokens, or any
    /// string not in the vocabulary — is
    /// [`Error::UnknownCapability`]: the closed vocabulary admits nothing else,
    /// so the evaluator can never see a capability it does not understand.
    pub fn from_token(token: &str) -> Result<Self> {
        if token.len() > MAX_CAPABILITY_LEN {
            return Err(Error::SizeLimitExceeded("governance capability token"));
        }
        match token {
            TOKEN_ADMIN => Ok(Capability::Admin),
            TOKEN_POLICY => Ok(Capability::Policy),
            _ => {
                if let Some(tag) = token.strip_prefix(PREFIX_BIND) {
                    nonempty_tag(tag).map(|t| Capability::Bind(t.to_owned()))
                } else if let Some(tag) = token.strip_prefix(PREFIX_DIAL) {
                    nonempty_tag(tag).map(|t| Capability::Dial(t.to_owned()))
                } else {
                    Err(Error::UnknownCapability)
                }
            }
        }
    }

    /// Whether `self` is **at or below** `issuer` in the attenuation lattice:
    /// the relation "`issuer` may grant `self`". This is the single rule the
    /// evaluator uses to reject over-attenuation (a delegation granting a
    /// capability its issuer does not itself hold).
    ///
    /// - `admin` covers everything: `x.is_at_or_below(admin)` is always true.
    /// - Otherwise a capability is granted only by itself: `x.is_at_or_below(x)`.
    ///
    /// Service capabilities follow the same rule (exact-tag match, or covered
    /// by `admin`); finer service-tag-prefix attenuation is an ADR-013 policy
    /// detail layered on top, not a relaxation of this floor.
    #[must_use]
    pub fn is_at_or_below(&self, issuer: &Capability) -> bool {
        matches!(issuer, Capability::Admin) || self == issuer
    }
}

/// Reject an empty service tag — `bind:` or `dial:` with nothing after the prefix
/// is not a valid capability.
fn nonempty_tag(tag: &str) -> Result<&str> {
    if tag.is_empty() {
        Err(Error::UnknownCapability)
    } else {
        Ok(tag)
    }
}

/// A canonical, deduplicated **set** of capabilities — the granted set of an
/// admin-delegation cert (ADR-007).
///
/// Backed by a [`BTreeSet`] so iteration (and therefore the encoded token array)
/// is in a fixed total order regardless of insertion order: two implementations
/// that build the same logical set encode byte-identical bytes (the golden-vector
/// precondition). The set never stores duplicates.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapabilitySet {
    caps: BTreeSet<Capability>,
}

impl CapabilitySet {
    /// An empty capability set (grants nothing).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The full-authority set: just [`Capability::Admin`] (which *implies* every
    /// other capability via [`Capability::is_at_or_below`]). This is the genesis
    /// creator's set.
    #[must_use]
    pub fn admin() -> Self {
        let mut s = Self::new();
        s.insert(Capability::Admin);
        s
    }

    /// Build from an iterator of capabilities (deduplicated, ordered).
    pub fn from_iter_caps<I: IntoIterator<Item = Capability>>(it: I) -> Self {
        let mut s = Self::new();
        for c in it {
            s.insert(c);
        }
        s
    }

    /// Insert a capability (idempotent).
    pub fn insert(&mut self, cap: Capability) -> &mut Self {
        self.caps.insert(cap);
        self
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.caps.is_empty()
    }

    /// The number of capabilities held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.caps.len()
    }

    /// Iterate the capabilities in canonical (sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.caps.iter()
    }

    /// Whether the set grants `cap` — *directly or by implication*. Holding
    /// [`Capability::Admin`] grants every capability; otherwise the exact
    /// capability must be present.
    #[must_use]
    pub fn grants(&self, cap: &Capability) -> bool {
        self.caps.contains(&Capability::Admin) || self.caps.contains(cap)
    }

    /// Whether this set is wholly **at or below** `issuer`: every capability in
    /// `self` is granted by `issuer` (directly, or because `issuer` holds
    /// `admin`). This is the monotonic-attenuation check applied to a whole
    /// delegated set: a delegation is valid only if `delegated.is_within(issuer)`.
    #[must_use]
    pub fn is_within(&self, issuer: &CapabilitySet) -> bool {
        self.caps.iter().all(|c| issuer.grants(c))
    }

    /// The canonical token array (sorted text strings) for CBOR encoding.
    #[must_use]
    pub fn to_tokens(&self) -> Vec<String> {
        self.caps.iter().map(Capability::to_token).collect()
    }

    /// Parse a token array into a set, rejecting any unknown token. Order in the
    /// input does not matter (the set re-canonicalizes), but a token that is not
    /// in the vocabulary fails the whole parse (closed-vocabulary guarantee).
    pub fn from_tokens<S: AsRef<str>>(tokens: &[S]) -> Result<Self> {
        let mut s = Self::new();
        for t in tokens {
            s.insert(Capability::from_token(t.as_ref())?);
        }
        Ok(s)
    }
}
