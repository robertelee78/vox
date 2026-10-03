//! The closed capability vocabulary and attenuation lattice (ADR-007
//! §"Capability vocabulary").
//!
//! Authorization in Vox is an SPKI/SDSI/UCAN-style *capability* model: the
//! genesis creator holds the top capability ([`Capability::Admin`]), and every
//! delegation may grant **only capabilities at or below the issuer's own**
//! (monotonic attenuation — a delegation can never escalate). The evaluator
//! ([`crate::governance::evaluator`]) recognizes **exactly** the capabilities
//! defined here and nothing else: an unknown capability type is a verification
//! failure, never silently ignored, so the evaluator's domain is closed and the
//! golden-vector equality gate is well defined.
//!
//! ## The lattice
//! ```text
//!                         admin                (implies every capability below)
//!         ┌────────┬────────┼─────────┐
//!     delegate   invite   policy  passphrase-rotate
//! ```
//! `admin` *implies* (is ≥) every other capability. The four named capabilities are
//! otherwise mutually incomparable: holding `invite` says nothing about `policy`. The
//! "≤" relation is therefore: `x ≤ y` iff `y == admin`, or `x == y`.
//!
//! ## No tunnel capabilities
//! The `bind:<svc>` / `dial:<svc>` tunnel capabilities and `#role` attributes were the
//! capability model ADR-017 M17.7 withdrew, and are removed from the vocabulary
//! (PRD-001 R44): who reaches a service is the host's own decision (its trust keyring
//! and the room's current authors), never a token in the log. A cert or genesis
//! carrying one is refused like any unknown capability.
//!
//! ## Wire encoding
//! A capability is a CBOR text string in a capability-set array (the cert body,
//! [`crate::governance::cert`]), one fixed ASCII token per capability. The
//! set is canonicalized (sorted, deduplicated) so two implementations encode the
//! identical bytes for the identical logical set — a precondition for the
//! golden-vector gate.

use std::collections::BTreeSet;

use crate::error::{Error, Result};

/// The ASCII token for [`Capability::Admin`].
pub const TOKEN_ADMIN: &str = "admin";
/// The ASCII token for [`Capability::Delegate`].
pub const TOKEN_DELEGATE: &str = "delegate";
/// The ASCII token for [`Capability::Invite`].
pub const TOKEN_INVITE: &str = "invite";
/// The ASCII token for [`Capability::Policy`].
pub const TOKEN_POLICY: &str = "policy";
/// The ASCII token for [`Capability::PassphraseRotate`].
pub const TOKEN_PASSPHRASE_ROTATE: &str = "passphrase-rotate";

/// The longest capability token text string accepted on decode: rejects a hostile
/// multi-megabyte "capability" before it is looked at (anti-abuse, ADR-008).
pub const MAX_CAPABILITY_LEN: usize = 256;

/// A capability from the closed ADR-007 vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Capability {
    /// `admin` — full governance; implies every capability below. Held by the
    /// root admin from genesis (ADR-007).
    Admin,
    /// `delegate` — may issue admin-delegation certs (attenuable).
    Delegate,
    /// `invite` — may issue identity-bound invites (ADR-005).
    Invite,
    /// `policy` — may author policy-update entries (history / TTL).
    Policy,
    /// `passphrase-rotate` — may author passphrase-rotation (epoch) entries.
    PassphraseRotate,
}

impl Capability {
    /// Serialize to the canonical capability token (the exact text encoded in a
    /// cert body).
    #[must_use]
    pub fn to_token(&self) -> String {
        match self {
            Capability::Admin => TOKEN_ADMIN.to_owned(),
            Capability::Delegate => TOKEN_DELEGATE.to_owned(),
            Capability::Invite => TOKEN_INVITE.to_owned(),
            Capability::Policy => TOKEN_POLICY.to_owned(),
            Capability::PassphraseRotate => TOKEN_PASSPHRASE_ROTATE.to_owned(),
        }
    }

    /// Parse a capability from its canonical token.
    ///
    /// An unrecognized token — including the withdrawn `bind:`/`dial:`/`#role` forms,
    /// or any string not in the vocabulary — is
    /// [`Error::UnknownCapability`]: the closed vocabulary admits nothing else,
    /// so the evaluator can never see a capability it does not understand.
    pub fn from_token(token: &str) -> Result<Self> {
        if token.len() > MAX_CAPABILITY_LEN {
            return Err(Error::SizeLimitExceeded("governance capability token"));
        }
        match token {
            TOKEN_ADMIN => Ok(Capability::Admin),
            TOKEN_DELEGATE => Ok(Capability::Delegate),
            TOKEN_INVITE => Ok(Capability::Invite),
            TOKEN_POLICY => Ok(Capability::Policy),
            TOKEN_PASSPHRASE_ROTATE => Ok(Capability::PassphraseRotate),
            _ => Err(Error::UnknownCapability),
        }
    }

    /// Whether `self` is **at or below** `issuer` in the attenuation lattice:
    /// the relation "`issuer` may grant `self`". This is the single rule the
    /// evaluator uses to reject over-attenuation (a delegation granting a
    /// capability its issuer does not itself hold).
    ///
    /// - `admin` covers everything: `x.is_at_or_below(admin)` is always true.
    /// - Otherwise a capability is granted only by itself: `x.is_at_or_below(x)`.
    #[must_use]
    pub fn is_at_or_below(&self, issuer: &Capability) -> bool {
        matches!(issuer, Capability::Admin) || self == issuer
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
