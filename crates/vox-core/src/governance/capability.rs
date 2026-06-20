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
//!         ┌────────┬────────┼─────────┬───────────────────┐
//!     delegate   invite   policy  passphrase-rotate   tunnel caps
//!                                                  (bind:<svc> / dial:<svc>
//!                                                   + role-tag attributes #tag)
//! ```
//! `admin` *implies* (is ≥) every other capability. The five named scalar
//! capabilities (`delegate`, `invite`, `policy`, `passphrase-rotate`) plus the
//! tunnel capabilities are otherwise mutually incomparable: holding `invite`
//! says nothing about `policy`. The "≤" relation is therefore: `x ≤ y` iff
//! `y == admin`, or `x == y` (a capability is ≤ itself), with tunnel
//! capabilities additionally attenuable by service tag and role tag (below).
//!
//! ## Tunnel capabilities (defined here, *used* by ADR-013/M11)
//! `bind:<service-tag>` (advertise/host a service) and `dial:<service-tag>`
//! (consume one), plus attenuable **role-tag attributes** (e.g. `#ops`,
//! `#ssh-hosts`). These are *registered into this one lattice* so ADR-013's ABAC
//! policies ("`#ops` may Dial `#ssh-hosts`") are evaluated by the **same**
//! deterministic evaluator over these grants — ADR-013 adds no parallel
//! authorization engine (ADR-007 §"Capability vocabulary"). M6 defines them and
//! the evaluator evaluates them; the tunnel *mechanism* that consumes a granted
//! `bind`/`dial` is M11's job.
//!
//! ## Wire encoding
//! A capability is a CBOR text string in a capability-set array (the cert body,
//! [`crate::governance::cert`]). The scalar capabilities use their fixed ASCII
//! tokens; the tunnel capabilities use a `kind:tag` / `#tag` lexical form. The
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
/// The lexical prefix for a [`Capability::Bind`] tunnel capability.
pub const PREFIX_BIND: &str = "bind:";
/// The lexical prefix for a [`Capability::Dial`] tunnel capability.
pub const PREFIX_DIAL: &str = "dial:";
/// The lexical prefix for a [`Capability::Role`] attribute.
pub const PREFIX_ROLE: &str = "#";

/// The longest capability token text string accepted on decode. Service/role
/// tags are short labels (ADR-013); this bound rejects a hostile multi-megabyte
/// "capability" before it is interned (anti-abuse, ADR-008).
pub const MAX_CAPABILITY_LEN: usize = 256;

/// A capability from the closed ADR-007 vocabulary.
///
/// The `String` payloads of [`Capability::Bind`] / [`Capability::Dial`] /
/// [`Capability::Role`] hold the *tag* only (the prefix is stripped on parse and
/// re-applied on encode), so two equal logical tags are one value.
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
    /// `bind:<service-tag>` — advertise / host a tunnel service (ADR-013).
    Bind(String),
    /// `dial:<service-tag>` — consume a tunnel service (ADR-013).
    Dial(String),
    /// `#<role-tag>` — an attenuable role-tag attribute (e.g. `#ops`), evaluated
    /// by the same evaluator for ADR-013 ABAC (ADR-007).
    Role(String),
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

    /// A `#<tag>` role attribute.
    #[must_use]
    pub fn role(tag: impl Into<String>) -> Self {
        Capability::Role(tag.into())
    }

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
            Capability::Bind(tag) => format!("{PREFIX_BIND}{tag}"),
            Capability::Dial(tag) => format!("{PREFIX_DIAL}{tag}"),
            Capability::Role(tag) => format!("{PREFIX_ROLE}{tag}"),
        }
    }

    /// Parse a capability from its canonical token.
    ///
    /// An unrecognized token — including a `bind:`/`dial:` with an empty tag, a
    /// bare `#`, or any string not in the vocabulary — is
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
            _ => {
                if let Some(tag) = token.strip_prefix(PREFIX_BIND) {
                    nonempty_tag(tag).map(|t| Capability::Bind(t.to_owned()))
                } else if let Some(tag) = token.strip_prefix(PREFIX_DIAL) {
                    nonempty_tag(tag).map(|t| Capability::Dial(t.to_owned()))
                } else if let Some(tag) = token.strip_prefix(PREFIX_ROLE) {
                    nonempty_tag(tag).map(|t| Capability::Role(t.to_owned()))
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
    /// Tunnel/role capabilities follow the same rule (exact-tag match, or covered
    /// by `admin`); finer service-tag-prefix attenuation is an ADR-013 policy
    /// detail layered on top, not a relaxation of this floor.
    #[must_use]
    pub fn is_at_or_below(&self, issuer: &Capability) -> bool {
        matches!(issuer, Capability::Admin) || self == issuer
    }
}

/// Reject an empty tunnel/role tag — `bind:`, `dial:`, and `#` with nothing
/// after the prefix are not valid capabilities.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_token_round_trip() {
        for c in [
            Capability::Admin,
            Capability::Delegate,
            Capability::Invite,
            Capability::Policy,
            Capability::PassphraseRotate,
        ] {
            let t = c.to_token();
            assert_eq!(Capability::from_token(&t).unwrap(), c);
        }
    }

    #[test]
    fn tunnel_token_round_trip() {
        let cases = [
            Capability::bind("ssh-hosts"),
            Capability::dial("http"),
            Capability::role("ops"),
        ];
        for c in cases {
            let t = c.to_token();
            assert_eq!(Capability::from_token(&t).unwrap(), c.clone());
        }
        assert_eq!(Capability::bind("x").to_token(), "bind:x");
        assert_eq!(Capability::dial("x").to_token(), "dial:x");
        assert_eq!(Capability::role("x").to_token(), "#x");
    }

    #[test]
    fn unknown_capability_rejected() {
        assert!(matches!(
            Capability::from_token("superuser"),
            Err(Error::UnknownCapability)
        ));
        // Empty tunnel/role tags are not valid capabilities.
        assert!(matches!(
            Capability::from_token("bind:"),
            Err(Error::UnknownCapability)
        ));
        assert!(matches!(
            Capability::from_token("dial:"),
            Err(Error::UnknownCapability)
        ));
        assert!(matches!(
            Capability::from_token("#"),
            Err(Error::UnknownCapability)
        ));
    }

    #[test]
    fn oversized_token_rejected_before_intern() {
        let huge = format!("bind:{}", "a".repeat(MAX_CAPABILITY_LEN));
        assert!(matches!(
            Capability::from_token(&huge),
            Err(Error::SizeLimitExceeded(_))
        ));
    }

    #[test]
    fn admin_implies_everything() {
        // Every capability is at-or-below admin in the lattice.
        for c in [
            Capability::Delegate,
            Capability::Invite,
            Capability::Policy,
            Capability::PassphraseRotate,
            Capability::bind("svc"),
            Capability::dial("svc"),
            Capability::role("ops"),
            Capability::Admin,
        ] {
            assert!(c.is_at_or_below(&Capability::Admin));
        }
    }

    #[test]
    fn scalar_caps_are_incomparable() {
        // invite says nothing about policy: a delegation holding only invite
        // cannot grant policy.
        assert!(!Capability::Policy.is_at_or_below(&Capability::Invite));
        assert!(!Capability::Invite.is_at_or_below(&Capability::Policy));
        // But a capability is at-or-below itself.
        assert!(Capability::Invite.is_at_or_below(&Capability::Invite));
    }

    #[test]
    fn admin_set_grants_all() {
        let admin = CapabilitySet::admin();
        assert!(admin.grants(&Capability::Delegate));
        assert!(admin.grants(&Capability::bind("ssh")));
        assert!(admin.grants(&Capability::Admin));
    }

    #[test]
    fn set_is_within_issuer() {
        let issuer = CapabilitySet::from_iter_caps([Capability::Delegate, Capability::Invite]);
        let ok = CapabilitySet::from_iter_caps([Capability::Invite]);
        let over = CapabilitySet::from_iter_caps([Capability::Policy]);
        assert!(ok.is_within(&issuer));
        assert!(!over.is_within(&issuer));
        // An issuer with admin contains any set.
        assert!(over.is_within(&CapabilitySet::admin()));
    }

    #[test]
    fn set_tokens_are_sorted_and_dedup() {
        let mut s = CapabilitySet::new();
        s.insert(Capability::Policy);
        s.insert(Capability::Invite);
        s.insert(Capability::Invite); // duplicate
        s.insert(Capability::Admin);
        let tokens = s.to_tokens();
        assert_eq!(tokens.len(), 3);
        // BTreeSet order == the derived Ord on Capability (variant order then tag):
        // Admin, Invite, Policy.
        assert_eq!(tokens, vec!["admin", "invite", "policy"]);
        // Re-parsing yields the same set.
        assert_eq!(CapabilitySet::from_tokens(&tokens).unwrap(), s);
    }

    #[test]
    fn from_tokens_rejects_unknown() {
        assert!(matches!(
            CapabilitySet::from_tokens(&["invite", "wat"]),
            Err(Error::UnknownCapability)
        ));
    }
}
