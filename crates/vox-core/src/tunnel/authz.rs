//! Tunnel authorization (ADR-013 §"Authorization model") — a thin gate over the
//! **single** ADR-007 evaluator. ADR-013 introduces no second authorization
//! engine: Bind/Dial are capabilities in the same lattice
//! ([`Capability::Bind`] / [`Capability::Dial`]), decided by the same deterministic
//! [`Evaluator`], so the one golden-vector suite covers tunnel authz too.
//!
//! ## Hard invariants enforced here
//! - **Default-deny / dark services.** The *absence* of a `dial:<service>` grant is
//!   a denial; there is no implicit reachability. A denial returns the same
//!   [`Error::TunnelDenied`] regardless of whether the service exists, so an
//!   unauthorized member cannot even confirm a service is hosted.
//! - **Bind vs Dial are distinct rights.** Hosting requires `bind:<service>`;
//!   connecting requires `dial:<service>`; neither implies the other (each is
//!   checked against its own capability).
//! - **Chat membership grants no tunnel reach.** This gate consults only the
//!   capability lattice — being a member, holding the passphrase, or having message
//!   consent conveys nothing here. A tunnel capability must be granted explicitly.
//! - **Epoch-bound.** The evaluator's verdict reflects the current epoch and all
//!   authorized revocations; a revoked or rotated-out capability no longer grants.

use crate::error::{Error, Result};
use crate::governance::capability::Capability;
use crate::governance::evaluator::Evaluator;
use crate::hash::Digest32;

/// Whether `member` may **Dial** (consume) the service tagged `service_tag` — i.e.
/// holds a valid, unrevoked `dial:<service_tag>` capability for the current epoch.
#[must_use]
pub fn can_dial(evaluator: &Evaluator, member: &Digest32, service_tag: &str) -> bool {
    evaluator
        .grants(member, &Capability::dial(service_tag))
        .is_granted()
}

/// Whether `member` may **Bind** (host/advertise) the service tagged `service_tag`
/// — i.e. holds a valid, unrevoked `bind:<service_tag>` capability.
#[must_use]
pub fn can_bind(evaluator: &Evaluator, member: &Digest32, service_tag: &str) -> bool {
    evaluator
        .grants(member, &Capability::bind(service_tag))
        .is_granted()
}

/// Authorize an inbound Dial request at stream setup (the host side, ADR-013).
///
/// `client` is the peer identity the QUIC transport authenticated (ADR-011); the
/// host calls this before opening any local connection. Returns `Ok(())` only if
/// the client holds `dial:<service_tag>`; otherwise [`Error::TunnelDenied`] —
/// default-deny, and the error does not reveal whether the service exists.
pub fn authorize_dial(evaluator: &Evaluator, client: &Digest32, service_tag: &str) -> Result<()> {
    if can_dial(evaluator, client, service_tag) {
        Ok(())
    } else {
        Err(Error::TunnelDenied("no dial capability for service"))
    }
}

/// Authorize hosting a service locally (the host advertising a Bind, ADR-013).
/// Returns `Ok(())` only if `host` holds `bind:<service_tag>`.
pub fn authorize_bind(evaluator: &Evaluator, host: &Digest32, service_tag: &str) -> Result<()> {
    if can_bind(evaluator, host, service_tag) {
        Ok(())
    } else {
        Err(Error::TunnelDenied("no bind capability for service"))
    }
}

/// The set of members authorized to Dial `service_tag`, from a candidate member
/// list — the audience a Bind holder seals its advertisement to
/// ([`crate::tunnel::service::seal_to_recipient`]). Order follows `candidates`.
///
/// The host supplies the candidate member identities (e.g. the channel roster); the
/// gate filters to exactly those holding `dial:<service_tag>`, so an advertisement
/// is never sealed to a member who could not use it (and so a member who is not in
/// the Dial set never receives even ciphertext).
#[must_use]
pub fn dial_audience<'a, I>(
    evaluator: &Evaluator,
    service_tag: &str,
    candidates: I,
) -> Vec<Digest32>
where
    I: IntoIterator<Item = &'a Digest32>,
{
    candidates
        .into_iter()
        .filter(|m| can_dial(evaluator, m, service_tag))
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    // The authorization decisions are exercised end-to-end against a real
    // `Evaluator` built from genesis + delegation certs in the governance test
    // suite (the single golden-vector engine, ADR-007). Here we assert the
    // default-deny surface: with an evaluator that grants nothing, every gate
    // denies, and the deny is a `TunnelDenied`, not a panic or an allow.
    use super::*;
    use crate::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
    use crate::identity::composite::{RootSigner, SoftwareRootSigner};

    fn policy() -> ChannelPolicy {
        ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            deniability_mode: DeniabilityMode::Attributable,
            ttl: 0,
        }
    }

    /// A genesis-only channel: the root admin holds Admin (covers all); any other
    /// identity holds nothing — the default-deny case.
    fn genesis_only() -> (Evaluator, Digest32, Digest32) {
        let admin = SoftwareRootSigner::from_component_seeds(&[1; 32], &[2; 32]).unwrap();
        let genesis = Genesis::create_with_nonce(&admin, 0, policy(), [0x55; 16]).unwrap();
        let ev = Evaluator::build(&genesis, &[], 1_000, |_| None).unwrap();
        let stranger = SoftwareRootSigner::from_component_seeds(&[3; 32], &[4; 32]).unwrap();
        (ev, admin.fingerprint(), stranger.fingerprint())
    }

    #[test]
    fn default_deny_for_unprivileged_member() {
        let (ev, _admin, stranger) = genesis_only();
        assert!(!can_dial(&ev, &stranger, "ssh-hosts"));
        assert!(!can_bind(&ev, &stranger, "ssh-hosts"));
        assert!(matches!(
            authorize_dial(&ev, &stranger, "ssh-hosts"),
            Err(Error::TunnelDenied(_))
        ));
        assert!(matches!(
            authorize_bind(&ev, &stranger, "ssh-hosts"),
            Err(Error::TunnelDenied(_))
        ));
        assert!(dial_audience(&ev, "ssh-hosts", [&stranger]).is_empty());
    }

    #[test]
    fn root_admin_covers_dial_and_bind() {
        // Admin is top of the lattice and covers every capability, so the root
        // admin can both bind and dial any service.
        let (ev, admin, _stranger) = genesis_only();
        assert!(can_dial(&ev, &admin, "ssh-hosts"));
        assert!(can_bind(&ev, &admin, "ssh-hosts"));
        assert_eq!(dial_audience(&ev, "ssh-hosts", [&admin]), vec![admin]);
    }
}
