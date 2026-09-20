//! Emergent membership and per-sender visibility (ADR-007 §"Join and per-sender
//! consent flow", §"Conflict resolution").
//!
//! **Membership is emergent, not a roster** (ADR-007): you are *in the swarm* by
//! holding the passphrase (ADR-005/M3), and you are *readable* by whoever has
//! consent-granted to you. There is no admin-issued membership certificate and no
//! admin-maintained member list to forge — the Signalgate / Megolm
//! membership-injection class is structurally absent.
//!
//! This module derives the "who can read whom" view **from the log** (via the
//! deterministic [`crate::governance::evaluator::Evaluator`]) and exposes the
//! per-sender, monotonic visibility ADR-007 promises:
//! - a reader `N`'s readable set fills in **monotonically, per sender**: each
//!   member `A` independently decides whether to consent, and until `A` does, `A`'s
//!   messages are undecryptable to `N` — forever if `A` never consents.
//!
//! It also provides the consent issuing seam: building the consent-grant entry
//! that carries `skdm_ref` (the SHA-256 of the SKDM delivered over M4's pairwise
//! session), and the consent-revocation entry that records `A`'s `chain_id`
//! rotation excluding the revoked target. The SKDM and the actual sender-key
//! rotation are M4's job; M6 authors the signed log facts.

use std::collections::BTreeSet;

use crate::error::Result;
use crate::governance::consent::{ConsentGrant, ConsentRevocation};
use crate::governance::evaluator::Evaluator;
use crate::governance::genesis::HistoryMode;
use crate::governance::visibility::VisibilitySet;
use crate::group::Skdm;
use crate::hash::{sha256, Digest32};
use crate::identity::composite::RootSigner;

/// The emergent membership / readability view over a channel, derived from the
/// governance log via the [`Evaluator`].
///
/// Borrows the evaluator: the view is exactly the consent edges the evaluator
/// resolved (single-writer, latest-causal), with no separate roster. It composes
/// outbound consent (the log) with an optional inbound [`VisibilitySet`] (local,
/// receiver-side) at the render decision.
#[derive(Debug)]
pub struct MembershipView<'a> {
    evaluator: &'a Evaluator,
}

impl<'a> MembershipView<'a> {
    /// View the emergent membership/readability over the given evaluator.
    #[must_use]
    pub fn new(evaluator: &'a Evaluator) -> Self {
        Self { evaluator }
    }

    /// Whether `reader` may currently read `author`'s messages on the **outbound**
    /// (consent) axis. This is the authoritative log-derived readability.
    #[must_use]
    pub fn can_read(&self, reader: &Digest32, author: &Digest32) -> bool {
        self.evaluator.can_read(reader, author)
    }

    /// Whether `viewer` would actually **render** `author`, composing both axes:
    /// `author` has consent-granted to `viewer` (outbound, the log) **and**
    /// `viewer` has not muted `author` (inbound, local `VisibilitySet`). This is
    /// the render-site decision (ADR-007: the two axes are orthogonal and
    /// independently set).
    #[must_use]
    pub fn renders(&self, viewer: &Digest32, author: &Digest32, inbound: &VisibilitySet) -> bool {
        self.can_read(viewer, author) && inbound.is_visible(author)
    }

    /// The set of authors `reader` may currently read, derived by asking the
    /// evaluator which authors consent to `reader`. This is `reader`'s monotonic
    /// per-sender readable set (ADR-007): it grows as more members consent and
    /// shrinks only when a member revokes (forward-only).
    #[must_use]
    pub fn readable_authors(
        &self,
        reader: &Digest32,
        all_authors: &[Digest32],
    ) -> BTreeSet<Digest32> {
        all_authors
            .iter()
            .copied()
            .filter(|a| self.evaluator.can_read(reader, a))
            .collect()
    }

    /// The set of identities `author` currently consents to (who may read
    /// `author`), in deterministic order.
    #[must_use]
    pub fn readers_of(&self, author: &Digest32) -> BTreeSet<Digest32> {
        self.evaluator.readers_of(author)
    }
}

/// Compute the `skdm_ref` a consent-grant entry carries: the SHA-256 of the framed
/// SKDM `A` delivered to the target over the M4 pairwise session (ADR-007 — the
/// entry carries only this hash; the SKDM itself travels out-of-band).
#[must_use]
pub fn skdm_ref(skdm: &Skdm) -> Digest32 {
    sha256(&skdm.to_wire())
}

/// Issue a consent grant: `A` releasing `A`'s sender key to `target`.
///
/// This authors the signed consent-grant log entry ([`ConsentGrant`]) carrying the
/// `skdm_ref` of the SKDM `A` delivered to `target` over M4's pairwise session, and
/// the history mode in force at grant time (which decided whether `A` released its
/// origin or current chain key, ADR-006/M4). The SKDM delivery itself is M4's job;
/// this is the M6 log fact that records the consent.
pub fn issue_consent_grant(
    author_root: &dyn RootSigner,
    channel_id: &Digest32,
    epoch: u64,
    target: Digest32,
    delivered_skdm: &Skdm,
    history_mode_at_grant: HistoryMode,
) -> Result<ConsentGrant> {
    ConsentGrant::build(
        author_root,
        channel_id,
        epoch,
        target,
        skdm_ref(delivered_skdm),
        history_mode_at_grant,
    )
}

/// Issue a consent revocation: `A` withdrawing `target`'s access to `A`'s **future**
/// messages by rotating `A`'s own `chain_id` to `new_chain_id` (excluding
/// `target`). This authors the signed consent-revocation log entry; the actual
/// sender-key rotation + SKDM redistribution to the remaining consenters is M4's
/// job. Only the forward guarantee is cryptographic — `target` keeps the old
/// (now-uncallable) keys and cannot read `A`'s future, but already-held traffic is
/// not recalled (ADR-007 §"Enforcement honesty").
pub fn issue_consent_revocation(
    author_root: &dyn RootSigner,
    channel_id: &Digest32,
    epoch: u64,
    target: Digest32,
    new_chain_id: u64,
) -> Result<ConsentRevocation> {
    ConsentRevocation::build(author_root, channel_id, epoch, target, new_chain_id)
}
