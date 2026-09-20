//! Invite modes — how a newcomer's identity is known (ADR-007 §"Invite modes").
//!
//! Neither mode involves an admin *admitting* anyone: membership is consent-based.
//! What an invite establishes is **how a joiner's identity is recognized**, chosen
//! by whoever shares the channel:
//!
//! - **Identity-bound invite (high-trust default).** The out-of-band invite names
//!   the newcomer's identity fingerprint, so members know which identity to expect
//!   and verify before consent-granting. Issued under the `invite` capability
//!   ([`crate::governance::capability::Capability::Invite`]). The joiner is
//!   recognized on arrival.
//! - **Open passphrase join.** Anyone with `channelID + passphrase` joins the
//!   swarm (ADR-005/M3) and appears as an *unverified* self-asserted identity until
//!   a member verifies the fingerprint and consents.
//!
//! **The passphrase gates the swarm; per-sender consent gates reading.** There is
//! no admin admission. This module is the small, explicit representation of an
//! invite an inviter hands out and a joiner presents; the *authorization* to issue
//! an identity-bound invite (the `invite` capability) is checked by the evaluator
//! ([`crate::governance::evaluator::Evaluator::grants`]), not here.

use crate::governance::capability::Capability;
use crate::governance::evaluator::Evaluator;
use crate::hash::Digest32;

/// Which invite mode established a joiner's identity recognition (ADR-007).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InviteMode {
    /// Identity-bound (high-trust default): the invite names the expected newcomer
    /// fingerprint. Members verify *this* identity before consenting.
    IdentityBound {
        /// The newcomer's expected identity fingerprint (ADR-002).
        newcomer_fingerprint: Digest32,
    },
    /// Open passphrase join: anyone with the passphrase joins the swarm and is an
    /// unverified self-asserted identity until a member verifies + consents.
    OpenPassphrase,
}

/// An invite shared out-of-band by a channel member.
///
/// It binds the invite to a `(channelID, epoch)` and records the inviter (whose
/// `invite` capability authorizes an identity-bound invite). An open-passphrase
/// invite needs no special capability — the passphrase itself gates the swarm — so
/// the inviter field documents provenance but is not an authority claim in that
/// mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// The channel this invite is for (ADR-005).
    pub channel_id: Digest32,
    /// The membership epoch in force when issued (ADR-007).
    pub epoch: u64,
    /// The inviting member's identity fingerprint.
    pub inviter_id: Digest32,
    /// How the joiner's identity is established.
    pub mode: InviteMode,
}

impl Invite {
    /// An identity-bound invite naming the expected newcomer fingerprint (the
    /// high-trust default). Issuing this requires the `invite` capability — the
    /// caller checks that via the evaluator before sharing it.
    #[must_use]
    pub fn identity_bound(
        channel_id: Digest32,
        epoch: u64,
        inviter_id: Digest32,
        newcomer_fingerprint: Digest32,
    ) -> Self {
        Self {
            channel_id,
            epoch,
            inviter_id,
            mode: InviteMode::IdentityBound {
                newcomer_fingerprint,
            },
        }
    }

    /// An open passphrase invite: anyone with the passphrase joins the swarm as an
    /// unverified identity. No `invite` capability is needed (the passphrase gates
    /// the swarm).
    #[must_use]
    pub fn open_passphrase(channel_id: Digest32, epoch: u64, inviter_id: Digest32) -> Self {
        Self {
            channel_id,
            epoch,
            inviter_id,
            mode: InviteMode::OpenPassphrase,
        }
    }

    /// Whether this invite *requires* the inviter to hold the `invite` capability.
    /// Only identity-bound invites do (ADR-007); open passphrase joins do not.
    #[must_use]
    pub fn requires_invite_capability(&self) -> bool {
        matches!(self.mode, InviteMode::IdentityBound { .. })
    }

    /// For an identity-bound invite, whether `presented` matches the expected
    /// newcomer fingerprint (the recognition check a member performs on arrival).
    /// For an open passphrase invite this is always `false` — there is no
    /// pre-named identity to match (the joiner is unverified until verified
    /// out-of-band).
    #[must_use]
    pub fn recognizes(&self, presented: &Digest32) -> bool {
        match &self.mode {
            InviteMode::IdentityBound {
                newcomer_fingerprint,
            } => newcomer_fingerprint == presented,
            InviteMode::OpenPassphrase => false,
        }
    }

    /// Whether this invite is **authorized to be issued/shared** by its inviter,
    /// checked against the channel's governance state via `evaluator`. An
    /// identity-bound invite requires the inviter to currently hold the `invite`
    /// capability ([`crate::governance::capability::Capability::Invite`], which
    /// `admin` implies); an open-passphrase invite needs no capability (the
    /// passphrase gates the swarm). Callers (the UI / share path) MUST gate sharing
    /// on this so an unauthorized member cannot mint identity-bound invites
    /// (ADR-007 §"Invite modes").
    #[must_use]
    pub fn is_authorized(&self, evaluator: &Evaluator) -> bool {
        match self.mode {
            InviteMode::OpenPassphrase => true,
            InviteMode::IdentityBound { .. } => evaluator
                .grants(&self.inviter_id, &Capability::Invite)
                .is_granted(),
        }
    }
}
