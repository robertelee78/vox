//! Multi-device strategy and per-channel pseudonymity (ADR-002 §Multi-device,
//! §Pseudonymity).
//!
//! Per the project decision, the multi-device strategy is the **member's choice**
//! and Vox provides **no device↔identity attestation**. This module models that
//! choice as a type and models per-channel identity-key selection as an explicit
//! operation. It is intentionally mostly type-modeling + invariants: there is no
//! attestation protocol to implement, and pretending otherwise would be a stub.

use crate::hash::Digest32;

/// The member-chosen multi-device strategy (ADR-002 §Multi-device).
///
/// Vox does not enforce or attest device↔identity linkage; this enum records the
/// member's chosen model so the client can represent it correctly (ADR-014) and
/// so consent/membership operate on the right unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceStrategy {
    /// **Shared-root**: the same root identity on multiple devices (root synced
    /// by the user out of band). Devices are indistinguishable; consent and
    /// membership operate on the one identity, and received consent / channel
    /// state are shared over the identity-keyed self-channel (ADR-008), so
    /// adding or restoring a shared-root device needs no re-consent by peers.
    SharedRoot,

    /// **Per-device keys**: each device is a distinct identity. Consent and
    /// membership operate on device keys as identities. A member MAY publish
    /// device sub-keys cross-signed by a shared root and present that linkage to
    /// peers, but that is member-managed convention, not Vox-enforced
    /// attestation. Clients MUST represent device-keys clearly so consent is
    /// never granted to an unrecognized device by accident (ADR-014).
    PerDeviceKey,
}

impl DeviceStrategy {
    /// Whether received consent and channel state are shared across this member's
    /// devices automatically over the self-channel (true only for
    /// [`SharedRoot`](Self::SharedRoot)).
    #[must_use]
    pub fn shares_consent_across_devices(self) -> bool {
        matches!(self, DeviceStrategy::SharedRoot)
    }

    /// Whether each device presents as a distinct identity to peers (true only
    /// for [`PerDeviceKey`](Self::PerDeviceKey)).
    #[must_use]
    pub fn devices_are_distinct_identities(self) -> bool {
        matches!(self, DeviceStrategy::PerDeviceKey)
    }
}

/// An explicit per-channel identity-key selection (ADR-002 §Pseudonymity).
///
/// Membership is attributable (ADR-009), so unlinkability is achieved
/// *operationally*: a member joins a channel under a dedicated identity key
/// rather than reusing one. Per-channel identity-key selection is a first-class,
/// explicit client operation (ADR-014); Vox never reuses an identity across
/// channels without the user choosing to. This type makes that choice explicit
/// and auditable: a channel is bound to exactly one chosen identity fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelIdentitySelection {
    /// The channel this selection applies to (channel ID, ADR-005/008).
    channel_id: Digest32,
    /// The fingerprint of the identity key the member chose for this channel.
    identity_fingerprint: Digest32,
}

impl ChannelIdentitySelection {
    /// Record that `identity_fingerprint` is the identity the member chose to use
    /// in `channel_id`. The caller is responsible for having actually generated /
    /// selected that identity; this type records and enforces the *one identity
    /// per channel selection* invariant downstream (a selection is immutable —
    /// changing personas is a new selection, surfaced to the user, ADR-014).
    #[must_use]
    pub fn new(channel_id: Digest32, identity_fingerprint: Digest32) -> Self {
        Self {
            channel_id,
            identity_fingerprint,
        }
    }

    /// The channel ID.
    #[must_use]
    pub fn channel_id(&self) -> &Digest32 {
        &self.channel_id
    }

    /// The chosen identity fingerprint for this channel.
    #[must_use]
    pub fn identity_fingerprint(&self) -> &Digest32 {
        &self.identity_fingerprint
    }

    /// Whether this selection uses the given identity. Used by clients to warn
    /// when a member is about to reuse a main identity in a channel where they
    /// previously chose a pseudonym (ADR-014 foot-gun guard).
    #[must_use]
    pub fn uses_identity(&self, fingerprint: &Digest32) -> bool {
        &self.identity_fingerprint == fingerprint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_root_shares_consent() {
        assert!(DeviceStrategy::SharedRoot.shares_consent_across_devices());
        assert!(!DeviceStrategy::SharedRoot.devices_are_distinct_identities());
    }

    #[test]
    fn per_device_key_is_distinct_identity() {
        assert!(DeviceStrategy::PerDeviceKey.devices_are_distinct_identities());
        assert!(!DeviceStrategy::PerDeviceKey.shares_consent_across_devices());
    }

    #[test]
    fn channel_selection_records_choice() {
        let chan = [1u8; 32];
        let id_a = [2u8; 32];
        let id_b = [3u8; 32];
        let sel = ChannelIdentitySelection::new(chan, id_a);
        assert_eq!(sel.channel_id(), &chan);
        assert_eq!(sel.identity_fingerprint(), &id_a);
        assert!(sel.uses_identity(&id_a));
        assert!(!sel.uses_identity(&id_b));
    }

    #[test]
    fn distinct_channels_can_select_distinct_identities() {
        // Pseudonymity: the same member uses different identities in two channels.
        let s1 = ChannelIdentitySelection::new([10u8; 32], [0xA0; 32]);
        let s2 = ChannelIdentitySelection::new([11u8; 32], [0xB0; 32]);
        assert_ne!(s1.identity_fingerprint(), s2.identity_fingerprint());
    }
}
