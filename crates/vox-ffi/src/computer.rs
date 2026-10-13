//! Public computer-pairing facts; node and management signing keys remain in the daemon.
use vox_core::node::computer as core;

/// One authenticated Vox installation, distinct from physical hardware or another data root.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ComputerIdentity {
    /// Presented name.
    pub name: String,
    /// Full management fingerprint.
    pub fingerprint: String,
    /// Stable installation discriminator.
    pub installation: String,
}
impl From<core::ComputerIdentity> for ComputerIdentity {
    fn from(v: core::ComputerIdentity) -> Self {
        Self {
            name: v.name,
            fingerprint: v.fingerprint,
            installation: v.installation,
        }
    }
}
/// Exact candidate which has proved both identity and possession of the pairing secret.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PairingPreview {
    /// Opaque operation identifier; approve this exact displayed value.
    pub operation_id: String,
    /// Authenticated remote presentation.
    pub peer: ComputerIdentity,
    /// Local approval has been durably recorded.
    pub approved_here: bool,
    /// Peer approval has been verified and retained.
    pub approved_there: bool,
    /// Unix milliseconds when an unconsumed invitation expires.
    pub expires_ms: u64,
}
impl From<core::PairingPreview> for PairingPreview {
    fn from(v: core::PairingPreview) -> Self {
        Self {
            operation_id: v.operation_id,
            peer: v.peer.into(),
            approved_here: v.approved_here,
            approved_there: v.approved_there,
            expires_ms: v.expires_ms,
        }
    }
}
/// Public daemon-wide pairing state, independent of any selected chat node.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ComputerStatus {
    /// This installation.
    pub this_computer: ComputerIdentity,
    /// Fixed permission policy, shown before confirmation.
    pub policy: String,
    /// individual / waiting / needs-approval / applying / confirmed.
    pub state: String,
    /// One-time invitation, never included in logs or error messages.
    pub invite_link: Option<String>,
    /// Cancellation identifier before the peer has proved itself.
    pub invite_id: Option<String>,
    /// Invitation expiry, Unix milliseconds.
    pub invite_expires_ms: Option<u64>,
    /// Authenticated candidate, if any.
    pub pairing: Option<PairingPreview>,
    /// Explicitly enrolled installations.
    pub computers: Vec<ComputerIdentity>,
    /// Nodes still requiring normal attach or policy reconciliation.
    pub pending_nodes: Vec<String>,
    /// Reachability or protocol problem; never evidence of success.
    pub problem: Option<String>,
}
impl From<core::ComputerStatus> for ComputerStatus {
    fn from(v: core::ComputerStatus) -> Self {
        Self {
            this_computer: v.this_computer.into(),
            policy: v.policy,
            state: v.state,
            invite_link: v.invite_link,
            invite_id: v.invite_id,
            invite_expires_ms: v.invite_expires_ms,
            pairing: v.pairing.map(Into::into),
            computers: v.computers.into_iter().map(Into::into).collect(),
            pending_nodes: v.pending_nodes,
            problem: v.problem,
        }
    }
}
