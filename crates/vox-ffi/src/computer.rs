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
/// Application receipt for one member at the exact current group frontier.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ComputerApplication {
    /// Enrolled installation.
    pub computer: ComputerIdentity,
    /// Verified complete application; false means pending, not necessarily offline.
    pub confirmed: bool,
}
impl From<core::ComputerApplication> for ComputerApplication {
    fn from(v: core::ComputerApplication) -> Self {
        Self {
            computer: v.computer.into(),
            confirmed: v.confirmed,
        }
    }
}
/// Authenticated managed-node presentation and role.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ComputerNode {
    /// Full managing computer identity.
    pub computer: String,
    /// Full node fingerprint.
    pub fingerprint: String,
    /// Presented node name; local aliases remain separate.
    pub name: String,
    /// Saved personal selection.
    pub personal: bool,
}
impl From<core::ComputerNode> for ComputerNode {
    fn from(v: core::ComputerNode) -> Self {
        Self {
            computer: v.computer,
            fingerprint: v.fingerprint,
            name: v.name,
            personal: v.personal,
        }
    }
}
/// Available explicit binding operation, backed by retained authenticated evidence.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ComputerBindingAction {
    /// Full node identity.
    pub node: String,
    /// Authenticated presented name.
    pub name: String,
    /// Previous manager identity.
    pub computer: String,
    /// release / transfer / recover.
    pub action: String,
}
impl From<core::ComputerBindingAction> for ComputerBindingAction {
    fn from(v: core::ComputerBindingAction) -> Self {
        Self {
            node: v.node,
            name: v.name,
            computer: v.computer,
            action: v.action,
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
    /// Each enrolled member’s exact-frontier application receipt.
    pub applications: Vec<ComputerApplication>,
    /// Authenticated roster and selected personal roles.
    pub nodes: Vec<ComputerNode>,
    /// Explicit source-release or destination transfer/recovery choices.
    pub binding_actions: Vec<ComputerBindingAction>,
    /// Removed members; remote erasure is never asserted.
    pub removed: Vec<ComputerIdentity>,
    /// Exact displayed removal confirmation frontier.
    pub frontier: String,
    /// Saved local personal node, if selected.
    pub selected_node: Option<String>,
    /// Saved authenticated local selection name.
    pub selected_name: Option<String>,
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
            applications: v.applications.into_iter().map(Into::into).collect(),
            nodes: v.nodes.into_iter().map(Into::into).collect(),
            binding_actions: v.binding_actions.into_iter().map(Into::into).collect(),
            removed: v.removed.into_iter().map(Into::into).collect(),
            frontier: v.frontier,
            selected_node: v.selected_node,
            selected_name: v.selected_name,
            pending_nodes: v.pending_nodes,
            problem: v.problem,
        }
    }
}
