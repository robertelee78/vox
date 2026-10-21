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
/// One completed management-state exchange, with the policy revisions it carried.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ExchangeRecord {
    /// Unix milliseconds when the exchange completed.
    pub at_ms: u64,
    /// This daemon's policy revision sent to the peer.
    pub sent_revision: u64,
    /// This daemon's policy revision after merging the peer's state.
    pub merged_revision: u64,
}
impl From<core::ExchangeRecord> for ExchangeRecord {
    fn from(v: core::ExchangeRecord) -> Self {
        Self {
            at_ms: v.at_ms,
            sent_revision: v.sent_revision,
            merged_revision: v.merged_revision,
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
    /// Last completed exchange since this daemon started.
    pub last_exchange_ms: Option<u64>,
    /// Completed exchanges since this daemon started.
    pub exchanges: u64,
    /// Started exchanges since this daemon started, including failures.
    pub exchange_attempts: u64,
    /// Consecutive exchanges which did not satisfy their causal contract.
    pub exchange_failures: u32,
    /// Last exchange this daemon started with the member.
    pub last_started_exchange: Option<ExchangeRecord>,
    /// Last exchange the member started and this daemon answered.
    pub last_answered_exchange: Option<ExchangeRecord>,
}
impl From<core::ComputerApplication> for ComputerApplication {
    fn from(v: core::ComputerApplication) -> Self {
        Self {
            computer: v.computer.into(),
            confirmed: v.confirmed,
            last_exchange_ms: v.last_exchange_ms,
            exchanges: v.exchanges,
            exchange_attempts: v.exchange_attempts,
            exchange_failures: v.exchange_failures,
            last_started_exchange: v.last_started_exchange.map(Into::into),
            last_answered_exchange: v.last_answered_exchange.map(Into::into),
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
    /// Policy revision at which this local binding was last derived.
    pub binding_revision: Option<u64>,
    /// Unix milliseconds when this local binding was last derived.
    pub binding_derived_ms: Option<u64>,
}
impl From<core::ComputerNode> for ComputerNode {
    fn from(v: core::ComputerNode) -> Self {
        Self {
            computer: v.computer,
            fingerprint: v.fingerprint,
            name: v.name,
            personal: v.personal,
            binding_revision: v.binding_revision,
            binding_derived_ms: v.binding_derived_ms,
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
    /// Current computer-policy revision.
    pub revision: u64,
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
            revision: v.revision,
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
