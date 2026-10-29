//! Daemon-only local trust (ADR-031 LT-1–6). No IPC request exposes these operations.
use super::*;
use crate::node::trust::Capability;

impl NodeHandle {
    /// The daemon reads manual-removal exclusions from an unlocked node it already owns.
    /// `None` means the node has no ready vault; it must not participate in automatic trust yet.
    ///
    /// # Errors
    /// The actor stopped, or retained removal history cannot be read or saved.
    pub async fn local_trust_blacklist(&self) -> crate::error::Result<Option<BTreeSet<Digest32>>> {
        let (reply, rx) = oneshot::channel();
        self.net_tx
            .send(NetEvent::LocalTrustBlacklist(reply))
            .await
            .map_err(|_| Error::Unreachable("the node has stopped"))?;
        rx.await
            .map_err(|_| Error::Unreachable("the node has stopped"))?
    }

    /// Apply one grant derived by the owning daemon from its local actors and personal-node
    /// selection. This is deliberately separate from user/IPC keyring commands and their window.
    pub async fn trust_local_node(
        &self,
        fingerprint: Digest32,
        name: String,
        capability: Capability,
    ) -> Outcome {
        let (reply, rx) = oneshot::channel();
        if self
            .net_tx
            .send(NetEvent::TrustLocalNode {
                fingerprint,
                name,
                capability,
                reply,
            })
            .await
            .is_err()
        {
            return Outcome::Failed(Fault::Internal);
        }
        rx.await.unwrap_or(Outcome::Failed(Fault::Internal))
    }
}
