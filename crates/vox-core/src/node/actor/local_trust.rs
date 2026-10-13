//! Daemon-only local trust (ADR-031 LT-1–6). No IPC request exposes these operations.
use super::*;
use crate::node::trust::{Capability, HistoryGrant};

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

impl Node {
    pub(super) fn import_local_trust_history(&mut self) -> crate::error::Result<()> {
        if self.trust.local_history_imported() {
            self.decisions.hold_for_local_trust_import(false);
            return Ok(());
        }
        let profile = self.profile.as_ref().ok_or(Error::Profile("no identity"))?;
        let signer = profile.signer()?;
        let removed = self.decisions.local_trust_removals()?;
        let mut next = self.trust.clone();
        next.import_local_removals(removed);
        next.save(profile.store(), signer)?;
        self.trust = next;
        self.decisions.hold_for_local_trust_import(false);
        Ok(())
    }

    pub(super) fn local_trust_blacklist(
        &mut self,
    ) -> crate::error::Result<Option<BTreeSet<Digest32>>> {
        if self.profile.as_ref().is_none_or(|p| !p.is_unlocked()) {
            return Ok(None);
        }
        self.import_local_trust_history()?;
        Ok(Some(self.trust.local_removals().clone()))
    }

    pub(super) async fn trust_local_node(
        &mut self,
        fingerprint: Digest32,
        name: &str,
        capability: Capability,
    ) -> Outcome {
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        if !profile.is_unlocked() {
            return Outcome::Failed(Fault::Locked);
        }
        if fingerprint == profile.fingerprint() {
            return Outcome::Done;
        }
        if let Err(e) = self.import_local_trust_history() {
            return Outcome::Failed(fault_of(&e));
        }
        // Recheck inside the actor: a queued grant must not undo a removal processed since
        // the daemon read its snapshot.
        if self.trust.local_removals().contains(&fingerprint) {
            return Outcome::Done;
        }
        let held = self.trust.capability(&fingerprint);
        if held.is_some_and(|held| held >= capability) {
            return Outcome::Done;
        }
        let name = self.trust.petname(&fingerprint).unwrap_or(name).to_owned();
        let history = if held.is_some() {
            self.trust.history(&fingerprint)
        } else {
            HistoryGrant::Now
        };
        let outcome = self
            .trust_identity(fingerprint, &name, history, Some(capability))
            .await;
        if matches!(outcome, Outcome::Done) {
            self.decided(
                "to trust a node of this computer",
                fingerprint,
                None,
                crate::node::decisions::Decided::Trusted,
                format!(
                    "the daemon applied this computer's local trust rule: {}",
                    capability.words()
                ),
            );
        }
        outcome
    }
}
