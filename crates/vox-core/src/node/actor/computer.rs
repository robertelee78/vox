//! Computer policy is daemon-owned. No public node command can forge a management binding.
use super::*;
use crate::identity::composite::RootSigner;
use crate::node::trust::HistoryGrant;

impl NodeHandle {
    /// Ask the already attached node to sign its management binding and durably apply policy.
    pub async fn reconcile_computer(&self) -> crate::error::Result<()> {
        let (reply, rx) = oneshot::channel();
        self.net_tx
            .send(NetEvent::ComputerPolicy(reply))
            .await
            .map_err(|_| Error::Unreachable("the node has stopped"))?;
        rx.await
            .map_err(|_| Error::Unreachable("the node has stopped"))?
    }
}

impl Node {
    pub(super) fn prepare_computer_binding(&self) -> crate::error::Result<()> {
        let Some(computer) = &self.computer else {
            return Ok(());
        };
        if computer.binding_group().is_none() {
            return Ok(());
        }
        let name = self
            .paths
            .profile_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(Error::Profile("managed node name is unreadable"))?;
        let personal = std::fs::read_to_string(self.paths.account().config_dir.join("app/node"))
            .ok()
            .is_some_and(|s| s.trim() == name);
        if let Some(p) = &self.profile {
            if p.is_unlocked() {
                return computer.bind_node(p.signer()?, name, personal);
            }
        }
        if let Some(s) = &self.headless {
            return computer.bind_node(s.as_ref(), name, false);
        }
        Err(Error::Profile(
            "managed node awaits its ordinary attach passphrase",
        ))
    }

    /// Before the endpoint registers, and before handling live authorization work, reconcile the
    /// durable plan. Persist the keyring before its journal receipt; repeat safely after a crash.
    pub(super) async fn apply_computer_keyring(&mut self) -> crate::error::Result<()> {
        let Some(c) = &self.computer else {
            return Ok(());
        };
        if !c.grouped()
            || self
                .computer_revision
                .load(std::sync::atomic::Ordering::Acquire)
                == c.revision()
        {
            return Ok(());
        }
        let mut floor = 0;
        for room in self.channels.values() {
            floor = floor.max(room.lock().await.newest_mint_seq());
        }
        self.apply_computer_keyring_at(floor)
    }

    pub(super) fn apply_computer_keyring_at(&mut self, floor: u64) -> crate::error::Result<()> {
        let Some(computer) = self.computer.clone() else {
            return Ok(());
        };
        if !computer.grouped() {
            return Ok(());
        }
        let revision = computer.revision();
        if self
            .computer_revision
            .load(std::sync::atomic::Ordering::Acquire)
            == revision
        {
            return Ok(());
        }
        let Some(profile) = &self.profile else {
            if let Some(signer) = &self.headless {
                computer.mark_applied(signer.fingerprint(), revision)?;
                self.computer_revision
                    .store(revision, std::sync::atomic::Ordering::Release);
            }
            return Ok(());
        };
        if !profile.is_unlocked() {
            return Ok(());
        }
        let me = profile.fingerprint();
        let Some((revision, plan)) = computer.plan(me)? else {
            return Ok(());
        };
        let mut next = self.trust.clone();
        let mut newly = Vec::new();
        let mut changed_drive = Vec::new();
        for (id, name, capability) in plan {
            if self.trust.capability(&id) == Some(capability) {
                continue;
            }
            if !self.trust.is_trusted(&id) {
                newly.push(id);
            }
            changed_drive.push((id, self.trust.has_drive(&id)));
            let name = self.trust.petname(&id).unwrap_or(&name).to_owned();
            let history = if self.trust.is_trusted(&id) {
                self.trust.history(&id)
            } else {
                HistoryGrant::Now
            };
            // Exact replacement consumes a stronger manual drive grant. There is no shadow grant.
            next.trust_as(id, &name, history, capability)?;
        }
        for id in newly {
            crate::node::consent_order::stamp_trust(profile.store(), profile.signer()?, id, floor)?;
        }
        let profile = self
            .profile
            .as_ref()
            .ok_or(Error::Profile("managed profile disappeared"))?;
        next.save(profile.store(), profile.signer()?)?;
        self.trust = next;
        for (id, was) in changed_drive {
            self.note_capability(id, was);
        }
        computer.mark_applied(me, revision)?;
        self.computer_revision
            .store(revision, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    pub(super) fn computer_change_refused(&self, command: &NodeCommand) -> bool {
        let Some(computer) = &self.computer else {
            return false;
        };
        if !computer.grouped() {
            return false;
        }
        let Some(me) = self.profile.as_ref().map(Profile::fingerprint) else {
            return false;
        };
        let (peer, requested) = match command {
            NodeCommand::Proved { change, .. } => return self.computer_change_refused(change),
            NodeCommand::Untrust { fingerprint } => (*fingerprint, None),
            NodeCommand::SetCapability {
                fingerprint,
                capability,
            } => (*fingerprint, Some(*capability)),
            NodeCommand::TrustWith {
                fingerprint,
                capability,
                ..
            } => (*fingerprint, Some(capability.unwrap_or_default())),
            NodeCommand::Trust { fingerprint, .. } => {
                (*fingerprint, Some(crate::node::trust::Capability::Read))
            }
            _ => return false,
        };
        match computer.capability(me, &peer) {
            Ok(Some(expected)) => requested != Some(expected),
            Ok(None) => false,
            Err(_) => true,
        }
    }
}
