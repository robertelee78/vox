//! Computer policy is daemon-owned. No public node command can forge a management binding.
use super::*;
use crate::identity::composite::RootSigner;
use crate::node::trust::HistoryGrant;

impl NodeHandle {
    /// Current daemon policy for rendering individual Trust actions. This is an observation,
    /// never an authorization token: every mutation reconciles and checks policy again.
    pub fn individual_trust_eligibility(&self, peer: Digest32) -> (bool, String) {
        let view = self.view();
        let Some(me) = view.identity.as_ref().map(|id| id.fingerprint) else {
            return (
                false,
                "make this node Ready before changing individual trust".into(),
            );
        };
        if self.cmd_tx.is_closed() || view.locked || view.locking {
            return (
                false,
                "make this node Ready before changing individual trust".into(),
            );
        }
        if me == peer {
            return (false, "a node does not grant trust to itself".into());
        }
        let Some(computer) = &self.computer else {
            return (true, String::new());
        };
        let applied = self
            .computer_revision
            .load(std::sync::atomic::Ordering::Acquire);
        if !computer.policy_current(applied) {
            return (
                false,
                "computer policy is pending application on this node".into(),
            );
        }
        let result = match computer.capability(me, &peer) {
            Ok(Some(_)) => (false, "this node's trust is managed by My computers".into()),
            Ok(None) => (true, String::new()),
            Err(e) => (false, e.to_string()),
        };
        if !computer.policy_current(applied) {
            return (
                false,
                "computer policy changed; refresh before changing individual trust".into(),
            );
        }
        result
    }

    /// Whether this node stands at the current computer policy: its binding derived at the
    /// current revision and its keyring applied at it (ADR-038 FX-28). A node that does has
    /// nothing to reconcile; the daemon asks it to only when a change moved the revision.
    pub fn computer_current(&self) -> bool {
        let Some(computer) = &self.computer else {
            return true;
        };
        if !computer.grouped() && computer.binding_group().is_none() {
            return true;
        }
        let applied = self
            .computer_revision
            .load(std::sync::atomic::Ordering::Acquire);
        let me = self
            .view_rx
            .borrow()
            .identity
            .as_ref()
            .map(|id| id.fingerprint);
        computer.policy_current(applied) && me.is_some_and(|me| computer.binding_current(&me))
    }

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
        if let Some(p) = &self.profile {
            if p.is_unlocked() {
                return computer.bind_node(p.signer()?, name);
            }
        }
        if let Some(s) = &self.headless {
            return computer.bind_node(s.as_ref(), name);
        }
        Err(Error::Profile(
            "managed node needs its passphrase to become Ready",
        ))
    }

    /// Before the endpoint registers, and before handling live authorization work, reconcile the
    /// durable plan. Persist the keyring before its journal receipt; repeat safely after a crash.
    pub(super) async fn apply_computer_keyring(&mut self) -> crate::error::Result<()> {
        let Some(c) = &self.computer else {
            return Ok(());
        };
        if c.grouped() {
            c.storage_ready()?;
        }
        if !c.grouped()
            || self
                .computer_revision
                .load(std::sync::atomic::Ordering::Acquire)
                == c.revision()
        {
            return Ok(());
        }
        for _ in 0..8 {
            let mut floor = 0;
            for room in self.channels.values() {
                floor = floor.max(room.lock().await.newest_mint_seq());
            }
            let changes = self.apply_computer_keyring_at(floor)?;
            // A policy revision can grant an already admitted member read or drive. That member
            // may not have received the live capability record before this boundary, so publish
            // discovery again. It carries no authority; rooms coalesce it to one signed record.
            self.owe_private_support_in_open_rooms().await;
            for (id, stamp) in changes {
                self.mark_trust_decision(id, stamp).await;
            }
            // The existing room machinery performs pending removals, sender-key rotation, and
            // consent delivery. Computer policy does not create a second room authorization path.
            self.refresh_reachers().await;
            for prepared in self.preparing_rooms.values_mut() {
                prepared.channel.get_mut().release_held_packages();
            }
            let rooms: Vec<_> = self.channels.keys().copied().collect();
            for room in rooms {
                self.act_on_removals_while_closed(&room).await?;
                self.mark_decisions_on_open(&room).await?;
                if let Some(channel) = self.channels.get(&room) {
                    channel.lock().await.release_held_packages();
                }
                self.install_key_packages(&room).await;
            }
            self.deliver_owed_consents(None).await;
            self.tend_drive_keys().await;
            self.publish().await;
            if self.computer.as_ref().is_none_or(|c| {
                c.revision()
                    == self
                        .computer_revision
                        .load(std::sync::atomic::Ordering::Acquire)
            }) {
                return Ok(());
            }
        }
        Err(Error::Profile(
            "computer policy is still changing; this node is not ready to authorize requests",
        ))
    }

    pub(super) fn apply_computer_keyring_at(
        &mut self,
        floor: u64,
    ) -> crate::error::Result<Vec<(Digest32, crate::node::consent_order::Stamp)>> {
        let Some(computer) = self.computer.clone() else {
            return Ok(Vec::new());
        };
        if !computer.grouped() {
            return Ok(Vec::new());
        }
        computer.storage_ready()?;
        let revision = computer.revision();
        if self
            .computer_revision
            .load(std::sync::atomic::Ordering::Acquire)
            == revision
        {
            return Ok(Vec::new());
        }
        let Some(profile) = &self.profile else {
            if let Some(signer) = &self.headless {
                computer.mark_applied(signer.fingerprint(), revision, &[])?;
                self.computer_revision
                    .store(revision, std::sync::atomic::Ordering::Release);
            }
            return Ok(Vec::new());
        };
        if !profile.is_unlocked() {
            return Ok(Vec::new());
        }
        let me = profile.fingerprint();
        let Some(plan) = computer.plan(me)? else {
            return Ok(Vec::new());
        };
        let revision = plan.revision;
        let covered: Vec<_> = plan
            .grants
            .iter()
            .map(|(id, _, _)| *id)
            .chain(plan.denied.iter().copied())
            .collect();
        let aliases: Vec<_> = covered
            .iter()
            .filter_map(|peer| {
                self.trust
                    .petname(peer)
                    .map(|name| (*peer, name.to_owned()))
            })
            .collect();
        computer.retain_aliases(me, &aliases)?;
        let mut next = self.trust.clone();
        let mut newly = Vec::new();
        let mut changed_drive = Vec::new();
        // Persist closed/open room removal work before removing the keyring entry. On a crash,
        // the ordinary room reopen path finishes it before authorizing new room activity.
        let mut locks =
            crate::node::pending_lock::PendingLocks::load(profile.store(), profile.signer()?)?;
        let mut pending = self.consent_keys.clone();
        let rooms = profile.store().channels()?;
        for id in &plan.denied {
            if !next.is_trusted(id) {
                continue;
            }
            for room in &rooms {
                if !locks.insert(*room, *id) {
                    return Err(Error::Profile(
                        "computer trust removal could not be recorded",
                    ));
                }
            }
            pending.forget(id);
            changed_drive.push((*id, next.has_drive(id)));
            next.untrust(id);
            let _ =
                crate::node::consent_order::forget_trust(profile.store(), profile.signer()?, id);
        }
        locks.save(profile.store(), profile.signer()?)?;
        pending.save(profile.store(), profile.signer()?)?;
        self.consent_keys = pending;
        for (id, name, capability) in plan.grants {
            if self.trust.capability(&id) == Some(capability) {
                continue;
            }
            if !self.trust.is_trusted(&id) {
                newly.push(id);
            }
            changed_drive.push((id, self.trust.has_drive(&id)));
            let name = self
                .trust
                .petname(&id)
                .map(str::to_owned)
                .or_else(|| computer.alias(&me, &id))
                .unwrap_or(name);
            let history = if self.trust.is_trusted(&id) {
                self.trust.history(&id)
            } else {
                HistoryGrant::Now
            };
            // Exact replacement consumes a stronger manual drive grant. There is no shadow grant.
            next.trust_as(id, &name, history, capability)?;
        }
        let mut changes = Vec::new();
        for id in newly {
            changes.push((
                id,
                crate::node::consent_order::stamp_trust(
                    profile.store(),
                    profile.signer()?,
                    id,
                    floor,
                )?,
            ));
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
        computer.mark_applied(me, revision, &covered)?;
        self.view_tx.send_modify(|view| {
            view.trusted = self.trust_rows();
            view.drive = self
                .trust
                .iter()
                .map(|(fp, _)| *fp)
                .filter(|fp| self.trust.has_drive(fp))
                .collect();
        });
        self.computer_revision
            .store(revision, std::sync::atomic::Ordering::Release);
        Ok(changes)
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
