//! Computer policy is daemon-owned. No public node command can forge a management binding.
use super::*;
use crate::identity::composite::RootSigner;
use crate::node::trust::HistoryGrant;

/// **Test-only** (`test-knobs`): `<node>\t<arm>\t<engaged>\t<release socket>`. The actor consumes
/// `arm`, creates `engaged`, and waits for one connection to `release`. The shipped-binary proof
/// can therefore hold and release the exact actor message causally, without a sleep standing in
/// for product behavior. Shipped builds neither name nor read this variable (V210-105).
#[cfg(feature = "test-knobs")]
const TEST_HOLD_COMPUTER_POLICY_ENV: &str = "VOX_TEST_HOLD_COMPUTER_POLICY";
#[cfg(feature = "test-knobs")]
const TEST_HOLD_COMPUTER_POLICY_REPLY_ENV: &str = "VOX_TEST_HOLD_COMPUTER_POLICY_REPLY";

#[cfg(feature = "test-knobs")]
impl Node {
    pub(super) async fn hold_computer_policy_for_proof(&self) {
        let Ok(spec) = std::env::var(TEST_HOLD_COMPUTER_POLICY_ENV) else {
            return;
        };
        let mut fields = spec.splitn(4, '\t');
        let (Some(node), Some(arm), Some(engaged), Some(release)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return;
        };
        let mine = self
            .paths
            .profile_dir
            .file_name()
            .and_then(|name| name.to_str());
        if mine != Some(node) || std::fs::remove_file(arm).is_err() {
            return;
        }
        let _ = std::fs::remove_file(release);
        let Ok(listener) = tokio::net::UnixListener::bind(release) else {
            return;
        };
        if std::fs::write(engaged, b"computer policy actor held\n").is_err() {
            return;
        }
        let _ = listener.accept().await;
        let _ = std::fs::remove_file(engaged);
        let _ = std::fs::remove_file(release);
    }

    /// Test apparatus: delay only the reply to an applied policy event, leaving the actor free
    /// to detach. This stages a replacement attachment before an old reconciliation resolves.
    #[cfg(feature = "test-knobs")]
    pub(super) fn hold_computer_policy_reply_for_proof(&self) -> Option<Duration> {
        let spec = std::env::var(TEST_HOLD_COMPUTER_POLICY_REPLY_ENV).ok()?;
        let mut fields = spec.splitn(3, '\t');
        let (node, milliseconds, marker) = (fields.next()?, fields.next()?, fields.next()?);
        let mine = self.paths.profile_dir.file_name()?.to_str()?;
        if mine != node || !std::path::Path::new(marker).is_file() {
            return None;
        }
        let delay = milliseconds
            .parse::<u64>()
            .ok()
            .map(Duration::from_millis)?;
        // One-shot, and observable by the apparatus: its disappearance proves the old actor
        // accepted the event before the proof replaces that attachment.
        std::fs::remove_file(marker).ok()?;
        Some(delay)
    }
}

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
    pub async fn reconcile_computer(
        &self,
        deadline: std::time::Instant,
    ) -> crate::error::Result<()> {
        let (reply, rx) = oneshot::channel();
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let send = self.net_tx.send(NetEvent::ComputerPolicy {
            deadline,
            cancelled: Arc::clone(&cancelled),
            reply,
        });
        tokio::pin!(send);
        tokio::select! {
            result = &mut send => {
                result.map_err(|_| Error::Unreachable("the node has stopped"))?;
            }
            () = tokio::time::sleep_until(deadline.into()) => {
                cancelled.store(true, std::sync::atomic::Ordering::Release);
                return Err(Error::Profile("computer trust did not enter the actor before its causal deadline"));
            }
        }
        tokio::pin!(rx);
        tokio::select! {
            biased;
            result = &mut rx => {
                let result = result.map_err(|_| Error::Unreachable("the node has stopped"))?;
                if std::time::Instant::now() >= deadline {
                    cancelled.store(true, std::sync::atomic::Ordering::Release);
                    Err(Error::Profile("computer trust did not apply before its causal deadline"))
                } else {
                    result
                }
            }
            () = tokio::time::sleep_until(deadline.into()) => {
                cancelled.store(true, std::sync::atomic::Ordering::Release);
                Err(Error::Profile("computer trust did not apply before its causal deadline"))
            }
        }
    }
}

impl Node {
    /// Whether this actor's live trust/key projection belongs to the current durable computer
    /// policy. Periodic work is an authorization path too: a queued policy event must fence the
    /// old projection before the next tick can publish consent, drive keys, or private attention.
    pub(super) fn computer_authority_current(&self) -> bool {
        if crate::node::computer::fx28_mutant("stale-tick-authority") {
            return true;
        }
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
            .profile
            .as_ref()
            .filter(|profile| profile.is_unlocked())
            .map(Profile::fingerprint)
            .or_else(|| self.headless.as_ref().map(|signer| signer.fingerprint()));
        computer.policy_current(applied) && me.is_some_and(|me| computer.binding_current(&me))
    }

    pub(super) fn computer_policy_active(
        deadline: std::time::Instant,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> crate::error::Result<()> {
        if cancelled.load(std::sync::atomic::Ordering::Acquire)
            || std::time::Instant::now() >= deadline
        {
            Err(Error::Profile(
                "computer trust did not apply before its causal deadline",
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn prepare_computer_binding_until(
        &self,
        deadline: std::time::Instant,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> crate::error::Result<()> {
        self.prepare_computer_binding_causal(deadline, cancelled, false)
    }

    pub(super) fn prepare_computer_binding_causal(
        &self,
        deadline: std::time::Instant,
        cancelled: &std::sync::atomic::AtomicBool,
        may_replace_expired: bool,
    ) -> crate::error::Result<()> {
        Self::computer_policy_active(deadline, cancelled)?;
        let Some(computer) = &self.computer else {
            return Ok(());
        };
        if !may_replace_expired && computer.current_revision_expired() {
            return Err(Error::Profile(
                "this policy revision expired before convergence; an operator change must replace it",
            ));
        }
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
                return computer.bind_node_until(p.signer()?, name, deadline);
            }
        }
        if let Some(s) = &self.headless {
            return computer.bind_node_until(s.as_ref(), name, deadline);
        }
        Err(Error::Profile(
            "managed node needs its passphrase to become Ready",
        ))
    }

    /// Before the endpoint registers, and before handling live authorization work, reconcile the
    /// durable plan. Persist the keyring before its journal receipt; repeat safely after a crash.
    pub(super) async fn apply_computer_keyring(&mut self) -> crate::error::Result<()> {
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        self.apply_computer_keyring_until(
            std::time::Instant::now() + crate::node::computer::COMPUTER_CHANGE_SHOWN_WITHIN,
            &cancelled,
        )
        .await
    }

    pub(super) async fn apply_computer_keyring_until(
        &mut self,
        deadline: std::time::Instant,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> crate::error::Result<()> {
        Self::computer_policy_active(deadline, cancelled)?;
        let Some(c) = self.computer.clone() else {
            return Ok(());
        };
        if c.grouped() {
            c.storage_ready()?;
        }
        if !c.grouped()
            || (!c.current_revision_expired()
                && self
                    .computer_revision
                    .load(std::sync::atomic::Ordering::Acquire)
                    == c.policy_revision())
        {
            return Ok(());
        }
        loop {
            Self::computer_policy_active(deadline, cancelled)?;
            let mut floor = 0;
            for room in self.channels.values() {
                floor = floor.max(room.lock().await.newest_mint_seq());
                Self::computer_policy_active(deadline, cancelled)?;
            }
            let changes = self.apply_computer_keyring_at_until(floor, deadline, cancelled)?;
            // A policy revision can grant an already admitted member read or drive. That member
            // may not have received the live capability record before this boundary, so publish
            // discovery again. It carries no authority; rooms coalesce it to one signed record.
            self.owe_private_support_in_open_rooms().await;
            Self::computer_policy_active(deadline, cancelled)?;
            for (id, stamp) in changes {
                self.mark_trust_decision(id, stamp).await;
                Self::computer_policy_active(deadline, cancelled)?;
            }
            // The existing room machinery performs pending removals, sender-key rotation, and
            // consent delivery. Computer policy does not create a second room authorization path.
            self.refresh_reachers_until(deadline, cancelled).await?;
            for prepared in self.preparing_rooms.values_mut() {
                prepared.channel.get_mut().release_held_packages();
            }
            let rooms: Vec<_> = self.channels.keys().copied().collect();
            for room in rooms {
                self.act_on_removals_while_closed(&room).await?;
                Self::computer_policy_active(deadline, cancelled)?;
                self.mark_decisions_on_open(&room).await?;
                Self::computer_policy_active(deadline, cancelled)?;
                if let Some(channel) = self.channels.get(&room) {
                    channel.lock().await.release_held_packages();
                }
                self.install_key_packages(&room).await;
                Self::computer_policy_active(deadline, cancelled)?;
            }
            self.deliver_owed_consents(None).await;
            Self::computer_policy_active(deadline, cancelled)?;
            self.tend_drive_keys_until(deadline, cancelled).await?;
            if let Err(error) = Self::computer_policy_active(deadline, cancelled) {
                c.invalidate_reachers();
                return Err(error);
            }
            self.publish().await;
            if let Err(error) = Self::computer_policy_active(deadline, cancelled) {
                c.invalidate_reachers();
                return Err(error);
            }
            if c.current_revision_expired() {
                return Ok(());
            }
            if self.computer.as_ref().is_none_or(|c| {
                c.policy_revision()
                    == self
                        .computer_revision
                        .load(std::sync::atomic::Ordering::Acquire)
            }) {
                return Ok(());
            }
        }
    }

    pub(super) fn apply_computer_keyring_at_until(
        &mut self,
        floor: u64,
        deadline: std::time::Instant,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> crate::error::Result<Vec<(Digest32, crate::node::consent_order::Stamp)>> {
        Self::computer_policy_active(deadline, cancelled)?;
        let Some(computer) = self.computer.clone() else {
            return Ok(Vec::new());
        };
        if !computer.grouped() {
            return Ok(Vec::new());
        }
        computer.storage_ready()?;
        let revision = computer.policy_revision();
        if !computer.current_revision_expired()
            && self
                .computer_revision
                .load(std::sync::atomic::Ordering::Acquire)
                == revision
        {
            return Ok(Vec::new());
        }
        let Some(profile) = &self.profile else {
            if let Some(signer) = &self.headless {
                if computer.current_revision_expired() {
                    computer.mark_expired_until(signer.fingerprint(), revision, deadline)?;
                } else if !computer.applied(&signer.fingerprint(), revision) {
                    computer.mark_applied_until(signer.fingerprint(), revision, &[], deadline)?;
                }
                self.computer_revision
                    .store(revision, std::sync::atomic::Ordering::Release);
            }
            return Ok(Vec::new());
        };
        if !profile.is_unlocked() {
            return Ok(Vec::new());
        }
        let me = profile.fingerprint();
        // Applied at this revision already: recorded after the keyring was saved, and kept
        // across a restart, so nothing is derived or written again (ADR-038 FX-28).
        if computer.applied(&me, revision) {
            self.computer_revision
                .store(revision, std::sync::atomic::Ordering::Release);
            return Ok(Vec::new());
        }
        let Some(plan) = computer.plan(me)? else {
            return Ok(Vec::new());
        };
        let expired = plan.expired;
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
        computer.retain_aliases_until(me, &aliases, deadline)?;
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
        Self::computer_policy_active(deadline, cancelled)?;
        locks.save(profile.store(), profile.signer()?)?;
        Self::computer_policy_active(deadline, cancelled)?;
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
            Self::computer_policy_active(deadline, cancelled)?;
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
        Self::computer_policy_active(deadline, cancelled)?;
        next.save_checked(profile.store(), profile.signer()?, || {
            Self::computer_policy_active(deadline, cancelled)
        })?;
        Self::computer_policy_active(deadline, cancelled)?;
        self.trust = next;
        for (id, was) in changed_drive {
            self.note_capability(id, was);
        }
        if expired {
            computer.mark_expired_until(me, revision, deadline)?;
        } else {
            computer.mark_applied_until(me, revision, &covered, deadline)?;
        }
        if let Err(error) = Self::computer_policy_active(deadline, cancelled) {
            computer.invalidate_reachers();
            return Err(error);
        }
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
