//! The daemon composes computer policy with already-attached node actors; no new unlock path.
use super::*;

/// **Test-only** (`test-knobs`): `<arm>\t<accepted>\t<returned>`. The daemon consumes `arm` and
/// creates `accepted` immediately before one shipped `computer status` enters the synchronous
/// status read, then creates `returned` immediately after it leaves. A shipped-binary journey can
/// prove that an accepted status was overtaken by a later independent command instead of waiting
/// for an arbitrary deadman. Shipped builds neither name nor read this variable.
#[cfg(feature = "test-knobs")]
const TEST_MARK_COMPUTER_STATUS_ENV: &str = "VOX_TEST_MARK_COMPUTER_STATUS_FILE";

#[cfg(feature = "test-knobs")]
fn mark_computer_status_accepted_for_proof() -> Option<std::path::PathBuf> {
    let spec = std::env::var(TEST_MARK_COMPUTER_STATUS_ENV).ok()?;
    let mut fields = spec.splitn(3, '\t');
    let (arm, accepted, returned) = (fields.next()?, fields.next()?, fields.next()?);
    std::fs::remove_file(arm).ok()?;
    std::fs::write(accepted, b"accepted\n").ok()?;
    Some(returned.into())
}

#[cfg(feature = "test-knobs")]
fn mark_computer_status_returned_for_proof(returned: Option<std::path::PathBuf>) {
    if let Some(returned) = returned {
        let _ = std::fs::write(returned, b"returned\n");
    }
}

impl Router {
    /// Reconcile the daemon's nodes with computer trust on change, and on no timer (ADR-038
    /// FX-28): when the policy revision moves (a change made here, or a merged exchange that
    /// moved it), and when a node attaches or detaches. Endpoint movement records transport reach
    /// for the other computers without starting another node-application clock. Measured before this
    /// (2026-10-20, the decider's daemon): a 1 s tick re-derived every node's binding, an ML-DSA
    /// verification of every management event, with nothing changed.
    pub(super) fn follow_computer_trust(&self) {
        let weak = Arc::downgrade(&self.inner);
        let management = Arc::clone(&self.inner.defaults.computer);
        let mut policy = management.computer.changes();
        let mut endpoints = management.endpoint_changes();
        let mut nodes = self.inner.events.subscribe();
        self.inner.rt.spawn(async move {
            // Daemon start is the first cause. Every later pass carries the deadline of the
            // event that caused it; a remote merge does not get a new reconciliation clock.
            let mut change =
                vox_core::node::computer::ComputerChange::now(management.computer.policy_target());
            let mut advertised = endpoints.borrow_and_update().clone();
            loop {
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                if inner.stopping.load(Ordering::Relaxed) {
                    return;
                }
                Router { inner }.reconcile_computer_trust(change).await;
                change = tokio::select! {
                    moved = policy.recv() => {
                        match moved {
                            Ok(event) => event,
                            Err(broadcast::error::RecvError::Lagged(_)) => {
                                // A missed earlier event may already be at its bound; never
                                // replace it with a later five-second window.
                                let now = std::time::Instant::now();
                                vox_core::node::computer::ComputerChange::at(
                                    management.computer.policy_target(), now, now,
                                )
                            }
                            Err(broadcast::error::RecvError::Closed) => return,
                        }
                    }
                    moved = endpoints.changed() => {
                        if moved.is_err() {
                            return;
                        }
                        let now = endpoints.borrow_and_update().clone();
                        if now == advertised {
                            continue;
                        }
                        advertised = now;
                        if let Err(error) = management.record_reach() {
                            eprintln!("vox daemon: computer reach update pending: {error}");
                        }
                        continue;
                    }
                    event = nodes.recv() => {
                        match event {
                            Ok(DaemonEvent::Attached { .. } | DaemonEvent::Detached { .. })
                            | Err(broadcast::error::RecvError::Lagged(_)) => {
                                // Unlock owns a new attachment's startup boundary. Updating the
                                // roster must not renew an older attached node's policy deadline;
                                // any actual roster policy change arrives through `policy` above.
                                change
                            }
                            Err(broadcast::error::RecvError::Closed) => return,
                        }
                    }
                };
            }
        });
    }

    /// One reconciliation pass: the roster follows the nodes on disk, and every attached node
    /// that is behind the policy derives its binding and applies its keyring on a task of its own.
    /// The causal deadline records a public historical miss but never discards same-current work;
    /// exact policy movement or attachment lifecycle supersedes it. Each successful task records
    /// the application receipt. The pass itself waits for none of them, so a revision arriving
    /// meanwhile starts its own pass at once and a stuck node holds nothing but itself. A current
    /// node is not asked; an unfinished or failed one is said in status and remains attached but
    /// non-authoritative. `Computer::policy_current` and synchronously invalidated reacher gates
    /// fail its old projection closed until the accepted application completes.
    async fn reconcile_computer_trust(&self, change: vox_core::node::computer::ComputerChange) {
        let management = Arc::clone(&self.inner.defaults.computer);
        let revision = change.revision();
        let target = change.target();
        let deadline = change.apply_deadline();
        if management.computer.binding_group().is_none() && !management.computer.grouped() {
            return;
        }
        if let Err(e) = management.computer.ensure_roster() {
            eprintln!("vox daemon: computer roster pending: {e}");
            return;
        }
        let names = self
            .inner
            .account
            .nodes_on_disk()
            .into_iter()
            .map(|n| n.to_string())
            .collect();
        if let Err(e) = management.computer.retain_local_nodes(&names) {
            eprintln!("vox daemon: computer roster pending: {e}");
            return;
        }
        let mut pending = Vec::new();
        let mut behind = Vec::new();
        let pass = self.inner.next_generation.fetch_add(1, Ordering::Relaxed);
        let attached: Vec<_> = {
            let slots = lock(&self.inner.slots);
            slots
                .iter()
                .filter_map(|(name, slot)| match slot {
                    Slot::Attached(attached) => Some((
                        name.as_str().to_owned(),
                        attached.handle.clone(),
                        attached.generation,
                    )),
                    _ => None,
                })
                .collect()
        };
        for info in self.nodes() {
            let Some((_, handle, generation)) = attached
                .iter()
                .find(|(name, _, _)| name == info.name.as_str())
            else {
                pending.push(format!(
                    "{}: make this node Ready to apply computer trust",
                    info.name
                ));
                continue;
            };
            if handle.computer_current() {
                continue;
            }
            let Some(identity) = info.fingerprint else {
                pending.push(format!(
                    "{}: the Ready actor has no authenticated identity for computer trust",
                    info.name
                ));
                continue;
            };
            behind.push((info.name.clone(), handle.clone(), *generation, identity));
        }
        management.pending_nodes(pending);
        if behind.is_empty() {
            if let Err(e) = management.record_application() {
                eprintln!("vox daemon: computer trust application pending: {e}");
            }
            return;
        }
        let claimed: Vec<_> = {
            let mut slots = lock(&self.inner.slots);
            behind
                .into_iter()
                .filter_map(|(name, handle, generation, identity)| {
                    let Some(Slot::Attached(attached)) = slots.get_mut(&name) else {
                        return None;
                    };
                    if attached.generation != generation {
                        return None;
                    }
                    if attached
                        .computer_reconciliation
                        .as_ref()
                        .is_some_and(|flight| flight.target == target)
                    {
                        return None;
                    }
                    let superseded = Arc::new(vox_core::node::actor::PolicySupersession::default());
                    attached.computer_reconciliation = Some(ComputerReconciliation {
                        target,
                        pass,
                        superseded: Arc::clone(&superseded),
                    });
                    Some((name, handle, generation, identity, superseded))
                })
                .collect()
        };
        for (name, handle, generation, identity, superseded) in claimed {
            let router = self.clone();
            let management = Arc::clone(&management);
            self.inner.rt.spawn(async move {
                let application = handle.reconcile_computer_current(change, Arc::clone(&superseded));
                tokio::pin!(application);
                let outcome = tokio::select! {
                    biased;
                    result = &mut application => result,
                    () = tokio::time::sleep_until(deadline.into()) => {
                        router.mark_computer_reconciliation_late(
                            &name, generation, identity, change, pass,
                        );
                        application.await
                    }
                }
                .map_err(|error| error.to_string());
                match outcome {
                    Ok(()) => {
                        if !router.finish_computer_reconciliation(
                            &name, generation, target, pass, None,
                        ) {
                            return;
                        }
                        if let Err(e) = management.record_application() {
                            eprintln!("vox daemon: computer trust application pending: {e}");
                        }
                    }
                    Err(why) => {
                        // The actor can durably settle its exact keyring before later room
                        // maintenance reports a fault. That fault belongs in the daemon log, but
                        // must not leave the already-current Computer application pending forever:
                        // later follower passes deliberately skip a current actor. The finish
                        // fence below still requires this exact target, attachment and pass, so a
                        // node already current only for a newer target cannot complete this one.
                        let applied = handle.computer_current();
                        if !router.finish_computer_reconciliation(
                            &name,
                            generation,
                            target,
                            pass,
                            (!applied).then_some(why.as_str()),
                        ) {
                            return;
                        }
                        if applied {
                            eprintln!(
                                "vox daemon: node {name} applied computer trust revision {revision}; its ancillary room reconciliation reported: {why}"
                            );
                            if let Err(e) = management.record_application() {
                                eprintln!("vox daemon: computer trust application pending: {e}");
                            }
                        } else {
                            eprintln!(
                                "vox daemon: node {name} computer trust reconciliation at revision {revision} failed: {why}"
                            );
                        }
                    }
                }
            });
        }
    }

    fn mark_computer_reconciliation_late(
        &self,
        node: &NodeName,
        generation: u64,
        identity: vox_core::hash::Digest32,
        change: vox_core::node::computer::ComputerChange,
        pass: u64,
    ) {
        let owns_pass = {
            let slots = lock(&self.inner.slots);
            matches!(
                slots.get(node),
                Some(Slot::Attached(attached))
                    if attached.generation == generation
                        && attached.computer_reconciliation.as_ref().is_some_and(|flight|
                            flight.target == change.target() && flight.pass == pass)
            )
        };
        if !owns_pass {
            return;
        }
        let management = &self.inner.defaults.computer;
        match management
            .computer
            .record_application_miss(identity, change)
        {
            Ok(true) => {
                let slots = lock(&self.inner.slots);
                if matches!(
                    slots.get(node),
                    Some(Slot::Attached(attached))
                        if attached.generation == generation
                            && attached.computer_reconciliation.as_ref().is_some_and(|flight|
                                flight.target == change.target() && flight.pass == pass)
                ) {
                    // Keep pass ownership through the synchronous status write. Target-tagging
                    // independently keeps a later durable policy from displaying these words.
                    management.node_pending(
                        node.as_str(),
                        change.target(),
                        &format!(
                            "computer trust revision {} missed its local application boundary; the accepted application is still running",
                            change.revision()
                        ),
                    );
                }
            }
            Ok(false) => {}
            Err(error) => {
                let slots = lock(&self.inner.slots);
                if matches!(
                    slots.get(node),
                    Some(Slot::Attached(attached))
                        if attached.generation == generation
                            && attached.computer_reconciliation.as_ref().is_some_and(|flight|
                                flight.target == change.target() && flight.pass == pass)
                ) {
                    management.node_pending(
                        node.as_str(),
                        change.target(),
                        &format!("computer trust lateness could not be recorded: {error}"),
                    );
                }
            }
        }
    }

    fn finish_computer_reconciliation(
        &self,
        node: &NodeName,
        generation: u64,
        target: vox_core::node::computer::ComputerPolicyTarget,
        pass: u64,
        failure: Option<&str>,
    ) -> bool {
        match lock(&self.inner.slots).get_mut(node) {
            Some(Slot::Attached(attached)) => {
                if attached.generation != generation
                    || self.inner.defaults.computer.computer.policy_target() != target
                    || !attached
                        .computer_reconciliation
                        .as_ref()
                        .is_some_and(|flight| flight.target == target && flight.pass == pass)
                {
                    return false;
                }
                // Ownership and its status update share this slot lock. Checking, unlocking and
                // only then updating allowed an earlier pass to overwrite a newer result.
                attached.computer_reconciliation = None;
                let management = &self.inner.defaults.computer;
                match failure {
                    Some(why) => management.node_pending(node.as_str(), target, why),
                    None => management.node_applied(node.as_str()),
                }
                true
            }
            _ => false,
        }
    }

    pub(super) async fn computer_request(&self, request: DaemonRequest) -> DaemonFrame {
        let management = &self.inner.defaults.computer;
        let result = match request {
            DaemonRequest::ComputerStatus => {
                #[cfg(feature = "test-knobs")]
                let returned = mark_computer_status_accepted_for_proof();
                let status = management.status();
                #[cfg(feature = "test-knobs")]
                mark_computer_status_returned_for_proof(returned);
                status
            }
            DaemonRequest::ComputerBegin => management.begin(),
            DaemonRequest::ComputerPreview { link } => management.preview(&link).await,
            DaemonRequest::ComputerApprove { operation } => management.approve(&operation),
            DaemonRequest::ComputerCancel { operation } => management.cancel(&operation),
            DaemonRequest::ComputerRemove { computer, frontier } => {
                management.remove(&computer, &frontier)
            }
            DaemonRequest::ComputerBinding {
                action,
                node,
                destination,
                frontier,
            } => management.binding_update(&action, &node, &destination, &frontier),
            DaemonRequest::ComputerPersonal { node } => {
                let selected = if node.is_empty() {
                    None
                } else {
                    let Some((name, handle)) = self
                        .attached_handles()
                        .into_iter()
                        .find(|(name, _)| name == &node)
                    else {
                        return DaemonFrame::ComputerFailed(
                            "make the selected node Ready before choosing it as the personal node"
                                .into(),
                        );
                    };
                    let deadline = std::time::Instant::now()
                        + vox_core::node::computer::COMPUTER_CHANGE_SHOWN_WITHIN;
                    if let Err(e) = handle.reconcile_computer(deadline).await {
                        return DaemonFrame::ComputerFailed(e.to_string());
                    }
                    let Some(info) = self
                        .attached()
                        .into_iter()
                        .find(|info| info.name.as_str() == name)
                    else {
                        return DaemonFrame::ComputerFailed(
                            "the selected node stopped; choose it again when Ready".into(),
                        );
                    };
                    let Some(id) = info.fingerprint else {
                        return DaemonFrame::ComputerFailed(
                            "the selected node has no authenticated identity".into(),
                        );
                    };
                    Some(id)
                };
                management
                    .computer
                    .select_personal(selected, &node)
                    .and_then(|()| management.status())
            }
            _ => return DaemonFrame::ComputerFailed("not a computer management request".into()),
        };
        match result {
            Ok(status) => match serde_json::to_string(&status) {
                Ok(json) => DaemonFrame::ComputerStatus(json),
                Err(e) => DaemonFrame::ComputerFailed(e.to_string()),
            },
            Err(e) => DaemonFrame::ComputerFailed(e.to_string()),
        }
    }
}
