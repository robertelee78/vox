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
    /// moved it), when a node attaches or detaches, and when the endpoints this daemon advertises
    /// move (its reach is then recorded for the other computers). Measured before this
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
            let mut change = vox_core::node::computer::ComputerChange::now(
                management.computer.policy_revision(),
            );
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
                                let revision = management.computer.policy_revision();
                                let now = std::time::Instant::now();
                                vox_core::node::computer::ComputerChange::at(
                                    revision, now, now,
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
                        vox_core::node::computer::ComputerChange::now(
                            management.computer.policy_revision(),
                        )
                    }
                    event = nodes.recv() => {
                        match event {
                            Ok(DaemonEvent::Attached { .. } | DaemonEvent::Detached { .. })
                            | Err(broadcast::error::RecvError::Lagged(_)) => {
                                vox_core::node::computer::ComputerChange::now(
                                    management.computer.policy_revision(),
                                )
                            }
                            Err(broadcast::error::RecvError::Closed) => return,
                        }
                    }
                };
            }
        });
    }

    /// One reconciliation pass: the roster follows the nodes on disk, and every attached node
    /// that is behind the policy derives its binding and applies its keyring on a task of its
    /// own, bounded by the causal event's absolute deadline; each records the application receipt when it is
    /// done. The pass itself waits for none of them, so a revision arriving meanwhile starts its
    /// own pass at once and a stuck node holds nothing but itself. A node at the current
    /// revision is not asked; one that fails or does not answer is said in the status and remains
    /// attached but non-authoritative. `Computer::policy_current` and the synchronously invalidated
    /// reacher gates fail its old projection closed. Keeping the actor is essential: a later valid
    /// policy event must be able to reconcile it without an unlock or daemon restart.
    async fn reconcile_computer_trust(&self, change: vox_core::node::computer::ComputerChange) {
        let management = Arc::clone(&self.inner.defaults.computer);
        let revision = change.revision();
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
        let attached: Vec<_> = {
            let mut slots = lock(&self.inner.slots);
            slots
                .iter_mut()
                .filter_map(|(name, slot)| match slot {
                    Slot::Attached(attached) => {
                        // Claim the attachment for this exact revision before any older task can
                        // report. Attachment generation alone cannot distinguish R1 from R2 on
                        // the same live actor.
                        attached.computer_reconciliation = Some(revision);
                        Some((
                            name.as_str().to_owned(),
                            attached.handle.clone(),
                            attached.generation,
                        ))
                    }
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
            behind.push((info.name.clone(), handle.clone(), *generation));
        }
        management.pending_nodes(pending);
        if behind.is_empty() {
            if let Err(e) = management.record_application() {
                eprintln!("vox daemon: computer trust application pending: {e}");
            }
            return;
        }
        for (name, handle, generation) in behind {
            let router = self.clone();
            let management = Arc::clone(&management);
            self.inner.rt.spawn(async move {
                let outcome = handle
                    .reconcile_computer(deadline)
                    .await
                    .map_err(|error| error.to_string());
                match outcome {
                    Ok(()) => {
                        if !router.computer_reconciliation_current(&name, generation, revision) {
                            return;
                        }
                        if let Err(e) = management.record_application() {
                            eprintln!("vox daemon: computer trust application pending: {e}");
                        }
                    }
                    Err(why) => {
                        eprintln!(
                            "vox daemon: node {name} computer trust reconciliation at revision {revision} failed: {why}"
                        );
                        if router.computer_reconciliation_current(&name, generation, revision) {
                            management.node_pending(name.as_str(), &why);
                        }
                    }
                }
            });
        }
    }

    fn computer_reconciliation_current(
        &self,
        node: &NodeName,
        generation: u64,
        revision: u64,
    ) -> bool {
        match lock(&self.inner.slots).get(node) {
            Some(Slot::Attached(attached)) => {
                attached.generation == generation
                    && attached.computer_reconciliation == Some(revision)
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
