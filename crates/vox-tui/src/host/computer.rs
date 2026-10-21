//! The daemon composes computer policy with already-attached node actors; no new unlock path.
use super::*;

/// Leave enough of FX-28's visible five-second contract for the daemon to publish `Detaching`
/// and for the person's status request to observe it after a node fails to answer.
const RECONCILE_DETACH_RESERVE: Duration = Duration::from_secs(1);
const RECONCILE_APPLY_WITHIN: Duration =
    vox_core::node::computer::COMPUTER_CHANGE_SHOWN_WITHIN.saturating_sub(RECONCILE_DETACH_RESERVE);

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
            // The first pass runs at start; every later one has a cause.
            policy.mark_changed();
            let mut advertised = endpoints.borrow_and_update().clone();
            loop {
                tokio::select! {
                    moved = policy.changed() => {
                        if moved.is_err() {
                            return;
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
                    }
                    event = nodes.recv() => {
                        match event {
                            Ok(DaemonEvent::Attached { .. } | DaemonEvent::Detached { .. })
                            | Err(broadcast::error::RecvError::Lagged(_)) => {}
                            Err(broadcast::error::RecvError::Closed) => return,
                        }
                    }
                }
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                if inner.stopping.load(Ordering::Relaxed) {
                    return;
                }
                Router { inner }.reconcile_computer_trust().await;
            }
        });
    }

    /// One reconciliation pass: the roster follows the nodes on disk, and every attached node
    /// that is behind the policy derives its binding and applies its keyring on a task of its
    /// own, bounded by [`RECONCILE_APPLY_WITHIN`]; each records the application receipt when it is
    /// done. The pass itself waits for none of them, so a revision arriving meanwhile starts its
    /// own pass at once and a stuck node holds nothing but itself. A node at the current
    /// revision is not asked; one that fails or does not answer is said in the status and
    /// detached (a failed write must not leave stale grants on the network). The slot moves to
    /// `Detaching` synchronously before cleanup starts, so queued actor work cannot hide a stale
    /// attached node past the public five-second contract.
    async fn reconcile_computer_trust(&self) {
        let management = Arc::clone(&self.inner.defaults.computer);
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
        let attached = self.attached_handles();
        for info in self.nodes() {
            let Some((_, handle)) = attached.iter().find(|(name, _)| name == info.name.as_str())
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
            behind.push((info.name.clone(), handle.clone()));
        }
        management.pending_nodes(pending);
        if behind.is_empty() {
            if let Err(e) = management.record_application() {
                eprintln!("vox daemon: computer trust application pending: {e}");
            }
            return;
        }
        for (name, handle) in behind {
            let router = self.clone();
            let management = Arc::clone(&management);
            self.inner.rt.spawn(async move {
                let outcome =
                    match tokio::time::timeout(RECONCILE_APPLY_WITHIN, handle.reconcile_computer())
                        .await
                    {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(e)) => Err(e.to_string()),
                        Err(_) => Err(format!(
                            "did not apply computer trust within {RECONCILE_APPLY_WITHIN:?}"
                        )),
                    };
                match outcome {
                    Ok(()) => {
                        if let Err(e) = management.record_application() {
                            eprintln!("vox daemon: computer trust application pending: {e}");
                        }
                    }
                    Err(why) => {
                        management.node_pending(name.as_str(), &why);
                        router.detach_failed_computer_node(name);
                    }
                }
            });
        }
    }

    /// Make a failed node non-attached in the same synchronous critical section that decides it,
    /// then leave its potentially slow actor cleanup to an independent task.
    fn detach_failed_computer_node(&self, node: NodeName) {
        let going = begin_detach(&mut lock(&self.inner.slots), &node);
        if let Some((attached, done)) = going {
            let router = self.clone();
            self.inner.rt.spawn(async move {
                let _ = router
                    .finish_detach(node, attached, done, DetachCause::Requested)
                    .await;
            });
        }
    }

    pub(super) async fn computer_request(&self, request: DaemonRequest) -> DaemonFrame {
        let management = &self.inner.defaults.computer;
        let result = match request {
            DaemonRequest::ComputerStatus => management.status(),
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
                    if let Err(e) = handle.reconcile_computer().await {
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
