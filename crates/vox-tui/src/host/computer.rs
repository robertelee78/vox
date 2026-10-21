//! The daemon composes computer policy with already-attached node actors; no new unlock path.
use super::*;

/// How long one node may take to apply computer trust before it is treated as a failed write:
/// its stale grants must not stand on the network, and the other nodes never wait on it.
const RECONCILE_WITHIN: Duration = Duration::from_secs(30);

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

    /// One reconciliation pass: the roster follows the nodes on disk, every attached node that
    /// is behind the policy derives its binding and applies its keyring, all at once and each
    /// within [`RECONCILE_WITHIN`], and the application receipt is recorded. A node at the
    /// current revision is not asked; one that fails or does not answer is detached, off this
    /// task, so no node holds the follower.
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
        let mut behind = tokio::task::JoinSet::new();
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
            let handle = handle.clone();
            let name = info.name.clone();
            behind.spawn(async move {
                let outcome =
                    match tokio::time::timeout(RECONCILE_WITHIN, handle.reconcile_computer()).await
                    {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(e)) => Err(e.to_string()),
                        Err(_) => Err(format!(
                            "did not apply computer trust within {RECONCILE_WITHIN:?}"
                        )),
                    };
                (name, outcome)
            });
        }
        while let Some(joined) = behind.join_next().await {
            let (name, outcome) = match joined {
                Ok(done) => done,
                Err(e) => {
                    eprintln!("vox daemon: computer trust application stopped: {e}");
                    continue;
                }
            };
            if let Err(e) = outcome {
                pending.push(format!("{name}: {e}"));
                // A failed write must not leave stale grants on the network. The detach waits
                // for the node's actor to end, which a wedged one may not do soon: off this task.
                let router = self.clone();
                self.inner.rt.spawn(async move {
                    let _ = router.detach(&name, DetachCause::Requested).await;
                });
            }
        }
        management.pending_nodes(pending);
        if let Err(e) = management.record_application() {
            eprintln!("vox daemon: computer trust application pending: {e}");
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
