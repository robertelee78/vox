//! The daemon composes computer policy with already-attached node actors; no new unlock path.
use super::*;

impl Router {
    pub(super) fn follow_computer_trust(&self) {
        let weak = Arc::downgrade(&self.inner);
        self.inner.rt.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                if inner.stopping.load(Ordering::Relaxed) {
                    return;
                }
                let router = Router { inner };
                let management = Arc::clone(&router.inner.defaults.computer);
                if management.computer.binding_group().is_none() {
                    continue;
                }
                if let Err(e) = management.computer.ensure_roster() {
                    eprintln!("vox daemon: computer roster pending: {e}");
                    continue;
                }
                let mut pending = Vec::new();
                for info in router.nodes() {
                    let Some((_, handle)) = router
                        .attached_handles()
                        .into_iter()
                        .find(|(name, _)| name == info.name.as_str())
                    else {
                        pending.push(format!(
                            "{}: make this node Ready to apply computer trust",
                            info.name
                        ));
                        continue;
                    };
                    if let Err(e) = handle.reconcile_computer().await {
                        pending.push(format!("{}: {e}", info.name));
                        // A failed write must not leave stale grants on the network.
                        let _ = router.detach(&info.name, DetachCause::Requested).await;
                    }
                }
                management.pending_nodes(pending);
                if let Err(e) = management.record_application() {
                    eprintln!("vox daemon: computer trust application pending: {e}");
                }
            }
        });
    }

    pub(super) async fn computer_request(&self, request: DaemonRequest) -> DaemonFrame {
        let management = &self.inner.defaults.computer;
        let result = match request {
            DaemonRequest::ComputerStatus => management.status(),
            DaemonRequest::ComputerBegin => management.begin(),
            DaemonRequest::ComputerPreview { link } => management.preview(&link).await,
            DaemonRequest::ComputerApprove { operation } => management.approve(&operation),
            DaemonRequest::ComputerCancel { operation } => management.cancel(&operation),
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
