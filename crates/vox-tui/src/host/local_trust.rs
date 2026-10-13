//! Apply the person's local trust rule from the daemon's own actors (ADR-031 LT).
use super::*;
use vox_core::node::api::NodeView;
use vox_core::node::trust::Capability;

struct ReadyNode {
    name: String,
    fingerprint: Digest32,
    handle: NodeHandle,
    view: NodeView,
    removed: BTreeSet<Digest32>,
}

impl Router {
    pub(super) fn follow_local_trust(&self) {
        let weak = Arc::downgrade(&self.inner);
        self.inner.rt.spawn(async move {
            let mut ticks = tokio::time::interval(Duration::from_secs(1));
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last_error = None;
            loop {
                ticks.tick().await;
                let Some(inner) = weak.upgrade() else { return };
                if inner.stopping.load(Ordering::Relaxed) {
                    return;
                }
                let router = Router { inner };
                let error = router.reconcile_local_trust().await.err();
                if error != last_error {
                    if let Some(why) = &error {
                        eprintln!("vox daemon: local trust waits: {why}");
                    }
                    last_error = error;
                }
            }
        });
    }

    async fn reconcile_local_trust(&self) -> Result<(), String> {
        // This is the app's existing persisted choice, kept when its window is closed. Neither
        // a remote name nor a caller-supplied fingerprint can designate the personal node.
        let path = self.inner.account.config_dir.join("app/node");
        let choice = match std::fs::read_to_string(path) {
            Ok(name) => NodeName::parse(name.trim()).map_err(|e| e.to_string())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.to_string()),
        };
        let mut ready = Vec::new();
        for (name, handle) in self.attached_handles() {
            let view = handle.view();
            if view.locked || view.locking {
                continue;
            }
            let Some(identity) = &view.identity else {
                continue;
            };
            let fingerprint = identity.fingerprint;
            let Some(removed) = handle
                .local_trust_blacklist()
                .await
                .map_err(|e| e.to_string())?
            else {
                continue;
            };
            ready.push(ReadyNode {
                name,
                fingerprint,
                handle,
                view,
                removed,
            });
        }
        let Some(personal) = ready.iter().find(|node| node.name == choice.as_str()) else {
            return Ok(());
        };
        for eligible in ready
            .iter()
            .filter(|node| node.fingerprint != personal.fingerprint)
        {
            let shares = eligible.view.open_channels.iter().any(|room| {
                room.members.contains(&eligible.fingerprint)
                    && room.members.contains(&personal.fingerprint)
                    && personal.view.open_channels.iter().any(|held| {
                        held.channel_id == room.channel_id
                            && held.members.contains(&eligible.fingerprint)
                            && held.members.contains(&personal.fingerprint)
                    })
            });
            if !shares {
                continue;
            }
            for other in ready
                .iter()
                .filter(|node| node.fingerprint != eligible.fingerprint)
            {
                if eligible.removed.contains(&other.fingerprint)
                    || other.removed.contains(&eligible.fingerprint)
                {
                    continue;
                }
                let capability = if other.fingerprint == personal.fingerprint {
                    Capability::ReadDrive
                } else {
                    Capability::Read
                };
                grant(eligible, other, capability).await?;
                grant(other, eligible, Capability::Read).await?;
            }
        }
        Ok(())
    }
}

async fn grant(from: &ReadyNode, to: &ReadyNode, capability: Capability) -> Result<(), String> {
    if from
        .view
        .trusted
        .iter()
        .any(|(fp, _)| *fp == to.fingerprint)
        && (!capability.drive() || from.view.drive.contains(&to.fingerprint))
    {
        return Ok(());
    }
    match from
        .handle
        .trust_local_node(to.fingerprint, to.name.clone(), capability)
        .await
    {
        Outcome::Done => Ok(()),
        other => Err(format!(
            "{} could not trust {}: {other}",
            from.name, to.name
        )),
    }
}
