//! Retry a failed room store without blocking the node's command loop.
use super::*;
use crate::identity::composite::RootSigner;
use std::time::Instant;

pub(super) struct Retry {
    cause: String,
    name: String,
    attempts: u32,
    due: Instant,
    busy: bool,
}

impl Node {
    pub(super) fn recover_storage(&mut self) {
        let Some(profile) = self.profile.as_ref() else {
            return;
        };
        let Ok(signer) = profile.signer() else { return };
        let me = signer.fingerprint();
        let now_ms = self.now_ms();
        self.store_recovery
            .retain(|id, _| self.channels.contains_key(id));
        self.store_recovered
            .retain(|id, _| self.channels.contains_key(id));
        for (id, shared) in &self.channels {
            let Ok(ch) = shared.try_lock() else { continue };
            if !ch.is_poisoned() {
                continue;
            }
            self.store_recovered.remove(id);
            let retry = self.store_recovery.entry(*id).or_insert_with(|| Retry {
                cause: ch.save_failure().to_string(),
                name: ch
                    .name()
                    .map(str::to_owned)
                    .unwrap_or_else(|| crate::node::link::b32_encode(id)),
                attempts: 0,
                due: Instant::now() + Duration::from_secs(1),
                busy: false,
            });
            if retry.busy || Instant::now() < retry.due {
                continue;
            }
            let Ok(keys) = ch.recovery_keys() else {
                continue;
            };
            retry.busy = true;
            retry.attempts = retry.attempts.saturating_add(1);
            let id = *id;
            let store = profile.store_handle();
            let original = Arc::downgrade(shared);
            let tx = self.net_tx.clone();
            let secret_work = Arc::clone(&self.secret_work);
            // Retire every sync before taking a replacement room from disk.
            for ((room, _), port) in &mut self.ports {
                if *room == id {
                    port.poisoned = true;
                    for attempt in port.take_attempts() {
                        attempt.retire();
                    }
                }
            }
            tokio::spawn(async move {
                let opened = secret_blocking(&secret_work, move || {
                    store.reopen_after_write_failure(&id)?;
                    ChannelState::open_with_sek(
                        &store,
                        &id,
                        crate::atrest::sek::Sek::from_bytes(keys.sek),
                        &keys.passphrase,
                        me,
                        now_ms,
                    )
                })
                .await;
                // A cancelled/panicked worker must leave the same retry path as a failed
                // reopen. Otherwise busy remains true and this room can never recover.
                let opened = opened.unwrap_or_else(|| {
                    Err(crate::error::Error::Storage {
                        op: "recover room",
                        detail: "the recovery worker stopped before completion; retrying".into(),
                    })
                });
                let _ = tx
                    .send(NetEvent::StoreReopened {
                        channel_id: id,
                        original,
                        opened: Box::new(opened),
                    })
                    .await;
            });
        }
    }

    pub(super) async fn finish_store_recovery(
        &mut self,
        id: Digest32,
        original: std::sync::Weak<tokio::sync::Mutex<ChannelState>>,
        opened: crate::error::Result<ChannelState>,
    ) {
        if !self
            .channels
            .get(&id)
            .zip(original.upgrade())
            .is_some_and(|(a, b)| Arc::ptr_eq(a, &b))
        {
            self.store_recovery.remove(&id);
            return;
        }
        // A storage reopen initially knows the room policy. Apply this node's shorter limits
        // before success is reported or the replacement is exposed; retain the original OS
        // cause and retry state if that additional write fails.
        let opened = match opened {
            Ok(mut channel) => self
                .retention_before_publication(&mut channel)
                .await
                .map(|()| channel),
            Err(error) => Err(error),
        };
        match opened {
            Ok(channel) => {
                let name = self
                    .store_recovery
                    .remove(&id)
                    .map(|r| r.name)
                    .unwrap_or_else(|| crate::node::link::b32_encode(&id));
                let peers = self
                    .ports
                    .keys()
                    .filter(|(room, _)| *room == id)
                    .map(|(_, peer)| *peer)
                    .collect::<Vec<_>>();
                for peer in peers {
                    self.drop_port(&id, &peer);
                }
                self.publish_open_channel(channel).await;
                self.store_recovered
                    .insert(id, format!("{name} recovered; it can save again"));
                eprintln!(
                    "vox: node {} room {}: {name} recovered; it can save again",
                    self.paths
                        .profile_dir
                        .file_name()
                        .and_then(|v| v.to_str())
                        .unwrap_or("unknown"),
                    crate::node::link::b32_encode(&id)
                );
            }
            Err(e) => {
                if let Some(retry) = self.store_recovery.get_mut(&id) {
                    retry.cause = e.to_string();
                    retry.busy = false;
                    retry.due = Instant::now() + Duration::from_secs(1u64 << retry.attempts.min(6));
                }
            }
        }
    }

    pub(super) fn storage_health(&self, report: &mut crate::node::status::StatusReport) {
        report.recovered = self
            .store_recovered
            .iter()
            .map(|(id, message)| crate::node::status::Unhealthy {
                key: format!("room-store:{}", crate::node::link::b32_encode(id)),
                message: message.clone(),
            })
            .collect();
        for (id, shared) in &self.channels {
            let state = shared.try_lock().ok();
            let retry = self.store_recovery.get(id);
            let cause = state
                .as_ref()
                .filter(|c| c.is_poisoned())
                .map(|c| c.save_failure().to_string())
                .or_else(|| retry.map(|r| r.cause.clone()));
            let Some(cause) = cause else { continue };
            let name = retry
                .map(|r| r.name.clone())
                .or_else(|| state.and_then(|c| c.name().map(str::to_owned)))
                .unwrap_or_else(|| crate::node::link::b32_encode(id));
            report.unhealthy.push(crate::node::status::Unhealthy {
                key: format!("room-store:{}", crate::node::link::b32_encode(id)),
                message: format!(
                    "{name} cannot save: {cause}. It recovers by itself when writes succeed again."
                ),
            });
        }
    }
}
