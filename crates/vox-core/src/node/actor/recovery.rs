//! Retry a failed room store without blocking the node's command loop.
use super::*;
use crate::identity::composite::RootSigner;
use std::time::Instant;

pub(super) struct Retry {
    pub(super) cause: String,
    pub(super) name: String,
    pub(super) attempts: u32,
    pub(super) due: Instant,
    pub(super) busy: bool,
}

impl Node {
    pub(super) fn recover_storage(&mut self) {
        let Some(profile) = self.profile.as_ref() else {
            return;
        };
        let Ok(signer) = profile.signer() else { return };
        let me = signer.fingerprint();
        let Ok(retained_legacy) = crate::node::history_demand::retained_legacy_owner(profile)
        else {
            return;
        };
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
            let paused_legacy_owner = retained_legacy_owner_for(retained_legacy, id);
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
                    // Establish a real durable writer before opening a replacement room.
                    // A latched native backend requires fresh-inode reconstruction; failure
                    // leaves the original poisoned room and its committed read pin authoritative.
                    store.resave_room_after_write_failure(&id)?;
                    ChannelState::open_with_sek_owned(
                        &store,
                        &id,
                        crate::atrest::sek::Sek::from_bytes(keys.sek),
                        &keys.passphrase,
                        me,
                        now_ms,
                        paused_legacy_owner,
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
        // Keep the poisoned room authoritative (and refusing) while its replacement
        // advances through the same bounded preparation turns as an ordinary open.
        match opened {
            Ok(channel) => {
                self.preparing_rooms.insert(
                    id,
                    RoomPreparation {
                        legacy_cleanup_due: channel
                            .legacy_startup_cleanup_blocks_current()
                            .then_some(std::time::Instant::now()),
                        waiting: None,
                        waiting_noted: false,
                        progressed: false,
                        channel: Arc::new(tokio::sync::Mutex::new(channel)),
                        reply: None,
                        reopening: false,
                        recovery: Some(original),
                        recovery_writer_gate: None,
                        save: preparation_save::State::default(),
                        retry_packages: false,
                    },
                );
            }
            Err(error) => {
                self.fail_store_recovery(id, error);
            }
        }
    }

    pub(super) fn fail_store_recovery(&mut self, id: Digest32, error: Error) -> Outcome {
        let fault = fault_of(&error);
        if let Some(retry) = self.store_recovery.get_mut(&id) {
            retry.cause = error.to_string();
            retry.busy = false;
            retry.due = Instant::now() + Duration::from_secs(1u64 << retry.attempts.min(6));
        }
        Outcome::Failed(fault)
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
