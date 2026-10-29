//! Exact ordinary sender receipts after confirmed pairwise delivery or committed packages.
use super::*;

pub(crate) struct PendingDelivery {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    sek: crate::atrest::sek::WeakSek,
    delivered: BTreeMap<Digest32, u64>,
    history: BTreeMap<Digest32, u64>,
    delivered_changed: bool,
    history_changed: bool,
    pin: Option<history::PendingHistoryRead>,
}
pub(crate) struct CompletedDelivery {
    pending: PendingDelivery,
    pub(crate) result: Result<()>,
}
impl ChannelState {
    pub(crate) fn prepare_pending_consent_delivery(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        target: Digest32,
        generation: u64,
        history_sent: bool,
    ) -> Result<PendingDelivery> {
        let mut delivered = self.delivered.clone();
        let mut history = self.history.clone();
        let delivered_changed = delivered.get(&target).is_none_or(|old| *old < generation);
        if delivered_changed {
            delivered.insert(target, generation);
        }
        let history_changed = history_sent && history.remove(&target).is_some();
        let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(PendingDelivery {
            owner,
            room: self.channel_id,
            epoch: self.epoch,
            sek: self.sek.reader(),
            delivered,
            history,
            delivered_changed,
            history_changed,
            pin: Some(pin),
        })
    }
    pub(crate) fn finish_pending_consent_delivery(
        &mut self,
        done: CompletedDelivery,
    ) -> Result<()> {
        if done.can_install(self, &done.pending.owner) {
            if done.result.is_ok() {
                if done.pending.delivered_changed {
                    self.delivered = done.pending.delivered;
                }
                if done.pending.history_changed {
                    self.history = done.pending.history;
                }
            }
            self.release_pending_text(&done.pending.owner, false);
        }
        done.result
    }
}
impl CompletedDelivery {
    pub(crate) fn can_install(&self, room: &ChannelState, owner: &Arc<()>) -> bool {
        self.pending.room == room.channel_id
            && self.pending.epoch == room.epoch
            && Arc::ptr_eq(owner, &self.pending.owner)
            && room
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.pending.pin.take()
    }
}
impl PendingDelivery {
    pub(crate) fn run(self, store: &Store) -> CompletedDelivery {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if !self.delivered_changed && !self.history_changed {
                return Ok(());
            }
            let mut batch = store.batch()?;
            self.sek.with(|sek| {
                if self.delivered_changed {
                    batch.put_segment(
                        &self.room,
                        SegmentKind::KeyMaterial,
                        SEG_DELIVERED,
                        &seal_segment(
                            sek,
                            SegmentKind::KeyMaterial,
                            SEG_DELIVERED,
                            &delivered_bytes(&self.delivered),
                        )?,
                    )?;
                }
                if self.history_changed {
                    batch.put_segment(
                        &self.room,
                        SegmentKind::KeyMaterial,
                        SEG_HISTORY,
                        &seal_segment(
                            sek,
                            SegmentKind::KeyMaterial,
                            SEG_HISTORY,
                            &delivered_bytes(&self.history),
                        )?,
                    )?;
                }
                Ok(())
            })?;
            batch.commit()
        }))
        .unwrap_or_else(|_| Err(Error::Profile("consent delivery save worker stopped")));
        CompletedDelivery {
            pending: self,
            result,
        }
    }
}
