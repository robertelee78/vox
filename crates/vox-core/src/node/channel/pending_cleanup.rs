//! One own-receiver overlay cleanup cursor turn, without receiver key ownership.
use super::*;
use crate::atrest::sek::WeakSek;

pub(crate) struct PendingCleanup {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    sek: WeakSek,
    pin: Option<history::PendingHistoryRead>,
}

pub(crate) struct CompletedCleanup {
    pending: PendingCleanup,
    /// `(more, own_retry_ready)`: the cursor has more to walk; a deferred own receiver install
    /// has a free slot now.
    pub(crate) result: Result<(bool, bool)>,
}

impl CompletedCleanup {
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.pending.pin.take()
    }

    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.pending.room == channel.channel_id
            && self.pending.epoch == channel.epoch
            && Arc::ptr_eq(owner, &self.pending.owner)
            && channel
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }
}

impl ChannelState {
    pub(crate) fn prepare_pending_receiver_cleanup(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
    ) -> Result<Option<PendingCleanup>> {
        let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(Some(PendingCleanup {
            owner,
            room: self.channel_id,
            epoch: self.epoch,
            sek: self.sek.reader(),
            pin: Some(pin),
        }))
    }

    pub(crate) fn finish_pending_receiver_cleanup(
        &mut self,
        completed: CompletedCleanup,
    ) -> Result<(bool, bool)> {
        if completed.can_install(self, &completed.pending.owner) {
            self.release_pending_text(&completed.pending.owner, false);
        }
        completed.result
    }
}

impl PendingCleanup {
    pub(crate) fn run(self, store: &Store) -> CompletedCleanup {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut batch = store.batch()?;
            self.sek.with(|sek| {
                if let Some((more, own_retry_ready)) =
                    receiver_overlay::advance(&mut batch, sek, &self.room)?
                {
                    batch.commit()?;
                    Ok((more, own_retry_ready))
                } else {
                    // Opening writer admission still belongs to this physical worker.
                    Ok((false, false))
                }
            })
        }))
        .unwrap_or_else(|_| Err(Error::Profile("receiver cleanup worker stopped")));
        CompletedCleanup {
            pending: self,
            result,
        }
    }
}
