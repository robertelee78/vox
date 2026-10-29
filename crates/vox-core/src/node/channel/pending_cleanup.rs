//! One existing receiver-release or overlay cursor turn, without receiver key ownership.
use super::*;
use crate::atrest::sek::WeakSek;

type Binding = (u64, (u64, Digest32));

pub(crate) struct PendingCleanup {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    sek: WeakSek,
    receiver: Option<((Digest32, u64), Option<Binding>)>,
    packages: key_package_queue::Queue,
    pin: Option<history::PendingHistoryRead>,
}

pub(crate) struct CompletedCleanup {
    pending: PendingCleanup,
    replay: Option<key_package_queue::Queue>,
    pub(crate) result: Result<(bool, bool, bool)>,
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
        // Preserve the package's exact replay basis until its ordinary completion.
        if self.key_packages.has_attempt() {
            return Ok(None);
        }
        let receiver = receiver_releases::cleanup_receiver(store, &self.sek, &self.channel_id)?
            .map(|slot| {
                let binding = self
                    .receivers
                    .get(&slot)
                    .map(|receiver| (receiver.epoch(), receiver.history_release_binding()));
                (slot, binding)
            });
        let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(Some(PendingCleanup {
            owner,
            room: self.channel_id,
            epoch: self.epoch,
            sek: self.sek.reader(),
            receiver,
            packages: self.key_packages.clone(),
            pin: Some(pin),
        }))
    }

    pub(crate) fn finish_pending_receiver_cleanup(
        &mut self,
        completed: CompletedCleanup,
    ) -> Result<(bool, bool, bool)> {
        if completed.can_install(self, &completed.pending.owner) {
            if let Some(replay) = completed.replay {
                self.key_packages = replay;
            }
            self.release_pending_text(&completed.pending.owner, false);
        }
        completed.result
    }
}

impl PendingCleanup {
    pub(crate) fn run(self, store: &Store) -> CompletedCleanup {
        let mut replay = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut batch = store.batch()?;
            self.sek.with(|sek| {
                let progress = receiver_releases::advance_current(
                    &mut batch,
                    sek,
                    &self.room,
                    |author, chain, epoch, binding| {
                        let Some((slot, current)) = &self.receiver else {
                            return Err(Error::MalformedAtRest(
                                "receiver cleanup selection changed",
                            ));
                        };
                        if *slot != (*author, chain) {
                            return Err(Error::MalformedAtRest(
                                "receiver cleanup selection changed",
                            ));
                        }
                        Ok(*current == Some((epoch, binding)))
                    },
                )?;
                if let Some((more, retry_ready)) = progress {
                    let next = if retry_ready {
                        Some(self.packages.capacity_retry(&mut batch, sek, &self.room)?)
                    } else {
                        None
                    };
                    let more = more || receiver_overlay::pending(&batch, sek, &self.room)?;
                    batch.commit()?;
                    replay = next;
                    Ok((more, retry_ready, false))
                } else if let Some((more, own_retry_ready)) =
                    receiver_overlay::advance(&mut batch, sek, &self.room)?
                {
                    batch.commit()?;
                    Ok((more, false, own_retry_ready))
                } else {
                    // Opening writer admission still belongs to this physical worker.
                    Ok((false, false, false))
                }
            })
        }))
        .unwrap_or_else(|_| Err(Error::Profile("receiver cleanup worker stopped")));
        CompletedCleanup {
            pending: self,
            replay,
            result,
        }
    }
}
