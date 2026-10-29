//! Preserve the exact fallback consent key before any pairwise framing can fail.
use super::*;
use crate::node::pending_consent::PendingConsents;

pub(crate) struct PendingHeld {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    candidate: Option<Box<Skdm>>,
    pin: Option<history::PendingHistoryRead>,
}

pub(crate) struct HeldConsent {
    pub(crate) skdm: Box<Skdm>,
    pub(crate) retained: bool,
}

pub(crate) struct CompletedHeld {
    pending: PendingHeld,
    pub(crate) result: Result<HeldConsent>,
}

impl ChannelState {
    pub(crate) fn prepare_pending_held_consent(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        candidate: Box<Skdm>,
    ) -> Result<PendingHeld> {
        let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(PendingHeld {
            owner,
            room: self.channel_id,
            epoch: self.epoch,
            candidate: Some(candidate),
            pin: Some(pin),
        })
    }

    pub(crate) fn finish_pending_held_consent(
        &mut self,
        done: CompletedHeld,
    ) -> Result<HeldConsent> {
        if done.can_install(self, &done.pending.owner) {
            self.release_pending_text(&done.pending.owner, false);
        }
        done.result
    }
}

impl CompletedHeld {
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

impl PendingHeld {
    pub(crate) fn run(
        mut self,
        store: &Store,
        signer: &dyn RootSigner,
        target: Digest32,
    ) -> CompletedHeld {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut candidate = self
                .candidate
                .take()
                .ok_or(Error::Profile("held consent candidate missing"))?;
            // Admission precedes the read, so another room's exact map delta cannot be lost.
            let mut batch = store.batch()?;
            let mut held = PendingConsents::load(store, signer)?;
            if let Some(skdm) = held
                .get(&self.room, &target)
                .and_then(|wire| Skdm::from_wire(wire).ok())
                .filter(|skdm| skdm.body.epoch == self.epoch)
            {
                *candidate = skdm;
                return Ok(HeldConsent {
                    skdm: candidate,
                    retained: true,
                });
            }
            let wire = candidate.to_wire();
            let retained = held.insert(self.room, target, wire);
            if retained {
                held.queue_save(&mut batch, signer)?;
                batch.commit()?;
            }
            // Preserve the original legal map-bound behavior: no held row does not prohibit
            // immediate delivery, but it must not be reported as a saved pending consent.
            Ok(HeldConsent {
                skdm: candidate,
                retained,
            })
        }))
        .unwrap_or_else(|_| Err(Error::Profile("held consent save worker stopped")));
        CompletedHeld {
            pending: self,
            result,
        }
    }
}
