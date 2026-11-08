//! Preserve the exact fallback consent key before any pairwise framing can fail.
use super::*;
use crate::node::pending_consent::PendingConsents;

pub(crate) struct PendingHeld {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    sek: crate::atrest::sek::WeakSek,
    removal_generation: u64,
    forward_only: bool,
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
        target: Digest32,
        candidate: Box<Skdm>,
    ) -> Result<PendingHeld> {
        let removal_generation = self.removal_generation(store)?;
        if self.is_member_removed(store, &self.me())?
            || self.is_member_removed(store, &target)?
            || self.room_removal_rotation_needed(store)?
        {
            return Err(Error::Profile(governance::REFRESHING));
        }
        governance::check_removal_generation(
            store,
            &self.sek,
            &self.channel_id,
            removal_generation,
        )?;
        let forward_only = !self
            .validated_member_removals(store, &target, crate::time::Ms(self.now_hint))?
            .is_empty();
        if forward_only && candidate.body.chain_id != self.sender.chain_id() {
            return Err(Error::Profile(governance::REFRESHING));
        }
        let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(PendingHeld {
            owner,
            room: self.channel_id,
            epoch: self.epoch,
            sek: self.sek.reader(),
            removal_generation,
            forward_only,
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
            self.sek.with(|sek| {
                governance::check_removal_generation_in(
                    &batch,
                    sek,
                    &self.room,
                    self.removal_generation,
                )
            })?;
            let mut held = PendingConsents::load(store, signer)?;
            if let Some(skdm) = held
                .get(&self.room, &target)
                .and_then(|wire| Skdm::from_wire(wire).ok())
                .filter(|skdm| skdm.body.epoch == self.epoch)
                .filter(|skdm| !self.forward_only || skdm.body.chain_id == candidate.body.chain_id)
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
