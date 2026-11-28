//! The one place a member's key debt is settled: its authenticated answer to a direct delivery.
use super::*;

pub(crate) struct PendingDelivery {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    sek: crate::atrest::sek::WeakSek,
    store: Arc<Store>,
    /// The ledger in memory at prepare: what is written when the stored one is absent or in
    /// the floor format, which is not read.
    snapshot: BTreeMap<Digest32, BTreeSet<u64>>,
    live: u64,
    target: Digest32,
    /// The generations this answer settles: exactly the one it answered for.
    settles: BTreeSet<u64>,
    revision: u64,
    changed: bool,
    removal_generation: u64,
    pin: Option<history::PendingHistoryRead>,
}
pub(crate) struct CompletedDelivery {
    pending: PendingDelivery,
    pub(crate) result: Result<()>,
}

/// `settles` leave `target`'s set in `ledger`; a target with no row there owes `row`.
fn settle(
    ledger: &mut BTreeMap<Digest32, BTreeSet<u64>>,
    target: Digest32,
    settles: &BTreeSet<u64>,
    row: impl FnOnce() -> BTreeSet<u64>,
) {
    ledger
        .entry(target)
        .or_insert_with(row)
        .retain(|generation| !settles.contains(generation));
}

impl ChannelState {
    /// **The settlement rule** (V210-45): `target` answered a direct delivery of `generation`
    /// as taken (installed, already held, or deleted after reading), and that delivery was
    /// selected under debt `revision`. Exactly that generation leaves its set, and only when
    /// the debt was not owed anew since (a refusal for want of trust, a reset, a boundary): an
    /// older answer cannot settle a renewed debt. Nothing else settles a debt: not a package
    /// in the log, not a timeout, not a later generation.
    pub(crate) fn prepare_pending_consent_delivery(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        target: Digest32,
        generation: u64,
        revision: u64,
        expected_removal_generation: Option<u64>,
    ) -> Result<PendingDelivery> {
        let removal_generation = self.removal_generation(store)?;
        if expected_removal_generation.is_some_and(|expected| expected != removal_generation)
            || self.is_member_removed(store, &self.me())?
            || self.is_member_removed(store, &target)?
        {
            return Err(Error::Profile(governance::REFRESHING));
        }
        governance::check_removal_generation(
            store,
            &self.sek,
            &self.channel_id,
            removal_generation,
        )?;
        let live = self.sender.chain_id();
        let changed = revision == self.history_revision(&target)
            && self
                .outstanding
                .get(&target)
                .map_or(generation == live, |row| row.contains(&generation));
        // Exactly the generation answered for. `test-knobs` mutant
        // `VOX_TEST_FWD_MUTANT=settle-whole` puts back the first cause: the answer settles the
        // rest of the member's set from that generation on too, the generations retired while
        // its delivery was on its way included.
        #[cfg_attr(not(feature = "test-knobs"), allow(unused_mut))]
        let mut settles = BTreeSet::from([generation]);
        #[cfg(feature = "test-knobs")]
        if changed && std::env::var("VOX_TEST_FWD_MUTANT").as_deref() == Ok("settle-whole") {
            if let Some(row) = self.outstanding.get(&target) {
                settles.extend(row.range(generation..).copied());
            }
            if settles.len() > 1 {
                eprintln!(
                    "test-knobs: settle-whole mutant engaged: an answer for generation \
                     {generation} settles generations {settles:?}"
                );
            }
        }
        let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(PendingDelivery {
            owner,
            room: self.channel_id,
            epoch: self.epoch,
            sek: self.sek.reader(),
            store: Arc::clone(store),
            snapshot: if changed {
                self.outstanding.clone()
            } else {
                BTreeMap::new()
            },
            live,
            target,
            settles,
            revision,
            changed,
            removal_generation,
            pin: Some(pin),
        })
    }
    pub(crate) fn finish_pending_consent_delivery(
        &mut self,
        done: CompletedDelivery,
    ) -> Result<()> {
        let install = done.can_install(self, &done.pending.owner);
        let CompletedDelivery {
            pending,
            mut result,
        } = done;
        if install {
            if result.is_ok() && pending.changed {
                if pending.revision == self.history_revision(&pending.target) {
                    let live = pending.live;
                    settle(
                        &mut self.outstanding,
                        pending.target,
                        &pending.settles,
                        || BTreeSet::from([live]),
                    );
                } else if let Err(error) = self.persist_outstanding(&pending.store) {
                    // Owed anew while the answer was being saved: the renewal wins, and the
                    // ledger in memory, which still owes the generation, is written again.
                    result = Err(error);
                }
            }
            self.release_pending_text(&pending.owner, false);
        }
        result
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
            if !self.changed {
                return Ok(());
            }
            let mut batch = store.batch()?;
            self.sek.with(|sek| {
                governance::check_removal_generation_in(
                    &batch,
                    sek,
                    &self.room,
                    self.removal_generation,
                )?;
                // Only this one generation of this one row: every other row, and anything
                // owed to this member since prepare, stays as stored.
                let stored =
                    match batch.get_segment(&self.room, SegmentKind::KeyMaterial, SEG_HISTORY)? {
                        Some(sealed) => parse_outstanding(&open_segment(
                            sek,
                            SegmentKind::KeyMaterial,
                            SEG_HISTORY,
                            &sealed,
                        )?)?,
                        None => None,
                    };
                let (mut ledger, posted) = stored.unwrap_or_else(|| {
                    (self.snapshot.clone(), crate::node::channel::Posted::new())
                });
                // A stored ledger without this member's row owes what memory does (`open` reads
                // an entitled member without a row conservatively, in memory only).
                let row = || {
                    self.snapshot
                        .get(&self.target)
                        .cloned()
                        .unwrap_or_else(|| BTreeSet::from([self.live]))
                };
                settle(&mut ledger, self.target, &self.settles, row);
                batch.put_segment(
                    &self.room,
                    SegmentKind::KeyMaterial,
                    SEG_HISTORY,
                    &seal_segment(
                        sek,
                        SegmentKind::KeyMaterial,
                        SEG_HISTORY,
                        &outstanding_bytes(&ledger, &posted),
                    )?,
                )?;
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
