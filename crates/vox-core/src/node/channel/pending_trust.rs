//! Compact trust narrowing, exact removal debt and decision marks under one retained room owner.
use super::*;
use crate::atrest::sek::WeakSek;
use crate::atrest::vault::VaultRootSigner;
use crate::node::pending_lock::PendingLocks;

pub(crate) enum TrustWrite {
    /// `withdrawn` is supplied only by the matching successful Work::Withdraw continuation.
    /// A known-absent withdrawal still must really commit its delivered/history/entitled cleanup.
    Delete {
        trusted: BTreeSet<Digest32>,
        withdrawn: Option<Digest32>,
    },
    RemovalPage {
        trusted: BTreeSet<Digest32>,
        after: Option<Digest32>,
    },
    MarkDecisions,
    MarkDecision {
        target: Digest32,
        decision: Stamp,
    },
}

pub(crate) enum TrustSaved {
    Deleted {
        dropped: usize,
        debt_cleared: Option<Digest32>,
    },
    /// One existing 64-slot page, at most one untrusted withdrawal selected. The target's cursor
    /// advances only AFTER the caller's owned Withdraw -> Delete+debt transaction completes.
    RemovalPage {
        target: Option<Digest32>,
        after: Option<Digest32>,
        done: bool,
    },
    Marked,
}

pub(crate) struct PendingTrust {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    sek: WeakSek,
    pin: Option<history::PendingHistoryRead>,
    normal_version: receiver_overlay::Stamp,
    drive_version: receiver_overlay::Stamp,
    normal_next: Option<receiver_overlay::Stamp>,
    normal: Option<Zeroizing<Vec<u8>>>,
    drive: Option<Zeroizing<Vec<u8>>>,
    normal_deleted: Vec<(Digest32, u64)>,
    drive_deleted: Vec<(Digest32, u64)>,
    live: Option<Stamp>,
    position: (u64, u64),
    write: TrustWrite,
}

pub(crate) struct CompletedTrust {
    pending: PendingTrust,
    deletion_committed: bool,
    marks: Option<BTreeMap<Digest32, TrustMark>>,
    pub(crate) result: Result<TrustSaved>,
}

impl CompletedTrust {
    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.pending.room == channel.channel_id
            && self.pending.epoch == channel.epoch
            && Arc::ptr_eq(owner, &self.pending.owner)
            && channel
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.pending.pin.take()
    }
}

impl ChannelState {
    pub(crate) fn prepare_pending_trust(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        write: TrustWrite,
    ) -> Result<PendingTrust> {
        let marking = matches!(
            &write,
            TrustWrite::MarkDecisions | TrustWrite::MarkDecision { .. }
        );
        if self.poisoned && !marking {
            return Err(self.save_failure());
        }
        let mut normal = None;
        let mut drive = None;
        let mut normal_deleted = Vec::new();
        let mut drive_deleted = Vec::new();
        let mut normal_next = None;
        if let TrustWrite::Delete { trusted, withdrawn } = &write {
            if withdrawn.is_some_and(|target| trusted.contains(&target)) {
                return Err(Error::Profile(
                    "withdrawal debt belongs to a superseded trust decision",
                ));
            }
            let me = self.me();
            normal_deleted.extend(
                self.receivers
                    .keys()
                    .filter(|(author, _)| *author != me && !trusted.contains(author))
                    .copied(),
            );
            drive_deleted.extend(
                self.drive
                    .receivers
                    .keys()
                    .filter(|(author, _)| !trusted.contains(author))
                    .copied(),
            );
            if !normal_deleted.is_empty() {
                let mut e = Encoder::for_secrets();
                e.array(2)
                    .uint(RECEIVERS_VERSION)
                    .array(self.receivers.len() - normal_deleted.len());
                for ((author, _), chain) in &self.receivers {
                    if *author == me || trusted.contains(author) {
                        e.bytes(&chain.to_state());
                    }
                }
                normal = Some(Zeroizing::new(e.finish()));
                normal_next = Some(self.receiver_persistence.next_normal()?);
            }
            // The bounded drive key/ledger component is serialized, never moved out of the live
            // room. Decode/filter/seal and all writer admission happen on the native worker.
            if !drive_deleted.is_empty() || normal.is_some() {
                drive = Some(self.drive.to_state());
            }
        }
        let current = self.sender.chain_id();
        let live = if marking {
            self.my_generations()
                .into_iter()
                .find(|(chain, _)| *chain == current)
                .and_then(|(_, stamp)| stamp)
        } else {
            None
        };
        let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(PendingTrust {
            owner,
            room: self.channel_id,
            epoch: self.epoch,
            sek: self.sek.reader(),
            pin: Some(pin),
            normal_version: self.receiver_persistence.normal(),
            drive_version: self.receiver_persistence.drive(),
            normal_next,
            normal,
            drive,
            normal_deleted,
            drive_deleted,
            live,
            position: (current, self.sender.current_position().0),
            write,
        })
    }

    pub(crate) fn finish_pending_trust(&mut self, completed: CompletedTrust) -> Result<TrustSaved> {
        if !completed.can_install(self, &completed.pending.owner) {
            return completed.result;
        }
        let CompletedTrust {
            pending,
            deletion_committed,
            marks,
            result,
        } = completed;
        let matching = self.receiver_persistence.normal() == pending.normal_version
            && self.receiver_persistence.drive() == pending.drive_version;
        if !matching {
            self.release_pending_text(&pending.owner, true);
            return Err(Error::Profile(
                "trust save receiver basis changed during its reservation",
            ));
        }
        if deletion_committed {
            for slot in &pending.normal_deleted {
                self.receivers.remove(slot);
            }
            for slot in &pending.drive_deleted {
                self.drive.receivers.remove(slot);
            }
            if pending.normal_next.is_some() {
                self.receiver_persistence.advance_normal()?;
            }
            if let TrustWrite::Delete { trusted, .. } = pending.write {
                self.legacy_cache_trusted = Some(trusted);
            }
        }
        if let Some(marks) = marks {
            self.trust_marks = marks;
        }
        if let Err(error) = &result {
            self.poison(error);
        }
        self.release_pending_text(&pending.owner, false);
        result
    }
}

impl PendingTrust {
    pub(crate) fn run(self, store: &Store, signer: &VaultRootSigner) -> CompletedTrust {
        let mut deletion_committed = false;
        let mut marks = None;
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<TrustSaved> {
                // Loading every global metadata map after admission prevents another room's exact
                // deletion/debt completion from being replaced by this room's old actor snapshot.
                let mut batch = store.batch()?;
                match &self.write {
                    TrustWrite::Delete { withdrawn, .. } => self.sek.with(|sek| {
                        let mut changed = self.normal.is_some() || self.drive.is_some();
                        if let Some(bytes) = &self.normal {
                            let segment =
                                seal_segment(sek, SegmentKind::KeyMaterial, SEG_RECEIVERS, bytes)?;
                            receiver_overlay::rewrite(
                                &mut batch,
                                sek,
                                &self.room,
                                &segment,
                                self.normal_next
                                    .ok_or(Error::Profile("missing receiver deletion stamp"))?,
                            )?;
                            receiver_releases::retire(&mut batch, sek, &self.room)?;
                        }
                        if let Some(bytes) = &self.drive {
                            let filtered;
                            let bytes = if self.drive_deleted.is_empty() {
                                bytes.as_slice()
                            } else {
                                let mut drive = crate::node::drive::DriveState::from_state(bytes)?;
                                for slot in &self.drive_deleted {
                                    drive.receivers.remove(slot);
                                }
                                filtered = drive.to_state();
                                filtered.as_slice()
                            };
                            let segment =
                                seal_segment(sek, SegmentKind::KeyMaterial, SEG_DRIVE, bytes)?;
                            batch.put_segment(
                                &self.room,
                                SegmentKind::KeyMaterial,
                                SEG_DRIVE,
                                &segment,
                            )?;
                            receiver_overlay::wrote_drive(
                                &mut batch,
                                sek,
                                &self.room,
                                self.drive_version,
                            )?;
                        }
                        let mut cleared = None;
                        if let Some(target) = withdrawn {
                            let mut locks = PendingLocks::load(store, signer)?;
                            if locks.clear(&self.room, target) {
                                locks.queue_save(&mut batch, signer)?;
                                changed = true;
                            }
                            cleared = Some(*target);
                        }
                        // Existing absence is already durable; a real deletion/debt mutation needs
                        // this ordinary commit. An empty reconciliation must not add a needless fsync.
                        if changed {
                            batch.commit()?;
                        }
                        deletion_committed = true;
                        Ok(TrustSaved::Deleted {
                            dropped: self.normal_deleted.len(),
                            debt_cleared: cleared,
                        })
                    }),
                    TrustWrite::RemovalPage { trusted, after } => {
                        let locks = PendingLocks::load(store, signer)?;
                        let mut iter = locks
                            .for_room(&self.room)
                            .into_iter()
                            .filter(|member| after.is_none_or(|a| *member > a));
                        let mut cursor = *after;
                        for _ in 0..64 {
                            let Some(member) = iter.next() else {
                                return Ok(TrustSaved::RemovalPage {
                                    target: None,
                                    after: cursor,
                                    done: true,
                                });
                            };
                            if !trusted.contains(&member) {
                                return Ok(TrustSaved::RemovalPage {
                                    target: Some(member),
                                    after: cursor,
                                    done: false,
                                });
                            }
                            cursor = Some(member);
                        }
                        Ok(TrustSaved::RemovalPage {
                            target: None,
                            after: cursor,
                            done: false,
                        })
                    }
                    TrustWrite::MarkDecisions | TrustWrite::MarkDecision { .. } => {
                        self.sek.with(|sek| {
                            let mut next = match batch.get_segment(
                                &self.room,
                                SegmentKind::KeyMaterial,
                                SEG_TRUST_MARKS,
                            )? {
                                Some(segment) => parse_marks(&open_segment(
                                    sek,
                                    SegmentKind::KeyMaterial,
                                    SEG_TRUST_MARKS,
                                    &segment,
                                )?)?,
                                None => BTreeMap::new(),
                            };
                            let mut changed = false;
                            let mut record = |target: Digest32, decision: Stamp| -> Result<()> {
                                if self.live.is_some_and(|live| live.after(&decision))
                                    || next.get(&target).is_some_and(|mark| mark.0 == decision)
                                {
                                    return Ok(());
                                }
                                if !next.contains_key(&target) && next.len() >= AUTHORS_HARD_LIMIT {
                                    return Err(Error::SizeLimitExceeded("trust marks"));
                                }
                                let position = (decision, self.position.0, self.position.1);
                                next.insert(target, position);
                                changed = true;
                                Ok(())
                            };
                            match &self.write {
                                TrustWrite::MarkDecision { target, decision } => {
                                    record(*target, *decision)?
                                }
                                _ => {
                                    let order = crate::node::consent_order::ConsentOrder::load(
                                        store, signer,
                                    )?;
                                    for (target, decision) in order.decisions() {
                                        record(target, decision)?;
                                    }
                                }
                            }
                            if changed {
                                let segment = seal_segment(
                                    sek,
                                    SegmentKind::KeyMaterial,
                                    SEG_TRUST_MARKS,
                                    &marks_bytes(&next),
                                )?;
                                batch.put_segment(
                                    &self.room,
                                    SegmentKind::KeyMaterial,
                                    SEG_TRUST_MARKS,
                                    &segment,
                                )?;
                                batch.commit()?;
                            }
                            marks = Some(next);
                            Ok(TrustSaved::Marked)
                        })
                    }
                }
            }))
            .unwrap_or_else(|_| Err(Error::Profile("trust save worker stopped")));
        // Candidate marks are an install delta only after their real commit. A sealing/queueing
        // failure or panic must not publish the candidate map.
        if result.is_err() {
            marks = None;
        }
        CompletedTrust {
            pending: self,
            deletion_committed,
            marks,
            result,
        }
    }
}
