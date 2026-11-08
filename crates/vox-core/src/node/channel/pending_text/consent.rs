//! Consent publication retains the authored reservation, not the room or actor.
use super::*;
use crate::node::pending_consent::PendingConsents;

pub(crate) struct PendingConsent {
    append: PendingText,
    action: Action,
    entitled: BTreeMap<Digest32, (u64, u64)>,
    history: BTreeMap<Digest32, u64>,
    delivered: Option<BTreeMap<Digest32, u64>>,
    rotation: Option<Rotation>,
    ledgers_committed: bool,
    origins_committed: Option<OriginKeyStore>,
    held_committed: Option<(Digest32, Digest32)>,
    package_seq: Option<u64>,
    package_attempted: bool,
    consent_seq: Option<u64>,
}

enum Action {
    Issue(Issuance),
    Withdraw {
        target: Digest32,
        revoke: bool,
        here: bool,
    },
    RoomRotation {
        generation: u64,
        here: bool,
    },
}

struct Issuance {
    target: Digest32,
    skdm: Box<Skdm>,
    full_history: bool,
    entitled_from: (u64, u64),
    package: Option<crate::node::keypackage::KeyPackage>,
}

pub(crate) enum ConsentSaved {
    Issued { history_owed: bool },
    Withdrawn(Option<Box<ConsentRevocation>>),
    RoomRotated,
}

pub(crate) struct CompletedConsent {
    append: CompletedText,
    entitled: Option<BTreeMap<Digest32, (u64, u64)>>,
    history: Option<BTreeMap<Digest32, u64>>,
    delivered: Option<BTreeMap<Digest32, u64>>,
    origins: Option<OriginKeyStore>,
    /// A committed held-key deletion must be installed even when the later append failed.
    pub(crate) held: Option<(Digest32, Digest32)>,
    /// Actual committed heads, including a package committed before a failed consent.
    pub(crate) package_seq: Option<u64>,
    pub(crate) package: Option<crate::node::keypackage::KeyPackage>,
    pub(crate) release: Option<Box<Skdm>>,
    pub(crate) consent_seq: Option<u64>,
    package_unconfirmed: bool,
    pub(crate) result: Result<ConsentSaved>,
}

impl CompletedConsent {
    pub(crate) fn package_unconfirmed(&self) -> bool {
        self.package_unconfirmed
    }

    pub(crate) fn can_install(&self, room: &ChannelState, owner: &Arc<()>) -> bool {
        self.append.can_install(room, owner)
            && self.append.pending.as_ref().is_some_and(|pending| {
                pending.room == room.channel_id && pending.epoch == room.epoch
            })
    }

    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.append.take_history_pin()
    }
}

impl ChannelState {
    /// A newly applied room-removal generation must have a durable fresh sender chain
    /// before this node can encrypt or release another room key.
    pub(crate) fn room_removal_rotation_needed(&self, store: &Store) -> Result<bool> {
        let generation = governance::removal_generation(store, &self.channel_id)?;
        let Some(segment) = store.get_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_ROOM_REMOVAL_SENDER,
        )?
        else {
            return Ok(generation != 0);
        };
        let bytes = open_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_ROOM_REMOVAL_SENDER,
            &segment,
        )?;
        let mut d = Decoder::new(&bytes);
        if d.array()? != 3 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest("room sender rotation checkpoint"));
        }
        let checked = d.uint()?;
        let chain = d.uint()?;
        d.finish()?;
        if checked > generation || chain > self.sender.chain_id() {
            return Err(Error::MalformedAtRest(
                "room sender rotation checkpoint ahead",
            ));
        }
        Ok(checked != generation)
    }

    pub(crate) fn prepare_room_removal_rotation(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
    ) -> Result<Option<PendingConsent>> {
        self.require_governance_ready(store, now)?;
        let me = self.me();
        if self.is_member_removed(store, &me)? || !self.room_removal_rotation_needed(store)? {
            return Ok(None);
        }
        self.require_legacy_current(store)?;
        let generation = governance::removal_generation(store, &self.channel_id)?;
        let view = self.checked_governance(store, now.get())?;
        let next_chain = self
            .sender
            .chain_id()
            .checked_add(1)
            .ok_or(Error::MalformedBundle("sender chain_id overflow"))?;
        let mut entitled = self.entitled.clone();
        let mut history = self.history.clone();
        let mut delivered = self.delivered.clone();
        let targets: BTreeSet<_> = self
            .authors
            .keys()
            .chain(entitled.keys())
            .copied()
            .collect();
        for target in targets {
            let removals = view.validated_member_removals(&target)?;
            if removals.is_empty() {
                continue;
            }
            let mut cut = None;
            let mut had_entitlement = entitled.contains_key(&target);
            #[cfg(feature = "test-knobs")]
            let mut previous_entitlement = None;
            for hash in removals {
                let (chain, old) = view
                    .sender_cut(&hash, &target, &me)?
                    .ok_or(Error::Profile(governance::REFRESHING))?;
                cut = Some(cut.map_or(chain, |held: u64| held.max(chain)));
                had_entitlement |= old.is_some();
                #[cfg(feature = "test-knobs")]
                if old.is_some() {
                    previous_entitlement = old;
                }
            }
            let removed = view.is_member_removed(&target)?;
            let needs_boundary = removed
                || (had_entitlement
                    && entitled
                        .get(&target)
                        .is_none_or(|(chain, _)| *chain <= cut.unwrap_or(0)));
            if needs_boundary {
                history.remove(&target);
                delivered.remove(&target);
                if removed {
                    entitled.remove(&target);
                } else {
                    entitled.insert(target, (next_chain, 0));
                    #[cfg(feature = "test-knobs")]
                    if let Some(old) = previous_entitlement.filter(|_| {
                        std::env::var("VOX_TEST_FX62_MUTANT").as_deref() == Ok("old-entitlement")
                    }) {
                        entitled.insert(target, old);
                    }
                }
            }
        }
        drop(view);
        let readers = self.with_consent_facts(|facts| {
            entitled
                .keys()
                .filter(|target| facts.can_read(target, &me))
                .copied()
                .collect::<BTreeSet<_>>()
        })?;
        let retired = self.sender.chain_id();
        let mut owed = Vec::new();
        for (reader, (from, _)) in &entitled {
            if *reader == me
                || self.has_left(reader)
                || !readers.contains(reader)
                || self.is_member_removed(store, reader)?
            {
                continue;
            }
            let floor = match delivered.get(reader) {
                None => *from,
                Some(delivered) if *delivered < retired => (*delivered + 1).max(*from),
                Some(_) => continue,
            };
            if floor <= retired {
                owed.push((*reader, floor));
            }
        }
        let rotation = Rotation {
            origins: OriginKeyStore::from_state(&self.origins.to_state())?,
            newest_mint: self.newest_mint_seq(),
            history: rotation_history_bytes(&history, &owed),
            owed,
        };
        let delivered = Some(delivered);
        let here = !self.said_left(&me);
        let mut append = self.prepare_pending_control(store, owner, now)?;
        append.removal_fence = Some(generation);
        Ok(Some(PendingConsent {
            append,
            action: Action::RoomRotation { generation, here },
            entitled,
            history,
            delivered,
            rotation: Some(rotation),
            ledgers_committed: false,
            origins_committed: None,
            held_committed: None,
            package_seq: None,
            package_attempted: false,
            consent_seq: None,
        }))
    }

    /// Full-history consent needs positions and its live key, not a signed copy of every
    /// retained historical key. Actual history deliveries still sign their selected keys.
    pub(crate) fn full_consent_release(
        &self,
        profile: &Profile,
    ) -> Result<(Skdm, Vec<(u64, u64)>)> {
        let live = self.rekey_skdm(profile)?;
        let mut plan: Vec<_> = self
            .origins
            .generations(&self.channel_id, self.epoch, &self.me())
            .into_iter()
            .filter(|(generation, _)| *generation != live.body.chain_id)
            .map(|(generation, _)| (generation, 0))
            .collect();
        plan.push((live.body.chain_id, live.body.iteration));
        Ok((live, plan))
    }

    /// Caller retains the original ComputerPublication and exact trust revision through enqueue.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_pending_consent(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        target: Digest32,
        skdm: Box<Skdm>,
        full_history: bool,
        entitled_from: (u64, u64),
        package: Option<crate::node::keypackage::KeyPackage>,
        now: crate::time::Ms,
    ) -> Result<PendingConsent> {
        self.require_legacy_current(store)?;
        self.require_governance_ready(store, now)?;
        let generation = self.removal_generation(store)?;
        if self.is_member_removed(store, &self.me())?
            || self.is_member_removed(store, &target)?
            || self.room_removal_rotation_needed(store)?
        {
            return Err(Error::Profile(governance::REFRESHING));
        }
        governance::check_removal_generation(store, &self.sek, &self.channel_id, generation)?;
        let once_removed = !self
            .validated_member_removals(store, &target, now)?
            .is_empty();
        #[cfg(feature = "test-knobs")]
        let once_removed = once_removed
            && std::env::var("VOX_TEST_FX62_MUTANT").as_deref() != Ok("readmission-full-plan");
        if once_removed
            && (skdm.body.chain_id != self.sender.chain_id()
                || entitled_from.0 != self.sender.chain_id()
                || full_history)
        {
            return Err(Error::Profile(governance::REFRESHING));
        }
        if !self.is_author(&target) {
            return Err(Error::MalformedGovernance(
                "consent target is not an author",
            ));
        }
        let entitled = self.entitled.clone();
        let history = self.history.clone();
        let mut append = self.prepare_pending_control(store, owner, now)?;
        append.removal_fence = Some(generation);
        Ok(PendingConsent {
            append,
            action: Action::Issue(Issuance {
                target,
                skdm,
                full_history,
                entitled_from,
                package,
            }),
            entitled,
            history,
            delivered: None,
            rotation: None,
            ledgers_committed: false,
            origins_committed: None,
            held_committed: None,
            package_seq: None,
            package_attempted: false,
            consent_seq: None,
        })
    }

    /// Narrowing may proceed while consent facts replay; incomplete facts never grant a key.
    pub(crate) fn prepare_pending_withdrawal(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        target: Digest32,
        now: crate::time::Ms,
    ) -> Result<PendingConsent> {
        if target == self.me() {
            return Err(Error::MalformedGovernance(
                "an identity cannot withdraw trust in itself",
            ));
        }
        let revoke = match self.has_consented(store, &target) {
            Ok(consented) => consented,
            Err(error) if governance::refreshing(&error) => true,
            Err(error) => return Err(error),
        };
        // Even an already committed revocation must replay its durable ledger cleanup.
        let rotation = if revoke {
            self.require_legacy_current(store)?;
            let me = self.me();
            let readers = match self.with_consent_facts(|facts| {
                self.entitled
                    .keys()
                    .filter(|t| facts.can_read(t, &me))
                    .copied()
                    .collect::<BTreeSet<_>>()
            }) {
                Ok(readers) => Some(readers),
                Err(error) if governance::refreshing(&error) => None,
                Err(error) => return Err(error),
            };
            let retired = self.sender.chain_id();
            let mut owed = Vec::new();
            for (reader, (from, _)) in &self.entitled {
                if *reader == me
                    || self.has_left(reader)
                    || !readers
                        .as_ref()
                        .is_none_or(|readers| readers.contains(reader))
                {
                    continue;
                }
                let floor = match self.delivered.get(reader) {
                    None => *from,
                    Some(delivered) if *delivered < retired => (*delivered + 1).max(*from),
                    Some(_) => continue,
                };
                if floor <= retired {
                    owed.push((*reader, floor));
                }
            }
            Some(Rotation {
                origins: OriginKeyStore::from_state(&self.origins.to_state())?,
                newest_mint: self.newest_mint_seq(),
                history: rotation_history_bytes(&self.history, &owed),
                owed,
            })
        } else {
            None
        };
        let entitled = self.entitled.clone();
        let history = self.history.clone();
        let delivered = Some(self.delivered.clone());
        let here = !self.said_left(&self.me());
        let append = if revoke {
            self.prepare_pending_control(store, owner, now)?
        } else {
            // An already committed withdrawal still clears its ledgers while own history or
            // governance catches up; this path authors no entry and grants no key.
            let sparse = self
                .entries
                .read(store, &self.sek, &self.channel_id)?
                .sparse_enabled();
            self.prepare_pending_append(
                store,
                self.me(),
                owner,
                now.get(),
                now.get(),
                sparse,
                Vec::new(),
                None,
            )?
        };
        Ok(PendingConsent {
            append,
            action: Action::Withdraw {
                target,
                revoke,
                here,
            },
            entitled,
            history,
            delivered,
            rotation,
            ledgers_committed: false,
            origins_committed: None,
            held_committed: None,
            package_seq: None,
            package_attempted: false,
            consent_seq: None,
        })
    }

    pub(crate) fn finish_pending_consent(
        &mut self,
        store: &Store,
        completed: CompletedConsent,
    ) -> Result<ConsentSaved> {
        let CompletedConsent {
            append,
            entitled,
            history,
            delivered,
            origins,
            result,
            ..
        } = completed;
        let matching = append.pending.as_ref().is_some_and(|pending| {
            pending.room == self.channel_id
                && pending.epoch == self.epoch
                && self
                    .pending_text
                    .as_ref()
                    .is_some_and(|owner| Arc::ptr_eq(owner, &pending.owner))
        });
        if matching {
            if let Some(entitled) = entitled {
                self.entitled = entitled;
            }
            if let Some(history) = history {
                self.history = history;
            }
            if let Some(delivered) = delivered {
                self.delivered = delivered;
            }
            if let Some(origins) = origins {
                self.origins = origins;
            }
        }
        // The append result is an installation receipt; the real operation result below may
        // still be an error after an earlier durable rotation/package/grant.
        let _ = self.finish_pending_text(store, append);
        result
    }
}

impl PendingConsent {
    pub(crate) fn run(
        mut self,
        store: &Store,
        signer: &crate::atrest::vault::VaultRootSigner,
    ) -> CompletedConsent {
        // Keep the candidate outside catch_unwind so every earlier committed delta survives.
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.save(store, signer)))
                .unwrap_or_else(|_| Err(Error::Profile("consent save worker stopped")));
        // Every committed package, held-key deletion and rotation is carried by the
        // completion below. A generation refusal must not turn the room into a storage fault.
        let failure = result
            .as_ref()
            .err()
            .filter(|error| !governance::refreshing(error))
            .map(ToString::to_string);
        let hash = self.append.committed.last().map(Entry::entry_hash);
        let (package, release) = match self.action {
            Action::Issue(issue) => (
                if self.package_seq.is_some() {
                    issue.package
                } else {
                    None
                },
                result.is_ok().then_some(issue.skdm),
            ),
            Action::Withdraw { .. } | Action::RoomRotation { .. } => (None, None),
        };
        let append = CompletedText {
            pending: Some(self.append),
            result: Ok(Saved::Governance(hash)),
            failure,
            #[cfg(feature = "test-knobs")]
            rotated: self.origins_committed.is_some(),
        };
        CompletedConsent {
            append,
            entitled: self.ledgers_committed.then_some(self.entitled),
            history: self.ledgers_committed.then_some(self.history),
            delivered: if self.ledgers_committed {
                self.delivered
            } else {
                None
            },
            origins: self.origins_committed,
            held: self.held_committed,
            package_seq: self.package_seq,
            package,
            release,
            consent_seq: self.consent_seq,
            package_unconfirmed: self.package_attempted
                && self.package_seq.is_none()
                && result.is_err(),
            result,
        }
    }

    fn save(
        &mut self,
        store: &Store,
        signer: &crate::atrest::vault::VaultRootSigner,
    ) -> Result<ConsentSaved> {
        match &mut self.action {
            Action::Issue(issue) => {
                let Issuance {
                    target,
                    skdm,
                    full_history,
                    entitled_from,
                    package,
                } = issue;
                if let Some(package) = package {
                    self.package_attempted = true;
                    self.append.append(
                        store,
                        signer,
                        package.to_wire(),
                        EntryKind::Content,
                        SignedEntryKind::KeyPackage,
                        None,
                        &[],
                        None,
                    )?;
                    self.package_seq = Some(self.append.control_head(&signer.fingerprint()));
                    self.append.cleanup(store)?;
                }
                // The disk key goes first. Failure can narrow but cannot resurrect an old release.
                {
                    // Read after writer admission: parallel room saves must not overwrite a
                    // newer pending-consent map with a captured actor snapshot.
                    let mut batch = store.batch()?;
                    let mut held = PendingConsents::load(store, signer)?;
                    if held.remove(&self.append.room, target) {
                        held.queue_save(&mut batch, signer)?;
                        batch.commit()?;
                    }
                    self.held_committed = Some((self.append.room, *target));
                }
                let grant = issue_consent_grant(
                    signer,
                    &self.append.room,
                    self.append.epoch,
                    *target,
                    skdm,
                    if *full_history {
                        HistoryMode::FullHistory
                    } else {
                        HistoryMode::ForwardOnly
                    },
                )?;
                let from = self
                    .entitled
                    .get(target)
                    .map_or(*entitled_from, |old| (*old).min(*entitled_from));
                self.entitled.insert(*target, from);
                let floor = entitled_from.0;
                let history_owed =
                    floor < skdm.body.chain_id && floor < self.append.sender.chain_id();
                let changed =
                    history_owed && self.history.get(target).is_none_or(|old| *old > floor);
                if changed {
                    self.history.insert(*target, floor);
                }
                let rows = self.append.sek.with(|sek| {
                    let mut rows = vec![(
                        SEG_ENTITLED,
                        Some(seal_segment(
                            sek,
                            SegmentKind::KeyMaterial,
                            SEG_ENTITLED,
                            &positions_bytes(&self.entitled),
                        )?),
                    )];
                    if changed {
                        rows.push((
                            SEG_HISTORY,
                            Some(seal_segment(
                                sek,
                                SegmentKind::KeyMaterial,
                                SEG_HISTORY,
                                &delivered_bytes(&self.history),
                            )?),
                        ));
                    }
                    Ok(rows)
                })?;
                self.append.append(
                    store,
                    signer,
                    grant.to_wire(),
                    EntryKind::Governance,
                    SignedEntryKind::Governance,
                    None,
                    &rows,
                    None,
                )?;
                self.ledgers_committed = true;
                self.consent_seq = Some(self.append.control_head(&signer.fingerprint()));
                self.append.cleanup(store)?;
                Ok(ConsentSaved::Issued { history_owed })
            }
            Action::Withdraw {
                target,
                revoke,
                here,
            } => {
                let target = *target;
                let revoke = *revoke;
                let here = *here;
                let revocation = if revoke {
                    self.rotate_for_withdrawal(store, signer, here, None)?;
                    let revocation = issue_consent_revocation(
                        signer,
                        &self.append.room,
                        self.append.epoch,
                        target,
                        self.append.sender.chain_id(),
                    )?;
                    self.append.append(
                        store,
                        signer,
                        revocation.to_wire(),
                        EntryKind::Governance,
                        SignedEntryKind::Governance,
                        None,
                        &[],
                        None,
                    )?;
                    self.consent_seq = Some(self.append.control_head(&signer.fingerprint()));
                    self.append.cleanup(store)?;
                    Some(Box::new(revocation))
                } else {
                    None
                };
                let mut entitled = self.entitled.clone();
                let mut history = self.history.clone();
                let mut delivered = self
                    .delivered
                    .clone()
                    .ok_or(Error::MalformedAtRest("withdrawal delivered state missing"))?;
                let changed = entitled.remove(&target).is_some()
                    | history.remove(&target).is_some()
                    | delivered.remove(&target).is_some();
                if changed {
                    let mut batch = store.batch()?;
                    self.append.sek.with(|sek| {
                        for (slot, bytes) in [
                            (SEG_ENTITLED, positions_bytes(&entitled)),
                            (SEG_HISTORY, delivered_bytes(&history)),
                            (SEG_DELIVERED, delivered_bytes(&delivered)),
                        ] {
                            batch.put_segment(
                                &self.append.room,
                                SegmentKind::KeyMaterial,
                                slot,
                                &seal_segment(sek, SegmentKind::KeyMaterial, slot, &bytes)?,
                            )?;
                        }
                        Ok(())
                    })?;
                    batch.commit()?;
                    self.entitled = entitled;
                    self.history = history;
                    self.delivered = Some(delivered);
                    self.ledgers_committed = true;
                }
                Ok(ConsentSaved::Withdrawn(revocation))
            }
            Action::RoomRotation { generation, here } => {
                let generation = *generation;
                let here = *here;
                self.rotate_for_withdrawal(store, signer, here, Some(generation))?;
                Ok(ConsentSaved::RoomRotated)
            }
        }
    }

    fn rotate_for_withdrawal(
        &mut self,
        store: &Store,
        signer: &crate::atrest::vault::VaultRootSigner,
        here: bool,
        checkpoint: Option<u64>,
    ) -> Result<()> {
        let mut rotation = self
            .rotation
            .take()
            .ok_or(Error::MalformedAtRest("withdrawal rotation missing"))?;
        let next = self.append.sender.rotated(self.append.now_millis)?;
        let mint = crate::node::consent_order::stamp_mint(store, signer, rotation.newest_mint)?;
        retain_generation(
            &mut rotation.origins,
            &self.append.room,
            self.append.epoch,
            &signer.fingerprint(),
            &next,
            self.append.now_millis,
            mint,
        )?;
        for (target, floor) in &rotation.owed {
            self.history
                .entry(*target)
                .and_modify(|old| *old = (*old).min(*floor))
                .or_insert(*floor);
        }
        let rows = self.append.sek.with(|sek| {
            Ok([
                (
                    SEG_SENDER,
                    Some(seal_segment(
                        sek,
                        SegmentKind::KeyMaterial,
                        SEG_SENDER,
                        &next.to_state(),
                    )?),
                ),
                (
                    SEG_ORIGINS,
                    Some(seal_segment(
                        sek,
                        SegmentKind::KeyMaterial,
                        SEG_ORIGINS,
                        &rotation.origins.to_state(),
                    )?),
                ),
                (
                    SEG_HISTORY,
                    Some(seal_segment(
                        sek,
                        SegmentKind::KeyMaterial,
                        SEG_HISTORY,
                        &delivered_bytes(&self.history),
                    )?),
                ),
                (
                    SEG_ENTITLED,
                    checkpoint
                        .map(|_| {
                            seal_segment(
                                sek,
                                SegmentKind::KeyMaterial,
                                SEG_ENTITLED,
                                &positions_bytes(&self.entitled),
                            )
                        })
                        .transpose()?,
                ),
                (
                    SEG_DELIVERED,
                    checkpoint
                        .map(|_| {
                            let delivered = self.delivered.as_ref().ok_or(
                                Error::MalformedAtRest("room rotation delivered state missing"),
                            )?;
                            seal_segment(
                                sek,
                                SegmentKind::KeyMaterial,
                                SEG_DELIVERED,
                                &delivered_bytes(delivered),
                            )
                        })
                        .transpose()?,
                ),
                (
                    SEG_ROOM_REMOVAL_SENDER,
                    checkpoint
                        .map(|generation| {
                            let mut e = Encoder::new();
                            e.array(3).uint(1).uint(generation).uint(next.chain_id());
                            seal_segment(
                                sek,
                                SegmentKind::KeyMaterial,
                                SEG_ROOM_REMOVAL_SENDER,
                                &e.finish(),
                            )
                        })
                        .transpose()?,
                ),
            ])
        })?;
        if self.append.sparse {
            let statement = crate::governance::presence::Presence::build(
                signer,
                &self.append.room,
                self.append.epoch,
                here,
                next.chain_id(),
            )?;
            self.append.append(
                store,
                signer,
                statement.to_wire(),
                EntryKind::Governance,
                SignedEntryKind::Governance,
                None,
                &rows,
                None,
            )?;
        } else {
            let mut batch = store.batch()?;
            if let Some(generation) = checkpoint {
                self.append.sek.with(|sek| {
                    governance::check_removal_generation_in(
                        &batch,
                        sek,
                        &self.append.room,
                        generation,
                    )
                })?;
            }
            for (slot, segment) in &rows {
                if let Some(segment) = segment {
                    batch.put_segment(
                        &self.append.room,
                        SegmentKind::KeyMaterial,
                        *slot,
                        segment,
                    )?;
                }
            }
            batch.commit()?;
        }
        self.append.sender = next;
        self.origins_committed = Some(rotation.origins);
        self.ledgers_committed = true;
        self.append.cleanup(store)
    }
}
