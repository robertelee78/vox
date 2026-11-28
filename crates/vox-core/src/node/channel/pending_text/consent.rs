//! Consent publication retains the authored reservation, not the room or actor.
use super::*;
use crate::node::pending_consent::PendingConsents;

pub(crate) struct PendingConsent {
    append: PendingText,
    action: Action,
    entitled: BTreeMap<Digest32, (u64, u64)>,
    /// The key-debt ledger this save writes (`ChannelState::outstanding`).
    history: BTreeMap<Digest32, BTreeSet<u64>>,
    /// The posted marks of that ledger (`ChannelState::posted`), written with it.
    posted: crate::node::channel::Posted,
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
    /// The room's one forward-only migration (R9): its ledgers, the return cuts of members that
    /// came back before the update, as `(member, return sequence)`, and its marker in one batch.
    ForwardMigration {
        returns: Vec<(Digest32, u64)>,
    },
}

struct Issuance {
    target: Digest32,
    skdm: Box<Skdm>,
    entitled_from: (u64, u64),
    package: Option<crate::node::keypackage::KeyPackage>,
    /// The posted mark of `package` ([`crate::node::channel::posted_release`]): written in the
    /// package's own append batch when its generation is in the member's set; `None` once it
    /// was not written.
    mark: Option<Digest32>,
    /// What the grant owes: every retained generation from the merged entitlement on.
    owed: BTreeSet<u64>,
}

pub(crate) enum ConsentSaved {
    Issued { history_owed: bool },
    Withdrawn(Option<Box<ConsentRevocation>>),
    RoomRotated,
    Migrated,
}

pub(crate) struct CompletedConsent {
    append: CompletedText,
    entitled: Option<BTreeMap<Digest32, (u64, u64)>>,
    history: Option<BTreeMap<Digest32, BTreeSet<u64>>>,
    origins: Option<OriginKeyStore>,
    /// A committed held-key deletion must be installed even when the later append failed.
    pub(crate) held: Option<(Digest32, Digest32)>,
    /// Actual committed heads, including a package committed before a failed consent.
    pub(crate) package_seq: Option<u64>,
    pub(crate) package: Option<crate::node::keypackage::KeyPackage>,
    /// The posted mark `(member, generation, mark)` the committed package's append wrote.
    posted_mark: Option<(Digest32, u64, Digest32)>,
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
        let mut history = self.outstanding.clone();
        let targets: BTreeSet<_> = self
            .authors
            .keys()
            .chain(entitled.keys())
            .copied()
            .collect();
        for target in targets {
            let removals = view.validated_member_removals(&target)?;
            // A member here again after a departure is applied like a readmission (R3): its
            // return cut is a boundary as a removal cut is.
            let returned = target != me && self.key_returned(&target);
            // Rule F2 B: a proved forker is removed with no signed removal row; its boundary is
            // this sender's rotation itself (no observation cut to read).
            if removals.is_empty() && !returned && !view.is_member_removed(&target)? {
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
            if returned {
                let back = view
                    .return_cut(&target, &me)?
                    .ok_or(Error::Profile(governance::REFRESHING))?;
                cut = Some(cut.map_or(back.chain, |held: u64| held.max(back.chain)));
                had_entitlement |= back.entitlement.is_some();
            }
            let removed = view.is_member_removed(&target)?;
            let needs_boundary = removed
                || (had_entitlement
                    && entitled
                        .get(&target)
                        .is_none_or(|(chain, _)| *chain <= cut.unwrap_or(0)));
            if needs_boundary {
                // The boundary rewrites the set: a removed member is owed nothing, a readmitted
                // or returned one only what its new entitlement allows (the rotation adds it).
                history.remove(&target);
                if removed {
                    entitled.remove(&target);
                } else {
                    entitled.insert(target, (next_chain, 0));
                    // `VOX_TEST_FX62_MUTANT=readmission-backfill` (with the readmission body cut
                    // in `governance/view.rs` `recipient_cut`) undoes the readmission boundary:
                    // the member keeps the entitlement it held when it was removed.
                    #[cfg(feature = "test-knobs")]
                    if let Some(old) = previous_entitlement.filter(|_| {
                        std::env::var("VOX_TEST_FX62_MUTANT").as_deref()
                            == Ok("readmission-backfill")
                    }) {
                        eprintln!(
                            "test-knobs: readmission-backfill mutant engaged: entitlement {old:?} kept at readmission"
                        );
                        entitled.insert(target, old);
                    }
                }
            }
        }
        drop(view);
        let rotation = self.rotation(store, &history, &entitled, next_chain)?;
        let here = !self.said_left(&me);
        let mut append = self.prepare_pending_control(store, owner, now)?;
        append.removal_fence = Some(generation);
        Ok(Some(PendingConsent {
            append,
            action: Action::RoomRotation { generation, here },
            entitled,
            history,
            posted: self.posted.clone(),
            rotation: Some(rotation),
            ledgers_committed: false,
            origins_committed: None,
            held_committed: None,
            package_seq: None,
            package_attempted: false,
            consent_seq: None,
        }))
    }

    /// The room's forward-only migration (v0.4.31, R9), prepared from committed state: `None`
    /// once the room is migrated. `legacy_full` are the identities a build before v0.4.31
    /// trusted with older history, each with its trust decision.
    ///
    /// 1. A legacy full row is narrowed to its trust point: its entitlement and history row are
    ///    raised to the first position `history_plan` gives. For a member this identity once
    ///    untrusted and trusted again, that is where this room marked the re-trust, after its
    ///    latest revocation. A member once removed and readmitted by an admin already holds a
    ///    forward-only entitlement (its consent and the removal rotation set it), which is kept
    ///    with its debt. Where no trust point can be established, the member reads from the
    ///    live position on (accepted loss O1).
    /// 2. A member that left and came back before the update has its return applied as any
    ///    return is (R3): its return cut and one advance of the membership counter, so the
    ///    next rotation gives it a fresh chain and it reads from there on (accepted loss O2).
    /// 3. Every other entitled member that is neither removed nor departed keeps its
    ///    entitlement and is owed again, from it, every retained generation and the live one
    ///    (its origins are kept by its set), so the next re-key delivers them again under the
    ///    new policy and each answer settles its own.
    pub(crate) fn prepare_forward_migration(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        legacy_full: &BTreeMap<Digest32, Option<crate::node::consent_order::Stamp>>,
        now: crate::time::Ms,
    ) -> Result<Option<PendingConsent>> {
        if self.forward_migrated() {
            return Ok(None);
        }
        self.require_governance_ready(store, now)?;
        let me = self.me();
        let live = self.sender.chain_id();
        let live_position = (live, self.sender.current_position().0);
        let mut entitled = self.entitled.clone();
        let mut history = self.outstanding.clone();
        for (target, decision) in legacy_full {
            if *target == me
                || !self
                    .validated_member_removals(store, target, now)?
                    .is_empty()
            {
                continue;
            }
            // `test-knobs` mutant `VOX_TEST_FWD_MUTANT=migrate-clamp` undoes step 1's trust
            // point: every legacy full row is clamped to the live position, as if none could be
            // established, so the post-trust catch-up of a member offline across the update is
            // lost.
            #[cfg(feature = "test-knobs")]
            let clamp = std::env::var("VOX_TEST_FWD_MUTANT").as_deref() == Ok("migrate-clamp");
            #[cfg(not(feature = "test-knobs"))]
            let clamp = false;
            #[cfg(feature = "test-knobs")]
            if clamp {
                eprintln!("test-knobs: migrate-clamp mutant engaged: a legacy full row is clamped to the live position");
            }
            let plan = if clamp {
                None
            } else {
                self.history_plan(store, target, *decision)?
            };
            match plan {
                Some(plan) => {
                    let floor = plan[0];
                    if let Some(from) = entitled.get_mut(target) {
                        *from = (*from).max(floor);
                    }
                    if let Some(row) = history.get_mut(target) {
                        row.retain(|generation| *generation >= floor.0);
                    }
                }
                None => {
                    if let Some(from) = entitled.get_mut(target) {
                        *from = live_position;
                    }
                    if let Some(row) = history.get_mut(target) {
                        row.retain(|generation| *generation >= live);
                    }
                }
            }
        }
        let returns: Vec<(Digest32, u64)> = self
            .presence
            .iter()
            .filter(|(target, _)| **target != me && self.key_returned(target))
            .filter_map(|(target, presence)| presence.back.map(|(back, _)| (*target, back)))
            .collect();
        let targets: Vec<_> = entitled.keys().copied().collect();
        for target in targets {
            if target == me || self.key_excluded(store, &target)? || self.key_returned(&target) {
                continue;
            }
            let owed = entitled_generations(
                &self.origins,
                &self.channel_id,
                self.epoch,
                &me,
                live,
                entitled[&target].0,
            );
            history.entry(target).or_default().extend(owed);
        }
        let append = self.prepare_pending_control(store, owner, now)?;
        Ok(Some(PendingConsent {
            append,
            action: Action::ForwardMigration { returns },
            entitled,
            history,
            posted: self.posted.clone(),
            rotation: None,
            ledgers_committed: false,
            origins_committed: None,
            held_committed: None,
            package_seq: None,
            package_attempted: false,
            consent_seq: None,
        }))
    }

    /// Caller retains the original ComputerPublication and exact trust revision through enqueue.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_pending_consent(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        target: Digest32,
        skdm: Box<Skdm>,
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
        self.require_key_target(store, &target)?;
        let once_removed = !self
            .validated_member_removals(store, &target, now)?
            .is_empty();
        if (once_removed || self.key_returned(&target))
            && (skdm.body.chain_id != self.sender.chain_id()
                || entitled_from.0 != self.sender.chain_id())
        {
            return Err(Error::Profile(governance::REFRESHING));
        }
        // A held entitlement is the floor every later release starts from (R5): a key or a
        // floor before it, such as a pending consent key prepared before a return, is prepared
        // again from the entitlement.
        if let Some(floor) = self.entitled.get(&target) {
            if (skdm.body.chain_id, skdm.body.iteration) < *floor || entitled_from < *floor {
                return Err(Error::Profile(governance::REFRESHING));
            }
        }
        if !self.is_author(&target) {
            return Err(Error::MalformedGovernance(
                "consent target is not an author",
            ));
        }
        let entitled = self.entitled.clone();
        let history = self.outstanding.clone();
        let from = self
            .entitled
            .get(&target)
            .map_or(entitled_from, |old| (*old).min(entitled_from));
        let owed = entitled_generations(
            &self.origins,
            &self.channel_id,
            self.epoch,
            &self.me(),
            self.sender.chain_id(),
            from.0,
        );
        let mut append = self.prepare_pending_control(store, owner, now)?;
        append.removal_fence = Some(generation);
        let mut mark = None;
        if package.is_some() {
            let back = self.package_return(store, &target)?;
            if let Some(back) = back {
                append.require_ancestor(back);
            }
            // A package is posted once (V210-45): its mark goes in its own append's batch.
            mark = Some(crate::node::channel::posted_release(
                &back.unwrap_or(crate::node::channel::NEVER_LEFT),
                &crate::governance::membership::skdm_ref(&skdm),
            ));
        }
        Ok(PendingConsent {
            append,
            action: Action::Issue(Issuance {
                target,
                skdm,
                entitled_from,
                package,
                mark,
                owed,
            }),
            entitled,
            history,
            posted: self.posted.clone(),
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
        // A key may have gone out to the target when a grant committed, when it holds an
        // entitlement (a first grant's package writes the entitlement in its own batch, before
        // the grant commits, `PendingConsent::save`), or whenever it is an admitted author here:
        // a store written before this release may hold a package to it with neither a grant nor
        // a row. So the withdrawal rotates in each of those cases, and nothing written after it
        // is sealed under a key the target may hold. `authors` is this room's own durable
        // admission state; an identity that never was an author here was never given a key and
        // costs no rotation.
        let revoke = match self.has_consented(store, &target) {
            Ok(consented) => {
                consented || self.entitled.contains_key(&target) || self.is_author(&target)
            }
            Err(error) if governance::refreshing(&error) => true,
            Err(error) => return Err(error),
        };
        // Even an already committed revocation must replay its durable ledger cleanup. The
        // withdrawal is the target's boundary: its rotation owes the target nothing.
        let mut entitled = self.entitled.clone();
        let mut history = self.outstanding.clone();
        entitled.remove(&target);
        history.remove(&target);
        let rotation = if revoke {
            self.require_legacy_current(store)?;
            Some(self.rotation(store, &history, &entitled, self.next_generation()?)?)
        } else {
            None
        };
        let entitled = self.entitled.clone();
        let history = self.outstanding.clone();
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
            posted: self.posted.clone(),
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
            origins,
            posted_mark,
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
            // A consent change that takes generations out of a member's set (a boundary, a
            // withdrawal, the migration) owes it anew: no answer to a delivery selected before
            // settles it. One that only adds (a grant) leaves answers in flight valid.
            let renewed: Vec<Digest32> = history
                .iter()
                .flat_map(|history| {
                    self.outstanding.iter().filter(|(target, old)| {
                        history.get(*target).is_none_or(|new| !old.is_subset(new))
                    })
                })
                .map(|(target, _)| *target)
                .collect();
            for target in renewed {
                self.renew_history_debt(target);
            }
            if let Some(history) = history {
                self.outstanding = history;
            }
            if let Some(origins) = origins {
                self.origins = origins;
            }
            if let Some((target, generation, mark)) = posted_mark {
                self.note_package_posted(target, generation, mark);
            }
            if matches!(result, Ok(ConsentSaved::Migrated)) {
                self.forward_migrated = true;
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
            .filter(|error| {
                !governance::refreshing(error)
                    && !matches!(
                        error,
                        Error::Profile("this room's trust withdrawal is incomplete")
                    )
            })
            .map(ToString::to_string);
        let hash = self.append.committed.last().map(Entry::entry_hash);
        let (package, posted_mark) = match self.action {
            Action::Issue(issue) if self.package_seq.is_some() => {
                let generation = issue.skdm.body.chain_id;
                let mark = issue.mark.map(|mark| (issue.target, generation, mark));
                (issue.package, mark)
            }
            _ => (None, None),
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
            origins: self.origins_committed,
            held: self.held_committed,
            package_seq: self.package_seq,
            package,
            posted_mark,
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
                self.append.require_trust_withdrawn(store, signer)?;
                let Issuance {
                    target,
                    skdm,
                    entitled_from,
                    package,
                    mark,
                    owed,
                } = issue;
                let from = self
                    .entitled
                    .get(target)
                    .map_or(*entitled_from, |old| (*old).min(*entitled_from));
                self.entitled.insert(*target, from);
                // The debt follows the merged floor, not the supplied one: a re-issued consent
                // for an entitlement already held owes what that entitlement is owed (R5). It
                // only adds: what the member has not acknowledged stays in its set.
                let floor = from.0;
                let history_owed = floor < self.append.sender.chain_id();
                let row = self.history.entry(*target).or_default();
                let before = row.len();
                row.extend(
                    owed.iter()
                        .copied()
                        .filter(|generation| *generation >= floor),
                );
                let changed = row.len() != before || before == 0;
                if let Some(package) = package {
                    self.package_attempted = true;
                    // **The package writes the grant's ledgers and its posted mark in its own
                    // batch** (V210-45): it already hands the member the key, so the entitlement
                    // and the debt it creates are true from here, and a restart before the grant
                    // commits finds the mark, issues the grant and posts nothing again. A first
                    // grant's row is created here, with its mark.
                    let generation = skdm.body.chain_id;
                    *mark = mark.filter(|_| {
                        self.history
                            .get(target)
                            .is_some_and(|row| row.contains(&generation))
                    });
                    let mut posted = self.posted.clone();
                    if let Some(mark) = *mark {
                        posted.insert((*target, generation), mark);
                    }
                    let (entitled, history) = (&self.entitled, &self.history);
                    let rows = self.append.sek.with(|sek| {
                        Ok(vec![
                            (
                                SEG_ENTITLED,
                                Some(seal_segment(
                                    sek,
                                    SegmentKind::KeyMaterial,
                                    SEG_ENTITLED,
                                    &positions_bytes(entitled),
                                )?),
                            ),
                            (
                                SEG_HISTORY,
                                Some(seal_segment(
                                    sek,
                                    SegmentKind::KeyMaterial,
                                    SEG_HISTORY,
                                    &outstanding_bytes(history, &posted),
                                )?),
                            ),
                        ])
                    })?;
                    self.append.append(
                        store,
                        signer,
                        package.to_wire(),
                        EntryKind::Content,
                        SignedEntryKind::KeyPackage,
                        None,
                        &rows,
                        None,
                    )?;
                    self.posted = posted;
                    self.ledgers_committed = true;
                    self.package_seq = Some(self.append.control_head(&signer.fingerprint()));
                    self.append.cleanup(store)?;
                }
                // The disk key goes first. Failure can narrow but cannot resurrect an old release.
                {
                    // Read after writer admission: parallel room saves must not overwrite a
                    // newer pending-consent map with a captured actor snapshot.
                    let mut batch = store.batch()?;
                    self.append.require_trust_withdrawn(store, signer)?;
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
                    HistoryMode::ForwardOnly,
                )?;
                let changed = changed && !self.ledgers_committed;
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
                                &outstanding_bytes(&self.history, &self.posted),
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
                // The withdrawal is the member's boundary: its entitlement and its set go, so
                // it is owed nothing and pins nothing.
                let mut entitled = self.entitled.clone();
                let mut history = self.history.clone();
                let changed =
                    entitled.remove(&target).is_some() | history.remove(&target).is_some();
                if changed {
                    let mut batch = store.batch()?;
                    self.append.sek.with(|sek| {
                        for (slot, bytes) in [
                            (SEG_ENTITLED, positions_bytes(&entitled)),
                            (SEG_HISTORY, outstanding_bytes(&history, &self.posted)),
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
            Action::ForwardMigration { returns } => {
                let mut batch = store.batch()?;
                self.append.sek.with(|sek| {
                    // Each return is reconciled before the ledgers are written, so its cut
                    // records the entitlement the member held before the update.
                    for (target, back) in returns.iter() {
                        governance::reconcile_return(
                            &mut batch,
                            sek,
                            &self.append.room,
                            target,
                            *back,
                        )?;
                    }
                    for (slot, bytes) in [
                        (SEG_ENTITLED, positions_bytes(&self.entitled)),
                        (SEG_HISTORY, outstanding_bytes(&self.history, &self.posted)),
                        (SEG_FORWARD_MIGRATED, forward_migrated_bytes()),
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
                self.ledgers_committed = true;
                Ok(ConsentSaved::Migrated)
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
        // The generation its debt owes, so what is minted and what is owed cannot differ.
        let next = SenderChain::new(
            &self.append.room,
            self.append.epoch,
            &signer.fingerprint(),
            rotation.debt.minted,
            self.append.now_millis,
        )?;
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
        let lost = rotation.debt.apply(&mut self.history);
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
                        &outstanding_bytes(&self.history, &self.posted),
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
        rotation.debt.say_lost(&self.append.room, &lost);
        self.append.cleanup(store)
    }
}
