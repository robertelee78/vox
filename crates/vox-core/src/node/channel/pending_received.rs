//! Exact received effect/refill ownership. A completion carries both committed deltas and
//! its actual error; a later visibility failure cannot discard an earlier data commit.
use super::semantic_projection::{PreparedContent, ProjectionOutcome, SemanticProjection};
use super::sparse_history::*;
use super::*;
use crate::atrest::sek::WeakSek;
#[cfg(feature = "test-knobs")]
use crate::log::entry::EntryRead;
use crate::log::history::SignedEntryKind;
use crate::node::store::{Batch, ReceivedFlow};
use std::sync::atomic::{AtomicBool, Ordering};

enum Work {
    Immediate(HistoryEffectProgress),
    Finished {
        author: Digest32,
        refill_pending: bool,
        body_expected: bool,
    },
    Effect {
        entry: Entry,
        log: u64,
        body_expected: bool,
    },
    Refill {
        head: Digest32,
        log: u64,
        settled: bool,
        key_body: Option<crate::node::history_stream::KeyBodyNeed>,
    },
}

pub(crate) struct PendingReceived {
    room: Digest32,
    epoch: u64,
    me: Digest32,
    creator: Digest32,
    authors: BTreeMap<Digest32, CompositePublicKey>,
    sek: WeakSek,
    index: entry_store::EntryIndex,
    cursor: HistoryEffectCursor,
    work: Work,
    projection: Option<SemanticProjection>,
    content: Option<PreparedContent>,
    presence: Option<governance::Presence>,
    late: bool,
    private: Vec<(Digest32, Digest32, u64)>,
    refill_recipient: bool,
    maintenance_now: crate::time::Ms,
}

pub(crate) struct CompletedReceived {
    pending: PendingReceived,
    pub(crate) result: Result<HistoryEffectProgress>,
    committed: bool,
    effect: Option<(Digest32, u64, u64, SignedEntryKind, bool)>,
    presence: Option<(Digest32, governance::Presence)>,
    consent: bool,
    governance_changed: bool,
    contiguous: Option<(Digest32, entry_store::sparse::ContiguousAdvance)>,
    private: Vec<Digest32>,
    available: Option<Digest32>,
    poisoned: bool,
}

impl CompletedReceived {
    pub(crate) fn legacy_migration(&self) -> Option<crate::time::Ms> {
        (self.committed
            && matches!(
                &self.pending.work,
                Work::Effect { .. } | Work::Refill { .. }
            ))
        .then_some(self.pending.maintenance_now)
    }
}

impl ChannelState {
    pub(crate) fn prepare_received_effect(
        &mut self,
        store: &Store,
        mut cursor: HistoryEffectCursor,
        now: crate::time::Ms,
        body_expected: bool,
        historical: bool,
    ) -> Result<PendingReceived> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let input = self.history_read(store)?;
        let hash = cursor.hash;
        let header = input
            .history_object(entry_store::sparse::ObjectKind::Header, &hash)?
            .map(|wire| Entry::from_wire(&wire))
            .transpose()?
            .ok_or(Error::MalformedAtRest(
                "pending history source header missing",
            ))?;
        let mut work = if input.history_effect_finished(&hash)? {
            let refill_pending = body_expected
                && header
                    .skeleton
                    .v2
                    .as_ref()
                    .is_some_and(|v2| v2.kind == SignedEntryKind::Content)
                && input
                    .retention(&hash)?
                    .is_none_or(|tracked| tracked.cache_id.is_none());
            Work::Finished {
                author: header.skeleton.author_id,
                refill_pending,
                body_expected,
            }
        } else {
            self.require_history_source_boundary(&header)?;
            let v2 = header
                .skeleton
                .v2
                .as_ref()
                .ok_or(Error::MalformedAtRest("pending history source is legacy"))?;
            let context = input
                .history_context(&v2.pre_context)?
                .ok_or(Error::MalformedAtRest("pending history context missing"))?;
            if cursor.next > context.coordinates.len() {
                return Err(Error::MalformedAtRest(
                    "history effect cursor outside context",
                ));
            }
            let end = cursor
                .next
                .saturating_add(64)
                .min(context.coordinates.len());
            let mut waiting = None;
            for coordinate in &context.coordinates[cursor.next..end] {
                let (head, control) = input
                    .history_validated_header(&coordinate.author, coordinate.seq)?
                    .ok_or(Error::MalformedAtRest("validated history control vanished"))?;
                if control.entry_hash() != coordinate.hash {
                    return Err(Error::MalformedAtRest("history control binding changed"));
                }
                if !input.control_effects_complete(&head, coordinate.seq)? {
                    waiting = Some(HistoryEffectProgress::ControlPending {
                        head,
                        through: coordinate.seq,
                    });
                    break;
                }
                cursor.next += 1;
            }
            if let Some(waiting) = waiting {
                Work::Immediate(waiting)
            } else if cursor.next < context.coordinates.len() {
                Work::Immediate(HistoryEffectProgress::Progress)
            } else {
                let entry = input.history_entry(&hash)?.ok_or(Error::MalformedAtRest(
                    "pending history body record missing",
                ))?;
                let log = input
                    .log_id(&hash)?
                    .ok_or(Error::MalformedAtRest("pending history locator missing"))?;
                let checkpoint_pending = if v2.kind == SignedEntryKind::Checkpoint {
                    let checkpoint = entry
                        .payload
                        .as_deref()
                        .map(crate::log::checkpoint::Checkpoint::from_payload)
                        .transpose()?
                        .flatten()
                        .ok_or(Error::MalformedAtRest("checkpoint body missing"))?;
                    input
                        .history_position_header(&entry.skeleton.author_id, checkpoint.seq)?
                        .is_none_or(|named| named.entry_hash() != checkpoint.entry_hash)
                        .then_some(HistoryEffectProgress::CheckpointPending {
                            author: entry.skeleton.author_id,
                            seq: checkpoint.seq,
                        })
                } else {
                    None
                };
                if let Some(progress) = checkpoint_pending {
                    Work::Immediate(progress)
                } else {
                    Work::Effect {
                        entry,
                        log,
                        body_expected,
                    }
                }
            }
        };
        drop(input);
        if let Work::Effect { entry, .. } = &work {
            let kind = entry
                .skeleton
                .v2
                .as_ref()
                .ok_or(Error::MalformedAtRest("pending history source is legacy"))?
                .kind;
            if matches!(
                kind,
                SignedEntryKind::Governance | SignedEntryKind::StepPolicy
            ) && !matches!(governance::sparse_control_evaluation(store, &self.sek, &self.channel_id, entry, now.get())?,
                    governance::ControlEvaluation::Settled(receipt) if receipt.entry_hash() == cursor.hash)
            {
                work = Work::Immediate(HistoryEffectProgress::GovernancePending);
            } else {
                match self.checked_governance(store, now.get()) {
                    Ok(view) => drop(view),
                    Err(error) if governance::refreshing(&error) => {
                        work = Work::Immediate(HistoryEffectProgress::GovernancePending);
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        let mut pending = self.received_context(store, cursor, work, now.get())?;
        if let Work::Effect { entry, .. } = &pending.work {
            if entry
                .skeleton
                .v2
                .as_ref()
                .is_some_and(|v2| v2.kind == SignedEntryKind::Content)
            {
                if let Some(payload) = entry.payload.as_deref() {
                    pending.content = Some(
                        pending
                            .projection
                            .as_mut()
                            .ok_or(Error::Profile("semantic effect candidate absent"))?
                            .prepare(
                                self,
                                store,
                                entry.skeleton.author_id,
                                entry.entry_hash(),
                                payload,
                                historical,
                            )?,
                    );
                }
            }
        }
        if let Some(projection) = &mut pending.projection {
            projection.seal_preparation(self)?;
        }
        Ok(pending)
    }

    pub(crate) fn prepare_received_refill(
        &mut self,
        store: &Store,
        entry: &Entry,
        body: &governance::TypedSparseBody,
        now: crate::time::Ms,
        historical: bool,
        key_body: Option<crate::node::history_stream::KeyBodyNeed>,
    ) -> Result<PendingReceived> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if entry.payload.is_none()
            || body.entry_hash() != entry.entry_hash()
            || body.state() != governance::SparsePayloadState::Held
        {
            return Err(Error::MalformedBundle("history refill body token differs"));
        }
        entry.verify_payload_binding()?;
        self.require_history_source_boundary(entry)?;
        let input = self.history_read(store)?;
        let (head, header) = input
            .history_validated_header(&entry.skeleton.author_id, entry.skeleton.seq)?
            .ok_or(Error::MalformedBundle(
                "history refill has no published source",
            ))?;
        if header.header_wire() != entry.header_wire() {
            return Err(Error::MalformedBundle("history refill header differs"));
        }
        let kind = entry
            .skeleton
            .v2
            .as_ref()
            .ok_or(Error::MalformedBundle("history refill is legacy"))?
            .kind;
        let hash = entry.entry_hash();
        let log = input
            .log_id(&hash)?
            .ok_or(Error::MalformedAtRest("history refill locator missing"))?;
        let settled = input.history_effect_finished(&hash)?;
        drop(input);
        let mut work = Work::Refill {
            head,
            log,
            settled,
            key_body,
        };
        if settled || key_body.is_some() {
            match self.checked_governance(store, now.get()) {
                Ok(view) => drop(view),
                Err(error) if governance::refreshing(&error) => {
                    work = Work::Immediate(HistoryEffectProgress::GovernancePending)
                }
                Err(error) => return Err(error),
            }
        }
        let mut pending =
            self.received_context(store, HistoryEffectCursor::new(hash), work, now.get())?;
        pending.refill_recipient =
            kind == SignedEntryKind::KeyPackage && key_package_for(entry, &self.me());
        if settled
            && kind == SignedEntryKind::Content
            && matches!(pending.work, Work::Refill { .. })
        {
            pending.content = Some(
                pending
                    .projection
                    .as_mut()
                    .ok_or(Error::Profile("semantic refill candidate absent"))?
                    .prepare(
                        self,
                        store,
                        entry.skeleton.author_id,
                        hash,
                        entry
                            .payload
                            .as_deref()
                            .ok_or(Error::MalformedBundle("refill body vanished"))?,
                        historical,
                    )?,
            );
        }
        if let Some(projection) = &mut pending.projection {
            projection.seal_preparation(self)?;
        }
        Ok(pending)
    }

    fn received_context(
        &self,
        store: &Store,
        cursor: HistoryEffectCursor,
        work: Work,
        now: u64,
    ) -> Result<PendingReceived> {
        let author = match &work {
            Work::Effect { entry, .. } => Some(entry.skeleton.author_id),
            _ => None,
        };
        let semantic = matches!(&work, Work::Effect { .. } | Work::Refill { .. });
        let governance = matches!(&work, Work::Effect { entry, .. } if entry.skeleton.v2.as_ref()
            .is_some_and(|v2| matches!(v2.kind, SignedEntryKind::Governance | SignedEntryKind::StepPolicy)));
        let late = governance
            && self
                .history_read(store)?
                .child_after(&cursor.hash, None)?
                .is_some();
        let projection = if semantic {
            Some(SemanticProjection::new(self, store, now)?)
        } else {
            None
        };
        Ok(PendingReceived {
            room: self.channel_id,
            epoch: self.epoch,
            me: self.me(),
            creator: self.genesis.creator_pubkey().fingerprint(),
            authors: if governance {
                self.authors.clone()
            } else {
                BTreeMap::new()
            },
            sek: self.sek.reader(),
            index: self.entries.fork_reader(),
            cursor,
            work,
            projection,
            content: None,
            presence: author.and_then(|author| self.presence.get(&author).copied()),
            late,
            private: if semantic {
                self.snapshot_private_generations()
            } else {
                Vec::new()
            },
            refill_recipient: false,
            maintenance_now: crate::time::Ms(self.now_hint),
        })
    }

    pub(crate) fn finish_received(
        &mut self,
        store: &Store,
        completed: CompletedReceived,
    ) -> Result<(HistoryEffectCursor, HistoryEffectProgress)> {
        let CompletedReceived {
            pending,
            mut result,
            committed,
            effect,
            presence,
            consent,
            governance_changed,
            contiguous,
            private,
            available,
            poisoned,
        } = completed;
        let PendingReceived {
            room,
            epoch,
            cursor,
            work,
            projection,
            refill_recipient,
            ..
        } = pending;
        if self.channel_id != room || self.epoch != epoch {
            return result.map(|progress| (cursor, progress));
        }
        let was_member = effect.is_some_and(|(author, ..)| self.is_member(&author));
        #[cfg(feature = "test-knobs")]
        let content_outcome = match &work {
            Work::Effect { entry, .. }
                if entry.payload.is_some()
                    && entry.skeleton.author_id != self.me()
                    && entry
                        .skeleton
                        .v2
                        .as_ref()
                        .is_some_and(|v2| v2.kind == SignedEntryKind::Content) =>
            {
                Some(entry.entry_hash())
            }
            _ => None,
        };
        #[cfg(feature = "test-knobs")]
        let refill_outcome = matches!(&work, Work::Refill { settled: true, .. })
            && effect.is_some_and(|(_, _, _, kind, _)| kind == SignedEntryKind::Content);
        if committed {
            self.entries.committed();
            let projection_result =
                projection.map_or(Ok(()), |projection| projection.install(self, store));
            let install = (|| {
                if governance_changed {
                    self.retire_governance()?;
                }
                if let Some((author, state)) = presence {
                    self.presence.insert(author, state);
                }
                if consent {
                    if let Work::Effect { entry, .. } = &work {
                        self.note_committed_consent(entry)?;
                    }
                }
                if let Some((author, seq, log, kind, body)) = effect {
                    if matches!(&work, Work::Effect { .. }) {
                        self.sparse_applied_tips
                            .entry(author)
                            .and_modify(|held| *held = (*held).max(seq))
                            .or_insert(seq);
                        if !was_member && self.is_member(&author) {
                            self.key_member_became_current(author);
                        }
                        self.key_packages.published(self.next_log_id);
                    }
                    if kind == SignedEntryKind::KeyPackage && body {
                        self.note_key_body_acquired();
                        let recipient = match &work {
                            Work::Effect { entry, .. } => key_package_for(entry, &self.me()),
                            _ => refill_recipient,
                        };
                        if recipient {
                            self.key_packages.published(self.next_log_id);
                            self.key_packages.note(author, log)?;
                        }
                    }
                    self.note_role_progress(author, 0);
                }
                self.install_private_generations(&private);
                if matches!(&work, Work::Effect { .. } | Work::Refill { .. }) {
                    self.gen.fetch_add(1, Ordering::Relaxed);
                }
                if let Some(author) = available {
                    self.note_available(store, author)?;
                }
                if let Some((author, progress)) = contiguous {
                    self.note_contiguous_advance(author, progress)?;
                }
                Ok(())
            })();
            if let Err(error) = projection_result.and(install) {
                result = Err(error);
            }
        } else if let Some((author, progress)) = contiguous {
            if let Err(error) = self.note_contiguous_advance(author, progress) {
                self.poison(&error);
                result = Err(error);
            }
        }
        let authority_changed = matches!(&result, Err(Error::StreamRefused(reason))
            if *reason == crate::node::history_stream::AUTHORIZATION_CHANGED);
        if !authority_changed && (poisoned || result.is_err() && committed) {
            if let Err(error) = &result {
                self.poison(error);
            }
        }
        #[cfg(feature = "test-knobs")]
        if let Some(hash) = content_outcome {
            if committed || poisoned {
                self.record_fx29_content_outcome(&hash, result.is_ok())?;
            }
        }
        #[cfg(feature = "test-knobs")]
        if refill_outcome
            && result.as_ref().is_ok_and(|progress| {
                matches!(
                    progress,
                    HistoryEffectProgress::Complete { .. }
                        | HistoryEffectProgress::AdmittedProgress { .. }
                )
            })
        {
            self.record_fx29_refill_outcome(&cursor.hash)?;
        }
        result.map(|progress| (cursor, progress))
    }
}

impl PendingReceived {
    pub(crate) fn save(
        mut self,
        store: &Store,
        committed_ledger: &AtomicBool,
        received: &ReceivedFlow,
        refill: Option<&Entry>,
        check_binding: impl FnOnce(&Batch<'_>) -> Result<()>,
        on_admitted: impl FnOnce(&mut Batch<'_>, Digest32) -> Result<()>,
    ) -> CompletedReceived {
        let mut committed = false;
        let mut effect = None;
        let mut presence = None;
        let mut consent = false;
        let mut governance_changed = false;
        let mut contiguous = None;
        let mut private = Vec::new();
        let mut available = None;
        let mut poisoned = false;
        let weak = self.sek.clone();
        let result = received.scope(|| {
            weak.with(|sek| {
                if let Work::Immediate(_) = &self.work {
                    let Work::Immediate(progress) = std::mem::replace(
                        &mut self.work,
                        Work::Immediate(HistoryEffectProgress::Progress),
                    ) else {
                        unreachable!()
                    };
                    return Ok(progress);
                }
                if let Work::Finished {
                    author,
                    refill_pending,
                    body_expected,
                } = &self.work
                {
                    let author = *author;
                    let refill_pending = *refill_pending;
                    let body_expected = *body_expected;
                    let mut batch = store.batch()?;
                    check_binding(&batch)?;
                    if !refill_pending {
                        on_admitted(&mut batch, self.cursor.hash)?;
                    }
                    if refill_pending {
                        batch.derived();
                    }
                    let mut index = self.index.write(&mut batch, sek, &self.room)?;
                    let progress = index.advance_sparse_contiguous(&author, &self.me)?;
                    let more = progress.more;
                    if !refill_pending || progress.state.is_some() || more {
                        index.seal()?;
                        batch.commit()?;
                        self.index.committed();
                        committed = true;
                        committed_ledger.store(true, Ordering::Release);
                    }
                    contiguous = Some((author, progress));
                    return Ok(if refill_pending {
                        HistoryEffectProgress::RefillPending { governance: false }
                    } else if more {
                        if body_expected {
                            HistoryEffectProgress::AdmittedProgress {
                                rendered: self.cursor.rendered,
                            }
                        } else {
                            HistoryEffectProgress::Progress
                        }
                    } else {
                        HistoryEffectProgress::Complete {
                            rendered: self.cursor.rendered,
                        }
                    });
                }
                let (entry, log, is_refill, settled, body_expected, key_body, head) =
                    match &self.work {
                        Work::Effect {
                            entry,
                            log,
                            body_expected,
                        } => (entry, *log, false, true, *body_expected, None, None),
                        Work::Refill {
                            head,
                            log,
                            settled,
                            key_body,
                        } => (
                            refill.ok_or(Error::MalformedBundle("refill body vanished"))?,
                            *log,
                            true,
                            *settled,
                            true,
                            *key_body,
                            Some(*head),
                        ),
                        _ => unreachable!(),
                    };
                let projection = self
                    .projection
                    .as_mut()
                    .ok_or(Error::Profile("semantic transaction candidate absent"))?;
                let hash = entry.entry_hash();
                let author = entry.skeleton.author_id;
                let kind = entry
                    .skeleton
                    .v2
                    .as_ref()
                    .ok_or(Error::MalformedBundle("history effect is legacy"))?
                    .kind;
                #[cfg(feature = "test-knobs")]
                let publish_before_effect = kind != SignedEntryKind::Content
                    && std::env::var("VOX_TEST_FX29_MUTANT").as_deref()
                        != Ok("finish-control-after-effect");
                #[cfg(not(feature = "test-knobs"))]
                let publish_before_effect = kind != SignedEntryKind::Content;
                let mut batch = store.received_batch(received)?;
                if settled {
                    batch.note_received_author(author)?;
                }
                check_binding(&batch)?;
                if let Some(need) = key_body {
                    if kind != SignedEntryKind::KeyPackage
                        || Some(need.head) != head
                        || need.seq != entry.skeleton.seq
                        || need.target.author != author
                        || need.hash != hash
                    {
                        return Err(Error::MalformedBundle("key body refill owner differs"));
                    }
                    let index = self.index.write(&mut batch, sek, &self.room)?;
                    if !index.history_key_body_pending(need)? {
                        return Ok(HistoryEffectProgress::KeyBodyRetired);
                    }
                }
                if is_refill && kind == SignedEntryKind::KeyPackage {
                    projection.track_known_with(&mut batch, sek, entry, log)?;
                    if key_body.is_some()
                        && projection.expired(&batch, sek, entry, entry.skeleton.claimed_ms)?
                    {
                        return Ok(HistoryEffectProgress::KeyBodyRetired);
                    }
                }
                poisoned = true;
                if let Some(head) = head {
                    if matches!(
                        kind,
                        SignedEntryKind::Governance
                            | SignedEntryKind::StepPolicy
                            | SignedEntryKind::KeyPackage
                    ) {
                        batch.ruled();
                    }
                    let mut index = self.index.write(&mut batch, sek, &self.room)?;
                    let newly_available = index.refill_available(entry, log)?;
                    index.put_committed(entry, log)?;
                    if kind == SignedEntryKind::KeyPackage {
                        index.finish_history_obligation(&entry_store::sparse::Obligation {
                            head,
                            kind: entry_store::sparse::ObligationKind::KeyBody,
                            object: hash,
                            author,
                            from: entry.skeleton.seq,
                            through: entry.skeleton.seq,
                        })?;
                    }
                    index.seal()?;
                    if newly_available {
                        available = Some(author);
                    }
                } else {
                    if publish_before_effect {
                        let mut index = self.index.write(&mut batch, sek, &self.room)?;
                        let catalog = index.finish_history_effect(
                            entry,
                            &FinishedHistoryEffect { hash },
                            self.me,
                        )?;
                        index.seal()?;
                        if catalog {
                            batch.ruled();
                        }
                    }
                    session_projection::private_index::observe_public(
                        &mut batch, sek, &self.room, entry, self.epoch,
                    )?;
                    if matches!(
                        kind,
                        SignedEntryKind::Governance | SignedEntryKind::StepPolicy
                    ) {
                        if !matches!(
                            GovEntry::body_bound_to(entry),
                            Ok(GovBody::ConsentGrant(_) | GovBody::ConsentRevocation(_))
                        ) {
                            batch.ruled();
                        }
                        let accepted = governance::accepted_into(
                            &mut batch,
                            &self.index,
                            sek,
                            &self.room,
                            &self.authors,
                            &self.creator,
                            &self.me,
                            log,
                            entry,
                            self.late,
                        )?;
                        consent = accepted.current_advanced;
                        governance_changed = accepted.work_changed;
                        if let Ok(GovBody::Presence(body)) = GovEntry::body_bound_to(entry) {
                            let old = self.presence;
                            let mut state = old.unwrap_or(governance::Presence {
                                last: (entry.skeleton.seq, body.body.here),
                                back: None,
                            });
                            if entry.skeleton.seq >= state.last.0 {
                                state.last = (entry.skeleton.seq, body.body.here);
                            }
                            if body.body.here
                                && state.back.is_none_or(|(seq, _)| seq < entry.skeleton.seq)
                            {
                                state.back = Some((entry.skeleton.seq, entry.skeleton.claimed_ms));
                            }
                            if old
                                .is_none_or(|old| old.last != state.last || old.back != state.back)
                            {
                                let mut index = self.index.write(&mut batch, sek, &self.room)?;
                                index.note_presence(author, state)?;
                                index.seal()?;
                                presence = Some((author, state));
                            }
                        }
                    }
                    if kind == SignedEntryKind::KeyPackage && key_package_for(entry, &self.me) {
                        batch.ruled();
                    }
                    if kind == SignedEntryKind::KeyPackage && entry.payload.is_some() {
                        projection.track_known_with(&mut batch, sek, entry, log)?;
                    }
                }
                let refill_pending = !is_refill
                    && body_expected
                    && kind == SignedEntryKind::Content
                    && entry.payload.is_none();
                let mut deferred = false;
                let mut unavailable = false;
                if let Some(content) = self.content.take() {
                    #[cfg(feature = "test-knobs")]
                    {
                        let mutant = std::env::var("VOX_TEST_FX29_MUTANT");
                        if !is_refill
                            && mutant.as_deref() == Ok("track-content-through-settled-index")
                            && std::env::var_os("VOX_TEST_FX29_CONTENT_OUTCOME_FILE").is_some()
                            && author != self.me
                        {
                            let tracked = self
                                .index
                                .in_batch(&batch, sek, &self.room)?
                                .get_sparse_published(&hash)?
                                .ok_or(Error::MalformedAtRest("tracked entry missing"))?;
                            projection.track_current_with(&mut batch, sek, &tracked, log)?;
                        } else if is_refill
                            && mutant.as_deref() == Ok("refill-content-with-current-time")
                            && std::env::var("VOX_TEST_FX29_CONTENT_REFILL_HASH").as_deref()
                                == Ok(crate::node::link::b32_encode(&hash).as_str())
                        {
                            projection.track_current_with(&mut batch, sek, entry, log)?;
                        } else {
                            projection.track_known_with(&mut batch, sek, entry, log)?;
                        }
                    }
                    #[cfg(not(feature = "test-knobs"))]
                    projection.track_known_with(&mut batch, sek, entry, log)?;
                    match projection.apply_with(&mut batch, sek, content, entry)? {
                        ProjectionOutcome::Deferred => deferred = true,
                        ProjectionOutcome::Unavailable => unavailable = true,
                        _ => {}
                    }
                }
                if !is_refill || settled && kind == SignedEntryKind::Content {
                    projection.queue_receivers_with(&mut batch, sek)?;
                    for (hash, author, generation) in &self.private {
                        if self
                            .index
                            .in_batch(&batch, sek, &self.room)?
                            .log_id(hash)?
                            .is_some()
                        {
                            batch.ruled();
                            session_projection::private_index::observe_control(
                                &mut batch,
                                sek,
                                &self.room,
                                author,
                                session_projection::private_index::Control {
                                    generation: Some(*generation),
                                    ..Default::default()
                                },
                            )?;
                            if !is_refill {
                                private.push(*hash);
                            }
                        }
                    }
                }
                let staged_deferred = body_expected && deferred;
                let admitted = settled && !(refill_pending || staged_deferred || unavailable);
                if admitted {
                    if !is_refill && (kind == SignedEntryKind::Content || !publish_before_effect) {
                        let mut index = self.index.write(&mut batch, sek, &self.room)?;
                        let catalog = index.finish_history_effect(
                            entry,
                            &FinishedHistoryEffect { hash },
                            self.me,
                        )?;
                        index.seal()?;
                        if catalog {
                            batch.ruled();
                        }
                    }
                    on_admitted(&mut batch, hash)?;
                }
                let progress = if !is_refill || admitted {
                    let mut index = self.index.write(&mut batch, sek, &self.room)?;
                    let progress = index.advance_sparse_contiguous(&author, &self.me)?;
                    index.seal()?;
                    Some(progress)
                } else {
                    None
                };
                batch.commit()?;
                self.index.committed();
                committed = true;
                committed_ledger.store(true, Ordering::Release);
                projection.committed = true;
                if !is_refill || settled {
                    effect = Some((
                        author,
                        entry.skeleton.seq,
                        log,
                        kind,
                        entry.payload.is_some(),
                    ));
                }
                let more = progress.as_ref().is_some_and(|progress| progress.more);
                contiguous = progress.map(|progress| (author, progress));
                projection.after_commit_with(store, sek)?;
                if available.is_some()
                    && !self
                        .index
                        .read(store, sek, &self.room)?
                        .payload_present(&hash)?
                {
                    available = None;
                }
                self.cursor.rendered |= !projection.rows.is_empty();
                Ok(if unavailable {
                    HistoryEffectProgress::BodyUnavailable
                } else if refill_pending || staged_deferred {
                    HistoryEffectProgress::RefillPending {
                        governance: staged_deferred,
                    }
                } else if more {
                    if body_expected {
                        HistoryEffectProgress::AdmittedProgress {
                            rendered: self.cursor.rendered,
                        }
                    } else {
                        HistoryEffectProgress::Progress
                    }
                } else if settled {
                    HistoryEffectProgress::Complete {
                        rendered: self.cursor.rendered,
                    }
                } else {
                    HistoryEffectProgress::Progress
                })
            })
        });
        CompletedReceived {
            pending: self,
            result,
            committed,
            effect,
            presence,
            consent,
            governance_changed,
            contiguous,
            private,
            available,
            poisoned,
        }
    }
}
