//! Bounded maintenance candidates keep the published room unchanged during native saves.
use super::*;
use crate::atrest::sek::WeakSek;
use crate::log::entry::EntryWrite;
use crate::node::channel::entry_store::sparse::Obligation;

/// Existing retention turn order. The actor retains this cursor across owned completions;
/// backfill precedes Prune and the authored checkpoint follows HistoricalKeys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    OwedCleanup,
    KeyDebt,
    Projection,
    Prune,
    PrivateExpiry,
    HistoricalKeys,
    Signatures,
}

struct Pruned {
    entry: Entry,
    tracked: Tracked,
    shed_signature: bool,
    legacy_kind: Option<bool>,
}

enum Work {
    Cleanup {
        remove: Vec<(Digest32, u64, Option<Digest32>)>,
        next: Option<(Digest32, u64)>,
    },
    KeyDebt {
        debts: Vec<Obligation>,
        more: bool,
    },
    Projection {
        state: history::State,
        before: Vec<u8>,
        owed: Vec<(Digest32, Option<(u64, u64)>)>,
        idle: bool,
    },
    Prune {
        due: Vec<Pruned>,
        legacy: legacy_session::LegacyProjectionContext,
    },
    PrivateExpiry,
    HistoricalKeys {
        state: own_historical_keys::Retirement,
        retire: Option<([u8; 64], u64)>,
    },
    Signatures {
        entries: Vec<Entry>,
        swept: Vec<(Digest32, u64)>,
    },
}

pub(crate) struct PendingCheckpoint {
    append: pending_text::PendingText,
    sek: WeakSek,
    room: Digest32,
    me: Digest32,
    already: u64,
    head: u64,
    last_pruned_at: u64,
    idle_seconds: u64,
    now: crate::time::Ms,
}

pub(crate) struct PendingRetention {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    sek: WeakSek,
    index: entry_store::EntryIndex,
    next_log_id: u64,
    now: u64,
    retention: (u64, u64),
    work: Work,
    pin: Option<history::PendingHistoryRead>,
}

#[derive(Default)]
pub(crate) struct Installed {
    pub(crate) pruned: usize,
    pub(crate) pruned_hashes: Vec<Digest32>,
    pub(crate) changed: bool,
    pub(crate) more_key_debt: bool,
    pub(crate) projection_ready: bool,
}

pub(crate) struct CompletedRetention {
    pending: PendingRetention,
    pub(crate) result: Result<Installed>,
    committed: bool,
    body_changes: u64,
    display_changed: bool,
}

impl CompletedRetention {
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.pending.pin.take()
    }

    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.pending.owner, owner)
            && channel.channel_id == self.pending.room
            && channel.epoch == self.pending.epoch
            && channel
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }
}

type HistoricalRetirement = (own_historical_keys::Retirement, Option<([u8; 64], u64)>);

impl ChannelState {
    /// Policy setters cleaned settled debt at the room's prior observation time. The
    /// ordinary sweep advances that time separately; neither cleanup invents a clock.
    pub(crate) fn retention_cleanup_hint(&self) -> crate::time::Ms {
        crate::time::Ms(self.now_hint)
    }

    /// Read-only preparation, apart from the shared publication reservation. Policy cleanup
    /// can remove settled debt before governance is ready; expiry still needs current policy.
    pub(crate) fn prepare_pending_retention(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        step: Step,
        now: crate::time::Ms,
    ) -> Result<Option<PendingRetention>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if self.post_pending() || self.legacy_cache_only(store)? {
            return Ok(None);
        }
        if step != Step::OwedCleanup {
            match self.require_governance_ready(store, now) {
                Ok(_) if self.governance_display_current(now.get()) => {}
                Ok(_) => return Ok(None),
                Err(error) if governance::refreshing(&error) => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        let now_ms = self.now_hint.max(now.get());
        let retention = (self.effective_retention(), self.effective_step_retention());
        let read = self.entries.read(store, &self.sek, &self.channel_id)?;
        if read.publication_busy() {
            return Ok(None);
        }
        let work = match step {
            Step::OwedCleanup => {
                let (positions, next) =
                    read.missing_page(self.projection_state.cleanup_cursor, 64)?;
                let mut remove = Vec::new();
                for (author, seq) in positions {
                    let entry = read.get(&author, seq)?;
                    let keep = match entry.as_ref() {
                        Some(entry) => {
                            entry.payload.is_none()
                                && self.private_id(store, &entry.entry_hash())?.is_none()
                                && !(self.governance_display_current(now_ms)
                                    && expired_at(
                                        entry.skeleton.claimed_ms,
                                        now_ms,
                                        self.entry_retention(read.transaction(), entry)?,
                                    ))
                        }
                        None => false,
                    };
                    if !keep {
                        remove.push((author, seq, entry.map(|entry| entry.entry_hash())));
                    }
                }
                Work::Cleanup { remove, next }
            }
            Step::KeyDebt => {
                let debts = if retention.0 == 0 {
                    Vec::new()
                } else {
                    read.expired_key_debts(
                        now_ms.saturating_sub(retention.0.saturating_mul(1_000)),
                        16,
                    )?
                };
                for debt in &debts {
                    let Some((head, entry)) =
                        read.history_validated_header(&debt.author, debt.from)?
                    else {
                        return Err(Error::MalformedAtRest("expired key debt source missing"));
                    };
                    let log = read
                        .log_id(&debt.object)?
                        .ok_or(Error::MalformedAtRest("expired key debt log missing"))?;
                    let first_seen = history_first_seen_at(
                        &store.snapshot()?,
                        &self.sek,
                        &self.channel_id,
                        log,
                    )?;
                    if debt.from != debt.through
                        || head != debt.head
                        || entry.entry_hash() != debt.object
                        || !entry.skeleton.v2.as_ref().is_some_and(|v| {
                            v.kind == crate::log::history::SignedEntryKind::KeyPackage
                        })
                        || !expired_at(
                            entry.skeleton.claimed_ms.min(first_seen),
                            now_ms,
                            retention.0,
                        )
                    {
                        return Err(Error::MalformedAtRest("expired key debt binding"));
                    }
                }
                let more = debts.len() == 16;
                Work::KeyDebt { debts, more }
            }
            Step::Projection => {
                let mut state = self.projection_state.clone();
                let before = state.to_bytes();
                let policy = [
                    retention.0,
                    retention.1,
                    self.legacy_sessions.display_revision(),
                ];
                let idle = if state.policy == Some(policy) && !state.pending {
                    if let Ok(rendered) =
                        self.entries.render_view(store, &self.sek, &self.channel_id)
                    {
                        rendered.next_owed_expiry()?.is_none_or(|at| at > now_ms)
                    } else {
                        false
                    }
                } else {
                    false
                };
                if state.policy != Some(policy) {
                    state.policy = Some(policy);
                    state.pending = true;
                    state.cursor = None;
                    state.through = None;
                }
                let mut owed = Vec::new();
                if state.pending {
                    let (positions, next) = read.missing_page(state.cursor, 64)?;
                    let mut through = false;
                    for (author, seq) in positions {
                        if state.through.is_some_and(|end| (author, seq) > end) {
                            through = true;
                            break;
                        }
                        state.cursor = Some((author, seq));
                        let entry = read
                            .get(&author, seq)?
                            .ok_or(Error::MalformedAtRest("owed entry missing"))?;
                        let hash = entry.entry_hash();
                        let visibility = if entry.payload.is_some()
                            || self.private_id(store, &hash)?.is_some()
                            || self.legacy_is_session_in(read.transaction(), &hash)?
                        {
                            None
                        } else {
                            let created = entry.skeleton.claimed_ms;
                            let ttl = self.entry_retention(read.transaction(), &entry)?;
                            (!expired_at(created, now_ms, ttl)).then_some((
                                created,
                                if ttl == 0 {
                                    u64::MAX
                                } else {
                                    created.saturating_add(ttl.saturating_mul(1_000))
                                },
                            ))
                        };
                        owed.push((hash, visibility));
                    }
                    state.pending = !through
                        && next.is_some()
                        && state.through.is_none_or(|end| state.cursor < Some(end));
                }
                Work::Projection {
                    state,
                    before,
                    owed,
                    idle,
                }
            }
            Step::Prune => {
                let (selected, _) = read.retention_due(now_ms, retention.0, retention.1, 64)?;
                let mut due = Vec::new();
                let mut bytes = 0usize;
                for (hash, tracked) in selected {
                    let entry = self
                        .dag
                        .get_by_hash(&read, &hash)?
                        .ok_or(Error::MalformedAtRest("pruned entry missing"))?;
                    let size = entry.payload.as_ref().map_or(0, Vec::len);
                    if !due.is_empty() && bytes.saturating_add(size) > 1024 * 1024 {
                        break;
                    }
                    bytes = bytes.saturating_add(size);
                    if entry.payload.as_deref().is_some_and(retained_control) {
                        return Err(Error::MalformedAtRest(
                            "retained control indexed for expiry",
                        ));
                    }
                    let shed_signature = retention.0 != 0
                        && self
                            .dag
                            .checkpoint(&entry.skeleton.author_id)
                            .is_some_and(|(below, _)| entry.skeleton.seq <= below);
                    let legacy_kind = self.available_legacy_kind(&entry);
                    due.push(Pruned {
                        entry,
                        tracked,
                        shed_signature,
                        legacy_kind,
                    });
                }
                Work::Prune {
                    due,
                    legacy: self.legacy_projection_context(store)?,
                }
            }
            Step::PrivateExpiry => {
                if !self.private_policy_ready(store, now_ms)? {
                    return Ok(None);
                }
                Work::PrivateExpiry
            }
            Step::HistoricalKeys => {
                let (state, retire) = self.prepare_historical_retirement(store, now_ms)?;
                Work::HistoricalKeys { state, retire }
            }
            Step::Signatures => {
                if retention == (0, 0) {
                    return Ok(None);
                }
                let (entries, swept) = self
                    .dag
                    .retention_signature_page(&read, SIGNATURE_SWEEP_PAGE)?;
                Work::Signatures { entries, swept }
            }
        };
        drop(read);
        let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(Some(PendingRetention {
            owner,
            room: self.channel_id,
            epoch: self.epoch,
            sek: self.sek.reader(),
            index: entry_store::EntryIndex::default(),
            next_log_id: self.next_log_id,
            now: now_ms,
            retention,
            work,
            pin: Some(pin),
        }))
    }

    fn prepare_historical_retirement(
        &self,
        store: &Store,
        now: u64,
    ) -> Result<HistoricalRetirement> {
        let me = self.me();
        let head = self.dag.verified_head(&me);
        let retention = (self.effective_retention(), self.effective_step_retention());
        let generation = self.entries.commit_generation();
        let mut scan = self.historical_retirement.clone();
        if self.own_behind {
            scan.reset();
            return Ok((scan, None));
        }
        if scan.head != head
            || scan.epoch != self.epoch
            || scan.retention != retention
            || scan.entry_generation != generation
            || scan.wake_at.is_some_and(|at| now >= at)
        {
            scan.reset();
            scan.head = head;
            scan.epoch = self.epoch;
            scan.retention = retention;
            scan.entry_generation = generation;
        }
        if scan.complete || head == 0 {
            return Ok((scan, None));
        }
        let (key, id, mut next) = match scan.current {
            Some(current) => current,
            None => {
                let Some((key, id)) = own_historical_keys::first_after(
                    &store.snapshot()?,
                    &self.sek,
                    &self.channel_id,
                    scan.after,
                )?
                else {
                    scan.complete = true;
                    return Ok((scan, None));
                };
                (key, id, 1)
            }
        };
        let entries = self.entries.read(store, &self.sek, &self.channel_id)?;
        let Some(feed) = self.dag.feed(&me) else {
            return Ok((scan, None));
        };
        if feed
            .get(&entries, head)?
            .is_none_or(|entry| entry.skeleton.epoch != self.epoch)
        {
            scan.complete = true;
            return Ok((scan, None));
        }
        let epoch = u64::from_be_bytes(
            key[..8]
                .try_into()
                .map_err(|_| Error::MalformedAtRest("own historical epoch key width"))?,
        );
        let chain = u64::from_be_bytes(
            key[8..16]
                .try_into()
                .map_err(|_| Error::MalformedAtRest("own historical chain key width"))?,
        );
        if epoch >= self.epoch {
            scan.after = Some(key);
            scan.current = None;
            return Ok((scan, None));
        }
        for _ in 0..64 {
            if next > head {
                scan.after = Some(key);
                scan.current = None;
                return Ok((scan, Some((key, id))));
            }
            let Some((_source, header)) = entries.history_validated_header(&me, next)? else {
                scan.after = Some(key);
                scan.current = None;
                return Ok((scan, None));
            };
            next += 1;
            if header.skeleton.epoch != epoch
                || !header
                    .skeleton
                    .v2
                    .as_ref()
                    .is_some_and(|v2| v2.kind == crate::log::history::SignedEntryKind::Content)
            {
                continue;
            }
            let hash = header.entry_hash();
            let entry = entries.history_entry(&hash)?;
            let Some(payload) = entry.as_ref().and_then(|entry| entry.payload.as_deref()) else {
                if entries.history_effect_finished(&hash)? {
                    if let Some(log) = entries.log_id(&hash)? {
                        let first_seen = history_first_seen_at(
                            &store.snapshot()?,
                            &self.sek,
                            &self.channel_id,
                            log,
                        )?;
                        let base = header.skeleton.claimed_ms.min(first_seen);
                        if expired_at(base, now, retention.0) && expired_at(base, now, retention.1)
                        {
                            continue;
                        }
                        if retention.0 != 0 && retention.1 != 0 {
                            let due = base
                                .saturating_add(retention.0.max(retention.1).saturating_mul(1_000));
                            if due > now {
                                scan.wait_until(due);
                            }
                        }
                    }
                }
                scan.after = Some(key);
                scan.current = None;
                return Ok((scan, None));
            };
            let message = GroupMessage::from_wire(payload)?;
            if message.header.author_id != me || message.header.epoch != epoch {
                return Err(Error::MalformedAtRest(
                    "own historical receiver entry binding",
                ));
            }
            if message.header.channel_id == self.channel_id && message.header.chain_id == chain {
                scan.after = Some(key);
                scan.current = None;
                return Ok((scan, None));
            }
        }
        scan.current = Some((key, id, next));
        Ok((scan, None))
    }

    /// Reserve the existing authored capsule without scanning the expired backlog under the
    /// room lock. Selection and the ordinary durable control append run on its native worker.
    pub(crate) fn prepare_pending_checkpoint(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        me: Digest32,
        now: crate::time::Ms,
    ) -> Result<Option<PendingCheckpoint>> {
        if self.poisoned
            || !self.governance_display_current(now.get())
            || (self.room_retention() == 0 && self.room_step_retention() == 0)
        {
            return Ok(None);
        }
        let head = self.dag.feed(&me).map_or(0, |feed| feed.max_seq());
        let already = self.dag.checkpoint(&me).map_or(0, |(seq, _)| seq);
        if head <= already {
            return Ok(None);
        }
        let append = self.prepare_pending_control(store, owner, now)?;
        Ok(Some(PendingCheckpoint {
            append,
            sek: self.sek.reader(),
            room: self.channel_id,
            me,
            already,
            head,
            last_pruned_at: self.last_pruned_at,
            idle_seconds: self.checkpoint_idle,
            now,
        }))
    }

    pub(crate) fn finish_pending_retention(
        &mut self,
        store: &Store,
        completed: CompletedRetention,
    ) -> Result<Installed> {
        let CompletedRetention {
            pending,
            mut result,
            committed,
            body_changes,
            display_changed,
            ..
        } = completed;
        if self.channel_id != pending.room
            || self.epoch != pending.epoch
            || !self
                .pending_text
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &pending.owner))
        {
            return result;
        }
        // Even a later failure must acknowledge already committed native transactions. The
        // pin is held by the common completion until all these component facts are installed.
        if committed {
            if !matches!(
                &pending.work,
                Work::PrivateExpiry | Work::HistoricalKeys { .. }
            ) {
                self.entries.committed();
            }
            self.dag.install_retention_delta(
                body_changes,
                match &pending.work {
                    Work::Signatures { swept, .. } => swept.as_slice(),
                    _ => &[],
                },
            );
        }
        if let Work::Prune { legacy, .. } = &pending.work {
            // The context retains its last real commit independently of a later failed
            // candidate. Its pre-prune pass can commit even if pruning itself then fails.
            self.install_legacy_projection_context(legacy);
        }
        if result.is_ok() {
            self.now_hint = self.now_hint.max(pending.now);
            match pending.work {
                Work::Cleanup { next, .. } => self.projection_state.cleanup_cursor = next,
                Work::Projection { state, .. } => self.projection_state = state,
                Work::KeyDebt { more, .. } => {
                    self.key_debt_retention_pending = more;
                }
                Work::HistoricalKeys { state, .. } => self.historical_retirement = state,
                _ => {}
            }
            if result.as_ref().is_ok_and(|installed| installed.pruned != 0) {
                self.last_pruned_at = pending.now;
            }
        }
        if display_changed {
            self.invalidate_display();
            match self
                .entries
                .render_view(store, &self.sek, &self.channel_id)
                .and_then(|view| view.step(None, true, None, true))
            {
                Ok(row) => self.display_tail = row.map(|(key, _)| key),
                Err(error) => result = Err(error),
            }
        }
        if let Err(error) = &result {
            self.poison(error);
        }
        self.pending_text = None;
        self.history_publication_changed.notify_waiters();
        result
    }
}

impl PendingRetention {
    /// Only the native owned worker calls this. No actor, room or Computer state lock is held.
    pub(crate) fn save(mut self, store: &Store) -> CompletedRetention {
        let mut committed = false;
        let mut body_changes = 0;
        let mut display_changed = false;
        let result = self.sek.with(|sek| -> Result<Installed> {
            let mut installed = Installed::default();
            match &mut self.work {
                Work::Cleanup { remove, .. } => {
                    if !remove.is_empty() {
                        let mut batch = store.batch()?;
                        batch.derived();
                        let mut index = self.index.write(&mut batch, sek, &self.room)?;
                        let mut changed = false;
                        for (author, seq, hash) in remove {
                            if let Some(hash) = hash {
                                index.set_owed(*hash, None)?;
                            }
                            changed |= index.set_missing(author, *seq, false)?;
                        }
                        index.seal()?;
                        batch.commit()?;
                        committed = true;
                        display_changed |= changed;
                    }
                }
                Work::KeyDebt { debts, more } => {
                    if !debts.is_empty() {
                        let mut batch = store.batch()?;
                        batch.derived();
                        let mut index = self.index.write(&mut batch, sek, &self.room)?;
                        for debt in debts {
                            index.finish_history_obligation(debt)?;
                        }
                        index.seal()?;
                        batch.commit()?;
                        committed = true;
                    }
                    installed.more_key_debt = *more;
                }
                Work::Projection {
                    state,
                    before,
                    owed,
                    idle,
                } => {
                    if *idle {
                        installed.projection_ready = true;
                        return Ok(installed);
                    }
                    let mut batch = store.batch()?;
                    batch.derived();
                    let mut index = self.index.write(&mut batch, sek, &self.room)?;
                    let mut changed = false;
                    for (hash, visibility) in owed {
                        index.set_owed(*hash, *visibility)?;
                        changed = true;
                    }
                    for _ in 0..64 {
                        let Some(hash) = index.first_expired_owed(self.now)? else {
                            break;
                        };
                        index.set_owed(hash, None)?;
                        changed = true;
                    }
                    installed.projection_ready =
                        !state.pending && index.first_expired_owed(self.now)?.is_none();
                    let progress = state.to_bytes();
                    if changed || *before != progress {
                        index.note_projection(progress)?;
                        index.seal()?;
                        batch.commit()?;
                        committed = true;
                        display_changed |= changed;
                    }
                }
                Work::Prune { due, legacy } => {
                    // Keep both existing bounded classification passes: the first learns
                    // declarations before expiry, the second shares the prune transaction.
                    if !due.is_empty() {
                        legacy.reconcile(store, sek, self.now)?;
                        legacy.prepare_reconcile(store, sek, self.now, None, |legacy, batch| {
                            for selected in due.iter() {
                                if selected.entry.skeleton.v2.is_none() {
                                    if let Some(kind) = selected.legacy_kind {
                                        legacy.remember(
                                            batch,
                                            sek,
                                            selected.entry.entry_hash(),
                                            selected.entry.skeleton.author_id,
                                            kind,
                                        )?;
                                    }
                                }
                            }
                            Ok(())
                        })?;
                        let mut batch = store.batch()?;
                        batch.derived();
                        semantic_projection::SelectedReceiverInput::check(&batch)?;
                        let mut dropped = 0;
                        let mut shown = false;
                        for selected in due.iter_mut() {
                            let hash = selected.entry.entry_hash();
                            session_projection::private_index::observe_public(
                                &mut batch,
                                sek,
                                &self.room,
                                &selected.entry,
                                self.epoch,
                            )?;
                            if selected.entry.skeleton.v2.is_none() {
                                if let Some(kind) = selected.legacy_kind {
                                    legacy.remember(
                                        &mut batch,
                                        sek,
                                        hash,
                                        selected.entry.skeleton.author_id,
                                        kind,
                                    )?;
                                }
                            }
                            {
                                let mut index = self.index.write(&mut batch, sek, &self.room)?;
                                index.committing(self.next_log_id);
                                shown |= index.has_rendered(&hash)?;
                                index.remove_rendered(&hash)?;
                                index.remove_read_receipt(&hash)?;
                                index.set_retention(hash, None)?;
                                if selected.entry.prune_payload() {
                                    dropped += 1;
                                }
                                if selected.shed_signature {
                                    selected.entry.drop_signature();
                                }
                                index.put(&selected.entry)?;
                                index.seal()?;
                            }
                            let tracked = selected.tracked;
                            let age = seal_segment(
                                sek,
                                SegmentKind::Index,
                                tracked.log_id,
                                &first_seen_bytes(tracked.first_seen_ms, tracked.steps),
                            )?;
                            batch.put_segment(
                                &self.room,
                                SegmentKind::Index,
                                tracked.log_id,
                                &age,
                            )?;
                            if let Some(cache) = tracked.cache_id {
                                batch.delete_segment(
                                    &self.room,
                                    SegmentKind::PlaintextCache,
                                    cache,
                                )?;
                            }
                        }
                        legacy.reconcile_in(&mut batch, sek, self.now)?;
                        legacy.require_inputs()?;
                        batch.commit()?;
                        committed = true;
                        legacy.committed();
                        body_changes += dropped;
                        display_changed |= shown;
                        installed.pruned = due.len();
                        installed
                            .pruned_hashes
                            .extend(due.iter().map(|selected| selected.entry.entry_hash()));
                    }
                }
                Work::PrivateExpiry => {
                    private_session::pending_upgrade::sweep_private(
                        store,
                        sek,
                        &self.room,
                        self.now,
                        self.retention,
                        |hash| {
                            committed = true;
                            installed.pruned += 1;
                            installed.pruned_hashes.push(hash);
                        },
                    )?;
                }
                Work::HistoricalKeys { retire, .. } => {
                    if let Some((key, id)) = retire {
                        // Key deletion remains an ordinary durable commit, never Derived.
                        let mut batch = store.batch()?;
                        own_historical_keys::retire(&mut batch, sek, &self.room, *key, *id)?;
                        batch.commit()?;
                        committed = true;
                    }
                }
                Work::Signatures { entries, swept } => {
                    if !swept.is_empty() {
                        let mut batch = store.batch()?;
                        batch.derived();
                        let mut index = self.index.write(&mut batch, sek, &self.room)?;
                        index.committing(self.next_log_id);
                        for entry in entries {
                            if entry.drop_signature() {
                                index.put(entry)?;
                            }
                        }
                        index.note_swept_delta(swept)?;
                        index.seal()?;
                        batch.commit()?;
                        committed = true;
                    }
                }
            }
            installed.changed = committed || display_changed;
            Ok(installed)
        });
        CompletedRetention {
            pending: self,
            result,
            committed,
            body_changes,
            display_changed,
        }
    }
}

impl PendingCheckpoint {
    pub(crate) fn save(
        mut self,
        store: &Store,
        signer: &dyn RootSigner,
    ) -> pending_text::CompletedText {
        let selected = self.sek.with(|sek| {
            let index = entry_store::EntryIndex::default();
            let entries = index.read(store, sek, &self.room)?;
            let mut below = None;
            let mut expired = 0usize;
            for seq in self.already.saturating_add(1)..=self.head {
                let Some(entry) = entries.get(&self.me, seq)? else {
                    break;
                };
                match entry.payload.as_deref() {
                    None => {
                        below = Some((seq, entry.entry_hash()));
                        expired += 1;
                    }
                    Some(payload)
                        if matches!(classify_payload(payload), Ok(EntryKind::Content)) =>
                    {
                        break
                    }
                    Some(_) => {}
                }
            }
            let Some((seq, entry_hash)) = below else {
                return Ok(None);
            };
            let idle = self.now.get().saturating_sub(self.last_pruned_at)
                >= self.idle_seconds.saturating_mul(1_000);
            if seq <= self.already || (expired < CHECKPOINT_EVERY && !idle) {
                return Ok(None);
            }
            Ok(Some(
                crate::log::checkpoint::Checkpoint { seq, entry_hash }.to_wire(),
            ))
        });
        let result = match selected {
            Ok(Some(payload)) => self
                .append
                .append_control_owned(
                    store,
                    signer,
                    payload,
                    EntryKind::Checkpoint,
                    crate::log::history::SignedEntryKind::Checkpoint,
                    self.now,
                )
                .map(|hash| pending_text::Saved::Governance(Some(hash))),
            Ok(None) => Ok(pending_text::Saved::Governance(None)),
            Err(error) => Err(error),
        };
        self.append.complete_control(result)
    }
}
