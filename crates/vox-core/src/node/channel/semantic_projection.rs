//! Operation-owned content projection. Only selected ratchets and bounded publication deltas
//! cross the room boundary; retained entries and indexes remain source-owned.
use super::*;
use crate::log::entry::{EntryRead, EntryWrite};
use crate::node::store::Batch;

/// One exact native publication may prepare a selected ratchet between Store transactions.
/// The scoped callback owns the original room/epoch/instance/owner capability; it never runs
/// while a classification probe retains its writer.
#[derive(Clone)]
pub(crate) struct SelectedReceiverInput(Arc<dyn ReceiverInputSource>);

trait ReceiverInputSource: Send + Sync {
    fn selected(&self, slot: (Digest32, u64)) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn metadata(&self, slot: (Digest32, u64), iteration: Option<u64>) -> Result<bool>;
    fn check(&self, batch: &Batch<'_>) -> Result<()>;
}

struct BoundReceiverInput<Select, Metadata, Check> {
    select: Select,
    metadata: Metadata,
    check: Check,
}

impl<Select, Metadata, Check> ReceiverInputSource for BoundReceiverInput<Select, Metadata, Check>
where
    Select: Fn((Digest32, u64)) -> Result<Option<Zeroizing<Vec<u8>>>> + Send + Sync,
    Metadata: Fn((Digest32, u64), Option<u64>) -> Result<bool> + Send + Sync,
    Check: Fn(&Batch<'_>) -> Result<()> + Send + Sync,
{
    fn selected(&self, slot: (Digest32, u64)) -> Result<Option<Zeroizing<Vec<u8>>>> {
        (self.select)(slot)
    }
    fn metadata(&self, slot: (Digest32, u64), iteration: Option<u64>) -> Result<bool> {
        (self.metadata)(slot, iteration)
    }
    fn check(&self, batch: &Batch<'_>) -> Result<()> {
        (self.check)(batch)
    }
}

thread_local! {
    static SELECTED_RECEIVER_INPUT: std::cell::RefCell<Option<SelectedReceiverInput>> =
        const { std::cell::RefCell::new(None) };
}

impl SelectedReceiverInput {
    pub(crate) fn new(
        select: impl Fn((Digest32, u64)) -> Result<Option<Zeroizing<Vec<u8>>>> + Send + Sync + 'static,
        metadata: impl Fn((Digest32, u64), Option<u64>) -> Result<bool> + Send + Sync + 'static,
        check: impl Fn(&Batch<'_>) -> Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(BoundReceiverInput {
            select,
            metadata,
            check,
        }))
    }

    pub(crate) fn scope<T>(&self, body: impl FnOnce() -> T) -> T {
        struct Restore(Option<SelectedReceiverInput>);
        impl Drop for Restore {
            fn drop(&mut self) {
                SELECTED_RECEIVER_INPUT.with(|input| input.replace(self.0.take()));
            }
        }
        let _restore =
            Restore(SELECTED_RECEIVER_INPUT.with(|input| input.replace(Some(self.clone()))));
        body()
    }

    pub(crate) fn selected(slot: (Digest32, u64)) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let input = SELECTED_RECEIVER_INPUT
            .with(|input| input.borrow().clone())
            .ok_or(Error::Profile("native classification input owner missing"))?;
        input.0.selected(slot)
    }

    pub(crate) fn metadata(slot: (Digest32, u64), iteration: Option<u64>) -> Result<bool> {
        let input = SELECTED_RECEIVER_INPUT
            .with(|input| input.borrow().clone())
            .ok_or(Error::Profile("native classification input owner missing"))?;
        input.0.metadata(slot, iteration)
    }

    pub(crate) fn check(batch: &Batch<'_>) -> Result<()> {
        let input = SELECTED_RECEIVER_INPUT
            .with(|input| input.borrow().clone())
            .ok_or(Error::Profile("native classification input owner missing"))?;
        input.0.check(batch)
    }
}

impl ChannelState {
    pub(crate) fn classification_receiver_bytes(
        &self,
        slot: (Digest32, u64),
        owner: &Arc<()>,
        epoch: u64,
        instance: &Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.classification_receiver_owner(owner, epoch, instance)?;
        Ok(self.drive.receivers.get(&slot).map(ReceiverChain::to_state))
    }

    pub(crate) fn classification_receiver_metadata(
        &self,
        slot: (Digest32, u64),
        iteration: Option<u64>,
        owner: &Arc<()>,
        epoch: u64,
        instance: &Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<bool> {
        self.classification_receiver_owner(owner, epoch, instance)?;
        Ok(self.drive.receivers.get(&slot).is_some_and(|chain| {
            iteration.is_none_or(|iteration| chain.can_open_iteration(iteration))
        }))
    }

    fn classification_receiver_owner(
        &self,
        owner: &Arc<()>,
        epoch: u64,
        instance: &Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<()> {
        if self.epoch != epoch
            || !Arc::ptr_eq(&self.gen, instance)
            || !self.owns_pending_history_write(owner)
        {
            return Err(Error::Unreachable(
                "classification input room owner changed",
            ));
        }
        Ok(())
    }
}

pub(crate) struct PreparedContent {
    author: Digest32,
    hash: Digest32,
    outcome: PreparedOutcome,
}

enum PreparedOutcome {
    Applied,
    Deferred,
    Unavailable,
    Open {
        decoded: Option<Decoded>,
        drive: bool,
    },
}

impl PreparedOutcome {
    fn opened(plaintext: Zeroizing<Vec<u8>>, drive: bool) -> Self {
        Self::Open {
            decoded: crate::node::content::decode(&plaintext).ok(),
            drive,
        }
    }
}

pub(crate) enum ProjectionOutcome {
    Visible,
    Applied,
    Deferred,
    Unavailable,
}

/// A bounded semantic page may revisit a ratchet. Preparation advances that one candidate,
/// not a second copy of the published chain, so the final serialization includes every row.
pub(crate) struct SemanticProjection {
    room: Digest32,
    epoch: u64,
    entries: entry_store::EntryIndex,
    normal: BTreeMap<(Digest32, u64), ReceiverChain>,
    drive: BTreeMap<(Digest32, u64), ReceiverChain>,
    normal_advances: u64,
    drive_advances: u64,
    receivers_dirty: bool,
    normal_bytes: Zeroizing<Vec<u8>>,
    drive_bytes: Zeroizing<Vec<u8>>,
    normal_stamp: receiver_overlay::Stamp,
    drive_stamp: receiver_overlay::Stamp,
    next_log_id: u64,
    legacy: legacy_session::LegacyProjectionContext,
    retention: (u64, u64),
    governance_current: bool,
    held: BTreeMap<Digest32, (u64, u64)>,
    now: u64,
    maintenance_now: u64,
    unheld: BTreeSet<Digest32>,
    pub(crate) rows: Vec<Rendered>,
    pub(crate) sessions: Vec<(SessionRow, u64)>,
    pub(crate) expired: Vec<(Digest32, Tracked)>,
    step_bodies: Vec<Digest32>,
    pub(crate) committed: bool,
    pub(crate) display_changed: bool,
    pruned: u64,
}

impl SemanticProjection {
    pub(crate) fn new(channel: &ChannelState, store: &Store, now: u64) -> Result<Self> {
        Ok(Self {
            room: channel.channel_id,
            epoch: channel.epoch,
            entries: channel.entries.fork_reader(),
            normal: BTreeMap::new(),
            drive: BTreeMap::new(),
            normal_advances: 0,
            drive_advances: 0,
            receivers_dirty: channel.chains_advanced,
            normal_bytes: Zeroizing::new(Vec::new()),
            drive_bytes: Zeroizing::new(Vec::new()),
            normal_stamp: channel.receiver_persistence.normal(),
            drive_stamp: channel.receiver_persistence.drive(),
            next_log_id: channel.next_log_id,
            legacy: channel.legacy_projection_context(store)?,
            retention: (
                channel.effective_retention(),
                channel.effective_step_retention(),
            ),
            held: channel
                .authors
                .keys()
                .filter_map(|author| {
                    channel.dag.feed(author).map(|feed| {
                        (
                            *author,
                            (
                                feed.max_seq(),
                                channel.dag.checkpoint(author).map_or(0, |(seq, _)| seq),
                            ),
                        )
                    })
                })
                .collect(),
            governance_current: channel.governance_display_current(now),
            now,
            maintenance_now: channel.now_hint,
            unheld: BTreeSet::new(),
            rows: Vec::new(),
            sessions: Vec::new(),
            expired: Vec::new(),
            step_bodies: Vec::new(),
            committed: false,
            display_changed: false,
            pruned: 0,
        })
    }

    pub(crate) fn prepare(
        &mut self,
        channel: &ChannelState,
        store: &Store,
        author: Digest32,
        hash: Digest32,
        payload: &[u8],
        historical: bool,
    ) -> Result<PreparedContent> {
        let outcome = self.prepare_inner(channel, store, author, hash, payload, historical)?;
        Ok(PreparedContent {
            author,
            hash,
            outcome,
        })
    }

    fn prepare_inner(
        &mut self,
        channel: &ChannelState,
        store: &Store,
        author: Digest32,
        hash: Digest32,
        payload: &[u8],
        historical: bool,
    ) -> Result<PreparedOutcome> {
        let own = author == channel.me();
        if !own {
            match channel.consent_facts() {
                Ok(facts) if !facts.can_read(&channel.me(), &author) => {
                    return Ok(PreparedOutcome::Applied)
                }
                Ok(_) => {}
                Err(error) if governance::refreshing(&error) => {
                    return Ok(PreparedOutcome::Deferred)
                }
                Err(error) => return Err(error),
            }
        }
        let Ok(message) = GroupMessage::from_wire(payload) else {
            return Ok(PreparedOutcome::Applied);
        };
        let drive = message.header.channel_id == drive_channel(&self.room);
        let slot = (author, message.header.chain_id);
        if drive {
            let chain = match self.drive.entry(slot) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let Some(chain) = channel.drive.receivers.get(&slot) else {
                        if channel.drive.holds_from(&author)
                            && !channel.drive.told_unheld.contains(&author)
                        {
                            self.unheld.insert(author);
                        }
                        return Ok(PreparedOutcome::Applied);
                    };
                    entry.insert(ReceiverChain::from_state(&chain.to_state())?)
                }
            };
            let plaintext = match chain.decrypt(&message) {
                Ok(plaintext) => plaintext,
                Err(error @ Error::MalformedBundle("group iteration overflow")) => {
                    return Err(error)
                }
                Err(_) => return Ok(PreparedOutcome::Applied),
            };
            self.drive_advances = self
                .drive_advances
                .checked_add(1)
                .ok_or(Error::MalformedAtRest("receiver persistence overflow"))?;
            return Ok(PreparedOutcome::opened(Zeroizing::new(plaintext), true));
        }
        if historical || own {
            let input = channel.entries.read(store, &channel.sek, &self.room)?;
            if channel
                .entries
                .render_view(store, &channel.sek, &self.room)?
                .fact(&hash)?
                .is_some()
                || input.read_receipt_cache(&hash)?.is_some()
                || input
                    .retention(&hash)?
                    .is_some_and(|tracked| tracked.cache_id.is_some())
                || channel.private_id(store, &hash)?.is_some()
                || channel
                    .drive
                    .pending
                    .iter()
                    .any(|(row, _)| row.entry_hash == hash)
                || self.rows.iter().any(|row| row.entry_hash == hash)
                || self.sessions.iter().any(|(row, _)| row.entry_hash == hash)
            {
                return Ok(PreparedOutcome::Applied);
            }
        }
        let old_own = if own && message.header.epoch < self.epoch {
            let root = channel
                .authors
                .get(&author)
                .ok_or(Error::MalformedGovernance("own history author missing"))?;
            let snapshot = store.snapshot()?;
            own_historical_keys::lookup(
                &snapshot,
                &channel.sek,
                &self.room,
                root,
                &author,
                message.header.epoch,
                message.header.chain_id,
            )?
        } else {
            None
        };
        if own {
            let chain = old_own.as_ref().or_else(|| {
                channel
                    .receivers
                    .get(&slot)
                    .filter(|chain| chain.epoch() == message.header.epoch)
            });
            let Some(chain) = chain else {
                return Ok(if channel.own_behind {
                    PreparedOutcome::Unavailable
                } else {
                    PreparedOutcome::Applied
                });
            };
            return Ok(match chain.decrypt_retained(&message) {
                Ok(plaintext) => PreparedOutcome::opened(Zeroizing::new(plaintext), false),
                Err(_) => PreparedOutcome::Unavailable,
            });
        }
        if let std::collections::btree_map::Entry::Vacant(entry) = self.normal.entry(slot) {
            if let Some(chain) = channel
                .receivers
                .get(&slot)
                .filter(|chain| chain.epoch() == message.header.epoch)
            {
                entry.insert(ReceiverChain::from_state(&chain.to_state())?);
            }
        }
        let Some(chain) = self.normal.get_mut(&slot) else {
            return Ok(PreparedOutcome::Applied);
        };
        let plaintext = match if historical {
            chain.decrypt_history(&message)
        } else {
            chain.decrypt(&message)
        } {
            Ok(plaintext) => Zeroizing::new(plaintext),
            Err(error @ Error::MalformedBundle("group iteration overflow")) => return Err(error),
            Err(_) if historical => return Ok(PreparedOutcome::Unavailable),
            Err(_) => return Ok(PreparedOutcome::Applied),
        };
        self.normal_advances = self
            .normal_advances
            .checked_add(1)
            .ok_or(Error::MalformedAtRest("receiver persistence overflow"))?;
        Ok(PreparedOutcome::opened(plaintext, false))
    }

    /// Complete borrowed serialization before releasing the room. Unselected ratchets are
    /// encoded directly from their owner, never reconstructed as a second mutable map.
    pub(crate) fn seal_preparation(&mut self, channel: &ChannelState) -> Result<()> {
        let mut encoder = Encoder::for_secrets();
        encoder
            .array(2)
            .uint(RECEIVERS_VERSION)
            .array(channel.receivers.len());
        for (slot, chain) in &channel.receivers {
            encoder.bytes(&self.normal.get(slot).unwrap_or(chain).to_state());
        }
        self.normal_bytes = Zeroizing::new(encoder.finish());
        self.drive_bytes = channel.drive.state_with_receivers(&self.drive);
        self.normal_stamp = channel
            .receiver_persistence
            .normal_after(self.normal_advances)?;
        self.drive_stamp = channel
            .receiver_persistence
            .drive_after(self.drive_advances)?;
        Ok(())
    }

    pub(crate) fn apply_with(
        &mut self,
        batch: &mut Batch<'_>,
        sek: &Sek,
        prepared: PreparedContent,
        entry: &Entry,
    ) -> Result<ProjectionOutcome> {
        let PreparedContent {
            author,
            hash,
            outcome,
        } = prepared;
        let (decoded, drive) = match outcome {
            PreparedOutcome::Applied => return Ok(ProjectionOutcome::Applied),
            PreparedOutcome::Unavailable => return Ok(ProjectionOutcome::Unavailable),
            PreparedOutcome::Deferred => {
                let mut index = self.entries.write(batch, sek, &self.room)?;
                index.queue_backfill(author, Some(1))?;
                index.seal()?;
                return Ok(ProjectionOutcome::Deferred);
            }
            PreparedOutcome::Open { decoded, drive } => (decoded, drive),
        };
        if drive {
            let session = matches!(&decoded, Some(Decoded::Session(_)));
            self.legacy.remember(batch, sek, hash, author, session)?;
            let Some(Decoded::Session(content)) = decoded else {
                return Ok(ProjectionOutcome::Applied);
            };
            if self.expired_into(batch, sek, entry, content.created_millis)? {
                return Ok(ProjectionOutcome::Applied);
            }
            let id = self.next_log_id;
            let row = SessionRow {
                entry_hash: hash,
                author,
                created_millis: content.created_millis,
                session_id: content.session_id,
                body: content.body,
            };
            self.cache(batch, sek, id, &session_cache_bytes(&row))?;
            self.retention_rendered(batch, sek, &hash, row.created_millis, Some(id))?;
            self.next_log_id = id.saturating_add(1);
            self.sessions.push((row, id));
            return Ok(ProjectionOutcome::Applied);
        }
        match decoded {
            Some(Decoded::Text(content)) => {
                if self.expired_into(batch, sek, entry, content.created_millis)? {
                    return Ok(ProjectionOutcome::Applied);
                }
                let id = self.next_log_id;
                let row = Rendered {
                    entry_hash: hash,
                    author,
                    created_millis: content.created_millis,
                    text: content.text,
                    arrival: id,
                    shown_at_ms: 0,
                    late: false,
                    owed: false,
                };
                self.cache(batch, sek, id, &cache_bytes(&row))?;
                let mut index = self.entries.write(batch, sek, &self.room)?;
                index.put_rendered(&row, shown_now())?;
                index.retention_rendered(&hash, row.created_millis, Some(id))?;
                index.seal()?;
                self.next_log_id = id.saturating_add(1);
                self.rows.push(row);
                Ok(ProjectionOutcome::Visible)
            }
            Some(Decoded::Read(content)) => {
                if self.expired_into(batch, sek, entry, content.created_millis)? {
                    return Ok(ProjectionOutcome::Applied);
                }
                let id = self.next_log_id;
                let row = ReadRow {
                    entry_hash: hash,
                    reader: author,
                    created_millis: content.created_millis,
                    read: content.read,
                };
                self.cache(batch, sek, id, &read_cache_bytes(&row))?;
                let mut index = self.entries.write(batch, sek, &self.room)?;
                index.put_read_receipt(&row, id)?;
                index.retention_rendered(&hash, row.created_millis, Some(id))?;
                index.seal()?;
                self.next_log_id = id.saturating_add(1);
                Ok(ProjectionOutcome::Applied)
            }
            Some(Decoded::LegacySessionIndex(index)) => {
                self.legacy
                    .accept(batch, sek, hash, author, index, self.now)?;
                Ok(ProjectionOutcome::Applied)
            }
            _ => Ok(ProjectionOutcome::Applied),
        }
    }

    fn cache(&self, batch: &mut Batch<'_>, sek: &Sek, id: u64, bytes: &[u8]) -> Result<()> {
        let sealed = seal_segment(sek, SegmentKind::PlaintextCache, id, bytes)?;
        batch.put_segment(&self.room, SegmentKind::PlaintextCache, id, &sealed)
    }

    fn retention_rendered(
        &self,
        batch: &mut Batch<'_>,
        sek: &Sek,
        hash: &Digest32,
        created: u64,
        cache: Option<u64>,
    ) -> Result<()> {
        let mut index = self.entries.write(batch, sek, &self.room)?;
        index.retention_rendered(hash, created, cache)?;
        index.seal()
    }

    pub(crate) fn expired(
        &self,
        batch: &Batch<'_>,
        sek: &Sek,
        entry: &Entry,
        created: u64,
    ) -> Result<bool> {
        if !self.governance_current || entry.payload.as_deref().is_some_and(retained_control) {
            return Ok(false);
        }
        let tracked = self
            .entries
            .in_batch(batch, sek, &self.room)?
            .retention(&entry.entry_hash())?;
        let steps = tracked.map_or_else(
            || {
                entry
                    .payload
                    .as_deref()
                    .is_some_and(|body| is_step_body(&self.room, body))
            },
            |tracked| tracked.steps,
        );
        let ttl = if steps {
            self.retention.1
        } else {
            self.retention.0
        };
        let first_seen = tracked.map_or(self.now, |tracked| tracked.first_seen_ms);
        Ok(ttl != 0
            && created.min(first_seen) <= self.now.saturating_sub(ttl.saturating_mul(1_000)))
    }

    fn expired_into(
        &mut self,
        batch: &mut Batch<'_>,
        sek: &Sek,
        entry: &Entry,
        created: u64,
    ) -> Result<bool> {
        if !self.expired(batch, sek, entry, created)? {
            return Ok(false);
        }
        let hash = entry.entry_hash();
        self.retention_rendered(batch, sek, &hash, created, None)?;
        self.expired.extend(
            self.entries
                .in_batch(batch, sek, &self.room)?
                .retention(&hash)?
                .map(|tracked| (hash, tracked)),
        );
        Ok(true)
    }

    pub(crate) fn track_known_with(
        &mut self,
        batch: &mut Batch<'_>,
        sek: &Sek,
        entry: &Entry,
        log: u64,
    ) -> Result<()> {
        if entry.payload.as_deref().is_some_and(retained_control) {
            return Ok(());
        }
        let hash = entry.entry_hash();
        let saved = batch
            .get_segment(&self.room, SegmentKind::Index, log)?
            .ok_or(Error::MalformedAtRest("sparse Content age missing"))?;
        let (source_seen, source_steps) =
            parse_first_seen(&open_segment(sek, SegmentKind::Index, log, &saved)?)?;
        let previous = self
            .entries
            .in_batch(batch, sek, &self.room)?
            .retention(&hash)?;
        if previous.is_some_and(|tracked| tracked.log_id != log) {
            return Err(Error::MalformedAtRest(
                "sparse Content retention locator differs",
            ));
        }
        let first_seen_ms = previous
            .map_or(source_seen, |tracked| tracked.first_seen_ms)
            .min(source_seen);
        let steps = source_steps
            || previous.is_some_and(|tracked| tracked.steps)
            || entry
                .payload
                .as_deref()
                .is_some_and(|body| is_step_body(&self.room, body));
        if steps {
            self.step_bodies.push(hash);
        }
        let tracked = Tracked {
            log_id: log,
            steps,
            first_seen_ms,
            claimed_ms: previous
                .and_then(|tracked| tracked.claimed_ms)
                .or_else(|| steps.then_some(entry.skeleton.claimed_ms)),
            cache_id: previous.and_then(|tracked| tracked.cache_id),
        };
        let age = seal_segment(
            sek,
            SegmentKind::Index,
            log,
            &first_seen_bytes(first_seen_ms, steps),
        )?;
        batch.put_segment(&self.room, SegmentKind::Index, log, &age)?;
        let mut index = self.entries.write(batch, sek, &self.room)?;
        index.set_retention(hash, Some(tracked))?;
        index.seal()
    }

    #[cfg(feature = "test-knobs")]
    pub(crate) fn track_current_with(
        &mut self,
        batch: &mut Batch<'_>,
        sek: &Sek,
        entry: &Entry,
        log: u64,
    ) -> Result<()> {
        if entry.payload.as_deref().is_some_and(retained_control) {
            return Ok(());
        }
        let hash = entry.entry_hash();
        let steps = entry
            .payload
            .as_deref()
            .is_some_and(|body| is_step_body(&self.room, body));
        if steps {
            self.step_bodies.push(hash);
        }
        let age = seal_segment(
            sek,
            SegmentKind::Index,
            log,
            &first_seen_bytes(self.now, steps),
        )?;
        batch.put_segment(&self.room, SegmentKind::Index, log, &age)?;
        let mut index = self.entries.write(batch, sek, &self.room)?;
        index.set_retention(
            hash,
            Some(Tracked {
                log_id: log,
                steps,
                first_seen_ms: self.now,
                claimed_ms: steps.then_some(entry.skeleton.claimed_ms),
                cache_id: None,
            }),
        )?;
        index.seal()
    }

    pub(crate) fn queue_receivers_with(&self, batch: &mut Batch<'_>, sek: &Sek) -> Result<()> {
        let normal = seal_segment(
            sek,
            SegmentKind::KeyMaterial,
            SEG_RECEIVERS,
            &self.normal_bytes,
        )?;
        receiver_overlay::rewrite(batch, sek, &self.room, &normal, self.normal_stamp)?;
        let drive = seal_segment(sek, SegmentKind::KeyMaterial, SEG_DRIVE, &self.drive_bytes)?;
        batch.put_segment(&self.room, SegmentKind::KeyMaterial, SEG_DRIVE, &drive)?;
        receiver_overlay::wrote_drive(batch, sek, &self.room, self.drive_stamp)
    }

    /// Derived visibility and expiry are physical worker work, never install-time saves.
    /// The caller records its data commit before entering this fallible continuation.
    pub(crate) fn after_commit_with(&mut self, store: &Store, sek: &Sek) -> Result<()> {
        self.committed = true;
        self.entries.committed();
        self.legacy.committed();
        if !self.rows.is_empty() {
            let shown = shown_now();
            let mut batch = store.batch()?;
            batch.derived();
            SelectedReceiverInput::check(&batch)?;
            let mut index = self.entries.write(&mut batch, sek, &self.room)?;
            for row in &self.rows {
                index.remove_rendered(&row.entry_hash)?;
            }
            for row in &self.rows {
                index.put_rendered(row, shown)?;
            }
            index.seal()?;
            batch.commit()?;
            self.entries.committed();
        }
        if !self.expired.is_empty() {
            self.legacy.reconcile_with_candidates(
                store,
                sek,
                self.maintenance_now,
                Some(&self.drive),
            )?;
            self.legacy.prepare_reconcile(
                store,
                sek,
                self.maintenance_now,
                Some(&self.drive),
                |_, _| Ok(()),
            )?;
            let mut batch = store.batch()?;
            batch.derived();
            SelectedReceiverInput::check(&batch)?;
            let mut pruned = 0;
            let mut display_changed = false;
            for (hash, tracked) in &self.expired {
                let input = self.entries.in_batch(&batch, sek, &self.room)?;
                let mut entry = match input.get_sparse_published(hash)? {
                    Some(entry) => entry,
                    None => {
                        let (author, seq) = input
                            .locate(hash)?
                            .ok_or(Error::MalformedAtRest("pruned entry locator missing"))?;
                        input
                            .get(&author, seq)?
                            .ok_or(Error::MalformedAtRest("pruned entry missing"))?
                    }
                };
                drop(input);
                session_projection::private_index::observe_public(
                    &mut batch, sek, &self.room, &entry, self.epoch,
                )?;
                let mut index = self.entries.write(&mut batch, sek, &self.room)?;
                index.committing(self.next_log_id);
                display_changed |= index.has_rendered(hash)?;
                index.remove_rendered(hash)?;
                index.remove_read_receipt(hash)?;
                index.set_retention(*hash, None)?;
                if let Some((maximum, checkpoint)) = self.held.get(&entry.skeleton.author_id) {
                    if entry.skeleton.seq != 0 && entry.skeleton.seq <= *maximum {
                        if entry.prune_payload() {
                            pruned += 1;
                        }
                        if self.retention.0 != 0 && entry.skeleton.seq <= *checkpoint {
                            entry.drop_signature();
                        }
                    }
                }
                index.put(&entry)?;
                index.seal()?;
                let age = seal_segment(
                    sek,
                    SegmentKind::Index,
                    tracked.log_id,
                    &first_seen_bytes(tracked.first_seen_ms, tracked.steps),
                )?;
                batch.put_segment(&self.room, SegmentKind::Index, tracked.log_id, &age)?;
                if let Some(cache) = tracked.cache_id {
                    batch.delete_segment(&self.room, SegmentKind::PlaintextCache, cache)?;
                }
            }
            self.legacy
                .reconcile_in(&mut batch, sek, self.maintenance_now)?;
            self.legacy.require_inputs()?;
            self.queue_receivers_with(&mut batch, sek)?;
            batch.commit()?;
            self.entries.committed();
            self.pruned += pruned;
            self.display_changed |= display_changed;
            self.legacy.committed();
        }
        Ok(())
    }

    pub(crate) fn receivers_advanced(&self) -> bool {
        self.receivers_dirty || self.normal_advances != 0 || self.drive_advances != 0
    }

    pub(crate) fn install(self, channel: &mut ChannelState, store: &Store) -> Result<()> {
        if !self.committed {
            return Ok(());
        }
        channel.entries.committed();
        if self.normal_advances != 0 {
            for (slot, chain) in self.normal {
                channel.receivers.insert(slot, chain);
            }
            channel
                .receiver_persistence
                .advance_normal_by(self.normal_advances)?;
        }
        if self.drive_advances != 0 {
            for (slot, chain) in self.drive {
                channel.drive.receivers.insert(slot, chain);
            }
            channel
                .receiver_persistence
                .advance_drive_by(self.drive_advances)?;
        }
        channel.next_log_id = self.next_log_id;
        channel.install_legacy_projection_context(&self.legacy);
        channel.chains_advanced |= self.normal_advances != 0 || self.drive_advances != 0;
        for author in self.unheld {
            if channel.drive.told_unheld.insert(author) {
                channel
                    .drive
                    .news
                    .push(crate::node::drive::KEY_CHANGED.to_owned());
            }
        }
        channel.drive.pending.extend(self.sessions);
        for (row, _) in std::mem::take(&mut channel.drive.pending) {
            if !crate::node::drive::is_key_changed(&row.session_id) {
                channel.drive.news.push(row.session_id);
            }
        }
        for hash in self.step_bodies {
            channel.invalidate_display();
            channel.private_sessions.legacy_pending.insert(hash);
        }
        if self.pruned != 0 {
            channel.dag.install_retention_delta(self.pruned, &[]);
        }
        if self.display_changed {
            channel.invalidate_display();
            channel.display_tail = channel
                .entries
                .render_view(store, &channel.sek, &channel.channel_id)?
                .step(None, true, None, true)?
                .map(|(key, _)| key);
        }
        for row in self.rows {
            channel.note_rendered(store, &row.entry_hash)?;
        }
        channel.settle_display_order(store)
    }
}
