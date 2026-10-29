//! Current-version private controls, retained public steps and private receiver replay.
//! Only bounded key/roster metadata crosses the native boundary; history stays in Store.
use super::*;
use crate::atrest::sek::{Sek, WeakSek};
use crate::log::entry::{EntryRead, EntryWrite};
use crate::node::drive::DriveState;

/// Prerequisites use the existing maintenance owner, never a second task/queue convention.
pub(crate) enum Preparation {
    Work(Box<PendingUpgrade>),
    ControlImport,
    PrivateExpiry,
    Waiting,
    Complete,
}

enum Work {
    Restore,
    Controls,
    Legacy,
    Replay,
    ScheduleReplay {
        replay: Result<bool>,
    },
    Receive {
        wire: Vec<u8>,
        authority: Option<TrustNonce>,
    },
    Check {
        wire: Vec<u8>,
        preview: bool,
    },
    Cached {
        hash: Digest32,
        at: u64,
    },
    Serve(serve::Serving),
    PullCursor {
        peer: Digest32,
        cursor: Cursor,
        cursors: BTreeMap<Digest32, Cursor>,
        incarnation: Option<Digest32>,
        binding: Digest32,
        authority: TrustNonce,
    },
}

#[derive(Clone)]
struct LegacyCursor {
    through: u64,
    after: Option<u64>,
    migrating: bool,
}

type ReceiverQuery = ((Digest32, u64), Option<u64>);

#[derive(Default)]
struct LegacyReceiverInput {
    presence: Option<((Digest32, u64), bool)>,
    iteration: Option<((Digest32, u64), u64, bool)>,
    requested: Option<ReceiverQuery>,
}

pub(crate) struct PendingUpgrade {
    owner: Option<Arc<()>>,
    room: Digest32,
    epoch: u64,
    me: Digest32,
    sek: WeakSek,
    pin: Option<history::PendingHistoryRead>,
    index: entry_store::EntryIndex,
    authors: BTreeMap<Digest32, CompositePublicKey>,
    heads: BTreeMap<Digest32, u64>,
    memberships: BTreeMap<Digest32, u64>,
    settled: bool,
    me_left: bool,
    controls_pending: bool,
    drive_input: Option<Zeroizing<Vec<u8>>>,
    drive: DriveState,
    /// Legacy migration asks the original room owner for selected read-only facts.
    receiver_metadata: Option<std::cell::RefCell<LegacyReceiverInput>>,
    receiver_version: receiver_overlay::Stamp,
    drive_committed: bool,
    progress: private_index::Restart,
    legacy: Option<LegacyCursor>,
    legacy_pending: bool,
    observed: BTreeMap<Digest32, (Digest32, u64)>,
    observed_removed: Vec<(Digest32, (Digest32, u64))>,
    controls_after: Option<Digest32>,
    next_log_id: u64,
    now: u64,
    retention: (u64, u64),
    expiry_allowed: bool,
    finish_initial: bool,
    work: Work,
    entries_changed: bool,
    body_changes: u64,
    records: u64,
    news: Vec<String>,
    invalid: Vec<(Digest32, String)>,
    receive_persisting: bool,
    maintenance: bool,
    cursor: Option<(Digest32, Cursor)>,
    incarnation: Option<Digest32>,
}

#[derive(Clone, Copy)]
pub(crate) struct CheckedRecord {
    hash: Digest32,
    author_id: Digest32,
    chain_id: u64,
    iteration: u64,
}

pub(crate) struct Saved {
    pub(crate) advance: SessionAdvance,
    pub(crate) received: Option<Digest32>,
    pub(crate) session_rendered: usize,
    pub(crate) preview: Option<Option<SessionRow>>,
    pub(crate) checked_wire: Option<Vec<u8>>,
    checked_record: Option<CheckedRecord>,
    pub(crate) cached: Option<bool>,
    pub(crate) cursor_committed: bool,
    pub(crate) page: Option<Page>,
}

pub(crate) struct CompletedUpgrade {
    pending: Box<PendingUpgrade>,
    pub(crate) result: Result<Saved>,
}

impl CompletedUpgrade {
    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.pending.room == channel.channel_id
            && self.pending.epoch == channel.epoch
            && self
                .pending
                .owner
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(owner, held))
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
    /// Read-only prerequisite selection. In particular no continuity_step or Store::batch here.
    pub(crate) fn prepare_pending_private_upgrade(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
        finish_initial: bool,
    ) -> Result<Preparation> {
        // Initial admission ends before a peer-dependent control receipt is available.
        // Local restore/import/migration still has to finish before publication.
        if finish_initial {
            self.private_sessions.upgrading = false;
        }
        if !self.private_policy_ready(store, now.get())? {
            return Ok(Preparation::Waiting);
        }
        if self.poisoned {
            return Err(self.save_failure());
        }
        if self.private_sessions.upgrading {
            return Ok(Preparation::Waiting);
        }
        let work = if self.private_sessions.restoring {
            Work::Restore
        } else if self.private_sessions.controls_import {
            return Ok(Preparation::ControlImport);
        } else if !self.current_session_controls_ready(store)? {
            if self.legacy_private_controls_ready(store)? {
                return Ok(Preparation::Waiting);
            }
            Work::Controls
        } else if self.private_sessions.legacy_work.is_some()
            || !self.private_sessions.legacy_pending.is_empty()
        {
            if !self.legacy_private_controls_ready(store)? {
                Work::Controls
            } else {
                Work::Legacy
            }
        } else if self.private_sessions.pending_active {
            Work::Replay
        } else {
            return Ok(if self.private_expiry_ready(store, now.get())? {
                Preparation::Complete
            } else {
                Preparation::PrivateExpiry
            });
        };
        Ok(Preparation::Work(self.prepare_private_component(
            store,
            owner,
            now,
            finish_initial,
            work,
        )?))
    }

    /// Caller retains the exact received flow/trust/room/publication authority until install.
    pub(crate) fn prepare_pending_private_record(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        wire: Vec<u8>,
        now: crate::time::Ms,
        authority: Option<TrustNonce>,
    ) -> Result<Box<PendingUpgrade>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.require_governance_ready(store, now)?;
        if wire.len() > crate::node::sessionstream::MAX_RECORD {
            return Err(Error::SizeLimitExceeded("private Session record"));
        }
        self.prepare_private_component(store, owner, now, false, Work::Receive { wire, authority })
    }

    fn prepare_private_component(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
        finish_initial: bool,
        work: Work,
    ) -> Result<Box<PendingUpgrade>> {
        let mut pending = self.capture_private_component(store, now, finish_initial, work)?;
        pending.pin = Some(self.reserve_pending_write(store, Arc::clone(&owner))?);
        pending.owner = Some(owner);
        Ok(pending)
    }

    fn capture_private_component(
        &self,
        store: &Store,
        now: crate::time::Ms,
        finish_initial: bool,
        work: Work,
    ) -> Result<Box<PendingUpgrade>> {
        let memberships = self
            .authors
            .keys()
            .filter(|peer| !self.has_left(peer))
            .map(|peer| (*peer, self.admission(peer).0))
            .collect();
        let progress = private_index::Restart {
            complete: !self.private_sessions.restoring,
            after: self.private_sessions.restore_after,
            next: self.private_sessions.next.max(1),
            pending: self.private_sessions.pending_active,
            pending_after: self.private_sessions.pending_after,
            pending_through: self.private_sessions.pending_through,
        };
        let legacy = self
            .private_sessions
            .legacy_work
            .as_ref()
            .map(|work| LegacyCursor {
                through: work.through,
                after: work.after,
                migrating: work.migrating,
            });
        Ok(Box::new(PendingUpgrade {
            owner: None,
            room: self.channel_id,
            epoch: self.epoch,
            me: self.me(),
            sek: self.sek.reader(),
            pin: None,
            index: entry_store::EntryIndex::default(),
            authors: self.authors.clone(),
            heads: self
                .authors
                .keys()
                .map(|author| (*author, self.dag.verified_head(author)))
                .collect(),
            memberships,
            settled: self.settled,
            me_left: self.has_left(&self.me()),
            controls_pending: self.private_sessions.controls_import
                || self.private_sessions.restoring,
            drive_input: if matches!(
                &work,
                Work::Restore
                    | Work::Controls
                    | Work::Legacy
                    | Work::ScheduleReplay {
                        replay: Ok(false) | Err(_)
                    }
                    | Work::Serve(_)
                    | Work::PullCursor { .. }
            ) {
                None
            } else {
                Some(self.drive.to_state())
            },
            drive: DriveState::default(),
            receiver_metadata: matches!(&work, Work::Legacy)
                .then(|| std::cell::RefCell::new(LegacyReceiverInput::default())),
            receiver_version: self.receiver_persistence.drive(),
            drive_committed: false,
            progress,
            legacy,
            legacy_pending: !self.private_sessions.legacy_pending.is_empty(),
            observed: self.private_sessions.observed_generations.clone(),
            observed_removed: Vec::new(),
            controls_after: self.private_sessions.controls_after,
            maintenance: matches!(
                &work,
                Work::Restore
                    | Work::Controls
                    | Work::Legacy
                    | Work::Replay
                    | Work::ScheduleReplay { .. }
            ),
            expiry_allowed: match &work {
                Work::ScheduleReplay { replay: Ok(true) } => true,
                Work::Receive { .. } | Work::Replay => {
                    self.private_policy_ready(store, now.get())?
                }
                _ => false,
            },
            next_log_id: self.next_log_id,
            now: now.get(),
            finish_initial,
            work,
            retention: (self.effective_retention(), self.effective_step_retention()),
            entries_changed: false,
            body_changes: 0,
            records: 0,
            news: Vec::new(),
            invalid: Vec::new(),
            receive_persisting: false,
            cursor: None,
            incarnation: None,
        }))
    }

    pub(crate) fn finish_pending_private_upgrade(
        &mut self,
        completed: CompletedUpgrade,
    ) -> Result<Saved> {
        if !completed
            .pending
            .owner
            .as_ref()
            .is_some_and(|owner| completed.can_install(self, owner))
        {
            return completed.result;
        }
        self.finish_legacy_migration(completed)
    }

    /// Shared delta installer; unreserved callers require Source::write_owned's exact owner.
    pub(crate) fn finish_legacy_migration(&mut self, completed: CompletedUpgrade) -> Result<Saved> {
        if completed.pending.room != self.channel_id || completed.pending.epoch != self.epoch {
            return completed.result;
        }
        let CompletedUpgrade {
            pending,
            mut result,
        } = completed;
        let pending = *pending;
        let same_receivers = self.receiver_persistence.drive() == pending.receiver_version;
        if pending.drive_committed {
            if same_receivers {
                let mut drive = pending.drive;
                drive.pending = std::mem::take(&mut self.drive.pending);
                drive.news = std::mem::take(&mut self.drive.news);
                drive.told_unheld = std::mem::take(&mut self.drive.told_unheld);
                drive.change_unsaid = self.drive.change_unsaid;
                self.drive = drive;
            } else {
                result = Err(Error::Profile(
                    "private save receiver basis changed during its reservation",
                ));
            }
        }
        if pending.finish_initial {
            self.private_sessions.upgrading = false;
        }
        self.private_sessions.restoring = !pending.progress.complete;
        self.private_sessions.restore_after = pending.progress.after;
        self.private_sessions.next = self.private_sessions.next.max(pending.progress.next);
        self.private_sessions.pending_active = pending.progress.pending;
        self.private_sessions.pending_after = pending.progress.pending_after;
        self.private_sessions.pending_through = pending.progress.pending_through;
        self.private_sessions.legacy_pending.0 = pending.legacy_pending;
        self.private_sessions.legacy_work = pending.legacy.map(|work| LegacyWork {
            through: work.through,
            after: work.after,
            migrating: work.migrating,
        });
        for (hash, observation) in pending.observed_removed {
            if self.private_sessions.observed_generations.get(&hash) == Some(&observation) {
                self.private_sessions.observed_generations.remove(&hash);
            }
        }
        self.private_sessions.controls_after = pending.controls_after;
        if pending.entries_changed {
            self.entries.committed();
        }
        self.dag.install_retention_delta(pending.body_changes, &[]);
        self.drive.news.extend(pending.news);
        self.gen
            .fetch_add(pending.records, std::sync::atomic::Ordering::Relaxed);
        if let Some((peer, cursor)) = pending.cursor {
            self.private_sessions.cursors.insert(peer, cursor);
        }
        if let Some(incarnation) = pending.incarnation {
            self.private_sessions.incarnation = Some(incarnation);
        }
        for (hash, error) in pending.invalid {
            if !self.private_sessions.invalid_noted {
                self.set_aside.push(format!(
                    "invalid unread private Session {}: {error}; further refusals are logged",
                    crate::node::link::b32_encode(&hash)
                ));
                self.private_sessions.invalid_noted = true;
            }
            tracing::warn!(room = ?self.channel_id, ?hash, %error, "discarded invalid unread legacy Session");
        }
        if let Err(error) = &result {
            if !matches!(error, Error::StreamRefused(reason)
                if *reason == TRUST_CHANGED || *reason == crate::node::history_stream::AUTHORIZATION_CHANGED)
                && (pending.maintenance
                    || pending.receive_persisting
                    || matches!(
                        error,
                        Error::Storage { .. }
                            | Error::MalformedAtRest(_)
                            | Error::AtRestLocked
                            | Error::AtRestUnlockFailed
                    ))
            {
                self.private_save_failed(error);
            }
        }
        if let Some(owner) = &pending.owner {
            self.release_pending_text(owner, false);
        }
        result
    }
}

impl PendingUpgrade {
    pub(crate) fn refused(self: Box<Self>, error: Error) -> CompletedUpgrade {
        CompletedUpgrade {
            pending: self,
            result: Err(error),
        }
    }

    pub(crate) fn run(self: Box<Self>, store: &Store) -> CompletedUpgrade {
        self.run_guarded(store, |_| Ok(()))
    }

    pub(crate) fn run_guarded(
        mut self: Box<Self>,
        store: &Store,
        check: impl Fn(&crate::node::store::Batch<'_>) -> Result<()>,
    ) -> CompletedUpgrade {
        let sek = self.sek.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sek.with(|sek| {
                if let Some(input) = self.drive_input.take() {
                    self.drive = DriveState::from_state(&input)?;
                }
                let work = std::mem::replace(&mut self.work, Work::Controls);
                let mut preview = None;
                let mut cursor_committed = false;
                let mut cached = None;
                let mut checked_wire = None;
                let mut checked_record = None;
                let mut page = None;
                let (advance, received) = match work {
                    Work::Restore => (self.restore(store, sek)?, None),
                    Work::Controls => (self.controls(store, sek)?, None),
                    Work::Legacy => (self.legacy(store, sek, &check)?, None),
                    Work::Replay => (self.replay(store, sek)?, None),
                    Work::ScheduleReplay { replay } => {
                        let mut next = self.progress.clone();
                        next.pending = true;
                        next.pending_after = None;
                        next.pending_through = next.next;
                        self.progress(store, sek, next)?;
                        (
                            if replay? {
                                self.replay(store, sek)?
                            } else {
                                SessionAdvance::Advanced
                            },
                            None,
                        )
                    }
                    Work::Receive { wire, authority } => {
                        let hash = self.receive(store, sek, &wire, authority)?;
                        (SessionAdvance::Advanced, Some(hash))
                    }
                    Work::Check {
                        wire,
                        preview: want_preview,
                    } => {
                        let record = Record::read(&wire)?;
                        let author = record.message.header.author_id;
                        record.verify(
                            &self.room,
                            self.authors
                                .get(&author)
                                .ok_or(Error::StreamRefused("private Session author unknown"))?,
                        )?;
                        if !self.permitted(store, sek, &record)? {
                            return Err(Error::StreamRefused(if want_preview {
                                "private Session has no current drive grant"
                            } else {
                                "private Session has no current Drive grant"
                            }));
                        }
                        if want_preview {
                            preview = Some(self.preview(store, sek, &record)?);
                        }
                        if !want_preview {
                            let header = &record.message.header;
                            checked_record = Some(CheckedRecord {
                                hash: record.hash(),
                                author_id: header.author_id,
                                chain_id: header.chain_id,
                                iteration: header.iteration,
                            });
                        }
                        checked_wire = Some(wire);
                        (SessionAdvance::Waiting, None)
                    }
                    Work::Cached { hash, at } => {
                        cached = Some(
                            match private_index::find(&store.snapshot()?, sek, &self.room, &hash)? {
                                Some(id) => match self.at(store, sek, id)? {
                                    Some(saved) => {
                                        saved.row.is_some()
                                            && !expired(&saved, at, self.retention)
                                            && self.permitted(store, sek, &saved.record)?
                                    }
                                    None => false,
                                },
                                None => false,
                            },
                        );
                        (SessionAdvance::Waiting, None)
                    }
                    Work::Serve(serving) => {
                        page = Some(self.serve(store, sek, serving)?);
                        (SessionAdvance::Waiting, None)
                    }
                    Work::PullCursor {
                        peer,
                        cursor,
                        cursors,
                        incarnation,
                        binding,
                        authority,
                    } => {
                        self.save_cursor(
                            store,
                            sek,
                            &cursors,
                            incarnation,
                            binding,
                            Some(authority),
                        )?;
                        self.cursor = Some((peer, cursor));
                        cursor_committed = true;
                        (SessionAdvance::Advanced, None)
                    }
                };
                Ok(Saved {
                    advance,
                    received,
                    preview,
                    checked_wire,
                    checked_record,
                    cached,
                    cursor_committed,
                    page,
                    session_rendered: self.news.len(),
                })
            })
        }))
        .unwrap_or_else(|_| {
            self.receive_persisting = true;
            Err(Error::Profile("private upgrade worker stopped"))
        });
        CompletedUpgrade {
            pending: self,
            result,
        }
    }

    fn read_private(
        &self,
        sek: &Sek,
        id: u64,
        segment: &crate::atrest::store::SealedSegment,
    ) -> Result<Stored> {
        if segment.ciphertext.len()
            > 2 * crate::node::sessionstream::MAX_RECORD + crate::atrest::sek::TAG_LEN
        {
            return Err(Error::MalformedAtRest(
                "private Session stored row exceeds format",
            ));
        }
        Stored::read(&open_segment(
            sek,
            SegmentKind::PrivateSession,
            id,
            segment,
        )?)
    }
    fn at(&self, store: &Store, sek: &Sek, id: u64) -> Result<Option<Stored>> {
        store
            .snapshot()?
            .get_segment_bounded(
                &self.room,
                SegmentKind::PrivateSession,
                id,
                2 * crate::node::sessionstream::MAX_RECORD,
            )?
            .map(|segment| self.read_private(sek, id, &segment))
            .transpose()
    }
    fn progress(&mut self, store: &Store, sek: &Sek, next: private_index::Restart) -> Result<()> {
        let mut batch = store.batch()?;
        batch.derived();
        next.queue(&mut batch, sek, &self.room)?;
        batch.commit()?;
        self.progress = next;
        Ok(())
    }
    fn restore(&mut self, store: &Store, sek: &Sek) -> Result<SessionAdvance> {
        let mut bytes = 0usize;
        for _ in 0..WORK_ROWS {
            let Some((id, segment)) = store.snapshot()?.segment_after(
                &self.room,
                SegmentKind::PrivateSession,
                self.progress.after,
            )?
            else {
                let mut next = self.progress.clone();
                next.complete = true;
                next.pending = true;
                next.pending_after = None;
                next.pending_through = next.next;
                self.progress(store, sek, next)?;
                return Ok(SessionAdvance::Advanced);
            };
            let saved = self.read_private(sek, id, &segment)?;
            let size = saved.record.message.ciphertext.len();
            if bytes != 0 && bytes.saturating_add(size) > WORK_BYTES {
                break;
            }
            bytes = bytes.saturating_add(size);
            let key = self
                .authors
                .get(&saved.record.message.header.author_id)
                .ok_or(Error::MalformedAtRest("private Session author missing"))?;
            saved.record.verify(&self.room, key)?;
            let mut next = self.progress.clone();
            next.next = next.next.max(
                id.checked_add(1)
                    .ok_or(Error::MalformedAtRest("private Session id exhausted"))?,
            );
            next.after = Some(id);
            if saved.row.is_none() {
                next.pending = true;
                next.pending_after = None;
                next.pending_through = next.next;
            }
            let mut batch = store.batch()?;
            batch.derived();
            private_index::put(&mut batch, sek, &self.room, id, &saved)?;
            next.queue(&mut batch, sek, &self.room)?;
            batch.commit()?;
            self.progress = next;
        }
        Ok(SessionAdvance::Advanced)
    }
    fn controls(&mut self, store: &Store, sek: &Sek) -> Result<SessionAdvance> {
        let mut bytes = 0usize;
        let mut advanced = false;
        for _ in 0..WORK_ROWS {
            let author = match self.controls_after {
                Some(after) => self
                    .heads
                    .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
                    .next()
                    .map(|(a, _)| *a),
                None => self.heads.keys().next().copied(),
            };
            let Some(author) = author else {
                self.controls_after = None;
                return Ok(SessionAdvance::Advanced);
            };
            let snapshot = store.snapshot()?;
            let fact = private_index::control(&snapshot, sek, &self.room, &author)?;
            let head = self.heads[&author];
            let floor =
                floor_index::author(Transaction::Snapshot(&snapshot), sek, &self.room, &author)?
                    .through;
            let through = fact.through.min(floor);
            if through >= head {
                self.controls_after = Some(author);
                continue;
            }
            let seq = through
                .checked_add(1)
                .ok_or(Error::MalformedAtRest("Session control frontier exhausted"))?;
            let read = self.index.read(store, sek, &self.room)?;
            let entry = read
                .get(&author, seq)?
                .ok_or(Error::MalformedAtRest("Session control entry missing"))?;
            let hash = entry.entry_hash();
            if read.log_id(&hash)?.is_none() {
                return Ok(if advanced {
                    SessionAdvance::Advanced
                } else {
                    SessionAdvance::Waiting
                });
            }
            drop(read);
            let entry = self
                .index
                .order_view(store, sek, &self.room)?
                .entry(&hash)?
                .ok_or(Error::MalformedAtRest(
                    "published Session control entry missing",
                ))?;
            let size = entry.payload.as_ref().map_or(0, Vec::len);
            if bytes != 0 && bytes.saturating_add(size) > WORK_BYTES {
                break;
            }
            bytes = bytes.saturating_add(size);
            let mut batch = store.batch()?;
            batch.derived();
            private_index::observe_public(&mut batch, sek, &self.room, &entry, self.epoch)?;
            batch.commit()?;
            advanced = true;
            if seq == head {
                self.controls_after = Some(author);
            }
        }
        Ok(if advanced {
            SessionAdvance::Advanced
        } else {
            SessionAdvance::Waiting
        })
    }
    fn legacy_after(
        &self,
        store: &Store,
        sek: &Sek,
        work: &LegacyCursor,
    ) -> Result<Option<(u64, Entry)>> {
        let snapshot = store.snapshot()?;
        let Some((id, sealed)) =
            snapshot.segment_after(&self.room, SegmentKind::LogDb, work.after)?
        else {
            return Ok(None);
        };
        if id >= work.through {
            return Ok(None);
        }
        let entry = Entry::from_wire(&open_segment(sek, SegmentKind::LogDb, id, &sealed)?)?;
        if self
            .index
            .view(Transaction::Snapshot(&snapshot), sek, &self.room)?
            .log_id(&entry.entry_hash())?
            != Some(id)
        {
            return Err(Error::MalformedAtRest(
                "private migration unpublished entry",
            ));
        }
        Ok(Some((id, entry)))
    }
    fn legacy(
        &mut self,
        store: &Store,
        sek: &Sek,
        check: &impl Fn(&crate::node::store::Batch<'_>) -> Result<()>,
    ) -> Result<SessionAdvance> {
        if self.legacy_pending {
            let read = self.index.read(store, sek, &self.room)?;
            for (author, verified) in &self.heads {
                if !control_ready(
                    &read,
                    sek,
                    &self.room,
                    author,
                    *verified,
                    self.controls_pending,
                )? {
                    return Ok(SessionAdvance::Waiting);
                }
            }
            self.legacy_pending = false;
            self.legacy = Some(LegacyCursor {
                through: self.next_log_id,
                after: None,
                migrating: false,
            });
        }
        let Some(mut work) = self.legacy.clone() else {
            return Ok(SessionAdvance::Complete);
        };
        let mut bytes = 0usize;
        for _ in 0..WORK_ROWS {
            let Some((id, entry)) = self.legacy_after(store, sek, &work)? else {
                if !work.migrating {
                    let read = self.index.read(store, sek, &self.room)?;
                    let mut done = Vec::new();
                    let mut batch = store.batch()?;
                    for (hash, (author, generation)) in &self.observed {
                        if read.log_id(hash)?.is_some() {
                            batch.ruled();
                            private_index::observe_control(
                                &mut batch,
                                sek,
                                &self.room,
                                author,
                                private_index::Control {
                                    generation: Some(*generation),
                                    ..Default::default()
                                },
                            )?;
                            done.push(*hash);
                        }
                    }
                    drop(read);
                    if !done.is_empty() {
                        check(&batch)?;
                        batch.commit()?;
                    }
                    for hash in done {
                        if let Some(observation) = self.observed.remove(&hash) {
                            self.observed_removed.push((hash, observation));
                        }
                    }
                    work.migrating = true;
                    work.after = None;
                    self.legacy = Some(work);
                    return Ok(SessionAdvance::Advanced);
                }
                let mut next = self.progress.clone();
                next.pending = true;
                next.pending_after = None;
                next.pending_through = next.next;
                let mut batch = store.batch()?;
                {
                    let mut index = self.index.write(&mut batch, sek, &self.room)?;
                    index.clear_retained_step_marker()?;
                    index.seal()?;
                }
                next.queue(&mut batch, sek, &self.room)?;
                check(&batch)?;
                batch.commit()?;
                self.index.committed();
                self.progress = next;
                self.entries_changed = true;
                self.legacy = None;
                return Ok(SessionAdvance::Advanced);
            };
            let size = entry.payload.as_ref().map_or(0, Vec::len);
            if bytes != 0 && bytes.saturating_add(size) > WORK_BYTES {
                break;
            }
            bytes = bytes.saturating_add(size);
            if entry
                .payload
                .as_deref()
                .is_some_and(|body| is_step_body(&self.room, body))
            {
                let result = if work.migrating {
                    self.migrate_row(store, sek, entry, check)
                } else {
                    if let Ok(record) = Record::legacy(entry) {
                        let author = record.message.header.author_id;
                        if self
                            .authors
                            .get(&author)
                            .is_some_and(|key| record.verify(&self.room, key).is_ok())
                        {
                            let mut batch = store.batch()?;
                            private_index::observe_control(
                                &mut batch,
                                sek,
                                &self.room,
                                &author,
                                private_index::Control {
                                    generation: Some(record.message.header.chain_id),
                                    ..Default::default()
                                },
                            )?;
                            check(&batch)?;
                            batch.commit()?;
                        }
                    }
                    Ok(())
                };
                if let Err(error) = result {
                    self.legacy = Some(work);
                    if ChannelState::authorization_refreshing(&error)
                        || governance::refreshing(&error)
                    {
                        return Ok(SessionAdvance::Waiting);
                    }
                    return Err(error);
                }
            }
            work.after = Some(id);
            self.legacy = Some(work.clone());
        }
        self.legacy = Some(work);
        Ok(SessionAdvance::Advanced)
    }
    fn current_drive(
        &self,
        transaction: Transaction<'_, '_>,
        sek: &Sek,
        author: &Digest32,
    ) -> Result<bool> {
        if *author == self.me {
            return Ok(true);
        }
        if !self.authors.contains_key(author) || self.me_left {
            return Ok(false);
        }
        if self.controls_pending {
            return Err(Error::StreamRefused(CONTROL_REFRESHING));
        }
        let fact = match transaction {
            Transaction::Snapshot(snapshot) => {
                private_index::control(snapshot, sek, &self.room, author)?
            }
            Transaction::Batch(batch) => private_index::control_in(batch, sek, &self.room, author)?,
        };
        if fact.through < self.heads.get(author).copied().unwrap_or(0) {
            return Err(Error::StreamRefused(CONTROL_REFRESHING));
        }
        let floor = floor_index::author(transaction, sek, &self.room, author)?;
        if floor.through < self.heads.get(author).copied().unwrap_or(0) {
            return Err(Error::StreamRefused(floor_index::REFRESHING));
        }
        let newest = floor
            .announced
            .into_iter()
            .chain(fact.generation)
            .chain(
                self.observed
                    .values()
                    .filter(|(a, _)| a == author)
                    .map(|(_, generation)| *generation),
            )
            .max();
        let Some(generation) = newest else {
            return Ok(false);
        };
        if floor.announced == Some(generation) {
            return Ok(floor_index::floor(
                transaction,
                sek,
                &self.room,
                &(*author, self.me, self.epoch, generation),
            )?
            .is_some_and(|(membership, _, _)| {
                self.memberships.get(&self.me) == Some(&membership)
            }));
        }
        self.receiver_fact((*author, generation), None)
    }
    fn receiver_fact(&self, slot: (Digest32, u64), iteration: Option<u64>) -> Result<bool> {
        if let Some(input) = &self.receiver_metadata {
            let mut input = input.borrow_mut();
            let query = (slot, iteration);
            let answer = match iteration {
                None => input
                    .presence
                    .filter(|(held, _)| *held == slot)
                    .map(|(_, yes)| yes),
                Some(iteration) => input
                    .iteration
                    .filter(|(held, at, _)| *held == slot && *at == iteration)
                    .map(|(_, _, yes)| yes),
            };
            if let Some(answer) = answer {
                return Ok(answer);
            }
            input.requested = Some(query);
            return Err(Error::Profile("legacy receiver input pending"));
        }
        Ok(self.drive.receivers.get(&slot).is_some_and(|chain| {
            iteration.is_none_or(|iteration| chain.can_open_iteration(iteration))
        }))
    }
    fn permitted(&self, store: &Store, sek: &Sek, record: &Record) -> Result<bool> {
        self.permitted_to(store, sek, record, &self.me)
    }
    fn permitted_to(
        &self,
        store: &Store,
        sek: &Sek,
        record: &Record,
        recipient: &Digest32,
    ) -> Result<bool> {
        if !self.settled || !self.authors.contains_key(recipient) {
            return Ok(false);
        }
        let Some(membership) = self.memberships.get(recipient).copied() else {
            return Ok(false);
        };
        let header = &record.message.header;
        if header.author_id == *recipient {
            return Ok(true);
        }
        let read = self.index.read(store, sek, &self.room)?;
        if !control_ready(
            &read,
            sek,
            &self.room,
            &header.author_id,
            self.heads.get(&header.author_id).copied().unwrap_or(0),
            self.controls_pending,
        )? {
            return Err(Error::StreamRefused(floor_index::REFRESHING));
        }
        drop(read);
        let snapshot = store.snapshot()?;
        let Some((old, iteration, _)) = floor_index::floor(
            Transaction::Snapshot(&snapshot),
            sek,
            &self.room,
            &(header.author_id, *recipient, header.epoch, header.chain_id),
        )?
        else {
            return Ok(false);
        };
        if old != membership || header.iteration < iteration {
            return Ok(false);
        }
        drop(snapshot);
        // Derived continuity may itself acquire the writer: exclusively a native-worker leaf.
        let range = floor_index::continuity_step(
            store,
            sek,
            &self.room,
            &header.author_id,
            recipient,
            membership,
        )?
        .ok_or(Error::StreamRefused(floor_index::REFRESHING))?;
        Ok(range.is_some_and(|(lower, upper)| {
            lower <= (header.epoch, header.chain_id) && (header.epoch, header.chain_id) <= upper
        }))
    }
    fn migrate_row(
        &mut self,
        store: &Store,
        sek: &Sek,
        mut entry: Entry,
        check: &impl Fn(&crate::node::store::Batch<'_>) -> Result<()>,
    ) -> Result<()> {
        if let Some(input) = &self.receiver_metadata {
            *input.borrow_mut() = LegacyReceiverInput::default();
        }
        loop {
            let result = self.migrate_row_prepared(store, sek, &mut entry, check);
            let requested = self
                .receiver_metadata
                .as_ref()
                .and_then(|input| input.borrow_mut().requested.take());
            let Some((slot, iteration)) = requested else {
                return result;
            };
            // The probe dropped every Store transaction before asking the original
            // room owner for one scalar. Retry this row, not its committed prefix.
            let answer =
                crate::node::channel::semantic_projection::SelectedReceiverInput::metadata(
                    slot, iteration,
                )?;
            if let Some(input) = &self.receiver_metadata {
                let mut input = input.borrow_mut();
                match iteration {
                    None => input.presence = Some((slot, answer)),
                    Some(iteration) => input.iteration = Some((slot, iteration, answer)),
                }
            }
        }
    }

    fn migrate_row_prepared(
        &mut self,
        store: &Store,
        sek: &Sek,
        entry: &mut Entry,
        check: &impl Fn(&crate::node::store::Batch<'_>) -> Result<()>,
    ) -> Result<()> {
        let hash = entry.entry_hash();
        let before = self
            .index
            .read(store, sek, &self.room)?
            .retention(&hash)?
            .ok_or(Error::MalformedAtRest("legacy step retention missing"))?;
        let permitted = if before.cache_id.is_some() || entry.skeleton.author_id == self.me {
            true
        } else if let Ok(record) = Record::legacy(entry.clone()) {
            self.permitted(store, sek, &record)?
        } else {
            false
        };
        let mut batch = store.batch()?;
        let tracked = self
            .index
            .view(Transaction::Batch(&batch), sek, &self.room)?
            .retention(&hash)?
            .ok_or(Error::MalformedAtRest("legacy step retention missing"))?;
        let cached = match tracked.cache_id {
            Some(id) => {
                let segment = batch
                    .get_segment(&self.room, SegmentKind::PlaintextCache, id)?
                    .ok_or(Error::MalformedAtRest("legacy Session cache missing"))?;
                let CacheRow::Session(row) = parse_cache(&open_segment(
                    sek,
                    SegmentKind::PlaintextCache,
                    id,
                    &segment,
                )?)?
                else {
                    return Err(Error::MalformedAtRest("legacy Session cache kind"));
                };
                if row.entry_hash != hash || row.author != entry.skeleton.author_id {
                    return Err(Error::MalformedAtRest("legacy Session cache binding"));
                }
                Some(row)
            }
            None => None,
        };
        let author = entry.skeleton.author_id;
        private_index::observe_public(&mut batch, sek, &self.room, entry, self.epoch)?;
        let current_drive = self.current_drive(Transaction::Batch(&batch), sek, &author)?;
        let generation = private_index::control_in(&batch, sek, &self.room, &author)?.generation;
        let record = Record::legacy(entry.clone()).ok().filter(|record| {
            self.authors
                .get(&author)
                .is_some_and(|key| record.verify(&self.room, key).is_ok())
        });
        let mut next = self.progress.next.max(1);
        let no_announced_floor =
            floor_index::author(Transaction::Batch(&batch), sek, &self.room, &author)?
                .announced
                .is_none();
        if private_index::find_in(&batch, sek, &self.room, &hash)?.is_none() {
            let retain = if let Some(record) = &record {
                current_drive
                    && (cached.is_some()
                        || permitted
                        || author == self.me
                        || (no_announced_floor
                            && generation == Some(record.message.header.chain_id)
                            && self.receiver_fact(
                                (author, record.message.header.chain_id),
                                Some(record.message.header.iteration),
                            )?))
            } else {
                false
            };
            if let Some(record) = record.filter(|_| retain) {
                let saved = Stored {
                    record,
                    row: cached,
                    first_seen: tracked.first_seen_ms,
                    attention_after: None,
                };
                let id = next;
                next = id
                    .checked_add(1)
                    .ok_or(Error::SizeLimitExceeded("private Session records"))?;
                let segment = seal_segment(sek, SegmentKind::PrivateSession, id, &saved.bytes())?;
                batch.put_segment(&self.room, SegmentKind::PrivateSession, id, &segment)?;
                private_index::put(&mut batch, sek, &self.room, id, &saved)?;
            }
        }
        let dropped = u64::from(entry.prune_payload());
        {
            let mut index = self.index.write(&mut batch, sek, &self.room)?;
            index.committing(self.next_log_id);
            index.put(entry)?;
            index.set_retention(hash, None)?;
            index.seal()?;
        }
        let age = seal_segment(
            sek,
            SegmentKind::Index,
            tracked.log_id,
            &first_seen_bytes(tracked.first_seen_ms, true),
        )?;
        batch.put_segment(&self.room, SegmentKind::Index, tracked.log_id, &age)?;
        if let Some(cache) = tracked.cache_id {
            batch.delete_segment(&self.room, SegmentKind::PlaintextCache, cache)?;
        }
        check(&batch)?;
        batch.commit()?;
        self.progress.next = next;
        self.index.committed();
        self.entries_changed = true;
        self.body_changes += dropped;
        Ok(())
    }
    fn receive(
        &mut self,
        store: &Store,
        sek: &Sek,
        wire: &[u8],
        authority: Option<TrustNonce>,
    ) -> Result<Digest32> {
        self.receive_persisting = false;
        let record = Record::read(wire)?;
        let hash = record.hash();
        self.receive_persisting = true;
        let id = private_index::find(&store.snapshot()?, sek, &self.room, &hash)?;
        let known = id.map(|id| self.at(store, sek, id)).transpose()?.flatten();
        self.receive_persisting = false;
        if known.as_ref().is_some_and(|saved| saved.row.is_some()) {
            return Ok(hash);
        }
        let author = record.message.header.author_id;
        let key = self
            .authors
            .get(&author)
            .ok_or(Error::StreamRefused("private Session author unknown"))?;
        record.verify(&self.room, key)?;
        if author == self.me {
            return Ok(hash);
        }
        let locally_held = known.is_some()
            && record.legacy_claimed_ms().is_some()
            && self.current_drive(Transaction::Snapshot(&store.snapshot()?), sek, &author)?;
        if !locally_held && !self.permitted(store, sek, &record)? {
            return Err(Error::StreamRefused("private Session has no drive grant"));
        }
        let slot = (author, record.message.header.chain_id);
        let receiver = self.drive.receivers.get(&slot).ok_or(Error::StreamRefused(
            "private Session drive key not received",
        ))?;
        if !receiver.can_open_iteration(record.message.header.iteration) {
            return Ok(hash);
        }
        let mut next_receiver = ReceiverChain::from_state(&receiver.to_state())?;
        let plaintext = Zeroizing::new(next_receiver.decrypt(&record.message)?);
        let Decoded::Session(content) = crate::node::content::decode(&plaintext)? else {
            return Err(Error::MalformedBundle("private Session content kind"));
        };
        let row = SessionRow {
            entry_hash: hash,
            author,
            created_millis: content.created_millis,
            session_id: content.session_id,
            body: content.body,
        };
        let saved = Stored {
            record,
            row: Some(row),
            first_seen: known.as_ref().map_or(self.now, |saved| saved.first_seen),
            attention_after: None,
        };
        let id = id.unwrap_or(self.progress.next.max(1));
        let next = id
            .checked_add(1)
            .ok_or(Error::SizeLimitExceeded("private Session records"))?;
        self.receive_persisting = true;
        let drive = self.drive.state_with_receiver(Some((slot, &next_receiver)));
        let segment = seal_segment(sek, SegmentKind::PrivateSession, id, &saved.bytes())?;
        let drive_segment = seal_segment(sek, SegmentKind::KeyMaterial, SEG_DRIVE, &drive)?;
        let mut batch = store.batch()?;
        batch.ruled();
        if let Some(expected) = authority {
            if batch.get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(
                crate::node::trust::TRUST_META_KEY,
            )? != expected
            {
                return Err(Error::StreamRefused(TRUST_CHANGED));
            }
        }
        if let Some(old) = batch.get_segment(&self.room, SegmentKind::PrivateSession, id)? {
            let old = self.read_private(sek, id, &old)?;
            private_index::remove(&mut batch, sek, &self.room, id, &old)?;
        }
        batch.put_segment(&self.room, SegmentKind::PrivateSession, id, &segment)?;
        batch.put_segment(
            &self.room,
            SegmentKind::KeyMaterial,
            SEG_DRIVE,
            &drive_segment,
        )?;
        private_index::put(&mut batch, sek, &self.room, id, &saved)?;
        batch.commit()?;
        self.drive.receivers.insert(slot, next_receiver);
        self.drive_committed = true;
        self.progress.next = self.progress.next.max(next);
        self.records += 1;
        if let Some(row) = saved.row {
            if !crate::node::drive::is_key_changed(&row.session_id) {
                self.news.push(row.session_id);
            }
        }
        self.receive_persisting = true;
        if self.expiry_allowed {
            sweep_private(store, sek, &self.room, self.now, self.retention, |_| {})?;
        }
        self.receive_persisting = false;
        Ok(hash)
    }
    fn replay(&mut self, store: &Store, sek: &Sek) -> Result<SessionAdvance> {
        let mut next = self.progress.clone();
        let mut bytes = 0usize;
        for _ in 0..WORK_ROWS {
            let id = private_index::unread_after(
                &store.snapshot()?,
                sek,
                &self.room,
                next.pending_after,
            )?;
            let Some(id) = id.filter(|id| *id < next.pending_through) else {
                next.pending = false;
                next.pending_after = None;
                next.next = self.progress.next;
                self.progress(store, sek, next)?;
                return Ok(SessionAdvance::Advanced);
            };
            let saved = self
                .at(store, sek, id)?
                .ok_or(Error::MalformedAtRest("unread Session locator missing"))?;
            let size = saved.record.message.ciphertext.len();
            if bytes != 0 && bytes.saturating_add(size) > WORK_BYTES {
                break;
            }
            bytes = bytes.saturating_add(size);
            if saved.row.is_none()
                && self.drive.receivers.contains_key(&(
                    saved.record.message.header.author_id,
                    saved.record.message.header.chain_id,
                ))
            {
                if let Err(error) = self.receive(store, sek, &saved.record.wire(), None) {
                    if governance::refreshing(&error)
                        || floor_index::refreshing(&error)
                        || matches!(&error, Error::StreamRefused(reason) if *reason == CONTROL_REFRESHING)
                    {
                        return Ok(SessionAdvance::Waiting);
                    }
                    // Candidate authentication/content failures discard only unread wire;
                    // a failed native read/write never masquerades as an invalid record.
                    if self.receive_persisting
                        || matches!(
                            &error,
                            Error::MalformedAtRest(_)
                                | Error::AtRestLocked
                                | Error::AtRestUnlockFailed
                        )
                    {
                        return Err(error);
                    }
                    if let Some(current) = self.at(store, sek, id)? {
                        if current.row.is_none() {
                            let mut batch = store.batch()?;
                            batch.derived();
                            batch.delete_segment(&self.room, SegmentKind::PrivateSession, id)?;
                            private_index::remove(&mut batch, sek, &self.room, id, &current)?;
                            batch.commit()?;
                            self.invalid
                                .push((current.record.hash(), error.to_string()));
                        }
                    }
                }
            }
            next.pending_after = Some(id);
        }
        next.next = self.progress.next;
        self.progress(store, sek, next)?;
        Ok(SessionAdvance::Waiting)
    }
}

impl ChannelState {
    /// A committed key arrival schedules the original durable unread pass before yielding.
    pub(crate) fn prepare_pending_private_replay(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
    ) -> Result<Box<PendingUpgrade>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let replay = (|| {
            Ok(self.private_policy_ready(store, now.get())?
                && !self.private_sessions.upgrading
                && !self.private_sessions.restoring
                && self.private_sessions.legacy_work.is_none()
                && self.private_sessions.legacy_pending.is_empty()
                && self.current_session_controls_ready(store)?)
        })();
        self.prepare_private_component(store, owner, now, false, Work::ScheduleReplay { replay })
    }

    /// Use authorize-only for every live page record before applying its first record;
    /// use preview before each individual apply, with the previous real receiver install.
    pub(crate) fn prepare_pending_private_check(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        wire: Vec<u8>,
        preview: bool,
        now: crate::time::Ms,
    ) -> Result<Box<PendingUpgrade>> {
        self.require_governance_ready(store, now)?;
        if self.poisoned {
            return Err(self.save_failure());
        }
        if wire.len() > crate::node::sessionstream::MAX_RECORD {
            return Err(Error::SizeLimitExceeded("private Session record"));
        }
        self.prepare_private_component(store, owner, now, false, Work::Check { wire, preview })
    }

    pub(crate) fn prepare_pending_private_cached(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        hash: Digest32,
        now: crate::time::Ms,
    ) -> Result<Box<PendingUpgrade>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.prepare_private_component(
            store,
            owner,
            now,
            false,
            Work::Cached {
                hash,
                at: self.now_hint,
            },
        )
    }

    pub(crate) fn prepare_pending_private_cursor(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        request: (Digest32, Cursor, u64, TrustNonce),
        now: crate::time::Ms,
    ) -> Result<Box<PendingUpgrade>> {
        let (peer, cursor, revision, authority) = request;
        self.require_governance_ready(store, now)?;
        if self.poisoned
            || self.private_sessions.revision != revision
            || !self.drive_members().contains(&peer)
        {
            return Err(Error::StreamRefused(
                "private live request or authority changed",
            ));
        }
        let mut cursors = self.private_sessions.cursors.clone();
        cursors.insert(peer, cursor.clone());
        let work = Work::PullCursor {
            peer,
            cursor,
            cursors,
            incarnation: self.private_sessions.incarnation,
            binding: self.private_pull_binding(),
            authority,
        };
        self.prepare_private_component(store, owner, now, false, work)
    }
}

impl PendingUpgrade {
    fn preview(&self, store: &Store, sek: &Sek, record: &Record) -> Result<Option<SessionRow>> {
        if let Some(id) = private_index::find(&store.snapshot()?, sek, &self.room, &record.hash())?
        {
            if let Some(saved) = self.at(store, sek, id)? {
                if saved.row.is_some() {
                    return Ok(saved.row);
                }
            }
        }
        let author = record.message.header.author_id;
        if author == self.me {
            return Ok(None);
        }
        let receiver = self
            .drive
            .receivers
            .get(&(author, record.message.header.chain_id))
            .ok_or(Error::StreamRefused(
                "private Session drive key not received",
            ))?;
        if !receiver.can_open_iteration(record.message.header.iteration) {
            return Ok(None);
        }
        let mut next = ReceiverChain::from_state(&receiver.to_state())?;
        let plain = Zeroizing::new(next.decrypt(&record.message)?);
        let Decoded::Session(content) = crate::node::content::decode(&plain)? else {
            return Err(Error::MalformedBundle("private Session content kind"));
        };
        Ok(Some(SessionRow {
            entry_hash: record.hash(),
            author,
            created_millis: content.created_millis,
            session_id: content.session_id,
            body: content.body,
        }))
    }

    fn save_cursor(
        &mut self,
        store: &Store,
        sek: &Sek,
        cursors: &BTreeMap<Digest32, Cursor>,
        incarnation: Option<Digest32>,
        binding: Digest32,
        authority: Option<TrustNonce>,
    ) -> Result<()> {
        if cursors.len() > AUTHORS_HARD_LIMIT {
            return Err(Error::MalformedAtRest("private pull peer bound"));
        }
        self.receive_persisting = true;
        let mut e = Encoder::new();
        e.array(4)
            .uint(1)
            .bytes(incarnation.as_ref().map_or(&[][..], |v| &v[..]))
            .bytes(&binding)
            .array(cursors.len());
        for (peer, cursor) in cursors {
            e.array(3)
                .bytes(peer)
                .bytes(&cursor.incarnation)
                .uint(cursor.after);
        }
        let segment = seal_segment(
            sek,
            SegmentKind::KeyMaterial,
            SEG_PRIVATE_PULLS,
            &e.finish(),
        )?;
        let mut batch = store.batch()?;
        batch.derived();
        if let Some(expected) = authority {
            if batch.get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(
                crate::node::trust::TRUST_META_KEY,
            )? != expected
            {
                return Err(Error::StreamRefused(TRUST_CHANGED));
            }
        }
        batch.put_segment(
            &self.room,
            SegmentKind::KeyMaterial,
            SEG_PRIVATE_PULLS,
            &segment,
        )?;
        batch.commit()?;
        self.receive_persisting = false;
        Ok(())
    }
}

mod page;
pub(crate) use page::{PageFlow, PagePreparation, PageResult};
mod expiry;
mod serve;
pub(in crate::node::channel) use expiry::sweep_private;

impl ChannelState {
    pub(in crate::node::channel) fn snapshot_private_generations(
        &self,
    ) -> Vec<(Digest32, Digest32, u64)> {
        self.private_sessions
            .observed_generations
            .iter()
            .map(|(hash, (author, generation))| (*hash, *author, *generation))
            .collect()
    }

    pub(in crate::node::channel) fn install_private_generations(&mut self, committed: &[Digest32]) {
        for hash in committed {
            self.private_sessions.observed_generations.remove(hash);
        }
    }
}

impl ChannelState {
    /// Exact place_committed/backfill cadence: one bounded migration turn, not the
    /// restore/import/replay/expiry prerequisite sequence used before private release.
    pub(crate) fn prepare_pending_legacy_migration(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
    ) -> Result<Option<Box<PendingUpgrade>>> {
        if self.private_sessions.upgrading
            || self.private_sessions.restoring
            || !self.legacy_private_controls_ready(store)?
        {
            return Ok(None);
        }
        self.prepare_private_component(store, owner, now, false, Work::Legacy)
            .map(Some)
    }
}

impl ChannelState {
    /// Source::write_owned adds its one reservation and pin AFTER this short capture.
    pub(crate) fn prepare_legacy_migration(
        &self,
        store: &Store,
        now: crate::time::Ms,
    ) -> Result<Option<Box<PendingUpgrade>>> {
        if self.private_sessions.upgrading
            || self.private_sessions.restoring
            || !self.legacy_private_controls_ready(store)?
        {
            return Ok(None);
        }
        self.capture_private_component(store, now, false, Work::Legacy)
            .map(Some)
    }
}

/// Shared borrowed control-readiness predicate, used by live and native permission views.
pub(super) fn control_ready(
    read: &entry_store::Read<'_>,
    sek: &Sek,
    room: &Digest32,
    author: &Digest32,
    verified: u64,
    controls_pending: bool,
) -> Result<bool> {
    if controls_pending {
        return Ok(false);
    }
    let target = if read.sparse_enabled() {
        let state = read.sparse_author(author, crate::log::history::LogScope::Public)?;
        if state.as_ref().is_some_and(|state| {
            state.committed.is_some() && state.control_ready == state.committed
        }) {
            return Ok(true);
        }
        match state.and_then(|state| state.committed) {
            Some(head) => {
                read.history_head(&head)?
                    .ok_or(Error::MalformedAtRest("committed history head missing"))?
                    .root
                    .leaves
            }
            None => verified,
        }
    } else {
        verified
    };
    let transaction = read.transaction();
    let control = match transaction {
        Transaction::Snapshot(snapshot) => private_index::control(snapshot, sek, room, author)?,
        Transaction::Batch(batch) => private_index::control_in(batch, sek, room, author)?,
    }
    .through;
    let floor = floor_index::author(transaction, sek, room, author)?.through;
    Ok(verified >= target && control >= target && floor >= target)
}
