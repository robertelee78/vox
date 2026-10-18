//! Session payloads live outside the public room log. Each sealed record commits its verified
//! wire, rendered row and first-seen time together with the consumed drive chain.

use std::time::{Duration, Instant};

use super::session_projection::{floor_index, private_index};
use super::*;
use crate::node::sessionstream::{
    Ask, Cursor, Locator, Page, Query as PrivateQuery, Record, MAX_PAGE, MAX_RECORD, PAGE_OVERHEAD,
    PAGE_RECORDS,
};

const SUPPORT: &str = "vox/private-session-stream/v1";
const CONTROL_REFRESHING: &str = "Session control facts are refreshing";
const SEG_LEGACY_DRIVE_GENERATIONS: u64 = 19;
const SEG_PRIVATE_PULLS: u64 = 23;
const WORK_ROWS: usize = 32;
const WORK_BYTES: usize = 1024 * 1024;
const TRUST_CHANGED: &str = "private trust incarnation changed";
type TrustNonce = Option<[u8; crate::atrest::sek::NONCE_LEN]>;

/// Callers only signal that committed public steps need inspection. The actual work is a
/// disk cursor, not one resident hash for every historical step.
#[derive(Default)]
pub(super) struct LegacyPending(bool);
impl LegacyPending {
    pub(super) fn insert(&mut self, _hash: Digest32) {
        self.0 = true;
    }
    pub(super) fn is_empty(&self) -> bool {
        !self.0
    }
}

struct LegacyWork {
    through: u64,
    after: Option<u64>,
    migrating: bool,
}

struct RefreshWork {
    grant: Digest32,
    public: u64,
    private: u64,
    through: u64,
    public_after: Option<(u64, u64, Digest32)>,
    private_after: Option<[u8; 64]>,
    stage: u8,
}

pub(super) fn support_body(room: &Digest32, author: &Digest32) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(3).text(SUPPORT).bytes(room).bytes(author);
    let mut body = GROUP_MSG_SIGN_DOMAIN.as_bytes().to_vec();
    body.extend(e.finish());
    body
}

pub(super) fn is_support(body: &[u8]) -> bool {
    let Some(bytes) = body.strip_prefix(GROUP_MSG_SIGN_DOMAIN.as_bytes()) else {
        return false;
    };
    let mut d = Decoder::new(bytes);
    d.array().ok() == Some(3)
        && d.text().ok() == Some(SUPPORT)
        && d.bytes().is_ok_and(|b| b.len() == 32)
        && d.bytes().is_ok_and(|b| b.len() == 32)
        && d.finish().is_ok()
}

#[derive(Clone, Copy)]
pub(super) struct AttentionOpening {
    pub(super) after: crate::node::api::HistoryCursor,
    pub(super) identity: Digest32,
}

pub(super) struct Stored {
    pub(super) record: Record,
    // An authorized legacy body can arrive before its drive key package is installed.
    pub(super) row: Option<SessionRow>,
    pub(super) first_seen: u64,
    // Own lifecycle records retain the public arrival boundary of their publication.
    // This stays local, is copied on grant refresh, and is never transmitted to peers.
    attention_after: Option<AttentionOpening>,
}

#[derive(Default)]
pub(super) struct PrivateSessions {
    pub(super) legacy_pending: LegacyPending,
    legacy_work: Option<LegacyWork>,
    restoring: bool,
    restore_after: Option<u64>,
    pending_active: bool,
    pending_after: Option<u64>,
    pending_through: u64,
    refresh: Option<RefreshWork>,
    invalid_noted: bool,
    pub(super) upgrading: bool,
    // Verified input from one bounded receive batch, cleared only after its effects commit.
    observed_generations: BTreeMap<Digest32, (Digest32, u64)>,
    controls_import: bool,
    controls_import_after: Option<(usize, u64, Digest32)>,
    controls_after: Option<Digest32>,
    next: u64,
    incarnation: Option<Digest32>,
    cursors: BTreeMap<Digest32, Cursor>,
    observed_tips: BTreeMap<Digest32, Cursor>,
    pulling: BTreeSet<Digest32>,
    attempted: BTreeMap<Digest32, Instant>,
    revision: u64,
    // A capability record is live traffic, not history: a member admitted after the previous
    // record cannot learn it. Set on every admission and open, and clear only after the current
    // node has appended a fresh authenticated announcement.
    support_owed: bool,
}

impl Stored {
    fn bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Encoder::new();
        e.array(7)
            .uint(2)
            .bytes(&self.record.wire())
            .bytes(&self.row.as_ref().map_or_else(Vec::new, session_cache_bytes))
            .uint(self.first_seen);
        if let Some(after) = self.attention_after {
            e.bytes(&after.after.instance)
                .uint(after.after.arrival)
                .bytes(&after.identity);
        } else {
            e.bytes(&[]).uint(0).bytes(&[]);
        }
        Zeroizing::new(e.finish())
    }

    pub(super) fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let fields = d.array()?;
        let version = d.uint()?;
        if !matches!((fields, version), (4, 1) | (7, 2)) {
            return Err(Error::MalformedAtRest("private Session state version"));
        }
        let record = Record::read(d.bytes()?)?;
        let row = match d.bytes()? {
            [] => None,
            bytes => {
                let CacheRow::Session(row) = parse_cache(bytes)? else {
                    return Err(Error::MalformedAtRest("private Session cache kind"));
                };
                Some(row)
            }
        };
        let first_seen = d.uint()?;
        let attention_after = if version == 2 {
            let instance = d.bytes()?;
            let arrival = d.uint()?;
            let identity = d.bytes()?;
            match (instance, identity) {
                ([], []) if arrival == 0 => None,
                (bytes, identity) => Some(AttentionOpening {
                    after: crate::node::api::HistoryCursor {
                        instance: bytes.try_into().map_err(|_| {
                            Error::MalformedAtRest("private Session attention instance")
                        })?,
                        arrival,
                    },
                    identity: identity.try_into().map_err(|_| {
                        Error::MalformedAtRest("private Session attention identity")
                    })?,
                }),
            }
        } else {
            None
        };
        d.finish()?;
        if row.as_ref().is_some_and(|row| {
            row.entry_hash != record.hash() || row.author != record.message.header.author_id
        }) {
            return Err(Error::MalformedAtRest("private Session cache binding"));
        }
        Ok(Self {
            record,
            row,
            first_seen,
            attention_after,
        })
    }
}

impl ChannelState {
    pub(super) fn private_contains_in(
        &self,
        batch: &crate::node::store::Batch<'_>,
        hash: &Digest32,
    ) -> Result<bool> {
        private_index::find_in(batch, &self.sek, &self.channel_id, hash).map(|id| id.is_some())
    }

    pub(super) fn private_id(&self, store: &Store, hash: &Digest32) -> Result<Option<u64>> {
        let snapshot = store.snapshot()?;
        private_index::find(&snapshot, &self.sek, &self.channel_id, hash)
    }

    pub(super) fn private_attention_after(
        &self,
        store: &Store,
        opening: &Digest32,
    ) -> Result<Option<AttentionOpening>> {
        let Some(id) = self.private_id(store, opening)? else {
            return Ok(None);
        };
        let saved = self.private_at(store, id)?.ok_or(Error::MalformedAtRest(
            "Session attention opening source missing",
        ))?;
        if saved.record.hash() != *opening || saved.record.message.header.author_id != self.me() {
            return Err(Error::MalformedAtRest("Session attention opening binding"));
        }
        Ok(saved.attention_after)
    }

    fn private_at(&self, store: &Store, id: u64) -> Result<Option<Stored>> {
        store
            .snapshot()?
            .get_segment_bounded(
                &self.channel_id,
                SegmentKind::PrivateSession,
                id,
                2 * MAX_RECORD,
            )?
            .map(|segment| self.read_private(id, &segment))
            .transpose()
    }

    pub(super) fn read_private(
        &self,
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
            &self.sek,
            SegmentKind::PrivateSession,
            id,
            segment,
        )?)
    }

    fn private_after(&self, store: &Store, after: Option<u64>) -> Result<Option<(u64, Stored)>> {
        let snapshot = store.snapshot()?;
        snapshot
            .segment_after(&self.channel_id, SegmentKind::PrivateSession, after)?
            .map(|(id, segment)| self.read_private(id, &segment).map(|saved| (id, saved)))
            .transpose()
    }

    /// A ready sealed observation is a denial boundary, never a grant. Missing evidence is
    /// meaningful only after the published feed has been inspected through its current head.
    pub(super) fn legacy_drive_generation(
        &self,
        store: &Store,
        author: &Digest32,
    ) -> Result<Option<u64>> {
        let fact = private_index::control(&store.snapshot()?, &self.sek, &self.channel_id, author)?;
        if self.private_sessions.controls_import
            || self.private_sessions.restoring
            || fact.through < self.dag.verified_head(author)
        {
            return Err(Error::StreamRefused("Session control facts are refreshing"));
        }
        Ok(fact
            .generation
            .into_iter()
            .chain(
                self.private_sessions
                    .observed_generations
                    .values()
                    .filter(|(a, _)| a == author)
                    .map(|(_, generation)| *generation)
                    .max(),
            )
            .max())
    }

    /// Called only for an authenticated input in the current bounded receive batch, before
    /// withholding can remove its payload. No uncommitted observation survives a restart.
    pub(super) fn observe_legacy_drive_generation(&mut self, entry: &Entry) -> Result<()> {
        let Some(message) = entry
            .payload
            .as_deref()
            .and_then(|p| GroupMessage::from_wire(p).ok())
        else {
            return Ok(());
        };
        let h = message.header;
        if h.channel_id != drive_channel(&self.channel_id)
            || h.author_id != entry.skeleton.author_id
            || h.epoch != entry.skeleton.epoch
        {
            return Ok(());
        }
        let hash = entry.entry_hash();
        if !self
            .private_sessions
            .observed_generations
            .contains_key(&hash)
            && self.private_sessions.observed_generations.len() >= crate::log::sync::MAX_STAGED
        {
            return Err(Error::SizeLimitExceeded(
                "Session received control observations",
            ));
        }
        self.private_sessions
            .observed_generations
            .insert(hash, (h.author_id, h.chain_id));
        Ok(())
    }

    /// Queue compact evidence with the received entries' own effects. Do not clear on failure.
    pub(super) fn queue_private_generations(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
    ) -> Result<()> {
        for (hash, (author, generation)) in &self.private_sessions.observed_generations {
            if self
                .entries
                .in_batch(batch, &self.sek, &self.channel_id)?
                .log_id(hash)?
                .is_some()
            {
                private_index::observe_control(
                    batch,
                    &self.sek,
                    &self.channel_id,
                    author,
                    private_index::Control {
                        generation: Some(*generation),
                        ..Default::default()
                    },
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn private_controls_committed(&mut self, store: &Store) -> Result<()> {
        let result = (|| {
            let read = self.entries.read(store, &self.sek, &self.channel_id)?;
            let mut after = None;
            loop {
                let next = match after {
                    Some(hash) => self
                        .private_sessions
                        .observed_generations
                        .range((std::ops::Bound::Excluded(hash), std::ops::Bound::Unbounded))
                        .next(),
                    None => self.private_sessions.observed_generations.first_key_value(),
                }
                .map(|(hash, _)| *hash);
                let Some(hash) = next else {
                    break;
                };
                if read.log_id(&hash)?.is_some() {
                    self.private_sessions.observed_generations.remove(&hash);
                }
                after = Some(hash);
            }
            Ok(())
        })();
        if let Err(error) = &result {
            self.private_save_failed(error);
        }
        result
    }

    /// Whether the legacy indexes have scanned every public position. Encrypted legacy drive
    /// generations can live in ordinary Content, so only explicit legacy recovery may satisfy
    /// this predicate when a sparse room omitted those bodies.
    fn legacy_private_controls_ready(&self, store: &Store) -> Result<bool> {
        if self.private_sessions.controls_import || self.private_sessions.restoring {
            return Ok(false);
        }
        let snapshot = store.snapshot()?;
        for author in self.authors.keys() {
            if private_index::control(&snapshot, &self.sek, &self.channel_id, author)?.through
                < self.dag.verified_head(author)
                || self
                    .floor_author(Transaction::Snapshot(&snapshot), author)?
                    .through
                    < self.dag.verified_head(author)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether the current Session control effects are complete at one author's exact head.
    /// Sparse control proofs deliberately omit ordinary/archive bodies, so their durable receipt
    /// replaces sequence contiguity only for signed Session floors and support declarations.
    pub(super) fn current_session_control_ready(
        &self,
        store: &Store,
        author: &Digest32,
    ) -> Result<bool> {
        if self.private_sessions.controls_import || self.private_sessions.restoring {
            return Ok(false);
        }
        let read = self.entries.read(store, &self.sek, &self.channel_id)?;
        let contiguous_target = if read.sparse_enabled() {
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
                None => self.dag.verified_head(author),
            }
        } else {
            self.dag.verified_head(author)
        };
        drop(read);
        // Join/import may have applied every position before sparse receipt bookkeeping runs.
        // A genuinely complete contiguous scan is equally authoritative; unlike the old sole
        // predicate, it is now an alternative and cannot make an omitted archive body necessary.
        let snapshot = store.snapshot()?;
        let control =
            private_index::control(&snapshot, &self.sek, &self.channel_id, author)?.through;
        let floor = self
            .floor_author(Transaction::Snapshot(&snapshot), author)?
            .through;
        let verified = self.dag.verified_head(author);
        let ready = verified >= contiguous_target
            && control >= contiguous_target
            && floor >= contiguous_target;
        Ok(ready)
    }

    pub(super) fn current_session_controls_ready(&self, store: &Store) -> Result<bool> {
        for author in self.authors.keys() {
            if !self.current_session_control_ready(store, author)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// One bounded catch-up turn over already published entries. A staged suffix cannot
    /// certify absence, and no snapshot is retained while the actor yields or waits.
    pub(super) fn advance_private_controls(&mut self, store: &Store) -> Result<bool> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let result = self.advance_private_controls_inner(store);
        if let Err(error) = &result {
            self.private_save_failed(error);
        }
        result
    }

    fn advance_private_controls_inner(&mut self, store: &Store) -> Result<bool> {
        if self.private_sessions.controls_import {
            return self.import_private_controls(store);
        }
        if self.private_sessions.restoring {
            return Ok(false);
        }
        let mut bytes = 0usize;
        for _ in 0..WORK_ROWS {
            let author = match self.private_sessions.controls_after {
                Some(after) => self
                    .authors
                    .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
                    .next()
                    .map(|(a, _)| *a),
                None => self.authors.keys().next().copied(),
            };
            let Some(author) = author else {
                self.private_sessions.controls_after = None;
                return self.legacy_private_controls_ready(store);
            };
            let fact =
                private_index::control(&store.snapshot()?, &self.sek, &self.channel_id, &author)?;
            let head = self.dag.verified_head(&author);
            let floor_through = self
                .floor_author(Transaction::Snapshot(&store.snapshot()?), &author)?
                .through;
            let through = fact.through.min(floor_through);
            if through >= head {
                self.private_sessions.controls_after = Some(author);
                continue;
            }
            let seq = through
                .checked_add(1)
                .ok_or(Error::MalformedAtRest("Session control frontier exhausted"))?;
            let entry = {
                let read = self.entries.read(store, &self.sek, &self.channel_id)?;
                let entry = read
                    .get(&author, seq)?
                    .ok_or(Error::MalformedAtRest("Session control entry missing"))?;
                if read.log_id(&entry.entry_hash())?.is_none() {
                    return Ok(false); // verified in memory, not durably published yet
                }
                self.entries
                    .order_view(store, &self.sek, &self.channel_id)?
                    .entry(&entry.entry_hash())?
                    .ok_or(Error::MalformedAtRest(
                        "published Session control entry missing",
                    ))?
            };
            let size = entry.payload.as_ref().map_or(0, Vec::len);
            if bytes != 0 && bytes.saturating_add(size) > WORK_BYTES {
                break;
            }
            bytes = bytes.saturating_add(size);
            let mut batch = store.batch()?;
            private_index::observe_public(
                &mut batch,
                &self.sek,
                &self.channel_id,
                &entry,
                self.epoch,
            )?;
            batch.commit()?;
            if seq == head {
                self.private_sessions.controls_after = Some(author);
            }
        }
        Ok(false)
    }

    /// Current-data transition of the old sealed author map. It is format-bounded by the
    /// existing admitted-author limit, read one row at a time, and deleted only after its
    /// final page commits. A restart safely repeats monotone observations.
    fn import_private_controls(&mut self, store: &Store) -> Result<bool> {
        let Some(segment) = store.get_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_LEGACY_DRIVE_GENERATIONS,
        )?
        else {
            self.private_sessions.controls_import = false;
            return Ok(false);
        };
        if segment.ciphertext.len() > AUTHORS_HARD_LIMIT * 48 + 128 + crate::atrest::sek::TAG_LEN {
            return Err(Error::MalformedAtRest(
                "legacy drive generation record exceeds author bound",
            ));
        }
        let bytes = open_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_LEGACY_DRIVE_GENERATIONS,
            &segment,
        )?;
        let mut header = Decoder::new(&bytes);
        if header.array()? != 2 || header.uint()? != 1 {
            return Err(Error::MalformedAtRest("legacy drive generations version"));
        }
        let count = header.array()?;
        if count > AUTHORS_HARD_LIMIT {
            return Err(Error::MalformedAtRest("legacy drive generation authors"));
        }
        let (offset, done, mut previous) = self.private_sessions.controls_import_after.unwrap_or((
            bytes.len() - header.remaining(),
            0,
            [0; 32],
        ));
        let rest = bytes
            .get(offset..)
            .ok_or(Error::MalformedAtRest("legacy drive generation cursor"))?;
        let mut d = Decoder::new(rest);
        let mut done = done;
        let mut batch = store.batch()?;
        for _ in 0..WORK_ROWS {
            if done == count as u64 {
                break;
            }
            if d.array()? != 2 {
                return Err(Error::MalformedAtRest("legacy drive generation row"));
            }
            let author: Digest32 = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedAtRest("legacy drive author"))?;
            if done != 0 && author <= previous {
                return Err(Error::MalformedAtRest(
                    "legacy drive authors not unique ordered",
                ));
            }
            if !self.authors.contains_key(&author) {
                return Err(Error::MalformedAtRest("legacy drive author unknown"));
            }
            let generation = d.uint()?;
            private_index::observe_control(
                &mut batch,
                &self.sek,
                &self.channel_id,
                &author,
                private_index::Control {
                    generation: Some(generation),
                    ..Default::default()
                },
            )?;
            previous = author;
            done += 1;
        }
        let complete = done == count as u64;
        let next_offset = bytes.len() - d.remaining();
        if complete {
            d.finish()?;
            batch.delete_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_LEGACY_DRIVE_GENERATIONS,
            )?;
        }
        batch.commit()?;
        self.private_sessions.controls_import_after =
            (!complete).then_some((next_offset, done, previous));
        self.private_sessions.controls_import = !complete;
        Ok(false)
    }

    fn legacy_current_drive(
        &self,
        transaction: Transaction<'_, '_>,
        author: &Digest32,
    ) -> Result<bool> {
        if *author == self.me() {
            return Ok(true);
        }
        if !self.authors.contains_key(author) || self.has_left(&self.me()) {
            return Ok(false);
        }
        let fact = match transaction {
            Transaction::Snapshot(snapshot) => {
                private_index::control(snapshot, &self.sek, &self.channel_id, author)?
            }
            Transaction::Batch(batch) => {
                private_index::control_in(batch, &self.sek, &self.channel_id, author)?
            }
        };
        if self.private_sessions.controls_import
            || self.private_sessions.restoring
            || fact.through < self.dag.verified_head(author)
        {
            return Err(Error::StreamRefused("Session control facts are refreshing"));
        }
        let floor = self.floor_author(transaction, author)?;
        if floor.through < self.dag.verified_head(author) {
            return Err(Error::StreamRefused(floor_index::REFRESHING));
        }
        let announced = floor.announced;
        let newest = announced
            .into_iter()
            .chain(fact.generation)
            .chain(
                self.private_sessions
                    .observed_generations
                    .values()
                    .filter(|(a, _)| a == author)
                    .map(|(_, generation)| *generation)
                    .max(),
            )
            .max();
        let Some(generation) = newest else {
            return Ok(false);
        };
        if announced == Some(generation) {
            return Ok(self
                .session_floor(transaction, &(*author, self.me(), self.epoch, generation))?
                .is_some_and(|(membership, _, _)| membership == self.admission(&self.me()).0));
        }
        Ok(self.drive.receivers.contains_key(&(*author, generation)))
    }

    /// Inspect committed rows by their stable LogDb coordinate. Publication already removed
    /// provisional work before opening; verify that the active index still owns each row.
    fn legacy_after(
        &self,
        store: &Store,
        after: Option<u64>,
        through: u64,
    ) -> Result<Option<(u64, Entry)>> {
        let snapshot = store.snapshot()?;
        let Some((id, sealed)) =
            snapshot.segment_after(&self.channel_id, SegmentKind::LogDb, after)?
        else {
            return Ok(None);
        };
        if id >= through {
            return Ok(None);
        }
        let entry = Entry::from_wire(&open_segment(&self.sek, SegmentKind::LogDb, id, &sealed)?)?;
        let view = self.entries.view(
            Transaction::Snapshot(&snapshot),
            &self.sek,
            &self.channel_id,
        )?;
        if view.log_id(&entry.entry_hash())? != Some(id) {
            return Err(Error::MalformedAtRest(
                "private migration unpublished entry",
            ));
        }
        Ok(Some((id, entry)))
    }

    /// One bounded turn. New arrivals restart generation discovery before another row can
    /// be retained: a newer signed generation can revoke permission, never silently grant it.
    pub(super) fn migrate_legacy_steps(&mut self, store: &Store, now: u64) -> Result<()> {
        if self.private_sessions.upgrading
            || self.private_sessions.restoring
            || !self.legacy_private_controls_ready(store)?
        {
            return Ok(());
        }
        let result = self.migrate_legacy_steps_inner(store, now).map(|_| ());
        if let Err(error) = &result {
            self.private_save_failed(error);
        }
        result
    }

    fn migrate_legacy_steps_inner(&mut self, store: &Store, _now: u64) -> Result<bool> {
        if !self.private_sessions.legacy_pending.is_empty() {
            self.index_session_floors(store)?;
            self.private_sessions.legacy_pending.0 = false;
            self.private_sessions.legacy_work = Some(LegacyWork {
                through: self.next_log_id,
                after: None,
                migrating: false,
            });
        }
        let Some(mut work) = self.private_sessions.legacy_work.take() else {
            return Ok(true);
        };
        let mut bytes = 0usize;
        for _ in 0..WORK_ROWS {
            let Some((id, entry)) = self.legacy_after(store, work.after, work.through)? else {
                if !work.migrating {
                    let mut batch = store.batch()?;
                    self.queue_private_generations(&mut batch)?;
                    batch.commit()?;
                    self.private_controls_committed(store)?;
                    work.migrating = true;
                    work.after = None;
                    self.private_sessions.legacy_work = Some(work);
                    return Ok(false);
                }
                self.private_sessions.pending_active = true;
                self.private_sessions.pending_after = None;
                self.private_sessions.pending_through = self.private_sessions.next;
                let mut batch = store.batch()?;
                {
                    let mut index = self
                        .entries
                        .write(&mut batch, &self.sek, &self.channel_id)?;
                    index.clear_retained_step_marker()?;
                    index.seal()?;
                }
                self.queue_private_progress(&mut batch)?;
                batch.commit()?;
                self.entries.committed();
                return Ok(true);
            };
            let size = entry.payload.as_ref().map_or(0, Vec::len);
            if bytes != 0 && bytes.saturating_add(size) > WORK_BYTES {
                break;
            }
            bytes = bytes.saturating_add(size);
            if entry
                .payload
                .as_deref()
                .is_some_and(|p| is_step_body(&self.channel_id, p))
            {
                if work.migrating {
                    if let Err(error) = self.migrate_legacy_row(store, entry) {
                        if floor_index::refreshing(&error) {
                            self.private_sessions.legacy_work = Some(work);
                            return Ok(false);
                        }
                        return Err(error);
                    }
                } else if let Ok(record) = Record::legacy(entry) {
                    let author = record.message.header.author_id;
                    if self
                        .authors
                        .get(&author)
                        .is_some_and(|key| record.verify(&self.channel_id, key).is_ok())
                    {
                        let mut batch = store.batch()?;
                        private_index::observe_control(
                            &mut batch,
                            &self.sek,
                            &self.channel_id,
                            &author,
                            private_index::Control {
                                generation: Some(record.message.header.chain_id),
                                ..Default::default()
                            },
                        )?;
                        batch.commit()?;
                    }
                }
            }
            work.after = Some(id);
        }
        self.private_sessions.legacy_work = Some(work);
        Ok(false)
    }

    /// Wire, exact cached row, retention retirement and public-body pruning commit together.
    /// One legal large entry is processed alone; no transaction grows with retained history.
    fn migrate_legacy_row(&mut self, store: &Store, entry: Entry) -> Result<()> {
        let hash = entry.entry_hash();
        let tracked_before = self
            .retention_get(store, &hash)?
            .ok_or(Error::MalformedAtRest("legacy step retention missing"))?;
        let permitted =
            if tracked_before.cache_id.is_some() || entry.skeleton.author_id == self.me() {
                true
            } else if let Ok(record) = Record::legacy(entry.clone()) {
                self.private_permitted(store, &record, &self.me())?
            } else {
                false
            };
        let mut batch = store.batch()?;
        let Some(tracked) = self.retention_get_in(Transaction::Batch(&batch), &hash)? else {
            return Err(Error::MalformedAtRest("legacy step retention missing"));
        };
        let cached = match tracked.cache_id {
            Some(id) => {
                let sealed = batch
                    .get_segment(&self.channel_id, SegmentKind::PlaintextCache, id)?
                    .ok_or(Error::MalformedAtRest("legacy Session cache missing"))?;
                let CacheRow::Session(row) = parse_cache(&open_segment(
                    &self.sek,
                    SegmentKind::PlaintextCache,
                    id,
                    &sealed,
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
        private_index::observe_public(&mut batch, &self.sek, &self.channel_id, &entry, self.epoch)?;
        let current_drive = self.legacy_current_drive(Transaction::Batch(&batch), &author)?;
        let generation =
            private_index::control_in(&batch, &self.sek, &self.channel_id, &author)?.generation;
        let record = Record::legacy(entry).ok().filter(|r| {
            self.authors
                .get(&author)
                .is_some_and(|key| r.verify(&self.channel_id, key).is_ok())
        });
        let mut next = self.private_sessions.next.max(1);
        let no_announced_floor = self
            .floor_author(Transaction::Batch(&batch), &author)?
            .announced
            .is_none();
        if !self.private_contains_in(&batch, &hash)? {
            if let Some(record) = record.filter(|r| {
                current_drive
                    && (cached.is_some()
                        || permitted
                        || author == self.me()
                        || (no_announced_floor
                            && generation == Some(r.message.header.chain_id)
                            && self
                                .drive
                                .receivers
                                .get(&(author, r.message.header.chain_id))
                                .is_some_and(|chain| {
                                    chain.can_open_iteration(r.message.header.iteration)
                                })))
            }) {
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
                let segment =
                    seal_segment(&self.sek, SegmentKind::PrivateSession, id, &saved.bytes())?;
                batch.put_segment(&self.channel_id, SegmentKind::PrivateSession, id, &segment)?;
                private_index::put(&mut batch, &self.sek, &self.channel_id, id, &saved)?;
            }
        }
        {
            let mut index = self
                .entries
                .write(&mut batch, &self.sek, &self.channel_id)?;
            index.committing(self.next_log_id);
            self.dag.prune_payload(&mut index, &hash)?;
            index.set_retention(hash, None)?;
            index.seal()?;
        }
        let age = seal_segment(
            &self.sek,
            SegmentKind::Index,
            tracked.log_id,
            &first_seen_bytes(tracked.first_seen_ms, true),
        )?;
        batch.put_segment(&self.channel_id, SegmentKind::Index, tracked.log_id, &age)?;
        if let Some(cache) = tracked.cache_id {
            batch.delete_segment(&self.channel_id, SegmentKind::PlaintextCache, cache)?;
        }
        batch.commit()?;
        self.private_sessions.next = next;
        self.entries.committed();
        Ok(())
    }

    /// A key arrival schedules a bounded pass; it cannot synchronously scan every retained
    /// record while holding the room. Already readable rows are never reopened or discarded.
    pub(super) fn render_pending_private(&mut self, store: &Store, now: u64) -> Result<()> {
        self.private_sessions.pending_active = true;
        self.private_sessions.pending_after = None;
        self.private_sessions.pending_through = self.private_sessions.next;
        self.save_private_progress(store)?;
        if self.private_policy_ready(store, now)?
            && !self.private_sessions.upgrading
            && !self.private_sessions.restoring
            && self.private_sessions.legacy_work.is_none()
            && self.private_sessions.legacy_pending.is_empty()
            && self.current_session_controls_ready(store)?
        {
            let result = self.advance_pending_private(store, now).map(|_| ());
            if let Err(error) = &result {
                self.private_save_failed(error);
            }
            result
        } else {
            Ok(())
        }
    }

    fn advance_pending_private(&mut self, store: &Store, now: u64) -> Result<bool> {
        if !self.private_sessions.pending_active {
            return Ok(true);
        }
        if !self.private_policy_ready(store, now)? {
            return Ok(false);
        }
        let mut bytes = 0usize;
        for _ in 0..WORK_ROWS {
            let next = private_index::unread_after(
                &store.snapshot()?,
                &self.sek,
                &self.channel_id,
                self.private_sessions.pending_after,
            )?;
            let Some(id) = next.filter(|id| *id < self.private_sessions.pending_through) else {
                self.private_sessions.pending_active = false;
                self.private_sessions.pending_after = None;
                self.save_private_progress(store)?;
                return Ok(true);
            };
            let saved = self
                .private_at(store, id)?
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
                if let Err(error) = self.take_private_record(store, &saved.record.wire(), now, None)
                {
                    // A policy replay is not a verdict on the saved wire. Keep both the
                    // record and the last completed cursor so the same row can be retried.
                    if super::governance::refreshing(&error)
                        || floor_index::refreshing(&error)
                        || matches!(&error, Error::StreamRefused(reason) if *reason == CONTROL_REFRESHING)
                    {
                        return Ok(false);
                    }
                    if self.poisoned {
                        return Err(error);
                    }
                    // Only an unread invalid wire is discarded. Storage failures propagate
                    // through the caller's poison guard and cannot masquerade as absence.
                    if let Some(current) = self.private_at(store, id)? {
                        if current.row.is_none() {
                            let mut batch = store.batch()?;
                            batch.delete_segment(
                                &self.channel_id,
                                SegmentKind::PrivateSession,
                                id,
                            )?;
                            private_index::remove(
                                &mut batch,
                                &self.sek,
                                &self.channel_id,
                                id,
                                &current,
                            )?;
                            batch.commit()?;
                            if !self.private_sessions.invalid_noted {
                                self.set_aside.push(format!(
                                    "invalid unread private Session {}: {error}; further refusals are logged",
                                    crate::node::link::b32_encode(&current.record.hash())
                                ));
                                self.private_sessions.invalid_noted = true;
                            }
                            tracing::warn!(room = ?self.channel_id, hash = ?current.record.hash(), %error,
                                "discarded invalid unread legacy Session");
                        }
                    }
                }
            }
            self.private_sessions.pending_after = Some(id);
        }
        self.save_private_progress(store)?;
        Ok(false)
    }

    pub(crate) fn needs_session_upgrade(&self) -> bool {
        self.private_sessions.upgrading
            || self.private_sessions.restoring
            || self.private_sessions.controls_import
            || !self.private_sessions.legacy_pending.is_empty()
            || self.private_sessions.legacy_work.is_some()
            || self.private_sessions.pending_active
    }

    /// The actor yields between false results and keeps the room unpublished. Key packages
    /// have already been attempted when the initial gate is lifted.
    pub(crate) fn finish_session_upgrade(&mut self, store: &Store, now: u64) -> Result<bool> {
        self.private_sessions.upgrading = false;
        self.advance_private_sessions(store, now)
    }

    // An incomplete governance projection must neither expire saved Session bodies nor
    // release them using a policy sampled before the current canonical room history.
    fn private_policy_ready(&self, store: &Store, now: u64) -> Result<bool> {
        match self.require_governance_ready(store, crate::time::Ms(now)) {
            Ok(()) => Ok(true),
            Err(error)
                if super::governance::refreshing(&error) || floor_index::refreshing(&error) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    /// Also driven by ordinary maintenance, before Session projection or grant release.
    pub(crate) fn advance_private_sessions(&mut self, store: &Store, now: u64) -> Result<bool> {
        if !self.private_policy_ready(store, now)? {
            return Ok(false);
        }
        if self.poisoned {
            return Err(self.save_failure());
        }
        if self.private_sessions.upgrading {
            return Ok(false);
        }
        let result = (|| {
            if self.private_sessions.restoring {
                return self.restore_private_chunk(store);
            }
            if !self.current_session_controls_ready(store)? {
                // Old sealed author maps and an actually contiguous legacy/current feed still
                // need their bounded importer. Once that scan is complete it is not repeated;
                // a sparse head beyond the contiguous frontier remains pending on its exact
                // control receipt instead of spinning this legacy reader.
                if !self.legacy_private_controls_ready(store)? {
                    self.advance_private_controls(store)?;
                }
                return Ok(false);
            }
            if self.private_sessions.legacy_work.is_some()
                || !self.private_sessions.legacy_pending.is_empty()
            {
                if !self.legacy_private_controls_ready(store)? {
                    self.advance_private_controls(store)?;
                    return Ok(false);
                }
                self.migrate_legacy_steps_inner(store, now)?;
                return Ok(false);
            }
            if !self.advance_pending_private(store, now)? {
                return Ok(false);
            }
            self.sweep_private_sessions(store, now)?;
            self.private_expiry_ready(store, now)
        })();
        if let Err(error) = &result {
            self.private_save_failed(error);
        }
        result.map(|complete| complete && !self.needs_session_upgrade())
    }

    pub(super) fn supports_private(&mut self, store: &Store, peer: &Digest32) -> Result<bool> {
        if !self.current_session_control_ready(store, peer)? {
            return Err(Error::StreamRefused(CONTROL_REFRESHING));
        }
        Ok(
            private_index::control(&store.snapshot()?, &self.sek, &self.channel_id, peer)?
                .support
                .is_some(),
        )
    }

    /// Authenticated capability, not a Session step. Published old readers skip its unknown
    /// content body. Only an author who advertised support is ever probed with stream 13.
    pub(crate) fn announce_private_support(&mut self, profile: &Profile, now: u64) -> Result<()> {
        let me = self.me();
        if !self.settled || self.poisoned || self.has_left(&me) {
            return Ok(());
        }
        if !self.private_sessions.support_owed && self.supports_private(profile.store(), &me)? {
            return Ok(());
        }
        self.append_control_kind(
            profile,
            &support_body(&self.channel_id, &me),
            now,
            EntryKind::Content,
            false,
        )?;
        self.private_sessions.support_owed = false;
        Ok(())
    }
    pub(super) fn restore_private_sessions(&mut self, store: &Store) -> Result<()> {
        let snapshot = store.snapshot()?;
        let state = private_index::restart(&snapshot, &self.sek, &self.channel_id)?;
        self.private_sessions.controls_import = snapshot
            .get_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_LEGACY_DRIVE_GENERATIONS,
            )?
            .is_some();
        self.private_sessions.controls_import_after = None;
        self.private_sessions.controls_after = None;
        self.private_sessions.restoring = !state.complete;
        self.private_sessions.restore_after = state.after;
        self.private_sessions.next = state.next;
        self.private_sessions.pending_active = state.pending;
        self.private_sessions.pending_after = state.pending_after;
        self.private_sessions.pending_through = state.pending_through;
        // A restart may follow an admission that committed just before its capability
        // announcement. Repeating this one small signed fact is bounded to one per open.
        self.private_sessions.support_owed = true;
        self.restore_private_pulls(store)?;
        Ok(())
    }

    pub(crate) fn owe_private_support(&mut self) {
        self.private_sessions.support_owed = true;
    }

    // Cursor scope follows held grant generations, not ratchet iterations. A grant saved
    // immediately before a crash invalidates the old cursor even if its reset was not saved.
    fn private_pull_binding(&self) -> Digest32 {
        let mut e = Encoder::new();
        e.array(3)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .array(self.drive.receivers.len());
        for (author, generation) in self.drive.receivers.keys() {
            e.array(2).bytes(author).uint(*generation);
        }
        crate::hash::sha256(&e.finish())
    }

    fn restore_private_pulls(&mut self, store: &Store) -> Result<()> {
        let Some(segment) = store.get_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_PRIVATE_PULLS,
        )?
        else {
            return Ok(());
        };
        if segment.ciphertext.len() > AUTHORS_HARD_LIMIT * 96 + 256 {
            return Err(Error::MalformedAtRest("private pull cursor bound"));
        }
        let bytes = open_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_PRIVATE_PULLS,
            &segment,
        )?;
        let mut d = Decoder::new(&bytes);
        if d.array()? != 4 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest("private pull cursor version"));
        }
        self.private_sessions.incarnation = match d.bytes()? {
            [] => None,
            b => Some(
                b.try_into()
                    .map_err(|_| Error::MalformedAtRest("private stream incarnation"))?,
            ),
        };
        let binding: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("private pull grant binding"))?;
        let count = d.array()?;
        if count > AUTHORS_HARD_LIMIT {
            return Err(Error::MalformedAtRest("private pull peer bound"));
        }
        let mut cursors = BTreeMap::new();
        for _ in 0..count {
            if d.array()? != 3 {
                return Err(Error::MalformedAtRest("private pull peer cursor"));
            }
            let peer = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedAtRest("private pull peer"))?;
            let incarnation = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedAtRest("private pull incarnation"))?;
            let after = d.uint()?;
            if cursors
                .insert(peer, Cursor { incarnation, after })
                .is_some()
            {
                return Err(Error::MalformedAtRest("duplicate private pull peer"));
            }
        }
        d.finish()?;
        if binding == self.private_pull_binding() {
            self.private_sessions.cursors = cursors;
        }
        Ok(())
    }

    fn save_private_pulls(&self, store: &Store) -> Result<()> {
        self.save_private_pull_candidate(store, &self.private_sessions.cursors, None)
    }

    fn save_private_pull_candidate(
        &self,
        store: &Store,
        cursors: &BTreeMap<Digest32, Cursor>,
        authority: Option<TrustNonce>,
    ) -> Result<()> {
        if cursors.len() > AUTHORS_HARD_LIMIT {
            return Err(Error::MalformedAtRest("private pull peer bound"));
        }
        let mut e = Encoder::new();
        e.array(4)
            .uint(1)
            .bytes(
                self.private_sessions
                    .incarnation
                    .as_ref()
                    .map_or(&[][..], |v| &v[..]),
            )
            .bytes(&self.private_pull_binding())
            .array(cursors.len());
        for (peer, cursor) in cursors {
            e.array(3)
                .bytes(peer)
                .bytes(&cursor.incarnation)
                .uint(cursor.after);
        }
        let segment = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_PRIVATE_PULLS,
            &e.finish(),
        )?;
        let mut batch = store.batch()?;
        if let Some(expected) = authority {
            if batch.get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(
                crate::node::trust::TRUST_META_KEY,
            )? != expected
            {
                return Err(Error::StreamRefused(TRUST_CHANGED));
            }
        }
        batch.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_PRIVATE_PULLS,
            &segment,
        )?;
        batch.commit()
    }

    fn queue_private_progress(&self, batch: &mut crate::node::store::Batch<'_>) -> Result<()> {
        private_index::Restart {
            complete: !self.private_sessions.restoring,
            after: self.private_sessions.restore_after,
            next: self.private_sessions.next.max(1),
            pending: self.private_sessions.pending_active,
            pending_after: self.private_sessions.pending_after,
            pending_through: self.private_sessions.pending_through,
        }
        .queue(batch, &self.sek, &self.channel_id)
    }

    fn save_private_progress(&self, store: &Store) -> Result<()> {
        let mut batch = store.batch()?;
        self.queue_private_progress(&mut batch)?;
        batch.commit()
    }

    fn restore_private_chunk(&mut self, store: &Store) -> Result<bool> {
        let mut bytes = 0usize;
        for _ in 0..WORK_ROWS {
            let Some((id, saved)) =
                self.private_after(store, self.private_sessions.restore_after)?
            else {
                self.private_sessions.restoring = false;
                self.private_sessions.pending_active = true;
                self.private_sessions.pending_after = None;
                self.private_sessions.pending_through = self.private_sessions.next;
                self.save_private_progress(store)?;
                return Ok(false);
            };
            let size = saved.record.message.ciphertext.len();
            if bytes != 0 && bytes.saturating_add(size) > WORK_BYTES {
                break;
            }
            bytes = bytes.saturating_add(size);
            let key = self
                .authors
                .get(&saved.record.message.header.author_id)
                .ok_or(Error::MalformedAtRest("private Session author missing"))?;
            saved.record.verify(&self.channel_id, key)?;
            let next = id
                .checked_add(1)
                .ok_or(Error::MalformedAtRest("private Session id exhausted"))?;
            let mut batch = store.batch()?;
            private_index::put(&mut batch, &self.sek, &self.channel_id, id, &saved)?;
            self.private_sessions.next = self.private_sessions.next.max(next);
            self.private_sessions.restore_after = Some(id);
            if saved.row.is_none() {
                self.private_sessions.pending_active = true;
                self.private_sessions.pending_after = None;
                self.private_sessions.pending_through = self.private_sessions.next;
            }
            self.queue_private_progress(&mut batch)?;
            batch.commit()?;
        }
        Ok(false)
    }

    pub(super) fn sweep_private_sessions(&mut self, store: &Store, now: u64) -> Result<usize> {
        if !self.private_policy_ready(store, now)? {
            return Ok(0);
        }
        if self.poisoned {
            return Ok(0);
        }
        let result = self.sweep_private_sessions_inner(store, now);
        if let Err(error) = &result {
            self.private_save_failed(error);
        }
        result
    }

    fn sweep_private_sessions_inner(&mut self, store: &Store, now: u64) -> Result<usize> {
        let mut count = 0usize;
        let mut bytes = 0usize;
        // One bounded page per maintenance turn; expiration is also checked at query time.
        for _ in 0..WORK_ROWS {
            let Some(id) = private_index::next_expired(
                &store.snapshot()?,
                &self.sek,
                &self.channel_id,
                now,
                self.effective_retention(),
                self.effective_step_retention(),
            )?
            else {
                break;
            };
            let saved = self
                .private_at(store, id)?
                .ok_or(Error::MalformedAtRest("Session expiry locator missing"))?;
            let size = saved.record.message.ciphertext.len();
            if bytes != 0 && bytes.saturating_add(size) > WORK_BYTES {
                break;
            }
            bytes = bytes.saturating_add(size);
            if !self.private_expired(&saved, now) {
                return Err(Error::MalformedAtRest("Session expiry fact differs"));
            }
            let result = (|| {
                let mut batch = store.batch()?;
                batch.delete_segment(&self.channel_id, SegmentKind::PrivateSession, id)?;
                private_index::remove(&mut batch, &self.sek, &self.channel_id, id, &saved)?;
                batch.commit()
            })();
            if let Err(error) = result {
                self.private_save_failed(&error);
                return Err(error);
            }
            count = count.saturating_add(1);
        }
        Ok(count)
    }

    pub(super) fn private_expiry_ready(&self, store: &Store, now: u64) -> Result<bool> {
        if !self.private_policy_ready(store, now)? {
            return Ok(false);
        }
        if self.needs_session_upgrade() {
            return Ok(false);
        }
        Ok(private_index::next_expired(
            &store.snapshot()?,
            &self.sek,
            &self.channel_id,
            now,
            self.effective_retention(),
            self.effective_step_retention(),
        )?
        .is_none())
    }

    pub(super) fn private_expired(&self, saved: &Stored, now: u64) -> bool {
        let ttl = if saved
            .row
            .as_ref()
            .is_some_and(|row| crate::node::sessions::is_record(&row.body))
        {
            self.effective_retention()
        } else {
            self.effective_step_retention()
        };
        let claimed = saved
            .row
            .as_ref()
            .map(|row| row.created_millis)
            .or_else(|| saved.record.legacy_claimed_ms())
            .unwrap_or(saved.first_seen);
        ttl != 0 && saved.first_seen.min(claimed) <= now.saturating_sub(ttl.saturating_mul(1000))
    }

    fn private_save_failed(&mut self, error: &Error) {
        if super::governance::refreshing(error) || floor_index::refreshing(error) {
            return;
        }
        self.poisoned = true;
        self.save_error = Some(error.to_string());
    }

    fn keep_private(
        &mut self,
        store: &Store,
        saved: Stored,
        completion: Option<&crate::node::session_ingress::Completion>,
    ) -> Result<Digest32> {
        self.keep_private_candidate(store, saved, completion, None, None)
    }

    fn keep_private_candidate(
        &mut self,
        store: &Store,
        saved: Stored,
        completion: Option<&crate::node::session_ingress::Completion>,
        candidate: Option<((Digest32, u64), &ReceiverChain)>,
        authority: Option<TrustNonce>,
    ) -> Result<Digest32> {
        let hash = saved.record.hash();
        let id = self
            .private_id(store, &hash)?
            .unwrap_or(self.private_sessions.next.max(1));
        let Some(next) = id.checked_add(1) else {
            let error = Error::SizeLimitExceeded("private Session records");
            self.private_save_failed(&error);
            return Err(error);
        };
        let result = (|| {
            let segment = seal_segment(&self.sek, SegmentKind::PrivateSession, id, &saved.bytes())?;
            let mut batch = store.batch()?;
            if let Some(expected) = authority {
                if batch.get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(
                    crate::node::trust::TRUST_META_KEY,
                )? != expected
                {
                    return Err(Error::StreamRefused(TRUST_CHANGED));
                }
            }
            if let Some(old) =
                batch.get_segment(&self.channel_id, SegmentKind::PrivateSession, id)?
            {
                let old = self.read_private(id, &old)?;
                private_index::remove(&mut batch, &self.sek, &self.channel_id, id, &old)?;
            }
            batch.put_segment(&self.channel_id, SegmentKind::PrivateSession, id, &segment)?;
            let drive = seal_segment(
                &self.sek,
                SegmentKind::KeyMaterial,
                SEG_DRIVE,
                &self.drive.state_with_receiver(candidate),
            )?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_DRIVE,
                &drive,
            )?;
            private_index::put(&mut batch, &self.sek, &self.channel_id, id, &saved)?;
            if let Some(completion) = completion {
                completion.queue(&mut batch)?;
            }
            batch.commit()
        })();
        if let Err(e) = result {
            if !matches!(&e, Error::StreamRefused(reason) if *reason == TRUST_CHANGED) {
                self.private_save_failed(&e);
            }
            return Err(e);
        }
        if let Some(row) = &saved.row {
            if !crate::node::drive::is_key_changed(&row.session_id) {
                self.drive.news.push(row.session_id.clone());
            }
        }
        self.private_sessions.next = self.private_sessions.next.max(next);
        self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(hash)
    }

    /// Copy lifecycle source records into a new grant, without assembling whole metadata or
    /// backfilling activity. False is pending work: callers must not release that grant yet.
    pub(crate) fn refresh_session_records(
        &mut self,
        profile: &Profile,
        holders: &BTreeSet<Digest32>,
        owed: &[Digest32],
        now: u64,
    ) -> Result<bool> {
        if !self.private_policy_ready(profile.store(), now)? {
            return Ok(false);
        }
        if self.poisoned {
            return Err(self.save_failure());
        }
        if self.needs_session_upgrade() {
            return Ok(false);
        }
        if self.has_left(&self.me()) || self.ended(now).is_some() {
            return Ok(true);
        }
        let result = self.refresh_session_records_inner(profile, holders, owed, now);
        if let Err(error) = &result {
            self.private_save_failed(error);
        }
        result
    }

    fn refresh_grant(
        &self,
        store: &Store,
        holders: &BTreeSet<Digest32>,
        owed: &[Digest32],
    ) -> Result<Digest32> {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"vox/private-session-refresh-grant/v1");
        hash.update(self.epoch.to_be_bytes());
        hash.update(
            self.drive
                .chain
                .as_ref()
                .map_or(0, |c| c.chain_id())
                .to_be_bytes(),
        );
        hash.update((holders.len() as u64).to_be_bytes());
        for peer in holders {
            hash.update(peer);
        }
        hash.update((owed.len() as u64).to_be_bytes());
        for peer in owed {
            hash.update(peer);
            hash.update(self.admission(peer).0.to_be_bytes());
        }
        // Any signed floor change by this author invalidates the previous scan, including
        // a late change to an old generation. Current-recipient membership is hashed above.
        hash.update(
            self.floor_author(Transaction::Snapshot(&store.snapshot()?), &self.me())?
                .revision
                .to_be_bytes(),
        );
        Ok(hash.finalize().into())
    }

    fn refresh_session_records_inner(
        &mut self,
        profile: &Profile,
        holders: &BTreeSet<Digest32>,
        owed: &[Digest32],
        now: u64,
    ) -> Result<bool> {
        self.rotate_drive_if_lost(profile.store(), holders, crate::time::Ms(now))?;
        let grant = self.refresh_grant(profile.store(), holders, owed)?;
        let public = self
            .entries
            .render_view(profile.store(), &self.sek, &self.channel_id)?
            .session_revision();
        let private = private_index::lifecycle_revision(
            &profile.store().snapshot()?,
            &self.sek,
            &self.channel_id,
        )?;
        let reset = self.private_sessions.refresh.as_ref().is_none_or(|work| {
            work.grant != grant || work.public != public || work.private != private
        });
        if reset {
            self.private_sessions.refresh = Some(RefreshWork {
                grant,
                public,
                private,
                through: self.private_sessions.next,
                public_after: None,
                private_after: None,
                stage: 0,
            });
        }
        let mut work = self
            .private_sessions
            .refresh
            .take()
            .ok_or(Error::MalformedAtRest("Session refresh cursor missing"))?;
        let mut bytes = 0usize;
        let progress = (|| -> Result<()> {
            for _ in 0..WORK_ROWS {
                if work.stage == 0 {
                    let next = {
                        let view = self.entries.render_view(
                            profile.store(),
                            &self.sek,
                            &self.channel_id,
                        )?;
                        view.session_candidate(work.public_after)?
                            .map(|(key, _)| {
                                let row = view.row(&key.2)?.ok_or(Error::MalformedAtRest(
                                    "Session refresh candidate missing",
                                ))?;
                                Ok::<_, Error>((key, row))
                            })
                            .transpose()?
                    };
                    let Some((key, row)) = next else {
                        work.stage = 1;
                        continue;
                    };
                    if bytes != 0 && bytes.saturating_add(row.text.len()) > WORK_BYTES {
                        break;
                    }
                    bytes = bytes.saturating_add(row.text.len());
                    if row.author == self.me() && crate::node::sessions::is_record(&row.text) {
                        let tracked = self
                            .retention_get(profile.store(), &row.entry_hash)?
                            .ok_or(Error::MalformedAtRest("Session refresh retention missing"))?;
                        let ttl = self.effective_retention();
                        if ttl == 0
                            || tracked.first_seen_ms.min(row.created_millis)
                                > now.saturating_sub(ttl.saturating_mul(1000))
                        {
                            let env = vox_agentcomms::envelope::Envelope::parse(&row.text)
                                .map_err(|_| {
                                    Error::MalformedAtRest("classified Session envelope changed")
                                })?;
                            let session = if env.from.is_empty() {
                                env.data["session_parts"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .to_owned()
                            } else {
                                env.from
                            };
                            self.refresh_one_session_record(
                                profile,
                                holders,
                                owed,
                                row.created_millis,
                                &session,
                                &row.text,
                                row.entry_hash,
                                now,
                            )?;
                        }
                    }
                    work.public_after = Some(key);
                } else if work.stage == 1 {
                    let next = private_index::candidate_after(
                        &profile.store().snapshot()?,
                        &self.sek,
                        &self.channel_id,
                        work.private_after,
                    )?;
                    let Some((key, id)) = next else {
                        work.stage = 2;
                        break;
                    };
                    if id < work.through {
                        let saved =
                            self.private_at(profile.store(), id)?
                                .ok_or(Error::MalformedAtRest(
                                    "Session refresh private source missing",
                                ))?;
                        let size = saved.record.message.ciphertext.len();
                        if bytes != 0 && bytes.saturating_add(size) > WORK_BYTES {
                            break;
                        }
                        bytes = bytes.saturating_add(size);
                        if !self.private_expired(&saved, now) {
                            if let Some(row) = saved.row.filter(|r| {
                                r.author == self.me() && crate::node::sessions::is_record(&r.body)
                            }) {
                                self.refresh_one_session_record(
                                    profile,
                                    holders,
                                    owed,
                                    row.created_millis,
                                    &row.session_id,
                                    &row.body,
                                    row.entry_hash,
                                    now,
                                )?;
                            }
                        }
                    }
                    work.private_after = Some(key);
                } else {
                    break;
                }
            }
            Ok(())
        })();
        if progress.as_ref().is_err_and(floor_index::refreshing) {
            self.private_sessions.refresh = Some(work);
            return Ok(false);
        }
        progress?;
        // Our own refresh copies change this generation; they do not invalidate their
        // source cursor. A later independent lifecycle write does restart it next turn.
        work.private = private_index::lifecycle_revision(
            &profile.store().snapshot()?,
            &self.sek,
            &self.channel_id,
        )?;
        let complete =
            work.stage == 2 && work.grant == self.refresh_grant(profile.store(), holders, owed)?;
        self.private_sessions.refresh = Some(work);
        Ok(complete)
    }

    #[allow(clippy::too_many_arguments)]
    fn refresh_one_session_record(
        &mut self,
        profile: &Profile,
        holders: &BTreeSet<Digest32>,
        owed: &[Digest32],
        created: u64,
        session: &str,
        body: &str,
        source: Digest32,
        now: u64,
    ) -> Result<()> {
        let matched = private_index::matching_lifecycle(
            &profile.store().snapshot()?,
            &self.sek,
            &self.channel_id,
            &self.me(),
            created,
            body,
        )?;
        let mut attention_after = None;
        let mut identity = source;
        if let Some(id) = matched {
            let saved = self
                .private_at(profile.store(), id)?
                .ok_or(Error::MalformedAtRest("Session refresh locator missing"))?;
            if !saved.row.as_ref().is_some_and(|row| {
                row.author == self.me() && row.created_millis == created && row.body == body
            }) {
                return Err(Error::MalformedAtRest("Session refresh locator binding"));
            }
            attention_after = saved.attention_after;
            identity = saved.record.hash();
            if !self.private_expired(&saved, now) {
                let mut all = true;
                for peer in owed {
                    if !self.private_permitted(profile.store(), &saved.record, peer)? {
                        all = false;
                        break;
                    }
                }
                if all {
                    return Ok(());
                }
            }
        }
        let attention_after = match attention_after {
            Some(boundary) => boundary,
            None => AttentionOpening {
                after: crate::node::api::HistoryCursor {
                    instance: self.history_instance(profile.store())?,
                    arrival: self.last_arrival(profile.store())?.unwrap_or(0),
                },
                identity,
            },
        };
        let content = crate::node::content::SessionEntry::new(created, session, body)?;
        self.append_private_content(profile, content, holders, now, None, Some(attention_after))?;
        Ok(())
    }

    /// A newly written record does not advance any public feed or refer to its heads.
    pub(super) fn append_private_session(
        &mut self,
        profile: &Profile,
        session_id: &str,
        body: &str,
        holders: &BTreeSet<Digest32>,
        now: u64,
    ) -> Result<Digest32> {
        let content = crate::node::content::SessionEntry::new(now, session_id, body)?;
        self.append_private_content(profile, content, holders, now, None, None)
    }

    pub(crate) fn append_ingress_session(
        &mut self,
        profile: &Profile,
        session_id: &str,
        body: &str,
        holders: &BTreeSet<Digest32>,
        now: u64,
        completion: &crate::node::session_ingress::Completion,
    ) -> Result<Digest32> {
        let content = crate::node::content::SessionEntry::new(now, session_id, body)?;
        self.append_private_content(profile, content, holders, now, Some(completion), None)
    }

    fn append_private_content(
        &mut self,
        profile: &Profile,
        content: crate::node::content::SessionEntry,
        holders: &BTreeSet<Digest32>,
        now: u64,
        completion: Option<&crate::node::session_ingress::Completion>,
        attention_after: Option<AttentionOpening>,
    ) -> Result<Digest32> {
        self.require_governance_ready(profile.store(), crate::time::Ms(now))?;
        if self.poisoned {
            return Err(Error::Profile("room save failed; reopen it"));
        }
        if !self.settled {
            return Err(Error::RoomNotSynced);
        }
        if !self.authors.contains_key(&self.me()) {
            return Err(Error::Profile("this identity is not an author of the room"));
        }
        if self.has_left(&self.me()) || self.ended(now).is_some() {
            return Err(Error::Profile("this room has ended or was left"));
        }
        if self
            .drive
            .chain
            .as_ref()
            .is_none_or(|c| c.epoch() != self.epoch || c.should_rotate(now))
        {
            self.begin_drive(profile.store(), holders, now)?;
        }
        self.ensure_session_floors(profile, holders, now)?;
        let new_boundary =
            if attention_after.is_none() && crate::node::sessions::is_record(&content.body) {
                Some(crate::node::api::HistoryCursor {
                    instance: self.history_instance(profile.store())?,
                    arrival: self.last_arrival(profile.store())?.unwrap_or(0),
                })
            } else {
                None
            };
        // The actor cannot accept another public arrival between this sample and keep_private's
        // Batch commit. Multipart openings use their first part's source and boundary.
        // Every failure after encrypting poisons the in-memory chain. Nothing may reuse its
        // iteration when either the record or its advanced state failed to commit.
        let result = (|| {
            let message = self
                .drive
                .chain
                .as_mut()
                .ok_or(Error::Profile("drive key missing"))?
                .encrypt(&Zeroizing::new(content.to_canonical_vec()))?;
            let record = Record::new(profile.signer()?, self.channel_id, message)?;
            let attention_after = attention_after.or_else(|| {
                new_boundary.map(|after| AttentionOpening {
                    after,
                    identity: record.hash(),
                })
            });
            let row = SessionRow {
                entry_hash: record.hash(),
                author: self.me(),
                created_millis: content.created_millis,
                session_id: content.session_id,
                body: content.body,
            };
            self.keep_private(
                profile.store(),
                Stored {
                    record,
                    row: Some(row),
                    first_seen: now,
                    attention_after,
                },
                completion,
            )
        })();
        if let Err(e) = &result {
            self.private_save_failed(e);
        }
        if result.is_ok() {
            self.drive.change_unsaid = Some(false);
        }
        result
    }

    /// A current grant and an uninterrupted grant from the step's generation are both needed.
    /// A revoked-and-regranted peer cannot use its retained old key to backfill a former grant.
    fn private_permitted(
        &self,
        store: &Store,
        record: &Record,
        recipient: &Digest32,
    ) -> Result<bool> {
        let h = &record.message.header;
        if !self.settled || self.has_left(recipient) || !self.authors.contains_key(recipient) {
            return Ok(false);
        }
        if h.author_id == *recipient {
            return Ok(true);
        }
        let membership = self.admission(recipient).0;
        {
            let snapshot = store.snapshot()?;
            let transaction = Transaction::Snapshot(&snapshot);
            if !self.current_session_control_ready(store, &h.author_id)? {
                return Err(Error::StreamRefused(floor_index::REFRESHING));
            }
            let Some((m, iteration, _)) =
                self.session_floor(transaction, &(h.author_id, *recipient, h.epoch, h.chain_id))?
            else {
                return Ok(false);
            };
            if m != membership || h.iteration < iteration {
                return Ok(false);
            }
        }
        let range = floor_index::continuity_step(
            store,
            &self.sek,
            &self.channel_id,
            &h.author_id,
            recipient,
            membership,
        )?
        .ok_or(Error::StreamRefused(floor_index::REFRESHING))?;
        Ok(range.is_some_and(|(lower, upper)| {
            lower <= (h.epoch, h.chain_id) && (h.epoch, h.chain_id) <= upper
        }))
    }

    pub(crate) fn private_page(
        &mut self,
        store: &Store,
        ask: &Ask,
        peer: &Digest32,
        holders: &BTreeSet<Digest32>,
        charge: crate::node::history_budget::BufferCharge,
    ) -> Result<Page> {
        self.require_governance_ready(store, crate::time::Ms(self.now_hint))?;
        if self.poisoned
            || self.needs_session_upgrade()
            || ask.room != self.channel_id
            || ask.epoch != self.epoch
            || !self.drive_members().contains(peer)
        {
            return Err(Error::StreamRefused("private Session room unavailable"));
        }
        self.index_session_floors(store)?;
        let incarnation = match self.private_sessions.incarnation {
            Some(i) => i,
            None => {
                let mut i = [0; 32];
                getrandom::fill(&mut i).map_err(|_| Error::Rng)?;
                self.private_sessions.incarnation = Some(i);
                if let Err(error) = self.save_private_pulls(store) {
                    self.private_save_failed(&error);
                    return Err(error);
                }
                i
            }
        };
        let mut page = Page {
            revision: 0,
            query: ask.query.clone(),
            cursor: Cursor {
                incarnation,
                after: 0,
            },
            more: false,
            records: Vec::new(),
            positions: Vec::new(),
            hints: Vec::new(),
            charge,
        };
        let mut wire_bytes = PAGE_OVERHEAD;
        let permitted = |saved: &Stored| -> Result<bool> {
            Ok(!self.private_expired(saved, self.now_hint)
                && (saved.record.message.header.author_id != self.me() || holders.contains(peer))
                && self.private_permitted(store, &saved.record, peer)?)
        };
        match &ask.query {
            PrivateQuery::LiveTail => {
                let tip = self.private_sessions.next.saturating_sub(1);
                page.cursor.after = tip;
                let lower = tip.saturating_sub(PAGE_RECORDS as u64 - 1).max(1);
                let seen = if ask.cursor.incarnation == incarnation {
                    ask.cursor.after
                } else {
                    0
                };
                let mut before = tip.checked_add(1);
                for _ in 0..PAGE_RECORDS {
                    let Some(id) = private_index::arrival_before(
                        &store.snapshot()?,
                        &self.sek,
                        &self.channel_id,
                        before,
                    )?
                    else {
                        break;
                    };
                    if id < lower || id <= seen {
                        break;
                    }
                    before = Some(id);
                    let saved = self
                        .private_at(store, id)?
                        .ok_or(Error::MalformedAtRest("private live locator missing"))?;
                    if !permitted(&saved)? {
                        continue;
                    }
                    let wire = saved.record.wire();
                    if wire.len() > MAX_RECORD {
                        return Err(Error::SizeLimitExceeded("private Session record"));
                    }
                    if wire_bytes + wire.len() + 16 > MAX_PAGE {
                        page.more = true;
                        break;
                    }
                    wire_bytes += wire.len() + 16;
                    page.positions.push(id);
                    page.records.push(wire);
                }
                // Delivery order keeps ratchet advancement and lifecycle ordering monotone.
                page.positions.reverse();
                page.records.reverse();
                page.more |= lower > seen.saturating_add(1);
            }
            PrivateQuery::ArchiveInventory { lo, hi, before } => {
                if ask.cursor.incarnation != incarnation {
                    return Err(Error::StreamRefused(
                        "private history donor incarnation changed",
                    ));
                }
                let mut before = *before;
                for _ in 0..PAGE_RECORDS {
                    let Some(id) = private_index::arrival_before(
                        &store.snapshot()?,
                        &self.sek,
                        &self.channel_id,
                        Some(before),
                    )?
                    else {
                        break;
                    };
                    if id < *lo {
                        break;
                    }
                    if id > *hi {
                        return Err(Error::MalformedBundle("private history interval widened"));
                    }
                    before = id;
                    let saved = self
                        .private_at(store, id)?
                        .ok_or(Error::MalformedAtRest("private history locator missing"))?;
                    if permitted(&saved)? {
                        page.hints.push(Locator {
                            id,
                            hash: saved.record.hash(),
                        });
                    }
                }
                page.hints.reverse();
                page.cursor.after = before.max(*lo);
                page.more = private_index::arrival_before(
                    &store.snapshot()?,
                    &self.sek,
                    &self.channel_id,
                    Some(before),
                )?
                .is_some_and(|id| id >= *lo && id <= *hi);
            }
            PrivateQuery::ArchiveRecords { positions, .. } => {
                if ask.cursor.incarnation != incarnation {
                    return Err(Error::StreamRefused(
                        "private history donor incarnation changed",
                    ));
                }
                for position in positions {
                    let saved =
                        self.private_at(store, position.id)?
                            .ok_or(Error::StreamRefused(
                                "requested private history is no longer retained",
                            ))?;
                    if saved.record.hash() != position.hash || !permitted(&saved)? {
                        return Err(Error::StreamRefused(
                            "requested private history is not authorized",
                        ));
                    }
                    let wire = saved.record.wire();
                    if wire.len() > MAX_RECORD {
                        return Err(Error::SizeLimitExceeded("private Session record"));
                    }
                    if wire_bytes + wire.len() + 16 > MAX_PAGE {
                        page.more = true;
                        break;
                    }
                    wire_bytes += wire.len() + 16;
                    page.cursor.after = position.id;
                    page.positions.push(position.id);
                    page.records.push(wire);
                }
            }
        }
        Ok(page)
    }

    pub(crate) fn start_private_pull(
        &mut self,
        store: &Store,
        peer: Digest32,
    ) -> Result<Option<Ask>> {
        if !self.private_policy_ready(store, self.now_hint)? {
            return Ok(None);
        }
        if self.poisoned
            || self.drive.receivers.is_empty()
            || !self.supports_private(store, &peer)?
            || !self.drive_members().contains(&peer)
            || (self.private_sessions.pulling.contains(&peer)
                && self
                    .private_sessions
                    .attempted
                    .get(&peer)
                    .is_some_and(|at| at.elapsed() < Duration::from_secs(30)))
            || self
                .private_sessions
                .attempted
                .get(&peer)
                .is_some_and(|t| t.elapsed() < Duration::from_secs(1))
        {
            return Ok(None);
        }
        self.private_sessions.pulling.insert(peer);
        self.private_sessions.attempted.insert(peer, Instant::now());
        Ok(Some(Ask {
            revision: self.private_sessions.revision,
            room: self.channel_id,
            epoch: self.epoch,
            query: PrivateQuery::LiveTail,
            cursor: self
                .private_sessions
                .cursors
                .get(&peer)
                .cloned()
                .unwrap_or_default(),
        }))
    }

    pub(crate) fn finish_private_pull(
        &mut self,
        store: &Store,
        peer: Digest32,
        page: Result<Page>,
        now: u64,
        trust_nonce: TrustNonce,
    ) -> Result<bool> {
        self.private_sessions.pulling.remove(&peer);
        let page = page?;
        self.require_governance_ready(store, crate::time::Ms(now))?;
        if self.poisoned
            || !self.drive_members().contains(&peer)
            || page.revision != self.private_sessions.revision
            || page.query != PrivateQuery::LiveTail
        {
            return Err(Error::StreamRefused(
                "private live request or authority changed",
            ));
        }
        // No whole-room projection gate here: each record is placed by its own per-record
        // Drive, generation, floor and receiver-chain checks below. Gating this apply on
        // every author's still-building receipt made a member's own apply wait on the very
        // receipts only this apply's rounds could advance.
        // This is a donor-local locator hint, not a completeness statement or a watermark.
        // Authenticate the whole advertised page before retaining even that bounded hint.
        for wire in &page.records {
            let record = Record::read(wire)?;
            let author = record.message.header.author_id;
            let key = self
                .authors
                .get(&author)
                .ok_or(Error::StreamRefused("private Session author unknown"))?;
            record.verify(&self.channel_id, key)?;
            if !self.private_permitted(store, &record, &self.me())? {
                return Err(Error::StreamRefused(
                    "private Session has no current Drive grant",
                ));
            }
        }
        if page.records.is_empty()
            && page.cursor.after > self.private_recovery_after(&peer, page.cursor.incarnation)
        {
            return Err(Error::StreamRefused(
                "private donor advertised a gap without authenticated records",
            ));
        }
        self.private_sessions
            .observed_tips
            .insert(peer, page.cursor.clone());
        for wire in &page.records {
            let record = Record::read(wire)?;
            let header = &record.message.header;
            if !self.private_cached(store, &record.hash())? && header.author_id != self.me() {
                let behind = match self
                    .drive
                    .receivers
                    .get(&(header.author_id, header.chain_id))
                {
                    Some(receiver) => {
                        receiver.has_skipped_iterations()
                            || header.iteration != receiver.next_iteration()
                    }
                    None => true,
                };
                if behind {
                    // A sealed record beyond this receiver chain's keys is not applicable
                    // here at this chain state, and refusing the page here made the pull
                    // a dead end: the retry re-requested the same tail while the named
                    // explicit recovery was armed by nothing, and the failed round lost
                    // the walk entirely. The chain says which it is: a receiver this
                    // member holds names its chain, so the record is this member's and the
                    // covering package merely has not landed yet — this pull returns no
                    // progress and retries after the install, at its own pacing. Only a
                    // record of a chain this member holds no receiver for at all, with no
                    // package of its author in flight, is not this member's to apply: a
                    // Session is read from a grant onward, and this member holds no grant
                    // for this generation, so the pull moves past it.
                    if self.key_packages.pending_from(&header.author_id) {
                        return Ok(false);
                    }
                    if self
                        .drive
                        .receivers
                        .contains_key(&(header.author_id, header.chain_id))
                    {
                        return Ok(false);
                    }
                    continue;
                }
            }
            // A record whose covering key package is still in flight cannot be previewed
            // yet, and one whose opening Session record is still in flight cannot find its
            // session yet. Refusing the page for either made this pull a dead end: the retry
            // re-requested the same tail while the named explicit recovery was armed by
            // nothing, and the failed round lost the walk that carried the pull. Each
            // returns no progress instead and retries at its own pacing once the package or
            // the opening record lands; the explicit refusal stays for a record whose
            // session the projection will not hold.
            if self.key_packages.pending_from(&header.author_id) {
                return Ok(false);
            }
            let row = match self.preview_private_record(store, wire)? {
                Some(row) => row,
                // The receiver cannot open this iteration yet: the covering package has
                // not landed. No progress; the install advances the chain and this pull
                // retries the page.
                None => return Ok(false),
            };
            if !crate::node::sessions::is_record(&row.body)
                && row.session_id != crate::node::drive::KEY_CHANGED
            {
                use super::session_projection::{Query, Reply};
                if !matches!(
                    self.session_query(
                        store,
                        Query::Lookup {
                            node: row.author,
                            id: row.session_id.clone()
                        },
                        1,
                        now
                    ),
                    Ok(Reply::Lookup(Some(_)))
                ) {
                    // The opening Session record of this lifecycle record's session is
                    // still in flight through this same pull: refusing the page here
                    // failed the round and lost the walk, and the retry re-requested the
                    // same tail while the recovery it named was armed by nothing. No
                    // progress; the opening record lands and this pull retries the page.
                    return Ok(false);
                }
            }
            self.take_private_record(store, wire, now, Some(trust_nonce))?;
        }
        let advanced = self.private_sessions.cursors.get(&peer) != Some(&page.cursor);
        if advanced {
            let mut next = self.private_sessions.cursors.clone();
            next.insert(peer, page.cursor);
            if let Err(error) = self.save_private_pull_candidate(store, &next, Some(trust_nonce)) {
                if !matches!(&error, Error::StreamRefused(reason) if *reason == TRUST_CHANGED) {
                    self.private_save_failed(&error);
                }
                return Err(error);
            }
            self.private_sessions.cursors = next;
        }
        // `true` is this page advanced the pull: its caller pulls the next page at once, so a
        // member's private records converge in one run instead of one page per tick. `false`
        // leaves the next page to the tick's own pacing: a page that applied nothing waits
        // for whatever it waits for, and no failing page is retried in a tight loop. No
        // private archive is scheduled automatically either way, even when a gap remains.
        Ok(advanced)
    }

    fn preview_private_record(&self, store: &Store, wire: &[u8]) -> Result<Option<SessionRow>> {
        let record = Record::read(wire)?;
        let author = record.message.header.author_id;
        let key = self
            .authors
            .get(&author)
            .ok_or(Error::StreamRefused("private Session author unknown"))?;
        record.verify(&self.channel_id, key)?;
        if !self.private_permitted(store, &record, &self.me())? {
            return Err(Error::StreamRefused(
                "private Session has no current drive grant",
            ));
        }
        if let Some(id) = self.private_id(store, &record.hash())? {
            if let Some(saved) = self.private_at(store, id)? {
                if saved.row.is_some() {
                    return Ok(saved.row);
                }
            }
        }
        if author == self.me() {
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

    /// Stable generation scope for explicit private history. Ratchet iteration advances do
    /// not change it; a durable receiver generation or membership change does.
    pub(crate) fn private_history_scope(
        &self,
        store: &Store,
        peer: &Digest32,
    ) -> Result<(Cursor, Digest32)> {
        self.require_governance_ready(store, crate::time::Ms(self.now_hint))?;
        if self.poisoned
            || !self.drive_members().contains(peer)
            || !self.current_session_controls_ready(store)?
        {
            return Err(Error::StreamRefused(
                "private history authority is unavailable",
            ));
        }
        let boundary = self
            .private_sessions
            .observed_tips
            .get(peer)
            .or_else(|| self.private_sessions.cursors.get(peer))
            .cloned()
            .ok_or(Error::StreamRefused(
                "current private donor boundary is not available yet",
            ))?;
        Ok((boundary, self.private_pull_binding()))
    }

    pub(crate) fn private_history_ask(
        &self,
        store: &Store,
        bounds: crate::node::history_demand::Bounds,
        plan: &crate::node::history_demand::PrivatePlan,
    ) -> Result<Ask> {
        let (boundary, grant) = self.private_history_scope(store, &plan.donor)?;
        if boundary.incarnation != bounds.head || grant != plan.grant || bounds.hi > boundary.after
        {
            return Err(Error::StreamRefused(
                "private history donor or Drive generation changed",
            ));
        }
        let query = if !plan.inventory_done {
            PrivateQuery::ArchiveInventory {
                lo: bounds.lo,
                hi: bounds.hi,
                before: bounds
                    .hi
                    .checked_add(1)
                    .ok_or(Error::SizeLimitExceeded("private history boundary"))?,
            }
        } else {
            PrivateQuery::ArchiveRecords {
                lo: bounds.lo,
                hi: bounds.hi,
                positions: plan.positions.clone(),
            }
        };
        Ok(Ask {
            revision: self.private_sessions.revision,
            room: self.channel_id,
            epoch: self.epoch,
            cursor: Cursor {
                incarnation: bounds.head,
                after: bounds.hi,
            },
            query,
        })
    }

    /// One explicit quantum only. The caller persists this exact updated plan after these
    /// idempotent record effects commit and before reporting progress to the person.
    pub(crate) fn finish_private_history(
        &mut self,
        store: &Store,
        bounds: crate::node::history_demand::Bounds,
        plan: &mut crate::node::history_demand::PrivatePlan,
        page: Page,
        now: u64,
        trust_nonce: TrustNonce,
    ) -> Result<()> {
        let ask = self.private_history_ask(store, bounds, plan)?;
        if page.revision != ask.revision || page.query != ask.query {
            return Err(Error::StreamRefused(
                "private history request changed during transfer",
            ));
        }
        self.index_session_floors(store)?;
        match &page.query {
            PrivateQuery::ArchiveInventory { .. } => {
                if page.more {
                    return Err(Error::StreamRefused(
                        "private inventory did not finish its fixed interval",
                    ));
                }
                let mut missing = Vec::new();
                for position in page.hints {
                    if !self.private_cached(store, &position.hash)? {
                        missing.push(position);
                    }
                }
                plan.positions = missing;
                plan.inventory_done = true;
            }
            PrivateQuery::ArchiveRecords { .. } => {
                for wire in &page.records {
                    self.preview_private_record(store, wire)?
                        .ok_or(Error::StreamRefused(
                            "requested private history key is no longer retained",
                        ))?;
                    self.take_private_record(store, wire, now, Some(trust_nonce))?;
                }
                plan.positions.drain(..page.records.len());
            }
            PrivateQuery::LiveTail => {
                return Err(Error::StreamRefused(
                    "live delivery is not an archive quantum",
                ))
            }
        }
        Ok(())
    }

    pub(crate) fn private_recovery_after(&self, peer: &Digest32, incarnation: Digest32) -> u64 {
        self.private_sessions
            .cursors
            .get(peer)
            .filter(|c| c.incarnation == incarnation)
            .map_or(0, |c| c.after)
    }
    pub(crate) fn private_cached(&self, store: &Store, hash: &Digest32) -> Result<bool> {
        let Some(id) = self.private_id(store, hash)? else {
            return Ok(false);
        };
        let Some(saved) = self.private_at(store, id)? else {
            return Ok(false);
        };
        Ok(saved.row.is_some()
            && !self.private_expired(&saved, self.now_hint)
            && self.private_permitted(store, &saved.record, &self.me())?)
    }

    fn take_private_record(
        &mut self,
        store: &Store,
        wire: &[u8],
        now: u64,
        authority: Option<TrustNonce>,
    ) -> Result<()> {
        if let Err(error) = self.require_governance_ready(store, crate::time::Ms(now)) {
            self.private_save_failed(&error);
            return Err(error);
        }
        let record = Record::read(wire)?;
        let hash = record.hash();
        let known = (|| {
            self.private_id(store, &hash)?
                .map(|id| self.private_at(store, id))
                .transpose()
                .map(Option::flatten)
        })();
        let known = match known {
            Ok(known) => known,
            Err(error) => {
                self.private_save_failed(&error);
                return Err(error);
            }
        };
        if known.as_ref().is_some_and(|saved| saved.row.is_some()) {
            return Ok(());
        }
        let author = record.message.header.author_id;
        let key = self
            .authors
            .get(&author)
            .ok_or(Error::StreamRefused("private Session author unknown"))?;
        record.verify(&self.channel_id, key)?;
        if author == self.me() {
            return Ok(());
        }
        let migrated = known.as_ref();
        let first_seen = migrated.map_or(now, |saved| saved.first_seen);
        let locally_held = migrated.is_some()
            && record.legacy_claimed_ms().is_some()
            && self.legacy_current_drive(Transaction::Snapshot(&store.snapshot()?), &author)?;
        if !locally_held && !self.private_permitted(store, &record, &self.me())? {
            return Err(Error::StreamRefused("private Session has no drive grant"));
        }
        let slot = (author, record.message.header.chain_id);
        let receiver = self.drive.receivers.get(&slot).ok_or(Error::StreamRefused(
            "private Session drive key not received",
        ))?;
        // A shorter local retention may already have deleted this authenticated record. Its
        // one-use key is gone too; do not pin the donor cursor trying to resurrect it.
        if !receiver.can_open_iteration(record.message.header.iteration) {
            return Ok(());
        }
        // Validate on a candidate: even a correctly signed non-Session body cannot consume the
        // only key and prevent the legitimate Session body from being read later.
        let mut next = ReceiverChain::from_state(&receiver.to_state())?;
        let plaintext = Zeroizing::new(next.decrypt(&record.message)?);
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
        self.keep_private_candidate(
            store,
            Stored {
                record,
                row: Some(row),
                first_seen,
                attention_after: None,
            },
            None,
            Some((slot, &next)),
            authority,
        )?;
        self.drive.receivers.insert(slot, next);
        self.sweep_private_sessions(store, now)?;
        Ok(())
    }

    pub(super) fn reset_private_pulls(&mut self) {
        self.private_sessions.revision = self.private_sessions.revision.wrapping_add(1);
        self.private_sessions.cursors.clear();
        self.private_sessions.observed_tips.clear();
        self.private_sessions.attempted.clear();
    }

    pub(super) fn private_drive_used(&self, store: &Store) -> Result<Option<u64>> {
        self.legacy_drive_generation(store, &self.me())
    }
}
