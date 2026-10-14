//! Session payloads live outside the public room log. Each sealed record commits its verified
//! wire, rendered row and first-seen time together with the consumed drive chain.

use std::time::{Duration, Instant};

use super::session_projection::private_index;
use super::*;
use crate::node::sessionstream::{Ask, Cursor, Page, Record, PAGE_RECORDS};

const SUPPORT: &str = "vox/private-session-stream/v1";
const SEG_LEGACY_DRIVE_GENERATIONS: u64 = 19;
const WORK_ROWS: usize = 32;
const WORK_BYTES: usize = 1024 * 1024;

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

fn support_body(room: &Digest32, author: &Digest32) -> Vec<u8> {
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

pub(super) struct Stored {
    pub(super) record: Record,
    // An authorized legacy body can arrive before its drive key package is installed.
    pub(super) row: Option<SessionRow>,
    pub(super) first_seen: u64,
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
    legacy_generations: BTreeMap<Digest32, u64>,
    next: u64,
    incarnation: Option<Digest32>,
    cursors: BTreeMap<Digest32, Cursor>,
    pulling: BTreeSet<Digest32>,
    attempted: BTreeMap<Digest32, Instant>,
    supports: BTreeMap<Digest32, (u64, bool)>,
    revision: u64,
}

impl Stored {
    fn bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(1)
            .bytes(&self.record.wire())
            .bytes(&self.row.as_ref().map_or_else(Vec::new, session_cache_bytes))
            .uint(self.first_seen);
        Zeroizing::new(e.finish())
    }

    pub(super) fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 4 || d.uint()? != 1 {
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

    fn private_id(&self, store: &Store, hash: &Digest32) -> Result<Option<u64>> {
        let snapshot = store.snapshot()?;
        private_index::find(&snapshot, &self.sek, &self.channel_id, hash)
    }

    fn private_at(&self, store: &Store, id: u64) -> Result<Option<Stored>> {
        store
            .get_segment(&self.channel_id, SegmentKind::PrivateSession, id)?
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

    /// Local evidence about a legacy sender's generation survives deletion of its body. It
    /// confers no relay permission: other recipients still need the author's signed floors.
    pub(super) fn legacy_drive_generation(&self, author: &Digest32) -> Option<u64> {
        self.private_sessions
            .legacy_generations
            .get(author)
            .copied()
    }

    /// Called only after verification, before a forbidden legacy body is discarded. A
    /// generation observation can deny obsolete permission, never grant forwarding rights.
    pub(super) fn observe_legacy_drive_generation(&mut self, entry: &Entry) {
        let Some(message) = entry
            .payload
            .as_deref()
            .and_then(|p| GroupMessage::from_wire(p).ok())
        else {
            return;
        };
        let h = message.header;
        if h.channel_id != drive_channel(&self.channel_id)
            || h.author_id != entry.skeleton.author_id
            || h.epoch != entry.skeleton.epoch
        {
            return;
        }
        self.private_sessions
            .legacy_generations
            .entry(h.author_id)
            .and_modify(|generation| *generation = (*generation).max(h.chain_id))
            .or_insert(h.chain_id);
    }

    pub(super) fn queue_private_generations(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
    ) -> Result<()> {
        if self.private_sessions.legacy_generations.is_empty() {
            return Ok(());
        }
        let mut e = Encoder::new();
        e.array(2)
            .uint(1)
            .array(self.private_sessions.legacy_generations.len());
        for (author, generation) in &self.private_sessions.legacy_generations {
            e.array(2).bytes(author).uint(*generation);
        }
        let segment = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_LEGACY_DRIVE_GENERATIONS,
            &e.finish(),
        )?;
        batch.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_LEGACY_DRIVE_GENERATIONS,
            &segment,
        )
    }

    fn legacy_current_drive(&self, author: &Digest32) -> bool {
        if *author == self.me() {
            return true;
        }
        if !self.authors.contains_key(author) || self.has_left(&self.me()) {
            return false;
        }
        let announced = self
            .drive
            .floors
            .keys()
            .filter(|(a, _, epoch, _)| a == author && *epoch <= self.epoch)
            .map(|(_, _, _, g)| *g)
            .max();
        let newest = announced
            .into_iter()
            .chain(self.legacy_drive_generation(author))
            .max();
        let Some(generation) = newest else {
            return false;
        };
        if announced == Some(generation) {
            // Merely having an unopened old key package is not a current grant.
            return self
                .drive
                .floors
                .iter()
                .any(|((a, target, epoch, g), (membership, _, _))| {
                    a == author
                        && *target == self.me()
                        && *epoch == self.epoch
                        && *g == generation
                        && *membership == self.admission(&self.me()).0
                });
        }
        self.drive.receivers.contains_key(&(*author, generation))
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
        if self.private_sessions.upgrading || self.private_sessions.restoring {
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
                    work.migrating = true;
                    work.after = None;
                    self.private_sessions.legacy_work = Some(work);
                    return Ok(false);
                }
                self.private_sessions.pending_active = true;
                self.private_sessions.pending_after = None;
                self.private_sessions.pending_through = self.private_sessions.next;
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
                    self.migrate_legacy_row(store, entry)?;
                } else if let Ok(record) = Record::legacy(entry) {
                    let author = record.message.header.author_id;
                    if self
                        .authors
                        .get(&author)
                        .is_some_and(|key| record.verify(&self.channel_id, key).is_ok())
                    {
                        self.private_sessions
                            .legacy_generations
                            .entry(author)
                            .and_modify(|g| *g = (*g).max(record.message.header.chain_id))
                            .or_insert(record.message.header.chain_id);
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
        let record = Record::legacy(entry).ok().filter(|r| {
            self.authors
                .get(&author)
                .is_some_and(|key| r.verify(&self.channel_id, key).is_ok())
        });
        let mut next = self.private_sessions.next.max(1);
        if !self.private_contains_in(&batch, &hash)? {
            if let Some(record) = record.filter(|r| {
                self.legacy_current_drive(&author)
                    && (cached.is_some()
                        || self.private_permitted(r, &self.me())
                        || author == self.me()
                        || (!self.drive.floors.keys().any(|(a, _, _, _)| *a == author)
                            && self.legacy_drive_generation(&author)
                                == Some(r.message.header.chain_id)
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
        if !self.private_sessions.upgrading
            && !self.private_sessions.restoring
            && self.private_sessions.legacy_work.is_none()
            && self.private_sessions.legacy_pending.is_empty()
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
        let mut bytes = 0usize;
        for _ in 0..WORK_ROWS {
            let next = self.private_after(store, self.private_sessions.pending_after)?;
            let Some((id, saved)) =
                next.filter(|(id, _)| *id < self.private_sessions.pending_through)
            else {
                self.private_sessions.pending_active = false;
                self.private_sessions.pending_after = None;
                return Ok(true);
            };
            let size = saved.record.message.ciphertext.len();
            if bytes != 0 && bytes.saturating_add(size) > WORK_BYTES {
                break;
            }
            bytes = bytes.saturating_add(size);
            if saved.row.is_none()
                && self.legacy_current_drive(&saved.record.message.header.author_id)
                && self.drive.receivers.contains_key(&(
                    saved.record.message.header.author_id,
                    saved.record.message.header.chain_id,
                ))
            {
                if let Err(error) = self.take_private_record(store, &saved.record.wire(), now) {
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
        Ok(false)
    }

    pub(crate) fn needs_session_upgrade(&self) -> bool {
        self.private_sessions.upgrading
            || self.private_sessions.restoring
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

    /// Also driven by ordinary maintenance, before Session projection or grant release.
    pub(crate) fn advance_private_sessions(&mut self, store: &Store, now: u64) -> Result<bool> {
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
            if self.private_sessions.legacy_work.is_some()
                || !self.private_sessions.legacy_pending.is_empty()
            {
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
        let head = self.dag.verified_head(peer);
        if let Some((known, supported)) = self.private_sessions.supports.get(peer) {
            if *known == head {
                return Ok(*supported);
            }
        }
        let expected = support_body(&self.channel_id, peer);
        let mut supported = false;
        let entries = self.entries.read(store, &self.sek, &self.channel_id)?;
        for seq in 1..=head {
            let entry = entries.get(peer, seq)?.ok_or(Error::MalformedAtRest(
                "private capability feed entry missing",
            ))?;
            if entry.payload.as_deref() == Some(expected.as_slice()) {
                supported = true;
                break;
            }
        }
        self.private_sessions
            .supports
            .insert(*peer, (head, supported));
        Ok(supported)
    }

    /// Authenticated capability, not a Session step. Published old readers skip its unknown
    /// content body. Only an author who advertised support is ever probed with stream 13.
    pub(crate) fn announce_private_support(&mut self, profile: &Profile, now: u64) -> Result<()> {
        let me = self.me();
        if !self.settled
            || self.poisoned
            || self.has_left(&me)
            || self.supports_private(profile.store(), &me)?
        {
            return Ok(());
        }
        self.append_control_kind(
            profile,
            &support_body(&self.channel_id, &me),
            now,
            EntryKind::Content,
        )?;
        Ok(())
    }
    pub(super) fn restore_private_sessions(&mut self, store: &Store) -> Result<()> {
        if let Some(segment) = store.get_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_LEGACY_DRIVE_GENERATIONS,
        )? {
            let bytes = open_segment(
                &self.sek,
                SegmentKind::KeyMaterial,
                SEG_LEGACY_DRIVE_GENERATIONS,
                &segment,
            )?;
            let mut d = Decoder::new(&bytes);
            if d.array()? != 2 || d.uint()? != 1 {
                return Err(Error::MalformedAtRest("legacy drive generations version"));
            }
            for _ in 0..d.array()? {
                if d.array()? != 2 {
                    return Err(Error::MalformedAtRest("legacy drive generation row"));
                }
                let author = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedAtRest("legacy drive author"))?;
                if self
                    .private_sessions
                    .legacy_generations
                    .insert(author, d.uint()?)
                    .is_some()
                {
                    return Err(Error::MalformedAtRest("duplicate legacy drive author"));
                }
            }
            d.finish()?;
        }
        self.private_sessions.restoring = true;
        self.private_sessions.restore_after = None;
        Ok(())
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
            batch.commit()?;
            self.private_sessions.next = self.private_sessions.next.max(next);
            self.private_sessions.restore_after = Some(id);
        }
        Ok(false)
    }

    pub(super) fn sweep_private_sessions(&mut self, store: &Store, now: u64) -> Result<usize> {
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
        self.poisoned = true;
        self.save_error = Some(error.to_string());
    }

    fn keep_private(&mut self, store: &Store, saved: Stored) -> Result<Digest32> {
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
            if let Some(old) =
                batch.get_segment(&self.channel_id, SegmentKind::PrivateSession, id)?
            {
                let old = self.read_private(id, &old)?;
                private_index::remove(&mut batch, &self.sek, &self.channel_id, id, &old)?;
            }
            batch.put_segment(&self.channel_id, SegmentKind::PrivateSession, id, &segment)?;
            self.queue_drive(&mut batch)?;
            private_index::put(&mut batch, &self.sek, &self.channel_id, id, &saved)?;
            batch.commit()
        })();
        if let Err(e) = result {
            self.private_save_failed(&e);
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

    fn refresh_grant(&self, holders: &BTreeSet<Digest32>, owed: &[Digest32]) -> Digest32 {
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
        // Grant floors can move without a chain rotation. They must invalidate a completed
        // scan before it can authorize release using an obsolete recipient position.
        for ((author, target, epoch, generation), (membership, iteration, from)) in
            &self.drive.floors
        {
            if *author == self.me() && (owed.contains(target) || *target == self.me()) {
                hash.update(author);
                hash.update(target);
                hash.update(epoch.to_be_bytes());
                hash.update(generation.to_be_bytes());
                hash.update(membership.to_be_bytes());
                hash.update(iteration.to_be_bytes());
                hash.update(from.to_be_bytes());
            }
        }
        hash.finalize().into()
    }

    fn refresh_session_records_inner(
        &mut self,
        profile: &Profile,
        holders: &BTreeSet<Digest32>,
        owed: &[Digest32],
        now: u64,
    ) -> Result<bool> {
        self.rotate_drive_if_lost(profile.store(), holders, crate::time::Ms(now))?;
        let grant = self.refresh_grant(holders, owed);
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
        for _ in 0..WORK_ROWS {
            if work.stage == 0 {
                let next = {
                    let view =
                        self.entries
                            .render_view(profile.store(), &self.sek, &self.channel_id)?;
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
                        let env =
                            vox_agentcomms::envelope::Envelope::parse(&row.text).map_err(|_| {
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
        // Our own refresh copies change this generation; they do not invalidate their
        // source cursor. A later independent lifecycle write does restart it next turn.
        work.private = private_index::lifecycle_revision(
            &profile.store().snapshot()?,
            &self.sek,
            &self.channel_id,
        )?;
        let complete = work.stage == 2 && work.grant == self.refresh_grant(holders, owed);
        self.private_sessions.refresh = Some(work);
        Ok(complete)
    }

    fn refresh_one_session_record(
        &mut self,
        profile: &Profile,
        holders: &BTreeSet<Digest32>,
        owed: &[Digest32],
        created: u64,
        session: &str,
        body: &str,
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
        if let Some(id) = matched {
            let saved = self
                .private_at(profile.store(), id)?
                .ok_or(Error::MalformedAtRest("Session refresh locator missing"))?;
            if !saved.row.as_ref().is_some_and(|row| {
                row.author == self.me() && row.created_millis == created && row.body == body
            }) {
                return Err(Error::MalformedAtRest("Session refresh locator binding"));
            }
            if !self.private_expired(&saved, now)
                && owed
                    .iter()
                    .all(|peer| self.private_permitted(&saved.record, peer))
            {
                return Ok(());
            }
        }
        let content = crate::node::content::SessionEntry::new(created, session, body)?;
        self.append_private_content(profile, content, holders, now)?;
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
        self.append_private_content(profile, content, holders, now)
    }

    fn append_private_content(
        &mut self,
        profile: &Profile,
        content: crate::node::content::SessionEntry,
        holders: &BTreeSet<Digest32>,
        now: u64,
    ) -> Result<Digest32> {
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
                },
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
    fn private_permitted(&self, record: &Record, recipient: &Digest32) -> bool {
        let h = &record.message.header;
        if !self.settled || self.has_left(recipient) || !self.authors.contains_key(recipient) {
            return false;
        }
        if h.author_id == *recipient {
            return true;
        }
        let membership = self.admission(recipient).0;
        let Some((m, iteration, _)) =
            self.drive
                .floors
                .get(&(h.author_id, *recipient, h.epoch, h.chain_id))
        else {
            return false;
        };
        if *m != membership || h.iteration < *iteration {
            return false;
        }
        let mut saw_author = false;
        for ((author, target, epoch, generation), (_, _, author_start)) in &self.drive.floors {
            if *author != h.author_id
                || author != target
                || (*epoch, *generation) < (h.epoch, h.chain_id)
            {
                continue;
            }
            saw_author = true;
            if self
                .drive
                .floors
                .get(&(*author, *recipient, *epoch, *generation))
                .is_none_or(|(m, from, first_seq)| {
                    *m != membership
                        || ((*epoch, *generation) > (h.epoch, h.chain_id)
                            && (*from != 0 || first_seq > author_start))
                })
            {
                return false;
            }
            // Continuing holders are marked at iteration zero before the author's own floor
            // is published. A later grant in any intervening generation breaks continuity:
            // its key position may be later, or it may still be zero if nobody has written
            // yet. The signed public position distinguishes that second case. Merely having
            // a floor again must never revive permission to fetch the former grant's bodies.
        }
        saw_author
    }

    pub(crate) fn private_page(
        &mut self,
        store: &Store,
        ask: &Ask,
        peer: &Digest32,
        holders: &BTreeSet<Digest32>,
    ) -> Result<Page> {
        if self.poisoned
            || self.needs_session_upgrade()
            || ask.room != self.channel_id
            || ask.epoch != self.epoch
            || !self.drive_members().contains(peer)
        {
            return Err(Error::StreamRefused("private Session room unavailable"));
        }
        if let Err(error) = self.index_session_floors(store) {
            self.poison(&error);
            return Err(error);
        }
        let incarnation = match self.private_sessions.incarnation {
            Some(i) => i,
            None => {
                let mut i = [0; 32];
                getrandom::fill(&mut i).map_err(|_| Error::Rng)?;
                self.private_sessions.incarnation = Some(i);
                i
            }
        };
        let mut after = if ask.cursor.incarnation == incarnation {
            ask.cursor.after
        } else {
            0
        };
        let mut records = Vec::new();
        // Bound CPU and bytes even when most retained records belong to other audiences.
        for _ in 0..256 {
            if records.len() == PAGE_RECORDS {
                break;
            }
            let Some((id, saved)) = self.private_after(store, Some(after))? else {
                break;
            };
            after = id;
            if self.private_expired(&saved, self.now_hint) {
                continue;
            }
            if saved.record.message.header.author_id == self.me() && !holders.contains(peer) {
                continue;
            }
            if self.private_permitted(&saved.record, peer) {
                records.push(saved.record.wire());
            }
        }
        let more = self.private_after(store, Some(after))?.is_some();
        Ok(Page {
            revision: 0,
            cursor: Cursor { incarnation, after },
            more,
            records,
        })
    }

    pub(crate) fn start_private_pull(
        &mut self,
        store: &Store,
        peer: Digest32,
    ) -> Result<Option<Ask>> {
        if self.poisoned
            || self.drive.receivers.is_empty()
            || !self.supports_private(store, &peer)?
            || !self.drive_members().contains(&peer)
            || self.private_sessions.pulling.contains(&peer)
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
    ) -> Result<bool> {
        self.private_sessions.pulling.remove(&peer);
        let page = page?;
        if self.poisoned || !self.drive_members().contains(&peer) {
            return Err(Error::StreamRefused("private Session room unavailable"));
        }
        self.index_session_floors(store)?;
        for wire in &page.records {
            self.take_private_record(store, wire, now)?;
        }
        // A grant arriving while the request was in flight resets recovery to the beginning.
        // Do not overwrite that reset with a cursor sampled before the grant.
        if page.revision == self.private_sessions.revision {
            self.private_sessions.cursors.insert(peer, page.cursor);
        }
        if page.more {
            self.private_sessions.attempted.remove(&peer);
        }
        Ok(page.more)
    }

    fn take_private_record(&mut self, store: &Store, wire: &[u8], now: u64) -> Result<()> {
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
            && self.legacy_current_drive(&author);
        if !locally_held && !self.private_permitted(&record, &self.me()) {
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
        self.drive.receivers.insert(slot, next);
        self.keep_private(
            store,
            Stored {
                record,
                row: Some(row),
                first_seen,
            },
        )?;
        self.sweep_private_sessions(store, now)?;
        Ok(())
    }

    pub(super) fn reset_private_pulls(&mut self) {
        self.private_sessions.revision = self.private_sessions.revision.wrapping_add(1);
        self.private_sessions.cursors.clear();
        self.private_sessions.attempted.clear();
    }

    pub(super) fn private_drive_used(&self, store: &Store) -> Result<Option<u64>> {
        let mut after = None;
        let mut used: Option<u64> = None;
        while let Some((id, saved)) = self.private_after(store, after)? {
            after = Some(id);
            if saved.record.message.header.author_id == self.me() {
                let generation = saved.record.message.header.chain_id;
                used = Some(used.map_or(generation, |old| old.max(generation)));
            }
        }
        Ok(used)
    }
}
