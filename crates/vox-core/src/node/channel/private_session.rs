//! Session payloads live outside the public room log. Each sealed record commits its verified
//! wire, rendered row and first-seen time together with the consumed drive chain.

use std::time::{Duration, Instant};

use super::*;
use crate::node::sessionstream::{Ask, Cursor, Page, Record, PAGE_RECORDS};

const SUPPORT: &str = "vox/private-session-stream/v1";
const SEG_LEGACY_DRIVE_GENERATIONS: u64 = 19;

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

struct Stored {
    record: Record,
    // An authorized legacy body can arrive before its drive key package is installed.
    row: Option<SessionRow>,
    first_seen: u64,
}

#[derive(Default)]
pub(super) struct PrivateSessions {
    records: BTreeMap<u64, Stored>,
    hashes: BTreeMap<Digest32, u64>,
    pub(super) legacy_pending: BTreeSet<Digest32>,
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

impl PrivateSessions {
    pub(super) fn contains(&self, hash: &Digest32) -> bool {
        self.hashes.contains_key(hash)
    }
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

    fn read(bytes: &[u8]) -> Result<Self> {
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

    /// Rewrite old public step pages before a room is exposed. Repeating this is harmless:
    /// migrated records are no longer public bodies, and later drive loss never deletes an
    /// already-read private row. The same operation handles an older writer during upgrade.
    pub(super) fn migrate_legacy_steps(&mut self, store: &Store, now: u64) -> Result<()> {
        if self.private_sessions.upgrading || self.private_sessions.legacy_pending.is_empty() {
            return Ok(());
        }
        let result = self.migrate_legacy_steps_inner(store, now);
        if let Err(error) = &result {
            self.private_save_failed(error);
        }
        result
    }

    fn migrate_legacy_steps_inner(&mut self, store: &Store, now: u64) -> Result<()> {
        self.index_session_floors();
        let pending: Vec<_> = self
            .private_sessions
            .legacy_pending
            .iter()
            .filter_map(|hash| self.dag.get_by_hash(hash).cloned())
            .filter(|entry| {
                entry
                    .payload
                    .as_deref()
                    .is_some_and(|p| is_step_body(&self.channel_id, p))
            })
            .collect();
        // Learn every verified generation before deciding which old rows may survive. Neither
        // log order nor a stale receiver key may preserve an already-revoked legacy cache.
        let mut records = Vec::new();
        for entry in pending {
            let hash = entry.entry_hash();
            let Some(tracked) = self.retention.get(&hash) else {
                continue;
            };
            let mut record = Record::legacy(entry.clone()).ok();
            if record.as_ref().is_some_and(|r| {
                self.authors
                    .get(&entry.skeleton.author_id)
                    .is_none_or(|key| r.verify(&self.channel_id, key).is_err())
            }) {
                record = None;
            }
            if let Some(r) = &record {
                self.private_sessions
                    .legacy_generations
                    .entry(entry.skeleton.author_id)
                    .and_modify(|g| *g = (*g).max(r.message.header.chain_id))
                    .or_insert(r.message.header.chain_id);
            }
            records.push((entry, record, tracked));
        }
        let cached: BTreeMap<_, _> = self
            .drive
            .sessions
            .rows()
            .iter()
            .filter(|row| {
                self.private_sessions
                    .legacy_pending
                    .contains(&row.entry_hash)
            })
            .map(|row| (row.entry_hash, row.clone()))
            .collect();
        let mut kept = Vec::new();
        let mut next = self.private_sessions.next.max(1);
        let mut batch = store.batch()?;
        for (entry, record, tracked) in &mut records {
            let hash = entry.entry_hash();
            if !self.private_sessions.hashes.contains_key(&hash) {
                if let Some(record) = record.take().filter(|r| {
                    self.legacy_current_drive(&r.message.header.author_id)
                        && (cached.contains_key(&hash)
                            || self.private_permitted(r, &self.me())
                            || r.message.header.author_id == self.me()
                            || (!self
                                .drive
                                .floors
                                .keys()
                                .any(|(a, _, _, _)| *a == r.message.header.author_id)
                                && self.legacy_drive_generation(&r.message.header.author_id)
                                    == Some(r.message.header.chain_id)
                                && self
                                    .drive
                                    .receivers
                                    .get(&(r.message.header.author_id, r.message.header.chain_id))
                                    .is_some_and(|chain| {
                                        chain.can_open_iteration(r.message.header.iteration)
                                    })))
                }) {
                    let saved = Stored {
                        record,
                        row: cached.get(&hash).cloned(),
                        first_seen: tracked.first_seen_ms,
                    };
                    let id = next;
                    next = id
                        .checked_add(1)
                        .ok_or(Error::SizeLimitExceeded("private Session records"))?;
                    let segment =
                        seal_segment(&self.sek, SegmentKind::PrivateSession, id, &saved.bytes())?;
                    batch.put_segment(
                        &self.channel_id,
                        SegmentKind::PrivateSession,
                        id,
                        &segment,
                    )?;
                    kept.push((id, saved));
                }
            }
            let mut bare = entry.clone();
            bare.prune_payload();
            let segment = seal_segment(
                &self.sek,
                SegmentKind::LogDb,
                tracked.log_id,
                &bare.to_wire(),
            )?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::LogDb,
                tracked.log_id,
                &segment,
            )?;
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
        }
        self.queue_private_generations(&mut batch)?;
        batch.commit()?;
        for (id, saved) in kept {
            self.private_sessions.hashes.insert(saved.record.hash(), id);
            self.private_sessions.records.insert(id, saved);
        }
        self.private_sessions.next = next;
        let gone: BTreeSet<_> = records
            .iter()
            .map(|(entry, _, _)| entry.entry_hash())
            .collect();
        for hash in &gone {
            self.dag.prune_payload(hash);
            self.retention.forget(hash);
        }
        self.drive.sessions.retain(|row| {
            !gone.contains(&row.entry_hash)
                || self.private_sessions.hashes.contains_key(&row.entry_hash)
        });
        self.private_sessions.legacy_pending.clear();
        self.sweep_private_sessions(store, now)?;
        Ok(())
    }

    /// A migrated, authorized body may have preceded its key package. Decrypt it once that key
    /// is installed; retain its original age and never re-fetch it through the public log.
    pub(super) fn render_pending_private(&mut self, store: &Store, now: u64) -> Result<()> {
        if self.private_sessions.upgrading {
            return Ok(());
        }
        let pending: Vec<_> = self
            .private_sessions
            .records
            .values()
            .filter(|saved| {
                saved.row.is_none()
                    && self.legacy_current_drive(&saved.record.message.header.author_id)
            })
            .filter(|saved| {
                self.drive.receivers.contains_key(&(
                    saved.record.message.header.author_id,
                    saved.record.message.header.chain_id,
                ))
            })
            .map(|saved| saved.record.wire())
            .collect();
        for wire in pending {
            if let Err(error) = self.take_private_record(store, &wire, now) {
                if self.poisoned {
                    return Err(error);
                }
                // An old author may have sealed malformed/non-Session content in the drive
                // namespace. Do not let that keep a whole room closed during upgrade. Only
                // unread migration records are discarded here; a stored readable row stays.
                let hash = Record::read(&wire)?.hash();
                let Some(id) = self.private_sessions.hashes.get(&hash).copied() else {
                    continue;
                };
                if self
                    .private_sessions
                    .records
                    .get(&id)
                    .is_none_or(|s| s.row.is_some())
                {
                    continue;
                }
                let mut batch = store.batch()?;
                batch.delete_segment(&self.channel_id, SegmentKind::PrivateSession, id)?;
                batch.commit()?;
                self.private_sessions.records.remove(&id);
                self.private_sessions.hashes.remove(&hash);
                self.set_aside.push(format!(
                    "legacy Session {}: {error}",
                    crate::node::link::b32_encode(&hash)
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn needs_session_upgrade(&self) -> bool {
        self.private_sessions.upgrading
    }

    /// Called before publication, after the actor has tried the stored key packages. Without
    /// that ordering an old writer's legitimate, not-yet-opened drive grant could look absent.
    pub(crate) fn finish_session_upgrade(&mut self, store: &Store, now: u64) -> Result<()> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.private_sessions.upgrading = false;
        self.migrate_legacy_steps(store, now)?;
        self.render_pending_private(store, now)
    }

    pub(super) fn supports_private(&mut self, peer: &Digest32) -> bool {
        let seq = self.dag.verified_head(peer);
        if let Some((known, supported)) = self.private_sessions.supports.get(peer) {
            if *known == seq {
                return *supported;
            }
        }
        let expected = support_body(&self.channel_id, peer);
        let supported = self.dag.feed(peer).is_some_and(|feed| {
            feed.iter()
                .any(|e| e.skeleton.seq <= seq && e.payload.as_deref() == Some(expected.as_slice()))
        });
        self.private_sessions
            .supports
            .insert(*peer, (seq, supported));
        supported
    }

    /// Authenticated capability, not a Session step. Published old readers skip its unknown
    /// content body. Only an author who advertised support is ever probed with stream 13.
    pub(crate) fn announce_private_support(&mut self, profile: &Profile, now: u64) -> Result<()> {
        let me = self.me();
        if !self.settled || self.poisoned || self.has_left(&me) || self.supports_private(&me) {
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
        for (id, segment) in store.segments(&self.channel_id, SegmentKind::PrivateSession)? {
            let bytes = open_segment(&self.sek, SegmentKind::PrivateSession, id, &segment)?;
            let saved = Stored::read(&bytes)?;
            let key = self
                .authors
                .get(&saved.record.message.header.author_id)
                .ok_or(Error::MalformedAtRest("private Session author missing"))?;
            saved.record.verify(&self.channel_id, key)?;
            self.private_sessions.next = self.private_sessions.next.max(id.saturating_add(1));
            self.private_sessions.hashes.insert(saved.record.hash(), id);
            if let Some(row) = &saved.row {
                self.drive.sessions.push(row.clone());
            }
            self.private_sessions.records.insert(id, saved);
        }
        Ok(())
    }

    pub(super) fn sweep_private_sessions(&mut self, store: &Store, now: u64) -> Result<usize> {
        let ttl = self.effective_step_retention();
        if ttl == 0 || self.poisoned {
            return Ok(0);
        }
        let before = now.saturating_sub(ttl.saturating_mul(1000));
        let due: Vec<_> = self
            .private_sessions
            .records
            .iter()
            .filter(|(_, s)| {
                s.first_seen.min(
                    s.row
                        .as_ref()
                        .map(|r| r.created_millis)
                        .or_else(|| s.record.legacy_claimed_ms())
                        .unwrap_or(s.first_seen),
                ) <= before
            })
            .map(|(id, s)| (*id, s.record.hash()))
            .collect();
        if due.is_empty() {
            return Ok(0);
        }
        let saved = (|| {
            let mut batch = store.batch()?;
            for (id, _) in &due {
                batch.delete_segment(&self.channel_id, SegmentKind::PrivateSession, *id)?;
            }
            batch.commit()
        })();
        if let Err(e) = saved {
            self.private_save_failed(&e);
            return Err(e);
        }
        for (id, hash) in &due {
            self.private_sessions.records.remove(id);
            self.private_sessions.hashes.remove(hash);
        }
        let gone: BTreeSet<_> = due.iter().map(|(_, h)| *h).collect();
        self.drive
            .sessions
            .retain(|row| !gone.contains(&row.entry_hash));
        Ok(due.len())
    }

    fn private_save_failed(&mut self, error: &Error) {
        self.poisoned = true;
        self.save_error = Some(error.to_string());
    }

    fn keep_private(&mut self, store: &Store, saved: Stored) -> Result<Digest32> {
        let hash = saved.record.hash();
        let id = self
            .private_sessions
            .hashes
            .get(&hash)
            .copied()
            .unwrap_or(self.private_sessions.next.max(1));
        let Some(next) = id.checked_add(1) else {
            let error = Error::SizeLimitExceeded("private Session records");
            self.private_save_failed(&error);
            return Err(error);
        };
        let result = (|| {
            let segment = seal_segment(&self.sek, SegmentKind::PrivateSession, id, &saved.bytes())?;
            let mut batch = store.batch()?;
            batch.put_segment(&self.channel_id, SegmentKind::PrivateSession, id, &segment)?;
            self.queue_drive(&mut batch)?;
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
            self.drive.sessions.push(row.clone());
        }
        self.private_sessions.hashes.insert(hash, id);
        self.private_sessions.records.insert(id, saved);
        self.private_sessions.next = self.private_sessions.next.max(next);
        self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(hash)
    }

    /// A newly written step does not advance any public feed or refer to its heads.
    pub(super) fn append_private_session(
        &mut self,
        profile: &Profile,
        session_id: &str,
        body: &str,
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
        let content = crate::node::content::SessionEntry::new(now, session_id, body)?;
        if self
            .drive
            .chain
            .as_ref()
            .is_none_or(|c| c.epoch() != self.epoch || c.should_rotate(now))
        {
            self.begin_drive(holders, now)?;
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
                created_millis: now,
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
        ask: &Ask,
        peer: &Digest32,
        holders: &BTreeSet<Digest32>,
    ) -> Result<Page> {
        if self.poisoned
            || ask.room != self.channel_id
            || ask.epoch != self.epoch
            || !self.drive_members().contains(peer)
        {
            return Err(Error::StreamRefused("private Session room unavailable"));
        }
        self.index_session_floors();
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
        for (scanned, (id, saved)) in self
            .private_sessions
            .records
            .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
            .enumerate()
        {
            if scanned == 256 || records.len() == PAGE_RECORDS {
                break;
            }
            after = *id;
            if saved.record.message.header.author_id == self.me() && !holders.contains(peer) {
                continue;
            }
            if self.private_permitted(&saved.record, peer) {
                records.push(saved.record.wire());
            }
        }
        let more = self
            .private_sessions
            .records
            .keys()
            .next_back()
            .is_some_and(|id| *id > after);
        Ok(Page {
            revision: 0,
            cursor: Cursor { incarnation, after },
            more,
            records,
        })
    }

    pub(crate) fn start_private_pull(&mut self, peer: Digest32) -> Option<Ask> {
        if self.poisoned
            || self.drive.receivers.is_empty()
            || !self.supports_private(&peer)
            || !self.drive_members().contains(&peer)
            || self.private_sessions.pulling.contains(&peer)
            || self
                .private_sessions
                .attempted
                .get(&peer)
                .is_some_and(|t| t.elapsed() < Duration::from_secs(1))
        {
            return None;
        }
        self.private_sessions.pulling.insert(peer);
        self.private_sessions.attempted.insert(peer, Instant::now());
        Some(Ask {
            revision: self.private_sessions.revision,
            room: self.channel_id,
            epoch: self.epoch,
            cursor: self
                .private_sessions
                .cursors
                .get(&peer)
                .cloned()
                .unwrap_or_default(),
        })
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
        self.index_session_floors();
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
        if self
            .private_sessions
            .hashes
            .get(&hash)
            .and_then(|id| self.private_sessions.records.get(id))
            .is_some_and(|s| s.row.is_some())
        {
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
        let migrated = self
            .private_sessions
            .hashes
            .get(&hash)
            .and_then(|id| self.private_sessions.records.get(id));
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

    pub(super) fn private_drive_used(&self) -> Option<u64> {
        self.private_sessions
            .records
            .values()
            .filter(|s| s.record.message.header.author_id == self.me())
            .map(|s| s.record.message.header.chain_id)
            .max()
    }
}
