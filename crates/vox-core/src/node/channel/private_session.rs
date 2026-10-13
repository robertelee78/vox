//! Session payloads live outside the public room log. Each sealed record commits its verified
//! wire, rendered row and first-seen time together with the consumed drive chain.

use std::time::{Duration, Instant};

use super::*;
use crate::node::sessionstream::{Ask, Cursor, Page, Record, PAGE_RECORDS};

const SUPPORT: &str = "vox/private-session-stream/v1";

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
    row: SessionRow,
    first_seen: u64,
}

#[derive(Default)]
pub(super) struct PrivateSessions {
    records: BTreeMap<u64, Stored>,
    hashes: BTreeSet<Digest32>,
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
            .bytes(&session_cache_bytes(&self.row))
            .uint(self.first_seen);
        Zeroizing::new(e.finish())
    }

    fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 4 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest("private Session state version"));
        }
        let record = Record::read(d.bytes()?)?;
        let CacheRow::Session(row) = parse_cache(d.bytes()?)? else {
            return Err(Error::MalformedAtRest("private Session cache kind"));
        };
        let first_seen = d.uint()?;
        d.finish()?;
        if row.entry_hash != record.hash() || row.author != record.message.header.author_id {
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
    fn supports_private(&mut self, peer: &Digest32) -> bool {
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
        for (id, segment) in store.segments(&self.channel_id, SegmentKind::PrivateSession)? {
            let bytes = open_segment(&self.sek, SegmentKind::PrivateSession, id, &segment)?;
            let saved = Stored::read(&bytes)?;
            let key = self
                .authors
                .get(&saved.row.author)
                .ok_or(Error::MalformedAtRest("private Session author missing"))?;
            saved.record.verify(&self.channel_id, key)?;
            self.private_sessions.next = self.private_sessions.next.max(id.saturating_add(1));
            self.private_sessions.hashes.insert(saved.row.entry_hash);
            self.drive.sessions.push(saved.row.clone());
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
            .filter(|(_, s)| s.first_seen.min(s.row.created_millis) <= before)
            .map(|(id, s)| (*id, s.row.entry_hash))
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
        let id = self.private_sessions.next.max(1);
        let next = id
            .checked_add(1)
            .ok_or(Error::SizeLimitExceeded("private Session records"))?;
        let hash = saved.row.entry_hash;
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
        if !crate::node::drive::is_key_changed(&saved.row.session_id) {
            self.drive.news.push(saved.row.session_id.clone());
        }
        self.drive.sessions.push(saved.row.clone());
        self.private_sessions.hashes.insert(hash);
        self.private_sessions.records.insert(id, saved);
        self.private_sessions.next = next;
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
                    row,
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
        for (author, target, epoch, generation) in self.drive.floors.keys() {
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
                .is_none_or(|(m, _, _)| *m != membership)
            {
                return false;
            }
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
            if saved.row.author == self.me() && !holders.contains(peer) {
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
        if self.private_sessions.hashes.contains(&hash) {
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
        if !self.private_permitted(&record, &self.me()) {
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
                row,
                first_seen: now,
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
            .filter(|s| s.row.author == self.me())
            .map(|s| s.record.message.header.chain_id)
            .max()
    }
}
