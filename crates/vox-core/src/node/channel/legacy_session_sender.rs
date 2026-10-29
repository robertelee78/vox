//! Publish this author's exact legacy Session hashes under its ordinary sender key (#787).
//! The scan cursor commits with the declaration and the advanced sender chain. A restart
//! cannot skip an unsaved declaration or reuse its message key. No step body is disclosed.

use super::session_projection::private_index;
use super::*;
use crate::node::content::{LegacySessionIndex, MAX_LEGACY_SESSION_HASHES};

// 17 is the retained board. This versioned cursor is part of the shared format-3 upgrade.
const SEG_LEGACY_ANNOUNCED: u64 = 18;
const SCAN_PER_TURN: u64 = 4096;

#[derive(Clone, Default)]
pub(super) struct Announcements {
    through: u64,
    // Reader -> (membership, epoch, ordinary grant generation, ordinary grant iteration).
    // A v0.4.4 reader consumes an unknown declaration's message key without caching its body.
    // Once it advertises support, resend metadata at its current grant, never an old key.
    readers: BTreeMap<Digest32, (u64, u64, u64, u64)>,
}

pub(crate) struct PendingAnnouncement {
    append: pending_text::PendingText,
    room: Digest32,
    me: Digest32,
    sek: crate::atrest::sek::WeakSek,
    previous: Option<Announcements>,
    readers: BTreeMap<Digest32, (u64, u64, u64, u64)>,
    feed: Option<crate::log::feed::Feed>,
    verified: u64,
    now: crate::time::Ms,
}

pub(crate) struct CompletedAnnouncement {
    append: pending_text::CompletedText,
    state: Option<Announcements>,
    pub(crate) count: usize,
    pub(crate) complete: bool,
}

impl CompletedAnnouncement {
    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.append.can_install(channel, owner)
    }
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.append.take_history_pin()
    }
    pub(crate) fn into_result(self) -> Result<(usize, bool)> {
        self.append.result.map(|_| (self.count, self.complete))
    }
}

impl ChannelState {
    pub(crate) fn prepare_pending_legacy_announcement(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
    ) -> Result<Option<PendingAnnouncement>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .sparse_enabled()
        {
            return Ok(None);
        }
        self.ensure_local_append_available(store)?;
        let me = self.me();
        if !self.settled || self.has_left(&me) || !self.authors.contains_key(&me) {
            return Ok(None);
        }
        let mut readers = BTreeMap::new();
        for peer in self.authors.keys() {
            if *peer == me || self.has_left(peer) || !self.has_consented(store, peer)? {
                continue;
            }
            if !self.current_session_control_ready(store, peer)? {
                return Err(Error::StreamRefused(private_session::CONTROL_REFRESHING));
            }
            if private_index::control(&store.snapshot()?, &self.sek, &self.channel_id, peer)?
                .support
                .is_none()
            {
                continue;
            }
            if let Some((generation, iteration)) = self.entitled.get(peer) {
                readers.insert(
                    *peer,
                    (self.admission(peer).0, self.epoch, *generation, *iteration),
                );
            }
        }
        let verified = self.dag.verified_head(&me);
        if self
            .legacy_announced
            .as_ref()
            .is_some_and(|previous| previous.through >= verified && previous.readers == readers)
        {
            return Ok(None);
        }
        let previous = self.legacy_announced.clone();
        let feed = self.dag.feed(&me).cloned();
        Ok(Some(PendingAnnouncement {
            append: self.prepare_pending_control(store, owner, now)?,
            room: self.channel_id,
            me,
            sek: self.sek.reader(),
            previous,
            readers,
            feed,
            verified,
            now,
        }))
    }

    pub(crate) fn finish_pending_legacy_announcement(
        &mut self,
        store: &Store,
        completed: CompletedAnnouncement,
    ) -> Result<(usize, bool)> {
        let matching = self
            .pending_text
            .as_ref()
            .is_some_and(|owner| completed.can_install(self, owner));
        if matching {
            if let Some(state) = completed.state {
                self.legacy_announced = Some(state);
            }
        }
        self.finish_pending_text(store, completed.append)
            .map(|_| (completed.count, completed.complete))
    }
}

impl PendingAnnouncement {
    pub(crate) fn run(mut self, store: &Store, signer: &dyn RootSigner) -> CompletedAnnouncement {
        let mut state = None;
        let mut count = 0;
        let mut complete = false;
        let mut candidate = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let previous = match self.previous.take() {
                Some(state) => state,
                None => match store.get_segment(
                    &self.room,
                    SegmentKind::KeyMaterial,
                    SEG_LEGACY_ANNOUNCED,
                )? {
                    Some(segment) => self.sek.with(|sek| {
                        Announcements::parse(
                            &open_segment(
                                sek,
                                SegmentKind::KeyMaterial,
                                SEG_LEGACY_ANNOUNCED,
                                &segment,
                            )?,
                            &self.me,
                        )
                    })?,
                    None => Announcements::default(),
                },
            };
            let new_reader = self
                .readers
                .iter()
                .any(|(peer, grant)| previous.readers.get(peer) != Some(grant));
            let through = if new_reader { 0 } else { previous.through };
            if through >= self.verified && self.readers == previous.readers {
                complete = true;
                state = Some(previous);
                return Ok(pending_text::Saved::Governance(None));
            }
            let mut scanned = through;
            let mut steps = Vec::new();
            self.sek.with(|sek| {
                let entries = entry_store::EntryIndex::default();
                let read = entries.read(store, sek, &self.room)?;
                if let Some(feed) = &self.feed {
                    for seq in through.saturating_add(1)
                        ..=self.verified.min(through.saturating_add(SCAN_PER_TURN))
                    {
                        let Some(entry) = feed.get(&read, seq)? else {
                            break;
                        };
                        scanned = seq;
                        if entry_steps_in(&entries, read.transaction(), sek, &self.room, &entry)? {
                            steps.push(entry.entry_hash());
                            if steps.len() == MAX_LEGACY_SESSION_HASHES {
                                break;
                            }
                        }
                    }
                }
                Ok(())
            })?;
            complete = scanned >= self.verified;
            if scanned == through && self.readers == previous.readers {
                return Ok(pending_text::Saved::Governance(None));
            }
            steps.sort_unstable();
            count = steps.len();
            let next = Announcements {
                through: scanned,
                readers: self.readers.clone(),
            };
            let cursor = self.sek.with(|sek| next.seal(sek, &self.me))?;
            candidate = Some(next);
            if steps.is_empty() {
                let mut batch = store.batch()?;
                batch.put_segment(
                    &self.room,
                    SegmentKind::KeyMaterial,
                    SEG_LEGACY_ANNOUNCED,
                    &cursor,
                )?;
                batch.commit()?;
                state = candidate.take();
                Ok(pending_text::Saved::Governance(None))
            } else {
                let plaintext = Zeroizing::new(
                    LegacySessionIndex::new(self.now.get(), self.room, self.me, steps)?
                        .to_canonical_vec(),
                );
                let hash = self
                    .append
                    .append_legacy_index_owned(store, signer, &plaintext, cursor, self.now)?;
                state = candidate.take();
                Ok(pending_text::Saved::Governance(Some(hash)))
            }
        }))
        .unwrap_or_else(|_| Err(Error::Profile("legacy Session announcement worker stopped")));
        // Append cleanup can fail after its actual transaction. Its cursor/feed still install.
        if self.append.legacy_index_committed() && state.is_none() {
            state = candidate;
        }
        let append = self.append.complete_control(result);
        CompletedAnnouncement {
            append,
            state,
            count,
            complete,
        }
    }
}

/// Shared exact subtype algorithm, also used by the live ChannelState entry_steps_in.
pub(super) fn entry_steps_in(
    entries: &entry_store::EntryIndex,
    transaction: Transaction<'_, '_>,
    sek: &Sek,
    room: &Digest32,
    entry: &Entry,
) -> Result<bool> {
    let index = entries.view(transaction, sek, room)?;
    let hash = entry.entry_hash();
    Ok(if let Some(tracked) = index.retention(&hash)? {
        tracked.steps
    } else if let Some(body) = entry.payload.as_deref() {
        is_step_body(room, body)
    } else {
        let Some(log) = index.log_id(&hash)? else {
            return Ok(false);
        };
        let segment = match transaction {
            Transaction::Snapshot(snapshot) => {
                snapshot.get_segment(room, SegmentKind::Index, log)?
            }
            Transaction::Batch(batch) => batch.get_segment(room, SegmentKind::Index, log)?,
        };
        match segment {
            Some(segment) => {
                parse_first_seen(&open_segment(sek, SegmentKind::Index, log, &segment)?)?.1
            }
            None => false,
        }
    })
}

impl Announcements {
    fn seal(&self, sek: &Sek, me: &Digest32) -> Result<SealedSegment> {
        let mut cursor = Encoder::new();
        cursor
            .array(4)
            .uint(2)
            .bytes(me)
            .uint(self.through)
            .array(self.readers.len());
        for (peer, (membership, epoch, generation, iteration)) in &self.readers {
            cursor
                .array(5)
                .bytes(peer)
                .uint(*membership)
                .uint(*epoch)
                .uint(*generation)
                .uint(*iteration);
        }
        seal_segment(
            sek,
            SegmentKind::KeyMaterial,
            SEG_LEGACY_ANNOUNCED,
            &cursor.finish(),
        )
    }

    /// Parse the complete cursor before distinguishing it from the former own-history slot.
    pub(super) fn parse(bytes: &[u8], me: &Digest32) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let (arity, version) = (d.array()?, d.uint()?);
        if !matches!((arity, version), (3, 1) | (4, 2)) || d.bytes()? != me {
            return Err(Error::MalformedAtRest("legacy Session announcement cursor"));
        }
        let through = d.uint()?;
        let mut readers = BTreeMap::new();
        if version == 2 {
            let count = d.array()?;
            if count > AUTHORS_HARD_LIMIT {
                return Err(Error::MalformedAtRest(
                    "legacy Session announcement readers",
                ));
            }
            for _ in 0..count {
                if d.array()? != 5 {
                    return Err(Error::MalformedAtRest("legacy Session announcement reader"));
                }
                let peer: Digest32 = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedAtRest("legacy Session announcement reader"))?;
                let grant = (d.uint()?, d.uint()?, d.uint()?, d.uint()?);
                if readers.insert(peer, grant).is_some() {
                    return Err(Error::MalformedAtRest(
                        "duplicate Session announcement reader",
                    ));
                }
            }
        }
        d.finish()?;
        Ok(Self { through, readers })
    }
}
