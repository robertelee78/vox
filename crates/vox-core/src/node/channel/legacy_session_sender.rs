//! Publish this author's exact legacy Session hashes under its ordinary sender key (#787).
//! The scan cursor commits with the declaration and the advanced sender chain. A restart
//! cannot skip an unsaved declaration or reuse its message key. No step body is disclosed.

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

impl ChannelState {
    fn legacy_announced_through(&mut self, store: &Store) -> Result<Announcements> {
        if let Some(state) = &self.legacy_announced {
            return Ok(state.clone());
        }
        let state = match store.get_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_LEGACY_ANNOUNCED,
        )? {
            None => Announcements::default(),
            Some(segment) => {
                let bytes = open_segment(
                    &self.sek,
                    SegmentKind::KeyMaterial,
                    SEG_LEGACY_ANNOUNCED,
                    &segment,
                )?;
                let mut d = Decoder::new(&bytes);
                let (arity, version) = (d.array()?, d.uint()?);
                if !matches!((arity, version), (3, 1) | (4, 2)) || d.bytes()? != self.me() {
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
                            return Err(Error::MalformedAtRest(
                                "legacy Session announcement reader",
                            ));
                        }
                        let peer: Digest32 = d.bytes()?.try_into().map_err(|_| {
                            Error::MalformedAtRest("legacy Session announcement reader")
                        })?;
                        let grant = (d.uint()?, d.uint()?, d.uint()?, d.uint()?);
                        if readers.insert(peer, grant).is_some() {
                            return Err(Error::MalformedAtRest(
                                "duplicate Session announcement reader",
                            ));
                        }
                    }
                }
                d.finish()?;
                Announcements { through, readers }
            }
        };
        self.legacy_announced = Some(state.clone());
        Ok(state)
    }

    /// Announce at most one bounded page per maintenance turn, so a large legacy transcript
    /// does not monopolize the actor. The next turn continues from the committed own-feed mark.
    /// The subtype comes from this author's own sealed record of what it wrote, never a peer's
    /// name, a missing body, or a Session-floor sequence range.
    pub fn announce_legacy_sessions(&mut self, profile: &Profile, now_ms: u64) -> Result<usize> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let me = self.me();
        if !self.settled || self.has_left(&me) || !self.authors.contains_key(&me) {
            return Ok(0);
        }
        let previous = self.legacy_announced_through(profile.store())?;
        let mut readers = BTreeMap::new();
        for peer in self.consented() {
            if peer == me || self.has_left(&peer) || !self.supports_private(&peer) {
                continue;
            }
            if let Some((generation, iteration)) = self.entitled.get(&peer) {
                readers.insert(
                    peer,
                    (self.admission(&peer).0, self.epoch, *generation, *iteration),
                );
            }
        }
        // A published reader may already have consumed every earlier declaration. Its newly
        // authenticated capability or a new ordinary grant needs a fresh bounded scan. Keep
        // this audience in the same transaction as the cursor so restarting does not repeat
        // the entire history, or skip pages of a scan that had not committed.
        let new_reader = readers
            .iter()
            .any(|(peer, grant)| previous.readers.get(peer) != Some(grant));
        let through = if new_reader { 0 } else { previous.through };
        let verified = self.dag.verified_head(&me);
        if through >= verified && readers == previous.readers {
            return Ok(0);
        }
        let mut scanned = through;
        let mut steps = Vec::new();
        if let Some(feed) = self.dag.feed(&me) {
            for seq in
                through.saturating_add(1)..=verified.min(through.saturating_add(SCAN_PER_TURN))
            {
                let Some(entry) = feed.get(seq) else { break };
                scanned = seq;
                let hash = entry.entry_hash();
                if self.step_bodies.contains(&hash) {
                    steps.push(hash);
                    if steps.len() == MAX_LEGACY_SESSION_HASHES {
                        break;
                    }
                }
            }
        }
        if scanned == through && readers == previous.readers {
            return Ok(0);
        }
        steps.sort_unstable();
        let count = steps.len();
        let plaintext = if steps.is_empty() {
            None
        } else {
            Some(Zeroizing::new(
                LegacySessionIndex::new(now_ms, self.channel_id, me, steps)?.to_canonical_vec(),
            ))
        };
        let mut cursor = Encoder::new();
        cursor
            .array(4)
            .uint(2)
            .bytes(&me)
            .uint(scanned)
            .array(readers.len());
        for (peer, (membership, epoch, generation, iteration)) in &readers {
            cursor
                .array(5)
                .bytes(peer)
                .uint(*membership)
                .uint(*epoch)
                .uint(*generation)
                .uint(*iteration);
        }
        let cursor = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_LEGACY_ANNOUNCED,
            &cursor.finish(),
        )?;
        let persisted = (|| -> Result<Option<(Digest32, u64)>> {
            let mut batch = profile.store().batch()?;
            let posted = if let Some(plaintext) = plaintext {
                let signer = profile.signer()?;
                let payload = self.sender.encrypt(&plaintext)?.to_wire();
                let skeleton = self.next_skeleton(&me, &payload, now_ms);
                let entry = Entry::build_signed(signer, skeleton, payload)?;
                let hash = entry.entry_hash();
                let id = self.next_log_id;
                let log = seal_segment(&self.sek, SegmentKind::LogDb, id, &entry.to_wire())?;
                let sender = seal_segment(
                    &self.sek,
                    SegmentKind::KeyMaterial,
                    SEG_SENDER,
                    &self.sender.to_state(),
                )?;
                let seen = seal_segment(
                    &self.sek,
                    SegmentKind::Index,
                    id,
                    &first_seen_bytes(now_ms, false),
                )?;
                self.dag
                    .accept(
                        entry,
                        EntryKind::Content,
                        &signer.public_key(),
                        &self.admission,
                    )
                    .map_err(|_| Error::Profile("authored Session index failed acceptance"))?;
                batch.put_segment(&self.channel_id, SegmentKind::LogDb, id, &log)?;
                batch.put_segment(&self.channel_id, SegmentKind::Index, id, &seen)?;
                batch.put_segment(
                    &self.channel_id,
                    SegmentKind::KeyMaterial,
                    SEG_SENDER,
                    &sender,
                )?;
                Some((hash, id))
            } else {
                None
            };
            batch.put_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_LEGACY_ANNOUNCED,
                &cursor,
            )?;
            batch.commit()?;
            Ok(posted)
        })();
        let posted = match persisted {
            Ok(posted) => posted,
            Err(e) => {
                self.poisoned = true;
                self.save_error = Some(e.to_string());
                return Err(e);
            }
        };
        self.legacy_announced = Some(Announcements {
            through: scanned,
            readers,
        });
        if let Some((hash, id)) = posted {
            self.log_ids.insert(hash, id);
            self.next_log_id = id.saturating_add(1);
            self.retention.track(
                hash,
                Tracked {
                    log_id: id,
                    first_seen_ms: now_ms,
                    steps: false,
                    claimed_ms: Some(now_ms),
                    cache_id: None,
                },
            );
            self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(count)
    }
}
