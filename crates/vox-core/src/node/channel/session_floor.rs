//! Public, root-authenticated Session history floors (ADR-031 SA-8).
//!
//! This is an explicit control subtype of the existing group-content carrier. Its nine-field
//! body is not a three-field encrypted GroupMessage. Published readers classify the carrier as
//! content, keep the signed entry, and skip its unknown body without interrupting room sync.
//! The enclosing Entry's root signature authenticates every field; no sender key is disclosed.

use super::*;

const MARKER: &str = "vox/session-floor/v1";

struct Floor {
    room: Digest32,
    author: Digest32,
    recipient: Digest32,
    epoch: u64,
    generation: u64,
    iteration: u64,
    first_seq: u64,
    membership: u64,
}

impl Floor {
    fn wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(9)
            .text(MARKER)
            .bytes(&self.room)
            .bytes(&self.author)
            .bytes(&self.recipient)
            .uint(self.epoch)
            .uint(self.generation)
            .uint(self.iteration)
            .uint(self.first_seq)
            .uint(self.membership);
        let mut out = GROUP_MSG_SIGN_DOMAIN.as_bytes().to_vec();
        out.extend(e.finish());
        out
    }

    fn read(payload: &[u8]) -> Option<Self> {
        let mut d = Decoder::new(payload.strip_prefix(GROUP_MSG_SIGN_DOMAIN.as_bytes())?);
        if d.array().ok()? != 9 || d.text().ok()? != MARKER {
            return None;
        }
        let f = Self {
            room: d.bytes().ok()?.try_into().ok()?,
            author: d.bytes().ok()?.try_into().ok()?,
            recipient: d.bytes().ok()?.try_into().ok()?,
            epoch: d.uint().ok()?,
            generation: d.uint().ok()?,
            iteration: d.uint().ok()?,
            first_seq: d.uint().ok()?,
            membership: d.uint().ok()?,
        };
        d.finish().ok()?;
        (f.wire() == payload).then_some(f)
    }
}

/// Whether a payload is a canonical floor control record. Its enclosing verified log entry
/// supplies authentication. Retention must preserve these controls, as it does checkpoints.
pub(crate) fn is_session_floor(payload: &[u8]) -> bool {
    Floor::read(payload).is_some()
}

impl ChannelState {
    fn learn_session_floor(&mut self, entry: &Entry) {
        let Some(floor) = entry.payload.as_deref().and_then(Floor::read) else {
            return;
        };
        if floor.room != self.channel_id
            || floor.author != entry.skeleton.author_id
            || floor.epoch > self.epoch
            || floor.first_seq > entry.skeleton.seq.saturating_add(1)
        {
            return;
        }
        let key = (floor.author, floor.recipient, floor.epoch, floor.generation);
        let value = (floor.membership, floor.iteration, floor.first_seq);
        let old = self.drive.floors.get(&key).copied();
        if old.is_none_or(|old| value > old) {
            self.drive.floors.insert(key, value);
            // A newly learned authorization can make a body available from a peer that could
            // not serve it before the floor arrived. Omission hints are never permanent facts.
            self.drive.omitted.clear();
        }
    }

    pub(super) fn index_session_floors(&mut self, store: &Store) -> Result<()> {
        if self.drive.floors_indexed {
            return Ok(());
        }
        let indexed = (|| -> Result<()> {
            for author in self.dag.authors() {
                let head = self.dag.verified_head(&author);
                for seq in 1..=head {
                    let entry = self
                        .entries
                        .read(store, &self.sek, &self.channel_id)?
                        .get(&author, seq)?
                        .ok_or(Error::MalformedAtRest("Session floor feed entry missing"))?;
                    if entry.payload.as_deref().is_some_and(is_session_floor) {
                        self.learn_session_floor(&entry);
                    }
                }
            }
            self.drive.floors_indexed = true;
            Ok(())
        })();
        if let Err(ref error) = indexed {
            self.poison(error);
        }
        indexed
    }

    /// Publish the boundary before releasing the matching key or writing a Session step.
    pub(super) fn ensure_session_floors(
        &mut self,
        profile: &Profile,
        holders: &BTreeSet<Digest32>,
        now: u64,
    ) -> Result<()> {
        self.index_session_floors(profile.store())?;
        let me = self.me();
        let members = self.drive_members();
        let Some(generation) = self.drive.chain.as_ref().map(SenderChain::chain_id) else {
            return Ok(());
        };
        // A room left and rejoined holds none of the old release. Detect its signed current
        // membership before writing a step, even if the actor's next lifecycle tick is later.
        for recipient in holders.iter().filter(|p| members.contains(*p)) {
            if self
                .drive
                .floors
                .get(&(me, *recipient, self.epoch, generation))
                .is_some_and(|(membership, _, _)| *membership != self.admission(recipient).0)
            {
                self.drive.forget(&[*recipient]);
            }
        }
        let owed = self.drive.take_owed(&members, holders);
        if !owed.is_empty() {
            // Persist the new mark before its public floor: a restart cannot restore an old
            // delivered mark beside a newer floor and silently skip the replacement release.
            self.persist_drive(profile.store())?;
        }
        let mut marks = holders
            .iter()
            .filter(|p| members.contains(*p))
            .filter_map(|p| self.drive.floor_mark(p).map(|(g, i)| (*p, g, i)))
            .collect::<Vec<_>>();
        // This also preserves the author's generation when every old step body is withheld
        // on rejoin, including a Session with no other drive holders.
        marks.push((me, generation, 0));
        for (recipient, generation, iteration) in marks {
            let key = (me, recipient, self.epoch, generation);
            let membership = self.admission(&recipient).0;
            if self
                .drive
                .floors
                .get(&key)
                .is_some_and(|(m, i, _)| *m == membership && *i >= iteration)
            {
                continue;
            }
            let head = self.dag.feed(&me).map_or(0, |feed| feed.max_seq());
            let mut first_seq = head
                .checked_add(2)
                .ok_or(Error::MalformedAtRest("feed sequence exhausted"))?;
            let entries = self
                .entries
                .read(profile.store(), &self.sek, &self.channel_id)?;
            for seq in 1..=head {
                let entry = entries
                    .get(&me, seq)?
                    .ok_or(Error::MalformedAtRest("Session floor feed entry missing"))?;
                if entry
                    .payload
                    .as_deref()
                    .and_then(|p| GroupMessage::from_wire(p).ok())
                    .is_some_and(|m| {
                        m.header.channel_id == drive_channel(&self.channel_id)
                            && m.header.epoch == self.epoch
                            && m.header.chain_id == generation
                            && m.header.iteration >= iteration
                    })
                {
                    first_seq = seq;
                    break;
                }
            }
            drop(entries);
            let floor = Floor {
                room: self.channel_id,
                author: me,
                recipient,
                epoch: self.epoch,
                generation,
                iteration,
                first_seq,
                membership,
            };
            self.append_control_kind(profile, &floor.wire(), now, EntryKind::Content)?;
            self.drive
                .floors
                .insert(key, (membership, iteration, first_seq));
        }
        Ok(())
    }

    fn session_body_allowed(&self, entry: &Entry, recipient: &Digest32) -> bool {
        let Some(msg) = entry
            .payload
            .as_deref()
            .and_then(|p| GroupMessage::from_wire(p).ok())
        else {
            return true;
        };
        if msg.header.channel_id != drive_channel(&self.channel_id) {
            return true;
        }
        let key = (
            entry.skeleton.author_id,
            *recipient,
            msg.header.epoch,
            msg.header.chain_id,
        );
        if self
            .admission(recipient)
            .1
            .is_some_and(|at| entry.skeleton.claimed_ms < at)
        {
            return false;
        }
        if entry.skeleton.author_id == *recipient {
            return true;
        }
        if let Some((membership, iteration, seq)) = self.drive.floors.get(&key) {
            return *membership == self.admission(recipient).0
                && msg.header.iteration >= *iteration
                && entry.skeleton.seq >= *seq;
        }
        // A published older author has no public floor record. This receiver can still
        // establish its own grant from the verified SKDM's chain: it cannot derive a key
        // before that release. This local evidence grants no forwarding rights to others.
        // After restart the sealed receiver state retains its live and skipped keys; already
        // rendered history remains in the cache, without inventing old grants for relays.
        *recipient == self.me()
            && msg.header.epoch == self.epoch
            && self
                .drive
                .receivers
                .get(&(entry.skeleton.author_id, msg.header.chain_id))
                .is_some_and(|chain| chain.can_open_iteration(msg.header.iteration))
    }

    /// Keep signed skeletons while withholding bodies older than the recipient's authorization.
    pub(super) fn session_entries_for(
        &mut self,
        store: &Store,
        peer: &Digest32,
        wants: &[crate::log::sync::WantRange],
        now_ms: u64,
    ) -> Result<Vec<Vec<u8>>> {
        self.now_hint = self.now_hint.max(now_ms);
        self.index_session_floors(store)?;
        let entries = self.entries.read(store, &self.sek, &self.channel_id)?;
        crate::log::sync::entries_for_wants(&self.dag, &entries, wants)?
            .into_iter()
            .map(|wire| {
                let mut entry = Entry::from_wire(&wire)?;
                // Physical expiry is page-bounded. The saved age still withholds an
                // expired body immediately, including while a shorter TTL drains a backlog.
                let expired = entries.retention(&entry.entry_hash())?.is_some_and(|t| {
                    let ttl = if t.steps {
                        self.effective_step_retention()
                    } else {
                        self.effective_retention()
                    };
                    expired_at(t.base(), self.now_hint, ttl)
                });
                if expired || !self.session_body_allowed(&entry, peer) {
                    entry.payload = None;
                }
                Ok(entry.to_wire())
            })
            .collect()
    }

    /// Learn every verified floor before publication decides which received bodies to keep.
    /// Already published refills can be classified and withheld here atomically. New entries
    /// wait for their publication Batch, where their log locator and subtype become durable.
    pub(super) fn filter_received_session_bodies(
        &mut self,
        store: &Store,
        peer: Digest32,
        staged: &[Vec<u8>],
    ) -> Result<()> {
        self.index_session_floors(store)?;
        for wire in staged {
            let Ok(incoming) = Entry::from_wire(wire) else {
                continue;
            };
            let Some(entry) = self.entry(store, &incoming.entry_hash())? else {
                continue;
            };
            if entry.skeleton.seq > self.dag.verified_head(&entry.skeleton.author_id) {
                continue;
            }
            self.learn_session_floor(&entry);
            self.observe_legacy_drive_generation(&entry)?;
        }
        let me = self.me();
        for wire in staged {
            let Ok(incoming) = Entry::from_wire(wire) else {
                continue;
            };
            let Some(mut entry) = self.entry(store, &incoming.entry_hash())? else {
                continue;
            };
            if entry.skeleton.seq > self.dag.verified_head(&entry.skeleton.author_id) {
                continue;
            }
            let missing = entry.payload.is_none() || !self.session_body_allowed(&entry, &me);
            let position = (entry.skeleton.author_id, entry.skeleton.seq);
            // No body of a newly verified entry is removed before its publication can save
            // the exact subtype beside its assigned LogDb id. This closes the old volatile
            // observation gap between pre-filtering and absorb_batch.
            let published = {
                let snapshot = store.snapshot()?;
                self.log_id_at(Transaction::Snapshot(&snapshot), &entry.entry_hash())?
                    .is_some()
            };
            if published {
                let mut batch = store.batch()?;
                let withheld = self.filter_received_session_body_into(&mut batch, &mut entry)?;
                if withheld || self.legacy_sessions.dirty() {
                    batch.commit()?;
                    self.entries.committed();
                    self.legacy_sessions.committed();
                }
            }
            if missing {
                self.drive
                    .omitted
                    .entry(peer)
                    .or_insert_with(|| (std::time::Instant::now(), BTreeSet::new()))
                    .1
                    .insert(position);
            } else if let Some(omitted) = self.drive.omitted.get_mut(&peer) {
                omitted.1.remove(&position);
            }
        }
        Ok(())
    }

    /// Classify the authenticated body before withholding it, in the transaction that owns
    /// its published locator. The caller must use the resulting payload for rendering too.
    pub(super) fn filter_received_session_body_into(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        entry: &mut Entry,
    ) -> Result<bool> {
        self.inspect_legacy_body_into(batch, entry)?;
        if entry.payload.is_none() || self.session_body_allowed(entry, &self.me()) {
            return Ok(false);
        }
        let mut index = self.entries.write(batch, &self.sek, &self.channel_id)?;
        self.dag.prune_payload(&mut index, &entry.entry_hash())?;
        index.seal()?;
        entry.payload = None;
        Ok(true)
    }
}
