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

    pub(super) fn index_session_floors(&mut self) {
        if self.drive.floors_indexed {
            return;
        }
        let mut entries = Vec::new();
        for author in self.dag.authors() {
            if let Some(feed) = self.dag.feed(&author) {
                entries.extend(
                    feed.iter()
                        .filter(|e| e.skeleton.seq <= self.dag.verified_head(&author))
                        .filter(|e| e.payload.as_deref().is_some_and(is_session_floor))
                        .cloned(),
                );
            }
        }
        for entry in entries {
            self.learn_session_floor(&entry);
        }
        self.drive.floors_indexed = true;
    }

    /// Publish the boundary before releasing the matching key or writing a Session step.
    pub(super) fn ensure_session_floors(
        &mut self,
        profile: &Profile,
        holders: &BTreeSet<Digest32>,
        now: u64,
    ) -> Result<()> {
        self.index_session_floors();
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
            let first_seq = self
                .dag
                .feed(&me)
                .and_then(|feed| {
                    feed.iter().find_map(|e| {
                        let m = GroupMessage::from_wire(e.payload.as_deref()?).ok()?;
                        (m.header.channel_id == drive_channel(&self.channel_id)
                            && m.header.epoch == self.epoch
                            && m.header.chain_id == generation
                            && m.header.iteration >= iteration)
                            .then_some(e.skeleton.seq)
                    })
                })
                .unwrap_or_else(|| self.next_skeleton(&me, &[], now).seq.saturating_add(1));
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
        peer: &Digest32,
        wants: &[crate::log::sync::WantRange],
    ) -> Vec<Vec<u8>> {
        self.index_session_floors();
        crate::log::sync::entries_for_wants(&self.dag, wants)
            .into_iter()
            .map(|wire| {
                let Ok(mut entry) = Entry::from_wire(&wire) else {
                    return wire;
                };
                if !self.session_body_allowed(&entry, peer) {
                    entry.payload = None;
                }
                entry.to_wire()
            })
            .collect()
    }

    /// Run only after the DAG verified the incoming entries, and before any body reaches disk.
    pub(super) fn filter_received_session_bodies(&mut self, peer: Digest32, staged: &[Vec<u8>]) {
        self.index_session_floors();
        let verified = staged
            .iter()
            .filter_map(|wire| Entry::from_wire(wire).ok())
            .filter_map(|e| self.dag.get_by_hash(&e.entry_hash()).cloned())
            .filter(|e| e.skeleton.seq <= self.dag.verified_head(&e.skeleton.author_id))
            .collect::<Vec<_>>();
        for entry in &verified {
            self.learn_session_floor(entry);
            self.observe_legacy_drive_generation(entry);
        }
        let me = self.me();
        for entry in verified {
            let missing = entry.payload.is_none() || !self.session_body_allowed(&entry, &me);
            let position = (entry.skeleton.author_id, entry.skeleton.seq);
            if missing {
                self.dag.prune_payload(&entry.entry_hash());
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
    }
}
