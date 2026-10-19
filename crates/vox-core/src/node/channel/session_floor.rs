//! Public, root-authenticated Session history floors (ADR-031 SA-8).
//!
//! This is an explicit control subtype of the existing group-content carrier. Its nine-field
//! body is not a three-field encrypted GroupMessage. Published readers classify the carrier as
//! content, keep the signed entry, and skip its unknown body without interrupting room sync.
//! The enclosing Entry's root signature authenticates every field; no sender key is disclosed.

use super::session_projection::{floor_index, private_index};
use super::*;

const MARKER: &str = "vox/session-floor/v1";

pub(super) struct Floor {
    pub(super) room: Digest32,
    pub(super) author: Digest32,
    pub(super) recipient: Digest32,
    pub(super) epoch: u64,
    pub(super) generation: u64,
    pub(super) iteration: u64,
    pub(super) first_seq: u64,
    pub(super) membership: u64,
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

    pub(super) fn read(payload: &[u8]) -> Option<Self> {
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
    pub(crate) fn authorization_refreshing(error: &Error) -> bool {
        floor_index::refreshing(error)
    }

    pub(super) fn floor_author(
        &self,
        transaction: Transaction<'_, '_>,
        author: &Digest32,
    ) -> Result<floor_index::Author> {
        floor_index::author(transaction, &self.sek, &self.channel_id, author)
    }

    pub(super) fn session_floor(
        &self,
        transaction: Transaction<'_, '_>,
        key: &crate::node::drive::SessionFloorKey,
    ) -> Result<Option<crate::node::drive::SessionFloorBoundary>> {
        floor_index::floor(transaction, &self.sek, &self.channel_id, key)
    }

    pub(super) fn index_session_floors(&self, store: &Store) -> Result<()> {
        if !self.current_session_controls_ready(store)? {
            return Err(Error::StreamRefused(floor_index::REFRESHING));
        }
        Ok(())
    }

    /// Whether this author's own floor boundary is publishable: this author's control effects
    /// are complete through its committed head. Another author's still-building receipt never
    /// blocks this author's own boundary; readiness of the whole room is an answer the
    /// projection gives, not a gate on one author's own publication.
    fn own_floor_ready(&self, store: &Store, author: &Digest32) -> Result<()> {
        if !self.current_session_control_ready(store, author)? {
            return Err(Error::StreamRefused(floor_index::REFRESHING));
        }
        Ok(())
    }

    /// Publish the boundary before releasing the matching key or writing a Session step.
    pub(super) fn ensure_session_floors(
        &mut self,
        profile: &Profile,
        holders: &BTreeSet<Digest32>,
        now: u64,
    ) -> Result<()> {
        let me = self.me();
        self.own_floor_ready(profile.store(), &me)?;
        let members = self.drive_members();
        let Some(generation) = self.drive.chain.as_ref().map(SenderChain::chain_id) else {
            return Ok(());
        };
        // A room left and rejoined holds none of the old release. Detect its signed current
        // membership before writing a step, even if the actor's next lifecycle tick is later.
        for recipient in holders.iter().filter(|p| members.contains(*p)) {
            if self
                .session_floor(
                    Transaction::Snapshot(&profile.store().snapshot()?),
                    &(me, *recipient, self.epoch, generation),
                )?
                .is_some_and(|(membership, _, _)| membership != self.admission(recipient).0)
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
                .session_floor(Transaction::Snapshot(&profile.store().snapshot()?), &key)?
                .is_some_and(|(m, i, _)| m == membership && i >= iteration)
            {
                continue;
            }
            let head = self.dag.feed(&me).map_or(0, |feed| feed.max_seq());
            let first_seq = floor_index::first_sequence(
                profile.store(),
                &self.sek,
                &self.channel_id,
                &me,
                self.epoch,
                generation,
                iteration,
                head,
                |seq| {
                    self.entries
                        .read(profile.store(), &self.sek, &self.channel_id)?
                        .get(&me, seq)?
                        .ok_or(Error::MalformedAtRest("Session floor feed entry missing"))
                },
            )?
            .ok_or(Error::StreamRefused(floor_index::REFRESHING))?
            .map(Ok)
            .unwrap_or_else(|| {
                head.checked_add(2)
                    .ok_or(Error::MalformedAtRest("feed sequence exhausted"))
            })?;
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
            self.append_control_kind(profile, &floor.wire(), now, EntryKind::Content, false)?;
        }
        Ok(())
    }

    fn session_body_allowed(
        &self,
        transaction: Transaction<'_, '_>,
        entry: &Entry,
        recipient: &Digest32,
    ) -> Result<bool> {
        let Some(msg) = entry
            .payload
            .as_deref()
            .and_then(|p| GroupMessage::from_wire(p).ok())
        else {
            return Ok(true);
        };
        if msg.header.channel_id != drive_channel(&self.channel_id) {
            return Ok(true);
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
            return Ok(false);
        }
        if entry.skeleton.author_id == *recipient {
            return Ok(true);
        }
        // A partially rebuilt catalog cannot authorize a body using an obsolete floor.
        if self
            .floor_author(transaction, &entry.skeleton.author_id)?
            .through
            < self.dag.verified_head(&entry.skeleton.author_id)
        {
            return Ok(false);
        }
        if let Some((membership, iteration, seq)) = self.session_floor(transaction, &key)? {
            return Ok(membership == self.admission(recipient).0
                && msg.header.iteration >= iteration
                && entry.skeleton.seq >= seq);
        }
        // A published older author has no public floor record. This receiver can still
        // establish its own grant from the verified SKDM's chain: it cannot derive a key
        // before that release. This local evidence grants no forwarding rights to others.
        // After restart the sealed receiver state retains its live and skipped keys; already
        // rendered history remains in the cache, without inventing old grants for relays.
        Ok(*recipient == self.me()
            && msg.header.epoch == self.epoch
            && self
                .drive
                .receivers
                .get(&(entry.skeleton.author_id, msg.header.chain_id))
                .is_some_and(|chain| chain.can_open_iteration(msg.header.iteration)))
    }

    pub(super) fn session_entries_for_bounded(
        &mut self,
        store: &Store,
        peer: &Digest32,
        wants: &[crate::log::sync::WantRange],
        now_ms: u64,
        max_entries: usize,
        max_bytes: usize,
    ) -> Result<Vec<Vec<u8>>> {
        self.now_hint = self.now_hint.max(now_ms);
        // No whole-room projection gate here: the stored entries are authenticated, and each
        // served entry passes its own verified closure; the receiver places each record with
        // its own per-record Drive, generation and floor checks. Gating this serve on every
        // author's still-building receipt made a fresh member's own serve wait on peers whose
        // receipts only its serve could advance.
        let entries = self.entries.read(store, &self.sek, &self.channel_id)?;
        crate::log::sync::entries_for_wants_bounded(
            &self.dag,
            &entries,
            wants,
            max_entries,
            max_bytes,
        )?
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
            if expired
                || !self.session_body_allowed(
                    Transaction::Snapshot(&store.snapshot()?),
                    &entry,
                    peer,
                )?
            {
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
        staged: &[Vec<u8>],
        now_ms: u64,
    ) -> Result<()> {
        self.now_hint = self.now_hint.max(now_ms);
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
            if entry.payload.as_deref().is_some_and(is_session_floor) {
                // Refilled already published controls are authoritative now. New controls are
                // learned by their own publication Batch, never ahead of their durable locator.
                let published = self
                    .log_id_at(
                        Transaction::Snapshot(&store.snapshot()?),
                        &entry.entry_hash(),
                    )?
                    .is_some();
                if published {
                    let mut batch = store.batch()?;
                    private_index::observe_public(
                        &mut batch,
                        &self.sek,
                        &self.channel_id,
                        &entry,
                        self.epoch,
                    )?;
                    batch.commit()?;
                }
            }
            self.observe_legacy_drive_generation(&entry)?;
        }
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
        if entry.payload.is_none()
            || self.session_body_allowed(Transaction::Batch(batch), entry, &self.me())?
        {
            return Ok(false);
        }
        if self
            .floor_author(Transaction::Batch(batch), &entry.skeleton.author_id)?
            .through
            < self.dag.verified_head(&entry.skeleton.author_id)
        {
            // Pending is not denial: retain the encrypted body in its existing sealed log,
            // but do not render it. The bounded legacy migration retries once authorization
            // facts are complete. Its age is preserved before this publication commits.
            self.preserve_withheld_body_into(batch, entry)?;
            let hash = entry.entry_hash();
            let id =
                self.log_id_at(Transaction::Batch(batch), &hash)?
                    .ok_or(Error::MalformedAtRest(
                        "pending Session body locator missing",
                    ))?;
            if self
                .retention_get_in(Transaction::Batch(batch), &hash)?
                .is_none()
            {
                let segment = batch
                    .get_segment(&self.channel_id, SegmentKind::Index, id)?
                    .ok_or(Error::MalformedAtRest("pending Session body age missing"))?;
                let (first_seen, _) =
                    parse_first_seen(&open_segment(&self.sek, SegmentKind::Index, id, &segment)?)?;
                self.track_body_into(batch, hash, id, first_seen)?;
            }
            self.private_sessions.legacy_pending.insert(hash);
            entry.payload = None;
            return Ok(true);
        }
        self.preserve_withheld_body_into(batch, entry)?;
        let mut index = self.entries.write(batch, &self.sek, &self.channel_id)?;
        self.dag.prune_payload(&mut index, &entry.entry_hash())?;
        index.seal()?;
        entry.payload = None;
        Ok(true)
    }
}
