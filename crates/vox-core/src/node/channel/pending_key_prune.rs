//! R14 pruning owns slot IDs and compact feed heads; key state stays in its committed store.
use super::*;
use crate::atrest::sek::WeakSek;
use crate::log::feed::Feed;

type Slot = (Digest32, u64);
type Feeds = BTreeMap<Digest32, (Feed, u64)>;
type Generations = Vec<(u64, Option<Stamp>)>;

/// The receiving-side R14 selection kernel never reads or copies a receiver ratchet.
/// A missing, nonexpired body stops the proof even though its generation is not known yet.
/// A superseded generation is removable only after a contiguous verified prefix reaches a
/// later generation and every entry under the old generation is rendered. The newest held
/// generation always stays. Expired bodies need no key; gaps and nonexpired missing bodies
/// stop the prefix proof. A sender only advances generations, so no older-generation entry
/// can arrive after the proved later-generation entry.
///
/// Also returns, per walked author, the first generation that is not finished: the lowest
/// unrendered generation in the verified prefix, capped at the newest one. Every generation
/// below it has all its entries in that prefix, rendered or expired.
fn select_receivers(
    held: &BTreeSet<Slot>,
    feeds: &Feeds,
    read: &impl EntryRead,
    mut rendered: impl FnMut(&Digest32) -> Result<bool>,
    mut expired: impl FnMut(u64) -> bool,
) -> Result<(Vec<Slot>, BTreeMap<Digest32, u64>)> {
    let mut gone = Vec::new();
    let mut finished = BTreeMap::new();
    for (author, (feed, head)) in feeds {
        let generations: Vec<u64> = held
            .range((*author, 0)..=(*author, u64::MAX))
            .map(|(_, chain)| *chain)
            .collect();
        if generations.len() <= 1 {
            continue;
        }
        let mut newest: Option<u64> = None;
        let mut unrendered = BTreeSet::new();
        for seq in 1..=*head {
            let Some(entry) = feed.get(read, seq)? else {
                break;
            };
            let Some(payload) = entry.payload.as_deref() else {
                if expired(entry.skeleton.claimed_ms) {
                    continue;
                }
                break;
            };
            if !matches!(classify_payload(payload), Ok(EntryKind::Content)) {
                continue;
            }
            let Ok(message) = GroupMessage::from_wire(payload) else {
                continue;
            };
            let chain = message.header.chain_id;
            newest = Some(newest.map_or(chain, |prior| prior.max(chain)));
            if !rendered(&entry.entry_hash())? {
                unrendered.insert(chain);
            }
        }
        let Some(newest) = newest else {
            continue;
        };
        finished.insert(
            *author,
            unrendered
                .first()
                .map_or(newest, |lowest| (*lowest).min(newest)),
        );
        let last = generations.last().copied().unwrap_or(0);
        gone.extend(
            generations
                .into_iter()
                .filter(|chain| *chain < newest && *chain < last && !unrendered.contains(chain))
                .map(|chain| (*author, chain)),
        );
    }
    Ok((gone, finished))
}

/// The deleted-receiver tombstones within [`SegmentKind::KeyMaterial`] (R1).
pub(super) const SEG_DELETED_RECEIVERS: u64 = 31;
/// At most this many exact tombstones per room; at the cap a key is kept, not deleted.
const TOMBSTONES_MAX: usize = 16_384;

/// The ordinary room receivers this node deleted (R1), `[1, [[author, epoch, floor, [chain,
/// ..]], ..]]`: per author and key epoch, every generation below `floor` and each listed
/// `chain`. A deleted key stays deleted: a later offer of it, by any route, is answered as
/// accepted and unchanged and installs nothing. Only this node's own committed prune writes it;
/// Drive keys are another namespace and never read it. Absent means empty; any other format is
/// refused, never reset.
#[derive(Clone, Default)]
pub(crate) struct DeletedReceivers {
    rows: BTreeMap<(Digest32, u64), (u64, BTreeSet<u64>)>,
    count: usize,
}

impl DeletedReceivers {
    fn invalid() -> Error {
        Error::MalformedAtRest("deleted receiver tombstones")
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 2 || d.uint()? != 1 {
            return Err(Self::invalid());
        }
        let mut record = Self::default();
        let mut previous: Option<(Digest32, u64)> = None;
        for _ in 0..d.array()? {
            if d.array()? != 4 {
                return Err(Self::invalid());
            }
            let author: Digest32 = d.bytes()?.try_into().map_err(|_| Self::invalid())?;
            let epoch = d.uint()?;
            let floor = d.uint()?;
            let mut chains = BTreeSet::new();
            for _ in 0..d.array()? {
                let chain = d.uint()?;
                if chain < floor || chains.last().is_some_and(|last| *last >= chain) {
                    return Err(Self::invalid());
                }
                chains.insert(chain);
            }
            if previous.is_some_and(|key| key >= (author, epoch))
                || (floor == 0 && chains.is_empty())
            {
                return Err(Self::invalid());
            }
            previous = Some((author, epoch));
            record.count += chains.len();
            if record.count > TOMBSTONES_MAX {
                return Err(Self::invalid());
            }
            record.rows.insert((author, epoch), (floor, chains));
        }
        d.finish()?;
        Ok(record)
    }

    fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2).uint(1).array(self.rows.len());
        for ((author, epoch), (floor, chains)) in &self.rows {
            e.array(4)
                .bytes(author)
                .uint(*epoch)
                .uint(*floor)
                .array(chains.len());
            for chain in chains {
                e.uint(*chain);
            }
        }
        e.finish()
    }

    /// The room's record as stored: read with its receivers at open, and by the prune under
    /// its writer.
    pub(super) fn load(sealed: Option<SealedSegment>, sek: &Sek) -> Result<Self> {
        match sealed {
            Some(sealed) => Self::decode(&open_segment(
                sek,
                SegmentKind::KeyMaterial,
                SEG_DELETED_RECEIVERS,
                &sealed,
            )?),
            None => Ok(Self::default()),
        }
    }

    fn save(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
        sek: &Sek,
        room: &Digest32,
    ) -> Result<()> {
        let sealed = seal_segment(
            sek,
            SegmentKind::KeyMaterial,
            SEG_DELETED_RECEIVERS,
            &self.encode(),
        )?;
        batch.put_segment(
            room,
            SegmentKind::KeyMaterial,
            SEG_DELETED_RECEIVERS,
            &sealed,
        )
    }

    /// Whether this node deleted `author`'s room receiver of `chain` in key epoch `epoch`.
    pub(crate) fn covers(&self, author: &Digest32, epoch: u64, chain: u64) -> bool {
        self.rows
            .get(&(*author, epoch))
            .is_some_and(|(floor, chains)| chain < *floor || chains.contains(&chain))
    }

    /// Collapse the tombstones below `finished` (every generation below it is finished, see
    /// [`select_receivers`]) into the row's floor.
    fn compact(&mut self, author: Digest32, epoch: u64, finished: u64) {
        let Some((floor, chains)) = self.rows.get_mut(&(author, epoch)) else {
            return;
        };
        let Some(highest) = chains.range(..finished).next_back().copied() else {
            return;
        };
        *floor = (*floor).max(highest.saturating_add(1));
        let kept = chains.split_off(floor);
        self.count -= chains.len();
        *chains = kept;
    }

    /// Record one deletion. `false`: the record is at its cap, so the key is kept.
    fn delete(&mut self, author: Digest32, epoch: u64, chain: u64) -> bool {
        if self.covers(&author, epoch, chain) {
            return true;
        }
        if self.count >= TOMBSTONES_MAX {
            return false;
        }
        // `test-knobs` mutant `VOX_TEST_FWD_MUTANT=floor-not-exact`: the deletion is recorded as
        // "deleted through" (the floor moves past it) rather than exactly, so an older generation
        // still to come is refused as if deleted. Never selectable without the feature.
        #[cfg(feature = "test-knobs")]
        if std::env::var("VOX_TEST_FWD_MUTANT").as_deref() == Ok("floor-not-exact") {
            let (floor, chains) = self.rows.entry((author, epoch)).or_default();
            *floor = (*floor).max(chain.saturating_add(1));
            let kept = chains.split_off(floor);
            self.count -= chains.len();
            *chains = kept;
            eprintln!(
                "test-knobs: floor-not-exact mutant engaged: deleted through generation {chain}"
            );
            return true;
        }
        self.rows
            .entry((author, epoch))
            .or_default()
            .1
            .insert(chain);
        self.count += 1;
        true
    }
}

/// The exact origin safety decision: which retired generations are still needed (live
/// included), and the nonsecret generation IDs it was taken over.
struct Origins {
    needed: super::OriginsNeeded,
    live: u64,
    generations: Generations,
}

pub(crate) struct Prepared {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    me: Digest32,
    sek: WeakSek,
    index: entry_store::EntryIndex,
    slots: BTreeSet<Slot>,
    feeds: Feeds,
    normal: receiver_overlay::Stamp,
    written: (receiver_overlay::Stamp, receiver_overlay::Stamp),
    expiry: Option<(u64, u64)>,
    origins: Option<Origins>,
    origin_error: Option<Error>,
    pin: Option<history::PendingHistoryRead>,
}

/// Committed facts are independent of a later error (receiver and origin writes are separate).
pub(crate) struct Saved {
    pub(crate) receivers: usize,
    pub(crate) origins: usize,
    pub(crate) result: Result<()>,
}
impl Saved {
    pub(crate) fn changed(&self) -> bool {
        self.receivers != 0 || self.origins != 0
    }
}

pub(crate) struct Completed {
    pending: Prepared,
    removed: Vec<Slot>,
    deleted: Option<DeletedReceivers>,
    saved: Saved,
    poison: bool,
}
impl Completed {
    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.pending.room == channel.channel_id
            && self.pending.epoch == channel.epoch
            && Arc::ptr_eq(owner, &self.pending.owner)
            && channel
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.pending.pin.take()
    }
    pub(crate) fn into_result(self) -> Result<Saved> {
        Ok(self.saved)
    }
    pub(crate) fn finish(mut self, channel: &mut ChannelState, _store: &Store) -> Result<Saved> {
        if self.can_install(channel, &self.pending.owner) {
            if self.saved.receivers != 0 {
                for slot in &self.removed {
                    channel.receivers.remove(slot);
                }
                if let Some(deleted) = self.deleted.take() {
                    channel.deleted_receivers = deleted;
                }
                if let Err(error) = channel.receiver_persistence.advance_normal() {
                    self.saved.result = Err(error);
                    self.poison = true;
                }
            }
            if self.saved.origins != 0 {
                if let Some(origins) = &self.pending.origins {
                    channel.origins.retain_needed(
                        &self.pending.room,
                        self.pending.epoch,
                        |generation| origins.needed.keeps(generation, origins.live),
                    );
                }
            }
            if self.poison {
                if let Err(error) = &self.saved.result {
                    channel.poison(error);
                }
            }
            channel.release_pending_text(&self.pending.owner, false);
        }
        Ok(self.saved)
    }
}

impl ChannelState {
    pub(crate) fn prepare_pending_key_prune(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        trusted: &Arc<BTreeSet<Digest32>>,
        now: crate::time::Ms,
    ) -> Result<Option<Prepared>> {
        if self.poisoned.get() {
            return Err(self.save_failure());
        }
        self.keyring = Arc::clone(trusted);
        // Uncommitted ratchets cannot be reconstructed from disk. Their ordinary bounded
        // render/drive completion persists them; keep this tick's source untouched until then.
        if self.chains_advanced {
            return Ok(None);
        }
        let origins = (|| -> Result<Option<Origins>> {
            if self.key_generations() <= 1 {
                return Ok(None);
            }
            // The migration reads the retained origins for the catch-up it keeps (R9): no
            // origin is deleted before it commits.
            if !self.forward_migrated() {
                return Ok(None);
            }
            match self.require_governance_ready(store, crate::time::Ms(self.now_hint)) {
                Ok(_) if self.governance_display_current(self.now_hint) => {}
                Ok(_) => return Ok(None),
                Err(error) if governance::refreshing(&error) => return Ok(None),
                Err(error) => return Err(error),
            }
            let needed = self.origins_needed(store, trusted, now)?;
            let live = self.sender.chain_id();
            let generations = self
                .origins
                .generations(&self.channel_id, self.epoch, &self.me());
            // `test-knobs`: each new origin decision is said once, so a proof can stage after it.
            #[cfg(feature = "test-knobs")]
            {
                static SAID: std::sync::Mutex<BTreeMap<Digest32, String>> =
                    std::sync::Mutex::new(BTreeMap::new());
                let held: Vec<u64> = generations.iter().map(|(chain, _)| *chain).collect();
                let kept: Vec<u64> = held
                    .iter()
                    .copied()
                    .filter(|chain| needed.keeps(*chain, live))
                    .collect();
                let said = format!("keeps generations {kept:?} of {held:?}");
                let mut last = SAID
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if last.get(&self.channel_id) != Some(&said) {
                    eprintln!(
                        "test-knobs: origin prune of room {} {said}",
                        crate::node::network::short_id(self.channel_id)
                    );
                    last.insert(self.channel_id, said);
                }
            }
            // No origin-key cloning or serialization on a quiet tick, even with many held keys.
            Ok(generations
                .iter()
                .any(|(chain, _)| !needed.keeps(*chain, live))
                .then_some(Origins {
                    needed,
                    live,
                    generations,
                }))
        })();
        let (origins, origin_error) = match origins {
            Ok(origins) => (origins, None),
            Err(error) => (None, Some(error)),
        };
        let slots: BTreeSet<_> = self.receivers.keys().copied().collect();
        let authors: BTreeSet<_> = slots.iter().map(|(author, _)| *author).collect();
        let feeds = authors
            .into_iter()
            .filter_map(|author| {
                self.dag
                    .feed(&author)
                    .map(|feed| (author, (feed.clone(), self.dag.verified_head(&author))))
            })
            .collect();
        let normal = self.receiver_persistence.next_normal()?;
        let written =
            receiver_overlay::written_stamps(&store.snapshot()?, &self.sek, &self.channel_id)?;
        let expiry = self
            .governance_display_current(self.now_hint)
            .then_some((self.now_hint, self.effective_retention()));
        let index = self.entries.fork_reader();
        let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(Some(Prepared {
            owner,
            room: self.channel_id,
            epoch: self.epoch,
            me: self.me(),
            sek: self.sek.reader(),
            index,
            slots,
            feeds,
            normal,
            written,
            expiry,
            origins,
            origin_error,
            pin: Some(pin),
        }))
    }
}

impl Prepared {
    pub(crate) fn run(mut self, store: &Store, _signer: &dyn RootSigner) -> Completed {
        let mut removed = Vec::new();
        let mut deleted = None;
        // The retired release index (segment kind 18) held copies of signed releases that
        // nothing reads: the first pass deletes them all, in one batch.
        let purged = (|| -> Result<()> {
            let releases = SegmentKind::ReceiverReleases;
            if store
                .snapshot()?
                .segment_id_after(&self.room, releases, None)?
                .is_none()
            {
                return Ok(());
            }
            let mut batch = store.batch()?;
            while let Some(id) = batch.segment_id_after(&self.room, releases, None)? {
                batch.delete_segment(&self.room, releases, id)?;
            }
            batch.commit()
        })();
        let mut saved = Saved {
            receivers: 0,
            origins: 0,
            result: self.origin_error.take().map_or(Ok(()), Err),
        };
        let mut poison = false;
        if let Err(error) = purged {
            if saved.result.is_ok() {
                saved.result = Err(error);
            }
        }
        let mut writing = false;
        let receiver_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.sek.with(|sek| -> Result<()> {
                let snapshot = Arc::new(store.snapshot()?);
                let read = self
                    .index
                    .read_snapshot(Arc::clone(&snapshot), sek, &self.room)?;
                let rendered = self.index.render_snapshot(snapshot, sek, &self.room)?;
                let (mut gone, finished) = select_receivers(
                    &self.slots,
                    &self.feeds,
                    &read,
                    |hash| rendered.fact(hash).map(|fact| fact.is_some()),
                    |claimed| {
                        self.expiry
                            .is_some_and(|(now, ttl)| expired_at(claimed, now, ttl))
                    },
                )?;
                if gone.is_empty() {
                    return Ok(());
                }
                drop(rendered);
                drop(read);
                // The legacy canonical format needs a whole-map rewrite only on actual deletion.
                // Reconstruct under the native writer, never by copying live room key caches.
                let mut batch = store.batch()?;
                receiver_overlay::require_written_stamps(&batch, sek, &self.room, self.written)?;
                let snapshot = store.snapshot()?;
                let sealed =
                    snapshot.get_segment(&self.room, SegmentKind::KeyMaterial, SEG_RECEIVERS)?;
                let base = receiver_overlay::digest(sealed.as_ref());
                let mut receivers = match sealed {
                    Some(sealed) => parse_receivers(&open_segment(
                        sek,
                        SegmentKind::KeyMaterial,
                        SEG_RECEIVERS,
                        &sealed,
                    )?)?,
                    None => BTreeMap::new(),
                };
                receiver_overlay::merge(
                    &snapshot,
                    sek,
                    &self.room,
                    &self.me,
                    self.epoch,
                    base,
                    &mut receivers,
                )?;
                if !receivers.keys().copied().eq(self.slots.iter().copied()) {
                    return Err(Error::MalformedAtRest("key prune receiver basis changed"));
                }
                drop(snapshot);
                // R1: each deletion leaves an exact tombstone in this same batch; finished
                // generations collapse into their author's floor first. At the cap, a key is kept.
                let mut tombstones = DeletedReceivers::load(
                    batch.get_segment(
                        &self.room,
                        SegmentKind::KeyMaterial,
                        SEG_DELETED_RECEIVERS,
                    )?,
                    sek,
                )?;
                for (author, finished) in &finished {
                    tombstones.compact(*author, self.epoch, *finished);
                }
                gone.retain(|slot| {
                    receivers
                        .get(slot)
                        .is_some_and(|chain| tombstones.delete(slot.0, chain.epoch(), slot.1))
                });
                if gone.is_empty() {
                    return Ok(());
                }
                for slot in &gone {
                    receivers.remove(slot);
                }
                writing = true;
                let segment = seal_segment(
                    sek,
                    SegmentKind::KeyMaterial,
                    SEG_RECEIVERS,
                    &receivers_bytes(&receivers),
                )?;
                receiver_overlay::rewrite(&mut batch, sek, &self.room, &segment, self.normal)?;
                tombstones.save(&mut batch, sek, &self.room)?;
                // Drive is not modified by receiver deletion. Its exact written stamp was checked,
                // so retaining its durable segment avoids copying or reserializing any drive keys.
                batch.commit()?;
                saved.receivers = gone.len();
                removed = gone;
                deleted = Some(tombstones);
                writing = false;
                Ok(())
            })
        }))
        .unwrap_or_else(|_| Err(Error::Profile("receiver pruning worker stopped")));
        if let Err(error) = receiver_result {
            poison |= writing;
            saved.result = Err(error);
        }
        if let Some(origins) = self.origins.as_ref().filter(|_| !poison) {
            writing = false;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.sek.with(|sek| -> Result<()> {
                    let mut batch = store.batch()?;
                    let sealed = batch
                        .get_segment(&self.room, SegmentKind::KeyMaterial, SEG_ORIGINS)?
                        .ok_or(Error::MalformedAtRest("key prune origins missing"))?;
                    let mut candidate = OriginKeyStore::from_state(&open_segment(
                        sek,
                        SegmentKind::KeyMaterial,
                        SEG_ORIGINS,
                        &sealed,
                    )?)?;
                    if candidate.generations(&self.room, self.epoch, &self.me)
                        != origins.generations
                    {
                        return Err(Error::MalformedAtRest("key prune origin basis changed"));
                    }
                    let gone = candidate.retain_needed(&self.room, self.epoch, |generation| {
                        origins.needed.keeps(generation, origins.live)
                    });
                    if gone == 0 {
                        return Ok(());
                    }
                    let segment = seal_segment(
                        sek,
                        SegmentKind::KeyMaterial,
                        SEG_ORIGINS,
                        &candidate.to_state(),
                    )?;
                    writing = true;
                    batch.put_segment(
                        &self.room,
                        SegmentKind::KeyMaterial,
                        SEG_ORIGINS,
                        &segment,
                    )?;
                    batch.commit()?;
                    saved.origins = gone;
                    writing = false;
                    Ok(())
                })
            }))
            .unwrap_or_else(|_| Err(Error::Profile("origin pruning worker stopped")));
            if let Err(error) = result {
                poison |= writing;
                if saved.result.is_ok() {
                    saved.result = Err(error);
                }
            }
        }
        Completed {
            pending: self,
            removed,
            deleted,
            saved,
            poison,
        }
    }
}
