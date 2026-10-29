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
fn select_receivers(
    held: &BTreeSet<Slot>,
    feeds: &Feeds,
    read: &impl EntryRead,
    mut rendered: impl FnMut(&Digest32) -> Result<bool>,
    mut expired: impl FnMut(u64) -> bool,
) -> Result<Vec<Slot>> {
    let mut gone = Vec::new();
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
        let last = generations.last().copied().unwrap_or(0);
        gone.extend(
            generations
                .into_iter()
                .filter(|chain| *chain < newest && *chain < last && !unrendered.contains(chain))
                .map(|chain| (*author, chain)),
        );
    }
    Ok(gone)
}

/// The exact origin safety decision contains only a floor and nonsecret generation IDs.
struct Origins {
    floor: u64,
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
                if let Err(error) = channel.receiver_persistence.advance_normal() {
                    self.saved.result = Err(error);
                    self.poison = true;
                }
            }
            if self.saved.origins != 0 {
                if let Some(origins) = &self.pending.origins {
                    channel.origins.retain_from(
                        &self.pending.room,
                        self.pending.epoch,
                        origins.floor,
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
        full: &BTreeSet<Digest32>,
        trusted: &BTreeSet<Digest32>,
        now: crate::time::Ms,
    ) -> Result<Option<Prepared>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        // Uncommitted ratchets cannot be reconstructed from disk. Their ordinary bounded
        // render/drive completion persists them; keep this tick's source untouched until then.
        if self.chains_advanced {
            return Ok(None);
        }
        let origins = (|| -> Result<Option<Origins>> {
            if self.key_generations() <= 1 {
                return Ok(None);
            }
            match self.owed_consents(store, full) {
                Ok(owed) if owed.is_empty() => {}
                Ok(_) => return Ok(None),
                Err(error) if governance::refreshing(&error) => return Ok(None),
                Err(error) => return Err(error),
            }
            match self.require_governance_ready(store, crate::time::Ms(self.now_hint)) {
                Ok(_) if self.governance_display_current(self.now_hint) => {}
                Ok(_) => return Ok(None),
                Err(error) if governance::refreshing(&error) => return Ok(None),
                Err(error) => return Err(error),
            }
            let floor = self
                .oldest_generation_needed(trusted, now)
                .unwrap_or(u64::MAX)
                .min(self.sender.chain_id());
            let generations = self
                .origins
                .generations(&self.channel_id, self.epoch, &self.me());
            // No origin-key cloning or serialization on a quiet tick, even with many held keys.
            Ok(generations
                .iter()
                .any(|(chain, _)| *chain < floor)
                .then_some(Origins { floor, generations }))
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
        let mut saved = Saved {
            receivers: 0,
            origins: 0,
            result: self.origin_error.take().map_or(Ok(()), Err),
        };
        let mut poison = false;
        let mut writing = false;
        let receiver_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.sek.with(|sek| -> Result<()> {
                let snapshot = Arc::new(store.snapshot()?);
                let read = self
                    .index
                    .read_snapshot(Arc::clone(&snapshot), sek, &self.room)?;
                let rendered = self.index.render_snapshot(snapshot, sek, &self.room)?;
                let gone = select_receivers(
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
                // Drive is not modified by receiver deletion. Its exact written stamp was checked,
                // so retaining its durable segment avoids copying or reserializing any drive keys.
                receiver_releases::retire(&mut batch, sek, &self.room)?;
                batch.commit()?;
                saved.receivers = gone.len();
                removed = gone;
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
                    let gone = candidate.retain_from(&self.room, self.epoch, origins.floor);
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
            saved,
            poison,
        }
    }
}
