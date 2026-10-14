//! The room's encrypted DAG facts and restartable late-parent work. These use the entry
//! index's existing sealed pages and publication descriptor, never a second authority store.

use super::*;
use crate::log::dag::MAX_LEAD_MS;

/// Published display order: hybrid clock, then exact entry hash.
pub type OrderKey = (u64, Digest32);

fn ordered((clock, hash): OrderKey) -> Key {
    let mut key = [0; 64];
    key[..8].copy_from_slice(&clock.to_be_bytes());
    key[8..40].copy_from_slice(&hash);
    key
}
fn order_key(key: Key) -> Result<OrderKey> {
    if key[40..].iter().any(|b| *b != 0) {
        return Err(invalid("DAG order key padding"));
    }
    let clock = u64::from_be_bytes(key[..8].try_into().map_err(|_| invalid("DAG clock key"))?);
    let hash = key[8..40].try_into().map_err(|_| invalid("DAG hash key"))?;
    Ok((clock, hash))
}
fn pair(first: &Digest32, second: &Digest32) -> Key {
    let mut key = [0; 64];
    key[..32].copy_from_slice(first);
    key[32..].copy_from_slice(second);
    key
}
fn successor(mut key: Key) -> Option<Key> {
    for byte in key.iter_mut().rev() {
        if *byte != u8::MAX {
            *byte += 1;
            return Some(key);
        }
        *byte = 0;
    }
    None
}
fn predecessor(mut key: Key) -> Option<Key> {
    for byte in key.iter_mut().rev() {
        if *byte != 0 {
            *byte -= 1;
            return Some(key);
        }
        *byte = u8::MAX;
    }
    None
}

/// One pinned published order view. Drop it before waiting on a client or network operation.
/// A cursor across separate views must also carry `revision`: late parents can move keys.
pub struct OrderView<'a> {
    pub(super) read: Read<'a>,
}
impl OrderView<'_> {
    /// Revision of the pinned published roots. A mismatch calls for explicit refresh.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.read.directory.revision
    }
    /// One exact published entry's display-order key, or absence; storage failures remain errors.
    pub fn key(&self, hash: &Digest32) -> Result<Option<OrderKey>> {
        Ok(self.read.clock(hash)?.map(|clock| (clock, *hash)))
    }
    /// The first published key strictly after `after`; `None` starts at the oldest entry.
    pub fn next(&self, after: Option<OrderKey>) -> Result<Option<OrderKey>> {
        self.read.order_next(after)
    }
    /// The first published key strictly before `before`; `None` starts at the newest entry.
    pub fn previous(&self, before: Option<OrderKey>) -> Result<Option<OrderKey>> {
        self.read.order_previous(before)
    }
    /// Read exactly one published entry, without exposing an unsigned provisional tail.
    pub fn entry(&self, hash: &Digest32) -> Result<Option<Entry>> {
        if self.read.clock(hash)?.is_none() {
            return Ok(None);
        }
        let source = self.read.source();
        let Some(at) = source.find(
            self.read.sek,
            self.read.channel,
            self.read.directory.active.hash,
            &hashed(hash),
        )?
        else {
            return Ok(None);
        };
        let entry = indexed_entry(
            &source,
            self.read.sek,
            self.read.channel,
            SegmentKind::LogDb,
            at,
        )?;
        if entry.entry_hash() != *hash {
            return Err(invalid("published entry hash differs"));
        }
        Ok(Some(entry))
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct Work {
    queue: u64,
    parent: Option<(Digest32, Option<Digest32>)>,
}
impl Work {
    pub(super) fn valid_for(&self, next_page: u64, phase: Phase) -> bool {
        self.queue < next_page
            && (matches!(phase, Phase::Rebuilding | Phase::Building) || self.is_empty())
    }
    pub(super) fn is_empty(&self) -> bool {
        self.queue == 0 && self.parent.is_none()
    }
    pub(super) fn write(&self, e: &mut Encoder) {
        e.array(2).uint(self.queue);
        match self.parent {
            None => {
                e.array(0);
            }
            Some((parent, cursor)) => {
                e.array(2).bytes(&parent);
                match cursor {
                    None => {
                        e.array(0);
                    }
                    Some(child) => {
                        e.array(1).bytes(&child);
                    }
                }
            }
        }
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 2 {
            return Err(invalid("DAG work arity"));
        }
        let queue = d.uint()?;
        let parent = match d.array()? {
            0 => None,
            2 => {
                let parent = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| invalid("DAG work parent"))?;
                let cursor = match d.array()? {
                    0 => None,
                    1 => Some(
                        d.bytes()?
                            .try_into()
                            .map_err(|_| invalid("DAG child cursor"))?,
                    ),
                    _ => return Err(invalid("DAG child cursor arity")),
                };
                Some((parent, cursor))
            }
            _ => return Err(invalid("DAG work parent arity")),
        };
        Ok(Self { queue, parent })
    }
}

impl Source<'_> {
    pub(super) fn number(
        &self,
        sek: &Sek,
        channel: &Digest32,
        root: u64,
        key: &Key,
    ) -> Result<Option<u64>> {
        match self.find_value(sek, channel, root, key)? {
            Some(Value::Number(n)) => Ok(Some(n)),
            None => Ok(None),
            _ => Err(invalid("DAG numeric fact kind")),
        }
    }
    fn last(
        &self,
        sek: &Sek,
        channel: &Digest32,
        root: u64,
        key: &Key,
        depth: usize,
    ) -> Result<Option<(Key, Value)>> {
        if root == 0 {
            return Ok(None);
        }
        if depth >= MAX_DEPTH {
            return Err(invalid("entry index cycle or depth"));
        }
        match self.page(sek, channel, root)? {
            Page::Leaf(rows) => Ok(rows.into_iter().rev().find(|r| r.0 <= *key)),
            Page::Branch(rows) => {
                for i in (0..rows.len()).rev() {
                    // This child's minimum exceeds the preceding child's maximum.
                    if i != 0 && rows[i - 1].0 >= *key {
                        continue;
                    }
                    if let Some(row) = self.last(sek, channel, rows[i].1, key, depth + 1)? {
                        return Ok(Some(row));
                    }
                }
                Ok(None)
            }
        }
    }
    pub(super) fn order_next(
        &self,
        sek: &Sek,
        channel: &Digest32,
        root: u64,
        after: Option<OrderKey>,
    ) -> Result<Option<OrderKey>> {
        let start = match after {
            None => [0; 64],
            Some(key) => match successor(ordered(key)) {
                Some(key) => key,
                None => return Ok(None),
            },
        };
        self.first(sek, channel, root, &start, 0)?
            .map(|(key, value)| {
                if value != Value::Present {
                    return Err(invalid("DAG order value kind"));
                }
                order_key(key)
            })
            .transpose()
    }
    pub(super) fn order_previous(
        &self,
        sek: &Sek,
        channel: &Digest32,
        root: u64,
        before: Option<OrderKey>,
    ) -> Result<Option<OrderKey>> {
        let start = match before {
            None => [u8::MAX; 64],
            Some(key) => match predecessor(ordered(key)) {
                Some(key) => key,
                None => return Ok(None),
            },
        };
        self.last(sek, channel, root, &start, 0)?
            .map(|(key, value)| {
                if value != Value::Present {
                    return Err(invalid("DAG order value kind"));
                }
                order_key(key)
            })
            .transpose()
    }
    fn child_after(
        &self,
        sek: &Sek,
        channel: &Digest32,
        root: u64,
        parent: &Digest32,
        after: Option<Digest32>,
    ) -> Result<Option<Digest32>> {
        let start = match after {
            None => pair(parent, &[0; 32]),
            Some(child) => match successor(pair(parent, &child)) {
                Some(key) => key,
                None => return Ok(None),
            },
        };
        let Some((key, value)) = self.first(sek, channel, root, &start, 0)? else {
            return Ok(None);
        };
        if key[..32] != parent[..] {
            return Ok(None);
        }
        if value != Value::Present {
            return Err(invalid("DAG edge value kind"));
        }
        Ok(Some(
            key[32..].try_into().map_err(|_| invalid("DAG child key"))?,
        ))
    }
}

impl Read<'_> {
    pub(crate) fn order_revision(&self) -> u64 {
        self.directory.order_revision
    }
}
impl EntryIndex {
    pub(crate) fn order_view<'a>(
        &'a self,
        store: &Store,
        sek: &'a Sek,
        channel: &'a Digest32,
    ) -> Result<OrderView<'a>> {
        let read = self.read(store, sek, channel)?;
        if !read.directory.graph_ready {
            return Err(invalid("DAG facts not yet rebuilt"));
        }
        Ok(OrderView { read })
    }
    pub(crate) fn finish_fact_work(
        &self,
        store: &Store,
        sek: &Sek,
        channel: &Digest32,
    ) -> Result<()> {
        loop {
            let mut batch = store.batch()?;
            let mut writer = self.write(&mut batch, sek, channel)?;
            let done = writer.fact_chunk()?;
            writer.seal()?;
            batch.commit()?;
            if done {
                return Ok(());
            }
        }
    }
}
impl Write<'_, '_> {
    pub(super) fn set_origin(&mut self, origin: u64) -> Result<()> {
        if self.directory.origin.is_some_and(|old| old != origin) {
            return Err(invalid("DAG origin differs from room genesis"));
        }
        self.directory.origin = Some(origin);
        Ok(())
    }
    pub(super) fn enqueue_fact(&mut self, hash: Digest32) -> Result<()> {
        self.directory.work.queue = self.change_value(
            self.directory.work.queue,
            hashed(&hash),
            Some(Value::Present),
        )?;
        Ok(())
    }
    fn fact_roots(&self) -> Result<Roots> {
        match self.directory.phase {
            Phase::Rebuilding => Ok(self.directory.active),
            Phase::Building => self
                .directory
                .promotion
                .as_ref()
                .map(|p| p.work)
                .ok_or(invalid("DAG promotion missing")),
            _ if self.directory.work.is_empty() => Ok(self.directory.active),
            _ => Err(invalid("DAG work outside unpublished roots")),
        }
    }
    fn set_fact_roots(&mut self, roots: Roots) -> Result<()> {
        match self.directory.phase {
            Phase::Rebuilding => self.directory.active = roots,
            Phase::Building => {
                self.directory
                    .promotion
                    .as_mut()
                    .ok_or(invalid("DAG promotion missing"))?
                    .work = roots
            }
            _ => return Err(invalid("DAG work outside unpublished roots")),
        }
        Ok(())
    }
    fn place_fact(&mut self, hash: Digest32) -> Result<()> {
        let mut roots = self.fact_roots()?;
        let source = Source::Batch(self.batch);
        let at = source
            .find(self.sek, self.channel, roots.hash, &hashed(&hash))?
            .ok_or(invalid("DAG work entry missing"))?;
        let entry = indexed_entry(&source, self.sek, self.channel, SegmentKind::LogDb, at)?;
        if entry.entry_hash() != hash {
            return Err(invalid("DAG work hash differs"));
        }
        let sk = &entry.skeleton;
        let old = source.number(self.sek, self.channel, roots.clock, &hashed(&hash))?;
        let mut latest = None;
        for parent in sk.seen.iter().chain((sk.seq > 1).then_some(&sk.prev_hash)) {
            if let Some(clock) = Source::Batch(self.batch).number(
                self.sek,
                self.channel,
                roots.clock,
                &hashed(parent),
            )? {
                latest = Some(latest.map_or(clock, |held: u64| held.max(clock)));
            }
            if old.is_none() {
                roots.children =
                    self.change_value(roots.children, pair(parent, &hash), Some(Value::Present))?;
            }
        }
        // Referencing a late parent is causal even if its clock does not lift this child.
        for parent in &sk.seen {
            if Source::Batch(self.batch)
                .number(self.sek, self.channel, roots.clock, &hashed(parent))?
                .is_none()
            {
                continue;
            }
            if let Some(parent_at) = Source::Batch(self.batch).find(
                self.sek,
                self.channel,
                roots.hash,
                &hashed(parent),
            )? {
                let key = pair(&sk.author_id, &parent_at.author);
                let prior = Source::Batch(self.batch)
                    .number(self.sek, self.channel, roots.referenced, &key)?
                    .unwrap_or(0);
                if parent_at.seq > prior {
                    roots.referenced = self.change_value(
                        roots.referenced,
                        key,
                        Some(Value::Number(parent_at.seq)),
                    )?;
                }
            }
        }
        let claimed = match latest.or(self.directory.origin) {
            Some(anchor) => sk.claimed_ms.min(anchor.saturating_add(MAX_LEAD_MS)),
            None => sk.claimed_ms,
        };
        let clock = latest.map_or(claimed, |parent| claimed.max(parent.saturating_add(1)));
        if old.is_none_or(|old| clock > old) {
            if let Some(old) = old {
                roots.order = self.change_value(roots.order, ordered((old, hash)), None)?;
                if let Some(p) = &mut self.directory.promotion {
                    p.reordered = p.reordered.wrapping_add(1);
                } else {
                    self.directory.order_revision = self.directory.order_revision.wrapping_add(1);
                }
            }
            roots.clock =
                self.change_value(roots.clock, hashed(&hash), Some(Value::Number(clock)))?;
            roots.order =
                self.change_value(roots.order, ordered((clock, hash)), Some(Value::Present))?;
            self.directory.work.parent = Some((hash, None));
        }
        self.set_fact_roots(roots)
    }
    /// Each step visits at most one entry or one reverse edge; queued descendants stay sealed.
    /// Tree updates are COW and the active roots remain unchanged until the effects commit.
    pub(super) fn fact_chunk(&mut self) -> Result<bool> {
        for _ in 0..PROMOTION_ENTRIES {
            if let Some((parent, cursor)) = self.directory.work.parent {
                let roots = self.fact_roots()?;
                match Source::Batch(self.batch).child_after(
                    self.sek,
                    self.channel,
                    roots.children,
                    &parent,
                    cursor,
                )? {
                    Some(child) => {
                        self.enqueue_fact(child)?;
                        self.directory.work.parent = Some((parent, Some(child)));
                    }
                    None => self.directory.work.parent = None,
                }
                continue;
            }
            let row = Source::Batch(self.batch).first(
                self.sek,
                self.channel,
                self.directory.work.queue,
                &[0; 64],
                0,
            )?;
            let Some((key, value)) = row else {
                return Ok(true);
            };
            if value != Value::Present || key[32..].iter().any(|b| *b != 0) {
                return Err(invalid("DAG work key"));
            }
            self.directory.work.queue = self.change_value(self.directory.work.queue, key, None)?;
            let hash = key[..32].try_into().map_err(|_| invalid("DAG work hash"))?;
            self.place_fact(hash)?;
        }
        Ok(self.directory.work.is_empty())
    }
}

impl EntryIndex {
    pub(crate) fn prepare_publication(
        &self,
        store: &Store,
        sek: &Sek,
        channel: &Digest32,
        publication: Publication<'_>,
    ) -> Result<()> {
        {
            let mut batch = store.batch()?;
            let mut writer = self.write(&mut batch, sek, channel)?;
            writer.begin_promotion(publication)?;
            writer.seal()?;
            batch.commit()?;
        }
        loop {
            let mut batch = store.batch()?;
            let mut writer = self.write(&mut batch, sek, channel)?;
            let done = writer.promotion_chunk()?;
            writer.seal()?;
            batch.commit()?;
            if done {
                break;
            }
        }
        self.finish_fact_work(store, sek, channel)
    }
}

impl EntryIndex {
    /// Rebuild absent derived DAG facts only from the prefixes that replay actually verified.
    /// Stored but unlinked/set-aside rows never acquire a published clock or reference credit.
    pub(crate) fn prepare_facts(
        &self,
        store: &Store,
        sek: &Sek,
        channel: &Digest32,
        dag: &crate::log::dag::Dag,
        origin: u64,
    ) -> Result<()> {
        let read = self.read(store, sek, channel)?;
        if read.directory.graph_ready {
            return Ok(());
        }
        drop(read);
        {
            let mut batch = store.batch()?;
            let mut writer = self.write(&mut batch, sek, channel)?;
            if writer.directory.phase != Phase::Idle {
                return Err(invalid("DAG rebuild during publication"));
            }
            writer.set_origin(origin)?;
            writer.directory.phase = Phase::Rebuilding;
            writer.seal()?;
            batch.commit()?;
        }
        let mut batch = Some(store.batch()?);
        let mut count = 0usize;
        for author in dag.authors() {
            for seq in 1..=dag.verified_head(&author) {
                let current = batch.as_mut().ok_or(invalid("DAG rebuild batch missing"))?;
                let mut writer = self.write(current, sek, channel)?;
                let entry = writer
                    .get(&author, seq)?
                    .ok_or(invalid("DAG verified prefix missing"))?;
                writer.enqueue_fact(entry.entry_hash())?;
                writer.seal()?;
                count += 1;
                if count == PROMOTION_ENTRIES {
                    batch
                        .take()
                        .ok_or(invalid("DAG rebuild batch missing"))?
                        .commit()?;
                    batch = Some(store.batch()?);
                    count = 0;
                }
            }
        }
        batch
            .ok_or(invalid("DAG rebuild batch missing"))?
            .commit()?;
        self.finish_fact_work(store, sek, channel)?;
        let mut batch = store.batch()?;
        let mut writer = self.write(&mut batch, sek, channel)?;
        writer.finish_rebuild()?;
        // An empty verified DAG can coexist with stored set-aside rows.
        writer.directory.graph_ready = true;
        writer.seal()?;
        batch.commit()?;
        self.committed();
        Ok(())
    }
}
