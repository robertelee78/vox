//! The room's encrypted DAG facts and restartable late-parent work. These use the entry
//! index's existing sealed pages and publication descriptor, never a second authority store.

use super::*;
use crate::log::dag::MAX_LEAD_MS;

/// Published display order: hybrid clock, then exact entry hash.
pub type OrderKey = (u64, Digest32);

pub(super) fn ordered((clock, hash): OrderKey) -> Key {
    let mut key = [0; 64];
    key[..8].copy_from_slice(&clock.to_be_bytes());
    key[8..40].copy_from_slice(&hash);
    key
}
pub(super) fn order_key(key: Key) -> Result<OrderKey> {
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
pub(super) fn successor(mut key: Key) -> Option<Key> {
    for byte in key.iter_mut().rev() {
        if *byte != u8::MAX {
            *byte += 1;
            return Some(key);
        }
        *byte = 0;
    }
    None
}
pub(super) fn predecessor(mut key: Key) -> Option<Key> {
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
    /// Open one rendering using the very same snapshot as the published order roots.
    pub(crate) fn cache(&self, id: u64) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.read.source().open(
            self.read.sek,
            self.read.channel,
            SegmentKind::PlaintextCache,
            id,
        )
    }
    /// Author and sequence from the same sealed, published locator roots as this order.
    /// Display indicators need these facts, not the entry's encrypted body/signature.
    pub(crate) fn author_position(&self, hash: &Digest32) -> Result<Option<(Digest32, u64)>> {
        if self.read.clock(hash)?.is_none() {
            return Ok(None);
        }
        Ok(self
            .read
            .source()
            .find(
                self.read.sek,
                self.read.channel,
                self.read.directory.active.hash,
                &hashed(hash),
            )?
            .map(|at| (at.author, at.seq)))
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
    placing: Option<Place>,
}
#[derive(Clone, Debug)]
struct Place {
    hash: Digest32,
    cursor: usize,
    latest: Option<u64>,
}
impl Work {
    pub(super) fn valid_for(&self, next_page: u64, phase: Phase) -> bool {
        self.queue < next_page
            && (matches!(phase, Phase::Rebuilding | Phase::Building) || self.is_empty())
    }
    pub(super) fn is_empty(&self) -> bool {
        self.queue == 0 && self.parent.is_none() && self.placing.is_none()
    }
    pub(super) fn write(&self, e: &mut Encoder) {
        e.array(3).uint(self.queue);
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
        match &self.placing {
            None => {
                e.array(0);
            }
            Some(place) => {
                e.array(3).bytes(&place.hash).uint(place.cursor as u64);
                match place.latest {
                    None => {
                        e.array(0);
                    }
                    Some(clock) => {
                        e.array(1).uint(clock);
                    }
                }
            }
        }
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        let arity = d.array()?;
        if !matches!(arity, 2 | 3) {
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
        let placing = if arity == 3 {
            match d.array()? {
                0 => None,
                3 => {
                    let hash = d
                        .bytes()?
                        .try_into()
                        .map_err(|_| invalid("DAG placement hash"))?;
                    let cursor =
                        usize::try_from(d.uint()?).map_err(|_| invalid("DAG placement cursor"))?;
                    if cursor
                        > crate::log::history::MAX_CONTEXT_AUTHORS + crate::log::entry::MAX_SEEN + 1
                    {
                        return Err(invalid("DAG placement cursor exceeds parent bound"));
                    }
                    let latest = match d.array()? {
                        0 => None,
                        1 => Some(d.uint()?),
                        _ => return Err(invalid("DAG placement clock option")),
                    };
                    Some(Place {
                        hash,
                        cursor,
                        latest,
                    })
                }
                _ => return Err(invalid("DAG placement arity")),
            }
        } else {
            None
        };
        Ok(Self {
            queue,
            parent,
            placing,
        })
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
    pub(super) fn last(
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
            Page::Ranked(rows) => {
                for i in (0..rows.len()).rev() {
                    if i != 0 && rows[i - 1].0 >= *key {
                        continue;
                    }
                    if let Some(row) = self.last(sek, channel, rows[i].1, key, depth + 1)? {
                        return Ok(Some(row));
                    }
                }
                Ok(None)
            }
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
    /// One reverse edge from the same published roots as this entry read.
    pub(crate) fn child_after(
        &self,
        parent: &Digest32,
        after: Option<Digest32>,
    ) -> Result<Option<Digest32>> {
        self.source().child_after(
            self.sek,
            self.channel,
            self.directory.active.children,
            parent,
            after,
        )
    }
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
            batch.derived();
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
    fn order_header(&self, roots: Roots, at: Locator) -> Result<Entry> {
        let source = Source::Batch(self.batch);
        if let Some(header) = source.sparse_position_header(
            self.sek,
            self.channel,
            roots.sparse,
            &at.author,
            at.seq,
        )? {
            return Ok(header);
        }
        indexed_entry(&source, self.sek, self.channel, SegmentKind::LogDb, at)
    }

    /// One bounded parent-coordinate slice. A large verified context does not make one
    /// entry an excuse for thousands of index writes in a single transaction.
    fn place_fact(&mut self, remaining: usize) -> Result<usize> {
        let mut place = self
            .directory
            .work
            .placing
            .clone()
            .ok_or(invalid("DAG placement missing"))?;
        let hash = place.hash;
        let mut roots = self.fact_roots()?;
        let source = Source::Batch(self.batch);
        let at = source
            .find(self.sek, self.channel, roots.hash, &hashed(&hash))?
            .ok_or(invalid("DAG work entry missing"))?;
        let entry = self.order_header(roots, at)?;
        if entry.entry_hash() != hash {
            return Err(invalid("DAG work hash differs"));
        }
        let sk = &entry.skeleton;
        let old = source.number(self.sek, self.channel, roots.clock, &hashed(&hash))?;
        let mut parents = sk.seen.clone();
        if let Some(v2) = &sk.v2 {
            let context = source
                .sparse_context(self.sek, self.channel, roots.sparse, &v2.pre_context)?
                .ok_or(invalid("admitted v2 ordering context missing"))?;
            if context.scope != v2.scope {
                return Err(invalid("ordering context scope"));
            }
            parents.extend(context.coordinates.iter().map(|coordinate| coordinate.hash));
            let predecessor = if sk.seq > 1 {
                source
                    .last(
                        self.sek,
                        self.channel,
                        roots.sequence,
                        &position(&sk.author_id, sk.seq - 1),
                        0,
                    )?
                    .map(|(_, value)| value.locator())
                    .transpose()?
                    .filter(|held| held.author == sk.author_id)
            } else {
                None
            };
            let predecessor_hash = predecessor
                .map(|held| {
                    self.order_header(roots, held)
                        .map(|header| header.entry_hash())
                })
                .transpose()?;
            if let Some(parent) = predecessor_hash {
                parents.push(parent);
            }
            if old.is_none() && place.cursor == 0 {
                // Inserting into a gap replaces the old temporary same-author edge. Keep
                // that edge only if the successor also explicitly names it as control/seen.
                let successor = source
                    .first(
                        self.sek,
                        self.channel,
                        roots.sequence,
                        &position(
                            &sk.author_id,
                            sk.seq
                                .checked_add(1)
                                .ok_or(invalid("DAG successor overflow"))?,
                        ),
                        0,
                    )?
                    .map(|(_, value)| value.locator())
                    .transpose()?
                    .filter(|held| held.author == sk.author_id);
                if let Some(successor) = successor {
                    let next = self.order_header(roots, successor)?;
                    let next_hash = next.entry_hash();
                    if let (Some(parent), Some(next_v2)) =
                        (predecessor_hash, next.skeleton.v2.as_ref())
                    {
                        let next_context = source
                            .sparse_context(
                                self.sek,
                                self.channel,
                                roots.sparse,
                                &next_v2.pre_context,
                            )?
                            .ok_or(invalid("successor ordering context missing"))?;
                        if !next.skeleton.seen.contains(&parent)
                            && !next_context.coordinates.iter().any(|c| c.hash == parent)
                        {
                            roots.children =
                                self.change_value(roots.children, pair(&parent, &next_hash), None)?;
                        }
                    }
                    self.enqueue_fact(next_hash)?;
                }
            }
        } else if sk.seq > 1 {
            parents.push(sk.prev_hash);
        }
        parents.sort_unstable();
        parents.dedup();
        if place.cursor > parents.len() {
            return Err(invalid("DAG placement parent cursor changed"));
        }
        let mut spent = 0;
        while place.cursor < parents.len() && spent < remaining {
            let parent = parents[place.cursor];
            if let Some(clock) = Source::Batch(self.batch).number(
                self.sek,
                self.channel,
                roots.clock,
                &hashed(&parent),
            )? {
                place.latest = Some(place.latest.map_or(clock, |held| held.max(clock)));
            }
            if old.is_none() || sk.v2.is_some() {
                roots.children =
                    self.change_value(roots.children, pair(&parent, &hash), Some(Value::Present))?;
            }
            if sk.seen.contains(&parent) {
                if let Some(parent_at) = Source::Batch(self.batch).find(
                    self.sek,
                    self.channel,
                    roots.hash,
                    &hashed(&parent),
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
            place.cursor += 1;
            spent += 1;
        }
        if place.cursor < parents.len() || spent == remaining {
            self.directory.work.placing = Some(place);
            self.set_fact_roots(roots)?;
            return Ok(spent);
        }
        let claimed = match place.latest.or(self.directory.origin) {
            Some(anchor) => sk.claimed_ms.min(anchor.saturating_add(MAX_LEAD_MS)),
            None => sk.claimed_ms,
        };
        let clock = place
            .latest
            .map_or(claimed, |parent| claimed.max(parent.saturating_add(1)));
        if old.is_none_or(|prior| {
            if sk.v2.is_some() {
                clock != prior
            } else {
                clock > prior
            }
        }) {
            if let Some(old) = old {
                roots.order = self.change_value(roots.order, ordered((old, hash)), None)?;
                self.move_rendered(&mut roots, hash, old, clock)?;
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
        self.directory.work.placing = None;
        self.set_fact_roots(roots)?;
        Ok(spent + 1)
    }

    /// Cold rebuilds know their entire verified set. Wait for an included parent rather than
    /// publishing a provisional clock and repeatedly moving its already placed descendants.
    /// Stored rows outside that set remain missing parents, just as in live publication.
    fn rebuild_parents_ready(&self, entry: &Entry, dag: &crate::log::dag::Dag) -> Result<bool> {
        let roots = self.fact_roots()?;
        let source = Source::Batch(self.batch);
        let sk = &entry.skeleton;
        for parent in sk.seen.iter().chain((sk.seq > 1).then_some(&sk.prev_hash)) {
            let Some(at) = source.find(self.sek, self.channel, roots.hash, &hashed(parent))? else {
                continue;
            };
            if at.seq <= dag.verified_head(&at.author)
                && source
                    .number(self.sek, self.channel, roots.clock, &hashed(parent))?
                    .is_none()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Each step visits at most one entry or one reverse edge; queued descendants stay sealed.
    /// Tree updates are COW and the active roots remain unchanged until the effects commit.
    pub(super) fn fact_chunk(&mut self) -> Result<bool> {
        let mut remaining = PROMOTION_ENTRIES;
        while remaining > 0 {
            if self.directory.work.placing.is_some() {
                let spent = self.place_fact(remaining)?;
                remaining = remaining.saturating_sub(spent);
                continue;
            }
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
                remaining -= 1;
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
            self.directory.work.placing = Some(Place {
                hash,
                cursor: 0,
                latest: None,
            });
            remaining -= 1;
        }
        Ok(self.directory.work.is_empty())
    }
}

impl EntryIndex {
    /// Stage exactly one evidence-complete source. Subsequent work is sliced by the caller;
    /// this entry point does not loop over its ancestry or wait while holding room state.
    pub(crate) fn begin_sparse_publication(
        &self,
        store: &Store,
        sek: &Sek,
        channel: &Digest32,
        publication: SparsePublication<'_>,
    ) -> Result<()> {
        let mut batch = store.batch()?;
        batch.derived();
        let mut writer = self.write(&mut batch, sek, channel)?;
        writer.begin_sparse_publication(publication)?;
        writer.seal()?;
        batch.commit()?;
        self.committed();
        Ok(())
    }

    /// One source-copy or DAG-coordinate quantum. `true` means the unpublished roots are
    /// ready for the caller's atomic source/evaluator transaction, not semantic acceptance.
    pub(crate) fn advance_sparse_publication(
        &self,
        store: &Store,
        sek: &Sek,
        channel: &Digest32,
    ) -> Result<bool> {
        let mut batch = store.batch()?;
        batch.derived();
        let mut writer = self.write(&mut batch, sek, channel)?;
        let promotion = writer
            .directory
            .promotion
            .as_ref()
            .ok_or(invalid("sparse publication absent"))?;
        if writer.directory.phase != Phase::Building || promotion.sparse_head.is_none() {
            return Err(invalid("sparse publication phase differs"));
        }
        let ready = if promotion.cursor <= promotion.through {
            writer.promotion_chunk()?;
            false
        } else {
            writer.fact_chunk()?
        };
        writer.seal()?;
        batch.commit()?;
        self.committed();
        Ok(ready)
    }

    /// One cleanup quantum after the root switch. Live admission yields between calls.
    pub(crate) fn cleanup_publication(
        &self,
        store: &Store,
        sek: &Sek,
        channel: &Digest32,
    ) -> Result<bool> {
        let mut batch = store.batch()?;
        batch.derived();
        let mut writer = self.write(&mut batch, sek, channel)?;
        let done = writer.cleanup_chunk()?;
        writer.seal()?;
        batch.commit()?;
        self.committed();
        Ok(done)
    }

    pub(crate) fn prepare_publication(
        &self,
        store: &Store,
        sek: &Sek,
        channel: &Digest32,
        publication: Publication<'_>,
    ) -> Result<()> {
        {
            let mut batch = store.batch()?;
            batch.derived();
            let mut writer = self.write(&mut batch, sek, channel)?;
            writer.begin_promotion(publication)?;
            writer.seal()?;
            batch.commit()?;
        }
        loop {
            let mut batch = store.batch()?;
            batch.derived();
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
        if read.directory.active.sparse.enabled {
            return Err(invalid(
                "sparse order state is missing; legacy rebuild is not valid",
            ));
        }
        drop(read);
        {
            let mut batch = store.batch()?;
            batch.derived();
            let mut writer = self.write(&mut batch, sek, channel)?;
            if writer.directory.phase != Phase::Idle {
                return Err(invalid("DAG rebuild during publication"));
            }
            writer.set_origin(origin)?;
            writer.directory.phase = Phase::Rebuilding;
            writer.seal()?;
            batch.commit()?;
        }
        // Keep one cursor per verified author, not a queue containing every saved hash.
        // Hash order can put descendants first. In an ordinary old room their provisional
        // clocks all clamp to genesis + MAX_LEAD_MS, so late parents repeatedly lift them.
        let mut heads: Vec<_> = dag
            .authors()
            .into_iter()
            .filter_map(|author| {
                let through = dag.verified_head(&author);
                (through != 0).then_some((author, Some(1), through))
            })
            .collect();
        let mut remaining = heads.len();
        while remaining != 0 {
            let mut batch = store.batch()?;
            batch.derived();
            let mut writer = self.write(&mut batch, sek, channel)?;
            let mut count = 0usize;
            let mut bytes = 0usize;
            'chunk: loop {
                let mut progressed = false;
                for (author, next, through) in &mut heads {
                    let Some(seq) = *next else { continue };
                    let entry = writer
                        .get(author, seq)?
                        .ok_or(invalid("DAG verified prefix missing"))?;
                    if !writer.rebuild_parents_ready(&entry, dag)? {
                        continue;
                    }
                    let size = entry.to_wire().len();
                    if count != 0 && bytes.saturating_add(size) > PROMOTION_BYTES {
                        break 'chunk;
                    }
                    writer.directory.work.placing = Some(Place {
                        hash: entry.entry_hash(),
                        cursor: 0,
                        latest: None,
                    });
                    // Every included parent was placed first, so no already placed child
                    // needs repair. Preserve the normal work-drain invariant before sealing.
                    if !writer.fact_chunk()? {
                        return Err(invalid("cold DAG placement left descendant work"));
                    }
                    if seq == *through {
                        *next = None;
                        remaining -= 1;
                    } else {
                        *next = Some(seq + 1);
                    }
                    count += 1;
                    bytes = bytes.saturating_add(size);
                    progressed = true;
                    if count == PROMOTION_ENTRIES || remaining == 0 {
                        break 'chunk;
                    }
                }
                if !progressed {
                    return Err(invalid("verified DAG parents cannot be ordered"));
                }
            }
            writer.seal()?;
            batch.commit()?;
        }
        self.finish_fact_work(store, sek, channel)?;
        let mut batch = store.batch()?;
        batch.derived();
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
