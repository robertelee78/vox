//! Fixed-size sealed retention facts. Age indexes select a bounded due prefix; changing
//! the local/shared TTL changes only the cutoff, never rewrites every retained row.

use super::dag_facts::successor;
use super::*;
use crate::node::retention::Tracked;

pub(crate) const DUE_ENTRIES: usize = 64;
const DUE_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Roots {
    hash: u64,
    age: u64,
    steps: u64,
}
impl Roots {
    pub(super) fn write(self, e: &mut Encoder) {
        e.array(3).uint(self.hash).uint(self.age).uint(self.steps);
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 3 {
            return Err(invalid("retention roots arity"));
        }
        Ok(Self {
            hash: d.uint()?,
            age: d.uint()?,
            steps: d.uint()?,
        })
    }
    pub(super) fn valid_for(self, next: u64) -> bool {
        [self.hash, self.age, self.steps]
            .iter()
            .all(|id| *id < next)
    }
}
fn option(e: &mut Encoder, value: Option<u64>) {
    match value {
        Some(n) => {
            e.array(1).uint(n);
        }
        None => {
            e.array(0);
        }
    }
}
fn read_option(d: &mut Decoder<'_>) -> Result<Option<u64>> {
    match d.array()? {
        0 => Ok(None),
        1 => Ok(Some(d.uint()?)),
        _ => Err(invalid("retention optional id")),
    }
}
pub(super) fn write_fact(t: Tracked, e: &mut Encoder) {
    e.array(6).uint(5).uint(t.log_id).uint(t.first_seen_ms);
    option(e, t.claimed_ms);
    option(e, t.cache_id);
    e.uint(u64::from(t.steps));
}
pub(super) fn read_fact(d: &mut Decoder<'_>) -> Result<Tracked> {
    let t = Tracked {
        log_id: d.uint()?,
        first_seen_ms: d.uint()?,
        claimed_ms: read_option(d)?,
        cache_id: read_option(d)?,
        steps: flag(d)?,
    };
    if t.log_id == 0 || t.cache_id == Some(0) {
        return Err(invalid("retention zero location"));
    }
    Ok(t)
}
fn fact(value: Value) -> Result<Tracked> {
    match value {
        Value::Retained(t) => Ok(t),
        _ => Err(invalid("retention value kind")),
    }
}
fn age_key(base: u64, hash: Digest32) -> Key {
    let mut k = [0; 64];
    k[..8].copy_from_slice(&base.to_be_bytes());
    k[8..40].copy_from_slice(&hash);
    k
}
fn age_parts(key: Key) -> Result<(u64, Digest32)> {
    if key[40..].iter().any(|b| *b != 0) {
        return Err(invalid("retention age key"));
    }
    Ok((
        u64::from_be_bytes(key[..8].try_into().map_err(|_| invalid("retention age"))?),
        key[8..40]
            .try_into()
            .map_err(|_| invalid("retention hash"))?,
    ))
}
fn get(
    source: &Source<'_>,
    sek: &Sek,
    room: &Digest32,
    roots: Roots,
    hash: &Digest32,
) -> Result<Option<Tracked>> {
    source
        .find_value(sek, room, roots.hash, &hashed(hash))?
        .map(fact)
        .transpose()
}
fn next_due(
    source: &Source<'_>,
    sek: &Sek,
    room: &Digest32,
    root: u64,
    after: Option<Key>,
    cutoff: Option<u64>,
) -> Result<Option<(Key, Tracked)>> {
    let Some(cutoff) = cutoff else {
        return Ok(None);
    };
    let key = match after {
        Some(k) => match successor(k) {
            Some(k) => k,
            None => return Ok(None),
        },
        None => [0; 64],
    };
    source
        .first(sek, room, root, &key, 0)?
        .map(|(key, value)| {
            let (base, _) = age_parts(key)?;
            let t = fact(value)?;
            if base != t.base() {
                return Err(invalid("retention age differs"));
            }
            Ok((base <= cutoff).then_some((key, t)))
        })
        .transpose()
        .map(Option::flatten)
}
fn cutoff(now: u64, ttl: u64) -> Option<u64> {
    (ttl != 0).then(|| now.saturating_sub(ttl.saturating_mul(1_000)))
}
#[allow(clippy::too_many_arguments)]
fn due(
    source: &Source<'_>,
    sek: &Sek,
    room: &Digest32,
    roots: Roots,
    now: u64,
    ttl: u64,
    step_ttl: u64,
    limit: usize,
) -> Result<(Vec<(Digest32, Tracked)>, bool)> {
    let mut after = None;
    let limit = limit
        .min(DUE_ENTRIES)
        .min(DUE_BYTES / std::mem::size_of::<(Digest32, Tracked)>());
    let mut rows = Vec::new();
    loop {
        let regular = next_due(source, sek, room, roots.age, after, cutoff(now, ttl))?;
        let steps = next_due(source, sek, room, roots.steps, after, cutoff(now, step_ttl))?;
        let next = match (regular, steps) {
            (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
            (a, None) => a,
            (None, b) => b,
        };
        let Some((key, t)) = next else {
            return Ok((rows, false));
        };
        if rows.len() >= limit {
            return Ok((rows, true));
        }
        let (_, hash) = age_parts(key)?;
        if get(source, sek, room, roots, &hash)? != Some(t) {
            return Err(invalid("retention age locator differs"));
        }
        rows.push((hash, t));
        after = Some(key);
    }
}

impl Write<'_, '_> {
    pub(crate) fn retention(&self, hash: &Digest32) -> Result<Option<Tracked>> {
        get(
            &Source::Batch(self.batch),
            self.sek,
            self.channel,
            self.render_roots()?.retained,
            hash,
        )
    }
    pub(crate) fn set_retention(&mut self, hash: Digest32, value: Option<Tracked>) -> Result<()> {
        let mut roots = self.render_roots()?;
        let old = get(
            &Source::Batch(self.batch),
            self.sek,
            self.channel,
            roots.retained,
            &hash,
        )?;
        if old == value {
            return Ok(());
        }
        if let Some(old) = old {
            let key = age_key(old.base(), hash);
            roots.retained.age = self.change_value(roots.retained.age, key, None)?;
            if old.steps {
                roots.retained.steps = self.change_value(roots.retained.steps, key, None)?;
            }
        }
        roots.retained.hash = self.change_value(
            roots.retained.hash,
            hashed(&hash),
            value.map(Value::Retained),
        )?;
        if let Some(t) = value {
            if t.log_id == 0 || t.cache_id == Some(0) {
                return Err(invalid("retention zero location"));
            }
            let key = age_key(t.base(), hash);
            roots.retained.age =
                self.change_value(roots.retained.age, key, Some(Value::Retained(t)))?;
            if t.steps {
                roots.retained.steps =
                    self.change_value(roots.retained.steps, key, Some(Value::Retained(t)))?;
            }
        }
        self.set_render_roots(roots)?;
        self.restamp_rendered_retention(&hash)?;
        self.invalidate_owed_expiry(&hash)
    }
    pub(crate) fn retention_rendered(
        &mut self,
        hash: &Digest32,
        created: u64,
        cache: Option<u64>,
    ) -> Result<()> {
        if let Some(mut t) = self.retention(hash)? {
            t.claimed_ms = Some(created);
            t.cache_id = cache;
            self.set_retention(*hash, Some(t))?;
        }
        Ok(())
    }
}
impl View<'_, '_> {
    pub(crate) fn retention(&self, hash: &Digest32) -> Result<Option<Tracked>> {
        if self.directory.retention_stage != 2 {
            return Err(invalid("retention index not ready"));
        }
        get(
            &self.transaction.source(),
            self.sek,
            self.channel,
            self.directory.active.retained,
            hash,
        )
    }
}
impl Read<'_> {
    pub(crate) fn retention(&self, hash: &Digest32) -> Result<Option<Tracked>> {
        if self.directory.retention_stage != 2 {
            return Err(invalid("retention index not ready"));
        }
        get(
            &self.source(),
            self.sek,
            self.channel,
            self.directory.active.retained,
            hash,
        )
    }
    pub(crate) fn retention_due(
        &self,
        now: u64,
        ttl: u64,
        step_ttl: u64,
        limit: usize,
    ) -> Result<(Vec<(Digest32, Tracked)>, bool)> {
        if self.directory.retention_stage != 2 {
            return Err(invalid("retention index not ready"));
        }
        due(
            &self.source(),
            self.sek,
            self.channel,
            self.directory.active.retained,
            now,
            ttl,
            step_ttl,
            limit,
        )
    }
}
impl RenderView<'_> {
    pub(crate) fn retention(&self, hash: &Digest32) -> Result<Option<Tracked>> {
        self.order.read.retention(hash)
    }
}

impl EntryIndex {
    /// Rebuild absent derived facts in fixed entry/byte batches. LogDb and first-seen
    /// records are authoritative; a second streamed pass attaches retained cache locations.
    pub(crate) fn prepare_retention(
        &self,
        store: &Store,
        sek: &Sek,
        room: &Digest32,
        now: u64,
        eligible: impl Fn(&Entry) -> Result<bool>,
    ) -> Result<()> {
        loop {
            let mut batch = store.batch()?;
            let mut w = self.write(&mut batch, sek, room)?;
            if w.directory.retention_stage == 2 {
                return Ok(());
            }
            let kind = if w.directory.retention_stage == 0 {
                SegmentKind::LogDb
            } else {
                SegmentKind::PlaintextCache
            };
            let mut bytes = 0usize;
            for _ in 0..PROMOTION_ENTRIES {
                let Some((id, sealed)) =
                    w.batch
                        .segment_after(room, kind, w.directory.retention_cursor)?
                else {
                    w.directory.retention_stage += 1;
                    w.directory.retention_cursor = None;
                    break;
                };
                let opened = open_segment(sek, kind, id, &sealed)?;
                if bytes != 0 && bytes.saturating_add(opened.len()) > PROMOTION_BYTES {
                    break;
                }
                bytes = bytes.saturating_add(opened.len());
                if kind == SegmentKind::LogDb {
                    let entry = Entry::from_wire(&opened)?;
                    if eligible(&entry)? {
                        let (seen, stored_steps) =
                            match w.batch.get_segment(room, SegmentKind::Index, id)? {
                                Some(sealed) => super::super::parse_first_seen(&open_segment(
                                    sek,
                                    SegmentKind::Index,
                                    id,
                                    &sealed,
                                )?)?,
                                None => {
                                    // Stabilize an absent first-seen fact once, even across a crashed rebuild.
                                    let raw = super::super::first_seen_bytes(now, false);
                                    let sealed = seal_segment(sek, SegmentKind::Index, id, &raw)?;
                                    w.batch.put_segment(room, SegmentKind::Index, id, &sealed)?;
                                    (now, false)
                                }
                            };
                        let steps = stored_steps
                            || entry
                                .payload
                                .as_deref()
                                .is_some_and(|p| super::super::is_step_body(room, p));
                        w.set_retention(
                            entry.entry_hash(),
                            Some(Tracked {
                                log_id: id,
                                first_seen_ms: seen,
                                steps,
                                claimed_ms: steps.then_some(entry.skeleton.claimed_ms),
                                cache_id: None,
                            }),
                        )?;
                    }
                } else {
                    let (hash, created) = match super::super::parse_cache(&opened)? {
                        super::super::CacheRow::Text(row) => (row.entry_hash, row.created_millis),
                        super::super::CacheRow::Read(row) => (row.entry_hash, row.created_millis),
                        super::super::CacheRow::Session(row) => {
                            (row.entry_hash, row.created_millis)
                        }
                    };
                    w.retention_rendered(&hash, created, Some(id))?;
                }
                w.directory.retention_cursor = Some(id);
            }
            w.seal()?;
            batch.commit()?;
            self.committed();
        }
    }
}
