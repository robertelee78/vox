//! Fixed-size sealed retention facts. Age indexes select a bounded due prefix; changing
//! the local/shared TTL changes only the cutoff, never rewrites every retained row.

use super::dag_facts::successor;
use super::*;
use crate::node::retention::{Fence, Tracked};

pub(crate) const DUE_ENTRIES: usize = 64;
pub(crate) const DUE_PAYLOAD_BYTES: usize = 1024 * 1024;
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
/// Six fields; a message that came back carries a seventh, `1` (ADR-053 MP-11). A fact written
/// before that, or of any other message, has six and reads as not returned.
pub(super) fn write_fact(t: Tracked, e: &mut Encoder) {
    e.array(if t.returned { 7 } else { 6 })
        .uint(5)
        .uint(t.log_id)
        .uint(t.first_seen_ms);
    option(e, t.claimed_ms);
    option(e, t.cache_id);
    e.uint(u64::from(t.steps));
    if t.returned {
        e.uint(1);
    }
}
pub(super) fn read_fact(d: &mut Decoder<'_>, arity: usize) -> Result<Tracked> {
    let t = Tracked {
        log_id: d.uint()?,
        first_seen_ms: d.uint()?,
        claimed_ms: read_option(d)?,
        cache_id: read_option(d)?,
        steps: flag(d)?,
        returned: arity == 7 && flag(d)?,
    };
    if t.log_id == 0 || t.cache_id == Some(0) {
        return Err(invalid("retention zero location"));
    }
    if arity == 7 && !t.returned {
        return Err(invalid("retention returned mark"));
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
/// The first row after `after` due by lifetime (aged at or before `cutoff`) or kept expired by
/// `fence`. A row the fence reaches by age but first seen here after it was set arrived late and
/// is walked past: the longer lifetime keeps it.
fn next_due(
    source: &Source<'_>,
    sek: &Sek,
    room: &Digest32,
    root: u64,
    after: Option<Key>,
    cutoff: Option<u64>,
    fence: Fence,
) -> Result<Option<(Key, Tracked)>> {
    let Some(reach) = cutoff.max(fence.reach()) else {
        return Ok(None);
    };
    let mut key = match after {
        Some(k) => match successor(k) {
            Some(k) => k,
            None => return Ok(None),
        },
        None => [0; 64],
    };
    loop {
        let Some((found, value)) = source.first(sek, room, root, &key, 0)? else {
            return Ok(None);
        };
        let (base, _) = age_parts(found)?;
        let t = fact(value)?;
        if base != t.base() {
            return Err(invalid("retention age differs"));
        }
        if base > reach {
            return Ok(None);
        }
        if cutoff.is_some_and(|cutoff| base <= cutoff) || fence.covers(base, t.first_seen_ms) {
            return Ok(Some((found, t)));
        }
        key = match successor(found) {
            Some(k) => k,
            None => return Ok(None),
        };
    }
}
/// The newest due age by lifetime.
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
    fence: [Fence; 2],
    limit: usize,
) -> Result<(Vec<(Digest32, Tracked)>, bool)> {
    let mut after = None;
    let limit = limit
        .min(DUE_ENTRIES)
        .min(DUE_BYTES / std::mem::size_of::<(Digest32, Tracked)>());
    let mut rows = Vec::new();
    loop {
        let regular = next_due(
            source,
            sek,
            room,
            roots.age,
            after,
            cutoff(now, ttl),
            fence[0],
        )?;
        let steps = next_due(
            source,
            sek,
            room,
            roots.steps,
            after,
            cutoff(now, step_ttl),
            fence[1],
        )?;
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
        self.set_render_roots(roots)
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
        fence: [Fence; 2],
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
            fence,
            limit,
        )
    }
}
impl RenderView<'_> {
    pub(crate) fn retention(&self, hash: &Digest32) -> Result<Option<Tracked>> {
        self.order.read.retention(hash)
    }
}
