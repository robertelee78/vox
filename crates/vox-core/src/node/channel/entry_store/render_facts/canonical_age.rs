//! One canonical-age rank per rendered selection and retention class. These roots
//! do not depend on display/arrival order or its page splits, and never include owed rows.

use super::*;

const REGULAR: u8 = 0;
const STEPS: u8 = 1;
const DURABLE: u8 = 2;
const UNKNOWN: u8 = 3;

fn slot(filter: Option<&Filter>, class: u8) -> Key {
    let selection = filter.map_or_else(
        || crate::hash::sha256(b"render-canonical-age-all-v1"),
        Filter::digest,
    );
    let mut key = hashed(&crate::hash::sha256_concat(&[
        b"render-canonical-age-v1\0",
        &selection,
    ]));
    key[32] = class;
    key
}

fn state(ready: bool) -> Key {
    let mut key = hashed(&crate::hash::sha256(b"render-canonical-age-state-v1"));
    key[32] = u8::from(ready);
    key
}

fn position(hash: Digest32, fact: RenderFact) -> (u8, Key) {
    let (base, class) = fact
        .expiry
        .map_or((0, u64::from(UNKNOWN)), RenderExpiry::parts);
    (class as u8, ordered((base, hash)))
}

impl Write<'_, '_> {
    pub(super) fn canonical_ages_ready(&self, roots: &Roots) -> Result<bool> {
        match Source::Batch(self.batch).number(
            self.sek,
            self.channel,
            roots.filters,
            &state(true),
        )? {
            None => Ok(false),
            Some(1) => Ok(true),
            Some(_) => Err(invalid("canonical age readiness marker")),
        }
    }

    pub(super) fn finish_canonical_ages(&mut self, roots: &mut Roots) -> Result<()> {
        roots.filters = self.change_value(roots.filters, state(false), None)?;
        roots.filters = self.change_value(roots.filters, state(true), Some(Value::Number(1)))?;
        Ok(())
    }

    /// Exactly one membership, independent of its two ordering indexes. Caller commits
    /// this with the canonical RenderFact/filter mutation in the same existing Batch.
    pub(super) fn change_canonical_age(
        &mut self,
        roots: &mut Roots,
        filter: Option<&Filter>,
        hash: Digest32,
        old: Option<RenderFact>,
        new: Option<RenderFact>,
    ) -> Result<()> {
        if old == new {
            return Ok(());
        }
        for (fact, insert) in [(old, false), (new, true)] {
            let Some(fact) = fact else { continue };
            let (class, key) = position(hash, fact);
            let outer = slot(filter, class);
            let root = Source::Batch(self.batch)
                .number(self.sek, self.channel, roots.filters, &outer)?
                .unwrap_or(0);
            let current =
                Source::Batch(self.batch).render_fact(self.sek, self.channel, root, &key)?;
            if insert && current == Some(fact) {
                continue;
            }
            match current {
                Some(held) if held != fact => {
                    return Err(invalid("canonical age membership differs"));
                }
                None if !insert && self.canonical_ages_ready(roots)? => {
                    return Err(invalid("canonical age old membership missing"));
                }
                _ => {}
            }
            let changed = self.change_rendered(root, key, insert.then_some(fact))?;
            roots.filters = self.change_value(
                roots.filters,
                outer,
                (changed != 0).then_some(Value::Number(changed)),
            )?;
        }
        Ok(())
    }
}

impl RenderView<'_> {
    /// Exact rendered count over one pinned snapshot and query policy, shared by arrival
    /// and display. Absent/restoring age roots or an UNKNOWN canonical age return None.
    /// Owed visibility and non-expiry authorization/classification belong to the caller.
    pub(crate) fn visible_count(
        &self,
        filter: Option<&Filter>,
        policy: ExpiryPolicy,
    ) -> Result<Option<u64>> {
        let roots = self.roots();
        let source = self.source();
        let sek = self.order.read.sek;
        let room = self.order.read.channel;
        match source.number(sek, room, roots.filters, &state(true))? {
            None => return Ok(None),
            Some(1) => {}
            Some(_) => return Err(invalid("canonical age readiness marker")),
        }
        if matches!(filter, Some(Filter::General)) && !self.room_views_ready()? {
            return Ok(None);
        }
        let mut total = 0u64;
        let mut live = 0u64;
        let mut unknown = false;
        for class in [REGULAR, STEPS, DURABLE, UNKNOWN] {
            let root = source
                .number(sek, room, roots.filters, &slot(filter, class))?
                .unwrap_or(0);
            let count = source.render_summary(sek, room, root)?.count;
            total = total
                .checked_add(count)
                .ok_or(invalid("canonical age count overflow"))?;
            let visible = match class {
                UNKNOWN => {
                    unknown |= count != 0;
                    0
                }
                DURABLE => count,
                _ => {
                    let ttl = policy.ttl(u64::from(class));
                    let duration = ttl.saturating_mul(1_000);
                    if ttl == 0 || policy.now < duration {
                        count
                    } else if policy.now == u64::MAX {
                        // Every finite/saturated nonzero-TTL deadline is <= MAX.
                        0
                    } else {
                        let cutoff = policy.now - duration;
                        let mut bound = ordered((cutoff, [u8::MAX; 32]));
                        // render_range is strict >. Include ALL hashes at cutoff in the
                        // expired prefix, including MAX_HASH and its canonical padding.
                        bound[40..].fill(u8::MAX);
                        source
                            .render_range(sek, room, root, &bound, false, 0)?
                            .count
                    }
                }
            };
            live = live
                .checked_add(visible)
                .ok_or(invalid("canonical age live count overflow"))?;
        }
        let membership = source
            .render_summary(sek, room, self.root(filter, false)?)?
            .count;
        if total != membership {
            return Err(invalid("canonical age membership count differs"));
        }
        Ok((!unknown).then_some(live))
    }
}

impl EntryIndex {
    /// Existing room-view maintenance owns this continuation. At most its existing
    /// entry/byte quantum is visited per call; no first-read full restore or new wake.
    /// UNKNOWN ages are indexed as UNKNOWN and do not prevent restoration terminating.
    pub(super) fn advance_canonical_ages(
        &self,
        store: &Store,
        sek: &Sek,
        channel: &Digest32,
    ) -> Result<bool> {
        let mut batch = store.batch()?;
        let mut writer = self.write(&mut batch, sek, channel)?;
        if writer.directory.phase == Phase::Building {
            return Ok(false); // The publication owner supplies the real completion wake.
        }
        let roots = writer.render_roots()?;
        if writer.canonical_ages_ready(&roots.rendered)? {
            return Ok(false);
        }
        let mut after = Source::Batch(writer.batch).number(
            sek,
            channel,
            roots.rendered.filters,
            &state(false),
        )?;
        let mut bytes = 0usize;
        let mut pending = true;
        for _ in 0..PROMOTION_ENTRIES {
            let start = match after {
                Some(id) => match successor(ordered((id, [u8::MAX; 32]))) {
                    Some(key) => key,
                    None => {
                        pending = false;
                        break;
                    }
                },
                None => [0; 64],
            };
            let roots = writer.render_roots()?;
            let next = Source::Batch(writer.batch).first(
                sek,
                channel,
                roots.rendered.arrival,
                &start,
                0,
            )?;
            let Some((key, Value::Rendered(fact))) = next else {
                if next.is_some() {
                    return Err(invalid("canonical age restore arrival kind"));
                }
                pending = false;
                break;
            };
            let (arrival, hash) = order_key(key)?;
            let opened = Source::Batch(writer.batch)
                .open(sek, channel, SegmentKind::PlaintextCache, fact.cache)?
                .ok_or(invalid("canonical age restore cache missing"))?;
            if bytes != 0 && bytes.saturating_add(opened.len()) > PROMOTION_BYTES {
                break;
            }
            bytes = bytes.saturating_add(opened.len());
            let super::super::super::CacheRow::Text(row) =
                super::super::super::parse_cache(&opened)?
            else {
                return Err(invalid("canonical age restore cache kind"));
            };
            if row.entry_hash != hash || fact.cache != arrival {
                return Err(invalid("canonical age restore cache binding"));
            }
            // This canonical producer may open the same one bounded cache row again;
            // it preserves first-seen/cache identity and every display fact.
            writer.restamp_rendered_retention(&hash)?;
            let mut roots = writer.render_roots()?;
            let fact = Source::Batch(writer.batch)
                .render_fact(sek, channel, roots.rendered.hash, &hashed(&hash))?
                .ok_or(invalid("canonical age restore render missing"))?;
            writer.change_canonical_age(&mut roots.rendered, None, hash, None, Some(fact))?;
            for filter in filters(&row) {
                let root = Source::Batch(writer.batch)
                    .number(
                        sek,
                        channel,
                        roots.rendered.filters,
                        &filter_key(&filter, false),
                    )?
                    .unwrap_or(0);
                match Source::Batch(writer.batch).render_fact(sek, channel, root, &key)? {
                    Some(held) if held == fact => writer.change_canonical_age(
                        &mut roots.rendered,
                        Some(&filter),
                        hash,
                        None,
                        Some(fact),
                    )?,
                    None => {}
                    Some(_) => return Err(invalid("canonical age restore filter differs")),
                }
            }
            writer.set_render_roots(roots)?;
            after = Some(arrival);
        }
        let mut roots = writer.render_roots()?;
        if pending {
            roots.rendered.filters = writer.change_value(
                roots.rendered.filters,
                state(false),
                after.map(Value::Number),
            )?;
        } else {
            writer.finish_canonical_ages(&mut roots.rendered)?;
        }
        writer.set_render_roots(roots)?;
        writer.seal()?;
        batch.commit()?;
        self.committed();
        Ok(pending)
    }
}
