//! Read receipts retain one cache locator and exact message/reader reference counts.
//! Their bodies remain in PlaintextCache. All changes share the cache/retention Batch.

use super::dag_facts::successor;
use super::*;

const READERS_PER_PAGE: usize = 64;

fn readable_roots(directory: &Directory) -> Result<Roots> {
    if !directory.render_ready {
        return Err(invalid("read receipt index not ready"));
    }
    Ok(directory.active)
}

fn pair(message: &Digest32, reader: &Digest32) -> Key {
    let mut key = [0; 64];
    key[..32].copy_from_slice(message);
    key[32..].copy_from_slice(reader);
    key
}

fn receipt_cache(
    source: &Source<'_>,
    sek: &Sek,
    room: &Digest32,
    roots: Roots,
    receipt: &Digest32,
) -> Result<Option<u64>> {
    match source.find_value(sek, room, roots.read_receipts, &hashed(receipt))? {
        Some(Value::Number(id)) if id != 0 => Ok(Some(id)),
        None => Ok(None),
        _ => Err(invalid("read receipt locator")),
    }
}

fn count(source: &Source<'_>, sek: &Sek, room: &Digest32, root: u64, key: &Key) -> Result<u64> {
    match source.find_value(sek, room, root, key)? {
        Some(Value::Number(n)) if n != 0 => Ok(n),
        None => Ok(0),
        _ => Err(invalid("read receipt reference count")),
    }
}

fn row_at(
    source: &Source<'_>,
    sek: &Sek,
    room: &Digest32,
    roots: Roots,
    receipt: &Digest32,
    id: u64,
) -> Result<super::super::ReadRow> {
    let bytes = source
        .open(sek, room, SegmentKind::PlaintextCache, id)?
        .ok_or(invalid("read receipt cache missing"))?;
    let super::super::CacheRow::Read(row) = super::super::parse_cache(&bytes)? else {
        return Err(invalid("read receipt cache kind"));
    };
    let locator = source
        .find(sek, room, roots.hash, &hashed(receipt))?
        .ok_or(invalid("read receipt entry missing"))?;
    if row.entry_hash != *receipt
        || row.reader != locator.author
        || row.read.is_empty()
        || row.read.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid("read receipt cache binding"));
    }
    Ok(row)
}

#[allow(clippy::too_many_arguments)]
fn readers(
    source: &Source<'_>,
    sek: &Sek,
    room: &Digest32,
    root: u64,
    message: &Digest32,
    after: Option<Digest32>,
    limit: usize,
) -> Result<(Vec<Digest32>, Option<Digest32>)> {
    let limit = limit.clamp(1, READERS_PER_PAGE);
    let mut key = match after {
        Some(reader) => match successor(pair(message, &reader)) {
            Some(key) => key,
            None => return Ok((Vec::new(), None)),
        },
        None => pair(message, &[0; 32]),
    };
    let mut out = Vec::with_capacity(limit);
    // One lookahead distinguishes an exact last page from a page with continuation.
    for _ in 0..=limit {
        let Some((found, value)) = source.first(sek, room, root, &key, 0)? else {
            break;
        };
        if found[..32] != message[..] {
            break;
        }
        if !matches!(value, Value::Number(n) if n != 0) {
            return Err(invalid("read receipt reader value"));
        }
        if out.len() == limit {
            let next = out.last().copied();
            return Ok((out, next));
        }
        out.push(
            found[32..]
                .try_into()
                .map_err(|_| invalid("read receipt reader key"))?,
        );
        let Some(next) = successor(found) else {
            break;
        };
        key = next;
    }
    Ok((out, None))
}

impl Write<'_, '_> {
    pub(crate) fn read_receipt_cache(&self, receipt: &Digest32) -> Result<Option<u64>> {
        receipt_cache(
            &Source::Batch(self.batch),
            self.sek,
            self.channel,
            self.render_roots()?,
            receipt,
        )
    }

    /// Install one already-sealed cache row. Repeated receipt hashes never add references.
    /// The caller seals these roots and commits the cache, ratchet and retention together.
    pub(crate) fn put_read_receipt(
        &mut self,
        row: &super::super::ReadRow,
        cache: u64,
    ) -> Result<bool> {
        if cache == 0 {
            return Err(invalid("zero read receipt cache"));
        }
        let mut roots = self.render_roots()?;
        let saved = row_at(
            &Source::Batch(self.batch),
            self.sek,
            self.channel,
            roots,
            &row.entry_hash,
            cache,
        )?;
        if saved.reader != row.reader
            || saved.created_millis != row.created_millis
            || saved.read != row.read
        {
            return Err(invalid("read receipt differs from sealed cache"));
        }
        if let Some(existing) = receipt_cache(
            &Source::Batch(self.batch),
            self.sek,
            self.channel,
            roots,
            &row.entry_hash,
        )? {
            if existing != cache {
                return Err(invalid("read receipt cache locator changed"));
            }
            return Ok(false);
        }
        for message in &row.read {
            let key = pair(message, &row.reader);
            let next = count(
                &Source::Batch(self.batch),
                self.sek,
                self.channel,
                roots.read_pairs,
                &key,
            )?
            .checked_add(1)
            .ok_or(invalid("read receipt reference count exhausted"))?;
            roots.read_pairs =
                self.change_value(roots.read_pairs, key, Some(Value::Number(next)))?;
        }
        roots.read_receipts = self.change_value(
            roots.read_receipts,
            hashed(&row.entry_hash),
            Some(Value::Number(cache)),
        )?;
        self.set_render_roots(roots)?;
        Ok(true)
    }

    /// Remove references before deleting this receipt's cache in the same pruning Batch.
    /// Missing/contradictory stored facts are storage faults, never silently saturated counts.
    pub(crate) fn remove_read_receipt(&mut self, receipt: &Digest32) -> Result<bool> {
        let mut roots = self.render_roots()?;
        let Some(cache) = receipt_cache(
            &Source::Batch(self.batch),
            self.sek,
            self.channel,
            roots,
            receipt,
        )?
        else {
            return Ok(false);
        };
        let row = row_at(
            &Source::Batch(self.batch),
            self.sek,
            self.channel,
            roots,
            receipt,
            cache,
        )?;
        for message in &row.read {
            let key = pair(message, &row.reader);
            let previous = count(
                &Source::Batch(self.batch),
                self.sek,
                self.channel,
                roots.read_pairs,
                &key,
            )?;
            let next = previous
                .checked_sub(1)
                .ok_or(invalid("read receipt reference missing"))?;
            roots.read_pairs = self.change_value(
                roots.read_pairs,
                key,
                (next != 0).then_some(Value::Number(next)),
            )?;
        }
        roots.read_receipts = self.change_value(roots.read_receipts, hashed(receipt), None)?;
        self.set_render_roots(roots)?;
        Ok(true)
    }
}

impl Read<'_> {
    pub(crate) fn read_receipt_cache(&self, receipt: &Digest32) -> Result<Option<u64>> {
        receipt_cache(
            &self.source(),
            self.sek,
            self.channel,
            readable_roots(&self.directory)?,
            receipt,
        )
    }

    pub(crate) fn was_read(&self, message: &Digest32, reader: &Digest32) -> Result<bool> {
        Ok(count(
            &self.source(),
            self.sek,
            self.channel,
            readable_roots(&self.directory)?.read_pairs,
            &pair(message, reader),
        )? != 0)
    }

    pub(crate) fn readers_page(
        &self,
        message: &Digest32,
        after: Option<Digest32>,
        limit: usize,
    ) -> Result<(Vec<Digest32>, Option<Digest32>)> {
        readers(
            &self.source(),
            self.sek,
            self.channel,
            readable_roots(&self.directory)?.read_pairs,
            message,
            after,
            limit,
        )
    }
}

impl View<'_, '_> {
    pub(crate) fn read_receipt_cache(&self, receipt: &Digest32) -> Result<Option<u64>> {
        receipt_cache(
            &self.transaction.source(),
            self.sek,
            self.channel,
            readable_roots(&self.directory)?,
            receipt,
        )
    }

    pub(crate) fn was_read(&self, message: &Digest32, reader: &Digest32) -> Result<bool> {
        Ok(count(
            &self.transaction.source(),
            self.sek,
            self.channel,
            readable_roots(&self.directory)?.read_pairs,
            &pair(message, reader),
        )? != 0)
    }
}

impl RenderView<'_> {
    /// Uses this render view's pinned snapshot, so body and read state cannot cross revisions.
    pub(crate) fn read_receipt_cache(&self, receipt: &Digest32) -> Result<Option<u64>> {
        self.order.read.read_receipt_cache(receipt)
    }

    pub(crate) fn was_read(&self, message: &Digest32, reader: &Digest32) -> Result<bool> {
        self.order.read.was_read(message, reader)
    }

    pub(crate) fn readers_page(
        &self,
        message: &Digest32,
        after: Option<Digest32>,
        limit: usize,
    ) -> Result<(Vec<Digest32>, Option<Digest32>)> {
        self.order.read.readers_page(message, after, limit)
    }
}
