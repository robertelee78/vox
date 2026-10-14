//! Durable missing-body membership, separate from whether a placeholder is displayed.
//! Cursors visit a fixed number of positions; no scan builds a second copy of the set.

use super::dag_facts::successor;
use super::*;

const POSITIONS_PER_PAGE: usize = 256;
type Position = (Digest32, u64);
type PositionPage = (Vec<Position>, Option<Position>);

fn contains(
    source: &Source<'_>,
    sek: &Sek,
    room: &Digest32,
    root: u64,
    author: &Digest32,
    seq: u64,
) -> Result<bool> {
    if seq == 0 {
        return Err(invalid("zero missing-body sequence"));
    }
    match source.find_value(sek, room, root, &position(author, seq))? {
        Some(Value::Present) => Ok(true),
        None => Ok(false),
        _ => Err(invalid("missing-body position value")),
    }
}

fn positions(
    source: &Source<'_>,
    sek: &Sek,
    room: &Digest32,
    root: u64,
    after: Option<(Digest32, u64)>,
    limit: usize,
) -> Result<PositionPage> {
    let limit = limit.clamp(1, POSITIONS_PER_PAGE);
    let mut key = match after {
        Some((author, seq)) => match successor(position(&author, seq)) {
            Some(key) => key,
            None => return Ok((Vec::new(), None)),
        },
        None => [0; 64],
    };
    let mut out = Vec::with_capacity(limit);
    for _ in 0..=limit {
        let Some((found, value)) = source.first(sek, room, root, &key, 0)? else {
            break;
        };
        let author = found[..32]
            .try_into()
            .map_err(|_| invalid("missing-body position author"))?;
        let seq = u64::from_be_bytes(
            found[32..40]
                .try_into()
                .map_err(|_| invalid("missing-body position sequence"))?,
        );
        if seq == 0 || found[40..] != [0; 24] || !matches!(value, Value::Present) {
            return Err(invalid("missing-body position format"));
        }
        if out.len() == limit {
            let next = out.last().copied();
            return Ok((out, next));
        }
        out.push((author, seq));
        let Some(next) = successor(found) else {
            break;
        };
        key = next;
    }
    Ok((out, None))
}

impl Write<'_, '_> {
    /// Operates on the supplied roots so promotion can keep membership unpublished.
    pub(super) fn missing_in_roots(
        &mut self,
        mut roots: Roots,
        entry: &Entry,
        missing: bool,
    ) -> Result<Roots> {
        if missing && entry.payload.is_some() {
            return Err(invalid("missing-body position has a body"));
        }
        let author = &entry.skeleton.author_id;
        let seq = entry.skeleton.seq;
        if contains(
            &Source::Batch(self.batch),
            self.sek,
            self.channel,
            roots.missing_positions,
            author,
            seq,
        )? != missing
        {
            roots.missing_positions = self.change_value(
                roots.missing_positions,
                position(author, seq),
                missing.then_some(Value::Present),
            )?;
        }
        Ok(roots)
    }

    /// Update recovery membership only for a verified published bodyless position.
    /// Local retention pruning must not call this with `missing = true`.
    pub(crate) fn set_missing(
        &mut self,
        author: &Digest32,
        seq: u64,
        missing: bool,
    ) -> Result<bool> {
        let mut roots = self.render_roots()?;
        if contains(
            &Source::Batch(self.batch),
            self.sek,
            self.channel,
            roots.missing_positions,
            author,
            seq,
        )? == missing
        {
            return Ok(false);
        }
        if missing {
            let source = Source::Batch(self.batch);
            let locator = source
                .find(
                    self.sek,
                    self.channel,
                    roots.sequence,
                    &position(author, seq),
                )?
                .ok_or(invalid("missing-body entry not published"))?;
            let entry =
                indexed_entry(&source, self.sek, self.channel, SegmentKind::LogDb, locator)?;
            if entry.skeleton.author_id != *author
                || entry.skeleton.seq != seq
                || entry.payload.is_some()
            {
                return Err(invalid("missing-body entry binding"));
            }
        }
        roots.missing_positions = self.change_value(
            roots.missing_positions,
            position(author, seq),
            missing.then_some(Value::Present),
        )?;
        self.set_render_roots(roots)?;
        Ok(true)
    }

    pub(crate) fn missing_contains(&self, author: &Digest32, seq: u64) -> Result<bool> {
        contains(
            &Source::Batch(self.batch),
            self.sek,
            self.channel,
            self.render_roots()?.missing_positions,
            author,
            seq,
        )
    }

    pub(crate) fn missing_page(
        &self,
        after: Option<(Digest32, u64)>,
        limit: usize,
    ) -> Result<PositionPage> {
        positions(
            &Source::Batch(self.batch),
            self.sek,
            self.channel,
            self.render_roots()?.missing_positions,
            after,
            limit,
        )
    }
}

impl Read<'_> {
    pub(crate) fn missing_contains(&self, author: &Digest32, seq: u64) -> Result<bool> {
        contains(
            &self.source(),
            self.sek,
            self.channel,
            self.directory.active.missing_positions,
            author,
            seq,
        )
    }

    pub(crate) fn missing_page(
        &self,
        after: Option<(Digest32, u64)>,
        limit: usize,
    ) -> Result<PositionPage> {
        positions(
            &self.source(),
            self.sek,
            self.channel,
            self.directory.active.missing_positions,
            after,
            limit,
        )
    }
}

impl View<'_, '_> {
    pub(crate) fn missing_contains(&self, author: &Digest32, seq: u64) -> Result<bool> {
        contains(
            &self.transaction.source(),
            self.sek,
            self.channel,
            self.directory.active.missing_positions,
            author,
            seq,
        )
    }
}

impl RenderView<'_> {
    pub(crate) fn missing_contains(&self, author: &Digest32, seq: u64) -> Result<bool> {
        self.order.read.missing_contains(author, seq)
    }
}
