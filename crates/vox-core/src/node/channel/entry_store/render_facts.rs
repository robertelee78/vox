//! The rendered subset of the published DAG. Bodies remain in PlaintextCache; sealed
//! ranked pages carry only locators, ordering, and exact scalar selection facts.

use super::dag_facts::{order_key, ordered, predecessor, successor, OrderKey};
use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Roots {
    hash: u64,
    arrival: u64,
    display: u64,
    filters: u64,
    created: u64,
    authors: u64,
    owed_hash: u64,
    owed_display: u64,
    owed_expiry: u64,
    thread_authors: u64,
    backfill: u64,
    session_candidates: u64,
}
impl Roots {
    pub(super) fn write(self, e: &mut Encoder) {
        e.array(12)
            .uint(self.hash)
            .uint(self.arrival)
            .uint(self.display)
            .uint(self.filters)
            .uint(self.created)
            .uint(self.authors)
            .uint(self.owed_hash)
            .uint(self.owed_display)
            .uint(self.owed_expiry)
            .uint(self.thread_authors)
            .uint(self.backfill)
            .uint(self.session_candidates);
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 12 {
            return Err(invalid("render roots arity"));
        }
        Ok(Self {
            hash: d.uint()?,
            arrival: d.uint()?,
            display: d.uint()?,
            filters: d.uint()?,
            created: d.uint()?,
            authors: d.uint()?,
            owed_hash: d.uint()?,
            owed_display: d.uint()?,
            owed_expiry: d.uint()?,
            thread_authors: d.uint()?,
            backfill: d.uint()?,
            session_candidates: d.uint()?,
        })
    }
    pub(super) fn valid_for(self, next: u64) -> bool {
        [
            self.hash,
            self.arrival,
            self.display,
            self.filters,
            self.created,
            self.authors,
            self.owed_hash,
            self.owed_display,
            self.owed_expiry,
            self.thread_authors,
            self.backfill,
            self.session_candidates,
        ]
        .into_iter()
        .all(|id| id < next)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RenderFact {
    pub cache: u64,
    pub epoch: u64,
    pub shown: u64,
    pub created: u64,
}

/// An operation's earliest semantic witness and first conflicting arrival survive
/// retention. No message body or lifetime member list is retained in these facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct OperationFact {
    pub semantic: Digest32,
    pub first: u64,
    pub conflict: u64,
}

impl OperationFact {
    pub(super) fn write(self, e: &mut Encoder) {
        e.array(4)
            .uint(6)
            .bytes(&self.semantic)
            .uint(self.first)
            .uint(self.conflict);
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        let fact = Self {
            semantic: d
                .bytes()?
                .try_into()
                .map_err(|_| invalid("operation semantic digest"))?,
            first: d.uint()?,
            conflict: d.uint()?,
        };
        if fact.first == 0 || (fact.conflict != 0 && fact.conflict < fact.first) {
            return Err(invalid("operation arrival facts"));
        }
        Ok(fact)
    }
}
impl RenderFact {
    pub(super) fn write(self, e: &mut Encoder) {
        e.array(5)
            .uint(3)
            .uint(self.cache)
            .uint(self.epoch)
            .uint(self.shown)
            .uint(self.created);
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        let found = Self {
            cache: d.uint()?,
            epoch: d.uint()?,
            shown: d.uint()?,
            created: d.uint()?,
        };
        if found.cache == 0 {
            return Err(invalid("zero render cache locator"));
        }
        Ok(found)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct OwedFact {
    pub created: u64,
    pub expires: u64,
}
impl OwedFact {
    pub(super) fn write(self, e: &mut Encoder) {
        e.array(4)
            .uint(4)
            .uint(self.created)
            .uint(self.expires)
            .uint(0);
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        let fact = Self {
            created: d.uint()?,
            expires: d.uint()?,
        };
        if d.uint()? != 0 {
            return Err(invalid("owed fact format"));
        }
        Ok(fact)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Summary {
    count: u64,
    earliest: (u64, u64),
    newest: u64,
}
impl Default for Summary {
    fn default() -> Self {
        Self {
            count: 0,
            earliest: (u64::MAX, u64::MAX),
            newest: 0,
        }
    }
}
impl Summary {
    pub(super) fn write(self, e: &mut Encoder) {
        e.array(4)
            .uint(self.count)
            .uint(self.earliest.0)
            .uint(self.earliest.1)
            .uint(self.newest);
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 4 {
            return Err(invalid("render summary arity"));
        }
        let found = Self {
            count: d.uint()?,
            earliest: (d.uint()?, d.uint()?),
            newest: d.uint()?,
        };
        if found.count == 0 {
            return Err(invalid("empty render branch"));
        }
        Ok(found)
    }
    fn add(&mut self, other: Self) -> Result<()> {
        self.count = self
            .count
            .checked_add(other.count)
            .ok_or(invalid("render count overflow"))?;
        self.earliest = self.earliest.min(other.earliest);
        self.newest = self.newest.max(other.newest);
        Ok(())
    }
    fn fact(fact: RenderFact) -> Self {
        Self {
            count: 1,
            earliest: (fact.epoch, fact.shown),
            newest: fact.created,
        }
    }
}
impl Page {
    fn rendered_summary(&self) -> Result<Summary> {
        let mut out = Summary::default();
        match self {
            Self::Leaf(rows) => {
                for (_, value) in rows {
                    out.add(Summary::value(*value)?)?;
                }
            }
            Self::Ranked(rows) => {
                for (_, _, summary) in rows {
                    out.add(*summary)?;
                }
            }
            Self::Branch(_) => return Err(invalid("unranked render branch")),
        }
        Ok(out)
    }
}

/// Concrete rendered subsets, all computed only after a body has passed its read gate.
#[derive(Clone, Debug)]
pub(crate) enum Filter {
    General,
    Type(String),
    Op(String),
    Tag(String),
    Thread(Digest32),
    Author(Digest32),
    SessionCandidates,
    NoticeCandidates,
}
impl Filter {
    fn digest(&self) -> Digest32 {
        use crate::hash::sha256_concat;
        match self {
            Self::General => sha256_concat(&[b"render-general-v2\0"]),
            Self::Type(s) => sha256_concat(&[b"render-type\0", s.as_bytes()]),
            Self::Op(s) => sha256_concat(&[b"render-op\0", s.as_bytes()]),
            Self::Tag(s) => sha256_concat(&[b"render-tag\0", s.as_bytes()]),
            Self::Thread(h) => sha256_concat(&[b"render-thread\0", h]),
            Self::Author(h) => sha256_concat(&[b"render-author\0", h]),
            Self::SessionCandidates => sha256_concat(&[b"render-session-candidates\0"]),
            Self::NoticeCandidates => sha256_concat(&[b"render-notice-candidates\0"]),
        }
    }
}
fn filter_key(filter: &Filter, display: bool) -> Key {
    let mut key = hashed(&filter.digest());
    key[32] = u8::from(display);
    key
}
// These are derived selection metadata in the existing filter directory, not page
// locators. An absent marker means bounded catch-up is required, never an empty view.
fn general_state_key(ready: bool) -> Key {
    let mut key = hashed(&crate::hash::sha256(b"render-general-state-v2"));
    key[32] = u8::from(ready);
    key
}
fn operation_key(author: &Digest32, op: &str, selector: u8) -> Key {
    let mut key = hashed(&crate::hash::sha256_concat(&[
        b"render-operation\0",
        author,
        op.as_bytes(),
    ]));
    key[32] = selector;
    key
}
// General is conversation, not automatic Session participation or node plumbing. Match the
// authenticated envelope's type, never its prose: a say with identical words remains visible.
// Malformed envelopes remain visible as text, just as the clients render them.
fn is_general_root(text: &str) -> bool {
    use vox_agentcomms::envelope::{is_plumbing, Envelope, BYE, HELLO};
    crate::node::api::message_thread(text).is_none()
        && Envelope::parse(text).map_or(true, |env| {
            !is_plumbing(&env.kind) && env.kind != HELLO && env.kind != BYE
        })
}

fn filters(row: &super::super::Rendered) -> Vec<Filter> {
    let mut out = vec![Filter::Author(row.author)];
    if is_general_root(&row.text) {
        out.push(Filter::General);
    }
    if let Some((kind, op)) = crate::node::api::structured_kind(&row.text) {
        out.push(Filter::Type(kind));
        if let Some(op) = op {
            out.push(Filter::Op(op));
        }
    }
    out.extend(
        crate::node::api::message_tags(&row.text)
            .into_iter()
            .map(Filter::Tag),
    );
    if let Ok(envelope) = vox_agentcomms::envelope::Envelope::parse(&row.text) {
        if envelope.re.is_some() || (envelope.urgent && !envelope.to.is_empty()) {
            out.push(Filter::NoticeCandidates);
        }
        if let Some(root) = envelope
            .thread
            .and_then(|s| crate::node::link::b32_decode(s.trim(), "thread").ok())
            .filter(|root| *root != row.entry_hash)
        {
            out.push(Filter::Thread(root));
        }
    }
    if crate::node::sessions::is_record(&row.text) || row.text.contains("session_name") {
        out.push(Filter::SessionCandidates);
    }
    out
}

type SessionOrderKey = (u64, u64, Digest32);

fn session_key((created, clock, hash): SessionOrderKey) -> Key {
    let mut key = [0; 64];
    key[..8].copy_from_slice(&created.to_be_bytes());
    key[8..16].copy_from_slice(&clock.to_be_bytes());
    key[16..48].copy_from_slice(&hash);
    key
}
fn session_cursor(key: Key) -> Result<(u64, u64, Digest32)> {
    if key[48..].iter().any(|b| *b != 0) {
        return Err(invalid("session candidate key"));
    }
    Ok((
        u64::from_be_bytes(
            key[..8]
                .try_into()
                .map_err(|_| invalid("session created key"))?,
        ),
        u64::from_be_bytes(
            key[8..16]
                .try_into()
                .map_err(|_| invalid("session clock key"))?,
        ),
        key[16..48]
            .try_into()
            .map_err(|_| invalid("session hash key"))?,
    ))
}

impl Source<'_> {
    fn render_fact(
        &self,
        sek: &Sek,
        room: &Digest32,
        root: u64,
        key: &Key,
    ) -> Result<Option<RenderFact>> {
        self.find_value(sek, room, root, key)?
            .map(|value| match value {
                Value::Rendered(fact) => Ok(fact),
                _ => Err(invalid("render locator value")),
            })
            .transpose()
    }
    fn render_summary(&self, sek: &Sek, room: &Digest32, root: u64) -> Result<Summary> {
        if root == 0 {
            return Ok(Summary::default());
        }
        self.page(sek, room, root)?.rendered_summary()
    }
    // Prefix counts and suffix minima visit only the boundary path. Whole subtrees
    // contribute their stored summary without opening any message bodies.
    fn render_range(
        &self,
        sek: &Sek,
        room: &Digest32,
        root: u64,
        bound: &Key,
        before: bool,
        depth: usize,
    ) -> Result<Summary> {
        if root == 0 {
            return Ok(Summary::default());
        }
        if depth >= MAX_DEPTH {
            return Err(invalid("render tree depth"));
        }
        let mut out = Summary::default();
        match self.page(sek, room, root)? {
            Page::Leaf(rows) => {
                for (key, value) in rows {
                    if (before && key < *bound) || (!before && key > *bound) {
                        out.add(Summary::value(value)?)?;
                    }
                }
            }
            Page::Ranked(rows) => {
                let mut prior = None;
                for (max, id, summary) in rows {
                    if before {
                        if max < *bound {
                            out.add(summary)?;
                        } else {
                            out.add(self.render_range(sek, room, id, bound, before, depth + 1)?)?;
                            break;
                        }
                    } else if max > *bound {
                        if prior.is_some_and(|p| p >= *bound) {
                            out.add(summary)?;
                        } else {
                            out.add(self.render_range(sek, room, id, bound, before, depth + 1)?)?;
                        }
                    }
                    prior = Some(max);
                }
            }
            Page::Branch(_) => return Err(invalid("unranked render range")),
        }
        Ok(out)
    }
}

impl Write<'_, '_> {
    fn put_ranked(&mut self, page: &Page) -> Result<(Key, u64, Summary)> {
        let summary = page.rendered_summary()?;
        let (key, id) = self.put_page(page)?;
        Ok((key, id, summary))
    }
    fn replace_rendered(
        &mut self,
        root: u64,
        key: Key,
        value: Option<Value>,
        depth: usize,
    ) -> Result<Vec<(Key, u64, Summary)>> {
        if depth >= MAX_DEPTH {
            return Err(invalid("render tree depth"));
        }
        let old = if root == 0 {
            Page::Leaf(Vec::new())
        } else {
            Source::Batch(self.batch).page(self.sek, self.channel, root)?
        };
        let mut parts = Vec::with_capacity(2);
        match old {
            Page::Leaf(mut rows) => {
                match (rows.binary_search_by_key(&key, |r| r.0), value) {
                    (Ok(at), Some(fact)) => rows[at].1 = fact,
                    (Ok(at), None) => {
                        rows.remove(at);
                    }
                    (Err(at), Some(fact)) => rows.insert(at, (key, fact)),
                    (Err(_), None) => {
                        return if root == 0 {
                            Ok(Vec::new())
                        } else {
                            let page = Page::Leaf(rows);
                            Ok(vec![(page.max()?, root, page.rendered_summary()?)])
                        }
                    }
                }
                if rows.len() > PAGE_ITEMS {
                    let right = rows.split_off(rows.len() / 2);
                    parts.push(self.put_ranked(&Page::Leaf(rows))?);
                    parts.push(self.put_ranked(&Page::Leaf(right))?);
                } else if !rows.is_empty() {
                    parts.push(self.put_ranked(&Page::Leaf(rows))?);
                }
            }
            Page::Ranked(mut rows) => {
                let at = rows
                    .iter()
                    .position(|r| r.0 >= key)
                    .unwrap_or(rows.len() - 1);
                let children = self.replace_rendered(rows[at].1, key, value, depth + 1)?;
                rows.splice(at..=at, children);
                if rows.len() > PAGE_ITEMS {
                    let right = rows.split_off(rows.len() / 2);
                    parts.push(self.put_ranked(&Page::Ranked(rows))?);
                    parts.push(self.put_ranked(&Page::Ranked(right))?);
                } else if !rows.is_empty() {
                    parts.push(self.put_ranked(&Page::Ranked(rows))?);
                }
            }
            Page::Branch(_) => return Err(invalid("unranked render tree")),
        }
        if root != 0 {
            self.retire(root)?;
        }
        Ok(parts)
    }
    fn change_ranked(&mut self, root: u64, key: Key, value: Option<Value>) -> Result<u64> {
        let parts = self.replace_rendered(root, key, value, 0)?;
        match parts.as_slice() {
            [] => Ok(0),
            [(_, id, _)] => Ok(*id),
            _ => Ok(self.put_ranked(&Page::Ranked(parts))?.1),
        }
    }
    fn change_rendered(&mut self, root: u64, key: Key, value: Option<RenderFact>) -> Result<u64> {
        self.change_ranked(root, key, value.map(Value::Rendered))
    }
    pub(super) fn render_roots(&self) -> Result<super::Roots> {
        match self.directory.phase {
            Phase::Building => self
                .directory
                .promotion
                .as_ref()
                .map(|p| p.work)
                .ok_or(invalid("render promotion missing")),
            Phase::Idle | Phase::Rebuilding | Phase::Switched => Ok(self.directory.active),
        }
    }
    pub(super) fn set_render_roots(&mut self, roots: super::Roots) -> Result<()> {
        if self.directory.phase == Phase::Building {
            self.directory
                .promotion
                .as_mut()
                .ok_or(invalid("render promotion missing"))?
                .work = roots;
        } else {
            self.directory.active = roots;
        }
        Ok(())
    }
    fn change_filter(
        &mut self,
        roots: &mut Roots,
        filter: &Filter,
        key: OrderKey,
        display: bool,
        fact: Option<RenderFact>,
    ) -> Result<()> {
        let outer = filter_key(filter, display);
        let root = Source::Batch(self.batch)
            .number(self.sek, self.channel, roots.filters, &outer)?
            .unwrap_or(0);
        let changed = self.change_rendered(root, ordered(key), fact)?;
        roots.filters = self.change_value(
            roots.filters,
            outer,
            (changed != 0).then_some(Value::Number(changed)),
        )?;
        Ok(())
    }
    fn change_operation(
        &mut self,
        roots: &mut Roots,
        row: &super::super::Rendered,
        fact: Option<RenderFact>,
    ) -> Result<()> {
        let Ok(envelope) = vox_agentcomms::envelope::Envelope::parse(&row.text) else {
            return Ok(());
        };
        let Some(op) = vox_agentcomms::ops::op_of(&envelope) else {
            return Ok(());
        };
        let key = operation_key(&row.author, op, 2);
        let root = Source::Batch(self.batch)
            .number(self.sek, self.channel, roots.filters, &key)?
            .unwrap_or(0);
        let changed =
            self.change_rendered(root, ordered((row.created_millis, row.entry_hash)), fact)?;
        roots.filters = self.change_value(
            roots.filters,
            key,
            (changed != 0).then_some(Value::Number(changed)),
        )?;
        if fact.is_none() {
            return Ok(());
        } // Pruning never makes a known conflict valid again.
        let key = operation_key(&row.author, op, 3);
        let semantic = crate::hash::sha256(vox_agentcomms::ops::semantic(&envelope).as_bytes());
        let old = match Source::Batch(self.batch).find_value(
            self.sek,
            self.channel,
            roots.filters,
            &key,
        )? {
            Some(Value::Operation(fact)) => Some(fact),
            None => None,
            _ => return Err(invalid("operation witness kind")),
        };
        let mut next = old.unwrap_or(OperationFact {
            semantic,
            first: row.arrival,
            conflict: 0,
        });
        if next.semantic != semantic {
            let conflict = next.first.max(row.arrival);
            next.conflict = if next.conflict == 0 {
                conflict
            } else {
                next.conflict.min(conflict)
            };
        }
        if row.arrival < next.first {
            next.first = row.arrival;
            next.semantic = semantic;
        }
        if old != Some(next) {
            roots.filters = self.change_value(roots.filters, key, Some(Value::Operation(next)))?;
        }
        Ok(())
    }
    /// Queue renderer locators and concrete filter facts with their cache write.
    pub(crate) fn put_rendered(&mut self, row: &super::super::Rendered, shown: u64) -> Result<()> {
        let mut roots = self.render_roots()?;
        let hash = row.entry_hash;
        let source = Source::Batch(self.batch);
        if let Some(old) =
            source.render_fact(self.sek, self.channel, roots.rendered.hash, &hashed(&hash))?
        {
            if old.cache == row.arrival {
                return Ok(());
            }
            return Err(invalid("render cache locator changed"));
        }
        let clock = source
            .number(self.sek, self.channel, roots.clock, &hashed(&hash))?
            .ok_or(invalid("render has no published clock"))?;
        let fact = RenderFact {
            cache: row.arrival,
            epoch: self.directory.render_epoch,
            shown,
            created: row.created_millis,
        };
        roots.rendered.hash = self.change_value(
            roots.rendered.hash,
            hashed(&hash),
            Some(Value::Rendered(fact)),
        )?;
        roots.rendered.arrival = self.change_rendered(
            roots.rendered.arrival,
            ordered((row.arrival, hash)),
            Some(fact),
        )?;
        roots.rendered.display =
            self.change_rendered(roots.rendered.display, ordered((clock, hash)), Some(fact))?;
        roots.rendered.created = self.change_rendered(
            roots.rendered.created,
            ordered((row.created_millis, hash)),
            Some(fact),
        )?;
        for filter in filters(row) {
            if matches!(filter, Filter::SessionCandidates) {
                roots.rendered.session_candidates = self.change_rendered(
                    roots.rendered.session_candidates,
                    session_key((row.created_millis, clock, hash)),
                    Some(fact),
                )?;
            }
            if let Filter::Thread(root) = &filter {
                self.thread_author(&mut roots.rendered, *root, row.author, true)?;
            }
            self.change_filter(
                &mut roots.rendered,
                &filter,
                (row.arrival, hash),
                false,
                Some(fact),
            )?;
            self.change_filter(
                &mut roots.rendered,
                &filter,
                (clock, hash),
                true,
                Some(fact),
            )?;
        }
        self.change_operation(&mut roots.rendered, row, Some(fact))?;
        let author = hashed(&row.author);
        let n = Source::Batch(self.batch)
            .number(self.sek, self.channel, roots.rendered.authors, &author)?
            .unwrap_or(0);
        roots.rendered.authors = self.change_value(
            roots.rendered.authors,
            author,
            Some(Value::Number(
                n.checked_add(1)
                    .ok_or(invalid("render author count overflow"))?,
            )),
        )?;
        self.set_render_roots(roots)
    }
    pub(crate) fn remove_rendered(&mut self, hash: &Digest32) -> Result<()> {
        let mut roots = self.render_roots()?;
        let source = Source::Batch(self.batch);
        let Some(fact) =
            source.render_fact(self.sek, self.channel, roots.rendered.hash, &hashed(hash))?
        else {
            return Ok(());
        };
        let clock = source
            .number(self.sek, self.channel, roots.clock, &hashed(hash))?
            .ok_or(invalid("render clock missing"))?;
        let bytes = source
            .open(
                self.sek,
                self.channel,
                SegmentKind::PlaintextCache,
                fact.cache,
            )?
            .ok_or(invalid("render cache missing"))?;
        let super::super::CacheRow::Text(row) = super::super::parse_cache(&bytes)? else {
            return Err(invalid("render points to nontext"));
        };
        if row.entry_hash != *hash {
            return Err(invalid("render cache hash differs"));
        }
        roots.rendered.hash = self.change_value(roots.rendered.hash, hashed(hash), None)?;
        roots.rendered.arrival =
            self.change_rendered(roots.rendered.arrival, ordered((fact.cache, *hash)), None)?;
        roots.rendered.display =
            self.change_rendered(roots.rendered.display, ordered((clock, *hash)), None)?;
        roots.rendered.created = self.change_rendered(
            roots.rendered.created,
            ordered((row.created_millis, *hash)),
            None,
        )?;
        for filter in filters(&row) {
            if matches!(filter, Filter::SessionCandidates) {
                roots.rendered.session_candidates = self.change_rendered(
                    roots.rendered.session_candidates,
                    session_key((row.created_millis, clock, *hash)),
                    None,
                )?;
            }
            if let Filter::Thread(root) = &filter {
                self.thread_author(&mut roots.rendered, *root, row.author, false)?;
            }
            self.change_filter(
                &mut roots.rendered,
                &filter,
                (fact.cache, *hash),
                false,
                None,
            )?;
            self.change_filter(&mut roots.rendered, &filter, (clock, *hash), true, None)?;
        }
        self.change_operation(&mut roots.rendered, &row, None)?;
        let author = hashed(&row.author);
        let n = Source::Batch(self.batch)
            .number(self.sek, self.channel, roots.rendered.authors, &author)?
            .ok_or(invalid("render author count missing"))?;
        roots.rendered.authors = self.change_value(
            roots.rendered.authors,
            author,
            n.checked_sub(1).filter(|n| *n != 0).map(Value::Number),
        )?;
        self.set_render_roots(roots)
    }
    pub(super) fn move_rendered(
        &mut self,
        roots: &mut super::Roots,
        hash: Digest32,
        old: u64,
        new: u64,
    ) -> Result<()> {
        if let Some(value @ Value::Owed(_)) = Source::Batch(self.batch).find_value(
            self.sek,
            self.channel,
            roots.rendered.owed_hash,
            &hashed(&hash),
        )? {
            roots.rendered.owed_display =
                self.change_ranked(roots.rendered.owed_display, ordered((old, hash)), None)?;
            roots.rendered.owed_display = self.change_ranked(
                roots.rendered.owed_display,
                ordered((new, hash)),
                Some(value),
            )?;
        }
        let source = Source::Batch(self.batch);
        let Some(fact) =
            source.render_fact(self.sek, self.channel, roots.rendered.hash, &hashed(&hash))?
        else {
            return Ok(());
        };
        let bytes = source
            .open(
                self.sek,
                self.channel,
                SegmentKind::PlaintextCache,
                fact.cache,
            )?
            .ok_or(invalid("render cache missing"))?;
        let super::super::CacheRow::Text(row) = super::super::parse_cache(&bytes)? else {
            return Err(invalid("render points to nontext"));
        };
        if row.entry_hash != hash {
            return Err(invalid("render cache hash differs"));
        }
        roots.rendered.display =
            self.change_rendered(roots.rendered.display, ordered((old, hash)), None)?;
        roots.rendered.display =
            self.change_rendered(roots.rendered.display, ordered((new, hash)), Some(fact))?;
        for filter in filters(&row) {
            if matches!(filter, Filter::SessionCandidates) {
                roots.rendered.session_candidates = self.change_rendered(
                    roots.rendered.session_candidates,
                    session_key((row.created_millis, old, hash)),
                    None,
                )?;
                roots.rendered.session_candidates = self.change_rendered(
                    roots.rendered.session_candidates,
                    session_key((row.created_millis, new, hash)),
                    Some(fact),
                )?;
            }
            self.change_filter(&mut roots.rendered, &filter, (old, hash), true, None)?;
            self.change_filter(&mut roots.rendered, &filter, (new, hash), true, Some(fact))?;
        }
        Ok(())
    }
}

pub(crate) struct RenderView<'a> {
    pub(super) order: OrderView<'a>,
}
impl RenderView<'_> {
    pub(crate) fn snapshot(&self) -> &crate::node::store::Snapshot {
        &self.order.read.snapshot
    }

    fn source(&self) -> Source<'_> {
        self.order.read.source()
    }
    fn roots(&self) -> Roots {
        self.order.read.directory.active.rendered
    }
    pub(crate) fn author_backfill_pending(&self, author: &Digest32) -> Result<bool> {
        Ok(self
            .source()
            .number(
                self.order.read.sek,
                self.order.read.channel,
                self.roots().backfill,
                &hashed(author),
            )?
            .is_some())
    }
    pub(crate) fn has_backfill(&self) -> bool {
        self.roots().backfill != 0
    }
    pub(crate) fn transaction(&self) -> Transaction<'_, '_> {
        self.order.read.transaction()
    }
    pub(crate) fn order(&self) -> &OrderView<'_> {
        &self.order
    }
    /// Only facts that can change a rendered row or an owed placeholder. Ordinary
    /// directory seals, receipt writes and recovery cursors do not change this token.
    pub(crate) fn display_roots(&self) -> [u64; 4] {
        let roots = self.roots();
        [
            roots.hash,
            roots.display,
            roots.owed_display,
            self.order.read.directory.render_epoch,
        ]
    }
    pub(crate) fn fact(&self, hash: &Digest32) -> Result<Option<RenderFact>> {
        self.source().render_fact(
            self.order.read.sek,
            self.order.read.channel,
            self.roots().hash,
            &hashed(hash),
        )
    }
    pub(crate) fn room_views_ready(&self) -> Result<bool> {
        match self.source().number(
            self.order.read.sek,
            self.order.read.channel,
            self.roots().filters,
            &general_state_key(true),
        )? {
            None => Ok(false),
            Some(1) => Ok(true),
            Some(_) => Err(invalid("room view readiness marker")),
        }
    }
    pub(crate) fn selected_before(&self, filter: &Filter, before: Option<OrderKey>) -> Result<u64> {
        let root = self.root(Some(filter), true)?;
        let summary = match before {
            Some(key) => self.source().render_range(
                self.order.read.sek,
                self.order.read.channel,
                root,
                &ordered(key),
                true,
                0,
            )?,
            None => {
                self.source()
                    .render_summary(self.order.read.sek, self.order.read.channel, root)?
            }
        };
        Ok(summary.count)
    }
    pub(crate) fn count(&self) -> Result<u64> {
        Ok(self
            .source()
            .render_summary(
                self.order.read.sek,
                self.order.read.channel,
                self.roots().display,
            )?
            .count)
    }
    pub(crate) fn before(&self, key: OrderKey) -> Result<u64> {
        Ok(self
            .source()
            .render_range(
                self.order.read.sek,
                self.order.read.channel,
                self.roots().display,
                &ordered(key),
                true,
                0,
            )?
            .count)
    }
    pub(crate) fn after_arrival(&self, arrival: u64) -> Result<u64> {
        let mut bound = ordered((arrival, [u8::MAX; 32]));
        bound[40..].fill(u8::MAX);
        Ok(self
            .source()
            .render_range(
                self.order.read.sek,
                self.order.read.channel,
                self.roots().arrival,
                &bound,
                false,
                0,
            )?
            .count)
    }
    fn root(&self, filter: Option<&Filter>, display: bool) -> Result<u64> {
        match filter {
            Some(filter) => Ok(self
                .source()
                .number(
                    self.order.read.sek,
                    self.order.read.channel,
                    self.roots().filters,
                    &filter_key(filter, display),
                )?
                .unwrap_or(0)),
            None => Ok(if display {
                self.roots().display
            } else {
                self.roots().arrival
            }),
        }
    }
    /// Current canonical selection identity for a metadata reader. Reuses the sealed
    /// filter root; unrelated ordinary messages do not change the HELLO selection.
    pub(crate) fn filter_display_root(&self, filter: &Filter) -> Result<u64> {
        self.root(Some(filter), true)
    }

    /// One exact operation's canonical rows and retained conflict witness, from this same
    /// pinned snapshot. Other authors using the same op id do not invalidate its root.
    pub(crate) fn operation_state(
        &self,
        author: &Digest32,
        op: &str,
    ) -> Result<(u64, Option<u64>)> {
        let source = self.source();
        let root = source
            .number(
                self.order.read.sek,
                self.order.read.channel,
                self.roots().filters,
                &operation_key(author, op, 2),
            )?
            .unwrap_or(0);
        let conflict = match source.find_value(
            self.order.read.sek,
            self.order.read.channel,
            self.roots().filters,
            &operation_key(author, op, 3),
        )? {
            Some(Value::Operation(fact)) => (fact.conflict != 0).then_some(fact.conflict),
            None if root == 0 => None,
            _ => return Err(invalid("operation witness missing")),
        };
        Ok((root, conflict))
    }
    pub(crate) fn operation_next(
        &self,
        root: u64,
        after: Option<OrderKey>,
    ) -> Result<Option<(OrderKey, RenderFact)>> {
        let key = match after {
            Some(key) => match successor(ordered(key)) {
                Some(key) => key,
                None => return Ok(None),
            },
            None => [0; 64],
        };
        self.source()
            .first(self.order.read.sek, self.order.read.channel, root, &key, 0)?
            .map(|(key, value)| match value {
                Value::Rendered(fact) => Ok((order_key(key)?, fact)),
                _ => Err(invalid("operation candidate kind")),
            })
            .transpose()
    }
    pub(crate) fn summary(&self, filter: &Filter) -> Result<(u64, u64)> {
        let summary = self.source().render_summary(
            self.order.read.sek,
            self.order.read.channel,
            self.root(Some(filter), false)?,
        )?;
        Ok((summary.count, summary.newest))
    }
    pub(crate) fn step(
        &self,
        filter: Option<&Filter>,
        display: bool,
        cursor: Option<OrderKey>,
        backwards: bool,
    ) -> Result<Option<(OrderKey, RenderFact)>> {
        let key = match (cursor, backwards) {
            (None, false) => [0; 64],
            (None, true) => [u8::MAX; 64],
            (Some(key), false) => match successor(ordered(key)) {
                Some(key) => key,
                None => return Ok(None),
            },
            (Some(key), true) => match predecessor(ordered(key)) {
                Some(key) => key,
                None => return Ok(None),
            },
        };
        let root = self.root(filter, display)?;
        let source = self.source();
        let item = if backwards {
            source.last(self.order.read.sek, self.order.read.channel, root, &key, 0)?
        } else {
            source.first(self.order.read.sek, self.order.read.channel, root, &key, 0)?
        };
        item.map(|(key, value)| match value {
            Value::Rendered(fact) => Ok((order_key(key)?, fact)),
            _ => Err(invalid("render page value")),
        })
        .transpose()
    }
    /// The immutable root changes only when the public Session/name input changes.
    pub(crate) fn history_instance(&self) -> [u8; 16] {
        self.order.read.directory.history_instance
    }

    pub(crate) fn session_revision(&self) -> u64 {
        self.roots().session_candidates
    }

    /// One public Session/name candidate in stable created-time/canonical order.
    pub(crate) fn session_candidate(
        &self,
        after: Option<SessionOrderKey>,
    ) -> Result<Option<(SessionOrderKey, RenderFact)>> {
        let key = match after {
            Some(key) => match successor(session_key(key)) {
                Some(key) => key,
                None => return Ok(None),
            },
            None => [0; 64],
        };
        self.source()
            .first(
                self.order.read.sek,
                self.order.read.channel,
                self.roots().session_candidates,
                &key,
                0,
            )?
            .map(|(key, value)| match value {
                Value::Rendered(fact) => Ok((session_cursor(key)?, fact)),
                _ => Err(invalid("session candidate fact")),
            })
            .transpose()
    }
    pub(crate) fn row(&self, hash: &Digest32) -> Result<Option<super::super::Rendered>> {
        let Some(fact) = self.fact(hash)? else {
            return Ok(None);
        };
        let key = self
            .order
            .key(hash)?
            .ok_or(invalid("rendered entry not published"))?;
        let bytes = self
            .order
            .cache(fact.cache)?
            .ok_or(invalid("render cache missing"))?;
        let super::super::CacheRow::Text(mut row) = super::super::parse_cache(&bytes)? else {
            return Err(invalid("render points to nontext"));
        };
        if row.entry_hash != *hash {
            return Err(invalid("render cache hash differs"));
        }
        row.arrival = fact.cache;
        (row.shown_at_ms, row.late) = self.display_timing(key, fact)?;
        Ok(Some(row))
    }

    /// Visible timing depends on the selected fact and the indexed display suffix. Share
    /// this calculation with selected-window fences without loading any plaintext body.
    pub(crate) fn display_timing(&self, key: OrderKey, fact: RenderFact) -> Result<(u64, bool)> {
        let current_epoch = self.order.read.directory.render_epoch;
        let shown_at_ms = if fact.epoch == current_epoch {
            fact.shown
        } else {
            0
        };
        let suffix = self.source().render_range(
            self.order.read.sek,
            self.order.read.channel,
            self.roots().display,
            &ordered(key),
            false,
            0,
        )?;
        let earliest = if suffix.earliest.0 < current_epoch {
            0
        } else {
            suffix.earliest.1
        };
        let late = shown_at_ms != 0
            && suffix.count != 0
            && earliest
                .checked_add(super::super::LATE_AFTER_MS)
                .is_some_and(|seen| shown_at_ms >= seen);
        Ok((shown_at_ms, late))
    }
}
impl EntryIndex {
    pub(crate) fn render_view<'a>(
        &'a self,
        store: &Store,
        sek: &'a Sek,
        channel: &'a Digest32,
    ) -> Result<RenderView<'a>> {
        let order = self.order_view(store, sek, channel)?;
        if !order.read.directory.render_ready {
            return Err(invalid("render facts not yet rebuilt"));
        }
        Ok(RenderView { order })
    }
}

impl Write<'_, '_> {
    pub(crate) fn empty_rendered(&mut self) -> Result<()> {
        if self.directory.active.rendered != Roots::default() {
            return Err(invalid("render initialization not empty"));
        }
        self.directory.render_epoch = 1;
        self.directory.render_ready = true;
        self.directory.render_cursor = None;
        self.directory.retention_stage = 2;
        self.directory.retention_cursor = None;
        Ok(())
    }
}
impl EntryIndex {
    /// Build the current typed General selector without resetting authoritative history or
    /// other indexes. Its new identity never accepts an old complete selector. One transaction
    /// retires at most 64 obsolete selector entries, or examines at most 64 current rendered
    /// arrivals / 1 MiB (one legal large row alone); a restart resumes the prefix.
    /// Returns true while another fair maintenance turn is required.
    pub(crate) fn advance_room_views(
        &self,
        store: &Store,
        sek: &Sek,
        channel: &Digest32,
    ) -> Result<bool> {
        let mut batch = store.batch()?;
        let mut writer = self.write(&mut batch, sek, channel)?;
        if writer.directory.phase == Phase::Building {
            // The exact history flow that owns the unpublished promotion drives its next
            // preparation or retirement slice and wakes governance when the room changes.
            // Reporting view work here makes the actor's always-ready maintenance branch
            // rescan the same immutable roots until that separate owner runs. Under a busy
            // multi-node daemon this consumed whole cores and could starve the owner's cleanup,
            // leaving ordinary posts refused as "still being applied" until restart.
            return Ok(false);
        }
        let mut roots = writer.render_roots()?;
        match Source::Batch(writer.batch).number(
            sek,
            channel,
            roots.rendered.filters,
            &general_state_key(true),
        )? {
            Some(1) => return Ok(false),
            Some(_) => return Err(invalid("room view readiness marker")),
            None => {}
        }
        // Drain only the obsolete derived selector before building its replacement. The
        // remaining roots themselves are the durable continuation; no signed row, cache,
        // other selector or whole-tree traversal is involved. Share the existing 64-entry
        // maintenance budget instead of doing retirement and catch-up in the same turn.
        let mut retired = 0usize;
        for display in [false, true] {
            let mut old = hashed(&crate::hash::sha256_concat(&[b"render-general\0"]));
            old[32] = u8::from(display);
            let Some(mut root) =
                Source::Batch(writer.batch).number(sek, channel, roots.rendered.filters, &old)?
            else {
                continue;
            };
            while root != 0 && retired < PROMOTION_ENTRIES {
                let Some((key, Value::Rendered(_))) =
                    Source::Batch(writer.batch).first(sek, channel, root, &[0; 64], 0)?
                else {
                    return Err(invalid("obsolete room view selector fact"));
                };
                root = writer.change_rendered(root, key, None)?;
                retired += 1;
            }
            roots.rendered.filters = writer.change_value(
                roots.rendered.filters,
                old,
                (root != 0).then_some(Value::Number(root)),
            )?;
            if retired == PROMOTION_ENTRIES {
                break;
            }
        }
        if retired != 0 {
            writer.set_render_roots(roots)?;
            writer.seal()?;
            batch.commit()?;
            self.committed();
            return Ok(true);
        }
        for ready in [false, true] {
            let mut old = hashed(&crate::hash::sha256(b"render-general-state-v1"));
            old[32] = u8::from(ready);
            if Source::Batch(writer.batch)
                .number(sek, channel, roots.rendered.filters, &old)?
                .is_some()
            {
                roots.rendered.filters = writer.change_value(roots.rendered.filters, old, None)?;
            }
        }
        let mut after = Source::Batch(writer.batch).number(
            sek,
            channel,
            roots.rendered.filters,
            &general_state_key(false),
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
            let next = Source::Batch(writer.batch).first(
                sek,
                channel,
                roots.rendered.arrival,
                &start,
                0,
            )?;
            let Some((key, Value::Rendered(fact))) = next else {
                if next.is_some() {
                    return Err(invalid("room view arrival fact"));
                }
                pending = false;
                break;
            };
            let (arrival, hash) = order_key(key)?;
            let opened = Source::Batch(writer.batch)
                .open(sek, channel, SegmentKind::PlaintextCache, fact.cache)?
                .ok_or(invalid("room view cache missing"))?;
            if bytes != 0 && bytes.saturating_add(opened.len()) > PROMOTION_BYTES {
                break;
            }
            bytes = bytes.saturating_add(opened.len());
            let super::super::CacheRow::Text(row) = super::super::parse_cache(&opened)? else {
                return Err(invalid("room view cache kind"));
            };
            if row.entry_hash != hash || fact.cache != arrival {
                return Err(invalid("room view cache locator"));
            }
            if is_general_root(&row.text) {
                let clock = Source::Batch(writer.batch)
                    .number(sek, channel, roots.clock, &hashed(&hash))?
                    .ok_or(invalid("room view clock missing"))?;
                writer.change_filter(
                    &mut roots.rendered,
                    &Filter::General,
                    (arrival, hash),
                    false,
                    Some(fact),
                )?;
                writer.change_filter(
                    &mut roots.rendered,
                    &Filter::General,
                    (clock, hash),
                    true,
                    Some(fact),
                )?;
            }
            after = Some(arrival);
        }
        roots.rendered.filters = writer.change_value(
            roots.rendered.filters,
            general_state_key(false),
            if pending {
                after.map(Value::Number)
            } else {
                None
            },
        )?;
        if !pending {
            roots.rendered.filters = writer.change_value(
                roots.rendered.filters,
                general_state_key(true),
                Some(Value::Number(1)),
            )?;
        }
        writer.set_render_roots(roots)?;
        writer.seal()?;
        batch.commit()?;
        self.committed();
        Ok(pending)
    }

    /// Only a missing derived index is rebuilt. Each transaction visits a bounded cache
    /// prefix and stores its exact continuation; a restart resumes without resetting history.
    pub(crate) fn prepare_rendered(
        &self,
        store: &Store,
        sek: &Sek,
        channel: &Digest32,
        retained: impl Fn(&Batch<'_>, &Digest32, u64) -> Result<bool>,
    ) -> Result<()> {
        loop {
            let mut batch = store.batch()?;
            let mut writer = self.write(&mut batch, sek, channel)?;
            if writer.directory.render_ready {
                break;
            }
            let mut bytes = 0usize;
            for _ in 0..PROMOTION_ENTRIES {
                let next = writer.batch.segment_after(
                    channel,
                    SegmentKind::PlaintextCache,
                    writer.directory.render_cursor,
                )?;
                let Some((id, sealed)) = next else {
                    writer.directory.render_ready = true;
                    break;
                };
                let opened = open_segment(sek, SegmentKind::PlaintextCache, id, &sealed)?;
                if bytes != 0 && bytes.saturating_add(opened.len()) > PROMOTION_BYTES {
                    break;
                }
                bytes = bytes.saturating_add(opened.len());
                match super::super::parse_cache(&opened)? {
                    super::super::CacheRow::Text(mut row) => {
                        row.arrival = id;
                        if retained(writer.batch, &row.entry_hash, id)? {
                            writer.put_rendered(&row, 0)?;
                        }
                    }
                    super::super::CacheRow::Read(row) => {
                        if retained(writer.batch, &row.entry_hash, id)? {
                            writer.put_read_receipt(&row, id)?;
                        }
                    }
                    super::super::CacheRow::Session(_) => {}
                }
                writer.directory.render_cursor = Some(id);
            }
            writer.seal()?;
            batch.commit()?;
            self.committed();
        }
        // Prior-open rows were already visible on restart. Their old epoch derives a zero
        // shown time without rewriting either all cache bodies or all ranked leaves.
        let mut batch = store.batch()?;
        let mut writer = self.write(&mut batch, sek, channel)?;
        writer.directory.render_epoch = writer
            .directory
            .render_epoch
            .checked_add(1)
            .ok_or(invalid("render epoch exhausted"))?;
        writer.seal()?;
        batch.commit()?;
        self.committed();
        Ok(())
    }
}

impl Summary {
    fn value(value: Value) -> Result<Self> {
        match value {
            Value::Rendered(fact) => Ok(Self::fact(fact)),
            Value::Owed(fact) => Ok(Self {
                count: 1,
                earliest: (u64::MAX, u64::MAX),
                newest: fact.created,
            }),
            _ => Err(invalid("ranked projection value")),
        }
    }
}
impl Write<'_, '_> {
    /// Caller supplies authenticated classification and its effective local deadline.
    /// Removal happens before a body/cache replaces the placeholder in the same Batch.
    pub(crate) fn set_owed(&mut self, hash: Digest32, shown: Option<(u64, u64)>) -> Result<()> {
        let mut roots = self.render_roots()?;
        let source = Source::Batch(self.batch);
        let old = match source.find_value(
            self.sek,
            self.channel,
            roots.rendered.owed_hash,
            &hashed(&hash),
        )? {
            Some(Value::Owed(fact)) => Some(fact),
            None => None,
            _ => return Err(invalid("owed locator value")),
        };
        let new = shown.map(|(created, expires)| OwedFact { created, expires });
        if old == new {
            return Ok(());
        }
        let clock = source
            .number(self.sek, self.channel, roots.clock, &hashed(&hash))?
            .ok_or(invalid("owed entry not published"))?;
        if let Some(old) = old {
            roots.rendered.owed_expiry = self.change_ranked(
                roots.rendered.owed_expiry,
                ordered((old.expires, hash)),
                None,
            )?;
        }
        roots.rendered.owed_hash = self.change_value(
            roots.rendered.owed_hash,
            hashed(&hash),
            new.map(Value::Owed),
        )?;
        roots.rendered.owed_display = self.change_ranked(
            roots.rendered.owed_display,
            ordered((clock, hash)),
            new.map(Value::Owed),
        )?;
        if let Some(new) = new {
            roots.rendered.owed_expiry = self.change_ranked(
                roots.rendered.owed_expiry,
                ordered((new.expires, hash)),
                Some(Value::Owed(new)),
            )?;
        }
        self.set_render_roots(roots)
    }
}
impl RenderView<'_> {
    pub(crate) fn is_owed(&self, hash: &Digest32) -> Result<bool> {
        match self.source().find_value(
            self.order.read.sek,
            self.order.read.channel,
            self.roots().owed_hash,
            &hashed(hash),
        )? {
            Some(Value::Owed(_)) => Ok(true),
            None => Ok(false),
            _ => Err(invalid("owed locator value")),
        }
    }
    pub(crate) fn owed_before(&self, before: Option<OrderKey>) -> Result<u64> {
        let source = self.source();
        let summary = match before {
            Some(key) => source.render_range(
                self.order.read.sek,
                self.order.read.channel,
                self.roots().owed_display,
                &ordered(key),
                true,
                0,
            )?,
            None => source.render_summary(
                self.order.read.sek,
                self.order.read.channel,
                self.roots().owed_display,
            )?,
        };
        Ok(summary.count)
    }
    pub(crate) fn owed_step(
        &self,
        cursor: Option<OrderKey>,
        backwards: bool,
    ) -> Result<Option<OrderKey>> {
        let key = match (cursor, backwards) {
            (None, false) => [0; 64],
            (None, true) => [u8::MAX; 64],
            (Some(key), false) => match successor(ordered(key)) {
                Some(key) => key,
                None => return Ok(None),
            },
            (Some(key), true) => match predecessor(ordered(key)) {
                Some(key) => key,
                None => return Ok(None),
            },
        };
        let source = self.source();
        let room = self.order.read.channel;
        let sek = self.order.read.sek;
        let item = if backwards {
            source.last(sek, room, self.roots().owed_display, &key, 0)?
        } else {
            source.first(sek, room, self.roots().owed_display, &key, 0)?
        };
        item.map(|(key, value)| match value {
            Value::Owed(_) => order_key(key),
            _ => Err(invalid("owed order value")),
        })
        .transpose()
    }
    pub(crate) fn next_owed_expiry(&self) -> Result<Option<u64>> {
        let item = self.source().first(
            self.order.read.sek,
            self.order.read.channel,
            self.roots().owed_expiry,
            &[0; 64],
            0,
        )?;
        match item {
            Some((key, Value::Owed(_))) => {
                let (expires, _) = order_key(key)?;
                Ok((expires != u64::MAX).then_some(expires))
            }
            None => Ok(None),
            _ => Err(invalid("owed expiry value")),
        }
    }
}

impl Write<'_, '_> {
    pub(crate) fn first_expired_owed(&self, now: u64) -> Result<Option<Digest32>> {
        let roots = self.render_roots()?;
        let item = Source::Batch(self.batch).first(
            self.sek,
            self.channel,
            roots.rendered.owed_expiry,
            &[0; 64],
            0,
        )?;
        match item {
            Some((key, Value::Owed(_))) => {
                let (expires, hash) = order_key(key)?;
                Ok((expires != u64::MAX && expires <= now).then_some(hash))
            }
            None => Ok(None),
            _ => Err(invalid("owed expiry value")),
        }
    }
}

impl RenderView<'_> {
    pub(crate) fn contains(&self, filter: &Filter, hash: &Digest32) -> Result<bool> {
        let Some(fact) = self.fact(hash)? else {
            return Ok(false);
        };
        Ok(self
            .source()
            .render_fact(
                self.order.read.sek,
                self.order.read.channel,
                self.root(Some(filter), false)?,
                &ordered((fact.cache, *hash)),
            )?
            .is_some())
    }
    pub(crate) fn stamp_info(&self, now: u64, limit: u64) -> Result<(u64, Vec<Digest32>)> {
        let source = self.source();
        let sek = self.order.read.sek;
        let room = self.order.read.channel;
        let latest = source.last(
            sek,
            room,
            self.roots().created,
            &ordered((limit, [u8::MAX; 32])),
            0,
        )?;
        let stamp = match latest {
            Some((key, _)) => now.max(order_key(key)?.0.saturating_add(1)),
            None => now,
        };
        let mut skipped = Vec::new();
        let mut cursor = [0; 64];
        // This tree has at most the room's admitted-author bound, not one row per message.
        while let Some((key, value)) = source.first(sek, room, self.roots().authors, &cursor, 0)? {
            if !matches!(value, Value::Number(_)) {
                return Err(invalid("render author value"));
            }
            let author: Digest32 = key[..32]
                .try_into()
                .map_err(|_| invalid("render author key"))?;
            if self.summary(&Filter::Author(author))?.1 > limit {
                skipped.push(author);
            }
            let Some(next) = successor(key) else {
                break;
            };
            cursor = next;
        }
        Ok((stamp, skipped))
    }
}

impl Write<'_, '_> {
    fn thread_author(
        &mut self,
        roots: &mut Roots,
        thread: Digest32,
        author: Digest32,
        add: bool,
    ) -> Result<()> {
        let mut key = [0; 64];
        key[..32].copy_from_slice(&thread);
        key[32..].copy_from_slice(&author);
        let old = Source::Batch(self.batch)
            .number(self.sek, self.channel, roots.thread_authors, &key)?
            .unwrap_or(0);
        let n = if add {
            old.checked_add(1)
        } else {
            old.checked_sub(1)
        }
        .ok_or(invalid("thread author count overflow"))?;
        roots.thread_authors = self.change_value(
            roots.thread_authors,
            key,
            (n != 0).then_some(Value::Number(n)),
        )?;
        Ok(())
    }
}
impl RenderView<'_> {
    pub(crate) fn thread_authors(
        &self,
        thread: Digest32,
        after: Option<Digest32>,
        limit: usize,
    ) -> Result<(Vec<Digest32>, Option<Digest32>)> {
        let mut key = [0; 64];
        key[..32].copy_from_slice(&thread);
        if let Some(author) = after {
            key[32..].copy_from_slice(&author);
            let Some(next) = successor(key) else {
                return Ok((Vec::new(), None));
            };
            key = next;
        }
        let mut authors = Vec::new();
        while authors.len() <= limit {
            let Some((found, value)) = self.source().first(
                self.order.read.sek,
                self.order.read.channel,
                self.roots().thread_authors,
                &key,
                0,
            )?
            else {
                break;
            };
            if found[..32] != thread {
                break;
            }
            if !matches!(value, Value::Number(_)) {
                return Err(invalid("thread author value"));
            }
            authors.push(
                found[32..]
                    .try_into()
                    .map_err(|_| invalid("thread author key"))?,
            );
            let Some(next) = successor(found) else {
                break;
            };
            key = next;
        }
        let next = if authors.len() > limit {
            authors.pop();
            authors.last().copied()
        } else {
            None
        };
        Ok((authors, next))
    }
}

impl Write<'_, '_> {
    pub(crate) fn has_rendered(&self, hash: &Digest32) -> Result<bool> {
        Ok(Source::Batch(self.batch)
            .render_fact(
                self.sek,
                self.channel,
                self.render_roots()?.rendered.hash,
                &hashed(hash),
            )?
            .is_some())
    }
    pub(crate) fn queue_backfill(&mut self, author: Digest32, next: Option<u64>) -> Result<()> {
        let mut roots = self.render_roots()?;
        roots.rendered.backfill = self.change_value(
            roots.rendered.backfill,
            hashed(&author),
            next.map(Value::Number),
        )?;
        self.set_render_roots(roots)
    }
    pub(crate) fn next_backfill_after(
        &self,
        after: Option<Digest32>,
    ) -> Result<Option<(Digest32, u64)>> {
        let key = match after {
            None => [0; 64],
            Some(author) => match successor(hashed(&author)) {
                Some(key) => key,
                None => return Ok(None),
            },
        };
        Source::Batch(self.batch)
            .first(
                self.sek,
                self.channel,
                self.render_roots()?.rendered.backfill,
                &key,
                0,
            )?
            .map(|(key, value)| match value {
                Value::Number(seq) if seq != 0 => Ok((
                    key[..32]
                        .try_into()
                        .map_err(|_| invalid("backfill author"))?,
                    seq,
                )),
                _ => Err(invalid("backfill cursor value")),
            })
            .transpose()
    }
}
