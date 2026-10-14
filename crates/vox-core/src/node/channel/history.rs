//! Bounded, selected-room reads. PlaintextCache remains the sealed rendering store; the
//! published DAG supplies display order and cache ids supply local arrival order.
//! Rendered bodies, transient late facts, counts and selection indexes are read from
//! the same pinned sealed roots. No body mirror is retained by this query layer.

pub(crate) use super::entry_store::Filter;
use super::*;
use crate::node::api::{
    HistoryCursor, MessagePage, MessageRow, NoticePage, NoticeRevision, NoticeRow, NoticeState,
};

pub(crate) enum Query {
    ArrivalHead,
    NoticeState,
    NoticeExact {
        entry: Digest32,
    },
    NoticePage {
        after: Option<HistoryCursor>,
    },
    CursorPage {
        after: Option<HistoryCursor>,
        selection: Option<Selection>,
        limit: usize,
    },
    LocateUnread,
    SessionCandidates {
        after: Option<(u64, u64, Digest32)>,
        revision: Option<SessionRevision>,
        limit: usize,
    },
    Arrival {
        after: Option<u64>,
        limit: usize,
    },
    ThreadSummary {
        root: Digest32,
        after_author: Option<Digest32>,
    },
    Filtered {
        selection: Selection,
        since: Option<Digest32>,
        resume: Option<u64>,
        limit: usize,
    },
    Order {
        after: Option<(u64, Digest32)>,
        revision: Option<u64>,
        limit: usize,
    },
    Agreement {
        entry: Option<Digest32>,
        types: Vec<String>,
        now: u64,
    },
    Read {
        since: Option<Digest32>,
        after: Option<Digest32>,
        limit: usize,
    },
    Older {
        before: Option<Digest32>,
        limit: usize,
    },
    Count {
        since: Option<Digest32>,
    },
    Locate {
        entries: Vec<Digest32>,
    },
    Exact {
        entry: Digest32,
        revision: Revision,
    },
}

pub(crate) enum Reply {
    ArrivalHead(HistoryCursor),
    NoticeState(NoticeState),
    NoticeExact(Option<NoticeRow>),
    NoticePage(NoticePage),
    CursorPage(MessagePage),
    SessionCandidates {
        rows: Vec<MessageRow>,
        next: Option<(u64, u64, Digest32)>,
        revision: SessionRevision,
    },
    ThreadSummary {
        count: u64,
        last: u64,
        authors: Vec<Digest32>,
        next: Option<Digest32>,
    },
    Page {
        rows: Vec<MessageRow>,
        next: Option<u64>,
    },
    Order {
        entries: Vec<(Digest32, u64)>,
        next: Option<(u64, Digest32)>,
        revision: u64,
    },
    Agreement(Option<crate::node::agreestream::Answer>),
    Rows(Vec<MessageRow>),
    Older {
        rows: Vec<MessageRow>,
        older: u64,
    },
    Count {
        n: u64,
        last: Option<Digest32>,
    },
    Located {
        entries: Vec<Digest32>,
        revision: Revision,
    },
    Exact(MessageRow),
}

/// A union or intersection of concrete sealed indexes. A page may finish its work
/// budget without a match; the explicit scan cursor is still returned to the client.
pub(crate) enum Selection {
    Any(Vec<entry_store::Filter>),
    All(Vec<entry_store::Filter>),
}
impl Selection {
    fn filters(&self) -> &[entry_store::Filter] {
        match self {
            Self::Any(v) | Self::All(v) => v,
        }
    }
    fn matches(&self, view: &entry_store::RenderView<'_>, hash: &Digest32) -> Result<bool> {
        if self.filters().is_empty() {
            return Ok(false);
        }
        for filter in self.filters() {
            let found = view.contains(filter, hash)?;
            match self {
                Self::Any(_) if found => return Ok(true),
                Self::All(_) if !found => return Ok(false),
                _ => {}
            }
        }
        Ok(matches!(self, Self::All(_)))
    }
}

/// A short query may be followed by a client wait, but no Store snapshot or room lock is.
/// This token rejects a changed room before another part of one Find answer is read.
#[derive(Clone)]
pub(crate) struct Revision {
    incarnation: Arc<std::sync::atomic::AtomicU64>,
    facts: [u64; 8],
}

impl Revision {
    fn of(ch: &ChannelState) -> Self {
        Self {
            incarnation: ch.gen.clone(),
            facts: [
                ch.gen.load(std::sync::atomic::Ordering::Relaxed),
                ch.display_rewrite,
                ch.timeline.len() as u64,
                ch.dag.reorder_generation(),
                ch.dag.body_generation(),
                ch.legacy_sessions.display_revision(),
                ch.effective_retention(),
                ch.effective_step_retention(),
            ],
        }
    }
    fn current(&self, ch: &ChannelState) -> bool {
        let now = Self::of(ch);
        Arc::ptr_eq(&self.incarnation, &now.incarnation) && self.facts == now.facts
    }
}

/// Only a Session/name candidate insertion, removal or canonical move invalidates
/// this fold. Unrelated chat must not keep a multi-page Session rebuild restarting.
#[derive(Clone)]
pub(crate) struct SessionRevision {
    incarnation: Arc<std::sync::atomic::AtomicU64>,
    root: u64,
}
impl SessionRevision {
    fn of(ch: &ChannelState, rendered: &entry_store::RenderView<'_>) -> Self {
        Self {
            incarnation: ch.gen.clone(),
            root: rendered.session_revision(),
        }
    }
    fn current(&self, ch: &ChannelState, rendered: &entry_store::RenderView<'_>) -> bool {
        Arc::ptr_eq(&self.incarnation, &ch.gen) && self.root == rendered.session_revision()
    }
}

enum Failure {
    Storage(Error),
    Request(&'static str),
}
impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Storage(error)
    }
}
type Answer<T> = std::result::Result<T, Failure>;
const CHANGED: &str = "the room changed while reading; refresh and retry";

struct View<'a> {
    ch: &'a ChannelState,
    store: &'a Store,
    rendered: entry_store::RenderView<'a>,
}

impl View<'_> {
    fn row(&self, hash: &Digest32) -> Result<Option<MessageRow>> {
        let order = self.rendered.order();
        if let Some(row) = self.rendered.row(hash)? {
            let entry = order
                .entry(hash)?
                .ok_or(Error::MalformedAtRest("rendered entry missing"))?;
            if entry.skeleton.author_id != row.author {
                return Err(Error::MalformedAtRest("rendering author differs"));
            }
            return Ok(Some(Self::message(row)));
        }
        if !self.rendered.is_owed(hash)? {
            return Ok(None);
        }
        let Some(entry) = order.entry(hash)? else {
            return Ok(None);
        };
        if entry.payload.is_some()
            || !self
                .ch
                .owed
                .contains(&(entry.skeleton.author_id, entry.skeleton.seq))
            || self.ch.legacy_sessions.is_session(hash)
            || expired_at(
                entry.skeleton.claimed_ms,
                self.ch.now_hint,
                self.ch.entry_retention(&entry),
            )
        {
            return Ok(None);
        }
        Ok(Some(MessageRow {
            entry_hash: *hash,
            author: entry.skeleton.author_id,
            created_millis: entry.skeleton.claimed_ms,
            text: String::new(),
            arrival: 0,
            late: false,
            owed: true,
        }))
    }
    fn message(row: Rendered) -> MessageRow {
        MessageRow {
            entry_hash: row.entry_hash,
            author: row.author,
            created_millis: row.created_millis,
            text: row.text,
            arrival: row.arrival,
            late: row.late,
            owed: false,
        }
    }
    fn arrival(&self, after: &mut Option<u64>) -> Result<Option<MessageRow>> {
        let next = self
            .rendered
            .step(None, false, after.map(|id| (id, [u8::MAX; 32])), false)?;
        let Some(((id, hash), _)) = next else {
            return Ok(None);
        };
        *after = Some(id);
        self.row(&hash)
    }

    fn display(
        &self,
        cursor: &mut Option<(u64, Digest32)>,
        backwards: bool,
    ) -> Result<Option<MessageRow>> {
        let rendered = self
            .rendered
            .step(None, true, *cursor, backwards)?
            .map(|(key, _)| key);
        let owed = self.rendered.owed_step(*cursor, backwards)?;
        let key = match (rendered, owed) {
            (Some(a), Some(b)) => Some(if backwards { a.max(b) } else { a.min(b) }),
            (a, b) => a.or(b),
        };
        let Some(key) = key else {
            return Ok(None);
        };
        *cursor = Some(key);
        self.row(&key.1)?
            .ok_or(Error::MalformedAtRest("visible row missing"))
            .map(Some)
    }

    fn count_before(&self, before: Option<(u64, Digest32)>) -> Result<u64> {
        let rendered = match before {
            Some(mark) => self.rendered.before(mark)?,
            None => self.rendered.count()?,
        };
        rendered
            .checked_add(self.rendered.owed_before(before)?)
            .ok_or(Error::MalformedAtRest("visible row count overflow"))
    }

    fn mark(&self, hash: Digest32, arrival: bool, why: &'static str) -> Answer<MessageRow> {
        let row = self.row(&hash)?.ok_or(Failure::Request(why))?;
        if arrival && row.owed {
            return Err(Failure::Request(why));
        }
        Ok(row)
    }

    fn filtered(
        &self,
        selection: Selection,
        since: Option<Digest32>,
        resume: Option<u64>,
        limit: usize,
        bytes: usize,
    ) -> Answer<Reply> {
        let filters = selection.filters();
        if filters.len() > crate::node::ipc::PAGE_ENTRIES {
            return Err(Failure::Request("too many history filters"));
        }
        if filters.is_empty() {
            return Ok(Reply::Page {
                rows: Vec::new(),
                next: None,
            });
        }
        let mut cursor = resume;
        if let Some(hash) = since {
            if !selection.matches(&self.rendered, &hash)? {
                return Err(Failure::Request(
                    "cursor not among this room's selected messages",
                ));
            }
            let arrival = self
                .rendered
                .fact(&hash)?
                .ok_or(Failure::Request(
                    "cursor not among this room's selected messages",
                ))?
                .cache;
            cursor = Some(cursor.map_or(arrival, |c| c.max(arrival)));
        }
        let mut base = 0;
        if matches!(selection, Selection::All(_)) {
            let mut least = u64::MAX;
            for (i, filter) in filters.iter().enumerate() {
                let count = self.rendered.summary(filter)?.0;
                if count < least {
                    base = i;
                    least = count;
                }
            }
        }
        let mut rows = Vec::new();
        let mut used = 0usize;
        for _ in 0..256 {
            if rows.len() >= limit.min(crate::node::ipc::PAGE_ENTRIES)
                || (!rows.is_empty() && used >= bytes)
            {
                return Ok(Reply::Page { rows, next: cursor });
            }
            let after = cursor.map(|c| (c, [u8::MAX; 32]));
            let next = if matches!(selection, Selection::All(_)) {
                self.rendered
                    .step(Some(&filters[base]), false, after, false)?
                    .map(|(k, _)| k)
            } else {
                let mut next = None;
                for filter in filters {
                    if let Some((key, _)) = self.rendered.step(Some(filter), false, after, false)? {
                        next = Some(next.map_or(key, |old: (u64, Digest32)| old.min(key)));
                    }
                }
                next
            };
            let Some((arrival, hash)) = next else {
                return Ok(Reply::Page { rows, next: None });
            };
            if selection.matches(&self.rendered, &hash)? {
                let row = self
                    .row(&hash)?
                    .ok_or(Error::MalformedAtRest("filtered row missing"))?;
                let cost = row
                    .text
                    .len()
                    .saturating_add(crate::node::ipc::ROW_OVERHEAD);
                if !rows.is_empty() && used.saturating_add(cost) > bytes {
                    return Ok(Reply::Page { rows, next: cursor });
                }
                used = used.saturating_add(cost);
                rows.push(row);
            }
            cursor = Some(arrival);
        }
        Ok(Reply::Page { rows, next: cursor })
    }

    fn head(&self) -> Result<HistoryCursor> {
        Ok(HistoryCursor {
            instance: self.rendered.history_instance(),
            arrival: self
                .rendered
                .step(None, false, None, true)?
                .map_or(0, |(_, fact)| fact.cache),
        })
    }
    fn notice_state(&self) -> Result<NoticeState> {
        Ok(NoticeState {
            head: self.head()?,
            revision: NoticeRevision {
                incarnation: self.ch.gen.clone(),
                facts: [
                    self.ch.display_rewrite,
                    self.ch.effective_retention(),
                    self.ch.effective_step_retention(),
                    self.ch.legacy_sessions.display_revision(),
                ],
            },
            now_ms: self.ch.now_hint,
        })
    }
    fn notice_row(&self, row: MessageRow) -> Result<Option<NoticeRow>> {
        if row.owed {
            return Ok(None);
        }
        let entry = self
            .rendered
            .order()
            .entry(&row.entry_hash)?
            .ok_or(Error::MalformedAtRest("notice entry missing"))?;
        let ttl = self.ch.entry_retention(&entry);
        let expires = if ttl == 0 {
            None
        } else {
            let tracked = self
                .ch
                .retention
                .get(&row.entry_hash)
                .ok_or(Error::MalformedAtRest("notice retention missing"))?;
            Some(tracked.base().saturating_add(ttl.saturating_mul(1_000)))
        };
        Ok(expires
            .is_none_or(|at| self.ch.now_hint < at)
            .then_some(NoticeRow { row, expires }))
    }
    fn cursor_page(
        &self,
        after: Option<HistoryCursor>,
        selection: Option<Selection>,
        limit: usize,
        bytes: usize,
    ) -> Answer<MessagePage> {
        let instance = self.rendered.history_instance();
        let after = after.filter(|c| c.instance == instance).map(|c| c.arrival);
        let answer = match selection {
            Some(selection) => self.filtered(selection, None, after, limit, bytes)?,
            None => self.answer(Query::Arrival { after, limit }, bytes)?,
        };
        let Reply::Page { rows, next } = answer else {
            return Err(Failure::Storage(Error::MalformedAtRest(
                "unexpected arrival page",
            )));
        };
        Ok(MessagePage {
            rows,
            instance,
            next: next.map(|arrival| HistoryCursor { instance, arrival }),
        })
    }

    fn answer(&self, query: Query, bytes: usize) -> Answer<Reply> {
        let cursor_error = "cursor not in this room's timeline";
        match query {
            Query::SessionCandidates {
                after,
                revision,
                limit,
            } => {
                if revision
                    .as_ref()
                    .is_some_and(|r| !r.current(self.ch, &self.rendered))
                {
                    return Err(Failure::Request(CHANGED));
                }
                let revision =
                    revision.unwrap_or_else(|| SessionRevision::of(self.ch, &self.rendered));
                let mut cursor = after;
                let mut rows = Vec::new();
                let mut used = 0usize;
                while rows.len() < limit.min(crate::node::ipc::PAGE_ENTRIES) {
                    let Some((key, _)) = self.rendered.session_candidate(cursor)? else {
                        return Ok(Reply::SessionCandidates {
                            rows,
                            next: None,
                            revision,
                        });
                    };
                    let row = self
                        .row(&key.2)?
                        .ok_or(Error::MalformedAtRest("session candidate missing"))?;
                    let cost = row
                        .text
                        .len()
                        .saturating_add(crate::node::ipc::ROW_OVERHEAD);
                    if !rows.is_empty() && used.saturating_add(cost) > bytes {
                        break;
                    }
                    used = used.saturating_add(cost);
                    rows.push(row);
                    cursor = Some(key);
                }
                Ok(Reply::SessionCandidates {
                    rows,
                    next: cursor,
                    revision,
                })
            }
            Query::ArrivalHead => Ok(Reply::ArrivalHead(self.head()?)),
            Query::NoticeState => Ok(Reply::NoticeState(self.notice_state()?)),
            Query::NoticeExact { entry } => Ok(Reply::NoticeExact(
                self.row(&entry)?
                    .map(|row| self.notice_row(row))
                    .transpose()?
                    .flatten(),
            )),
            Query::CursorPage {
                after,
                selection,
                limit,
            } => Ok(Reply::CursorPage(
                self.cursor_page(after, selection, limit, bytes)?,
            )),
            Query::NoticePage { after } => {
                let page = self.cursor_page(
                    after,
                    Some(Selection::Any(vec![Filter::NoticeCandidates])),
                    crate::node::ipc::PAGE_ENTRIES,
                    bytes,
                )?;
                let mut rows = Vec::with_capacity(page.rows.len());
                for row in page.rows {
                    if let Some(row) = self.notice_row(row)? {
                        rows.push(row);
                    }
                }
                Ok(Reply::NoticePage(NoticePage {
                    rows,
                    next: page.next,
                    state: self.notice_state()?,
                }))
            }
            Query::Arrival { after, limit } => {
                let mut cursor = after;
                let mut rows = Vec::new();
                let mut used = 0usize;
                while rows.len() < limit.min(crate::node::ipc::PAGE_ENTRIES)
                    && (rows.is_empty() || used < bytes)
                {
                    let before = cursor;
                    let Some(row) = self.arrival(&mut cursor)? else {
                        return Ok(Reply::Page { rows, next: None });
                    };
                    let cost = row
                        .text
                        .len()
                        .saturating_add(crate::node::ipc::ROW_OVERHEAD);
                    if !rows.is_empty() && used.saturating_add(cost) > bytes {
                        return Ok(Reply::Page { rows, next: before });
                    }
                    used = used.saturating_add(cost);
                    rows.push(row);
                }
                Ok(Reply::Page { rows, next: cursor })
            }
            Query::ThreadSummary { root, after_author } => {
                let (count, last) = self.rendered.summary(&entry_store::Filter::Thread(root))?;
                let (authors, next) = self.rendered.thread_authors(
                    root,
                    after_author,
                    crate::node::ipc::PAGE_ENTRIES,
                )?;
                Ok(Reply::ThreadSummary {
                    count,
                    last,
                    authors,
                    next,
                })
            }
            Query::Filtered {
                selection,
                since,
                resume,
                limit,
            } => self.filtered(selection, since, resume, limit, bytes),
            Query::Order {
                after,
                revision,
                limit,
            } => {
                let current = self.rendered.order().revision();
                if revision.is_some_and(|r| r != current) {
                    return Err(Failure::Request(CHANGED));
                }
                let mut cursor = after;
                let mut entries = Vec::new();
                while entries.len() < limit.min(crate::node::ipc::PAGE_ENTRIES) {
                    let Some(key) = self.rendered.order().next(cursor)? else {
                        break;
                    };
                    entries.push((key.1, key.0));
                    cursor = Some(key);
                }
                let next = if entries.len() == limit.min(crate::node::ipc::PAGE_ENTRIES) {
                    cursor
                } else {
                    None
                };
                Ok(Reply::Order {
                    entries,
                    next,
                    revision: current,
                })
            }
            Query::Agreement { entry, types, now } => {
                use crate::node::agreestream::{Answer, MAX_LISTED, STAMP_LEAD_LIMIT_MILLIS};
                if let Some(entry) = entry {
                    let Some(fact) = self.rendered.fact(&entry)? else {
                        return Ok(Reply::Agreement(None));
                    };
                    if fact.created > now.saturating_add(STAMP_LEAD_LIMIT_MILLIS) {
                        return Ok(Reply::Agreement(Some(Answer::ClocksApart)));
                    }
                }
                let filters: Vec<_> = types.into_iter().map(entry_store::Filter::Type).collect();
                if filters.len() > crate::node::ipc::PAGE_ENTRIES {
                    return Err(Failure::Request("too many post types"));
                }
                let mut cursor = None;
                let mut entries = Vec::new();
                loop {
                    let mut next = None;
                    for filter in &filters {
                        if let Some((key, _)) =
                            self.rendered.step(Some(filter), true, cursor, false)?
                        {
                            next = Some(next.map_or(key, |old: (u64, Digest32)| old.min(key)));
                        }
                    }
                    let Some(key) = next else {
                        break;
                    };
                    cursor = Some(key);
                    if entries.len() == MAX_LISTED {
                        return Ok(Reply::Agreement(Some(Answer::TooMany)));
                    }
                    entries.push(key.1);
                }
                Ok(Reply::Agreement(Some(Answer::Holds(entries))))
            }
            Query::Read {
                since,
                after,
                limit,
            } => {
                if since.is_some() && after.is_some() {
                    return Err(Failure::Request(
                        "a read takes a cursor or a page mark, not both",
                    ));
                }
                let mut arrival = match since {
                    Some(h) => Some(self.mark(h, true, cursor_error)?.arrival),
                    None => None,
                };
                let mut display = match after {
                    Some(h) => {
                        self.mark(h, false, "page mark not in this room's timeline")?;
                        self.rendered.order().key(&h)?
                    }
                    None => None,
                };
                let mut rows = Vec::new();
                let mut used = 0usize;
                while rows.len() < limit && (rows.is_empty() || used < bytes) {
                    let next = if since.is_some() {
                        self.arrival(&mut arrival)?
                    } else {
                        self.display(&mut display, false)?
                    };
                    let Some(row) = next else { break };
                    let cost = row
                        .text
                        .len()
                        .saturating_add(crate::node::ipc::ROW_OVERHEAD);
                    if !rows.is_empty() && used.saturating_add(cost) > bytes {
                        break;
                    }
                    used = used.saturating_add(cost);
                    rows.push(row);
                }
                Ok(Reply::Rows(rows))
            }
            Query::Older { before, limit } => {
                let mut cursor = match before {
                    Some(h) => {
                        self.mark(h, false, cursor_error)?;
                        self.rendered.order().key(&h)?
                    }
                    None => None,
                };
                let total = self.count_before(cursor)?;
                let mut rows = Vec::new();
                let mut used = 0usize;
                while rows.len() < limit && (rows.is_empty() || used < bytes) {
                    let Some(row) = self.display(&mut cursor, true)? else {
                        break;
                    };
                    let cost = row
                        .text
                        .len()
                        .saturating_add(crate::node::ipc::ROW_OVERHEAD);
                    if !rows.is_empty() && used.saturating_add(cost) > bytes {
                        break;
                    }
                    used = used.saturating_add(cost);
                    rows.push(row);
                }
                let older = total
                    .checked_sub(rows.len() as u64)
                    .ok_or(Error::MalformedAtRest("history count smaller than page"))?;
                rows.reverse();
                Ok(Reply::Older { rows, older })
            }
            Query::Count { since } => {
                let mark = match since {
                    Some(h) => Some(self.mark(h, true, cursor_error)?.arrival),
                    None => None,
                };
                let last = self
                    .rendered
                    .step(None, false, None, true)?
                    .map(|((_, hash), _)| hash);
                let n = match mark {
                    Some(mark) => self.rendered.after_arrival(mark)?,
                    None => self.count_before(None)?,
                };
                Ok(Reply::Count { n, last })
            }
            Query::LocateUnread => {
                let entries = self.ch.unread(self.store)?;
                let mut found = BTreeSet::new();
                for hash in entries {
                    if self.rendered.fact(&hash)?.is_some() {
                        let key = self
                            .rendered
                            .order()
                            .key(&hash)?
                            .ok_or(Error::MalformedAtRest("unread order missing"))?;
                        found.insert(key);
                    }
                }
                Ok(Reply::Located {
                    entries: found.into_iter().map(|(_, h)| h).collect(),
                    revision: Revision::of(self.ch),
                })
            }
            Query::Locate { entries } => {
                if entries.len() > crate::node::ipc::MAX_FIND {
                    return Err(Failure::Request("too many message ids"));
                }
                let mut found = BTreeSet::new();
                for hash in entries {
                    if self.row(&hash)?.is_some() {
                        let key = self
                            .rendered
                            .order()
                            .key(&hash)?
                            .ok_or(Error::MalformedAtRest("located row order missing"))?;
                        found.insert(key);
                    }
                }
                Ok(Reply::Located {
                    entries: found.into_iter().map(|(_, h)| h).collect(),
                    revision: Revision::of(self.ch),
                })
            }
            Query::Exact { entry, revision } => {
                if !revision.current(self.ch) {
                    return Err(Failure::Request(CHANGED));
                }
                Ok(Reply::Exact(
                    self.row(&entry)?.ok_or(Failure::Request(CHANGED))?,
                ))
            }
        }
    }
}

impl ChannelState {
    pub(crate) fn history_instance(&self, store: &Store) -> Result<[u8; 16]> {
        Ok(self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?
            .history_instance())
    }
    pub(crate) fn last_arrival(&self, store: &Store) -> Result<Option<u64>> {
        self.entries
            .render_view(store, &self.sek, &self.channel_id)?
            .step(None, false, None, true)
            .map(|row| row.map(|(_, fact)| fact.cache))
    }

    pub(crate) fn history_query(
        &mut self,
        store: &Store,
        query: Query,
        max_bytes: usize,
        now_ms: u64,
    ) -> std::result::Result<Reply, String> {
        self.now_hint = self.now_hint.max(now_ms);
        if self.poisoned {
            return Err(self.save_failure().to_string());
        }
        let result = (|| -> Answer<Reply> {
            if !self.refresh_projection(store)? {
                return Err(Failure::Request(
                    "the room is refreshing saved history; retry",
                ));
            }
            let view = View {
                rendered: self
                    .entries
                    .render_view(store, &self.sek, &self.channel_id)?,
                ch: self,
                store,
            };
            view.answer(query, max_bytes)
        })();
        match result {
            Ok(reply) => Ok(reply),
            Err(Failure::Request(why)) => Err(why.into()),
            Err(Failure::Storage(error)) => {
                self.poison(&error);
                Err(error.to_string())
            }
        }
    }
}

/// A bounded refresh cursor, never a copy of rows. Policy/classification changes must
/// settle before exact projection answers; ordinary row changes update their own facts.
#[derive(Default)]
pub(super) struct State {
    policy: Option<[u64; 3]>,
    pending: bool,
    cursor: Option<(Digest32, u64)>,
    through: Option<(Digest32, u64)>,
    pub(super) cleanup_cursor: Option<(Digest32, u64)>,
}
impl State {
    pub(super) fn owed_range(&mut self, author: Digest32, from: u64, through: u64) {
        let before = Some((author, from.saturating_sub(1)));
        let end = Some((author, through));
        if self.pending {
            self.cursor = self.cursor.min(before);
            if self.through.is_some() {
                self.through = self.through.max(end);
            }
        } else {
            self.pending = true;
            self.cursor = before;
            self.through = end;
        }
    }
}
impl ChannelState {
    pub(super) fn owed_visibility(&self, entry: &Entry) -> Option<(u64, u64)> {
        let hash = entry.entry_hash();
        if entry.payload.is_some()
            || self.private_sessions.contains(&hash)
            || self.legacy_sessions.is_session(&hash)
            || !self
                .owed
                .contains(&(entry.skeleton.author_id, entry.skeleton.seq))
        {
            return None;
        }
        let created = entry.skeleton.claimed_ms;
        let ttl = self.entry_retention(entry);
        if expired_at(created, self.now_hint, ttl) {
            return None;
        }
        let expires = if ttl == 0 {
            u64::MAX
        } else {
            created.saturating_add(ttl.saturating_mul(1_000))
        };
        Some((created, expires))
    }
    /// At most 64 selected owed entries plus 64 expired visibility facts per actor turn.
    /// Exact counts never decrypt/scan the remaining history while a client waits.
    pub(crate) fn refresh_projection(&mut self, store: &Store) -> Result<bool> {
        let result = (|| -> Result<bool> {
            let policy = [
                self.effective_retention(),
                self.effective_step_retention(),
                self.legacy_sessions.display_revision(),
            ];
            if self.projection_state.policy != Some(policy) {
                self.projection_state.policy = Some(policy);
                self.projection_state.pending = true;
                self.projection_state.cursor = None;
                self.projection_state.through = None;
            }
            let mut batch = store.batch()?;
            let mut writer = self
                .entries
                .write(&mut batch, &self.sek, &self.channel_id)?;
            let mut changed = false;
            if self.projection_state.pending {
                use std::ops::Bound::{Excluded, Unbounded};
                let start = self.projection_state.cursor.map_or(Unbounded, Excluded);
                let end = self
                    .projection_state
                    .through
                    .map_or(Unbounded, std::ops::Bound::Included);
                let positions: Vec<_> = self.owed.range((start, end)).take(64).copied().collect();
                for (author, seq) in &positions {
                    let entry = writer
                        .get(author, *seq)?
                        .ok_or(Error::MalformedAtRest("owed entry missing"))?;
                    writer.set_owed(entry.entry_hash(), self.owed_visibility(&entry))?;
                }
                self.projection_state.cursor =
                    positions.last().copied().or(self.projection_state.cursor);
                self.projection_state.pending = positions.len() == 64;
                changed = true;
            }
            for _ in 0..64 {
                let Some(hash) = writer.first_expired_owed(self.now_hint)? else {
                    break;
                };
                writer.set_owed(hash, None)?;
                changed = true;
            }
            let expired_remain = writer.first_expired_owed(self.now_hint)?.is_some();
            if changed {
                writer.seal()?;
                batch.commit()?;
                self.entries.committed();
                self.invalidate_display();
            }
            Ok(!self.projection_state.pending && !expired_remain)
        })();
        if let Err(ref error) = result {
            self.poison(error);
        }
        result
    }
}
