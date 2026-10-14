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
    Governance(crate::node::api::GovernanceQuery),
    DisplayRevision,
    ArrivalHead,
    OperationPage {
        author: Digest32,
        op: String,
        through: HistoryCursor,
        after: Option<(u64, Digest32)>,
        revision: Option<u64>,
    },
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
    UnreadSummary,
    Arrival {
        after: Option<u64>,
        limit: usize,
    },
    ThreadPage {
        root: Digest32,
        before: Option<Digest32>,
        after: Option<Digest32>,
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
    Governance(crate::node::api::GovernancePage),
    DisplayRevision(Digest32),
    ArrivalHead(HistoryCursor),
    OperationPage {
        rows: Vec<MessageRow>,
        next: Option<(u64, Digest32)>,
        revision: u64,
        conflict_at: Option<u64>,
    },
    NoticeState(NoticeState),
    NoticeExact(Option<NoticeRow>),
    NoticePage(NoticePage),
    CursorPage(MessagePage),
    ThreadPage {
        rows: Vec<MessageRow>,
        before: Option<Digest32>,
        after: Option<Digest32>,
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
    UnreadSummary(crate::node::api::UnreadSummary),
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
    rendered_roots: [u64; 4],
}

impl Revision {
    fn of(ch: &ChannelState, rendered: &entry_store::RenderView<'_>) -> Result<Self> {
        Ok(Self {
            incarnation: ch.gen.clone(),
            facts: [
                ch.gen.load(std::sync::atomic::Ordering::Relaxed),
                ch.display_rewrite,
                rendered.count()?,
                ch.dag.reorder_generation(),
                ch.dag.body_generation(),
                ch.legacy_sessions.display_revision(),
                ch.effective_retention(),
                ch.effective_step_retention(),
            ],
            rendered_roots: rendered.display_roots(),
        })
    }
    fn current(&self, ch: &ChannelState, rendered: &entry_store::RenderView<'_>) -> Result<bool> {
        let now = Self::of(ch, rendered)?;
        Ok(Arc::ptr_eq(&self.incarnation, &now.incarnation)
            && self.facts == now.facts
            && self.rendered_roots == now.rendered_roots)
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
                .rendered
                .missing_contains(&entry.skeleton.author_id, entry.skeleton.seq)?
            || expired_at(
                entry.skeleton.claimed_ms,
                self.ch.now_hint,
                self.ch
                    .entry_retention(self.rendered.transaction(), &entry)?,
            )
            || self
                .ch
                .legacy_is_session_current_in(self.rendered.transaction(), hash)?
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
        let owed = self.rendered.owed_before(before)?;
        if owed != 0 {
            self.ch
                .require_legacy_classification_complete_in(self.rendered.transaction())?;
        }
        rendered
            .checked_add(owed)
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
        let ttl = self
            .ch
            .entry_retention(self.rendered.transaction(), &entry)?;
        let expires = if ttl == 0 {
            None
        } else {
            let tracked = self
                .rendered
                .retention(&row.entry_hash)?
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
            Query::DisplayRevision => {
                use sha2::{Digest, Sha256};
                let revision = Revision::of(self.ch, &self.rendered)?;
                let mut hash = Sha256::new();
                hash.update(b"vox-room-history-revision-v1");
                hash.update(self.ch.channel_id());
                hash.update(self.rendered.history_instance());
                hash.update(self.ch.projection_state.incarnation.to_be_bytes());
                for fact in revision.facts {
                    hash.update(fact.to_be_bytes());
                }
                for root in revision.rendered_roots {
                    hash.update(root.to_be_bytes());
                }
                Ok(Reply::DisplayRevision(hash.finalize().into()))
            }
            Query::Governance(query) => Ok(Reply::Governance(
                self.ch.governance_page(self.store, query)?,
            )),
            Query::ArrivalHead => Ok(Reply::ArrivalHead(self.head()?)),
            Query::OperationPage {
                author,
                op,
                through,
                after,
                revision,
            } => {
                if through.instance != self.rendered.history_instance() {
                    return Err(Failure::Request(
                        "the saved room changed during operation lookup; retry",
                    ));
                }
                let (current, conflict_at) = self.rendered.operation_state(&author, &op)?;
                let conflict_at = conflict_at.filter(|arrival| *arrival <= through.arrival);
                if revision.is_some_and(|revision| revision != current) {
                    return Err(Failure::Request(
                        "the selected operation changed during lookup; retry",
                    ));
                }
                let mut cursor = after;
                let mut rows = Vec::new();
                let mut used = 0usize;
                // Direct created/hash order, with a bounded examined budget even for rows
                // beyond the fixed arrival horizon. No query scans unrelated room history.
                for _ in 0..256 {
                    if rows.len() == crate::node::ipc::PAGE_ENTRIES {
                        return Ok(Reply::OperationPage {
                            rows,
                            next: cursor,
                            revision: current,
                            conflict_at,
                        });
                    }
                    let Some((key, fact)) = self.rendered.operation_next(current, cursor)? else {
                        return Ok(Reply::OperationPage {
                            rows,
                            next: None,
                            revision: current,
                            conflict_at,
                        });
                    };
                    if fact.cache <= through.arrival {
                        let row = self
                            .row(&key.1)?
                            .ok_or(Error::MalformedAtRest("operation row missing"))?;
                        if row.author != author
                            || crate::node::api::structured_kind(&row.text)
                                .and_then(|(_, found)| found)
                                .as_deref()
                                != Some(op.as_str())
                        {
                            return Err(Failure::Storage(Error::MalformedAtRest(
                                "operation row binding",
                            )));
                        }
                        let cost = row
                            .text
                            .len()
                            .saturating_add(crate::node::ipc::ROW_OVERHEAD);
                        if !rows.is_empty() && used.saturating_add(cost) > bytes {
                            return Ok(Reply::OperationPage {
                                rows,
                                next: cursor,
                                revision: current,
                                conflict_at,
                            });
                        }
                        used = used.saturating_add(cost);
                        rows.push(row);
                    }
                    cursor = Some(key);
                }
                Ok(Reply::OperationPage {
                    rows,
                    next: cursor,
                    revision: current,
                    conflict_at,
                })
            }
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
            Query::ThreadPage {
                root,
                before,
                after,
            } => {
                if before.is_some() && after.is_some() {
                    return Err(Failure::Request(
                        "choose either earlier or later thread replies",
                    ));
                }
                let filter = Filter::Thread(root);
                let anchor = before.or(after);
                let mut cursor = if let Some(hash) = anchor {
                    if !self.rendered.contains(&filter, &hash)? {
                        return Err(Failure::Request(
                            "cursor not among this room's thread replies",
                        ));
                    }
                    let fact = self.rendered.fact(&hash)?.ok_or(Failure::Request(
                        "cursor not among this room's thread replies",
                    ))?;
                    Some((fact.cache, hash))
                } else {
                    None
                };
                let anchor_key = cursor;
                let backwards = before.is_some();
                let mut rows = Vec::new();
                let mut used = 0usize;
                let mut first = None;
                let mut last = None;
                for _ in 0..crate::node::ipc::PAGE_ENTRIES {
                    let Some((key, _)) =
                        self.rendered
                            .step(Some(&filter), false, cursor, backwards)?
                    else {
                        break;
                    };
                    let row = self
                        .row(&key.1)?
                        .ok_or(Error::MalformedAtRest("thread row missing"))?;
                    let cost = row
                        .text
                        .len()
                        .saturating_add(crate::node::ipc::ROW_OVERHEAD);
                    if !rows.is_empty() && used.saturating_add(cost) > bytes {
                        break;
                    }
                    used = used.saturating_add(cost);
                    if first.is_none() {
                        first = Some(key);
                    }
                    last = Some(key);
                    cursor = Some(key);
                    rows.push(row);
                }
                if backwards {
                    rows.reverse();
                    std::mem::swap(&mut first, &mut last);
                }
                let first = first.or(anchor_key);
                let last = last.or(anchor_key);
                let before = match first {
                    Some(key)
                        if self
                            .rendered
                            .step(Some(&filter), false, Some(key), true)?
                            .is_some() =>
                    {
                        Some(key.1)
                    }
                    _ => None,
                };
                let after = match last {
                    Some(key)
                        if self
                            .rendered
                            .step(Some(&filter), false, Some(key), false)?
                            .is_some() =>
                    {
                        Some(key.1)
                    }
                    _ => None,
                };
                Ok(Reply::ThreadPage {
                    rows,
                    before,
                    after,
                })
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
            Query::UnreadSummary => {
                use vox_agentcomms::attention::{unread_level, UnreadLevel};
                let mut summary = crate::node::api::UnreadSummary::default();
                let me = self.ch.me();
                let name = crate::node::link::b32_encode(&me);
                let mut cursor = None;
                let mut examined = 0;
                let mut reached_read = false;
                for _ in 0..UNREAD_LOOKED {
                    let Some((key, _)) = self.rendered.step(None, true, cursor, true)? else {
                        break;
                    };
                    cursor = Some(key);
                    examined += 1;
                    if self.rendered.was_read(&key.1, &me)? {
                        reached_read = true;
                        break;
                    }
                    let Some(row) = self.row(&key.1)? else {
                        continue;
                    };
                    if row.author == me {
                        continue;
                    }
                    match unread_level(&row.text, Some(&name)) {
                        UnreadLevel::ToYou => {
                            summary.addressed += 1;
                            if vox_agentcomms::envelope::Envelope::parse(&row.text)
                                .is_ok_and(|e| e.urgent)
                            {
                                summary.urgent += 1;
                            }
                        }
                        UnreadLevel::New => summary.new += 1,
                        UnreadLevel::Coordination => summary.coordination += 1,
                    }
                    summary.first = Some(row.entry_hash);
                }
                summary.scan_limited = !reached_read
                    && examined == UNREAD_LOOKED
                    && self.rendered.step(None, true, cursor, true)?.is_some();
                Ok(Reply::UnreadSummary(summary))
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
                    revision: Revision::of(self.ch, &self.rendered)?,
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
                    revision: Revision::of(self.ch, &self.rendered)?,
                })
            }
            Query::Exact { entry, revision } => {
                if !revision.current(self.ch, &self.rendered)? {
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
            let query = match query {
                Query::Governance(query) => {
                    return self
                        .governance_page(store, query)
                        .map(Reply::Governance)
                        .map_err(|e| match e {
                            Error::Profile(why) => Failure::Request(why),
                            e => Failure::Storage(e),
                        })
                }
                query => query,
            };
            self.require_governance_ready(store, crate::time::Ms(now_ms))
                .map_err(|e| match e {
                    Error::Profile(why) => Failure::Request(why),
                    e => Failure::Storage(e),
                })?;
            self.prune_retention_page(store)?;
            if self.retention_due(store, 0)?.1 {
                return Err(Failure::Request(
                    "the room is removing expired saved history; retry",
                ));
            }
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
pub(super) struct State {
    /// Unique for this open room in this process; the public token also binds the actor's
    /// random lifetime. An allocator address alone could be reused after closing the room.
    incarnation: u64,
    policy: Option<[u64; 3]>,
    pending: bool,
    cursor: Option<(Digest32, u64)>,
    through: Option<(Digest32, u64)>,
    pub(super) cleanup_cursor: Option<(Digest32, u64)>,
}
impl Default for State {
    fn default() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            incarnation: NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            policy: None,
            pending: false,
            cursor: None,
            through: None,
            cleanup_cursor: None,
        }
    }
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
    /// Caller has established missing membership in the current Batch.
    pub(super) fn owed_visibility(
        &self,
        batch: &crate::node::store::Batch<'_>,
        entry: &Entry,
    ) -> Result<Option<(u64, u64)>> {
        let hash = entry.entry_hash();
        if entry.payload.is_some()
            || self.private_contains_in(batch, &hash)?
            || self.legacy_is_session_in(Transaction::Batch(batch), &hash)?
        {
            return Ok(None);
        }
        let created = entry.skeleton.claimed_ms;
        let ttl = self.entry_retention(Transaction::Batch(batch), entry)?;
        if expired_at(created, self.now_hint, ttl) {
            return Ok(None);
        }
        let expires = if ttl == 0 {
            u64::MAX
        } else {
            created.saturating_add(ttl.saturating_mul(1_000))
        };
        Ok(Some((created, expires)))
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
                let (positions, next) = writer.missing_page(self.projection_state.cursor, 64)?;
                let mut through = false;
                for (author, seq) in positions {
                    if self
                        .projection_state
                        .through
                        .is_some_and(|end| (author, seq) > end)
                    {
                        through = true;
                        break;
                    }
                    self.projection_state.cursor = Some((author, seq));
                    let entry = writer
                        .get(&author, seq)?
                        .ok_or(Error::MalformedAtRest("owed entry missing"))?;
                    let visibility = self.owed_visibility(writer.batch(), &entry)?;
                    writer.set_owed(entry.entry_hash(), visibility)?;
                    changed = true;
                }
                self.projection_state.pending = !through
                    && next.is_some()
                    && self
                        .projection_state
                        .through
                        .is_none_or(|end| self.projection_state.cursor < Some(end));
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
