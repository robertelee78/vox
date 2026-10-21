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
    MemberHellos {
        instance: Option<[u8; 16]>,
        revision: Option<Digest32>,
        before: Option<(u64, Digest32)>,
    },
    ViewPage {
        view: crate::node::api::RoomView,
        instance: Option<[u8; 16]>,
        before: Option<Digest32>,
        limit: usize,
    },
    ViewRows {
        view: crate::node::api::RoomView,
        instance: [u8; 16],
        entries: Vec<Digest32>,
    },
    ViewRevision {
        view: crate::node::api::RoomView,
        instance: [u8; 16],
        entries: Vec<Digest32>,
    },
    Footers {
        instance: [u8; 16],
        entries: Vec<crate::node::api::FooterSelection>,
        limit: usize,
    },
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
    MemberHellos(crate::node::api::MemberHelloPage),
    Footers {
        rows: Vec<crate::node::api::MessageFooter>,
        tags: Vec<Option<String>>,
    },
    Governance(crate::node::api::GovernancePage),
    DisplayRevision(Digest32),
    ArrivalHead(HistoryCursor),
    OperationPage {
        rows: Vec<MessageRow>,
        next: Option<(u64, Digest32)>,
        revision: u64,
        conflict_at: Option<u64>,
        examined: usize,
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
        /// The fold was behind the receipt frontier at this read (ADR-037 R3).
        provisional: bool,
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
    /// The room's fold was not current at read time (ADR-037 R3): the page is said to be
    /// provisional, never refused.
    provisional: bool,
}

impl View<'_> {
    fn accepted_cache_answer(&self, query: Query, bytes: usize) -> Answer<Reply> {
        use super::legacy_provisional::LEGACY_HISTORY_REQUIRED;
        // Counts, agreement and operation/attention authority require the completed current
        // projection. Cached row selection and its stable cursors remain usable.
        if !matches!(
            &query,
            Query::ViewPage { .. }
                | Query::ViewRows { .. }
                | Query::ViewRevision { .. }
                | Query::DisplayRevision
                | Query::ArrivalHead
                | Query::NoticeState
                | Query::NoticeExact { .. }
                | Query::NoticePage { .. }
                | Query::CursorPage { .. }
                | Query::Arrival { .. }
                | Query::Filtered { .. }
                | Query::Read { .. }
                | Query::Older { .. }
                | Query::Exact { .. }
        ) {
            return Err(Failure::Request(LEGACY_HISTORY_REQUIRED));
        }
        // The completed current authority and consent projection are held by the open room.
        // This unchanged read must not open even the governance header: acceptance invalidates
        // readiness and the bounded governance turn publishes the next in-memory revision.
        self.ch
            .require_governance_display(self.store, crate::time::Ms(self.ch.now_hint))?;
        let me = self.ch.me();
        let answer = self.answer(query, bytes)?;
        let facts = self.ch.consent_facts()?;
        let check = |row: &MessageRow| -> Answer<()> {
            // Owed placeholders are not accepted bodies. Do not expose unpublished
            // projection work or label it as an empty historical message.
            if row.owed {
                return Err(Failure::Request(LEGACY_HISTORY_REQUIRED));
            }
            if row.author != me
                && !self
                    .ch
                    .legacy_cache_trusted
                    .as_ref()
                    .is_some_and(|trusted| trusted.contains(&row.author))
            {
                return Err(Failure::Request(LEGACY_HISTORY_REQUIRED));
            }
            if row.author != me && !facts.can_read(&me, &row.author) {
                return Err(Failure::Request(LEGACY_HISTORY_REQUIRED));
            }
            let tracked = self
                .rendered
                .retention(&row.entry_hash)?
                .ok_or(Error::MalformedAtRest("cached row retention missing"))?;
            let entry = self
                .rendered
                .order()
                .entry(&row.entry_hash)?
                .ok_or(Error::MalformedAtRest("cached row source missing"))?;
            if expired_at(
                tracked.base(),
                self.ch.now_hint,
                self.ch
                    .entry_retention(self.rendered.transaction(), &entry)?,
            ) {
                return Err(Failure::Request(LEGACY_HISTORY_REQUIRED));
            }
            Ok(())
        };
        match &answer {
            Reply::Rows(rows) | Reply::Older { rows, .. } | Reply::Page { rows, .. } => {
                for row in rows {
                    check(row)?;
                }
            }
            Reply::CursorPage(page) => {
                for row in &page.rows {
                    check(row)?;
                }
            }
            Reply::NoticeExact(Some(row)) => check(&row.row)?,
            Reply::NoticePage(page) => {
                for row in &page.rows {
                    check(&row.row)?;
                }
            }
            Reply::Exact(row) => check(row)?,
            Reply::DisplayRevision(_)
            | Reply::ArrivalHead(_)
            | Reply::NoticeState(_)
            | Reply::NoticeExact(None) => {}
            _ => return Err(Failure::Request(LEGACY_HISTORY_REQUIRED)),
        }
        Ok(answer)
    }

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

    fn view_instance(&self, instance: [u8; 16]) -> Answer<()> {
        if instance != self.rendered.history_instance() {
            return Err(Failure::Request(
                "the saved room changed; open its current page again",
            ));
        }
        Ok(())
    }

    fn view_filter(&self, view: &crate::node::api::RoomView) -> Answer<Filter> {
        use crate::node::api::RoomView;
        match view {
            RoomView::General | RoomView::All => {
                if !self.rendered.room_views_ready()? {
                    return Err(Failure::Request(
                        "the room is preparing selected history; retry",
                    ));
                }
                Ok(Filter::General)
            }
            RoomView::Tag(tag) => {
                if !vox_agentcomms::envelope::is_valid_tag(tag) {
                    return Err(Failure::Request("invalid room history tag"));
                }
                Ok(Filter::Tag(tag.clone()))
            }
        }
    }
    fn view_contains(&self, filter: &Filter, hash: &Digest32) -> Result<bool> {
        Ok(self.rendered.contains(filter, hash)?
            || (matches!(filter, Filter::General) && self.rendered.is_owed(hash)?))
    }
    fn view_page(
        &self,
        view: &crate::node::api::RoomView,
        instance: Option<[u8; 16]>,
        before: Option<Digest32>,
        limit: usize,
        bytes: usize,
    ) -> Answer<Reply> {
        if instance.is_some_and(|value| value != self.rendered.history_instance()) {
            return Err(Failure::Request(
                "the saved room changed; open its current page again",
            ));
        }
        if before.is_some() && instance.is_none() {
            return Err(Failure::Request(
                "an earlier selected page requires its saved room identity",
            ));
        }
        let filter = self.view_filter(view)?;
        let mut cursor = match before {
            Some(hash) => {
                if !self.view_contains(&filter, &hash)? {
                    return Err(Failure::Request(
                        "cursor not among this room's selected messages",
                    ));
                }
                self.mark(
                    hash,
                    false,
                    "cursor not among this room's selected messages",
                )?;
                self.rendered.order().key(&hash)?
            }
            None => None,
        };
        let mut total = self.rendered.selected_before(&filter, cursor)?;
        if matches!(filter, Filter::General) {
            let owed = self.rendered.owed_before(cursor)?;
            if owed != 0 {
                self.ch
                    .require_legacy_classification_complete_in(self.rendered.transaction())?;
            }
            total = total
                .checked_add(owed)
                .ok_or(Error::MalformedAtRest("selected history count overflow"))?;
        }
        let mut rows = Vec::new();
        let mut used = 0usize;
        for _ in 0..limit.min(128) {
            let rendered = self
                .rendered
                .step(Some(&filter), true, cursor, true)?
                .map(|(key, _)| key);
            let owed = if matches!(filter, Filter::General) {
                self.rendered.owed_step(cursor, true)?
            } else {
                None
            };
            let key = match (rendered, owed) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
            let Some(key) = key else {
                break;
            };
            let row = self
                .row(&key.1)?
                .ok_or(Error::MalformedAtRest("selected visible row missing"))?;
            let cost = row
                .text
                .len()
                .saturating_add(crate::node::ipc::ROW_OVERHEAD);
            if !rows.is_empty() && used.saturating_add(cost) > bytes {
                break;
            }
            used = used.saturating_add(cost);
            cursor = Some(key);
            rows.push(row);
        }
        let older = total
            .checked_sub(rows.len() as u64)
            .ok_or(Error::MalformedAtRest(
                "selected history count smaller than page",
            ))?;
        rows.reverse();
        Ok(Reply::Older {
            rows,
            older,
            provisional: self.provisional,
        })
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
            provisional: self.provisional,
        })
    }

    fn member_hellos(
        &self,
        instance: Option<[u8; 16]>,
        known: Option<Digest32>,
        before: Option<(u64, Digest32)>,
        bytes: usize,
    ) -> Answer<Reply> {
        if let Some(instance) = instance {
            self.view_instance(instance)?;
        }
        if (known.is_some() && instance.is_none()) || (before.is_some() && known.is_none()) {
            return Err(Failure::Request(
                "member metadata continuation lacks its room/revision",
            ));
        }
        let filter = Filter::Type(vox_agentcomms::envelope::HELLO.into());
        let members = self.ch.members();
        use sha2::{Digest, Sha256};
        let mut stamp = Sha256::new();
        stamp.update(b"vox-member-hello-selection-v1");
        stamp.update(self.ch.channel_id());
        stamp.update(self.ch.me());
        stamp.update(self.rendered.history_instance());
        for value in [
            self.ch.projection_state.incarnation,
            self.rendered.filter_display_root(&filter)?,
            self.rendered.display_roots()[3],
            self.ch.effective_retention(),
            self.ch.effective_step_retention(),
        ] {
            stamp.update(value.to_be_bytes());
        }
        stamp.update((members.len() as u64).to_be_bytes());
        for member in &members {
            stamp.update(member);
        }
        let revision: Digest32 = stamp.finalize().into();
        let mut page = crate::node::api::MemberHelloPage {
            instance: self.rendered.history_instance(),
            revision,
            unchanged: known == Some(revision) && before.is_none(),
            rows: Vec::new(),
            next: None,
        };
        if page.unchanged {
            return Ok(Reply::MemberHellos(page));
        }
        // A changed selection explicitly restarts at its newest row. Clients replace their
        // small per-current-member map when the returned revision changes.
        let mut cursor = if known == Some(revision) {
            before
        } else {
            None
        };
        if let Some((clock, hash)) = cursor {
            if !self.rendered.contains(&filter, &hash)?
                || self.rendered.order().key(&hash)? != Some((clock, hash))
            {
                return Err(Failure::Request(
                    "member metadata cursor is not in this selection",
                ));
            }
        }
        let mut used = 0usize;
        for _ in 0..256 {
            let Some((key, _)) = self.rendered.step(Some(&filter), true, cursor, true)? else {
                return Ok(Reply::MemberHellos(page));
            };
            let author = self
                .rendered
                .order()
                .entry(&key.1)?
                .ok_or(Error::MalformedAtRest("member hello entry missing"))?
                .skeleton
                .author_id;
            if members.binary_search(&author).is_ok() {
                let row = self
                    .row(&key.1)?
                    .ok_or(Error::MalformedAtRest("member hello row missing"))?;
                let cost = row
                    .text
                    .len()
                    .saturating_add(crate::node::ipc::ROW_OVERHEAD);
                if !page.rows.is_empty() && used.saturating_add(cost) > bytes {
                    page.next = cursor;
                    return Ok(Reply::MemberHellos(page));
                }
                used = used.saturating_add(cost);
                page.rows.push(row);
            }
            cursor = Some(key);
            if page.rows.len() >= crate::node::ipc::MEMBER_HELLO_ROWS || used >= bytes {
                page.next = cursor;
                return Ok(Reply::MemberHellos(page));
            }
        }
        page.next = cursor;
        Ok(Reply::MemberHellos(page))
    }

    fn answer(&self, query: Query, bytes: usize) -> Answer<Reply> {
        let cursor_error = "cursor not in this room's timeline";
        match query {
            Query::MemberHellos {
                instance,
                revision,
                before,
            } => self.member_hellos(instance, revision, before, bytes),
            Query::ViewPage {
                view,
                instance,
                before,
                limit,
            } => self.view_page(&view, instance, before, limit, bytes),
            Query::ViewRows {
                view,
                instance,
                entries,
            } => {
                self.view_instance(instance)?;
                if entries.len() > crate::node::ipc::MAX_FIND {
                    return Err(Failure::Request("too many message ids"));
                }
                let filter = self.view_filter(&view)?;
                let mut found = BTreeMap::new();
                let mut used = 0usize;
                for hash in entries {
                    if !self.view_contains(&filter, &hash)? {
                        continue;
                    }
                    if let Some(row) = self.row(&hash)? {
                        let key = self
                            .rendered
                            .order()
                            .key(&hash)?
                            .ok_or(Error::MalformedAtRest("selected located row order missing"))?;
                        if found.contains_key(&key) {
                            continue;
                        }
                        used = used.saturating_add(row.text.len() + crate::node::ipc::ROW_OVERHEAD);
                        if !found.is_empty() && used > bytes {
                            return Err(Failure::Request(
                                crate::node::ipc::ROOM_VIEW_CHUNK_TOO_LARGE,
                            ));
                        }
                        found.insert(key, row);
                    }
                }
                // One bounded snapshot, released before IPC writes or waits. An unrelated
                // arrival cannot invalidate the middle of this selected chunk.
                Ok(Reply::Rows(found.into_values().collect()))
            }
            Query::ViewRevision {
                view,
                instance,
                entries,
            } => {
                self.view_instance(instance)?;
                if entries.len() > crate::node::ipc::MAX_ROOM_SELECTION {
                    return Err(Failure::Request("too many held message ids"));
                }
                let filter = self.view_filter(&view)?;
                use sha2::{Digest, Sha256};
                let mut hash = Sha256::new();
                hash.update(b"vox-room-held-selection-v1");
                hash.update(self.ch.channel_id());
                hash.update(instance);
                hash.update(self.ch.projection_state.incarnation.to_be_bytes());
                hash.update(self.ch.effective_retention().to_be_bytes());
                hash.update(self.ch.effective_step_retention().to_be_bytes());
                // A render epoch is a rewrite, not an ordinary append. No whole-history
                // count, root or arrival generation belongs to this selected-ID fence.
                hash.update(self.rendered.display_roots()[3].to_be_bytes());
                match view {
                    crate::node::api::RoomView::General => hash.update([0]),
                    crate::node::api::RoomView::All => hash.update([1]),
                    crate::node::api::RoomView::Tag(tag) => {
                        hash.update([2]);
                        hash.update((tag.len() as u64).to_be_bytes());
                        hash.update(tag.as_bytes());
                    }
                }
                hash.update((entries.len() as u64).to_be_bytes());
                for entry in entries {
                    hash.update(entry);
                    if !self.view_contains(&filter, &entry)? {
                        hash.update([0]);
                        continue;
                    }
                    let fact = self.rendered.fact(&entry)?;
                    if let Some(fact) = fact {
                        // The immutable entry/cache binding identifies the body without
                        // decrypting every selected body just to fingerprint the window.
                        hash.update([1]);
                        for value in [fact.cache, fact.epoch, fact.shown, fact.created] {
                            hash.update(value.to_be_bytes());
                        }
                    } else if let Some(row) = self.row(&entry)? {
                        // No render fact means only a currently readable owed placeholder
                        // can reach here. row() rechecks missing membership and expiry.
                        hash.update([2]);
                        hash.update(row.author);
                        hash.update(row.created_millis.to_be_bytes());
                    } else {
                        hash.update([0]);
                        continue;
                    }
                    let key = self
                        .rendered
                        .order()
                        .key(&entry)?
                        .ok_or(Error::MalformedAtRest("held selection order missing"))?;
                    if let Some(fact) = fact {
                        // Reordering elsewhere can alter the visible late label while this
                        // entry's own locator/order stays fixed. Hash only the derived bit,
                        // not the unrelated suffix root/count that produced it.
                        let (_, late) = self.rendered.display_timing(key, fact)?;
                        hash.update([u8::from(late)]);
                    }
                    hash.update(key.0.to_be_bytes());
                    hash.update(key.1);
                }
                Ok(Reply::DisplayRevision(hash.finalize().into()))
            }
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
            Query::Footers {
                instance,
                entries,
                limit,
            } => {
                if instance != self.rendered.history_instance() {
                    return Err(Failure::Request(
                        "the saved room changed; open its current page again",
                    ));
                }
                if entries.len() > 128
                    || limit == 0
                    || limit > if entries.len() == 1 { 64 } else { 8 }
                {
                    return Err(Failure::Request(
                        "displayed footers exceed one bounded page",
                    ));
                }
                let me = self.ch.me();
                let others: Vec<_> = self
                    .ch
                    .members()
                    .into_iter()
                    .filter(|member| *member != me)
                    .collect();
                let mut rows = Vec::new();
                let mut tags = Vec::new();
                for selection in entries {
                    let mut footer = crate::node::api::MessageFooter {
                        entry: selection.entry,
                        present: false,
                        read_by: Vec::new(),
                        read_after: None,
                        held: 0,
                        others: others.len() as u64,
                        pulled_by: Vec::new(),
                        pulled_after: None,
                    };
                    let mut tag = None;
                    if let Some(row) = self
                        .row(&selection.entry)?
                        .filter(|row| !row.owed && row.author == me)
                    {
                        let entry = self
                            .rendered
                            .order()
                            .entry(&selection.entry)?
                            .ok_or(Error::MalformedAtRest("footer entry missing"))?;
                        footer.present = true;
                        (footer.read_by, footer.read_after) = self.rendered.readers_page(
                            &selection.entry,
                            selection.read_after,
                            limit,
                        )?;
                        footer.held = others
                            .iter()
                            .filter(|member| {
                                self.ch
                                    .held
                                    .get(*member)
                                    .is_some_and(|head| *head >= entry.skeleton.seq)
                            })
                            .count() as u64;
                        if let Ok(envelope) = serde_json::from_str::<serde_json::Value>(&row.text) {
                            if envelope.get("type").and_then(serde_json::Value::as_str)
                                == Some(crate::node::shares::FILE)
                            {
                                tag = envelope
                                    .get("data")
                                    .and_then(|data| data.get("tag"))
                                    .and_then(serde_json::Value::as_str)
                                    .filter(|tag| tag.len() <= 512)
                                    .map(str::to_owned);
                            }
                        }
                    }
                    rows.push(footer);
                    tags.push(tag);
                }
                Ok(Reply::Footers { rows, tags })
            }

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
                let mut examined = 0;
                // Direct created/hash order, with a bounded examined budget even for rows
                // beyond the fixed arrival horizon. No query scans unrelated room history.
                for _ in 0..256 {
                    if rows.len() == crate::node::ipc::PAGE_ENTRIES {
                        return Ok(Reply::OperationPage {
                            rows,
                            next: cursor,
                            revision: current,
                            conflict_at,
                            examined,
                        });
                    }
                    let Some((key, fact)) = self.rendered.operation_next(current, cursor)? else {
                        return Ok(Reply::OperationPage {
                            rows,
                            next: None,
                            revision: current,
                            conflict_at,
                            examined,
                        });
                    };
                    examined += 1;
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
                                examined,
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
                    examined,
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
                Ok(Reply::Older {
                    rows,
                    older,
                    provisional: self.provisional,
                })
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
    /// One bounded turn of derived view-index catch-up: (more work, just became ready).
    pub(crate) fn advance_room_views(&self, store: &Store) -> Result<(bool, bool)> {
        // A paused v1 request is not a scheduled view-rebuild job. Its accepted selector
        // remains readable; an absent selector reports pending on that selected read.
        if self.legacy_cache_only(store)? {
            return Ok((false, false));
        }
        let was_ready = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?
            .room_views_ready()?;
        let more = self
            .entries
            .advance_room_views(store, &self.sek, &self.channel_id)?;
        Ok((more, !was_ready && !more))
    }
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
            if self.legacy_cache_only(store)? {
                // The currently accepted fold, never the unpublished witness, authorizes
                // this bounded cache selection. It performs no EntryIndex mutation.
                let view = View {
                    rendered: self
                        .entries
                        .render_view(store, &self.sek, &self.channel_id)?,
                    ch: self,
                    store,
                    provisional: !self.governance_ready,
                };
                return view.accepted_cache_answer(query, max_bytes);
            }
            // ADR-037 R3/R4: a page is answered from what this node holds; a fold behind its
            // receipts marks the page provisional and never refuses it. The legacy-recovery
            // gate above (`legacy_cache_only`) stays. Measured before this: a newcomer's
            // `vox room read --json --limit 25` was refused "room governance is refreshing"
            // while the control entries of the room he had just joined were still folding.
            // Acceptance invalidates the in-memory publication before the source Batch can be
            // used. The bounded governance turn restores it after publishing the new revision,
            // so an unchanged read neither opens nor decrypts the governance header.
            let provisional = !self.governance_display_current(now_ms);
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
                provisional,
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
    /// Persist only bounded progress; incarnation remains new for every live room.
    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut e = crate::cbor::Encoder::new();
        e.array(6).uint(1);
        match self.policy {
            Some(policy) => {
                e.array(3);
                for part in policy {
                    e.uint(part);
                }
            }
            None => {
                e.array(0);
            }
        }
        e.uint(u64::from(self.pending));
        for position in [self.cursor, self.through, self.cleanup_cursor] {
            match position {
                Some((author, seq)) => {
                    e.array(2).bytes(&author).uint(seq);
                }
                None => {
                    e.array(0);
                }
            }
        }
        e.finish()
    }
    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut d = crate::cbor::Decoder::new(bytes);
        if d.array()? != 6 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest("projection restart format"));
        }
        let policy = match d.array()? {
            0 => None,
            3 => Some([d.uint()?, d.uint()?, d.uint()?]),
            _ => return Err(Error::MalformedAtRest("projection restart policy")),
        };
        let pending = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedAtRest("projection restart pending")),
        };
        let mut positions = [None; 3];
        for position in &mut positions {
            *position = match d.array()? {
                0 => None,
                2 => Some((
                    d.bytes()?
                        .try_into()
                        .map_err(|_| Error::MalformedAtRest("projection restart author"))?,
                    d.uint()?,
                )),
                _ => return Err(Error::MalformedAtRest("projection restart position")),
            };
        }
        d.finish()?;
        Ok(Self {
            policy,
            pending,
            cursor: positions[0],
            through: positions[1],
            cleanup_cursor: positions[2],
            ..Self::default()
        })
    }
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
            let before = self.projection_state.to_bytes();
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
            let progress = self.projection_state.to_bytes();
            if changed || before != progress {
                writer.note_projection(progress)?;
                writer.seal()?;
                batch.commit()?;
                self.entries.committed();
                if changed {
                    self.invalidate_display();
                }
            }
            Ok(!self.projection_state.pending && !expired_remain)
        })();
        if let Err(ref error) = result {
            self.poison(error);
        }
        result
    }
}
