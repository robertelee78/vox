//! One on-demand page and exact count on one captured eligibility view. There is no
//! durable cursor/service here, no physical pruning, and no snapshot switch on yield.
use super::*;
use crate::node::history_budget::{BufferCharge, Job, OutputCharge};
use crate::node::store::Snapshot;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Notify, OwnedRwLockReadGuard, RwLock};

/// One fixed erasure barrier per open room, not a table of jobs. A retiring room
/// cancels readers before awaiting only their actual bounded physical tails.
pub(crate) struct ReadLifetime {
    retired: AtomicBool,
    changed: Arc<Notify>,
    work: Arc<RwLock<()>>,
}
impl ReadLifetime {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            retired: AtomicBool::new(false),
            changed: Arc::new(Notify::new()),
            work: Arc::new(RwLock::new(())),
        })
    }
    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
    pub(crate) fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }
    pub(crate) async fn retired(&self) {
        let mut wake = Box::pin(Arc::clone(&self.changed).notified_owned());
        wake.as_mut().enable();
        if !self.is_retired() {
            wake.await;
        }
    }
    pub(crate) async fn drain(&self) {
        drop(Arc::clone(&self.work).write_owned().await);
    }
    pub(crate) fn lease(&self) -> Result<Arc<OwnedRwLockReadGuard<()>>> {
        if self.is_retired() {
            return Err(Error::AtRestLocked);
        }
        let held = Arc::clone(&self.work)
            .try_read_owned()
            .map_err(|_| Error::AtRestLocked)?;
        if self.is_retired() {
            return Err(Error::AtRestLocked);
        }
        Ok(Arc::new(held))
    }
}

/// The owning room/node retires its lifetime when it goes away; captured Arc leases
/// cannot postpone this signal by keeping the lifetime object itself alive.
pub(crate) struct ReadOwner(Arc<ReadLifetime>);
impl ReadOwner {
    pub(crate) fn new() -> Self {
        Self(ReadLifetime::new())
    }
}
impl std::ops::Deref for ReadOwner {
    type Target = Arc<ReadLifetime>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for ReadOwner {
    fn drop(&mut self) {
        self.0.retire();
    }
}

/// All buffers and both erasure barriers follow the real operation, including a
/// blocking child which its async supervisor cannot abort. Declared after secrets.
pub(crate) struct ReadLeases {
    _charge: BufferCharge,
    _job: Job,
    _secret_work: Arc<OwnedRwLockReadGuard<()>>,
    _room_work: Arc<OwnedRwLockReadGuard<()>>,
}
impl ReadLeases {
    pub(crate) fn work_bytes() -> usize {
        // Existing bounded directory decode/cache, one canonical wire/cipher/Entry peak,
        // cache text decode, reply + serialization copy and bounded trust/author metadata.
        entry_store::EntryIndex::read_work_bytes()
            + 4 * crate::log::history::MAX_ENTRY_WIRE
            + 3 * (crate::node::content::MAX_TEXT_LEN + crate::node::ipc::ROW_OVERHEAD)
            + 2 * crate::node::ipc::ROWS_BUDGET
            + crate::node::trust::MAX_TRUSTED * (4 * std::mem::size_of::<Digest32>())
            + AUTHORS_HARD_LIMIT * (3 * std::mem::size_of::<Digest32>())
    }
    pub(crate) fn from_reserved(
        job: Job,
        charge: BufferCharge,
        secret: Arc<OwnedRwLockReadGuard<()>>,
        room: Arc<OwnedRwLockReadGuard<()>>,
    ) -> Self {
        Self {
            _charge: charge,
            _job: job,
            _secret_work: secret,
            _room_work: room,
        }
    }
    fn into_reply(mut self) -> Result<ReplyLeases> {
        // Reply rows, complete encoded frame and byte-page encoder coexist during IPC.
        // Every snapshot/cache/key/canonical-wire buffer is gone before this conversion.
        let keep = 2 * crate::node::ipc::MAX_FRAME + crate::node::ipc::ROWS_BUDGET;
        let kept = self
            ._charge
            .split_off(keep)
            .ok_or(Error::MalformedAtRest("page reply charge missing"))?;
        let output = kept
            .into_output()
            .map_err(|_| Error::MalformedAtRest("page output used non-shared lane"))?;
        let ReadLeases {
            _charge,
            _job,
            _secret_work,
            _room_work,
        } = self;
        drop(_charge);
        drop(_job);
        Ok(ReplyLeases {
            _charge: output,
            _secret_work,
            _room_work,
        })
    }
}

struct ReplyLeases {
    _charge: OutputCharge,
    _secret_work: Arc<OwnedRwLockReadGuard<()>>,
    _room_work: Arc<OwnedRwLockReadGuard<()>>,
}

#[derive(Clone)]
pub(crate) struct Scope {
    pub room: Digest32,
    pub node: Digest32,
    pub instance: [u8; 16],
    pub epoch: u64,
    pub regular: u64,
    pub steps: u64,
    pub classification: u64,
    pub lifetime: Arc<ReadLifetime>,
    pub node_lifetime: Arc<ReadLifetime>,
    pub legacy: bool,
    pub legacy_authors: Vec<Digest32>,
    // Stamped by the original supervisor before first publication, never authority.
    pub reference: std::sync::Weak<tokio::sync::Mutex<ChannelState>>,
    pub store: std::sync::Weak<crate::node::store::Store>,
}

pub(crate) struct Capture {
    index: entry_store::CapturedIndex,
    key: Sek,
    scope: Scope,
    policy: entry_store::ExpiryPolicy,
    render_epoch: u64,
    verified: BTreeMap<Digest32, u64>,
    footer_members: Vec<(Digest32, u64)>,
    provisional: bool,
    _leases: ReadLeases,
}

pub(crate) enum CapturePlan {
    Owned(Box<Capture>),
    Legacy {
        scope: Box<Scope>,
        leases: ReadLeases,
    },
}
/// This wrapper is kept through current-scope publication and IPC writing. Cancelled
/// results wipe their plaintext; a successful typed handoff explicitly takes the reply.
pub(crate) struct Answer {
    pub scope: Scope,
    reply: Option<Reply>,
    leases: Option<ReplyLeases>,
}
pub(crate) struct ReplyLease {
    scope: Scope,
    _leases: ReplyLeases,
}
impl ReplyLease {
    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }
    pub(crate) fn is_retired(&self) -> bool {
        self.scope.lifetime.is_retired() || self.scope.node_lifetime.is_retired()
    }
    pub(crate) async fn retired(&self) {
        tokio::select! { () = self.scope.lifetime.retired() => {}, () = self.scope.node_lifetime.retired() => {} }
    }
}
impl Answer {
    pub(crate) fn reply(&self) -> Option<&Reply> {
        self.reply.as_ref()
    }
    pub(crate) fn is_retired(&self) -> bool {
        self.scope.lifetime.is_retired() || self.scope.node_lifetime.is_retired()
    }
    pub(crate) async fn retired(&self) {
        tokio::select! { () = self.scope.lifetime.retired() => {}, () = self.scope.node_lifetime.retired() => {} }
    }
    /// Arrival-head contains only a fixed scalar cursor, never plaintext buffers.
    pub(crate) fn arrival_head(&self) -> std::result::Result<HistoryCursor, String> {
        if self.is_retired() {
            return Err("the room read was retired".into());
        }
        match self.reply() {
            Some(Reply::ArrivalHead(head)) => Ok(*head),
            _ => Err("unexpected arrival-head answer".into()),
        }
    }
    pub(crate) fn into_parts(mut self) -> std::result::Result<(Reply, ReplyLease), String> {
        // Take the lease first: on an invalid handoff the still-owned reply is
        // scrubbed by Answer::drop before its remaining erasure guards release.
        let leases = self.leases.take().ok_or("owned page lease missing")?;
        let reply = self.reply.take().ok_or("owned page reply missing")?;
        let lease = ReplyLease {
            scope: self.scope.clone(),
            _leases: leases,
        };
        Ok((reply, lease))
    }
}
fn scrub(reply: &mut Reply) {
    use zeroize::Zeroize;
    let rows = match reply {
        Reply::Rows(rows)
        | Reply::Older { rows, .. }
        | Reply::Page { rows, .. }
        | Reply::ThreadPage { rows, .. }
        | Reply::OperationPage { rows, .. } => Some(rows),
        Reply::CursorPage(page) => Some(&mut page.rows),
        Reply::MemberHellos(page) => Some(&mut page.rows),
        _ => None,
    };
    if let Some(rows) = rows {
        for row in rows {
            row.text.zeroize();
        }
        return;
    }
    match reply {
        Reply::Exact(row) => row.text.zeroize(),
        Reply::NoticeExact(Some(row)) => row.row.text.zeroize(),
        Reply::NoticePage(page) => {
            for row in &mut page.rows {
                row.row.text.zeroize();
            }
        }
        Reply::Footers { tags, .. } => {
            for tag in tags.iter_mut().flatten() {
                tag.zeroize();
            }
        }
        _ => {}
    }
}
struct PendingReply(Option<Reply>);
impl Drop for PendingReply {
    fn drop(&mut self) {
        if let Some(reply) = &mut self.0 {
            scrub(reply);
        }
    }
}
impl Drop for Answer {
    fn drop(&mut self) {
        if let Some(reply) = &mut self.reply {
            scrub(reply);
        }
    }
}
impl Answer {
    pub(crate) fn legacy(mut scope: Scope, mut reply: Reply, leases: ReadLeases) -> Result<Self> {
        if !matches!(
            reply,
            Reply::Older { .. } | Reply::ArrivalHead(_) | Reply::Footers { .. }
        ) {
            scrub(&mut reply);
            return Err(Error::MalformedAtRest("unexpected owned page reply"));
        }
        if let Reply::Older { rows, .. } = &reply {
            scope.legacy_authors = rows.iter().map(|row| row.author).collect();
            scope.legacy_authors.sort();
            scope.legacy_authors.dedup();
        }
        Self::finish(scope, reply, leases)
    }
    fn finish(scope: Scope, reply: Reply, leases: ReadLeases) -> Result<Self> {
        let mut pending = PendingReply(Some(reply));
        let leases = leases.into_reply()?;
        Ok(Self {
            scope,
            reply: pending.0.take(),
            leases: Some(leases),
        })
    }
}

pub(crate) fn consume_native<T>(
    answer: Answer,
    consume: impl FnOnce(&crate::node::api::HistoryPage) -> T,
) -> std::result::Result<T, String> {
    if answer.is_retired() {
        return Err("the room read was retired".into());
    }
    if !matches!(answer.reply(), Some(Reply::Older { .. })) {
        return Err("unexpected owned page reply".into());
    }
    let (reply, lease) = answer.into_parts()?;
    let Reply::Older {
        rows,
        older,
        provisional,
    } = reply
    else {
        return Err("unexpected owned page reply".into());
    };
    struct NativePage {
        page: crate::node::api::HistoryPage,
        lease: ReplyLease,
    }
    impl Drop for NativePage {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            for row in &mut self.page.rows {
                row.text.zeroize();
            }
        }
    }
    let owned = NativePage {
        page: crate::node::api::HistoryPage {
            rows,
            older,
            provisional,
        },
        lease,
    };
    if owned.lease.is_retired() {
        return Err("the room read was retired".into());
    }
    Ok(consume(&owned.page))
}

pub(crate) fn is_page(query: &Query) -> bool {
    matches!(
        query,
        Query::Older { .. } | Query::ViewPage { .. } | Query::ArrivalHead | Query::Footers { .. }
    )
}

impl ChannelState {
    pub(crate) fn page_read_lifetime(&self) -> Arc<ReadLifetime> {
        Arc::clone(&self.page_reads)
    }
    pub(crate) fn page_scope_current(&self, _store: &Store, scope: &Scope) -> Result<bool> {
        Ok(!self.poisoned
            && !self.history_retirement_locked()
            && !scope.lifetime.is_retired()
            && !scope.node_lifetime.is_retired()
            && Arc::ptr_eq(&self.page_reads, &scope.lifetime)
            && self.me() == scope.node
            && self.epoch == scope.epoch
            && self
                .entries
                .read_identity_current(scope.instance, scope.legacy)
            && self.effective_retention() == scope.regular
            && self.effective_step_retention() == scope.steps
            && self.legacy_sessions.display_revision() == scope.classification)
    }
    pub(crate) fn legacy_page_authorized(
        &self,
        store: &Store,
        scope: &Scope,
        trusted: &crate::node::trust::Keyring,
        now: u64,
    ) -> Result<bool> {
        if !scope.legacy {
            return Ok(true);
        }
        self.require_governance_display(store, crate::time::Ms(now))?;
        let facts = self.consent_facts()?;
        Ok(scope.legacy_authors.iter().all(|author| {
            *author == self.me()
                || (trusted.is_trusted(author) && facts.can_read(&self.me(), author))
        }))
    }
    pub(crate) fn capture_page_read(
        &self,
        store: &Store,
        leases: ReadLeases,
        now: u64,
        node_lifetime: Arc<ReadLifetime>,
    ) -> Result<CapturePlan> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if self.page_reads.is_retired() || self.history_retirement_locked() {
            return Err(Error::AtRestLocked);
        }
        let index = self.entries.capture(store, &self.sek, &self.channel_id)?;
        // Generic index restore may still be minting an old layout's zero instance.
        // A published owned page must already have its real saved-room identity.
        if index.instance() == [0; 16] {
            return Err(Error::Profile("saved room identity is not prepared"));
        }
        let scope = Scope {
            room: self.channel_id,
            node: self.me(),
            instance: index.instance(),
            epoch: self.epoch,
            regular: self.effective_retention(),
            steps: self.effective_step_retention(),
            classification: self.legacy_sessions.display_revision(),
            lifetime: Arc::clone(&self.page_reads),
            node_lifetime,
            legacy: index.legacy_cache_only(),
            legacy_authors: Vec::new(),
            reference: std::sync::Weak::new(),
            store: std::sync::Weak::new(),
        };
        if scope.legacy {
            drop(index);
            return Ok(CapturePlan::Legacy {
                scope: Box::new(scope),
                leases,
            });
        }
        let key = Sek::from_bytes(Zeroizing::new(
            self.sek
                .key_bytes()?
                .try_into()
                .map_err(|_| Error::MalformedAtRest("room SEK length"))?,
        ));
        let render_epoch = index.render_epoch();
        let policy = entry_store::ExpiryPolicy {
            now: now.max(self.now_hint),
            regular: scope.regular,
            steps: scope.steps,
        };
        let verified = self
            .authors
            .keys()
            .map(|author| (*author, self.dag.verified_head(author)))
            .collect();
        Ok(CapturePlan::Owned(Box::new(Capture {
            index,
            key,
            scope,
            policy,
            render_epoch,
            verified,
            footer_members: self
                .members()
                .into_iter()
                .filter(|member| *member != self.me())
                .map(|member| (member, self.held.get(&member).copied().unwrap_or(0)))
                .collect(),
            provisional: !self.governance_display_current(now),
            _leases: leases,
        })))
    }
}

struct PageSpec {
    filter: Option<Filter>,
    before: Option<Digest32>,
    limit: usize,
    instance: Option<[u8; 16]>,
}
impl PageSpec {
    fn from_query(query: Query) -> Result<Self> {
        match query {
            Query::Older { before, limit } => Ok(Self {
                filter: None,
                before,
                limit,
                instance: None,
            }),
            Query::ViewPage {
                view,
                instance,
                before,
                limit,
            } => {
                let filter = match view {
                    crate::node::api::RoomView::General | crate::node::api::RoomView::All => {
                        Filter::General
                    }
                    crate::node::api::RoomView::Tag(tag) => {
                        if !vox_agentcomms::envelope::is_valid_tag(&tag) {
                            return Err(Error::Profile("invalid room history tag"));
                        }
                        Filter::Tag(tag)
                    }
                };
                if before.is_some() && instance.is_none() {
                    return Err(Error::Profile(
                        "an earlier selected page requires its saved room identity",
                    ));
                }
                Ok(Self {
                    filter: Some(filter),
                    before,
                    limit: limit.min(128),
                    instance,
                })
            }
            _ => Err(Error::Profile("not an owned page query")),
        }
    }
}

fn cancelled(cancel: &AtomicBool, scope: &Scope) -> Result<()> {
    if scope.lifetime.is_retired() || scope.node_lifetime.is_retired() {
        cancel.store(true, Ordering::Release);
    }
    if cancel.load(Ordering::Acquire) {
        Err(Error::Profile("room read cancelled"))
    } else {
        Ok(())
    }
}
fn yielded(cancel: &AtomicBool, scope: &Scope) -> Result<()> {
    cancelled(cancel, scope)?;
    std::thread::yield_now();
    cancelled(cancel, scope)
}
fn snapshot<'a>(view: &'a entry_store::RenderView<'_>) -> &'a Snapshot {
    match view.transaction() {
        Transaction::Snapshot(snapshot) => snapshot,
        Transaction::Batch(_) => unreachable!(),
    }
}
fn header_visible(
    view: &entry_store::RenderView<'_>,
    key: &Sek,
    room: &Digest32,
    entry: &Entry,
    policy: entry_store::ExpiryPolicy,
    verified: &BTreeMap<Digest32, u64>,
) -> Result<bool> {
    let hash = entry.entry_hash();
    if entry.payload.is_some()
        || entry
            .skeleton
            .v2
            .as_ref()
            .is_some_and(|value| value.kind != crate::log::history::SignedEntryKind::Content)
        || session_projection::private_index::find(snapshot(view), key, room, &hash)?.is_some()
    {
        return Ok(false);
    }
    let log = view
        .entry_log_id(&hash)?
        .ok_or(Error::MalformedAtRest("missing header locator"))?;
    // A never-received header can legally have neither retained-body age nor a
    // sealed first-seen fact. Preserve entry_steps_in/owed_visibility's established
    // regular/claimed logical fallback without minting a canonical age stamp.
    let live = if policy.regular == 0 && policy.steps == 0 {
        true
    } else {
        let (base, steps) = match view.retention(&hash)? {
            Some(tracked) => (tracked.base(), tracked.steps),
            None => match snapshot(view).get_segment(room, SegmentKind::Index, log)? {
                Some(sealed) => {
                    let (seen, steps) =
                        parse_first_seen(&open_segment(key, SegmentKind::Index, log, &sealed)?)?;
                    (entry.skeleton.claimed_ms.min(seen), steps)
                }
                None => (entry.skeleton.claimed_ms, false),
            },
        };
        !expired_at(
            base,
            policy.now,
            if steps { policy.steps } else { policy.regular },
        )
    };
    if !live {
        return Ok(false);
    }
    // Expired candidates need no subtype convergence to be excluded. Unknown v1
    // subtype follows the existing completed-classification fence, not a peer wait.
    Ok(!legacy_session::read_snapshot_kind(
        snapshot(view),
        key,
        room,
        entry,
        log,
        verified
            .get(&entry.skeleton.author_id)
            .copied()
            .unwrap_or(0),
    )?)
}

struct RenderedScratch(Option<Rendered>);
impl Drop for RenderedScratch {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(row) = self.0.as_mut() {
            row.text.zeroize();
        }
    }
}

struct PageRows {
    values: Vec<(entry_store::OrderKey, MessageRow)>,
    excluded: Option<entry_store::OrderKey>,
}
impl PageRows {
    fn new() -> Self {
        Self {
            values: Vec::new(),
            excluded: None,
        }
    }
    fn accepts(&self, key: entry_store::OrderKey) -> bool {
        self.excluded.is_none_or(|floor| key > floor)
    }
    fn finish(mut self) -> Vec<MessageRow> {
        std::mem::take(&mut self.values)
            .into_iter()
            .map(|(_, row)| row)
            .collect()
    }
}
impl std::ops::Deref for PageRows {
    type Target = Vec<(entry_store::OrderKey, MessageRow)>;
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl Drop for PageRows {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for (_, row) in &mut self.values {
            row.text.zeroize();
        }
    }
}
fn put_row(
    rows: &mut PageRows,
    order: entry_store::OrderKey,
    mut row: MessageRow,
    limit: usize,
    bytes: usize,
) {
    use zeroize::Zeroize;
    if !rows.accepts(order) {
        row.text.zeroize();
        return;
    }
    let at = rows
        .values
        .binary_search_by_key(&order, |(key, _)| *key)
        .unwrap_or_else(|at| at);
    rows.values.insert(at, (order, row));
    while rows.values.len() > limit
        || (rows.values.len() > 1
            && rows
                .values
                .iter()
                .map(|(_, row)| row.text.len() + crate::node::ipc::ROW_OVERHEAD)
                .sum::<usize>()
                > bytes)
    {
        let (excluded, mut row) = rows.values.remove(0);
        rows.excluded = Some(rows.excluded.map_or(excluded, |old| old.max(excluded)));
        row.text.zeroize();
    }
    // A later stream may reveal a newer excluded boundary. Never retain/refill any
    // lower row: Older must return a contiguous newest prefix, not a knapsack page.
    while rows
        .values
        .first()
        .is_some_and(|(key, _)| !rows.accepts(*key))
    {
        let (_, mut row) = rows.values.remove(0);
        row.text.zeroize();
    }
}

/// Metadata shares the page's fixed eligibility snapshot, never a global prune gate.
fn rendered_live(
    view: &entry_store::RenderView<'_>,
    hash: &Digest32,
    policy: entry_store::ExpiryPolicy,
) -> Result<bool> {
    let Some(fact) = view.fact(hash)? else {
        return Ok(false);
    };
    let tracked = view
        .retention(hash)?
        .ok_or(Error::MalformedAtRest("rendered retention missing"))?;
    if tracked.cache_id != Some(fact.cache) {
        return Err(Error::MalformedAtRest("rendered retention cache differs"));
    }
    let entry = view
        .order()
        .entry(hash)?
        .ok_or(Error::MalformedAtRest("rendered source missing"))?;
    let ttl = if entry.payload.as_deref().is_some_and(retained_control) {
        0
    } else if tracked.steps {
        policy.steps
    } else {
        policy.regular
    };
    Ok(!expired_at(tracked.base(), policy.now, ttl))
}
fn metadata_reply(
    view: &entry_store::RenderView<'_>,
    query: Query,
    scope: &Scope,
    policy: entry_store::ExpiryPolicy,
    members: &[(Digest32, u64)],
    cancel: &AtomicBool,
) -> Result<Reply> {
    match query {
        Query::ArrivalHead => {
            let mut cursor = None;
            let mut budget = crate::log::history::WorkBudget::default();
            loop {
                cancelled(cancel, scope)?;
                if !budget.take_control_lookup() {
                    yielded(cancel, scope)?;
                    budget = Default::default();
                }
                let Some((order, fact)) = view.step(None, false, cursor, true)? else {
                    return Ok(Reply::ArrivalHead(HistoryCursor {
                        instance: scope.instance,
                        arrival: 0,
                    }));
                };
                if rendered_live(view, &order.1, policy)? {
                    return Ok(Reply::ArrivalHead(HistoryCursor {
                        instance: scope.instance,
                        arrival: fact.cache,
                    }));
                }
                cursor = Some(order);
            }
        }
        Query::Footers {
            instance,
            entries,
            limit,
        } => {
            if instance != scope.instance {
                return Err(Error::Profile(
                    "the saved room changed; open its current page again",
                ));
            }
            if entries.len() > 128 || limit == 0 || limit > if entries.len() == 1 { 64 } else { 8 }
            {
                return Err(Error::Profile("displayed footers exceed one bounded page"));
            }
            // Serde structs also accept sequences. Footer metadata historically
            // recognizes JSON objects only, at both the envelope and data boundary.
            struct Object<T>(T);
            impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Object<T> {
                fn deserialize<D: serde::Deserializer<'de>>(
                    d: D,
                ) -> std::result::Result<Self, D::Error> {
                    struct Visitor<T>(std::marker::PhantomData<T>);
                    impl<'de, T: serde::Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
                        type Value = Object<T>;
                        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                            f.write_str("a JSON object")
                        }
                        fn visit_map<M: serde::de::MapAccess<'de>>(
                            self,
                            map: M,
                        ) -> std::result::Result<Self::Value, M::Error> {
                            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                                .map(Object)
                        }
                    }
                    d.deserialize_map(Visitor(std::marker::PhantomData))
                }
            }
            #[derive(serde::Deserialize)]
            struct Envelope<'a> {
                #[serde(rename = "type", borrow)]
                kind: std::borrow::Cow<'a, str>,
                #[serde(borrow)]
                data: Option<Object<Data<'a>>>,
            }
            #[derive(serde::Deserialize)]
            struct Data<'a> {
                #[serde(borrow)]
                tag: Option<std::borrow::Cow<'a, str>>,
            }
            impl Drop for Envelope<'_> {
                fn drop(&mut self) {
                    use zeroize::Zeroize;
                    if let std::borrow::Cow::Owned(text) = &mut self.kind {
                        text.zeroize();
                    }
                }
            }
            impl Drop for Data<'_> {
                fn drop(&mut self) {
                    use zeroize::Zeroize;
                    if let Some(std::borrow::Cow::Owned(text)) = &mut self.tag {
                        text.zeroize();
                    }
                }
            }
            struct Tags(Vec<Option<String>>);
            impl Drop for Tags {
                fn drop(&mut self) {
                    use zeroize::Zeroize;
                    for text in self.0.iter_mut().flatten() {
                        text.zeroize();
                    }
                }
            }
            let mut rows = Vec::new();
            let mut tags = Tags(Vec::new());
            for selection in entries {
                cancelled(cancel, scope)?;
                let mut footer = crate::node::api::MessageFooter {
                    entry: selection.entry,
                    present: false,
                    read_by: Vec::new(),
                    read_after: None,
                    held: 0,
                    others: members.len() as u64,
                    pulled_by: Vec::new(),
                    pulled_after: None,
                };
                let mut tag = None;
                if rendered_live(view, &selection.entry, policy)? {
                    let raw = view
                        .row(&selection.entry)?
                        .ok_or(Error::MalformedAtRest("footer rendering missing"))?;
                    let text = Zeroizing::new(raw.text);
                    let entry = view
                        .order()
                        .entry(&selection.entry)?
                        .ok_or(Error::MalformedAtRest("footer entry missing"))?;
                    if raw.author != entry.skeleton.author_id {
                        return Err(Error::MalformedAtRest("rendering author differs"));
                    }
                    if raw.author == scope.node {
                        footer.present = true;
                        (footer.read_by, footer.read_after) =
                            view.readers_page(&selection.entry, selection.read_after, limit)?;
                        footer.held = members
                            .iter()
                            .filter(|(_, held)| *held >= entry.skeleton.seq)
                            .count() as u64;
                        if let Ok(envelope) = serde_json::from_str::<Object<Envelope<'_>>>(&text) {
                            if envelope.0.kind == crate::node::shares::FILE {
                                tag = envelope
                                    .0
                                    .data
                                    .as_ref()
                                    .and_then(|data| data.0.tag.as_deref())
                                    .filter(|tag| tag.len() <= 512)
                                    .map(str::to_owned);
                            }
                        }
                    }
                }
                rows.push(footer);
                tags.0.push(tag);
                yielded(cancel, scope)?;
            }
            Ok(Reply::Footers {
                rows,
                tags: std::mem::take(&mut tags.0),
            })
        }
        _ => Err(Error::MalformedAtRest("unexpected page metadata query")),
    }
}

impl Capture {
    pub(crate) fn run(self, query: Query, cancel: &AtomicBool, bytes: usize) -> Result<Answer> {
        let leases = self._leases;
        let scope = self.scope;
        let policy = self.policy;
        let render_epoch = self.render_epoch;
        let verified = self.verified;
        let provisional = self.provisional;
        let footer_members = self.footer_members;
        let key = self.key;
        let index = self.index;
        let fresh_index = entry_store::EntryIndex::default();
        let view = fresh_index.render_captured(index, &key, &scope.room)?;
        if matches!(&query, Query::ArrivalHead | Query::Footers { .. }) {
            let reply = metadata_reply(&view, query, &scope, policy, &footer_members, cancel)?;
            drop(view);
            drop(fresh_index);
            drop(key);
            drop(verified);
            drop(footer_members);
            return Answer::finish(scope, reply, leases);
        }
        drop(footer_members);
        let spec = PageSpec::from_query(query)?;
        if spec
            .instance
            .is_some_and(|instance| instance != scope.instance)
        {
            return Err(Error::Profile(
                "the saved room changed; open its current page again",
            ));
        }
        let general_fallback =
            matches!(spec.filter, Some(Filter::General)) && !view.room_views_ready()?;
        let before = if let Some(hash) = spec.before {
            let order = view
                .order()
                .key(&hash)?
                .ok_or(Error::Profile("cursor not in this room's timeline"))?;
            let rendered = view.fact(&hash)?;
            let selected = if let Some(fact) = rendered {
                let tracked = view
                    .retention(&hash)?
                    .ok_or(Error::MalformedAtRest("rendered retention missing"))?;
                if tracked.cache_id != Some(fact.cache) {
                    return Err(Error::MalformedAtRest("rendered retention cache differs"));
                }
                let entry = view
                    .order()
                    .entry(&hash)?
                    .ok_or(Error::MalformedAtRest("rendered source missing"))?;
                let ttl = if entry.payload.as_deref().is_some_and(retained_control) {
                    0
                } else if tracked.steps {
                    policy.steps
                } else {
                    policy.regular
                };
                if expired_at(tracked.base(), policy.now, ttl) {
                    false
                } else {
                    match spec.filter.as_ref() {
                        None => true,
                        Some(Filter::General) if general_fallback => {
                            let row = RenderedScratch(view.row(&hash)?);
                            row.0
                                .as_ref()
                                .is_some_and(|row| Filter::matches_general_text(&row.text))
                        }
                        Some(filter) => view.contains(filter, &hash)?,
                    }
                }
            } else if spec.filter.is_none() || matches!(spec.filter, Some(Filter::General)) {
                match view.order().author_position(&hash)? {
                    Some((author, seq)) if view.missing_contains(&author, seq)? => {
                        let entry = view
                            .order()
                            .entry(&hash)?
                            .ok_or(Error::MalformedAtRest("cursor header source missing"))?;
                        header_visible(&view, &key, &scope.room, &entry, policy, &verified)?
                    }
                    _ => false,
                }
            } else {
                false
            };
            if !selected {
                return Err(Error::Profile(
                    "cursor not among this room's selected messages",
                ));
            }
            Some(order)
        } else {
            None
        };
        let mut rows = PageRows::new();
        let known_rendered_total = if before.is_none() && !general_fallback {
            view.visible_count(spec.filter.as_ref(), policy)?
        } else {
            None
        };
        let all_rendered_live = view.visible_count(None, policy)? == Some(view.count()?);
        let selected_scan = if all_rendered_live && !general_fallback {
            spec.filter.as_ref()
        } else {
            None
        };
        let mut total = known_rendered_total.unwrap_or(0);
        let mut suffix: Option<u64> = None;
        let mut budget = crate::log::history::WorkBudget::default();
        // Rendered scan is independent from owed projection membership/deadline cleanup.
        let mut scan =
            view.visibility_scan(selected_scan, true, (None, None), true, false, policy)?;
        while known_rendered_total != Some(0)
            && !(known_rendered_total.is_some() && spec.limit == 0)
        {
            cancelled(cancel, &scope)?;
            match scan.step(&mut budget, cancel, || {
                scope.lifetime.is_retired() || scope.node_lifetime.is_retired()
            })? {
                entry_store::VisibilityStep::Candidate { key: order } => {
                    if known_rendered_total.is_some() && rows.len() >= spec.limit && spec.limit != 0
                    {
                        break;
                    }
                    if !resolve(&mut scan, &mut budget, cancel, &scope, order)? {
                        continue;
                    }
                    let fact = view
                        .fact(&order.1)?
                        .ok_or(Error::MalformedAtRest("render candidate missing"))?;
                    let shown = if fact.epoch == render_epoch {
                        fact.shown
                    } else {
                        0
                    };
                    let late = shown != 0
                        && suffix.is_some_and(|earliest| {
                            earliest
                                .checked_add(LATE_AFTER_MS)
                                .is_some_and(|at| shown >= at)
                        });
                    suffix = Some(suffix.map_or(shown, |old| old.min(shown)));
                    if before.is_some_and(|before| order >= before) {
                        continue;
                    }
                    let mut rendered = RenderedScratch(None);
                    let selected = match spec.filter.as_ref() {
                        None => true,
                        Some(Filter::General) if general_fallback => {
                            rendered.0 = view.row(&order.1)?;
                            rendered
                                .0
                                .as_ref()
                                .is_some_and(|row| Filter::matches_general_text(&row.text))
                        }
                        Some(filter) => view.contains(filter, &order.1)?,
                    };
                    if !selected {
                        continue;
                    }
                    if known_rendered_total.is_none() {
                        total = total
                            .checked_add(1)
                            .ok_or(Error::MalformedAtRest("history count overflow"))?;
                    }
                    // Only the newest bounded selected rows are opened as plaintext.
                    if spec.limit != 0
                        && rows.accepts(order)
                        && (rows.len() < spec.limit
                            || rows.first().is_some_and(|(key, _)| order > *key))
                    {
                        if rendered.0.is_none() {
                            rendered.0 = view.row(&order.1)?;
                        }
                        let author = view
                            .order()
                            .author_position(&order.1)?
                            .ok_or(Error::MalformedAtRest("render author missing"))?
                            .0;
                        if rendered
                            .0
                            .as_ref()
                            .ok_or(Error::MalformedAtRest("visible render missing"))?
                            .author
                            != author
                        {
                            return Err(Error::MalformedAtRest("rendering author differs"));
                        }
                        let mut message = View::message(
                            rendered
                                .0
                                .take()
                                .ok_or(Error::MalformedAtRest("visible render missing"))?,
                        );
                        if !all_rendered_live {
                            message.late = late;
                        }
                        put_row(&mut rows, order, message, spec.limit, bytes);
                        if known_rendered_total.is_some()
                            && !rows.iter().any(|(key, _)| *key == order)
                        {
                            break;
                        }
                    }
                }
                entry_store::VisibilityStep::Yielded => {
                    yielded(cancel, &scope)?;
                    budget = Default::default();
                }
                entry_store::VisibilityStep::Complete { count } => {
                    if spec.filter.is_none() && before.is_none() && count != total {
                        return Err(Error::MalformedAtRest(
                            "visible render count differs from scan",
                        ));
                    }
                    break;
                }
                entry_store::VisibilityStep::Cancelled => {
                    return Err(Error::Profile("room read cancelled"))
                }
            }
        }
        // Missing positions are authoritative; partial owed_display cannot stand in for them.
        if spec.filter.is_none() || matches!(spec.filter, Some(Filter::General)) {
            let mut after = None;
            let mut classification_checked = false;
            loop {
                cancelled(cancel, &scope)?;
                let (positions, next) = view.missing_page(after, 64)?;
                for (author, seq) in positions {
                    if !budget.take_control_lookup() {
                        yielded(cancel, &scope)?;
                        budget = Default::default();
                        if !budget.take_control_lookup() {
                            return Err(Error::MalformedAtRest("empty header work budget"));
                        }
                    }
                    let entry = view
                        .entry_at_position(&author, seq)?
                        .ok_or(Error::MalformedAtRest("missing header source absent"))?;
                    let hash = entry.entry_hash();
                    let Some(order) = view.order().key(&hash)? else {
                        continue;
                    };
                    if before.is_some_and(|before| order >= before) || view.fact(&hash)?.is_some() {
                        continue;
                    }
                    if !header_visible(&view, &key, &scope.room, &entry, policy, &verified)? {
                        continue;
                    }
                    if !classification_checked {
                        legacy_session::read_snapshot_complete(snapshot(&view), &key, &scope.room)?;
                        classification_checked = true;
                    }
                    total = total
                        .checked_add(1)
                        .ok_or(Error::MalformedAtRest("history count overflow"))?;
                    if spec.limit != 0 {
                        put_row(
                            &mut rows,
                            order,
                            MessageRow {
                                entry_hash: hash,
                                author,
                                created_millis: entry.skeleton.claimed_ms,
                                text: String::new(),
                                arrival: 0,
                                late: false,
                                owed: true,
                            },
                            spec.limit,
                            bytes,
                        );
                    }
                }
                after = next;
                if after.is_none() {
                    break;
                }
                yielded(cancel, &scope)?;
                budget = Default::default();
            }
        }
        cancelled(cancel, &scope)?;
        let older = total
            .checked_sub(rows.len() as u64)
            .ok_or(Error::MalformedAtRest("history count smaller than page"))?;
        let rows = rows.finish();
        drop(view);
        drop(fresh_index);
        drop(key);
        drop(verified);
        Answer::finish(
            scope,
            Reply::Older {
                rows,
                older,
                provisional,
            },
            leases,
        )
    }
}
fn resolve(
    scan: &mut entry_store::VisibilityScan<'_, '_>,
    budget: &mut crate::log::history::WorkBudget,
    cancel: &AtomicBool,
    scope: &Scope,
    expected: entry_store::OrderKey,
) -> Result<bool> {
    loop {
        cancelled(cancel, scope)?;
        match scan.resolve_pending(budget, cancel, || {
            scope.lifetime.is_retired() || scope.node_lifetime.is_retired()
        })? {
            entry_store::VisibilityResolution::Resolved { key, visible } => {
                if key != expected {
                    return Err(Error::MalformedAtRest(
                        "resolved visibility candidate differs",
                    ));
                }
                return Ok(visible);
            }
            entry_store::VisibilityResolution::Yielded => {
                yielded(cancel, scope)?;
                *budget = Default::default();
            }
            entry_store::VisibilityResolution::MissingAge { key } => {
                if key != expected {
                    return Err(Error::MalformedAtRest("missing-age candidate differs"));
                }
                return Err(Error::Profile("this saved header's age is not available"));
            }
            entry_store::VisibilityResolution::Cancelled => {
                return Err(Error::Profile("room read cancelled"))
            }
        }
    }
}
