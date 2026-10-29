//! One bounded classification transaction uses the same implementation as live-room callers.
use super::semantic_projection::SelectedReceiverInput;
use super::*;

type SelectedSnapshot = Option<((Digest32, u64), Option<Zeroizing<Vec<u8>>>)>;

pub(in crate::node::channel) struct LegacyProjectionContext {
    room: Digest32,
    entries: entry_store::EntryIndex,
    heads: BTreeMap<Digest32, (u64, u64)>,
    classifications: BTreeMap<Digest32, Option<bool>>,
    requests: std::cell::RefCell<BTreeMap<Digest32, (Digest32, u64)>>,
    state: LegacySessions,
    published: LegacySessions,
    governance_ready: bool,
    governance_until: u64,
    retention: u64,
}

enum Heads<'a> {
    Live(&'a Dag),
    Detached(&'a BTreeMap<Digest32, (u64, u64)>),
}

impl Heads<'_> {
    fn verified_head(&self, author: &Digest32) -> u64 {
        match self {
            Self::Live(dag) => dag.verified_head(author),
            Self::Detached(heads) => heads.get(author).map_or(0, |(_, verified)| *verified),
        }
    }

    fn get_by_hash(
        &self,
        entries: &impl crate::log::entry::EntryRead,
        hash: &Digest32,
    ) -> Result<Option<Entry>> {
        if let Self::Live(dag) = self {
            return dag.get_by_hash(entries, hash);
        }
        if let Some(entry) = entries.get_sparse_published(hash)? {
            return Ok(Some(entry));
        }
        let Some((author, seq)) = entries.locate(hash)? else {
            return Ok(None);
        };
        let Self::Detached(heads) = self else {
            unreachable!()
        };
        let Some((maximum, _)) = heads.get(&author) else {
            return Ok(None);
        };
        if seq == 0 || seq > *maximum {
            return Ok(None);
        }
        let entry = entries
            .get(&author, seq)?
            .ok_or(Error::MalformedAtRest("held feed entry missing"))?;
        if entry.entry_hash() != *hash {
            return Err(Error::MalformedAtRest("DAG locator hash differs"));
        }
        Ok(Some(entry))
    }
}

enum Receivers<'a> {
    Live(&'a DriveState),
    Prepared {
        classifications: &'a BTreeMap<Digest32, Option<bool>>,
        requests: &'a std::cell::RefCell<BTreeMap<Digest32, (Digest32, u64)>>,
    },
}

impl Receivers<'_> {
    fn classify(&self, hash: Digest32, author: Digest32, message: &GroupMessage) -> Option<bool> {
        let slot = (author, message.header.chain_id);
        match self {
            Self::Live(drive) => {
                let mut selected =
                    ReceiverChain::from_state(&drive.receivers.get(&slot)?.to_state()).ok()?;
                classify_selected(&mut selected, message)
            }
            Self::Prepared {
                classifications,
                requests,
            } => {
                if let Some(classification) = classifications.get(&hash) {
                    *classification
                } else {
                    requests.borrow_mut().insert(hash, slot);
                    None
                }
            }
        }
    }
}

fn classify_selected(selected: &mut ReceiverChain, message: &GroupMessage) -> Option<bool> {
    if !selected.can_open_iteration(message.header.iteration) {
        return None;
    }
    let plaintext = Zeroizing::new(selected.decrypt(message).ok()?);
    Some(matches!(
        crate::node::content::decode(&plaintext),
        Ok(Decoded::Session(_))
    ))
}

struct LegacyProjection<'a> {
    channel_id: Digest32,
    sek: &'a Sek,
    entries: &'a entry_store::EntryIndex,
    dag: Heads<'a>,
    drive: Receivers<'a>,
    legacy_sessions: LegacySessions,
    published: Option<LegacySessions>,
    governance_ready: bool,
    governance_until: u64,
    retention: u64,
}

impl ChannelState {
    fn legacy_projection(&self) -> LegacyProjection<'_> {
        LegacyProjection {
            channel_id: self.channel_id,
            sek: &self.sek,
            entries: &self.entries,
            dag: Heads::Live(&self.dag),
            drive: Receivers::Live(&self.drive),
            legacy_sessions: self.legacy_sessions,
            published: None,
            governance_ready: self.governance_ready,
            governance_until: self.governance_display.valid_until,
            retention: self.effective_retention(),
        }
    }

    fn update_legacy_projection<T>(
        &mut self,
        operation: impl FnOnce(&mut LegacyProjection<'_>) -> Result<T>,
    ) -> Result<T> {
        let (result, state) = {
            let mut projection = self.legacy_projection();
            let result = operation(&mut projection);
            (result, projection.legacy_sessions)
        };
        self.legacy_sessions = state;
        result
    }

    pub(in crate::node::channel) fn legacy_projection_context(
        &self,
        _store: &Store,
    ) -> Result<LegacyProjectionContext> {
        let heads = self
            .authors
            .keys()
            .filter_map(|author| {
                self.dag
                    .feed(author)
                    .map(|feed| (*author, (feed.max_seq(), self.dag.verified_head(author))))
            })
            .collect();
        Ok(LegacyProjectionContext {
            room: self.channel_id,
            entries: self.entries.fork_reader(),
            heads,
            classifications: BTreeMap::new(),
            requests: std::cell::RefCell::new(BTreeMap::new()),
            state: self.legacy_sessions,
            published: self.legacy_sessions,
            governance_ready: self.governance_ready,
            governance_until: self.governance_display.valid_until,
            retention: self.effective_retention(),
        })
    }

    pub(in crate::node::channel) fn install_legacy_projection_context(
        &mut self,
        context: &LegacyProjectionContext,
    ) {
        self.legacy_sessions = context.published_state();
    }

    pub(super) fn legacy_header(&self, transaction: Transaction<'_, '_>) -> Result<Header> {
        self.legacy_projection().legacy_header(transaction)
    }

    pub(super) fn save_legacy_header(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        header: &Header,
    ) -> Result<()> {
        self.update_legacy_projection(|projection| projection.save_legacy_header(batch, header))
    }

    pub(super) fn request_legacy_pass(
        &self,
        batch: &crate::node::store::Batch<'_>,
        header: &mut Header,
    ) -> Result<()> {
        self.legacy_projection().request_legacy_pass(batch, header)
    }

    pub(in crate::node::channel) fn available_legacy_kind(&self, entry: &Entry) -> Option<bool> {
        self.legacy_projection().available_legacy_kind(entry)
    }

    pub(in crate::node::channel) fn legacy_is_session_in(
        &self,
        transaction: Transaction<'_, '_>,
        hash: &Digest32,
    ) -> Result<bool> {
        self.legacy_projection()
            .legacy_is_session_in(transaction, hash)
    }

    pub(in crate::node::channel) fn remember_legacy_kind(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        hash: Digest32,
        author: Digest32,
        session: bool,
    ) -> Result<()> {
        self.update_legacy_projection(|projection| {
            projection.remember_legacy_kind(batch, hash, author, session)
        })
    }

    pub(in crate::node::channel) fn inspect_legacy_body_into(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        entry: &Entry,
    ) -> Result<()> {
        self.update_legacy_projection(|projection| {
            projection.inspect_legacy_body_into(batch, entry)
        })
    }

    pub(in crate::node::channel) fn accept_legacy_index(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        declaration: Digest32,
        author: Digest32,
        index: LegacySessionIndex,
        now: u64,
    ) -> Result<()> {
        self.update_legacy_projection(|projection| {
            projection.accept_legacy_index(batch, declaration, author, index, now)
        })
    }

    pub(in crate::node::channel) fn reconcile_legacy_sessions(
        &mut self,
        store: &Store,
        now: u64,
    ) -> Result<bool> {
        self.update_legacy_projection(|projection| projection.reconcile_legacy_sessions(store, now))
    }

    pub(in crate::node::channel) fn reconcile_legacy_sessions_in(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        now: u64,
    ) -> Result<bool> {
        self.update_legacy_projection(|projection| {
            projection.reconcile_legacy_sessions_in(batch, now)
        })
    }

    pub(crate) fn legacy_classification_pending(&self, store: &Store) -> Result<bool> {
        self.legacy_projection()
            .legacy_classification_pending(store)
    }
}

impl LegacyProjectionContext {
    fn using<T>(
        &mut self,
        sek: &Sek,
        operation: impl FnOnce(&mut LegacyProjection<'_>) -> Result<T>,
    ) -> Result<T> {
        let entries = self.entries.fork_reader();
        let mut projection = LegacyProjection {
            channel_id: self.room,
            sek,
            entries: &entries,
            dag: Heads::Detached(&self.heads),
            drive: Receivers::Prepared {
                classifications: &self.classifications,
                requests: &self.requests,
            },
            legacy_sessions: self.state,
            published: None,
            governance_ready: self.governance_ready,
            governance_until: self.governance_until,
            retention: self.retention,
        };
        let result = operation(&mut projection);
        if self.requests.borrow().is_empty() {
            self.state = projection.legacy_sessions;
        }
        if let Some(published) = projection.published {
            self.published = published;
        }
        result
    }

    pub(in crate::node::channel) fn published_state(&self) -> LegacySessions {
        self.published
    }
    pub(in crate::node::channel) fn committed(&mut self) {
        self.state.committed();
        self.published = self.state;
    }

    pub(in crate::node::channel) fn reconcile(
        &mut self,
        store: &Store,
        sek: &Sek,
        now: u64,
    ) -> Result<bool> {
        self.reconcile_with_candidates(store, sek, now, None)
    }

    pub(in crate::node::channel) fn reconcile_with_candidates(
        &mut self,
        store: &Store,
        sek: &Sek,
        now: u64,
        candidates: Option<&BTreeMap<(Digest32, u64), ReceiverChain>>,
    ) -> Result<bool> {
        let mut selected = None;
        loop {
            let progress = self.using(sek, |projection| {
                projection.reconcile_legacy_sessions(store, now)
            })?;
            if !self.needs_inputs() {
                return Ok(progress);
            }
            self.resolve_inputs(store, sek, candidates, &mut selected)?;
        }
    }

    pub(in crate::node::channel) fn reconcile_in(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        sek: &Sek,
        now: u64,
    ) -> Result<bool> {
        self.using(sek, |projection| {
            projection.reconcile_legacy_sessions_in(batch, now)
        })
    }

    pub(in crate::node::channel) fn remember(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        sek: &Sek,
        hash: Digest32,
        author: Digest32,
        session: bool,
    ) -> Result<()> {
        self.using(sek, |projection| {
            projection.remember_legacy_kind(batch, hash, author, session)
        })
    }

    pub(in crate::node::channel) fn accept(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        sek: &Sek,
        hash: Digest32,
        author: Digest32,
        index: LegacySessionIndex,
        now: u64,
    ) -> Result<()> {
        self.using(sek, |projection| {
            projection.accept_legacy_index(batch, hash, author, index, now)
        })
    }

    pub(in crate::node::channel) fn advance(
        &mut self,
        store: &Store,
        sek: &Sek,
        now: u64,
    ) -> Result<bool> {
        let mut selected = None;
        loop {
            let progress = self.using(sek, |projection| {
                projection.advance_legacy_sessions(store, now)
            })?;
            if !self.needs_inputs() {
                return Ok(progress);
            }
            self.resolve_inputs(store, sek, None, &mut selected)?;
        }
    }

    pub(in crate::node::channel) fn needs_inputs(&self) -> bool {
        !self.requests.borrow().is_empty()
    }

    pub(in crate::node::channel) fn require_inputs(&self) -> Result<()> {
        if self.needs_inputs() {
            return Err(Error::Profile(
                "classification input changed within reserved publication",
            ));
        }
        Ok(())
    }

    /// Run the same bounded kernel against unpublished caller facts, then discard every
    /// scalar, page and cursor mutation before acquiring one selected receiver at a time.
    pub(in crate::node::channel) fn prepare_reconcile(
        &mut self,
        store: &Store,
        sek: &Sek,
        now: u64,
        candidates: Option<&BTreeMap<(Digest32, u64), ReceiverChain>>,
        mut prepare: impl FnMut(&mut Self, &mut crate::node::store::Batch<'_>) -> Result<()>,
    ) -> Result<()> {
        let mut selected = None;
        loop {
            let before = self.state;
            let published = self.published;
            let mut batch = store.batch()?;
            batch.derived();
            SelectedReceiverInput::check(&batch)?;
            let result =
                prepare(self, &mut batch).and_then(|()| self.reconcile_in(&mut batch, sek, now));
            drop(batch);
            self.state = before;
            self.published = published;
            result?;
            if !self.needs_inputs() {
                return Ok(());
            }
            self.resolve_inputs(store, sek, candidates, &mut selected)?;
        }
    }

    fn resolve_inputs(
        &mut self,
        store: &Store,
        sek: &Sek,
        candidates: Option<&BTreeMap<(Digest32, u64), ReceiverChain>>,
        selected: &mut SelectedSnapshot,
    ) -> Result<()> {
        let requests = std::mem::take(&mut *self.requests.borrow_mut());
        for (hash, slot) in requests {
            if selected.as_ref().is_none_or(|(held, _)| *held != slot) {
                *selected = None;
                let state =
                    if let Some(receiver) = candidates.and_then(|selected| selected.get(&slot)) {
                        Some(receiver.to_state())
                    } else {
                        SelectedReceiverInput::selected(slot)?
                    };
                *selected = Some((slot, state));
            }
            let classification =
                if let Some(state) = selected.as_ref().and_then(|(_, state)| state.as_ref()) {
                    let mut copied = ReceiverChain::from_state(state)?;
                    let entry = {
                        let snapshot = store.snapshot()?;
                        self.using(sek, |projection| {
                            projection.entry_at(Transaction::Snapshot(&snapshot), &hash)
                        })?
                        .ok_or(Error::MalformedAtRest(
                            "classification input entry vanished",
                        ))?
                    };
                    let message = GroupMessage::from_wire(
                        entry
                            .payload
                            .as_deref()
                            .ok_or(Error::MalformedAtRest("classification input body vanished"))?,
                    )
                    .map_err(|_| Error::MalformedAtRest("classification input body changed"))?;
                    classify_selected(&mut copied, &message)
                } else {
                    None
                };
            self.classifications.insert(hash, classification);
        }
        Ok(())
    }
}

impl LegacyProjection<'_> {
    fn classification_inputs_pending(&self) -> bool {
        match &self.drive {
            Receivers::Live(_) => false,
            Receivers::Prepared { requests, .. } => !requests.borrow().is_empty(),
        }
    }

    fn check_classification_authority(&self, batch: &crate::node::store::Batch<'_>) -> Result<()> {
        if matches!(&self.drive, Receivers::Prepared { .. }) {
            SelectedReceiverInput::check(batch)?;
        }
        Ok(())
    }

    fn entry_at(&self, transaction: Transaction<'_, '_>, hash: &Digest32) -> Result<Option<Entry>> {
        self.dag.get_by_hash(
            &self.entries.view(transaction, self.sek, &self.channel_id)?,
            hash,
        )
    }

    fn log_id_at(&self, transaction: Transaction<'_, '_>, hash: &Digest32) -> Result<Option<u64>> {
        self.entries
            .view(transaction, self.sek, &self.channel_id)?
            .log_id(hash)
    }

    fn retention_get_in(
        &self,
        transaction: Transaction<'_, '_>,
        hash: &Digest32,
    ) -> Result<Option<Tracked>> {
        self.entries
            .view(transaction, self.sek, &self.channel_id)?
            .retention(hash)
    }

    fn governance_display_current(&self, now: u64) -> bool {
        self.governance_ready && (self.governance_until == 0 || now < self.governance_until)
    }

    fn effective_retention(&self) -> u64 {
        self.retention
    }
    fn legacy_header(&self, transaction: Transaction<'_, '_>) -> Result<Header> {
        let Some(sealed) = segment(transaction, &self.channel_id, HEADER)? else {
            return Ok(Header::empty(
                next_id(transaction, &self.channel_id, 1)?.is_none(),
            ));
        };
        if sealed.ciphertext.len() > 256 {
            return Err(Error::MalformedAtRest("Session classification cursor size"));
        }
        Header::read(&open_segment(
            self.sek,
            SegmentKind::SessionClassification,
            HEADER,
            &sealed,
        )?)
    }
    fn save_legacy_header(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        header: &Header,
    ) -> Result<()> {
        let bytes = header.wire();
        let same = match segment(Transaction::Batch(batch), &self.channel_id, HEADER)? {
            Some(sealed) => {
                open_segment(
                    self.sek,
                    SegmentKind::SessionClassification,
                    HEADER,
                    &sealed,
                )?
                .as_slice()
                    == bytes.as_slice()
            }
            None => false,
        };
        if !same {
            let sealed =
                seal_segment(self.sek, SegmentKind::SessionClassification, HEADER, &bytes)?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::SessionClassification,
                HEADER,
                &sealed,
            )?;
            self.legacy_sessions.dirty = true;
        }
        self.legacy_sessions.display_revision = header.revision;
        Ok(())
    }
    fn legacy_page(&self, transaction: Transaction<'_, '_>, id: u64) -> Result<Option<Page>> {
        let Some(sealed) = segment(transaction, &self.channel_id, id)? else {
            return Ok(None);
        };
        if sealed.ciphertext.len() > PAGE_BYTES + crate::atrest::sek::TAG_LEN {
            return Err(Error::MalformedAtRest("Session classification page size"));
        }
        let page = Page::read(&open_segment(
            self.sek,
            SegmentKind::SessionClassification,
            id,
            &sealed,
        )?)?;
        if matches!(page, Page::Pending { .. }) != (id % 2 == 1) || id < 2 {
            return Err(Error::MalformedAtRest("Session classification page parity"));
        }
        Ok(Some(page))
    }
    /// A verified target, not a claimed time/sequence range or an unverified bare hash.
    fn legacy_target(
        &self,
        transaction: Transaction<'_, '_>,
        hash: &Digest32,
        author: &Digest32,
    ) -> Result<Option<Entry>> {
        Ok(self.entry_at(transaction, hash)?.filter(|entry| {
            entry.skeleton.v2.is_none()
                && entry.skeleton.channel_id == self.channel_id
                && entry.skeleton.author_id == *author
                && entry.skeleton.seq <= self.dag.verified_head(author)
        }))
    }
    /// Inspect an authenticated available body without consuming the live receiver chain.
    fn available_legacy_kind(&self, entry: &Entry) -> Option<bool> {
        // Format-2 public entries cannot carry the legacy private Session namespace.
        if entry.skeleton.v2.is_some() {
            return Some(false);
        }
        let payload = entry.payload.as_deref()?;
        if !matches!(classify_payload(payload), Ok(EntryKind::Content)) {
            return Some(false);
        }
        let Ok(msg) = GroupMessage::from_wire(payload) else {
            return Some(false);
        };
        if msg.header.channel_id != drive_channel(&self.channel_id) {
            return Some(false);
        }
        self.drive
            .classify(entry.entry_hash(), entry.skeleton.author_id, &msg)
    }
    fn legacy_kind_in(
        &self,
        transaction: Transaction<'_, '_>,
        hash: &Digest32,
    ) -> Result<Option<bool>> {
        let Some(log) = self.log_id_at(transaction, hash)? else {
            return Ok(None);
        };
        let Some(entry) = self.entry_at(transaction, hash)? else {
            return Err(Error::MalformedAtRest(
                "Session classification source missing",
            ));
        };
        // A signed-format entry cannot carry the legacy private Session namespace, as
        // `available_legacy_kind` and `inspect_legacy_body_into` already say; and an entry held
        // past its author's verified head is not classified yet, not malformed. Measured
        // 2026-10-20 on the decider's node (ADR-038 FX-33): a retention change's sweep walked a
        // declaration's steps onto a format-2 entry, refused it as "Session classification
        // source unverified", and poisoned the room on every tick.
        // An entry of another room under this hash is a real integrity failure and stays one;
        // only an entry that belongs here is then deferred or classified.
        if entry.skeleton.channel_id != self.channel_id {
            return Err(Error::MalformedAtRest(
                "Session classification source unverified",
            ));
        }
        if entry.skeleton.v2.is_some() {
            return Ok(Some(false));
        }
        let author = entry.skeleton.author_id;
        if entry.skeleton.seq > self.dag.verified_head(&author) {
            return Ok(None);
        }
        let saved = match self.legacy_page(transaction, page_id(log, false)?)? {
            Some(Page::Target {
                hash: saved,
                author: signer,
                session,
            }) if saved == *hash && signer == author => Some(session),
            Some(_) => {
                return Err(Error::MalformedAtRest(
                    "Session classification target binding",
                ))
            }
            None => None,
        };
        Ok(self.available_legacy_kind(&entry).or(saved))
    }
    /// Known subtype evidence for a transaction's derived indexes. Unknown is not a claim
    /// that pending declarations are complete; selected owed reads use the checked variant.
    pub(super) fn legacy_is_session_in(
        &self,
        transaction: Transaction<'_, '_>,
        hash: &Digest32,
    ) -> Result<bool> {
        Ok(self.legacy_kind_in(transaction, hash)? == Some(true))
    }
    fn put_legacy_target(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        header: &mut Header,
        hash: Digest32,
        author: Digest32,
        session: bool,
    ) -> Result<()> {
        let transaction = Transaction::Batch(batch);
        let log = self
            .log_id_at(transaction, &hash)?
            .ok_or(Error::MalformedAtRest(
                "Session classification source unpublished",
            ))?;
        let Some(entry) = self.entry_at(transaction, &hash)? else {
            return Err(Error::MalformedAtRest(
                "Session classification target unverified",
            ));
        };
        // An entry of another room or author is a real integrity failure and stays one; for
        // an entry that belongs here there is nothing to remember when it is signed-format, and
        // nothing yet when it is past its author's verified head (ADR-038 FX-33): the next pass
        // classifies what it can.
        if entry.skeleton.channel_id != self.channel_id || entry.skeleton.author_id != author {
            return Err(Error::MalformedAtRest(
                "Session classification target unverified",
            ));
        }
        if entry.skeleton.v2.is_some() || entry.skeleton.seq > self.dag.verified_head(&author) {
            return Ok(());
        }
        let id = page_id(log, false)?;
        let page = Page::Target {
            hash,
            author,
            session,
        };
        let previous = self.legacy_page(transaction, id)?;
        if previous.as_ref() == Some(&page) {
            return Ok(());
        }
        let prior = match previous {
            Some(Page::Target {
                hash: saved,
                author: signer,
                session,
            }) if saved == hash && signer == author => session,
            Some(_) => {
                return Err(Error::MalformedAtRest(
                    "Session classification target binding",
                ))
            }
            None => false,
        };
        let sealed = seal_segment(
            self.sek,
            SegmentKind::SessionClassification,
            id,
            &page.wire(),
        )?;
        batch.put_segment(
            &self.channel_id,
            SegmentKind::SessionClassification,
            id,
            &sealed,
        )?;
        self.legacy_sessions.dirty = true;
        if prior != session {
            header.changed()?;
        }
        Ok(())
    }
    /// Store subtype evidence in the transaction that publishes or prunes its source body.
    pub(super) fn remember_legacy_kind(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        hash: Digest32,
        author: Digest32,
        session: bool,
    ) -> Result<()> {
        let mut header = self.legacy_header(Transaction::Batch(batch))?;
        self.put_legacy_target(batch, &mut header, hash, author, session)?;
        if self.legacy_sessions.dirty() {
            self.save_legacy_header(batch, &header)?;
        }
        Ok(())
    }
    /// Called only after the verified entry has its transaction-local LogDb locator.
    pub(super) fn inspect_legacy_body_into(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        entry: &Entry,
    ) -> Result<()> {
        if entry.skeleton.v2.is_some() {
            return Ok(());
        }
        if let Some(session) = self.available_legacy_kind(entry) {
            self.remember_legacy_kind(
                batch,
                entry.entry_hash(),
                entry.skeleton.author_id,
                session,
            )?;
        }
        Ok(())
    }
    fn request_legacy_pass(
        &self,
        batch: &crate::node::store::Batch<'_>,
        header: &mut Header,
    ) -> Result<()> {
        if !header.pending && header.initialized {
            return Ok(());
        }
        if header.active {
            header.again = true;
        } else {
            header.active = true;
            header.after = 1;
            header.current = 0;
            header.offset = 0;
            header.through = batch
                .last_segment_id(&self.channel_id, SegmentKind::SessionClassification)?
                .unwrap_or(1)
                .max(1);
            header.unresolved = false;
            header.changed()?;
        }
        Ok(())
    }
    pub(super) fn accept_legacy_index(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        declaration: Digest32,
        outer_author: Digest32,
        index: LegacySessionIndex,
        now_ms: u64,
    ) -> Result<()> {
        if index.channel_id != self.channel_id || index.author != outer_author {
            return Ok(());
        }
        let transaction = Transaction::Batch(batch);
        let Some(entry) = self.legacy_target(transaction, &declaration, &outer_author)? else {
            return Ok(());
        };
        if entry.payload.is_none() {
            return Ok(());
        }
        let log = self
            .log_id_at(transaction, &declaration)?
            .ok_or(Error::MalformedAtRest(
                "Session declaration has no log page",
            ))?;
        let id = page_id(log, true)?;
        let first_seen = self
            .retention_get_in(transaction, &declaration)?
            .map_or(now_ms, |t| t.first_seen_ms);
        let page = Page::Pending {
            declaration,
            author: outer_author,
            first_seen,
            steps: index.steps,
        };
        // Re-rendering can repeat a declaration. Its original local age is never extended.
        let page = match self.legacy_page(transaction, id)? {
            Some(Page::Pending {
                declaration: saved,
                author,
                first_seen: first,
                steps,
            }) if saved == declaration && author == outer_author => Page::Pending {
                declaration,
                author,
                first_seen: first.min(first_seen),
                steps,
            },
            Some(_) => return Err(Error::MalformedAtRest("Session declaration page binding")),
            None => page,
        };
        if self.legacy_page(transaction, id)?.as_ref() != Some(&page) {
            let sealed = seal_segment(
                self.sek,
                SegmentKind::SessionClassification,
                id,
                &page.wire(),
            )?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::SessionClassification,
                id,
                &sealed,
            )?;
            self.legacy_sessions.dirty = true;
        }
        let mut header = self.legacy_header(Transaction::Batch(batch))?;
        header.pending = true;
        self.request_legacy_pass(batch, &mut header)?;
        self.save_legacy_header(batch, &header)
    }
    /// Request a fair pass for new input or retention changes, then inspect one bounded chunk.
    /// True means another turn is needed; unresolved absent targets do not spin a finished pass.
    pub(super) fn reconcile_legacy_sessions(&mut self, store: &Store, now_ms: u64) -> Result<bool> {
        let mut batch = store.batch()?;
        batch.derived();
        let more = self.reconcile_legacy_sessions_in(&mut batch, now_ms)?;
        if self.legacy_sessions.dirty() && !self.classification_inputs_pending() {
            batch.commit()?;
            self.legacy_sessions.committed();
            self.published = Some(self.legacy_sessions);
        }
        Ok(more)
    }
    pub(super) fn reconcile_legacy_sessions_in(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        now_ms: u64,
    ) -> Result<bool> {
        self.check_classification_authority(batch)?;
        let mut header = self.legacy_header(Transaction::Batch(batch))?;
        self.request_legacy_pass(batch, &mut header)?;
        self.advance_legacy_at(batch, &mut header, now_ms)?;
        if self.classification_inputs_pending() {
            return Ok(header.active || !header.initialized);
        }
        self.save_legacy_header(batch, &header)?;
        Ok(header.active || !header.initialized)
    }
    /// Continue existing work without requesting another pass. No Store or snapshot is retained.
    pub(crate) fn advance_legacy_sessions(&mut self, store: &Store, now_ms: u64) -> Result<bool> {
        let mut batch = store.batch()?;
        batch.derived();
        self.check_classification_authority(&batch)?;
        let mut header = self.legacy_header(Transaction::Batch(&batch))?;
        if !header.initialized && !header.active {
            self.request_legacy_pass(&batch, &mut header)?;
        }
        self.advance_legacy_at(&mut batch, &mut header, now_ms)?;
        let more = header.active || !header.initialized;
        if !self.classification_inputs_pending()
            && (self.legacy_sessions.dirty()
                || self.legacy_header(Transaction::Batch(&batch))? != header)
        {
            self.save_legacy_header(&mut batch, &header)?;
            batch.commit()?;
            self.legacy_sessions.committed();
            self.published = Some(self.legacy_sessions);
        }
        Ok(more)
    }
    /// Whether bounded classification work is owed, independent of unresolved absent targets.
    pub(crate) fn legacy_classification_pending(&self, store: &Store) -> Result<bool> {
        let snapshot = store.snapshot()?;
        let header = self.legacy_header(Transaction::Snapshot(&snapshot))?;
        Ok(header.active || !header.initialized)
    }
    fn advance_legacy_at(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        header: &mut Header,
        now_ms: u64,
    ) -> Result<()> {
        let mut remaining_work = WORK_SLOTS;
        while header.active && remaining_work > 0 {
            // Resolving a declaration can insert target pages before its own locator.
            // Keep the current page explicit so its reference offset cannot be applied
            // to one of those newly inserted pages on the next turn.
            let next = if header.current != 0 {
                Some(header.current)
            } else {
                next_id(Transaction::Batch(batch), &self.channel_id, header.after)?
                    .filter(|id| *id <= header.through)
            };
            let Some(id) = next else {
                header.initialized = true;
                header.active = false;
                header.current = 0;
                header.offset = 0;
                let again = std::mem::take(&mut header.again);
                // New input may have inserted a declaration beyond this pass's fixed tail.
                // Its request survives even when the old range had no unresolved targets.
                header.pending = header.unresolved || again;
                if again {
                    self.request_legacy_pass(batch, header)?;
                } else {
                    header.changed()?;
                }
                break;
            };
            remaining_work -= 1;
            let page =
                self.legacy_page(Transaction::Batch(batch), id)?
                    .ok_or(Error::MalformedAtRest(
                        "Session classification cursor page missing",
                    ))?;
            let (hash, author, pending) = match &page {
                Page::Target { hash, author, .. } => (*hash, *author, false),
                Page::Pending {
                    declaration,
                    author,
                    ..
                } => (*declaration, *author, true),
            };
            let Some(log) = self.log_id_at(Transaction::Batch(batch), &hash)? else {
                batch.delete_segment(&self.channel_id, SegmentKind::SessionClassification, id)?;
                self.legacy_sessions.dirty = true;
                header.after = id;
                header.current = 0;
                header.offset = 0;
                continue;
            };
            if page_id(log, pending)? != id
                || self
                    .legacy_target(Transaction::Batch(batch), &hash, &author)?
                    .is_none()
            {
                return Err(Error::MalformedAtRest(
                    "Session classification page binding",
                ));
            }
            match page {
                Page::Target { hash, author, .. } => {
                    if header.current != 0 || header.offset != 0 {
                        return Err(Error::MalformedAtRest(
                            "Session classification pending cursor kind",
                        ));
                    }
                    let session = self
                        .legacy_target(Transaction::Batch(batch), &hash, &author)?
                        .and_then(|entry| self.available_legacy_kind(&entry));
                    if self.classification_inputs_pending() {
                        return Ok(());
                    }
                    if let Some(session) = session {
                        self.put_legacy_target(batch, header, hash, author, session)?;
                    }
                    header.after = id;
                }
                Page::Pending {
                    declaration,
                    author,
                    first_seen,
                    steps,
                } => {
                    // Neither expiry nor a declaration's remaining lifetime can be decided
                    // from stale policy. Governance maintenance has no dependency on this pass.
                    if !self.governance_display_current(now_ms) {
                        break;
                    }
                    let ttl = self.effective_retention();
                    if ttl != 0 && first_seen <= now_ms.saturating_sub(ttl.saturating_mul(1_000)) {
                        batch.delete_segment(
                            &self.channel_id,
                            SegmentKind::SessionClassification,
                            id,
                        )?;
                        self.legacy_sessions.dirty = true;
                        header.after = id;
                        header.current = 0;
                        header.offset = 0;
                        continue;
                    }
                    if header.offset > steps.len() {
                        return Err(Error::MalformedAtRest(
                            "Session classification pending cursor offset",
                        ));
                    }
                    let end = (header.offset + remaining_work).min(steps.len());
                    let mut remaining = steps[..header.offset].to_vec();
                    for target in &steps[header.offset..end] {
                        remaining_work -= 1;
                        let transaction = Transaction::Batch(batch);
                        let Some(entry) = self.entry_at(transaction, target)? else {
                            remaining.push(*target);
                            continue;
                        };
                        if entry.skeleton.seq > self.dag.verified_head(&entry.skeleton.author_id)
                            || self.log_id_at(transaction, target)?.is_none()
                        {
                            remaining.push(*target);
                            continue;
                        }
                        if entry.skeleton.channel_id != self.channel_id
                            || entry.skeleton.author_id != author
                        {
                            continue;
                        }
                        // A signed-format entry cannot be a step of the legacy private Session
                        // namespace: it is dropped from the declaration's steps, never
                        // classified (ADR-038 FX-33).
                        if entry.skeleton.v2.is_some() {
                            continue;
                        }
                        let session = self.legacy_kind_in(transaction, target)?;
                        if self.classification_inputs_pending() {
                            return Ok(());
                        }
                        self.put_legacy_target(
                            batch,
                            header,
                            *target,
                            author,
                            session.unwrap_or(true),
                        )?;
                    }
                    let offset = remaining.len();
                    remaining.extend_from_slice(&steps[end..]);
                    if remaining.is_empty() {
                        batch.delete_segment(
                            &self.channel_id,
                            SegmentKind::SessionClassification,
                            id,
                        )?;
                        self.legacy_sessions.dirty = true;
                    } else if remaining != steps {
                        let page = Page::Pending {
                            declaration,
                            author,
                            first_seen,
                            steps: remaining.clone(),
                        };
                        let sealed = seal_segment(
                            self.sek,
                            SegmentKind::SessionClassification,
                            id,
                            &page.wire(),
                        )?;
                        batch.put_segment(
                            &self.channel_id,
                            SegmentKind::SessionClassification,
                            id,
                            &sealed,
                        )?;
                        self.legacy_sessions.dirty = true;
                    }
                    if end == steps.len() {
                        header.unresolved |= !remaining.is_empty();
                        header.after = id;
                        header.current = 0;
                        header.offset = 0;
                    } else {
                        header.current = id;
                        header.offset = offset;
                    }
                }
            }
        }
        Ok(())
    }
}
