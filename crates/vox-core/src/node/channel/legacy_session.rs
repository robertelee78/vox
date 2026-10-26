//! Authenticated exact-hash legacy Session subtype evidence (#804).
//!
//! Two sealed pages per log-id namespace: the even page records a target's known subtype;
//! the odd page holds the remaining references of that entry's authenticated declaration.
//! Pending pages follow local first-seen and ordinary retention. A resolved target page lives
//! with its verified skeleton, independently of the declaration's later expiry. No page grants
//! drive or changes `owed_wants`: subtype and permission eligibility are separate facts.

use super::*;
use crate::node::content::{LegacySessionIndex, MAX_LEGACY_SESSION_HASHES};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Page {
    Pending {
        declaration: Digest32,
        author: Digest32,
        first_seen: u64,
        steps: Vec<Digest32>,
    },
    Target {
        hash: Digest32,
        author: Digest32,
        session: bool,
    },
}

impl Page {
    fn wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Self::Pending {
                declaration,
                author,
                first_seen,
                steps,
            } => {
                e.array(6)
                    .uint(1)
                    .uint(0)
                    .bytes(declaration)
                    .bytes(author)
                    .uint(*first_seen)
                    .array(steps.len());
                for hash in steps {
                    e.bytes(hash);
                }
            }
            Self::Target {
                hash,
                author,
                session,
            } => {
                e.array(4)
                    .uint(1)
                    .uint(if *session { 1 } else { 2 })
                    .bytes(hash)
                    .bytes(author);
            }
        }
        e.finish()
    }

    fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let arity = d.array()?;
        if d.uint()? != 1 {
            return Err(Error::MalformedAtRest("Session classification version"));
        }
        let kind = d.uint()?;
        let hash = digest(&mut d)?;
        let author = digest(&mut d)?;
        let page = match (arity, kind) {
            (4, 1 | 2) => Self::Target {
                hash,
                author,
                session: kind == 1,
            },
            (6, 0) => {
                let first_seen = d.uint()?;
                let n = d.array()?;
                if n == 0 || n > MAX_LEGACY_SESSION_HASHES {
                    return Err(Error::MalformedAtRest("Session classification length"));
                }
                let mut steps = Vec::with_capacity(n);
                for _ in 0..n {
                    let h = digest(&mut d)?;
                    if steps.last().is_some_and(|last| *last >= h) {
                        return Err(Error::MalformedAtRest("Session classification order"));
                    }
                    steps.push(h);
                }
                Self::Pending {
                    declaration: hash,
                    author,
                    first_seen,
                    steps,
                }
            }
            _ => return Err(Error::MalformedAtRest("Session classification page")),
        };
        d.finish()?;
        Ok(page)
    }
}

fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("Session classification digest"))
}

fn page_id(log_id: u64, pending: bool) -> Result<u64> {
    log_id
        .checked_mul(2)
        .and_then(|id| id.checked_add(u64::from(pending)))
        .ok_or(Error::SizeLimitExceeded("Session classification pages"))
}

// LogDb starts at one, leaving page zero for bounded reconciliation state.
const HEADER: u64 = 0;
const WORK_SLOTS: usize = 64;
const PAGE_BYTES: usize = MAX_LEGACY_SESSION_HASHES * 34 + 256;
const REFRESHING: &str = "legacy Session classification is refreshing";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Header {
    revision: u64,
    initialized: bool,
    pending: bool,
    active: bool,
    after: u64,
    through: u64,
    current: u64,
    offset: usize,
    unresolved: bool,
    again: bool,
}

impl Header {
    fn empty(initialized: bool) -> Self {
        Self {
            revision: 0,
            initialized,
            pending: !initialized,
            active: false,
            after: 1,
            through: 1,
            current: 0,
            offset: 0,
            unresolved: false,
            again: false,
        }
    }

    fn wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(11)
            .uint(1)
            .uint(self.revision)
            .uint(u64::from(self.initialized))
            .uint(u64::from(self.pending))
            .uint(u64::from(self.active))
            .uint(self.after)
            .uint(self.through)
            .uint(self.current)
            .uint(self.offset as u64)
            .uint(u64::from(self.unresolved))
            .uint(u64::from(self.again));
        e.finish()
    }

    fn read(bytes: &[u8]) -> Result<Self> {
        fn flag(d: &mut Decoder<'_>) -> Result<bool> {
            match d.uint()? {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(Error::MalformedAtRest("Session classification cursor flag")),
            }
        }
        let mut d = Decoder::new(bytes);
        if d.array()? != 11 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest(
                "Session classification cursor version",
            ));
        }
        let header = Self {
            revision: d.uint()?,
            initialized: flag(&mut d)?,
            pending: flag(&mut d)?,
            active: flag(&mut d)?,
            after: d.uint()?,
            through: d.uint()?,
            current: d.uint()?,
            offset: usize::try_from(d.uint()?)
                .map_err(|_| Error::MalformedAtRest("Session classification cursor offset"))?,
            unresolved: flag(&mut d)?,
            again: flag(&mut d)?,
        };
        if header.after < 1
            || header.after > header.through
            || (header.current != 0
                && (header.current <= header.after || header.current > header.through))
            || header.offset > MAX_LEGACY_SESSION_HASHES
            || (header.offset != 0 && header.current == 0)
            || (!header.active && (header.current != 0 || header.offset != 0 || header.again))
        {
            return Err(Error::MalformedAtRest("Session classification cursor"));
        }
        d.finish()?;
        Ok(header)
    }

    fn changed(&mut self) -> Result<()> {
        self.revision = self.revision.checked_add(1).ok_or(Error::MalformedAtRest(
            "Session classification revision exhausted",
        ))?;
        Ok(())
    }
}

/// Only scalar publication state is resident. Pages and pending references remain sealed.
#[derive(Debug, Default)]
pub(super) struct LegacySessions {
    display_revision: u64,
    /// The caller's current Batch contains classification writes and must be committed.
    dirty: bool,
}

impl LegacySessions {
    pub(super) fn display_revision(&self) -> u64 {
        self.display_revision
    }

    pub(super) fn dirty(&self) -> bool {
        self.dirty
    }

    pub(super) fn committed(&mut self) {
        self.dirty = false;
    }
}

fn segment(
    transaction: Transaction<'_, '_>,
    room: &Digest32,
    id: u64,
) -> Result<Option<crate::atrest::store::SealedSegment>> {
    match transaction {
        Transaction::Snapshot(snapshot) => {
            snapshot.get_segment(room, SegmentKind::SessionClassification, id)
        }
        Transaction::Batch(batch) => {
            batch.get_segment(room, SegmentKind::SessionClassification, id)
        }
    }
}

fn next_id(transaction: Transaction<'_, '_>, room: &Digest32, after: u64) -> Result<Option<u64>> {
    match transaction {
        Transaction::Snapshot(snapshot) => {
            snapshot.segment_id_after(room, SegmentKind::SessionClassification, Some(after))
        }
        Transaction::Batch(batch) => {
            batch.segment_id_after(room, SegmentKind::SessionClassification, Some(after))
        }
    }
}

impl ChannelState {
    /// Exact retry classification; malformed or unreadable sealed facts remain errors.
    pub fn legacy_classification_refreshing(error: &Error) -> bool {
        matches!(error, Error::Profile(why) if *why == REFRESHING)
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
            &self.sek,
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
                    &self.sek,
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
            let sealed = seal_segment(
                &self.sek,
                SegmentKind::SessionClassification,
                HEADER,
                &bytes,
            )?;
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
            &self.sek,
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
        let slot = (entry.skeleton.author_id, msg.header.chain_id);
        let chain = self.drive.receivers.get(&slot)?;
        if !chain.can_open_iteration(msg.header.iteration) {
            return None;
        }
        let mut copied = ReceiverChain::from_state(&chain.to_state()).ok()?;
        let plaintext = Zeroizing::new(copied.decrypt(&msg).ok()?);
        Some(matches!(
            crate::node::content::decode(&plaintext),
            Ok(Decoded::Session(_))
        ))
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

    /// Refuse only an unknown subtype while its declaration evidence is still being examined.
    pub(super) fn legacy_is_session_current_in(
        &self,
        transaction: Transaction<'_, '_>,
        hash: &Digest32,
    ) -> Result<bool> {
        if let Some(session) = self.legacy_kind_in(transaction, hash)? {
            return Ok(session);
        }
        let header = self.legacy_header(transaction)?;
        if header.active || !header.initialized {
            return Err(Error::Profile(REFRESHING));
        }
        Ok(false)
    }

    /// Aggregate counts that include owed placeholders need a complete classification pass.
    /// Readable-only selections do not depend on this fence.
    pub(super) fn require_legacy_classification_complete_in(
        &self,
        transaction: Transaction<'_, '_>,
    ) -> Result<()> {
        let header = self.legacy_header(transaction)?;
        if header.active || !header.initialized {
            return Err(Error::Profile(REFRESHING));
        }
        Ok(())
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
            &self.sek,
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
                &self.sek,
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
        let more = self.reconcile_legacy_sessions_in(&mut batch, now_ms)?;
        if self.legacy_sessions.dirty() {
            batch.commit()?;
            self.legacy_sessions.committed();
        }
        Ok(more)
    }

    pub(super) fn reconcile_legacy_sessions_in(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        now_ms: u64,
    ) -> Result<bool> {
        let mut header = self.legacy_header(Transaction::Batch(batch))?;
        self.request_legacy_pass(batch, &mut header)?;
        self.advance_legacy_at(batch, &mut header, now_ms)?;
        self.save_legacy_header(batch, &header)?;
        Ok(header.active || !header.initialized)
    }

    /// Continue existing work without requesting another pass. No Store or snapshot is retained.
    pub(crate) fn advance_legacy_sessions(&mut self, store: &Store, now_ms: u64) -> Result<bool> {
        let mut batch = store.batch()?;
        let mut header = self.legacy_header(Transaction::Batch(&batch))?;
        if !header.initialized && !header.active {
            self.request_legacy_pass(&batch, &mut header)?;
        }
        self.advance_legacy_at(&mut batch, &mut header, now_ms)?;
        let more = header.active || !header.initialized;
        if self.legacy_sessions.dirty() || self.legacy_header(Transaction::Batch(&batch))? != header
        {
            self.save_legacy_header(&mut batch, &header)?;
            batch.commit()?;
            self.legacy_sessions.committed();
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
                    if let Some(session) = self
                        .legacy_target(Transaction::Batch(batch), &hash, &author)?
                        .and_then(|entry| self.available_legacy_kind(&entry))
                    {
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
                        let session = self.legacy_kind_in(transaction, target)?.unwrap_or(true);
                        self.put_legacy_target(batch, header, *target, author, session)?;
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
                            &self.sek,
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

    /// Load only the sealed cursor. Existing subtype pages are checked on lookup or one
    /// bounded reconciliation turn; reopening never materializes the retained classification set.
    pub(super) fn restore_legacy_sessions(&mut self, store: &Store, _now_ms: u64) -> Result<()> {
        let mut batch = store.batch()?;
        let mut header = self.legacy_header(Transaction::Batch(&batch))?;
        self.request_legacy_pass(&batch, &mut header)?;
        self.legacy_sessions.display_revision = header.revision;
        if self.legacy_header(Transaction::Batch(&batch))? != header {
            self.save_legacy_header(&mut batch, &header)?;
            batch.commit()?;
            self.legacy_sessions.committed();
        }
        Ok(())
    }
}

/// The bodyless-header part of legacy_is_session_current_in, on an owned read's
/// immutable snapshot. No receiver chain/key is cloned. Format-2 signed headers
/// are outside the legacy private namespace; old unknown evidence keeps its fence.
pub(super) fn read_snapshot_kind(
    snapshot: &crate::node::store::Snapshot,
    sek: &Sek,
    room: &Digest32,
    entry: &Entry,
    log: u64,
    verified: u64,
) -> Result<bool> {
    if entry.skeleton.channel_id != *room {
        return Err(Error::MalformedAtRest(
            "Session classification source unverified",
        ));
    }
    if entry.skeleton.v2.is_some() {
        return Ok(false);
    }
    // Past the verified prefix legacy_kind_in returns unknown. Mirror its
    // completed-header fallback instead of making a reader wait for a peer.
    if entry.skeleton.seq <= verified {
        let id = page_id(log, false)?;
        if let Some(sealed) = snapshot.get_segment(room, SegmentKind::SessionClassification, id)? {
            if sealed.ciphertext.len() > PAGE_BYTES + crate::atrest::sek::TAG_LEN {
                return Err(Error::MalformedAtRest("Session classification page size"));
            }
            return match Page::read(&open_segment(
                sek,
                SegmentKind::SessionClassification,
                id,
                &sealed,
            )?)? {
                Page::Target {
                    hash,
                    author,
                    session,
                } if hash == entry.entry_hash() && author == entry.skeleton.author_id => {
                    Ok(session)
                }
                _ => Err(Error::MalformedAtRest(
                    "Session classification target binding",
                )),
            };
        }
    }
    let header = match snapshot.get_segment(room, SegmentKind::SessionClassification, HEADER)? {
        Some(sealed) => {
            if sealed.ciphertext.len() > 256 {
                return Err(Error::MalformedAtRest("Session classification cursor size"));
            }
            Header::read(&open_segment(
                sek,
                SegmentKind::SessionClassification,
                HEADER,
                &sealed,
            )?)?
        }
        None => Header::empty(
            snapshot
                .segment_id_after(room, SegmentKind::SessionClassification, Some(1))?
                .is_none(),
        ),
    };
    if header.active || !header.initialized {
        Err(Error::Profile(REFRESHING))
    } else {
        Ok(false)
    }
}

pub(super) fn read_snapshot_complete(
    snapshot: &crate::node::store::Snapshot,
    sek: &Sek,
    room: &Digest32,
) -> Result<()> {
    let header = match snapshot.get_segment(room, SegmentKind::SessionClassification, HEADER)? {
        Some(sealed) => {
            if sealed.ciphertext.len() > 256 {
                return Err(Error::MalformedAtRest("Session classification cursor size"));
            }
            Header::read(&open_segment(
                sek,
                SegmentKind::SessionClassification,
                HEADER,
                &sealed,
            )?)?
        }
        None => Header::empty(
            snapshot
                .segment_id_after(room, SegmentKind::SessionClassification, Some(1))?
                .is_none(),
        ),
    };
    if header.active || !header.initialized {
        Err(Error::Profile(REFRESHING))
    } else {
        Ok(())
    }
}
