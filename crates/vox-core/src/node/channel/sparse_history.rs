//! Bounded access to authenticated-history state. Callers acquire the shared worker/buffer
//! envelope before these methods; every pinned store read is dropped before network I/O.

use super::*;
use crate::log::history::LogScope;
use crate::node::store::Batch;

/// Exact signed header and the length bound governing payload continuations.
pub(crate) struct HistoryHeader {
    pub wire: Vec<u8>,
}

pub(crate) struct HistoryHeadHint {
    pub author: Digest32,
    pub leaves: u64,
    pub head: Digest32,
}

pub(crate) struct HistoryHeadPage {
    pub heads: Vec<HistoryHeadHint>,
    pub next: Option<Digest32>,
}

/// A missing local body is not an authenticated expiry claim.
pub(crate) enum HistoryPayload {
    Missing,
    BodyNotHeld { payload_len: u64 },
    Held { payload_len: u64, bytes: Vec<u8> },
}

/// Bounded admission facts shared by live preflight and an owned physical transaction.
pub(crate) trait HistoryAdmissionRoom {
    fn channel_id(&self) -> Digest32;
    fn me(&self) -> Digest32;
    fn history_author_key(&self, author: &Digest32) -> Option<CompositePublicKey>;
    /// Rule F3: every proved splitter here, read now (`governance::splits`).
    fn history_splits(&self, store: &Store) -> Result<governance::Splits>;
    fn history_read<'a>(&'a self, store: &Store) -> Result<entry_store::Read<'a>>;
    fn history_publication_busy(&self, store: &Store) -> Result<bool>;
    fn generation(&self) -> Arc<std::sync::atomic::AtomicU64>;
    fn history_write_classified<T>(
        &self,
        store: &Store,
        durable: bool,
        operation: impl FnOnce(&mut entry_store::Write<'_, '_>) -> Result<T>,
    ) -> Result<T>;
    fn history_write_tracked<T>(
        &self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        operation: impl FnOnce(&mut entry_store::Write<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        let result = self.history_write_classified(store, false, operation)?;
        committed.store(true, std::sync::atomic::Ordering::Release);
        Ok(result)
    }
    /// Safety-narrowing own-head evidence is durable before the later recovery fence.
    fn history_write_own_head_tracked<T>(
        &self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        operation: impl FnOnce(&mut entry_store::Write<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        let result = self.history_write_classified(store, true, operation)?;
        committed.store(true, std::sync::atomic::Ordering::Release);
        Ok(result)
    }
}

/// The room while readers' view of it is pinned (`pin_history_read`): the only way history is
/// written on the room itself, as every other history writer writes (the source writer pins
/// first too, `history_stream/source.rs`). Readers are answered from the pinned view until the
/// writer publishes again, so a commit in between never refuses a read (`read_resource.rs`).
/// Built only from a held pin: no caller can write history on the room without one.
pub(crate) struct PinnedHistory<'a> {
    room: &'a ChannelState,
    pin: &'a history::PendingHistoryRead,
}

impl<'a> PinnedHistory<'a> {
    pub(crate) fn new(room: &'a ChannelState, pin: &'a history::PendingHistoryRead) -> Self {
        Self { room, pin }
    }
}

impl HistoryAdmissionRoom for PinnedHistory<'_> {
    fn channel_id(&self) -> Digest32 {
        ChannelState::channel_id(self.room)
    }
    fn me(&self) -> Digest32 {
        ChannelState::me(self.room)
    }
    fn history_author_key(&self, author: &Digest32) -> Option<CompositePublicKey> {
        ChannelState::history_author_key(self.room, author)
    }
    fn history_splits(&self, store: &Store) -> Result<governance::Splits> {
        ChannelState::history_splits(self.room, store)
    }
    fn history_read<'b>(&'b self, store: &Store) -> Result<entry_store::Read<'b>> {
        ChannelState::history_read(self.room, store)
    }
    fn history_publication_busy(&self, store: &Store) -> Result<bool> {
        ChannelState::history_publication_busy(self.room, store)
    }
    fn generation(&self) -> Arc<std::sync::atomic::AtomicU64> {
        ChannelState::generation(self.room)
    }
    fn history_write_classified<T>(
        &self,
        store: &Store,
        durable: bool,
        operation: impl FnOnce(&mut entry_store::Write<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        ChannelState::history_write_pinned(self.room, self.pin, store, durable, operation)
    }
}

pub(crate) struct PendingHistoryAdmission {
    pub(super) room: Digest32,
    pub(super) instance: [u8; 16],
    pub(super) epoch: u64,
    pub(super) me: Digest32,
    sek: crate::atrest::sek::WeakSek,
    authors: BTreeMap<Digest32, CompositePublicKey>,
    generation: Arc<std::sync::atomic::AtomicU64>,
    authorization: Option<(Digest32, Digest32)>,
    /// The room's creator: never eligible for the coordinate fallback (`governance::Split`).
    root: Digest32,
    /// Whether the room's DAG held any fork proof when these facts were taken: without one,
    /// `history_splits` reads nothing (`governance::splits`).
    forked: bool,
}

pub(crate) struct HistoryAdmission<'a> {
    pending: &'a PendingHistoryAdmission,
    sek: &'a Sek,
    entries: entry_store::EntryIndex,
}

impl HistoryAdmission<'_> {
    /// The room's key, for a committed read under it.
    pub(super) fn sek(&self) -> &Sek {
        self.sek
    }
}

impl PendingHistoryAdmission {
    pub(crate) fn with<T>(
        &self,
        operation: impl FnOnce(&HistoryAdmission<'_>) -> Result<T>,
    ) -> Result<T> {
        self.sek.with(|sek| {
            operation(&HistoryAdmission {
                pending: self,
                sek,
                entries: entry_store::EntryIndex::default(),
            })
        })
    }
}

impl HistoryAdmissionRoom for HistoryAdmission<'_> {
    fn channel_id(&self) -> Digest32 {
        self.pending.room
    }
    fn me(&self) -> Digest32 {
        self.pending.me
    }
    fn history_author_key(&self, author: &Digest32) -> Option<CompositePublicKey> {
        self.pending.authors.get(author).cloned()
    }
    fn history_splits(&self, store: &Store) -> Result<governance::Splits> {
        governance::splits(
            store,
            self.sek,
            &self.pending.room,
            &self.pending.root,
            self.pending.forked,
        )
    }
    fn history_read<'a>(&'a self, store: &Store) -> Result<entry_store::Read<'a>> {
        let read = self.entries.read(store, self.sek, &self.pending.room)?;
        if !read.sparse_enabled() {
            return Err(Error::MalformedGovernance(
                "room has no activated authenticated-history format",
            ));
        }
        Ok(read)
    }
    fn history_publication_busy(&self, store: &Store) -> Result<bool> {
        Ok(self.history_read(store)?.publication_busy())
    }
    fn generation(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.pending.generation)
    }
    fn history_write_classified<T>(
        &self,
        store: &Store,
        durable: bool,
        operation: impl FnOnce(&mut entry_store::Write<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        let mut batch = store.batch()?;
        if let Some((node, expected)) = self.pending.authorization {
            if crate::node::history_stream::authorization_generation_in(
                &batch,
                node,
                self.pending.room,
                self.pending.instance,
                self.pending.epoch,
            )? != expected
            {
                return Err(Error::Profile(
                    "history authorization changed before publication",
                ));
            }
        }
        if durable {
            batch.ruled();
        } else {
            batch.derived();
        }
        let mut index = self
            .entries
            .write(&mut batch, self.sek, &self.pending.room)?;
        let result = operation(&mut index)?;
        index.seal()?;
        batch.commit()?;
        self.entries.committed();
        Ok(result)
    }
}

/// The facts one sparse source's publication needs, captured under the room lock before its
/// transaction: at Begin for a new publication, at `prepare_history_source` to resume one.
pub(crate) struct PendingHistorySource {
    room: Digest32,
    sek: crate::atrest::sek::WeakSek,
    authors: BTreeMap<Digest32, CompositePublicKey>,
    creator: Digest32,
    me: Digest32,
    hash: Digest32,
    log: u64,
    request: [u8; 16],
    late: bool,
}

/// What one publication transaction reached. Nothing of the source is readable history until
/// `switched`: the log record, the root switch and the governance facts over it are one commit.
pub(crate) struct PublishedHistorySource {
    switched: Option<SwitchedHistorySource>,
    /// The publication's cleanup finished in that transaction: the room's publication is idle,
    /// with this newest published causal clock.
    cleaned: Option<Option<u64>>,
}

struct SwitchedHistorySource {
    next_log: u64,
    current_advanced: bool,
    governance_changed: bool,
}

impl PublishedHistorySource {
    pub(crate) fn switched(&self) -> bool {
        self.switched.is_some()
    }
    pub(crate) fn cleaned(&self) -> bool {
        self.cleaned.is_some()
    }
    /// The source changed the room's governance work: the fold's bounded turn is owed.
    pub(crate) fn governance_changed(&self) -> bool {
        self.switched
            .as_ref()
            .is_some_and(|switched| switched.governance_changed)
    }
}

impl PendingHistorySource {
    /// Resume this room's own sparse publication in one transaction.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn publish(
        self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        entry: &Entry,
        binding: entry_store::sparse::CursorBinding,
        now: crate::time::Ms,
        received: &crate::node::store::ReceivedFlow,
        check_binding: impl FnOnce(&Batch<'_>) -> Result<()>,
    ) -> Result<PublishedHistorySource> {
        self.sek.with(|sek| {
            let mut batch = store.received_batch(received)?;
            check_binding(&batch)?;
            let published = self.publish_in(&mut batch, sek, entry, binding, now)?;
            batch.commit()?;
            committed.store(true, std::sync::atomic::Ordering::Release);
            Ok(published)
        })
    }

    /// The one place a sparse source becomes history: one source-copy and DAG quantum; when the
    /// unpublished roots are ready, the log record, root switch, body debt, first-seen fact and
    /// the governance facts over it (`accepted_into`: observed, applied when live, `known_tail`
    /// advanced); then one cleanup quantum. All in the caller's one Batch.
    fn publish_in(
        &self,
        batch: &mut Batch<'_>,
        sek: &crate::atrest::sek::Sek,
        entry: &Entry,
        binding: entry_store::sparse::CursorBinding,
        now: crate::time::Ms,
    ) -> Result<PublishedHistorySource> {
        let entries = entry_store::EntryIndex::default();
        let input = entries.in_batch(batch, sek, &self.room)?;
        if input.sparse_publication_source()? != Some((self.hash, self.log))
            || input.sparse_publication_request() != Some(self.request)
            || entry.entry_hash() != self.hash
        {
            return Err(Error::MalformedAtRest(
                "sparse source publication binding changed",
            ));
        }
        drop(input);
        let mut index = entries.write(batch, sek, &self.room)?;
        if !index.advance_sparse_publication()? {
            index.seal()?;
            return Ok(PublishedHistorySource {
                switched: None,
                cleaned: None,
            });
        }
        index.publish_promotion()?;
        index.publish_key_body_debt(entry, now.get())?;
        index.seal()?;
        drop(index);
        let first_seen = seal_segment(
            sek,
            SegmentKind::Index,
            self.log,
            &first_seen_bytes(now.get(), false),
        )?;
        batch.put_segment(&self.room, SegmentKind::Index, self.log, &first_seen)?;
        let accepted = governance::accepted_into(
            batch,
            &entries,
            sek,
            &self.room,
            &self.authors,
            &self.creator,
            &self.me,
            self.log,
            entry,
            self.late,
        )?;
        // Preserve the source transaction's original promotion: current consent/presence
        // flushes here; other received facts remain owned by this Flow until settlement.
        if accepted.current_advanced
            && matches!(
                GovEntry::body_bound_to(entry),
                Ok(GovBody::ConsentGrant(_) | GovBody::ConsentRevocation(_) | GovBody::Presence(_))
            )
        {
            batch.ruled();
        }
        let mut index = entries.write(batch, sek, &self.room)?;
        let cleaned = index.cleanup_chunk()?;
        if cleaned {
            index.finish_history_verifier_cursor(binding)?;
        }
        index.seal()?;
        drop(index);
        let cleaned = if cleaned {
            let input = entries.in_batch(batch, sek, &self.room)?;
            Some(input.order_previous(None)?.map(|(clock, _)| clock))
        } else {
            None
        };
        Ok(PublishedHistorySource {
            switched: Some(SwitchedHistorySource {
                next_log: self
                    .log
                    .checked_add(1)
                    .ok_or(Error::MalformedAtRest("log allocator exhausted"))?,
                current_advanced: accepted.current_advanced,
                governance_changed: accepted.work_changed,
            }),
            cleaned,
        })
    }
}

impl ChannelState {
    pub(crate) fn prepare_history_admission(
        &self,
        store: &Store,
        authorization: Option<(Digest32, Digest32)>,
    ) -> Result<PendingHistoryAdmission> {
        if self.poisoned.get() {
            return Err(self.save_failure());
        }
        if self.post_pending() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        self.admission_facts(store, authorization)
    }

    /// The same facts for serving a peer: read-only, so a pending save does not stand in its way.
    pub(super) fn served_history_admission(
        &self,
        store: &Store,
    ) -> Result<PendingHistoryAdmission> {
        self.admission_facts(store, None)
    }

    fn admission_facts(
        &self,
        store: &Store,
        authorization: Option<(Digest32, Digest32)>,
    ) -> Result<PendingHistoryAdmission> {
        Ok(PendingHistoryAdmission {
            room: self.channel_id,
            instance: self.history_instance(store)?,
            epoch: self.epoch,
            me: self.me(),
            sek: self.sek.reader(),
            authors: self.authors.clone(),
            generation: Arc::clone(&self.gen),
            authorization,
            root: self.genesis.creator_pubkey().fingerprint(),
            forked: self.dag.any_frozen(),
        })
    }

    pub(crate) fn owns_pending_history_write(&self, owner: &Arc<()>) -> bool {
        self.pending_text
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, owner))
    }

    pub(crate) fn fail_pending_history_write(&mut self, owner: &Arc<()>, error: &Error) {
        if self.owns_pending_history_write(owner) {
            self.poison(error);
        }
    }

    pub(crate) fn history_index_committed(&self) {
        self.entries.committed();
    }
    /// Publication workers have already checked their exact source/hash/log binding. They
    /// retain that existing exclusion while reserving the same in-memory completion owner.
    pub(crate) fn reserve_pending_history_write(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        publication_owned: bool,
    ) -> Result<history::PendingHistoryRead> {
        if !publication_owned {
            return self.reserve_pending_write(store, owner);
        }
        if self.post_pending() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        let pin = self.pin_history_read(Arc::clone(store))?;
        self.pending_text = Some(owner);
        Ok(pin)
    }

    /// The current membership incarnation whose inventory a refusal describes. A leave makes
    /// this absent until the member's signed return supplies a newer position.
    pub(crate) fn history_inventory_incarnation(&self, member: &Digest32) -> Option<u64> {
        if !self.is_member(member) {
            return None;
        }
        Some(
            self.presence
                .get(member)
                .and_then(|presence| presence.back)
                .map_or(0, |(seq, _)| seq),
        )
    }

    /// The admitted author's inventory lifetime, including a historical author who has left.
    /// Peers may still advertise that author's terminal head after the departure. The departure
    /// itself changes the incarnation that validates prior refusals; if the same historical head
    /// is subsequently advertised, that indexed relationship is invalidated and becomes one new
    /// exact decision scoped to the departed author's terminal position.
    pub(crate) fn history_author_inventory_incarnation(&self, author: &Digest32) -> Option<u64> {
        if !self.is_author(author) {
            return None;
        }
        if let Some(left) = self.left_at(author) {
            return Some(left);
        }
        Some(
            self.presence
                .get(author)
                .and_then(|presence| presence.back)
                .map_or(0, |(seq, _)| seq),
        )
    }

    pub(crate) fn uses_sparse_history(&self, store: &Store) -> Result<bool> {
        if self.poisoned.get() {
            return Err(self.save_failure());
        }
        Ok(self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .sparse_enabled())
    }

    /// An exact echo of our already applied, contiguous departure is delivery evidence.
    /// It grants no authority, admits no source and needs no earlier body/proof fetch.
    pub(crate) fn history_departure_matches(
        &self,
        store: &Store,
        hint: crate::node::history_stream::HeadHint,
    ) -> Result<bool> {
        let own = self.me();
        if hint.author != own || !self.has_left(&own) {
            return Ok(false);
        }
        let read = self.history_read(store)?;
        if read.publication_busy() {
            return Ok(false);
        }
        let Some(head) = read.history_head(&hint.head)? else {
            return Ok(false);
        };
        if head.binding.author != own
            || head.root.leaves != hint.size
            || !read.history_head_committed(&hint.head, head.binding)?
            || read
                .sparse_author(&own, LogScope::Public)?
                .is_none_or(|s| s.committed != Some(hint.head))
        {
            return Ok(false);
        }
        let Some(included) = read.history_inclusion_receipt(&hint.head, &own, hint.size)? else {
            return Ok(false);
        };
        let entry = included.header().entry();
        Ok(read
            .restart_state()
            .and_then(|state| state.feeds.get(&own))
            .is_some_and(|feed| feed.seq == hint.size && feed.hash == entry.entry_hash())
            && self
                .presence
                .get(&own)
                .is_some_and(|p| p.last == (hint.size, false)))
    }

    /// Retain the existing exact departure acknowledgement. Ordinary join settlement is
    /// derived from durable own-head/window facts, never from this completion edge.
    pub(crate) fn note_history_head_complete(
        &mut self,
        store: &Store,
        hint: crate::node::history_stream::HeadHint,
    ) -> Result<Option<u64>> {
        if self.history_departure_matches(store, hint)? {
            return Ok(Some(
                self.generation().load(std::sync::atomic::Ordering::Relaxed),
            ));
        }
        Ok(None)
    }

    /// Settlement from this node's own durable record (ADR-037 R5): a sparse room not yet
    /// settled, no evidence that a member holds more of the own feed, and current governance.
    /// No peer acknowledgement is waited for; the detector above reads that when it comes.
    pub(crate) fn sparse_settlement_local_ready(
        &self,
        store: &Store,
        now: crate::time::Ms,
    ) -> Result<bool> {
        if self.settled || self.own_behind || !self.uses_sparse_history(store)? {
            return Ok(false);
        }
        if self.history_read(store)?.publication_busy() {
            return Ok(false);
        }
        if self.own_history_conflict(store)? {
            return Ok(false);
        }
        match self.require_governance_ready(store, now) {
            Ok(_) => Ok(true),
            Err(error) if Self::governance_refreshing(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(super) fn require_history_source_boundary(&self, entry: &Entry) -> Result<()> {
        if !self.history_source_admissible(entry) {
            return Err(Error::MalformedGovernance(
                "history source room, epoch or author boundary changed",
            ));
        }
        Ok(())
    }

    /// Whether this node would still admit a body of `entry` as a history source: its room, its
    /// epoch's admission of its author, and its author not frozen by a fork proof.
    pub(super) fn history_source_admissible(&self, entry: &Entry) -> bool {
        entry.skeleton.channel_id == self.channel_id
            && self.admission.is_admitted(
                &self.channel_id,
                entry.skeleton.epoch,
                &entry.skeleton.author_id,
            )
            && !self.dag.is_frozen(&entry.skeleton.author_id)
    }

    pub(crate) fn history_author_key(&self, author: &Digest32) -> Option<CompositePublicKey> {
        self.authors.get(author).cloned()
    }

    /// Rule F3: every proved splitter here (`governance::splits`); none without a frozen author.
    pub(crate) fn history_splits(&self, store: &Store) -> Result<governance::Splits> {
        governance::splits(
            store,
            &self.sek,
            &self.channel_id,
            &self.genesis.creator_pubkey().fingerprint(),
            self.dag.any_frozen(),
        )
    }

    /// One history commit on the room, only under a pin of readers' view ([`PinnedHistory`]).
    fn history_write_pinned<T>(
        &self,
        _pin: &history::PendingHistoryRead,
        store: &Store,
        durable: bool,
        operation: impl FnOnce(&mut entry_store::Write<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        if self.post_pending() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        if self.poisoned.get() {
            return Err(self.save_failure());
        }
        let mut batch = store.batch()?;
        // The lane's writes are derived: heads, headers, contexts, cursors, receipts, windows,
        // rebuilt from the proofs and the peers after a crash (ADR-038 FX-30).
        if durable {
            batch.ruled();
        } else {
            batch.derived();
        }
        let mut index = self
            .entries
            .write(&mut batch, &self.sek, &self.channel_id)?;
        let result = operation(&mut index)?;
        index.seal()?;
        batch.commit()?;
        self.entries.committed();
        self.publish_room_snapshot(store);
        Ok(result)
    }

    pub(crate) fn history_read<'a>(&'a self, store: &Store) -> Result<entry_store::Read<'a>> {
        if self.poisoned.get() {
            return Err(self.save_failure());
        }
        let read = self.entries.read(store, &self.sek, &self.channel_id)?;
        if !read.sparse_enabled() {
            return Err(Error::MalformedGovernance(
                "room has no activated authenticated-history format",
            ));
        }
        Ok(read)
    }

    /// What a person's `--history older` asks of this room. Each author's history is held here
    /// as one unbroken run of positions reaching down from what the walk syncs (its floor), and a
    /// request extends those runs downward, never anything else: per author, the page of up to
    /// [`OLDER_PAGE`] positions just below the lowest position of that run, down to position 1.
    /// Positions held below a gap do not count: the run merges with them when it reaches them, so
    /// no hole is ever left behind. An author is complete when its run reaches position 1. The
    /// lowest post of each run is read as its row is ([`Self::key_opens`]): one no key held here
    /// opens is counted (`unreadable`), this node's own runs too, and its walk goes on, since
    /// nothing this node holds says it was written before its author trusted this node. An author
    /// already owed a page (`fetching`) gets no second one. Authors whose run ends at the newest
    /// row are served
    /// first, at most `limit` of them (the requests this node may still keep); the others are
    /// counted (`left_out`). The row named (`before`) is where the person reads; it does not
    /// decide what is selected.
    pub(crate) fn history_older_page(
        &self,
        store: &Store,
        before: &Digest32,
        fetching: &BTreeSet<Digest32>,
        limit: usize,
    ) -> Result<OlderPage> {
        let read = self.history_read(store)?;
        let bytes = read
            .history_object(entry_store::sparse::ObjectKind::Header, before)?
            .ok_or(Error::Profile("The older-history cursor is not retained."))?;
        let anchor = Entry::from_wire(&bytes)?;
        if anchor.entry_hash() != *before
            || anchor.skeleton.channel_id != self.channel_id
            || anchor.skeleton.v2.is_none()
        {
            return Err(Error::Profile(
                "The older-history cursor binding is invalid.",
            ));
        }
        let record = self
            .room_snapshot
            .current()
            .and_then(|s| s.history().cloned());
        let render = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?;
        let mut page = OlderPage::default();
        // Per author with something below its run: when the run's lowest row shows, its head,
        // the author and that lowest position.
        let mut below = Vec::new();
        for author in self.authors.keys() {
            let Some((row, head)) = record
                .as_deref()
                .and_then(|history| history.author(author))
                .and_then(|row| Some((row, row.committed.as_ref()?)))
                .filter(|(row, _)| row.floor() > 0)
            else {
                page.unknown += 1;
                continue;
            };
            if row.window().is_some() {
                page.arriving += 1;
            }
            if fetching.contains(author) {
                continue;
            }
            let lowest = run_lowest(row);
            if self.oldest_unreadable(&read, &render, row, author, lowest)? {
                page.unreadable += 1;
            }
            if lowest <= 1 {
                continue;
            }
            let shown = match row
                .header_held(lowest)
                .then(|| read.history_position_header(author, lowest))
                .transpose()?
                .flatten()
            {
                Some(header) => read
                    .display_time(&header.entry_hash())?
                    .unwrap_or(header.skeleton.claimed_ms),
                None => 0,
            };
            below.push((shown, head.id(), *author, lowest));
        }
        below.sort_by(|a, b| b.0.cmp(&a.0));
        page.left_out = below.len().saturating_sub(limit);
        for (_, head, author, lowest) in below.into_iter().take(limit) {
            let lo = lowest.saturating_sub(OLDER_PAGE).max(1);
            page.owed.push((head, author, lo, lowest - 1));
        }
        Ok(page)
    }

    /// Whether the lowest post of `author`'s run from `lowest` up has no row here because no key
    /// held here opens it ([`Self::key_opens`]); false when it shows, is still being admitted, or
    /// no post is found. Reads at most [`OLDER_PAGE`] positions of the run.
    fn oldest_unreadable(
        &self,
        read: &entry_store::Read<'_>,
        render: &entry_store::RenderView<'_>,
        row: &super::held_history::HeldAuthor,
        author: &Digest32,
        lowest: u64,
    ) -> Result<bool> {
        use crate::log::history::SignedEntryKind;
        for seq in lowest..lowest.saturating_add(OLDER_PAGE) {
            if !row.held(seq) {
                if row.walked(seq) {
                    continue;
                }
                break;
            }
            let Some(header) = row
                .header_held(seq)
                .then(|| read.history_position_header(author, seq))
                .transpose()?
                .flatten()
                .filter(|header| {
                    header
                        .skeleton
                        .v2
                        .as_ref()
                        .is_some_and(|v2| v2.kind == SignedEntryKind::Content)
                })
            else {
                continue;
            };
            let hash = header.entry_hash();
            if render.fact(&hash)?.is_some() || !read.history_effect_finished(&hash)? {
                return Ok(false);
            }
            match self.held_post_opens(read, author, &hash)? {
                None => continue,
                Some(opens) => return Ok(!opens),
            }
        }
        Ok(false)
    }

    /// Whether a key held here opens a held post of another author ([`Self::key_opens`]), or
    /// `None` when the body is not a room post (a Session's step, which only its node's drive
    /// key opens).
    fn held_post_opens(
        &self,
        read: &entry_store::Read<'_>,
        author: &Digest32,
        hash: &Digest32,
    ) -> Result<Option<bool>> {
        let Some(payload) = self
            .dag
            .get_by_hash(read, hash)?
            .and_then(|entry| entry.payload)
        else {
            return Ok(None);
        };
        let Ok(msg) = GroupMessage::from_wire(&payload) else {
            return Ok(None);
        };
        if msg.header.channel_id == drive_channel(&self.channel_id) {
            return Ok(None);
        }
        Ok(Some(self.key_opens(author, &msg.header)))
    }

    /// Whether a post of `author` is held here and is not a row: among the newest
    /// [`OLDER_PAGE`] positions whose body is held here, a room post (not a control, not a
    /// Session step) whose admission finished, with no row here and not past its retention.
    /// False when none is found within that bound: it is said only when established.
    pub(crate) fn holds_unshown_post(
        &self,
        store: &Store,
        author: &Digest32,
        now_ms: u64,
    ) -> Result<bool> {
        use crate::log::history::SignedEntryKind;
        let record = self
            .room_snapshot
            .current()
            .and_then(|s| s.history().cloned());
        let Some(row) = record.as_deref().and_then(|history| history.author(author)) else {
            return Ok(false);
        };
        let read = self.history_read(store)?;
        let render = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?;
        let mut seq = row.held_below(u64::MAX);
        for _ in 0..OLDER_PAGE {
            if seq == 0 {
                break;
            }
            let here = seq;
            seq = row.held_below(here - 1);
            let Some(header) = row
                .header_held(here)
                .then(|| read.history_position_header(author, here))
                .transpose()?
                .flatten()
                .filter(|header| {
                    header
                        .skeleton
                        .v2
                        .as_ref()
                        .is_some_and(|v2| v2.kind == SignedEntryKind::Content)
                })
            else {
                continue;
            };
            let hash = header.entry_hash();
            if render.fact(&hash)?.is_some() || !read.history_effect_finished(&hash)? {
                continue;
            }
            let Some(entry) = self.dag.get_by_hash(&read, &hash)? else {
                continue;
            };
            let room_post = entry
                .payload
                .as_deref()
                .and_then(|payload| GroupMessage::from_wire(payload).ok())
                .is_some_and(|msg| msg.header.channel_id != drive_channel(&self.channel_id));
            if room_post
                && !self.already_expired_entry(
                    read.transaction(),
                    &entry,
                    entry.skeleton.claimed_ms,
                    now_ms,
                )?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Positions of one author a person's older-history request owes at most (one page).
pub(crate) const OLDER_PAGE: u64 = 64;

/// The lowest position of `row`'s unbroken run reaching down from the walk's floor: every
/// position from it to the floor is held or its admission completed.
fn run_lowest(row: &super::held_history::HeldAuthor) -> u64 {
    let mut seq = row.floor().saturating_sub(1);
    while seq > 0 {
        let unheld = row.unheld_below(seq);
        if unheld == 0 {
            return 1;
        }
        let gap = row.walked_runs().absent_below(unheld);
        if gap == unheld {
            return unheld + 1;
        }
        seq = gap;
    }
    1
}

/// What [`ChannelState::history_older_page`] found.
#[derive(Default)]
pub(crate) struct OlderPage {
    /// Per author: its committed head, the author, and the run `lo..=hi` owed.
    pub(crate) owed: Vec<(Digest32, Digest32, u64, u64)>,
    /// Members whose walk still owes this node posts: they are still arriving.
    pub(crate) arriving: usize,
    /// Members, this node included, whose oldest post held here has no row because no key held
    /// here opens it.
    pub(crate) unreadable: usize,
    /// Members with older posts to fetch that got no page: this node already keeps as many
    /// older-history requests as it may.
    pub(crate) left_out: usize,
    /// Members whose history this node does not know yet.
    pub(crate) unknown: usize,
}

pub(crate) struct PendingHistoryPublication {
    room: Digest32,
    sek: crate::atrest::sek::WeakSek,
    source_owned: bool,
}

pub(crate) struct CompletedHistoryPublication {
    result: Result<(bool, Option<[u8; 64]>)>,
    /// The newest published causal clock after the publication, for the idle end.
    newest_clock: Option<Option<u64>>,
}

impl PendingHistoryPublication {
    pub(crate) fn cleanup(
        self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        cursor: Option<entry_store::sparse::CursorBinding>,
        verifiers: Option<([u8; 16], Option<[u8; 64]>)>,
    ) -> CompletedHistoryPublication {
        let mut newest_clock = None;
        let result = self.sek.with(|sek| {
            let entries = entry_store::EntryIndex::default();
            let source_done = if self.source_owned {
                let done = entries.cleanup_publication(store, sek, &self.room)?;
                committed.store(true, std::sync::atomic::Ordering::Release);
                entries.committed();
                done
            } else {
                true
            };
            if !source_done {
                return Ok((false, verifiers.and_then(|(_, after)| after)));
            }
            let read = entries.read(store, sek, &self.room)?;
            newest_clock = Some(read.order_previous(None)?.map(|(clock, _)| clock));
            drop(read);
            let (done, next) = if cursor.is_some() || verifiers.is_some() {
                let mut batch = store.batch()?;
                batch.derived();
                let mut index = entries.write(&mut batch, sek, &self.room)?;
                let (done, next, changed) = if let Some((request, after)) = verifiers {
                    index.cleanup_history_verifiers(request, after)?
                } else {
                    (true, None, true)
                };
                if let Some(cursor) = cursor {
                    index.finish_history_verifier_cursor(cursor)?;
                }
                if changed || cursor.is_some() {
                    index.seal()?;
                    batch.commit()?;
                    committed.store(true, std::sync::atomic::Ordering::Release);
                }
                (done, next)
            } else {
                (true, None)
            };
            Ok((done, next))
        });
        CompletedHistoryPublication {
            result,
            newest_clock,
        }
    }
}

pub(crate) struct PendingHistoryBegin {
    room: Digest32,
    sek: crate::atrest::sek::WeakSek,
    first_log: u64,
    origin: u64,
    action: HistoryBeginAction,
}

#[allow(clippy::large_enum_variant)]
enum HistoryBeginAction {
    Start(PendingHistorySource),
    Duplicate,
    Busy,
    Fork {
        proof: Box<crate::log::dag::VerifiedFork>,
        issuer_key: CompositePublicKey,
        sealed: SealedSegment,
        invalid: Vec<(Digest32, u64)>,
        kept: usize,
    },
}

pub(crate) struct CompletedHistoryBegin {
    result: Result<HistorySourceStart>,
    fork: Option<crate::log::dag::VerifiedFork>,
    kept: usize,
    poison: bool,
}

impl PendingHistoryBegin {
    /// Begin, and in the same transaction as far as one bounded quantum reaches, publish.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit(
        self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        request: [u8; 16],
        entry: &Entry,
        validated: &governance::ValidatedSparseEntry,
        binding: entry_store::sparse::CursorBinding,
        now: crate::time::Ms,
        received: &crate::node::store::ReceivedFlow,
        check_binding: impl FnOnce(&Batch<'_>) -> Result<()>,
    ) -> CompletedHistoryBegin {
        let mut fork = None;
        let mut kept = 0;
        let mut poison = false;
        let result = self.sek.with(|sek| {
            if entry.entry_hash() != validated.entry_hash()
                || entry.header_wire() != validated.included().header().entry().header_wire()
            {
                return Err(Error::MalformedBundle(
                    "sparse source differs from validation",
                ));
            }
            let entries = entry_store::EntryIndex::default();
            match self.action {
                HistoryBeginAction::Busy => Ok(HistorySourceStart::Busy),
                HistoryBeginAction::Start(source) => {
                    let mut batch = store.received_batch(received)?;
                    check_binding(&batch)?;
                    let mut index = entries.write(&mut batch, sek, &self.room)?;
                    index.begin_sparse_publication(entry_store::SparsePublication {
                        request,
                        entry,
                        validated,
                        first_log: self.first_log,
                        received_ms: now.get(),
                        origin: self.origin,
                    })?;
                    index.seal()?;
                    drop(index);
                    let published = source.publish_in(&mut batch, sek, entry, binding, now)?;
                    batch.commit()?;
                    committed.store(true, std::sync::atomic::Ordering::Release);
                    Ok(HistorySourceStart::Started(published))
                }
                HistoryBeginAction::Duplicate => {
                    let mut batch = store.batch()?;
                    batch.derived();
                    check_binding(&batch)?;
                    let mut index = entries.write(&mut batch, sek, &self.room)?;
                    index.finish_history_verifier_cursor(binding)?;
                    index.seal()?;
                    batch.commit()?;
                    committed.store(true, std::sync::atomic::Ordering::Release);
                    Ok(HistorySourceStart::Duplicate)
                }
                HistoryBeginAction::Fork {
                    proof,
                    issuer_key,
                    sealed,
                    invalid,
                    kept: count,
                } => {
                    poison = true;
                    let mut batch = store.batch()?;
                    if let Err(error) = check_binding(&batch) {
                        poison = false;
                        return Err(error);
                    }
                    batch.put_segment(&self.room, SegmentKind::KeyMaterial, SEG_FORKS, &sealed)?;
                    let mut index = entries.write(&mut batch, sek, &self.room)?;
                    for (author, seq) in invalid {
                        index.resolve_legacy_required_invalid(&author, seq);
                    }
                    index.seal()?;
                    drop(index);
                    governance::note_fork_in(
                        &mut batch,
                        sek,
                        &self.room,
                        proof.proof(),
                        &issuer_key,
                        Some(validated),
                    )?;
                    batch.commit()?;
                    committed.store(true, std::sync::atomic::Ordering::Release);
                    poison = false;
                    fork = Some(*proof);
                    kept = count;
                    Err(Error::MalformedGovernance(
                        "author equivocated at a held sparse position",
                    ))
                }
            }
        });
        CompletedHistoryBegin {
            result,
            fork,
            kept,
            poison,
        }
    }
}

/// A retryable scheduling result. Busy never mutates a sender, poisons a room or loses the
/// caller's request; the actor retains and retries that request at its next eligible turn.
pub(crate) enum HistorySourceStart {
    Started(PublishedHistorySource),
    Duplicate,
    Busy,
}

impl ChannelState {
    pub(crate) fn history_publication_busy(&self, store: &Store) -> Result<bool> {
        if self.post_pending() {
            return Ok(true);
        }
        Ok(self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .publication_busy())
    }

    /// Source validation has already consumed the shared verifier envelope. This checks the
    /// current room/admission boundary again before starting one unpublished index operation;
    /// the validation token's binding to this entry is checked in its transaction.
    pub(crate) fn prepare_history_begin(
        &self,
        store: &Store,
        entry: &Entry,
        request: [u8; 16],
    ) -> Result<PendingHistoryBegin> {
        if self.post_pending() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        if self.poisoned.get() {
            return Err(self.save_failure());
        }
        if entry.skeleton.channel_id != self.channel_id
            || !self.admission.is_admitted(
                &self.channel_id,
                entry.skeleton.epoch,
                &entry.skeleton.author_id,
            )
            || self.dag.is_frozen(&entry.skeleton.author_id)
        {
            return Err(Error::MalformedGovernance(
                "sparse source is not currently admitted",
            ));
        }
        let read = self.history_read(store)?;
        let action = if read.publication_busy() {
            HistoryBeginAction::Busy
        } else if let Some(prior) =
            read.history_position_header(&entry.skeleton.author_id, entry.skeleton.seq)?
        {
            if prior.entry_hash() == entry.entry_hash() {
                HistoryBeginAction::Duplicate
            } else {
                let key = self
                    .authors
                    .get(&entry.skeleton.author_id)
                    .ok_or(Error::MalformedGovernance("sparse source author missing"))?;
                let proof = crate::log::dag::VerifiedFork::verify(
                    crate::log::dag::ForkProof {
                        author_id: entry.skeleton.author_id,
                        seq: entry.skeleton.seq,
                        existing: prior,
                        conflicting: entry.clone(),
                    },
                    key,
                )
                .map_err(|_| Error::MalformedBundle("sparse fork proof verification failed"))?;
                let mut proofs = self.dag.fork_proofs();
                proofs.push(proof.proof());
                proofs.sort_unstable_by_key(|proof| proof.author_id);
                let sealed = seal_segment(
                    &self.sek,
                    SegmentKind::KeyMaterial,
                    SEG_FORKS,
                    &forks_bytes(&proofs),
                )?;
                let invalid = proofs
                    .iter()
                    .map(|proof| (proof.author_id, proof.seq))
                    .collect();
                let kept = proofs.len();
                HistoryBeginAction::Fork {
                    proof: Box::new(proof),
                    issuer_key: key.clone(),
                    sealed,
                    invalid,
                    kept,
                }
            }
        } else if read.history_obligation_capacity() < 2 {
            HistoryBeginAction::Busy
        } else {
            HistoryBeginAction::Start(self.history_source(&read, entry, request)?)
        };
        Ok(PendingHistoryBegin {
            room: self.channel_id,
            sek: self.sek.reader(),
            first_log: self.next_log_id,
            origin: self.genesis.body.created_ms,
            action,
        })
    }

    pub(crate) fn finish_history_begin(
        &mut self,
        completed: CompletedHistoryBegin,
    ) -> Result<HistorySourceStart> {
        if let Some(proof) = completed.fork {
            self.dag.install_verified_fork(proof);
            self.forks_kept = completed.kept;
            self.entries.committed();
            // The proof froze its author and `note_fork_in` started a governance replay: what was
            // decided under the governance before it no longer stands. Read authority and every
            // "not received yet" decision go with the fork's installation, before the read
            // resource is published again, as for any governance change (`OwedDecided` starts a
            // new turn once governance is current again).
            self.retire_governance()?;
        }
        if completed.poison {
            if let Err(error) = &completed.result {
                self.poison(error);
            }
        }
        completed.result
    }

    /// MP-9: apply two signed entries of one author at one position, found by comparing two
    /// signed heads or received from a peer, exactly as a fork found at a held position is
    /// applied: the author is frozen, the proof kept in SEG_FORKS and its boundary noted.
    /// Returns false when the author was already frozen and this proof gives no lower boundary
    /// here by rule A, decided before any signature is verified; one that does replaces the
    /// kept proof, which is saved, and the boundary goes to 1 and is replayed (the fork rule's
    /// two steps, `pull::FORK_ASKS`; `sec-2.md` condition 1 as amended there).
    pub(crate) fn record_history_fork(
        &mut self,
        store: &Store,
        existing: Entry,
        conflicting: Entry,
    ) -> Result<bool> {
        let author = existing.skeleton.author_id;
        let seq = existing.skeleton.seq;
        if seq == 0
            || existing.skeleton.channel_id != self.channel_id
            || conflicting.skeleton.channel_id != self.channel_id
        {
            return Err(Error::MalformedBundle("fork proof binding"));
        }
        let key = self
            .authors
            .get(&author)
            .ok_or(Error::MalformedBundle("fork proof author is unknown"))?;
        let proof = crate::log::dag::ForkProof {
            author_id: author,
            seq,
            existing,
            conflicting,
        };
        // The cheap test before the expensive one: for an author already frozen here, a proof
        // whose boundary (rule A: its position, or 1, from its headers and this node's accepted
        // entry below it; no signature read) is not below the recorded one is dropped before
        // any signature is verified. A peer repeating a proof this node holds costs a lookup.
        let lower = self.dag.is_frozen(&author);
        if lower && !governance::fork_proof_lowers(store, &self.sek, &self.channel_id, &proof)? {
            return Ok(false);
        }
        let proof = crate::log::dag::VerifiedFork::verify(proof, key)
            .map_err(|_| Error::MalformedBundle("fork proof verification failed"))?;
        self.dag.install_verified_fork(proof);
        self.keep_forks(store, lower)?;
        Ok(true)
    }

    /// Capture only the exact publication's sealed-index access, never its room guard.
    pub(crate) fn prepare_history_publication(
        &self,
        store: &Store,
        source: Option<Digest32>,
        request: Option<[u8; 16]>,
    ) -> Result<PendingHistoryPublication> {
        if self.post_pending() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        let read = self.history_read(store)?;
        let current = read.sparse_publication_request();
        if read.publication_busy() && current.is_none() {
            return Err(Error::Profile("history publication owner changed"));
        }
        if let Some(source) = source {
            if read
                .sparse_publication_source()?
                .is_none_or(|(hash, _)| hash != source)
            {
                return Err(Error::MalformedAtRest(
                    "sparse source publication binding changed",
                ));
            }
        }
        if request.is_some() && current.is_some() && current != request {
            return Err(Error::Profile("history publication owner changed"));
        }
        Ok(PendingHistoryPublication {
            room: self.channel_id,
            sek: self.sek.reader(),
            source_owned: request.is_none() || current == request,
        })
    }

    pub(crate) fn finish_history_publication(
        &mut self,
        completed: CompletedHistoryPublication,
    ) -> Result<(bool, Option<[u8; 64]>)> {
        self.entries.committed();
        if let Some(newest) = completed.newest_clock {
            self.dag.set_newest_clock(newest);
        }
        completed.result
    }

    /// Resume this room's own sparse publication (its fact work or cleanup took more than the
    /// first transaction's quantum).
    pub(crate) fn prepare_history_source(
        &self,
        store: &Store,
        entry: &Entry,
        request: [u8; 16],
    ) -> Result<PendingHistorySource> {
        if self.post_pending() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        if self.poisoned.get() {
            return Err(self.save_failure());
        }
        let read = self.history_read(store)?;
        if read.sparse_publication_request() != Some(request) {
            return Err(Error::Profile("history publication owner changed"));
        }
        let (hash, log) = read
            .sparse_publication_source()?
            .ok_or(Error::MalformedAtRest("sparse source publication absent"))?;
        if hash != entry.entry_hash() || log != self.next_log_id {
            return Err(Error::MalformedAtRest(
                "sparse source publication binding changed",
            ));
        }
        self.history_source(&read, entry, request)
    }

    /// The source checks a publication has always made before its log record is written.
    fn history_source(
        &self,
        read: &entry_store::Read<'_>,
        entry: &Entry,
        request: [u8; 16],
    ) -> Result<PendingHistorySource> {
        self.require_history_source_boundary(entry)?;
        entry.verify_payload_binding()?;
        let hash = entry.entry_hash();
        Ok(PendingHistorySource {
            room: self.channel_id,
            sek: self.sek.reader(),
            authors: self.authors.clone(),
            creator: self.genesis.creator_pubkey().fingerprint(),
            me: self.me(),
            hash,
            log: self.next_log_id,
            request,
            late: read.child_after(&hash, None)?.is_some(),
        })
    }

    pub(crate) fn install_history_source(
        &mut self,
        entry: &Entry,
        published: &PublishedHistorySource,
    ) -> Result<()> {
        // Advance the in-memory mirror only after this path's Batch commits. Unlike the ordinary
        // publication paths, a sparse history caller does not poison the room on commit failure.
        self.entries.committed();
        if let Some(switched) = &published.switched {
            if switched.governance_changed {
                self.retire_governance()?;
            }
            if switched.current_advanced {
                self.note_committed_consent(entry)?;
            }
            self.next_log_id = switched.next_log;
        }
        if let Some(newest) = published.cleaned {
            self.dag.set_newest_clock(newest);
        }
        Ok(())
    }

    /// The exact request that owns an unfinished sparse-history publication, if any.
    pub(crate) fn history_publication_request(&self, store: &Store) -> Result<Option<[u8; 16]>> {
        Ok(self.history_read(store)?.sparse_publication_request())
    }

    /// Called only under the room mutex after this Begin owns its physical reservation.
    pub(crate) fn register_history_publication_flow(
        &mut self,
        store: &Store,
        request: [u8; 16],
        root: [u8; 16],
    ) -> Result<()> {
        if let Some((previous, previous_root)) = self.history_publication_flow {
            if (previous, previous_root) != (request, root) {
                self.settle_history_publication_flow(store, previous, previous_root)?;
                if self.history_publication_flow.is_some() {
                    return Err(Error::Profile(
                        "sparse publication has another live Flow owner",
                    ));
                }
            }
        }
        self.history_publication_flow = Some((request, root));
        Ok(())
    }

    /// The physical worker has ended; only a committed read may release this exact binding.
    pub(crate) fn settle_history_publication_flow(
        &mut self,
        store: &Store,
        request: [u8; 16],
        root: [u8; 16],
    ) -> Result<()> {
        if self.history_publication_flow != Some((request, root)) {
            return Ok(());
        }
        let current = self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .sparse_publication_request();
        if current != Some(request) {
            self.history_publication_flow = None;
            self.history_publication_changed.notify_waiters();
        }
        Ok(())
    }

    /// Subscribe under the room mutex before testing its actual publication owner. Only a
    /// committed completion or key erasure publishes this edge; no room guard is retained.
    pub(crate) fn history_publication_wake(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>> {
        let mut wake =
            Box::pin(std::sync::Arc::clone(&self.history_publication_changed).notified_owned());
        wake.as_mut().enable();
        wake
    }
    pub(crate) fn history_retirement_locked(&self) -> bool {
        self.sek.key_bytes().is_err()
    }
}

/// Transaction-scoped authority for the exact typed effect. Content constructs it only after
/// semantic admission. Non-Content may stage it before dispatch in the same Batch because its
/// handler requires the marker; no marker becomes durable unless that handler and the Batch both
/// succeed. A committed marker therefore always means semantic dispatch completed. Encrypted key
/// installation stays independent.
pub(super) struct FinishedHistoryEffect {
    pub(super) hash: Digest32,
}
impl FinishedHistoryEffect {
    pub(super) fn entry_hash(&self) -> Digest32 {
        self.hash
    }
}

#[cfg(feature = "test-knobs")]
const TEST_FX29_CONTENT_OUTCOME_ENV: &str = "VOX_TEST_FX29_CONTENT_OUTCOME_FILE";
#[cfg(feature = "test-knobs")]
const TEST_FX29_REFILL_OUTCOME_ENV: &str = "VOX_TEST_FX29_CONTENT_REFILL_OUTCOME_FILE";
#[cfg(feature = "test-knobs")]
const TEST_FX29_REFILL_HASH_ENV: &str = "VOX_TEST_FX29_CONTENT_REFILL_HASH";

#[derive(Clone, Copy)]
pub(crate) struct HistoryEffectCursor {
    pub(super) hash: Digest32,
    pub(super) next: usize,
    pub(super) rendered: bool,
}
impl HistoryEffectCursor {
    pub(crate) fn new(hash: Digest32) -> Self {
        Self {
            hash,
            next: 0,
            rendered: false,
        }
    }
    pub(crate) fn with_rendered(hash: Digest32, rendered: bool) -> Self {
        Self {
            hash,
            next: 0,
            rendered,
        }
    }
}

pub(crate) enum HistoryEffectProgress {
    Progress,
    /// This exact staged entry was admitted, but contiguous feed work remains.
    AdmittedProgress {
        rendered: bool,
    },
    RefillPending {
        governance: bool,
    },
    BodyUnavailable,
    /// The exact requested package expired or was otherwise already satisfied.
    KeyBodyRetired,
    ControlPending {
        head: Digest32,
        through: u64,
    },
    GovernancePending,
    CheckpointPending {
        author: Digest32,
        seq: u64,
    },
    Complete {
        rendered: bool,
    },
}

impl ChannelState {
    #[cfg(feature = "test-knobs")]
    pub(super) fn record_fx29_content_outcome(
        &self,
        hash: &Digest32,
        accepted: bool,
    ) -> Result<()> {
        use std::io::Write as _;
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

        let Some(path) = std::env::var_os(TEST_FX29_CONTENT_OUTCOME_ENV)
            .filter(|path| !path.is_empty())
            .map(std::path::PathBuf::from)
        else {
            return Ok(());
        };
        let mut temporary = path.as_os_str().to_os_string();
        temporary.push(format!(
            ".writing.{}.{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        ));
        let temporary: std::path::PathBuf = temporary.into();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| {
                Error::Profile("test sparse-Content outcome marker could not be created")
            })?;
        let outcome = if accepted { "accepted" } else { "refused" };
        if write!(file, "{outcome}:{}", crate::node::link::b32_encode(hash)).is_err() {
            drop(file);
            let _ = std::fs::remove_file(&temporary);
            return Err(Error::Profile(
                "test sparse-Content outcome marker could not be written",
            ));
        }
        drop(file);
        // A hard link is the no-replace publication primitive here: all callers have a unique,
        // complete temporary inode, and exactly one can attach it at `path`. Unlike a
        // check-then-rename, a later Content outcome can never replace the first marker.
        let published = match std::fs::hard_link(&temporary, &path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(_) => Err(Error::Profile(
                "test sparse-Content outcome marker could not be published",
            )),
        };
        let _ = std::fs::remove_file(&temporary);
        published
    }

    #[cfg(feature = "test-knobs")]
    pub(super) fn record_fx29_refill_outcome(&self, hash: &Digest32) -> Result<()> {
        use std::io::Write as _;
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

        let encoded = crate::node::link::b32_encode(hash);
        if std::env::var(TEST_FX29_REFILL_HASH_ENV).as_deref() != Ok(encoded.as_str()) {
            return Ok(());
        }
        let Some(path) = std::env::var_os(TEST_FX29_REFILL_OUTCOME_ENV)
            .filter(|path| !path.is_empty())
            .map(std::path::PathBuf::from)
        else {
            return Ok(());
        };
        let mut temporary = path.as_os_str().to_os_string();
        temporary.push(format!(
            ".writing.{}.{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        ));
        let temporary: std::path::PathBuf = temporary.into();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| {
                Error::Profile("test sparse-Content refill marker could not be created")
            })?;
        if write!(file, "accepted:{encoded}").is_err() {
            drop(file);
            let _ = std::fs::remove_file(&temporary);
            return Err(Error::Profile(
                "test sparse-Content refill marker could not be written",
            ));
        }
        drop(file);
        let published = match std::fs::hard_link(&temporary, &path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(_) => Err(Error::Profile(
                "test sparse-Content refill marker could not be published",
            )),
        };
        let _ = std::fs::remove_file(&temporary);
        published
    }
}

impl ChannelState {
    pub(super) fn note_contiguous_advance(
        &mut self,
        author: Digest32,
        progress: entry_store::sparse::ContiguousAdvance,
    ) -> Result<()> {
        if let Some(state) = progress.state {
            self.dag.restore_contiguous_author(author, &state)?;
            self.role_cuts.insert(author, state.seq);
        }
        if progress.more {
            self.sparse_contiguous_pending.insert(author);
        } else {
            self.sparse_contiguous_pending.remove(&author);
        }
        Ok(())
    }
}
