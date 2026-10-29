//! Bounded access to authenticated-history state. Callers acquire the shared worker/buffer
//! envelope before these methods; every pinned store read is dropped before network I/O.

use super::*;
use crate::log::history::{ControlContext, LogScope, SignedHead};
use crate::node::store::Batch;

pub(super) struct KeyProviderPruneWait {
    pub(super) ready: Arc<std::sync::atomic::AtomicBool>,
    pub(super) task: tokio::task::JoinHandle<()>,
}
impl Drop for KeyProviderPruneWait {
    fn drop(&mut self) {
        self.task.abort();
    }
}

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

/// One authenticated local debt, or an explicit dependency that must wake before retry.
// Keep the bounded record inline; boxing would add an uncharged allocation.
#[allow(clippy::large_enum_variant)]
pub(crate) enum KeyDebtPage {
    End,
    Frozen {
        serial: u64,
    },
    Ready {
        serial: u64,
        need: crate::node::history_stream::KeyBodyNeed,
    },
}

/// Atomic result of persisting one advertised-head refusal. Authorization mismatch is not a
/// storage error: it carries the fresh generation read by the same batch that fenced the flow's
/// captured generation.
pub(crate) enum HistoryDeclineResult {
    Stored { remembered: bool, current: Digest32 },
    AuthorizationChanged { current: Digest32 },
}

/// Exact refusal inputs captured from the currently authorized room. The trust generation
/// remains an in-transaction check; capturing these scalars does not confer peer authority.
pub(crate) struct PendingHistoryDecline {
    room: Digest32,
    instance: [u8; 16],
    epoch: u64,
    sek: crate::atrest::sek::WeakSek,
    node: Digest32,
    peer: Digest32,
    author: Digest32,
    head: Digest32,
    authorization: Digest32,
    metadata: bool,
    peer_incarnation: u64,
    author_incarnation: u64,
}

impl PendingHistoryDecline {
    pub(crate) fn commit(
        self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
    ) -> Result<HistoryDeclineResult> {
        let mut batch = store.batch()?;
        let current = crate::node::history_stream::authorization_generation_in(
            &batch,
            self.node,
            self.room,
            self.instance,
            self.epoch,
        )?;
        if current != self.authorization {
            return Ok(HistoryDeclineResult::AuthorizationChanged { current });
        }
        self.sek.with(|sek| {
            let entries = entry_store::EntryIndex::default();
            let mut index = entries.write(&mut batch, sek, &self.room)?;
            let prior = if self.metadata {
                index.history_declined_metadata(&self.peer, &self.author)?
            } else {
                index.history_declined_head(&self.peer, &self.author)?
            };
            if prior
                == Some((
                    self.head,
                    self.authorization,
                    self.peer_incarnation,
                    self.author_incarnation,
                ))
            {
                return Ok(HistoryDeclineResult::Stored {
                    remembered: false,
                    current,
                });
            }
            if self.metadata {
                index.keep_history_declined_metadata(
                    self.peer,
                    self.author,
                    self.head,
                    self.authorization,
                    self.peer_incarnation,
                    self.author_incarnation,
                )?;
            } else {
                index.keep_history_declined_head(
                    self.peer,
                    self.author,
                    self.head,
                    self.authorization,
                    self.peer_incarnation,
                    self.author_incarnation,
                )?;
            }
            index.seal()?;
            batch.commit()?;
            committed.store(true, std::sync::atomic::Ordering::Release);
            Ok(HistoryDeclineResult::Stored {
                remembered: true,
                current,
            })
        })
    }
}

/// Bounded admission facts shared by live preflight and an owned physical transaction.
pub(crate) trait HistoryAdmissionRoom {
    fn channel_id(&self) -> Digest32;
    fn me(&self) -> Digest32;
    fn history_author_key(&self, author: &Digest32) -> Option<CompositePublicKey>;
    fn history_read<'a>(&'a self, store: &Store) -> Result<entry_store::Read<'a>>;
    fn history_publication_busy(&self, store: &Store) -> Result<bool>;
    fn history_departure_matches(
        &self,
        store: &Store,
        hint: crate::node::history_stream::HeadHint,
    ) -> Result<bool>;
    fn note_role_progress(&self, author: Digest32, seq: u64);
    fn role_owed(&self) -> Arc<role_owed::RoleOwed>;
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

impl HistoryAdmissionRoom for ChannelState {
    fn channel_id(&self) -> Digest32 {
        ChannelState::channel_id(self)
    }
    fn me(&self) -> Digest32 {
        ChannelState::me(self)
    }
    fn history_author_key(&self, author: &Digest32) -> Option<CompositePublicKey> {
        ChannelState::history_author_key(self, author)
    }
    fn history_read<'a>(&'a self, store: &Store) -> Result<entry_store::Read<'a>> {
        ChannelState::history_read(self, store)
    }
    fn history_publication_busy(&self, store: &Store) -> Result<bool> {
        ChannelState::history_publication_busy(self, store)
    }
    fn history_departure_matches(
        &self,
        store: &Store,
        hint: crate::node::history_stream::HeadHint,
    ) -> Result<bool> {
        ChannelState::history_departure_matches(self, store, hint)
    }
    fn note_role_progress(&self, author: Digest32, seq: u64) {
        ChannelState::note_role_progress(self, author, seq)
    }
    fn role_owed(&self) -> Arc<role_owed::RoleOwed> {
        ChannelState::role_owed(self)
    }
    fn generation(&self) -> Arc<std::sync::atomic::AtomicU64> {
        ChannelState::generation(self)
    }
    fn history_write_classified<T>(
        &self,
        store: &Store,
        durable: bool,
        operation: impl FnOnce(&mut entry_store::Write<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        ChannelState::history_write_classified(self, store, durable, operation)
    }
}

pub(crate) struct PendingHistoryAdmission {
    room: Digest32,
    instance: [u8; 16],
    epoch: u64,
    me: Digest32,
    sek: crate::atrest::sek::WeakSek,
    authors: BTreeMap<Digest32, CompositePublicKey>,
    members: BTreeSet<Digest32>,
    role_cuts: BTreeMap<Digest32, u64>,
    role_owed: Arc<role_owed::RoleOwed>,
    generation: Arc<std::sync::atomic::AtomicU64>,
    own_left: bool,
    own_presence: Option<governance::Presence>,
    authorization: Option<(Digest32, Digest32)>,
}

pub(crate) struct HistoryAdmission<'a> {
    pending: &'a PendingHistoryAdmission,
    sek: &'a Sek,
    entries: entry_store::EntryIndex,
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
    fn history_departure_matches(
        &self,
        store: &Store,
        hint: crate::node::history_stream::HeadHint,
    ) -> Result<bool> {
        let own = self.me();
        if hint.author != own || !self.pending.own_left {
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
                .is_none_or(|state| state.committed != Some(hint.head))
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
                .pending
                .own_presence
                .is_some_and(|p| p.last == (hint.size, false)))
    }
    fn note_role_progress(&self, author: Digest32, seq: u64) {
        if !self.pending.members.contains(&author) {
            self.pending.role_owed.clear(author);
        } else if author != self.me()
            && seq != 0
            && self.pending.role_cuts.get(&author).copied() == Some(seq)
        {
            self.pending.role_owed.mark_dirty(author);
        }
    }
    fn role_owed(&self) -> Arc<role_owed::RoleOwed> {
        Arc::clone(&self.pending.role_owed)
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

pub(crate) struct PendingKeyProviderCursor {
    room: Digest32,
    instance: [u8; 16],
    epoch: u64,
    sek: crate::atrest::sek::WeakSek,
    provider: Digest32,
    node: Digest32,
    authorization: Digest32,
    expected: Option<entry_store::sparse::KeyProviderCursor>,
    next: entry_store::sparse::KeyProviderCursor,
}

impl PendingKeyProviderCursor {
    pub(crate) fn commit(self, store: &Store) -> Result<bool> {
        let mut batch = store.batch()?;
        if crate::node::history_stream::authorization_generation_in(
            &batch,
            self.node,
            self.room,
            self.instance,
            self.epoch,
        )? != self.authorization
        {
            return Ok(false);
        }
        self.sek.with(|sek| {
            let entries = entry_store::EntryIndex::default();
            let mut index = entries.write(&mut batch, sek, &self.room)?;
            if index.key_provider_cursor(&self.provider)? != self.expected {
                return Ok(false);
            }
            index.keep_key_provider_cursor(self.provider, self.next)?;
            index.seal()?;
            batch.commit()?;
            Ok(true)
        })
    }
}

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

pub(crate) struct CommittedHistorySource {
    next_log: u64,
    current_advanced: bool,
}

impl PendingHistorySource {
    pub(crate) fn commit(
        self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        entry: &Entry,
        now: crate::time::Ms,
        received: &crate::node::store::ReceivedFlow,
        on_publish: impl FnOnce(&mut Batch<'_>) -> Result<()>,
    ) -> Result<CommittedHistorySource> {
        let next_log = self
            .log
            .checked_add(1)
            .ok_or(Error::MalformedAtRest("log allocator exhausted"))?;
        let mut batch = store.received_batch(received)?;
        on_publish(&mut batch)?;
        self.sek.with(|sek| {
            let entries = entry_store::EntryIndex::default();
            let input = entries.in_batch(&batch, sek, &self.room)?;
            if input.sparse_publication_source()? != Some((self.hash, self.log))
                || input.sparse_publication_request() != Some(self.request)
            {
                return Err(Error::MalformedAtRest(
                    "sparse source publication binding changed",
                ));
            }
            drop(input);
            let mut index = entries.write(&mut batch, sek, &self.room)?;
            index.publish_promotion()?;
            index.publish_key_body_debt(entry, now.get())?;
            index.seal()?;
            let first_seen = seal_segment(
                sek,
                SegmentKind::Index,
                self.log,
                &first_seen_bytes(now.get(), false),
            )?;
            batch.put_segment(&self.room, SegmentKind::Index, self.log, &first_seen)?;
            let accepted = governance::accepted_into(
                &mut batch,
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
                    Ok(GovBody::ConsentGrant(_)
                        | GovBody::ConsentRevocation(_)
                        | GovBody::Presence(_))
                )
            {
                batch.ruled();
            }
            batch.commit()?;
            committed.store(true, std::sync::atomic::Ordering::Release);
            Ok(CommittedHistorySource {
                next_log,
                current_advanced: accepted.current_advanced,
            })
        })
    }
}

impl ChannelState {
    pub(crate) fn prepare_history_admission(
        &self,
        store: &Store,
        authorization: Option<(Digest32, Digest32)>,
    ) -> Result<PendingHistoryAdmission> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if self.post_pending() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        Ok(PendingHistoryAdmission {
            room: self.channel_id,
            instance: self.history_instance(store)?,
            epoch: self.epoch,
            me: self.me(),
            sek: self.sek.reader(),
            authors: self.authors.clone(),
            members: self
                .authors
                .keys()
                .filter(|author| self.is_member(author))
                .copied()
                .collect(),
            role_cuts: self.role_cuts.clone(),
            role_owed: Arc::clone(&self.role_owed),
            generation: Arc::clone(&self.gen),
            own_left: self.has_left(&self.me()),
            own_presence: self.presence.get(&self.me()).copied(),
            authorization,
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
    /// this absent; a readmission uses the leave position until the member's signed `back`
    /// statement supplies its newer position. Thus the same scalar head after a real scope
    /// removal is a changed inventory lifetime, while a socket reconnect is not.
    pub(crate) fn history_inventory_incarnation(&self, member: &Digest32) -> Option<u64> {
        if !self.is_member(member) {
            return None;
        }
        if let Some(left) = self.left_at(member) {
            if self.readmitted.get(member) == Some(&left) {
                return Some(left);
            }
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

    /// Capture one exact refusal without acquiring the Store writer.
    pub(crate) fn prepare_history_decline(
        &self,
        store: &Store,
        peer: Digest32,
        author: Digest32,
        head: Digest32,
        authorization: (Digest32, Digest32, bool),
    ) -> Result<PendingHistoryDecline> {
        if self.post_pending() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        let (node, expected_authorization, metadata) = authorization;
        let peer_incarnation =
            self.history_inventory_incarnation(&peer)
                .ok_or(Error::MalformedGovernance(
                    "declined history source is not a member",
                ))?;
        let author_incarnation = self.history_author_inventory_incarnation(&author).ok_or(
            Error::MalformedGovernance("declined history author is not admitted"),
        )?;
        if node != self.me() {
            return Err(Error::Profile(
                "history authorization changed before refusal",
            ));
        }
        Ok(PendingHistoryDecline {
            room: self.channel_id,
            instance: self.history_instance(store)?,
            epoch: self.epoch,
            sek: self.sek.reader(),
            node,
            peer,
            author,
            head,
            authorization: expected_authorization,
            metadata,
            peer_incarnation,
            author_incarnation,
        })
    }

    /// Read the receiver's one provider cursor. The caller owns a bounded worker and must
    /// recheck the room/connection and peer trust before using the result.
    pub(crate) fn key_provider_cursor(
        &self,
        store: &Store,
        provider: Digest32,
    ) -> Result<Option<entry_store::sparse::KeyProviderCursor>> {
        self.history_read(store)?.key_provider_cursor(&provider)
    }

    /// Capture only the expected cursor and its current room/authorization incarnation.
    pub(crate) fn prepare_key_provider_cursor(
        &self,
        store: &Store,
        provider: Digest32,
        node: Digest32,
        authorization: Digest32,
        expected: Option<entry_store::sparse::KeyProviderCursor>,
        next: entry_store::sparse::KeyProviderCursor,
    ) -> Result<Option<PendingKeyProviderCursor>> {
        if self.post_pending() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        if node != self.me()
            || !self.is_member(&node)
            || !self.is_member(&provider)
            || self.history_inventory_incarnation(&provider) != Some(next.peer_incarnation)
            || next.authorization != authorization
        {
            return Ok(None);
        }
        if let Some(old) = expected {
            if old.authorization == next.authorization
                && old.peer_incarnation == next.peer_incarnation
                && old.connection == next.connection
                && (next.local_after < old.local_after
                    || (old.instance == next.instance && next.after < old.after))
            {
                return Err(Error::Profile("key provider cursor moved backwards"));
            }
        }
        Ok(Some(PendingKeyProviderCursor {
            room: self.channel_id,
            instance: self.history_instance(store)?,
            epoch: self.epoch,
            sek: self.sek.reader(),
            provider,
            node,
            authorization,
            expected,
            next,
        }))
    }

    /// A relevant advertised successor or changed membership incarnation removes the durable
    /// refusal. The inbox holds only charge-free pending scalar hints; this indexed record is the
    /// sole refusal state.
    pub(crate) fn forget_history_decline(
        &self,
        store: &Store,
        peer: Digest32,
        author: Digest32,
        committed: &std::sync::atomic::AtomicBool,
    ) -> Result<()> {
        let read = self.history_read(store)?;
        if read.history_declined_head(&peer, &author)?.is_none() {
            return Ok(());
        }
        drop(read);
        self.history_write_tracked(store, committed, |index| {
            index.forget_history_declined_head(peer, author)
        })
    }

    pub(crate) fn uses_sparse_history(&self, store: &Store) -> Result<bool> {
        if self.poisoned {
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

    /// The own-author committed head whose live-window acknowledgement is the only
    /// missing piece of [`Self::sparse_settlement_ready`]: the room is unsettled,
    /// the own sparse state has a committed own head with no observed conflict, the
    /// local contiguous verified prefix covers that head, and the own live window
    /// has not (fully) visited it. `None` when the settlement is missing something
    /// else, or is already ready.
    pub(crate) fn sparse_settlement_pending_own_head(
        &self,
        store: &Store,
    ) -> Option<(Digest32, Digest32, u64)> {
        // Asked for whether or not the room is settled (ADR-037 R5): settlement no longer
        // waits on it, but the own-history conflict detector reads what it fetches.
        let read = self.history_read(store).ok()?;
        if read.publication_busy() {
            return None;
        }
        let own = self.me();
        let contiguous = self.dag.verified_head(&own);
        if read
            .history_settled_tip(&own)
            .ok()?
            .is_some_and(|tip| tip.skeleton.seq > contiguous)
        {
            return None;
        }
        let state = read.sparse_author(&own, LogScope::Public).ok()??;
        if state.observed_conflict.is_some() {
            return None;
        }
        let committed = state.committed?;
        let head = read.history_head(&committed).ok()??;
        let acknowledged = state.live.is_some_and(|window| {
            window.head == committed && window.through == head.root.leaves && window.complete()
        });
        if acknowledged
            || head.binding.author != own
            || head.binding.scope != LogScope::Public
            || head.root.leaves > contiguous
        {
            return None;
        }
        Some((own, committed, head.root.leaves))
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
        if entry.skeleton.channel_id != self.channel_id
            || !self.admission.is_admitted(
                &self.channel_id,
                entry.skeleton.epoch,
                &entry.skeleton.author_id,
            )
            || self.dag.is_frozen(&entry.skeleton.author_id)
        {
            return Err(Error::MalformedGovernance(
                "history source room, epoch or author boundary changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn history_author_key(&self, author: &Digest32) -> Option<CompositePublicKey> {
        self.authors.get(author).cloned()
    }

    /// One caller-budgeted transaction. The callback may only use the typed storage APIs;
    /// network waits and queue admission happen before taking this room/store context.
    pub(crate) fn history_write<T>(
        &self,
        store: &Store,
        operation: impl FnOnce(&mut entry_store::Write<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        self.history_write_classified(store, false, operation)
    }

    fn history_write_classified<T>(
        &self,
        store: &Store,
        durable: bool,
        operation: impl FnOnce(&mut entry_store::Write<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        if self.post_pending() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        if self.poisoned {
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
        Ok(result)
    }

    /// Run one history transaction and mark its user-visible lane immediately after the commit.
    /// A later transaction or callback failure must not turn already durable work into a quiet
    /// status sample.
    pub(crate) fn history_write_tracked<T>(
        &self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        operation: impl FnOnce(&mut entry_store::Write<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        let result = self.history_write(store, operation)?;
        committed.store(true, std::sync::atomic::Ordering::Release);
        Ok(result)
    }

    pub(crate) fn history_head_by_id(
        &self,
        store: &Store,
        head: &Digest32,
    ) -> Result<Option<SignedHead>> {
        let read = self.history_read(store)?;
        let Some(value) = read.history_head(head)? else {
            return Ok(None);
        };
        if read.history_head_committed(head, value.binding)? {
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// One bounded page of commitments. No scan or signed-head vector survives this read.
    pub(crate) fn history_head_hints(
        &self,
        store: &Store,
        after: Option<Digest32>,
    ) -> Result<HistoryHeadPage> {
        let read = self.history_read(store)?;
        let mut next = after;
        let mut heads = Vec::new();
        for _ in 0..64 {
            let Some((author, state)) = read.history_author_after(next)? else {
                return Ok(HistoryHeadPage { heads, next: None });
            };
            next = Some(author);
            if let Some(id) = state.committed {
                let head = read
                    .history_head(&id)?
                    .ok_or(Error::MalformedAtRest("committed history head missing"))?;
                heads.push(HistoryHeadHint {
                    author,
                    leaves: head.root.leaves,
                    head: id,
                });
            }
        }
        Ok(HistoryHeadPage { heads, next })
    }
    pub(crate) fn history_read<'a>(&'a self, store: &Store) -> Result<entry_store::Read<'a>> {
        if self.poisoned {
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

    /// The latest consistency-accepted commitment. It is not a control-ready or contiguous
    /// position, and serving it does not change either state.
    pub(crate) fn history_head(
        &self,
        store: &Store,
        author: &Digest32,
    ) -> Result<Option<SignedHead>> {
        let read = self.history_read(store)?;
        let Some(id) = read
            .sparse_author(author, LogScope::Public)?
            .and_then(|state| state.committed)
        else {
            return Ok(None);
        };
        read.history_head(&id)
    }

    pub(crate) fn history_context(
        &self,
        store: &Store,
        hash: &Digest32,
    ) -> Result<Option<ControlContext>> {
        self.history_read(store)?.history_context(hash)
    }

    pub(crate) fn history_header(
        &self,
        store: &Store,
        author: &Digest32,
        seq: u64,
    ) -> Result<Option<HistoryHeader>> {
        self.history_read(store)?
            .history_position_header(author, seq)?
            .map(|entry| {
                Ok(HistoryHeader {
                    wire: entry.header_wire(),
                })
            })
            .transpose()
    }

    /// Return only a retained signed commitment exactly at this node's completed role cut.
    /// A newer accepted commitment is metadata, not a receipt for its unfinished source.
    pub(crate) fn history_role_head(
        &self,
        store: &Store,
        author: &Digest32,
    ) -> Result<Option<SignedHead>> {
        let read = self.history_read(store)?;
        let Some(state) = read.sparse_author(author, LogScope::Public)? else {
            return Ok(None);
        };
        let (through, hash) = read.history_held_through(author).unwrap_or((0, [0; 32]));
        let source = if through == 0 {
            None
        } else {
            read.history_validated_header(author, through)?
                .map(|(head, _)| head)
        };
        for id in [state.committed, state.control_ready, source]
            .into_iter()
            .flatten()
        {
            let head = read
                .history_head(&id)?
                .ok_or(Error::MalformedAtRest("role receipt head missing"))?;
            if head.id() != id
                || head.binding.room != self.channel_id
                || head.binding.author != *author
                || head.binding.scope != LogScope::Public
            {
                return Err(Error::MalformedAtRest("role receipt head binding"));
            }
            if head.root.leaves != through || !read.history_head_committed(&id, head.binding)? {
                continue;
            }
            if through != 0 {
                let Some(included) = read.history_inclusion_receipt(&id, author, through)? else {
                    continue;
                };
                if included.head_id() != id
                    || included.binding() != head.binding
                    || included.root() != head.root
                    || included.header().entry().skeleton.seq != through
                {
                    return Err(Error::MalformedAtRest("role receipt inclusion binding"));
                }
                if included.header().entry().entry_hash() != hash {
                    continue;
                }
            }
            return Ok(Some(head));
        }
        Ok(None)
    }

    /// Metadata-only fallback: an exact sealed inclusion receipt can retain a signed header
    /// before its source/effect has reached the canonical position index. This never supplies
    /// Entry/Page bodies or publishes a canonical position.
    pub(crate) fn history_proof_header(
        &self,
        store: &Store,
        head: &SignedHead,
        seq: u64,
    ) -> Result<Option<HistoryHeader>> {
        let read = self.history_read(store)?;
        if let Some(entry) = read.history_position_header(&head.binding.author, seq)? {
            return Ok(Some(HistoryHeader {
                wire: entry.header_wire(),
            }));
        }
        let Some(included) =
            read.history_inclusion_receipt(&head.id(), &head.binding.author, seq)?
        else {
            return Ok(None);
        };
        let entry = included.header().entry();
        if included.head_id() != head.id()
            || included.binding() != head.binding
            || included.root() != head.root
            || entry.skeleton.channel_id != self.channel_id
            || entry.skeleton.author_id != head.binding.author
            || entry.skeleton.seq != seq
        {
            return Err(Error::MalformedAtRest("proof header receipt binding"));
        }
        Ok(Some(HistoryHeader {
            wire: entry.header_wire(),
        }))
    }

    /// A locally queued receipt probe obeys the same durable exact refusal as wire inventory.
    pub(crate) fn history_own_receipt_targets(
        &self,
        store: &Store,
        peers: Vec<(Digest32, Option<(u64, crate::node::ports::OwnProbe)>)>,
        head: Digest32,
        size: u64,
    ) -> Result<Vec<Digest32>> {
        // One captured index for all current peers, not a Directory decode per peer.
        let read = self.history_read(store)?;
        let authorization = crate::node::history_stream::authorization_generation(
            store,
            self.me(),
            self.channel_id,
            read.sparse_history_instance(),
            self.epoch,
        )?;
        let mut targets = Vec::new();
        for (peer, parked) in peers {
            if !self.is_member(&peer) || self.held_through(&peer).is_some_and(|held| held >= size) {
                continue;
            }
            if parked.is_some_and(|(connection, probe)| {
                probe.matches(
                    crate::node::ports::SupportDiscovery {
                        connection,
                        instance: read.sparse_history_instance(),
                        epoch: self.epoch,
                        authorization,
                    },
                    head,
                    self.history_inventory_incarnation(&peer)
                        .zip(self.history_author_inventory_incarnation(&self.me())),
                )
            }) {
                continue;
            }
            let refused = read.history_declined_head(&peer, &self.me())?;
            let current = self
                .history_inventory_incarnation(&peer)
                .zip(self.history_author_inventory_incarnation(&self.me()))
                .map(|(peer_life, author_life)| (head, authorization, peer_life, author_life));
            if refused != current {
                targets.push(peer);
            }
        }
        Ok(targets)
    }

    /// Decode and authenticate one body once under the caller's large-record envelope.
    /// The response driver borrows its chunks for this quantum and drops the body before
    /// yielding; it must not call whole-record AEAD once for every 64-KiB frame.
    pub(crate) fn history_payload(&self, store: &Store, hash: &Digest32) -> Result<HistoryPayload> {
        let read = self.history_read(store)?;
        let Some(entry) = read.history_entry(hash)? else {
            return Ok(HistoryPayload::Missing);
        };
        if entry.skeleton.v2.is_none() {
            return Err(Error::MalformedAtRest("legacy entry in activated history"));
        }
        let payload_len = entry.skeleton.payload_len;
        let Some(payload) = entry.payload else {
            return Ok(HistoryPayload::BodyNotHeld { payload_len });
        };
        if payload.len() as u64 != payload_len || sha256(&payload) != entry.skeleton.payload_hash {
            return Err(Error::MalformedAtRest(
                "stored history payload differs from header",
            ));
        }
        Ok(HistoryPayload::Held {
            payload_len,
            bytes: payload,
        })
    }
}

pub(crate) struct PendingHistoryPublication {
    room: Digest32,
    sek: crate::atrest::sek::WeakSek,
    source_owned: bool,
}

pub(crate) struct CompletedHistoryPublication {
    result: Result<(bool, Option<[u8; 64]>)>,
    order: Option<(u64, Option<u64>)>,
}

impl PendingHistoryPublication {
    pub(crate) fn advance(
        self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
    ) -> Result<bool> {
        self.sek.with(|sek| {
            let entries = entry_store::EntryIndex::default();
            let ready = entries.advance_sparse_publication(store, sek, &self.room)?;
            committed.store(true, std::sync::atomic::Ordering::Release);
            Ok(ready)
        })
    }

    pub(crate) fn cleanup(
        self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        cursor: Option<entry_store::sparse::CursorBinding>,
        verifiers: Option<([u8; 16], Option<[u8; 64]>)>,
    ) -> CompletedHistoryPublication {
        let mut order = None;
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
            order = Some((
                read.order_revision(),
                read.order_previous(None)?.map(|(clock, _)| clock),
            ));
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
        CompletedHistoryPublication { result, order }
    }
}

pub(crate) struct PendingHistoryBegin {
    room: Digest32,
    sek: crate::atrest::sek::WeakSek,
    first_log: u64,
    origin: u64,
    action: HistoryBeginAction,
}

enum HistoryBeginAction {
    Start,
    Duplicate,
    Busy,
    Fork {
        proof: Box<crate::log::dag::VerifiedFork>,
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
        check_binding: impl FnOnce(&Batch<'_>) -> Result<()>,
    ) -> CompletedHistoryBegin {
        let mut fork = None;
        let mut kept = 0;
        let mut poison = false;
        let result = self.sek.with(|sek| {
            let entries = entry_store::EntryIndex::default();
            match self.action {
                HistoryBeginAction::Busy => Ok(HistorySourceStart::Busy),
                HistoryBeginAction::Start => {
                    entries.begin_sparse_publication(
                        store,
                        sek,
                        &self.room,
                        entry_store::SparsePublication {
                            request,
                            entry,
                            validated,
                            first_log: self.first_log,
                            received_ms: now.get(),
                            origin: self.origin,
                        },
                    )?;
                    committed.store(true, std::sync::atomic::Ordering::Release);
                    Ok(HistorySourceStart::Started)
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
    Started,
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

    /// Enumerate one locally held sealed package using the durable acquisition cursor.
    /// An ineligible catalog entry advances the cursor without advertising it.
    pub(crate) fn history_key_available_page(
        &self,
        store: &Store,
        after: Option<u64>,
    ) -> Result<Option<(u64, Option<crate::node::history_stream::KeyBodyAvailable>)>> {
        let read = self.history_read(store)?;
        let Some((cursor, log)) = read.key_package_after(after)? else {
            return Ok(None);
        };
        let sealed = store
            .snapshot()?
            .get_segment_bounded(
                &self.channel_id,
                SegmentKind::LogDb,
                log,
                crate::node::keypackage::MAX_KEY_PACKAGE
                    + crate::log::history::MAX_HEADER_BYTES
                    + 9,
            )?
            .ok_or(Error::MalformedAtRest("key-package catalog body missing"))?;
        let wire = open_segment(&self.sek, SegmentKind::LogDb, log, &sealed)?;
        let entry = Entry::from_wire(&wire)?;
        entry.verify_payload_binding()?;
        let Some(v2) = entry.skeleton.v2.as_ref() else {
            return Ok(Some((cursor, None)));
        };
        if v2.kind != crate::log::history::SignedEntryKind::KeyPackage {
            return Err(Error::MalformedAtRest("key-package catalog entry differs"));
        }
        if entry.payload.is_none() {
            return Ok(Some((cursor, None)));
        }
        let recipient = v2
            .recipient
            .ok_or(Error::MalformedAtRest("key-package recipient missing"))?;
        let Some((head, header)) =
            read.history_validated_header(&entry.skeleton.author_id, entry.skeleton.seq)?
        else {
            return Ok(Some((cursor, None)));
        };
        if header.entry_hash() != entry.entry_hash() {
            return Err(Error::MalformedAtRest("key-package source header differs"));
        }
        Ok(Some((
            cursor,
            Some(crate::node::history_stream::KeyBodyAvailable {
                cursor,
                author: entry.skeleton.author_id,
                head,
                seq: entry.skeleton.seq,
                hash: entry.entry_hash(),
                recipient,
            }),
        )))
    }

    /// A newly committed sealed-package debt may be filled by any eligible room peer.
    pub(crate) fn note_key_body_debt(&self) {
        for peer in self
            .authors
            .keys()
            .copied()
            .filter(|peer| *peer != self.me() && self.is_member(peer))
        {
            self.role_owed.mark_key_dirty(peer);
        }
    }

    /// A newly durable indexed ciphertext may satisfy an exact peer's outstanding debt.
    pub(crate) fn note_key_body_acquired(&self) {
        for peer in self
            .authors
            .keys()
            .copied()
            .filter(|peer| *peer != self.me() && self.is_member(peer))
        {
            self.role_owed.mark_key_catalog_changed(peer);
        }
    }

    /// Read one exact local debt in insertion order; this does not advance its owner.
    /// An unavailable author head is a dependency, never evidence that the debt is gone.
    pub(crate) fn key_debt_after(
        &self,
        store: &Store,
        authorization: Digest32,
        after: u64,
    ) -> Result<Option<KeyDebtPage>> {
        let read = self.history_read(store)?;
        if read.publication_busy() {
            return Ok(None);
        }
        let Some((serial, debt)) = read.history_key_debt_after(Some(after))? else {
            return Ok(Some(KeyDebtPage::End));
        };
        let author = debt.author;
        let state = read
            .sparse_author(&author, crate::log::history::LogScope::Public)?
            .ok_or(Error::MalformedAtRest("key-body author missing"))?;
        // A conflicting signed source is permanently frozen, so it cannot be a donor
        // candidate. Advance past it without blocking unrelated authenticated authors.
        if state.observed_conflict.is_some() {
            return Ok(Some(KeyDebtPage::Frozen { serial }));
        }
        let target_id = state
            .committed
            .ok_or(Error::MalformedAtRest("key-body committed head missing"))?;
        let target = read
            .history_head(&target_id)?
            .ok_or(Error::MalformedAtRest("key-body head object missing"))?;
        let (source_head, entry) = read
            .history_validated_header(&author, debt.from)?
            .ok_or(Error::MalformedAtRest("key-body source missing"))?;
        let recipient = entry
            .skeleton
            .v2
            .as_ref()
            .filter(|v| v.kind == crate::log::history::SignedEntryKind::KeyPackage)
            .and_then(|v| v.recipient)
            .ok_or(Error::MalformedAtRest("key-body recipient missing"))?;
        if debt.from != debt.through
            || source_head != debt.head
            || entry.entry_hash() != debt.object
            || !read.history_head_accepted(&source_head, target.binding)?
            || !read.history_head_accepted(&target.id(), target.binding)?
            || debt.from > target.root.leaves
        {
            return Err(Error::MalformedAtRest("key-body source binding"));
        }
        Ok(Some(KeyDebtPage::Ready {
            serial,
            need: crate::node::history_stream::KeyBodyNeed {
                head: source_head,
                seq: debt.from,
                hash: debt.object,
                recipient,
                authorization,
                target: crate::node::history_stream::HeadHint {
                    author,
                    head: target.id(),
                    size: target.root.leaves,
                },
            },
        }))
    }

    /// Match an availability hint against an already authenticated, still-pending local debt.
    /// The hint is neither evidence of a body nor a grant to admit it.
    pub(crate) fn key_debt_for_notice(
        &self,
        store: &Store,
        authorization: Digest32,
        notice: crate::node::history_stream::KeyBodyAvailable,
    ) -> Result<Option<Option<crate::node::history_stream::KeyBodyNeed>>> {
        let read = self.history_read(store)?;
        if read.publication_busy() {
            return Ok(None);
        }
        let Some((source_head, entry)) =
            read.history_validated_header(&notice.author, notice.seq)?
        else {
            return Ok(Some(None));
        };
        if entry.entry_hash() != notice.hash
            || !entry.skeleton.v2.as_ref().is_some_and(|v| {
                v.kind == crate::log::history::SignedEntryKind::KeyPackage
                    && v.recipient == Some(notice.recipient)
            })
        {
            return Ok(Some(None));
        }
        let Some(state) =
            read.sparse_author(&notice.author, crate::log::history::LogScope::Public)?
        else {
            return Ok(Some(None));
        };
        if state.observed_conflict.is_some() {
            return Ok(Some(None));
        }
        let Some(target_id) = state.committed else {
            return Ok(Some(None));
        };
        let Some(target) = read.history_head(&target_id)? else {
            return Ok(Some(None));
        };
        if !read.history_head_accepted(&source_head, target.binding)?
            || !read.history_head_accepted(&target_id, target.binding)?
        {
            return Ok(Some(None));
        }
        let need = crate::node::history_stream::KeyBodyNeed {
            head: source_head,
            seq: notice.seq,
            hash: notice.hash,
            recipient: notice.recipient,
            authorization,
            target: crate::node::history_stream::HeadHint {
                author: notice.author,
                head: target.id(),
                size: target.root.leaves,
            },
        };
        Ok(Some(
            read.history_key_body_owed(need, self.me())?.then_some(need),
        ))
    }

    /// Source validation has already consumed the shared verifier envelope. This checks the
    /// current room/admission boundary again before starting one unpublished index operation.
    pub(crate) fn prepare_history_begin(
        &self,
        store: &Store,
        entry: &Entry,
        validated: &governance::ValidatedSparseEntry,
    ) -> Result<PendingHistoryBegin> {
        if self.post_pending() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        if self.poisoned {
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
        if entry.entry_hash() != validated.entry_hash()
            || entry.header_wire() != validated.included().header().entry().header_wire()
        {
            return Err(Error::MalformedBundle(
                "sparse source differs from validation",
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
                        conflicting: validated.included().header().entry().clone(),
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
                    sealed,
                    invalid,
                    kept,
                }
            }
        } else if read.history_obligation_capacity() < 2 {
            HistoryBeginAction::Busy
        } else {
            HistoryBeginAction::Start
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
        }
        if completed.poison {
            if let Err(error) = &completed.result {
                self.poison(error);
            }
        }
        completed.result
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
        if let Some((revision, newest)) = completed.order {
            self.dag.set_order_revision(revision, newest);
        }
        completed.result
    }

    pub(crate) fn history_write_released(&mut self, store: &Store) -> Result<()> {
        self.flush_available(store)
    }

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
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.require_history_source_boundary(entry)?;
        entry.verify_payload_binding()?;
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
        let late = read.child_after(&hash, None)?.is_some();
        drop(read);
        Ok(PendingHistorySource {
            room: self.channel_id,
            sek: self.sek.reader(),
            authors: self.authors.clone(),
            creator: self.genesis.creator_pubkey().fingerprint(),
            me: self.me(),
            hash,
            log,
            request,
            late,
        })
    }

    pub(crate) fn install_history_source(
        &mut self,
        entry: &Entry,
        completed: &CommittedHistorySource,
    ) -> Result<()> {
        if entry.payload.is_none()
            && entry
                .skeleton
                .v2
                .as_ref()
                .is_some_and(|v| v.kind == crate::log::history::SignedEntryKind::KeyPackage)
        {
            self.note_key_body_debt();
        }
        // Advance the in-memory mirror only after this path's Batch commits. Unlike the ordinary
        // publication paths, a sparse history caller does not poison the room on commit failure.
        if completed.current_advanced {
            self.note_committed_consent(entry)?;
        }
        self.entries.committed();
        self.next_log_id = completed.next_log;
        Ok(())
    }

    /// The exact request that owns an unfinished sparse-history publication, if any.
    pub(crate) fn history_publication_request(&self, store: &Store) -> Result<Option<[u8; 16]>> {
        Ok(self.history_read(store)?.sparse_publication_request())
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
    pub(crate) fn role_owed(&self) -> std::sync::Arc<super::role_owed::RoleOwed> {
        std::sync::Arc::clone(&self.role_owed)
    }

    /// Keep the exact author runnable after a committed change; the inventory worker
    /// resolves and authenticates the signed role head separately.
    pub(crate) fn note_role_progress(&self, author: Digest32, seq: u64) {
        if !self.is_member(&author) {
            self.role_owed.clear(author);
            return;
        }
        if author != self.me() && seq != 0 && self.role_cuts.get(&author).copied() == Some(seq) {
            self.role_owed.mark_dirty(author);
        }
    }

    pub(super) fn note_contiguous_advance(
        &mut self,
        author: Digest32,
        progress: entry_store::sparse::ContiguousAdvance,
    ) -> Result<()> {
        if let Some(state) = progress.state {
            let was_member = self.is_member(&author);
            self.dag.restore_contiguous_author(author, &state)?;
            if !was_member && self.is_member(&author) {
                self.key_member_became_current(author);
            }
            self.role_cuts.insert(author, state.seq);
            self.note_role_progress(author, state.seq);
        }
        if progress.more {
            self.sparse_contiguous_pending.insert(author);
        } else {
            self.sparse_contiguous_pending.remove(&author);
        }
        Ok(())
    }
}
