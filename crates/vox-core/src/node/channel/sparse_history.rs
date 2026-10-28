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

impl ChannelState {
    /// One cursor per turn; membership is checked under the same room guard that
    /// owns the write, so a stale departure observation cannot erase a rejoin.
    pub(crate) fn advance_key_provider_prune(&mut self, store: &Store) -> Result<bool> {
        if self.role_owed.take_key_provider_prune() {
            self.key_provider_prune_pending = true;
            self.key_provider_prune_after = None;
        }
        if !self.key_provider_prune_pending {
            return Ok(false);
        }
        if let Some(wait) = self.key_provider_prune_wait.as_ref() {
            if !wait.ready.load(std::sync::atomic::Ordering::Acquire) {
                return Ok(false);
            }
            self.key_provider_prune_wait = None;
        }
        let wake = self.history_publication_wake();
        let read = self.history_read(store)?;
        if read.publication_busy() {
            drop(read);
            let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let signal = Arc::clone(&ready);
            let owner = Arc::clone(&self.role_owed);
            let local = self.me();
            let task = tokio::spawn(async move {
                wake.await;
                signal.store(true, std::sync::atomic::Ordering::Release);
                owner.mark_key_provider_prune(local);
            });
            self.key_provider_prune_wait = Some(KeyProviderPruneWait { ready, task });
            return Ok(false);
        }
        let next = read.key_provider_cursor_after(self.key_provider_prune_after)?;
        drop(read);
        let Some(peer) = next else {
            self.key_provider_prune_pending = false;
            self.key_provider_prune_after = None;
            return Ok(false);
        };
        if !self.is_member(&peer) {
            self.history_write(store, |index| index.forget_key_provider_cursor(peer))?;
        }
        self.key_provider_prune_after = Some(peer);
        Ok(true)
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

    /// Persist one exact refusal before the flow treats it as settled. Repeating the same
    /// decision is write-free; a successor replaces it under the same real relationship key.
    pub(crate) fn remember_history_decline(
        &self,
        store: &Store,
        peer: Digest32,
        author: Digest32,
        head: Digest32,
        authorization: (Digest32, Digest32, bool),
        committed: &std::sync::atomic::AtomicBool,
    ) -> Result<HistoryDeclineResult> {
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
        let room = self.channel_id();
        let instance = self.history_instance(store)?;
        let epoch = self.epoch();
        // The trust nonce read and refusal replacement share one store transaction. If a trust
        // save commits first, this old flow is rejected here. If this transaction commits first,
        // the later trust nonce makes the recorded generation stale. Cancellation after either
        // commit cannot relabel the refusal because no current generation is read outside it.
        let mut batch = store.batch()?;
        let current = crate::node::history_stream::authorization_generation_in(
            &batch, node, room, instance, epoch,
        )?;
        if current != expected_authorization {
            return Ok(HistoryDeclineResult::AuthorizationChanged { current });
        }
        let mut index = self.entries.write(&mut batch, &self.sek, &room)?;
        let prior = if metadata {
            index.history_declined_metadata(&peer, &author)?
        } else {
            index.history_declined_head(&peer, &author)?
        };
        if prior
            == Some((
                head,
                expected_authorization,
                peer_incarnation,
                author_incarnation,
            ))
        {
            return Ok(HistoryDeclineResult::Stored {
                remembered: false,
                current,
            });
        }
        if metadata {
            index.keep_history_declined_metadata(
                peer,
                author,
                head,
                expected_authorization,
                peer_incarnation,
                author_incarnation,
            )?;
        } else {
            index.keep_history_declined_head(
                peer,
                author,
                head,
                expected_authorization,
                peer_incarnation,
                author_incarnation,
            )?;
        }
        index.seal()?;
        batch.commit()?;
        self.entries.committed();
        committed.store(true, std::sync::atomic::Ordering::Release);
        Ok(HistoryDeclineResult::Stored {
            remembered: true,
            current,
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

    /// Commit only the captured cursor owner under the same batch as authority revalidation.
    /// A superseded Flow must never advance the current provider cursor.
    pub(crate) fn advance_key_provider_cursor(
        &self,
        store: &Store,
        provider: Digest32,
        node: Digest32,
        authorization: Digest32,
        expected: Option<entry_store::sparse::KeyProviderCursor>,
        next: entry_store::sparse::KeyProviderCursor,
    ) -> Result<bool> {
        if node != self.me()
            || !self.is_member(&node)
            || !self.is_member(&provider)
            || self.history_inventory_incarnation(&provider) != Some(next.peer_incarnation)
            || next.authorization != authorization
        {
            return Ok(false);
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
        let instance = self.history_instance(store)?;
        let mut batch = store.batch()?;
        if crate::node::history_stream::authorization_generation_in(
            &batch,
            node,
            self.channel_id,
            instance,
            self.epoch,
        )? != authorization
        {
            return Ok(false);
        }
        let mut index = self
            .entries
            .write(&mut batch, &self.sek, &self.channel_id)?;
        if index.key_provider_cursor(&provider)? != expected {
            return Ok(false);
        }
        index.keep_key_provider_cursor(provider, next)?;
        index.seal()?;
        batch.commit()?;
        self.entries.committed();
        Ok(true)
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

    fn require_history_source_boundary(&self, entry: &Entry) -> Result<()> {
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

    /// Safety-narrowing evidence about this node's own signed feed must survive a crash
    /// before later actor maintenance has written the recovery fence.
    pub(crate) fn history_write_own_head_tracked<T>(
        &self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        operation: impl FnOnce(&mut entry_store::Write<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        let result = self.history_write_classified(store, true, operation)?;
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

/// A retryable scheduling result. Busy never mutates a sender, poisons a room or loses the
/// caller's request; the actor retains and retries that request at its next eligible turn.
pub(crate) enum HistorySourceStart {
    Started,
    Duplicate,
    Busy,
}

impl ChannelState {
    pub(crate) fn history_publication_busy(&self, store: &Store) -> Result<bool> {
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
    pub(crate) fn begin_history_source(
        &mut self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        request: [u8; 16],
        entry: &Entry,
        validated: &governance::ValidatedSparseEntry,
        now: crate::time::Ms,
    ) -> Result<HistorySourceStart> {
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
        if read.publication_busy() {
            return Ok(HistorySourceStart::Busy);
        }
        if let Some(prior) =
            read.history_position_header(&entry.skeleton.author_id, entry.skeleton.seq)?
        {
            drop(read);
            if prior.entry_hash() == entry.entry_hash() {
                return Ok(HistorySourceStart::Duplicate);
            }
            let key = self
                .authors
                .get(&entry.skeleton.author_id)
                .ok_or(Error::MalformedGovernance("sparse source author missing"))?;
            // Existing signed witnesses remain retained even when their payloads are pruned.
            // Reuse the existing independently verified fork boundary; never frame an author
            // using an unverified conflicting header.
            self.dag
                .restore_fork(
                    crate::log::dag::ForkProof {
                        author_id: entry.skeleton.author_id,
                        seq: entry.skeleton.seq,
                        existing: prior,
                        conflicting: validated.included().header().entry().clone(),
                    },
                    key,
                )
                .map_err(|_| Error::MalformedBundle("sparse fork proof verification failed"))?;
            self.keep_forks(store)?;
            committed.store(true, std::sync::atomic::Ordering::Release);
            return Err(Error::MalformedGovernance(
                "author equivocated at a held sparse position",
            ));
        }
        if read.history_obligation_capacity() < 2 {
            return Ok(HistorySourceStart::Busy);
        }
        drop(read);
        self.entries.begin_sparse_publication(
            store,
            &self.sek,
            &self.channel_id,
            entry_store::SparsePublication {
                request,
                entry,
                validated,
                first_log: self.next_log_id,
                received_ms: now.get(),
                origin: self.genesis.body.created_ms,
            },
        )?;
        committed.store(true, std::sync::atomic::Ordering::Release);
        Ok(HistorySourceStart::Started)
    }

    /// One bounded preparation quantum. A true result still leaves roots unpublished until
    /// commit_history_source records both the source and its governance work atomically.
    pub(crate) fn advance_history_source(
        &self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
    ) -> Result<bool> {
        let ready = self
            .entries
            .advance_sparse_publication(store, &self.sek, &self.channel_id)?;
        committed.store(true, std::sync::atomic::Ordering::Release);
        Ok(ready)
    }

    pub(crate) fn commit_history_source(
        &mut self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        entry: &Entry,
        now: crate::time::Ms,
        received: &crate::node::store::ReceivedFlow,
        on_publish: impl FnOnce(&mut Batch<'_>) -> Result<()>,
    ) -> Result<()> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.require_history_source_boundary(entry)?;
        entry.verify_payload_binding()?;
        let read = self.history_read(store)?;
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
        let mut batch = store.received_batch(received)?;
        // Other received source entries remain owned by this flow and flush before ACK.
        on_publish(&mut batch)?;
        let mut index = self
            .entries
            .write(&mut batch, &self.sek, &self.channel_id)?;
        index.publish_promotion()?;
        index.publish_key_body_debt(entry, now.get())?;
        index.seal()?;
        let first_seen = seal_segment(
            &self.sek,
            SegmentKind::Index,
            log,
            &first_seen_bytes(now.get(), false),
        )?;
        batch.put_segment(&self.channel_id, SegmentKind::Index, log, &first_seen)?;
        // The governance index records authenticated single-writer current inputs at this
        // publication boundary. Presence side effects, private floors, keys and rendering still
        // wait for semantic completion.
        let accepted = governance::accepted_into(
            &mut batch,
            &self.entries,
            &self.sek,
            &self.channel_id,
            &self.authors,
            &self.genesis.creator_pubkey().fingerprint(),
            &self.me(),
            log,
            entry,
            late,
        )?;
        // Current consent/presence may become visible immediately at source publication, before
        // the later effect turn. A newer current input can also change the causal sequence or
        // historical revocation even when its displayed value stays the same. Keep those facts
        // durable; duplicate, superseded and other-recipient key headers do not qualify.
        // A consent target can be unknown at publication and become known through a later
        // derived admission without an intervening flush. Its already-authenticated current
        // input must therefore be durable before that admission can make it visible.
        let durable_current = accepted.current_advanced
            && matches!(
                GovEntry::body_bound_to(entry),
                Ok(GovBody::ConsentGrant(_) | GovBody::ConsentRevocation(_) | GovBody::Presence(_))
            );
        if durable_current {
            batch.ruled();
        }
        batch.commit()?;
        committed.store(true, std::sync::atomic::Ordering::Release);
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
        if accepted.current_advanced {
            self.note_committed_consent(entry)?;
        }
        self.entries.committed();
        self.next_log_id = log
            .checked_add(1)
            .ok_or(Error::MalformedAtRest("log allocator exhausted"))?;
        Ok(())
    }

    /// Cleanup is resumable and does not turn source storage into a user-visible admission.
    pub(crate) fn cleanup_history_source(
        &mut self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
    ) -> Result<bool> {
        let done = self
            .entries
            .cleanup_publication(store, &self.sek, &self.channel_id)?;
        committed.store(true, std::sync::atomic::Ordering::Release);
        if done {
            self.history_publication_changed.notify_waiters();
            let read = self.history_read(store)?;
            self.dag.set_order_revision(
                read.order_revision(),
                read.order_previous(None)?.map(|(clock, _)| clock),
            );
        }
        Ok(done)
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

    /// A retired request may roll back only its own unpublished roots, or finish only its
    /// own post-switch cleanup. The room lock covers this ownership check and transaction.
    pub(crate) fn cleanup_history_source_owned(
        &mut self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        request: [u8; 16],
    ) -> Result<bool> {
        if self.history_read(store)?.sparse_publication_request() != Some(request) {
            return Ok(true);
        }
        self.cleanup_history_source(store, committed)
    }

    /// One local retirement slice. Another request's publication must finish first; it is
    /// never rolled back merely to reclaim this request's verifier checkpoints.
    pub(crate) fn cleanup_history_verifiers(
        &self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        request: [u8; 16],
        after: Option<[u8; 64]>,
    ) -> Result<(bool, Option<[u8; 64]>)> {
        if self.history_publication_busy(store)? {
            return Ok((false, after));
        }
        let mut batch = store.batch()?;
        batch.derived();
        let mut index = self
            .entries
            .write(&mut batch, &self.sek, &self.channel_id)?;
        let (done, next, changed) = index.cleanup_history_verifiers(request, after)?;
        if changed {
            index.seal()?;
            batch.commit()?;
            committed.store(true, std::sync::atomic::Ordering::Release);
            self.entries.committed();
        }
        Ok((done, next))
    }
}

/// Transaction-scoped authority for the exact typed effect. Content constructs it only after
/// semantic admission. Non-Content may stage it before dispatch in the same Batch because its
/// handler requires the marker; no marker becomes durable unless that handler and the Batch both
/// succeed. A committed marker therefore always means semantic dispatch completed. Encrypted key
/// installation stays independent.
pub(super) struct FinishedHistoryEffect {
    hash: Digest32,
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
    hash: Digest32,
    next: usize,
    rendered: bool,
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
    Busy,
}

impl ChannelState {
    #[cfg(feature = "test-knobs")]
    fn record_fx29_content_outcome(&self, hash: &Digest32, accepted: bool) -> Result<()> {
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
    fn record_fx29_refill_outcome(&self, hash: &Digest32) -> Result<()> {
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

    /// One signed-context coordinate per call. The caller retains only (hash,next), never
    /// a full context/map, and holds the shared read/verification envelope for this turn.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn advance_history_effect(
        &mut self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        cursor: &mut HistoryEffectCursor,
        now: crate::time::Ms,
        body_expected: bool,
        historical: bool,
        received: &crate::node::store::ReceivedFlow,
        check_binding: impl FnOnce(&Batch<'_>) -> Result<()>,
        on_admitted: impl FnOnce(&mut Batch<'_>, Digest32) -> Result<()>,
    ) -> Result<HistoryEffectProgress> {
        use crate::log::history::SignedEntryKind;
        let hash = &cursor.hash;
        if self.poisoned {
            return Err(self.save_failure());
        }
        let input = self.history_read(store)?;
        if input.publication_busy() {
            return Ok(HistoryEffectProgress::Busy);
        }
        let finished = input.history_effect_finished(hash)?;
        let header = input
            .history_object(entry_store::sparse::ObjectKind::Header, hash)?
            .map(|wire| Entry::from_wire(&wire))
            .transpose()?
            .ok_or(Error::MalformedAtRest(
                "pending history source header missing",
            ))?;
        if finished {
            let author = header.skeleton.author_id;
            // Header/effect completion does not prove that an explicitly selected content body
            // was retained. Sparse history can settle the authenticated header first and fetch
            // its body in a later bounded turn. Keep that exact body staged until refill has run
            // it through the ordinary projection and durable-cache transaction.
            let refill_pending = body_expected
                && header
                    .skeleton
                    .v2
                    .as_ref()
                    .is_some_and(|v2| v2.kind == SignedEntryKind::Content)
                && input
                    .retention(hash)?
                    .is_none_or(|tracked| tracked.cache_id.is_none());
            drop(input);
            if !refill_pending {
                // A foreground flow may have settled this effect after the archive staged the
                // same header. The archive acknowledgement is still owed. Run its idempotent
                // callback under the current grant and commit it before reporting completion;
                // otherwise the demand can retain semantic debt forever despite the effect.
                let mut batch = store.batch()?;
                check_binding(&batch)?;
                on_admitted(&mut batch, *hash)?;
                batch.commit()?;
            }
            // Feed restoration is local accepted-header maintenance. Advance at most one
            // successor in this bounded turn, including while the exact staged body continues
            // through refill below.
            let contiguous_pending = self.advance_history_contiguous(store, committed, &author)?;
            if refill_pending {
                return Ok(HistoryEffectProgress::RefillPending { governance: false });
            }
            if contiguous_pending {
                return Ok(if body_expected {
                    HistoryEffectProgress::AdmittedProgress {
                        rendered: cursor.rendered,
                    }
                } else {
                    HistoryEffectProgress::Progress
                });
            }
            return Ok(HistoryEffectProgress::Complete {
                rendered: cursor.rendered,
            });
        }
        self.require_history_source_boundary(&header)?;
        let v2 = header
            .skeleton
            .v2
            .as_ref()
            .ok_or(Error::MalformedAtRest("pending history source is legacy"))?;
        let context = input
            .history_context(&v2.pre_context)?
            .ok_or(Error::MalformedAtRest("pending history context missing"))?;
        let end = cursor
            .next
            .saturating_add(64)
            .min(context.coordinates.len());
        if cursor.next > context.coordinates.len() {
            return Err(Error::MalformedAtRest(
                "history effect cursor outside context",
            ));
        }
        for coordinate in &context.coordinates[cursor.next..end] {
            let (head, control) = input
                .history_validated_header(&coordinate.author, coordinate.seq)?
                .ok_or(Error::MalformedAtRest("validated history control vanished"))?;
            if control.entry_hash() != coordinate.hash {
                return Err(Error::MalformedAtRest("history control binding changed"));
            }
            if !input.control_effects_complete(&head, coordinate.seq)? {
                return Ok(HistoryEffectProgress::ControlPending {
                    head,
                    through: coordinate.seq,
                });
            }
            cursor.next += 1;
        }
        if cursor.next < context.coordinates.len() {
            return Ok(HistoryEffectProgress::Progress);
        }
        drop(context);
        let entry = input.history_entry(hash)?.ok_or(Error::MalformedAtRest(
            "pending history body record missing",
        ))?;
        let log = input
            .log_id(hash)?
            .ok_or(Error::MalformedAtRest("pending history locator missing"))?;
        let kind = v2.kind;
        if kind == SignedEntryKind::Checkpoint {
            let checkpoint = entry
                .payload
                .as_deref()
                .map(crate::log::checkpoint::Checkpoint::from_payload)
                .transpose()?
                .flatten()
                .ok_or(Error::MalformedAtRest("checkpoint body missing"))?;
            if input
                .history_position_header(&entry.skeleton.author_id, checkpoint.seq)?
                .is_none_or(|named| named.entry_hash() != checkpoint.entry_hash)
            {
                return Ok(HistoryEffectProgress::CheckpointPending {
                    author: entry.skeleton.author_id,
                    seq: checkpoint.seq,
                });
            }
        }
        drop(input);
        if matches!(
            kind,
            SignedEntryKind::Governance | SignedEntryKind::StepPolicy
        ) {
            match governance::sparse_control_evaluation(
                store,
                &self.sek,
                &self.channel_id,
                &entry,
                now.get(),
            )? {
                governance::ControlEvaluation::Settled(receipt)
                    if receipt.entry_hash() == *hash => {}
                _ => return Ok(HistoryEffectProgress::GovernancePending),
            }
        }
        // Current trust/consent/Drive remain use-time checks. A historical closure is not a
        // replacement for the current checked view used by the existing render/key paths.
        match self.checked_governance(store, now.get()) {
            Ok(view) => drop(view),
            Err(error) if governance::refreshing(&error) => {
                return Ok(HistoryEffectProgress::GovernancePending)
            }
            Err(error) => return Err(error),
        }
        let mut batch = store.received_batch(received)?;
        // This completion can belong to a different flow than the one that published the
        // source. Keep the completion's own received debt: flushing it before a receipt also
        // carries the earlier source transaction to disk.
        batch.note_received_author(entry.skeleton.author_id)?;
        // A changed grant is an ordinary cancellation before projection/index mutation.
        // The held Batch serializes trust writes through the final publication.
        check_binding(&batch)?;
        let applied = (|| -> Result<(
            bool,
            bool,
            bool,
            bool,
            entry_store::sparse::ContiguousAdvance,
        )> {
            // Governance effects may update Presence, whose durable invariant requires this
            // exact sparse position to be semantically published. Publish the effect first in
            // the same transaction: any failure below rolls both changes back. Content remains
            // delayed until its selected body is actually admitted (role-complete receipts).
            #[cfg(feature = "test-knobs")]
            let publish_before_effect = kind != SignedEntryKind::Content
                && std::env::var("VOX_TEST_FX29_MUTANT").as_deref()
                    != Ok("finish-control-after-effect");
            #[cfg(not(feature = "test-knobs"))]
            let publish_before_effect = kind != SignedEntryKind::Content;
            if publish_before_effect {
                let finished = FinishedHistoryEffect { hash: *hash };
                let mut index = self
                    .entries
                    .write(&mut batch, &self.sek, &self.channel_id)?;
                let catalog_advanced = index.finish_history_effect(&entry, &finished, self.me())?;
                index.seal()?;
                if catalog_advanced {
                    // A peer can persist this catalog position after our notification. Its
                    // allocation must survive a crash before that position is advertised.
                    batch.ruled();
                }
            }
            session_projection::private_index::observe_public(
                &mut batch,
                &self.sek,
                &self.channel_id,
                &entry,
                self.epoch,
            )?;
            if matches!(
                kind,
                SignedEntryKind::Governance | SignedEntryKind::StepPolicy
            ) {
                // Current consent inputs were classified and, when they advanced, made durable
                // in their source publication. Their later effect is derived bookkeeping; in
                // particular a superseded older grant must not force a second full flush.
                // Other governance can change authority in this turn and stays conservative.
                if !matches!(
                    GovEntry::body_bound_to(&entry),
                    Ok(GovBody::ConsentGrant(_) | GovBody::ConsentRevocation(_))
                ) {
                    batch.ruled();
                }
                self.observe_governance_into(store, &mut batch, &entry, log)?;
            }
            // The source publication has already recorded the governance hash, so the
            // observer treats it as known. Publish presence at semantic settlement instead.
            let presence_after = if let Ok(GovBody::Presence(presence)) =
                GovEntry::body_bound_to(&entry)
            {
                let author = entry.skeleton.author_id;
                let old = self.presence.get(&author).copied();
                let mut state = old.unwrap_or(governance::Presence {
                    last: (entry.skeleton.seq, presence.body.here),
                    back: None,
                });
                if entry.skeleton.seq >= state.last.0 {
                    state.last = (entry.skeleton.seq, presence.body.here);
                }
                if presence.body.here
                    && state.back.is_none_or(|(seq, _)| seq < entry.skeleton.seq)
                {
                    state.back = Some((entry.skeleton.seq, entry.skeleton.claimed_ms));
                }
                if old.is_none_or(|old| old.last != state.last || old.back != state.back) {
                    let mut index = self.entries.write(&mut batch, &self.sek, &self.channel_id)?;
                    index.note_presence(author, state)?;
                    index.seal()?;
                    Some((author, state))
                } else {
                    None
                }
            } else {
                None
            };
            if kind == SignedEntryKind::KeyPackage && key_package_for(&entry, &self.me()) {
                batch.ruled();
            }
            let mut expired = Vec::new();
            let mut rows = Vec::new();
            if kind == SignedEntryKind::KeyPackage && entry.payload.is_some() {
                self.track_known_body_into(&mut batch, &entry, log)?;
            }
            let refill_pending =
                body_expected && kind == SignedEntryKind::Content && entry.payload.is_none();
            let mut projection_deferred = false;
            let mut body_unavailable = false;
            if kind == SignedEntryKind::Content {
                if let Some(payload) = &entry.payload {
                    #[cfg(feature = "test-knobs")]
                    if std::env::var("VOX_TEST_FX29_MUTANT").as_deref()
                        == Ok("track-content-through-settled-index")
                        && std::env::var_os(TEST_FX29_CONTENT_OUTCOME_ENV).is_some()
                        && entry.skeleton.author_id != self.me()
                    {
                        self.track_body_into(&mut batch, *hash, log, now.get())?;
                    } else {
                        self.track_known_body_into(&mut batch, &entry, log)?;
                    }
                    #[cfg(not(feature = "test-knobs"))]
                    self.track_known_body_into(&mut batch, &entry, log)?;
                    match self.render_content_into(
                        &mut batch,
                        entry.skeleton.author_id,
                        *hash,
                        payload,
                        Some(&entry),
                        now.get(),
                        historical,
                        &mut expired,
                    )? {
                        super::ContentProjection::Visible(row) => rows.push(row),
                        super::ContentProjection::Applied => {}
                        super::ContentProjection::Deferred => projection_deferred = true,
                        super::ContentProjection::Unavailable => body_unavailable = true,
                    }
                }
            }
            let staged_deferred = body_expected && projection_deferred;
            self.queue_receivers(&mut batch)?;
            self.queue_private_generations(&mut batch)?;
            let effect_complete = !(refill_pending || staged_deferred || body_unavailable);
            if effect_complete {
                // Role-complete means the requested body was semantically admitted, not merely
                // durable. `Deferred` and `Unavailable` deliberately leave both the effect
                // obligation and contiguous receipt cursor behind this position, including
                // across restart. A non-recipient package has no owed body and reaches this same
                // point after its authenticated header's semantic dispatch.
                if kind == SignedEntryKind::Content || !publish_before_effect {
                    let finished = FinishedHistoryEffect { hash: *hash };
                    let mut index = self
                        .entries
                        .write(&mut batch, &self.sek, &self.channel_id)?;
                    let catalog_advanced = index.finish_history_effect(&entry, &finished, self.me())?;
                    index.seal()?;
                    if catalog_advanced {
                        batch.ruled();
                    }
                }
                on_admitted(&mut batch, *hash)?;
            }
            // Settlement, obligation retirement, and the restart receipt cursor are one
            // transaction. A crash can expose all of them or none of them, never a settled
            // position whose receipt cursor still waits for an unrelated event.
            let contiguous = {
                let mut index = self
                    .entries
                    .write(&mut batch, &self.sek, &self.channel_id)?;
                let progress =
                    index.advance_sparse_contiguous(&entry.skeleton.author_id, &self.me())?;
                index.seal()?;
                progress
            };
            let was_member = self.is_member(&entry.skeleton.author_id);
            batch.commit()?;
            committed.store(true, std::sync::atomic::Ordering::Release);
            self.entries.committed();
            if let Some((author, state)) = presence_after {
                self.presence.insert(author, state);
            }
            // The settled-tip index and presence update are now durable in the same Batch.
            // A source-only entry cannot change membership, and a late earlier effect must
            // not move the applied tail backward past a later return/content statement.
            self.sparse_applied_tips
                .entry(entry.skeleton.author_id)
                .and_modify(|seq| *seq = (*seq).max(entry.skeleton.seq))
                .or_insert(entry.skeleton.seq);
            if !was_member && self.is_member(&entry.skeleton.author_id) {
                self.key_member_became_current(entry.skeleton.author_id);
            }
            self.key_packages.published(self.next_log_id);
            if kind == SignedEntryKind::KeyPackage && entry.payload.is_some() {
                self.note_key_body_acquired();
            }
            if kind == SignedEntryKind::KeyPackage
                && entry.payload.is_some()
                && key_package_for(&entry, &self.me())
            {
                self.key_packages.note(entry.skeleton.author_id, log)?;
            }
            self.private_controls_committed(store)?;
            self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let rendered = !rows.is_empty();
            self.place_committed(store, rows, &expired)?;
            self.settle_display_order(store)?;
            Ok((
                rendered,
                refill_pending,
                staged_deferred,
                body_unavailable,
                contiguous,
            ))
        })();
        let (rendered, refill_pending, projection_deferred, body_unavailable, contiguous) =
            match applied {
                Ok(outcome) => outcome,
                Err(error) => {
                    self.poison(&error);
                    #[cfg(feature = "test-knobs")]
                    if kind == SignedEntryKind::Content
                        && entry.payload.is_some()
                        && entry.skeleton.author_id != self.me()
                    {
                        self.record_fx29_content_outcome(hash, false)?;
                    }
                    return Err(error);
                }
            };
        self.note_role_progress(entry.skeleton.author_id, 0);
        let contiguous_more = contiguous.more;
        if let Err(error) = self.note_contiguous_advance(entry.skeleton.author_id, contiguous) {
            self.poison(&error);
            return Err(error);
        }
        #[cfg(feature = "test-knobs")]
        if kind == SignedEntryKind::Content
            && entry.payload.is_some()
            && entry.skeleton.author_id != self.me()
        {
            self.record_fx29_content_outcome(hash, true)?;
        }
        cursor.rendered |= rendered;
        if body_unavailable {
            return Ok(HistoryEffectProgress::BodyUnavailable);
        }
        if refill_pending || projection_deferred {
            return Ok(HistoryEffectProgress::RefillPending {
                governance: projection_deferred,
            });
        }
        if contiguous_more {
            return Ok(if body_expected {
                HistoryEffectProgress::AdmittedProgress {
                    rendered: cursor.rendered,
                }
            } else {
                HistoryEffectProgress::Progress
            });
        }
        Ok(HistoryEffectProgress::Complete {
            rendered: cursor.rendered,
        })
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

    /// One bounded page of role-complete successors after semantic publication. A full page
    /// remains explicitly pending; a real sparse hole parks until its own arrival wakes it.
    pub(crate) fn advance_history_contiguous(
        &mut self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        author: &Digest32,
    ) -> Result<bool> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if self.history_publication_busy(store)? {
            return Ok(self.sparse_contiguous_pending.contains(author));
        }
        let mut batch = store.batch()?;
        batch.derived();
        let mut index = self
            .entries
            .write(&mut batch, &self.sek, &self.channel_id)?;
        let progress = index.advance_sparse_contiguous(author, &self.me())?;
        if progress.state.is_none() && !progress.more {
            drop(index);
            self.note_contiguous_advance(*author, progress)?;
            return Ok(false);
        }
        index.seal()?;
        batch.commit()?;
        committed.store(true, std::sync::atomic::Ordering::Release);
        self.entries.committed();
        let more = progress.more;
        self.note_contiguous_advance(*author, progress)?;
        Ok(more)
    }

    fn note_contiguous_advance(
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

    /// Advance one author per room turn, rotating after the last author examined. The set is
    /// reconstructed from settled tips on restart, so continuation is durable without a timer.
    pub(crate) fn advance_pending_sparse_contiguous(&mut self, store: &Store) -> Result<bool> {
        use std::ops::Bound::{Excluded, Unbounded};
        let next = self
            .sparse_contiguous_after
            .and_then(|after| {
                self.sparse_contiguous_pending
                    .range((Excluded(after), Unbounded))
                    .next()
                    .copied()
            })
            .or_else(|| self.sparse_contiguous_pending.first().copied());
        let Some(author) = next else {
            self.sparse_contiguous_after = None;
            return Ok(false);
        };
        self.sparse_contiguous_after = Some(author);
        let committed = std::sync::atomic::AtomicBool::new(false);
        self.advance_history_contiguous(store, &committed, &author)?;
        Ok(!self.sparse_contiguous_pending.is_empty())
    }
}

impl ChannelState {
    /// Refill an exact missing body after typed validation, without changing its signed
    /// identity. A large-record envelope owns `entry` through this transaction and rendering.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn refill_history_body(
        &mut self,
        store: &Store,
        committed: &std::sync::atomic::AtomicBool,
        entry: &Entry,
        body: &governance::TypedSparseBody,
        now: crate::time::Ms,
        historical: bool,
        key_body: Option<crate::node::history_stream::KeyBodyNeed>,
        received: &crate::node::store::ReceivedFlow,
        check_binding: impl FnOnce(&Batch<'_>) -> Result<()>,
        on_admitted: impl FnOnce(&mut Batch<'_>, Digest32) -> Result<()>,
    ) -> Result<HistoryEffectProgress> {
        use crate::log::history::SignedEntryKind;
        if self.poisoned {
            return Err(self.save_failure());
        }
        if entry.payload.is_none()
            || body.entry_hash() != entry.entry_hash()
            || body.state() != governance::SparsePayloadState::Held
        {
            return Err(Error::MalformedBundle("history refill body token differs"));
        }
        entry.verify_payload_binding()?;
        self.require_history_source_boundary(entry)?;
        let input = self.history_read(store)?;
        if input.publication_busy() {
            return Ok(HistoryEffectProgress::Busy);
        }
        let (head, header) = input
            .history_validated_header(&entry.skeleton.author_id, entry.skeleton.seq)?
            .ok_or(Error::MalformedBundle(
                "history refill has no published source",
            ))?;
        if header.header_wire() != entry.header_wire() {
            return Err(Error::MalformedBundle("history refill header differs"));
        }
        let kind = entry
            .skeleton
            .v2
            .as_ref()
            .ok_or(Error::MalformedBundle("history refill is legacy"))?
            .kind;
        let hash = entry.entry_hash();
        let log = input
            .log_id(&hash)?
            .ok_or(Error::MalformedAtRest("history refill locator missing"))?;
        let settled = input.history_effect_finished(&hash)?;
        drop(input);
        if settled || key_body.is_some() {
            match self.checked_governance(store, now.get()) {
                Ok(view) => drop(view),
                Err(error) if governance::refreshing(&error) => {
                    return Ok(HistoryEffectProgress::GovernancePending)
                }
                Err(error) => return Err(error),
            }
        }
        let mut batch = store.received_batch(received)?;
        if settled {
            batch.note_received_author(entry.skeleton.author_id)?;
        }
        // A changed grant is an ordinary cancellation before projection/index mutation.
        // The held Batch serializes trust writes through the final publication.
        check_binding(&batch)?;
        if let Some(need) = key_body {
            if kind != SignedEntryKind::KeyPackage
                || need.head != head
                || need.seq != entry.skeleton.seq
                || need.target.author != entry.skeleton.author_id
                || need.hash != hash
            {
                return Err(Error::MalformedBundle("key body refill owner differs"));
            }
            let index = self
                .entries
                .write(&mut batch, &self.sek, &self.channel_id)?;
            if !index.history_key_body_pending(need)? {
                return Ok(HistoryEffectProgress::KeyBodyRetired);
            }
        }
        // Retention must follow the signed package age in the same transaction as its
        // refill. A body already past its current lifetime cannot revive an expired debt.
        if kind == SignedEntryKind::KeyPackage {
            self.track_known_body_into(&mut batch, entry, log)?;
            if key_body.is_some()
                && self.already_expired_entry(
                    Transaction::Batch(&batch),
                    entry,
                    entry.skeleton.claimed_ms,
                    now.get(),
                )?
            {
                return Ok(HistoryEffectProgress::KeyBodyRetired);
            }
        }
        // A received body (ADR-038 FX-30): flushed before this node acknowledges it, at once
        // when it is a key package or governance.
        if matches!(
            kind,
            SignedEntryKind::Governance | SignedEntryKind::StepPolicy
        ) || kind == SignedEntryKind::KeyPackage
        {
            batch.ruled();
        }
        let applied = (|| -> Result<HistoryEffectProgress> {
            let mut index = self
                .entries
                .write(&mut batch, &self.sek, &self.channel_id)?;
            index.put_committed(entry, log)?;

            if kind == SignedEntryKind::KeyPackage {
                index.finish_history_obligation(&entry_store::sparse::Obligation {
                    head,
                    kind: entry_store::sparse::ObligationKind::KeyBody,
                    object: hash,
                    author: entry.skeleton.author_id,
                    from: entry.skeleton.seq,
                    through: entry.skeleton.seq,
                })?;
            }
            index.seal()?;
            let mut expired = Vec::new();
            let mut rows = Vec::new();
            let mut deferred = false;
            let mut unavailable = false;
            if settled && kind == SignedEntryKind::Content {
                // Settlement can precede a selected Content body. Its sealed source time is the
                // retention origin; a later refill must not make an old body young again.
                #[cfg(feature = "test-knobs")]
                if std::env::var("VOX_TEST_FX29_MUTANT").as_deref()
                    == Ok("refill-content-with-current-time")
                    && std::env::var(TEST_FX29_REFILL_HASH_ENV).as_deref()
                        == Ok(crate::node::link::b32_encode(&hash).as_str())
                {
                    self.track_body_into(&mut batch, hash, log, now.get())?;
                } else {
                    self.track_known_body_into(&mut batch, entry, log)?;
                }
                #[cfg(not(feature = "test-knobs"))]
                self.track_known_body_into(&mut batch, entry, log)?;
                match self.render_content_into(
                    &mut batch,
                    entry.skeleton.author_id,
                    hash,
                    entry
                        .payload
                        .as_deref()
                        .ok_or(Error::MalformedBundle("refill body vanished"))?,
                    Some(entry),
                    now.get(),
                    historical,
                    &mut expired,
                )? {
                    super::ContentProjection::Visible(row) => rows.push(row),
                    super::ContentProjection::Applied => {}
                    super::ContentProjection::Deferred => deferred = true,
                    super::ContentProjection::Unavailable => unavailable = true,
                }
                self.queue_receivers(&mut batch)?;
                self.queue_private_generations(&mut batch)?;
            }
            if settled && !deferred && !unavailable {
                on_admitted(&mut batch, hash)?;
            }
            let contiguous = if settled && !deferred && !unavailable {
                let mut index = self
                    .entries
                    .write(&mut batch, &self.sek, &self.channel_id)?;
                let progress =
                    index.advance_sparse_contiguous(&entry.skeleton.author_id, &self.me())?;
                index.seal()?;
                Some(progress)
            } else {
                None
            };
            batch.commit()?;
            committed.store(true, std::sync::atomic::Ordering::Release);
            self.entries.committed();
            self.note_role_progress(entry.skeleton.author_id, 0);
            if settled && kind == SignedEntryKind::KeyPackage {
                self.note_key_body_acquired();
            }
            if settled && kind == SignedEntryKind::KeyPackage && key_package_for(entry, &self.me())
            {
                self.key_packages.published(self.next_log_id);
                self.key_packages.note(entry.skeleton.author_id, log)?;
            }
            self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let rendered = !rows.is_empty();
            self.place_committed(store, rows, &expired)?;
            let contiguous_more = contiguous.as_ref().is_some_and(|progress| progress.more);
            if let Some(progress) = contiguous {
                self.note_contiguous_advance(entry.skeleton.author_id, progress)?;
            }
            #[cfg(feature = "test-knobs")]
            if settled && kind == SignedEntryKind::Content && !deferred && !unavailable {
                self.record_fx29_refill_outcome(&hash)?;
            }
            Ok(if unavailable {
                HistoryEffectProgress::BodyUnavailable
            } else if deferred {
                HistoryEffectProgress::RefillPending { governance: true }
            } else if contiguous_more {
                if settled {
                    HistoryEffectProgress::AdmittedProgress { rendered }
                } else {
                    HistoryEffectProgress::Progress
                }
            } else if settled {
                HistoryEffectProgress::Complete { rendered }
            } else {
                HistoryEffectProgress::Progress
            })
        })();
        match applied {
            Ok(progress) => Ok(progress),
            Err(error) => {
                self.poison(&error);
                Err(error)
            }
        }
    }
}
