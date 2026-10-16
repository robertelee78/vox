//! Bounded access to authenticated-history state. Callers acquire the shared worker/buffer
//! envelope before these methods; every pinned store read is dropped before network I/O.

use super::*;
use crate::log::history::{ControlContext, Descriptor, LogScope, SignedHead, TreeBinding};
use crate::node::store::Batch;

/// Exact signed header and the length bound governing payload continuations.
pub(crate) struct HistoryHeader {
    pub wire: Vec<u8>,
    pub payload_len: u64,
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

impl ChannelState {
    pub(crate) fn uses_sparse_history(&self, store: &Store) -> Result<bool> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        Ok(self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .sparse_enabled())
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
        if self.poisoned {
            return Err(self.save_failure());
        }
        let mut batch = store.batch()?;
        let mut index = self
            .entries
            .write(&mut batch, &self.sek, &self.channel_id)?;
        let result = operation(&mut index)?;
        index.seal()?;
        batch.commit()?;
        self.entries.committed();
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
                    payload_len: entry.skeleton.payload_len,
                })
            })
            .transpose()
    }

    pub(crate) fn history_tree_range(
        &self,
        store: &Store,
        binding: TreeBinding,
        start: u64,
        leaves: u64,
    ) -> Result<Option<Descriptor>> {
        self.history_read(store)?
            .history_range(binding, start, leaves)
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

    /// Source validation has already consumed the shared verifier envelope. This checks the
    /// current room/admission boundary again before starting one unpublished index operation.
    pub(crate) fn begin_history_source(
        &mut self,
        store: &Store,
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
                local_id: self.me(),
            },
        )?;
        Ok(HistorySourceStart::Started)
    }

    /// One bounded preparation quantum. A true result still leaves roots unpublished until
    /// commit_history_source records both the source and its governance work atomically.
    pub(crate) fn advance_history_source(&self, store: &Store) -> Result<bool> {
        self.entries
            .advance_sparse_publication(store, &self.sek, &self.channel_id)
    }

    pub(crate) fn commit_history_source(
        &mut self,
        store: &Store,
        entry: &Entry,
        now: crate::time::Ms,
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
        let mut batch = store.batch()?;
        on_publish(&mut batch)?;
        let mut index = self
            .entries
            .write(&mut batch, &self.sek, &self.channel_id)?;
        index.publish_promotion()?;
        index.seal()?;
        let first_seen = seal_segment(
            &self.sek,
            SegmentKind::Index,
            log,
            &first_seen_bytes(now.get(), false),
        )?;
        batch.put_segment(&self.channel_id, SegmentKind::Index, log, &first_seen)?;
        // Only source/causal facts are observed here. Presence, private floors, keys and
        // rendering wait for semantic completion, so source validation cannot grant effects.
        governance::accepted_into(
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
        batch.commit()?;
        self.entries.committed();
        self.next_log_id = log
            .checked_add(1)
            .ok_or(Error::MalformedAtRest("log allocator exhausted"))?;
        self.governance_ready = false;
        Ok(())
    }

    /// Cleanup is resumable and does not turn source storage into a user-visible admission.
    pub(crate) fn cleanup_history_source(&mut self, store: &Store) -> Result<bool> {
        let done = self
            .entries
            .cleanup_publication(store, &self.sek, &self.channel_id)?;
        if done {
            let read = self.history_read(store)?;
            self.dag.set_order_revision(
                read.order_revision(),
                read.order_previous(None)?.map(|(clock, _)| clock),
            );
        }
        Ok(done)
    }

    /// A retired request may roll back only its own unpublished roots, or finish only its
    /// own post-switch cleanup. The room lock covers this ownership check and transaction.
    pub(crate) fn cleanup_history_source_owned(
        &mut self,
        store: &Store,
        request: [u8; 16],
    ) -> Result<bool> {
        if self.history_read(store)?.sparse_publication_request() != Some(request) {
            return Ok(true);
        }
        self.cleanup_history_source(store)
    }

    /// One local retirement slice. Another request's publication must finish first; it is
    /// never rolled back merely to reclaim this request's verifier checkpoints.
    pub(crate) fn cleanup_history_verifiers(
        &self,
        store: &Store,
        request: [u8; 16],
        after: Option<[u8; 64]>,
    ) -> Result<(bool, Option<[u8; 64]>)> {
        if self.history_publication_busy(store)? {
            return Ok((false, after));
        }
        let mut batch = store.batch()?;
        let mut index = self
            .entries
            .write(&mut batch, &self.sek, &self.channel_id)?;
        let (done, next, changed) = index.cleanup_history_verifiers(request, after)?;
        if changed {
            index.seal()?;
            batch.commit()?;
            self.entries.committed();
        }
        Ok((done, next))
    }
}

/// Created only after the signed prior-control closure and the typed handler finish. The
/// marker means semantic dispatch completed; encrypted key installation stays independent.
pub(super) struct FinishedHistoryEffect {
    hash: Digest32,
}
impl FinishedHistoryEffect {
    pub(super) fn entry_hash(&self) -> Digest32 {
        self.hash
    }
}

#[derive(Clone, Copy)]
pub(crate) struct HistoryEffectCursor {
    hash: Digest32,
    next: usize,
}
impl HistoryEffectCursor {
    pub(crate) fn new(hash: Digest32) -> Self {
        Self { hash, next: 0 }
    }
}

pub(crate) enum HistoryEffectProgress {
    Progress,
    ControlPending {
        head: Digest32,
        through: u64,
    },
    GovernancePending,
    CheckpointPending {
        author: Digest32,
        seq: u64,
        hash: Digest32,
    },
    Complete {
        rendered: bool,
    },
    Busy,
}

impl ChannelState {
    /// One signed-context coordinate per call. The caller retains only (hash,next), never
    /// a full context/map, and holds the shared read/verification envelope for this turn.
    pub(crate) fn advance_history_effect(
        &mut self,
        store: &Store,
        cursor: &mut HistoryEffectCursor,
        now: crate::time::Ms,
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
        if input.history_effect_finished(hash)? {
            return Ok(HistoryEffectProgress::Complete { rendered: false });
        }
        let header = input
            .history_object(entry_store::sparse::ObjectKind::Header, hash)?
            .map(|wire| Entry::from_wire(&wire))
            .transpose()?
            .ok_or(Error::MalformedAtRest(
                "pending history source header missing",
            ))?;
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
            if !input
                .history_position_header(&entry.skeleton.author_id, checkpoint.seq)?
                .is_some_and(|named| named.entry_hash() == checkpoint.entry_hash)
            {
                return Ok(HistoryEffectProgress::CheckpointPending {
                    author: entry.skeleton.author_id,
                    seq: checkpoint.seq,
                    hash: checkpoint.entry_hash,
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
        let mut batch = store.batch()?;
        // A changed grant is an ordinary cancellation before projection/index mutation.
        // The held Batch serializes trust writes through the final publication.
        check_binding(&batch)?;
        let applied = (|| -> Result<HistoryEffectProgress> {
            let finished = FinishedHistoryEffect { hash: *hash };
            let mut index = self
                .entries
                .write(&mut batch, &self.sek, &self.channel_id)?;
            index.finish_history_effect(&entry, &finished)?;
            index.seal()?;
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
                self.observe_governance_into(store, &mut batch, &entry, log)?;
            }
            let mut expired = Vec::new();
            let mut rows = Vec::new();
            if kind == SignedEntryKind::Content {
                if let Some(payload) = &entry.payload {
                    self.track_body_into(&mut batch, *hash, log, now.get())?;
                    if let Some(row) = self.render_content_into(
                        &mut batch,
                        entry.skeleton.author_id,
                        *hash,
                        payload,
                        now.get(),
                        &mut expired,
                    )? {
                        rows.push(row);
                    }
                }
            }
            self.queue_receivers(&mut batch)?;
            self.queue_private_generations(&mut batch)?;
            on_admitted(&mut batch, *hash)?;
            batch.commit()?;
            self.entries.committed();
            self.key_packages.published(self.next_log_id);
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
            Ok(HistoryEffectProgress::Complete { rendered })
        })();
        if let Err(error) = &applied {
            self.poison(error);
        }
        applied
    }
}

impl ChannelState {
    /// One real Feed successor, after its semantic publication. The actor may schedule
    /// another bounded turn only when this reports progress; sparse holes stop immediately.
    pub(crate) fn advance_history_contiguous(
        &mut self,
        store: &Store,
        author: &Digest32,
    ) -> Result<bool> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if self.history_publication_busy(store)? {
            return Ok(false);
        }
        let mut batch = store.batch()?;
        let mut index = self
            .entries
            .write(&mut batch, &self.sek, &self.channel_id)?;
        let Some(state) = index.advance_sparse_contiguous(author)? else {
            return Ok(false);
        };
        index.seal()?;
        batch.commit()?;
        self.entries.committed();
        if let Err(error) = self.dag.restore_contiguous_author(*author, &state) {
            self.poison(&error);
            return Err(error);
        }
        Ok(true)
    }
}

impl ChannelState {
    /// Refill an exact missing body after typed validation, without changing its signed
    /// identity. A large-record envelope owns `entry` through this transaction and rendering.
    pub(crate) fn refill_history_body(
        &mut self,
        store: &Store,
        entry: &Entry,
        body: &governance::TypedSparseBody,
        now: crate::time::Ms,
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
        if settled {
            match self.checked_governance(store, now.get()) {
                Ok(view) => drop(view),
                Err(error) if governance::refreshing(&error) => {
                    return Ok(HistoryEffectProgress::GovernancePending)
                }
                Err(error) => return Err(error),
            }
        }
        let mut batch = store.batch()?;
        // A changed grant is an ordinary cancellation before projection/index mutation.
        // The held Batch serializes trust writes through the final publication.
        check_binding(&batch)?;
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
            if settled && kind == SignedEntryKind::Content {
                self.track_body_into(&mut batch, hash, log, now.get())?;
                if let Some(row) = self.render_content_into(
                    &mut batch,
                    entry.skeleton.author_id,
                    hash,
                    entry
                        .payload
                        .as_deref()
                        .ok_or(Error::MalformedBundle("refill body vanished"))?,
                    now.get(),
                    &mut expired,
                )? {
                    rows.push(row);
                }
                self.queue_receivers(&mut batch)?;
                self.queue_private_generations(&mut batch)?;
            }
            if settled {
                on_admitted(&mut batch, hash)?;
            }
            batch.commit()?;
            self.entries.committed();
            if settled && kind == SignedEntryKind::KeyPackage && key_package_for(entry, &self.me())
            {
                self.key_packages.published(self.next_log_id);
                self.key_packages.note(entry.skeleton.author_id, log)?;
            }
            self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let rendered = !rows.is_empty();
            self.place_committed(store, rows, &expired)?;
            Ok(HistoryEffectProgress::Complete { rendered })
        })();
        if let Err(error) = &applied {
            self.poison(error);
        }
        applied
    }
}
