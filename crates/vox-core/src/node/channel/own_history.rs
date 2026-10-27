//! Own-feed recovery is a durable write fence, not authority supplied by an inventory hint.
use super::*;
use crate::log::history::{
    inclusion_ranges, ContextSource, ControlContext, Descriptor, HistoryStep, LocalAppendBudget,
    LogScope, SignedHead, TreeBinding, TreeRange, TreeRangeSource, WorkBudget,
};

/// Serving-cache descriptors are only verification inputs here. They never become an
/// authored lookup fallback: the whole forest must reproduce the already committed signed root
/// before a separate canonical-index transaction can publish any missing subtree.
struct AppendForest<'a, 'read> {
    read: &'a entry_store::Read<'read>,
    target: &'a SignedHead,
    joined: Option<ControlContext>,
}
impl ContextSource for AppendForest<'_, '_> {
    fn context(&self, hash: &Digest32) -> Result<Option<ControlContext>> {
        if let Some(context) = self
            .joined
            .as_ref()
            .filter(|context| context.hash() == *hash)
        {
            return Ok(Some(context.clone()));
        }
        self.read.history_context(hash)
    }
}
impl TreeRangeSource for AppendForest<'_, '_> {
    fn range(&self, binding: TreeBinding, range: TreeRange) -> Result<Option<Descriptor>> {
        if binding != self.target.binding
            || range.start == 0
            || range.leaves == 0
            || range
                .start
                .checked_add(range.leaves - 1)
                .is_none_or(|end| end > self.target.root.leaves)
        {
            return Err(Error::MalformedAtRest("own append forest range binding"));
        }
        if let Some(descriptor) = self
            .read
            .history_range(binding, range.start, range.leaves)?
        {
            return Ok(Some(descriptor));
        }
        self.read
            .history_proof_range(&self.target.id(), binding, range.start, range.leaves)
    }
}

pub(super) enum Recovery {
    UnknownBehind,
    Head(SignedHead),
    Fork,
}
impl Recovery {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > crate::log::history::MAX_HEADER_BYTES + 64 {
            return Err(Error::MalformedAtRest("own history recovery marker size"));
        }
        // The originally shipped marker carried no target. It cannot mean sequence zero.
        if bytes == [1] {
            return Ok(Self::UnknownBehind);
        }
        let mut d = Decoder::new(bytes);
        if d.array()? != 3 || d.uint()? != 2 {
            return Err(Error::MalformedAtRest("own history recovery marker"));
        }
        let kind = d.uint()?;
        let wire = d.bytes()?;
        let recovery = match kind {
            0 if wire.is_empty() => Self::UnknownBehind,
            1 => Self::Head(SignedHead::from_wire(wire)?),
            2 if wire.is_empty() => Self::Fork,
            _ => return Err(Error::MalformedAtRest("own history recovery state")),
        };
        d.finish()?;
        Ok(recovery)
    }
    fn bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3).uint(2);
        match self {
            Self::UnknownBehind => {
                e.uint(0).bytes(&[]);
            }
            Self::Head(head) => {
                e.uint(1).bytes(&head.to_wire());
            }
            Self::Fork => {
                e.uint(2).bytes(&[]);
            }
        }
        e.finish()
    }
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UnknownBehind, Self::UnknownBehind) | (Self::Fork, Self::Fork) => true,
            (Self::Head(a), Self::Head(b)) => a.id() == b.id(),
            _ => false,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct OwnRecoveryPage {
    pub head: Digest32,
    pub lo: u64,
    pub hi: u64,
    pub donor_through: u64,
}

/// One bounded step toward certifying the actual content in the retained signed prefix.
/// Debts are parked until the exact body, key or authority changes; they are not a timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnReadability {
    Complete,
    Runnable,
    Waiting,
    BodyDebt {
        target: Digest32,
        seq: u64,
        entry_hash: Digest32,
    },
    KeyDebt {
        target: Digest32,
        seq: u64,
        entry_hash: Digest32,
        chain: u64,
        iteration: u64,
    },
}

/// A cursor is meaningful only for one exact authenticated recovery target. Legacy markers
/// have no cursor and start at one; a changed target is conservatively checked from one again.
struct ReadabilityCursor {
    target: Digest32,
    next: u64,
}
impl ReadabilityCursor {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 3 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest("own readability cursor"));
        }
        let target = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("own readability target"))?;
        let next = d.uint()?;
        d.finish()?;
        if next == 0 {
            return Err(Error::MalformedAtRest("own readability position"));
        }
        Ok(Self { target, next })
    }
    fn bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3).uint(1).bytes(&self.target).uint(self.next);
        e.finish()
    }
}

impl ChannelState {
    /// Check one bounded chunk of the exact own-author prefix. An already-settled receipt
    /// alone is not evidence that ciphertext from a later sender generation can be read.
    pub(crate) fn audit_own_readability(
        &mut self,
        store: &Store,
        now: crate::time::Ms,
    ) -> Result<OwnReadability> {
        if !self.own_behind {
            return Ok(OwnReadability::Waiting);
        }
        let Recovery::Head(target) = &self.own_recovery else {
            return Ok(OwnReadability::Waiting);
        };
        let target = target.clone();
        self.checked_own_head(&target)?;
        let read = self.history_read(store)?;
        if read.publication_busy() || !read.history_head_accepted(&target.id(), target.binding)? {
            return Ok(OwnReadability::Waiting);
        }
        let snapshot = store.snapshot()?;
        let stored = snapshot.get_segment_bounded(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_OWN_READABILITY,
            128,
        )?;
        let mut initialize = stored.is_none();
        let mut cursor = match stored {
            Some(segment) => ReadabilityCursor::parse(&open_segment(
                &self.sek,
                SegmentKind::KeyMaterial,
                SEG_OWN_READABILITY,
                &segment,
            )?)?,
            None => ReadabilityCursor {
                target: target.id(),
                next: 1,
            },
        };
        if cursor.target != target.id() {
            cursor = ReadabilityCursor {
                target: target.id(),
                next: 1,
            };
            initialize = true;
        }
        if cursor.next > target.root.leaves.saturating_add(1) {
            return Err(Error::MalformedAtRest(
                "own readability cursor exceeds target",
            ));
        }
        let start = cursor.next;
        let rendered = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?;
        if rendered.author_backfill_pending(&self.me())? {
            return Ok(OwnReadability::Waiting);
        }
        let mut outcome = OwnReadability::Runnable;
        let mut render_from = None;
        for _ in 0..RENDER_BACKFILL_ROWS_PER_TURN {
            if cursor.next > target.root.leaves {
                outcome = OwnReadability::Complete;
                break;
            }
            let seq = cursor.next;
            let Some((_source, header)) = read.history_validated_header(&self.me(), seq)? else {
                outcome = OwnReadability::Waiting;
                break;
            };
            let hash = header.entry_hash();
            let effect_finished = read.history_effect_finished(&hash)?;
            let kind = header
                .skeleton
                .v2
                .as_ref()
                .ok_or(Error::OwnHistoryBehind)?
                .kind;
            if kind == crate::log::history::SignedEntryKind::Content
                && rendered.fact(&hash)?.is_none()
            {
                let entry = read.history_entry(&hash)?;
                let payload = entry.as_ref().and_then(|entry| entry.payload.as_deref());
                let Some(payload) = payload else {
                    // The signed claim is sufficient only if both possible retention classes
                    // have expired; zero retention is unlimited and cannot discharge this debt.
                    let ms = header.skeleton.claimed_ms;
                    if effect_finished
                        && self.governance_display_current(now.get())
                        && expired_at(ms, now.get(), self.effective_retention())
                        && expired_at(ms, now.get(), self.effective_step_retention())
                    {
                        cursor.next += 1;
                        continue;
                    }
                    outcome = OwnReadability::BodyDebt {
                        target: target.id(),
                        seq,
                        entry_hash: hash,
                    };
                    break;
                };
                let message = GroupMessage::from_wire(payload)?;
                if message.header.author_id != self.me()
                    || message.header.epoch != header.skeleton.epoch
                {
                    return Err(Error::MalformedAtRest("own readability message binding"));
                }
                // Session payloads use the drive receiver and are accounted for by their own
                // already-settled effects; they are not ordinary sender-chain messages.
                if message.header.channel_id != drive_channel(&self.channel_id) {
                    if message.header.channel_id != self.channel_id {
                        return Err(Error::MalformedAtRest("own readability room binding"));
                    }
                    let slot = (self.me(), message.header.chain_id);
                    let plaintext = self
                        .receivers
                        .get(&slot)
                        .filter(|chain| chain.epoch() == message.header.epoch)
                        .and_then(|chain| chain.decrypt_retained(&message).ok())
                        .map(Zeroizing::new);
                    let Some(plaintext) = plaintext else {
                        outcome = OwnReadability::KeyDebt {
                            target: target.id(),
                            seq,
                            entry_hash: hash,
                            chain: message.header.chain_id,
                            iteration: message.header.iteration,
                        };
                        break;
                    };
                    if let Ok(Decoded::Text(content)) = crate::node::content::decode(&plaintext) {
                        let Some(entry) = entry.as_ref() else {
                            return Err(Error::MalformedAtRest("own readable entry missing"));
                        };
                        if !self.already_expired_entry(
                            Transaction::Snapshot(&snapshot),
                            entry,
                            content.created_millis,
                            now.get(),
                        )? {
                            // A prior opaque receipt may already have drained the ordinary
                            // cursor. Queue the exact now-readable position and recheck after
                            // the normal projection has committed its user-visible row.
                            render_from = Some(seq);
                            break;
                        }
                    }
                }
            }
            if !effect_finished {
                outcome = OwnReadability::Waiting;
                break;
            }
            cursor.next = cursor
                .next
                .checked_add(1)
                .ok_or(Error::MalformedAtRest("own readability overflow"))?;
        }
        if cursor.next > target.root.leaves {
            outcome = OwnReadability::Complete;
        }
        drop(rendered);
        drop(read);
        drop(snapshot);
        if cursor.next != start || initialize || render_from.is_some() {
            let mut batch = store.batch()?;
            self.check_own_recovery_marker_in(&batch)?;
            if let Some(seq) = render_from {
                let mut index = self
                    .entries
                    .write(&mut batch, &self.sek, &self.channel_id)?;
                index.queue_backfill(self.me(), Some(seq))?;
                index.seal()?;
            }
            batch.put_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_OWN_READABILITY,
                &seal_segment(
                    &self.sek,
                    SegmentKind::KeyMaterial,
                    SEG_OWN_READABILITY,
                    &cursor.bytes(),
                )?,
            )?;
            batch.commit()?;
            if render_from.is_some() {
                self.entries.committed();
            }
        }
        Ok(outcome)
    }

    /// An authenticated high observation fences the next append even before the actor has
    /// persisted its scheduling target. This read is the append's existing canonical view.
    pub(super) fn require_own_history_safe_in(&self, read: &entry_store::Read<'_>) -> Result<()> {
        self.require_own_history_current()?;
        if self.dag.is_frozen(&self.me()) {
            return Err(Error::OwnHistoryBehind);
        }
        let own = self.me();
        let through = self.dag.verified_head(&own);
        if read
            .history_settled_tip(&own)?
            .is_some_and(|tip| tip.skeleton.seq > through)
        {
            return Err(Error::OwnHistoryBehind);
        }
        if let Some(state) = read.sparse_author(&own, LogScope::Public)? {
            if state.observed_conflict.is_some() {
                return Err(Error::OwnHistoryBehind);
            }
            for id in [state.observed, state.committed].into_iter().flatten() {
                let head = read.history_head(&id)?.ok_or(Error::OwnHistoryBehind)?;
                if head.binding.author != own
                    || head.binding.room != self.channel_id
                    || head.binding.scope != LogScope::Public
                    || head.root.leaves > through
                {
                    return Err(Error::OwnHistoryBehind);
                }
            }
        }
        Ok(())
    }

    fn checked_own_head(&self, head: &SignedHead) -> Result<()> {
        if head.binding.room != self.channel_id
            || head.binding.author != self.me()
            || head.binding.scope != LogScope::Public
        {
            return Err(Error::MalformedAtRest("own recovery head binding"));
        }
        let key = self
            .authors
            .get(&self.me())
            .ok_or(Error::OwnHistoryBehind)?;
        match head.verify(key, &mut WorkBudget::default())? {
            HistoryStep::Complete(_) => Ok(()),
            HistoryStep::Yielded | HistoryStep::Progress(_) | HistoryStep::MissingContext(_) => {
                Err(Error::OwnHistoryBehind)
            }
        }
    }

    /// The highest retained signed observation is sticky. A lower new head never pays an
    /// older, higher debt; a restored boolean requires real retained evidence to resolve.
    fn own_recovery_evidence(&self, store: &Store) -> Result<Option<Recovery>> {
        if self.dag.is_frozen(&self.me()) {
            return Ok(Some(Recovery::Fork));
        }
        let read = self.history_read(store)?;
        if read.publication_busy() {
            return Err(Error::OwnHistoryBehind);
        }
        let own = self.me();
        let held = self.dag.verified_head(&own);
        let tip = read
            .history_settled_tip(&own)?
            .map_or(0, |e| e.skeleton.seq);
        let mut target = match &self.own_recovery {
            Recovery::Fork if self.own_behind => return Ok(Some(Recovery::Fork)),
            Recovery::Head(head) if self.own_behind => {
                self.checked_own_head(head)?;
                Some(head.clone())
            }
            _ => None,
        };
        if let Some(state) = read.sparse_author(&own, LogScope::Public)? {
            if let Some((a, b)) = state.observed_conflict {
                let a = read.history_head(&a)?.ok_or(Error::OwnHistoryBehind)?;
                let b = read.history_head(&b)?.ok_or(Error::OwnHistoryBehind)?;
                self.checked_own_head(&a)?;
                self.checked_own_head(&b)?;
                if a.root.leaves != b.root.leaves || a.id() == b.id() {
                    return Err(Error::MalformedAtRest("own conflicting head witnesses"));
                }
                return Ok(Some(Recovery::Fork));
            }
            for id in [state.observed, state.committed].into_iter().flatten() {
                let head = read.history_head(&id)?.ok_or(Error::OwnHistoryBehind)?;
                self.checked_own_head(&head)?;
                if let Some(old) = &target {
                    if old.root.leaves == head.root.leaves && old.id() != head.id() {
                        return Ok(Some(Recovery::Fork));
                    }
                }
                if target
                    .as_ref()
                    .is_none_or(|old| head.root.leaves > old.root.leaves)
                {
                    target = Some(head);
                }
            }
        }
        if let Some(head) = target {
            if head.root.leaves < tip {
                return Ok(Some(Recovery::UnknownBehind));
            }
            if self.own_behind || head.root.leaves > held {
                return Ok(Some(Recovery::Head(head)));
            }
        }
        Ok((self.own_behind || tip > held).then_some(Recovery::UnknownBehind))
    }

    pub(crate) fn own_history_conflict(&self, store: &Store) -> Result<bool> {
        Ok(self.own_recovery_evidence(store)?.is_some())
    }

    /// Whether the durable fence changed. Repeated observations are write-free.
    pub(crate) fn refresh_own_recovery(&mut self, store: &Store) -> Result<bool> {
        let Some(mut next) = self.own_recovery_evidence(store)? else {
            return Ok(false);
        };
        // Missing evidence cannot lower a previously authenticated target.
        if matches!(next, Recovery::UnknownBehind) && self.own_behind {
            return Ok(false);
        }
        if let (Recovery::Head(old), Recovery::Head(new)) = (&self.own_recovery, &next) {
            if self.own_behind && old.root.leaves > new.root.leaves {
                next = Recovery::Head(old.clone());
            }
        }
        if self.own_behind && self.own_recovery.same(&next) {
            return Ok(false);
        }
        store.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_OWN_BEHIND,
            &seal_segment(
                &self.sek,
                SegmentKind::KeyMaterial,
                SEG_OWN_BEHIND,
                &next.bytes(),
            )?,
        )?;
        self.own_behind = true;
        self.own_recovery = next;
        Ok(true)
    }

    pub(crate) fn own_recovery_key(&self, store: &Store) -> Result<Option<(Digest32, u64, bool)>> {
        if !self.own_behind {
            return Ok(None);
        }
        let read = self.history_read(store)?;
        let held = read
            .history_held_through(&self.me())
            .map_or(0, |(seq, _)| seq);
        match &self.own_recovery {
            Recovery::Head(head) => Ok(Some((
                head.id(),
                held,
                read.history_head_accepted(&head.id(), head.binding)?,
            ))),
            Recovery::UnknownBehind => Ok(Some(([0; 32], held, false))),
            Recovery::Fork => Ok(None),
        }
    }

    /// Derive one exact local verification root at ordinary foreground admission. No scalar
    /// inbox insertion is required, and a donor's role receipt cannot suppress local proof debt.
    /// A durable exact metadata refusal remains parked until its real authority/incarnation
    /// changes. Old whole-head refusals still suppress ordinary/body inventory; they cannot
    /// assert that this new exact metadata-verification operation was ever attempted.
    pub(crate) fn own_recovery_discovery_hint(
        &self,
        store: &Store,
        peer: &Digest32,
        authorization: Digest32,
    ) -> Result<Option<(Digest32, Digest32, u64)>> {
        if !self.own_behind || !self.is_member(peer) || self.dag.is_frozen(&self.me()) {
            return Ok(None);
        }
        let Recovery::Head(head) = &self.own_recovery else {
            return Ok(None);
        };
        self.checked_own_head(head)?;
        let read = self.history_read(store)?;
        if read
            .sparse_author(&self.me(), LogScope::Public)?
            .is_some_and(|state| state.observed_conflict.is_some())
            || read.history_head_accepted(&head.id(), head.binding)?
        {
            return Ok(None);
        }
        if let Some((refused, grant, peer_life, author_life)) =
            read.history_declined_metadata(peer, &self.me())?
        {
            if refused == head.id()
                && grant == authorization
                && self.history_inventory_incarnation(peer) == Some(peer_life)
                && self.history_author_inventory_incarnation(&self.me()) == Some(author_life)
            {
                return Ok(None);
            }
        }
        Ok(Some((self.me(), head.id(), head.root.leaves)))
    }

    pub(crate) fn own_recovery_page(
        &self,
        store: &Store,
        peer: &Digest32,
    ) -> Result<Option<OwnRecoveryPage>> {
        if !self.own_behind || self.dag.is_frozen(&self.me()) {
            return Ok(None);
        }
        let Recovery::Head(head) = &self.own_recovery else {
            return Ok(None);
        };
        self.checked_own_head(head)?;
        match self.own_recovery_evidence(store)? {
            Some(Recovery::Head(current)) if current.id() == head.id() => {}
            _ => return Ok(None),
        }
        let read = self.history_read(store)?;
        if read.publication_busy() || !read.history_head_accepted(&head.id(), head.binding)? {
            return Ok(None);
        }
        let held = read
            .history_held_through(&self.me())
            .map_or(0, |(seq, _)| seq);
        let donor_through = self.held_through(peer).unwrap_or(0);
        if held >= head.root.leaves || !self.is_member(peer) || donor_through <= held {
            return Ok(None);
        }
        let lo = held.checked_add(1).ok_or(Error::OwnHistoryBehind)?;
        let hi = head
            .root
            .leaves
            .min(donor_through)
            .min(lo.saturating_add(crate::log::history::MAX_PAGE_ENTRIES as u64 - 1));
        Ok(Some(OwnRecoveryPage {
            head: head.id(),
            lo,
            hi,
            donor_through,
        }))
    }

    /// Seed only a locally retained generation, using its backup live position plus its
    /// authenticated origin as the history floor. No remote key is minted or released.
    pub(crate) fn prepare_own_recovery_receiver(&mut self, profile: &Profile) -> Result<bool> {
        if !self.own_behind || !matches!(self.own_recovery, Recovery::Head(_)) {
            return Ok(false);
        }
        let me = self.me();
        let slot = (me, self.sender.chain_id());
        if self
            .receivers
            .get(&slot)
            .is_some_and(|chain| chain.recovers_own_sender(&self.sender))
        {
            return Ok(false);
        }
        if !self.origins.has(&self.channel_id, self.epoch, slot.1)
            || (!self.receivers.contains_key(&slot) && self.receivers.len() >= MAX_RECEIVER_CHAINS)
        {
            return Err(Error::OwnHistoryBehind);
        }
        let signer = profile.signer()?;
        let root = self.authors.get(&me).ok_or(Error::OwnHistoryBehind)?;
        let (iteration, key) = self.sender.current_position();
        let current = self.sender.skdm_for(signer, iteration, key)?;
        let live = ReceiverChain::from_skdm(&current, root, &self.channel_id, self.epoch)?;
        let origin =
            self.origins
                .full_history_skdm(signer, &self.channel_id, self.epoch, slot.1)?;
        let floor = ReceiverChain::from_skdm(&origin, root, &self.channel_id, self.epoch)?;
        let mut candidate = if let Some(existing) = self
            .receivers
            .get(&slot)
            .filter(|existing| existing.next_iteration() >= live.next_iteration())
        {
            let mut existing = ReceiverChain::from_state(&existing.to_state())?;
            existing.retain_history_release(&live)?;
            existing
        } else {
            live
        };
        candidate.retain_history_release(&floor)?;
        if !candidate.recovers_own_sender(&self.sender) {
            return Err(Error::OwnHistoryBehind);
        }
        let mut batch = profile.store().batch()?;
        let stored = receiver_overlay::put(
            &mut batch,
            &self.sek,
            &self.channel_id,
            &me,
            self.epoch,
            self.receiver_persistence.base,
            &candidate,
        )?;
        if let receiver_overlay::Put::Busy { changed } = stored {
            if changed {
                batch.commit()?;
            }
            return Err(Error::StreamRefused(receiver_overlay::CLEANUP_PENDING));
        }
        let mut index = self
            .entries
            .write(&mut batch, &self.sek, &self.channel_id)?;
        index.queue_backfill(me, Some(1))?;
        index.seal()?;
        batch.commit()?;
        self.entries.committed();
        self.receivers.insert(slot, candidate);
        Ok(true)
    }

    pub(super) fn require_own_recovery_complete(&self, store: &Store) -> Result<()> {
        if !self.own_behind || !self.is_member(&self.me()) {
            return Err(Error::OwnHistoryBehind);
        }
        let Recovery::Head(target) = &self.own_recovery else {
            return Err(Error::OwnHistoryBehind);
        };
        match self.own_recovery_evidence(store)? {
            Some(Recovery::Head(current)) if current.id() == target.id() => {}
            _ => return Err(Error::OwnHistoryBehind),
        }
        let read = self.history_read(store)?;
        let Some((through, _)) = read.history_held_through(&self.me()) else {
            return Err(Error::OwnHistoryBehind);
        };
        if through < target.root.leaves
            || !read.history_head_accepted(&target.id(), target.binding)?
            || read.history_range(target.binding, 1, target.root.leaves)? != Some(target.root)
        {
            return Err(Error::OwnHistoryBehind);
        }
        if self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?
            .author_backfill_pending(&self.me())?
        {
            return Err(Error::OwnHistoryBehind);
        }
        let snapshot = store.snapshot()?;
        let segment = snapshot
            .get_segment_bounded(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_OWN_READABILITY,
                128,
            )?
            .ok_or(Error::OwnHistoryBehind)?;
        let audit = ReadabilityCursor::parse(&open_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_OWN_READABILITY,
            &segment,
        )?)?;
        if audit.target != target.id() || audit.next != target.root.leaves.saturating_add(1) {
            return Err(Error::OwnHistoryBehind);
        }
        self.require_legacy_current(store)?;
        let governance = self.current_governance(store)?;
        let generation = match governance.presence_sender_generation(&self.me())? {
            Some(generation) => generation,
            // A creator starts settled at generation zero without appending Presence. Sparse
            // rotations publish Presence and the fresh sender atomically; absence is not an
            // invented generation for a joiner or a restored later sender.
            None if self.sender.chain_id() == 0
                && self.me() == self.genesis.creator_pubkey().fingerprint() =>
            {
                0
            }
            None => return Err(Error::OwnHistoryBehind),
        };
        if generation != self.sender.chain_id() {
            // Earlier code could count opaque own ciphertext as role-complete. That receipt
            // cannot certify keys for a generation minted after this backup. Recovery of those
            // keys remains separate owed work; never clear the fence on this old receipt alone.
            return Err(Error::OwnHistoryBehind);
        }
        Ok(())
    }

    pub(super) fn check_own_recovery_marker_in(
        &self,
        batch: &crate::node::store::Batch<'_>,
    ) -> Result<()> {
        let segment = batch
            .get_segment_bounded(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_OWN_BEHIND,
                crate::log::history::MAX_HEADER_BYTES + 64,
            )?
            .ok_or(Error::OwnHistoryBehind)?;
        let stored = Recovery::parse(&open_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_OWN_BEHIND,
            &segment,
        )?)?;
        if !self.own_behind || !self.own_recovery.same(&stored) {
            return Err(Error::OwnHistoryBehind);
        }
        Ok(())
    }

    /// Recover the bounded append frontier only after the own prefix is role-complete.
    /// This is mathematical preparation for the existing local append, not new head/source
    /// admission. Missing serving metadata keeps the exact recovery debt instead of poisoning
    /// a room whose restored canonical prefix legitimately lacks subtree indices.
    fn prepare_own_append_ranges(&mut self, store: &Store) -> Result<()> {
        let Recovery::Head(target) = &self.own_recovery else {
            return Err(Error::OwnHistoryBehind);
        };
        let target = target.clone();
        let read = self.history_read(store)?;
        if !read.history_head_committed(&target.id(), target.binding)? {
            return Err(Error::OwnHistoryBehind);
        }
        let next = target
            .root
            .leaves
            .checked_add(1)
            .ok_or(Error::OwnHistoryBehind)?;
        let coordinates = inclusion_ranges(next, next)?;
        let mut forest = Vec::with_capacity(coordinates.len());
        let mut source = AppendForest {
            read: &read,
            target: &target,
            joined: None,
        };
        let mut budget = LocalAppendBudget::new();
        for range in &coordinates {
            let descriptor = budget
                .range(&source, target.binding, *range)?
                .ok_or(Error::OwnHistoryBehind)?;
            if descriptor.leaves != range.leaves {
                return Err(Error::MalformedAtRest("own append forest span differs"));
            }
            forest.push((range.start, descriptor));
        }
        let Some(&(mut start, mut root)) = forest.first() else {
            return Err(Error::OwnHistoryBehind);
        };
        for &(left_start, left) in &forest[1..] {
            if left_start.checked_add(left.leaves) != Some(start) {
                return Err(Error::MalformedAtRest(
                    "own append forest is not contiguous",
                ));
            }
            match budget.join_ranges(target.binding, left, root, &source)? {
                HistoryStep::Complete((joined, context)) => {
                    root = joined;
                    start = left_start;
                    source.joined = Some(context);
                }
                HistoryStep::MissingContext(_) => return Err(Error::OwnHistoryBehind),
                _ => return Err(Error::SizeLimitExceeded("own append forest work quota")),
            }
        }
        if start != 1 || root != target.root {
            return Err(Error::MalformedAtRest(
                "own append forest differs from signed root",
            ));
        }
        let root_context = budget
            .context(&source, &root.frontier)?
            .ok_or(Error::OwnHistoryBehind)?;
        drop(source);
        drop(read);
        // Room serialization plus the current Computer fence are held by recovery's caller.
        // Recheck its exact durable marker in this same batch before making any index visible.
        let mut batch = store.batch()?;
        self.check_own_recovery_marker_in(&batch)?;
        let mut index = self
            .entries
            .write(&mut batch, &self.sek, &self.channel_id)?;
        index.keep_history_context(&root_context)?;
        for (start, descriptor) in forest {
            index.keep_history_range(target.binding, start, descriptor)?;
        }
        index.seal()?;
        batch.commit()?;
        self.entries.committed();
        Ok(())
    }

    /// The marker, signed return Presence and fresh sender/origins share the effects Batch.
    /// Ordinary append guards never observe a clear-first intermediate state.
    pub(crate) fn complete_own_recovery(
        &mut self,
        profile: &Profile,
        now: crate::time::Ms,
    ) -> Result<bool> {
        if !self.own_behind {
            return Ok(false);
        }
        self.require_own_recovery_complete(profile.store())?;
        self.prepare_own_append_ranges(profile.store())?;
        let me = self.me();
        let used = self.dag.verified_head(&me);
        let next_id = used
            .checked_add(2)
            .ok_or(Error::MalformedBundle("chain_id overflow"))?;
        if self.sender.chain_id() >= next_id {
            return Err(Error::OwnHistoryBehind);
        }
        let next = SenderChain::new(&self.channel_id, self.epoch, &me, next_id, now.get())?;
        self.rotate_sender_with_presence(profile, next, now.get(), false, false, true)?;
        Ok(true)
    }
}
