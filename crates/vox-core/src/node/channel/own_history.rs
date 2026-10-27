//! Own-feed recovery is a durable write fence, not authority supplied by an inventory hint.
use super::*;
use crate::log::history::{HistoryStep, LogScope, SignedHead, WorkBudget};

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

impl ChannelState {
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

    pub(crate) fn own_recovery_discovery_hint(
        &self,
        store: &Store,
    ) -> Result<Option<(Digest32, Digest32, u64)>> {
        if !self.own_behind {
            return Ok(None);
        }
        let read = self.history_read(store)?;
        let head = match &self.own_recovery {
            Recovery::Head(head) => Some(head.clone()),
            Recovery::UnknownBehind => read
                .sparse_author(&self.me(), LogScope::Public)?
                .and_then(|state| state.committed.or(state.observed))
                .map(|id| read.history_head(&id))
                .transpose()?
                .flatten(),
            Recovery::Fork => None,
        };
        if let Some(head) = head {
            self.checked_own_head(&head)?;
            return Ok(Some((self.me(), head.id(), head.root.leaves)));
        }
        Ok(None)
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
        if held >= head.root.leaves
            || !self.is_member(peer)
            || self.held_through(peer).is_none_or(|n| n < head.root.leaves)
        {
            return Ok(None);
        }
        let lo = held.checked_add(1).ok_or(Error::OwnHistoryBehind)?;
        let hi = head
            .root
            .leaves
            .min(lo.saturating_add(crate::log::history::MAX_PAGE_ENTRIES as u64 - 1));
        Ok(Some(OwnRecoveryPage {
            head: head.id(),
            lo,
            hi,
            donor_through: self.held_through(peer).ok_or(Error::OwnHistoryBehind)?,
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
        let segment = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_RECEIVERS,
            &receivers_bytes_with(&self.receivers, Some((&slot, &candidate))),
        )?;
        let mut batch = profile.store().batch()?;
        batch.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_RECEIVERS,
            &segment,
        )?;
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
        self.require_legacy_current(store)?;
        self.current_governance(store)?;
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
