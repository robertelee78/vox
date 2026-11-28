//! Own-feed recovery is a durable write fence, not authority supplied by an inventory hint.
use super::pending_text::recovery::Ranges;
use super::*;
use crate::log::history::{
    inclusion_ranges, ContextSource, ControlContext, Descriptor, HistoryStep, LocalAppendBudget,
    LogScope, SignedHead, TreeBinding, TreeRange, TreeRangeSource, WorkBudget,
};

/// A separate identity-keyed scope survives the room's cryptographic purge.
fn continuity_scope(room: &Digest32, author: &Digest32) -> Digest32 {
    let mut input = b"vox/own-continuity-scope/v1".to_vec();
    input.extend_from_slice(room);
    input.extend_from_slice(author);
    sha256(&input)
}

pub(super) fn continuity_key(signer: &crate::atrest::vault::VaultRootSigner) -> Result<Sek> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, signer.self_seed());
    let mut key = Zeroizing::new([0u8; crate::atrest::sek::SEK_LEN]);
    hk.expand(b"vox/own-continuity-key/v1", key.as_mut())
        .map_err(|_| Error::AtRestUnlockFailed)?;
    Ok(Sek::from_bytes(key))
}

pub(super) struct Continuity {
    pub(super) head: SignedHead,
    pub(super) epoch: u64,
    pub(super) generation: u64,
    pub(super) genesis: crate::governance::genesis::Genesis,
}

impl Continuity {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 5 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest("own continuity marker"));
        }
        let head = SignedHead::from_wire(d.bytes()?)?;
        let epoch = d.uint()?;
        let generation = d.uint()?;
        let genesis = crate::governance::genesis::Genesis::from_wire(d.bytes()?)?;
        genesis.accept_for_channel(&head.binding.room)?;
        d.finish()?;
        Ok(Self {
            head,
            epoch,
            generation,
            genesis,
        })
    }

    fn bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(5)
            .uint(1)
            .bytes(&self.head.to_wire())
            .uint(self.epoch)
            .uint(self.generation)
            .bytes(&self.genesis.to_wire());
        e.finish()
    }
}

const CONTINUITY_MAX_BYTES: usize = crate::log::history::MAX_HEADER_BYTES
    + crate::hash::COMPOSITE_PUB_LEN
    + crate::hash::COMPOSITE_SIG_LEN
    + 1024;

pub(super) fn load_continuity(
    store: &Store,
    key: &Sek,
    room: &Digest32,
    author: &Digest32,
) -> Result<Option<Continuity>> {
    let scope = continuity_scope(room, author);
    store
        .snapshot()?
        .get_segment_bounded(&scope, SegmentKind::KeyMaterial, 0, CONTINUITY_MAX_BYTES)?
        .map(|segment| {
            let marker =
                Continuity::parse(&open_segment(key, SegmentKind::KeyMaterial, 0, &segment)?)?;
            if marker.head.binding.room != *room
                || marker.head.binding.author != *author
                || marker.head.binding.scope != LogScope::Public
            {
                return Err(Error::MalformedAtRest("own continuity binding"));
            }
            Ok(marker)
        })
        .transpose()
}

pub(super) fn save_continuity(
    batch: &mut crate::node::store::Batch<'_>,
    key: &Sek,
    head: &SignedHead,
    epoch: u64,
    generation: u64,
    genesis: &crate::governance::genesis::Genesis,
) -> Result<()> {
    genesis.accept_for_channel(&head.binding.room)?;
    let scope = continuity_scope(&head.binding.room, &head.binding.author);
    let previous = batch
        .get_segment_bounded(&scope, SegmentKind::KeyMaterial, 0, CONTINUITY_MAX_BYTES)?
        .map(|segment| {
            Continuity::parse(&open_segment(key, SegmentKind::KeyMaterial, 0, &segment)?)
        })
        .transpose()?;
    let (epoch, generation) = if let Some(previous) = previous {
        if previous.head.binding != head.binding
            || previous.genesis.body != genesis.body
            || previous.genesis.signature != genesis.signature
            || previous.head.root.leaves > head.root.leaves
            || (previous.head.root.leaves == head.root.leaves && previous.head.id() != head.id())
        {
            return Err(Error::OwnHistoryBehind);
        }
        (epoch, generation).max((previous.epoch, previous.generation))
    } else {
        (epoch, generation)
    };
    let marker = Continuity {
        head: head.clone(),
        epoch,
        generation,
        genesis: genesis.clone(),
    };
    let segment = seal_segment(key, SegmentKind::KeyMaterial, 0, &marker.bytes())?;
    batch.put_segment(&scope, SegmentKind::KeyMaterial, 0, &segment)?;
    batch.ruled();
    Ok(())
}

pub(crate) fn erase_continuity(
    batch: &mut crate::node::store::Batch<'_>,
    room: &Digest32,
    author: &Digest32,
) -> Result<()> {
    batch.purge_channel(&continuity_scope(room, author))?;
    Ok(())
}

/// Confirm an End with the creator key retained in the former member's checkpoint, and with
/// `erase` clear that checkpoint when it is confirmed.
pub(crate) fn confirm_creator_end(
    store: &Store,
    signer: &crate::atrest::vault::VaultRootSigner,
    room: &Digest32,
    supplied_genesis: Option<&crate::governance::genesis::Genesis>,
    withdrawals: &[crate::nat::withdraw::BoardWithdraw],
    now: u64,
    erase: bool,
) -> Result<bool> {
    let me = signer.fingerprint();
    let key = continuity_key(signer)?;
    let mut batch = store.batch()?;
    let marker = batch
        .get_segment_bounded(
            &continuity_scope(room, &me),
            SegmentKind::KeyMaterial,
            0,
            CONTINUITY_MAX_BYTES,
        )?
        .map(|segment| {
            let marker =
                Continuity::parse(&open_segment(&key, SegmentKind::KeyMaterial, 0, &segment)?)?;
            if marker.head.binding.room != *room
                || marker.head.binding.author != me
                || marker.head.binding.scope != LogScope::Public
            {
                return Err(Error::MalformedAtRest("own continuity binding"));
            }
            Ok(marker)
        })
        .transpose()?;
    let genesis = match marker.as_ref() {
        Some(marker) => &marker.genesis,
        None => match supplied_genesis {
            Some(genesis) => genesis,
            None => return Ok(false),
        },
    };
    genesis.accept_for_channel(room)?;
    let creator = genesis.creator_pubkey();
    #[cfg(feature = "test-knobs")]
    let first_only = crate::node::computer::fx28_mutant("end-first-withdrawal-only");
    #[cfg(not(feature = "test-knobs"))]
    let first_only = false;
    #[cfg(feature = "test-knobs")]
    let ignore_room = crate::node::computer::fx28_mutant("end-ignore-room");
    #[cfg(not(feature = "test-knobs"))]
    let ignore_room = false;
    #[cfg(feature = "test-knobs")]
    let ignore_future = crate::node::computer::fx28_mutant("end-ignore-future");
    #[cfg(not(feature = "test-knobs"))]
    let ignore_future = false;
    #[cfg(feature = "test-knobs")]
    let trust_delegated = crate::node::computer::fx28_mutant("end-trust-revoked-admin");
    #[cfg(not(feature = "test-knobs"))]
    let trust_delegated = false;
    let verified = withdrawals
        .iter()
        .take(if first_only { 1 } else { usize::MAX })
        .any(|withdrawal| {
            (ignore_room || withdrawal.channel_id == *room)
                && withdrawal.scope == crate::nat::withdraw::WithdrawScope::Room
                && (trust_delegated || withdrawal.author_id == creator.fingerprint())
                && marker
                    .as_ref()
                    .is_none_or(|marker| withdrawal.epoch == marker.epoch)
                && (ignore_future
                    || withdrawal.timestamp_ms
                        <= now.saturating_add(crate::nat::store::MAX_CLOCK_SKEW_MS))
                && (trust_delegated || withdrawal.verify(creator).is_ok())
        });
    #[cfg(feature = "test-knobs")]
    let keep_marker = crate::node::computer::fx28_mutant("end-keeps-checkpoint");
    #[cfg(not(feature = "test-knobs"))]
    let keep_marker = false;
    #[cfg(feature = "test-knobs")]
    let erase_without_evidence = crate::node::computer::fx28_mutant("end-erases-without-evidence");
    #[cfg(not(feature = "test-knobs"))]
    let erase_without_evidence = false;
    if erase && marker.is_some() && ((verified && !keep_marker) || erase_without_evidence) {
        erase_continuity(&mut batch, room, &me)?;
        batch.commit()?;
    }
    Ok(verified)
}
// A second signed boundary is needed when the responder's valid head is older than the
// retained one. It is a room-scoped recovery input and is erased with the room.
const SEG_OWN_RECOVERY_BOUNDARY: u64 = 26;
const SEG_OWN_UNKNOWN_HIGHER: u64 = 27;

/// Keep the proposer's unavailable classification until verified recovery completes.
pub(super) fn save_unknown_higher(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    header: &[u8],
) -> Result<()> {
    let segment = seal_segment(
        sek,
        SegmentKind::KeyMaterial,
        SEG_OWN_UNKNOWN_HIGHER,
        header,
    )?;
    batch.put_segment(
        room,
        SegmentKind::KeyMaterial,
        SEG_OWN_UNKNOWN_HIGHER,
        &segment,
    )
}

pub(super) fn delete_unknown_higher(
    batch: &mut crate::node::store::Batch<'_>,
    room: &Digest32,
) -> Result<()> {
    batch.delete_segment(room, SegmentKind::KeyMaterial, SEG_OWN_UNKNOWN_HIGHER)?;
    Ok(())
}

fn unknown_higher(store: &Store, sek: &Sek, room: &Digest32) -> Result<Option<Entry>> {
    let Some(segment) = store.snapshot()?.get_segment_bounded(
        room,
        SegmentKind::KeyMaterial,
        SEG_OWN_UNKNOWN_HIGHER,
        crate::log::history::MAX_HEADER_BYTES,
    )?
    else {
        return Ok(None);
    };
    let wire = open_segment(
        sek,
        SegmentKind::KeyMaterial,
        SEG_OWN_UNKNOWN_HIGHER,
        &segment,
    )?;
    let entry = Entry::from_wire(&wire)?;
    if entry.payload.is_some() || entry.skeleton.channel_id != *room || entry.skeleton.seq == 0 {
        return Err(Error::MalformedAtRest("own history extent binding"));
    }
    Ok(Some(entry))
}

pub(super) fn save_recovery_boundary(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    head: &SignedHead,
) -> Result<()> {
    let segment = seal_segment(
        sek,
        SegmentKind::KeyMaterial,
        SEG_OWN_RECOVERY_BOUNDARY,
        &head.to_wire(),
    )?;
    batch.put_segment(
        room,
        SegmentKind::KeyMaterial,
        SEG_OWN_RECOVERY_BOUNDARY,
        &segment,
    )
}

pub(super) fn delete_recovery_boundary(
    batch: &mut crate::node::store::Batch<'_>,
    room: &Digest32,
) -> Result<()> {
    batch.delete_segment(room, SegmentKind::KeyMaterial, SEG_OWN_RECOVERY_BOUNDARY)?;
    Ok(())
}

fn load_recovery_boundary(store: &Store, sek: &Sek, room: &Digest32) -> Result<Option<SignedHead>> {
    store
        .snapshot()?
        .get_segment_bounded(
            room,
            SegmentKind::KeyMaterial,
            SEG_OWN_RECOVERY_BOUNDARY,
            crate::log::history::MAX_HEADER_BYTES,
        )?
        .map(|segment| {
            SignedHead::from_wire(&open_segment(
                sek,
                SegmentKind::KeyMaterial,
                SEG_OWN_RECOVERY_BOUNDARY,
                &segment,
            )?)
        })
        .transpose()
}

pub(crate) struct RecoveryContexts {
    room: Digest32,
    key: crate::atrest::sek::WeakSek,
    author: Digest32,
    head: Digest32,
    contexts: Vec<Digest32>,
}

impl RecoveryContexts {
    pub(crate) fn commit(self, store: &Store) -> Result<()> {
        let Self {
            room,
            key,
            author,
            head,
            contexts,
        } = self;
        key.with(|sek| {
            let mut batch = store.batch()?;
            batch.ruled();
            let entries = entry_store::EntryIndex::default();
            let mut index = entries.write(&mut batch, sek, &room)?;
            for context in contexts {
                index.keep_recovery_context(&author, &head, &context)?;
            }
            index.seal()?;
            batch.commit()
        })
    }
}

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

/// Reconstruct an exact prefix from authenticated canonical/serving subtrees without scanning
/// the feed. The caller compares the result with a separately verified signed boundary.
fn recovered_prefix(
    read: &entry_store::Read<'_>,
    target: &SignedHead,
    leaves: u64,
) -> Result<Option<Descriptor>> {
    if leaves == 0 {
        return Ok(Some(Descriptor::empty(target.binding)));
    }
    if let Some(root) = read.history_range(target.binding, 1, leaves)? {
        return Ok(Some(root));
    }
    let next = leaves.checked_add(1).ok_or(Error::OwnHistoryBehind)?;
    let ranges = inclusion_ranges(next, next)?;
    let mut source = AppendForest {
        read,
        target,
        joined: None,
    };
    let mut budget = LocalAppendBudget::new();
    let mut root: Option<(u64, Descriptor)> = None;
    for range in ranges {
        let Some(node) = budget.range(&source, target.binding, range)? else {
            return Ok(None);
        };
        root = Some(match root {
            None => (range.start, node),
            Some((start, right)) => {
                if range.start.checked_add(node.leaves) != Some(start) {
                    return Err(Error::MalformedAtRest("own recovery prefix ranges"));
                }
                match budget.join_ranges(target.binding, node, right, &source)? {
                    HistoryStep::Complete((joined, context)) => {
                        source.joined = Some(context);
                        (range.start, joined)
                    }
                    HistoryStep::MissingContext(_) => return Ok(None),
                    _ => return Err(Error::OwnHistoryBehind),
                }
            }
        });
    }
    Ok(root.and_then(|(start, node)| (start == 1).then_some(node)))
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
    pub(super) fn bytes(&self) -> Vec<u8> {
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
    pub(super) fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UnknownBehind, Self::UnknownBehind) | (Self::Fork, Self::Fork) => true,
            (Self::Head(a), Self::Head(b)) => a.id() == b.id(),
            _ => false,
        }
    }
}

/// A sealed recovery fence. It contains no room guard or mutable room projection.
pub(crate) struct PendingOwnRecovery {
    room: Digest32,
    epoch: u64,
    next: Recovery,
    sealed: SealedSegment,
}

impl PendingOwnRecovery {
    pub(crate) fn commit(&self, store: &Store) -> Result<()> {
        store.put_segment(
            &self.room,
            SegmentKind::KeyMaterial,
            SEG_OWN_BEHIND,
            &self.sealed,
        )
    }
}

impl ChannelState {
    pub(crate) fn prepare_recovery_contexts(
        &self,
        store: &Store,
        author: Digest32,
        head: Digest32,
        contexts: Vec<Digest32>,
    ) -> Result<RecoveryContexts> {
        if contexts.len() > crate::log::history::MAX_PROOF_TOKENS + 2
            || !self.recovery_standing(store, &author)?
        {
            return Err(Error::OwnHistoryBehind);
        }
        let signed = self
            .history_head_by_id(store, &head)?
            .ok_or(Error::OwnHistoryBehind)?;
        if signed.binding.room != self.channel_id
            || signed.binding.author != author
            || signed.binding.scope != LogScope::Public
        {
            return Err(Error::OwnHistoryBehind);
        }
        let key = self.authors.get(&author).ok_or(Error::OwnHistoryBehind)?;
        if !matches!(
            signed.verify(key, &mut WorkBudget::default())?,
            HistoryStep::Complete(_)
        ) {
            return Err(Error::OwnHistoryBehind);
        }
        Ok(RecoveryContexts {
            room: self.channel_id,
            key: self.sek.reader(),
            author,
            head,
            contexts,
        })
    }

    /// Narrow standing for reconstructing a returning author's own signed prefix and keys.
    /// It is not membership and must never authorize general history, Read, Drive or services.
    pub(crate) fn recovery_standing(&self, store: &Store, author: &Digest32) -> Result<bool> {
        if !self.is_author(author) || self.dag.is_frozen(author) {
            return Ok(false);
        }
        let Some(seq) = self.left_at(author) else {
            return Ok(self.is_member(author));
        };
        let Some((at, wire)) = self.board_kept.notices.get(author) else {
            return Ok(false);
        };
        if *at
            > self
                .now_hint
                .saturating_add(crate::nat::store::MAX_CLOCK_SKEW_MS)
            || self.withdrawn_since(author, *at)
        {
            return Ok(false);
        }
        let notice = crate::nat::notice::AdmissionNotice::from_wire(wire)?;
        if notice.joiner() != *author || notice.witness.timestamp_ms != *at {
            return Err(Error::MalformedAtRest("recovery notice binding"));
        }
        let Some(witness) = self.authors.get(&notice.witness.witness_id) else {
            return Ok(false);
        };
        if !self.is_member(&notice.witness.witness_id) {
            return Ok(false);
        }
        notice.verify(witness, &self.channel_id, self.epoch)?;
        let read = self.history_read(store)?;
        let departure = match read.get(author, seq)? {
            Some(entry) => Some(entry),
            None if read.sparse_enabled() => read
                .history_validated_header(author, seq)?
                .map(|(_, entry)| entry),
            None => None,
        };
        Ok(departure.is_some_and(|entry| notice.witness.timestamp_ms > entry.skeleton.claimed_ms))
    }

    /// Classify only locally held, authenticated evidence for the joining author.
    /// A board withdrawal or admission alone does not prove an authored sequence.
    pub(crate) fn classify_joiner_history(
        &self,
        store: &Store,
        key: &CompositePublicKey,
    ) -> Result<crate::node::joinstream::OwnHistory> {
        use crate::node::joinstream::OwnHistory;

        let author = key.fingerprint();
        if self.dag.is_frozen(&author) {
            return Err(Error::OwnHistoryBehind);
        }
        let held = self.dag.feed(&author).map_or(0, |feed| feed.max_seq());
        let read = self.history_read(store)?;
        let extent = |seq: u64| -> Result<OwnHistory> {
            let entry = match read.get(&author, seq)? {
                Some(entry) => Some(entry),
                None if read.sparse_enabled() => read
                    .history_validated_header(&author, seq)?
                    .map(|(_, entry)| entry),
                None => None,
            }
            .ok_or(Error::OwnHistoryBehind)?;
            if entry.skeleton.channel_id != self.channel_id
                || entry.skeleton.author_id != author
                || entry.skeleton.seq != seq
            {
                return Err(Error::MalformedAtRest("joiner history extent binding"));
            }
            entry.verify(key)?;
            let wire = entry.header_wire();
            if wire.len() > crate::log::history::MAX_HEADER_BYTES {
                return Err(Error::SizeLimitExceeded("own history extent header"));
            }
            Ok(OwnHistory::Unavailable(wire))
        };
        if !read.sparse_enabled() {
            return if held == 0 {
                Ok(OwnHistory::None)
            } else {
                extent(held)
            };
        }
        // A publication in progress is waited for (the join's proposal asks again once it ends),
        // never reported as this node being behind what a member holds: nothing was compared
        // yet, and the history in question is the joiner's, not this node's.
        if read.publication_busy() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        let settled = read
            .history_settled_tip(&author)?
            .map_or(0, |entry| entry.skeleton.seq);
        #[cfg(feature = "test-knobs")]
        if crate::node::computer::fx28_mutant("join-extent-without-head") && held.max(settled) != 0
        {
            return extent(held.max(settled));
        }
        let mut selected: Option<SignedHead> = None;
        if let Some(state) = read.sparse_author(&author, LogScope::Public)? {
            if state.observed_conflict.is_some() {
                return Err(Error::OwnHistoryBehind);
            }
            for id in [state.observed, state.committed].into_iter().flatten() {
                let head = read
                    .history_head(&id)?
                    .ok_or(Error::MalformedAtRest("joiner history head missing"))?;
                if head.binding.room != self.channel_id
                    || head.binding.author != author
                    || head.binding.scope != LogScope::Public
                {
                    return Err(Error::MalformedAtRest("joiner history head binding"));
                }
                match head.verify(key, &mut WorkBudget::default())? {
                    HistoryStep::Complete(_) => {}
                    _ => return Err(Error::OwnHistoryBehind),
                }
                if selected
                    .as_ref()
                    .is_some_and(|old| old.root.leaves == head.root.leaves && old.id() != head.id())
                {
                    return Err(Error::OwnHistoryBehind);
                }
                if selected
                    .as_ref()
                    .is_none_or(|old| head.root.leaves > old.root.leaves)
                {
                    selected = Some(head);
                }
            }
        }
        match selected {
            Some(head) if head.root.leaves < held.max(settled) => extent(held.max(settled)),
            Some(head) if head.root.leaves != 0 => Ok(OwnHistory::Head(head.to_wire())),
            _ if held != 0 || settled != 0 => extent(held.max(settled)),
            _ => Ok(OwnHistory::None),
        }
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

    /// `SignedHead::verify` is a pure function of the head's wire bytes (body and
    /// signature) and the key, so a head this node already verified under its own key is
    /// not verified again on every outbound sync start. The memo is keyed by the digest of
    /// the exact wire bytes and the key's fingerprint, never by `SignedHead::id`, which
    /// excludes the signature; it holds only heads that completed verification.
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
        let mut input = head.to_wire();
        input.extend_from_slice(&key.fingerprint());
        let memo = sha256(&input);
        let mut verified = self
            .own_heads_verified
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if verified.contains(&memo) {
            return Ok(());
        }
        match head.verify(key, &mut WorkBudget::default())? {
            HistoryStep::Complete(_) => {
                if verified.len() >= 8 {
                    verified.remove(0);
                }
                verified.push(memo);
                Ok(())
            }
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
        // A publication in progress is waited for (its callers re-run after it), never
        // reported as this node being behind what a member holds: nothing was compared yet.
        if read.publication_busy() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
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
            if self.own_behind && read.history_head_accepted(&head.id(), head.binding)? {
                let retained =
                    load_continuity(store, &self.continuity_key, &self.channel_id, &own)?;
                let supplied = load_recovery_boundary(store, &self.sek, &self.channel_id)?;
                for boundary in retained
                    .as_ref()
                    .map(|marker| &marker.head)
                    .into_iter()
                    .chain(supplied.as_ref())
                {
                    self.checked_own_head(boundary)?;
                    if boundary.root.leaves <= head.root.leaves {
                        if let Some(root) = recovered_prefix(&read, &head, boundary.root.leaves)? {
                            if root != boundary.root {
                                return Ok(Some(Recovery::Fork));
                            }
                        }
                    }
                }
                if let Some(extent) = unknown_higher(store, &self.sek, &self.channel_id)? {
                    if extent.skeleton.author_id != own {
                        return Err(Error::MalformedAtRest("own history extent author"));
                    }
                    extent.verify(self.authors.get(&own).ok_or(Error::OwnHistoryBehind)?)?;
                    if extent.skeleton.seq <= head.root.leaves {
                        if let Some((_, actual)) =
                            read.history_validated_header(&own, extent.skeleton.seq)?
                        {
                            if actual.entry_hash() != extent.entry_hash() {
                                return Ok(Some(Recovery::Fork));
                            }
                        }
                    }
                }
            }
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

    /// Prepare the exact durable fence without changing its published in-memory mirror.
    pub(crate) fn prepare_own_recovery(&self, store: &Store) -> Result<Option<PendingOwnRecovery>> {
        let Some(mut next) = self.own_recovery_evidence(store)? else {
            return Ok(None);
        };
        // Missing evidence cannot lower a previously authenticated target.
        if matches!(next, Recovery::UnknownBehind) && self.own_behind {
            return Ok(None);
        }
        if let (Recovery::Head(old), Recovery::Head(new)) = (&self.own_recovery, &next) {
            if self.own_behind && old.root.leaves > new.root.leaves {
                next = Recovery::Head(old.clone());
            }
        }
        if self.own_behind && self.own_recovery.same(&next) {
            return Ok(None);
        }
        let sealed = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_OWN_BEHIND,
            &next.bytes(),
        )?;
        Ok(Some(PendingOwnRecovery {
            room: self.channel_id,
            epoch: self.epoch,
            next,
            sealed,
        }))
    }

    pub(crate) fn install_own_recovery(&mut self, pending: PendingOwnRecovery) -> Result<()> {
        if pending.room != self.channel_id || pending.epoch != self.epoch {
            return Err(Error::Unreachable("own recovery room changed"));
        }
        self.own_behind = true;
        self.own_recovery = pending.next;
        Ok(())
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

    pub(super) fn require_own_recovery_complete(&self, store: &Store) -> Result<()> {
        if !self.own_behind || !self.recovery_standing(store, &self.me())? {
            return Err(Error::OwnHistoryBehind);
        }
        let extent = unknown_higher(store, &self.sek, &self.channel_id)?;
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
        if let Some(extent) = extent {
            if extent.skeleton.author_id != self.me() || extent.skeleton.seq > target.root.leaves {
                return Err(Error::OwnHistoryBehind);
            }
            extent.verify(
                self.authors
                    .get(&self.me())
                    .ok_or(Error::OwnHistoryBehind)?,
            )?;
            let Some((_, actual)) =
                read.history_validated_header(&self.me(), extent.skeleton.seq)?
            else {
                return Err(Error::OwnHistoryBehind);
            };
            if actual.entry_hash() != extent.entry_hash() {
                return Err(Error::OwnHistoryBehind);
            }
        }
        // A larger signed head is not evidence that it extends either previously known
        // signed boundary. Check the actual recovered prefix root against each witness.
        let retained = load_continuity(store, &self.continuity_key, &self.channel_id, &self.me())?;
        let supplied = load_recovery_boundary(store, &self.sek, &self.channel_id)?;
        for boundary in retained
            .as_ref()
            .map(|marker| &marker.head)
            .into_iter()
            .chain(supplied.as_ref())
        {
            self.checked_own_head(boundary)?;
            if boundary.root.leaves > target.root.leaves {
                return Err(Error::OwnHistoryBehind);
            }
            let actual = recovered_prefix(&read, target, boundary.root.leaves)?;
            if actual != Some(boundary.root) {
                return Err(Error::OwnHistoryBehind);
            }
        }
        if self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?
            .author_backfill_pending(&self.me())?
        {
            return Err(Error::OwnHistoryBehind);
        }
        // `VOX_TEST_FWD_MUTANT=audit-back` puts back the completion check of the deleted
        // blocking readability audit: completion waits for an audit cursor, which nothing
        // writes any more, as the audit waited for own keys no node releases any more.
        #[cfg(feature = "test-knobs")]
        if std::env::var("VOX_TEST_FWD_MUTANT").as_deref() == Ok("audit-back")
            && store
                .snapshot()?
                .get_segment_bounded(
                    &self.channel_id,
                    SegmentKind::KeyMaterial,
                    super::SEG_OWN_READABILITY,
                    128,
                )?
                .is_none()
        {
            eprintln!(
                "test-knobs: audit-back mutant engaged: own recovery waits for a readability \
                 audit cursor nothing writes"
            );
            return Err(Error::OwnHistoryBehind);
        }
        self.require_legacy_current(store)?;
        let governance = self.current_governance(store)?;
        let _generation = match governance.presence_sender_generation(&self.me())? {
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
    pub(super) fn prepare_own_append_ranges(&self, store: &Store) -> Result<Ranges> {
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
        Ok(Ranges {
            marker: self.own_recovery.bytes(),
            binding: target.binding,
            context: root_context,
            forest,
        })
    }
}
