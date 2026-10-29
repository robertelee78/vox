//! Own-feed recovery and join settlement retain component deltas, never a room projection.
//! This module is a child of pending_text so all signed controls use its original append kernel.
use super::super::own_history::{PendingOwnRecovery, Recovery};
use super::*;
use crate::log::history::{ControlContext, Descriptor, TreeBinding};

pub(crate) enum Work {
    Offer(Vec<(Digest32, Option<(u64, crate::node::ports::OwnProbe)>)>),
    Settle,
    CatchUp,
    Presence,
    Shares,
    Fence,
    Refresh,
    Receiver,
    Audit,
    Ranges,
    Complete,
    Inspect,
}

pub(crate) enum Saved {
    Offered {
        hint: Option<(Digest32, Digest32, u64)>,
        targets: Vec<Digest32>,
    },
    Settlement {
        changed: bool,
        sparse: bool,
        eligible: bool,
    },
    CaughtUp,
    Presence(bool),
    Shares(bool),
    Inactive,
    Fence(bool),
    Receiver(bool),
    Audit(OwnReadability),
    Ranges,
    Recovered(bool),
    Inspected(Option<(Digest32, u64, bool)>),
}

pub(crate) struct Audit {
    pub(crate) outcome: OwnReadability,
    pub(crate) write: Option<AuditWrite>,
}
pub(crate) struct AuditWrite {
    pub(crate) marker: Vec<u8>,
    pub(crate) cursor: SealedSegment,
    pub(crate) render_from: Option<u64>,
}
impl Audit {
    pub(crate) fn unchanged(outcome: OwnReadability) -> Self {
        Self {
            outcome,
            write: None,
        }
    }
}
pub(crate) struct Ranges {
    pub(crate) marker: Vec<u8>,
    pub(crate) binding: TreeBinding,
    pub(crate) context: ControlContext,
    pub(crate) forest: Vec<(u64, Descriptor)>,
}

/// The expected recovery marker and its deletion share the exact signed Presence batch.
pub(super) struct AppendBoundary {
    settle: bool,
    recover: Option<Vec<u8>>,
}
impl AppendBoundary {
    pub(super) fn check(
        &self,
        batch: &crate::node::store::Batch<'_>,
        sek: &Sek,
        room: &Digest32,
    ) -> Result<()> {
        if let Some(expected) = &self.recover {
            check_marker(batch, sek, room, expected)?;
        }
        Ok(())
    }
    pub(super) fn apply(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
        room: &Digest32,
    ) -> Result<()> {
        if self.settle {
            batch.delete_segment(room, SegmentKind::KeyMaterial, SEG_UNSETTLED)?;
        }
        if self.recover.is_some() {
            batch.delete_segment(room, SegmentKind::KeyMaterial, SEG_OWN_BEHIND)?;
            batch.delete_segment(room, SegmentKind::KeyMaterial, SEG_OWN_READABILITY)?;
        }
        Ok(())
    }
}
fn check_marker(
    batch: &crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    expected: &[u8],
) -> Result<()> {
    let sealed = batch
        .get_segment_bounded(
            room,
            SegmentKind::KeyMaterial,
            SEG_OWN_BEHIND,
            crate::log::history::MAX_HEADER_BYTES + 64,
        )?
        .ok_or(Error::OwnHistoryBehind)?;
    let current = Recovery::parse(&open_segment(
        sek,
        SegmentKind::KeyMaterial,
        SEG_OWN_BEHIND,
        &sealed,
    )?)?;
    if !current.same(&Recovery::parse(expected)?) {
        return Err(Error::OwnHistoryBehind);
    }
    Ok(())
}

struct Capsule {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    instance: [u8; 16],
    sek: WeakSek,
    pin: Option<history::PendingHistoryRead>,
}
impl Capsule {
    fn prepare(channel: &mut ChannelState, store: &Arc<Store>, owner: Arc<()>) -> Result<Self> {
        let instance = channel.history_instance(store)?;
        let pin = channel.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(Self {
            owner,
            room: channel.channel_id,
            epoch: channel.epoch,
            instance,
            sek: channel.sek.reader(),
            pin: Some(pin),
        })
    }
    fn matches(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        Arc::ptr_eq(owner, &self.owner)
            && channel.channel_id == self.room
            && channel.epoch == self.epoch
            && channel
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }
}
struct Seed {
    sender: SenderChain,
    origins: OriginKeyStore,
    existing: Option<ReceiverChain>,
    root: CompositePublicKey,
    base: Digest32,
    marker: Vec<u8>,
}
enum Operation {
    Unchanged(Saved),
    Fence(Option<PendingOwnRecovery>),
    Receiver(Box<Seed>),
    Audit(Audit),
    Ranges(Ranges),
    LegacySettle,
}
struct Append {
    pending: PendingText,
    mode: AppendMode,
    rotation: Option<Rotation>,
    boundary: AppendBoundary,
}
enum AppendMode {
    Rotate {
        next: u64,
        here: bool,
        settle: bool,
        recover: bool,
    },
    Presence,
    Shares(Vec<(String, ServiceKind)>),
}
impl AppendMode {
    fn saved(&self, changed: bool, sparse: bool) -> Saved {
        match self {
            Self::Rotate { settle: true, .. } => Saved::Settlement {
                changed,
                sparse,
                eligible: true,
            },
            Self::Rotate { recover: true, .. } => Saved::Recovered(changed),
            Self::Rotate { .. } => Saved::CaughtUp,
            Self::Presence => Saved::Presence(changed),
            Self::Shares(_) => Saved::Shares(changed),
        }
    }
}
pub(crate) struct Prepared {
    kind: PreparedKind,
}
enum PreparedKind {
    Component(Box<(Capsule, Operation)>),
    Append(Box<Append>),
}
struct RotationSaved {
    sender: SenderChain,
    origins: OriginKeyStore,
    owed: Vec<(Digest32, u64)>,
    settle: bool,
    recover: bool,
}
enum Delta {
    None,
    Fence(PendingOwnRecovery),
    Receiver((Digest32, u64), Box<ReceiverChain>),
    Settled,
}
pub(crate) struct Completed {
    kind: CompletedKind,
}
enum CompletedKind {
    Component(Box<CompletedComponent>),
    Append(Box<CompletedAppend>),
}
struct CompletedAppend {
    completed: CompletedText,
    rotation: Option<RotationSaved>,
    saved: Saved,
}
struct CompletedComponent {
    capsule: Capsule,
    delta: Delta,
    result: Result<Saved>,
}

impl ChannelState {
    pub(crate) fn prepare_pending_recovery_work(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        work: Work,
        now: crate::time::Ms,
    ) -> Result<Option<Prepared>> {
        let operation = match work {
            Work::Offer(peers) => {
                let hint = if self.uses_sparse_history(store)? {
                    self.sparse_settlement_pending_own_head(store)
                } else {
                    None
                };
                let targets = match hint {
                    Some((_, head, size)) => {
                        self.history_own_receipt_targets(store, peers, head, size)?
                    }
                    None => Vec::new(),
                };
                Operation::Unchanged(Saved::Offered { hint, targets })
            }
            Work::Fence => {
                if !self.uses_sparse_history(store)? {
                    Operation::Unchanged(Saved::Inactive)
                } else {
                    Operation::Fence(self.prepare_own_recovery(store)?)
                }
            }
            Work::Refresh => Operation::Fence(self.prepare_own_recovery(store)?),
            Work::Inspect => Operation::Unchanged(Saved::Inspected(self.own_recovery_key(store)?)),
            Work::Audit => Operation::Audit(self.prepare_own_readability(store, now)?),
            Work::Ranges => Operation::Ranges(self.prepare_own_append_ranges(store)?),
            Work::Receiver => {
                let me = self.me();
                let slot = (me, self.sender.chain_id());
                if !self.own_behind
                    || !matches!(self.own_recovery, Recovery::Head(_))
                    || self
                        .receivers
                        .get(&slot)
                        .is_some_and(|chain| chain.recovers_own_sender(&self.sender))
                {
                    Operation::Unchanged(Saved::Receiver(false))
                } else {
                    if !self.origins.has(&self.channel_id, self.epoch, slot.1)
                        || (!self.receivers.contains_key(&slot)
                            && self.receivers.len() >= MAX_RECEIVER_CHAINS)
                    {
                        return Err(Error::OwnHistoryBehind);
                    }
                    Operation::Receiver(Box::new(Seed {
                        sender: SenderChain::from_state(&self.sender.to_state())?,
                        origins: self.origins.generation_candidate(
                            &self.channel_id,
                            self.epoch,
                            slot.1,
                        ),
                        existing: self
                            .receivers
                            .get(&slot)
                            .map(|chain| ReceiverChain::from_state(&chain.to_state()))
                            .transpose()?,
                        root: self
                            .authors
                            .get(&me)
                            .cloned()
                            .ok_or(Error::OwnHistoryBehind)?,
                        base: self.receiver_persistence.base,
                        marker: self.own_recovery.bytes(),
                    }))
                }
            }
            Work::Settle => {
                let sparse = self.uses_sparse_history(store)?;
                #[cfg(feature = "test-knobs")]
                let held = std::env::var_os(TEST_NEVER_SETTLE_ENV).is_some_and(|v| !v.is_empty());
                #[cfg(not(feature = "test-knobs"))]
                let held = false;
                if held
                    || (!sparse && self.settled)
                    || (sparse
                        && !self.settled
                        && !self.sparse_settlement_local_ready(store, now)?)
                {
                    Operation::Unchanged(Saved::Settlement {
                        changed: false,
                        sparse,
                        eligible: false,
                    })
                } else if self.settled {
                    Operation::Unchanged(Saved::Settlement {
                        changed: false,
                        sparse,
                        eligible: true,
                    })
                } else if !sparse {
                    Operation::LegacySettle
                } else {
                    let seq = self.dag.verified_head(&self.me());
                    let bound = seq
                        .checked_add(1)
                        .ok_or(Error::MalformedBundle("chain_id overflow"))?;
                    if self.sender.chain_id() > bound {
                        return Err(Error::MalformedBundle(
                            "sender generation exceeds authenticated sparse sequence bound",
                        ));
                    }
                    let next = bound
                        .checked_add(1)
                        .ok_or(Error::MalformedBundle("chain_id overflow"))?;
                    return self
                        .prepare_recovery_append(
                            store,
                            owner,
                            AppendMode::Rotate {
                                next,
                                here: true,
                                settle: true,
                                recover: false,
                            },
                            now,
                        )
                        .map(Some);
                }
            }
            Work::Complete => {
                if !self.own_behind {
                    Operation::Unchanged(Saved::Recovered(false))
                } else {
                    self.require_own_recovery_complete(store)?;
                    let next = self
                        .dag
                        .verified_head(&self.me())
                        .checked_add(2)
                        .ok_or(Error::MalformedBundle("chain_id overflow"))?;
                    if self.sender.chain_id() >= next {
                        return Err(Error::OwnHistoryBehind);
                    }
                    return self
                        .prepare_recovery_append(
                            store,
                            owner,
                            AppendMode::Rotate {
                                next,
                                here: !self.said_left(&self.me()),
                                settle: false,
                                recover: true,
                            },
                            now,
                        )
                        .map(Some);
                }
            }
            Work::CatchUp => {
                let me = self.me();
                let Some(feed) = self.dag.feed(&me).filter(|feed| !feed.is_empty()) else {
                    return self.prepare_recovery_unchanged(store, owner, Saved::CaughtUp);
                };
                let sparse = self.uses_sparse_history(store)?;
                let mut used = if sparse { feed.max_seq() } else { 0 };
                if !sparse {
                    let entries = self.entries.read(store, &self.sek, &self.channel_id)?;
                    for entry in feed.iter(&entries) {
                        let entry = entry?;
                        let Some(payload) = entry.payload.as_deref() else {
                            continue;
                        };
                        let chain = match classify_payload(payload) {
                            Ok(EntryKind::Content) => GroupMessage::from_wire(payload)
                                .ok()
                                .filter(|message| message.header.channel_id == self.channel_id)
                                .map(|message| message.header.chain_id),
                            Ok(EntryKind::Governance) => match GovBody::parse_framed(payload) {
                                Ok(GovBody::Presence(presence)) => Some(presence.body.chain_id),
                                Ok(GovBody::ConsentRevocation(revocation)) => {
                                    Some(revocation.body.new_chain_id)
                                }
                                _ => None,
                            },
                            Ok(EntryKind::Checkpoint) | Err(_) => None,
                        };
                        used = used.max(chain.unwrap_or(0));
                    }
                }
                if self.sender.chain_id() > used {
                    Operation::Unchanged(Saved::CaughtUp)
                } else {
                    let next = used
                        .checked_add(if sparse { 2 } else { 1 })
                        .ok_or(Error::MalformedBundle("chain_id overflow"))?;
                    return self
                        .prepare_recovery_append(
                            store,
                            owner,
                            AppendMode::Rotate {
                                next,
                                here: !self.said_left(&me),
                                settle: false,
                                recover: false,
                            },
                            now,
                        )
                        .map(Some);
                }
            }
            Work::Presence => {
                if !self.said_left(&self.me()) {
                    Operation::Unchanged(Saved::Presence(false))
                } else {
                    return self
                        .prepare_recovery_append(store, owner, AppendMode::Presence, now)
                        .map(Some);
                }
            }
            Work::Shares => {
                let view = self.current_governance(store)?;
                let me = self.me();
                let mut unsaid = Vec::new();
                for tag in self
                    .services
                    .keys()
                    .filter(|tag| !self.transient.contains(*tag))
                {
                    if view.share(&me, service_name(tag))?.is_none() {
                        unsaid.push((tag.clone(), self.kind_of(tag)));
                    }
                }
                drop(view);
                if unsaid.is_empty() {
                    Operation::Unchanged(Saved::Shares(false))
                } else {
                    return self
                        .prepare_recovery_append(store, owner, AppendMode::Shares(unsaid), now)
                        .map(Some);
                }
            }
        };
        let capsule = Capsule::prepare(self, store, owner)?;
        Ok(Some(Prepared {
            kind: PreparedKind::Component(Box::new((capsule, operation))),
        }))
    }
    fn prepare_recovery_unchanged(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        saved: Saved,
    ) -> Result<Option<Prepared>> {
        let capsule = Capsule::prepare(self, store, owner)?;
        Ok(Some(Prepared {
            kind: PreparedKind::Component(Box::new((capsule, Operation::Unchanged(saved)))),
        }))
    }
    fn prepare_recovery_append(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        mode: AppendMode,
        now: crate::time::Ms,
    ) -> Result<Prepared> {
        let (settle, recover, after_departure) = match &mode {
            AppendMode::Rotate {
                settle, recover, ..
            } => (*settle, *recover, *settle),
            AppendMode::Presence => (false, false, true),
            AppendMode::Shares(_) => (false, false, false),
        };
        self.require_legacy_current(store)?;
        self.ensure_local_append_available_mode(store, after_departure, recover)?;
        self.ensure_governance_append_eligible_by(store, &self.me(), settle, recover)?;
        let sparse = self.uses_sparse_history(store)?;
        let rotation = if matches!(&mode, AppendMode::Rotate { .. }) {
            let me = self.me();
            let readers = self.with_consent_facts(|facts| {
                self.entitled
                    .keys()
                    .filter(|target| facts.can_read(target, &me))
                    .copied()
                    .collect::<BTreeSet<_>>()
            })?;
            let retired = self.sender.chain_id();
            let mut owed = Vec::new();
            for (target, (from, _)) in &self.entitled {
                if *target == me || self.has_left(target) || !readers.contains(target) {
                    continue;
                }
                let floor = match self.delivered.get(target) {
                    None => *from,
                    Some(delivered) if *delivered < retired => (*delivered + 1).max(*from),
                    Some(_) => continue,
                };
                if floor <= retired {
                    owed.push((*target, floor));
                }
            }
            Some(Rotation {
                origins: OriginKeyStore::from_state(&self.origins.to_state())?,
                newest_mint: self.newest_mint_seq(),
                history: rotation_history_bytes(&self.history, &owed),
                owed,
            })
        } else {
            None
        };
        let boundary = AppendBoundary {
            settle,
            recover: recover.then(|| self.own_recovery.bytes()),
        };
        let pending = self.prepare_pending_append(
            store,
            self.me(),
            owner,
            now.get(),
            now.get(),
            sparse,
            Vec::new(),
            None,
        )?;
        Ok(Prepared {
            kind: PreparedKind::Append(Box::new(Append {
                pending,
                mode,
                rotation,
                boundary,
            })),
        })
    }
}

impl Prepared {
    pub(crate) fn run(
        self,
        store: &Store,
        signer: &crate::atrest::vault::VaultRootSigner,
    ) -> Completed {
        match self.kind {
            PreparedKind::Component(component) => {
                let (capsule, operation) = *component;
                let mut delta = Delta::None;
                let result = (|| match operation {
                    Operation::Unchanged(saved) => Ok(saved),
                    Operation::Fence(None) => Ok(Saved::Fence(false)),
                    Operation::Fence(Some(pending)) => {
                        pending.commit(store)?;
                        delta = Delta::Fence(pending);
                        Ok(Saved::Fence(true))
                    }
                    Operation::LegacySettle => {
                        store.delete_segment(
                            &capsule.room,
                            SegmentKind::KeyMaterial,
                            SEG_UNSETTLED,
                        )?;
                        delta = Delta::Settled;
                        Ok(Saved::Settlement {
                            changed: true,
                            sparse: false,
                            eligible: true,
                        })
                    }
                    Operation::Receiver(seed) => capsule.sek.with(|sek| {
                        let seed = *seed;
                        let me = seed.sender.author_id();
                        let slot = (me, seed.sender.chain_id());
                        let (iteration, key) = seed.sender.current_position();
                        let current = seed.sender.skdm_for(signer, iteration, key)?;
                        let live = ReceiverChain::from_skdm(
                            &current,
                            &seed.root,
                            &capsule.room,
                            capsule.epoch,
                        )?;
                        let origin = seed.origins.full_history_skdm(
                            signer,
                            &capsule.room,
                            capsule.epoch,
                            slot.1,
                        )?;
                        let floor = ReceiverChain::from_skdm(
                            &origin,
                            &seed.root,
                            &capsule.room,
                            capsule.epoch,
                        )?;
                        let mut candidate = match seed.existing {
                            Some(mut existing)
                                if existing.next_iteration() >= live.next_iteration() =>
                            {
                                existing.retain_history_release(&live)?;
                                existing
                            }
                            _ => live,
                        };
                        candidate.retain_history_release(&floor)?;
                        if !candidate.recovers_own_sender(&seed.sender) {
                            return Err(Error::OwnHistoryBehind);
                        }
                        let mut batch = store.batch()?;
                        check_marker(&batch, sek, &capsule.room, &seed.marker)?;
                        let stored = receiver_overlay::put(
                            &mut batch,
                            sek,
                            &capsule.room,
                            &me,
                            capsule.epoch,
                            seed.base,
                            &candidate,
                        )?;
                        if let receiver_overlay::Put::Busy { changed } = stored {
                            if changed {
                                batch.commit()?;
                            }
                            return Err(Error::StreamRefused(receiver_overlay::CLEANUP_PENDING));
                        }
                        let entries = entry_store::EntryIndex::default();
                        let mut index = entries.write(&mut batch, sek, &capsule.room)?;
                        index.queue_backfill(me, Some(1))?;
                        index.seal()?;
                        batch.commit()?;
                        delta = Delta::Receiver(slot, Box::new(candidate));
                        Ok(Saved::Receiver(true))
                    }),
                    Operation::Audit(audit) => {
                        if let Some(write) = audit.write {
                            capsule.sek.with(|sek| {
                                let mut batch = store.batch()?;
                                check_marker(&batch, sek, &capsule.room, &write.marker)?;
                                if let Some(seq) = write.render_from {
                                    let entries = entry_store::EntryIndex::default();
                                    let mut index =
                                        entries.write(&mut batch, sek, &capsule.room)?;
                                    index.queue_backfill(signer.fingerprint(), Some(seq))?;
                                    index.seal()?;
                                }
                                batch.put_segment(
                                    &capsule.room,
                                    SegmentKind::KeyMaterial,
                                    SEG_OWN_READABILITY,
                                    &write.cursor,
                                )?;
                                batch.commit()
                            })?;
                        }
                        Ok(Saved::Audit(audit.outcome))
                    }
                    Operation::Ranges(ranges) => capsule.sek.with(|sek| {
                        let mut batch = store.batch()?;
                        check_marker(&batch, sek, &capsule.room, &ranges.marker)?;
                        let entries = entry_store::EntryIndex::default();
                        let mut index = entries.write(&mut batch, sek, &capsule.room)?;
                        index.keep_history_context(&ranges.context)?;
                        for (start, descriptor) in ranges.forest {
                            index.keep_history_range(ranges.binding, start, descriptor)?;
                        }
                        index.seal()?;
                        batch.commit()?;
                        Ok(Saved::Ranges)
                    }),
                })();
                Completed {
                    kind: CompletedKind::Component(Box::new(CompletedComponent {
                        capsule,
                        delta,
                        result,
                    })),
                }
            }
            PreparedKind::Append(append) => {
                let mut append = *append;
                let mut rotation_saved = None;
                let sparse = append.pending.sparse;
                let result = (|| -> Result<bool> {
                    match &append.mode {
                        AppendMode::Rotate {
                            next,
                            here,
                            settle,
                            recover,
                        } => {
                            let next = SenderChain::new(
                                &append.pending.room,
                                append.pending.epoch,
                                &signer.fingerprint(),
                                *next,
                                append.pending.now_millis,
                            )?;
                            let mut rotation = append
                                .rotation
                                .take()
                                .ok_or(Error::Profile("recovery rotation state absent"))?;
                            let mint = crate::node::consent_order::stamp_mint(
                                store,
                                signer,
                                rotation.newest_mint,
                            )?;
                            retain_generation(
                                &mut rotation.origins,
                                &append.pending.room,
                                append.pending.epoch,
                                &signer.fingerprint(),
                                &next,
                                append.pending.now_millis,
                                mint,
                            )?;
                            let extra = append.pending.sek.with(|sek| {
                                Ok([
                                    (
                                        SEG_SENDER,
                                        Some(seal_segment(
                                            sek,
                                            SegmentKind::KeyMaterial,
                                            SEG_SENDER,
                                            &next.to_state(),
                                        )?),
                                    ),
                                    (
                                        SEG_ORIGINS,
                                        Some(seal_segment(
                                            sek,
                                            SegmentKind::KeyMaterial,
                                            SEG_ORIGINS,
                                            &rotation.origins.to_state(),
                                        )?),
                                    ),
                                    (
                                        SEG_HISTORY,
                                        if rotation.owed.is_empty() {
                                            None
                                        } else {
                                            Some(seal_segment(
                                                sek,
                                                SegmentKind::KeyMaterial,
                                                SEG_HISTORY,
                                                &rotation.history,
                                            )?)
                                        },
                                    ),
                                ])
                            })?;
                            if sparse {
                                let presence = crate::governance::presence::Presence::build(
                                    signer,
                                    &append.pending.room,
                                    append.pending.epoch,
                                    *here,
                                    next.chain_id(),
                                )?;
                                append.pending.append(
                                    store,
                                    signer,
                                    presence.to_wire(),
                                    EntryKind::Governance,
                                    SignedEntryKind::Governance,
                                    None,
                                    &extra,
                                    Some(&append.boundary),
                                )?;
                            } else {
                                let mut batch = store.batch()?;
                                for (slot, segment) in &extra {
                                    if let Some(segment) = segment {
                                        batch.put_segment(
                                            &append.pending.room,
                                            SegmentKind::KeyMaterial,
                                            *slot,
                                            segment,
                                        )?;
                                    }
                                }
                                batch.commit()?;
                            }
                            rotation_saved = Some(RotationSaved {
                                sender: next,
                                origins: rotation.origins,
                                owed: rotation.owed,
                                settle: *settle,
                                recover: *recover,
                            });
                            if sparse {
                                append.pending.cleanup(store)?;
                            }
                            Ok(true)
                        }
                        AppendMode::Presence => {
                            let presence = crate::governance::presence::Presence::build(
                                signer,
                                &append.pending.room,
                                append.pending.epoch,
                                true,
                                append.pending.sender.chain_id(),
                            )?;
                            append.pending.append_control_owned(
                                store,
                                signer,
                                presence.to_wire(),
                                EntryKind::Governance,
                                SignedEntryKind::Governance,
                                crate::time::Ms(append.pending.now_millis),
                            )?;
                            Ok(true)
                        }
                        AppendMode::Shares(shares) => {
                            for (tag, kind) in shares {
                                let share = crate::governance::share::ServiceShare::build(
                                    signer,
                                    &append.pending.room,
                                    append.pending.epoch,
                                    service_name(tag),
                                    crate::tunnel::udp::is_udp(tag),
                                    true,
                                    *kind,
                                )?;
                                append.pending.append_control_owned(
                                    store,
                                    signer,
                                    share.to_wire(),
                                    EntryKind::Governance,
                                    SignedEntryKind::Governance,
                                    crate::time::Ms(append.pending.now_millis),
                                )?;
                            }
                            Ok(!shares.is_empty())
                        }
                    }
                })();
                let changed = rotation_saved.is_some() || !append.pending.committed.is_empty();
                let saved = append.mode.saved(changed, sparse);
                let mut completed = append
                    .pending
                    .complete_control(result.map(|_| super::Saved::Governance(None)));
                if matches!(&append.mode, AppendMode::Rotate { recover: true, .. })
                    && matches!(&completed.result, Err(Error::OwnHistoryBehind))
                {
                    completed.failure = None;
                }
                Completed {
                    kind: CompletedKind::Append(Box::new(CompletedAppend {
                        completed,
                        rotation: rotation_saved,
                        saved,
                    })),
                }
            }
        }
    }
}
impl Completed {
    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        match &self.kind {
            CompletedKind::Component(component) => component.capsule.matches(channel, owner),
            CompletedKind::Append(append) => {
                let completed = &append.completed;
                completed.can_install(channel, owner)
                    && completed.pending.as_ref().is_some_and(|pending| {
                        pending.room == channel.channel_id && pending.epoch == channel.epoch
                    })
            }
        }
    }
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        match &mut self.kind {
            CompletedKind::Component(component) => component.capsule.pin.take(),
            CompletedKind::Append(append) => append.completed.take_history_pin(),
        }
    }
    pub(crate) fn into_result(self) -> Result<Saved> {
        match self.kind {
            CompletedKind::Component(component) => component.result,
            CompletedKind::Append(append) => {
                let CompletedAppend {
                    completed, saved, ..
                } = *append;
                completed.result.map(|_| saved)
            }
        }
    }
    pub(crate) fn finish(self, channel: &mut ChannelState, store: &Store) -> Result<Saved> {
        match self.kind {
            CompletedKind::Component(component) => {
                let CompletedComponent {
                    capsule,
                    delta,
                    result,
                } = *component;
                let owns = capsule.matches(channel, &capsule.owner);
                let current = if owns {
                    channel
                        .history_instance(store)
                        .map(|instance| instance == capsule.instance)
                } else {
                    Ok(false)
                };
                if matches!(current, Ok(true)) {
                    match delta {
                        Delta::None => {}
                        Delta::Fence(pending) => {
                            channel.install_own_recovery(pending)?;
                        }
                        Delta::Receiver(slot, receiver) => {
                            channel.receivers.insert(slot, *receiver);
                        }
                        Delta::Settled => channel.settled = true,
                    }
                }
                if owns {
                    channel.entries.committed();
                }
                channel.release_pending_text(&capsule.owner, false);
                let result = result.and_then(|saved| {
                    current.and_then(|current| {
                        if current {
                            Ok(saved)
                        } else {
                            Err(Error::Profile("own recovery room instance changed"))
                        }
                    })
                });
                if let Err(error) = &result {
                    if owns
                        && !matches!(error, Error::OwnHistoryBehind)
                        && !ChannelState::receiver_release_cleanup_waiting(error)
                    {
                        channel.poison(error);
                    }
                }
                result
            }
            CompletedKind::Append(append) => {
                let CompletedAppend {
                    completed,
                    rotation,
                    saved,
                } = *append;
                let owns = completed.pending.as_ref().is_some_and(|pending| {
                    pending.room == channel.channel_id
                        && pending.epoch == channel.epoch
                        && channel
                            .pending_text
                            .as_ref()
                            .is_some_and(|owner| Arc::ptr_eq(owner, &pending.owner))
                });
                let result = channel.finish_pending_text(store, completed).map(|_| saved);
                if let Some(rotation) = rotation.filter(|_| owns) {
                    channel.sender = rotation.sender;
                    channel.origins = rotation.origins;
                    install_rotation_history(&mut channel.history, rotation.owed);
                    if rotation.settle {
                        channel.settled = true;
                    }
                    if rotation.recover {
                        channel.own_behind = false;
                        channel.own_recovery = Recovery::UnknownBehind;
                    }
                }
                result
            }
        }
    }
}
