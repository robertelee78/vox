//! Unpublished authored work owns feed/key/append metadata, never a retained-history copy.
use super::*;
use crate::atrest::sek::WeakSek;
use crate::log::dag::PublishedFeed;
use crate::log::history::{ControlContext, EntryReference, EntryV2, SignedEntryKind};

pub(crate) mod consent;
pub(crate) mod consent_delivery;
pub(crate) mod held_consent;
#[path = "pending_text/leave.rs"]
pub(crate) mod leave;
#[path = "pending_text/legacy_session.rs"]
mod legacy_session;
pub(crate) mod read;
#[path = "pending_recovery.rs"]
pub(crate) mod recovery;

pub(crate) struct PendingText {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    origin: u64,
    creator: Digest32,
    authors: BTreeMap<Digest32, CompositePublicKey>,
    admission: AdmissionPolicy,
    dag: Dag,
    entries: entry_store::EntryIndex,
    sek: WeakSek,
    sender: SenderChain,
    next_log_id: u64,
    sparse: bool,
    skipped: Vec<Digest32>,
    now_millis: u64,
    rotation_now: u64,
    committed: Vec<Entry>,
    governance_changed: bool,
    rotation: Option<Rotation>,
    committed_feed: Option<PublishedFeed>,
    durable_text: Option<Rendered>,
    rotation_committed: bool,
    encrypted_control: bool,
    encrypted_control_committed: bool,
    read_append: Option<read::ReadAppend>,
    read_committed: bool,
    presence: Option<governance::Presence>,
    #[cfg(feature = "mutant-sender")]
    history_mode: HistoryMode,
    history_pin: Option<history::PendingHistoryRead>,
}

struct Rotation {
    origins: OriginKeyStore,
    newest_mint: u64,
    owed: Vec<(Digest32, u64)>,
    history: Vec<u8>,
}

/// Serialize the immutable ledger with the ordered entitlement deltas, without cloning it.
fn rotation_history_bytes(history: &BTreeMap<Digest32, u64>, owed: &[(Digest32, u64)]) -> Vec<u8> {
    if owed.is_empty() {
        return Vec::new();
    }
    let added = owed
        .iter()
        .filter(|(target, _)| !history.contains_key(target))
        .count();
    let mut encoder = Encoder::new();
    encoder
        .array(2)
        .uint(DELIVERED_VERSION)
        .array(history.len() + added);
    let mut owed = owed.iter().peekable();
    for (target, floor) in history {
        while owed.peek().is_some_and(|(next, _)| next < target) {
            if let Some((next, floor)) = owed.next() {
                encoder.array(2).bytes(next).uint(*floor);
            }
        }
        let floor = if owed.peek().is_some_and(|(next, _)| next == target) {
            owed.next().map_or(*floor, |(_, next)| (*floor).min(*next))
        } else {
            *floor
        };
        encoder.array(2).bytes(target).uint(floor);
    }
    for (target, floor) in owed {
        encoder.array(2).bytes(target).uint(*floor);
    }
    encoder.finish()
}

fn install_rotation_history(history: &mut BTreeMap<Digest32, u64>, owed: Vec<(Digest32, u64)>) {
    for (target, floor) in owed {
        history
            .entry(target)
            .and_modify(|old| *old = (*old).min(floor))
            .or_insert(floor);
    }
}

pub(crate) enum GovernanceWrite {
    Rename(String),
    Retention {
        seconds: u64,
        steps: bool,
    },
    IdleEnd(u64),
    End,
    AddAdmin(Digest32),
    Anchors {
        add: BootstrapSet,
        remove: Option<Digest32>,
    },
}

pub(crate) enum GovernancePreparation {
    Append(Box<PendingText>, Vec<u8>),
    Unchanged,
    OwnRetention { own: u64, room: u64 },
}

pub(crate) enum Saved {
    Text(Rendered),
    Governance(Option<Digest32>),
    OwnRetention { own: u64, room: u64 },
}

pub(crate) struct CompletedText {
    pending: Option<PendingText>,
    pub(crate) result: Result<Saved>,
    failure: Option<String>,
    #[cfg(feature = "test-knobs")]
    pub(crate) rotated: bool,
}

impl CompletedText {
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.pending
            .as_mut()
            .and_then(|pending| pending.history_pin.take())
    }

    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.pending.as_ref().is_none_or(|pending| {
            Arc::ptr_eq(&pending.owner, owner)
                && channel
                    .pending_text
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, owner))
        })
    }

    pub(crate) fn without_append(saved: Saved) -> Self {
        Self {
            pending: None,
            result: Ok(saved),
            failure: None,
            #[cfg(feature = "test-knobs")]
            rotated: false,
        }
    }
}

impl ChannelState {
    pub(crate) fn post_pending(&self) -> bool {
        self.pending_text.is_some()
    }

    /// Reserve only publication ownership; incoming repair has no local-author prerequisites.
    pub(crate) fn reserve_pending_write(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
    ) -> Result<history::PendingHistoryRead> {
        if self.post_pending()
            || self
                .entries
                .read(store, &self.sek, &self.channel_id)?
                .publication_busy()
        {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        let pin = self.pin_history_read(Arc::clone(store))?;
        self.pending_text = Some(owner);
        Ok(pin)
    }

    /// Admission only reads committed facts. No transaction or sender advancement occurs here.
    pub(crate) fn prepare_pending_text(
        &mut self,
        store: &Arc<Store>,
        me: Digest32,
        owner: Arc<()>,
        now_millis: u64,
        rotation_now: u64,
        force_rotation: bool,
    ) -> Result<PendingText> {
        self.ensure_local_append_available_for(store, true)?;
        if self.poisoned {
            return Err(self.save_failure());
        }
        if !self.settled {
            return Err(Error::RoomNotSynced);
        }
        self.require_own_history_current()?;
        if self.dag.is_frozen(&me) {
            return Err(Error::MalformedGovernance(
                "entry failed the acceptance predicate",
            ));
        }
        if !self.authors.contains_key(&me) {
            return Err(Error::Profile("this identity is not an author of the room"));
        }
        if self.ended(now_millis).is_some() {
            return Err(Error::Profile("this room has ended"));
        }
        let (now_millis, skipped) = self.stamp_after_held(store, now_millis)?;
        let sparse = self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .sparse_enabled();
        let rotation_due = force_rotation
            || self.sender.should_rotate(rotation_now)
            || self.sender.next_iteration().saturating_add(1)
                >= crate::group::state::ROTATE_AFTER_MESSAGES;
        let rotation = if rotation_due {
            (|| -> Result<Rotation> {
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
                Ok(Rotation {
                    origins: OriginKeyStore::from_state(&self.origins.to_state())?,
                    newest_mint: self.newest_mint_seq(),
                    history: rotation_history_bytes(&self.history, &owed),
                    owed,
                })
            })()
            .ok()
        } else {
            None
        };
        self.prepare_pending_append(
            store,
            me,
            owner,
            now_millis,
            rotation_now,
            sparse,
            skipped,
            rotation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_pending_append(
        &mut self,
        store: &Arc<Store>,
        me: Digest32,
        owner: Arc<()>,
        now_millis: u64,
        rotation_now: u64,
        sparse: bool,
        skipped: Vec<Digest32>,
        rotation: Option<Rotation>,
    ) -> Result<PendingText> {
        let sender = SenderChain::from_state(&self.sender.to_state())?;
        let history_pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        let pending = PendingText {
            owner: Arc::clone(&owner),
            room: self.channel_id,
            epoch: self.epoch,
            origin: self.genesis.body.created_ms,
            creator: self.genesis.creator_pubkey().fingerprint(),
            authors: self.authors.clone(),
            admission: self.admission.clone(),
            dag: self.dag.authored_candidate(),
            entries: entry_store::EntryIndex::default(),
            sek: self.sek.reader(),
            sender,
            next_log_id: self.next_log_id,
            sparse,
            skipped,
            now_millis,
            rotation_now,
            committed: Vec::with_capacity(3),
            governance_changed: false,
            rotation,
            committed_feed: None,
            durable_text: None,
            rotation_committed: false,
            encrypted_control: false,
            encrypted_control_committed: false,
            read_append: None,
            read_committed: false,
            presence: self.presence.get(&me).copied(),
            history_pin: Some(history_pin),
            #[cfg(feature = "mutant-sender")]
            history_mode: self.genesis.body.policy.history_mode,
        };
        Ok(pending)
    }

    /// One local authored reservation shared by public controls and their later durable work.
    pub(crate) fn prepare_pending_control(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
    ) -> Result<PendingText> {
        let me = self.me();
        self.ensure_local_append_available(store)?;
        self.ensure_governance_append_eligible_by(store, &me, false, false)?;
        let sparse = self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .sparse_enabled();
        self.prepare_pending_append(
            store,
            me,
            owner,
            now.get(),
            now.get(),
            sparse,
            Vec::new(),
            None,
        )
    }

    /// Build the original signed governance payload against committed authority only.
    pub(crate) fn prepare_pending_governance(
        &mut self,
        store: &Arc<Store>,
        signer: &dyn RootSigner,
        owner: Arc<()>,
        write: &GovernanceWrite,
        now: crate::time::Ms,
    ) -> Result<GovernancePreparation> {
        let me = signer.fingerprint();
        let payload = match write {
            GovernanceWrite::Rename(name) => {
                if !self.may_rename(store, &me, now)? {
                    return Err(Error::MalformedGovernance(
                        "only the room's creator or an admin may rename it",
                    ));
                }
                crate::governance::name::RoomName::build(
                    signer,
                    &self.channel_id,
                    self.epoch,
                    name,
                )?
                .to_wire()
            }
            GovernanceWrite::Retention { seconds, steps } => {
                if !self.governs_retention(store, &me, now)? {
                    let room = if *steps {
                        crate::node::retention::shortest(
                            self.room_retention(),
                            self.room_step_retention(),
                        )
                    } else {
                        self.room_retention()
                    };
                    return Ok(GovernancePreparation::OwnRetention {
                        own: *seconds,
                        room,
                    });
                }
                drop(self.local_append_eligible_for(store, false)?);
                self.ensure_governance_append_eligible_by(store, &me, false, false)?;
                let current = self
                    .checked_governance(store, now.get())?
                    .display(&self.genesis)?;
                let millis = seconds.saturating_mul(1_000);
                if if *steps {
                    current.step_ttl_ms == millis
                } else {
                    current.policy.ttl_ms == millis
                } {
                    return Ok(GovernancePreparation::Unchanged);
                }
                if *steps {
                    crate::governance::step_policy::StepPolicyUpdate::build(
                        signer,
                        &self.channel_id,
                        self.epoch,
                        millis,
                    )?
                    .to_wire()
                } else {
                    crate::governance::policy::PolicyUpdate::build(
                        signer,
                        &self.channel_id,
                        self.epoch,
                        millis,
                    )?
                    .to_wire()
                }
            }
            GovernanceWrite::IdleEnd(seconds) => {
                if me != self.genesis.creator_pubkey().fingerprint() {
                    return Err(Error::Profile(
                        "only the room's creator may choose its idle end",
                    ));
                }
                crate::governance::lifecycle::RoomLifecycle::build(
                    signer,
                    &self.channel_id,
                    self.epoch,
                    crate::governance::lifecycle::LifecycleKind::IdleEnd(
                        seconds.saturating_mul(1_000),
                    ),
                )?
                .to_wire()
            }
            GovernanceWrite::End => {
                if me != self.genesis.creator_pubkey().fingerprint()
                    && !self.checked_governance(store, now.get())?.can_end(&me)?
                {
                    return Err(Error::Profile(
                        "only the room's creator or an admin may end it",
                    ));
                }
                crate::governance::lifecycle::RoomLifecycle::build(
                    signer,
                    &self.channel_id,
                    self.epoch,
                    crate::governance::lifecycle::LifecycleKind::End,
                )?
                .to_wire()
            }
            GovernanceWrite::AddAdmin(member) => self.admin_payload(store, signer, member, now)?,
            GovernanceWrite::Anchors { add, remove } => {
                self.require_governance_ready(store, now)?;
                let mut next = BootstrapSet::new();
                for anchor in self.anchors().nodes() {
                    // Member bootstrap addresses never become room anchors.
                    if Some(anchor.id) != *remove && !self.is_known_member(&anchor.id) {
                        next.add(anchor.clone())?;
                    }
                }
                next.merge_endpoints(add)?;
                if !self.may_rename(store, &me, now)? {
                    return Err(Error::MalformedGovernance(
                        "only the room's creator or an admin may change its anchors",
                    ));
                }
                crate::governance::anchors::RoomAnchors::build(
                    signer,
                    &self.channel_id,
                    self.epoch,
                    &next,
                )?
                .to_wire()
            }
        };
        let pending = self.prepare_pending_control(store, owner, now)?;
        Ok(GovernancePreparation::Append(Box::new(pending), payload))
    }

    /// Install only the exact retained owner's durable delta. Failed candidates never restore
    /// a retryable old sender: the room is poisoned even if a context-control already committed.
    pub(crate) fn finish_pending_text(
        &mut self,
        store: &Store,
        completed: CompletedText,
    ) -> Result<Saved> {
        let CompletedText {
            pending,
            result,
            mut failure,
            ..
        } = completed;
        let Some(pending) = pending else {
            return result;
        };
        if !self
            .pending_text
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, &pending.owner))
        {
            return result;
        }
        self.pending_text = None;
        if !pending.committed.is_empty() {
            let me = pending.sender.author_id();
            if let Some(feed) = &pending.committed_feed {
                if let Err(error) = self.dag.commit_authored_feed(me, feed) {
                    failure = Some(error.to_string());
                }
                if pending.sparse {
                    self.sparse_applied_tips.insert(me, feed.seq);
                }
            }
            if pending.governance_changed {
                if let Err(error) = self.retire_governance() {
                    failure = Some(error.to_string());
                }
            }
            for entry in &pending.committed {
                if let Err(error) = self.note_committed_consent(entry) {
                    failure = Some(error.to_string());
                }
            }
            if let Some(presence) = pending.presence {
                self.presence.insert(me, presence);
            }
            self.next_log_id = pending.next_log_id;
            self.key_packages
                .published(self.next_log_id.saturating_sub(1));
            self.entries.committed();
            let order = (|| -> Result<_> {
                let read = self.entries.read(store, &self.sek, &self.channel_id)?;
                Ok((
                    read.order_revision(),
                    read.order_previous(None)?.map(|(clock, _)| clock),
                ))
            })();
            match order {
                Ok((revision, newest)) => self.dag.set_order_revision(revision, newest),
                Err(error) => failure = Some(error.to_string()),
            }
            self.gen.fetch_add(
                pending.committed.len() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        if result.is_ok() || pending.encrypted_control_committed || pending.read_committed {
            self.sender = pending.sender;
            if pending.rotation_committed {
                if let Some(rotation) = pending.rotation {
                    self.origins = rotation.origins;
                    install_rotation_history(&mut self.history, rotation.owed);
                }
            }
            if let Ok(Saved::Text(rendered)) = &result {
                if !pending.skipped.is_empty() {
                    if self.skipped.len() >= SKIPPED_KEPT {
                        self.skipped.pop_front();
                    }
                    self.skipped
                        .push_back((rendered.entry_hash, pending.skipped));
                }
                if let Err(error) = self.note_rendered(store, &rendered.entry_hash) {
                    failure = Some(error.to_string());
                }
            }
        }
        if let Some(error) = failure {
            self.poisoned = true;
            self.save_error = Some(error);
        }
        self.history_publication_changed.notify_waiters();
        result
    }

    pub(crate) fn release_pending_text(&mut self, owner: &Arc<()>, poison: bool) {
        if self
            .pending_text
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, owner))
        {
            self.pending_text = None;
            if poison {
                self.poisoned = true;
                self.save_error = Some("authored save worker stopped".to_owned());
            }
            self.history_publication_changed.notify_waiters();
        }
    }

    /// Release waiters when the actor consumes an owned publication, including a no-op.
    pub(crate) fn note_publication_complete(&self) {
        self.history_publication_changed.notify_waiters();
    }
}

impl PendingText {
    /// Runs entirely on one physical blocking worker, including nested derived transactions.
    pub(crate) fn run(
        mut self,
        store: &Store,
        signer: &crate::atrest::vault::VaultRootSigner,
        text: &str,
    ) -> CompletedText {
        let work = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            self.append_text(store, signer, text)?;
            if self.rotation.is_some() {
                self.rotate(store, signer)?;
            }
            Ok(())
        }));
        let (failure, error) = match work {
            Ok(Ok(())) => (None, None),
            Ok(Err(error)) => (Some(error.to_string()), Some(error)),
            Err(_) => (
                Some("authored save worker stopped".to_owned()),
                Some(Error::Profile("authored save worker stopped")),
            ),
        };
        let result = match self.durable_text.take() {
            Some(rendered) => Ok(rendered),
            None => Err(error.unwrap_or(Error::Profile("authored save did not complete"))),
        };
        #[cfg(feature = "test-knobs")]
        let rotated = self.rotation_committed;
        CompletedText {
            pending: Some(self),
            result: result.map(Saved::Text),
            failure,
            #[cfg(feature = "test-knobs")]
            rotated,
        }
    }

    pub(crate) fn run_governance(
        mut self,
        store: &Store,
        signer: &dyn RootSigner,
        payload: Vec<u8>,
    ) -> CompletedText {
        let work =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Digest32> {
                let kind = classify_payload(&payload)?;
                let signed_kind = if crate::governance::step_policy::is_step_policy(&payload) {
                    SignedEntryKind::StepPolicy
                } else {
                    SignedEntryKind::Governance
                };
                let now = crate::time::Ms(self.now_millis);
                self.append_control_owned(store, signer, payload, kind, signed_kind, now)
            }));
        let result = match work {
            Ok(result) => result.map(|hash| Saved::Governance(Some(hash))),
            Err(_) => Err(Error::Profile("authored save worker stopped")),
        };
        self.complete_control(result)
    }

    pub(crate) fn control_head(&self, author: &Digest32) -> u64 {
        self.dag.feed(author).map_or(0, |feed| feed.max_seq())
    }

    pub(crate) fn committed_control(&self, payload_hash: &Digest32, kind: SignedEntryKind) -> bool {
        self.committed.iter().any(|entry| {
            entry.skeleton.payload_hash == *payload_hash
                && entry
                    .skeleton
                    .v2
                    .as_ref()
                    .is_none_or(|typed| typed.kind == kind)
        })
    }

    /// Call only on the physical owner worker. A later failure retains earlier durable controls.
    pub(crate) fn append_control_owned(
        &mut self,
        store: &Store,
        signer: &dyn RootSigner,
        payload: Vec<u8>,
        kind: EntryKind,
        signed_kind: SignedEntryKind,
        now: crate::time::Ms,
    ) -> Result<Digest32> {
        self.append_control_owned_with(store, signer, payload, kind, signed_kind, now, &[])
    }

    /// The caller's key-material rows share the exact signed control's durable transaction.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn append_control_owned_with(
        &mut self,
        store: &Store,
        signer: &dyn RootSigner,
        payload: Vec<u8>,
        kind: EntryKind,
        signed_kind: SignedEntryKind,
        now: crate::time::Ms,
        extra: &[(u64, Option<SealedSegment>)],
    ) -> Result<Digest32> {
        self.now_millis = now.get();
        self.append(store, signer, payload, kind, signed_kind, None, extra, None)?;
        let hash = self
            .committed
            .last()
            .ok_or(Error::Profile("authored control save did not complete"))?
            .entry_hash();
        self.cleanup(store)?;
        Ok(hash)
    }

    pub(crate) fn complete_control(self, result: Result<Saved>) -> CompletedText {
        let failure = result.as_ref().err().map(ToString::to_string);
        #[cfg(feature = "test-knobs")]
        let rotated = self.rotation_committed;
        CompletedText {
            pending: Some(self),
            result,
            failure,
            #[cfg(feature = "test-knobs")]
            rotated,
        }
    }

    fn context(
        &self,
        store: &Store,
        signer: &dyn RootSigner,
    ) -> Result<Option<(ControlContext, Vec<EntryReference>, bool)>> {
        if !self.sparse {
            return Ok(None);
        }
        self.sek.with(|sek| {
            local_history::authored_context(
                &self.entries.read(store, sek, &self.room)?,
                self.room,
                &self.authors,
                self.dag
                    .feed(&signer.fingerprint())
                    .map_or(0, |feed| feed.max_seq()),
                &signer.fingerprint(),
            )
            .map(Some)
        })
    }

    fn append_text(&mut self, store: &Store, signer: &dyn RootSigner, text: &str) -> Result<()> {
        let content = Content::text(self.now_millis, text)?;
        if self
            .context(store, signer)?
            .is_some_and(|(_, _, changed)| changed)
        {
            self.append(
                store,
                signer,
                Vec::new(),
                EntryKind::Content,
                SignedEntryKind::ContextUpdate,
                None,
                &[],
                None,
            )?;
            self.cleanup(store)?;
        }
        let plaintext = Zeroizing::new(content.to_canonical_vec());
        let payload = self.sender.encrypt(&plaintext)?.to_wire();
        #[cfg(feature = "mutant-sender")]
        let payload = crate::log::sync::mutant::authored(payload);
        #[cfg(feature = "mutant-sender")]
        let payload = if crate::log::sync::mutant::misbound() {
            let (iteration, key) = self.sender.current_position();
            let skdm = self.sender.skdm_for(signer, iteration, key)?;
            crate::governance::membership::issue_consent_grant(
                signer,
                &self.room,
                self.epoch + 7,
                signer.fingerprint(),
                &skdm,
                self.history_mode,
            )?
            .to_wire()
        } else {
            payload
        };
        let rendered = Rendered {
            entry_hash: [0; 32],
            author: signer.fingerprint(),
            created_millis: self.now_millis,
            text: content.text,
            arrival: self.next_log_id,
            shown_at_ms: 0,
            late: false,
            owed: false,
        };
        self.append(
            store,
            signer,
            payload,
            EntryKind::Content,
            SignedEntryKind::Content,
            Some(rendered),
            &[],
            None,
        )?;
        if let Some(rendered) = &self.durable_text {
            self.seal_visibility(store, rendered)?;
        }
        self.cleanup(store)
    }

    #[allow(clippy::too_many_arguments)]
    fn append(
        &mut self,
        store: &Store,
        signer: &dyn RootSigner,
        payload: Vec<u8>,
        kind: EntryKind,
        signed_kind: SignedEntryKind,
        mut rendered: Option<Rendered>,
        extra: &[(u64, Option<SealedSegment>)],
        boundary: Option<&recovery::AppendBoundary>,
    ) -> Result<()> {
        let keep_log = kind == EntryKind::Governance || signed_kind == SignedEntryKind::StepPolicy;
        let context = self.context(store, signer)?;
        let recipient = if self.sparse && signed_kind == SignedEntryKind::KeyPackage {
            Some(crate::node::keypackage::KeyPackage::from_wire(&payload)?.recipient)
        } else {
            None
        };
        let me = signer.fingerprint();
        let seq = self
            .dag
            .feed(&me)
            .map_or(0, |feed| feed.max_seq())
            .checked_add(1)
            .ok_or(Error::MalformedAtRest("feed sequence exhausted"))?;
        let entry = self.sek.with(|sek| {
            let read = self.entries.read(store, sek, &self.room)?;
            let hash = |seq| -> Result<Digest32> {
                read.get(&me, seq)?
                    .map(|entry| entry.entry_hash())
                    .ok_or(Error::MalformedAtRest("local feed predecessor missing"))
            };
            let typed = context.as_ref().map(|(pre, seen, _)| EntryV2 {
                kind: signed_kind,
                scope: LogScope::Public,
                pre_context: pre.hash(),
                seen: seen.clone(),
                recipient,
            });
            let seen = match &context {
                Some((_, seen, _)) => seen.iter().map(|reference| reference.hash).collect(),
                None => self.dag.seen_for(&read, &me)?,
            };
            Entry::build_signed(
                signer,
                EntrySkeleton {
                    v2: typed,
                    author_id: me,
                    seq,
                    prev_hash: if seq == 1 { ZERO_HASH } else { hash(seq - 1)? },
                    lipmaa_backlink: if seq == 1 {
                        ZERO_HASH
                    } else {
                        hash(lipmaa(seq))?
                    },
                    channel_id: self.room,
                    epoch: self.epoch,
                    algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
                    payload_hash: sha256(&payload),
                    payload_len: payload.len() as u64,
                    end_of_feed: false,
                    claimed_ms: self.now_millis,
                    seen,
                },
                payload,
            )
        })?;
        let prepared = if let Some((pre, _, _)) = context {
            let mut budget = LocalAppendBudget::new();
            budget.reserve_context_preparation()?;
            Some(self.sek.with(|sek| {
                local_history::prepare(
                    &self.entries.read(store, sek, &self.room)?,
                    signer,
                    &entry,
                    pre,
                    budget,
                )
            })?)
        } else {
            None
        };
        // The worker owns the candidate DAG. Neither staging writes nor promotion chunk commits
        // publish sender/feed/governance mirrors into the live room.
        self.sek.with(|sek| {
            let mut staging = self.entries.staging(store, sek, &self.room);
            self.dag
                .accept(
                    &mut staging,
                    entry.clone(),
                    kind,
                    &signer.public_key(),
                    &self.admission,
                )
                .map_err(|why| match why {
                    crate::log::dag::Rejected::Local(error) => error,
                    crate::log::dag::Rejected::PreCheckpoint => {
                        Error::MalformedGovernance("entry is at or below its author's checkpoint")
                    }
                    _ => Error::MalformedGovernance("entry failed the acceptance predicate"),
                })?;
            self.entries.prepare_publication(
                store,
                sek,
                &self.room,
                entry_store::Publication {
                    witness: &entry,
                    from: seq,
                    first_log: self.next_log_id,
                    received_ms: self.now_millis,
                    bodyless_prefix: false,
                    origin: self.origin,
                    local_contexts: prepared
                        .as_ref()
                        .map(|prepared| (&prepared.pre, &prepared.post)),
                },
            )
        })?;
        let id = self.next_log_id;
        if let Some(rendered) = &mut rendered {
            rendered.entry_hash = entry.entry_hash();
        }
        // Acquisition and commit are outside every room/actor/key-byte guard. Batch stays on
        // this physical thread, preserving the existing durable received-debt settlement.
        let mut batch = store.batch()?;
        let accepted = self.sek.with(|sek| {
            if let Some(boundary) = boundary {
                boundary.check(&batch, sek, &self.room)?;
            }
            let settlement = {
                let mut index = self.entries.write(&mut batch, sek, &self.room)?;
                index.publish_promotion()?;
                let settlement = if let Some(prepared) = &prepared {
                    Some(index.publish_local_history(
                        entry_store::sparse::LocalHistoryPublication {
                            entry: &entry,
                            header: &prepared.header,
                            head: &prepared.head,
                            consistency: &prepared.consistency,
                            included: &prepared.included,
                            pre_context: &prepared.pre,
                            post_context: &prepared.post,
                            ranges: &prepared.ranges,
                        },
                    )?)
                } else {
                    None
                };
                index.seal()?;
                settlement
            };
            session_projection::private_index::observe_public(
                &mut batch, sek, &self.room, &entry, self.epoch,
            )?;
            let late = self
                .entries
                .read(store, sek, &self.room)?
                .child_after(&entry.entry_hash(), None)?
                .is_some();
            let accepted = governance::accepted_into(
                &mut batch,
                &self.entries,
                sek,
                &self.room,
                &self.authors,
                &self.creator,
                &me,
                id,
                &entry,
                late,
            )?;
            if accepted.work_changed {
                if let Ok(GovBody::Presence(presence)) = GovEntry::body_bound_to(&entry) {
                    let mut state = self.presence.unwrap_or(governance::Presence {
                        last: (entry.skeleton.seq, presence.body.here),
                        back: None,
                    });
                    state.last = (entry.skeleton.seq, presence.body.here);
                    if presence.body.here {
                        state.back = Some((entry.skeleton.seq, entry.skeleton.claimed_ms));
                    }
                    let mut index = self.entries.write(&mut batch, sek, &self.room)?;
                    index.note_presence(me, state)?;
                    index.seal()?;
                }
            }
            if keep_log {
                let log = seal_segment(sek, SegmentKind::LogDb, id, &entry.to_wire())?;
                batch.put_segment(&self.room, SegmentKind::LogDb, id, &log)?;
            }
            if self.encrypted_control {
                let log = seal_segment(sek, SegmentKind::LogDb, id, &entry.to_wire())?;
                let sender = seal_segment(
                    sek,
                    SegmentKind::KeyMaterial,
                    SEG_SENDER,
                    &self.sender.to_state(),
                )?;
                let seen = seal_segment(
                    sek,
                    SegmentKind::Index,
                    id,
                    &first_seen_bytes(self.now_millis, false),
                )?;
                batch.put_segment(&self.room, SegmentKind::LogDb, id, &log)?;
                batch.put_segment(&self.room, SegmentKind::KeyMaterial, SEG_SENDER, &sender)?;
                batch.put_segment(&self.room, SegmentKind::Index, id, &seen)?;
                let mut index = self.entries.write(&mut batch, sek, &self.room)?;
                index.set_retention(
                    entry.entry_hash(),
                    Some(Tracked {
                        log_id: id,
                        first_seen_ms: self.now_millis,
                        steps: false,
                        claimed_ms: Some(self.now_millis),
                        cache_id: None,
                    }),
                )?;
                index.seal()?;
            }
            if let Some(read) = &mut self.read_append {
                read.queue(
                    &mut batch,
                    &self.entries,
                    sek,
                    &self.room,
                    &entry,
                    id,
                    &self.sender,
                )?;
            }
            if let Some(rendered) = &rendered {
                let log = seal_segment(sek, SegmentKind::LogDb, id, &entry.to_wire())?;
                let cache =
                    seal_segment(sek, SegmentKind::PlaintextCache, id, &cache_bytes(rendered))?;
                let sender = seal_segment(
                    sek,
                    SegmentKind::KeyMaterial,
                    SEG_SENDER,
                    &self.sender.to_state(),
                )?;
                let seen = seal_segment(
                    sek,
                    SegmentKind::Index,
                    id,
                    &first_seen_bytes(self.now_millis, false),
                )?;
                batch.put_segment(&self.room, SegmentKind::LogDb, id, &log)?;
                batch.put_segment(&self.room, SegmentKind::PlaintextCache, id, &cache)?;
                batch.put_segment(&self.room, SegmentKind::KeyMaterial, SEG_SENDER, &sender)?;
                batch.put_segment(&self.room, SegmentKind::Index, id, &seen)?;
                let mut index = self.entries.write(&mut batch, sek, &self.room)?;
                index.put_rendered(rendered, shown_now())?;
                index.set_retention(
                    entry.entry_hash(),
                    Some(Tracked {
                        log_id: id,
                        first_seen_ms: self.now_millis,
                        steps: false,
                        claimed_ms: Some(self.now_millis),
                        cache_id: Some(id),
                    }),
                )?;
                index.seal()?;
            }
            for (slot, segment) in extra {
                if let Some(segment) = segment {
                    batch.put_segment(&self.room, SegmentKind::KeyMaterial, *slot, segment)?;
                }
            }
            if let Some(boundary) = boundary {
                boundary.apply(&mut batch, &self.room)?;
            }
            if let Some(settlement) = settlement {
                let mut index = self.entries.write(&mut batch, sek, &self.room)?;
                index.finish_local_history_effect(&entry, settlement)?;
                index.seal()?;
            }
            Ok(accepted)
        })?;
        batch.commit()?;
        self.governance_changed |= accepted.work_changed;
        self.encrypted_control_committed |= self.encrypted_control;
        self.read_committed |= self.read_append.is_some();
        if rendered.is_some() {
            self.durable_text = rendered;
        }
        self.committed_feed = self.dag.authored_feed(&me);
        if let Ok(GovBody::Presence(presence)) = GovEntry::body_bound_to(&entry) {
            let mut state = self.presence.unwrap_or(governance::Presence {
                last: (seq, presence.body.here),
                back: None,
            });
            state.last = (seq, presence.body.here);
            if presence.body.here {
                state.back = Some((seq, self.now_millis));
            }
            self.presence = Some(state);
        }
        self.entries.committed();
        self.next_log_id = id.saturating_add(1);
        self.committed.push(entry);
        Ok(())
    }

    fn seal_visibility(&self, store: &Store, rendered: &Rendered) -> Result<()> {
        let mut batch = store.batch()?;
        batch.derived();
        self.sek.with(|sek| {
            let mut index = self.entries.write(&mut batch, sek, &self.room)?;
            index.remove_rendered(&rendered.entry_hash)?;
            index.put_rendered(rendered, shown_now())?;
            index.seal()
        })?;
        batch.commit()?;
        self.entries.committed();
        Ok(())
    }

    fn cleanup(&self, store: &Store) -> Result<()> {
        loop {
            let mut batch = store.batch()?;
            batch.derived();
            let done = self.sek.with(|sek| {
                let mut index = self.entries.write(&mut batch, sek, &self.room)?;
                let done = index.cleanup_chunk()?;
                index.seal()?;
                Ok(done)
            })?;
            batch.commit()?;
            self.entries.committed();
            if done {
                return Ok(());
            }
        }
    }

    fn rotate(
        &mut self,
        store: &Store,
        signer: &crate::atrest::vault::VaultRootSigner,
    ) -> Result<()> {
        let Some(mut rotation) = self.rotation.take() else {
            return Ok(());
        };
        self.now_millis = self.rotation_now;
        let next = self.sender.rotated(self.now_millis)?;
        let mint = crate::node::consent_order::stamp_mint(store, signer, rotation.newest_mint)?;
        retain_generation(
            &mut rotation.origins,
            &self.room,
            self.epoch,
            &signer.fingerprint(),
            &next,
            self.now_millis,
            mint,
        )?;
        let extra = self.sek.with(|sek| {
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
        if self.sparse {
            let statement = crate::governance::presence::Presence::build(
                signer,
                &self.room,
                self.epoch,
                true,
                next.chain_id(),
            )?;
            self.append(
                store,
                signer,
                statement.to_wire(),
                EntryKind::Governance,
                SignedEntryKind::Governance,
                None,
                &extra,
                None,
            )?;
        } else {
            let mut batch = store.batch()?;
            for (slot, segment) in &extra {
                if let Some(segment) = segment {
                    batch.put_segment(&self.room, SegmentKind::KeyMaterial, *slot, segment)?;
                }
            }
            batch.commit()?;
        }
        self.sender = next;
        self.rotation_committed = true;
        self.rotation = Some(rotation);
        self.cleanup(store)
    }
}
