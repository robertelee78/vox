//! Native node-global policy transactions and the existing room-save adapter.
//! Queueing, command replies and publication ownership remain with the retained save owner.
use super::*;
use crate::atrest::vault::VaultRootSigner;
use crate::node::channel::pending_trust::{CompletedTrust, PendingTrust, TrustSaved, TrustWrite};
use crate::node::consent_order::{ConsentOrder, Stamp};
use crate::node::pending_consent::PendingConsents;
use crate::node::pending_lock::PendingLocks;
use crate::node::store::Store;
use crate::node::trust::{Capability, HistoryGrant, Keyring};

mod grant;
pub(super) use grant::{GrantChange, GrantSaved};
mod startup;
pub(super) use startup::{
    apply_headless_policy, settle_headless_startup_policy, settle_startup_policy, StartupPolicy,
};

enum PolicyWrite {
    Untrust {
        target: Digest32,
    },
    Managed {
        denied: Vec<Digest32>,
        grants: Vec<(Digest32, String, Capability)>,
        floor: u64,
    },
    ImportBlacklist {
        history: crate::node::decisions::DecisionLog,
    },
}

pub(super) enum Policy {
    Untrust {
        target: Digest32,
    },
    Managed(Managed),
    Grant {
        change: GrantChange,
        floor: u64,
    },
    ImportBlacklist {
        history: crate::node::decisions::DecisionLog,
    },
    DismissOffers {
        bases: Vec<(Digest32, crate::node::api::OfferBasis)>,
        decision: Option<(
            crate::node::decisions::DecisionLog,
            u64,
            crate::node::decisions::Decision,
        )>,
    },
    RecordDecision {
        log: crate::node::decisions::DecisionLog,
        now: u64,
        decision: crate::node::decisions::Decision,
    },
}

pub(super) enum PolicyCompleted {
    Saved(crate::error::Result<PolicySaved>),
    Managed(ManagedCompleted),
    Dismissed(crate::error::Result<Option<crate::node::offers::DismissedOffers>>),
    Recorded,
}

impl Policy {
    pub(super) fn run(self, store: &Store, signer: &VaultRootSigner) -> PolicyCompleted {
        match self {
            Self::Untrust { target } => {
                PolicyCompleted::Saved(PolicyWrite::Untrust { target }.run(store, signer))
            }
            Self::ImportBlacklist { history } => {
                PolicyCompleted::Saved(PolicyWrite::ImportBlacklist { history }.run(store, signer))
            }
            Self::Managed(work) => PolicyCompleted::Managed(work.run(store, signer)),
            Self::Grant { change, floor } => {
                PolicyCompleted::Saved(grant::run(change, floor, store, signer))
            }
            Self::RecordDecision { log, now, decision } => {
                log.record(now, &decision);
                PolicyCompleted::Recorded
            }
            Self::DismissOffers { bases, decision } => {
                let result = crate::node::offers::native::dismiss(store, signer, bases);
                if let Some((log, now, decision)) = decision {
                    log.record(now, &decision);
                }
                PolicyCompleted::Dismissed(result)
            }
        }
    }
}

/// An exact committed keyring and exact edits to actor-held pending-key metadata. Never return
/// a captured replacement PendingConsents/PendingLocks map: independent room saves update them.
pub(super) struct PolicySaved {
    pub(super) trust: Keyring,
    pub(super) removed: Vec<Digest32>,
    pub(super) changed_drive: Vec<(Digest32, bool)>,
    pub(super) grant: Option<GrantSaved>,
}

impl PolicyWrite {
    /// Physical worker only. Writer admission precedes every global-map read. No actor,
    /// ChannelState guard or Computer.state guard may surround this call.
    pub(super) fn run(
        self,
        store: &Store,
        signer: &VaultRootSigner,
    ) -> crate::error::Result<PolicySaved> {
        self.run_checked(store, signer, || Ok(()))
    }

    fn run_checked(
        self,
        store: &Store,
        signer: &VaultRootSigner,
        before_commit: impl FnOnce() -> crate::error::Result<()>,
    ) -> crate::error::Result<PolicySaved> {
        let mut batch = store.batch()?;
        let mut trust = Keyring::load(store, signer)?;
        if let Self::ImportBlacklist { history } = self {
            if !trust.local_history_imported() {
                trust.import_local_removals(history.local_trust_removals()?);
                trust.queue_save(&mut batch, signer)?;
                before_commit()?;
                batch.commit()?;
            }
            return Ok(PolicySaved {
                trust,
                removed: Vec::new(),
                changed_drive: Vec::new(),
                grant: None,
            });
        }
        let mut pending = PendingConsents::load(store, signer)?;
        let mut locks = PendingLocks::load(store, signer)?;
        let rooms = store.channels()?;
        let mut removed = Vec::new();
        let mut newly = Vec::new();
        let mut changed_drive = Vec::new();
        let mut pending_changed = false;
        let (denied, grants, floor) = match self {
            Self::Untrust { target } => {
                if !trust.is_trusted(&target) {
                    return Err(Error::Profile("identity is not trusted"));
                }
                (vec![target], Vec::new(), 0)
            }
            Self::Managed {
                denied,
                grants,
                floor,
            } => (denied, grants, floor),
            Self::ImportBlacklist { .. } => {
                return Err(Error::Profile("blacklist import entered grant preparation"));
            }
        };
        for target in denied {
            if !trust.is_trusted(&target) {
                continue;
            }
            for room in &rooms {
                if !locks.insert(*room, target) {
                    return Err(Error::Profile("trust removal could not be recorded"));
                }
            }
            pending_changed |= pending.forget(&target);
            changed_drive.push((target, trust.has_drive(&target)));
            trust.untrust(&target);
            removed.push(target);
        }
        for (target, alias, capability) in grants {
            locks.forget(&target);
            if trust.capability(&target) == Some(capability) {
                continue;
            }
            let was_trusted = trust.is_trusted(&target);
            if !was_trusted {
                newly.push(target);
            }
            changed_drive.push((target, trust.has_drive(&target)));
            let name = trust.petname(&target).unwrap_or(&alias).to_owned();
            let history = if was_trusted {
                trust.history(&target)
            } else {
                HistoryGrant::Now
            };
            trust.trust_as(target, &name, history, capability)?;
        }
        if pending_changed {
            pending.queue_save(&mut batch, signer)?;
        }
        ConsentOrder::queue_policy(&mut batch, signer, &removed, &newly, floor)?;
        locks.queue_save(&mut batch, signer)?;
        trust.queue_save(&mut batch, signer)?;
        before_commit()?;
        batch.commit()?;
        Ok(PolicySaved {
            trust,
            removed,
            changed_drive,
            grant: None,
        })
    }
}

/// An owned Computer application. The original exclusive publication transition fences policy
/// movement through journal preparation, node-store commit and receipt; Computer.state is used
/// only by the existing short validation/snapshot methods, never retained across native I/O.
pub(super) struct Managed {
    pub(super) computer: Arc<crate::node::computer::Computer>,
    pub(super) guard: computer::ComputerPolicyGuard,
    pub(super) transition: Arc<crate::node::computer::ComputerPublicationTransition>,
    pub(super) plan: crate::node::computer::PolicyPlan,
    pub(super) aliases: Vec<(Digest32, String)>,
    pub(super) floor: u64,
    pub(super) node: Digest32,
    pub(super) node_name: String,
}

pub(super) struct ManagedCompleted {
    computer: Arc<crate::node::computer::Computer>,
    transition: Arc<crate::node::computer::ComputerPublicationTransition>,
    revision: u64,
    expired: bool,
    node: Digest32,
    /// Present as soon as the node-store commit succeeds, even if its later journal receipt
    /// fails. Installation must retain this fact, invalidate the old applied revision and keep
    /// the prepared recovery obligation instead of pretending the keyring commit never happened.
    pub(super) committed: Option<PolicySaved>,
    pub(super) result: crate::error::Result<bool>,
}

impl Managed {
    pub(super) fn run(self, store: &Store, signer: &VaultRootSigner) -> ManagedCompleted {
        let mut committed = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.guard.active(Some(&self.computer))?;
            if self
                .computer
                .policy_current(self.plan.revision, self.plan.expired, self.node)
            {
                return Ok(true);
            }
            let covered: Vec<_> = self
                .plan
                .grants
                .iter()
                .map(|(id, _, _)| *id)
                .chain(self.plan.denied.iter().copied())
                .collect();
            let deadline = match &self.guard {
                computer::ComputerPolicyGuard::Deadline { deadline, .. } => *deadline,
                computer::ComputerPolicyGuard::Current { change, .. } => change.apply_deadline(),
            };
            let change = match &self.guard {
                computer::ComputerPolicyGuard::Current { change, .. } => Some(*change),
                computer::ComputerPolicyGuard::Deadline { .. } => None,
            };
            if self.computer.binding_group().is_some() && !self.computer.current_revision_expired()
            {
                match change {
                    Some(change) => {
                        if !self.computer.bind_node_for_change(
                            signer,
                            &self.node_name,
                            change,
                            &self.transition,
                        )? {
                            return Err(Error::ComputerPolicySuperseded);
                        }
                    }
                    None => self.computer.bind_node_until(
                        signer,
                        &self.node_name,
                        deadline,
                        &self.transition,
                    )?,
                }
            }
            let prepared = match change {
                Some(change) => self.computer.prepare_application_for_change(
                    self.node,
                    self.plan.revision,
                    self.plan.expired,
                    &covered,
                    change,
                    &self.transition,
                )?,
                None => self.computer.prepare_application_until(
                    self.node,
                    self.plan.revision,
                    self.plan.expired,
                    &covered,
                    deadline,
                    &self.transition,
                )?,
            };
            if !prepared {
                return Ok(false);
            }
            let aliases_retained = match change {
                Some(change) => self.computer.retain_aliases_for_change(
                    self.node,
                    &self.aliases,
                    change,
                    &self.transition,
                )?,
                None => {
                    self.computer.retain_aliases_until(
                        self.node,
                        &self.aliases,
                        deadline,
                        Some(&self.transition),
                    )?;
                    true
                }
            };
            if !aliases_retained {
                return Err(Error::ComputerPolicySuperseded);
            }
            let grants = self
                .plan
                .grants
                .iter()
                .map(|(id, name, capability)| {
                    (
                        *id,
                        self.computer
                            .alias(&self.node, id)
                            .unwrap_or_else(|| name.clone()),
                        *capability,
                    )
                })
                .collect();
            // This existing API validates under short state ownership, drops that guard, then
            // enters the native node transaction under this SAME retained transition.
            let saved = self.computer.commit_application_if_current(
                self.plan.revision,
                self.plan.expired,
                || {
                    self.guard.active(Some(&self.computer))?;
                    PolicyWrite::Managed {
                        denied: self.plan.denied.clone(),
                        grants,
                        floor: self.floor,
                    }
                    .run_checked(store, signer, || self.guard.active(Some(&self.computer)))
                },
                &self.transition,
            )?;
            let Some(saved) = saved else {
                return Ok(false);
            };
            committed = Some(saved);
            // No deadline/supersession escape is permitted between irreversible commit and its
            // durable Current/Reconcile classification; these APIs preserve the recovery journal.
            let receipt = if self.plan.expired {
                self.computer.mark_expired_until(
                    self.node,
                    self.plan.revision,
                    deadline,
                    &self.transition,
                )?
            } else {
                self.computer.mark_applied_until(
                    self.node,
                    self.plan.revision,
                    &covered,
                    deadline,
                    Some(&self.transition),
                )?
            };
            Ok(receipt == crate::node::computer::ApplicationReceipt::Current)
        }))
        .unwrap_or_else(|_| Err(Error::Profile("Computer trust save worker stopped")));
        ManagedCompleted {
            computer: self.computer,
            transition: self.transition,
            revision: self.plan.revision,
            expired: self.plan.expired,
            node: self.node,
            committed,
            result,
        }
    }
}

/// Uses the common maintenance preparation/result cell, not a second task queue.
pub(super) struct Work(pub(super) TrustWrite);
pub(super) struct Prepared(PendingTrust);
pub(super) struct Completed(CompletedTrust);

impl Work {
    pub(super) fn prepare(
        self,
        channel: &mut ChannelState,
        store: &Arc<Store>,
        owner: Arc<()>,
    ) -> crate::error::Result<Prepared> {
        channel
            .prepare_pending_trust(store, owner, self.0)
            .map(Prepared)
    }
}
impl Prepared {
    pub(super) fn run(self, store: &Store, signer: &VaultRootSigner) -> Completed {
        Completed(self.0.run(store, signer))
    }
}
impl Completed {
    pub(super) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.0.can_install(channel, owner)
    }
    pub(super) fn take_history_pin(
        &mut self,
    ) -> Option<crate::node::channel::history::PendingHistoryRead> {
        self.0.take_history_pin()
    }
    pub(super) fn finish(self, channel: &mut ChannelState) -> crate::error::Result<TrustSaved> {
        channel.finish_pending_trust(self.0)
    }
    pub(super) fn into_result(self) -> crate::error::Result<TrustSaved> {
        self.0.result
    }
}

#[derive(Clone, Copy)]
pub(super) enum ReconcileScope {
    Preparation,
    Removals,
    Cache,
}

#[derive(Clone, Copy)]
enum Cursor {
    Removal,
    Consent,
}
#[derive(Clone, Copy)]
enum ReconcileStage {
    DeleteInitial,
    Removals,
    Withdraw { target: Digest32, cursor: Cursor },
    DeleteAfter { target: Digest32, cursor: Cursor },
    Consents,
    Marks,
    Complete,
}

/// This bounded continuation belongs to the ORIGINAL open/preparing room instance. A worker
/// completion is applied here only after exact-pointer/attachment/owner installation succeeds.
/// In particular a preparing room is not looked up in self.channels and is never declared done
/// merely because it has no published entry there.
pub(super) struct Reconcile {
    trusted: BTreeSet<Digest32>,
    scope: ReconcileScope,
    removal_after: Option<Digest32>,
    consent_after: Option<Digest32>,
    stage: ReconcileStage,
}

pub(super) enum ReconcileAction {
    Trust(Work),
    Withdraw { target: Digest32 },
    Progress,
    Complete,
}

impl Reconcile {
    pub(super) fn new(trusted: BTreeSet<Digest32>, scope: ReconcileScope) -> Self {
        Self {
            trusted,
            scope,
            removal_after: None,
            consent_after: None,
            stage: ReconcileStage::DeleteInitial,
        }
    }

    pub(super) fn matches_trust(&self, trusted: &BTreeSet<Digest32>) -> bool {
        &self.trusted == trusted
    }

    /// Read-only room preparation. consent_page is the existing bounded committed reader;
    /// no Store::batch, withdrawal or mark persistence occurs under this short room guard.
    pub(super) fn action(
        &mut self,
        channel: &ChannelState,
        store: &Store,
    ) -> crate::error::Result<ReconcileAction> {
        Ok(match self.stage {
            ReconcileStage::DeleteInitial => ReconcileAction::Trust(Work(TrustWrite::Delete {
                trusted: self.trusted.clone(),
                withdrawn: None,
            })),
            ReconcileStage::Removals => ReconcileAction::Trust(Work(TrustWrite::RemovalPage {
                trusted: self.trusted.clone(),
                after: self.removal_after,
            })),
            ReconcileStage::Withdraw { target, .. } => ReconcileAction::Withdraw { target },
            ReconcileStage::DeleteAfter { target, .. } => {
                ReconcileAction::Trust(Work(TrustWrite::Delete {
                    trusted: self.trusted.clone(),
                    withdrawn: Some(target),
                }))
            }
            ReconcileStage::Consents => {
                let page = channel.consent_page(store, &channel.me(), self.consent_after, 64)?;
                if let Some(target) = page
                    .targets
                    .iter()
                    .find(|member| !self.trusted.contains(*member))
                    .copied()
                {
                    self.stage = ReconcileStage::Withdraw {
                        target,
                        cursor: Cursor::Consent,
                    };
                    ReconcileAction::Withdraw { target }
                } else if let Some(after) = page.next {
                    self.consent_after = Some(after);
                    ReconcileAction::Progress
                } else {
                    self.stage = ReconcileStage::Marks;
                    ReconcileAction::Trust(Work(TrustWrite::MarkDecisions))
                }
            }
            ReconcileStage::Marks => ReconcileAction::Trust(Work(TrustWrite::MarkDecisions)),
            ReconcileStage::Complete => ReconcileAction::Complete,
        })
    }

    /// Call only for a real matching successful consent-save completion. Known-absent is a
    /// successful ledger-cleanup commit, not a fabricated revocation or permission to skip debt.
    pub(super) fn withdrawn(
        &mut self,
        saved: &crate::node::channel::pending_text::consent::ConsentSaved,
    ) -> crate::error::Result<()> {
        let ReconcileStage::Withdraw { target, cursor } = self.stage else {
            return Err(Error::Profile("unexpected trust withdrawal completion"));
        };
        if !matches!(
            saved,
            crate::node::channel::pending_text::consent::ConsentSaved::Withdrawn(_)
        ) {
            return Err(Error::Profile("trust withdrawal returned a consent grant"));
        }
        self.stage = ReconcileStage::DeleteAfter { target, cursor };
        Ok(())
    }

    pub(super) fn saved(&mut self, saved: &TrustSaved) -> crate::error::Result<()> {
        match (&self.stage, saved) {
            (
                ReconcileStage::DeleteInitial,
                TrustSaved::Deleted {
                    debt_cleared: None, ..
                },
            ) => {
                self.stage = match self.scope {
                    ReconcileScope::Cache => ReconcileStage::Marks,
                    _ => ReconcileStage::Removals,
                };
            }
            (
                ReconcileStage::Removals,
                TrustSaved::RemovalPage {
                    target,
                    after,
                    done,
                },
            ) => {
                self.removal_after = *after;
                self.stage = if let Some(target) = target {
                    ReconcileStage::Withdraw {
                        target: *target,
                        cursor: Cursor::Removal,
                    }
                } else if *done {
                    match self.scope {
                        ReconcileScope::Preparation => ReconcileStage::Consents,
                        ReconcileScope::Removals => ReconcileStage::Complete,
                        ReconcileScope::Cache => ReconcileStage::Marks,
                    }
                } else {
                    ReconcileStage::Removals
                };
            }
            (
                ReconcileStage::DeleteAfter { target, cursor },
                TrustSaved::Deleted {
                    debt_cleared: Some(cleared),
                    ..
                },
            ) if target == cleared => match cursor {
                Cursor::Removal => {
                    self.removal_after = Some(*target);
                    self.stage = ReconcileStage::Removals;
                }
                Cursor::Consent => {
                    self.consent_after = Some(*target);
                    self.stage = ReconcileStage::Consents;
                }
            },
            (ReconcileStage::Marks, TrustSaved::Marked) => self.stage = ReconcileStage::Complete,
            _ => return Err(Error::Profile("unexpected trust save completion")),
        }
        Ok(())
    }
}

/// The global policy owner retains only these exact room bindings and committed-read pins,
/// never a room mutex guard. Failed preflight releases every reservation before returning.
pub(super) struct PolicyRoom {
    pub(super) room: Digest32,
    pub(super) instance: SharedChannel,
    pub(super) owner: Arc<()>,
    _pin: crate::node::channel::history::PendingHistoryRead,
}

pub(super) fn reserve_policy_rooms(
    mut rooms: Vec<(Digest32, SharedChannel)>,
    store: &Arc<Store>,
    owner: Arc<()>,
    require_append: bool,
    wait: bool,
) -> crate::error::Result<Vec<PolicyRoom>> {
    rooms.sort_by_key(|(room, _)| *room);
    let mut reserved: Vec<PolicyRoom> = Vec::with_capacity(rooms.len());
    let result = (|| {
        for (room, instance) in rooms {
            let mut channel = if wait {
                instance.blocking_lock()
            } else {
                instance
                    .try_lock()
                    .map_err(|_| Error::StreamRefused("a room change is pending"))?
            };
            if require_append {
                channel.ensure_local_append_available(store)?;
            }
            let pin = channel.reserve_pending_write(store, Arc::clone(&owner))?;
            drop(channel);
            reserved.push(PolicyRoom {
                room,
                instance,
                owner: Arc::clone(&owner),
                _pin: pin,
            });
        }
        Ok(())
    })();
    if let Err(error) = result {
        // Physical preparation worker only. A concurrent nondisk reader can briefly own a room;
        // waiting for that reader here is not actor/Store/Computer.state ownership.
        for room in &mut reserved {
            room.instance
                .blocking_lock()
                .release_pending_text(&room.owner, false);
        }
        return Err(error);
    }
    Ok(reserved)
}

impl Node {
    /// Matching attachment only, under the ORIGINAL publication/journal owner. This installs
    /// committed metadata facts; it does not certify room withdrawals or clear any room debt.
    pub(super) fn install_owned_policy(&mut self, saved: PolicySaved) {
        if !saved.removed.is_empty() {
            if let Some(net) = self.net.as_ref() {
                net.forget_board_exchanges();
            }
        }
        if let Some((room, peer, instance, request, generation)) =
            self.history_demand.note_route_trust_change()
        {
            self.bounded_sync
                .cancel_unstarted_archive_admission(room, peer, instance, request, generation);
            self.sched_rooms.insert(room);
        }
        for target in &saved.removed {
            // The native transaction deleted this target in every room, not a replacement map
            // captured before independent per-room held-key deletions completed.
            self.consent_keys.forget(target);
            self.deliveries.retain(|(_, peer, _), _| peer != target);
            self.delivery_reserved
                .retain(|(_, peer, _), _| peer != target);
            self.key_waiting.retain(|(_, peer), _| peer != target);
            self.key_delivery_settling
                .retain(|(_, peer)| peer != target);
        }
        self.trust = saved.trust;
        self.note_key_body_trust_change();
        for (target, had_drive) in saved.changed_drive {
            self.note_capability(target, had_drive);
        }
    }
}

/// Captured ONCE at original admission. A continued save borrows this authority and never waits
/// for a newer publication reader while retaining an older reader/transition.
pub(super) struct Lifetime {
    pub(super) save: Option<Arc<maintenance_save::Lifetime>>,
    pub(super) transition: Option<Arc<crate::node::computer::ComputerPublicationTransition>>,
    pub(super) journal: Option<crate::node::computer::ComputerJournalWriter>,
    pub(super) own_transitions: Vec<crate::node::channel::own_writer_gate::Transition>,
}

pub(super) enum PolicyContinuation {
    Untrust {
        lifetime: Lifetime,
        target: Digest32,
        alias: Option<String>,
    },
    Blacklist {
        lifetime: Lifetime,
        reply: oneshot::Sender<crate::error::Result<Option<BTreeSet<Digest32>>>>,
    },
    LocalTrustImport {
        lifetime: Lifetime,
        fingerprint: Digest32,
        name: String,
        capability: Capability,
    },
    Managed {
        lifetime: Lifetime,
        work: computer::OwnKeyPolicyWork,
        reservations: Vec<PolicyRoom>,
    },
    FinishUntrust {
        lifetime: Lifetime,
        operation: Untrust,
    },
    Grant {
        lifetime: Lifetime,
        source: policy_save::GrantSource,
    },
    FinishGrant {
        lifetime: Lifetime,
        source: policy_save::GrantSource,
        grant: GrantSaved,
    },
    DismissOffer {
        lifetime: Lifetime,
    },
}

pub(super) enum TrustContinuation {
    Untrust {
        lifetime: Lifetime,
        operation: Untrust,
        stage: UntrustStage,
    },
    Managed(policy_save::ManagedTurn),
    Grant(policy_save::GrantTurn),
}

pub(super) struct Untrust {
    pub(super) target: Digest32,
    pub(super) alias: Option<String>,
    pub(super) rooms: Vec<PolicyRoom>,
    pub(super) cursor: usize,
    pub(super) trusted: BTreeSet<Digest32>,
    pub(super) completed: Vec<(Digest32, Digest32, u64)>,
}

pub(super) enum UntrustStage {
    Withdraw,
    Delete,
    Reconcile(Reconcile),
}

impl PolicyContinuation {
    pub(super) fn lifetime(&self) -> &Lifetime {
        match self {
            Self::Untrust { lifetime, .. }
            | Self::Blacklist { lifetime, .. }
            | Self::LocalTrustImport { lifetime, .. }
            | Self::Managed { lifetime, .. }
            | Self::FinishUntrust { lifetime, .. }
            | Self::Grant { lifetime, .. }
            | Self::FinishGrant { lifetime, .. }
            | Self::DismissOffer { lifetime } => lifetime,
        }
    }
    pub(super) fn lifetime_mut(&mut self) -> &mut Lifetime {
        match self {
            Self::Untrust { lifetime, .. }
            | Self::Blacklist { lifetime, .. }
            | Self::LocalTrustImport { lifetime, .. }
            | Self::Managed { lifetime, .. }
            | Self::FinishUntrust { lifetime, .. }
            | Self::Grant { lifetime, .. }
            | Self::FinishGrant { lifetime, .. }
            | Self::DismissOffer { lifetime } => lifetime,
        }
    }
}
impl TrustContinuation {
    pub(super) fn lifetime(&self) -> &Lifetime {
        match self {
            Self::Untrust { lifetime, .. } => lifetime,
            Self::Managed(turn) => &turn.lifetime,
            Self::Grant(turn) => &turn.lifetime,
        }
    }
    pub(super) fn instance(&self) -> &SharedChannel {
        match self {
            Self::Untrust { operation, .. } => &operation.rooms[operation.cursor].instance,
            Self::Managed(turn) => &turn.rooms[turn.cursor].instance,
            Self::Grant(turn) => &turn.rooms[turn.cursor].instance,
        }
    }
}

pub(super) enum Next {
    Trust(Work),
    Withdraw { target: Digest32 },
}
pub(super) enum TrustCompletion {
    Trust(TrustSaved),
    Withdraw(crate::node::channel::pending_text::consent::ConsentSaved),
}
pub(super) enum TrustResume {
    Next {
        room: Digest32,
        work: Next,
        continuation: TrustContinuation,
    },
    Progress {
        room: Digest32,
        continuation: TrustContinuation,
    },
    Finished {
        continuation: TrustContinuation,
    },
}
pub(super) enum PolicyResume {
    Trust(TrustResume),
    Blacklist,
    LocalTrust {
        lifetime: Lifetime,
        fingerprint: Digest32,
        name: String,
        capability: Capability,
    },
    FinishedUntrust {
        lifetime: Lifetime,
        operation: Untrust,
        dismissed: bool,
    },
    Grant {
        lifetime: Lifetime,
        source: policy_save::GrantSource,
        grant: Option<GrantSaved>,
        rooms: Vec<PolicyRoom>,
    },
    GrantFinished {
        lifetime: Lifetime,
        source: policy_save::GrantSource,
        grant: GrantSaved,
    },
    Dismissed {
        lifetime: Lifetime,
        result: crate::error::Result<bool>,
    },
    Managed {
        lifetime: Lifetime,
        work: computer::OwnKeyPolicyWork,
        result: crate::error::Result<computer::KeyringApplication>,
        rooms: Vec<PolicyRoom>,
        revision: u64,
        expired: bool,
    },
    Failed {
        continuation: PolicyContinuation,
        error: Error,
        rooms: Vec<PolicyRoom>,
    },
}

impl Node {
    /// Common owner validates original attachment before this callback. `rooms` are the actual
    /// native preflight reservations, retained even when policy persistence failed.
    pub(super) fn finish_owned_policy(
        &mut self,
        completed: PolicyCompleted,
        continuation: PolicyContinuation,
        rooms: Vec<PolicyRoom>,
    ) -> PolicyResume {
        match (completed, continuation) {
            (
                PolicyCompleted::Saved(Ok(mut saved)),
                PolicyContinuation::Grant { lifetime, source },
            ) => {
                let grant = saved.grant.take();
                if grant.is_some() {
                    self.install_owned_policy(saved);
                }
                PolicyResume::Grant {
                    lifetime,
                    source,
                    grant,
                    rooms,
                }
            }
            (
                PolicyCompleted::Recorded,
                PolicyContinuation::FinishGrant {
                    lifetime,
                    source,
                    grant,
                },
            ) => PolicyResume::GrantFinished {
                lifetime,
                source,
                grant,
            },
            (
                PolicyCompleted::Saved(Ok(saved)),
                PolicyContinuation::Untrust {
                    lifetime,
                    target,
                    alias,
                },
            ) => {
                let trusted = saved.trust.trusted();
                self.install_owned_policy(saved);
                let operation = Untrust {
                    target,
                    alias,
                    rooms,
                    cursor: 0,
                    trusted,
                    completed: Vec::new(),
                };
                let room = operation.rooms.first().map(|reserved| reserved.room);
                let continuation = TrustContinuation::Untrust {
                    lifetime,
                    operation,
                    stage: UntrustStage::Withdraw,
                };
                PolicyResume::Trust(match room {
                    Some(room) => TrustResume::Next {
                        room,
                        work: Next::Withdraw { target },
                        continuation,
                    },
                    None => TrustResume::Finished { continuation },
                })
            }
            (
                PolicyCompleted::Dismissed(result),
                PolicyContinuation::FinishUntrust {
                    lifetime,
                    operation,
                },
            ) => {
                let dismissed = match result {
                    Ok(Some(saved)) => {
                        self.dismissed_offers = saved;
                        true
                    }
                    // As before, dismissal is best-effort ONLY after the actual removal and all
                    // debt/deletion commits. Its failure never resurrects a grant or old SKDM.
                    Ok(None) | Err(_) => false,
                };
                PolicyResume::FinishedUntrust {
                    lifetime,
                    operation,
                    dismissed,
                }
            }
            (PolicyCompleted::Dismissed(result), PolicyContinuation::DismissOffer { lifetime }) => {
                let result = result.map(|saved| match saved {
                    Some(saved) => {
                        self.dismissed_offers = saved;
                        true
                    }
                    None => false,
                });
                PolicyResume::Dismissed { lifetime, result }
            }
            (
                PolicyCompleted::Saved(Ok(saved)),
                PolicyContinuation::Blacklist { lifetime, reply },
            ) => {
                self.install_owned_policy(saved);
                self.decisions.hold_for_local_trust_import(false);
                let _ = reply.send(Ok(Some(self.trust.local_removals().clone())));
                drop(lifetime);
                PolicyResume::Blacklist
            }
            (
                PolicyCompleted::Saved(Ok(saved)),
                PolicyContinuation::LocalTrustImport {
                    lifetime,
                    fingerprint,
                    name,
                    capability,
                },
            ) => {
                self.install_owned_policy(saved);
                self.decisions.hold_for_local_trust_import(false);
                PolicyResume::LocalTrust {
                    lifetime,
                    fingerprint,
                    name,
                    capability,
                }
            }
            (
                PolicyCompleted::Managed(completed),
                PolicyContinuation::Managed {
                    mut lifetime, work, ..
                },
            ) => {
                let ManagedCompleted {
                    computer,
                    transition,
                    revision,
                    expired,
                    node,
                    committed,
                    mut result,
                } = completed;
                if matches!(&result, Ok(true)) {
                    // Reconcile may have settled a newer plan under this SAME physical owner.
                    // Children use its actual receipt, never the pre-write or actor-MAX tag.
                    let authority = computer::ComputerAuthority::Managed {
                        computer,
                        applied: revision,
                        expired,
                        node,
                    };
                    if let Some(save) = lifetime.save.as_mut() {
                        if let Some(save) = Arc::get_mut(save) {
                            save.authority = authority;
                        } else {
                            *save = Arc::new(super::maintenance_save::Lifetime {
                                authority,
                                publication: None,
                                exclusive: Some(Arc::clone(&transition)),
                                secret: Arc::clone(&save.secret),
                                store: Arc::clone(&save.store),
                                signer: Arc::clone(&save.signer),
                            });
                        }
                    } else {
                        result = Err(Error::Profile("managed policy lost its original lifetime"));
                    }
                }
                if let Some(saved) = committed {
                    // Even a failed receipt cannot undo the node-store fact; its old application
                    // marker no longer certifies the changed keyring.
                    self.computer_revision
                        .store(u64::MAX, std::sync::atomic::Ordering::Release);
                    self.install_owned_policy(saved);
                }
                let result = result.map(|settled| {
                    if settled {
                        self.computer_revision
                            .store(u64::MAX, std::sync::atomic::Ordering::Release);
                    }
                    computer::KeyringApplication { settled }
                });
                lifetime.transition = Some(transition);
                PolicyResume::Managed {
                    lifetime,
                    work,
                    result,
                    rooms,
                    revision,
                    expired,
                }
            }
            (PolicyCompleted::Saved(Err(error)), continuation) => PolicyResume::Failed {
                continuation,
                error,
                rooms,
            },
            (_, continuation) => PolicyResume::Failed {
                continuation,
                rooms,
                error: Error::Profile("policy completion does not match its original caller"),
            },
        }
    }

    /// `channel` is the exact room whose compact completion the common owner just installed.
    /// This callback performs no transaction and never reports task delivery as a durable fact.
    /// Returned Next/Progress retains the original lifetime and original caller/reply.
    pub(super) fn finish_owned_trust(
        &mut self,
        room: Digest32,
        channel: &ChannelState,
        mut continuation: TrustContinuation,
        result: crate::error::Result<TrustCompletion>,
        store: &Store,
    ) -> std::result::Result<TrustResume, Box<(TrustContinuation, Error)>> {
        let saved = match result {
            Ok(saved) => saved,
            Err(error) => return Err(Box::new((continuation, error))),
        };
        let transition = (|| -> crate::error::Result<()> {
            match (&mut continuation, saved) {
                (
                    TrustContinuation::Untrust {
                        operation, stage, ..
                    },
                    TrustCompletion::Withdraw(saved),
                ) => {
                    if let crate::node::channel::pending_text::consent::ConsentSaved::Withdrawn(
                        Some(revocation),
                    ) = &saved
                    {
                        operation.completed.push((
                            room,
                            revocation.body.target_id,
                            revocation.body.new_chain_id,
                        ));
                    }
                    match stage {
                        UntrustStage::Withdraw => {
                            if !matches!(saved, crate::node::channel::pending_text::consent::ConsentSaved::Withdrawn(_)) {
                                return Err(Error::Profile("trust withdrawal returned a grant"));
                            }
                            *stage = UntrustStage::Delete;
                        }
                        UntrustStage::Reconcile(state) => state.withdrawn(&saved)?,
                        UntrustStage::Delete => {
                            return Err(Error::Profile(
                                "unexpected duplicate withdrawal completion",
                            ))
                        }
                    }
                }
                (
                    TrustContinuation::Untrust {
                        operation, stage, ..
                    },
                    TrustCompletion::Trust(saved),
                ) => match stage {
                    UntrustStage::Delete => match saved {
                        TrustSaved::Deleted {
                            debt_cleared: Some(target),
                            dropped,
                        } if target == operation.target => {
                            if dropped > 0 {
                                self.governance_work.wake_room(room);
                            }
                            operation.cursor += 1;
                            if operation.cursor == operation.rooms.len() {
                                operation.cursor = 0;
                                *stage = UntrustStage::Reconcile(Reconcile::new(
                                    operation.trusted.clone(),
                                    ReconcileScope::Removals,
                                ));
                            } else {
                                *stage = UntrustStage::Withdraw;
                            }
                        }
                        _ => {
                            return Err(Error::Profile(
                                "trust deletion did not commit its exact withdrawal debt",
                            ))
                        }
                    },
                    UntrustStage::Reconcile(state) => state.saved(&saved)?,
                    UntrustStage::Withdraw => {
                        return Err(Error::Profile(
                            "withdrawal was not committed before deletion",
                        ))
                    }
                },
                _ => {
                    return Err(Error::Profile(
                        "trust completion does not match its original continuation",
                    ))
                }
            }
            Ok(())
        })();
        if let Err(error) = transition {
            return Err(Box::new((continuation, error)));
        }
        self.continue_owned_trust(room, channel, continuation, store)
    }

    pub(super) fn continue_owned_trust(
        &mut self,
        room: Digest32,
        channel: &ChannelState,
        mut continuation: TrustContinuation,
        store: &Store,
    ) -> std::result::Result<TrustResume, Box<(TrustContinuation, Error)>> {
        let next = match &mut continuation {
            TrustContinuation::Untrust {
                operation, stage, ..
            } => {
                match stage {
                    UntrustStage::Withdraw => Some((
                        operation.rooms[operation.cursor].room,
                        Next::Withdraw {
                            target: operation.target,
                        },
                    )),
                    UntrustStage::Delete => Some((
                        room,
                        Next::Trust(Work(TrustWrite::Delete {
                            trusted: operation.trusted.clone(),
                            withdrawn: Some(operation.target),
                        })),
                    )),
                    UntrustStage::Reconcile(state) => {
                        let current = operation.rooms[operation.cursor].room;
                        // Starting a new room needs no read yet; its first step is exact deletion.
                        if current != room {
                            Some((
                                current,
                                Next::Trust(Work(TrustWrite::Delete {
                                    trusted: operation.trusted.clone(),
                                    withdrawn: None,
                                })),
                            ))
                        } else {
                            match state.action(channel, store) {
                                Ok(ReconcileAction::Trust(work)) => Some((room, Next::Trust(work))),
                                Ok(ReconcileAction::Withdraw { target }) => {
                                    Some((room, Next::Withdraw { target }))
                                }
                                Ok(ReconcileAction::Complete) => {
                                    operation.cursor += 1;
                                    if operation.cursor == operation.rooms.len() {
                                        None
                                    } else {
                                        *stage = UntrustStage::Reconcile(Reconcile::new(
                                            operation.trusted.clone(),
                                            ReconcileScope::Removals,
                                        ));
                                        Some((
                                            operation.rooms[operation.cursor].room,
                                            Next::Trust(Work(TrustWrite::Delete {
                                                trusted: operation.trusted.clone(),
                                                withdrawn: None,
                                            })),
                                        ))
                                    }
                                }
                                Ok(ReconcileAction::Progress) => {
                                    return Ok(TrustResume::Progress { room, continuation })
                                }
                                Err(error) => return Err(Box::new((continuation, error))),
                            }
                        }
                    }
                }
            }
            TrustContinuation::Managed(_) => {
                return Err(Box::new((
                    continuation,
                    Error::Profile("managed policy has its own retained room continuation"),
                )))
            }
            TrustContinuation::Grant(_) => {
                return Err(Box::new((
                    continuation,
                    Error::Profile("grant has its own retained room continuation"),
                )))
            }
        };
        Ok(match next {
            Some((room, work)) => TrustResume::Next {
                room,
                work,
                continuation,
            },
            None => TrustResume::Finished { continuation },
        })
    }
}

impl TrustContinuation {
    pub(super) fn is_preparation(&self) -> bool {
        false
    }
    pub(super) fn policy_reservation_owner(&self) -> Option<Arc<()>> {
        match self {
            Self::Untrust {
                operation,
                stage: UntrustStage::Withdraw,
                ..
            } => Some(Arc::clone(&operation.rooms[operation.cursor].owner)),
            Self::Managed(turn) => turn.policy_reservation_owner(),
            Self::Grant(turn) => Some(Arc::clone(&turn.rooms[turn.cursor].owner)),
            _ => None,
        }
    }
}

pub(super) async fn retire_detached(
    room: Digest32,
    result: crate::error::Result<maintenance_save::Saved>,
    continuation: TrustContinuation,
    reply: Option<oneshot::Sender<Outcome>>,
) {
    policy_save::retire_detached(room, result, continuation, reply).await;
}
