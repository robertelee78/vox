//! Unpublished rooms use the ordinary retained save owner. A scheduled quantum is never
//! a readiness fact; only its matching native result advances this continuation.
use super::*;
use crate::node::channel::pending_retention::Step;
use crate::node::channel::pending_session::{SessionSaved, SessionWrite};
use crate::node::channel::session_projection::{ProjectionProgress, ProjectionWork};
use maintenance_save::{Lifetime, Saved, Work};

type Reply = Option<oneshot::Sender<Outcome>>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Stage {
    Receiver,
    Startup,
    Governance,
    Packages,
    Legacy,
    MessagePolicyCleanup,
    StepPolicyCleanup,
    Upgrade,
    Import,
    Expiry,
    Refresh,
    Retention(Step),
    Backfill,
    Classification,
    Views,
    Trust,
    Remember,
    Ready,
    CatchUpgrade,
    CatchImport,
    CatchExpiry,
    CatchProjection,
}

pub(super) struct State {
    stage: Stage,
    pending: bool,
    result: Option<crate::error::Result<Saved>>,
    request: Option<Work>,
    lifetime: Option<Arc<Lifetime>>,
    reconcile: Option<trust_save::Reconcile>,
    cache_only: bool,
    resume_after_governance: Option<Stage>,
    policy: Option<(u64, u64)>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            stage: Stage::Receiver,
            pending: false,
            result: None,
            request: None,
            lifetime: None,
            reconcile: None,
            cache_only: false,
            resume_after_governance: None,
            policy: None,
        }
    }
}

impl State {
    pub(super) fn lifetime(&self) -> Option<Arc<Lifetime>> {
        self.lifetime.as_ref().map(Arc::clone)
    }
    pub(super) fn is_pending(&self) -> bool {
        self.pending
    }
    pub(super) fn has_lifetime(&self) -> bool {
        self.lifetime.is_some()
    }
    pub(super) fn take_lifetime(&mut self) -> Option<Arc<Lifetime>> {
        self.lifetime.take()
    }
}

/// A queued policy writer fences fresh ingress, not the continuation which owns the
/// publication reader that writer is waiting to retire. Keep the existing due/gate checks.
pub(super) fn turn_eligible(
    prepared: &RoomPreparation,
    now: std::time::Instant,
    allow_fresh: bool,
) -> bool {
    !prepared.save.is_pending()
        && (allow_fresh || prepared.save.has_lifetime())
        && !matches!(
            prepared.recovery_writer_gate,
            Some(RecoveryWriterGate::Waiting { .. })
        )
        && prepared.legacy_cleanup_due.is_none_or(|due| now >= due)
}

/// Accepted publication is likewise completion work, not another Store transaction.
/// A queued waiter may already have taken the original authority out of the room map.
pub(super) fn publication_eligible(
    node: &Node,
    room: &Digest32,
    waiting: &RoomPublication,
    allow_fresh: bool,
) -> bool {
    !node.pending_posts.contains_key(room)
        && !node.metadata_publication_pending(room)
        && (allow_fresh
            || waiting.authority.is_some()
            || node.room_publication_authority.contains_key(room))
}

pub(super) struct Continuation {
    pub(super) instance: SharedChannel,
    pub(super) attachment: u64,
    pub(super) lifetime: Option<Arc<Lifetime>>,
    stage: Stage,
    // The pre-existing catch-up bound, not a new maintenance cap. Each projection quantum
    // consumes one turn; prerequisite writes remain part of that same turn.
    remaining: usize,
}

impl Continuation {
    pub(super) fn new(instance: SharedChannel, attachment: u64, stage: Stage) -> Self {
        Self {
            instance,
            attachment,
            lifetime: None,
            stage,
            remaining: 64,
        }
    }
    pub(super) fn lifetime(&self) -> Option<Arc<Lifetime>> {
        self.lifetime.as_ref().map(Arc::clone)
    }
    pub(super) fn instance(&self) -> &SharedChannel {
        &self.instance
    }
    pub(super) fn is_preparation(&self) -> bool {
        !matches!(
            self.stage,
            Stage::CatchUpgrade | Stage::CatchImport | Stage::CatchExpiry | Stage::CatchProjection
        )
    }
    fn attached(&self, node: &Node, room: &Digest32) -> bool {
        self.attachment == node.delivery_epoch
            && if self.is_preparation() {
                node.preparing_rooms
                    .get(room)
                    .is_some_and(|prepared| Arc::ptr_eq(&prepared.channel, &self.instance))
            } else {
                node.channels
                    .get(room)
                    .is_some_and(|current| Arc::ptr_eq(current, &self.instance))
            }
    }
}

impl Node {
    pub(super) fn reject_owned_preparation(
        &mut self,
        room: Digest32,
        error: Error,
        continuation: Continuation,
        reply: Reply,
    ) {
        let fault = fault_of(&error);
        if continuation.attached(self, &room) && continuation.is_preparation() {
            if let Some(prepared) = self.preparing_rooms.get_mut(&room) {
                prepared.save.pending = false;
                prepared.save.result = Some(Err(error));
                prepared.legacy_cleanup_due = None;
            }
        }
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(fault));
        }
    }

    pub(super) async fn finish_owned_preparation(
        &mut self,
        room: Digest32,
        result: crate::error::Result<Saved>,
        lifetime: Arc<Lifetime>,
        mut continuation: Continuation,
        reply: Reply,
    ) {
        if !continuation.attached(self, &room) {
            if let Some(reply) = reply {
                let outcome = match result {
                    Ok(_) => Outcome::Done,
                    Err(error) => Outcome::Failed(fault_of(&error)),
                };
                let _ = reply.send(outcome);
            }
            return;
        }
        let result = match result {
            Ok(Saved::Packages(package_save::Saved::Selected {
                mut progress,
                context,
            })) if continuation.stage == Stage::Packages => {
                if let Some(pending) = progress.package.take() {
                    continuation.lifetime = Some(lifetime);
                    let (work, next) = if let Some(ring) = self.prekeys.as_ref() {
                        (
                            package_save::Work::Open {
                                pending,
                                context,
                                ring: Arc::clone(ring),
                                trusted: self.trust.trusted(),
                            },
                            maintenance_save::Continuation::Preparation(continuation),
                        )
                    } else {
                        // No usable local ring is the original nonstorage refusal. Acknowledge
                        // this exact attempted package, but never install a fabricated key.
                        (
                            package_save::Work::Attempt {
                                locator: (pending.author, pending.log_id),
                                skdm: None,
                            },
                            maintenance_save::Continuation::Packages(
                                package_save::Continuation::preparation(continuation),
                            ),
                        )
                    };
                    Box::pin(self.begin_pending_maintenance(
                        room,
                        Work::Packages(work),
                        next,
                        reply,
                    ))
                    .await;
                    return;
                }
                Ok(Saved::Packages(package_save::Saved::Selected {
                    progress,
                    context,
                }))
            }
            Ok(Saved::Packages(package_save::Saved::Opened { locator, skdm }))
                if continuation.stage == Stage::Packages =>
            {
                continuation.lifetime = Some(lifetime);
                Box::pin(self.begin_pending_maintenance(
                    room,
                    Work::Packages(package_save::Work::Attempt { locator, skdm }),
                    maintenance_save::Continuation::Packages(
                        package_save::Continuation::preparation(continuation),
                    ),
                    reply,
                ))
                .await;
                return;
            }
            other => other,
        };
        if continuation.is_preparation() {
            if let Some(prepared) = self.preparing_rooms.get_mut(&room) {
                // A rejected or superseded old stage cannot satisfy a later stage.
                if prepared.save.stage == continuation.stage {
                    prepared.save.pending = false;
                    prepared.save.result = Some(result);
                    prepared.save.lifetime = Some(lifetime);
                    prepared.legacy_cleanup_due = None;
                }
            }
            return;
        }
        let saved = match result {
            Ok(saved) => saved,
            Err(error) => {
                self.reject_owned_preparation(room, error, continuation, reply);
                return;
            }
        };
        continuation.lifetime = Some(lifetime);
        let next = match (continuation.stage, saved) {
            (Stage::CatchUpgrade, Saved::Private(private_save::Saved::UpgradeComplete)) => {
                let Ok(channel) = continuation.instance.try_lock() else {
                    return;
                };
                if channel.needs_session_upgrade() {
                    return;
                }
                drop(channel);
                continuation.stage = Stage::CatchProjection;
                Work::Projection(ProjectionWork::Sessions)
            }
            (Stage::CatchUpgrade, Saved::Private(private_save::Saved::ControlImport)) => {
                continuation.stage = Stage::CatchImport;
                Work::Consent(consent_save::Work::ControlImport)
            }
            (Stage::CatchUpgrade, Saved::Private(private_save::Saved::PrivateExpiry)) => {
                continuation.stage = Stage::CatchExpiry;
                Work::Retention(Step::PrivateExpiry)
            }
            (Stage::CatchUpgrade, Saved::Private(private_save::Saved::Upgrade(saved))) => {
                if saved.advance == SessionAdvance::Waiting {
                    return;
                }
                Work::Private(private_save::Work::Upgrade {
                    finish_initial: false,
                })
            }
            (Stage::CatchImport, Saved::Consent(consent_save::Effect::ControlImport))
            | (Stage::CatchExpiry, Saved::Retention(_)) => {
                continuation.stage = Stage::CatchUpgrade;
                Work::Private(private_save::Work::Upgrade {
                    finish_initial: false,
                })
            }
            (
                Stage::CatchProjection,
                Saved::Projection(ProjectionProgress::Sessions { advanced: true }),
            ) if continuation.remaining > 1 => {
                continuation.remaining -= 1;
                continuation.stage = Stage::CatchUpgrade;
                Work::Private(private_save::Work::Upgrade {
                    finish_initial: false,
                })
            }
            // Waiting, unavailable and a genuinely finished projection stop this original
            // catch-up run. A later ordinary query/announcement can request another run.
            _ => return,
        };
        tokio::task::yield_now().await;
        Box::pin(self.begin_pending_maintenance(
            room,
            next,
            maintenance_save::Continuation::Preparation(continuation),
            reply,
        ))
        .await;
    }

    /// Called only after the unpublished RoomPreparation has been reinserted. This is
    /// asynchronous admission, not physical I/O; the ordinary result cell owns completion.
    pub(super) async fn begin_preparation_turn(&mut self, room: Digest32) -> bool {
        let allow_fresh = !self.store_save_pending();
        let Some(prepared) = self.preparing_rooms.get_mut(&room) else {
            return false;
        };
        if prepared.save.pending || self.pending_posts.contains_key(&room) {
            return false;
        }
        if !allow_fresh && !prepared.save.has_lifetime() {
            return false;
        }
        let Some(work) = prepared.save.request.take() else {
            return false;
        };
        let mut continuation = Continuation::new(
            Arc::clone(&prepared.channel),
            self.delivery_epoch,
            prepared.save.stage,
        );
        continuation.lifetime = prepared.save.lifetime.take();
        prepared.save.pending = true;
        let accepted = self
            .begin_pending_maintenance(
                room,
                work,
                maintenance_save::Continuation::Preparation(continuation),
                None,
            )
            .await;
        if !accepted {
            if let Some(prepared) = self.preparing_rooms.get_mut(&room) {
                prepared.save.pending = false;
            }
        }
        accepted
    }

    pub(super) async fn spawn_session_projection_catch_up(
        &mut self,
        room: &Digest32,
        lifetime: Option<Arc<Lifetime>>,
    ) {
        if self.pending_posts.contains_key(room)
            || (lifetime.is_none() && self.store_save_pending())
        {
            return;
        }
        let Some(instance) = self.channels.get(room).cloned() else {
            return;
        };
        let mut continuation =
            Continuation::new(instance, self.delivery_epoch, Stage::CatchUpgrade);
        continuation.lifetime = lifetime;
        self.begin_pending_maintenance(
            *room,
            Work::Private(private_save::Work::Upgrade {
                finish_initial: false,
            }),
            maintenance_save::Continuation::Preparation(continuation),
            None,
        )
        .await;
    }

    /// Establish the same prerequisites as the former synchronous preparation, in the
    /// same order. Only checked reads and scalar state changes occur under this room lock.
    pub(super) async fn retention_before_publication(
        &mut self,
        prepared: &mut RoomPreparation,
    ) -> crate::error::Result<bool> {
        if prepared.save.pending {
            return Ok(false);
        }
        let now = self.now_ms();
        let instance = Arc::clone(&prepared.channel);
        let Ok(mut channel) = instance.try_lock() else {
            return Ok(false);
        };
        if prepared.retry_packages {
            channel.release_held_packages();
            prepared.retry_packages = false;
        }
        let store = self
            .profile
            .as_ref()
            .ok_or(Error::AtRestLocked)?
            .store_handle();
        if prepared
            .save
            .lifetime
            .as_ref()
            .is_some_and(|held| !held.authority.current())
        {
            prepared.save = State::default();
            prepared.wait_on("current computer trust", now.get());
            return Ok(false);
        }
        if let Some(result) = prepared.save.result.take() {
            let saved = match result {
                Ok(saved) => saved,
                Err(Error::ComputerPolicySuperseded) => {
                    prepared.wait_on("current computer trust", now.get());
                    prepared.save.lifetime = None;
                    return Ok(false);
                }
                Err(error)
                    if matches!(
                        prepared.save.stage,
                        Stage::Upgrade | Stage::Import | Stage::Expiry
                    ) =>
                {
                    prepared.wait_on(&format!("restoring its Sessions ({error})"), now.get());
                    prepared.save.lifetime = None;
                    return Ok(false);
                }
                Err(error) => return Err(error),
            };
            if matches!(saved, Saved::Unavailable) {
                prepared.wait_on(stage_wait(prepared.save.stage), now.get());
                prepared.save.lifetime = None;
                return Ok(false);
            }
            match (prepared.save.stage, saved) {
                (Stage::Receiver, Saved::Consent(consent_save::Effect::Cleanup { more, .. })) => {
                    prepared.progressed |= more;
                    prepared.save.stage = Stage::Startup;
                }
                (
                    Stage::Startup,
                    Saved::Governance(governance_save::Saved::StartupCleanup { blocks_current }),
                ) => {
                    if blocks_current {
                        prepared.wait_on("cleaning up its earlier saved form", now.get());
                        prepared.legacy_cleanup_due = Some(std::time::Instant::now() + TICK);
                        return Ok(false);
                    }
                    prepared.save.stage = Stage::Governance;
                }
                (
                    Stage::Governance,
                    Saved::Projection(ProjectionProgress::Governance(progress)),
                ) => {
                    if !progress.ready {
                        if progress.pending {
                            prepared.progressed("folding its governance records", now.get());
                        } else {
                            prepared.wait_on("governance records from its members", now.get());
                            prepared.save.lifetime = None;
                        }
                        return Ok(false);
                    }
                    prepared.save.cache_only = channel.legacy_cache_only(&store)?;
                    prepared.save.stage = if prepared.save.cache_only {
                        Stage::Trust
                    } else {
                        prepared
                            .save
                            .resume_after_governance
                            .take()
                            .unwrap_or(Stage::Packages)
                    };
                }
                (
                    Stage::Packages,
                    Saved::Packages(package_save::Saved::Selected { progress, .. }),
                ) => {
                    if progress.pending {
                        prepared.wait_on("a member's key package", now.get());
                        prepared.save.lifetime = None;
                        return Ok(false);
                    }
                    prepared.save.stage = Stage::Legacy;
                }
                (Stage::Packages, Saved::Packages(package_save::Saved::Attempted(_))) => {
                    prepared.progressed("opening members' key packages", now.get());
                    return Ok(false);
                }
                (
                    Stage::Legacy,
                    Saved::Governance(governance_save::Saved::Legacy { pending, .. }),
                ) => {
                    if pending {
                        prepared.progressed("carrying its earlier Sessions over", now.get());
                        return Ok(false);
                    }
                    let id = channel.channel_id();
                    channel.set_node_retention(self.node_retention_for(&id));
                    prepared.save.policy = Some((
                        self.node_retention_for(&id),
                        self.node_step_retention.for_room(&id),
                    ));
                    prepared.save.stage = Stage::MessagePolicyCleanup;
                }
                (Stage::MessagePolicyCleanup, Saved::Retention(_)) => {
                    let id = channel.channel_id();
                    channel.set_node_step_retention(self.node_step_retention.for_room(&id));
                    prepared.save.stage = Stage::StepPolicyCleanup;
                }
                (Stage::StepPolicyCleanup, Saved::Retention(_)) => {
                    prepared.save.stage = Stage::Upgrade
                }
                (
                    Stage::Classification,
                    Saved::Governance(governance_save::Saved::Legacy { pending, .. }),
                ) => {
                    if pending {
                        prepared.progressed("classifying its earlier saved history", now.get());
                        return Ok(false);
                    }
                    prepared.save.stage = Stage::Views;
                }
                (Stage::Upgrade, Saved::Private(private_save::Saved::UpgradeComplete)) => {
                    prepared.save.stage = Stage::Refresh;
                }
                (Stage::Upgrade, Saved::Private(private_save::Saved::ControlImport)) => {
                    prepared.save.stage = Stage::Import
                }
                (Stage::Upgrade, Saved::Private(private_save::Saved::PrivateExpiry)) => {
                    prepared.save.stage = Stage::Expiry
                }
                (Stage::Upgrade, Saved::Private(private_save::Saved::Upgrade(saved))) => {
                    if channel.session_upgrade_local_work() {
                        if saved.advance == SessionAdvance::Advanced {
                            prepared.progressed("restoring its Sessions", now.get());
                        } else {
                            prepared.wait_on("restoring its Sessions", now.get());
                        }
                        return Ok(false);
                    }
                    prepared.save.stage = Stage::Refresh;
                }
                (Stage::Upgrade, Saved::Private(private_save::Saved::UpgradeWaiting)) => {
                    if channel.session_upgrade_local_work() {
                        prepared.wait_on("restoring its Sessions", now.get());
                        prepared.save.lifetime = None;
                        return Ok(false);
                    }
                    prepared.save.stage = Stage::Refresh;
                }
                (Stage::Import, Saved::Consent(consent_save::Effect::ControlImport))
                | (Stage::Expiry, Saved::Retention(_)) => prepared.save.stage = Stage::Upgrade,
                (Stage::Refresh, Saved::Session(SessionSaved::Refreshed(refresh))) => match refresh
                {
                    SessionRefresh::Complete => {
                        prepared.save.stage = Stage::Retention(Step::OwedCleanup)
                    }
                    SessionRefresh::Progressed => {
                        prepared.progressed("refreshing its Session records", now.get());
                        return Ok(false);
                    }
                    SessionRefresh::Waiting(what) => {
                        prepared.wait_on(what, now.get());
                        prepared.save.lifetime = None;
                        return Ok(false);
                    }
                },
                (Stage::Retention(step), Saved::Retention(installed)) => {
                    if step == Step::Projection && !installed.projection_ready {
                        prepared.progressed("building its saved history projection", now.get());
                        return Ok(false);
                    }
                    prepared.save.stage = match step {
                        Step::OwedCleanup => Stage::Retention(Step::KeyDebt),
                        Step::KeyDebt => Stage::Retention(Step::Projection),
                        Step::Projection => Stage::Backfill,
                        Step::Prune => Stage::Retention(Step::PrivateExpiry),
                        Step::PrivateExpiry => Stage::Retention(Step::HistoricalKeys),
                        Step::HistoricalKeys => Stage::Classification,
                        Step::Signatures => {
                            return Err(Error::Profile("unexpected preparation signature sweep"))
                        }
                    }
                }
                (Stage::Backfill, Saved::Governance(governance_save::Saved::Backfill { .. })) => {
                    prepared.save.stage = Stage::Retention(Step::Prune);
                }
                (Stage::Views, Saved::Projection(ProjectionProgress::RoomViews { more, .. })) => {
                    if more {
                        prepared.progressed("building its room views", now.get());
                        return Ok(false);
                    }
                    prepared.save.stage = Stage::Trust;
                }
                (Stage::Trust, Saved::Trust(saved)) => {
                    prepared
                        .save
                        .reconcile
                        .as_mut()
                        .ok_or(Error::Profile("preparation trust cursor missing"))?
                        .saved(&saved)?;
                }
                (Stage::Trust, Saved::Consent(consent_save::Effect::Consent(saved))) => {
                    prepared
                        .save
                        .reconcile
                        .as_mut()
                        .ok_or(Error::Profile("preparation trust cursor missing"))?
                        .withdrawn(&saved)?;
                }
                (Stage::Remember, Saved::Metadata(saved)) => {
                    self.note_room_remembered(channel.channel_id(), saved);
                    prepared.save.stage = Stage::Ready;
                }
                _ => {
                    return Err(Error::Profile(
                        "unexpected room preparation save completion",
                    ))
                }
            }
        }
        // Governance can expire during a slow native save. Refresh it before choosing
        // another policy-dependent stage, then resume the exact owed stage.
        if !prepared.save.cache_only
            && !matches!(
                prepared.save.stage,
                Stage::Receiver | Stage::Startup | Stage::Governance
            )
            && prepared.save.result.is_none()
        {
            if let Err(error) = channel.require_governance_ready(&store, now) {
                if !ChannelState::governance_refreshing(&error) {
                    return Err(error);
                }
                prepared.save.resume_after_governance = Some(prepared.save.stage);
                prepared.save.stage = Stage::Governance;
            }
        }
        let id = channel.channel_id();
        let policy = (
            self.node_retention_for(&id),
            self.node_step_retention.for_room(&id),
        );
        if prepared.save.cache_only {
            // Accepted-cache publication applies scalar policy without entering mutable roots.
            channel.set_node_retention(policy.0);
            channel.set_node_step_retention(policy.1);
        } else if prepared
            .save
            .policy
            .is_some_and(|applied| applied != policy)
        {
            // A real settings change while this room was preparing restarts only the policy
            // prerequisite chain. Both original setter cleanup turns must commit again.
            channel.set_node_retention(policy.0);
            prepared.save.policy = Some(policy);
            prepared.save.stage = Stage::MessagePolicyCleanup;
            prepared.save.reconcile = None;
        }
        if prepared.save.stage == Stage::Startup && !channel.legacy_startup_cleanup_blocks_current()
        {
            prepared.save.stage = Stage::Governance;
        }
        if prepared.save.stage == Stage::Packages
            && !(channel.needs_session_upgrade() && channel.key_packages_pending())
        {
            prepared.save.stage = Stage::Legacy;
        }
        if prepared.save.stage == Stage::Classification
            && !channel.legacy_classification_pending(&store)?
        {
            prepared.save.stage = Stage::Views;
        }
        if prepared.save.stage == Stage::Ready
            && prepared
                .save
                .reconcile
                .as_ref()
                .is_none_or(|state| !state.matches_trust(&self.trust.trusted()))
        {
            // Recovery writer admission can outlive the last narrowing turn. Its eventual
            // publication must still reflect the current exact trust decision.
            prepared.save.stage = Stage::Trust;
        }
        if prepared.save.stage == Stage::Trust {
            let trusted = self.trust.trusted();
            let scope = if prepared.save.cache_only {
                trust_save::ReconcileScope::Cache
            } else {
                trust_save::ReconcileScope::Preparation
            };
            if prepared
                .save
                .reconcile
                .as_ref()
                .is_some_and(|state| !state.matches_trust(&trusted))
            {
                prepared.save.reconcile = None;
            }
            let reconcile = prepared
                .save
                .reconcile
                .get_or_insert_with(|| trust_save::Reconcile::new(trusted, scope));
            match reconcile.action(&channel, &store)? {
                trust_save::ReconcileAction::Trust(work) => {
                    prepared.save.request = Some(Work::Trust(work))
                }
                trust_save::ReconcileAction::Withdraw { target } => {
                    prepared.save.request =
                        Some(Work::Consent(consent_save::Work::Withdraw { target }));
                }
                trust_save::ReconcileAction::Progress => {
                    prepared.progressed("narrowing its trust", now.get());
                    return Ok(false);
                }
                trust_save::ReconcileAction::Complete => {
                    prepared.save.stage = Stage::Remember;
                    prepared.save.request = Some(Work::Metadata(metadata_save::Work::Remember));
                }
            }
        } else {
            prepared.save.request = match prepared.save.stage {
                Stage::Receiver => Some(Work::Consent(consent_save::Work::ReceiverCleanup)),
                Stage::Startup => Some(Work::Governance(governance_save::Work::StartupCleanup)),
                Stage::Governance => Some(Work::Projection(ProjectionWork::Governance)),
                Stage::Legacy => Some(Work::Governance(governance_save::Work::Legacy)),
                Stage::Classification => Some(Work::Governance(governance_save::Work::Legacy)),
                Stage::MessagePolicyCleanup | Stage::StepPolicyCleanup => Some(Work::RetentionAt {
                    step: Step::OwedCleanup,
                    now: channel.retention_cleanup_hint(),
                }),
                Stage::Upgrade => Some(Work::Private(private_save::Work::Upgrade {
                    finish_initial: true,
                })),
                Stage::Import => Some(Work::Consent(consent_save::Work::ControlImport)),
                Stage::Expiry => Some(Work::Retention(Step::PrivateExpiry)),
                Stage::Refresh => Some(Work::Session(SessionWrite::Refresh { owed: Vec::new() })),
                Stage::Retention(step) => Some(Work::Retention(step)),
                Stage::Backfill => Some(Work::Governance(governance_save::Work::Backfill)),
                Stage::Views => Some(Work::Projection(ProjectionWork::RoomViews)),
                Stage::Remember => Some(Work::Metadata(metadata_save::Work::Remember)),
                Stage::Ready => return Ok(true),
                Stage::Packages => {
                    #[cfg(feature = "test-knobs")]
                    if let Some(path) = held_packages_path() {
                        note_package_hold_engaged(&path);
                        prepared.wait_on("test apparatus holding members' sender keys", now.get());
                        return Ok(false);
                    }
                    Some(Work::Packages(package_save::Work::Select {
                        trust_digest: crate::hash::sha256(&self.trust.to_bytes()),
                        replay: false,
                    }))
                }
                _ => return Err(Error::Profile("unexpected preparation stage")),
            };
        }
        prepared.wait_on(stage_wait(prepared.save.stage), now.get());
        Ok(false)
    }
}

fn stage_wait(stage: Stage) -> &'static str {
    match stage {
        Stage::Receiver => "reclaiming earlier sender keys",
        Stage::Startup => "cleaning up its earlier saved form",
        Stage::Governance => "its governance records being refreshed",
        Stage::Packages => "opening members' key packages",
        Stage::Legacy | Stage::Classification => "classifying its earlier saved history",
        Stage::Upgrade | Stage::Import | Stage::Expiry => "restoring its Sessions",
        Stage::Refresh => "refreshing its Session records",
        Stage::MessagePolicyCleanup
        | Stage::StepPolicyCleanup
        | Stage::Retention(_)
        | Stage::Backfill => "applying its retention rules",
        Stage::Views => "building its room views",
        Stage::Trust => "narrowing its trust",
        Stage::Remember => "remembering it for restart",
        Stage::Ready => "publication",
        Stage::CatchUpgrade | Stage::CatchImport | Stage::CatchExpiry | Stage::CatchProjection => {
            "refreshing its Session view"
        }
    }
}
