//! Unpublished rooms use the ordinary retained save owner. A scheduled quantum is never
//! a readiness fact; only its matching native result advances this continuation.
use super::*;
use crate::node::channel::pending_retention::Step;
use crate::node::channel::pending_session::{SessionSaved, SessionWrite};
use crate::node::channel::pending_upgrade::UpgradeWait;
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
    /// The resumed stage was refused because governance facts it needs were still refreshing.
    refused: bool,
    /// A governance turn since that refusal had local fold work to do.
    folded: bool,
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
            refused: false,
            folded: false,
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

/// The longest a room whose Session control catch-up keeps ending with nothing advanced waits
/// between driven checks (#1206).
const SESSION_CONTROL_CHECK_MAX: Duration = Duration::from_secs(60);

/// When each published room's Session control frontier is next checked against its authors'
/// verified heads by [`Node::drive_session_control_catch_up`], and whose turn it is (#1206).
#[derive(Default)]
pub(super) struct SessionControlChecks {
    /// Per room: the time of its next check, and the wait that set it. A catch-up that ended
    /// waiting on a peer with nothing advanced doubles the wait, up to
    /// [`SESSION_CONTROL_CHECK_MAX`]; one that advanced, or a current frontier, resets it to
    /// `PREPARE_WAIT`.
    rooms: BTreeMap<Digest32, (std::time::Instant, Duration)>,
    /// The room whose catch-up the driver last began; the next tick looks after it first.
    cursor: Option<Digest32>,
}

impl SessionControlChecks {
    pub(super) fn remove(&mut self, room: &Digest32) {
        self.rooms.remove(room);
    }

    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }

    fn due(&self, room: &Digest32, now: std::time::Instant) -> bool {
        self.rooms.get(room).is_none_or(|(at, _)| *at <= now)
    }

    fn wait_of(&self, room: &Digest32) -> Duration {
        self.rooms
            .get(room)
            .map_or(super::PREPARE_WAIT, |(_, wait)| *wait)
    }

    /// The room's frontier is current: looked at again after `PREPARE_WAIT`.
    fn current(&mut self, room: Digest32, now: std::time::Instant) {
        self.rooms
            .insert(room, (now + super::PREPARE_WAIT, super::PREPARE_WAIT));
    }

    /// A catch-up for the room was attempted: its turn is taken, at its current wait.
    fn began(&mut self, room: Digest32, now: std::time::Instant) {
        let wait = self.wait_of(&room);
        self.rooms.insert(room, (now + wait, wait));
        self.cursor = Some(room);
    }

    /// A catch-up run for the room ended. Nothing advanced: the next look waits twice as long,
    /// up to [`SESSION_CONTROL_CHECK_MAX`]. Something did: the pace is back to `PREPARE_WAIT`.
    fn catch_up_ended(&mut self, room: Digest32, advanced: bool) {
        let wait = if advanced {
            super::PREPARE_WAIT
        } else {
            (self.wait_of(&room) * 2).min(SESSION_CONTROL_CHECK_MAX)
        };
        self.rooms
            .insert(room, (std::time::Instant::now() + wait, wait));
    }
}

pub(super) struct Continuation {
    pub(super) instance: SharedChannel,
    pub(super) attachment: u64,
    pub(super) lifetime: Option<Arc<Lifetime>>,
    stage: Stage,
    // The pre-existing catch-up bound, not a new maintenance cap. Each projection quantum
    // consumes one turn; prerequisite writes remain part of that same turn.
    remaining: usize,
    /// Whether any quantum of this catch-up run advanced something (#1206): a run that ends
    /// waiting on a peer having advanced nothing paces that room's next driven check.
    advanced: bool,
}

impl Continuation {
    pub(super) fn new(instance: SharedChannel, attachment: u64, stage: Stage) -> Self {
        Self {
            instance,
            attachment,
            lifetime: None,
            stage,
            remaining: 64,
            advanced: false,
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
                continuation.advanced = true;
                let Ok(channel) = continuation.instance.try_lock() else {
                    self.session_control_check_at
                        .catch_up_ended(room, continuation.advanced);
                    return;
                };
                if channel.needs_session_upgrade() {
                    self.session_control_check_at
                        .catch_up_ended(room, continuation.advanced);
                    return;
                }
                drop(channel);
                continuation.stage = Stage::CatchProjection;
                Work::Projection(ProjectionWork::Sessions)
            }
            (Stage::CatchUpgrade, Saved::Private(private_save::Saved::ControlImport)) => {
                continuation.advanced = true;
                continuation.stage = Stage::CatchImport;
                Work::Consent(consent_save::Work::ControlImport)
            }
            (Stage::CatchUpgrade, Saved::Private(private_save::Saved::PrivateExpiry)) => {
                continuation.advanced = true;
                continuation.stage = Stage::CatchExpiry;
                Work::Retention(Step::PrivateExpiry)
            }
            (Stage::CatchUpgrade, Saved::Private(private_save::Saved::Upgrade(saved))) => {
                if saved.advance == SessionAdvance::Waiting {
                    self.session_control_check_at
                        .catch_up_ended(room, continuation.advanced);
                    return;
                }
                continuation.advanced = true;
                Work::Private(private_save::Work::Upgrade {
                    finish_initial: false,
                })
            }
            (Stage::CatchImport, Saved::Consent(consent_save::Effect::ControlImport))
            | (Stage::CatchExpiry, Saved::Retention(_)) => {
                continuation.advanced = true;
                continuation.stage = Stage::CatchUpgrade;
                Work::Private(private_save::Work::Upgrade {
                    finish_initial: false,
                })
            }
            (
                Stage::CatchProjection,
                Saved::Projection(ProjectionProgress::Sessions { advanced: true }),
            ) if continuation.remaining > 1 => {
                continuation.advanced = true;
                continuation.remaining -= 1;
                continuation.stage = Stage::CatchUpgrade;
                Work::Private(private_save::Work::Upgrade {
                    finish_initial: false,
                })
            }
            // Waiting, unavailable and a genuinely finished projection stop this original
            // catch-up run. A later ordinary query/announcement can request another run.
            _ => {
                self.session_control_check_at
                    .catch_up_ended(room, continuation.advanced);
                return;
            }
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
        let allow_fresh = self.fresh_maintenance_allowed();
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

    /// A legacy Session migration left to the published room (#1203) waits on a member's
    /// records. Retry it at a pace once the room is published; the governance wake folds
    /// whatever arrived, which ordinary content alone does not wake.
    pub(super) async fn retry_deferred_session_upgrades(&mut self) {
        let now = std::time::Instant::now();
        let due: Vec<Digest32> = self
            .session_upgrade_retry_at
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(room, _)| *room)
            .collect();
        for room in due {
            let Some(instance) = self.channels.get(&room).cloned() else {
                if !self.preparing_rooms.contains_key(&room) {
                    self.session_upgrade_retry_at.remove(&room);
                }
                continue;
            };
            if instance
                .try_lock()
                .is_ok_and(|channel| !channel.legacy_upgrade_pending())
            {
                self.session_upgrade_retry_at.remove(&room);
                continue;
            }
            self.session_upgrade_retry_at
                .insert(room, now + super::PREPARE_WAIT);
            self.governance_work.wake_room(room);
            self.spawn_session_projection_catch_up(&room, None).await;
        }
    }

    /// Drive the Session control catch-up of every published room whose frontier lags an
    /// author's verified head, at a pace (#1206). The catch-up used to run only from a Session
    /// query, a refused room publication, or a deferred legacy migration; a room that merely
    /// received an author's rows out of sequence kept answering "Session control facts are
    /// refreshing" for that author — refusing its Session pulls, its announcement round, and
    /// with it the own-feed control append every member waits on — until a client happened
    /// to ask about Sessions. The inspection is scalar reads under a try-lock; a current room
    /// costs nothing more and is looked at once per `PREPARE_WAIT`.
    ///
    /// One catch-up is begun per tick — its save owns the Store — and the rooms take turns
    /// from the one begun last ([`SessionControlChecks::cursor`]). A room whose catch-up ends
    /// waiting on a peer with nothing advanced (an author's control entry this node does not
    /// hold, a departed author's frontier) is looked at again after a doubling wait, up to
    /// [`SESSION_CONTROL_CHECK_MAX`]: it would otherwise take the one turn every tick, ahead
    /// of every other room's catch-up and of the room maintenance that runs after this.
    pub(super) async fn drive_session_control_catch_up(&mut self) {
        // Nothing can be begun while a save owns the Store; the due rooms stay due.
        if self.store_save_pending() {
            return;
        }
        let now = std::time::Instant::now();
        let Some(store) = self
            .profile
            .as_ref()
            .filter(|profile| profile.is_unlocked())
            .map(|profile| profile.store_handle())
        else {
            return;
        };
        let mut rooms: Vec<(Digest32, SharedChannel)> = self
            .channels
            .iter()
            .filter(|(room, _)| self.session_control_check_at.due(room, now))
            .map(|(room, instance)| (*room, Arc::clone(instance)))
            .collect();
        if let Some(cursor) = self.session_control_check_at.cursor {
            let first = rooms
                .iter()
                .position(|(room, _)| *room > cursor)
                .unwrap_or(0);
            rooms.rotate_left(first);
        }
        for (room, instance) in rooms {
            let Ok(channel) = instance.try_lock() else {
                continue; // A session holds it; the next tick looks again.
            };
            let lagging = matches!(channel.session_controls_lagging(&store), Ok(true));
            drop(channel);
            if !lagging {
                self.session_control_check_at.current(room, now);
                continue;
            }
            let began = self.spawn_session_projection_catch_up(&room, None).await;
            self.session_control_check_at.began(room, now);
            if began {
                return;
            }
        }
    }

    /// Whether the catch-up was begun; it is not when a save already owns the Store, or the
    /// room cannot take maintenance right now.
    pub(super) async fn spawn_session_projection_catch_up(
        &mut self,
        room: &Digest32,
        lifetime: Option<Arc<Lifetime>>,
    ) -> bool {
        if self.pending_posts.contains_key(room)
            || (lifetime.is_none() && self.store_save_pending())
        {
            return false;
        }
        let Some(instance) = self.channels.get(room).cloned() else {
            return false;
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
        .await
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
                Err(
                    Error::ComputerPolicySuperseded
                    | Error::Profile("room publication is busy; retry this operation"),
                ) => {
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
                Err(error)
                    if ChannelState::governance_refreshing(&error)
                        && prepared.save.stage != Stage::Governance =>
                {
                    // The stage's native work needs governance facts this room has not folded
                    // yet. Only the fold below produces them for a preparing room; retrying the
                    // same stage would repeat the same refusal (#1203). Fold, then resume it.
                    refold(prepared, now.get());
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
                        prepared.save.folded |= prepared.save.refused && progress.pending;
                        if progress.pending {
                            prepared.progressed("folding its governance records", now.get());
                        } else {
                            prepared.wait_on("governance records from its members", now.get());
                            prepared.save.lifetime = None;
                        }
                        return Ok(false);
                    }
                    if prepared.save.refused {
                        if progress.pending {
                            prepared.save.folded = true;
                            prepared.progressed("folding its governance records", now.get());
                            return Ok(false);
                        }
                        if !prepared.save.folded {
                            prepared.save.refused = false;
                            let room = channel.channel_id();
                            match prepared.save.resume_after_governance {
                                // Nothing local was left to fold, so the refused stage needs
                                // records a member has not sent, and a member is reached only
                                // once the room is published (ADR-037 R1). Continue without
                                // it: the published room's package owner opens the package
                                // once its governance settles, as for a package refused after
                                // publication.
                                Some(Stage::Packages) => {
                                    self.key_package_governance_wait.insert(room);
                                    self.key_package_unopened.insert(room);
                                    prepared.save.resume_after_governance = Some(Stage::Legacy);
                                }
                                // Likewise a legacy Session row whose causal past has not
                                // arrived: the published room migrates it, at a pace.
                                Some(Stage::Upgrade) if channel.defer_legacy_upgrade() => {
                                    self.session_upgrade_retry_at.insert(
                                        room,
                                        std::time::Instant::now() + super::PREPARE_WAIT,
                                    );
                                }
                                _ => {
                                    // Retry the stage once a second, not at once: the next
                                    // governance turn resumes it.
                                    prepared
                                        .wait_on("governance records from its members", now.get());
                                    prepared.save.lifetime = None;
                                    prepared.legacy_cleanup_due =
                                        Some(std::time::Instant::now() + super::PREPARE_WAIT);
                                    return Ok(false);
                                }
                            }
                        }
                        prepared.save.refused = false;
                        prepared.save.folded = false;
                    }
                    prepared.save.cache_only = channel.legacy_cache_only(&store)?;
                    let resume = prepared.save.resume_after_governance.take();
                    prepared.save.stage = if prepared.save.cache_only {
                        Stage::Trust
                    } else {
                        resume.unwrap_or(Stage::Packages)
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
                        } else if matches!(saved.wait, Some(UpgradeWait::Governance)) {
                            // A legacy row's eligibility is refreshing: fold, then retry the
                            // row or, with nothing local to fold, leave it to the published
                            // room (#1203).
                            refold(prepared, now.get());
                        } else {
                            prepared.wait_on("restoring its Sessions", now.get());
                        }
                        return Ok(false);
                    }
                    prepared.save.stage = Stage::Refresh;
                }
                (Stage::Upgrade, Saved::Private(private_save::Saved::UpgradeWaiting(_))) => {
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
            && (channel.is_member_removed(&store, &channel.me())?
                || !(channel.needs_session_upgrade() && channel.key_packages_pending()))
        {
            prepared.save.stage = Stage::Legacy;
        }
        // Publish the room before work that needs restored membership or peer history.
        // Its normal governance/Drive owners retain and complete rotation and refresh;
        // closing it here would prevent the readmission or missing history from arriving.
        if prepared.save.stage == Stage::Refresh
            && (channel.is_member_removed(&store, &channel.me())?
                || channel.room_removal_rotation_needed(&store)?
                || channel.room_removal_drive_rotation_needed(&store)?)
        {
            prepared.save.stage = Stage::Retention(Step::OwedCleanup);
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
            let action = match reconcile.action(&channel, &store) {
                Ok(action) => action,
                Err(error) if ChannelState::governance_refreshing(&error) => {
                    // The last native result is installed. Keep the exact reconciliation
                    // cursor, but release its physical reader before fresh governance work
                    // can wait behind a Computer transition.
                    prepared.save.lifetime = None;
                    prepared.save.resume_after_governance = Some(Stage::Trust);
                    prepared.save.stage = Stage::Governance;
                    prepared.save.request = Some(Work::Projection(ProjectionWork::Governance));
                    prepared.wait_on(stage_wait(Stage::Governance), now.get());
                    return Ok(false);
                }
                Err(error) => return Err(error),
            };
            match action {
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
                        // The prior chain finished or was rejected before this turn.
                        // Retry an interrupted package from its unchanged durable cursor.
                        abandon_unopened: true,
                    }))
                }
                _ => return Err(Error::Profile("unexpected preparation stage")),
            };
        }
        prepared.wait_on(stage_wait(prepared.save.stage), now.get());
        Ok(false)
    }
}

/// Fold this preparing room's governance records, then resume the refused stage (#1203).
fn refold(prepared: &mut RoomPreparation, now: u64) {
    prepared.save.lifetime = None;
    prepared.save.resume_after_governance = Some(prepared.save.stage);
    prepared.save.stage = Stage::Governance;
    prepared.save.refused = true;
    prepared.save.folded = false;
    prepared.save.request = Some(Work::Projection(ProjectionWork::Governance));
    prepared.wait_on(stage_wait(Stage::Governance), now);
}

fn stage_wait(stage: Stage) -> &'static str {
    match stage {
        Stage::Receiver => "reclaiming earlier sender keys",
        Stage::Startup => "cleaning up its earlier saved form",
        Stage::Governance => "its governance records to refresh",
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
