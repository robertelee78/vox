//! Original governance and retention turns, resumed only from actual owned-save results.
use super::*;
use crate::node::channel::pending_retention::Step;
use crate::node::channel::pending_trust::{TrustSaved, TrustWrite};
use crate::node::channel::session_projection::{ProjectionProgress, ProjectionWork};
use crate::node::store::Store;

pub(super) use crate::node::channel::pending_governance::{Completed, Prepared, Saved, Work};

impl Work {
    pub(super) fn prepare(
        self,
        channel: &mut ChannelState,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
    ) -> crate::error::Result<Option<Prepared>> {
        channel.prepare_pending_governance_work(store, owner, self, now)
    }
}
impl Completed {
    pub(super) fn finish(
        self,
        channel: &mut ChannelState,
        store: &Store,
    ) -> crate::error::Result<Saved> {
        channel.finish_pending_governance_work(store, self)
    }
}

pub(super) struct Continuation<L = Option<Arc<maintenance_save::Lifetime>>> {
    pub(super) instance: SharedChannel,
    pub(super) attachment: u64,
    pub(super) lifetime: L,
    after: After,
}

pub(super) type Retained = Continuation<Arc<maintenance_save::Lifetime>>;

impl From<Retained> for Continuation {
    fn from(next: Retained) -> Self {
        Self {
            instance: next.instance,
            attachment: next.attachment,
            lifetime: Some(next.lifetime),
            after: next.after,
        }
    }
}

struct Turn {
    stage: TurnStage,
    ready: bool,
    changed: bool,
    backfilled: usize,
    legacy_finished: bool,
    views_finished: bool,
}

#[derive(Clone, Copy)]
enum TurnStage {
    Cleanup,
    CleanupRecovery,
    Governance,
    CacheDelete,
    Backfill,
    Contiguous,
    KeyDebt,
    Provider,
    Legacy,
    Projection,
    Views,
    SupportFence(crate::time::Ms),
    Support(crate::time::Ms),
    Withdraw(Digest32),
    Delete(Digest32),
}

struct Sweep {
    stage: SweepStage,
    now: crate::time::Ms,
    cleanup_now: crate::time::Ms,
    applied: bool,
    pruned: usize,
    checkpointed: bool,
    projection_finished: bool,
}

#[derive(Clone, Copy)]
enum SweepStage {
    MessagePolicyCleanup,
    StepPolicyCleanup,
    OwedCleanup,
    KeyDebt,
    Projection,
    Backfill,
    Prune,
    PrivateExpiry,
    HistoricalKeys,
    Checkpoint,
    Signatures,
    FinalProjection,
}

type CleanupOwner = Option<crate::node::channel::legacy_provisional::LegacyProvisionalOwner>;

enum CleanupTurn {
    Again(CleanupOwner),
    Done,
    Failed(String),
}

enum After {
    Turn(Turn),
    Sweep(Sweep),
    Admin(governance::Removal),
    Cleanup {
        owner: CleanupOwner,
        preparation: bool,
    },
}

impl Continuation {
    pub(super) fn turn(instance: SharedChannel, attachment: u64) -> Self {
        Self {
            instance,
            attachment,
            lifetime: None,
            after: After::Turn(Turn {
                stage: TurnStage::Cleanup,
                ready: false,
                changed: false,
                backfilled: 0,
                legacy_finished: false,
                views_finished: false,
            }),
        }
    }
    pub(super) fn admin(
        instance: SharedChannel,
        attachment: u64,
        work: governance::Removal,
    ) -> Self {
        Self {
            instance,
            attachment,
            lifetime: None,
            after: After::Admin(work),
        }
    }
    pub(super) fn lifetime(&self) -> Option<Arc<maintenance_save::Lifetime>> {
        self.lifetime.as_ref().map(Arc::clone)
    }
}

impl<L> Continuation<L> {
    pub(super) fn instance(&self) -> &SharedChannel {
        &self.instance
    }
    pub(super) fn is_preparation(&self) -> bool {
        matches!(
            self.after,
            After::Cleanup {
                preparation: true,
                ..
            }
        )
    }
    pub(super) fn now(&self) -> Option<crate::time::Ms> {
        match &self.after {
            After::Sweep(sweep) => Some(match sweep.stage {
                SweepStage::MessagePolicyCleanup | SweepStage::StepPolicyCleanup => {
                    sweep.cleanup_now
                }
                _ => sweep.now,
            }),
            After::Turn(Turn {
                stage: TurnStage::SupportFence(now) | TurnStage::Support(now),
                ..
            }) => Some(*now),
            _ => None,
        }
    }
    fn attached(&self, node: &Node, room: &Digest32) -> bool {
        let current = if self.is_preparation() {
            node.preparing_rooms
                .get(room)
                .map(|prepared| &prepared.channel)
        } else {
            node.channels.get(room)
        };
        self.attachment == node.delivery_epoch
            && current.is_some_and(|current| Arc::ptr_eq(current, &self.instance))
            && match &self.after {
                After::Cleanup { owner, .. } => node.legacy_cleanup_rooms.get(room) == Some(owner),
                _ => true,
            }
    }
}

impl Node {
    pub(super) fn reject_owned_governance<L>(
        &mut self,
        room: Digest32,
        error: Error,
        continuation: Continuation<L>,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        if continuation.attached(self, &room) {
            match continuation.after {
                After::Sweep(sweep) => {
                    if matches!(
                        sweep.stage,
                        SweepStage::MessagePolicyCleanup | SweepStage::StepPolicyCleanup
                    ) {
                        self.retention_dirty.insert(room);
                    }
                }
                After::Cleanup { owner, .. } => {
                    let turn = if matches!(
                        error,
                        Error::ComputerPolicySuperseded
                            | Error::Profile("current computer trust is unavailable")
                            | Error::Profile("room publication is busy; retry this operation")
                    ) {
                        CleanupTurn::Again(owner)
                    } else {
                        CleanupTurn::Failed(error.to_string())
                    };
                    self.finish_legacy_cleanup_turn(room, owner, turn);
                }
                After::Turn(_) => {
                    if ChannelState::governance_refreshing(&error)
                        || ChannelState::legacy_classification_refreshing(&error)
                        || matches!(
                            error,
                            Error::Profile("room publication is busy; retry this operation")
                        )
                    {
                        self.governance_work.again = true;
                    }
                }
                After::Admin(work) => {
                    if ChannelState::governance_refreshing(&error)
                        || matches!(
                            error,
                            Error::ComputerPolicySuperseded
                                | Error::Profile("current computer trust is unavailable")
                                | Error::Profile("room publication is busy; retry this operation")
                        )
                    {
                        self.governance_work.removal = Some(work);
                    } else {
                        let _ = work.reply.send(Outcome::Failed(fault_of(&error)));
                    }
                }
            }
        } else if let After::Admin(work) = continuation.after {
            let _ = work.reply.send(Outcome::Failed(Fault::ChannelNotOpen));
        }
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(fault_of(&error)));
        }
    }

    pub(super) async fn finish_owned_governance(
        &mut self,
        room: Digest32,
        result: crate::error::Result<maintenance_save::Saved>,
        lifetime: Arc<maintenance_save::Lifetime>,
        continuation: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        if !continuation.attached(self, &room) {
            if let After::Admin(work) = continuation.after {
                let _ = work.reply.send(Outcome::Failed(Fault::ChannelNotOpen));
            }
            if let Some(reply) = reply {
                let _ = reply.send(
                    result
                        .map(|_| Outcome::Done)
                        .unwrap_or_else(|error| Outcome::Failed(fault_of(&error))),
                );
            }
            return;
        }
        let mut continuation = Retained {
            instance: continuation.instance,
            attachment: continuation.attachment,
            lifetime,
            after: continuation.after,
        };
        let saved = match result {
            Ok(saved) => saved,
            Err(error) => {
                if matches!(
                    &continuation.after,
                    After::Turn(Turn {
                        stage: TurnStage::SupportFence(_) | TurnStage::Support(_),
                        ..
                    })
                ) {
                    // Automatic support renewal was best-effort. Its real failed fence or
                    // append is not readiness, but never gated the original governance tail.
                    self.finish_governance_consents(room, continuation, reply)
                        .await;
                    return;
                }
                if matches!(
                    error,
                    Error::Profile("room publication is busy; retry this operation")
                ) {
                    let publish = match &continuation.after {
                        After::Turn(turn) => {
                            turn.changed
                                || turn.backfilled > 0
                                || turn.legacy_finished
                                || turn.views_finished
                        }
                        After::Sweep(sweep) => sweep.applied,
                        _ => false,
                    };
                    if publish {
                        self.publish().await;
                    }
                    self.reject_owned_governance(room, error, continuation, reply);
                    return;
                }
                match &continuation.after {
                    After::Turn(Turn {
                        stage:
                            TurnStage::Backfill
                            | TurnStage::Contiguous
                            | TurnStage::KeyDebt
                            | TurnStage::Provider
                            | TurnStage::Legacy
                            | TurnStage::Projection
                            | TurnStage::Views,
                        ..
                    }) => {
                        if ChannelState::legacy_classification_refreshing(&error) {
                            self.governance_work.again = true;
                        } else {
                            continuation.instance.lock().await.poison(&error);
                        }
                        self.resume_governance_turn(room, continuation, reply).await;
                    }
                    After::Turn(Turn {
                        stage: TurnStage::CacheDelete,
                        changed,
                        ..
                    }) => {
                        let changed = *changed;
                        continuation.instance.lock().await.poison(&error);
                        if changed {
                            self.publish().await;
                        }
                        drop(continuation);
                    }
                    After::Sweep(Sweep {
                        stage: SweepStage::Checkpoint | SweepStage::Signatures,
                        ..
                    }) => {
                        // These two original calls were best-effort after a successful sweep.
                        self.finish_retention_step(
                            room,
                            maintenance_save::Saved::Unavailable,
                            continuation,
                            reply,
                        )
                        .await;
                    }
                    After::Sweep(sweep) if sweep.applied => {
                        self.publish().await;
                        drop(continuation);
                    }
                    _ => self.reject_owned_governance(room, error, continuation, reply),
                }
                return;
            }
        };
        match &mut continuation.after {
            After::Admin(_) => {
                self.finish_governance_admin(room, saved, continuation, reply)
                    .await
            }
            After::Sweep(_) => {
                self.finish_retention_step(room, saved, continuation, reply)
                    .await
            }
            After::Cleanup { .. } => {
                self.finish_owned_legacy_cleanup(room, saved, continuation, reply)
                    .await
            }
            After::Turn(turn) => {
                use maintenance_save::Saved as Result;
                match (turn.stage, saved) {
                    (
                        TurnStage::Cleanup,
                        Result::Consent(consent_save::Effect::Cleanup {
                            more,
                            retry_ready,
                            own_retry_ready,
                        }),
                    ) => {
                        self.governance_work.again |= more;
                        if retry_ready {
                            self.key_package_rooms.entry(room).or_insert(false);
                        }
                        if own_retry_ready {
                            self.governance_work.wake_room(room);
                            turn.stage = TurnStage::CleanupRecovery;
                            Box::pin(self.continue_governance_recovery(
                                room,
                                false,
                                continuation,
                                reply,
                            ))
                            .await;
                            return;
                        }
                    }
                    (TurnStage::Cleanup, Result::Unavailable) => {}
                    (
                        TurnStage::Governance,
                        Result::Projection(ProjectionProgress::Governance(progress)),
                    ) => {
                        turn.ready = progress.ready;
                        turn.changed = progress.changed;
                        self.governance_work.again |= progress.pending;
                        if progress.ready && !progress.pending {
                            self.governance_work.settled.insert(room);
                        }
                    }
                    (
                        TurnStage::CacheDelete,
                        Result::Trust(TrustSaved::Deleted {
                            dropped,
                            debt_cleared: None,
                        }),
                    ) => {
                        if dropped > 0 {
                            self.governance_work.wake_room(room);
                        }
                        let changed = turn.changed;
                        if changed {
                            self.publish().await;
                        }
                        drop(continuation);
                        return;
                    }
                    (
                        TurnStage::Backfill,
                        Result::Governance(Saved::Backfill {
                            rendered, pending, ..
                        }),
                    ) => {
                        turn.backfilled = rendered;
                        self.governance_work.again |= pending;
                    }
                    (TurnStage::Contiguous, Result::Governance(Saved::Contiguous { pending }))
                    | (TurnStage::Provider, Result::Governance(Saved::ProviderPrune { pending })) => {
                        self.governance_work.again |= pending
                    }
                    (TurnStage::Provider, Result::Unavailable) => {}
                    (TurnStage::KeyDebt, Result::Retention(installed)) => {
                        self.governance_work.again |= installed.more_key_debt
                    }
                    (TurnStage::KeyDebt, Result::Unavailable) => {}
                    (TurnStage::Projection, Result::Retention(installed)) => {
                        if !installed.projection_ready {
                            self.continue_governance_save(
                                room,
                                maintenance_save::Work::Retention(Step::Projection),
                                continuation,
                                reply,
                            )
                            .await;
                            return;
                        }
                    }
                    (
                        TurnStage::Legacy,
                        Result::Governance(Saved::Legacy { advanced, pending }),
                    ) => {
                        self.governance_work.again |= pending;
                        turn.legacy_finished = advanced;
                    }
                    (
                        TurnStage::Views,
                        Result::Projection(ProjectionProgress::RoomViews { more, finished }),
                    ) => {
                        self.governance_work.again |= more;
                        turn.views_finished = finished;
                    }
                    (
                        TurnStage::SupportFence(now),
                        Result::Recovery(recovery_save::Saved::Fence(_)),
                    ) => {
                        turn.stage = TurnStage::Support(now);
                        self.continue_governance_save(
                            room,
                            maintenance_save::Work::Consent(consent_save::Work::PrivateSupport {
                                discovery_ready: true,
                            }),
                            continuation,
                            reply,
                        )
                        .await;
                        return;
                    }
                    (
                        TurnStage::Support(_),
                        Result::Consent(consent_save::Effect::PrivateSupport(appended)),
                    ) => {
                        if appended {
                            self.note_local_append(&room);
                        }
                        self.finish_governance_consents(room, continuation, reply)
                            .await;
                        return;
                    }
                    (TurnStage::SupportFence(_) | TurnStage::Support(_), Result::Unavailable) => {
                        self.finish_governance_consents(room, continuation, reply)
                            .await;
                        return;
                    }
                    (
                        TurnStage::Withdraw(target),
                        Result::Consent(consent_save::Effect::Consent(
                            crate::node::channel::pending_text::consent::ConsentSaved::Withdrawn(
                                revocation,
                            ),
                        )),
                    ) => {
                        if let Some(revocation) = revocation {
                            self.note_completed_untrust(room, target, revocation.body.new_chain_id);
                        }
                        turn.stage = TurnStage::Delete(target);
                        let work =
                            maintenance_save::Work::Trust(trust_save::Work(TrustWrite::Delete {
                                trusted: self.trust.trusted(),
                                withdrawn: Some(target),
                            }));
                        self.continue_governance_save(room, work, continuation, reply)
                            .await;
                        return;
                    }
                    (
                        TurnStage::Delete(target),
                        Result::Trust(TrustSaved::Deleted {
                            dropped,
                            debt_cleared: Some(cleared),
                        }),
                    ) if target == cleared => {
                        if dropped > 0 {
                            self.governance_work.wake_room(room);
                        }
                        self.governance_work.consent_after.insert(room, target);
                        self.governance_work.again = true;
                        self.finish_governance_publication(room, continuation, reply)
                            .await;
                        return;
                    }
                    (_, Result::Unavailable) => {
                        // No prepared work is not a native readiness result. Retain this room's
                        // original turn for the existing causal scheduler, not a fabricated fold.
                        self.governance_work.again = true;
                        return;
                    }
                    _ => {
                        self.reject_owned_governance(
                            room,
                            Error::Profile(
                                "governance completion does not match its retained stage",
                            ),
                            continuation,
                            reply,
                        );
                        return;
                    }
                }
                self.resume_governance_turn(room, continuation, reply).await;
            }
        }
    }

    async fn continue_governance_save(
        &mut self,
        room: Digest32,
        work: maintenance_save::Work,
        continuation: impl Into<Continuation>,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        Box::pin(self.begin_pending_maintenance(
            room,
            work,
            maintenance_save::Continuation::Governance(continuation.into()),
            reply,
        ))
        .await;
    }

    async fn resume_governance_turn(
        &mut self,
        room: Digest32,
        mut continuation: Retained,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        let After::Turn(turn) = &mut continuation.after else {
            return;
        };
        use maintenance_save::Work as Save;
        let work = match turn.stage {
            TurnStage::Cleanup => {
                if self.governance_work.settled.contains(&room) {
                    turn.ready = true;
                    return self.governance_after_fold(room, continuation, reply).await;
                }
                turn.stage = TurnStage::Governance;
                Save::Projection(ProjectionWork::Governance)
            }
            TurnStage::Governance => {
                return self.governance_after_fold(room, continuation, reply).await
            }
            TurnStage::Backfill => {
                #[cfg(feature = "test-knobs")]
                if continuation
                    .instance
                    .lock()
                    .await
                    .render_backfill_held_for_proof()
                {
                    let publish = turn.changed || turn.backfilled > 0;
                    self.governance_work.pending = false;
                    if publish {
                        self.publish().await;
                    }
                    drop(continuation);
                    return;
                }
                turn.stage = TurnStage::Contiguous;
                Save::Governance(Work::Contiguous)
            }
            TurnStage::Contiguous if turn.ready => {
                let debt = continuation
                    .instance
                    .lock()
                    .await
                    .key_debt_retention_pending();
                if debt {
                    turn.stage = TurnStage::KeyDebt;
                    Save::Retention(Step::KeyDebt)
                } else {
                    turn.stage = TurnStage::Provider;
                    Save::Governance(Work::ProviderPrune)
                }
            }
            TurnStage::Contiguous | TurnStage::KeyDebt => {
                turn.stage = TurnStage::Provider;
                Save::Governance(Work::ProviderPrune)
            }
            TurnStage::Provider if turn.ready => {
                turn.stage = TurnStage::Legacy;
                Save::Governance(Work::Legacy)
            }
            TurnStage::Provider => {
                return self
                    .finish_governance_room_work(room, continuation, reply)
                    .await
            }
            TurnStage::Legacy => {
                // Governance and legacy classification can change the exact policy basis
                // required by saved-history reads. Its existing bounded cursor is causal
                // work of this retained turn, not work left for a competing periodic sweep.
                turn.stage = TurnStage::Projection;
                Save::Retention(Step::Projection)
            }
            TurnStage::Projection => {
                turn.stage = TurnStage::Views;
                Save::Projection(ProjectionWork::RoomViews)
            }
            TurnStage::Views => {
                return self
                    .finish_governance_room_work(room, continuation, reply)
                    .await
            }
            _ => return,
        };
        self.continue_governance_save(room, work, continuation, reply)
            .await;
    }

    async fn governance_after_fold(
        &mut self,
        room: Digest32,
        mut continuation: Retained,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        let After::Turn(turn) = &mut continuation.after else {
            return;
        };
        let cache_only = {
            let channel = continuation.instance.lock().await;
            if turn.ready {
                self.governance_work
                    .set_deadline(room, channel.governance_deadline());
            }
            channel.legacy_cache_only(&continuation.lifetime.store)
        };
        let work = match cache_only {
            Ok(true) => {
                turn.stage = TurnStage::CacheDelete;
                maintenance_save::Work::Trust(trust_save::Work(TrustWrite::Delete {
                    trusted: self.trust.trusted(),
                    withdrawn: None,
                }))
            }
            Ok(false) => {
                turn.stage = TurnStage::Backfill;
                maintenance_save::Work::Governance(Work::Backfill)
            }
            Err(error) => {
                continuation.instance.lock().await.poison(&error);
                return;
            }
        };
        self.continue_governance_save(room, work, continuation, reply)
            .await;
    }

    async fn finish_governance_room_work(
        &mut self,
        room: Digest32,
        continuation: Retained,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        let After::Turn(turn) = &continuation.after else {
            return;
        };
        let store = &continuation.lifetime.store;
        let settle = {
            let channel = continuation.instance.lock().await;
            !channel.is_settled() && channel.uses_sparse_history(store).unwrap_or(false)
        };
        if turn.ready {
            Box::pin(self.continue_governance_recovery(room, settle, continuation, reply)).await;
        } else {
            self.finish_governance_publication(room, continuation, reply)
                .await;
        }
    }

    pub(super) async fn finish_governance_recovery(
        &mut self,
        room: Digest32,
        mut continuation: Retained,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        if !continuation.attached(self, &room) {
            return;
        }
        if matches!(
            &continuation.after,
            After::Turn(Turn {
                stage: TurnStage::CleanupRecovery,
                ..
            })
        ) {
            return;
        }
        if self.locking != 0
            || self
                .profile
                .as_ref()
                .is_none_or(|profile| profile.signer().is_err())
        {
            self.finish_governance_consents(room, continuation, reply)
                .await;
            return;
        }
        let lifetime = &continuation.lifetime;
        let mut busy = false;
        let ready = match continuation.instance.try_lock() {
            Ok(channel) => self.checked_support_discovery(room, &channel, &lifetime.store),
            Err(_) => {
                busy = true;
                false
            }
        };
        if busy {
            if let Some(profile) = self.profile.as_ref() {
                self.bounded_sync.wait_for_own_recovery_room(
                    &self.net_tx,
                    &mut self.next_token,
                    profile.fingerprint(),
                    room,
                    Arc::clone(&continuation.instance),
                );
            }
        }
        if ready {
            let now = self.now_ms();
            let After::Turn(turn) = &mut continuation.after else {
                return;
            };
            turn.stage = TurnStage::SupportFence(now);
            self.continue_governance_save(
                room,
                maintenance_save::Work::Recovery(recovery_save::Work::support_refresh(now)),
                continuation,
                reply,
            )
            .await;
            return;
        }
        self.finish_governance_consents(room, continuation, reply)
            .await;
    }

    async fn finish_governance_consents(
        &mut self,
        room: Digest32,
        mut continuation: Retained,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        if !continuation.attached(self, &room) {
            return;
        }
        let After::Turn(turn) = &continuation.after else {
            return;
        };
        let store = &continuation.lifetime.store;
        if turn.ready && (turn.changed || self.governance_work.consent_after.contains_key(&room)) {
            let page = {
                let channel = continuation.instance.lock().await;
                channel.consent_page(
                    store,
                    &channel.me(),
                    self.governance_work.consent_after.get(&room).copied(),
                    64,
                )
            };
            let page = match page {
                Ok(page) => page,
                Err(error) => {
                    continuation.instance.lock().await.poison(&error);
                    return;
                }
            };
            if let Some(target) = page
                .targets
                .iter()
                .find(|target| !self.trust.is_trusted(target))
                .copied()
            {
                let After::Turn(turn) = &mut continuation.after else {
                    return;
                };
                turn.stage = TurnStage::Withdraw(target);
                self.continue_governance_save(
                    room,
                    maintenance_save::Work::Consent(consent_save::Work::Withdraw { target }),
                    continuation,
                    reply,
                )
                .await;
                return;
            }
            if let Some(next) = page.next {
                self.governance_work.consent_after.insert(room, next);
                self.governance_work.again = true;
            } else {
                self.governance_work.consent_after.remove(&room);
            }
        }
        self.finish_governance_publication(room, continuation, reply)
            .await;
    }

    async fn finish_governance_publication(
        &mut self,
        room: Digest32,
        continuation: Retained,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        let After::Turn(turn) = &continuation.after else {
            return;
        };
        let publish =
            turn.changed || turn.backfilled > 0 || turn.legacy_finished || turn.views_finished;
        if turn.ready && (turn.changed || self.governance_work.admin_rosters.contains(&room)) {
            self.adopt_channel_anchors(&room).await;
            self.refresh_network_view().await;
            match self
                .publish_governance_admin_roster(&room, &continuation.lifetime)
                .await
            {
                Ok(()) => {
                    self.governance_work.admin_rosters.remove(&room);
                }
                Err(fault) => {
                    self.governance_work.admin_rosters.insert(room);
                    self.governance_work.again |= matches!(fault, Fault::GovernanceRefreshing);
                }
            }
        }
        if publish {
            self.publish().await;
        }
        drop(continuation);
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Done);
        }
    }

    /// Build and release the original bounded roster under the already admitted publication
    /// reader. A queued policy writer must not make this decision acquire a second reader.
    async fn publish_governance_admin_roster(
        &self,
        room: &Digest32,
        lifetime: &Arc<maintenance_save::Lifetime>,
    ) -> Result<(), Fault> {
        let shared = self.channels.get(room).ok_or(Fault::ChannelNotOpen)?;
        let mut channel = shared.lock().await;
        if channel.me() != channel.genesis().creator_pubkey().fingerprint() {
            return Ok(());
        }
        let stamp = match channel.admin_change_clock(&lifetime.store) {
            Ok(Some(stamp)) => stamp,
            Ok(None) => return Ok(()),
            Err(error) => {
                if !ChannelState::governance_refreshing(&error) {
                    channel.poison(&error);
                }
                return Err(fault_of(&error));
            }
        };
        let mut admins = Vec::new();
        let mut after = None;
        loop {
            let page = match channel.admin_page(&lifetime.store, after, 64, self.now_ms()) {
                Ok(page) => page,
                Err(error) => {
                    if !ChannelState::governance_refreshing(&error) {
                        channel.poison(&error);
                    }
                    return Err(fault_of(&error));
                }
            };
            if admins.len().saturating_add(page.targets.len()) > crate::nat::withdraw::MAX_ROSTER {
                return Err(Fault::Internal);
            }
            admins.extend(page.targets);
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        drop(channel);
        if !lifetime.authority.current() {
            return Err(Fault::ComputerPolicy);
        }
        let wire =
            crate::nat::withdraw::AdminRoster::build(lifetime.signer.as_ref(), room, stamp, admins)
                .map_err(|error| fault_of(&error))?
                .to_wire();
        let Some(net) = self.net.as_ref() else {
            return Ok(());
        };
        if !lifetime.authority.current() {
            return Err(Fault::ComputerPolicy);
        }
        let _ = net.publish_local(&wire);
        for conn in self
            .anchor_ids
            .iter()
            .filter(|id| self.anchor_serves_room(room, id))
            .filter_map(|id| net.manager().existing(id))
        {
            Self::put_withdraws(&conn, vec![wire.clone()]);
        }
        Ok(())
    }

    async fn finish_governance_admin(
        &mut self,
        room: Digest32,
        saved: maintenance_save::Saved,
        continuation: Retained,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        let After::Admin(mut work) = continuation.after else {
            return;
        };
        match saved {
            maintenance_save::Saved::Governance(Saved::AdminRemoval { count, next }) => {
                work.count = work.count.saturating_add(count);
                if count > 0 {
                    self.note_local_governance_append(&room);
                    self.governance_work.again = true;
                }
                if let Some(next) = next {
                    work.after = Some(next);
                    self.governance_work.removal = Some(work);
                    self.governance_work.again = true;
                } else if work.count == 0 {
                    let _ = work.reply.send(Outcome::Failed(Fault::NotAnAdmin));
                } else {
                    work.done = true;
                    self.governance_work.removal = Some(work);
                    self.governance_work.again = true;
                }
            }
            maintenance_save::Saved::Unavailable => {
                self.governance_work.removal = Some(work);
            }
            _ => {
                let _ = work.reply.send(Outcome::Failed(Fault::Internal));
            }
        }
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Done);
        }
    }

    /// Start each room in the original BTreeMap order. Scheduling is not a prune/checkpoint;
    /// only the matching final callback publishes a changed retention view.
    pub(super) async fn sweep_retention(&mut self) -> bool {
        #[cfg(feature = "test-knobs")]
        if std::env::var_os("VOX_TEST_HOLD_RETENTION_SWEEP_FILE")
            .filter(|path| !path.is_empty())
            .is_some_and(|path| std::path::Path::new(&path).is_file())
        {
            return false;
        }
        let now = self.now_ms();
        self.refresh_node_retention(now);
        if self.profile.is_none() {
            return false;
        }
        use std::ops::Bound::{Excluded, Unbounded};
        let mut after = None;
        loop {
            let next = match after {
                Some(after) => self.channels.range((Excluded(after), Unbounded)).next(),
                None => self.channels.iter().next(),
            }
            .map(|(room, instance)| (*room, Arc::clone(instance)));
            let Some((room, instance)) = next else { break };
            after = Some(room);
            if let Some(pending) = self.pending_posts.get_mut(&room) {
                pending.owe_retention(&instance, self.delivery_epoch);
                continue;
            }
            self.sweep_retention_room(room, instance, self.delivery_epoch)
                .await;
        }
        false
    }

    /// A deferred periodic sweep starts only after the preceding physical owner and all
    /// of its immediate successors retire. Its fresh native admission still rechecks
    /// current authority; no reader is acquired while the old lifetime remains held.
    pub(super) async fn sweep_retention_room(
        &mut self,
        room: Digest32,
        instance: SharedChannel,
        attachment: u64,
    ) -> bool {
        if attachment != self.delivery_epoch
            || !self
                .channels
                .get(&room)
                .is_some_and(|current| Arc::ptr_eq(current, &instance))
            || self.pending_posts.contains_key(&room)
        {
            return false;
        }
        let Some(store) = self.profile.as_ref().map(Profile::store_handle) else {
            return false;
        };
        let Ok(mut channel) = instance.try_lock() else {
            return false;
        };
        if channel.is_poisoned() {
            return false;
        }
        let now = self.now_ms();
        let applying = self.retention_dirty.remove(&room);
        let cleanup_now = channel.retention_cleanup_hint();
        let (stage, work) = if applying {
            channel.set_node_retention(self.node_retention.for_room(&room));
            (
                SweepStage::MessagePolicyCleanup,
                maintenance_save::Work::Retention(Step::OwedCleanup),
            )
        } else {
            self.warn_retention_above_room(room, &channel);
            match channel.retention_turn_ready(&store, now) {
                Ok(true) => (
                    SweepStage::OwedCleanup,
                    maintenance_save::Work::Retention(Step::OwedCleanup),
                ),
                Ok(false) => {
                    if channel.key_debt_retention_pending() {
                        self.governance_work.wake_room(room);
                    }
                    channel.set_checkpoint_idle(self.checkpoint_idle_secs);
                    (SweepStage::Checkpoint, maintenance_save::Work::Checkpoint)
                }
                Err(error) => {
                    channel.poison(&error);
                    return false;
                }
            }
        };
        drop(channel);
        let continuation = Continuation {
            instance,
            attachment,
            lifetime: None,
            after: After::Sweep(Sweep {
                stage,
                now,
                cleanup_now,
                applied: false,
                pruned: 0,
                checkpointed: false,
                projection_finished: false,
            }),
        };
        self.begin_pending_maintenance(
            room,
            work,
            maintenance_save::Continuation::Governance(continuation),
            None,
        )
        .await
    }

    async fn finish_retention_step(
        &mut self,
        room: Digest32,
        saved: maintenance_save::Saved,
        mut continuation: Retained,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        let After::Sweep(sweep) = &mut continuation.after else {
            return;
        };
        use maintenance_save::Saved as Result;
        match saved {
            Result::Retention(installed) => {
                sweep.pruned = sweep.pruned.saturating_add(installed.pruned);
                if installed.more_key_debt {
                    self.governance_work.wake_room(room);
                }
                if matches!(
                    sweep.stage,
                    SweepStage::Projection | SweepStage::FinalProjection
                ) {
                    if !installed.projection_ready {
                        self.continue_governance_save(
                            room,
                            maintenance_save::Work::Retention(Step::Projection),
                            continuation,
                            reply,
                        )
                        .await;
                        return;
                    }
                    sweep.projection_finished = true;
                }
            }
            Result::Governance(Saved::Backfill { .. }) => {}
            Result::Checkpoint(crate::node::channel::pending_text::Saved::Governance(hash)) => {
                sweep.checkpointed = hash.is_some();
            }
            Result::Unavailable
                if matches!(
                    sweep.stage,
                    SweepStage::Projection | SweepStage::FinalProjection
                ) =>
            {
                self.governance_work.wake_room(room);
                self.finish_retention_publication(room, continuation, reply)
                    .await;
                return;
            }
            Result::Unavailable => {}
            _ => {
                self.reject_owned_governance(
                    room,
                    Error::Profile("retention completion does not match its retained stage"),
                    continuation,
                    reply,
                );
                return;
            }
        }
        use maintenance_save::Work as Save;
        let (next, work) = match sweep.stage {
            SweepStage::MessagePolicyCleanup => {
                continuation
                    .instance
                    .lock()
                    .await
                    .set_node_step_retention(self.node_step_retention.for_room(&room));
                (
                    SweepStage::StepPolicyCleanup,
                    Save::Retention(Step::OwedCleanup),
                )
            }
            SweepStage::StepPolicyCleanup => {
                sweep.applied = true;
                let mut channel = continuation.instance.lock().await;
                self.warn_retention_above_room(room, &channel);
                let store = &continuation.lifetime.store;
                match channel.retention_turn_ready(store, sweep.now) {
                    Ok(true) => (SweepStage::OwedCleanup, Save::Retention(Step::OwedCleanup)),
                    Ok(false) => {
                        if channel.key_debt_retention_pending() {
                            self.governance_work.wake_room(room);
                        }
                        channel.set_checkpoint_idle(self.checkpoint_idle_secs);
                        (SweepStage::Checkpoint, Save::Checkpoint)
                    }
                    Err(error) => {
                        channel.poison(&error);
                        drop(channel);
                        self.publish().await;
                        drop(continuation);
                        return;
                    }
                }
            }
            SweepStage::OwedCleanup => (SweepStage::KeyDebt, Save::Retention(Step::KeyDebt)),
            SweepStage::KeyDebt => (SweepStage::Projection, Save::Retention(Step::Projection)),
            SweepStage::Projection => (SweepStage::Backfill, Save::Governance(Work::Backfill)),
            SweepStage::Backfill => (SweepStage::Prune, Save::Retention(Step::Prune)),
            SweepStage::Prune => (
                SweepStage::PrivateExpiry,
                Save::Retention(Step::PrivateExpiry),
            ),
            SweepStage::PrivateExpiry => (
                SweepStage::HistoricalKeys,
                Save::Retention(Step::HistoricalKeys),
            ),
            SweepStage::HistoricalKeys => {
                let mut channel = continuation.instance.lock().await;
                if channel.key_debt_retention_pending() {
                    self.governance_work.wake_room(room);
                }
                channel.set_checkpoint_idle(self.checkpoint_idle_secs);
                (SweepStage::Checkpoint, Save::Checkpoint)
            }
            SweepStage::Checkpoint => (SweepStage::Signatures, Save::Retention(Step::Signatures)),
            SweepStage::Signatures => {
                // Backfill and pruning can publish a newer legacy classification basis
                // after the first projection receipt. Settle that exact basis, never a
                // readiness flag, before completing the retained sweep.
                let current = !sweep.projection_finished
                    || continuation
                        .instance
                        .lock()
                        .await
                        .retention_projection_current();
                if !current {
                    (
                        SweepStage::FinalProjection,
                        Save::Retention(Step::Projection),
                    )
                } else {
                    self.finish_retention_publication(room, continuation, reply)
                        .await;
                    return;
                }
            }
            SweepStage::FinalProjection => {
                self.finish_retention_publication(room, continuation, reply)
                    .await;
                return;
            }
        };
        sweep.stage = next;
        self.continue_governance_save(room, work, continuation, reply)
            .await;
    }

    async fn finish_retention_publication(
        &mut self,
        room: Digest32,
        continuation: Retained,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        let After::Sweep(sweep) = &continuation.after else {
            return;
        };
        let changed = sweep.pruned > 0 || sweep.checkpointed || sweep.applied;
        if sweep.checkpointed {
            self.note_local_append(&room);
        }
        if changed {
            self.publish().await;
        }
        drop(continuation);
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Done);
        }
    }

    fn warn_retention_above_room(&mut self, room: Digest32, channel: &ChannelState) {
        if let Some((node, policy)) = channel
            .retention_above_room()
            .filter(|&(node, policy)| self.retention_warned.insert((room, node, policy)))
        {
            let _ = self.event_tx.send(NodeEvent::RetentionAboveRoom {
                channel_id: room,
                node,
                room: policy,
            });
        }
    }

    /// Keep the existing cursor and tick cadence; only its physical work changes owners.
    pub(super) async fn advance_legacy_cleanup(&mut self) {
        use std::ops::Bound::{Excluded, Unbounded};
        let id = self
            .legacy_cleanup_after
            .and_then(|after| {
                self.legacy_cleanup_rooms
                    .range((Excluded(after), Unbounded))
                    .next()
                    .map(|(id, _)| *id)
            })
            .or_else(|| {
                self.legacy_cleanup_rooms
                    .first_key_value()
                    .map(|(id, _)| *id)
            });
        let Some(id) = id else { return };
        self.legacy_cleanup_after = Some(id);
        let owner = self.legacy_cleanup_rooms.get(&id).copied().flatten();
        if self.profile.is_none() {
            self.legacy_cleanup_rooms.clear();
            return;
        }
        let (instance, lifetime, preparation) =
            if let Some(prepared) = self.preparing_rooms.get(&id) {
                (
                    Arc::clone(&prepared.channel),
                    prepared.save.lifetime(),
                    true,
                )
            } else if self.store_recovery.contains_key(&id) {
                self.finish_legacy_cleanup_turn(id, owner, CleanupTurn::Again(owner));
                return;
            } else if let Some(instance) = self.channels.get(&id) {
                (Arc::clone(instance), None, false)
            } else {
                let turn = if self.opening_rooms.contains_key(&id) || self.reopening.contains(&id) {
                    CleanupTurn::Again(owner)
                } else {
                    CleanupTurn::Done
                };
                self.finish_legacy_cleanup_turn(id, owner, turn);
                return;
            };
        if self.pending_posts.contains_key(&id) || instance.try_lock().is_err() {
            self.finish_legacy_cleanup_turn(id, owner, CleanupTurn::Again(owner));
            return;
        }
        let work = match owner {
            Some(owner) => Work::CleanupProvisional { owner },
            None => Work::StartupCleanup,
        };
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime,
            after: After::Cleanup { owner, preparation },
        };
        self.continue_governance_save(
            id,
            maintenance_save::Work::Governance(work),
            continuation,
            None,
        )
        .await;
    }

    async fn finish_owned_legacy_cleanup(
        &mut self,
        room: Digest32,
        saved: maintenance_save::Saved,
        continuation: Retained,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        let After::Cleanup { owner, .. } = continuation.after else {
            return;
        };
        let turn = match (owner, saved) {
            (
                Some(expected),
                maintenance_save::Saved::Governance(Saved::CleanupProvisional { owner, complete }),
            ) if expected == owner => CleanupTurn::Again(if complete { None } else { Some(owner) }),
            (None, maintenance_save::Saved::Governance(Saved::StartupCleanup { .. })) => {
                if continuation
                    .instance
                    .lock()
                    .await
                    .legacy_startup_cleanup_pending()
                {
                    CleanupTurn::Again(None)
                } else {
                    CleanupTurn::Done
                }
            }
            (_, maintenance_save::Saved::Unavailable) => CleanupTurn::Again(owner),
            _ => CleanupTurn::Failed(
                "cleanup completion does not match its retained owner".to_owned(),
            ),
        };
        self.finish_legacy_cleanup_turn(room, owner, turn);
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Done);
        }
    }

    fn finish_legacy_cleanup_turn(
        &mut self,
        id: Digest32,
        selected: CleanupOwner,
        turn: CleanupTurn,
    ) {
        if self.legacy_cleanup_rooms.get(&id).copied() != Some(selected) {
            return;
        }
        match turn {
            CleanupTurn::Again(owner) => {
                self.legacy_cleanup_rooms.insert(id, owner);
                self.legacy_cleanup_due = std::time::Instant::now() + TICK;
            }
            CleanupTurn::Done => {
                self.legacy_cleanup_rooms.remove(&id);
            }
            CleanupTurn::Failed(reason) => {
                self.legacy_cleanup_rooms.remove(&id);
                let _ = self.event_tx.send(NodeEvent::NodeNote {
                    note: format!("room {} could not reclaim provisional history: {reason}; reopen will retry",
                        crate::node::link::b32_encode(&id)),
                });
            }
        }
    }
}

/// A detached multi-certificate command cannot certify the rest of its original room.
/// Resolve its retained reply rather than dropping it when the common native owner retires.
pub(super) fn retire_detached(
    result: crate::error::Result<maintenance_save::Saved>,
    continuation: Continuation,
    reply: Option<oneshot::Sender<Outcome>>,
) {
    if let After::Admin(work) = continuation.after {
        let outcome = match &result {
            Err(error) => Outcome::Failed(fault_of(error)),
            Ok(_) => Outcome::Failed(Fault::ChannelNotOpen),
        };
        let _ = work.reply.send(outcome);
    }
    if let Some(reply) = reply {
        let outcome = match result {
            Ok(maintenance_save::Saved::Unavailable) => Outcome::Failed(Fault::RoomChangePending),
            Ok(_) => Outcome::Done,
            Err(error) => Outcome::Failed(fault_of(&error)),
        };
        let _ = reply.send(outcome);
    }
}
