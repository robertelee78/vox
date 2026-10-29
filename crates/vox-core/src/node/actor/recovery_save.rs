//! Own recovery and settlement advance only from the retained native stage's real result.
use super::*;
use crate::node::channel::pending_text::recovery;
use crate::node::channel::OwnReadability;
use crate::node::store::Store;

use recovery::Work as Step;
pub(super) use recovery::{Completed, Prepared, Saved};
pub(super) struct Work {
    step: Step,
    now: crate::time::Ms,
}
impl Work {
    pub(super) fn support_refresh(now: crate::time::Ms) -> Self {
        Self {
            step: Step::Refresh,
            now,
        }
    }
    pub(super) fn prepare(
        self,
        channel: &mut ChannelState,
        store: &Arc<Store>,
        owner: Arc<()>,
        _now: crate::time::Ms,
    ) -> crate::error::Result<Option<Prepared>> {
        channel.prepare_pending_recovery_work(store, owner, self.step, self.now)
    }
}

#[derive(Clone, Copy)]
enum Stage {
    Offer,
    Settle,
    CatchUp,
    Presence,
    Shares,
    Fence,
    Receiver,
    Audit,
    Ranges,
    Complete,
    Inspect,
}
enum After {
    Producer,
    Governance(governance_save::Retained),
}
struct Offer {
    hint: Option<(Digest32, Digest32, u64)>,
    targets: Vec<Digest32>,
}
pub(super) struct Continuation {
    instance: SharedChannel,
    attachment: u64,
    lifetime: Option<Arc<maintenance_save::Lifetime>>,
    after: After,
    stage: Stage,
    settle: bool,
    recover: bool,
    offer: Option<Offer>,
    back: bool,
    changed: bool,
    completed: bool,
    receiver_changed: bool,
    audit: OwnReadability,
    now: crate::time::Ms,
}
impl Continuation {
    fn new(
        instance: SharedChannel,
        attachment: u64,
        settle: bool,
        recover: bool,
        after: After,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
        now: crate::time::Ms,
    ) -> Self {
        Self {
            instance,
            attachment,
            lifetime,
            after,
            stage: if settle { Stage::Offer } else { Stage::Fence },
            settle,
            recover,
            offer: None,
            back: false,
            changed: false,
            completed: false,
            receiver_changed: false,
            audit: OwnReadability::Waiting,
            now,
        }
    }
    pub(super) fn instance(&self) -> &SharedChannel {
        &self.instance
    }
    pub(super) fn lifetime(&self) -> Option<Arc<maintenance_save::Lifetime>> {
        self.lifetime.as_ref().map(Arc::clone)
    }
    pub(super) fn is_preparation(&self) -> bool {
        false
    }
    fn attached(&self, node: &Node, room: &Digest32) -> bool {
        self.attachment == node.delivery_epoch
            && node
                .channels
                .get(room)
                .is_some_and(|current| Arc::ptr_eq(current, &self.instance))
    }
}

impl Node {
    /// Producer entry point; repeated progress uses the same durable own target, never a timer.
    pub(super) async fn advance_own_recovery(&mut self, room: Digest32) {
        self.begin_owned_recovery(room).await;
    }
    pub(super) async fn begin_owned_recovery(&mut self, room: Digest32) {
        self.try_install_own_key(room);
        self.begin_recovery_chain(room, false, true).await;
    }
    pub(super) async fn settle_room(&mut self, room: &Digest32) {
        self.begin_recovery_chain(*room, true, false).await;
    }
    pub(super) async fn begin_owned_settlement_recovery(&mut self, room: Digest32) {
        self.try_install_own_key(room);
        self.begin_recovery_chain(room, true, true).await;
    }
    async fn begin_recovery_chain(&mut self, room: Digest32, settle: bool, recover: bool) {
        if self.locking != 0
            || self
                .profile
                .as_ref()
                .is_none_or(|profile| !profile.is_unlocked() || profile.signer().is_err())
        {
            return;
        }
        if self.pending_posts.contains_key(&room) {
            self.governance_work.wake_room(room);
            return;
        }
        let Some(instance) = self.channels.get(&room).cloned() else {
            return;
        };
        let continuation = Continuation::new(
            instance,
            self.delivery_epoch,
            settle,
            recover,
            After::Producer,
            None,
            self.now_ms(),
        );
        if settle && !recover {
            let pending = {
                let channel = continuation.instance.lock().await;
                let Some(profile) = self.profile.as_ref() else {
                    return;
                };
                channel.settlement_work_pending(profile.store(), continuation.now, || {
                    self.recovery_offer_peers(room)
                })
            };
            match pending {
                Ok(true) => {}
                Ok(false) => return,
                Err(error) => {
                    self.reject_owned_recovery(room, error, continuation, None);
                    return;
                }
            }
        }
        self.continue_recovery_stage(room, continuation, None).await;
    }
    pub(super) async fn continue_governance_recovery(
        &mut self,
        room: Digest32,
        settle: bool,
        next: governance_save::Retained,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        let instance = Arc::clone(next.instance());
        let lifetime = Arc::clone(&next.lifetime);
        let continuation = Continuation::new(
            instance,
            next.attachment,
            settle,
            true,
            After::Governance(next),
            Some(lifetime),
            self.now_ms(),
        );
        self.continue_recovery_stage(room, continuation, reply)
            .await;
    }
    fn recovery_offer_peers(
        &self,
        room: Digest32,
    ) -> Vec<(Digest32, Option<(u64, crate::node::ports::OwnProbe)>)> {
        self.connected_peers()
            .into_iter()
            .map(|peer| {
                let parked = self
                    .ports
                    .get(&(room, peer))
                    .and_then(|port| port.own_receipt_lower)
                    .zip(
                        self.net
                            .as_ref()
                            .and_then(|net| net.manager().existing(&peer)),
                    )
                    .map(|(probe, connection)| (connection.serial(), probe));
                (peer, parked)
            })
            .collect()
    }

    async fn continue_recovery_stage(
        &mut self,
        room: Digest32,
        continuation: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        let step = match continuation.stage {
            Stage::Offer => Step::Offer(self.recovery_offer_peers(room)),
            Stage::Settle => Step::Settle,
            Stage::CatchUp => Step::CatchUp,
            Stage::Presence => Step::Presence,
            Stage::Shares => Step::Shares,
            Stage::Fence => Step::Fence,
            Stage::Receiver => Step::Receiver,
            Stage::Audit => Step::Audit,
            Stage::Ranges => Step::Ranges,
            Stage::Complete => Step::Complete,
            Stage::Inspect => Step::Inspect,
        };
        let work = Work {
            step,
            now: continuation.now,
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Recovery(work),
            maintenance_save::Continuation::Recovery(continuation),
            reply,
        )
        .await;
    }
    pub(super) fn reject_owned_recovery(
        &mut self,
        room: Digest32,
        error: Error,
        continuation: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        if continuation.attached(self, &room) {
            if matches!(
                error,
                Error::AtRestLocked
                    | Error::Profile("current computer trust changed before save")
                    | Error::Profile("current computer trust is unavailable")
            ) {
                self.defer_own_key_policy(room);
            }
            if ChannelState::receiver_release_cleanup_waiting(&error)
                || ChannelState::governance_refreshing(&error)
                || matches!(error, Error::OwnHistoryBehind)
            {
                self.governance_work.wake_room(room);
            }
        }
        match continuation.after {
            After::Governance(next) => self.reject_owned_governance(room, error, next, reply),
            After::Producer => {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(fault_of(&error)));
                } else {
                    let _ = self.event_tx.send(NodeEvent::JoinFailed {
                        reason: format!(
                            "room {} recovery could not complete its retained save: {error}",
                            crate::node::network::short_id(room)
                        ),
                    });
                }
            }
        }
    }
    pub(super) async fn finish_owned_recovery(
        &mut self,
        room: Digest32,
        result: crate::error::Result<maintenance_save::Saved>,
        lifetime: Arc<maintenance_save::Lifetime>,
        mut continuation: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        if !continuation.attached(self, &room) {
            match continuation.after {
                After::Governance(next) => self.reject_owned_governance(
                    room,
                    Error::Profile("room changed during own recovery"),
                    next,
                    reply,
                ),
                After::Producer => {
                    if let Some(reply) = reply {
                        let _ = reply.send(
                            result
                                .map(|_| Outcome::Done)
                                .unwrap_or_else(|error| Outcome::Failed(fault_of(&error))),
                        );
                    }
                }
            }
            return;
        }
        continuation.lifetime = Some(lifetime);
        let saved = match result {
            Ok(maintenance_save::Saved::Recovery(saved)) => saved,
            Ok(maintenance_save::Saved::Unavailable) => {
                self.reject_owned_recovery(
                    room,
                    Error::Profile("own recovery stage unavailable"),
                    continuation,
                    reply,
                );
                return;
            }
            Ok(_) => {
                self.reject_owned_recovery(
                    room,
                    Error::Profile("own recovery result does not match retained stage"),
                    continuation,
                    reply,
                );
                return;
            }
            Err(error) => {
                if matches!(continuation.stage, Stage::Receiver)
                    && matches!(error, Error::OwnHistoryBehind)
                {
                    continuation.stage = Stage::Audit;
                    self.continue_recovery_stage(room, continuation, reply)
                        .await;
                } else if matches!(continuation.stage, Stage::Receiver)
                    && ChannelState::receiver_release_cleanup_waiting(&error)
                {
                    self.governance_work.wake_room(room);
                    continuation.audit = OwnReadability::Waiting;
                    continuation.stage = Stage::Inspect;
                    self.continue_recovery_stage(room, continuation, reply)
                        .await;
                } else if matches!(continuation.stage, Stage::Ranges | Stage::Complete)
                    && matches!(error, Error::OwnHistoryBehind)
                {
                    continuation.audit = OwnReadability::Waiting;
                    continuation.stage = Stage::Inspect;
                    self.continue_recovery_stage(room, continuation, reply)
                        .await;
                } else if matches!(
                    continuation.stage,
                    Stage::Settle | Stage::CatchUp | Stage::Presence | Stage::Shares
                ) {
                    let _ = self.event_tx.send(NodeEvent::JoinFailed { reason: format!(
                        "joined room {} again, but could not start a new sender key in it: {error}", crate::node::network::short_id(room)) });
                    self.finish_settlement_offer(room, &mut continuation);
                    if continuation.recover {
                        continuation.stage = Stage::Fence;
                        self.continue_recovery_stage(room, continuation, reply)
                            .await;
                    } else {
                        self.finish_recovery_chain(room, continuation, reply).await;
                    }
                } else {
                    self.reject_owned_recovery(room, error, continuation, reply);
                }
                return;
            }
        };
        let next = match (continuation.stage, saved) {
            (Stage::Offer, Saved::Offered { hint, targets }) => {
                continuation.offer = Some(Offer { hint, targets });
                Stage::Settle
            }
            (
                Stage::Settle,
                Saved::Settlement {
                    changed,
                    sparse,
                    eligible,
                },
            ) => {
                continuation.back |= sparse && changed;
                if !eligible {
                    self.finish_settlement_offer(room, &mut continuation);
                    Stage::Fence
                } else if sparse {
                    Stage::Shares
                } else {
                    Stage::CatchUp
                }
            }
            (Stage::CatchUp, Saved::CaughtUp) => Stage::Presence,
            (Stage::Presence, Saved::Presence(back)) => {
                continuation.back |= back;
                Stage::Shares
            }
            (Stage::Shares, Saved::Shares(said)) => {
                continuation.back |= said;
                self.finish_settlement_offer(room, &mut continuation);
                Stage::Fence
            }
            (Stage::Fence, Saved::Inactive) => {
                self.finish_recovery_chain(room, continuation, reply).await;
                return;
            }
            (Stage::Fence, Saved::Fence(changed)) => {
                continuation.changed |= changed;
                Stage::Receiver
            }
            (Stage::Receiver, Saved::Receiver(changed)) => {
                continuation.receiver_changed |= changed;
                Stage::Audit
            }
            (Stage::Audit, Saved::Audit(audit)) => {
                continuation.audit = audit;
                if audit == OwnReadability::Complete {
                    Stage::Ranges
                } else {
                    Stage::Inspect
                }
            }
            (Stage::Ranges, Saved::Ranges) => Stage::Complete,
            (Stage::Complete, Saved::Recovered(completed)) => {
                continuation.completed |= completed;
                Stage::Inspect
            }
            (Stage::Inspect, Saved::Inspected(key)) => {
                self.install_recovery_effects(room, &continuation, key);
                self.finish_recovery_chain(room, continuation, reply).await;
                return;
            }
            _ => {
                self.reject_owned_recovery(
                    room,
                    Error::Profile("own recovery completion has another retained stage"),
                    continuation,
                    reply,
                );
                return;
            }
        };
        if matches!(next, Stage::Fence) && !continuation.recover {
            self.finish_recovery_chain(room, continuation, reply).await;
            return;
        }
        continuation.stage = next;
        self.continue_recovery_stage(room, continuation, reply)
            .await;
    }
    fn finish_settlement_offer(&mut self, room: Digest32, continuation: &mut Continuation) {
        if continuation.back {
            self.note_local_governance_append(&room);
            continuation.back = false;
        }
        if let Some(offer) = continuation.offer.take() {
            self.offer_own_head(&room, offer.hint, offer.targets);
        }
        if continuation.recover {
            continuation.now = self.now_ms();
        }
    }
    async fn finish_recovery_chain(
        &mut self,
        room: Digest32,
        continuation: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        match continuation.after {
            After::Governance(next) => self.finish_governance_recovery(room, next, reply).await,
            After::Producer => {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Done);
                }
                if let Some(lifetime) = continuation.lifetime.filter(|_| continuation.settle) {
                    // The synchronous producer used to return before its caller released
                    // owed keys. Transfer that causal tail only after the real native
                    // settlement terminal, under its original publication/secret lifetime.
                    Box::pin(self.begin_owned_rekeys_for(
                        room,
                        false,
                        Some(Arc::clone(&lifetime)),
                        consent_release::RekeyAfter::Settlement { lifetime },
                    ))
                    .await;
                }
            }
        }
    }
    fn install_recovery_effects(
        &mut self,
        room: Digest32,
        continuation: &Continuation,
        key: Option<(Digest32, u64, bool)>,
    ) {
        let shared = &continuation.instance;
        let audit = continuation.audit;
        if audit == OwnReadability::Runnable {
            self.governance_work.wake_room(room);
        }
        if let OwnReadability::EffectReady {
            target,
            seq,
            entry_hash,
        } = audit
        {
            let same = self.own_readable_effects.get(&room).is_some_and(|ready| {
                ready.target == target
                    && ready.seq == seq
                    && ready.entry_hash == entry_hash
                    && ready
                        .instance
                        .upgrade()
                        .is_some_and(|held| Arc::ptr_eq(&held, shared))
            });
            if !same {
                self.own_readable_effects.insert(
                    room,
                    ReadableOwnEffect {
                        instance: Arc::downgrade(shared),
                        target,
                        seq,
                        entry_hash,
                        woken: BTreeSet::new(),
                    },
                );
            }
            self.retry_readable_own_effect(room);
        }
        if let OwnReadability::KeyDebt {
            target,
            epoch,
            chain,
            iteration,
            ..
        } = audit
        {
            self.start_own_key_request(room, target, epoch, chain, iteration);
        }
        if continuation.receiver_changed {
            self.governance_work.wake_room(room);
        }
        if continuation.completed {
            self.note_local_governance_append(&room);
        }
        let debt = match audit {
            OwnReadability::BodyDebt {
                target,
                seq,
                entry_hash,
            } => Some((target, seq, entry_hash)),
            _ => None,
        };
        let debt_changed = match debt {
            Some(debt) => self.own_recovery_body_debts.insert(room, debt) != Some(debt),
            None => self.own_recovery_body_debts.remove(&room).is_some(),
        };
        let progress = match key {
            Some(key) => self.own_recovery_rooms.insert(room, key) != Some(key),
            None => {
                self.own_recovery_rooms.remove(&room);
                false
            }
        };
        if continuation.completed || key.is_none() {
            self.own_readable_effects.remove(&room);
        }
        if progress || debt_changed {
            for ((r, _), port) in &mut self.ports {
                if *r == room {
                    port.raise();
                }
            }
            self.sched_rooms.insert(room);
        }
        if continuation.changed || continuation.completed {
            let note = if continuation.completed {
                "this node recovered its own history; it can write here again"
            } else {
                "this node is behind its own history; it cannot write here until recovery completes"
            };
            let _ = self.event_tx.send(NodeEvent::NodeNote {
                note: format!("room {}: {note}", crate::node::link::b32_encode(&room)),
            });
        }
    }
}
