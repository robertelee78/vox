//! Original consent delivery ownership survives native grants and their exact continuation.
use super::*;
use crate::group::skdm::Skdm;
use crate::node::channel::pending_session::{SessionSaved, SessionWrite};
use crate::node::channel::pending_text::consent::ConsentSaved;
use crate::node::keypackage::KeyPackage;
use maintenance_save::{Lifetime, Saved, Work};

mod outbound;
mod rekeys;
pub(super) use rekeys::RekeyAfter;

type Cursor = Arc<std::sync::Mutex<Owed>>;
type Reply = Option<oneshot::Sender<Outcome>>;

struct Owed {
    rooms: VecDeque<Digest32>,
    room: Option<Digest32>,
    targets: VecDeque<Digest32>,
    trusted: Arc<BTreeSet<Digest32>>,
    asked_for: Option<Digest32>,
    lifetime: Option<Arc<Lifetime>>,
    terminal: Option<oneshot::Sender<crate::error::Result<()>>>,
    stopped: bool,
    wake: Arc<tokio::sync::Notify>,
}

pub(super) struct Offline {
    attempt: u64,
    source_room: Digest32,
    asked: bool,
}

enum Route {
    Online {
        conn: Arc<VoxConnection>,
        modern: bool,
    },
    Offline(Offline),
}

enum Stage {
    Vacant,
    Outbound(outbound::Stage),
    Rekeys(Box<rekeys::Target>),
    Hold(Route),
    Online {
        queue: mpsc::OwnedPermit<PairwiseJob>,
        job: PairwiseJob,
    },
    Legacy {
        conn: Arc<VoxConnection>,
        queue: mpsc::OwnedPermit<PairwiseJob>,
        credit: PairwiseCredit,
    },
    Offline {
        route: Offline,
        posted_as: Digest32,
    },
    Packages {
        route: Offline,
        keys: VecDeque<Skdm>,
        history: bool,
        generation: u64,
        posted_as: Digest32,
    },
    Delivered(Offline),
    Acknowledged {
        history: bool,
        whole_history: bool,
    },
}

pub(super) struct Continuation {
    instance: SharedChannel,
    attachment: u64,
    lifetime: Option<Arc<Lifetime>>,
    target: Digest32,
    asked: bool,
    history: crate::node::trust::HistoryGrant,
    decision: Option<crate::node::consent_order::Stamp>,
    plan: Option<ReleasePlan>,
    cursor: Option<Cursor>,
    prekey: Option<prekeys::OneTimeReservation>,
    stage: Stage,
}

impl Continuation {
    pub(super) fn instance(&self) -> &SharedChannel {
        &self.instance
    }
    pub(super) fn lifetime(&self) -> Option<Arc<Lifetime>> {
        self.lifetime.as_ref().map(Arc::clone)
    }
    pub(super) fn is_preparation(&self) -> bool {
        false
    }
    pub(super) fn mark_confirmed_package(&mut self) {
        if let Some(reservation) = &self.prekey {
            reservation.mark_named();
        }
    }
    pub(super) fn mark_unconfirmed_package(&mut self) {
        if let Some(reservation) = &self.prekey {
            reservation.mark_uncertain();
        }
    }
    fn attached(&self, node: &Node, room: &Digest32) -> bool {
        self.attachment == node.delivery_epoch
            && node
                .channels
                .get(room)
                .is_some_and(|current| Arc::ptr_eq(current, &self.instance))
    }
    fn trusted(&self, node: &Node) -> bool {
        node.trust.is_trusted(&self.target)
            && node.trust.history(&self.target) == self.history
            && node.trust_decision(&self.target) == self.decision
    }
}

impl Node {
    pub(super) async fn begin_owned_pairwise_receipt(
        &mut self,
        room: Digest32,
        target: Digest32,
        generation: u64,
        history: bool,
        whole_history: bool,
    ) {
        if self.profile.is_none() {
            return;
        }
        let Some(instance) = self.channels.get(&room).cloned() else {
            return;
        };
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime: None,
            target,
            asked: false,
            history: self.trust.history(&target),
            decision: self.trust_decision(&target),
            plan: None,
            cursor: None,
            prekey: None,
            stage: Stage::Acknowledged {
                history,
                whole_history,
            },
        };
        self.begin_pending_maintenance(
            room,
            Work::Consent(consent_save::Work::Delivered {
                target,
                generation,
                history: whole_history,
            }),
            maintenance_save::Continuation::Consent(continuation),
            None,
        )
        .await;
    }

    pub(super) async fn deliver_owed_consents(&mut self, asked_for: Option<Digest32>) {
        self.begin_owned_consent_pass(asked_for, None, None).await;
    }

    pub(super) async fn deliver_through_log(&mut self, attempt: u64, owner: MemberReachOwner) {
        if self.net.is_none() {
            return;
        }
        let trusted = self.trust.trusted();
        let rooms: Vec<_> = self.channels.keys().copied().collect();
        for room in rooms {
            let Some(instance) = self.channels.get(&room).cloned() else {
                continue;
            };
            let owed = {
                let channel = instance.lock().await;
                let Some(profile) = self.profile.as_ref() else {
                    return;
                };
                match channel.owed_consents(profile.store(), &trusted) {
                    Ok(owed) => owed.contains(&owner.peer),
                    Err(_) => continue,
                }
            };
            if owed {
                self.begin_owned_offline_consent(
                    room,
                    owner.peer,
                    attempt,
                    owner.room,
                    owner.asked,
                )
                .await;
            } else {
                self.begin_owned_log_rekeys(
                    room,
                    owner.peer,
                    Offline {
                        attempt,
                        source_room: owner.room,
                        asked: owner.asked,
                    },
                    None,
                )
                .await;
            }
        }
    }

    /// The managed policy retains its ORIGINAL exclusive transition while this actual receipt
    /// waits. Its provided lifetime intentionally has publication=None; never acquire a reader.
    pub(super) async fn begin_owned_owed_consents(
        &mut self,
        lifetime: Arc<Lifetime>,
        reply: oneshot::Sender<crate::error::Result<()>>,
    ) {
        self.begin_owned_owed_consents_for(lifetime, None, reply)
            .await;
    }

    /// As the original owed-consent pass, the requested identity is dialled once immediately;
    /// it does not filter out other admitted/trusted members' existing durable obligations.
    pub(super) async fn begin_owned_owed_consents_for(
        &mut self,
        lifetime: Arc<Lifetime>,
        asked_for: Option<Digest32>,
        reply: oneshot::Sender<crate::error::Result<()>>,
    ) {
        self.begin_owned_consent_pass(asked_for, Some(lifetime), Some(reply))
            .await;
    }

    pub(super) async fn begin_owned_consent_pass(
        &mut self,
        asked_for: Option<Digest32>,
        lifetime: Option<Arc<Lifetime>>,
        terminal: Option<oneshot::Sender<crate::error::Result<()>>>,
    ) {
        if self.net.is_none() || (lifetime.is_none() && !self.computer_authority_current()) {
            if let Some(terminal) = terminal {
                let _ = terminal.send(if self.net.is_none() {
                    Ok(())
                } else {
                    Err(Error::Profile("consent release is not authorized"))
                });
                self.post_save_wake.notify_one();
            }
            return;
        }
        self.deliver_reopens().await;
        let cursor = Arc::new(std::sync::Mutex::new(Owed {
            rooms: self.channels.keys().copied().collect(),
            room: None,
            targets: VecDeque::new(),
            trusted: Arc::new(self.trust.trusted()),
            asked_for,
            lifetime,
            terminal,
            stopped: false,
            wake: Arc::clone(&self.post_save_wake),
        }));
        self.advance_owned_owed_consents(cursor).await;
    }

    async fn advance_owned_owed_consents(&mut self, cursor: Cursor) {
        loop {
            let selected = {
                let mut owed = cursor
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if owed.stopped {
                    return;
                }
                if let (Some(room), Some(target)) = (owed.room, owed.targets.pop_front()) {
                    Some((
                        room,
                        target,
                        owed.asked_for == Some(target),
                        owed.lifetime.as_ref().map(Arc::clone),
                    ))
                } else {
                    None
                }
            };
            if let Some((room, target, asked, lifetime)) = selected {
                match self
                    .prepare_owned_online_consent(
                        room,
                        target,
                        asked,
                        lifetime,
                        Arc::clone(&cursor),
                    )
                    .await
                {
                    Ok(true) => return,
                    Ok(false) => continue,
                    Err(fault) => {
                        let managed = cursor
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .terminal
                            .is_some();
                        if managed
                            && matches!(
                                fault,
                                Fault::RoomChangePending
                                    | Fault::ComputerPolicy
                                    | Fault::NotTrusted
                            )
                        {
                            self.finish_owned_consent_cursor(
                                &cursor,
                                Err(Error::Profile(
                                    "consent prerequisite changed before publication",
                                )),
                            );
                            return;
                        }
                        if asked && matches!(fault, Fault::Unreachable) {
                            cursor
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .asked_for = None;
                        }
                        continue;
                    }
                }
            }
            let next = {
                let mut owed = cursor
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                owed.room = None;
                owed.rooms
                    .pop_front()
                    .map(|room| (room, owed.trusted.clone(), owed.asked_for))
            };
            let Some((room, trusted, asked_for)) = next else {
                self.finish_owned_consent_cursor(&cursor, Ok(()));
                return;
            };
            let Some(instance) = self.channels.get(&room).cloned() else {
                continue;
            };
            let targets = {
                let channel = instance.lock().await;
                let Some(profile) = self.profile.as_ref() else {
                    self.finish_owned_consent_cursor(&cursor, Err(Error::AtRestLocked));
                    return;
                };
                match channel.owed_consents(profile.store(), &trusted) {
                    Ok(targets) => {
                        if let Some(target) = asked_for.filter(|target| !targets.contains(target)) {
                            let why = if !channel.is_settled() {
                                Some("this node has not synced the room since it joined, so writes nothing there yet")
                            } else if !channel.is_author(&target) && channel.me() != target {
                                Some("this node has not admitted it to the room yet, so holds no key of its to check")
                            } else {
                                None
                            };
                            if let (Some(why), Some(net)) = (why, self.net.as_ref()) {
                                net.manager().note(target, format!("your key for it in room {} waits: {why}; it is sent once that changes",
                                    crate::node::network::short_id(room)));
                            }
                        }
                        targets
                    }
                    Err(error) => {
                        if let (Some(target), Some(net)) = (asked_for, self.net.as_ref()) {
                            net.manager().note(
                                target,
                                format!(
                                    "your key for it in room {} waits: {error}",
                                    crate::node::network::short_id(room)
                                ),
                            );
                        }
                        continue;
                    }
                }
            };
            let mut owed = cursor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            owed.room = Some(room);
            owed.targets = targets.into_iter().collect();
        }
    }

    fn finish_owned_consent_cursor(&self, cursor: &Cursor, result: crate::error::Result<()>) {
        let mut owed = cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if owed.stopped {
            return;
        }
        owed.stopped = true;
        if let Some(terminal) = owed.terminal.take() {
            let _ = terminal.send(result);
            self.post_save_wake.notify_one();
        }
    }

    async fn prepare_owned_online_consent(
        &mut self,
        room: Digest32,
        target: Digest32,
        asked: bool,
        lifetime: Option<Arc<Lifetime>>,
        cursor: Cursor,
    ) -> std::result::Result<bool, Fault> {
        if !self.trust.is_trusted(&target) {
            return Err(Fault::NotTrusted);
        }
        if lifetime.is_none() && !self.computer_authority_current() {
            return Err(Fault::ComputerPolicy);
        }
        if self.pending_posts.contains_key(&room) {
            self.redeliver_now = true;
            return Err(Fault::RoomChangePending);
        }
        let instance = self
            .channels
            .get(&room)
            .cloned()
            .ok_or(Fault::UnknownChannel)?;
        {
            let channel = instance.lock().await;
            let profile = self.profile.as_ref().ok_or(Fault::UnknownChannel)?;
            if !channel.is_author(&target) {
                return Err(Fault::NotAdmitted);
            }
            if !channel.is_settled() {
                return Err(Fault::RoomNotSynced);
            }
            if channel.own_history_behind() {
                return Err(Fault::OwnHistoryBehind);
            }
            channel
                .require_governance_ready(profile.store(), self.now_ms())
                .map_err(|error| fault_of(&error))?;
        }
        let conn = self
            .reach_member(&room, target, asked)
            .await
            .ok_or(Fault::Unreachable)?;
        let modern = !matches!(self.older.get(&(room, target)), Some(false));
        if modern {
            if let Err(wait) = self.delivery_bundle_waiting(&room, target, false).await {
                self.say_key_waits(&room, target, wait);
                return Err(Fault::Unreachable);
            }
        }
        let history = self.trust.history(&target);
        let decision = self.trust_decision(&target);
        let (skdm, plan, hold) = {
            let channel = instance.lock().await;
            self.prepare_owned_consent_key(&channel, target, history, decision)?
        };
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime,
            target,
            asked,
            history,
            decision,
            plan,
            cursor: Some(cursor),
            prekey: None,
            stage: Stage::Hold(Route::Online { conn, modern }),
        };
        if hold {
            Ok(self
                .begin_pending_maintenance(
                    room,
                    Work::Consent(consent_save::Work::Hold {
                        target,
                        skdm: Box::new(skdm),
                    }),
                    maintenance_save::Continuation::Consent(continuation),
                    None,
                )
                .await)
        } else {
            self.frame_owned_consent(room, Box::new(skdm), continuation, &mut None)
                .await
        }
    }

    /// Pure committed reads/signing only. The fallback pending-key write is a native Hold stage.
    fn prepare_owned_consent_key(
        &self,
        channel: &ChannelState,
        target: Digest32,
        history: crate::node::trust::HistoryGrant,
        decision: Option<crate::node::consent_order::Stamp>,
    ) -> std::result::Result<(Skdm, Option<ReleasePlan>, bool), Fault> {
        let profile = self.profile.as_ref().ok_or(Fault::UnknownChannel)?;
        if !channel.is_author(&target) {
            return Err(Fault::NotAdmitted);
        }
        if !channel.is_settled() {
            return Err(Fault::RoomNotSynced);
        }
        if channel.own_history_behind() {
            return Err(Fault::OwnHistoryBehind);
        }
        channel
            .require_governance_ready(profile.store(), self.now_ms())
            .map_err(|error| fault_of(&error))?;
        let selected = (|| -> crate::error::Result<_> {
            if history == crate::node::trust::HistoryGrant::Full {
                let (live, plan) = channel.full_consent_release(profile)?;
                return Ok((live, Some(plan), false));
            }
            let plan = channel.history_plan(profile.store(), &target, decision)?;
            if let Some(&(generation, iteration)) = plan.as_ref().and_then(|plan| plan.last()) {
                return Ok((
                    channel.release_generation(profile, generation, iteration)?,
                    plan,
                    false,
                ));
            }
            let held = self
                .consent_keys
                .get(&channel.channel_id(), &target)
                .and_then(|wire| Skdm::from_wire(wire).ok())
                .filter(|key| key.body.epoch == channel.epoch());
            let key = match held {
                Some(key) => key,
                None => channel.skdm_for_consent(profile)?,
            };
            Ok((key, None, true))
        })();
        selected.map_err(|error| fault_of(&error))
    }

    pub(super) async fn begin_owned_offline_consent(
        &mut self,
        room: Digest32,
        peer: Digest32,
        attempt: u64,
        source_room: Digest32,
        asked: bool,
    ) {
        if !self.trust.is_trusted(&peer) {
            return;
        }
        let Some(instance) = self.channels.get(&room).cloned() else {
            return;
        };
        let history = self.trust.history(&peer);
        let decision = self.trust_decision(&peer);
        let selected = {
            let channel = instance.lock().await;
            self.prepare_owned_consent_key(&channel, peer, history, decision)
        };
        let Ok((skdm, plan, hold)) = selected else {
            return;
        };
        self.key_delivery_settling.insert((room, peer));
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime: None,
            target: peer,
            asked,
            history,
            decision,
            plan,
            cursor: None,
            prekey: None,
            stage: Stage::Hold(Route::Offline(Offline {
                attempt,
                source_room,
                asked,
            })),
        };
        if hold {
            self.begin_pending_maintenance(
                room,
                Work::Consent(consent_save::Work::Hold {
                    target: peer,
                    skdm: Box::new(skdm),
                }),
                maintenance_save::Continuation::Consent(continuation),
                None,
            )
            .await;
        } else {
            let _ = self
                .frame_owned_consent(room, Box::new(skdm), continuation, &mut None)
                .await;
        }
    }

    pub(super) fn reject_owned_consent(
        &mut self,
        room: Digest32,
        error: Error,
        continuation: Continuation,
        reply: Reply,
    ) {
        let fault = fault_of(&error);
        if let Stage::Acknowledged {
            history: _history,
            whole_history: _whole_history,
        } = &continuation.stage
        {
            #[cfg(feature = "test-knobs")]
            if continuation.attached(self, &room) {
                self.mark_delivery_drained_for_proof(
                    room,
                    continuation.target,
                    *_history,
                    *_whole_history,
                    false,
                );
            }
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(fault));
            }
            return;
        }
        if let Stage::Rekeys(target) = continuation.stage {
            self.reject_owned_rekeys(*target, error);
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(fault));
            }
            return;
        }
        let route = match &continuation.stage {
            Stage::Offline { route, .. } | Stage::Hold(Route::Offline(route)) => Some(route),
            Stage::Outbound(stage) => outbound::offline_route(stage),
            _ => None,
        };
        if let Some(route) = route {
            self.offline_fallbacks.insert(
                (room, continuation.target),
                OfflineFallback {
                    attempt: route.attempt,
                    source_room: route.source_room,
                    room,
                    peer: continuation.target,
                    asked: route.asked,
                    package_seq: None,
                    consent_seq: None,
                },
            );
        }
        if let Some(cursor) = continuation.cursor {
            let managed = cursor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .terminal
                .is_some();
            if managed {
                self.finish_owned_consent_cursor(&cursor, Err(error));
            } else if self.pending_posts.contains_key(&room) {
                self.redeliver_now = true;
            }
        }
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(fault));
        }
    }

    async fn fail_owned_consent(
        &mut self,
        room: Digest32,
        error: Error,
        continuation: Continuation,
        reply: Reply,
    ) {
        let cursor = continuation.cursor.as_ref().map(Arc::clone);
        let managed = cursor.as_ref().is_some_and(|cursor| {
            cursor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .terminal
                .is_some()
        });
        self.reject_owned_consent(room, error, continuation, reply);
        if !managed {
            if let Some(cursor) = cursor {
                self.advance_owned_owed_consents(cursor).await;
            }
        }
    }

    pub(super) async fn wait_owned_consent(
        &mut self,
        room: Digest32,
        continuation: Continuation,
        reply: Reply,
    ) {
        let route = match &continuation.stage {
            Stage::Offline { route, .. } | Stage::Hold(Route::Offline(route)) => Some(route),
            Stage::Outbound(stage) => outbound::offline_route(stage),
            _ => None,
        };
        if let Some(route) = route {
            self.offline_fallbacks.insert(
                (room, continuation.target),
                OfflineFallback {
                    attempt: route.attempt,
                    source_room: route.source_room,
                    room,
                    peer: continuation.target,
                    asked: route.asked,
                    package_seq: None,
                    consent_seq: None,
                },
            );
        }
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(Fault::Unreachable));
        }
        if let Some(cursor) = continuation.cursor {
            if continuation.asked {
                cursor
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .asked_for = None;
            }
            self.advance_owned_owed_consents(cursor).await;
        }
    }

    pub(super) async fn after_owned_consent_enqueue(
        &mut self,
        room: Digest32,
        history_owed: bool,
        mut continuation: Continuation,
        lifetime: Arc<Lifetime>,
        reply: Reply,
    ) {
        continuation.prekey = None;
        let _ = self.event_tx.send(NodeEvent::Consented {
            channel_id: room,
            target: continuation.target,
        });
        if history_owed {
            self.begin_owned_rekeys_for(
                room,
                continuation.asked,
                Some(lifetime),
                RekeyAfter::Consent {
                    next: Box::new(continuation),
                    reply,
                },
            )
            .await;
        } else {
            self.finish_owned_consent_tail(continuation, reply).await;
        }
    }

    pub(super) async fn finish_owned_consent_tail(
        &mut self,
        continuation: Continuation,
        reply: Reply,
    ) {
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Done);
        }
        if let Some(cursor) = continuation.cursor {
            self.advance_owned_owed_consents(cursor).await;
        }
    }

    pub(super) async fn finish_owned_consent(
        &mut self,
        room: Digest32,
        result: crate::error::Result<Saved>,
        lifetime: Arc<Lifetime>,
        mut continuation: Continuation,
        mut reply: Reply,
    ) {
        if matches!(&continuation.stage, Stage::Rekeys(_)) {
            self.finish_owned_rekeys(room, result, lifetime, continuation)
                .await;
            return;
        }
        if !continuation.attached(self, &room)
            || (!matches!(&continuation.stage, Stage::Acknowledged { .. })
                && !continuation.trusted(self))
        {
            self.fail_owned_consent(
                room,
                Error::Profile("consent release attachment or trust changed"),
                continuation,
                reply,
            )
            .await;
            return;
        }
        continuation.lifetime = Some(Arc::clone(&lifetime));
        let saved = match result {
            Ok(saved) => saved,
            Err(error) => {
                self.fail_owned_consent(room, error, continuation, reply)
                    .await;
                return;
            }
        };
        if let Saved::Consent(consent_save::Effect::Held(held)) = saved {
            if held.retained {
                let _ = self
                    .consent_keys
                    .insert(room, continuation.target, held.skdm.to_wire());
            }
            let cursor = continuation.cursor.as_ref().map(Arc::clone);
            let asked = continuation.asked;
            match self
                .frame_owned_consent(room, held.skdm, continuation, &mut reply)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    if let Some(cursor) = cursor {
                        self.advance_owned_owed_consents(cursor).await;
                    }
                }
                Err(fault) => {
                    if let Some(reply) = reply {
                        let _ = reply.send(Outcome::Failed(fault));
                    }
                    if let Some(cursor) = cursor {
                        if asked && matches!(fault, Fault::Unreachable) {
                            cursor
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .asked_for = None;
                        }
                        if matches!(fault, Fault::NotTrusted | Fault::ComputerPolicy) {
                            self.finish_owned_consent_cursor(
                                &cursor,
                                Err(Error::Profile("consent trust changed before enqueue")),
                            );
                        } else {
                            self.advance_owned_owed_consents(cursor).await;
                        }
                    }
                }
            }
            return;
        }
        if matches!(&continuation.stage, Stage::Outbound(_)) {
            self.finish_owned_consent_outbound(room, saved, lifetime, continuation, reply)
                .await;
            return;
        }
        if let Saved::Consent(consent_save::Effect::Publication {
            package_seq,
            consent_seq,
            ..
        }) = &saved
        {
            if package_seq.is_some() || consent_seq.is_some() {
                self.note_local_governance_append(&room);
            }
        }
        let stage = std::mem::replace(&mut continuation.stage, Stage::Vacant);
        match (stage, saved) {
            (
                Stage::Legacy {
                    conn,
                    queue,
                    credit,
                },
                Saved::Consent(consent_save::Effect::Publication {
                    result, release, ..
                }),
            ) => {
                let history_owed = match result {
                    Ok(ConsentSaved::Issued { history_owed, .. }) => history_owed,
                    Err(error) => {
                        self.fail_owned_consent(room, error, continuation, reply)
                            .await;
                        return;
                    }
                    _ => {
                        self.fail_owned_consent(
                            room,
                            Error::Profile("unexpected legacy consent grant"),
                            continuation,
                            reply,
                        )
                        .await;
                        return;
                    }
                };
                let Some(skdm) = release else {
                    self.fail_owned_consent(
                        room,
                        Error::Profile("committed consent release missing"),
                        continuation,
                        reply,
                    )
                    .await;
                    return;
                };
                self.continue_owned_legacy_consent(
                    room,
                    outbound::LegacyConsent {
                        skdm,
                        history_owed,
                        conn,
                        queue,
                        credit,
                    },
                    continuation,
                    lifetime,
                    reply,
                )
                .await;
            }
            (
                Stage::Online { queue, job },
                Saved::Consent(consent_save::Effect::Publication { result, .. }),
            ) => match result {
                Ok(ConsentSaved::Issued { history_owed, .. }) => {
                    *self
                        .keys_in_flight
                        .entry((room, continuation.target))
                        .or_default() += 1;
                    queue.send(job);
                    self.after_owned_consent_enqueue(
                        room,
                        history_owed,
                        continuation,
                        lifetime,
                        reply,
                    )
                    .await;
                }
                Err(error) => {
                    if let Some(reply) = reply {
                        let _ = reply.send(Outcome::Failed(fault_of(&error)));
                    }
                    if let Some(cursor) = continuation.cursor {
                        let managed = cursor
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .terminal
                            .is_some();
                        if managed {
                            self.finish_owned_consent_cursor(&cursor, Err(error));
                        } else {
                            self.advance_owned_owed_consents(cursor).await;
                        }
                    }
                }
                _ => {
                    if let Some(reply) = reply {
                        let _ = reply.send(Outcome::Failed(Fault::Internal));
                    }
                    if let Some(cursor) = continuation.cursor {
                        self.finish_owned_consent_cursor(
                            &cursor,
                            Err(Error::Profile("unexpected consent grant result")),
                        );
                    }
                }
            },
            (
                Stage::Offline { route, posted_as },
                Saved::Consent(consent_save::Effect::Publication {
                    result,
                    package_seq,
                    consent_seq,
                    package,
                    ..
                }),
            ) => {
                if let Some(package) = package.as_ref().filter(|_| package_seq.is_some()) {
                    self.note_key_package_posted((room, continuation.target, posted_as), package);
                    continuation.prekey = None;
                }
                if result.is_err() && package_seq.is_none() {
                    continuation.mark_unconfirmed_package();
                }
                let granted = matches!(result, Ok(ConsentSaved::Issued { .. }));
                self.offline_fallbacks.insert(
                    (room, continuation.target),
                    OfflineFallback {
                        attempt: route.attempt,
                        source_room: route.source_room,
                        room,
                        peer: continuation.target,
                        asked: route.asked,
                        package_seq,
                        consent_seq,
                    },
                );
                if granted {
                    let _ = self.event_tx.send(NodeEvent::Consented {
                        channel_id: room,
                        target: continuation.target,
                    });
                    let target = continuation.target;
                    self.begin_owned_log_rekeys(room, target, route, Some(lifetime))
                        .await;
                } else if let Some(reply) = reply {
                    let outcome = result
                        .map(|_| Outcome::Done)
                        .unwrap_or_else(|error| Outcome::Failed(fault_of(&error)));
                    let _ = reply.send(outcome);
                }
            }
            (
                Stage::Packages {
                    route,
                    keys,
                    history,
                    generation,
                    posted_as,
                },
                Saved::Session(SessionSaved::Package { package, .. }),
            ) => {
                self.note_key_package_posted((room, continuation.target, posted_as), &package);
                self.note_local_governance_append(&room);
                continuation.prekey = None;
                let next = Continuation {
                    stage: Stage::Delivered(route),
                    ..continuation
                };
                self.advance_owned_log_keys(room, next, keys, history, generation)
                    .await;
            }
            (Stage::Delivered(_), Saved::Consent(consent_save::Effect::Delivered)) => {
                self.settle_owned_key_receipt(room, &continuation).await;
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Done);
                }
            }
            (
                Stage::Acknowledged {
                    history: _history,
                    whole_history: _whole_history,
                },
                Saved::Consent(consent_save::Effect::Delivered),
            ) => {
                self.settle_owned_key_receipt(room, &continuation).await;
                #[cfg(feature = "test-knobs")]
                self.mark_delivery_drained_for_proof(
                    room,
                    continuation.target,
                    _history,
                    _whole_history,
                    true,
                );
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Done);
                }
            }
            _ => {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::Internal));
                }
                if let Some(cursor) = continuation.cursor {
                    self.finish_owned_consent_cursor(
                        &cursor,
                        Err(Error::Profile("unexpected consent publication completion")),
                    );
                }
            }
        }
        self.post_save_wake.notify_one();
    }
    async fn settle_owned_key_receipt(&mut self, room: Digest32, continuation: &Continuation) {
        let pending = {
            let channel = continuation.instance.lock().await;
            self.profile.as_ref().is_none_or(|profile| {
                channel
                    .key_delivery_pending(profile.store(), &continuation.target)
                    .unwrap_or(true)
            })
        };
        if !pending
            && !self
                .keys_in_flight
                .contains_key(&(room, continuation.target))
            && !self
                .history_in_flight
                .contains_key(&(room, continuation.target))
        {
            self.key_delivery_settling
                .remove(&(room, continuation.target));
        }
    }

    pub(super) async fn begin_owned_log_rekeys(
        &mut self,
        room: Digest32,
        peer: Digest32,
        route: Offline,
        lifetime: Option<Arc<Lifetime>>,
    ) {
        let Some(instance) = self.channels.get(&room).cloned() else {
            return;
        };
        let selected = {
            let channel = instance.lock().await;
            let Some(profile) = self.profile.as_ref() else {
                return;
            };
            let Ok(floor) = channel.owed_history_for(profile.store(), &peer) else {
                return;
            };
            let history = floor
                .and_then(|floor| channel.history_skdms(profile, &peer, floor).ok())
                .filter(|keys| !keys.is_empty());
            let Ok(owed) = channel.owed_rekey(profile.store(), &peer) else {
                return;
            };
            let rekey = if history.is_none() && owed {
                channel.rekey_skdm_for(profile, &peer).ok()
            } else {
                None
            };
            (history, rekey, channel.sender_generation())
        };
        let (history, rekey, generation) = selected;
        let history_sent = history.is_some();
        let keys: VecDeque<_> = match (history, rekey) {
            (Some(keys), _) => keys.into(),
            (None, Some(key)) => [key].into(),
            _ => return,
        };
        self.key_delivery_settling.insert((room, peer));
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime,
            target: peer,
            asked: route.asked,
            history: self.trust.history(&peer),
            decision: self.trust_decision(&peer),
            plan: None,
            cursor: None,
            prekey: None,
            stage: Stage::Delivered(route),
        };
        self.advance_owned_log_keys(room, continuation, keys, history_sent, generation)
            .await;
    }

    async fn advance_owned_log_keys(
        &mut self,
        room: Digest32,
        mut continuation: Continuation,
        mut keys: VecDeque<Skdm>,
        history: bool,
        generation: u64,
    ) {
        while let Some(key) = keys.pop_front() {
            if !continuation.attached(self, &room) || !continuation.trusted(self) {
                return;
            }
            let posted_as = (
                room,
                continuation.target,
                crate::governance::membership::skdm_ref(&key),
            );
            if self.packages_posted.contains(&posted_as) {
                continue;
            }
            let Some(selected) = self
                .select_owned_key_package(&room, continuation.target)
                .await
            else {
                return;
            };
            let Stage::Delivered(route) = std::mem::replace(&mut continuation.stage, Stage::Vacant)
            else {
                return;
            };
            continuation.stage = Stage::Outbound(outbound::Stage::SealLog {
                route,
                keys,
                history,
                generation,
                posted_as: posted_as.2,
            });
            self.begin_pending_maintenance(
                room,
                Work::Packages(selected.into_work(continuation.target, Box::new(key))),
                maintenance_save::Continuation::Consent(continuation),
                None,
            )
            .await;
            return;
        }
        self.begin_pending_maintenance(
            room,
            Work::Consent(consent_save::Work::Delivered {
                target: continuation.target,
                generation,
                history,
            }),
            maintenance_save::Continuation::Consent(continuation),
            None,
        )
        .await;
    }
}

/// Retirement cannot enqueue a key or promote a committed intermediate to aggregate success.
pub(super) fn retire_detached(
    result: crate::error::Result<Saved>,
    continuation: Continuation,
    reply: Reply,
) {
    if let Stage::Rekeys(target) = continuation.stage {
        rekeys::retire(
            *target,
            result
                .err()
                .unwrap_or(Error::Profile("rekey publication retired before enqueue")),
        );
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(Fault::RoomChangePending));
        }
        return;
    }
    let final_delivery =
        matches!(
            &continuation.stage,
            Stage::Delivered(_) | Stage::Acknowledged { .. }
        ) && matches!(&result, Ok(Saved::Consent(consent_save::Effect::Delivered)));
    let result = match result {
        Err(error) => Err(error),
        Ok(Saved::Consent(consent_save::Effect::Publication {
            result: Err(error), ..
        })) => Err(error),
        Ok(_) if final_delivery && continuation.cursor.is_none() => Ok(()),
        Ok(_) => Err(Error::Profile(
            "consent publication retired before its delivery continuation",
        )),
    };
    let outcome = result
        .as_ref()
        .map(|()| Outcome::Done)
        .unwrap_or_else(|error| Outcome::Failed(fault_of(error)));
    if let Some(cursor) = continuation.cursor {
        let mut owed = cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !owed.stopped {
            owed.stopped = true;
            if let Some(terminal) = owed.terminal.take() {
                let _ = terminal.send(result);
            }
            owed.wake.notify_one();
        }
    }
    if let Some(reply) = reply {
        let _ = reply.send(outcome);
    }
}
