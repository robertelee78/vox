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

enum PrepareFailure {
    Fault(Fault),
    Refreshing(Error),
}

impl From<Fault> for PrepareFailure {
    fn from(fault: Fault) -> Self {
        Self::Fault(fault)
    }
}

struct Owed {
    rooms: VecDeque<Digest32>,
    room: Option<Digest32>,
    targets: VecDeque<Digest32>,
    trusted: Arc<BTreeSet<Digest32>>,
    asked_for: Option<Digest32>,
    lifetime: Option<Arc<Lifetime>>,
    guard: Option<computer::ComputerPolicyGuard>,
    terminal: Option<oneshot::Sender<crate::error::Result<()>>>,
    stopped: bool,
    wake: Arc<tokio::sync::Notify>,
}

/// Passes a person waits for (`vox trust add`) whose room was held by its own save when they
/// reached it, by room. A save admits no other in its room until it ends, so each is taken up
/// again when that save ends ([`Node::resume_parked_consents`]), not refused.
#[derive(Default)]
pub(super) struct ParkedConsents(std::collections::BTreeMap<Digest32, Vec<Cursor>>);

/// `VOX_TEST_HOLD_REGRANT_FILE=<path>` (proofs only): while the file names a member, no consent
/// is issued to it, online or through the log, so two of this node's rotations can happen with
/// no re-grant between them; `<path>.engaged` is written each time one is held.
#[cfg(feature = "test-knobs")]
fn regrant_held(target: &Digest32) -> bool {
    let Some(path) = std::env::var_os("VOX_TEST_HOLD_REGRANT_FILE")
        .filter(|path| !path.is_empty())
        .map(std::path::PathBuf::from)
    else {
        return false;
    };
    let held = std::fs::read_to_string(&path)
        .ok()
        .as_deref()
        .map(str::trim)
        == Some(crate::node::link::b32_encode(target).as_str());
    if held {
        let _ = std::fs::write(path.with_extension("engaged"), b"held consent");
    }
    held
}

#[cfg(not(feature = "test-knobs"))]
const fn regrant_held(_target: &Digest32) -> bool {
    false
}

pub(super) struct Offline {
    attempt: u64,
    source_room: Digest32,
    asked: bool,
}

enum Route {
    Online { conn: Arc<VoxConnection> },
    Offline(Offline),
}

enum Stage {
    Vacant,
    Outbound(outbound::Stage),
    Rekeys(Box<rekeys::Target>),
    SelectionGovernance,
    RekeyGovernance {
        rekey_after: Option<Digest32>,
        history_after: Option<Digest32>,
    },
    LogRekeyGovernance(Offline),
    Hold(Route),
    Online {
        queue: mpsc::OwnedPermit<PairwiseJob>,
        job: PairwiseJob,
    },
    Offline {
        route: Offline,
        posted_as: Digest32,
    },
    Packages {
        route: Offline,
        keys: VecDeque<Skdm>,
        posted_as: Digest32,
    },
    Delivered(Offline),
    Acknowledged,
}

pub(super) struct Continuation {
    instance: SharedChannel,
    attachment: u64,
    lifetime: Option<Arc<Lifetime>>,
    target: Digest32,
    asked: bool,
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
        node.trust.is_trusted(&self.target) && node.trust_decision(&self.target) == self.decision
    }
    fn rekey_authorized(&self, node: &Node, lifetime: &Lifetime) -> crate::error::Result<()> {
        let guard = self.cursor.as_ref().and_then(|cursor| {
            cursor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .guard
                .clone()
        });
        if let Some(guard) = guard {
            guard.active(node.computer.as_ref())
        } else if lifetime.authority.current() {
            Ok(())
        } else {
            Err(Error::ComputerPolicySuperseded)
        }
    }
}

impl Node {
    /// `target` answered a direct delivery of `generation`, selected under debt `revision`, as
    /// taken: save that exactly that generation left its set.
    pub(super) async fn begin_owned_pairwise_receipt(
        &mut self,
        room: Digest32,
        target: Digest32,
        generation: u64,
        removal_generation: u64,
        revision: u64,
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
            decision: self.trust_decision(&target),
            plan: None,
            cursor: None,
            prekey: None,
            stage: Stage::Acknowledged,
        };
        self.begin_pending_maintenance(
            room,
            Work::Consent(consent_save::Work::Delivered {
                target,
                generation,
                revision,
                removal_generation: Some(removal_generation),
            }),
            maintenance_save::Continuation::Consent(continuation),
            None,
        )
        .await;
    }

    pub(super) async fn deliver_owed_consents(&mut self, asked_for: Option<Digest32>) {
        self.begin_owned_consent_pass(asked_for, None, None, None)
            .await;
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
                    Ok(owed) => owed.contains(&owner.peer) && !regrant_held(&owner.peer),
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
        self.begin_owned_consent_pass(asked_for, Some(lifetime), Some(reply), None)
            .await;
    }

    pub(super) async fn begin_owned_consent_pass(
        &mut self,
        asked_for: Option<Digest32>,
        lifetime: Option<Arc<Lifetime>>,
        terminal: Option<oneshot::Sender<crate::error::Result<()>>>,
        guard: Option<computer::ComputerPolicyGuard>,
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
            guard,
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
                    Err(PrepareFailure::Refreshing(error))
                        if ChannelState::governance_refreshing(&error) =>
                    {
                        self.refresh_consent_selection(room, target, asked, cursor)
                            .await;
                        return;
                    }
                    Err(PrepareFailure::Refreshing(error)) => {
                        self.finish_owned_consent_cursor(&cursor, Err(error));
                        return;
                    }
                    Err(PrepareFailure::Fault(Fault::RoomChangePending)) => {
                        self.refresh_consent_selection(room, target, asked, cursor)
                            .await;
                        return;
                    }
                    Err(PrepareFailure::Fault(fault)) => {
                        let managed = cursor
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .terminal
                            .is_some();
                        if managed && matches!(fault, Fault::ComputerPolicy | Fault::NotTrusted) {
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
            owed.targets = targets
                .into_iter()
                .filter(|target| !regrant_held(target))
                .collect();
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

    /// Take up the passes parked on `room` once its own save has ended (see
    /// `refresh_consent_selection`): each selects its target again. One that finds the room
    /// held again, by a save this one started or another, parks again for that save's end.
    pub(super) async fn resume_parked_consents(&mut self, room: Digest32) {
        if self.pending_posts.contains_key(&room) {
            return;
        }
        let Some(parked) = self.parked_consents.0.remove(&room) else {
            return;
        };
        for cursor in parked {
            self.advance_owned_owed_consents(cursor).await;
        }
    }

    /// The node is locking: a parked pass ends as one under way does, with the lock.
    pub(super) fn retire_parked_consents(&mut self) {
        for cursor in std::mem::take(&mut self.parked_consents.0)
            .into_values()
            .flatten()
        {
            self.finish_owned_consent_cursor(&cursor, Err(Error::AtRestLocked));
        }
    }

    async fn refresh_consent_selection(
        &mut self,
        room: Digest32,
        target: Digest32,
        asked: bool,
        cursor: Cursor,
    ) {
        // **A room held by its own save is waited for, not refused** (the rule joins use): the
        // selection below is a save of that room, which is refused at once while another holds
        // it, and a person's `vox trust add` was then told its change "made no change" although
        // the trust was saved. A pass a person waits for keeps its place, `target` first, until
        // the room's save ends; a background pass is retried by the redelivery as before.
        if self.pending_posts.contains_key(&room) {
            let mut owed = cursor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if owed.terminal.is_some() && !owed.stopped {
                owed.room = Some(room);
                owed.targets.push_front(target);
                drop(owed);
                self.parked_consents.0.entry(room).or_default().push(cursor);
                return;
            }
        }
        let Some(instance) = self.channels.get(&room).cloned() else {
            self.finish_owned_consent_cursor(&cursor, Err(Error::Profile("consent room changed")));
            return;
        };
        let lifetime = cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .lifetime
            .as_ref()
            .map(Arc::clone);
        self.governance_work.wake_room(room);
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime,
            target,
            asked,
            decision: self.trust_decision(&target),
            plan: None,
            cursor: Some(cursor),
            prekey: None,
            stage: Stage::SelectionGovernance,
        };
        self.begin_pending_maintenance(
            room,
            Work::Projection(crate::node::channel::session_projection::ProjectionWork::Governance),
            maintenance_save::Continuation::Consent(continuation),
            None,
        )
        .await;
    }

    async fn prepare_owned_online_consent(
        &mut self,
        room: Digest32,
        target: Digest32,
        asked: bool,
        lifetime: Option<Arc<Lifetime>>,
        cursor: Cursor,
    ) -> std::result::Result<bool, PrepareFailure> {
        if regrant_held(&target) {
            return Err(Fault::Unreachable.into());
        }
        if !self.trust.is_trusted(&target) {
            return Err(Fault::NotTrusted.into());
        }
        if lifetime.is_none() && !self.computer_authority_current() {
            return Err(Fault::ComputerPolicy.into());
        }
        if self.pending_posts.contains_key(&room) {
            self.redeliver_now = true;
            return Err(Fault::RoomChangePending.into());
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
                return Err(Fault::NotAdmitted.into());
            }
            if !channel.is_settled() {
                return Err(Fault::RoomNotSynced.into());
            }
            if channel.own_history_behind() {
                return Err(Fault::OwnHistoryBehind.into());
            }
            channel
                .require_governance_ready(profile.store(), self.now_ms())
                .map_err(PrepareFailure::Refreshing)?;
            if channel
                .is_member_removed(profile.store(), &target)
                .map_err(|error| fault_of(&error))?
            {
                return Err(Fault::NotAdmitted.into());
            }
        }
        // A member that came back takes room keys only by return-bound log package (R4): its
        // consent goes the offline way, never on a connection.
        let returned = instance.lock().await.key_returned(&target);
        if returned {
            self.begin_owned_offline_consent(room, target, 0, room, asked)
                .await;
            return Err(Fault::Unreachable.into());
        }
        // A connection without a version-3 exchange for the room carries no key (R10): the
        // consent stays owed, as for a member out of reach.
        let conn = self
            .reach_member(&room, target, asked)
            .await
            .filter(|conn| self.key_connection(&room, conn).is_some())
            .ok_or(Fault::Unreachable)?;
        // The frame selects and reserves its bundle once. A probe here would reset the
        // signed-prekey grace before that selection and make it wait again.
        let decision = self.trust_decision(&target);
        let (skdm, plan, hold) = {
            let channel = instance.lock().await;
            self.prepare_owned_consent_key(&channel, target, decision)?
        };
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime,
            target,
            asked,
            decision,
            plan,
            cursor: Some(cursor),
            prekey: None,
            stage: Stage::Hold(Route::Online { conn }),
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
                .map_err(PrepareFailure::from)
        }
    }

    /// Pure committed reads/signing only. The fallback pending-key write is a native Hold stage.
    fn prepare_owned_consent_key(
        &self,
        channel: &ChannelState,
        target: Digest32,
        decision: Option<crate::node::consent_order::Stamp>,
    ) -> std::result::Result<(Skdm, Option<ReleasePlan>, bool), Fault> {
        let profile = self.profile.as_ref().ok_or(Fault::UnknownChannel)?;
        channel
            .require_trust_withdrawn(
                profile.store(),
                profile.signer().map_err(|error| fault_of(&error))?,
            )
            .map_err(|error| fault_of(&error))?;
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
        if channel
            .is_member_removed(profile.store(), &target)
            .map_err(|error| fault_of(&error))?
        {
            return Err(Fault::NotAdmitted);
        }
        if channel
            .room_removal_rotation_needed(profile.store())
            .map_err(|error| fault_of(&error))?
        {
            // As the consent preparation refuses this state (`governance::REFRESHING`): the
            // room is skipped and its key stays owed for redelivery. Not `RoomChangePending`,
            // whose selection refresh would retake the room before its rotation can be saved.
            return Err(Fault::GovernanceRefreshing);
        }
        if channel.key_departed(&target) {
            return Err(Fault::NotAdmitted);
        }
        // A consent delivers from the entitlement already held (R5): a returned or readmitted
        // member's floor is its rotation's fresh chain, and re-issued consent keeps its floor.
        // A key at the current position is never evidence that earlier iterations went.
        if let Some((generation, iteration)) = channel.entitled_from(&target) {
            let live = channel.sender_generation();
            let key = if generation == live {
                channel.release_generation(profile, &target, generation, iteration)
            } else if generation < live {
                // The live generation at its origin; the consent save owes the older ones from
                // the merged floor.
                channel.rekey_skdm(profile, &target)
            } else {
                Err(Error::MalformedAtRest(
                    "entitlement past the live generation",
                ))
            };
            return key
                .map(|key| (key, None, true))
                .map_err(|error| fault_of(&error));
        }
        // A creator readmission or a return is a new forward boundary regardless of an old
        // pending SKDM or trust mark.
        let once_removed = !channel
            .validated_member_removals(profile.store(), &target, self.now_ms())
            .map_err(|error| fault_of(&error))?
            .is_empty();
        if once_removed || channel.key_returned(&target) {
            return channel
                .skdm_for_consent(profile, &target)
                .map(|key| (key, None, true))
                .map_err(|error| fault_of(&error));
        }
        let selected = (|| -> crate::error::Result<_> {
            let plan = channel.history_plan(profile.store(), &target, decision)?;
            if let Some(&(generation, iteration)) = plan.as_ref().and_then(|plan| plan.last()) {
                return Ok((
                    channel.release_generation(profile, &target, generation, iteration)?,
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
                None => channel.skdm_for_consent(profile, &target)?,
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
        let decision = self.trust_decision(&peer);
        let selected = {
            let channel = instance.lock().await;
            self.prepare_owned_consent_key(&channel, peer, decision)
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
        if let Stage::Acknowledged = &continuation.stage {
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
            Stage::Offline { route, .. }
            | Stage::Hold(Route::Offline(route))
            | Stage::LogRekeyGovernance(route) => Some(route),
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
            Stage::Offline { route, .. }
            | Stage::Hold(Route::Offline(route))
            | Stage::LogRekeyGovernance(route) => Some(route),
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
            || (!matches!(&continuation.stage, Stage::Acknowledged) && !continuation.trusted(self))
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
        if matches!(
            &continuation.stage,
            Stage::RekeyGovernance { .. } | Stage::LogRekeyGovernance(_)
        ) {
            self.finish_rekey_governance(room, saved, lifetime, continuation, reply)
                .await;
            return;
        }
        if matches!(&continuation.stage, Stage::SelectionGovernance) {
            match saved {
                Saved::Projection(
                    crate::node::channel::session_projection::ProjectionProgress::Governance(
                        progress,
                    ),
                ) if progress.ready => {
                    if let Some(cursor) = continuation.cursor {
                        {
                            let mut owed = cursor
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            owed.room = Some(room);
                            owed.targets.push_front(continuation.target);
                        }
                        self.advance_owned_owed_consents(cursor).await;
                    }
                }
                Saved::Projection(
                    crate::node::channel::session_projection::ProjectionProgress::Governance(
                        progress,
                    ),
                ) if progress.pending => {
                    self.begin_pending_maintenance(
                        room,
                        Work::Projection(
                            crate::node::channel::session_projection::ProjectionWork::Governance,
                        ),
                        maintenance_save::Continuation::Consent(continuation),
                        reply,
                    )
                    .await;
                }
                _ => {
                    self.fail_owned_consent(
                        room,
                        Error::Profile("consent governance projection stopped before readiness"),
                        continuation,
                        reply,
                    )
                    .await;
                }
            }
            return;
        }
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
            self.finish_owned_consent_outbound(room, saved, continuation, reply)
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
        if matches!(&continuation.stage, Stage::Online { .. }) {
            let checked = continuation
                .instance
                .lock()
                .await
                .require_trust_withdrawn(&lifetime.store, lifetime.signer.as_ref());
            if let Err(error) = checked {
                self.fail_owned_consent(room, error, continuation, reply)
                    .await;
                return;
            }
        }
        let stage = std::mem::replace(&mut continuation.stage, Stage::Vacant);
        match (stage, saved) {
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
                self.advance_owned_log_keys(room, next, keys).await;
            }
            (Stage::Acknowledged, Saved::Consent(consent_save::Effect::Delivered)) => {
                self.settle_owned_key_receipt(room, &continuation).await;
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
        let mut continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime,
            target: peer,
            asked: route.asked,
            decision: self.trust_decision(&peer),
            plan: None,
            cursor: None,
            prekey: None,
            stage: Stage::Delivered(route),
        };
        // **The log route settles nothing** (V210-45): a package only makes each owed key
        // available to a member that is not reachable now. Every generation in its set stays
        // there until its own authenticated answer to a direct delivery, the next time it is
        // reachable.
        let selected = {
            let channel = continuation.instance.lock().await;
            self.profile
                .as_ref()
                .ok_or(Error::AtRestLocked)
                .and_then(
                    |profile| match channel.owed_keys_for(profile.store(), &peer)? {
                        Some(generations) => channel.owed_skdms(profile, &peer, &generations),
                        None => Ok(Vec::new()),
                    },
                )
        };
        let keys: VecDeque<_> = match selected {
            Ok(keys) => keys.into(),
            Err(error) if ChannelState::governance_refreshing(&error) => {
                // The grant saved the debt before invalidating its fold. Keep this exact
                // offline delivery until that fold can select the owed keys.
                let Stage::Delivered(route) = continuation.stage else {
                    return;
                };
                continuation.stage = Stage::LogRekeyGovernance(route);
                self.begin_pending_maintenance(
                    room,
                    Work::Projection(
                        crate::node::channel::session_projection::ProjectionWork::Governance,
                    ),
                    maintenance_save::Continuation::Consent(continuation),
                    None,
                )
                .await;
                return;
            }
            Err(error) => {
                self.fail_owned_consent(room, error, continuation, None)
                    .await;
                return;
            }
        };
        if keys.is_empty() {
            return;
        }
        self.key_delivery_settling.insert((room, peer));
        self.advance_owned_log_keys(room, continuation, keys).await;
    }

    /// Post each owed key as a package, once since this node unlocked: a fresh bundle is no
    /// reason to post it again (the author cannot tell a member that opened it from one that
    /// could not). Once none is left, the route is over; the debt is unchanged.
    async fn advance_owned_log_keys(
        &mut self,
        room: Digest32,
        mut continuation: Continuation,
        mut keys: VecDeque<Skdm>,
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
            // Posted once, durably (the mark in the member's ledger row survives a restart).
            let marked = {
                let channel = continuation.instance.lock().await;
                self.profile.as_ref().is_some_and(|profile| {
                    channel.package_posted(
                        profile.store(),
                        &continuation.target,
                        key.body.chain_id,
                        &posted_as.2,
                    )
                })
            };
            if marked || self.packages_posted.contains(&posted_as) {
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
                generation: key.body.chain_id,
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
        self.settle_owned_log_route(room, &continuation).await;
    }

    /// The log route to `continuation.target` is over, every key it owes posted to its bundle:
    /// no delivery to it is in flight any more unless a direct key is, whatever its durable debt
    /// still owes.
    async fn settle_owned_log_route(&mut self, room: Digest32, continuation: &Continuation) {
        #[cfg(feature = "test-knobs")]
        if let Some(profile) = self.profile.as_ref() {
            let owed = continuation
                .instance
                .lock()
                .await
                .owed_keys_for(profile.store(), &continuation.target);
            if let Ok(Some(owed)) = owed {
                eprintln!(
                    "test-knobs: every key owed to {} is in the log of room {}: generations {owed:?}",
                    crate::node::link::b32_encode(&continuation.target),
                    crate::node::network::short_id(room)
                );
            }
        }
        let pair = (room, continuation.target);
        if !self.keys_in_flight.contains_key(&pair) && !self.history_in_flight.contains_key(&pair) {
            self.key_delivery_settling.remove(&pair);
        }
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
    let final_delivery = matches!(&continuation.stage, Stage::Acknowledged)
        && matches!(&result, Ok(Saved::Consent(consent_save::Effect::Delivered)));
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
