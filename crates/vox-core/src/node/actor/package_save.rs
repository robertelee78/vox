//! Actual key-package work and pairwise answers share the original native-save owner.
use super::*;
use crate::node::channel::pending_package as native;
use crate::node::store::Store;
use maintenance_save::{Lifetime, Saved as CommonSaved, Work as CommonWork};
pub(super) use native::{Attempt, Saved, Work};

type Reply = Option<oneshot::Sender<Outcome>>;

pub(super) struct Prepared {
    pending: native::Prepared,
    now: crate::time::Ms,
}
pub(super) struct Completed(native::Completed);

impl Work {
    pub(super) fn prepare(
        self,
        channel: &mut ChannelState,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
    ) -> crate::error::Result<Option<Prepared>> {
        channel
            .prepare_pending_package(store, owner, self)
            .map(|pending| Some(Prepared { pending, now }))
    }
}
impl Prepared {
    pub(super) fn run(
        self,
        store: &Store,
        signer: &dyn crate::identity::composite::RootSigner,
    ) -> Completed {
        Completed(self.pending.run(store, signer, self.now))
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
    pub(super) fn finish(
        self,
        channel: &mut ChannelState,
        store: &Store,
    ) -> crate::error::Result<Saved> {
        channel.finish_pending_package(store, self.0)
    }
    pub(super) fn into_result(self) -> crate::error::Result<Saved> {
        self.0.into_result()
    }
}

#[derive(Clone, Copy)]
enum Stage {
    Select,
    Open,
    Install,
    Backfill,
    Replay,
    Acknowledge,
    Respond,
    Unseal,
    HelloInitiate,
    HelloForget,
    HelloRefuse,
    Reoffer,
    Reset,
}

struct Inbound {
    peer: Digest32,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    _conn: Arc<VoxConnection>,
    _recovery_credit: Option<OwnedSemaphorePermit>,
    _donor_admission: Option<PairwiseAdmission>,
    delivery: Option<Digest32>,
    opening: Option<Opening>,
    trusted: BTreeSet<Digest32>,
    lifetime: Option<Arc<Lifetime>>,
}
enum Opening {
    Delivery {
        sealed: Vec<u8>,
    },
    Hello {
        hash: Digest32,
        replaces: bool,
        second: Option<crate::node::pairwise_stream::PairwiseFrame>,
        serial: Option<u64>,
    },
    RenewHello {
        hash: Digest32,
        initial: Vec<u8>,
        second: Option<crate::node::pairwise_stream::PairwiseFrame>,
    },
    Existing {
        serial: Option<u64>,
        session: native::SessionSlot,
        key: bool,
    },
}
enum After {
    Logged,
    Preparation(Box<preparation_save::Continuation>),
    Inbound(Box<Inbound>),
    Reoffer {
        target: Digest32,
        remaining: Redelivery,
    },
    Probe(Digest32),
    Rejoin(Digest32),
    AdoptJoin {
        peer: Digest32,
        session: Box<crate::pairwise::session::Session>,
        mine: bool,
        basis: Option<u64>,
        next: JoinNext,
    },
}

enum JoinNext {
    Metadata(metadata_save::JoinAdoption),
    Answered,
}
struct AnsweredJoin {
    room: Digest32,
    peer: Digest32,
    instance: SharedChannel,
}

pub(super) struct AdoptionWait {
    room: Digest32,
    peer: Digest32,
    session: Box<crate::pairwise::session::Session>,
    instance: SharedChannel,
    attachment: u64,
    lifetime: Arc<Lifetime>,
}

struct ReofferTarget {
    room: Digest32,
    target: Digest32,
    instance: SharedChannel,
}
pub(super) struct Redelivery {
    attachment: u64,
    lifetime: Arc<Lifetime>,
    targets: VecDeque<ReofferTarget>,
    answered: Option<AnsweredJoin>,
}

pub(super) struct Continuation {
    instance: SharedChannel,
    attachment: u64,
    lifetime: Option<Arc<Lifetime>>,
    after: After,
    stage: Stage,
    attempt: Option<Attempt>,
}
impl Continuation {
    pub(super) fn preparation(next: preparation_save::Continuation) -> Self {
        Self {
            instance: Arc::clone(next.instance()),
            attachment: next.attachment,
            lifetime: next.lifetime(),
            after: After::Preparation(Box::new(next)),
            stage: Stage::Install,
            attempt: None,
        }
    }
    pub(super) fn instance(&self) -> &SharedChannel {
        &self.instance
    }
    pub(super) fn lifetime(&self) -> Option<Arc<Lifetime>> {
        self.lifetime.as_ref().map(Arc::clone)
    }
    pub(super) fn is_preparation(&self) -> bool {
        matches!(&self.after, After::Preparation(_))
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
    pub(super) async fn install_key_packages(&mut self, channel_id: &Digest32) -> bool {
        self.begin_owned_package_turn(*channel_id, None, None).await
    }

    pub(super) async fn begin_owned_package_turn(
        &mut self,
        room: Digest32,
        lifetime: Option<Arc<Lifetime>>,
        reply: Reply,
    ) -> bool {
        #[cfg(feature = "test-knobs")]
        if let Some(path) = held_packages_path() {
            note_package_hold_engaged(&path);
            self.key_package_rooms.entry(room).or_insert(false);
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(Fault::RoomChangePending));
            }
            self.post_save_wake.notify_one();
            return false;
        }
        let Some(instance) = self.channels.get(&room).cloned() else {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
            }
            self.post_save_wake.notify_one();
            return false;
        };
        if self.pending_posts.contains_key(&room) {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(Fault::RoomChangePending));
            }
            self.post_save_wake.notify_one();
            return false;
        }
        let replay = self.key_package_rooms.remove(&room).unwrap_or(false);
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime,
            after: After::Logged,
            stage: Stage::Select,
            attempt: None,
        };
        self.begin_pending_maintenance(
            room,
            CommonWork::Packages(Work::Select {
                trust_digest: crate::hash::sha256(&self.trust.to_bytes()),
                replay,
            }),
            maintenance_save::Continuation::Packages(continuation),
            reply,
        )
        .await
    }

    pub(super) fn reject_owned_packages(
        &mut self,
        room: Digest32,
        error: Error,
        continuation: Continuation,
        reply: Reply,
    ) {
        let attached = continuation.attached(self, &room);
        let lifetime = continuation.lifetime();
        match continuation.after {
            After::Preparation(next) => self.reject_owned_preparation(room, error, *next, reply),
            After::Inbound(inbound) => {
                let mut inbound = *inbound;
                if inbound.lifetime.is_none() {
                    inbound.lifetime = lifetime;
                }
                let key = !matches!(&inbound.opening, Some(Opening::Existing { key: false, .. }));
                if let Some(Opening::Existing {
                    serial, session, ..
                }) = inbound.opening.take()
                {
                    let pair = (room, inbound.peer);
                    if attached
                        && self.session_serial.get(&pair).copied() == serial
                        && !self.sessions.contains_key(&pair)
                    {
                        if let Some(session) = session
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                        {
                            self.sessions.insert(pair, session);
                        }
                    }
                }
                answer_inbound(
                    inbound,
                    key.then_some(Err(crate::node::pairwise_stream::KeyRefusal::NotAccepted)),
                );
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(fault_of(&error)));
                }
            }
            After::Logged => {
                if attached {
                    let _ = self.event_tx.send(NodeEvent::NodeNote {
                        note: format!(
                            "room {} could not read its saved key deliveries: {error}",
                            crate::node::link::b32_encode(&room)
                        ),
                    });
                }
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(fault_of(&error)));
                }
            }
            After::Reoffer { target, remaining } => {
                if attached {
                    self.reoffer.insert((room, target));
                    self.reject_package_redelivery(remaining);
                }
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(fault_of(&error)));
                }
            }
            After::Probe(_) | After::Rejoin(_) => {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(fault_of(&error)));
                }
            }
            After::AdoptJoin { peer, next, .. } => {
                let fault = fault_of(&error);
                self.reject_package_join_adoption(room, peer, error, next, lifetime);
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(fault));
                }
            }
        }
        self.post_save_wake.notify_one();
    }

    pub(super) async fn finish_owned_packages(
        &mut self,
        room: Digest32,
        result: crate::error::Result<CommonSaved>,
        lifetime: Arc<Lifetime>,
        mut continuation: Continuation,
        reply: Reply,
    ) {
        if !continuation.attached(self, &room) {
            if let After::Inbound(inbound) = continuation.after {
                answer_inbound(
                    *inbound,
                    Some(Err(crate::node::pairwise_stream::KeyRefusal::NotAccepted)),
                );
            }
            if let Some(reply) = reply {
                let _ = reply.send(
                    result
                        .map(|_| Outcome::Done)
                        .unwrap_or_else(|error| Outcome::Failed(fault_of(&error))),
                );
            }
            self.post_save_wake.notify_one();
            return;
        }
        let saved = match result {
            Ok(saved) => saved,
            Err(error) => {
                self.reject_owned_packages(room, error, continuation, reply);
                return;
            }
        };
        continuation.lifetime = Some(Arc::clone(&lifetime));
        if let After::Inbound(inbound) = &mut continuation.after {
            inbound.lifetime = Some(Arc::clone(&lifetime));
        }
        let work = match (continuation.stage, saved) {
            (Stage::Select, CommonSaved::Packages(Saved::Selected { progress, context })) => {
                let Some(pending) = progress.package else {
                    if progress.pending {
                        self.key_package_rooms.entry(room).or_insert(false);
                    }
                    if let Some(reply) = reply {
                        let _ = reply.send(Outcome::Done);
                    }
                    drop(continuation);
                    self.post_save_wake.notify_one();
                    self.publish().await;
                    return;
                };
                match self.prekeys.as_ref().map(Arc::clone) {
                    Some(ring) => {
                        continuation.stage = Stage::Open;
                        CommonWork::Packages(Work::Open {
                            pending,
                            context,
                            ring,
                            trusted: self.trust.trusted(),
                        })
                    }
                    None => {
                        continuation.stage = Stage::Install;
                        CommonWork::Packages(Work::Attempt {
                            locator: (pending.author, pending.log_id),
                            skdm: None,
                        })
                    }
                }
            }
            (Stage::Open, CommonSaved::Packages(Saved::Opened { locator, skdm })) => {
                continuation.stage = Stage::Install;
                CommonWork::Packages(Work::Attempt { locator, skdm })
            }
            (Stage::Install, CommonSaved::Packages(Saved::Installed(attempt))) => {
                if attempt
                    .refusal
                    .as_ref()
                    .is_some_and(ChannelState::receiver_release_cleanup_waiting)
                {
                    self.governance_work.wake_room(room);
                }
                let backfill = attempt.accepted.is_some_and(|accepted| accepted.changed);
                if backfill {
                    continuation.attempt = Some(attempt);
                    self.governance_work.pending = true;
                    continuation.stage = Stage::Backfill;
                    CommonWork::Governance(governance_save::Work::Backfill)
                } else {
                    continuation.stage = Stage::Acknowledge;
                    CommonWork::Packages(Work::Acknowledge(attempt))
                }
            }
            (
                Stage::Backfill,
                CommonSaved::Governance(governance_save::Saved::Backfill {
                    rendered,
                    session_rendered,
                    pending,
                    ..
                }),
            ) => {
                self.governance_work.again |= pending;
                let Some(mut attempt) = continuation.attempt.take() else {
                    self.reject_owned_packages(
                        room,
                        Error::Profile("backfill package receipt missing"),
                        continuation,
                        reply,
                    );
                    return;
                };
                if let Some(accepted) = attempt.accepted.as_mut() {
                    accepted.rendered = if attempt.drive {
                        session_rendered
                    } else {
                        rendered
                    };
                }
                if attempt.drive {
                    continuation.attempt = Some(attempt);
                    continuation.stage = Stage::Replay;
                    CommonWork::Private(private_save::Work::ScheduleReplay)
                } else {
                    continuation.stage = Stage::Acknowledge;
                    CommonWork::Packages(Work::Acknowledge(attempt))
                }
            }
            (Stage::Replay, CommonSaved::Private(private_save::Saved::Upgrade(saved))) => {
                let Some(mut attempt) = continuation.attempt.take() else {
                    self.reject_owned_packages(
                        room,
                        Error::Profile("private package receipt missing"),
                        continuation,
                        reply,
                    );
                    return;
                };
                if let Some(accepted) = attempt.accepted.as_mut() {
                    accepted.rendered += saved.session_rendered;
                }
                continuation.stage = Stage::Acknowledge;
                CommonWork::Packages(Work::Acknowledge(attempt))
            }
            (Stage::Acknowledge, CommonSaved::Packages(Saved::Attempted(attempt))) => {
                let peer = match &continuation.after {
                    After::Inbound(inbound) => Some(inbound.peer),
                    _ => None,
                };
                self.apply_attempt_effect(room, &attempt, peer);
                match continuation.after {
                    After::Preparation(next) => {
                        Box::pin(self.finish_owned_preparation(
                            room,
                            Ok(CommonSaved::Packages(Saved::Attempted(attempt))),
                            lifetime,
                            *next,
                            reply,
                        ))
                        .await;
                    }
                    After::Logged => {
                        if attempt.package_pending {
                            self.key_package_rooms.entry(room).or_insert(false);
                        }
                        if let Some(reply) = reply {
                            let _ = reply.send(Outcome::Done);
                        }
                        self.post_save_wake.notify_one();
                        self.publish().await;
                        self.schedule().await;
                    }
                    After::Inbound(inbound) => {
                        let inbound = *inbound;
                        let accepted = attempt.accepted.is_some();
                        if accepted {
                            if let Some(delivery) = inbound.delivery {
                                let taken = self
                                    .taken_deliveries
                                    .entry((room, inbound.peer))
                                    .or_default();
                                if taken.len() >= TAKEN_DELIVERIES_KEPT {
                                    taken.pop_front();
                                }
                                taken.push_back(delivery);
                            }
                            if attempt.fresh {
                                self.reoffer
                                    .insert((room, attempt.author.unwrap_or(inbound.peer)));
                            }
                        }
                        answer_inbound(
                            inbound,
                            Some(if accepted {
                                Ok(())
                            } else {
                                Err(crate::node::pairwise_stream::KeyRefusal::NotAccepted)
                            }),
                        );
                        if let Some(reply) = reply {
                            let _ = reply.send(Outcome::Done);
                        }
                        self.finish_pairwise_package_effects(lifetime).await;
                    }
                    After::Reoffer { .. }
                    | After::Probe(_)
                    | After::Rejoin(_)
                    | After::AdoptJoin { .. } => {
                        unreachable!("non-package continuation has no key attempt")
                    }
                }
                return;
            }
            (Stage::Unseal, CommonSaved::Packages(Saved::Unsealed { session, result })) => {
                let After::Inbound(inbound) = continuation.after else {
                    unreachable!("retained pairwise session owner")
                };
                let mut inbound = *inbound;
                let Some(Opening::Existing { serial, key, .. }) = inbound.opening.take() else {
                    unreachable!("retained pairwise session selection")
                };
                let pair = (room, inbound.peer);
                if self.session_serial.get(&pair).copied() != serial
                    || self.sessions.contains_key(&pair)
                {
                    answer_inbound(
                        inbound,
                        key.then_some(Err(crate::node::pairwise_stream::KeyRefusal::NoSession)),
                    );
                    return;
                }
                self.sessions.insert(pair, *session);
                match result {
                    Ok(Some(skdm)) => {
                        self.continue_inbound_key(room, inbound, skdm, Some(lifetime))
                            .await
                    }
                    Ok(None) => {
                        answer_inbound(inbound, None);
                        self.finish_pairwise_package_effects(lifetime).await;
                    }
                    Err(why) => {
                        answer_inbound(inbound, Some(Err(why)));
                        self.finish_pairwise_package_effects(lifetime).await;
                    }
                }
                return;
            }
            (
                Stage::HelloInitiate,
                CommonSaved::Packages(Saved::Initiated {
                    initiated: opened,
                    reservation,
                }),
            ) => {
                let After::Inbound(mut inbound) = continuation.after else {
                    unreachable!("renewed hello owner")
                };
                let Some(Opening::RenewHello {
                    hash,
                    initial,
                    second,
                }) = inbound.opening.take()
                else {
                    unreachable!("renewed hello decision")
                };
                let pair = (room, inbound.peer);
                if self.sessions.contains_key(&pair) {
                    answer_inbound(
                        *inbound,
                        Some(Err(crate::node::pairwise_stream::KeyRefusal::HelloRefused)),
                    );
                    return;
                }
                if let Some((initial, session)) = opened {
                    self.sessions.insert(pair, *session);
                    self.stamp_session(pair);
                    self.accepted_hello.remove(&pair);
                    self.initiated.insert(
                        pair,
                        Initiated {
                            initial: Some(*initial),
                            hello_delivered: false,
                            reservation: reservation.map(Arc::new),
                        },
                    );
                    self.reopen.insert(pair);
                    continuation.after = After::Inbound(inbound);
                    continuation.stage = Stage::HelloRefuse;
                    Box::pin(self.begin_pending_maintenance(
                        room,
                        CommonWork::Packages(Work::ResetDelivery {
                            target: pair.1,
                            history: true,
                        }),
                        maintenance_save::Continuation::Packages(continuation),
                        reply,
                    ))
                    .await;
                } else {
                    drop(reservation);
                    let inbound = Inbound {
                        opening: Some(Opening::Hello {
                            hash,
                            replaces: true,
                            second,
                            serial: None,
                        }),
                        ..*inbound
                    };
                    Box::pin(self.begin_package_respond(
                        room,
                        continuation.instance,
                        inbound,
                        initial,
                        Some(lifetime),
                    ))
                    .await;
                }
                return;
            }
            (Stage::Respond, CommonSaved::Packages(Saved::Responded(response))) => {
                let After::Inbound(mut inbound) = continuation.after else {
                    unreachable!("session response owner")
                };
                let session = match response {
                    Ok(session) => session,
                    Err(refusal) => {
                        answer_inbound(*inbound, Some(Err(refusal)));
                        self.finish_pairwise_package_effects(lifetime).await;
                        return;
                    }
                };
                let Some(opening) = inbound.opening.take() else {
                    answer_inbound(
                        *inbound,
                        Some(Err(crate::node::pairwise_stream::KeyRefusal::NotAccepted)),
                    );
                    if let Some(reply) = reply {
                        let _ = reply.send(Outcome::Failed(Fault::Internal));
                    }
                    self.finish_pairwise_package_effects(lifetime).await;
                    return;
                };
                match opening {
                    Opening::Delivery { sealed } => {
                        let mut session = session;
                        let opened = crate::node::pairwise_stream::open_skdm(
                            &mut session,
                            &sealed,
                            self.now_ms().get(),
                        );
                        drop(session);
                        let skdm = match opened {
                            Ok(skdm) => skdm,
                            Err(_) => {
                                answer_inbound(
                                    *inbound,
                                    Some(Err(crate::node::pairwise_stream::KeyRefusal::CannotOpen)),
                                );
                                return;
                            }
                        };
                        self.continue_inbound_key(room, *inbound, Box::new(skdm), Some(lifetime))
                            .await;
                    }
                    Opening::Hello {
                        hash,
                        replaces,
                        second,
                        serial,
                    } => {
                        if self.session_serial.get(&(room, inbound.peer)).copied() != serial {
                            answer_inbound(
                                *inbound,
                                Some(Err(crate::node::pairwise_stream::KeyRefusal::HelloRefused)),
                            );
                            return;
                        }
                        let pair = (room, inbound.peer);
                        self.sessions.insert(pair, *session);
                        self.stamp_session(pair);
                        self.initiated.remove(&pair);
                        self.reopen.remove(&pair);
                        self.accepted_hello.insert(pair, hash);
                        if replaces {
                            inbound.opening = Some(Opening::Hello {
                                hash,
                                replaces: false,
                                second,
                                serial: self.session_serial.get(&pair).copied(),
                            });
                            continuation.after = After::Inbound(inbound);
                            continuation.stage = Stage::HelloForget;
                            self.key_backoff.remove(&pair);
                            self.redeliver_now = true;
                            Box::pin(self.begin_pending_maintenance(
                                room,
                                CommonWork::Packages(Work::ResetDelivery {
                                    target: pair.1,
                                    history: true,
                                }),
                                maintenance_save::Continuation::Packages(continuation),
                                reply,
                            ))
                            .await;
                        } else {
                            self.continue_inbound_second(room, *inbound, second, Some(lifetime))
                                .await;
                        }
                    }
                    Opening::RenewHello { .. } | Opening::Existing { .. } => {
                        unreachable!("respond uses an incoming opening")
                    }
                }
                return;
            }
            (Stage::HelloForget, CommonSaved::Packages(Saved::DeliveryReset { .. })) => {
                let After::Inbound(inbound) = continuation.after else {
                    unreachable!("hello forget owner")
                };
                let mut inbound = *inbound;
                let Some(Opening::Hello { second, .. }) = inbound.opening.take() else {
                    unreachable!("hello follow-up")
                };
                self.continue_inbound_second(room, inbound, second, Some(lifetime))
                    .await;
                return;
            }
            (Stage::HelloRefuse, CommonSaved::Packages(Saved::DeliveryReset { .. })) => {
                let After::Inbound(inbound) = continuation.after else {
                    unreachable!("kept hello owner")
                };
                answer_inbound(
                    *inbound,
                    Some(Err(crate::node::pairwise_stream::KeyRefusal::HelloRefused)),
                );
                self.finish_pairwise_package_effects(lifetime).await;
                return;
            }
            (Stage::Reset, CommonSaved::Packages(Saved::DeliveryReset { error })) => {
                let fault = error.as_ref().map(fault_of);
                match continuation.after {
                    After::Probe(peer) => {
                        if let Some(after) = self.older_probes.get_mut(&peer) {
                            *after = Some(room);
                        }
                        if error.is_none() {
                            Box::pin(self.begin_owned_rekeys_for(
                                room,
                                false,
                                Some(Arc::clone(&lifetime)),
                                consent_release::RekeyAfter::Automatic,
                            ))
                            .await;
                        }
                        self.drive_owned_older_probes(Some(lifetime)).await;
                    }
                    After::Rejoin(peer) => {
                        if let Some(seen) = self.departed_seen.get_mut(&room) {
                            seen.remove(&peer);
                        }
                        if self.ports.contains_key(&(room, peer)) {
                            self.drop_port(&room, &peer);
                            self.discover_rooms.insert(room);
                            self.sched_rooms.insert(room);
                        }
                        self.begin_owned_rejoin_reset(room, Some(lifetime)).await;
                    }
                    After::AdoptJoin {
                        peer,
                        session,
                        mine,
                        basis,
                        next,
                    } => {
                        if self.session_serial.get(&(room, peer)).copied() != basis {
                            Box::pin(self.continue_package_join_adoption(
                                room, peer, *session, mine, lifetime, next,
                            ))
                            .await;
                        } else {
                            self.install_package_join_session(room, peer, *session, mine);
                            self.finish_package_join_adoption(room, peer, lifetime, next)
                                .await;
                        }
                    }
                    _ => unreachable!("delivery reset continuation"),
                }
                if let Some(reply) = reply {
                    let _ = reply.send(fault.map_or(Outcome::Done, Outcome::Failed));
                }
                return;
            }
            (Stage::Reoffer, CommonSaved::Packages(Saved::Reoffered)) => {
                let After::Reoffer { target, remaining } = continuation.after else {
                    unreachable!("reoffer owner")
                };
                self.key_backoff.remove(&(room, target));
                Box::pin(self.begin_owned_rekeys_for(
                    room,
                    false,
                    Some(lifetime),
                    consent_release::RekeyAfter::Packages {
                        next: remaining,
                        reply,
                    },
                ))
                .await;
                return;
            }
            (_, CommonSaved::Unavailable) => {
                self.reject_owned_packages(
                    room,
                    Error::Profile("key delivery is waiting for its saved room"),
                    continuation,
                    reply,
                );
                return;
            }
            _ => {
                self.reject_owned_packages(
                    room,
                    Error::Profile("unexpected key delivery save completion"),
                    continuation,
                    reply,
                );
                return;
            }
        };
        Box::pin(self.begin_pending_maintenance(
            room,
            work,
            maintenance_save::Continuation::Packages(continuation),
            reply,
        ))
        .await;
    }

    fn apply_attempt_effect(&mut self, room: Digest32, attempt: &Attempt, peer: Option<Digest32>) {
        if let Some(accepted) = attempt.accepted.filter(|accepted| accepted.changed) {
            let _ = self.event_tx.send(if attempt.drive {
                NodeEvent::SessionEntry {
                    channel_id: room,
                    session_id: crate::node::drive::KEY_CHANGED.to_owned(),
                }
            } else {
                NodeEvent::SenderKeyReceived {
                    channel_id: room,
                    peer: peer.or(attempt.author).unwrap_or_default(),
                    backfilled: accepted.rendered as u64,
                }
            });
        }
    }

    async fn continue_inbound_key(
        &mut self,
        room: Digest32,
        inbound: Inbound,
        skdm: Box<crate::group::skdm::Skdm>,
        lifetime: Option<Arc<Lifetime>>,
    ) {
        use crate::node::pairwise_stream::KeyRefusal;
        if !self.profile.as_ref().is_some_and(Profile::is_unlocked) {
            answer_inbound(inbound, Some(Err(KeyRefusal::NotAccepted)));
            return;
        }
        if !inbound.trusted.contains(&skdm.body.author_id) {
            answer_inbound(inbound, Some(Err(KeyRefusal::NotTrusted)));
            return;
        }
        #[cfg(feature = "test-knobs")]
        if let Some(path) = held_packages_path() {
            note_package_hold_engaged(&path);
            answer_inbound(inbound, Some(Err(KeyRefusal::NotAccepted)));
            return;
        }
        let Some(instance) = self.channels.get(&room).cloned() else {
            answer_inbound(inbound, Some(Err(KeyRefusal::NotAccepted)));
            return;
        };
        let next = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime,
            after: After::Inbound(Box::new(inbound)),
            stage: Stage::Install,
            attempt: None,
        };
        Box::pin(self.begin_pending_maintenance(
            room,
            CommonWork::Packages(Work::Accept { skdm }),
            maintenance_save::Continuation::Packages(next),
            None,
        ))
        .await;
    }

    async fn continue_inbound_second(
        &mut self,
        _room: Digest32,
        inbound: Inbound,
        second: Option<crate::node::pairwise_stream::PairwiseFrame>,
        lifetime: Option<Arc<Lifetime>>,
    ) {
        use crate::node::pairwise_stream::PairwiseFrame;
        match second {
            Some(PairwiseFrame::Skdm { channel_id, sealed }) => {
                self.begin_existing_package(channel_id, inbound, sealed, true, lifetime)
                    .await
            }
            Some(PairwiseFrame::Open { channel_id, sealed }) => {
                self.begin_existing_package(channel_id, inbound, sealed, false, lifetime)
                    .await
            }
            _ => {
                answer_inbound(inbound, None);
                if let Some(lifetime) = lifetime {
                    self.finish_pairwise_package_effects(lifetime).await;
                }
            }
        }
    }

    async fn begin_existing_package(
        &mut self,
        room: Digest32,
        mut inbound: Inbound,
        sealed: Vec<u8>,
        key: bool,
        lifetime: Option<Arc<Lifetime>>,
    ) {
        use crate::node::pairwise_stream::KeyRefusal;
        let Some(instance) = self.channels.get(&room).cloned() else {
            answer_inbound(inbound, key.then_some(Err(KeyRefusal::NoSession)));
            return;
        };
        if self.pending_posts.contains_key(&room) {
            answer_inbound(inbound, key.then_some(Err(KeyRefusal::NotAccepted)));
            return;
        }
        let pair = (room, inbound.peer);
        let Some(session) = self.sessions.remove(&pair) else {
            answer_inbound(inbound, key.then_some(Err(KeyRefusal::NoSession)));
            return;
        };
        let session = Arc::new(std::sync::Mutex::new(Some(session)));
        inbound.opening = Some(Opening::Existing {
            serial: self.session_serial.get(&pair).copied(),
            session: Arc::clone(&session),
            key,
        });
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime,
            after: After::Inbound(Box::new(inbound)),
            stage: Stage::Unseal,
            attempt: None,
        };
        Box::pin(self.begin_pending_maintenance(
            room,
            CommonWork::Packages(Work::Unseal {
                session,
                sealed,
                key,
            }),
            maintenance_save::Continuation::Packages(continuation),
            None,
        ))
        .await;
    }

    async fn finish_pairwise_package_effects(&mut self, lifetime: Arc<Lifetime>) {
        let targets = std::mem::take(&mut self.reoffer)
            .into_iter()
            .filter_map(|(room, target)| {
                self.channels
                    .get(&room)
                    .cloned()
                    .map(|instance| ReofferTarget {
                        room,
                        target,
                        instance,
                    })
            })
            .collect();
        let next = Redelivery {
            attachment: self.delivery_epoch,
            lifetime: Arc::clone(&lifetime),
            targets,
            answered: None,
        };
        if std::mem::take(&mut self.redeliver_now) {
            let (reply, result) = oneshot::channel();
            self.begin_owned_owed_consents(lifetime, reply).await;
            self.join_tasks.spawn(async move {
                let result = result
                    .await
                    .unwrap_or_else(|_| Err(Error::Profile("consent redelivery owner stopped")));
                roster_save::AnsweredJoin::PackageRedelivery { next, result }
            });
        } else {
            Box::pin(self.resume_package_redelivery(next, Ok(()))).await;
        }
    }

    pub(super) fn reject_package_redelivery(&mut self, next: Redelivery) {
        if next.attachment != self.delivery_epoch {
            return;
        }
        for selected in next.targets {
            if self
                .channels
                .get(&selected.room)
                .is_some_and(|current| Arc::ptr_eq(current, &selected.instance))
            {
                self.reoffer.insert((selected.room, selected.target));
            }
        }
    }

    pub(super) async fn resume_package_redelivery(
        &mut self,
        mut next: Redelivery,
        result: crate::error::Result<()>,
    ) {
        if next.attachment != self.delivery_epoch {
            return;
        }
        if let Some(answered) = next.answered.take() {
            if self
                .channels
                .get(&answered.room)
                .is_some_and(|current| Arc::ptr_eq(current, &answered.instance))
            {
                self.finish_answered_join_tail(answered.room, answered.peer);
            }
            return;
        }
        if result.is_err() {
            self.reject_package_redelivery(next);
            return;
        }
        while let Some(selected) = next.targets.pop_front() {
            if !self
                .channels
                .get(&selected.room)
                .is_some_and(|current| Arc::ptr_eq(current, &selected.instance))
            {
                continue;
            }
            let continuation = Continuation {
                instance: selected.instance,
                attachment: next.attachment,
                lifetime: Some(Arc::clone(&next.lifetime)),
                after: After::Reoffer {
                    target: selected.target,
                    remaining: next,
                },
                stage: Stage::Reoffer,
                attempt: None,
            };
            Box::pin(self.begin_pending_maintenance(
                selected.room,
                CommonWork::Packages(Work::Reoffer {
                    target: selected.target,
                    history: true,
                }),
                maintenance_save::Continuation::Packages(continuation),
                None,
            ))
            .await;
            return;
        }
    }

    pub(super) async fn begin_inbound_package(
        &mut self,
        mut stream: PairwiseIn,
        lifetime: Option<Arc<Lifetime>>,
    ) {
        use crate::node::pairwise_stream::{KeyRefusal, PairwiseFrame};
        let lifetime = lifetime.or_else(|| stream.inherited_lifetime.take());
        if matches!(stream.first, PairwiseFrame::RecoveryOpen { .. }) {
            self.start_own_key_donor(stream, lifetime);
            return;
        }
        #[cfg(feature = "test-knobs")]
        if self.end_key_unanswered_for_proof(
            stream.peer,
            match &stream.first {
                PairwiseFrame::RotationHello { channel_id, .. } => Some(*channel_id),
                _ => None,
            },
        ) {
            let PairwiseIn { mut send, recv, .. } = stream;
            let _recv = recv;
            let _ = send.finish();
            return;
        }
        let PairwiseIn {
            peer,
            first,
            second,
            send,
            recv,
            conn,
            recovery_credit,
            donor_admission,
            ..
        } = stream;
        let room = match &first {
            PairwiseFrame::Skdm { channel_id, .. }
            | PairwiseFrame::Open { channel_id, .. }
            | PairwiseFrame::Hello { channel_id, .. }
            | PairwiseFrame::RotationHello { channel_id, .. }
            | PairwiseFrame::RecoveryOpen { channel_id, .. }
            | PairwiseFrame::RecoveryReply { channel_id, .. } => *channel_id,
        };
        let inbound = Inbound {
            peer,
            send,
            recv,
            _conn: conn,
            _recovery_credit: recovery_credit,
            _donor_admission: donor_admission,
            delivery: None,
            opening: None,
            trusted: self.trust.trusted(),
            lifetime: lifetime.as_ref().map(Arc::clone),
        };
        let Some(instance) = self.channels.get(&room).cloned() else {
            answer_inbound(inbound, Some(Err(KeyRefusal::HelloRefused)));
            return;
        };
        let delivery = matches!(&first, PairwiseFrame::RotationHello { .. })
            .then(|| crate::hash::sha256(&first.to_frame()));
        match first {
            PairwiseFrame::RecoveryOpen { .. } | PairwiseFrame::RecoveryReply { .. } => {
                answer_inbound(inbound, Some(Err(KeyRefusal::NotAccepted)))
            }
            PairwiseFrame::Open { sealed, .. } => {
                self.begin_existing_package(room, inbound, sealed, false, lifetime)
                    .await
            }
            PairwiseFrame::Skdm { sealed, .. } => {
                self.begin_existing_package(room, inbound, sealed, true, lifetime)
                    .await
            }
            PairwiseFrame::RotationHello {
                initial, sealed, ..
            } => {
                let Some(delivery) = delivery else {
                    answer_inbound(inbound, Some(Err(KeyRefusal::NotAccepted)));
                    return;
                };
                if self
                    .taken_deliveries
                    .get(&(room, peer))
                    .is_some_and(|taken| taken.contains(&delivery))
                {
                    answer_inbound(inbound, Some(Ok(())));
                    return;
                }
                self.begin_package_respond(
                    room,
                    instance,
                    Inbound {
                        delivery: Some(delivery),
                        opening: Some(Opening::Delivery { sealed }),
                        ..inbound
                    },
                    initial,
                    lifetime,
                )
                .await;
            }
            PairwiseFrame::Hello { initial, .. } => {
                let pair = (room, peer);
                let hash = crate::hash::sha256(&initial);
                if self.sessions.contains_key(&pair)
                    && self.accepted_hello.get(&pair) == Some(&hash)
                {
                    // No prekey is consumed for an already accepted identical hello.
                    self.continue_inbound_second(room, inbound, second, lifetime)
                        .await;
                    return;
                }
                let replaces = self.sessions.contains_key(&pair);
                let ours_wins = replaces
                    && self.profile.as_ref().is_some_and(|profile| {
                        !incoming_session_wins(
                            &profile.fingerprint(),
                            &peer,
                            self.initiated.contains_key(&pair),
                        )
                    });
                if ours_wins {
                    if self
                        .initiated
                        .get(&pair)
                        .is_some_and(|opening| opening.initial.is_none())
                    {
                        self.sessions.remove(&pair);
                        self.initiated.remove(&pair);
                        self.accepted_hello.remove(&pair);
                        self.session_serial.remove(&pair);
                        let context = instance.lock().await.join_context();
                        let bundle = self.delivery_bundle_or_signed(&room, peer).await;
                        if let (Ok(context), Ok(mut bundle), Some(ring)) =
                            (context, bundle, self.prekeys.as_ref().map(Arc::clone))
                        {
                            let one_time = bundle.one_time_prekey.as_ref().map(|key| key.prekey_id);
                            let reservation =
                                one_time.and_then(|id| self.refused_otps.reserve(peer, id));
                            if one_time.is_some() && reservation.is_none() {
                                bundle.one_time_prekey = None;
                                bundle.one_time_prekey_sig = None;
                            }
                            let inbound = Inbound {
                                opening: Some(Opening::RenewHello {
                                    hash,
                                    initial,
                                    second,
                                }),
                                ..inbound
                            };
                            let next = Continuation {
                                instance,
                                attachment: self.delivery_epoch,
                                lifetime,
                                after: After::Inbound(Box::new(inbound)),
                                stage: Stage::HelloInitiate,
                                attempt: None,
                            };
                            Box::pin(self.begin_pending_maintenance(
                                room,
                                CommonWork::Packages(Work::Initiate {
                                    bundle: Box::new(bundle),
                                    context,
                                    ring,
                                    reservation,
                                }),
                                maintenance_save::Continuation::Packages(next),
                                None,
                            ))
                            .await;
                        } else {
                            self.begin_package_respond(
                                room,
                                instance,
                                Inbound {
                                    opening: Some(Opening::Hello {
                                        hash,
                                        replaces,
                                        second,
                                        serial: None,
                                    }),
                                    ..inbound
                                },
                                initial,
                                lifetime,
                            )
                            .await;
                        }
                        return;
                    }
                    if let Some(opening) = self.initiated.get_mut(&pair) {
                        opening.hello_delivered = false;
                    }
                    self.reopen.insert(pair);
                    answer_inbound(inbound, Some(Err(KeyRefusal::HelloRefused)));
                    return;
                }
                self.begin_package_respond(
                    room,
                    instance,
                    Inbound {
                        opening: Some(Opening::Hello {
                            hash,
                            replaces,
                            second,
                            serial: self.session_serial.get(&pair).copied(),
                        }),
                        ..inbound
                    },
                    initial,
                    lifetime,
                )
                .await;
            }
        }
    }

    async fn begin_package_respond(
        &mut self,
        room: Digest32,
        instance: SharedChannel,
        inbound: Inbound,
        initial: Vec<u8>,
        lifetime: Option<Arc<Lifetime>>,
    ) {
        use crate::node::pairwise_stream::KeyRefusal;
        let initial = match InitialMessage::from_wire(&initial) {
            Ok(initial) => initial,
            Err(_) => {
                answer_inbound(inbound, Some(Err(KeyRefusal::HelloRefused)));
                return;
            }
        };
        let context = {
            let channel = instance.lock().await;
            if !channel.is_member(&inbound.peer) {
                answer_inbound(inbound, Some(Err(KeyRefusal::HelloRefused)));
                return;
            }
            match channel.join_context() {
                Ok(context) => context,
                Err(_) => {
                    answer_inbound(inbound, Some(Err(KeyRefusal::HelloRefused)));
                    return;
                }
            }
        };
        let Some(ring) = self.prekeys.as_ref().map(Arc::clone) else {
            answer_inbound(inbound, Some(Err(KeyRefusal::HelloRefused)));
            return;
        };
        let next = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime,
            after: After::Inbound(Box::new(inbound)),
            stage: Stage::Respond,
            attempt: None,
        };
        Box::pin(self.begin_pending_maintenance(
            room,
            CommonWork::Packages(Work::Respond {
                initial: Box::new(initial),
                context,
                ring,
            }),
            maintenance_save::Continuation::Packages(next),
            None,
        ))
        .await;
    }

    /// The existing probe book is a per-peer completed-room cursor, never a second job queue.
    pub(super) async fn owe_older_probes(&mut self) {
        self.drive_owned_older_probes(None).await;
    }

    async fn drive_owned_older_probes(&mut self, lifetime: Option<Arc<Lifetime>>) {
        if lifetime.is_none() && self.store_save_pending() {
            return;
        }
        loop {
            let Some((&peer, &after)) = self.older_probes.first_key_value() else {
                return;
            };
            let room = self.older.keys().find_map(|(room, member)| {
                (*member == peer && after.is_none_or(|after| *room > after)).then_some(*room)
            });
            let Some(room) = room else {
                self.older_probes.remove(&peer);
                continue;
            };
            if self.pending_posts.contains_key(&room) {
                return;
            }
            let Some(instance) = self.channels.get(&room).cloned() else {
                if let Some(after) = self.older_probes.get_mut(&peer) {
                    *after = Some(room);
                }
                continue;
            };
            let next = Continuation {
                instance,
                attachment: self.delivery_epoch,
                lifetime,
                after: After::Probe(peer),
                stage: Stage::Reset,
                attempt: None,
            };
            Box::pin(self.begin_pending_maintenance(
                room,
                CommonWork::Packages(Work::ResetDelivery {
                    target: peer,
                    history: false,
                }),
                maintenance_save::Continuation::Packages(next),
                None,
            ))
            .await;
            return;
        }
    }

    pub(super) async fn begin_owned_rejoin_reset(
        &mut self,
        room: Digest32,
        lifetime: Option<Arc<Lifetime>>,
    ) {
        if (lifetime.is_none() && self.store_save_pending())
            || self.pending_posts.contains_key(&room)
        {
            return;
        }
        let Some(instance) = self.channels.get(&room).cloned() else {
            return;
        };
        let peer = {
            let Ok(channel) = instance.try_lock() else {
                return;
            };
            self.departed_seen
                .get(&room)
                .and_then(|seen| seen.iter().find(|peer| !channel.has_left(peer)).copied())
        };
        let Some(peer) = peer else {
            if let Some(lifetime) = lifetime {
                Box::pin(self.begin_owned_rekeys_for(
                    room,
                    false,
                    Some(lifetime),
                    consent_release::RekeyAfter::Automatic,
                ))
                .await;
            }
            return;
        };
        let next = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime,
            after: After::Rejoin(peer),
            stage: Stage::Reset,
            attempt: None,
        };
        Box::pin(self.begin_pending_maintenance(
            room,
            CommonWork::Packages(Work::ResetDelivery {
                target: peer,
                history: false,
            }),
            maintenance_save::Continuation::Packages(next),
            None,
        ))
        .await;
    }

    pub(super) async fn begin_owned_join_adoption(
        &mut self,
        room: Digest32,
        peer: Digest32,
        session: crate::pairwise::session::Session,
        mine: bool,
        lifetime: Arc<Lifetime>,
        after: metadata_save::JoinAdoption,
    ) {
        self.continue_package_join_adoption(
            room,
            peer,
            session,
            mine,
            lifetime,
            JoinNext::Metadata(after),
        )
        .await;
    }

    pub(super) async fn begin_owned_answered_join_adoption(
        &mut self,
        room: Digest32,
        peer: Digest32,
        session: crate::pairwise::session::Session,
        lifetime: Option<Arc<Lifetime>>,
    ) {
        let Some(lifetime) = lifetime else {
            let _ = self.event_tx.send(NodeEvent::JoinFailed {
                reason: "join publication lifetime is missing".to_owned(),
            });
            return;
        };
        self.continue_package_join_adoption(
            room,
            peer,
            session,
            false,
            lifetime,
            JoinNext::Answered,
        )
        .await;
    }

    pub(super) async fn resume_package_adoption(&mut self, next: AdoptionWait) {
        if next.attachment != self.delivery_epoch
            || !self
                .channels
                .get(&next.room)
                .is_some_and(|current| Arc::ptr_eq(current, &next.instance))
        {
            return;
        }
        Box::pin(self.continue_package_join_adoption(
            next.room,
            next.peer,
            *next.session,
            false,
            next.lifetime,
            JoinNext::Answered,
        ))
        .await;
    }

    async fn continue_package_join_adoption(
        &mut self,
        room: Digest32,
        peer: Digest32,
        session: crate::pairwise::session::Session,
        mine: bool,
        lifetime: Arc<Lifetime>,
        next: JoinNext,
    ) {
        let Some(instance) = self.channels.get(&room).cloned() else {
            self.reject_package_join_adoption(
                room,
                peer,
                Error::Profile("joined room closed before session adoption"),
                next,
                Some(lifetime),
            );
            return;
        };
        if self.pending_posts.contains_key(&room) {
            match next {
                JoinNext::Metadata(after) => {
                    self.defer_metadata_join_adoption(room, peer, session, mine, lifetime, after)
                }
                JoinNext::Answered => {
                    let wake = instance.lock().await.history_publication_wake();
                    let next = AdoptionWait {
                        room,
                        peer,
                        session: Box::new(session),
                        instance,
                        attachment: self.delivery_epoch,
                        lifetime,
                    };
                    self.join_tasks.spawn(async move {
                        wake.await;
                        roster_save::AnsweredJoin::PackageAdoption { next }
                    });
                }
            }
            return;
        }
        let pair = (room, peer);
        if self.sessions.contains_key(&pair) {
            let existing_mine = self.initiated.contains_key(&pair);
            let incoming_wins = match self.profile.as_ref().map(Profile::fingerprint) {
                Some(me) if mine => existing_mine || me < peer,
                Some(me) => incoming_session_wins(&me, &peer, existing_mine),
                None => true,
            };
            if !incoming_wins {
                if existing_mine {
                    if let Some(initial) = self.initiated.get_mut(&pair) {
                        initial.hello_delivered = false;
                    }
                    self.reopen.insert(pair);
                }
                self.finish_package_join_adoption(room, peer, lifetime, next)
                    .await;
                return;
            }
            let continuation = Continuation {
                instance,
                attachment: self.delivery_epoch,
                lifetime: Some(lifetime),
                after: After::AdoptJoin {
                    peer,
                    session: Box::new(session),
                    mine,
                    basis: self.session_serial.get(&pair).copied(),
                    next,
                },
                stage: Stage::Reset,
                attempt: None,
            };
            Box::pin(self.begin_pending_maintenance(
                room,
                CommonWork::Packages(Work::ResetDelivery {
                    target: peer,
                    history: true,
                }),
                maintenance_save::Continuation::Packages(continuation),
                None,
            ))
            .await;
            return;
        }
        self.install_package_join_session(room, peer, session, mine);
        self.finish_package_join_adoption(room, peer, lifetime, next)
            .await;
    }

    fn install_package_join_session(
        &mut self,
        room: Digest32,
        peer: Digest32,
        session: crate::pairwise::session::Session,
        mine: bool,
    ) {
        let pair = (room, peer);
        self.sessions.insert(pair, session);
        self.stamp_session(pair);
        self.accepted_hello.remove(&pair);
        self.reopen.remove(&pair);
        if mine {
            self.initiated.insert(
                pair,
                Initiated {
                    initial: None,
                    hello_delivered: true,
                    reservation: None,
                },
            );
        } else {
            self.initiated.remove(&pair);
        }
    }

    fn reject_package_join_adoption(
        &mut self,
        room: Digest32,
        _peer: Digest32,
        error: Error,
        next: JoinNext,
        lifetime: Option<Arc<Lifetime>>,
    ) {
        match next {
            JoinNext::Metadata(after) => {
                if let Some(lifetime) = lifetime {
                    self.reject_metadata_join_adoption(room, error, after, lifetime);
                } else {
                    let _ = after.reply.send(Outcome::Failed(fault_of(&error)));
                }
            }
            JoinNext::Answered => {
                let _ = self.event_tx.send(NodeEvent::JoinFailed {
                    reason: error.to_string(),
                });
            }
        }
    }

    async fn finish_package_join_adoption(
        &mut self,
        room: Digest32,
        peer: Digest32,
        lifetime: Arc<Lifetime>,
        next: JoinNext,
    ) {
        match next {
            JoinNext::Metadata(after) => {
                self.finish_metadata_join_adoption(room, after, lifetime)
                    .await
            }
            JoinNext::Answered => {
                let Some(instance) = self.channels.get(&room).cloned() else {
                    return;
                };
                if let Some(net) = self.net.as_ref() {
                    net.policy().forget_joiner(&peer);
                }
                let next = Redelivery {
                    attachment: self.delivery_epoch,
                    lifetime: Arc::clone(&lifetime),
                    targets: VecDeque::new(),
                    answered: Some(AnsweredJoin {
                        room,
                        peer,
                        instance,
                    }),
                };
                let (reply, completed) = oneshot::channel();
                self.begin_owned_owed_consents(lifetime, reply).await;
                self.join_tasks.spawn(async move {
                    let result = completed
                        .await
                        .unwrap_or_else(|_| Err(Error::Profile("join consent owner stopped")));
                    roster_save::AnsweredJoin::PackageRedelivery { next, result }
                });
            }
        }
    }

    fn finish_answered_join_tail(&mut self, room: Digest32, peer: Digest32) {
        if !self.trust.is_trusted(&peer) {
            if let Some(net) = self.net.as_ref() {
                net.forget_prejoin(&room, &peer);
            }
        }
        self.joins_answered
            .retain(|_, at| at.elapsed() < JOINER_SEAL_GRACE);
        self.joins_answered
            .insert((room, peer), std::time::Instant::now());
        let _ = self.event_tx.send(NodeEvent::PeerJoined {
            channel_id: room,
            peer,
        });
    }
}

fn answer_inbound(
    mut inbound: Inbound,
    result: Option<Result<(), crate::node::pairwise_stream::KeyRefusal>>,
) {
    match result {
        Some(Ok(())) => {
            tokio::spawn(async move {
                let _ = tokio::time::timeout(
                    crate::transport::framing::FRAME_PATIENCE,
                    inbound
                        .send
                        .write_all(&[crate::node::pairwise_stream::KEY_TAKEN]),
                )
                .await;
                let _ = inbound.send.finish();
                drop(inbound);
            });
        }
        Some(Err(why)) => {
            let _ = inbound.send.reset(why.code());
            let _ = inbound.recv.stop(why.code());
        }
        None => {
            let _ = inbound.send.finish();
        }
    }
}
