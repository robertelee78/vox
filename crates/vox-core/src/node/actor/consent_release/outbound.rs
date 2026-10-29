//! Outbound crypto waits on the native prekey owner, never on the actor's ring lock.
use super::*;

pub(super) enum Stage {
    FrameConsent {
        conn: Arc<VoxConnection>,
        queue: mpsc::OwnedPermit<PairwiseJob>,
        credit: PairwiseCredit,
        key_ref: Digest32,
    },
    SealConsent {
        route: Offline,
        posted_as: Digest32,
    },
    InitiateConsent(LegacyConsent),
    SealLog {
        route: Offline,
        keys: VecDeque<Skdm>,
        history: bool,
        generation: u64,
        posted_as: Digest32,
    },
}

pub(super) struct LegacyConsent {
    pub(super) skdm: Box<Skdm>,
    pub(super) history_owed: bool,
    pub(super) conn: Arc<VoxConnection>,
    pub(super) queue: mpsc::OwnedPermit<PairwiseJob>,
    pub(super) credit: PairwiseCredit,
}

impl Node {
    pub(super) async fn frame_owned_consent(
        &mut self,
        room: Digest32,
        skdm: Box<Skdm>,
        mut continuation: Continuation,
        reply: &mut Reply,
    ) -> std::result::Result<bool, Fault> {
        if !continuation.attached(self, &room) || !continuation.trusted(self) {
            return Err(Fault::NotTrusted);
        }
        let super::Stage::Hold(route) =
            std::mem::replace(&mut continuation.stage, super::Stage::Vacant)
        else {
            return Err(Fault::Internal);
        };
        match route {
            Route::Online { conn, modern } => {
                let Some(admitted) = self.reserve_key_deliveries(
                    &room,
                    continuation.target,
                    std::slice::from_ref(skdm.as_ref()),
                    modern,
                    false,
                ) else {
                    return Err(Fault::DeliveryBusy);
                };
                let Some(PairwiseAdmission {
                    queue, job: credit, ..
                }) = admitted.into_iter().next()
                else {
                    return Err(Fault::DeliveryBusy);
                };
                if !modern {
                    continuation.stage = super::Stage::Legacy {
                        conn,
                        queue,
                        credit,
                    };
                    return Ok(self
                        .dispatch_owned_consent_issue(room, skdm, continuation, None, reply.take())
                        .await);
                }
                let key_ref = crate::governance::membership::skdm_ref(&skdm);
                let id = (room, continuation.target, skdm.body.chain_id);
                if let Some(frame) = self
                    .deliveries
                    .get(&id)
                    .filter(|delivery| delivery.key == key_ref)
                    .map(|delivery| delivery.frame.clone())
                {
                    let opening = Some(crate::hash::sha256(&frame));
                    let job = PairwiseJob {
                        conn,
                        frames: vec![frame].into_boxed_slice(),
                        channel_id: room,
                        after: AfterWrite::Key {
                            chain_id: skdm.body.chain_id,
                            opening,
                            hello: false,
                            session: None,
                            history: false,
                            epoch: continuation.attachment,
                        },
                        credit,
                    };
                    continuation.stage = super::Stage::Online { queue, job };
                    return Ok(self
                        .dispatch_owned_consent_issue(room, skdm, continuation, None, reply.take())
                        .await);
                }
                if !self.delivery_reserved.contains_key(&id) {
                    return Err(Fault::DeliveryBusy);
                }
                let selected = self
                    .select_owned_prekey_delivery(&room, continuation.target, false)
                    .await
                    .ok_or(Fault::Unreachable)?;
                let work = selected.into_frame_work(skdm);
                continuation.stage = super::Stage::Outbound(Stage::FrameConsent {
                    conn,
                    queue,
                    credit,
                    key_ref,
                });
                Ok(self
                    .begin_pending_maintenance(
                        room,
                        Work::Packages(work),
                        maintenance_save::Continuation::Consent(continuation),
                        reply.take(),
                    )
                    .await)
            }
            Route::Offline(route) => {
                let posted_as = (
                    room,
                    continuation.target,
                    crate::governance::membership::skdm_ref(&skdm),
                );
                if self.packages_posted.contains(&posted_as) {
                    continuation.stage = super::Stage::Offline {
                        route,
                        posted_as: posted_as.2,
                    };
                    return Ok(self
                        .dispatch_owned_consent_issue(room, skdm, continuation, None, reply.take())
                        .await);
                }
                let Some(selected) = self
                    .select_owned_key_package(&room, continuation.target)
                    .await
                else {
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
                    return Err(Fault::Unreachable);
                };
                let work = selected.into_work(continuation.target, skdm);
                continuation.stage = super::Stage::Outbound(Stage::SealConsent {
                    route,
                    posted_as: posted_as.2,
                });
                Ok(self
                    .begin_pending_maintenance(
                        room,
                        Work::Packages(work),
                        maintenance_save::Continuation::Consent(continuation),
                        reply.take(),
                    )
                    .await)
            }
        }
    }

    pub(super) async fn dispatch_owned_consent_issue(
        &mut self,
        room: Digest32,
        skdm: Box<Skdm>,
        continuation: Continuation,
        package: Option<KeyPackage>,
        reply: Reply,
    ) -> bool {
        let entitled_from = continuation
            .plan
            .as_ref()
            .and_then(|plan| plan.first().copied())
            .unwrap_or((skdm.body.chain_id, skdm.body.iteration));
        self.begin_pending_maintenance(
            room,
            Work::Consent(consent_save::Work::Issue {
                target: continuation.target,
                skdm,
                full_history: continuation.history == crate::node::trust::HistoryGrant::Full,
                entitled_from,
                package,
            }),
            maintenance_save::Continuation::Consent(continuation),
            reply,
        )
        .await
    }

    pub(super) async fn finish_owned_consent_outbound(
        &mut self,
        room: Digest32,
        saved: Saved,
        lifetime: Arc<Lifetime>,
        mut continuation: Continuation,
        reply: Reply,
    ) {
        let super::Stage::Outbound(stage) =
            std::mem::replace(&mut continuation.stage, super::Stage::Vacant)
        else {
            self.fail_owned_consent(
                room,
                Error::Profile("outbound consent continuation missing"),
                continuation,
                reply,
            )
            .await;
            return;
        };
        match (stage, saved) {
            (
                Stage::FrameConsent {
                    conn,
                    queue,
                    credit,
                    key_ref,
                },
                Saved::Packages(package_save::Saved::FramedOutbound {
                    frame,
                    skdm,
                    reservation: prekey,
                }),
            ) => {
                let Some(frame) = frame else {
                    drop((queue, credit, prekey));
                    self.say_key_waits(&room, continuation.target, None);
                    self.wait_owned_consent(room, continuation, reply).await;
                    return;
                };
                if key_ref != crate::governance::membership::skdm_ref(&skdm) {
                    drop((queue, credit, prekey));
                    self.fail_owned_consent(
                        room,
                        Error::Profile("outbound consent key changed"),
                        continuation,
                        reply,
                    )
                    .await;
                    return;
                }
                let id = (room, continuation.target, skdm.body.chain_id);
                let Some(reservation) = self.delivery_reserved.remove(&id) else {
                    drop((queue, credit, prekey));
                    self.fail_owned_consent(
                        room,
                        Error::Profile("outbound consent delivery reservation changed"),
                        continuation,
                        reply,
                    )
                    .await;
                    return;
                };
                continuation.prekey = prekey;
                if let Some(prekey) = frame.one_time_prekey {
                    self.refused_otps.note(continuation.target, prekey);
                }
                let bytes = frame.frame.into_boxed_slice();
                self.deliveries.insert(
                    id,
                    Delivery {
                        frame: bytes.clone(),
                        one_time_prekey: frame.one_time_prekey,
                        key: key_ref,
                        reservation,
                        opening: frame.opening,
                    },
                );
                self.key_left(&room, continuation.target);
                let job = PairwiseJob {
                    conn,
                    frames: vec![bytes].into_boxed_slice(),
                    channel_id: room,
                    after: AfterWrite::Key {
                        chain_id: skdm.body.chain_id,
                        opening: Some(frame.opening),
                        hello: false,
                        session: None,
                        history: false,
                        epoch: continuation.attachment,
                    },
                    credit,
                };
                continuation.stage = super::Stage::Online { queue, job };
                self.dispatch_owned_consent_issue(room, skdm, continuation, None, reply)
                    .await;
            }
            (
                Stage::SealConsent { route, posted_as },
                Saved::Packages(package_save::Saved::SealedOutbound {
                    package,
                    skdm,
                    reservation,
                }),
            ) => {
                let Some(package) = package else {
                    drop(reservation);
                    continuation.stage = super::Stage::Offline { route, posted_as };
                    self.wait_owned_consent(room, continuation, reply).await;
                    return;
                };
                continuation.stage = super::Stage::Offline { route, posted_as };
                continuation.prekey = reservation;
                self.dispatch_owned_consent_issue(room, skdm, continuation, Some(package), reply)
                    .await;
            }
            (
                Stage::InitiateConsent(delivery),
                Saved::Packages(package_save::Saved::Initiated {
                    initiated,
                    reservation,
                }),
            ) => {
                if !self.install_owned_legacy_session(
                    room,
                    continuation.target,
                    initiated,
                    reservation,
                ) {
                    self.wait_owned_consent(room, continuation, reply).await;
                    return;
                }
                self.enqueue_owned_legacy_consent(room, delivery, continuation, lifetime, reply)
                    .await;
            }
            (
                Stage::SealLog {
                    route,
                    keys,
                    history,
                    generation,
                    posted_as,
                },
                Saved::Packages(package_save::Saved::SealedOutbound {
                    package,
                    reservation,
                    ..
                }),
            ) => {
                let Some(package) = package else {
                    drop(reservation);
                    self.wait_owned_consent(room, continuation, reply).await;
                    return;
                };
                continuation.stage = super::Stage::Packages {
                    route,
                    keys,
                    history,
                    generation,
                    posted_as,
                };
                continuation.prekey = reservation;
                self.begin_pending_maintenance(
                    room,
                    Work::Session(SessionWrite::Package { package }),
                    maintenance_save::Continuation::Consent(continuation),
                    reply,
                )
                .await;
            }
            _ => {
                self.fail_owned_consent(
                    room,
                    Error::Profile("unexpected native outbound consent completion"),
                    continuation,
                    reply,
                )
                .await
            }
        }
    }

    pub(super) async fn continue_owned_legacy_consent(
        &mut self,
        room: Digest32,
        delivery: LegacyConsent,
        mut continuation: Continuation,
        lifetime: Arc<Lifetime>,
        reply: Reply,
    ) {
        if self.sessions.contains_key(&(room, continuation.target)) {
            self.enqueue_owned_legacy_consent(room, delivery, continuation, lifetime, reply)
                .await;
            return;
        }
        let Some(selected) = self
            .select_owned_legacy_session(&room, continuation.target)
            .await
        else {
            self.wait_owned_consent(room, continuation, reply).await;
            return;
        };
        continuation.stage = super::Stage::Outbound(Stage::InitiateConsent(delivery));
        self.begin_pending_maintenance(
            room,
            Work::Packages(selected.into_initiate_work()),
            maintenance_save::Continuation::Consent(continuation),
            reply,
        )
        .await;
    }

    pub(super) fn install_owned_legacy_session(
        &mut self,
        room: Digest32,
        peer: Digest32,
        candidate: Option<(Box<InitialMessage>, Box<crate::pairwise::session::Session>)>,
        reservation: Option<prekeys::OneTimeReservation>,
    ) -> bool {
        let pair = (room, peer);
        // An inbound session accepted during native initiation is current authority. Never
        // overwrite it with an old absent-session selection or restore a speculative ratchet.
        if self.sessions.contains_key(&pair) {
            return true;
        }
        let Some((initial, session)) = candidate else {
            return false;
        };
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
        true
    }

    pub(super) fn frame_owned_legacy_key(
        &mut self,
        room: Digest32,
        peer: Digest32,
        key: &Skdm,
        announce: bool,
    ) -> Option<(Vec<Vec<u8>>, bool, Option<u64>)> {
        let hello = self
            .initiated
            .get(&(room, peer))
            .filter(|opening| announce && !opening.hello_delivered)
            .and_then(|opening| opening.initial.as_ref());
        let mut frames = Vec::with_capacity(2);
        if let Some(initial) = hello {
            frames.push(crate::node::pairwise_stream::hello_frame(&room, initial));
        }
        let carries_hello = hello.is_some();
        let session = self.sessions.get_mut(&(room, peer))?;
        frames.push(crate::node::pairwise_stream::skdm_frame(&room, session, key).ok()?);
        Some((
            frames,
            carries_hello,
            self.session_serial.get(&(room, peer)).copied(),
        ))
    }

    async fn enqueue_owned_legacy_consent(
        &mut self,
        room: Digest32,
        delivery: LegacyConsent,
        continuation: Continuation,
        lifetime: Arc<Lifetime>,
        reply: Reply,
    ) {
        let LegacyConsent {
            skdm,
            history_owed,
            conn,
            queue,
            credit,
        } = delivery;
        let before = self.snapshot_legacy_session((room, continuation.target), true);
        let Some((frames, hello, session)) =
            self.frame_owned_legacy_key(room, continuation.target, &skdm, true)
        else {
            self.restore_legacy_session(before);
            self.wait_owned_consent(room, continuation, reply).await;
            return;
        };
        *self
            .keys_in_flight
            .entry((room, continuation.target))
            .or_default() += 1;
        let opening = frames
            .first()
            .filter(|_| session.is_none())
            .map(|frame| crate::hash::sha256(frame));
        queue.send(PairwiseJob {
            conn,
            frames: frames.into_iter().map(Vec::into_boxed_slice).collect(),
            channel_id: room,
            after: AfterWrite::Key {
                chain_id: skdm.body.chain_id,
                opening,
                hello,
                session,
                history: false,
                epoch: continuation.attachment,
            },
            credit,
        });
        if hello {
            self.note_owned_legacy_hello(room, continuation.target);
        }
        self.after_owned_consent_enqueue(room, history_owed, continuation, lifetime, reply)
            .await;
    }

    pub(super) fn note_owned_legacy_hello(&mut self, room: Digest32, peer: Digest32) {
        let prekey = self
            .initiated
            .get(&(room, peer))
            .and_then(|opening| opening.initial.as_ref())
            .and_then(|initial| initial.one_time_prekey_id);
        if let Some(prekey) = prekey {
            self.refused_otps.note(peer, prekey);
        }
        if let Some(opening) = self.initiated.get_mut(&(room, peer)) {
            opening.reservation = None;
        }
    }
}

pub(super) fn offline_route(stage: &Stage) -> Option<&Offline> {
    match stage {
        Stage::SealConsent { route, .. } => Some(route),
        _ => None,
    }
}
