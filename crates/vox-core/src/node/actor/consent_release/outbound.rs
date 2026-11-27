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
    SealLog {
        route: Offline,
        keys: VecDeque<Skdm>,
        history: bool,
        generation: u64,
        posted_as: Digest32,
    },
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
            Route::Online { conn } => {
                let Some(admitted) = self.reserve_key_deliveries(
                    &room,
                    continuation.target,
                    &conn,
                    std::slice::from_ref(skdm.as_ref()),
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
                let key_ref = crate::governance::membership::skdm_ref(&skdm);
                let id = (room, continuation.target, skdm.body.chain_id);
                if let Some((frame, prekey)) = self
                    .deliveries
                    .get(&id)
                    .filter(|delivery| delivery.key == key_ref)
                    .map(|delivery| (delivery.frame.clone(), delivery.prekey.clone()))
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
                        prekey,
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
                // Keep the selection reserved, but unnamed, until the physical write.
                let bytes = frame.frame.into_boxed_slice();
                self.deliveries.insert(
                    id,
                    Delivery {
                        frame: bytes.clone(),
                        one_time_prekey: frame.one_time_prekey,
                        key: key_ref,
                        reservation,
                        opening: frame.opening,
                        prekey: prekey.clone(),
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
                    prekey,
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
                    ..
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
                    removal_generation,
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
                    Work::Session(SessionWrite::Package {
                        package,
                        removal_generation,
                    }),
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
}

pub(super) fn offline_route(stage: &Stage) -> Option<&Offline> {
    match stage {
        Stage::SealConsent { route, .. } => Some(route),
        _ => None,
    }
}
