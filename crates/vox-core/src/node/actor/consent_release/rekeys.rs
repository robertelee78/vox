//! Original bounded ordinary rekey scan, with native prekey/frame continuations.
use super::*;

pub(in crate::node::actor) enum RekeyAfter {
    Automatic,
    Settlement {
        lifetime: Arc<Lifetime>,
    },
    Consent {
        next: Box<Continuation>,
        reply: Reply,
    },
}
struct Selection {
    room: Digest32,
    instance: SharedChannel,
    asked: bool,
    lifetime: Option<Arc<Lifetime>>,
    after: RekeyAfter,
    rekey_after: Option<Digest32>,
    history_after: Option<Digest32>,
}

struct Pass {
    room: Digest32,
    instance: SharedChannel,
    attachment: u64,
    lifetime: Option<Arc<Lifetime>>,
    targets: VecDeque<Digest32>,
    asked: bool,
    now: u64,
    delivered: u64,
    after: RekeyAfter,
}

enum Step {
    Ready,
    Frame {
        queue: mpsc::OwnedPermit<PairwiseJob>,
        credit: PairwiseCredit,
        generation: u64,
        key_ref: Digest32,
    },
}

pub(in crate::node::actor) struct Target {
    pass: Pass,
    peer: Digest32,
    conn: Arc<VoxConnection>,
    history: bool,
    /// The revision of the member's key debt these keys were selected under: each answer
    /// settles its own generation under it, and nothing under another (V210-45).
    revision: u64,
    keys: VecDeque<Skdm>,
    admitted: VecDeque<PairwiseAdmission>,
    jobs: Vec<(mpsc::OwnedPermit<PairwiseJob>, PairwiseJob)>,
    live: Option<Arc<Lifetime>>,
    step: Step,
    all_sent: bool,
}

impl Node {
    pub(in crate::node::actor) async fn begin_owned_rekeys_for(
        &mut self,
        room: Digest32,
        asked: bool,
        lifetime: Option<Arc<Lifetime>>,
        after: RekeyAfter,
    ) {
        let Some(instance) = self.channels.get(&room).cloned() else {
            self.finish_owned_rekey_after(after, Err(Error::Profile("rekey room is not open")))
                .await;
            return;
        };
        if self.net.is_none() {
            self.finish_owned_rekey_after(after, Ok(0)).await;
            return;
        }
        if self.pending_posts.contains_key(&room) {
            self.redeliver_now = true;
            self.finish_owned_rekey_after(
                after,
                Err(Error::Profile("rekey room publication is busy")),
            )
            .await;
            return;
        }
        let selection = Selection {
            room,
            instance,
            asked,
            lifetime,
            after,
            rekey_after: self.rekey_after.get(&room).copied(),
            history_after: self.history_after.get(&room).copied(),
        };
        self.select_owned_rekeys(selection).await;
    }

    async fn select_owned_rekeys(&mut self, selection: Selection) {
        let Selection {
            room,
            instance,
            asked,
            lifetime,
            after,
            rekey_after,
            history_after,
        } = selection;
        let selected = {
            let channel = instance.lock().await;
            if let RekeyAfter::Consent { next, .. } = &after {
                let validation = if !next.attached(self, &room) || !next.trusted(self) {
                    Err(Error::Profile(
                        "consent release attachment or trust changed",
                    ))
                } else if let Some(held) = &lifetime {
                    next.rekey_authorized(self, held)
                } else {
                    Err(Error::ComputerPolicySuperseded)
                };
                if let Err(error) = validation {
                    drop(channel);
                    self.finish_owned_rekey_after(after, Err(error)).await;
                    return;
                }
            }
            match self.profile.as_ref() {
                Some(profile) => (|| -> crate::error::Result<_> {
                    let owed = channel.owed_rekeys(profile.store(), rekey_after)?;
                    let (history, history_next) =
                        channel.owed_history_page(profile.store(), history_after)?;
                    Ok((owed, history, history_next))
                })(),
                None => Err(Error::AtRestLocked),
            }
        };
        let (owed, history, history_next) = match selected {
            Ok(selected) => selected,
            Err(error) => {
                match after {
                    RekeyAfter::Consent { mut next, reply }
                        if ChannelState::governance_refreshing(&error) =>
                    {
                        // The issue and outbound enqueue already committed. Retain their exact
                        // consent owner and retry only these two unadvanced selection cursors.
                        next.stage = super::Stage::RekeyGovernance {
                            rekey_after,
                            history_after,
                        };
                        self.begin_pending_maintenance(
                            room,
                            Work::Projection(crate::node::channel::session_projection::ProjectionWork::Governance),
                            maintenance_save::Continuation::Consent(*next),
                            reply,
                        )
                        .await;
                    }
                    after => self.finish_owned_rekey_after(after, Err(error)).await,
                }
                return;
            }
        };
        match owed.next {
            Some(next) => {
                self.rekey_after.insert(room, next);
            }
            None => {
                self.rekey_after.remove(&room);
            }
        }
        match history_next {
            Some(next) => {
                self.history_after.insert(room, next);
            }
            None => {
                self.history_after.remove(&room);
            }
        }
        let targets: BTreeSet<_> = owed
            .targets
            .into_iter()
            .chain(history.keys().copied())
            .collect();
        let pass = Pass {
            room,
            instance,
            attachment: self.delivery_epoch,
            lifetime,
            targets: targets.into_iter().collect(),
            asked,
            now: self.now_ms().get(),
            delivered: 0,
            after,
        };
        self.advance_owned_rekey_pass(pass).await;
    }

    pub(super) async fn finish_rekey_governance(
        &mut self,
        room: Digest32,
        saved: Saved,
        lifetime: Arc<Lifetime>,
        mut continuation: Continuation,
        reply: Reply,
    ) {
        if let Err(error) = continuation.rekey_authorized(self, &lifetime) {
            self.fail_owned_consent(room, error, continuation, reply)
                .await;
            return;
        }
        let progress = match saved {
            Saved::Projection(
                crate::node::channel::session_projection::ProjectionProgress::Governance(progress),
            ) => progress,
            _ => {
                self.fail_owned_consent(
                    room,
                    Error::Profile("unexpected rekey governance completion"),
                    continuation,
                    reply,
                )
                .await;
                return;
            }
        };
        if !progress.ready {
            if progress.pending {
                self.begin_pending_maintenance(
                    room,
                    Work::Projection(
                        crate::node::channel::session_projection::ProjectionWork::Governance,
                    ),
                    maintenance_save::Continuation::Consent(continuation),
                    reply,
                )
                .await;
            } else {
                self.fail_owned_consent(
                    room,
                    Error::Profile("rekey governance projection stopped before readiness"),
                    continuation,
                    reply,
                )
                .await;
            }
            return;
        }
        let (rekey_after, history_after) =
            match std::mem::replace(&mut continuation.stage, super::Stage::Vacant) {
                super::Stage::LogRekeyGovernance(route) => {
                    self.begin_owned_log_rekeys(room, continuation.target, route, Some(lifetime))
                        .await;
                    return;
                }
                super::Stage::RekeyGovernance {
                    rekey_after,
                    history_after,
                } => (rekey_after, history_after),
                _ => {
                    self.fail_owned_consent(
                        room,
                        Error::Profile("rekey governance prerequisite missing"),
                        continuation,
                        reply,
                    )
                    .await;
                    return;
                }
            };
        let selection = Selection {
            room,
            instance: Arc::clone(&continuation.instance),
            asked: continuation.asked,
            lifetime: Some(lifetime),
            after: RekeyAfter::Consent {
                next: Box::new(continuation),
                reply,
            },
            rekey_after,
            history_after,
        };
        self.select_owned_rekeys(selection).await;
    }

    async fn advance_owned_rekey_pass(&mut self, mut pass: Pass) {
        while let Some(peer) = pass.targets.pop_front() {
            if pass.attachment != self.delivery_epoch
                || !self
                    .channels
                    .get(&pass.room)
                    .is_some_and(|current| Arc::ptr_eq(current, &pass.instance))
            {
                self.finish_owned_rekey_after(
                    pass.after,
                    Err(Error::Profile("rekey attachment changed")),
                )
                .await;
                return;
            }
            if !self.trust.is_trusted(&peer) {
                continue;
            }
            // **The direct route carries every generation still in the member's set** (V210-45),
            // whether it was owed at a rotation, a reset or a boundary; each answer settles its
            // own. The send stays gated as ever (`owed_keys_for`: a valid grant at this moment).
            let owed = {
                let channel = pass.instance.lock().await;
                let live = channel.sender_generation();
                match self.profile.as_ref() {
                    Some(profile) => channel
                        .owed_keys_for(profile.store(), &peer)
                        .map(|owed| owed.map(|owed| owed.iter().any(|g| *g < live))),
                    None => Err(Error::AtRestLocked),
                }
            };
            let history = match owed {
                Ok(Some(history)) => history,
                Ok(None) | Err(_) => continue,
            };
            if !pass.asked
                && self
                    .key_backoff
                    .get(&(pass.room, peer))
                    .is_some_and(|backoff| pass.now < backoff.until)
            {
                continue;
            }
            let pair = (pass.room, peer);
            if self.history_in_flight.contains_key(&pair)
                || (!history && self.keys_in_flight.contains_key(&pair))
            {
                continue;
            }
            // A member that came back takes room keys only by return-bound log package (R4),
            // and the log route posts each it is owed once. **The acknowledgement probe**
            // (ruling-returner): once every key it is owed is posted to it, that exact release in
            // a package bound to its current return (the posted mark), those same releases go to
            // it directly, where it installs none of them (`package_install`) and its answers
            // settle them. The log route is skipped only while a delivery to it is this room's
            // save in flight: the settling mark is not that, as it outlives a delivery that
            // deferred or failed.
            let returned = {
                let channel = pass.instance.lock().await;
                channel.key_returned(&peer).then(|| {
                    self.profile.as_ref().is_some_and(|profile| {
                        channel
                            .owed_keys_for(profile.store(), &peer)
                            .ok()
                            .flatten()
                            .and_then(|owed| channel.owed_skdms(profile, &peer, &owed).ok())
                            .is_some_and(|keys| {
                                channel.releases_posted(profile.store(), &peer, &keys)
                            })
                    })
                })
            };
            if returned == Some(false) {
                let delivering = match self.pending_posts.get(&pass.room) {
                    Some(post_save::Pending::Maintenance(pending)) => {
                        pending.consent().is_some_and(|next| next.target == peer)
                    }
                    _ => false,
                };
                if !delivering {
                    self.begin_owned_log_rekeys(
                        pass.room,
                        peer,
                        super::Offline {
                            attempt: 0,
                            source_room: pass.room,
                            asked: pass.asked,
                        },
                        None,
                    )
                    .await;
                }
                continue;
            }
            let selected = {
                let channel = pass.instance.lock().await;
                let revision = channel.history_revision(&peer);
                match self.profile.as_ref() {
                    Some(profile) => match channel.owed_keys_for(profile.store(), &peer) {
                        Ok(Some(owed)) => channel.owed_skdms(profile, &peer, &owed),
                        Ok(None) => Ok(Vec::new()),
                        Err(error) => Err(error),
                    },
                    None => Err(Error::AtRestLocked),
                }
                .map(|keys| (keys, revision))
            };
            let Ok((mut keys, revision)) = selected else {
                continue;
            };
            if keys.is_empty() {
                continue;
            }
            if history {
                keys.reverse();
            }
            let owed_now: BTreeSet<_> = keys.iter().map(|key| key.body.chain_id).collect();
            self.deliveries.retain(|(room, target, generation), _| {
                *room != pass.room || *target != peer || owed_now.contains(generation)
            });
            self.delivery_reserved
                .retain(|(room, target, generation), _| {
                    *room != pass.room || *target != peer || owed_now.contains(generation)
                });
            let Some(conn) = self.reach_member(&pass.room, peer, pass.asked).await else {
                continue;
            };
            // The room's lock is waited for, as this pass waited for it just above to select
            // the keys; nothing of the room's is held here (ledger 148).
            let Some(admitted) = self
                .reserve_key_deliveries_waiting(&pass.room, peer, &conn, &keys, history)
                .await
            else {
                continue;
            };
            let capacity = keys.len();
            let live = pass.lifetime.as_ref().map(Arc::clone);
            let target = Target {
                pass,
                peer,
                conn,
                history,
                revision,
                keys: keys.into(),
                admitted: admitted.into(),
                jobs: Vec::with_capacity(capacity),
                live,
                step: Step::Ready,
                all_sent: true,
            };
            let Some(next) = self.advance_owned_rekey_target(target).await else {
                return;
            };
            pass = next;
        }
        #[cfg(feature = "test-knobs")]
        self.finish_post_proof(&pass.room, pass.delivered);
        self.finish_owned_rekey_after(pass.after, Ok(pass.delivered))
            .await;
    }

    async fn advance_owned_rekey_target(&mut self, mut target: Target) -> Option<Pass> {
        let room = target.pass.room;
        while let Some(key) = target.keys.pop_front() {
            let Some(admission) = target.admitted.pop_front() else {
                self.fail_owned_rekey_target(target, Error::Profile("rekey admission changed"))
                    .await;
                return None;
            };
            let id = (room, target.peer, key.body.chain_id);
            let key_ref = crate::governance::membership::skdm_ref(&key);
            if let Some(delivery) = self
                .deliveries
                .get(&id)
                .filter(|delivery| delivery.key == key_ref)
            {
                let frame = delivery.frame.clone();
                let opening = delivery.opening;
                target.jobs.push((
                    admission.queue,
                    PairwiseJob {
                        conn: Arc::clone(&target.conn),
                        frames: vec![frame].into_boxed_slice(),
                        channel_id: room,
                        after: AfterWrite::Key {
                            chain_id: key.body.chain_id,
                            opening: Some(opening),
                            hello: false,
                            session: None,
                            history: target.history,
                            revision: target.revision,
                            epoch: target.pass.attachment,
                        },
                        credit: admission.job,
                        prekey: delivery.prekey.clone(),
                    },
                ));
                continue;
            }
            let Some(selected) = self
                .select_owned_prekey_delivery(&room, target.peer, false)
                .await
            else {
                target.all_sent = false;
                break;
            };
            target.step = Step::Frame {
                queue: admission.queue,
                credit: admission.job,
                generation: key.body.chain_id,
                key_ref,
            };
            self.dispatch_owned_rekey_native(target, selected.into_frame_work(Box::new(key)))
                .await;
            return None;
        }
        self.enqueue_owned_rekey_target(target).await
    }

    async fn dispatch_owned_rekey_native(&mut self, target: Target, work: package_save::Work) {
        let room = target.pass.room;
        let continuation = Continuation {
            instance: Arc::clone(&target.pass.instance),
            attachment: target.pass.attachment,
            lifetime: target.live.as_ref().map(Arc::clone),
            target: target.peer,
            asked: target.pass.asked,
            decision: self.trust_decision(&target.peer),
            plan: None,
            cursor: None,
            prekey: None,
            stage: super::Stage::Rekeys(Box::new(target)),
        };
        self.begin_pending_maintenance(
            room,
            Work::Packages(work),
            maintenance_save::Continuation::Consent(continuation),
            None,
        )
        .await;
    }

    pub(super) async fn finish_owned_rekeys(
        &mut self,
        room: Digest32,
        result: crate::error::Result<Saved>,
        lifetime: Arc<Lifetime>,
        mut continuation: Continuation,
    ) {
        let super::Stage::Rekeys(target) =
            std::mem::replace(&mut continuation.stage, super::Stage::Vacant)
        else {
            return;
        };
        let mut target = *target;
        if !continuation.attached(self, &room) || !continuation.trusted(self) {
            self.fail_owned_rekey_target(
                target,
                Error::Profile("rekey trust or attachment changed"),
            )
            .await;
            return;
        }
        target.live = Some(lifetime);
        let saved = match result {
            Ok(saved) => saved,
            Err(error) => {
                self.fail_owned_rekey_target(target, error).await;
                return;
            }
        };
        match (std::mem::replace(&mut target.step, Step::Ready), saved) {
            (
                Step::Frame {
                    queue,
                    credit,
                    generation,
                    key_ref,
                },
                Saved::Packages(package_save::Saved::FramedOutbound {
                    frame,
                    skdm,
                    reservation: prekey,
                }),
            ) => {
                let Some(frame) = frame else {
                    drop((prekey, queue, credit));
                    self.say_key_waits(&room, target.peer, None);
                    target.all_sent = false;
                    let Some(pass) = self.enqueue_owned_rekey_target(target).await else {
                        return;
                    };
                    self.advance_owned_rekey_pass(pass).await;
                    return;
                };
                if key_ref != crate::governance::membership::skdm_ref(&skdm)
                    || generation != skdm.body.chain_id
                {
                    drop((prekey, queue, credit));
                    self.fail_owned_rekey_target(target, Error::Profile("selected rekey changed"))
                        .await;
                    return;
                }
                let Some(reservation) =
                    self.delivery_reserved
                        .remove(&(room, target.peer, generation))
                else {
                    drop((prekey, queue, credit));
                    self.fail_owned_rekey_target(
                        target,
                        Error::Profile("rekey frame reservation changed"),
                    )
                    .await;
                    return;
                };
                let bytes = frame.frame.into_boxed_slice();
                self.deliveries.insert(
                    (room, target.peer, generation),
                    Delivery {
                        frame: bytes.clone(),
                        one_time_prekey: frame.one_time_prekey,
                        key: key_ref,
                        reservation,
                        opening: frame.opening,
                        revision: target.revision,
                        prekey: prekey.clone(),
                    },
                );
                self.key_left(&room, target.peer);
                target.jobs.push((
                    queue,
                    PairwiseJob {
                        conn: Arc::clone(&target.conn),
                        frames: vec![bytes].into_boxed_slice(),
                        channel_id: room,
                        after: AfterWrite::Key {
                            chain_id: generation,
                            opening: Some(frame.opening),
                            hello: false,
                            session: None,
                            history: target.history,
                            revision: target.revision,
                            epoch: target.pass.attachment,
                        },
                        credit,
                        prekey,
                    },
                ));
            }
            _ => {
                self.fail_owned_rekey_target(
                    target,
                    Error::Profile("unexpected native rekey completion"),
                )
                .await;
                return;
            }
        }
        if !target.all_sent {
            if let Some(pass) = self.enqueue_owned_rekey_target(target).await {
                self.advance_owned_rekey_pass(pass).await;
            }
        } else if let Some(pass) = self.advance_owned_rekey_target(target).await {
            self.advance_owned_rekey_pass(pass).await;
        }
    }

    async fn enqueue_owned_rekey_target(&mut self, target: Target) -> Option<Pass> {
        self.finish_rekey_enqueue(target).await
    }

    async fn finish_rekey_enqueue(&mut self, mut target: Target) -> Option<Pass> {
        if !target.all_sent {
            target.keys.clear();
            target.admitted.clear();
        }
        let room = target.pass.room;
        let pair = (room, target.peer);
        let watched = target.jobs.len() as u32;
        for _ in 0..watched {
            self.key_in_flight(room, target.peer);
        }
        if target.history && watched != 0 {
            self.history_in_flight
                .insert(pair, (watched, !target.all_sent));
        }
        let jobs = std::mem::take(&mut target.jobs);
        let published = if target.live.is_some() {
            for (queue, job) in jobs {
                queue.send(job);
            }
            true
        } else {
            self.computer_authority()
                .and_then(|authority| {
                    authority.publish(|| {
                        for (queue, job) in jobs {
                            queue.send(job);
                        }
                        true
                    })
                })
                .unwrap_or(false)
        };
        if !published {
            for _ in 0..watched {
                self.key_landed(room, target.peer);
            }
            if target.history {
                self.history_in_flight.remove(&pair);
            }
        } else if target.all_sent {
            target.pass.delivered += 1;
        }
        if !published && !matches!(target.pass.after, RekeyAfter::Automatic) {
            self.finish_owned_rekey_after(
                target.pass.after,
                Err(Error::Profile("rekey authority changed before enqueue")),
            )
            .await;
            return None;
        }
        Some(target.pass)
    }

    async fn fail_owned_rekey_target(&mut self, target: Target, error: Error) {
        self.finish_owned_rekey_after(target.pass.after, Err(error))
            .await;
    }

    async fn finish_owned_rekey_after(
        &mut self,
        after: RekeyAfter,
        result: crate::error::Result<u64>,
    ) {
        match after {
            RekeyAfter::Automatic => {}
            RekeyAfter::Settlement { lifetime } => {
                if result.is_ok() {
                    Box::pin(self.begin_owned_consent_pass(None, Some(lifetime), None, None)).await;
                }
            }
            RekeyAfter::Consent { next, reply } => match result {
                Ok(_) => self.finish_owned_consent_tail(*next, reply).await,
                Err(error) => {
                    let room = next.instance.lock().await.channel_id();
                    self.fail_owned_consent(room, error, *next, reply).await;
                }
            },
        }
    }

    pub(super) fn reject_owned_rekeys(&mut self, target: Target, error: Error) {
        match target.pass.after {
            RekeyAfter::Automatic | RekeyAfter::Settlement { .. } => {}
            RekeyAfter::Consent { next, reply } => {
                self.reject_owned_consent(target.pass.room, error, *next, reply)
            }
        }
    }
}

pub(super) fn retire(target: Target, error: Error) {
    match target.pass.after {
        RekeyAfter::Automatic | RekeyAfter::Settlement { .. } => {}
        RekeyAfter::Consent { next, reply } => super::retire_detached(Err(error), *next, reply),
    }
}
