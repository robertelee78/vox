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
    Packages {
        next: package_save::Redelivery,
        reply: Reply,
    },
}

struct Pass {
    room: Digest32,
    instance: SharedChannel,
    attachment: u64,
    lifetime: Option<Arc<Lifetime>>,
    targets: VecDeque<Digest32>,
    history: BTreeMap<Digest32, u64>,
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
    Initiate,
}

pub(super) struct Target {
    pass: Pass,
    peer: Digest32,
    conn: Arc<VoxConnection>,
    modern: bool,
    history: bool,
    keys: VecDeque<Skdm>,
    admitted: VecDeque<PairwiseAdmission>,
    jobs: Vec<(mpsc::OwnedPermit<PairwiseJob>, PairwiseJob)>,
    live: Option<Arc<Lifetime>>,
    step: Step,
    all_sent: bool,
    legacy_before: Option<LegacySessionRollback>,
    reservations: Vec<prekeys::OneTimeReservation>,
    #[cfg(feature = "test-knobs")]
    generations: Vec<u64>,
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
        let selected = {
            let channel = instance.lock().await;
            match self.profile.as_ref() {
                Some(profile) => (|| -> crate::error::Result<_> {
                    let owed = channel
                        .owed_rekeys(profile.store(), self.rekey_after.get(&room).copied())?;
                    let (history, history_next) = channel.owed_history_page(
                        profile.store(),
                        self.history_after.get(&room).copied(),
                    )?;
                    Ok((owed, history, history_next))
                })(),
                None => Err(Error::AtRestLocked),
            }
        };
        let (owed, history, history_next) = match selected {
            Ok(selected) => selected,
            Err(error) => {
                self.finish_owned_rekey_after(after, Err(error)).await;
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
            history,
            asked,
            now: self.now_ms().get(),
            delivered: 0,
            after,
        };
        self.advance_owned_rekey_pass(pass).await;
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
            #[cfg(feature = "test-knobs")]
            if self.fx28_rekey_pause == Some((pass.room, peer)) {
                continue;
            }
            if !self.trust.is_trusted(&peer) {
                continue;
            }
            if let std::collections::btree_map::Entry::Vacant(slot) = pass.history.entry(peer) {
                let selected = {
                    let channel = pass.instance.lock().await;
                    match self.profile.as_ref() {
                        Some(profile) => channel.owed_history_for(profile.store(), &peer),
                        None => Err(Error::AtRestLocked),
                    }
                };
                match selected {
                    Ok(Some(floor)) => {
                        slot.insert(floor);
                    }
                    Ok(None) => {}
                    Err(_) => continue,
                }
            }
            if !pass.asked
                && self
                    .key_backoff
                    .get(&(pass.room, peer))
                    .is_some_and(|(_, until)| pass.now < *until)
            {
                continue;
            }
            let history = pass.history.contains_key(&peer);
            let pair = (pass.room, peer);
            if self.history_in_flight.contains_key(&pair)
                || (!history && self.keys_in_flight.contains_key(&pair))
            {
                continue;
            }
            let selected = {
                let channel = pass.instance.lock().await;
                match self.profile.as_ref() {
                    Some(profile) => match pass.history.get(&peer) {
                        Some(floor) => channel.history_skdms(profile, &peer, *floor),
                        None => channel.rekey_skdm_for(profile, &peer).map(|key| vec![key]),
                    },
                    None => Err(Error::AtRestLocked),
                }
            };
            let Ok(mut keys) = selected else { continue };
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
            let modern = !matches!(self.older.get(&pair), Some(false));
            let Some(admitted) =
                self.reserve_key_deliveries(&pass.room, peer, &keys, modern, history)
            else {
                continue;
            };
            let capacity = keys.len();
            let live = pass.lifetime.as_ref().map(Arc::clone);
            let target = Target {
                pass,
                peer,
                conn,
                modern,
                history,
                keys: keys.into(),
                admitted: admitted.into(),
                jobs: Vec::with_capacity(capacity),
                live,
                step: Step::Ready,
                all_sent: true,
                legacy_before: None,
                reservations: Vec::new(),
                #[cfg(feature = "test-knobs")]
                generations: Vec::with_capacity(capacity),
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
        if !target.modern {
            if !self.sessions.contains_key(&(room, target.peer)) {
                let Some(selected) = self.select_owned_legacy_session(&room, target.peer).await
                else {
                    target.all_sent = false;
                    return self.enqueue_owned_rekey_target(target).await;
                };
                target.step = Step::Initiate;
                self.dispatch_owned_rekey_native(target, selected.into_initiate_work())
                    .await;
                return None;
            }
            target.legacy_before = self.snapshot_legacy_session((room, target.peer), true);
            let mut first = true;
            while let (Some(key), Some(admission)) =
                (target.keys.pop_front(), target.admitted.pop_front())
            {
                let Some((frames, hello, session)) =
                    self.frame_owned_legacy_key(room, target.peer, &key, first)
                else {
                    target.all_sent = false;
                    break;
                };
                first = false;
                let opening = frames
                    .first()
                    .filter(|_| session.is_none())
                    .map(|frame| crate::hash::sha256(frame));
                #[cfg(feature = "test-knobs")]
                target.generations.push(key.body.chain_id);
                target.jobs.push((
                    admission.queue,
                    PairwiseJob {
                        conn: Arc::clone(&target.conn),
                        frames: frames.into_iter().map(Vec::into_boxed_slice).collect(),
                        channel_id: room,
                        after: AfterWrite::Key {
                            chain_id: key.body.chain_id,
                            opening,
                            hello,
                            session,
                            history: target.history,
                            epoch: target.pass.attachment,
                        },
                        credit: admission.job,
                    },
                ));
            }
            return self.enqueue_owned_rekey_target(target).await;
        }
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
                #[cfg(feature = "test-knobs")]
                target.generations.push(key.body.chain_id);
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
                            epoch: target.pass.attachment,
                        },
                        credit: admission.job,
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
            history: self.trust.history(&target.peer),
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
                Step::Initiate,
                Saved::Packages(package_save::Saved::Initiated {
                    initiated,
                    reservation,
                }),
            ) => {
                if !self.install_owned_legacy_session(room, target.peer, initiated, reservation) {
                    target.all_sent = false;
                }
            }
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
                if let Some(prekey) = prekey {
                    target.reservations.push(prekey);
                }
                if let Some(prekey) = frame.one_time_prekey {
                    self.refused_otps.note(target.peer, prekey);
                }
                let bytes = frame.frame.into_boxed_slice();
                self.deliveries.insert(
                    (room, target.peer, generation),
                    Delivery {
                        frame: bytes.clone(),
                        one_time_prekey: frame.one_time_prekey,
                        key: key_ref,
                        reservation,
                        opening: frame.opening,
                    },
                );
                self.key_left(&room, target.peer);
                #[cfg(feature = "test-knobs")]
                target.generations.push(generation);
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
                            epoch: target.pass.attachment,
                        },
                        credit,
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

    async fn enqueue_owned_rekey_target(&mut self, mut target: Target) -> Option<Pass> {
        if !target.all_sent {
            target.keys.clear();
            target.admitted.clear();
        }
        let room = target.pass.room;
        let pair = (room, target.peer);
        let watched = target.jobs.len() as u32;
        #[cfg(feature = "test-knobs")]
        let held_for_proof = {
            let live = target.pass.instance.lock().await.sender_generation();
            self.hold_rekey_enqueue_for_proof(
                room,
                target.peer,
                !target.modern,
                target.all_sent,
                live,
                &target.generations,
            )
            .await
        };
        for _ in 0..watched {
            self.key_in_flight(room, target.peer);
        }
        if target.history && watched != 0 {
            self.history_in_flight
                .insert(pair, (watched, !target.all_sent));
        }
        let jobs = std::mem::take(&mut target.jobs);
        let hello = jobs
            .iter()
            .any(|(_, job)| matches!(&job.after, AfterWrite::Key { hello: true, .. }));
        #[cfg(feature = "test-knobs")]
        let bypass = crate::node::computer::fx28_mutant("stale-rekey-authority");
        #[cfg(not(feature = "test-knobs"))]
        let bypass = false;
        let published = if bypass || target.live.is_some() {
            for (queue, job) in jobs {
                queue.send(job);
            }
            true
        } else {
            self.with_current_computer_authority(|| {
                for (queue, job) in jobs {
                    queue.send(job);
                }
                true
            })
            .unwrap_or(false)
        };
        if !published {
            self.restore_legacy_session(target.legacy_before.take());
            for _ in 0..watched {
                self.key_landed(room, target.peer);
            }
            if target.history {
                self.history_in_flight.remove(&pair);
            }
        } else if target.all_sent {
            target.pass.delivered += 1;
        }
        if published && hello {
            self.note_owned_legacy_hello(room, target.peer);
        }
        #[cfg(feature = "test-knobs")]
        if held_for_proof {
            self.mark_rekey_authority_decision_for_proof(published);
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
                    Box::pin(self.begin_owned_consent_pass(None, Some(lifetime), None)).await;
                }
            }
            RekeyAfter::Consent { next, reply } => match result {
                Ok(_) => self.finish_owned_consent_tail(*next, reply).await,
                Err(error) => {
                    let room = next.instance.lock().await.channel_id();
                    self.fail_owned_consent(room, error, *next, reply).await;
                }
            },
            RekeyAfter::Packages { next, reply } => {
                let outcome = result
                    .as_ref()
                    .map(|_| Outcome::Done)
                    .unwrap_or_else(|error| Outcome::Failed(fault_of(error)));
                self.resume_package_redelivery(next, result.map(|_| ()))
                    .await;
                if let Some(reply) = reply {
                    let _ = reply.send(outcome);
                }
                self.post_save_wake.notify_one();
            }
        }
    }

    pub(super) fn reject_owned_rekeys(&mut self, target: Target, error: Error) {
        match target.pass.after {
            RekeyAfter::Automatic | RekeyAfter::Settlement { .. } => {}
            RekeyAfter::Consent { next, reply } => {
                self.reject_owned_consent(target.pass.room, error, *next, reply)
            }
            RekeyAfter::Packages { next, reply } => {
                let fault = fault_of(&error);
                self.reject_package_redelivery(next);
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(fault));
                }
                self.post_save_wake.notify_one();
            }
        }
    }
}

pub(super) fn retire(target: Target, error: Error) {
    match target.pass.after {
        RekeyAfter::Automatic | RekeyAfter::Settlement { .. } => {}
        RekeyAfter::Consent { next, reply } => super::retire_detached(Err(error), *next, reply),
        RekeyAfter::Packages { reply, .. } => {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(fault_of(&error)));
            }
        }
    }
}
