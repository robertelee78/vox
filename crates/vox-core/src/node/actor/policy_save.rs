//! Node-global native policy work. One retained owner uses the existing post-save wake;
//! there is no fake room id, second command queue, timer or result-channel credit dependency.
use super::trust_save::{
    Lifetime, Next, Policy, PolicyCompleted, PolicyContinuation, PolicyResume, PolicyRoom,
    Reconcile, ReconcileAction, ReconcileScope, TrustCompletion, TrustContinuation, TrustResume,
};
use super::*;
use crate::node::channel::pending_trust::{TrustSaved, TrustWrite};
use crate::node::store::Store;

mod grant;
pub(super) use grant::{GrantSource, GrantTurn};
mod headless;

type Reply = Option<oneshot::Sender<Outcome>>;
struct Returned {
    continuation: PolicyContinuation,
    completed: crate::error::Result<PolicyCompleted>,
    rooms: Vec<PolicyRoom>,
}
pub(super) struct NativePending {
    store: Arc<Store>,
    epoch: u64,
    owner: Arc<()>,
    instances: Vec<(Digest32, SharedChannel)>,
    result: Arc<std::sync::Mutex<Option<Returned>>>,
    task: tokio::task::JoinHandle<()>,
    reply: Reply,
}

pub(super) enum Pending {
    Native(NativePending),
    TrustProgress {
        room: Digest32,
        continuation: TrustContinuation,
        reply: Reply,
    },
    ManagedTrust(ManagedWaiting),
    ManagedDrive(ManagedDrive),
    GrantMarks(grant::GrantWaiting),
    GrantDelivery(grant::GrantDelivery),
    Leave(leave_save::Pending),
    Headless(headless::HeadlessPending),
    Construction(construction_save::Pending),
    PeerBook(peer_book_save::Pending),
}

pub(super) struct ManagedWaiting {
    receiver: oneshot::Receiver<crate::error::Result<ManagedNotice>>,
    reply: oneshot::Sender<crate::error::Result<()>>,
}

pub(super) struct ManagedReady {
    lifetime: Lifetime,
    guard: computer::ComputerPolicyGuard,
    rooms: Vec<PolicyRoom>,
    revision: u64,
    expired: bool,
}

enum ManagedNotice {
    Ready(ManagedReady),
    Progress {
        turn: ManagedTurn,
        receiver: oneshot::Receiver<crate::error::Result<ManagedNotice>>,
    },
}

enum ManagedRoomStage {
    Marks,
    Reconcile(Reconcile),
}
pub(super) struct ManagedTurn {
    pub(super) lifetime: Lifetime,
    pub(super) rooms: Vec<PolicyRoom>,
    pub(super) cursor: usize,
    guard: computer::ComputerPolicyGuard,
    revision: u64,
    expired: bool,
    stage: ManagedRoomStage,
    terminal: oneshot::Sender<crate::error::Result<ManagedNotice>>,
}

enum DriveStage {
    Begin,
    Packages {
        cursor: usize,
        result: Option<oneshot::Receiver<Outcome>>,
    },
    Consents(oneshot::Receiver<crate::error::Result<()>>),
    Private {
        cursor: usize,
        result: Option<oneshot::Receiver<Outcome>>,
    },
}
pub(super) struct ManagedDrive {
    ready: ManagedReady,
    stage: DriveStage,
    reply: oneshot::Sender<crate::error::Result<()>>,
}

impl Pending {
    pub(super) async fn retire(self) {
        match self {
            Self::Native(pending) => pending.retire().await,
            Self::TrustProgress {
                room,
                continuation,
                reply,
            } => {
                retire_detached(
                    room,
                    Err(Error::Profile("trust continuation retired")),
                    continuation,
                    reply,
                )
                .await
            }
            Self::ManagedTrust(mut pending) => {
                match (&mut pending.receiver).await {
                    Ok(Ok(ManagedNotice::Ready(ready))) => release_rooms(&ready.rooms, true).await,
                    Ok(Ok(ManagedNotice::Progress { turn, .. })) => {
                        release_rooms(&turn.rooms, true).await
                    }
                    _ => {}
                }
                let _ = pending
                    .reply
                    .send(Err(Error::Profile("managed policy continuation retired")));
            }
            Self::ManagedDrive(pending) => {
                release_rooms(&pending.ready.rooms, true).await;
                let _ = pending
                    .reply
                    .send(Err(Error::Profile("managed policy continuation retired")));
            }
            Self::GrantMarks(pending) => pending.retire().await,
            Self::GrantDelivery(pending) => pending.retire().await,
            Self::Leave(pending) => pending.retire().await,
            Self::Headless(pending) => pending.retire().await,
            Self::Construction(pending) => pending.retire().await,
            Self::PeerBook(pending) => pending.retire().await,
        }
    }
}

fn outcome(result: &crate::error::Result<maintenance_save::Saved>) -> Outcome {
    match result {
        Ok(maintenance_save::Saved::Unavailable) => Outcome::Failed(Fault::RoomChangePending),
        Ok(_) => Outcome::Done,
        Err(error) => Outcome::Failed(fault_of(error)),
    }
}

async fn release_rooms(rooms: &[PolicyRoom], poison: bool) {
    for room in rooms {
        let mut channel = room.instance.lock().await;
        if poison {
            channel.poison(&Error::Profile(
                "trust withdrawal is incomplete; reopen this room",
            ));
        }
        channel.release_pending_text(&room.owner, poison);
    }
}

impl NativePending {
    /// Lifecycle retirement waits for the actual native terminal cell. It cannot cancel a
    /// transaction or forget its exact room ownership while the Store still uses secret keys.
    pub(super) async fn retire(self) {
        let _ = self.task.await;
        let returned = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(returned) = returned {
            finish_detached_policy(returned, self.reply).await;
        } else {
            for (_, instance) in &self.instances {
                instance
                    .lock()
                    .await
                    .release_pending_text(&self.owner, true);
            }
            if let Some(reply) = self.reply {
                let _ = reply.send(Outcome::Failed(Fault::Internal));
            }
        }
    }
}

fn finish_rejected_policy(continuation: PolicyContinuation, error: Error, reply: Reply) {
    match continuation {
        PolicyContinuation::Blacklist {
            reply: blacklist, ..
        } => {
            let _ = blacklist.send(Err(error));
        }
        PolicyContinuation::Managed {
            work,
            reservations,
            lifetime,
        } => {
            tokio::spawn(async move {
                release_rooms(&reservations, true).await;
                let _ = work.reply.send(Err(error));
                drop(lifetime);
            });
        }
        _ => {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(fault_of(&error)));
            }
        }
    }
}

impl Node {
    pub(super) fn policy_save_pending(&self) -> bool {
        self.pending_policy.is_some()
            || self.own_key_untrust_pending.is_some()
            || self.own_key_computer_flight.is_some()
            || !self.own_key_computer_pending.is_empty()
    }

    pub(super) async fn begin_pending_policy(
        &mut self,
        mut policy: Policy,
        mut continuation: PolicyContinuation,
        reply: Reply,
    ) -> bool {
        if self.pending_policy.is_some() {
            finish_rejected_policy(
                continuation,
                Error::Profile("a node policy save is pending"),
                reply,
            );
            return false;
        }
        if continuation.lifetime().save.is_none() {
            let Some(profile) = self
                .profile
                .as_ref()
                .filter(|profile| profile.is_unlocked())
            else {
                finish_rejected_policy(continuation, Error::AtRestLocked, reply);
                return false;
            };
            let Some(authority) = self.computer_authority() else {
                finish_rejected_policy(
                    continuation,
                    Error::Profile("current computer trust is unavailable"),
                    reply,
                );
                return false;
            };
            let signer = match profile.signer_arc() {
                Ok(signer) => signer,
                Err(error) => {
                    finish_rejected_policy(continuation, error, reply);
                    return false;
                }
            };
            let secret = match self.secret_work.clone().try_read_owned() {
                Ok(secret) => Arc::new(secret),
                Err(_) => {
                    finish_rejected_policy(continuation, Error::AtRestLocked, reply);
                    return false;
                }
            };
            continuation.lifetime_mut().save = Some(Arc::new(maintenance_save::Lifetime {
                authority,
                publication: None,
                secret,
                store: profile.store_handle(),
                signer,
                exclusive: match &policy {
                    Policy::Managed(native) => Some(Arc::clone(&native.transition)),
                    _ => None,
                },
            }));
        }
        let Some(save) = continuation.lifetime().save.as_ref().map(Arc::clone) else {
            finish_rejected_policy(continuation, Error::AtRestLocked, reply);
            return false;
        };
        let store = Arc::clone(&save.store);
        let epoch = self.delivery_epoch;
        let attachment = self.pairwise_epoch.subscribe();
        let grant_decision =
            matches!(&policy, Policy::Grant { change, .. } if change.needs_decision(&self.trust));
        let reserves_rooms =
            matches!(&policy, Policy::Untrust { .. } | Policy::Managed(_)) || grant_decision;
        let managed = matches!(&policy, Policy::Managed(_));
        let needs_publication = matches!(&policy, Policy::Untrust { .. } | Policy::Grant { .. });
        let require_append = matches!(&policy, Policy::Untrust { .. });
        let choice_target = match &policy {
            Policy::Untrust { target } => Some(*target),
            Policy::Grant { change, .. } if change.individual_choice() => Some(change.target()),
            _ => None,
        };
        let instances: Vec<_> = if reserves_rooms
            || matches!(&policy, Policy::Grant { change, .. }
            if !matches!(change, trust_save::GrantChange::Capability { .. }))
        {
            self.channels
                .iter()
                .map(|(room, instance)| (*room, Arc::clone(instance)))
                .collect()
        } else {
            Vec::new()
        };
        let worker_instances = instances.clone();
        let owner = Arc::new(());
        let worker_owner = Arc::clone(&owner);
        let computer = self.computer.clone();
        let node = self.profile.as_ref().map(Profile::fingerprint);
        let result = Arc::new(std::sync::Mutex::new(None));
        let output = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        let task = tokio::spawn(async move {
            // A continued operation reuses its original reader or exclusive transition. Never
            // reacquire while holding either: a pending writer would deadlock that old reader.
            let save = if needs_publication
                && save.publication.is_none()
                && save.exclusive.is_none()
                && !managed
                && continuation.lifetime().transition.is_none()
            {
                match save.authority.acquire_publication().await {
                    Some(publication) => Arc::new(maintenance_save::Lifetime {
                        authority: save.authority.clone(),
                        publication: Some(publication),
                        exclusive: save.exclusive.as_ref().map(Arc::clone),
                        secret: Arc::clone(&save.secret),
                        store: Arc::clone(&save.store),
                        signer: Arc::clone(&save.signer),
                    }),
                    None => {
                        *output
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Returned {
                            continuation,
                            completed: Err(Error::Profile(
                                "computer policy changed before policy admission",
                            )),
                            rooms: Vec::new(),
                        });
                        wake.notify_one();
                        return;
                    }
                }
            } else {
                save
            };
            continuation.lifetime_mut().save = Some(Arc::clone(&save));
            let saved = tokio::task::spawn_blocking(move || {
                let mut rooms = match &mut continuation {
                    PolicyContinuation::Managed { reservations, .. } => {
                        std::mem::take(reservations)
                    }
                    _ => Vec::new(),
                };
                let completed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if *attachment.borrow() != epoch {
                        return Err(Error::AtRestLocked);
                    }
                    if let Some(target) = choice_target {
                        if let Some(computer) =
                            computer.as_ref().filter(|computer| computer.grouped())
                        {
                            let journal =
                                continuation
                                    .lifetime()
                                    .journal
                                    .as_ref()
                                    .ok_or(Error::Profile(
                                        "trust command has no original Computer journal admission",
                                    ))?;
                            computer.individual_choice(
                                node.ok_or(Error::AtRestLocked)?,
                                target,
                                journal,
                            )?;
                        }
                    }
                    if reserves_rooms && rooms.is_empty() {
                        rooms = trust_save::reserve_policy_rooms(
                            worker_instances,
                            &save.store,
                            worker_owner,
                            require_append,
                            grant_decision || require_append,
                        )?;
                    }
                    if let Policy::Grant { floor, .. } = &mut policy {
                        for room in &rooms {
                            *floor = (*floor).max(room.instance.blocking_lock().newest_mint_seq());
                        }
                    }
                    Ok(policy.run(&save.store, save.signer.as_ref()))
                }))
                .unwrap_or_else(|_| Err(Error::Profile("native policy worker stopped")));
                Returned {
                    continuation,
                    completed,
                    rooms,
                }
            })
            .await;
            if let Ok(returned) = saved {
                *output
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(returned);
            }
            wake.notify_one();
        });
        self.pending_policy = Some(Pending::Native(NativePending {
            store,
            epoch,
            owner,
            instances,
            result,
            task,
            reply,
        }));
        true
    }

    pub(super) async fn complete_pending_policies(&mut self) {
        let Some(pending) = self.pending_policy.take() else {
            return;
        };
        let pending = match pending {
            Pending::Native(pending) => pending,
            Pending::TrustProgress {
                room,
                continuation,
                reply,
            } => {
                let instance = Arc::clone(continuation.instance());
                let Some(save) = continuation.lifetime().save.as_ref().map(Arc::clone) else {
                    self.fail_trust_continuation(continuation, Error::AtRestLocked, reply)
                        .await;
                    return;
                };
                let channel = instance.lock().await;
                let result = self.continue_owned_trust(room, &channel, continuation, &save.store);
                drop(channel);
                match result {
                    Ok(resume) => self.schedule_trust_resume(resume, reply).await,
                    Err(failed) => {
                        let (continuation, error) = *failed;
                        self.fail_trust_continuation(continuation, error, reply)
                            .await
                    }
                }
                return;
            }
            Pending::ManagedTrust(pending) => {
                self.poll_managed_trust(pending).await;
                return;
            }
            Pending::ManagedDrive(pending) => {
                self.poll_managed_drive(pending).await;
                return;
            }
            Pending::GrantMarks(pending) => {
                self.poll_grant_marks(pending).await;
                return;
            }
            Pending::GrantDelivery(pending) => {
                self.poll_grant_delivery(pending).await;
                return;
            }
            Pending::Leave(pending) => {
                self.complete_leave_save(pending).await;
                return;
            }
            Pending::Headless(pending) => {
                self.complete_headless_policy(pending).await;
                return;
            }
            Pending::Construction(pending) => {
                self.complete_construction(pending).await;
                return;
            }
            Pending::PeerBook(pending) => {
                self.complete_peer_book_save(pending);
                return;
            }
        };
        let returned = pending
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(returned) = returned else {
            // An outer worker stop is terminal only after the real task ended; it is not an
            // admission failure or successful policy receipt.
            if pending.task.is_finished() {
                pending.retire().await;
            } else {
                self.pending_policy = Some(Pending::Native(pending));
            }
            return;
        };
        // The global commit belongs to this identity/store, not to one room's lifetime. A
        // concurrently retired room must not leave live authorization behind a durable denial.
        // Each subsequent room capsule still checks its original exact instance before install.
        let current = pending.epoch == self.delivery_epoch
            && self
                .profile
                .as_ref()
                .is_some_and(|profile| Arc::ptr_eq(&profile.store_handle(), &pending.store));
        let _ = pending.task.await;
        if !current {
            finish_detached_policy(returned, pending.reply).await;
            return;
        }
        let resume = match returned.completed {
            Ok(completed) => {
                self.finish_owned_policy(completed, returned.continuation, returned.rooms)
            }
            Err(error) => PolicyResume::Failed {
                continuation: returned.continuation,
                error,
                rooms: returned.rooms,
            },
        };
        self.resume_policy_result(resume, pending.reply).await;
    }

    async fn resume_policy_result(&mut self, resume: PolicyResume, reply: Reply) {
        match resume {
            PolicyResume::Trust(resume) => self.schedule_trust_resume(resume, reply).await,
            PolicyResume::Blacklist => {}
            PolicyResume::LocalTrust {
                lifetime,
                fingerprint,
                name,
                capability,
            } => {
                self.begin_owned_local_grant(fingerprint, name, capability, lifetime, reply)
                    .await
            }
            PolicyResume::Grant {
                lifetime,
                source,
                grant,
                rooms,
            } => {
                self.begin_grant_marks(lifetime, source, grant, rooms, reply)
                    .await
            }
            PolicyResume::GrantFinished {
                lifetime,
                source,
                grant,
            } => {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Done);
                }
                drop((lifetime, source, grant));
            }
            PolicyResume::Dismissed { lifetime, result } => {
                if matches!(&result, Ok(true)) {
                    self.publish().await;
                }
                if let Some(reply) = reply {
                    let _ = reply.send(match result {
                        Ok(_) => Outcome::Done,
                        Err(error) => Outcome::Failed(fault_of(&error)),
                    });
                }
                drop(lifetime);
            }
            PolicyResume::FinishedUntrust {
                lifetime,
                operation,
                dismissed,
            } => {
                if dismissed {
                    self.publish().await;
                }
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Done);
                }
                drop((lifetime, operation));
            }
            PolicyResume::Managed {
                lifetime,
                work,
                result,
                rooms,
                revision,
                expired,
            } => {
                self.begin_managed_trust_continuation(
                    lifetime, work, result, rooms, revision, expired,
                )
                .await;
            }
            PolicyResume::Failed {
                continuation,
                error,
                rooms,
            } => {
                release_rooms(&rooms, false).await;
                finish_rejected_policy(continuation, error, reply);
            }
        }
    }

    pub(super) async fn resume_owned_trust(
        &mut self,
        room: Digest32,
        result: crate::error::Result<maintenance_save::Saved>,
        continuation: TrustContinuation,
        reply: Reply,
    ) {
        if let TrustContinuation::Managed(turn) = continuation {
            self.resume_managed_trust(room, result, turn, reply).await;
            return;
        }
        if let TrustContinuation::Grant(turn) = continuation {
            self.resume_grant_marks(result, turn).await;
            return;
        }
        let saved = result.and_then(|saved| match saved {
            maintenance_save::Saved::Trust(saved) => Ok(TrustCompletion::Trust(saved)),
            maintenance_save::Saved::Consent(consent_save::Effect::Consent(saved)) => {
                Ok(TrustCompletion::Withdraw(saved))
            }
            _ => Err(Error::Profile("unexpected trust save completion")),
        });
        let instance = Arc::clone(continuation.instance());
        let save = continuation.lifetime().save.as_ref().map(Arc::clone);
        let Some(save) = save else {
            self.reject_owned_trust(room, Error::AtRestLocked, continuation, reply);
            return;
        };
        let channel = instance.lock().await;
        let resumed = self.finish_owned_trust(room, &channel, continuation, saved, &save.store);
        drop(channel);
        match resumed {
            Ok(resume) => self.schedule_trust_resume(resume, reply).await,
            Err(failed) => {
                let (continuation, error) = *failed;
                self.fail_trust_continuation(continuation, error, reply)
                    .await
            }
        }
    }

    async fn schedule_trust_resume(&mut self, resume: TrustResume, reply: Reply) {
        match resume {
            TrustResume::Next {
                room,
                work,
                continuation,
            } => {
                let work = match work {
                    Next::Trust(work) => maintenance_save::Work::Trust(work),
                    Next::Withdraw { target } => {
                        maintenance_save::Work::Consent(consent_save::Work::Withdraw { target })
                    }
                };
                self.begin_pending_maintenance(
                    room,
                    work,
                    maintenance_save::Continuation::Trust(continuation),
                    reply,
                )
                .await;
            }
            TrustResume::Progress { room, continuation } => {
                self.pending_policy = Some(Pending::TrustProgress {
                    room,
                    continuation,
                    reply,
                });
                // This is an actual bounded-page progress edge, serviced by the SAME retained
                // policy book on the common wake. No fake write, polling timer or second queue.
                self.post_save_wake.notify_one();
            }
            TrustResume::Finished { continuation } => {
                self.finish_trust_continuation(continuation, reply).await
            }
        }
    }

    async fn finish_trust_continuation(&mut self, continuation: TrustContinuation, reply: Reply) {
        match continuation {
            TrustContinuation::Untrust {
                mut lifetime,
                operation,
                ..
            } => {
                for (room, target, generation) in &operation.completed {
                    self.note_completed_untrust(*room, *target, *generation);
                }
                lifetime.own_transitions.clear();
                self.refresh_reachers().await;
                self.publish().await;
                let bases = self
                    .view_tx
                    .borrow()
                    .open_channels
                    .iter()
                    .flat_map(|room| {
                        room.offer_bases
                            .iter()
                            .filter(|basis| basis.member == operation.target)
                            .map(|basis| (room.channel_id, *basis))
                    })
                    .collect();
                let decision = operation.alias.as_ref().map(|alias| {
                    (
                        self.decisions.clone(),
                        (self.millis_clock)(),
                        crate::node::decisions::Decision {
                            asked: "to remove a member from the keyring",
                            by: operation.target,
                            alias: Some(alias.clone()),
                            decided: crate::node::decisions::Decided::Untrusted,
                            why: "this node's person removed them from the keyring: they read \
                              nothing new from it and reach none of its services"
                                .to_owned(),
                            room: None,
                        },
                    )
                });
                self.begin_pending_policy(
                    Policy::DismissOffers { bases, decision },
                    PolicyContinuation::FinishUntrust {
                        lifetime,
                        operation,
                    },
                    reply,
                )
                .await;
            }
            other => {
                self.fail_trust_continuation(
                    other,
                    Error::Profile("unexpected terminal trust continuation"),
                    reply,
                )
                .await
            }
        }
    }

    async fn fail_trust_continuation(
        &mut self,
        continuation: TrustContinuation,
        error: Error,
        reply: Reply,
    ) {
        match continuation {
            TrustContinuation::Untrust {
                lifetime,
                operation,
                ..
            } => {
                release_rooms(&operation.rooms, true).await;
                for (room, target, generation) in &operation.completed {
                    self.note_completed_untrust(*room, *target, *generation);
                }
                self.refresh_reachers().await;
                self.publish().await;
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(fault_of(&error)));
                }
                drop((lifetime, operation, error));
            }
            other => {
                let room = other.instance().lock().await.channel_id();
                retire_detached(room, Err(error), other, reply).await;
                self.post_save_wake.notify_one();
            }
        }
    }

    pub(super) fn reject_owned_trust(
        &mut self,
        room: Digest32,
        error: Error,
        continuation: TrustContinuation,
        reply: Reply,
    ) {
        let result = Err(error);
        // This is finite exact-owner retirement, not a command/result queue. No disk transaction
        // is started, and the original lifetime/pins remain owned until every release finishes.
        let wake = Arc::clone(&self.post_save_wake);
        tokio::spawn(async move {
            retire_detached(room, result, continuation, reply).await;
            wake.notify_one();
        });
    }
    pub(super) async fn retire_owned_trust(
        &mut self,
        room: Digest32,
        result: crate::error::Result<maintenance_save::Saved>,
        continuation: TrustContinuation,
        reply: Reply,
    ) {
        retire_detached(room, result, continuation, reply).await;
        self.post_save_wake.notify_one();
    }
}

pub(super) async fn retire_detached(
    _room: Digest32,
    result: crate::error::Result<maintenance_save::Saved>,
    continuation: TrustContinuation,
    reply: Reply,
) {
    match continuation {
        TrustContinuation::Untrust {
            lifetime,
            operation,
            ..
        } => {
            release_rooms(&operation.rooms, true).await;
            if let Some(reply) = reply {
                // A real committed prefix is not an aggregate Untrust completion. Preserve a
                // real failure; an interrupted successful prefix retains honest room debt.
                let answer = match &result {
                    Err(_) => outcome(&result),
                    Ok(_) => Outcome::Failed(Fault::TrustRemovalIncomplete),
                };
                let _ = reply.send(answer);
            }
            drop((lifetime, operation));
        }
        TrustContinuation::Managed(turn) => {
            release_rooms(&turn.rooms, true).await;
            let error = result.err().unwrap_or(Error::Profile(
                "managed trust committed a prefix before retirement",
            ));
            let _ = turn.terminal.send(Err(error));
            drop(turn.lifetime);
        }
        TrustContinuation::Grant(turn) => {
            turn.retire(result.err().unwrap_or(Error::Profile(
                "trust decision committed a prefix before retirement",
            )))
            .await;
        }
    }
}

impl ManagedTurn {
    pub(super) fn policy_reservation_owner(&self) -> Option<Arc<()>> {
        matches!(self.stage, ManagedRoomStage::Marks)
            .then(|| Arc::clone(&self.rooms[self.cursor].owner))
    }
}

impl Node {
    async fn begin_managed_trust_continuation(
        &mut self,
        mut lifetime: Lifetime,
        mut work: computer::OwnKeyPolicyWork,
        result: crate::error::Result<computer::KeyringApplication>,
        rooms: Vec<PolicyRoom>,
        revision: u64,
        expired: bool,
    ) {
        let application = match result {
            Ok(application) => application,
            Err(error) => {
                release_rooms(&rooms, true).await;
                let _ = work.reply.send(Err(error));
                return;
            }
        };
        if !application.settled {
            // This is the original loop's actual Reconcile edge, under its SAME owner/guard and
            // transition, not a timer, new deadline or acknowledgement of admission.
            let next = (|| -> crate::error::Result<trust_save::Managed> {
                work.guard.active(self.computer.as_ref())?;
                let computer = self.computer.clone().ok_or(Error::AtRestLocked)?;
                let profile = self.profile.as_ref().ok_or(Error::AtRestLocked)?;
                let node = profile.fingerprint();
                let plan = computer
                    .plan(node)?
                    .ok_or(Error::ComputerPolicySuperseded)?;
                let removed: Vec<_> = plan
                    .denied
                    .iter()
                    .copied()
                    .filter(|peer| self.trust.is_trusted(peer))
                    .collect();
                if removed
                    .iter()
                    .any(|peer| work.targets.binary_search(peer).is_err())
                {
                    return Err(Error::OwnKeyWriterDrainRequired(removed));
                }
                let aliases = plan
                    .grants
                    .iter()
                    .map(|(peer, _, _)| peer)
                    .chain(plan.denied.iter())
                    .filter_map(|peer| {
                        self.trust
                            .petname(peer)
                            .map(|alias| (*peer, alias.to_owned()))
                    })
                    .collect();
                let transition = lifetime.transition.take().ok_or(Error::Profile(
                    "managed policy lost its original transition",
                ))?;
                let node_name = self
                    .paths
                    .profile_dir
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(Error::Profile("managed node name is unreadable"))?
                    .to_owned();
                Ok(trust_save::Managed {
                    computer,
                    guard: work.guard.clone(),
                    transition,
                    plan,
                    aliases,
                    floor: 0,
                    node,
                    node_name,
                })
            })();
            match next {
                Ok(mut next) => {
                    for room in &rooms {
                        next.floor = next.floor.max(room.instance.lock().await.newest_mint_seq());
                    }
                    self.begin_pending_policy(
                        Policy::Managed(next),
                        PolicyContinuation::Managed {
                            lifetime,
                            work,
                            reservations: rooms,
                        },
                        None,
                    )
                    .await;
                }
                Err(Error::OwnKeyWriterDrainRequired(targets)) => {
                    release_rooms(&rooms, false).await;
                    work.targets = targets;
                    self.own_key_computer_pending.push_front(work);
                    self.post_save_wake.notify_one();
                }
                Err(error) => {
                    release_rooms(&rooms, true).await;
                    let _ = work.reply.send(Err(error));
                }
            }
            return;
        }
        if let Err(error) = work.guard.active(self.computer.as_ref()) {
            release_rooms(&rooms, true).await;
            let _ = work.reply.send(Err(error));
            return;
        }
        self.owe_private_support_in_open_rooms().await;
        let (terminal, receiver) = oneshot::channel();
        let guard = work.guard;
        self.pending_policy = Some(Pending::ManagedTrust(ManagedWaiting {
            receiver,
            reply: work.reply,
        }));
        if rooms.is_empty() {
            let _ = terminal.send(Ok(ManagedNotice::Ready(ManagedReady {
                lifetime,
                guard,
                rooms,
                revision,
                expired,
            })));
            self.post_save_wake.notify_one();
            return;
        }
        let room = rooms[0].room;
        let turn = ManagedTurn {
            lifetime,
            rooms,
            cursor: 0,
            guard,
            revision,
            expired,
            stage: ManagedRoomStage::Marks,
            terminal,
        };
        // Mark this exact room BEFORE any withdrawal rotates its sender. All other rooms still
        // own their original global reservation, so their decision positions cannot advance.
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Trust(trust_save::Work(TrustWrite::MarkDecisions)),
            maintenance_save::Continuation::Trust(TrustContinuation::Managed(turn)),
            None,
        )
        .await;
    }

    async fn resume_managed_trust(
        &mut self,
        room: Digest32,
        result: crate::error::Result<maintenance_save::Saved>,
        mut turn: ManagedTurn,
        _reply: Reply,
    ) {
        let saved = match result {
            Ok(saved) => saved,
            Err(error) => {
                self.fail_managed_turn(turn, error).await;
                return;
            }
        };
        let applied = match (&mut turn.stage, saved) {
            (ManagedRoomStage::Marks, maintenance_save::Saved::Trust(TrustSaved::Marked)) => {
                turn.stage = ManagedRoomStage::Reconcile(Reconcile::new(
                    self.trust.trusted(),
                    ReconcileScope::Preparation,
                ));
                Ok(())
            }
            (ManagedRoomStage::Reconcile(state), maintenance_save::Saved::Trust(saved)) => {
                state.saved(&saved)
            }
            (
                ManagedRoomStage::Reconcile(state),
                maintenance_save::Saved::Consent(consent_save::Effect::Consent(saved)),
            ) => {
                let result = state.withdrawn(&saved);
                if result.is_ok() {
                    if let crate::node::channel::pending_text::consent::ConsentSaved::Withdrawn(
                        Some(revocation),
                    ) = saved
                    {
                        self.note_completed_untrust(
                            room,
                            revocation.body.target_id,
                            revocation.body.new_chain_id,
                        );
                    }
                }
                result
            }
            _ => Err(Error::Profile("unexpected managed trust completion")),
        };
        if let Err(error) = applied {
            self.fail_managed_turn(turn, error).await;
            return;
        }
        self.continue_managed_trust(turn).await;
    }

    async fn continue_managed_trust(&mut self, mut turn: ManagedTurn) {
        if let Err(error) = turn.guard.active(self.computer.as_ref()) {
            self.fail_managed_turn(turn, error).await;
            return;
        }
        let Some(save) = turn.lifetime.save.as_ref().map(Arc::clone) else {
            self.fail_managed_turn(turn, Error::AtRestLocked).await;
            return;
        };
        let room = turn.rooms[turn.cursor].room;
        let action = match &mut turn.stage {
            ManagedRoomStage::Marks => Ok(ReconcileAction::Trust(trust_save::Work(
                TrustWrite::MarkDecisions,
            ))),
            ManagedRoomStage::Reconcile(state) => {
                let instance = Arc::clone(&turn.rooms[turn.cursor].instance);
                let channel = instance.lock().await;
                state.action(&channel, &save.store)
            }
        };
        match action {
            Ok(ReconcileAction::Trust(work)) => {
                self.begin_pending_maintenance(
                    room,
                    maintenance_save::Work::Trust(work),
                    maintenance_save::Continuation::Trust(TrustContinuation::Managed(turn)),
                    None,
                )
                .await;
            }
            Ok(ReconcileAction::Withdraw { target }) => {
                self.begin_pending_maintenance(
                    room,
                    maintenance_save::Work::Consent(consent_save::Work::Withdraw { target }),
                    maintenance_save::Continuation::Trust(TrustContinuation::Managed(turn)),
                    None,
                )
                .await;
            }
            Ok(ReconcileAction::Progress) => {
                let (sender, receiver) = oneshot::channel();
                let terminal = std::mem::replace(&mut turn.terminal, sender);
                let _ = terminal.send(Ok(ManagedNotice::Progress { turn, receiver }));
                self.post_save_wake.notify_one();
            }
            Ok(ReconcileAction::Complete) => {
                turn.cursor += 1;
                if turn.cursor == turn.rooms.len() {
                    let mut lifetime = turn.lifetime;
                    lifetime.own_transitions.clear();
                    let _ = turn.terminal.send(Ok(ManagedNotice::Ready(ManagedReady {
                        lifetime,
                        guard: turn.guard,
                        rooms: turn.rooms,
                        revision: turn.revision,
                        expired: turn.expired,
                    })));
                    self.post_save_wake.notify_one();
                } else {
                    turn.stage = ManagedRoomStage::Marks;
                    let room = turn.rooms[turn.cursor].room;
                    self.begin_pending_maintenance(
                        room,
                        maintenance_save::Work::Trust(trust_save::Work(TrustWrite::MarkDecisions)),
                        maintenance_save::Continuation::Trust(TrustContinuation::Managed(turn)),
                        None,
                    )
                    .await;
                }
            }
            Err(error) => self.fail_managed_turn(turn, error).await,
        }
    }

    async fn fail_managed_turn(&mut self, turn: ManagedTurn, error: Error) {
        release_rooms(&turn.rooms, true).await;
        let _ = turn.terminal.send(Err(error));
        drop(turn.lifetime);
        self.post_save_wake.notify_one();
    }

    async fn poll_managed_trust(&mut self, mut pending: ManagedWaiting) {
        match pending.receiver.try_recv() {
            Ok(Ok(ManagedNotice::Ready(ready))) => {
                self.poll_managed_drive(ManagedDrive {
                    ready,
                    stage: DriveStage::Begin,
                    reply: pending.reply,
                })
                .await;
            }
            Ok(Ok(ManagedNotice::Progress { turn, receiver })) => {
                self.pending_policy = Some(Pending::ManagedTrust(ManagedWaiting {
                    receiver,
                    reply: pending.reply,
                }));
                self.continue_managed_trust(turn).await;
            }
            Ok(Err(error)) => {
                let _ = pending.reply.send(Err(error));
            }
            Err(oneshot::error::TryRecvError::Empty) => {
                self.pending_policy = Some(Pending::ManagedTrust(pending))
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                let _ = pending.reply.send(Err(Error::Profile(
                    "managed trust completion owner stopped",
                )));
            }
        }
    }

    async fn poll_managed_drive(&mut self, mut pending: ManagedDrive) {
        let Some(save) = pending.ready.lifetime.save.as_ref().map(Arc::clone) else {
            release_rooms(&pending.ready.rooms, true).await;
            let _ = pending.reply.send(Err(Error::AtRestLocked));
            return;
        };
        let next = match &mut pending.stage {
            DriveStage::Begin => {
                if let Err(error) = pending.ready.guard.active(self.computer.as_ref()) {
                    let _ = pending.reply.send(Err(error));
                    return;
                }
                if pending.ready.expired {
                    self.publish().await;
                    self.finish_managed_policy(pending).await;
                    return;
                }
                if let Err(error) = self.refresh_reachers_guarded(&pending.ready.guard).await {
                    let _ = pending.reply.send(Err(error));
                    return;
                }
                for prepared in self.preparing_rooms.values_mut() {
                    prepared.channel.lock().await.release_held_packages();
                }
                pending.stage = DriveStage::Packages {
                    cursor: 0,
                    result: None,
                };
                true
            }
            DriveStage::Packages { cursor, result } => {
                if let Some(receiver) = result {
                    match receiver.try_recv() {
                        Ok(Outcome::Done) => {
                            *cursor += 1;
                            *result = None;
                        }
                        Ok(_) => {
                            let _ = pending.reply.send(Err(Error::Profile(
                                "managed key-package continuation failed",
                            )));
                            return;
                        }
                        Err(oneshot::error::TryRecvError::Empty) => {
                            self.pending_policy = Some(Pending::ManagedDrive(pending));
                            return;
                        }
                        Err(oneshot::error::TryRecvError::Closed) => {
                            let _ = pending.reply.send(Err(Error::Profile(
                                "managed key-package completion owner stopped",
                            )));
                            return;
                        }
                    }
                }
                if let Err(error) = pending.ready.guard.active(self.computer.as_ref()) {
                    let _ = pending.reply.send(Err(error));
                    return;
                }
                if *cursor == pending.ready.rooms.len() {
                    let (sender, receiver) = oneshot::channel();
                    self.begin_owned_owed_consents(Arc::clone(&save), sender)
                        .await;
                    pending.stage = DriveStage::Consents(receiver);
                } else {
                    let room = &pending.ready.rooms[*cursor];
                    if !self
                        .channels
                        .get(&room.room)
                        .is_some_and(|current| Arc::ptr_eq(current, &room.instance))
                    {
                        let _ = pending.reply.send(Err(Error::Profile(
                            "managed room changed before key-package continuation",
                        )));
                        return;
                    }
                    room.instance.lock().await.release_held_packages();
                    let (sender, receiver) = oneshot::channel();
                    *result = Some(receiver);
                    self.begin_owned_package_turn(room.room, Some(Arc::clone(&save)), Some(sender))
                        .await;
                }
                false
            }
            DriveStage::Consents(receiver) => {
                match receiver.try_recv() {
                    Ok(Ok(())) => {
                        pending.stage = DriveStage::Private {
                            cursor: 0,
                            result: None,
                        }
                    }
                    Ok(Err(error)) => {
                        let _ = pending.reply.send(Err(error));
                        return;
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {
                        self.pending_policy = Some(Pending::ManagedDrive(pending));
                        return;
                    }
                    Err(oneshot::error::TryRecvError::Closed) => {
                        let _ = pending.reply.send(Err(Error::Profile(
                            "managed consent completion owner stopped",
                        )));
                        return;
                    }
                }
                true
            }
            DriveStage::Private { cursor, result } => {
                if let Some(receiver) = result {
                    match receiver.try_recv() {
                        Ok(Outcome::Done) => {
                            *cursor += 1;
                            *result = None;
                        }
                        Ok(_) => {
                            let _ = pending.reply.send(Err(Error::Profile(
                                "managed private-key continuation failed",
                            )));
                            return;
                        }
                        Err(oneshot::error::TryRecvError::Empty) => {
                            self.pending_policy = Some(Pending::ManagedDrive(pending));
                            return;
                        }
                        Err(oneshot::error::TryRecvError::Closed) => {
                            let _ = pending.reply.send(Err(Error::Profile(
                                "managed private-key completion owner stopped",
                            )));
                            return;
                        }
                    }
                }
                if let Err(error) = pending.ready.guard.active(self.computer.as_ref()) {
                    let _ = pending.reply.send(Err(error));
                    return;
                }
                if *cursor == pending.ready.rooms.len() {
                    self.finish_managed_policy(pending).await;
                    return;
                }
                let room = pending.ready.rooms[*cursor].room;
                let (sender, receiver) = oneshot::channel();
                *result = Some(receiver);
                !self
                    .begin_owned_private_drive(
                        room,
                        Some(pending.ready.guard.clone()),
                        Some(Arc::clone(&save)),
                        Some(sender),
                    )
                    .await
            }
        };
        self.pending_policy = Some(Pending::ManagedDrive(pending));
        // A stage transition or immediate terminal refusal is a real causal edge. Native
        // completions use this SAME wake; no timer or elapsed-time refresh is introduced.
        if next {
            self.post_save_wake.notify_one();
        }
    }

    async fn finish_managed_policy(&mut self, pending: ManagedDrive) {
        let result = pending.ready.guard.active(self.computer.as_ref());
        if result.is_ok() {
            self.computer_expired = pending.ready.expired;
            self.computer_revision
                .store(pending.ready.revision, std::sync::atomic::Ordering::Release);
            self.publish_computer_trust_projection();
            self.publish().await;
            self.governance_work.resume_after_computer_policy();
            self.resume_own_key_interruptions();
            self.resume_own_key_donor_busy();
            self.resume_own_key_policy_waiting();
        }
        let _ = pending.reply.send(result);
        drop(pending.ready);
    }
}

impl Node {
    /// Called from the existing OwnKeyUntrustReady branch AFTER its exact room-set and send-gate
    /// drain check. It consumes the ORIGINAL command, proof, secret lease and journal admission.
    pub(super) async fn begin_owned_untrust(
        &mut self,
        command: NodeCommand,
        reply: oneshot::Sender<Outcome>,
        secret: own_keys::SecretLease,
        journal: Option<crate::node::computer::ComputerJournalWriter>,
        transitions: Vec<crate::node::channel::own_writer_gate::Transition>,
    ) {
        if self.computer_change_refused(&command) {
            let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
            return;
        }
        let (target, proved) = match &command {
            NodeCommand::Untrust { fingerprint } => (*fingerprint, false),
            NodeCommand::Proved { change } => match change.as_ref() {
                NodeCommand::Untrust { fingerprint } => (*fingerprint, true),
                _ => {
                    let _ = reply.send(Outcome::Failed(Fault::Internal));
                    return;
                }
            },
            _ => {
                let _ = reply.send(Outcome::Failed(Fault::Internal));
                return;
            }
        };
        if proved && self.profile.as_ref().is_some_and(Profile::is_unlocked) {
            self.note_passphrase_entered();
        }
        let Some(profile) = self.profile.as_ref() else {
            let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
            return;
        };
        if profile.is_unlocked() && !proved && !self.passphrase_entered_recently() {
            let _ = reply.send(Outcome::Failed(Fault::PassphraseNeeded));
            return;
        }
        let signer = match profile.signer_arc() {
            Ok(signer) => signer,
            Err(error) => {
                let _ = reply.send(Outcome::Failed(fault_of(&error)));
                return;
            }
        };
        if !self.trust.is_trusted(&target) {
            let _ = reply.send(Outcome::Failed(Fault::NotConsented));
            return;
        }
        let Some(authority) = self.computer_authority() else {
            let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
            return;
        };
        let store = profile.store_handle();
        let alias = self.trust.petname(&target).map(str::to_owned);
        let lifetime = Lifetime {
            save: Some(Arc::new(maintenance_save::Lifetime {
                authority,
                publication: None,
                secret,
                store,
                signer,
                exclusive: None,
            })),
            transition: None,
            journal,
            own_transitions: transitions,
        };
        self.begin_pending_policy(
            Policy::Untrust { target },
            PolicyContinuation::Untrust {
                lifetime,
                target,
                alias,
            },
            Some(reply),
        )
        .await;
    }

    pub(super) async fn begin_owned_blacklist(
        &mut self,
        reply: oneshot::Sender<crate::error::Result<Option<BTreeSet<Digest32>>>>,
    ) {
        if self
            .profile
            .as_ref()
            .is_none_or(|profile| !profile.is_unlocked())
        {
            let _ = reply.send(Ok(None));
            return;
        }
        if self.trust.local_history_imported() {
            self.decisions.hold_for_local_trust_import(false);
            let _ = reply.send(Ok(Some(self.trust.local_removals().clone())));
            return;
        }
        self.begin_pending_policy(
            Policy::ImportBlacklist {
                history: self.decisions.clone(),
            },
            PolicyContinuation::Blacklist {
                lifetime: Lifetime {
                    save: None,
                    transition: None,
                    journal: None,
                    own_transitions: Vec::new(),
                },
                reply,
            },
            None,
        )
        .await;
    }

    pub(super) async fn begin_owned_local_trust(
        &mut self,
        fingerprint: Digest32,
        name: String,
        capability: crate::node::trust::Capability,
        reply: oneshot::Sender<Outcome>,
    ) {
        if self
            .computer
            .as_ref()
            .is_some_and(|computer| computer.grouped())
        {
            let _ = reply.send(Outcome::Done);
            return;
        }
        let Some(profile) = self.profile.as_ref() else {
            let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
            return;
        };
        if !profile.is_unlocked() {
            let _ = reply.send(Outcome::Failed(Fault::Locked));
            return;
        }
        if fingerprint == profile.fingerprint() {
            let _ = reply.send(Outcome::Done);
            return;
        }
        if self.trust.local_history_imported() {
            self.begin_owned_local_grant(
                fingerprint,
                name,
                capability,
                Lifetime {
                    save: None,
                    transition: None,
                    journal: None,
                    own_transitions: Vec::new(),
                },
                Some(reply),
            )
            .await;
            return;
        }
        self.begin_pending_policy(
            Policy::ImportBlacklist {
                history: self.decisions.clone(),
            },
            PolicyContinuation::LocalTrustImport {
                lifetime: Lifetime {
                    save: None,
                    transition: None,
                    journal: None,
                    own_transitions: Vec::new(),
                },
                fingerprint,
                name,
                capability,
            },
            Some(reply),
        )
        .await;
    }

    /// The original accepted Computer work, send-gate drain and exclusive transition are moved
    /// here from apply_owned_computer_policy. No binding/journal/keyring fsync occurs on actor.
    pub(super) async fn begin_owned_computer_policy(
        &mut self,
        mut work: computer::OwnKeyPolicyWork,
        secret: own_keys::SecretLease,
        transition: crate::node::computer::ComputerPublicationTransition,
        transitions: Vec<crate::node::channel::own_writer_gate::Transition>,
    ) {
        if self
            .computer
            .as_ref()
            .is_none_or(|computer| !computer.grouped())
        {
            let _ = work.reply.send(Ok(()));
            return;
        }
        if self.profile.is_none() && self.headless.is_some() {
            self.begin_headless_policy(work, secret, transition, transitions);
            return;
        }
        let transition = Arc::new(transition);
        let prepared = (|| -> crate::error::Result<(trust_save::Managed, Lifetime)> {
            work.guard.active(self.computer.as_ref())?;
            let computer = self.computer.clone().ok_or(Error::AtRestLocked)?;
            let profile = self
                .profile
                .as_ref()
                .filter(|profile| profile.is_unlocked())
                .ok_or(Error::AtRestLocked)?;
            let node = profile.fingerprint();
            let signer = profile.signer_arc()?;
            let plan = computer
                .plan(node)?
                .ok_or(Error::ComputerPolicySuperseded)?;
            let removed: Vec<_> = plan
                .denied
                .iter()
                .copied()
                .filter(|peer| self.trust.is_trusted(peer))
                .collect();
            if removed
                .iter()
                .any(|peer| work.targets.binary_search(peer).is_err())
            {
                return Err(Error::OwnKeyWriterDrainRequired(removed));
            }
            let aliases = plan
                .grants
                .iter()
                .map(|(peer, _, _)| peer)
                .chain(plan.denied.iter())
                .filter_map(|peer| {
                    self.trust
                        .petname(peer)
                        .map(|name| (*peer, name.to_owned()))
                })
                .collect();
            let authority = computer::ComputerAuthority::Managed {
                computer: Arc::clone(&computer),
                applied: plan.revision,
                expired: plan.expired,
                node,
            };
            let node_name = self
                .paths
                .profile_dir
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(Error::Profile("managed node name is unreadable"))?
                .to_owned();
            let native = trust_save::Managed {
                computer,
                guard: work.guard.clone(),
                transition: Arc::clone(&transition),
                plan,
                aliases,
                floor: 0,
                node,
                node_name,
            };
            let lifetime = Lifetime {
                save: Some(Arc::new(maintenance_save::Lifetime {
                    authority,
                    publication: None,
                    exclusive: Some(Arc::clone(&transition)),
                    secret,
                    store: profile.store_handle(),
                    signer,
                })),
                transition: None,
                journal: None,
                own_transitions: transitions,
            };
            Ok((native, lifetime))
        })();
        match prepared {
            Ok((mut native, lifetime)) => {
                for room in self.channels.values() {
                    native.floor = native.floor.max(room.lock().await.newest_mint_seq());
                }
                self.begin_pending_policy(
                    Policy::Managed(native),
                    PolicyContinuation::Managed {
                        lifetime,
                        work,
                        reservations: Vec::new(),
                    },
                    None,
                )
                .await;
            }
            Err(Error::OwnKeyWriterDrainRequired(targets)) => {
                work.targets = targets;
                self.own_key_computer_pending.push_front(work);
                self.post_save_wake.notify_one();
            }
            Err(error) => {
                let _ = work.reply.send(Err(error));
            }
        }
    }
}

impl Node {
    pub(super) async fn begin_owned_dismiss_offer(
        &mut self,
        member: Digest32,
        reply: oneshot::Sender<Outcome>,
    ) {
        if self
            .profile
            .as_ref()
            .is_none_or(|profile| !profile.is_unlocked())
        {
            let _ = reply.send(Outcome::Failed(Fault::Locked));
            return;
        }
        let bases = self
            .view_tx
            .borrow()
            .open_channels
            .iter()
            .flat_map(|room| {
                room.offer_bases
                    .iter()
                    .filter(|basis| basis.member == member)
                    .map(|basis| (room.channel_id, *basis))
            })
            .collect();
        self.begin_pending_policy(
            Policy::DismissOffers {
                bases,
                decision: None,
            },
            PolicyContinuation::DismissOffer {
                lifetime: Lifetime {
                    save: None,
                    transition: None,
                    journal: None,
                    own_transitions: Vec::new(),
                },
            },
            Some(reply),
        )
        .await;
    }
}

async fn finish_detached_policy(returned: Returned, reply: Reply) {
    release_rooms(&returned.rooms, true).await;
    match (returned.completed, returned.continuation) {
        (
            Ok(PolicyCompleted::Recorded),
            PolicyContinuation::FinishGrant {
                lifetime,
                source,
                grant,
            },
        ) => {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Done);
            }
            drop((lifetime, source, grant));
        }
        (
            Ok(PolicyCompleted::Dismissed(_)),
            PolicyContinuation::FinishUntrust {
                lifetime,
                operation,
            },
        ) => {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Done);
            }
            drop((lifetime, operation));
        }
        (Ok(PolicyCompleted::Dismissed(result)), PolicyContinuation::DismissOffer { lifetime }) => {
            if let Some(reply) = reply {
                let _ = reply.send(match result {
                    Ok(_) => Outcome::Done,
                    Err(error) => Outcome::Failed(fault_of(&error)),
                });
            }
            drop(lifetime);
        }
        (
            Ok(PolicyCompleted::Saved(Ok(saved))),
            PolicyContinuation::Blacklist { lifetime, reply },
        ) => {
            let _ = reply.send(Ok(Some(saved.trust.local_removals().clone())));
            drop(lifetime);
        }
        (Ok(PolicyCompleted::Saved(Err(error))), continuation) | (Err(error), continuation) => {
            finish_rejected_policy(continuation, error, reply)
        }
        (
            Ok(PolicyCompleted::Managed(completed)),
            PolicyContinuation::Managed {
                work,
                lifetime,
                reservations,
            },
        ) => {
            release_rooms(&reservations, true).await;
            let error = completed.result.err().unwrap_or(Error::Profile(
                "managed policy committed a prefix before retirement",
            ));
            let _ = work.reply.send(Err(error));
            drop(lifetime);
        }
        (
            Ok(PolicyCompleted::Saved(Ok(saved))),
            PolicyContinuation::Grant {
                lifetime,
                source: GrantSource::Local { .. },
            },
        ) if saved.grant.is_none() => {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Done);
            }
            drop(lifetime);
        }
        (_, PolicyContinuation::Untrust { lifetime, .. }) => {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(Fault::TrustRemovalIncomplete));
            }
            drop(lifetime);
        }
        (_, continuation) => finish_rejected_policy(
            continuation,
            Error::Profile("policy command committed a prefix before retirement"),
            reply,
        ),
    }
}
