//! Node-global native policy work. One retained owner uses the existing post-save wake;
//! there is no fake room id, second command queue, timer or result-channel credit dependency.
use super::trust_save::{Lifetime, Policy, PolicyCompleted, PolicyContinuation, PolicyResume};
use super::*;
use crate::node::store::Store;

mod grant;
pub(super) use grant::GrantSource;
mod headless;

type Reply = Option<oneshot::Sender<Outcome>>;
struct Returned {
    continuation: PolicyContinuation,
    completed: crate::error::Result<PolicyCompleted>,
}

pub(super) struct NativePending {
    store: Arc<Store>,
    epoch: u64,
    result: Arc<std::sync::Mutex<Option<Returned>>>,
    task: tokio::task::JoinHandle<()>,
    reply: Reply,
}

pub(super) enum Pending {
    Native(NativePending),
    Leave(leave_save::Pending),
    Headless(headless::HeadlessPending),
    Construction(construction_save::Pending),
    PeerBook(peer_book_save::Pending),
}

impl Pending {
    pub(super) async fn retire(self) {
        match self {
            Self::Native(pending) => pending.retire().await,
            Self::Leave(pending) => pending.retire().await,
            Self::Headless(pending) => pending.retire().await,
            Self::Construction(pending) => pending.retire().await,
            Self::PeerBook(pending) => pending.retire().await,
        }
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
        PolicyContinuation::Managed { work, lifetime } => {
            tokio::spawn(async move {
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

    pub(super) fn policy_work_already_current(&self, work: &computer::OwnKeyPolicyWork) -> bool {
        let Some(identity) = self
            .startup_identity_info()
            .map(|identity| identity.fingerprint)
        else {
            return false;
        };
        let Some(computer) = self.computer.as_ref() else {
            return false;
        };
        let Some((revision, expired)) = self.applied_computer_policy() else {
            return false;
        };
        let view_current = {
            let view = self.view_tx.borrow();
            !view.locked
                && !view.locking
                && view
                    .identity
                    .as_ref()
                    .is_some_and(|info| info.fingerprint == identity)
                && view.computer_policy == Some((revision, expired))
        };
        view_current
            && computer.policy_current(revision, expired, identity)
            && work.guard.active(self.computer.as_ref()).is_ok()
    }

    pub(super) async fn begin_pending_policy(
        &mut self,
        policy: Policy,
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
        let managed = matches!(&policy, Policy::Managed(_));
        let needs_publication = matches!(&policy, Policy::Untrust { .. } | Policy::Grant { .. });
        let choice_target = match &policy {
            Policy::Untrust { target } => Some(*target),
            Policy::Grant { change, .. } if change.individual_choice() => Some(change.target()),
            _ => None,
        };
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
                    Ok(policy.run(&save.store, save.signer.as_ref()))
                }))
                .unwrap_or_else(|_| Err(Error::Profile("native policy worker stopped")));
                Returned {
                    continuation,
                    completed,
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
        let completed = returned.completed;
        let resume = match completed {
            Ok(completed) => self.finish_owned_policy(completed, returned.continuation),
            Err(error) => PolicyResume::Failed {
                continuation: returned.continuation,
                error,
            },
        };
        self.refresh_reachers().await;
        self.resume_policy_result(resume, pending.reply).await;
    }

    /// The reply observes room completion and the original requested consent pass without
    /// retaining the node's policy owner.
    fn reply_after_room_trust(
        &mut self,
        reply: Reply,
        consents: Option<oneshot::Receiver<crate::error::Result<()>>>,
    ) {
        let Some(mut reply) = reply else {
            return;
        };
        let generation = self.trust_generation;
        let cancelled = &mut self.own_key_room_cancel;
        let rooms: Vec<_> = self
            .channels
            .iter()
            .map(|(room, instance)| {
                let retired = cancelled
                    .entry(*room)
                    .or_insert_with(|| tokio::sync::watch::channel(false).0)
                    .subscribe();
                (Arc::clone(instance), retired)
            })
            .collect();
        let mut attachment = self.pairwise_epoch.subscribe();
        tokio::spawn(async move {
            for (instance, mut retired) in rooms {
                loop {
                    let channel = tokio::select! {
                        _ = reply.closed() => return,
                        _ = attachment.changed() => {
                            let _ = reply.send(Outcome::Failed(Fault::Locked));
                            return;
                        }
                        _ = retired.changed() => break,
                        channel = instance.lock() => channel,
                    };
                    let changed = channel.history_publication_wake();
                    if channel.trust_reconciled(generation) {
                        break;
                    }
                    if channel.is_poisoned() || channel.trust_failed(generation) {
                        let _ = reply.send(Outcome::Failed(Fault::TrustRemovalIncomplete));
                        return;
                    }
                    drop(channel);
                    tokio::select! {
                        _ = reply.closed() => return,
                        _ = attachment.changed() => {
                            let _ = reply.send(Outcome::Failed(Fault::Locked));
                            return;
                        }
                        _ = retired.changed() => break,
                        _ = changed => {}
                    }
                }
            }
            if let Some(consents) = consents {
                let consent_result = tokio::select! {
                    biased;
                    _ = reply.closed() => return,
                    _ = attachment.changed() => {
                        let _ = reply.send(Outcome::Failed(Fault::Locked));
                        return;
                    }
                    result = consents => result,
                };
                match consent_result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        let _ = reply.send(Outcome::Failed(fault_of(&error)));
                        return;
                    }
                    Err(_) => {
                        let _ = reply.send(Outcome::Failed(Fault::Internal));
                        return;
                    }
                }
            }
            let _ = reply.send(Outcome::Done);
        });
    }

    async fn finish_untrust_save(
        &mut self,
        lifetime: Lifetime,
        operation: trust_save::Untrust,
        reply: Reply,
    ) {
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

    async fn resume_policy_result(&mut self, resume: PolicyResume, reply: Reply) {
        match resume {
            PolicyResume::Untrusted {
                lifetime,
                operation,
            } => {
                self.finish_untrust_save(lifetime, operation, reply).await;
            }
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
            } => self.finish_grant_save(lifetime, source, grant, reply).await,
            PolicyResume::GrantFinished {
                lifetime,
                source,
                grant,
            } => {
                drop((lifetime, source));
                self.finish_grant_reply(grant, reply).await;
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
                drop((lifetime, operation));
                self.reply_after_room_trust(reply, None);
            }
            PolicyResume::Managed {
                lifetime,
                work,
                result,
                revision,
                expired,
            } => {
                self.begin_managed_trust_continuation(lifetime, work, result, revision, expired)
                    .await;
            }
            PolicyResume::Failed {
                continuation,
                error,
            } => {
                finish_rejected_policy(continuation, error, reply);
            }
        }
    }
}

impl Node {
    async fn begin_managed_trust_continuation(
        &mut self,
        mut lifetime: Lifetime,
        work: computer::OwnKeyPolicyWork,
        result: crate::error::Result<computer::KeyringApplication>,
        revision: u64,
        expired: bool,
    ) {
        let application = match result {
            Ok(application) => application,
            Err(error) => {
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
                Ok(next) => {
                    self.begin_pending_policy(
                        Policy::Managed(next),
                        PolicyContinuation::Managed { lifetime, work },
                        None,
                    )
                    .await;
                }
                Err(error) => {
                    let _ = work.reply.send(Err(error));
                }
            }
            return;
        }
        if let Err(error) = work.guard.active(self.computer.as_ref()) {
            let _ = work.reply.send(Err(error));
            return;
        }
        // Room withdrawals keep their existing durable PendingLocks and run independently.
        drop(lifetime);
        if self.capture_open_computer_offer_boundaries().await.is_err() {
            // Policy is already applied. Keep unpaid boundaries behind their read barrier,
            // and let each room retry without stranding this completion's other waiters.
            for room in self.channels.keys().copied() {
                self.governance_work.wake_room(room);
            }
        }
        self.computer_expired = expired;
        self.computer_revision
            .store(revision, std::sync::atomic::Ordering::Release);
        self.publish_computer_trust_projection();
        self.governance_work.pending = true;
        self.governance_work.again = true;
        self.redeliver_now = true;
        self.governance_work.resume_after_computer_policy();
        self.resume_interrupted_governance();
        self.resume_own_key_policy_waiting();
        self.ready_parked_construction();
        self.publish().await;
        let _ = work.reply.send(Ok(()));
    }
}

impl Node {
    /// Consume the original command, proof, secret lease and journal admission.
    pub(super) async fn begin_owned_untrust(
        &mut self,
        command: NodeCommand,
        reply: oneshot::Sender<Outcome>,
        secret: own_keys::SecretLease,
        journal: Option<crate::node::computer::ComputerJournalWriter>,
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
                },
                fingerprint,
                name,
                capability,
            },
            Some(reply),
        )
        .await;
    }

    /// Move the accepted Computer work and exclusive transition to the native worker.
    pub(super) async fn begin_owned_computer_policy(
        &mut self,
        work: computer::OwnKeyPolicyWork,
        secret: own_keys::SecretLease,
        transition: crate::node::computer::ComputerPublicationTransition,
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
            self.begin_headless_policy(work, secret, transition);
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
            };
            Ok((native, lifetime))
        })();
        match prepared {
            Ok((native, lifetime)) => {
                self.begin_pending_policy(
                    Policy::Managed(native),
                    PolicyContinuation::Managed { lifetime, work },
                    None,
                )
                .await;
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
                },
            },
            Some(reply),
        )
        .await;
    }
}

async fn finish_detached_policy(returned: Returned, reply: Reply) {
    let completed = returned.completed;
    match (completed, returned.continuation) {
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
            PolicyContinuation::Managed { work, lifetime },
        ) => {
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
