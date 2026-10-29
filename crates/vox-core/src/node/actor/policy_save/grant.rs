//! Original Trust/TrustWith/Rename/SetCapability/local-trust continuations, not admission replies.
use super::*;
use crate::node::actor::trust_save::{GrantChange, GrantSaved};
use crate::node::trust::{Capability, HistoryGrant};

pub(crate) enum GrantCommand {
    Trust,
    Capability,
    Rename,
}
pub(crate) enum GrantSource {
    Command(GrantCommand),
    Local { capability: Capability },
}
pub(crate) struct GrantReady {
    lifetime: Lifetime,
    source: GrantSource,
    grant: GrantSaved,
    reservations: Vec<PolicyRoom>,
    rooms: Vec<(Digest32, SharedChannel)>,
}
pub(crate) struct GrantWaiting {
    receiver: oneshot::Receiver<crate::error::Result<GrantReady>>,
    reply: Reply,
}
pub(crate) struct GrantTurn {
    pub(in crate::node::actor) lifetime: Lifetime,
    pub(in crate::node::actor) rooms: Vec<PolicyRoom>,
    pub(in crate::node::actor) cursor: usize,
    source: GrantSource,
    grant: GrantSaved,
    decision: crate::node::consent_order::Stamp,
    terminal: oneshot::Sender<crate::error::Result<GrantReady>>,
}
enum Stage {
    Begin,
    Consents(oneshot::Receiver<crate::error::Result<()>>),
    Packages {
        cursor: usize,
        result: Option<oneshot::Receiver<Outcome>>,
    },
}
pub(crate) struct GrantDelivery {
    ready: GrantReady,
    stage: Stage,
    reply: Reply,
}

impl GrantWaiting {
    pub(super) async fn retire(mut self) {
        if let Ok(Ok(ready)) = (&mut self.receiver).await {
            release_rooms(&ready.reservations, true).await;
        }
        if let Some(reply) = self.reply {
            let _ = reply.send(Outcome::Failed(Fault::TrustRemovalIncomplete));
        }
    }
}
impl GrantDelivery {
    pub(super) async fn retire(self) {
        release_rooms(&self.ready.reservations, true).await;
        if let Some(reply) = self.reply {
            let _ = reply.send(Outcome::Failed(Fault::TrustRemovalIncomplete));
        }
    }
}
impl GrantTurn {
    pub(super) async fn retire(self, error: Error) {
        release_rooms(&self.rooms, true).await;
        let _ = self.terminal.send(Err(error));
        drop(self.lifetime);
    }
}

impl Node {
    /// Called by the original command loop after its Computer journal admission. The fixed-policy
    /// and passphrase checks are the same original command checks, before any native effect.
    pub(in crate::node::actor) async fn begin_owned_trust_command(
        &mut self,
        command: NodeCommand,
        reply: oneshot::Sender<Outcome>,
    ) {
        if self.computer_change_refused(&command) {
            let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
            return;
        }
        let (inner, proved) = match command {
            NodeCommand::Proved { change } => (*change, true),
            command => (command, false),
        };
        let (change, kind) = match inner {
            NodeCommand::Trust {
                fingerprint,
                petname,
            } => (
                GrantChange::Trust {
                    target: fingerprint,
                    petname,
                    history: HistoryGrant::Now,
                    capability: None,
                },
                GrantCommand::Trust,
            ),
            NodeCommand::TrustWith {
                fingerprint,
                petname,
                history,
                capability,
            } => (
                GrantChange::Trust {
                    target: fingerprint,
                    petname,
                    history,
                    capability,
                },
                GrantCommand::Trust,
            ),
            NodeCommand::SetCapability {
                fingerprint,
                capability,
            } => (
                GrantChange::Capability {
                    target: fingerprint,
                    capability,
                },
                GrantCommand::Capability,
            ),
            NodeCommand::Rename {
                fingerprint,
                petname,
            } => (
                GrantChange::Rename {
                    target: fingerprint,
                    petname,
                },
                GrantCommand::Rename,
            ),
            _ => {
                let _ = reply.send(Outcome::Failed(Fault::Internal));
                return;
            }
        };
        if proved && self.profile.as_ref().is_some_and(Profile::is_unlocked) {
            self.note_passphrase_entered();
        }
        if matches!(&change, GrantChange::Rename { .. }) && !self.trust.is_trusted(&change.target())
        {
            let _ = reply.send(Outcome::Failed(Fault::NotConsented));
            return;
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
        if matches!(&change, GrantChange::Capability { .. })
            && !self.trust.is_trusted(&change.target())
        {
            let _ = reply.send(Outcome::Failed(Fault::NotConsented));
            return;
        }
        let Some(authority) = self.computer_authority() else {
            let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
            return;
        };
        let secret = match self.secret_work.clone().try_read_owned() {
            Ok(secret) => Arc::new(secret),
            Err(_) => {
                let _ = reply.send(Outcome::Failed(Fault::Locked));
                return;
            }
        };
        let store = profile.store_handle();
        let lifetime = Lifetime {
            save: Some(Arc::new(maintenance_save::Lifetime {
                authority,
                publication: None,
                exclusive: None,
                secret,
                store,
                signer,
            })),
            transition: None,
            journal: self.computer_journal_writer.take(),
            own_transitions: Vec::new(),
        };
        self.begin_pending_policy(
            Policy::Grant { change, floor: 0 },
            PolicyContinuation::Grant {
                lifetime,
                source: GrantSource::Command(kind),
            },
            Some(reply),
        )
        .await;
    }

    pub(super) async fn begin_owned_local_grant(
        &mut self,
        fingerprint: Digest32,
        name: String,
        capability: Capability,
        lifetime: Lifetime,
        reply: Reply,
    ) {
        self.begin_pending_policy(
            Policy::Grant {
                change: GrantChange::Local {
                    target: fingerprint,
                    name,
                    capability,
                },
                floor: 0,
            },
            PolicyContinuation::Grant {
                lifetime,
                source: GrantSource::Local { capability },
            },
            reply,
        )
        .await;
    }

    pub(super) async fn begin_grant_marks(
        &mut self,
        lifetime: Lifetime,
        source: GrantSource,
        grant: Option<GrantSaved>,
        rooms: Vec<PolicyRoom>,
        reply: Reply,
    ) {
        let Some(grant) = grant else {
            release_rooms(&rooms, false).await;
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Done);
            }
            return;
        };
        if grant.capability_only {
            if grant.announce_support {
                self.owe_private_support_in_open_rooms().await;
            }
            self.publish().await;
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Done);
            }
            return;
        }
        let Some(decision) = grant.decision.filter(|_| !rooms.is_empty()) else {
            let instances = self
                .channels
                .iter()
                .map(|(room, instance)| (*room, Arc::clone(instance)))
                .collect();
            let ready = GrantReady {
                lifetime,
                source,
                grant,
                rooms: instances,
                reservations: rooms,
            };
            self.poll_grant_delivery(GrantDelivery {
                ready,
                stage: Stage::Begin,
                reply,
            })
            .await;
            return;
        };
        let (terminal, receiver) = oneshot::channel();
        let room = rooms[0].room;
        let target = grant.target;
        let turn = GrantTurn {
            lifetime,
            source,
            grant,
            decision,
            rooms,
            cursor: 0,
            terminal,
        };
        self.pending_policy = Some(Pending::GrantMarks(GrantWaiting { receiver, reply }));
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Trust(trust_save::Work(TrustWrite::MarkDecision {
                target,
                decision,
            })),
            maintenance_save::Continuation::Trust(TrustContinuation::Grant(turn)),
            None,
        )
        .await;
    }

    pub(super) async fn resume_grant_marks(
        &mut self,
        result: crate::error::Result<maintenance_save::Saved>,
        mut turn: GrantTurn,
    ) {
        match result {
            Ok(maintenance_save::Saved::Trust(TrustSaved::Marked)) => {}
            Ok(_) => {
                turn.retire(Error::Profile("unexpected trust-decision mark completion"))
                    .await;
                self.post_save_wake.notify_one();
                return;
            }
            Err(error) => {
                turn.retire(error).await;
                self.post_save_wake.notify_one();
                return;
            }
        }
        turn.cursor += 1;
        if turn.cursor == turn.rooms.len() {
            let instances = turn
                .rooms
                .iter()
                .map(|room| (room.room, Arc::clone(&room.instance)))
                .collect();
            let ready = GrantReady {
                lifetime: turn.lifetime,
                source: turn.source,
                grant: turn.grant,
                rooms: instances,
                reservations: turn.rooms,
            };
            let _ = turn.terminal.send(Ok(ready));
            self.post_save_wake.notify_one();
        } else {
            let room = turn.rooms[turn.cursor].room;
            let work = TrustWrite::MarkDecision {
                target: turn.grant.target,
                decision: turn.decision,
            };
            self.begin_pending_maintenance(
                room,
                maintenance_save::Work::Trust(trust_save::Work(work)),
                maintenance_save::Continuation::Trust(TrustContinuation::Grant(turn)),
                None,
            )
            .await;
        }
    }

    pub(super) async fn poll_grant_marks(&mut self, mut pending: GrantWaiting) {
        match pending.receiver.try_recv() {
            Ok(Ok(ready)) => {
                self.poll_grant_delivery(GrantDelivery {
                    ready,
                    stage: Stage::Begin,
                    reply: pending.reply,
                })
                .await
            }
            Ok(Err(error)) => {
                if let Some(reply) = pending.reply {
                    let _ = reply.send(Outcome::Failed(fault_of(&error)));
                }
            }
            Err(oneshot::error::TryRecvError::Empty) => {
                self.pending_policy = Some(Pending::GrantMarks(pending))
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                if let Some(reply) = pending.reply {
                    let _ = reply.send(Outcome::Failed(Fault::Internal));
                }
            }
        }
    }

    pub(super) async fn poll_grant_delivery(&mut self, mut pending: GrantDelivery) {
        let Some(save) = pending.ready.lifetime.save.as_ref().map(Arc::clone) else {
            release_rooms(&pending.ready.reservations, true).await;
            if let Some(reply) = pending.reply {
                let _ = reply.send(Outcome::Failed(Fault::Locked));
            }
            return;
        };
        let progressed = match &mut pending.stage {
            Stage::Begin => {
                if pending.ready.grant.announce_support {
                    self.owe_private_support_in_open_rooms().await;
                }
                self.refresh_reachers().await;
                let (sender, receiver) = oneshot::channel();
                self.begin_owned_owed_consents_for(
                    Arc::clone(&save),
                    Some(pending.ready.grant.target),
                    sender,
                )
                .await;
                pending.stage = Stage::Consents(receiver);
                false
            }
            Stage::Consents(receiver) => {
                match receiver.try_recv() {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        self.fail_grant_delivery(pending, error).await;
                        return;
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {
                        self.pending_policy = Some(Pending::GrantDelivery(pending));
                        return;
                    }
                    Err(oneshot::error::TryRecvError::Closed) => {
                        self.fail_grant_delivery(
                            pending,
                            Error::Profile("trust consent completion owner stopped"),
                        )
                        .await;
                        return;
                    }
                }
                for prepared in self.preparing_rooms.values_mut() {
                    prepared.channel.lock().await.release_held_packages();
                }
                pending.stage = Stage::Packages {
                    cursor: 0,
                    result: None,
                };
                true
            }
            Stage::Packages { cursor, result } => {
                if let Some(receiver) = result {
                    match receiver.try_recv() {
                        Ok(Outcome::Done) => {
                            *cursor += 1;
                            *result = None;
                        }
                        Ok(_) => {
                            self.fail_grant_delivery(
                                pending,
                                Error::Profile("trust key-package continuation failed"),
                            )
                            .await;
                            return;
                        }
                        Err(oneshot::error::TryRecvError::Empty) => {
                            self.pending_policy = Some(Pending::GrantDelivery(pending));
                            return;
                        }
                        Err(oneshot::error::TryRecvError::Closed) => {
                            self.fail_grant_delivery(
                                pending,
                                Error::Profile("trust key-package completion owner stopped"),
                            )
                            .await;
                            return;
                        }
                    }
                }
                if *cursor == pending.ready.rooms.len() {
                    self.finish_grant_delivery(pending).await;
                    return;
                }
                let (room, instance) = &pending.ready.rooms[*cursor];
                if !self
                    .channels
                    .get(room)
                    .is_some_and(|current| Arc::ptr_eq(current, instance))
                {
                    self.fail_grant_delivery(
                        pending,
                        Error::Profile("room changed during trust key-package continuation"),
                    )
                    .await;
                    return;
                }
                instance.lock().await.release_held_packages();
                let (sender, receiver) = oneshot::channel();
                *result = Some(receiver);
                self.begin_owned_package_turn(*room, Some(Arc::clone(&save)), Some(sender))
                    .await;
                false
            }
        };
        self.pending_policy = Some(Pending::GrantDelivery(pending));
        if progressed {
            self.post_save_wake.notify_one();
        }
    }

    async fn fail_grant_delivery(&mut self, pending: GrantDelivery, error: Error) {
        release_rooms(&pending.ready.reservations, true).await;
        if let Some(reply) = pending.reply {
            let _ = reply.send(Outcome::Failed(fault_of(&error)));
        }
        drop(pending.ready);
    }

    async fn finish_grant_delivery(&mut self, pending: GrantDelivery) {
        self.publish().await;
        let decision = match &pending.ready.source {
            GrantSource::Local { capability } => Some(crate::node::decisions::Decision {
                asked: "to trust a node of this computer",
                by: pending.ready.grant.target,
                alias: self
                    .trust
                    .petname(&pending.ready.grant.target)
                    .map(str::to_owned),
                decided: crate::node::decisions::Decided::Trusted,
                why: format!(
                    "the daemon applied this computer's local trust rule: {}",
                    capability.words()
                ),
                room: None,
            }),
            GrantSource::Command(kind) => {
                if pending.ready.grant.newly && matches!(kind, GrantCommand::Trust) {
                    Some(crate::node::decisions::Decision {
                        asked: "to trust a member",
                        by: pending.ready.grant.target,
                        alias: self
                            .trust
                            .petname(&pending.ready.grant.target)
                            .map(str::to_owned),
                        decided: crate::node::decisions::Decided::Trusted,
                        why: "this node's person added them to the keyring".to_owned(),
                        room: None,
                    })
                } else {
                    None
                }
            }
        };
        let GrantReady {
            lifetime,
            source,
            grant,
            ..
        } = pending.ready;
        if let Some(decision) = decision {
            self.begin_pending_policy(
                Policy::RecordDecision {
                    log: self.decisions.clone(),
                    now: (self.millis_clock)(),
                    decision,
                },
                PolicyContinuation::FinishGrant {
                    lifetime,
                    source,
                    grant,
                },
                pending.reply,
            )
            .await;
        } else {
            if let Some(reply) = pending.reply {
                let _ = reply.send(Outcome::Done);
            }
            drop((lifetime, source, grant));
        }
    }
}
