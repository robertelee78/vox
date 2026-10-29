use super::*;
use crate::node::channel::session_projection::{
    ProjectionProgress, ProjectionWork, Query, Reply as SessionReply,
};
use crate::node::history_budget::{BufferCharge, Job};
use crate::node::ports::Token;
use crate::transport::quic::VoxConnection;

type ActorReply = Option<oneshot::Sender<Outcome>>;

pub(in crate::node::actor) struct ArchiveReceipt {
    pub(in crate::node::actor) plan: PrivatePlan,
    pub(in crate::node::actor) lifetime: Arc<maintenance_save::Lifetime>,
    pub(in crate::node::actor) charge: BufferCharge,
}

#[derive(Clone, Copy)]
enum DriveStage {
    Upgrade,
    Sessions,
    Legacy,
    Support,
}
#[derive(Clone, Copy)]
enum SupportStage {
    Refresh,
    Publish,
}
enum After {
    Drive {
        stage: DriveStage,
        guard: Option<computer::ComputerPolicyGuard>,
    },
    SupportDiscovery(SupportStage),
    Serving {
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        connection: Arc<VoxConnection>,
        job: Job,
        charge: BufferCharge,
        guard: history_demand::CurrentPrivateGuard,
    },
    Live {
        answer: oneshot::Sender<Result<bool>>,
        guard: history_demand::CurrentPrivateGuard,
        charge: BufferCharge,
    },
    Archive {
        answer: oneshot::Sender<std::result::Result<ArchiveReceipt, String>>,
        guard: history_demand::PrivateGuard,
        job: Job,
        charge: BufferCharge,
    },
}

pub(in crate::node::actor) struct Continuation {
    pub(in crate::node::actor) instance: SharedChannel,
    pub(in crate::node::actor) attachment: u64,
    pub(in crate::node::actor) lifetime: Option<Arc<maintenance_save::Lifetime>>,
    after: After,
}
impl Continuation {
    pub(in crate::node::actor) fn instance(&self) -> &SharedChannel {
        &self.instance
    }
    pub(in crate::node::actor) fn lifetime(&self) -> Option<Arc<maintenance_save::Lifetime>> {
        self.lifetime.as_ref().map(Arc::clone)
    }
    pub(in crate::node::actor) fn is_preparation(&self) -> bool {
        false
    }
    pub(in crate::node::actor) fn secret(
        &self,
    ) -> Option<Arc<tokio::sync::OwnedRwLockReadGuard<()>>> {
        match &self.after {
            After::Serving { guard, .. } | After::Live { guard, .. } => Some(guard.secret()),
            After::Archive { guard, .. } => Some(guard.secret()),
            After::Drive { .. } | After::SupportDiscovery(_) => None,
        }
    }
    fn attached(&self, node: &Node, room: &Digest32) -> bool {
        self.attachment == node.delivery_epoch
            && node
                .channels
                .get(room)
                .is_some_and(|current| Arc::ptr_eq(current, &self.instance))
    }
    fn flow_guard(&self) -> Option<FlowGuard> {
        match &self.after {
            After::Live { guard, .. } => Some(FlowGuard::Live {
                guard: guard.clone(),
                initial: false,
            }),
            After::Archive { guard, .. } => Some(FlowGuard::Archive {
                guard: guard.clone(),
                initial: false,
            }),
            _ => None,
        }
    }
}

impl Node {
    pub(in crate::node::actor) fn checked_support_discovery(
        &mut self,
        room: Digest32,
        channel: &ChannelState,
        store: &Store,
    ) -> bool {
        if !channel.private_support_discovery_pending() {
            return false;
        }
        let Ok((ready, missing_port)) = self.support_recipients_checked(&room, channel, store)
        else {
            return false;
        };
        if missing_port {
            self.discover_rooms.insert(room);
            self.sched_rooms.insert(room);
        }
        ready
    }

    /// This connection/proof edge renews support only; it never starts a Drive release.
    pub(in crate::node::actor) async fn begin_owned_support_discovery(
        &mut self,
        room: Digest32,
    ) -> bool {
        let Some(profile) = self.profile.as_ref() else {
            return false;
        };
        if self.locking != 0 || profile.signer().is_err() {
            return false;
        }
        let node = profile.fingerprint();
        let store = profile.store_handle();
        let Some(instance) = self.channels.get(&room).cloned() else {
            return false;
        };
        let Ok(channel) = instance.try_lock() else {
            self.bounded_sync.wait_for_own_recovery_room(
                &self.net_tx,
                &mut self.next_token,
                node,
                room,
                instance.clone(),
            );
            return false;
        };
        if !channel.private_support_discovery_pending() {
            return false;
        }
        if self.pending_posts.contains_key(&room) || channel.post_pending() {
            let released = channel.history_publication_wake();
            drop(channel);
            self.bounded_sync.wait_for_support_discovery_publication(
                &self.net_tx,
                &mut self.next_token,
                node,
                room,
                instance,
                released,
            );
            return false;
        }
        if !self.checked_support_discovery(room, &channel, &store) {
            return false;
        }
        drop(channel);
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime: None,
            after: After::SupportDiscovery(SupportStage::Refresh),
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Recovery(recovery_save::Work::support_refresh(self.now_ms())),
            maintenance_save::Continuation::Private(continuation),
            None,
        )
        .await
    }

    /// Owned policy tails validate the settled receipt under their original publication
    /// boundary; the aggregate actor revision stays pending until the entire tail completes.
    fn owned_private_drive_guard(
        &self,
        guard: Option<&computer::ComputerPolicyGuard>,
        lifetime: Option<&maintenance_save::Lifetime>,
    ) -> Result<()> {
        let Some(lifetime) = lifetime else {
            return self.computer_drive_guard(guard);
        };
        if let Some(guard) = guard {
            guard.active(self.computer.as_ref())?;
        }
        lifetime.publish(|| ()).ok_or(Error::Profile(
            "computer trust is pending application on this node",
        ))
    }

    /// Existing tend-drive callers hand over their ORIGINAL policy decision and lease.
    pub(in crate::node::actor) async fn begin_owned_private_drive(
        &mut self,
        room: Digest32,
        guard: Option<computer::ComputerPolicyGuard>,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
        reply: ActorReply,
    ) -> bool {
        let Some(instance) = self.channels.get(&room).cloned() else {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
            }
            return false;
        };
        if let Err(error) = self.owned_private_drive_guard(guard.as_ref(), lifetime.as_deref()) {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(fault_of(&error)));
            }
            return false;
        }
        let Some(profile) = &self.profile else {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
            }
            return false;
        };
        let readiness = {
            let channel = instance.lock().await;
            channel
                .legacy_cache_only(profile.store())
                .and_then(|legacy| {
                    if legacy {
                        Err(Error::StreamRefused("legacy history is not current"))
                    } else {
                        channel
                            .require_governance_ready(profile.store(), self.now_ms())
                            .map(|_| ())
                    }
                })
        };
        let readiness = readiness
            .and_then(|()| self.owned_private_drive_guard(guard.as_ref(), lifetime.as_deref()));
        if let Err(error) = readiness {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(fault_of(&error)));
            }
            return false;
        }
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime,
            after: After::Drive {
                stage: DriveStage::Upgrade,
                guard,
            },
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Private(Work::Upgrade {
                finish_initial: false,
            }),
            maintenance_save::Continuation::Private(continuation),
            reply,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::node::actor) async fn begin_owned_private_serving(
        &mut self,
        instance: SharedChannel,
        ask: Ask,
        peer: Digest32,
        holders: BTreeSet<Digest32>,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        connection: Arc<VoxConnection>,
        job: Job,
        charge: BufferCharge,
        page_charge: BufferCharge,
        guard: history_demand::CurrentPrivateGuard,
    ) -> bool {
        let room = ask.room;
        let work = Work::Serve {
            ask,
            peer,
            holders,
            charge: page_charge,
            guard: guard.clone(),
        };
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime: None,
            after: After::Serving {
                send,
                recv,
                connection,
                job,
                charge,
                guard,
            },
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Private(work),
            maintenance_save::Continuation::Private(continuation),
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::node::actor) async fn begin_owned_private_live(
        &mut self,
        room: Digest32,
        instance: SharedChannel,
        peer: Digest32,
        _token: Token,
        revision: u64,
        page: Result<Page>,
        received_at: u64,
        charge: BufferCharge,
        guard: history_demand::CurrentPrivateGuard,
        answer: oneshot::Sender<Result<bool>>,
    ) -> bool {
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime: None,
            after: After::Live {
                answer,
                guard: guard.clone(),
                charge,
            },
        };
        let work = Work::Live {
            peer,
            revision,
            page,
            received_at,
            guard,
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Private(work),
            maintenance_save::Continuation::Private(continuation),
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::node::actor) async fn begin_owned_private_archive(
        &mut self,
        room: Digest32,
        instance: SharedChannel,
        bounds: Bounds,
        plan: PrivatePlan,
        page: Page,
        nonce: Option<[u8; crate::atrest::sek::NONCE_LEN]>,
        guard: history_demand::PrivateGuard,
        job: Job,
        charge: BufferCharge,
        answer: oneshot::Sender<std::result::Result<ArchiveReceipt, String>>,
    ) -> bool {
        let work = Work::Archive {
            bounds,
            plan,
            page: Box::new(page),
            nonce,
            guard: guard.clone(),
        };
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime: None,
            after: After::Archive {
                answer,
                guard,
                job,
                charge,
            },
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Private(work),
            maintenance_save::Continuation::Private(continuation),
            None,
        )
        .await
    }

    pub(in crate::node::actor) fn reject_owned_private(
        &mut self,
        error: Error,
        continuation: Continuation,
        reply: ActorReply,
    ) {
        let fault = fault_of(&error);
        match continuation.after {
            After::Serving {
                mut send, mut recv, ..
            } => crate::transport::streams::refuse(&mut send, &mut recv),
            After::Live { answer, .. } => {
                let _ = answer.send(Err(error));
            }
            After::Archive { answer, .. } => {
                let _ = answer.send(Err(error.to_string()));
            }
            After::Drive { .. } | After::SupportDiscovery(_) => {}
        }
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(fault));
        }
    }

    pub(in crate::node::actor) async fn finish_owned_private(
        &mut self,
        room: Digest32,
        result: Result<maintenance_save::Saved>,
        lifetime: Arc<maintenance_save::Lifetime>,
        mut continuation: Continuation,
        reply: ActorReply,
    ) {
        let result = match result {
            Ok(saved) => saved,
            Err(error) => {
                self.reject_owned_private(error, continuation, reply);
                return;
            }
        };
        if !continuation.attached(self, &room) {
            self.reject_owned_private(
                Error::StreamRefused("private room attachment changed"),
                continuation,
                reply,
            );
            return;
        }
        continuation.lifetime = None;
        if let maintenance_save::Saved::Private(Saved::Flow(flow)) = result {
            let Some(guard) = continuation.flow_guard() else {
                self.reject_owned_private(
                    Error::Profile("private flow continuation changed"),
                    continuation,
                    reply,
                );
                return;
            };
            continuation.lifetime = Some(lifetime);
            self.continue_private(
                room,
                maintenance_save::Work::Private(Work::Flow { flow, guard }),
                continuation,
                reply,
            )
            .await;
            return;
        }
        if let After::SupportDiscovery(stage) = &continuation.after {
            let stage = *stage;
            self.finish_support_discovery(room, result, lifetime, continuation, reply, stage)
                .await;
            return;
        }
        if let After::Drive { stage, guard } = &continuation.after {
            if let Err(error) =
                self.owned_private_drive_guard(guard.as_ref(), Some(lifetime.as_ref()))
            {
                self.reject_owned_private(error, continuation, reply);
                return;
            }
            let stage = *stage;
            self.finish_private_drive(room, result, lifetime, continuation, reply, stage)
                .await;
            return;
        }
        match (continuation.after, result) {
            (
                After::Serving {
                    send,
                    mut recv,
                    connection,
                    job,
                    charge,
                    guard,
                },
                maintenance_save::Saved::Private(Saved::Page(page)),
            ) => {
                self.spawn_join_housekeeping(async move {
                    let (_lifetime, _guard, _connection, _job, _charge) =
                        (lifetime, guard, connection, job, charge);
                    let _ = &mut recv;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(10),
                        crate::node::sessionstream::answer(send, page),
                    )
                    .await;
                });
            }
            (
                After::Live {
                    answer,
                    guard,
                    charge,
                },
                maintenance_save::Saved::Private(Saved::PageFinished(
                    pending_upgrade::PageResult::Live(advanced),
                )),
            ) => {
                let _ = answer.send(Ok(advanced));
                drop((lifetime, guard, charge));
            }
            (
                After::Archive {
                    answer,
                    guard,
                    job,
                    charge,
                },
                maintenance_save::Saved::Private(Saved::PageFinished(
                    pending_upgrade::PageResult::Archive(plan),
                )),
            ) => {
                let _ = answer.send(Ok(ArchiveReceipt {
                    plan,
                    lifetime,
                    charge,
                }));
                drop((guard, job));
            }
            (after, _) => {
                let continuation = Continuation {
                    after,
                    ..continuation
                };
                self.reject_owned_private(
                    Error::Profile("private completion does not match its continuation"),
                    continuation,
                    reply,
                );
                return;
            }
        }
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Done);
        }
    }

    async fn continue_private(
        &mut self,
        room: Digest32,
        work: maintenance_save::Work,
        continuation: Continuation,
        reply: ActorReply,
    ) {
        Box::pin(self.begin_pending_maintenance(
            room,
            work,
            maintenance_save::Continuation::Private(continuation),
            reply,
        ))
        .await;
    }

    async fn finish_private_drive(
        &mut self,
        room: Digest32,
        result: maintenance_save::Saved,
        lifetime: Arc<maintenance_save::Lifetime>,
        mut continuation: Continuation,
        reply: ActorReply,
        stage: DriveStage,
    ) {
        let next = match (stage, result) {
            (DriveStage::Upgrade, maintenance_save::Saved::Private(Saved::Upgrade(saved))) => {
                if saved.advance == SessionAdvance::Waiting {
                    None
                } else {
                    Some((
                        DriveStage::Upgrade,
                        maintenance_save::Work::Private(Work::Upgrade {
                            finish_initial: false,
                        }),
                    ))
                }
            }
            (DriveStage::Upgrade, maintenance_save::Saved::Private(Saved::ControlImport)) => {
                Some((
                    DriveStage::Upgrade,
                    maintenance_save::Work::Private(Work::Import),
                ))
            }
            (DriveStage::Upgrade, maintenance_save::Saved::Private(Saved::PrivateExpiry)) => {
                Some((
                    DriveStage::Upgrade,
                    maintenance_save::Work::Private(Work::Expiry),
                ))
            }
            (
                DriveStage::Upgrade,
                maintenance_save::Saved::Private(Saved::Imported | Saved::Expired),
            ) => Some((
                DriveStage::Upgrade,
                maintenance_save::Work::Private(Work::Upgrade {
                    finish_initial: false,
                }),
            )),
            (DriveStage::Upgrade, maintenance_save::Saved::Private(Saved::UpgradeComplete)) => {
                Some((
                    DriveStage::Sessions,
                    maintenance_save::Work::Projection(ProjectionWork::Sessions),
                ))
            }
            (DriveStage::Upgrade, maintenance_save::Saved::Private(Saved::UpgradeWaiting)) => None,
            (
                DriveStage::Sessions,
                maintenance_save::Saved::Projection(ProjectionProgress::Sessions {
                    advanced: true,
                }),
            ) => Some((
                DriveStage::Sessions,
                maintenance_save::Work::Projection(ProjectionWork::Sessions),
            )),
            (
                DriveStage::Sessions,
                maintenance_save::Saved::Projection(ProjectionProgress::Sessions {
                    advanced: false,
                }),
            ) => {
                let checked = {
                    let channel = continuation.instance.lock().await;
                    self.support_recipients_checked(&room, &channel, &lifetime.store)
                };
                let (ready, missing_port) = match checked {
                    Ok(checked) => checked,
                    Err(error) => {
                        self.reject_owned_private(error, continuation, reply);
                        return;
                    }
                };
                if missing_port {
                    self.discover_rooms.insert(room);
                    self.sched_rooms.insert(room);
                }
                ready.then_some((
                    DriveStage::Legacy,
                    maintenance_save::Work::Private(Work::AnnounceLegacy),
                ))
            }
            (
                DriveStage::Legacy,
                maintenance_save::Saved::Private(Saved::Announcement { count, complete }),
            ) => {
                if count != 0 {
                    self.note_local_append(&room);
                }
                Some(if complete {
                    (
                        DriveStage::Support,
                        maintenance_save::Work::Consent(consent_save::Work::PrivateSupport {
                            discovery_ready: true,
                        }),
                    )
                } else {
                    (
                        DriveStage::Legacy,
                        maintenance_save::Work::Private(Work::AnnounceLegacy),
                    )
                })
            }
            (
                DriveStage::Support,
                maintenance_save::Saved::Consent(consent_save::Effect::PrivateSupport(appended)),
            ) => {
                if appended {
                    self.note_local_append(&room);
                }
                self.release_private_drive(room, lifetime, continuation, reply)
                    .await;
                return;
            }
            (DriveStage::Support, maintenance_save::Saved::Unavailable) => {
                let ready = {
                    let channel = continuation.instance.lock().await;
                    channel.is_settled()
                        && !channel.is_poisoned()
                        && channel.is_author(&channel.me())
                        && !channel.has_left(&channel.me())
                        && !channel.private_support_discovery_pending()
                };
                if ready {
                    self.release_private_drive(room, lifetime, continuation, reply)
                        .await;
                    return;
                }
                None
            }
            (_, maintenance_save::Saved::Unavailable) => None,
            _ => {
                self.reject_owned_private(
                    Error::Profile("private drive prerequisite receipt changed"),
                    continuation,
                    reply,
                );
                return;
            }
        };
        if let Some((stage, work)) = next {
            if let After::Drive { stage: current, .. } = &mut continuation.after {
                *current = stage;
            }
            continuation.lifetime = Some(lifetime);
            self.continue_private(room, work, continuation, reply).await;
        } else if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(Fault::RoomChangePending));
        }
    }

    async fn release_private_drive(
        &mut self,
        room: Digest32,
        lifetime: Arc<maintenance_save::Lifetime>,
        continuation: Continuation,
        reply: ActorReply,
    ) {
        let answer = {
            let mut channel = continuation.instance.lock().await;
            let me = channel.me();
            channel.session_query(
                &lifetime.store,
                Query::HasOpen { node: me },
                1,
                (self.millis_clock)(),
            )
        };
        let ensure = match answer {
            Ok(SessionReply::HasOpen(open)) => open,
            _ => {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::RoomChangePending));
                }
                return;
            }
        };
        let After::Drive { guard, .. } = continuation.after else {
            return;
        };
        self.begin_owned_session_drive_retained(room, ensure, guard, Some(lifetime), reply)
            .await;
    }
}

impl Node {
    async fn finish_support_discovery(
        &mut self,
        room: Digest32,
        result: maintenance_save::Saved,
        lifetime: Arc<maintenance_save::Lifetime>,
        mut continuation: Continuation,
        reply: ActorReply,
        stage: SupportStage,
    ) {
        match (stage, result) {
            (
                SupportStage::Refresh,
                maintenance_save::Saved::Recovery(recovery_save::Saved::Fence(_)),
            ) => {
                let Ok(channel) = continuation.instance.try_lock() else {
                    self.bounded_sync.wait_for_own_recovery_room(
                        &self.net_tx,
                        &mut self.next_token,
                        crate::identity::composite::RootSigner::fingerprint(
                            lifetime.signer.as_ref(),
                        ),
                        room,
                        continuation.instance.clone(),
                    );
                    return;
                };
                if !self.checked_support_discovery(room, &channel, &lifetime.store) {
                    return;
                }
                drop(channel);
                continuation.after = After::SupportDiscovery(SupportStage::Publish);
                continuation.lifetime = Some(lifetime);
                self.continue_private(
                    room,
                    maintenance_save::Work::Consent(consent_save::Work::PrivateSupport {
                        discovery_ready: true,
                    }),
                    continuation,
                    reply,
                )
                .await;
            }
            (
                SupportStage::Publish,
                maintenance_save::Saved::Consent(consent_save::Effect::PrivateSupport(appended)),
            ) => {
                if appended {
                    self.note_local_append(&room);
                }
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Done);
                }
            }
            (_, maintenance_save::Saved::Unavailable) => {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::RoomChangePending));
                }
            }
            _ => self.reject_owned_private(
                Error::Profile("private support receipt does not match its retained stage"),
                continuation,
                reply,
            ),
        }
    }
}
