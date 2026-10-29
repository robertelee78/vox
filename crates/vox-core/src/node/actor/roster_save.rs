//! Real board admission completes through the common room book, never an actor await.
use super::*;
use crate::atrest::vault::VaultRootSigner;
use crate::node::channel::pending_roster;
use crate::node::store::Store;
use std::future::Future;

pub(super) use pending_roster::Saved;
pub(super) enum Work {
    Board {
        records: Vec<MemberBundleRecord>,
        quota: usize,
        now: crate::time::Ms,
        tail: Option<pending_roster::NoticeTail>,
    },
    Join {
        candidate: Box<pending_roster::JoinCandidate>,
        net: Option<Arc<NodeNet>>,
    },
}
pub(super) struct Prepared(pending_roster::Prepared, Option<Arc<NodeNet>>);
pub(super) struct Completed(pending_roster::Completed);
impl Work {
    pub(super) fn prepare(
        self,
        channel: &mut ChannelState,
        store: &Arc<Store>,
        owner: Arc<()>,
        preparation_now: crate::time::Ms,
    ) -> crate::error::Result<Prepared> {
        match self {
            Self::Board {
                records,
                quota,
                now,
                tail,
            } => channel
                .prepare_pending_roster(store, owner, records, quota, now, tail)
                .map(|pending| Prepared(pending, None)),
            Self::Join { candidate, net } => channel
                .prepare_pending_join_admission(store, owner, candidate, preparation_now)
                .map(|pending| Prepared(pending, net)),
        }
    }
}
impl Prepared {
    pub(super) fn run(self, store: &Store, _signer: &VaultRootSigner) -> Completed {
        let completed = self.0.run(store);
        if let (Some(net), Some(notice)) = (self.1, completed.joined_notice()) {
            // This local service publication can write its board store too. It belongs to
            // the same native decision, never the actor or the live room guard.
            let _ = net.publish_local(&notice.to_wire());
        }
        Completed(completed)
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
    pub(super) fn finish(self, channel: &mut ChannelState, _store: &Store) -> Saved {
        self.0.finish(channel)
    }
    pub(super) fn into_result(self) -> Saved {
        self.0.into_result()
    }
}

pub(super) struct Sync {
    pub(super) conn: Arc<VoxConnection>,
    pub(super) peer: Digest32,
    pub(super) epoch: u64,
    pub(super) history: Option<crate::node::history_stream::Preamble>,
    pub(super) send: quinn::SendStream,
    pub(super) recv: quinn::RecvStream,
}
pub(super) enum After {
    News,
    Port(Digest32),
    Sync(Sync),
    JoinAdmit(oneshot::Sender<crate::error::Result<JoinAdmission>>),
}
pub(super) struct Continuation {
    pub(super) instance: SharedChannel,
    pub(super) attachment: u64,
    pub(super) after: After,
}
impl Continuation {
    pub(super) fn instance(&self) -> &SharedChannel {
        &self.instance
    }
    pub(super) fn lifetime(&self) -> Option<Arc<maintenance_save::Lifetime>> {
        None
    }
    pub(super) fn is_preparation(&self) -> bool {
        false
    }
    fn attached(&self, node: &Node, room: &Digest32) -> bool {
        self.attachment == node.delivery_epoch
            && node
                .channels
                .get(room)
                .is_some_and(|current| Arc::ptr_eq(current, &self.instance))
    }
}

pub(super) struct JoinAdmission {
    pub(super) name: Option<String>,
    pub(super) lifetime: Arc<maintenance_save::Lifetime>,
}
pub(super) struct JoinRequest {
    pub(super) original: std::sync::Weak<tokio::sync::Mutex<ChannelState>>,
    pub(super) attachment: u64,
    pub(super) peer: Digest32,
    pub(super) identity: crate::identity::composite::CompositePublicKey,
    pub(super) witness: crate::nat::record::JoinWitness,
    pub(super) ack: oneshot::Sender<crate::error::Result<JoinAdmission>>,
}
pub(super) enum AnsweredJoin {
    /// Existing unit-output lifecycle/validation work has no actor continuation.
    Settled,
    Join {
        peer: Digest32,
        channel_id: Digest32,
        outcome: std::result::Result<Box<crate::node::joinstream::JoinOutcome>, String>,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
        original: std::sync::Weak<tokio::sync::Mutex<ChannelState>>,
        attachment: u64,
    },
    PackageRedelivery {
        next: package_save::Redelivery,
        result: crate::error::Result<()>,
    },
    PackageAdoption {
        next: package_save::AdoptionWait,
    },
}

impl Node {
    pub(super) fn spawn_join_housekeeping<F>(&mut self, future: F) -> tokio::task::AbortHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.join_tasks.spawn(async move {
            future.await;
            AnsweredJoin::Settled
        })
    }

    pub(super) async fn begin_roster_admission(
        &mut self,
        room: Digest32,
        instance: SharedChannel,
        records: Vec<MemberBundleRecord>,
        after: After,
    ) {
        let tail = if matches!(&after, After::News) {
            self.net.as_ref().map(|net| pending_roster::NoticeTail {
                notices: net.board_notices(&room),
                withdraws: net.board_member_withdraws(&room),
                quota: ChannelState::MAX_ADMISSIONS_PER_SWEEP,
            })
        } else {
            None
        };
        if records.is_empty()
            && tail
                .as_ref()
                .is_none_or(|tail| tail.notices.is_empty() && tail.withdraws.is_empty())
        {
            return;
        }
        let work = Work::Board {
            records,
            quota: ChannelState::MAX_ADMISSIONS_PER_SWEEP,
            now: self.now_ms(),
            tail,
        };
        let next = Continuation {
            instance,
            attachment: self.delivery_epoch,
            after,
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Roster(work),
            maintenance_save::Continuation::Roster(next),
            None,
        )
        .await;
    }

    pub(super) async fn begin_join_admission(&mut self, room: Digest32, request: JoinRequest) {
        let JoinRequest {
            original,
            attachment,
            peer,
            identity,
            witness,
            ack,
        } = request;
        #[cfg(feature = "test-knobs")]
        let fails = std::env::var_os(TEST_ADMISSION_FAILS_ENV).is_some();
        #[cfg(not(feature = "test-knobs"))]
        let fails = false;
        let selected = (|| {
            if fails {
                return Err(Error::Profile("locked"));
            }
            let instance = self
                .channels
                .get(&room)
                .map(Arc::clone)
                .ok_or(Error::Profile("no such room on this node"))?;
            if attachment != self.delivery_epoch
                || original
                    .upgrade()
                    .is_none_or(|original| !Arc::ptr_eq(&original, &instance))
            {
                return Err(Error::JoinRefused(
                    "the room or attachment changed during the join",
                ));
            }
            let profile = self.profile.as_ref().ok_or(Error::Profile("locked"))?;
            let responder = crate::identity::composite::RootSigner::public_key(profile.signer()?);
            Ok((instance, responder))
        })();
        let (instance, responder) = match selected {
            Ok(selected) => selected,
            Err(error) => {
                let _ = ack.send(Err(error));
                return;
            }
        };
        let work = Work::Join {
            candidate: Box::new(pending_roster::JoinCandidate {
                peer,
                key: identity,
                witness,
                responder,
            }),
            net: self.net.as_ref().map(Arc::clone),
        };
        let next = Continuation {
            instance,
            attachment,
            after: After::JoinAdmit(ack),
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Roster(work),
            maintenance_save::Continuation::Roster(next),
            None,
        )
        .await;
    }

    pub(super) async fn complete_join_task(
        &mut self,
        returned: std::result::Result<AnsweredJoin, tokio::task::JoinError>,
    ) {
        match returned {
            Ok(AnsweredJoin::Settled) => {}
            Ok(AnsweredJoin::PackageAdoption { next }) => self.resume_package_adoption(next).await,
            Ok(AnsweredJoin::PackageRedelivery { next, result }) => {
                self.resume_package_redelivery(next, result).await
            }
            Ok(AnsweredJoin::Join {
                peer,
                channel_id,
                mut outcome,
                lifetime,
                original,
                attachment,
            }) => {
                if outcome.is_ok()
                    && (attachment != self.delivery_epoch
                        || !self.channels.get(&channel_id).is_some_and(|current| {
                            original
                                .upgrade()
                                .is_some_and(|original| Arc::ptr_eq(current, &original))
                        })
                        || lifetime
                            .as_ref()
                            .is_none_or(|held| !held.authority.current()))
                {
                    outcome = Err(
                        "the room or admission authority changed before the join could be filed"
                            .to_owned(),
                    );
                }
                self.apply_join_outcome(
                    peer,
                    channel_id,
                    outcome.map(|outcome| *outcome),
                    lifetime,
                )
                .await;
            }
            Err(error) => {
                let _ = self.event_tx.send(NodeEvent::JoinFailed {
                    reason: format!("answering a join: {error}"),
                });
            }
        }
    }

    pub(super) async fn finish_owned_roster(
        &mut self,
        room: Digest32,
        result: crate::error::Result<maintenance_save::Saved>,
        lifetime: Arc<maintenance_save::Lifetime>,
        next: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        let mut saved = match result {
            Ok(maintenance_save::Saved::Roster(saved)) => saved,
            Ok(_) => {
                self.reject_owned_roster(
                    room,
                    Error::Profile("unexpected roster save result"),
                    next,
                    reply,
                );
                return;
            }
            Err(error) => {
                self.reject_owned_roster(room, error, next, reply);
                return;
            }
        };
        if !next.attached(self, &room) || lifetime.publish(|| ()).is_none() {
            self.reject_owned_roster(
                room,
                Error::Profile("roster room authority changed"),
                next,
                reply,
            );
            return;
        }
        let after = match next.after {
            After::JoinAdmit(ack) => {
                let admitted = match (saved.result, saved.joined.take()) {
                    (Ok(()), Some(joined)) => {
                        self.governance_work.wake_room(room);
                        self.refresh_network_view().await;
                        Ok(JoinAdmission {
                            name: joined.name,
                            lifetime,
                        })
                    }
                    (Err(error), _) => Err(error),
                    (Ok(()), None) => Err(Error::Profile(
                        "native join admission returned no durable receipt",
                    )),
                };
                let _ = ack.send(admitted);
                return;
            }
            after => after,
        };
        if let Some(net) = &self.net {
            let cap = crate::node::channel::max_authors();
            for (author, members) in &saved.admitted {
                if *members > cap {
                    net.manager().note(*author, format!(
                        "admitted to room {} past its cap of {cap}, now {members} members: another member admitted it",
                        crate::node::network::short_id(room)));
                }
            }
        }
        // A later write failure never erases an already committed prefix or its network effects.
        let changed = !saved.admitted.is_empty();
        if changed {
            self.refresh_network_view().await;
            for ((channel, _), port) in &mut self.ports {
                if *channel == room {
                    port.raise();
                }
            }
            self.note_local_governance_append(&room);
        }
        match after {
            After::News => {}
            After::JoinAdmit(ack) => {
                let _ = ack.send(Err(Error::Profile("join admission was not finalized")));
            }
            After::Port(peer) => {
                drop(lifetime);
                if next.instance.lock().await.is_member(&peer) {
                    self.ensure_port(&room, &peer).await;
                }
            }
            After::Sync(sync) => {
                // Protocol replay rechecks policy; do not acquire a new reader behind a
                // waiting writer while retaining the original physical write reader.
                drop(lifetime);
                if next.instance.lock().await.is_member(&sync.peer) {
                    self.run_sync_session(
                        sync.conn,
                        sync.peer,
                        room,
                        sync.epoch,
                        sync.history,
                        sync.send,
                        sync.recv,
                        true,
                    )
                    .await;
                } else {
                    refuse(sync);
                }
            }
        }
        if let Some(reply) = reply {
            let _ = reply.send(
                saved
                    .result
                    .map(|_| Outcome::Done)
                    .unwrap_or_else(|error| Outcome::Failed(fault_of(&error))),
            );
        }
    }

    pub(super) fn reject_owned_roster(
        &mut self,
        _room: Digest32,
        error: Error,
        next: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        let fault = fault_of(&error);
        reject_after(next.after, error);
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(fault));
        }
    }
}
fn refuse(sync: Sync) {
    let (mut send, mut recv) = (sync.send, sync.recv);
    crate::node::net::refuse_stream(&mut send, &mut recv);
}

pub(super) fn retire_detached(
    result: crate::error::Result<maintenance_save::Saved>,
    next: Continuation,
    reply: Option<oneshot::Sender<Outcome>>,
) {
    match next.after {
        After::JoinAdmit(ack) => {
            let result = result.and_then(|saved| match saved {
                maintenance_save::Saved::Roster(saved) => saved.result,
                _ => Err(Error::Profile("unexpected native join admission result")),
            });
            let _ = ack.send(Err(result.err().unwrap_or(Error::Profile(
                "join admission lost its live room attachment",
            ))));
            return;
        }
        after => reject_after(
            after,
            Error::Profile("roster save lost its live room attachment"),
        ),
    }
    if let Some(reply) = reply {
        let result = result.and_then(|saved| match saved {
            maintenance_save::Saved::Roster(saved) => saved.result,
            _ => Err(Error::Profile("roster completion lost its room authority")),
        });
        let _ = reply.send(
            result
                .map(|_| Outcome::Done)
                .unwrap_or_else(|error| Outcome::Failed(fault_of(&error))),
        );
    }
}

fn reject_after(after: After, error: Error) {
    match after {
        After::Sync(sync) => refuse(sync),
        After::JoinAdmit(ack) => {
            let _ = ack.send(Err(error));
        }
        After::News | After::Port(_) => {}
    }
}

pub(super) struct BoardRecords {
    pub(super) records: Vec<MemberBundleRecord>,
    pub(super) quota: usize,
    pub(super) now: crate::time::Ms,
    pub(super) tail: Option<pending_roster::NoticeTail>,
}

/// The already-background exchange owns its physical save, as in Source::write_owned.
/// It waits only for an actual room reservation, never an unadmitted common-book worker.
pub(super) async fn background(
    instance: SharedChannel,
    lifetime: Arc<maintenance_save::Lifetime>,
    scope: BoardExchangeScope,
    records: BoardRecords,
    net: Arc<NodeNet>,
) -> usize {
    let BoardRecords {
        records,
        quota,
        now,
        tail,
    } = records;
    let owner = Arc::new(());
    let pending = loop {
        let mut room = instance.lock().await;
        if !scope.is_live() || !lifetime.authority.current() || room.epoch() != scope.epoch {
            return 0;
        }
        if room.post_pending() {
            let changed = room.history_publication_wake();
            drop(room);
            changed.await;
            continue;
        }
        match room.prepare_pending_roster(
            &lifetime.store,
            Arc::clone(&owner),
            records,
            quota,
            now,
            tail,
        ) {
            Ok(pending) => break pending,
            Err(_) => return 0,
        }
    };
    tokio::task::spawn_blocking(move || {
        let ready = {
            let room = instance.blocking_lock();
            scope.is_live() && lifetime.authority.current() && pending.can_run(&room, &owner)
        };
        let mut completed = if ready { pending.run(&lifetime.store) } else {
            pending.refuse(Error::Profile("board exchange retired before native admission"))
        };
        let pin = completed.take_history_pin();
        let mut room = instance.blocking_lock();
        let saved = if completed.can_install(&room, &owner) {
            Some(completed.finish(&mut room))
        } else {
            room.release_pending_text(&owner, false);
            None
        };
        if saved.is_some() {
            // This family changes roster/authority facts only, never the pinned history roots.
            if let Err(error) = room.publish_history_read(Arc::clone(&lifetime.store)) {
                room.poison(&error);
            }
        }
        drop(pin);
        // Cancellation must not suppress the physical reservation's enabled completion edge.
        room.note_publication_complete();
        drop(room);
        let Some(saved) = saved else { return 0; };
        if !scope.is_live() || lifetime.publish(|| ()).is_none() { return 0; }
        let cap = crate::node::channel::max_authors();
        for (author, members) in &saved.admitted {
            if *members > cap {
                net.manager().note(*author, format!(
                    "admitted to room {} past its cap of {cap}, now {members} members: another member admitted it",
                    crate::node::network::short_id(scope.channel_id)));
            }
        }
        saved.admitted.len()
    }).await.unwrap_or(0)
}
