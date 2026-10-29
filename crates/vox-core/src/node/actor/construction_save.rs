//! Fresh unpublished room construction on the native owner; never extracts a live room.
use super::*;
use crate::atrest::sek::Sek;
use crate::atrest::SekWrap;
use crate::governance::genesis::Genesis;
use crate::governance::share::ServiceKind;
use crate::node::store::Store;

pub(super) struct Created {
    pub(super) name: String,
    pub(super) passphrase: Secret,
    pub(super) genesis: Genesis,
    pub(super) sealed: (Sek, SekWrap),
    pub(super) now: crate::time::Ms,
    pub(super) anchors: BootstrapSet,
    pub(super) service: Option<(String, SocketAddr, ServiceKind)>,
}

enum Work {
    Create {
        name: String,
        passphrase: Secret,
        genesis: Genesis,
        sek: Sek,
        wrap: SekWrap,
        now: crate::time::Ms,
        anchors: BootstrapSet,
        service: Option<(String, SocketAddr, ServiceKind)>,
    },
    Join {
        genesis: Genesis,
        room: Digest32,
        name: Option<String>,
        passphrase: Secret,
        now: crate::time::Ms,
        sealed: (Sek, SekWrap),
        admission: crate::nat::record::Admission,
        set: Box<crate::nat::service::RecordSet>,
        net: Option<Arc<NodeNet>>,
    },
}

enum After {
    Create,
    Join {
        parsed: crate::node::link::InviteLink,
        me: Digest32,
        joined: Box<crate::node::joinstream::JoinOutcome>,
        responder: Digest32,
        conn: Arc<VoxConnection>,
    },
}

struct Returned {
    result: crate::error::Result<ChannelState>,
    lifetime: Arc<maintenance_save::Lifetime>,
}

pub(super) struct Pending {
    room: Digest32,
    epoch: u64,
    store: Arc<Store>,
    result: Arc<std::sync::Mutex<Option<Returned>>>,
    task: tokio::task::JoinHandle<()>,
    after: After,
    reply: oneshot::Sender<Outcome>,
}

impl Work {
    fn run(self, lifetime: &maintenance_save::Lifetime) -> crate::error::Result<ChannelState> {
        let store = &lifetime.store;
        let signer = lifetime.signer.as_ref();
        match self {
            Self::Create {
                name,
                passphrase,
                genesis,
                sek,
                wrap,
                now,
                anchors,
                service,
            } => {
                let mut channel = ChannelState::create_from_sealed_owned(
                    store,
                    signer,
                    &name,
                    &passphrase,
                    genesis,
                    sek,
                    &wrap,
                    now,
                    &anchors,
                )?;
                if let Some((tag, endpoint, kind)) = service {
                    if let Err(error) =
                        channel.offer_unpublished_service(store, signer, &tag, endpoint, kind, now)
                    {
                        // This worker alone created this private, unpublished room. Never purge
                        // an existing live room or a failed join that discovered an existing wrap.
                        metadata_save::purge_unpublished(
                            store,
                            signer,
                            channel.me(),
                            channel.channel_id(),
                        )?;
                        return Err(error);
                    }
                }
                Ok(channel)
            }
            Self::Join {
                genesis,
                room,
                name,
                passphrase,
                now,
                sealed,
                admission,
                set,
                net,
            } => {
                let mut channel = ChannelState::join_channel_from_sealed_owned(
                    store,
                    signer,
                    &genesis,
                    &room,
                    name.as_deref(),
                    &passphrase,
                    now,
                    sealed,
                    admission,
                )?;
                let known = channel.author_fingerprints().into_iter().collect();
                let pending = verify_unknown_records(&known, &set.bundles);
                admit_verified_records(
                    &mut channel,
                    store,
                    pending,
                    ChannelState::MAX_ADMISSIONS_PER_SWEEP,
                    now,
                    net.as_deref(),
                );
                Ok(channel)
            }
        }
    }
}

impl Pending {
    pub(super) async fn retire(self) {
        let _ = self.task.await;
        let returned = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        // Retirement still owns the actual durable result and its original secret/publication
        // lease. A successfully constructed room is private until its metadata tail installs it.
        let outcome = if let Some(returned) = returned {
            let channel = match returned.result {
                Ok(channel) => channel,
                Err(error) => {
                    let _ = self.reply.send(Outcome::Failed(fault_of(&error)));
                    return;
                }
            };
            let lifetime = returned.lifetime;
            let room = channel.channel_id();
            let node = channel.me();
            match tokio::task::spawn_blocking(move || {
                let _channel = channel;
                metadata_save::purge_unpublished(&lifetime.store, &lifetime.signer, node, room)
            })
            .await
            {
                Ok(Err(error)) => Outcome::Failed(fault_of(&error)),
                Err(_) => Outcome::Failed(Fault::Internal),
                Ok(Ok(())) => Outcome::Failed(Fault::Locked),
            }
        } else {
            Outcome::Failed(Fault::Internal)
        };
        let _ = self.reply.send(outcome);
    }
}

impl Node {
    pub(super) fn begin_construct_created(
        &mut self,
        created: Created,
        reply: oneshot::Sender<Outcome>,
    ) {
        let Created {
            name,
            passphrase,
            genesis,
            sealed,
            now,
            anchors,
            service,
        } = created;
        let room = genesis.channel_id();
        if self.room_named(&name).is_some() {
            let _ = reply.send(Outcome::Failed(Fault::RoomNameTaken));
            return;
        }
        let (sek, wrap) = sealed;
        self.begin_construction(
            room,
            Work::Create {
                name,
                passphrase,
                genesis,
                sek,
                wrap,
                now,
                anchors,
                service,
            },
            After::Create,
            reply,
        );
    }

    pub(super) fn begin_construct_joined(
        &mut self,
        parsed: crate::node::link::InviteLink,
        passphrase: Secret,
        now: crate::time::Ms,
        me: Digest32,
        won: JoinerWon,
        reply: oneshot::Sender<Outcome>,
    ) {
        let JoinerWon {
            joined,
            responder,
            conn,
            set,
            genesis,
            sealed,
            steps: _,
        } = won;
        let room = parsed.channel_id;
        if let Some(holder) = joined
            .room_name
            .as_deref()
            .and_then(|name| self.room_named(name).map(|id| (name, id)))
        {
            let _ = self.event_tx.send(NodeEvent::JoinFailed {
                reason: format!(
                    "the room is called {}, and the room {} on this node already is",
                    holder.0,
                    crate::node::link::b32_encode(&holder.1)
                        .chars()
                        .take(12)
                        .collect::<String>(),
                ),
            });
            self.begin_metadata_abort_join(room, Fault::RoomNameTaken, Some(reply), None);
            return;
        }
        let work = Work::Join {
            genesis,
            room,
            name: joined.room_name.clone(),
            passphrase,
            now,
            sealed,
            admission: crate::nat::record::Admission::Witnessed(Box::new(joined.witness.clone())),
            set: Box::new(set),
            net: self.net.as_ref().map(Arc::clone),
        };
        self.begin_construction(
            room,
            work,
            After::Join {
                parsed,
                me,
                joined: Box::new(joined),
                responder,
                conn,
            },
            reply,
        );
    }

    fn begin_construction(
        &mut self,
        room: Digest32,
        work: Work,
        after: After,
        reply: oneshot::Sender<Outcome>,
    ) {
        let captured = (|| {
            if self.pending_policy.is_some() {
                return Err(Fault::RoomChangePending);
            }
            let profile = self
                .profile
                .as_ref()
                .filter(|p| p.is_unlocked())
                .ok_or(Fault::NoIdentity)?;
            let authority = self.computer_authority().ok_or(Fault::ComputerPolicy)?;
            let signer = profile.signer_arc().map_err(|e| fault_of(&e))?;
            let secret = self
                .secret_work
                .clone()
                .try_read_owned()
                .map_err(|_| Fault::Locked)?;
            Ok(maintenance_save::Lifetime {
                authority,
                publication: None,
                exclusive: None,
                secret: Arc::new(secret),
                store: profile.store_handle(),
                signer,
            })
        })();
        let lifetime = match captured {
            Ok(lifetime) => lifetime,
            Err(fault) => {
                if matches!(after, After::Join { .. }) {
                    self.begin_metadata_abort_join(room, fault, Some(reply), None);
                } else {
                    let _ = reply.send(Outcome::Failed(fault));
                }
                return;
            }
        };
        let store = Arc::clone(&lifetime.store);
        let result = Arc::new(std::sync::Mutex::new(None));
        let returned = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        let task = tokio::spawn(async move {
            let mut lifetime = lifetime;
            lifetime.publication = lifetime.authority.acquire_publication().await;
            let lifetime = Arc::new(lifetime);
            let held = Arc::clone(&lifetime);
            let saved = if lifetime.publication.is_some() {
                tokio::task::spawn_blocking(move || work.run(&held))
                    .await
                    .unwrap_or_else(|_| Err(Error::Profile("room constructor worker stopped")))
            } else {
                Err(Error::ComputerPolicySuperseded)
            };
            *returned
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Returned {
                result: saved,
                lifetime,
            });
            wake.notify_one();
        });
        self.pending_policy = Some(policy_save::Pending::Construction(Pending {
            room,
            epoch: self.delivery_epoch,
            store,
            result,
            task,
            after,
            reply,
        }));
    }

    pub(super) async fn complete_construction(&mut self, pending: Pending) {
        let returned = pending
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(returned) = returned else {
            if pending.task.is_finished() {
                pending.retire().await;
            } else {
                self.pending_policy = Some(policy_save::Pending::Construction(pending));
            }
            return;
        };
        let _ = pending.task.await;
        let current = pending.epoch == self.delivery_epoch
            && self
                .profile
                .as_ref()
                .is_some_and(|p| Arc::ptr_eq(&p.store_handle(), &pending.store));
        if !current {
            // The task already completed; ownership moves to a nonblocking cleanup task.
            let room = pending.room;
            let reply = pending.reply;
            tokio::spawn(async move {
                let result = tokio::task::spawn_blocking(move || {
                    let held = returned.lifetime;
                    let channel = returned.result?;
                    metadata_save::purge_unpublished(&held.store, &held.signer, channel.me(), room)
                })
                .await;
                let outcome = match result {
                    Ok(Err(error)) => Outcome::Failed(fault_of(&error)),
                    Err(_) => Outcome::Failed(Fault::Internal),
                    Ok(Ok(())) => Outcome::Failed(Fault::Locked),
                };
                let _ = reply.send(outcome);
            });
            return;
        }
        match returned.result {
            Err(error) => match pending.after {
                After::Create => {
                    self.answer_when_published(
                        pending.room,
                        pending.reply,
                        Outcome::Failed(fault_of(&error)),
                    )
                    .await
                }
                After::Join { .. } => self.begin_metadata_abort_join(
                    pending.room,
                    fault_of(&error),
                    Some(pending.reply),
                    Some(returned.lifetime),
                ),
            },
            Ok(channel) => {
                let authority = returned.lifetime.authority.clone();
                match pending.after {
                    After::Create => {
                        self.begin_metadata_created(
                            channel,
                            authority,
                            pending.reply,
                            Some(returned.lifetime),
                        )
                        .await
                    }
                    After::Join {
                        parsed,
                        me,
                        joined,
                        responder,
                        conn,
                    } => {
                        let tail = metadata_save::JoinTail {
                            channel: Box::new(channel),
                            parsed,
                            me,
                            joined: *joined,
                            responder,
                            conn,
                            authority,
                        };
                        self.begin_metadata_room(
                            metadata_save::RoomAfter::Join(Box::new(tail)),
                            pending.reply,
                            Some(returned.lifetime),
                            true,
                        )
                        .await;
                    }
                }
            }
        }
    }
}

pub(super) use crate::node::channel::pending_roster::verify_unknown_records;

/// Original witness fixpoint and whole-call quota. Call only on a physical native owner.
pub(super) fn admit_verified_records(
    channel: &mut ChannelState,
    store: &Store,
    pending: Vec<crate::node::channel::pending_roster::VerifiedRecord<'_>>,
    quota: usize,
    now: crate::time::Ms,
    net: Option<&NodeNet>,
) -> usize {
    crate::node::channel::pending_roster::admit_verified_records(pending, quota, |record, key| {
        let result = channel.admit_from_board(store, key, &record.admission, now);
        if matches!(&result, Ok(true)) {
            let (members, cap) = (channel.author_count(), crate::node::channel::max_authors());
            if members > cap {
                if let Some(net) = net {
                    net.manager().note(
                        key.fingerprint(),
                        format!(
                            "admitted to room {} past its cap of {cap}, now {members} \
                         members: another member admitted it",
                            crate::node::network::short_id(channel.channel_id()),
                        ),
                    );
                }
            }
        }
        result
    })
}
