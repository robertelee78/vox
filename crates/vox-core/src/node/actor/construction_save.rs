//! Fresh unpublished room construction on the native owner; never extracts a live room.
use super::*;
use crate::atrest::sek::Sek;
use crate::atrest::SekWrap;
use crate::governance::genesis::Genesis;
use crate::governance::share::ServiceKind;
use crate::identity::composite::RootSigner as _;
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
    Create(Box<Created>),
    Join(Box<JoinConstruction>),
}

struct JoinConstruction {
    genesis: Genesis,
    room: Digest32,
    name: Option<String>,
    passphrase: Secret,
    now: crate::time::Ms,
    sealed: (Sek, SekWrap),
    admission: crate::nat::record::Admission,
    responder_key: crate::identity::composite::CompositePublicKey,
    resuming: bool,
    own_history: crate::node::joinstream::OwnHistory,
    set: crate::nat::service::RecordSet,
    net: Option<Arc<NodeNet>>,
}

enum After {
    Create,
    Join {
        parsed: crate::node::link::InviteLink,
        me: Digest32,
        joined: Option<Box<crate::node::joinstream::JoinOutcome>>,
        responder: Digest32,
        conn: Arc<VoxConnection>,
    },
}

// The result is already stored in a heap-allocated shared slot; boxing adds another allocation.
#[allow(clippy::large_enum_variant)]
enum Returned {
    Unadmitted {
        work: Work,
        lifetime: maintenance_save::Lifetime,
    },
    Started {
        result: crate::error::Result<ChannelState>,
        lifetime: Arc<maintenance_save::Lifetime>,
    },
}

pub(super) struct Parked {
    room: Digest32,
    epoch: u64,
    store: std::sync::Weak<Store>,
    work: Work,
    pub(super) reply: oneshot::Sender<Outcome>,
    ready: bool,
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
            Self::Create(created) => {
                let Created {
                    name,
                    passphrase,
                    genesis,
                    sealed: (sek, wrap),
                    now,
                    anchors,
                    service,
                } = *created;
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
                if let Err(error) = fold_unpublished_governance(&mut channel, store, now) {
                    metadata_save::purge_unpublished(
                        store,
                        signer,
                        channel.me(),
                        channel.channel_id(),
                    )?;
                    return Err(error);
                }
                Ok(channel)
            }
            Self::Join(joined) => {
                let JoinConstruction {
                    genesis,
                    room,
                    name,
                    passphrase,
                    now,
                    sealed,
                    admission,
                    responder_key,
                    resuming,
                    own_history,
                    set,
                    net,
                } = *joined;
                let mut channel = match (resuming, store.get_sek_wrap(&room)?) {
                    (true, Some(saved)) if saved == sealed.1 => ChannelState::open_with_sek_owned(
                        store,
                        signer,
                        &room,
                        sealed.0,
                        &passphrase,
                        signer.fingerprint(),
                        now,
                        None,
                    )?,
                    (true, Some(_)) => return Err(Error::Profile("accepted join wrap changed")),
                    (_, None) => ChannelState::join_channel_from_sealed_owned(
                        store,
                        signer,
                        &genesis,
                        &room,
                        name.as_deref(),
                        &passphrase,
                        now,
                        sealed,
                        admission,
                        &responder_key,
                        own_history,
                    )?,
                    (false, Some(_)) => return Err(Error::Profile("room already stored")),
                };
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
                if resuming && !channel.is_member(&responder_key.fingerprint()) {
                    return Err(Error::Profile(
                        "accepted join responder authority is unavailable",
                    ));
                }
                fold_unpublished_governance(&mut channel, store, now)?;
                Ok(channel)
            }
        }
    }
}

/// Fold a freshly constructed room's governance on this worker, before the room is shared,
/// announced (`ChannelOpened`) or answered. A room's first rows are governance (its name and
/// anchors at creation, its admission at a join), and each retires the in-memory governance
/// display until the actor's bounded maintenance turn folds it again. That turn runs only after
/// the room is in the open-room map, so a client told the room is open (the app restarts its
/// observation on `ChannelOpened` and reads the room at once) was answered "room governance is
/// refreshing" for its roster, services, notices and history, and the daemon logged `network
/// authorization unavailable` for the room's own creator. This is the same bounded turn the
/// maintenance ladder runs (`FOLD_STEPS`, `FOLD_BUDGET`), on the worker that already owns the
/// room's publication lease and just wrote those rows; work the budget leaves over is the
/// ladder's as before, and a fold still refreshing is not a failed construction.
fn fold_unpublished_governance(
    channel: &mut ChannelState,
    store: &Store,
    now: crate::time::Ms,
) -> crate::error::Result<()> {
    match channel.advance_governance(store, now) {
        Ok(_) => Ok(()),
        Err(error) if ChannelState::governance_refreshing(&error) => Ok(()),
        Err(error) => Err(error),
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
            let Returned::Started { result, lifetime } = returned else {
                let _ = self.reply.send(Outcome::Failed(Fault::Locked));
                return;
            };
            let channel = match result {
                Ok(channel) => channel,
                Err(error) => {
                    let _ = self.reply.send(Outcome::Failed(fault_of(&error)));
                    return;
                }
            };
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
    pub(super) fn ready_parked_construction(&mut self) {
        if let Some(parked) = &mut self.parked_construction {
            parked.ready = true;
            self.post_save_wake.notify_one();
        }
    }

    pub(super) fn retire_parked_construction(&mut self, fault: Fault) {
        if let Some(parked) = self.parked_construction.take() {
            let _ = parked.reply.send(Outcome::Failed(fault));
        }
    }

    pub(super) fn resume_parked_construction(&mut self) {
        let Some(parked) = self.parked_construction.as_ref() else {
            return;
        };
        if parked.reply.is_closed() {
            self.parked_construction = None;
            return;
        }
        let current = parked.epoch == self.delivery_epoch
            && self.profile.as_ref().is_some_and(|profile| {
                parked
                    .store
                    .upgrade()
                    .is_some_and(|store| Arc::ptr_eq(&store, &profile.store_handle()))
            });
        if !current {
            self.retire_parked_construction(Fault::Locked);
            return;
        }
        if !parked.ready
            || self.pending_policy.is_some()
            || self.own_key_untrust_pending.is_some()
            || self.own_key_computer_flight.is_some()
            || !self.own_key_computer_pending.is_empty()
            || !self.computer_authority_current()
        {
            return;
        }
        let Some(parked) = self.parked_construction.take() else {
            return;
        };
        if let Work::Create(created) = &parked.work {
            if self.room_named(&created.name).is_some() {
                let _ = parked.reply.send(Outcome::Failed(Fault::RoomNameTaken));
                return;
            }
        }
        self.begin_construction(parked.room, parked.work, After::Create, parked.reply);
    }

    pub(super) fn begin_construct_created(
        &mut self,
        created: Created,
        reply: oneshot::Sender<Outcome>,
    ) {
        if self.parked_construction.is_some() {
            let _ = reply.send(Outcome::Failed(Fault::RoomChangePending));
            return;
        }
        let room = created.genesis.channel_id();
        if self
            .room_named(&created.name)
            .is_some_and(|held| held != room)
        {
            self.join_name_reservations.remove(&room);
            let _ = reply.send(Outcome::Failed(Fault::RoomNameTaken));
            return;
        }
        self.begin_construction(room, Work::Create(Box::new(created)), After::Create, reply);
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
        let (name, admission, responder_key, own_history, joined, resuming) = match joined {
            JoinAccepted::Fresh(joined) => {
                let Some(history) = joined.own_history.clone() else {
                    let _ = reply.send(Outcome::Failed(Fault::Internal));
                    return;
                };
                (
                    joined.room_name.clone(),
                    crate::nat::record::Admission::Witnessed(Box::new(joined.witness.clone())),
                    joined.peer.identity.clone(),
                    history,
                    Some(joined),
                    false,
                )
            }
            JoinAccepted::Resumed(accepted) => {
                let parsed =
                    crate::node::joinstream::AdmissionProposal::from_body(&accepted.proposal);
                let witness = crate::nat::record::JoinWitness::from_body(&accepted.witness);
                let (Ok(proposal), Ok(witness)) = (parsed, witness) else {
                    let _ = reply.send(Outcome::Failed(Fault::Storage));
                    return;
                };
                (
                    Some(accepted.name),
                    crate::nat::record::Admission::Witnessed(Box::new(witness)),
                    accepted.responder_key,
                    proposal.own_history,
                    None,
                    true,
                )
            }
        };
        if let Some(holder) = name.as_deref().and_then(|name| {
            self.view_tx
                .borrow()
                .channels
                .iter()
                .find(|channel| channel.channel_id != room && channel.name.as_deref() == Some(name))
                .map(|channel| (name, channel.channel_id))
        }) {
            let _ = self.event_tx.send(NodeEvent::JoinStep {
                step: format!(
                    "joined room {} but its name {} also belongs to room {}; distinguish them by their full IDs",
                    crate::node::link::b32_encode(&room),
                    holder.0,
                    crate::node::link::b32_encode(&holder.1),
                ),
            });
        }
        if resuming && self.channels.contains_key(&room) {
            let same = self
                .profile
                .as_ref()
                .and_then(|profile| profile.store().get_sek_wrap(&room).ok().flatten())
                .as_ref()
                == Some(&sealed.1);
            if !same {
                let _ = reply.send(Outcome::Failed(Fault::RoomChangePending));
                return;
            }
            self.retract_live_channel(&room);
        }
        let work = Work::Join(Box::new(JoinConstruction {
            genesis,
            room,
            name,
            passphrase,
            now,
            sealed,
            admission,
            responder_key,
            resuming,
            own_history,
            set,
            net: self.net.as_ref().map(Arc::clone),
        }));
        self.begin_construction(
            room,
            work,
            After::Join {
                parsed,
                me,
                joined,
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
                    self.join_name_reservations.remove(&room);
                    let _ = reply.send(Outcome::Failed(fault));
                }
                return;
            }
        };
        let store = Arc::clone(&lifetime.store);
        let result = Arc::new(std::sync::Mutex::new(None));
        let returned = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        #[cfg(feature = "test-knobs")]
        let prelease_hold = if matches!(&work, Work::Join { .. }) {
            (|| {
                let spec = std::env::var("VOX_TEST_HOLD_ROOM_JOIN_AFTER_BOARD").ok()?;
                let mut fields = spec.splitn(4, '\t');
                let (node, arm, engaged, release) = (
                    fields.next()?,
                    fields.next()?,
                    fields.next()?,
                    fields.next()?,
                );
                if self.paths.profile_dir.file_name()?.to_str()? != node
                    || std::fs::read(arm).ok()? != b"hold join before publication lease\n"
                {
                    return None;
                }
                std::fs::remove_file(arm).ok()?;
                let _ = std::fs::remove_file(release);
                let listener = tokio::net::UnixListener::bind(release).ok()?;
                std::fs::write(engaged, crate::node::link::b32_encode(&room)).ok()?;
                Some((
                    listener,
                    std::path::PathBuf::from(engaged),
                    std::path::PathBuf::from(release),
                ))
            })()
        } else {
            None
        };
        let task = tokio::spawn(async move {
            #[cfg(feature = "test-knobs")]
            if let Some((listener, engaged, release)) = prelease_hold {
                let _ = listener.accept().await;
                let _ = std::fs::remove_file(engaged);
                let _ = std::fs::remove_file(release);
            }
            let mut lifetime = lifetime;
            let saved = match lifetime.authority.acquire_publication().await {
                Some(publication) => {
                    lifetime.publication = Some(publication);
                    let lifetime = Arc::new(lifetime);
                    let held = Arc::clone(&lifetime);
                    let result = tokio::task::spawn_blocking(move || work.run(&held))
                        .await
                        .unwrap_or_else(|_| Err(Error::Profile("room constructor worker stopped")));
                    Returned::Started { result, lifetime }
                }
                None => {
                    #[cfg(feature = "test-knobs")]
                    if (crate::node::computer::fx28_mutant("constructor-stale-commit")
                        && matches!(work, Work::Create { .. }))
                        || (crate::node::computer::fx28_mutant("stale-join-authority")
                            && matches!(work, Work::Join { .. }))
                    {
                        let lifetime = Arc::new(lifetime);
                        let held = Arc::clone(&lifetime);
                        let result = tokio::task::spawn_blocking(move || work.run(&held))
                            .await
                            .unwrap_or_else(|_| {
                                Err(Error::Profile("room constructor worker stopped"))
                            });
                        *returned
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some(Returned::Started { result, lifetime });
                        wake.notify_one();
                        return;
                    }
                    Returned::Unadmitted { work, lifetime }
                }
            };
            *returned
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(saved);
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
        let returned = match returned {
            Returned::Unadmitted { work, lifetime } => {
                let superseded = lifetime.authority.superseded();
                drop(lifetime);
                if matches!(work, Work::Create { .. }) {
                    if !matches!(superseded, Ok(true))
                        || self
                            .failed_construction_policy
                            .as_ref()
                            .is_some_and(|guard| guard.active(self.computer.as_ref()).is_ok())
                    {
                        let _ = pending.reply.send(Outcome::Failed(Fault::ComputerPolicy));
                        return;
                    }
                    #[cfg(feature = "test-knobs")]
                    if crate::node::computer::fx28_mutant("constructor-terminal-refusal") {
                        let _ = pending.reply.send(Outcome::Failed(Fault::ComputerPolicy));
                        return;
                    }
                    let ready = self.computer_authority_current();
                    self.parked_construction = Some(Parked {
                        room: pending.room,
                        epoch: pending.epoch,
                        store: Arc::downgrade(&pending.store),
                        work,
                        reply: pending.reply,
                        ready,
                    });
                    if ready {
                        self.post_save_wake.notify_one();
                    }
                } else {
                    self.begin_metadata_abort_join(
                        pending.room,
                        Fault::ComputerPolicy,
                        Some(pending.reply),
                        None,
                    );
                }
                return;
            }
            Returned::Started { result, lifetime } => (result, lifetime),
        };
        let (result, lifetime) = returned;
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
                    let channel = result?;
                    metadata_save::purge_unpublished(
                        &lifetime.store,
                        &lifetime.signer,
                        channel.me(),
                        room,
                    )
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
        match result {
            Err(error) => match pending.after {
                After::Create => {
                    self.join_name_reservations.remove(&pending.room);
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
                    Some(lifetime),
                ),
            },
            Ok(channel) => {
                let authority = lifetime.authority.clone();
                match pending.after {
                    After::Create => {
                        self.begin_metadata_created(
                            channel,
                            authority,
                            pending.reply,
                            Some(lifetime),
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
                            joined: joined.map(|joined| *joined),
                            responder,
                            conn,
                            authority,
                        };
                        self.begin_metadata_room(
                            metadata_save::RoomAfter::Join(Box::new(tail)),
                            pending.reply,
                            Some(lifetime),
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
