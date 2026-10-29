//! Retained authored-save replies and physical worker ownership, independent of actor queue space.
use super::*;
use crate::identity::composite::RootSigner as _;
use crate::node::channel::pending_text::{
    CompletedText, GovernancePreparation, GovernanceWrite, Saved,
};
use crate::node::store::Store;

type Command = (NodeCommand, oneshot::Sender<Outcome>);

pub(super) struct DeferredCommand {
    pub(super) command: Command,
    // Reserve the original queue's released position; do not grow a second unbounded queue.
    pub(super) _permit: Option<mpsc::OwnedPermit<Command>>,
}

type SavedEnd = Option<std::result::Result<EndWithdrawal, Fault>>;
type SavedAppend = (CompletedText, SavedEnd);
pub(super) type Returned = std::result::Result<
    (
        CompletedText,
        Option<computer::ComputerPublication>,
        SavedEnd,
    ),
    Fault,
>;

struct EndPreparation {
    routes: BTreeMap<Digest32, Vec<std::net::SocketAddr>>,
}

pub(super) struct EndWithdrawal {
    pending: PendingWithdrawal,
}

impl EndPreparation {
    fn save(
        self,
        store: &Store,
        signer: &dyn crate::identity::composite::RootSigner,
        room: Digest32,
        epoch: u64,
        now: u64,
    ) -> std::result::Result<EndWithdrawal, Fault> {
        let wire = crate::nat::withdraw::BoardWithdraw::build(
            signer,
            &room,
            epoch,
            crate::nat::withdraw::WithdrawScope::Room,
            now,
        )
        .map_err(|error| fault_of(&error))?
        .to_wire();
        // Read the latest ledger after writer admission: independent rooms can finish
        // their owned saves in either actor order without overwriting another withdrawal.
        let mut batch = store.batch().map_err(|error| fault_of(&error))?;
        let mut next = match store
            .get_meta(PENDING_WITHDRAWALS_META_KEY)
            .map_err(|error| fault_of(&error))?
        {
            Some(bytes) => read_pending_withdrawals(&bytes).map_err(|error| fault_of(&error))?,
            None => BTreeMap::new(),
        };
        next.insert(
            room,
            PendingWithdrawal {
                wire,
                routes: self.routes,
            },
        );
        let bytes = pending_withdrawals_bytes(&next).map_err(|error| fault_of(&error))?;
        #[cfg(feature = "test-knobs")]
        let durable = !crate::node::computer::fx28_mutant("withdrawal-not-durable");
        #[cfg(not(feature = "test-knobs"))]
        let durable = true;
        if durable {
            batch
                .put_meta(PENDING_WITHDRAWALS_META_KEY, &bytes)
                .map_err(|error| fault_of(&error))?;
            batch.commit().map_err(|error| fault_of(&error))?;
        }
        Ok(EndWithdrawal {
            pending: next.remove(&room).ok_or(Fault::Internal)?,
        })
    }
}

#[derive(Clone, Copy)]
enum ReplyKind {
    Text,
    Rename,
    Governance,
    Retention,
    End,
    AddAdmin,
    Anchors,
}

impl ReplyKind {
    fn outcome(self, saved: &Saved) -> Outcome {
        match saved {
            Saved::Governance(Some(hash)) if matches!(self, Self::Rename) => {
                Outcome::Appended(*hash)
            }
            Saved::OwnRetention { own, room } => Outcome::OwnRetention {
                own: *own,
                room: *room,
            },
            _ => Outcome::Done,
        }
    }
}

pub(super) enum Pending {
    Append(AppendPending),
    Maintenance(Box<maintenance_save::Pending>),
    Metadata(metadata_save::RoomPending),
}

impl Pending {
    pub(super) fn owe_governance(&mut self, instance: &SharedChannel, attachment: u64) {
        match self {
            Self::Append(pending) => {
                if attachment == pending.epoch && Arc::ptr_eq(instance, &pending.instance) {
                    pending.governance_owed = true;
                }
            }
            Self::Maintenance(pending) => pending.owe_governance(instance, attachment),
            // Constructors own unpublished rooms, not this admitted room incarnation.
            Self::Metadata(_) => {}
        }
    }

    pub(super) fn owe_retention(&mut self, instance: &SharedChannel, attachment: u64) {
        match self {
            Self::Append(pending) => {
                if attachment == pending.epoch && Arc::ptr_eq(instance, &pending.instance) {
                    pending.retention_owed = true;
                }
            }
            Self::Maintenance(pending) => pending.owe_retention(instance, attachment),
            // Constructors own unpublished rooms, not this admitted room incarnation.
            Self::Metadata(_) => {}
        }
    }

    fn retention_request(&self) -> Option<(SharedChannel, u64)> {
        match self {
            Self::Append(pending) => pending
                .retention_owed
                .then(|| (Arc::clone(&pending.instance), pending.epoch)),
            Self::Maintenance(pending) => pending.retention_request(),
            Self::Metadata(_) => None,
        }
    }
}

pub(super) struct AppendPending {
    instance: SharedChannel,
    owner: Arc<()>,
    store: Arc<Store>,
    epoch: u64,
    retention_owed: bool,
    governance_owed: bool,
    result: Arc<std::sync::Mutex<Option<Returned>>>,
    task: tokio::task::JoinHandle<()>,
    reply: oneshot::Sender<Outcome>,
    kind: ReplyKind,
    #[cfg(feature = "mutant-sender")]
    end_authority: Option<computer::ComputerAuthority>,
    _slot: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    _secret: tokio::sync::OwnedRwLockReadGuard<()>,
}

pub(super) struct FailedRead {
    pub(super) instance: std::sync::Weak<tokio::sync::Mutex<ChannelState>>,
    pub(super) store: Arc<Store>,
    pub(super) _pin: crate::node::channel::history::PendingHistoryRead,
}

#[cfg(feature = "test-knobs")]
pub(super) struct PostProof {
    marker: std::path::PathBuf,
    rotated: bool,
    release_requested: bool,
    released_paused: bool,
}

impl Node {
    /// Writer-dependent commands retain their original reply. Read-only requests continue
    /// through the same command loop, and deferred ownership consumes the original admission.
    pub(super) fn command_waits_for_save(command: &NodeCommand) -> bool {
        !matches!(
            command,
            NodeCommand::Ping
                | NodeCommand::PreparePost { .. }
                | NodeCommand::VerifyPassphrase { .. }
                | NodeCommand::SetAnchors { .. }
                | NodeCommand::StopForward { .. }
                | NodeCommand::Forward { .. }
                | NodeCommand::Up { .. }
                | NodeCommand::CheckRoomPassphrase { .. }
                | NodeCommand::Shutdown
                | NodeCommand::Status { .. }
                | NodeCommand::Attention {
                    operation: crate::node::attention::Operation::Page(_),
                    ..
                }
                | NodeCommand::RoomPause { paused: None, .. }
                | NodeCommand::SendText { .. }
                | NodeCommand::SendTextAt { .. }
                | NodeCommand::SendTextAdmitted { .. }
        )
    }

    pub(super) fn command_needs_journal(command: &NodeCommand) -> bool {
        match command {
            NodeCommand::Trust { .. }
            | NodeCommand::TrustWith { .. }
            | NodeCommand::SetCapability { .. } => true,
            NodeCommand::Proved { change } => Self::command_needs_journal(change),
            _ => false,
        }
    }

    pub(super) fn retain_store_command(
        &mut self,
        command: NodeCommand,
        reply: oneshot::Sender<Outcome>,
    ) {
        let permit = self
            .command_sender
            .upgrade()
            .and_then(|sender| sender.try_reserve_owned().ok());
        self.deferred_commands.push_back(DeferredCommand {
            command: (command, reply),
            _permit: permit,
        });
    }

    pub(super) async fn begin_pending_append(
        &mut self,
        command: NodeCommand,
        reply: oneshot::Sender<Outcome>,
    ) {
        let channel_id = match &command {
            NodeCommand::SendText { channel_id, .. }
            | NodeCommand::SendTextAt { channel_id, .. }
            | NodeCommand::SendTextAdmitted { channel_id, .. }
            | NodeCommand::RenameRoom { channel_id, .. }
            | NodeCommand::SetRetention { channel_id, .. }
            | NodeCommand::SetStepRetention { channel_id, .. }
            | NodeCommand::ChooseIdleEnd { channel_id, .. }
            | NodeCommand::EndRoom { channel_id }
            | NodeCommand::SetAdmin {
                channel_id,
                admin: true,
                ..
            }
            | NodeCommand::ChangeRoomAnchors { channel_id, .. } => *channel_id,
            _ => {
                let _ = reply.send(Outcome::Failed(Fault::Internal));
                return;
            }
        };
        if self.pending_posts.contains_key(&channel_id)
            || (!self.pending_posts.is_empty() && !self.deferred_commands.is_empty())
        {
            self.retain_store_command(command, reply);
            return;
        }
        let (text, expected_instance, slot, governance, kind) = match command {
            NodeCommand::SendText { text, .. } => (text, None, None, None, ReplyKind::Text),
            NodeCommand::SendTextAt { text, instance, .. } => {
                (text, Some(instance), None, None, ReplyKind::Text)
            }
            NodeCommand::SendTextAdmitted {
                text,
                instance,
                permit,
                ..
            } => (text, instance, permit, None, ReplyKind::Text),
            NodeCommand::RenameRoom { name, .. } => {
                if crate::governance::name::room_name(&name).as_deref() != Ok(name.as_str()) {
                    let _ = reply.send(Outcome::Failed(Fault::NotARoomName));
                    return;
                }
                (
                    String::new(),
                    None,
                    None,
                    Some(GovernanceWrite::Rename(name)),
                    ReplyKind::Rename,
                )
            }
            NodeCommand::SetRetention { ttl, .. } => (
                String::new(),
                None,
                None,
                Some(GovernanceWrite::Retention {
                    seconds: ttl,
                    steps: false,
                }),
                ReplyKind::Retention,
            ),
            NodeCommand::SetStepRetention { seconds, .. } => (
                String::new(),
                None,
                None,
                Some(GovernanceWrite::Retention {
                    seconds,
                    steps: true,
                }),
                ReplyKind::Retention,
            ),
            NodeCommand::ChooseIdleEnd { idle_secs, .. } => (
                String::new(),
                None,
                None,
                Some(GovernanceWrite::IdleEnd(idle_secs)),
                ReplyKind::Governance,
            ),
            NodeCommand::EndRoom { .. } => (
                String::new(),
                None,
                None,
                Some(GovernanceWrite::End),
                ReplyKind::End,
            ),
            NodeCommand::SetAdmin {
                member,
                admin: true,
                ..
            } => (
                String::new(),
                None,
                None,
                Some(GovernanceWrite::AddAdmin(member)),
                ReplyKind::AddAdmin,
            ),
            NodeCommand::ChangeRoomAnchors { add, remove, .. } => (
                String::new(),
                None,
                None,
                Some(GovernanceWrite::Anchors { add, remove }),
                ReplyKind::Anchors,
            ),
            _ => unreachable!(),
        };
        #[cfg(feature = "test-knobs")]
        if governance.is_none() {
            test_panic_on_text(&text);
        }
        if governance.is_some() && self.publish_waiters.contains_key(&channel_id) {
            let _ = reply.send(Outcome::Failed(Fault::RoomChangePending));
            return;
        }
        if matches!(kind, ReplyKind::AddAdmin) && self.governance_work.removal.is_some() {
            let _ = reply.send(Outcome::Failed(Fault::AdminChangePending));
            return;
        }
        let Some(profile) = self.profile.as_ref() else {
            let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
            return;
        };
        let Some(shared) = self.channels.get(&channel_id).cloned() else {
            let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
            return;
        };
        let Some(authority) = self.computer_authority() else {
            let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
            return;
        };
        #[cfg(feature = "mutant-sender")]
        let end_authority = matches!(kind, ReplyKind::End).then(|| authority.clone());
        let end_preparation = matches!(kind, ReplyKind::End).then(|| EndPreparation {
            routes: self.withdrawal_routes(&channel_id),
        });
        let Ok(secret) = self.secret_work.clone().try_read_owned() else {
            let _ = reply.send(Outcome::Failed(Fault::Locked));
            return;
        };
        let signer = match profile.signer_arc() {
            Ok(signer) => signer,
            Err(error) => {
                let _ = reply.send(Outcome::Failed(fault_of(&error)));
                return;
            }
        };
        let store = profile.store_handle();
        let owner = Arc::new(());
        let worker_owner = Arc::clone(&owner);
        let worker_room = Arc::clone(&shared);
        let millis_clock = Arc::clone(&self.millis_clock);
        let rotation_now = self.now_ms().get();
        let epoch = self.delivery_epoch;
        let attachment = self.pairwise_epoch.subscribe();
        #[cfg(feature = "test-knobs")]
        let force_rotation = std::env::var_os("VOX_TEST_FX28_ROTATE_AFTER_POST")
            .and_then(|path| std::fs::read_to_string(path).ok())
            .is_some_and(|arm| {
                let fields: Vec<_> = arm.trim_end().split('\t').collect();
                fields.len() == 2
                    && self
                        .paths
                        .profile_dir
                        .file_name()
                        .and_then(|name| name.to_str())
                        == fields.first().copied()
                    && fields.get(1).copied()
                        == Some(crate::node::link::b32_encode(&channel_id).as_str())
            });
        #[cfg(not(feature = "test-knobs"))]
        let force_rotation = false;
        let result = Arc::new(std::sync::Mutex::new(None));
        let output = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        let worker_store = Arc::clone(&store);
        let own_retention_file = match &governance {
            Some(GovernanceWrite::Retention { steps, .. }) => Some((
                self.paths.clone(),
                if *steps {
                    crate::node::paths::STEP_RETENTION_FILE
                } else {
                    crate::node::paths::RETENTION_FILE
                },
            )),
            _ => None,
        };
        #[cfg(feature = "test-knobs")]
        self.hold_text_append_publication_for_proof().await;
        let worker = tokio::spawn(async move {
            #[cfg(feature = "test-knobs")]
            let publication = if crate::node::computer::fx28_mutant("stale-post-authority") {
                None
            } else {
                match authority.acquire_publication().await {
                    Some(publication) => Some(publication),
                    None => return Err(Fault::ComputerPolicy),
                }
            };
            #[cfg(not(feature = "test-knobs"))]
            let publication = match authority.acquire_publication().await {
                Some(publication) => Some(publication),
                None => return Err(Fault::ComputerPolicy),
            };
            let saved =
                tokio::task::spawn_blocking(move || -> std::result::Result<SavedAppend, Fault> {
                    let pending = {
                        let mut channel = worker_room.blocking_lock();
                        if *attachment.borrow() != epoch {
                            return Err(Fault::Locked);
                        }
                        if let Some(expected) = expected_instance {
                            match channel.history_instance(&worker_store) {
                                Ok(actual) if actual == expected => {}
                                Ok(_) => return Err(Fault::PostSelectionChanged),
                                Err(error) => {
                                    channel.poison(&error);
                                    return Err(fault_of(&error));
                                }
                            }
                        }
                        if let Some(write) = &governance {
                            let now = crate::time::Ms(millis_clock());
                            if matches!(write, GovernanceWrite::End)
                                && channel.ended(now.get()).is_some()
                            {
                                return Err(Fault::RoomEnded);
                            }
                            let prepared = channel
                                .prepare_pending_governance(
                                    &worker_store,
                                    signer.as_ref(),
                                    worker_owner,
                                    write,
                                    now,
                                )
                                .map_err(|error| fault_of(&error))?;
                            let room_epoch = channel.epoch();
                            drop(channel);
                            return match prepared {
                                GovernancePreparation::Append(pending, payload) => {
                                    let completed = pending.run_governance(
                                        &worker_store,
                                        signer.as_ref(),
                                        payload,
                                    );
                                    let withdrawal = end_preparation
                                        .filter(|_| completed.result.is_ok())
                                        .map(|preparation| {
                                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                                                || {
                                                    preparation.save(
                                                        &worker_store,
                                                        signer.as_ref(),
                                                        channel_id,
                                                        room_epoch,
                                                        millis_clock(),
                                                    )
                                                },
                                            ))
                                            .unwrap_or(Err(Fault::Storage))
                                        });
                                    Ok((completed, withdrawal))
                                }
                                GovernancePreparation::Unchanged => Ok((
                                    CompletedText::without_append(Saved::Governance(None)),
                                    None,
                                )),
                                GovernancePreparation::OwnRetention { own, room } => {
                                    if room != 0 && (own == 0 || own > room) {
                                        return Err(Fault::AboveRoomRetention);
                                    }
                                    let (paths, name) =
                                        own_retention_file.ok_or(Fault::Internal)?;
                                    let file = paths
                                        .own_config_path(name)
                                        .map_err(|_| Fault::RetentionFileUnwritable)?;
                                    crate::node::retention::RetentionConfig::write_room(
                                        &file,
                                        &channel_id,
                                        (own != room).then_some(own),
                                    )
                                    .map_err(|_| Fault::RetentionFileUnwritable)?;
                                    Ok((
                                        CompletedText::without_append(Saved::OwnRetention {
                                            own,
                                            room,
                                        }),
                                        None,
                                    ))
                                }
                            };
                        }
                        let now_millis = millis_clock();
                        match channel.prepare_pending_text(
                            &worker_store,
                            signer.fingerprint(),
                            worker_owner,
                            now_millis,
                            rotation_now,
                            force_rotation,
                        ) {
                            Ok(pending) => pending,
                            Err(error) => {
                                let fault = fault_of(&error);
                                if matches!(fault, Fault::Internal) {
                                    eprintln!(
                                        "vox: preparing post in room {}: {error}",
                                        crate::node::link::b32_encode(&channel_id)
                                    );
                                }
                                return Err(fault);
                            }
                        }
                    };
                    Ok((pending.run(&worker_store, signer.as_ref(), &text), None))
                })
                .await;
            match saved {
                Ok(Ok((completed, withdrawal))) => Ok((completed, publication, withdrawal)),
                Ok(Err(fault)) => Err(fault),
                Err(_) => Err(Fault::Storage),
            }
        });
        let task = tokio::spawn(async move {
            let returned = worker.await.unwrap_or(Err(Fault::Storage));
            *output
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(returned);
            wake.notify_one();
        });
        self.pending_posts.insert(
            channel_id,
            Pending::Append(AppendPending {
                instance: shared,
                owner,
                store,
                epoch: self.delivery_epoch,
                retention_owed: false,
                governance_owed: false,
                result,
                task,
                reply,
                kind,
                #[cfg(feature = "mutant-sender")]
                end_authority,
                _slot: slot,
                _secret: secret,
            }),
        );
    }

    pub(super) async fn complete_pending_posts(&mut self) {
        let rooms: Vec<_> = self.pending_posts.keys().copied().collect();
        for room in rooms {
            let retention = self
                .pending_posts
                .get(&room)
                .and_then(Pending::retention_request);
            if matches!(self.pending_posts.get(&room), Some(Pending::Metadata(_))) {
                self.complete_room_metadata(room).await;
                continue;
            }
            if matches!(self.pending_posts.get(&room), Some(Pending::Maintenance(_))) {
                self.complete_pending_maintenance(room).await;
                self.continue_deferred_retention(room, retention).await;
                continue;
            }
            let Some(Pending::Append(pending)) = self.pending_posts.get(&room) else {
                continue;
            };
            let returned = pending
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            let Some(returned) = returned else {
                continue;
            };
            let current = pending.epoch == self.delivery_epoch
                && self
                    .channels
                    .get(&room)
                    .is_some_and(|current| Arc::ptr_eq(current, &pending.instance));
            let shared = Arc::clone(&pending.instance);
            let Ok(mut channel) = shared.try_lock() else {
                *pending
                    .result
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(returned);
                continue;
            };
            let pending = self.pending_posts.remove(&room);
            let Some(Pending::Append(pending)) = pending else {
                continue;
            };
            let mut governance_owed = current && pending.governance_owed;
            let result = match returned {
                Ok((mut completed, _publication, withdrawal))
                    if current && completed.can_install(&channel, &pending.owner) =>
                {
                    #[cfg(feature = "test-knobs")]
                    let rotated = completed.rotated;
                    let pin = completed.take_history_pin();
                    let result = channel.finish_pending_text(&pending.store, completed);
                    if channel
                        .publish_history_read(Arc::clone(&pending.store))
                        .is_err()
                    {
                        if let Some(pin) = pin {
                            self.failed_post_reads.insert(
                                room,
                                FailedRead {
                                    instance: Arc::downgrade(&shared),
                                    store: Arc::clone(&pending.store),
                                    _pin: pin,
                                },
                            );
                        }
                    }
                    #[cfg(feature = "test-knobs")]
                    if matches!(&result, Ok(Saved::Text(_))) {
                        self.note_post_proof(room, rotated);
                    }
                    result
                        .map(|saved| (saved, true, withdrawal, _publication))
                        .map_err(|error| {
                            let fault = fault_of(&error);
                            if matches!(fault, Fault::Internal) {
                                eprintln!(
                                    "vox: posting to room {}: {error}",
                                    crate::node::link::b32_encode(&room)
                                );
                            }
                            fault
                        })
                }
                Ok((completed, _publication, withdrawal)) => {
                    governance_owed = false;
                    let result = completed
                        .result
                        .map(|saved| (saved, false, withdrawal, _publication))
                        .map_err(|error| fault_of(&error));
                    channel.release_pending_text(&pending.owner, false);
                    result
                }
                Err(fault) => {
                    channel.release_pending_text(&pending.owner, matches!(fault, Fault::Storage));
                    Err(fault)
                }
            };
            drop(channel);
            let _ = pending.task.await;
            match result {
                Ok((saved, installed, mut withdrawal, publication)) => {
                    let mut outcome = pending.kind.outcome(&saved);
                    if installed {
                        match &saved {
                            Saved::Text(rendered) => {
                                let _ = self.event_tx.send(NodeEvent::NewEntry {
                                    channel_id: room,
                                    row: row_of(rendered),
                                });
                                self.note_local_append(&room);
                            }
                            Saved::Governance(Some(_)) => self.note_local_governance_append(&room),
                            Saved::Governance(None) | Saved::OwnRetention { .. } => {}
                        }
                        if matches!(pending.kind, ReplyKind::Retention) {
                            self.retention_read_at = 0;
                            self.refresh_node_retention(self.now_ms());
                            self.retention_dirty.insert(room);
                        }
                        if matches!(pending.kind, ReplyKind::AddAdmin) {
                            self.governance_work.admin_rosters.insert(room);
                            self.governance_work.pending = true;
                            self.governance_work.again = true;
                        }
                        if let Some(withdrawal) = withdrawal.take() {
                            match withdrawal {
                                Ok(EndWithdrawal {
                                    pending: withdrawal,
                                }) => {
                                    self.withdrawn.insert(room, withdrawal);
                                    if let Some(net) = &self.net {
                                        if let Some(pending) = self.withdrawn.get(&room) {
                                            let _ = net.publish_local(&pending.wire);
                                            for board in pending.routes.keys() {
                                                if let Some(conn) = net.manager().existing(board) {
                                                    Self::put_withdraws(
                                                        &conn,
                                                        vec![pending.wire.clone()],
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(fault) => outcome = Outcome::Failed(fault),
                            }
                        }
                    }
                    if let Some(Err(fault)) = withdrawal {
                        outcome = Outcome::Failed(fault);
                    }
                    drop(publication);
                    self.publish().await;
                    if installed && !matches!(pending.kind, ReplyKind::Text) && outcome.is_done() {
                        self.queue_room_publication(
                            room,
                            Some(pending.reply),
                            outcome,
                            false,
                            if matches!(pending.kind, ReplyKind::Anchors) {
                                RoomPublicationKind::Anchors
                            } else {
                                RoomPublicationKind::Settings
                            },
                        );
                    } else {
                        let _ = pending.reply.send(outcome);
                    }
                }
                Err(fault) => {
                    #[cfg(feature = "mutant-sender")]
                    if matches!(pending.kind, ReplyKind::End)
                        && matches!(fault, Fault::NotCreator)
                        && crate::log::sync::mutant::withdraws_unentitled()
                    {
                        if let Some(authority) = pending.end_authority.clone() {
                            self.begin_metadata_mutant_withdrawal(
                                room,
                                metadata_save::MutantEndWithdrawal {
                                    authority,
                                    instance: pending.instance,
                                    attachment: pending.epoch,
                                    store: pending.store,
                                    secret: pending._secret,
                                    slot: pending._slot,
                                    reply: pending.reply,
                                },
                            )
                            .await;
                            self.continue_deferred_retention(room, retention).await;
                            if governance_owed {
                                self.continue_deferred_governance(room, &shared, pending.epoch);
                            }
                            continue;
                        }
                    }
                    self.publish().await;
                    let _ = pending.reply.send(Outcome::Failed(fault));
                }
            }
            self.continue_deferred_retention(room, retention).await;
            if governance_owed {
                self.continue_deferred_governance(room, &shared, pending.epoch);
            }
        }
    }

    /// Carry a skipped governance turn across native successors without making an occupied
    /// writer runnable. Lock and room replacement discard only the old attachment's debt.
    pub(super) fn continue_deferred_governance(
        &mut self,
        room: Digest32,
        instance: &SharedChannel,
        attachment: u64,
    ) {
        if attachment != self.delivery_epoch
            || !self
                .channels
                .get(&room)
                .is_some_and(|current| Arc::ptr_eq(current, instance))
        {
            return;
        }
        if let Some(successor) = self.pending_posts.get_mut(&room) {
            successor.owe_governance(instance, attachment);
        } else {
            self.governance_work.wake_room(room);
        }
    }

    async fn continue_deferred_retention(
        &mut self,
        room: Digest32,
        request: Option<(SharedChannel, u64)>,
    ) {
        let Some((instance, attachment)) = request else {
            return;
        };
        if attachment != self.delivery_epoch
            || !self
                .channels
                .get(&room)
                .is_some_and(|current| Arc::ptr_eq(current, &instance))
        {
            return;
        }
        if let Some(successor) = self.pending_posts.get_mut(&room) {
            successor.owe_retention(&instance, attachment);
            return;
        }
        self.sweep_retention_room(room, instance, attachment).await;
    }

    /// Lock/termination transfers retained replies to a joiner; cancellation never drops a
    /// physical save or turns a durable outcome into a fabricated unsent result.
    pub(super) fn retire_pending_posts(&mut self) {
        self.failed_post_reads.clear();
        let pending = std::mem::take(&mut self.pending_posts);
        for (_, pending) in pending {
            let pending = match pending {
                Pending::Append(pending) => pending,
                Pending::Maintenance(pending) => {
                    tokio::spawn(pending.retire());
                    continue;
                }
                Pending::Metadata(pending) => {
                    tokio::spawn(pending.retire());
                    continue;
                }
            };
            tokio::spawn(async move {
                let _secret = pending._secret;
                let _slot = pending._slot;
                let _ = pending.task.await;
                let returned = pending
                    .result
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                let outcome = match returned {
                    Some(Ok((completed, _publication, withdrawal))) => match completed.result {
                        Ok(saved) => match withdrawal {
                            Some(Err(fault)) => Outcome::Failed(fault),
                            _ => pending.kind.outcome(&saved),
                        },
                        Err(error) => Outcome::Failed(fault_of(&error)),
                    },
                    Some(Err(fault)) => Outcome::Failed(fault),
                    None => Outcome::Failed(Fault::Storage),
                };
                pending
                    .instance
                    .lock()
                    .await
                    .release_pending_text(&pending.owner, false);
                let _ = pending.reply.send(outcome);
            });
        }
    }
}

impl Node {
    pub(super) fn refresh_failed_post_reads(&mut self) {
        for (room, failed) in std::mem::take(&mut self.failed_post_reads) {
            let current = self.channels.get(&room).cloned();
            let Some(instance) = failed.instance.upgrade().filter(|instance| {
                current
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, instance))
            }) else {
                continue;
            };
            let refreshed = instance.try_lock().is_ok_and(|mut channel| {
                !channel.post_pending()
                    && channel
                        .publish_history_read(Arc::clone(&failed.store))
                        .is_ok()
            });
            if !refreshed {
                self.failed_post_reads.insert(room, failed);
            }
        }
    }

    #[cfg(feature = "test-knobs")]
    fn note_post_proof(&mut self, room: Digest32, rotated: bool) {
        let Some(arm) = std::env::var_os("VOX_TEST_FX28_ROTATE_AFTER_POST") else {
            return;
        };
        let marker = std::path::PathBuf::from(&arm).with_extension("result");
        let Ok(staged) = std::fs::read_to_string(&arm) else {
            return;
        };
        let fields: Vec<_> = staged.trim_end().split('\t').collect();
        let exact = self
            .paths
            .profile_dir
            .file_name()
            .and_then(|name| name.to_str())
            == fields.first().copied()
            && fields.get(1).copied() == Some(crate::node::link::b32_encode(&room).as_str());
        let action = match fields.as_slice() {
            [_, _] if exact => Some(None),
            [_, _, "release-paused", peer] if exact => {
                crate::node::link::b32_decode(peer, "FX-28 paused re-key peer")
                    .ok()
                    .map(Some)
            }
            _ => None,
        };
        let Some(peer) = action else {
            crate::node::computer::publish_proof_fault(
                &marker.with_extension("fault"),
                "post-side re-key arm differs from this exact node and room",
            );
            return;
        };
        if let Err(error) = std::fs::remove_file(&arm) {
            crate::node::computer::publish_proof_fault(
                &marker.with_extension("fault"),
                &format!("consume forced rotation arm: {error}"),
            );
            return;
        }
        let released_paused = peer.is_some_and(|peer| {
            let pair = (room, peer);
            if self.fx28_rekey_pause == Some(pair) && self.older.get(&pair) == Some(&false) {
                self.fx28_rekey_pause = None;
                true
            } else {
                crate::node::computer::publish_proof_fault(
                    &marker.with_extension("fault"),
                    "exact paused re-key selection did not survive",
                );
                false
            }
        });
        self.fx28_post_rekey.insert(
            room,
            PostProof {
                marker,
                rotated,
                release_requested: peer.is_some(),
                released_paused,
            },
        );
    }

    #[cfg(feature = "test-knobs")]
    pub(super) fn finish_post_proof(&mut self, room: &Digest32, delivered: u64) {
        let Some(proof) = self.fx28_post_rekey.remove(room) else {
            return;
        };
        let node = self
            .paths
            .profile_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("<unknown>");
        let _ = crate::node::computer::publish_proof_marker(&proof.marker, format!(
            "{node}\t{}\trotated={}\trelease_requested={}\treleased_paused={}\tcomplete_target_batches={delivered}\n",
            crate::node::link::b32_encode(room), proof.rotated, proof.release_requested, proof.released_paused,
        ).as_bytes());
    }
}
