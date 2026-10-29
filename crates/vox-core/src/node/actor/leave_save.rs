//! Leave, close and deletion retain the original command until their real native result.
use super::*;
use crate::atrest::vault::VaultRootSigner;
use crate::node::channel::pending_text::leave;
use crate::node::store::Store;

pub(super) use leave::{Completed, Prepared, Saved};
pub(super) struct Work {
    now: crate::time::Ms,
}
impl Work {
    pub(super) fn prepare(
        self,
        channel: &mut ChannelState,
        store: &Arc<Store>,
        owner: Arc<()>,
        _now: crate::time::Ms,
    ) -> crate::error::Result<Option<Prepared>> {
        channel.prepare_pending_leave(store, owner, self.now)
    }
}

pub(super) struct Continuation {
    instance: SharedChannel,
    attachment: u64,
    authority: computer::ComputerAuthority,
    secret: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    transition: Option<crate::node::channel::own_writer_gate::Transition>,
    lifetime: Option<Arc<maintenance_save::Lifetime>>,
}
impl Continuation {
    pub(super) fn instance(&self) -> &SharedChannel {
        &self.instance
    }
    pub(super) fn lifetime(&self) -> Option<Arc<maintenance_save::Lifetime>> {
        self.lifetime.as_ref().map(Arc::clone)
    }
    pub(super) fn authority(&self) -> computer::ComputerAuthority {
        self.authority.clone()
    }
    pub(super) fn secret(&self) -> Option<Arc<tokio::sync::OwnedRwLockReadGuard<()>>> {
        Some(Arc::clone(&self.secret))
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

/// The signed departure and its durable withdrawal are already installed. Network delivery
/// owes an acknowledgement, not another authored transaction: keeping a physical publication
/// reader here would make policy admission depend on Store-gated network scheduling.
pub(super) struct CommittedDeparture {
    instance: SharedChannel,
    attachment: u64,
    epoch: u64,
}

impl CommittedDeparture {
    pub(super) async fn current(&self, node: &Node, room: &Digest32) -> bool {
        self.attachment == node.delivery_epoch
            && node
                .channels
                .get(room)
                .is_some_and(|current| Arc::ptr_eq(current, &self.instance))
            && self.instance.lock().await.epoch() == self.epoch
    }
}

type Reply = Option<oneshot::Sender<Outcome>>;
type RetirementPermit = mpsc::OwnedPermit<crate::node::session_ingress::Retirement>;
enum NativeWork {
    Withdrawal {
        epoch: u64,
        now: u64,
        routes: BTreeMap<Digest32, Vec<std::net::SocketAddr>>,
    },
    Close,
    ForgetWithdrawal,
    Purge {
        paths: crate::node::paths::Paths,
        name: String,
        retirement: Option<RetirementPermit>,
    },
}
enum NativeSaved {
    Withdrawal(crate::error::Result<PendingWithdrawal>),
    Close(crate::error::Result<()>),
    ForgottenWithdrawal(crate::error::Result<()>),
    Purge {
        retirement: Option<crate::node::session_ingress::Retirement>,
        result: crate::error::Result<()>,
    },
    Failed(Error),
}
enum After {
    Withdrawal {
        departure: leave::Departure,
        continuation: Continuation,
        lifetime: Arc<maintenance_save::Lifetime>,
    },
    Close {
        transition: Option<crate::node::channel::own_writer_gate::Transition>,
    },
    Undone {
        purpose: LeftPurgePurpose,
    },
    Purge {
        transition: crate::node::channel::own_writer_gate::Transition,
        purpose: Option<LeftPurgePurpose>,
    },
}

struct MetadataOwner {
    room: Digest32,
    instance: Option<SharedChannel>,
    secret: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    lifetime: Option<Arc<maintenance_save::Lifetime>>,
}

/// One admitted metadata operation, not a queue. It uses the existing post-save wake.
pub(super) struct Pending {
    room: Digest32,
    instance: Option<SharedChannel>,
    attachment: u64,
    secret: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    lifetime: Option<Arc<maintenance_save::Lifetime>>,
    result: Arc<std::sync::Mutex<Option<NativeSaved>>>,
    task: Option<tokio::task::JoinHandle<()>>,
    after: After,
    reply: Reply,
}
impl Pending {
    pub(super) async fn retire(mut self) {
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        let saved = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        match self.after {
            After::Withdrawal { .. } => {
                let outcome = match saved {
                    Some(NativeSaved::Withdrawal(Err(error))) => Outcome::Failed(fault_of(&error)),
                    Some(NativeSaved::Withdrawal(Ok(_))) => Outcome::Failed(Fault::LeaveNotHeard),
                    _ => Outcome::Failed(Fault::Internal),
                };
                if let Some(reply) = self.reply {
                    let _ = reply.send(outcome);
                }
            }
            After::Close { .. } => {
                let outcome = match saved {
                    Some(NativeSaved::Close(result)) => {
                        if result.is_ok() {
                            if let Some(instance) = self.instance {
                                instance.lock().await.lock_now();
                            }
                        }
                        result
                            .map(|_| Outcome::Done)
                            .unwrap_or_else(|error| Outcome::Failed(fault_of(&error)))
                    }
                    _ => Outcome::Failed(Fault::Internal),
                };
                if let Some(reply) = self.reply {
                    let _ = reply.send(outcome);
                }
            }
            After::Undone { purpose } => {
                let fault = match saved {
                    Some(NativeSaved::ForgottenWithdrawal(Ok(()))) => Fault::LeaveUndone,
                    Some(NativeSaved::ForgottenWithdrawal(Err(error))) => fault_of(&error),
                    _ => Fault::Internal,
                };
                purpose.fail(fault);
            }
            After::Purge { purpose, .. } => {
                let outcome = match saved {
                    Some(NativeSaved::Purge { result, .. }) => result
                        .map(|_| Outcome::Done)
                        .unwrap_or_else(|error| Outcome::Failed(fault_of(&error))),
                    _ => Outcome::Failed(Fault::Internal),
                };
                match purpose {
                    Some(LeftPurgePurpose::Leave { replies, .. }) => {
                        for reply in replies {
                            let _ = reply.send(outcome);
                        }
                    }
                    Some(LeftPurgePurpose::Join { reply, .. }) => {
                        let _ = reply.send(if outcome.is_done() {
                            Outcome::Failed(Fault::Locked)
                        } else {
                            outcome
                        });
                    }
                    None => {}
                }
            }
        }
    }
}

fn native(
    work: NativeWork,
    room: Digest32,
    store: &Store,
    signer: &VaultRootSigner,
) -> NativeSaved {
    match work {
        NativeWork::Withdrawal { epoch, now, routes } => NativeSaved::Withdrawal((|| {
            let statement = crate::nat::withdraw::BoardWithdraw::build(
                signer,
                &room,
                epoch,
                crate::nat::withdraw::WithdrawScope::Member,
                now,
            )?;
            let pending = PendingWithdrawal {
                wire: statement.to_wire(),
                routes,
            };
            // Admission precedes the read: a concurrent canonical metadata writer is never lost.
            let mut batch = store.batch()?;
            let mut withdrawn = match store.get_meta(PENDING_WITHDRAWALS_META_KEY)? {
                Some(bytes) => read_pending_withdrawals(&bytes)?,
                None => BTreeMap::new(),
            };
            withdrawn.insert(room, pending.clone());
            batch.put_meta(
                PENDING_WITHDRAWALS_META_KEY,
                &pending_withdrawals_bytes(&withdrawn)?,
            )?;
            batch.commit()?;
            Ok(pending)
        })()),
        NativeWork::Close => NativeSaved::Close((|| {
            let mut batch = store.batch()?;
            metadata_save::MapChange::Forget(room).queue(store, signer, &mut batch)?;
            batch.commit()
        })()),
        NativeWork::ForgetWithdrawal => NativeSaved::ForgottenWithdrawal((|| {
            let mut batch = store.batch()?;
            let mut withdrawn = match store.get_meta(PENDING_WITHDRAWALS_META_KEY)? {
                Some(bytes) => read_pending_withdrawals(&bytes)?,
                None => BTreeMap::new(),
            };
            if withdrawn.remove(&room).is_some() {
                batch.put_meta(
                    PENDING_WITHDRAWALS_META_KEY,
                    &pending_withdrawals_bytes(&withdrawn)?,
                )?;
                batch.commit()?;
            }
            Ok(())
        })()),
        NativeWork::Purge {
            paths,
            name,
            retirement,
        } => {
            paths.remove_room_cursors(&crate::node::link::b32_encode(&room), &name);
            let mut committed_retirement = None;
            let result = (|| {
                let mut batch = store.batch()?;
                metadata_save::MapChange::Forget(room).queue(store, signer, &mut batch)?;
                let mut consents =
                    crate::node::pending_consent::PendingConsents::load(store, signer)?;
                if consents.forget_room(&room) {
                    consents.queue_save(&mut batch, signer)?;
                }
                let mut locks = crate::node::pending_lock::PendingLocks::load(store, signer)?;
                if locks.clear_room(&room) {
                    locks.queue_save(&mut batch, signer)?;
                }
                let pending = crate::node::session_ingress::queue_remove_room(
                    &mut batch,
                    signer,
                    &room,
                    retirement.is_some(),
                )?;
                batch.commit()?;
                committed_retirement = pending;
                if let (Some(permit), Some(pending)) = (retirement, pending) {
                    // This exact receipt is already durable. Rewrite failure cannot strand it.
                    permit.send(pending);
                }
                store.rewrite_fresh()
            })();
            NativeSaved::Purge {
                retirement: committed_retirement,
                result,
            }
        }
    }
}

/// A detached durable departure is not an unsent append, nor a completed leave.
pub(super) fn retire_detached(
    result: crate::error::Result<maintenance_save::Saved>,
    _next: Continuation,
    reply: Reply,
) {
    if let Some(reply) = reply {
        let outcome = match result {
            Ok(maintenance_save::Saved::Leave(_)) => Outcome::Failed(Fault::LeaveNotHeard),
            Ok(_) => Outcome::Failed(Fault::Internal),
            Err(error) => Outcome::Failed(fault_of(&error)),
        };
        let _ = reply.send(outcome);
    }
}

impl Node {
    pub(super) async fn begin_leave(
        &mut self,
        room: Digest32,
        reply: oneshot::Sender<Outcome>,
        transition: Option<crate::node::channel::own_writer_gate::Transition>,
        original_secret: Option<Arc<tokio::sync::OwnedRwLockReadGuard<()>>>,
        original_lifetime: Option<Arc<maintenance_save::Lifetime>>,
    ) {
        self.history_demand.retire_room(room);
        self.history_hints.retire_room(room);
        let Some(instance) = self.channels.get(&room).cloned() else {
            let held = self
                .profile
                .as_ref()
                .and_then(|profile| profile.store().channels().ok())
                .is_some_and(|channels| channels.contains(&room));
            let _ = reply.send(Outcome::Failed(if held {
                Fault::ChannelNotOpen
            } else {
                Fault::UnknownChannel
            }));
            return;
        };
        if self.net.is_none() {
            let _ = reply.send(Outcome::Failed(Fault::NotNetworked));
            return;
        }
        let Some(authority) = original_lifetime
            .as_ref()
            .map(|held| held.authority.clone())
            .or_else(|| self.computer_authority())
        else {
            let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
            return;
        };
        if self
            .profile
            .as_ref()
            .is_none_or(|profile| !profile.is_unlocked())
        {
            let _ = reply.send(Outcome::Failed(Fault::Locked));
            return;
        }
        let secret = match original_lifetime
            .as_ref()
            .map(|held| Arc::clone(&held.secret))
            .or(original_secret)
        {
            Some(secret) => secret,
            None => match self.secret_work.clone().try_read_owned() {
                Ok(secret) => Arc::new(secret),
                Err(_) => {
                    let _ = reply.send(Outcome::Failed(Fault::Locked));
                    return;
                }
            },
        };
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            authority,
            secret,
            transition,
            lifetime: original_lifetime,
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Leave(Work { now: self.now_ms() }),
            maintenance_save::Continuation::Leave(continuation),
            Some(reply),
        )
        .await;
    }

    pub(super) fn reject_owned_leave(
        &mut self,
        _room: Digest32,
        error: Error,
        _next: Continuation,
        reply: Reply,
    ) {
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(fault_of(&error)));
        }
    }

    pub(super) async fn finish_owned_leave(
        &mut self,
        room: Digest32,
        result: crate::error::Result<maintenance_save::Saved>,
        lifetime: Arc<maintenance_save::Lifetime>,
        mut next: Continuation,
        reply: Reply,
    ) {
        if !next.attached(self, &room) {
            retire_detached(result, next, reply);
            return;
        }
        let departure = match result {
            Ok(maintenance_save::Saved::Leave(Saved::Installed(saved))) => saved,
            Ok(_) => {
                self.reject_owned_leave(
                    room,
                    Error::Profile("departure save has no matching receipt"),
                    next,
                    reply,
                );
                return;
            }
            Err(error) => {
                self.reject_owned_leave(room, error, next, reply);
                return;
            }
        };
        {
            let mut channel = next.instance.lock().await;
            match detail_of(
                &channel,
                &lifetime.store,
                None,
                self.now_ms(),
                &self.display_sequence,
            ) {
                Ok(detail) => {
                    let rows = detail.display_stamp.rows();
                    self.fresh_details
                        .insert(room, (summary_of(&channel, rows), detail));
                }
                Err(error) => detail_failed(&mut channel, &error),
            }
        }
        // As before, the physical own-key retirement ends only after the matching departure.
        drop(next.transition.take());
        self.cancel_own_key_room(room);
        let work = NativeWork::Withdrawal {
            epoch: departure.epoch,
            now: self.now_ms().get(),
            routes: self.withdrawal_routes(&room),
        };
        let instance = Some(Arc::clone(&next.instance));
        let secret = Arc::clone(&next.secret);
        self.begin_leave_metadata(
            MetadataOwner {
                room,
                instance,
                secret,
                lifetime: Some(Arc::clone(&lifetime)),
            },
            work,
            After::Withdrawal {
                departure,
                continuation: next,
                lifetime,
            },
            reply,
        );
    }

    fn begin_leave_metadata(
        &mut self,
        owner: MetadataOwner,
        work: NativeWork,
        after: After,
        reply: Reply,
    ) {
        let MetadataOwner {
            room,
            instance,
            secret,
            lifetime,
        } = owner;
        if self.pending_policy.is_some() && lifetime.is_none() {
            self.reject_leave_metadata(after, reply, Fault::RoomChangePending);
            return;
        }
        let Some(profile) = self
            .profile
            .as_ref()
            .filter(|profile| profile.is_unlocked())
        else {
            self.reject_leave_metadata(after, reply, Fault::Locked);
            return;
        };
        let store = lifetime
            .as_ref()
            .map_or_else(|| profile.store_handle(), |held| Arc::clone(&held.store));
        let signer = match lifetime
            .as_ref()
            .map(|held| Arc::clone(&held.signer))
            .map(Ok)
            .unwrap_or_else(|| profile.signer_arc())
        {
            Ok(signer) => signer,
            Err(error) => {
                self.reject_leave_metadata(after, reply, fault_of(&error));
                return;
            }
        };
        let result = Arc::new(std::sync::Mutex::new(None));
        let output = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        let held_secret = Arc::clone(&secret);
        let held_lifetime = lifetime.as_ref().map(Arc::clone);
        let task = tokio::spawn(async move {
            let saved = tokio::task::spawn_blocking(move || {
                let _secret = held_secret;
                let _lifetime = held_lifetime;
                native(work, room, &store, &signer)
            })
            .await;
            let saved = saved.unwrap_or_else(|_| {
                NativeSaved::Failed(Error::Profile("native leave metadata worker stopped"))
            });
            *output
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(saved);
            wake.notify_one();
        });
        let retained = lifetime.is_some() && self.pending_policy.is_some();
        let mut pending = Pending {
            room,
            instance,
            attachment: self.delivery_epoch,
            secret,
            lifetime,
            result,
            task: Some(task),
            after,
            reply,
        };
        if retained {
            // The original departure already owns publication admission. Its causal metadata
            // must not wait in the fresh policy slot behind the writer that reader blocks.
            let completions = Arc::clone(&self.own_key_completions);
            let epoch = completions.lifecycle_epoch();
            tokio::spawn(async move {
                if let Some(task) = pending.task.take() {
                    let _ = task.await;
                }
                completions.complete_lifecycle(epoch, Ready::LeaveMetadata(Box::new(pending)));
            });
        } else {
            self.pending_policy = Some(policy_save::Pending::Leave(pending));
        }
    }

    fn reject_leave_metadata(&mut self, after: After, reply: Reply, fault: Fault) {
        match after {
            After::Purge {
                purpose: Some(purpose),
                ..
            }
            | After::Undone { purpose } => purpose.fail(fault),
            _ => {}
        }
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(fault));
        }
    }

    pub(super) fn begin_owned_leave_undone(
        &mut self,
        room: Digest32,
        instance: SharedChannel,
        purpose: LeftPurgePurpose,
        secret: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    ) {
        let lifetime = match &purpose {
            LeftPurgePurpose::Leave { lifetimes, .. } => lifetimes.first().map(Arc::clone),
            _ => None,
        };
        self.begin_leave_metadata(
            MetadataOwner {
                room,
                instance: Some(instance),
                secret,
                lifetime,
            },
            NativeWork::ForgetWithdrawal,
            After::Undone { purpose },
            None,
        );
    }

    pub(super) async fn begin_owned_close(
        &mut self,
        room: Digest32,
        reply: oneshot::Sender<Outcome>,
        transition: Option<crate::node::channel::own_writer_gate::Transition>,
        original_secret: Option<Arc<tokio::sync::OwnedRwLockReadGuard<()>>>,
    ) {
        self.history_demand.retire_room(room);
        self.history_hints.retire_room(room);
        let held = self.channels.contains_key(&room)
            || self.reopening.contains(&room)
            || self.opening_rooms.contains_key(&room)
            || self.preparing_rooms.contains_key(&room)
            || self.publish_waiters.contains_key(&room);
        if !held {
            let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
            return;
        }
        let secret = match original_secret {
            Some(secret) => secret,
            None => match self.secret_work.clone().try_read_owned() {
                Ok(secret) => Arc::new(secret),
                Err(_) => {
                    let _ = reply.send(Outcome::Failed(Fault::Locked));
                    return;
                }
            },
        };
        let instance = self.channels.get(&room).cloned();
        self.begin_leave_metadata(
            MetadataOwner {
                room,
                instance,
                secret,
                lifetime: None,
            },
            NativeWork::Close,
            After::Close { transition },
            Some(reply),
        );
    }

    fn refuse_owned_purge(
        &mut self,
        room: Digest32,
        purpose: Option<LeftPurgePurpose>,
        fault: Fault,
    ) {
        if let Some(purpose) = purpose {
            if self.channels.contains_key(&room) {
                self.sched_rooms.insert(room);
                self.discover_rooms.insert(room);
            }
            purpose.fail(fault);
        }
    }

    pub(super) async fn begin_owned_purge(
        &mut self,
        room: Digest32,
        instance: SharedChannel,
        transition: crate::node::channel::own_writer_gate::Transition,
        mut channel: tokio::sync::OwnedMutexGuard<ChannelState>,
        purpose: Option<LeftPurgePurpose>,
        secret: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    ) {
        self.history_demand.retire_room(room);
        self.history_hints.retire_room(room);
        if self.pending_policy.is_some()
            && !matches!(&purpose, Some(LeftPurgePurpose::Leave { lifetimes, .. }) if !lifetimes.is_empty())
        {
            self.refuse_owned_purge(room, purpose, Fault::RoomChangePending);
            return;
        }
        if self
            .session_rooms_retiring
            .iter()
            .any(|pending| pending.room == room)
        {
            self.refuse_owned_purge(room, purpose, Fault::SessionCleanupBusy);
            return;
        }
        let Some(profile) = self.profile.as_ref() else {
            self.refuse_owned_purge(room, purpose, Fault::NoIdentity);
            return;
        };
        match crate::node::session_ingress::retirements(profile) {
            Ok(pending)
                if pending.iter().any(|pending| pending.room == room)
                    || (self.session_room_removed.is_some() && pending.len() == 2) =>
            {
                self.refuse_owned_purge(room, purpose, Fault::SessionCleanupBusy);
                return;
            }
            Err(error) => {
                self.refuse_owned_purge(room, purpose, fault_of(&error));
                return;
            }
            Ok(_) => {}
        }
        let retirement = match &self.session_room_removed {
            None => None,
            Some(owner) => match owner.clone().try_reserve_owned() {
                Ok(permit) => Some(permit),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.refuse_owned_purge(room, purpose, Fault::SessionCleanupBusy);
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.refuse_owned_purge(room, purpose, Fault::SessionCleanupUnavailable);
                    return;
                }
            },
        };
        let name = crate::node::resolver::room_shown(channel.name(), &room);
        // Preserve the original purge fence before any native writer can admit a publisher.
        self.cancel_own_key_room(room);
        channel.lock_now();
        drop(channel);
        let lifetime = match &purpose {
            Some(LeftPurgePurpose::Leave { lifetimes, .. }) => lifetimes.first().map(Arc::clone),
            _ => None,
        };
        self.begin_leave_metadata(
            MetadataOwner {
                room,
                instance: Some(instance),
                secret,
                lifetime,
            },
            NativeWork::Purge {
                paths: self.paths.clone(),
                name,
                retirement,
            },
            After::Purge {
                transition,
                purpose,
            },
            None,
        );
    }

    pub(super) async fn complete_leave_save(&mut self, mut pending: Pending) {
        let saved = pending
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(saved) = saved else {
            self.pending_policy = Some(policy_save::Pending::Leave(pending));
            return;
        };
        let current = pending.attachment == self.delivery_epoch
            && pending.instance.as_ref().is_none_or(|instance| {
                self.channels
                    .get(&pending.room)
                    .is_some_and(|current| Arc::ptr_eq(current, instance))
            });
        if let Some(task) = pending.task.take() {
            let _ = task.await;
        }
        let room = pending.room;
        let _secret = pending.secret;
        let _lifetime = pending.lifetime;
        match (pending.after, saved) {
            (
                After::Withdrawal {
                    departure,
                    continuation,
                    lifetime,
                },
                NativeSaved::Withdrawal(result),
            ) => {
                let withdrawal = match result {
                    Ok(withdrawal) => withdrawal,
                    Err(error) => {
                        self.reject_owned_leave(room, error, continuation, pending.reply);
                        return;
                    }
                };
                if !current || !continuation.attached(self, &room) {
                    if let Some(reply) = pending.reply {
                        let _ = reply.send(Outcome::Failed(Fault::LeaveNotHeard));
                    }
                    return;
                }
                self.withdrawn.insert(room, withdrawal.clone());
                if let Some(net) = self.net.as_ref() {
                    let _ = net.publish_local(&withdrawal.wire);
                    for board in withdrawal.routes.keys() {
                        if let Some(connection) = net.manager().existing(board) {
                            Self::put_withdraws(&connection, vec![withdrawal.wire.clone()]);
                        }
                    }
                }
                if departure.alone {
                    let replies = pending.reply.into_iter().collect();
                    self.begin_own_key_left_purge(
                        room,
                        continuation.instance,
                        LeftPurgePurpose::Leave {
                            replies,
                            lifetimes: vec![lifetime],
                        },
                    )
                    .await;
                } else {
                    let committed = CommittedDeparture {
                        instance: Arc::clone(&continuation.instance),
                        attachment: continuation.attachment,
                        epoch: departure.epoch,
                    };
                    // Both native workers and their matching actor installs have completed:
                    // the signed Presence(false), then the durable PendingWithdrawal. Retire
                    // their physical admission before waiting for a peer. A later purge is a
                    // new local cleanup under then-current admission, never a replayed leave.
                    drop(continuation);
                    drop(lifetime);
                    drop(_lifetime);
                    drop(_secret);
                    self.wait_for_leave(room, departure.generation, pending.reply, Some(committed))
                        .await;
                }
            }
            (After::Close { transition }, NativeSaved::Close(result)) => {
                let outcome = match result {
                    Ok(()) if current => self.finish_saved_close(&room, transition).await,
                    Ok(()) => Outcome::Failed(Fault::ChannelNotOpen),
                    Err(error) => Outcome::Failed(fault_of(&error)),
                };
                if let Some(reply) = pending.reply {
                    let _ = reply.send(outcome);
                }
            }
            (
                After::Purge {
                    transition,
                    purpose,
                },
                NativeSaved::Purge { retirement, result },
            ) => {
                if let Some(retirement) = retirement {
                    self.session_rooms_retiring.insert(retirement);
                }
                let outcome = if current {
                    self.finish_saved_purge(&room, transition, result).await
                } else {
                    result
                        .map(|_| Outcome::Done)
                        .unwrap_or_else(|error| Outcome::Failed(fault_of(&error)))
                };
                match purpose {
                    Some(LeftPurgePurpose::Join {
                        link,
                        passphrase,
                        reply,
                    }) => {
                        if outcome.is_done() && current {
                            self.begin_join_channel(link, passphrase, reply).await;
                        } else {
                            let _ = reply.send(if outcome.is_done() {
                                Outcome::Failed(Fault::ChannelNotOpen)
                            } else {
                                outcome
                            });
                        }
                    }
                    Some(LeftPurgePurpose::Leave { replies, .. }) => {
                        for reply in replies {
                            let _ = reply.send(outcome);
                        }
                    }
                    None => {}
                }
            }
            (After::Undone { purpose }, NativeSaved::ForgottenWithdrawal(result)) => {
                let fault = match result {
                    Ok(()) => {
                        if current {
                            self.withdrawn.remove(&room);
                        }
                        Fault::LeaveUndone
                    }
                    Err(error) => fault_of(&error),
                };
                purpose.fail(fault);
            }
            (after, NativeSaved::Failed(error)) => {
                self.reject_leave_metadata(after, pending.reply, fault_of(&error))
            }
            (after, _) => self.reject_leave_metadata(after, pending.reply, Fault::Internal),
        }
    }

    async fn finish_saved_close(
        &mut self,
        room: &Digest32,
        transition: Option<crate::node::channel::own_writer_gate::Transition>,
    ) -> Outcome {
        if let Some(net) = self.net.as_ref() {
            net.forget_board_exchange_room(room);
        }
        self.key_package_rooms.remove(room);
        self.cancel_private_pulls(Some(*room));
        self.cancel_own_key_room(*room);
        self.own_recovery_rooms.remove(room);
        self.own_recovery_body_debts.remove(room);
        self.own_readable_effects.remove(room);
        self.governance_work.set_deadline(*room, None);
        self.legacy_cleanup_rooms.remove(room);
        let preparing = self.cancel_room_preparation(room, Fault::ChannelNotOpen);
        let reopening = self.reopening.remove(room);
        if self.channels.contains_key(room) {
            self.own_key_room_set_changed.send_replace(());
        }
        let removed = self.channels.remove(room);
        drop(transition);
        let outcome = match removed {
            Some(shared) => {
                shared.lock().await.lock_now();
                if let Some(net) = self.net.as_ref() {
                    net.membership().clear_channel(room);
                }
                self.on_board.retain(|(r, _)| r != room);
                self.board_routes.retain(|(r, _), _| r != room);
                self.publish_trouble.retain(|(r, _), _| r != room);
                self.anchor_owed.retain(|(r, _), _| r != room);
                let (closed, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.address_waiters)
                    .into_iter()
                    .partition(|(r, _, _)| r == room);
                self.address_waiters = waiting;
                for (_, reply, _) in closed {
                    let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                }
                self.refresh_network_view().await;
                let _ = self
                    .event_tx
                    .send(NodeEvent::ChannelClosed { channel_id: *room });
                Outcome::Done
            }
            None if preparing || reopening => Outcome::Done,
            None => Outcome::Failed(Fault::ChannelNotOpen),
        };
        if outcome.is_done() {
            self.publish().await;
        }
        outcome
    }

    async fn finish_saved_purge(
        &mut self,
        room: &Digest32,
        transition: crate::node::channel::own_writer_gate::Transition,
        result: crate::error::Result<()>,
    ) -> Outcome {
        if let Some(net) = self.net.as_ref() {
            net.forget_board_exchange_room(room);
        }
        self.cancel_room_preparation(room, Fault::UnknownChannel);
        let (overtaken, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.leave_waiters)
            .into_iter()
            .partition(|(r, _, _, _, _)| r == room);
        self.leave_waiters = waiting;
        for reply in overtaken
            .into_iter()
            .filter_map(|(_, _, reply, _, _)| reply)
        {
            let _ = reply.send(Outcome::Failed(Fault::LeaveUndone));
        }
        self.key_package_rooms.remove(room);
        self.cancel_private_pulls(Some(*room));
        self.own_recovery_rooms.remove(room);
        self.own_recovery_body_debts.remove(room);
        self.own_readable_effects.remove(room);
        self.governance_work.set_deadline(*room, None);
        if self.channels.contains_key(room) {
            self.own_key_room_set_changed.send_replace(());
        }
        self.channels.remove(room);
        drop(transition);
        self.reopening.remove(room);
        if let Some(net) = self.net.as_ref() {
            net.membership().clear_channel(room);
        }
        let peers: Vec<Digest32> = self
            .ports
            .keys()
            .filter(|(r, _)| r == room)
            .map(|(_, peer)| *peer)
            .collect();
        for peer in peers {
            self.drop_port(room, &peer);
        }
        self.winding.remove(room);
        self.records_renew_at.remove(room);
        self.publish_failures.retain(|(r, _), _| r != room);
        self.departed_seen.remove(room);
        self.fresh_details.remove(room);
        // Away anchors retain their exact durable withdrawal, including every assigned route.
        self.room_anchors.remove(room);
        if let Some(net) = self.net.as_ref() {
            self.sync_anchor_scopes(net);
        }
        if let Some(reachers) = self.reachers.remove(room) {
            crate::node::tunnel::publish_reachers(&reachers, BTreeSet::new());
        }
        self.app.set_reachers(&self.reachers);
        crate::node::status::SyncBook::forget_room(&self.sync_book, room);
        self.sched_rooms.remove(room);
        self.discover_rooms.remove(room);
        self.consent_keys.forget_room(room);
        if let Err(error) = result {
            self.refresh_network_view().await;
            self.publish().await;
            return Outcome::Failed(fault_of(&error));
        }
        self.deliveries.retain(|(r, _, _), _| r != room);
        self.delivery_reserved.retain(|(r, _, _), _| r != room);
        self.key_waiting.retain(|(r, _), _| r != room);
        self.key_delivery_settling.retain(|(r, _)| r != room);
        self.refresh_network_view().await;
        self.publish().await;
        let _ = self
            .event_tx
            .send(NodeEvent::RoomRemoved { channel_id: *room });
        Outcome::Done
    }
}

/// Original lifecycle results, retained independently of bounded network ingress.
/// Results retain original ownership; recovery's caller and reader stay in preparing_rooms.
pub(super) enum Ready {
    DonorResume(Box<own_keys::DonorResume>),
    Donor(Box<own_keys::DonorReady>),
    LeaveMetadata(Box<Pending>),
    Recovery {
        room: Digest32,
        owner: Arc<()>,
        transition: Option<crate::node::channel::own_writer_gate::Transition>,
    },
    Untrust {
        _secret: own_keys::SecretLease,
        owner: Arc<()>,
        rooms: Vec<(Digest32, SharedChannel)>,
        transitions: Option<Vec<crate::node::channel::own_writer_gate::Transition>>,
        journal: Option<crate::node::computer::ComputerJournalWriter>,
        command: NodeCommand,
        reply: oneshot::Sender<Outcome>,
    },
    Leave {
        _secret: own_keys::SecretLease,
        room: Digest32,
        instance: SharedChannel,
        owner: Arc<()>,
        transition: Option<crate::node::channel::own_writer_gate::Transition>,
        lifetime: std::result::Result<Arc<maintenance_save::Lifetime>, Fault>,
        retired: Option<bounded_sync::RetiredRoom>,
        reply: oneshot::Sender<Outcome>,
    },
    Close {
        _secret: own_keys::SecretLease,
        room: Digest32,
        instance: Option<SharedChannel>,
        owner: Arc<()>,
        transition: Option<crate::node::channel::own_writer_gate::Transition>,
        retired: Option<bounded_sync::RetiredRoom>,
        reply: oneshot::Sender<Outcome>,
    },
    LeftPurge {
        _secret: own_keys::SecretLease,
        room: Digest32,
        instance: SharedChannel,
        owner: Arc<()>,
        transition: Option<crate::node::channel::own_writer_gate::Transition>,
        retired: Option<bounded_sync::RetiredRoom>,
        admission_fault: Option<Fault>,
        purpose: LeftPurgePurpose,
    },
    EndedPurge {
        _secret: own_keys::SecretLease,
        room: Digest32,
        instance: SharedChannel,
        owner: Arc<()>,
        transition: Option<crate::node::channel::own_writer_gate::Transition>,
        retired: Option<bounded_sync::RetiredRoom>,
    },
}

impl Ready {
    /// Lock retires the original command, not its already-completed physical work. A late
    /// producer uses the same path after its completion generation has been retired.
    pub(super) fn retire(self) {
        match self {
            Self::DonorResume(ready) => own_keys::retire_donor_resume(*ready),
            Self::Donor(ready) => own_keys::retire_donor(*ready),
            Self::LeaveMetadata(pending) => {
                tokio::spawn(pending.retire());
            }
            Self::Recovery { .. } => {}
            Self::Untrust { reply, .. } => {
                let _ = reply.send(Outcome::Failed(Fault::Locked));
            }
            Self::Leave {
                lifetime,
                retired,
                reply,
                ..
            } => {
                let fault = retired
                    .as_ref()
                    .and_then(|retired| retired.failure())
                    .map(fault_of)
                    .or_else(|| lifetime.err())
                    .unwrap_or(Fault::Locked);
                let _ = reply.send(Outcome::Failed(fault));
            }
            Self::Close { retired, reply, .. } => {
                let fault = retired
                    .as_ref()
                    .and_then(|retired| retired.failure())
                    .map(fault_of)
                    .unwrap_or(Fault::Locked);
                let _ = reply.send(Outcome::Failed(fault));
            }
            Self::LeftPurge {
                retired,
                admission_fault,
                purpose,
                ..
            } => {
                let fault = retired
                    .as_ref()
                    .and_then(|retired| retired.failure())
                    .map(fault_of)
                    .or(admission_fault)
                    .unwrap_or(Fault::Locked);
                purpose.fail(fault);
            }
            Self::EndedPurge { .. } => {}
        }
    }
}

impl Node {
    pub(super) async fn complete_lifecycle(&mut self, ready: Ready) {
        match ready {
            Ready::DonorResume(ready) => self.resume_own_key_donor(*ready),
            Ready::Donor(ready) => self.finish_own_key_donor(*ready),
            Ready::LeaveMetadata(pending) => self.complete_leave_save(*pending).await,
            Ready::Recovery {
                room,
                owner,
                transition,
            } => {
                if let Some(prepared) = self.preparing_rooms.get_mut(&room) {
                    if matches!(&prepared.recovery_writer_gate, Some(RecoveryWriterGate::Waiting { owner: current, .. }) if Arc::ptr_eq(current, &owner))
                    {
                        prepared.recovery_writer_gate = transition.map(RecoveryWriterGate::Ready);
                        prepared.legacy_cleanup_due = None;
                        self.preparation_after = None;
                    }
                }
            }
            Ready::Untrust {
                _secret,
                owner,
                rooms,
                transitions,
                journal,
                command,
                reply,
            } => {
                if !self
                    .own_key_untrust_pending
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &owner))
                {
                    let _ = reply.send(Outcome::Failed(Fault::RoomChangePending));
                } else {
                    self.own_key_untrust_pending = None;
                    let current = rooms.len() == self.channels.len()
                        && rooms.iter().all(|(room, instance)| {
                            self.channels
                                .get(room)
                                .is_some_and(|current| Arc::ptr_eq(current, instance))
                        });
                    if reply.is_closed() {
                        drop(transitions);
                    } else if current {
                        if let Some(transitions) = transitions {
                            self.begin_owned_untrust(command, reply, _secret, journal, transitions)
                                .await;
                        } else {
                            let _ = reply.send(Outcome::Failed(Fault::RoomChangePending));
                        }
                    } else {
                        drop(transitions);
                        self.begin_own_key_untrust(command, reply);
                    }
                }
            }
            Ready::Leave {
                _secret,
                room,
                instance,
                owner,
                transition,
                lifetime,
                retired,
                reply,
            } => {
                if let Some(retired) = retired {
                    if let Err(error) =
                        self.finish_bounded_room_retirement(retired, transition.is_some())
                    {
                        if self
                            .own_key_leave_pending
                            .get(&room)
                            .is_some_and(|current| Arc::ptr_eq(current, &owner))
                        {
                            self.own_key_leave_pending.remove(&room);
                        }
                        if self.publish_waiters.contains_key(&room) {
                            self.publication_pending = true;
                            self.publication_again = true;
                        }
                        let _ = reply.send(Outcome::Failed(fault_of(&error)));
                        return;
                    }
                }
                if !self
                    .own_key_leave_pending
                    .get(&room)
                    .is_some_and(|current| Arc::ptr_eq(current, &owner))
                {
                    let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                } else {
                    self.own_key_leave_pending.remove(&room);
                    if self.publish_waiters.contains_key(&room) {
                        self.publication_pending = true;
                        self.publication_again = true;
                    }
                    if reply.is_closed() {
                        drop(transition);
                    } else {
                        match lifetime {
                            Err(fault) => {
                                let _ = reply.send(Outcome::Failed(fault));
                            }
                            Ok(lifetime) => {
                                if self
                                    .channels
                                    .get(&room)
                                    .is_some_and(|current| Arc::ptr_eq(current, &instance))
                                {
                                    if let Some(transition) = transition {
                                        self.begin_leave(
                                            room,
                                            reply,
                                            Some(transition),
                                            Some(_secret),
                                            Some(lifetime),
                                        )
                                        .await;
                                    } else {
                                        let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                                    }
                                } else {
                                    let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                                }
                            }
                        }
                    }
                }
            }
            Ready::Close {
                _secret,
                room,
                instance,
                owner,
                transition,
                retired,
                reply,
            } => {
                if let Some(retired) = retired {
                    if let Err(error) =
                        self.finish_bounded_room_retirement(retired, transition.is_some())
                    {
                        if self
                            .own_key_leave_pending
                            .get(&room)
                            .is_some_and(|current| Arc::ptr_eq(current, &owner))
                        {
                            self.own_key_leave_pending.remove(&room);
                        }
                        if self.publish_waiters.contains_key(&room) {
                            self.publication_pending = true;
                            self.publication_again = true;
                        }
                        let _ = reply.send(Outcome::Failed(fault_of(&error)));
                        return;
                    }
                }
                if !self
                    .own_key_leave_pending
                    .get(&room)
                    .is_some_and(|current| Arc::ptr_eq(current, &owner))
                {
                    let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                } else {
                    self.own_key_leave_pending.remove(&room);
                    if self.publish_waiters.contains_key(&room) {
                        self.publication_pending = true;
                        self.publication_again = true;
                    }
                    if reply.is_closed() {
                        drop(transition);
                    } else if instance.as_ref().is_none_or(|instance| {
                        self.channels
                            .get(&room)
                            .is_some_and(|current| Arc::ptr_eq(current, instance))
                            && transition.is_some()
                    }) {
                        self.begin_owned_close(room, reply, transition, Some(_secret))
                            .await;
                    } else {
                        let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                    }
                }
            }
            Ready::LeftPurge {
                _secret,
                room,
                instance,
                owner,
                transition,
                retired,
                admission_fault,
                purpose,
            } => {
                if let Some(retired) = retired {
                    if let Err(error) =
                        self.finish_bounded_room_retirement(retired, transition.is_some())
                    {
                        if self
                            .own_key_ended_pending
                            .get(&room)
                            .is_some_and(|current| Arc::ptr_eq(current, &owner))
                        {
                            self.own_key_ended_pending.remove(&room);
                        }
                        if self
                            .channels
                            .get(&room)
                            .is_some_and(|current| Arc::ptr_eq(current, &instance))
                        {
                            self.sched_rooms.insert(room);
                            self.discover_rooms.insert(room);
                        }
                        purpose.fail(fault_of(&error));
                        return;
                    }
                }
                if let Some(fault) = admission_fault {
                    if self
                        .own_key_ended_pending
                        .get(&room)
                        .is_some_and(|current| Arc::ptr_eq(current, &owner))
                    {
                        self.own_key_ended_pending.remove(&room);
                    }
                    purpose.fail(fault);
                    return;
                }
                if !self
                    .own_key_ended_pending
                    .get(&room)
                    .is_some_and(|current| Arc::ptr_eq(current, &owner))
                {
                    purpose.fail(Fault::ChannelNotOpen);
                } else if let Some(transition) = transition {
                    if !self
                        .channels
                        .get(&room)
                        .is_some_and(|current| Arc::ptr_eq(current, &instance))
                    {
                        self.own_key_ended_pending.remove(&room);
                        purpose.fail(Fault::ChannelNotOpen);
                    } else {
                        match Arc::clone(&instance).try_lock_owned() {
                            Err(_) => self.wait_own_key_left_room(
                                room, instance, owner, transition, purpose, _secret,
                            ),
                            Ok(channel) if !channel.has_left(&channel.me()) => {
                                drop(channel);
                                drop(transition);
                                self.own_key_ended_pending.remove(&room);
                                self.sched_rooms.insert(room);
                                self.discover_rooms.insert(room);
                                self.begin_owned_leave_undone(room, instance, purpose, _secret);
                            }
                            Ok(channel) => {
                                self.own_key_ended_pending.remove(&room);
                                self.begin_owned_purge(
                                    room,
                                    instance,
                                    transition,
                                    channel,
                                    Some(purpose),
                                    _secret,
                                )
                                .await;
                            }
                        }
                    }
                } else {
                    self.own_key_ended_pending.remove(&room);
                    if self
                        .channels
                        .get(&room)
                        .is_some_and(|current| Arc::ptr_eq(current, &instance))
                    {
                        self.sched_rooms.insert(room);
                        self.discover_rooms.insert(room);
                    }
                    purpose.fail(Fault::ChannelNotOpen);
                }
            }
            Ready::EndedPurge {
                _secret,
                room,
                instance,
                owner,
                transition,
                retired,
            } => {
                if let Some(retired) = retired {
                    if let Err(error) =
                        self.finish_bounded_room_retirement(retired, transition.is_some())
                    {
                        if self
                            .own_key_ended_pending
                            .get(&room)
                            .is_some_and(|current| Arc::ptr_eq(current, &owner))
                        {
                            self.own_key_ended_pending.remove(&room);
                        }
                        let _ = self.event_tx.send(NodeEvent::NodeNote {
                            note: format!("ended room cleanup stopped: {error}"),
                        });
                        return;
                    }
                }
                if self
                    .own_key_ended_pending
                    .get(&room)
                    .is_some_and(|current| Arc::ptr_eq(current, &owner))
                {
                    if let Some(transition) = transition {
                        if self
                            .channels
                            .get(&room)
                            .is_some_and(|current| Arc::ptr_eq(current, &instance))
                        {
                            match Arc::clone(&instance).try_lock_owned() {
                                Ok(channel) => {
                                    let ended = channel.ended(self.now_ms().get()).is_some();
                                    let pending =
                                        self.publish_waiters.get(&room).is_some_and(|waiting| {
                                            waiting.kind != RoomPublicationKind::Open
                                        });
                                    if ended && !pending && self.winding.contains_key(&room) {
                                        let members: Vec<_> = channel
                                            .members()
                                            .into_iter()
                                            .filter(|peer| *peer != channel.me())
                                            .collect();
                                        let winding = &self.winding[&room];
                                        let handed = members
                                            .iter()
                                            .filter(|peer| {
                                                self.ports.get(&(room, **peer)).is_some_and(
                                                    |port| port.done_gen >= winding.gen,
                                                )
                                            })
                                            .count();
                                        if handed >= members.len()
                                            || winding.since.elapsed() >= WIND_DOWN
                                        {
                                            self.own_key_ended_pending.remove(&room);
                                            self.winding.remove(&room);
                                            let _ = self.event_tx.send(NodeEvent::RoomEnded {
                                                channel_id: room,
                                                handed,
                                                members: members.len(),
                                            });
                                            self.begin_owned_purge(
                                                room, instance, transition, channel, None, _secret,
                                            )
                                            .await;
                                            return;
                                        }
                                    }
                                    drop(channel);
                                    drop(transition);
                                    self.own_key_ended_pending.remove(&room);
                                    self.sched_rooms.insert(room);
                                    self.discover_rooms.insert(room);
                                }
                                Err(_) => {
                                    self.wait_own_key_ended_room(
                                        room, instance, owner, transition, _secret,
                                    );
                                }
                            }
                        } else {
                            self.own_key_ended_pending.remove(&room);
                        }
                    } else {
                        self.own_key_ended_pending.remove(&room);
                        self.sched_rooms.insert(room);
                    }
                }
            }
        }
    }
}
