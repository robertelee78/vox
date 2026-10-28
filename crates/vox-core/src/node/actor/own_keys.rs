//! One-shot self-author key recovery. These messages confer no reading permission and share
//! neither ordinary sender-delivery receipts nor the pair's long-lived ratchet.
use super::*;
use crate::cbor::{Decoder, Encoder};
use zeroize::Zeroizing;

/// A prepared ciphertext owns its shared byte credit and peer admission through the actor
/// handoff and actual socket write. It contains no session or plaintext key material.
enum DonorWait {
    Room(SharedChannel),
    Secret(Arc<tokio::sync::RwLock<()>>),
    Capacity(
        Arc<Semaphore>,
        Arc<Semaphore>,
        tokio::sync::mpsc::Sender<PairwiseJob>,
    ),
}

pub(super) struct DonorReady {
    peer: Digest32,
    node: Digest32,
    connection: Arc<VoxConnection>,
    room: SharedChannel,
    context: crate::join::session::JoinContext,
    frame: crate::error::Result<Vec<u8>>,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    credit: PairwiseCredit,
    output: crate::node::history_budget::OutputCharge,
    input_credit: Option<OwnedSemaphorePermit>,
    secret: SecretLease,
}

pub(super) struct DonorBusy {
    owner: Arc<()>,
    connection: Arc<VoxConnection>,
    instance: SharedChannel,
    ready: bool,
    waiting: bool,
    cancel: tokio::sync::watch::Sender<bool>,
    secret: SecretLease,
}

pub(super) struct InterruptedReady {
    node: Digest32,
    peer: Digest32,
    connection: Arc<VoxConnection>,
    room: SharedChannel,
    context: crate::join::session::JoinContext,
    interruption: crate::node::channel::own_writer_gate::Interrupted,
    _secret: SecretLease,
}

/// One unavailable donor is parked only for this exact authenticated connection and debt.
/// A replacement connection or a changed target/key request is new work, not a timed retry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Parked {
    target: Digest32,
    session_epoch: u64,
    key_epoch: u64,
    chain: u64,
    iteration: u64,
    connection: u64,
    availability: Option<crate::node::channel::availability::Token>,
}

pub(super) type SecretLease = Arc<tokio::sync::OwnedRwLockReadGuard<()>>;

pub(super) struct ActiveAttempt {
    pub(super) request: Request,
    pub(super) cancel: tokio::sync::watch::Sender<bool>,
}

pub(super) struct OpenReady {
    request: Request,
    lease: Arc<super::own_attempts::Lease>,
    cancel: tokio::sync::watch::Receiver<bool>,
    node: Digest32,
    peer: Digest32,
    connection: Arc<VoxConnection>,
    room: std::sync::Weak<tokio::sync::Mutex<ChannelState>>,
    context: crate::join::session::JoinContext,
    bundle: crate::identity::keyagreement::PrekeyBundlePublic,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    peer_credit: OwnedSemaphorePermit,
    queue: tokio::sync::mpsc::OwnedPermit<PairwiseJob>,
}

pub(super) struct RequestReady {
    request: Request,
    lease: Arc<super::own_attempts::Lease>,
    cancel: tokio::sync::watch::Receiver<bool>,
    node: Digest32,
    peer: Digest32,
    connection: Arc<VoxConnection>,
    room: SharedChannel,
    context: crate::join::session::JoinContext,
    prepared: crate::error::Result<(crate::pairwise::session::Session, Vec<u8>)>,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    queue: tokio::sync::mpsc::OwnedPermit<PairwiseJob>,
    credit: PairwiseCredit,
    output: crate::node::history_budget::OutputCharge,
    secret: SecretLease,
}

pub(super) enum OwnKeyReply {
    Available(crate::group::skdm::Skdm),
    Unavailable,
    DonorStorageFault,
}

pub(super) struct ResponseReady {
    request: Request,
    _lease: Arc<super::own_attempts::Lease>,
    cancel: tokio::sync::watch::Receiver<bool>,
    node: Digest32,
    peer: Digest32,
    connection: Arc<VoxConnection>,
    room: SharedChannel,
    context: crate::join::session::JoinContext,
    release: crate::error::Result<OwnKeyReply>,
    _credit: PairwiseCredit,
    _output: crate::node::history_budget::OutputCharge,
    _secret: SecretLease,
}

fn refuse(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    let code = crate::node::pairwise_stream::KeyRefusal::NotAccepted.code();
    let _ = send.reset(code);
    let _ = recv.stop(code);
}

impl Node {
    pub(super) fn own_key_room_watch(
        &mut self,
        room: Digest32,
    ) -> tokio::sync::watch::Receiver<bool> {
        self.own_key_room_cancel
            .entry(room)
            .or_insert_with(|| tokio::sync::watch::channel(false).0)
            .subscribe()
    }

    pub(super) fn cancel_own_key_room(&mut self, room: Digest32) {
        if let Some(profile) = self.profile.as_ref() {
            self.bounded_sync
                .cancel_own_recovery_admission(room, profile.fingerprint());
        }
        if let Some(cancel) = self.own_key_room_cancel.remove(&room) {
            cancel.send_replace(true);
        }
        for ((id, _), attempt) in &self.own_key_active {
            if *id == room {
                attempt.cancel.send_replace(true);
            }
        }
        self.own_key_credit_trust.remove(&room);
        self.own_key_credit_missing.remove(&room);
        self.own_key_policy_waiting.remove(&room);
        self.own_key_pending.retain(|(id, _), _| *id != room);
        self.own_key_interrupted_pending
            .retain(|(id, _), _| *id != room);
        self.own_key_donor_busy.retain(|(id, _), busy| {
            if *id == room {
                busy.cancel.send_replace(true);
                false
            } else {
                true
            }
        });
        self.own_key_parked.retain(|(id, _), _| *id != room);
    }

    fn own_key_current(
        &self,
        request: Request,
        identities: (Digest32, Digest32),
        connection: &Arc<VoxConnection>,
        room: &SharedChannel,
        context: &crate::join::session::JoinContext,
        channel: &ChannelState,
    ) -> bool {
        let (node, peer) = identities;
        self.locking == 0
            && self.own_key_active.get(&(request.room, peer)).is_some_and(|attempt| attempt.request.id == request.id && !*attempt.cancel.borrow())
            && self.profile.as_ref().is_some_and(|p| p.is_unlocked() && p.fingerprint() == node
                && matches!(channel.own_recovery_key(p.store()), Ok(Some((id, _, true))) if id == request.target))
            && self.trust.is_trusted(&peer)
            && channel.is_member(&peer) && !channel.has_left(&peer)
            && channel.join_context().is_ok_and(|current| current == *context)
            && self.channels.get(&request.room).is_some_and(|current| Arc::ptr_eq(current, room))
            && self.net.as_ref().and_then(|net| net.manager().existing(&peer))
                .is_some_and(|current| Arc::ptr_eq(&current, connection))
    }

    pub(super) fn fail_own_key_request(
        &mut self,
        request: Request,
        peer: Digest32,
        connection: u64,
    ) {
        let Some(attempt) = self
            .own_key_active
            .get(&(request.room, peer))
            .filter(|attempt| attempt.request.id == request.id && !*attempt.cancel.borrow())
        else {
            return;
        };
        attempt.cancel.send_replace(true);
        self.own_key_parked.insert(
            (request.room, peer),
            Parked {
                target: request.target,
                session_epoch: request.session_epoch,
                key_epoch: request.key_epoch,
                chain: request.chain,
                iteration: request.floor,
                connection,
                availability: request.availability,
            },
        );
        // This completion is a real producer edge. The next room turn may choose another donor;
        // the same unchanged donor stays parked.
        self.governance_work.wake_room(request.room);
    }

    pub(super) fn defer_own_key_policy(&mut self, room: Digest32) {
        if self.own_key_policy_waiting.contains_key(&room) {
            return;
        }
        let owner = Arc::new(());
        self.own_key_policy_waiting.insert(room, Arc::clone(&owner));
        let Some(authority) = self.computer_authority() else {
            return;
        };
        let computer = match &authority {
            computer::ComputerAuthority::Managed { computer, .. } => Arc::clone(computer),
            computer::ComputerAuthority::Unmanaged => return,
        };
        let mut settled = computer.own_key_settled();
        let mut room_cancel = self.own_key_room_watch(room);
        let mut epoch_changed = self.pairwise_epoch.subscribe();
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            loop {
                if let Err(error) = computer.storage_ready() {
                    let _ = tx
                        .send(NetEvent::OwnKeyPolicyFailed {
                            room,
                            owner,
                            error: error.to_string(),
                        })
                        .await;
                    return;
                }
                if !computer.own_key_authority_blocked() {
                    break;
                }
                tokio::select! {
                    biased;
                    _ = room_cancel.changed() => return,
                    _ = epoch_changed.changed() => return,
                    changed = settled.changed() => if changed.is_err() { return; },
                }
            }
            if authority.current() {
                tokio::select! {
                    biased;
                    _ = room_cancel.changed() => {},
                    _ = epoch_changed.changed() => {},
                    _ = tx.send(NetEvent::OwnKeyPolicyReady { room, owner }) => {},
                }
            }
        });
    }

    pub(super) fn resume_own_key_policy_waiting(&mut self) {
        for room in std::mem::take(&mut self.own_key_policy_waiting).into_keys() {
            if self.channels.contains_key(&room) {
                self.governance_work.wake_room(room);
            }
        }
    }

    pub(super) fn own_key_board_growth(&mut self, room: Digest32) {
        let Some((epoch, peers)) = self.own_key_credit_missing.get(&room) else {
            return;
        };
        let Some(net) = self.net.as_ref() else {
            return;
        };
        let available = peers.iter().any(|peer| {
            self.trust.is_trusted(peer)
                && net.manager().existing(peer).is_some()
                && net
                    .board_bundle(&room, *epoch, peer)
                    .map(|record| record.prekey_bundle)
                    .or_else(|| net.board_prejoin_bundle(&room, peer))
                    .is_some_and(|bundle| {
                        prekeys::delivery_bundle(
                            &bundle,
                            self.now_ms().get(),
                            &self.refused_otps.of(peer),
                            prekeys::SpentOneTime::SignedPrekey,
                        )
                        .is_ok()
                    })
        });
        if available {
            self.own_key_credit_missing.remove(&room);
            self.governance_work.wake_room(room);
        }
    }

    pub(super) fn finish_own_key_request(&mut self, ready: RequestReady) {
        let room_lock = Arc::clone(&ready.room);
        let Ok(channel) = room_lock.try_lock() else {
            let request = ready.request;
            let failure_lease = Arc::clone(&ready.lease);
            let mut cancel = ready.cancel.clone();
            let connection = Arc::clone(&ready.connection);
            let room = Arc::clone(&ready.room);
            let peer = ready.peer;
            let tx = self.net_tx.clone();
            let mut room_cancel = self.own_key_room_watch(request.room);
            let mut epoch_changed = self.pairwise_epoch.subscribe();
            tokio::spawn(async move {
                let mut ready = Some(ready);
                let available = tokio::select! {
                    biased;
                    _ = room_cancel.changed() => false,
                    _ = cancel.changed() => false,
                    _ = epoch_changed.changed() => false,
                    _ = connection.quinn().closed() => {
                        drop(ready.take());
                        let _ = tx.send(NetEvent::OwnKeyRequestFailed { _lease: Arc::clone(&failure_lease), request, peer, connection: connection.serial() }).await;
                        false
                    },
                    channel = room.lock() => { drop(channel); true },
                };
                if available {
                    let permit = tokio::select! {
                        biased;
                        _ = room_cancel.changed() => None,
                        _ = cancel.changed() => None,
                        _ = epoch_changed.changed() => None,
                        _ = connection.quinn().closed() => {
                            drop(ready.take());
                            let _ = tx.send(NetEvent::OwnKeyRequestFailed { _lease: Arc::clone(&failure_lease), request, peer, connection: connection.serial() }).await;
                            None
                        },
                        permit = tx.clone().reserve_owned() => permit.ok(),
                    };
                    if let (Some(permit), Some(ready)) = (permit, ready.take()) {
                        permit.send(NetEvent::OwnKeyRequestReady(Box::new(ready)));
                    }
                }
            });
            return;
        };
        let RequestReady {
            request,
            lease,
            mut cancel,
            node,
            peer,
            connection,
            room,
            context,
            prepared,
            send,
            recv,
            queue,
            credit,
            output,
            secret,
        } = ready;
        let current = self.own_key_current(
            request,
            (node, peer),
            &connection,
            &room,
            &context,
            &channel,
        );
        if !current {
            if let Some(attempt) = self
                .own_key_active
                .get(&(request.room, peer))
                .filter(|attempt| attempt.request.id == request.id)
            {
                attempt.cancel.send_replace(true);
            }
            return;
        }
        let Ok((session, frame)) = prepared else {
            drop(channel);
            self.fail_own_key_request(request, peer, connection.serial());
            return;
        };
        let tx = self.net_tx.clone();
        let mut epoch_changed = self.pairwise_epoch.subscribe();
        let mut room_cancel = self.own_key_room_watch(request.room);
        let clock = Arc::clone(&self.clock);
        let room_for_network = Arc::clone(&room);
        let mut launch = Some((
            session, frame, send, recv, queue, credit, output, secret, lease,
        ));
        let authorized = self.with_current_computer_authority(|| {
            let Some((mut session, frame, mut send, mut recv, queue, credit, output, secret, lease)) = launch.take() else { return; };
            // This one-shot session has no shared ratchet ordering with ordinary key delivery.
            drop(queue);
            tokio::spawn(async move {
                let result = tokio::select! {
                    biased;
                    _ = epoch_changed.changed() => return,
                    _ = room_cancel.changed() => return,
                    _ = cancel.changed() => return,
                    result = async {
                        crate::transport::framing::write_frame(&mut send, &crate::transport::streams::StreamKind::Pairwise.frame()).await?;
                        crate::transport::framing::write_frame(&mut send, &frame).await?;
                        send.finish().map_err(|_| Error::Unreachable("own-key request stream closed"))?;
                        let frame = crate::node::pairwise_stream::recv_pairwise(&mut recv).await?
                            .ok_or(Error::Unreachable("own-key response ended without a reply"))?;
                        open_response(&mut session, frame, request, node, clock())
                    } => result,
                };
                let ready = ResponseReady { request, _lease: lease, cancel, node, peer, connection, room: room_for_network, context,
                    release: result, _credit: credit, _output: output, _secret: secret };
                let _ = tx.send(NetEvent::OwnKeyResponseReady(Box::new(ready))).await;
            });
        });
        if authorized.is_none() {
            if let Some(attempt) = self
                .own_key_active
                .get(&(request.room, peer))
                .filter(|attempt| attempt.request.id == request.id)
            {
                attempt.cancel.send_replace(true);
            }
            self.defer_own_key_policy(request.room);
        }
    }

    pub(super) fn receive_own_key_response(&mut self, ready: ResponseReady) {
        let request = ready.request;
        if *ready.cancel.borrow() {
            return;
        }
        if !self
            .own_key_active
            .get(&(request.room, ready.peer))
            .is_some_and(|attempt| attempt.request.id == request.id && !*attempt.cancel.borrow())
        {
            return;
        }
        match &ready.release {
            Ok(OwnKeyReply::Available(_)) => {}
            Ok(OwnKeyReply::Unavailable) => {
                self.fail_own_key_request(request, ready.peer, ready.connection.serial());
                return;
            }
            Ok(OwnKeyReply::DonorStorageFault) => {
                let _ = self.event_tx.send(NodeEvent::NodeNote {
                    note: format!("room {}: a peer could not read its retained history key due to a storage error", crate::node::link::b32_encode(&request.room)),
                });
                self.fail_own_key_request(request, ready.peer, ready.connection.serial());
                return;
            }
            Err(error) => {
                let _ = self.event_tx.send(NodeEvent::NodeNote {
                    note: format!(
                        "room {}: own history key request failed: {error}",
                        crate::node::link::b32_encode(&request.room)
                    ),
                });
                self.fail_own_key_request(request, ready.peer, ready.connection.serial());
                return;
            }
        }
        self.own_key_pending
            .insert((request.room, ready.peer), ready);
        self.try_install_own_key(request.room);
    }

    /// A ready response stays owned and charged while a different operation holds the room.
    /// The existing room-release continuation retries this exact response, not a network poll.
    pub(super) fn try_install_own_key(&mut self, room_id: Digest32) {
        let Some(key) = self
            .own_key_pending
            .keys()
            .find(|(room, _)| *room == room_id)
            .copied()
        else {
            return;
        };
        let Some(ready) = self.own_key_pending.remove(&key) else {
            return;
        };
        let request = ready.request;
        let Ok(mut channel) = ready.room.try_lock() else {
            let node = ready.node;
            let room = Arc::clone(&ready.room);
            self.own_key_pending.insert(key, ready);
            self.bounded_sync.wait_for_own_recovery_room(
                &self.net_tx,
                &mut self.next_token,
                node,
                room_id,
                room,
            );
            return;
        };
        if !self.own_key_current(
            request,
            (ready.node, ready.peer),
            &ready.connection,
            &ready.room,
            &ready.context,
            &channel,
        ) {
            if let Some(attempt) = self
                .own_key_active
                .get(&(room_id, ready.peer))
                .filter(|attempt| attempt.request.id == request.id)
            {
                attempt.cancel.send_replace(true);
            }
            return;
        }
        let Some(profile) = self.profile.as_ref() else {
            return;
        };
        let Ok(OwnKeyReply::Available(release)) = &ready.release else {
            return;
        };
        let result = self.with_current_computer_authority(|| {
            channel.accept_own_recovery_release(
                profile.store(),
                request.target,
                release,
                self.now_ms(),
            )
        });
        match result {
            Some(Ok(_)) => {
                for ((room, _), attempt) in &self.own_key_active {
                    if *room == room_id {
                        attempt.cancel.send_replace(true);
                    }
                }
                self.own_key_pending.retain(|(room, _), _| *room != room_id);
                self.own_key_parked.remove(&(room_id, ready.peer));
                self.governance_work.wake_room(room_id);
            }
            Some(Err(error)) if ChannelState::receiver_release_cleanup_waiting(&error) => {
                drop(channel);
                self.own_key_pending.insert(key, ready);
                self.governance_work.wake_room(room_id);
            }
            Some(Err(error)) if channel.is_poisoned() => {
                // Local storage failure is room health, not evidence that this donor lacks a key.
                // Keep the recovery obligation and stop selecting other donors for this failure.
                for ((room, _), attempt) in &self.own_key_active {
                    if *room == room_id {
                        attempt.cancel.send_replace(true);
                    }
                }
                self.own_key_pending.retain(|(room, _), _| *room != room_id);
                let _ = self.event_tx.send(NodeEvent::NodeNote {
                    note: format!(
                        "room {}: own history key could not be saved: {error}",
                        crate::node::link::b32_encode(&room_id)
                    ),
                });
            }
            Some(Err(_)) => {
                // A peer-supplied invalid or unusable key is not a local store failure. Any
                // actual write failure was already recorded by the room's acceptance path.
                drop(channel);
                self.fail_own_key_request(request, ready.peer, ready.connection.serial());
            }
            None => {
                if let Some(attempt) = self
                    .own_key_active
                    .get(&(room_id, ready.peer))
                    .filter(|attempt| attempt.request.id == request.id)
                {
                    attempt.cancel.send_replace(true);
                }
                self.defer_own_key_policy(room_id);
            }
        }
        // `ready` owns the secret lease, output bytes and peer credit until this point.
    }

    /// Start one missing-generation request. The caller supplies the exact authenticated content
    /// debt produced by the room's durable readability audit; it must not infer it from a receipt.
    pub(super) fn start_own_key_request(
        &mut self,
        room_id: Digest32,
        target: Digest32,
        epoch: u64,
        chain: u64,
        iteration: u64,
    ) {
        if self.locking != 0 {
            return;
        }
        let Some(profile) = self.profile.as_ref().filter(|p| p.is_unlocked()) else {
            return;
        };
        let node = profile.fingerprint();
        let store = profile.store_handle();
        let (Some(room), Some(ring), Some(net)) = (
            self.channels.get(&room_id).map(Arc::clone),
            self.prekeys.as_ref().map(Arc::clone),
            self.net.as_ref().map(Arc::clone),
        ) else {
            return;
        };
        let Ok(channel) = room.try_lock() else {
            self.bounded_sync.wait_for_own_recovery_room(
                &self.net_tx,
                &mut self.next_token,
                node,
                room_id,
                Arc::clone(&room),
            );
            return;
        };
        let Ok(context) = channel.join_context() else {
            return;
        };
        if epoch > context.epoch
            || !matches!(channel.own_recovery_key(&store), Ok(Some((id, _, true))) if id == target)
        {
            return;
        }
        self.own_key_parked
            .retain(|(room, peer), _| self.ports.contains_key(&(*room, *peer)));
        for ((room, _), attempt) in &self.own_key_active {
            if *room == room_id
                && (attempt.request.target != target
                    || attempt.request.key_epoch != epoch
                    || attempt.request.chain != chain
                    || attempt.request.floor != iteration)
            {
                attempt.cancel.send_replace(true);
            }
        }
        let mut selected = Vec::new();
        let mut missing_prekeys = BTreeSet::new();
        for ((r, peer), port) in &self.ports {
            if *r != room_id
                || self.own_key_active.contains_key(&(room_id, *peer))
                || !channel.is_member(peer)
                || channel.has_left(peer)
                || !self.trust.is_trusted(peer)
            {
                continue;
            }
            let Some(connection) = net
                .manager()
                .existing(peer)
                .filter(|c| c.supports_own_recovery())
            else {
                continue;
            };
            let parked = Parked {
                target,
                session_epoch: context.epoch,
                key_epoch: epoch,
                chain,
                iteration,
                connection: connection.serial(),
                availability: port.availability.remote(connection.serial()),
            };
            if self.own_key_parked.get(&(room_id, *peer)) == Some(&parked) {
                continue;
            }
            let Some(bundle) = net
                .board_bundle(&room_id, context.epoch, peer)
                .map(|record| record.prekey_bundle)
                .or_else(|| net.board_prejoin_bundle(&room_id, peer))
            else {
                missing_prekeys.insert(*peer);
                continue;
            };
            let Ok(bundle) = prekeys::delivery_bundle(
                &bundle,
                self.now_ms().get(),
                &self.refused_otps.of(peer),
                prekeys::SpentOneTime::SignedPrekey,
            ) else {
                missing_prekeys.insert(*peer);
                continue;
            };
            let availability = port.availability.remote(connection.serial());
            selected.push((*peer, connection, bundle, availability));
        }
        drop(channel);
        let mut candidates = Vec::new();
        for (peer, connection, bundle, availability) in selected {
            if self.reserve_pairwise(peer, &[]).is_none() {
                continue;
            }
            if let Some(out) = self.pairwise_out.get(&peer) {
                candidates.push((
                    peer,
                    connection,
                    bundle,
                    availability,
                    Arc::clone(&out.jobs),
                    out.queue.clone(),
                ));
            }
        }
        self.own_key_credit_trust.insert(
            room_id,
            self.ports
                .keys()
                .filter_map(|(room, peer)| {
                    (*room == room_id && self.trust.is_trusted(peer)).then_some(*peer)
                })
                .collect(),
        );
        if candidates.is_empty() {
            if !missing_prekeys.is_empty() {
                self.own_key_credit_missing
                    .insert(room_id, (context.epoch, missing_prekeys));
            } else {
                self.own_key_credit_missing.remove(&room_id);
            }
            return;
        }
        drop(ring);
        self.own_key_credit_missing
            .insert(room_id, (context.epoch, missing_prekeys));

        for (peer, connection, bundle, availability, peer_jobs, queue) in candidates {
            let Ok(id) = crate::identity::rng::random_array::<16>() else {
                continue;
            };
            let request = Request {
                id,
                room: room_id,
                session_epoch: context.epoch,
                key_epoch: epoch,
                target,
                chain,
                floor: iteration,
                availability,
            };
            let (cancel_tx, mut cancel) = tokio::sync::watch::channel(false);
            self.own_key_active.insert(
                (room_id, peer),
                ActiveAttempt {
                    request,
                    cancel: cancel_tx,
                },
            );
            let lease = self
                .own_key_completions
                .lease(super::own_attempts::Identity {
                    room: room_id,
                    peer,
                    request: id,
                });
            let failure_lease = Arc::clone(&lease);
            let room = Arc::downgrade(&room);
            let context = context.clone();
            let tx = self.net_tx.clone();
            let mut epoch_changed = self.pairwise_epoch.subscribe();
            let mut room_cancel = self.own_key_room_watch(room_id);
            tokio::spawn(async move {
                let opened = tokio::select! {
                    biased;
                    _ = epoch_changed.changed() => return,
                    _ = room_cancel.changed() => return,
                    _ = cancel.changed() => return,
                    result = connection.quinn().open_bi() => result,
                };
                let Ok((send, recv)) = opened else {
                    drop(lease);
                    let _ = tx
                        .send(NetEvent::OwnKeyRequestFailed {
                            _lease: Arc::clone(&failure_lease),
                            request,
                            peer,
                            connection: connection.serial(),
                        })
                        .await;
                    return;
                };
                let peer_credit = tokio::select! {
                    biased;
                    _ = epoch_changed.changed() => return,
                    _ = room_cancel.changed() => return,
                    _ = cancel.changed() => return,
                    _ = connection.quinn().closed() => { drop(lease); let _ = tx.send(NetEvent::OwnKeyRequestFailed { _lease: Arc::clone(&failure_lease), request, peer, connection: connection.serial() }).await; return; },
                    permit = peer_jobs.acquire_owned() => permit,
                };
                let Ok(peer_credit) = peer_credit else {
                    return;
                };
                let queue = tokio::select! {
                    biased;
                    _ = epoch_changed.changed() => return,
                    _ = room_cancel.changed() => return,
                    _ = cancel.changed() => return,
                    _ = connection.quinn().closed() => { drop((lease, peer_credit)); let _ = tx.send(NetEvent::OwnKeyRequestFailed { _lease: Arc::clone(&failure_lease), request, peer, connection: connection.serial() }).await; return; },
                    permit = queue.reserve_owned() => permit,
                };
                let Ok(queue) = queue else {
                    return;
                };
                let connection_watch = Arc::clone(&connection);
                let ready = OpenReady {
                    request,
                    lease,
                    cancel: cancel.clone(),
                    node,
                    peer,
                    connection,
                    room,
                    context,
                    bundle,
                    send,
                    recv,
                    peer_credit,
                    queue,
                };
                tokio::select! {
                    biased;
                    _ = epoch_changed.changed() => {},
                    _ = room_cancel.changed() => {},
                    _ = cancel.changed() => {},
                    _ = connection_watch.quinn().closed() => {},
                    _ = tx.send(NetEvent::OwnKeyOpenReady(Box::new(ready))) => {},
                }
            });
        }
    }

    pub(super) fn finish_own_key_open(&mut self, ready: OpenReady) {
        use crate::node::history_budget::Lane;
        use crate::node::pairwise_stream::MAX_PAIRWISE_FRAME;
        let Some(room_lock) = ready.room.upgrade() else {
            return;
        };
        let Ok(channel) = room_lock.try_lock() else {
            let request = ready.request;
            let failure_lease = Arc::clone(&ready.lease);
            let mut cancel = ready.cancel.clone();
            let room = Arc::clone(&room_lock);
            let Ok(room_secret) = self.secret_work.clone().try_read_owned() else {
                return;
            };
            let connection = Arc::clone(&ready.connection);
            let peer = ready.peer;
            let tx = self.net_tx.clone();
            let mut epoch_changed = self.pairwise_epoch.subscribe();
            let mut room_cancel = self.own_key_room_watch(request.room);
            tokio::spawn(async move {
                let _room_secret = room_secret;
                let available = tokio::select! {
                    biased;
                    _ = epoch_changed.changed() => false,
                    _ = room_cancel.changed() => false,
                    _ = cancel.changed() => false,
                    _ = connection.quinn().closed() => { let _ = tx.send(NetEvent::OwnKeyRequestFailed { _lease: Arc::clone(&failure_lease), request, peer, connection: connection.serial() }).await; false },
                    channel = room.lock() => { drop(channel); true },
                };
                if available {
                    tokio::select! {
                        biased;
                        _ = epoch_changed.changed() => {},
                        _ = room_cancel.changed() => {},
                        _ = cancel.changed() => {},
                        _ = connection.quinn().closed() => { let _ = tx.send(NetEvent::OwnKeyRequestFailed { _lease: Arc::clone(&failure_lease), request, peer, connection: connection.serial() }).await; },
                        _ = tx.send(NetEvent::OwnKeyOpenReady(Box::new(ready))) => {},
                    }
                }
            });
            return;
        };
        if !self.own_key_current(
            ready.request,
            (ready.node, ready.peer),
            &ready.connection,
            &room_lock,
            &ready.context,
            &channel,
        ) {
            if let Some(attempt) = self
                .own_key_active
                .get(&(ready.request.room, ready.peer))
                .filter(|attempt| attempt.request.id == ready.request.id)
            {
                attempt.cancel.send_replace(true);
            }
            return;
        }
        drop(channel);
        let OpenReady {
            request,
            lease,
            mut cancel,
            node,
            peer,
            connection,
            room: room_weak,
            context,
            bundle,
            send,
            recv,
            peer_credit,
            queue,
        } = ready;
        let Some(ring) = self.prekeys.as_ref().map(Arc::downgrade) else {
            self.fail_own_key_request(request, peer, connection.serial());
            return;
        };
        let node_jobs = Arc::clone(&self.pairwise_jobs);
        let secret_work = Arc::clone(&self.secret_work);
        let budget = Arc::clone(&self.history_budget);
        let tx = self.net_tx.clone();
        let mut epoch_changed = self.pairwise_epoch.subscribe();
        let mut room_cancel = self.own_key_room_watch(request.room);
        let connection_serial = connection.serial();
        let failure_lease = Arc::clone(&lease);
        tokio::spawn(async move {
            let node_credit = tokio::select! {
                biased;
                _ = epoch_changed.changed() => return,
                _ = room_cancel.changed() => return,
                    _ = cancel.changed() => return,
                _ = connection.quinn().closed() => { drop((peer_credit, queue)); let _ = tx.send(NetEvent::OwnKeyRequestFailed { _lease: Arc::clone(&failure_lease), request, peer, connection: connection_serial }).await; return; },
                permit = node_jobs.acquire_owned() => permit,
            };
            let Ok(node_credit) = node_credit else {
                drop((peer_credit, queue));
                let _ = tx
                    .send(NetEvent::OwnKeyRequestFailed {
                        _lease: Arc::clone(&failure_lease),
                        request,
                        peer,
                        connection: connection_serial,
                    })
                    .await;
                return;
            };
            let credit = PairwiseCredit {
                _node: node_credit,
                _peer: peer_credit,
            };
            let secret = tokio::select! {
                biased;
                _ = epoch_changed.changed() => return,
                _ = room_cancel.changed() => return,
                    _ = cancel.changed() => return,
                _ = connection.quinn().closed() => { drop((credit, queue)); let _ = tx.send(NetEvent::OwnKeyRequestFailed { _lease: Arc::clone(&failure_lease), request, peer, connection: connection_serial }).await; return; },
                secret = secret_work.read_owned() => Arc::new(secret),
            };
            let Some(room) = room_weak.upgrade() else {
                drop((secret, credit, queue));
                let _ = tx
                    .send(NetEvent::OwnKeyRequestFailed {
                        _lease: Arc::clone(&failure_lease),
                        request,
                        peer,
                        connection: connection_serial,
                    })
                    .await;
                return;
            };
            let Some(ring) = ring.upgrade() else {
                drop((secret, credit, queue));
                let _ = tx
                    .send(NetEvent::OwnKeyRequestFailed {
                        _lease: Arc::clone(&failure_lease),
                        request,
                        peer,
                        connection: connection_serial,
                    })
                    .await;
                return;
            };
            let (job, mut work) = loop {
                let job = tokio::select! {
                    biased;
                    _ = epoch_changed.changed() => return,
                    _ = room_cancel.changed() => return,
                    _ = cancel.changed() => return,
                    _ = connection.quinn().closed() => { drop((secret, credit, queue)); let _ = tx.send(NetEvent::OwnKeyRequestFailed { _lease: Arc::clone(&failure_lease), request, peer, connection: connection_serial }).await; return; },
                    job = budget.admit_job(node, Lane::LargeControl) => job,
                };
                let envelope = Lane::LargeControl.buffer_limit() / 4;
                match job.reserve_or_pressure_with_headroom(envelope, envelope) {
                    Ok(work) => break (job, work),
                    Err(Error::HistoryCapacity(pressure)) => {
                        drop(job);
                        tokio::select! {
                                biased;
                                _ = epoch_changed.changed() => return,
                                _ = room_cancel.changed() => return,
                        _ = cancel.changed() => return,
                                _ = connection.quinn().closed() => { drop((secret, credit, queue)); let _ = tx.send(NetEvent::OwnKeyRequestFailed { _lease: Arc::clone(&failure_lease), request, peer, connection: connection_serial }).await; return; },
                                _ = pressure.released() => {},
                            }
                    }
                    Err(_) => {
                        drop((secret, credit, queue));
                        let _ = tx
                            .send(NetEvent::OwnKeyRequestFailed {
                                _lease: Arc::clone(&failure_lease),
                                request,
                                peer,
                                connection: connection_serial,
                            })
                            .await;
                        return;
                    }
                }
            };
            let Some(output) = work.split_off(2 * MAX_PAIRWISE_FRAME) else {
                drop((secret, credit, queue));
                let _ = tx
                    .send(NetEvent::OwnKeyRequestFailed {
                        _lease: Arc::clone(&failure_lease),
                        request,
                        peer,
                        connection: connection_serial,
                    })
                    .await;
                return;
            };
            let worker_secret = Arc::clone(&secret);
            let worker_lease = Arc::clone(&lease);
            let worker = tokio::task::spawn_blocking(move || {
                let _secret = worker_secret;
                let _lease = worker_lease;
                let prepared = (|| {
                    let ring = ring.blocking_lock();
                    let (initial, mut session) = crate::pairwise::session::Session::initiate(
                        ring.identity_dh(),
                        &bundle,
                        &context.channel_id,
                        context.epoch,
                        context.suite_id,
                        context.floor,
                    )?;
                    drop(ring);
                    let frame = seal_request(request, &initial, &mut session)?.to_frame();
                    if frame.len() > MAX_PAIRWISE_FRAME {
                        return Err(Error::SizeLimitExceeded("own-key request frame"));
                    }
                    Ok((session, frame))
                })();
                drop(work);
                drop(job);
                (prepared, output)
            });
            let Ok((prepared, output)) = worker.await else {
                drop((secret, credit, queue));
                let _ = tx
                    .send(NetEvent::OwnKeyRequestFailed {
                        _lease: Arc::clone(&failure_lease),
                        request,
                        peer,
                        connection: connection_serial,
                    })
                    .await;
                return;
            };
            let Ok(output) = output.into_output() else {
                drop((secret, credit, queue));
                let _ = tx
                    .send(NetEvent::OwnKeyRequestFailed {
                        _lease: Arc::clone(&failure_lease),
                        request,
                        peer,
                        connection: connection_serial,
                    })
                    .await;
                return;
            };
            if epoch_changed.has_changed().unwrap_or(true) || *room_cancel.borrow() {
                return;
            }
            let connection_watch = Arc::clone(&connection);
            let ready = RequestReady {
                request,
                lease,
                cancel: cancel.clone(),
                node,
                peer,
                connection,
                room,
                context,
                prepared,
                send,
                recv,
                queue,
                credit,
                output,
                secret,
            };
            tokio::select! {
                biased;
                _ = epoch_changed.changed() => {},
                _ = room_cancel.changed() => {},
                _ = cancel.changed() => {},
                _ = connection_watch.quinn().closed() => { let _ = tx.send(NetEvent::OwnKeyRequestFailed { _lease: Arc::clone(&failure_lease), request, peer, connection: connection_serial }).await; },
                _ = tx.send(NetEvent::OwnKeyRequestReady(Box::new(ready))) => {},
            }
        });
    }

    pub(super) fn begin_own_key_donor_busy(
        &mut self,
        room: Digest32,
        peer: Digest32,
        connection: Arc<VoxConnection>,
        slots: Arc<Semaphore>,
    ) {
        let Some(instance) = self.channels.get(&room).cloned() else {
            return;
        };
        if !self.trust.is_trusted(&peer)
            || !self
                .net
                .as_ref()
                .and_then(|net| net.manager().existing(&peer))
                .is_some_and(|current| Arc::ptr_eq(&current, &connection))
        {
            return;
        }
        if self
            .own_key_donor_busy
            .get(&(room, peer))
            .is_some_and(|busy| {
                Arc::ptr_eq(&busy.connection, &connection) && Arc::ptr_eq(&busy.instance, &instance)
            })
        {
            return;
        }
        let Ok(secret) = self.secret_work.clone().try_read_owned() else {
            return;
        };
        let secret = Arc::new(secret);
        self.retire_own_key_donor_busy((room, peer));
        let owner = Arc::new(());
        let (cancel, mut cancelled) = tokio::sync::watch::channel(false);
        self.own_key_donor_busy.insert(
            (room, peer),
            DonorBusy {
                owner: Arc::clone(&owner),
                connection: Arc::clone(&connection),
                instance: Arc::clone(&instance),
                ready: false,
                waiting: false,
                cancel,
                secret: Arc::clone(&secret),
            },
        );
        let mut room_cancel = self.own_key_room_watch(room);
        let mut epoch_changed = self.pairwise_epoch.subscribe();
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let released = tokio::select! {
                biased;
                _ = room_cancel.changed() => false,
                _ = cancelled.changed() => false,
                _ = epoch_changed.changed() => false,
                _ = connection.quinn().closed() => false,
                permit = slots.acquire_owned() => match permit { Ok(permit) => { drop(permit); true }, Err(_) => false },
            };
            if released {
                tokio::select! {
                    biased;
                    _ = room_cancel.changed() => {},
                    _ = cancelled.changed() => {},
                    _ = epoch_changed.changed() => {},
                    _ = connection.quinn().closed() => {},
                    _ = tx.send(NetEvent::OwnKeyDonorAvailable { room, peer, connection: Arc::clone(&connection), instance, owner, from_wait: false, _secret: secret }) => {},
                }
            }
        });
    }

    fn note_own_key_donor_policy_refusal(
        &mut self,
        room: Digest32,
        peer: Digest32,
        connection: Arc<VoxConnection>,
        instance: SharedChannel,
    ) {
        let key = (room, peer);
        if let Some(existing) = self.own_key_donor_busy.get(&key) {
            if Arc::ptr_eq(&existing.connection, &connection)
                && Arc::ptr_eq(&existing.instance, &instance)
            {
                if !existing.ready {
                    return;
                }
                let owner = Arc::clone(&existing.owner);
                self.finish_own_key_donor_busy(room, peer, connection, instance, owner, false);
                return;
            }
        }
        let Ok(secret) = self.secret_work.clone().try_read_owned() else {
            return;
        };
        let secret = Arc::new(secret);
        self.retire_own_key_donor_busy(key);
        let owner = Arc::new(());
        let (cancel, _) = tokio::sync::watch::channel(false);
        self.own_key_donor_busy.insert(
            key,
            DonorBusy {
                owner: Arc::clone(&owner),
                connection: Arc::clone(&connection),
                instance: Arc::clone(&instance),
                ready: true,
                waiting: false,
                cancel,
                secret,
            },
        );
        self.finish_own_key_donor_busy(room, peer, connection, instance, owner, false);
    }

    pub(super) fn retire_own_key_donor_busy(&mut self, key: (Digest32, Digest32)) {
        if let Some(busy) = self.own_key_donor_busy.remove(&key) {
            busy.cancel.send_replace(true);
        }
    }

    pub(super) fn finish_own_key_donor_busy(
        &mut self,
        room: Digest32,
        peer: Digest32,
        connection: Arc<VoxConnection>,
        instance: SharedChannel,
        owner: Arc<()>,
        from_wait: bool,
    ) {
        let key = (room, peer);
        let Some(busy) = self
            .own_key_donor_busy
            .get_mut(&key)
            .filter(|busy| Arc::ptr_eq(&busy.owner, &owner))
        else {
            return;
        };
        if busy.waiting && !from_wait {
            return;
        }
        if from_wait && !busy.waiting {
            return;
        }
        busy.ready = true;
        if from_wait {
            busy.waiting = false;
        }
        if !self.trust.is_trusted(&peer)
            || !self
                .channels
                .get(&room)
                .is_some_and(|current| Arc::ptr_eq(current, &instance))
            || !self
                .net
                .as_ref()
                .and_then(|net| net.manager().existing(&peer))
                .is_some_and(|current| Arc::ptr_eq(&current, &connection))
        {
            self.retire_own_key_donor_busy(key);
            return;
        }
        let Ok(mut channel) = instance.try_lock() else {
            if let Some(busy) = self.own_key_donor_busy.get_mut(&key) {
                if busy.waiting {
                    return;
                }
                busy.waiting = true;
            }
            let secret = Arc::clone(&self.own_key_donor_busy[&key].secret);
            let mut cancelled = self.own_key_donor_busy[&key].cancel.subscribe();
            let mut room_cancel = self.own_key_room_watch(room);
            let mut epoch_changed = self.pairwise_epoch.subscribe();
            let tx = self.net_tx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    biased;
                    _ = room_cancel.changed() => {},
                    _ = cancelled.changed() => {},
                    _ = epoch_changed.changed() => {},
                    _ = connection.quinn().closed() => {},
                    channel = instance.lock() => {
                        drop(channel);
                        let event = NetEvent::OwnKeyDonorAvailable { room, peer, connection: Arc::clone(&connection), instance: Arc::clone(&instance), owner, from_wait: true, _secret: secret };
                        tokio::select! {
                            biased;
                            _ = room_cancel.changed() => {},
                            _ = cancelled.changed() => {},
                            _ = epoch_changed.changed() => {},
                            _ = connection.quinn().closed() => {},
                            _ = tx.send(event) => {},
                        }
                    },
                }
            });
            return;
        };
        if channel.has_left(&channel.me()) || !channel.is_member(&peer) || channel.has_left(&peer) {
            self.retire_own_key_donor_busy(key);
            return;
        }
        match self.with_current_computer_authority(|| channel.note_own_response_resumed(peer)) {
            Some(result) => {
                self.retire_own_key_donor_busy(key);
                if let Err(error) = result {
                    let _ = self.event_tx.send(NodeEvent::NodeNote {
                        note: format!("own-key donor availability could not be recorded: {error}"),
                    });
                }
            }
            None => {
                drop(channel);
                self.defer_own_key_policy(room);
            }
        }
    }

    pub(super) fn resume_own_key_donor_busy(&mut self) {
        let ready: Vec<_> = self
            .own_key_donor_busy
            .iter()
            .filter(|(_, busy)| busy.ready && !busy.waiting)
            .map(|(&(room, peer), busy)| {
                (
                    room,
                    peer,
                    Arc::clone(&busy.connection),
                    Arc::clone(&busy.instance),
                    Arc::clone(&busy.owner),
                )
            })
            .collect();
        for (room, peer, connection, instance, owner) in ready {
            self.finish_own_key_donor_busy(room, peer, connection, instance, owner, false);
        }
    }

    fn wait_own_key_donor(&mut self, mut stream: PairwiseIn, room: Digest32, wait: DonorWait) {
        let tx = self.net_tx.clone();
        let room_secret = if matches!(wait, DonorWait::Room(_)) {
            match self.secret_work.clone().try_read_owned() {
                Ok(secret) => Some(secret),
                Err(_) => return,
            }
        } else {
            None
        };
        let mut room_cancel = self.own_key_room_watch(room);
        let mut epoch_changed = self.pairwise_epoch.subscribe();
        tokio::spawn(async move {
            let _room_secret = room_secret;
            let conn = Arc::clone(&stream.conn);
            let stopped = stream.send.stopped();
            tokio::pin!(stopped);
            let admitted = tokio::select! {
                biased;
                _ = room_cancel.changed() => false,
                _ = epoch_changed.changed() => false,
                _ = conn.quinn().closed() => false,
                _ = &mut stopped => false,
                result = async {
                    match wait {
                        DonorWait::Room(room) => { drop(room.lock().await); Some(None) }
                        DonorWait::Secret(secret) => { drop(secret.read_owned().await); Some(None) }
                        DonorWait::Capacity(node, peer, queue) => {
                            let peer = peer.acquire_owned().await.ok()?;
                            let node = node.acquire_owned().await.ok()?;
                            let queue = queue.reserve_owned().await.ok()?;
                            Some(Some(PairwiseAdmission { queue, job: PairwiseCredit { _node: node, _peer: peer }, delivery: None }))
                        }
                    }
                } => match result { Some(admission) => { stream.donor_admission = admission; true }, None => false },
            };
            if admitted {
                tokio::select! {
                    biased;
                    _ = room_cancel.changed() => {},
                    _ = epoch_changed.changed() => {},
                    _ = conn.quinn().closed() => {},
                    _ = &mut stopped => {},
                    _ = tx.send(NetEvent::Pairwise(stream)) => {},
                }
            }
        });
    }

    fn wait_own_key_donor_ready(&mut self, ready: DonorReady) {
        let tx = self.net_tx.clone();
        let mut room_cancel = self.own_key_room_watch(ready.context.channel_id);
        let mut epoch_changed = self.pairwise_epoch.subscribe();
        tokio::spawn(async move {
            let conn = Arc::clone(&ready.connection);
            let room = Arc::clone(&ready.room);
            let stopped = ready.send.stopped();
            tokio::pin!(stopped);
            let available = tokio::select! {
                biased;
                _ = room_cancel.changed() => false,
                _ = epoch_changed.changed() => false,
                _ = conn.quinn().closed() => false,
                _ = &mut stopped => false,
                channel = room.lock() => { drop(channel); true },
            };
            if available {
                tokio::select! {
                    biased;
                    _ = room_cancel.changed() => {},
                    _ = epoch_changed.changed() => {},
                    _ = conn.quinn().closed() => {},
                    _ = &mut stopped => {},
                    _ = tx.send(NetEvent::OwnKeyDonorReady(ready)) => {},
                }
            }
        });
    }

    /// Admit one incoming own-key request without holding the node actor on disk or network I/O.
    /// All secret-bearing blocking work keeps its room-work admission and lock lease until the
    /// physical worker exits, even when the connection or node is retired meanwhile.
    pub(super) fn start_own_key_donor(&mut self, stream: PairwiseIn) {
        use crate::node::history_budget::Lane;
        use crate::node::pairwise_stream::{PairwiseFrame, MAX_PAIRWISE_FRAME};

        let mut stream = stream;
        let PairwiseFrame::RecoveryOpen { channel_id, .. } = &stream.first else {
            refuse(stream.send, stream.recv);
            return;
        };
        let channel_id = *channel_id;
        let peer = stream.peer;
        if self.locking != 0
            || !stream.conn.supports_own_recovery()
            || !self.trust.is_trusted(&peer)
        {
            refuse(stream.send, stream.recv);
            return;
        }
        let Some(profile) = self
            .profile
            .as_ref()
            .filter(|profile| profile.is_unlocked())
        else {
            refuse(stream.send, stream.recv);
            return;
        };
        let (node, store, signer) = (
            profile.fingerprint(),
            profile.store_handle(),
            profile.signer_arc(),
        );
        let (Ok(signer), Some(ring), Some(room)) = (
            signer,
            self.prekeys.as_ref().map(Arc::clone),
            self.channels.get(&channel_id).map(Arc::clone),
        ) else {
            refuse(stream.send, stream.recv);
            return;
        };
        let context = match room.try_lock() {
            Ok(channel) if channel.is_member(&peer) && !channel.has_left(&peer) => {
                channel.join_context()
            }
            Ok(_) => {
                refuse(stream.send, stream.recv);
                return;
            }
            Err(_) => {
                self.wait_own_key_donor(stream, channel_id, DonorWait::Room(Arc::clone(&room)));
                return;
            }
        };
        let Ok(context) = context else {
            refuse(stream.send, stream.recv);
            return;
        };
        let Ok(secret) = self.secret_work.clone().try_read_owned() else {
            self.wait_own_key_donor(
                stream,
                channel_id,
                DonorWait::Secret(Arc::clone(&self.secret_work)),
            );
            return;
        };
        let admission = stream.donor_admission.take().or_else(|| {
            self.reserve_pairwise(peer, &[false])
                .and_then(|mut items| items.pop())
        });
        let Some(admission) = admission else {
            drop(secret);
            if self.reserve_pairwise(peer, &[]).is_none() {
                refuse(stream.send, stream.recv);
                return;
            }
            let Some(out) = self.pairwise_out.get(&peer) else {
                refuse(stream.send, stream.recv);
                return;
            };
            let wait = DonorWait::Capacity(
                Arc::clone(&self.pairwise_jobs),
                Arc::clone(&out.jobs),
                out.queue.clone(),
            );
            self.wait_own_key_donor(stream, channel_id, wait);
            return;
        };
        let PairwiseAdmission {
            queue, job: credit, ..
        } = admission;
        drop(queue);
        let PairwiseIn {
            conn,
            first,
            send,
            recv,
            recovery_credit: input_credit,
            ..
        } = stream;
        let PairwiseFrame::RecoveryOpen {
            initial, sealed, ..
        } = first
        else {
            refuse(send, recv);
            return;
        };
        let secret = Arc::new(secret);
        let worker_secret = Arc::clone(&secret);
        let budget = Arc::clone(&self.history_budget);
        let tx = self.net_tx.clone();
        let worker_room = Arc::clone(&room);
        let now = self.now_ms().get();
        let mut epoch_changed = self.pairwise_epoch.subscribe();
        let mut room_cancel = self.own_key_room_watch(channel_id);
        tokio::spawn(async move {
            let stopped = send.stopped();
            tokio::pin!(stopped);
            // A queued request owns only its bounded peer admission while waiting. A worker or
            // byte release, rather than a timer, permits the next admission attempt. The node's
            // epoch cancels the wait on lock/detach and drops the secret lease.
            let (job, mut work) = loop {
                let job = tokio::select! {
                    biased;
                    _ = epoch_changed.changed() => { refuse(send, recv); return; }
                    _ = room_cancel.changed() => { refuse(send, recv); return; }
                    _ = conn.quinn().closed() => { refuse(send, recv); return; }
                    _ = &mut stopped => { refuse(send, recv); return; }
                    job = budget.admit_job(node, Lane::LargeControl) => job,
                };
                // A quarter of the existing foreground envelope covers the bounded prekey
                // ring's encoding/sealing overlap and the reply. No extra pool is created.
                match job.reserve_or_pressure(Lane::LargeControl.buffer_limit() / 4) {
                    Ok(work) => break (job, work),
                    Err(Error::HistoryCapacity(pressure)) => {
                        drop(job);
                        tokio::select! {
                            biased;
                            _ = epoch_changed.changed() => { refuse(send, recv); return; }
                            _ = room_cancel.changed() => { refuse(send, recv); return; }
                            _ = conn.quinn().closed() => { refuse(send, recv); return; }
                            _ = &mut stopped => { refuse(send, recv); return; }
                            _ = pressure.released() => {}
                        }
                    }
                    Err(_) => {
                        refuse(send, recv);
                        return;
                    }
                }
            };
            let Some(output) = work.split_off(2 * MAX_PAIRWISE_FRAME) else {
                refuse(send, recv);
                return;
            };
            let worker = tokio::task::spawn_blocking(move || {
                let _secret = worker_secret;
                let result = (|| {
                    let mut ring = ring.blocking_lock();
                    let mut session = accept_initial(
                        &initial,
                        &context,
                        &mut ring,
                        &store,
                        signer.as_ref(),
                        now,
                    )?;
                    drop(ring);
                    let mut channel = worker_room.blocking_lock();
                    let frame = prepare_donor_reply(
                        &mut channel,
                        &store,
                        peer,
                        &context,
                        &mut session,
                        &sealed,
                        now,
                    )?;
                    let bytes = frame.to_frame();
                    if bytes.len() > MAX_PAIRWISE_FRAME {
                        return Err(Error::SizeLimitExceeded("own-key response frame"));
                    }
                    Ok(bytes)
                })();
                drop(work);
                drop(job);
                (result, output)
            });
            // Always join the physical worker: aborting an async supervisor cannot free its
            // secret lease or byte reservation while the blocking child still uses them.
            let Ok((frame, output)) = worker.await else {
                refuse(send, recv);
                return;
            };
            let Ok(output) = output.into_output() else {
                refuse(send, recv);
                return;
            };
            if epoch_changed.has_changed().unwrap_or(true) || *room_cancel.borrow() {
                refuse(send, recv);
                return;
            }
            let conn_watch = Arc::clone(&conn);
            let ready = DonorReady {
                peer,
                node,
                connection: conn,
                room,
                context,
                frame,
                send,
                recv,
                credit,
                output,
                input_credit,
                secret,
            };
            tokio::select! {
                biased;
                _ = epoch_changed.changed() => {},
                _ = room_cancel.changed() => {},
                _ = conn_watch.quinn().closed() => {},
                _ = &mut stopped => {},
                _ = tx.send(NetEvent::OwnKeyDonorReady(ready)) => {},
            }
        });
    }

    /// Revalidate the exact actor, room, peer, connection and policy after the worker returns.
    /// A stale response is discarded rather than delivered under a replacement connection.
    pub(super) fn finish_own_key_donor(&mut self, ready: DonorReady) {
        let DonorReady {
            peer,
            node,
            connection,
            room,
            context,
            frame,
            send,
            recv,
            credit,
            output,
            input_credit,
            secret,
        } = ready;
        let current = self.locking == 0
            && self
                .profile
                .as_ref()
                .is_some_and(|profile| profile.is_unlocked() && profile.fingerprint() == node)
            && self.trust.is_trusted(&peer)
            && self
                .channels
                .get(&context.channel_id)
                .is_some_and(|current| Arc::ptr_eq(current, &room))
            && self
                .net
                .as_ref()
                .and_then(|net| net.manager().existing(&peer))
                .is_some_and(|current| Arc::ptr_eq(&current, &connection));
        let Ok(channel) = room.try_lock() else {
            self.wait_own_key_donor_ready(DonorReady {
                peer,
                node,
                connection,
                room,
                context,
                frame,
                send,
                recv,
                credit,
                output,
                input_credit,
                secret,
            });
            return;
        };
        let current = current
            && !channel.has_left(&node)
            && channel.is_member(&peer)
            && !channel.has_left(&peer)
            && channel
                .join_context()
                .is_ok_and(|current| current == context);
        let Ok(frame) = frame else {
            refuse(send, recv);
            return;
        };
        if channel.is_poisoned() {
            let _ = self.event_tx.send(NodeEvent::NodeNote {
                note: format!(
                    "room {}: cannot read a retained history key: {}",
                    crate::node::link::b32_encode(&context.channel_id),
                    channel.save_failure()
                ),
            });
        }
        if !current {
            refuse(send, recv);
            return;
        }
        let gate = Arc::clone(&channel.own_writer_gate);
        let Some(writer) = gate.try_writer(peer, &connection) else {
            drop(channel);
            let tx = self.net_tx.clone();
            let mut room_cancel = self.own_key_room_watch(context.channel_id);
            let mut epoch_changed = self.pairwise_epoch.subscribe();
            tokio::spawn(async move {
                let stopped = send.stopped();
                tokio::pin!(stopped);
                tokio::select! {
                    biased;
                    _ = room_cancel.changed() => {},
                    _ = epoch_changed.changed() => {},
                    _ = connection.quinn().closed() => {},
                    _ = &mut stopped => {},
                    _ = gate.wait_open() => {
                        let connection_watch = Arc::clone(&connection);
                        let ready = DonorReady { peer, node, connection, room, context,
                            frame: Ok(frame), send, recv, credit, output, input_credit, secret };
                        tokio::select! {
                            biased;
                            _ = room_cancel.changed() => {},
                            _ = epoch_changed.changed() => {},
                            _ = connection_watch.quinn().closed() => {},
                            _ = &mut stopped => {},
                            _ = tx.send(NetEvent::OwnKeyDonorReady(ready)) => {},
                        }
                    }
                }
            });
            return;
        };
        let send = crate::node::channel::own_writer_gate::RevocableSend::new(send);
        let mut pending = Some((recv, credit, output, frame, input_credit));
        let computer = self.computer.clone();
        let mut room_cancel = self.own_key_room_watch(context.channel_id);
        let refused_room = Arc::clone(&room);
        let refused_connection = Arc::clone(&connection);
        let refused_room_id = context.channel_id;
        let response_room = Arc::clone(&room);
        let response_connection = Arc::clone(&connection);
        let response_context = context.clone();
        let tx = self.net_tx.clone();
        let event_tx = self.event_tx.clone();
        let admitted = self.with_current_computer_authority(|| {
            if computer
                .as_ref()
                .is_some_and(|computer| !computer.register_own_key_writer(&send))
            {
                return;
            }
            let Some((recv, credit, output, frame, input_credit)) = pending.take() else {
                return;
            };
            let mut epoch_changed = self.pairwise_epoch.subscribe();
            let mut revoked = send.cancelled();
            let mut settled = computer.as_ref().map(|computer| computer.own_key_settled());
            let send = Arc::clone(&send);
            tokio::spawn(async move {
                let (_recv, _credit, _output, _input_credit) = (recv, credit, output, input_credit);
                let mut writer = writer;
                let mut interrupted = false;
                let written = tokio::select! {
                    biased;
                    _ = writer.cancel.changed() => { interrupted = true; false },
                    _ = revoked.changed() => { interrupted = true; false },
                    _ = epoch_changed.changed() => false,
                    _ = room_cancel.changed() => false,
                    written = send.write_frame(&frame) => written,
                };
                let acknowledged = if written {
                    tokio::select! {
                        biased;
                        _ = writer.cancel.changed() => { interrupted = true; false },
                        _ = revoked.changed() => { interrupted = true; false },
                        _ = epoch_changed.changed() => false,
                        _ = room_cancel.changed() => false,
                        stopped = send.finish_and_wait() => stopped,
                    }
                } else {
                    false
                };
                interrupted |= *revoked.borrow();
                if !acknowledged {
                    send.revoke();
                }
                let interruption = interrupted.then(|| writer.interrupted()).flatten();
                drop(writer);
                drop((_recv, _credit, _output, _input_credit));
                if let Some(interruption) = interruption {
                    if *revoked.borrow() {
                        if let (Some(computer), Some(settled)) = (&computer, &mut settled) {
                            loop {
                                if let Err(error) = computer.storage_ready() {
                                    let _ = event_tx.send(NodeEvent::NodeNote {
                                        note: format!("own-key recovery response stopped: {error}"),
                                    });
                                    return;
                                }
                                if !computer.own_key_authority_blocked() {
                                    break;
                                }
                                tokio::select! {
                                    biased;
                                    _ = room_cancel.changed() => return,
                                    _ = epoch_changed.changed() => return,
                                    _ = response_connection.quinn().closed() => return,
                                    changed = settled.changed() => if changed.is_err() { return; },
                                }
                            }
                        }
                    }
                    let ready = InterruptedReady {
                        node,
                        peer,
                        connection: response_connection,
                        room: response_room,
                        context: response_context,
                        interruption,
                        _secret: secret,
                    };
                    let connection = Arc::clone(&ready.connection);
                    tokio::select! {
                        biased;
                        _ = room_cancel.changed() => {},
                        _ = epoch_changed.changed() => {},
                        _ = connection.quinn().closed() => {},
                        _ = tx.send(NetEvent::OwnKeyWriterInterrupted(ready)) => {},
                    }
                }
            });
        });
        if admitted.is_none() || pending.is_some() {
            send.revoke();
            if let Some((mut recv, _, _, _, _)) = pending {
                let _ = recv.stop(crate::node::pairwise_stream::KeyRefusal::NotAccepted.code());
            }
            self.note_own_key_donor_policy_refusal(
                refused_room_id,
                peer,
                refused_connection,
                refused_room,
            );
        }
    }
    pub(super) fn resume_own_key_interruptions(&mut self) {
        let pending = std::mem::take(&mut self.own_key_interrupted_pending);
        for (_, ready) in pending {
            self.finish_own_key_interruption(ready);
        }
    }

    pub(super) fn finish_own_key_interruption(&mut self, ready: InterruptedReady) {
        let room_id = ready.context.channel_id;
        let current = self.locking == 0
            && self.profile.as_ref().is_some_and(|profile| {
                profile.is_unlocked() && profile.fingerprint() == ready.node
            })
            && self.trust.is_trusted(&ready.peer)
            && self
                .channels
                .get(&room_id)
                .is_some_and(|room| Arc::ptr_eq(room, &ready.room))
            && self
                .net
                .as_ref()
                .and_then(|net| net.manager().existing(&ready.peer))
                .is_some_and(|connection| {
                    Arc::ptr_eq(&connection, &ready.connection)
                        && connection.quinn().close_reason().is_none()
                });
        if !current {
            return;
        }
        let Ok(mut channel) = ready.room.try_lock() else {
            self.wait_own_key_interruption(ready, false);
            return;
        };
        let Some(_admission) = ready.interruption.gate.try_open() else {
            drop(channel);
            self.wait_own_key_interruption(ready, true);
            return;
        };
        if channel.has_left(&ready.node)
            || !channel.is_member(&ready.peer)
            || !channel
                .join_context()
                .is_ok_and(|context| context == ready.context)
        {
            return;
        }
        let published =
            self.with_current_computer_authority(|| channel.note_own_response_resumed(ready.peer));
        match published {
            Some(Ok(())) => {}
            Some(Err(error)) => {
                let _ = self.event_tx.send(NodeEvent::NodeNote {
                    note: format!("own-history retry signal failed: {error}"),
                });
            }
            None => {
                drop(_admission);
                drop(channel);
                self.own_key_interrupted_pending
                    .insert((room_id, ready.peer), ready);
            }
        }
    }

    fn wait_own_key_interruption(&mut self, ready: InterruptedReady, gate: bool) {
        let tx = self.net_tx.clone();
        let mut room_cancel = self.own_key_room_watch(ready.context.channel_id);
        let mut epoch_changed = self.pairwise_epoch.subscribe();
        tokio::spawn(async move {
            let connection = Arc::clone(&ready.connection);
            if gate {
                tokio::select! { biased; _ = room_cancel.changed() => return, _ = epoch_changed.changed() => return,
                _ = connection.quinn().closed() => return, _ = ready.interruption.gate.wait_open() => {} }
            } else {
                tokio::select! { biased; _ = room_cancel.changed() => return, _ = epoch_changed.changed() => return,
                _ = connection.quinn().closed() => return, channel = ready.room.lock() => drop(channel) }
            }
            tokio::select! { biased; _ = room_cancel.changed() => {}, _ = epoch_changed.changed() => {},
            _ = connection.quinn().closed() => {}, _ = tx.send(NetEvent::OwnKeyWriterInterrupted(ready)) => {} }
        });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Request {
    pub(super) id: [u8; 16],
    pub(super) room: Digest32,
    pub(super) session_epoch: u64,
    pub(super) key_epoch: u64,
    pub(super) target: Digest32,
    pub(super) chain: u64,
    pub(super) floor: u64,
    // Local request provenance only; never encoded or accepted from a peer.
    availability: Option<crate::node::channel::availability::Token>,
}
impl Request {
    pub(super) fn encode(self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(8)
            .uint(2)
            .bytes(&self.id)
            .bytes(&self.room)
            .uint(self.session_epoch)
            .uint(self.key_epoch)
            .bytes(&self.target)
            .uint(self.chain)
            .uint(self.floor);
        e.finish()
    }
    pub(super) fn decode(bytes: &[u8]) -> crate::error::Result<Self> {
        if bytes.len() > 256 {
            return Err(Error::SizeLimitExceeded("own-key request"));
        }
        let mut d = Decoder::new(bytes);
        if d.array()? != 8 || d.uint()? != 2 {
            return Err(Error::MalformedBundle("own-key request version"));
        }
        let id = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("own-key request id"))?;
        let room = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("own-key request room"))?;
        let session_epoch = d.uint()?;
        let key_epoch = d.uint()?;
        let target = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("own-key request target"))?;
        let chain = d.uint()?;
        let floor = d.uint()?;
        d.finish()?;
        Ok(Self {
            id,
            room,
            session_epoch,
            key_epoch,
            target,
            chain,
            floor,
            availability: None,
        })
    }
}

/// Seal one recovery request into a fresh, request-owned pairwise session. This session is
/// deliberately independent of the long-lived key-delivery ratchet and its acknowledgements.
pub(super) fn seal_request(
    request: Request,
    initial: &crate::pairwise::InitialMessage,
    session: &mut crate::pairwise::session::Session,
) -> crate::error::Result<crate::node::pairwise_stream::PairwiseFrame> {
    let sealed = session.encrypt(&request.encode())?.to_wire();
    Ok(crate::node::pairwise_stream::PairwiseFrame::RecoveryOpen {
        channel_id: request.room,
        initial: initial.to_wire(),
        sealed,
    })
}

/// Open a request only in its authenticated room and current epoch. The caller separately
/// establishes the requesting author's identity from the authenticated connection.
pub(super) fn open_request(
    session: &mut crate::pairwise::session::Session,
    sealed: &[u8],
    room: Digest32,
    epoch: u64,
    now: u64,
) -> crate::error::Result<Request> {
    let message = crate::pairwise::message::Message::from_wire(sealed)?;
    let plaintext = Zeroizing::new(session.decrypt(&message, now)?);
    let request = Request::decode(&plaintext)?;
    if request.room != room || request.session_epoch != epoch || request.key_epoch > epoch {
        return Err(Error::MalformedBundle("own-key request scope"));
    }
    Ok(request)
}

/// Seal the response in the same request-owned session. An unavailable release is explicit;
/// it does not acknowledge a key delivery or modify donor state.
pub(super) fn seal_response(
    session: &mut crate::pairwise::session::Session,
    request: Request,
    release: Option<&crate::group::skdm::Skdm>,
) -> crate::error::Result<crate::node::pairwise_stream::PairwiseFrame> {
    let plaintext = response(request, release);
    let sealed = session.encrypt(&plaintext)?.to_wire();
    Ok(crate::node::pairwise_stream::PairwiseFrame::RecoveryReply {
        channel_id: request.room,
        sealed,
    })
}

/// Decrypt a response in the originating one-shot session and bind it to the complete request.
/// The returned signed release still requires verification under the author's admitted root.
pub(super) fn open_response(
    session: &mut crate::pairwise::session::Session,
    frame: crate::node::pairwise_stream::PairwiseFrame,
    request: Request,
    author: Digest32,
    now: u64,
) -> crate::error::Result<OwnKeyReply> {
    let crate::node::pairwise_stream::PairwiseFrame::RecoveryReply { channel_id, sealed } = frame
    else {
        return Err(Error::MalformedBundle("own-key response frame"));
    };
    if channel_id != request.room {
        return Err(Error::MalformedBundle("own-key response room"));
    }
    let message = crate::pairwise::message::Message::from_wire(&sealed)?;
    let plaintext = Zeroizing::new(session.decrypt(&message, now)?);
    decode_response(&plaintext, request, author)
}

/// Accept a one-shot opening using the same durable one-time-prekey rules as an ordinary
/// pairwise delivery. The caller owns the prekey lock and must persist consumption before
/// exposing the resulting session to its response worker.
pub(super) fn accept_initial(
    initial: &[u8],
    context: &crate::join::session::JoinContext,
    ring: &mut crate::node::prekeys::PrekeyRing,
    store: &crate::node::store::Store,
    signer: &dyn crate::identity::composite::RootSigner,
    now: u64,
) -> crate::error::Result<crate::pairwise::session::Session> {
    let initial = crate::pairwise::InitialMessage::from_wire(initial)?;
    let mut reuse = crate::pairwise::OtpReuseTracker::new();
    if let Some(id) = initial.one_time_prekey_id {
        match ring.use_one_time(id, now) {
            crate::node::prekeys::OneTimeUse::Fresh => {}
            crate::node::prekeys::OneTimeUse::Reused => {
                reuse.observe(id);
            }
            crate::node::prekeys::OneTimeUse::Unknown => {
                return Err(Error::Unreachable(
                    "the requested one-time prekey is unavailable",
                ));
            }
        }
        crate::node::prekeys::save(store, signer, ring)?;
    }
    let signed_prekey =
        ring.signed_prekey_for(initial.signed_prekey_id)
            .ok_or(Error::Unreachable(
                "the requested signed prekey is unavailable",
            ))?;
    let prekeys = crate::pairwise::ResponderPrekeys {
        identity_dh_key: ring.identity_dh(),
        signed_prekey,
        one_time_prekey: initial
            .one_time_prekey_id
            .and_then(|id| ring.consumed_one_time(id)),
    };
    crate::pairwise::session::Session::accept(
        &initial,
        &prekeys,
        &context.channel_id,
        context.epoch,
        &mut reuse,
        context.floor,
    )
}

/// Prepare a reply to the authenticated peer for its own retained sender release. This performs
/// no network I/O and must be called under the room's current-scope guard; the caller checks that
/// the originating connection and room instance are still current before sending the reply.
pub(super) fn prepare_donor_reply(
    channel: &mut ChannelState,
    store: &crate::node::store::Store,
    peer: Digest32,
    context: &crate::join::session::JoinContext,
    session: &mut crate::pairwise::session::Session,
    sealed: &[u8],
    now: u64,
) -> crate::error::Result<crate::node::pairwise_stream::PairwiseFrame> {
    if channel.join_context()? != *context || !channel.is_member(&peer) || channel.has_left(&peer) {
        return Err(Error::Unreachable(
            "the recovery requester is not a current room member",
        ));
    }
    let request = open_request(session, sealed, context.channel_id, context.epoch, now)?;
    match channel.own_original_release(store, peer, request.key_epoch, request.chain, request.floor)
    {
        Ok(release) => seal_response(session, request, release.as_ref()),
        Err(error @ (Error::Storage { .. } | Error::Path { .. } | Error::MalformedAtRest(_))) => {
            channel.poison(&error);
            let mut e = Encoder::for_secrets();
            e.array(4)
                .uint(1)
                .bytes(&request.encode())
                .uint(2)
                .bytes(&[]);
            let sealed = session.encrypt(&Zeroizing::new(e.finish()))?.to_wire();
            Ok(crate::node::pairwise_stream::PairwiseFrame::RecoveryReply {
                channel_id: request.room,
                sealed,
            })
        }
        Err(error) => Err(error),
    }
}

/// The response repeats the entire immutable query. The only successful key is still verified
/// against the restored author's own admitted root before any receiver state is changed.
pub(super) fn response(
    request: Request,
    release: Option<&crate::group::skdm::Skdm>,
) -> Zeroizing<Vec<u8>> {
    let mut e = Encoder::for_secrets();
    e.array(4)
        .uint(1)
        .bytes(&request.encode())
        .uint(u64::from(release.is_some()));
    if let Some(release) = release {
        e.bytes(&release.to_wire());
    } else {
        e.bytes(&[]);
    }
    Zeroizing::new(e.finish())
}
pub(super) fn decode_response(
    bytes: &[u8],
    request: Request,
    author: Digest32,
) -> crate::error::Result<OwnKeyReply> {
    if bytes.len() > crate::node::pairwise_stream::MAX_PAIRWISE_FRAME {
        return Err(Error::SizeLimitExceeded("own-key response"));
    }
    let mut d = Decoder::new(bytes);
    if d.array()? != 4 || d.uint()? != 1 {
        return Err(Error::MalformedBundle("own-key response binding"));
    }
    // Availability is local admission provenance, not part of the echoed wire request.
    let expected = Request {
        availability: None,
        ..request
    };
    if Request::decode(d.bytes()?)? != expected {
        return Err(Error::MalformedBundle("own-key response binding"));
    }
    let status = d.uint()?;
    let wire = d.bytes()?;
    let result = match status {
        0 if wire.is_empty() => OwnKeyReply::Unavailable,
        2 if wire.is_empty() => OwnKeyReply::DonorStorageFault,
        1 => {
            let release = crate::group::skdm::Skdm::from_wire(wire)?;
            if release.body.channel_id != request.room
                || release.body.epoch != request.key_epoch
                || release.body.author_id != author
                || release.body.chain_id != request.chain
                || release.body.iteration > request.floor
            {
                return Err(Error::MalformedBundle(
                    "own-key release does not satisfy request",
                ));
            }
            OwnKeyReply::Available(release)
        }
        _ => return Err(Error::MalformedBundle("own-key response status")),
    };
    d.finish()?;
    Ok(result)
}
