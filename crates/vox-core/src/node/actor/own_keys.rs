//! One-shot self-author key recovery. These messages confer no reading permission and share
//! neither ordinary sender-delivery receipts nor the pair's long-lived ratchet.
use super::*;
use crate::cbor::{Decoder, Encoder};
use zeroize::Zeroizing;

/// A prepared ciphertext owns its shared byte credit and peer admission through the actor
/// handoff and actual socket write. It contains no session or plaintext key material.
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

type SecretLease = Arc<tokio::sync::OwnedRwLockReadGuard<()>>;

pub(super) struct RequestReady {
    request: Request,
    node: Digest32,
    peer: Digest32,
    connection: Arc<VoxConnection>,
    room: SharedChannel,
    context: crate::join::session::JoinContext,
    prepared: crate::error::Result<(crate::pairwise::session::Session, Vec<u8>)>,
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
    fn own_key_room_watch(&mut self, room: Digest32) -> tokio::sync::watch::Receiver<bool> {
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
        self.own_key_active.remove(&room);
        self.own_key_pending.remove(&room);
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
            && self.own_key_active.get(&request.room) == Some(&request.id)
            && self.profile.as_ref().is_some_and(|p| p.is_unlocked() && p.fingerprint() == node
                && matches!(channel.own_recovery_key(p.store()), Ok(Some((id, _, true))) if id == request.target))
            && self.trust.is_trusted(&peer)
            && channel.is_member(&peer) && !channel.has_left(&peer)
            && channel.join_context().is_ok_and(|current| current == *context)
            && self.channels.get(&request.room).is_some_and(|current| Arc::ptr_eq(current, room))
            && self.net.as_ref().and_then(|net| net.manager().existing(&peer))
                .is_some_and(|current| Arc::ptr_eq(&current, connection))
    }

    fn own_key_wait_for_room(&mut self, request: Request, node: Digest32, room: SharedChannel) {
        self.own_key_active.remove(&request.room);
        self.bounded_sync.wait_for_own_recovery_room(
            &self.net_tx,
            &mut self.next_token,
            node,
            request.room,
            room,
        );
    }

    pub(super) fn fail_own_key_request(
        &mut self,
        request: Request,
        peer: Digest32,
        connection: u64,
    ) {
        if self.own_key_active.get(&request.room) != Some(&request.id) {
            return;
        }
        self.own_key_active.remove(&request.room);
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

    pub(super) fn finish_own_key_request(&mut self, ready: RequestReady) {
        let RequestReady {
            request,
            node,
            peer,
            connection,
            room,
            context,
            prepared,
            queue,
            credit,
            output,
            secret,
        } = ready;
        let Ok(channel) = room.try_lock() else {
            self.own_key_wait_for_room(request, node, Arc::clone(&room));
            return;
        };
        let current = self.own_key_current(
            request,
            (node, peer),
            &connection,
            &room,
            &context,
            &channel,
        );
        if !current {
            if self.own_key_active.get(&request.room) == Some(&request.id) {
                self.own_key_active.remove(&request.room);
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
        let mut launch = Some((session, frame, queue, credit, output, secret));
        let authorized = self.with_current_computer_authority(|| {
            let Some((mut session, frame, queue, credit, output, secret)) = launch.take() else { return; };
            // This one-shot session has no shared ratchet ordering with ordinary key delivery.
            drop(queue);
            tokio::spawn(async move {
                let result = tokio::select! {
                    biased;
                    _ = epoch_changed.changed() => return,
                    _ = room_cancel.changed() => return,
                    result = async {
                        let mut recv = crate::node::pairwise_stream::write_pairwise(&connection, &[frame]).await?;
                        let frame = crate::node::pairwise_stream::recv_pairwise(&mut recv).await?
                            .ok_or(Error::Unreachable("own-key response ended without a reply"))?;
                        open_response(&mut session, frame, request, node, clock())
                    } => result,
                };
                let ready = ResponseReady { request, node, peer, connection, room: room_for_network, context,
                    release: result, _credit: credit, _output: output, _secret: secret };
                let _ = tx.send(NetEvent::OwnKeyResponseReady(Box::new(ready))).await;
            });
        });
        if authorized.is_none() {
            self.own_key_active.remove(&request.room);
        }
    }

    pub(super) fn receive_own_key_response(&mut self, ready: ResponseReady) {
        let request = ready.request;
        if self.own_key_active.get(&request.room) != Some(&request.id) {
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
        self.own_key_pending.insert(request.room, ready);
        self.try_install_own_key(request.room);
    }

    /// A ready response stays owned and charged while a different operation holds the room.
    /// The existing room-release continuation retries this exact response, not a network poll.
    pub(super) fn try_install_own_key(&mut self, room_id: Digest32) {
        let Some(ready) = self.own_key_pending.remove(&room_id) else {
            return;
        };
        let request = ready.request;
        let Ok(mut channel) = ready.room.try_lock() else {
            let node = ready.node;
            let room = Arc::clone(&ready.room);
            self.own_key_pending.insert(room_id, ready);
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
            if self.own_key_active.get(&room_id) == Some(&request.id) {
                self.own_key_active.remove(&room_id);
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
                self.own_key_active.remove(&room_id);
                self.own_key_parked.remove(&(room_id, ready.peer));
                self.governance_work.wake_room(room_id);
            }
            Some(Err(error)) if ChannelState::receiver_release_cleanup_waiting(&error) => {
                drop(channel);
                self.own_key_pending.insert(room_id, ready);
                self.governance_work.wake_room(room_id);
            }
            Some(Err(error)) if channel.is_poisoned() => {
                // Local storage failure is room health, not evidence that this donor lacks a key.
                // Keep the recovery obligation and stop selecting other donors for this failure.
                self.own_key_active.remove(&room_id);
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
                self.own_key_active.remove(&room_id);
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
        use crate::node::history_budget::Lane;
        use crate::node::pairwise_stream::MAX_PAIRWISE_FRAME;

        if self.locking != 0 || self.own_key_active.contains_key(&room_id) {
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
        let mut selected = None;
        for ((r, peer), port) in &self.ports {
            if *r != room_id
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
                continue;
            };
            let Ok(bundle) = prekeys::delivery_bundle(
                &bundle,
                self.now_ms().get(),
                &self.refused_otps.of(peer),
                prekeys::SpentOneTime::SignedPrekey,
            ) else {
                continue;
            };
            selected = Some((*peer, connection, bundle));
            break;
        }
        drop(channel);
        let Some((peer, connection, bundle)) = selected else {
            return;
        };
        let Ok(id) = crate::identity::rng::random_array::<16>() else {
            return;
        };
        let request = Request {
            id,
            room: room_id,
            session_epoch: context.epoch,
            key_epoch: epoch,
            target,
            chain,
            floor: iteration,
            availability: self
                .ports
                .get(&(room_id, peer))
                .and_then(|p| p.availability.remote(connection.serial())),
        };
        let Ok(secret) = self.secret_work.clone().try_read_owned() else {
            return;
        };
        let secret = Arc::new(secret);
        let Some(admission) = self
            .reserve_pairwise(peer, &[false])
            .and_then(|mut a| a.pop())
        else {
            drop(secret);
            let Some(out) = self.pairwise_out.get(&peer) else {
                return;
            };
            let node_jobs = Arc::clone(&self.pairwise_jobs);
            let peer_jobs = Arc::clone(&out.jobs);
            let queue = out.queue.clone();
            let tx = self.net_tx.clone();
            let mut epoch_changed = self.pairwise_epoch.subscribe();
            let mut room_cancel = self.own_key_room_watch(room_id);
            self.own_key_active.insert(room_id, id);
            tokio::spawn(async move {
                tokio::select! {
                    biased;
                    _ = epoch_changed.changed() => (),
                    _ = room_cancel.changed() => (),
                    result = async {
                        let node = node_jobs.acquire_owned().await.ok()?;
                        let peer = peer_jobs.acquire_owned().await.ok()?;
                        let slot = queue.reserve_owned().await.ok()?;
                        drop((node, peer, slot));
                        Some(())
                    } => {
                        if result.is_some() {
                            let _ = tx.send(NetEvent::OwnKeyCapacityReady { request }).await;
                        }
                    }
                }
            });
            return;
        };
        let PairwiseAdmission {
            queue, job: credit, ..
        } = admission;
        self.own_key_active.insert(room_id, id);
        let budget = Arc::clone(&self.history_budget);
        let tx = self.net_tx.clone();
        let mut epoch_changed = self.pairwise_epoch.subscribe();
        let mut room_cancel = self.own_key_room_watch(room_id);
        let worker_secret = Arc::clone(&secret);
        let connection_serial = connection.serial();
        tokio::spawn(async move {
            let (job, mut work) = loop {
                let job = tokio::select! {
                    biased;
                    _ = epoch_changed.changed() => return,
                    _ = room_cancel.changed() => return,
                    job = budget.admit_job(node, Lane::LargeControl) => job,
                };
                let envelope = Lane::LargeControl.buffer_limit() / 4;
                match job.reserve_or_pressure_with_headroom(envelope, envelope) {
                    Ok(work) => break (job, work),
                    Err(Error::HistoryCapacity(pressure)) => {
                        drop(job);
                        tokio::select! { biased; _ = epoch_changed.changed() => return, _ = room_cancel.changed() => return, _ = pressure.released() => {} }
                    }
                    Err(_) => {
                        let _ = tx
                            .send(NetEvent::OwnKeyRequestFailed {
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
                let _ = tx
                    .send(NetEvent::OwnKeyRequestFailed {
                        request,
                        peer,
                        connection: connection_serial,
                    })
                    .await;
                return;
            };
            let worker = tokio::task::spawn_blocking(move || {
                let _secret = worker_secret;
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
                let _ = tx
                    .send(NetEvent::OwnKeyRequestFailed {
                        request,
                        peer,
                        connection: connection_serial,
                    })
                    .await;
                return;
            };
            let Ok(output) = output.into_output() else {
                let _ = tx
                    .send(NetEvent::OwnKeyRequestFailed {
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
            let ready = RequestReady {
                request,
                node,
                peer,
                connection,
                room,
                context,
                prepared,
                queue,
                credit,
                output,
                secret,
            };
            let _ = tx.send(NetEvent::OwnKeyRequestReady(Box::new(ready))).await;
        });
    }

    /// Admit one incoming own-key request without holding the node actor on disk or network I/O.
    /// All secret-bearing blocking work keeps its room-work admission and lock lease until the
    /// physical worker exits, even when the connection or node is retired meanwhile.
    pub(super) fn start_own_key_donor(&mut self, stream: PairwiseIn) {
        use crate::node::history_budget::Lane;
        use crate::node::pairwise_stream::{PairwiseFrame, MAX_PAIRWISE_FRAME};

        let PairwiseIn {
            conn,
            peer,
            first,
            send,
            recv,
            ..
        } = stream;
        let PairwiseFrame::RecoveryOpen {
            channel_id,
            initial,
            sealed,
        } = first
        else {
            refuse(send, recv);
            return;
        };
        if self.locking != 0 || !conn.supports_own_recovery() || !self.trust.is_trusted(&peer) {
            refuse(send, recv);
            return;
        }
        let Some(profile) = self
            .profile
            .as_ref()
            .filter(|profile| profile.is_unlocked())
        else {
            refuse(send, recv);
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
            refuse(send, recv);
            return;
        };
        let context = match room.try_lock() {
            Ok(channel) if channel.is_member(&peer) && !channel.has_left(&peer) => {
                channel.join_context()
            }
            _ => Err(Error::Unreachable("the recovery room is not ready")),
        };
        let Ok(context) = context else {
            refuse(send, recv);
            return;
        };
        let Ok(secret) = self.secret_work.clone().try_read_owned() else {
            refuse(send, recv);
            return;
        };
        let Some(admission) = self
            .reserve_pairwise(peer, &[false])
            .and_then(|mut items| items.pop())
        else {
            refuse(send, recv);
            return;
        };
        // The peer slot is still owned by `job`; the ordinary writer queue is not used for a
        // response on an already-open stream.
        let PairwiseAdmission {
            queue, job: credit, ..
        } = admission;
        drop(queue);
        let budget = Arc::clone(&self.history_budget);
        let tx = self.net_tx.clone();
        let worker_room = Arc::clone(&room);
        let now = self.now_ms().get();
        let mut epoch_changed = self.pairwise_epoch.subscribe();
        let mut room_cancel = self.own_key_room_watch(channel_id);
        tokio::spawn(async move {
            // A queued request owns only its bounded peer admission while waiting. A worker or
            // byte release, rather than a timer, permits the next admission attempt. The node's
            // epoch cancels the wait on lock/detach and drops the secret lease.
            let (job, mut work) = loop {
                let job = tokio::select! {
                    biased;
                    _ = epoch_changed.changed() => { refuse(send, recv); return; }
                    _ = room_cancel.changed() => { refuse(send, recv); return; }
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
                let _secret = secret;
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
            };
            let _ = tx.send(NetEvent::OwnKeyDonorReady(ready)).await;
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
            refuse(send, recv);
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
        let Some(writer) = gate.try_writer() else {
            drop(channel);
            let tx = self.net_tx.clone();
            let mut room_cancel = self.own_key_room_watch(context.channel_id);
            tokio::spawn(async move {
                tokio::select! {
                    biased;
                    _ = room_cancel.changed() => {},
                    _ = gate.wait_open() => {
                        let ready = DonorReady { peer, node, connection, room, context,
                            frame: Ok(frame), send, recv, credit, output };
                        tokio::select! {
                            biased;
                            _ = room_cancel.changed() => {},
                            _ = tx.send(NetEvent::OwnKeyDonorReady(ready)) => {},
                        }
                    }
                }
            });
            return;
        };
        let mut pending = Some((send, recv, credit, output, frame));
        let mut room_cancel = self.own_key_room_watch(context.channel_id);
        let admitted = self.with_current_computer_authority(|| {
            let Some((mut send, recv, credit, output, frame)) = pending.take() else {
                return;
            };
            let mut epoch_changed = self.pairwise_epoch.subscribe();
            tokio::spawn(async move {
                let (_recv, _credit, _output) = (recv, credit, output);
                let mut writer = writer;
                let written = tokio::select! {
                    biased;
                    _ = writer.cancel.changed() => false,
                    _ = epoch_changed.changed() => false,
                    _ = room_cancel.changed() => false,
                    written = crate::transport::framing::write_frame(&mut send, &frame) => written.is_ok(),
                };
                let acknowledged = if written && send.finish().is_ok() {
                    tokio::select! {
                        biased;
                        _ = writer.cancel.changed() => false,
                        _ = epoch_changed.changed() => false,
                        _ = room_cancel.changed() => false,
                        stopped = send.stopped() => matches!(stopped, Ok(None)),
                    }
                } else {
                    false
                };
                if !acknowledged {
                    let _ = send.reset(crate::node::pairwise_stream::KeyRefusal::NotAccepted.code());
                }
            });
        });
        if admitted.is_none() {
            if let Some((send, recv, _, _, _)) = pending {
                refuse(send, recv);
            }
        }
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
