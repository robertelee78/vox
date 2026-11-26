//! One-shot self-author key recovery. These messages confer no reading permission and share
//! neither ordinary sender-delivery receipts nor the pair's long-lived ratchet.
use super::*;
use crate::cbor::{Decoder, Encoder};
use crate::identity::composite::RootSigner as _;
use zeroize::Zeroizing;

/// A prepared ciphertext owns its shared byte credit and peer admission through the actor
/// handoff and actual socket write. It contains no session or plaintext key material.
enum DonorWait {
    Room(SharedChannel),
    Capacity(
        Arc<Semaphore>,
        Arc<Semaphore>,
        tokio::sync::mpsc::Sender<PairwiseJob>,
    ),
}

/// Every continuation keeps the cancellation generation that admitted the original stream.
struct DonorCancellation {
    room_cancel: tokio::sync::watch::Receiver<bool>,
    epoch_changed: tokio::sync::watch::Receiver<u64>,
    lifecycle_epoch: u64,
}

impl DonorCancellation {
    fn cancelled(&self) -> bool {
        *self.room_cancel.borrow()
            || self.room_cancel.has_changed().unwrap_or(true)
            || self.epoch_changed.has_changed().unwrap_or(true)
    }
}

pub(super) struct DonorResume {
    stream: PairwiseIn,
    cancellation: DonorCancellation,
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
    lifetime: Arc<maintenance_save::Lifetime>,
    cancellation: DonorCancellation,
}

pub(crate) type SecretLease = Arc<tokio::sync::OwnedRwLockReadGuard<()>>;
pub(crate) enum OwnKeyReply {
    Available(Box<crate::group::skdm::Skdm>),
    Unavailable,
    DonorStorageFault,
}

fn refuse(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    let code = crate::node::pairwise_stream::KeyRefusal::NotAccepted.code();
    let _ = send.reset(code);
    let _ = recv.stop(code);
}

pub(super) fn retire_donor_resume(ready: DonorResume) {
    refuse(ready.stream.send, ready.stream.recv);
}

pub(super) fn retire_donor(ready: DonorReady) {
    refuse(ready.send, ready.recv);
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
            // Ends the donor work of the room and any loop's OwnRelease exchange in it.
            cancel.send_replace(true);
        }
        self.own_key_policy_waiting.remove(&room);
        // The room's own-key debt goes with it; a reopened room's audit names it again.
        self.history_frontier.owe_own_key(room, None);
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

    /// The peer boards of a room grew: an OwnRelease the actor could not grant for want of a
    /// usable prekey bundle may be grantable now. The room's recovery stages run again, and
    /// their audit names the own-key debt to the loops again (`Frontier::owe_own_key`).
    pub(super) fn own_key_board_growth(&mut self, room: Digest32) {
        if self.own_recovery_rooms.contains_key(&room) {
            self.governance_work.wake_room(room);
        }
    }

    /// OwnRelease (ADR-054 adoption step 5): the actor's checks for one loop's exchange
    /// (`pull::own_release`), those the old opening, request and install made: this node
    /// unlocked and not locking, the peer trusted, this connection still the peer's current
    /// connection and able to recover own history, the room instance still current; to open,
    /// also the peer's delivery bundle usable, the Computer authority current and the node's
    /// secret lease free. Answered at once, never waited for: "not now" is answered as such
    /// and the room's next audit asks again.
    pub(super) fn grant_own_release(
        &mut self,
        ask: crate::node::history_stream::pull::OwnReleaseAsk,
    ) {
        use crate::node::history_stream::pull::OwnReleaseReply;
        let current = self.own_release_current(&ask);
        let grant = (current && matches!(ask.reply, OwnReleaseReply::Open(_)))
            .then(|| self.own_release_grant(&ask))
            .flatten();
        match ask.reply {
            OwnReleaseReply::Install(reply) => {
                let _ = reply.send(current);
            }
            OwnReleaseReply::Open(reply) => {
                let _ = reply.send(grant);
            }
        }
    }

    fn own_release_current(&self, ask: &crate::node::history_stream::pull::OwnReleaseAsk) -> bool {
        self.locking == 0
            && self
                .profile
                .as_ref()
                .is_some_and(|p| p.is_unlocked() && p.fingerprint() == ask.node)
            && self.trust.is_trusted(&ask.peer)
            && self
                .channels
                .get(&ask.room)
                .is_some_and(|current| Arc::ptr_eq(current, &ask.shared))
            && self.net.as_ref().is_some_and(|net| {
                net.manager().existing(&ask.peer).is_some_and(|current| {
                    Arc::ptr_eq(&current, &ask.conn) && current.supports_own_recovery()
                })
            })
    }

    fn own_release_grant(
        &mut self,
        ask: &crate::node::history_stream::pull::OwnReleaseAsk,
    ) -> Option<crate::node::history_stream::pull::OwnReleaseGrant> {
        let net = self.net.as_ref()?;
        let ring = self.prekeys.as_ref().map(Arc::clone)?;
        // A missing or unusable bundle waits for the room's boards to grow
        // (`own_key_board_growth`), as the old opening did.
        let bundle = net
            .board_bundle(&ask.room, ask.epoch, &ask.peer)
            .map(|record| record.prekey_bundle)
            .or_else(|| net.board_prejoin_bundle(&ask.room, &ask.peer))?;
        let bundle = prekeys::delivery_bundle(
            &bundle,
            self.now_ms().get(),
            &self.refused_otps.of(&ask.peer),
            prekeys::SpentOneTime::SignedPrekey,
        )
        .ok()?;
        let authority = self.computer_authority()?;
        if !authority.current() {
            // The policy settling wakes the room (`resume_own_key_policy_waiting`).
            self.defer_own_key_policy(ask.room);
            return None;
        }
        let secret = Arc::new(Arc::clone(&self.secret_work).try_read_owned().ok()?);
        Some(crate::node::history_stream::pull::OwnReleaseGrant {
            ring,
            bundle,
            secret,
            clock: Arc::clone(&self.clock),
            cancel: (
                self.pairwise_epoch.subscribe(),
                self.own_key_room_watch(ask.room),
            ),
            publish: Box::new(move |write| authority.publish(write).is_some()),
        })
    }

    fn wait_own_key_donor(
        &mut self,
        mut stream: PairwiseIn,
        mut cancellation: DonorCancellation,
        wait: DonorWait,
    ) {
        let completions = Arc::clone(&self.own_key_completions);
        tokio::spawn(async move {
            let conn = Arc::clone(&stream.conn);
            let stopped = stream.send.stopped();
            tokio::pin!(stopped);
            let admitted = tokio::select! {
                biased;
                _ = cancellation.room_cancel.changed() => false,
                _ = cancellation.epoch_changed.changed() => false,
                _ = conn.quinn().closed() => false,
                _ = &mut stopped => false,
                result = async {
                    match wait {
                        DonorWait::Room(room) => { drop(room.lock().await); Some(None) }
                        DonorWait::Capacity(node, peer, queue) => {
                            let peer = peer.acquire_owned().await.ok()?;
                            let node = node.acquire_owned().await.ok()?;
                            let queue = queue.reserve_owned().await.ok()?;
                            Some(Some(PairwiseAdmission { queue, job: PairwiseCredit { _node: node, _peer: peer, room_fence: None }, delivery: None }))
                        }
                    }
                } => match result {
                    Some(admission) => {
                        if let Some(admission) = admission {
                            stream.donor_admission = Some(admission);
                        }
                        true
                    }
                    None => false,
                },
            };
            if admitted && !cancellation.cancelled() {
                completions.complete_lifecycle(
                    cancellation.lifecycle_epoch,
                    leave_save::Ready::DonorResume(Box::new(DonorResume {
                        stream,
                        cancellation,
                    })),
                );
            } else {
                refuse(stream.send, stream.recv);
            }
        });
    }

    fn wait_own_key_donor_ready(&mut self, mut ready: DonorReady) {
        let completions = Arc::clone(&self.own_key_completions);
        tokio::spawn(async move {
            let conn = Arc::clone(&ready.connection);
            let room = Arc::clone(&ready.room);
            let stopped = ready.send.stopped();
            tokio::pin!(stopped);
            let available = tokio::select! {
                biased;
                _ = ready.cancellation.room_cancel.changed() => false,
                _ = ready.cancellation.epoch_changed.changed() => false,
                _ = conn.quinn().closed() => false,
                _ = &mut stopped => false,
                channel = room.lock() => { drop(channel); true },
            };
            if available && !ready.cancellation.cancelled() {
                completions.complete_lifecycle(
                    ready.cancellation.lifecycle_epoch,
                    leave_save::Ready::Donor(Box::new(ready)),
                );
            } else {
                retire_donor(ready);
            }
        });
    }

    /// Admit one incoming own-key request without holding the node actor on disk or network I/O.
    /// All secret-bearing blocking work keeps its room-work admission and lock lease until the
    /// physical worker exits, even when the connection or node is retired meanwhile.
    pub(super) fn start_own_key_donor(
        &mut self,
        stream: PairwiseIn,
        inherited: Option<Arc<maintenance_save::Lifetime>>,
    ) {
        self.continue_own_key_donor(stream, inherited, None);
    }

    pub(super) fn resume_own_key_donor(&mut self, ready: DonorResume) {
        if ready.cancellation.cancelled() || ready.stream.inherited_lifetime.is_none() {
            retire_donor_resume(ready);
            return;
        }
        self.continue_own_key_donor(ready.stream, None, Some(ready.cancellation));
    }

    fn continue_own_key_donor(
        &mut self,
        stream: PairwiseIn,
        inherited: Option<Arc<maintenance_save::Lifetime>>,
        cancellation: Option<DonorCancellation>,
    ) {
        use crate::node::history_budget::Lane;
        use crate::node::pairwise_stream::{PairwiseFrame, MAX_PAIRWISE_FRAME};

        let mut stream = stream;
        let PairwiseFrame::RecoveryOpen { channel_id, .. } = &stream.first else {
            refuse(stream.send, stream.recv);
            return;
        };
        let channel_id = *channel_id;
        let mut cancellation = cancellation.unwrap_or_else(|| DonorCancellation {
            room_cancel: self.own_key_room_watch(channel_id),
            epoch_changed: self.pairwise_epoch.subscribe(),
            lifecycle_epoch: self.own_key_completions.lifecycle_epoch(),
        });
        let peer = stream.peer;
        if self.locking != 0
            || cancellation.cancelled()
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
        let node = profile.fingerprint();
        let inherited = inherited.or_else(|| stream.inherited_lifetime.take());
        let lifetime = if let Some(held) = inherited {
            held
        } else {
            // Capture this exact request's authority once. Ordinary network requests acquire
            // their first boundary off actor; inherited local decisions never enter this path.
            let Ok(signer) = profile.signer_arc() else {
                refuse(stream.send, stream.recv);
                return;
            };
            let store = profile.store_handle();
            let Some(authority) = self.computer_authority() else {
                refuse(stream.send, stream.recv);
                return;
            };
            let secret = Arc::clone(&self.secret_work);
            let completions = Arc::clone(&self.own_key_completions);
            tokio::spawn(async move {
                let connection = Arc::clone(&stream.conn);
                let stopped = stream.send.stopped();
                tokio::pin!(stopped);
                let secret = tokio::select! {
                    biased;
                    _ = cancellation.room_cancel.changed() => { refuse(stream.send, stream.recv); return; },
                    _ = cancellation.epoch_changed.changed() => { refuse(stream.send, stream.recv); return; },
                    _ = connection.quinn().closed() => { refuse(stream.send, stream.recv); return; },
                    _ = &mut stopped => { refuse(stream.send, stream.recv); return; },
                    secret = secret.read_owned() => Arc::new(secret),
                };
                let publication = tokio::select! {
                    biased;
                    _ = cancellation.room_cancel.changed() => { refuse(stream.send, stream.recv); return; },
                    _ = cancellation.epoch_changed.changed() => { refuse(stream.send, stream.recv); return; },
                    _ = connection.quinn().closed() => { refuse(stream.send, stream.recv); return; },
                    _ = &mut stopped => { refuse(stream.send, stream.recv); return; },
                    publication = authority.acquire_publication() => publication,
                };
                let Some(publication) = publication else {
                    refuse(stream.send, stream.recv);
                    return;
                };
                stream.inherited_lifetime = Some(Arc::new(maintenance_save::Lifetime {
                    authority,
                    publication: Some(publication),
                    exclusive: None,
                    secret,
                    store,
                    signer,
                }));
                if cancellation.cancelled() {
                    refuse(stream.send, stream.recv);
                    return;
                }
                completions.complete_lifecycle(
                    cancellation.lifecycle_epoch,
                    leave_save::Ready::DonorResume(Box::new(DonorResume {
                        stream,
                        cancellation,
                    })),
                );
            });
            return;
        };
        if lifetime.signer.fingerprint() != node {
            refuse(stream.send, stream.recv);
            return;
        }
        stream.inherited_lifetime = Some(Arc::clone(&lifetime));
        let (Some(ring), Some(room)) = (
            self.prekeys.as_ref().map(Arc::clone),
            self.channels.get(&channel_id).map(Arc::clone),
        ) else {
            refuse(stream.send, stream.recv);
            return;
        };
        let context = match room.try_lock() {
            Ok(channel)
                if channel
                    .recovery_standing(&lifetime.store, &peer)
                    .unwrap_or(false) =>
            {
                channel.join_context()
            }
            Ok(_) => {
                refuse(stream.send, stream.recv);
                return;
            }
            Err(_) => {
                self.wait_own_key_donor(stream, cancellation, DonorWait::Room(Arc::clone(&room)));
                return;
            }
        };
        let Ok(context) = context else {
            refuse(stream.send, stream.recv);
            return;
        };
        let admission = stream.donor_admission.take().or_else(|| {
            self.reserve_pairwise(peer, &[false])
                .and_then(|mut items| items.pop())
        });
        let Some(admission) = admission else {
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
            self.wait_own_key_donor(stream, cancellation, wait);
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
        let worker_lifetime = Arc::clone(&lifetime);
        let budget = Arc::clone(&self.history_budget);
        let completions = Arc::clone(&self.own_key_completions);
        let worker_room = Arc::clone(&room);
        let now = self.now_ms().get();
        tokio::spawn(async move {
            let stopped = send.stopped();
            tokio::pin!(stopped);
            // A queued request owns only its bounded peer admission while waiting. A worker or
            // byte release, rather than a timer, permits the next admission attempt. The node's
            // epoch cancels the wait on lock/detach and drops the secret lease.
            let (job, mut work) = loop {
                let job = tokio::select! {
                    biased;
                    _ = cancellation.epoch_changed.changed() => { refuse(send, recv); return; }
                    _ = cancellation.room_cancel.changed() => { refuse(send, recv); return; }
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
                            _ = cancellation.epoch_changed.changed() => { refuse(send, recv); return; }
                            _ = cancellation.room_cancel.changed() => { refuse(send, recv); return; }
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
                let held = worker_lifetime;
                let result = (|| {
                    held.publish(|| ())
                        .ok_or(Error::Profile("own-key donor authority changed"))?;
                    let mut ring = ring.blocking_lock();
                    let mut session = accept_initial(
                        &initial,
                        &context,
                        &mut ring,
                        &held.store,
                        held.signer.as_ref(),
                        now,
                    )?;
                    drop(ring);
                    let mut channel = worker_room.blocking_lock();
                    let frame = prepare_donor_reply(
                        &mut channel,
                        &held.store,
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
            if cancellation.cancelled() {
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
                input_credit,
                lifetime,
                cancellation,
            };
            completions.complete_lifecycle(
                ready.cancellation.lifecycle_epoch,
                leave_save::Ready::Donor(Box::new(ready)),
            );
        });
    }

    /// Revalidate the exact actor, room, peer, connection and policy after the worker returns.
    /// A stale response is discarded rather than delivered under a replacement connection.
    pub(super) fn finish_own_key_donor(&mut self, ready: DonorReady) {
        if ready.cancellation.cancelled() {
            retire_donor(ready);
            return;
        }
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
            lifetime,
            mut cancellation,
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
        if !current {
            refuse(send, recv);
            return;
        }
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
                lifetime,
                cancellation,
            });
            return;
        };
        let current = current
            && !channel.has_left(&node)
            && channel
                .recovery_standing(&lifetime.store, &peer)
                .unwrap_or(false)
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
            let completions = Arc::clone(&self.own_key_completions);
            tokio::spawn(async move {
                let stopped = send.stopped();
                tokio::pin!(stopped);
                let available = tokio::select! {
                    biased;
                    _ = cancellation.room_cancel.changed() => false,
                    _ = cancellation.epoch_changed.changed() => false,
                    _ = connection.quinn().closed() => false,
                    _ = &mut stopped => false,
                    _ = gate.wait_open() => true,
                };
                if available && !cancellation.cancelled() {
                    let ready = DonorReady {
                        peer,
                        node,
                        connection,
                        room,
                        context,
                        frame: Ok(frame),
                        send,
                        recv,
                        credit,
                        output,
                        input_credit,
                        lifetime,
                        cancellation,
                    };
                    completions.complete_lifecycle(
                        ready.cancellation.lifecycle_epoch,
                        leave_save::Ready::Donor(Box::new(ready)),
                    );
                } else {
                    refuse(send, recv);
                }
            });
            return;
        };
        let send = crate::node::channel::own_writer_gate::RevocableSend::new(send);
        let mut pending = Some((recv, credit, output, frame, input_credit));
        let computer = self.computer.clone();
        let DonorCancellation {
            mut room_cancel,
            mut epoch_changed,
            ..
        } = cancellation;
        let publication = Arc::clone(&lifetime);
        let admitted = publication.publish(|| {
            if computer
                .as_ref()
                .is_some_and(|computer| !computer.register_own_key_writer(&send))
            {
                return;
            }
            let Some((recv, credit, output, frame, input_credit)) = pending.take() else {
                return;
            };
            let mut revoked = send.cancelled();
            let send = Arc::clone(&send);
            tokio::spawn(async move {
                let (_recv, _credit, _output, _input_credit) = (recv, credit, output, input_credit);
                let held = lifetime;
                let mut writer = writer;
                let written = tokio::select! {
                    biased;
                    _ = writer.cancel.changed() => false,
                    _ = revoked.changed() => false,
                    _ = epoch_changed.changed() => false,
                    _ = room_cancel.changed() => false,
                    written = send.write_frame(&frame) => written,
                };
                let acknowledged = if written {
                    tokio::select! {
                        biased;
                        _ = writer.cancel.changed() => false,
                        _ = revoked.changed() => false,
                        _ = epoch_changed.changed() => false,
                        _ = room_cancel.changed() => false,
                        stopped = send.finish_and_wait() => stopped,
                    }
                } else {
                    false
                };
                if !acknowledged {
                    send.revoke();
                }
                drop(writer);
                // The response has physically stopped; release its original boundary.
                drop(held);
                drop((_recv, _credit, _output, _input_credit));
            });
        });
        if admitted.is_none() || pending.is_some() {
            send.revoke();
            if let Some((mut recv, _, _, _, _)) = pending {
                let _ = recv.stop(crate::node::pairwise_stream::KeyRefusal::NotAccepted.code());
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) id: [u8; 16],
    pub(crate) room: Digest32,
    pub(crate) session_epoch: u64,
    pub(crate) key_epoch: u64,
    pub(crate) target: Digest32,
    pub(crate) chain: u64,
    pub(crate) floor: u64,
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
        })
    }
}

/// The asking side of one OwnRelease exchange, run by the connection's pull loop
/// (`pull::own_release`): a fresh request-owned one-shot session opened against the donor's
/// delivery bundle (never the pair's long-lived ratchet), the sealed request on its own Pairwise
/// stream of this exact connection, and the reply opened in that session and bound to every
/// request field (`open_response`, `decode_response`). The local sealing is admitted as a
/// large control job and released before the peer is waited for; the room's cancellation or
/// the node's lock ends the exchange. `secret`: the node's secret-work lease; the blocking
/// worker holds its own clone from before it can touch the prekey ring until its result (the
/// session) is disposed, so a lock (`lock_all`, which waits on this lease) never completes
/// while that worker can still use the identity's prekey secrets, even when this future is
/// cancelled and the worker's result is dropped unread.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn ask_release(
    conn: &Arc<VoxConnection>,
    budget: &Arc<crate::node::history_budget::Budget>,
    fence: &crate::transport::stream_transport::Fence,
    node: Digest32,
    (ring, bundle): (
        Arc<tokio::sync::Mutex<crate::node::prekeys::PrekeyRing>>,
        crate::identity::keyagreement::PrekeyBundlePublic,
    ),
    clock: &crate::time::Clock,
    secret: &SecretLease,
    cancel: &mut (
        tokio::sync::watch::Receiver<u64>,
        tokio::sync::watch::Receiver<bool>,
    ),
    request: Request,
    context: &crate::join::session::JoinContext,
) -> crate::error::Result<OwnKeyReply> {
    use crate::node::history_budget::Lane;
    use crate::node::pairwise_stream::MAX_PAIRWISE_FRAME;
    let (epoch_changed, room_cancel) = cancel;
    if *room_cancel.borrow() {
        return Err(Error::Unreachable("own-key request cancelled"));
    }
    let exchange = async {
        let (job, mut work) = loop {
            let job = budget.admit_job(node, Lane::LargeControl).await;
            let envelope = Lane::LargeControl.buffer_limit() / 4;
            match job.reserve_or_pressure_with_headroom(envelope, envelope) {
                Ok(work) => break (job, work),
                Err(Error::HistoryCapacity(pressure)) => {
                    drop(job);
                    pressure.released().await;
                }
                Err(error) => return Err(error),
            }
        };
        let output = work
            .split_off(2 * MAX_PAIRWISE_FRAME)
            .ok_or(Error::SizeLimitExceeded("own-key request frame"))?;
        let context = *context;
        let worker_secret = Arc::clone(secret);
        let (prepared, output, _secret) = tokio::task::spawn_blocking(move || {
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
            // The lease travels with the result and is its last field: if this future was
            // cancelled, the runtime disposes the session before the lease.
            (prepared, output, worker_secret)
        })
        .await
        .map_err(|_| Error::Unreachable("own-key request worker stopped"))?;
        // The request's bytes stay charged until its reply is read.
        let _output = output
            .into_output()
            .map_err(|_| Error::Unreachable("own-key request output admission ended"))?;
        let (mut session, frame) = prepared?;
        let (mut send, mut recv) = conn
            .quinn()
            .open_bi()
            .await
            .map_err(|_| Error::Unreachable("own-key request stream closed"))?;
        crate::transport::framing::write_frame(
            &mut send,
            &crate::transport::streams::StreamKind::Pairwise.frame(),
        )
        .await?;
        crate::transport::framing::write_frame(&mut send, &frame).await?;
        send.finish()
            .map_err(|_| Error::Unreachable("own-key request stream closed"))?;
        let reply = crate::node::pairwise_stream::recv_pairwise(&mut recv)
            .await?
            .ok_or(Error::Unreachable("own-key response ended without a reply"))?;
        open_response(&mut session, reply, request, node, clock())
    };
    tokio::select! {
        biased;
        () = fence.retired() => Err(Error::Unreachable("connection ended")),
        _ = epoch_changed.changed() => Err(Error::Unreachable("own-key request cancelled")),
        _ = room_cancel.changed() => Err(Error::Unreachable("own-key request cancelled")),
        result = exchange => result,
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
    if channel.join_context()? != *context || !channel.recovery_standing(store, &peer)? {
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
    if Request::decode(d.bytes()?)? != request {
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
            OwnKeyReply::Available(Box::new(release))
        }
        _ => return Err(Error::MalformedBundle("own-key response status")),
    };
    d.finish()?;
    Ok(result)
}
