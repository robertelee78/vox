//! Original read request owns one on-demand admitted worker, not a count service.
//! No room mutex crosses a count slice, capacity wait, or IPC wait.
use super::*;
use crate::node::channel::history::{self, page_read};
use crate::node::history_budget::Lane;
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) type PageResult<T> = std::result::Result<T, String>;
type WeakRoom = std::sync::Weak<tokio::sync::Mutex<ChannelState>>;
type WeakStore = std::sync::Weak<crate::node::store::Store>;

pub(super) struct PrepareRequest {
    room: Digest32,
    node: Digest32,
    reference: WeakRoom,
    store: WeakStore,
    lifetime: Arc<page_read::ReadLifetime>,
    node_lifetime: Arc<page_read::ReadLifetime>,
    reply: oneshot::Sender<PageResult<Prepared>>,
}
pub(super) enum Prepared {
    Wait,
    Ready {
        secret: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
        room_work: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
        lifetime: Arc<page_read::ReadLifetime>,
        node_lifetime: Arc<page_read::ReadLifetime>,
    },
}
pub(super) struct PublishRequest {
    scope: page_read::Scope,
    reference: WeakRoom,
    store: WeakStore,
    reply: oneshot::Sender<PageResult<bool>>,
}
pub(super) struct FaultRequest {
    room: Digest32,
    reference: WeakRoom,
    error: Arc<Error>,
    reply: oneshot::Sender<bool>,
}
fn remember_fault(error: Error, slot: &std::sync::Mutex<Option<Error>>) -> String {
    let message = error.to_string();
    if !matches!(
        error,
        Error::Profile(_) | Error::AtRestLocked | Error::HistoryCapacity(_)
    ) {
        if let Ok(mut stored) = slot.lock() {
            *stored = Some(error);
        }
    }
    message
}
struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl Node {
    pub(super) fn prepare_owned_page_read(&mut self, request: PrepareRequest) {
        let result = (|| -> PageResult<Prepared> {
            let profile = self.profile.as_ref().ok_or("the node is locked")?;
            if self.locking != 0
                || profile.fingerprint() != request.node
                || profile.signer().is_err()
            {
                return Err("the node is locked".into());
            }
            let store = profile.store_handle();
            if !request
                .store
                .upgrade()
                .is_some_and(|old| Arc::ptr_eq(&old, &store))
            {
                return Err("the room reader's profile changed".into());
            }
            let shared = self.channels.get(&request.room).ok_or("room not open")?;
            if !request
                .reference
                .upgrade()
                .is_some_and(|old| Arc::ptr_eq(&old, shared))
            {
                return Err("the saved room changed".into());
            }
            let Ok(mut room) = shared.try_lock() else {
                return Ok(Prepared::Wait);
            };
            if request.lifetime.is_retired()
                || request.node_lifetime.is_retired()
                || !Arc::ptr_eq(&room.page_read_lifetime(), &request.lifetime)
                || !Arc::ptr_eq(&self.page_reads, &request.node_lifetime)
            {
                return Err("room read retired".into());
            }
            // Same current trust refresh as the original RoomHistory handler, with the
            // operation's physical bytes already reserved before any metadata allocation.
            let trusted = self.trust.trusted();
            room.forget_keys_except(&store, &trusted)
                .map_err(|error| error.to_string())?;
            let lifetime = room.page_read_lifetime();
            self.page_read_rooms
                .insert(request.room, Arc::downgrade(&lifetime));
            let room_work = lifetime.lease().map_err(|error| error.to_string())?;
            let secret = Arc::new(
                Arc::clone(&self.secret_work)
                    .try_read_owned()
                    .map_err(|_| "the node is locking")?,
            );
            Ok(Prepared::Ready {
                secret,
                room_work,
                lifetime,
                node_lifetime: Arc::clone(&self.page_reads),
            })
        })();
        let _ = request.reply.send(result);
    }
    pub(super) fn publish_owned_page_read(&mut self, request: PublishRequest) {
        let result = (|| -> PageResult<bool> {
            let profile = self.profile.as_ref().ok_or("the node is locked")?;
            if self.locking != 0
                || profile.signer().is_err()
                || profile.fingerprint() != request.scope.node
            {
                return Err("the node is locked".into());
            }
            if !Arc::ptr_eq(&self.page_reads, &request.scope.node_lifetime)
                || self.page_reads.is_retired()
            {
                return Err("the room read was retired".into());
            }
            let store = profile.store_handle();
            if !request
                .store
                .upgrade()
                .is_some_and(|old| Arc::ptr_eq(&old, &store))
            {
                return Err("the room reader's profile changed".into());
            }
            let shared = self
                .channels
                .get(&request.scope.room)
                .ok_or("room not open")?;
            if !request
                .reference
                .upgrade()
                .is_some_and(|old| Arc::ptr_eq(&old, shared))
            {
                return Err("the saved room changed".into());
            }
            let Ok(room) = shared.try_lock() else {
                return Ok(false);
            };
            if !room
                .page_scope_current(&store, &request.scope)
                .map_err(|error| error.to_string())?
                || !room
                    .legacy_page_authorized(&store, &request.scope, &self.trust, (self.clock)())
                    .map_err(|error| error.to_string())?
            {
                return Err("the room's authority or history policy changed while reading".into());
            }
            Ok(true)
        })();
        let _ = request.reply.send(result);
    }

    pub(super) fn record_owned_page_fault(&mut self, request: FaultRequest) {
        let done = match self.channels.get(&request.room) {
            Some(shared)
                if request
                    .reference
                    .upgrade()
                    .is_some_and(|old| Arc::ptr_eq(&old, shared)) =>
            {
                match shared.try_lock() {
                    Ok(mut room) => {
                        room.poison(&request.error);
                        true
                    }
                    Err(_) => false,
                }
            }
            _ => true,
        };
        let _ = request.reply.send(done);
    }
    pub(super) fn start_owned_page_read(
        &mut self,
        room: Digest32,
        query: history::Query,
        mut reply: oneshot::Sender<PageResult<page_read::Answer>>,
    ) {
        if !page_read::is_page(&query) {
            let _ = reply.send(Err("not an owned page query".into()));
            return;
        }
        let Some(profile) = self.profile.as_ref() else {
            let _ = reply.send(Err("the node is locked".into()));
            return;
        };
        if self.locking != 0 || profile.signer().is_err() {
            let _ = reply.send(Err("the node is locked".into()));
            return;
        }
        let Some(reference) = self.channels.get(&room).map(Arc::downgrade) else {
            let _ = reply.send(Err("room not open".into()));
            return;
        };
        let node = profile.fingerprint();
        let store = Arc::downgrade(&profile.store_handle());
        if self.page_reads.is_retired() {
            self.page_reads = page_read::ReadOwner::new();
        }
        let queued_node = Arc::clone(&self.page_reads);
        let budget = Arc::clone(&self.history_budget);
        let secret_work = Arc::clone(&self.secret_work);
        let clock = Arc::clone(&self.clock);
        let tx = self.net_tx.downgrade();
        let cancel = Arc::new(AtomicBool::new(false));
        self.reap_join_tasks();
        self.join_tasks.spawn(async move {
            let _cancel_on_drop = CancelOnDrop(Arc::clone(&cancel));
            let mut query = Some(query);
            let outcome: PageResult<page_read::Answer> = async {
                // No admission, byte reservation, snapshot or SEK clone while acquiring
                // only the original room's nonsecret cancellation identity.
                let queued_room = capture_lifetime(&reference, &secret_work, &queued_node, &mut reply).await?;
                loop {
                    if queued_room.is_retired() || queued_node.is_retired() { return Err("room read retired".into()); }
                    let mut ticket = budget.enqueue(node, Lane::LargeControl);
                    let job = loop {
                        let wake = ticket.wake();
                        if let Some(job) = ticket.try_admit() { break job; }
                        tokio::select! { biased;
                            () = reply.closed() => return Err("room read cancelled".into()),
                            () = queued_room.retired() => return Err("room read retired".into()),
                            () = queued_node.retired() => return Err("the node is locked".into()),
                            () = wake => {}
                        }
                    };
                    drop(ticket);
                    let charge = match job.reserve_or_pressure(page_read::ReadLeases::work_bytes()) {
                        Ok(charge) => charge,
                        Err(Error::HistoryCapacity(pressure)) => {
                            drop(job);
                            tokio::select! { biased;
                                () = reply.closed() => return Err("room read cancelled".into()),
                                () = queued_room.retired() => return Err("room read retired".into()),
                                () = queued_node.retired() => return Err("the node is locked".into()),
                                () = pressure.released() => {}
                            }
                            continue;
                        }
                        Err(error) => return Err(error.to_string()),
                    };
                    let Some(sender) = tx.upgrade() else { return Err("the node has stopped".into()); };
                    let (send, prepared) = oneshot::channel();
                    let request = PrepareRequest { room, node, reference: reference.clone(), store: store.clone(), lifetime: Arc::clone(&queued_room), node_lifetime: Arc::clone(&queued_node), reply: send };
                    tokio::select! { biased;
                        () = reply.closed() => return Err("room read cancelled".into()),
                        () = queued_room.retired() => return Err("room read retired".into()),
                        () = queued_node.retired() => return Err("the node is locked".into()),
                        sent = sender.send(NetEvent::PageReadPrepare(request)) => sent.map_err(|_| "the node has stopped")?,
                    }
                    drop(sender);
                    let prepared = tokio::select! { biased;
                        () = reply.closed() => return Err("room read cancelled".into()),
                        () = queued_room.retired() => return Err("room read retired".into()),
                        () = queued_node.retired() => return Err("the node is locked".into()),
                        prepared = prepared => prepared.map_err(|_| "the node stopped before preparing the read")??,
                    };
                    let (secret, room_work, lifetime, node_lifetime) = match prepared {
                        Prepared::Wait => {
                            drop(charge); drop(job);
                            wait_room(&reference, &secret_work, &mut reply, Some((&queued_room, &queued_node))).await?;
                            continue;
                        }
                        Prepared::Ready { secret, room_work, lifetime, node_lifetime } => (secret, room_work, lifetime, node_lifetime),
                    };
                    let Some(shared) = reference.upgrade() else { return Err("room not open".into()); };
                    let guard = match Arc::clone(&shared).try_lock_owned() {
                        Ok(guard) => guard,
                        Err(_) => {
                            drop(charge); drop(job); drop(secret); drop(room_work); drop(shared);
                            wait_room(&reference, &secret_work, &mut reply, Some((&lifetime, &node_lifetime))).await?;
                            continue;
                        }
                    };
                    let Some(work_store) = store.upgrade() else { return Err("the room reader's profile closed".into()); };
                    let physical_tail = job.clone();
                    let leases = page_read::ReadLeases::from_reserved(job, charge, Arc::clone(&secret), Arc::clone(&room_work));
                    let work_cancel = Arc::clone(&cancel);
                    let worker_node_lifetime = Arc::clone(&node_lifetime);
                    let work_query = query.take().ok_or("room read query was consumed")?;
                    let fault = Arc::new(std::sync::Mutex::new(None));
                    let work_fault = Arc::clone(&fault);
                    let mut worker = tokio::task::spawn_blocking(move || -> PageResult<page_read::Answer> {
                        let _physical_tail = physical_tail;
                        let mut guard = guard;
                        let now = clock();
                        let plan = guard.capture_page_read(&work_store, leases, now, worker_node_lifetime)
                            .map_err(|error| remember_fault(error, &work_fault))?;
                        match plan {
                            page_read::CapturePlan::Owned(capture) => {
                                drop(guard);
                                capture.run(work_query, &work_cancel, crate::node::ipc::rows_budget()).map_err(|error| remember_fault(error, &work_fault))
                            }
                            page_read::CapturePlan::Legacy { scope, leases } => {
                                let result = guard.history_query(&work_store, work_query, crate::node::ipc::rows_budget(), now);
                                drop(guard);
                                let reply = result?;
                                page_read::Answer::legacy(scope, reply, leases).map_err(|error| remember_fault(error, &work_fault))
                            }
                        }
                    });
                    drop(shared);
                    // Once spawned, ordinary cancellation joins the physical tail. Aborting
                    // this supervisor still retires the flag; the child's mandatory erasure
                    // guards and charges survive until it exits, as lock_all already requires.
                    let result = tokio::select! { biased;
                        result = &mut worker => result.map_err(|_| "room read worker stopped")?,
                        () = reply.closed() => { cancel.store(true, Ordering::Release); let _ = worker.await; return Err("room read cancelled".into()); }
                        () = lifetime.retired() => { cancel.store(true, Ordering::Release); let _ = worker.await; return Err("room read retired".into()); }
                        () = node_lifetime.retired() => { cancel.store(true, Ordering::Release); let _ = worker.await; return Err("the node is locked".into()); }
                    };
                    let stored_fault = fault.lock().ok().and_then(|mut stored| stored.take());
                    if let Some(error) = stored_fault {
                        let original_fault = error.to_string();
                        let error = Arc::new(error);
                        loop {
                            let Some(sender) = tx.upgrade() else { break; };
                            let (send, recorded) = oneshot::channel();
                            let request = FaultRequest { room, reference: reference.clone(), error: Arc::clone(&error), reply: send };
                            tokio::select! { biased;
                                () = reply.closed() => return Err("room read cancelled".into()),
                                () = queued_room.retired() => return Err(original_fault.clone()),
                                () = queued_node.retired() => return Err(original_fault.clone()),
                                sent = sender.send(NetEvent::PageReadFault(request)) => if sent.is_err() { break; },
                            }
                            drop(sender);
                            let done = tokio::select! { biased;
                                () = reply.closed() => return Err("room read cancelled".into()),
                                () = queued_room.retired() => return Err(original_fault.clone()),
                                () = queued_node.retired() => return Err(original_fault.clone()),
                                done = recorded => done.unwrap_or(true),
                            };
                            if done { break; }
                            wait_room(&reference, &secret_work, &mut reply, Some((&queued_room, &queued_node))).await.map_err(|_| original_fault.clone())?;
                        }
                    }
                    let mut answer = result?;
                    answer.scope.reference = reference.clone();
                    answer.scope.store = store.clone();
                    // Scalar validation only crosses the actor mailbox; plaintext stays owned
                    // here and is wiped on cancellation/lock, never queued on the actor.
                    loop {
                        if answer.is_retired() { return Err("room read retired".into()); }
                        let Some(sender) = tx.upgrade() else { return Err("the node has stopped".into()); };
                        let (send, validation) = oneshot::channel();
                        let request = PublishRequest { scope: answer.scope.clone(), reference: reference.clone(), store: store.clone(), reply: send };
                        tokio::select! { biased;
                            () = reply.closed() => return Err("room read cancelled".into()),
                            () = answer.retired() => return Err("room read retired".into()),
                            sent = sender.send(NetEvent::PageReadPublish(request)) => sent.map_err(|_| "the node has stopped")?,
                        }
                        drop(sender);
                        let current = tokio::select! { biased;
                            () = reply.closed() => return Err("room read cancelled".into()),
                            () = answer.retired() => return Err("room read retired".into()),
                            checked = validation => checked.map_err(|_| "the node stopped before publishing the read")??,
                        };
                        if current {
                            if answer.is_retired() { return Err("room read retired".into()); }
                            return Ok(answer);
                        }
                        wait_room(&reference, &secret_work, &mut reply, Some((&lifetime, &node_lifetime))).await?;
                    }
                }
            }.await;
            let _ = reply.send(outcome);
        });
    }

    pub(super) async fn retire_page_reads(&mut self, room: &Digest32) {
        let Some(lifetime) = self
            .page_read_rooms
            .remove(room)
            .and_then(|weak| weak.upgrade())
        else {
            return;
        };
        lifetime.retire();
        // No room mutex is needed to retire/drain. Cancelled tasks/writes drop their
        // erasure leases independently of the actor; this never waits a full count.
        lifetime.drain().await;
    }
}

async fn capture_lifetime(
    reference: &WeakRoom,
    secret_work: &Arc<tokio::sync::RwLock<()>>,
    node: &page_read::ReadLifetime,
    reply: &mut oneshot::Sender<PageResult<page_read::Answer>>,
) -> PageResult<Arc<page_read::ReadLifetime>> {
    let capture = async {
        // This guards the strong RoomRef only until its lock is released; no key
        // is copied and no physical/byte capacity is held during this wait.
        let secret = Arc::clone(secret_work).read_owned().await;
        let shared = reference.upgrade().ok_or("room not open")?;
        let room = shared.lock_owned().await;
        let lifetime = room.page_read_lifetime();
        if lifetime.is_retired() {
            return Err("room read retired".into());
        }
        drop(room);
        drop(secret);
        Ok(lifetime)
    };
    tokio::select! { biased;
        () = reply.closed() => Err("room read cancelled".into()),
        () = node.retired() => Err("the node is locked".into()),
        result = capture => result,
    }
}

async fn wait_room(
    reference: &WeakRoom,
    secret_work: &Arc<tokio::sync::RwLock<()>>,
    reply: &mut oneshot::Sender<PageResult<page_read::Answer>>,
    retirement: Option<(&page_read::ReadLifetime, &page_read::ReadLifetime)>,
) -> PageResult<()> {
    let wait = async {
        let _secret = Arc::clone(secret_work).read_owned().await;
        let shared = reference.upgrade().ok_or("room not open")?;
        drop(shared.lock_owned().await);
        Ok(())
    };
    if let Some((room, node)) = retirement {
        tokio::select! { biased; () = reply.closed() => Err("room read cancelled".into()), () = room.retired() => Err("room read retired".into()), () = node.retired() => Err("the node is locked".into()), result = wait => result }
    } else {
        tokio::select! { biased; () = reply.closed() => Err("room read cancelled".into()), result = wait => result }
    }
}

/// Revalidate a published metadata result without nested execution/byte admission.
/// The output lease itself retains both erasure barriers through this actual wait.
pub(super) async fn validate_reply(
    tx: &mpsc::Sender<NetEvent>,
    lease: &page_read::ReplyLease,
) -> PageResult<()> {
    loop {
        if lease.is_retired() {
            return Err("room read retired".into());
        }
        let scope = lease.scope().clone();
        let reference = scope.reference.clone();
        let store = scope.store.clone();
        let (reply, checked) = oneshot::channel();
        let request = PublishRequest {
            scope,
            reference: reference.clone(),
            store,
            reply,
        };
        tokio::select! { biased;
            () = lease.retired() => return Err("room read retired".into()),
            sent = tx.send(NetEvent::PageReadPublish(request)) => sent.map_err(|_| "the node has stopped")?,
        }
        let current = tokio::select! { biased;
            () = lease.retired() => return Err("room read retired".into()),
            checked = checked => checked.map_err(|_| "the node stopped before validating the read")??,
        };
        if current {
            return Ok(());
        }
        // No re-read or polling: observe the exact contended room lock release.
        let shared = reference.upgrade().ok_or("room not open")?;
        tokio::select! { biased;
            () = lease.retired() => return Err("room read retired".into()),
            guard = shared.lock_owned() => drop(guard),
        }
    }
}
