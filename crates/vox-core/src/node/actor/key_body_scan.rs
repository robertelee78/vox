//! Bounded, off-actor discovery of recipient key bodies owed by a room peer.
use super::*;
use crate::node::history_budget::{Lane, Ticket};
use crate::node::history_stream::{authorization_generation, KeyBodyNeed};
use crate::node::ports::KeyBodyWait;

type Wake = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>;
type Page = (Option<[u8; 64]>, Option<KeyBodyNeed>);
enum ScanResult {
    Page([u8; 16], Page),
    Busy(Wake),
    Ineligible,
    Failed(String),
}

struct Running {
    room: Digest32,
    peer: Digest32,
    shared: Arc<Mutex<ChannelState>>,
    owner: Arc<crate::node::channel::role_owed::RoleOwed>,
    token: Arc<()>,
    result: Arc<std::sync::Mutex<Option<ScanResult>>>,
}

#[derive(Default)]
pub(super) struct Controller {
    running: Option<Running>,
    ticket: Option<Ticket>,
    capacity_wait: Option<(
        tokio::task::JoinHandle<()>,
        Arc<std::sync::atomic::AtomicBool>,
    )>,
}

impl Drop for Controller {
    fn drop(&mut self) {
        if let Some((wait, _)) = self.capacity_wait.take() {
            wait.abort();
        }
    }
}

impl Node {
    pub(super) fn advance_key_body_scan(&mut self) {
        if let Some(running) = self.key_body_scan.running.as_ref() {
            let result = running
                .result
                .lock()
                .ok()
                .and_then(|mut value| value.take());
            let Some(result) = result else { return };
            let running = self.key_body_scan.running.take().expect("running scan");
            let current_room = self
                .channels
                .get(&running.room)
                .is_some_and(|room| Arc::ptr_eq(room, &running.shared));
            let current_token = running
                .owner
                .key_token(running.peer)
                .is_some_and(|token| Arc::ptr_eq(&token, &running.token));
            let current_owner = self.role_wake.current(running.room, &running.owner);
            let trusted = self.trust.is_trusted(&running.peer);
            let connected = self
                .net
                .as_ref()
                .and_then(|net| net.manager().existing(&running.peer))
                .is_some_and(|conn| conn.quinn().close_reason().is_none());
            let exact_port = self
                .ports
                .get(&(running.room, running.peer))
                .is_some_and(|port| {
                    port.room
                        .is(&crate::node::ports::RoomRef::Channel(Arc::downgrade(
                            &running.shared,
                        )))
                });
            if current_room && current_owner && current_token && trusted && connected && exact_port
            {
                if let Some(port) = self.ports.get_mut(&(running.room, running.peer)) {
                    // Never overwrite a body currently owned by a physical Flow.
                    if port.key_body.is_none() {
                        match result {
                            ScanResult::Page(instance, (after, need)) => {
                                port.key_body_after = after;
                                if let Some(need) = need {
                                    port.key_body = Some(need);
                                    port.key_body_instance = Some(instance);
                                    port.key_body_token = Some(Arc::clone(&running.token));
                                    port.key_body_initialized = true;
                                    port.raise();
                                    self.sched_rooms.insert(running.room);
                                } else if after.is_some() {
                                    port.key_body_initialized = false;
                                    self.bounded_completion_wake.notify_one();
                                } else {
                                    port.key_body_initialized = true;
                                    running.owner.ack_key(running.peer, &running.token);
                                }
                            }
                            ScanResult::Busy(wake) => {
                                let owner = Arc::clone(&running.owner);
                                let peer = running.peer;
                                port.key_body_wait = Some(KeyBodyWait(tokio::spawn(async move {
                                    wake.await;
                                    owner.mark_key_dirty(peer);
                                })));
                            }
                            ScanResult::Ineligible => port.key_body_initialized = true,
                            ScanResult::Failed(error) => {
                                port.key_body_initialized = true;
                                eprintln!("vox: recipient key recovery could not inspect saved work: {error}");
                            }
                        }
                    }
                }
            }
        }
        if self.key_body_scan.running.is_some() {
            return;
        }
        if let Some((_, completed)) = self.key_body_scan.capacity_wait.as_ref() {
            if !completed.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            self.key_body_scan.capacity_wait = None;
        }
        let Some(profile) = self.profile.as_ref() else {
            self.key_body_scan.ticket = None;
            return;
        };
        let node = profile.fingerprint();
        let store = profile.store_handle();
        let selected = self.ports.iter_mut().find_map(|(&(room, peer), port)| {
            if port
                .key_body_wait
                .as_ref()
                .is_some_and(|wait| wait.0.is_finished())
            {
                port.key_body_wait = None;
            }
            if port.key_body.is_some()
                || port.key_body_initialized
                || port.key_body_wait.is_some()
                || !self.trust.is_trusted(&peer)
                || !self
                    .net
                    .as_ref()
                    .and_then(|net| net.manager().existing(&peer))
                    .is_some_and(|conn| conn.quinn().close_reason().is_none())
            {
                return None;
            }
            let owner = self.role_wake.owner(room)?;
            let token = owner.key_token(peer)?;
            if !port
                .key_body_scan_token
                .as_ref()
                .is_some_and(|old| Arc::ptr_eq(old, &token))
            {
                return None;
            }
            let shared = self.channels.get(&room)?.clone();
            Some((room, peer, owner, token, shared, port.key_body_after))
        });
        let Some((room, peer, owner, token, shared, after)) = selected else {
            self.key_body_scan.ticket = None;
            return;
        };
        let guard = match shared.clone().try_lock_owned() {
            Ok(guard) => guard,
            Err(_) => {
                self.key_body_scan.ticket = None;
                if let Some(port) = self.ports.get_mut(&(room, peer)) {
                    port.key_body_wait = Some(KeyBodyWait(tokio::spawn(async move {
                        drop(shared.lock_owned().await);
                        owner.mark_key_dirty(peer);
                    })));
                }
                self.bounded_completion_wake.notify_one();
                return;
            }
        };
        if self.key_body_scan.ticket.is_none() {
            self.key_body_scan.ticket = Some(self.history_budget.enqueue(node, Lane::Control));
        }
        let ticket = self.key_body_scan.ticket.as_mut().expect("scan ticket");
        let wake = ticket.wake();
        let Some(job) = ticket.try_admit() else {
            drop(guard);
            let done = Arc::clone(&self.bounded_completion_wake);
            let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let signal = Arc::clone(&completed);
            let task = tokio::spawn(async move {
                wake.await;
                signal.store(true, std::sync::atomic::Ordering::Release);
                done.notify_one();
            });
            self.key_body_scan.capacity_wait = Some((task, completed));
            return;
        };
        self.key_body_scan.ticket = None;
        let charge = match job.reserve_or_pressure(64 * 1024) {
            Ok(charge) => charge,
            Err(Error::HistoryCapacity(pressure)) => {
                drop(guard);
                drop(job);
                let done = Arc::clone(&self.bounded_completion_wake);
                let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let signal = Arc::clone(&completed);
                let task = tokio::spawn(async move {
                    (*pressure).released().await;
                    signal.store(true, std::sync::atomic::Ordering::Release);
                    done.notify_one();
                });
                self.key_body_scan.capacity_wait = Some((task, completed));
                return;
            }
            Err(error) => {
                if let Some(port) = self.ports.get_mut(&(room, peer)) {
                    port.key_body_initialized = true;
                }
                eprintln!("vox: recipient key recovery admission failed: {error}");
                return;
            }
        };
        let secret = match self.secret_work.clone().try_read_owned() {
            Ok(secret) => secret,
            Err(_) => {
                drop(charge);
                drop(job);
                drop(guard);
                let secret = self.secret_work.clone();
                if let Some(port) = self.ports.get_mut(&(room, peer)) {
                    port.key_body_wait = Some(KeyBodyWait(tokio::spawn(async move {
                        drop(secret.read_owned().await);
                        owner.mark_key_dirty(peer);
                    })));
                }
                self.bounded_completion_wake.notify_one();
                return;
            }
        };
        let result = Arc::new(std::sync::Mutex::new(None));
        let output = Arc::clone(&result);
        let done = Arc::clone(&self.bounded_completion_wake);
        tokio::spawn(async move {
            let inspected = tokio::task::spawn_blocking(move || {
                let _held = (secret, job, charge);
                let inspected = (|| -> crate::error::Result<ScanResult> {
                    if !guard.is_member(&peer) || !guard.is_member(&node) {
                        return Ok(ScanResult::Ineligible);
                    }
                    let instance = guard.history_instance(&store)?;
                    let generation =
                        authorization_generation(&store, node, room, instance, guard.epoch())?;
                    let wake = guard.history_publication_wake();
                    match guard.history_key_body_page(&store, peer, generation, after)? {
                        Some(page) => Ok(ScanResult::Page(instance, page)),
                        None => Ok(ScanResult::Busy(wake)),
                    }
                })()
                .unwrap_or_else(|error| ScanResult::Failed(error.to_string()));
                drop(guard);
                inspected
            })
            .await
            .unwrap_or_else(|_| ScanResult::Failed("inspection worker stopped".to_owned()));
            if let Ok(mut output) = output.lock() {
                *output = Some(inspected);
            }
            done.notify_one();
        });
        self.key_body_scan.running = Some(Running {
            room,
            peer,
            shared,
            owner,
            token,
            result,
        });
    }
}
