//! Bounded, off-actor discovery of recipient key bodies owed by a room peer.
use super::*;
use crate::node::channel::entry_store::sparse::KeyProviderCursor;
use crate::node::channel::KeyDebtPage;
use crate::node::history_budget::{Lane, Ticket};
use crate::node::history_stream::{authorization_generation, KeyBodyNeed};
use crate::node::ports::KeyBodyWait;

type Wake = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>;
enum ScanResult {
    Page(
        [u8; 16],
        Option<KeyProviderCursor>,
        KeyProviderCursor,
        KeyDebtPage,
    ),
    Advanced(KeyProviderCursor, bool),
    Installed(KeyProviderCursor),
    RemoteNeed([u8; 16], [u8; 16], u64, KeyBodyNeed),
    Exhausted([u8; 16], u64),
    RefreshCatalog,
    Superseded,
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
    connection: (u64, [u8; 16]),
    result: Arc<std::sync::Mutex<Option<ScanResult>>>,
}

#[derive(Default)]
pub(super) struct Controller {
    running: Option<Running>,
    /// Last selected port; wrap once so one backlog cannot monopolize this worker.
    after: Option<(Digest32, Digest32)>,
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
                .is_some_and(|conn| {
                    conn.quinn().close_reason().is_none() && conn.serial() == running.connection.0
                })
                && running.owner.key_catalog_connection(running.peer) == Some(running.connection);
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
                            ScanResult::Page(instance, expected, cursor, page) => {
                                port.key_provider_expected = expected;
                                port.key_provider_cursor = Some(cursor);
                                match page {
                                    KeyDebtPage::Ready { serial, need } => {
                                        port.key_debt_selected = Some(serial);
                                        port.key_body = Some(need);
                                        port.key_body_instance = Some(instance);
                                        port.key_body_token = Some(Arc::clone(&running.token));
                                        port.key_body_initialized = true;
                                        port.raise();
                                        self.sched_rooms.insert(running.room);
                                    }
                                    KeyDebtPage::Frozen { serial } => {
                                        port.key_debt_advance = Some(serial);
                                        port.key_body_initialized = false;
                                        self.bounded_completion_wake.notify_one();
                                    }
                                    KeyDebtPage::End => {
                                        let catalog = running.owner.key_catalog(running.peer);
                                        if let Some((catalog_instance, tip)) =
                                            catalog.filter(|catalog| {
                                                port.key_availability_exhausted != Some(*catalog)
                                            })
                                        {
                                            let after = if cursor.instance == catalog_instance {
                                                cursor.after
                                            } else {
                                                0
                                            };
                                            if tip > after {
                                                port.key_availability_request = Some((
                                                    (after != 0).then_some(after),
                                                    Arc::clone(&running.token),
                                                    catalog_instance,
                                                    tip,
                                                ));
                                                port.key_body_initialized = true;
                                                port.raise();
                                                self.sched_rooms.insert(running.room);
                                            } else {
                                                port.key_body_initialized = true;
                                                running.owner.ack_key(running.peer, &running.token);
                                            }
                                        } else {
                                            port.key_body_initialized = true;
                                            running.owner.ack_key(running.peer, &running.token);
                                        }
                                    }
                                }
                            }
                            ScanResult::Installed(cursor) => {
                                port.key_availability_exhausted = None;
                                port.key_provider_cursor = Some(cursor);
                                port.key_provider_expected = Some(cursor);
                                port.key_body_initialized = false;
                                self.bounded_completion_wake.notify_one();
                            }
                            ScanResult::Advanced(cursor, local_advanced) => {
                                port.key_provider_remote_turn = local_advanced;
                                port.key_provider_cursor = Some(cursor);
                                port.key_provider_expected = Some(cursor);
                                port.key_debt_advance = None;
                                port.key_evidence_advance = false;
                                port.key_remote_advance = None;
                                port.key_availability_page = None;
                                port.key_body_initialized = false;
                                self.bounded_completion_wake.notify_one();
                            }
                            ScanResult::RemoteNeed(room_instance, instance, serial, need) => {
                                port.key_availability_page = None;
                                port.key_remote_selected = Some((instance, serial));
                                port.key_body = Some(need);
                                port.key_body_instance = Some(room_instance);
                                port.key_body_token = Some(Arc::clone(&running.token));
                                port.key_body_initialized = true;
                                port.raise();
                                self.sched_rooms.insert(running.room);
                            }
                            ScanResult::Exhausted(instance, tip) => {
                                port.key_availability_page = None;
                                port.key_availability_exhausted = Some((instance, tip));
                                port.key_provider_remote_turn = false;
                                port.key_body_initialized = false;
                                self.bounded_completion_wake.notify_one();
                            }
                            ScanResult::RefreshCatalog => {
                                port.key_availability_page = None;
                                port.key_body_initialized = true;
                                port.raise();
                                self.sched_rooms.insert(running.room);
                            }
                            ScanResult::Superseded => {
                                port.key_debt_advance = None;
                                port.key_evidence_advance = false;
                                port.key_remote_advance = None;
                                port.key_availability_page = None;
                                port.key_provider_cursor = None;
                                port.key_provider_expected = None;
                                port.key_body_initialized = false;
                                self.bounded_completion_wake.notify_one();
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
        let mut select =
            |(&(room, peer), port): (&(Digest32, Digest32), &mut crate::node::ports::Port)| {
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
                let connection = owner.key_catalog_connection(peer)?;
                if self
                    .net
                    .as_ref()
                    .and_then(|net| net.manager().existing(&peer))
                    .map(|conn| conn.serial())
                    != Some(connection.0)
                {
                    return None;
                }
                let token = owner.key_token(peer)?;
                if !port
                    .key_body_scan_token
                    .as_ref()
                    .is_some_and(|old| Arc::ptr_eq(old, &token))
                {
                    return None;
                }
                let shared = self.channels.get(&room)?.clone();
                Some((
                    room,
                    peer,
                    owner.clone(),
                    token,
                    connection,
                    shared,
                    port.key_debt_advance,
                    port.key_evidence_advance,
                    port.key_remote_advance,
                    port.key_availability_page,
                    port.key_provider_cursor,
                    port.key_provider_expected,
                    port.key_provider_remote_turn,
                    owner.key_catalog(peer),
                    port.key_availability_exhausted,
                ))
            };
        let selected = match self.key_body_scan.after {
            Some(after) => self
                .ports
                .range_mut((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
                .find_map(&mut select)
                .or_else(|| self.ports.range_mut(..=after).find_map(&mut select)),
            None => self.ports.iter_mut().find_map(&mut select),
        };
        let Some((
            room,
            peer,
            owner,
            token,
            connection,
            shared,
            advance,
            evidence_advance,
            remote_advance,
            remote_page,
            held_cursor,
            held_expected,
            remote_turn,
            catalog,
            exhausted,
        )) = selected
        else {
            self.key_body_scan.ticket = None;
            return;
        };
        self.key_body_scan.after = Some((room, peer));
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
                    if advance.is_some() || remote_advance.is_some() {
                        let Some(mut cursor) = held_cursor else {
                            return Ok(ScanResult::Superseded);
                        };
                        if cursor.connection != connection.1 {
                            return Ok(ScanResult::Superseded);
                        }
                        cursor.evidence_unavailable |= evidence_advance;
                        if let Some(serial) = advance {
                            if serial <= cursor.local_after {
                                return Ok(ScanResult::Superseded);
                            }
                            cursor.local_after = serial;
                        }
                        if let Some((remote_instance, serial)) = remote_advance {
                            if remote_instance == cursor.instance && serial <= cursor.after {
                                return Ok(ScanResult::Superseded);
                            }
                            cursor.instance = remote_instance;
                            cursor.after = serial;
                        }
                        return if guard.advance_key_provider_cursor(
                            &store,
                            peer,
                            node,
                            generation,
                            held_expected,
                            cursor,
                        )? {
                            Ok(ScanResult::Advanced(cursor, advance.is_some()))
                        } else {
                            Ok(ScanResult::Superseded)
                        };
                    }
                    if let Some((expected_instance, tip, remote_instance, page)) = remote_page {
                        if remote_instance != expected_instance {
                            return Ok(ScanResult::RefreshCatalog);
                        }
                        let Some(mut cursor) = held_cursor else {
                            return Ok(ScanResult::Superseded);
                        };
                        if cursor.connection != connection.1 {
                            return Ok(ScanResult::Superseded);
                        }
                        let Some((serial, notice)) = page else {
                            return Ok(ScanResult::Exhausted(remote_instance, tip));
                        };
                        // A page beyond the advertised snapshot cannot advance that snapshot.
                        // Honest later acquisitions are independently announced by the provider.
                        if serial > tip {
                            return Ok(ScanResult::Exhausted(remote_instance, tip));
                        }
                        if remote_instance == cursor.instance && serial <= cursor.after {
                            return Err(Error::MalformedAtRest(
                                "key availability cursor did not advance",
                            ));
                        }
                        if let Some(notice) = notice {
                            match guard.key_debt_for_notice(&store, generation, notice)? {
                                None => return Ok(ScanResult::Busy(wake)),
                                Some(Some(need)) => {
                                    return Ok(ScanResult::RemoteNeed(
                                        instance,
                                        remote_instance,
                                        serial,
                                        need,
                                    ))
                                }
                                Some(None) => {}
                            }
                        }
                        cursor.instance = remote_instance;
                        cursor.after = serial;
                        return if guard.advance_key_provider_cursor(
                            &store,
                            peer,
                            node,
                            generation,
                            held_expected,
                            cursor,
                        )? {
                            Ok(ScanResult::Advanced(cursor, false))
                        } else {
                            Ok(ScanResult::Superseded)
                        };
                    }
                    let Some(peer_incarnation) = guard.history_inventory_incarnation(&peer) else {
                        return Ok(ScanResult::Ineligible);
                    };
                    let expected = guard.key_provider_cursor(&store, peer)?;
                    let mut cursor = expected
                        .filter(|cursor| {
                            cursor.authorization == generation
                                && cursor.peer_incarnation == peer_incarnation
                        })
                        .unwrap_or(KeyProviderCursor {
                            instance: [0; 16],
                            connection: connection.1,
                            after: 0,
                            local_after: 0,
                            evidence_unavailable: false,
                            authorization: generation,
                            peer_incarnation,
                        });
                    // Install this physical connection's fence before doing any cursor work.
                    // Earlier completed positions are safe to retain only when no evidence
                    // failure requires exceptional rediscovery on a real reconnect.
                    if expected.is_none_or(|old| {
                        old.connection != connection.1
                            || old.authorization != generation
                            || old.peer_incarnation != peer_incarnation
                    }) {
                        if cursor.evidence_unavailable {
                            cursor.instance = [0; 16];
                            cursor.after = 0;
                            cursor.local_after = 0;
                            cursor.evidence_unavailable = false;
                        }
                        cursor.connection = connection.1;
                        if guard.history_publication_busy(&store)? {
                            return Ok(ScanResult::Busy(wake));
                        }
                        return if guard.advance_key_provider_cursor(
                            &store, peer, node, generation, expected, cursor,
                        )? {
                            Ok(ScanResult::Installed(cursor))
                        } else {
                            Ok(ScanResult::Superseded)
                        };
                    }
                    // Repair a previously poisoned remote position without rewinding local debt.
                    // The provider's monotonic tip bounds every valid position in its instance.
                    if catalog.is_some_and(|(catalog_instance, tip)| {
                        cursor.instance == catalog_instance && cursor.after > tip
                    }) {
                        cursor.instance = [0; 16];
                        cursor.after = 0;
                        if guard.history_publication_busy(&store)? {
                            return Ok(ScanResult::Busy(wake));
                        }
                        return if guard.advance_key_provider_cursor(
                            &store, peer, node, generation, expected, cursor,
                        )? {
                            Ok(ScanResult::Installed(cursor))
                        } else {
                            Ok(ScanResult::Superseded)
                        };
                    }
                    if remote_turn
                        && catalog.is_some_and(|(catalog_instance, tip)| {
                            exhausted != Some((catalog_instance, tip))
                                && tip
                                    > if cursor.instance == catalog_instance {
                                        cursor.after
                                    } else {
                                        0
                                    }
                        })
                    {
                        return Ok(ScanResult::Page(
                            instance,
                            expected,
                            cursor,
                            KeyDebtPage::End,
                        ));
                    }
                    match guard.key_debt_after(&store, generation, cursor.local_after)? {
                        Some(page) => Ok(ScanResult::Page(instance, expected, cursor, page)),
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
            connection,
            result,
        });
    }
}
