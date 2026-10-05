//! **The daemon's one network presence** (ADR-026 D-3, ADR-012 N-41–N-45): one UDP socket, one
//! QUIC endpoint ([`SharedEndpoint`]) and one inbound gate, shared by every node attached.
//!
//! A node attaches ([`NetPresence::attach`]) and gets its view of the endpoint and the connections
//! accepted for it. The presence accepts every inbound attempt under one gate — at most
//! [`HANDSHAKES_IN_FLIGHT`] handshakes and identity exchanges at once, a validated attempt past
//! that waiting a moment for a slot, an unvalidated one sent a Retry — runs the neutral handshake
//! and the identity exchange, and hands the connection to the node the exchange named. A node
//! sees only its own connections, and never one before its `CLAIM` verified (ADR-011
//! requirement 33).
//!
//! A node that detaches drops its [`NodeLink`]: it leaves the exchange (its signer with it), its
//! inbound queue closes, and nothing about the endpoint or any other node's connections changes
//! (D-5). Closing the presence ([`NetPresence::close`]) is the daemon stopping.
//!
//! A node that has the machine to itself (today's `vox daemon` and `vox serve`) runs on a presence
//! of its own, made for it and closed with it.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, watch, Semaphore};

use crate::error::Result;
use crate::hash::Digest32;
use crate::identity::composite::RootSigner;
use crate::nat::multiaddr::{EndpointList, Multiaddr};
use crate::nat::portmap::PortMapping;
use crate::node::circuitstream::CircuitLedger;
use crate::node::nearby::{Entry, Nearby};
use crate::transport::quic::{unix_now, SharedEndpoint, VoxConnection, VoxEndpoint};

/// How many inbound handshakes — the TLS handshake and the identity exchange after it — may run
/// at once (ADR-011 requirement 34): the cap pre-identity connections share.
///
/// Inline, the ceiling was one, which was the defect. Enough that ordinary use never reaches it,
/// small enough that an attacker cannot make a daemon hold unbounded state.
pub const HANDSHAKES_IN_FLIGHT: usize = 64;

/// How many validated attempts may wait for a handshake slot at once; past it, one is refused.
/// Twice the members of a large room (PRD-001), so a whole room redialling a restarted anchor
/// waits rather than being turned away, and still a bound on what a flood can make a node hold.
pub const HANDSHAKES_WAITING: usize = 1024;

/// How long a validated attempt may wait for a handshake slot before it is refused: half of what
/// a dialler gives one attempt (`nat::reachability::PER_ATTEMPT_TIMEOUT`, 10 s), so an attempt
/// given a slot still has a dialler waiting for it.
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(5);

/// How many accepted connections may wait for a node to take them before more are closed.
const INBOUND_QUEUE: usize = 256;

/// How long the presence's close waits for the closes to leave: the node's stop budget for it.
const CLOSE_FLUSH: Duration = Duration::from_millis(600);

/// One burst of inbound attempts that had to wait for a handshake slot, from the first that
/// waited until none was waiting: what each node says of it (`NodeEvent::HandshakesQueued`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandshakeBurst {
    /// How many waited in all.
    pub waited: usize,
    /// The most that waited at once.
    pub most_waiting: usize,
    /// The most handshakes seen running at once.
    pub most_running: usize,
    /// How many were refused: no place to wait, or no slot within [`HANDSHAKE_WAIT`].
    pub refused: usize,
    /// The longest any waited.
    pub longest: Duration,
}

/// The burst being counted, with how many wait now.
#[derive(Default)]
struct Burst {
    waiting: usize,
    counted: HandshakeBurst,
}

impl Burst {
    /// A handshake took a slot of `gate`.
    fn ran(&mut self, gate: &Semaphore) {
        if self.waiting > 0 {
            self.counted.most_running = self
                .counted
                .most_running
                .max(HANDSHAKES_IN_FLIGHT - gate.available_permits());
        }
    }

    /// An attempt starts waiting for a slot of `gate`.
    fn enter(&mut self, gate: &Semaphore) {
        self.counted.most_running = self
            .counted
            .most_running
            .max(HANDSHAKES_IN_FLIGHT - gate.available_permits());
        self.waiting += 1;
        self.counted.waited += 1;
        self.counted.most_waiting = self.counted.most_waiting.max(self.waiting);
    }

    /// An attempt stops waiting after `waited`; when it was the last, the burst is over.
    fn leave(&mut self, waited: Duration) -> Option<HandshakeBurst> {
        self.waiting -= 1;
        self.counted.longest = self.counted.longest.max(waited);
        self.over()
    }

    /// When nothing is left waiting, the burst is over: what it came to. A refusal with nothing
    /// waiting is a burst of its own, so no refusal goes unsaid.
    fn over(&mut self) -> Option<HandshakeBurst> {
        (self.waiting == 0).then(|| std::mem::take(&mut self.counted))
    }
}

fn lock_burst(b: &Mutex<Burst>) -> std::sync::MutexGuard<'_, Burst> {
    b.lock().unwrap_or_else(PoisonError::into_inner)
}

/// **The machine's one presence**: the shared endpoint and the gate in front of it, and what the
/// daemon keeps once for every node on it (ADR-026 D-3, ADR-012 N-41–N-45): the addresses the
/// ladder's publish side composed and the gateway mappings behind them, the reflexive addresses
/// peers report, the relay ledger and the nearby group.
pub struct NetPresence {
    shared: Arc<SharedEndpoint>,
    bursts: broadcast::Sender<HandshakeBurst>,
    accept: tokio::task::AbortHandle,
    /// What every node on this presence advertises (ADR-012 N-46: one ip:port for all), composed
    /// once per presence. `None` until the first discovery has run.
    advertised: watch::Sender<Option<EndpointList>>,
    /// The gateway mappings in force, renewed and retried per address family (N-43).
    mapping: Mutex<Mapping>,
    /// What the last discovery or renewal asked, per family, and what answered (N-54).
    asks: Mutex<crate::nat::reachability::GatewayAsks>,
    /// The task that discovers, maps and renews.
    mapper: Mutex<Option<tokio::task::AbortHandle>>,
    /// Wakes the mapper for a discovery now.
    rediscover: Arc<tokio::sync::Notify>,
    /// How many discoveries the presence has run: one at start and one per renewal or
    /// rediscovery, never one per node.
    discoveries: std::sync::atomic::AtomicU64,
    /// What each peer reports as this presence's source address, by (the local node it reported
    /// to, the reporter): one socket, so every node's reporters describe the same address
    /// (ADR-012 rung 3, N-43). Never published.
    observed: Mutex<BTreeMap<(Digest32, Digest32), Multiaddr>>,
    /// The one relay ledger (N-45): the relay caps hold across every node on the presence.
    ledger: Arc<CircuitLedger>,
    /// The nearby group, opened for the first node that wants it (N-44), and what it hears, said
    /// to every node.
    nearby: Mutex<Option<NearbyGroup>>,
}

/// What the nearby group heard: where from, and the members it named.
pub type Heard = (IpAddr, Vec<Entry>);

/// The nearby group of a presence: the socket, what it hears, and the task that hears it.
struct NearbyGroup {
    nearby: Arc<Nearby>,
    heard: broadcast::Sender<Heard>,
    task: tokio::task::AbortHandle,
}

/// The gateway mappings of a presence, per address family (V210-75): `false` for the IPv4
/// mapping, `true` for the IPv6 pinhole.
#[derive(Default)]
struct Mapping {
    /// The mappings in force.
    held: Vec<PortMapping>,
    /// When each family's timed lease runs out (unix seconds). Until then its mapped address is
    /// still advertised, even while its renewal is failing.
    expires: BTreeMap<bool, u64>,
    /// The wait set after the last discovery that got nothing back for a family whose lease had
    /// run out, doubling from [`MAPPING_RETRY_SECS`] to [`MAPPING_RETRY_MAX_SECS`].
    retry: BTreeMap<bool, u64>,
    /// When each family's timed lease was granted (unix seconds) and for how long: the
    /// renewal schedule is fractions of it (N-55).
    granted: BTreeMap<bool, (u64, u64)>,
    /// How many renewals of each family's lease have failed in a row (N-55: retried at 3/4,
    /// then 7/8 of the lifetime).
    failures: BTreeMap<bool, u8>,
}

/// The first wait before a port-mapping renewal that got nothing back is tried again (V210-75),
/// doubling to [`MAPPING_RETRY_MAX_SECS`]. A gateway that is restarting, or a request lost on
/// the way, must not end renewal for the life of the presence.
const MAPPING_RETRY_SECS: u64 = 15;

/// The longest wait between retries of a failed port-mapping renewal.
const MAPPING_RETRY_MAX_SECS: u64 = 600;

/// The least time between two renewal attempts of one lease: RFC 6887 §11.2.1's 4 s (N-55), plus
/// one, because the schedule is kept in whole seconds and an attempt started late in one second
/// and the next early in another would otherwise be under 4 s apart.
const RENEW_SPACING_SECS: u64 = 5;

/// A uniformly random whole number of seconds in `lo..=hi`.
fn uniform(lo: u64, hi: u64) -> u64 {
    if hi <= lo {
        return lo;
    }
    let r: [u8; 8] = crate::identity::rng::random_array().unwrap_or([0; 8]);
    lo + u64::from_le_bytes(r) % (hi - lo + 1)
}

/// When a lease of `lifetime` seconds granted at `at` is first renewed: a uniformly random point
/// in 1/2–5/8 of it (RFC 6887 §11.2.1, N-55), so clients behind one server do not renew in step.
fn first_renewal(at: u64, lifetime: u64) -> u64 {
    at + uniform(lifetime / 2, lifetime * 5 / 8).max(1)
}

/// When a lease of `lifetime` granted at `at` is tried again after `failures` failed renewals,
/// the last started at `last`: at 3/4 of the lifetime, then 7/8 (N-55), never less than
/// [`RENEW_SPACING_SECS`] after the last try. Past 7/8 it is the lease's end, where a discovery
/// asks for a new mapping.
fn retry_renewal(at: u64, lifetime: u64, failures: u8, last: u64) -> u64 {
    let target = match failures {
        1 => at + lifetime * 3 / 4,
        2 => at + lifetime * 7 / 8,
        _ => at + lifetime,
    };
    target.max(last + RENEW_SPACING_SECS)
}

/// Whether a mapping is the IPv6 pinhole (`true`) rather than the IPv4 mapping.
fn mapping_is_v6(m: &PortMapping) -> bool {
    m.method == crate::nat::portmap::Method::PcpV6Pinhole
}

impl Mapping {
    /// Take what a discovery or a renewal (started at `started`) was granted, **per address
    /// family** (V210-75), and say when the next renewal or retry is due.
    ///
    /// A family granted again is held anew and renewed at a random point in 1/2–5/8 of its lease
    /// (N-55). A family whose renewal got nothing back is tried again at 3/4 and then 7/8 of the
    /// lease, at least [`RENEW_SPACING_SECS`] apart, and its mapping is kept, and still
    /// advertised, until its lease runs out: the gateway most likely still holds it, and a lost
    /// reply is not a withdrawn mapping. Once the lease is over, a discovery asks again after a
    /// backoff of its own. A permanent grant (lifetime zero) is never re-requested; it is deleted
    /// when the presence closes.
    fn take(&mut self, fresh: &[PortMapping], started: u64, now: u64) -> Option<u64> {
        let mut held = Vec::new();
        let mut due: Option<u64> = None;
        let mut sooner = |at: u64| due = Some(due.map_or(at, |d| d.min(at)));
        for v6 in [false, true] {
            let granted = fresh.iter().find(|m| mapping_is_v6(m) == v6).copied();
            let had = self.held.iter().find(|m| mapping_is_v6(m) == v6).copied();
            if let Some(m) = granted {
                held.push(m);
                self.retry.remove(&v6);
                self.failures.remove(&v6);
                if m.lifetime_secs > 0 {
                    let lifetime = u64::from(m.lifetime_secs);
                    self.expires.insert(v6, now + lifetime);
                    self.granted.insert(v6, (now, lifetime));
                    sooner(first_renewal(now, lifetime));
                } else {
                    self.expires.remove(&v6);
                    self.granted.remove(&v6);
                }
                continue;
            }
            if let Some(m) = had.filter(|m| m.lifetime_secs == 0) {
                held.push(m);
                continue;
            }
            // A held lease whose renewal failed: kept, and tried again on the RFC's schedule.
            if let (Some(m), Some(&expires), Some(&(at, lifetime))) =
                (had, self.expires.get(&v6), self.granted.get(&v6))
            {
                if now < expires {
                    let failures = self.failures.get(&v6).copied().unwrap_or(0) + 1;
                    self.failures.insert(v6, failures);
                    held.push(m);
                    sooner(retry_renewal(at, lifetime, failures, started).min(expires));
                    continue;
                }
            }
            self.failures.remove(&v6);
            self.granted.remove(&v6);
            if had.is_none() && !self.retry.contains_key(&v6) {
                continue; // never granted: no gateway for this family, nothing to keep alive
            }
            let wait = (self.retry.get(&v6).copied().unwrap_or(0) * 2)
                .clamp(MAPPING_RETRY_SECS, MAPPING_RETRY_MAX_SECS);
            self.retry.insert(v6, wait);
            let mut at = now + wait;
            match (had, self.expires.get(&v6).copied()) {
                (Some(m), Some(expires)) if now < expires => {
                    held.push(m);
                    at = at.min(expires);
                }
                _ => {
                    self.expires.remove(&v6);
                }
            }
            sooner(at);
        }
        self.held = held;
        due
    }

    /// The mappings whose lease has not run out, offered again at a renewal so a family whose
    /// renewal fails is still advertised at its mapped address until the lease ends.
    fn leased(&self, now: u64) -> Vec<PortMapping> {
        self.held
            .iter()
            .filter(|m| {
                m.lifetime_secs == 0
                    || self
                        .expires
                        .get(&mapping_is_v6(m))
                        .is_some_and(|at| now < *at)
            })
            .copied()
            .collect()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A node's attachment to a [`NetPresence`]: its view of the endpoint, and the connections
/// accepted for it. Dropping the endpoint view takes the node off the exchange.
pub struct NodeLink {
    /// This node's view of the shared endpoint.
    pub endpoint: Arc<VoxEndpoint>,
    /// Connections accepted for this node, after their identity exchange.
    pub inbound: mpsc::Receiver<VoxConnection>,
}

impl NetPresence {
    /// Run the presence on `shared`: its accept loop starts now.
    #[must_use]
    pub fn start(shared: Arc<SharedEndpoint>) -> Arc<Self> {
        let (bursts, _) = broadcast::channel(16);
        let accept = spawn_accept_loop(Arc::clone(&shared), bursts.clone());
        let presence = Arc::new(Self {
            shared,
            bursts,
            accept,
            advertised: watch::channel(None).0,
            mapping: Mutex::new(Mapping::default()),
            asks: Mutex::new(crate::nat::reachability::GatewayAsks::default()),
            mapper: Mutex::new(None),
            rediscover: Arc::new(tokio::sync::Notify::new()),
            discoveries: std::sync::atomic::AtomicU64::new(0),
            observed: Mutex::new(BTreeMap::new()),
            ledger: Arc::new(CircuitLedger::default()),
            nearby: Mutex::new(None),
        });
        let mapper = spawn_mapper(Arc::downgrade(&presence));
        *lock(&presence.mapper) = Some(mapper);
        presence
    }

    /// Bind a presence on `addr` **keeping its port** (V210-167, ADR-012 N-42): the port in
    /// `port_file` (else in `fallback`) is bound again, so the address records every node
    /// published stay valid. A first start records the port it was given; if another program
    /// holds the kept port, another is bound for this run, the file keeps the old one, and the
    /// second value says so. A port given explicitly is bound as given and not recorded.
    ///
    /// # Errors
    /// As [`SharedEndpoint::bind`].
    pub fn bind_kept(
        addr: std::net::SocketAddr,
        port_file: &std::path::Path,
        fallback: Option<&std::path::Path>,
    ) -> Result<(Arc<SharedEndpoint>, Option<String>)> {
        if addr.port() != 0 {
            return Ok((SharedEndpoint::bind(addr)?, None));
        }
        let read_port = |f: &std::path::Path| {
            std::fs::read_to_string(f)
                .ok()
                .and_then(|t| t.trim().parse::<u16>().ok())
                .filter(|p| *p != 0)
        };
        let kept = read_port(port_file).or_else(|| fallback.and_then(read_port));
        let Some(port) = kept else {
            let endpoint = SharedEndpoint::bind(addr)?;
            if let Ok(at) = endpoint.local_addr() {
                let _ = crate::node::paths::write_private_file(
                    port_file,
                    format!("{}\n", at.port()).as_bytes(),
                );
            }
            return Ok((endpoint, None));
        };
        let why = match SharedEndpoint::bind(std::net::SocketAddr::new(addr.ip(), port)) {
            Ok(endpoint) => return Ok((endpoint, None)),
            Err(crate::error::Error::LocalBind {
                cause: crate::error::BindCause::InUse,
                ..
            }) => "another program holds it".to_owned(),
            Err(e) => e.to_string(),
        };
        let endpoint = SharedEndpoint::bind(addr)?;
        let now = endpoint
            .local_addr()
            .map_or_else(|_| "another".to_owned(), |a| a.port().to_string());
        Ok((
            endpoint,
            Some(format!(
                "port {port} is not free ({why}), so it listens on port {now} this run"
            )),
        ))
    }

    /// What every node on this presence advertises, as a watch: `None` until the first discovery
    /// has run, then each new composition.
    #[must_use]
    pub fn advertised(&self) -> watch::Receiver<Option<EndpointList>> {
        self.advertised.subscribe()
    }

    /// What every node on this presence advertises now, if a discovery has run.
    #[must_use]
    pub fn advertised_now(&self) -> Option<EndpointList> {
        self.advertised.borrow().clone()
    }

    /// The gateway mappings in force.
    #[must_use]
    pub fn port_mappings(&self) -> Vec<PortMapping> {
        lock(&self.mapping).held.clone()
    }

    /// What the last discovery or renewal asked, per address family, and which candidate
    /// answered on which rung (N-54): what `vox status` names.
    #[must_use]
    pub fn gateway_asks(&self) -> crate::nat::reachability::GatewayAsks {
        lock(&self.asks).clone()
    }

    /// How many discoveries (the ladder's publish side, with its gateway requests) this presence
    /// has run.
    #[must_use]
    pub fn discoveries(&self) -> u64 {
        self.discoveries.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Run the ladder's publish side again now (a node's network changed).
    pub fn rediscover(&self) {
        self.rediscover.notify_one();
    }

    /// Remember what `reporter`, asked by the local node `local`, said this presence's source
    /// address is.
    pub fn note_observed(&self, local: Digest32, reporter: Digest32, addr: Multiaddr) {
        lock(&self.observed).insert((local, reporter), addr);
    }

    /// Forget what `reporter` told `local` (its connection is gone).
    pub fn forget_observed(&self, local: &Digest32, reporter: &Digest32) {
        lock(&self.observed).remove(&(*local, *reporter));
    }

    /// The address the reporters agree they see for this presence, if any: the one most report,
    /// counting each reporter once whichever node it told.
    #[must_use]
    pub fn observed_addr(&self) -> Option<Multiaddr> {
        let observed = lock(&self.observed);
        let mut by_reporter: BTreeMap<Digest32, Multiaddr> = BTreeMap::new();
        for ((_, reporter), addr) in observed.iter() {
            by_reporter.insert(*reporter, *addr);
        }
        let mut tally: Vec<(Multiaddr, usize)> = Vec::new();
        for addr in by_reporter.values() {
            match tally.iter_mut().find(|(a, _)| a == addr) {
                Some((_, n)) => *n += 1,
                None => tally.push((*addr, 1)),
            }
        }
        tally.into_iter().max_by_key(|(_, n)| *n).map(|(a, _)| a)
    }

    /// Discard every reflexive address, so the next punch asks again: they are true only of the
    /// network the machine was on when they were asked.
    pub fn refresh_observed(&self) {
        lock(&self.observed).clear();
    }

    /// The one relay ledger of this presence (ADR-012 N-45).
    #[must_use]
    pub fn ledger(&self) -> &Arc<CircuitLedger> {
        &self.ledger
    }

    /// The nearby group (ADR-012 N-44), opened once for the first node that asks, and what it
    /// hears from now on. `None` if the group cannot be opened here.
    pub fn nearby(&self) -> Option<(Arc<Nearby>, broadcast::Receiver<Heard>)> {
        let mut group = lock(&self.nearby);
        if group.is_none() {
            let nearby = Arc::new(Nearby::open().ok()?);
            let (heard, _) = broadcast::channel(64);
            let (hear, tx) = (Arc::clone(&nearby), heard.clone());
            let task = tokio::spawn(async move {
                while let Ok(said) = hear.hear().await {
                    let _ = tx.send(said);
                }
            })
            .abort_handle();
            *group = Some(NearbyGroup {
                nearby,
                heard,
                task,
            });
        }
        group
            .as_ref()
            .map(|g| (Arc::clone(&g.nearby), g.heard.subscribe()))
    }

    /// **A node gone without detaching** — its actor panicked (ADR-026 L-6): take it off the
    /// exchange and close every connection it had, as stopping. Nothing of any other node's is
    /// touched.
    pub fn evict(&self, local: &Digest32) {
        self.shared.evict(local);
    }

    /// Bind a presence on `addr` ([`SharedEndpoint::bind`]).
    ///
    /// # Errors
    /// As [`SharedEndpoint::bind`].
    pub fn bind(addr: std::net::SocketAddr) -> Result<Arc<Self>> {
        Ok(Self::start(SharedEndpoint::bind(addr)?))
    }

    /// **Attach a node**: register it on the endpoint with a fresh instance, and give it its view
    /// and its inbound connections.
    ///
    /// # Errors
    /// As [`SharedEndpoint::register`]: the node is attached here already.
    pub fn attach(&self, signer: Arc<dyn RootSigner + Send + Sync>) -> Result<NodeLink> {
        let (tx, inbound) = mpsc::channel(INBOUND_QUEUE);
        let endpoint = self.shared.register(signer, Some(tx))?;
        Ok(NodeLink {
            endpoint: Arc::new(endpoint),
            inbound,
        })
    }

    /// The shared endpoint.
    #[must_use]
    pub fn shared(&self) -> &Arc<SharedEndpoint> {
        &self.shared
    }

    /// The handshake bursts the gate reports, for a node to say.
    #[must_use]
    pub fn bursts(&self) -> broadcast::Receiver<HandshakeBurst> {
        self.bursts.subscribe()
    }

    /// **Close the presence** — the daemon stopping: the accept loop ends, the endpoint and every
    /// connection on it close, and the closes are given a moment to leave.
    pub async fn close(&self) {
        self.accept.abort();
        if let Some(mapper) = lock(&self.mapper).take() {
            mapper.abort();
        }
        if let Some(g) = lock(&self.nearby).take() {
            g.task.abort();
        }
        // A UPnP mapping the router granted only *permanently* (lifetime 0) would outlive the
        // presence: it is deleted, best-effort, on its own task. Timed mappings of every kind
        // expire by themselves (N-43: the daemon's stop unmaps; a node's detach never does).
        for m in std::mem::take(&mut lock(&self.mapping).held) {
            if m.method == crate::nat::portmap::Method::UpnpIgd && m.lifetime_secs == 0 {
                tokio::spawn(async move {
                    let _ = crate::nat::portmap::unmap_port_upnp(
                        crate::nat::portmap::Protocol::Udp,
                        m.internal_port,
                    )
                    .await;
                });
            }
        }
        self.shared.close();
        let _ = tokio::time::timeout(CLOSE_FLUSH, self.shared.wait_idle()).await;
    }
}

impl Drop for NetPresence {
    fn drop(&mut self) {
        self.accept.abort();
        if let Some(mapper) = lock(&self.mapper).take() {
            mapper.abort();
        }
        if let Some(g) = lock(&self.nearby).take() {
            g.task.abort();
        }
    }
}

/// **The presence's publish side** (ADR-012, N-43): compose what its nodes advertise — routable
/// addresses, a gateway-mapped one when one can be had, loopback — once for the presence, then
/// renew each granted mapping on RFC 6887's schedule (N-55) and retry a family that got nothing back, until
/// the presence goes. A node asking for a discovery ([`NetPresence::rediscover`]) wakes it early.
fn spawn_mapper(presence: std::sync::Weak<NetPresence>) -> tokio::task::AbortHandle {
    tokio::spawn(async move {
        let mut leased: Vec<PortMapping> = Vec::new();
        loop {
            let (bound, wake) = {
                let Some(p) = presence.upgrade() else { return };
                let Ok(bound) = p.shared.local_addr() else {
                    return;
                };
                (bound, Arc::clone(&p.rediscover))
            };
            let started = unix_now();
            let (list, granted, asks) =
                crate::nat::reachability::advertise_endpoints(bound, &leased).await;
            let due = {
                let Some(p) = presence.upgrade() else { return };
                let now = unix_now();
                let due = {
                    let mut m = lock(&p.mapping);
                    let due = m.take(&granted, started, now);
                    leased = m.leased(now);
                    due
                };
                *lock(&p.asks) = asks;
                p.discoveries
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                p.advertised.send_replace(Some(list));
                due
            };
            match due {
                Some(at) => {
                    let wait = Duration::from_secs(at.saturating_sub(unix_now()).max(1));
                    tokio::select! {
                        () = tokio::time::sleep(wait) => {}
                        () = wake.notified() => {}
                    }
                }
                None => wake.notified().await,
            }
        }
    })
    .abort_handle()
}

/// **The accept loop and its gate**, moved here from the node (it was `actor::spawn_accept_loop`):
/// one per presence, so the cap is the daemon's, not each node's.
///
/// - An attempt that finds a slot runs at once, on a task of its own.
/// - Past [`HANDSHAKES_IN_FLIGHT`], an attempt whose source address is **not yet validated** gets
///   a QUIC Retry, which a spoofed flood cannot answer and a real peer pays one round trip for.
/// - One that **is** validated waits for a slot on a task of its own, up to [`HANDSHAKE_WAIT`],
///   with at most [`HANDSHAKES_WAITING`] waiting; past either it is refused (V210-86, #278).
///
/// Each finished connection goes to the node its exchange named
/// ([`SharedEndpoint::route`]). **Residual, stated rather than implied:** 64 validated attempts
/// that stall still hold every slot for up to their handshake bound (30 s) plus the exchange's
/// (5 s).
fn spawn_accept_loop(
    shared: Arc<SharedEndpoint>,
    bursts: broadcast::Sender<HandshakeBurst>,
) -> tokio::task::AbortHandle {
    tokio::spawn(async move {
        let gate = Arc::new(Semaphore::new(HANDSHAKES_IN_FLIGHT));
        let queue = Arc::new(Semaphore::new(HANDSHAKES_WAITING));
        let burst = Arc::new(Mutex::new(Burst::default()));
        while let Some(incoming) = shared.accept_incoming().await {
            if let Ok(permit) = Arc::clone(&gate).try_acquire_owned() {
                lock_burst(&burst).ran(&gate);
                spawn_handshake(Arc::clone(&shared), permit, incoming);
                continue;
            }
            if !incoming.remote_address_validated() {
                // `Err` means this attempt is already a retried one; retrying it again would
                // loop, so it is simply dropped.
                let _ = incoming.retry();
                continue;
            }
            let Ok(place) = Arc::clone(&queue).try_acquire_owned() else {
                let over = {
                    let mut b = lock_burst(&burst);
                    b.counted.refused += 1;
                    b.over()
                };
                incoming.refuse();
                if let Some(over) = over {
                    let _ = bursts.send(over);
                }
                continue;
            };
            lock_burst(&burst).enter(&gate);
            let (shared, gate, burst, bursts) = (
                Arc::clone(&shared),
                Arc::clone(&gate),
                Arc::clone(&burst),
                bursts.clone(),
            );
            tokio::spawn(async move {
                let since = std::time::Instant::now();
                let slot = tokio::time::timeout(HANDSHAKE_WAIT, Arc::clone(&gate).acquire_owned())
                    .await
                    .ok()
                    .and_then(std::result::Result::ok);
                drop(place);
                let over = {
                    let mut b = lock_burst(&burst);
                    if slot.is_some() {
                        b.ran(&gate);
                    } else {
                        b.counted.refused += 1;
                    }
                    b.leave(since.elapsed())
                };
                match slot {
                    Some(permit) => spawn_handshake(shared, permit, incoming),
                    None => incoming.refuse(),
                }
                if let Some(over) = over {
                    let _ = bursts.send(over);
                }
            });
        }
    })
    .abort_handle()
}

/// One inbound handshake and identity exchange on its own task, holding `permit` throughout,
/// then the connection handed to its node.
fn spawn_handshake(
    shared: Arc<SharedEndpoint>,
    permit: tokio::sync::OwnedSemaphorePermit,
    incoming: quinn::Incoming,
) {
    tokio::spawn(async move {
        let _permit = permit;
        if let Ok(conn) = shared.finish_incoming(incoming, unix_now()).await {
            shared.route(conn);
        }
    });
}

#[cfg(test)]
#[path = "presence_tests.rs"]
mod tests;
