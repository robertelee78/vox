//! UDP tunnels (ADR-022 decision 6, PRD-001 R25–R26): a UDP service carried as a
//! datagram flow bound to a `Tunnel` stream.
//!
//! The stream does everything a TCP tunnel's stream does up to the host's verdict — the
//! request names the room and the service, the host runs the same gate, a refusal is the
//! same uniform `Denied` — and then carries no bytes at all. It **is** the flow's
//! lifetime: the datagrams ride the flow bound to it
//! ([`VoxConnection::bind_flow`](crate::transport::quic::VoxConnection::bind_flow)),
//! and whichever side ends the stream ends the flow on both.
//!
//! ## Why the service label, not a flag on the request
//! A UDP service is served as `udp/<port>` and a bare `<port>` stays TCP, so TCP 53 and
//! UDP 53 are two services that never collide, and the host's existing gate — which keys
//! on the label and nothing else — needs no change to tell them apart. A wire flag would
//! have been a second field for every existing request to be wrong about.
//!
//! ## Limits, and why they look like a NAT's
//! A UDP "connection" has no end the network can see, so a flow ends when it goes quiet
//! for [`UDP_IDLE`] (RFC 9298's floor). A node holds at most [`FLOWS_PER_PEER`] flows per
//! peer — a new one evicts that peer's longest-idle flow, as a NAT table does — and at most
//! [`FLOWS_TOTAL`] in all; past that a new flow is refused rather than displacing another
//! peer's, so no one peer can empty the table for the rest.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Notify;

use crate::hash::Digest32;
use crate::transport::router::DatagramFlow;

/// A flow with no traffic in either direction for this long is closed (ADR-022).
pub const UDP_IDLE: Duration = Duration::from_secs(120);

/// Flows one node holds with one peer, in both roles together.
pub const FLOWS_PER_PEER: usize = 32;

/// Flows one node holds in all.
pub const FLOWS_TOTAL: usize = 256;

/// The largest UDP payload, and so the receive buffer every pump reads into.
pub const MAX_UDP: usize = 65_535;

const UDP_PREFIX: &str = "udp/";

/// The service label a person's `<port>[/udp|/tcp]` names: `53/udp` → `udp/53`, and `53`
/// or `53/tcp` → `53`. A label already in wire form (`udp/53`) is accepted as it is.
/// `None` for anything that is not a port.
#[must_use]
pub fn service_label(spec: &str) -> Option<String> {
    let spec = spec.trim();
    let (port, udp) = if let Some(p) = spec.strip_suffix("/udp") {
        (p, true)
    } else if let Some(p) = spec.strip_suffix("/tcp") {
        (p, false)
    } else if let Some(p) = spec.strip_prefix(UDP_PREFIX) {
        (p, true)
    } else {
        (spec, false)
    };
    let port: u16 = port.parse().ok()?;
    Some(if udp {
        format!("{UDP_PREFIX}{port}")
    } else {
        port.to_string()
    })
}

/// Whether `label` names a UDP service.
#[must_use]
pub fn is_udp(label: &str) -> bool {
    label.starts_with(UDP_PREFIX)
}

/// One flow's counters, shared between its pump and [`UdpFlows::snapshot`].
#[derive(Debug, Default)]
pub struct FlowCounters {
    /// Packets from the local UDP side put on the flow.
    pub to_peer: AtomicU64,
    /// Packets from the flow delivered to the local UDP side.
    pub from_peer: AtomicU64,
    /// Packets dropped because the local socket or the queue in front of the flow
    /// could not take them. Sending never waits: a full buffer loses a packet.
    pub dropped: AtomicU64,
}

/// A read of one live flow, for a status display.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowInfo {
    /// The peer at the other end.
    pub peer: Digest32,
    /// The service label (`udp/<port>`).
    pub label: String,
    /// Packets sent toward the peer.
    pub to_peer: u64,
    /// Packets received from the peer.
    pub from_peer: u64,
    /// Packets dropped.
    pub dropped: u64,
    /// How long since the last packet in either direction.
    pub idle: Duration,
}

struct Slot {
    peer: Digest32,
    label: String,
    last: Arc<AtomicU64>,
    evict: Arc<Notify>,
    counters: Arc<FlowCounters>,
}

#[derive(Default)]
struct Table {
    next: u64,
    slots: HashMap<u64, Slot>,
}

/// Every UDP flow this node holds, as host or as dialer: what enforces
/// [`FLOWS_PER_PEER`] and [`FLOWS_TOTAL`].
pub struct UdpFlows {
    base: Instant,
    table: Mutex<Table>,
}

impl std::fmt::Debug for UdpFlows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpFlows")
            .field("flows", &self.table().slots.len())
            .finish()
    }
}

impl Default for UdpFlows {
    fn default() -> Self {
        Self {
            base: Instant::now(),
            table: Mutex::new(Table::default()),
        }
    }
}

impl UdpFlows {
    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        // No critical section awaits or panics mid-update, so a poisoned lock still
        // holds a consistent table.
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Admit a new flow with `peer`, or `None` when the node already holds
    /// [`FLOWS_TOTAL`].
    ///
    /// At [`FLOWS_PER_PEER`] for this peer the peer's longest-idle flow is evicted to make
    /// room: its pump is told to stop and its slot is freed at once, so the count is right
    /// before the new flow is counted.
    pub fn admit(self: &Arc<Self>, peer: Digest32, label: &str) -> Option<FlowGuard> {
        let now = self.now_ms();
        let mut t = self.table();
        let mine: Vec<(u64, u64)> = t
            .slots
            .iter()
            .filter(|(_, s)| s.peer == peer)
            .map(|(k, s)| (*k, s.last.load(Ordering::Relaxed)))
            .collect();
        if mine.len() >= FLOWS_PER_PEER {
            if let Some((victim, _)) = mine.iter().min_by_key(|(_, last)| *last) {
                if let Some(slot) = t.slots.remove(victim) {
                    slot.evict.notify_one();
                }
            }
        }
        if t.slots.len() >= FLOWS_TOTAL {
            return None;
        }
        let key = t.next;
        t.next += 1;
        let last = Arc::new(AtomicU64::new(now));
        let evict = Arc::new(Notify::new());
        let counters = Arc::new(FlowCounters::default());
        t.slots.insert(
            key,
            Slot {
                peer,
                label: label.to_owned(),
                last: Arc::clone(&last),
                evict: Arc::clone(&evict),
                counters: Arc::clone(&counters),
            },
        );
        Some(FlowGuard {
            table: Arc::clone(self),
            key,
            last,
            evict,
            counters,
        })
    }

    /// How many flows are live.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table().slots.len()
    }

    /// Whether no flow is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every live flow and its counters.
    #[must_use]
    pub fn snapshot(&self) -> Vec<FlowInfo> {
        let now = self.now_ms();
        self.table()
            .slots
            .values()
            .map(|s| FlowInfo {
                peer: s.peer,
                label: s.label.clone(),
                to_peer: s.counters.to_peer.load(Ordering::Relaxed),
                from_peer: s.counters.from_peer.load(Ordering::Relaxed),
                dropped: s.counters.dropped.load(Ordering::Relaxed),
                idle: Duration::from_millis(now.saturating_sub(s.last.load(Ordering::Relaxed))),
            })
            .collect()
    }
}

/// One admitted flow's place in [`UdpFlows`]. Dropping it frees the place.
pub struct FlowGuard {
    table: Arc<UdpFlows>,
    key: u64,
    last: Arc<AtomicU64>,
    evict: Arc<Notify>,
    /// The flow's counters.
    pub counters: Arc<FlowCounters>,
}

impl FlowGuard {
    /// Record traffic: the flow is not idle.
    pub fn touch(&self) {
        self.last.store(self.table.now_ms(), Ordering::Relaxed);
    }

    /// When the flow becomes idle if nothing more happens.
    #[must_use]
    pub fn idle_deadline(&self) -> tokio::time::Instant {
        let last = Duration::from_millis(self.last.load(Ordering::Relaxed));
        tokio::time::Instant::from_std(self.table.base + last + UDP_IDLE)
    }

    /// Resolves when this flow has been evicted to make room for a newer one.
    pub async fn evicted(&self) {
        self.evict.notified().await;
    }
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.table.table().slots.remove(&self.key);
    }
}

/// Why a pump stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// The far side ended the flow's stream.
    Flow,
    /// Nothing moved for [`UDP_IDLE`].
    Idle,
    /// Evicted to make room ([`FLOWS_PER_PEER`]).
    Evicted,
    /// Reach was withdrawn, or the service removed.
    Withdrawn,
    /// The local side went away.
    Local,
}

/// The host side of one UDP flow: packets from the flow go to the service through `sock`,
/// a socket connected to it, and its replies go back on the flow, until the flow ends,
/// goes idle, is evicted, or `cut` resolves.
///
/// Dropping `flow` on return ends the stream, which ends the flow at the dialer.
pub async fn host_pump(
    mut flow: DatagramFlow,
    sock: UdpSocket,
    guard: FlowGuard,
    cut: impl core::future::Future<Output = ()>,
) -> Ended {
    tokio::pin!(cut);
    let mut buf = vec![0u8; MAX_UDP];
    let c = Arc::clone(&guard.counters);
    loop {
        let idle = tokio::time::sleep_until(guard.idle_deadline());
        tokio::select! {
            packet = flow.recv() => {
                let Some(packet) = packet else { return Ended::Flow };
                guard.touch();
                // `try_send`, never `send().await`: a service whose socket buffer is full
                // loses this packet, as it would have on the wire, and the pump moves on.
                match sock.try_send(&packet) {
                    Ok(_) => { c.from_peer.fetch_add(1, Ordering::Relaxed); }
                    Err(_) => { c.dropped.fetch_add(1, Ordering::Relaxed); }
                }
            }
            got = sock.recv(&mut buf) => {
                // A connected UDP socket reports an ICMP "port unreachable" as an error on
                // the next read. The service may simply not be up yet; the flow stays.
                if let Ok(n) = got {
                    guard.touch();
                    if flow.send(&buf[..n]).is_err() {
                        return Ended::Flow;
                    }
                    c.to_peer.fetch_add(1, Ordering::Relaxed);
                }
            }
            () = idle => {
                if tokio::time::Instant::now() >= guard.idle_deadline() {
                    return Ended::Idle;
                }
            }
            () = guard.evicted() => return Ended::Evicted,
            () = &mut cut => return Ended::Withdrawn,
        }
    }
}

/// Bind an ephemeral UDP socket connected to `target`: the host's end of one flow.
///
/// # Errors
/// If the socket cannot be bound or connected.
pub async fn connect_service(target: SocketAddr) -> std::io::Result<UdpSocket> {
    let local = if target.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let sock = UdpSocket::bind(local).await?;
    sock.connect(target).await?;
    Ok(sock)
}

/// The dialer side of one UDP flow: packets a local client sent (queued in
/// `from_client`) go out on the flow, and packets from the flow go back through
/// `to_client`, until the flow ends, goes idle, is evicted, or the local side goes away.
///
/// `to_client` must not wait — it is `try_send_to` on a shared socket — and returns
/// whether the packet was taken; one that was not is counted as dropped.
pub async fn client_pump<F: Fn(&[u8]) -> bool>(
    mut flow: DatagramFlow,
    mut from_client: tokio::sync::mpsc::Receiver<Vec<u8>>,
    to_client: F,
    guard: FlowGuard,
) -> Ended {
    let c = Arc::clone(&guard.counters);
    loop {
        let idle = tokio::time::sleep_until(guard.idle_deadline());
        tokio::select! {
            packet = from_client.recv() => {
                let Some(packet) = packet else { return Ended::Local };
                guard.touch();
                if flow.send(&packet).is_err() {
                    return Ended::Flow;
                }
                c.to_peer.fetch_add(1, Ordering::Relaxed);
            }
            packet = flow.recv() => {
                let Some(packet) = packet else { return Ended::Flow };
                guard.touch();
                if to_client(&packet) {
                    c.from_peer.fetch_add(1, Ordering::Relaxed);
                } else {
                    c.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            () = idle => {
                if tokio::time::Instant::now() >= guard.idle_deadline() {
                    return Ended::Idle;
                }
            }
            () = guard.evicted() => return Ended::Evicted,
        }
    }
}

/// How many packets a client's flow queues while its tunnel is being opened, or while
/// the flow is busy. Past this they are dropped: UDP does not wait.
pub const CLIENT_QUEUE: usize = 64;
