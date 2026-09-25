//! The datagram multiplexer under every [`VoxEndpoint`](crate::transport::quic::VoxEndpoint)
//! (ADR-012 rung 4, the relay of last resort).
//!
//! A relayed connection needs the endpoint's QUIC to run over a path that is not the
//! wire: packets carried through a relay peer. quinn binds one endpoint to one
//! socket, so the socket is where the paths must meet. [`MuxSocket`] wraps the real
//! socket (or the abstract one a simulation supplies) and adds **circuits**: synthetic
//! destination addresses whose datagrams go to, and arrive from, a relay stream
//! instead of the network.
//!
//! Above it nothing changes. A relayed peer is an address to dial, the handshake and
//! identity pinning are exactly those of a direct connection, one connection per
//! peer still holds — and the relay forwards QUIC packets it cannot read, which is
//! what makes it **ciphertext-only by construction** rather than by promise.
//!
//! ## Synthetic addresses
//! quinn addresses every path by `SocketAddr`, so each circuit needs one. A circuit's
//! address is **allocated at random** inside a Vox-specific IPv6 Unique Local Address
//! subnet, and the mapping from peer to address is held in this socket's table. Three
//! properties follow, and each is load-bearing:
//!
//! - **Unlinkable.** The address carries no function of the peer's identity, so it tells
//!   an observer who obtains one nothing about which peer it stands for. A fingerprint is
//!   published deliberately — it is what `vox trust add` takes — so an address *derived*
//!   from one would let anybody holding a fingerprint test whether a node has a circuit to
//!   that peer, and read a node's relay topology out of any address that escaped.
//! - **Known, not guessed.** Whether an address is a circuit is answered by
//!   [`MuxSocket::is_circuit`] from the table, never by testing its range. This is what
//!   makes the range's choice non-critical: `240.0.0.0/4` is reserved but *is* used
//!   privately in the field, including by VPN software, so a host can legitimately have an
//!   interface there — and a real address in the range is simply not in the table, so it is
//!   not a circuit. Guessing from the range answers wrongly in both directions.
//! - **Contained, in the socket's own family.** The range is IPv4 whatever the socket is:
//!   quinn refuses an IPv6 destination on an IPv4 socket and maps an IPv4 one on an IPv6
//!   socket, so an IPv4 address is the only one that works on both. An IPv6 Unique Local
//!   Address with a random RFC 4193 Global ID would be the better container — collision
//!   with a real network becomes negligible rather than merely unlikely — and is what to
//!   move to if endpoints ever bind dual-stack.
//!
//! A datagram for a circuit that no longer exists is dropped here rather than handed to
//! the kernel, and the port is a fixed placeholder because a circuit is identified by its
//! address alone.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;

use crate::error::Result;
use crate::hash::Digest32;

/// How many outbound datagrams a circuit will queue before dropping. A relay stream
/// that cannot keep up is a slow path, and QUIC on a slow path drops packets — it
/// does not buffer without bound.
pub const CIRCUIT_QUEUE: usize = 256;

/// How many inbound datagrams, across all circuits, are held for the endpoint before
/// the oldest is dropped.
const INBOX_LIMIT: usize = 1024;

/// The range circuit addresses are allocated inside: `240.0.0.0/4`, reserved by RFC 1112
/// §4 and never routed on the public internet.
///
/// Containment only. It is **not** how a circuit is identified — see
/// [`MuxSocket::is_circuit`] — which matters because this range is used privately in the
/// field, so a host can have a real interface in it.
const CIRCUIT_RANGE_HIGH_NIBBLE: u8 = 0xF0;

/// The placeholder port every circuit address carries. A circuit is identified by its
/// address, so the port conveys nothing; a fixed value keeps the `SocketAddr` stable for
/// quinn, which keys paths on the pair.
pub const CIRCUIT_PORT: u16 = 1;

/// Whether `addr` falls inside the range circuits are allocated from.
///
/// Containment, not identification: an address can be in the range and belong to a real
/// interface. Use [`MuxSocket::is_circuit`] to ask whether an address *is* a live circuit.
#[must_use]
pub fn in_circuit_range(addr: SocketAddr) -> bool {
    match addr.ip().to_canonical() {
        IpAddr::V4(v4) => v4.octets()[0] & 0xF0 == CIRCUIT_RANGE_HIGH_NIBBLE,
        IpAddr::V6(_) => false,
    }
}

/// A fresh circuit address: 28 random bits inside the range.
///
/// Random, not derived from the peer. A fingerprint is published deliberately — it is what
/// `vox trust add` takes — so an address derived from one would let anybody holding a
/// fingerprint compute it and test whether it appears among a node's endpoints, reading
/// that node's relay topology out of public data.
///
/// 28 bits is a small space, which is why [`MuxSocket::attach`] checks the table for a
/// collision rather than trusting uniqueness.
fn random_circuit_addr() -> Result<SocketAddr> {
    let r: [u8; 4] = crate::identity::rng::random_array()?;
    let ip = Ipv4Addr::new(CIRCUIT_RANGE_HIGH_NIBBLE | (r[0] & 0x0F), r[1], r[2], r[3]);
    Ok(SocketAddr::new(IpAddr::V4(ip), CIRCUIT_PORT))
}

/// The circuit table's canonical key: IPv4, whatever quinn presented.
fn key(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// The socket every endpoint runs on: the real one plus the circuits.
pub struct MuxSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    circuits: Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>,
    /// Which address each peer's live circuit stands at. The addresses are random, so
    /// this is the only way to get from a peer to its circuit.
    by_peer: Mutex<HashMap<Digest32, SocketAddr>>,
    inbox: Mutex<Inbox>,
    /// Whether the socket underneath is IPv6, and so what family a circuit's datagrams must be
    /// handed up in (see [`Self::as_seen`]).
    ipv6: bool,
}

#[derive(Default)]
struct Inbox {
    queue: VecDeque<(SocketAddr, Vec<u8>)>,
    waker: Option<Waker>,
}

impl std::fmt::Debug for MuxSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxSocket")
            .field("inner", &self.inner)
            .field("circuits", &self.circuits().len())
            .finish()
    }
}

/// One attached circuit, as its driver holds it: where outbound datagrams come out,
/// and where inbound ones go in. Dropping it detaches the circuit.
pub struct CircuitPort {
    addr: SocketAddr,
    mux: Arc<MuxSocket>,
    /// Datagrams the endpoint sent to this circuit's address, to be carried to the
    /// far side. Taken once by the writing task.
    outbound: Option<mpsc::Receiver<Vec<u8>>>,
}

impl std::fmt::Debug for CircuitPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CircuitPort({})", self.addr)
    }
}

impl CircuitPort {
    /// The synthetic address this circuit stands at.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Take the outbound queue for the task that carries datagrams to the far side.
    /// `None` after the first call.
    pub fn take_outbound(&mut self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.outbound.take()
    }

    /// The half that feeds datagrams *in*: cloneable, for the reading task.
    #[must_use]
    pub fn inlet(&self) -> CircuitInlet {
        CircuitInlet {
            addr: self.addr,
            mux: Arc::clone(&self.mux),
        }
    }
}

impl Drop for CircuitPort {
    fn drop(&mut self) {
        self.mux.detach(self.addr);
    }
}

/// Where a circuit's driver puts the datagrams it received from the far side.
#[derive(Clone)]
pub struct CircuitInlet {
    addr: SocketAddr,
    mux: Arc<MuxSocket>,
}

impl CircuitInlet {
    /// Hand the endpoint one datagram that arrived over the circuit.
    pub fn deliver(&self, datagram: Vec<u8>) {
        self.mux.deliver(self.addr, datagram);
    }
}

impl MuxSocket {
    /// Wrap a socket. Everything not addressed to a circuit passes straight through.
    #[must_use]
    pub fn new(inner: Arc<dyn AsyncUdpSocket>) -> Arc<Self> {
        let ipv6 = inner.local_addr().is_ok_and(|a| a.is_ipv6());
        Arc::new(Self {
            ipv6,
            inner,
            circuits: Mutex::new(HashMap::new()),
            by_peer: Mutex::new(HashMap::new()),
            inbox: Mutex::new(Inbox::default()),
        })
    }

    /// Attach a circuit to `peer` at a freshly allocated address, replacing any earlier
    /// one to the same peer: the old driver's outbound queue closes, which ends its
    /// stream, which is how a stale circuit is torn down when a fresh one is wanted.
    ///
    /// # Errors
    /// If the OS CSPRNG is unavailable. Vox never falls back to a weaker source, and a
    /// guessable circuit address would leak which peers this node relays to.
    pub fn attach(self: &Arc<Self>, peer: &Digest32) -> Result<CircuitPort> {
        let (tx, rx) = mpsc::channel(CIRCUIT_QUEUE);
        let mut circuits = self.circuits();
        // Retried rather than assumed unique: 28 bits is a small space and a collision
        // would silently cross two circuits' datagrams.
        let addr = loop {
            let candidate = random_circuit_addr()?;
            if !circuits.contains_key(&candidate) {
                break candidate;
            }
        };
        circuits.insert(addr, tx);
        if let Some(stale) = self.by_peer().insert(*peer, addr) {
            circuits.remove(&stale);
        }
        drop(circuits);
        Ok(CircuitPort {
            addr,
            mux: Arc::clone(self),
            outbound: Some(rx),
        })
    }

    /// Whether `addr` is a **live circuit** on this socket.
    ///
    /// The answer comes from the table. A circuit address is random, so nothing about its
    /// shape identifies it, and an address that merely falls inside the subnet
    /// ([`in_circuit_range`]) is not a circuit unless it is attached.
    #[must_use]
    pub fn is_circuit(&self, addr: SocketAddr) -> bool {
        self.circuits().contains_key(&key(addr))
    }

    /// The address `peer`'s live circuit stands at, if it has one.
    #[must_use]
    pub fn circuit_addr_of(&self, peer: &Digest32) -> Option<SocketAddr> {
        self.by_peer().get(peer).copied()
    }

    fn by_peer(&self) -> std::sync::MutexGuard<'_, HashMap<Digest32, SocketAddr>> {
        self.by_peer.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The number of live circuits.
    #[must_use]
    pub fn circuit_count(&self) -> usize {
        self.circuits().len()
    }

    fn detach(&self, addr: SocketAddr) {
        self.circuits().remove(&addr);
        self.by_peer().retain(|_, a| *a != addr);
    }

    fn circuits(&self) -> std::sync::MutexGuard<'_, HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>> {
        self.circuits.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A circuit's address as quinn on this socket knows it.
    ///
    /// **In the socket's own family.** A circuit address is IPv4, and on an IPv6 socket quinn dials
    /// it as the IPv4-mapped `::ffff:a.b.c.d` and records *that* as the connection's remote. A
    /// datagram handed up from the plain IPv4 address is then from an address the connection has
    /// never seen, and a QUIC client discards it — so every handshake over a circuit from a node on
    /// an IPv6 socket (`[::1]`, or the dual-stack `[::]`) timed out, and the relay rung was dead
    /// for it.
    fn as_seen(&self, addr: SocketAddr) -> SocketAddr {
        match addr {
            SocketAddr::V4(v4) if self.ipv6 => {
                SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
            }
            other => other,
        }
    }

    fn deliver(&self, from: SocketAddr, datagram: Vec<u8>) {
        let from = self.as_seen(from);
        let waker = {
            let mut inbox = self.inbox.lock().unwrap_or_else(PoisonError::into_inner);
            if inbox.queue.len() >= INBOX_LIMIT {
                inbox.queue.pop_front();
            }
            inbox.queue.push_back((from, datagram));
            inbox.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Send one datagram down a circuit, or drop it: a circuit that is gone or full
    /// behaves like a lossy path, which is what QUIC is built for.
    fn send_circuit(&self, dest: SocketAddr, datagram: &[u8]) {
        let sender = self.circuits().get(&key(dest)).cloned();
        if let Some(tx) = sender {
            let _ = tx.try_send(datagram.to_vec());
        }
    }
}

impl AsyncUdpSocket for MuxSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // Circuit sends never block, so the real socket's writability is the only
        // one worth waiting for.
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // The table decides, not the address's shape. A datagram for the subnet with no
        // live circuit behind it is not a circuit send; it goes to the socket and fails
        // there, which is the same answer any unreachable destination gets.
        if !self.is_circuit(transmit.destination) {
            return self.inner.try_send(transmit);
        }
        match transmit.segment_size {
            Some(size) if size < transmit.contents.len() => {
                for chunk in transmit.contents.chunks(size) {
                    self.send_circuit(transmit.destination, chunk);
                }
            }
            _ => self.send_circuit(transmit.destination, transmit.contents),
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Circuits first: they are cheap to drain and the real socket registers its
        // own wake-up when it has nothing.
        {
            let mut inbox = self.inbox.lock().unwrap_or_else(PoisonError::into_inner);
            let capacity = bufs.len().min(meta.len());
            let mut filled = 0;
            while filled < capacity {
                let Some((from, datagram)) = inbox.queue.front() else {
                    break;
                };
                if datagram.len() > bufs[filled].len() {
                    // Larger than the buffer offered: dropped, as a kernel would
                    // truncate it. Never handed up corrupted.
                    inbox.queue.pop_front();
                    continue;
                }
                let (from, datagram) = (*from, datagram.clone());
                inbox.queue.pop_front();
                bufs[filled][..datagram.len()].copy_from_slice(&datagram);
                meta[filled] = RecvMeta {
                    addr: from,
                    len: datagram.len(),
                    stride: datagram.len(),
                    ecn: None,
                    dst_ip: None,
                };
                filled += 1;
            }
            if filled > 0 {
                return Poll::Ready(Ok(filled));
            }
            inbox.waker = Some(cx.waker().clone());
        }
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
