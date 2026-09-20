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
//! A circuit's address is derived from the far peer's fingerprint into `240.0.0.0/4`
//! (reserved, never routed — RFC 1112 §4), so it can never collide with a real
//! destination and a datagram for a circuit that no longer exists is dropped here
//! rather than handed to the kernel. IPv4 is used whatever the socket's family:
//! quinn refuses an IPv6 destination on an IPv4 socket, and maps an IPv4 one on an
//! IPv6 socket, so an IPv4 synthetic address works on both.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;

use crate::hash::{domain_hash, Digest32};

/// The domain label under which a circuit address is derived from a fingerprint.
pub const CIRCUIT_ADDR_LABEL: &str = "vox/circuit-addr/v1";

/// How many outbound datagrams a circuit will queue before dropping. A relay stream
/// that cannot keep up is a slow path, and QUIC on a slow path drops packets — it
/// does not buffer without bound.
pub const CIRCUIT_QUEUE: usize = 256;

/// How many inbound datagrams, across all circuits, are held for the endpoint before
/// the oldest is dropped.
const INBOX_LIMIT: usize = 1024;

/// The synthetic address that stands for a circuit to `peer` on this endpoint.
#[must_use]
pub fn circuit_addr(peer: &Digest32) -> SocketAddr {
    let h = domain_hash(CIRCUIT_ADDR_LABEL, peer);
    // 240.0.0.0/4: the first octet's high nibble is fixed, 28 bits of address and 16
    // of port come from the hash. 255.255.255.255 is broadcast and port 0 is not a
    // port, so both are steered away from.
    let mut d = h[3];
    if h[0] & 0x0F == 0x0F && h[1] == 0xFF && h[2] == 0xFF && d == 0xFF {
        d = 0xFE;
    }
    let ip = Ipv4Addr::new(0xF0 | (h[0] & 0x0F), h[1], h[2], d);
    let port = u16::from_be_bytes([h[4], h[5]]).max(1);
    SocketAddr::V4(SocketAddrV4::new(ip, port))
}

/// Whether `addr` is in the synthetic range, whatever family quinn presented it in —
/// which is how a connection's path is told apart: a peer whose remote address is a
/// circuit's is being relayed.
#[must_use]
pub fn is_circuit_addr(addr: SocketAddr) -> bool {
    match addr.ip().to_canonical() {
        IpAddr::V4(v4) => v4.octets()[0] & 0xF0 == 0xF0,
        IpAddr::V6(_) => false,
    }
}

/// The circuit table's canonical key: IPv4, whatever quinn presented.
fn key(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// The socket every endpoint runs on: the real one plus the circuits.
pub struct MuxSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    circuits: Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>,
    inbox: Mutex<Inbox>,
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
        Arc::new(Self {
            inner,
            circuits: Mutex::new(HashMap::new()),
            inbox: Mutex::new(Inbox::default()),
        })
    }

    /// Attach a circuit to `peer`, replacing any earlier one to the same peer: the
    /// old driver's outbound queue closes, which ends its stream, which is how a
    /// stale circuit is torn down when a fresh one is wanted.
    #[must_use]
    pub fn attach(self: &Arc<Self>, peer: &Digest32) -> CircuitPort {
        let addr = circuit_addr(peer);
        let (tx, rx) = mpsc::channel(CIRCUIT_QUEUE);
        self.circuits().insert(addr, tx);
        CircuitPort {
            addr,
            mux: Arc::clone(self),
            outbound: Some(rx),
        }
    }

    /// The number of live circuits.
    #[must_use]
    pub fn circuit_count(&self) -> usize {
        self.circuits().len()
    }

    fn detach(&self, addr: SocketAddr) {
        self.circuits().remove(&addr);
    }

    fn circuits(&self) -> std::sync::MutexGuard<'_, HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>> {
        self.circuits.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn deliver(&self, from: SocketAddr, datagram: Vec<u8>) {
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
        if !is_circuit_addr(transmit.destination) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;
    use crate::transport::quic::VoxEndpoint;

    fn signer(seed: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[seed; 32], &[seed ^ 0xFF; 32]).unwrap()
    }

    /// Carry every datagram one circuit emits into the other: the whole of a relay,
    /// minus the relay.
    fn pipe(mut from: CircuitPort, to: CircuitInlet) -> CircuitPort {
        let mut rx = from.take_outbound().unwrap();
        tokio::spawn(async move {
            while let Some(d) = rx.recv().await {
                to.deliver(d);
            }
        });
        from
    }

    /// The rung-4 premise: two endpoints whose real sockets never carry a byte to
    /// each other still complete the full authenticated handshake when their
    /// circuits are joined. What a relay forwards is therefore QUIC it cannot read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pinned_handshake_completes_over_circuits_alone() {
        let (sa, sb) = (signer(1), signer(2));
        let a = Arc::new(VoxEndpoint::bind(&sa, "127.0.0.1:0".parse().unwrap()).unwrap());
        let b = Arc::new(VoxEndpoint::bind(&sb, "127.0.0.1:0".parse().unwrap()).unwrap());
        let (a_id, b_id) = (a.local_id(), b.local_id());
        let a_port = a.attach_circuit(&b_id);
        let b_port = b.attach_circuit(&a_id);
        assert_eq!(a.circuit_count(), 1);
        let (a_inlet, b_inlet) = (a_port.inlet(), b_port.inlet());
        let _a_port = pipe(a_port, b_inlet);
        let _b_port = pipe(b_port, a_inlet);

        let accept = {
            let b = Arc::clone(&b);
            tokio::spawn(async move { b.accept(1_800_000_000).await })
        };
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            a.connect(circuit_addr(&b_id), b_id, 1_800_000_000),
        )
        .await
        .expect("did not hang")
        .expect("the handshake completed over the circuit");
        assert_eq!(conn.peer_id(), b_id, "pinned to B, authenticated as B");
        // B saw A arrive from A's circuit address, not from any real socket.
        let accepted = accept.await.unwrap().unwrap().unwrap();
        assert_eq!(accepted.peer_id(), a_id);
        assert_eq!(accepted.quinn().remote_address(), circuit_addr(&a_id));

        // A stream works over it, both ways.
        let (mut s, mut r) = conn.open_stream().await.unwrap();
        s.write_all(b"over the circuit").await.unwrap();
        s.finish().unwrap();
        let (mut bs, mut br) = accepted.accept_stream().await.unwrap();
        let got = br.read_to_end(64).await.unwrap();
        assert_eq!(got, b"over the circuit");
        bs.write_all(b"and back").await.unwrap();
        bs.finish().unwrap();
        assert_eq!(r.read_to_end(64).await.unwrap(), b"and back");

        // Dropping a port detaches its circuit.
        drop(_a_port);
        assert_eq!(a.circuit_count(), 0);
    }

    #[test]
    fn circuit_addresses_are_reserved_and_never_broadcast_or_port_zero() {
        for seed in 0..=255u8 {
            let addr = circuit_addr(&[seed; 32]);
            assert!(is_circuit_addr(addr), "{addr}");
            assert_ne!(addr.port(), 0);
            match addr {
                SocketAddr::V4(v4) => {
                    assert!(v4.ip().octets()[0] >= 240);
                    assert_ne!(*v4.ip(), Ipv4Addr::BROADCAST);
                }
                SocketAddr::V6(_) => panic!("circuit addresses are IPv4"),
            }
        }
        // Deterministic per peer, distinct across peers.
        assert_eq!(circuit_addr(&[1; 32]), circuit_addr(&[1; 32]));
        assert_ne!(circuit_addr(&[1; 32]), circuit_addr(&[2; 32]));
        // Real addresses are never mistaken for circuits, in either presentation.
        assert!(!is_circuit_addr("203.0.113.5:4433".parse().unwrap()));
        assert!(!is_circuit_addr("[2001:db8::1]:4433".parse().unwrap()));
        assert!(!is_circuit_addr(
            "[::ffff:203.0.113.5]:4433".parse().unwrap()
        ));
        // A v4-mapped circuit address (how quinn presents it on an IPv6 socket) is.
        let SocketAddr::V4(v4) = circuit_addr(&[9; 32]) else {
            unreachable!()
        };
        let mapped = SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port());
        assert!(is_circuit_addr(mapped));
        assert_eq!(key(mapped), circuit_addr(&[9; 32]));
    }
}
