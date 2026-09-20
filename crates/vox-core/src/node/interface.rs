//! The Vox interface: terminating TCP in userspace and handing it to the overlay
//! (ADR-017 decision 5, M17.3b).
//!
//! This is the half of `vox up` that moves bytes. A tool on this machine opens TCP to a
//! `.vox` name, which the resolver answered with the host's ADR-013 derived address; the
//! kernel routes those packets to the Vox interface; this module reads them, terminates
//! the TCP itself, and hands the caller a byte stream to splice into a tunnel.
//!
//! ## Nothing binds a port
//! The interface never calls `bind` or `listen` on an OS socket. A destination port
//! arrives as a **field in an IPv6/TCP header**, is read here, and becomes the service
//! tag of a tunnel request — so port 22 is the same to it as port 65532, it cannot
//! collide with anything this machine already runs, and no part of the data path needs
//! privilege. It behaves like a NAT over the Vox layer: the port in a `.vox` address is a
//! Vox-layer identifier that the *serving* machine translates to whatever local endpoint
//! it chose (ADR-017 decision 4).
//!
//! ## Ports are discovered from the SYN, not configured
//! A client may dial any port and this machine cannot know which in advance — the
//! services are the *host's* configuration, not something a guest holds. A userspace
//! stack has no wildcard listen, so [`SynSniffer`] sits between the device and the stack,
//! reads each inbound packet's headers, and on a SYN for a pair with no listening socket
//! **holds the packet back**, asks for a socket, and replays it once one exists. Holding
//! it rather than dropping it is the difference between connecting now and connecting
//! after the client's first SYN retransmit.
//!
//! ## Why the byte moving is not in the poll loop
//! `smoltcp`'s sockets are only touchable from the loop that polls the device, and that
//! loop is synchronous. Rather than hand-roll an `AsyncRead`/`AsyncWrite` over the
//! sockets, each terminated connection gets a [`tokio::io::duplex`] pair: the caller is
//! given one half, and a small pump task moves bytes between the other half and two
//! channels. The poll loop then only ever does `try_recv`/`try_send`, which is sync and
//! cannot block the stack, and backpressure is preserved in both directions — an unread
//! byte is a byte left in the socket, which closes the TCP window on the tool.
//!
//! ## Where it runs
//! [`Netstack`] is generic over `smoltcp`'s `Device`, so the same code drives a real
//! `tun`/`utun` device (ADR-014's privileged setup, M17.3c) and an in-process paired
//! device. The gate uses the latter: cross-wiring two stacks proves the whole datapath
//! with no kernel and no root, exactly as `tests/support/vnet.rs` does for UDP.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, RxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv6Packet, TcpPacket};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use crate::error::{Error, Result};

/// Per-socket buffer, each direction.
const SOCKET_BUFFER: usize = 64 * 1024;

/// The local bridge's buffer, each direction.
const BRIDGE_BUFFER: usize = 64 * 1024;

/// The largest chunk the pump moves in one read.
const CHUNK: usize = 16 * 1024;

/// How long the loop sleeps between polls. It bounds how quickly a retransmit timer or a
/// newly readable socket is noticed; the cost of a shorter interval is idle wakeups.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// The most connections one interface terminates at once. A tunnel is a door, not a
/// leash, but an unbounded set of them is a way for a local process to exhaust this one.
pub const MAX_CONNECTIONS: usize = 256;

/// The most distinct `(address, port)` pairs kept listening. Each costs two socket
/// buffers, so an unbounded set is a local memory attack by port scan.
pub const MAX_LISTENERS: usize = 64;

/// A connection the interface has terminated, ready to be carried.
///
/// The interface cannot carry it itself — that needs a room, a peer and a capability — so
/// it reports it and the caller dials.
pub struct Accepted {
    /// The overlay address the tool connected to, which names the room (look it up with
    /// [`crate::node::resolver::VoxResolver::route`]).
    pub to: Ipv6Addr,
    /// The port it connected to, which names the service (ADR-017: the port *is* the tag).
    pub port: u16,
    /// The local byte stream: what the tool sent is readable from it, and what the service
    /// replies is written to it. Hand it to [`crate::tunnel::session::dial`].
    pub stream: DuplexStream,
}

impl core::fmt::Debug for Accepted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Accepted")
            .field("to", &self.to)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// An `(address, port)` pair a SYN arrived for.
type Target = (Ipv6Addr, u16);

/// Whether `packet` is a bare SYN, and to where.
///
/// Malformed input simply answers `None` and is passed through for the stack to reject:
/// this is not a filter, and a second opinion on what a valid IPv6 packet is would be a
/// second place to be wrong.
fn syn_target(packet: &[u8]) -> Option<Target> {
    let ip = Ipv6Packet::new_checked(packet).ok()?;
    if ip.next_header() != IpProtocol::Tcp {
        return None;
    }
    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
    // A bare SYN opens a connection; SYN+ACK answers one this side opened.
    if !tcp.syn() || tcp.ack() {
        return None;
    }
    Some((ip.dst_addr(), tcp.dst_port()))
}

/// What the sniffer and the loop share: the targets a SYN asked about and the packets
/// held back waiting for their sockets. Public only because [`SniffRx`] names it; nothing
/// outside this module constructs or reads one.
#[derive(Default)]
pub struct Pending {
    /// Targets seen in a SYN that have no listening socket yet.
    wanted: BTreeSet<Target>,
    /// Packets held back until their socket exists, replayed in arrival order.
    held: VecDeque<Vec<u8>>,
}

/// A `Device` wrapper that holds back the first SYN to an address/port that has no
/// listening socket, so the loop can create one and the packet is replayed rather than
/// dropped (see the module docs).
///
/// Transparent otherwise: every packet it passes through is byte-identical and nothing is
/// rewritten.
pub struct SynSniffer<D> {
    inner: D,
    listening: Arc<Mutex<BTreeSet<Target>>>,
    pending: Arc<Mutex<Pending>>,
}

impl<D: Device> Device for SynSniffer<D> {
    type RxToken<'a>
        = SniffRx<D::RxToken<'a>>
    where
        Self: 'a;
    type TxToken<'a>
        = D::TxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // A held packet whose socket now exists is replayed before anything new, so
        // arrival order is preserved.
        let replay = {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            let listening = self.listening.lock().unwrap_or_else(|e| e.into_inner());
            let ready = pending
                .held
                .front()
                .and_then(|p| syn_target(p))
                .is_some_and(|t| listening.contains(&t));
            if ready {
                pending.held.pop_front()
            } else {
                None
            }
        };
        if let Some(packet) = replay {
            // A replay still needs a transmit token to answer with; if the device has
            // none this instant, put it back and try on the next poll.
            return match self.inner.transmit(timestamp) {
                Some(tx) => Some((SniffRx::Replay(packet), tx)),
                None => {
                    self.pending
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .held
                        .push_front(packet);
                    None
                }
            };
        }

        let (rx, tx) = self.inner.receive(timestamp)?;
        Some((
            SniffRx::Fresh {
                inner: rx,
                listening: Arc::clone(&self.listening),
                pending: Arc::clone(&self.pending),
            },
            tx,
        ))
    }

    fn transmit(&mut self, timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        self.inner.transmit(timestamp)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.inner.capabilities()
    }
}

/// A [`SynSniffer`] receive token: a fresh packet from the device, which may be held
/// back, or one being replayed.
pub enum SniffRx<R> {
    /// Straight from the device.
    Fresh {
        /// The wrapped token.
        inner: R,
        /// The targets that currently have a listening socket.
        listening: Arc<Mutex<BTreeSet<Target>>>,
        /// Where a held-back packet and its request go.
        pending: Arc<Mutex<Pending>>,
    },
    /// Held back earlier, now replayed.
    Replay(Vec<u8>),
}

impl<R: RxToken> RxToken for SniffRx<R> {
    fn consume<T, F: FnOnce(&[u8]) -> T>(self, f: F) -> T {
        match self {
            SniffRx::Replay(packet) => f(&packet),
            SniffRx::Fresh {
                inner,
                listening,
                pending,
            } => inner.consume(|packet| {
                if let Some(target) = syn_target(packet) {
                    let known = listening
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .contains(&target);
                    if !known {
                        let mut p = pending.lock().unwrap_or_else(|e| e.into_inner());
                        // Bounded: a port scan must not queue unboundedly.
                        if p.held.len() < MAX_LISTENERS {
                            p.wanted.insert(target);
                            p.held.push_back(packet.to_vec());
                        }
                        // An empty slice is how "nothing arrived" is said from inside
                        // `consume`; the stack ignores it.
                        return f(&[]);
                    }
                }
                f(packet)
            }),
        }
    }
}

/// One terminated connection, from the stack's side.
struct Conn {
    handle: SocketHandle,
    /// Bytes the tool sent, from the pump.
    from_local: mpsc::Receiver<Vec<u8>>,
    /// Bytes for the tool, to the pump.
    to_local: mpsc::Sender<Vec<u8>>,
    /// Read from `from_local` but not yet accepted by the socket.
    queued: VecDeque<u8>,
    /// The local side has closed and `queued` is drained: close the socket.
    local_done: bool,
}

/// The userspace TCP stack behind the Vox interface.
///
/// Drive it with [`Netstack::run`]. Every connection it terminates arrives on the channel
/// given to [`Netstack::new`].
pub struct Netstack<D: Device> {
    device: SynSniffer<D>,
    iface: Interface,
    sockets: SocketSet<'static>,
    listening: Arc<Mutex<BTreeSet<Target>>>,
    pending: Arc<Mutex<Pending>>,
    /// Exactly one socket in LISTEN per target, replaced as connections are taken.
    listeners: BTreeMap<Target, SocketHandle>,
    conns: Vec<Conn>,
    accepted: mpsc::Sender<Accepted>,
}

impl<D: Device> Netstack<D> {
    /// Build a stack that answers for `addrs` — the overlay addresses of the rooms this
    /// machine has `.vox` names for — reporting terminated connections to `accepted`.
    ///
    /// Each address is a `/128`: a single host this machine answers for, never a subnet
    /// it routes.
    pub fn new(device: D, addrs: &[Ipv6Addr], accepted: mpsc::Sender<Accepted>) -> Result<Self> {
        if addrs.is_empty() {
            return Err(Error::MalformedLink("an interface with no addresses"));
        }
        let listening: Arc<Mutex<BTreeSet<Target>>> = Arc::default();
        let pending: Arc<Mutex<Pending>> = Arc::default();
        let mut device = SynSniffer {
            inner: device,
            listening: Arc::clone(&listening),
            pending: Arc::clone(&pending),
        };
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            SmolInstant::from_millis(0),
        );
        let mut added = 0usize;
        iface.update_ip_addrs(|list| {
            for a in addrs {
                if list.push(IpCidr::new(IpAddress::Ipv6(*a), 128)).is_ok() {
                    added += 1;
                }
            }
        });
        if added == 0 {
            return Err(Error::MalformedLink("no interface address could be set"));
        }
        Ok(Self {
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            listening,
            pending,
            listeners: BTreeMap::new(),
            conns: Vec::new(),
            accepted,
        })
    }

    /// Put one socket into LISTEN for `target`, recording it as listening.
    fn arm(&mut self, target: Target) -> bool {
        if self.listeners.len() >= MAX_LISTENERS && !self.listeners.contains_key(&target) {
            return false;
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; SOCKET_BUFFER]),
            tcp::SocketBuffer::new(vec![0u8; SOCKET_BUFFER]),
        );
        // No `bind()`: this is the stack's own table and the port is a header field.
        if socket
            .listen((IpAddress::Ipv6(target.0), target.1))
            .is_err()
        {
            return false;
        }
        let handle = self.sockets.add(socket);
        self.listeners.insert(target, handle);
        self.listening
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(target);
        true
    }

    /// Arm a listener for every target a SYN asked about. Returns how many were added.
    fn arm_wanted(&mut self) -> usize {
        let wanted: Vec<Target> = {
            let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            core::mem::take(&mut p.wanted).into_iter().collect()
        };
        let mut armed = 0;
        for target in wanted {
            if self.listeners.contains_key(&target) {
                continue;
            }
            if self.arm(target) {
                armed += 1;
            }
        }
        armed
    }

    /// Promote every listener that has become established into a connection, reporting it
    /// and re-arming a listener behind it so the next connection has somewhere to land.
    async fn take_established(&mut self) {
        let established: Vec<(Target, SocketHandle)> = self
            .listeners
            .iter()
            .filter(|(_, h)| {
                let s = self.sockets.get::<tcp::Socket>(**h);
                s.remote_endpoint().is_some()
            })
            .map(|(t, h)| (*t, *h))
            .collect();
        for (target, handle) in established {
            self.listeners.remove(&target);
            if self.conns.len() >= MAX_CONNECTIONS {
                // Refuse rather than queue: the tool sees a reset, which is the truthful
                // answer to "this machine will not carry another one right now".
                self.sockets.get_mut::<tcp::Socket>(handle).abort();
                self.sockets.remove(handle);
                self.listening
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&target);
                continue;
            }
            let (caller, stack) = tokio::io::duplex(BRIDGE_BUFFER);
            let (to_stack_tx, to_stack_rx) = mpsc::channel::<Vec<u8>>(8);
            let (from_stack_tx, from_stack_rx) = mpsc::channel::<Vec<u8>>(8);
            tokio::spawn(pump(stack, to_stack_tx, from_stack_rx));
            self.conns.push(Conn {
                handle,
                from_local: to_stack_rx,
                to_local: from_stack_tx,
                queued: VecDeque::new(),
                local_done: false,
            });
            let sent = self
                .accepted
                .send(Accepted {
                    to: target.0,
                    port: target.1,
                    stream: caller,
                })
                .await;
            if sent.is_err() {
                return; // the consumer went away; `run` notices and stops
            }
            // Someone else may dial the same service while this one is up.
            self.arm(target);
        }
    }

    /// Move bytes between each connection's socket and its pump, and reap finished ones.
    fn service(&mut self) {
        let mut finished = Vec::new();
        for (i, conn) in self.conns.iter_mut().enumerate() {
            let socket = self.sockets.get_mut::<tcp::Socket>(conn.handle);

            // Local → socket. Take from the pump only while there is somewhere to put it,
            // so an unwritable socket becomes backpressure rather than an unbounded queue.
            while conn.queued.len() < SOCKET_BUFFER {
                match conn.from_local.try_recv() {
                    Ok(chunk) => conn.queued.extend(chunk),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        conn.local_done = true;
                        break;
                    }
                }
            }
            while socket.can_send() && !conn.queued.is_empty() {
                let (head, _) = conn.queued.as_slices();
                let n = match socket.send_slice(head) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                conn.queued.drain(..n);
            }
            if conn.local_done && conn.queued.is_empty() && socket.may_send() {
                // The tool closed its side: half-close the TCP so the peer sees EOF, and
                // keep reading the other direction until it closes too.
                socket.close();
            }

            // Socket → local. Consume only what the pump accepted, so an unread byte
            // stays in the socket and closes the window on the tool.
            while socket.can_recv() {
                match conn.to_local.try_reserve() {
                    Ok(permit) => {
                        let taken = socket.recv(|data| {
                            let n = data.len().min(CHUNK);
                            (n, data[..n].to_vec())
                        });
                        match taken {
                            Ok(chunk) if !chunk.is_empty() => permit.send(chunk),
                            _ => break,
                        }
                    }
                    Err(_) => break,
                }
            }

            // Done when the socket is gone and nothing is left to hand over.
            let dead = !socket.is_active() && !socket.can_recv();
            if dead && conn.queued.is_empty() {
                finished.push(i);
            }
        }
        for i in finished.into_iter().rev() {
            let conn = self.conns.swap_remove(i);
            // Dropping `to_local` gives the pump EOF, which gives the caller EOF.
            self.sockets.remove(conn.handle);
        }
    }

    /// Drive the stack until the consumer of accepted connections goes away.
    pub async fn run(mut self) -> Result<()> {
        let mut clock = SmolInstant::from_millis(0);
        let step = smoltcp::time::Duration::from_millis(
            u64::try_from(POLL_INTERVAL.as_millis()).unwrap_or(5),
        );
        loop {
            self.iface.poll(clock, &mut self.device, &mut self.sockets);
            // A SYN for a port with no socket asked for one. Arm it and poll again, so the
            // held packet is replayed in this same tick rather than after a retransmit.
            if self.arm_wanted() > 0 {
                self.iface.poll(clock, &mut self.device, &mut self.sockets);
            }
            self.take_established().await;
            if self.accepted.is_closed() && self.conns.is_empty() {
                return Ok(());
            }
            self.service();
            tokio::time::sleep(POLL_INTERVAL).await;
            clock += step;
        }
    }
}

/// Move bytes between the stack's half of the local bridge and the loop's channels.
///
/// This exists so the poll loop never awaits: it does `try_recv`/`try_reserve` only, which
/// cannot stall the stack no matter what the local tool does.
async fn pump(
    stack: DuplexStream,
    to_stack: mpsc::Sender<Vec<u8>>,
    mut from_stack: mpsc::Receiver<Vec<u8>>,
) {
    let (mut read, mut write) = tokio::io::split(stack);
    let up = async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to_stack.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    let down = async move {
        while let Some(chunk) = from_stack.recv().await {
            if write.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = write.shutdown().await;
    };
    tokio::join!(up, down);
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::TxToken;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A device pair that carries packets between two stacks with no kernel involved —
    /// the same idea as `tests/support/vnet.rs` for UDP, one layer down.
    type Wire = Rc<RefCell<VecDeque<Vec<u8>>>>;

    struct Paired {
        rx: Wire,
        tx: Wire,
    }
    struct PairRx(Vec<u8>);
    struct PairTx(Wire);

    impl RxToken for PairRx {
        fn consume<T, F: FnOnce(&[u8]) -> T>(self, f: F) -> T {
            f(&self.0)
        }
    }
    impl TxToken for PairTx {
        fn consume<T, F: FnOnce(&mut [u8]) -> T>(self, len: usize, f: F) -> T {
            let mut buf = vec![0u8; len];
            let r = f(&mut buf);
            self.0.borrow_mut().push_back(buf);
            r
        }
    }
    impl Device for Paired {
        type RxToken<'a>
            = PairRx
        where
            Self: 'a;
        type TxToken<'a>
            = PairTx
        where
            Self: 'a;
        fn receive(&mut self, _t: SmolInstant) -> Option<(PairRx, PairTx)> {
            let p = self.rx.borrow_mut().pop_front()?;
            Some((PairRx(p), PairTx(Rc::clone(&self.tx))))
        }
        fn transmit(&mut self, _t: SmolInstant) -> Option<PairTx> {
            Some(PairTx(Rc::clone(&self.tx)))
        }
        fn capabilities(&self) -> DeviceCapabilities {
            let mut c = DeviceCapabilities::default();
            c.medium = smoltcp::phy::Medium::Ip;
            c.max_transmission_unit = 1500;
            c
        }
    }

    fn ula(last: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, last)
    }

    #[test]
    fn a_syn_is_recognised_and_a_synack_is_not() {
        // The sniffer must react to a connection being *opened*, never to one being
        // answered, or it would arm a listener for traffic this side initiated.
        let mut ip = vec![0u8; 40 + 20];
        {
            let mut p = Ipv6Packet::new_unchecked(&mut ip);
            p.set_version(6);
            p.set_next_header(IpProtocol::Tcp);
            p.set_payload_len(20);
            p.set_hop_limit(64);
            p.set_src_addr(ula(2));
            p.set_dst_addr(ula(1));
        }
        {
            let mut t = TcpPacket::new_unchecked(&mut ip[40..]);
            t.set_src_port(49152);
            t.set_dst_port(22);
            t.set_header_len(20);
            t.set_syn(true);
            t.set_ack(false);
        }
        assert_eq!(syn_target(&ip), Some((ula(1), 22)));
        {
            let mut t = TcpPacket::new_unchecked(&mut ip[40..]);
            t.set_ack(true);
        }
        assert_eq!(syn_target(&ip), None, "SYN+ACK is not an open");
        // Not TCP at all, and truncated garbage: answered `None`, never panicking.
        {
            let mut p = Ipv6Packet::new_unchecked(&mut ip);
            p.set_next_header(IpProtocol::Udp);
        }
        assert_eq!(syn_target(&ip), None);
        assert_eq!(syn_target(&[]), None);
        assert_eq!(syn_target(&[6u8; 12]), None);
    }

    #[test]
    fn an_interface_needs_at_least_one_address() {
        let (tx, _rx) = mpsc::channel(1);
        let dev = Paired {
            rx: Rc::new(RefCell::new(VecDeque::new())),
            tx: Rc::new(RefCell::new(VecDeque::new())),
        };
        assert!(matches!(
            Netstack::new(dev, &[], tx),
            Err(Error::MalformedLink("an interface with no addresses"))
        ));
    }

    /// The datapath, end to end, with no kernel: a client stack opens TCP to port 22 of a
    /// Vox overlay address, and the interface terminates it, reports it with the address
    /// and port that name the room and the service, and carries bytes **both ways**.
    ///
    /// This is what makes the interface gateable without root — the proof needs no `tun`
    /// device, no route and no privilege, only two stacks wired to each other.
    #[tokio::test(flavor = "current_thread")]
    async fn a_connection_to_a_vox_address_is_terminated_and_carried_both_ways() {
        let a2b: Wire = Rc::new(RefCell::new(VecDeque::new()));
        let b2a: Wire = Rc::new(RefCell::new(VecDeque::new()));
        let srv_dev = Paired {
            rx: Rc::clone(&a2b),
            tx: Rc::clone(&b2a),
        };
        let mut cli_dev = Paired {
            rx: Rc::clone(&b2a),
            tx: Rc::clone(&a2b),
        };

        let srv_ip = ula(1);
        let cli_ip = ula(2);
        let (acc_tx, mut acc_rx) = mpsc::channel(4);
        let stack = Netstack::new(srv_dev, &[srv_ip], acc_tx).unwrap();

        // The client side is an ordinary smoltcp stack standing in for the kernel.
        let mut clock = SmolInstant::from_millis(0);
        let mut cli_if = Interface::new(Config::new(HardwareAddress::Ip), &mut cli_dev, clock);
        cli_if.update_ip_addrs(|l| {
            l.push(IpCidr::new(IpAddress::Ipv6(cli_ip), 128)).unwrap();
        });
        let mut cli_sockets = SocketSet::new(Vec::new());
        let h = cli_sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; SOCKET_BUFFER]),
            tcp::SocketBuffer::new(vec![0u8; SOCKET_BUFFER]),
        ));
        cli_sockets
            .get_mut::<tcp::Socket>(h)
            .connect(
                cli_if.context(),
                (IpAddress::Ipv6(srv_ip), 22),
                (IpAddress::Ipv6(cli_ip), 49152),
            )
            .unwrap();

        // Drive both sides by hand: the interface's own loop and the client stack, on one
        // thread, so the test is deterministic.
        let mut stack = stack;
        let mut accepted: Option<Accepted> = None;
        let request = b"SSH-2.0-vox-client";
        let reply = b"SSH-2.0-vox-service";
        let mut sent = false;
        let mut carried = Vec::new();
        let mut echoed = Vec::new();

        for _ in 0..4_000 {
            clock += smoltcp::time::Duration::from_millis(5);
            cli_if.poll(clock, &mut cli_dev, &mut cli_sockets);
            stack.tick(clock).await;
            if accepted.is_none() {
                if let Ok(a) = acc_rx.try_recv() {
                    // The interface names the room and the service by what was in the
                    // packet headers, with nothing configured.
                    assert_eq!(a.to, srv_ip);
                    assert_eq!(a.port, 22);
                    accepted = Some(a);
                }
            }
            {
                let c = cli_sockets.get_mut::<tcp::Socket>(h);
                if c.can_send() && !sent {
                    c.send_slice(request).unwrap();
                    sent = true;
                }
                if c.can_recv() {
                    let _ = c.recv(|d| {
                        echoed.extend_from_slice(d);
                        (d.len(), ())
                    });
                }
            }
            if let Some(a) = accepted.as_mut() {
                // Read what the tool sent, then answer as the service would.
                if carried.len() < request.len() {
                    let mut buf = [0u8; 64];
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_millis(1), a.stream.read(&mut buf))
                            .await
                    {
                        carried.extend_from_slice(&buf[..n]);
                        if carried.len() >= request.len() {
                            a.stream.write_all(reply).await.unwrap();
                            a.stream.flush().await.unwrap();
                        }
                    }
                }
            }
            if echoed.len() >= reply.len() {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert!(accepted.is_some(), "the connection was never terminated");
        assert_eq!(carried, request, "the tool's bytes reached the interface");
        assert_eq!(echoed, reply, "the service's bytes reached the tool");
    }

    impl<D: Device> Netstack<D> {
        /// One iteration of [`Netstack::run`], for a test that drives the clock itself.
        async fn tick(&mut self, clock: SmolInstant) {
            self.iface.poll(clock, &mut self.device, &mut self.sockets);
            if self.arm_wanted() > 0 {
                self.iface.poll(clock, &mut self.device, &mut self.sockets);
            }
            self.take_established().await;
            self.service();
        }
    }
}
