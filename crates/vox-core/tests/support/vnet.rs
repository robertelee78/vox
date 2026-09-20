//! An in-process virtual UDP network with **NAT devices**, so tests can observe real
//! NAT behaviour (ADR-012 rungs 3 and 4).
//!
//! Hole punching is a claim about middleboxes: that a *simultaneous open* gets through
//! a NAT that drops unsolicited inbound datagrams. On loopback there is no such NAT,
//! so a test that "punches" over loopback proves nothing — it would pass without any
//! punch at all. This module supplies the middlebox: a deterministic, in-process
//! network of virtual sockets ([`quinn::AsyncUdpSocket`], driven through
//! [`VoxEndpoint::bind_abstract`](vox_core::transport::quic::VoxEndpoint::bind_abstract)),
//! where each host may sit behind a NAT that maps and filters per RFC 4787.
//!
//! No packet is ever lost, reordered or delayed, so a failure is a real behavioural
//! failure rather than a flake.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

/// How a NAT device maps and filters (RFC 4787 terminology).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatKind {
    /// Endpoint-**independent** mapping with address-and-port-dependent filtering (the
    /// "port-restricted cone" of common usage): one external port per inner socket,
    /// whoever it talks to, and inbound accepted only from a remote that inner socket
    /// has already sent to. This is the NAT hole punching is *for*: the address a peer
    /// learns from a third party is the right one to dial, and the dial only needs the
    /// filter opened, which the peer's own simultaneous dial does.
    PortRestrictedCone,
    /// Address-and-port-**dependent** mapping (a "symmetric" NAT): a different external
    /// port per destination, so the address learned from a third party is *not* the one
    /// a peer must dial. Hole punching cannot traverse this — ADR-012's documented
    /// limit, and the reason a relay rung exists.
    Symmetric,
}

/// The virtual network: an address space, the hosts in it, and their NAT devices.
pub struct VirtualNet {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for VirtualNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VirtualNet")
    }
}

#[derive(Default)]
struct Inner {
    /// Every socket by the address it is bound to (private for a NATed host).
    hosts: HashMap<SocketAddr, Weak<VirtualSocket>>,
    /// Which NAT a host sits behind, if any.
    behind: HashMap<SocketAddr, usize>,
    nats: Vec<Nat>,
    /// External address → the inner socket it maps to.
    external: HashMap<SocketAddr, SocketAddr>,
    /// (nat, inner, destination-or-any) → external address.
    mappings: HashMap<(usize, SocketAddr, Option<SocketAddr>), SocketAddr>,
    /// (external address, remote address) pairs the NAT will accept inbound from.
    filters: HashSet<(SocketAddr, SocketAddr)>,
    next_external_port: u16,
    /// Datagrams a NAT dropped because no mapping or filter admitted them.
    filtered: u64,
    /// Datagrams dropped because nothing is bound at the destination.
    unroutable: u64,
}

struct Nat {
    external_ip: IpAddr,
    kind: NatKind,
}

impl VirtualNet {
    /// A new, empty network.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                next_external_port: 40_000,
                ..Inner::default()
            }),
        })
    }

    /// Add a host with a globally routable address — no NAT, reachable by anyone.
    #[must_use]
    pub fn public(self: &Arc<Self>, addr: SocketAddr) -> Arc<VirtualSocket> {
        self.add(addr, None)
    }

    /// Add a host at private address `addr` behind a NAT of `kind` whose external
    /// address is `external_ip`.
    #[must_use]
    pub fn behind_nat(
        self: &Arc<Self>,
        addr: SocketAddr,
        kind: NatKind,
        external_ip: IpAddr,
    ) -> Arc<VirtualSocket> {
        let index = {
            let mut g = self.lock();
            g.nats.push(Nat { external_ip, kind });
            g.nats.len() - 1
        };
        self.add(addr, Some(index))
    }

    fn add(self: &Arc<Self>, addr: SocketAddr, nat: Option<usize>) -> Arc<VirtualSocket> {
        let socket = Arc::new(VirtualSocket {
            addr,
            net: Arc::clone(self),
            inbox: Mutex::new(Inbox::default()),
        });
        let mut g = self.lock();
        g.hosts.insert(addr, Arc::downgrade(&socket));
        if let Some(index) = nat {
            g.behind.insert(addr, index);
        }
        socket
    }

    /// How many datagrams a NAT has dropped for want of a mapping or filter. A
    /// hole-punch test asserts this is non-zero for the unsolicited case: without it,
    /// the "NAT" would be letting everything through and proving nothing.
    #[must_use]
    pub fn filtered(&self) -> u64 {
        self.lock().filtered
    }

    /// How many datagrams went to an address with nothing bound behind it.
    #[must_use]
    pub fn unroutable(&self) -> u64 {
        self.lock().unroutable
    }

    /// The external address a host's NAT currently maps for traffic to `dest`, if the
    /// host has sent there (or anywhere, for a cone NAT). This is what a third party
    /// observes as the host's source address — the "observed address" of ADR-012 rung 3.
    #[must_use]
    pub fn observed(&self, host: SocketAddr, dest: SocketAddr) -> Option<SocketAddr> {
        let g = self.lock();
        let index = *g.behind.get(&host)?;
        let key = match g.nats[index].kind {
            NatKind::PortRestrictedCone => None,
            NatKind::Symmetric => Some(dest),
        };
        g.mappings.get(&(index, host, key)).copied()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("virtual net mutex")
    }

    /// Carry one datagram from `from` to `to`, translating and filtering as the hosts'
    /// NATs require.
    fn send(&self, from: SocketAddr, to: SocketAddr, payload: &[u8]) {
        let delivery = {
            let mut g = self.lock();
            let src = g.translate_out(from, to);
            g.route_in(from, src, to)
        };
        // The waker runs outside the network lock: a woken task may send immediately.
        if let Some((socket, src)) = delivery {
            let waker = {
                let mut inbox = socket.inbox.lock().expect("inbox mutex");
                inbox.queue.push_back((src, payload.to_vec()));
                inbox.waker.take()
            };
            if let Some(w) = waker {
                w.wake();
            }
        }
    }
}

impl Inner {
    /// The source address the rest of the network sees for a datagram `from` → `to`,
    /// creating the NAT mapping and opening the return filter as a real NAT would.
    fn translate_out(&mut self, from: SocketAddr, to: SocketAddr) -> SocketAddr {
        let Some(&index) = self.behind.get(&from) else {
            return from; // a host with a routable address translates nothing
        };
        let key = match self.nats[index].kind {
            NatKind::PortRestrictedCone => None,
            NatKind::Symmetric => Some(to),
        };
        let external = match self.mappings.get(&(index, from, key)) {
            Some(&addr) => addr,
            None => {
                let port = self.next_external_port;
                self.next_external_port = self
                    .next_external_port
                    .checked_add(1)
                    .expect("virtual net external ports");
                let addr = SocketAddr::new(self.nats[index].external_ip, port);
                self.mappings.insert((index, from, key), addr);
                self.external.insert(addr, from);
                addr
            }
        };
        // Sending to `to` is what admits `to`'s replies: address-and-port-dependent
        // filtering, the half of NAT behaviour a hole punch exists to open.
        self.filters.insert((external, to));
        external
    }

    /// Resolve the destination, applying the receiving NAT's filter. `None` means the
    /// datagram is dropped, and which counter moved says why.
    fn route_in(
        &mut self,
        from: SocketAddr,
        src: SocketAddr,
        to: SocketAddr,
    ) -> Option<(Arc<VirtualSocket>, SocketAddr)> {
        // A private address is reachable only from behind the same NAT: this is what
        // makes a NATed node's own address useless to a distant peer, and therefore what
        // makes the punch necessary. Without it the "NAT" would be a router.
        if let Some(&nat) = self.behind.get(&to) {
            if self.behind.get(&from) != Some(&nat) && !self.external.contains_key(&to) {
                self.unroutable += 1;
                return None;
            }
        }
        let target = match self.external.get(&to) {
            Some(&inner) => {
                if !self.filters.contains(&(to, src)) {
                    self.filtered += 1;
                    return None;
                }
                inner
            }
            None => to,
        };
        match self.hosts.get(&target).and_then(Weak::upgrade) {
            Some(socket) => Some((socket, src)),
            None => {
                self.unroutable += 1;
                None
            }
        }
    }
}

#[derive(Default)]
struct Inbox {
    queue: VecDeque<(SocketAddr, Vec<u8>)>,
    waker: Option<Waker>,
}

/// One host's socket on a [`VirtualNet`].
pub struct VirtualSocket {
    addr: SocketAddr,
    net: Arc<VirtualNet>,
    inbox: Mutex<Inbox>,
}

impl std::fmt::Debug for VirtualSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VirtualSocket({})", self.addr)
    }
}

/// A poller for a socket whose sends never block: the inbox is unbounded, so a
/// transmit is always accepted.
#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for VirtualSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // `max_transmit_segments` is 1, so quinn never batches; a segmented transmit
        // is still split rather than silently sent as one oversized datagram.
        match transmit.segment_size {
            Some(size) if size < transmit.contents.len() => {
                for chunk in transmit.contents.chunks(size) {
                    self.net.send(self.addr, transmit.destination, chunk);
                }
            }
            _ => self
                .net
                .send(self.addr, transmit.destination, transmit.contents),
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut inbox = self.inbox.lock().expect("inbox mutex");
        let capacity = bufs.len().min(meta.len());
        let mut filled = 0;
        while filled < capacity {
            let Some((src, payload)) = inbox.queue.front() else {
                break;
            };
            if payload.len() > bufs[filled].len() {
                // A datagram larger than the buffer quinn offered is dropped, as the
                // kernel would truncate it; never silently corrupt the stream.
                inbox.queue.pop_front();
                continue;
            }
            let (src, payload) = (*src, payload.clone());
            inbox.queue.pop_front();
            bufs[filled][..payload.len()].copy_from_slice(&payload);
            meta[filled] = RecvMeta {
                addr: src,
                len: payload.len(),
                stride: payload.len(),
                ecn: None,
                dst_ip: Some(self.addr.ip()),
            };
            filled += 1;
        }
        if filled == 0 {
            inbox.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(filled))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}
