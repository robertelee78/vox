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
//! By default no packet is ever lost, reordered or delayed, so a failure is a real
//! behavioural failure rather than a flake. A test that is *about* a bad path shapes it
//! explicitly and deterministically: [`VirtualNet::set_delay`] (a fixed one-way delay,
//! order preserved), [`VirtualNet::set_loss`] (every Nth datagram on one directed link),
//! and [`VirtualNet::set_mtu`] (datagrams past a size dropped, as a small-MTU path
//! does). Each is counted, so a gate can show the shaping actually happened.

// Shared by several test binaries, each of which uses a different part of it.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

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
    /// Fixed one-way delay applied to every datagram.
    delay: Duration,
    /// Where delayed datagrams wait, in the order they were sent.
    delayed: Option<tokio::sync::mpsc::UnboundedSender<Delayed>>,
    /// (sender's own address, destination) → (drop about one in N, generator state).
    loss: HashMap<(SocketAddr, SocketAddr), (u64, u64)>,
    /// Datagrams dropped by [`VirtualNet::set_loss`].
    lost: u64,
    /// Datagrams larger than this are dropped, as a path with that MTU would.
    mtu: Option<usize>,
    /// Per-host MTU: the host's own access link, both directions.
    host_mtu: HashMap<SocketAddr, usize>,
    /// Datagrams dropped by [`VirtualNet::set_mtu`] or [`VirtualNet::set_host_mtu`].
    too_big: u64,
}

/// A datagram waiting out [`VirtualNet::set_delay`].
struct Delayed {
    at: tokio::time::Instant,
    socket: Arc<VirtualSocket>,
    src: SocketAddr,
    payload: Vec<u8>,
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
            severed: AtomicBool::new(false),
        });
        let mut g = self.lock();
        g.hosts.insert(addr, Arc::downgrade(&socket));
        if let Some(index) = nat {
            g.behind.insert(addr, index);
        }
        socket
    }

    /// Change how a NAT behaves after it was created, so a test can model the thing that
    /// actually happens in the field: conditions improve. A pair that could only be relayed
    /// because both sides sat behind symmetric NATs becomes punchable when one of them moves
    /// to a cone NAT — a different network, a router that stopped being hostile, a captive
    /// portal released.
    ///
    /// `at` is the index handed back by the order of [`VirtualNet::behind_nat`] calls: the
    /// first is 0, the second 1.
    pub fn set_nat_kind(&self, at: usize, kind: NatKind) {
        let mut g = self.lock();
        if let Some(nat) = g.nats.get_mut(at) {
            nat.kind = kind;
        }
    }

    /// Cut `socket` off the network for good: nothing it sends is carried and nothing is
    /// delivered to it. This is a **crashed process**, as the rest of the network sees one — its
    /// last words (a QUIC close on shutdown) never leave the box, so every peer is left holding a
    /// connection to something that is no longer there. A graceful shutdown would tell them, and
    /// a restart test that let it would prove nothing about restarts.
    pub fn sever(&self, socket: &VirtualSocket) {
        socket.severed.store(true, Ordering::SeqCst);
    }

    /// A new socket at `addr`, where a severed one used to be — the same host coming back **on
    /// the same address and port**, behind the same NAT if it had one. The NAT's mappings are
    /// the NAT's, not the process's, so they survive: a peer sees the restarted process at
    /// exactly the external address it saw the old one at. That is the case an address rule
    /// gets wrong in the "same address, must be the old connection" direction.
    #[must_use]
    pub fn replug(self: &Arc<Self>, addr: SocketAddr) -> Arc<VirtualSocket> {
        self.add(addr, None)
    }

    /// Make a host's NAT **rebind**: drop every mapping it holds for the host at inner address
    /// `host`, so its next datagram to any destination leaves from a fresh external port, and
    /// the old external ports route nowhere. What a home router does when a mapping times out or
    /// the router reboots — the process behind it is alive throughout and never knows.
    ///
    /// Without this a symmetric mapping is keyed by (host, destination) for ever, so a live
    /// process could never appear at a new port, and the case an address rule gets wrong in the
    /// "new port, must be a new process" direction could not be staged. Returns how many
    /// mappings were dropped, so a test can assert it staged something.
    pub fn rebind(&self, host: SocketAddr) -> usize {
        let mut g = self.lock();
        let dropped: Vec<SocketAddr> = g
            .mappings
            .iter()
            .filter(|((_, inner, _), _)| *inner == host)
            .map(|(_, ext)| *ext)
            .collect();
        g.mappings.retain(|(_, inner, _), _| *inner != host);
        for ext in &dropped {
            g.external.remove(ext);
        }
        g.filters.retain(|(ext, _)| !dropped.contains(ext));
        dropped.len()
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

    /// Delay every datagram by `delay`, one way, preserving order. Must be called inside
    /// a tokio runtime: the datagrams wait on one task, so they come out in the order
    /// they went in.
    pub fn set_delay(&self, delay: Duration) {
        let mut g = self.lock();
        g.delay = delay;
        if g.delayed.is_none() && !delay.is_zero() {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Delayed>();
            tokio::spawn(async move {
                while let Some(d) = rx.recv().await {
                    tokio::time::sleep_until(d.at).await;
                    d.socket.deliver(d.src, d.payload);
                }
            });
            g.delayed = Some(tx);
        }
    }

    /// Drop about one in `every` of the datagrams the host bound at `from` sends to `to`
    /// (0 stops it), chosen by a fixed-seed generator.
    ///
    /// **Not every `every`th.** It was, and a strict period can phase-lock with the
    /// traffic it is meant to damage: when the packets on a link fall into a cycle whose
    /// length shares a factor with the period, every loss lands on the same kind of
    /// packet. `relay_drops_not_stalls` was red 2 runs in 40 for exactly that — 63 outer
    /// datagrams lost, every one of them an acknowledgement, and 400 of 400 app datagrams
    /// delivered. A generator has no period to lock to. The seed is fixed, so a run is
    /// repeatable given the same traffic.
    pub fn set_loss(&self, from: SocketAddr, to: SocketAddr, every: u64) {
        let mut g = self.lock();
        if every == 0 {
            g.loss.remove(&(from, to));
        } else {
            g.loss.insert((from, to), (every, 0x9E37_79B9_7F4A_7C15));
        }
    }

    /// How many datagrams [`VirtualNet::set_loss`] has dropped.
    #[must_use]
    pub fn lost(&self) -> u64 {
        self.lock().lost
    }

    /// Drop every datagram larger than `mtu` bytes, as a path with that MTU does.
    pub fn set_mtu(&self, mtu: Option<usize>) {
        self.lock().mtu = mtu;
    }

    /// Give the host bound at `host` an access link of `mtu` bytes: every datagram it
    /// sends or receives larger than that is dropped. How a path with a small MTU on one
    /// side only — one leg of a relay circuit, say — is modelled.
    pub fn set_host_mtu(&self, host: SocketAddr, mtu: usize) {
        self.lock().host_mtu.insert(host, mtu);
    }

    /// How many datagrams [`VirtualNet::set_mtu`] and [`VirtualNet::set_host_mtu`] have
    /// dropped.
    #[must_use]
    pub fn too_big(&self) -> u64 {
        self.lock().too_big
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("virtual net mutex")
    }

    /// Carry one datagram from `from` to `to`, translating and filtering as the hosts'
    /// NATs require.
    fn send(&self, from: SocketAddr, to: SocketAddr, payload: &[u8]) {
        let (delivery, delayed) = {
            let mut g = self.lock();
            if g.mtu.is_some_and(|mtu| payload.len() > mtu) {
                g.too_big += 1;
                return;
            }
            if let Some((every, state)) = g.loss.get_mut(&(from, to)) {
                // xorshift64: small, fixed-seed, and without a short period.
                *state ^= *state << 13;
                *state ^= *state >> 7;
                *state ^= *state << 17;
                if *state % *every == 0 {
                    g.lost += 1;
                    return;
                }
            }
            let src = g.translate_out(from, to);
            let routed = g.route_in(from, src, to);
            let over = |host: &SocketAddr| g.host_mtu.get(host).is_some_and(|m| payload.len() > *m);
            if over(&from) || routed.as_ref().is_some_and(|(sock, _)| over(&sock.addr)) {
                g.too_big += 1;
                return;
            }
            let delayed = g
                .delayed
                .clone()
                .filter(|_| !g.delay.is_zero())
                .map(|tx| (tx, tokio::time::Instant::now() + g.delay));
            (routed, delayed)
        };
        let Some((socket, src)) = delivery else {
            return;
        };
        match delayed {
            Some((tx, at)) => {
                let _ = tx.send(Delayed {
                    at,
                    socket,
                    src,
                    payload: payload.to_vec(),
                });
            }
            None => socket.deliver(src, payload.to_vec()),
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
    /// Set by [`VirtualNet::sever`]: the process behind this socket has crashed.
    severed: AtomicBool,
}

impl VirtualSocket {
    fn deliver(&self, src: SocketAddr, payload: Vec<u8>) {
        if self.severed.load(Ordering::SeqCst) {
            return; // a crashed process receives nothing
        }
        // The waker runs outside the inbox lock: a woken task may send immediately.
        let waker = {
            let mut inbox = self.inbox.lock().expect("inbox mutex");
            inbox.queue.push_back((src, payload));
            inbox.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
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
        if self.severed.load(Ordering::SeqCst) {
            return Ok(()); // a crashed process's last words never leave the box
        }
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
