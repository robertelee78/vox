//! **Two NATs in userspace**, one in front of a host and one in front of a guest, with every datagram
//! between the two `vox` processes — and between each of them and the anchor — crossing them. No
//! packet filter, no `sudo`: the separation comes from the address family, as in `relay.rs`.
//!
//! - The **host** binds `127.0.0.1` (an IPv4 socket) and the **guest** binds `[::1]`. Neither can
//!   send the other a datagram, and neither is ever told the anchor's real address: each is given an
//!   *alias* of the anchor in its own family ([`TwoNats::anchor_for_host`], `…_for_guest`), a socket
//!   of this file's. So every destination a process can reach is a socket of this file's.
//! - The host's NAT has its **public** side on `[::1]` — where the guest and the anchor can reach
//!   it — and the guest's NAT has its public side on `127.0.0.1`. The anchor (dual-stack on `[::]`)
//!   is reached *from* those public sockets, so **the address the anchor observes for each process
//!   is its NAT's public mapping**, as on the internet: the reflexive address a hole punch trades is
//!   real, not configured. The anchor is told to advertise only the aliases, so neither process can
//!   learn a route around its NAT.
//!
//! Each NAT keeps a **mapping** (inside address, and for a symmetric NAT the remote too → a public
//! socket) and a **filter** (public socket, remote) opened by the inside host's own outbound
//! datagram. A datagram arriving at a public socket from a remote the filter does not hold is
//! **dropped** — so a lone direct dial dies at the far NAT, and only a *simultaneous* open, each
//! side's datagram opening its own filter for the other's, gets through.
//!
//! - [`Kind::PortRestrictedCone`]: one public port per inside address, whatever the destination
//!   (endpoint-independent mapping), filtered by remote address and port. The reflexive address the
//!   anchor observed is the one the peer's datagrams arrive at, so a coordinated punch works and
//!   nothing less does.
//! - [`Kind::Symmetric`]: a new public port for each destination. The address the anchor observed
//!   is not the one used towards the peer, so a punch cannot work and the pair must stay relayed —
//!   the **control** that shows nothing leaks around the emulator.
//!
//! Peer-to-peer datagrams (host ↔ guest, not via the anchor) are counted, delivered and filtered
//! separately, so a proof can tell a direct path from the anchor's circuit by bytes, and can show
//! that unsolicited datagrams were in fact dropped.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    PortRestrictedCone,
    Symmetric,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Host,
    Guest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// The anchor's alias the host dials (IPv4).
    AnchorForHost,
    /// The anchor's alias the guest dials (IPv6).
    AnchorForGuest,
    /// A public socket of this side's NAT.
    Public(Side),
}

#[derive(Default)]
struct Nat {
    /// (inside, remote-for-symmetric) → public address.
    mapping: HashMap<(SocketAddr, Option<SocketAddr>), SocketAddr>,
    /// public address → inside address.
    inside_of: HashMap<SocketAddr, SocketAddr>,
    /// (public, remote) pairs the inside host has sent to.
    filter: HashSet<(SocketAddr, SocketAddr)>,
}

struct Inner {
    kind: Kind,
    sockets: HashMap<SocketAddr, Arc<UdpSocket>>,
    roles: HashMap<SocketAddr, Role>,
    host_nat: Nat,
    guest_nat: Nat,
}

#[derive(Default)]
struct Counters {
    /// Peer datagram payload bytes delivered guest → host and host → guest.
    p2p_to_host: AtomicU64,
    p2p_to_guest: AtomicU64,
    /// Peer datagrams a NAT's filter dropped (unsolicited).
    p2p_filtered: AtomicU64,
    /// Datagrams to or from the anchor that a filter dropped.
    anchor_filtered: AtomicU64,
    /// Every peer datagram, in order: when, which way, where from and to, and whether a filter
    /// let it in — the first [`EVENT_LOG`] of them, for a report that must say which side sent.
    events: Mutex<Vec<P2pEvent>>,
}

/// How many peer datagrams are kept for a report.
const EVENT_LOG: usize = 400;

/// One peer datagram as the emulator handled it.
#[derive(Clone, Debug)]
pub struct P2pEvent {
    pub at: Instant,
    /// `true` host → guest, `false` guest → host.
    pub to_guest: bool,
    /// The sender's inside address and the public address it was sent to.
    pub from_inside: SocketAddr,
    pub to_public: SocketAddr,
    pub delivered: bool,
    pub len: usize,
}

pub struct TwoNats {
    pub kind: Kind,
    /// The anchor's real address, IPv6 and IPv4 (it listens on `[::]`).
    anchor_v6: SocketAddr,
    anchor_v4: SocketAddr,
    /// The anchor as the host must name it (an IPv4 alias).
    pub anchor_for_host: SocketAddr,
    /// The anchor as the guest must name it (an IPv6 alias).
    pub anchor_for_guest: SocketAddr,
    inner: Arc<Mutex<Inner>>,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
    /// When each inside address first sent a peer datagram (towards the other process).
    first_p2p: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
}

impl TwoNats {
    /// Two NATs of `kind` in front of whatever binds `127.0.0.1` (the host) and `[::1]` (the
    /// guest), around an anchor listening on `[::]:anchor_port`.
    pub fn start(kind: Kind, anchor_port: u16) -> Self {
        let anchor_v6 = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, anchor_port));
        let anchor_v4 = SocketAddr::from(([127, 0, 0, 1], anchor_port));
        let inner = Arc::new(Mutex::new(Inner {
            kind,
            sockets: HashMap::new(),
            roles: HashMap::new(),
            host_nat: Nat::default(),
            guest_nat: Nat::default(),
        }));
        let counters = Arc::new(Counters::default());
        let stop = Arc::new(AtomicBool::new(false));
        let first_p2p = Arc::new(Mutex::new(HashMap::new()));
        let ctx = Ctx {
            inner: Arc::clone(&inner),
            counters: Arc::clone(&counters),
            stop: Arc::clone(&stop),
            first_p2p: Arc::clone(&first_p2p),
            anchor_v6,
            anchor_v4,
        };
        let (anchor_for_host, anchor_for_guest) = {
            let mut locked = inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                bind_socket(&mut locked, "127.0.0.1:0", Role::AnchorForHost, &ctx),
                bind_socket(&mut locked, "[::1]:0", Role::AnchorForGuest, &ctx),
            )
        };
        Self {
            kind,
            anchor_v6,
            anchor_v4,
            anchor_for_host,
            anchor_for_guest,
            inner,
            counters,
            stop,
            first_p2p,
        }
    }

    /// Peer payload bytes delivered guest → host.
    pub fn p2p_to_host(&self) -> u64 {
        self.counters.p2p_to_host.load(Ordering::SeqCst)
    }

    /// Peer payload bytes delivered host → guest.
    pub fn p2p_to_guest(&self) -> u64 {
        self.counters.p2p_to_guest.load(Ordering::SeqCst)
    }

    /// Unsolicited peer datagrams a NAT dropped.
    pub fn p2p_filtered(&self) -> u64 {
        self.counters.p2p_filtered.load(Ordering::SeqCst)
    }

    /// Anchor datagrams a NAT dropped (should stay 0: each process dialled its anchor).
    pub fn anchor_filtered(&self) -> u64 {
        self.counters.anchor_filtered.load(Ordering::SeqCst)
    }

    /// When each inside address first sent the other process a datagram.
    pub fn first_p2p(&self) -> HashMap<SocketAddr, Instant> {
        self.first_p2p
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The peer datagrams seen so far (the first few hundred).
    pub fn events(&self) -> Vec<P2pEvent> {
        self.counters
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The public mappings each NAT holds, as `(inside, public)` — for a report.
    pub fn mappings(&self) -> (usize, usize) {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (inner.host_nat.mapping.len(), inner.guest_nat.mapping.len())
    }
}

impl Drop for TwoNats {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[derive(Clone)]
struct Ctx {
    inner: Arc<Mutex<Inner>>,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
    first_p2p: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
    anchor_v6: SocketAddr,
    anchor_v4: SocketAddr,
}

fn bind_socket(inner: &mut Inner, bind: &str, role: Role, ctx: &Ctx) -> SocketAddr {
    let sock = UdpSocket::bind(bind)
        .unwrap_or_else(|e| panic!("APPARATUS: could not bind an emulator socket on {bind}: {e}"));
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap_or_else(|e| panic!("APPARATUS: an emulator socket on {bind}: {e}"));
    let addr = sock
        .local_addr()
        .unwrap_or_else(|e| panic!("APPARATUS: an emulator socket on {bind}: {e}"));
    let sock = Arc::new(sock);
    inner.sockets.insert(addr, Arc::clone(&sock));
    inner.roles.insert(addr, role);
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        while !ctx.stop.load(Ordering::SeqCst) {
            let Ok((n, src)) = sock.recv_from(&mut buf) else {
                continue;
            };
            if let Some((via, to)) = route(&ctx, addr, role, src, n) {
                let _ = via.send_to(&buf[..n], to);
            }
        }
    });
    addr
}

/// The public address `side`'s NAT uses for `inside` talking to `remote`, created on first use;
/// the filter is opened for `remote` on it. The outbound half of a NAT.
fn egress(
    inner: &mut Inner,
    ctx: &Ctx,
    side: Side,
    inside: SocketAddr,
    remote: SocketAddr,
) -> SocketAddr {
    let key = (
        inside,
        match inner.kind {
            Kind::PortRestrictedCone => None,
            Kind::Symmetric => Some(remote),
        },
    );
    let existing = match side {
        Side::Host => inner.host_nat.mapping.get(&key).copied(),
        Side::Guest => inner.guest_nat.mapping.get(&key).copied(),
    };
    let public = existing.unwrap_or_else(|| {
        // The host's NAT faces the guest's family, and the guest's the host's.
        let bind = match side {
            Side::Host => "[::1]:0",
            Side::Guest => "127.0.0.1:0",
        };
        let public = bind_socket(inner, bind, Role::Public(side), ctx);
        let nat = match side {
            Side::Host => &mut inner.host_nat,
            Side::Guest => &mut inner.guest_nat,
        };
        nat.mapping.insert(key, public);
        nat.inside_of.insert(public, inside);
        public
    });
    match side {
        Side::Host => inner.host_nat.filter.insert((public, remote)),
        Side::Guest => inner.guest_nat.filter.insert((public, remote)),
    };
    public
}

/// The inside address a datagram from `remote` at `public` goes to, if the filter holds it. The
/// inbound half of a NAT.
fn ingress(
    inner: &Inner,
    side: Side,
    public: SocketAddr,
    remote: SocketAddr,
) -> Option<SocketAddr> {
    let nat = match side {
        Side::Host => &inner.host_nat,
        Side::Guest => &inner.guest_nat,
    };
    if nat.filter.contains(&(public, remote)) {
        nat.inside_of.get(&public).copied()
    } else {
        None
    }
}

/// Where a datagram that arrived at `at` from `src` goes next, and from which socket.
fn route(
    ctx: &Ctx,
    at: SocketAddr,
    role: Role,
    src: SocketAddr,
    n: usize,
) -> Option<(Arc<UdpSocket>, SocketAddr)> {
    let mut inner = ctx
        .inner
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match role {
        // A process dials its anchor: out through its NAT, to the anchor's real address.
        Role::AnchorForHost => {
            let public = egress(&mut inner, ctx, Side::Host, src, ctx.anchor_v6);
            Some((Arc::clone(&inner.sockets[&public]), ctx.anchor_v6))
        }
        Role::AnchorForGuest => {
            let public = egress(&mut inner, ctx, Side::Guest, src, ctx.anchor_v4);
            Some((Arc::clone(&inner.sockets[&public]), ctx.anchor_v4))
        }
        Role::Public(side) => {
            let (anchor, alias_role) = match side {
                Side::Host => (ctx.anchor_v6, Role::AnchorForHost),
                Side::Guest => (ctx.anchor_v4, Role::AnchorForGuest),
            };
            if src == anchor {
                // The anchor answering (or relaying) to a process behind this NAT: delivered from
                // the alias that process knows the anchor by.
                let Some(inside) = ingress(&inner, side, at, anchor) else {
                    ctx.counters.anchor_filtered.fetch_add(1, Ordering::SeqCst);
                    return None;
                };
                let alias = inner
                    .roles
                    .iter()
                    .find(|(_, r)| **r == alias_role)
                    .map(|(a, _)| *a)?;
                return Some((Arc::clone(&inner.sockets[&alias]), inside));
            }
            // Otherwise it is the *other* process, sending to this public address: out through its
            // own NAT first, then in through this one.
            let other = match side {
                Side::Host => Side::Guest,
                Side::Guest => Side::Host,
            };
            ctx.first_p2p
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(src)
                .or_insert_with(Instant::now);
            let from_public = egress(&mut inner, ctx, other, src, at);
            let verdict = ingress(&inner, side, at, from_public);
            {
                let mut ev = ctx
                    .counters
                    .events
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if ev.len() < EVENT_LOG {
                    ev.push(P2pEvent {
                        at: Instant::now(),
                        to_guest: side == Side::Guest,
                        from_inside: src,
                        to_public: at,
                        delivered: verdict.is_some(),
                        len: n,
                    });
                }
            }
            let Some(inside) = verdict else {
                ctx.counters.p2p_filtered.fetch_add(1, Ordering::SeqCst);
                return None;
            };
            match side {
                Side::Host => ctx
                    .counters
                    .p2p_to_host
                    .fetch_add(n as u64, Ordering::SeqCst),
                Side::Guest => ctx
                    .counters
                    .p2p_to_guest
                    .fetch_add(n as u64, Ordering::SeqCst),
            };
            Some((Arc::clone(&inner.sockets[&from_public]), inside))
        }
    }
}
