//! **The family LAN** (PRD-001 R28, ADR-013 §"The family LAN"): a room's members on one
//! virtual Ethernet-less subnet, so that software which finds things by asking the local
//! network — Plex and Jellyfin, Chromecast, a game's "join LAN game" — finds them across
//! Vox.
//!
//! ## What it is built from, and why nothing new
//! A LAN is IP packets between members, some to one member and some to all of them. Vox
//! already carries unreliable packets between two members ([`crate::node::app`] streams
//! with a datagram flow bound, ADR-022) and already decides who may exchange them (the
//! app gate: this node's keyring joined with the room's authors, in both directions). So
//! the LAN is **one more program on the app API**, speaking [`LAN_LABEL`]:
//!
//! - **One app stream per trusted member**, with a datagram flow bound. Each IP packet is
//!   one datagram; one bigger than a datagram is fragmented by the flow (ADR-022 M22.1).
//!   The stream carries no bytes. It is the link's lifetime, and when the gate withdraws
//!   it, the link is gone.
//! - **Unicast** goes on the link of the member holding the destination address
//!   ([`plan::LanPlan`]).
//! - **Broadcast and multicast** — mDNS on `224.0.0.251`, SSDP on `239.255.255.250`, the
//!   subnet broadcast, and the rest of `224.0.0.0/4` and `ff00::/8` — are copied onto
//!   **every** link: a switch floods them the same way. A copy goes only where a link is,
//!   and a link exists only where the gate admitted it, so an untrusted member receives
//!   nothing — there is nothing to leak through.
//! - **TCP** needs nothing of its own. Its segments are IP packets like any other, and the
//!   endpoints' TCP stacks retransmit what a datagram loses, as they would across Wi-Fi.
//!
//! ## What is checked on arrival, and why at the receiver
//! A packet from member P must come **from one of P's addresses** and go **to one of
//! mine, or to a group**. Anything else is dropped and counted (`spoofed`, `not_for_me`).
//! The check is on the receiving side because that is the side whose code the sender
//! does not control: a modified node can send whatever it likes, and the receiver is the
//! one who decides what reaches its kernel. So a trusted member can impersonate nobody,
//! and cannot use this node as a router to anywhere.
//!
//! ## Why floods are rate-capped
//! A flood costs one datagram per member, and it is the one kind of packet a member
//! receives without having asked. So each direction has a token bucket: what this node
//! floods ([`FLOOD_RATE`] a second, bursts of [`FLOOD_BURST`]), and what each peer may
//! flood into it (the same). Discovery traffic is a few packets a second; a loop or a
//! misbehaving member is thousands, and loses the excess instead of the LAN.
//!
//! ## The device
//! The engine reads and writes whole IP packets through [`Tun`]. On a Mac that is a
//! `utun` interface, which needs root to create and is created by the CLI (`vox lan up`)
//! before it gives root up; [`ChannelTun`] is the same interface as a pair of channels,
//! which is how the gates stand in for the kernel — and how a mobile client's packet
//! tunnel extension, which is handed packets rather than a file descriptor, will feed it.

pub mod packet;
pub mod plan;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};

use crate::error::Result;
use crate::hash::Digest32;
use crate::node::actor::NodeHandle;
use crate::node::api::NodeView;
use crate::node::app::{AppHub, AppStream};

use packet::{is_group, parse, to_limited_broadcast};
use plan::LanPlan;

/// The app label the LAN speaks (ADR-022 decision 7).
pub const LAN_LABEL: &str = "vox-lan/v1";

/// The interface MTU. IPv6's minimum, so nothing on the LAN has to discover a path MTU,
/// and small enough that a packet fits one datagram on most direct paths; a relayed path
/// fragments it (ADR-022 M22.1).
pub const LAN_MTU: u16 = 1280;

/// Floods this node sends, and floods each peer may send it, per second.
pub const FLOOD_RATE: f64 = 100.0;

/// The burst either flood bucket allows.
pub const FLOOD_BURST: f64 = 200.0;

/// The first wait before dialling a member again after a failed open.
const REDIAL_MIN: Duration = Duration::from_millis(500);

/// The longest wait between opens to a member whose LAN is not up.
const REDIAL_MAX: Duration = Duration::from_secs(8);

/// How often the member list and the keyring are re-read even without a change, so a
/// member whose LAN came up late is dialled again.
const TICK: Duration = Duration::from_secs(1);

/// The IP side of the LAN: whole packets to and from the operating system.
pub trait Tun: Send + Sync + 'static {
    /// The next packet the operating system sent out of the interface, or `None` once the
    /// interface is gone.
    fn recv(&self) -> impl std::future::Future<Output = Option<Vec<u8>>> + Send;

    /// Hand the operating system a packet as if it arrived on the interface. Never waits:
    /// returns whether the packet was taken, and one that was not is lost, as it would
    /// be on a wire.
    fn send(&self, packet: &[u8]) -> bool;
}

/// A [`Tun`] whose other side is a pair of channels ([`OsSide`]) instead of a kernel.
#[derive(Debug)]
pub struct ChannelTun {
    from_os: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    to_os: mpsc::Sender<Vec<u8>>,
}

/// The operating system's side of a [`ChannelTun`]: `send` is a packet the system routes
/// out of the interface, `recv` is a packet the LAN delivered to it.
#[derive(Debug)]
pub struct OsSide {
    /// Packets out of the interface, into the LAN.
    pub send: mpsc::Sender<Vec<u8>>,
    /// Packets the LAN delivered.
    pub recv: mpsc::Receiver<Vec<u8>>,
}

/// A [`ChannelTun`] and its [`OsSide`], each direction buffering `depth` packets.
#[must_use]
pub fn channel_tun(depth: usize) -> (ChannelTun, OsSide) {
    let (os_tx, lan_rx) = mpsc::channel(depth);
    let (lan_tx, os_rx) = mpsc::channel(depth);
    (
        ChannelTun {
            from_os: tokio::sync::Mutex::new(lan_rx),
            to_os: lan_tx,
        },
        OsSide {
            send: os_tx,
            recv: os_rx,
        },
    )
}

impl Tun for ChannelTun {
    async fn recv(&self) -> Option<Vec<u8>> {
        self.from_os.lock().await.recv().await
    }

    fn send(&self, packet: &[u8]) -> bool {
        self.to_os.try_send(packet.to_vec()).is_ok()
    }
}

/// What the LAN has done, for gates, `vox lan up`'s stats and `vox status`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LanStats {
    /// Packets the operating system sent into the LAN.
    pub from_os: u64,
    /// Unicast packets put on a member's link.
    pub to_peers: u64,
    /// Broadcast or multicast packets flooded.
    pub floods: u64,
    /// Copies those floods made: one per link.
    pub flood_copies: u64,
    /// Packets that arrived from members.
    pub from_peers: u64,
    /// Packets handed to the operating system.
    pub to_os: u64,
    /// Packets to this node's own address that reached the LAN, handed straight back.
    pub looped: u64,
    /// Packets for somewhere that is not this LAN.
    pub off_lan: u64,
    /// Unicast packets for an address no linked member holds.
    pub no_route: u64,
    /// Arrivals whose source is not an address of the member they came from.
    pub spoofed: u64,
    /// Arrivals addressed neither to this node nor to a group.
    pub not_for_me: u64,
    /// Floods dropped by a rate cap, in either direction.
    pub rate_capped: u64,
    /// Arrivals the operating system's side had no room for.
    pub device_full: u64,
    /// The members this node has a live link to, in fingerprint order.
    pub links: Vec<Digest32>,
}

#[derive(Default)]
struct Counters {
    from_os: AtomicU64,
    to_peers: AtomicU64,
    floods: AtomicU64,
    flood_copies: AtomicU64,
    from_peers: AtomicU64,
    to_os: AtomicU64,
    looped: AtomicU64,
    off_lan: AtomicU64,
    no_route: AtomicU64,
    spoofed: AtomicU64,
    not_for_me: AtomicU64,
    rate_capped: AtomicU64,
    device_full: AtomicU64,
}

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full() -> Self {
        Self {
            tokens: FLOOD_BURST,
            at: Instant::now(),
        }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        let refill = now.duration_since(self.at).as_secs_f64() * FLOOD_RATE;
        self.tokens = (self.tokens + refill).min(FLOOD_BURST);
        self.at = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

/// One member's link: the app stream the gate admitted, with its datagram flow.
struct Link {
    id: u64,
    /// Which side opened it. When both sides open at once, both keep the one the lower
    /// fingerprint opened, so they agree on one link without another message.
    opener: Digest32,
    stream: AppStream,
    /// What this peer may flood into this node.
    floods: Mutex<Bucket>,
    /// Told when this link stops being the member's link, so its reader lets the stream
    /// go. Without it a link that lost the open race would sit open on both sides for as
    /// long as the process ran, holding one of the peer's app-stream places.
    retired: tokio::sync::Notify,
}

fn retire(link: &Link) {
    link.retired.notify_one();
}

struct Backoff {
    at: Instant,
    wait: Duration,
}

struct State {
    plan: LanPlan,
    links: HashMap<Digest32, Arc<Link>>,
    dialing: HashSet<Digest32>,
    backoff: HashMap<Digest32, Backoff>,
    floods: Bucket,
    next_id: u64,
}

struct Shared<T: Tun> {
    me: Digest32,
    channel_id: Digest32,
    hub: Arc<AppHub>,
    tun: T,
    state: Mutex<State>,
    c: Counters,
}

fn lock<S>(m: &Mutex<S>) -> MutexGuard<'_, S> {
    // No critical section awaits or can panic half-way, so a poisoned lock still holds a
    // consistent state.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running LAN. Dropping it takes the LAN down: every link is closed and nothing more
/// is read from the device.
pub struct Lan<T: Tun> {
    shared: Arc<Shared<T>>,
    _stop: watch::Sender<()>,
}

impl<T: Tun> std::fmt::Debug for Lan<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lan").finish_non_exhaustive()
    }
}

/// The members of `channel_id` this node would link to: in the room, in the keyring, and
/// not itself. The app gate decides again on both ends; this only saves dialling someone
/// the local half of it would refuse.
fn wanted(view: &NodeView, channel_id: &Digest32, me: &Digest32) -> (Vec<Digest32>, Vec<Digest32>) {
    let members = view
        .open_channels
        .iter()
        .find(|c| c.channel_id == *channel_id)
        .map(|c| c.members.clone())
        .unwrap_or_default();
    let trusted: HashSet<Digest32> = view.trusted.iter().map(|(fp, _)| *fp).collect();
    let peers = members
        .iter()
        .filter(|m| *m != me && trusted.contains(*m))
        .copied()
        .collect();
    (members, peers)
}

impl<T: Tun> Lan<T> {
    /// Bring the LAN of `channel_id` up on `tun`, over `node`.
    ///
    /// # Errors
    /// If the node has no identity, or something here already runs this room's LAN.
    pub fn start(node: &NodeHandle, channel_id: Digest32, tun: T) -> Result<Self> {
        let view = node.view();
        let me = view
            .identity
            .as_ref()
            .map(|i| i.fingerprint)
            .ok_or(crate::error::Error::AtRestLocked)?;
        let hub = Arc::clone(node.app());
        let listener = hub.listen(Some(channel_id), LAN_LABEL)?;
        let (members, _) = wanted(&view, &channel_id, &me);
        let shared = Arc::new(Shared {
            me,
            channel_id,
            hub,
            tun,
            state: Mutex::new(State {
                plan: LanPlan::new(channel_id, &members),
                links: HashMap::new(),
                dialing: HashSet::new(),
                backoff: HashMap::new(),
                floods: Bucket::full(),
                next_id: 0,
            }),
            c: Counters::default(),
        });
        let (stop, stopped) = watch::channel(());
        tokio::spawn(accept_loop(Arc::clone(&shared), listener, stopped.clone()));
        tokio::spawn(member_loop(
            Arc::clone(&shared),
            node.watch(),
            stopped.clone(),
        ));
        tokio::spawn(device_loop(Arc::clone(&shared), stopped));
        Ok(Self {
            shared,
            _stop: stop,
        })
    }

    /// This node's fingerprint.
    #[must_use]
    pub fn me(&self) -> Digest32 {
        self.shared.me
    }

    /// The room's current plan: its prefixes and every member's addresses.
    #[must_use]
    pub fn plan(&self) -> LanPlan {
        lock(&self.shared.state).plan.clone()
    }

    /// A snapshot of the counters and the live links.
    #[must_use]
    pub fn stats(&self) -> LanStats {
        let c = &self.shared.c;
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut links: Vec<Digest32> = lock(&self.shared.state).links.keys().copied().collect();
        links.sort_unstable();
        LanStats {
            from_os: g(&c.from_os),
            to_peers: g(&c.to_peers),
            floods: g(&c.floods),
            flood_copies: g(&c.flood_copies),
            from_peers: g(&c.from_peers),
            to_os: g(&c.to_os),
            looped: g(&c.looped),
            off_lan: g(&c.off_lan),
            no_route: g(&c.no_route),
            spoofed: g(&c.spoofed),
            not_for_me: g(&c.not_for_me),
            rate_capped: g(&c.rate_capped),
            device_full: g(&c.device_full),
            links,
        }
    }
}

async fn stopped(rx: &mut watch::Receiver<()>) {
    // Nothing is ever sent: the sender is dropped with the `Lan`, which ends this.
    while rx.changed().await.is_ok() {}
}

async fn accept_loop<T: Tun>(
    sh: Arc<Shared<T>>,
    mut listener: crate::node::app::AppListener,
    mut stop: watch::Receiver<()>,
) {
    loop {
        let incoming = tokio::select! {
            () = stopped(&mut stop) => return,
            i = listener.next() => match i { Some(i) => i, None => return },
        };
        let sh = Arc::clone(&sh);
        let stop = stop.clone();
        tokio::spawn(async move {
            if let Ok(stream) = sh.hub.accept(incoming.id).await {
                install(&sh, incoming.peer, incoming.peer, stream, stop);
            }
        });
    }
}

/// Keep the plan current and a link to every wanted member: re-read on every change to
/// the node's view and every [`TICK`] regardless.
async fn member_loop<T: Tun>(
    sh: Arc<Shared<T>>,
    mut view: watch::Receiver<NodeView>,
    mut stop: watch::Receiver<()>,
) {
    loop {
        let (members, peers) = wanted(&view.borrow_and_update(), &sh.channel_id, &sh.me);
        let dial: Vec<Digest32> = {
            let mut st = lock(&sh.state);
            let plan = LanPlan::new(sh.channel_id, &members);
            if plan != st.plan {
                st.plan = plan;
            }
            // A member no longer wanted loses its link here, as well as through the
            // app gate's own teardown: whichever is first.
            st.links.retain(|m, l| {
                let keep = peers.contains(m);
                if !keep {
                    retire(l);
                }
                keep
            });
            let now = Instant::now();
            let due: Vec<Digest32> = peers
                .iter()
                .filter(|m| !st.links.contains_key(*m) && !st.dialing.contains(*m))
                .filter(|m| st.backoff.get(*m).is_none_or(|b| b.at <= now))
                .copied()
                .collect();
            st.dialing.extend(due.iter().copied());
            due
        };
        for peer in dial {
            tokio::spawn(dial_one(Arc::clone(&sh), peer, stop.clone()));
        }
        tokio::select! {
            () = stopped(&mut stop) => return,
            r = view.changed() => if r.is_err() { return },
            () = tokio::time::sleep(TICK) => {}
        }
    }
}

async fn dial_one<T: Tun>(sh: Arc<Shared<T>>, peer: Digest32, stop: watch::Receiver<()>) {
    let opened = sh
        .hub
        .open(sh.channel_id, peer, vec![LAN_LABEL.to_owned()], true)
        .await;
    {
        let mut st = lock(&sh.state);
        st.dialing.remove(&peer);
        match &opened {
            Ok(_) => {
                st.backoff.remove(&peer);
            }
            Err(_) => {
                let wait = st
                    .backoff
                    .get(&peer)
                    .map_or(REDIAL_MIN, |b| (b.wait * 2).min(REDIAL_MAX));
                st.backoff.insert(
                    peer,
                    Backoff {
                        at: Instant::now() + wait,
                        wait,
                    },
                );
            }
        }
    }
    if let Ok(stream) = opened {
        install(&sh, peer, sh.me, stream, stop);
    }
}

/// Make `stream` the link to `peer` unless a link it must yield to is already there, and
/// start reading it.
fn install<T: Tun>(
    sh: &Arc<Shared<T>>,
    peer: Digest32,
    opener: Digest32,
    stream: AppStream,
    stop: watch::Receiver<()>,
) {
    let link = {
        let mut st = lock(&sh.state);
        if let Some(cur) = st.links.get(&peer) {
            // Both sides keep the link the lower fingerprint opened; a second open by the
            // same side (a redial racing a link not yet seen to end) replaces the first.
            if opener > cur.opener {
                return;
            }
            retire(cur);
        }
        st.next_id += 1;
        let link = Arc::new(Link {
            id: st.next_id,
            opener,
            stream,
            floods: Mutex::new(Bucket::full()),
            retired: tokio::sync::Notify::new(),
        });
        st.links.insert(peer, Arc::clone(&link));
        link
    };
    tokio::spawn(link_loop(Arc::clone(sh), peer, link, stop));
}

/// Deliver what arrives on one link until it ends, then forget it.
async fn link_loop<T: Tun>(
    sh: Arc<Shared<T>>,
    peer: Digest32,
    link: Arc<Link>,
    mut stop: watch::Receiver<()>,
) {
    let mut buf = [0u8; 64];
    loop {
        tokio::select! {
            () = stopped(&mut stop) => break,
            () = link.retired.notified() => break,
            d = link.stream.recv_datagram() => match d {
                Some(p) => arrive(&sh, &peer, &link, p),
                None => break,
            },
            // The stream carries nothing; it ends when the far side drops the link.
            r = link.stream.read(&mut buf) => if !matches!(r, Ok(Some(_))) { break },
        }
    }
    let mut st = lock(&sh.state);
    if st.links.get(&peer).is_some_and(|l| l.id == link.id) {
        st.links.remove(&peer);
    }
}

/// A packet from member `peer`: checked, then handed to the operating system.
fn arrive<T: Tun>(sh: &Shared<T>, peer: &Digest32, link: &Link, mut p: Vec<u8>) {
    bump(&sh.c.from_peers);
    let Some(h) = parse(&p) else {
        bump(&sh.c.not_for_me);
        return;
    };
    let (flood, subnet_broadcast) = {
        let st = lock(&sh.state);
        if !st.plan.of(peer).is_some_and(|a| a.holds(h.src)) {
            bump(&sh.c.spoofed);
            return;
        }
        let subnet_broadcast = matches!(h.dst, IpAddr::V4(a) if a == st.plan.broadcast_v4());
        if st.plan.of(&sh.me).is_some_and(|a| a.holds(h.dst)) {
            (false, false)
        } else if subnet_broadcast || is_group(h.dst) {
            (true, subnet_broadcast)
        } else {
            bump(&sh.c.not_for_me);
            return;
        }
    };
    if flood && !lock(&link.floods).take() {
        bump(&sh.c.rate_capped);
        return;
    }
    if subnet_broadcast {
        to_limited_broadcast(&mut p);
    }
    if sh.tun.send(&p) {
        bump(&sh.c.to_os);
    } else {
        bump(&sh.c.device_full);
    }
}

enum Route {
    To(Arc<Link>),
    Flood(Vec<Arc<Link>>),
    Loop,
}

/// Read the device until it closes, routing every packet the operating system sends.
async fn device_loop<T: Tun>(sh: Arc<Shared<T>>, mut stop: watch::Receiver<()>) {
    loop {
        let p = tokio::select! {
            () = stopped(&mut stop) => return,
            p = sh.tun.recv() => match p { Some(p) => p, None => return },
        };
        depart(&sh, &p);
    }
}

fn depart<T: Tun>(sh: &Shared<T>, p: &[u8]) {
    bump(&sh.c.from_os);
    let Some(h) = parse(p) else {
        bump(&sh.c.off_lan);
        return;
    };
    let route = {
        let mut st = lock(&sh.state);
        let group =
            is_group(h.dst) || matches!(h.dst, IpAddr::V4(a) if a == st.plan.broadcast_v4());
        let in_lan = match h.dst {
            IpAddr::V4(a) => st.plan.in_subnet_v4(a),
            IpAddr::V6(a) => st.plan.in_prefix_v6(a),
        };
        if group {
            if !st.floods.take() {
                bump(&sh.c.rate_capped);
                return;
            }
            Route::Flood(st.links.values().cloned().collect())
        } else if !in_lan {
            bump(&sh.c.off_lan);
            return;
        } else {
            match st.plan.owner(h.dst) {
                Some(m) if m == sh.me => Route::Loop,
                Some(m) => match st.links.get(&m) {
                    Some(l) => Route::To(Arc::clone(l)),
                    None => {
                        bump(&sh.c.no_route);
                        return;
                    }
                },
                None => {
                    bump(&sh.c.no_route);
                    return;
                }
            }
        }
    };
    match route {
        Route::To(link) => {
            if link.stream.send_datagram(p).is_ok() {
                bump(&sh.c.to_peers);
            } else {
                bump(&sh.c.no_route);
            }
        }
        Route::Flood(links) => {
            bump(&sh.c.floods);
            for link in links {
                if link.stream.send_datagram(p).is_ok() {
                    bump(&sh.c.flood_copies);
                }
            }
        }
        Route::Loop => {
            bump(&sh.c.looped);
            if sh.tun.send(p) {
                bump(&sh.c.to_os);
            } else {
                bump(&sh.c.device_full);
            }
        }
    }
}
