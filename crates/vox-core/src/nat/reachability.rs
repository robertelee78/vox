//! The prefer-direct reachability ladder (ADR-012 §"Reachability strategy").
//!
//! Given a peer's advertised [`EndpointList`] (recovered from an authenticated
//! [`crate::nat::record::RendezvousRecord`]), connect over the M9 QUIC transport
//! preferring direct connections, in order:
//!
//! 1. **IPv6 direct**, then **IPv4 direct** — raced Happy-Eyeballs-style
//!    (RFC 8305): the first candidate is tried immediately, each subsequent
//!    candidate is launched after a short staggered delay, and the first QUIC
//!    connection that authenticates as the expected peer wins; the rest are
//!    cancelled. IPv6 candidates are ordered first ([`EndpointList::direct_candidates`]).
//! 2. **Hole-punch** (coordinated via [`crate::nat::holepunch`]) and **relay**
//!    (the relay-hint rung) are the fallbacks for peers with no reachable direct
//!    endpoint. Relay *data-plane* forwarding is ADR-013/M11; this module exposes
//!    the relay hints ([`EndpointList::relay_hints`]) and the direct/hole-punch
//!    rungs.
//!
//! Every attempt authenticates the peer cryptographically (M9 pins the expected
//! composite identity; a wrong identity aborts the handshake). Exhausting the
//! ladder returns [`Error::Unreachable`] — the honest ADR-012 limit, never a false
//! success.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::task::JoinSet;

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::nat::multiaddr::{EndpointList, Multiaddr};
use crate::nat::portmap::{
    gateway, gateway_addr, gateway_addr_v6, map_port, open_ipv6_pinhole, Method, PortMapping,
    Protocol,
};

/// What one address family's gateway work asked, and what answered (ADR-012 N-54).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GatewayAsk {
    /// Every candidate asked, in the order tried: a PCP or NAT-PMP server as `address:port`, and
    /// UPnP's search as `UPnP search <multicast address>`. Empty when the family was not asked
    /// (no routable address of it).
    pub asked: Vec<String>,
    /// The candidate that granted a mapping, and on which rung; `None` when none did.
    pub answered: Option<(String, Method)>,
}

/// [`GatewayAsk`] for both families: what `vox status` names (N-54).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GatewayAsks {
    /// The IPv4 mapping's candidates.
    pub ipv4: GatewayAsk,
    /// The IPv6 pinhole's candidates.
    pub ipv6: GatewayAsk,
}

impl GatewayAsk {
    /// The ask over `asked`, answered by `won` if it granted.
    fn of(asked: Vec<String>, won: Option<&PortMapping>) -> Self {
        Self {
            asked,
            answered: won.map(|m| {
                (
                    m.server.map_or_else(|| "?".to_owned(), |s| s.to_string()),
                    m.method,
                )
            }),
        }
    }
}
use crate::transport::quic::{VoxConnection, VoxEndpoint};

/// The Happy-Eyeballs "Connection Attempt Delay" (RFC 8305 §5): how long to wait
/// before launching the next candidate in parallel with those already in flight.
/// 250 ms is the RFC's recommended default (bounds simultaneous attempts while
/// still racing).
pub const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Per-candidate hard timeout: an individual QUIC attempt that neither connects nor
/// fails within this window is abandoned (its slot frees for the next candidate).
pub const PER_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether `ip` is an address a peer elsewhere on the internet could plausibly reach.
///
/// "Plausibly" is exact, not hedging: a NAT-mapped public address appears in this
/// node's advertised set only because a port map succeeded (ADR-012 rung 2), and that
/// is precisely the case this must accept. What it rejects is every address whose scope
/// is known to be local — so a node holding nothing but these is one that needs a relay,
/// which is what the caller wants to know before minting an address for someone.
///
/// Rejected: unspecified, loopback, multicast, IPv4 link-local (169.254/16), RFC 1918
/// private (10/8, 172.16/12, 192.168/16), RFC 6598 CGNAT (100.64/10), RFC 5737
/// documentation ranges, IPv6 link-local (fe80::/10) and unique-local (fc00::/7) —
/// which includes Vox's own overlay prefix (ADR-013).
#[must_use]
pub fn is_routable(ip: &IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                // RFC 6598 carrier-grade NAT: 100.64.0.0/10.
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                // RFC 1112 reserved 240.0.0.0/4 — Vox's own circuit addresses live here.
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            // fe80::/10 link-local, fc00::/7 unique-local (the ADR-013 overlay prefix
            // is inside the latter), and 2001:db8::/32 documentation — the same
            // classes rejected for IPv4, so the two families answer alike.
            !((seg[0] & 0xffc0) == 0xfe80
                || (seg[0] & 0xfe00) == 0xfc00
                || (seg[0] == 0x2001 && seg[1] == 0x0db8))
        }
    }
}

/// The ordered direct-connection candidates for a peer (IPv6 first, then IPv4),
/// taken from its advertised endpoints. This is the input to [`connect_direct`].
#[must_use]
pub fn direct_candidates(endpoints: &EndpointList) -> Vec<SocketAddr> {
    endpoints.direct_candidates()
}

/// The mapping lifetime this node asks a gateway for, and therefore the interval it
/// must renew well inside (RFC 6886/6887 put renewal on the caller). Two hours
/// matches the ADR-012 address-record TTL, so a mapping and the record that
/// advertises it age together.
pub const PORT_MAP_LIFETIME_SECS: u32 = 2 * 60 * 60;

/// The address the operating system would use to reach the wider internet, found
/// **without sending a packet**: a UDP socket is "connected" to a public address,
/// which only makes the kernel pick a route and bind a source address, and that
/// source address is read back. No datagram is ever sent, so this contacts nobody
/// and reveals nothing.
///
/// This is what a node must advertise instead of its bound address. A node that binds
/// the wildcard (the normal case) has no single bound address to publish, and
/// publishing `0.0.0.0` would advertise a destination nobody can dial.
///
/// Empty when there is no route at all (an offline or sandboxed host), which is not
/// an error: the node still works on loopback and over whatever rungs it does have.
///
/// **Both** families are probed and returned, IPv6 first (the ADR-012 preference
/// order): a dual-stack host is dialable two ways, and advertising only the family
/// that happened to be probed first would throw one of them away.
pub async fn local_route_ips() -> Vec<IpAddr> {
    let mut out = Vec::with_capacity(2);
    // 2001:db8::/32 and 192.0.2.0/24 are the reserved documentation prefixes
    // (RFC 3849, RFC 5737): never routed to a real host, so even a stray packet could
    // not reach anything. Port 9 is discard.
    for probe in ["[2001:db8::1]:9", "192.0.2.1:9"] {
        let Ok(target) = probe.parse::<SocketAddr>() else {
            continue;
        };
        let bind: SocketAddr = if target.is_ipv6() {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let Ok(socket) = UdpSocket::bind(bind).await else {
            continue;
        };
        if socket.connect(target).await.is_err() {
            continue;
        }
        match socket.local_addr() {
            Ok(addr) if !addr.ip().is_unspecified() && !addr.ip().is_loopback() => {
                out.push(addr.ip());
            }
            _ => continue,
        }
    }
    out
}

/// The single most-preferred routable address, or `None` — [`local_route_ips`] with
/// the ADR-012 order already applied.
pub async fn local_route_ip() -> Option<IpAddr> {
    local_route_ips().await.into_iter().next()
}

/// The endpoints this node should advertise for a socket bound on `bound_port`, and
/// the port mapping if a gateway granted one.
///
/// This is the **publish side** of the ADR-012 ladder, in the ADR-012 preference
/// order (IPv6 first, then IPv4, so a dialer tries the path needing no translation
/// first):
///
/// 1. the routable **IPv6** address the OS would use ([`local_route_ips`]) — nothing
///    is translated, so the address is dialable as it stands, and a PCP *pinhole*
///    ([`open_ipv6_pinhole`]) is asked for alongside it to get through the stateful
///    firewall that is usually what stands in the way. This is the ADR's first rung;
/// 2. the routable **IPv4** address (a LAN peer can use it) and the **mapped
///    external** address when a gateway grants one over PCP or NAT-PMP
///    ([`map_port`]) — the second rung, and the only way an IPv4 node behind NAT is
///    dialable at all;
/// 3. loopback, last, so two profiles on one machine still reach each other.
///
/// Both families are published when the host has both, and their gateway work runs
/// concurrently; within a rung the candidate PCP servers are raced (see
/// [`gateway::server_candidates_v4`]). Every mapping a gateway granted comes back so
/// the caller can renew it inside its lifetime.
///
/// Every rung is best-effort: no route, no gateway, or a refusing gateway each just
/// leaves that entry out. A node with no dialable address is not broken — it reaches
/// peers outbound and is reached by hole punching or a relay (the ladder's later
/// rungs), which is the ordinary case for a client inside a private network.
///
/// **Only addresses the socket accepts traffic on are advertised.** The machine's routable
/// addresses are this socket's addresses only when it is bound to the wildcard of their
/// family (`[::]` is dual-stack and takes both). A socket bound to one particular address
/// listens on that address alone: advertising the machine's others with its port sent every
/// peer to a destination where nothing listens, and each such dial waited out a full timeout
/// — a host on `[::1]` published its global IPv6 and LAN IPv4 addresses and not `::1` at all
/// (#223). So a specific-bound socket advertises its bound address, plus whichever routable
/// address (and that address's gateway mapping) *is* its bound address.
///
/// **A lease still held is still advertised** (V210-75). `leased` is what the caller holds and
/// whose lease has not run out. When the IPv4 request gets no answer this time, the held IPv4
/// mapping's external address is advertised in its place: the gateway most likely still holds
/// it, and withdrawing it on one lost reply made the node undialable from outside for as long as
/// the renewal kept failing. Only what was granted *now* is returned, so the caller can tell a
/// failed renewal from a successful one.
pub async fn advertise_endpoints(
    bound: SocketAddr,
    leased: &[PortMapping],
) -> (EndpointList, Vec<PortMapping>, GatewayAsks) {
    let bound_port = bound.port();
    let ips: Vec<IpAddr> = local_route_ips()
        .await
        .into_iter()
        .filter(|ip| listens_on(bound, *ip))
        .collect();
    let v6 = ips.iter().find_map(|ip| match ip {
        IpAddr::V6(a) => Some(*a),
        IpAddr::V4(_) => None,
    });
    let v4 = ips.iter().find_map(|ip| match ip {
        IpAddr::V4(a) => Some(*a),
        IpAddr::V6(_) => None,
    });
    // The two families' gateway work runs at once: each is a few seconds of
    // retransmissions against candidates that may not answer, and they are
    // independent. Serialising them would double the wait for a dual-stack host.
    //
    // **A held mapping is renewed, not raced for again** (N-55): one still leased for the same
    // address goes back to the server that granted it, with its own nonce; only a family holding
    // none (or holding one for an address the machine no longer uses) runs the race, which draws
    // new nonces.
    let renewable = |v6_family: bool, addr: Option<IpAddr>| {
        leased
            .iter()
            .find(|m| {
                mapping_is_v6(m) == v6_family
                    && m.method != Method::UpnpIgd
                    && m.lifetime_secs > 0
                    && m.server.is_some()
                    && addr.is_some()
                    && m.asked_for == addr
            })
            .copied()
    };
    let renew_v6 = renewable(true, v6.map(IpAddr::V6));
    let renew_v4 = renewable(false, v4.map(IpAddr::V4));
    let ((pinhole, ask_v6), (mapped, ask_v4)) = tokio::join!(
        async {
            match (renew_v6, v6) {
                (Some(m), _) => renew_one(&m).await,
                (None, Some(a)) => pinhole_any(a, bound_port).await,
                (None, None) => (None, GatewayAsk::default()),
            }
        },
        async {
            match (renew_v4, v4) {
                (Some(m), _) => renew_one(&m).await,
                (None, Some(a)) => map_port_any(a, bound_port).await,
                (None, None) => (None, GatewayAsk::default()),
            }
        },
    );

    let held_v4 = leased
        .iter()
        .find(|m| !mapping_is_v6(m))
        .filter(|_| v4.is_some());
    let list = compose_endpoints(bound, v6, v4, mapped.as_ref().or(held_v4));
    let asks = GatewayAsks {
        ipv4: ask_v4,
        ipv6: ask_v6,
    };
    (list, pinhole.into_iter().chain(mapped).collect(), asks)
}

/// Whether a mapping is the IPv6 pinhole rather than the IPv4 mapping.
fn mapping_is_v6(m: &PortMapping) -> bool {
    m.method == Method::PcpV6Pinhole
}

/// Renew `held` at its own server (N-55), and say so as the family's ask (N-54).
async fn renew_one(held: &PortMapping) -> (Option<PortMapping>, GatewayAsk) {
    let asked = held.server.iter().map(ToString::to_string).collect();
    let won = crate::nat::portmap::renew(held, PORT_MAP_LIFETIME_SECS)
        .await
        .ok();
    let ask = GatewayAsk::of(asked, won.as_ref());
    (won, ask)
}

/// [`advertise_endpoints`] **without its gateway work**: the routable addresses the socket
/// listens on, any held mapping still leased, and loopback, composed at once. At a change of the
/// machine's network (ADR-012 N-51) nodes advertise this straight away; the gateway requests,
/// seconds of retransmissions against candidates that may not answer, follow in a full discovery.
pub async fn routable_endpoints(bound: SocketAddr, leased: &[PortMapping]) -> EndpointList {
    let ips: Vec<IpAddr> = local_route_ips()
        .await
        .into_iter()
        .filter(|ip| listens_on(bound, *ip))
        .collect();
    let v6 = ips.iter().find_map(|ip| match ip {
        IpAddr::V6(a) => Some(*a),
        IpAddr::V4(_) => None,
    });
    let v4 = ips.iter().find_map(|ip| match ip {
        IpAddr::V4(a) => Some(*a),
        IpAddr::V6(_) => None,
    });
    let held_v4 = leased
        .iter()
        .find(|m| m.method != crate::nat::portmap::Method::PcpV6Pinhole)
        .filter(|_| v4.is_some());
    compose_endpoints(bound, v6, v4, held_v4)
}

/// Whether a socket bound to `bound` receives datagrams sent to `ip`: any address of its family
/// when it is bound to a wildcard (the IPv6 wildcard is dual-stack), else only its own address.
#[must_use]
pub fn listens_on(bound: SocketAddr, ip: IpAddr) -> bool {
    match bound.ip() {
        IpAddr::V6(b) if b.is_unspecified() => true,
        IpAddr::V4(b) if b.is_unspecified() => ip.to_canonical().is_ipv4(),
        b => b.to_canonical() == ip.to_canonical(),
    }
}

/// Put the ladder's findings in ADR-012 preference order. Pure: no network, so the
/// ordering is testable without a gateway.
///
/// The IPv6 **pinhole** contributes no address of its own — it makes the address in
/// `v6` reachable through the firewall, which is why an IPv6 node needs no
/// translation — so it is not an input here.
#[must_use]
fn compose_endpoints(
    bound: SocketAddr,
    v6: Option<Ipv6Addr>,
    v4: Option<Ipv4Addr>,
    mapped: Option<&PortMapping>,
) -> EndpointList {
    let bound_port = bound.port();
    let mut addrs: Vec<Multiaddr> = Vec::new();
    // Rung 1: a routable IPv6 address is dialable as it stands — nothing is
    // translated — so it goes first.
    if let Some(a) = v6 {
        addrs.push(Multiaddr::Ip6(SocketAddrV6::new(a, bound_port, 0, 0)));
    }
    // Rung 2: an IPv4 node is behind NAT in the ordinary case, so its own address is
    // worth advertising mainly for peers on the same LAN, and the *mapped* external
    // address is the one a distant peer can dial.
    if let Some(a) = v4 {
        addrs.push(Multiaddr::Ip4(SocketAddrV4::new(a, bound_port)));
    }
    if let Some(external) = mapped.and_then(|m| m.external_ip.map(|ip| (ip, m.external_port))) {
        let mapped_addr = match external {
            (IpAddr::V4(e), port) => Multiaddr::Ip4(SocketAddrV4::new(e, port)),
            (IpAddr::V6(e), port) => Multiaddr::Ip6(SocketAddrV6::new(e, port, 0, 0)),
        };
        if !addrs.contains(&mapped_addr) {
            addrs.push(mapped_addr);
        }
    }
    // Last rung: loopback, so two profiles on one machine can still reach each other — the
    // loopback this socket listens on. A wildcard socket takes `127.0.0.1`; a socket bound to
    // one address takes that address alone, loopback or not, and it is what it advertises.
    let own = if bound.ip().is_unspecified() {
        Multiaddr::Ip4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, bound_port))
    } else {
        Multiaddr::from(SocketAddr::new(bound.ip().to_canonical(), bound_port))
    };
    if !addrs.contains(&own) {
        addrs.push(own);
    }
    // `EndpointList::new` caps the count; a truncation here would silently drop the
    // *last* (least preferred) rungs, which is the right direction.
    EndpointList::new(addrs.clone()).unwrap_or_else(|_| {
        addrs.truncate(crate::nat::multiaddr::MAX_ENDPOINTS);
        EndpointList::new(addrs).unwrap_or_default()
    })
}

/// Ask each candidate PCP server for an IPv6 pinhole on `port`, stopping at the first
/// that grants one ([`gateway::server_candidates_v6`] supplies the order: the real
/// default route, then the RFC 7723 anycast address), and say what was asked (N-54).
async fn pinhole_any(client_ip: Ipv6Addr, port: u16) -> (Option<PortMapping>, GatewayAsk) {
    let candidates: Vec<SocketAddr> = match gateway::test_gateways() {
        Some(list) => list.into_iter().filter(SocketAddr::is_ipv6).collect(),
        None => gateway::server_candidates_v6()
            .into_iter()
            .map(|(server, scope)| gateway_addr_v6(server, scope))
            .collect(),
    };
    let asked = candidates.iter().map(ToString::to_string).collect();
    let won = first_success(candidates.into_iter().map(|server| async move {
        open_ipv6_pinhole(
            server,
            Protocol::Udp,
            client_ip,
            port,
            PORT_MAP_LIFETIME_SECS,
        )
        .await
        .ok()
    }))
    .await;
    let ask = GatewayAsk::of(asked, won.as_ref());
    (won, ask)
}

/// Ask each candidate gateway to forward `port`, stopping at the first that grants a
/// mapping. Each candidate runs the PCP-then-NAT-PMP ladder of
/// [`crate::nat::portmap::map_port`]; if none grants one, **UPnP-IGD** is
/// tried last (ADR-012 rung 2's full order) — it finds the router by SSDP rather
/// than by address, which is why it is not one of the raced candidates.
///
/// A proof's gateway override ([`gateway::test_gateways`]) replaces the candidates and leaves
/// UPnP out, so nothing but the proof's stand-in is asked.
async fn map_port_any(client_ip: Ipv4Addr, port: u16) -> (Option<PortMapping>, GatewayAsk) {
    let (candidates, upnp): (Vec<SocketAddr>, bool) = match gateway::test_gateways() {
        Some(list) => (
            list.into_iter().filter(SocketAddr::is_ipv4).collect(),
            false,
        ),
        None => (
            gateway::server_candidates_v4(client_ip)
                .into_iter()
                .map(|server| gateway_addr(IpAddr::V4(server)))
                .collect(),
            true,
        ),
    };
    let mut asked: Vec<String> = candidates.iter().map(ToString::to_string).collect();
    let raced = first_success(candidates.into_iter().map(|server| async move {
        map_port(server, Protocol::Udp, port, port, PORT_MAP_LIFETIME_SECS)
            .await
            .ok()
            .map(|m| PortMapping {
                asked_for: Some(IpAddr::V4(client_ip)),
                ..m
            })
    }))
    .await;
    if raced.is_some() || !upnp {
        let ask = GatewayAsk::of(asked, raced.as_ref());
        return (raced, ask);
    }
    asked.push(format!(
        "UPnP search {}",
        crate::nat::portmap::upnp::SSDP_MULTICAST
    ));
    let won =
        crate::nat::portmap::map_port_upnp(Protocol::Udp, port, client_ip, PORT_MAP_LIFETIME_SECS)
            .await
            .ok();
    let ask = GatewayAsk::of(asked, won.as_ref());
    (won, ask)
}

/// Run every future at once and return the first `Some`; **every other grant is deleted** as it
/// comes (N-57).
///
/// Candidates are **raced**, not tried in turn: a candidate that is not a PCP server
/// simply never answers, and its full retransmission schedule (~3.75 s) would
/// otherwise be paid before the next one is even asked. Racing bounds a whole rung at
/// one schedule. The losers are not abandoned mid-request: one whose request has left may
/// already have been granted, and a grant left behind holds a port on that gateway for its
/// whole lifetime. So they run on, off the caller's path, and each grant one of them gets is
/// deleted at once ([`crate::nat::portmap::unmap`]).
async fn first_success<F>(futures: impl Iterator<Item = F>) -> Option<PortMapping>
where
    F: std::future::Future<Output = Option<PortMapping>> + Send + 'static,
{
    let mut set = JoinSet::new();
    for f in futures {
        set.spawn(f);
    }
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(m)) = joined {
            if !set.is_empty() {
                tokio::spawn(async move {
                    while let Some(late) = set.join_next().await {
                        if let Ok(Some(lost)) = late {
                            let _ = tokio::time::timeout(
                                crate::nat::portmap::UNMAP_PATIENCE,
                                crate::nat::portmap::unmap(&lost),
                            )
                            .await;
                        }
                    }
                });
            }
            return Some(m);
        }
    }
    None
}

/// Connect to `expected_peer` over QUIC by racing its direct candidates
/// Happy-Eyeballs-style (RFC 8305).
///
/// Returns the first [`VoxConnection`] that completes the M9 handshake authenticated
/// as `expected_peer`; remaining in-flight attempts are cancelled. Returns
/// [`Error::Unreachable`] if `candidates` is empty or every candidate fails.
///
/// `endpoint` is shared (`Arc`) so each raced attempt can run concurrently on the
/// same local QUIC endpoint. `now_secs` is the caller-supplied wall clock recorded
/// in the session-establishment entry (ADR-011).
pub async fn connect_direct(
    endpoint: Arc<VoxEndpoint>,
    candidates: &[SocketAddr],
    expected_peer: Digest32,
    now_secs: u64,
) -> Result<VoxConnection> {
    connect_direct_within(
        endpoint,
        candidates,
        expected_peer,
        now_secs,
        PER_ATTEMPT_TIMEOUT,
    )
    .await
}

/// [`connect_direct`] with an explicit per-candidate timeout. A hole punch uses a
/// shorter one than a plain dial: QUIC retransmits its Initial at about 1, 2 and 4 s,
/// and a punch that has not landed by then will not.
pub async fn connect_direct_within(
    endpoint: Arc<VoxEndpoint>,
    candidates: &[SocketAddr],
    expected_peer: Digest32,
    now_secs: u64,
    per_attempt: Duration,
) -> Result<VoxConnection> {
    let candidates = dialable_candidates(&endpoint, candidates);
    if candidates.is_empty() {
        return Err(Error::Unreachable("no direct candidates"));
    }
    connect_dialable(endpoint, candidates, expected_peer, now_secs, per_attempt).await
}

/// The candidates `endpoint`'s socket can send to, an IPv4-mapped address written as IPv4 on an
/// IPv4 socket: what [`connect_direct_within`] dials, and what a reach counts as a direct rung
/// (V210-122). A reach whose candidates are all outside this has no direct path, so it asks for its
/// circuit at once rather than after a dial that could only fail.
#[must_use]
pub fn dialable_candidates(endpoint: &VoxEndpoint, candidates: &[SocketAddr]) -> Vec<SocketAddr> {
    // A candidate the socket cannot even address is not a candidate: quinn refuses
    // an IPv6 destination on an IPv4 socket outright, and an IPv6 socket carries IPv4 only
    // as v4-mapped addresses — which works for a socket bound to the IPv6 wildcard (`[::]`,
    // dual-stack) and **not** for one bound to a particular IPv6 address such as `[::1]`.
    // Dropping them here is what keeps a dual-stack peer's IPv6 entries from costing an
    // IPv4-bound node anything, and a peer's IPv4 entries from costing an IPv6-only node a full
    // per-attempt timeout each: measured, an IPv6-only joiner spent `board 20.76s` dialling two
    // IPv4 addresses it could never reach before the one it could (#197).
    //
    // **A circuit is not on the socket.** A relay circuit stands at a synthetic IPv4 address in
    // the range the mux reserves (`transport::mux::in_circuit_range`); its packets travel over
    // the relay's connection, whatever this socket's family. Filtered by family, an IPv6-only
    // node refused every circuit it dialled — "circuit via …: no direct candidates" — and could
    // reach an IPv4 host no way at all (#173's proof, red once #197 merged).
    //
    // **Nor is a candidate the socket's scope cannot reach.** A socket bound to a *particular*
    // IPv6 address cannot send to an IPv4-mapped one either — `::ffff:a.b.c.d` is IPv6 in
    // form only, and the kernel refuses it (`EADDRNOTAVAIL`) — and a loopback-bound socket
    // cannot send off the machine. Kept, each was a dial that could only time out: a guest on
    // `[::1]` waited on `[::ffff:127.0.0.1]`, the observed address a dual-stack anchor reports
    // for an IPv4 host (#222).
    let local = endpoint.local_addr().ok();
    let reachable = |c: &SocketAddr| {
        crate::transport::mux::in_circuit_range(*c) || local.is_none_or(|l| can_send_to(l, *c))
    };
    // **An IPv4-mapped IPv6 address is an IPv4 address.** A peer on a dual-stack socket (`[::]`)
    // sees an IPv4 sender as `::ffff:a.b.c.d`, and that is what it reports back as the sender's
    // observed address — the reflexive address a hole punch trades. Filtered by family as it
    // stands, an IPv4-bound node dropped the only address its peer can be punched at, and fired
    // nothing: measured through the shipped binary behind two userspace NATs (RP-23), the
    // responder sent not one datagram while the initiator's went unanswered at 1, 2, 4 and 7 s.
    candidates
        .iter()
        .map(|c| match (local, c.ip().to_canonical()) {
            (Some(SocketAddr::V4(_)), ip @ std::net::IpAddr::V4(_)) => {
                SocketAddr::new(ip, c.port())
            }
            _ => *c,
        })
        .filter(reachable)
        .collect()
}

/// [`connect_direct_within`]'s staggered dial of candidates already known dialable.
async fn connect_dialable(
    endpoint: Arc<VoxEndpoint>,
    candidates: Vec<SocketAddr>,
    expected_peer: Digest32,
    now_secs: u64,
    per_attempt: Duration,
) -> Result<VoxConnection> {
    // Each attempt carries the address it was for, so a failure can name it. Flattening
    // every candidate to one message hid, for a long time, the difference between "nothing
    // is listening there" and "something answered but was not the peer we expected" — the
    // two failures a person would act on in completely opposite ways (ADR-018 §8b).
    let mut set: JoinSet<(SocketAddr, Result<VoxConnection>)> = JoinSet::new();
    let mut next = 0usize;
    let mut why: Vec<String> = Vec::with_capacity(candidates.len());

    loop {
        // Nothing in flight: launch the next candidate at once — there is nothing to
        // stagger behind. (Waiting on an empty set returns immediately, and a loop
        // that re-armed the stagger timer around that would spin, hot, forever: the
        // defect the M15.1 gate caught when an attempt failed faster than the timer.)
        if set.is_empty() {
            if next >= candidates.len() {
                return Err(exhausted(&why));
            }
            spawn_attempt(
                &mut set,
                &endpoint,
                candidates[next],
                expected_peer,
                now_secs,
                per_attempt,
            );
            next += 1;
            continue;
        }
        if next < candidates.len() {
            // Race a staggered launch of the next candidate against completion of
            // any in-flight attempt (RFC 8305 staggered start).
            tokio::select! {
                () = tokio::time::sleep(CONNECTION_ATTEMPT_DELAY) => {
                    spawn_attempt(&mut set, &endpoint, candidates[next], expected_peer, now_secs, per_attempt);
                    next += 1;
                }
                joined = set.join_next() => {
                    match take_success(joined) {
                        Ok(conn) => return Ok(conn), // JoinSet drop cancels the rest
                        Err(Some(reason)) => why.push(reason),
                        Err(None) => {}
                    }
                }
            }
        } else {
            // All candidates launched: drain remaining attempts.
            match set.join_next().await {
                Some(joined) => match take_success(Some(joined)) {
                    Ok(conn) => return Ok(conn),
                    Err(Some(reason)) => why.push(reason),
                    Err(None) => {}
                },
                None => return Err(exhausted(&why)),
            }
        }
    }
}

/// Whether a UDP socket bound to `local` can send a datagram to `to` at all: the address
/// family and the scope of the bound address both decide it.
///
/// - The IPv6 wildcard (`[::]`) is dual-stack: it reaches IPv6 and, as IPv4-mapped addresses,
///   IPv4. The IPv4 wildcard reaches IPv4.
/// - A socket bound to a particular IPv6 address is IPv6 only: an IPv4-mapped destination is
///   refused by the kernel.
/// - A loopback-bound socket reaches loopback only, and a link-local-bound IPv6 socket reaches
///   its link only: the source address has no route anywhere else.
#[must_use]
pub fn can_send_to(local: SocketAddr, to: SocketAddr) -> bool {
    match local.ip() {
        // An IPv4 socket cannot address an IPv6 destination, mapped or not: the caller turns a
        // mapped candidate into plain IPv4 before asking.
        IpAddr::V4(l) => to.is_ipv4() && (!l.is_loopback() || to.ip().is_loopback()),
        IpAddr::V6(l) if l.is_unspecified() => true,
        IpAddr::V6(l) => match to {
            SocketAddr::V4(_) => false,
            SocketAddr::V6(t) => {
                t.ip().to_ipv4_mapped().is_none()
                    && (!l.is_loopback() || t.ip().is_loopback())
                    && (!l.is_unicast_link_local() || t.ip().is_unicast_link_local())
            }
        },
    }
}

/// Spawn one staggered QUIC connection attempt onto `set`.
fn spawn_attempt(
    set: &mut JoinSet<(SocketAddr, Result<VoxConnection>)>,
    endpoint: &Arc<VoxEndpoint>,
    addr: SocketAddr,
    expected_peer: Digest32,
    now_secs: u64,
    per_attempt: Duration,
) {
    let ep = Arc::clone(endpoint);
    set.spawn(async move {
        let outcome = match tokio::time::timeout(
            per_attempt,
            ep.connect(addr, expected_peer, now_secs),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Err(Error::Unreachable("direct attempt timed out")),
        };
        (addr, outcome)
    });
}

/// Interpret a `JoinSet::join_next` result: `Some(connection)` on a successful,
/// authenticated attempt; `None` if the attempt failed, timed out, or its task
/// panicked/was cancelled (the caller keeps draining the set).
fn take_success(
    joined: Option<
        std::result::Result<(SocketAddr, Result<VoxConnection>), tokio::task::JoinError>,
    >,
) -> std::result::Result<VoxConnection, Option<String>> {
    match joined {
        Some(Ok((_, Ok(conn)))) => Ok(conn),
        // A failure names the address it was for: see the note on the `JoinSet` above.
        Some(Ok((addr, Err(e)))) => Err(Some(format!("{addr}: {e}"))),
        // A panicked or cancelled attempt is not a candidate's verdict, so it contributes
        // nothing to the reason — but it must not be read as a success either.
        Some(Err(_)) | None => Err(None),
    }
}

/// The error for "every candidate was tried and none connected", carrying each one's
/// verdict. Ordered so the same failure reads the same way between runs.
fn exhausted(why: &[String]) -> Error {
    if why.is_empty() {
        return Error::Unreachable("all direct candidates failed");
    }
    let mut sorted = why.to_vec();
    sorted.sort();
    Error::LadderExhausted(sorted.join(", "))
}
