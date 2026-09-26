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
    gateway, gateway_addr, gateway_addr_v6, map_port, open_ipv6_pinhole, PortMapping, Protocol,
};
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
pub async fn advertise_endpoints(bound_port: u16) -> (EndpointList, Vec<PortMapping>) {
    let ips = local_route_ips().await;
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
    let (pinhole, mapped) = tokio::join!(
        async {
            match v6 {
                Some(a) => pinhole_any(a, bound_port).await,
                None => None,
            }
        },
        async {
            match v4 {
                Some(a) => map_port_any(a, bound_port).await,
                None => None,
            }
        },
    );

    let list = compose_endpoints(bound_port, v6, v4, mapped.as_ref());
    (list, pinhole.into_iter().chain(mapped).collect())
}

/// Put the ladder's findings in ADR-012 preference order. Pure: no network, so the
/// ordering is testable without a gateway.
///
/// The IPv6 **pinhole** contributes no address of its own — it makes the address in
/// `v6` reachable through the firewall, which is why an IPv6 node needs no
/// translation — so it is not an input here.
#[must_use]
fn compose_endpoints(
    bound_port: u16,
    v6: Option<Ipv6Addr>,
    v4: Option<Ipv4Addr>,
    mapped: Option<&PortMapping>,
) -> EndpointList {
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
    // Last rung: loopback, so two profiles on one machine can still reach each other.
    let loopback = Multiaddr::Ip4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, bound_port));
    if !addrs.contains(&loopback) {
        addrs.push(loopback);
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
/// default route, then the RFC 7723 anycast address).
async fn pinhole_any(client_ip: Ipv6Addr, port: u16) -> Option<PortMapping> {
    first_success(
        gateway::server_candidates_v6()
            .into_iter()
            .map(|(server, scope)| async move {
                open_ipv6_pinhole(
                    gateway_addr_v6(server, scope),
                    Protocol::Udp,
                    client_ip,
                    port,
                    PORT_MAP_LIFETIME_SECS,
                )
                .await
                .ok()
            }),
    )
    .await
}

/// Ask each candidate gateway to forward `port`, stopping at the first that grants a
/// mapping. Each candidate runs the PCP-then-NAT-PMP ladder of
/// [`map_port`](crate::nat::portmap::map_port); if none grants one, **UPnP-IGD** is
/// tried last (ADR-012 rung 2's full order) — it finds the router by SSDP rather
/// than by address, which is why it is not one of the raced candidates.
async fn map_port_any(client_ip: Ipv4Addr, port: u16) -> Option<PortMapping> {
    let raced = first_success(gateway::server_candidates_v4(client_ip).into_iter().map(
        |server| async move {
            map_port(
                gateway_addr(IpAddr::V4(server)),
                Protocol::Udp,
                port,
                port,
                PORT_MAP_LIFETIME_SECS,
            )
            .await
            .ok()
        },
    ))
    .await;
    if raced.is_some() {
        return raced;
    }
    crate::nat::portmap::map_port_upnp(Protocol::Udp, port, client_ip, PORT_MAP_LIFETIME_SECS)
        .await
        .ok()
}

/// Run every future at once and return the first `Some`, abandoning the rest.
///
/// Candidates are **raced**, not tried in turn: a candidate that is not a PCP server
/// simply never answers, and its full retransmission schedule (~3.75 s) would
/// otherwise be paid before the next one is even asked. Racing bounds a whole rung at
/// one schedule. Two gateways both granting is harmless — the unused grant expires on
/// its own lifetime.
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
            set.abort_all();
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
    let local = endpoint.local_addr().ok();
    let reachable = |c: &SocketAddr| {
        crate::transport::mux::in_circuit_range(*c)
            || match local {
                Some(SocketAddr::V4(_)) => c.is_ipv4(),
                Some(SocketAddr::V6(l)) => c.is_ipv6() || l.ip().is_unspecified(),
                None => true,
            }
    };
    let candidates: Vec<SocketAddr> = candidates.iter().copied().filter(reachable).collect();
    if candidates.is_empty() {
        return Err(Error::Unreachable("no direct candidates"));
    }

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
