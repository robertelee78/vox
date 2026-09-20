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
    // an IPv6 destination on an IPv4 socket outright (and maps IPv4 onto an IPv6
    // one, so the reverse is fine). Dropping them here is what keeps a dual-stack
    // peer's IPv6 entries from costing an IPv4-bound node anything.
    let local_v6 = endpoint.local_addr().is_ok_and(|a| a.is_ipv6());
    let candidates: Vec<SocketAddr> = candidates
        .iter()
        .copied()
        .filter(|c| local_v6 || c.is_ipv4())
        .collect();
    if candidates.is_empty() {
        return Err(Error::Unreachable("no direct candidates"));
    }

    let mut set: JoinSet<Result<VoxConnection>> = JoinSet::new();
    let mut next = 0usize;

    loop {
        // Nothing in flight: launch the next candidate at once — there is nothing to
        // stagger behind. (Waiting on an empty set returns immediately, and a loop
        // that re-armed the stagger timer around that would spin, hot, forever: the
        // defect the M15.1 gate caught when an attempt failed faster than the timer.)
        if set.is_empty() {
            if next >= candidates.len() {
                return Err(Error::Unreachable("all direct candidates failed"));
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
                    if let Some(conn) = take_success(joined) {
                        return Ok(conn); // JoinSet drop cancels the rest
                    }
                }
            }
        } else {
            // All candidates launched: drain remaining attempts.
            match set.join_next().await {
                Some(joined) => {
                    if let Some(conn) = take_success(Some(joined)) {
                        return Ok(conn);
                    }
                }
                None => return Err(Error::Unreachable("all direct candidates failed")),
            }
        }
    }
}

/// Spawn one staggered QUIC connection attempt onto `set`.
fn spawn_attempt(
    set: &mut JoinSet<Result<VoxConnection>>,
    endpoint: &Arc<VoxEndpoint>,
    addr: SocketAddr,
    expected_peer: Digest32,
    now_secs: u64,
    per_attempt: Duration,
) {
    let ep = Arc::clone(endpoint);
    set.spawn(async move {
        match tokio::time::timeout(per_attempt, ep.connect(addr, expected_peer, now_secs)).await {
            Ok(res) => res,
            Err(_) => Err(Error::Unreachable("direct attempt timed out")),
        }
    });
}

/// Interpret a `JoinSet::join_next` result: `Some(connection)` on a successful,
/// authenticated attempt; `None` if the attempt failed, timed out, or its task
/// panicked/was cancelled (the caller keeps draining the set).
fn take_success(
    joined: Option<std::result::Result<Result<VoxConnection>, tokio::task::JoinError>>,
) -> Option<VoxConnection> {
    match joined {
        Some(Ok(Ok(conn))) => Some(conn),
        // Connect error, timeout, or a join error (panic/cancel): not a success.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;
    use crate::nat::multiaddr::Multiaddr;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::runtime::Runtime;

    fn rt() -> Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    #[test]
    fn direct_candidates_order_v6_first() {
        let list = EndpointList::new(vec![
            Multiaddr::Ip4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1)),
            Multiaddr::Ip6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::LOCALHOST,
                2,
                0,
                0,
            )),
            Multiaddr::Relay([0u8; 32]),
        ])
        .unwrap();
        let cand = direct_candidates(&list);
        assert_eq!(cand.len(), 2, "relay excluded from direct candidates");
        assert!(cand[0].is_ipv6());
    }

    #[test]
    fn empty_candidates_is_unreachable() {
        let rt = rt();
        rt.block_on(async {
            let server = signer(9, 9);
            let ep = Arc::new(VoxEndpoint::bind(&server, loopback(0)).unwrap());
            let res = connect_direct(ep, &[], [0u8; 32], 1000).await;
            assert!(matches!(res, Err(Error::Unreachable(_))));
        });
    }

    #[test]
    fn races_past_a_dead_candidate_to_the_live_one() {
        let rt = rt();
        rt.block_on(async {
            // Real server endpoint with an accept loop.
            let server_signer = signer(1, 2);
            let server = Arc::new(VoxEndpoint::bind(&server_signer, loopback(0)).unwrap());
            let server_addr = server.local_addr().unwrap();
            let server_id = server.local_id();
            let accept_server = Arc::clone(&server);
            tokio::spawn(async move {
                // Accept a couple of connections (the live candidate).
                for _ in 0..2 {
                    if (accept_server.accept(1000).await).is_err() {
                        break;
                    }
                }
            });

            // A dead candidate: an address with no listener. Bind+drop to obtain a
            // free port that will refuse/blackhole.
            let dead = {
                let s = tokio::net::UdpSocket::bind(loopback(0)).await.unwrap();
                let a = s.local_addr().unwrap();
                drop(s);
                a
            };

            let client_signer = signer(3, 4);
            let client = Arc::new(VoxEndpoint::bind(&client_signer, loopback(0)).unwrap());
            // Dead candidate first, live second: Happy-Eyeballs must still succeed.
            let candidates = vec![dead, server_addr];
            let conn = tokio::time::timeout(
                Duration::from_secs(15),
                connect_direct(client, &candidates, server_id, 1000),
            )
            .await
            .expect("did not hang")
            .expect("connects to the live candidate");
            assert_eq!(conn.peer_id(), server_id);
        });
    }

    #[test]
    fn all_dead_candidates_is_unreachable() {
        let rt = rt();
        rt.block_on(async {
            let dead1 = {
                let s = tokio::net::UdpSocket::bind(loopback(0)).await.unwrap();
                let a = s.local_addr().unwrap();
                drop(s);
                a
            };
            let client_signer = signer(3, 4);
            let client = Arc::new(VoxEndpoint::bind(&client_signer, loopback(0)).unwrap());
            // One unreachable candidate; pin a random expected peer it can never be.
            let res = tokio::time::timeout(
                Duration::from_secs(15),
                connect_direct(client, &[dead1], [7u8; 32], 1000),
            )
            .await
            .expect("did not hang");
            assert!(matches!(res, Err(Error::Unreachable(_))));
        });
    }
    /// An attempt that fails faster than the stagger timer used to leave the loop
    /// waiting on an empty set — which returns at once — and re-arming a fresh timer
    /// each time round: a hot spin that starved the runtime. An IPv6 candidate on an
    /// IPv4 socket is exactly such an attempt.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fast_failing_candidate_does_not_spin_and_ipv6_is_skipped_on_ipv4() {
        let server_signer = signer(5, 6);
        let server = VoxEndpoint::bind(&server_signer, loopback(0)).unwrap();
        let live = server.local_addr().unwrap();
        let server_id = server.local_id();
        let accept = tokio::spawn(async move { server.accept(1000).await });
        let client = Arc::new(VoxEndpoint::bind(&signer(7, 8), loopback(0)).unwrap());
        // IPv6 first (unaddressable from an IPv4 socket), then the live one.
        let v6: SocketAddr = "[2001:db8::1]:4433".parse().unwrap();
        let started = std::time::Instant::now();
        let conn = tokio::time::timeout(
            Duration::from_secs(15),
            connect_direct(Arc::clone(&client), &[v6, live], server_id, 1000),
        )
        .await
        .expect("did not spin")
        .expect("the live candidate connects");
        assert_eq!(conn.peer_id(), server_id);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the IPv6 candidate cost nothing: {:?}",
            started.elapsed()
        );
        let _ = accept.await;
        // Only unaddressable candidates: an immediate, honest failure.
        let res = tokio::time::timeout(
            Duration::from_secs(5),
            connect_direct(client, &[v6], server_id, 1000),
        )
        .await
        .expect("did not spin");
        assert!(matches!(res, Err(Error::Unreachable(_))));
    }

    #[tokio::test]
    async fn the_route_probe_never_sends_and_yields_a_usable_or_absent_address() {
        // Whatever the host's networking looks like, the probe must not panic, must
        // not block, and must never claim the wildcard or loopback as this node's
        // address — publishing either would advertise a destination nobody can dial.
        let ip = local_route_ip().await;
        if let Some(ip) = ip {
            assert!(!ip.is_unspecified(), "{ip} is the wildcard");
            assert!(!ip.is_loopback(), "{ip} is loopback");
        }
    }

    #[tokio::test]
    async fn advertised_endpoints_are_ordered_and_always_include_loopback() {
        // Live: whether a gateway answers depends on the machine this runs on, so the
        // assertions are the invariants that hold either way.
        let (list, mappings) = advertise_endpoints(4433).await;
        let addrs = list.addrs();
        for m in &mappings {
            // A granted mapping must be reflected in what we advertise: a pinhole by
            // the IPv6 address it opened, a NAT mapping by its external address.
            if let Some(external) = m.external_ip {
                assert!(
                    addrs.iter().any(|a| match a {
                        Multiaddr::Ip4(s) => IpAddr::V4(*s.ip()) == external,
                        Multiaddr::Ip6(s) => IpAddr::V6(*s.ip()) == external,
                        Multiaddr::Relay(_) => false,
                    }),
                    "granted {m:?} is not advertised in {addrs:?}"
                );
            }
        }
        assert!(!addrs.is_empty());
        // Every entry carries the port we bound.
        for a in addrs {
            match a {
                Multiaddr::Ip4(s) => assert_eq!(s.port(), 4433),
                Multiaddr::Ip6(s) => assert_eq!(s.port(), 4433),
                Multiaddr::Relay(_) => panic!("no relay hint is advertised here"),
            }
        }
        // Loopback is present and last: two profiles on one machine still reach each
        // other, but a dialer tries a real address first.
        let loopback = Multiaddr::Ip4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4433));
        assert_eq!(addrs.last(), Some(&loopback));
        // IPv6 first when there is one (ADR-012 prefers the path needing no NAT).
        if addrs.iter().any(|a| matches!(a, Multiaddr::Ip6(_))) {
            assert!(matches!(addrs[0], Multiaddr::Ip6(_)), "{addrs:?}");
        }
        // No duplicates: a dialer would waste an attempt on each.
        let mut seen = std::collections::HashSet::new();
        for a in addrs {
            assert!(seen.insert(format!("{a}")), "duplicate {a}");
        }
    }

    #[test]
    fn composition_puts_ipv6_first_the_mapped_address_next_and_loopback_last() {
        let v6: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let v4 = Ipv4Addr::new(192, 168, 1, 50);
        let mapped = PortMapping {
            internal_port: 4433,
            external_port: 62000,
            external_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
            lifetime_secs: 7200,
            method: crate::nat::portmap::Method::Pcp,
        };
        let list = compose_endpoints(4433, Some(v6), Some(v4), Some(&mapped));
        assert_eq!(
            list.addrs(),
            &[
                Multiaddr::Ip6(SocketAddrV6::new(v6, 4433, 0, 0)),
                Multiaddr::Ip4(SocketAddrV4::new(v4, 4433)),
                Multiaddr::Ip4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 62000)),
                Multiaddr::Ip4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4433)),
            ]
        );

        // No route at all: loopback alone, so two profiles on one machine still talk.
        let bare = compose_endpoints(4433, None, None, None);
        assert_eq!(
            bare.addrs(),
            &[Multiaddr::Ip4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4433))]
        );

        // An identity mapping (the IPv6 pinhole's shape, were it passed as a mapping)
        // adds nothing: the address is already advertised.
        let identity = PortMapping {
            internal_port: 4433,
            external_port: 4433,
            external_ip: Some(IpAddr::V6(v6)),
            lifetime_secs: 7200,
            method: crate::nat::portmap::Method::PcpV6Pinhole,
        };
        let deduped = compose_endpoints(4433, Some(v6), None, Some(&identity));
        assert_eq!(
            deduped.addrs(),
            &[
                Multiaddr::Ip6(SocketAddrV6::new(v6, 4433, 0, 0)),
                Multiaddr::Ip4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4433)),
            ]
        );
    }

    #[tokio::test]
    async fn the_route_probe_returns_at_most_one_address_per_family_ipv6_first() {
        let ips = local_route_ips().await;
        assert!(ips.len() <= 2, "{ips:?}");
        assert_eq!(
            ips.iter().filter(|ip| ip.is_ipv6()).count(),
            ips.iter().filter(|ip| ip.is_ipv6()).count().min(1)
        );
        // IPv6 first when present (ADR-012 prefers the path needing no translation),
        // and `local_route_ip` is that same preference applied.
        if ips.len() == 2 {
            assert!(ips[0].is_ipv6() && ips[1].is_ipv4(), "{ips:?}");
        }
        assert_eq!(local_route_ip().await, ips.first().copied());
    }

    #[test]
    fn the_mapping_lifetime_matches_the_record_ttl() {
        // The mapping lifetime and the ADR-012 address-record TTL age together.
        assert_eq!(
            u64::from(PORT_MAP_LIFETIME_SECS),
            crate::nat::store::MAX_TTL_SECS
        );
    }
}
