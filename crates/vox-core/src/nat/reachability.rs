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
use crate::nat::portmap::{gateway_addr, map_port, PortMapping, Protocol};
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
/// `None` when there is no route at all (an offline or sandboxed host), which is not
/// an error: the node still works on loopback and over whatever rungs it does have.
pub async fn local_route_ip() -> Option<IpAddr> {
    // 192.0.2.1 is TEST-NET-1 (RFC 5737): reserved, never routed to a real host, so
    // even a stray packet could not reach anything. Port 9 is discard.
    for probe in ["192.0.2.1:9", "[2001:db8::1]:9"] {
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
                return Some(addr.ip())
            }
            _ => continue,
        }
    }
    None
}

/// The endpoints this node should advertise for a socket bound on `bound_port`, and
/// the port mapping if a gateway granted one.
///
/// This is the **publish side** of the ADR-012 ladder, in the ADR-012 preference
/// order (IPv6 first, then IPv4, so a dialer tries the path needing no translation
/// first):
///
/// 1. the routable address the OS would use ([`local_route_ip`]) — IPv6 needs no
///    mapping at all, which is the ADR's first rung;
/// 2. the **mapped external** address when a gateway grants one over PCP or NAT-PMP
///    ([`map_port`](crate::nat::portmap::map_port)) — the second rung, and the only
///    way an IPv4 node behind NAT is dialable at all;
/// 3. loopback, last, so two profiles on one machine still reach each other.
///
/// Every rung is best-effort: no route, no gateway, or a refusing gateway each just
/// leaves that entry out. A node with no dialable address is not broken — it reaches
/// peers outbound and is reached by hole punching or a relay (the ladder's later
/// rungs), which is the ordinary case for a client inside a private network.
pub async fn advertise_endpoints(bound_port: u16) -> (EndpointList, Option<PortMapping>) {
    let mut addrs: Vec<Multiaddr> = Vec::new();
    let route_ip = local_route_ip().await;
    let mut mapping = None;

    // Rung 1: the routable local address. An IPv6 address goes first (ADR-012).
    match route_ip {
        Some(IpAddr::V6(v6)) => addrs.push(Multiaddr::Ip6(SocketAddrV6::new(v6, bound_port, 0, 0))),
        Some(IpAddr::V4(v4)) => addrs.push(Multiaddr::Ip4(SocketAddrV4::new(v4, bound_port))),
        None => {}
    }

    // Rung 2: ask the gateway to forward our port. Only meaningful for IPv4 (RFC
    // 6886/6887 are IPv4-NAT protocols).
    if let Some(IpAddr::V4(v4)) = route_ip {
        let gateway = gateway_addr(IpAddr::V4(default_gateway_guess(v4)));
        if let Ok(m) = map_port(
            gateway,
            Protocol::Udp,
            bound_port,
            bound_port,
            PORT_MAP_LIFETIME_SECS,
        )
        .await
        {
            if let Some(external) = m.external_ip {
                let mapped = Multiaddr::Ip4(SocketAddrV4::new(external, m.external_port));
                if !addrs.contains(&mapped) {
                    addrs.push(mapped);
                }
            }
            mapping = Some(m);
        }
    }

    // Rung 3: loopback, so two profiles on one machine can still reach each other.
    let loopback = Multiaddr::Ip4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, bound_port));
    if !addrs.contains(&loopback) {
        addrs.push(loopback);
    }
    // `EndpointList::new` caps the count; a truncation here would silently drop the
    // *last* (least preferred) rungs, which is the right direction.
    let list = EndpointList::new(addrs.clone()).unwrap_or_else(|_| {
        addrs.truncate(crate::nat::multiaddr::MAX_ENDPOINTS);
        EndpointList::new(addrs).unwrap_or_default()
    });
    (list, mapping)
}

/// The conventional gateway address for a LAN IPv4: the same /24 with host `.1`.
///
/// Reading the real default route needs a platform-specific call; RFC 6886 §3.2.1
/// itself notes clients commonly assume the gateway is the first host address, and a
/// wrong guess simply fails the rung (the mapping request times out and the node
/// carries on without it). Making this a real route lookup is a documented follow-up.
fn default_gateway_guess(ip: Ipv4Addr) -> Ipv4Addr {
    let o = ip.octets();
    Ipv4Addr::new(o[0], o[1], o[2], 1)
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
    if candidates.is_empty() {
        return Err(Error::Unreachable("no direct candidates"));
    }

    let mut set: JoinSet<Result<VoxConnection>> = JoinSet::new();
    let mut next = 0usize;

    // Launch the first candidate immediately.
    spawn_attempt(
        &mut set,
        &endpoint,
        candidates[next],
        expected_peer,
        now_secs,
    );
    next += 1;

    loop {
        if next < candidates.len() {
            // Race a staggered launch of the next candidate against completion of
            // any in-flight attempt (RFC 8305 staggered start).
            tokio::select! {
                () = tokio::time::sleep(CONNECTION_ATTEMPT_DELAY) => {
                    spawn_attempt(&mut set, &endpoint, candidates[next], expected_peer, now_secs);
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
) {
    let ep = Arc::clone(endpoint);
    set.spawn(async move {
        match tokio::time::timeout(
            PER_ATTEMPT_TIMEOUT,
            ep.connect(addr, expected_peer, now_secs),
        )
        .await
        {
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
        // No gateway answers in a test environment, so this exercises rungs 1 and 3.
        let (list, mapping) = advertise_endpoints(4433).await;
        assert!(
            mapping.is_none(),
            "no gateway should have granted a mapping here"
        );
        let addrs = list.addrs();
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
    fn the_gateway_guess_is_the_first_host_on_the_same_slash_24() {
        assert_eq!(
            default_gateway_guess(Ipv4Addr::new(192, 168, 1, 57)),
            Ipv4Addr::new(192, 168, 1, 1)
        );
        assert_eq!(
            default_gateway_guess(Ipv4Addr::new(10, 3, 4, 200)),
            Ipv4Addr::new(10, 3, 4, 1)
        );
        // The mapping lifetime and the ADR-012 address-record TTL age together.
        assert_eq!(
            u64::from(PORT_MAP_LIFETIME_SECS),
            crate::nat::store::MAX_TTL_SECS
        );
    }
}
