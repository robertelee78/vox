//! Automatic IPv4 port-mapping (ADR-012 step 2: "IPv4 automatic port-mapping,
//! fallback ladder PCP → NAT-PMP → UPnP-IGD").
//!
//! This module implements the first two, security-relevant rungs as real UDP
//! clients against the gateway:
//! - [`pcp`] — PCP (RFC 6887), preferred (nonce-authenticated, IPv6-aware).
//! - [`natpmp`] — NAT-PMP (RFC 6886), the fallback for older gateways.
//!
//! [`map_port`] runs the ladder: try PCP; on no-response or an explicit
//! unsupported-version, fall through to NAT-PMP. Each rung uses RFC-style
//! exponential-backoff retransmission so a single dropped datagram does not abort
//! the attempt. A failure on every rung returns [`Error::PortMappingFailed`] — the
//! caller then proceeds down the ADR-012 reachability ladder (hole-punch, relay);
//! the mapper never reports a mapping that does not exist.
//!
//! ## Why UPnP-IGD is intentionally not a rung here
//! ADR-012 names UPnP-IGD as the *last* port-mapping fallback while flagging its
//! security baggage (CallStranger, CVE-2020-12695) and noting "never rely on UPnP
//! for security; many routers ship UPnP disabled." UPnP-IGD is SSDP discovery +
//! SOAP/HTTP control — a large, security-fraught surface for marginal gain over
//! PCP/NAT-PMP. Vox therefore ships PCP + NAT-PMP as the complete, defensible
//! port-mapping ladder (this is a deliberate scoping decision recorded in ADR-012,
//! not an unfinished rung). If a real deployment proves UPnP necessary it becomes
//! its own ADR.
//!
//! ## Gateway address
//! [`map_port`] takes the gateway socket address explicitly so it is fully
//! testable. [`gateway::default_gateway_v4`] discovers it on Linux (the routing
//! table); on other platforms the deployment supplies it (commonly the host's
//! default route, learned by the OS or via config). The protocol works identically
//! given a gateway, regardless of how it was discovered.

pub mod gateway;
pub mod natpmp;
pub mod pcp;
pub mod upnp;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::error::{Error, Result};
use crate::identity::rng::random_array;

/// The transport protocol of a requested mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// UDP — Vox's QUIC substrate (ADR-011). The usual choice.
    Udp,
    /// TCP.
    Tcp,
}

impl Protocol {
    /// The IANA protocol number PCP uses (RFC 6887 §11.1): UDP = 17, TCP = 6.
    #[must_use]
    pub fn pcp_iana(self) -> u8 {
        match self {
            Protocol::Udp => 17,
            Protocol::Tcp => 6,
        }
    }
}

/// Which rung of the ladder produced a mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// PCP (RFC 6887).
    Pcp,
    /// NAT-PMP (RFC 6886).
    NatPmp,
    /// A PCP **IPv6 firewall pinhole** — an identity mapping, translating nothing
    /// (ADR-012 rung 1).
    PcpV6Pinhole,
    /// UPnP-IGD (ADR-012 rung 2's third fallback, ADR-016 M15.1c).
    UpnpIgd,
}

/// A successfully established port mapping (ADR-012 step 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortMapping {
    /// The external port the gateway assigned.
    pub external_port: u16,
    /// The external address the gateway assigned, when it reported one (NAT-PMP
    /// always; PCP when it assigns one). An IPv6 pinhole reports the node's own
    /// address, since nothing is translated.
    pub external_ip: Option<IpAddr>,
    /// The lifetime the gateway granted, in seconds. The caller MUST renew before
    /// this elapses (RFC 6886/6887): re-issue the same request well before expiry.
    pub lifetime_secs: u32,
    /// The internal (host) port that was mapped.
    pub internal_port: u16,
    /// Which protocol rung granted the mapping.
    pub method: Method,
}

/// RFC-style retransmission schedule (RFC 6886 §3.1 / RFC 6887 §8.1.1): start at
/// 250 ms and double, a few times, before giving up on a rung.
const RETRANSMIT_TIMEOUTS_MS: [u64; 4] = [250, 500, 1000, 2000];

/// Send `request` on the connected `socket` and await one datagram, retransmitting
/// on timeout per [`RETRANSMIT_TIMEOUTS_MS`]. Returns the received bytes, or
/// [`Error::PortMappingFailed`] if every attempt times out.
async fn exchange(
    socket: &UdpSocket,
    request: &[u8],
    timeout_ctx: &'static str,
) -> Result<Vec<u8>> {
    let mut buf = [0u8; 1024];
    for &ms in &RETRANSMIT_TIMEOUTS_MS {
        socket
            .send(request)
            .await
            .map_err(|_| Error::PortMappingFailed("port-map: send failed"))?;
        match tokio::time::timeout(Duration::from_millis(ms), socket.recv(&mut buf)).await {
            Ok(Ok(n)) => return Ok(buf[..n].to_vec()),
            // A recv error (e.g. ICMP port-unreachable surfaced as an error on a
            // connected UDP socket) means this rung is unavailable — stop retrying.
            Ok(Err(_)) => return Err(Error::PortMappingFailed(timeout_ctx)),
            // Timeout: retransmit (the loop).
            Err(_) => {}
        }
    }
    Err(Error::PortMappingFailed(timeout_ctx))
}

/// The PCP rung: returns `Ok(Some(mapping))` on success, `Ok(None)` on *any* PCP
/// failure (so the caller falls through to NAT-PMP), or `Err` only if the mapping
/// nonce could not be generated.
async fn try_pcp(
    socket: &UdpSocket,
    protocol: Protocol,
    client_ip: Ipv4Addr,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
) -> Result<Option<PortMapping>> {
    let nonce: [u8; pcp::NONCE_LEN] = random_array()?;
    let req = pcp::encode_map_request(
        &nonce,
        protocol,
        client_ip,
        internal_port,
        suggested_external_port,
        lifetime_secs,
    );
    let Ok(resp) = exchange(socket, &req, "pcp: no response").await else {
        return Ok(None);
    };
    match pcp::parse_map_response(&resp, &nonce, protocol, internal_port) {
        // A SUCCESS with a zero lifetime is not a live mapping (it is the delete
        // confirmation form); for a create request it is a phantom — fall through
        // to NAT-PMP rather than report a mapping that does not exist.
        Ok(m) if m.lifetime_secs == 0 => Ok(None),
        Ok(m) => Ok(Some(PortMapping {
            external_port: m.external_port,
            external_ip: m.external_ipv4().map(IpAddr::V4),
            lifetime_secs: m.lifetime_secs,
            internal_port,
            method: Method::Pcp,
        })),
        Err(_) => Ok(None),
    }
}

/// Attempt to map `internal_port` on `gateway`, running the PCP → NAT-PMP ladder.
///
/// `suggested_external_port` of `0` lets the gateway choose. `lifetime_secs` is the
/// requested mapping lifetime (the gateway may grant less; renew before expiry).
/// On success returns the established [`PortMapping`]; if both rungs fail, returns
/// [`Error::PortMappingFailed`].
pub async fn map_port(
    gateway: SocketAddr,
    protocol: Protocol,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
) -> Result<PortMapping> {
    // Bind an ephemeral local UDP socket and connect it to the gateway so the OS
    // selects the source address (the PCP client IP) and recv only yields gateway
    // datagrams.
    let bind: SocketAddr = (Ipv4Addr::UNSPECIFIED, 0).into();
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|_| Error::PortMappingFailed("port-map: socket bind failed"))?;
    socket
        .connect(gateway)
        .await
        .map_err(|_| Error::PortMappingFailed("port-map: connect failed"))?;
    let client_ip = match socket.local_addr() {
        Ok(SocketAddr::V4(v4)) => *v4.ip(),
        // The link to an IPv4 gateway should yield a V4 source; if not, PCP's
        // client-IP field has no IPv4 form, so fall straight to NAT-PMP.
        _ => Ipv4Addr::UNSPECIFIED,
    };

    // Rung 1: PCP. Any PCP failure (no response, unsupported version, error result,
    // malformed/forged reply) falls through to NAT-PMP — only a *successful* mapping
    // short-circuits.
    if let Some(m) = try_pcp(
        &socket,
        protocol,
        client_ip,
        internal_port,
        suggested_external_port,
        lifetime_secs,
    )
    .await?
    {
        return Ok(m);
    }

    // Rung 2: NAT-PMP (older gateways that ignore PCP).
    let pmp_req = natpmp::encode_map_request(
        protocol,
        internal_port,
        suggested_external_port,
        lifetime_secs,
    );
    let resp = exchange(&socket, &pmp_req, "nat-pmp: no response").await?;
    let m = natpmp::parse_map_response(&resp, protocol, internal_port)?;
    // A zero-lifetime SUCCESS is not a live mapping for a create request — reject it
    // rather than report a phantom mapping (ADR-012 "failure is hard").
    if m.lifetime_secs == 0 {
        return Err(Error::PortMappingFailed("nat-pmp: zero-lifetime mapping"));
    }
    // Best-effort external-address query (informational; failure does not void the
    // mapping the gateway already granted).
    let external_ip = query_external_v4(&socket).await;
    Ok(PortMapping {
        external_port: m.external_port,
        external_ip: external_ip.map(IpAddr::V4),
        lifetime_secs: m.lifetime_secs,
        internal_port,
        method: Method::NatPmp,
    })
}

/// Best-effort NAT-PMP external-address query; returns `None` on any failure (it is
/// purely informational — the mapping stands regardless).
async fn query_external_v4(socket: &UdpSocket) -> Option<Ipv4Addr> {
    let req = natpmp::encode_external_addr_request();
    let resp = exchange(socket, &req, "nat-pmp: external addr")
        .await
        .ok()?;
    natpmp::parse_external_addr_response(&resp)
        .ok()
        .map(|e| e.addr)
}

/// Map `port` through a UPnP Internet Gateway Device found by SSDP (ADR-012 rung 2's
/// third fallback). `client_ip` is this node's address on the LAN, which the router
/// forwards to. A lifetime of `0` in the result means the router granted only a
/// permanent mapping; the caller deletes it when done ([`unmap_port_upnp`]).
pub async fn map_port_upnp(
    protocol: Protocol,
    port: u16,
    client_ip: Ipv4Addr,
    lifetime_secs: u32,
) -> Result<PortMapping> {
    let gw = upnp::discover(client_ip, upnp::SSDP_MULTICAST, upnp::SSDP_TIMEOUT).await?;
    let granted =
        upnp::add_port_mapping(&gw, protocol, port, port, client_ip, lifetime_secs).await?;
    let external = upnp::get_external_ip(&gw).await?;
    Ok(PortMapping {
        external_port: port,
        external_ip: Some(IpAddr::V4(external)),
        lifetime_secs: granted,
        internal_port: port,
        method: Method::UpnpIgd,
    })
}

/// Remove a mapping [`map_port_upnp`] added. Best-effort: the gateway is found again
/// by SSDP (from whichever interface the OS routes multicast on), which costs a search.
pub async fn unmap_port_upnp(protocol: Protocol, port: u16) -> Result<()> {
    let gw = upnp::discover(
        Ipv4Addr::UNSPECIFIED,
        upnp::SSDP_MULTICAST,
        upnp::SSDP_TIMEOUT,
    )
    .await?;
    upnp::delete_port_mapping(&gw, protocol, port).await
}

/// Open an **IPv6 firewall pinhole** for `port` via PCP (ADR-012 rung 1).
///
/// On IPv6 nothing is translated: the node's address is already globally routable and
/// what stands in the way is a stateful firewall, so this asks the PCP server for an
/// *identity* mapping — same port, same address — and the address a peer dials is the
/// node's own IPv6. There is no NAT-PMP fallback: RFC 6886 is IPv4-only.
///
/// `client_ip` must be the node's address on the link to `gateway`.
pub async fn open_ipv6_pinhole(
    gateway: SocketAddr,
    protocol: Protocol,
    client_ip: Ipv6Addr,
    port: u16,
    lifetime_secs: u32,
) -> Result<PortMapping> {
    if !gateway.is_ipv6() {
        return Err(Error::PortMappingFailed("pinhole: gateway is not IPv6"));
    }
    let bind: SocketAddr = (Ipv6Addr::UNSPECIFIED, 0).into();
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|_| Error::PortMappingFailed("pinhole: socket bind failed"))?;
    socket
        .connect(gateway)
        .await
        .map_err(|_| Error::PortMappingFailed("pinhole: connect failed"))?;
    let nonce: [u8; pcp::NONCE_LEN] = random_array()?;
    let request = pcp::encode_map_request_pinhole(&nonce, protocol, client_ip, port, lifetime_secs);
    let resp = exchange(&socket, &request, "pinhole: no response").await?;
    let m = pcp::parse_map_response(&resp, &nonce, protocol, port)?;
    if m.lifetime_secs == 0 {
        // A zero lifetime is a delete confirmation, not a live pinhole.
        return Err(Error::PortMappingFailed("pinhole: zero lifetime"));
    }
    if m.external_ipv4().is_some() {
        // An IPv4-mapped external address answers a question this rung did not ask:
        // the pinhole is for the node's own IPv6 address.
        return Err(Error::PortMappingFailed(
            "pinhole: gateway answered with IPv4",
        ));
    }
    Ok(PortMapping {
        external_port: m.external_port,
        external_ip: Some(IpAddr::V6(m.external_ip)),
        lifetime_secs: m.lifetime_secs,
        internal_port: port,
        method: Method::PcpV6Pinhole,
    })
}

/// Convenience: build a [`SocketAddr`] for the standard gateway port 5351 from a
/// gateway IP (RFC 6886/6887).
#[must_use]
pub fn gateway_addr(ip: IpAddr) -> SocketAddr {
    SocketAddr::new(ip, natpmp::NATPMP_PORT)
}

/// The same for an IPv6 server that may be **link-local**: a link-local address is
/// meaningless without the interface to send it on, which is the `scope` (the kernel
/// interface index, as [`gateway::server_candidates_v6`] supplies it).
#[must_use]
pub fn gateway_addr_v6(ip: Ipv6Addr, scope: u32) -> SocketAddr {
    SocketAddr::V6(std::net::SocketAddrV6::new(
        ip,
        natpmp::NATPMP_PORT,
        0,
        scope,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// A gateway that ignores the first datagram (PCP probe) and answers the second
    /// (NAT-PMP) — exercises the ladder fallthrough.
    async fn mock_gateway_natpmp_only(
        natpmp_response: Vec<u8>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            // Answer the first (PCP) request with a deliberately-unparseable reply
            // so the PCP rung fails fast and the client falls through to NAT-PMP.
            let (_, peer0) = sock.recv_from(&mut buf).await.unwrap();
            sock.send_to(&[0xFFu8, 0x00, 0x00, 0x00], peer0)
                .await
                .unwrap();
            // Answer the NAT-PMP map request, then the external-address query.
            let (_, peer) = sock.recv_from(&mut buf).await.unwrap();
            sock.send_to(&natpmp_response, peer).await.unwrap();
            // External-addr query → reply.
            if let Ok((_, peer2)) = sock.recv_from(&mut buf).await {
                let mut ext = vec![0u8, 128, 0, 0];
                ext.extend_from_slice(&1u32.to_be_bytes());
                ext.extend_from_slice(&[203, 0, 113, 1]);
                let _ = sock.send_to(&ext, peer2).await;
            }
        });
        (addr, handle)
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn natpmp_fallback_succeeds_when_pcp_silent() {
        let rt = rt();
        rt.block_on(async {
            // NAT-PMP UDP map response: op 0x81, result 0, internal 4433, ext 51820.
            let mut resp = vec![0u8, 0x81, 0, 0];
            resp.extend_from_slice(&5u32.to_be_bytes()); // epoch
            resp.extend_from_slice(&4433u16.to_be_bytes());
            resp.extend_from_slice(&51820u16.to_be_bytes());
            resp.extend_from_slice(&3600u32.to_be_bytes());
            let (addr, handle) = mock_gateway_natpmp_only(resp).await;
            let m = map_port(addr, Protocol::Udp, 4433, 0, 3600).await.unwrap();
            assert_eq!(m.method, Method::NatPmp);
            assert_eq!(m.external_port, 51820);
            assert_eq!(
                m.external_ip,
                Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)))
            );
            handle.await.unwrap();
        });
    }

    #[test]
    fn zero_lifetime_success_is_not_a_phantom_mapping() {
        let rt = rt();
        rt.block_on(async {
            // NAT-PMP SUCCESS but lifetime 0 → no live mapping → hard failure.
            let mut resp = vec![0u8, 0x81, 0, 0];
            resp.extend_from_slice(&5u32.to_be_bytes()); // epoch
            resp.extend_from_slice(&4433u16.to_be_bytes());
            resp.extend_from_slice(&51820u16.to_be_bytes());
            resp.extend_from_slice(&0u32.to_be_bytes()); // lifetime 0
            let (addr, handle) = mock_gateway_natpmp_only(resp).await;
            let res = map_port(addr, Protocol::Udp, 4433, 0, 3600).await;
            assert!(matches!(res, Err(Error::PortMappingFailed(_))));
            // On the zero-lifetime error path `map_port` returns before issuing the
            // external-address query, so the mock is still blocked on its third
            // recv — abort it rather than await (which would hang).
            handle.abort();
        });
    }

    #[test]
    fn pcp_map_succeeds_over_loopback() {
        let rt = rt();
        rt.block_on(async {
            // A PCP-aware mock: echo the request's nonce so parse succeeds. It must
            // read the request to learn the nonce, then build a matching response.
            let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let addr = sock.local_addr().unwrap();
            let handle = tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
                assert_eq!(n, pcp::MAP_MESSAGE_LEN, "PCP request length");
                let req = &buf[..n];
                let nonce = &req[24..36];
                let internal = u16::from_be_bytes([req[40], req[41]]);
                // Build a success MAP response echoing nonce + internal port.
                let mut resp = vec![0u8; pcp::MAP_MESSAGE_LEN];
                resp[0] = pcp::PCP_VERSION;
                resp[1] = 0x81; // R=1 | MAP
                resp[3] = 0; // SUCCESS
                resp[4..8].copy_from_slice(&7200u32.to_be_bytes());
                resp[24..36].copy_from_slice(nonce);
                resp[36] = 17; // UDP
                resp[40..42].copy_from_slice(&internal.to_be_bytes());
                resp[42..44].copy_from_slice(&62000u16.to_be_bytes());
                resp[44..60]
                    .copy_from_slice(&Ipv4Addr::new(198, 51, 100, 4).to_ipv6_mapped().octets());
                sock.send_to(&resp, peer).await.unwrap();
            });
            let m = map_port(addr, Protocol::Udp, 4433, 0, 7200).await.unwrap();
            assert_eq!(m.method, Method::Pcp);
            assert_eq!(m.external_port, 62000);
            assert_eq!(
                m.external_ip,
                Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)))
            );
            handle.await.unwrap();
        });
    }

    /// A PCP server on IPv6 loopback that echoes one MAP request as a firewall
    /// pinhole would: same internal port, and `external_ip` taken from the request's
    /// own client-address field (`override_external` replaces it, to exercise a
    /// gateway that answers the wrong family).
    async fn mock_pcp_v6(
        lifetime: u32,
        override_external: Option<[u8; 16]>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, pcp::MAP_MESSAGE_LEN, "PCP request length");
            let req = &buf[..n];
            let mut client = [0u8; 16];
            client.copy_from_slice(&req[8..24]);
            let mut resp = vec![0u8; pcp::MAP_MESSAGE_LEN];
            resp[0] = pcp::PCP_VERSION;
            resp[1] = 0x81; // R=1 | MAP
            resp[3] = 0; // SUCCESS
            resp[4..8].copy_from_slice(&lifetime.to_be_bytes());
            resp[24..36].copy_from_slice(&req[24..36]); // echo the nonce
            resp[36] = req[36]; // echo the protocol
            resp[40..44].copy_from_slice(&req[40..44]); // internal == external port
            resp[44..60].copy_from_slice(&override_external.unwrap_or(client));
            sock.send_to(&resp, peer).await.unwrap();
        });
        (addr, handle)
    }

    #[test]
    fn ipv6_pinhole_is_an_identity_mapping_of_our_own_address() {
        let rt = rt();
        rt.block_on(async {
            let me: Ipv6Addr = "2001:db8::5".parse().unwrap();
            let (addr, handle) = mock_pcp_v6(7200, None).await;
            let m = open_ipv6_pinhole(addr, Protocol::Udp, me, 4433, 7200)
                .await
                .unwrap();
            assert_eq!(m.method, Method::PcpV6Pinhole);
            // Nothing is translated: the port and address a peer dials are ours.
            assert_eq!(m.internal_port, 4433);
            assert_eq!(m.external_port, 4433);
            assert_eq!(m.external_ip, Some(IpAddr::V6(me)));
            assert_eq!(m.lifetime_secs, 7200);
            handle.await.unwrap();
        });
    }

    #[test]
    fn a_pinhole_answered_with_ipv4_or_no_lifetime_is_not_a_pinhole() {
        let rt = rt();
        rt.block_on(async {
            let me: Ipv6Addr = "2001:db8::5".parse().unwrap();
            // A v4-mapped external address answers a question this rung did not ask.
            let v4_mapped = Ipv4Addr::new(198, 51, 100, 4).to_ipv6_mapped().octets();
            let (addr, handle) = mock_pcp_v6(7200, Some(v4_mapped)).await;
            let err = open_ipv6_pinhole(addr, Protocol::Udp, me, 4433, 7200)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::PortMappingFailed(_)));
            handle.await.unwrap();
            // SUCCESS with a zero lifetime is a deletion, not a live pinhole.
            let (addr, handle) = mock_pcp_v6(0, None).await;
            let err = open_ipv6_pinhole(addr, Protocol::Udp, me, 4433, 7200)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::PortMappingFailed(_)));
            handle.await.unwrap();
        });
    }

    #[test]
    fn a_pinhole_needs_an_ipv6_server_and_carries_the_scope() {
        let rt = rt();
        rt.block_on(async {
            let me: Ipv6Addr = "2001:db8::5".parse().unwrap();
            // An IPv4 gateway cannot hold an IPv6 pinhole: refused before any packet.
            let err = open_ipv6_pinhole(
                gateway_addr(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Protocol::Udp,
                me,
                4433,
                7200,
            )
            .await
            .unwrap_err();
            assert!(matches!(err, Error::PortMappingFailed(_)));
        });
        // A link-local server is only meaningful with the interface to send it on.
        let scoped = gateway_addr_v6("fe80::1".parse().unwrap(), 7);
        match scoped {
            SocketAddr::V6(s) => {
                assert_eq!(s.scope_id(), 7);
                assert_eq!(s.port(), 5351);
            }
            SocketAddr::V4(_) => panic!("v6 address built as v4"),
        }
    }

    #[test]
    fn both_rungs_silent_fails_hard() {
        let rt = rt();
        rt.block_on(async {
            // A gateway socket that never answers: bind it and drop nothing — the
            // client should exhaust both rungs' retransmits and fail. Use a port
            // with no listener.
            let dead = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let addr = dead.local_addr().unwrap();
            drop(dead); // free the port so datagrams are unanswered
                        // Shorten the wait by relying on the schedule; this still takes a few
                        // seconds total across both rungs, acceptable for a single hard-path test.
            let err = map_port(addr, Protocol::Udp, 4433, 0, 60)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::PortMappingFailed(_)));
        });
    }

    #[test]
    fn gateway_addr_uses_standard_port() {
        let a = gateway_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(a.port(), 5351);
    }
}
