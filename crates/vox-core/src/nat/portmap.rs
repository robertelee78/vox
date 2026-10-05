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
    /// The server that granted it, where a renewal and the deletion go (N-55, N-56): the PCP or
    /// NAT-PMP server's address, or a UPnP router's control address.
    pub server: Option<SocketAddr>,
    /// The PCP mapping nonce it was created with (RFC 6887 §11.1), which every renewal and the
    /// deletion carry (N-55); `None` for NAT-PMP and UPnP, which have none.
    pub nonce: Option<[u8; pcp::NONCE_LEN]>,
    /// The node's routable address it was asked for: a renewal is for the same address only,
    /// and a new address is a new mapping with a new nonce (N-55, N-51).
    pub asked_for: Option<IpAddr>,
}

impl Method {
    /// The rung's name as `vox status` says it (N-54): `PCP`, `NAT-PMP`, `UPnP-IGD`, `pinhole`.
    #[must_use]
    pub fn rung(self) -> &'static str {
        match self {
            Method::Pcp => "PCP",
            Method::NatPmp => "NAT-PMP",
            Method::UpnpIgd => "UPnP-IGD",
            Method::PcpV6Pinhole => "pinhole",
        }
    }
}

/// How long the daemon's stop waits, in all, for its mappings' deletions (N-56).
pub const UNMAP_PATIENCE: Duration = Duration::from_secs(2);

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
    gateway: SocketAddr,
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
            server: Some(gateway),
            nonce: Some(nonce),
            asked_for: None,
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
        gateway,
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
        server: Some(gateway),
        nonce: None,
        asked_for: None,
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
        server: Some(gw.control_host),
        nonce: None,
        asked_for: Some(IpAddr::V4(client_ip)),
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
    let nonce: [u8; pcp::NONCE_LEN] = random_array()?;
    pinhole_with(gateway, protocol, client_ip, port, lifetime_secs, nonce).await
}

/// [`open_ipv6_pinhole`] with the nonce given: a new pinhole's fresh one, or a held pinhole's own
/// for its renewal (N-55).
async fn pinhole_with(
    gateway: SocketAddr,
    protocol: Protocol,
    client_ip: Ipv6Addr,
    port: u16,
    lifetime_secs: u32,
    nonce: [u8; pcp::NONCE_LEN],
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
        server: Some(gateway),
        nonce: Some(nonce),
        asked_for: Some(IpAddr::V6(client_ip)),
    })
}

/// A UDP socket connected to `server`, of its family, so the OS picks the source address and
/// only the server's datagrams are read.
async fn connected(server: SocketAddr) -> Result<UdpSocket> {
    let bind: SocketAddr = if server.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|_| Error::PortMappingFailed("port-map: socket bind failed"))?;
    socket
        .connect(server)
        .await
        .map_err(|_| Error::PortMappingFailed("port-map: connect failed"))?;
    Ok(socket)
}

/// **Renew a held mapping at the server that granted it** (ADR-012 N-55): the same request again,
/// asking for `lifetime_secs`. A PCP mapping and a pinhole carry the nonce they were created
/// with, which a server in RFC 6887's Simple Threat Model requires (§11.3) — a renewal under a
/// fresh nonce is refused `NOT_AUTHORIZED`. Retransmissions are the same bytes, so the same nonce
/// (§8.1.1). NAT-PMP renews by its own request again; a UPnP lease is renewed by a discovery.
///
/// # Errors
/// [`Error::PortMappingFailed`] when the server does not answer, refuses, or grants nothing.
pub async fn renew(held: &PortMapping, lifetime_secs: u32) -> Result<PortMapping> {
    let server = held
        .server
        .ok_or(Error::PortMappingFailed("renew: no server"))?;
    let protocol = Protocol::Udp;
    match held.method {
        Method::Pcp => {
            let nonce = held
                .nonce
                .ok_or(Error::PortMappingFailed("renew: no PCP nonce"))?;
            let socket = connected(server).await?;
            let client_ip = match socket.local_addr() {
                Ok(SocketAddr::V4(v4)) => *v4.ip(),
                _ => Ipv4Addr::UNSPECIFIED,
            };
            let req = pcp::encode_map_request(
                &nonce,
                protocol,
                client_ip,
                held.internal_port,
                held.external_port,
                lifetime_secs,
            );
            let resp = exchange(&socket, &req, "pcp: renewal not answered").await?;
            let m = pcp::parse_map_response(&resp, &nonce, protocol, held.internal_port)?;
            if m.lifetime_secs == 0 {
                return Err(Error::PortMappingFailed("pcp: renewal granted nothing"));
            }
            Ok(PortMapping {
                external_port: m.external_port,
                external_ip: m.external_ipv4().map(IpAddr::V4).or(held.external_ip),
                lifetime_secs: m.lifetime_secs,
                ..*held
            })
        }
        Method::NatPmp => {
            let socket = connected(server).await?;
            let req = natpmp::encode_map_request(
                protocol,
                held.internal_port,
                held.external_port,
                lifetime_secs,
            );
            let resp = exchange(&socket, &req, "nat-pmp: renewal not answered").await?;
            let m = natpmp::parse_map_response(&resp, protocol, held.internal_port)?;
            if m.lifetime_secs == 0 {
                return Err(Error::PortMappingFailed("nat-pmp: renewal granted nothing"));
            }
            Ok(PortMapping {
                external_port: m.external_port,
                lifetime_secs: m.lifetime_secs,
                ..*held
            })
        }
        Method::PcpV6Pinhole => {
            let (Some(nonce), Some(IpAddr::V6(client_ip))) = (held.nonce, held.asked_for) else {
                return Err(Error::PortMappingFailed("renew: pinhole without nonce"));
            };
            pinhole_with(
                server,
                protocol,
                client_ip,
                held.internal_port,
                lifetime_secs,
                nonce,
            )
            .await
        }
        Method::UpnpIgd => Err(Error::PortMappingFailed("renew: UPnP renews by discovery")),
    }
}

/// **Delete a mapping at the server that granted it** (ADR-012 N-56), best-effort: PCP and the
/// IPv6 pinhole by a MAP with lifetime 0 and the mapping's own nonce (RFC 6887 §15.1), NAT-PMP by
/// lifetime 0 and suggested external port 0 (RFC 6886 §3.4), UPnP by `DeletePortMapping`. The
/// request is retransmitted as any other; the caller bounds the whole by [`UNMAP_PATIENCE`].
///
/// # Errors
/// [`Error::PortMappingFailed`] when the server could not be reached or did not answer.
pub async fn unmap(m: &PortMapping) -> Result<()> {
    let protocol = Protocol::Udp;
    let server = m.server;
    match (m.method, server, m.nonce) {
        (Method::Pcp, Some(server), Some(nonce)) => {
            let socket = connected(server).await?;
            let client_ip = match socket.local_addr() {
                Ok(SocketAddr::V4(v4)) => *v4.ip(),
                _ => Ipv4Addr::UNSPECIFIED,
            };
            let req = pcp::encode_map_request(&nonce, protocol, client_ip, m.internal_port, 0, 0);
            exchange(&socket, &req, "pcp: deletion not answered").await?;
            Ok(())
        }
        (Method::PcpV6Pinhole, Some(server), Some(nonce)) => {
            let Some(IpAddr::V6(client_ip)) = m.asked_for else {
                return Err(Error::PortMappingFailed("unmap: pinhole without address"));
            };
            let socket = connected(server).await?;
            let req =
                pcp::encode_map_request_pinhole(&nonce, protocol, client_ip, m.internal_port, 0);
            exchange(&socket, &req, "pinhole: deletion not answered").await?;
            Ok(())
        }
        (Method::NatPmp, Some(server), _) => {
            let socket = connected(server).await?;
            let req = natpmp::encode_map_request(protocol, m.internal_port, 0, 0);
            exchange(&socket, &req, "nat-pmp: deletion not answered").await?;
            Ok(())
        }
        (Method::UpnpIgd, _, _) => unmap_port_upnp(protocol, m.external_port).await,
        _ => Err(Error::PortMappingFailed("unmap: no server or nonce")),
    }
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
