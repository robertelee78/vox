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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
}

/// A successfully established port mapping (ADR-012 step 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortMapping {
    /// The external port the gateway assigned.
    pub external_port: u16,
    /// The external IPv4 address, when the gateway reported one (NAT-PMP always;
    /// PCP when the assigned address is IPv4-mapped).
    pub external_ip: Option<Ipv4Addr>,
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
            external_ip: m.external_ipv4(),
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
        external_ip,
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

/// Convenience: build a [`SocketAddr`] for the standard gateway port 5351 from a
/// gateway IP (RFC 6886/6887).
#[must_use]
pub fn gateway_addr(ip: IpAddr) -> SocketAddr {
    SocketAddr::new(ip, natpmp::NATPMP_PORT)
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
            assert_eq!(m.external_ip, Some(Ipv4Addr::new(203, 0, 113, 1)));
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
            assert_eq!(m.external_ip, Some(Ipv4Addr::new(198, 51, 100, 4)));
            handle.await.unwrap();
        });
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
