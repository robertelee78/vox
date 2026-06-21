//! PCP (Port Control Protocol, RFC 6887) MAP message codec — the preferred IPv4
//! port-mapping rung (ADR-012 step 2 ladder, PCP → NAT-PMP → UPnP).
//!
//! Pure wire encode/decode; the UDP exchange (gateway UDP port 5351, RFC
//! retransmission) lives in [`crate::nat::portmap`]. PCP is fixed-layout
//! big-endian. The mapping **nonce** is the anti-spoofing handle: the gateway
//! echoes it, and this codec rejects a response whose nonce does not match the
//! request — so an off-path attacker cannot inject a forged mapping (RFC 6887
//! §11.2), and the mapper never claims a mapping the gateway did not grant.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::Protocol;
use crate::error::{Error, Result};

/// The PCP version byte (RFC 6887 §7.1).
pub const PCP_VERSION: u8 = 2;

/// The MAP opcode (RFC 6887 §11).
const OP_MAP: u8 = 1;
/// Responses set the high bit of the opcode byte (RFC 6887 §7.2).
const RESPONSE_BIT: u8 = 0x80;

/// The common-header length (RFC 6887 §7.1).
const HEADER_LEN: usize = 24;
/// The MAP opcode-specific length (RFC 6887 §11.1).
const MAP_BODY_LEN: usize = 36;
/// A full MAP request/response length.
pub const MAP_MESSAGE_LEN: usize = HEADER_LEN + MAP_BODY_LEN;
/// The PCP mapping-nonce length (RFC 6887 §11.1).
pub const NONCE_LEN: usize = 12;

/// Translate a PCP result code into the appropriate hard error (RFC 6887 §7.4).
/// Result `0` (SUCCESS) returns `Ok(())`.
fn check_result(code: u8) -> Result<()> {
    match code {
        0 => Ok(()),
        1 => Err(Error::PortMappingFailed("pcp: unsupported version")),
        2 => Err(Error::PortMappingFailed("pcp: not authorized")),
        3 => Err(Error::PortMappingFailed("pcp: malformed request")),
        4 => Err(Error::PortMappingFailed("pcp: unsupported opcode")),
        5 => Err(Error::PortMappingFailed("pcp: unsupported option")),
        6 => Err(Error::PortMappingFailed("pcp: malformed option")),
        7 => Err(Error::PortMappingFailed("pcp: network failure")),
        8 => Err(Error::PortMappingFailed("pcp: no resources")),
        9 => Err(Error::PortMappingFailed("pcp: unsupported protocol")),
        10 => Err(Error::PortMappingFailed("pcp: user exceeded quota")),
        11 => Err(Error::PortMappingFailed("pcp: cannot provide external")),
        12 => Err(Error::PortMappingFailed("pcp: address mismatch")),
        13 => Err(Error::PortMappingFailed("pcp: excessive remote peers")),
        _ => Err(Error::PortMappingFailed("pcp: unknown result code")),
    }
}

/// Map an IPv4 address to its IPv4-mapped IPv6 form (`::ffff:a.b.c.d`), the
/// representation PCP uses for all address fields (RFC 6887 §5).
fn v4_mapped(addr: Ipv4Addr) -> [u8; 16] {
    addr.to_ipv6_mapped().octets()
}

/// A granted PCP mapping (RFC 6887 §11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    /// The internal (host) port the mapping forwards to.
    pub internal_port: u16,
    /// The external port the gateway assigned.
    pub external_port: u16,
    /// The external IP the gateway assigned. PCP reports it as an IPv6 (possibly
    /// IPv4-mapped) value; preserved verbatim so the caller can recover either.
    pub external_ip: Ipv6Addr,
    /// The granted mapping lifetime in seconds (may be shorter than requested).
    pub lifetime_secs: u32,
}

impl Mapping {
    /// The assigned external address as an IPv4 address, if it is IPv4-mapped.
    #[must_use]
    pub fn external_ipv4(&self) -> Option<Ipv4Addr> {
        self.external_ip.to_ipv4_mapped()
    }
}

/// Encode a PCP MAP request (RFC 6887 §11.1).
///
/// `nonce` is the per-mapping random nonce the gateway must echo (generate it
/// fresh per mapping and keep it for renewals). `client_ip` is the host's address
/// on the link to the gateway (IPv4-mapped). `lifetime_secs` of `0` deletes the
/// mapping. A `suggested_external_port` of `0` lets the gateway choose.
#[must_use]
pub fn encode_map_request(
    nonce: &[u8; NONCE_LEN],
    protocol: Protocol,
    client_ip: Ipv4Addr,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
) -> [u8; MAP_MESSAGE_LEN] {
    let mut out = [0u8; MAP_MESSAGE_LEN];
    // Common header.
    out[0] = PCP_VERSION;
    out[1] = OP_MAP; // R=0 (request) | opcode
                     // out[2..4] reserved = 0.
    out[4..8].copy_from_slice(&lifetime_secs.to_be_bytes());
    out[8..24].copy_from_slice(&v4_mapped(client_ip));
    // MAP opcode body.
    out[24..36].copy_from_slice(nonce);
    out[36] = protocol.pcp_iana();
    // out[37..40] reserved = 0.
    out[40..42].copy_from_slice(&internal_port.to_be_bytes());
    out[42..44].copy_from_slice(&suggested_external_port.to_be_bytes());
    // Suggested external IP "no preference" = all zeros (RFC 6887 §11.1) — left 0.
    out
}

/// Parse a PCP MAP response (RFC 6887 §11.2).
///
/// Validates the version, the MAP response opcode, the result code, the echoed
/// nonce (anti-spoofing), the protocol, and the echoed internal port. Any mismatch
/// is a hard error: the response is for a different request or is forged.
pub fn parse_map_response(
    buf: &[u8],
    expected_nonce: &[u8; NONCE_LEN],
    protocol: Protocol,
    expected_internal_port: u16,
) -> Result<Mapping> {
    if buf.len() != MAP_MESSAGE_LEN {
        return Err(Error::PortMappingFailed("pcp: bad response length"));
    }
    if buf[0] != PCP_VERSION {
        return Err(Error::PortMappingFailed("pcp: bad version"));
    }
    if buf[1] != OP_MAP | RESPONSE_BIT {
        return Err(Error::PortMappingFailed("pcp: bad opcode"));
    }
    check_result(buf[3])?;
    let lifetime_secs = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    // buf[8..12] epoch, buf[12..24] reserved (response).
    if &buf[24..36] != expected_nonce {
        return Err(Error::PortMappingFailed("pcp: nonce mismatch"));
    }
    if buf[36] != protocol.pcp_iana() {
        return Err(Error::PortMappingFailed("pcp: protocol mismatch"));
    }
    let internal_port = u16::from_be_bytes([buf[40], buf[41]]);
    if internal_port != expected_internal_port {
        return Err(Error::PortMappingFailed("pcp: internal port mismatch"));
    }
    let external_port = u16::from_be_bytes([buf[42], buf[43]]);
    if external_port == 0 {
        return Err(Error::PortMappingFailed("pcp: gateway assigned port 0"));
    }
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&buf[44..60]);
    Ok(Mapping {
        internal_port,
        external_port,
        external_ip: Ipv6Addr::from(ip),
        lifetime_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce() -> [u8; NONCE_LEN] {
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    }

    /// Build a MAP response mirroring a request body.
    fn map_response(
        result: u8,
        n: &[u8; NONCE_LEN],
        proto: u8,
        internal: u16,
        external: u16,
        ext_ip: Ipv4Addr,
        lifetime: u32,
    ) -> Vec<u8> {
        let mut b = vec![0u8; MAP_MESSAGE_LEN];
        b[0] = PCP_VERSION;
        b[1] = OP_MAP | RESPONSE_BIT;
        b[3] = result;
        b[4..8].copy_from_slice(&lifetime.to_be_bytes());
        b[24..36].copy_from_slice(n);
        b[36] = proto;
        b[40..42].copy_from_slice(&internal.to_be_bytes());
        b[42..44].copy_from_slice(&external.to_be_bytes());
        b[44..60].copy_from_slice(&v4_mapped(ext_ip));
        b
    }

    #[test]
    fn map_request_layout_is_rfc6887() {
        let req = encode_map_request(
            &nonce(),
            Protocol::Udp,
            Ipv4Addr::new(192, 168, 1, 5),
            0x1234,
            0,
            7200,
        );
        assert_eq!(req.len(), 60);
        assert_eq!(req[0], 2); // version
        assert_eq!(req[1], 1); // R=0 | MAP
        assert_eq!(&req[4..8], &7200u32.to_be_bytes());
        assert_eq!(&req[8..24], &v4_mapped(Ipv4Addr::new(192, 168, 1, 5)));
        assert_eq!(&req[24..36], &nonce());
        assert_eq!(req[36], 17); // UDP IANA
        assert_eq!(&req[40..42], &[0x12, 0x34]);
    }

    #[test]
    fn map_response_success_parses_and_recovers_ipv4() {
        let resp = map_response(
            0,
            &nonce(),
            17,
            4433,
            51820,
            Ipv4Addr::new(203, 0, 113, 9),
            3600,
        );
        let m = parse_map_response(&resp, &nonce(), Protocol::Udp, 4433).unwrap();
        assert_eq!(m.external_port, 51820);
        assert_eq!(m.external_ipv4(), Some(Ipv4Addr::new(203, 0, 113, 9)));
        assert_eq!(m.lifetime_secs, 3600);
    }

    #[test]
    fn nonce_mismatch_is_rejected() {
        let resp = map_response(
            0,
            &[9u8; NONCE_LEN],
            17,
            4433,
            51820,
            Ipv4Addr::LOCALHOST,
            60,
        );
        assert!(matches!(
            parse_map_response(&resp, &nonce(), Protocol::Udp, 4433),
            Err(Error::PortMappingFailed(_))
        ));
    }

    #[test]
    fn result_error_is_rejected() {
        let resp = map_response(8, &nonce(), 17, 4433, 0, Ipv4Addr::LOCALHOST, 0);
        assert!(matches!(
            parse_map_response(&resp, &nonce(), Protocol::Udp, 4433),
            Err(Error::PortMappingFailed(_))
        ));
    }

    #[test]
    fn protocol_mismatch_is_rejected() {
        let resp = map_response(0, &nonce(), 6, 4433, 51820, Ipv4Addr::LOCALHOST, 60);
        assert!(matches!(
            parse_map_response(&resp, &nonce(), Protocol::Udp, 4433),
            Err(Error::PortMappingFailed(_))
        ));
    }

    #[test]
    fn internal_port_mismatch_is_rejected() {
        let resp = map_response(0, &nonce(), 17, 9999, 51820, Ipv4Addr::LOCALHOST, 60);
        assert!(matches!(
            parse_map_response(&resp, &nonce(), Protocol::Udp, 4433),
            Err(Error::PortMappingFailed(_))
        ));
    }

    #[test]
    fn truncated_response_is_rejected() {
        assert!(parse_map_response(&[0u8; 30], &nonce(), Protocol::Udp, 1).is_err());
    }
}
