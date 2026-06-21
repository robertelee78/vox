//! NAT-PMP message codec (RFC 6886) — the IPv4 port-mapping fallback rung
//! (ADR-012 step 2 ladder, PCP → NAT-PMP → UPnP).
//!
//! Pure wire encode/decode; the UDP exchange (gateway UDP port 5351, RFC
//! retransmission) lives in [`crate::nat::portmap`]. NAT-PMP is fixed-layout
//! big-endian; this module rejects every malformed or mismatched response rather
//! than guessing, so the port-mapper never claims a mapping the gateway did not
//! grant (ADR-012 "failure is hard").

use std::net::Ipv4Addr;

use super::Protocol;
use crate::error::{Error, Result};

/// The NAT-PMP / PCP gateway UDP port (RFC 6886 §3.2.1).
pub const NATPMP_PORT: u16 = 5351;

/// The NAT-PMP version byte (RFC 6886 §3.2).
const VERSION: u8 = 0;

/// Opcode: request the external IPv4 address (RFC 6886 §3.2).
const OP_EXTERNAL_ADDR: u8 = 0;
/// Opcode: map a UDP port (RFC 6886 §3.3).
const OP_MAP_UDP: u8 = 1;
/// Opcode: map a TCP port (RFC 6886 §3.3).
const OP_MAP_TCP: u8 = 2;
/// Responses set the high bit of the opcode (RFC 6886 §3.3).
const RESPONSE_BIT: u8 = 0x80;

/// The NAT-PMP map opcode for a protocol (RFC 6886 §3.3): UDP = 1, TCP = 2.
fn map_opcode(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::Udp => OP_MAP_UDP,
        Protocol::Tcp => OP_MAP_TCP,
    }
}

/// Translate a NAT-PMP result code into the appropriate hard error (RFC 6886 §3.5).
/// Result `0` is success and returns `Ok(())`.
fn check_result(code: u16) -> Result<()> {
    match code {
        0 => Ok(()),
        1 => Err(Error::PortMappingFailed("nat-pmp: unsupported version")),
        2 => Err(Error::PortMappingFailed("nat-pmp: not authorized/refused")),
        3 => Err(Error::PortMappingFailed("nat-pmp: network failure")),
        4 => Err(Error::PortMappingFailed("nat-pmp: out of resources")),
        5 => Err(Error::PortMappingFailed("nat-pmp: unsupported opcode")),
        _ => Err(Error::PortMappingFailed("nat-pmp: unknown result code")),
    }
}

/// The gateway's reported external IPv4 address (RFC 6886 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalAddr {
    /// The external IPv4 address the gateway presents to the Internet.
    pub addr: Ipv4Addr,
    /// The gateway's seconds-since-start epoch (RFC 6886 §3.2) — a reset detects a
    /// gateway reboot that may have dropped mappings.
    pub epoch_secs: u32,
}

/// Encode the 2-byte external-address request (RFC 6886 §3.2).
#[must_use]
pub fn encode_external_addr_request() -> [u8; 2] {
    [VERSION, OP_EXTERNAL_ADDR]
}

/// Parse a 12-byte external-address response (RFC 6886 §3.2). Validates the
/// version, the response opcode, and the result code before reading the address.
pub fn parse_external_addr_response(buf: &[u8]) -> Result<ExternalAddr> {
    if buf.len() != 12 {
        return Err(Error::PortMappingFailed(
            "nat-pmp: bad external-addr length",
        ));
    }
    if buf[0] != VERSION {
        return Err(Error::PortMappingFailed("nat-pmp: bad version"));
    }
    if buf[1] != OP_EXTERNAL_ADDR | RESPONSE_BIT {
        return Err(Error::PortMappingFailed(
            "nat-pmp: bad external-addr opcode",
        ));
    }
    check_result(u16::from_be_bytes([buf[2], buf[3]]))?;
    let epoch_secs = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let addr = Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]);
    Ok(ExternalAddr { addr, epoch_secs })
}

/// A granted port mapping (RFC 6886 §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    /// The internal (host) port the mapping forwards to.
    pub internal_port: u16,
    /// The external port the gateway assigned (may differ from the suggestion).
    pub external_port: u16,
    /// The mapping lifetime the gateway granted, in seconds (may be shorter than
    /// requested; the caller must renew before it elapses).
    pub lifetime_secs: u32,
}

/// Encode a 12-byte map request (RFC 6886 §3.3).
///
/// `suggested_external_port` of `0` lets the gateway choose; `lifetime_secs` of `0`
/// deletes the mapping (RFC 6886 §3.4) — callers wanting a mapping pass a positive
/// lifetime.
#[must_use]
pub fn encode_map_request(
    protocol: Protocol,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = VERSION;
    out[1] = map_opcode(protocol);
    // out[2..4] reserved = 0.
    out[4..6].copy_from_slice(&internal_port.to_be_bytes());
    out[6..8].copy_from_slice(&suggested_external_port.to_be_bytes());
    out[8..12].copy_from_slice(&lifetime_secs.to_be_bytes());
    out
}

/// Parse a 16-byte map response (RFC 6886 §3.3).
///
/// Validates the version, the response opcode for `protocol`, the result code, and
/// that the echoed internal port matches `expected_internal_port` — a mismatch is a
/// response for a different request and is rejected (never silently accepted).
pub fn parse_map_response(
    buf: &[u8],
    protocol: Protocol,
    expected_internal_port: u16,
) -> Result<Mapping> {
    if buf.len() != 16 {
        return Err(Error::PortMappingFailed("nat-pmp: bad map-response length"));
    }
    if buf[0] != VERSION {
        return Err(Error::PortMappingFailed("nat-pmp: bad version"));
    }
    if buf[1] != map_opcode(protocol) | RESPONSE_BIT {
        return Err(Error::PortMappingFailed("nat-pmp: bad map opcode"));
    }
    check_result(u16::from_be_bytes([buf[2], buf[3]]))?;
    // buf[4..8] = epoch (informational here).
    let internal_port = u16::from_be_bytes([buf[8], buf[9]]);
    if internal_port != expected_internal_port {
        return Err(Error::PortMappingFailed("nat-pmp: internal port mismatch"));
    }
    let external_port = u16::from_be_bytes([buf[10], buf[11]]);
    let lifetime_secs = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    if external_port == 0 {
        return Err(Error::PortMappingFailed("nat-pmp: gateway assigned port 0"));
    }
    Ok(Mapping {
        internal_port,
        external_port,
        lifetime_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid 16-byte map response for tests.
    fn map_response(op: u8, result: u16, internal: u16, external: u16, lifetime: u32) -> Vec<u8> {
        let mut b = vec![VERSION, op];
        b.extend_from_slice(&result.to_be_bytes());
        b.extend_from_slice(&7u32.to_be_bytes()); // epoch
        b.extend_from_slice(&internal.to_be_bytes());
        b.extend_from_slice(&external.to_be_bytes());
        b.extend_from_slice(&lifetime.to_be_bytes());
        b
    }

    #[test]
    fn external_addr_request_is_two_bytes() {
        assert_eq!(encode_external_addr_request(), [0, 0]);
    }

    #[test]
    fn external_addr_response_round_trips() {
        let mut b = vec![VERSION, OP_EXTERNAL_ADDR | RESPONSE_BIT, 0, 0];
        b.extend_from_slice(&42u32.to_be_bytes());
        b.extend_from_slice(&[203, 0, 113, 7]);
        let got = parse_external_addr_response(&b).unwrap();
        assert_eq!(got.addr, Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(got.epoch_secs, 42);
    }

    #[test]
    fn map_request_layout_is_rfc6886() {
        let req = encode_map_request(Protocol::Udp, 0x1234, 0x5678, 7200);
        assert_eq!(req[0], 0); // version
        assert_eq!(req[1], 1); // UDP opcode
        assert_eq!(&req[4..6], &[0x12, 0x34]); // internal port BE
        assert_eq!(&req[6..8], &[0x56, 0x78]); // suggested external BE
        assert_eq!(&req[8..12], &7200u32.to_be_bytes());
    }

    #[test]
    fn map_response_success_parses() {
        let resp = map_response(OP_MAP_UDP | RESPONSE_BIT, 0, 4433, 51820, 3600);
        let m = parse_map_response(&resp, Protocol::Udp, 4433).unwrap();
        assert_eq!(m.external_port, 51820);
        assert_eq!(m.lifetime_secs, 3600);
    }

    #[test]
    fn map_response_error_code_maps_to_hard_error() {
        let resp = map_response(OP_MAP_UDP | RESPONSE_BIT, 2, 4433, 0, 0);
        assert!(matches!(
            parse_map_response(&resp, Protocol::Udp, 4433),
            Err(Error::PortMappingFailed(_))
        ));
    }

    #[test]
    fn map_response_internal_port_mismatch_is_rejected() {
        let resp = map_response(OP_MAP_UDP | RESPONSE_BIT, 0, 9999, 51820, 3600);
        assert!(matches!(
            parse_map_response(&resp, Protocol::Udp, 4433),
            Err(Error::PortMappingFailed(_))
        ));
    }

    #[test]
    fn map_response_wrong_opcode_is_rejected() {
        // A TCP response to a UDP request is rejected.
        let resp = map_response(OP_MAP_TCP | RESPONSE_BIT, 0, 4433, 51820, 3600);
        assert!(matches!(
            parse_map_response(&resp, Protocol::Udp, 4433),
            Err(Error::PortMappingFailed(_))
        ));
    }

    #[test]
    fn map_response_zero_external_port_is_rejected() {
        let resp = map_response(OP_MAP_UDP | RESPONSE_BIT, 0, 4433, 0, 3600);
        assert!(matches!(
            parse_map_response(&resp, Protocol::Udp, 4433),
            Err(Error::PortMappingFailed(_))
        ));
    }

    #[test]
    fn truncated_responses_are_rejected() {
        assert!(parse_external_addr_response(&[0, 128, 0]).is_err());
        assert!(parse_map_response(&[0u8; 10], Protocol::Udp, 1).is_err());
    }
}
