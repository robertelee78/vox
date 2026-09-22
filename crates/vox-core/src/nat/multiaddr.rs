//! Endpoint addressing for rendezvous records (ADR-012 §"Rendezvous").
//!
//! A [`Multiaddr`] is one reachable address a peer advertises: an IPv6 socket, an
//! IPv4 socket, or a **relay hint** (the identity fingerprint of a node willing to
//! relay to the advertiser). An [`EndpointList`] is the ordered, capped set a peer
//! publishes — "only the addresses needed for the reachability ladder" (ADR-012,
//! endpoint-minimized).
//!
//! ## Why a Vox-specific type and not `std::net::SocketAddr`
//! Rendezvous endpoints must also express the relay-of-last-resort rung (ADR-012
//! step 4), which is not an IP socket at all but a *peer identity*. A single
//! enum keeps the reachability ladder (IPv6 → IPv4 → relay) expressible in one
//! ordered list, and gives a canonical, strictly-decoded CBOR encoding that a
//! poisoner cannot smuggle ambiguity through (ADR-012: readers reject malformed
//! records).
//!
//! ## Canonical encoding
//! Each address is a CBOR array led by a 1-byte kind discriminant:
//! - IPv6: `[kind=2, addr(16 bytes), port]`
//! - IPv4: `[kind=1, addr(4 bytes), port]`
//! - Relay: `[kind=3, relay_fingerprint(32 bytes)]`
//!
//! Ports are CBOR uints validated to fit `u16`. The kind discriminant is checked
//! against the closed set; an unknown kind is a hard parse error (no silent skip).

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;

/// The CBOR kind discriminant for an IPv4 socket address.
const KIND_IP4: u64 = 1;
/// The CBOR kind discriminant for an IPv6 socket address.
const KIND_IP6: u64 = 2;
/// The CBOR kind discriminant for a relay hint.
const KIND_RELAY: u64 = 3;

/// The maximum number of addresses one [`EndpointList`] may carry (ADR-012
/// "endpoint-minimized": a member advertises only what the ladder needs). A small
/// hard cap bounds record size before any per-element allocation and keeps a
/// poisoned record from ballooning a reader's memory.
pub const MAX_ENDPOINTS: usize = 8;

/// One advertised reachable address (ADR-012 multiaddr).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Multiaddr {
    /// An IPv6 socket — tried first (ADR-012 step 1: IPv6 direct, no translation).
    Ip6(SocketAddrV6),
    /// An IPv4 socket — tried after IPv6 (ADR-012 step 2: IPv4 + port-mapping).
    Ip4(SocketAddrV4),
    /// A relay hint: the composite-identity fingerprint of a node that will relay
    /// to the advertiser (ADR-012 step 4: relay of last resort via the user's own
    /// node). The dialer reaches that node — learned via the same rendezvous /
    /// bootstrap set — and requests relaying to the advertiser.
    Relay(Digest32),
}

impl Multiaddr {
    /// `true` if this is a directly-dialable IP socket (IPv6 or IPv4), as opposed
    /// to a relay hint.
    #[must_use]
    pub fn is_direct(&self) -> bool {
        matches!(self, Multiaddr::Ip6(_) | Multiaddr::Ip4(_))
    }

    /// The directly-dialable [`SocketAddr`], if this is an IP endpoint; `None` for
    /// a relay hint.
    #[must_use]
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Multiaddr::Ip6(s) => Some(SocketAddr::V6(*s)),
            Multiaddr::Ip4(s) => Some(SocketAddr::V4(*s)),
            Multiaddr::Relay(_) => None,
        }
    }

    /// The relay node's identity fingerprint, if this is a relay hint.
    #[must_use]
    pub fn relay_target(&self) -> Option<Digest32> {
        match self {
            Multiaddr::Relay(fpr) => Some(*fpr),
            _ => None,
        }
    }

    /// Encode this address into an in-progress CBOR stream.
    pub(crate) fn encode_into(&self, e: &mut Encoder) {
        match self {
            Multiaddr::Ip6(s) => {
                e.array(3)
                    .uint(KIND_IP6)
                    .bytes(&s.ip().octets())
                    .uint(u64::from(s.port()));
            }
            Multiaddr::Ip4(s) => {
                e.array(3)
                    .uint(KIND_IP4)
                    .bytes(&s.ip().octets())
                    .uint(u64::from(s.port()));
            }
            Multiaddr::Relay(fpr) => {
                e.array(2).uint(KIND_RELAY).bytes(fpr);
            }
        }
    }

    /// Decode one address from an in-progress CBOR stream (strict).
    pub(crate) fn decode_from(d: &mut Decoder<'_>) -> Result<Self> {
        let arity = d.array()?;
        let kind = d.uint()?;
        match (kind, arity) {
            (KIND_IP6, 3) => {
                let octets: [u8; 16] = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedRendezvous("multiaddr ipv6 length"))?;
                let port = decode_port(d)?;
                Ok(Multiaddr::Ip6(SocketAddrV6::new(
                    Ipv6Addr::from(octets),
                    port,
                    0,
                    0,
                )))
            }
            (KIND_IP4, 3) => {
                let octets: [u8; 4] = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedRendezvous("multiaddr ipv4 length"))?;
                let port = decode_port(d)?;
                Ok(Multiaddr::Ip4(SocketAddrV4::new(
                    Ipv4Addr::from(octets),
                    port,
                )))
            }
            (KIND_RELAY, 2) => {
                let fpr: Digest32 = d.bytes()?.try_into().map_err(|_| {
                    Error::MalformedRendezvous("multiaddr relay fingerprint length")
                })?;
                Ok(Multiaddr::Relay(fpr))
            }
            (KIND_IP6 | KIND_IP4 | KIND_RELAY, _) => {
                Err(Error::MalformedRendezvous("multiaddr arity"))
            }
            _ => Err(Error::MalformedRendezvous("multiaddr unknown kind")),
        }
    }
}

/// Decode a CBOR uint into a `u16` port (rejects values that do not fit).
fn decode_port(d: &mut Decoder<'_>) -> Result<u16> {
    let raw = d.uint()?;
    u16::try_from(raw).map_err(|_| Error::MalformedRendezvous("multiaddr port out of range"))
}

impl From<SocketAddr> for Multiaddr {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V6(s) => Multiaddr::Ip6(s),
            // Normalize the scope/flowinfo away on V4 (none exist).
            SocketAddr::V4(s) => Multiaddr::Ip4(s),
        }
    }
}

impl Multiaddr {
    /// Parse the text form [`Display`](fmt::Display) produces: `/ip6/<addr>/udp/<port>`,
    /// `/ip4/<addr>/udp/<port>` or `/relay/<64 hex chars>`.
    ///
    /// Strict: an unknown protocol, a missing or extra segment, a malformed address
    /// or port, or a relay fingerprint that is not exactly 32 hex-encoded bytes is
    /// [`Error::MalformedRendezvous`]. This is the form the ADR-016 invite link
    /// carries, so it must round-trip exactly.
    pub fn parse(text: &str) -> Result<Self> {
        let parts: Vec<&str> = text.split('/').collect();
        // A leading '/' yields an empty first element.
        match parts.as_slice() {
            ["", "ip6", addr, "udp", port] => {
                let ip: Ipv6Addr = addr
                    .parse()
                    .map_err(|_| Error::MalformedRendezvous("multiaddr ip6 address"))?;
                let port: u16 = port
                    .parse()
                    .map_err(|_| Error::MalformedRendezvous("multiaddr port"))?;
                Ok(Multiaddr::Ip6(SocketAddrV6::new(ip, port, 0, 0)))
            }
            ["", "ip4", addr, "udp", port] => {
                let ip: Ipv4Addr = addr
                    .parse()
                    .map_err(|_| Error::MalformedRendezvous("multiaddr ip4 address"))?;
                let port: u16 = port
                    .parse()
                    .map_err(|_| Error::MalformedRendezvous("multiaddr port"))?;
                Ok(Multiaddr::Ip4(SocketAddrV4::new(ip, port)))
            }
            ["", "relay", hex] => {
                if hex.len() != 64 {
                    return Err(Error::MalformedRendezvous("multiaddr relay length"));
                }
                let mut out = [0u8; 32];
                for (i, byte) in out.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                        .map_err(|_| Error::MalformedRendezvous("multiaddr relay hex"))?;
                }
                Ok(Multiaddr::Relay(out))
            }
            _ => Err(Error::MalformedRendezvous("multiaddr form")),
        }
    }
}

impl fmt::Display for Multiaddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Multiaddr::Ip6(s) => write!(f, "/ip6/{}/udp/{}", s.ip(), s.port()),
            Multiaddr::Ip4(s) => write!(f, "/ip4/{}/udp/{}", s.ip(), s.port()),
            Multiaddr::Relay(fpr) => {
                write!(f, "/relay/")?;
                for b in fpr {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }
    }
}

/// An ordered, capped list of advertised endpoints (ADR-012). Order is meaningful:
/// it is the advertiser's preference for the reachability ladder (IPv6 first), and
/// it is preserved byte-for-byte through the canonical encoding so a record's
/// signed bytes are stable.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EndpointList {
    addrs: Vec<Multiaddr>,
}

impl EndpointList {
    /// Build from an ordered slice of addresses. Rejects an over-cap list
    /// ([`MAX_ENDPOINTS`]) — endpoint-minimization is enforced at construction so
    /// an over-large list can never be signed and published.
    pub fn new(addrs: Vec<Multiaddr>) -> Result<Self> {
        if addrs.len() > MAX_ENDPOINTS {
            return Err(Error::SizeLimitExceeded("rendezvous endpoint list"));
        }
        Ok(Self { addrs })
    }

    /// The advertised addresses, in preference order.
    #[must_use]
    pub fn addrs(&self) -> &[Multiaddr] {
        &self.addrs
    }

    /// `true` if the list carries no addresses.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    /// The number of advertised addresses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    /// The directly-dialable IP endpoints, in preference order (IPv6 before IPv4,
    /// preserving the advertiser's ordering within each family). This is the
    /// Happy-Eyeballs-friendly candidate order the reachability ladder consumes
    /// (ADR-012 step 1–2).
    ///
    /// **A circuit address is never a direct candidate.** Vox derives a circuit's address
    /// from the far peer's fingerprint into `240.0.0.0/4` (`transport::mux`), so such an
    /// address is an overlay handle one node's mux can interpret and no datagram can reach.
    /// One used to arrive here whenever a peer had learned its "observed" address over a
    /// relayed path and advertised it, and each one then consumed a full
    /// `PER_ATTEMPT_TIMEOUT` before failing — sometimes as the *only* candidate for a peer,
    /// which is what made a cross-process join fail about 40% of the time and take 250s.
    ///
    /// **The source is not yet fixed.** `node::network` answers `WHOAMI` with the
    /// connection's remote address, and over a relayed path that is a circuit address — so a
    /// peer reached through a relay learns a circuit address as its own reflexive address and
    /// advertises it. The fix for that is a protocol behaviour change (a relayed path must
    /// answer no `WHOAMI`) and is written but **not landed**, because it could not be shown
    /// to change the observed failure rate and the reachability ladder is not a place to land
    /// unproven changes. See ADR-012.
    ///
    /// This filter lands on its own because it cannot make anything worse: it removes
    /// candidates that provably cannot be reached by a datagram, each of which otherwise
    /// costs a full `PER_ATTEMPT_TIMEOUT`.
    /// Loopback and private addresses are **kept**: both are legitimately dialable from the
    /// right vantage point, and it is not this function's place to decide which.
    #[must_use]
    pub fn direct_candidates(&self) -> Vec<SocketAddr> {
        let mut v6 = Vec::new();
        let mut v4 = Vec::new();
        for a in &self.addrs {
            match a {
                Multiaddr::Ip6(s) => v6.push(SocketAddr::V6(*s)),
                Multiaddr::Ip4(s) => {
                    let sa = SocketAddr::V4(*s);
                    if !crate::transport::mux::is_circuit_addr(sa) {
                        v4.push(sa);
                    }
                }
                Multiaddr::Relay(_) => {}
            }
        }
        v6.extend(v4);
        v6
    }

    /// The relay hints, in advertised order (ADR-012 step 4 fallback).
    #[must_use]
    pub fn relay_hints(&self) -> Vec<Digest32> {
        self.addrs
            .iter()
            .filter_map(Multiaddr::relay_target)
            .collect()
    }

    /// Encode into an in-progress CBOR stream as a definite-length array.
    pub(crate) fn encode_into(&self, e: &mut Encoder) {
        e.array(self.addrs.len());
        for a in &self.addrs {
            a.encode_into(e);
        }
    }

    /// Decode from an in-progress CBOR stream (strict, cap-checked before any
    /// per-element allocation).
    pub(crate) fn decode_from(d: &mut Decoder<'_>) -> Result<Self> {
        let n = d.array()?;
        if n > MAX_ENDPOINTS {
            return Err(Error::SizeLimitExceeded("rendezvous endpoint list"));
        }
        let mut addrs = Vec::with_capacity(n);
        for _ in 0..n {
            addrs.push(Multiaddr::decode_from(d)?);
        }
        Ok(Self { addrs })
    }
}
