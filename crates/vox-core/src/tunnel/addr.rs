//! Identity-derived overlay addressing for the TUN model (ADR-013 §"Addressing &
//! name resolution").
//!
//! Each member's overlay address is a self-certifying /128 derived from its
//! composite identity public key (ADR-002):
//!
//! ```text
//! addr = 0xFD ‖ high-120-bits( SHA-256("vox/ula/v1" ‖ composite_identity_pubkey) )
//! ```
//!
//! This is **Vox-CGA-style** (CGA / Yggdrasil-flavoured), *not* RFC-4193 ULA: there
//! is no 40-bit pseudo-random Global ID + 16-bit subnet structure, so it must not be
//! expected to interoperate with other ULA users sharing a link. Properties:
//! - **Unforgeable**: bound to the key; a peer recomputes and [`verify_addr`]s it
//!   from the claimed identity, so an address cannot be spoofed.
//! - **Allocation-free**: derived, never assigned.
//! - **Collision-negligible**: 120 bits of hash output under the `0xFD` prefix.
//!
//! ## An address grants no reachability
//! Holding (or verifying) a ULA address conveys **zero** ability to reach anything.
//! Tunnel services are dark / default-deny and capability-gated (ADR-013
//! §Authorization, [`crate::tunnel::authz`]); the address is an identifier for the
//! TUN path, not an authorization.

use std::net::Ipv6Addr;

use crate::hash::{domain_hash, Digest32, COMPOSITE_PUB_LEN};

/// The domain-separation label for ULA derivation (ADR-013).
pub const ULA_LABEL: &str = "vox/ula/v1";

/// The fixed high byte of every Vox overlay address (`0xFD`). It sits in the
/// `fd00::/8` space but, per the module docs, is deliberately not RFC-4193-shaped.
pub const ULA_PREFIX_BYTE: u8 = 0xFD;

/// Derive the overlay address for a composite identity public key (ADR-013).
///
/// `addr[0] = 0xFD`; `addr[1..16]` = the high 120 bits (first 15 bytes) of
/// `SHA-256("vox/ula/v1" ‖ pubkey)`.
#[must_use]
pub fn overlay_addr(composite_pubkey: &[u8; COMPOSITE_PUB_LEN]) -> Ipv6Addr {
    let h: Digest32 = domain_hash(ULA_LABEL, composite_pubkey);
    let mut octets = [0u8; 16];
    octets[0] = ULA_PREFIX_BYTE;
    octets[1..16].copy_from_slice(&h[..15]);
    Ipv6Addr::from(octets)
}

/// Verify that `claimed` is the correct overlay address for `composite_pubkey`.
///
/// A peer authenticates an address by recomputing it from the identity it
/// authenticated over the transport (ADR-011) — an address that does not match the
/// key is rejected (self-certifying, no spoofing).
#[must_use]
pub fn verify_addr(claimed: &Ipv6Addr, composite_pubkey: &[u8; COMPOSITE_PUB_LEN]) -> bool {
    // Constant-timeness is unnecessary: both inputs are public (a public key and a
    // public address); the comparison leaks nothing secret.
    *claimed == overlay_addr(composite_pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey(seed: u8) -> [u8; COMPOSITE_PUB_LEN] {
        [seed; COMPOSITE_PUB_LEN]
    }

    #[test]
    fn derivation_matches_spec() {
        let pk = pubkey(7);
        let addr = overlay_addr(&pk);
        let h = domain_hash(ULA_LABEL, &pk);
        let oct = addr.octets();
        assert_eq!(oct[0], 0xFD);
        assert_eq!(&oct[1..16], &h[..15]);
    }

    #[test]
    fn is_deterministic_and_in_fd_space() {
        let pk = pubkey(3);
        assert_eq!(overlay_addr(&pk), overlay_addr(&pk));
        assert_eq!(overlay_addr(&pk).octets()[0], 0xFD);
    }

    #[test]
    fn distinct_keys_distinct_addrs() {
        assert_ne!(overlay_addr(&pubkey(1)), overlay_addr(&pubkey(2)));
    }

    #[test]
    fn verify_accepts_matching_rejects_mismatched() {
        let pk = pubkey(9);
        let addr = overlay_addr(&pk);
        assert!(verify_addr(&addr, &pk));
        // A different key does not verify against this address.
        assert!(!verify_addr(&addr, &pubkey(10)));
        // A tampered address does not verify against the real key.
        let mut bad = addr.octets();
        bad[5] ^= 0xff;
        assert!(!verify_addr(&Ipv6Addr::from(bad), &pk));
    }
}
