//! The channelID (ADR-005 §"channelID is high-entropy and self-certifying").
//!
//! `channelID = SHA-256(canonical genesis record)`. The genesis record carries a
//! 128-bit random nonce (ADR-007), so the channelID is 256-bit, high-entropy, and
//! bound to exactly one genesis: a cold-joiner fetches genesis from the rendezvous
//! and accepts it only if its hash equals the channelID, so there is one true
//! genesis per channel. Because the channelID is high-entropy, a *fast* KDF
//! ([`mod@crate::join::rendezvous`]) is sufficient to derive the rendezvous address —
//! no memory-hard derivation is needed (ADR-005).
//!
//! ## Boundary: the genesis schema is ADR-007/M6, not here
//! This module deliberately does **not** define the genesis-record struct. M3
//! treats genesis as **opaque, high-entropy, already-canonical** bytes and hashes
//! them. When M6 lands the genesis schema it will produce those canonical bytes
//! (canonical CBOR under a struct tag, ADR-008) and feed them here unchanged. The
//! hash is a pure function of whatever canonical bytes it is given, so the two
//! milestones compose without either reaching into the other.

use crate::hash::{sha256, Digest32};

/// Compute a channelID from the canonical genesis-record bytes:
/// `channelID = SHA-256(genesis_canonical_bytes)` (ADR-005).
///
/// `genesis_canonical_bytes` must be the *canonical* serialization of the genesis
/// record (ADR-008 canonical CBOR). The caller (M6) owns producing those bytes;
/// this function is the fixed, schema-agnostic hash that turns them into the
/// 256-bit self-certifying address. Passing non-canonical bytes would produce a
/// channelID no honest peer derives, which is exactly the self-certifying
/// property: only the one true canonical genesis yields the published channelID.
#[must_use]
pub fn channel_id(genesis_canonical_bytes: &[u8]) -> Digest32 {
    sha256(genesis_canonical_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Encoder;

    /// A representative canonical-CBOR genesis body carrying a 128-bit nonce.
    /// This is **only** a stand-in for the M6 genesis schema (which this module
    /// does not own); it exercises that `channel_id` is a deterministic hash of
    /// whatever canonical bytes it is given. The shape — a CBOR array with a
    /// 16-byte (128-bit) nonce — mirrors ADR-007's "128-bit random nonce".
    fn representative_genesis(nonce: [u8; 16]) -> Vec<u8> {
        let mut e = Encoder::new();
        // [version, nonce] — a minimal canonical body; M6 defines the real one.
        e.array(2).uint(1).bytes(&nonce);
        e.finish()
    }

    #[test]
    fn channel_id_is_sha256_of_genesis_bytes() {
        let g = representative_genesis([0x11; 16]);
        // channelID is exactly SHA-256 of the bytes — no domain prefix, no salt.
        assert_eq!(channel_id(&g), sha256(&g));
        assert_eq!(channel_id(&g).len(), 32);
    }

    #[test]
    fn channel_id_is_deterministic() {
        let g = representative_genesis([0x42; 16]);
        assert_eq!(channel_id(&g), channel_id(&g));
    }

    #[test]
    fn distinct_genesis_nonces_give_distinct_channel_ids() {
        // The 128-bit genesis nonce is what makes each channel's ID unique.
        let a = channel_id(&representative_genesis([1u8; 16]));
        let b = channel_id(&representative_genesis([2u8; 16]));
        assert_ne!(a, b);
    }

    #[test]
    fn single_bit_flip_changes_channel_id() {
        let mut n = [0u8; 16];
        let a = channel_id(&representative_genesis(n));
        n[15] ^= 1;
        let b = channel_id(&representative_genesis(n));
        assert_ne!(a, b);
    }

    #[test]
    fn known_vector_empty_genesis() {
        // Self-certifying property is just SHA-256: lock the empty-input digest so
        // a hash-function swap is caught. (SHA-256("") — the FIPS empty vector.)
        assert_eq!(
            hex::encode(channel_id(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
