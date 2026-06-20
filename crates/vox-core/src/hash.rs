//! SHA-256 hashing and the domain-separated helpers used series-wide.
//!
//! SHA-256 is the series-wide hash (ADR-003 registry) for every `prev_hash`,
//! `payload_hash`, channel ID, content ID, and fingerprint, unless a future
//! suite names otherwise.

use sha2::{Digest, Sha256};

/// Length of a SHA-256 digest in bytes.
pub const DIGEST_LEN: usize = 32;

/// A 32-byte SHA-256 digest.
pub type Digest32 = [u8; DIGEST_LEN];

/// SHA-256 of a single byte slice.
#[must_use]
pub fn sha256(data: &[u8]) -> Digest32 {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// SHA-256 over the concatenation of `parts`, without allocating the joined
/// buffer (parts are absorbed in order).
#[must_use]
pub fn sha256_concat(parts: &[&[u8]]) -> Digest32 {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Domain-separated hash: `SHA-256(domain_ascii ‖ data)`. `domain` is an ASCII
/// label such as a [`crate::wire::StructTag::domain_sep`] value.
#[must_use]
pub fn domain_hash(domain: &str, data: &[u8]) -> Digest32 {
    sha256_concat(&[domain.as_bytes(), data])
}

/// Length of an Ed25519 public key (ADR-002 composite layout).
pub const ED25519_PUB_LEN: usize = 32;
/// Length of an Ed25519 signature (ADR-002 composite layout).
pub const ED25519_SIG_LEN: usize = 64;
/// Length of an ML-DSA-65 public key (ADR-002 composite layout).
pub const ML_DSA_65_PUB_LEN: usize = 1952;
/// Length of an ML-DSA-65 signature (ADR-002 composite layout).
pub const ML_DSA_65_SIG_LEN: usize = 3309;
/// Length of the composite Ed25519+ML-DSA-65 public key (ADR-002):
/// `Ed25519_pub(32) ‖ ML-DSA-65_pub(1952)`.
pub const COMPOSITE_PUB_LEN: usize = ED25519_PUB_LEN + ML_DSA_65_PUB_LEN;
/// Length of the composite Ed25519+ML-DSA-65 signature (ADR-002):
/// `Ed25519_sig(64) ‖ ML-DSA-65_sig(3309)`.
pub const COMPOSITE_SIG_LEN: usize = ED25519_SIG_LEN + ML_DSA_65_SIG_LEN;

/// The human-verifiable identity fingerprint (ADR-002):
/// `SHA-256(Ed25519_pub ‖ ML-DSA_pub)`. Both components are always covered, so
/// the ML-DSA co-key cannot be swapped without changing the fingerprint peers
/// verify.
///
/// The component lengths are fixed by the ADR-002 composite layout, so the
/// concatenation is unambiguous. Taking fixed-size arrays makes that a
/// compile-time guarantee rather than a caller convention.
#[must_use]
pub fn identity_fingerprint(
    ed25519_pub: &[u8; ED25519_PUB_LEN],
    ml_dsa_pub: &[u8; ML_DSA_65_PUB_LEN],
) -> Digest32 {
    sha256_concat(&[&ed25519_pub[..], &ml_dsa_pub[..]])
}

/// A lowercase-hex `Debug` wrapper for byte slices, used so key/fingerprint
/// `Debug` output is a readable hex string instead of a byte-array dump (and so
/// secret-bearing types can render only their public fingerprint).
pub struct Hex<'a>(pub &'a [u8]);

impl core::fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // NIST FIPS 180-4 example: SHA-256("abc").
        let d = sha256(b"abc");
        assert_eq!(
            hex::encode(d),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_empty_vector() {
        let d = sha256(b"");
        assert_eq!(
            hex::encode(d),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn concat_matches_joined() {
        let joined = sha256(b"hello world");
        let parts = sha256_concat(&[b"hello", b" ", b"world"]);
        assert_eq!(joined, parts);
    }

    #[test]
    fn domain_hash_is_prefixed() {
        let manual = sha256_concat(&[b"vox/genesis/v1", b"body"]);
        assert_eq!(domain_hash("vox/genesis/v1", b"body"), manual);
        // Different domains separate identical data.
        assert_ne!(domain_hash("vox/a/v1", b"x"), domain_hash("vox/b/v1", b"x"));
    }

    #[test]
    fn fingerprint_covers_both_components() {
        let ed = [0x11u8; 32];
        let mldsa = [0x22u8; 1952];
        let fp = identity_fingerprint(&ed, &mldsa);
        // Swapping any byte of either component changes the fingerprint.
        let mut mldsa2 = mldsa;
        mldsa2[0] ^= 1;
        assert_ne!(fp, identity_fingerprint(&ed, &mldsa2));
    }
}
