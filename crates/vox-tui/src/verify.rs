//! Key verification primitives (ADR-015 §"Verification ceremony"): the pinned
//! safety-code derivation and the verification QR payload.
//!
//! These are the security-critical, client-agnostic parts of the ceremony: two
//! independent clients (this TUI and the ADR-014 macOS client) MUST derive the
//! identical safety code for the same pair of identities, and the QR a peer scans
//! MUST decode to exactly the displaying party's composite identity. Everything
//! here is pure and deterministic so it is exhaustively testable and so the two
//! clients provably agree.

use vox_core::cbor::{Decoder, Encoder};
use vox_core::error::{Error, Result};
use vox_core::hash::{sha256_concat, COMPOSITE_PUB_LEN};
use vox_core::identity::composite::CompositePublicKey;

/// Domain-separation label for the safety code (ADR-015, pinned).
pub const SAFETY_LABEL: &str = "vox/safety/v1";

/// Number of 5-digit groups in a safety code (8 groups → 40 decimal digits, one
/// per 4-byte window of the SHA-256 output: ~133 bits of manual-compare strength).
pub const SAFETY_GROUPS: usize = 8;

/// Domain label for the verification QR payload (its own ADR-008-style framing).
pub const VERIFY_QR_LABEL: &str = "vox/verify-qr/v1";

/// Order two composite public keys by ascending byte representation, returning
/// `(lo, hi)`. Pinning the order makes the safety code symmetric — both parties
/// feed the same `(lo, hi)` regardless of who displays.
fn ordered_bytes(
    a: &CompositePublicKey,
    b: &CompositePublicKey,
) -> ([u8; COMPOSITE_PUB_LEN], [u8; COMPOSITE_PUB_LEN]) {
    let (ab, bb) = (a.to_bytes(), b.to_bytes());
    if ab <= bb {
        (ab, bb)
    } else {
        (bb, ab)
    }
}

/// Derive the grouped-decimal safety code for the pair `(a, b)` (ADR-015, pinned):
/// `SHA-256("vox/safety/v1" ‖ pk_lo ‖ pk_hi)`, then [`SAFETY_GROUPS`] groups of 5
/// decimal digits, each the big-endian `u32` of a 4-byte window mod 100000.
///
/// Symmetric in its arguments (uses ascending byte order), so both parties compute
/// the same string. Rendered as space-separated zero-padded groups, e.g.
/// `"01234 56789 ..."`.
#[must_use]
pub fn safety_code(a: &CompositePublicKey, b: &CompositePublicKey) -> String {
    let (lo, hi) = ordered_bytes(a, b);
    let h = sha256_concat(&[SAFETY_LABEL.as_bytes(), &lo, &hi]);
    let mut groups = Vec::with_capacity(SAFETY_GROUPS);
    for i in 0..SAFETY_GROUPS {
        let w = u32::from_be_bytes([h[i * 4], h[i * 4 + 1], h[i * 4 + 2], h[i * 4 + 3]]);
        groups.push(format!("{:05}", w % 100_000));
    }
    groups.join(" ")
}

/// Encode the verification QR payload for `displayer`: a canonical-CBOR record
/// `[label, composite_pubkey]` (ADR-008 framing-style). The peer scans this, decodes
/// it, and recomputes the safety code against its own identity.
#[must_use]
pub fn encode_verify_payload(displayer: &CompositePublicKey) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(2)
        .text(VERIFY_QR_LABEL)
        .bytes(&displayer.to_bytes());
    e.finish()
}

/// Strictly decode a verification QR payload into the displaying party's composite
/// public key. Rejects a wrong label, wrong arity, wrong-length key, or trailing
/// bytes — so a malformed/foreign QR cannot be mistaken for a valid identity.
pub fn decode_verify_payload(bytes: &[u8]) -> Result<CompositePublicKey> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedBundle("verify-qr arity"));
    }
    if d.text()? != VERIFY_QR_LABEL {
        return Err(Error::MalformedBundle("verify-qr label"));
    }
    let pk: [u8; COMPOSITE_PUB_LEN] = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle("verify-qr pubkey length"))?;
    d.finish()?;
    CompositePublicKey::from_bytes(&pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vox_core::identity::composite::{RootSigner, SoftwareRootSigner};

    fn key(a: u8, b: u8) -> CompositePublicKey {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32])
            .unwrap()
            .public_key()
    }

    #[test]
    fn safety_code_is_symmetric() {
        let (x, y) = (key(1, 2), key(3, 4));
        assert_eq!(
            safety_code(&x, &y),
            safety_code(&y, &x),
            "order-independent"
        );
    }

    #[test]
    fn safety_code_format_is_grouped_decimal() {
        let code = safety_code(&key(1, 2), &key(3, 4));
        let groups: Vec<&str> = code.split(' ').collect();
        assert_eq!(groups.len(), SAFETY_GROUPS);
        for g in groups {
            assert_eq!(g.len(), 5, "5-digit groups");
            assert!(g.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn different_pairs_differ() {
        assert_ne!(
            safety_code(&key(1, 2), &key(3, 4)),
            safety_code(&key(1, 2), &key(5, 6))
        );
    }

    #[test]
    fn safety_code_matches_pinned_derivation() {
        // Recompute independently from the spec to pin the construction.
        let (a, b) = (key(7, 7), key(9, 9));
        let (lo, hi) = ordered_bytes(&a, &b);
        let h = sha256_concat(&[SAFETY_LABEL.as_bytes(), &lo, &hi]);
        let expected: Vec<String> = (0..SAFETY_GROUPS)
            .map(|i| {
                let w = u32::from_be_bytes([h[i * 4], h[i * 4 + 1], h[i * 4 + 2], h[i * 4 + 3]]);
                format!("{:05}", w % 100_000)
            })
            .collect();
        assert_eq!(safety_code(&a, &b), expected.join(" "));
    }

    #[test]
    fn verify_payload_round_trips() {
        let k = key(2, 3);
        let payload = encode_verify_payload(&k);
        assert_eq!(decode_verify_payload(&payload).unwrap(), k);
    }

    #[test]
    fn verify_payload_rejects_tamper_and_wrong_label() {
        let k = key(2, 3);
        let mut payload = encode_verify_payload(&k);
        // Truncated → rejected.
        assert!(decode_verify_payload(&payload[..payload.len() - 1]).is_err());
        // Flip a byte in the key region → length still ok but key may be invalid or
        // simply different; decode must still be strict about structure.
        let n = payload.len();
        payload[n - 1] ^= 0xff;
        // Either it fails to parse as a valid composite key, or it parses to a
        // different key — never silently to `k`.
        if let Ok(other) = decode_verify_payload(&payload) {
            assert_ne!(other, k);
        }
    }

    #[test]
    fn wrong_label_is_rejected() {
        let mut e = Encoder::new();
        e.array(2)
            .text("vox/not-verify/v1")
            .bytes(&key(1, 1).to_bytes());
        assert!(decode_verify_payload(&e.finish()).is_err());
    }
}
