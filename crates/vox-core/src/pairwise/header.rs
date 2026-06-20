//! Ratchet message header, wire encodings, and the two AEAD associated-data
//! constructions (ADR-004 §Wire format & operational rules).
//!
//! ## Why dedicated domain labels, not ADR-008 struct tags
//! Pairwise PQXDH/ratchet messages are **payloads carried by later milestones**
//! (sent over the transport, ADR-011, or wrapped in log entries by ADR-006/008),
//! not first-class log structures. They therefore do **not** draw from the
//! ADR-008 [`crate::wire::StructTag`] registry (which is reserved for log
//! entries). Instead they are canonical-CBOR bodies under their own ASCII domain
//! labels — [`PQXDH_INIT_DOMAIN`] and [`RATCHET_MSG_DOMAIN`] — exactly the
//! pattern the identity layer uses for its non-log records
//! ([`crate::identity::keyagreement`]). The label both versions the format and
//! domain-separates these payloads from every other Vox structure.
//!
//! ## The two associated-data constructions
//! ADR-004 mandates a single, exactly-once AD state transition:
//!
//! - The **first** post-handshake message authenticates the KEM-binding AD
//!   ([`kem_binding_ad`]): `transcript_hash ‖ kem_pub ‖ kem_ct ‖ suite_id ‖
//!   channelID ‖ epoch`. Binding `kem_pub`/`kem_ct` into the AEAD AD defeats the
//!   re-encapsulation attack (ADR-003 requirement 2).
//! - **Every subsequent** message authenticates the header AD ([`header_ad`]):
//!   `header ‖ suite_id ‖ channelID ‖ epoch`, where `header` is the canonical
//!   encoding of `{ratchet_pubkey, PN, N, algo_ids}`.
//!
//! Both are deterministic canonical encodings so the same bytes are produced and
//! verified on both sides.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::identity::keyagreement::{ML_KEM_768_ENCAPS_LEN, X25519_PUB_LEN};
use crate::pairwise::kem::ML_KEM_768_CT_LEN;
use crate::suite::algo;

/// Domain label for the PQXDH initial-message canonical body (ADR-004).
pub const PQXDH_INIT_DOMAIN: &str = "vox/pqxdh-init/v1";
/// Domain label for the ratchet-message canonical body (ADR-004).
pub const RATCHET_MSG_DOMAIN: &str = "vox/ratchet-msg/v1";
/// Domain label for the PQXDH handshake transcript hash (ADR-004).
pub const PQXDH_TRANSCRIPT_DOMAIN: &str = "vox/pqxdh-transcript/v1";
/// Domain label for the first-message KEM-binding associated data (ADR-004).
pub const KEM_BINDING_AD_DOMAIN: &str = "vox/pqxdh-ad/v1";
/// Domain label for the per-message header associated data (ADR-004).
pub const RATCHET_AD_DOMAIN: &str = "vox/ratchet-ad/v1";

/// A Double Ratchet message header (ADR-004 §Wire): the sender's current ratchet
/// public key, the previous sending-chain length `PN`, the message number `N`,
/// and the algorithm IDs pinning the curve/AEAD in force.
///
/// The header is transmitted in the clear (it routes decryption) but is bound
/// into the AEAD associated data, so tampering it fails the open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetHeader {
    /// The sender's current X25519 ratchet public key (algorithm `0x0101`).
    pub ratchet_pubkey: [u8; X25519_PUB_LEN],
    /// Number of messages sent in the previous sending chain (`PN`).
    pub pn: u64,
    /// Message number in the current sending chain (`N`, 0-indexed).
    pub n: u64,
    /// The curve algorithm ID in force (`X25519` = `0x0101`).
    pub curve_algo: u16,
    /// The AEAD algorithm ID in force (`AES-256-GCM` = `0x0401`).
    pub aead_algo: u16,
}

impl RatchetHeader {
    /// Canonical-CBOR body, fixed field order (ADR-008 array form):
    /// `[curve_algo, aead_algo, ratchet_pubkey, pn, n]`.
    ///
    /// The two algorithm IDs lead so the encoding self-describes the key's class
    /// (ADR-003 requirement 1): the ratchet public key occupies the curve slot
    /// and can never be parsed as a KEM key.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(5)
            .uint(u64::from(self.curve_algo))
            .uint(u64::from(self.aead_algo))
            .bytes(&self.ratchet_pubkey)
            .uint(self.pn)
            .uint(self.n);
        e.finish()
    }

    /// Decode a header from its canonical body, rejecting an algorithm-ID
    /// mismatch (ADR-003 type confusion) and the wrong arity.
    pub fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 5 {
            return Err(Error::MalformedBundle("ratchet header arity"));
        }
        let curve_algo = expect_one_of(d.uint()?, &[algo::X25519])?;
        let aead_algo = expect_one_of(d.uint()?, &[algo::AES_256_GCM, algo::CHACHA20_POLY1305])?;
        let ratchet_pubkey = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::InvalidKeyEncoding { algo: curve_algo })?;
        let pn = d.uint()?;
        let n = d.uint()?;
        d.finish()?;
        Ok(Self {
            ratchet_pubkey,
            pn,
            n,
            curve_algo,
            aead_algo,
        })
    }
}

/// The header AD authenticated by every *non-first* ratchet message (ADR-004):
/// `RATCHET_AD_DOMAIN ‖ header_body ‖ suite_id ‖ channelID ‖ epoch`.
///
/// `channel_id` is the 32-byte channel identifier and `epoch` its membership
/// epoch (ADR-006); both are bound so a message cannot be replayed into a
/// different channel or epoch.
#[must_use]
pub fn header_ad(
    header: &RatchetHeader,
    suite_id: u16,
    channel_id: &[u8; 32],
    epoch: u64,
) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(4)
        .bytes(&header.canonical_body())
        .uint(u64::from(suite_id))
        .bytes(channel_id)
        .uint(epoch);
    domain_prefixed(RATCHET_AD_DOMAIN, &e.finish())
}

/// The KEM-binding AD authenticated by the *first* post-handshake message
/// (ADR-004 §Decision): `KEM_BINDING_AD_DOMAIN ‖ transcript_hash ‖ kem_pub ‖
/// kem_ct ‖ suite_id ‖ channelID ‖ epoch`.
///
/// Binding the KEM public key and ciphertext defeats the re-encapsulation attack
/// (ADR-003 requirement 2): an attacker who re-encapsulates against the same KEM
/// key to forge a first message cannot reproduce this AD without the exact
/// `(kem_pub, kem_ct, transcript_hash)` the honest handshake committed to.
#[must_use]
pub fn kem_binding_ad(
    transcript_hash: &[u8; 32],
    kem_pub: &[u8; ML_KEM_768_ENCAPS_LEN],
    kem_ct: &[u8; ML_KEM_768_CT_LEN],
    suite_id: u16,
    channel_id: &[u8; 32],
    epoch: u64,
) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(6)
        .bytes(transcript_hash)
        .bytes(kem_pub)
        .bytes(kem_ct)
        .uint(u64::from(suite_id))
        .bytes(channel_id)
        .uint(epoch);
    domain_prefixed(KEM_BINDING_AD_DOMAIN, &e.finish())
}

/// Prefix `body` with an ASCII domain label (the identity-layer signing-input
/// shape, [`crate::wire::signing_input`]).
fn domain_prefixed(domain: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + body.len());
    out.extend_from_slice(domain.as_bytes());
    out.extend_from_slice(body);
    out
}

/// Accept `got` only if it is one of `allowed`, else [`Error::UnexpectedAlgo`]
/// (using the first allowed value as the reported expectation).
fn expect_one_of(got: u64, allowed: &[u16]) -> Result<u16> {
    let got16 = u16::try_from(got).map_err(|_| Error::UnknownAlgoId(u16::MAX))?;
    if allowed.contains(&got16) {
        Ok(got16)
    } else {
        Err(Error::UnexpectedAlgo {
            got: got16,
            expected: allowed.first().copied().unwrap_or(0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> RatchetHeader {
        RatchetHeader {
            ratchet_pubkey: [7u8; X25519_PUB_LEN],
            pn: 3,
            n: 5,
            curve_algo: algo::X25519,
            aead_algo: algo::AES_256_GCM,
        }
    }

    #[test]
    fn header_body_round_trips() {
        let h = header();
        let body = h.canonical_body();
        assert_eq!(RatchetHeader::from_canonical_body(&body).unwrap(), h);
    }

    #[test]
    fn header_rejects_kem_id_in_curve_slot() {
        // ADR-003 requirement 1: a KEM algo id where the curve id belongs fails.
        let mut e = Encoder::new();
        e.array(5)
            .uint(u64::from(algo::ML_KEM_768))
            .uint(u64::from(algo::AES_256_GCM))
            .bytes(&[0u8; X25519_PUB_LEN])
            .uint(0)
            .uint(0);
        let body = e.finish();
        assert!(matches!(
            RatchetHeader::from_canonical_body(&body),
            Err(Error::UnexpectedAlgo { got, expected })
                if got == algo::ML_KEM_768 && expected == algo::X25519
        ));
    }

    #[test]
    fn header_rejects_bad_arity() {
        let mut e = Encoder::new();
        e.array(4)
            .uint(u64::from(algo::X25519))
            .uint(u64::from(algo::AES_256_GCM))
            .bytes(&[0u8; X25519_PUB_LEN])
            .uint(0);
        assert!(matches!(
            RatchetHeader::from_canonical_body(&e.finish()),
            Err(Error::MalformedBundle(_))
        ));
    }

    #[test]
    fn ad_constructions_are_domain_separated_and_deterministic() {
        let h = header();
        let cid = [9u8; 32];
        let a = header_ad(&h, 0x0001, &cid, 7);
        let b = header_ad(&h, 0x0001, &cid, 7);
        assert_eq!(a, b); // deterministic
        assert!(a.starts_with(RATCHET_AD_DOMAIN.as_bytes()));

        let th = [1u8; 32];
        let kp = [2u8; ML_KEM_768_ENCAPS_LEN];
        let ct = [3u8; ML_KEM_768_CT_LEN];
        let k = kem_binding_ad(&th, &kp, &ct, 0x0001, &cid, 7);
        assert!(k.starts_with(KEM_BINDING_AD_DOMAIN.as_bytes()));
        // The two AD families are never equal (distinct domains + shapes).
        assert_ne!(a, k);
    }

    #[test]
    fn kem_binding_ad_changes_when_ct_or_pub_tampered() {
        let th = [1u8; 32];
        let kp = [2u8; ML_KEM_768_ENCAPS_LEN];
        let ct = [3u8; ML_KEM_768_CT_LEN];
        let cid = [9u8; 32];
        let base = kem_binding_ad(&th, &kp, &ct, 0x0001, &cid, 0);

        let mut ct2 = ct;
        ct2[0] ^= 1;
        assert_ne!(base, kem_binding_ad(&th, &kp, &ct2, 0x0001, &cid, 0));

        let mut kp2 = kp;
        kp2[0] ^= 1;
        assert_ne!(base, kem_binding_ad(&th, &kp2, &ct, 0x0001, &cid, 0));
    }
}
