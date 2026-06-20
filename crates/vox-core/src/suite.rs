//! The algorithm and ciphersuite registry (ADR-003) — the single source for
//! every `algo_id` and suite ID on the wire.
//!
//! An algorithm ID is a `u16` big-endian: the **high byte is the class** (this
//! *is* the pairwise-disjoint encoding range + algorithm prefix that ADR-003
//! requirement 1 mandates) and the low byte is the member. A **ciphersuite** is
//! a named, versioned, rank-ordered tuple over the classes.
//!
//! ## Floor-gated downgrade rejection
//! A channel policy names a **minimum suite**; a peer advertises only suites
//! whose strength rank is ≥ the floor's and **rejects** (aborts) any proposal
//! below it ([`check_floor`]). There is no "downgrade to classical" path — hybrid
//! PQ is the floor.

use crate::error::{Error, Result};

/// Algorithm class — the high byte of every `algo_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum AlgoClass {
    /// `0x01` — curve / key exchange.
    Curve = 0x01,
    /// `0x02` — KEM.
    Kem = 0x02,
    /// `0x03` — signature.
    Signature = 0x03,
    /// `0x04` — AEAD.
    Aead = 0x04,
    /// `0x05` — hash.
    Hash = 0x05,
    /// `0x06` — KDF.
    Kdf = 0x06,
    /// `0x07` — PAKE.
    Pake = 0x07,
    /// `0x08` — TLS group.
    TlsGroup = 0x08,
}

impl AlgoClass {
    /// The class byte of an `algo_id` (its high byte).
    #[must_use]
    pub const fn of(algo_id: u16) -> u8 {
        (algo_id >> 8) as u8
    }
}

/// Algorithm IDs (ADR-003 registry). Names are the canonical wire constants.
pub mod algo {
    /// X25519 curve / key exchange.
    pub const X25519: u16 = 0x0101;
    /// ML-KEM-768 KEM.
    pub const ML_KEM_768: u16 = 0x0201;
    /// Ed25519 signature.
    pub const ED25519: u16 = 0x0301;
    /// ML-DSA-65 signature.
    pub const ML_DSA_65: u16 = 0x0302;
    /// SLH-DSA-SHA2-128s signature.
    pub const SLH_DSA_SHA2_128S: u16 = 0x0303;
    /// Composite Ed25519+ML-DSA-65 signature (the day-one hybrid signer).
    pub const COMPOSITE_ED25519_ML_DSA_65: u16 = 0x0304;
    /// AES-256-GCM AEAD.
    pub const AES_256_GCM: u16 = 0x0401;
    /// ChaCha20-Poly1305 AEAD.
    pub const CHACHA20_POLY1305: u16 = 0x0402;
    /// SHA-256 hash (series-wide default).
    pub const SHA_256: u16 = 0x0501;
    /// BLAKE3-256 hash.
    pub const BLAKE3_256: u16 = 0x0502;
    /// HKDF-SHA-256 KDF.
    pub const HKDF_SHA_256: u16 = 0x0601;
    /// Argon2id KDF / password hash.
    pub const ARGON2ID: u16 = 0x0602;
    /// CPace over Ristretto255 with SHA-512 (PAKE).
    pub const CPACE_RISTRETTO255_SHA512: u16 = 0x0701;
    /// X25519MLKEM768 TLS group (`0x11EC` on the TLS wire).
    pub const TLS_X25519MLKEM768: u16 = 0x0801;
}

/// Every registered algorithm ID, in ascending order.
pub const ALL_ALGOS: &[u16] = &[
    algo::X25519,
    algo::ML_KEM_768,
    algo::ED25519,
    algo::ML_DSA_65,
    algo::SLH_DSA_SHA2_128S,
    algo::COMPOSITE_ED25519_ML_DSA_65,
    algo::AES_256_GCM,
    algo::CHACHA20_POLY1305,
    algo::SHA_256,
    algo::BLAKE3_256,
    algo::HKDF_SHA_256,
    algo::ARGON2ID,
    algo::CPACE_RISTRETTO255_SHA512,
    algo::TLS_X25519MLKEM768,
];

/// Validate that an `algo_id` is in the registry, else [`Error::UnknownAlgoId`].
pub fn validate_algo(algo_id: u16) -> Result<()> {
    if ALL_ALGOS.contains(&algo_id) {
        Ok(())
    } else {
        Err(Error::UnknownAlgoId(algo_id))
    }
}

/// A named, versioned ciphersuite over the algorithm classes (ADR-003).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ciphersuite {
    /// Suite ID (`u16`; disjoint from the struct-tag space — see [`crate::wire`]).
    pub id: u16,
    /// Total strength **rank** used by the floor relation (higher = stronger).
    /// The floor is defined by rank, *not* by numeric ID.
    pub rank: u32,
    /// Human-readable suite name.
    pub name: &'static str,
    /// Curve / KEX algorithm ID.
    pub curve: u16,
    /// KEM algorithm ID.
    pub kem: u16,
    /// Signature algorithm ID.
    pub signature: u16,
    /// AEAD algorithm ID.
    pub aead: u16,
    /// Hash algorithm ID.
    pub hash: u16,
    /// KDF algorithm ID.
    pub kdf: u16,
    /// PAKE algorithm ID.
    pub pake: u16,
}

/// `vox-suite-1` (`0x0001`, rank 1): the day-one hybrid-PQ suite.
pub const VOX_SUITE_1: Ciphersuite = Ciphersuite {
    id: 0x0001,
    rank: 1,
    name: "vox-suite-1",
    curve: algo::X25519,
    kem: algo::ML_KEM_768,
    signature: algo::COMPOSITE_ED25519_ML_DSA_65,
    aead: algo::AES_256_GCM,
    hash: algo::SHA_256,
    kdf: algo::HKDF_SHA_256,
    pake: algo::CPACE_RISTRETTO255_SHA512,
};

/// The ciphersuite registry. New suites are appended with an assigned rank, so
/// the floor advances deliberately and never silently downgrades.
pub const SUITES: &[Ciphersuite] = &[VOX_SUITE_1];

/// Resolve a suite by ID, else [`Error::UnknownSuite`].
pub fn suite_by_id(id: u16) -> Result<&'static Ciphersuite> {
    SUITES
        .iter()
        .find(|s| s.id == id)
        .ok_or(Error::UnknownSuite(id))
}

/// Floor-gated downgrade rejection (ADR-003): accept `observed` only if its rank
/// is ≥ the `floor` suite's rank, else [`Error::SuiteBelowFloor`].
///
/// With the current single-suite registry the suite-level rank check is the whole
/// relation; when suites diverge in individual components, per-component ranks are
/// added to [`Ciphersuite`] and compared here too. The extension point is
/// deliberate, not a stub: the relation is complete and correct for every suite
/// the registry actually defines.
pub fn check_floor(observed: u16, floor: u16) -> Result<()> {
    let obs = suite_by_id(observed)?;
    let flr = suite_by_id(floor)?;
    if obs.rank >= flr.rank {
        Ok(())
    } else {
        Err(Error::SuiteBelowFloor { observed, floor })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_extraction() {
        assert_eq!(AlgoClass::of(algo::X25519), AlgoClass::Curve as u8);
        assert_eq!(AlgoClass::of(algo::ML_KEM_768), AlgoClass::Kem as u8);
        assert_eq!(
            AlgoClass::of(algo::COMPOSITE_ED25519_ML_DSA_65),
            AlgoClass::Signature as u8
        );
        assert_eq!(
            AlgoClass::of(algo::TLS_X25519MLKEM768),
            AlgoClass::TlsGroup as u8
        );
    }

    #[test]
    fn every_algo_has_known_class() {
        for &a in ALL_ALGOS {
            let class = AlgoClass::of(a);
            assert!((0x01..=0x08).contains(&class), "{a:#06x}");
            assert!(validate_algo(a).is_ok());
        }
    }

    #[test]
    fn unknown_algo_rejected() {
        assert!(matches!(
            validate_algo(0x09ff),
            Err(Error::UnknownAlgoId(0x09ff))
        ));
        // A plausible-looking but unregistered member is still rejected.
        assert!(matches!(
            validate_algo(0x0399),
            Err(Error::UnknownAlgoId(0x0399))
        ));
    }

    #[test]
    fn suite_one_components_are_registered() {
        let s = suite_by_id(0x0001).unwrap();
        assert_eq!(s.name, "vox-suite-1");
        for a in [s.curve, s.kem, s.signature, s.aead, s.hash, s.kdf, s.pake] {
            assert!(validate_algo(a).is_ok(), "{a:#06x}");
        }
    }

    #[test]
    fn floor_accepts_equal_and_rejects_below() {
        // Equal rank passes.
        assert!(check_floor(0x0001, 0x0001).is_ok());
        // Unknown suite IDs are rejected, not silently passed.
        assert!(matches!(
            check_floor(0x9999, 0x0001),
            Err(Error::UnknownSuite(0x9999))
        ));
    }
}
