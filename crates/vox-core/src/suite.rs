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

/// A **test-only** suite ranked *below* `vox-suite-1` (rank 0) with identical
/// components, so the floor relation can be exercised while the production
/// registry has a single suite. It does not exist in a non-test build: no
/// production peer can propose or accept it.
#[cfg(test)]
pub const VOX_SUITE_TEST_WEAK: Ciphersuite = Ciphersuite {
    id: 0x7FFF,
    rank: 0,
    name: "vox-suite-test-weak",
    ..VOX_SUITE_1
};

/// The ciphersuite registry. New suites are appended with an assigned rank, so
/// the floor advances deliberately and never silently downgrades.
#[cfg(not(test))]
pub const SUITES: &[Ciphersuite] = &[VOX_SUITE_1];
/// The ciphersuite registry (test build: plus the rank-0 test suite).
#[cfg(test)]
pub const SUITES: &[Ciphersuite] = &[VOX_SUITE_1, VOX_SUITE_TEST_WEAK];

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
/// The relation is on the registry's **suite rank** (the rank column of the
/// ADR-003 table). Ranks are assigned deliberately when a suite is appended —
/// "the floor advances deliberately and never silently downgrades" — so the
/// total rank *is* the strength order; there is no separate per-component rank
/// registry to compare against. Both ids must be registered.
pub fn check_floor(observed: u16, floor: u16) -> Result<()> {
    let obs = suite_by_id(observed)?;
    let flr = suite_by_id(floor)?;
    if obs.rank >= flr.rank {
        Ok(())
    } else {
        Err(Error::SuiteBelowFloor { observed, floor })
    }
}

/// A channel's **minimum ciphersuite** (ADR-003 §"Floor relation"), the value
/// every handshake on that channel is gated by: a proposal whose suite ranks
/// below the floor is rejected (aborted, no fallback).
///
/// The floor comes from the signed genesis policy (`ChannelPolicy::min_suite`,
/// ADR-007) and can only be raised by a `policy`-holder. It is a distinct type
/// from a proposed suite id so the two `u16`s cannot be swapped at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuiteFloor {
    id: u16,
}

impl SuiteFloor {
    /// The day-one floor: `vox-suite-1`. New channels are created at this floor
    /// unless the creator names a stronger registered suite.
    pub const DAY_ONE: SuiteFloor = SuiteFloor { id: VOX_SUITE_1.id };

    /// A floor at the registered suite `id`, else [`Error::UnknownSuite`].
    pub fn new(id: u16) -> Result<Self> {
        suite_by_id(id)?;
        Ok(Self { id })
    }

    /// The floor suite's id.
    #[must_use]
    pub const fn id(self) -> u16 {
        self.id
    }

    /// The floor suite's rank.
    #[must_use]
    pub fn rank(self) -> u32 {
        // The id was validated at construction; an unregistered id cannot exist
        // here, so a lookup miss is an internal invariant breach — rank 0 keeps
        // the relation conservative (everything registered is ≥ 0).
        suite_by_id(self.id).map_or(0, |s| s.rank)
    }

    /// Gate a proposed suite: `Ok` iff `observed` is registered and ranks at or
    /// above this floor, else [`Error::SuiteBelowFloor`] / [`Error::UnknownSuite`].
    pub fn check(self, observed: u16) -> Result<()> {
        check_floor(observed, self.id)
    }

    /// Whether `other` is at or above this floor (used by the policy fold: a
    /// floor is only ever *raised*).
    #[must_use]
    pub fn permits_raise_to(self, other: SuiteFloor) -> bool {
        other.rank() >= self.rank()
    }
}
