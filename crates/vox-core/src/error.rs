//! Crate-wide error type.
//!
//! Foundation milestone (M0) only models the errors the foundation can actually
//! raise. Later milestones extend [`Error`] as they add real failure modes —
//! never speculatively (ADR mantra: no stubs, no "we'll fill it in later").

use crate::cbor::CborError;

/// Result alias used throughout `vox-core`.
pub type Result<T> = core::result::Result<T, Error>;

/// The unified `vox-core` error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Canonical-CBOR encode/decode failure (includes canonicality violations).
    #[error("cbor: {0}")]
    Cbor(#[from] CborError),

    /// A framed struct carried a 2-byte tag not in the ADR-008 registry.
    #[error("unknown struct tag {0:#06x}")]
    UnknownStructTag(u16),

    /// A framed struct carried a format version this build does not implement.
    #[error("unsupported format version {version} for struct tag {tag:#06x}")]
    UnsupportedVersion {
        /// The struct-type tag whose version was rejected.
        tag: u16,
        /// The unrecognized format version byte.
        version: u8,
    },

    /// An `algo_id` (u16) was not found in the ADR-003 registry.
    #[error("unknown algorithm id {0:#06x}")]
    UnknownAlgoId(u16),

    /// A ciphersuite id was not found in the ADR-003 registry.
    #[error("unknown ciphersuite id {0:#06x}")]
    UnknownSuite(u16),

    /// A negotiated/observed suite ranked below the channel's policy floor
    /// (ADR-003 floor-gated downgrade rejection — abort, never fall back).
    #[error("ciphersuite {observed:#06x} is below the policy floor {floor:#06x}")]
    SuiteBelowFloor {
        /// The suite that was offered/observed.
        observed: u16,
        /// The minimum suite the channel policy requires.
        floor: u16,
    },

    /// The operating-system CSPRNG was unavailable (ADR-002 identity key
    /// generation). A hard failure — Vox never falls back to a weaker source.
    #[error("operating-system CSPRNG unavailable")]
    Rng,

    /// Public-key bytes did not decode as a valid key for the named algorithm
    /// (ADR-002/003). The `algo` field is the ADR-003 algorithm ID.
    #[error("invalid key encoding for algorithm {algo:#06x}")]
    InvalidKeyEncoding {
        /// The ADR-003 algorithm ID whose key encoding was rejected.
        algo: u16,
    },

    /// Signature bytes did not decode as a structurally valid signature
    /// (ADR-002 composite signature parsing).
    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,

    /// A signature failed verification (ADR-002). For composite signatures this
    /// is returned whenever *either* component half fails, without revealing
    /// which.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// A signing operation failed (ADR-002). Distinct from a verification
    /// failure: this is an error producing a signature, not checking one.
    #[error("signing operation failed")]
    SigningFailed,

    /// A field carried an algorithm ID that is valid in the registry but not the
    /// one this structure requires (ADR-003 type-confusion guard at a boundary).
    #[error("unexpected algorithm {got:#06x}, expected {expected:#06x}")]
    UnexpectedAlgo {
        /// The algorithm ID actually present.
        got: u16,
        /// The algorithm ID the structure requires.
        expected: u16,
    },

    /// A consume-once one-time prekey was requested but the pool is empty
    /// (ADR-002 §2). Callers fall back to the signed last-resort prekey.
    #[error("one-time prekey pool is empty")]
    PrekeyPoolEmpty,

    /// A backup/binding bundle's declared field was inconsistent or out of range
    /// on parse (ADR-002 §Backup, §GPG integration).
    #[error("malformed identity bundle: {0}")]
    MalformedBundle(&'static str),
}
