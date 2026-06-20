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
}
