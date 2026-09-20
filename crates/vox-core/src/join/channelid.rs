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
