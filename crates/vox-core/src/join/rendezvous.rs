//! Rendezvous-address derivation (ADR-005 §"channelID → rendezvous address").
//!
//! `rendezvous = HKDF-SHA-256(ikm = seed, info = <label>)`, truncated to the DHT
//! key width. A *plain, fast* KDF is sufficient and correct because the seed is
//! already high-entropy (the channelID is `SHA-256(genesis)`, the self-channel
//! seed is the private per-identity self-channel secret). A memory-hard KDF would
//! add cost without benefit: knowing the seed, an observer computes the key once
//! regardless. Swarm-presence *unlinkability* is the later metadata-privacy phase
//! (ADR-001), not this derivation.
//!
//! ## The passphrase is NEVER an input to rendezvous
//! This is a load-bearing security property (ADR-005): rendezvous must not leak
//! anything an offline dictionary attack on the low-entropy passphrase could use.
//! It is enforced **at the type level** — every function here takes only a
//! high-entropy `seed` (a `[u8; 32]`); there is no parameter through which a
//! passphrase could be threaded. The passphrase feeds *only* CPace
//! ([`crate::join::cpace`]). A reviewer can confirm the separation by inspecting
//! these signatures alone.
//!
//! ## Labels
//! - **Channel rendezvous**: `info = "vox/rendezvous/v1" ‖ epoch_be` — the exact
//!   derivation ADR-012 (M10) consumes, with the channel epoch (ADR-007 rotation)
//!   mixed in so a rotated channel meets at a fresh address.
//! - **Self-channel rendezvous**: `info = "vox/self-rzv/v1"` with `seed =
//!   self_seed` (ADR-008/ADR-002) — a distinct label so the self-channel and a
//!   channel sharing the same seed bytes can never collide on an address.
//!
//! ## Boundary: the DHT key width is ADR-012/M10
//! [`rendezvous`] returns the full 32-byte HKDF output; [`truncate`] narrows it.
//! M3 derives the full key and documents the seam — the *width choice* (and any
//! DHT-specific encoding) belongs to M10, which owns the DHT.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::hash::Digest32;

/// Length of a full (untruncated) rendezvous key — one SHA-256 block.
pub const RENDEZVOUS_KEY_LEN: usize = 32;

/// The channel-rendezvous info label (ADR-005/ADR-012). The big-endian epoch is
/// appended to it; see [`channel_info`].
pub const CHANNEL_RENDEZVOUS_LABEL: &str = "vox/rendezvous/v1";

/// The self-channel-rendezvous info label (ADR-005/ADR-008). No epoch is appended
/// (the self-channel does not rotate on the channel epoch cadence).
pub const SELF_RENDEZVOUS_LABEL: &str = "vox/self-rzv/v1";

/// Derive a 32-byte rendezvous key: `HKDF-SHA-256(ikm = seed, info)`.
///
/// `seed` MUST be high-entropy (a channelID or a self-channel seed). `info` is the
/// fully-assembled info string (use [`channel_info`] / [`self_info`] to build the
/// canonical ones). HKDF is used with an empty salt: the seed is already uniform,
/// and the info label provides domain separation between uses.
///
/// HKDF-Expand over a 32-byte output cannot exceed the 255·HashLen ceiling, so
/// the only documented error path is unreachable; it is nevertheless surfaced as
/// [`Error::MalformedJoin`] — never as an all-zero key (no fallback; 2026-09-19
/// review).
pub fn rendezvous(seed: &Digest32, info: &[u8]) -> Result<[u8; RENDEZVOUS_KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; RENDEZVOUS_KEY_LEN];
    hk.expand(info, &mut okm)
        .map_err(|_| Error::MalformedJoin("rendezvous hkdf expand"))?;
    Ok(okm)
}

/// Build the channel-rendezvous info string `"vox/rendezvous/v1" ‖ epoch_be`
/// (ADR-005/ADR-012). The epoch is encoded big-endian so the byte ordering is
/// canonical and platform-independent.
#[must_use]
pub fn channel_info(epoch: u64) -> Vec<u8> {
    let mut info = Vec::with_capacity(CHANNEL_RENDEZVOUS_LABEL.len() + 8);
    info.extend_from_slice(CHANNEL_RENDEZVOUS_LABEL.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());
    info
}

/// Build the self-channel-rendezvous info string `"vox/self-rzv/v1"`.
#[must_use]
pub fn self_info() -> Vec<u8> {
    SELF_RENDEZVOUS_LABEL.as_bytes().to_vec()
}

/// Derive the channel rendezvous key for `(channel_id, epoch)` — the convenience
/// wrapper over [`rendezvous`] + [`channel_info`] that ADR-012 (M10) consumes.
pub fn channel_rendezvous(channel_id: &Digest32, epoch: u64) -> Result<[u8; RENDEZVOUS_KEY_LEN]> {
    rendezvous(channel_id, &channel_info(epoch))
}

/// Derive the self-channel rendezvous key from the private `self_seed`
/// (ADR-005/ADR-008). The seed is the **private** per-identity self-channel
/// secret — never the public identity key — so no third party can locate where a
/// user's own shared-root devices meet.
pub fn self_rendezvous(self_seed: &Digest32) -> Result<[u8; RENDEZVOUS_KEY_LEN]> {
    rendezvous(self_seed, &self_info())
}

/// Truncate a rendezvous key to `width` bytes (the DHT key width, ADR-012/M10).
///
/// Returns [`Error::MalformedJoin`] if `width` exceeds [`RENDEZVOUS_KEY_LEN`] —
/// you cannot stretch a 32-byte key. `width == 32` is the identity (full key).
/// The *choice* of width is M10's; this is the mechanism it will call.
pub fn truncate(key: &[u8; RENDEZVOUS_KEY_LEN], width: usize) -> Result<Vec<u8>> {
    if width > RENDEZVOUS_KEY_LEN {
        return Err(Error::MalformedJoin(
            "rendezvous truncation width too large",
        ));
    }
    Ok(key[..width].to_vec())
}
