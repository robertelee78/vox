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
#[must_use]
pub fn rendezvous(seed: &Digest32, info: &[u8]) -> [u8; RENDEZVOUS_KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; RENDEZVOUS_KEY_LEN];
    // HKDF-Expand over a 32-byte output cannot exceed the 255*HashLen ceiling, so
    // the only documented error path is unreachable. If it ever did fire, `okm`
    // stays all-zero (a key no honest peer derives) rather than panicking — but it
    // cannot, since 32 <= 255*32.
    if hk.expand(info, &mut okm).is_err() {
        okm = [0u8; RENDEZVOUS_KEY_LEN];
    }
    okm
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
#[must_use]
pub fn channel_rendezvous(channel_id: &Digest32, epoch: u64) -> [u8; RENDEZVOUS_KEY_LEN] {
    rendezvous(channel_id, &channel_info(epoch))
}

/// Derive the self-channel rendezvous key from the private `self_seed`
/// (ADR-005/ADR-008). The seed is the **private** per-identity self-channel
/// secret — never the public identity key — so no third party can locate where a
/// user's own shared-root devices meet.
#[must_use]
pub fn self_rendezvous(self_seed: &Digest32) -> [u8; RENDEZVOUS_KEY_LEN] {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(b: u8) -> Digest32 {
        [b; 32]
    }

    #[test]
    fn rendezvous_is_deterministic() {
        let s = seed(7);
        assert_eq!(channel_rendezvous(&s, 1), channel_rendezvous(&s, 1));
    }

    #[test]
    fn rendezvous_is_epoch_sensitive() {
        // Epoch rotation (ADR-007) must move the channel to a fresh address.
        let s = seed(7);
        assert_ne!(channel_rendezvous(&s, 1), channel_rendezvous(&s, 2));
    }

    #[test]
    fn rendezvous_is_seed_sensitive() {
        assert_ne!(
            channel_rendezvous(&seed(1), 5),
            channel_rendezvous(&seed(2), 5)
        );
    }

    #[test]
    fn self_label_differs_from_channel_label() {
        // The same 32 bytes used as a channelID and as a self_seed must NOT land
        // on the same rendezvous address — the labels separate the two uses.
        let s = seed(9);
        // Channel at epoch 0 vs self-channel (no epoch).
        assert_ne!(channel_rendezvous(&s, 0), self_rendezvous(&s));
        // And the raw info strings are different.
        assert_ne!(channel_info(0), self_info());
    }

    #[test]
    fn channel_info_appends_big_endian_epoch() {
        let info = channel_info(0x0102_0304_0506_0708);
        let (label, epoch) = info.split_at(CHANNEL_RENDEZVOUS_LABEL.len());
        assert_eq!(label, CHANNEL_RENDEZVOUS_LABEL.as_bytes());
        assert_eq!(epoch, &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn truncate_narrows_and_rejects_overlong() {
        let key = channel_rendezvous(&seed(3), 0);
        // A narrower width is a prefix of the full key.
        let narrow = truncate(&key, 20).unwrap();
        assert_eq!(narrow.len(), 20);
        assert_eq!(&narrow[..], &key[..20]);
        // Full width is the identity.
        assert_eq!(truncate(&key, 32).unwrap(), key.to_vec());
        // Over-wide is rejected, never stretched.
        assert!(matches!(truncate(&key, 33), Err(Error::MalformedJoin(_))));
    }

    #[test]
    fn rendezvous_matches_manual_hkdf() {
        // Pin the construction: HKDF-SHA-256(ikm=seed, salt=empty, info=label‖epoch).
        let s = seed(5);
        let hk = Hkdf::<Sha256>::new(None, &s);
        let mut expected = [0u8; 32];
        hk.expand(&channel_info(42), &mut expected).unwrap();
        assert_eq!(channel_rendezvous(&s, 42), expected);
    }
}
