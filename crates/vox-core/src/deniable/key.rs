//! The deniable epoch key `K` and the key-confirmation MAC (ADR-009 §"Concrete
//! protocol", steps 2 & 4).
//!
//! `K` is the HKDF output over the Burmester–Desmedt combined group element
//! ([`crate::deniable::share`]). It is used **only** to derive the confirmation
//! sub-key and produce the step-4 confirmation MAC over the epoch transcript `T`
//! — never to encrypt content (content confidentiality is the PQ Sender Keys, M4),
//! which is why a classical `K` is acceptable (ADR-009).

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Error, Result};

use crate::deniable::epoch::EpochContext;
use crate::deniable::share::SHARE_LEN;

type HmacSha256 = Hmac<Sha256>;

/// HKDF `info` label for the epoch key derivation (ADR-009 step 2).
pub const KEY_INFO_LABEL: &[u8] = b"vox/dgka/v1";
/// HKDF `info` label separating the confirmation sub-key from `K`.
pub const CONFIRM_INFO_LABEL: &[u8] = b"vox/dgka-confirm/v1";
/// Length of a confirmation MAC (HMAC-SHA-256).
pub const CONFIRM_LEN: usize = 32;

/// The agreed epoch key `K` after a successful DGKA. Held as the HKDF-derived
/// 32-byte secret (the Ristretto `K` point is the IKM); zeroized on drop. Used
/// only to derive the confirmation sub-key — never to encrypt content.
#[derive(Clone)]
pub struct EpochKey {
    bytes: [u8; 32],
}

impl Drop for EpochKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl core::fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EpochKey(<redacted>)")
    }
}

impl EpochKey {
    /// Derive the epoch key `K` from the Burmester–Desmedt combined group element by
    /// HKDF (IKM = compressed `K` point; info = "vox/dgka/v1" ‖ channelID ‖ epoch),
    /// per ADR-009 step 2.
    pub(crate) fn derive(k_point: &[u8; SHARE_LEN], ctx: &EpochContext) -> Result<Self> {
        let info = key_info(KEY_INFO_LABEL, ctx);
        let hk = Hkdf::<Sha256>::new(None, k_point);
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm)
            .map_err(|_| Error::MalformedBundle("dgka key expand"))?;
        Ok(Self { bytes: okm })
    }

    /// Whether two epoch keys are byte-equal (test/diagnostic).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn equals(&self, other: &EpochKey) -> bool {
        self.bytes == other.bytes
    }

    /// Derive the confirmation sub-key `K_confirm = HKDF(K, info=confirm-label ‖
    /// channelID ‖ epoch)`. Separating the confirmation key from `K` ensures the
    /// confirmation MAC never leaks `K` (standard AKE key-confirmation hygiene).
    fn confirm_key(&self, ctx: &EpochContext) -> Result<[u8; 32]> {
        let info = key_info(CONFIRM_INFO_LABEL, ctx);
        let hk = Hkdf::<Sha256>::new(None, &self.bytes);
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm)
            .map_err(|_| Error::MalformedBundle("dgka confirm-key expand"))?;
        Ok(okm)
    }

    /// The key-confirmation MAC `HMAC(K_confirm, message)` (ADR-009 step 4). The
    /// confirmation sub-key is derived from `ctx` (so it is bound to the channel +
    /// epoch), and the MAC is taken over `message` — the DSKE **bind transcript**
    /// `T_bind = SHA-256(T ‖ X_*)`, which commits to the agreement material. Used
    /// both to emit a member's own confirmation and to check a peer's (every honest
    /// member derives the same `K`, so the MACs match).
    pub(crate) fn confirm_mac_over(
        &self,
        ctx: &EpochContext,
        message: &[u8],
    ) -> Result<[u8; CONFIRM_LEN]> {
        let key = self.confirm_key(ctx)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key)
            .map_err(|_| Error::MalformedBundle("dgka confirm mac key"))?;
        mac.update(message);
        let out = mac.finalize().into_bytes();
        let mut tag = [0u8; CONFIRM_LEN];
        tag.copy_from_slice(&out);
        Ok(tag)
    }
}

/// Build an HKDF `info` of `label ‖ channelID ‖ epoch_le` for a context.
fn key_info(label: &[u8], ctx: &EpochContext) -> Vec<u8> {
    let epoch_le = ctx.epoch().to_le_bytes();
    let mut info = Vec::with_capacity(label.len() + 32 + 8);
    info.extend_from_slice(label);
    info.extend_from_slice(&ctx.channel_id());
    info.extend_from_slice(&epoch_le);
    info
}
