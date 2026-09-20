//! The at-rest **identity factor** (ADR-010 §"Double-lock key derivation").
//!
//! One of the two factors that gate a channel's Store Encryption Key. It is
//! derived **without ever reading raw private-key material**, so it works with a
//! non-exportable key in `gpg-agent`, a smartcard, or the Secure Enclave.
//!
//! ## The two backends (one shipped, one a documented seam)
//! ADR-010 defines two ways to realize the identity factor:
//!
//! - **Signature variant (shipped here in full).** The factor is the
//!   *deterministic* (RFC 8032) Ed25519 signature over a fixed, channel-bound
//!   challenge:
//!   ```text
//!   challenge = "vox/sek-id-factor/v1" ‖ channelID
//!   id_proof  = Ed25519_sign(identity, challenge)
//!   factor_id = HKDF-SHA-256(id_proof, info = "vox/sek-id/v1")
//!   ```
//!   Because Ed25519 signing is deterministic, `id_proof` is reproducible across
//!   unlocks, so `factor_id` — and therefore the KEK — is reproducible without
//!   exporting the key. [`SignatureIdentityFactor`] wraps any
//!   [`crate::identity::composite::RootSigner`]; a delegated gpg-agent/Enclave
//!   backend that only knows how to produce a *composite* signature still works,
//!   because the factor uses only the (deterministic) Ed25519 half.
//!
//! - **Hardware-stored-secret variant (the seam).** For randomized or
//!   hardware-bound keys that cannot sign deterministically (some ML-DSA/smartcard
//!   configs), the identity factor instead **unwraps a hardware-stored random
//!   secret** released only to that identity — again never touching raw key bytes,
//!   and *fully* PQ (the secret, not a quantum-forgeable signature, gates unlock;
//!   ADR-010 §"Post-quantum strength"). The [`IdentityFactor`] trait is exactly
//!   that seam: a hardware backend implements it by returning the released secret
//!   as the `id_proof`. The Secure-Enclave / gpg-agent IPC that releases the
//!   secret is **platform integration**, not core crypto — it is a documented
//!   deferral (the milestone brief's scope boundary), not a stub: the trait and
//!   the complete software backend ship here.
//!
//! ## Why `factor_id` is HKDF of the proof, not the proof itself
//! The raw `id_proof` (a 64-byte Ed25519 signature, or a hardware secret) is run
//! through HKDF-SHA-256 with a domain-separated `info` so the value fed into the
//! KEK derivation is a uniform 32-byte key with a fixed label, and so the same
//! `id_proof` reused under a different purpose cannot collide with this one.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::Result;
use crate::hash::DIGEST_LEN;
use crate::identity::composite::RootSigner;

/// The challenge domain for the identity factor (ADR-010, exact):
/// `challenge = "vox/sek-id-factor/v1" ‖ channelID`.
pub const ID_FACTOR_CHALLENGE_DOMAIN: &str = "vox/sek-id-factor/v1";

/// The HKDF `info` for `factor_id` (ADR-010, exact):
/// `factor_id = HKDF-SHA-256(id_proof, info = "vox/sek-id/v1")`.
pub const ID_FACTOR_HKDF_INFO: &[u8] = b"vox/sek-id/v1";

/// Length of the derived `factor_id` (a 32-byte HKDF output).
pub const FACTOR_ID_LEN: usize = DIGEST_LEN;

/// The channel ID is a 32-byte SHA-256 digest series-wide (ADR-005/007).
pub const CHANNEL_ID_LEN: usize = DIGEST_LEN;

/// Build the channel-bound identity-factor challenge
/// `"vox/sek-id-factor/v1" ‖ channelID`.
#[must_use]
pub fn id_factor_challenge(channel_id: &[u8; CHANNEL_ID_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ID_FACTOR_CHALLENGE_DOMAIN.len() + CHANNEL_ID_LEN);
    out.extend_from_slice(ID_FACTOR_CHALLENGE_DOMAIN.as_bytes());
    out.extend_from_slice(channel_id);
    out
}

/// The identity-factor seam (ADR-010). An implementor produces a reproducible
/// `id_proof` for a channel-bound challenge *without exposing private-key bytes*.
///
/// - [`SignatureIdentityFactor`] implements it via the deterministic Ed25519
///   signature (shipped).
/// - A hardware backend implements it by releasing its identity-gated random
///   secret as the proof (the documented seam; the IPC is platform integration).
pub trait IdentityFactor {
    /// Produce the reproducible `id_proof` over `challenge` (see
    /// [`id_factor_challenge`]). Must be deterministic for a given identity +
    /// challenge so the derived KEK is reproducible across unlocks.
    ///
    /// The returned bytes are secret-adjacent (they fully determine `factor_id`),
    /// so they are wrapped in [`Zeroizing`].
    fn id_proof(&self, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>>;

    /// Derive the 32-byte `factor_id` for `channel_id`:
    /// `HKDF-SHA-256(id_proof(challenge), info = "vox/sek-id/v1")`.
    fn factor_id(
        &self,
        channel_id: &[u8; CHANNEL_ID_LEN],
    ) -> Result<Zeroizing<[u8; FACTOR_ID_LEN]>> {
        let challenge = id_factor_challenge(channel_id);
        let proof = self.id_proof(&challenge)?;
        let hk = Hkdf::<Sha256>::new(None, &proof);
        let mut out = Zeroizing::new([0u8; FACTOR_ID_LEN]);
        // HKDF-Expand of 32 bytes from SHA-256 never exceeds 255*32 and so never
        // fails; treat any error as a derivation failure rather than panicking.
        hk.expand(ID_FACTOR_HKDF_INFO, out.as_mut())
            .map_err(|_| crate::error::Error::Argon2Failed)?;
        Ok(out)
    }
}

/// The shipped signature-based identity factor: the deterministic Ed25519
/// `id_proof` from a composite root signer (ADR-010).
///
/// Wraps a borrowed [`RootSigner`]; signing is delegated to it, so this works with
/// the in-software backend *and* with a future gpg-agent/Enclave backend that
/// implements `RootSigner` by delegation — neither exposes the private key.
pub struct SignatureIdentityFactor<'a, R: RootSigner + ?Sized> {
    signer: &'a R,
}

impl<'a, R: RootSigner + ?Sized> SignatureIdentityFactor<'a, R> {
    /// Wrap a root signer as the identity factor.
    #[must_use]
    pub fn new(signer: &'a R) -> Self {
        Self { signer }
    }
}

impl<R: RootSigner + ?Sized> IdentityFactor for SignatureIdentityFactor<'_, R> {
    fn id_proof(&self, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        // The deterministic Ed25519 half of a composite signature over the
        // challenge (RFC 8032). Reproducible across unlocks; private key never
        // materialized. `ed25519_id_proof` returns a non-`Copy` `Zeroizing`, so no
        // bare `[u8; 64]` id_proof remnant is ever bound; `sig` wipes on drop and
        // the proof is re-wrapped as a zeroizing `Vec`.
        let sig = self.signer.ed25519_id_proof(challenge)?;
        Ok(Zeroizing::new(sig.to_vec()))
    }
}
