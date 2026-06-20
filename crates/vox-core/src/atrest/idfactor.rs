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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    #[test]
    fn challenge_is_domain_then_channel_id() {
        let cid = [0x42u8; CHANNEL_ID_LEN];
        let c = id_factor_challenge(&cid);
        let mut expect = b"vox/sek-id-factor/v1".to_vec();
        expect.extend_from_slice(&cid);
        assert_eq!(c, expect);
    }

    #[test]
    fn id_proof_is_deterministic_across_calls() {
        // The property the double-lock depends on: same identity + challenge =>
        // byte-identical proof every unlock.
        let s = signer(7, 9);
        let f = SignatureIdentityFactor::new(&s);
        let cid = [1u8; CHANNEL_ID_LEN];
        let c = id_factor_challenge(&cid);
        let p1 = f.id_proof(&c).unwrap();
        let p2 = f.id_proof(&c).unwrap();
        assert_eq!(p1.as_slice(), p2.as_slice());
        assert_eq!(p1.len(), 64); // Ed25519 signature length
    }

    #[test]
    fn ed25519_id_proof_return_is_zeroizing_wrapped() {
        // The id_proof is a factor input (factor_id = HKDF(id_proof)), so its
        // accessor must hand back non-`Copy`, self-zeroizing material — no bare
        // `[u8; 64]` remnant can survive past use. This binds the exact return type;
        // it fails to compile if the signature regresses to a bare array.
        use crate::hash::ED25519_SIG_LEN;
        use zeroize::Zeroizing;
        let s = signer(7, 9);
        let cid = [1u8; CHANNEL_ID_LEN];
        let challenge = id_factor_challenge(&cid);
        let proof: Zeroizing<[u8; ED25519_SIG_LEN]> = s.ed25519_id_proof(&challenge).unwrap();
        // Deterministic (RFC 8032): re-deriving yields identical bytes.
        let proof2 = s.ed25519_id_proof(&challenge).unwrap();
        assert_eq!(proof.as_ref(), proof2.as_ref());
    }

    #[test]
    fn factor_id_is_reproducible_and_channel_bound() {
        let s = signer(7, 9);
        let f = SignatureIdentityFactor::new(&s);
        let cid_a = [1u8; CHANNEL_ID_LEN];
        let cid_b = [2u8; CHANNEL_ID_LEN];
        let a1 = f.factor_id(&cid_a).unwrap();
        let a2 = f.factor_id(&cid_a).unwrap();
        let b = f.factor_id(&cid_b).unwrap();
        // Reproducible for the same channel...
        assert_eq!(a1.as_ref(), a2.as_ref());
        // ...but different per channel (the challenge binds channelID).
        assert_ne!(a1.as_ref(), b.as_ref());
    }

    #[test]
    fn factor_id_differs_per_identity() {
        let cid = [3u8; CHANNEL_ID_LEN];
        let fa = signer(1, 1);
        let fb = signer(2, 2);
        let a = SignatureIdentityFactor::new(&fa).factor_id(&cid).unwrap();
        let b = SignatureIdentityFactor::new(&fb).factor_id(&cid).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn factor_id_matches_manual_derivation() {
        let s = signer(5, 6);
        let f = SignatureIdentityFactor::new(&s);
        let cid = [9u8; CHANNEL_ID_LEN];
        let derived = f.factor_id(&cid).unwrap();

        // Re-derive by hand from the public id_proof path.
        let challenge = id_factor_challenge(&cid);
        let proof = f.id_proof(&challenge).unwrap();
        let hk = Hkdf::<Sha256>::new(None, &proof);
        let mut expect = [0u8; FACTOR_ID_LEN];
        hk.expand(ID_FACTOR_HKDF_INFO, &mut expect).unwrap();
        assert_eq!(derived.as_ref(), &expect);
    }
}
