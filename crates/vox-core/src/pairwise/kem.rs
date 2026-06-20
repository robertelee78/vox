//! ML-KEM-768 encapsulation/decapsulation for the PQXDH KEM leg (ADR-004).
//!
//! This is the *handshake-time* counterpart to the keypair wrapper in
//! [`crate::identity::keyagreement`]: M1 generates and signs the responder's
//! KEM prekeys and exposes their 64-byte seeds; here M2 performs the actual
//! encapsulation (initiator) and decapsulation (responder) that yields the
//! ML-KEM shared secret `SS` mixed into the PQXDH KDF.
//!
//! ## Type-confusion prevention (ADR-003 requirement 1)
//! Every public KEM key consumed here is parsed through [`encaps_key_from_bytes`],
//! which runs the FIPS 203 §7.2 validity check. The caller has *already* bound the
//! key to its `ML-KEM-768` algorithm slot at decode time (the signed prekey body
//! puts the KEM key in an algorithm-tagged position, [`crate::identity::keyagreement`]),
//! so a curve key can never reach this code in a KEM slot.

use ml_kem::kem::{Decapsulate as _, Encapsulate as _};
use ml_kem::{Kem, MlKem768, Seed as KemSeed};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::identity::keyagreement::ML_KEM_768_ENCAPS_LEN;
use crate::suite::algo;

type DecapKey = <MlKem768 as Kem>::DecapsulationKey;
type EncapKey = <MlKem768 as Kem>::EncapsulationKey;

/// Length of an ML-KEM-768 ciphertext in bytes (FIPS 203, ML-KEM-768).
pub const ML_KEM_768_CT_LEN: usize = 1088;
/// Length of an ML-KEM shared secret in bytes (FIPS 203: always 32).
pub const ML_KEM_SS_LEN: usize = 32;

/// An ML-KEM-768 shared secret, zeroized on drop. Mixed into the PQXDH KDF as
/// `SS`; it is never exposed in the clear outside the handshake.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KemSharedSecret(pub(crate) [u8; ML_KEM_SS_LEN]);

impl KemSharedSecret {
    /// Borrow the raw shared-secret bytes (for the KDF input only).
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8; ML_KEM_SS_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for KemSharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KemSharedSecret").finish_non_exhaustive()
    }
}

/// Parse and validate an ML-KEM-768 encapsulation (public) key, rejecting
/// type-confused or malformed bytes with [`Error::InvalidKeyEncoding`]
/// (ADR-003 requirement 1; FIPS 203 §7.2 modulus check).
pub fn encaps_key_from_bytes(bytes: &[u8; ML_KEM_768_ENCAPS_LEN]) -> Result<EncapKey> {
    let key: ml_kem::Key<EncapKey> = (*bytes).into();
    EncapKey::new(&key).map_err(|_| Error::InvalidKeyEncoding {
        algo: algo::ML_KEM_768,
    })
}

/// Encapsulate against `peer_encaps`, producing the ciphertext to transmit and
/// the shared secret `SS` (initiator side).
///
/// Randomness comes from the ml-kem crate's audited system-RNG path (the same
/// OS CSPRNG Vox uses everywhere); no caller-supplied RNG object is threaded.
#[must_use]
pub fn encapsulate(peer_encaps: &EncapKey) -> ([u8; ML_KEM_768_CT_LEN], KemSharedSecret) {
    let (ct, ss) = peer_encaps.encapsulate();
    let mut ct_bytes = [0u8; ML_KEM_768_CT_LEN];
    ct_bytes.copy_from_slice(ct.as_slice());
    let mut ss_bytes = [0u8; ML_KEM_SS_LEN];
    ss_bytes.copy_from_slice(ss.as_slice());
    (ct_bytes, KemSharedSecret(ss_bytes))
}

/// Reconstruct the responder's decapsulation key from its stored 64-byte seed
/// (the secret M1 holds, [`crate::identity::keyagreement`]).
#[must_use]
pub fn decaps_key_from_seed(seed: [u8; 64]) -> DecapKey {
    let kem_seed: KemSeed = seed.into();
    <MlKem768 as Kem>::DecapsulationKey::from_seed(kem_seed)
}

/// Decapsulate `ct` with `decaps`, recovering the shared secret `SS` (responder
/// side). ML-KEM decapsulation is, by construction, infallible for a
/// well-formed ciphertext (implicit rejection yields a pseudo-random secret on a
/// malformed one), so a wrong ciphertext simply yields a different `SS` and the
/// downstream AEAD open fails — never a panic.
#[must_use]
pub fn decapsulate(decaps: &DecapKey, ct: &[u8; ML_KEM_768_CT_LEN]) -> KemSharedSecret {
    let ct_arr: ml_kem::Ciphertext<MlKem768> = (*ct).into();
    let ss = decaps.decapsulate(&ct_arr);
    let mut ss_bytes = [0u8; ML_KEM_SS_LEN];
    ss_bytes.copy_from_slice(ss.as_slice());
    KemSharedSecret(ss_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::KeyExport as _;

    // Build a responder keypair the way M1 does: a 64-byte seed -> decaps key,
    // and the public encaps-key bytes derived from it.
    fn responder() -> ([u8; 64], [u8; ML_KEM_768_ENCAPS_LEN], DecapKey) {
        let seed = crate::identity::rng::random_array::<64>().unwrap();
        let dk = decaps_key_from_seed(seed);
        let ek = dk.encapsulation_key().clone();
        let mut pub_bytes = [0u8; ML_KEM_768_ENCAPS_LEN];
        pub_bytes.copy_from_slice(ek.to_bytes().as_slice());
        (seed, pub_bytes, dk)
    }

    #[test]
    fn encapsulate_decapsulate_round_trips() {
        let (_seed, pub_bytes, dk) = responder();
        let ek = encaps_key_from_bytes(&pub_bytes).unwrap();
        let (ct, ss_send) = encapsulate(&ek);
        let ss_recv = decapsulate(&dk, &ct);
        assert_eq!(ss_send.as_bytes(), ss_recv.as_bytes());
    }

    #[test]
    fn tampered_ciphertext_yields_different_secret() {
        let (_seed, pub_bytes, dk) = responder();
        let ek = encaps_key_from_bytes(&pub_bytes).unwrap();
        let (mut ct, ss_send) = encapsulate(&ek);
        ct[0] ^= 0x01;
        // Implicit rejection: decapsulation returns a pseudo-random secret, not
        // the sender's. It must not equal the real one (so the downstream AEAD
        // fails) and must not panic.
        let ss_recv = decapsulate(&dk, &ct);
        assert_ne!(ss_send.as_bytes(), ss_recv.as_bytes());
    }

    #[test]
    fn malformed_encaps_key_rejected() {
        // All-0xFF bytes exceed the FIPS 203 modulus and are not a valid key.
        let bad = [0xffu8; ML_KEM_768_ENCAPS_LEN];
        assert!(matches!(
            encaps_key_from_bytes(&bad),
            Err(Error::InvalidKeyEncoding { algo }) if algo == algo::ML_KEM_768
        ));
    }

    #[test]
    fn reconstruction_matches_published_public_key() {
        // The seed-reconstructed decaps key's public half equals the bytes a
        // peer would have fetched — encapsulating against either succeeds.
        let (seed, pub_bytes, _dk) = responder();
        let dk2 = decaps_key_from_seed(seed);
        let mut pub2 = [0u8; ML_KEM_768_ENCAPS_LEN];
        pub2.copy_from_slice(dk2.encapsulation_key().to_bytes().as_slice());
        assert_eq!(pub_bytes, pub2);
    }
}
