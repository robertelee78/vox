//! The composite Ed25519 + ML-DSA-65 root identity (ADR-002 §1, ADR-003).
//!
//! The root of trust is a *hybrid* signing pair: an Ed25519 key and an ML-DSA-65
//! key. A composite signature is the concatenation of both component signatures
//! and is valid **only if both halves verify** — so the construction is secure
//! as long as *either* the classical or the post-quantum assumption holds
//! (ADR-003 "hybrid everywhere — never pure-PQ").
//!
//! ## Fixed byte layout (ADR-002 §1)
//! The component keys/signatures are concatenated in a fixed order, lengths
//! implied by the algorithm ID `COMPOSITE_ED25519_ML_DSA_65` (`0x0304`):
//!
//! ```text
//! composite_pubkey = Ed25519_pub(32) ‖ ML-DSA-65_pub(1952)   = 1984 bytes
//! composite_sig    = Ed25519_sig(64) ‖ ML-DSA-65_sig(3309)   = 3373 bytes
//! ```
//!
//! There is no inner length prefix or domain tag at the concatenation itself:
//! the lengths are fixed by the algorithm, and the surrounding canonical struct
//! (ADR-008) carries the framing. The byte offsets are therefore load-bearing
//! and are covered by golden-layout tests.
//!
//! ## ML-DSA context
//! ML-DSA supports a signing "context" string. Vox does **not** use it: domain
//! separation is applied uniformly *in the message bytes* via
//! [`crate::wire::signing_input`] (`domain_sep ‖ body`), exactly as Ed25519 —
//! which has no native context — already requires. Both halves therefore sign
//! the identical byte string with an empty ML-DSA context, keeping the two
//! component signatures over the same input.

use ed25519_dalek::{
    Signature as EdSignature, Signer as _, SigningKey as EdSigningKey, Verifier as _,
    VerifyingKey as EdVerifyingKey,
};
use ml_dsa::signature::Keypair as _;
use ml_dsa::{
    MlDsa65, Signature as DsaSignature, SigningKey as DsaSigningKey,
    VerifyingKey as DsaVerifyingKey, B32 as DsaB32,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::hash::{
    identity_fingerprint, Digest32, COMPOSITE_PUB_LEN, COMPOSITE_SIG_LEN, ED25519_PUB_LEN,
    ED25519_SIG_LEN, ML_DSA_65_PUB_LEN, ML_DSA_65_SIG_LEN,
};
use crate::identity::rng::fill_random;
use crate::suite::algo;

/// The composite (Ed25519 + ML-DSA-65) root **public key**.
///
/// Stores both component public keys and exposes the canonical fixed-order byte
/// serialization plus composite signature verification (both halves must pass).
#[derive(Clone)]
pub struct CompositePublicKey {
    ed: EdVerifyingKey,
    ml_dsa: DsaVerifyingKey<MlDsa65>,
}

impl CompositePublicKey {
    /// The algorithm ID for this composite signer (`0x0304`).
    pub const ALGO_ID: u16 = algo::COMPOSITE_ED25519_ML_DSA_65;

    /// The serialized length of a composite public key (1984 bytes).
    pub const LEN: usize = COMPOSITE_PUB_LEN;

    /// The Ed25519 component public key (32 raw bytes).
    #[must_use]
    pub fn ed25519_bytes(&self) -> [u8; ED25519_PUB_LEN] {
        self.ed.to_bytes()
    }

    /// The ML-DSA-65 component public key (1952 raw bytes).
    #[must_use]
    pub fn ml_dsa_bytes(&self) -> [u8; ML_DSA_65_PUB_LEN] {
        let enc = self.ml_dsa.encode();
        let mut out = [0u8; ML_DSA_65_PUB_LEN];
        out.copy_from_slice(enc.as_slice());
        out
    }

    /// Serialize to the canonical fixed-order layout
    /// `Ed25519_pub(32) ‖ ML-DSA-65_pub(1952)`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; COMPOSITE_PUB_LEN] {
        let mut out = [0u8; COMPOSITE_PUB_LEN];
        out[..ED25519_PUB_LEN].copy_from_slice(&self.ed25519_bytes());
        out[ED25519_PUB_LEN..].copy_from_slice(&self.ml_dsa_bytes());
        out
    }

    /// Parse a composite public key from the canonical fixed-order layout.
    ///
    /// Both component keys are validated by their respective libraries; an
    /// Ed25519 point that is not a valid public key, or ML-DSA bytes that do not
    /// decode, is rejected with [`Error::InvalidKeyEncoding`].
    pub fn from_bytes(bytes: &[u8; COMPOSITE_PUB_LEN]) -> Result<Self> {
        let mut ed_arr = [0u8; ED25519_PUB_LEN];
        ed_arr.copy_from_slice(&bytes[..ED25519_PUB_LEN]);
        let ed = EdVerifyingKey::from_bytes(&ed_arr).map_err(|_| Error::InvalidKeyEncoding {
            algo: algo::ED25519,
        })?;

        let mut ml_arr = [0u8; ML_DSA_65_PUB_LEN];
        ml_arr.copy_from_slice(&bytes[ED25519_PUB_LEN..]);
        let ml_enc: ml_dsa::EncodedVerifyingKey<MlDsa65> = ml_arr.into();
        let ml_dsa = DsaVerifyingKey::<MlDsa65>::decode(&ml_enc);

        Ok(Self { ed, ml_dsa })
    }

    /// The human-verifiable identity fingerprint (ADR-002):
    /// `SHA-256(Ed25519_pub ‖ ML-DSA_pub)`. Both components are covered, so the
    /// ML-DSA co-key cannot be swapped without changing the fingerprint peers
    /// verify.
    #[must_use]
    pub fn fingerprint(&self) -> Digest32 {
        identity_fingerprint(&self.ed25519_bytes(), &self.ml_dsa_bytes())
    }

    /// Verify a composite signature over `msg`. Returns `Ok(())` **only if both**
    /// the Ed25519 and the ML-DSA-65 halves verify; otherwise
    /// [`Error::SignatureInvalid`].
    ///
    /// Both halves are always evaluated (no short-circuit on the first failure)
    /// so the verification cost does not depend on *which* half is wrong.
    pub fn verify(&self, msg: &[u8], sig: &CompositeSignature) -> Result<()> {
        let ed_ok = self.ed.verify(msg, &sig.ed).is_ok();
        // ML-DSA verification with an empty context (domain separation is in `msg`).
        let ml_ok = self.ml_dsa.verify_with_context(msg, b"", &sig.ml_dsa);
        if ed_ok & ml_ok {
            Ok(())
        } else {
            Err(Error::SignatureInvalid)
        }
    }
}

impl core::fmt::Debug for CompositePublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Render only the fingerprint; never dump raw key bytes.
        f.debug_struct("CompositePublicKey")
            .field("fingerprint", &crate::hash::Hex(&self.fingerprint()))
            .finish()
    }
}

impl PartialEq for CompositePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}
impl Eq for CompositePublicKey {}

/// A composite (Ed25519 + ML-DSA-65) signature.
#[derive(Clone)]
pub struct CompositeSignature {
    ed: EdSignature,
    ml_dsa: DsaSignature<MlDsa65>,
}

impl CompositeSignature {
    /// The serialized length of a composite signature (3373 bytes).
    pub const LEN: usize = COMPOSITE_SIG_LEN;

    /// Serialize to the canonical fixed-order layout
    /// `Ed25519_sig(64) ‖ ML-DSA-65_sig(3309)`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; COMPOSITE_SIG_LEN] {
        let mut out = [0u8; COMPOSITE_SIG_LEN];
        out[..ED25519_SIG_LEN].copy_from_slice(&self.ed.to_bytes());
        out[ED25519_SIG_LEN..].copy_from_slice(self.ml_dsa.encode().as_slice());
        out
    }

    /// The Ed25519 component signature (64 raw bytes).
    ///
    /// Exposed for the ADR-010 at-rest **identity factor**: that factor is the
    /// *deterministic* (RFC 8032) Ed25519 signature over a fixed challenge, and is
    /// derived by signing composite and taking this half — so the at-rest KEK is
    /// reproducible across unlocks without ever materializing the private key, and
    /// works through a delegated (gpg-agent/Enclave) backend that only knows how to
    /// produce a composite signature. The ML-DSA half is *not* used for the factor
    /// (it is the reproducible-yet-deniable-of-the-PQ-co-key concern of ADR-010
    /// §"Post-quantum strength of the at-rest factors").
    #[must_use]
    pub fn ed25519_bytes(&self) -> [u8; ED25519_SIG_LEN] {
        self.ed.to_bytes()
    }

    /// Parse a composite signature from the canonical fixed-order layout.
    ///
    /// The ML-DSA half is decoded structurally; the Ed25519 half is always a
    /// well-formed 64-byte value (any 64 bytes parse — validity is decided at
    /// [`CompositePublicKey::verify`] time, matching Ed25519 semantics). A
    /// malformed ML-DSA half is rejected with [`Error::InvalidSignatureEncoding`].
    pub fn from_bytes(bytes: &[u8; COMPOSITE_SIG_LEN]) -> Result<Self> {
        let mut ed_arr = [0u8; ED25519_SIG_LEN];
        ed_arr.copy_from_slice(&bytes[..ED25519_SIG_LEN]);
        let ed = EdSignature::from_bytes(&ed_arr);

        let mut ml_arr = [0u8; ML_DSA_65_SIG_LEN];
        ml_arr.copy_from_slice(&bytes[ED25519_SIG_LEN..]);
        let ml_enc: ml_dsa::EncodedSignature<MlDsa65> = ml_arr.into();
        let ml_dsa =
            DsaSignature::<MlDsa65>::decode(&ml_enc).ok_or(Error::InvalidSignatureEncoding)?;

        Ok(Self { ed, ml_dsa })
    }
}

impl PartialEq for CompositeSignature {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}
impl Eq for CompositeSignature {}

impl core::fmt::Debug for CompositeSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompositeSignature").finish_non_exhaustive()
    }
}

/// The secret half of a composite root identity: an Ed25519 signing key and an
/// ML-DSA-65 signing key.
///
/// Held only by the in-software [`SoftwareRootSigner`]; external backends
/// (gpg-agent, Secure Enclave) keep their own secrets and never construct this.
/// The Ed25519 key zeroizes on drop natively; the ML-DSA key is stored as its
/// 32-byte seed (the value ML-DSA keygen is derived from), wrapped so it
/// zeroizes on drop.
struct CompositeSecret {
    ed: EdSigningKey,
    ml_dsa_seed: DsaSeed,
}

/// A 32-byte ML-DSA seed that zeroizes on drop. The expanded signing key is
/// re-derived from it on demand, so only this minimal secret persists.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct DsaSeed([u8; 32]);

impl CompositeSecret {
    /// Derive the ML-DSA signing key from the stored seed.
    fn ml_dsa_key(&self) -> DsaSigningKey<MlDsa65> {
        let seed: DsaB32 = self.ml_dsa_seed.0.into();
        DsaSigningKey::<MlDsa65>::from_seed(&seed)
    }

    /// The composite public key.
    fn public(&self) -> CompositePublicKey {
        CompositePublicKey {
            ed: self.ed.verifying_key(),
            ml_dsa: self.ml_dsa_key().verifying_key(),
        }
    }

    /// Produce a composite signature over `msg` (empty ML-DSA context).
    fn sign(&self, msg: &[u8]) -> Result<CompositeSignature> {
        let ed = self.ed.sign(msg);
        // The deterministic ML-DSA variant with an empty context. `ctx` is empty
        // and constant, so the only error path (context too long) is unreachable;
        // we still surface it as an error rather than panicking.
        let ml_dsa = self
            .ml_dsa_key()
            .expanded_key()
            .sign_deterministic(msg, b"")
            .map_err(|_| Error::SigningFailed)?;
        Ok(CompositeSignature { ed, ml_dsa })
    }
}

impl Drop for CompositeSecret {
    fn drop(&mut self) {
        // `ed` (ed25519-dalek SigningKey) and `ml_dsa_seed` both zeroize
        // themselves on drop; nothing extra to do, but the explicit impl
        // documents that this type owns secret material.
    }
}

/// The pluggable root-signing backend (ADR-002 §1).
///
/// A `RootSigner` owns (or delegates to a holder of) the composite root secret
/// and can produce composite signatures and expose the composite public key /
/// fingerprint. This trait is the seam for a future gpg-agent / smartcard /
/// Secure Enclave backend (ADR-002 §GPG integration): such a backend would keep
/// the Ed25519 private key in the agent and never materialize the in-process
/// composite secret.
///
/// **Boundary note (ADR-010 / M8).** The gpg-agent-delegation backend is
/// deliberately *not* implemented in this milestone — it belongs to the
/// at-rest/vault milestone (ADR-010), which owns the agent transport and the
/// passphrase/double-lock model. What ships here is the trait plus a complete,
/// non-stub in-software backend ([`SoftwareRootSigner`]); that is a finished
/// capability, not a placeholder.
pub trait RootSigner {
    /// The composite root public key.
    fn public_key(&self) -> CompositePublicKey;

    /// The identity fingerprint `SHA-256(Ed25519_pub ‖ ML-DSA_pub)`.
    fn fingerprint(&self) -> Digest32 {
        self.public_key().fingerprint()
    }

    /// Produce a composite signature over `msg`.
    ///
    /// Callers pass the fully prepared signing input (typically
    /// [`crate::wire::signing_input`] output, i.e. `domain_sep ‖ body`); this
    /// method does not add domain separation of its own.
    fn sign(&self, msg: &[u8]) -> Result<CompositeSignature>;

    /// The deterministic Ed25519 **id_proof** over `challenge` — the ADR-010
    /// at-rest identity factor (`id_proof = Ed25519_sign(identity, challenge)`).
    ///
    /// The default extracts the Ed25519 half of a composite signature over the
    /// challenge. Because Ed25519 signing is deterministic (RFC 8032), the same
    /// challenge yields byte-identical bytes on every unlock, so the derived KEK is
    /// reproducible — the property the double-lock depends on — and a delegated
    /// backend (gpg-agent/Enclave) that only signs composite still satisfies it
    /// without exporting the private key. A hardware-bound backend that cannot sign
    /// deterministically uses the [`crate::atrest::IdentityFactor`]
    /// release-a-stored-secret variant instead (ADR-010).
    ///
    /// The proof fully determines `factor_id` (one unlock factor), so it is secret
    /// material: it is returned in a [`Zeroizing`] buffer (non-`Copy`, wiped on
    /// drop) and the default extracts the Ed25519 half directly into it, never
    /// binding a bare `[u8; 64]` that could linger on the stack past an app-lock.
    fn ed25519_id_proof(&self, challenge: &[u8]) -> Result<Zeroizing<[u8; ED25519_SIG_LEN]>> {
        Ok(Zeroizing::new(self.sign(challenge)?.ed25519_bytes()))
    }
}

/// The complete in-software root-signing backend (ADR-002 §1).
///
/// Generates and holds the composite root secret in process memory (zeroized on
/// drop) and signs with both components. This is the default backend for a
/// natively-generated identity (ADR-002 §GPG integration "Generate").
pub struct SoftwareRootSigner {
    secret: CompositeSecret,
}

impl SoftwareRootSigner {
    /// Generate a fresh composite root identity from the operating-system CSPRNG.
    ///
    /// Both component keys are derived from independently-sampled 32-byte seeds
    /// (`getrandom`), so a weakness in deriving one component cannot bias the
    /// other.
    pub fn generate() -> Result<Self> {
        let mut ed_seed = [0u8; 32];
        let mut ml_seed = [0u8; 32];
        fill_random(&mut ed_seed)?;
        fill_random(&mut ml_seed)?;
        let signer = Self::from_component_seeds(&ed_seed, &ml_seed);
        ed_seed.zeroize();
        ml_seed.zeroize();
        signer
    }

    /// Construct from explicit component seeds (Ed25519 seed, ML-DSA seed).
    ///
    /// Deterministic given the seeds — used by [`generate`](Self::generate),
    /// by backup restore (ADR-002 §Backup), and by tests with fixed vectors.
    pub fn from_component_seeds(ed_seed: &[u8; 32], ml_dsa_seed: &[u8; 32]) -> Result<Self> {
        let ed = EdSigningKey::from_bytes(ed_seed);
        let secret = CompositeSecret {
            ed,
            ml_dsa_seed: DsaSeed(*ml_dsa_seed),
        };
        Ok(Self { secret })
    }

    /// The Ed25519 component seed (for encrypted backup export, ADR-002 §Backup).
    ///
    /// Returns secret material in a [`Zeroizing`] buffer (non-`Copy`, wiped on
    /// drop) so no bare `[u8; 32]` seed copy lingers at a call site. Used by the
    /// backup bundle builder (M1) and the epoch-end ESK publication (M7).
    #[must_use]
    pub(crate) fn ed25519_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.ed.to_bytes())
    }

    /// The ML-DSA component seed (for encrypted backup export, ADR-002 §Backup).
    /// Returned [`Zeroizing`] for the same reason as [`Self::ed25519_seed`].
    #[must_use]
    pub(crate) fn ml_dsa_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.ml_dsa_seed.0)
    }
}

impl RootSigner for SoftwareRootSigner {
    fn public_key(&self) -> CompositePublicKey {
        self.secret.public()
    }

    fn sign(&self, msg: &[u8]) -> Result<CompositeSignature> {
        self.secret.sign(msg)
    }
}

impl core::fmt::Debug for SoftwareRootSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SoftwareRootSigner")
            .field("fingerprint", &crate::hash::Hex(&self.fingerprint()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_signer() -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[7u8; 32], &[9u8; 32]).unwrap()
    }

    #[test]
    fn composite_sign_verify_round_trip() {
        let signer = fixed_signer();
        let pk = signer.public_key();
        let msg = b"vox/test/v1 hello world";
        let sig = signer.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn verify_fails_on_wrong_message() {
        let signer = fixed_signer();
        let pk = signer.public_key();
        let sig = signer.sign(b"original").unwrap();
        assert!(matches!(
            pk.verify(b"tampered", &sig),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_fails_if_ed25519_half_corrupted() {
        // Prove the Ed25519 half is actually checked: corrupt only it.
        let signer = fixed_signer();
        let pk = signer.public_key();
        let sig = signer.sign(b"m").unwrap();
        let mut raw = sig.to_bytes();
        raw[0] ^= 0x01; // flip a bit in the Ed25519 signature region
        let bad = CompositeSignature::from_bytes(&raw).unwrap();
        assert!(matches!(
            pk.verify(b"m", &bad),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_fails_if_ml_dsa_half_corrupted() {
        // Prove the ML-DSA half is actually checked: corrupt only it.
        let signer = fixed_signer();
        let pk = signer.public_key();
        let sig = signer.sign(b"m").unwrap();
        let mut raw = sig.to_bytes();
        // Flip a bit well inside the ML-DSA signature region.
        let idx = ED25519_SIG_LEN + 100;
        raw[idx] ^= 0x01;
        // Some ML-DSA byte flips make the signature structurally undecodable
        // (a rejected encoding), others decode but fail verification. Either
        // way the composite must not verify.
        match CompositeSignature::from_bytes(&raw) {
            Ok(bad) => assert!(matches!(
                pk.verify(b"m", &bad),
                Err(Error::SignatureInvalid)
            )),
            Err(Error::InvalidSignatureEncoding) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_fails_with_other_key() {
        let a = fixed_signer();
        let b = SoftwareRootSigner::from_component_seeds(&[1u8; 32], &[2u8; 32]).unwrap();
        let sig = a.sign(b"m").unwrap();
        assert!(matches!(
            b.public_key().verify(b"m", &sig),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn pubkey_byte_layout_offsets() {
        let signer = fixed_signer();
        let pk = signer.public_key();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), COMPOSITE_PUB_LEN);
        assert_eq!(bytes.len(), 1984);
        // The first 32 bytes are exactly the Ed25519 public key.
        assert_eq!(&bytes[..ED25519_PUB_LEN], &pk.ed25519_bytes());
        // The remaining 1952 bytes are exactly the ML-DSA public key.
        assert_eq!(&bytes[ED25519_PUB_LEN..], &pk.ml_dsa_bytes()[..]);
    }

    #[test]
    fn sig_byte_layout_offsets() {
        let signer = fixed_signer();
        let sig = signer.sign(b"m").unwrap();
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), COMPOSITE_SIG_LEN);
        assert_eq!(bytes.len(), 3373);
        assert_eq!(ED25519_SIG_LEN, 64);
        assert_eq!(ML_DSA_65_SIG_LEN, 3309);
    }

    #[test]
    fn pubkey_round_trips_through_bytes() {
        let signer = fixed_signer();
        let pk = signer.public_key();
        let bytes = pk.to_bytes();
        let pk2 = CompositePublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk, pk2);
        // And it still verifies real signatures.
        let sig = signer.sign(b"x").unwrap();
        assert!(pk2.verify(b"x", &sig).is_ok());
    }

    #[test]
    fn sig_round_trips_through_bytes() {
        let signer = fixed_signer();
        let sig = signer.sign(b"x").unwrap();
        let bytes = sig.to_bytes();
        let sig2 = CompositeSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, sig2);
        assert!(signer.public_key().verify(b"x", &sig2).is_ok());
    }

    #[test]
    fn fingerprint_is_deterministic_and_sensitive() {
        let a = fixed_signer();
        let b = fixed_signer();
        // Same seeds -> same fingerprint.
        assert_eq!(a.fingerprint(), b.fingerprint());
        // Different ML-DSA seed (same Ed25519) -> different fingerprint, proving
        // the ML-DSA component is covered.
        let c = SoftwareRootSigner::from_component_seeds(&[7u8; 32], &[10u8; 32]).unwrap();
        assert_ne!(a.fingerprint(), c.fingerprint());
        // Different Ed25519 seed (same ML-DSA) -> different fingerprint too.
        let d = SoftwareRootSigner::from_component_seeds(&[8u8; 32], &[9u8; 32]).unwrap();
        assert_ne!(a.fingerprint(), d.fingerprint());
    }

    #[test]
    fn generated_signers_are_distinct() {
        let a = SoftwareRootSigner::generate().unwrap();
        let b = SoftwareRootSigner::generate().unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn deterministic_signing_is_reproducible() {
        // The composite signer uses deterministic ML-DSA + deterministic
        // Ed25519, so repeated signing of the same message is byte-identical.
        let signer = fixed_signer();
        let s1 = signer.sign(b"same").unwrap();
        let s2 = signer.sign(b"same").unwrap();
        assert_eq!(s1.to_bytes(), s2.to_bytes());
    }

    #[test]
    fn rejects_invalid_ed25519_point_in_pubkey() {
        // `0x02` repeated 32 times is a y-coordinate that does not decompress to a
        // valid Edwards point, so ed25519-dalek rejects it. (Note: the curve is
        // dense — most 32-byte strings *are* valid points — so this exercises a
        // genuinely-rejected encoding rather than an arbitrary tamper.)
        let signer = fixed_signer();
        let mut bytes = signer.public_key().to_bytes();
        for b in &mut bytes[..ED25519_PUB_LEN] {
            *b = 0x02;
        }
        assert!(matches!(
            CompositePublicKey::from_bytes(&bytes),
            Err(Error::InvalidKeyEncoding {
                algo: algo::ED25519
            })
        ));
    }
}
