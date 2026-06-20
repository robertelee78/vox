//! Identity proof-of-possession (ADR-005 factor 2).
//!
//! CPace ([`crate::join::cpace`]) proves "this party holds the passphrase", not
//! *which identity* it is. Inside the CPace-keyed channel each party therefore
//! **proves possession** of its composite Ed25519+ML-DSA identity key (ADR-002) by
//! signing a value bound to the specific CPace run, and the peer matches the
//! presented identity's fingerprint against the one it expects out-of-band
//! (ADR-014). Merely *naming* an identity is not enough; the private key must be
//! exercised, and it is.
//!
//! ## What is signed
//! Each party signs the domain-separated input
//! `"vox/join-pop/v1" ‖ sid ‖ transcript_hash`, where:
//! - `sid` is the CPace session id (fresh per run), and
//! - `transcript_hash = SHA-256("vox/join-tr/v1" ‖ sid ‖ ISK ‖ own_share ‖ peer_share)`
//!   binds the proof to *this* CPace exchange (its key and both public shares).
//!
//! Because `transcript_hash` includes the run-unique `ISK` and `sid`, a signature
//! captured from one run is worthless in another (replay across runs fails). The
//! signature is over the composite key, so it holds as long as *either* the
//! classical or the post-quantum assumption holds (ADR-003).
//!
//! ## Why the two failure modes are one error
//! [`verify`] returns [`Error::JoinProofFailed`] both when the signature does not
//! verify and when the fingerprint does not match the expected one. Collapsing the
//! two denies a probe the ability to distinguish "wrong key" from "right key,
//! wrong identity" — the join either binds the expected identity or it aborts.
//!
//! ## Confidentiality of the proof on the wire
//! The PoP message is exchanged *inside* the CPace-derived channel (encrypted
//! under a key derived from the ISK; see [`crate::join::session`]). This module
//! produces and checks the signed material; the transport encryption is the
//! caller's (an AEAD keyed from the ISK), so a passive observer never sees the
//! identity public keys in clear.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::hash::{sha256_concat, Digest32, COMPOSITE_PUB_LEN, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::identity::rng::random_array;

/// Domain label for the PoP signing input.
pub const JOIN_POP_DOMAIN: &str = "vox/join-pop/v1";

/// HKDF `info` for the AEAD key that seals the PoP on the wire (ADR-005): the PoP
/// message is encrypted inside the CPace-derived channel under
/// `K_pop = HKDF-SHA-256(ISK, info = "vox/cpace-pop/v1")`.
pub const POP_SEAL_DOMAIN: &str = "vox/cpace-pop/v1";

/// AES-256-GCM nonce length in bytes.
const POP_NONCE_LEN: usize = 12;

/// Domain label for the CPace-run transcript hash.
pub const JOIN_TRANSCRIPT_DOMAIN: &str = "vox/join-tr/v1";

/// Bind a CPace run to a single 32-byte transcript hash:
/// `SHA-256("vox/join-tr/v1" ‖ sid ‖ ISK ‖ own_share ‖ peer_share)`.
///
/// Both parties compute the **same** value: each passes its own share as
/// `own_share` and the peer's as `peer_share`, but the hash is order-independent
/// because the two shares are combined symmetrically — see the note below. To keep
/// it genuinely identical on both ends without depending on who is "a" or "b", the
/// shares are sorted before hashing (the smaller share first), mirroring CPace's
/// own symmetric ordering.
#[must_use]
pub fn transcript_hash(sid: &[u8], isk: &[u8], share_x: &[u8; 32], share_y: &[u8; 32]) -> Digest32 {
    // Symmetric ordering so both parties derive an identical transcript hash
    // regardless of role (CPace itself is role-symmetric).
    let (first, second) = if share_x <= share_y {
        (share_x, share_y)
    } else {
        (share_y, share_x)
    };
    sha256_concat(&[
        JOIN_TRANSCRIPT_DOMAIN.as_bytes(),
        sid,
        isk,
        &first[..],
        &second[..],
    ])
}

/// The PoP signing input `"vox/join-pop/v1" ‖ sid ‖ transcript_hash`.
fn signing_input(sid: &[u8], transcript_hash: &Digest32) -> Vec<u8> {
    let mut out = Vec::with_capacity(JOIN_POP_DOMAIN.len() + sid.len() + transcript_hash.len());
    out.extend_from_slice(JOIN_POP_DOMAIN.as_bytes());
    out.extend_from_slice(sid);
    out.extend_from_slice(&transcript_hash[..]);
    out
}

/// The identity material a party presents in its PoP message: the composite
/// identity public key and the composite signature over the run-bound input.
///
/// The peer parses this, verifies the signature, and matches the key's fingerprint
/// against the expected one ([`verify`]).
#[derive(Clone)]
pub struct IdentityProof {
    /// The presenter's composite identity public key bytes (ADR-002 layout).
    pub identity_pub: [u8; crate::hash::COMPOSITE_PUB_LEN],
    /// The composite signature over `"vox/join-pop/v1" ‖ sid ‖ transcript_hash`.
    pub signature: [u8; crate::hash::COMPOSITE_SIG_LEN],
}

impl core::fmt::Debug for IdentityProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Show only the fingerprint of the presented key; never the signature.
        let fp = CompositePublicKey::from_bytes(&self.identity_pub)
            .map(|k| k.fingerprint())
            .unwrap_or_default();
        f.debug_struct("IdentityProof")
            .field("fingerprint", &crate::hash::Hex(&fp))
            .finish_non_exhaustive()
    }
}

impl IdentityProof {
    /// Produce this party's proof: sign `"vox/join-pop/v1" ‖ sid ‖ transcript_hash`
    /// with the composite root signer (ADR-002) and attach the identity public key.
    pub fn create(root: &dyn RootSigner, sid: &[u8], transcript_hash: &Digest32) -> Result<Self> {
        let sig = root.sign(&signing_input(sid, transcript_hash))?;
        Ok(Self {
            identity_pub: root.public_key().to_bytes(),
            signature: sig.to_bytes(),
        })
    }

    /// The fingerprint of the presented identity key (ADR-002).
    pub fn fingerprint(&self) -> Result<Digest32> {
        Ok(CompositePublicKey::from_bytes(&self.identity_pub)?.fingerprint())
    }

    /// Serialize as `identity_pub(1984) ‖ signature(3373)` — both fixed-length, so
    /// no framing is needed. This is the plaintext that [`seal_pop`] encrypts.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COMPOSITE_PUB_LEN + COMPOSITE_SIG_LEN);
        out.extend_from_slice(&self.identity_pub);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse the fixed-length encoding produced by [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != COMPOSITE_PUB_LEN + COMPOSITE_SIG_LEN {
            return Err(Error::JoinProofFailed);
        }
        let mut identity_pub = [0u8; COMPOSITE_PUB_LEN];
        identity_pub.copy_from_slice(&bytes[..COMPOSITE_PUB_LEN]);
        let mut signature = [0u8; COMPOSITE_SIG_LEN];
        signature.copy_from_slice(&bytes[COMPOSITE_PUB_LEN..]);
        Ok(Self {
            identity_pub,
            signature,
        })
    }
}

/// Derive the PoP-sealing AEAD key from the CPace ISK:
/// `K_pop = HKDF-SHA-256(ISK, info = "vox/cpace-pop/v1")` (ADR-005).
#[must_use]
pub fn derive_pop_key(isk: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, isk);
    let mut key = [0u8; 32];
    // HKDF-Expand with a 32-byte OKM never fails for SHA-256; map defensively.
    if hk.expand(POP_SEAL_DOMAIN.as_bytes(), &mut key).is_err() {
        key = [0u8; 32];
    }
    key
}

/// Seal an [`IdentityProof`] under an already-derived `K_pop` (see
/// [`derive_pop_key`]): `nonce(12) ‖ AES-256-GCM(K_pop, nonce, proof_bytes)`
/// (ADR-005). A fresh random nonce is prepended so the two directions (which share
/// `K_pop`) never reuse a `(key, nonce)` pair. Use this when the caller already
/// holds `K_pop` (e.g. the join orchestration); [`seal_pop`] derives it from the
/// ISK for you.
pub fn seal_pop_with_key(key: &[u8; 32], proof: &IdentityProof) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::SigningFailed)?;
    let nonce_bytes = random_array::<POP_NONCE_LEN>()?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), proof.to_bytes().as_ref())
        .map_err(|_| Error::SigningFailed)?;
    let mut out = Vec::with_capacity(POP_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a PoP sealed by [`seal_pop_with_key`] under an already-derived `K_pop`. A
/// decryption failure (wrong key or tamper) collapses to [`Error::JoinProofFailed`],
/// like every other PoP-layer failure.
pub fn open_pop_with_key(key: &[u8; 32], sealed: &[u8]) -> Result<IdentityProof> {
    if sealed.len() < POP_NONCE_LEN {
        return Err(Error::JoinProofFailed);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::JoinProofFailed)?;
    let (nonce_bytes, ct) = sealed.split_at(POP_NONCE_LEN);
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| Error::JoinProofFailed)?;
    IdentityProof::from_bytes(&pt)
}

/// Seal an [`IdentityProof`] for transmission inside the CPace channel, deriving
/// `K_pop` from the CPace `isk` (ADR-005). Thin wrapper over [`derive_pop_key`] +
/// [`seal_pop_with_key`].
pub fn seal_pop(isk: &[u8], proof: &IdentityProof) -> Result<Vec<u8>> {
    seal_pop_with_key(&derive_pop_key(isk), proof)
}

/// Open a PoP sealed by [`seal_pop`], deriving `K_pop` from the CPace `isk`. Thin
/// wrapper over [`derive_pop_key`] + [`open_pop_with_key`].
pub fn open_pop(isk: &[u8], sealed: &[u8]) -> Result<IdentityProof> {
    open_pop_with_key(&derive_pop_key(isk), sealed)
}

/// The verified peer identity yielded by a successful PoP check: the composite
/// public key and its fingerprint, both now bound to *this* CPace run.
#[derive(Clone, Debug)]
pub struct JoinPeerIdentity {
    /// The peer's verified composite identity public key.
    pub identity: CompositePublicKey,
    /// The peer's identity fingerprint (matched against the expected one).
    pub fingerprint: Digest32,
}

/// Verify a peer's [`IdentityProof`] for this CPace run against the
/// `expected_fingerprint` (the identity the joiner intends to authenticate,
/// verified out-of-band per ADR-014).
///
/// Checks, in order, that the presented key parses, that its fingerprint equals
/// the expected one, and that the composite signature over
/// `"vox/join-pop/v1" ‖ sid ‖ transcript_hash` verifies. Any failure yields the
/// single [`Error::JoinProofFailed`] so a probe cannot distinguish the cases.
///
/// On success returns the verified [`JoinPeerIdentity`].
pub fn verify(
    proof: &IdentityProof,
    sid: &[u8],
    transcript_hash: &Digest32,
    expected_fingerprint: &Digest32,
) -> Result<JoinPeerIdentity> {
    let identity =
        CompositePublicKey::from_bytes(&proof.identity_pub).map_err(|_| Error::JoinProofFailed)?;
    let fingerprint = identity.fingerprint();
    // Fingerprint must match the expected identity. Use a constant-time compare so
    // the check does not leak how many leading bytes matched.
    use subtle::ConstantTimeEq;
    if fingerprint.ct_eq(expected_fingerprint).unwrap_u8() != 1 {
        return Err(Error::JoinProofFailed);
    }
    let signature =
        CompositeSignature::from_bytes(&proof.signature).map_err(|_| Error::JoinProofFailed)?;
    identity
        .verify(&signing_input(sid, transcript_hash), &signature)
        .map_err(|_| Error::JoinProofFailed)?;
    Ok(JoinPeerIdentity {
        identity,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    fn run(sid: &[u8], isk: &[u8]) -> (Digest32, [u8; 32], [u8; 32]) {
        let share_a = [0x11u8; 32];
        let share_b = [0x22u8; 32];
        let th = transcript_hash(sid, isk, &share_a, &share_b);
        (th, share_a, share_b)
    }

    #[test]
    fn honest_proof_verifies_and_binds_identity() {
        let root = signer(1, 2);
        let (th, _a, _b) = run(b"sid-1", b"isk-bytes-aaaa");
        let proof = IdentityProof::create(&root, b"sid-1", &th).unwrap();
        let peer = verify(&proof, b"sid-1", &th, &root.public_key().fingerprint()).unwrap();
        assert_eq!(peer.fingerprint, root.public_key().fingerprint());
        assert_eq!(peer.identity, root.public_key());
    }

    #[test]
    fn wrong_expected_fingerprint_rejected() {
        let root = signer(1, 2);
        let other = signer(3, 4);
        let (th, _a, _b) = run(b"sid", b"isk");
        let proof = IdentityProof::create(&root, b"sid", &th).unwrap();
        // The presenter is `root`, but the verifier expects `other`'s identity.
        assert!(matches!(
            verify(&proof, b"sid", &th, &other.public_key().fingerprint()),
            Err(Error::JoinProofFailed)
        ));
    }

    #[test]
    fn forged_signature_rejected() {
        let root = signer(1, 2);
        let (th, _a, _b) = run(b"sid", b"isk");
        let mut proof = IdentityProof::create(&root, b"sid", &th).unwrap();
        // Corrupt the Ed25519 half of the composite signature.
        proof.signature[0] ^= 0xff;
        assert!(matches!(
            verify(&proof, b"sid", &th, &root.public_key().fingerprint()),
            Err(Error::JoinProofFailed)
        ));
    }

    #[test]
    fn substituted_identity_key_rejected() {
        // An attacker presents its OWN key + a valid self-signature but claims the
        // victim's fingerprint: fingerprint mismatch ⇒ rejected. (Naming is not
        // possession.)
        let attacker = signer(9, 9);
        let victim = signer(1, 2);
        let (th, _a, _b) = run(b"sid", b"isk");
        let proof = IdentityProof::create(&attacker, b"sid", &th).unwrap();
        assert!(matches!(
            verify(&proof, b"sid", &th, &victim.public_key().fingerprint()),
            Err(Error::JoinProofFailed)
        ));
    }

    #[test]
    fn replay_across_runs_fails() {
        // A proof from run 1 (its sid + transcript hash) must not verify in run 2.
        let root = signer(1, 2);
        let (th1, _a, _b) = run(b"sid-1", b"isk-1");
        let proof1 = IdentityProof::create(&root, b"sid-1", &th1).unwrap();
        // Run 2 has a different sid and ISK ⇒ different transcript hash.
        let (th2, _a2, _b2) = run(b"sid-2", b"isk-2");
        assert!(matches!(
            verify(&proof1, b"sid-2", &th2, &root.public_key().fingerprint()),
            Err(Error::JoinProofFailed)
        ));
    }

    #[test]
    fn transcript_hash_is_symmetric_in_shares() {
        // Both parties must derive the same transcript hash regardless of which
        // share they call "own" vs "peer".
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        assert_eq!(
            transcript_hash(b"sid", b"isk", &a, &b),
            transcript_hash(b"sid", b"isk", &b, &a)
        );
    }

    #[test]
    fn transcript_hash_binds_isk_and_sid_and_shares() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let base = transcript_hash(b"sid", b"isk", &a, &b);
        assert_ne!(base, transcript_hash(b"sid2", b"isk", &a, &b));
        assert_ne!(base, transcript_hash(b"sid", b"isk2", &a, &b));
        let mut c = a;
        c[0] ^= 1;
        assert_ne!(base, transcript_hash(b"sid", b"isk", &c, &b));
    }

    #[test]
    fn proof_bytes_round_trip() {
        let root = signer(1, 2);
        let (th, _a, _b) = run(b"sid", b"isk");
        let proof = IdentityProof::create(&root, b"sid", &th).unwrap();
        let bytes = proof.to_bytes();
        assert_eq!(
            bytes.len(),
            crate::hash::COMPOSITE_PUB_LEN + crate::hash::COMPOSITE_SIG_LEN
        );
        let back = IdentityProof::from_bytes(&bytes).unwrap();
        assert_eq!(back.identity_pub, proof.identity_pub);
        assert_eq!(back.signature, proof.signature);
        // Wrong length is rejected.
        assert!(matches!(
            IdentityProof::from_bytes(&bytes[..bytes.len() - 1]),
            Err(Error::JoinProofFailed)
        ));
    }

    #[test]
    fn seal_open_round_trip_and_verifies() {
        let root = signer(1, 2);
        let (th, a, b) = run(b"sid", b"isk-shared-secret");
        let isk = b"isk-shared-secret";
        let proof = IdentityProof::create(&root, b"sid", &th).unwrap();
        let sealed = seal_pop(isk, &proof).unwrap();
        // Sealing hides the identity public key bytes (no plaintext pubkey on wire).
        assert!(sealed
            .windows(proof.identity_pub.len())
            .all(|w| w != proof.identity_pub));
        let opened = open_pop(isk, &sealed).unwrap();
        // The opened proof still verifies and binds the identity.
        let peer = verify(&opened, b"sid", &th, &root.public_key().fingerprint()).unwrap();
        assert_eq!(peer.fingerprint, root.public_key().fingerprint());
        let _ = (a, b);
    }

    #[test]
    fn seal_uses_fresh_nonce() {
        let root = signer(1, 2);
        let (th, _a, _b) = run(b"sid", b"k");
        let proof = IdentityProof::create(&root, b"sid", &th).unwrap();
        // Two seals of the same proof under the same key differ (random nonce), so
        // the shared-key two-direction exchange never reuses a (key, nonce) pair.
        assert_ne!(
            seal_pop(b"k", &proof).unwrap(),
            seal_pop(b"k", &proof).unwrap()
        );
    }

    #[test]
    fn open_with_wrong_isk_or_tamper_fails() {
        let root = signer(1, 2);
        let (th, _a, _b) = run(b"sid", b"k");
        let proof = IdentityProof::create(&root, b"sid", &th).unwrap();
        let mut sealed = seal_pop(b"isk-correct", &proof).unwrap();
        // Wrong ISK ⇒ wrong key ⇒ AEAD open fails.
        assert!(matches!(
            open_pop(b"isk-wrong", &sealed),
            Err(Error::JoinProofFailed)
        ));
        // Tampered ciphertext ⇒ AEAD open fails.
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(
            open_pop(b"isk-correct", &sealed),
            Err(Error::JoinProofFailed)
        ));
    }
}
