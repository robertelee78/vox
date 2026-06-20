//! The OpenPGP ↔ ML-DSA binding statement (ADR-002 §GPG integration).
//!
//! The root identity is an OpenPGP-representable Ed25519 key (ADR-002 §1). The
//! ML-DSA-65 co-key is a Vox-managed companion committed to the OpenPGP key via a
//! **signed binding statement**: a canonical-CBOR struct
//! `{ openpgp_fpr, mldsa_pub, created }`, signed by the OpenPGP Ed25519 primary.
//! The identity fingerprint `SHA-256(Ed25519_pub ‖ ML-DSA_pub)` (ADR-002 §1)
//! covers both keys, so the binding cannot be swapped without changing the
//! fingerprint peers verify; the binding statement makes the commitment explicit
//! and externally checkable against the OpenPGP key.
//!
//! ## Why this is not a wire/log struct
//! There is no struct tag for the binding statement in the ADR-008
//! `0x0001..0x0011` registry: it is an *identity-layer* artifact signed under its
//! own domain label, not a log/wire structure. It is therefore serialized as a
//! canonical-CBOR array (the same array discipline as signed structs, ADR-008)
//! and its signing input is the domain label prefixed directly onto that body —
//! `BINDING_DOMAIN ‖ canonical_body` — rather than going through
//! [`crate::wire::signing_input`] (which is keyed by a registered tag).
//!
//! ## Signing key
//! The statement is signed by the **OpenPGP Ed25519 primary key only** (the
//! classical key that PGP tooling and `gpg --verify` understand) — *not* the
//! composite key. That is deliberate: the binding's job is to let existing PGP
//! verifiers confirm "this PGP key vouches for this ML-DSA co-key," so the
//! signature must be a plain Ed25519 signature checkable with the OpenPGP key.

use ed25519_dalek::{
    Signature as EdSignature, Signer as _, SigningKey as EdSigningKey, Verifier as _,
    VerifyingKey as EdVerifyingKey,
};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{ED25519_SIG_LEN, ML_DSA_65_PUB_LEN};

/// OpenPGP v4 fingerprint length (SHA-1, 20 bytes). v5/v6 fingerprints are 32
/// bytes; this type carries the fingerprint as a variable-length byte string so
/// either applies, and the length is validated on parse against the two known
/// sizes.
pub const OPENPGP_V4_FPR_LEN: usize = 20;
/// OpenPGP v6 fingerprint length (SHA-256, 32 bytes).
pub const OPENPGP_V6_FPR_LEN: usize = 32;

/// Domain label for the binding-statement signing input (ADR-002 §GPG).
pub const BINDING_DOMAIN: &str = "vox/ml-dsa-binding/v1";

/// A signed OpenPGP ↔ ML-DSA binding statement (ADR-002 §GPG integration).
#[derive(Clone, PartialEq, Eq)]
pub struct GpgBindingStatement {
    /// The OpenPGP primary-key fingerprint (20 or 32 bytes).
    openpgp_fpr: Vec<u8>,
    /// The ML-DSA-65 co-key public bytes (1952 B).
    mldsa_pub: [u8; ML_DSA_65_PUB_LEN],
    /// Unix-seconds creation time.
    created: u64,
    /// The Ed25519 signature by the OpenPGP primary over `signing_input`.
    signature: [u8; ED25519_SIG_LEN],
}

impl GpgBindingStatement {
    /// Build and sign a binding statement with the OpenPGP Ed25519 primary key.
    ///
    /// `openpgp_signer` is the OpenPGP primary's Ed25519 signing key (in the
    /// `gpg-agent` delegation model of ADR-010 this would be replaced by an
    /// agent call; here we accept the in-software key, which is complete for a
    /// natively-generated identity per ADR-002 §GPG "Generate").
    pub fn build(
        openpgp_signer: &EdSigningKey,
        openpgp_fpr: &[u8],
        mldsa_pub: &[u8; ML_DSA_65_PUB_LEN],
        created: u64,
    ) -> Result<Self> {
        validate_fpr_len(openpgp_fpr)?;
        let body = canonical_body(openpgp_fpr, mldsa_pub, created);
        let si = signing_input(&body);
        let signature = openpgp_signer.sign(&si).to_bytes();
        Ok(Self {
            openpgp_fpr: openpgp_fpr.to_vec(),
            mldsa_pub: *mldsa_pub,
            created,
            signature,
        })
    }

    /// The OpenPGP primary-key fingerprint bytes.
    #[must_use]
    pub fn openpgp_fpr(&self) -> &[u8] {
        &self.openpgp_fpr
    }

    /// The ML-DSA-65 co-key public bytes.
    #[must_use]
    pub fn mldsa_pub(&self) -> &[u8; ML_DSA_65_PUB_LEN] {
        &self.mldsa_pub
    }

    /// The creation time (Unix seconds).
    #[must_use]
    pub fn created(&self) -> u64 {
        self.created
    }

    /// Verify the statement against the OpenPGP primary's Ed25519 public key,
    /// binding it to an `expected_fpr` the caller is trusting.
    ///
    /// Both conditions must hold: the statement's `openpgp_fpr` field equals
    /// `expected_fpr`, **and** the Ed25519 signature verifies under the binding
    /// domain. The fingerprint check closes a confused-deputy gap: without it one
    /// could verify with key A's signature while trusting fingerprint B, since the
    /// statement never otherwise proves its embedded fingerprint belongs to the
    /// verifying key. The caller is responsible for deriving `expected_fpr` from
    /// the OpenPGP key it actually trusts — computing the OpenPGP packet
    /// fingerprint from the key material is an OpenPGP-import concern owned by the
    /// vault/import path (ADR-010 / M8); this layer only enforces the equality and
    /// the signature.
    ///
    /// Returns [`Error::SignatureInvalid`] if the fingerprints differ or the
    /// signature does not verify (so a signature made for a different purpose /
    /// domain, or against a different fingerprint, cannot be replayed here).
    pub fn verify(&self, openpgp_pub: &EdVerifyingKey, expected_fpr: &[u8]) -> Result<()> {
        // Constant-time-ish equality is unnecessary here (the fingerprint is
        // public), but the check must precede returning Ok.
        if self.openpgp_fpr != expected_fpr {
            return Err(Error::SignatureInvalid);
        }
        let body = canonical_body(&self.openpgp_fpr, &self.mldsa_pub, self.created);
        let si = signing_input(&body);
        let sig = EdSignature::from_bytes(&self.signature);
        openpgp_pub
            .verify(&si, &sig)
            .map_err(|_| Error::SignatureInvalid)
    }

    /// Serialize the full statement (body + signature) to canonical CBOR for
    /// storage/transport. Layout (ADR-008 array form):
    /// `[openpgp_fpr, mldsa_pub, created, signature]`.
    #[must_use]
    pub fn to_canonical_vec(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .bytes(&self.openpgp_fpr)
            .bytes(&self.mldsa_pub)
            .uint(self.created)
            .bytes(&self.signature);
        e.finish()
    }

    /// Parse a statement previously produced by [`to_canonical_vec`](Self::to_canonical_vec).
    /// Does not verify the signature — call [`verify`](Self::verify) after parsing.
    pub fn from_canonical_slice(buf: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(buf);
        if d.array()? != 4 {
            return Err(Error::MalformedBundle("binding statement arity"));
        }
        let openpgp_fpr = d.bytes()?.to_vec();
        validate_fpr_len(&openpgp_fpr)?;
        let mldsa_pub: [u8; ML_DSA_65_PUB_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("binding mldsa_pub length"))?;
        let created = d.uint()?;
        let signature: [u8; ED25519_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("binding signature length"))?;
        d.finish()?;
        Ok(Self {
            openpgp_fpr,
            mldsa_pub,
            created,
            signature,
        })
    }
}

impl core::fmt::Debug for GpgBindingStatement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GpgBindingStatement")
            .field("openpgp_fpr", &crate::hash::Hex(&self.openpgp_fpr))
            .field("created", &self.created)
            .finish_non_exhaustive()
    }
}

/// Canonical-CBOR body (the signed part), fixed field order
/// `[openpgp_fpr, mldsa_pub, created]` (ADR-002 §GPG).
fn canonical_body(
    openpgp_fpr: &[u8],
    mldsa_pub: &[u8; ML_DSA_65_PUB_LEN],
    created: u64,
) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(3).bytes(openpgp_fpr).bytes(mldsa_pub).uint(created);
    e.finish()
}

/// The domain-separated signing input `BINDING_DOMAIN ‖ canonical_body`.
fn signing_input(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BINDING_DOMAIN.len() + body.len());
    out.extend_from_slice(BINDING_DOMAIN.as_bytes());
    out.extend_from_slice(body);
    out
}

fn validate_fpr_len(fpr: &[u8]) -> Result<()> {
    if fpr.len() == OPENPGP_V4_FPR_LEN || fpr.len() == OPENPGP_V6_FPR_LEN {
        Ok(())
    } else {
        Err(Error::MalformedBundle("openpgp fingerprint length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pgp_key() -> EdSigningKey {
        EdSigningKey::from_bytes(&[0x42u8; 32])
    }

    fn mldsa_pub() -> [u8; ML_DSA_65_PUB_LEN] {
        [0x11u8; ML_DSA_65_PUB_LEN]
    }

    #[test]
    fn build_verify_round_trip() {
        let signer = pgp_key();
        let fpr = [0xABu8; OPENPGP_V4_FPR_LEN];
        let stmt = GpgBindingStatement::build(&signer, &fpr, &mldsa_pub(), 1_700_000_000).unwrap();
        assert!(stmt.verify(&signer.verifying_key(), &fpr).is_ok());
    }

    #[test]
    fn verify_fails_for_wrong_pgp_key() {
        let signer = pgp_key();
        let other = EdSigningKey::from_bytes(&[0x07u8; 32]);
        let fpr = [0xABu8; OPENPGP_V6_FPR_LEN];
        let stmt = GpgBindingStatement::build(&signer, &fpr, &mldsa_pub(), 1).unwrap();
        assert!(matches!(
            stmt.verify(&other.verifying_key(), &fpr),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_fails_on_fingerprint_mismatch() {
        // The MED fix: verifying with key A's signature while trusting a DIFFERENT
        // fingerprint must fail, even though the signature itself is valid for the
        // statement's own (embedded) fingerprint.
        let signer = pgp_key();
        let fpr = [0xABu8; OPENPGP_V4_FPR_LEN];
        let stmt = GpgBindingStatement::build(&signer, &fpr, &mldsa_pub(), 1).unwrap();
        let trusted_but_different = [0xCDu8; OPENPGP_V4_FPR_LEN];
        assert!(matches!(
            stmt.verify(&signer.verifying_key(), &trusted_but_different),
            Err(Error::SignatureInvalid)
        ));
        // And the matching fingerprint still passes.
        assert!(stmt.verify(&signer.verifying_key(), &fpr).is_ok());
    }

    #[test]
    fn verify_fails_when_mldsa_pub_tampered() {
        let signer = pgp_key();
        let fpr = [0xABu8; OPENPGP_V4_FPR_LEN];
        let mut stmt = GpgBindingStatement::build(&signer, &fpr, &mldsa_pub(), 1).unwrap();
        stmt.mldsa_pub[0] ^= 0x01;
        assert!(matches!(
            stmt.verify(&signer.verifying_key(), &fpr),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_fails_when_fpr_tampered() {
        let signer = pgp_key();
        let fpr = [0xABu8; OPENPGP_V4_FPR_LEN];
        let mut stmt = GpgBindingStatement::build(&signer, &fpr, &mldsa_pub(), 1).unwrap();
        stmt.openpgp_fpr[0] ^= 0x01;
        // Verify against the ORIGINAL (untampered) fpr: the equality check itself
        // now rejects, before the signature is even examined.
        assert!(matches!(
            stmt.verify(&signer.verifying_key(), &fpr),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn wrong_domain_signature_is_rejected() {
        // A signature made over the *body* without the binding domain prefix must
        // not verify as a binding statement (domain separation is load-bearing).
        let signer = pgp_key();
        let fpr = [0xABu8; OPENPGP_V4_FPR_LEN];
        let mp = mldsa_pub();
        let body = canonical_body(&fpr, &mp, 5);
        // Sign the body WITHOUT the domain prefix (wrong domain).
        let wrong_sig = signer.sign(&body).to_bytes();
        let stmt = GpgBindingStatement {
            openpgp_fpr: fpr.to_vec(),
            mldsa_pub: mp,
            created: 5,
            signature: wrong_sig,
        };
        assert!(matches!(
            stmt.verify(&signer.verifying_key(), &fpr),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn canonical_round_trip() {
        let signer = pgp_key();
        let fpr = [0xCDu8; OPENPGP_V6_FPR_LEN];
        let stmt = GpgBindingStatement::build(&signer, &fpr, &mldsa_pub(), 99).unwrap();
        let bytes = stmt.to_canonical_vec();
        let back = GpgBindingStatement::from_canonical_slice(&bytes).unwrap();
        assert_eq!(stmt, back);
        assert!(back.verify(&signer.verifying_key(), &fpr).is_ok());
    }

    #[test]
    fn rejects_bad_fingerprint_length() {
        let signer = pgp_key();
        let bad_fpr = [0u8; 19]; // neither 20 nor 32
        assert!(matches!(
            GpgBindingStatement::build(&signer, &bad_fpr, &mldsa_pub(), 1),
            Err(Error::MalformedBundle(_))
        ));
    }

    #[test]
    fn parse_rejects_bad_fingerprint_length() {
        // A hand-built statement whose fpr field is neither 20 nor 32 bytes must be
        // rejected on parse (MED fix: validate length before accepting the field).
        let mut e = Encoder::new();
        e.array(4)
            .bytes(&[0u8; 19]) // bad fpr length
            .bytes(&mldsa_pub())
            .uint(1)
            .bytes(&[0u8; ED25519_SIG_LEN]);
        let bytes = e.finish();
        assert!(matches!(
            GpgBindingStatement::from_canonical_slice(&bytes),
            Err(Error::MalformedBundle(_))
        ));
    }
}
