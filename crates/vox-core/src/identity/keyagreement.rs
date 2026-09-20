//! Key-agreement keys (ADR-002 §2) consumed by PQXDH (ADR-004).
//!
//! Three key kinds, all rooted in the composite identity (ADR-002 §1):
//!
//! 1. **X25519 identity DH key** ([`X25519IdentityKey`]) — the long-term DH key
//!    used in the DH legs of PQXDH.
//! 2. **Signed prekey** ([`SignedPrekey`]) — an X25519 key *and* an ML-KEM-768
//!    KEM keypair, both committed in one body and signed by the root. Rotated on
//!    a cadence (ADR-002 §Lifecycle); the previous one is retained one period to
//!    decrypt in-flight sessions (that retention policy is a higher-layer
//!    concern — this module provides the signed object and its verification).
//! 3. **One-time prekeys** ([`OneTimePrekeyPool`]) — a replenished pool of
//!    X25519 + ML-KEM-768 one-time keys, each root-signed, **consumed once** and
//!    never reused; a low-water-mark refill API keeps the pool stocked.
//!
//! ## Type-confusion prevention (ADR-003 requirement 1)
//! Every public component carries its ADR-003 class-prefixed algorithm ID in the
//! signed body (`X25519` = `0x0101`, `ML-KEM-768` = `0x0201`). The curve key and
//! the KEM key occupy distinct, algorithm-tagged fields, so a curve key can
//! never be parsed or substituted as a KEM key — the canonical-body decoders
//! reject an algorithm-ID in the wrong slot with [`Error::UnexpectedAlgo`]
//! (exercised by the `type_confusion_rejected_via_canonical_decode` test).
//!
//! ## Authenticated identity DH key
//! The long-term X25519 identity DH key is published as a **root-signed** record
//! ([`X25519IdentityKeyPublic`] / [`SignedIdentityDhKey`]) so ADR-004 PQXDH can
//! consume it as an authenticated `IK_B`; a bare, unsigned DH key would let an
//! active attacker substitute their own.
//!
//! ## Domain-separated signing input
//! These records are identity-layer artifacts, not log/wire structs, so they have
//! no tag in the ADR-008 `0x0001..0x0011` registry (like the GPG binding
//! statement, [`crate::identity::binding`]). They are signed under their own ASCII
//! domain labels prefixed directly onto the canonical-CBOR body:
//!
//! - identity DH key: [`IDENTITY_DH_KEY_DOMAIN`]
//! - signed prekey: [`SIGNED_PREKEY_DOMAIN`]
//! - one-time prekey: [`ONE_TIME_PREKEY_DOMAIN`]
//!
//! The signing input is `domain ‖ canonical_cbor_body` (the same shape as
//! [`crate::wire::signing_input`], but with an identity-layer label).

use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::ML_DSA_65_PUB_LEN;
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::identity::rng::random_array;
use crate::suite::algo;

/// Length of an X25519 public key.
pub const X25519_PUB_LEN: usize = 32;
/// Length of an ML-KEM-768 encapsulation (public) key.
pub const ML_KEM_768_ENCAPS_LEN: usize = 1184;

/// Domain label for the identity-DH-key signing input (ADR-002 §2).
pub const IDENTITY_DH_KEY_DOMAIN: &str = "vox/identity-dh-key/v1";
/// Domain label for the signed-prekey signing input (ADR-002 §2).
pub const SIGNED_PREKEY_DOMAIN: &str = "vox/signed-prekey/v1";
/// Domain label for the one-time-prekey signing input (ADR-002 §2).
pub const ONE_TIME_PREKEY_DOMAIN: &str = "vox/one-time-prekey/v1";

// ---------------------------------------------------------------------------
// ML-KEM-768 keypair wrapper
// ---------------------------------------------------------------------------

mod mlkem {
    //! Thin, fixed-byte-length wrapper over RustCrypto `ml-kem` for ML-KEM-768,
    //! exposing only the operations Vox needs (deterministic-from-seed keygen,
    //! public-key serialization). The shared-secret derivation used in the
    //! PQXDH handshake itself lives in ADR-004 (M2); here we only need the
    //! keypair and its public encapsulation key bytes.

    use ml_kem::{Kem, KeyExport, MlKem768, Seed as KemSeed};
    use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

    use super::ML_KEM_768_ENCAPS_LEN;
    use crate::error::{Error, Result};
    use crate::identity::rng::random_array;
    use crate::suite::algo;

    type DecapKey = <MlKem768 as Kem>::DecapsulationKey;
    type EncapKey = <MlKem768 as Kem>::EncapsulationKey;

    /// A 64-byte ML-KEM seed that zeroizes on drop. The expanded decapsulation
    /// key is re-derived from it on demand.
    #[derive(Clone, Zeroize, ZeroizeOnDrop)]
    pub(super) struct KemSeed64(pub(super) [u8; 64]);

    /// An ML-KEM-768 keypair, persisted as its 64-byte seed (the minimal secret).
    pub(super) struct MlKemKeypair {
        seed: KemSeed64,
    }

    impl MlKemKeypair {
        /// Generate a fresh keypair from the OS CSPRNG.
        pub(super) fn generate() -> Result<Self> {
            Ok(Self {
                seed: KemSeed64(random_array::<64>()?),
            })
        }

        /// Rebuild a keypair from its stored 64-byte seed (at-rest restore).
        pub(super) fn from_seed(seed: &[u8; 64]) -> Self {
            Self {
                seed: KemSeed64(*seed),
            }
        }

        /// The 64-byte seed (secret; for backup export and PQXDH reconstruction),
        /// in a non-`Copy` [`Zeroizing`] buffer.
        pub(super) fn seed_bytes(&self) -> Zeroizing<[u8; 64]> {
            Zeroizing::new(self.seed.0)
        }

        fn decap_key(&self) -> DecapKey {
            let seed: KemSeed = self.seed.0.into();
            <MlKem768 as Kem>::DecapsulationKey::from_seed(seed)
        }

        /// The 1184-byte encapsulation (public) key bytes.
        pub(super) fn encaps_public_bytes(&self) -> [u8; ML_KEM_768_ENCAPS_LEN] {
            let ek: EncapKey = self.decap_key().encapsulation_key().clone();
            let bytes = ek.to_bytes();
            let mut out = [0u8; ML_KEM_768_ENCAPS_LEN];
            out.copy_from_slice(bytes.as_slice());
            out
        }
    }

    /// Validate that `bytes` decode as an ML-KEM-768 encapsulation key, rejecting
    /// type-confused or malformed input with [`Error::InvalidKeyEncoding`].
    pub(super) fn validate_encaps_public(bytes: &[u8; ML_KEM_768_ENCAPS_LEN]) -> Result<()> {
        let key: ml_kem::Key<EncapKey> = (*bytes).into();
        EncapKey::new(&key).map_err(|_| Error::InvalidKeyEncoding {
            algo: algo::ML_KEM_768,
        })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// X25519 identity DH key
// ---------------------------------------------------------------------------

/// The long-term X25519 identity DH key (ADR-002 §2), used in PQXDH DH legs.
///
/// Stored as the 32-byte clamped secret (zeroized on drop via the dalek type);
/// the public key is derived on demand.
pub struct X25519IdentityKey {
    secret: XSecret,
}

impl X25519IdentityKey {
    /// Algorithm ID for this key (`0x0101`).
    pub const ALGO_ID: u16 = algo::X25519;

    /// Generate a fresh identity DH key from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut seed = random_array::<32>()?;
        let secret = XSecret::from(seed);
        seed.zeroize();
        Ok(Self { secret })
    }

    /// Reconstruct from a stored 32-byte secret (for backup restore).
    #[must_use]
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: XSecret::from(bytes),
        }
    }

    /// The 32-byte secret scalar (secret; for backup export and PQXDH), in a
    /// non-`Copy` [`Zeroizing`] buffer so no bare copy can linger at a call site.
    pub(crate) fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// The X25519 public key bytes.
    #[must_use]
    pub fn public_bytes(&self) -> [u8; X25519_PUB_LEN] {
        XPublic::from(&self.secret).to_bytes()
    }
}

/// The public, root-signed identity DH key record (ADR-002 §2): the long-term
/// X25519 IK_B that PQXDH (ADR-004) uses in its DH legs, authenticated by the
/// composite root so an initiator can bind the DH key to the verified identity.
///
/// Without this signature the identity DH key would be unauthenticated and an
/// active attacker could substitute their own IK_B; ADR-002 (the root signs
/// sub-keys) and ADR-004 (authenticated IK_B) both require it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519IdentityKeyPublic {
    /// Unix-seconds creation time, covered by the root signature.
    pub created: u64,
    /// X25519 identity DH public key bytes (algorithm `0x0101`).
    pub x25519_pub: [u8; X25519_PUB_LEN],
}

impl X25519IdentityKeyPublic {
    /// Canonical-CBOR body, fixed field order (ADR-008 array form):
    /// `[algo_x25519, x25519_pub, created]`.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3)
            .uint(u64::from(algo::X25519))
            .bytes(&self.x25519_pub)
            .uint(self.created);
        e.finish()
    }

    /// Domain-separated signing input `IDENTITY_DH_KEY_DOMAIN ‖ canonical_body`.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        let body = self.canonical_body();
        let mut out = Vec::with_capacity(IDENTITY_DH_KEY_DOMAIN.len() + body.len());
        out.extend_from_slice(IDENTITY_DH_KEY_DOMAIN.as_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Decode from a canonical body, rejecting an algorithm-ID mismatch
    /// (ADR-003 type confusion).
    pub fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 3 {
            return Err(Error::MalformedBundle("identity dh key arity"));
        }
        expect_algo(d.uint()?, algo::X25519)?;
        let x25519_pub = fixed_bytes(d.bytes()?, algo::X25519)?;
        let created = d.uint()?;
        d.finish()?;
        Ok(Self {
            created,
            x25519_pub,
        })
    }

    /// Verify that `root` signed this identity DH key.
    pub fn verify(&self, root: &CompositePublicKey, sig: &CompositeSignature) -> Result<()> {
        root.verify(&self.signing_input(), sig)
    }
}

/// An owner-held, root-signed identity DH key: the secret X25519 material, the
/// public record, and the composite root signature over it (ADR-002 §2).
pub struct SignedIdentityDhKey {
    public: X25519IdentityKeyPublic,
    signature: CompositeSignature,
    key: X25519IdentityKey,
}

impl SignedIdentityDhKey {
    /// Generate and root-sign a fresh identity DH key.
    pub fn generate(root: &dyn RootSigner, created: u64) -> Result<Self> {
        let key = X25519IdentityKey::generate()?;
        let public = X25519IdentityKeyPublic {
            created,
            x25519_pub: key.public_bytes(),
        };
        let signature = root.sign(&public.signing_input())?;
        Ok(Self {
            public,
            signature,
            key,
        })
    }

    /// Root-sign an existing identity DH key (e.g. the one carried in a backup).
    pub fn from_key(root: &dyn RootSigner, key: X25519IdentityKey, created: u64) -> Result<Self> {
        let public = X25519IdentityKeyPublic {
            created,
            x25519_pub: key.public_bytes(),
        };
        let signature = root.sign(&public.signing_input())?;
        Ok(Self {
            public,
            signature,
            key,
        })
    }

    /// Rebuild a stored signed identity DH key from its public record, the root
    /// signature over it and the secret key, checking that the secret derives
    /// exactly the recorded public key and that `root` signed the record.
    pub fn from_parts(
        root: &CompositePublicKey,
        public: X25519IdentityKeyPublic,
        signature: CompositeSignature,
        key: X25519IdentityKey,
    ) -> Result<Self> {
        if key.public_bytes() != public.x25519_pub {
            return Err(Error::MalformedBundle(
                "identity dh key secret/public mismatch",
            ));
        }
        public.verify(root, &signature)?;
        Ok(Self {
            public,
            signature,
            key,
        })
    }

    /// The public, signable record.
    #[must_use]
    pub fn public(&self) -> &X25519IdentityKeyPublic {
        &self.public
    }

    /// The secret-holding X25519 key (the PQXDH responder's `IK_B`).
    #[must_use]
    pub fn key(&self) -> &X25519IdentityKey {
        &self.key
    }

    /// The composite root signature over the public record.
    #[must_use]
    pub fn signature(&self) -> &CompositeSignature {
        &self.signature
    }

    /// The secret X25519 scalar (PQXDH responder input, ADR-004, M2), in a
    /// non-`Copy` [`Zeroizing`] buffer (wiped on drop).
    #[must_use]
    pub fn x25519_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.key.secret_bytes()
    }
}

// ---------------------------------------------------------------------------
// Signed prekey
// ---------------------------------------------------------------------------

/// The public, root-signed half of a signed prekey (ADR-002 §2): the data peers
/// fetch and verify before running PQXDH.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPrekeyPublic {
    /// Monotonic prekey id (for rotation/retention bookkeeping by higher layers).
    pub prekey_id: u64,
    /// Unix-seconds creation time (ADR-002 §2 "creation metadata").
    pub created: u64,
    /// X25519 public key bytes (algorithm `0x0101`).
    pub x25519_pub: [u8; X25519_PUB_LEN],
    /// ML-KEM-768 encapsulation key bytes (algorithm `0x0201`).
    pub ml_kem_pub: [u8; ML_KEM_768_ENCAPS_LEN],
}

impl SignedPrekeyPublic {
    /// Encode the canonical-CBOR body in fixed field order (ADR-008 array form):
    /// `[algo_x25519, algo_ml_kem, prekey_id, created, x25519_pub, ml_kem_pub]`.
    ///
    /// The two algorithm IDs are encoded explicitly so the signed bytes pin each
    /// component's type (ADR-003 type-confusion guard).
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(6)
            .uint(u64::from(algo::X25519))
            .uint(u64::from(algo::ML_KEM_768))
            .uint(self.prekey_id)
            .uint(self.created)
            .bytes(&self.x25519_pub)
            .bytes(&self.ml_kem_pub);
        e.finish()
    }

    /// The domain-separated signing input `SIGNED_PREKEY_DOMAIN ‖ canonical_body`.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        let body = self.canonical_body();
        let mut out = Vec::with_capacity(SIGNED_PREKEY_DOMAIN.len() + body.len());
        out.extend_from_slice(SIGNED_PREKEY_DOMAIN.as_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Verify that `root` signed this prekey. Returns [`Error::SignatureInvalid`]
    /// on failure and validates that both component public keys are well-formed
    /// for their algorithms (ADR-003 type-confusion guard).
    pub fn verify(&self, root: &CompositePublicKey, sig: &CompositeSignature) -> Result<()> {
        mlkem::validate_encaps_public(&self.ml_kem_pub)?;
        root.verify(&self.signing_input(), sig)
    }

    /// Decode from a canonical-CBOR body produced by [`canonical_body`](Self::canonical_body),
    /// rejecting any algorithm-ID mismatch (ADR-003 type confusion).
    pub fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 6 {
            return Err(Error::MalformedBundle("signed prekey arity"));
        }
        expect_algo(d.uint()?, algo::X25519)?;
        expect_algo(d.uint()?, algo::ML_KEM_768)?;
        let prekey_id = d.uint()?;
        let created = d.uint()?;
        let x25519_pub = fixed_bytes(d.bytes()?, algo::X25519)?;
        let ml_kem_pub = fixed_bytes_kem(d.bytes()?)?;
        d.finish()?;
        Ok(Self {
            prekey_id,
            created,
            x25519_pub,
            ml_kem_pub,
        })
    }
}

/// A signed prekey held by its owner: the secret X25519 + ML-KEM-768 material,
/// the public record, and the root signature over it (ADR-002 §2).
pub struct SignedPrekey {
    public: SignedPrekeyPublic,
    signature: CompositeSignature,
    x25519: X25519IdentityKey,
    ml_kem: mlkem::MlKemKeypair,
}

impl SignedPrekey {
    /// Generate and root-sign a fresh signed prekey.
    pub fn generate(root: &dyn RootSigner, prekey_id: u64, created: u64) -> Result<Self> {
        let x25519 = X25519IdentityKey::generate()?;
        let ml_kem = mlkem::MlKemKeypair::generate()?;
        let public = SignedPrekeyPublic {
            prekey_id,
            created,
            x25519_pub: x25519.public_bytes(),
            ml_kem_pub: ml_kem.encaps_public_bytes(),
        };
        let signature = root.sign(&public.signing_input())?;
        Ok(Self {
            public,
            signature,
            x25519,
            ml_kem,
        })
    }

    /// Rebuild a stored signed prekey from its public record, the root signature
    /// and its secrets, checking that the secrets derive exactly the recorded
    /// public keys and that `root` signed the record (at-rest restore).
    pub fn from_parts(
        root: &CompositePublicKey,
        public: SignedPrekeyPublic,
        signature: CompositeSignature,
        x25519_secret: &Zeroizing<[u8; 32]>,
        ml_kem_seed: &Zeroizing<[u8; 64]>,
    ) -> Result<Self> {
        let x25519 = X25519IdentityKey::from_secret_bytes(**x25519_secret);
        let ml_kem = mlkem::MlKemKeypair::from_seed(ml_kem_seed);
        if x25519.public_bytes() != public.x25519_pub
            || ml_kem.encaps_public_bytes() != public.ml_kem_pub
        {
            return Err(Error::MalformedBundle(
                "signed prekey secret/public mismatch",
            ));
        }
        public.verify(root, &signature)?;
        Ok(Self {
            public,
            signature,
            x25519,
            ml_kem,
        })
    }

    /// The public, signable record.
    #[must_use]
    pub fn public(&self) -> &SignedPrekeyPublic {
        &self.public
    }

    /// The root signature over the public record.
    #[must_use]
    pub fn signature(&self) -> &CompositeSignature {
        &self.signature
    }

    /// The secret X25519 scalar of this prekey.
    ///
    /// This is the responder-side private input PQXDH (ADR-004, M2) consumes to
    /// complete the handshake. Returned in a non-`Copy` [`Zeroizing`] buffer
    /// (wiped on drop).
    #[must_use]
    pub fn x25519_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.x25519.secret_bytes()
    }

    /// The secret ML-KEM-768 seed of this prekey (the responder-side KEM private
    /// input for PQXDH, ADR-004, M2), in a non-`Copy` [`Zeroizing`] buffer.
    #[must_use]
    pub fn ml_kem_seed_bytes(&self) -> Zeroizing<[u8; 64]> {
        self.ml_kem.seed_bytes()
    }
}

// ---------------------------------------------------------------------------
// One-time prekeys
// ---------------------------------------------------------------------------

/// The public, root-signed half of a one-time prekey (ADR-002 §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OneTimePrekeyPublic {
    /// One-time prekey id (unique within the pool).
    pub prekey_id: u64,
    /// Unix-seconds creation time (ADR-002 §2 "creation metadata"); covered by
    /// the root signature so a stale prekey cannot be silently re-dated.
    pub created: u64,
    /// X25519 public key bytes (algorithm `0x0101`).
    pub x25519_pub: [u8; X25519_PUB_LEN],
    /// ML-KEM-768 encapsulation key bytes (algorithm `0x0201`).
    pub ml_kem_pub: [u8; ML_KEM_768_ENCAPS_LEN],
}

impl OneTimePrekeyPublic {
    /// Canonical-CBOR body, fixed field order (ADR-008 array form):
    /// `[algo_x25519, algo_ml_kem, prekey_id, created, x25519_pub, ml_kem_pub]`.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(6)
            .uint(u64::from(algo::X25519))
            .uint(u64::from(algo::ML_KEM_768))
            .uint(self.prekey_id)
            .uint(self.created)
            .bytes(&self.x25519_pub)
            .bytes(&self.ml_kem_pub);
        e.finish()
    }

    /// Domain-separated signing input `ONE_TIME_PREKEY_DOMAIN ‖ canonical_body`.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        let body = self.canonical_body();
        let mut out = Vec::with_capacity(ONE_TIME_PREKEY_DOMAIN.len() + body.len());
        out.extend_from_slice(ONE_TIME_PREKEY_DOMAIN.as_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Decode from a canonical-CBOR body produced by [`canonical_body`](Self::canonical_body),
    /// rejecting any algorithm-ID mismatch (ADR-003 type confusion).
    pub fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 6 {
            return Err(Error::MalformedBundle("one-time prekey arity"));
        }
        expect_algo(d.uint()?, algo::X25519)?;
        expect_algo(d.uint()?, algo::ML_KEM_768)?;
        let prekey_id = d.uint()?;
        let created = d.uint()?;
        let x25519_pub = fixed_bytes(d.bytes()?, algo::X25519)?;
        let ml_kem_pub = fixed_bytes_kem(d.bytes()?)?;
        d.finish()?;
        Ok(Self {
            prekey_id,
            created,
            x25519_pub,
            ml_kem_pub,
        })
    }

    /// Verify the root signed this one-time prekey.
    pub fn verify(&self, root: &CompositePublicKey, sig: &CompositeSignature) -> Result<()> {
        mlkem::validate_encaps_public(&self.ml_kem_pub)?;
        root.verify(&self.signing_input(), sig)
    }
}

/// An owner-held one-time prekey: secret material, public record, root signature.
pub struct OneTimePrekey {
    public: OneTimePrekeyPublic,
    signature: CompositeSignature,
    x25519: X25519IdentityKey,
    ml_kem: mlkem::MlKemKeypair,
}

impl OneTimePrekey {
    /// Rebuild a stored one-time prekey from its public record, the root
    /// signature and its secrets, with the same checks as
    /// [`SignedPrekey::from_parts`].
    pub fn from_parts(
        root: &CompositePublicKey,
        public: OneTimePrekeyPublic,
        signature: CompositeSignature,
        x25519_secret: &Zeroizing<[u8; 32]>,
        ml_kem_seed: &Zeroizing<[u8; 64]>,
    ) -> Result<Self> {
        let x25519 = X25519IdentityKey::from_secret_bytes(**x25519_secret);
        let ml_kem = mlkem::MlKemKeypair::from_seed(ml_kem_seed);
        if x25519.public_bytes() != public.x25519_pub
            || ml_kem.encaps_public_bytes() != public.ml_kem_pub
        {
            return Err(Error::MalformedBundle(
                "one-time prekey secret/public mismatch",
            ));
        }
        public.verify(root, &signature)?;
        Ok(Self {
            public,
            signature,
            x25519,
            ml_kem,
        })
    }

    /// The public, signable record.
    #[must_use]
    pub fn public(&self) -> &OneTimePrekeyPublic {
        &self.public
    }

    /// The root signature over the public record.
    #[must_use]
    pub fn signature(&self) -> &CompositeSignature {
        &self.signature
    }

    /// The secret X25519 scalar of this one-time prekey (PQXDH responder input,
    /// ADR-004, M2), in a non-`Copy` [`Zeroizing`] buffer (wiped on drop).
    #[must_use]
    pub fn x25519_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.x25519.secret_bytes()
    }

    /// The secret ML-KEM-768 seed of this one-time prekey (PQXDH responder input,
    /// ADR-004, M2), in a non-`Copy` [`Zeroizing`] buffer.
    #[must_use]
    pub fn ml_kem_seed_bytes(&self) -> Zeroizing<[u8; 64]> {
        self.ml_kem.seed_bytes()
    }
}

/// A consume-once pool of one-time prekeys with low-water-mark refill (ADR-002 §2).
///
/// [`take`](Self::take) removes and returns a prekey so it can never be reused;
/// [`refill_to`](Self::refill_to) tops the pool back up to a target size when it
/// drops below a low-water mark. The pool assigns prekey ids monotonically from
/// an internal counter so ids are never reused even across refills.
pub struct OneTimePrekeyPool {
    prekeys: Vec<OneTimePrekey>,
    next_id: u64,
}

impl OneTimePrekeyPool {
    /// Create an empty pool starting prekey ids at `first_id`.
    #[must_use]
    pub fn new(first_id: u64) -> Self {
        Self {
            prekeys: Vec::new(),
            next_id: first_id,
        }
    }

    /// Generate a pool of `count` root-signed one-time prekeys, each stamped with
    /// `created` (Unix seconds), covered by the root signature.
    pub fn generate(
        root: &dyn RootSigner,
        count: usize,
        first_id: u64,
        created: u64,
    ) -> Result<Self> {
        let mut pool = Self::new(first_id);
        pool.add(root, count, created)?;
        Ok(pool)
    }

    /// Number of prekeys currently available.
    #[must_use]
    pub fn len(&self) -> usize {
        self.prekeys.len()
    }

    /// Whether the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prekeys.is_empty()
    }

    /// Append `count` freshly generated, root-signed one-time prekeys, each
    /// stamped with `created` (Unix seconds), covered by the root signature.
    pub fn add(&mut self, root: &dyn RootSigner, count: usize, created: u64) -> Result<()> {
        self.prekeys.reserve(count);
        for _ in 0..count {
            let prekey_id = self.next_id;
            self.next_id = self
                .next_id
                .checked_add(1)
                .ok_or(Error::MalformedBundle("prekey id overflow"))?;
            let x25519 = X25519IdentityKey::generate()?;
            let ml_kem = mlkem::MlKemKeypair::generate()?;
            let public = OneTimePrekeyPublic {
                prekey_id,
                created,
                x25519_pub: x25519.public_bytes(),
                ml_kem_pub: ml_kem.encaps_public_bytes(),
            };
            let signature = root.sign(&public.signing_input())?;
            self.prekeys.push(OneTimePrekey {
                public,
                signature,
                x25519,
                ml_kem,
            });
        }
        Ok(())
    }

    /// Refill the pool up to `target` if it has dropped to or below
    /// `low_water`. No-op when above the low-water mark. New prekeys are stamped
    /// with `created` (Unix seconds). Returns the number of prekeys added.
    pub fn refill_to(
        &mut self,
        root: &dyn RootSigner,
        low_water: usize,
        target: usize,
        created: u64,
    ) -> Result<usize> {
        if self.prekeys.len() > low_water || self.prekeys.len() >= target {
            return Ok(0);
        }
        let need = target - self.prekeys.len();
        self.add(root, need, created)?;
        Ok(need)
    }

    /// Remove and return one prekey, consuming it permanently. Returns
    /// [`Error::PrekeyPoolEmpty`] when exhausted (callers fall back to the signed
    /// last-resort prekey — never to no-prekey, ADR-002/ADR-004).
    pub fn take(&mut self) -> Result<OneTimePrekey> {
        self.prekeys.pop().ok_or(Error::PrekeyPoolEmpty)
    }

    /// Rebuild a pool from stored prekeys and the next id to assign (at-rest
    /// restore). Every stored id must be below `next_id` and unique, or the pool
    /// could re-issue an id that was already published.
    pub fn from_parts(next_id: u64, prekeys: Vec<OneTimePrekey>) -> Result<Self> {
        let mut seen = std::collections::HashSet::with_capacity(prekeys.len());
        for p in &prekeys {
            let id = p.public().prekey_id;
            if id >= next_id || !seen.insert(id) {
                return Err(Error::MalformedBundle("one-time prekey pool ids"));
            }
        }
        Ok(Self { prekeys, next_id })
    }

    /// The pooled prekeys, in pool order.
    pub fn iter(&self) -> impl Iterator<Item = &OneTimePrekey> {
        self.prekeys.iter()
    }

    /// The prekey with the lowest id — the one a bundle advertises next.
    #[must_use]
    pub fn first(&self) -> Option<&OneTimePrekey> {
        self.prekeys.iter().min_by_key(|p| p.public().prekey_id)
    }

    /// Consume the prekey with `prekey_id` (an inbound session used it; ADR-002
    /// "consumed once per inbound session and never reused"). `None` if it was
    /// never in the pool or was already consumed.
    pub fn take_by_id(&mut self, prekey_id: u64) -> Option<OneTimePrekey> {
        let i = self
            .prekeys
            .iter()
            .position(|p| p.public().prekey_id == prekey_id)?;
        Some(self.prekeys.swap_remove(i))
    }

    /// The next prekey id the pool will assign (for bookkeeping/tests).
    #[must_use]
    pub fn next_id(&self) -> u64 {
        self.next_id
    }
}

// ---------------------------------------------------------------------------
// Public prekey bundle (what an initiator fetches, ADR-004 §Prekey publication)
// ---------------------------------------------------------------------------

/// The public prekey bundle an initiator fetches from the rendezvous/log
/// (ADR-004): the root identity, the **root-signed identity DH key** (the
/// authenticated IK_B PQXDH consumes), the signed prekey (+ its signature), and
/// at most one one-time prekey (+ its signature). The KEM/DH secrets stay with
/// the owner; only public material is here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrekeyBundlePublic {
    /// The composite root public key bytes (1984 B).
    pub root_pub: [u8; crate::hash::COMPOSITE_PUB_LEN],
    /// The root-signed identity DH key record (authenticated IK_B for PQXDH).
    pub identity_dh_key: X25519IdentityKeyPublic,
    /// The root signature over the identity DH key.
    pub identity_dh_key_sig: [u8; crate::hash::COMPOSITE_SIG_LEN],
    /// The signed prekey public record.
    pub signed_prekey: SignedPrekeyPublic,
    /// The root signature over the signed prekey.
    pub signed_prekey_sig: [u8; crate::hash::COMPOSITE_SIG_LEN],
    /// An optional one-time prekey public record (absent when the pool is drained).
    pub one_time_prekey: Option<OneTimePrekeyPublic>,
    /// The root signature over the one-time prekey, present iff `one_time_prekey` is.
    pub one_time_prekey_sig: Option<[u8; crate::hash::COMPOSITE_SIG_LEN]>,
}

impl PrekeyBundlePublic {
    /// Verify every signature in the bundle against the embedded root key.
    ///
    /// Checks: the identity DH key is root-signed, the signed prekey is
    /// root-signed, and (if present) the one-time prekey is root-signed. The root
    /// key itself is trusted via fingerprint (ADR-002 §1) out of band — this
    /// method proves the bundle's keys belong to *that* root, not that the root
    /// is trusted.
    pub fn verify(&self) -> Result<()> {
        let root = CompositePublicKey::from_bytes(&self.root_pub)?;
        let idk_sig = CompositeSignature::from_bytes(&self.identity_dh_key_sig)?;
        self.identity_dh_key.verify(&root, &idk_sig)?;
        let spk_sig = CompositeSignature::from_bytes(&self.signed_prekey_sig)?;
        self.signed_prekey.verify(&root, &spk_sig)?;
        match (&self.one_time_prekey, &self.one_time_prekey_sig) {
            (Some(otp), Some(sig_bytes)) => {
                let sig = CompositeSignature::from_bytes(sig_bytes)?;
                otp.verify(&root, &sig)?;
            }
            (None, None) => {}
            _ => {
                return Err(Error::MalformedBundle(
                    "one-time prekey/sig presence mismatch",
                ))
            }
        }
        Ok(())
    }

    /// Canonical-CBOR encoding of the full public bundle, for embedding in other
    /// authenticated structs (e.g. the ADR-012 pre-join rendezvous record).
    ///
    /// Layout — arity `6` (no one-time prekey) or `8` (with one):
    /// `[ root_pub, identity_dh_key_body, identity_dh_key_sig,
    ///    signed_prekey_body, signed_prekey_sig, has_otp,
    ///    (one_time_prekey_body, one_time_prekey_sig)? ]`.
    ///
    /// Each component sub-record is embedded as the **byte string** of its own
    /// `canonical_body()` so the existing per-component strict decoders
    /// (`from_canonical_body`) recover it byte-for-byte. This is a plain
    /// serialization helper — it carries no domain tag of its own; the enclosing
    /// struct (the pre-join record) supplies the ADR-008 framing and signature.
    #[must_use]
    pub fn encode_canonical(&self) -> Vec<u8> {
        let has_otp = self.one_time_prekey.is_some() && self.one_time_prekey_sig.is_some();
        let mut e = Encoder::new();
        e.array(if has_otp { 8 } else { 6 })
            .bytes(&self.root_pub)
            .bytes(&self.identity_dh_key.canonical_body())
            .bytes(&self.identity_dh_key_sig)
            .bytes(&self.signed_prekey.canonical_body())
            .bytes(&self.signed_prekey_sig)
            .uint(u64::from(has_otp));
        if let (Some(otp), Some(sig)) = (&self.one_time_prekey, &self.one_time_prekey_sig) {
            e.bytes(&otp.canonical_body()).bytes(sig);
        }
        e.finish()
    }

    /// Strictly decode a [`PrekeyBundlePublic::encode_canonical`] body.
    ///
    /// Rejects a wrong arity, an `has_otp`/arity mismatch, wrong-length key or
    /// signature fields, or any trailing bytes. Does **not** verify the embedded
    /// signatures — call [`PrekeyBundlePublic::verify`] after decoding.
    pub fn decode_canonical(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        let arity = d.array()?;
        if arity != 6 && arity != 8 {
            return Err(Error::MalformedBundle("prekey-bundle arity"));
        }
        let root_pub: [u8; crate::hash::COMPOSITE_PUB_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("prekey-bundle root_pub length"))?;
        let identity_dh_key = X25519IdentityKeyPublic::from_canonical_body(d.bytes()?)?;
        let identity_dh_key_sig: [u8; crate::hash::COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("prekey-bundle identity_dh_key_sig length"))?;
        let signed_prekey = SignedPrekeyPublic::from_canonical_body(d.bytes()?)?;
        let signed_prekey_sig: [u8; crate::hash::COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("prekey-bundle signed_prekey_sig length"))?;
        let has_otp = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedBundle("prekey-bundle has_otp domain")),
        };
        if has_otp != (arity == 8) {
            return Err(Error::MalformedBundle(
                "prekey-bundle has_otp/arity mismatch",
            ));
        }
        let (one_time_prekey, one_time_prekey_sig) = if has_otp {
            let otp = OneTimePrekeyPublic::from_canonical_body(d.bytes()?)?;
            let sig: [u8; crate::hash::COMPOSITE_SIG_LEN] = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedBundle("prekey-bundle one_time_prekey_sig length"))?;
            (Some(otp), Some(sig))
        } else {
            (None, None)
        };
        d.finish()?;
        Ok(Self {
            root_pub,
            identity_dh_key,
            identity_dh_key_sig,
            signed_prekey,
            signed_prekey_sig,
            one_time_prekey,
            one_time_prekey_sig,
        })
    }
}

// ---------------------------------------------------------------------------
// Decode helpers
// ---------------------------------------------------------------------------

fn expect_algo(got: u64, expected: u16) -> Result<()> {
    let got16 = u16::try_from(got).map_err(|_| Error::UnknownAlgoId(u16::MAX))?;
    if got16 == expected {
        Ok(())
    } else {
        Err(Error::UnexpectedAlgo {
            got: got16,
            expected,
        })
    }
}

fn fixed_bytes(slice: &[u8], algo: u16) -> Result<[u8; X25519_PUB_LEN]> {
    slice
        .try_into()
        .map_err(|_| Error::InvalidKeyEncoding { algo })
}

fn fixed_bytes_kem(slice: &[u8]) -> Result<[u8; ML_KEM_768_ENCAPS_LEN]> {
    let arr: [u8; ML_KEM_768_ENCAPS_LEN] =
        slice.try_into().map_err(|_| Error::InvalidKeyEncoding {
            algo: algo::ML_KEM_768,
        })?;
    let _ = ML_DSA_65_PUB_LEN; // keep the import meaningful if layout consts shift
    Ok(arr)
}
