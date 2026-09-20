//! `self_seed` and the serializable identity-backup bundle (ADR-002 §Backup).
//!
//! ## `self_seed` (ADR-002 §Backup, ADR-008 self-channel)
//! A 256-bit CSPRNG secret generated once at identity creation. It keys the
//! personal self-channel (ADR-008 multi-device consent sync) and is a *private*
//! secret — never derived from the public identity key — so the self-channel
//! rendezvous is not locatable by third parties. This module **generates,
//! stores, and zeroizes** the seed; its *use* to key the self-channel is M5.
//!
//! ## Backup bundle (ADR-002 §Backup)
//! Backup of the root (and its OpenPGP representation) is the user's
//! responsibility; Vox provides an explicit, encrypted export. This module
//! defines the **plaintext data model and serialization** of that export — the
//! [`IdentityBackup`] bundle: the composite root seeds, the X25519 identity DH
//! secret, the `self_seed`, the OpenPGP representation reference, and the ML-DSA
//! co-key binding.
//!
//! ## Milestone boundary (ADR-010 / M8) — explicit, not a stub
//! The **at-rest double-lock encryption** of this bundle (passphrase →
//! Argon2id → AEAD, plus the second lock) is ADR-010, milestone M8. It is *not*
//! implemented here, by design: M8 owns the at-rest threat model, the KDF
//! parameters, and the vault format. What this module ships is complete up to
//! that boundary — a faithful, canonical, round-tripping serialization of the
//! secret-bearing bundle that M8 will encrypt. The bundle therefore carries raw
//! secret material and **must never be persisted unencrypted**; that contract is
//! the reason the type zeroizes on drop and its `Debug` reveals nothing.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::identity::composite::SoftwareRootSigner;

/// Length of the `self_seed` in bytes (256 bits, ADR-002 §Backup).
pub const SELF_SEED_LEN: usize = 32;

/// The personal `self_seed` (ADR-002 §Backup): a 256-bit private secret that keys
/// the self-channel (ADR-008). Zeroizes on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SelfSeed([u8; SELF_SEED_LEN]);

impl SelfSeed {
    /// Generate a fresh `self_seed` from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        Ok(Self(crate::identity::rng::random_array::<SELF_SEED_LEN>()?))
    }

    /// Reconstruct from stored bytes (e.g. on backup restore / device enrollment).
    #[must_use]
    pub fn from_bytes(bytes: [u8; SELF_SEED_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw seed bytes (secret; for self-channel keying in M5 and backup).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SELF_SEED_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for SelfSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never reveal the secret.
        f.write_str("SelfSeed(<redacted>)")
    }
}

/// Format version for the backup bundle serialization (independent of the wire
/// `FORMAT_VERSION`; this is an identity-vault artifact, ADR-010).
pub const BACKUP_BUNDLE_VERSION: u64 = 1;

/// The serializable identity-backup bundle (ADR-002 §Backup) — the plaintext that
/// M8 (ADR-010) will encrypt with the at-rest double lock.
///
/// Carries raw secret key material. Zeroizes on drop. **Never persist this
/// unencrypted** — serialize it only to hand to the M8 vault encryptor (or, in
/// tests, to verify the round-trip).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IdentityBackup {
    /// Ed25519 component seed of the composite root (32 B).
    ed25519_seed: [u8; 32],
    /// ML-DSA-65 component seed of the composite root (32 B).
    ml_dsa_seed: [u8; 32],
    /// X25519 identity DH secret scalar (32 B).
    x25519_identity_secret: [u8; 32],
    /// The `self_seed` (32 B).
    self_seed: [u8; SELF_SEED_LEN],
    /// Reference to the OpenPGP representation of the root: the primary-key
    /// fingerprint (20 or 32 B). The full OpenPGP key material itself is exported
    /// separately by `gpg`/the vault (ADR-002 §GPG, ADR-010); the bundle records
    /// the fingerprint so a restore can re-associate the two.
    #[zeroize(skip)]
    openpgp_fpr: Vec<u8>,
}

impl IdentityBackup {
    /// Assemble a backup bundle from the live identity material.
    ///
    /// Takes the in-software root signer (to extract its two component seeds),
    /// the X25519 identity DH secret, the `self_seed`, and the OpenPGP
    /// fingerprint reference.
    ///
    /// Validates the OpenPGP fingerprint length (v4 = 20 B or v6 = 32 B) at this
    /// boundary; an out-of-range fingerprint is rejected with
    /// [`Error::MalformedBundle`] rather than stored.
    pub fn new(
        root: &SoftwareRootSigner,
        x25519_identity_secret: Zeroizing<[u8; 32]>,
        self_seed: &SelfSeed,
        openpgp_fpr: &[u8],
    ) -> Result<Self> {
        validate_fpr_len(openpgp_fpr)?;
        Ok(Self {
            // The seed getters return `Zeroizing<[u8; 32]>` and the X25519 secret is
            // taken as a non-`Copy` `Zeroizing` too; deref-copy into the bundle's own
            // zeroize-on-drop fields. Every temporary `Zeroizing` wipes on drop, so no
            // bare secret copy lingers at this call site or the caller's.
            ed25519_seed: *root.ed25519_seed(),
            ml_dsa_seed: *root.ml_dsa_seed(),
            x25519_identity_secret: *x25519_identity_secret,
            self_seed: *self_seed.as_bytes(),
            openpgp_fpr: openpgp_fpr.to_vec(),
        })
    }

    /// Reconstruct the in-software root signer from the backup.
    pub fn root_signer(&self) -> Result<SoftwareRootSigner> {
        SoftwareRootSigner::from_component_seeds(&self.ed25519_seed, &self.ml_dsa_seed)
    }

    /// The recovered X25519 identity DH secret scalar.
    ///
    /// Returned in a [`Zeroizing`] buffer (non-`Copy`, wiped on drop) so a caller
    /// cannot leave a bare `[u8; 32]` secret copy lingering — it fully determines
    /// the identity DH secret (ADR-010 secret-hygiene audit).
    #[must_use]
    pub fn x25519_identity_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.x25519_identity_secret)
    }

    /// The recovered `self_seed`.
    #[must_use]
    pub fn self_seed(&self) -> SelfSeed {
        SelfSeed::from_bytes(self.self_seed)
    }

    /// The OpenPGP fingerprint reference.
    #[must_use]
    pub fn openpgp_fpr(&self) -> &[u8] {
        &self.openpgp_fpr
    }

    /// Serialize the bundle to canonical CBOR (the plaintext M8 will encrypt).
    /// Layout (ADR-008 array form):
    /// `[version, ed25519_seed, ml_dsa_seed, x25519_secret, self_seed, openpgp_fpr]`.
    ///
    /// The returned `Vec` holds secrets; callers must zeroize it after use.
    #[must_use]
    pub fn to_canonical_vec(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(6)
            .uint(BACKUP_BUNDLE_VERSION)
            .bytes(&self.ed25519_seed)
            .bytes(&self.ml_dsa_seed)
            .bytes(&self.x25519_identity_secret)
            .bytes(&self.self_seed)
            .bytes(&self.openpgp_fpr);
        e.finish()
    }

    /// Parse a bundle from canonical CBOR produced by
    /// [`to_canonical_vec`](Self::to_canonical_vec).
    pub fn from_canonical_slice(buf: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(buf);
        if d.array()? != 6 {
            return Err(Error::MalformedBundle("backup bundle arity"));
        }
        let version = d.uint()?;
        if version != BACKUP_BUNDLE_VERSION {
            return Err(Error::MalformedBundle("backup bundle version"));
        }
        // Each seed is bound as a non-`Copy` `Zeroizing` local, so no un-zeroized
        // Copy stack remnant survives the move into the (zeroize-on-drop) fields.
        let ed25519_seed = take32(&mut d, "ed25519_seed")?;
        let ml_dsa_seed = take32(&mut d, "ml_dsa_seed")?;
        let x25519_identity_secret = take32(&mut d, "x25519_secret")?;
        let self_seed = take32(&mut d, "self_seed")?;
        let fpr_slice = d.bytes()?;
        validate_fpr_len(fpr_slice)?;
        let openpgp_fpr = fpr_slice.to_vec();
        d.finish()?;
        Ok(Self {
            ed25519_seed: *ed25519_seed,
            ml_dsa_seed: *ml_dsa_seed,
            x25519_identity_secret: *x25519_identity_secret,
            self_seed: *self_seed,
            openpgp_fpr,
        })
    }
}

impl core::fmt::Debug for IdentityBackup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Reveal only the (non-secret) OpenPGP fingerprint reference.
        f.debug_struct("IdentityBackup")
            .field("openpgp_fpr", &crate::hash::Hex(&self.openpgp_fpr))
            .finish_non_exhaustive()
    }
}

fn take32(d: &mut Decoder<'_>, field: &'static str) -> Result<Zeroizing<[u8; 32]>> {
    let slice = d.bytes()?;
    if slice.len() != 32 {
        return Err(Error::MalformedBundle(field));
    }
    // Copy straight into the zeroizing buffer — no bare `[u8; 32]` Copy local.
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(slice);
    Ok(out)
}

/// Validate the OpenPGP fingerprint reference is exactly a v4 (20-byte) or v6
/// (32-byte) fingerprint, reusing the binding-layer length constants so the two
/// agree on the accepted sizes.
fn validate_fpr_len(fpr: &[u8]) -> Result<()> {
    use crate::identity::binding::{OPENPGP_V4_FPR_LEN, OPENPGP_V6_FPR_LEN};
    if fpr.len() == OPENPGP_V4_FPR_LEN || fpr.len() == OPENPGP_V6_FPR_LEN {
        Ok(())
    } else {
        Err(Error::MalformedBundle("backup openpgp fingerprint length"))
    }
}
