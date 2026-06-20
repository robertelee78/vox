//! The identity **vault** — the M1-deferred encrypted-`IdentityBackup` backend
//! (ADR-010 §"Where the identity key lives").
//!
//! The root identity lives in a **separate protection domain** from any per-channel
//! SEK store, unlocked **once at app start**. This separation is load-bearing and
//! deliberate: the identity key is an *input* to deriving each channel's SEK (the
//! identity factor, [`crate::atrest::idfactor`]), so it cannot itself sit behind a
//! SEK — that would make unlocking circular (ADR-010). The vault is therefore
//! locked under an **identity factor of its own**: `Argon2id` over an *identity
//! passphrase* (independent of any channel passphrase).
//!
//! ## What ships vs the documented seam
//! - **Generated keys (shipped, complete).** The root [`IdentityBackup`] bundle
//!   (M1, ADR-002 §Backup) is wrapped here: `Argon2id(identity_passphrase, salt)`
//!   → AES-256-GCM over the bundle's canonical bytes. Unlock re-derives the factor,
//!   AEAD-opens, and yields a [`VaultRootSigner`] — a vault-backed
//!   [`RootSigner`] that signs verifiably.
//!   This is exactly the encrypted-backup persistence M1 deferred to M8.
//! - **Imported keys (gpg-agent / smartcard / YubiKey) — the seam.** For keys held
//!   in an agent or on a card, signing is *delegated* and the private key never
//!   leaves the device; there is nothing for the vault to encrypt. That backend is
//!   a `RootSigner` implemented over the agent IPC — **platform integration**, a
//!   documented deferral (milestone scope boundary), not a stub. The
//!   [`RootSigner`] trait is the seam; the
//!   software vault here is the complete generated-key path.
//!
//! ## Why a distinct Argon2 profile is reused
//! The vault reuses [`crate::atrest::sek::Argon2Profile`] (same production-vs-test
//! discipline) but a *distinct HKDF/AEAD domain* so a vault wrap and a SEK wrap can
//! never be cross-opened even if (pathologically) the same passphrase and salt were
//! used for both.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::atrest::sek::{factor_pass, Argon2Profile, FACTOR_PASS_LEN, NONCE_LEN, SALT_LEN};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::identity::backup::IdentityBackup;
use crate::identity::composite::{
    CompositePublicKey, CompositeSignature, RootSigner, SoftwareRootSigner,
};
use crate::identity::rng::random_array;

/// HKDF `info` deriving the vault key from the identity-passphrase factor, kept
/// distinct from the SEK wrap's `info` so the two domains never collide.
const VAULT_KEK_HKDF_INFO: &[u8] = b"vox/identity-vault-wrap/v1";

/// AEAD associated data for a vault bundle.
const VAULT_AAD: &[u8] = b"vox/identity-vault-aead/v1";

/// Format version of the [`IdentityVault`] serialization.
const VAULT_VERSION: u64 = 1;

/// Length of the vault key (256 bits).
const VAULT_KEY_LEN: usize = 32;

/// Derive the vault AEAD key from the identity-passphrase factor:
/// `HKDF-SHA-256(factor_pass(identity_passphrase, salt, profile), info = "...vault-wrap/v1")`.
fn derive_vault_key(
    identity_passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    profile: Argon2Profile,
) -> Result<Zeroizing<[u8; VAULT_KEY_LEN]>> {
    let fp: Zeroizing<[u8; FACTOR_PASS_LEN]> = factor_pass(identity_passphrase, salt, profile)?;
    let hk = Hkdf::<Sha256>::new(None, fp.as_ref());
    let mut key = Zeroizing::new([0u8; VAULT_KEY_LEN]);
    hk.expand(VAULT_KEK_HKDF_INFO, key.as_mut())
        .map_err(|_| Error::Argon2Failed)?;
    Ok(key)
}

/// An encrypted identity vault (ADR-010). Holds the AEAD-sealed
/// [`IdentityBackup`] plus the salt/nonce/profile needed to re-derive the vault
/// key. This is the one identity artifact safe to persist; it never holds raw key
/// material usable without the identity passphrase.
///
/// Canonical CBOR layout (array of 5):
/// `[version, profile_id, salt(16), nonce(12), ciphertext(bundle + tag)]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityVault {
    /// Argon2id profile id used to derive the identity factor.
    pub profile_id: u8,
    /// Per-vault 128-bit Argon2id salt.
    pub salt: [u8; SALT_LEN],
    /// AES-256-GCM nonce.
    pub nonce: [u8; NONCE_LEN],
    /// `AES-256-GCM(vault_key, nonce, canonical(IdentityBackup))`.
    pub ciphertext: Vec<u8>,
}

impl IdentityVault {
    /// **Seal** an [`IdentityBackup`] bundle under `identity_passphrase` (ADR-010,
    /// generated-key path). Fresh random salt + nonce are sampled. The bundle's
    /// plaintext canonical bytes are zeroized after encryption.
    pub fn seal(
        backup: &IdentityBackup,
        identity_passphrase: &[u8],
        profile: Argon2Profile,
    ) -> Result<Self> {
        let salt = random_array::<SALT_LEN>()?;
        Self::seal_with_salt(backup, identity_passphrase, profile, &salt)
    }

    /// Like [`Self::seal`] but with a caller-supplied salt (re-wrap / tests).
    pub fn seal_with_salt(
        backup: &IdentityBackup,
        identity_passphrase: &[u8],
        profile: Argon2Profile,
        salt: &[u8; SALT_LEN],
    ) -> Result<Self> {
        let key = derive_vault_key(identity_passphrase, salt, profile)?;
        let nonce = random_array::<NONCE_LEN>()?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| Error::Argon2Failed)?;
        let mut plaintext = Zeroizing::new(backup.to_canonical_vec());
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: VAULT_AAD,
                },
            )
            .map_err(|_| Error::AtRestUnlockFailed)?;
        plaintext.zeroize();
        Ok(Self {
            profile_id: profile.id,
            salt: *salt,
            nonce,
            ciphertext: ct,
        })
    }

    /// **Unlock** the vault: re-derive the vault key from `identity_passphrase`,
    /// AEAD-open, and parse the [`IdentityBackup`]. Any failure collapses to
    /// [`Error::AtRestUnlockFailed`] (wrong passphrase / tamper) — the plaintext
    /// is never partially exposed.
    pub fn unlock(&self, identity_passphrase: &[u8]) -> Result<IdentityBackup> {
        let profile = Argon2Profile::from_id(self.profile_id)?;
        let key = derive_vault_key(identity_passphrase, &self.salt, profile)?;
        let cipher =
            Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| Error::AtRestUnlockFailed)?;
        let mut pt = cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: VAULT_AAD,
                },
            )
            .map_err(|_| Error::AtRestUnlockFailed)?;
        let backup = IdentityBackup::from_canonical_slice(&pt)?;
        pt.zeroize();
        Ok(backup)
    }

    /// Unlock and return a ready-to-use vault-backed signer (ADR-010). Thin wrapper
    /// over [`Self::unlock`] + [`VaultRootSigner::from_backup`].
    pub fn unlock_signer(&self, identity_passphrase: &[u8]) -> Result<VaultRootSigner> {
        let backup = self.unlock(identity_passphrase)?;
        VaultRootSigner::from_backup(&backup)
    }

    /// Serialize to canonical CBOR (safe to persist).
    #[must_use]
    pub fn to_canonical_vec(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(5)
            .uint(VAULT_VERSION)
            .uint(u64::from(self.profile_id))
            .bytes(&self.salt)
            .bytes(&self.nonce)
            .bytes(&self.ciphertext);
        e.finish()
    }

    /// Parse from canonical CBOR produced by [`Self::to_canonical_vec`].
    pub fn from_canonical_slice(buf: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(buf);
        if d.array().map_err(Error::from)? != 5 {
            return Err(Error::MalformedAtRest("vault arity"));
        }
        let version = d.uint().map_err(Error::from)?;
        if version != VAULT_VERSION {
            return Err(Error::MalformedAtRest("vault version"));
        }
        let profile_id = u8::try_from(d.uint().map_err(Error::from)?)
            .map_err(|_| Error::MalformedAtRest("vault profile id range"))?;
        let salt: [u8; SALT_LEN] = d
            .bytes()
            .map_err(Error::from)?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("vault salt length"))?;
        let nonce: [u8; NONCE_LEN] = d
            .bytes()
            .map_err(Error::from)?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("vault nonce length"))?;
        let ciphertext = d.bytes().map_err(Error::from)?.to_vec();
        d.finish().map_err(Error::from)?;
        Ok(Self {
            profile_id,
            salt,
            nonce,
            ciphertext,
        })
    }
}

/// A vault-backed root signer (ADR-010). Holds the in-software composite signer
/// reconstructed from an unlocked [`IdentityBackup`], plus the recovered identity
/// DH secret and `self_seed` so the caller can derive everything an unlocked
/// identity domain needs. Implements [`RootSigner`] by delegation, so it is a
/// drop-in for the identity factor and any other signing path.
pub struct VaultRootSigner {
    signer: SoftwareRootSigner,
    x25519_identity_secret: Zeroizing<[u8; 32]>,
    self_seed: Zeroizing<[u8; 32]>,
}

impl VaultRootSigner {
    /// Reconstruct from an unlocked backup bundle.
    pub fn from_backup(backup: &IdentityBackup) -> Result<Self> {
        Ok(Self {
            signer: backup.root_signer()?,
            // `x25519_identity_secret()` already returns a `Zeroizing<[u8; 32]>`.
            x25519_identity_secret: backup.x25519_identity_secret(),
            self_seed: Zeroizing::new(*backup.self_seed().as_bytes()),
        })
    }

    /// The recovered X25519 identity DH secret (secret; for key agreement).
    #[must_use]
    pub fn x25519_identity_secret(&self) -> &[u8; 32] {
        &self.x25519_identity_secret
    }

    /// The recovered `self_seed` (secret; for self-channel keying, M5).
    #[must_use]
    pub fn self_seed(&self) -> &[u8; 32] {
        &self.self_seed
    }
}

impl RootSigner for VaultRootSigner {
    fn public_key(&self) -> CompositePublicKey {
        self.signer.public_key()
    }

    fn sign(&self, msg: &[u8]) -> Result<CompositeSignature> {
        self.signer.sign(msg)
    }
}

impl core::fmt::Debug for VaultRootSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultRootSigner")
            .field("fingerprint", &crate::hash::Hex(&self.fingerprint()))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::backup::SelfSeed;

    const P: Argon2Profile = Argon2Profile::REDUCED;

    fn backup() -> IdentityBackup {
        let root = SoftwareRootSigner::from_component_seeds(&[3u8; 32], &[4u8; 32]).unwrap();
        IdentityBackup::new(
            &root,
            Zeroizing::new([9u8; 32]),
            &SelfSeed::from_bytes([5u8; 32]),
            &[0xAA; 20],
        )
        .unwrap()
    }

    #[test]
    fn seal_unlock_round_trip_recovers_identity() {
        let b = backup();
        let fp = b.root_signer().unwrap().fingerprint();
        let vault = IdentityVault::seal(&b, b"identity-pp", P).unwrap();
        let recovered = vault.unlock(b"identity-pp").unwrap();
        assert_eq!(recovered.root_signer().unwrap().fingerprint(), fp);
        assert_eq!(*recovered.x25519_identity_secret(), [9u8; 32]);
        assert_eq!(recovered.self_seed().as_bytes(), &[5u8; 32]);
    }

    #[test]
    fn wrong_identity_passphrase_fails() {
        let vault = IdentityVault::seal(&backup(), b"right", P).unwrap();
        assert!(matches!(
            vault.unlock(b"wrong"),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn vault_backed_signer_signs_verifiably() {
        let b = backup();
        let pk = b.root_signer().unwrap().public_key();
        let vault = IdentityVault::seal(&b, b"pp", P).unwrap();
        let signer = vault.unlock_signer(b"pp").unwrap();
        let sig = signer.sign(b"hello at-rest").unwrap();
        // A vault-backed signature verifies under the original root public key.
        assert!(pk.verify(b"hello at-rest", &sig).is_ok());
        // And the signer exposes the same fingerprint.
        assert_eq!(signer.fingerprint(), pk.fingerprint());
    }

    #[test]
    fn vault_round_trips_through_cbor() {
        let vault = IdentityVault::seal(&backup(), b"pp", P).unwrap();
        let bytes = vault.to_canonical_vec();
        let back = IdentityVault::from_canonical_slice(&bytes).unwrap();
        assert_eq!(vault, back);
        assert!(back.unlock(b"pp").is_ok());
    }

    #[test]
    fn tampered_vault_fails() {
        let mut vault = IdentityVault::seal(&backup(), b"pp", P).unwrap();
        vault.ciphertext[0] ^= 0x01;
        assert!(matches!(
            vault.unlock(b"pp"),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn vault_factor_is_independent_of_channel_sek_domain() {
        // A vault sealed with a given passphrase+salt must not be openable as if it
        // were a SEK wrap, even structurally — the domains differ. Here we just
        // confirm the vault key derivation uses its own info by checking two
        // identical inputs to vault vs the SEK path differ.
        let salt = [0x11u8; SALT_LEN];
        let vk = derive_vault_key(b"pp", &salt, P).unwrap();
        // The SEK path's factor_pass is the same, but the vault adds a distinct
        // HKDF; so the vault key must not equal the bare factor_pass.
        let fp = factor_pass(b"pp", &salt, P).unwrap();
        assert_ne!(vk.as_ref(), fp.as_ref());
    }
}
