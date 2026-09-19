//! The profile: one identity plus its store (ADR-016 §"The `Node`", §"Persistence").
//!
//! A profile directory holds `vault.cbor` — the ADR-010 [`IdentityVault`] sealing
//! the [`IdentityBackup`] (root seeds, X25519 identity secret, `self_seed`,
//! OpenPGP fingerprint) under the identity passphrase — and `store.redb`. The
//! store's public `meta` carries the identity's composite fingerprint and creation
//! time so a *locked* profile can still show who it is.
//!
//! ## Lifecycle
//! `create` generates a native root (ADR-002 §GPG *Generate*: an
//! OpenPGP-representable Ed25519 key whose v4 fingerprint is recorded in the
//! backup), seals the vault under the production Argon2id profile, and opens the
//! store. `open` loads the sealed vault and the store and starts **locked**.
//! `unlock` derives the vault key and yields a [`VaultRootSigner`] held in memory;
//! `lock` drops it (its secrets zeroize on drop). Every operation that needs the
//! identity goes through [`Profile::signer`], which fails while locked — there is no
//! way to sign, derive or decrypt through a locked profile.
//!
//! The passphrase is taken as `&[u8]` and never retained; the UI keeps it in a
//! `SecretString` and drops it after the call (ADR-015).

use zeroize::Zeroizing;

use crate::atrest::sek::Argon2Profile;
use crate::atrest::vault::{IdentityVault, VaultRootSigner};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::identity::backup::{IdentityBackup, SelfSeed};
use crate::identity::composite::{RootSigner, SoftwareRootSigner};
use crate::identity::keyagreement::X25519IdentityKey;
use crate::identity::openpgp::ed25519_v4_fingerprint;
use crate::node::paths::{write_private_file, Paths};
use crate::node::store::Store;

const META_FINGERPRINT: &str = "identity_fingerprint";
const META_CREATED: &str = "identity_created";

/// An opened profile: sealed vault + store, and the unlocked identity when
/// unlocked.
pub struct Profile {
    paths: Paths,
    store: Store,
    vault: IdentityVault,
    fingerprint: Digest32,
    created: u64,
    unlocked: Option<VaultRootSigner>,
}

impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Profile")
            .field("fingerprint", &crate::hash::Hex(&self.fingerprint))
            .field("unlocked", &self.unlocked.is_some())
            .finish_non_exhaustive()
    }
}

impl Profile {
    /// Whether `paths` already holds an identity (a vault file).
    #[must_use]
    pub fn exists(paths: &Paths) -> bool {
        paths.vault_file().is_file()
    }

    /// Create a new identity in `paths`, sealed under `passphrase` with the
    /// production Argon2id profile, and open its store. Fails if an identity
    /// already exists (a profile is one identity; use another profile name).
    /// `now_secs` becomes the identity's creation time (and the OpenPGP key's).
    pub fn create(paths: Paths, passphrase: &[u8], now_secs: u64) -> Result<Self> {
        Self::create_with_profile(paths, passphrase, now_secs, Argon2Profile::default())
    }

    /// [`Profile::create`] with an explicit Argon2id profile (tests use the reduced
    /// one; production callers use [`Profile::create`]).
    pub fn create_with_profile(
        paths: Paths,
        passphrase: &[u8],
        now_secs: u64,
        argon2: Argon2Profile,
    ) -> Result<Self> {
        if Self::exists(&paths) {
            return Err(Error::Profile("identity already exists in this profile"));
        }
        let root = SoftwareRootSigner::generate()?;
        let dh = X25519IdentityKey::generate()?;
        let self_seed = SelfSeed::generate()?;
        let created_u32 = u32::try_from(now_secs)
            .map_err(|_| Error::Profile("creation time does not fit OpenPGP's 32-bit field"))?;
        let openpgp_fpr = ed25519_v4_fingerprint(&root.public_key().ed25519_bytes(), created_u32);
        let backup = IdentityBackup::new(&root, dh.secret_bytes(), &self_seed, &openpgp_fpr)?;
        let vault = IdentityVault::seal(&backup, passphrase, argon2)?;
        let fingerprint = root.fingerprint();
        // Persist: vault file first (0600, atomic), then the store with the public
        // facts. A crash between the two leaves a vault without meta, which `open`
        // repairs from the vault on the next unlock.
        write_private_file(&paths.vault_file(), &vault.to_canonical_vec())?;
        let store = Store::open(&paths.store_file())?;
        store.put_meta(META_FINGERPRINT, &fingerprint)?;
        store.put_meta(META_CREATED, &now_secs.to_be_bytes())?;
        let signer = VaultRootSigner::from_backup(&backup)?;
        drop(backup);
        Ok(Self {
            paths,
            store,
            vault,
            fingerprint,
            created: now_secs,
            unlocked: Some(signer),
        })
    }

    /// Open an existing profile, **locked**.
    pub fn open(paths: Paths) -> Result<Self> {
        let vault_path = paths.vault_file();
        if !vault_path.is_file() {
            return Err(Error::Profile("no identity in this profile"));
        }
        let bytes = std::fs::read(&vault_path).map_err(|e| Error::Path {
            op: "read vault",
            detail: format!("{}: {e}", vault_path.display()),
        })?;
        let vault = IdentityVault::from_canonical_slice(&bytes)?;
        let store = Store::open(&paths.store_file())?;
        let fingerprint: Digest32 = store
            .get_meta(META_FINGERPRINT)?
            .and_then(|v| v.as_slice().try_into().ok())
            .ok_or(Error::Profile("store is missing the identity fingerprint"))?;
        let created = store
            .get_meta(META_CREATED)?
            .and_then(|v| v.as_slice().try_into().ok().map(u64::from_be_bytes))
            .ok_or(Error::Profile(
                "store is missing the identity creation time",
            ))?;
        Ok(Self {
            paths,
            store,
            vault,
            fingerprint,
            created,
            unlocked: None,
        })
    }

    /// Unlock with the identity passphrase. A wrong passphrase (or a tampered
    /// vault) is [`Error::AtRestUnlockFailed`]; the profile stays locked.
    pub fn unlock(&mut self, passphrase: &[u8]) -> Result<()> {
        if self.unlocked.is_some() {
            return Ok(());
        }
        let signer = self.vault.unlock_signer(passphrase)?;
        if signer.fingerprint() != self.fingerprint {
            // The vault and the store disagree about who this is: refuse rather
            // than silently adopt either.
            return Err(Error::Profile("vault identity does not match the store"));
        }
        self.unlocked = Some(signer);
        Ok(())
    }

    /// Lock: drop the unlocked identity (its secrets zeroize on drop). Idempotent.
    pub fn lock(&mut self) {
        self.unlocked = None;
    }

    /// Whether the identity is unlocked.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.unlocked.is_some()
    }

    /// The unlocked root signer, or [`Error::Profile`] while locked.
    pub fn signer(&self) -> Result<&VaultRootSigner> {
        self.unlocked.as_ref().ok_or(Error::Profile("locked"))
    }

    /// The identity's composite fingerprint (public; available while locked).
    #[must_use]
    pub fn fingerprint(&self) -> Digest32 {
        self.fingerprint
    }

    /// The identity's creation time in seconds (public; available while locked).
    #[must_use]
    pub fn created(&self) -> u64 {
        self.created
    }

    /// The identity's OpenPGP v4 fingerprint (needs the unlocked backup's key;
    /// derived, never stored in plaintext meta).
    pub fn openpgp_fingerprint(&self) -> Result<Zeroizing<[u8; 20]>> {
        let signer = self.signer()?;
        let created = u32::try_from(self.created)
            .map_err(|_| Error::Profile("creation time does not fit OpenPGP's 32-bit field"))?;
        Ok(Zeroizing::new(ed25519_v4_fingerprint(
            &signer.public_key().ed25519_bytes(),
            created,
        )))
    }

    /// The profile's store.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Mutable access to the store (compaction).
    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    /// The profile's paths.
    #[must_use]
    pub fn paths(&self) -> &Paths {
        &self.paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atrest::sek::Argon2Profile;

    fn paths(tmp: &tempfile::TempDir) -> Paths {
        Paths::resolve("t", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap()
    }

    #[test]
    fn create_open_unlock_lock_and_survive_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let created =
            Profile::create_with_profile(p.clone(), b"pass", 1_700_000_000, Argon2Profile::REDUCED)
                .unwrap();
        assert!(created.is_unlocked());
        let fp = created.fingerprint();
        let sig = created.signer().unwrap().sign(b"hello").unwrap();
        assert!(created
            .signer()
            .unwrap()
            .public_key()
            .verify(b"hello", &sig)
            .is_ok());
        let pgp = *created.openpgp_fingerprint().unwrap();
        assert!(Profile::exists(&p));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(p.vault_file())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        drop(created);

        // "Restart": open from disk, locked.
        let mut opened = Profile::open(p.clone()).unwrap();
        assert!(!opened.is_unlocked());
        assert_eq!(opened.fingerprint(), fp);
        assert_eq!(opened.created(), 1_700_000_000);
        assert!(matches!(opened.signer(), Err(Error::Profile("locked"))));
        assert!(matches!(
            opened.openpgp_fingerprint(),
            Err(Error::Profile("locked"))
        ));
        // Wrong passphrase: still locked, collapsed error.
        assert!(matches!(
            opened.unlock(b"wrong"),
            Err(Error::AtRestUnlockFailed)
        ));
        assert!(!opened.is_unlocked());
        // Right passphrase: the same identity.
        opened.unlock(b"pass").unwrap();
        assert!(opened.is_unlocked());
        assert_eq!(opened.signer().unwrap().fingerprint(), fp);
        assert_eq!(*opened.openpgp_fingerprint().unwrap(), pgp);
        // The restored signer verifies the pre-restart signature.
        assert!(opened
            .signer()
            .unwrap()
            .public_key()
            .verify(b"hello", &sig)
            .is_ok());
        // Lock drops it.
        opened.lock();
        assert!(!opened.is_unlocked());
        assert!(matches!(opened.signer(), Err(Error::Profile("locked"))));
        // Unlock is idempotent once unlocked.
        opened.unlock(b"pass").unwrap();
        opened.unlock(b"pass").unwrap();
    }

    #[test]
    fn one_identity_per_profile_and_no_identity_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        assert!(!Profile::exists(&p));
        assert!(matches!(
            Profile::open(p.clone()),
            Err(Error::Profile("no identity in this profile"))
        ));
        let _a = Profile::create_with_profile(p.clone(), b"a", 1, Argon2Profile::REDUCED).unwrap();
        assert!(matches!(
            Profile::create_with_profile(p.clone(), b"b", 2, Argon2Profile::REDUCED),
            Err(Error::Profile("identity already exists in this profile"))
        ));
    }

    #[test]
    fn tampered_vault_does_not_unlock() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        drop(Profile::create_with_profile(p.clone(), b"pass", 1, Argon2Profile::REDUCED).unwrap());
        let mut bytes = std::fs::read(p.vault_file()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        write_private_file(&p.vault_file(), &bytes).unwrap();
        let mut opened = Profile::open(p).unwrap();
        assert!(matches!(
            opened.unlock(b"pass"),
            Err(Error::AtRestUnlockFailed)
        ));
        assert!(!opened.is_unlocked());
    }

    #[test]
    fn vault_and_store_must_agree_on_identity() {
        // Swap in another profile's vault: the fingerprint in meta no longer matches.
        let tmp = tempfile::tempdir().unwrap();
        let pa = Paths::resolve("a", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
        let pb = Paths::resolve("b", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
        drop(Profile::create_with_profile(pa.clone(), b"pass", 1, Argon2Profile::REDUCED).unwrap());
        drop(Profile::create_with_profile(pb.clone(), b"pass", 1, Argon2Profile::REDUCED).unwrap());
        std::fs::copy(pb.vault_file(), pa.vault_file()).unwrap();
        let mut opened = Profile::open(pa).unwrap();
        assert!(matches!(
            opened.unlock(b"pass"),
            Err(Error::Profile("vault identity does not match the store"))
        ));
        assert!(!opened.is_unlocked());
    }
}
