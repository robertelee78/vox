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

use std::sync::Arc;

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
    store: std::sync::Arc<Store>,
    vault: IdentityVault,
    fingerprint: Digest32,
    created: u64,
    unlocked: Option<Arc<VaultRootSigner>>,
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
        let store = std::sync::Arc::new(Store::open(&paths.store_file())?);
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
            unlocked: Some(Arc::new(signer)),
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
        // **Read-only while locked.** A locked profile only reads its public facts, and opening
        // the store writable writes to it — so a command refused for a wrong passphrase used to
        // leave the profile changed. It becomes writable in `unlock`, once the passphrase is
        // proved (see `store::Backing`).
        let store = std::sync::Arc::new(Store::open_read_only(&paths.store_file())?);
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
        // Only now, with the passphrase proved, may the profile be written.
        self.store.make_writable()?;
        self.unlocked = Some(Arc::new(signer));
        Ok(())
    }

    /// Check a passphrase against the vault **without changing any state**.
    ///
    /// [`Profile::unlock`] cannot be used for this: it short-circuits on an already
    /// unlocked profile and answers `Ok(())` for any passphrase at all. That is correct
    /// for unlocking — the work is already done — and useless as a check, which matters
    /// because a running daemon is always unlocked. Anything that needs to know the
    /// caller holds the passphrase must ask here.
    ///
    /// # Errors
    /// [`Error::AtRestUnlockFailed`] for a wrong passphrase or a tampered vault, and
    /// [`Error::Profile`] if the vault and the store disagree about the identity.
    pub fn verify_passphrase(&self, passphrase: &[u8]) -> Result<()> {
        self.passphrase_verifier().verify(passphrase)
    }

    /// What [`Profile::verify_passphrase`] needs, owned, so the check can run on a
    /// blocking thread: it is production Argon2id, and on the node's actor it stalled every
    /// post, read and sync on the node for as long as it took (V210-26).
    #[must_use]
    pub fn passphrase_verifier(&self) -> PassphraseVerifier {
        PassphraseVerifier {
            vault: self.vault.clone(),
            fingerprint: self.fingerprint,
        }
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
        self.unlocked.as_deref().ok_or(Error::Profile("locked"))
    }

    /// The unlocked root signer as a handle a **spawned task** can own, or
    /// [`Error::Profile`] while locked.
    ///
    /// [`Profile::signer`] hands out a borrow, which is right for anything running on the
    /// node's actor and useless for anything that must outlive the call — answering a join
    /// runs off the actor precisely so a joiner cannot stall the node, and it signs five
    /// times while it does (the challenge, the CPace accept, its own proof, the prekey-ring
    /// save and the join witness).
    ///
    /// # Zeroize
    /// This extends the signer's life past [`Profile::lock`] for as long as a holder keeps
    /// the handle, which ADR-015 otherwise forbids. The node therefore tracks the tasks it
    /// gives handles to and aborts them when it locks, so "locked" still means the secrets
    /// are gone rather than gone *soon*.
    pub fn signer_arc(&self) -> Result<Arc<VaultRootSigner>> {
        self.unlocked
            .as_ref()
            .map(Arc::clone)
            .ok_or(Error::Profile("locked"))
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

    /// A shared handle to the store, for work that must run on another thread (the
    /// ADR-008 sync engine is synchronous and runs on a blocking task, M14.7e).
    #[must_use]
    pub fn store_handle(&self) -> std::sync::Arc<Store> {
        std::sync::Arc::clone(&self.store)
    }

    /// Compact the store, which needs exclusive access. Returns `Ok(false)` without
    /// compacting if another handle is outstanding — a sync session holds one while
    /// it runs (M14.7e) — so compaction is attempted, never forced.
    pub fn compact_store(&mut self) -> Result<bool> {
        match std::sync::Arc::get_mut(&mut self.store) {
            Some(store) => store.compact(),
            None => Ok(false),
        }
    }

    /// The profile's paths.
    #[must_use]
    pub fn paths(&self) -> &Paths {
        &self.paths
    }
}

/// An owned passphrase check (see [`Profile::passphrase_verifier`]).
#[derive(Clone)]
pub struct PassphraseVerifier {
    vault: IdentityVault,
    fingerprint: Digest32,
}

impl PassphraseVerifier {
    /// Whether `passphrase` unlocks this identity's vault, and the vault is this identity.
    ///
    /// # Errors
    /// [`Error::AtRestUnlockFailed`] for a wrong passphrase or a tampered vault, and
    /// [`Error::Profile`] if the vault and the store disagree about the identity.
    pub fn verify(&self, passphrase: &[u8]) -> Result<()> {
        let signer = self.vault.unlock_signer(passphrase)?;
        if signer.fingerprint() != self.fingerprint {
            return Err(Error::Profile("vault identity does not match the store"));
        }
        Ok(())
    }
}
