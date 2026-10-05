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

/// The operation a failure to write the vault is reported as, so it is named as the vault's.
pub const VAULT_WRITE: &str = "write the identity file";

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
        Self::create_noting(paths, passphrase, now_secs, argon2, &|| {})
    }

    /// [`Profile::create_with_profile`], calling `waiting` once if another vox holds the
    /// profile's lock for longer than a second, so the caller can say so where its user will
    /// see it (see [`LockWaitNotice`]).
    pub fn create_noting(
        paths: Paths,
        passphrase: &[u8],
        now_secs: u64,
        argon2: Argon2Profile,
        waiting: LockWaitNotice<'_>,
    ) -> Result<Self> {
        // **One creation at a time per profile** (V210-91). Two `vox id`s started together
        // both saw no vault, and the second moved the first's store aside and renamed its own
        // vault over the first's: both printed a fingerprint, and one of them was gone. The
        // directory is locked across the whole create, so the check below and the files it
        // guards are one step; whoever comes second finds the vault and is refused — at once,
        // as soon as the vault is there, even while its maker goes on holding the lock (a TUI
        // keeps it for as long as it runs). The lock is then kept with the profile.
        let vault_file = paths.vault_file();
        let lock = lock_dir(
            &paths.profile_dir,
            "lock the node to create its identity",
            waiting,
            &|| {
                vault_file
                    .is_file()
                    .then_some(Error::Profile("identity already exists on this node"))
            },
        )?;
        if Self::exists(&paths) {
            return Err(Error::Profile("identity already exists on this node"));
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
        // Persist: the store with the public facts first, then the vault file (0600,
        // atomic), which is what makes the profile exist. A failure anywhere before the
        // vault leaves no identity, so creating again works; the other order left a vault
        // whose store had no fingerprint, which neither opens nor can be created over.
        //
        // **A store with no vault beside it is moved aside, never adopted** (V210-77).
        // Everything in it is sealed under the identity whose vault is gone, so the new one
        // could not open it — its prekeys, keyring and rooms would refuse every unlock. It is
        // kept, renamed, in case that vault turns up again.
        let store_file = paths.store_file();
        let mut aside = None;
        if store_file.exists() {
            // Never over another one kept aside: a rename replaces what is there.
            let mut to = store_file.with_extension(format!("redb.orphaned-{now_secs}"));
            let mut n = 1u32;
            while to.exists() {
                to = store_file.with_extension(format!("redb.orphaned-{now_secs}-{n}"));
                n += 1;
            }
            std::fs::rename(&store_file, &to).map_err(|e| Error::Path {
                op: "move aside a store with no vault",
                detail: format!("{} -> {}: {e}", store_file.display(), to.display()),
            })?;
            aside = Some(to);
        }
        // The store keeps a handle on the lock, so the lock outlives the store whatever holds it
        // last; this function keeps its own until it is done, failure cleanup included.
        let made = open_letting_go(|| Store::open(&store_file)).and_then(|store| {
            let store = std::sync::Arc::new(store.keep_lock(clone_lock(&lock)?));
            store.put_meta(META_FINGERPRINT, &fingerprint)?;
            store.put_meta(META_CREATED, &now_secs.to_be_bytes())?;
            // Named as the vault's, not the store's: it is the file a person would look for.
            write_private_file(&paths.vault_file(), &vault.to_canonical_vec()).map_err(
                |e| match e {
                    Error::Path { detail, .. } => Error::Path {
                        op: VAULT_WRITE,
                        detail,
                    },
                    other => other,
                },
            )?;
            Ok(store)
        });
        // **A failed attempt leaves nothing behind** (V210-77): the store it made holds only
        // the public facts of an identity that never existed, so it is removed, and a store it
        // moved aside goes back where it was, for the next attempt to move aside again. So is
        // the vault, if the failure came after its rename (the directory would not flush): a
        // vault left beside a removed or restored store is a profile that opens as nobody. It
        // is this attempt's own — creating refuses a profile that already has one.
        let store = match made {
            Ok(store) => store,
            Err(e) => {
                let _ = std::fs::remove_file(paths.vault_file());
                let _ = std::fs::remove_file(&store_file);
                if let Some(from) = aside {
                    let _ = std::fs::rename(&from, &store_file);
                }
                return Err(e);
            }
        };
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
        Self::open_noting(paths, &|| {})
    }

    /// [`Profile::open`], first taking the profile's lock ([`lock_profile`]) and keeping it for
    /// as long as the profile is open; `waiting` is called once if that takes over a second.
    pub fn open_noting(paths: Paths, waiting: LockWaitNotice<'_>) -> Result<Self> {
        if !paths.vault_file().is_file() {
            return Err(Error::Profile("no identity on this node"));
        }
        let lock = lock_profile(&paths, waiting)?;
        let vault = read_vault(&paths)?;
        // **Read-only while locked.** A locked profile only reads its public facts, and opening
        // the store writable writes to it — so a command refused for a wrong passphrase used to
        // leave the profile changed. It becomes writable in `unlock`, once the passphrase is
        // proved (see `store::Backing`).
        let store = std::sync::Arc::new(
            open_letting_go(|| Store::open_read_only(&paths.store_file()))?.keep_lock(lock),
        );
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
    ///
    pub fn unlock(&mut self, passphrase: &[u8]) -> Result<()> {
        if self.unlocked.is_some() {
            return Ok(());
        }
        let backup = self.vault.unlock(passphrase)?;
        let signer = VaultRootSigner::from_backup(&backup)?;
        if signer.fingerprint() != self.fingerprint {
            // The vault and the store disagree about who this is: refuse rather
            // than silently adopt either.
            return Err(Error::Profile("vault identity does not match the store"));
        }
        // Only now, with the passphrase proved, may the profile be written.
        self.store.make_writable()?;
        drop(backup);
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

/// Read and parse the profile's vault file.
fn read_vault(paths: &Paths) -> Result<IdentityVault> {
    let vault_path = paths.vault_file();
    let bytes = std::fs::read(&vault_path).map_err(|e| Error::Path {
        op: "read vault",
        detail: format!("{}: {e}", vault_path.display()),
    })?;
    IdentityVault::from_canonical_slice(&bytes)
}

/// Wait for the milliseconds named by the proof-only variable `env`, saying so on stderr so a
/// proof can tell the moment has been reached; nothing when it is unset.
#[cfg(feature = "test-knobs")]
pub(crate) fn test_pause(env: &str, what: &str) {
    let Some(ms) = std::env::var(env).ok().and_then(|v| v.parse::<u64>().ok()) else {
        return;
    };
    eprintln!("vox-test: {what} (waiting {ms} ms for {env})");
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

/// How long a vox waits for another one holding the profile before it is refused as
/// [`Error::ProfileBusy`] (V210-100): long enough for a command to finish — a production Argon2id
/// unlock and what follows it — so two started together both run, one after the other. A holder
/// that answers on the profile's control socket (a `vox daemon` or `vox tui`, which keep the
/// profile for as long as they run) is not waited for at all.
pub const PROFILE_PATIENCE: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a vox waits for another one's profile lock before saying that it is waiting.
pub const LOCK_PATIENCE: std::time::Duration = std::time::Duration::from_secs(1);

/// Take the profile directory's lock before opening its store, and hold it for as long as the
/// store is open (V210-100). **Every vox that opens a profile's store takes it first**: a
/// profile's node ([`Profile::open`]), its creation ([`Profile::create_noting`]) and a `vox node`
/// keeping its anchor logs in the profile's store.
///
/// Before, the store's own (redb) lock was the only one, and it refused rather than waited: of
/// two commands started together, the second was refused because the first had started first.
/// Now the second waits — saying so after a second, through `waiting` — and runs when the first
/// is done. It is refused, as [`Error::ProfileBusy`], only if the holder answers on the profile's
/// control socket (it is a daemon or a TUI, which do not finish) or after [`PROFILE_PATIENCE`].
///
/// # Errors
/// [`Error::ProfileBusy`] as above, or the lock cannot be taken at all.
pub fn lock_profile(paths: &Paths, waiting: LockWaitNotice<'_>) -> Result<std::fs::File> {
    let socket = paths.socket_file();
    lock_dir(
        &paths.profile_dir,
        "lock the node to open it",
        waiting,
        &|| (holder_serves(&socket) || attached_on_daemon(paths)).then_some(Error::ProfileBusy),
    )
}

/// Whether the account's daemon has this node attached (ADR-026): it holds the node for as long
/// as it stays attached, so a wait for its lock would be a wait until `vox node detach`.
fn attached_on_daemon(paths: &Paths) -> bool {
    let Some(name) = paths
        .profile_dir
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| crate::node::paths::NodeName::parse(n).ok())
    else {
        return false;
    };
    crate::node::daemonipc::attached_nodes(
        &paths.account().socket(),
        std::time::Duration::from_millis(500),
    )
    .contains(&name)
}

/// How long a vox that holds the profile's lock waits for a store that is still open elsewhere.
///
/// With the lock held, the only way to find the store open is another vox's process ending: a
/// store releases the lock only after it is closed, but a process that ends closes its files in
/// whatever order the kernel takes, and the lock's file can go first. That gap is a matter of
/// milliseconds, so this is short; a vox that still has the store open past it is not ending,
/// and is refused as [`Error::ProfileBusy`].
const LET_GO_PATIENCE: std::time::Duration = std::time::Duration::from_millis(500);

/// Open a profile's store with `open`, waiting up to half a second (`LET_GO_PATIENCE`) for another vox's
/// process that is ending to let go of it (V210-100).
pub fn open_letting_go<T>(open: impl Fn() -> Result<T>) -> Result<T> {
    let started = std::time::Instant::now();
    loop {
        match open() {
            Err(Error::ProfileBusy) if started.elapsed() < LET_GO_PATIENCE => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            other => return other,
        }
    }
}

/// Another handle on the same profile lock: the lock is released only when every handle is.
pub fn clone_lock(lock: &std::fs::File) -> Result<std::fs::File> {
    lock.try_clone().map_err(|e| Error::Path {
        op: "keep the node's lock",
        detail: e.to_string(),
    })
}

/// Whether a vox answers on the profile's control socket: a daemon or a TUI, which hold the
/// profile for as long as they run.
pub fn holder_serves(socket: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(socket).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = socket;
        false
    }
}

/// What a vox does when it has waited a second for another one's profile lock: called once,
/// while the wait goes on.
///
/// **The caller decides where the notice goes** (V210-100). It was printed to stderr from here,
/// and `vox tui` draws on the terminal stderr writes to: the line landed inside the TUI's screen,
/// across its prompt box, and stayed there. A CLI verb prints its words; a node that is already
/// running (the TUI, creating an identity) reports
/// [`NodeEvent::WaitingForProfile`](crate::node::api::NodeEvent::WaitingForProfile), which the
/// TUI puts in its status line.
pub type LockWaitNotice<'a> = &'a (dyn Fn() + Sync);

/// Take an exclusive lock on the directory `dir`, waiting for any other holder; it is released
/// when the returned handle drops (or the process exits, however it exits). `op` names what the
/// lock is for, in an error.
///
/// While it waits it asks `give_up` (each 50 ms) whether to stop waiting with that error, says it
/// is waiting through `waiting` once after [`LOCK_PATIENCE`], and stops with
/// [`Error::ProfileBusy`] after [`PROFILE_PATIENCE`]. It never waits without bound.
///
/// The directory itself is locked rather than a lock file beside the vault, so locking a
/// profile leaves no file behind that is not the profile's own.
fn lock_dir(
    dir: &std::path::Path,
    op: &'static str,
    waiting: LockWaitNotice<'_>,
    give_up: &dyn Fn() -> Option<Error>,
) -> Result<std::fs::File> {
    let fail = |e: std::io::Error| Error::Path {
        op,
        detail: format!("{}: {e}", dir.display()),
    };
    let handle = std::fs::File::open(dir).map_err(fail)?;
    let started = std::time::Instant::now();
    let mut said = false;
    loop {
        match handle.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::Error(e)) => return Err(fail(e)),
            Err(std::fs::TryLockError::WouldBlock) => {}
        }
        if let Some(e) = give_up() {
            return Err(e);
        }
        // **A wait is never silent** (V210-100): a holder that is stopped (Ctrl-Z) or slow holds
        // the profile for as long as it stays so, and a vox waiting with nothing on the screen
        // looked hung.
        if !said && started.elapsed() >= LOCK_PATIENCE {
            waiting();
            said = true;
        }
        if started.elapsed() >= PROFILE_PATIENCE {
            return Err(Error::ProfileBusy);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    #[cfg(feature = "test-knobs")]
    test_pause(TEST_LOCK_HOLD_ENV, "holding the node lock");
    Ok(handle)
}

/// **For proofs only.** When set, a vox that has just taken the profile lock (to create the
/// identity, or to migrate it) holds it this many milliseconds before going on, so a proof can
/// stop it while it holds the lock. Nothing a person runs sets it; unset, nothing changes. Not
/// compiled in without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_LOCK_HOLD_ENV: &str = "VOX_TEST_LOCK_HOLD_MS";

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
