//! The headless node's identity (ADR-016 `vox node`, M15.2a).
//!
//! A `vox node` is the user's always-on anchor: it serves the board, coordinates
//! punches, carries circuits and stores ciphertext, and it must come up on a box
//! with nobody at a keyboard. So its identity is not a vault behind a passphrase; it
//! is a **file-backed composite key** — two 32-byte seeds in a private file — from
//! which the same [`SoftwareRootSigner`] is rebuilt at every start, so peers can pin
//! its fingerprint once and keep pinning it.
//!
//! What that file protects is the anchor's *transport identity*: whoever holds it
//! can be this anchor. It protects no channel: the anchor holds no channel secret
//! (ADR-016: "can never decrypt"), so the file's compromise lets an attacker
//! impersonate the introducer, deny service, and read what any anchor reads —
//! ciphertext and rendezvous records — and nothing else.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::identity::composite::SoftwareRootSigner;
use crate::identity::rng::fill_random;
use crate::node::paths::{write_private_file, Paths};

/// The identity file's name inside the profile directory.
pub const IDENTITY_FILE: &str = "node-identity.key";

/// The file's exact size: the Ed25519 seed and the ML-DSA seed, 32 bytes each.
const IDENTITY_LEN: usize = 64;

/// The identity file for a headless node under `paths`.
#[must_use]
pub fn identity_file(paths: &Paths) -> PathBuf {
    paths.profile_dir.join(IDENTITY_FILE)
}

/// Load the headless identity, creating it — with fresh random seeds, in a file
/// only the owner can read — if there is none yet. A file of the wrong size is
/// refused rather than guessed at.
pub fn load_or_create_identity(paths: &Paths) -> Result<SoftwareRootSigner> {
    let path = identity_file(paths);
    let seeds = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut fresh = [0u8; IDENTITY_LEN];
            fill_random(&mut fresh)?;
            write_private_file(&path, &fresh)?;
            fresh.to_vec()
        }
        Err(e) => {
            return Err(Error::Path {
                op: "read node identity",
                detail: format!("{}: {e}", path.display()),
            })
        }
    };
    from_seeds(&seeds, &path)
}

fn from_seeds(seeds: &[u8], path: &Path) -> Result<SoftwareRootSigner> {
    if seeds.len() != IDENTITY_LEN {
        return Err(Error::Path {
            op: "read node identity",
            detail: format!("{}: not a node identity file", path.display()),
        });
    }
    let mut ed = [0u8; 32];
    let mut ml = [0u8; 32];
    ed.copy_from_slice(&seeds[..32]);
    ml.copy_from_slice(&seeds[32..]);
    SoftwareRootSigner::from_component_seeds(&ed, &ml)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::RootSigner;

    #[test]
    fn the_identity_is_created_once_and_rebuilt_identically() {
        let tmp = tempfile::tempdir().unwrap();
        let paths =
            Paths::resolve("node", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
        assert!(!identity_file(&paths).exists());
        let first = load_or_create_identity(&paths).unwrap();
        assert!(identity_file(&paths).exists());
        let again = load_or_create_identity(&paths).unwrap();
        assert_eq!(
            first.fingerprint(),
            again.fingerprint(),
            "the same identity every start"
        );
        // Two different profiles are two different anchors.
        let other =
            Paths::resolve("node2", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
        assert_ne!(
            load_or_create_identity(&other).unwrap().fingerprint(),
            first.fingerprint()
        );
        // A file that is not an identity is refused, not reinterpreted.
        std::fs::write(identity_file(&paths), b"nope").unwrap();
        assert!(load_or_create_identity(&paths).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(identity_file(&other))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "owner-only");
        }
    }
}
