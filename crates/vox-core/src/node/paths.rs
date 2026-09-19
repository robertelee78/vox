//! Profile paths (ADR-016 §"Persistence: redb, sealed segments, XDG layout";
//! ADR-015 §"XDG-conformant layout").
//!
//! - config: `$XDG_CONFIG_HOME/vox/` (macOS: `~/Library/Application Support/vox/`)
//! - data:   `$XDG_DATA_HOME/vox/<profile>/` holding `vault.cbor` and `store.redb`
//!
//! Precedence (ADR-015): explicit override > `VOX_CONFIG_DIR` / `VOX_DATA_DIR` env
//! > XDG env > platform default. Directories are created `0700` and files are
//! created `0600` on Unix; ADR-015 scopes clients to macOS + Linux, and on other
//! platforms the mode calls are no-ops (documented, not hidden).

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The vault file name inside a profile directory.
pub const VAULT_FILE: &str = "vault.cbor";
/// The store file name inside a profile directory.
pub const STORE_FILE: &str = "store.redb";
/// The default profile name.
pub const DEFAULT_PROFILE: &str = "default";

/// Resolved, created profile paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// `…/vox/` config directory (created).
    pub config_dir: PathBuf,
    /// `…/vox/<profile>/` data directory (created).
    pub profile_dir: PathBuf,
}

impl Paths {
    /// Resolve and create the directories for `profile`, honoring the ADR-015
    /// precedence. `data_override` / `config_override` are the CLI-flag layer.
    pub fn resolve(
        profile: &str,
        data_override: Option<&Path>,
        config_override: Option<&Path>,
    ) -> Result<Self> {
        if profile.is_empty() || profile.contains(['/', '\\']) || profile == "." || profile == ".."
        {
            return Err(Error::Path {
                op: "profile name",
                detail: "must be a single non-empty path component".into(),
            });
        }
        let data_root = match data_override {
            Some(p) => p.to_path_buf(),
            None => match std::env::var_os("VOX_DATA_DIR") {
                Some(v) => PathBuf::from(v),
                None => default_data_root()?,
            },
        };
        let config_dir = match config_override {
            Some(p) => p.to_path_buf(),
            None => match std::env::var_os("VOX_CONFIG_DIR") {
                Some(v) => PathBuf::from(v),
                None => default_config_root()?,
            },
        };
        let profile_dir = data_root.join(profile);
        create_private_dir(&data_root)?;
        create_private_dir(&profile_dir)?;
        create_private_dir(&config_dir)?;
        Ok(Self {
            config_dir,
            profile_dir,
        })
    }

    /// `<profile_dir>/vault.cbor`.
    #[must_use]
    pub fn vault_file(&self) -> PathBuf {
        self.profile_dir.join(VAULT_FILE)
    }

    /// `<profile_dir>/store.redb`.
    #[must_use]
    pub fn store_file(&self) -> PathBuf {
        self.profile_dir.join(STORE_FILE)
    }
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| Error::Path {
            op: "home directory",
            detail: "HOME is not set".into(),
        })
}

fn default_data_root() -> Result<PathBuf> {
    if let Some(v) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(v).join("vox"));
    }
    let home = home_dir()?;
    Ok(if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support").join("vox")
    } else {
        home.join(".local").join("share").join("vox")
    })
}

fn default_config_root() -> Result<PathBuf> {
    if let Some(v) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(v).join("vox"));
    }
    let home = home_dir()?;
    Ok(if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support").join("vox")
    } else {
        home.join(".config").join("vox")
    })
}

/// Create `dir` (and parents) and set it to `0700` on Unix.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| Error::Path {
        op: "create directory",
        detail: format!("{}: {e}", dir.display()),
    })?;
    set_mode(dir, 0o700, "chmod directory")
}

/// Write `bytes` to `path` atomically (temp file + rename) with mode `0600`.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| Error::Path {
        op: "write file",
        detail: format!("{}: {e}", tmp.display()),
    })?;
    set_mode(&tmp, 0o600, "chmod file")?;
    std::fs::rename(&tmp, path).map_err(|e| Error::Path {
        op: "rename file",
        detail: format!("{}: {e}", path.display()),
    })
}

/// Set an existing file to `0600` (used for the store file the engine creates).
pub(crate) fn set_private_file_mode(path: &Path) -> Result<()> {
    set_mode(path, 0o600, "chmod file")
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32, op: &'static str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| Error::Path {
        op,
        detail: format!("{}: {e}", path.display()),
    })
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32, _op: &'static str) -> Result<()> {
    // ADR-015 scopes clients to macOS + Linux; on other platforms the mode is
    // not enforced here and the caller's platform ACLs apply.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_wins_and_directories_are_private() {
        let tmp = tempfile::tempdir().unwrap();
        let p = Paths::resolve("alice", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
        assert_eq!(p.profile_dir, tmp.path().join("alice"));
        assert_eq!(p.config_dir, tmp.path().join("cfg"));
        assert!(p.profile_dir.is_dir() && p.config_dir.is_dir());
        assert_eq!(p.vault_file(), tmp.path().join("alice").join("vault.cbor"));
        assert_eq!(p.store_file(), tmp.path().join("alice").join("store.redb"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p.profile_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[test]
    fn profile_name_must_be_a_single_component() {
        let tmp = tempfile::tempdir().unwrap();
        for bad in ["", "..", ".", "a/b", "a\\b"] {
            assert!(matches!(
                Paths::resolve(bad, Some(tmp.path()), Some(tmp.path())),
                Err(Error::Path {
                    op: "profile name",
                    ..
                })
            ));
        }
    }

    #[test]
    fn private_file_is_0600_and_atomic() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("vault.cbor");
        write_private_file(&f, b"one").unwrap();
        write_private_file(&f, b"two").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"two");
        assert!(!f.with_extension("tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
