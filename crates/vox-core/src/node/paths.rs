//! Profile paths (ADR-016 §"Persistence: redb, sealed segments, XDG layout";
//! ADR-015 §"XDG-conformant layout").
//!
//! - config: `$XDG_CONFIG_HOME/vox/` (macOS: `~/Library/Application Support/vox/`)
//! - data:   `$XDG_DATA_HOME/vox/<profile>/` holding `vault.cbor` and `store.redb`
//!
//! Precedence (ADR-015), highest first: explicit override, then the
//! `VOX_CONFIG_DIR` / `VOX_DATA_DIR` env vars, then the XDG env vars, then the
//! platform default. Directories are created `0700` and files are created `0600`
//! on Unix; ADR-015 scopes clients to macOS + Linux, and on other platforms the
//! mode calls are no-ops (documented, not hidden).

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The vault file name inside a profile directory.
pub const VAULT_FILE: &str = "vault.cbor";
/// The store file name inside a profile directory.
pub const STORE_FILE: &str = "store.redb";
/// The ADR-020 §7 local control socket, inside the profile directory.
pub const SOCKET_FILE: &str = "node.sock";

/// The longest socket path we will use before falling back to a short one.
///
/// `sockaddr_un.sun_path` is 104 bytes on macOS and 108 on Linux, including the
/// terminator. 100 is under both with room to spare, and being conservative costs
/// nothing: the fallback is as good a socket, just less self-describing.
const SUN_PATH_BUDGET: usize = 100;
/// The anchors file inside a profile's **config** directory (ADR-017 decision 7, M17.4):
/// one `<fingerprint>@<multiaddr>` per line, `#` comments and blank lines ignored.
///
/// It lives in the config directory rather than the data directory because it is
/// configuration a person edits, not state the node owns — and it carries no secret: an
/// anchor spec is a public identity and a public address.
pub const ANCHORS_FILE: &str = "anchors";

/// The node's retention policy file (ADR-023 decision 2), in the config directory.
pub const RETENTION_FILE: &str = "retention";
/// The profile's settings file in the config directory: `key = value` lines, `#`
/// comments. Its first setting is `notify = off` (PRD-001 R37).
pub const CONFIG_FILE: &str = "config";
/// Directory of per-session read cursors inside a profile.
pub const CURSOR_DIR: &str = "cursors";
/// Where a harness session records how it can be woken (ADR-020 §6).
pub const SESSION_DIR: &str = "sessions";
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

    /// `<profile_dir>/node.sock` — the ADR-020 §7 local control socket.
    ///
    /// Per profile, so several nodes on one machine never contend for it, and
    /// inside the profile directory because that is already the trust boundary:
    /// whoever can open the socket can already read `vault.cbor` beside it.
    /// **Falls back to a short path when the profile's is too long.** A Unix socket
    /// address is a fixed-size buffer — 104 bytes on macOS, 108 on Linux — and a
    /// profile under a deep directory blows it. `vox daemon` then dies at startup
    /// with `path must be shorter than SUN_LEN`, which tells a person nothing about
    /// what to do, and the feature is simply unavailable on a path they chose for
    /// unrelated reasons.
    ///
    /// The fallback is `<tmp>/vox-<16 hex>.sock`, where the hex is a digest of the
    /// profile directory. **Deterministic**, so a client computes the same path the
    /// daemon bound without being told, and distinct per profile, so two nodes never
    /// collide. It is only used when the natural path does not fit, so an ordinary
    /// profile keeps the socket beside its vault where the trust boundary already is.
    #[must_use]
    pub fn socket_file(&self) -> PathBuf {
        let natural = self.profile_dir.join(SOCKET_FILE);
        if natural.as_os_str().len() < SUN_PATH_BUDGET {
            return natural;
        }
        let digest = crate::hash::domain_hash(
            "vox/control-socket/v1",
            self.profile_dir.as_os_str().as_encoded_bytes(),
        );
        let mut name = String::from("vox-");
        for byte in &digest[..8] {
            use std::fmt::Write as _;
            let _ = write!(name, "{byte:02x}");
        }
        name.push_str(".sock");
        std::env::temp_dir().join(name)
    }

    /// The settings file for this profile ([`CONFIG_FILE`]).
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join(CONFIG_FILE)
    }

    /// The anchors file for this profile ([`ANCHORS_FILE`]).
    #[must_use]
    pub fn anchors_file(&self) -> PathBuf {
        self.config_dir.join(ANCHORS_FILE)
    }

    /// The node's retention file for this profile ([`RETENTION_FILE`],
    /// [`crate::node::retention::RetentionConfig`]).
    #[must_use]
    pub fn retention_file(&self) -> PathBuf {
        self.config_dir.join(RETENTION_FILE)
    }

    /// Where an agent session's read cursor for one room is kept
    /// (`<profile_dir>/cursors/<room>-<session>`).
    ///
    /// Per session, because two agent sessions on one node have read different
    /// amounts and each must be told only what *it* has not seen. Beside the
    /// store rather than in the config directory: it is state, not configuration.
    ///
    /// The cursor is an ADR-008 entry hash, so it is not secret — it names a
    /// message without revealing it — but it lives in the private profile
    /// directory like everything else here.
    #[must_use]
    pub fn cursor_file(&self, room: &str, session: &str) -> PathBuf {
        self.profile_dir
            .join(CURSOR_DIR)
            .join(format!("{}-{}", sanitize(room), sanitize(session)))
    }

    /// The directory holding this profile's cursors.
    #[must_use]
    pub fn cursor_dir(&self) -> PathBuf {
        self.profile_dir.join(CURSOR_DIR)
    }

    /// Where a session records its wake channel.
    #[must_use]
    pub fn session_file(&self, session: &str) -> PathBuf {
        self.profile_dir
            .join(SESSION_DIR)
            .join(format!("{}.json", sanitize(session)))
    }

    /// The directory holding every session's wake channel.
    #[must_use]
    pub fn session_dir(&self) -> PathBuf {
        self.profile_dir.join(SESSION_DIR)
    }
}

/// Keep a session or room id to characters that cannot escape the cursor
/// directory. Ids are already base32 or uuid-shaped in practice; this is the
/// boundary check, not a formatting step, because the session id arrives from a
/// harness and is not ours to trust.
fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(96)
        .collect()
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
