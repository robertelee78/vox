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
/// The download-directory file inside a profile's **config** directory (PRD-001 R18): one
/// line naming where `vox room get` puts a collected file when no `--dir` or `--out` is
/// given. A leading `~/` means the home directory. Absent, it is `~/Downloads`.
pub const DOWNLOADS_FILE: &str = "downloads";

/// The config file saying which rooms `vox node` serves: `anyone` or `trusted` (its
/// `--serve` flag overrides it).
pub const SERVE_FILE: &str = "serve";
/// Directory of per-session read cursors inside a profile.
pub const CURSOR_DIR: &str = "cursors";
/// Where a harness session records how it can be woken (ADR-020 §6).
pub const SESSION_DIR: &str = "sessions";
/// The file inside a profile directory holding the UDP port this node first bound, so it binds
/// the same one on every start and members find it where they last saw it (V210-167).
pub const PORT_FILE: &str = "port";
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
    /// The fallback is `<tmp>/vox-<uid>/<16 hex>.sock`, where the hex is a digest of the
    /// profile directory. **Deterministic**, so a client computes the same path the
    /// daemon bound without being told, and distinct per profile, so two nodes never
    /// collide. It is only used when the natural path does not fit, so an ordinary
    /// profile keeps the socket beside its vault where the trust boundary already is.
    ///
    /// **The fallback is a directory private to this user, never the shared temp
    /// directory itself** (V210-72). It was `<tmp>/vox-<hex>.sock`, and on Linux `<tmp>` is
    /// `/tmp`, which every local user can write: another user could bind that predictable
    /// name first and be handed every passphrase a client sends, or plant a file there so
    /// the daemon could not start. [`prepare_socket_dir`] creates `vox-<uid>` `0700` and
    /// refuses one that is a symlink or belongs to someone else, and a client refuses a
    /// socket that is not this user's ([`check_socket_owner`]).
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
        let mut name = String::new();
        for byte in &digest[..8] {
            use std::fmt::Write as _;
            let _ = write!(name, "{byte:02x}");
        }
        name.push_str(".sock");
        socket_fallback_dir().join(name)
    }

    /// `<profile_dir>/port` ([`PORT_FILE`]).
    #[must_use]
    pub fn port_file(&self) -> PathBuf {
        self.profile_dir.join(PORT_FILE)
    }

    /// The anchors file for this profile ([`ANCHORS_FILE`]).
    #[must_use]
    pub fn anchors_file(&self) -> PathBuf {
        self.config_dir.join(ANCHORS_FILE)
    }

    /// Which rooms `vox node` serves, for this profile ([`SERVE_FILE`]).
    #[must_use]
    pub fn serve_file(&self) -> PathBuf {
        self.config_dir.join(SERVE_FILE)
    }

    /// The download-directory file for this profile ([`DOWNLOADS_FILE`]).
    #[must_use]
    pub fn downloads_file(&self) -> PathBuf {
        self.config_dir.join(DOWNLOADS_FILE)
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
///
/// **Two ids never share a name** (V210-79). Dropping characters alone made `agent.1` and
/// `agent1` — or any two ids alike past 96 characters, or any two made only of other
/// characters — one file: one session's drain then advanced the other's cursor, and the
/// other never saw what it skipped. An id that is already safe is kept as it is; any other
/// keeps a safe prefix and adds `~` (which no safe id contains) and a digest of the whole id.
fn sanitize(s: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    if !s.is_empty() && s.len() <= 96 && s.chars().all(safe) {
        return s.to_owned();
    }
    let digest = crate::hash::domain_hash("vox/path-component/v1", s.as_bytes());
    let mut out: String = s.chars().filter(|c| safe(*c)).take(64).collect();
    out.push('~');
    for b in &digest[..10] {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
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

/// This user's effective uid.
#[cfg(unix)]
#[must_use]
pub fn my_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// The directory a control socket goes in when the profile's own path is too long:
/// `<tmp>/vox-<uid>` (see [`Paths::socket_file`]).
fn socket_fallback_dir() -> PathBuf {
    #[cfg(unix)]
    let uid = my_uid();
    #[cfg(not(unix))]
    let uid = 0;
    std::env::temp_dir().join(format!("vox-{uid}"))
}

/// Make the directory `socket` is to be bound in private to this user, before binding.
///
/// The fallback directory lives in the shared temp directory, where another user can get
/// there first: it is created `0700`, and one that is a symlink, is not a directory, or
/// belongs to another user is **refused**, never used, because whoever owns the directory
/// can replace the socket in it. The profile's own directory is created `0700` by
/// [`Paths::resolve`], and is checked for its owner the same way.
///
/// # Errors
/// If the directory cannot be created, or is not this user's own.
#[cfg(unix)]
pub fn prepare_socket_dir(socket: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
    let Some(dir) = socket.parent() else {
        return Err(Error::Path {
            op: "control socket directory",
            detail: format!("{} has no parent directory", socket.display()),
        });
    };
    let fallback = dir == socket_fallback_dir();
    if fallback {
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(Error::Path {
                    op: "create control socket directory",
                    detail: format!("{}: {e}", dir.display()),
                })
            }
        }
    }
    // In the shared temp directory a symlink is refused rather than followed: it would let
    // whoever planted it choose which directory gets tightened and bound in.
    let meta = if fallback {
        std::fs::symlink_metadata(dir)
    } else {
        std::fs::metadata(dir)
    }
    .map_err(|e| Error::Path {
        op: "control socket directory",
        detail: format!("{}: {e}", dir.display()),
    })?;
    let me = my_uid();
    if !meta.file_type().is_dir() || meta.uid() != me {
        return Err(Error::Path {
            op: "control socket directory",
            detail: format!(
                "{} is not a directory owned by you (uid {me}); it is {} owned by uid {}. \
                 Refusing to put the control socket where another user could reach it — \
                 remove it, or use a shorter VOX_DATA_DIR",
                dir.display(),
                if meta.file_type().is_symlink() {
                    "a symlink"
                } else if meta.file_type().is_dir() {
                    "a directory"
                } else {
                    "a file"
                },
                meta.uid()
            ),
        });
    }
    if meta.mode() & 0o077 != 0 {
        set_mode(dir, 0o700, "chmod control socket directory")?;
    }
    Ok(())
}

/// Refuse to talk to a control socket that is not this user's own.
///
/// A client sends the socket passphrases, so before connecting it checks that what is at
/// `socket` is a socket, not a symlink, owned by this uid. Another user can create neither.
///
/// # Errors
/// If nothing is there ([`std::io::ErrorKind::NotFound`] in the detail), or it is not this
/// user's socket.
#[cfg(unix)]
pub fn check_socket_owner(socket: &Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    let meta = std::fs::symlink_metadata(socket).map_err(|e| Error::Path {
        op: "control socket",
        detail: format!("{}: {e}", socket.display()),
    })?;
    let me = my_uid();
    if meta.file_type().is_socket() && meta.uid() == me {
        return Ok(());
    }
    Err(Error::Path {
        op: "control socket",
        detail: format!(
            "{} is not a socket owned by you (uid {me}): it is {} owned by uid {}. Refusing to \
             send it anything",
            socket.display(),
            if meta.file_type().is_symlink() {
                "a symlink"
            } else if meta.file_type().is_socket() {
                "a socket"
            } else {
                "not a socket"
            },
            meta.uid()
        ),
    })
}

/// Write `bytes` to `path` atomically (temp file + rename) with mode `0600`, **durably**.
///
/// What this writes is what a person cannot get back: the identity vault and a headless node's
/// identity seeds. So (V210-55, #241):
/// - the temp file is created `0600` from its first byte, never at the umask's mode and
///   `chmod`ed after, which left a headless node's plaintext seeds readable by other local
///   users for a moment;
/// - its bytes are flushed to the device (`sync_all`, which on macOS is `F_FULLFSYNC`)
///   **before** the rename, or a power loss could leave the new name on an empty file and the
///   identity lost;
/// - the directory is flushed after the rename, so the rename itself survives a power loss.
///
/// A failure at any step leaves `path` as it was: the old file is replaced only by the rename,
/// and only once the new bytes are on the device.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let tmp = path.with_extension("tmp");
    let fail = |op: &'static str, at: &Path, e: std::io::Error| Error::Path {
        op,
        detail: format!("{}: {e}", at.display()),
    };
    // A temp file left by a crash may carry another mode: remove it, then create afresh.
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|e| fail("create file", &tmp, e))?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| fail("write file", &tmp, e));
    drop(file);
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        fail("rename file", path, e)
    })?;
    sync_dir(path)
}

/// Flush the directory holding `path`, so a rename into it is durable.
#[cfg(unix)]
pub(crate) fn sync_dir(path: &Path) -> Result<()> {
    let Some(dir) = path.parent() else {
        return Ok(());
    };
    let dir_file = std::fs::File::open(dir).map_err(|e| Error::Path {
        op: "open directory",
        detail: format!("{}: {e}", dir.display()),
    })?;
    match dir_file.sync_all() {
        Ok(()) => Ok(()),
        // Some filesystems cannot flush a directory handle (macOS's `F_FULLFSYNC` on a
        // directory may say so); the rename there is committed by the filesystem's own journal.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Unsupported
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(Error::Path {
            op: "sync directory",
            detail: format!("{}: {e}", dir.display()),
        }),
    }
}

#[cfg(not(unix))]
pub(crate) fn sync_dir(_path: &Path) -> Result<()> {
    Ok(())
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
