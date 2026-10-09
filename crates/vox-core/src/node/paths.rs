//! Profile paths (ADR-016 §"Persistence: redb, sealed segments, XDG layout";
//! ADR-015 §"XDG-conformant layout").
//!
//! - config: `$XDG_CONFIG_HOME/vox/` (macOS: `~/Library/Application Support/vox/`), the
//!   account's settings, read for any node that has no file of its own (ADR-026 F-2)
//! - data:   `$XDG_DATA_HOME/vox/` is the **data root** (ADR-026 F-1): `.daemon/` holds what is
//!   the daemon's (lock, socket, port, log, attach list, settings) and `nodes/<name>/` holds one
//!   node each — `vault.cbor` or `node-identity.key`, `store.redb`, its own `config/` directory,
//!   `cursors/` and `sessions/`. A data root holding a node's files outside `nodes/`
//!   (`<data root>/<name>/`) is refused, unchanged ([`crate::node::layout::refuse_old_layout`],
//!   #423).
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
/// The profile's settings file in the config directory: `key = value` lines, `#`
/// comments. Its first setting is `notify = off` (PRD-001 R37).
pub const CONFIG_FILE: &str = "config";

/// The node's retention policy file (ADR-023 decision 2), in the config directory.
pub const RETENTION_FILE: &str = "retention";

/// The config file saying how long a tunnel's bytes may wait to be taken before it is closed as
/// stuck (V030-11): one line, `600`, `600s`, `10m` or `1h`. Absent or unreadable, it is 10
/// minutes ([`STUCK_AFTER`](crate::tunnel::session::STUCK_AFTER)).
pub const TUNNEL_STUCK_FILE: &str = "tunnel-stuck-after";

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
/// The directory under the data root holding one directory per node (ADR-026 F-1).
pub const NODES_DIR: &str = "nodes";
/// The directory under the data root holding what is the daemon's, not any node's (ADR-026 F-1).
pub const DAEMON_DIR: &str = ".daemon";
/// A node's own settings directory, inside its node directory (ADR-026 F-1, F-2). It holds
/// today's config file names; a file missing here is read from the account's config directory.
pub const NODE_CONFIG_DIR: &str = "config";
/// The daemon's control socket, in `.daemon/` (ADR-026 C-1).
pub const DAEMON_SOCKET_FILE: &str = "vox.sock";
/// The daemon's lock, in `.daemon/` (ADR-026 D-1): held for the daemon's whole life.
pub const DAEMON_LOCK_FILE: &str = "lock";
/// The daemon's log, in `.daemon/` (ADR-026 S-2).
pub const DAEMON_LOG_FILE: &str = "log";
/// The nodes the daemon attaches when it starts, in `.daemon/` (ADR-026 L-4).
pub const DAEMON_ATTACH_FILE: &str = "attach";
/// `<data root>/.daemon/format`: the data root's format and the vox that last served it (ADR-026
/// F-3).
pub const FORMAT_FILE: &str = "format";
/// The longest node name, in bytes (ADR-026 N-1a).
pub const NODE_NAME_MAX: usize = 64;

/// A node's name (ADR-026 N-1a): one path component of 1–64 bytes from `[a-z0-9._-]`, not
/// starting with `.`, folded to lower case before use; `nodes` is refused (and `.daemon`, by
/// its leading dot), since both are directories of the data root.
///
/// **Folded, not refused, for upper case**, so `Alice` and `alice` are one node rather than two
/// directories that differ only on a case-sensitive filesystem — and the same directory on
/// macOS's default one, where two names would have shared one identity unseen.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeName(String);

impl NodeName {
    /// Parse and fold `s` (see [`NodeName`]).
    ///
    /// # Errors
    /// [`Error::Path`] saying which rule `s` breaks.
    pub fn parse(s: &str) -> Result<Self> {
        let folded = s.to_ascii_lowercase();
        let bad = |why: String| {
            Err(Error::Path {
                op: "node name",
                detail: format!("{s:?} {why}"),
            })
        };
        if folded.is_empty() || folded.len() > NODE_NAME_MAX {
            return bad(format!("must be 1 to {NODE_NAME_MAX} bytes long"));
        }
        if let Some(c) = folded.chars().find(|c| {
            !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
        }) {
            return bad(format!(
                "holds {c:?}; a node name is letters a-z, digits, '.', '_' and '-'"
            ));
        }
        if folded.starts_with('.') {
            return bad("must not start with '.'".into());
        }
        if folded == NODES_DIR {
            return bad(format!("is reserved: {NODES_DIR}/ holds the nodes"));
        }
        Ok(Self(folded))
    }

    /// The folded name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NodeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One OS account's Vox: its data root and its config directory (ADR-026 §7), resolved by the
/// ADR-015 precedence and **not created** by resolving, so asking which nodes an account holds
/// makes none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The data root: `.daemon/` and `nodes/` live here.
    pub data_root: PathBuf,
    /// The account's config directory, read for any setting a node has no file of its own for.
    pub config_dir: PathBuf,
}

impl Account {
    /// The account the overrides, the env vars or the platform default name.
    ///
    /// # Errors
    /// If neither an override, the env vars nor `HOME` names a directory.
    pub fn of(data_override: Option<&Path>, config_override: Option<&Path>) -> Result<Self> {
        let (data_root, config_dir) = roots(data_override, config_override)?;
        Ok(Self {
            data_root,
            config_dir,
        })
    }

    /// `<data root>/.daemon`.
    #[must_use]
    pub fn daemon_dir(&self) -> PathBuf {
        self.data_root.join(DAEMON_DIR)
    }

    /// `<data root>/.daemon/vox.sock`, or the short fallback when that path is too long (see
    /// [`socket_path_in`]).
    #[must_use]
    pub fn socket(&self) -> PathBuf {
        socket_path_in(&self.daemon_dir(), DAEMON_SOCKET_FILE)
    }

    /// `<data root>/.daemon/lock`.
    #[must_use]
    pub fn lock_file(&self) -> PathBuf {
        self.daemon_dir().join(DAEMON_LOCK_FILE)
    }

    /// `<data root>/.daemon/port`: the one UDP port of this data root (ADR-026 D-3).
    #[must_use]
    pub fn port_file(&self) -> PathBuf {
        self.daemon_dir().join(PORT_FILE)
    }

    /// `<data root>/.daemon/log`.
    #[must_use]
    pub fn log_file(&self) -> PathBuf {
        self.daemon_dir().join(DAEMON_LOG_FILE)
    }

    /// `<data root>/.daemon/attach`.
    #[must_use]
    pub fn attach_file(&self) -> PathBuf {
        self.daemon_dir().join(DAEMON_ATTACH_FILE)
    }

    /// `<data root>/.daemon/config`: the daemon's own settings (listen, metrics, relay limits).
    #[must_use]
    pub fn daemon_config_file(&self) -> PathBuf {
        self.daemon_dir().join(CONFIG_FILE)
    }

    /// `<data root>/nodes`.
    #[must_use]
    pub fn nodes_dir(&self) -> PathBuf {
        self.data_root.join(NODES_DIR)
    }

    /// `<data root>/nodes/<name>`, not created.
    #[must_use]
    pub fn node_dir(&self, name: &NodeName) -> PathBuf {
        self.nodes_dir().join(name.as_str())
    }

    /// Resolve and create `name`'s directories.
    ///
    /// # Errors
    /// If a directory cannot be created `0700`.
    pub fn node_paths(&self, name: &NodeName) -> Result<Paths> {
        let profile_dir = self.node_dir(name);
        create_private_dir(&self.data_root)?;
        create_private_dir(&self.nodes_dir())?;
        create_private_dir(&profile_dir)?;
        create_private_dir(&self.config_dir)?;
        Ok(Paths {
            config_dir: self.config_dir.clone(),
            profile_dir,
            data_root: self.data_root.clone(),
        })
    }

    /// Every node this account holds: each directory of `nodes/` with a valid name holding a
    /// vault or a headless key, sorted by name.
    #[must_use]
    pub fn nodes_on_disk(&self) -> Vec<NodeName> {
        let Ok(dir) = std::fs::read_dir(self.nodes_dir()) else {
            return Vec::new();
        };
        let mut out: Vec<NodeName> = dir
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                let p = e.path();
                p.join(VAULT_FILE).is_file()
                    || p.join(crate::node::headless::IDENTITY_FILE).is_file()
            })
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                NodeName::parse(&name).ok().filter(|n| n.as_str() == name)
            })
            .collect();
        out.sort();
        out
    }

    /// Take the account's lock now, or `None` if another process holds it (the daemon, which
    /// holds it for its whole life, ADR-026 D-1).
    ///
    /// # Errors
    /// If `.daemon/` or the lock cannot be made.
    pub fn try_lock(&self) -> Result<Option<std::fs::File>> {
        let file = self.open_lock()?;
        match file.try_lock() {
            Ok(()) => Ok(Some(file)),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(Error::Path {
                op: "take the account lock",
                detail: format!("{}: {e}", self.lock_file().display()),
            }),
        }
    }

    /// Open (creating) `.daemon/lock`, `0600`.
    fn open_lock(&self) -> Result<std::fs::File> {
        create_private_dir(&self.data_root)?;
        create_private_dir(&self.daemon_dir())?;
        let path = self.lock_file();
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options.open(&path).map_err(|e| Error::Path {
            op: "open the account lock",
            detail: format!("{}: {e}", path.display()),
        })
    }

    /// Take the account's lock (`.daemon/lock`, ADR-026 D-1), waiting up to
    /// [`PROFILE_PATIENCE`](crate::node::profile::PROFILE_PATIENCE) for another holder; it is
    /// released when the returned handle drops or the process ends.
    ///
    /// # Errors
    /// If `.daemon/` or the lock cannot be made, or another vox holds the lock past the wait.
    pub fn lock(&self) -> Result<std::fs::File> {
        create_private_dir(&self.data_root)?;
        create_private_dir(&self.daemon_dir())?;
        let path = self.lock_file();
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(|e| Error::Path {
            op: "open the account lock",
            detail: format!("{}: {e}", path.display()),
        })?;
        let started = std::time::Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(std::fs::TryLockError::Error(e)) => {
                    return Err(Error::Path {
                        op: "take the account lock",
                        detail: format!("{}: {e}", path.display()),
                    })
                }
                Err(std::fs::TryLockError::WouldBlock) => {}
            }
            if started.elapsed() >= crate::node::profile::PROFILE_PATIENCE {
                return Err(Error::Path {
                    op: "take the account lock",
                    detail: format!(
                        "another vox has held {} for {} s; stop it, or wait for it to finish",
                        path.display(),
                        crate::node::profile::PROFILE_PATIENCE.as_secs()
                    ),
                });
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

/// Resolved, created paths of one node (the name `Paths` keeps from when a node was a
/// "profile").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The account's config directory: read for a setting this node has no file of its own for
    /// (ADR-026 F-2). Created.
    pub config_dir: PathBuf,
    /// `<data root>/nodes/<name>/`, the node's directory (created).
    pub profile_dir: PathBuf,
    /// The data root the node directory is under.
    pub data_root: PathBuf,
}

impl Paths {
    /// Resolve and create the directories for node `profile`, honoring the ADR-015
    /// precedence. `data_override` / `config_override` are the CLI-flag layer.
    ///
    /// **A data root not in this version's layout is refused** before anything is created
    /// ([`crate::node::layout::refuse_old_layout`], #423).
    ///
    /// # Errors
    /// A name that is not a node name ([`NodeName`]), a data root this version does not read, or
    /// a directory that cannot be created.
    pub fn resolve(
        profile: &str,
        data_override: Option<&Path>,
        config_override: Option<&Path>,
    ) -> Result<Self> {
        let name = NodeName::parse(profile)?;
        let account = Account::of(data_override, config_override)?;
        crate::node::layout::refuse_old_layout(&account)?;
        account.node_paths(&name)
    }

    /// The account this node belongs to.
    #[must_use]
    pub fn account(&self) -> Account {
        Account {
            data_root: self.data_root.clone(),
            config_dir: self.config_dir.clone(),
        }
    }

    /// `<profile_dir>/config`, the node's own settings directory (ADR-026 F-1).
    #[must_use]
    pub fn node_config_dir(&self) -> PathBuf {
        self.profile_dir.join(NODE_CONFIG_DIR)
    }

    /// Where to **read** the setting file `file` from (ADR-026 F-2): the node's own
    /// `config/<file>` if it is there, else the account's.
    ///
    /// A node's file wins whole, line for line: it is never merged with the account's, so what a
    /// person reads in the node's file is everything that node is set to.
    #[must_use]
    pub fn config_path(&self, file: &str) -> PathBuf {
        let own = self.node_config_dir().join(file);
        if std::fs::symlink_metadata(&own).is_ok() {
            own
        } else {
            self.config_dir.join(file)
        }
    }

    /// Where to **write** the setting file `file`: always the node's own `config/<file>`, made
    /// from the account's file first when the node has none, so a change to one line keeps the
    /// lines this node was reading from the account's (ADR-026 F-2).
    ///
    /// # Errors
    /// If the node's config directory or the copy cannot be written.
    pub fn own_config_path(&self, file: &str) -> Result<PathBuf> {
        let own = self.node_config_dir().join(file);
        if std::fs::symlink_metadata(&own).is_ok() {
            return Ok(own);
        }
        create_private_dir(&self.node_config_dir())?;
        match std::fs::read(self.config_dir.join(file)) {
            Ok(bytes) => write_private_file(&own, &bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::Path {
                    op: "read the account's setting",
                    detail: format!("{}: {e}", self.config_dir.join(file).display()),
                })
            }
        }
        Ok(own)
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
        socket_path_in(&self.profile_dir, SOCKET_FILE)
    }

    /// The settings file to read for this node ([`CONFIG_FILE`]; [`Self::config_path`]).
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.config_path(CONFIG_FILE)
    }

    /// `<profile_dir>/port` ([`PORT_FILE`]).
    #[must_use]
    pub fn port_file(&self) -> PathBuf {
        self.profile_dir.join(PORT_FILE)
    }

    /// `<data root>/.daemon/port`: the data root's one port (ADR-026 D-3).
    #[must_use]
    pub fn account_port_file(&self) -> PathBuf {
        self.data_root.join(DAEMON_DIR).join(PORT_FILE)
    }

    /// The anchors file to read for this node ([`ANCHORS_FILE`]; [`Self::config_path`]).
    #[must_use]
    pub fn anchors_file(&self) -> PathBuf {
        self.config_path(ANCHORS_FILE)
    }

    /// The retention file to read for this node ([`RETENTION_FILE`],
    /// [`crate::node::retention::RetentionConfig`]; [`Self::config_path`]). A change is written
    /// to the node's own ([`Self::own_config_path`]).
    #[must_use]
    pub fn retention_file(&self) -> PathBuf {
        self.config_path(RETENTION_FILE)
    }

    /// Which rooms `vox node` serves, for this node ([`SERVE_FILE`]; [`Self::config_path`]).
    #[must_use]
    pub fn serve_file(&self) -> PathBuf {
        self.config_path(SERVE_FILE)
    }

    /// How long a stuck tunnel is given, for this node ([`TUNNEL_STUCK_FILE`];
    /// [`Self::config_path`]).
    #[must_use]
    pub fn tunnel_stuck_file(&self) -> PathBuf {
        self.config_path(TUNNEL_STUCK_FILE)
    }

    /// The time the profile's [`TUNNEL_STUCK_FILE`] names, if it names one.
    #[must_use]
    pub fn tunnel_stuck_after(&self) -> Option<std::time::Duration> {
        let text = std::fs::read_to_string(self.tunnel_stuck_file()).ok()?;
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))?;
        let (digits, unit) = line.split_at(
            line.find(|c: char| !c.is_ascii_digit())
                .unwrap_or(line.len()),
        );
        let n: u64 = digits.parse().ok()?;
        let secs = match unit.trim() {
            "" | "s" => n,
            "m" => n.checked_mul(60)?,
            "h" => n.checked_mul(3600)?,
            _ => return None,
        };
        (secs > 0).then(|| std::time::Duration::from_secs(secs))
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

    /// Delete the read cursors and held-claim records agent sessions kept for a room this node
    /// no longer holds — it left the room, or the room ended (V030-08) — so no per-room file
    /// outlives it. Each is filed under the room as the session named it: its id `room_id`
    /// (base32), a prefix of it of 8 characters or more, or its local `name`. Returns how many
    /// went.
    pub fn remove_room_cursors(&self, room_id: &str, name: &str) -> usize {
        let names_it = |file: &str| -> bool {
            let Some((room, _session)) = file.split_once('-') else {
                return false;
            };
            (room.len() >= 8 && room_id.starts_with(room))
                || (!name.is_empty() && file.starts_with(&format!("{}-", sanitize(name))))
        };
        let mut gone = 0usize;
        for dir in [self.cursor_dir(), self.cursor_dir().join("held")] {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                let file = e.file_name().to_string_lossy().into_owned();
                if e.path().is_file() && names_it(&file) && std::fs::remove_file(e.path()).is_ok() {
                    gone += 1;
                }
            }
        }
        gone
    }

    /// Where a session records its wake channel.
    #[must_use]
    pub fn session_file(&self, session: &str) -> PathBuf {
        self.profile_dir
            .join(SESSION_DIR)
            .join(format!("{}.json", sanitize(session)))
    }

    /// `<profile_dir>/files`: what this node pulled, a directory per room (ADR-028 F-4).
    #[must_use]
    pub fn files_dir(&self) -> PathBuf {
        self.profile_dir.join("files")
    }

    /// `<profile_dir>/pulls`: a record of each share this node pulled (ADR-028 F-3).
    #[must_use]
    pub fn pulls_dir(&self) -> PathBuf {
        self.profile_dir.join("pulls")
    }

    /// `<profile_dir>/shares`: a record of each share this node serves, and a folder share's
    /// archive (ADR-028 F-2).
    #[must_use]
    pub fn shares_dir(&self) -> PathBuf {
        self.profile_dir.join("shares")
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

/// The data root and the config directory, by the ADR-015 precedence [`Paths::resolve`] uses,
/// **without creating either**.
///
/// # Errors
/// If neither an override, the env vars nor `HOME` names a directory.
pub fn roots(
    data_override: Option<&Path>,
    config_override: Option<&Path>,
) -> Result<(PathBuf, PathBuf)> {
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
    Ok((data_root, config_dir))
}

/// The control socket `file` in `dir`, or its short fallback when that path does not fit a Unix
/// socket address (see [`Paths::socket_file`]): `<tmp>/vox-<uid>/<16 hex>.sock`, the hex a digest
/// of `dir`, so it is deterministic and distinct per directory.
#[must_use]
pub fn socket_path_in(dir: &Path, file: &str) -> PathBuf {
    let natural = dir.join(file);
    if natural.as_os_str().len() < SUN_PATH_BUDGET {
        return natural;
    }
    fallback_socket_for(dir)
}

/// The short fallback a control socket for `dir` would have been bound at, whether or not `dir`'s
/// own path is too long (the migration removes a stale one).
#[must_use]
pub(crate) fn fallback_socket_for(dir: &Path) -> PathBuf {
    let digest =
        crate::hash::domain_hash("vox/control-socket/v1", dir.as_os_str().as_encoded_bytes());
    let mut name = String::new();
    for byte in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(name, "{byte:02x}");
    }
    name.push_str(".sock");
    socket_fallback_dir().join(name)
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

/// Whether `dir` is the shared temp directory's per-user socket directory (`<tmp>/vox-<uid>`),
/// which only [`prepare_socket_dir`] may create or check: it is in a directory other users can
/// write, so it is never followed through a symlink or changed by a path.
#[must_use]
pub fn is_socket_fallback_dir(dir: &Path) -> bool {
    dir == socket_fallback_dir()
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
    write_private_via(path, bytes, &path.with_extension("tmp"))
}

/// [`write_private_file`] for a file **two processes may write at once**: an agent session's
/// record, cursor and notice record, written by its harness's hook and by the daemon. Each write
/// stages through a temporary file of its own (`<name>.<pid>.<n>.tmp`), so two writers never
/// share one and one cannot publish the other's half-written bytes under its own name; whichever
/// rename is last wins whole. The identity vault keeps the fixed name: its writers hold the
/// profile, so there is only ever one.
///
/// # Errors
/// As [`write_private_file`].
pub fn write_private_file_unique(path: &Path, bytes: &[u8]) -> Result<()> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(format!(".{}.{n}.tmp", std::process::id()));
    write_private_via(path, bytes, &path.with_file_name(name))
}

fn write_private_via(path: &Path, bytes: &[u8], tmp: &Path) -> Result<()> {
    use std::io::Write as _;
    let tmp = tmp.to_path_buf();
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
