//! Moving a data root of the layout before v0.3.0 into the daemon's (ADR-026 F-3).
//!
//! Before v0.3.0 each profile was a directory of the data root, `<data root>/<name>/`, holding a
//! vault (`vault.cbor`), a headless anchor's key (`node-identity.key`), or both, with its store
//! (`store.redb`), its control socket (`node.sock`) and the port it bound (`port`). From v0.3.0
//! each node is `<data root>/nodes/<name>/` and the data root's one port is `.daemon/port`
//! (ADR-026 F-1, D-3). [`migrate`] moves the one into the other:
//!
//! - every directory of the data root that is not hidden, is not `nodes`, and holds a vault, a
//!   headless key or a store is **renamed** to `nodes/<name>/`, keeping its identity, rooms and
//!   store byte for byte — a rename moves nothing, so there is nothing to copy wrong;
//! - a directory holding both a vault and a headless key is **split**, since one node is one
//!   identity: the vault keeps `<name>` and the headless key becomes node `<name>-anchor`;
//! - its stale `node.sock`, `port` and short fallback socket are removed;
//! - `.daemon/port` takes the port of the node being started, else the first moved node's, so
//!   the address records members hold stay valid;
//! - config files are not copied: a node's missing setting is read from the account's file
//!   ([`Paths::config_path`](crate::node::paths::Paths::config_path), ADR-026 F-2).
//!
//! **It runs under the account lock** (`.daemon/lock`), so two vox started together on an old
//! data root move it once, and **refuses a directory an older vox still holds** — its directory
//! lock, its store's lock or its control socket — rather than move files from under a running
//! process. **Each step is atomic and a re-run finishes the job**: a directory is moved by one
//! `rename`, a headless key by one `rename`, and the split also runs over `nodes/`, so a vox
//! stopped between the two renames of a split is finished by the next one.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::node::headless::IDENTITY_FILE;
use crate::node::paths::{
    create_private_dir, fallback_socket_for, sync_dir, write_private_file, Account, NodeName,
    NODES_DIR, PORT_FILE, SOCKET_FILE, STORE_FILE, VAULT_FILE,
};

/// The suffix of the node a split directory's headless key becomes (ADR-026 F-3).
pub const ANCHOR_SUFFIX: &str = "-anchor";

/// What a [`migrate`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// Each directory moved, and the node it became.
    pub moved: Vec<(PathBuf, NodeName)>,
    /// Each node whose headless key was split off, and the node the key became.
    pub split: Vec<(NodeName, NodeName)>,
    /// The port written to `.daemon/port`, if one was.
    pub port: Option<u16>,
}

/// The node a split directory's headless key becomes: `<name>-anchor`.
///
/// # Errors
/// If `<name>-anchor` is not a node name (too long).
pub fn anchor_name_of(name: &NodeName) -> Result<NodeName> {
    NodeName::parse(&format!("{name}{ANCHOR_SUFFIX}"))
}

/// Move `account`'s data root into the ADR-026 layout, if any of it is in the old one; nothing
/// is locked or written when nothing needs moving. `starting` is the node about to run, whose old
/// port `.daemon/port` takes first.
///
/// # Errors
/// [`Error::Path`] naming the directory and what to do, when an older vox holds a directory,
/// a directory's name is not a node name, its new place is taken, or a file cannot be moved.
pub fn migrate(account: &Account, starting: Option<&NodeName>) -> Result<MigrationReport> {
    if old_profiles(account).is_empty() && unsplit(account).is_empty() {
        return Ok(MigrationReport::default());
    }
    let _lock = account.lock()?;
    migrate_held(account, starting)
}

/// [`migrate`] for a caller that already holds the account lock (the daemon, which holds it for
/// its whole life, ADR-026 D-1).
///
/// # Errors
/// As [`migrate`].
pub fn migrate_held(account: &Account, starting: Option<&NodeName>) -> Result<MigrationReport> {
    let mut report = MigrationReport::default();
    let old = old_profiles(account);

    // Every name is checked before anything moves, so a refusal leaves the data root as it was.
    let mut plan: Vec<(PathBuf, NodeName)> = Vec::new();
    for (dir, raw) in &old {
        let name = NodeName::parse(raw).map_err(|_| {
            refuse(format!(
                "{} is a profile of an older vox, and {raw:?} is not a node name (1 to 64 of \
                 a-z, 0-9, '.', '_', '-', not starting with '.'); rename the directory, then run \
                 vox again",
                dir.display()
            ))
        })?;
        let to = account.node_dir(&name);
        if to.exists() || plan.iter().any(|(_, n)| *n == name) {
            return Err(refuse(format!(
                "{} would become node {name}, which {} already is; move one of them aside, then \
                 run vox again",
                dir.display(),
                to.display()
            )));
        }
        if dir.join(VAULT_FILE).is_file() && dir.join(IDENTITY_FILE).is_file() {
            let anchor = anchor_name_of(&name).map_err(|_| {
                refuse(format!(
                    "{} holds a vault and an anchor's key, and {name}{ANCHOR_SUFFIX} is too long \
                     a node name for the key; rename the directory to a shorter name, then run \
                     vox again",
                    dir.display()
                ))
            })?;
            if account.node_dir(&anchor).exists() {
                return Err(refuse(format!(
                    "{} holds a vault and an anchor's key, and the key's node {anchor} already \
                     exists at {}; move one aside, then run vox again",
                    dir.display(),
                    account.node_dir(&anchor).display()
                )));
            }
        }
        plan.push((dir.clone(), name));
    }

    // `.daemon/port` before anything moves: the node about to run's old port, else the first's.
    if !old.is_empty() && !account.port_file().exists() {
        let port_of = |dir: &Path| {
            std::fs::read_to_string(dir.join(PORT_FILE))
                .ok()
                .and_then(|t| t.trim().parse::<u16>().ok())
                .filter(|p| *p != 0)
        };
        let port = plan
            .iter()
            .find(|(_, n)| Some(n) == starting)
            .and_then(|(d, _)| port_of(d))
            .or_else(|| plan.iter().find_map(|(d, _)| port_of(d)));
        if let Some(port) = port {
            create_private_dir(&account.daemon_dir())?;
            write_private_file(&account.port_file(), format!("{port}\n").as_bytes())?;
            report.port = Some(port);
        }
    }

    for (dir, name) in plan {
        // Held across the rename, so no vox of this build opens it half-way.
        let _held = refuse_if_held(&dir)?;
        for stale in [dir.join(SOCKET_FILE), dir.join(PORT_FILE), fallback_socket_for(&dir)] {
            remove_if_there(&stale)?;
        }
        create_private_dir(&account.nodes_dir())?;
        let to = account.node_dir(&name);
        std::fs::rename(&dir, &to).map_err(|e| {
            refuse(format!(
                "moving {} to {}: {e}",
                dir.display(),
                to.display()
            ))
        })?;
        sync_dir(&to)?;
        eprintln!(
            "vox: moved {} to {} (from v0.3.0 each node lives under {NODES_DIR}/)",
            dir.display(),
            to.display()
        );
        report.moved.push((dir, name));
    }

    for name in unsplit(account) {
        let anchor = anchor_name_of(&name).map_err(|_| {
            refuse(format!(
                "node {name} holds a vault and an anchor's key, and {name}{ANCHOR_SUFFIX} is too \
                 long a node name for the key"
            ))
        })?;
        let from = account.node_dir(&name).join(IDENTITY_FILE);
        let to_dir = account.node_dir(&anchor);
        let to = to_dir.join(IDENTITY_FILE);
        if to.exists() {
            return Err(refuse(format!(
                "node {name} holds an anchor's key, and node {anchor} already has one at {}; \
                 move one aside, then run vox again",
                to.display()
            )));
        }
        create_private_dir(&to_dir)?;
        std::fs::rename(&from, &to).map_err(|e| {
            refuse(format!(
                "moving {} to {}: {e}",
                from.display(),
                to.display()
            ))
        })?;
        sync_dir(&to)?;
        sync_dir(&from)?;
        eprintln!(
            "vox: node {name}'s anchor key is now node {anchor} ({}): one node is one identity",
            to_dir.display()
        );
        report.split.push((name, anchor));
    }
    Ok(report)
}

/// Each directory of the data root in the old layout, with its name, sorted by name.
fn old_profiles(account: &Account) -> Vec<(PathBuf, String)> {
    let Ok(dir) = std::fs::read_dir(&account.data_root) else {
        return Vec::new();
    };
    let mut out: Vec<(PathBuf, String)> = dir
        .filter_map(std::result::Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if name.starts_with('.') || name == NODES_DIR {
                return None;
            }
            // A symlink is not followed: what it points at is not this data root's to move.
            if !e.file_type().ok()?.is_dir() {
                return None;
            }
            let p = e.path();
            [VAULT_FILE, IDENTITY_FILE, STORE_FILE]
                .iter()
                .any(|f| p.join(f).is_file())
                .then_some((p, name))
        })
        .collect();
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

/// Each node of `nodes/` holding both a vault and a headless key, sorted.
fn unsplit(account: &Account) -> Vec<NodeName> {
    let Ok(dir) = std::fs::read_dir(account.nodes_dir()) else {
        return Vec::new();
    };
    let mut out: Vec<NodeName> = dir
        .filter_map(std::result::Result::ok)
        .filter(|e| {
            let p = e.path();
            p.join(VAULT_FILE).is_file() && p.join(IDENTITY_FILE).is_file()
        })
        .filter_map(|e| {
            let raw = e.file_name().into_string().ok()?;
            NodeName::parse(&raw).ok().filter(|n| n.as_str() == raw)
        })
        .collect();
    out.sort();
    out
}

/// Take the locks an older vox holds while it runs on `dir` — the directory's own lock and its
/// store's — and see that nothing answers on its control socket; refuse if any is held. The
/// returned handles keep the locks until dropped.
fn refuse_if_held(dir: &Path) -> Result<Vec<std::fs::File>> {
    let running = || {
        refuse(format!(
            "an older vox is still running on {}; stop it (`vox daemon`, `vox node`, `vox tui` \
             or any other verb using it), then run this vox again",
            dir.display()
        ))
    };
    let mut held = Vec::new();
    for path in [dir.to_path_buf(), dir.join(STORE_FILE)] {
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(refuse(format!("opening {}: {e}", path.display()))),
        };
        match file.try_lock() {
            Ok(()) => held.push(file),
            Err(std::fs::TryLockError::WouldBlock) => return Err(running()),
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(refuse(format!("locking {}: {e}", path.display())))
            }
        }
    }
    for socket in [dir.join(SOCKET_FILE), fallback_socket_for(dir)] {
        if crate::node::profile::holder_serves(&socket) {
            return Err(running());
        }
    }
    Ok(held)
}

fn remove_if_there(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(refuse(format!("removing {}: {e}", path.display()))),
    }
}

fn refuse(detail: String) -> Error {
    Error::Path {
        op: "move to the v0.3.0 layout",
        detail,
    }
}
