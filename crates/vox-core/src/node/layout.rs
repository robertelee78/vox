//! **A data root is in this version's layout, or it is refused** (ADR-026 F-3, #423).
//!
//! Each node is `<data root>/nodes/<name>/` and the data root's own state is under `.daemon/`
//! (ADR-026 F-1, D-3). A directory of the root itself holding a vault (`vault.cbor`), an anchor's
//! key (`node-identity.key`) or a store (`store.redb`) is not a node, and a data root holding one
//! is not one this version reads: it is refused by every verb before anything is written
//! ([`refuse_old_layout`]), and left exactly as it is. Vox carries no code that reads or converts
//! such a directory; only the app, when the person asks (#576), renames it into
//! [`MOVED_ASIDE_DIR`], unread and whole ([`move_old_layout_aside`]).
//!
//! **What wrote a data root is written in it** (ADR-026 F-3): `.daemon/format` names the data
//! root's format and the version of vox that last served it ([`stamp_format`]). A release that
//! changes an on-disk format upgrades every data root a supported release wrote, and this is how
//! it tells which one it holds. A root without the file was last served by v0.4.0, which wrote
//! none: format 1.

use std::io::Read as _;

use crate::error::{Error, Result};
use crate::node::headless::IDENTITY_FILE;
use crate::node::paths::{
    write_private_file, Account, NodeName, FORMAT_FILE, NODES_DIR, STORE_FILE, VAULT_FILE,
};

/// The suffix of the node a vault-holding node runs its anchor as (`vox node`, one node is one
/// identity, ADR-026 F-3).
pub const ANCHOR_SUFFIX: &str = "-anchor";

/// The node a node holding a vault runs its anchor as: `<name>-anchor`.
///
/// # Errors
/// If `<name>-anchor` is not a node name (too long).
pub fn anchor_name_of(name: &NodeName) -> Result<NodeName> {
    NodeName::parse(&format!("{name}{ANCHOR_SUFFIX}"))
}

/// Where the app moves an earlier release's node directories when the person asks: under the
/// data root, so they stay where the person looked, and out of the way of [`refuse_old_layout`].
pub const MOVED_ASIDE_DIR: &str = "moved-aside";

/// The directories of the data root that make it one this version does not read, by name, sorted:
/// not hidden, not `nodes/` nor [`MOVED_ASIDE_DIR`], and holding a vault, an anchor's key or a
/// store. Read only.
#[must_use]
pub fn old_layout_dirs(account: &Account) -> Vec<String> {
    let Ok(dir) = std::fs::read_dir(&account.data_root) else {
        return Vec::new();
    };
    let mut old: Vec<String> = dir
        .filter_map(std::result::Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if name.starts_with('.')
                || name == NODES_DIR
                || name == MOVED_ASIDE_DIR
                || !e.file_type().ok()?.is_dir()
            {
                return None;
            }
            let p = e.path();
            [VAULT_FILE, IDENTITY_FILE, STORE_FILE]
                .iter()
                .any(|f| p.join(f).is_file())
                .then_some(name)
        })
        .collect();
    old.sort();
    old
}

/// **Move an earlier release's node directories aside**, when the person asks (#576): each of
/// [`old_layout_dirs`] is renamed, whole and unread, to `<data root>/moved-aside/<name>-<date>`
/// (`-2`, `-3`… when that is taken); nothing is deleted, converted or opened. Returns each move,
/// from and to.
///
/// # Errors
/// The `moved-aside` directory cannot be made, or a rename fails (the moves before it stand).
pub fn move_old_layout_aside(
    account: &Account,
    date: &str,
) -> Result<Vec<(std::path::PathBuf, std::path::PathBuf)>> {
    let aside = account.data_root.join(MOVED_ASIDE_DIR);
    let mut moved = Vec::new();
    for name in old_layout_dirs(account) {
        std::fs::create_dir_all(&aside).map_err(|e| Error::DataRootNotRead {
            root: account.data_root.display().to_string(),
            why: format!("{} could not be made: {e}", aside.display()),
        })?;
        let from = account.data_root.join(&name);
        let mut to = aside.join(format!("{name}-{date}"));
        let mut n = 2;
        while to.exists() {
            to = aside.join(format!("{name}-{date}-{n}"));
            n += 1;
        }
        std::fs::rename(&from, &to).map_err(|e| Error::DataRootNotRead {
            root: account.data_root.display().to_string(),
            why: format!(
                "{} could not be moved to {}: {e}",
                from.display(),
                to.display()
            ),
        })?;
        moved.push((from, to));
    }
    Ok(moved)
}

/// **Refuse a data root this version does not read**, reading it only: a directory of the root
/// that is not hidden, is not `nodes/`, and holds a vault, an anchor's key or a store is not a
/// node. Nothing is created, locked or written either way.
///
/// # Errors
/// [`Error::DataRootNotRead`], naming the root and the first such directory, or an unreadable,
/// malformed or newer format marker. A marker this build cannot read must never be overwritten.
pub fn refuse_old_layout(account: &Account) -> Result<()> {
    let old = old_layout_dirs(account);
    match old.first() {
        None => data_root_format(account).map(|_| ()),
        Some(first) => Err(Error::DataRootNotRead {
            root: account.data_root.display().to_string(),
            why: format!(
                "{} is not a node (a node lives under {}). Use another data directory \
                 (--data-dir or VOX_DATA_DIR), or move this one aside; nothing in it was changed",
                account.data_root.join(first).display(),
                account.data_root.join(NODES_DIR).display()
            ),
        }),
    }
}

/// The data root's format (ADR-026 F-3): the layout of `.daemon/` and `nodes/`, and every format
/// the files under them are in. A release that changes any of them raises it, and upgrades a root
/// of every earlier value a supported release (v0.4.0 on) wrote.
// Format 2 adds separate Session retention and version-3 age records. Opening a
// supported older root decodes its version-1/2 records and classifies stored drive
// envelopes before the first retention sweep; no identity or room is rewritten.
pub const DATA_ROOT_FORMAT: u32 = 2;

/// Read the supported format before opening or writing anything in the data root (ADR-026 F-3).
/// A missing marker is format 1, written by v0.4.0; an existing but unreadable marker is not.
/// The writer's version is descriptive: the format number decides whether this build can read it.
///
/// # Errors
/// [`Error::DataRootNotRead`] when the marker cannot be read, is malformed, or names a format
/// newer than this build. Refusing it preserves the person's data instead of silently downgrading
/// the marker and opening stores with incompatible code.
pub fn data_root_format(account: &Account) -> Result<u32> {
    const MAX_MARKER_BYTES: u64 = 4096;
    let path = account.daemon_dir().join(FORMAT_FILE);
    let refused = |why: String| Error::DataRootNotRead {
        root: account.data_root.display().to_string(),
        why,
    };
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                && std::fs::symlink_metadata(&path)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(1);
        }
        Err(e) => {
            return Err(refused(format!(
                "its format marker could not be read: {e}; nothing in it was changed"
            )));
        }
    };
    let mut text = String::new();
    file.take(MAX_MARKER_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| {
            refused(format!(
                "its format marker could not be read: {e}; nothing in it was changed"
            ))
        })?;
    let format = text
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("format "))
        .filter(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|number| number.parse::<u32>().ok())
        .filter(|number| *number > 0);
    let Some(format) = format.filter(|_| text.len() as u64 <= MAX_MARKER_BYTES) else {
        return Err(refused(
            "its format marker is not valid; nothing in it was changed".into(),
        ));
    };
    if format > DATA_ROOT_FORMAT {
        return Err(refused(format!(
            "data format {format} needs a newer Vox (this build reads through format \
             {DATA_ROOT_FORMAT}); use the version that last opened it or a newer one; \
             nothing in it was changed"
        )));
    }
    Ok(format)
}

/// What `.daemon/format` says: the data root's format and the vox that last served it.
fn format_text(version: &str) -> String {
    format!("format {DATA_ROOT_FORMAT}\nwritten-by vox {version}\n")
}

/// **Write what serves this data root** into `.daemon/format`, unless it says so already: called
/// by the daemon once it holds the account lock, so only one writer is ever at it. `version` is
/// the running vox's.
///
/// # Errors
/// The existing format is not supported, or the file cannot be written.
pub fn stamp_format(account: &Account, version: &str) -> Result<()> {
    // Recheck under the account lock: never replace a marker we cannot interpret.
    data_root_format(account)?;
    let path = account.daemon_dir().join(FORMAT_FILE);
    let text = format_text(version);
    if std::fs::read_to_string(&path).is_ok_and(|held| held == text) {
        return Ok(());
    }
    write_private_file(&path, text.as_bytes())
}
