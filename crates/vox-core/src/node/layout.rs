//! **A data root is in this version's layout, or it is refused** (ADR-026 F-3, #423).
//!
//! Each node is `<data root>/nodes/<name>/` and the data root's own state is under `.daemon/`
//! (ADR-026 F-1, D-3). A directory of the root itself holding a vault (`vault.cbor`), an anchor's
//! key (`node-identity.key`) or a store (`store.redb`) is not a node, and a data root holding one
//! is not one this version reads: it is refused by every verb before anything is written
//! ([`refuse_old_layout`]), and left exactly as it is. Vox carries no code that reads, converts or
//! moves such a directory.
//!
//! **What wrote a data root is written in it** (ADR-026 F-3): `.daemon/format` names the data
//! root's format and the version of vox that last served it ([`stamp_format`]). A release that
//! changes an on-disk format upgrades every data root a supported release wrote, and this is how
//! it tells which one it holds. A root without the file was last served by v0.4.0, which wrote
//! none: format 1.

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

/// **Refuse a data root this version does not read**, reading it only: a directory of the root
/// that is not hidden, is not `nodes/`, and holds a vault, an anchor's key or a store is not a
/// node. Nothing is created, locked or written either way.
///
/// # Errors
/// [`Error::DataRootNotRead`], naming the root and the first such directory.
pub fn refuse_old_layout(account: &Account) -> Result<()> {
    let Ok(dir) = std::fs::read_dir(&account.data_root) else {
        return Ok(());
    };
    let mut old: Vec<String> = dir
        .filter_map(std::result::Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if name.starts_with('.') || name == NODES_DIR || !e.file_type().ok()?.is_dir() {
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
    match old.first() {
        None => Ok(()),
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
pub const DATA_ROOT_FORMAT: u32 = 1;

/// What `.daemon/format` says: the data root's format and the vox that last served it.
fn format_text(version: &str) -> String {
    format!("format {DATA_ROOT_FORMAT}\nwritten-by vox {version}\n")
}

/// **Write what serves this data root** into `.daemon/format`, unless it says so already: called
/// by the daemon once it holds the account lock, so only one writer is ever at it. `version` is
/// the running vox's.
///
/// # Errors
/// The file cannot be written.
pub fn stamp_format(account: &Account, version: &str) -> Result<()> {
    let path = account.daemon_dir().join(FORMAT_FILE);
    let text = format_text(version);
    if std::fs::read_to_string(&path).is_ok_and(|held| held == text) {
        return Ok(());
    }
    write_private_file(&path, text.as_bytes())
}
