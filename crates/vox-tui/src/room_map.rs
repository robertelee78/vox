//! The room map: which room a harness session works in (ADR-029 §6).
//!
//! Each data root has one, `<data root>/rooms`, mode `0600`, read by every node of that data root,
//! in the style of `~/.ssh/config`:
//!
//! ```text
//! repo /opt/vox
//!     room       vox://…
//!     passphrase the room's passphrase
//! ```
//!
//! A session started in a mapped directory works in that room for its life (RB-2 – RB-4). The match
//! is exact: `/opt/vox` matches a session started in `/opt/vox`, and not one started in
//! `/opt/vox/crates` or in a worktree beside it. The link and the passphrase are separate fields;
//! the passphrase is never part of the link (ADR-005). Every node of the data root can read every
//! passphrase here, which whatever writes the map says (ADR-028 E-5).

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::app::AppError;

/// One `repo` block.
pub struct Entry {
    /// The start directory, as written.
    pub repo: PathBuf,
    /// The room link (`vox://…`).
    pub room: String,
    /// The room's passphrase; empty when the block gives none.
    pub passphrase: Zeroizing<String>,
}

/// Where a data root keeps its room map.
#[must_use]
pub fn path(data_root: &Path) -> PathBuf {
    data_root.join("rooms")
}

/// The room map of `data_root`, every block in file order. No file is an empty map.
///
/// # Errors
/// The file cannot be read, others than its owner may read it (it holds passphrases, so it is
/// refused, as ssh refuses a key others can read), or a line is not one the map takes, named by
/// its number.
pub fn read(data_root: &Path) -> Result<Vec<Entry>, AppError> {
    use std::os::unix::fs::PermissionsExt;
    let file = path(data_root);
    let text = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(AppError::Usage(format!(
                "cannot read the room map {}: {e}",
                file.display()
            )))
        }
    };
    let text = Zeroizing::new(text);
    let mode = std::fs::metadata(&file)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0);
    if mode & 0o077 != 0 {
        return Err(AppError::Usage(format!(
            "the room map {} holds room passphrases and others may read it (mode {mode:o}); \
             make it yours alone with `chmod 600 {}`",
            file.display(),
            file.display()
        )));
    }
    parse(&text).map_err(|(n, why)| {
        AppError::Usage(format!("the room map {}, line {n}: {why}", file.display()))
    })
}

/// The blocks of a room map's text, or the 1-based number of the first line it does not take and
/// why.
fn parse(text: &str) -> Result<Vec<Entry>, (usize, String)> {
    let mut entries: Vec<Entry> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once(char::is_whitespace) {
            Some((k, v)) => (k, v.trim()),
            None => (line, ""),
        };
        match key {
            "repo" => {
                if value.is_empty() {
                    return Err((n, "`repo` names no directory".into()));
                }
                entries.push(Entry {
                    repo: PathBuf::from(value),
                    room: String::new(),
                    passphrase: Zeroizing::new(String::new()),
                });
            }
            "room" | "passphrase" => {
                let Some(e) = entries.last_mut() else {
                    return Err((n, format!("`{key}` before any `repo`")));
                };
                if key == "room" {
                    if let Err(why) = vox_core::node::link::InviteLink::parse(value) {
                        return Err((n, format!("`room` is not a room link (vox://…): {why}")));
                    }
                    value.clone_into(&mut e.room);
                } else {
                    *e.passphrase = value.to_owned();
                }
            }
            other => {
                return Err((
                    n,
                    format!("{other:?} is not a field; the fields are repo, room and passphrase"),
                ))
            }
        }
    }
    if let Some(e) = entries.iter().find(|e| e.room.is_empty()) {
        return Err((
            text.lines().count(),
            format!("`repo {}` names no `room`", e.repo.display()),
        ));
    }
    Ok(entries)
}

/// The block whose `repo` is exactly `start`: the same directory, not one above or below it (RB-2).
/// A symlink and the directory it names are the same directory.
#[must_use]
pub fn lookup<'a>(entries: &'a [Entry], start: &Path) -> Option<&'a Entry> {
    let same = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let start = same(start);
    entries.iter().find(|e| same(&e.repo) == start)
}

/// The room the map gives a session started in `start`, as `(room id in base32, link,
/// passphrase)`: what the hook registers the session with (ADR-029 RB-2, RB-3). `None` when no
/// `repo` is `start`.
///
/// # Errors
/// What [`read`] refuses.
pub fn room_for(
    data_root: &Path,
    start: &Path,
) -> Result<Option<(String, String, Zeroizing<String>)>, AppError> {
    let entries = read(data_root)?;
    Ok(lookup(&entries, start).and_then(|e| {
        let link = vox_core::node::link::InviteLink::parse(&e.room).ok()?;
        Some((
            vox_core::node::link::b32_encode(&link.channel_id),
            e.room.clone(),
            e.passphrase.clone(),
        ))
    }))
}

/// What the hook tells a session about its room this turn, before its rooms' news (ADR-029
/// RB-5), or `None` when there is nothing to tell:
/// - a session new to its node that works in no room is told so, once, with the command that sets
///   one;
/// - a session whose room is being joined is told that, or why the join failed;
/// - a room map that cannot be read is named, with why, so a person can fix it.
#[must_use]
pub fn note(
    room: Option<&str>,
    new: bool,
    joining: Option<&str>,
    data_root: &Path,
) -> Option<String> {
    if let Err(e) = read(data_root) {
        return Some(format!("Vox: {e}\n"));
    }
    if let Some(j) = joining {
        return Some(format!("Vox: {j}\n"));
    }
    (new && room.is_none()).then(|| {
        "Vox: this session works in no room: no entry in the room map is the directory it \
         started in. `vox agent room <room>` sets one.\n"
            .to_owned()
    })
}
