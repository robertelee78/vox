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
//! A session started in a mapped directory works in that room for its life (RB-2 – RB-4). It is
//! matched to the deepest block at or above its start directory: a session started in
//! `/opt/vox/crates` works in `/opt/vox`'s room, unless `/opt/vox/crates` has a block of its own. A
//! git worktree is matched through to its main repository's directory, unless a block names the
//! worktree or a folder in it ([`resolve`]). The link and the passphrase are separate fields;
//! the passphrase is never part of the link (ADR-005). Every node of the data root can read every
//! passphrase here, which whatever writes the map says (ADR-028 E-5).
//!
//! **A repo with no room asks once, and a "no" is kept** (ADR-029 RB-5 – RB-7, v0.4.1): a session
//! started in a directory the map does not name is told to ask the operator for the repo's room
//! link, or a no. The operator binds a link with `vox room join <link> --node <agent node> --bind
//! <dir>` at a terminal of their own, so the room's passphrase is typed there and never given in the
//! session; a no is a block whose room is `none` (`vox agent room --none`), and silences the ask
//! for that directory.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::app::AppError;

/// What a `room` field holds for a directory whose operator said no to binding it (RB-7).
pub const DECLINED: &str = "none";

/// One `repo` block.
pub struct Entry {
    /// The start directory, as written.
    pub repo: PathBuf,
    /// The room link (`vox://…`), or [`DECLINED`].
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
                    if value == DECLINED {
                        DECLINED.clone_into(&mut e.room);
                        continue;
                    }
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

/// The block whose `repo` is exactly `dir`: the same directory, not one above or below it. What
/// writing the map asks (does it name `dir` already?). A symlink and the directory it names are the
/// same directory.
#[must_use]
pub fn lookup<'a>(entries: &'a [Entry], dir: &Path) -> Option<&'a Entry> {
    let same = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let dir = same(dir);
    entries.iter().find(|e| same(&e.repo) == dir)
}

/// The block a session started in `start` works by (ADR-029 RB-2): the deepest block whose `repo`
/// is `start` or a directory above it, so a subfolder of a bound repo works in the repo's room.
/// A start inside a git worktree is first looked up within that worktree (a block for the worktree
/// or a folder in it wins), then as the same place in the worktree's main repository, read from its
/// `.git` file and `commondir`.
#[must_use]
pub fn resolve<'a>(entries: &'a [Entry], start: &Path) -> Option<&'a Entry> {
    let same = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let start = same(start);
    let repos: Vec<(PathBuf, &Entry)> = entries.iter().map(|e| (same(&e.repo), e)).collect();
    // The deepest block at `from` or above it, stopping above `floor` when one is given.
    let deepest = |from: &Path, floor: Option<&Path>| -> Option<&'a Entry> {
        for dir in from.ancestors() {
            if let Some((_, e)) = repos.iter().find(|(r, _)| r == dir) {
                return Some(*e);
            }
            if floor.is_some_and(|f| f == dir) {
                return None;
            }
        }
        None
    };
    match worktree_of(&start) {
        Some((top, main)) => deepest(&start, Some(&top)).or_else(|| {
            let inside = start.strip_prefix(&top).unwrap_or(Path::new(""));
            deepest(&main.join(inside), None)
        }),
        None => deepest(&start, None),
    }
}

/// When `dir` is inside a linked git worktree: the worktree's top directory, and its main
/// repository's directory. A worktree's `.git` is a file, `gitdir: <its git dir>`, and that git dir
/// holds `commondir`, the main repository's `.git`. A submodule's `.git` file names a git dir with
/// no `commondir`, and is not a worktree.
fn worktree_of(dir: &Path) -> Option<(PathBuf, PathBuf)> {
    let top = dir.ancestors().find(|d| d.join(".git").exists())?;
    let text = std::fs::read_to_string(top.join(".git")).ok()?;
    let gitdir = PathBuf::from(text.trim().strip_prefix("gitdir:")?.trim());
    let gitdir = if gitdir.is_absolute() {
        gitdir
    } else {
        top.join(gitdir)
    };
    let common = std::fs::read_to_string(gitdir.join("commondir")).ok()?;
    let common = PathBuf::from(common.trim());
    let common = if common.is_absolute() {
        common
    } else {
        gitdir.join(common)
    };
    let common = std::fs::canonicalize(&common).ok()?;
    // The main repository's directory holds its `.git`.
    let main = common.parent()?.to_path_buf();
    Some((top.to_path_buf(), main))
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
    Ok(resolve(&entries, start).and_then(|e| {
        if e.room == DECLINED {
            return None;
        }
        let link = vox_core::node::link::InviteLink::parse(&e.room).ok()?;
        Some((
            vox_core::node::link::b32_encode(&link.channel_id),
            e.room.clone(),
            e.passphrase.clone(),
        ))
    }))
}

/// Whether the operator said no to binding `start` to a room (RB-7): its block's room is `none`.
#[must_use]
pub fn declined(data_root: &Path, start: &Path) -> bool {
    read(data_root)
        .ok()
        .is_some_and(|entries| resolve(&entries, start).is_some_and(|e| e.room == DECLINED))
}

/// What the hook tells a session about its room this turn, before its rooms' news (ADR-029
/// RB-5), or `None` when there is nothing to tell:
/// - a session new to its node that works in no room is told, once, that its repo is not tied to a
///   room and that Vox has asked the operator (Vox.app, `vox agent status`, [`crate::room_ask`]):
///   it tells them so once, and acts on a link or a no given in the session (RB-5, RB-6); unless
///   the operator said no for that directory already (RB-7);
/// - a session whose room is being joined is told that, or why the join failed;
/// - a room map that cannot be read is named, with why, so a person can fix it.
#[must_use]
pub fn note(
    room: Option<&str>,
    new: bool,
    joining: Option<&str>,
    data_root: &Path,
    start: &Path,
    node: &str,
) -> Option<String> {
    if let Err(e) = read(data_root) {
        return Some(format!("Vox: {e}\n"));
    }
    if let Some(j) = joining {
        return Some(format!("Vox: {j}\n"));
    }
    if !new || room.is_some() || declined(data_root, start) {
        return None;
    }
    // As the map will hold it: the directory itself, a symlink to it resolved.
    let dir = std::fs::canonicalize(start).unwrap_or_else(|_| start.to_path_buf());
    let bind = vox_text::shell::command(&[
        "vox",
        "room",
        "join",
        "<link>",
        "--node",
        node,
        "--bind",
        &dir.display().to_string(),
    ]);
    let into = vox_text::shell::command(&["vox", "agent", "room", "<room>", "--node", node]);
    let none = vox_text::shell::command(&["vox", "agent", "room", "--none", "--node", node]);
    let dir = dir.display();
    Some(format!(
        "Vox: this repo ({dir}) isn't tied to a Vox room, and Vox has asked the operator which \
         room it works in (a banner in Vox.app, and `vox agent status`). Tell them once, in one \
         sentence, in these words, and do not ask again on later turns: \"This repo isn't tied to \
         a Vox room. Vox has asked you in its app; you can also paste its room link here, or say \
         no.\"\n\
         - If they answer in Vox.app: Vox puts this session in that room itself; run nothing.\n\
         - If they paste a link here: never ask for the room's passphrase here. Give them this \
         command exactly, with the link they pasted in place of <link>, inside its single quotes, \
         to run in a terminal of their own (it asks for the passphrase there, and saves the link \
         for this repo so every later session started here works in that room):\n    \
         {bind}\n  \
         Once it says joined, put this session in the room: {into}\n\
         - If they say no: run {none}, and no session started here is asked again.\n"
    ))
}

/// Add a `repo` block to `data_root`'s room map: `repo` works in the room `link` names, joined with
/// `passphrase` (none when empty). The map is made, mode 0600, if there is none; what it held is
/// kept.
///
/// # Errors
/// The map cannot be read (what [`read`] refuses) or written, or it names `repo` already.
pub fn add(data_root: &Path, repo: &Path, link: &str, passphrase: &str) -> Result<(), AppError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let entries = read(data_root)?;
    if lookup(&entries, repo).is_some() {
        return Err(AppError::Usage(format!(
            "the room map names {} already; change it there",
            repo.display()
        )));
    }
    let mut block = format!("\nrepo {}\n    room       {link}\n", repo.display());
    if !passphrase.is_empty() {
        block.push_str(&format!("    passphrase {passphrase}\n"));
    }
    let block = Zeroizing::new(block);
    let file = path(data_root);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&file)
        .map_err(|e| {
            AppError::Usage(format!("cannot write the room map {}: {e}", file.display()))
        })?;
    f.write_all(block.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| AppError::Usage(format!("cannot write the room map {}: {e}", file.display())))
}

/// Record that the operator said no to binding `repo` to a room (RB-7): a block whose room is
/// `none`, which no passphrase rides on. A directory the map names already is left as it is.
///
/// # Errors
/// The map cannot be read or written.
pub fn decline(data_root: &Path, repo: &Path) -> Result<bool, AppError> {
    let entries = read(data_root)?;
    if lookup(&entries, repo).is_some() {
        return Ok(false);
    }
    append(
        data_root,
        &format!("\nrepo {}\n    room       {DECLINED}\n", repo.display()),
    )?;
    Ok(true)
}

/// Bind `repo` to the room `link` names, joined with `passphrase` (RB-6), replacing whatever the
/// map held for it: a `no`, or another room. Returns what was replaced, as a person reads it:
/// `None` when the map held nothing for `repo`.
///
/// # Errors
/// The map cannot be read or written.
pub fn bind(
    data_root: &Path,
    repo: &Path,
    link: &str,
    passphrase: &str,
) -> Result<Option<String>, AppError> {
    let entries = read(data_root)?;
    let before = lookup(&entries, repo).map(|e| {
        if e.room == DECLINED {
            "a no (`room none`)".to_owned()
        } else {
            let room = vox_core::node::link::InviteLink::parse(&e.room)
                .map(|l| vox_core::node::link::b32_encode(&l.channel_id))
                .unwrap_or_default();
            format!("room {}", room.chars().take(12).collect::<String>())
        }
    });
    if before.is_some() {
        drop_block(data_root, repo)?;
    }
    add(data_root, repo, link, passphrase)?;
    Ok(before)
}

/// Take `repo`'s block out of the map, keeping every other line as it is.
fn drop_block(data_root: &Path, repo: &Path) -> Result<(), AppError> {
    let file = path(data_root);
    let text = Zeroizing::new(std::fs::read_to_string(&file).map_err(|e| {
        AppError::Usage(format!("cannot read the room map {}: {e}", file.display()))
    })?);
    let same = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let target = same(repo);
    let mut kept = Zeroizing::new(String::new());
    let mut skipping = false;
    for line in text.lines() {
        let t = line.trim();
        if let Some(dir) = t.strip_prefix("repo").filter(|_| t.starts_with("repo ")) {
            skipping = same(Path::new(dir.trim())) == target;
        }
        if !skipping {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    vox_core::node::paths::write_private_file_unique(&file, kept.as_bytes())
        .map_err(|e| AppError::Usage(format!("cannot write the room map {}: {e}", file.display())))
}

/// Append `block` to the map, made mode 0600 when there is none.
fn append(data_root: &Path, block: &str) -> Result<(), AppError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let file = path(data_root);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&file)
        .map_err(|e| {
            AppError::Usage(format!("cannot write the room map {}: {e}", file.display()))
        })?;
    f.write_all(block.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| AppError::Usage(format!("cannot write the room map {}: {e}", file.display())))
}
