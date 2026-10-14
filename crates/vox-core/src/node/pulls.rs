//! Shares pulled without being asked (ADR-028 F-3, F-4).
//!
//! **An agent cannot click.** A node pulls a share by itself when it is addressed to this node, or
//! to no one, and the sharer is in this node's keyring — whatever its size, file or folder. A share
//! addressed to other nodes is left alone: any member may still pull it with `vox room get`.
//!
//! **Every pull is verified before it is saved** (ADR-020 11.4): the bytes go to a hidden `.part`
//! file, and only bytes whose size and SHA-256 match the signed announcement are linked into
//! place, under `<data root>/nodes/<node>/files/<room>/`, never over anything already there.
//! Nothing is written outside the node's files directory.
//!
//! **A pull never fills the disk.** Whatever its size, a share is pulled only while it leaves
//! [`RESERVE`] free on the disk it lands on, which also holds the node's store: one that would not
//! is not dialled, and the node says so once; it is looked at again on every scan and pulled when
//! there is room. A transfer re-checks every [`CHECK_EVERY`] bytes and stops below the reserve.
//!
//! Each pull is recorded in `<node>/pulls/<entry>.<nonce>.json`, by this daemon or by `vox room
//! get` into the same directory, so it is not pulled again, and so what was pulled can be found by
//! its announcement.
//!
//! **A pulled copy ends with its message** (ADR-028 F-5): once the announcement has expired here,
//! under the retention this node applies to the room, the daemon deletes the copy and its record.
//! A copy the person put elsewhere (`--dir`, `--out`) is theirs and is never recorded.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot, watch, Mutex};

use crate::hash::Digest32;
use crate::node::api::{Fault, NodeCommand, NodeView, Outcome};
use crate::node::link::{b32_decode, b32_encode};
use crate::node::paths::Paths;

/// How often the rooms are looked over for a share to pull, at most.
const SCAN: Duration = Duration::from_secs(1);

/// Pulls at once, across every room.
const AT_ONCE: usize = 2;

/// The first wait before a pull that failed is tried again; it doubles up to [`RETRY_MAX`].
const RETRY_MIN: Duration = Duration::from_secs(10);
/// The longest wait between tries of one pull.
const RETRY_MAX: Duration = Duration::from_secs(300);

/// How long one read of a transfer may wait before the pull is abandoned and tried again.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// What a pull must leave free on the disk it lands on: enough that the node's store and the
/// system can still write.
pub const RESERVE: u64 = 1_000_000_000;

/// How many bytes a transfer writes between looks at the free space.
pub const CHECK_EVERY: u64 = 64 << 20;

/// Free bytes for this user on the disk holding `dir`.
///
/// # Errors
/// The disk cannot be asked.
pub fn free_space(dir: &Path) -> Result<u64, String> {
    let s = rustix::fs::statvfs(dir)
        .map_err(|e| format!("cannot read the free space of {}: {e}", dir.display()))?;
    // The field's width differs by platform.
    #[allow(clippy::useless_conversion, clippy::unnecessary_fallible_conversions)]
    let unit = u64::try_from(s.f_frsize).unwrap_or(0).max(1);
    Ok(s.f_bavail.saturating_mul(unit))
}

/// Why `size` more bytes may not land in `dir`: a clause ending with what is free, or `None` when
/// they may. A disk that cannot be asked refuses nothing here; a write that fails says why.
#[must_use]
pub fn short_of_space(dir: &Path, size: u64) -> Option<String> {
    let free = free_space(dir).ok()?;
    (size.saturating_add(RESERVE) > free).then(|| {
        format!(
            "it would leave less than {} free on the disk holding {} ({} free now)",
            bytes(RESERVE),
            dir.display(),
            bytes(free)
        )
    })
}

/// A size as a person reads it: `12.0 GB`, `3.4 MB`, `512 bytes`.
#[must_use]
pub fn bytes(n: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let f = n as f64;
    match n {
        0..=999 => format!("{n} bytes"),
        1_000..=999_999 => format!("{:.1} KB", f / 1e3),
        1_000_000..=999_999_999 => format!("{:.1} MB", f / 1e6),
        1_000_000_000..=999_999_999_999 => format!("{:.1} GB", f / 1e9),
        _ => format!("{:.1} TB", f / 1e12),
    }
}

/// Whether a transfer into `dir` that has written `since` bytes since its last look must stop: it
/// looks every [`CHECK_EVERY`] bytes, and stops below [`RESERVE`].
///
/// # Errors
/// The sentence that stops it.
pub fn still_room(dir: &Path, since: &mut u64, written: u64) -> Result<(), String> {
    *since += written;
    if *since < CHECK_EVERY {
        return Ok(());
    }
    *since = 0;
    match free_space(dir) {
        Ok(free) if free < RESERVE => Err(format!(
            "stopped: the disk holding {} has less than {} free ({} free now)",
            dir.display(),
            bytes(RESERVE),
            bytes(free)
        )),
        _ => Ok(()),
    }
}

/// A share this node may pull: what its announcement says.
#[derive(Debug, Clone)]
struct Offer {
    room: Digest32,
    entry: Digest32,
    author: Digest32,
    name: String,
    size: u64,
    sha256: String,
    tag: String,
    http: bool,
    /// When it was announced, milliseconds.
    created_ms: u64,
    /// How many files a folder lists (ADR-028 F-8); `None` for a file. Its list is fetched from
    /// the sharer, and taken only if its SHA-256 is `sha256`.
    files: Option<u64>,
}

/// A pull, as it is recorded once done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pulled {
    /// The room.
    pub room: Digest32,
    /// The announcement's entry.
    pub entry: Digest32,
    /// Where the verified copy is.
    pub path: PathBuf,
    /// When it was announced, milliseconds.
    pub created_ms: u64,
    /// For a folder (ADR-028 F-8): who shared it and under what name, so pulling it again goes
    /// to the same place; `None` for a file.
    pub folder: Option<(Digest32, String)>,
    /// For a folder, every file this pull left in place as listed, `(path, sha256)`: what a later
    /// pull of it may replace, and what its message's end deletes.
    pub files: Vec<(String, String)>,
}

impl Pulled {
    fn to_json(&self) -> serde_json::Value {
        let mut v = serde_json::json!({
            "room": b32_encode(&self.room),
            "entry": b32_encode(&self.entry),
            "path": self.path.to_string_lossy(),
            "created_ms": self.created_ms,
        });
        if let Some((author, name)) = &self.folder {
            v["author"] = b32_encode(author).into();
            v["folder"] = name.clone().into();
            v["files"] = self
                .files
                .iter()
                .map(|(p, h)| serde_json::json!([p, h]))
                .collect();
        }
        v
    }

    fn from_json(v: &serde_json::Value) -> Option<Self> {
        let s = |k: &str| v.get(k).and_then(serde_json::Value::as_str);
        let folder = match (s("author"), s("folder")) {
            (Some(a), Some(n)) => Some((b32_decode(a, "pull record author").ok()?, n.to_owned())),
            _ => None,
        };
        let files = v
            .get("files")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        let e = e.as_array()?;
                        Some((
                            e.first()?.as_str()?.to_owned(),
                            e.get(1)?.as_str()?.to_owned(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            room: b32_decode(s("room")?, "pull record room").ok()?,
            entry: b32_decode(s("entry")?, "pull record entry").ok()?,
            path: PathBuf::from(s("path")?),
            // Milliseconds; a record written before held whole seconds as `created`.
            created_ms: v
                .get("created_ms")
                .and_then(serde_json::Value::as_u64)
                .or_else(|| {
                    v.get("created")
                        .and_then(serde_json::Value::as_u64)
                        .map(|secs| secs.saturating_mul(1_000))
                })?,
            folder,
            files,
        })
    }
}

/// Where a folder `name` shared by `author` in `room` is pulled to under `base`: where an earlier
/// pull of it went (ADR-028 F-8); else `name`, or the first of `name (1)`, `name (2)` … not
/// already there. Historical receipts are visited one at a time.
#[must_use]
pub fn folder_dir(
    paths: &Paths,
    base: &Path,
    room: &Digest32,
    author: &Digest32,
    name: &str,
) -> PathBuf {
    let name = safe_file_name(name);
    let earlier = recorded(paths)
        .chain(records_in(&pending_dir(paths)).map(|(_, p)| p))
        .find(|p| {
            p.room == *room
                && p.path.parent() == Some(base)
                && p.folder.as_ref() == Some(&(*author, name.clone()))
        });
    if let Some(first) = earlier {
        return first.path;
    }
    (0..1000)
        .map(|n| base.join(numbered(&name, n)))
        .find(|d| std::fs::symlink_metadata(d).is_err())
        .unwrap_or_else(|| base.join(&name))
}

/// What earlier pulls put at the paths in this verified folder listing. The listing already
/// has the folder protocol's file/path bounds; older versions cannot grow this map beyond it.
#[must_use]
pub fn folder_prior(
    paths: &Paths,
    dir: &Path,
    list: &[crate::node::folder::Listed],
) -> BTreeMap<String, String> {
    let wanted: BTreeSet<&str> = list.iter().map(|f| f.path.as_str()).collect();
    let mut prior = BTreeMap::new();
    for p in recorded(paths).chain(records_in(&pending_dir(paths)).map(|(_, p)| p)) {
        if p.path == dir && p.folder.is_some() {
            for (path, hash) in p.files {
                if wanted.contains(path.as_str()) {
                    prior.insert(path, hash);
                }
            }
        }
    }
    prior
}

/// Every pull this node has recorded.
#[must_use]
pub fn recorded(paths: &Paths) -> impl Iterator<Item = Pulled> + use<> {
    records(paths).map(|(_, p)| p)
}

/// Every pull this node has recorded, with the file that records it.
fn records(paths: &Paths) -> impl Iterator<Item = (PathBuf, Pulled)> + use<> {
    records_in(&paths.pulls_dir()).chain(
        std::fs::read_dir(paths.pulls_dir().join("records"))
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .flat_map(|entry| records_in(&entry.path())),
    )
}

fn entry_receipts(paths: &Paths, entry: &Digest32) -> PathBuf {
    paths.pulls_dir().join("records").join(b32_encode(entry))
}

/// Keep the existing receipt until its exact replacement directory entry is durable. If a
/// previous attempt stopped after linking it, only that same file may complete the move.
fn move_legacy_receipt(paths: &Paths, file: &Path, entry: &Digest32) -> Result<(), String> {
    let group = entry_receipts(paths, entry);
    let to = group.join(file.file_name().ok_or("receipt has no name")?);
    crate::node::paths::create_private_dir(&group).map_err(|e| e.to_string())?;
    crate::node::paths::sync_dir(&group).map_err(|e| e.to_string())?;
    if let Some(parent) = group.parent() {
        crate::node::paths::sync_dir(parent).map_err(|e| e.to_string())?;
    }
    if let Err(error) = std::fs::hard_link(file, &to) {
        #[cfg(unix)]
        let same = {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata(file)
                .ok()
                .zip(std::fs::metadata(&to).ok())
                .is_some_and(|(a, b)| a.dev() == b.dev() && a.ino() == b.ino())
        };
        #[cfg(not(unix))]
        let same = false;
        if error.kind() != std::io::ErrorKind::AlreadyExists || !same {
            return Err(error.to_string());
        }
    }
    crate::node::paths::sync_dir(&to).map_err(|e| e.to_string())?;
    std::fs::remove_file(file).map_err(|e| e.to_string())?;
    crate::node::paths::sync_dir(file).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(receipt_index(paths, entry));
    Ok(())
}

/// Where a folder pull under way is recorded until it completes: so one cut short is resumed in
/// the same place, and its files go with its message as a finished pull's do (ADR-028 F-5, F-8).
fn pending_dir(paths: &Paths) -> PathBuf {
    paths.pulls_dir().join("pending")
}

/// A folder pull is under way: `pulled` names its folder and every file it lists.
///
/// # Errors
/// It cannot be recorded.
pub fn begin(paths: &Paths, pulled: &Pulled) -> Result<(), String> {
    let dir = pending_dir(paths);
    crate::node::paths::create_private_dir(&dir)
        .and_then(|()| {
            crate::node::paths::write_private_file(
                &dir.join(format!("{}.json", b32_encode(&pulled.entry))),
                pulled.to_json().to_string().as_bytes(),
            )
        })
        .map_err(|e| e.to_string())
}

/// A folder pull completed: recorded as done, with what it left in place.
///
/// # Errors
/// It cannot be recorded.
pub fn finish(paths: &Paths, pulled: &Pulled) -> Result<(), String> {
    record(paths, pulled)?;
    let _ = std::fs::remove_file(
        pending_dir(paths).join(format!("{}.json", b32_encode(&pulled.entry))),
    );
    Ok(())
}

/// Every record in `dir`, with the file that holds it.
fn records_in(dir: &Path) -> impl Iterator<Item = (PathBuf, Pulled)> + use<> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter_map(|p| {
            let record = read_record(&p)?;
            Some((p, record))
        })
}

fn read_record(path: &Path) -> Option<Pulled> {
    read_record_checked(path).ok().flatten()
}

fn read_record_checked(path: &Path) -> Result<Option<Pulled>, String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let value = serde_json::from_reader::<_, serde_json::Value>(file)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Pulled::from_json(&value)
        .map(Some)
        .ok_or_else(|| format!("{}: invalid pull receipt", path.display()))
}

fn receipt_index(paths: &Paths, entry: &Digest32) -> PathBuf {
    paths
        .pulls_dir()
        .join("by-entry")
        .join(format!("{}.json", b32_encode(entry)))
}

/// A derived exact-entry pointer. Failure to save it cannot turn a completed, durable pull
/// into a failure: the authoritative receipt remains readable by the streaming fallback.
fn index_record(paths: &Paths, file: &Path, entry: &Digest32) {
    let Some(name) = file.file_name() else {
        return;
    };
    let path = receipt_index(paths, entry);
    if let Some(dir) = path.parent() {
        if crate::node::paths::create_private_dir(dir).is_ok() {
            let _ = crate::node::paths::write_private_file_unique(
                &path,
                name.to_string_lossy().as_bytes(),
            );
        }
    }
}

/// One completed offer, without loading other offers' bodies or folder manifests. The
/// streaming fallback upgrades the derived pointer for receipts written by an earlier build.
#[must_use]
pub fn recorded_entry(paths: &Paths, entry: &Digest32) -> Option<Pulled> {
    if let Some((_, pulled)) =
        records_in(&entry_receipts(paths, entry)).find(|(_, pulled)| pulled.entry == *entry)
    {
        return Some(pulled);
    }
    let prefix = format!("{}.", b32_encode(entry));
    if let Ok(name) = std::fs::read_to_string(receipt_index(paths, entry)) {
        let name = Path::new(&name);
        if name.components().count() == 1
            && name
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(&prefix))
        {
            if let Some(p) = read_record(&paths.pulls_dir().join(name)) {
                if p.entry == *entry {
                    return Some(p);
                }
            }
        }
    }
    // Filter names BEFORE opening records: an absent pointer never opens all historical
    // folder manifests just to find a single entry.
    for file in std::fs::read_dir(paths.pulls_dir())
        .into_iter()
        .flatten()
        .flatten()
    {
        if !file.file_name().to_string_lossy().starts_with(&prefix) {
            continue;
        }
        if let Some(p) = read_record(&file.path()) {
            if p.entry == *entry {
                index_record(paths, &file.path(), entry);
                return Some(p);
            }
        }
    }
    None
}

/// Record that `pulled` was put in the node's files directory, so it is deleted when its message
/// expires (F-5). A record of its own per copy: the same share pulled twice is two copies.
///
/// # Errors
/// The record cannot be written.
pub fn record(paths: &Paths, pulled: &Pulled) -> Result<(), String> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|e| format!("no randomness for the record: {e}"))?;
    // The authoritative receipts themselves are addressed by entry. A not-yet-pulled offer
    // therefore costs an exact directory lookup, not a walk over every completed transfer.
    // The flat earlier layout remains readable and is moved incrementally by the sweeper.
    let dir = entry_receipts(paths, &pulled.entry);
    let file = dir.join(format!(
        "{}.{}.json",
        b32_encode(&pulled.entry),
        hex(&nonce)
    ));
    crate::node::paths::create_private_dir(&dir)
        .and_then(|()| {
            crate::node::paths::sync_dir(&dir)?;
            if let Some(parent) = dir.parent() {
                crate::node::paths::sync_dir(parent)?;
            }
            crate::node::paths::write_private_file(&file, pulled.to_json().to_string().as_bytes())
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// The directory a room's pulled files land in.
#[must_use]
pub fn room_dir(paths: &Paths, room: &Digest32) -> PathBuf {
    paths.files_dir().join(b32_encode(room))
}

/// The sender's file name reduced to a **bare file name** that cannot leave the directory it is
/// put in.
///
/// Everything up to the last `/` or `\` is dropped, so `../../x`, `/etc/passwd` and `..\\x` all
/// become their last component. Control characters go, leading dots go (no `..`, and no file
/// hidden from a listing by a name somebody else chose), and the result is cut to 200 bytes.
/// Whatever is left empty becomes `download`.
#[must_use]
pub fn safe_file_name(name: &str) -> String {
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = last.chars().filter(|c| !c.is_control()).collect();
    let trimmed = cleaned.trim().trim_start_matches('.').trim();
    let mut out = String::new();
    for c in trimmed.chars() {
        if out.len() + c.len_utf8() > 200 {
            break;
        }
        out.push(c);
    }
    if out.is_empty() {
        "download".to_owned()
    } else {
        out
    }
}

/// `name`, then `name (1)`, `name (2)` … with the number before the extension.
#[must_use]
pub fn numbered(name: &str, n: usize) -> String {
    if n == 0 {
        return name.to_owned();
    }
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem} ({n}).{ext}"),
        _ => format!("{name} ({n})"),
    }
}

/// A retry/refusal belongs beside the saved pull records, not in a growing resident map.
#[derive(serde::Serialize, serde::Deserialize)]
struct SavedState {
    room: Digest32,
    created_ms: u64,
    state: SavedKind,
}

#[derive(serde::Serialize, serde::Deserialize)]
enum SavedKind {
    Waiting {
        until_ms: u64,
        wait_ms: u64,
        why: String,
    },
    Failed {
        why: String,
    },
    Short,
}

fn state_path(paths: &Paths, entry: &Digest32) -> PathBuf {
    paths
        .pulls_dir()
        .join("states")
        .join(format!("{}.json", b32_encode(entry)))
}

fn saved_state(paths: &Paths, entry: &Digest32) -> Result<Option<SavedState>, String> {
    let path = state_path(paths, entry);
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    };
    serde_json::from_reader(file)
        .map(Some)
        .map_err(|e| format!("reading {}: {e}", path.display()))
}

fn save_state(paths: &Paths, offer: &Offer, state: SavedKind) -> Result<(), String> {
    let path = state_path(paths, &offer.entry);
    let dir = path.parent().ok_or("pull state has no directory")?;
    let bytes = serde_json::to_vec(&SavedState {
        room: offer.room,
        created_ms: offer.created_ms,
        state,
    })
    .map_err(|e| e.to_string())?;
    crate::node::paths::create_private_dir(dir)
        .and_then(|()| crate::node::paths::write_private_file_unique(&path, &bytes))
        .map_err(|e| e.to_string())
}

/// Where one offer's pull stands on this node, for a client to say (ADR-028 F-3; D5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullState {
    /// Being pulled: `bytes` of `of` have come (a folder's are not counted).
    Pulling {
        /// What has come.
        bytes: u64,
        /// What was announced.
        of: u64,
    },
    /// Failed, and tried again later by itself: the sharer may be offline.
    Waiting {
        /// Why the last try failed.
        why: String,
    },
    /// Asked for, and failed.
    Failed {
        /// Why.
        why: String,
    },
}

#[derive(Default)]
struct ScanCursor {
    last_room: Option<Digest32>,
    pages: BTreeMap<Digest32, Option<crate::node::api::HistoryCursor>>,
    session_pages: BTreeMap<Digest32, Option<crate::node::api::HistoryCursor>>,
}

/// A retained directory cursor costs no per-receipt memory. Even invalid/non-record files
/// consume a sweep slot, so a directory full of them cannot make one daemon turn unbounded.
#[derive(Default)]
struct ExpireCursor {
    entries: Option<std::fs::ReadDir>,
    group_entries: Option<std::fs::ReadDir>,
    phase: usize,
    folder: Option<FolderExpiry>,
    failure: Option<String>,
}

/// At most one expired folder waits while its other receipts are checked in bounded turns.
/// Keeping an iterator, rather than completing that scan inside one sweep slot, avoids an
/// entire-history walk for each folder on one daemon turn.
struct FolderExpiry {
    receipt: PathBuf,
    pulled: Pulled,
    other: Box<dyn Iterator<Item = Result<PathBuf, String>> + Send>,
    revision: [Option<std::time::SystemTime>; 3],
}

fn receipt_paths(paths: &Paths) -> impl Iterator<Item = Result<PathBuf, String>> + use<> {
    let paths = paths.clone();
    let mut cursor = ExpireCursor::default();
    let mut done = false;
    std::iter::from_fn(move || {
        if done {
            return None;
        }
        let file = cursor.next(&paths);
        if let Some(why) = cursor.failure.take() {
            done = true;
            return Some(Err(why));
        }
        let file = file?;
        if cursor.phase == 3 {
            done = true;
            return None;
        }
        Some(Ok(file))
    })
}

fn receipt_revision(paths: &Paths) -> Result<[Option<std::time::SystemTime>; 3], String> {
    let modified = |dir: PathBuf| match std::fs::metadata(&dir) {
        Ok(meta) => meta
            .modified()
            .map(Some)
            .map_err(|e| format!("{}: {e}", dir.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", dir.display())),
    };
    Ok([
        modified(paths.pulls_dir())?,
        modified(paths.pulls_dir().join("records"))?,
        modified(pending_dir(paths))?,
    ])
}

fn forget_receipt(paths: &Paths, receipt: &Path, entry: &Digest32) {
    if std::fs::remove_file(receipt).is_ok() {
        let index = receipt_index(paths, entry);
        if std::fs::read_to_string(&index)
            .is_ok_and(|name| Some(std::ffi::OsStr::new(&name)) == receipt.file_name())
        {
            let _ = std::fs::remove_file(index);
        }
        let group = entry_receipts(paths, entry);
        if receipt.parent() == Some(group.as_path()) {
            let _ = std::fs::remove_dir(group);
        }
    }
}

impl ExpireCursor {
    fn open_dir(&mut self, path: &Path) -> Option<std::fs::ReadDir> {
        match std::fs::read_dir(path) {
            Ok(entries) => Some(entries),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                self.failure = Some(format!("{}: {e}", path.display()));
                None
            }
        }
    }

    fn entry_path(&mut self, entry: std::io::Result<std::fs::DirEntry>) -> PathBuf {
        match entry {
            Ok(entry) => entry.path(),
            Err(e) => {
                self.failure = Some(e.to_string());
                PathBuf::new()
            }
        }
    }

    fn next(&mut self, paths: &Paths) -> Option<PathBuf> {
        for _ in 0..4 {
            if self.phase == 1 {
                if let Some(entries) = &mut self.group_entries {
                    if let Some(entry) = entries.next() {
                        return Some(self.entry_path(entry));
                    }
                    self.group_entries = None;
                    return Some(PathBuf::new());
                }
            }
            if self.entries.is_none() {
                let dir = match self.phase {
                    0 => paths.pulls_dir(),
                    1 => paths.pulls_dir().join("records"),
                    2 => pending_dir(paths),
                    _ => paths.pulls_dir().join("states"),
                };
                self.entries = self.open_dir(&dir);
            }
            if let Some(entry) = self.entries.as_mut().and_then(Iterator::next) {
                if self.phase == 1 {
                    let path = self.entry_path(entry);
                    self.group_entries = self.open_dir(&path);
                    return Some(PathBuf::new());
                }
                return Some(self.entry_path(entry));
            }
            self.entries = None;
            self.phase = (self.phase + 1) % 4;
            if self.phase == 0 {
                return None;
            }
        }
        None
    }
}

/// The pulls of one node.
pub(crate) struct Pulls {
    paths: Paths,
    cmd: mpsc::WeakSender<(NodeCommand, oneshot::Sender<Outcome>)>,
    view: watch::Receiver<NodeView>,
    history: crate::node::actor::HistoryReader,
    cursor: Mutex<ScanCursor>,
    expiry: std::sync::Mutex<ExpireCursor>,
    events: tokio::sync::broadcast::Sender<crate::node::api::NodeEvent>,
    /// The transfer future owns its offer. Cancellation drops that ownership, so an
    /// interrupted client cannot leave a running slot stuck forever. At most AT_ONCE keys.
    running: Mutex<BTreeMap<Digest32, std::sync::Weak<Offer>>>,
}

impl std::fmt::Debug for Pulls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pulls")
    }
}

/// The node's clock in milliseconds, a test step included, as the node's own clock has it.
fn now_ms() -> u64 {
    (crate::time::clock_with_test_skew())()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// What a driver's drive request says of a file it sends into a Session (ADR-029 DR-1.7, #546).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Driven {
    /// The room the Session is in.
    pub room: Digest32,
    /// The driver's node, which serves it.
    pub from: Digest32,
    /// Its name.
    pub name: String,
    /// Its size, bytes.
    pub size: u64,
    /// Its SHA-256, hex.
    pub sha256: String,
    /// The driver's service it is served on.
    pub tag: String,
}

/// Pull a file a driver sent into a Session on this node (ADR-029 DR-1.7, #546): from the
/// driver's node, verified by its SHA-256 before it is kept, into the room's files directory
/// (ADR-028 F-4). Returns where it landed. Record it with [`record`] under the Session entry that
/// says so, so it ages with the room (F-5).
///
/// # Errors
/// The forward to the driver's node could not be made, or what came was not the file announced.
pub async fn pull_driven(
    handle: &crate::node::actor::NodeHandle,
    paths: &Paths,
    driven: &Driven,
) -> Result<PathBuf, String> {
    let sha = driven.sha256.to_ascii_lowercase();
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("the file's SHA-256 is not one".into());
    }
    let dir = room_dir(paths, &driven.room);
    crate::node::paths::create_private_dir(&dir).map_err(|e| e.to_string())?;
    // **From this node itself** (a node driving its own Session, ADR-029 SC-2): no tunnel runs
    // from a node to itself, so the file is copied from where its share serves it, and held to
    // what the drive named as a pull is.
    if handle.view().identity.map(|i| i.fingerprint) == Some(driven.from) {
        let (served, size, served_sha) = handle
            .shares()
            .served_file(&driven.room, &driven.tag)
            .await
            .ok_or("this node does not serve that file")?;
        if size != driven.size || served_sha != sha {
            return Err("the file this node serves is not the one the drive named".into());
        }
        let name = safe_file_name(&driven.name);
        let part = dir.join(format!(
            ".{name}.{}.part",
            hex(&crate::hash::sha256(driven.tag.as_bytes())[..8])
        ));
        let copied = {
            let (part, sha) = (part.clone(), sha.clone());
            tokio::task::spawn_blocking(move || copy_checked(&served, &part, size, &sha))
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r)
        };
        if let Err(e) = copied {
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
        let placed = place(&part, &dir, &name);
        let _ = std::fs::remove_file(&part);
        return placed;
    }
    let offer = Offer {
        room: driven.room,
        entry: crate::hash::sha256(driven.tag.as_bytes()),
        author: driven.from,
        name: driven.name.clone(),
        size: driven.size,
        sha256: sha,
        tag: driven.tag.clone(),
        http: true,
        created_ms: now_ms(),
        files: None,
    };
    let bound = match handle
        .apply(NodeCommand::Forward {
            channel_id: offer.room,
            host: offer.author,
            service_tag: offer.tag.clone(),
            local: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        })
        .await
    {
        Outcome::Bound(local) => local,
        other => return Err(other.to_string()),
    };
    let name = safe_file_name(&offer.name);
    let part = dir.join(format!(".{name}.{}.part", hex(&offer.entry[..8])));
    let received = receive(bound, &part, &offer).await;
    let _ = handle
        .apply(NodeCommand::StopForward { local: bound })
        .await;
    if let Err(e) = received {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    let placed = place(&part, &dir, &name);
    let _ = std::fs::remove_file(&part);
    placed
}

/// Copy `from` to `to`, holding it to `size` bytes and SHA-256 `sha` as a pull's bytes are held.
fn copy_checked(from: &Path, to: &Path, size: u64, sha: &str) -> Result<(), String> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;
    let mut src =
        std::fs::File::open(from).map_err(|e| format!("reading {}: {e}", from.display()))?;
    let mut dst =
        std::fs::File::create(to).map_err(|e| format!("writing {}: {e}", to.display()))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = src.read(&mut buf).map_err(|e| format!("reading: {e}"))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > size {
            return Err("the file is longer than the drive named".into());
        }
        hasher.update(&buf[..n]);
        dst.write_all(&buf[..n])
            .map_err(|e| format!("writing: {e}"))?;
    }
    dst.sync_all().map_err(|e| format!("writing: {e}"))?;
    if total != size || hex(&hasher.finalize()) != sha {
        return Err(format!(
            "the file does not match what the drive named: expected sha256 {sha} over {size} bytes"
        ));
    }
    Ok(())
}

/// The share `text` announces, if it is one this node may pull: a `file` announcement addressed to
/// `me` or to no one. `None` for anything else, for good.
#[allow(clippy::type_complexity)]
fn offer_in(text: &str, me: &str) -> Option<(String, u64, String, String, bool, Option<u64>)> {
    offer_fields(text, Some(me))
}

/// What a share's announcement offers. With `me`, only one addressed to this node, one of its
/// sessions (ADR-029 TA-1), or no one: what this node pulls by itself. Without, any: what a
/// person may pull with `get` (ADR-028 F-3).
fn offer_fields(
    text: &str,
    me: Option<&str>,
) -> Option<(String, u64, String, String, bool, Option<u64>)> {
    let v: serde_json::Value = serde_json::from_str(text.trim_start()).ok()?;
    if v.get("type").and_then(serde_json::Value::as_str) != Some(crate::node::shares::FILE) {
        return None;
    }
    let to: Vec<&str> = v
        .get("to")
        .and_then(serde_json::Value::as_array)
        .map(|a| a.iter().filter_map(serde_json::Value::as_str).collect())
        .unwrap_or_default();
    if let Some(me) = me {
        if !to.is_empty()
            && !to
                .iter()
                .any(|t| vox_agentcomms::envelope::addressee(t).0 == me)
        {
            return None;
        }
    }
    let d = v.get("data")?;
    let s = |k: &str| {
        d.get(k)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let sha256 = s("sha256")?;
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let sha256 = sha256.to_ascii_lowercase();
    let size = d.get("size").and_then(serde_json::Value::as_u64)?;
    // A folder says how many files its list holds (ADR-028 F-8); the list is fetched and checked
    // against the announced SHA-256 before anything else is.
    let files = match d.get("files") {
        None => None,
        Some(v) => {
            Some(v.as_u64()?).filter(|n| (1..=crate::node::folder::MAX_FILES as u64).contains(n))
        }
    };
    if d.get("files").is_some() && files.is_none() {
        return None;
    }
    Some((
        s("name")?,
        size,
        sha256,
        s("tag")?,
        d.get("http")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        files,
    ))
}

/// The share a Session's `file` entry announces (ADR-029 DR-1.8, #546), as [`offer_in`] reads a
/// room's: its fields sit in the entry itself, and it is for every member that can open it.
#[allow(clippy::type_complexity)]
fn offer_in_session(body: &str) -> Option<(String, u64, String, String, bool, Option<u64>)> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    if v["kind"] != "file" || v["dir"] != "out" {
        return None;
    }
    let s = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let sha256 = s("sha256")?;
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let files = match v.get("files") {
        None => None,
        Some(n) => {
            Some(n.as_u64()?).filter(|n| (1..=crate::node::folder::MAX_FILES as u64).contains(n))
        }
    };
    if v.get("files").is_some() && files.is_none() {
        return None;
    }
    Some((
        s("name")?,
        v.get("size").and_then(serde_json::Value::as_u64)?,
        sha256.to_ascii_lowercase(),
        s("tag")?,
        v.get("http")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        files,
    ))
}

impl Pulls {
    /// Pull what is this node's to pull, for as long as the node runs: the task ends when the
    /// node's view does.
    pub(crate) fn spawn(
        paths: Paths,
        cmd: mpsc::WeakSender<(NodeCommand, oneshot::Sender<Outcome>)>,
        view: watch::Receiver<NodeView>,
        history: crate::node::actor::HistoryReader,
        events: tokio::sync::broadcast::Sender<crate::node::api::NodeEvent>,
    ) -> Arc<Self> {
        let pulls = Arc::new(Self {
            history,
            cursor: Mutex::new(ScanCursor::default()),
            expiry: std::sync::Mutex::new(ExpireCursor::default()),
            events,
            paths,
            cmd,
            view,
            running: Mutex::new(BTreeMap::new()),
        });
        let held = Arc::clone(&pulls);
        tokio::spawn(async move {
            let mut view = pulls.view.clone();
            loop {
                tokio::select! {
                    changed = view.changed() => if changed.is_err() { break },
                    () = tokio::time::sleep(SCAN) => {}
                }
                Arc::clone(&pulls).scan().await;
                let expiring = Arc::clone(&pulls);
                // Folder checks can read/hash files. They must not occupy a Tokio worker or
                // borrow the current node view while doing disk I/O.
                let _ = tokio::task::spawn_blocking(move || expiring.expire()).await;
                tokio::time::sleep(SCAN).await;
            }
        });
        held
    }

    /// The bounded previous listing contract. Larger retained sets require exact-entry
    /// queries; never allocate all saved failures just to discover that the reply is too big.
    pub(crate) async fn states(
        &self,
        room: &Digest32,
    ) -> Result<Vec<(Digest32, PullState)>, String> {
        let active: Vec<Digest32> = self
            .running
            .lock()
            .await
            .iter()
            .filter(|(_, o)| o.upgrade().is_some_and(|o| o.room == *room))
            .map(|(e, _)| *e)
            .collect();
        let mut entries = active;
        for file in std::fs::read_dir(self.paths.pulls_dir().join("states"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = file.file_name();
            let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".json")) else {
                continue;
            };
            let Ok(entry) = b32_decode(id, "pull entry") else {
                continue;
            };
            if entries.contains(&entry) {
                continue;
            }
            if saved_state(&self.paths, &entry)?
                .is_some_and(|s| s.room == *room && !matches!(s.state, SavedKind::Short))
            {
                if entries.len() == 64 {
                    return Err("this room has more pull states than one reply holds; read the states of the displayed entries".into());
                }
                entries.push(entry);
            }
        }
        self.states_for(room, &entries).await
    }

    /// Only the requested visible entries, never the node's complete saved transfer history.
    pub(crate) async fn states_for(
        &self,
        room: &Digest32,
        entries: &[Digest32],
    ) -> Result<Vec<(Digest32, PullState)>, String> {
        if entries.len() > 64 {
            return Err("at most 64 pull states may be read at once".into());
        }
        let running = self.running.lock().await;
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for entry in entries {
            let state = if let Some(o) = running
                .get(entry)
                .and_then(std::sync::Weak::upgrade)
                .filter(|o| o.room == *room)
            {
                Some(PullState::Pulling {
                    bytes: std::fs::metadata(self.part_of(&o)).map_or(0, |m| m.len()),
                    of: o.size,
                })
            } else {
                match saved_state(&self.paths, entry)?
                    .filter(|s| s.room == *room)
                    .map(|s| s.state)
                {
                    Some(SavedKind::Waiting { why, .. }) => Some(PullState::Waiting { why }),
                    Some(SavedKind::Failed { why }) => Some(PullState::Failed { why }),
                    Some(SavedKind::Short) | None => None,
                }
            };
            if let Some(state) = state {
                bytes += 64
                    + match &state {
                        PullState::Waiting { why } | PullState::Failed { why } => why.len(),
                        PullState::Pulling { .. } => 0,
                    };
                if bytes > 512 * 1024 && !out.is_empty() {
                    return Err(
                        "these pull states exceed one reply's byte budget; read fewer entries"
                            .into(),
                    );
                }
                out.push((*entry, state));
            }
        }
        Ok(out)
    }

    fn note_short(&self, offer: &Offer) -> bool {
        if matches!(
            saved_state(&self.paths, &offer.entry),
            Ok(Some(SavedState {
                state: SavedKind::Short,
                ..
            }))
        ) {
            return false;
        }
        if let Err(why) = save_state(&self.paths, offer, SavedKind::Short) {
            self.say_state_error(why);
        }
        true
    }

    fn say_state_error(&self, why: String) {
        let _ = self.events.send(crate::node::api::NodeEvent::NodeNote {
            note: format!(
                "could not save/read a pull's retry state; it will be checked again: {why}"
            ),
        });
    }

    /// **Pull one offer now, as `vox room get` does** (ADR-028 F-3; D5): whoever it is addressed
    /// to, and from a member this node has not trusted too, since a person asked. Verified by its
    /// SHA-256 before it is put in place and recorded, as every pull is; nothing unverified is
    /// ever where a client looks. Where it landed, or why not. One already pulled is not pulled
    /// again; one being pulled is waited for.
    ///
    /// # Errors
    /// The offer cannot be found or pulled, said in plain words.
    pub(crate) async fn get(&self, room: Digest32, entry: Digest32) -> Result<PathBuf, String> {
        let landed = |paths: &Paths| {
            recorded_entry(paths, &entry)
                .filter(|p| p.room == room && p.path.exists())
                .or_else(|| {
                    let prefix = format!("{}.", b32_encode(&entry));
                    std::fs::read_dir(entry_receipts(paths, &entry))
                        .into_iter()
                        .flatten()
                        .chain(std::fs::read_dir(paths.pulls_dir()).into_iter().flatten())
                        .flatten()
                        .filter(|f| f.file_name().to_string_lossy().starts_with(&prefix))
                        .filter_map(|f| read_record(&f.path()))
                        .find(|p| p.room == room && p.entry == entry && p.path.exists())
                })
                .map(|p| p.path)
        };
        let offer = Arc::new(self.offer_of(&room, &entry).await?);
        loop {
            if let Some(path) = landed(&self.paths) {
                return Ok(path);
            }
            let mut running = self.running.lock().await;
            running.retain(|_, offer| offer.strong_count() > 0);
            if running.contains_key(&entry) || running.len() >= AT_ONCE {
                drop(running);
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
            let dir = room_dir(&self.paths, &room);
            let _ = crate::node::paths::create_private_dir(&dir);
            if let Some(why) = short_of_space(&dir, offer.size) {
                if let Err(e) =
                    save_state(&self.paths, &offer, SavedKind::Failed { why: why.clone() })
                {
                    self.say_state_error(e);
                }
                return Err(why);
            }
            running.insert(entry, Arc::downgrade(&offer));
            break;
        }
        let done = self.pull(&offer).await;
        let mut running = self.running.lock().await;
        running.remove(&entry);
        match done {
            Ok(()) => {
                let _ = std::fs::remove_file(state_path(&self.paths, &entry));
                landed(&self.paths).ok_or_else(|| "it was pulled, but its record is gone".into())
            }
            Err(why) => {
                if let Err(e) =
                    save_state(&self.paths, &offer, SavedKind::Failed { why: why.clone() })
                {
                    self.say_state_error(e);
                }
                Err(why)
            }
        }
    }

    /// The offer `entry` of `room` makes, whoever it is addressed to.
    async fn offer_of(&self, room: &Digest32, entry: &Digest32) -> Result<Offer, String> {
        let row = self
            .history
            .exact(*room, vec![*entry])
            .await?
            .into_iter()
            .next();
        let session = if row.is_none() {
            self.history.session_file(*room, *entry).await?
        } else {
            None
        };
        let now = now_ms();
        let view = self.view.borrow();
        let me = view.identity.as_ref().map(|i| i.fingerprint);
        let d = view
            .open_channels
            .iter()
            .find(|d| d.channel_id == *room)
            .ok_or("the room is not open on this node")?;
        let (author, created, fields) = if let Some(r) = row.as_ref() {
            if r.owed {
                return Err("that message has not arrived yet".into());
            }
            (r.author, r.created_millis, offer_fields(&r.text, None))
        } else if let Some(r) = session.as_ref() {
            (r.author, r.created_millis, offer_in_session(&r.body))
        } else {
            return Err("no message in this room has that id".into());
        };
        if Some(author) == me {
            return Err("it is this node's own share".into());
        }
        let (name, size, sha256, tag, http, files) = fields.ok_or("that message offers no file")?;
        let created = created.min(now);
        if d.retention > 0 && now >= created.saturating_add(d.retention.saturating_mul(1_000)) {
            return Err("its message has expired here, and the file with it".into());
        }
        Ok(Offer {
            room: *room,
            entry: *entry,
            author,
            name,
            size,
            sha256,
            tag,
            http,
            created_ms: created,
            files,
        })
    }

    /// Where a file offer is written while it comes.
    fn part_of(&self, offer: &Offer) -> PathBuf {
        room_dir(&self.paths, &offer.room).join(format!(
            ".{}.{}.part",
            safe_file_name(&offer.name),
            hex(&offer.entry[..8])
        ))
    }

    async fn apply(&self, command: NodeCommand) -> Outcome {
        let Some(cmd) = self.cmd.upgrade() else {
            return Outcome::Failed(Fault::ShuttingDown);
        };
        let (tx, rx) = oneshot::channel();
        if cmd.send((command, tx)).await.is_err() {
            return Outcome::Failed(Fault::ShuttingDown);
        }
        rx.await.unwrap_or(Outcome::Failed(Fault::ShuttingDown))
    }

    /// Look over every open room, and start what is due.
    async fn scan(self: Arc<Self>) {
        let now = now_ms();
        // One room and one bounded offer page per turn. A completed cycle starts again,
        // so granting trust later still discovers an older offer.
        let (room, after, session_after) = {
            let mut cursor = self.cursor.lock().await;
            let view = self.view.borrow();
            if view.locked || view.identity.is_none() {
                return;
            }
            cursor
                .pages
                .retain(|room, _| view.open_channels.iter().any(|d| d.channel_id == *room));
            cursor
                .session_pages
                .retain(|room, _| view.open_channels.iter().any(|d| d.channel_id == *room));
            // Rotate after one page, even on a read failure. An unending offer stream in
            // one room cannot prevent another open room's file from being considered.
            let chosen = view
                .open_channels
                .iter()
                .filter(|d| cursor.last_room.is_none_or(|last| d.channel_id > last))
                .map(|d| d.channel_id)
                .min()
                .or_else(|| view.open_channels.iter().map(|d| d.channel_id).min());
            let Some(room) = chosen else {
                return;
            };
            cursor.last_room = Some(room);
            (
                room,
                cursor.pages.get(&room).copied().flatten(),
                cursor.session_pages.get(&room).copied().flatten(),
            )
        };
        let page = match self
            .history
            .typed_page(room, vec![crate::node::shares::FILE.to_owned()], after, 32)
            .await
        {
            Ok(page) => page,
            Err(e) => {
                let _ = self.events.send(crate::node::api::NodeEvent::NodeNote {
                    note: format!("could not read file offers; will retry: {e}"),
                });
                return;
            }
        };
        let session_page = match self
            .history
            .session_files_page(room, session_after, 32)
            .await
        {
            Ok(page) => Some(page),
            Err(e) => {
                let _ = self.events.send(crate::node::api::NodeEvent::NodeNote {
                    note: format!("could not read Session file offers; will retry: {e}"),
                });
                None
            }
        };
        let mut found: Vec<Offer> = Vec::new();
        {
            let view = self.view.borrow();
            let Some(me) = view.identity.as_ref().map(|i| i.fingerprint) else {
                return;
            };
            if view.locked {
                return;
            }
            let me_b32 = b32_encode(&me);
            if let Some(d) = view.open_channels.iter().find(|d| d.channel_id == room) {
                for r in &page.rows {
                    if r.owed || r.author == me {
                        continue;
                    }
                    let Some((name, size, sha256, tag, http, files)) = offer_in(&r.text, &me_b32)
                    else {
                        continue;
                    };
                    let created = r.created_millis.min(now);
                    if d.retention > 0
                        && now >= created.saturating_add(d.retention.saturating_mul(1_000))
                    {
                        continue;
                    }
                    if !view.trusted.iter().any(|(fp, _)| *fp == r.author) {
                        continue;
                    }
                    found.push(Offer {
                        room: d.channel_id,
                        entry: r.entry_hash,
                        author: r.author,
                        name,
                        size,
                        sha256,
                        tag,
                        http,
                        created_ms: created,
                        files,
                    });
                }
                // **A file a Session sent out** (ADR-029 DR-1.8): this node opened its entry, so
                // its node trusts it with drive; it is pulled as a share addressed to it is.
                for r in session_page.as_ref().into_iter().flat_map(|p| &p.rows) {
                    let Some((name, size, sha256, tag, http, files)) = offer_in_session(&r.body)
                    else {
                        continue;
                    };
                    let created = r.created_millis.min(now);
                    if d.retention > 0
                        && now >= created.saturating_add(d.retention.saturating_mul(1_000))
                    {
                        continue;
                    }
                    if !view.trusted.iter().any(|(fp, _)| *fp == r.author) {
                        continue;
                    }
                    found.push(Offer {
                        room: d.channel_id,
                        entry: r.entry_hash,
                        author: r.author,
                        name,
                        size,
                        sha256,
                        tag,
                        http,
                        created_ms: created,
                        files,
                    });
                }
            }
        }
        self.cursor.lock().await.pages.insert(room, page.next);
        if let Some(page) = session_page {
            self.cursor
                .lock()
                .await
                .session_pages
                .insert(room, page.next);
        }
        let mut running = self.running.lock().await;
        running.retain(|_, offer| offer.strong_count() > 0);
        for offer in found {
            if running.len() >= AT_ONCE {
                break;
            }
            if recorded_entry(&self.paths, &offer.entry).is_some() {
                continue;
            }
            // **Not dialled while it would fill the disk**, and said once; looked at again on the
            // next scan rather than retried on a timer.
            let dir = room_dir(&self.paths, &offer.room);
            let _ = crate::node::paths::create_private_dir(&dir);
            if let Some(why) = short_of_space(&dir, offer.size) {
                if self.note_short(&offer) {
                    let who = self
                        .view
                        .borrow()
                        .trusted
                        .iter()
                        .find(|(fp, _)| *fp == offer.author)
                        .map_or_else(
                            || b32_encode(&offer.author)[..12].to_owned(),
                            |(_, n)| n.clone(),
                        );
                    let _ = self.events.send(crate::node::api::NodeEvent::NodeNote {
                        note: format!(
                            "not pulled: {} ({}) from {who} — {why}; it is pulled when there is \
                             room, or with `vox room get`",
                            safe_file_name(&offer.name),
                            bytes(offer.size)
                        ),
                    });
                }
                continue;
            }
            if running.contains_key(&offer.entry) {
                continue;
            }
            let wait_ms = match saved_state(&self.paths, &offer.entry) {
                Ok(Some(SavedState {
                    state: SavedKind::Waiting { until_ms, .. },
                    ..
                })) if until_ms > now => continue,
                Ok(Some(SavedState {
                    state: SavedKind::Waiting { wait_ms, .. },
                    ..
                })) => wait_ms,
                Ok(_) => RETRY_MIN.as_millis() as u64 / 2,
                Err(why) => {
                    self.say_state_error(why);
                    continue;
                }
            };
            let offer = Arc::new(offer);
            running.insert(offer.entry, Arc::downgrade(&offer));
            let pulls = Arc::clone(&self);
            tokio::spawn(async move {
                let done = pulls.pull(&offer).await;
                let mut running = pulls.running.lock().await;
                running.remove(&offer.entry);
                match done {
                    Ok(()) => {
                        let _ = std::fs::remove_file(state_path(&pulls.paths, &offer.entry));
                    }
                    Err(why) => {
                        let wait_ms = wait_ms
                            .saturating_mul(2)
                            .clamp(RETRY_MIN.as_millis() as u64, RETRY_MAX.as_millis() as u64);
                        if let Err(e) = save_state(
                            &pulls.paths,
                            &offer,
                            SavedKind::Waiting {
                                until_ms: now_ms().saturating_add(wait_ms),
                                wait_ms,
                                why,
                            },
                        ) {
                            pulls.say_state_error(e);
                        }
                    }
                }
            });
        }
    }

    /// Pull `offer`, verify it, and put it in place.
    async fn pull(&self, offer: &Offer) -> Result<(), String> {
        let dir = room_dir(&self.paths, &offer.room);
        crate::node::paths::create_private_dir(&dir).map_err(|e| e.to_string())?;
        if let Some(count) = offer.files {
            return self.pull_folder(offer, &dir, count).await;
        }
        let bound = match self
            .apply(NodeCommand::Forward {
                channel_id: offer.room,
                host: offer.author,
                service_tag: offer.tag.clone(),
                local: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            })
            .await
        {
            Outcome::Bound(local) => local,
            other => return Err(other.to_string()),
        };
        let name = safe_file_name(&offer.name);
        let part = self.part_of(offer);
        let received = receive(bound, &part, offer).await;
        let _ = self.apply(NodeCommand::StopForward { local: bound }).await;
        if let Err(e) = received {
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
        let placed = place(&part, &dir, &name);
        let _ = std::fs::remove_file(&part);
        let path = placed?;
        record(
            &self.paths,
            &Pulled {
                room: offer.room,
                entry: offer.entry,
                path,
                created_ms: offer.created_ms,
                folder: None,
                files: Vec::new(),
            },
        )
    }

    /// Pull a folder (ADR-028 F-8) into `base`: where an earlier pull of it went, fetching only
    /// what is not already there as listed. A pull cut short is not recorded, so it is tried again,
    /// and that try keeps every file the first one finished.
    async fn pull_folder(&self, offer: &Offer, base: &Path, count: u64) -> Result<(), String> {
        let dir = folder_dir(&self.paths, base, &offer.room, &offer.author, &offer.name);
        crate::node::paths::create_private_dir(&dir).map_err(|e| e.to_string())?;
        let bound = match self
            .apply(NodeCommand::Forward {
                channel_id: offer.room,
                host: offer.author,
                service_tag: offer.tag.clone(),
                local: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            })
            .await
        {
            Outcome::Bound(local) => local,
            other => return Err(other.to_string()),
        };
        let mut pull = Pulled {
            room: offer.room,
            entry: offer.entry,
            path: dir.clone(),
            created_ms: offer.created_ms,
            folder: Some((offer.author, safe_file_name(&offer.name))),
            files: Vec::new(),
        };
        let pulled = match crate::node::folder::fetch_list(bound, &offer.sha256, count).await {
            Ok(list) => {
                let prior = folder_prior(&self.paths, &dir, &list);
                pull.files = list
                    .iter()
                    .map(|f| (f.path.clone(), f.sha256.clone()))
                    .collect();
                match begin(&self.paths, &pull) {
                    Ok(()) => crate::node::folder::pull(bound, &dir, &list, &prior).await,
                    Err(e) => Err((e, crate::node::folder::Pulled::default())),
                }
            }
            Err(e) => Err((e, crate::node::folder::Pulled::default())),
        };
        let _ = self.apply(NodeCommand::StopForward { local: bound }).await;
        let done = pulled.map_err(|(e, _)| {
            // A folder made for a pull that put nothing in it goes again.
            let _ = std::fs::remove_dir(&dir);
            e
        })?;
        pull.files = done.placed;
        finish(&self.paths, &pull)
    }

    /// Visit a bounded portion of the saved receipts. A closed room is left alone until its
    /// retention is known again. Receipts and the folder-reference check are streamed, never
    /// collected into a second copy of all the node's retained history.
    fn expire(&self) {
        let now = now_ms();
        let retention: Option<BTreeMap<Digest32, u64>> = {
            let view = self.view.borrow();
            (!view.locked).then(|| {
                view.open_channels
                    .iter()
                    .map(|d| (d.channel_id, d.retention))
                    .collect()
            })
        };
        let Some(retention) = retention else {
            if let Ok(mut cursor) = self.expiry.lock() {
                *cursor = ExpireCursor::default();
            }
            return;
        };
        let due = |p: &Pulled| {
            retention.get(&p.room).is_some_and(|ttl| {
                *ttl > 0 && now >= p.created_ms.saturating_add(ttl.saturating_mul(1_000))
            })
        };
        let Ok(mut cursor) = self.expiry.lock() else {
            return;
        };
        let files = self.paths.files_dir();
        for _ in 0..64 {
            if let Some(mut folder) = cursor.folder.take() {
                // Retention may have changed while this bounded scan was suspended.
                if !due(&folder.pulled) {
                    continue;
                }
                match folder.other.next() {
                    Some(Err(why)) => {
                        self.say_state_error(why);
                    }
                    Some(Ok(file)) => {
                        let still_held = if file != folder.receipt
                            && file.extension().is_some_and(|x| x == "json")
                        {
                            match read_record_checked(&file) {
                                Ok(other) => other.is_some_and(|other| {
                                    other.path == folder.pulled.path && !due(&other)
                                }),
                                Err(why) => {
                                    self.say_state_error(why);
                                    continue;
                                }
                            }
                        } else {
                            false
                        };
                        if still_held {
                            forget_receipt(&self.paths, &folder.receipt, &folder.pulled.entry);
                        } else {
                            cursor.folder = Some(folder);
                        }
                    }
                    None => {
                        match receipt_revision(&self.paths) {
                            Ok(revision) if revision != folder.revision => {
                                folder.revision = revision;
                                folder.other = Box::new(receipt_paths(&self.paths));
                                cursor.folder = Some(folder);
                                continue;
                            }
                            Err(why) => {
                                self.say_state_error(why);
                                continue;
                            }
                            Ok(_) => {}
                        }
                        remove_folder_copy(&folder.pulled.path, &folder.pulled.files);
                        forget_receipt(&self.paths, &folder.receipt, &folder.pulled.entry);
                    }
                }
                continue;
            }
            let file = cursor.next(&self.paths);
            if let Some(why) = cursor.failure.take() {
                self.say_state_error(why);
            }
            let Some(file) = file else {
                break;
            };
            if !file.extension().is_some_and(|x| x == "json") {
                continue;
            }
            if cursor.phase == 3 {
                let saved = std::fs::File::open(&file)
                    .ok()
                    .and_then(|f| serde_json::from_reader::<_, SavedState>(f).ok());
                if saved.is_some_and(|s| {
                    retention.get(&s.room).is_some_and(|ttl| {
                        *ttl > 0 && now >= s.created_ms.saturating_add(ttl.saturating_mul(1_000))
                    })
                }) {
                    let _ = std::fs::remove_file(file);
                }
                continue;
            }
            let Some(p) = read_record(&file) else {
                continue;
            };
            if !due(&p) {
                if cursor.phase == 0 {
                    if let Err(why) = move_legacy_receipt(&self.paths, &file, &p.entry) {
                        self.say_state_error(why);
                    }
                }
                continue;
            }
            let ours = p.path.starts_with(&files)
                && !p
                    .path
                    .components()
                    .any(|c| c == std::path::Component::ParentDir);
            if ours && p.folder.is_some() {
                let revision = match receipt_revision(&self.paths) {
                    Ok(revision) => revision,
                    Err(why) => {
                        self.say_state_error(why);
                        continue;
                    }
                };
                cursor.folder = Some(FolderExpiry {
                    receipt: file,
                    pulled: p,
                    other: Box::new(receipt_paths(&self.paths)),
                    revision,
                });
                continue;
            } else if ours {
                match std::fs::remove_file(&p.path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => continue,
                }
            }
            forget_receipt(&self.paths, &file, &p.entry);
        }
    }
}

/// Delete a pulled folder copy at `dir`: each file this pull placed, `(path, sha256)`, that is
/// still as it placed it (one the person changed is theirs, and stays), then every folder that
/// leaves empty, `dir` too.
fn remove_folder_copy(dir: &Path, placed: &[(String, String)]) {
    let mut parents = BTreeSet::new();
    for (path, sha) in placed {
        if !crate::node::folder::safe_path(path) {
            continue;
        }
        let file = dir.join(path);
        let unchanged = std::fs::symlink_metadata(&file).is_ok_and(|m| m.is_file())
            && crate::node::folder::digest(&file).is_ok_and(|(now, _)| now == *sha);
        if unchanged && std::fs::remove_file(&file).is_ok() {
            let mut at = file.parent();
            while let Some(p) = at.filter(|p| p.starts_with(dir) && *p != dir) {
                parents.insert(p.to_path_buf());
                at = p.parent();
            }
        }
    }
    // Deepest first, so a folder is empty by the time it is tried.
    for p in parents.iter().rev() {
        let _ = std::fs::remove_dir(p);
    }
    let _ = std::fs::remove_dir(dir);
}

/// Link a verified `.part` into `dir` under `name` or the first free variant of it, never
/// replacing anything: a hard link fails if the name is taken.
fn place(part: &Path, dir: &Path, name: &str) -> Result<PathBuf, String> {
    for n in 0..1000 {
        let candidate = dir.join(numbered(name, n));
        match std::fs::hard_link(part, &candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {e}", candidate.display())),
        }
    }
    Err(format!(
        "every name from {name} on is taken in {}",
        dir.display()
    ))
}

/// Read the share through the forward at `bound` into `part`, refusing more bytes than were
/// announced, a stall, and any result whose SHA-256 or size is not the announced one.
async fn receive(bound: std::net::SocketAddr, part: &Path, offer: &Offer) -> Result<(), String> {
    use sha2::{Digest as _, Sha256};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(part)
        .map_err(|e| format!("{}: {e}", part.display()))?;
    let mut sock = tokio::time::timeout(READ_TIMEOUT, tokio::net::TcpStream::connect(bound))
        .await
        .map_err(|_| "the forward did not answer".to_owned())?
        .map_err(|e| format!("connecting to the forward: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    let dir = part.parent().unwrap_or(part).to_path_buf();
    let mut since = 0u64;
    let mut take = |chunk: &[u8], total: &mut u64| -> Result<(), String> {
        *total += chunk.len() as u64;
        if *total > offer.size {
            return Err("the sharer sent more than it announced".into());
        }
        still_room(&dir, &mut since, chunk.len() as u64)?;
        hasher.update(chunk);
        file.write_all(chunk)
            .map_err(|e| format!("writing the pull: {e}"))
    };
    if offer.http {
        let req = format!(
            "GET /{} HTTP/1.1\r\nHost: vox\r\nConnection: close\r\n\r\n",
            offer.name
        );
        sock.write_all(req.as_bytes())
            .await
            .map_err(|e| format!("asking for the share: {e}"))?;
        let mut head = Vec::new();
        let start = loop {
            let n = tokio::time::timeout(READ_TIMEOUT, sock.read(&mut buf))
                .await
                .map_err(|_| "the sharer did not answer".to_owned())?
                .map_err(|e| format!("reading the reply: {e}"))?;
            if n == 0 {
                return Err("the sharer closed before answering".into());
            }
            head.extend_from_slice(&buf[..n]);
            if let Some(i) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            if head.len() > 16 * 1024 {
                return Err("the sharer's reply is not HTTP".into());
            }
        };
        if !head.starts_with(b"HTTP/1.1 200") && !head.starts_with(b"HTTP/1.0 200") {
            return Err("the sharer refused the request".into());
        }
        take(&head[start..], &mut total)?;
    }
    loop {
        let n = tokio::time::timeout(READ_TIMEOUT, sock.read(&mut buf))
            .await
            .map_err(|_| "the transfer stalled".to_owned())?
            .map_err(|e| format!("reading the transfer: {e}"))?;
        if n == 0 {
            break;
        }
        take(&buf[..n], &mut total)?;
    }
    file.sync_all()
        .map_err(|e| format!("flushing the pull: {e}"))?;
    let got = hex(&hasher.finalize());
    if got != offer.sha256 || total != offer.size {
        return Err(format!(
            "the transfer does not match what was announced: expected sha256 {} over {} bytes, \
             got {got} over {total}",
            offer.sha256, offer.size
        ));
    }
    Ok(())
}
