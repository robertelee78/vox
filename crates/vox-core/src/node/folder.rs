//! A shared folder (ADR-028 F-8): its file list, how the sharer builds it, how a receiver checks
//! it, and how a receiver pulls only what it does not already hold.
//!
//! **The list is served, its hash announced.** Every file is listed by its path in the folder, its
//! size and its SHA-256; the announcement carries how many files there are, their total size and
//! the SHA-256 of the list ([`list_sha256`]), so one announcement still names one exact set of
//! bytes, however many files it holds. The sharer's daemon serves the list at [`LIST_TARGET`] and
//! each listed file at its own path ([`url_path`]), from the folder itself, and refuses a file that
//! changed since it was listed. A receiver takes the list only if its SHA-256 is the announced one
//! ([`fetch_list`]).
//!
//! **A pull fetches only what it lacks** ([`pull`]): a file already in place whose SHA-256 is the
//! listed one is kept, so a pull cut short resumes where it stopped, and pulling a folder again
//! after one file changed fetches that file alone. A file the person changed in the pulled copy is
//! theirs: it is never replaced. Nothing is ever deleted to make the copy match the sharer's: a
//! share is a hand-off, not a sync.
//!
//! **A path that could leave the folder, or two paths that one filesystem would treat as one
//! name**, are refused on both sides: `..`, an absolute path, an empty component, a control
//! character or a backslash; `A.txt` beside `a.txt`, or one name in NFC beside the same name in
//! NFD (macOS treats both pairs as one file).

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use unicode_normalization::UnicodeNormalization as _;

/// One file of a shared folder, as its announcement lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// Its path in the folder: relative, `/`-separated.
    pub path: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its SHA-256, lowercase hex.
    pub sha256: String,
}

/// A listed file as the sharer found it, with when it was last modified: a file whose size or
/// time has moved since is not served under the announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// What the announcement says of it.
    pub listed: Listed,
    /// When it was last modified, nanoseconds since the Unix epoch.
    pub modified: u128,
}

/// The longest path a listed file may have, in bytes.
const MAX_PATH: usize = 1024;

/// The most files a shared folder may hold: past any real folder, short of one that would take a
/// receiver's memory with its list alone.
pub const MAX_FILES: usize = 100_000;

/// Where a folder share serves its list. No listed file is served there: a listed path is never
/// empty.
pub const LIST_TARGET: &str = "/";

/// How long one read of a transfer may wait before the pull is abandoned.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// When `meta`'s file was last modified, nanoseconds since the Unix epoch; `0` when it cannot say.
#[must_use]
pub fn modified_ns(meta: &std::fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos())
}

/// Whether `path` is one a listed file may have: relative, `/`-separated, every component a plain
/// name (not empty, `.` or `..`), with no control character, backslash or NUL.
#[must_use]
pub fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH
        && !path.starts_with('/')
        && !path.chars().any(|c| c.is_control() || c == '\\')
        && path
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

/// The name two paths share on a case-insensitive, Unicode-normalising filesystem.
fn folded(path: &str) -> String {
    path.nfc().collect::<String>().to_lowercase()
}

/// Whether `list` is one a receiver may pull: every path safe, every SHA-256 well formed, and no
/// two paths one filesystem would treat as one, or as a file and a folder at once.
///
/// # Errors
/// What is wrong with it, for the person.
pub fn check(list: &[Listed]) -> Result<(), String> {
    if list.is_empty() {
        return Err("the folder's list is empty".into());
    }
    if list.len() > MAX_FILES {
        return Err(format!(
            "the folder lists {} files, and a shared folder holds at most {MAX_FILES}",
            list.len()
        ));
    }
    let mut files = BTreeMap::new();
    let mut dirs = BTreeSet::new();
    for f in list {
        if !safe_path(&f.path) {
            return Err(format!(
                "the folder lists {:?}, a path that could leave it",
                f.path
            ));
        }
        if f.sha256.len() != 64 || !f.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("the folder lists {} with no SHA-256", f.path));
        }
        let key = folded(&f.path);
        if let Some(other) = files.insert(key.clone(), f.path.clone()) {
            return Err(format!(
                "the folder lists {other} and {}, which this filesystem may treat as one file",
                f.path
            ));
        }
        let mut at = key.as_str();
        while let Some((parent, _)) = at.rsplit_once('/') {
            dirs.insert(parent.to_owned());
            at = parent;
        }
    }
    if let Some(both) = files.keys().find(|k| dirs.contains(*k)) {
        return Err(format!(
            "the folder lists {} as a file and as a folder",
            files[both]
        ));
    }
    Ok(())
}

/// The share's SHA-256: that of its list, one line per file in path order.
#[must_use]
pub fn list_sha256(list: &[Listed]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut sorted: Vec<&Listed> = list.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut h = Sha256::new();
    for f in sorted {
        h.update(f.path.as_bytes());
        h.update([0]);
        h.update(f.size.to_string().as_bytes());
        h.update([0]);
        h.update(f.sha256.as_bytes());
        h.update(b"\n");
    }
    hex(&h.finalize())
}

/// The list as the announcement carries it: `[[path, size, sha256], …]`.
#[must_use]
pub fn to_json(list: &[Listed]) -> serde_json::Value {
    list.iter()
        .map(|f| serde_json::json!([f.path, f.size, f.sha256]))
        .collect()
}

/// The list an announcement carries, or `None` for one that is not a list of files.
#[must_use]
pub fn from_json(v: &serde_json::Value) -> Option<Vec<Listed>> {
    v.as_array()?
        .iter()
        .map(|e| {
            let e = e.as_array()?;
            Some(Listed {
                path: e.first()?.as_str()?.to_owned(),
                size: e.get(1)?.as_u64()?,
                sha256: e.get(2)?.as_str()?.to_ascii_lowercase(),
            })
        })
        .collect()
}

/// Where the sharer serves `path`: `/` and each component percent-encoded.
#[must_use]
pub fn url_path(path: &str) -> String {
    use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
    const KEEP: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_');
    path.split('/')
        .map(|c| utf8_percent_encode(c, KEEP).to_string())
        .fold(String::new(), |mut s, c| {
            s.push('/');
            s.push_str(&c);
            s
        })
}

/// The listed path a request's target names, or `None` for one that names none.
#[must_use]
pub fn from_url_path(target: &str) -> Option<String> {
    let path = target.strip_prefix('/')?;
    let path = path.split(['?', '#']).next().unwrap_or(path);
    percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .ok()
        .map(std::borrow::Cow::into_owned)
}

/// List `root` as a share: every file under it, by path, size, SHA-256 and time, in path order.
///
/// # Errors
/// A sentence for the sharer: a symbolic link (a shared folder holds files and folders only), a
/// name that could not travel, two names one filesystem would treat as one, or a file that cannot
/// be read.
pub fn walk(root: &Path) -> Result<Vec<Found>, String> {
    let shown = root.file_name().map_or_else(
        || root.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let mut found = Vec::new();
    let mut todo = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = todo.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
            let name = entry.file_name().into_string().map_err(|n| {
                format!(
                    "{shown}/{prefix}{}: a name that is not UTF-8 cannot be shared",
                    n.to_string_lossy()
                )
            })?;
            let path = format!("{prefix}{name}");
            if !safe_path(&path) {
                return Err(format!("{shown}/{path}: a name like this cannot be shared"));
            }
            let meta = std::fs::symlink_metadata(entry.path())
                .map_err(|e| format!("{shown}/{path}: {e}"))?;
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "{shown}/{path} is a symbolic link; a shared folder holds only files and \
                     folders"
                ));
            }
            if meta.is_dir() {
                todo.push((entry.path(), format!("{path}/")));
            } else if meta.is_file() {
                if found.len() >= MAX_FILES {
                    return Err(format!(
                        "refusing to share {shown}/: it holds more than {MAX_FILES} files, the \
                         most a shared folder may hold; share a subfolder, or tar it yourself \
                         and share the file"
                    ));
                }
                let (sha256, size) = digest(&entry.path())?;
                found.push(Found {
                    listed: Listed { path, size, sha256 },
                    modified: modified_ns(&meta),
                });
            }
        }
    }
    found.sort_by(|a, b| a.listed.path.cmp(&b.listed.path));
    if found.is_empty() {
        return Err(format!("{shown} holds no files to share"));
    }
    let list: Vec<Listed> = found.iter().map(|f| f.listed.clone()).collect();
    check(&list).map_err(|e| e.replace("the folder lists", &format!("{shown} holds")))?;
    Ok(found)
}

/// A file's SHA-256 (lowercase hex) and length.
///
/// # Errors
/// It cannot be read.
pub fn digest(path: &Path) -> Result<(String, u64), String> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex(&h.finalize()), total))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The list of the folder share served at `bound`, taken only if its SHA-256 is `sha256` and it
/// lists `count` files, every path safe (ADR-028 F-8).
///
/// # Errors
/// Why it was not taken.
pub async fn fetch_list(
    bound: SocketAddr,
    sha256: &str,
    count: u64,
) -> Result<Vec<Listed>, String> {
    if count == 0 || count > MAX_FILES as u64 {
        return Err(format!(
            "it is announced with {count} files, and a shared folder holds 1 to {MAX_FILES}"
        ));
    }
    // A generous bound on a list of `count` entries: each a path, a size and a hash.
    let most = count.saturating_mul(MAX_PATH as u64 + 128);
    let body = get_body(bound, LIST_TARGET, most).await?;
    let v: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| "its file list is not a list".to_owned())?;
    let list = from_json(&v).ok_or_else(|| "its file list is not a list".to_owned())?;
    if list_sha256(&list) != sha256 || list.len() as u64 != count {
        return Err("its file list is not the one its announcement names".into());
    }
    check(&list)?;
    Ok(list)
}

/// GET `target` from the share at `bound`, refusing a reply longer than `most` bytes.
async fn get_body(bound: SocketAddr, target: &str, most: u64) -> Result<Vec<u8>, String> {
    let mut sock = tokio::time::timeout(READ_TIMEOUT, tokio::net::TcpStream::connect(bound))
        .await
        .map_err(|_| "the forward did not answer".to_owned())?
        .map_err(|e| format!("connecting to the forward: {e}"))?;
    sock.write_all(
        format!("GET {target} HTTP/1.1\r\nHost: vox\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .map_err(|e| format!("asking for it: {e}"))?;
    let mut all = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = tokio::time::timeout(READ_TIMEOUT, sock.read(&mut buf))
            .await
            .map_err(|_| "the sharer did not answer".to_owned())?
            .map_err(|e| format!("reading the reply: {e}"))?;
        if n == 0 {
            break;
        }
        all.extend_from_slice(&buf[..n]);
        if all.len() as u64 > most.saturating_add(16 * 1024) {
            return Err("the sharer's reply is longer than the list can be".into());
        }
    }
    let Some(start) = all.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) else {
        return Err("the sharer's reply is not HTTP".into());
    };
    if !all.starts_with(b"HTTP/1.1 200") && !all.starts_with(b"HTTP/1.0 200") {
        return Err("the sharer refused it".into());
    }
    Ok(all.split_off(start))
}

/// What a pull of a folder did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pulled {
    /// The paths it fetched.
    pub fetched: Vec<String>,
    /// How many listed files were already in place, as listed.
    pub here: usize,
    /// The paths the person changed in the pulled copy, kept as they are.
    pub kept: Vec<String>,
    /// Every file now in place as listed, `(path, sha256)`: what a later pull of this folder may
    /// replace, and what its message's end deletes.
    pub placed: Vec<(String, String)>,
}

/// Pull `list` from the share served at `bound` into `dir`, fetching only what is not already
/// there as listed. `prior` is what an earlier pull of this folder put there, `(path, sha256)`:
/// a file still as Vox left it may be replaced by a newer listing; one the person changed is kept.
///
/// # Errors
/// Why the pull stopped, with what it had done by then: the files fetched before are in place,
/// verified, and the next pull keeps them.
pub async fn pull(
    bound: SocketAddr,
    dir: &Path,
    list: &[Listed],
    prior: &BTreeMap<String, String>,
) -> Result<Pulled, (String, Pulled)> {
    let mut done = Pulled::default();
    if let Err(e) = check(list) {
        return Err((e, done));
    }
    for f in list {
        let target = dir.join(&f.path);
        let fail = |e: String, done: Pulled| Err((format!("{}: {e}", f.path), done));
        match std::fs::symlink_metadata(&target) {
            Ok(meta) => {
                let now = if meta.is_file() {
                    let t = target.clone();
                    tokio::task::spawn_blocking(move || digest(&t))
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .map(|(sha, _)| sha)
                } else {
                    None
                };
                if now.as_deref() == Some(f.sha256.as_str()) {
                    done.here += 1;
                    done.placed.push((f.path.clone(), f.sha256.clone()));
                    continue;
                }
                // Replaced only while it is still the copy an earlier pull put there.
                if now.is_none() || prior.get(&f.path) != now.as_ref() {
                    done.kept.push(f.path.clone());
                    continue;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return fail(e.to_string(), done),
        }
        let Some(parent) = target.parent() else {
            return fail("no folder to put it in".into(), done);
        };
        if let Err(e) = make_parents(dir, parent) {
            return fail(e, done);
        }
        let name = target
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let mut nonce = [0u8; 8];
        if getrandom::fill(&mut nonce).is_err() {
            return fail("no randomness for a temporary file".into(), done);
        }
        let part = parent.join(format!(".{name}.{}.part", hex(&nonce)));
        let got = fetch(bound, &url_path(&f.path), &part, f.size, &f.sha256).await;
        let placed = got.and_then(|()| {
            std::fs::rename(&part, &target).map_err(|e| format!("putting it in place: {e}"))
        });
        if let Err(e) = placed {
            let _ = std::fs::remove_file(&part);
            return fail(e, done);
        }
        done.fetched.push(f.path.clone());
        done.placed.push((f.path.clone(), f.sha256.clone()));
    }
    Ok(done)
}

/// Make `parent` and every folder between it and `dir`, refusing to pass through anything in the
/// way that is not a folder (a symbolic link above all: it could lead out of `dir`).
fn make_parents(dir: &Path, parent: &Path) -> Result<(), String> {
    let rel = parent.strip_prefix(dir).map_err(|e| e.to_string())?;
    let mut at = dir.to_path_buf();
    for c in rel.components() {
        at.push(c);
        match std::fs::symlink_metadata(&at) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                return Err(format!(
                    "{} is in the way, and is not a folder",
                    at.display()
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&at).map_err(|e| format!("{}: {e}", at.display()))?;
            }
            Err(e) => return Err(format!("{}: {e}", at.display())),
        }
    }
    Ok(())
}

/// GET `target` from the share at `bound` into `part`, refusing more bytes than `size`, a stall,
/// too little room on the disk, and any result whose SHA-256 or size is not the listed one.
async fn fetch(
    bound: SocketAddr,
    target: &str,
    part: &Path,
    size: u64,
    sha256: &str,
) -> Result<(), String> {
    use sha2::{Digest as _, Sha256};
    use std::io::Write as _;
    let dir: PathBuf = part.parent().unwrap_or(part).to_path_buf();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(part)
        .map_err(|e| format!("{}: {e}", part.display()))?;
    let mut sock = tokio::time::timeout(READ_TIMEOUT, tokio::net::TcpStream::connect(bound))
        .await
        .map_err(|_| "the forward did not answer".to_owned())?
        .map_err(|e| format!("connecting to the forward: {e}"))?;
    sock.write_all(
        format!("GET {target} HTTP/1.1\r\nHost: vox\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .map_err(|e| format!("asking for it: {e}"))?;
    let mut buf = vec![0u8; 64 * 1024];
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
        let status = String::from_utf8_lossy(&head[..head.len().min(64)])
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned();
        return Err(format!("the sharer refused it ({status})"));
    }
    let mut h = Sha256::new();
    let mut total = 0u64;
    let mut since = 0u64;
    let mut take = |chunk: &[u8], total: &mut u64| -> Result<(), String> {
        *total += chunk.len() as u64;
        if *total > size {
            return Err("the sharer sent more than it listed".into());
        }
        crate::node::pulls::still_room(&dir, &mut since, chunk.len() as u64)?;
        h.update(chunk);
        file.write_all(chunk)
            .map_err(|e| format!("writing it: {e}"))
    };
    take(&head[start..], &mut total)?;
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
    file.sync_all().map_err(|e| format!("flushing it: {e}"))?;
    let got = hex(&h.finalize());
    if got != sha256 || total != size {
        return Err(format!(
            "it does not match the list: expected sha256 {sha256} over {size} bytes, got {got} \
             over {total}"
        ));
    }
    Ok(())
}
