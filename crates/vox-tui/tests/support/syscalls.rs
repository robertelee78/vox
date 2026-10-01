//! Run the shipped `vox` binary, unmodified, with `crates/vox-test-interpose` loaded
//! (`DYLD_INSERT_LIBRARIES`), and read back the file-system calls it made, in order: what it
//! created and with what mode, what it flushed, what it renamed into place, what it `chmod`ed.
//!
//! A power loss cannot be staged from userspace and a `SIGKILL` keeps the page cache, so a crash
//! test cannot tell a flushed write from an unflushed one. The order of these calls can be
//! observed, and [`published_durably`] judges it (V210-55 #241, #242). macOS only.
//!
//! Included with `#[path]` by each proof that needs it.

#![allow(dead_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// `O_CREAT` and `O_EXCL` on macOS.
pub const O_CREAT: u32 = 0x0200;
pub const O_EXCL: u32 = 0x0800;

/// One recorded call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// `open`/`openat`: the path as named, flags, the mode passed (octal digits' value).
    Open {
        path: PathBuf,
        flags: u32,
        mode: u32,
    },
    /// `fsync`, or `fcntl(F_FULLFSYNC | F_BARRIERFSYNC)`: the descriptor's path, and how.
    Sync { path: PathBuf, how: String },
    /// `rename` and its variants.
    Rename { from: PathBuf, to: PathBuf },
    /// `chmod`/`fchmod`.
    Chmod { path: PathBuf, mode: u32 },
    /// `write`, `pwrite`, `writev`, `pwritev`: the descriptor's path and the bytes asked for.
    Write { path: PathBuf, bytes: u64 },
    /// A clone or copy onto `path` (`clonefile`, `clonefileat`, `fclonefileat`, `copyfile`,
    /// `fcopyfile`): `std::fs::copy` on macOS fills a file this way, without `write`.
    Copy { path: PathBuf, from: PathBuf },
}

impl Call {
    /// Whether this call put content into `file` (a write, or a clone or copy onto it).
    pub fn fills(&self, file: &Path) -> bool {
        match self {
            Call::Write { path, .. } | Call::Copy { path, .. } => norm(path) == *file,
            _ => false,
        }
    }
}

/// A call, with where it came from and what it returned.
#[derive(Debug, Clone)]
pub struct Event {
    pub seq: u64,
    pub pid: u32,
    pub call: Call,
    pub ret: i64,
    pub errno: i32,
}

/// The interposer, built once per test binary into this target's scratch directory.
pub fn interposer() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(|| {
        let manifest =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../vox-test-interpose/Cargo.toml");
        let target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("vox-test-interpose");
        let ok = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["build", "--release", "--offline", "--manifest-path"])
            .arg(&manifest)
            .env("CARGO_TARGET_DIR", &target)
            .status()
            .is_ok_and(|s| s.success());
        assert!(
            ok,
            "CANNOT MEASURE: the interposer did not build ({})",
            manifest.display()
        );
        let dylib = target.join("release/libvox_test_interpose.dylib");
        assert!(dylib.is_file(), "CANNOT MEASURE: no {}", dylib.display());
        dylib
    })
}

/// Run `exe` with `args` under the interposer, as [`crate::world::vox_once`] runs a verb, with
/// `stdin` written to it if given. Returns success, stdout, stderr and every recorded call.
pub fn recorded(
    exe: &Path,
    data: &Path,
    args: &[&str],
    stdin: Option<&str>,
    passphrase: &str,
) -> (bool, String, String, Vec<Event>) {
    let log = data.join(format!(
        "interpose-{}-{}.tsv",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let mut child = Command::new(exe)
        .args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", passphrase)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .env("DYLD_INSERT_LIBRARIES", interposer())
        .env("VOX_INTERPOSE_LOG", &log)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| {
            panic!(
                "APPARATUS: could not run {} under the interposer: {e}",
                exe.display()
            )
        });
    if let Some(s) = stdin {
        // A `vox` that exits without reading its stdin closes the pipe: its exit status and what
        // it said are the verdict, so a refused write is reported, not fatal.
        if let Err(e) = child
            .stdin
            .take()
            .expect("APPARATUS: a piped stdin")
            .write_all(s.as_bytes())
        {
            eprintln!("[harness] stdin not taken: {e}");
        }
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not wait for {}: {e}", exe.display()));
    // A log that is missing, or holds no `open` from a run that succeeded, is a recorder that
    // recorded nothing — never "vox did nothing", which a durability proof would read as a pass.
    let text = std::fs::read_to_string(&log).unwrap_or_else(|e| {
        panic!(
            "CANNOT MEASURE: the interposer wrote no log at {} ({e}); vox exited {}. Its stderr:\n{}",
            log.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let events = parse(&text);
    let _ = std::fs::remove_file(&log);
    assert!(
        !out.status.success() || events.iter().any(|e| matches!(e.call, Call::Open { .. })),
        "CANNOT MEASURE: the interposer recorded no `open` by `vox {}`, which succeeded: the \
         recorder saw nothing, so nothing here can say what vox did ({} event(s) in all)",
        args.join(" "),
        events.len()
    );
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        events,
    )
}

/// Parse the interposer's log. A line that does not parse is a broken apparatus, not data.
pub fn parse(log: &str) -> Vec<Event> {
    let mut events: Vec<Event> = log
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            let bad = || -> ! { unreadable(l) };
            let num = |s: &str| s.parse::<i64>().unwrap_or_else(|_| bad());
            let oct = |s: &str| u32::from_str_radix(s, 8).unwrap_or_else(|_| bad());
            let (call, rest) = match f.get(2).copied() {
                Some("open") if f.len() == 8 => (
                    Call::Open {
                        path: f[3].into(),
                        flags: u32::from_str_radix(f[4].trim_start_matches("0x"), 16)
                            .unwrap_or_else(|_| bad()),
                        mode: oct(f[5]),
                    },
                    &f[6..],
                ),
                Some("sync") if f.len() == 7 => (
                    Call::Sync {
                        path: f[3].into(),
                        how: f[4].to_owned(),
                    },
                    &f[5..],
                ),
                Some("rename") if f.len() == 8 => (
                    Call::Rename {
                        from: f[3].into(),
                        to: f[4].into(),
                    },
                    &f[6..],
                ),
                Some("write") if f.len() == 8 => (
                    Call::Write {
                        path: f[3].into(),
                        bytes: f[5].parse().unwrap_or_else(|_| bad()),
                    },
                    &f[6..],
                ),
                Some("copy") if f.len() == 8 => (
                    Call::Copy {
                        path: f[3].into(),
                        from: f[5].into(),
                    },
                    &f[6..],
                ),
                Some("chmod") if f.len() == 8 => (
                    Call::Chmod {
                        path: f[3].into(),
                        mode: oct(f[4]),
                    },
                    &f[6..],
                ),
                _ => bad(),
            };
            Event {
                seq: f[0].parse().unwrap_or_else(|_| bad()),
                pid: f[1].parse().unwrap_or_else(|_| bad()),
                call,
                ret: num(rest[0]),
                errno: num(rest[1]) as i32,
            }
        })
        .collect();
    events.sort_by_key(|e| (e.pid, e.seq));
    events
}

/// The recorder's positive control, asserted wherever a proof reads a record: a record with no
/// `open` by `vox` is a recorder that recorded nothing, never a `vox` that did nothing. (It replaces
/// the recorder's separate self-test, gate plan v0.2.10 DELETE #3.)
pub fn assert_the_recorder_saw_vox(events: &[Event], during: &str) {
    assert!(
        events.iter().any(|e| matches!(e.call, Call::Open { .. })),
        "CANNOT MEASURE: the syscall recorder (vox-test-interpose under DYLD_INSERT_LIBRARIES) \
         recorded no `open` by vox during {during} ({} call(s) in all): it is not recording, so \
         nothing vox did can be judged from it",
        events.len()
    );
}

fn unreadable(line: &str) -> ! {
    panic!("CANNOT MEASURE: unreadable interposer line: {line:?}")
}

/// `path` with its directory canonicalised, so a path as a call named it (`/var/…`) and as the
/// kernel reports it (`/private/var/…`) compare equal. The file itself may no longer exist.
pub fn norm(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(dir), Some(name)) => std::fs::canonicalize(dir)
            .map(|d| d.join(name))
            .unwrap_or_else(|_| path.to_owned()),
        _ => path.to_owned(),
    }
}

/// How `target` was last put in place, read from `events`.
#[derive(Debug)]
pub struct Publication {
    /// The rename that put it there.
    pub rename: Event,
    /// The open that created the renamed file, if one was recorded.
    pub created: Option<Event>,
    /// `chmod`s of the renamed file between its creation and the rename.
    pub chmods: Vec<Event>,
    /// Successful content events for the renamed file (writes, and clones or copies onto it)
    /// between its creation and the rename.
    pub content: Vec<Event>,
    /// Successful flushes of the renamed file **after its last content event** and before the
    /// rename: a flush before the bytes are in flushes nothing (found in verification of #241).
    pub synced_before: Vec<Event>,
    /// Flushes of the directory after the rename (any result).
    pub dir_synced_after: Vec<Event>,
}

/// The last successful rename onto `target`, and what surrounded it in the same process.
pub fn publication(events: &[Event], target: &Path) -> Option<Publication> {
    let target = norm(target);
    let (i, rename) = events.iter().enumerate().rev().find(|(_, e)| {
        e.ret == 0 && matches!(&e.call, Call::Rename { to, .. } if norm(to) == target)
    })?;
    let Call::Rename { from, .. } = &rename.call else {
        unreachable!()
    };
    let from = norm(from);
    let dir = target.parent().map(Path::to_path_buf).unwrap_or_default();
    let same = |e: &&Event| e.pid == rename.pid;
    let before: Vec<&Event> = events[..i].iter().filter(same).collect();
    let created_at = before.iter().rposition(|e| {
        matches!(&e.call, Call::Open { path, flags, .. }
            if norm(path) == from && flags & O_CREAT != 0 && e.ret >= 0)
    });
    let since = &before[created_at.unwrap_or(0)..];
    Some(Publication {
        rename: rename.clone(),
        created: created_at.map(|k| before[k].clone()),
        chmods: since
            .iter()
            .filter(|e| matches!(&e.call, Call::Chmod { path, .. } if norm(path) == from))
            .map(|e| (*e).clone())
            .collect(),
        content: since
            .iter()
            .filter(|e| e.ret >= 0 && e.call.fills(&from))
            .map(|e| (*e).clone())
            .collect(),
        synced_before: {
            let last_content = since.iter().rposition(|e| e.call.fills(&from));
            since[last_content.map_or(0, |k| k + 1)..]
                .iter()
                .filter(|e| {
                    e.ret == 0 && matches!(&e.call, Call::Sync { path, .. } if norm(path) == from)
                })
                .map(|e| (*e).clone())
                .collect()
        },
        dir_synced_after: events[i + 1..]
            .iter()
            .filter(same)
            .filter(|e| {
                matches!(&e.call, Call::Sync { path, .. }
                    if std::fs::canonicalize(path).unwrap_or_else(|_| path.clone()) == dir)
            })
            .cloned()
            .collect(),
    })
}

/// Whether `target` was published the way a file a person cannot get back must be: created
/// `O_CREAT | O_EXCL` with mode `0600` from its first byte and never `chmod`ed after, flushed
/// before the rename, and its directory flushed after (a flush the filesystem refuses for a
/// directory, `EINVAL` or `ENOTSUP`, is recorded and accepted). "Flushed" means after the file's
/// **last** content event (a write, or a clone or copy onto it): a flush of a file still empty,
/// its bytes put in after, publishes unflushed data. `Err` says what was missing.
pub fn published_durably(events: &[Event], target: &Path) -> Result<(), String> {
    let p = publication(events, target)
        .ok_or_else(|| format!("no rename onto {} was recorded", target.display()))?;
    let mut missing = Vec::new();
    match &p.created {
        Some(Event {
            call: Call::Open { flags, mode, .. },
            ..
        }) => {
            if flags & O_EXCL == 0 {
                missing.push(format!("created without O_EXCL (flags {flags:#x})"));
            }
            if *mode != 0o600 {
                missing.push(format!("created with mode {mode:o}, not 600"));
            }
        }
        _ => missing.push("its creation was not recorded".to_owned()),
    }
    if !p.chmods.is_empty() {
        missing.push(format!("chmod after creation: {:?}", p.chmods));
    }
    if p.content.is_empty() {
        missing.push("no write, clone or copy into it was recorded".to_owned());
    }
    if p.synced_before.is_empty() {
        missing.push(
            "not flushed after its last write, clone or copy, and before the rename".to_owned(),
        );
    }
    let dir_ok = p
        .dir_synced_after
        .iter()
        .any(|e| e.ret == 0 || e.errno == 22 || e.errno == 45);
    if !dir_ok {
        missing.push(format!(
            "its directory not flushed after the rename ({:?})",
            p.dir_synced_after
        ));
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("{}: {}", target.display(), missing.join("; ")))
    }
}
