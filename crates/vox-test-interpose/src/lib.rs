//! **Test apparatus only.** A `DYLD_INSERT_LIBRARIES` interposer that records, in order, the
//! file-system calls a process makes that decide whether a write survives a power loss: which
//! files it creates (and with what flags and mode), which it flushes, what it renames into place,
//! and which modes it changes afterwards (V210-55 #241, #242).
//!
//! A power loss cannot be staged from userspace, and a `SIGKILL` leaves the page cache intact,
//! so a crash test cannot tell a flushed write from an unflushed one. What can be observed is the
//! order of the calls the unmodified binary makes. The proofs that load this library assert that
//! order: a file is flushed before the rename that publishes it, and its directory after.
//!
//! Loaded into the shipped `vox` binary, unchanged, by `tests/support/syscalls.rs`. Never a
//! workspace member, never linked into vox. macOS only: it uses dyld's `__DATA,__interpose`.
//!
//! ## What is recorded
//! One line per call, appended to the file named by `VOX_INTERPOSE_LOG`, fields separated by
//! tabs: `seq pid kind fields… ret errno`. `seq` comes from one process-wide counter, so lines
//! from one process are in call order; `pid` separates the processes that inherit the library.
//!
//! - `open path flags(hex) mode(octal) ret errno`: `open` and `openat`; the mode is the one
//!   passed, meaningful only with `O_CREAT`.
//! - `sync path how ret errno`: `fsync`, and `fcntl` with `F_FULLFSYNC` or `F_BARRIERFSYNC`. The
//!   path is the descriptor's, taken with `F_GETPATH` at the moment of the call.
//! - `rename from to how ret errno`: `rename`, `renameat`, `renamex_np`, `renameatx_np`.
//! - `chmod path mode(octal) how ret errno`: `chmod`, `fchmod`.
//! - `write path how bytes ret errno`: `write`, `pwrite`, `writev`, `pwritev`; `bytes` is what the
//!   call asked to write, `ret` what it wrote. The path is the descriptor's, as for `sync`, so a
//!   proof can require the **last** write to a file to come before its flush (a flush of a file
//!   still empty, with the bytes written after, publishes unflushed data; found in verification
//!   of #241).
//! - `copy dest how src ret errno`: `clonefile`, `clonefileat`, `fclonefileat`, `copyfile`,
//!   `fcopyfile`. A clone or copy fills a file without `write` (`std::fs::copy` on macOS), so it
//!   is the destination's content event just as a write is. `copy_file_range` is Linux's and
//!   this library is macOS-only (dyld interposing), so it is not recorded.
//!
//! ## One injected failure
//! With `VOX_INTERPOSE_FAIL_DIR_SYNC` set to a directory's path, as the kernel names it, every
//! `F_FULLFSYNC`, `F_BARRIERFSYNC` or `fsync` of that directory fails with `EIO` without being made
//! (and is recorded with that outcome). It stages what no userspace test can otherwise: a rename
//! that lands whose directory will not flush (V210-77). Unset, nothing is injected.
//!
//! Paths are as the call named them (for `open` and `rename`) or as the kernel reports them (for a
//! descriptor), so a reader compares them after canonicalising the directory.
//!
//! ## One injected receive-buffer cap
//! With `VOX_INTERPOSE_RCVBUF_CAP` set to a number of bytes, every
//! `setsockopt(SOL_SOCKET, SO_RCVBUF, v)` asking for more is made with that number instead, so the
//! kernel really grants the smaller buffer and `getsockopt(SO_RCVBUF)` honestly reads it back. It
//! stages, without root, a host whose `kern.ipc.maxsockbuf` is small (#174): the binary is
//! unchanged and no sysctl is touched. Each call is recorded as `rcvbuf asked set ret errno`.
//! Unset, nothing is injected or recorded.
//!
//! ## Kill points
//! With `VOX_INTERPOSE_KILL_ARM` naming a file, the process kills itself with `SIGKILL` right
//! after the `N`th flush of a `store.redb` that returns while that file holds `N`: at a boundary
//! between two of the store's transactions, the one place a crash can leave it (V210-76). Flushes
//! are counted only while the file exists, so a proof arms it at the moment the operation under
//! test starts, and sweeps `N`. The kill is recorded first: `kill path n`.
//!
//! ## Memory scan on cue
//! With `VOX_INTERPOSE_SCAN` naming a directory, a thread of this library's looks through every
//! readable page of the process for byte strings a proof names, when the proof asks: see the
//! `scan` module (V210-94). It starts at the process's first recorded call.
//!
//! ## Variadic calls
//! `open`, `openat` and `fcntl` take their last argument variadically. On Apple arm64 a variadic
//! argument is passed on the stack, not in the register a non-variadic function reads it from,
//! and Rust cannot define a C-variadic function on stable. So each of these is replaced by a
//! two-instruction trampoline that loads the stack slot into the next argument register and
//! branches to an ordinary Rust hook. On x86_64 variadic arguments travel in registers like any
//! other, and the hook is the replacement itself.

#![cfg(target_os = "macos")]
#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, c_uint, c_ulong, CStr};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

mod scan;

const O_WRONLY: c_int = 0x0001;
const O_APPEND: c_int = 0x0008;
const O_CREAT: c_int = 0x0200;
const O_CLOEXEC: c_int = 0x0100_0000;
const F_GETPATH: c_int = 50;
const F_FULLFSYNC: c_int = 51;
const F_BARRIERFSYNC: c_int = 85;
const AT_FDCWD: c_int = -2;
const MAXPATHLEN: usize = 1024;
const EIO: c_int = 5;
const SOL_SOCKET: c_int = 0xffff;
const SO_RCVBUF: c_int = 0x1002;

extern "C" {
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn openat(fd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn fsync(fd: c_int) -> c_int;
    fn setsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        value: *const std::ffi::c_void,
        len: c_uint,
    ) -> c_int;
    fn read(fd: c_int, buf: *mut u8, n: usize) -> isize;
    fn close(fd: c_int) -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn rename(from: *const c_char, to: *const c_char) -> c_int;
    fn renameat(fromfd: c_int, from: *const c_char, tofd: c_int, to: *const c_char) -> c_int;
    fn renamex_np(from: *const c_char, to: *const c_char, flags: c_uint) -> c_int;
    fn renameatx_np(
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
        flags: c_uint,
    ) -> c_int;
    fn chmod(path: *const c_char, mode: u16) -> c_int;
    fn fchmod(fd: c_int, mode: u16) -> c_int;
    fn write(fd: c_int, buf: *const u8, n: usize) -> isize;
    fn pwrite(fd: c_int, buf: *const u8, n: usize, offset: i64) -> isize;
    fn writev(fd: c_int, iov: *const IoVec, count: c_int) -> isize;
    fn pwritev(fd: c_int, iov: *const IoVec, count: c_int, offset: i64) -> isize;
    fn clonefile(src: *const c_char, dst: *const c_char, flags: u32) -> c_int;
    fn clonefileat(
        src_dirfd: c_int,
        src: *const c_char,
        dst_dirfd: c_int,
        dst: *const c_char,
        flags: u32,
    ) -> c_int;
    fn fclonefileat(srcfd: c_int, dst_dirfd: c_int, dst: *const c_char, flags: u32) -> c_int;
    fn copyfile(from: *const c_char, to: *const c_char, state: *mut u8, flags: u32) -> c_int;
    fn fcopyfile(from: c_int, to: c_int, state: *mut u8, flags: u32) -> c_int;
    fn getpid() -> c_int;
    fn getenv(name: *const c_char) -> *const c_char;
    fn __error() -> *mut c_int;
}

/// `struct iovec`.
#[repr(C)]
pub struct IoVec {
    base: *const u8,
    len: usize,
}

// ---- the log ------------------------------------------------------------------------------

static SEQ: AtomicU64 = AtomicU64::new(0);
/// Flushes of the store counted while a kill point was armed.
static ARMED_SYNCS: AtomicU64 = AtomicU64::new(0);
const O_RDONLY: c_int = 0;
const SIGKILL: c_int = 9;
/// The log's descriptor: -1 not yet opened, -2 no log wanted (or it would not open).
static LOG_FD: AtomicI32 = AtomicI32::new(-1);

fn log_fd() -> c_int {
    let fd = LOG_FD.load(Ordering::Acquire);
    if fd != -1 {
        return fd;
    }
    // SAFETY: getenv/open are called with valid NUL-terminated strings; this library's own
    // calls are not interposed (dyld skips the interposing image).
    let opened = unsafe {
        let path = getenv(c"VOX_INTERPOSE_LOG".as_ptr());
        if path.is_null() {
            -2
        } else {
            let fd = open(
                path,
                O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                0o600 as c_uint,
            );
            if fd < 0 {
                -2
            } else {
                fd
            }
        }
    };
    match LOG_FD.compare_exchange(-1, opened, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => opened,
        Err(winner) => winner,
    }
}

/// `close`, which forgets the log's descriptor when the process closes it. A `vox daemon` started by a
/// client closes every descriptor it inherited or opened before its own start (ADR-026 S-2), the
/// log's among them; the number is then reused by a file of the daemon's, and a line written to
/// it would land in that file, never in the log. Forgotten here, the log is opened again at the
/// next line.
#[no_mangle]
pub unsafe extern "C" fn vti_close(fd: c_int) -> c_int {
    if fd >= 0 {
        let _ = LOG_FD.compare_exchange(fd, -1, Ordering::AcqRel, Ordering::Acquire);
    }
    close(fd)
}

/// Append one line, keeping the caller's `errno` as it was.
fn record(fields: &[&str]) {
    // SAFETY: __error returns this thread's errno location.
    let saved = unsafe { *__error() };
    // Started from the first recorded call: the library has no load-time constructor.
    scan::start_once();
    let fd = log_fd();
    if fd >= 0 {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        // SAFETY: getpid has no preconditions.
        let pid = unsafe { getpid() };
        let mut line = format!("{seq}\t{pid}");
        for f in fields {
            line.push('\t');
            line.push_str(f);
        }
        line.push('\n');
        // One write per line on an O_APPEND descriptor, so lines from several threads or
        // processes do not interleave within a line.
        // SAFETY: the buffer is valid for its length.
        unsafe { write(fd, line.as_ptr(), line.len()) };
    }
    // SAFETY: as above.
    unsafe { *__error() = saved };
}

/// `(ret, errno)` of a call just made, taken before anything else can change `errno`.
fn outcome(ret: c_int) -> (String, String) {
    // SAFETY: __error returns this thread's errno location.
    let errno = if ret < 0 { unsafe { *__error() } } else { 0 };
    (ret.to_string(), errno.to_string())
}

/// `(ret, errno)` of a call returning a byte count.
fn outcome_len(ret: isize) -> (String, String) {
    // SAFETY: __error returns this thread's errno location.
    let errno = if ret < 0 { unsafe { *__error() } } else { 0 };
    (ret.to_string(), errno.to_string())
}

/// Bytes an iovec array asks to write.
fn iov_len(iov: *const IoVec, count: c_int) -> usize {
    if iov.is_null() || count <= 0 {
        return 0;
    }
    // SAFETY: the caller passed `count` iovecs to the call being recorded.
    unsafe { std::slice::from_raw_parts(iov, count as usize) }
        .iter()
        .map(|v| v.len)
        .sum()
}

fn text(p: *const c_char) -> String {
    if p.is_null() {
        return String::from("(null)");
    }
    // SAFETY: the caller passed a NUL-terminated path to the call being recorded.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// The path of an open descriptor, as the kernel names it.
fn fd_path(fd: c_int) -> String {
    let mut buf = [0u8; MAXPATHLEN];
    // SAFETY: F_GETPATH writes at most MAXPATHLEN bytes, NUL-terminated, into buf.
    let ok = unsafe { fcntl(fd, F_GETPATH, buf.as_mut_ptr()) } == 0;
    if !ok {
        return format!("(fd {fd})");
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// `path` resolved against directory descriptor `dirfd`, as `*at` calls do.
fn at_path(dirfd: c_int, path: *const c_char) -> String {
    let p = text(path);
    if p.starts_with('/') || dirfd == AT_FDCWD {
        return p;
    }
    format!("{}/{p}", fd_path(dirfd))
}

/// The kill point armed now: the number in the file `VOX_INTERPOSE_KILL_ARM` names, or 0.
fn armed() -> u64 {
    // SAFETY: getenv/open/read/close are called with valid arguments; this library's own calls
    // are not interposed.
    unsafe {
        let path = getenv(c"VOX_INTERPOSE_KILL_ARM".as_ptr());
        if path.is_null() {
            return 0;
        }
        let fd = open(path, O_RDONLY | O_CLOEXEC);
        if fd < 0 {
            return 0;
        }
        let mut buf = [0u8; 32];
        let n = read(fd, buf.as_mut_ptr(), buf.len());
        close(fd);
        let n = usize::try_from(n).unwrap_or(0);
        std::str::from_utf8(&buf[..n])
            .ok()
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0)
    }
}

/// After a flush of `path` returned: the kill point, if this is it. See the module docs.
fn after_sync(path: &str, ret: c_int) {
    if ret != 0 || !path.ends_with("/store.redb") {
        return;
    }
    let n = armed();
    if n == 0 {
        return;
    }
    let k = ARMED_SYNCS.fetch_add(1, Ordering::AcqRel) + 1;
    if k == n {
        record(&["kill", path, &k.to_string()]);
        // SAFETY: kill and getpid have no preconditions.
        unsafe { kill(getpid(), SIGKILL) };
    }
}

/// Whether a flush of `path` is to fail with `EIO` (`VOX_INTERPOSE_FAIL_DIR_SYNC`).
fn fail_flush_of(path: &str) -> bool {
    // SAFETY: getenv is called with a NUL-terminated name; the value it returns is read once.
    let target = unsafe { getenv(c"VOX_INTERPOSE_FAIL_DIR_SYNC".as_ptr()) };
    !target.is_null() && text(target) == path
}

/// The receive-buffer cap to inject (`VOX_INTERPOSE_RCVBUF_CAP`), if any.
fn rcvbuf_cap() -> Option<c_int> {
    // SAFETY: getenv is called with a NUL-terminated name; the value it returns is read once.
    let cap = unsafe { getenv(c"VOX_INTERPOSE_RCVBUF_CAP".as_ptr()) };
    if cap.is_null() {
        return None;
    }
    text(cap).trim().parse().ok()
}

/// Fail as the call would have with `EIO`.
fn injected_eio() -> c_int {
    // SAFETY: __error returns this thread's errno slot.
    unsafe { *__error() = EIO };
    -1
}

// ---- hooks --------------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn vti_open_hook(path: *const c_char, flags: c_int, mode: c_ulong) -> c_int {
    let fd = open(path, flags, mode as c_uint);
    let (ret, errno) = outcome(fd);
    record(&[
        "open",
        &text(path),
        &format!("{flags:#x}"),
        &format!("{:o}", mode & 0o7777),
        &ret,
        &errno,
    ]);
    fd
}

#[no_mangle]
pub unsafe extern "C" fn vti_openat_hook(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_ulong,
) -> c_int {
    let fd = openat(dirfd, path, flags, mode as c_uint);
    let (ret, errno) = outcome(fd);
    record(&[
        "open",
        &at_path(dirfd, path),
        &format!("{flags:#x}"),
        &format!("{:o}", mode & 0o7777),
        &ret,
        &errno,
    ]);
    fd
}

#[no_mangle]
pub unsafe extern "C" fn vti_fcntl_hook(fd: c_int, cmd: c_int, arg: c_ulong) -> c_int {
    // The path is taken before the call: after it, nothing about the descriptor has changed.
    let flushing = cmd == F_FULLFSYNC || cmd == F_BARRIERFSYNC;
    let path = if flushing { fd_path(fd) } else { String::new() };
    let r = if flushing && fail_flush_of(&path) {
        injected_eio()
    } else {
        fcntl(fd, cmd, arg)
    };
    if flushing {
        let (ret, errno) = outcome(r);
        let how = if cmd == F_FULLFSYNC {
            "F_FULLFSYNC"
        } else {
            "F_BARRIERFSYNC"
        };
        record(&["sync", &path, how, &ret, &errno]);
        after_sync(&path, r);
    }
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_setsockopt(
    fd: c_int,
    level: c_int,
    name: c_int,
    value: *const std::ffi::c_void,
    len: c_uint,
) -> c_int {
    let int_len = std::mem::size_of::<c_int>() as c_uint;
    if level != SOL_SOCKET || name != SO_RCVBUF || len != int_len || value.is_null() {
        return setsockopt(fd, level, name, value, len);
    }
    let Some(cap) = rcvbuf_cap() else {
        return setsockopt(fd, level, name, value, len);
    };
    let asked = *value.cast::<c_int>();
    let set = asked.min(cap);
    let r = setsockopt(fd, level, name, (&set as *const c_int).cast(), len);
    let (ret, errno) = outcome(r);
    record(&["rcvbuf", &asked.to_string(), &set.to_string(), &ret, &errno]);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_fsync(fd: c_int) -> c_int {
    let path = fd_path(fd);
    let r = if fail_flush_of(&path) {
        injected_eio()
    } else {
        fsync(fd)
    };
    let (ret, errno) = outcome(r);
    record(&["sync", &path, "fsync", &ret, &errno]);
    after_sync(&path, r);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_rename(from: *const c_char, to: *const c_char) -> c_int {
    let r = rename(from, to);
    let (ret, errno) = outcome(r);
    record(&["rename", &text(from), &text(to), "rename", &ret, &errno]);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_renameat(
    fromfd: c_int,
    from: *const c_char,
    tofd: c_int,
    to: *const c_char,
) -> c_int {
    let (f, t) = (at_path(fromfd, from), at_path(tofd, to));
    let r = renameat(fromfd, from, tofd, to);
    let (ret, errno) = outcome(r);
    record(&["rename", &f, &t, "renameat", &ret, &errno]);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_renamex_np(
    from: *const c_char,
    to: *const c_char,
    flags: c_uint,
) -> c_int {
    let r = renamex_np(from, to, flags);
    let (ret, errno) = outcome(r);
    record(&["rename", &text(from), &text(to), "renamex_np", &ret, &errno]);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_renameatx_np(
    fromfd: c_int,
    from: *const c_char,
    tofd: c_int,
    to: *const c_char,
    flags: c_uint,
) -> c_int {
    let (f, t) = (at_path(fromfd, from), at_path(tofd, to));
    let r = renameatx_np(fromfd, from, tofd, to, flags);
    let (ret, errno) = outcome(r);
    record(&["rename", &f, &t, "renameatx_np", &ret, &errno]);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_chmod(path: *const c_char, mode: u16) -> c_int {
    let r = chmod(path, mode);
    let (ret, errno) = outcome(r);
    record(&[
        "chmod",
        &text(path),
        &format!("{:o}", mode & 0o7777),
        "chmod",
        &ret,
        &errno,
    ]);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_fchmod(fd: c_int, mode: u16) -> c_int {
    let path = fd_path(fd);
    let r = fchmod(fd, mode);
    let (ret, errno) = outcome(r);
    record(&[
        "chmod",
        &path,
        &format!("{:o}", mode & 0o7777),
        "fchmod",
        &ret,
        &errno,
    ]);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_write(fd: c_int, buf: *const u8, n: usize) -> isize {
    let path = fd_path(fd);
    let r = write(fd, buf, n);
    let (ret, errno) = outcome_len(r);
    record(&["write", &path, "write", &n.to_string(), &ret, &errno]);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_pwrite(fd: c_int, buf: *const u8, n: usize, offset: i64) -> isize {
    let path = fd_path(fd);
    let r = pwrite(fd, buf, n, offset);
    let (ret, errno) = outcome_len(r);
    record(&["write", &path, "pwrite", &n.to_string(), &ret, &errno]);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_writev(fd: c_int, iov: *const IoVec, count: c_int) -> isize {
    let (path, n) = (fd_path(fd), iov_len(iov, count));
    let r = writev(fd, iov, count);
    let (ret, errno) = outcome_len(r);
    record(&["write", &path, "writev", &n.to_string(), &ret, &errno]);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_pwritev(
    fd: c_int,
    iov: *const IoVec,
    count: c_int,
    offset: i64,
) -> isize {
    let (path, n) = (fd_path(fd), iov_len(iov, count));
    let r = pwritev(fd, iov, count, offset);
    let (ret, errno) = outcome_len(r);
    record(&["write", &path, "pwritev", &n.to_string(), &ret, &errno]);
    r
}

// A clone or copy puts a file's contents in place without `write` (`std::fs::copy` on macOS
// clones with `fclonefileat`, or falls back to `fcopyfile`), so each is recorded as the
// destination's content event, keyed by the destination's path like a write.

#[no_mangle]
pub unsafe extern "C" fn vti_clonefile(
    src: *const c_char,
    dst: *const c_char,
    flags: u32,
) -> c_int {
    let r = clonefile(src, dst, flags);
    let (ret, errno) = outcome(r);
    record(&["copy", &text(dst), "clonefile", &text(src), &ret, &errno]);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_clonefileat(
    src_dirfd: c_int,
    src: *const c_char,
    dst_dirfd: c_int,
    dst: *const c_char,
    flags: u32,
) -> c_int {
    let (s, d) = (at_path(src_dirfd, src), at_path(dst_dirfd, dst));
    let r = clonefileat(src_dirfd, src, dst_dirfd, dst, flags);
    let (ret, errno) = outcome(r);
    record(&["copy", &d, "clonefileat", &s, &ret, &errno]);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_fclonefileat(
    srcfd: c_int,
    dst_dirfd: c_int,
    dst: *const c_char,
    flags: u32,
) -> c_int {
    let (s, d) = (fd_path(srcfd), at_path(dst_dirfd, dst));
    let r = fclonefileat(srcfd, dst_dirfd, dst, flags);
    let (ret, errno) = outcome(r);
    record(&["copy", &d, "fclonefileat", &s, &ret, &errno]);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_copyfile(
    from: *const c_char,
    to: *const c_char,
    state: *mut u8,
    flags: u32,
) -> c_int {
    let r = copyfile(from, to, state, flags);
    let (ret, errno) = outcome(r);
    record(&["copy", &text(to), "copyfile", &text(from), &ret, &errno]);
    r
}

#[no_mangle]
pub unsafe extern "C" fn vti_fcopyfile(
    from: c_int,
    to: c_int,
    state: *mut u8,
    flags: u32,
) -> c_int {
    let (s, d) = (fd_path(from), fd_path(to));
    let r = fcopyfile(from, to, state, flags);
    let (ret, errno) = outcome(r);
    record(&["copy", &d, "fcopyfile", &s, &ret, &errno]);
    r
}

// ---- trampolines for the variadic calls ----------------------------------------------------

// Apple arm64: the variadic argument is the first 8-byte slot at the caller's `sp`. Load it into
// the next argument register and branch to the hook, which returns straight to the caller.
#[cfg(target_arch = "aarch64")]
std::arch::global_asm!(
    ".globl _vti_open",
    ".p2align 2",
    "_vti_open:",
    "    ldr x2, [sp]",
    "    b _vti_open_hook",
    ".globl _vti_openat",
    ".p2align 2",
    "_vti_openat:",
    "    ldr x3, [sp]",
    "    b _vti_openat_hook",
    ".globl _vti_fcntl",
    ".p2align 2",
    "_vti_fcntl:",
    "    ldr x2, [sp]",
    "    b _vti_fcntl_hook",
);

#[cfg(target_arch = "aarch64")]
extern "C" {
    fn vti_open();
    fn vti_openat();
    fn vti_fcntl();
}

// x86_64: variadic arguments are passed in registers like any other, so the hooks are the
// replacements.
#[cfg(target_arch = "x86_64")]
use {vti_fcntl_hook as vti_fcntl, vti_open_hook as vti_open, vti_openat_hook as vti_openat};

// ---- the interpose table -------------------------------------------------------------------

#[repr(C)]
pub struct Interpose {
    replacement: *const (),
    original: *const (),
}

// SAFETY: the table is immutable data read by dyld.
unsafe impl Sync for Interpose {}

macro_rules! interpose {
    ($($name:ident: $replacement:expr => $original:expr;)*) => {
        $(
            #[used]
            #[link_section = "__DATA,__interpose"]
            static $name: Interpose = Interpose {
                replacement: $replacement as *const (),
                original: $original as *const (),
            };
        )*
    };
}

interpose! {
    I_OPEN: vti_open => open;
    I_OPENAT: vti_openat => openat;
    I_FCNTL: vti_fcntl => fcntl;
    I_FSYNC: vti_fsync => fsync;
    I_SETSOCKOPT: vti_setsockopt => setsockopt;
    I_RENAME: vti_rename => rename;
    I_RENAMEAT: vti_renameat => renameat;
    I_RENAMEX_NP: vti_renamex_np => renamex_np;
    I_RENAMEATX_NP: vti_renameatx_np => renameatx_np;
    I_CHMOD: vti_chmod => chmod;
    I_FCHMOD: vti_fchmod => fchmod;
    I_WRITE: vti_write => write;
    I_PWRITE: vti_pwrite => pwrite;
    I_WRITEV: vti_writev => writev;
    I_PWRITEV: vti_pwritev => pwritev;
    I_CLONEFILE: vti_clonefile => clonefile;
    I_CLONEFILEAT: vti_clonefileat => clonefileat;
    I_FCLONEFILEAT: vti_fclonefileat => fclonefileat;
    I_COPYFILE: vti_copyfile => copyfile;
    I_FCOPYFILE: vti_fcopyfile => fcopyfile;
    I_CLOSE: vti_close => close;
}
