//! **The narrow OS calls Vox needs that no safe crate offers** (#218), and so the one Vox crate
//! that allows `unsafe`. Each is one system call with a buffer whose length is passed in and
//! checked on return:
//!
//! - [`recv_drops`]: a UDP socket's own drop count.
//! - [`process_args`]: another process's argv (macOS; Linux reads `/proc` without `unsafe`).
//!
//! **A UDP socket's own drop count.**
//! A receiver whose socket buffer fills drops what arrives next, and the kernel counts it per
//! socket (`sk_drops`, the `d` of `ss -m` and the "drops" column of `/proc/net/udp6`). Vox reads
//! that count on its endpoint's socket and tells the peers sending to it, so a sender does not
//! take the receiver's own overflow for congestion on the path (ADR-024, "Receiver overflow").
//!
//! [`recv_drops`] is one `getsockopt(SOL_SOCKET, SO_MEMINFO)` and the `SK_MEMINFO_DROPS` slot of
//! what it fills. Linux and Android only: elsewhere there is no per-socket counter (macOS counts
//! "dropped due to full socket buffers" for the whole system), and it answers `None`. Read with
//! this rather than `/proc`, whose per-socket table grows with every socket on a busy host; and
//! not in the vendored quinn-udp, which exists only until upstream fixes #414 and is meant to go.
//!
//! The `unsafe` is the call itself: a buffer of `SK_MEMINFO_VARS` `u32`s, its length passed in and
//! checked on return. The descriptor is a plain number to the kernel: a stale one is refused or
//! names another socket, never touches memory.
//!
//! **Another process's argv** (ADR-029 SE-1): whether a harness runs headless (`codex exec`) is
//! said only by its own argv, which a hook reads from its parent. No safe crate reads it on macOS:
//! `sysctl`'s crate asks the node's format first, which `kern.procargs2` has none of, and libproc
//! gives a path and a name, not argv. [`process_args`] is one `sysctl(KERN_PROCARGS2)` into a
//! bounded buffer, parsed with every length checked; anything it cannot read whole is `None`.
#![deny(missing_docs)]

use std::io;

#[cfg(unix)]
use std::os::fd::RawFd;

/// The socket's cumulative count of datagrams the kernel dropped on receive — its buffer was
/// full, or a filter refused them — since the socket was made. It wraps at `u32::MAX`, so take
/// differences with `wrapping_sub`. `None` where the kernel keeps no such count.
///
/// `fd` is a raw descriptor because the socket is owned elsewhere (inside quinn's runtime
/// wrapper): the caller keeps the socket open across the call. A descriptor that is closed or not
/// a socket only makes the kernel refuse; nothing here reads or writes past the buffer.
///
/// # Errors
/// If the kernel refuses the query (not a socket, or a kernel without `SO_MEMINFO`, which came
/// in Linux 3.9).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn recv_drops(fd: RawFd) -> io::Result<Option<u32>> {
    // `SK_MEMINFO_VARS` is 9 in every kernel since `SK_MEMINFO_DROPS` (8) was added; a longer
    // array from a later kernel is cut to what was asked for, which the length check allows.
    const SK_MEMINFO_DROPS: usize = 8;
    const VARS: usize = 9;
    let mut info = [0u32; VARS];
    let mut len = libc::socklen_t::try_from(std::mem::size_of_val(&info))
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `info` is a live, writable buffer of `len` bytes for the whole call, and `len` is
    // its exact size; the kernel writes at most `len` bytes and says how many in `len`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MEMINFO,
            info.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let filled = usize::try_from(len).unwrap_or(0) / std::mem::size_of::<u32>();
    Ok((filled > SK_MEMINFO_DROPS).then(|| info[SK_MEMINFO_DROPS]))
}

/// Where the kernel keeps no per-socket drop count: always `None`.
///
/// # Errors
/// Never.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
pub fn recv_drops(_fd: RawFd) -> io::Result<Option<u32>> {
    Ok(None)
}

/// The most bytes [`process_args`] reads: `kern.argmax` is 1 MiB on macOS; argv is far smaller in
/// practice, and a process whose argv and environment exceed this is read as unknown.
pub const MAX_PROCARGS: usize = 1 << 20;

/// `pid`'s argv as the kernel holds it, `argv[0]` first; `None` when it cannot be read whole
/// (the process is gone, belongs to another user, or what came back does not parse).
#[cfg(target_os = "macos")]
#[must_use]
pub fn process_args(pid: u32) -> Option<Vec<String>> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut len: libc::size_t = 0;
    // SAFETY: a size query: no buffer is passed (null, length 0), the kernel writes only `len`,
    // a live local.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len == 0 || len > MAX_PROCARGS {
        return None;
    }
    let mut buf = vec![0u8; len];
    // SAFETY: `buf` is a live, writable buffer of `len` bytes for the whole call, and `len` is its
    // exact size; the kernel writes at most `len` bytes and says how many in `len`.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len > buf.len() {
        return None;
    }
    buf.truncate(len);
    parse_procargs2(&buf)
}

/// `pid`'s argv from `/proc/<pid>/cmdline`, `argv[0]` first; `None` when it cannot be read.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[must_use]
pub fn process_args(pid: u32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() || raw.len() > MAX_PROCARGS {
        return None;
    }
    let raw = raw.strip_suffix(&[0]).unwrap_or(&raw);
    raw.split(|b| *b == 0)
        .map(|a| String::from_utf8(a.to_vec()).ok())
        .collect()
}

/// Where Vox reads no other process's argv: always `None`.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
#[must_use]
pub fn process_args(_pid: u32) -> Option<Vec<String>> {
    None
}

/// `KERN_PROCARGS2`'s layout: `argc` (a native `i32`), the executable's path and its terminating
/// NULs, then `argc` NUL-terminated strings (the environment follows, and is not read).
#[cfg(target_os = "macos")]
fn parse_procargs2(buf: &[u8]) -> Option<Vec<String>> {
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
    let argc = usize::try_from(argc)
        .ok()
        .filter(|n| (1..=4096).contains(n))?;
    let mut at = 4;
    // The executable's path, then NUL padding up to argv[0].
    at += buf.get(at..)?.iter().position(|b| *b == 0)?;
    at += buf.get(at..)?.iter().position(|b| *b != 0)?;
    let mut args = Vec::with_capacity(argc);
    for _ in 0..argc {
        let rest = buf.get(at..)?;
        let end = rest.iter().position(|b| *b == 0)?;
        args.push(String::from_utf8(rest[..end].to_vec()).ok()?);
        at += end + 1;
    }
    Some(args)
}
