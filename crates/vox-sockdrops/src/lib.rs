//! **A UDP socket's own drop count** — the one system call Vox needs that its safe dependencies
//! (rustix, socket2) do not offer, and so the one Vox crate that allows `unsafe` (#218, R41a).
//!
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
