//! Best-effort `mlock`-ed, always-zeroized secret memory (ADR-010 §"App-lock and
//! memory hygiene").
//!
//! The store encryption key (SEK) and every derived factor live **only in memory
//! while unlocked**. This module gives them a home that
//!
//! 1. is **best-effort `mlock`-ed** so the OS does not page it to swap, and
//! 2. is **always zeroized** on drop and on explicit lock — the *defined
//!    fallback* when `mlock` is unavailable. We never trade zeroization for
//!    locking: a buffer that could not be locked is still a zeroizing buffer, it
//!    is merely not pinned to RAM.
//!
//! `mlock` is exposed through the `region` crate's **safe** `lock`/`LockGuard`
//! RAII API, so the crate's `#![forbid(unsafe_code)]` root holds — Vox writes no
//! raw `unsafe` for this (the requirement from the milestone brief).
//!
//! ## Why best-effort, stated plainly
//! `mlock` can fail for honest reasons: an unprivileged process can hit the
//! `RLIMIT_MEMLOCK` ceiling, some sandboxes deny it, and WASM has no such syscall.
//! ADR-010 calls for it to be best-effort with a defined fallback; that fallback
//! is "the secret is still in a zeroizing buffer, just not pinned." We record
//! whether the lock succeeded ([`SecretBuf::is_mlocked`]) so callers/tests can
//! observe the posture, but a failed lock is **not** an error — refusing to hold
//! a secret because it could not be pinned would be strictly worse for the user.
//!
//! ## Pins are counted per page
//! `mlock` and `munlock` work on whole pages and do not nest: one `munlock` unpins a page
//! however many `mlock`s covered it. Two small buffers routinely share a heap page, so a
//! short-lived key's drop used to unpin the page a live key still sat on. Every page is
//! therefore pinned once, by the first buffer on it, and unpinned only when the last one
//! leaves (`PINNED`).

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use zeroize::Zeroize;

/// Every page this process has pinned: its address, how many live [`SecretBuf`]s lie on
/// it, and the guard whose drop unpins it.
static PINNED: Mutex<BTreeMap<usize, (usize, region::LockGuard)>> = Mutex::new(BTreeMap::new());

/// The page-aligned addresses `[addr, addr + len)` touches. `len` is non-zero.
fn pages(addr: usize, len: usize) -> impl Iterator<Item = usize> {
    let size = region::page::size();
    let first = addr & !(size - 1);
    let last = (addr + len - 1) & !(size - 1);
    (first..=last).step_by(size)
}

/// Pin every page under `[addr, addr + len)`, counting it. All or nothing: a page that
/// cannot be pinned releases the ones this call counted, and the answer is `false`.
fn pin(addr: usize, len: usize) -> bool {
    let size = region::page::size();
    let mut pinned = PINNED.lock().unwrap_or_else(PoisonError::into_inner);
    let mut counted = Vec::new();
    for page in pages(addr, len) {
        if let Some((n, _)) = pinned.get_mut(&page) {
            *n += 1;
        } else if let Ok(guard) = region::lock(page as *const u8, size) {
            pinned.insert(page, (1, guard));
        } else {
            for page in counted {
                release(&mut pinned, page);
            }
            return false;
        }
        counted.push(page);
    }
    true
}

/// Uncount every page under `[addr, addr + len)`; a page no buffer lies on any more is
/// unpinned.
fn unpin(addr: usize, len: usize) {
    let mut pinned = PINNED.lock().unwrap_or_else(PoisonError::into_inner);
    for page in pages(addr, len) {
        release(&mut pinned, page);
    }
}

fn release(pinned: &mut BTreeMap<usize, (usize, region::LockGuard)>, page: usize) {
    if let Some((n, _)) = pinned.get_mut(&page) {
        *n -= 1;
        if *n == 0 {
            // The guard unpins the page as it drops.
            pinned.remove(&page);
        }
    }
}

/// A heap buffer of secret bytes that is best-effort `mlock`-ed and always
/// zeroized on drop.
///
/// The bytes live in a boxed slice (a stable heap address, so the `mlock` covers
/// the actual storage and is not invalidated by a `Vec` realloc — the buffer is
/// fixed-length for its whole life). On drop the bytes are zeroized first, then
/// its pages are uncounted, and unpinned if no other buffer lies on them; on
/// [`SecretBuf::lock_now`] the same happens eagerly for app-lock.
pub struct SecretBuf {
    /// The secret storage. Boxed so its address is stable for the lifetime of the
    /// `mlock`. `Option` only so [`Drop`]/`lock_now` can zeroize-then-take.
    bytes: Box<[u8]>,
    /// Whether this buffer's pages are counted in [`PINNED`]. `false` means the
    /// fallback path (zeroize-only, not pinned).
    pinned: bool,
}

impl SecretBuf {
    /// Allocate a **zeroed** boxed buffer of `len` bytes, `mlock` it (best-effort),
    /// and only **then** copy the secret in via `fill`.
    ///
    /// This is the lock-before-fill order ADR-010 wants: the buffer is pinned to RAM
    /// *before* it ever holds plaintext, so the secret is never written to an
    /// unlocked page. (A zeroed page carries no secret, so locking it first is
    /// harmless and avoids an unlocked-heap plaintext window.) When `mlock` is
    /// unavailable, the defined fallback applies — the secret still lands in a
    /// zeroizing buffer, just not pinned.
    fn locked_with<F: FnOnce(&mut [u8])>(len: usize, fill: F) -> Self {
        // A zeroed allocation — no secret in it yet.
        let mut bytes: Box<[u8]> = vec![0u8; len].into_boxed_slice();
        // A zero-length region has no page to pin.
        let pinned = !bytes.is_empty() && pin(bytes.as_ptr() as usize, bytes.len());
        // Now that the page is (best-effort) pinned, write the secret into it.
        fill(&mut bytes);
        Self { bytes, pinned }
    }

    /// Wrap `data` in a best-effort-locked, zeroizing buffer, then zeroize the
    /// caller's copy.
    ///
    /// The locked storage is allocated and pinned **before** the secret is copied
    /// in (lock-before-fill), so the only persistent plaintext copy lives in locked
    /// memory. The caller's `Vec` is zeroized so the secret does not linger in a
    /// second place.
    #[must_use]
    pub fn from_vec(mut data: Vec<u8>) -> Self {
        let buf = Self::locked_with(data.len(), |dst| dst.copy_from_slice(&data));
        data.zeroize();
        buf
    }

    /// Wrap a fixed-size secret array.
    ///
    /// Takes a non-`Copy` [`zeroize::Zeroizing`] array so the caller has no leftover
    /// `Copy` stack remnant of the secret: the value is moved in and zeroized on
    /// drop, and the locked storage is pinned before the bytes are copied in
    /// (lock-before-fill).
    #[must_use]
    pub fn from_array<const N: usize>(data: zeroize::Zeroizing<[u8; N]>) -> Self {
        Self::locked_with(N, |dst| dst.copy_from_slice(data.as_ref()))
        // `data` (Zeroizing) zeroizes itself on drop here.
    }

    /// Borrow the secret bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the secret in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Whether the OS actually `mlock`-ed this buffer (best-effort observability;
    /// a `false` here is the defined zeroize-only fallback, not an error).
    #[must_use]
    pub fn is_mlocked(&self) -> bool {
        self.pinned
    }

    /// Give this buffer's pins back, once.
    fn release_pins(&mut self) {
        if std::mem::take(&mut self.pinned) {
            unpin(self.bytes.as_ptr() as usize, self.bytes.len());
        }
    }

    /// Eagerly zeroize and unlock the buffer **now** (app-lock / idle / sleep,
    /// ADR-010). After this the secret is gone; the buffer reads as all-zero.
    ///
    /// This is what the app-lock path calls so the SEK and derived material do not
    /// wait for `Drop`. Idempotent.
    pub fn lock_now(&mut self) {
        self.bytes.zeroize();
        self.release_pins();
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        // Zeroize the contents *before* the pages are uncounted, so the wipe happens
        // while the page is still pinned (when it was pinned at all).
        self.bytes.zeroize();
        self.release_pins();
    }
}

impl core::fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never reveal the secret; show only length and lock posture.
        f.debug_struct("SecretBuf")
            .field("len", &self.bytes.len())
            .field("mlocked", &self.is_mlocked())
            .finish()
    }
}
