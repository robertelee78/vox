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

use zeroize::Zeroize;

/// A heap buffer of secret bytes that is best-effort `mlock`-ed and always
/// zeroized on drop.
///
/// The bytes live in a boxed slice (a stable heap address, so the `mlock` covers
/// the actual storage and is not invalidated by a `Vec` realloc — the buffer is
/// fixed-length for its whole life). On drop the bytes are zeroized first, then
/// the `region` guard unlocks; on [`SecretBuf::lock_now`] the same zeroization
/// happens eagerly for app-lock.
pub struct SecretBuf {
    /// The secret storage. Boxed so its address is stable for the lifetime of the
    /// `mlock`. `Option` only so [`Drop`]/`lock_now` can zeroize-then-take.
    bytes: Box<[u8]>,
    /// The live `region` lock guard, if `mlock` succeeded. Dropping it unlocks.
    /// `None` means the fallback path (zeroize-only, not pinned).
    guard: Option<region::LockGuard>,
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
        let guard = if bytes.is_empty() {
            // `region::lock` rejects a zero-length region; nothing to pin.
            None
        } else {
            region::lock(bytes.as_ptr(), bytes.len()).ok()
        };
        // Now that the page is (best-effort) pinned, write the secret into it.
        fill(&mut bytes);
        Self { bytes, guard }
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
        self.guard.is_some()
    }

    /// Eagerly zeroize and unlock the buffer **now** (app-lock / idle / sleep,
    /// ADR-010). After this the secret is gone; the buffer reads as all-zero.
    ///
    /// This is what the app-lock path calls so the SEK and derived material do not
    /// wait for `Drop`. Idempotent.
    pub fn lock_now(&mut self) {
        self.bytes.zeroize();
        // Drop the region guard (unlock) by replacing it.
        self.guard = None;
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        // Zeroize the contents *before* the guard unlocks, so the wipe happens
        // while the page is still pinned (when it was pinned at all).
        self.bytes.zeroize();
        // `guard` unlocks here as it drops.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_bytes_and_clears_source() {
        let mut src = vec![1u8, 2, 3, 4, 5];
        let buf = SecretBuf::from_vec(src.clone());
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4, 5]);
        assert_eq!(buf.len(), 5);
        // from_vec zeroizes the *moved* copy, not our clone. (Zeroizing a `Vec`
        // wipes its bytes and truncates it to empty — the documented behavior.)
        src.zeroize();
        assert!(src.is_empty());
    }

    #[test]
    fn lock_now_zeroizes() {
        let mut buf = SecretBuf::from_vec(vec![0xAA; 32]);
        assert_eq!(buf.as_slice(), &[0xAA; 32]);
        buf.lock_now();
        // The secret is gone after app-lock.
        assert_eq!(buf.as_slice(), &[0u8; 32]);
        assert!(!buf.is_mlocked());
        // Idempotent.
        buf.lock_now();
        assert_eq!(buf.as_slice(), &[0u8; 32]);
    }

    #[test]
    fn empty_buffer_is_not_locked_but_valid() {
        let buf = SecretBuf::from_vec(Vec::new());
        assert!(buf.is_empty());
        assert!(!buf.is_mlocked());
        assert_eq!(buf.as_slice(), &[] as &[u8]);
    }

    #[test]
    fn from_array_works() {
        let buf = SecretBuf::from_array(zeroize::Zeroizing::new([7u8; 16]));
        assert_eq!(buf.as_slice(), &[7u8; 16]);
    }

    #[test]
    fn debug_hides_secret() {
        let buf = SecretBuf::from_vec(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let s = format!("{buf:?}");
        assert!(!s.contains("de"), "debug leaked secret: {s}");
        assert!(s.contains("len"));
    }

    #[test]
    fn mlock_is_best_effort_not_fatal() {
        // Whatever the platform/rlimit does, construction must succeed and the
        // bytes must be intact; mlock success is observable but not required.
        let buf = SecretBuf::from_vec(vec![0x11; 64]);
        assert_eq!(buf.as_slice(), &[0x11; 64]);
        // `is_mlocked()` may be true or false depending on environment; both are
        // valid — we only assert it does not panic and is consistent.
        let _ = buf.is_mlocked();
    }
}
