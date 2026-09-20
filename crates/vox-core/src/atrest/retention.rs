//! Retention, passphrase-rotation re-wrap, and KDF-profile upgrade (ADR-010
//! §"Passphrase rotation interaction", §"Retention / TTL", §"KDF-profile version").
//!
//! ## Passphrase rotation: re-wrap, never re-encrypt the store
//! The SEK is **independent of the passphrase value** (ADR-010), so rotating the
//! channel passphrase (a new epoch, ADR-007/M6) never touches the SEK or the bulk
//! store. An **online** device simply re-wraps its *existing* SEK under the new
//! `factor_pass` and **deletes the old wrap**; only the small wrap changes.
//! [`rewrap_for_new_passphrase`] performs exactly that. An **offline** device
//! cannot re-wrap until it returns: until then it keeps its old wrap and unlocks
//! only under the old passphrase it still holds — there is **no remote/"magic"
//! rewrap** of an offline device. That honest trade-off is encoded by the API
//! shape: re-wrap is a *local* operation that requires the device to know both the
//! old and the new passphrase, which an offline device does not yet have.
//!
//! A **revoked** device's stale wrap reads only old *local* history: new-epoch
//! *content* keys are obtained only on rejoin (ADR-006/M6), so a stale SEK wrap
//! grants nothing for new traffic. M8 provides the wrap mechanics; the content-key
//! gating is M6.
//!
//! ## TTL prune: client-honored, not enforceable
//! Admin-set TTL (ADR-007/M6 policy; default **never expire**). At TTL a client
//! prunes the **payload bytes** — reusing M5's authenticated pruning
//! ([`crate::log::entry::Entry::prune_payload`]) so the signed hash-skeleton stays
//! verifiable (ADR-008) — and, for "disappearing", also deletes the **plaintext
//! cache** for that entry. [`prune_entry_at_ttl_disappearing`] does both. This is
//! **client-honored, not enforceable**: a malicious client can retain data. We
//! state that plainly rather than implying a guarantee we cannot make.
//!
//! ## KDF-profile upgrade: transparent re-wrap
//! The wrap records its Argon2id profile id, so a build can raise the parameters
//! over time and transparently re-wrap under the new profile
//! ([`upgrade_kdf_profile`]) — again only the small wrap changes; the SEK and bulk
//! store are untouched.

use crate::atrest::idfactor::{IdentityFactor, CHANNEL_ID_LEN};
use crate::atrest::sek::{Argon2Profile, SekWrap};
use crate::error::Result;
use crate::log::entry::Entry;

/// The result of a re-wrap: the new wrap to persist, and an explicit reminder that
/// the **old wrap must be deleted** (ADR-010 §"deletes the old wrap"). The caller
/// owns persistence, so deletion is its responsibility; this type makes the
/// contract unmissable rather than returning a bare [`SekWrap`].
#[derive(Debug, Clone)]
#[must_use = "persist `new_wrap` and delete the old wrap (ADR-010)"]
pub struct Rewrap {
    /// The new wrap to write to disk.
    pub new_wrap: SekWrap,
}

/// **Online passphrase rotation** (ADR-010): re-wrap the SEK currently protected by
/// `old_wrap` under `new_passphrase`, keeping the SEK identical, and return the new
/// wrap. The identity factor and `channel_id` are unchanged across rotation (only
/// the passphrase factor changes).
///
/// The SEK is recovered with the old passphrase and re-sealed with the new one; the
/// profile is preserved (use [`upgrade_kdf_profile`] to also raise parameters). The
/// caller must persist [`Rewrap::new_wrap`] and **delete `old_wrap`**.
///
/// Requires *both* passphrases — an offline device that does not yet know the new
/// passphrase cannot call this, which is the ADR's "no remote rewrap" property.
pub fn rewrap_for_new_passphrase(
    old_wrap: &SekWrap,
    id_factor: &dyn IdentityFactor,
    channel_id: &[u8; CHANNEL_ID_LEN],
    old_passphrase: &[u8],
    new_passphrase: &[u8],
) -> Result<Rewrap> {
    // Resolve via the wrap's own accessor so an unknown stored id collapses to an
    // unlock failure (never a distinguishable oracle on a persisted field).
    let profile = old_wrap.profile()?;
    // Recover the SEK under the old factors, then re-seal under the new passphrase.
    let sek = old_wrap.unwrap_sek(id_factor, channel_id, old_passphrase)?;
    let new_wrap = sek.seal(id_factor, channel_id, new_passphrase, profile)?;
    Ok(Rewrap { new_wrap })
}

/// **KDF-profile upgrade** (ADR-010 §"transparent re-wrap"): re-wrap the SEK under a
/// stronger Argon2id profile while keeping the same passphrase and SEK. Returns the
/// new wrap to persist; the caller deletes the old one.
pub fn upgrade_kdf_profile(
    old_wrap: &SekWrap,
    id_factor: &dyn IdentityFactor,
    channel_id: &[u8; CHANNEL_ID_LEN],
    passphrase: &[u8],
    new_profile: Argon2Profile,
) -> Result<Rewrap> {
    let sek = old_wrap.unwrap_sek(id_factor, channel_id, passphrase)?;
    let new_wrap = sek.seal(id_factor, channel_id, passphrase, new_profile)?;
    Ok(Rewrap { new_wrap })
}

/// Prune an entry at TTL (ADR-010 §"Retention / TTL"): drop the payload bytes via
/// M5's authenticated pruning so the signed skeleton stays verifiable. Returns
/// whether a payload body was actually dropped.
///
/// For a "disappearing" delete the caller additionally erases the plaintext cache
/// segment for this entry; see [`prune_entry_at_ttl_disappearing`], which combines
/// both so the two deletions cannot be accidentally separated.
pub fn prune_entry_payload(entry: &mut Entry) -> bool {
    entry.prune_payload()
}

/// A handle to a per-entry plaintext-cache slot the caller can erase. The store
/// keeps plaintext caches *inside* SEK-sealed segments (ADR-010); deleting the
/// cache for a disappearing message means removing that segment. This trait is the
/// seam the storage layer implements (e.g. "remove segment id N"); M8 defines it
/// and drives it from [`prune_entry_at_ttl_disappearing`] so the prune-both
/// semantics are enforced in one place.
pub trait PlaintextCacheStore {
    /// Erase the plaintext cache associated with `entry_hash`. Returns whether a
    /// cache entry existed and was removed. Idempotent.
    fn erase_plaintext_cache(&mut self, entry_hash: &crate::hash::Digest32) -> bool;
}

/// **Disappearing** delete at TTL (ADR-010): prune the payload bytes **and** delete
/// the plaintext cache for the entry. Both deletions happen together so neither can
/// be forgotten. Returns `(payload_dropped, cache_erased)`.
pub fn prune_entry_at_ttl_disappearing<C: PlaintextCacheStore>(
    entry: &mut Entry,
    cache: &mut C,
) -> (bool, bool) {
    let payload_dropped = entry.prune_payload();
    let cache_erased = cache.erase_plaintext_cache(&entry.entry_hash());
    (payload_dropped, cache_erased)
}
