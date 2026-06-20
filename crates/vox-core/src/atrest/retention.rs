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
    let profile = Argon2Profile::from_id(old_wrap.profile_id)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atrest::idfactor::SignatureIdentityFactor;
    use crate::atrest::sek::Sek;
    use crate::error::Error;
    use crate::hash::{sha256, Digest32};
    use crate::identity::composite::{RootSigner, SoftwareRootSigner};
    use crate::log::entry::{Entry, EntrySkeleton};
    use crate::suite::algo;
    use std::collections::HashMap;

    const P: Argon2Profile = Argon2Profile::REDUCED;

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    #[test]
    fn rotation_keeps_sek_and_opens_under_new_passphrase() {
        let s = signer(7, 9);
        let f = SignatureIdentityFactor::new(&s);
        let cid = [1u8; CHANNEL_ID_LEN];
        let sek = Sek::generate().unwrap();
        let old = sek.seal(&f, &cid, b"old-pp", P).unwrap();

        let re = rewrap_for_new_passphrase(&old, &f, &cid, b"old-pp", b"new-pp").unwrap();

        // The NEW wrap opens under the NEW passphrase and yields the SAME SEK.
        let recovered = re.new_wrap.unwrap_sek(&f, &cid, b"new-pp").unwrap();
        assert_eq!(recovered.key_bytes().unwrap(), sek.key_bytes().unwrap());
        // The new wrap does NOT open under the old passphrase.
        assert!(matches!(
            re.new_wrap.unwrap_sek(&f, &cid, b"old-pp"),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn offline_device_keeps_old_wrap_until_it_knows_new_passphrase() {
        // An offline device that does not know the new passphrase simply cannot
        // call rewrap (it lacks `new_passphrase`); meanwhile its existing OLD wrap
        // still opens under the OLD passphrase it holds. We model that here.
        let s = signer(7, 9);
        let f = SignatureIdentityFactor::new(&s);
        let cid = [1u8; CHANNEL_ID_LEN];
        let sek = Sek::generate().unwrap();
        let old = sek.seal(&f, &cid, b"old-pp", P).unwrap();
        // Without the new passphrase, the device retains and uses the old wrap.
        assert_eq!(
            old.unwrap_sek(&f, &cid, b"old-pp")
                .unwrap()
                .key_bytes()
                .unwrap(),
            sek.key_bytes().unwrap()
        );
    }

    #[test]
    fn rewrap_requires_correct_old_passphrase() {
        let s = signer(7, 9);
        let f = SignatureIdentityFactor::new(&s);
        let cid = [1u8; CHANNEL_ID_LEN];
        let sek = Sek::generate().unwrap();
        let old = sek.seal(&f, &cid, b"old-pp", P).unwrap();
        // A wrong old passphrase cannot drive a re-wrap.
        assert!(matches!(
            rewrap_for_new_passphrase(&old, &f, &cid, b"WRONG", b"new-pp"),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn kdf_profile_upgrade_keeps_sek() {
        // Upgrade from REDUCED to REDUCED (same params, exercises the path without
        // running the 256 MiB production profile). The SEK survives the re-wrap.
        let s = signer(7, 9);
        let f = SignatureIdentityFactor::new(&s);
        let cid = [1u8; CHANNEL_ID_LEN];
        let sek = Sek::generate().unwrap();
        let old = sek.seal(&f, &cid, b"pp", P).unwrap();
        let re = upgrade_kdf_profile(&old, &f, &cid, b"pp", P).unwrap();
        assert_eq!(re.new_wrap.profile_id, P.id);
        assert_eq!(
            re.new_wrap
                .unwrap_sek(&f, &cid, b"pp")
                .unwrap()
                .key_bytes()
                .unwrap(),
            sek.key_bytes().unwrap()
        );
    }

    // A trivial in-memory plaintext-cache store for the prune tests.
    #[derive(Default)]
    struct MemCache {
        caches: HashMap<Digest32, Vec<u8>>,
    }
    impl PlaintextCacheStore for MemCache {
        fn erase_plaintext_cache(&mut self, entry_hash: &Digest32) -> bool {
            self.caches.remove(entry_hash).is_some()
        }
    }

    fn content_entry(payload: &[u8]) -> Entry {
        let r = signer(2, 3);
        let skeleton = EntrySkeleton {
            author_id: r.public_key().fingerprint(),
            seq: 1,
            prev_hash: [0u8; 32],
            lipmaa_backlink: [0u8; 32],
            channel_id: [9u8; 32],
            epoch: 0,
            algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
            payload_hash: sha256(payload),
            payload_len: payload.len() as u64,
            end_of_feed: false,
        };
        Entry::build_signed(&r, skeleton, payload.to_vec()).unwrap()
    }

    #[test]
    fn ttl_prune_drops_payload_but_skeleton_still_verifies() {
        let r = signer(2, 3);
        let mut entry = content_entry(b"secret message body");
        assert!(entry.payload.is_some());

        // Prune payload at TTL (reuses M5's authenticated prune).
        assert!(prune_entry_payload(&mut entry));
        assert!(entry.payload.is_none());

        // The signed skeleton STILL verifies after pruning (ADR-008/ADR-010).
        assert!(entry.verify(&r.public_key()).is_ok());
        // Pruning again is a no-op.
        assert!(!prune_entry_payload(&mut entry));
    }

    #[test]
    fn disappearing_deletes_payload_and_plaintext_cache() {
        let r = signer(2, 3);
        let mut entry = content_entry(b"disappearing body");
        let mut cache = MemCache::default();
        // Seed a plaintext cache for this entry.
        cache
            .caches
            .insert(entry.entry_hash(), b"decrypted plaintext".to_vec());

        let (payload_dropped, cache_erased) =
            prune_entry_at_ttl_disappearing(&mut entry, &mut cache);
        assert!(payload_dropped);
        assert!(cache_erased);
        assert!(entry.payload.is_none());
        assert!(cache.caches.is_empty());
        // Skeleton remains verifiable.
        assert!(entry.verify(&r.public_key()).is_ok());

        // Idempotent second call.
        let (p2, c2) = prune_entry_at_ttl_disappearing(&mut entry, &mut cache);
        assert!(!p2);
        assert!(!c2);
    }
}
