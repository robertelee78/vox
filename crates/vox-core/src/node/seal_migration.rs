//! The one-time move of a version-1 vault's node-wide blobs onto `self_seed` seals (V210-40,
//! #214; see [`crate::atrest::seal`] for why).
//!
//! [`Profile::unlock`](crate::node::profile::Profile::unlock) runs this when it opens a
//! version-1 vault, then rewrites the vault as version 2. That order makes it safe to repeat: a
//! crash between the two leaves re-sealed blobs under a v1 vault, and the next unlock finds each
//! of them already opening under its new key and leaves it alone.
//!
//! **Only here is a legacy key ever used.** Once the vault is v2, no loader tries one, so a
//! legacy-sealed blob planted afterwards, by someone who can compute `id_proof` from the public
//! key, is never opened. The vault's version is bound into its AEAD for the same reason: a v2
//! vault relabelled v1 does not open. What remains is an adversary holding a copy of this
//! vault taken **before** it was migrated. That copy is a genuine v1 vault, and restoring it
//! would bring the fallback back.
//!
//! A blob that opens under neither key is left exactly as it is: its loader refuses it, as it
//! always has.

use zeroize::Zeroizing;

use crate::atrest::sek::{Sek, NONCE_LEN};
use crate::atrest::store::{open_segment, seal_segment, SealedSegment, SegmentKind};
use crate::error::Result;
use crate::identity::composite::RootSigner;
use crate::node::store::{Batch, Store};
use crate::node::{pending_consent, prekeys, trust};

/// Re-seal every node-wide blob in `store` that still opens only under its legacy key, in one
/// transaction. Returns how many blobs were re-sealed.
///
/// Anchor pages are not among them: only a headless `vox node` keeps them, and it has no vault
/// (see [`crate::node::anchor::anchor_sek`]).
///
/// # Errors
/// A key cannot be derived, or the store cannot be read or written.
pub fn migrate_to_vault_seals(store: &Store, signer: &dyn RootSigner) -> Result<usize> {
    let mut batch = store.batch()?;
    let mut moved = 0;

    // The trust keyring and the pending consents: a meta blob each, `nonce ‖ ciphertext`.
    moved += reseal_meta(
        store,
        &mut batch,
        trust::TRUST_META_KEY,
        trust::TRUST_SEGMENT_ID,
        &trust::trust_sek(signer)?,
        &trust::legacy_trust_sek(signer)?,
    )?;
    moved += reseal_meta(
        store,
        &mut batch,
        pending_consent::META_KEY,
        pending_consent::SEGMENT_ID,
        &pending_consent::pending_consent_sek(signer)?,
        // Version 1 sealed the pending consents under the keyring's key.
        &trust::legacy_trust_sek(signer)?,
    )?;

    // The prekey ring: one segment in its pseudo-channel.
    let ring_channel = prekeys::ring_channel();
    if let Some(sealed) = store.get_segment(
        &ring_channel,
        SegmentKind::PrekeyRing,
        prekeys::SEG_PREKEY_RING,
    )? {
        if let Some(fresh) = reseal(
            SegmentKind::PrekeyRing,
            prekeys::SEG_PREKEY_RING,
            &sealed,
            &prekeys::ring_sek(signer)?,
            &prekeys::legacy_ring_sek(signer)?,
        )? {
            batch.put_segment(
                &ring_channel,
                SegmentKind::PrekeyRing,
                prekeys::SEG_PREKEY_RING,
                &fresh,
            )?;
            moved += 1;
        }
    }

    batch.commit()?;
    Ok(moved)
}

/// `sealed` re-sealed under `new`, if it opens only under `old`; `None` if it already opens
/// under `new`, or under neither.
fn reseal(
    kind: SegmentKind,
    id: u64,
    sealed: &SealedSegment,
    new: &Sek,
    old: &Sek,
) -> Result<Option<SealedSegment>> {
    if open_segment(new, kind, id, sealed).is_ok() {
        return Ok(None);
    }
    let Ok(plain) = open_segment(old, kind, id, sealed) else {
        return Ok(None);
    };
    let plain = Zeroizing::new(plain);
    seal_segment(new, kind, id, &plain).map(Some)
}

/// [`reseal`] for a blob kept in the store's meta table as `nonce ‖ ciphertext`.
fn reseal_meta(
    store: &Store,
    batch: &mut Batch<'_>,
    name: &str,
    id: u64,
    new: &Sek,
    old: &Sek,
) -> Result<usize> {
    let Some(blob) = store.get_meta(name)? else {
        return Ok(0);
    };
    if blob.len() < NONCE_LEN {
        return Ok(0);
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    let sealed = SealedSegment {
        nonce: nonce
            .try_into()
            .map_err(|_| crate::error::Error::MalformedAtRest("meta blob nonce"))?,
        ciphertext: ciphertext.to_vec(),
    };
    let Some(fresh) = reseal(SegmentKind::Trust, id, &sealed, new, old)? else {
        return Ok(0);
    };
    let mut out = Vec::with_capacity(NONCE_LEN + fresh.ciphertext.len());
    out.extend_from_slice(&fresh.nonce);
    out.extend_from_slice(&fresh.ciphertext);
    batch.put_meta(name, &out)?;
    Ok(1)
}
