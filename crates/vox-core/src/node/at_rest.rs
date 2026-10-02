//! **No at-rest key reaches AES-GCM's random-nonce bound** (V210-136).
//!
//! Every sealed store write draws a fresh random 96-bit nonce, and AES-GCM's bound for random
//! nonces is 2^32 seals per key: past it, a repeated nonce, and with it the key's authenticity,
//! is no longer negligible. So each at-rest key seals under a **data key of a generation**
//! ([`Sek::data_key`]); every sealed write is counted, in the same transaction as the write
//! ([`crate::node::store::SealState`]); and once a key has [`rotate_at`] seals under its
//! generation, everything it sealed is re-sealed under the next generation, in one
//! transaction, and the old data key is dropped (zeroized).
//!
//! Generation 0 is the key itself with today's AAD, so a store written before this opens
//! unchanged. A re-seal is one redb transaction: a crash before its commit leaves the old
//! generation whole, and after it the new one, so a message is never lost to a rotation. After a
//! rotation the old ciphertext is still in the store file's freed pages, so the store is to be
//! rewritten fresh ([`REWRITE_PENDING_META`]) the next time nothing else holds it.

use zeroize::Zeroizing;

use crate::atrest::sek::{Sek, NONCE_LEN};
use crate::atrest::store::{open_segment, seal_segment, SealedSegment, SegmentKind};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::store::{meta_slot, KeyClass, SealState, Store};

/// Seals under one data-key generation before the key rotates: a quarter of AES-GCM's 2^32
/// random-nonce bound, where the chance of any repeated nonce is about 2^-37.
pub const ROTATE_AT: u64 = 1 << 30;

/// Test-only: rotate after this many seals instead of [`ROTATE_AT`], so a proof can cross the
/// threshold. **For proofs; nothing in a real deployment sets it.** Unset or unparsable is
/// [`ROTATE_AT`]. Not compiled in without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_ROTATE_AT_ENV: &str = "VOX_TEST_AT_REST_ROTATE_AT";

/// Test-only: inside a room's re-seal, wait this many milliseconds before its commit, saying so
/// on stderr, so a proof can kill the node mid-rotation. **For proofs only.** Not compiled in
/// without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_ROTATE_PAUSE_ENV: &str = "VOX_TEST_AT_REST_ROTATE_PAUSE_MS";

/// Meta flag: a rotation committed, and the store file still holds the old generation's
/// ciphertext in freed pages until it is rewritten fresh.
pub const REWRITE_PENDING_META: &str = "at_rest_rewrite_pending";

/// The number of seals under one generation that makes a key rotate.
#[must_use]
pub fn rotate_at() -> u64 {
    #[cfg(feature = "test-knobs")]
    if let Some(n) = std::env::var(TEST_ROTATE_AT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
    {
        return n;
    }
    ROTATE_AT
}

/// The data key `base` seals under now, at `slot` in `class`.
///
/// # Errors
/// The store cannot be read, or `base` is locked.
pub fn data_key(store: &Store, slot: &Digest32, class: KeyClass, base: &Sek) -> Result<Sek> {
    base.data_key(store.seal_state(slot, class)?.generation)
}

/// Whether the key at `slot` in `class` has reached [`rotate_at`].
///
/// # Errors
/// The store cannot be read.
pub fn due(store: &Store, slot: &Digest32, class: KeyClass) -> Result<bool> {
    Ok(store.seal_state(slot, class)?.seals >= rotate_at())
}

/// Re-seal everything the key `class` at `slot` has sealed, from `old` (its current data key)
/// to the next generation of `base`, in **one** transaction, and return the new data key. A
/// segment `old` cannot open (it never opened, under any key) is carried over unchanged.
///
/// # Errors
/// The store cannot be read or written, or a key is locked. Nothing is written then.
pub fn rotate_segments(
    store: &Store,
    slot: &Digest32,
    class: KeyClass,
    old: &Sek,
    base: &Sek,
) -> Result<Sek> {
    let next = old
        .generation()
        .checked_add(1)
        .ok_or(Error::MalformedAtRest("at-rest generation exhausted"))?;
    let new = base.data_key(next)?;
    let mut batch = store.batch()?;
    let mut seals = 0u64;
    for &kind in class.kinds() {
        for (id, sealed) in store.segments(slot, kind)? {
            let fresh = match open_segment(old, kind, id, &sealed) {
                Ok(plain) => seal_segment(&new, kind, id, &plain)?,
                Err(_) => sealed,
            };
            batch.put_segment(slot, kind, id, &fresh)?;
            seals += 1;
        }
    }
    batch.set_seal_state(
        slot,
        class,
        SealState {
            generation: next,
            seals,
        },
    )?;
    batch.put_meta(REWRITE_PENDING_META, &[1])?;
    #[cfg(feature = "test-knobs")]
    super::profile::test_pause(
        TEST_ROTATE_PAUSE_ENV,
        "re-sealing at rest, not yet committed",
    );
    batch.commit()?;
    Ok(new)
}

/// Seal `plain` as the whole of one segment under `base` at `slot` in `class`, and write it in
/// one transaction — rotating to the next generation first when the key is [`due`]. For a key
/// that seals one blob that is always rewritten whole (the prekey ring), where rotation needs
/// no re-seal of anything older.
///
/// # Errors
/// The store cannot be read or written, or `base` is locked.
pub fn save_segment(
    store: &Store,
    slot: &Digest32,
    kind: SegmentKind,
    id: u64,
    base: &Sek,
    plain: &[u8],
) -> Result<()> {
    let class = KeyClass::of(kind);
    let (key, rotated) = current_or_next(store, slot, class, base)?;
    let sealed = seal_segment(&key, kind, id, plain)?;
    let mut batch = store.batch()?;
    batch.put_segment(slot, kind, id, &sealed)?;
    if rotated {
        batch.set_seal_state(slot, class, after_rotation(key.generation()))?;
        batch.put_meta(REWRITE_PENDING_META, &[1])?;
    }
    batch.commit()
}

/// Open the segment [`save_segment`] wrote, if there is one.
///
/// # Errors
/// The store cannot be read, a key is locked, or the segment does not open.
pub fn load_segment(
    store: &Store,
    slot: &Digest32,
    kind: SegmentKind,
    id: u64,
    base: &Sek,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let Some(sealed) = store.get_segment(slot, kind, id)? else {
        return Ok(None);
    };
    let key = data_key(store, slot, KeyClass::of(kind), base)?;
    open_segment(&key, kind, id, &sealed).map(Some)
}

/// [`save_segment`] for a node-wide blob kept in the store's meta table as `nonce ‖ ciphertext`
/// under `name`, sealed as a [`SegmentKind::Trust`] segment of `id`.
///
/// # Errors
/// As [`save_segment`].
pub fn save_meta_blob(store: &Store, name: &str, id: u64, base: &Sek, plain: &[u8]) -> Result<()> {
    let slot = meta_slot(name);
    let (key, rotated) = current_or_next(store, &slot, KeyClass::Meta, base)?;
    let sealed = seal_segment(&key, SegmentKind::Trust, id, plain)?;
    let mut blob = Vec::with_capacity(NONCE_LEN + sealed.ciphertext.len());
    blob.extend_from_slice(&sealed.nonce);
    blob.extend_from_slice(&sealed.ciphertext);
    let mut batch = store.batch()?;
    batch.put_sealed_meta(name, &blob)?;
    if rotated {
        batch.set_seal_state(&slot, KeyClass::Meta, after_rotation(key.generation()))?;
        batch.put_meta(REWRITE_PENDING_META, &[1])?;
    }
    batch.commit()
}

/// Open the blob [`save_meta_blob`] wrote under `name`, if there is one.
///
/// # Errors
/// The store cannot be read, a key is locked, or the blob is malformed or does not open.
pub fn load_meta_blob(
    store: &Store,
    name: &str,
    id: u64,
    base: &Sek,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let Some(blob) = store.get_meta(name)? else {
        return Ok(None);
    };
    let sealed = meta_blob_segment(&blob)?;
    let key = data_key(store, &meta_slot(name), KeyClass::Meta, base)?;
    open_segment(&key, SegmentKind::Trust, id, &sealed).map(Some)
}

/// A meta blob (`nonce ‖ ciphertext`) as the segment it was sealed as.
///
/// # Errors
/// The blob is shorter than a nonce.
pub fn meta_blob_segment(blob: &[u8]) -> Result<SealedSegment> {
    if blob.len() < NONCE_LEN {
        return Err(Error::MalformedAtRest("sealed meta blob too short"));
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    Ok(SealedSegment {
        nonce: nonce
            .try_into()
            .map_err(|_| Error::MalformedAtRest("sealed meta blob nonce"))?,
        ciphertext: ciphertext.to_vec(),
    })
}

/// The data key to seal with now, and whether that is a rotation to the next generation.
fn current_or_next(
    store: &Store,
    slot: &Digest32,
    class: KeyClass,
    base: &Sek,
) -> Result<(Sek, bool)> {
    let st = store.seal_state(slot, class)?;
    if st.seals >= rotate_at() {
        let next = st
            .generation
            .checked_add(1)
            .ok_or(Error::MalformedAtRest("at-rest generation exhausted"))?;
        Ok((base.data_key(next)?, true))
    } else {
        Ok((base.data_key(st.generation)?, false))
    }
}

/// The state after a one-blob rotation: the new generation, with the one write that made it.
fn after_rotation(generation: u64) -> SealState {
    SealState {
        generation,
        seals: 1,
    }
}
