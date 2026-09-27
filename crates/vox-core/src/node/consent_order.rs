//! **The order of consent decisions and sender-key generations** (V210-45).
//!
//! What a newly consented member may read of a room's history is decided by one question: was
//! a generation of this identity's sender key minted before or after this identity decided to
//! trust that member? A generation minted after the decision holds only posts sealed after it
//! and may be released whole; the generation live at the decision may be released only from the
//! position it had then; nothing older may be released at all (forward-only consent, ADR-006,
//! ADR-007).
//!
//! That question used to be answered with the wall clock: the keyring recorded when an identity
//! was trusted, each generation when it was minted, and the two were compared in whole seconds.
//! Both halves failed: two events in the same second were indistinguishable, and a clock stepped
//! backwards between a mint and a trust made a generation sealed before the decision look minted
//! after it, releasing its posts to a member who was never entitled to them.
//!
//! So the order is now **logical**. This profile keeps one counter. Every generation it mints
//! and every trust decision it takes draws the next value, and the value is persisted before it
//! is used, so no value is ever handed out twice, even across a crash. Comparing two values
//! compares the order the events were committed in, whatever any clock says. A clock cannot
//! move a value, so a clock step can no longer widen what anyone reads: that attack is not
//! defended against, it is made impossible to express.
//!
//! **Where it is kept, and under what seal.** The counter and each trusted identity's value sit
//! in one blob in the store's metadata table, sealed under HKDF of the identity's `self_seed`
//! (as #208's open-room set is), so it is exactly as hard to open as the identity vault, and not
//! under the classical `id_proof`-derived key the trust keyring still uses (#214). Each
//! generation's value is kept with the generation's origin in the room's own key material,
//! which the room's SEK seals.
//!
//! **Rollback.** A blob deleted or rolled back on disk would restart the counter. Every stamp is
//! therefore also floored by a caller-supplied value: a mint by the room's own newest
//! generation, a trust by the newest generation of every room open at that moment. A deleted
//! blob can then never make an open room's existing generation look newer than a new decision.

use std::collections::BTreeMap;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::atrest::sek::{Sek, NONCE_LEN, SEK_LEN};
use crate::atrest::store::{open_segment, seal_segment, SealedSegment, SegmentKind};
use crate::atrest::vault::VaultRootSigner;
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::store::Store;
use crate::node::trust::MAX_TRUSTED;

/// The metadata key the sealed blob is stored under.
pub const CONSENT_ORDER_META_KEY: &str = "consent-order";

/// HKDF info for the blob's sealing key, over `self_seed`. Distinct from every other label taken
/// over `self_seed`, so no other key derived from it opens this blob.
pub const CONSENT_ORDER_SEK_INFO: &[u8] = b"vox/consent-order-sek/v1";

/// Its slot within [`SegmentKind::Trust`] (the AEAD binds it); distinct from the keyring's (0)
/// and the pending consents' (1).
const SEGMENT_ID: u64 = 3;

/// Encoding version of the body.
const VERSION: u64 = 1;

fn order_sek(signer: &VaultRootSigner) -> Result<Sek> {
    let hk = Hkdf::<Sha256>::new(None, signer.self_seed());
    let mut key = Zeroizing::new([0u8; SEK_LEN]);
    hk.expand(CONSENT_ORDER_SEK_INFO, key.as_mut())
        .map_err(|_| Error::AtRestUnlockFailed)?;
    Ok(Sek::from_bytes(key))
}

/// The profile's consent-order counter and the value each trusted identity's decision drew.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConsentOrder {
    /// The last value handed out. Only ever increases.
    last: u64,
    /// Trusted identity → the value its (current) trust decision drew.
    trusted: BTreeMap<Digest32, u64>,
}

impl ConsentOrder {
    /// The value `fingerprint`'s current trust decision drew, if it was taken since this order
    /// was kept. An identity trusted before (a keyring row with no value) has none, and is
    /// entitled to no history: narrower, never wider.
    #[must_use]
    pub fn trusted_at(&self, fingerprint: &Digest32) -> Option<u64> {
        self.trusted.get(fingerprint).copied()
    }

    /// Every recorded decision, `(identity, value)`.
    pub fn decisions(&self) -> impl Iterator<Item = (Digest32, u64)> + '_ {
        self.trusted.iter().map(|(fp, v)| (*fp, *v))
    }

    fn next(&mut self, at_least: u64) -> Result<u64> {
        let v = self
            .last
            .max(at_least)
            .checked_add(1)
            .ok_or(Error::SizeLimitExceeded("consent order counter"))?;
        self.last = v;
        Ok(v)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3)
            .uint(VERSION)
            .uint(self.last)
            .array(self.trusted.len());
        for (fp, v) in &self.trusted {
            e.array(2).bytes(fp).uint(*v);
        }
        e.finish()
    }

    fn from_bytes(b: &[u8]) -> Result<Self> {
        let bad = |why: &'static str| Error::MalformedAtRest(why);
        let mut d = Decoder::new(b);
        if d.array().map_err(|_| bad("consent order"))? != 3 {
            return Err(bad("consent order arity"));
        }
        if d.uint().map_err(|_| bad("consent order version"))? != VERSION {
            return Err(bad("consent order version"));
        }
        let last = d.uint().map_err(|_| bad("consent order counter"))?;
        let n = d.array().map_err(|_| bad("consent order list"))?;
        if n > MAX_TRUSTED {
            return Err(Error::SizeLimitExceeded("consent order entries"));
        }
        let mut trusted = BTreeMap::new();
        for _ in 0..n {
            if d.array().map_err(|_| bad("consent order row"))? != 2 {
                return Err(bad("consent order row arity"));
            }
            let fp = Digest32::try_from(d.bytes().map_err(|_| bad("consent order identity"))?)
                .map_err(|_| bad("consent order identity length"))?;
            let v = d.uint().map_err(|_| bad("consent order value"))?;
            // Every value was handed out by this counter, so none can exceed it.
            if v > last {
                return Err(bad("consent order value past the counter"));
            }
            trusted.insert(fp, v);
        }
        d.finish().map_err(|_| bad("consent order trailing"))?;
        Ok(Self { last, trusted })
    }

    fn open(blob: Option<&[u8]>, signer: &VaultRootSigner) -> Result<Self> {
        let Some(blob) = blob else {
            return Ok(Self::default());
        };
        if blob.len() < NONCE_LEN {
            return Err(Error::MalformedAtRest("consent order blob too short"));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce = <[u8; NONCE_LEN]>::try_from(nonce_bytes)
            .map_err(|_| Error::MalformedAtRest("consent order nonce"))?;
        let sealed = SealedSegment {
            nonce,
            ciphertext: ciphertext.to_vec(),
        };
        let plain = open_segment(&order_sek(signer)?, SegmentKind::Trust, SEGMENT_ID, &sealed)?;
        Self::from_bytes(&plain)
    }

    fn seal(&self, signer: &VaultRootSigner) -> Result<Vec<u8>> {
        let sealed = seal_segment(
            &order_sek(signer)?,
            SegmentKind::Trust,
            SEGMENT_ID,
            &self.to_bytes(),
        )?;
        let mut blob = Vec::with_capacity(NONCE_LEN + sealed.ciphertext.len());
        blob.extend_from_slice(&sealed.nonce);
        blob.extend_from_slice(&sealed.ciphertext);
        Ok(blob)
    }

    /// Read and open the order, or an empty one if nothing was ever stamped. Requires an
    /// unlocked identity.
    pub fn load(store: &Store, signer: &VaultRootSigner) -> Result<Self> {
        let blob = store.get_meta(CONSENT_ORDER_META_KEY)?;
        Self::open(blob.as_deref(), signer)
    }

    /// Apply `f` to the persisted order in one store transaction and persist the result before
    /// returning, so a value is on disk before anybody can use it.
    fn update<T>(
        store: &Store,
        signer: &VaultRootSigner,
        f: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        store.update_meta(CONSENT_ORDER_META_KEY, |blob| {
            let mut order = Self::open(blob, signer)?;
            let out = f(&mut order)?;
            Ok((order.seal(signer)?, out))
        })
    }
}

/// Stamp one generation's mint: a value greater than every value this profile ever handed out,
/// and than `at_least` (the room's own newest generation). Persisted before it is returned.
///
/// # Errors
/// A store that cannot be written, or a blob that does not open.
pub fn stamp_mint(store: &Store, signer: &VaultRootSigner, at_least: u64) -> Result<u64> {
    ConsentOrder::update(store, signer, |o| o.next(at_least))
}

/// Stamp a **new** trust decision for `fingerprint` and record it, replacing any value an
/// earlier decision drew: a re-trust after a removal is a new decision, and what it entitles is
/// measured from it alone. `at_least` is the newest generation of every room open now.
///
/// # Errors
/// A store that cannot be written, or a blob that does not open.
pub fn stamp_trust(
    store: &Store,
    signer: &VaultRootSigner,
    fingerprint: Digest32,
    at_least: u64,
) -> Result<u64> {
    ConsentOrder::update(store, signer, |o| {
        if !o.trusted.contains_key(&fingerprint) && o.trusted.len() >= MAX_TRUSTED {
            return Err(Error::SizeLimitExceeded("consent order entries"));
        }
        let v = o.next(at_least)?;
        o.trusted.insert(fingerprint, v);
        Ok(v)
    })
}

/// Forget `fingerprint`'s decision: it was removed from the keyring. The counter is kept.
///
/// # Errors
/// A store that cannot be written, or a blob that does not open.
pub fn forget_trust(store: &Store, signer: &VaultRootSigner, fingerprint: &Digest32) -> Result<()> {
    ConsentOrder::update(store, signer, |o| {
        o.trusted.remove(fingerprint);
        Ok(())
    })
}
