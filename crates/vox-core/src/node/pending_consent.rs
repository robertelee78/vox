//! **Consents decided but not yet delivered**, each with the sender key it releases, fixed at the
//! moment of the decision (V210-30).
//!
//! Trusting a member releases this identity's sender key to it, and rooms are forward-only: the
//! member reads from the position the key is released at. A member that could not be reached
//! when it was trusted used to get a key built only when it *could* be — from the chain's
//! position then — so every post made in between was sealed before that position and never
//! readable to it. The key is now taken once, at the decision, kept here, and that same key is
//! what is delivered, however late.
//!
//! Kept **beside the keyring**, sealed under the same identity-derived key and not inside any
//! room: a pending consent exists only because of a trust entry, so removing the entry removes
//! every pending consent to that identity in one write, in rooms open or closed. A snapshot can
//! therefore never outlive the trust decision it was taken for, and a later re-trust takes a new
//! one from its own moment.

use std::collections::BTreeMap;

use crate::atrest::sek::NONCE_LEN;
use crate::atrest::store::{open_segment, seal_segment, SealedSegment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::identity::composite::RootSigner;
use crate::node::store::Store;
use crate::node::trust::{trust_sek, MAX_TRUSTED};

/// The metadata key the sealed map is stored under.
const META_KEY: &str = "pending-consent";

/// Its slot within [`SegmentKind::Trust`]; the keyring is slot 0.
const SEGMENT_ID: u64 = 1;

/// Encoding version of the body.
const VERSION: u64 = 1;

/// Most pending consents held at once: every trusted identity in a generous number of rooms.
/// A bound on load, so a corrupt blob cannot force an unbounded allocation.
const MAX_PENDING: usize = MAX_TRUSTED * 16;

/// Longest SKDM kept. A real one is a few KiB (composite signing key and signature).
const MAX_SKDM: usize = 16 * 1024;

/// `(room, member) → the SKDM taken when this identity decided to consent to that member`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PendingConsents {
    entries: BTreeMap<(Digest32, Digest32), Vec<u8>>,
}

impl PendingConsents {
    /// The SKDM (wire form) held for `target` in `channel_id`, if any.
    #[must_use]
    pub fn get(&self, channel_id: &Digest32, target: &Digest32) -> Option<&[u8]> {
        self.entries.get(&(*channel_id, *target)).map(Vec::as_slice)
    }

    /// Hold `skdm` (wire form) as the key to release to `target` in `channel_id`.
    pub fn insert(&mut self, channel_id: Digest32, target: Digest32, skdm: Vec<u8>) {
        self.entries.insert((channel_id, target), skdm);
    }

    /// The consent was delivered and recorded: nothing is pending for it any more.
    pub fn remove(&mut self, channel_id: &Digest32, target: &Digest32) -> bool {
        self.entries.remove(&(*channel_id, *target)).is_some()
    }

    /// `target` was removed from the keyring: forget every pending consent to it, in every room.
    pub fn forget(&mut self, target: &Digest32) -> bool {
        let before = self.entries.len();
        self.entries.retain(|(_, t), _| t != target);
        self.entries.len() != before
    }

    /// Canonical CBOR body: `[version, [[room, member, skdm], ..]]`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2).uint(VERSION).array(self.entries.len());
        for ((room, member), skdm) in &self.entries {
            e.array(3).bytes(room).bytes(member).bytes(skdm);
        }
        e.finish()
    }

    /// Parse a body.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let bad = |what| Error::MalformedAtRest(what);
        let mut d = Decoder::new(b);
        if d.array().map_err(|_| bad("pending consents"))? != 2 {
            return Err(bad("pending consents arity"));
        }
        if d.uint().map_err(|_| bad("pending consents version"))? != VERSION {
            return Err(bad("pending consents version"));
        }
        let n = d.array().map_err(|_| bad("pending consents len"))?;
        if n > MAX_PENDING {
            return Err(Error::SizeLimitExceeded("pending consents"));
        }
        let mut entries = BTreeMap::new();
        for _ in 0..n {
            if d.array().map_err(|_| bad("pending consent row"))? != 3 {
                return Err(bad("pending consent row arity"));
            }
            let room = Digest32::try_from(d.bytes().map_err(|_| bad("pending consent room"))?)
                .map_err(|_| bad("pending consent room length"))?;
            let member = Digest32::try_from(d.bytes().map_err(|_| bad("pending consent member"))?)
                .map_err(|_| bad("pending consent member length"))?;
            let skdm = d.bytes().map_err(|_| bad("pending consent key"))?;
            if skdm.len() > MAX_SKDM {
                return Err(Error::SizeLimitExceeded("pending consent key"));
            }
            entries.insert((room, member), skdm.to_vec());
        }
        d.finish().map_err(|_| bad("pending consents trailing"))?;
        Ok(Self { entries })
    }

    /// Seal and write. Requires an unlocked identity.
    pub fn save(&self, store: &Store, signer: &dyn RootSigner) -> Result<()> {
        let sek = trust_sek(signer)?;
        let sealed = seal_segment(&sek, SegmentKind::Trust, SEGMENT_ID, &self.to_bytes())?;
        let mut blob = Vec::with_capacity(NONCE_LEN + sealed.ciphertext.len());
        blob.extend_from_slice(&sealed.nonce);
        blob.extend_from_slice(&sealed.ciphertext);
        store.put_meta(META_KEY, &blob)
    }

    /// Read and open, or an empty map if nothing was ever pending. Requires an unlocked identity.
    pub fn load(store: &Store, signer: &dyn RootSigner) -> Result<Self> {
        let Some(blob) = store.get_meta(META_KEY)? else {
            return Ok(Self::default());
        };
        if blob.len() < NONCE_LEN {
            return Err(Error::MalformedAtRest("pending consents blob too short"));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce = <[u8; NONCE_LEN]>::try_from(nonce_bytes)
            .map_err(|_| Error::MalformedAtRest("pending consents nonce"))?;
        let sealed = SealedSegment {
            nonce,
            ciphertext: ciphertext.to_vec(),
        };
        let sek = trust_sek(signer)?;
        let plain = open_segment(&sek, SegmentKind::Trust, SEGMENT_ID, &sealed)?;
        Self::from_bytes(&plain)
    }
}
