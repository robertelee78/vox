//! History delivery: per-epoch origin chain-key retention and the
//! release-at-iteration mechanism (ADR-006 §History).
//!
//! The chain is one-way, so *what* a newly-consented member can read is fixed by
//! *which* iteration's chain key the sender releases in the SKDM:
//!
//! - **Forward-only:** release the chain key at the sender's **current**
//!   iteration → the newcomer reads only from now on. (No retention needed; use
//!   [`crate::group::state::SenderChain::current_position`].)
//! - **Full-history:** release the **origin** chain key (`iteration = 0`) for each
//!   epoch the retained history spans → the newcomer derives the whole chain and
//!   reads all of that sender's retained history.
//!
//! To release at *any* past iteration, the sender must retain the origin chain
//! key of that generation; from the origin it can derive the key at any
//! iteration by ratcheting forward (it cannot ratchet backward). This module is
//! that retention store plus the "produce an SKDM that releases generation G at
//! iteration X" operation.
//!
//! ## Scope boundary (ADR-006 / ADR-007 / ADR-010)
//! M4 provides only the **mechanism**: "retain origin keys" and "release a
//! verifiable SKDM at iteration X to identity Y". The **policy choice**
//! (forward-only vs full-history) and the **consent gate** (whether/when to send
//! an SKDM to a given identity at all — the per-sender-consent differentiator)
//! are ADR-007 / M6: M6 decides, M4 executes. The **TTL bound** on how long
//! origin keys are retained is ADR-010 / M8 (the channel-retention window); M4
//! exposes an explicit [`OriginKeyStore::prune_before`] so M8 can enforce it, and
//! never retains unboundedly on its own beyond what the caller installs.

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::group::senderkey::ChainKey;
use crate::group::skdm::Skdm;
use crate::hash::Digest32;
use crate::identity::composite::RootSigner;
use crate::pairwise::MAX_SKIP;

/// A retained origin record for one `(channel_id, epoch, chain_id)` generation:
/// the iteration-0 chain key, the composite Sender-Key signing public key, the
/// author identity, and the creation timestamp for TTL pruning (ADR-010/M8).
///
/// The **channel id and author id are stored, not just used as map keys** so a
/// released SKDM is always bound to the channel/identity the key was actually
/// minted for — a retained origin from channel G can never be root-signed into a
/// valid SKDM for channel H (the cross-group-confusion guard at the release
/// layer, ADR-006 / eprint 2023/1385).
struct OriginRecord {
    channel_id: Digest32,
    epoch: u64,
    author_id: Digest32,
    origin_key: ChainKey,
    signing_pubkey: [u8; crate::group::wire::SENDER_KEY_SIGNING_PUB_LEN],
    /// Wall-clock (Unix seconds) the generation was created — the TTL anchor.
    created_at: u64,
}

/// A sender's store of origin chain keys, enabling full-history (and
/// any-iteration) SKDM release (ADR-006 §History).
///
/// Keyed by `(channel_id, epoch, chain_id)` so generations are unambiguous across
/// channels, epochs, and rotations — and, critically, so a retained key can only
/// ever be released for the channel it was minted in (channel binding is part of
/// the key, not a caller-trusted parameter). Bounded only by what the caller
/// retains and by [`OriginKeyStore::prune_before`] (the M8/ADR-010 TTL seam).
#[derive(Default)]
pub struct OriginKeyStore {
    records: HashMap<(Digest32, u64, u64), OriginRecord>,
}

impl core::fmt::Debug for OriginKeyStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OriginKeyStore")
            .field("generations", &self.records.len())
            .finish()
    }
}

impl OriginKeyStore {
    /// A fresh, empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Retain the origin (iteration-0) chain key for one
    /// `(channel_id, epoch, chain_id)` generation, with its signing public key and
    /// author identity, so the sender can later release full history. Call this
    /// when a generation is created (alongside
    /// [`crate::group::state::SenderChain::new`]/`rotated`).
    ///
    /// `signing_pubkey` MUST be the composite Sender-Key signing public key of the
    /// same generation, and `author_id` the author's identity fingerprint, so a
    /// released SKDM names the key that actually signed that generation's messages
    /// and is bound to the right identity.
    #[allow(clippy::too_many_arguments)]
    pub fn retain_origin(
        &mut self,
        channel_id: &Digest32,
        epoch: u64,
        author_id: &Digest32,
        chain_id: u64,
        origin_key: ChainKey,
        signing_pubkey: [u8; crate::group::wire::SENDER_KEY_SIGNING_PUB_LEN],
        created_at: u64,
    ) {
        self.records.insert(
            (*channel_id, epoch, chain_id),
            OriginRecord {
                channel_id: *channel_id,
                epoch,
                author_id: *author_id,
                origin_key,
                signing_pubkey,
                created_at,
            },
        );
    }

    /// Whether an origin key is retained for `(channel_id, epoch, chain_id)`.
    #[must_use]
    pub fn has(&self, channel_id: &Digest32, epoch: u64, chain_id: u64) -> bool {
        self.records.contains_key(&(*channel_id, epoch, chain_id))
    }

    /// Derive the chain key at `iteration` for a retained generation by ratcheting
    /// the origin forward (one-way; cannot go backward). Bounded by
    /// [`MAX_SKIP`] iterations of derivation to avoid an unbounded loop on a
    /// hostile request.
    fn derive_at(
        &self,
        channel_id: &Digest32,
        epoch: u64,
        chain_id: u64,
        iteration: u64,
    ) -> Result<ChainKey> {
        let rec = self
            .records
            .get(&(*channel_id, epoch, chain_id))
            .ok_or(Error::MalformedBundle("no retained origin for generation"))?;
        if iteration > MAX_SKIP {
            return Err(Error::MalformedBundle(
                "history release iteration exceeds MAX_SKIP",
            ));
        }
        let mut ck = rec.origin_key.clone();
        let mut i = 0u64;
        while i < iteration {
            ck = ck.advance()?;
            i += 1;
        }
        Ok(ck)
    }

    /// Build a **full-history** SKDM: release the origin SKDM (`iteration = 0`) for
    /// `(channel_id, epoch, chain_id)` so the recipient derives the whole retained
    /// chain (ADR-006 §History full-history).
    pub fn full_history_skdm(
        &self,
        author_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        chain_id: u64,
    ) -> Result<Skdm> {
        self.release_at(author_root, channel_id, epoch, chain_id, 0)
    }

    /// Build an SKDM releasing `(channel_id, epoch, chain_id)` at an arbitrary
    /// `release_iteration` (the general mechanism; forward-only callers usually
    /// release at the sender's current iteration directly from the live
    /// [`crate::group::state::SenderChain`] instead).
    ///
    /// The lookup is keyed by `channel_id`, so a `channel_id` that does not match a
    /// retained generation simply finds nothing and is rejected — a retained key
    /// can never be released for the wrong channel. As defense in depth, the
    /// stored `channel_id` is also re-checked against the requested one, and the
    /// SKDM is built from the *stored* channel/epoch/author, never from
    /// caller-supplied values that could diverge from the signed key material.
    pub fn release_at(
        &self,
        author_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        chain_id: u64,
        release_iteration: u64,
    ) -> Result<Skdm> {
        let rec = self
            .records
            .get(&(*channel_id, epoch, chain_id))
            .ok_or(Error::MalformedBundle("no retained origin for generation"))?;
        // Defense in depth: the map key already scopes by channel, but assert the
        // stored binding matches so a future refactor cannot silently reintroduce
        // a cross-channel release.
        if &rec.channel_id != channel_id || rec.epoch != epoch {
            return Err(Error::MalformedBundle(
                "origin record channel/epoch mismatch",
            ));
        }
        // The released author_id MUST be the author that signs (Skdm::build sets
        // author_id = author_root.fingerprint()); guard that the retained record
        // was minted by this same identity so a key cannot be re-attributed.
        if rec.author_id != author_root.fingerprint() {
            return Err(Error::MalformedBundle("origin record author mismatch"));
        }
        let key = self.derive_at(channel_id, epoch, chain_id, release_iteration)?;
        Skdm::build(
            author_root,
            &rec.channel_id,
            rec.epoch,
            chain_id,
            release_iteration,
            key,
            rec.signing_pubkey,
        )
    }

    /// Drop every retained origin created strictly before `cutoff` (Unix seconds)
    /// — the ADR-010/M8 channel-TTL enforcement seam. After pruning, those
    /// generations can no longer be released as history (the keys are zeroized on
    /// drop), which is exactly the retention bound M8 enforces.
    pub fn prune_before(&mut self, cutoff: u64) {
        self.records.retain(|_, r| r.created_at >= cutoff);
    }

    /// The number of retained generations (for tests / capacity reporting).
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::senderkey::{SenderKeySigningKey, CHAIN_KEY_LEN};
    use crate::group::state::{ReceiverChain, SenderChain};
    use crate::identity::composite::SoftwareRootSigner;

    fn root(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    #[test]
    fn full_history_lets_newcomer_read_whole_retained_chain() {
        // Build a generation with a KNOWN origin key so the store and the live
        // sender chain ratchet identically; emit several messages, retain the
        // origin, then release a full-history (iteration-0) SKDM and confirm the
        // newcomer reads ALL of them.
        let cid = [9u8; 32];
        let r = root(1, 2);
        let author = r.public_key().fingerprint();

        // A signing key shared by the live chain and the retained record.
        let signing = SenderKeySigningKey::from_component_seeds(&[3u8; 32], &[4u8; 32]).unwrap();
        let origin = ChainKey::from_bytes([0x21; CHAIN_KEY_LEN]);

        // Drive a sender chain manually off the same origin/signing key.
        let mut s = SenderChain::new_with_parts(
            &cid,
            1,
            &author,
            0,
            origin.clone(),
            SenderKeySigningKey::from_component_seeds(&[3u8; 32], &[4u8; 32]).unwrap(),
            1_000,
        );
        let mut msgs = Vec::new();
        for i in 0..4 {
            msgs.push(s.encrypt(format!("h{i}").as_bytes()).unwrap());
        }

        // Retain the origin and release full history.
        let mut store = OriginKeyStore::new();
        store.retain_origin(
            &cid,
            1,
            &author,
            0,
            origin,
            signing.public_key().to_bytes(),
            1_000,
        );
        let skdm = store.full_history_skdm(&r, &cid, 1, 0).unwrap();
        assert_eq!(skdm.body.iteration, 0);

        let mut recv = ReceiverChain::from_skdm(&skdm, &r.public_key(), &cid, 1).unwrap();
        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(recv.decrypt(m).unwrap(), format!("h{i}").as_bytes());
        }
    }

    #[test]
    fn release_at_specific_iteration_reads_only_forward() {
        let cid = [9u8; 32];
        let r = root(1, 2);
        let author = r.public_key().fingerprint();
        let origin = ChainKey::from_bytes([0x77; CHAIN_KEY_LEN]);
        let signing = SenderKeySigningKey::from_component_seeds(&[5u8; 32], &[6u8; 32]).unwrap();

        let mut s = SenderChain::new_with_parts(
            &cid,
            1,
            &author,
            0,
            origin.clone(),
            SenderKeySigningKey::from_component_seeds(&[5u8; 32], &[6u8; 32]).unwrap(),
            1_000,
        );
        let m0 = s.encrypt(b"0").unwrap();
        let _m1 = s.encrypt(b"1").unwrap();
        let m2 = s.encrypt(b"2").unwrap();

        let mut store = OriginKeyStore::new();
        store.retain_origin(
            &cid,
            1,
            &author,
            0,
            origin,
            signing.public_key().to_bytes(),
            1_000,
        );
        // Release at iteration 2.
        let skdm = store.release_at(&r, &cid, 1, 0, 2).unwrap();
        let mut recv = ReceiverChain::from_skdm(&skdm, &r.public_key(), &cid, 1).unwrap();
        // Cannot read iteration 0 (before the released start).
        assert!(recv.decrypt(&m0).is_err());
        // Reads iteration 2 forward.
        assert_eq!(recv.decrypt(&m2).unwrap(), b"2");
    }

    #[test]
    fn prune_before_drops_old_generations() {
        let cid = [9u8; 32];
        let author = [0xABu8; 32];
        let mut store = OriginKeyStore::new();
        let spk = SenderKeySigningKey::from_component_seeds(&[1u8; 32], &[2u8; 32])
            .unwrap()
            .public_key()
            .to_bytes();
        store.retain_origin(
            &cid,
            1,
            &author,
            0,
            ChainKey::from_bytes([1; CHAIN_KEY_LEN]),
            spk,
            100,
        );
        store.retain_origin(
            &cid,
            2,
            &author,
            0,
            ChainKey::from_bytes([2; CHAIN_KEY_LEN]),
            spk,
            5_000,
        );
        assert_eq!(store.len(), 2);
        store.prune_before(1_000); // drop the epoch-1 generation (created at 100)
        assert!(!store.has(&cid, 1, 0));
        assert!(store.has(&cid, 2, 0));
    }

    #[test]
    fn release_unknown_generation_errors() {
        let store = OriginKeyStore::new();
        let r = root(1, 2);
        assert!(store.full_history_skdm(&r, &[0u8; 32], 9, 9).is_err());
    }

    #[test]
    fn release_for_wrong_channel_is_rejected() {
        // [MED] cross-channel release guard: an origin retained for channel G must
        // NOT be releasable as an SKDM for channel H even if (epoch, chain_id)
        // collide. The channel-scoped lookup makes it find nothing → reject.
        let g = [0x47u8; 32];
        let h = [0x48u8; 32]; // same epoch+chain_id, different channel
        let r = root(1, 2);
        let author = r.public_key().fingerprint();
        let spk = SenderKeySigningKey::from_component_seeds(&[1u8; 32], &[2u8; 32])
            .unwrap()
            .public_key()
            .to_bytes();
        let mut store = OriginKeyStore::new();
        store.retain_origin(
            &g,
            1,
            &author,
            0,
            ChainKey::from_bytes([1; CHAIN_KEY_LEN]),
            spk,
            100,
        );

        // Releasing for channel G works...
        assert!(store.release_at(&r, &g, 1, 0, 0).is_ok());
        // ...but releasing the SAME (epoch, chain_id) for channel H is rejected.
        assert!(matches!(
            store.release_at(&r, &h, 1, 0, 0),
            Err(Error::MalformedBundle("no retained origin for generation"))
        ));
        assert!(store.full_history_skdm(&r, &h, 1, 0).is_err());
    }

    #[test]
    fn release_by_wrong_author_is_rejected() {
        // An origin retained as authored by identity A cannot be re-signed/released
        // by identity B (author binding guard, defense in depth).
        let cid = [9u8; 32];
        let author_a = root(1, 2);
        let author_b = root(7, 8);
        let spk = SenderKeySigningKey::from_component_seeds(&[1u8; 32], &[2u8; 32])
            .unwrap()
            .public_key()
            .to_bytes();
        let mut store = OriginKeyStore::new();
        store.retain_origin(
            &cid,
            1,
            &author_a.public_key().fingerprint(),
            0,
            ChainKey::from_bytes([1; CHAIN_KEY_LEN]),
            spk,
            100,
        );
        assert!(store.release_at(&author_a, &cid, 1, 0, 0).is_ok());
        assert!(matches!(
            store.release_at(&author_b, &cid, 1, 0, 0),
            Err(Error::MalformedBundle("origin record author mismatch"))
        ));
    }
}
