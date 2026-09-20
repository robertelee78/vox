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

use zeroize::Zeroizing;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::group::senderkey::{ChainKey, CHAIN_KEY_LEN};
use crate::group::skdm::Skdm;
use crate::hash::Digest32;
use crate::identity::composite::RootSigner;
use crate::pairwise::MAX_SKIP;

/// Hard cap on retained generations. A generation spans up to
/// [`ROTATE_AFTER_MESSAGES`](crate::group::state::ROTATE_AFTER_MESSAGES) messages, so
/// this is continuity across hundreds of thousands of messages — while keeping the
/// sealed segment, and the memory holding live key material, bounded. At the cap the
/// **oldest** generation is evicted, never the newest: the live generation must always
/// be releasable (that is what a rotation's re-key needs).
pub const MAX_RETAINED_ORIGINS: usize = 256;

/// At-rest version of an [`OriginKeyStore`] state blob.
const ORIGIN_STATE_VERSION: u64 = 1;

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
        let key = (*channel_id, epoch, chain_id);
        // Make room before inserting, and only for a genuinely new generation:
        // re-retaining one already held must not evict a bystander.
        if !self.records.contains_key(&key) && self.records.len() >= MAX_RETAINED_ORIGINS {
            self.evict_oldest();
        }
        self.records.insert(
            key,
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

    /// Drop the generation with the smallest `created_at`, breaking ties on the key
    /// so eviction is deterministic (two generations minted in the same second must
    /// not evict differently on two nodes reading the same state).
    fn evict_oldest(&mut self) {
        let victim = self
            .records
            .iter()
            .min_by_key(|(k, r)| (r.created_at, **k))
            .map(|(k, _)| *k);
        if let Some(k) = victim {
            self.records.remove(&k);
        }
    }

    /// Serialize the store's **secret** state for a sealed at-rest key-material
    /// segment (ADR-010; ADR-016 M18.1). Canonical CBOR
    /// `[1, [[channel_id, epoch, chain_id, author_id, origin_key, signing_pubkey,
    /// created_at], …]]`, the generations in key order so the bytes are
    /// deterministic. Returned zeroizing; it must only ever be handed to
    /// [`crate::atrest::store::seal_segment`].
    #[must_use]
    pub fn to_state(&self) -> Zeroizing<Vec<u8>> {
        let mut keys: Vec<&(Digest32, u64, u64)> = self.records.keys().collect();
        keys.sort_unstable();
        let mut e = Encoder::new();
        e.array(2).uint(ORIGIN_STATE_VERSION).array(keys.len());
        for k in keys {
            let r = &self.records[k];
            e.array(7)
                .bytes(&r.channel_id)
                .uint(r.epoch)
                .uint(k.2)
                .bytes(&r.author_id)
                .bytes(r.origin_key.bytes())
                .bytes(&r.signing_pubkey)
                .uint(r.created_at);
        }
        Zeroizing::new(e.finish())
    }

    /// Restore a store from [`OriginKeyStore::to_state`] bytes (opened from a sealed
    /// segment). Strict: arity, version, count bound, lengths, trailing bytes — the
    /// blob is sealed, but a corrupt or rolled-back one must not become an
    /// unbounded allocation or a key bound to the wrong channel.
    pub fn from_state(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 2 {
            return Err(Error::MalformedBundle("origin store state arity"));
        }
        if d.uint()? != ORIGIN_STATE_VERSION {
            return Err(Error::MalformedBundle("origin store state version"));
        }
        let n = d.array()?;
        if n > MAX_RETAINED_ORIGINS {
            return Err(Error::SizeLimitExceeded("retained origin generations"));
        }
        let mut records = HashMap::with_capacity(n);
        for _ in 0..n {
            if d.array()? != 7 {
                return Err(Error::MalformedBundle("origin record arity"));
            }
            let channel_id: Digest32 = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedBundle("origin record channel_id"))?;
            let epoch = d.uint()?;
            let chain_id = d.uint()?;
            let author_id: Digest32 = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedBundle("origin record author_id"))?;
            let ck: [u8; CHAIN_KEY_LEN] = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedBundle("origin record origin_key"))?;
            let signing_pubkey: [u8; crate::group::wire::SENDER_KEY_SIGNING_PUB_LEN] = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedBundle("origin record signing_pubkey"))?;
            let created_at = d.uint()?;
            records.insert(
                (channel_id, epoch, chain_id),
                OriginRecord {
                    channel_id,
                    epoch,
                    author_id,
                    origin_key: ChainKey::from_bytes(ck),
                    signing_pubkey,
                    created_at,
                },
            );
        }
        d.finish()?;
        Ok(Self { records })
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
