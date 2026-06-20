//! Per-author sender-chain state: the send side ([`SenderChain`]) that ratchets
//! and signs broadcasts, and the receive side ([`ReceiverChain`]) that derives
//! message keys with a bounded skip/replay window (ADR-006 §Wire).
//!
//! ## Send side
//! A [`SenderChain`] owns the live chain key, the next `iteration`, the composite
//! Sender-Key signing key, and the channel/epoch/author/chain_id it is bound to.
//! [`SenderChain::encrypt`] derives the current message key, advances the chain
//! one step (one-way — the consumed key is gone), and signs the broadcast. A
//! scheduled-rotation bound (default `N` = 1000 messages or `T` = 7 days,
//! whichever first; ADR-006) is tracked by [`SenderChain::should_rotate`]; the
//! *trigger* for a membership-change rotation is M6/M7, but the mechanism (a new
//! `chain_id` generation) lives here.
//!
//! ## Receive side
//! A [`ReceiverChain`] is created from a verified SKDM at its starting
//! `iteration` (so it can read from there forward, never earlier — one-wayness).
//! It accepts a message only if its `iteration` has not already been consumed,
//! caches up to [`MAX_SKIP`] skipped per-iteration
//! message keys for out-of-order delivery (rejecting a gap beyond the bound — a
//! DoS guard, the same discipline as ADR-004), and **deletes a key after use** so
//! a replay at the same iteration fails. The `(channelID, epoch, author_id,
//! chain_id)` of every inbound message is checked against the chain's binding
//! before any key derivation (cross-group-confusion guard).

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::group::message::{GroupMessage, MessageHeader};
use crate::group::senderkey::{ChainKey, MessageKey, SenderKeySigningKey};
use crate::group::skdm::Skdm;
use crate::hash::Digest32;
use crate::identity::composite::{CompositePublicKey, RootSigner};
use crate::pairwise::{MAX_CACHE, MAX_SKIP};

/// Default scheduled-rotation message bound: rotate the sender key after this
/// many messages (ADR-006, `N` = 1000).
pub const ROTATE_AFTER_MESSAGES: u64 = 1000;
/// Default scheduled-rotation time bound in seconds (ADR-006, `T` = 7 days).
pub const ROTATE_AFTER_SECS: u64 = 7 * 24 * 60 * 60;

/// The send side of one sender-key generation for `(channel, epoch, author,
/// chain_id)`: live chain key, next iteration, signing key, and rotation clock.
pub struct SenderChain {
    channel_id: Digest32,
    epoch: u64,
    author_id: Digest32,
    chain_id: u64,
    chain_key: ChainKey,
    /// The iteration the *next* [`encrypt`](Self::encrypt) will use/emit.
    next_iteration: u64,
    signing_key: SenderKeySigningKey,
    /// Wall-clock (Unix seconds) when this generation was created (rotation clock).
    created_at: u64,
}

impl core::fmt::Debug for SenderChain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SenderChain")
            .field("channel_id", &crate::hash::Hex(&self.channel_id))
            .field("epoch", &self.epoch)
            .field("chain_id", &self.chain_id)
            .field("next_iteration", &self.next_iteration)
            .finish_non_exhaustive()
    }
}

impl SenderChain {
    /// Start a fresh sender-key generation: sample a random origin chain key,
    /// generate a composite Sender-Key signing key, and begin at iteration 0.
    ///
    /// `chain_id` is the generation id (0 for the first; incremented by the caller
    /// on every rotation — see [`SenderChain::rotated`]).
    pub fn new(
        channel_id: &Digest32,
        epoch: u64,
        author_id: &Digest32,
        chain_id: u64,
        created_at: u64,
    ) -> Result<Self> {
        Ok(Self {
            channel_id: *channel_id,
            epoch,
            author_id: *author_id,
            chain_id,
            chain_key: ChainKey::generate()?,
            next_iteration: 0,
            signing_key: SenderKeySigningKey::generate()?,
            created_at,
        })
    }

    /// Construct a sender chain from explicit parts (a known origin chain key and
    /// signing key). Used to keep a live chain and a retained origin
    /// ([`crate::group::history::OriginKeyStore`]) ratcheting in lockstep — the
    /// release path derives the same keys the live chain produced.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_with_parts(
        channel_id: &Digest32,
        epoch: u64,
        author_id: &Digest32,
        chain_id: u64,
        origin_key: ChainKey,
        signing_key: SenderKeySigningKey,
        created_at: u64,
    ) -> Self {
        Self {
            channel_id: *channel_id,
            epoch,
            author_id: *author_id,
            chain_id,
            chain_key: origin_key,
            next_iteration: 0,
            signing_key,
            created_at,
        }
    }

    /// The channel id this chain is bound to.
    #[must_use]
    pub fn channel_id(&self) -> &Digest32 {
        &self.channel_id
    }

    /// The membership epoch this chain is bound to.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The generation id of this sender key.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The iteration the next [`encrypt`](Self::encrypt) will emit.
    #[must_use]
    pub fn next_iteration(&self) -> u64 {
        self.next_iteration
    }

    /// The composite Sender-Key signing public key (carried in SKDMs).
    #[must_use]
    pub fn signing_pubkey(&self) -> CompositePublicKey {
        self.signing_key.public_key()
    }

    /// Encrypt and sign a broadcast at the current iteration, advancing the chain
    /// one step. The consumed message key is dropped immediately after sealing, so
    /// it cannot be recovered (forward secrecy within the chain).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<GroupMessage> {
        let header = MessageHeader {
            channel_id: self.channel_id,
            epoch: self.epoch,
            author_id: self.author_id,
            chain_id: self.chain_id,
            iteration: self.next_iteration,
        };
        let mk = self.chain_key.message_key()?;
        let msg = GroupMessage::seal(header, &mk, &self.signing_key, plaintext)?;
        // Advance one-way; the previous chain key is unrecoverable.
        self.chain_key = self.chain_key.advance()?;
        self.next_iteration = self
            .next_iteration
            .checked_add(1)
            .ok_or(Error::MalformedBundle("sender chain iteration overflow"))?;
        Ok(msg)
    }

    /// Build an SKDM that releases this sender key to a recipient identity at the
    /// given `release_iteration` (ADR-006 §History release-at-iteration
    /// mechanism). The chain key released is the *current* chain key only when
    /// `release_iteration == self.next_iteration`; releasing an earlier iteration
    /// requires the retained origin key (see [`crate::group::history`]).
    ///
    /// For the common "release current position" case (forward-only consent),
    /// pass `self.next_iteration` and `self.chain_key.clone()`.
    pub fn skdm_for(
        &self,
        author_root: &dyn RootSigner,
        release_iteration: u64,
        release_key: ChainKey,
    ) -> Result<Skdm> {
        Skdm::build(
            author_root,
            &self.channel_id,
            self.epoch,
            self.chain_id,
            release_iteration,
            release_key,
            self.signing_key.public_key().to_bytes(),
        )
    }

    /// The current chain key and iteration, for releasing a forward-only SKDM at
    /// the sender's current position (ADR-006 §History forward-only).
    #[must_use]
    pub fn current_position(&self) -> (u64, ChainKey) {
        (self.next_iteration, self.chain_key.clone())
    }

    /// Whether the scheduled-rotation bound has been reached (ADR-006): the chain
    /// has emitted at least `ROTATE_AFTER_MESSAGES`, or `ROTATE_AFTER_SECS` have
    /// elapsed since creation. The caller (M6/M7) acts on this by minting a new
    /// generation with [`SenderChain::rotated`].
    #[must_use]
    pub fn should_rotate(&self, now: u64) -> bool {
        self.next_iteration >= ROTATE_AFTER_MESSAGES
            || now.saturating_sub(self.created_at) >= ROTATE_AFTER_SECS
    }

    /// Mint the next generation: a fresh chain key, signing key, and iteration-0,
    /// with `chain_id` incremented. Supersedes this generation for new messages
    /// (existing recipients keep reading the old generation's retained history).
    pub fn rotated(&self, now: u64) -> Result<Self> {
        let next_chain_id = self
            .chain_id
            .checked_add(1)
            .ok_or(Error::MalformedBundle("chain_id overflow"))?;
        Self::new(
            &self.channel_id,
            self.epoch,
            &self.author_id,
            next_chain_id,
            now,
        )
    }
}

/// The receive side of one `(author_id, chain_id)` generation: derives message
/// keys forward from a starting iteration, with a bounded skip/replay window.
pub struct ReceiverChain {
    channel_id: Digest32,
    epoch: u64,
    author_id: Digest32,
    chain_id: u64,
    /// The composite signing public key authenticated via the SKDM's root
    /// signature; every inbound message's signature is checked against it.
    signing_pubkey: CompositePublicKey,
    /// The chain key at `next_iteration` (the lowest iteration not yet derived).
    chain_key: ChainKey,
    /// The next iteration the live chain key corresponds to.
    next_iteration: u64,
    /// Skipped (out-of-order) message keys, keyed by iteration, bounded.
    skipped: HashMap<u64, MessageKey>,
}

impl core::fmt::Debug for ReceiverChain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReceiverChain")
            .field("channel_id", &crate::hash::Hex(&self.channel_id))
            .field("epoch", &self.epoch)
            .field("chain_id", &self.chain_id)
            .field("next_iteration", &self.next_iteration)
            .field("skipped", &self.skipped.len())
            .finish_non_exhaustive()
    }
}

impl ReceiverChain {
    /// Build a receiver chain from a **verified** SKDM. The caller MUST have
    /// called [`Skdm::verify`] (or [`Skdm::verify_and_signing_key`]) first; this
    /// re-verifies the SKDM against `author_root` and the expected channel/epoch
    /// to make misuse impossible, then installs the released chain key at the
    /// SKDM's `iteration`.
    pub fn from_skdm(
        skdm: &Skdm,
        author_root: &CompositePublicKey,
        expected_channel: &Digest32,
        expected_epoch: u64,
    ) -> Result<Self> {
        let signing_pubkey =
            skdm.verify_and_signing_key(author_root, expected_channel, expected_epoch)?;
        Ok(Self {
            channel_id: skdm.body.channel_id,
            epoch: skdm.body.epoch,
            author_id: skdm.body.author_id,
            chain_id: skdm.body.chain_id,
            signing_pubkey,
            chain_key: skdm.body.chain_key.clone(),
            next_iteration: skdm.body.iteration,
            skipped: HashMap::new(),
        })
    }

    /// The generation id this receiver reads.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The lowest iteration this receiver has not yet consumed off the live chain.
    #[must_use]
    pub fn next_iteration(&self) -> u64 {
        self.next_iteration
    }

    /// Decrypt+verify an inbound broadcast. Enforces (in order):
    /// 1. `(channelID, epoch, author_id, chain_id)` match this chain's binding
    ///    (cross-group-confusion guard) — else reject.
    /// 2. The iteration is not before the chain head and not already consumed
    ///    (replay) — derive from cache or advance the live chain within
    ///    [`MAX_SKIP`].
    /// 3. The composite signature + AEAD open (via `GroupMessage`'s crate-internal
    ///    open path).
    ///
    /// On success the used key is deleted (replay at that iteration then fails).
    pub fn decrypt(&mut self, msg: &GroupMessage) -> Result<Vec<u8>> {
        self.check_binding(&msg.header)?;
        let iter = msg.header.iteration;

        // Path 1: a cached skipped key for this iteration (out-of-order arrival).
        if let Some(skipped_mk) = self.skipped.get(&iter) {
            let pt = msg.open(skipped_mk, &self.signing_pubkey)?;
            // Authenticated: consume the cached key.
            self.skipped.remove(&iter);
            return Ok(pt);
        }

        // Path 2: iteration before the live head and not cached → already consumed
        // or never-existed: a replay/forgery. Reject.
        if iter < self.next_iteration {
            return Err(Error::MalformedBundle("group iteration before chain head"));
        }

        // Path 3: iteration at/after the head. Plan the advance into temporaries
        // (do not mutate self until the AEAD/signature authenticate the packet).
        let gap = iter
            .checked_sub(self.next_iteration)
            .ok_or(Error::MalformedBundle("group iteration underflow"))?;
        if gap > MAX_SKIP {
            return Err(Error::MalformedBundle("group skip gap exceeds MAX_SKIP"));
        }
        if self.skipped.len().saturating_add(gap as usize) > MAX_CACHE {
            return Err(Error::MalformedBundle("group skipped-key cache full"));
        }

        // Derive the skipped keys (strictly before `iter`) and the target key,
        // advancing a *candidate* chain key without committing.
        let mut candidate_ck = self.chain_key.clone();
        let mut planned_skips: Vec<(u64, MessageKey)> = Vec::with_capacity(gap as usize);
        let mut i = self.next_iteration;
        while i < iter {
            planned_skips.push((i, candidate_ck.message_key()?));
            candidate_ck = candidate_ck.advance()?;
            i += 1;
        }
        let target_mk = candidate_ck.message_key()?;
        let after_target = candidate_ck.advance()?;

        // Authenticate against the target message key (signature + AEAD).
        let pt = msg.open(&target_mk, &self.signing_pubkey)?;

        // Authenticated: commit the advance + cache the skipped keys.
        for (skip_i, mk) in planned_skips {
            self.skipped.insert(skip_i, mk);
        }
        self.chain_key = after_target;
        self.next_iteration = iter
            .checked_add(1)
            .ok_or(Error::MalformedBundle("group iteration overflow"))?;
        Ok(pt)
    }

    /// Reject a message whose binding does not match this chain (the
    /// cross-group-confusion guard, applied before any key derivation).
    fn check_binding(&self, header: &MessageHeader) -> Result<()> {
        if header.channel_id != self.channel_id
            || header.epoch != self.epoch
            || header.author_id != self.author_id
            || header.chain_id != self.chain_id
        {
            return Err(Error::MalformedBundle("group message binding mismatch"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;

    fn root(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    // A sender + a receiver wired from a current-position SKDM (forward-only).
    fn wired(cid: Digest32, epoch: u64) -> (SoftwareRootSigner, SenderChain, ReceiverChain) {
        let r = root(1, 2);
        let author = r.public_key().fingerprint();
        let sender = SenderChain::new(&cid, epoch, &author, 0, 1_000).unwrap();
        let (iter, key) = sender.current_position();
        let skdm = sender.skdm_for(&r, iter, key).unwrap();
        let recv = ReceiverChain::from_skdm(&skdm, &r.public_key(), &cid, epoch).unwrap();
        (r, sender, recv)
    }

    #[test]
    fn in_order_sequence_round_trips() {
        let cid = [9u8; 32];
        let (_r, mut s, mut recv) = wired(cid, 1);
        for i in 0..5 {
            let m = s.encrypt(format!("msg{i}").as_bytes()).unwrap();
            assert_eq!(recv.decrypt(&m).unwrap(), format!("msg{i}").as_bytes());
        }
        assert_eq!(recv.next_iteration(), 5);
    }

    #[test]
    fn out_of_order_within_max_skip_ok() {
        let cid = [9u8; 32];
        let (_r, mut s, mut recv) = wired(cid, 1);
        let m0 = s.encrypt(b"m0").unwrap();
        let m1 = s.encrypt(b"m1").unwrap();
        let m2 = s.encrypt(b"m2").unwrap();
        // Deliver m2 first (skips 0,1), then m0, m1 from the cache.
        assert_eq!(recv.decrypt(&m2).unwrap(), b"m2");
        assert_eq!(recv.decrypt(&m0).unwrap(), b"m0");
        assert_eq!(recv.decrypt(&m1).unwrap(), b"m1");
    }

    #[test]
    fn replay_same_iteration_rejected() {
        let cid = [9u8; 32];
        let (_r, mut s, mut recv) = wired(cid, 1);
        let m0 = s.encrypt(b"once").unwrap();
        assert_eq!(recv.decrypt(&m0).unwrap(), b"once");
        // Replay: the key was consumed.
        assert!(recv.decrypt(&m0).is_err());
    }

    #[test]
    fn gap_beyond_max_skip_rejected() {
        let cid = [9u8; 32];
        let (_r, mut s, mut recv) = wired(cid, 1);
        let mut m = s.encrypt(b"far").unwrap();
        m.header.iteration = MAX_SKIP + 5;
        // (Header tamper also breaks the signature, but the bound is checked first.)
        assert!(recv.decrypt(&m).is_err());
    }

    #[test]
    fn cannot_read_before_start_iteration() {
        // A receiver started at iteration 3 (forward-only) cannot read iter 0..2.
        let cid = [9u8; 32];
        let r = root(1, 2);
        let author = r.public_key().fingerprint();
        let mut s = SenderChain::new(&cid, 1, &author, 0, 1_000).unwrap();
        // Sender emits 0,1,2 then we hand the receiver a current-position SKDM.
        let _ = s.encrypt(b"0").unwrap();
        let _ = s.encrypt(b"1").unwrap();
        let m2 = s.encrypt(b"2").unwrap();
        let (iter, key) = s.current_position(); // iter == 3
        assert_eq!(iter, 3);
        let skdm = s.skdm_for(&r, iter, key).unwrap();
        let mut recv = ReceiverChain::from_skdm(&skdm, &r.public_key(), &cid, 1).unwrap();
        // m2 (iteration 2) is before the start head → rejected.
        assert!(recv.decrypt(&m2).is_err());
        // But a message from iteration 3 onward reads fine.
        let m3 = s.encrypt(b"3").unwrap();
        assert_eq!(recv.decrypt(&m3).unwrap(), b"3");
    }

    #[test]
    fn binding_mismatch_rejected() {
        let cid = [9u8; 32];
        let (_r, mut s, mut recv) = wired(cid, 1);
        let mut m = s.encrypt(b"d").unwrap();
        // Wrong channel id → binding check rejects before key derivation.
        m.header.channel_id = [8u8; 32];
        assert!(recv.decrypt(&m).is_err());
    }

    #[test]
    fn should_rotate_on_time_bound() {
        let cid = [9u8; 32];
        let r = root(1, 2);
        let author = r.public_key().fingerprint();
        let s = SenderChain::new(&cid, 1, &author, 0, 1_000).unwrap();
        assert!(!s.should_rotate(1_000));
        assert!(s.should_rotate(1_000 + ROTATE_AFTER_SECS));
    }

    #[test]
    fn rotated_increments_chain_id_and_resets_iteration() {
        let cid = [9u8; 32];
        let r = root(1, 2);
        let author = r.public_key().fingerprint();
        let mut s = SenderChain::new(&cid, 1, &author, 0, 1_000).unwrap();
        let _ = s.encrypt(b"x").unwrap();
        let s2 = s.rotated(2_000).unwrap();
        assert_eq!(s2.chain_id(), 1);
        assert_eq!(s2.next_iteration(), 0);
    }
}
