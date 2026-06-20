//! The deniable content authenticator and its verifier (ADR-009 §"Per-entry-type
//! signing"; fills M5's [`crate::log::entry::DeniableVerifier`] seam).
//!
//! In a deniable channel a content entry's authenticator is a **composite
//! signature by the author's per-epoch ephemeral key `epk_i`** over the entry
//! signing input (`vox/log-entry/v1 ‖ canonical_body`, identical to the
//! attributable path — only the *key* differs). The authenticator bytes carried in
//! [`crate::log::entry::Authenticator::Deniable`] are exactly the composite
//! signature's fixed-length encoding.
//!
//! [`EpochVerifier`] registers, per epoch, the `(author_id → epk_i)` map and
//! verifies a deniable authenticator against the `epk` registered for that entry's
//! author **in that entry's epoch**. M5's
//! [`crate::log::dag::Dag::accept_with_deniable`] calls this through the trait.
//!
//! ## Per-sender consent (ADR-009 §"Per-sender consent is preserved")
//! The verifier holds **one `epk` per member**, registered only when that member's
//! verifier has been *released* (consent). Withholding = not registering. So a
//! recipient `N` that holds only `A`'s released `epk` can verify **only** `A`'s
//! content; `B`'s content fails with [`crate::log::entry::DeniableVerifier`]
//! returning an error — exactly the per-sender, monotonic visibility of ADR-007.
//! (Confidentiality is enforced separately by the M4 per-sender content keys;
//! this is the *authentication* half of the same per-sender gate.)

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature};
use crate::log::entry::{DeniableVerifier, Entry, EntrySkeleton};

use crate::deniable::epoch::{EphemeralSigningKey, MemberEpk};

/// Build the deniable authenticator bytes for a content entry: the composite
/// signature by `esk` over the entry's signing input. The returned bytes are the
/// fixed-length composite-signature encoding, ready for
/// [`crate::log::entry::Entry::with_deniable_authenticator`].
///
/// The `skeleton`'s `epoch`/`channel_id` MUST match the epoch this `esk` belongs
/// to; that binding is checked at verification time (the verifier keys on
/// `(epoch, author_id)`), and the author signs its own skeleton here.
pub fn sign_content(esk: &EphemeralSigningKey, skeleton: &EntrySkeleton) -> Result<Vec<u8>> {
    let sig = esk.sign(&skeleton.signing_input())?;
    Ok(sig.to_bytes().to_vec())
}

/// Build a complete deniable **content** [`Entry`] signed by `esk`, retaining
/// `payload`. Convenience over [`sign_content`] +
/// [`Entry::with_deniable_authenticator`]; the caller still constructs the
/// skeleton (it owns seq/prev_hash/lipmaa chaining from the M5 feed).
pub fn build_deniable_content(
    esk: &EphemeralSigningKey,
    skeleton: EntrySkeleton,
    payload: Vec<u8>,
) -> Result<Entry> {
    let auth = sign_content(esk, &skeleton)?;
    Entry::with_deniable_authenticator(skeleton, auth, Some(payload))
}

/// Verifies deniable content authenticators against per-epoch registered `epk`s.
///
/// Implements M5's [`DeniableVerifier`] trait. Keyed on the **exact**
/// `(channel_id, epoch, author_id)` triple: content authored by `A` in
/// `(channel, e)` verifies **only** under the `epk` registered for that exact
/// triple — never a scan across epochs. This is the security property ADR-009
/// requires: publishing an epoch's `esk` makes only *that* epoch's content
/// forgeable, so a published epoch-`e` key must NOT verify content claiming epoch
/// `e+1` (or a different channel). An entry whose triple has no registered `epk`
/// (not consented/released) fails — the per-sender consent gate.
#[derive(Debug, Default, Clone)]
pub struct EpochVerifier {
    /// (channel_id, epoch, author_id) -> epk_i. One ephemeral verification key per
    /// member per epoch per channel; populated only for *released* (consented)
    /// members.
    epks: HashMap<(Digest32, u64, Digest32), CompositePublicKey>,
}

impl EpochVerifier {
    /// An empty verifier (no member released yet).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Release (register) a single member's `epk` for `(channel_id, epoch)`.
    /// Calling this is the act of consent: afterwards this verifier can verify that
    /// member's content in that exact channel+epoch. Re-registering the *same* `epk`
    /// is idempotent; registering a *different* `epk` for an already-released triple
    /// is rejected (an epoch's per-member key is fixed once published in the DGKA
    /// setup — a second, different key would be an equivocation, not an update).
    pub fn release(&mut self, channel_id: Digest32, epoch: u64, member: &MemberEpk) -> Result<()> {
        let key = (channel_id, epoch, member.author_id);
        match self.epks.get(&key) {
            Some(existing) if existing == &member.epk => Ok(()),
            Some(_) => Err(Error::MalformedBundle("deniable epk re-release mismatch")),
            None => {
                self.epks.insert(key, member.epk.clone());
                Ok(())
            }
        }
    }

    /// Release every member of an epoch at once for `channel_id` (the channel
    /// operator's own view, where all consents are held). Each member goes through
    /// [`Self::release`].
    pub fn release_all(
        &mut self,
        channel_id: Digest32,
        epoch: u64,
        members: &[MemberEpk],
    ) -> Result<()> {
        for m in members {
            self.release(channel_id, epoch, m)?;
        }
        Ok(())
    }

    /// Whether `author`'s `epk` for `(channel_id, epoch)` has been released.
    #[must_use]
    pub fn is_released(&self, channel_id: &Digest32, epoch: u64, author: &Digest32) -> bool {
        self.epks.contains_key(&(*channel_id, epoch, *author))
    }

    /// The number of registered `(channel, epoch, author)` verification keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.epks.len()
    }

    /// Whether no verification key has been released.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.epks.is_empty()
    }
}

impl DeniableVerifier for EpochVerifier {
    fn verify_deniable(&self, skeleton: &EntrySkeleton, auth_bytes: &[u8]) -> Result<()> {
        // The deniable authenticator must carry a full composite signature; the
        // length is fixed, so a wrong length is a hard malformed-bundle error
        // (mirrors the entry decoder's composite-length guard).
        let arr: [u8; COMPOSITE_SIG_LEN] = auth_bytes
            .try_into()
            .map_err(|_| Error::MalformedBundle("deniable authenticator length"))?;
        let sig = CompositeSignature::from_bytes(&arr)?;
        // Look up the EXACT (channel_id, epoch, author_id) epk — no scan. This binds
        // the check to the entry's own epoch, so a published epoch-e key can never
        // verify content claiming a different epoch/channel (ADR-009 cross-epoch
        // forgery defense). A missing triple = not consented/released → reject.
        let key = (skeleton.channel_id, skeleton.epoch, skeleton.author_id);
        let epk = self.epks.get(&key).ok_or(Error::SignatureInvalid)?;
        epk.verify(&skeleton.signing_input(), &sig)
            .map_err(|_| Error::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;
    use crate::log::entry::ZERO_HASH;
    use crate::suite::algo;

    fn skeleton(author_id: Digest32, epoch: u64, payload: &[u8]) -> EntrySkeleton {
        EntrySkeleton {
            author_id,
            seq: 1,
            prev_hash: ZERO_HASH,
            lipmaa_backlink: ZERO_HASH,
            channel_id: [0xC1; 32],
            epoch,
            algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
            payload_hash: sha256(payload),
            payload_len: payload.len() as u64,
            end_of_feed: false,
        }
    }

    const CHANNEL: Digest32 = [0xC1; 32];

    fn member(seed: u8) -> (EphemeralSigningKey, MemberEpk, Digest32) {
        let esk = EphemeralSigningKey::from_component_seeds(&[seed; 32], &[!seed; 32]).unwrap();
        let epk = esk.epk();
        let author_id = epk.fingerprint();
        (esk, MemberEpk { author_id, epk }, author_id)
    }

    #[test]
    fn content_signed_by_epk_verifies_in_epoch() {
        let (esk, mepk, author) = member(1);
        let sk = skeleton(author, 7, b"hello deniable");
        let e = build_deniable_content(&esk, sk, b"hello deniable".to_vec()).unwrap();
        let mut v = EpochVerifier::new();
        v.release(CHANNEL, 7, &mepk).unwrap();
        assert!(v
            .verify_deniable(&e.skeleton, &e.authenticator.to_bytes())
            .is_ok());
    }

    #[test]
    fn tampered_content_rejected() {
        let (esk, mepk, author) = member(2);
        let sk = skeleton(author, 7, b"orig");
        let e = build_deniable_content(&esk, sk, b"orig".to_vec()).unwrap();
        let mut v = EpochVerifier::new();
        v.release(CHANNEL, 7, &mepk).unwrap();
        // Tamper the skeleton (changed payload_hash) → different signing input.
        let mut bad_sk = e.skeleton.clone();
        bad_sk.payload_hash = sha256(b"tampered");
        assert!(matches!(
            v.verify_deniable(&bad_sk, &e.authenticator.to_bytes()),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn unreleased_author_not_verifiable() {
        let (esk, _mepk, author) = member(3);
        let sk = skeleton(author, 7, b"x");
        let e = build_deniable_content(&esk, sk, b"x".to_vec()).unwrap();
        let v = EpochVerifier::new(); // nothing released
        assert!(matches!(
            v.verify_deniable(&e.skeleton, &e.authenticator.to_bytes()),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn per_sender_consent_releasing_a_does_not_verify_b() {
        // Release A's epk only; A's content verifies, B's does not.
        let (esk_a, mepk_a, a) = member(10);
        let (esk_b, _mepk_b, b) = member(11);
        let sk_a = skeleton(a, 7, b"from-a");
        let sk_b = skeleton(b, 7, b"from-b");
        let ea = build_deniable_content(&esk_a, sk_a, b"from-a".to_vec()).unwrap();
        let eb = build_deniable_content(&esk_b, sk_b, b"from-b".to_vec()).unwrap();
        let mut v = EpochVerifier::new();
        v.release(CHANNEL, 7, &mepk_a).unwrap();
        assert!(v
            .verify_deniable(&ea.skeleton, &ea.authenticator.to_bytes())
            .is_ok());
        assert!(v
            .verify_deniable(&eb.skeleton, &eb.authenticator.to_bytes())
            .is_err());
    }

    #[test]
    fn re_release_same_epk_idempotent_different_rejected() {
        let (_esk, mepk, _author) = member(4);
        let mut v = EpochVerifier::new();
        v.release(CHANNEL, 7, &mepk).unwrap();
        v.release(CHANNEL, 7, &mepk).unwrap(); // idempotent
                                               // A different epk under the SAME author_id (a synthesized equivocation).
        let other = EphemeralSigningKey::from_component_seeds(&[9; 32], &[8; 32]).unwrap();
        let conflicting = MemberEpk {
            author_id: mepk.author_id,
            epk: other.epk(),
        };
        assert!(matches!(
            v.release(CHANNEL, 7, &conflicting),
            Err(Error::MalformedBundle("deniable epk re-release mismatch"))
        ));
    }

    #[test]
    fn wrong_length_authenticator_rejected() {
        let (esk, mepk, author) = member(5);
        let mut v = EpochVerifier::new();
        v.release(CHANNEL, 7, &mepk).unwrap();
        let sk = skeleton(author, 7, b"x");
        let _ = esk;
        assert!(matches!(
            v.verify_deniable(&sk, &[0u8; 10]),
            Err(Error::MalformedBundle("deniable authenticator length"))
        ));
    }

    #[test]
    fn cross_epoch_forgery_rejected() {
        // [HIGH] A published epoch-N esk must NOT verify content claiming a DIFFERENT
        // epoch. We register A's epk for epoch 7 only, then present content that
        // claims epoch 8 signed by the SAME key — it must be rejected (the verifier
        // keys on the exact (channel, epoch, author), no cross-epoch scan).
        let (esk, mepk, author) = member(6);
        let mut v = EpochVerifier::new();
        v.release(CHANNEL, 7, &mepk).unwrap();
        // Content legitimately in epoch 7 verifies.
        let sk7 = skeleton(author, 7, b"epoch-7 content");
        let e7 = build_deniable_content(&esk, sk7, b"epoch-7 content".to_vec()).unwrap();
        assert!(v
            .verify_deniable(&e7.skeleton, &e7.authenticator.to_bytes())
            .is_ok());
        // The SAME key signing content that claims epoch 8 is rejected: epoch 8 has
        // no released epk for this author, so a published epoch-7 key can't forge it.
        let sk8 = skeleton(author, 8, b"epoch-8 content");
        let e8 = build_deniable_content(&esk, sk8, b"epoch-8 content".to_vec()).unwrap();
        assert!(matches!(
            v.verify_deniable(&e8.skeleton, &e8.authenticator.to_bytes()),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn cross_channel_forgery_rejected() {
        // The same defense across channels: a key released for CHANNEL must not
        // verify content claiming a different channel id.
        let (esk, mepk, author) = member(7);
        let mut v = EpochVerifier::new();
        v.release(CHANNEL, 7, &mepk).unwrap();
        let mut sk = skeleton(author, 7, b"other-channel");
        sk.channel_id = [0xC2; 32];
        let e = build_deniable_content(&esk, sk, b"other-channel".to_vec()).unwrap();
        assert!(matches!(
            v.verify_deniable(&e.skeleton, &e.authenticator.to_bytes()),
            Err(Error::SignatureInvalid)
        ));
    }
}
