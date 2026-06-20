//! The per-author sender key: the one-way symmetric chain ratchet and the
//! composite Sender-Key signing key cross-signed by the identity root
//! (ADR-006 §Decision, ADR-002 §3).
//!
//! ## The chain ratchet (Signal "Sender Keys", confirmed)
//! A sender key has a *chain key* that ratchets forward one-way, one step per
//! message. The construction is the **same keyed HMAC-SHA-256 chain KDF** the M2
//! Double Ratchet uses for its symmetric chain ([`crate::pairwise`]); ADR-006
//! mandates it explicitly ("HMAC-SHA-256-based, NOT bare SHA256"):
//!
//! ```text
//! message_key(i)  = HMAC-SHA-256(CK_i, 0x01)
//! CK_{i+1}        = HMAC-SHA-256(CK_i, 0x02)
//! ```
//!
//! This is exactly the libsignal `GroupCipher` chain: a 32-byte chain key, a
//! 31-bit chain id, and an XEdDSA signing key distributed in the
//! SenderKeyDistributionMessage (here generalized to a composite Ed25519+ML-DSA
//! signing key per ADR-002 §3 / ADR-003 hybrid-PQ). It is **one-way**: given
//! `CK_i` you can derive `message_key(j)` and `CK_j` for every `j >= i`, but you
//! cannot recover `CK_{i-1}` or any earlier message key — the basis for the
//! consent-gated history mechanism (ADR-006 §History, [`crate::group::history`]).
//!
//! Vox deliberately does **not** use the Matrix Megolm ratchet (a 4-part
//! `R0..R3` SHA-256 hierarchical ratchet advanced in `2^24/2^16/2^8` blocks):
//! the Signal keyed-HMAC chain is simpler, matches the M2 ratchet already in this
//! crate, and the fast-forward efficiency Megolm buys is unnecessary because the
//! consent/history model releases an *origin* chain key (iteration 0) rather than
//! fast-forwarding to an arbitrary point (ADR-006 §History).
//!
//! ## The Sender-Key signing key (ADR-002 §3)
//! Each member, per channel, holds a composite **Ed25519 + ML-DSA-65** signing
//! keypair *bound to `(channelID, epoch)`* and **cross-signed by the identity
//! root** so recipients tie it to the sender's identity. The cross-signature is a
//! composite root signature over the canonical tuple
//! `(channelID, epoch, author_id, chain_id, signing_pubkey)`; binding all five
//! means a signing key minted for one channel/epoch/generation cannot be replayed
//! into another (the cross-group-confusion guard, eprint 2023/1385, applied at the
//! key-authorization layer as well as at message AD).

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::group::wire::{
    sender_key_binding_input, SENDER_KEY_SIGNING_PUB_LEN, SENDER_KEY_SIGN_DOMAIN,
};
use crate::hash::Digest32;
use crate::identity::composite::{
    CompositePublicKey, CompositeSignature, RootSigner, SoftwareRootSigner,
};
use crate::identity::rng::fill_random;
use crate::suite::algo;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Length of a sender-key chain key in bytes (256-bit, libsignal-compatible).
pub const CHAIN_KEY_LEN: usize = 32;

/// HMAC chain-KDF constant deriving the per-iteration message key.
const MK_CONSTANT: u8 = 0x01;
/// HMAC chain-KDF constant advancing the chain key.
const CK_CONSTANT: u8 = 0x02;

/// `HMAC-SHA-256(key, [tag])` → 32 bytes. The only fallible path is an invalid
/// key length, which cannot occur for a fixed 32-byte key; it is surfaced as an
/// error rather than panicking (the crate bans `unwrap`/`expect`/`panic`).
fn hmac_tag(key: &[u8; CHAIN_KEY_LEN], tag: u8) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|_| Error::MalformedBundle("sender-key chain kdf"))?;
    mac.update(&[tag]);
    let out = mac.finalize().into_bytes();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out);
    Ok(k)
}

/// A sender-key chain key: 32 secret bytes that zeroize on drop, with a redacting
/// `Debug`. One-way ratchet state for a single `(author, chain_id)` generation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey([u8; CHAIN_KEY_LEN]);

impl core::fmt::Debug for ChainKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ChainKey(<redacted>)")
    }
}

/// A per-iteration message key: 32 secret bytes, zeroizing, redacting `Debug`.
/// Used once to seal/open one broadcast message, then dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey([u8; 32]);

impl core::fmt::Debug for MessageKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MessageKey(<redacted>)")
    }
}

impl MessageKey {
    /// The raw 32-byte key, for the AEAD layer ([`crate::group::message`]).
    #[must_use]
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ChainKey {
    /// Wrap explicit chain-key bytes (e.g. parsed from an SKDM, or a freshly
    /// sampled origin key). Validates only the length, which the type enforces.
    #[must_use]
    pub fn from_bytes(bytes: [u8; CHAIN_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Sample a fresh random origin chain key from the OS CSPRNG (the iteration-0
    /// key of a new generation). Returns [`Error::Rng`] if the CSPRNG fails.
    pub fn generate() -> Result<Self> {
        let mut b = [0u8; CHAIN_KEY_LEN];
        fill_random(&mut b)?;
        let ck = Self(b);
        b.zeroize();
        Ok(ck)
    }

    /// The raw chain-key bytes, for distribution inside an SKDM
    /// ([`crate::group::skdm`]). Secret material — the caller must keep it inside
    /// the encrypted pairwise envelope and never log it.
    #[must_use]
    pub(crate) fn bytes(&self) -> &[u8; CHAIN_KEY_LEN] {
        &self.0
    }

    /// Derive this iteration's message key without advancing: `HMAC(CK, 0x01)`.
    pub fn message_key(&self) -> Result<MessageKey> {
        Ok(MessageKey(hmac_tag(&self.0, MK_CONSTANT)?))
    }

    /// Advance the chain one step, returning the next chain key:
    /// `CK_{i+1} = HMAC(CK_i, 0x02)`. One-way — the previous key is unrecoverable.
    pub fn advance(&self) -> Result<ChainKey> {
        Ok(ChainKey(hmac_tag(&self.0, CK_CONSTANT)?))
    }
}

/// The composite (Ed25519 + ML-DSA-65) **Sender-Key signing key** held by a
/// member for one `(channelID, epoch, chain_id)` (ADR-002 §3, ADR-006).
///
/// It is a fresh composite keypair generated per sender key, distinct from the
/// identity root. Its public key travels in the SKDM and the root cross-signs it
/// (bound to the channel/epoch/author/generation) so recipients tie the signing
/// key — and hence every broadcast message it signs — to the sender's identity.
///
/// Reuses [`SoftwareRootSigner`] as the in-software composite signer: that type
/// *is* a composite Ed25519+ML-DSA keypair with the both-halves-must-verify
/// semantics this layer needs (it is not acting as an identity root here, only as
/// a general composite signer for the sender-key role).
pub struct SenderKeySigningKey {
    signer: SoftwareRootSigner,
}

impl core::fmt::Debug for SenderKeySigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SenderKeySigningKey")
            .finish_non_exhaustive()
    }
}

impl SenderKeySigningKey {
    /// The signature algorithm ID of this signing key (composite, `0x0304`).
    pub const ALGO_ID: u16 = algo::COMPOSITE_ED25519_ML_DSA_65;

    /// Generate a fresh composite Sender-Key signing keypair.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            signer: SoftwareRootSigner::generate()?,
        })
    }

    /// Construct deterministically from explicit component seeds (tests, vectors).
    pub fn from_component_seeds(ed_seed: &[u8; 32], ml_dsa_seed: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            signer: SoftwareRootSigner::from_component_seeds(ed_seed, ml_dsa_seed)?,
        })
    }

    /// The composite signing public key (carried in the SKDM, used to verify
    /// every broadcast message this sender key signs).
    #[must_use]
    pub fn public_key(&self) -> CompositePublicKey {
        self.signer.public_key()
    }

    /// The serialized signing public key bytes (fixed composite layout).
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; SENDER_KEY_SIGNING_PUB_LEN] {
        self.signer.public_key().to_bytes()
    }

    /// Sign a fully-prepared signing input (the caller applies domain separation,
    /// e.g. via [`crate::wire::signing_input`]) with the composite signing key.
    pub fn sign(&self, msg: &[u8]) -> Result<CompositeSignature> {
        self.signer.sign(msg)
    }
}

/// The identity root's **cross-signature** authorizing a Sender-Key signing key
/// for one `(channelID, epoch, author_id, chain_id)` (ADR-002 §3).
///
/// Computed over `SENDER_KEY_SIGN_DOMAIN ‖ canonical(channelID, epoch, author_id,
/// chain_id, signing_pubkey)`. Verifying it proves the named identity authorized
/// this signing key for exactly this channel, epoch, and generation — so a
/// signing key minted elsewhere cannot be presented here.
pub struct SenderKeyCrossSig;

impl SenderKeyCrossSig {
    /// Produce the root cross-signature binding `signing_pubkey` to
    /// `(channel_id, epoch, author_id, chain_id)`.
    pub fn sign(
        root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        author_id: &Digest32,
        chain_id: u64,
        signing_pubkey: &[u8; SENDER_KEY_SIGNING_PUB_LEN],
    ) -> Result<CompositeSignature> {
        let input =
            sender_key_binding_input(channel_id, epoch, author_id, chain_id, signing_pubkey);
        root.sign(&input)
    }

    /// Verify the root cross-signature. `author_root` is the *claimed author's*
    /// composite root public key (the verifier already trusts/pins it via the
    /// identity layer); this checks the root actually authorized `signing_pubkey`
    /// for `(channel_id, epoch, author_id, chain_id)`.
    pub fn verify(
        author_root: &CompositePublicKey,
        channel_id: &Digest32,
        epoch: u64,
        author_id: &Digest32,
        chain_id: u64,
        signing_pubkey: &[u8; SENDER_KEY_SIGNING_PUB_LEN],
        cross_sig: &CompositeSignature,
    ) -> Result<()> {
        let input =
            sender_key_binding_input(channel_id, epoch, author_id, chain_id, signing_pubkey);
        author_root.verify(&input, cross_sig)
    }

    /// The domain label used for the cross-signature (exposed for documentation
    /// and tests).
    #[must_use]
    pub const fn domain() -> &'static str {
        SENDER_KEY_SIGN_DOMAIN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_kdf_is_signal_sender_keys_hmac_construction() {
        // message_key = HMAC(CK, 0x01); next_ck = HMAC(CK, 0x02). Confirmed
        // against the Signal Sender Keys / Double Ratchet symmetric chain KDF.
        let ck = ChainKey::from_bytes([0x42; CHAIN_KEY_LEN]);
        let mk = ck.message_key().unwrap();
        let next = ck.advance().unwrap();
        assert_eq!(mk.0, hmac_tag(&[0x42; 32], 0x01).unwrap());
        assert_eq!(next.0, hmac_tag(&[0x42; 32], 0x02).unwrap());
        // The two outputs differ (distinct constants).
        assert_ne!(&mk.0[..], &next.0[..]);
        // A bare SHA-256(CK ‖ 0x01) would differ — not the construction used.
        let bare = crate::hash::sha256_concat(&[&[0x42u8; 32], &[0x01]]);
        assert_ne!(mk.0, bare);
    }

    #[test]
    fn chain_is_one_way_and_deterministic() {
        let ck0 = ChainKey::from_bytes([7u8; CHAIN_KEY_LEN]);
        let ck1 = ck0.advance().unwrap();
        let ck2 = ck1.advance().unwrap();
        // Deterministic: same start → same sequence.
        let ck0b = ChainKey::from_bytes([7u8; CHAIN_KEY_LEN]);
        assert_eq!(ck0b.advance().unwrap().0, ck1.0);
        // Each step's chain key and message key differ.
        assert_ne!(ck1.0, ck2.0);
        assert_ne!(ck0.message_key().unwrap().0, ck1.message_key().unwrap().0);
        // There is no API to recover ck0 from ck1 — one-wayness is structural
        // (HMAC preimage resistance); this test documents the intent.
    }

    #[test]
    fn generate_origin_keys_are_distinct() {
        let a = ChainKey::generate().unwrap();
        let b = ChainKey::generate().unwrap();
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn signing_key_public_is_composite_len() {
        let sk = SenderKeySigningKey::from_component_seeds(&[1u8; 32], &[2u8; 32]).unwrap();
        assert_eq!(sk.public_key_bytes().len(), SENDER_KEY_SIGNING_PUB_LEN);
        assert_eq!(
            SenderKeySigningKey::ALGO_ID,
            algo::COMPOSITE_ED25519_ML_DSA_65
        );
    }

    #[test]
    fn signing_key_signs_and_verifies() {
        let sk = SenderKeySigningKey::from_component_seeds(&[3u8; 32], &[4u8; 32]).unwrap();
        let sig = sk.sign(b"vox/test broadcast bytes").unwrap();
        assert!(sk
            .public_key()
            .verify(b"vox/test broadcast bytes", &sig)
            .is_ok());
        assert!(sk.public_key().verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn cross_sig_binds_channel_epoch_author_chain() {
        let root = SoftwareRootSigner::from_component_seeds(&[10u8; 32], &[11u8; 32]).unwrap();
        let sk = SenderKeySigningKey::from_component_seeds(&[12u8; 32], &[13u8; 32]).unwrap();
        let cid = [0xAAu8; 32];
        let author = root.public_key().fingerprint();
        let spk = sk.public_key_bytes();

        let xsig = SenderKeyCrossSig::sign(&root, &cid, 5, &author, 0, &spk).unwrap();
        assert!(
            SenderKeyCrossSig::verify(&root.public_key(), &cid, 5, &author, 0, &spk, &xsig).is_ok()
        );

        // Wrong epoch → reject.
        assert!(
            SenderKeyCrossSig::verify(&root.public_key(), &cid, 6, &author, 0, &spk, &xsig)
                .is_err()
        );
        // Wrong channel → reject.
        let other_cid = [0xBBu8; 32];
        assert!(SenderKeyCrossSig::verify(
            &root.public_key(),
            &other_cid,
            5,
            &author,
            0,
            &spk,
            &xsig
        )
        .is_err());
        // Wrong chain_id → reject.
        assert!(
            SenderKeyCrossSig::verify(&root.public_key(), &cid, 5, &author, 1, &spk, &xsig)
                .is_err()
        );
    }

    #[test]
    fn cross_sig_forged_by_other_root_rejected() {
        let root = SoftwareRootSigner::from_component_seeds(&[20u8; 32], &[21u8; 32]).unwrap();
        let attacker = SoftwareRootSigner::from_component_seeds(&[99u8; 32], &[98u8; 32]).unwrap();
        let sk = SenderKeySigningKey::from_component_seeds(&[22u8; 32], &[23u8; 32]).unwrap();
        let cid = [1u8; 32];
        let author = root.public_key().fingerprint();
        let spk = sk.public_key_bytes();

        // Attacker signs a binding for the honest author_id; verifying against the
        // honest root must fail (the attacker is not that root).
        let forged = SenderKeyCrossSig::sign(&attacker, &cid, 0, &author, 0, &spk).unwrap();
        assert!(
            SenderKeyCrossSig::verify(&root.public_key(), &cid, 0, &author, 0, &spk, &forged)
                .is_err()
        );
    }
}
