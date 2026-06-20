//! The Sender-Key Distribution Message (SKDM) — ADR-006 §Wire, tag `0x0002`,
//! domain `vox/skdm/v1`.
//!
//! An SKDM hands one recipient *identity* the material to read a sender's
//! broadcast chain: the chain key at a named `iteration`, the chain generation
//! `chain_id`, and the composite Sender-Key signing public key (so the recipient
//! can verify every message that key signs). It is **signed by the sender's
//! composite identity root**, which simultaneously (a) authenticates the whole
//! distribution and (b) cross-signs the signing key, binding it to the author's
//! identity and to `(channelID, epoch, chain_id)` — exactly the cross-signature
//! ADR-002 §3 requires.
//!
//! ## Fields (ADR-006 §Wire, exact order)
//! `{ channelID, epoch, author_id, chain_id, iteration, chain_key,
//!    signing_pubkey, algo_ids, signature }`, encoded as a canonical-CBOR array
//! (ADR-008). `algo_ids` is the 2-element array `[sign_algo, aead_algo]` pinning
//! the signature class (composite `0x0304`) and the broadcast AEAD class
//! (AES-256-GCM `0x0401`) so neither can be reinterpreted (ADR-003 requirement 1).
//!
//! ## Delivery (ADR-006 §Decision — no redundant KEM)
//! The SKDM is **wrapped as an ordinary M2 Double-Ratchet message inside an
//! already-established pairwise session** ([`crate::pairwise::Session`]). It
//! inherits that session's hybrid AEAD and the ML-KEM secret PQXDH already mixed
//! in; there is **no separate per-SKDM KEM step** (ADR-006 forbids building a
//! redundant KEM layer). [`Skdm::seal_into`] and [`Skdm::open_from`] are the
//! convenience seam over `Session::encrypt`/`decrypt`.
//!
//! ## (channelID, epoch) binding
//! `channelID` and `epoch` are inside the signed body, so an SKDM minted for
//! channel G / epoch E cannot be presented as one for channel H / epoch E'
//! (cross-group confusion, eprint 2023/1385). The recipient additionally rejects
//! any SKDM whose `(channelID, epoch)` ≠ the channel it processes ([`Skdm::verify`]).

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::group::senderkey::{ChainKey, CHAIN_KEY_LEN};
use crate::group::wire::SENDER_KEY_SIGNING_PUB_LEN;
use crate::hash::Digest32;
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::pairwise::{Message, Session};
use crate::suite::{algo, validate_algo};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// The unsigned SKDM body — every field except the signature (ADR-006 §Wire).
/// Held separately so [`SkdmBody::signing_input`] is the exact bytes the root
/// signs and the recipient verifies.
#[derive(Clone)]
pub struct SkdmBody {
    /// The 32-byte channel identifier (ADR-005).
    pub channel_id: Digest32,
    /// The membership epoch (passphrase-rotation generation, ADR-007).
    pub epoch: u64,
    /// The author's identity fingerprint (ADR-002 `SHA-256(Ed25519 ‖ ML-DSA)`).
    pub author_id: Digest32,
    /// The per-sender generation id, distinct from `epoch`, incremented on every
    /// sender-key rotation (ADR-006).
    pub chain_id: u64,
    /// The iteration at which `chain_key` sits (the recipient can derive this and
    /// every later message key, never an earlier one).
    pub iteration: u64,
    /// The chain key at `iteration` (secret; only ever on the wire inside the
    /// encrypted pairwise envelope).
    pub chain_key: ChainKey,
    /// The composite Sender-Key signing public key (ADR-002 §3).
    pub signing_pubkey: [u8; SENDER_KEY_SIGNING_PUB_LEN],
    /// `[sign_algo, aead_algo]` — the composite signature class and broadcast
    /// AEAD class in force (ADR-003 algorithm IDs).
    pub algo_ids: [u16; 2],
}

impl core::fmt::Debug for SkdmBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render the chain key bytes.
        f.debug_struct("SkdmBody")
            .field("channel_id", &crate::hash::Hex(&self.channel_id))
            .field("epoch", &self.epoch)
            .field("author_id", &crate::hash::Hex(&self.author_id))
            .field("chain_id", &self.chain_id)
            .field("iteration", &self.iteration)
            .field("chain_key", &self.chain_key)
            .finish_non_exhaustive()
    }
}

impl SkdmBody {
    /// Canonical-CBOR body in the ADR-006 field order
    /// `[channelID, epoch, author_id, chain_id, iteration, chain_key,
    ///   signing_pubkey, [sign_algo, aead_algo]]` (the signature is appended by
    /// the framed [`Skdm`], never inside its own signing input).
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(8)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.author_id)
            .uint(self.chain_id)
            .uint(self.iteration)
            .bytes(self.chain_key.bytes())
            .bytes(&self.signing_pubkey)
            .array(2)
            .uint(u64::from(self.algo_ids[0]))
            .uint(u64::from(self.algo_ids[1]));
        e.finish()
    }

    /// The signing input: `vox/skdm/v1 ‖ canonical_body` (ADR-008 framing).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::Skdm, &self.canonical_body())
    }

    /// Decode an SKDM body from its canonical bytes, validating arity, the
    /// algo-id registry membership, and the two algorithm classes (ADR-003
    /// type-confusion guard: `sign_algo` must be a signature, `aead_algo` an AEAD).
    fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 8 {
            return Err(Error::MalformedBundle("skdm arity"));
        }
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        let author_id = take_digest(&mut d)?;
        let chain_id = d.uint()?;
        let iteration = d.uint()?;
        let ck_bytes: [u8; CHAIN_KEY_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("skdm chain-key length"))?;
        let signing_pubkey: [u8; SENDER_KEY_SIGNING_PUB_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("skdm signing-pubkey length"))?;
        if d.array()? != 2 {
            return Err(Error::MalformedBundle("skdm algo_ids arity"));
        }
        let sign_algo = u16_from(d.uint()?)?;
        let aead_algo = u16_from(d.uint()?)?;
        d.finish()?;

        // Registry + class checks: the signature slot must hold a signature algo
        // and the AEAD slot an AEAD algo, so neither can be parsed as the other.
        validate_algo(sign_algo)?;
        validate_algo(aead_algo)?;
        if sign_algo != algo::COMPOSITE_ED25519_ML_DSA_65 {
            return Err(Error::UnexpectedAlgo {
                got: sign_algo,
                expected: algo::COMPOSITE_ED25519_ML_DSA_65,
            });
        }
        if aead_algo != algo::AES_256_GCM {
            return Err(Error::UnexpectedAlgo {
                got: aead_algo,
                expected: algo::AES_256_GCM,
            });
        }

        Ok(Self {
            channel_id,
            epoch,
            author_id,
            chain_id,
            iteration,
            chain_key: ChainKey::from_bytes(ck_bytes),
            signing_pubkey,
            algo_ids: [sign_algo, aead_algo],
        })
    }
}

/// A complete, root-signed SKDM: the body plus the composite identity-root
/// signature over [`SkdmBody::signing_input`] (ADR-006 §Wire `signature` field).
pub struct Skdm {
    /// The signed body.
    pub body: SkdmBody,
    /// The composite identity-root signature (binds the whole distribution — and
    /// thus the signing key — to the author's identity, ADR-002 §3).
    pub signature: CompositeSignature,
}

impl core::fmt::Debug for Skdm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Skdm")
            .field("body", &self.body)
            .finish_non_exhaustive()
    }
}

impl Skdm {
    /// Build and root-sign an SKDM that releases `chain_key` at `iteration` for
    /// `(channel_id, epoch, chain_id)` to a recipient identity.
    ///
    /// `author_root` is the sender's identity root; `author_id` MUST be its
    /// fingerprint (the build enforces this so the signed `author_id` always
    /// matches the signer). `signing_pubkey` is the composite Sender-Key signing
    /// public key the recipient will use to verify broadcast messages.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        author_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        chain_id: u64,
        iteration: u64,
        chain_key: ChainKey,
        signing_pubkey: [u8; SENDER_KEY_SIGNING_PUB_LEN],
    ) -> Result<Self> {
        let body = SkdmBody {
            channel_id: *channel_id,
            epoch,
            author_id: author_root.fingerprint(),
            chain_id,
            iteration,
            chain_key,
            signing_pubkey,
            algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
        };
        let signature = author_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// The 9-field canonical CBOR body: the 8 signed fields plus the composite
    /// root signature as the 9th element (ADR-006 §Wire). Framed by [`Skdm::to_wire`].
    #[must_use]
    fn wire_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(9)
            .bytes(&self.body.channel_id)
            .uint(self.body.epoch)
            .bytes(&self.body.author_id)
            .uint(self.body.chain_id)
            .uint(self.body.iteration)
            .bytes(self.body.chain_key.bytes())
            .bytes(&self.body.signing_pubkey)
            .array(2)
            .uint(u64::from(self.body.algo_ids[0]))
            .uint(u64::from(self.body.algo_ids[1]));
        e.bytes(&self.signature.to_bytes());
        e.finish()
    }

    /// The framed wire bytes per ADR-008: `tag(2 BE) ‖ version(1) ‖
    /// canonical_cbor_9field_body` (tag [`StructTag::Skdm`] = `0x0002`, version
    /// `0x01`). The `vox/skdm/v1` domain label is the *signing* input prefix
    /// ([`SkdmBody::signing_input`]), **not** the wire frame — transmitted structs
    /// carry the struct-tag frame, never the signing label (ADR-008 §Struct
    /// framing). The root signature still covers the 8-field signing input.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        frame(StructTag::Skdm, &self.wire_body())
    }

    /// Parse a framed SKDM from the wire, rejecting a wrong/unknown struct tag,
    /// unsupported version, arity, or malformed algorithm/signature fields. Does
    /// NOT verify the signature — call [`Skdm::verify`] for that.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::Skdm {
            return Err(Error::MalformedBundle("skdm wrong struct tag"));
        }
        // `parse_frame` already enforced version == FORMAT_VERSION.
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 9 {
            return Err(Error::MalformedBundle("skdm wire arity"));
        }
        // Re-encode the first 8 elements into a body-only canonical buffer so the
        // signing input is reconstructed exactly, then parse it through the strict
        // body decoder (which enforces the algo classes).
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        let author_id = take_digest(&mut d)?;
        let chain_id = d.uint()?;
        let iteration = d.uint()?;
        let chain_key = d.bytes()?.to_vec();
        let signing_pubkey = d.bytes()?.to_vec();
        if d.array()? != 2 {
            return Err(Error::MalformedBundle("skdm algo_ids arity"));
        }
        let sign_algo = d.uint()?;
        let aead_algo = d.uint()?;
        let sig_bytes = d.bytes()?.to_vec();
        d.finish()?;

        // Rebuild the 8-field body bytes and decode strictly (class checks etc.).
        let mut be = Encoder::new();
        be.array(8)
            .bytes(&channel_id)
            .uint(epoch)
            .bytes(&author_id)
            .uint(chain_id)
            .uint(iteration)
            .bytes(&chain_key)
            .bytes(&signing_pubkey)
            .array(2)
            .uint(sign_algo)
            .uint(aead_algo);
        let body = SkdmBody::from_canonical_body(&be.finish())?;

        let sig_arr: [u8; crate::hash::COMPOSITE_SIG_LEN] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::MalformedBundle("skdm signature length"))?;
        let signature = CompositeSignature::from_bytes(&sig_arr)?;
        Ok(Self { body, signature })
    }

    /// Verify the root signature and the `(channelID, epoch)` binding.
    ///
    /// `author_root` is the *claimed author's* composite root public key (trusted
    /// via the identity layer). The check passes only if (a) `author_root`'s
    /// fingerprint equals the SKDM's `author_id` (so the signer is who it claims),
    /// (b) the composite signature verifies, and (c) `(channelID, epoch)` matches
    /// `expected_channel`/`expected_epoch`. Any mismatch is a hard failure.
    pub fn verify(
        &self,
        author_root: &CompositePublicKey,
        expected_channel: &Digest32,
        expected_epoch: u64,
    ) -> Result<()> {
        if &self.body.channel_id != expected_channel || self.body.epoch != expected_epoch {
            return Err(Error::MalformedBundle("skdm (channelID, epoch) mismatch"));
        }
        if author_root.fingerprint() != self.body.author_id {
            return Err(Error::MalformedBundle("skdm author_id != root fingerprint"));
        }
        author_root.verify(&self.body.signing_input(), &self.signature)
    }

    /// Verify, then return the parsed Sender-Key signing public key for use in
    /// broadcast-message verification. Convenience over [`Skdm::verify`].
    pub fn verify_and_signing_key(
        &self,
        author_root: &CompositePublicKey,
        expected_channel: &Digest32,
        expected_epoch: u64,
    ) -> Result<CompositePublicKey> {
        self.verify(author_root, expected_channel, expected_epoch)?;
        CompositePublicKey::from_bytes(&self.body.signing_pubkey)
    }

    /// Wrap this SKDM as an M2 Double-Ratchet message and encrypt it into an
    /// established pairwise `session` (ADR-006 §Decision — no redundant KEM).
    pub fn seal_into(&self, session: &mut Session) -> Result<Message> {
        session.encrypt(&self.to_wire())
    }

    /// Decrypt an inbound M2 message carrying an SKDM and parse it (still
    /// unverified — the caller verifies against the author's root).
    pub fn open_from(session: &mut Session, message: &Message, now: u64) -> Result<Self> {
        let plaintext = session.decrypt(message, now)?;
        Self::from_wire(&plaintext)
    }
}

/// Take a 32-byte digest from the decoder, rejecting a wrong length.
fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle("skdm digest length"))
}

/// Narrow a CBOR `u64` to `u16`, rejecting out-of-range algorithm IDs.
fn u16_from(v: u64) -> Result<u16> {
    u16::try_from(v).map_err(|_| Error::MalformedBundle("skdm algo id out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;

    fn root(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    fn sample_skdm(r: &SoftwareRootSigner, cid: &Digest32, epoch: u64, chain_id: u64) -> Skdm {
        let spk = [0x5au8; SENDER_KEY_SIGNING_PUB_LEN];
        Skdm::build(
            r,
            cid,
            epoch,
            chain_id,
            0,
            ChainKey::from_bytes([0x11; CHAIN_KEY_LEN]),
            spk,
        )
        .unwrap()
    }

    #[test]
    fn skdm_wire_round_trips() {
        let r = root(1, 2);
        let cid = [9u8; 32];
        let s = sample_skdm(&r, &cid, 3, 0);
        let decoded = Skdm::from_wire(&s.to_wire()).unwrap();
        assert_eq!(decoded.body.channel_id, cid);
        assert_eq!(decoded.body.epoch, 3);
        assert_eq!(decoded.body.author_id, r.public_key().fingerprint());
        assert_eq!(decoded.body.chain_key.bytes(), &[0x11; CHAIN_KEY_LEN]);
        assert!(decoded.verify(&r.public_key(), &cid, 3).is_ok());
    }

    #[test]
    fn skdm_wire_is_adr008_framed() {
        // ADR-008 §Struct framing: tag(2 BE) ‖ version(1) ‖ cbor_body — for SKDM,
        // 0x00 0x02 (tag 0x0002) then 0x01 (FORMAT_VERSION). NOT the signing label.
        let r = root(1, 2);
        let wire = sample_skdm(&r, &[9u8; 32], 3, 0).to_wire();
        assert_eq!(&wire[..3], &[0x00, 0x02, 0x01]);
        assert!(!wire.starts_with(StructTag::Skdm.domain_sep().as_bytes()));
    }

    #[test]
    fn skdm_from_wire_rejects_bad_frames() {
        let r = root(1, 2);
        let wire = sample_skdm(&r, &[9u8; 32], 3, 0).to_wire();
        // Wrong (but valid) struct tag: re-frame body under LogEntry (0x0001).
        let reframed = crate::wire::frame(StructTag::LogEntry, &wire[3..]);
        assert!(matches!(
            Skdm::from_wire(&reframed),
            Err(Error::MalformedBundle("skdm wrong struct tag"))
        ));
        // Bad version byte.
        let mut bad_ver = wire.clone();
        bad_ver[2] = 0xff;
        assert!(matches!(
            Skdm::from_wire(&bad_ver),
            Err(Error::UnsupportedVersion { .. })
        ));
        // Unknown tag (0x9902 — not registered).
        let mut bad_tag = wire.clone();
        bad_tag[0] = 0x99;
        bad_tag[1] = 0x02;
        assert!(Skdm::from_wire(&bad_tag).is_err());
    }

    #[test]
    fn tampered_signature_rejected() {
        let r = root(1, 2);
        let cid = [9u8; 32];
        let mut s = sample_skdm(&r, &cid, 3, 0);
        // Flip a bit in the signature.
        let mut raw = s.signature.to_bytes();
        raw[0] ^= 0x01;
        s.signature = CompositeSignature::from_bytes(&raw).unwrap();
        assert!(s.verify(&r.public_key(), &cid, 3).is_err());
    }

    #[test]
    fn tampered_body_rejected() {
        let r = root(1, 2);
        let cid = [9u8; 32];
        let s = sample_skdm(&r, &cid, 3, 0);
        let mut decoded = Skdm::from_wire(&s.to_wire()).unwrap();
        // Mutate a field after parse; the original signature no longer covers it.
        decoded.body.iteration = 999;
        assert!(decoded.verify(&r.public_key(), &cid, 3).is_err());
    }

    #[test]
    fn wrong_channel_or_epoch_rejected() {
        let r = root(1, 2);
        let cid = [9u8; 32];
        let s = sample_skdm(&r, &cid, 3, 0);
        // Right signature, wrong expected channel/epoch.
        assert!(s.verify(&r.public_key(), &[8u8; 32], 3).is_err());
        assert!(s.verify(&r.public_key(), &cid, 4).is_err());
    }

    #[test]
    fn author_id_must_match_signer() {
        let r = root(1, 2);
        let other = root(5, 6);
        let cid = [9u8; 32];
        let s = sample_skdm(&r, &cid, 3, 0);
        // Verifying against a different root fails (fingerprint mismatch).
        assert!(s.verify(&other.public_key(), &cid, 3).is_err());
    }

    #[test]
    fn rejects_non_composite_sign_algo() {
        // Hand-build a body with a bad sign algo and confirm the strict decoder
        // rejects it (class/type guard).
        let mut be = Encoder::new();
        be.array(8)
            .bytes(&[0u8; 32])
            .uint(0)
            .bytes(&[0u8; 32])
            .uint(0)
            .uint(0)
            .bytes(&[0u8; CHAIN_KEY_LEN])
            .bytes(&[0u8; SENDER_KEY_SIGNING_PUB_LEN])
            .array(2)
            .uint(u64::from(algo::ED25519)) // not the composite signer
            .uint(u64::from(algo::AES_256_GCM));
        assert!(matches!(
            SkdmBody::from_canonical_body(&be.finish()),
            Err(Error::UnexpectedAlgo { .. })
        ));
    }
}
