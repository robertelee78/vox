//! The personal self-channel (ADR-008 §"Personal self-channel", tag `0x000C`,
//! domain `vox/self-channel-entry/v1`).
//!
//! A user's own shared-root devices (ADR-002) share state through a
//! **single-author self-log**: a log authored by the user's identity, keyed by a
//! dedicated random `self_seed` (M1). Both the encryption key and the rendezvous
//! derive from this **private** seed — never from a signature over a public
//! constant (a signing oracle could reproduce it) and never from the *public*
//! identity key (which would make the rendezvous locatable by anyone):
//! - `K_self        = HKDF-SHA-256(self_seed, info = "vox/self-channel/v1")`
//! - `rendezvous_self = HKDF-SHA-256(self_seed, info = "vox/self-rzv/v1")`
//!
//! The self-channel carries — load-bearing — **the SKDMs the identity has been
//! consent-granted** (ADR-006/M4), local nicknames + verification state, and
//! per-channel join material, so adding or restoring a shared-root device needs
//! no re-consent. It is replicated **only among that identity's own devices**.
//!
//! ## What M5 owns
//! The two KDFs, the self-channel entry type (a self-log payload), and the
//! single-author self-log built on [`crate::log::feed`]. The multi-device
//! *transport* (sibling discovery at `rendezvous_self`, PoP-to-peer) is M9
//! (ADR-011); per-device-key users hold no self-channel (no shared root), which
//! is not a special case here — they simply never construct one.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_SIG_LEN, DIGEST_LEN};
use crate::identity::backup::{SelfSeed, SELF_SEED_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// HKDF-SHA-256 `info` for the self-channel content key `K_self`.
pub const INFO_K_SELF: &[u8] = b"vox/self-channel/v1";
/// HKDF-SHA-256 `info` for the self-channel rendezvous `rendezvous_self`.
pub const INFO_RENDEZVOUS_SELF: &[u8] = b"vox/self-rzv/v1";

/// Length of the derived self-channel content key (256-bit AEAD key material).
pub const K_SELF_LEN: usize = 32;
/// Length of the derived self-channel rendezvous value (32 bytes, ADR-012 form).
pub const RENDEZVOUS_SELF_LEN: usize = DIGEST_LEN;

/// The self-channel content key `K_self = HKDF-SHA-256(self_seed,
/// info="vox/self-channel/v1")`. Zeroizes on drop; never logged.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KSelf([u8; K_SELF_LEN]);

impl KSelf {
    /// The raw key bytes (secret; for the self-log AEAD in M4/M8).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; K_SELF_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for KSelf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KSelf(<redacted>)")
    }
}

/// Derive the self-channel content key `K_self` from the private `self_seed`.
///
/// HKDF-SHA-256 with no salt (the seed is already a uniform 256-bit secret) and
/// `info = "vox/self-channel/v1"`. The dependency on the *private* seed (not the
/// public key, not a signature over a constant) is the ADR-008 security property:
/// only a holder of the seed — i.e. one of the identity's own devices — can
/// derive it.
#[must_use]
pub fn derive_k_self(self_seed: &SelfSeed) -> KSelf {
    let mut okm = [0u8; K_SELF_LEN];
    hkdf_expand(self_seed.as_bytes(), INFO_K_SELF, &mut okm);
    let k = KSelf(okm);
    okm.zeroize();
    k
}

/// Derive the self-channel rendezvous `rendezvous_self` from the private
/// `self_seed` (ADR-008; the ADR-005 rendezvous construction seeded by the
/// private seed). This is a *public* locator value used to find sibling devices,
/// but because it derives from the private seed it is unlinkable to the identity
/// by anyone who does not hold the seed.
#[must_use]
pub fn derive_rendezvous_self(self_seed: &SelfSeed) -> [u8; RENDEZVOUS_SELF_LEN] {
    let mut out = [0u8; RENDEZVOUS_SELF_LEN];
    hkdf_expand(self_seed.as_bytes(), INFO_RENDEZVOUS_SELF, &mut out);
    out
}

/// HKDF-SHA-256 expand with an empty salt over `ikm`, writing `okm.len()` bytes.
/// Used for both self-channel derivations so they share one KDF (and differ only
/// by `info`).
fn hkdf_expand(ikm: &[u8; SELF_SEED_LEN], info: &[u8], okm: &mut [u8]) {
    use hkdf::Hkdf;
    use sha2::Sha256;
    // Extract with no salt: the seed is already a high-entropy uniform secret.
    let hk = Hkdf::<Sha256>::new(None, ikm);
    // `expand` only errors if the output length exceeds 255*HashLen (8160 B for
    // SHA-256); our outputs are 32 B, so this is unreachable, but we still avoid
    // a panic by zero-filling on the impossible error rather than unwrapping.
    if hk.expand(info, okm).is_err() {
        okm.fill(0);
    }
}

/// The kind of self-channel entry payload (ADR-008). The self-channel multiplexes
/// the several state classes the device set must share; the discriminant lets a
/// receiving device route each entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum SelfEntryKind {
    /// A consent-granted SKDM (ADR-006/M4) the identity received — syncing it
    /// lets every shared-root device read what was consented to the identity,
    /// so adding/restoring a device needs no re-consent (the load-bearing case).
    ReceivedSkdm = 1,
    /// A local nickname / verification-state record for a peer.
    NicknameState = 2,
    /// Per-channel join material (channelID + epoch + opaque join blob).
    JoinMaterial = 3,
}

impl SelfEntryKind {
    /// The 1-byte discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Resolve from the discriminant byte.
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(SelfEntryKind::ReceivedSkdm),
            2 => Ok(SelfEntryKind::NicknameState),
            3 => Ok(SelfEntryKind::JoinMaterial),
            _ => Err(Error::MalformedBundle("self-channel entry kind")),
        }
    }
}

/// A self-channel entry payload (ADR-008 tag `0x000C`): a discriminated record
/// the self-log carries. The `data` bytes are the kind-specific body — for
/// [`SelfEntryKind::ReceivedSkdm`] they are the framed SKDM wire bytes
/// ([`crate::group::skdm::Skdm::to_wire`]); the self-log does not re-interpret
/// them beyond round-tripping, so the SKDM stays exactly as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfChannelEntry {
    /// The record class.
    pub kind: SelfEntryKind,
    /// The kind-specific body (opaque to the self-log).
    pub data: Vec<u8>,
}

impl SelfChannelEntry {
    /// Wrap received SKDM wire bytes as a self-channel entry.
    #[must_use]
    pub fn received_skdm(skdm_wire: Vec<u8>) -> Self {
        Self {
            kind: SelfEntryKind::ReceivedSkdm,
            data: skdm_wire,
        }
    }

    /// Canonical-CBOR body: a 2-element array `[kind_u8, data]` (ADR-008 array
    /// form). This is the *payload* a self-log [`crate::log::entry::Entry`]
    /// commits to via its `payload_hash`; the entry itself carries the tag
    /// `0x000C` framing and the composite self-signature.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2)
            .uint(u64::from(self.kind.as_u8()))
            .bytes(&self.data);
        e.finish()
    }

    /// Decode from the canonical body produced by [`Self::canonical_body`].
    pub fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 2 {
            return Err(Error::MalformedBundle("self-channel entry arity"));
        }
        let kind_u8 = u8::try_from(d.uint()?)
            .map_err(|_| Error::MalformedBundle("self-channel entry kind range"))?;
        let kind = SelfEntryKind::from_u8(kind_u8)?;
        let data = d.bytes()?.to_vec();
        d.finish()?;
        Ok(Self { kind, data })
    }

    /// The signing input for this entry: `vox/self-channel-entry/v1 ‖
    /// canonical_body` (ADR-008 tag `0x000C` domain label). The identity root
    /// signs this so a sibling device can verify the entry is genuinely authored
    /// by the shared identity (the self-channel is single-author).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::SelfChannelEntry, &self.canonical_body())
    }
}

/// A complete, identity-root-signed self-channel entry: the `[kind, data]` body
/// plus the composite signature over its [`SelfChannelEntry::signing_input`].
///
/// Framed on the wire with the ADR-008 struct tag `0x000C`
/// ([`StructTag::SelfChannelEntry`]) and authenticated under the domain
/// `vox/self-channel-entry/v1`. This is the first-class signed struct a device
/// publishes to its own self-log; when carried *inside* a log
/// [`crate::log::entry::Entry`]'s
/// payload, the inner entry's `payload_hash` additionally binds it, but the
/// self-channel-entry is independently verifiable via its own signature.
pub struct SignedSelfChannelEntry {
    /// The `[kind, data]` body.
    pub entry: SelfChannelEntry,
    /// The composite identity-root signature over [`SelfChannelEntry::signing_input`].
    pub signature: CompositeSignature,
}

impl core::fmt::Debug for SignedSelfChannelEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedSelfChannelEntry")
            .field("entry", &self.entry)
            .finish_non_exhaustive()
    }
}

impl SignedSelfChannelEntry {
    /// Sign `entry` with the identity `root` (the self-channel is single-author —
    /// the signer is the identity itself).
    pub fn sign(root: &dyn RootSigner, entry: SelfChannelEntry) -> Result<Self> {
        let signature = root.sign(&entry.signing_input())?;
        Ok(Self { entry, signature })
    }

    /// Verify the signature against the identity's composite root public key.
    pub fn verify(&self, root: &CompositePublicKey) -> Result<()> {
        root.verify(&self.entry.signing_input(), &self.signature)
    }

    /// Frame for the wire/storage per ADR-008: `tag(00 0C) ‖ version(01) ‖
    /// cbor[kind, data, signature]`.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3)
            .uint(u64::from(self.entry.kind.as_u8()))
            .bytes(&self.entry.data)
            .bytes(&self.signature.to_bytes());
        frame(StructTag::SelfChannelEntry, &e.finish())
    }

    /// Parse a framed signed self-channel entry, rejecting a wrong/unknown struct
    /// tag, unsupported version, arity, or malformed signature. Does NOT verify
    /// the signature — call [`SignedSelfChannelEntry::verify`].
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::SelfChannelEntry {
            return Err(Error::MalformedBundle("self-channel wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 3 {
            return Err(Error::MalformedBundle("self-channel wire arity"));
        }
        let kind_u8 = u8::try_from(d.uint()?)
            .map_err(|_| Error::MalformedBundle("self-channel entry kind range"))?;
        let kind = SelfEntryKind::from_u8(kind_u8)?;
        let data = d.bytes()?.to_vec();
        let sig_bytes: [u8; COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("self-channel signature length"))?;
        d.finish()?;
        let signature = CompositeSignature::from_bytes(&sig_bytes)?;
        Ok(Self {
            entry: SelfChannelEntry { kind, data },
            signature,
        })
    }
}

/// The self-channel identifier: a 32-byte channel id for the single-author
/// self-log, derived deterministically from the `self_seed` so every one of the
/// identity's devices computes the same id. Distinct `info` from `K_self` and
/// `rendezvous_self` so it is independent of both.
#[must_use]
pub fn self_channel_id(self_seed: &SelfSeed) -> Digest32 {
    let mut out = [0u8; DIGEST_LEN];
    hkdf_expand(self_seed.as_bytes(), b"vox/self-channel-id/v1", &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(b: u8) -> SelfSeed {
        SelfSeed::from_bytes([b; SELF_SEED_LEN])
    }

    #[test]
    fn kdfs_are_deterministic_from_seed() {
        let s = seed(0x42);
        let k1 = derive_k_self(&s);
        let k2 = derive_k_self(&s);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
        let r1 = derive_rendezvous_self(&s);
        let r2 = derive_rendezvous_self(&s);
        assert_eq!(r1, r2);
    }

    #[test]
    fn kdfs_differ_by_info() {
        // K_self and rendezvous_self derive from the same seed but different info,
        // so they must not collide (ADR-008 domain separation).
        let s = seed(0x07);
        let k = derive_k_self(&s);
        let r = derive_rendezvous_self(&s);
        assert_ne!(&k.as_bytes()[..], &r[..]);
        // And the channel id is independent of both.
        let cid = self_channel_id(&s);
        assert_ne!(&cid[..], &k.as_bytes()[..]);
        assert_ne!(cid, r);
    }

    #[test]
    fn different_seeds_yield_different_keys() {
        let a = derive_k_self(&seed(1));
        let b = derive_k_self(&seed(2));
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(
            derive_rendezvous_self(&seed(1)),
            derive_rendezvous_self(&seed(2))
        );
    }

    #[test]
    fn k_self_debug_is_redacted() {
        let k = derive_k_self(&seed(0xAB));
        let dbg = format!("{k:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("ab"));
    }

    #[test]
    fn self_entry_round_trips() {
        let e = SelfChannelEntry::received_skdm(vec![0x00, 0x02, 0x01, 0xde, 0xad]);
        let body = e.canonical_body();
        let back = SelfChannelEntry::from_canonical_body(&body).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.kind, SelfEntryKind::ReceivedSkdm);
    }

    #[test]
    fn self_entry_rejects_unknown_kind() {
        let mut enc = Encoder::new();
        enc.array(2).uint(99).bytes(&[1, 2, 3]);
        assert!(matches!(
            SelfChannelEntry::from_canonical_body(&enc.finish()),
            Err(Error::MalformedBundle("self-channel entry kind"))
        ));
    }

    #[test]
    fn self_log_carries_received_skdm_via_feed() {
        // The self-log is a single-author feed; a received-SKDM entry round-trips
        // through it carrying the exact SKDM wire bytes (no re-interpretation).
        use crate::hash::sha256;
        use crate::identity::composite::{RootSigner, SoftwareRootSigner};
        use crate::log::entry::{Entry, EntrySkeleton, ZERO_HASH};
        use crate::log::feed::Feed;
        use crate::suite::algo;

        let r = SoftwareRootSigner::from_component_seeds(&[3; 32], &[4; 32]).unwrap();
        let s = seed(0x55);
        let cid = self_channel_id(&s);

        // A fake received SKDM payload (opaque bytes that begin with the SKDM tag).
        let skdm_wire = vec![0x00, 0x02, 0x01, 0xAB, 0xCD, 0xEF];
        let payload = SelfChannelEntry::received_skdm(skdm_wire.clone()).canonical_body();

        let sk = EntrySkeleton {
            author_id: r.fingerprint(),
            seq: 1,
            prev_hash: ZERO_HASH,
            lipmaa_backlink: ZERO_HASH,
            channel_id: cid,
            epoch: 0,
            algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
            payload_hash: sha256(&payload),
            payload_len: payload.len() as u64,
            end_of_feed: false,
        };
        let entry = Entry::build_signed(&r, sk, payload).unwrap();

        let mut feed = Feed::new();
        feed.append_verified(entry, &r.public_key()).unwrap();
        feed.verify().unwrap();

        // Recover the SKDM bytes from the stored self-log entry.
        let stored = feed.get(1).unwrap();
        let body = stored.payload.as_ref().unwrap();
        let parsed = SelfChannelEntry::from_canonical_body(body).unwrap();
        assert_eq!(parsed.kind, SelfEntryKind::ReceivedSkdm);
        assert_eq!(parsed.data, skdm_wire);
    }

    #[test]
    fn signed_self_channel_entry_is_tag_000c_framed_and_verifies() {
        use crate::identity::composite::{RootSigner, SoftwareRootSigner};

        let r = SoftwareRootSigner::from_component_seeds(&[7; 32], &[8; 32]).unwrap();
        let entry = SelfChannelEntry::received_skdm(vec![0x00, 0x02, 0x01, 0x99]);
        let signed = SignedSelfChannelEntry::sign(&r, entry.clone()).unwrap();

        let wire = signed.to_wire();
        // ADR-008 framing: tag 0x000C, version 0x01.
        assert_eq!(&wire[..3], &[0x00, 0x0C, 0x01]);

        let decoded = SignedSelfChannelEntry::from_wire(&wire).unwrap();
        assert_eq!(decoded.entry, entry);
        decoded.verify(&r.public_key()).unwrap();
    }

    #[test]
    fn signed_self_channel_entry_rejects_tamper_and_wrong_tag() {
        use crate::identity::composite::{RootSigner, SoftwareRootSigner};

        let r = SoftwareRootSigner::from_component_seeds(&[3; 32], &[4; 32]).unwrap();
        let signed =
            SignedSelfChannelEntry::sign(&r, SelfChannelEntry::received_skdm(vec![1, 2, 3]))
                .unwrap();
        // Tampered body fails verification.
        let mut decoded = SignedSelfChannelEntry::from_wire(&signed.to_wire()).unwrap();
        decoded.entry.data.push(0xFF);
        assert!(decoded.verify(&r.public_key()).is_err());
        // Wrong struct tag is rejected at parse.
        let reframed = crate::wire::frame(StructTag::LogEntry, &signed.to_wire()[3..]);
        assert!(matches!(
            SignedSelfChannelEntry::from_wire(&reframed),
            Err(Error::MalformedBundle("self-channel wrong struct tag"))
        ));
    }
}
