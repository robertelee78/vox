//! PQXDH key agreement (ADR-004 §Decision): the post-quantum-augmented X3DH
//! handshake that yields the initial shared secret `SK` both sides feed into the
//! Double Ratchet.
//!
//! ## DH-leg assignment (Signal X3DH §3.3, confirmed against the spec)
//! With initiator identity key `IK_A`, fresh ephemeral `EK_A`, and responder
//! identity key `IK_B`, signed prekey `SPK_B`, optional one-time prekey `OPK_B`:
//!
//! ```text
//! DH1 = DH(IK_A, SPK_B)   — binds the initiator identity to the responder prekey
//! DH2 = DH(EK_A, IK_B)    — binds the responder identity to the initiator ephemeral
//! DH3 = DH(EK_A, SPK_B)   — forward secrecy
//! DH4 = DH(EK_A, OPK_B)   — forward secrecy (only when a one-time prekey is used)
//! ```
//!
//! DH1 and DH2 provide mutual authentication (each crosses one party's long-term
//! identity key with the other's prekey/ephemeral); DH3/DH4 use the ephemeral and
//! provide forward secrecy. X25519 DH is computed in the **initiator-public →
//! responder-secret / initiator-secret → responder-public** symmetric form, so
//! both sides derive the identical leg.
//!
//! ## Key derivation (ADR-004 — pinned construction)
//! ```text
//! SK = HKDF-SHA-256(
//!        ikm  = F ‖ DH1 ‖ DH2 ‖ DH3 ‖ [DH4] ‖ SS,
//!        salt = 0x00 * 32,
//!        info = "vox/pqxdh/v1" ‖ suite_id (u16 BE))
//! ```
//! `F = 0xFF * 32` is the X3DH/PQXDH curve domain-separation prefix (32 bytes for
//! X25519), prepended to the IKM exactly as the USENIX'24-verified construction
//! specifies — retained for byte-faithfulness to the analyzed PQXDH KDF. `SS` is
//! the ML-KEM-768 shared secret, **appended last** after all DH legs (matching
//! the PQXDH spec ordering). ADR-004 §Decision pins this exact IKM.
//!
//! ## Authentication of the responder bundle
//! [`initiate`] verifies the responder's [`PrekeyBundlePublic`] — the root
//! signature over the identity DH key `IK_B`, the signed prekey, and the one-time
//! prekey — **before** any key is used (the M1 HIGH fix; ADR-004 "Initiator
//! verifies B's PrekeyBundlePublic before use"). An unauthenticated `IK_B` is
//! rejected, so an active attacker cannot substitute their own.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::cbor::Encoder;
use crate::error::{Error, Result};
use crate::hash::{sha256_concat, Digest32};
use crate::identity::keyagreement::{
    OneTimePrekey, PrekeyBundlePublic, SignedPrekey, X25519IdentityKey, ML_KEM_768_ENCAPS_LEN,
    X25519_PUB_LEN,
};
use crate::pairwise::header::PQXDH_TRANSCRIPT_DOMAIN;
use crate::pairwise::init_message::InitialMessage;
use crate::pairwise::kem::{
    decaps_key_from_seed, decapsulate, encaps_key_from_bytes, encapsulate, KemSharedSecret,
    ML_KEM_768_CT_LEN,
};

/// The PQXDH info-string base (ADR-004); the big-endian `suite_id` is appended.
const PQXDH_INFO_BASE: &str = "vox/pqxdh/v1";

/// The PQXDH `F` prefix: 32 `0xFF` bytes prepended to the KDF IKM for X25519
/// (Signal PQXDH / X3DH §"Cryptographic notation"). It is the curve
/// domain-separation prefix the USENIX'24-verified construction requires;
/// retaining it keeps Vox byte-faithful to the analyzed PQXDH KDF.
const F_PREFIX: [u8; 32] = [0xFF; 32];

/// The derived PQXDH shared secret `SK` (32 bytes), zeroized on drop. Consumed
/// as the Double Ratchet's initial root key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedKey(pub(crate) [u8; 32]);

impl SharedKey {
    /// Borrow the raw bytes (for the ratchet's initial root-key install only).
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for SharedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedKey").finish_non_exhaustive()
    }
}

/// A single X25519 DH leg, zeroized on drop so leg secrets never linger.
#[derive(Zeroize, ZeroizeOnDrop)]
struct DhLeg([u8; 32]);

/// Compute `DH(secret, public)` as an X25519 shared point.
fn dh(secret_bytes: &[u8; 32], public_bytes: &[u8; X25519_PUB_LEN]) -> DhLeg {
    let secret = XSecret::from(*secret_bytes);
    let shared = secret.diffie_hellman(&XPublic::from(*public_bytes));
    DhLeg(shared.to_bytes())
}

/// Derive `SK` from the ordered DH legs and the KEM shared secret (ADR-004):
/// `SK = HKDF-SHA-256(ikm = F ‖ DH1 ‖ DH2 ‖ DH3 ‖ [DH4] ‖ SS, salt = 0x00*32,
/// info = "vox/pqxdh/v1" ‖ suite_id)`, where `F = 0xFF*32` is the PQXDH curve
/// prefix. The IKM buffer is zeroizing so the raw DH/KEM secrets do not linger.
fn derive_sk(legs: &[&DhLeg], ss: &KemSharedSecret, suite_id: u16) -> Result<SharedKey> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(F_PREFIX.len() + legs.len() * 32 + 32));
    ikm.extend_from_slice(&F_PREFIX);
    for leg in legs {
        ikm.extend_from_slice(&leg.0);
    }
    ikm.extend_from_slice(ss.as_bytes());

    let mut info = PQXDH_INFO_BASE.as_bytes().to_vec();
    info.extend_from_slice(&suite_id.to_be_bytes());

    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|_| Error::MalformedBundle("pqxdh hkdf expand"))?;
    Ok(SharedKey(okm))
}

/// The handshake transcript hash bound into the first message's KEM-binding AD
/// (ADR-004 §Decision): a domain-separated SHA-256 over every public handshake
/// value — `IK_A, EK_A, IK_B, SPK_B, OPK_B?, kem_pub, kem_ct, suite_id,
/// channelID, epoch` — plus the **selected prekey ids** (`signed_prekey_id` and
/// the optional `one_time_prekey_id`). Binding the ids (M2-review LOW fix) makes
/// "same key bytes, different id/record" unambiguous, so a reused or relabelled
/// prekey record cannot collide on the transcript. Both sides recompute it
/// identically.
#[allow(clippy::too_many_arguments)]
fn transcript_hash(
    ik_a: &[u8; X25519_PUB_LEN],
    ek_a: &[u8; X25519_PUB_LEN],
    ik_b: &[u8; X25519_PUB_LEN],
    spk_b: &[u8; X25519_PUB_LEN],
    opk_b: Option<&[u8; X25519_PUB_LEN]>,
    kem_pub: &[u8; ML_KEM_768_ENCAPS_LEN],
    kem_ct: &[u8; ML_KEM_768_CT_LEN],
    suite_id: u16,
    channel_id: &[u8; 32],
    epoch: u64,
    signed_prekey_id: u64,
    one_time_prekey_id: Option<u64>,
) -> Digest32 {
    // Canonical, length-delimited body so no two distinct field tuples collide.
    // The OTP id is encoded as a (present-flag, id) pair so None and Some(0) are
    // distinct, matching the InitialMessage wire encoding.
    let mut e = Encoder::new();
    e.array(13)
        .bytes(ik_a)
        .bytes(ek_a)
        .bytes(ik_b)
        .bytes(spk_b)
        .bytes(opk_b.map_or(&[][..], |o| &o[..]))
        .bytes(kem_pub)
        .bytes(kem_ct)
        .uint(u64::from(suite_id))
        .bytes(channel_id)
        .uint(epoch)
        .uint(signed_prekey_id)
        .uint(u64::from(one_time_prekey_id.is_some()))
        .uint(one_time_prekey_id.unwrap_or(0));
    sha256_concat(&[PQXDH_TRANSCRIPT_DOMAIN.as_bytes(), &e.finish()])
}

/// The output of [`initiate`]'s PQXDH half: the shared secret, the wire message,
/// and the transcript hash + KEM public bytes needed for the first message's AD.
pub struct InitiatorHandshake {
    /// The derived shared secret `SK`.
    pub sk: SharedKey,
    /// The initial message to send to the responder.
    pub message: InitialMessage,
    /// The handshake transcript hash (for the first-message KEM-binding AD).
    pub transcript_hash: [u8; 32],
    /// The responder KEM public-key bytes (for the first-message KEM-binding AD).
    pub kem_pub: [u8; ML_KEM_768_ENCAPS_LEN],
}

/// Run the initiator half of PQXDH against a *verified* responder bundle.
///
/// Verifies the bundle (root signatures over `IK_B`, the signed prekey, and any
/// one-time prekey) before use, generates a fresh ephemeral `EK_A`, encapsulates
/// the KEM secret, computes the four DH legs, and derives `SK`. Returns the wire
/// message plus the transcript material the session needs for the first AEAD AD.
pub fn initiate(
    ik_a: &X25519IdentityKey,
    bundle: &PrekeyBundlePublic,
    channel_id: &[u8; 32],
    epoch: u64,
    suite_id: u16,
) -> Result<InitiatorHandshake> {
    // Authenticate the whole bundle first (ADR-004; the M1 HIGH fix).
    bundle.verify()?;
    crate::suite::suite_by_id(suite_id)?;

    // Copied secret scalars are zeroized after the DH legs are computed.
    let ik_a_secret = Zeroizing::new(ik_a.secret_bytes());
    let ik_a_pub = ik_a.public_bytes();

    // Fresh ephemeral EK_A.
    let ek_a = X25519IdentityKey::generate()?;
    let ek_a_secret = Zeroizing::new(ek_a.secret_bytes());
    let ek_a_pub = ek_a.public_bytes();

    let ik_b = bundle.identity_dh_key.x25519_pub;
    let spk_b = bundle.signed_prekey.x25519_pub;
    let opk_b = bundle.one_time_prekey.as_ref().map(|o| o.x25519_pub);

    // KEM: prefer a one-time KEM prekey when present, else the signed (last-resort)
    // KEM prekey. The two travel in the same prekey record, so the choice mirrors
    // the OPK choice exactly (ADR-002 §2; ADR-004 last-resort fallback).
    let kem_pub = match &bundle.one_time_prekey {
        Some(otp) => otp.ml_kem_pub,
        None => bundle.signed_prekey.ml_kem_pub,
    };
    let encaps = encaps_key_from_bytes(&kem_pub)?;
    let (kem_ct, ss) = encapsulate(&encaps);

    // DH legs (X3DH §3.3 assignment).
    let dh1 = dh(&ik_a_secret, &spk_b); // DH(IK_A, SPK_B)
    let dh2 = dh(&ek_a_secret, &ik_b); // DH(EK_A, IK_B)
    let dh3 = dh(&ek_a_secret, &spk_b); // DH(EK_A, SPK_B)
    let dh4 = opk_b.as_ref().map(|o| dh(&ek_a_secret, o)); // DH(EK_A, OPK_B)?

    let sk = match &dh4 {
        Some(d4) => derive_sk(&[&dh1, &dh2, &dh3, d4], &ss, suite_id)?,
        None => derive_sk(&[&dh1, &dh2, &dh3], &ss, suite_id)?,
    };

    let signed_prekey_id = bundle.signed_prekey.prekey_id;
    let one_time_prekey_id = bundle.one_time_prekey.as_ref().map(|o| o.prekey_id);
    let th = transcript_hash(
        &ik_a_pub,
        &ek_a_pub,
        &ik_b,
        &spk_b,
        opk_b.as_ref(),
        &kem_pub,
        &kem_ct,
        suite_id,
        channel_id,
        epoch,
        signed_prekey_id,
        one_time_prekey_id,
    );

    let message = InitialMessage {
        suite_id,
        channel_id: *channel_id,
        epoch,
        ik_a: ik_a_pub,
        ek_a: ek_a_pub,
        signed_prekey_id,
        one_time_prekey_id,
        kem_ct,
    };

    Ok(InitiatorHandshake {
        sk,
        message,
        transcript_hash: th,
        kem_pub,
    })
}

/// The responder's own private prekey material for [`accept`]: the long-term
/// identity DH key, the targeted signed prekey, and the one-time prekey iff the
/// initial message consumed one.
pub struct ResponderPrekeys<'a> {
    /// The responder's long-term identity DH key (holds `IK_B`'s secret).
    pub identity_dh_key: &'a X25519IdentityKey,
    /// The signed prekey the initial message targeted (`signed_prekey_id`).
    pub signed_prekey: &'a SignedPrekey,
    /// The one-time prekey the initial message consumed, if any.
    pub one_time_prekey: Option<&'a OneTimePrekey>,
}

/// The output of [`accept`]'s PQXDH half: the shared secret plus the transcript
/// material the session needs to authenticate the first inbound message's AD.
pub struct ResponderHandshake {
    /// The derived shared secret `SK`.
    pub sk: SharedKey,
    /// The handshake transcript hash.
    pub transcript_hash: [u8; 32],
    /// The responder KEM public-key bytes used (for the first-message AD).
    pub kem_pub: [u8; ML_KEM_768_ENCAPS_LEN],
}

/// Run the responder half of PQXDH from a received initial message and the
/// responder's own private prekeys. Decapsulates the KEM secret and recomputes
/// the four DH legs and `SK`, deriving the same secret the initiator did.
///
/// The caller is responsible for resolving `signed_prekey`/`one_time_prekey`
/// from the message's ids and for one-time-prekey reuse detection
/// ([`crate::pairwise::session`]). The KEM public key is reconstructed from the
/// owner's secret so it exactly matches what the initiator encapsulated against.
pub fn accept(
    message: &InitialMessage,
    prekeys: &ResponderPrekeys<'_>,
    channel_id: &[u8; 32],
    epoch: u64,
) -> Result<ResponderHandshake> {
    if &message.channel_id != channel_id || message.epoch != epoch {
        return Err(Error::MalformedBundle("pqxdh-init channel/epoch mismatch"));
    }
    crate::suite::suite_by_id(message.suite_id)?;

    // Presence of the one-time prekey must match the initial message exactly.
    match (message.one_time_prekey_id, prekeys.one_time_prekey) {
        (Some(id), Some(otp)) if otp.public().prekey_id == id => {}
        (None, None) => {}
        _ => return Err(Error::MalformedBundle("pqxdh-init otp resolution mismatch")),
    }
    if message.signed_prekey_id != prekeys.signed_prekey.public().prekey_id {
        return Err(Error::MalformedBundle(
            "pqxdh-init signed-prekey id mismatch",
        ));
    }

    // Copied secret scalars/seeds are zeroized after the DH legs / decapsulation.
    let ik_b_secret = Zeroizing::new(prekeys.identity_dh_key.secret_bytes());
    let ik_b_pub = prekeys.identity_dh_key.public_bytes();
    let spk_b_secret = Zeroizing::new(prekeys.signed_prekey.x25519_secret_bytes());
    let spk_b_pub = prekeys.signed_prekey.public().x25519_pub;

    // KEM secret: decapsulate with the one-time KEM seed if an OTP was used, else
    // the signed-prekey KEM seed (mirrors the initiator's selection).
    let (kem_seed, kem_pub) = match prekeys.one_time_prekey {
        Some(otp) => (
            Zeroizing::new(otp.ml_kem_seed_bytes()),
            otp.public().ml_kem_pub,
        ),
        None => (
            Zeroizing::new(prekeys.signed_prekey.ml_kem_seed_bytes()),
            prekeys.signed_prekey.public().ml_kem_pub,
        ),
    };
    let decaps = decaps_key_from_seed(*kem_seed);
    let ss = decapsulate(&decaps, &message.kem_ct);

    let opk_b_pub = prekeys.one_time_prekey.map(|o| o.public().x25519_pub);
    let opk_b_secret = prekeys
        .one_time_prekey
        .map(|o| Zeroizing::new(o.x25519_secret_bytes()));

    // DH legs, responder side — the symmetric counterpart of each initiator leg.
    let dh1 = dh(&spk_b_secret, &message.ik_a); // DH(IK_A, SPK_B)
    let dh2 = dh(&ik_b_secret, &message.ek_a); // DH(EK_A, IK_B)
    let dh3 = dh(&spk_b_secret, &message.ek_a); // DH(EK_A, SPK_B)
    let dh4 = opk_b_secret.as_ref().map(|s| dh(s, &message.ek_a)); // DH(EK_A, OPK_B)?

    let sk = match &dh4 {
        Some(d4) => derive_sk(&[&dh1, &dh2, &dh3, d4], &ss, message.suite_id)?,
        None => derive_sk(&[&dh1, &dh2, &dh3], &ss, message.suite_id)?,
    };

    let th = transcript_hash(
        &message.ik_a,
        &message.ek_a,
        &ik_b_pub,
        &spk_b_pub,
        opk_b_pub.as_ref(),
        &kem_pub,
        &message.kem_ct,
        message.suite_id,
        channel_id,
        epoch,
        message.signed_prekey_id,
        message.one_time_prekey_id,
    );

    Ok(ResponderHandshake {
        sk,
        transcript_hash: th,
        kem_pub,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::{RootSigner as _, SoftwareRootSigner};
    use crate::identity::keyagreement::{OneTimePrekeyPool, SignedIdentityDhKey, SignedPrekey};

    struct Responder {
        idk: SignedIdentityDhKey,
        spk: SignedPrekey,
        otp_pool: OneTimePrekeyPool,
        root: SoftwareRootSigner,
    }

    fn responder() -> Responder {
        let root = SoftwareRootSigner::from_component_seeds(&[3u8; 32], &[4u8; 32]).unwrap();
        let idk = SignedIdentityDhKey::generate(&root, 1_700_000_000).unwrap();
        let spk = SignedPrekey::generate(&root, 1, 1_700_000_000).unwrap();
        let otp_pool = OneTimePrekeyPool::generate(&root, 4, 100, 1_700_000_000).unwrap();
        Responder {
            idk,
            spk,
            otp_pool,
            root,
        }
    }

    // A signed bundle for `r`, with the one-time prekey present iff `otp` is.
    fn bundle(r: &Responder, otp: Option<&OneTimePrekey>) -> PrekeyBundlePublic {
        PrekeyBundlePublic {
            root_pub: r.root.public_key().to_bytes(),
            identity_dh_key: r.idk.public().clone(),
            identity_dh_key_sig: r.idk.signature().to_bytes(),
            signed_prekey: r.spk.public().clone(),
            signed_prekey_sig: r.spk.signature().to_bytes(),
            one_time_prekey: otp.map(|o| o.public().clone()),
            one_time_prekey_sig: otp.map(|o| o.signature().to_bytes()),
        }
    }

    // Both halves derive the identical SK (and transcript/kem_pub) on both the
    // one-time-prekey path and the last-resort (no-OTP) path.
    fn assert_sk_agrees(with_otp: bool) {
        let mut r = responder();
        let otp = with_otp.then(|| r.otp_pool.take().unwrap());
        let b = bundle(&r, otp.as_ref());
        let ik_a = X25519IdentityKey::generate().unwrap();
        let cid = [9u8; 32];
        let bob_idk = X25519IdentityKey::from_secret_bytes(r.idk.x25519_secret_bytes());

        let init = initiate(&ik_a, &b, &cid, 7, 0x0001).unwrap();
        let prekeys = ResponderPrekeys {
            identity_dh_key: &bob_idk,
            signed_prekey: &r.spk,
            one_time_prekey: otp.as_ref(),
        };
        let resp = accept(&init.message, &prekeys, &cid, 7).unwrap();
        assert_eq!(init.sk.as_bytes(), resp.sk.as_bytes());
        assert_eq!(init.transcript_hash, resp.transcript_hash);
        assert_eq!(init.kem_pub, resp.kem_pub);
    }

    #[test]
    fn both_parties_derive_identical_sk_with_otp() {
        assert_sk_agrees(true);
    }

    #[test]
    fn both_parties_derive_identical_sk_last_resort() {
        assert_sk_agrees(false);
    }

    #[test]
    fn deterministic_sk_test_vector() {
        // Fixed DH legs + fixed SS -> a stable SK (golden vector for the KDF
        // construction; regenerate only on a deliberate KDF change). This vector
        // is over ikm = F(0xFF*32) ‖ DH1 ‖ DH2 ‖ DH3 ‖ SS; it changed from the
        // pre-F value when the M2-review MED restored the PQXDH F-prefix.
        let l1 = DhLeg([0x11; 32]);
        let l2 = DhLeg([0x22; 32]);
        let l3 = DhLeg([0x33; 32]);
        let ss = KemSharedSecret([0x44; 32]);
        let sk = derive_sk(&[&l1, &l2, &l3], &ss, 0x0001).unwrap();
        assert_eq!(
            hex::encode(sk.as_bytes()),
            "17fa629ec2cfb2b99e49a1e13a52dadf7a77bd2f1f1bee1440610dbe2d1f9000",
        );
    }

    #[test]
    fn f_prefix_is_present_in_ikm() {
        // The F-prefix materially changes the derived key: deriving WITHOUT it
        // (re-deriving by hand over the same legs+SS, no F) yields a different SK.
        let l1 = DhLeg([0x11; 32]);
        let l2 = DhLeg([0x22; 32]);
        let l3 = DhLeg([0x33; 32]);
        let ss = KemSharedSecret([0x44; 32]);
        let with_f = derive_sk(&[&l1, &l2, &l3], &ss, 0x0001).unwrap();

        let mut ikm_no_f = Vec::new();
        ikm_no_f.extend_from_slice(&l1.0);
        ikm_no_f.extend_from_slice(&l2.0);
        ikm_no_f.extend_from_slice(&l3.0);
        ikm_no_f.extend_from_slice(ss.as_bytes());
        let mut info = PQXDH_INFO_BASE.as_bytes().to_vec();
        info.extend_from_slice(&0x0001u16.to_be_bytes());
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&[0u8; 32]), &ikm_no_f);
        let mut no_f = [0u8; 32];
        hk.expand(&info, &mut no_f).unwrap();
        assert_ne!(with_f.as_bytes(), &no_f);
    }

    #[test]
    fn sk_changes_if_any_leg_or_ss_differs() {
        let l1 = DhLeg([0x11; 32]);
        let l2 = DhLeg([0x22; 32]);
        let l3 = DhLeg([0x33; 32]);
        let ss = KemSharedSecret([0x44; 32]);
        let base = derive_sk(&[&l1, &l2, &l3], &ss, 0x0001).unwrap();

        let l1b = DhLeg([0x10; 32]);
        assert_ne!(
            base.as_bytes(),
            derive_sk(&[&l1b, &l2, &l3], &ss, 0x0001)
                .unwrap()
                .as_bytes()
        );
        let ssb = KemSharedSecret([0x45; 32]);
        assert_ne!(
            base.as_bytes(),
            derive_sk(&[&l1, &l2, &l3], &ssb, 0x0001)
                .unwrap()
                .as_bytes()
        );
        // Adding a 4th leg changes the secret (OTP vs last-resort differ).
        let l4 = DhLeg([0x55; 32]);
        assert_ne!(
            base.as_bytes(),
            derive_sk(&[&l1, &l2, &l3, &l4], &ss, 0x0001)
                .unwrap()
                .as_bytes()
        );
    }

    #[test]
    fn initiate_rejects_unauthenticated_bundle() {
        let mut r = responder();
        let otp = r.otp_pool.take().unwrap();
        let mut b = bundle(&r, Some(&otp));
        // Substitute an attacker IK_B while keeping the old signature.
        let attacker = X25519IdentityKey::generate().unwrap();
        b.identity_dh_key.x25519_pub = attacker.public_bytes();
        let ik_a = X25519IdentityKey::generate().unwrap();
        assert!(matches!(
            initiate(&ik_a, &b, &[0u8; 32], 0, 0x0001),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn initial_message_wire_round_trips() {
        let mut r = responder();
        let otp = r.otp_pool.take().unwrap();
        let b = bundle(&r, Some(&otp));
        let ik_a = X25519IdentityKey::generate().unwrap();
        let init = initiate(&ik_a, &b, &[5u8; 32], 3, 0x0001).unwrap();

        let wire = init.message.to_wire();
        let decoded = InitialMessage::from_wire(&wire).unwrap();
        assert_eq!(decoded, init.message);

        // No-OTP variant round-trips with the absent id.
        let b2 = bundle(&r, None);
        let init2 = initiate(&ik_a, &b2, &[5u8; 32], 3, 0x0001).unwrap();
        let decoded2 = InitialMessage::from_wire(&init2.message.to_wire()).unwrap();
        assert_eq!(decoded2.one_time_prekey_id, None);
    }
}
