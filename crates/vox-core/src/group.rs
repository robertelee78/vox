//! # Group messaging — Sender Keys (ADR-006)
//!
//! The channel is the unit; every message is a one-to-many broadcast (ADR-001).
//! This module is the **Sender Keys** group-messaging primitive, channel-scoped,
//! chosen over MLS/TreeKEM precisely because per-author key material is what makes
//! **per-sender consent** (the headline differentiator, ADR-007) expressible:
//! consent is simply *withholding* a member's SKDM until they consent, with no new
//! cryptographic construct (ADR-006 §Decision).
//!
//! ## What a sender key is (ADR-006 §Decision, ADR-002 §3)
//! Each member, per channel, holds:
//! - a **chain key** that ratchets forward one-way, one step per message
//!   ([`senderkey::ChainKey`]) — the Signal Sender-Keys keyed-HMAC-SHA-256 chain
//!   (`mk = HMAC(CK, 0x01)`, `CK' = HMAC(CK, 0x02)`), the same construction the M2
//!   ratchet uses, *not* the Matrix Megolm 4-part SHA-256 ratchet;
//! - a per-sender **`chain_id`** generation id (distinct from the channel
//!   `epoch`), incremented on every sender-key rotation;
//! - a composite **Ed25519 + ML-DSA-65 Sender-Key signing key**
//!   ([`senderkey::SenderKeySigningKey`]) bound to `(channelID, epoch)` and
//!   **cross-signed by the identity root** (here: the root's signature over the
//!   whole SKDM) so recipients tie it to the sender's identity.
//!
//! ## The pieces
//! - [`skdm`] — the Sender-Key Distribution Message (tag `0x0002`, domain
//!   `vox/skdm/v1`): the chain key at an `iteration`, the signing public key, and
//!   the root signature; **delivered as an ordinary M2 Double-Ratchet message**
//!   inside an already-established pairwise session (no redundant per-SKDM KEM —
//!   ADR-006 forbids it; the KEM was done once at PQXDH setup).
//! - [`message`] — the broadcast message: header `{channelID, epoch, author_id,
//!   chain_id, iteration}` bound into the AEAD AD, AES-256-GCM ciphertext under
//!   the per-iteration message key, and a composite Sender-Key signature.
//! - [`state`] — [`state::SenderChain`] (encrypt + sign + scheduled rotation) and
//!   [`state::ReceiverChain`] (bounded skip/replay window, one-way derivation).
//! - [`history`] — per-epoch origin-key retention and the release-at-iteration
//!   mechanism (forward-only vs full-history consent, ADR-006 §History).
//! - [`wire`] — the group-layer domain labels and canonical bindings.
//!
//! ## Mandatory (channelID, epoch) binding (ADR-006, eprint 2023/1385)
//! Sender keys are not inherently bound to a logical group, so without binding an
//! inbound session from channel G can be replayed into channel H (cross-group
//! confusion). Every SKDM signed context, the Sender-Key cross-signature, and
//! every broadcast message's AEAD AD bind `(channelID, epoch)` (and the full
//! header). Receivers **reject** any message/SKDM whose `(channelID, epoch)`
//! does not match the channel being processed.
//!
//! ## Post-compromise security
//! Base Sender Keys has only weak PCS and does not self-heal (Balbás et al.,
//! ASIACRYPT 2023). Recovery/revocation is **explicit** rotation — a new
//! `chain_id` ([`state::SenderChain::rotated`]) redistributed to current
//! consenters, plus passphrase-epoch rotation (which supersedes all per-sender
//! chains). This module provides that mechanism; it does not pretend the ratchet
//! self-heals.
//!
//! ## Scope boundaries (documented, not stubbed)
//! - **Consent decisions / withholding** are ADR-007 / M6: M4 provides the
//!   withhold-by-not-sending-SKDM mechanism and the release-at-iteration knob; M6
//!   decides *whether/when* to release to a given identity.
//! - **Self-channel multi-device SKDM sync** is ADR-008 / M5: an SKDM here is
//!   addressed to an *identity* (its fingerprint); sharing received SKDMs across a
//!   shared-root identity's devices over the self-channel is M5.
//! - **Origin-key TTL** is ADR-010 / M8: [`history::OriginKeyStore::prune_before`]
//!   is the enforcement seam; M4 never retains unboundedly on its own.
//!
//! ## Engineering mantra (binding — see ADR-001)
//! No stubs, no `todo!()`, no shortcuts. Every type here is complete and tested.

pub mod history;
pub mod message;
pub mod senderkey;
pub mod skdm;
pub mod state;
pub mod wire;

pub use history::OriginKeyStore;
pub use message::{GroupMessage, MessageHeader};
pub use senderkey::{ChainKey, SenderKeyCrossSig, SenderKeySigningKey, CHAIN_KEY_LEN};
pub use skdm::{Skdm, SkdmBody};
pub use state::{ReceiverChain, SenderChain, ROTATE_AFTER_MESSAGES, ROTATE_AFTER_SECS};
pub use wire::{SENDER_KEY_SIGNING_PUB_LEN, SENDER_KEY_SIGN_DOMAIN};

#[cfg(test)]
mod integration_tests {
    //! End-to-end tests crossing the SKDM/M2/broadcast boundary: an SKDM built by
    //! a sender, delivered THROUGH an established M2 pairwise session, parsed and
    //! verified by the recipient, then used to read the sender's broadcasts.

    use super::*;
    use crate::identity::composite::{RootSigner as _, SoftwareRootSigner};
    use crate::identity::keyagreement::{
        OneTimePrekey, OneTimePrekeyPool, PrekeyBundlePublic, SignedIdentityDhKey, SignedPrekey,
        X25519IdentityKey,
    };
    use crate::pairwise::{OtpReuseTracker, ResponderPrekeys, Session};

    // ---- Pairwise (M2) session harness, mirroring pairwise::session tests. ----

    struct Peer {
        root: SoftwareRootSigner,
        idk: SignedIdentityDhKey,
        spk: SignedPrekey,
        pool: OneTimePrekeyPool,
    }

    fn peer(a: u8, b: u8) -> Peer {
        let root = SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap();
        let idk = SignedIdentityDhKey::generate(&root, 1_700_000_000).unwrap();
        let spk = SignedPrekey::generate(&root, 1, 1_700_000_000).unwrap();
        let pool = OneTimePrekeyPool::generate(&root, 8, 100, 1_700_000_000).unwrap();
        Peer {
            root,
            idk,
            spk,
            pool,
        }
    }

    fn bundle(p: &Peer, otp: &OneTimePrekey) -> PrekeyBundlePublic {
        PrekeyBundlePublic {
            root_pub: p.root.public_key().to_bytes(),
            identity_dh_key: p.idk.public().clone(),
            identity_dh_key_sig: p.idk.signature().to_bytes(),
            signed_prekey: p.spk.public().clone(),
            signed_prekey_sig: p.spk.signature().to_bytes(),
            one_time_prekey: Some(otp.public().clone()),
            one_time_prekey_sig: Some(otp.signature().to_bytes()),
        }
    }

    // Establish a pairwise session pair (alice = SKDM sender, bob = recipient).
    fn pairwise() -> (Session, Session) {
        let mut bob = peer(3, 4);
        let alice_idk = X25519IdentityKey::generate().unwrap();
        let otp = bob.pool.take().unwrap();
        let b = bundle(&bob, &otp);
        let cid = [9u8; 32];
        let (init_msg, alice) = Session::initiate(&alice_idk, &b, &cid, 7, 0x0001).unwrap();
        let bob_idk = X25519IdentityKey::from_secret_bytes(bob.idk.x25519_secret_bytes());
        let pk = ResponderPrekeys {
            identity_dh_key: &bob_idk,
            signed_prekey: &bob.spk,
            one_time_prekey: Some(&otp),
        };
        let mut reuse = OtpReuseTracker::new();
        let bob_session = Session::accept(&init_msg, &pk, &cid, 7, &mut reuse).unwrap();
        (alice, bob_session)
    }

    #[test]
    fn skdm_through_m2_then_read_broadcasts() {
        // The full path the lead asked for: build → M2-encrypt → M2-decrypt →
        // parse → verify → read the sender's group messages.
        let (mut alice_session, mut bob_session) = pairwise();

        let cid = [0x33u8; 32];
        let epoch = 2u64;
        let alice_root = SoftwareRootSigner::from_component_seeds(&[5u8; 32], &[6u8; 32]).unwrap();
        let author = alice_root.public_key().fingerprint();

        // Alice's sender chain + the SKDM at her current (origin) position.
        let mut chain = SenderChain::new(&cid, epoch, &author, 0, 1_700_000_000).unwrap();
        let (iter, key) = chain.current_position();
        let skdm = chain.skdm_for(&alice_root, iter, key).unwrap();

        // Deliver the SKDM as an ordinary M2 message (no separate KEM step).
        let wrapped = skdm.seal_into(&mut alice_session).unwrap();
        let received = Skdm::open_from(&mut bob_session, &wrapped, 1_700_000_001).unwrap();

        // Bob verifies it against Alice's (trusted) root and the expected channel.
        let mut recv =
            ReceiverChain::from_skdm(&received, &alice_root.public_key(), &cid, epoch).unwrap();

        // Now Alice broadcasts; Bob reads using the receiver chain.
        for i in 0..3 {
            let m = chain.encrypt(format!("broadcast {i}").as_bytes()).unwrap();
            assert_eq!(
                recv.decrypt(&m).unwrap(),
                format!("broadcast {i}").as_bytes()
            );
        }
    }

    #[test]
    fn tampered_wrapped_skdm_fails_m2_decrypt() {
        let (mut alice_session, mut bob_session) = pairwise();
        let cid = [0x33u8; 32];
        let alice_root = SoftwareRootSigner::from_component_seeds(&[5u8; 32], &[6u8; 32]).unwrap();
        let author = alice_root.public_key().fingerprint();
        let chain = SenderChain::new(&cid, 2, &author, 0, 1_700_000_000).unwrap();
        let (iter, key) = chain.current_position();
        let skdm = chain.skdm_for(&alice_root, iter, key).unwrap();
        let mut wrapped = skdm.seal_into(&mut alice_session).unwrap();
        // Tamper the M2 ciphertext: the AEAD open fails before any SKDM parse.
        wrapped.ciphertext[0] ^= 0xFF;
        assert!(Skdm::open_from(&mut bob_session, &wrapped, 1_700_000_001).is_err());
    }

    #[test]
    fn cross_group_skdm_replay_rejected() {
        // An SKDM minted for channel G must not verify when processed as channel H,
        // even after a clean M2 round-trip.
        let (mut alice_session, mut bob_session) = pairwise();
        let g = [0x47u8; 32];
        let h = [0x48u8; 32];
        let alice_root = SoftwareRootSigner::from_component_seeds(&[5u8; 32], &[6u8; 32]).unwrap();
        let author = alice_root.public_key().fingerprint();
        let chain = SenderChain::new(&g, 2, &author, 0, 1_700_000_000).unwrap();
        let (iter, key) = chain.current_position();
        let skdm = chain.skdm_for(&alice_root, iter, key).unwrap();
        let wrapped = skdm.seal_into(&mut alice_session).unwrap();
        let received = Skdm::open_from(&mut bob_session, &wrapped, 1_700_000_001).unwrap();
        // Processing as channel H is rejected.
        assert!(ReceiverChain::from_skdm(&received, &alice_root.public_key(), &h, 2).is_err());
        // Wrong epoch likewise.
        assert!(ReceiverChain::from_skdm(&received, &alice_root.public_key(), &g, 3).is_err());
    }

    #[test]
    fn two_generations_coexist_unambiguously() {
        // After a rotation, generation 0 and generation 1 are independent: a
        // generation-1 receiver cannot read generation-0 messages (binding) and
        // vice versa.
        let cid = [0x33u8; 32];
        let r = SoftwareRootSigner::from_component_seeds(&[5u8; 32], &[6u8; 32]).unwrap();
        let author = r.public_key().fingerprint();

        let mut g0 = SenderChain::new(&cid, 2, &author, 0, 1_000).unwrap();
        let (i0, k0) = g0.current_position();
        let skdm0 = g0.skdm_for(&r, i0, k0).unwrap();
        let mut recv0 = ReceiverChain::from_skdm(&skdm0, &r.public_key(), &cid, 2).unwrap();

        let mut g1 = g0.rotated(2_000).unwrap();
        let (i1, k1) = g1.current_position();
        let skdm1 = g1.skdm_for(&r, i1, k1).unwrap();
        let mut recv1 = ReceiverChain::from_skdm(&skdm1, &r.public_key(), &cid, 2).unwrap();

        let m0 = g0.encrypt(b"gen0").unwrap();
        let m1 = g1.encrypt(b"gen1").unwrap();
        assert_eq!(recv0.decrypt(&m0).unwrap(), b"gen0");
        assert_eq!(recv1.decrypt(&m1).unwrap(), b"gen1");
        // Cross-generation delivery is rejected (chain_id binding mismatch).
        assert!(recv0.decrypt(&m1).is_err());
        assert!(recv1.decrypt(&m0).is_err());
    }

    #[test]
    fn epoch_rotation_invalidates_prior_chain() {
        // A receiver bound to epoch 2 rejects a message authored under epoch 3
        // (passphrase-epoch rotation supersedes prior per-sender chains).
        let cid = [0x33u8; 32];
        let r = SoftwareRootSigner::from_component_seeds(&[5u8; 32], &[6u8; 32]).unwrap();
        let author = r.public_key().fingerprint();
        let mut e2 = SenderChain::new(&cid, 2, &author, 0, 1_000).unwrap();
        let (i, k) = e2.current_position();
        let skdm = e2.skdm_for(&r, i, k).unwrap();
        let mut recv = ReceiverChain::from_skdm(&skdm, &r.public_key(), &cid, 2).unwrap();

        // A new-epoch chain's message must not be readable by the epoch-2 receiver.
        let mut e3 = SenderChain::new(&cid, 3, &author, 0, 2_000).unwrap();
        let m = e3.encrypt(b"new epoch").unwrap();
        assert!(recv.decrypt(&m).is_err());
        // The epoch-2 chain still works for the epoch-2 receiver.
        let ok = e2.encrypt(b"same epoch").unwrap();
        assert_eq!(recv.decrypt(&ok).unwrap(), b"same epoch");
    }
}
