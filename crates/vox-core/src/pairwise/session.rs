//! The pairwise session API (ADR-004 §Session): glues PQXDH key agreement to the
//! Double Ratchet, manages the exactly-once AEAD associated-data transition, and
//! exposes `initiate` / `accept` / `encrypt` / `decrypt`.
//!
//! ## AD state transition (ADR-004 — exactly once)
//! The **first** post-handshake message authenticates the KEM-binding AD
//! (`transcript_hash ‖ kem_pub ‖ kem_ct ‖ suite_id ‖ channelID ‖ epoch`); every
//! subsequent message authenticates the header AD. The switch is exactly once
//! because the KEM-binding-AD message is identified *deterministically*, not by a
//! mutable "first seen" flag (which would break under out-of-order delivery): it
//! is the unique message whose header carries the **initiator's opening ratchet
//! key** with message number **`N == 0`** — the initiator's literal first
//! ciphertext.
//!
//! - The initiator knows its opening ratchet key at init; its `(opening, N == 0)`
//!   message uses the KEM-binding AD, all others header AD.
//! - The responder latches the opening ratchet key from the first inbound header,
//!   then applies the identical `(opening, N == 0)` test — so it decrypts that one
//!   message under the KEM-binding AD regardless of arrival order, and everything
//!   else under header AD.
//! - The responder's own replies carry *its* ratchet key (never the latched
//!   opening key), so they never match and always use header AD. The initiator
//!   therefore always decrypts inbound traffic with header AD.
//!
//! This matches the ADR: the KEM-binding AD exists to bind the *handshake's* KEM
//! commitment into the *first* ciphertext, defeating re-encapsulation; only the
//! initiator's opening message is that first ciphertext.
//!
//! ## One-time-prekey reuse detection (ADR-004 §Prekey publication)
//! In a serverless setting two initiators may consume the same one-time prekey
//! concurrently. [`OtpReuseTracker`] is the recipient-side hook: a one-time
//! prekey id seen twice is reported, and the second session is flagged
//! last-resort-grade (the OTP's forward-secrecy bonus is downgraded, never the
//! confidentiality). Reuse downgrades but does not break.

use zeroize::Zeroizing;

use crate::error::Result;
use crate::identity::keyagreement::{PrekeyBundlePublic, X25519IdentityKey, X25519_PUB_LEN};
use crate::pairwise::header::{header_ad, kem_binding_ad, RatchetHeader};
use crate::pairwise::init_message::InitialMessage;
use crate::pairwise::kem::ML_KEM_768_CT_LEN;
use crate::pairwise::message::{Message, OtpReuseTracker};
use crate::pairwise::pqxdh::{
    accept as pqxdh_accept, initiate as pqxdh_initiate, ResponderPrekeys,
};
use crate::pairwise::ratchet::Ratchet;

/// The KEM commitment bound into the first message's AD, recomputed identically
/// by both sides from the handshake.
#[derive(Clone)]
struct KemCommitment {
    transcript_hash: [u8; 32],
    kem_pub: [u8; crate::identity::keyagreement::ML_KEM_768_ENCAPS_LEN],
    kem_ct: [u8; ML_KEM_768_CT_LEN],
}

/// An established pairwise secure channel between two peers (ADR-004).
///
/// Drives the Double Ratchet underneath and applies the correct associated data
/// per message. One [`Session`] is one direction-symmetric channel: it both
/// [`encrypt`](Self::encrypt)s outbound and [`decrypt`](Self::decrypt)s inbound
/// messages, healing and tolerating out-of-order delivery within `MAX_SKIP`.
pub struct Session {
    ratchet: Ratchet,
    suite_id: u16,
    channel_id: [u8; 32],
    epoch: u64,
    commitment: KemCommitment,
    /// The initiator's *opening* ratchet public key — the key under which the one
    /// and only KEM-binding-AD message travels. The KEM-binding AD applies to
    /// exactly the message whose header carries this key with `N == 0` (the
    /// initiator's literal first ciphertext), so the AD selection is deterministic
    /// and order-independent, not a mutable "first seen" flag. On the initiator
    /// this is its own opening ratchet key (known at init); on the responder it is
    /// latched from the first inbound header.
    opening_ratchet: Option<[u8; X25519_PUB_LEN]>,
    /// Whether this side is last-resort-grade because the OTP was reused
    /// (responder only; surfaced via [`Session::is_last_resort_grade`]).
    last_resort_grade: bool,
}

impl Session {
    /// The negotiated ciphersuite id.
    #[must_use]
    pub fn suite_id(&self) -> u16 {
        self.suite_id
    }

    /// Whether this session was downgraded to last-resort-grade forward secrecy
    /// because its one-time prekey was reused (ADR-004 serverless reuse handling).
    #[must_use]
    pub fn is_last_resort_grade(&self) -> bool {
        self.last_resort_grade
    }

    /// Initiator entry point: run PQXDH against a verified responder bundle and
    /// build the session. Returns the [`InitialMessage`] to deliver to the
    /// responder and the ready [`Session`].
    ///
    /// The Double Ratchet's initial remote ratchet key is the responder's
    /// signed-prekey X25519 public key (`bundle.signed_prekey.x25519_pub`), which
    /// matches the responder's initial ratchet keypair in [`Session::accept`].
    pub fn initiate(
        ik_a: &X25519IdentityKey,
        bundle: &PrekeyBundlePublic,
        channel_id: &[u8; 32],
        epoch: u64,
        suite_id: u16,
    ) -> Result<(InitialMessage, Self)> {
        let hs = pqxdh_initiate(ik_a, bundle, channel_id, epoch, suite_id)?;
        let remote_ratchet = bundle.signed_prekey.x25519_pub;
        let aead_algo = crate::suite::suite_by_id(suite_id)?.aead;
        let sk = Zeroizing::new(*hs.sk.as_bytes());
        let ratchet = Ratchet::init_initiator(&sk, remote_ratchet, aead_algo)?;
        // The initiator's opening ratchet key is fixed at init; its first sent
        // message (this key, N == 0) is the unique KEM-binding-AD message.
        let opening_ratchet = Some(ratchet.self_public());
        let commitment = KemCommitment {
            transcript_hash: hs.transcript_hash,
            kem_pub: hs.kem_pub,
            kem_ct: hs.message.kem_ct,
        };
        let session = Self {
            ratchet,
            suite_id,
            channel_id: *channel_id,
            epoch,
            commitment,
            opening_ratchet,
            last_resort_grade: false,
        };
        Ok((hs.message, session))
    }

    /// Responder entry point: run PQXDH from a received [`InitialMessage`] and the
    /// responder's own private prekeys, building the session.
    ///
    /// `reuse` is the recipient-side one-time-prekey reuse tracker: if the
    /// message's one-time-prekey id has been seen before, the session is flagged
    /// last-resort-grade ([`Session::is_last_resort_grade`]).
    pub fn accept(
        message: &InitialMessage,
        prekeys: &ResponderPrekeys<'_>,
        channel_id: &[u8; 32],
        epoch: u64,
        reuse: &mut OtpReuseTracker,
    ) -> Result<Self> {
        let hs = pqxdh_accept(message, prekeys, channel_id, epoch)?;
        let aead_algo = crate::suite::suite_by_id(message.suite_id)?.aead;

        // The responder's initial ratchet keypair is the targeted signed prekey
        // (the key the initiator already ratcheted against).
        let spk_secret = prekeys.signed_prekey.x25519_secret_bytes();
        let spk_public = prekeys.signed_prekey.public().x25519_pub;
        let sk = Zeroizing::new(*hs.sk.as_bytes());
        let ratchet = Ratchet::init_responder(&sk, spk_secret, spk_public, aead_algo);

        let last_resort_grade = match message.one_time_prekey_id {
            Some(id) => reuse.observe(id),
            None => false,
        };

        let commitment = KemCommitment {
            transcript_hash: hs.transcript_hash,
            kem_pub: hs.kem_pub,
            kem_ct: message.kem_ct,
        };
        Ok(Self {
            ratchet,
            suite_id: message.suite_id,
            channel_id: *channel_id,
            epoch,
            commitment,
            // The responder learns the initiator's opening ratchet key from the
            // first inbound header; until then it is unknown.
            opening_ratchet: None,
            last_resort_grade,
        })
    }

    /// Encrypt `plaintext`, returning the wire [`Message`]. The first message a
    /// side sends (initiator only) is authenticated under the KEM-binding AD; all
    /// others under the header AD.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Message> {
        let (header, mk) = self.ratchet.next_send()?;
        let use_kem_ad = self.is_opening_message(&header);
        let ad = self.associated_data(&header, use_kem_ad);
        // `mk` is moved into `seal` (consumed by value): one-shot use, so the
        // deterministic per-key AEAD nonce is never reused.
        let ciphertext = Ratchet::seal(mk, &ad, plaintext)?;
        Ok(Message { header, ciphertext })
    }

    /// Decrypt a wire [`Message`] at wall-clock time `now` (Unix seconds, used for
    /// skipped-key expiry). The first inbound message a side decrypts (responder
    /// only) is authenticated under the KEM-binding AD; all others under header
    /// AD. A consumed `(ratchet_pubkey, N)` is deleted so replay fails.
    pub fn decrypt(&mut self, message: &Message, now: u64) -> Result<Vec<u8>> {
        // Transactional (M2-review HIGH fix): the responder's opening-ratchet
        // latch must NOT mutate from an unauthenticated packet. Compute the
        // CANDIDATE latch value and the AD against it, run the (itself
        // transactional) ratchet decrypt, and commit the latch ONLY on success —
        // so a forged first packet cannot poison the opening-key latch or the
        // AD-transition decision.
        let candidate_opening = self
            .opening_ratchet
            .unwrap_or(message.header.ratchet_pubkey);
        let use_kem_ad =
            Some(message.header.ratchet_pubkey) == Some(candidate_opening) && message.header.n == 0;
        let ad = self.associated_data(&message.header, use_kem_ad);
        let plaintext = self
            .ratchet
            .decrypt(&message.header, &ad, &message.ciphertext, now)?;
        // Authenticated: commit the latch.
        if self.opening_ratchet.is_none() {
            self.opening_ratchet = Some(message.header.ratchet_pubkey);
        }
        Ok(plaintext)
    }

    /// Whether `header` identifies the unique KEM-binding-AD message: the message
    /// under the initiator's opening ratchet key with message number 0. This is a
    /// deterministic, delivery-order-independent test — the AD transition is
    /// "exactly once" because exactly one `(opening_ratchet, N == 0)` message
    /// exists per session.
    fn is_opening_message(&self, header: &RatchetHeader) -> bool {
        self.opening_ratchet == Some(header.ratchet_pubkey) && header.n == 0
    }

    /// Build the associated data for `header`: the KEM-binding AD when
    /// `use_kem_ad`, else the per-message header AD.
    fn associated_data(&self, header: &RatchetHeader, use_kem_ad: bool) -> Vec<u8> {
        if use_kem_ad {
            kem_binding_ad(
                &self.commitment.transcript_hash,
                &self.commitment.kem_pub,
                &self.commitment.kem_ct,
                self.suite_id,
                &self.channel_id,
                self.epoch,
            )
        } else {
            header_ad(header, self.suite_id, &self.channel_id, self.epoch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::identity::composite::{RootSigner as _, SoftwareRootSigner};
    use crate::identity::keyagreement::{
        OneTimePrekey, OneTimePrekeyPool, SignedIdentityDhKey, SignedPrekey,
    };

    struct Peer {
        root: SoftwareRootSigner,
        idk: SignedIdentityDhKey,
        spk: SignedPrekey,
        pool: OneTimePrekeyPool,
    }

    fn peer(seed_a: u8, seed_b: u8) -> Peer {
        let root = SoftwareRootSigner::from_component_seeds(&[seed_a; 32], &[seed_b; 32]).unwrap();
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

    fn bundle(p: &Peer, otp: Option<&OneTimePrekey>) -> PrekeyBundlePublic {
        PrekeyBundlePublic {
            root_pub: p.root.public_key().to_bytes(),
            identity_dh_key: p.idk.public().clone(),
            identity_dh_key_sig: p.idk.signature().to_bytes(),
            signed_prekey: p.spk.public().clone(),
            signed_prekey_sig: p.spk.signature().to_bytes(),
            one_time_prekey: otp.map(|o| o.public().clone()),
            one_time_prekey_sig: otp.map(|o| o.signature().to_bytes()),
        }
    }

    fn prekeys<'a>(
        bob: &'a Peer,
        bob_idk: &'a X25519IdentityKey,
        otp: Option<&'a OneTimePrekey>,
    ) -> ResponderPrekeys<'a> {
        ResponderPrekeys {
            identity_dh_key: bob_idk,
            signed_prekey: &bob.spk,
            one_time_prekey: otp,
        }
    }

    // Establish an initiator/responder session pair (with a one-time prekey).
    fn established() -> (Session, Session, OneTimePrekey) {
        let mut bob = peer(3, 4);
        let alice_idk = X25519IdentityKey::generate().unwrap();
        let otp = bob.pool.take().unwrap();
        let b = bundle(&bob, Some(&otp));
        let cid = [9u8; 32];

        let (init_msg, alice) = Session::initiate(&alice_idk, &b, &cid, 7, 0x0001).unwrap();
        let bob_idk = X25519IdentityKey::from_secret_bytes(bob.idk.x25519_secret_bytes());
        let pk = prekeys(&bob, &bob_idk, Some(&otp));
        let mut reuse = OtpReuseTracker::new();
        let bob_session = Session::accept(&init_msg, &pk, &cid, 7, &mut reuse).unwrap();
        (alice, bob_session, otp)
    }

    #[test]
    fn first_message_decrypts_under_kem_ad() {
        let (mut alice, mut bob, _otp) = established();
        let m = alice.encrypt(b"hello bob").unwrap();
        let pt = bob.decrypt(&m, 1_700_000_001).unwrap();
        assert_eq!(pt, b"hello bob");
    }

    #[test]
    fn full_bidirectional_conversation_with_healing() {
        let (mut alice, mut bob, _otp) = established();

        // Alice -> Bob (first, KEM-AD).
        let m1 = alice.encrypt(b"a1").unwrap();
        assert_eq!(bob.decrypt(&m1, 1).unwrap(), b"a1");
        // Bob -> Alice (triggers Alice's DH ratchet, header AD).
        let r1 = bob.encrypt(b"b1").unwrap();
        assert_eq!(alice.decrypt(&r1, 2).unwrap(), b"b1");
        // Alice -> Bob again (new sending chain after ratchet).
        let m2 = alice.encrypt(b"a2").unwrap();
        assert_eq!(bob.decrypt(&m2, 3).unwrap(), b"a2");
        // Several rounds to exercise repeated DH-ratchet healing.
        for i in 0..5u8 {
            let rb = bob.encrypt(&[b'B', i]).unwrap();
            assert_eq!(alice.decrypt(&rb, 4).unwrap(), &[b'B', i]);
            let ra = alice.encrypt(&[b'A', i]).unwrap();
            assert_eq!(bob.decrypt(&ra, 5).unwrap(), &[b'A', i]);
        }
    }

    #[test]
    fn out_of_order_within_max_skip_succeeds() {
        let (mut alice, mut bob, _otp) = established();
        let m0 = alice.encrypt(b"m0").unwrap();
        let m1 = alice.encrypt(b"m1").unwrap();
        let m2 = alice.encrypt(b"m2").unwrap();
        // Deliver out of order: m2, m0, m1.
        assert_eq!(bob.decrypt(&m2, 1).unwrap(), b"m2");
        assert_eq!(bob.decrypt(&m0, 1).unwrap(), b"m0");
        assert_eq!(bob.decrypt(&m1, 1).unwrap(), b"m1");
    }

    #[test]
    fn replay_of_consumed_message_is_rejected() {
        let (mut alice, mut bob, _otp) = established();
        let m = alice.encrypt(b"once").unwrap();
        assert_eq!(bob.decrypt(&m, 1).unwrap(), b"once");
        // Replaying the same (ratchet_pubkey, N): the key was deleted after use.
        assert!(matches!(
            bob.decrypt(&m, 1),
            Err(Error::SignatureInvalid) | Err(Error::MalformedBundle(_))
        ));
    }

    #[test]
    fn gap_larger_than_max_skip_rejected() {
        let (mut alice, mut bob, _otp) = established();
        // Send one to establish the chain, then forge a header far past MAX_SKIP.
        let m0 = alice.encrypt(b"m0").unwrap();
        assert_eq!(bob.decrypt(&m0, 1).unwrap(), b"m0");
        // Produce a message with a huge N by encrypting then rewriting N.
        let mut m = alice.encrypt(b"far").unwrap();
        m.header.n = crate::pairwise::ratchet::MAX_SKIP + 5;
        assert!(bob.decrypt(&m, 1).is_err());
    }

    #[test]
    fn forged_first_packet_does_not_poison_session_state() {
        // M2-review HIGH fix, transactional decrypt: a forged first inbound packet
        // (valid header, garbage ciphertext) must fail AND leave Bob able to
        // decrypt the genuine first message afterward — i.e. it must not latch the
        // opening-ratchet key, advance the ratchet, or flip the AD transition.
        let (mut alice, mut bob, _otp) = established();
        let genuine = alice.encrypt(b"hello").unwrap();

        // Forge: same header (so it looks like the opening message), tampered ct.
        let mut forged = genuine.clone();
        forged.ciphertext[0] ^= 0xFF;
        assert!(bob.decrypt(&forged, 1).is_err());
        // State unchanged: the opening latch did not commit from the forgery.
        assert!(bob.opening_ratchet.is_none());

        // The genuine opening message still decrypts under the KEM-binding AD.
        assert_eq!(bob.decrypt(&genuine, 1).unwrap(), b"hello");
        // And the conversation continues normally afterward.
        let m2 = alice.encrypt(b"world").unwrap();
        assert_eq!(bob.decrypt(&m2, 1).unwrap(), b"world");
    }

    #[test]
    fn forged_dh_ratchet_packet_does_not_advance_receive_ratchet() {
        // A forged packet bearing an unseen ratchet pubkey (would trigger a DH
        // ratchet step) must fail without advancing Bob's receive ratchet, so the
        // next genuine message still decrypts.
        let (mut alice, mut bob, _otp) = established();
        assert_eq!(
            bob.decrypt(&alice.encrypt(b"a0").unwrap(), 1).unwrap(),
            b"a0"
        );
        // Bob replies -> Alice ratchets; capture a genuine Alice msg on a NEW chain.
        let r0 = bob.encrypt(b"b0").unwrap();
        assert_eq!(alice.decrypt(&r0, 1).unwrap(), b"b0");
        let genuine = alice.encrypt(b"a1-newchain").unwrap();

        // Forge a packet on the same new ratchet pubkey but tampered ct.
        let mut forged = genuine.clone();
        let last = forged.ciphertext.len() - 1;
        forged.ciphertext[last] ^= 0x01;
        assert!(bob.decrypt(&forged, 2).is_err());
        // The genuine message on that new chain still decrypts (ratchet not poisoned).
        assert_eq!(bob.decrypt(&genuine, 2).unwrap(), b"a1-newchain");
    }

    #[test]
    fn replayed_consumed_packet_leaves_session_functional() {
        // A replay of a consumed (pubkey, N) must fail AND not disturb a
        // legitimately-skipped key or the live chain: the next genuine message
        // still decrypts.
        let (mut alice, mut bob, _otp) = established();
        let m0 = alice.encrypt(b"m0").unwrap();
        let m1 = alice.encrypt(b"m1").unwrap();
        // Consume m0.
        assert_eq!(bob.decrypt(&m0, 1).unwrap(), b"m0");
        // Replay m0: rejected, and m1 still decrypts after.
        assert!(bob.decrypt(&m0, 1).is_err());
        assert_eq!(bob.decrypt(&m1, 1).unwrap(), b"m1");

        // Out-of-order: skip ahead to m3, then replay it, then deliver m2.
        let m2 = alice.encrypt(b"m2").unwrap();
        let m3 = alice.encrypt(b"m3").unwrap();
        assert_eq!(bob.decrypt(&m3, 1).unwrap(), b"m3"); // m2 now cached as skipped
        assert!(bob.decrypt(&m3, 1).is_err()); // replay of m3 rejected
                                               // A forgery at the cached (pubkey, m2.n) must not evict the real skipped key.
        let mut forged_m2 = m2.clone();
        forged_m2.ciphertext[0] ^= 0xFF;
        assert!(bob.decrypt(&forged_m2, 1).is_err());
        assert_eq!(bob.decrypt(&m2, 1).unwrap(), b"m2"); // genuine m2 still recoverable
    }

    #[test]
    fn tampered_kem_ct_breaks_first_message() {
        let mut bob = peer(3, 4);
        let alice_idk = X25519IdentityKey::generate().unwrap();
        let otp = bob.pool.take().unwrap();
        let b = bundle(&bob, Some(&otp));
        let cid = [9u8; 32];
        let (mut init_msg, mut alice) = Session::initiate(&alice_idk, &b, &cid, 7, 0x0001).unwrap();

        // Tamper the KEM ciphertext in the delivered initial message. Bob's SK
        // (and hence the whole ratchet + KEM-binding AD) diverges; the first
        // message fails to open.
        init_msg.kem_ct[0] ^= 0x01;
        let bob_idk = X25519IdentityKey::from_secret_bytes(bob.idk.x25519_secret_bytes());
        let pk = prekeys(&bob, &bob_idk, Some(&otp));
        let mut reuse = OtpReuseTracker::new();
        let mut bob_session = Session::accept(&init_msg, &pk, &cid, 7, &mut reuse).unwrap();

        let m = alice.encrypt(b"secret").unwrap();
        assert!(bob_session.decrypt(&m, 1).is_err());
    }

    #[test]
    fn last_resort_path_no_otp_works() {
        let bob = peer(5, 6);
        let alice_idk = X25519IdentityKey::generate().unwrap();
        let b = bundle(&bob, None);
        let cid = [1u8; 32];
        let (init_msg, mut alice) = Session::initiate(&alice_idk, &b, &cid, 0, 0x0001).unwrap();
        let bob_idk = X25519IdentityKey::from_secret_bytes(bob.idk.x25519_secret_bytes());
        let pk = prekeys(&bob, &bob_idk, None);
        let mut reuse = OtpReuseTracker::new();
        let mut bob_session = Session::accept(&init_msg, &pk, &cid, 0, &mut reuse).unwrap();
        let m = alice.encrypt(b"no otp").unwrap();
        assert_eq!(bob_session.decrypt(&m, 1).unwrap(), b"no otp");
        assert!(!bob_session.is_last_resort_grade());
    }

    #[test]
    fn otp_reuse_downgrades_second_session_not_breaks() {
        // Two initiators consume the same OTP id. The first session is full-grade;
        // the second is flagged last-resort-grade but still works.
        let mut bob = peer(7, 8);
        let otp = bob.pool.take().unwrap();
        let b = bundle(&bob, Some(&otp));
        let cid = [2u8; 32];
        let bob_idk = X25519IdentityKey::from_secret_bytes(bob.idk.x25519_secret_bytes());
        let mut reuse = OtpReuseTracker::new();

        let alice1 = X25519IdentityKey::generate().unwrap();
        let (im1, mut a1) = Session::initiate(&alice1, &b, &cid, 0, 0x0001).unwrap();
        let pk1 = prekeys(&bob, &bob_idk, Some(&otp));
        let mut bob1 = Session::accept(&im1, &pk1, &cid, 0, &mut reuse).unwrap();
        assert!(!bob1.is_last_resort_grade());
        assert_eq!(bob1.decrypt(&a1.encrypt(b"x").unwrap(), 1).unwrap(), b"x");

        let alice2 = X25519IdentityKey::generate().unwrap();
        let (im2, mut a2) = Session::initiate(&alice2, &b, &cid, 0, 0x0001).unwrap();
        let pk2 = prekeys(&bob, &bob_idk, Some(&otp));
        let mut bob2 = Session::accept(&im2, &pk2, &cid, 0, &mut reuse).unwrap();
        assert!(bob2.is_last_resort_grade()); // downgraded
        assert_eq!(bob2.decrypt(&a2.encrypt(b"y").unwrap(), 1).unwrap(), b"y"); // not broken
    }

    #[test]
    fn forward_secrecy_later_state_cannot_decrypt_earlier_message() {
        // Capture an early ciphertext, advance the ratchet, and confirm the
        // consumed key is gone (the captured message cannot be re-decrypted).
        let (mut alice, mut bob, _otp) = established();
        let captured = alice.encrypt(b"early secret").unwrap();
        assert_eq!(bob.decrypt(&captured, 1).unwrap(), b"early secret");
        // Drive the conversation forward (DH ratchet steps + new chains).
        for _ in 0..3 {
            let _ = bob.decrypt(&alice.encrypt(b"more").unwrap(), 2);
            let _ = alice.decrypt(&bob.encrypt(b"reply").unwrap(), 3);
        }
        // The early message's key was deleted on first use; replay fails.
        assert!(bob.decrypt(&captured, 4).is_err());
    }

    #[test]
    fn message_wire_round_trips() {
        let (mut alice, _bob, _otp) = established();
        let m = alice.encrypt(b"wire").unwrap();
        let decoded = Message::from_wire(&m.to_wire()).unwrap();
        assert_eq!(decoded, m);
        // Wrong domain label rejected.
        let mut wrong = b"vox/nope/v1".to_vec();
        wrong.extend_from_slice(&m.canonical_body());
        assert!(Message::from_wire(&wrong).is_err());
    }

    #[test]
    fn ad_transition_happens_exactly_once() {
        // The switch is deterministic and exactly once: only the message under the
        // initiator's opening ratchet key with N == 0 uses the KEM-binding AD.
        let (mut alice, mut bob, _otp) = established();

        let m0 = alice.encrypt(b"0").unwrap();
        assert!(alice.is_opening_message(&m0.header)); // KEM-AD
        let m1 = alice.encrypt(b"1").unwrap();
        assert!(!alice.is_opening_message(&m1.header)); // header AD (N == 1)

        // Bob latches the opening key on the first inbound message and applies the
        // same rule: m0 is KEM-AD, m1 is header AD.
        assert_eq!(bob.decrypt(&m0, 1).unwrap(), b"0");
        assert!(!bob.is_opening_message(&m1.header));
        assert_eq!(bob.decrypt(&m1, 1).unwrap(), b"1");

        // Bob's own replies are never opening messages (his ratchet key differs
        // from the latched opening key), so they always use header AD.
        let r0 = bob.encrypt(b"r0").unwrap();
        assert!(!bob.is_opening_message(&r0.header));
        assert_eq!(alice.decrypt(&r0, 2).unwrap(), b"r0");
    }
}
