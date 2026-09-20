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
use crate::suite::SuiteFloor;

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
        floor: SuiteFloor,
    ) -> Result<(InitialMessage, Self)> {
        let hs = pqxdh_initiate(ik_a, bundle, channel_id, epoch, suite_id, floor)?;
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
        floor: SuiteFloor,
    ) -> Result<Self> {
        let hs = pqxdh_accept(message, prekeys, channel_id, epoch, floor)?;
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
