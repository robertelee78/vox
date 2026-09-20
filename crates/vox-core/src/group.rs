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
