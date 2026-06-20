//! # Pairwise secure channel — PQXDH + Double Ratchet (ADR-004)
//!
//! The cryptographic core for *one-to-one* secure messaging underneath the
//! channel (ADR-001): the substrate that carries Sender-Key distribution
//! (ADR-006), the channel-join handshake (ADR-005), and consent/admin material
//! (ADR-007). It combines two formally-analyzed Signal constructions:
//!
//! - **[`pqxdh`]** — post-quantum-augmented X3DH key agreement. The X25519 X3DH
//!   DH legs are mixed with an ML-KEM-768 shared secret to derive the initial
//!   shared secret `SK`, giving forward secrecy *and* PQ confidentiality against
//!   a passive quantum adversary (harvest-now-decrypt-later defeated). The
//!   responder bundle is verified before use (the M1 HIGH fix), every key is
//!   parsed by its ADR-003 class-prefixed algorithm id (no type confusion), and
//!   the KEM public key + ciphertext are bound into the first message's AEAD
//!   associated data (no re-encapsulation).
//! - **[`ratchet`]** — the Double Ratchet: an X25519 DH ratchet plus an
//!   HMAC-SHA-256 symmetric chain ratchet with AES-256-GCM envelopes, providing
//!   forward secrecy and classical post-compromise security. Out-of-order
//!   delivery is handled with a bounded, expiring skipped-key store; consumed
//!   message keys are deleted so replay cannot re-derive plaintext.
//!
//! - **[`session`]** — the [`Session`] API tying the two together, including the
//!   exactly-once associated-data state transition (first message: KEM-binding
//!   AD; thereafter: header AD) and the serverless one-time-prekey reuse hook.
//! - **[`header`]** — the ratchet message header, the wire encodings, and the two
//!   associated-data constructions.
//! - **[`kem`]** — the ML-KEM-768 encapsulate/decapsulate operations.
//!
//! ## Wire boundary (ADR-004 vs ADR-008)
//! Pairwise PQXDH/ratchet messages are **payloads** carried by later milestones,
//! not log structures. They are canonical-CBOR bodies under their own ASCII
//! domain labels (`vox/pqxdh-init/v1`, `vox/ratchet-msg/v1`) and deliberately do
//! **not** consume ADR-008 [`crate::wire::StructTag`] registry tags (which are for
//! log entries). The transport (ADR-011) and group layer (ADR-006/008) frame
//! these payloads.
//!
//! ## Deferred boundaries (documented, not stubbed — ADR-004 / ADR-003)
//! - **PQ post-compromise security** (Signal SPQR / Triple-Ratchet, or PQ3-style
//!   amortized re-KEM) is a *distinct named capability with its own increment*
//!   (ADR-004 §"Post-quantum PCS (phased)", ADR-003 §scope). The day-one ratchet
//!   provides classical PCS and PQ confidentiality; the PQ-CKA layer is built
//!   complete when built, with its own ~2.3 KB/message bandwidth profile. The
//!   seam is the root KDF step in [`ratchet`]: a PQ continuous-key-agreement
//!   secret would be mixed in there. This is not implemented here and not faked.
//! - **Prekey *publication*** to the rendezvous / log is ADR-005/ADR-008 (M3/M5);
//!   here a verified in-memory [`crate::identity::keyagreement::PrekeyBundlePublic`]
//!   is consumed.
//! - **One-time-prekey reuse *detection*** *is* implemented ([`message::OtpReuseTracker`]),
//!   because ADR-004 specifies it as pairwise recipient-side behavior: a reused
//!   OTP downgrades the new session to last-resort-grade forward secrecy and is
//!   surfaced, never breaking confidentiality.

pub mod header;
pub mod init_message;
pub mod kem;
pub mod message;
pub mod pqxdh;
pub mod ratchet;
pub mod session;

pub use header::{RatchetHeader, PQXDH_INIT_DOMAIN, RATCHET_MSG_DOMAIN};
pub use init_message::InitialMessage;
pub use message::{Message, OtpReuseTracker};
pub use pqxdh::ResponderPrekeys;
pub use ratchet::{MAX_CACHE, MAX_SKIP, SKIP_EXPIRY_SECS};
pub use session::Session;
