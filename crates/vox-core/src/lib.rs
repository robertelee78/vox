//! # vox-core
//!
//! The single shared Rust core for Vox Lux (ADR-001 principle 10). Every Vox
//! client — the Rust TUI (ADR-015), the macOS app (ADR-014) — is a peer over
//! *this* library, never a fork of it.
//!
//! This crate is built up milestone by milestone in the dependency order fixed
//! by `docs/adr/README.md`. The modules present today are the **foundation**
//! (milestone M0) that every later milestone signs and verifies against:
//!
//! - [`cbor`] — the one canonical, deterministic CBOR codec the whole series
//!   signs over (ADR-008). Strict on decode: non-canonical input is rejected,
//!   not tolerated, because signature/MAC inputs must be unambiguous.
//! - [`wire`] — the struct-type tag registry, struct framing, and the wire
//!   error-code contract (ADR-008).
//! - [`suite`] — the algorithm / ciphersuite registry and floor relation
//!   (ADR-003): the single source for every `algo_id` on the wire.
//! - [`hash`] — SHA-256 and the domain-separated hashing helpers, including the
//!   identity fingerprint (ADR-002/003).
//! - [`error`] — the crate-wide error type.
//!
//! Built on that foundation, milestone **M1** adds:
//!
//! - [`identity`] — the self-sovereign identity and key model (ADR-002): the
//!   composite Ed25519+ML-DSA-65 root of trust, the hybrid (X25519 + ML-KEM-768)
//!   signed and one-time prekeys for PQXDH (ADR-004), the OpenPGP↔ML-DSA binding
//!   statement, the `self_seed`, the serializable identity-backup bundle, and the
//!   multi-device / pseudonymity model.
//!
//! Built on M1, milestone **M2** adds:
//!
//! - [`pairwise`] — the pairwise secure channel (ADR-004): PQXDH key agreement
//!   (post-quantum X3DH) and the Double Ratchet (X25519 DH ratchet +
//!   HMAC-SHA-256 chain ratchet + AES-256-GCM), with forward secrecy, classical
//!   post-compromise security, PQ confidentiality, KEM-secret binding, bounded
//!   out-of-order handling, and replay rejection.
//!
//! ## Engineering mantra (binding — see ADR-001)
//! No stubs, no `todo!()`, no shortcuts. What ships is complete and correct.
//! Every module here carries its own tests and, where the ADRs name a release
//! gate, golden test vectors.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Production code must not panic on attacker-controlled input. Tests assert
// freely, so the bans are relaxed there only.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod cbor;
pub mod error;
pub mod hash;
pub mod identity;
pub mod pairwise;
pub mod suite;
pub mod wire;

pub use error::{Error, Result};
