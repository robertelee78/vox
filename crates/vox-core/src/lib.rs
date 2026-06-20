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
//! Built on M1 + M2, milestone **M3** adds:
//!
//! - [`join`] — channel addressing and authenticated join (ADR-005): the
//!   high-entropy channelID and the fast rendezvous KDF (passphrase never an
//!   input), CPace (Ristretto255 + SHA-512 balanced PAKE) keyed by the passphrase,
//!   composite-identity proof-of-possession inside the CPace channel, an Equihash
//!   `(200,9)` join proof-of-work bound to `(channelID, epoch, nonce)`, and the
//!   orchestration that bootstraps an M2 [`pairwise::Session`] from a successful
//!   join — yielding no readable content (per-sender consent is ADR-007/M6).
//!
//! Built on M1 + M2, milestone **M4** adds:
//!
//! - [`group`] — group messaging via Sender Keys (ADR-006): the per-author
//!   one-way HMAC-SHA-256 chain ratchet (Signal Sender-Keys construction), a
//!   composite Ed25519+ML-DSA Sender-Key signing key bound to `(channelID,
//!   epoch)` and cross-signed by the identity root, the Sender-Key Distribution
//!   Message (tag `0x0002`) delivered as an ordinary M2 Double-Ratchet message
//!   (no redundant per-SKDM KEM), the mandatory `(channelID, epoch)` binding that
//!   defeats cross-group confusion, AES-256-GCM broadcast messages signed by the
//!   sender key, a bounded skip/replay window, the consent-gated history
//!   release-at-iteration mechanism, and explicit sender-key rotation for
//!   post-compromise recovery.
//!
//! Built on M0 + M1 + M4, milestone **M5** adds:
//!
//! - [`log`] — the replicated authenticated log & sync (ADR-008): per-author
//!   hash-linked feeds (Bamboo `lipmaa` skip-links, log-entry tag `0x0001`)
//!   merged into a causally-ordered Merkle-DAG (a CRDT, *not* a consensus
//!   blockchain); the signed-skeleton-over-payload-hash entry that lets payloads
//!   prune while the chain stays verifiable; render-gating (replicate-all,
//!   decrypt-what-you-can); anti-entropy sync over an abstract transport in both
//!   frontier and Negentropy-v1 range-reconciliation modes (keyed by the full
//!   32-byte entry hash); attributable fork/equivocation proofs with author
//!   freeze (and the deniable-alarm seam for ADR-009/M7); per-author abuse-quotas;
//!   and the personal multi-device self-channel (tag `0x000C`, `K_self` /
//!   `rendezvous_self` KDFs) that carries received SKDMs across an identity's own
//!   devices. The real QUIC transport (M9), the deniable authenticator (M7),
//!   payload-TTL policy (M8), and admitted-set population (M3/M6) are documented
//!   seams, not stubs.
//!
//! Built on M0 + M1 + M4 + M5, milestone **M6** adds:
//!
//! - [`governance`] — membership, per-sender consent & admin governance
//!   (ADR-007), Vox's headline differentiator. The self-certifying genesis record
//!   (tag `0x000D`, `channelID = SHA-256(canonical genesis)`, consistent with M3's
//!   derivation); the closed capability vocabulary + SPKI/SDSI/UCAN attenuation
//!   lattice (`admin` ⊇ `delegate`/`invite`/`policy`/`passphrase-rotate` + the
//!   ADR-013 tunnel caps `bind:`/`dial:`/`#role`); the composite-signed,
//!   `(channelID, epoch)`-bound governance entry bodies that ride the M5 log
//!   (admin-delegation cert `0x0003` and revocation `0x000E`, consent grant
//!   `0x0004` and revocation `0x0005`, policy-update + passphrase-rotation
//!   `0x0006`); the
//!   **deterministic evaluator** — a total function of log state with
//!   chain-to-genesis, monotonic attenuation, expiry, revocation-wins, and the
//!   ascending-entry-hash tie-break — gated by a mandatory golden-vector suite;
//!   emergent membership ("who can read whom" with no roster), monotonic
//!   per-sender visibility, the inbound visibility opt-out, and the invite modes.
//!   Tunnel-capability *use* (M11/ADR-013), SKDM *delivery* (M4), the CPace
//!   passphrase re-key on rotation (M3/M5), and TTL erasure (M8) are documented
//!   seams, not stubs.
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
pub mod governance;
pub mod group;
pub mod hash;
pub mod identity;
pub mod join;
pub mod log;
pub mod pairwise;
pub mod suite;
pub mod wire;

pub use error::{Error, Result};
