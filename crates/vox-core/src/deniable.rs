//! # Deniability mode (per-channel) — ADR-009, milestone M7
//!
//! Deniable channels make **message-content authorship repudiable** while leaving
//! governance/membership fully attributable (ADR-007/ADR-008). This is exactly
//! mpENC **weak deniability** (Van Gundy / mpENC, arXiv 1606.04598): *message
//! contents are deniable, but session participation is not*. Deniability is
//! defined against an offline judge — after an epoch closes, no transferable proof
//! of *who authored a message* survives, even given long-term secrets.
//!
//! ## What this module owns (the seam M5 left)
//! M5 ([`crate::log::entry`]) defined the wire seam for deniable content — the
//! [`crate::log::entry::Authenticator::Deniable`] variant, its non-attributable
//! classification, the deniable-content fork *alarm* path
//! ([`crate::log::dag::ForkOutcome::DeniableAlarm`]), and the
//! [`crate::log::entry::DeniableVerifier`] trait — but shipped **no** deniable
//! crypto. M7 fills it:
//! - [`epoch`] — the per-epoch **ephemeral composite (Ed25519+ML-DSA-65) signing
//!   key** `(esk_i, epk_i)` each member generates; content in a deniable channel is
//!   signed **only** by `esk_i`, never the static identity key. Also the canonical
//!   member ordering (ascending composite-pubkey) and the transcript `T`.
//! - [`share`] — the ephemeral Diffie-Hellman shares `g^{x_i}` (Ristretto255) and
//!   the **classical Burmester–Desmedt** combiner that yields the epoch key `K`.
//!   `K` is used **only** for key-confirmation/binding — never as a content key
//!   (content confidentiality is the PQ Sender Keys, ADR-006/M4). A classical `K`
//!   is therefore harmless (no harvest-now-decrypt-later exposure, ADR-009).
//! - [`key`] — the [`key::EpochKey`]: HKDF derivation of `K` from the BD group
//!   element and the step-4 key-confirmation MAC over the transcript `T`.
//! - [`dgka`] — the **4-round Deniable GKA + DSKE** state machine (commit →
//!   reveal → DSKE-bind → confirm). All four rounds ride the log as
//!   `dgka-setup` governance entries (tag `0x000B`, root-composite-signed
//!   *envelope* — participation attributable = weak deniability; the
//!   key-agreement material *inside* carries no static signature).
//! - [`verifier`] — [`verifier::EpochVerifier`], the [`crate::log::entry::DeniableVerifier`]
//!   implementation: a deniable content entry's authenticator is a composite
//!   signature by `epk_i` over the entry signing input, verified against the
//!   `epk_i` registered in that epoch's DGKA setup.
//! - [`rekey`] — the incremental DSKE re-key for a mid-epoch membership change
//!   (one bind+confirm round against the updated transcript `T'`).
//! - [`esk_publication`] — the epoch-end ephemeral *private*-key publication
//!   (tag `0x0010`), the mechanism that makes content repudiable: after `esk_i`
//!   is published anyone can forge that epoch's content signatures.
//!
//! ## Per-sender consent is preserved (critical — ADR-009 §"Per-sender consent")
//! The construction keeps **one ephemeral signing key per member** (public `epk`
//! shared), **not** a shared group signing secret. Consenting = `A` releases `A`'s
//! per-epoch `epk` verifier (+ the per-sender content key, M4) to `N`; withholding
//! = `A` does not. `N` gains/loses **only** `A`'s content — the per-sender,
//! monotonic visibility of ADR-007. [`verifier::EpochVerifier`] models exactly
//! this: it verifies only the `epk`s that have been *released* into it.
//!
//! ## Post-quantum posture (ADR-009 §"Post-quantum instantiation")
//! Deniable mode is **PQ today**: live origin auth is the composite (Ed25519 +
//! ML-DSA-65) ephemeral key; confidentiality is the PQ Sender Keys (M4). The DGKA
//! key `K` is classical Burmester–Desmedt (confirmation-only) — fine, by the
//! argument above. The optional *live* non-transferability upgrade (a PQ
//! designated-verifier signature, UDMVS/MDVRS) is **out of scope** (ADR-009 — a
//! young primitive; deniable mode ships complete without it). The crypto-agility
//! seam is the algorithm IDs already in the entry skeleton (ADR-003).
//!
//! ## ⚠ SHIP PREREQUISITE — formal analysis (ADR-009 §Consequences)
//! ADR-009 and the project README require a **formal security analysis of this
//! DGKA + DSKE construction before it ships to users**. Van Gundy/mpENC provide
//! the template, not a drop-in proven library; the multi-round deniable GKA plus
//! the incremental re-key is real protocol complexity. This module is a complete,
//! tested *implementation* of that construction, but the formal-analysis gate is a
//! release blocker that this code cannot itself discharge. Do not enable deniable
//! mode in a shipped build until that analysis is on file.
//!
//! ## Engineering mantra (binding — see ADR-001)
//! No stubs, no `todo!()`, no shortcuts. Every type here is complete and tested.

pub mod dgka;
pub mod epoch;
pub mod esk_publication;
pub mod key;
pub mod rekey;
pub mod rounds;
pub mod share;
pub mod verifier;

pub use dgka::{DgkaMember, DgkaSession};
pub use epoch::{EphemeralSigningKey, EpochContext, MemberDescriptor, MemberEpk};
pub use esk_publication::{EskPublication, PublishedEsk};
pub use key::EpochKey;
pub use rekey::ReKey;
pub use rounds::{Confirm, Reveal};
pub use share::EphemeralShare;
pub use verifier::EpochVerifier;

#[cfg(test)]
mod tests;
