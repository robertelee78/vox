//! # Membership, per-sender consent & admin governance (ADR-007) — milestone M6
//!
//! This is Vox's **headline differentiator** (ADR-001): admission is a
//! *per-member, per-sender* cryptographic decision with **no central authority**,
//! designed against the Signalgate failure (one wrong add exposing all future
//! traffic) and validated against the Megolm membership-control attacks (Albrecht
//! et al., IEEE S&P 2023). Every authority claim chains to a self-certifying
//! genesis; membership is *emergent* (join + consent), not an admin-issued roster.
//!
//! ## The trust anchor
//! - [`genesis`] — the channel genesis record (tag `0x000D`, domain
//!   `vox/genesis/v1`): the pinned, self-signed struct whose `SHA-256` **is** the
//!   channelID. It carries the channel policy (history / deniability / TTL) and the
//!   creator's composite key (the root admin). M3's
//!   [`crate::join::channelid::channel_id`] hashes the *same* canonical bytes
//!   [`genesis::Genesis::channel_id`] produces — the two milestones derive the
//!   identical channelID by construction.
//!
//! ## The capability model (SPKI/SDSI/UCAN attenuation)
//! - [`capability`] — the closed capability vocabulary (`admin` ⊇ `delegate`,
//!   `invite`, `policy`, `passphrase-rotate`, plus ADR-013 tunnel caps
//!   `bind:<svc>` / `dial:<svc>` and role-tag attributes `#tag`) and the
//!   attenuation lattice ("a delegation grants only capabilities at or below its
//!   own"). Unknown capability = verification failure (closed domain). Tunnel caps
//!   are *defined* here and *used* by M11/ADR-013 — one evaluator, no parallel
//!   engine.
//!
//! ## The governance entry bodies (pinned canonical CBOR)
//! All composite-signed, `(channelID, epoch)`-bound, and ride the causal log
//! ([`crate::log`]) as `EntryKind::Governance` payloads:
//! - [`cert`] — admin-delegation cert (`0x0003`) + admin-delegation revocation
//!   (`0x000E`).
//! - [`consent`] — consent grant (`0x0004`) + consent revocation (`0x0005`).
//! - [`policy`] — policy-update (`0x0006`, kind = policy-update); never carries
//!   `deniability_mode` (genesis-immutable, enforced at the schema level).
//! - [`rotation`] — passphrase-rotation / epoch bump (`0x0006`, kind = rotation):
//!   the only admin-side (bulk) removal.
//!
//! ## The deterministic evaluator (the release-gated core)
//! - [`entry`] — the evaluator-ready [`entry::GovEntry`]: a decoded body plus its
//!   entry hash and causal coordinates.
//! - [`evaluator`] — [`evaluator::Evaluator`]: a **total function of log state**.
//!   Input — genesis + governance entries + an author-key resolver; output —
//!   admin authority (chain-to-genesis, monotonic attenuation, expiry,
//!   revocation-wins, **ascending-entry-hash tie-break**), consent visibility
//!   ("who can read whom"), and effective policy. Same log ⇒ identical verdict on
//!   every client, the precondition for the golden-vector equality gate (the
//!   test-only `vectors` module).
//!
//! ## Membership & visibility
//! - [`membership`] — the emergent "who can read whom" view derived from the log
//!   (no roster), monotonic per-sender visibility, and the consent-grant /
//!   revocation issuing seam (which carries only `skdm_ref`; the SKDM travels over
//!   M4's pairwise session).
//! - [`visibility`] — the inbound visibility opt-out ("whom do I read?"):
//!   receiver-side only, **no** log entry, reversible, orthogonal to outbound
//!   consent.
//! - [`invite`] — identity-bound invites (high-trust default, under the `invite`
//!   capability) and open passphrase joins (unverified until a member verifies).
//!   The passphrase gates the swarm; consent gates reading.
//!
//! ## Golden vectors (release gate)
//! The mandatory evaluator golden-vector suite (the test-only `vectors` module)
//! pins verdicts for valid chains, over-attenuation, expiry, revoked links,
//! concurrent-conflict + tie-break, and totality across input order. This is THE
//! deliverable that lets two implementations agree bit-for-bit.
//!
//! ## Enforcement honesty (ADR-007 §"Enforcement honesty")
//! Only **forward** guarantees are cryptographic: rotating to keys a party never
//! receives is enforceable; recalling already-held keys is not, and TTL/erasure is
//! client-honored (M8/ADR-010). The evaluator reports *current* authorization, not
//! a false claim that already-readable traffic became unreadable.
//!
//! ## Scope boundaries (documented, not stubbed — ADR mantra)
//! - **Tunnel capability *use*** (ABAC over `bind`/`dial`/role-tags) → M11/ADR-013:
//!   M6 defines the caps in the lattice and the evaluator evaluates them; ADR-013
//!   adds no parallel engine.
//! - **SKDM *delivery*** → M4/ADR-006: a consent-grant carries only `skdm_ref`; the
//!   SKDM travels in the pairwise session.
//! - **CPace passphrase re-key on rotation** → M3/M5: M6 authors the rotation entry
//!   and bumps the epoch; the actual re-key + sender-key re-bind is M3/M6's join +
//!   M4's rotation.
//! - **TTL / at-rest erasure** → M8/ADR-010: M6 carries the TTL policy value; M8
//!   enforces it.
//!
//! ## Engineering mantra (binding — see ADR-001)
//! No stubs, no `todo!()`, no shortcuts. Every type here is complete and tested,
//! and the evaluator is golden-vector-gated.

pub mod capability;
pub mod cert;
pub mod consent;
pub mod entry;
pub mod evaluator;
pub mod genesis;
pub mod invite;
pub mod membership;
pub mod policy;
pub mod rotation;
pub mod visibility;

#[cfg(test)]
pub mod vectors;

pub use capability::{Capability, CapabilitySet};
pub use cert::{AdminCert, AdminRevocation, RevocationReason};
pub use consent::{ConsentGrant, ConsentRevocation};
pub use entry::{GovBody, GovEntry};
pub use evaluator::{DenyReason, Evaluator, Verdict};
pub use genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
pub use invite::{Invite, InviteMode};
pub use membership::MembershipView;
pub use policy::PolicyUpdate;
pub use rotation::PassphraseRotation;
pub use visibility::VisibilitySet;
