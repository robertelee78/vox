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
//!   channelID. It carries the channel policy (history / TTL / suite floor) and the
//!   creator's composite key (the root admin). M3's
//!   [`crate::join::channelid::channel_id`] hashes the *same* canonical bytes
//!   [`genesis::Genesis::channel_id`] produces — the two milestones derive the
//!   identical channelID by construction.
//!
//! ## The capability model (SPKI/SDSI/UCAN attenuation)
//! - [`capability`] — the closed capability vocabulary: `admin` ⊇ `policy`, plus the
//!   genesis service grant's `bind:<svc>` / `dial:<svc>`. Unknown capability =
//!   verification failure (closed domain). **Governance is only "the creator or an
//!   admin sets the room's retention"** (V030-32, the decider, 2026-10-02): the
//!   `delegate`, `invite` and `passphrase-rotate` capabilities and `#role` attributes,
//!   which no command ever issued, are removed and their tokens are refused as
//!   unknown.
//!
//! ## The governance entry bodies (pinned canonical CBOR)
//! All composite-signed, `(channelID, epoch)`-bound, and ride the causal log
//! ([`crate::log`]) as `EntryKind::Governance` payloads:
//! - [`cert`] — admin-delegation cert (`0x0003`) + admin-delegation revocation
//!   (`0x000E`).
//! - [`consent`] — consent grant (`0x0004`) + consent revocation (`0x0005`).
//! - [`policy`] — policy-update (`0x0006`, kind = policy-update): the room's retention
//!   (TTL) only. The rotation kind under the same tag, a passphrase-rotation / epoch
//!   bump no command ever wrote, is reserved and refused (V030-32).
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
//!
//! The inbound visibility opt-out and identity-bound invite modes were removed
//! (V030-32): nothing read or issued them. A room is joined with its passphrase
//! (ADR-005) and read by consent.
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
pub mod lifecycle;
pub mod membership;
pub mod policy;
pub mod servicegrant;

pub use capability::{Capability, CapabilitySet};
pub use cert::{AdminCert, AdminRevocation, RevocationReason};
pub use consent::{ConsentGrant, ConsentRevocation};
pub use entry::{GovBody, GovEntry};
pub use evaluator::{DenyReason, Evaluator, Verdict};
pub use genesis::{ChannelPolicy, Genesis, HistoryMode};
pub use lifecycle::{LifecycleKind, RoomLifecycle};
pub use membership::MembershipView;
pub use policy::PolicyUpdate;
pub use servicegrant::ServiceGrantExclusion;
