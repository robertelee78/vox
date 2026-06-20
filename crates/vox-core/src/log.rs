//! # Replicated authenticated log & sync (ADR-008) — milestone M5
//!
//! The replicated message store: per-author hash-linked logs merged into a
//! causally-ordered Merkle-DAG (a CRDT for causal histories), with anti-entropy
//! sync, render-gating, fork/equivocation handling, per-author quotas, and the
//! personal multi-device self-channel. This is **not** a consensus blockchain
//! (ADR-008 §Decision): there is no global total order and no mining — only
//! per-feed integrity plus causal merge with Strong Eventual Consistency.
//!
//! ## The pieces
//! - [`entry`] — the log entry (tag `0x0001`, domain `vox/log-entry/v1`): the
//!   signed 10-field skeleton over a payload **hash** (so payloads prune while the
//!   skeleton stays verifiable), and the [`entry::Authenticator`] seam (composite
//!   attributable today; ADR-009 deniable in M7).
//! - [`feed`] — the per-author append-only feed (Bamboo-derived): `prev_hash`
//!   contiguous chaining plus the [`feed::lipmaa`] skip-link, full verification,
//!   and logarithmic skip-link certificates for partial replication.
//! - [`dag`] — the cross-author causal Merkle-DAG: causal (not total) ordering,
//!   topological iteration, convergence (two replicas that receive the same
//!   entries converge), and the acceptance predicate + fork/equivocation handling.
//! - [`quota`] — the per-author abuse-resistance quotas (≤1000 entries/hour,
//!   ≤50 MB/epoch, channel-policy-tunable): over-quota entries are dropped, not
//!   relayed, and surfaced as an abuse signal.
//! - [`sync`] — anti-entropy over an abstract byte-stream transport: the frontier
//!   mode (default) and the Negentropy range-reconciliation mode, mode-negotiated
//!   by the `HELLO` bitmap, honoring the M0 wire error codes on hard-fail.
//! - [`negentropy`] — a faithful Negentropy v1 range-based set-reconciliation
//!   codec + engine (Doug Hoyte / NIP-77), keyed by the full 32-byte SHA-256 entry
//!   hash (no truncation).
//! - [`selfchannel`] — the personal self-channel (tag `0x000C`): the `K_self` /
//!   `rendezvous_self` KDFs from the M1 `self_seed`, and the single-author self-log
//!   that carries received SKDMs (M4) and per-device state across an identity's
//!   own shared-root devices.
//!
//! ## Render-gating (ADR-008 §"Render-gating = replicate-all, decrypt-what-you-can")
//! The log stores and replicates ciphertext entries regardless of readability;
//! rendering is gated by whether the holder has keys (M4/M6). M5 stores and
//! replicates everything and exposes the "attempt decrypt → render on success"
//! seam ([`dag::Dag::render`]); the actual decryption is M4/M6.
//!
//! ## Scope boundaries (documented, not stubbed)
//! - **Real QUIC transport** is M9 (ADR-011): M5 is the protocol *logic* over an
//!   abstract [`sync::Transport`]; an in-memory duplex drives the tests.
//! - **Deniable content authenticator** is M7 (ADR-009): the attributable path is
//!   built fully and [`entry::Authenticator`]/[`dag::ForkOutcome`] are the seam.
//! - **Payload TTL policy / at-rest** is M8 (ADR-010): M5 provides *authenticated
//!   pruning* ([`entry::Entry::prune_payload`]) — the mechanism, not the policy.
//! - **Admitted-set population / consent read-gate** is M3/M6 (ADR-005/007): M5
//!   models the admitted set as an input to the acceptance predicate
//!   ([`dag::AdmissionPolicy`]).

pub mod dag;
pub mod entry;
pub mod feed;
pub mod negentropy;
pub mod quota;
pub mod selfchannel;
pub mod sync;
