# Architecture Decision Records

This directory records the architectural decisions for Vox. **Build order is the topological order
of the `Depends on` column** (a partial order); each ADR is buildable once its dependencies are
done. ADR numbering largely follows that order, with one deliberate exception: ADR-008 (the log
primitive) precedes ADR-007 (consent, which is stored on the log) in build order. Start with ADR-001.

| # | Title | Depends on |
|---|-------|-----------|
| [001](ADR-001-vox-foundation-vision-threat-model-and-principles.md) | Foundation — Vision, Threat Model & Principles | — |
| [002](ADR-002-identity-and-key-model.md) | Identity & Key Model | 001 |
| [003](ADR-003-post-quantum-and-crypto-agility-policy.md) | Post-Quantum & Crypto-Agility Policy | 001, 002 |
| [004](ADR-004-pairwise-secure-channel.md) | Pairwise Secure Channel (PQXDH + Double Ratchet) | 002, 003 |
| [005](ADR-005-channel-addressing-and-authenticated-join.md) | Channel Addressing & Authenticated Join (CPace) | 002, 003, 004 |
| [006](ADR-006-group-messaging-sender-keys.md) | Group Messaging — Sender Keys | 003, 004 |
| [008](ADR-008-replicated-authenticated-log-and-sync.md) | Replicated Authenticated Log & Sync | 002, 006 |
| [007](ADR-007-membership-consent-and-admin-governance.md) | Membership, Per-Sender Consent & Admin Governance | 002, 005, 006, 008 |
| [009](ADR-009-deniability-mode.md) | Deniability Mode (per-channel) | 002, 003, 006, 007, 008 |
| [010](ADR-010-at-rest-storage-and-retention.md) | At-Rest Storage & Retention | 002, 007, 008 |
| [011](ADR-011-transport-substrate.md) | Transport Substrate (QUIC) | 002, 004, 008 |
| [012](ADR-012-nat-traversal-and-reachability.md) | NAT Traversal, Bootstrap & Reachability | 005, 011 |
| [013](ADR-013-overlay-tunneling.md) | Overlay Tunneling (TCP-over-Vox) | 002, 007, 011, 012 |
| [014](ADR-014-macos-client.md) | macOS Client (native SwiftUI + Rust core) | 002, 005–010, 012, 013 |
| [015](ADR-015-rust-tui-client.md) | Rust TUI Client (chat, swarm create/join, verification) | 002, 005–010, 012, 013 |

## Tiers

- **Tier 0 — Foundation:** 001
- **Tier 1 — Cross-cutting policy:** 002, 003
- **Tier 2 — Crypto core:** 004, 005, 006
- **Tier 3 — Differentiator + data:** 008, 007, 009, 010 (log before consent)
- **Tier 4 — Network & overlay:** 011, 012, 013
- **Tier 5 — App / platform:** 014, 015

## Status (2026-09-19)

Each ADR's `Status` line is authoritative; this is the roll-up. Every ADR is grounded in a multi-pass
research effort (Signal/PQXDH, Sender Keys/Megolm, MLS, SSB/Hypercore/Merkle-DAG, CPace/PAKE,
QUIC/DCUtR, NAT/IPv6, deniable authentication).

| ADR | Status | Where |
|---|---|---|
| 001 | accepted (governs) | M0 foundation in `vox-core/src/{cbor,wire,suite,hash}.rs` |
| 002 | implemented | M1 `identity/` |
| 003 | implemented | registry `suite.rs`; floor in genesis policy, enforced in PQXDH + join |
| 004 | implemented | M2 `pairwise/` |
| 005 | implemented | M3 `join/` (pure-Rust bucket-sorted Equihash solver, `(200,9)` ≈ 1.1 s / 245 MB) |
| 006 | implemented | M4 `group/` |
| 007 | implemented | M6 `governance/` |
| 008 | implemented | M5 `log/` |
| 009 | implemented, **not enabled** | M7 `deniable/` — formal analysis + `0x000B` wire codec outstanding |
| 010 | implemented | M8 `atrest/` (codecs/mechanisms; no persistence layer yet) |
| 011 | implemented | M9 `transport/` |
| 012 | implemented (primitives) | M10 `nat/` — not composed into the ladder |
| 013 | implemented (library) | M11 `tunnel/` — no CLI surface |
| 014 | proposed — not started | native macOS GUI |
| 015 | implemented (offline shell) | M12 `vox-tui/` — live core is the ADR-016 seam |

**What is missing is the node runtime** that composes the implemented layers (join → transport →
NAT → sync → governance) and gives the TUI a live `CoreHandle`; that is the next capability
(ADR-016). Each ADR's "Known gaps" bullet records its residual drift as of 2026-09-19. Later
capabilities (voice/video, iOS, Linux client, metadata/traffic-analysis resistance, PQ
post-compromise security) are **distinct named capabilities** with their own ADRs — not deferred
increments of the ones here (ADR-003 §Scope).

## Release gates & test-vector obligations (consolidated)

"Ship complete" (the mantra) means a release MUST satisfy every gate below; this is the single
auditable list so none is missed. **Status (2026-09-19)** is recorded per gate so the list is
honest, not aspirational:

- **Canonical serialization (ADR-008):** golden vectors for every struct tag `0x0001–0x0011`; two
  independent implementations must produce byte-identical canonical CBOR. — **UNMET**: only the
  log-entry skeleton is byte-pinned; CBOR primitives have RFC-8949 vectors; no per-tag fixtures.
- **Identity (ADR-002):** test vectors for composite pubkey/sig byte layout and the ML-DSA binding statement.
  — **PARTIAL**: layout asserted structurally with a fixed-seed signer; no pinned known-answer bytes.
- **PQXDH/ratchet (ADR-004):** KDF + AAD test vectors (PQXDH itself is formally verified upstream).
  — **PARTIAL**: one pinned `derive_sk` KAT; ratchet KDFs and AAD constructions have structural tests only.
- **CPace (ADR-005):** Ristretto255+SHA-512 test vectors; Equihash PoW solve/verify vectors. —
  **MET / PARTIAL**: the CFRG Appendix-B CPace vectors are pinned; Equihash is covered by
  solve→verify round-trips against the librustzcash verifier at `(48,5)`, `(96,5)` and the real
  `(200,9)` (CI, release) rather than by published known-answer bytes.
- **Governance (ADR-007):** the deterministic-evaluator golden-vector suite (valid chains,
  over-attenuation, expiry, revoked links, concurrent-conflict + tie-break) — bit-for-bit agreement gate.
  — **MET in-process**: 28+ vectors incl. order-invariance and exact `DenyReason`s; they are Rust
  assertions, not language-neutral fixtures with pinned hashes, which the "two implementations" reading needs.
- **Deniability (ADR-009):** **formal analysis of the DGKA+DSKE construction before shipping**; K-derivation
  and transcript test vectors. — **UNMET** (both); deniable mode is not enabled for shipping.
- **Transport (ADR-011):** cross-version interop matrix (handshake + identity-PoP) as a hard gate. —
  **UNMET**: no second implementation, no matrix, no CI job.
- **Sync (ADR-008):** frontier + Negentropy-v1 interop vectors; the wire error-code table is honored. —
  **PARTIAL**: every wire error code `0x01–0x08` is asserted end-to-end; frames and Negentropy messages are
  round-trip-tested only, with no interop bytes against a reference.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
