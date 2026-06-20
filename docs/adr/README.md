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
| [014](ADR-014-macos-client.md) | macOS Client (the wedge) | 002, 005–010, 012, 013 |

## Tiers

- **Tier 0 — Foundation:** 001
- **Tier 1 — Cross-cutting policy:** 002, 003
- **Tier 2 — Crypto core:** 004, 005, 006
- **Tier 3 — Differentiator + data:** 008, 007, 009, 010 (log before consent)
- **Tier 4 — Network & overlay:** 011, 012, 013
- **Tier 5 — App / platform:** 014

All ADRs are **proposed**; they are grounded in a multi-pass research effort (Signal/PQXDH,
Sender Keys/Megolm, MLS, SSB/Hypercore/Merkle-DAG, CPace/PAKE, QUIC/DCUtR, NAT/IPv6, deniable
authentication). Later capabilities (voice/video, iOS, Linux client, metadata/traffic-analysis
resistance, PQ post-compromise security) are **distinct named capabilities** with their own ADRs —
not deferred increments of the ones here (ADR-003 §Scope).

## Release gates & test-vector obligations (consolidated)

"Ship complete" (the mantra) means a release MUST satisfy every gate below; this is the single
auditable list so none is missed:

- **Canonical serialization (ADR-008):** golden vectors for every struct tag `0x0001–0x0011`; two
  independent implementations must produce byte-identical canonical CBOR.
- **Identity (ADR-002):** test vectors for composite pubkey/sig byte layout and the ML-DSA binding statement.
- **PQXDH/ratchet (ADR-004):** KDF + AAD test vectors (PQXDH itself is formally verified upstream).
- **CPace (ADR-005):** Ristretto255+SHA-512 test vectors; Equihash PoW solve/verify vectors.
- **Governance (ADR-007):** the deterministic-evaluator golden-vector suite (valid chains,
  over-attenuation, expiry, revoked links, concurrent-conflict + tie-break) — bit-for-bit agreement gate.
- **Deniability (ADR-009):** **formal analysis of the DGKA+DSKE construction before shipping**; K-derivation
  and transcript test vectors.
- **Transport (ADR-011):** cross-version interop matrix (handshake + identity-PoP) as a hard gate.
- **Sync (ADR-008):** frontier + Negentropy-v1 interop vectors; the wire error-code table is honored.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
