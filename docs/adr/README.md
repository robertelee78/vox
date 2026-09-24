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
| [016](ADR-016-node-runtime.md) | Node Runtime — composing the core (persistence, rendezvous service, join over the network, sync, headless anchor) | 002, 003, 005–008, 010–013, 015 |
| [017](ADR-017-room-bound-services.md) | Room-Bound Services (the Tor-hidden-service equivalent) | 005, 007, 012, 013, 016 |
| [018](ADR-018-quality-bar-and-product-proof.md) | Quality Bar — the Product-Proof Harness is the Test Authority | 001 |
| [019](ADR-019-pure-rust-tls-provider.md) | A Pure-Rust TLS Crypto Provider | 001, 003, 011 |
| [020](ADR-020-agent-comms.md) | Agent Comms (a room-based messaging app for AI coding agents across hosts) | 007, 008, 012, 016, 017, 018 |
| [021](ADR-021-work-item-interop.md) | Work-Item Interop (the contract Vox exposes to an external work tracker) | 008, 018, 020 |

## Tiers

- **Tier 0 — Foundation:** 001
- **Tier 1 — Cross-cutting policy:** 002, 003
- **Tier 2 — Crypto core:** 004, 005, 006
- **Tier 3 — Differentiator + data:** 008, 007, 009, 010 (log before consent)
- **Tier 4 — Network & overlay:** 011, 012, 013
- **Tier 5 — App / platform:** 014, 015
- **Tier 6 — Integration:** 016 (the runtime that composes Tiers 1–5 into a running node)
- **Tier 7 — Product surface:** 017 (what a person actually does with the overlay), 018 (how a
  capability is proved to work)
- **Tier 8 — Applications on the layer:** 020 (agent comms), and 021 (the work-item interop contract an
  external tracker consumes). 020 is the first ADR in the app tier: chat's
  semantics still live inside `vox-core`, and extracting them into a sibling `vox-chat` crate is the
  follow-on this tier anticipates.

## Status (2026-09-24)

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
| 012 | implemented | M10 `nat/`, composed into the ladder by ADR-016 M14.8–M14.10 + M15.1c (pinhole → UPnP-IGD → hole punch → anchor relay); real-router UPnP validation still pending |
| 013 | implemented | M11 `tunnel/`; CLI surface landed with M16.1 (`vox service`, `vox grant`, `vox forward`) |
| 014 | proposed — not started | native macOS GUI |
| 015 | implemented | M12 + M13.5 `vox-tui/` — embedded node, network verbs wired; §Distribution's install/update model landed 2026-09-21 (`install.sh`, `vox update`, three targets, macOS signed + notarized) |
| 016 | implemented (M13–M15) | node runtime: M13 single device ✓, M14 two machines over the real network ✓, M15 anchors + headless anchor ✓ |
| 017 | implemented (M17.1–M17.3) | room-bound services: genesis service grant, `vox serve`/`vox connect`, `.vox` names resolved by the `vox up` SOCKS5 entry point |
| 018 | accepted — **in force** | quality bar: unit tests removed (M18.2 ✓), distribution proved as built (M18.2a ✓), the node/edge/journey harness outstanding (M18.3) |
| 019 | proposed — not started | pure-Rust TLS crypto provider |
| 020 | partly implemented | agent comms: `crates/vox-agentcomms` over the `vox-core` IPC/event fan-out and the trust keyring; M19.1–M19.9 done. Its claim protocol is corrected by ADR-021; open defects F12, F14, F15 recorded there. No wire change. |
| 021 | implemented (M21.1–M21.8) | work-item interop: session-scoped claims, pending handoffs, bound renewals, op ids, the exact-version gate, a gapless `tail --json`, `board --json`, structured `post`. Vox holds no work state; an external tracker owns it. No wire change. |

**The node runtime that composes the layers is in.** ADR-016 landed through M15 — join, per-sender
consent and log sync run between separate hosts over QUIC, through the full NAT ladder, relayed by an
anchor you run yourself — and ADR-017 landed through M17.3, so a room-bound TCP service is reachable
by its `.vox` name through a loopback SOCKS5 proxy. **What is missing** is the proof harness that will
qualify releases (ADR-018 M18.3), golden **wire-byte** vectors for the ADR-008 struct tags (see the
gates below; `v0.1.0`'s bytes are now what `v0.2.0` must not break), re-keying for a member first met
off the join path, and the native macOS client (ADR-014, not started). Later capabilities
(voice/video, iOS, metadata/traffic-analysis resistance, PQ post-compromise security) are **distinct
named capabilities** with their own ADRs — not deferred increments of the ones here (ADR-003 §Scope).

## Release gates & test-vector obligations (consolidated)

"Ship complete" (the mantra) means a release MUST satisfy every gate below; this is the single
auditable list so none is missed. Status is recorded per gate so the list is honest, not
aspirational.

**`v0.1.0` was cut on 2026-09-21 with the canonical-serialization gate still UNMET.** That is stated
here rather than quietly carried: from `v0.1.0` on, these bytes are what a later version must not
break, so the golden wire-byte vectors stop being a future obligation and become a compatibility
debt with a known start date.

- **Canonical serialization (ADR-008):** golden vectors for every struct tag `0x0001–0x0012`; two
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
  **PARTIAL**: every wire error code `0x01–0x09` is asserted end-to-end (`0x09 TransportFailed` was added
  2026-09-20 — a transport failure used to be reported as a protocol-version mismatch); frames and
  Negentropy messages are round-trip-tested only, with no interop bytes against a reference. Range mode
  itself is tested in memory and **never runs over a transport** — ADR-008's own first known gap.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
