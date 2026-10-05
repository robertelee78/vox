# Architecture Decision Records

This directory records the architectural decisions for Vox. Each ADR is a set of normative
requirements: the key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD
NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in these documents are to be interpreted
as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as
shown here. An ADR states current decided behaviour; GitHub history and the issues keep how it got
there. Review transcripts, run logs and analyses of an ADR MUST NOT be committed here.

**Build order is the topological order of the `Depends on` column** (a partial order); each ADR is buildable once its dependencies are
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
| [009](ADR-009-deniability-mode.md) | Deniability Mode (per-channel) — **withdrawn** (R43) | 002, 003, 006, 007, 008 |
| [010](ADR-010-at-rest-storage-and-retention.md) | At-Rest Storage & Retention | 002, 007, 008 |
| [011](ADR-011-transport-substrate.md) | Transport Substrate (QUIC) | 002, 004, 008 |
| [012](ADR-012-nat-traversal-and-reachability.md) | NAT Traversal, Bootstrap & Reachability | 005, 011 |
| [013](ADR-013-overlay-tunneling.md) | Overlay Tunneling (TCP-over-Vox) | 002, 007, 011, 012 |
| [014](ADR-014-macos-client.md) | The macOS App (SwiftUI client of the daemon, login item, LAN helper, packaging, proof) — proposed | 013, 015, 017, 018, 026, 028 |
| [015](ADR-015-rust-tui-client.md) | Rust TUI Client (chat, swarm create/join, verification) | 002, 005–010, 012, 013 |
| [016](ADR-016-node-runtime.md) | Node Runtime — composing the core (persistence, rendezvous service, join over the network, sync, headless anchor) | 002, 003, 005–008, 010–013, 015 |
| [017](ADR-017-room-bound-services.md) | Room-Bound Services (the Tor-hidden-service equivalent) | 005, 007, 012, 013, 016 |
| [018](ADR-018-quality-bar-and-product-proof.md) | Quality Bar — the Product-Proof Harness is the Test Authority | 001 |
| [019](ADR-019-pure-rust-tls-provider.md) | A Pure-Rust TLS Crypto Provider | 001, 003, 011 |
| [020](ADR-020-agent-comms.md) | Agent Comms (a room-based messaging app for AI coding agents across hosts) | 007, 008, 012, 016, 017, 018 |
| [021](ADR-021-work-item-interop.md) | Work-Item Interop (the contract Vox exposes to an external work tracker) | 008, 018, 020 |
| [022](ADR-022-datagram-flows.md) | Datagram Flows (UDP tunnels, relays that behave like UDP, the app API) | 011, 012, 013, 016, 017, 020 |
| [023](ADR-023-room-lifecycle.md) | Room Lifecycle (one order, retention, key delivery through members, dumb anchors) | 006, 007, 008, 010, 012, 016 |
| [024](ADR-024-tapered-congestion-control.md) | Tapered Congestion Control (Cubic → loss-aware Cubic → BBR, both ways) | 011 |
| [025](ADR-025-sync-scheduling-switch-not-hub.md) | Sync Is Scheduled Like a Switch, Not a Hub (full duplex, receive classes, backoff kinds) | 008, 011, 016 |
| [026](ADR-026-daemon-and-nodes.md) | The Daemon and the Nodes That Use It (one presence per account, nodes attach and detach) | 002, 010, 011, 012, 016 |
| [028](ADR-028-one-experience-keyring-rooms-services-files.md) | One Experience (keyring, rooms, services and files in the TUI and the app; look; install) — accepted for v0.4.0 | 005, 007, 014, 015, 016, 017, 020, 023, 026 |

## Tiers

User documentation: [ADR-027 — One user manual, automatically skinned by voxlux.us](ADR-027-user-manual-and-website-skin.md)
is accepted for implementation. ADR-026 is reserved on `rearch/v030`; this documentation decision
does not import that branch's unreleased command surface into the released manual.

- **Tier 0 — Foundation:** 001
- **Tier 1 — Cross-cutting policy:** 002, 003
- **Tier 2 — Crypto core:** 004, 005, 006
- **Tier 3 — Differentiator + data:** 008, 007, 010 (log before consent); 009 is withdrawn
- **Tier 4 — Network & overlay:** 011, 012, 013
- **Tier 5 — App / platform:** 014, 015
- **Tier 6 — Integration:** 016 (the runtime that composes Tiers 1–5 into a running node), 026 (the
  daemon that hosts an account's nodes on one network presence)
- **Tier 7 — Product surface:** 017 (what a person actually does with the overlay), 018 (how a
  capability is proved to work)
- **Tier 8 — Applications on the layer:** 020 (agent comms), 021 (the work-item interop contract an
  external tracker consumes), 022 (datagram flows and the app API).
- **Tier 9 — Behaviour under load:** 023 (room lifecycle), 024 (congestion control), 025 (sync
  scheduling).

## Status (integrate/v0.3.0)

Each ADR's own `Status` line is authoritative, and marks per requirement what is built and what is
planned. This is the roll-up.

| ADR | Status |
|---|---|
| 001 | accepted; governs every later ADR |
| 002 | accepted; built (`identity/`, `node::prekeys`) except where marked |
| 003 | accepted; built (`suite.rs`, the floor in genesis policy) |
| 004 | accepted; built (`pairwise/`) |
| 005 | accepted; built (`join/`, `node::joinstream`) except where marked |
| 006 | accepted; built (`group/`) except the known gaps it lists |
| 007 | accepted; governance is only the creator or an admin setting the room's retention and ending the room, built; the strict member cap (G-22) is not built |
| 008 | accepted; built (`log/`); range reconciliation over the network and the self-channel are planned; golden vectors are open |
| 009 | **withdrawn** (R43); the deniable code is removed (b0f82185) |
| 010 | accepted; built (`atrest/`, `node/`) except where marked planned |
| 011 | built (`transport/`), including the OID's UUID arc and the observed group (#382); the interop matrix is not; the identity exchange (req 27–40) is decided, not built (#397) |
| 012 | accepted; all four rungs built, a relay-only pair taking its circuit at once |
| 013 | accepted; built except where marked |
| 014 | proposed; only the embedded node over FFI (`crates/vox-ffi`) is built |
| 015 | implemented in part (`crates/vox-tui`), each requirement marked |
| 016 | accepted; M13–M15.2c and M18.1 built; open defects listed in the ADR |
| 017 | accepted; built, including `service.node.room.vox` addressing (#339); `vox serve` into an existing room is not |
| 018 | accepted, in force: only real use of the shipped binary proves a claim; tests run on demand |
| 019 | proposed; nothing built |
| 020 | accepted; built (`vox-agentcomms`, the hook, wake and claims) except where marked |
| 021 | accepted; M21.1–M21.10 built |
| 022 | accepted; M22.1–M22.5 built; calls are an app |
| 023 | accepted; M23.1–M23.6 and leaving and ending a room (RL-8) built, except where marked |
| 024 | accepted, speed only; M24.1–M24.5 built, the taper is the default controller |
| 025 | accepted; built as V210-34 (#209) |
| 026 | accepted 2026-10-03, **not built** (#397); amends 005, 008, 010, 011, 012, 013, 014, 015, 016, 017, 020, 021 |

## Conformance-vector obligations

These obligations come from the ADRs named. None is a release gate: tests are real use of the
shipped binary, run on demand (ADR-018). Whether each is kept as a real-binary check or dropped is
open with the decider (V030-29 questions 12, 19, 30 and 32).

- **Canonical serialization (ADR-008):** golden vectors for every struct tag `0x0001`–`0x001E` (reserved tags excepted). No
  per-tag fixture exists.
- **Identity (ADR-002):** composite public key and signature layout, and the ML-DSA binding statement.
  No pinned known-answer bytes exist.
- **PQXDH and ratchet (ADR-004):** KDF and AAD vectors. No pinned known-answer bytes exist.
- **CPace (ADR-005):** the CFRG Ristretto255+SHA-512 vectors and Equihash solve/verify vectors. No
  real-binary proof exists.
- **Governance (ADR-007):** the deterministic-evaluator vector suite. None exists since the unit
  tests were deleted (df850734).
- **Transport (ADR-011):** a cross-version interop matrix (handshake and identity proof of
  possession). No second implementation, matrix or job exists.
- **Sync (ADR-008):** frontier and Negentropy-v1 interop vectors. Range mode never runs over a
  transport.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
