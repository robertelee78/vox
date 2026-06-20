# ADR-001: Vox Foundation — Vision, Threat Model, and Cross-Cutting Principles

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: foundation, vision, threat-model, principles

## Context

Vox Lux ("Vox" for short) is a serverless, end-to-end-encrypted peer-to-peer overlay for private
communication and arbitrary TCP/IP tunneling, built in Rust.

The motivating problems with existing secure messengers:

- **Central-server dependency.** Signal, Matrix, WhatsApp et al. depend on servers for prekey
  distribution, identity, and message routing — a metadata chokepoint, censorship target, and
  trust anchor the user does not control.
- **Identity tied to phone numbers / accounts.** Binds a secure identity to a SIM and a
  real-world identity.
- **Room-level admission ("Signalgate," March 2025).** In Signal/Megolm/Sender-Keys, admission
  is a room-level property: one wrong add instantly exposes *all new* traffic from *everyone*,
  because group membership is not cryptographically authenticated (Albrecht et al., IEEE S&P
  2023; eprint 2023/485, 2023/1300).

The author distrusts implementations with central servers or closed source, and requires full
control and customization. This ADR fixes the vision, threat model, and cross-cutting
principles that govern all subsequent ADRs. It is the root of a dependency-ordered series; the
order of ADRs is the intended build order.

## Decision

**Vision.** Signal-grade confidentiality without Signal's server, phone-number identity, or
account requirement — joining a conversation is as frictionless as opening a magnet link, and
the same overlay carries arbitrary byte streams (e.g. `ssh` over Vox), not just chat.

**Cross-cutting principles (binding on all ADRs):**

1. **Serverless = no *privileged* central server.** Some minimal bootstrap/rendezvous substrate
   is provably unavoidable (see ADR-012); the requirement is that it be decentralized and
   user-runnable — any node may serve, no Vox-operated infrastructure. "Serverless" means no
   server anyone is *forced* to trust, not "no infrastructure."
2. **The channel is the unit of communication.** All messages are broadcast to a channel; a 1:1
   chat is just a two-member channel. There is no special pairwise messaging path.
3. **Self-sovereign identity.** Identity is rooted in the user's own GPG/Ed25519 keys with manual
   fingerprint verification. No accounts, no phone numbers, no central key directory. (ADR-002)
4. **Per-sender consent admission is the headline trust model.** Possessing channel credentials
   grants nothing readable; each member individually consents to a newcomer. (ADR-007)
5. **Conventional, well-reviewed cryptography.** Novelty lives in the *trust model*, not the
   primitives. Prefer standardized, analyzed constructions.
6. **Post-quantum from the start.** Hybrid (classical + PQ) throughout. (ADR-003)
7. **Chat and tunneling are both first-class.** (ADR-011, ADR-013)
8. **MIT licensed.** Maximally permissive; open source is a requirement, not a preference.
9. **Capability-driven development.** Each capability is researched, specified, and defined
   before it is built; the ADR series is the spine.
10. **Rust-maximal implementation.** Vox is built in Rust to the maximum practical extent: a single
    shared Rust **core** (identity, crypto, log/sync, transport, governance, tunneling) and Rust
    **clients** over it — including a first-class **Rust TUI client** (chat, swarm create/join,
    verification, consent; ADR-015). Non-Rust code is the deliberate, scoped exception where an OS
    demands it for native UX/integration — e.g. the SwiftUI layer of the macOS client (ADR-014),
    which still runs the same Rust core via UniFFI. Multiple clients are peers over one core, not
    forks of it.

**Threat model (maximal — all four adversaries in scope):**

- **Nation-state / network observer** — traffic analysis, censorship. Metadata confidentiality
  to non-members is a *phased* goal (encryption + padding first; onion/mixnet-grade
  traffic-analysis resistance is a later capability). "Hide in plain sight" traffic shaping is a
  future interest.
- **Platform operators** — addressed by the serverless, open-source core.
- **Wrongly-added / passphrase-holder** — the Signalgate case; addressed by per-sender consent
  (ADR-007).
- **Device seizure / local compromise** — addressed by at-rest "double-lock" encryption and
  forward secrecy (ADR-010).

**Security-property taxonomy (named to keep later ADRs precise).** These are distinct guarantees and
must never be conflated: **PQ confidentiality** (harvest-now-decrypt-later resistance, ADR-003/004,
passive-quantum), **classical post-compromise security** (DH-ratchet healing, ADR-004), **PQ
post-compromise security** (phased, not day-one, ADR-004), **content deniability** (per-channel,
ADR-009), and **metadata privacy** against a network observer (phased; member-only first,
traffic-analysis resistance later). Each ADR states which of these it does and does not provide.

**Availability model.** Availability is emergent from who is online, with no always-on node
required: a two-member channel requires both members online; a 3+-member channel needs any two
online to propagate the log; a single online member is an outbox (can queue-to-send, cannot
receive). This is accepted as an inherent property (see ADR-008, ADR-012).

## Consequences

### Positive
- Maximal user autonomy: no server, account, or phone number to trust or be deplatformed from.
- Structurally avoids the Signalgate room-level-admission failure (ADR-007).
- One overlay serves both private messaging and arbitrary tunneling.

### Negative
- No "message someone while everyone is offline" without at least one reachable peer/own node.
- A minimal, decentralized bootstrap/rendezvous layer is unavoidable (ADR-012); strict
  zero-infrastructure is impossible.
- Inherits known limitations of the Sender-Keys family (weak PCS, ADR-006/ADR-007).
- Full nation-state traffic-analysis resistance is deferred, not solved in the first iteration.

### Neutral
- Positions Vox in the serverless/log-replicated family (Secure Scuttlebutt, Berty, Briar,
  SimpleX, Matrix event-DAG) rather than against Signal directly; the differentiator is
  per-sender consent + Signal-grade pairwise crypto.

## Links
- Governs: ADR-002 through ADR-014.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
