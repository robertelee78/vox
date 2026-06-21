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

**Threat model (scoped to what the controls actually enforce).** Vox defends a specific, bounded set
of adversaries and is explicit about the ones it does *not* — so the model never implies a control
that does not exist. What Vox provides is **post-quantum content confidentiality, content
authenticity, and unforgeable membership**; that is a real, bounded property, not blanket protection.

Defended adversaries:

- **On-path network adversary (passive or active), including a resourced ISP.** Message *content* is
  end-to-end encrypted with post-quantum-hybrid confidentiality (harvest-now-decrypt-later resistant,
  ADR-003/004) and authenticated, and channel *membership* cannot be forged (ADR-005/007). Such an
  adversary cannot read or tamper with content, or inject itself into a channel. It *can* still
  observe communication metadata (see non-goals).
- **Platform / server operator.** Eliminated by construction: there is no Vox server, account, or
  operator to trust, subpoena, or be deplatformed by (serverless, open-source core).
- **Wrongly-added participant / passphrase holder (the "Signalgate" case).** Holding the channel
  passphrase does not make your messages readable: per-sender consent (ADR-007) gates readability per
  author, independent of admission.
- **Device seizure / at-rest local access (a powered-off or locked device).** Addressed by the
  at-rest "double-lock" encryption and forward secrecy (ADR-010). At-rest only — a *running,
  compromised* device is a non-goal below.

**Explicit non-goals (stated so the model is honest, not aspirational — these are simply absent until
and unless a future ADR builds them):**

- **Metadata privacy against a global passive adversary / traffic analysis.** Who-talks-to-whom,
  when, and how much is *not* hidden from an observer who can watch enough of the network. Content is
  protected; communication patterns are not. Onion/mixnet-grade traffic-analysis resistance and
  traffic shaping are a possible future capability, not a current guarantee.
- **A running, compromised endpoint.** Malware, a keylogger, or a screen-grabber on a live, unlocked
  device defeats any messenger; the at-rest protections do not apply to a hot device with keys in
  memory.
- **Coercion of a participant.** Vox cannot stop a member compelled (legally or physically) to hand
  over keys or content; content deniability (ADR-009) limits cryptographic *proof* to third parties,
  not disclosure by a participant.
- **Availability against a determined blocker.** An adversary able to drop or block traffic can deny
  availability; Vox targets confidentiality/authenticity, not censorship circumvention, in this
  iteration.
- **"Nation-state" as a holistic adversary.** A state-level actor combines global traffic analysis,
  endpoint implants, supply-chain access, and coercion — the items above. Vox defends none of those
  as a bundle and therefore does **not** claim nation-state resistance. It gives a user facing a
  powerful adversary post-quantum content confidentiality and unforgeable membership — bounded, real,
  and not a substitute for the missing controls.

**Security-property taxonomy (named to keep later ADRs precise).** These are distinct guarantees and
must never be conflated: **PQ confidentiality** (harvest-now-decrypt-later resistance, ADR-003/004,
passive-quantum), **classical post-compromise security** (DH-ratchet healing, ADR-004), **PQ
post-compromise security** (phased, not day-one, ADR-004), **content deniability** (per-channel,
ADR-009), and **metadata privacy** against a network observer (member-only confidentiality is
provided; pattern/traffic-analysis privacy against a global passive adversary is an explicit non-goal
today, not merely "later"). Each ADR states which of these it does and does not provide.

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
- Metadata privacy / traffic-analysis resistance is an explicit non-goal today: Vox protects content
  and membership, not communication patterns. Nation-state resistance is not claimed (see the threat
  model's non-goals).

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
