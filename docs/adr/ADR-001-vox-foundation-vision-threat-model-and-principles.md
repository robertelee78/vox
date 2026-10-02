# ADR-001: Vox Foundation — Vision, Threat Model, and Cross-Cutting Principles

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status:** accepted. It governs every later ADR. The M0 foundation it names (canonical CBOR, wire
registry, suite registry, hashing) is built in `crates/vox-core/src/{cbor,wire,suite,hash}.rs`. The
macOS client of principle 10 (ADR-014) is planned, not built.
**Deciders:** Robert E. Lee <robert@agidreams.us>

## Context

Vox Lux ("Vox") is a serverless, end-to-end-encrypted peer-to-peer overlay for private communication
and arbitrary TCP/IP tunneling, built in Rust. Existing secure messengers depend on central servers
(for prekeys, identity and routing), tie identity to phone numbers or accounts, and treat admission as
a room-level property, so one wrong add exposes all new traffic from everyone (Albrecht, Celi, Dowling
and Jones, IEEE S&P 2023, eprint 2023/485; the "Signalgate" contact mix-up of March 2025 shows the
room-level model makes one misclick sufficient). This ADR fixes the vision, threat model and principles
every later ADR follows. The ADR order is the intended build order.

## Requirements

### Vision

- **V1.** Vox MUST give Signal-grade content confidentiality without a central server, phone-number
  identity or account.
- **V2.** Joining a conversation MUST be as frictionless as opening a magnet link.
- **V3.** The same overlay MUST carry arbitrary byte streams (for example `ssh` over Vox) as well as
  chat.

### Cross-cutting principles (binding on every ADR)

- **Principle 1 (serverless).** Vox MUST NOT depend on a privileged central server. Any node MAY serve as a
  bootstrap or rendezvous point, and Vox MUST NOT require Vox-operated infrastructure. A
  rendezvous substrate MAY be used only to bridge hosts that are both behind NAT and cannot otherwise
  find each other (ADR-012); hosts that can reach each other directly MUST NOT need one.
- **Principle 2 (the channel is the unit).** Every message MUST be broadcast to a channel. A 1:1 chat MUST be
  a two-member channel. There MUST NOT be a separate user-facing pairwise messaging path.
- **Principle 3 (self-sovereign identity).** Identity MUST be rooted in the user's own keys with manual
  fingerprint verification (ADR-002). Vox MUST NOT use accounts, phone numbers or a central key
  directory.
- **Principle 4 (per-sender consent).** Holding a channel's credentials MUST NOT make any member's messages
  readable; each member MUST individually consent to a newcomer reading it (ADR-007).
- **Principle 5 (conventional cryptography).** Vox MUST use standardized, analyzed cryptographic constructions.
  Novelty belongs in the trust model, not the primitives.
- **Principle 6 (hybrid from the start).** Every key agreement and every signature MUST pair a classical
  algorithm with a lattice algorithm, from the first release (ADR-003). Documents MUST state this as
  the construction, not as a guaranteed outcome: the lattice halves holding is an assumption.
- **Principle 7 (chat and tunneling).** Chat and tunneling MUST both be first-class (ADR-011, ADR-013).
- **Principle 8 (license).** Vox MUST be MIT licensed and open source.
- **Principle 9 (capability-driven).** Each capability MUST be researched, specified and defined in an ADR
  before it is built.
- **Principle 10 (Rust-maximal).** Vox MUST be written in Rust to the maximum practical extent: one shared Rust
  core (identity, crypto, log and sync, transport, governance, tunneling) and Rust clients over it,
  including a Rust TUI client (ADR-015). Non-Rust code MAY be used only where an OS requires it for
  native UX or integration (for example a SwiftUI layer over the same core through UniFFI, ADR-014).
  Every client MUST run the one core; a client MUST NOT fork it.

### Threat model

What Vox provides is post-quantum content confidentiality, content authenticity and unforgeable
membership. Every ADR MUST NOT claim more.

- **T1 (on-path network adversary, including a resourced ISP).** Message content MUST be end-to-end
  encrypted under a hybrid construction and authenticated, so recorded ciphertext stays closed to an
  adversary who later breaks only the classical half (harvest-now-decrypt-later, conditional on the
  lattice half holding; ADR-003, ADR-004). Channel membership MUST NOT be forgeable (ADR-005,
  ADR-007).
- **T2 (platform or server operator).** There MUST be no Vox server, account or operator to trust,
  subpoena or be deplatformed by.
- **T3 (wrongly added participant or passphrase holder).** Holding a channel passphrase MUST NOT make
  any member's messages readable (principle 4).
- **T4 (device seizure, at rest).** A powered-off or locked device MUST be protected by at-rest
  encryption and forward secrecy (ADR-010).

### Non-goals

Vox MUST NOT claim the following; each is absent unless a later ADR builds it:

- **N1.** Metadata privacy against a global passive adversary or traffic analysis: who talks to whom,
  when and how much.
- **N2.** Protection of a running, compromised endpoint (malware, keylogger, screen capture on an
  unlocked device).
- **N3.** Protection against coercion of a participant.
- **N4.** Availability against a determined blocker, or censorship circumvention.
- **N5.** Nation-state resistance as a whole.

### Security-property taxonomy

- **S1.** Every ADR MUST state which of these it provides and which it does not, and MUST NOT conflate
  them: PQ confidentiality (ADR-003, ADR-004; passive quantum adversary); classical post-compromise
  security (ADR-004); PQ post-compromise security (ADR-004; not provided today); metadata privacy
  (member-only confidentiality is provided; pattern privacy against a global passive adversary is
  N1).
- **S2.** Content deniability is not provided: deniable rooms were removed (PRD-001 R43; ADR-009).

### Availability model

- **A1.** Vox MUST NOT require an always-on node. A two-member channel needs both members online to
  exchange messages; a channel of three or more needs any two online to propagate the log; a single
  online member MAY queue messages to send but cannot receive (ADR-008, ADR-012).

## Consequences

- No server, account or phone number to trust or be deplatformed from; room-level admission failure
  is avoided by construction (ADR-007).
- Hosts both behind NAT need a decentralized rendezvous layer; zero infrastructure is impossible for
  them.
- Vox inherits the Sender-Keys family's weak post-compromise security (ADR-006, ADR-007).
- Communication patterns are visible to a capable observer (N1).

## Related ADRs

Governs ADR-002 onwards. Directly cited: ADR-002, ADR-003, ADR-004, ADR-005, ADR-006, ADR-007,
ADR-008, ADR-009, ADR-010, ADR-011, ADR-012, ADR-013, ADR-014, ADR-015.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
