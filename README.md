# Vox Lux

**A serverless, end-to-end-encrypted peer-to-peer overlay for private communication and tunneling.**

Vox lets a small, trusted group hold a private channel by sharing a channel ID and passphrase —
no central server, no accounts, no phone numbers. Identity is rooted in your own GPG/Ed25519 keys.
Beyond messaging, Vox is an overlay *transport*: it carries arbitrary TCP/IP between members
(e.g. `ssh` over Vox), not just chat. It is post-quantum from the first line of code.

---

## The problem

Mainstream secure messengers force trade-offs Vox refuses to make:

- **They depend on central servers** for prekey distribution, identity, and routing — a metadata
  chokepoint, a censorship target, and a trust anchor you do not control.
- **They tie identity to a phone number or account**, binding your secure identity to a SIM and a
  real-world persona.
- **Admission is room-level.** In Signal/Matrix/WhatsApp, group membership is not cryptographically
  authenticated: a single wrong add instantly exposes *all new* traffic from *everyone* (the
  March-2025 "Signalgate" failure; Albrecht et al., IEEE S&P 2023).

## What makes Vox different

- **Per-sender consent admission ("anti-Signalgate").** Joining a channel — even with the correct
  channel ID and passphrase — grants you *nothing readable*. Each existing member *individually*
  consents to a newcomer; until a member consents, their messages stay undecryptable to that
  newcomer, forever if they never consent. Visibility fills in monotonically, per sender. No single
  wrong add can expose the room. *(ADR-007)*
- **Truly serverless.** No *privileged* central server. Discovery is magnet-link style over a P2P
  swarm; any node can optionally act as a bootstrap/rendezvous point, and you run your own. *(ADR-012)*
- **The channel is the unit.** Every message is broadcast to a channel's append-only, hash-linked
  log; a 1:1 chat is simply a two-member channel. Messages you cannot decrypt replicate but are not
  rendered. *(ADR-006, ADR-008)*
- **Self-sovereign identity.** GPG/Ed25519 keys with manual fingerprint verification — no accounts,
  no phone numbers, no directory. Per-channel pseudonymous identities are your choice. *(ADR-002)*
- **Post-quantum from the start.** Hybrid (classical + post-quantum) key agreement and signatures,
  designed against "harvest now, decrypt later." *(ADR-003)*
- **Per-channel deniability.** Optionally, message content is authored deniably (no transferable
  proof of authorship to outsiders) while membership and governance stay verifiable. *(ADR-009)*
- **Chat *and* tunneling.** A first-class encrypted overlay for arbitrary byte streams — `ssh` over
  Vox and beyond — alongside messaging. *(ADR-011, ADR-013)*

## How it works

Each layer is a decision record in `docs/adr/`, built in dependency order:

1. **Identity & keys** *(ADR-002)* — GPG/Ed25519 root, role-separated keys (governance vs message
   vs key-agreement), per-channel identity selection, hybrid PQ co-keys.
2. **Post-quantum policy** *(ADR-003)* — hybrid everywhere (X25519+ML-KEM, Ed25519+ML-DSA),
   versioned/negotiable ciphersuites, two normative PQXDH hardening rules.
3. **Pairwise secure channel** *(ADR-004)* — PQXDH key agreement + Double Ratchet, forward secrecy.
4. **Channel addressing & join** *(ADR-005)* — channelID (rendezvous) + passphrase (CPace PAKE,
   offline-dictionary-resistant), cleanly separated so the DHT lookup never leaks the passphrase.
5. **Group messaging** *(ADR-006)* — channel-scoped Sender Keys, per-author distribution,
   (channelID, epoch) binding.
6. **Membership, consent & governance** *(ADR-007)* — per-sender consent, a signed admin/membership
   certificate tree rooted at channel creation, admin-set policy, revocation via key rotation and
   passphrase-epoch.
7. **Replicated log & sync** *(ADR-008)* — per-author hash-linked logs in a causal Merkle-DAG (not a
   consensus blockchain), render-gating, anti-entropy sync, TTL pruning via payload-hash signing.
8. **Deniability** *(ADR-009)* — per-channel content-authorship deniability via per-epoch ephemeral
   signing keys.
9. **At-rest storage** *(ADR-010)* — double-lock encryption (GPG key *and* channel passphrase),
   admin-set retention, app-lock for device seizure.
10. **Transport** *(ADR-011)* — QUIC substrate with stream multiplexing + datagrams; interactive and
    bulk traffic isolated.
11. **NAT traversal & bootstrap** *(ADR-012)* — IPv6-first, then automatic port-mapping, then
    DCUtR hole-punching, with a user-runnable rendezvous; honest about the limits.
12. **Overlay tunneling** *(ADR-013)* — arbitrary TCP/IP between members (`ssh` over Vox), authorized
    by channel membership and consent.
13. **macOS client** *(ADR-014)* — the first client surface over the Rust core.

## Threat model

Vox claims exactly what its controls deliver — **post-quantum content confidentiality, content
authenticity, and unforgeable membership** — and is explicit about what it does not.

**Defended:** an **on-path network adversary** (including a resourced ISP) — content is end-to-end,
post-quantum-hybrid encrypted and authenticated, and channel membership cannot be forged;
**platform / server operators** — there is none to trust or be deplatformed by; a **wrongly-added
participant / passphrase holder** (the "Signalgate" case) — per-sender consent gates readability per
author; and **device seizure at rest** (a powered-off or locked device) — double-lock at-rest
encryption plus forward secrecy.

**Explicit non-goals (absent until a future ADR builds them):** metadata privacy / traffic analysis
against a global passive adversary (content is protected, communication *patterns* are not); a
running, compromised endpoint (malware/keylogger); coercion of a participant; and availability
against a determined blocker. Vox therefore does **not** claim resistance to a nation-state as a
holistic adversary — that would require all of the above. See ADR-001 for the full model.

## Availability

Availability is emergent, with no always-on infrastructure required: a two-member channel needs both
members reachable; a 3+-member channel needs any two online to propagate the log; a lone online
member is an outbox. A strictly zero-infrastructure overlay is provably impossible for cold-start
discovery and worst-case NAT, so Vox reduces the unavoidable minimum to a decentralized, user-runnable
bootstrap/rendezvous any node can provide. See ADR-001 and ADR-012.

## Architecture decisions

All decisions live in [`docs/adr/`](docs/adr/) and are indexed in
[`docs/adr/README.md`](docs/adr/README.md). The series is dependency-ordered: the numbering is the
build order. Every ADR is grounded in a multi-pass, citation-backed research effort.

## Repository layout

```
docs/adr/      Architecture Decision Records (the design spine)
README.md      This file
LICENSE        MIT
```

Rust crates (core library, daemon, clients) will be added as their capabilities are implemented.

## Building

There is no build yet — implementation begins once the ADR series is complete. Vox will be written in
Rust (a headless core library plus platform clients). The first client targets macOS; Linux and iOS
follow as their own capabilities.

## Contributing

Vox is developed capability by capability: each capability is researched, specified as an ADR, and
only then implemented to completion. Start by reading ADR-001, then the ADR that covers the area you
want to work on. Discussion of a decision belongs in (or alongside) its ADR.

## Engineering principles

These are binding on all work in this repository:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a
  feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it:
  no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in
  front of a client.

## License

[MIT](LICENSE) © Robert E. Lee
