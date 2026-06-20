# Vox

**A serverless, end-to-end-encrypted peer-to-peer overlay for private communication and tunneling.**

Vox lets a small, trusted group establish a private channel by sharing a channel ID and
passphrase — no central server, no accounts, no phone numbers. Identity is rooted in your own
GPG/Ed25519 keys. Beyond messaging, Vox is an overlay *transport*: it can carry arbitrary
TCP/IP between members (e.g. `ssh` over Vox), not just chat.

> **Status: design phase.** Vox is a ground-up Rust redesign of an earlier Go prototype
> ("Vox Lux"). The architecture is being specified as a series of Architecture Decision
> Records (see `docs/adr/`) before implementation. Nothing here is built yet.

## What makes Vox different

- **Per-sender consent admission ("anti-Signalgate").** Joining a channel — even with the
  correct channel ID and passphrase — grants you *nothing* readable by default. Each existing
  member individually consents to a newcomer; until a member consents, their messages stay
  undecryptable to that newcomer. No single wrong add exposes the room.
- **Truly serverless.** No privileged central server. Discovery is magnet-link style over a
  P2P swarm; any node can optionally act as a bootstrap/rendezvous point, and you can run your
  own.
- **The channel is the unit.** All messages are broadcast to a channel's append-only,
  hash-linked log; a 1:1 chat is just a two-member channel. Messages you can't decrypt sync
  but don't render.
- **Your keys, your identity.** GPG/Ed25519 identity with manual fingerprint verification.
  Per-channel pseudonymous identities are up to you.
- **Post-quantum from the start.** Hybrid (classical + post-quantum) key agreement and
  signatures, designed against "harvest now, decrypt later."
- **Chat *and* tunneling.** A first-class encrypted overlay for arbitrary byte streams
  alongside messaging.

## Design principles

- No central servers and no closed source — these are requirements, not preferences.
- Strong, conventional, well-reviewed cryptography; novelty lives in the trust model, not the primitives.
- Capability-driven: each capability is researched, specified, and defined before it is built.

## Platforms

macOS, Linux, and iOS are the intended targets. The first client is macOS; computer-to-computer
is the starting point.

## Documentation

Architecture Decision Records live in `docs/adr/`. Start with ADR-001 for the vision, threat
model, and cross-cutting decisions.

## License

[MIT](LICENSE)
