# ADR-014: macOS Client (the Wedge)

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: client, macos, ux, wedge, consent-ui

## Context

The first concrete product surface and primary use case (ADR-001): the author and his wife
communicating privately across their devices, starting on macOS (the author has an Apple developer
account). Platforms are macOS, Linux, and iOS; computer-to-computer is the starting point, and the
macOS client is the wedge that proves the whole stack end-to-end.

## Decision

**Ship a macOS client over the Rust core.** The protocol core (ADR-002…ADR-012) is a headless,
well-tested Rust library; the macOS client is a thin app on top.

**v1 client capabilities (the wedge):**
- Generate/import a GPG/Ed25519 identity; select a per-channel identity key (ADR-002).
- Create or join a channel via channelID + passphrase (ADR-005); run one's own node / configure
  the always-on box as rendezvous/relay (ADR-012).
- View channel members and their keys/fingerprints; verify fingerprints.
- **Per-sender consent UI** — individually consent to (and revoke) each member; clearly represent
  per-device keys where members use them (ADR-007, ADR-002).
- Exchange text messages and files over the channel (ADR-006/ADR-008).

**Deferred to later capabilities/ADRs:** voice/video (reuse the datagram path, ADR-011/013);
overlay tunneling surfacing (ADR-013); iOS client (background-P2P constraints make it materially
harder — a separate approach); Linux client; mobile.

**iOS reality.** iOS aggressively suspends background P2P/DHT sockets, so a true serverless iOS
client is hard (it's why Briar has no real iOS app). The user's own always-on node (ADR-012) is the
natural enabler when iOS is tackled; the author has even floated Linux phones to escape platform
lockdown. Out of scope for v1.

## Consequences

### Positive
- Delivers the real-world wedge (private comms with spouse) and proves the full pipeline end-to-end.
- Headless Rust core keeps all other platforms/clients buildable on one tested foundation.
- The consent UI makes the headline differentiator (ADR-007) tangible to users.

### Negative
- macOS-first leaves iOS — arguably the spouse's likely device — for a harder later phase.
- Making per-sender consent and fingerprint verification understandable to non-experts is a real UX challenge.

### Neutral
- File transfer, voice/video, tunneling UI, and other clients are sequenced as later capabilities.

## Links
**Depends on**: ADR-002, ADR-005, ADR-006, ADR-007, ADR-008, ADR-009, ADR-010, ADR-012.
- First user-facing surface of the capability series.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
