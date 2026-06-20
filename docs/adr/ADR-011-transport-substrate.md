# ADR-011: Transport Substrate

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: transport, quic, multiplexing, datagrams, tunneling

## Context

Vox must carry two very different workloads over one overlay (ADR-001): low-latency *interactive*
tunnels (e.g. `ssh` over Vox, ADR-013) and *store-and-forward* log replication (ADR-008), with
different reliability/latency contracts, without one degrading the other. It must compose with the
crypto core (ADR-004) and the NAT/connectivity layer (ADR-012).

## Decision

**Connection substrate = QUIC.** A single QUIC connection provides built-in security plus
transport-level multiplexing of independent, ordered, reliable streams with no head-of-line
blocking between streams (RFC 9000/9308). With QUIC, no separate stream muxer is needed; each
tunneled byte stream and the log-sync traffic get their own stream.

**Two contracts on one connection.** Reliable/ordered QUIC streams for async/bulk (log
replication, file transfer); the RFC 9221 unreliable-DATAGRAM extension for low-latency/loss-
tolerant flows — all under one handshake. To prevent bulk traffic from degrading interactive
flows: separate *streams* for isolation, and separate QUIC *connections* only where genuinely
differential network treatment (DSCP/QoS) is required, since QUIC has one congestion controller per
connection (minimize connection count otherwise).

**Stream encryption keyed from the handshake.** Use the identity/PQXDH handshake (ADR-004) to
bootstrap a single AEAD session key per connection (Noise / QUIC-TLS 1.3), then let the AEAD
transport encrypt high-throughput streams — rather than per-packet ratcheting. This composes
alongside the per-message Sender-Keys/log crypto (ADR-006/ADR-008). *(Marked as engineering
inference pending validation at implementation time.)*

**TCP fallback (if ever needed):** yamux for multiplexing (never mplex — mplex lacks stream-level
backpressure).

## Consequences

### Positive
- One encrypted connection cleanly carries interactive tunnels + async sync without cross-stream HOL blocking.
- Native QUIC security + multiplexing reduces moving parts.
- Stream-keyed-from-handshake gives high throughput without per-packet ratchet overhead.

### Negative
- Shared per-connection congestion control means a bulk stream can still throttle an interactive
  one on the same connection; true QoS separation needs multiple connections (overhead trade-off).
- The handshake→stream-key composition needs explicit security validation (not yet from a verified source).

### Neutral
- QUIC is also the natural substrate for the NAT-traversal techniques in ADR-012 (UDP-based).

## Links
**Depends on**: ADR-004, ADR-008.
- Depended on by: ADR-012, ADR-013.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
