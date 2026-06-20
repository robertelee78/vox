# ADR-013: Overlay Tunneling (TCP-over-Vox)

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: tunneling, tcp, ssh, tun, socks, overlay

## Context

Beyond messaging, Vox is a first-class encrypted overlay transport: it must carry arbitrary TCP/IP
between members — `ssh` over Vox and other tunneled streams (ADR-001). This rides the QUIC
substrate (ADR-011) and the connectivity layer (ADR-012), reusing the channel's identity and
membership (ADR-007) for authorization.

## Decision

**Expose tunneling two ways, both mapped onto QUIC streams (ADR-011):**
1. **Per-stream SOCKS / ssh-style port-forwarding** — targeted "tunnel this port/stream to that
   member." The primary, least-privilege mode (`ssh`-over-Vox).
2. **TUN virtual interface (VPN-style)** — a Yggdrasil-style interface with an IPv6 address derived
   from the node key, so "everything just routes" between members. Convenience mode.

**Authorization via channel membership.** A tunnel between members is permitted by their channel
membership and consent (ADR-007); tunneling is an application riding the same authenticated overlay,
not a separate trust domain.

**Reliability contract.** Interactive tunnels use ordered/reliable QUIC streams, isolated from
bulk log-sync traffic (ADR-011); latency-sensitive flows may use QUIC datagrams (RFC 9221).

**Scope.** This is a distinct capability/milestone, built after the messaging + transport core is
working. Voice/video are later capabilities that may reuse the datagram path.

## Consequences

### Positive
- One overlay for both private chat and arbitrary encrypted tunneling — the differentiated product scope.
- SOCKS/port-forward gives least-privilege targeted tunnels; TUN gives whole-network convenience.
- Reuses identity, membership, transport, and NAT traversal already built (ADR-004/007/011/012).

### Negative
- A TUN interface broadens the attack/abuse surface (arbitrary IP routing between members) and needs
  careful scoping and per-member policy.
- Carrying live TCP demands the stricter low-latency reliability path, raising the bar on ADR-011/012.

### Neutral
- Could be merged with ADR-011 implementation-wise, but kept separate as its own user-facing capability.

## Links
**Depends on**: ADR-007, ADR-011, ADR-012.
- Depended on by: ADR-014 (optional surfacing).

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
