# ADR-012: NAT Traversal, Bootstrap, and Reachability

- **Status**: proposed
- **Date**: 2026-06-19
- **Deciders**: Robert E. Lee <robert@agidreams.us>
- **Tags**: nat, bootstrap, rendezvous, dht, ipv6, port-mapping, relay

## Context

The overlay must connect peers with no privileged central server (ADR-001), including the hardest
case: a two-member channel where both peers may be behind NAT with no third member to coordinate.
Research established hard facts: (a) cold-start onto a DHT requires some well-known bootstrap node;
(b) hole-punching always requires a reachable third party to coordinate, and both-symmetric-NAT
pairs cannot be hole-punched at all; (c) no serverless messenger achieves zero-dedicated-
infrastructure 2-party contact — a minimal coordinator is fundamentally required. The honest goal
is to *minimize and decentralize* that unavoidable layer, not eliminate it.

## Decision

**Any node can serve; users run their own.** Vox ships so that any node may *optionally* act as a
bootstrap / rendezvous / relay point. No Vox-operated infrastructure. For 3+-member channels, any
other online member serves as rendezvous/relay (availability is emergent, ADR-001). For the
2-member case, the user runs their own always-on node (e.g. a LAN box with a port-forward) as the
anchor for their channels — user-controlled, open-source, ciphertext-only. This makes even the
dual-symmetric-NAT 2-member case work, and is strictly better than the author's prior Tor-onion+ssh
approach (faster; signaling-only coordination, not a full relayed circuit; any peer, not a fixed
hidden service).

**Reachability strategy (prefer direct, in order):**
1. **IPv6 direct first.** On IPv6 there is no translation — only a stateful firewall; open an
   inbound pinhole via PCP (RFC 6887, identity mapping) where available. Race IPv6 vs IPv4
   (Happy-Eyeballs RFC 8305; ICE prioritizes IPv6). CGNAT carriers commonly provide native
   routable IPv6, so an IPv4-CGNAT'd peer is often reachable on IPv6.
2. **IPv4 automatic port-mapping**, fallback ladder PCP → NAT-PMP → UPnP-IGD. Request a single
   scoped port, validate the resulting mapping, and never rely on UPnP for security (CallStranger,
   CVE-2020-12695; many routers ship UPnP disabled).
3. **DCUtR-style hole-punching**, coordinated over a peer/own-node relay (Connect/Sync, half-RTT
   timer). The relay carries only lightweight signaling, not traffic.
4. **Relay of last resort** via the user's own node for the residual (both CGNAT/symmetric, no IPv6).

**Rendezvous.** Peers meet at the KDF-derived rendezvous key (ADR-005), publishing current
endpoints there (DHT mutable items / OpenDHT-style), which can double as the hole-punch
coordination channel for 3+-member channels. Cold-start joins the DHT via a minimal, possibly
piggybacked (e.g. existing public DHT) bootstrap set.

**Anti-abuse.** Rate-limit join attempts and/or require proof-of-work join tokens (PAKE stops
offline but not online guessing, ADR-005).

**Honest limit (documented).** Two peers both behind CGNAT/symmetric NAT with no IPv6 and no
reachable coordinator cannot connect. Global joint-IPv6 probability for a random pair is only
~0.17–0.20 today (rising), so a coordinator/relay remains mandatory for the residual — satisfied by
the user's own node.

## Consequences

### Positive
- Most pairs connect directly (IPv6 + port-mapping), with the user's own node closing the residual — no third-party trust.
- The 3+-member model makes availability genuinely emergent; the DHT can self-serve as coordinator.
- Honest, defensible "serverless" posture: no *privileged* server, minimal user-runnable infra.

### Negative
- Strict zero-infrastructure is impossible; some bootstrap/coordinator always exists.
- The pure 2-member, both-CGNAT, no-IPv6, no-own-node case is unsupported (documented limit).
- IPv6/PCP availability is uneven; UPnP carries security baggage.

### Neutral
- Reachability improves over time as IPv6 deployment grows (~41–50% single-endpoint and climbing).

## Links
- Depends on: ADR-005, ADR-011.
- Depended on by: ADR-013, ADR-014.
