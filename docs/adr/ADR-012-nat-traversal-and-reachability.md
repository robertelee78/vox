# ADR-012: NAT Traversal, Bootstrap, and Reachability

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: nat, bootstrap, rendezvous, dht, ipv6, port-mapping, relay

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

**Rendezvous (authenticated, fresh, epoch-scoped).** Peers meet at the rendezvous key
`HKDF-SHA-256(channelID, info="vox/rendezvous/v1" ‖ epoch)` (the exact ADR-005 derivation; a fast KDF
suffices because `channelID` is high-entropy, ADR-005/ADR-007) and publish current endpoints there as
**signed, sequence-numbered mutable records** (canonical-CBOR, ADR-008):
`{ author_id, channelID, epoch, endpoints, seq (monotonic), timestamp }`, where `endpoints` is a list
of **multiaddr** values (IPv6 / IPv4 / relay-hint), signed by the publishing member's composite
identity key (ADR-002). Readers **verify the signature, reject stale/replayed
records** (older `seq`/timestamp), and accept records only from channel members — so a poisoner
cannot inject or replay endpoints, and a stale record cannot be replayed after rotation. The
rendezvous point can double as the hole-punch coordination channel for 3+-member channels.
**Privacy:** because the rendezvous key is `(channelID, epoch)`-derived, a leaked key expires at the
next epoch (limiting swarm-presence tracking to that epoch); full unlinkability against a global
observer is the later metadata-privacy phase (ADR-001), stated, not silently omitted.
**Caps (anti-spam):** a member may publish **at most one current rendezvous record per
`(author_id, channelID, epoch)`**, refreshed **no more often than every 60 s** (records refreshing
faster, or extra records, are rejected by readers); records carry a short TTL (default 2 h) and are
endpoint-minimized (publish only the addresses needed for the reachability ladder). Rendezvous records are **epoch-scoped**: on passphrase rotation (new epoch, ADR-007) all prior-epoch
records are invalid (wrong `(channelID, epoch)`) and anyone not given the new passphrase can no longer
publish a valid record — that, not any per-member rendezvous revocation, is how the swarm sheds a
party. (There is no "member revocation": swarm presence is not consent-gated — per-sender consent
governs message *readability* only, ADR-007. A party whose message-consent was revoked is still present
in the swarm at ciphertext level until the epoch rotates.) The per-`(author,channel,epoch)` cap bounds
rendezvous-record spam even from a joined member.

**Pre-join rendezvous record class (the join-bootstrap path, ADR-004/ADR-005).** A peer that has not
yet completed the authenticated join publishes prekeys + endpoints in a **separate, clearly-typed
`pre-join` record class** at the same rendezvous key, self-signed by its asserted identity:
`{ kind: "pre-join", asserted_id, channelID, prekey_bundle, endpoints, seq, timestamp }`. These records
convey **no log authority** (ADR-008 accepts log entries only from joined identities) and readers treat
them **only** as join-bootstrap material — a candidate prekey bundle + endpoints to attempt CPace
against (ADR-005) — never as channel content. They carry the same caps/TTL/multiaddr encoding as member
records. This is the executable schema for the "pre-join rendezvous record class" referenced by ADR-004.

**Bootstrap (concrete, no third-party security dependency).** Cold-start onto the swarm uses a
**configurable bootstrap set the user controls**: by default the user's own always-on node (the
ADR-012 decision below) is their primary bootstrap + rendezvous; a user may additionally opt into a
community/volunteer set. Vox does **not** treat any external/public DHT as a security dependency —
bootstrap nodes only *introduce* peers (they can neither read traffic nor forge membership), so a
hostile or absent bootstrap degrades availability but never confidentiality or authenticity. (This
replaces the earlier "possibly piggyback public DHT" wording, which was a false deferral.)

**Anti-abuse.** Join-attempt abuse is bounded by the layered controls in ADR-005 (per-sender consent
gate + `(channelID, epoch)`-bound PoW join tokens + identity-bound log acceptance with per-author
quotas), not by rate-limiting alone. There is no admin admission step (ADR-007).

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
**Depends on**: ADR-005, ADR-011.
- Depended on by: ADR-013, ADR-014.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
