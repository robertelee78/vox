# ADR-012: NAT Traversal, Bootstrap, and Reachability

**Status**: implemented and composed — all four rungs of the reachability ladder run in the node (`crates/vox-core/src/nat/`, `crates/vox-core/src/node/{network,coordstream,circuitstream}.rs`, `crates/vox-core/src/transport/mux.rs`), proved against simulated RFC 4787 NATs; rung 2 complete including UPnP-IGD (proved against a specification-faithful in-process gateway, real-router validation pending); DHT not started (see Known gaps)
**Date**: 2026-06-19
**Updated**: 2026-09-19 — status reconciled; Known gaps recorded. 2026-09-20 — member bundle record (`0x0012`, ADR-016 M14.1) added to `nat::record` and to the store policy (`BUNDLE_MAX_TTL_SECS`, `accept_bundle`, `current_bundles`, `bundle`). The rendezvous **service** (`nat::service`, ADR-016 M14.2) makes the board reachable over a typed QUIC stream. 2026-09-20 — the connection manager keeps those reads open to unknown peers by gating stream *kinds* rather than the transport (`node::net`, M14.4); the board now also serves a channel's genesis, which a cold join needs (M14.7b). 2026-09-20 (evening) — the ladder composed rung by rung: publish side (M14.8a), IPv6 pinhole + real route + renewal (M14.8b), hole punch through a coordinator (M14.9), relay circuits (M14.10), anchors as node configuration so the helpers exist (ADR-016 M15.1); Status line updated to match.
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
- IPv6/PCP availability is uneven; UPnP carries security baggage (mitigated in the client, see
  Implementation notes — the baggage is the router's, and the client follows nothing off the responder).

### Neutral
- Reachability improves over time as IPv6 deployment grows (~41–50% single-endpoint and climbing).

## Implementation notes (M10)

These record the concrete decisions made building this ADR (`crates/vox-core/src/nat/`), so the spec and code stay in lockstep:

- **Records (`nat::record`, tags `0x0007`/`0x0008`).** Member [`RendezvousRecord`] is the 8-field signed body `[author_id, channelID, epoch, endpoints, seq, timestamp, ttl_secs, [sign_algo]]`, framed/signed under `vox/rendezvous-record/v1` with a composite signature appended (wire arity 9), mirroring the ADR-007 governance-struct codec. It carries the publisher's `author_id` **fingerprint only** (not the full key); verification requires the member's composite public key, which the store resolves from the authenticated membership set (ADR-007) keyed by `author_id` — a non-member resolves to no key and is rejected, so "accept records only from channel members" is enforced by the store, not by caller discipline. The pre-join record (`PreJoinRecord`) instead embeds the **full asserted composite key** (a non-member has no prior key on file) and is self-signed; it embeds the prekey bundle via a new `PrekeyBundlePublic::encode_canonical` codec and `verify()`s the self-signature, the **binding `prekey_bundle.root_pub == asserted_id`** (so a peer cannot self-sign as A while advertising B's bundle and misdirect a joiner's PQXDH), and the bundle's internal signatures. Per ADR text, the struct tag *is* the `kind` discriminant.
- **Multiaddr text form is parseable, not just printable (2026-09-20).** `Multiaddr::parse` round-trips
  `Display` (`/ip6/<addr>/udp/<port>`, `/ip4/<addr>/udp/<port>`, `/relay/<64 hex>`) strictly — unknown
  protocol, missing or extra segment, malformed address/port, or a relay fingerprint that is not exactly
  32 hex-encoded bytes are all refused. This is the form the ADR-016 `vox://` invite link carries, so the
  round trip has to be exact.
- **`endpoints` = `nat::multiaddr::EndpointList`.** A capped (`MAX_ENDPOINTS = 8`), ordered list of `Multiaddr` (`Ip6` / `Ip4` / `Relay(fingerprint)`), each a strictly-decoded CBOR array led by a kind discriminant. Order is preference order (IPv6 first); `direct_candidates()` yields the Happy-Eyeballs dial order.
- **Store policy (`nat::store::RendezvousStore`).** The reader-side gate: monotone strict `(seq, timestamp)` anti-replay, a `MIN_REFRESH_SECS = 60` rate floor, `MAX_TTL_SECS = 2 h` (member `ttl_secs` capped; pre-join gets the `DEFAULT_TTL_SECS = 2 h` since its body has no TTL field, matching "same TTL caps"), a `MAX_CLOCK_SKEW_SECS = 300` future-timestamp bound, `(channelID, epoch)` bucketing for epoch-scoping, and anti-spam capacity (`MAX_PREJOIN_PER_CHANNEL`, `MAX_AUTHORS_PER_BUCKET`). All time is caller-supplied (`now`) so the store is deterministic and clock-free.
- **Member bundle record (`nat::record::MemberBundleRecord`, tag `0x0012`, ADR-016 M14.1).** The third record kind: a member's current `PrekeyBundlePublic`, root-signed under `vox/member-bundle-record/v1` over the 8-field body `[author_id, channelID, epoch, prekey_bundle, seq, timestamp, ttl_secs, [sign_algo]]` (wire arity 9, composite signature appended — the `0x0007` shape with `endpoints` replaced by the canonical bundle bytes, capped at `MAX_PREKEY_BUNDLE_BYTES`). Like `0x0007` it carries the fingerprint only and is verified against the membership-resolved key; `verify` additionally requires `prekey_bundle.root_pub == author` and the bundle's internal signatures, and `build` refuses a bundle whose root is not the signer, so a member cannot publish another identity's prekeys under its own name (a store test forges the record by hand and confirms the store also refuses it). `RendezvousStore::accept_bundle` applies the member-only / `(seq, timestamp)` anti-replay / `MIN_REFRESH_SECS` / clock-skew / `MAX_AUTHORS_PER_BUCKET` policy of `accept_member` with the TTL capped at `BUNDLE_MAX_TTL_SECS = 7 days` (the ADR-002 signed-prekey cadence) instead of `MAX_TTL_SECS = 2 h`; bundles live in their own `(channelID, epoch)` buckets so an address refresh never displaces a bundle. Queries: `current_bundles`, `bundle`; `prune_expired` covers all three kinds.
- **A fourth board kind: the channel genesis (M14.7b).** ADR-007 §Genesis says a cold-joining node
  *fetches the genesis from the rendezvous*, and the board had no way to serve it — so a joiner could find
  the swarm but not build channel state. `RendezvousStore::accept_genesis` / `genesis` and
  `RecordKinds::GENESIS` add it. It is the one kind with **no membership check and no TTL**, and that is
  not a relaxation: a genesis is immutable and **self-validating** — its hash *is* the channelID — so it
  cannot be filed under a channelID anyone asked for unless it is that channel's genesis, and a reader
  re-checks the hash against the channelID it joined with anyway (the client refuses a genesis that is not
  the channel's). Anyone may therefore publish it, which is precisely what lets a join proceed when no
  member is online, and a tampered one fails its own signature check. The only bound is
  `MAX_GENESIS_CHANNELS`.
- **The rendezvous service (`nat::service`, ADR-016 M14.2).** The board becomes reachable: `RendezvousService` (a `RendezvousStore` behind a lock, a `MembershipOracle` — the channel's authenticated membership, `member_key(channel, epoch, author)` — and a `Clock`) serves a bi-stream typed `StreamKind::Rendezvous` (ADR-011 notes) as a request/response protocol of canonical-CBOR frames: `PUT <record>` (any of `0x0007`/`0x0008`/`0x0012`, identified by the record's own struct tag) answered `ACCEPTED` or `REJECTED <reason>` with a closed reason set (`NotMember`, `Malformed`, `Policy`, `Capacity`, `UnknownKind`), and `GET <channelID, epoch, kinds>` answered by `RECORD <wire>` frames then `END`. Every PUT goes through the store's existing policy, so member-only admission is enforced by the same code the M10 tests pin; the record is self-authenticating, so the connection's peer need not be its author (a member may re-publish a peer's current record to a second anchor). **Reading is open to any authenticated peer that knows the channelID** — the rendezvous half of the ADR-005 link is the read capability; the passphrase gates the join — and records come back parsed but **unverified**: a member verifies against its membership view, a joiner against the out-of-band fingerprint (a forged endpoint simply fails the pinned QUIC handshake). Caps: frames at `MAX_RENDEZVOUS_FRAME = 48 KiB` (measured 2026-09-20: a member bundle record with a full one-time prekey is 18 084 B, a pre-join record with eight IPv6 endpoints 20 211 B, an address record 3 634 B; the hard bundle cap is 32 KiB + ~3.5 KiB of signature and fields), a GET reply at `MAX_GET_RECORDS = 2304` frames. A frame that is not a request resets the stream with the ADR-008 coded close (a loopback test observes `0x05` at the peer); a record the server can parse but must refuse is answered, not reset. `RendezvousClient::{put, get, finish}` is the client; the store lock is never held across an `await`.
- **Open board reads survive the connection manager (M14.4).** ADR-016's Decision would accept inbound connections with `Admission::Callback` over the union of channel memberships, which would also reject the peers this ADR requires a rendezvous server to serve — reads are open to any authenticated peer that knows the channelID, and a joiner must publish its pre-join record before anyone knows it. `node::net::ConnectionManager` reconciles this by accepting any authenticated identity when it serves rendezvous (ADR-011's open-swarm default) and moving the membership rule to the **stream kind**: `PeerPolicy` classifies the peer (member / anchor / pending joiner / unknown) and an unknown peer may open the `rendezvous` stream and nothing else, a pending joiner `join` and `rendezvous` only, an anchor `rendezvous`/`sync`/`coord` but never `join` or `pairwise`. A refused stream is reset with the same coded rejection an unauthenticated peer gets, so probing kinds is not an oracle. A node that does *not* serve rendezvous can still close the transport with `PeerPolicy::closed_admission`.
- **Port-mapping ladder (`nat::portmap`).** PCP (RFC 6887, nonce-authenticated) → NAT-PMP (RFC 6886) implemented as real UDP clients with RFC exponential-backoff retransmission; any PCP failure falls through to NAT-PMP; a total failure is hard (`Error::PortMappingFailed`), never a phantom mapping. A SUCCESS response carrying a **zero lifetime** (the delete-confirmation form) is treated as no live mapping on the create path — PCP falls through, NAT-PMP errors — so a zero-lifetime reply can never masquerade as an established mapping. **UPnP-IGD was at first intentionally not implemented** — this note recorded CallStranger (CVE-2020-12695), "many routers ship UPnP disabled" and SSDP+SOAP as a large surface for marginal gain — and **that decision was reversed on 2026-09-20 (ADR-016 M15.1c)**, see the UPnP note below: the gain is not marginal, the Decision above had always listed it as rung 2's third fallback, and the surface is small when the XML is scanned for a handful of elements rather than parsed. Default-gateway discovery is provided for Linux via `/proc/net/route` and `/proc/net/ipv6_route` (pure parses, no `unsafe`/shell, link-local next hops paired with the sysfs interface index); on other platforms the deployment supplies the gateway, which `map_port` takes explicitly, **or the RFC 7723 PCP anycast address carries the request** (see the rung-1 note below).
- **The ladder's publish side is composed (2026-09-20, ADR-016 M14.8a).** A node no longer advertises its
  bound socket. `local_route_ip` finds the address the OS would use to reach the internet **without sending
  a packet** — a UDP socket is "connected" to TEST-NET-1 (RFC 5737, never routed) purely so the kernel picks
  a route, and its source address is read back — and `advertise_endpoints` composes what to publish in this
  ADR's preference order: the routable address (IPv6 first, needing no translation), then the
  gateway-**mapped** address when PCP or NAT-PMP grants one (`PORT_MAP_LIFETIME_SECS` = 2 h, matching the
  address-record TTL so a mapping and the record advertising it age together), then loopback last so two
  profiles on one machine still reach each other. This is what makes the second rung real: an IPv4 node
  behind NAT is otherwise not dialable at all. Every rung is best-effort — no route, no gateway, or a
  refusing gateway just omits that entry — because **a node with no dialable address is not broken**: it
  reaches peers outbound and is reached through hole punching or a relay, which is the ordinary case for a
  client inside a private network.
- **Rung 1 is composed: the IPv6 pinhole, the real default route, and mapping renewal (2026-09-20,
  ADR-016 M14.8b).** The first rung of this ADR's ladder is "IPv6 direct + PCP pinhole", and the publish
  side had only the "direct" half. Four things close it:
  - **A pinhole is an identity mapping.** `portmap::open_ipv6_pinhole` sends a PCP MAP whose client
    address, suggested external port and suggested external address are all the node's *own* — RFC 6887
    §13.1: a PCP server in front of a firewall translates nothing, so what comes back is the same port on
    the same address, now reachable through the stateful filter. There is no NAT-PMP fallback (RFC 6886 is
    IPv4-only), a zero-lifetime SUCCESS is not a pinhole (the delete-confirmation form, as on the IPv4
    path), and a gateway that answers with a **v4-mapped** external address is refused: it answered a
    question this rung did not ask. `Method::PcpV6Pinhole` records which rung granted a mapping, and
    `PortMapping::external_ip` widened to `IpAddr` to hold it.
  - **Finding the PCP server without asking a C library.** A PCP request needs a server address, and the
    routing table is where it lives. Linux: `/proc/net/ipv6_route` is parsed for the lowest-metric `::/0`
    next hop (network-order hex, unlike the little-endian IPv4 table), and because a router normally
    advertises a **link-local** next hop — which cannot be sent to without a scope — the interface name
    from the same row is resolved to a kernel interface index by reading
    `/sys/class/net/<iface>/ifindex` (a name that is not a plain interface name is refused rather than
    escaped). Everywhere else there is no portable file interface to the routing table, and this is
    exactly what **RFC 7723** exists for: `192.0.0.9` and `2001:1::1` are the registered PCP *anycast*
    addresses, answered by the on-path PCP server whether or not it is the default router. So
    `gateway::server_candidates_v4/v6` return an ordered candidate list — real default route, then the
    IPv4 `.1` convention (RFC 6886 §3.2.1), then the anycast address — and no platform is left with no
    way to ask. This retires the "guess the gateway" follow-up from M14.8a.
  - **Candidates are raced, and so are the families.** An address that is not a PCP server simply never
    answers, so trying candidates in turn would pay the full ~3.75 s retransmission schedule for each
    before asking the next. `advertise_endpoints` races the candidates within a rung (first grant wins,
    the rest are abandoned; an unused grant expires on its own lifetime) and runs the IPv6 and IPv4 work
    concurrently, so the whole publish side costs one schedule rather than five. `local_route_ips` now
    returns **both** families' routable addresses (IPv6 first) instead of whichever was probed first, so a
    dual-stack node advertises — and pinholes or maps — both; `compose_endpoints` is the pure ordering
    step, testable without a gateway.
  - **A two-hour mapping outlives nothing by itself.** The node re-runs the publish side at half the
    shortest granted lifetime (`renew_at`, the interval RFC 6887 §11.2.1 recommends) on the actor's tick,
    on its own task, landing back as `AddressesDiscovered` — which republishes the address records too,
    because a renewal that came back with a different external port must be advertised.
- **Reachability ladder (`nat::reachability`).** `connect_direct` races a peer's direct candidates Happy-Eyeballs-style (RFC 8305, 250 ms staggered start) over the M9 QUIC endpoint via a tokio `JoinSet`, returning the first attempt that authenticates as the expected composite identity; ladder exhaustion is `Error::Unreachable` (the honest ADR-012 limit), never a false success.
- **Hole-punch (`nat::holepunch`).** The DCUtR Connect/Sync coordination is a pure, deterministic state machine + message codec; the initiator fires RTT/2 after `Sync`, the responder fires on receiving `Sync`, so the simultaneous opens coincide. The synchronized dial reuses `reachability::connect_direct` on the shared endpoint (same local port the peer observed).
- **Rung 3 is composed, and proved against real NAT behaviour (2026-09-20, ADR-016 M14.9).** The state
  machine existed with nothing to drive it: no way to learn the address a peer must dial, no channel to
  carry `Connect`/`Sync` to a peer one cannot reach, and nothing to execute a `PunchPlan`. All three are
  here, and so is the middlebox needed to prove any of it.
  - **The proof first (`crates/vox-core/tests/support/vnet.rs`).** Hole punching is a claim about
    middleboxes, and on loopback there is none — a "punch" test there passes without any punch. So the
    tests run on an in-process virtual UDP network of `quinn::AsyncUdpSocket`s (reached through the new
    `VoxEndpoint::bind_abstract`) whose hosts sit behind NAT devices that map and filter per RFC 4787:
    endpoint-independent mapping with address-and-port-dependent filtering ("port-restricted cone"), or
    address-and-port-dependent mapping ("symmetric"). A private address is routable only from behind its
    own NAT, and every drop is counted, so a test can assert the NAT really refused something. Nothing is
    lost, reordered or delayed, so a failure is behavioural, never a flake. Measured on it: an unsolicited
    dial to a peer's mapped address **is dropped**; a simultaneous open **traverses** two port-restricted
    cone NATs and authenticates; the punch tolerates **1.5 s of skew** between the two dials, because
    QUIC retransmits its Initial — so the RTT/2 timer buys a faster punch, not the only possible one, and
    a missed timer degrades rather than fails; and a symmetric NAT **defeats** the punch, which is this
    ADR's documented limit and the reason rung 4 must exist.
  - **Observed addresses (`node::coordstream`, the `coord` stream).** `WHOAMI` → `OBSERVED <multiaddr>`:
    the peer answers with the source address it sees for the connection the stream arrived on — what a STUN
    server answers, from a peer already authenticated. It is open to **any** authenticated peer, including
    one this node shares no channel with, because the answer is the asker's own address and a NATed client
    has no other way to learn it (the same openness the board's reads have). A node keeps the answers per
    reporter and uses the one most of them agree on. It is deliberately **not** published in an address
    record: a lying peer would then make this node advertise somebody else's address, whereas in a punch a
    wrong answer costs one failed punch.
  - **Signaling relay (same stream).** `RELAY <peer>` asks a coordinator to carry a session; the
    coordinator opens its own `coord` stream to the target with `FROM <peer>`, and on `RELAYING` from both
    ends forwards `COORD` frames — one encoded `CoordMessage` each, opaque to it — in both directions,
    at most `MAX_RELAYED_FRAMES` per direction within `RELAY_SESSION_TIMEOUT`. It forwards nothing else,
    so the verb cannot become a free tunnel (byte forwarding is ADR-013's, with its own consent rules).
    Each direction is its own task: `read_frame` is not cancel-safe, so a `select!` over both could abandon
    a half-read frame and desynchronize the stream. Both ends of a relayed session must be peers the
    coordinator knows — a member, an anchor, or a **pending joiner** (a peer with a live self-signed
    pre-join record on this board, which is what classified it). Including the joiner is deliberate:
    without it a newcomer could only join a swarm that already has a publicly reachable member, which is
    the dependency this ADR exists to remove, and a joiner already holds the far more expensive PoW-gated
    join stream. An unknown peer gets `WHOAMI` and nothing else.
  - **The ladder is now one call.** `NodeNet::reach(peer, endpoints)` is rungs 1–3 in order: a live
    connection, else a direct dial of the advertised endpoints, else a punch coordinated through any
    connected peer that will relay for it. `punch_endpoints` offers the observed address first and this
    node's advertised set behind it (a peer on the same LAN can use those), capped at `MAX_ENDPOINTS`.
    Exhausting it returns the *last* coordinator's error rather than a flattened "unreachable", because a
    coordinator that will not relay, one that cannot reach the peer, a peer that never answered and a NAT
    that defeats the punch are worth telling apart. The node's single dial site goes through it, so every
    connection the node makes now climbs the whole ladder.
  - **One stream failing is not the connection failing.** Serving `coord` in place exposed a latent defect
    in the node's per-connection stream loop: any stream error ended the loop, so a peer that opened one
    bad stream — or a `WHOAMI` that timed out behind a busy actor — silently stopped that connection being
    served at all, and the node went quiet until it reconnected. The loop now ends only when the connection
    itself is gone (or after 16 consecutive failures, which cannot happen on a usable connection and keeps
    a pathological peer from spinning the task).
- **Relay data-plane boundary.** M10 expresses relay *hints* (`Multiaddr::Relay`) and the bootstrap/relay node set (`nat::bootstrap`), and can reach a relay node over M9. The actual **byte-forwarding** a relay performs is the tunnel mechanism of ADR-013/M11 (a relay is a special tunnel); this is a layering decision, not a deferral of the rendezvous/signaling work, which is complete here.
- **Rung 4 is composed: the relay carries QUIC packets, so it is ciphertext-only by construction
  (2026-09-20, ADR-016 M14.10).** The layering claim above was wrong in one respect worth stating: a
  relay is *not* an ADR-013 tunnel. A tunnel is a consented, capability-gated data path whose plaintext
  the two ends share; a relay of last resort must carry a **connection** between two peers that cannot
  reach each other, and must learn nothing doing it. The mechanism that gives both is to relay the
  peers' QUIC packets themselves:
  - **The socket is where paths meet (`transport::mux`).** quinn binds one endpoint to one socket, so
    every `VoxEndpoint` now runs on a `MuxSocket`: the real socket (or a simulation's abstract one) plus
    **circuits** — synthetic destination addresses whose datagrams go to, and arrive from, a relay stream
    instead of the wire. A circuit's address is derived from the far peer's fingerprint into
    `240.0.0.0/4` (reserved, never routed), always IPv4 because quinn refuses an IPv6 destination on an
    IPv4 socket and maps an IPv4 one on an IPv6 socket; a datagram for a circuit that no longer exists is
    dropped here, never handed to the kernel. Above the socket nothing changes: a relayed peer is an
    address to dial, the handshake and the identity pinning are exactly those of a direct connection,
    one-connection-per-peer still holds, and every stream kind works over it — join, pairwise, sync,
    coord, tunnel — which is what makes this a network layer rather than a feature of one application.
    A circuit's outbound queue is bounded and drops when full: a relay stream that cannot keep up is a
    slow path, and QUIC on a slow path drops packets, it does not buffer without bound.
  - **The `circuit` stream (`node::circuitstream`, `StreamKind::Circuit = 7`).** `OPEN <peer>` asks a
    relay to carry a circuit; the relay opens its own `circuit` stream to the target with
    `INCOMING <peer>`; on `OPENED` from the target it answers `OPENED` and forwards `DATAGRAM` frames — one
    QUIC packet each — both ways, one task per direction (`read_frame` is not cancel-safe), until either
    side is done or the circuit idles for `CIRCUIT_IDLE_TIMEOUT` (5 min; QUIC keeps a live connection
    ticking well inside it). It forwards nothing but datagrams and never looks inside one. The **stream**
    is the carrier rather than QUIC DATAGRAM frames on purpose: a QUIC Initial is at least 1200 bytes and
    the outer connection's datagram limit is not guaranteed to hold one plus a header, whereas a stream
    carries any size; the price — no inner loss, head-of-line blocking — is the ordinary price of
    QUIC-over-reliable and acceptable for a last resort. Both ends of a circuit must be peers the relay
    knows (member, anchor or pending joiner, the rung-3 rule for the rung-3 reasons), and carrying bytes
    is bounded where carrying signaling was not: `MAX_RELAYED_CIRCUITS = 64` in total,
    `MAX_CIRCUITS_PER_ASKER = 4`, enforced by a ledger whose places return on drop. A relay is a last
    resort, not a service.
  - **The ladder is complete.** `NodeNet::reach` covers all four rungs. *As first composed* it ran them
    in order — direct, then a punch through each helper, then a circuit — so a peer behind a symmetric
    NAT cost a 10 s dial timeout and a 10 s punch timeout before the relay was tried. That ordering was
    replaced the same day; see the next note.
- **UPnP-IGD, the reversal (2026-09-20, ADR-016 M15.1c).** Rung 2's third fallback exists now
  (`nat::portmap::upnp`, `Method::UpnpIgd`, tried after the PCP/NAT-PMP race comes back empty). Why the
  omission was reversed: on home routers UPnP is the *common* one of the three protocols, PCP is rare and
  NAT-PMP mostly Apple-era; it is what lets the user's own **anchor** forward its port without the router
  being configured by hand, and what lets two peers with no anchor at all find a direct path when one of
  them has a cooperative router — the two-party cold start ADR-016 is built for. Why the security
  reasoning still holds: CallStranger is a vulnerability *of routers* exploited from the WAN, not of a LAN
  client; nothing a router says is trusted for anything but a mapping that can only waste a dial; and the
  client is hardened where it listens — the `LOCATION` an SSDP responder hands out is followed **only on
  the responder's own address**, every read is bounded and timed, hosts must be literal IPv4 addresses
  (nothing to resolve, nothing to be lied to about), and the XML is *scanned* for `serviceType`,
  `controlURL`, `URLBase`, `errorCode` and `NewExternalIPAddress` — there is no XML parser. Three plain
  exchanges, no dependencies: SSDP `M-SEARCH` for `InternetGatewayDevice:1` (an IGD:2 router answers a
  version-1 search, UDA §1.3.2), an HTTP `GET` of the description, SOAP `POST`s to the
  `WANIPConnection` (preferred) or `WANPPPConnection` control URL — absolute, or relative to `URLBase`, or
  to `LOCATION`. `AddPortMapping` asks for `PORT_MAP_LIFETIME_SECS`; a router that answers
  `725 OnlyPermanentLeasesSupported` is asked again with lease 0, the mapping is then reported with
  lifetime 0, never renewed, and **deleted when the node locks or shuts down**. Handled real-router quirks,
  each tested: HTTP/1.0 replies, `Transfer-Encoding: chunked`, `URLBase` with relative control URLs, PPP-only
  routers, permanent-only leases. **The spike found no router to test against**: the LAN this was built on
  answers no SSDP search at all, so the proof is an in-process gateway that follows UDA 1.1 and
  WANIPConnection:1 exactly with the quirks switchable, and validation against real hardware is recorded
  in Known gaps as pending — the client will be watched on the first real router it meets.
- **Relay-first, upgrade later (2026-09-20, ADR-016 M15.1b).** The sequential ladder made the anchor-based
  cold start ~25 s. The rungs are now **raced**: `reach` starts the direct dial and a circuit through every
  connected helper at once and returns whichever lands first — through the user's own anchor, about one
  round trip. If what landed was relayed, the node runs `upgrade` behind it: a direct dial and a punch
  through every helper, raced, each with `PUNCH_ATTEMPT_TIMEOUT` (6 s: QUIC retransmits its Initial at
  about 1, 2 and 4 s, so a punch that has not landed by then will not). What makes the swap safe is the
  connection manager's rule, which changed from first-come to a **preference**: `PathClass::Direct` beats
  `PathClass::Relayed` (read off the remote address — a circuit address means relayed), a better newcomer
  replaces the held connection, and the displaced one is **retired**, not closed: kept open for
  `RETIRE_GRACE_SECS` (60 s) so whatever is in flight on it — a join exchange, a sync session with its
  20 s frame bound — finishes, then closed by the node's tick. A worse newcomer is closed as before, which
  is also what settles a simultaneous dial. Both ends apply the same rule, so the upgrade lands with no
  protocol: the side that punched files the direct connection as an improvement, and the side that
  accepted it does too. A circuit attempt abandoned because another rung won tears itself down on drop
  (its driver is aborted, the port detaches, the stream closes, and the relay and the far side let go).
  Proved on the virtual NAT network: behind cone NATs `reach` returns a relayed connection in under 5 s
  and `upgrade` lands a punched one whose remote address is the peer's mapped address, primary on both
  sides with the relayed one retiring on each; behind symmetric NATs `reach` is as fast and `upgrade`
  comes back empty; a private-only address record no longer costs the dial timeout. ADR-016's M15.1 gate
  went from 22.9 s to 7.9 s, the join itself now bounded at 12 s.
  - **Proved on the virtual NAT network.** With both peers behind *symmetric* NATs — every earlier rung
    defeated, which the same file demonstrates — `reach` returns a connection pinned to and authenticated
    by the far peer, its remote address is the circuit's, the relay reports carrying exactly one
    circuit and gains no connection of its own, and 64 KiB round-trips over a `sync`-typed stream that
    the far node's loop hands up as it would any other. A relay refuses a circuit for a peer it does not
    know, and nothing is left attached when it does. The transport-level premise — a pinned handshake and
    streams both ways over circuits *alone*, no real socket carrying a byte between the two — is a unit
    test in `transport::mux`.

- **Known gaps (recorded 2026-09-19).** The rungs exist as independent, tested primitives and nothing
  composes them: `connect_direct`, `map_port` and the DCUtR `Coordinator` have no orchestrator.
  Hole-punch is a state machine only — no observed-address discovery, no relay channel carrying
  `CoordMessage`, nothing executes a `PunchPlan`. Relay-of-last-resort is a `Multiaddr::Relay` hint
  with no consumer and no data plane (the M11 tunnel does not implement one either). There is **no
  DHT** anywhere and the join layer's `channel_rendezvous`/`truncate` derivation has no caller — the
  DHT key width remains unchosen. The "rendezvous server" is `RendezvousStore`, an in-memory policy gate
  with no wire protocol to publish or fetch records and no consumer outside its own tests;
  `BootstrapSet` is pure configuration. PCP is IPv4-only (no IPv6 pinhole) and default-gateway
  discovery is Linux-only. All of this is the node-runtime capability (ADR-016), which this ADR's
  primitives were built to be composed by.
- **Known gaps, revised (2026-09-20).** The rendezvous board now has its wire protocol and a consumer
  (`nat::service`, M14.2), and rungs 1 and 2 are composed on both the publish and dial sides
  (M14.8a/M14.8b above): what a node advertises is what the ladder can actually make reachable, and
  granted mappings are renewed. **Rungs 3 and 4 remain uncomposed**: hole-punch is still a state machine
  with no observed-address discovery, no `coord` channel carrying `CoordMessage` through an online
  member, and nothing executing a `PunchPlan`; relay-of-last-resort is still a `Multiaddr::Relay` hint
  with no data plane. There is still no DHT (`channel_rendezvous`/`truncate` has no caller, the key width
  is unchosen), `BootstrapSet` is still pure configuration with no node wiring, and UPnP-IGD remains a
  deliberate omission (see the port-mapping note). IPv6 route discovery is Linux-only for the *real*
  route; elsewhere the rung depends on the RFC 7723 anycast address being answered.
- **Known gaps, revised again (2026-09-20, after rung 3).** Rung 3 is composed and proved through
  simulated NATs. What remains: **rung 4 has no data plane** — `Multiaddr::Relay` is still a hint, and the
  both-symmetric-NAT case therefore still ends in `Error::Unreachable`, honestly but unhelpfully.
  A punch also needs a coordinator that is *already connected to both peers*, and finding one is by trial
  over the current connections (there is no "who can reach X?" query, and no DHT to ask). The relayed
  session is not itself authenticated end to end: the coordinator is trusted to forward frames between the
  two peers it named, which is bounded (it can drop or garble signaling, making the punch fail) but means a
  hostile coordinator can deny a punch it was asked to carry. `BootstrapSet` remains unwired, so the
  coordinators a node can use are whichever peers it happens to be connected to.
- **Helpers exist now (2026-09-20, ADR-016 M15.1).** The ladder's rungs 3 and 4 climb through *a peer
  already connected to both sides*, and ADR-016 M15.1 is what makes such a peer exist for two clients
  inside private networks: the configured `BootstrapSet` is dialled at network start, named in invite
  links (with fingerprints, so the dial is pinned), persisted per channel, published to, and — as the
  node the user configured to introduce peers — trusted to vouch for the far side of a session it relays.
  Two defects in this ADR's code were found by that gate and fixed here: `connect_direct` spun hot on an
  attempt that failed faster than its stagger (and dropped nothing an IPv4 socket could not address), and
  the sync transport had no per-frame bound. Details in ADR-016.
- **Known gaps, after rung 4 (2026-09-20).** The ladder is complete and every rung is proved against a
  middlebox that behaves like the real one. What remains is around it, not in it: a helper (coordinator or
  relay) must already be connected to both peers, and is found by trial over current connections —
  `Multiaddr::Relay` hints in address records are still not consulted, there is no "who can reach X?"
  query and no DHT; `BootstrapSet` is still unwired, so the helpers a node has are whichever peers it
  happens to hold. A relayed circuit is torn down by its idle timeout, not the instant the inner
  connection closes. A hostile helper can deny (never read or alter) what it was asked to carry. IPv6
  route discovery is Linux-only for the real route. (`BootstrapSet` was wired the same day, M15.1;
  UPnP-IGD was built the same day, M15.1c — its validation against real router hardware is pending,
  the network it was built on having no UPnP device to answer.)

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
