# ADR-012: NAT Traversal, Bootstrap, and Reachability

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted. Built on integrate/v0.3.0, except where a requirement says otherwise. All
four rungs of the reachability ladder run in the node (`crates/vox-core/src/nat/`,
`crates/vox-core/src/node/{network,net,coordstream,circuitstream}.rs`,
`crates/vox-core/src/transport/mux.rs`). Not built: a DHT (N-31). UPnP-IGD has not yet been checked
against a real router (N-14). **Decided 2026-10-03, not built (#397, ADR-026):** the daemon owns
the machine's one presence (N-41–N-48); until it is built, each profile's daemon binds, maps and
self-tests on its own.
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: nat, bootstrap, rendezvous, ipv6, port-mapping, relay, anchor

## Context

The overlay connects peers with no privileged central server (ADR-001). Two hosts that are both behind NAT
cannot make first contact without a third party both can reach. When either can be reached directly,
no third party is needed. Hole punching needs a coordinator, and a pair of symmetric NATs cannot be
punched at all, so that residual needs a relay. The goal is to keep that unavoidable third party to
the minimum and to have it run by the user, not to eliminate it.

An **anchor** is a node the user configures, typically their own always-on machine, that bridges
hosts that cannot otherwise find each other. A **board** is a node's rendezvous store (`nat::store`,
served by `nat::service`). A **helper** is any connected peer that coordinates a punch or carries a
relay circuit.

## Requirements

### The anchor principle (2026-10-01)

- **N-1.** An anchor MUST be needed only to bridge two hosts that are both behind NAT and cannot
  otherwise find or reach each other.
- **N-2.** Creating, serving, inviting, joining and connecting MUST NOT require an anchor. When the
  peer can be reached directly (an address in the link, a working port mapping, the same LAN), the
  node MUST connect directly, MUST NOT wait for an anchor, and MUST NOT fail because one is absent.
- **N-3.** An invite link MUST always name the inviting host. When the link's anchors exceed
  `MAX_LINK_ANCHORS` (4), anchors MUST be dropped before the host is.
- **N-4.** `vox serve` MUST NOT refuse for lack of an anchor. A verb that hands out a room's address
  (`vox serve`, an invite) MUST withhold that address only when it would name no route of this node's
  own, and only after waiting `ADDRESS_PATIENCE` for this node's addresses to be discovered or for an
  anchor to take the room. It MUST then say why (`NodeEvent::AddressWithheld`), naming each anchor and
  whether it took the room (V210-96, `withhold_address`).
- **N-5.** A join MUST dial the host's address carried in the link before waiting on any board for
  it. It MAY then wait up to `JOIN_ADDRESS_PATIENCE` (20 s) for an address on a board, but only when
  the link carries none or the link's address failed (V210-96).
- **N-6.** A join whose first board lacks the room MUST try every other board it knows, including
  the host named in the link, before it fails.
- **N-7.** An anchors file in which no line is usable MUST NOT stop any verb. Each unusable line MUST
  be named, and the verb MUST carry on with no anchor (V210-107).
- **N-8.** When an anchor is missing or down, the product MUST say truthfully what that costs. It MUST
  NOT call an anchor unreachable when it was reached. It MUST NOT blame an anchor the person never
  needed. A join that reaches no board MUST name each board it tried, as the room's host or as an
  anchor, with its addresses, and its advice MUST name the board that failed (V210-107).

### Topology

- **N-9.** Any node MAY serve as a bootstrap, rendezvous or relay point. Vox MUST NOT depend on
  infrastructure run by the Vox project.
- **N-10.** In a room of three or more members, any online member MAY serve as rendezvous or relay
  for the others.
- **N-11.** A node MUST prefer a direct path to a relayed one. Address privacy is not a goal: a direct
  path reveals each peer's transport address to the other, and that is accepted (ADR-017 decision 6).
  A relay-mandatory mode MUST NOT be offered. Location anonymity is obtained by composing Vox over
  Tor.

### The reachability ladder

- **N-12. Rung 1, IPv6 direct.** A node MUST advertise its routable IPv6 address first. Where a PCP
  server answers, it SHOULD open an inbound pinhole as an identity mapping (RFC 6887 §13.1,
  `portmap::open_ipv6_pinhole`). A pinhole reply carrying a v4-mapped external address, or a zero
  lifetime, MUST NOT be treated as a pinhole.
- **N-13. Rung 2, IPv4 port mapping.** A node SHOULD request one scoped port through PCP (RFC 6887),
  then NAT-PMP (RFC 6886), then UPnP-IGD (M15.1c). It MUST validate each grant. A reply with a zero
  lifetime MUST NOT be taken as a live mapping, and a total failure MUST be reported, never shown as a
  mapping. Mappings MUST be requested for `PORT_MAP_LIFETIME_SECS` (2 h) and renewed at half the
  shortest granted lifetime (RFC 6887 §11.2.1).
- **N-14. UPnP-IGD client hardening.**
  - The client MUST follow a responder's `LOCATION` only on the responder's own address.
  - It MUST accept only literal IPv4 hosts.
  - It MUST bound and time every read.
  - It MUST scan the XML for the elements it needs, with no XML parser.
  - The client MUST NOT trust anything a router says beyond the mapping it grants.
  - A router that grants only permanent leases (725) MUST be asked again with lease 0, and that
    mapping MUST be deleted when the node locks or shuts down. *Decided, not built:* the mapping
    belongs to the daemon and is deleted when the daemon stops, never when a node detaches (N-43).
    There is no node lock under ADR-026 (N-2).

  Status: built and proved against a specification-faithful in-process gateway; not yet validated on
  a real router.
- **N-15. Finding a PCP server.** Candidates MUST be the real default route where the platform
  exposes it, then the IPv4 `.1` convention, then the RFC 7723 anycast addresses `192.0.0.9` and
  `2001:1::1`. Candidates within a rung, and the IPv4 and IPv6 work, MUST be raced. **Known limit:**
  the real default route is read only on Linux (`/proc/net/route`, `/proc/net/ipv6_route`).
  Elsewhere the rung depends on the anycast address being answered.
- **N-16. Publish side.** A node MUST advertise, in order: its routable addresses (IPv6 first), then
  any mapped address, then loopback. A node with no dialable address is not broken: it MUST still reach
  out and be reached through a punch or a relay.
- **N-17. Direct dial.** Direct candidates MUST be raced Happy-Eyeballs style (RFC 8305) with a
  250 ms staggered start (`CONNECTION_ATTEMPT_DELAY`). A dial MUST succeed only when it authenticates
  as the expected identity.
- **N-18. Rung 3, hole punching (M14.9).** Punches MUST be coordinated through a helper over the
  `coord` stream using DCUtR Connect/Sync. The initiator MUST fire RTT/2 after `Sync`, and the
  responder MUST fire on receiving `Sync`.
  - **Observed addresses.** `WHOAMI` MUST be answered with the source address the helper sees, to any
    authenticated peer. A node MUST keep the answers per reporter and use the one most reporters agree
    on. It MUST NOT publish an observed address in its address record.
  - **Signalling relay.** `RELAY`/`FROM`/`RELAYING`/`COORD` MUST carry only encoded `CoordMessage`
    frames, at most `MAX_RELAYED_FRAMES` (8) per direction within `RELAY_SESSION_TIMEOUT` (30 s). Both
    ends MUST be a member, an anchor or a pending joiner of the helper.
- **N-19. Rung 4, relay circuits (M14.10).** A relay of last resort MUST carry the peers' QUIC
  packets on a `circuit` stream (`StreamKind::Circuit = 7`, `OPEN`/`INCOMING`/`OPENED`). The relay
  MUST forward each datagram from one leg's flow to the other without reading or reassembling it
  (ADR-022 M22.2), so it carries ciphertext only.
  - Each end MUST send no datagram larger than `CIRCUIT_DATAGRAM_MAX` (1100 bytes).
  - A circuit MUST end when either leg's stream ends or after `CIRCUIT_IDLE_TIMEOUT` (5 min) idle.
  - The initiator's driver MUST end `CIRCUIT_CLOSE_LINGER` (1 s) after the connection it carries
    closes.
  - Both ends MUST be peers the relay knows: a member, an anchor or a pending joiner.
  - A relay MUST carry at most `MAX_RELAYED_CIRCUITS` (64) circuits in all and
    `MAX_CIRCUITS_PER_ASKER` (4) per asker.
  - A circuit's outbound queue MUST be bounded, and it MUST drop when full.
- **N-20. Circuit addressing.**
  - A circuit's address MUST be drawn at random inside `240.0.0.0/4`, never derived from the peer's
    identity, so that an address that escapes identifies nothing.
  - Whether an address is a circuit MUST be answered from the mux's table (`MuxSocket::is_circuit`),
    never from the address range.
  - `attach` MUST check the table for a collision.
  - The address MUST be IPv4 whatever the socket's family.
  - The node MUST record which relay carries each circuit (`MuxSocket::attach_via`), and `vox status`
    MUST name it (PRD-001 R35).
- **N-21. Relay first, upgrade later (M15.1b).**
  - `NodeNet::reach` MUST start the direct dial and a circuit through every connected helper at once
    and return whichever lands first.
  - A pair that can only be relayed MUST take its relay circuit at once: with no direct candidate
    and no direct dial under way anywhere in the node, a circuit is asked without waiting
    (`reach_ladder`). A dial-back (V030-22) MAY race the circuit, and MUST NOT hold or delay it
    (decider, 2026-10-03).
  - While a direct dial is under way (this reach's own direct rung, or a dial elsewhere in the node),
    a circuit MUST wait at most `DIRECT_HEAD_START` (500 ms) before asking a relay, and MUST give way
    at once to a direct connection that lands in that time. A reach with no candidate and no helper
    MAY wait up to `DIRECT_HEAD_START` for a dial under way to bring one.
  - When that is relayed, the node MUST run `upgrade` behind it: a direct dial and a punch through
    every helper, raced, each bounded by `PUNCH_ATTEMPT_TIMEOUT` (6 s).
  - A circuit attempt abandoned because another rung won MUST tear itself down.
  - Exhausting the ladder MUST return every rung's verdict (`Error::LadderExhausted`).
  - `NodeEvent::StillRelayed` MUST be raised only for a real exhaustion, never for "already direct"
    or "nothing to upgrade".
  - A failed dial MUST be reported (`NetEvent::ReachFailed` → `NodeEvent::PeerUnreachable`), never
    dropped.

### One connection per peer

- **N-22.** A node MUST hold one primary connection per peer, preferring `Direct` over `Relayed`
  (`PathClass`).
  - A better newcomer MUST replace the held connection. The displaced one MUST be retired, kept for
    `RETIRE_GRACE_SECS` (60 s) so that what is in flight on it finishes, then closed once nothing
    holds it.
  - One stream failing MUST NOT end the connection's service. The per-connection stream loop MUST
    end only when the connection is gone, or after `MAX_CONSECUTIVE_STREAM_FAILURES` (16) failures in
    a row.
  - A worse newcomer MUST be closed. This is also what settles a simultaneous dial.
  - On an equal path the survivor MUST be the lower `tie_key`, which is identical at both ends.
  - A connection MUST be judged dead by silence, never by address (v0.2.9 #6): one that has received
    nothing for `SILENCE_IS_DEATH` (30 s) MUST be replaced by a newcomer. When a held connection
    crosses that line later, a retired connection to the same peer that is still being heard from
    MUST be promoted in its place (`promote_heard`), or, with none, the silent one MUST be closed. This
    runs on a once-a-second task (`tend_liveness`) and on the next lookup.
  - A newcomer from another process of the same identity MUST supersede every connection to the
    process before it (V210-57). *Decided, not built:* with one daemon per machine, "process" is the
    remote daemon's leaf together with the remote node (ADR-011 requirement 35), and "one connection
    per peer" is per (local node, remote node) (ADR-026 I-3).
  - **Known limit:** liveness is the count of datagrams routed to a connection, taken before
    authentication, so an on-path attacker who knows a connection ID can keep a dead connection
    looking alive. That returns the node to QUIC's 60 s idle timeout, no worse than without the rule.
    Tracked as V210-140 (#359).
- **N-23.** Before a newcomer is filed, each live, not-yet-dead connection held for that peer to the
  newcomer's own process, primary or retired (`probe_held`), MUST be probed with one
  ack-eliciting datagram, with a patience of 3 × RTT clamped to 250 ms–2 s. A held connection that does
  not answer MUST be retired, not closed, so that what it carries finishes; one already retiring MUST
  be left to finish. Every unanswered probe MUST be noted (V210-104, #299; V210-93). Status: built on
  integrate/v0.2.10; arrives in v0.3.0 by the #226 sync. integrate/v0.3.0 still closes an unanswered
  connection (`file_inner`).
- **N-24.** Holding a connection MUST NOT keep it alive past its grace:
  - the stream loop MUST hold it weakly;
  - a tunnel MUST hold its connection only while it splices;
  - a circuit MUST hold the connections it rides only while it runs;
  - `upgrade` MUST hold the connection it replaces weakly.

### Rendezvous records and the board

- **N-25. Record kinds.** A board MUST accept four kinds (ADR-008 tags):
  - **member address record**, `RendezvousRecord`, `0x0007`: `[author_id, channelID, epoch,
    endpoints, seq, timestamp, ttl_secs, sign_algo]`, composite-signed, carrying the author's
    fingerprint only;
  - **pre-join record**, `PreJoinRecord`, `0x0008`: self-signed, embedding the asserted composite key
    and prekey bundle, with `prekey_bundle.root_pub == asserted_id`;
  - **member bundle record**, `MemberBundleRecord`, `0x0012`, M14.1: a member's current
    `PrekeyBundlePublic`, with `prekey_bundle.root_pub == author`;
  - **channel genesis**, M14.7b: no membership check and no TTL, because its hash is the channelID.
    A board MUST hold at most `MAX_GENESIS_CHANNELS` (4096).
- **N-26. Endpoints.** `endpoints` MUST be a `nat::multiaddr::EndpointList` of at most `MAX_ENDPOINTS`
  (8) entries (`Ip6`/`Ip4`/`Relay`), in preference order. Its text form MUST parse strictly and
  round-trip `Display`.
- **N-27. Admission (`RendezvousStore`).**
  - A board MUST verify each record's signature and accept member and bundle records only from
    authors it knows as members:
    - for a member board, from its membership view;
    - for an anchor, from the genesis's creator and from members vouched for by a bundle record a known
      member published (M15.2a).
  - A board MUST enforce:
    - strictly advancing `(seq, timestamp)` per author;
    - `MAX_TTL_SECS` (2 h) for address and pre-join records;
    - `BUNDLE_MAX_TTL_SECS` (7 days) for bundles;
    - `MAX_CLOCK_SKEW_SECS` (300 s) of future timestamp;
    - one current record per `(author_id, channelID, epoch)`;
    - `MAX_AUTHORS_PER_BUCKET` (1024).
  - Member and bundle records MUST be bucketed by `(channelID, epoch)`, so that a passphrase rotation
    (new epoch, ADR-007) invalidates every earlier record.
  - Pre-join records convey no log authority and MUST be used only as join-bootstrap material
    (ADR-004/ADR-005).
  - Swarm presence is not consent-gated. A party whose message consent was revoked stays present at
    the ciphertext level until the epoch rotates; there is no per-member rendezvous revocation
    (ADR-007).
- **N-28. Refresh floor.** A record whose claim matches the one held, inside `MIN_REFRESH_SECS`
  (60 s), MUST be answered as a no-op success and leave the held record untouched. A record whose claim
  changed MUST be accepted as soon as it strictly advances `(seq, timestamp)`. A non-advancing record
  MUST be refused as `Stale` (wire code 6).
- **N-29. Pre-join capacity.** A board MUST hold at most `MAX_PREJOIN_PER_CHANNEL` (256) pre-join
  records per room. A full bucket MUST evict its earliest arrival and MUST NOT refuse the newcomer. A
  pre-join record MUST be dropped when its author's member address record is admitted (V210-102). It
  MUST NOT be dropped when only a bundle record arrives, because the board counts a member by its
  address record (V210-43).
- **N-30. The rendezvous service (M14.2).**
  - The board MUST be served on a `rendezvous` stream with `PUT <record>`, answered `ACCEPTED` or
    `REJECTED <reason>`, and `GET <channelID, epoch, kinds>`, answered with `RECORD` frames then
    `END`.
  - The reasons MUST be `NotMember` 1, `Malformed` 2, `Policy` 3, `Capacity` 4, `UnknownKind` 5 and
    `Stale` 6.
  - Reads MUST be open to any authenticated peer that knows the channelID, and records come back
    unverified for the reader to verify.
  - A record is self-authenticating, so the connection's peer need not be its author: a member MAY
    re-publish a peer's current record to a second board.
  - Frames MUST be capped at `MAX_RENDEZVOUS_FRAME` (48 KiB) and a reply at `MAX_GET_RECORDS` frames.
  - A frame that is not a request MUST reset the stream with the ADR-008 coded close.
- **N-31. Rendezvous key and DHT.**
  - The rendezvous key is `HKDF-SHA-256(channelID, info = "vox/rendezvous/v1" ‖ epoch)` (ADR-005,
    `join::rendezvous::channel_rendezvous`). Status: defined and unused, because no DHT is built and
    boards are reached directly.
  - Vox MUST NOT treat any external or public DHT as a security dependency.
  - Because the key is `(channelID, epoch)`-derived, a leaked key stops locating the swarm at the next
    epoch. Unlinkability against a global observer is not provided here; it belongs to the metadata
    privacy phase of ADR-001.
- **N-32. Join abuse.** Join-attempt abuse MUST be bounded by ADR-005's layered controls: the
  per-sender consent gate, `(channelID, epoch)`-bound proof-of-work join tokens, and identity-bound
  log acceptance. The per-author quotas once listed here were removed (PRD-001 R3). There is no admin
  admission step (ADR-007).
- **N-33. Stream-kind gate (M14.4).** A node that serves rendezvous MUST accept any authenticated
  identity and gate by stream kind (`PeerPolicy::allows`):
  - a **member** may open every kind;
  - an **anchor** may open `rendezvous`, `sync`, `coord` and `circuit`;
  - a **pending joiner** may open `join`, `rendezvous`, `pairwise`, `coord` and `circuit`;
  - a **join responder** may open `pairwise`, `rendezvous` and `coord`;
  - an **unknown** peer may open `rendezvous`, and `coord` for `WHOAMI` only;
  - anyone may open `goodbye`.

  A refused stream MUST be reset with the same coded rejection an unauthenticated peer gets, so that
  probing kinds reveals nothing.

### Bootstrap and publishing

- **N-34. Bootstrap (M15.1).** Cold start MUST use a bootstrap set the user controls. The configured
  anchors MUST be dialled when the network starts, named in invite links with their fingerprints, and
  persisted per room. With no anchor, the invite link's addresses are the bootstrap. Bootstrap nodes
  only introduce peers; a hostile or absent one MUST be able to degrade availability only, never
  confidentiality or authenticity.
- **N-35. Publisher sequence (V29-23).** A publisher's `seq` MUST keep rising across its restarts:
  `max(previous + 1, now in ms)`.
- **N-36. A peer book (2026-09-25, found by ADR-023's R10 gate).** A node MUST keep each member's last direct addresses (at most
  4, with the time each was last seen) in its own sealed store. It MUST fall back to them when no board
  has an address for the member, and MUST dial every other member of a room when it opens the room.
  Relayed paths MUST NOT be recorded.
- **N-37. Publish outcomes.**
  - Every put a node makes to a board MUST report its outcome, a refusal included
    (`NodeEvent::PublishRefused`).
  - A publish round to one board MUST give up after `ANCHOR_PUBLISH_PATIENCE` (5 s).
  - A failed round MUST be retried per (room, board) at 1, 2, 4, 8, 16, then 30 s, each shortened
    by up to a quarter at random, until a round finishes (#182).
  - The retry MUST be dropped when the room or the board's connection is gone.

### The daemon's one presence (ADR-026)

*Decided 2026-10-03, not built (#397).*

- **N-41.** The daemon, not a node, MUST bind the one UDP socket and QUIC endpoint of the machine's
  account, and run the dual-stack self-test once per bind.
- **N-42.** The port MUST be kept in `<data root>/.daemon/port` and reused on every start, so the
  address records every node published stay valid.
- **N-43.** The daemon MUST own the gateway port mapping (N-12–N-14) and the observed (reflexive)
  address cache. A node's detach MUST NOT unmap; the daemon's stop MUST.
- **N-44.** LAN discovery (nearby) MUST run once, in the daemon.
- **N-45.** Relay circuits (N-19) and board service (N-25–N-33) MUST be executed by the daemon and
  governed per node: a node relays for, and serves the board of, its own rooms' members (PRD-001
  R33).
  - The daemon MUST keep one relay circuit ledger, and the relay limits (`MAX_RELAYED_CIRCUITS`,
    `MAX_CIRCUITS_PER_ASKER`) MUST apply per daemon, configured in `.daemon/config`.
  - Boards MUST be per node: each node keeps its own board store, with its own capacities.
- **N-46.** Each attached node MUST publish its own address record, naming the daemon's shared
  ip:port. Nodes on one machine are therefore visibly co-hosted (an accepted cost, ADR-026).

- **N-47. Diagnostics.** A dial that finds no node answering as the expected identity MUST say
  "nothing at `<address>` answers as `<expected node>`", and MUST NOT name who else answered there
  (ADR-011 requirement 38a). This replaces V210-143's wording, which named the identity found.
- **N-48.** The hole punch's attempt timeout (`PUNCH_ATTEMPT_TIMEOUT`) MUST be re-measured with the
  identity exchange in place.

### Limits

- **N-38.** Two peers both behind NAT, with no IPv6 path, no port mapping and no helper both can
  reach, cannot connect, and when both NATs are symmetric only a relaying helper can join them. The
  product MUST say so rather than claim a connection.
- **N-39.** A helper MUST already be connected to both peers. **Known limit:** it is found by trial
  over the node's current connections. `Multiaddr::Relay` hints in address records are not
  consulted, and there is no "who can reach X?" query.

## Consequences

- Most pairs connect directly, through IPv6 or port mapping. The user's own anchor closes the
  residual, and no third party is trusted.
- Strict zero infrastructure is impossible for two hosts both behind NAT. Every other pair needs none.
- A hostile helper can deny what it was asked to carry, but cannot read or alter it.
- UPnP carries router-side security baggage (CallStranger, CVE-2020-12695). The client trusts nothing
  a router says beyond a mapping.

## Related ADRs

ADR-001 (principles), ADR-002 (identity), ADR-004 and ADR-005 (join), ADR-007 (membership),
ADR-008 (log and wire tags), ADR-011 (transport), ADR-013 (tunnels), ADR-016 (node runtime),
ADR-017 (room-bound services), ADR-022 (datagram flows).

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
