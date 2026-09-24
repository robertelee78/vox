# ADR-022: Datagram flows — UDP tunnels, relays that behave like UDP, and the app API

**Status**: **M22.1, M22.2, M22.3 and M22.4 built; M22.5 is not (on this branch).** 2026-09-24. Each milestone in the plan
below is marked `DONE` only with the gate that proved it.
**Date**: 2026-09-24
**Deciders**: Robert E. Lee
**Tags**: datagrams, udp, relay, app-api, calls
**Depends on**: 011, 012, 013, 016, 017, 020 — and PRD-001 (R25–R32)

## Context

PRD-001 asks for four things that all need the same missing piece:

- **R25–R26:** carry any UDP traffic between members, fragmenting packets that don't fit in one
  datagram.
- **R27:** relayed UDP must behave like UDP, dropping late packets rather than stalling behind them.
- **R29–R30:** an app API through which a separate program (the decider's chat and calls app) opens
  a live stream or datagram flow to a member node.
- **R32:** calls, 1:1 first, then a small-group mesh.

What exists today (read on `origin/main` 96c47ed):

- `VoxConnection::send_datagram` / `recv_datagram` (`transport/quic.rs`) frame each datagram as
  `seq(8) ‖ payload` behind a 1024-packet replay window (`transport/datagram.rs`). **No product code
  calls them.** The frame has no field saying which flow a datagram belongs to, and `recv_datagram`
  is the connection's only reader.
- A relay circuit (`node/circuitstream.rs`) carries the two ends' QUIC packets as `DATAGRAM` frames
  on a **reliable outer stream**. One lost outer packet stalls every inner packet queued behind it
  until it is retransmitted. That is what makes relayed UDP, and any future call, stall instead of
  drop.
- The tunnel stream (`StreamKind::Tunnel`, `tunnel/session.rs`) already provides most of what a flow
  needs:
  - a request that names a room and a service label;
  - a uniform `Denied` refusal;
  - a gate: the opener must be in the host's keyring **and** a current author of the room;
  - teardown when reach is withdrawn (the `Reachers` watch).

This ADR builds the missing piece once and puts all three consumers on it: UDP tunnels, relay
circuits, and the app API.

## Decision

### 1. A datagram flow is bound to a stream

Every flow is opened by a bidirectional stream: a `Tunnel` stream for UDP, a `Circuit` stream for a
relay, an `App` stream for the app API. The flow **lives exactly as long as that stream**. When
either side ends or resets the stream, the flow is gone, and datagrams still arriving for it are
dropped.

The flow's identifier is the **control stream's full QUIC stream ID**. It is already unique on the
connection and already known to both sides, so nothing has to be allocated and nothing can collide.

*(Corrected while building M22.1. This decision first said the stream ID divided by 4, RFC 9297's
Quarter Stream ID. That is unique in HTTP/3 only because only the client opens request streams. On a
Vox connection both ends open bidirectional streams — a relay opens its circuit stream to a target
that may have dialled it — and the client's stream 0 and the server's stream 1 share quarter 0, so two
flows would collide. The full ID costs one more varint byte only past stream 63.)*

The binding **takes** the stream: from then it carries no bytes, and a watcher ends the flow on both
sides the moment the stream ends in either direction. Nothing else can hold the stream open, so
unregistering is not something a caller can forget. That fits the `Circuit` and `Tunnel` streams, which carry
nothing once the flow is up. An `App` stream carries the app's bytes as well as its flow (decision
7), so M22.5 is to add a binding that shares the stream instead of taking it, and keeps the same rule:
the flow ends when the stream does.

Authorization happens **once, on the stream**, through the gate that stream kind already has. A
datagram is accepted only for a flow whose stream was authorized, so a datagram cannot reach anything
the stream could not.

### 2. The datagram frame

```
datagram := varint flow_id ‖ varint context ‖ body
context 0 := body is one whole packet
context 1 := body is a fragment: varint packet_id ‖ u8 index ‖ u8 count ‖ bytes
context ≥2 := reserved; a datagram with an unknown context is dropped and counted
```

The 8-byte sequence number and the replay window are **removed**. They protect nothing:

- QUIC already rejects a replayed or duplicated packet (RFC 9000 §12.3; packet protection).
- A relay carries inner QUIC packets that the inner connection de-duplicates for itself.
- The window could *wrongly* drop legitimate packets that arrived badly out of order.

Removing them saves 8 bytes on every packet.

### 3. One reader per connection routes datagrams

A per-connection `DatagramRouter` task is the only caller of the connection's datagram receive. It:

1. parses the flow ID and hands the datagram to that flow's bounded inbox;
2. drops (and counts) datagrams for unknown flows;
3. drops (and counts) datagrams whose flow inbox is full. A slow consumer loses packets and never
   stalls another flow.

Flows register with the router when their stream is authorized and unregister when it ends.

### 4. Oversize packets are fragmented inside Vox (R26)

A packet that fits `max_datagram_payload()` after the header goes as context 0. A larger one is split
into as many context-1 fragments as it needs, at most 255, and so at most 64 KiB, which is the
largest UDP payload. The receiver reassembles per `(flow, packet_id)`:

- **Timeout:** a packet whose fragments are not all present within **500 ms** is dropped, whole.
- **Bounds:** at most 32 partial packets per flow, and at most 1 MiB of partial data per connection.
  Past either bound the oldest partial packet is dropped.
- **Never retransmitted.** A lost fragment loses the packet, as a lost IP fragment does. Loss is
  amplified roughly by the fragment count, which is why fragmenting is the exception, not the norm.

Fragmentation is what lets inner QUIC (whose minimum is 1200 bytes), WireGuard at MTU 1420, and
game traffic cross a path whose datagrams hold only about 1150 bytes.

### 5. Relays carry datagrams, not a stream (R27)

The circuit stream keeps its handshake verbs (`OPEN`, `INCOMING`, `OPENED`, `REFUSED`) and its
bounds (64 circuits in total, 4 per asker, a 5-minute idle close). The `DATAGRAM` verb **moves off
the stream** and onto datagram flows:

- the initiator's circuit stream is a flow on the initiator–relay connection;
- the target's circuit stream is a flow on the relay–target connection;
- the relay forwards datagrams between the two flows without reading them. They are inner QUIC
  packets, as today.

Inner packets larger than the outer datagram limit are fragmented per decision 4. The relay forwards
fragments as they come and **never reassembles**. *(Found building M22.2:)* since the relay forwards a
datagram as it is and each end sees only its own leg, the ends must size datagrams for the smaller
leg, which neither can see. They send nothing larger than `CIRCUIT_DATAGRAM_MAX` = 1100 bytes, under
what every QUIC path carries; without that cap a leg grown to 1452 bytes by path-MTU discovery sends
datagrams a leg still at the 1200-byte floor drops, and the inner handshake never completes. A lost outer packet now loses one inner packet,
which the inner QUIC connection retransmits on its own schedule; it no longer stalls every packet
behind it.

What does not change: the relay is still ciphertext-only by construction.

### 6. UDP tunnels (R25)

- **Service label.** A UDP service is served as `udp/<port>`; a bare `<port>` stays TCP. So TCP 53
  and UDP 53 are two different services and never collide.
- **Opening a flow.** The dialer opens a `Tunnel` stream with `TunnelRequest{channel_id,
  "udp/<port>"}`. The host runs the existing gate unchanged. When authorized, it binds an ephemeral
  UDP socket connected to the service address and replies `Accepted`. The stream then carries no
  payload; it **is** the flow's lifetime.
- **Idle and limits.** A flow with no traffic in either direction for **120 s** is closed (the
  RFC 9298 floor). A node holds at most **32 flows per peer**, evicting the oldest idle one like a NAT
  table, and **256 in total**.
- **Teardown.** Untrusting the peer or removing the service resets the stream (R22). Resetting the
  stream ends the flow at once.
- **Surfaces**, in build order:
  1. `vox serve <room> 53/udp [--at addr]` on the host.
  2. `vox forward <name>.vox 53/udp <local-port>` on the dialer: a loopback UDP socket, one flow per
     distinct client source address.
  3. **SOCKS5 UDP ASSOCIATE** in `vox up` (RFC 1928 §7):
     - a loopback relay socket;
     - every destination must be a `.vox` name;
     - one flow per (association, destination);
     - `FRAG ≠ 0` dropped;
     - the association dies with its TCP control connection.
- **Backpressure and loss.** Sending never blocks: `send_datagram` drops the oldest queued datagram
  when the send buffer is full, so a stalled flow cannot stall its reader. Congestion control stays
  on (RFC 9298 forbids disabling it on the outer connection).

*Built (M22.3, M22.4), and where the build had to decide what this left open:*

- **Code.** `tunnel::udp` (labels, the flow table, both pumps); `tunnel::session::accept_reporting`
  serves a `udp/<port>` request after the unchanged gate by binding the stream as the flow on the
  connection it arrived on (`UdpHost`); `node::up::open_flow` is the dialer's side;
  `node::tunnel::Forward::bind_udp`; SOCKS5 `UDP ASSOCIATE` in `node::up`.
- **The surfaces differ from the list above in syntax, not in shape.** `vox serve` still creates the
  room (ADR-017's `vox serve <room>` is unbuilt), so it takes port specs: `vox serve 53/udp`, or
  `vox serve 53 53/udp` for TCP and UDP on one port, with `--at` applying to every spec. On an existing
  room, `vox service add <room> 53/udp <addr>`. The dialer's form is as written,
  `vox forward <name>.vox 53/udp <local-port>`: the `.vox` name gives the room and its host (the
  genesis creator), so the positionals shift left by one.
- **At `FLOWS_TOTAL` a new flow is refused, not given another's place.** Per peer, the longest-idle
  flow is evicted as decided above; across peers, eviction would let one peer empty the table for the
  rest. A refusal is the uniform `Denied`. The table is one per node and counts flows in both roles.
- **Teardown** is the TCP tunnel's watch (`withdrawn`: the reacher set and the live offer); when it
  fires the pump returns and dropping the flow ends the stream, which ends the flow at the dialer.
  quinn finishes a dropped stream rather than resetting it; for a flow that carries no bytes the two
  are the same event.
- **Per-flow counters** (to the peer, from the peer, dropped) live on each flow and are read with
  `UdpFlows::snapshot`. They are not yet surfaced in `vox status`.
- **Not proved by a gate:** the 120 s idle close, the 32-per-peer eviction and the 256 total, and a UDP
  flow cut by *service removal* (the same watch as untrust, which is proved; service removal is proved
  for TCP by `tunnel_honesty_proof`).

### 7. The app API (R29–R30)

- **New stream kind `App = 8`.**
  - The first frame after the kind is `[1, channel_id, [labels…≤8], flags]`.
  - The responder picks the first label it serves and answers `[1, label]`, or `[0, reason]`.
  - Labels are libp2p-style `name/vN`, at most 64 ASCII bytes, with no registry. An incompatible
    change is a new label.
  - Kinds stay reserved for Vox's own machinery.
  - `flags` bit 0 asks for a datagram flow bound to the stream.
- **The gate runs in both directions**, because each side gives the other data:
  - the responder accepts only an opener that is in **its** keyring and a current author of the room;
  - the opener's node refuses to open unless the target is in **its** keyring.
  - Untrusting either side tears the stream down through the `Reachers` watch.
- **Refusal has two tiers:**
  - A peer that is not trusted gets the same reset as a forbidden stream kind, so it cannot tell
    whether an app is running.
  - A mutually trusted peer gets the reason: `no-listener`, `busy` or `refused`.
- **App streams are live only.** Nothing is queued; anything durable belongs in the log.
- **Local IPC** (protocol 6, `0600` socket, as ADR-020 §7):
  - `AppListen{room|any, label}` turns the connection into a listener registration. A registration is
    exclusive per (room, label) and ends when the connection closes.
  - The node announces each incoming stream as `AppIncoming{id, room, peer, label}`.
  - `AppAccept{id}`, sent on a **fresh** connection, turns that connection into a raw splice of the
    stream. `AppOpen{room, peer, labels, datagrams}` does the same for an outbound stream.
  - A datagram flow travels on the same connection as length-prefixed frames after the splice
    handshake, marked stream-or-datagram.
  - An incoming stream nobody accepts within **5 s** is reset.
- **In-process library API.** The same operations are exposed from `vox-core` for a mobile app that
  embeds the node (R30). Packaging for Swift and Kotlin belongs to the app, not here.
- **Limits:**
  - 16 app streams per peer;
  - an open-rate bucket of about 10 per second per peer;
  - the `AppOpen` frame must arrive within 5 s;
  - app streams get a lower `set_priority` than sync, join and pairwise traffic;
  - `max_concurrent_bidi_streams` is set explicitly, replacing quinn's default of 100.

### 8. Calls sit on the app API (R32)

A call is an app (label e.g. `call/v1`) using an app stream for signalling and a datagram flow for
media.

- **1:1 calls** need nothing more from Vox.
- **Small-group mesh:** each participant opens one flow per other participant.
- **Beyond a mesh:** a forwarding node that must not see the media needs SFrame (RFC 9605) inside the
  app. That is out of scope here.

## Consequences

**Positive.**

- One mechanism serves UDP, relays and calls, and it rests on stream gates that already exist and are
  already proven.
- Relayed traffic stops head-of-line blocking.
- Every packet is 8 bytes smaller.

**Negative.**

- Fragmentation amplifies loss.
- Nested congestion control (inner QUIC over outer QUIC datagrams) is harder to reason about than a
  stream. MASQUE and Tailscale accept the same trade. *Measured building M22.2:* with every 10th
  datagram lost on one relay leg, the inner and outer congestion windows both sit at their 2904-byte
  floor, and at 200 small datagrams a second the inner one holds datagrams back for up to ~85 ms on
  its own — a stall that is congestion control, not carriage. At 100 a second it never binds. Calls
  (M22.5, R32) are to be sized against this.

**Neutral.**

- The replay window code is deleted.
- `StreamKind` gains `App = 8`.

## Proofs (each drives the shipped binary, each mutation-checked, each prints counts)

Each proof runs on a direct path **and** on a forced-relay path.

1. **DNS:** `dig` through a `53/udp` forward to a real DNS server gets the answer. Mutation: the host
   drops context-0 datagrams, and the proof goes red.
2. **Denied:** a peer outside the host's keyring gets no answer, and the host's service sees zero
   packets.
3. **Revocation:** a `dig` loop stops within 1 s of `vox trust remove`.
4. **Oversize:** 1400- and 4000-byte UDP payloads arrive intact via fragmentation. Mutation: disable
   fragmentation, and they are dropped and counted.
5. **Relay drops, not stalls:** `iperf3 -u` over the relay with induced loss shows loss and **no**
   head-of-line stalls; jitter is recorded. Mutation: stream carriage, and the jitter signature
   flips.
6. **TCP and UDP on the same port** both answer.
7. **App API:**
   - a 1 MiB app stream round trip with SHA-256;
   - 1000 app datagrams delivered;
   - an opener outside the responder's keyring gets **0** incoming notices at the listener;
   - an untrusted no-listener reset is byte-identical to an unknown-kind reset.
8. **Load:** 200 stalled app streams, and a chat message still arrives in under 1 s.

## Implementation plan

- **M22.1** The datagram seam — **DONE** (`transport::{datagram, router}`):
  - the frame (decision 2), deleting the replay window;
  - `DatagramRouter`;
  - fragmentation and reassembly;
  - counters (`VoxConnection::datagram_stats`; not yet surfaced in `vox status`).

  Proved by `crates/vox-core/tests/datagram_flows_gate.rs`:
  `oversize_packets_cross_a_small_path_in_fragments` (proof 4 at the seam, direct path only: 1400-
  and 4000-byte packets over a 1280-byte-MTU path; mutation — fragmentation disabled — drops all 40,
  and the sender's drop counter reads 40) and `unknown_and_ended_flows_drop_and_count` (unknown flow
  IDs, an unknown context, and a flow ended by its stream are dropped and counted; the flow ends at the
  far side by itself; mutations — the watcher no longer ending the flow, the unknown-flow counter
  removed — each go red). Proofs 1–6 through `vox serve … /udp` remain M22.3's.
- **M22.2** Relay circuits on datagram flows (decision 5) — **DONE**. Proved by
  `crates/vox-core/tests/relay_drops_not_stalls.rs`:
  `a_lossy_relay_leg_loses_packets_instead_of_stalling_them` (proof 5's property on real node network
  surfaces over a forced relay, 20 ms per link and every 10th datagram on one leg lost: datagrams are
  lost, and once the loss rate is established the longest gap between arrivals stays one lost
  datagram's, 21–32 ms over 8 runs; mutation — the stream carriage restored — flips it: 400/400
  arrive and the longest gap is 64–69 ms. In the first second after loss begins the outer congestion
  window falling to its floor holds datagrams once for up to ~80 ms; that is reported, not bounded) and `a_circuit_crosses_legs_of_different_datagram_sizes` (mutation — the
  `CIRCUIT_DATAGRAM_MAX` cap removed — the inner handshake never completes). The relay gates the
  milestone names stayed green on every run: `relayed_path_is_retried` (4/4),
  `nat_holepunch_through_nat` (8/8, 4 rounds), `mux_circuit_addressing` and
  `retire_keeps_carried_paths` (4 rounds each). **Two are not green, and not because of this change:**
  `node_m15_anchor_gate` passed 3 of 5 runs here and 1 of 3 on the ADR-022 base commit, and
  `service_rehearsal_proof` failed on this branch and on the base with the same messages (the stranger's
  `vox connect` failing, line 490; the first CONNECT refused, line 437 — the latter is ADR-012's open
  finding of 2026-09-22). Both are to be investigated as their own defects.
- **M22.3** UDP tunnels: `vox serve … /udp`, then `vox forward … /udp` (decision 6) — **DONE**.
- **M22.4** SOCKS5 UDP ASSOCIATE in `vox up` — **DONE**.

  Both proved by `crates/vox-tui/tests/udp_tunnel_proof.rs`: the shipped binary, a real `dig`, and
  real UDP sockets, on a **direct** path (everyone on IPv4 loopback) and a **forced-relay** path (the
  host on IPv6 loopback only, the guest on IPv4 only, the anchor dual-stack, so only a circuit can
  join them; the gate checks the host advertises IPv6 addresses only). No real DNS server or `iperf3`
  is installed, so the DNS responder and proof 5's blaster and sink are in the test. Seven tests, 3 of 3
  runs green (7/7 each) at the end; every mutation below was run and went red for the reason named.
  - **1 DNS.** `dig` through `vox forward <room>.vox <port>/udp` gets `10.53.0.1`, then 5 of 5 further
    queries. Direct: the first answer after 2 asks (~4.8 s, the first flow waiting on its tunnel);
    relayed: first ask, 6–28 ms. Mutation (host drops what the flow delivers): no answer in 40 asks
    over 120 s, the responder saw 0 packets.
  - **2 Denied.** An untrusted joiner: 5 `dig`s, no answer, the service saw 0 packets, and the forward
    printed `the host refused udp/<port>`. Mutation (the gate and the teardown watch both skipped):
    answered on the first `dig`. *(Skipping the gate alone stayed quiet: the teardown watch then cut
    the flow at once, since the dialer is not in the reacher set. Both layers deny.)*
  - **3 Revocation.** A query every 50 ms on one flow: 194–522 answers before `vox trust remove`, **0**
    after it returned. The command takes ~0.3 s (it checks the identity passphrase), and answers stop
    while it runs. Mutation (the teardown watch never fires): 133 340 answers after, the last 3.0 s
    later.
  - **4 Oversize.** 1400- and 4000-byte payloads through `UDP ASSOCIATE`, echoed byte for byte on both
    paths. Mutation (fragmentation disabled): the 1400-byte payload still crosses the loopback path
    whole, the 4000-byte one does not arrive.
  - **5 Relay drops, not stalls.** Relayed path only: a proxy on the guest's leg to the anchor, 20 ms
    each way, dropping every 10th datagram once setup is done; 3 s of unmeasured traffic for congestion
    control to settle, then 400 numbered datagrams every 10 ms. Every run lost what the leg dropped
    (41–61 lost for 47–51 dropped) — nothing retransmitted, so nothing could wait behind a
    retransmission. Mutation (the pre-ADR-022 stream carriage restored): **400 of 400** arrive, 0 lost
    for 38 dropped (and 0 of 43 and 0 of 47 in two earlier mutation runs); latency p99 82–309 ms.
    **Recorded, not bounded:** across the final runs the longest gap was 21, 115 and 132 ms. In the two
    long ones arrivals also bunched (median gap ~5 µs, against ~10 ms, the sender's pace, in the
    third) — outer and inner congestion control at their floor holding and releasing datagrams, the
    cost this ADR's *Negative* section already records. It is not a stream: the loss shows nothing
    was recovered.
  - **6 TCP and UDP on the same port.** `vox serve P P/udp` over one service bound on both: through one
    `vox up`, CONNECT gets `TCP:…` and `UDP ASSOCIATE` gets `UDP:…`. Mutation (ASSOCIATE asks for the
    bare port): no UDP answer.
  - **M22.4.** A `FRAG=1` datagram reaches the service 0 times (mutation: 1); after the control
    connection closes the service sees 0 packets and nothing answers (mutation: the service saw the
    datagram and the client got a reply).
  - **Setup fragility, not these properties:** early versions of proof 5 applied the loss from the
    start and failed 2 of 2 in parallel runs at `vox connect`, with the joining node's actor busy 30 s
    (ADR-018's open joining defect). The loss is now switched on after setup.
- **M22.5** The app API: `StreamKind::App`, both gates, IPC protocol 6, the library API, and the
  limits and priorities (decision 7). Proofs 7–8.
