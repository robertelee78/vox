# ADR-022: Datagram flows — UDP tunnels, relays that behave like UDP, and the app API

**Status**: **proposed — nothing here is built.** 2026-09-24. Each milestone in the plan below is
marked `DONE` only with the commit and gate that proved it.
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

The flow's identifier is the **control stream's QUIC stream ID divided by 4**. This is the RFC 9297
Quarter Stream ID. It is already unique on the connection and already known to both sides, so
nothing has to be allocated and nothing can collide.

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
fragments as they come and **never reassembles**. A lost outer packet now loses one inner packet,
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
  stream. MASQUE and Tailscale accept the same trade.

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

- **M22.1** The datagram seam:
  - the frame (decision 2), deleting the replay window;
  - `DatagramRouter`;
  - fragmentation and reassembly;
  - counters.
- **M22.2** Relay circuits on datagram flows (decision 5). The existing relay gates
  (`relayed_path_is_retried`, `nat_holepunch_through_nat`) must stay green.
- **M22.3** UDP tunnels: `vox serve … /udp`, then `vox forward … /udp` (decision 6). Proofs 1–6.
- **M22.4** SOCKS5 UDP ASSOCIATE in `vox up`.
- **M22.5** The app API: `StreamKind::App`, both gates, IPC protocol 6, the library API, and the
  limits and priorities (decision 7). Proofs 7–8.
