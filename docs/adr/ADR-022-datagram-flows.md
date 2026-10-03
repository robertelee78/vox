# ADR-022: Datagram flows — UDP tunnels, relays that behave like UDP, and the app API

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: accepted by the decider (2026-09-25). M22.1–M22.5 are built on integrate/v0.3.0
(`transport::{datagram, router}`, `node::circuitstream`, `tunnel::udp`, `node::{app, appipc}`,
`vox app`, `crates/vox-ffi`), to ship in v0.3.0. Calls (decision 8) are an app, not Vox code.
- **Not built:** per-flow counters in `vox status` (6.9; #383, V030-34); the Kotlin binding (7.13;
  #78). Per-connection counters are built: `vox status --json` `datagrams` and the metrics endpoint
  (`42597826`).
- **No proof on integrate/v0.3.0:** the unknown-flow and unknown-context drops (2.2, 3.2) and
  `CIRCUIT_DATAGRAM_MAX` (5.4), whose in-process gates (`datagram_flows_gate`,
  `relay_drops_not_stalls`) were deleted when v0.2.10 merged into v0.3.0 (`a1d01323`, #226) and
  await conversion (#227, V030-02); the 120 s idle close (6.3), the 32-per-peer eviction and the
  256 total (6.4) (#72); and a UDP flow cut by service removal (6.5; the untrust half is proved,
  and service removal is proved for TCP by `tunnel_honesty_proof`) (#68).
- **Proved short of the decision:** P8's bound (see P8), and the proofs' paths and substitutions
  listed under Proofs.
**Date**: 2026-09-24
**Deciders**: Robert E. Lee
**Tags**: datagrams, udp, relay, app-api, calls

## Context

PRD-001 asks for four things that need the same missing piece: carrying any UDP traffic between
members, fragmenting packets that do not fit one datagram (R25–R26); relayed UDP that behaves like
UDP, dropping late packets instead of stalling behind them (R27); an app API through which a separate
program opens a live stream or datagram flow to a member node (R29–R30); and calls, 1:1 first, then a
small-group mesh (R32). Before this ADR, datagrams carried no flow identifier and had one reader, and
a relay circuit carried its ends' QUIC packets on a reliable outer stream, so one lost outer packet
stalled every inner packet behind it. The tunnel stream (ADR-013) already had a named request, a
uniform `Denied` refusal, a keyring-and-author gate and teardown on withdrawn reach (`Reachers`).
This ADR builds datagram flows once and puts UDP tunnels, relay circuits and the app API on them.

## Requirements

### Decision 1 — a datagram flow is bound to a stream

1.1. Every flow MUST be opened by a bidirectional stream: `Tunnel` for UDP, `Circuit` for a relay,
     `App` for the app API. The flow MUST live exactly as long as that stream; when either side ends
     or resets the stream, the flow ends and datagrams still arriving for it MUST be dropped.
1.2. The flow ID MUST be the control stream's full QUIC stream ID. It MUST NOT be RFC 9297's Quarter
     Stream ID: both ends of a Vox connection open bidirectional streams, so quarter IDs collide.
1.3. A binding that takes the stream (`bind_flow`) MUST leave the stream carrying no bytes, and a
     watcher MUST end the flow on both sides when the stream ends in either direction.
1.4. An `App` stream carries the app's bytes as well as its flow, so its binding shares the stream
     (`bind_shared_flow`, crate-private). Its only caller, `node::app::AppStream`, MUST hold the
     stream and the flow in one object whose drop ends both.
1.5. Authorization MUST happen once, on the stream, through that stream kind's gate. A datagram MUST
     be accepted only for a flow whose stream was authorized.

### Decision 2 — the datagram frame

2.1. A datagram MUST be:
     ```
     datagram := varint flow_id ‖ varint context ‖ body
     context 0 := body is one whole packet
     context 1 := body is a fragment: varint packet_id ‖ u8 index ‖ u8 count ‖ bytes
     context ≥2 := reserved
     ```
2.2. A datagram with an unknown context MUST be dropped and counted.
2.3. Vox MUST NOT carry a datagram sequence number or replay window: QUIC rejects replayed and
     duplicated packets (RFC 9000 §12.3), a relay's inner QUIC de-duplicates for itself, and a
     window wrongly drops packets that arrive far out of order.

### Decision 3 — one reader per connection routes datagrams

3.1. A per-connection `DatagramRouter` MUST be the only caller of the connection's datagram receive.
     It MUST hand each datagram to its flow's bounded inbox.
3.2. It MUST drop and count datagrams for unknown flows and datagrams whose flow inbox is full. A
     slow consumer MUST lose packets and MUST NOT stall another flow.
3.3. Counters are read with `VoxConnection::datagram_stats`. They SHOULD be surfaced in
     `vox status`. Built: `vox status --json` carries them per peer and for the node, and the
     metrics endpoint as `vox_datagrams_*_total` (`42597826`).

### Decision 4 — oversize packets are fragmented inside Vox (R26)

4.1. A packet that fits `max_datagram_payload()` after the header MUST go as context 0. A larger one
     MUST be split into context-1 fragments, at most 255, so at most 64 KiB, the largest UDP payload.
4.2. The receiver MUST reassemble per `(flow, packet_id)` and MUST drop a packet, whole, whose
     fragments are not all present within 500 ms.
4.3. At most 32 partial packets per flow and 1 MiB of partial data per connection; past either
     bound the oldest partial packet MUST be dropped.
4.4. Fragments MUST NOT be retransmitted. A lost fragment loses the packet.

### Decision 5 — relays carry datagrams, not a stream (R27)

5.1. The circuit stream MUST keep its handshake verbs (`OPEN`, `INCOMING`, `OPENED`, `REFUSED`) and
     its bounds (64 circuits in total, 4 per asker, a 5-minute idle close).
5.2. Inner QUIC packets MUST travel as datagram flows: the initiator's circuit stream is a flow on
     the initiator–relay connection, the target's on the relay–target connection, and the relay MUST
     forward datagrams between the two flows without reading them.
5.3. The relay MUST forward fragments as they come and MUST NOT reassemble.
5.4. Each end MUST send no circuit datagram larger than `CIRCUIT_DATAGRAM_MAX` = 1100 bytes, since
     neither end can see the other leg's datagram size.
5.5. The relay MUST stay ciphertext-only.

### Decision 6 — UDP tunnels (R25)

6.1. **Labels.** A UDP service MUST be served as `udp/<port>`; a bare `<port>` stays TCP, so TCP and
     UDP on one port are two services.
6.2. **Opening.** The dialer opens a `Tunnel` stream with `TunnelRequest{channel_id, "udp/<port>"}`.
     The host MUST run the existing tunnel gate unchanged, then bind an ephemeral UDP socket connected
     to the service address and reply `Accepted`. The stream then carries no payload and is the
     flow's lifetime.
6.3. **Idle.** A flow with no traffic in either direction for 120 s (RFC 9298's floor, `UDP_IDLE`)
     MUST be closed.
6.4. **Limits.** A node MUST hold at most 32 flows per peer (`FLOWS_PER_PEER`), evicting that peer's
     longest-idle flow, and at most 256 in total (`FLOWS_TOTAL`), counting both roles. At the total,
     a new flow MUST be refused with the uniform `Denied` and MUST NOT evict another peer's flow.
6.5. **Teardown.** Untrusting the peer or removing the service MUST end the flow at once, through
     the TCP tunnel's watch (the reacher set and the live offer, R22).
6.6. **Surfaces.** The host: `vox serve <port>/udp`, or `vox serve <port> <port>/udp` for TCP and
     UDP on one port (`--at` applies to every spec); on an existing room,
     `vox service add <room> <port>/udp <addr>`. The dialer:
     `vox forward <service>.<node>.<room>.vox <port>/udp <local-port>`, one flow per distinct client source address.
6.7. **SOCKS5 UDP ASSOCIATE** in `vox up` (RFC 1928 §7): a loopback relay socket; every destination
     MUST be a `service.node.room.vox` name (ADR-017); one flow per (association, destination); a datagram with `FRAG ≠ 0` MUST
     be dropped; the association MUST end with its TCP control connection.
6.8. **Backpressure.** Sending MUST NOT block: when the send buffer is full the oldest queued datagram
     is dropped. Congestion control on the outer connection MUST stay on (RFC 9298).
6.9. Per-flow counters (to the peer, from the peer, dropped) are read with `UdpFlows::snapshot`. They
     SHOULD be surfaced in `vox status`; *not built*.

### Decision 7 — the app API (R29–R30)

7.1. **Stream kind `App = 9`.** The first frame after the kind MUST be
     `[1, channel_id, [labels…≤8], flags]`; `flags` bit 0 asks for a datagram flow bound to the
     stream. The responder MUST pick the first label it serves and answer `[1, label]`, or
     `[0, reason]`.
7.2. Labels are libp2p-style `name/vN`, at most 64 ASCII bytes, with no registry. An incompatible
     change MUST be a new label. Stream kinds MUST stay reserved for Vox's own machinery.
7.3. **Gate, both directions.** The responder MUST accept only an opener that is in its keyring and a
     current author of the room. The opener's node MUST refuse to open unless the target is in its
     keyring. Untrusting either side MUST tear the stream down through the `Reachers` watch.
7.4. **Refusal, two tiers.** A peer that is not trusted MUST get the same reset as an unknown or
     forbidden stream kind (`Reset(5)` on read, `Stopped(5)` on write; `streams::refuse`), so it
     cannot tell whether an app is running. A mutually trusted peer MUST get the reason:
     `no-listener`, `busy` or `refused`. A trusted stream nobody accepts in time MUST be told
     `refused`.
7.5. App streams MUST be live only; nothing is queued.
7.6. **Local IPC** (introduced in IPC protocol 6; `0600` socket, as ADR-020 §7; request tags
     2201–2212). A connection whose first request is an app request MUST stay an app connection for
     life.
     - `AppListen{room|any, label}` registers a listener, exclusive per (room, label), ending when
       the connection closes.
     - The node announces each incoming stream as `AppIncoming{id, room, peer, label}`.
     - `AppAccept{id}` on a fresh connection, and `AppOpen{room, peer, labels, datagrams}`, turn that
       connection into a raw splice of the stream. A datagram flow travels on the same connection as
       length-prefixed frames marked stream-or-datagram.
     - An incoming stream nobody accepts within 5 s MUST be refused (`refused`, as 7.4).
7.7. In the raw splice the node MUST shut its write side when the peer finishes, and MUST close the
     whole connection when the stream fails.
7.8. **Limits.** 16 app streams per peer, counted at the responder from admission to end; an
     open-rate bucket of burst 10, refilling 10 a second, per peer; the `AppOpen` frame MUST arrive
     within 5 s. `busy` MUST cover both the stream limit and the open rate.
7.9. App streams MUST run at a lower priority than sync, join and pairwise traffic (built: `-1`,
     below their default 0). `max_concurrent_bidi_streams` MUST be set explicitly, replacing quinn's
     default of 100 (built: 1024).
7.10. **Teardown.** A guardian per `AppStream` watches the live set and MUST reset both halves with
      `APP_WITHDRAWN_CODE` (`0x2207`). Every call on the stream MUST race the same watch, and whichever
      notices first MUST tear down before returning. A stream dropped after withdrawal MUST reset,
      not finish.
7.11. **CLI.** `vox app listen <room> <label>` and
      `vox app open <room> <peer> <label>… [--datagrams]` pipe stdin and stdout; with `--datagrams`
      each stdin line is one datagram and each datagram received is one line. A cut stream MUST exit
      non-zero and say so.
7.12. **In-process library API.** The same operations MUST be exposed from `vox-core` for a mobile
      app that embeds the node (R30). Packaging for Swift and Kotlin belongs to the app.
7.13. Swift is built (`crates/vox-ffi`, UniFFI: `appListen`, `appOpen`, stream and datagram calls;
      ADR-014 "The embedded node"). Kotlin is *not built*.

### Decision 8 — calls sit on the app API (R32)

8.1. A call MUST be an app (label such as `call/v1`): an app stream for signalling, a datagram flow
     for media. 1:1 calls need nothing more from Vox.
8.2. A small-group mesh opens one flow per other participant.
8.3. A forwarding node kept from seeing the media needs SFrame (RFC 9605) inside the app; that is
     out of scope for Vox.

### Proofs

Each proof MUST drive the shipped binary, MUST be mutation-checked and MUST print its counts, and
each MUST run on a direct path and on a forced-relay path.

P1. **DNS.** `dig` through a `53/udp` forward to a real DNS server gets the answer. Mutation: the
    host drops context-0 datagrams, and the proof goes red.
P2. **Denied.** A peer outside the host's keyring gets no answer, and the host's service sees zero
    packets.
P3. **Revocation.** A `dig` loop stops within 1 s of `vox trust remove`.
P4. **Oversize.** 1400- and 4000-byte UDP payloads arrive intact via fragmentation. Mutation:
    disable fragmentation, and they are dropped and counted.
P5. **Relay drops, not stalls.** `iperf3 -u` over the relay with induced loss shows loss and no
    head-of-line stalls; jitter is recorded. Mutation: stream carriage, and the jitter signature
    flips.
P6. **TCP and UDP on the same port** both answer.
P7. **App API.** A 1 MiB app stream round trip with SHA-256; 1000 app datagrams delivered; an opener
    outside the responder's keyring gets 0 incoming notices at the listener; an untrusted
    no-listener reset is byte-identical to an unknown-kind reset.
P8. **Load.** 200 stalled app streams, and a chat message still arrives in under 1 s.

**What is built** (`crates/vox-tui/tests/udp_tunnel_proof.rs` for P1–P6 and 6.7;
`crates/vox-tui/tests/app_api_proof.rs` for P7, P8 and 7.3, 7.4 and 7.10), and where it falls short
of the above:
- **Paths.** P1–P4 and P6 run on both paths. P5 runs on the forced-relay path only (it is a
  property of the relay). P7 and P8 run on a direct path only.
- **P1.** No real DNS server is installed: the responder is in the test (`dig` is real). Mutation:
  the host drops what the flow delivers.
- **P4.** Mutation: fragmentation disabled, and the 4000-byte payload does not arrive; the drop
  counter is not read.
- **P5.** No `iperf3` is installed: the blaster and sink are in the test. Loss is asserted (what the
  lossy leg drops stays lost); latency and gaps are recorded, not bounded. Mutation: stream
  carriage restored, and nothing is lost. The loss is switched on after setup, so P5 measures the
  relay's carriage, not a join over a lossy leg. The actor stall the proof's comment cites
  (V29-08, #43) is closed; a join over a lossy leg is not measured by P5.
- **P8.** Proved only to **1.5 s**: a local append is pushed within one 1 s actor tick, so the same
  message takes 30 ms to 1.03 s with no app streams at all, and the gate bounds it at 1.5 s. The
  decided bound is under 1 s; which one holds is the decider's to rule.

### Milestones

- **M22.1** The datagram seam: decisions 2–4 and `VoxConnection::datagram_stats`. Built.
- **M22.2** Relay circuits on datagram flows: decision 5. Built.
- **M22.3** UDP tunnels: `vox serve … /udp`, then `vox forward … /udp` (decision 6). Built.
- **M22.4** SOCKS5 UDP ASSOCIATE in `vox up` (requirement 6.7). Built.
- **M22.5** The app API: decision 7. Built.

## Consequences

- **Positive.** One mechanism serves UDP, relays and calls on stream gates that already exist.
  Relayed traffic stops head-of-line blocking. Every datagram is 8 bytes smaller.
- **Negative.** Fragmentation amplifies loss roughly by the fragment count, so it is the exception.
  Nested congestion control (inner QUIC over outer QUIC datagrams) is harder to reason about: on a
  lossy relay leg both windows sit at their floor, and at high datagram rates the inner one holds
  datagrams back for tens of milliseconds. Calls are to be sized against this.

## Related ADRs

- **Depends on:** ADR-011, ADR-012, ADR-013, ADR-016, ADR-017, ADR-020; PRD-001 R25–R32.
- **ADR-014** (the embedded node) carries the Swift binding.
