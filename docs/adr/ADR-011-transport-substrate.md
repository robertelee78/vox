# ADR-011: Transport Substrate

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: built (M9, `crates/vox-core/src/transport/`), except where a requirement says
otherwise: the Vox IANA Private Enterprise Number (requirement 6), the session record's observed
group (requirement 12) and the interop matrix (requirement 14) are not built. A TCP fallback
(requirement 2) does not exist.
**Decided 2026-10-03, not built (#397, ADR-026):** the identity exchange (requirements 27–40)
replaces identity in the TLS handshake (requirements 5–8) and ALPN `vox/1`. Until it is built, the
code does what requirements 5–8 say, and requirements 27–40 are planned.
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: transport, quic, tls, post-quantum, multiplexing, datagrams

## Context

Vox carries two workloads over one overlay (ADR-001): low-latency interactive tunnels (ADR-013) and
store-and-forward log replication (ADR-008). They have different reliability and latency contracts,
and neither may degrade the other. The transport composes with identity (ADR-002), the messaging
crypto core (ADR-004) and NAT traversal (ADR-012). This ADR is the concrete transport security
design, grounded in the libp2p TLS specification, IETF `draft-ietf-tls-ecdhe-mlkem` and RFC 7250.

## Requirements

### Substrate = QUIC

1. **Substrate = QUIC.** Vox MUST use one QUIC connection per peer (RFC 9000/9308). Each tunneled byte stream (ADR-013)
   and the log-sync traffic (ADR-008) MUST get their own stream; no separate stream muxer is used.
2. If a TCP fallback is ever added, it MUST use yamux and MUST NOT use mplex (no per-stream
   backpressure). QUIC is primary.
3. **Two contracts on one connection.** Reliable, ordered QUIC streams MUST carry bulk traffic (log replication, file transfer); RFC 9221
   datagrams carry low-latency, loss-tolerant flows, under the same handshake. Bulk traffic MUST be
   kept off interactive flows by separate streams. Separate QUIC connections SHOULD be used only
   where differential network treatment (DSCP/QoS) is genuinely required, since QUIC has one
   congestion controller per connection; otherwise the connection count SHOULD be minimal.

### Transport security (concrete)

Requirements 5–8 describe the built identity-in-the-handshake design. They are **superseded** by
requirements 27–40 and MUST be removed from the code when those are built.

4. **PQ-hybrid key exchange.** The QUIC TLS 1.3 handshake MUST use the hybrid group X25519MLKEM768
   (code point `0x11EC`), whose key-schedule secret is `concat(ML-KEM-768 secret, X25519 secret)`.
   Only hybrid PQ groups MUST be offered or accepted; no classical-only group. The provider's
   `kx_groups` MUST be exactly `[X25519MLKEM768]`, enforced at every config boundary
   (`provider::assert_pq_only`).
5. **Identity authentication, no CA.** Each peer MUST present a self-signed certificate carrying its
   Vox identity public key in a custom X.509 extension, and MUST sign
   `"vox-tls-handshake:" ‖ cert_public_key` with its composite Ed25519+ML-DSA identity key
   (ADR-002), binding the ephemeral certificate key to the long-term identity. `cert_public_key` is
   the certificate's raw subject-public-key bytes, not the SPKI DER. This signing string is a
   TLS-layer string, deliberately outside ADR-008's CBOR struct-domain regime.
6. **Extension layout.** OID `1.3.6.1.4.1.<VOX-PEN>.1.1`, where `<VOX-PEN>` MUST be a Vox-owned IANA
   Private Enterprise Number; Vox MUST NOT use libp2p's PEN 53594. `critical = false`. The value is
   canonical CBOR (ADR-008, tag `0x0009`) `{ composite_pubkey, pop_sig }` in ADR-003's `0x03`/`0x04`
   composite encodings. *Not built:* the PEN is unregistered and builds use the placeholder
   `1234567` (`identity_cert.rs`); the interop matrix (requirement 14) MUST pin the exact OID.
7. The verifier MUST derive the Vox identity from the extension and MUST require it to match the
   expected peer, aborting on mismatch (ADR-008 error `0x05`). A missing or duplicated extension
   MUST be rejected.
8. **PQ authentication.** Handshake authentication is carried by the composite identity signature
   in the extension; the certificate's own self-signature MAY be classical.
9. **Layering.** The transport (this ADR) and messaging (ADR-004: PQXDH + Double Ratchet, run over
   the authenticated transport) MUST stay separately keyed. Vox MUST NOT run PQXDH as the transport
   handshake, and application or message keys MUST NOT be derived from the TLS exporter. Binding a
   signature to the connection with the exporter (requirement 30) is not deriving a key. Tunnel
   streams (ADR-013), which are not ratcheted messages, use the transport's AEAD directly.

### Replay, 0-RTT, downgrade

10. **0-RTT is disabled.** Vox MUST NOT offer or accept TLS 1.3 early data
    (`max_early_data_size = 0`) and MUST NOT issue resumption tickets (`send_tls13_tickets = 0`).
11. **No Vox replay window.** Each datagram is `varint flow_id ‖ varint context ‖ body` on a flow
    bound to a stream (ADR-022). Replay and duplication are QUIC's concern (RFC 9000 §12.3); Vox
    MUST NOT add its own datagram sequence number or replay window.
12. **Downgrade auditability.** The negotiated suite MUST be recorded in a session-establishment entry (ADR-008
    canonical struct, tag `0x0011`, body `{ peer_id, suite_id, negotiated_group, ts }`). *Gap:*
    quinn 0.11 does not expose the negotiated group, so `SessionEstablishment::new` fills
    `negotiated_group` from the constant this build offers, not from the handshake. The guarantee
    rests on requirement 4 and on TLS 1.3 binding the negotiated parameters into the Finished MAC.
    The post-handshake check confirms only the ALPN `vox/1` (`confirm_vox_alpn`), and MUST NOT be
    described as confirming the group. *Decided, not built:* the ALPN becomes `vox/2`
    (requirement 27), and the record is written only after the identity exchange completes
    (requirement 33).
13. **Hard failure.** A peer or library that cannot negotiate the required hybrid group MUST fail to
    connect with a clear, surfaced error and MUST NOT silently downgrade. A failure of
    authentication is reported as `SignatureInvalid`; any other handshake failure (refused, timed
    out, closed) is reported by its own cause (`quic::handshake_failed`).
14. **Interop is a release gate.** The supported provider set (quinn + rustls with the
    X25519MLKEM768 provider, version-pinned) and a cross-version interop matrix (each supported
    client and library pair completes the handshake and identity proof of possession, with the OID
    and the raw-key binding pinned) MUST be release gates. Once requirements 27–40 are built, the
    matrix pins the exchange's flights, signature labels and exporter label instead of the OID. The required-suite floor is versioned
    (ADR-003). *Not built:* there is no second implementation, matrix or CI job.

### Datagram flows (ADR-022 M22.1)

15. `VoxConnection` MUST start one `DatagramRouter` with the connection, and it MUST be the only
    reader of the connection's datagrams. It routes by flow ID to the flow's bounded inbox, and MUST
    drop and count (`datagram_stats()`) a datagram for an unknown or ended flow, a full inbox, an
    unknown context, or one it cannot parse.
16. A flow MUST be bound to a stream (`bind_flow`) and end when the stream ends. The flow ID is the
    stream's full QUIC stream ID.
17. A packet larger than one datagram MUST be fragmented and reassembled (`transport::datagram`:
    at most 255 fragments, 500 ms, 32 partial packets per flow, 1 MiB per connection) and MUST NOT
    be retransmitted. Callers MUST NOT read datagrams through the raw `quinn()` accessor, which
    would race the router.

### Stream framing and typed streams (ADR-016 M14.2)

18. Every stream flow MUST use the u32-BE length-prefixed framing of
    `transport::framing::{write_frame, read_frame}`. A clean FIN exactly at a frame boundary is the
    success half-close; a FIN mid-frame, a reset, or a length above the caller's per-flow cap MUST
    be an error.
19. Each bi-stream MUST be typed by its first frame, the one-element canonical-CBOR array `[kind]`
    (`transport::streams::StreamKind`). This ADR fixes `sync` 1, `join` 2, `pairwise` 3,
    `rendezvous` 4, `tunnel` 5, `coord` 6; later kinds belong to the ADRs that define them.
    `accept_typed` MUST refuse an unknown kind before reading any flow bytes.

`open_typed` writes the kind frame and `accept_typed` reads it; `quic::close_code` is public, so any
flow can reset its stream with the ADR-008 code. M5 sync opens a typed `sync` stream through
`node::syncstream::open_sync` (M14.6); `QuicStreamTransport::open`/`accept` remain for callers that
pair streams themselves.

### Accepting connections

20. A server's accept loop MUST NOT let one failed handshake end the loop. `accept_incoming` yields
    the next connection attempt, and `finish_incoming` completes one handshake and admission,
    bounded by a 30-second handshake timeout. The node's own loop accepts in these two phases
    (`0653e050`); the convenience `VoxEndpoint::accept*` still returns `Err` for a single failed
    handshake, so a caller looping on it has to catch and continue.

### Throughput (R41)

21. **Path MTU.** When the socket's granted receive buffer is at least 4 MiB, both
    `MtuDiscoveryConfig::upper_bound` and `EndpointConfig::max_udp_payload_size` MUST be 8192
    (`quic::MAX_UDP_PAYLOAD`); quinn searches only up to the smaller of the two. Otherwise both MUST
    stay at quinn's 1452, and the node MUST print one line saying why (`quic::mtu_ceiling_for`).
    The node MUST read the receive buffer back after setting it, since Linux caps `SO_RCVBUF`
    silently.
22. **Socket buffers.** UDP send and receive buffers MUST be requested at 4 MiB each
    (`UDP_SOCKET_BUFFER`).
23. **Batched sends.** quinn-udp's `fast-apple-datapath` MUST be enabled on every platform, iOS
    included (decider).
24. **Flow-control windows.** The stream receive window MUST be 16 MiB (`quic::STREAM_WINDOW`) and
    the send window 32 MiB. The connection receive window MUST be bounded (`quic::CONNECTION_WINDOW`,
    two stream windows), never quinn's unlimited default, so one peer writing into streams nobody
    reads cannot park unbounded memory in a node. On integrate/v0.3.0 that is the base: each
    running tunnel this node authorized adds one `STREAM_WINDOW` on its own connection, up to
    `TUNNELS_PER_PEER` (16) per member (`quic.rs`, V210-81; the tunnel cap is ADR-013's).
25. **Restart after idle.** After 1 s with nothing sent, and at least 4 smoothed RTTs, the next send
    MUST start from a fresh congestion controller: initial window, slow start
    (`transport::congestion::IdleRestart`). Unlike RFC 5681 §4.1 it MUST NOT keep the slow-start
    threshold.
26. R41 MUST be measured against an emulated link, not against loopback (decider, PRD-001 R41 as
    clarified 2026-09-25), by `perf_r41_tunnel_throughput_proof`.

### Identity exchange on a shared endpoint (ADR-026)

One daemon's endpoint serves every node it hosts (ADR-026), so the TLS handshake cannot say which
node a dialler wants without showing it on the path: a fingerprint in SNI or ALPN is readable by any
observer (RFC 9001 §5.2; rustls has no server ECH), a QUIC connection id is the client's random
choice, and room-keyed tags give no secret to trust-only dials, anchors or circuits. QUIC forbids TLS
post-handshake client authentication (RFC 9001 §4.4). The identity is therefore proved inside the
connection, bound to the TLS session by its exporter.

27. **Neutral leaf.** The TLS 1.3 handshake MUST authenticate only the daemon: a self-signed leaf with
    no identity extension, generated once per daemon run and used for every connection of that run.
    The handshake MUST keep requirements 4, 10 and 13. The ALPN MUST be `vox/2`.
28. **One exchange per connection,** on the first client-opened bidirectional stream, immediately
    after the handshake, in three flights:
    1. dialler → `ASK { target_fp }`;
    2. listener → `PROVE { target_pubkey, sig_target("vox-id/v2/resp" ‖ E ‖ target_fp) }`, or the
       generic refusal (requirement 32);
    3. dialler, only after checking flight 2 against the pinned expected peer →
       `CLAIM { dialler_pubkey, sig_dialler("vox-id/v2/init" ‖ E ‖ target_fp ‖ dialler_fp) }`.

    Signatures are composite Ed25519+ML-DSA (ADR-002), so authentication stays post-quantum. Flight 3
    MAY carry the dialler's first application bytes.
29. **The responder proves first.** The dialler MUST NOT send `CLAIM` until `PROVE` has verified
    against the identity it pinned. A dialler therefore reveals its identity only to a party that has
    just proven the pinned identity on this TLS session, as the handshake did before.
30. **Exporter binding.** `E` MUST be the TLS exporter output with label `vox/identity/v2`, 64 bytes.
    The exporter is mandatory: if it cannot be read, the connection MUST be refused. (The
    connection tie-break's fallback when the exporter is missing does not apply here.)
31. **Direction labels.** The listener signs `vox-id/v2/resp` and the dialler `vox-id/v2/init`, so a
    flight MUST NOT verify in the other role, including between two nodes of one daemon.
32. **Generic refusal.** One refusal, byte-identical on the wire, MUST answer: an unknown target, a
    target attached but locked, a detached target, a malformed `ASK`, and a rate-limited source. It
    MUST be sent only after a fixed delay drawn from the window a real `PROVE` takes, so its timing
    does not distinguish these cases from each other.
33. **Nothing before the exchange.** Until flight 3 verifies, any other stream (bidirectional or
    unidirectional), any datagram, a second `ASK` or `CLAIM`, a malformed flight, or an exchange not
    finished within 5 s MUST close the connection. Nothing above the transport sees the connection,
    and no session-establishment record (requirement 12) is written, until then.
34. **Cost discipline.** The listener MUST sign only after the per-source rate limit and the
    pre-identity connection cap admit the `ASK`. Pre-identity connections MUST be capped (sharing the
    accept gate, requirement 20) and MUST time out after 5 s. The node's long-term key signs once
    per accepted connection.
35. **After the exchange.** The listener MUST apply admission (trust, join gate; ADR-016) as the
    target node. The result MUST fill the verified-peer slot the handshake verifier fills today, so a
    connection means (local node, remote node, remote daemon leaf) to everything above the transport.
36. **Everywhere.** The exchange MUST run on every Vox connection: direct dials, hole-punched
    connections, the inner connection of a relay circuit (ADR-012), and between two nodes of one
    daemon over its own address.
37. **Where the identity is carried.** After this change no certificate carries a Vox identity: the
    composite public key travels only in `PROVE` and `CLAIM`. Requirement 6's OID and PEN, and the
    identity extension (tag `0x0009`), then apply to nothing; of #382 (V030-33), only the session
    record's group (requirement 12) remains.
38. **Latency.** The exchange adds one round trip before the dialler may send and about 1.5 round
    trips to the listener's admission. R40 (under 1 s) and R42 (under 2 s) MUST be re-measured with
    it.
39. **Accepted cost (ADR-026).** A party that knows a node's fingerprint can test, by naming it,
    whether that node is hosted and unlocked at an address. The generic refusal (requirement 32)
    keeps it from learning anything more.
40. **Proofs**, by real use of the shipped binary (ADR-018), each with its mutant:
    - path privacy: a UDP proxy records every datagram of setup and no fingerprint appears (mutant:
      SNI = fingerprint);
    - exporter binding: a `CLAIM` replayed onto another connection is refused, and a second `ASK` on
      one connection closes it (mutants: no exporter in the signature; no one-exchange rule);
    - reflection: a `PROVE` fed back as a `CLAIM` is refused (mutant: one shared label);
    - responder first: a fake listener at a node's address, without its key, never receives the
      dialler's `CLAIM` (mutant: `CLAIM` sent before `PROVE` is checked);
    - no further oracle: unknown, locked and detached targets get byte-identical refusals in the same
      timing window (mutant: a distinct refusal for locked);
    - pre-identity gating: datagrams or extra streams before the exchange close the connection, and a
      flood of pre-identity connections is capped and times out (mutant: the datagram router started
      before the exchange).

## Known limits

- **The PEN placeholder** (requirement 6) and **the session record's constant group**
  (requirement 12) are open: #382 (V030-33).
- **The interop matrix** (requirement 14) is an open release gate, awaiting the decider (V030-29
  decider question 32).

Fixed since the old text: macOS black-holing at 1452 bytes with a 256 KiB receive buffer was
quinn-proto 0.11.14 reading overflow loss as a black hole. quinn-proto 0.11.18 (7c14ec60, #206) fixed
it; re-measured through `vox forward`, 0 of 10 runs black-holed (#381, V210-158, closed).

## Consequences

- **Positive.** A concrete PQ-hybrid, identity-authenticated transport modelled on deployed prior
  art; a transport compromise cannot undermine message forward secrecy or post-compromise security
  (owned by ADR-004); one encrypted connection carries tunnels and sync without cross-stream
  head-of-line blocking. QUIC is also the substrate for ADR-012's UDP NAT traversal.
- **Negative.** Disabling 0-RTT costs a round trip on every reconnection. Per-connection congestion
  control means true QoS separation needs more connections. The composite signature path is
  security-critical: a wrong binding breaks peer authentication. The identity exchange (requirements
  27–40) adds a round trip before a dialler may send, and lets a party that knows a fingerprint probe
  whether that node is hosted at an address. The 8192-byte
  ceiling helps only loopback and jumbo-frame links; a 1500-byte link keeps 1452.

## Related ADRs

- **Depends on:** ADR-002, ADR-004, ADR-008, ADR-026 (the shared endpoint).
- **Depended on by:** ADR-012, ADR-013, ADR-022 (datagram flows), ADR-024 (tapered congestion
  control).
- **ADR-019** proposes removing the AWS-LC provider this ADR uses.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
