# ADR-011: Transport Substrate

**Status**: implemented (M9, `crates/vox-core/src/transport/`)
**Date**: 2026-06-19
**Updated**: 2026-09-25 — **path-MTU discovery searches to 8192 bytes and the UDP socket buffers are 4 MiB** (PRD-001 R41; see "Throughput (R41)" under Implementation notes). 2026-09-19 — Implementation notes (M9) added; datagram sequence framing + anti-replay window moved into the connection (was caller discipline). 2026-09-20 — stream framing lifted into `transport::framing`; typed streams (`transport::streams`, ADR-016 M14.2).
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: transport, quic, tls, post-quantum, multiplexing, datagrams

## Context

Vox must carry two workloads over one overlay (ADR-001): low-latency *interactive* tunnels (`ssh`
over Vox, ADR-013) and *store-and-forward* log replication (ADR-008), with different
reliability/latency contracts, without one degrading the other. It must compose with identity
(ADR-002), the messaging crypto core (ADR-004), and NAT traversal (ADR-012). A prior review
correctly flagged that "key the QUIC streams from PQXDH/Noise/QUIC-TLS, pending validation" was not
a security spec but a false deferral. This ADR specifies the concrete transport security design.
Grounded in the libp2p TLS spec, IETF `draft-ietf-tls-ecdhe-mlkem`, and RFC 7250.

## Decision

### Substrate = QUIC

A single QUIC connection per peer provides built-in security plus transport-level multiplexing of
independent, ordered, reliable streams with no head-of-line blocking between streams (RFC 9000/9308).
Each tunneled byte stream (ADR-013) and the log-sync traffic (ADR-008) get their own stream; with
QUIC no separate stream muxer is needed. (TCP fallback, if ever required, uses yamux — never mplex,
which lacks per-stream backpressure — but QUIC is primary.)

### Transport security (concrete)

- **PQ-hybrid key exchange.** The QUIC TLS 1.3 handshake uses the hybrid named group
  **X25519MLKEM768** (code point 0x11EC): the key-schedule secret is `concat(ML-KEM-768 secret,
  X25519 secret)`, secure if *either* component holds — PQ confidentiality for the transport from day
  one. Only hybrid PQ groups are offered or accepted (no classical-only group), so there is no
  downgrade target.
- **Identity authentication (libp2p-style, no CA/PKI).** Each peer presents a **self-signed
  certificate carrying its Vox identity public key in a custom X.509 extension**, and signs
  `"vox-tls-handshake:" ‖ cert_public_key` with its **identity private key** (the composite
  Ed25519+ML-DSA key, ADR-002) — a proof-of-possession that binds the ephemeral TLS certificate key
  to the long-term Vox identity. The PoP string `"vox-tls-handshake:" ‖ cert_public_key` is a
  **TLS-layer signed string, deliberately outside** the ADR-008 CBOR struct-domain regime (it is not a
  log struct). **Extension layout (concrete):** OID **`1.3.6.1.4.1.<VOX-PEN>.1.1`** where `<VOX-PEN>` is
  a **Vox-owned IANA Private Enterprise Number** (registration pending; until assigned, builds use the
  documented provisional arc and the interop matrix pins the exact OID — Vox does **not** squat on
  libp2p's PEN 53594), `critical = false`, value = canonical-CBOR (ADR-008, tag `0x0009`)
  `{ composite_pubkey, pop_sig }` (ADR-003 `0x03/0x04` composite encodings). The verifier derives the Vox
  identity from the extension and **MUST require it to match the expected peer, aborting on mismatch**
  (ADR-008 error `0x05`). This authenticates Vox identities without a CA and without RFC-7250's
  out-of-band gap. (Production Rust prior art: the `libp2p-tls` crate's extension mechanism.)
- **PQ authentication.** Because the identity-binding signature is the composite Ed25519+ML-DSA key,
  handshake authentication is post-quantum; the TLS certificate's own self-signature may be classical
  since authentication is carried by the PQ composite extension signature and confidentiality by the
  hybrid group.

### Layering vs PQXDH (resolves the prior ambiguity)

Two distinct, separately-keyed layers, each binding the Vox identity:
- **Transport layer (this ADR):** QUIC-TLS 1.3 with X25519MLKEM768 + the identity-extension PoP.
  Authenticates the peer and secures the link.
- **Messaging layer (ADR-004):** PQXDH + Double Ratchet provides the per-author/pairwise *message*
  keys, run **over** the authenticated transport. Vox does **not** run PQXDH as the transport
  handshake, and **application/message keys are NOT derived from the TLS exporter** — so a transport
  compromise does not expose message forward-secrecy / post-compromise security, which remain owned
  by the ratchet. Tunnel streams (ADR-013), which are not ratcheted messages, use the transport's
  AEAD directly.

### Replay, 0-RTT, downgrade

- **0-RTT is disabled.** QUIC/TLS 1.3 0-RTT early data is replayable; for a security overlay that
  risk is unacceptable, so Vox never offers or accepts 0-RTT.
- **Datagram anti-replay.** RFC 9221 datagrams carry a Vox-framing 64-bit sequence number + a sliding
  replay window (**default 1024 packets**, DTLS-style bitmap); out-of-window or duplicate datagrams are
  dropped.
- **Downgrade prevention.** TLS 1.3's Finished MAC already binds the full transcript (including the
  negotiated group); offering only hybrid PQ groups removes any downgrade target; the negotiated
  suite is additionally recorded in the application **session-establishment** entry (ADR-008 canonical
  struct, tag `0x0011`, body `{ peer_id, suite_id, negotiated_group, ts }`) so downgrade is detectable
  end-to-end.
- **Interop is a release criterion, and failure is hard (no silent fallback).** Because Vox offers
  *no* classical-only group, a peer or library that cannot negotiate the required hybrid group simply
  **fails to connect with a clear, surfaced error** — it never silently downgrades. The supported
  provider set (quinn + rustls with the X25519MLKEM768 hybrid provider, version-pinned) and a
  cross-version **interop test matrix** (each supported client/library pair must complete the handshake
  + identity-PoP) are explicit release gates, not assumptions. The required-suite floor is versioned
  (ADR-003) so the matrix advances deliberately.

### Two contracts on one connection

Reliable/ordered QUIC streams carry async/bulk traffic (log replication, file transfer); the RFC
9221 unreliable-DATAGRAM extension carries low-latency/loss-tolerant flows — all under one handshake.
To stop bulk traffic degrading interactive flows: separate **streams** for isolation, and separate
QUIC **connections** only where genuinely differential network treatment (DSCP/QoS) is required
(QUIC has one congestion controller per connection); otherwise minimize connection count.

### Rust building blocks

`quinn` (QUIC) + `rustls` with the post-quantum/hybrid provider (X25519MLKEM768), and
`libp2p-tls`-style self-signed-cert + identity-extension handling for the PoP binding. All
production-ready as of 2026.

## Consequences

### Positive
- A concrete, PQ-hybrid, identity-authenticated transport — no deferral, modeled on deployed prior
  art (libp2p, IETF hybrid TLS).
- Clean layering: transport compromise cannot undermine message FS/PCS (owned by ADR-004).
- One encrypted connection carries interactive tunnels + async sync without cross-stream HOL blocking.

### Negative
- Disabling 0-RTT costs a round trip on resumption — accepted for the replay-safety it buys.
- Per-connection congestion control means true QoS separation needs multiple connections (overhead).
- The custom identity-extension + composite-PQ-signature cert path needs careful implementation and
  review (a wrong binding would break peer authentication).

### Neutral
- QUIC is also the natural substrate for ADR-012's UDP-based NAT traversal.

## Implementation notes (M9)

These record the concrete decisions made building this ADR (`crates/vox-core/src/transport/`), so the spec and code stay in lockstep:

- **Datagram anti-replay is a property of the connection.** `VoxConnection` owns the outbound 64-bit
  sequence counter and the inbound DTLS-style sliding window (default 1024 packets, per the rule above).
  `send_datagram(payload)` prepends the next sequence; `recv_datagram()` parses the prefix, runs the
  window, and **drops** — never returns — a datagram that is unframed (shorter than the 8-byte prefix),
  a duplicate, or below the window, counting each in `datagrams_dropped()` so a live replay shows up
  as a rising counter. The application only ever sees payloads and cannot choose or observe sequence
  numbers. The framing/window primitives remain in `transport::datagram` for tests and vectors.
  *(2026-09-19 review: previously the connection exposed raw datagram bytes and the window was applied
  only by caller discipline — a byte-exact replay reached the application, proven over real loopback
  QUIC and now pinned by a test.)* The raw `quinn()` accessor still exists for advanced callers (M11)
  and bypasses this layer by construction; any such use must apply the same rule.
- **Stream framing and typed streams (ADR-016 M14.2).** The u32-BE length prefix that
  `QuicStreamTransport` applied to M5 frames is now the async pair `transport::framing::{write_frame,
  read_frame}` (a clean FIN exactly at a frame boundary is the success half-close → `None`; a FIN
  mid-frame, a reset, or a length above the caller's per-flow cap is an error), and every stream flow
  — M5 sync, the rendezvous service, the join stream — uses it. Each bi-stream is **typed by its
  first frame**, the one-element canonical-CBOR array `[kind]` (`transport::streams::StreamKind`:
  `sync` 1, `join` 2, `pairwise` 3, `rendezvous` 4, `tunnel` 5, `coord` 6); `open_typed` writes it,
  `accept_typed` reads it and refuses an unknown kind before any flow bytes are read. `close_code`
  is public so any flow can reset its stream with the ADR-008 code. M5 sync opens a **typed** `sync`
  stream via `node::syncstream::open_sync` (M14.6); `QuicStreamTransport::open/accept` remain for
  callers that pair streams themselves.
- **Known gaps (recorded 2026-09-19).** `confirm_hybrid_group` checks only ALPN `vox/1`, and
  `SessionEstablishment::new` **hardcodes** the group code point `0x11EC`, so the "downgrade
  auditability" record documents a constant rather than an observation — the real guarantee is
  `assert_pq_only` on both providers plus TLS transcript binding, which is sound but should be what
  the record reports. All connect/accept failures collapse to `SignatureInvalid` (unreachable vs
  handshake vs identity are indistinguishable to callers). The identity-extension OID uses the
  placeholder PEN `1234567`. `VoxEndpoint::accept*` returns `Err` on a single failed handshake, so a
  server loop must catch-and-continue. Gate obligation: the cross-version interop matrix
  (handshake + identity-PoP) does not exist — no second implementation, no version-pinned matrix, no
  CI job; the PoP is over the raw subject-public-key bits (not SPKI DER), which such a matrix must pin.
- **Throughput (R41), 2026-09-25.** A direct tunnel through `vox forward` on one machine ran at ~290
  MB/s (2.3 Gbit/s) against ~10 GB/s (80 Gbit/s) for plain loopback TCP. Profiled with macOS
  `sample` during a transfer: the **receiving** node was mostly idle; the **sending** node spent
  its time in `__sendmsg` (one syscall per 1452-byte packet) and in the connection lock that
  `sendmsg` runs under, which the splice's stream writes wait on. AES-GCM (aws-lc) was a few
  percent; the flow-control windows did not bind. Changes, each A/B-measured against the others in
  interleaved rounds on one box (quiet-round medians):
  - `MtuDiscoveryConfig::upper_bound` and `EndpointConfig::max_udp_payload_size` raised to **8192**
    (`quic::MAX_UDP_PAYLOAD`): ~290 → ~1100 MB/s on loopback. Discovery probes, so a 1500-byte link
    keeps 1452 and gains nothing — this helps loopback and jumbo-frame links only. 16356 (the
    loopback MTU) broke connections on macOS, whose `net.inet.udp.maxdgram` is 9216.
  - UDP socket buffers 4 MiB each way (`quic::UDP_SOCKET_BUFFER`): no gain alone, but without them
    a burst overflowed the default buffer and quinn's black-hole detection dropped the MTU to 1200.
  - Measured and **not** kept: 4 runtime workers instead of 2 (no change). A 16 MiB stream window
    with a **64 MiB** send window (more in flight, more overflow loss, and the MTU collapsed) was
    also not kept; the windows that were kept are below.
  - **quinn-udp `fast-apple-datapath`** (batched `sendmsg_x`): +18% at a 1452-byte MTU, +4% at
    8192. It calls a private Apple API. The decider adopted it for every platform, iOS included.
  - **Stream window 16 MiB, send window 32 MiB** (`quic::STREAM_WINDOW`). quinn's default 1.25 MB
    stream window is sized for 100 Mbit/s at 100 ms, so a longer or faster path is capped by credit,
    not by the link. **History, withdrawn method:** these were measured over macOS dummynet shaping
    set up with `sudo`, which agents may no longer run (2026-09-25). Vox/raw-TCP ratios at 1 Gbit/s
    were 0.94–1.01 (1 ms and 20 ms RTT), and restoring quinn's default window dropped the 20 ms
    class to 0.46. They stand as history only. R41 against an emulated link is measured by
    `perf_r41` (its own owner and method).
  - **Unshaped loopback: ~1.1–1.2 GB/s (8.8–9.6 Gbit/s), about 11–12% of loopback TCP.** The decider
    has ruled that loopback is the wrong yardstick (PRD-001 R41 as clarified 2026-09-25): R41 is
    measured against a link.
  - **Observed, unexplained:** on unshaped loopback, 2 of 54 transfers collapsed to ~14 MB/s for the
    whole transfer, with and without the window change. Recorded, not investigated.

## Links
**Depends on**: ADR-002, ADR-004, ADR-008.
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
