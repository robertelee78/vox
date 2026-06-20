# ADR-011: Transport Substrate

**Status**: proposed
**Date**: 2026-06-19
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
