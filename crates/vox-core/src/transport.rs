//! # Transport substrate — QUIC (ADR-011) — milestone M9
//!
//! The real network transport the rest of Vox runs over: a single authenticated,
//! post-quantum-hybrid QUIC connection per peer, multiplexing independent reliable
//! streams (no cross-stream head-of-line blocking) for bulk/sync traffic and RFC
//! 9221 unreliable datagrams for low-latency flows. This is the concrete
//! realization of the abstract [`crate::log::sync::Transport`] M5 defined: M5's
//! anti-entropy sync runs over a real quinn-backed stream here
//! ([`quic::QuicStreamTransport`]).
//!
//! ## What this layer guarantees (ADR-011)
//! - **PQ-hybrid key exchange.** The TLS 1.3 handshake offers and accepts *only*
//!   the X25519MLKEM768 hybrid group (TLS code point `0x11EC`); there is **no
//!   classical-only group**, so no downgrade target. A peer that cannot negotiate
//!   it fails to connect with a surfaced error — never a silent fallback
//!   ([`provider`]).
//! - **Identity authentication without a CA, inside the connection.** The TLS handshake
//!   authenticates only the daemon, with a neutral self-signed leaf ([`identity_cert`],
//!   [`verifier`]); which node a connection is to is proved right after it by the identity
//!   exchange ([`identity`]): composite signatures bound to the TLS session by its exporter, the
//!   responder proving first. One endpoint serves every node of a daemon.
//! - **0-RTT disabled.** Early data is never offered or accepted (replay-unsafe).
//! - **Datagram flows.** Each datagram names the flow it belongs to; one reader per
//!   connection routes it there and drops and counts the rest, and oversize packets
//!   are fragmented and reassembled inside Vox ([`datagram`], [`router`], ADR-022).
//!   Replay protection is QUIC's (RFC 9000 §12.3); Vox adds no window of its own.
//! - **Downgrade auditability.** The negotiated suite + group are recorded in a
//!   session-establishment entry (tag `0x0011`) so a downgrade is detectable
//!   end-to-end ([`session`]).
//!
//! ## Layering vs the messaging crypto (resolves the prior ADR-011 ambiguity)
//! This transport authenticates the peer and secures the link. It does **not**
//! key the messaging layer: ADR-004's PQXDH + Double Ratchet message keys are
//! **not** derived from the TLS exporter, so a transport compromise cannot expose
//! message forward-secrecy / post-compromise security (those stay owned by the
//! ratchet). Tunnel streams (ADR-013, M11) use this transport's AEAD directly;
//! ratcheted messages do not.
//!
//! ## The one Rust-maximal exception (ADR-001 #10)
//! Vox application crypto is RustCrypto. The TLS crypto **provider**
//! ([`provider::vox_crypto_provider`]) is the single unavoidable exception:
//! rustls's `aws-lc-rs` provider (a C/asm backend) is what currently supplies the
//! X25519MLKEM768 hybrid group named by ADR-011, and no Rust-pure provider for it
//! exists. The exception is scoped to the transport handshake; `#![forbid(unsafe_code)]`
//! still holds in this crate (the unsafe lives in the dependency), and no
//! application/message/log key ever touches this provider.
//!
//! ## Scope boundaries (documented, not stubbed)
//! - **NAT traversal / hole-punching / bootstrap** are M10 (ADR-012). M9 is the
//!   QUIC substrate they build on; [`quic::VoxEndpoint`] binds a UDP socket and
//!   dials/accepts by `SocketAddr`, which M10 will drive through DCUtR + a
//!   rendezvous.
//! - **Tunnel streams (TCP-over-Vox)** are M11 (ADR-013). M9 exposes the stream +
//!   datagram primitives and the connection AEAD
//!   ([`quic::VoxConnection::open_stream`] / `bind_flow` / `quinn`); the tunnel
//!   service that uses them is M11.
//! - **No certificate carries an identity** (ADR-011 requirement 37): the old identity
//!   extension, its OID arc and its tag `0x0009` apply to nothing.

pub mod congestion;
pub mod datagram;
pub mod framing;
pub mod identity;
pub mod identity_cert;
pub mod mux;
pub mod provider;
pub mod quic;
pub mod router;
pub mod session;
pub mod stream_transport;
pub mod streams;
pub(crate) mod taper;
pub mod verifier;
pub(crate) mod vox_bbr;
