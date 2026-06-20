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
//! - **Identity authentication without a CA.** Each peer presents a self-signed
//!   leaf carrying its Vox composite identity (ADR-002) in a custom X.509 extension
//!   plus a composite proof-of-possession over `"vox-tls-handshake:" ‖
//!   cert_public_key`; the verifier recovers the identity and requires it to match
//!   the expected peer, aborting on mismatch ([`identity_cert`], [`verifier`]).
//! - **0-RTT disabled.** Early data is never offered or accepted (replay-unsafe).
//! - **Datagram anti-replay.** A Vox 64-bit sequence + a DTLS-style sliding window
//!   (default 1024) drops duplicate/out-of-window datagrams ([`datagram`]).
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
//!   ([`quic::VoxConnection::open_stream`] / `send_datagram` / `quinn`); the tunnel
//!   service that uses them is M11.
//! - **The IANA PEN** for the identity-extension OID is pending; M9 uses the
//!   documented provisional arc ([`identity_cert::VOX_IDENTITY_EXT_OID`]) which the
//!   interop matrix pins as a release gate.

pub mod datagram;
pub mod identity_cert;
pub mod provider;
pub mod quic;
pub mod session;
pub mod stream_transport;
pub mod verifier;

#[cfg(test)]
mod tests;
