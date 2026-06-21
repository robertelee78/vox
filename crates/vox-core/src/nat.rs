//! NAT traversal, bootstrap, and reachability (ADR-012).
//!
//! Vox connects peers with no privileged central server. This module provides the
//! pieces ADR-012 specifies, in two layers:
//!
//! ## Authenticated rendezvous (the security core)
//! - [`multiaddr`] — the endpoint addressing ([`multiaddr::Multiaddr`] /
//!   [`multiaddr::EndpointList`]): IPv6, IPv4, and relay-hint addresses with a
//!   canonical, strictly-decoded CBOR encoding.
//! - [`record`] — the two signed record classes published at the rendezvous key
//!   ([`mod@crate::join::rendezvous`]): [`record::RendezvousRecord`] (member,
//!   composite-signed) and [`record::PreJoinRecord`] (pre-join, self-signed,
//!   carrying a prekey bundle — no log authority).
//! - [`store`] — [`store::RendezvousStore`], the reader-side policy gate: member-
//!   only admission, one current record per `(author, channel, epoch)`, monotone
//!   `(seq, timestamp)` anti-replay, a refresh-rate floor, TTL + clock-skew bounds,
//!   epoch-scoping, and anti-spam capacity. This is what makes "a poisoner cannot
//!   inject or replay endpoints" true.
//! - [`bootstrap`] — [`bootstrap::BootstrapSet`], the user-controlled cold-start
//!   introducer set (the user's own node, plus any opted-in community set).
//!
//! ## Reachability (preferring direct connections)
//! - [`portmap`] — automatic IPv4 port-mapping: PCP (RFC 6887) with a NAT-PMP
//!   (RFC 6886) fallback, real UDP clients against the default gateway.
//! - [`reachability`] — the prefer-direct ladder and Happy-Eyeballs-style candidate
//!   ordering (IPv6 first, then IPv4, then relay) over the M9 QUIC transport.
//! - [`holepunch`] — DCUtR-style hole-punch coordination (Connect/Sync with a
//!   half-RTT timer) for the case where both peers are behind NAT but a coordinator
//!   is reachable.
//!
//! ## Honest limit (ADR-012)
//! Two peers both behind CGNAT/symmetric NAT with no IPv6 and no reachable
//! coordinator cannot connect. The reachability ladder degrades to the relay rung
//! (the user's own node) for that residual; it never reports a false success.

pub mod bootstrap;
pub mod holepunch;
pub mod multiaddr;
pub mod portmap;
pub mod reachability;
pub mod record;
pub mod store;
