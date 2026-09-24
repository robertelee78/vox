//! Overlay tunneling — TCP-over-Vox (ADR-013).
//!
//! Vox carries arbitrary TCP/IP between channel members over the M9 QUIC substrate
//! (ADR-011) reached via M10 NAT traversal (ADR-012), with `ssh` over Vox as the
//! canonical use case. Reach is the **host's own decision** (ADR-017 decision 3): its
//! trust keyring intersected with the room's current authors, enforced at stream setup
//! and for the life of the session. Room membership alone grants no tunnel reach.
//!
//! Modules:
//! - [`addr`] — identity-derived overlay addressing for the TUN model (self-
//!   certifying Vox-CGA /128; an address grants no reachability).
//! - [`service`] — signed [`service::ServiceAdvertisement`]s and discovery-gating by
//!   sealing each ad only to the members holding the matching `dial:` capability.
//! - [`sshca`] — "ssh over Vox": OpenSSH certificate issuance bound to the verified
//!   Vox identity (no host-key TOFU).
//! - [`session`] — the per-stream tunnel data path over one QUIC stream, with reach
//!   enforced at stream setup (the ssh-style port-forward primary model).
//! - [`socks`] — a SOCKS5 front-end that maps `CONNECT` requests onto tunnel
//!   sessions.
//!
//! ## Scope note (TUN/VPN path)
//! ADR-013 also offers an optional TUN virtual-interface (VPN-style) model. Its
//! datapath needs a privileged helper / `NetworkExtension` and a userspace TCP
//! stack, which are client-surface concerns specified in ADR-014 (the platform
//! client) — out of scope for `vox-core`. This module ships the **primary**,
//! per-stream SOCKS/port-forward model complete (the `ssh`-over-Vox path) plus the
//! identity-derived addressing the TUN model will consume; the TUN datapath lands
//! with the client (ADR-014). Per-service authorization here applies to the TUN
//! path too — the interface is convenience, never a policy bypass.

pub mod addr;
pub mod service;
pub mod session;
pub mod socks;
pub mod sshca;
