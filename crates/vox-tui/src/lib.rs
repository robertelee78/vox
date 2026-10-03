//! Vox Lux — Rust TUI client library (ADR-015).
//!
//! The terminal-native client over `vox-core`, linked directly as a Rust crate
//! (no FFI). This library crate holds the presentation-agnostic pieces — the typed
//! core↔UI boundary, the navigation state machine and the ratatui view. The `vox`
//! binary (`main.rs`) wires them to a live terminal and the core.
//!
//! ## Secret-handling contract (binding, ADR-015)
//! Only **rendered/redacted view models** cross into UI types here — decrypted text
//! destined for display, never raw keys, SKDMs, passphrases, the SEK, or
//! `self_seed`, which stay inside `vox-core` secret types. The boundary types in
//! [`viewmodel`] carry no secret material by construction.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Tests may use unwrap/expect/panic for assertions; the allow must come AFTER the
// deny so it wins under the test cfg.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod agent_hook;
pub mod app;
pub mod app_cli;
pub mod cli;
pub mod codex_trust;
pub mod coord;
pub mod ident;
pub mod lan_cli;
pub mod live;
pub mod notify;
pub mod room_cli;
pub mod share_cli;
pub mod shell;
pub mod state;
pub mod status_cli;
pub mod tunnel_cli;
pub mod ui;
pub mod update;
pub mod viewmodel;
pub mod wake;
