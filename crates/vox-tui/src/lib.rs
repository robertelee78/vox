//! Vox Lux — Rust TUI client library (ADR-015).
//!
//! The terminal-native client over `vox-core`, linked directly as a Rust crate
//! (no FFI). This library crate holds the testable, presentation-agnostic pieces —
//! verification primitives, the typed core↔UI boundary, the navigation/consent
//! state machine, QR rendering, and the ratatui view — so they are covered by
//! `TestBackend` render-snapshot and input-injection tests (the ADR-015 release
//! gate). The `vox` binary (`main.rs`) wires them to a live terminal and the core.
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

pub mod app;
pub mod cli;
pub mod qr;
pub mod state;
pub mod ui;
pub mod verify;
pub mod viewmodel;
