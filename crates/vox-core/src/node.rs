//! The node runtime (ADR-016): the layer that composes the core into a running
//! Vox node.
//!
//! M13 (single-device node) lands it in pieces, each complete and tested:
//! - [`paths`] — the ADR-015/016 XDG profile layout (`0700` dirs, `0600` files).
//! - [`store`] — the redb-backed persistent store whose API accepts only
//!   already-sealed artifacts (ADR-010 segments and SEK wraps), so the store never
//!   sees plaintext or a raw key.
//! - [`profile`] — the identity lifecycle: create a native root and seal it in the
//!   ADR-010 identity vault, open, unlock, lock.
//! - [`content`] — the plaintext envelope a message carries (kind, time, text).
//! - [`channel`] — per-channel state: create, open (double-lock), append, render,
//!   all persisted as sealed segments and re-verified on open.
//! - [`api`] — the node's client-agnostic typed boundary: [`api::NodeView`],
//!   [`api::NodeCommand`], [`api::NodeEvent`], [`api::Outcome`]. Every client (the
//!   Rust TUI, the macOS app over UniFFI) projects its own UI model from these;
//!   the node never depends on a UI.
//! - [`actor`] — the [`actor::Node`] actor and its [`actor::NodeHandle`]: one
//!   task owns every secret and is the single writer; commands go in over an
//!   `mpsc` with a per-command reply, the latest view comes out over a `watch`,
//!   and ordered events over an `mpsc` (ADR-016 §"The `Node`").
//!
//! Nothing in this module is a stub: each submodule is a finished, independently
//! useful unit.

pub mod actor;
pub mod anchor;
pub mod api;
pub mod app;
pub mod appipc;
pub mod channel;
pub mod circuitstream;
pub mod content;
pub mod coordstream;
pub mod headless;
pub mod ipc;
pub mod joinstream;
pub mod link;
pub mod net;
pub mod network;
pub mod pairwise_stream;
pub mod passphrase;
pub mod paths;
pub mod prekeys;
pub mod profile;
pub mod resolver;
pub mod retention;
pub mod status;
pub mod store;
pub mod syncstream;
pub mod trust;
pub mod tunnel;
pub mod up;
