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
//!
//! Later M13 pieces (channel state, the `Node` actor and its `CoreHandle`
//! binding) are added here as they ship. Nothing in this module is a stub: each
//! submodule is a finished, independently useful unit.

pub mod paths;
pub mod profile;
pub mod store;
