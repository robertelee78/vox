//! ADR-020 — **agent comms**: what agents say to each other in a Vox room, and
//! the rules they share about it.
//!
//! This is the first crate of the app tier. It rides the Vox layer exactly as
//! chat and room-bound services do, and it deliberately does **not** depend on
//! `vox-core`: an agent-comms message is JSON inside the ordinary text content of
//! an ADR-008 log entry, so there is no wire format here and nothing to
//! coordinate with the core. If this crate needed the core's internals, the layer
//! would not be a layer.
//!
//! ## What the room is for
//!
//! Planning, assignment of work, and higher-order discussion between agents —
//! **not** a mirror of what each agent is doing. Tool traces and per-turn chatter
//! belong nowhere near it. That is a product decision (ADR-020 §Context) and this
//! crate encodes the parts of it a machine can enforce: what may interrupt, who
//! may answer, and when to stop.
//!
//! ## The shape of a message
//!
//! The log already supplies an id (the entry hash), a signed author and a
//! timestamp, so [`Envelope`] carries only what the log does not know. Three
//! properties matter and each exists for a reason found in the field:
//!
//! - **Addressing is a field, never prose.** Matrix moved mentions into
//!   `m.mentions` because scanning message bodies failed; agents relaying text on
//!   Matrix looped until a gateway was restarted. [`Envelope::to`] is that field.
//! - **Urgency is its own field**, not a property of the type. That is what lets
//!   the type vocabulary stay open: a node can decide what may interrupt without
//!   understanding a single application type.
//! - **An unknown type is carried, not rejected.** Only `hello`, `bye` and `say`
//!   mean anything here; everything else passes through untouched, the way
//!   Matrix reserves `m.*` and ctm's own `MessageType` keeps an `Unknown`
//!   catch-all so a version skew does not break a daemon.
//!
//! ## Modules
//!
//! - [`envelope`] — the message: parsing, addressing, interrupting, loop control.
//! - [`claim`] — work assignment as claims, resolved by the log with no
//!   coordinator.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]

pub mod claim;
pub mod envelope;

pub use claim::{ClaimOp, Ownership, Posted};
pub use envelope::{Context, Envelope, ParseError, BYE, HELLO, SAY};
