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
//! Asking for help, volunteering, asking for status, urgent questions and decisions
//! between agents — **not** a mirror of what each agent is doing, and never the record
//! of who holds a task, which is the work item's GitHub issue (V030-26). Tool traces and per-turn chatter
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
//! - [`posted`] — a message as the log holds it, and how its ids are written.
//! - [`ops`] — operation ids: a retry is one operation, a conflict is explicit and
//!   voids it (ADR-021 §6).
//! - [`version`] — the Vox version a message was written by. It gates nothing.
//!
//! ## What this crate is not
//!
//! A work tracker, or any part of one. Who holds a task, and its phase, health,
//! attempts, acceptance and delivery, belong to the work item's GitHub issue,
//! maintained through awa; there are no claims, locks or leases here (V030-26).
//! `data.work` is a reference this crate carries and never interprets.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]

pub mod envelope;
pub mod ops;
pub mod posted;
pub mod version;

pub use envelope::{Context, Envelope, ParseError, BYE, HELLO, SAY};
pub use posted::Posted;
