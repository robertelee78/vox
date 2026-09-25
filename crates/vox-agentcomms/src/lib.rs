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
//! - [`claim`] — live ownership as claims, resolved by the log with no
//!   coordinator: session-scoped owners, pending handoffs, bound renewals
//!   (ADR-020 §5 as corrected by ADR-021 §4).
//! - [`ops`] — operation ids: a retry is one operation, a conflict is explicit and
//!   voids it (ADR-021 §6).
//! - [`version`] — workers must run the same Vox version, and refuse to coordinate
//!   when one does not (ADR-021 §5).
//!
//! ## What this crate is not
//!
//! A work tracker. Work items, their phase, health, priority, acceptance and
//! delivery belong to an external tracker (ADR-021 §1). `data.work` is a reference
//! this crate carries and never interprets.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]

pub mod claim;
pub mod envelope;
pub mod ops;
pub mod version;

pub use claim::{ClaimOp, Fold, Outcome, Owner, Posted, State};
pub use envelope::{Context, Envelope, ParseError, BYE, HELLO, SAY};
