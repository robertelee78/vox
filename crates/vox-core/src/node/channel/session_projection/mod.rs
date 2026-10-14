//! Storage-backed Session selection and metadata streaming (#872).
//!
//! Review boundaries:
//! * Untrusted part counts/field lengths never reserve a proportional vector or string.
//!   Part coordinates are sealed rows; counters and offset addition are checked.
//! * A duplicate, reordered or late part cannot publish partial metadata. The complete
//!   bundle hash is checked before the first-part-position event is interpreted.
//! * A stream is scoped to one selected actor, room incarnation, current drive grant and
//!   projection revision. Every continuation rechecks these facts; no snapshot or lock is
//!   held while an IPC consumer waits.
//! * Activity selection retains at most the existing page's 200 fixed origins;
//!   companion walks retain 64 locators, never an advertised part-count allocation.
//!   Duplicate/reordered parts preserve the existing arrival grouping and dedup;
//!   count and emission passes share a captured arrival boundary and authority fence.
//! * Raw request-part counts and logical waiting counts are distinct. A resolution
//!   retires its parts in bounded turns; exact raw pages refuse until cleanup commits.
//! * Only a committed projection header publishes roots. Incomplete rebuild or I/O failure
//!   is a refusal, never an empty Session list. Restart preserves the published version and
//!   resumes bounded work without accepting an unauthenticated or partially parsed field.

mod activity_fold;
mod activity_index;
mod activity_pending;
mod activity_query;
mod activity_state;
mod build;
mod files;
mod metadata;
mod query;
mod record;
mod source;
mod storage;
mod text;
mod waiting;

pub(super) mod private_index;

pub(crate) use activity_query::{
    Cursor as ActivityCursor, Plan as ActivityPlan, Query as ActivityQuery, Reply as ActivityReply,
};
pub(crate) use files::{FileQuery, FileReply};
pub(crate) use query::{FieldKind, Query, Reply, Row};
