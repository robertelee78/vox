//! Bounded validation before a logical Session reply is emitted. Raw pages keep the
//! original records accessible; this never rewrites or discards a saved part.

use super::{ROW_OVERHEAD, SESSION_READ_BYTES, SESSION_READ_LIMIT, SESSION_READ_ROWS};
use crate::hash::{sha256_concat, Digest32};
use crate::node::drive::SessionRow;
use std::collections::BTreeMap;

const INVALID: &str = "this Session activity has incomplete or invalid multipart records; use vox room session ROOM SESSION --raw, then --before ENTRY for older raw pages";

struct Part {
    group: Digest32,
    order: (u64, u64, usize),
    number: u64,
    total: u64,
}

pub(super) struct Preflight {
    logical: bool,
    rows: usize,
    bytes: usize,
    parts: Vec<Part>,
}

impl Preflight {
    pub(super) fn new(logical: bool) -> Self {
        Self {
            logical,
            rows: 0,
            bytes: 128,
            parts: Vec::new(),
        }
    }

    pub(super) fn push(&mut self, row: &SessionRow) -> Result<(), &'static str> {
        self.rows = self.rows.checked_add(1).ok_or(SESSION_READ_LIMIT)?;
        self.bytes = self
            .bytes
            .checked_add(row.body.len())
            .and_then(|n| n.checked_add(row.session_id.len()))
            .and_then(|n| n.checked_add(ROW_OVERHEAD))
            .ok_or(SESSION_READ_LIMIT)?;
        if self.rows > SESSION_READ_ROWS || self.bytes > SESSION_READ_BYTES {
            return Err(SESSION_READ_LIMIT);
        }
        if !self.logical {
            return Ok(());
        }
        let body: serde_json::Value = serde_json::from_str(&row.body).map_err(|_| INVALID)?;
        let object = body.as_object().ok_or(INVALID)?;
        // The sealed index uses an explicit ref before falling back to id/of; the renderer
        // uses id/of for drive pairing. Refuse contradictory aliases before emitting any
        // logical rows, rather than letting an unrelated result add a standalone line.
        let canonical = match object.get("kind").and_then(serde_json::Value::as_str) {
            Some("drive") => Some("id"),
            Some("drive-result") => Some("of"),
            _ => None,
        };
        if let (Some(canonical), Some(reference)) = (
            canonical,
            object.get("ref").and_then(serde_json::Value::as_str),
        ) {
            if reference
                != object
                    .get(canonical)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
            {
                return Err("this Session activity has conflicting drive references; use vox room session ROOM SESSION --raw, then --before ENTRY for older raw pages");
            }
        }
        let Some(part) = object.get("part") else {
            return Ok(());
        };
        let part = part.as_array().filter(|p| p.len() == 2).ok_or(INVALID)?;
        let number = part[0].as_u64().ok_or(INVALID)?;
        let total = part[1].as_u64().ok_or(INVALID)?;
        if number == 0
            || total == 0
            || number > total
            || total > crate::node::session_ingress::MAX_BATCH_ITEMS as u64
        {
            return Err(INVALID);
        }
        let field = |name| {
            object
                .get(name)
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
        };
        let kind = field("kind");
        if !object
            .get(vox_agentcomms::activity::big_field(kind))
            .is_some_and(serde_json::Value::is_string)
        {
            // join appends only to a string field in the first part. Accepting another
            // shape here would silently discard later bytes while presenting a whole row.
            return Err(INVALID);
        }
        // Match activity::join's key, with exact author/session scope and unambiguous lengths.
        let reference = field("ref");
        let group = sha256_concat(&[
            b"vox/session-reply-parts/v1",
            &row.author,
            &(row.session_id.len() as u64).to_be_bytes(),
            row.session_id.as_bytes(),
            &(kind.len() as u64).to_be_bytes(),
            kind.as_bytes(),
            reference.as_bytes(),
        ]);
        let seq = object
            .get("seq")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        self.parts.push(Part {
            group,
            order: (row.created_millis, seq, self.rows),
            number,
            total,
        });
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<usize, &'static str> {
        // session_view::of_session uses created time then seq, with stable input order for ties.
        // Keep only these bounded coordinates, never the bodies, across the preflight pass.
        self.parts.sort_by_key(|part| part.order);
        let mut open: BTreeMap<Digest32, (u64, u64)> = BTreeMap::new();
        for part in self.parts {
            let (next, total) = open.get(&part.group).copied().unwrap_or((1, part.total));
            if part.number != next || part.total != total {
                return Err(INVALID);
            }
            if part.number == part.total {
                open.remove(&part.group);
            } else {
                open.insert(part.group, (part.number + 1, part.total));
            }
        }
        if !open.is_empty() {
            return Err(INVALID);
        }
        Ok(self.rows)
    }
}
