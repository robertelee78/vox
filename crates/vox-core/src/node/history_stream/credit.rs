//! Request-local byte and chunk credit. Neither an ACK nor a continuation starts another page.

use super::{invalid, Continuation, Frame, Object, Query, RequestId, Status, DONE_RESERVE};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::history::{MAX_CHUNK_BYTES, MAX_PAYLOAD_BYTES, MAX_RESPONSE_BYTES};

/// One response quantum, recreated only by an explicit locally authorized request. The driver
/// persists remaining logical-page entry credit across quanta; the peer cannot replenish it.
pub(super) struct Response {
    request: RequestId,
    query: Query,
    wire_limit: usize,
    wire_used: usize,
    headers_left: usize,
    metadata_left: usize,
    body: Option<BodyCredit>,
    done: bool,
    inventory_seen: bool,
}

struct BodyCredit {
    entry: Digest32,
    length: u64,
    persisted: u64,
    pending: Option<u64>,
}

impl Response {
    pub(super) fn new(request: RequestId, query: Query) -> Result<Self> {
        query.validate()?;
        let (wire_limit, headers_left) = match query {
            Query::Page {
                wire_bytes,
                entries,
                ..
            } => (wire_bytes, entries),
            Query::Entry { .. } | Query::Header { .. } => (MAX_RESPONSE_BYTES, 1),
            Query::Range { want, .. } => (MAX_RESPONSE_BYTES, range_headers(want)),
            _ => (MAX_RESPONSE_BYTES, 0),
        };
        let metadata_left = match query {
            Query::Page { entries, .. } => entries,
            // A bundle's objects are bounded by its one wire quantum, not by a count.
            Query::Range { .. } => MAX_RESPONSE_BYTES,
            _ => 1,
        };
        Ok(Self {
            request,
            query,
            wire_limit,
            wire_used: 0,
            headers_left,
            metadata_left,
            body: None,
            done: false,
            inventory_seen: false,
        })
    }

    pub(super) fn request(&self) -> RequestId {
        self.request
    }

    pub(super) fn remaining_wire(&self) -> usize {
        self.wire_limit - self.wire_used
    }

    pub(super) fn headers_left(&self) -> usize {
        self.headers_left
    }

    pub(super) fn fits_data(&self, wire_len: usize) -> bool {
        !self.done
            && self
                .wire_used
                .checked_add(wire_len)
                .is_some_and(|used| used <= self.wire_limit - DONE_RESERVE)
    }

    /// A very small requested page may have room only for the handshake and a BUSY result.
    /// Account that traffic without mistaking ordinary insufficient data credit for malformed
    /// input. The terminal frame still has to fit the original exact wire limit.
    pub(super) fn charge_handshake(&mut self, wire_len: usize) -> Result<()> {
        if self.done || self.wire_used != 0 || wire_len >= self.wire_limit {
            return Err(Error::SizeLimitExceeded("history handshake quantum"));
        }
        self.wire_used = wire_len;
        Ok(())
    }

    /// Count handshake and credit-control traffic too. The smaller requested page ceiling is
    /// never permission to exceed the daemon's absolute one-quantum limit.
    pub(super) fn charge_overhead(&mut self, wire_len: usize) -> Result<()> {
        if !self.fits_data(wire_len) {
            return Err(Error::SizeLimitExceeded("history request/control quantum"));
        }
        self.wire_used += wire_len;
        Ok(())
    }

    /// Install only the length/hash from a header already verified and bound to the local
    /// request by the admission layer. A peer's CHUNK can never create or replace this state.
    pub(super) fn expect_body(
        &mut self,
        entry: Digest32,
        length: u64,
        persisted: u64,
    ) -> Result<()> {
        if self.done
            || !matches!(
                self.query,
                Query::Entry { .. } | Query::Page { .. } | Query::Range { .. }
            )
            || length > MAX_PAYLOAD_BYTES as u64
            || persisted > length
            || self
                .body
                .as_ref()
                .is_some_and(|body| !self.body_settled(body))
        {
            return Err(invalid("history body credit state"));
        }
        let resume = match self.query {
            Query::Entry { offset, .. } => Some(offset),
            Query::Range {
                want: super::RangeWant::Body { offset, .. },
                ..
            } => Some(offset),
            Query::Range { .. } => Some(0),
            _ => None,
        };
        if resume.is_some_and(|offset| persisted != offset) {
            return Err(invalid("history body resume offset"));
        }
        self.body = Some(BodyCredit {
            entry,
            length,
            persisted,
            pending: None,
        });
        Ok(())
    }

    /// A body may be followed by the next object: it is complete, or (in a Range bundle) none of
    /// it was sent, which is the holder's answer that it does not serve that body.
    fn body_settled(&self, body: &BodyCredit) -> bool {
        body.pending.is_none()
            && (body.persisted == body.length
                || (matches!(self.query, Query::Range { .. }) && body.persisted == 0))
    }

    /// A Range bundle's chunks carry no ACK: the reader holds them in its private assembly, not
    /// on disk, and the one wire quantum bounds them.
    fn unacknowledged(&self) -> bool {
        matches!(self.query, Query::Range { .. })
    }

    /// Validate and consume one response frame before handing its bytes to storage or QUIC.
    /// `wire_len` includes the four-byte framing prefix. On any error the stream is discarded;
    /// no retry can reinterpret partially consumed credit as a fresh quantum.
    pub(super) fn accept(&mut self, frame: &Frame<'_>, wire_len: usize) -> Result<()> {
        if self.done || wire_len < 5 {
            return Err(invalid("history response state"));
        }
        let used = self
            .wire_used
            .checked_add(wire_len)
            .ok_or(Error::SizeLimitExceeded("history quantum"))?;
        let terminal = matches!(frame, Frame::Done { .. });
        let limit = if terminal {
            self.wire_limit
        } else {
            self.wire_limit - DONE_RESERVE
        };
        if used > limit {
            return Err(Error::SizeLimitExceeded("history response quantum"));
        }
        match frame {
            // A Range answer's one correction: the holder's Have pages of the asked author
            // (the newest and the older body pages over the asked interval), at most
            // `MAX_CORRECTION_PAGES`, all of one author.
            Frame::Holding(authors)
                if matches!(self.query, Query::Range { .. })
                    && (1..=super::MAX_CORRECTION_PAGES).contains(&authors.len())
                    && authors.iter().all(|have| have.author == authors[0].author)
                    && !self.inventory_seen =>
            {
                self.inventory_seen = true;
            }
            Frame::Meta { request, object } if *request == self.request => {
                // Atomic object queries have exactly one metadata result. Keep reading
                // DONE (including its status/continuation), but reject duplicate objects
                // before they can multiply verifier/dependency handoffs. Page headers
                // retain their explicitly requested count; the receiver stages one body.
                self.metadata_left = self
                    .metadata_left
                    .checked_sub(1)
                    .ok_or(Error::SizeLimitExceeded("history metadata objects"))?;
                if self
                    .body
                    .as_ref()
                    .is_some_and(|body| body.pending.is_some())
                {
                    return Err(invalid("history metadata before persisted chunk"));
                }
                if matches!(object, Object::Header(_))
                    && self.unacknowledged()
                    && self
                        .body
                        .as_ref()
                        .is_some_and(|body| !self.body_settled(body))
                {
                    return Err(invalid("history bundle header inside a partial body"));
                }
                if matches!(object, Object::Header(_)) {
                    self.headers_left = self
                        .headers_left
                        .checked_sub(1)
                        .ok_or(Error::SizeLimitExceeded("history page headers"))?;
                }
            }
            Frame::Chunk {
                request,
                entry,
                offset,
                bytes,
            } if *request == self.request => {
                let unacknowledged = self.unacknowledged();
                let body = self
                    .body
                    .as_mut()
                    .ok_or(invalid("history chunk before verified header"))?;
                let end = offset
                    .checked_add(bytes.len() as u64)
                    .ok_or(invalid("history chunk overflow"))?;
                if body.entry != *entry
                    || body.pending.is_some()
                    || *offset != body.persisted
                    || bytes.is_empty()
                    || bytes.len() > MAX_CHUNK_BYTES
                    || end > body.length
                {
                    return Err(invalid("history chunk credit"));
                }
                if unacknowledged {
                    body.persisted = end;
                } else {
                    body.pending = Some(end);
                }
            }
            Frame::Done {
                request,
                status,
                continuation,
            } if *request == self.request => {
                if self
                    .body
                    .as_ref()
                    .is_some_and(|body| body.pending.is_some())
                    && *status != Status::Cancelled
                {
                    return Err(invalid("history done before persisted chunk"));
                }
                if *status == Status::Complete
                    && self.body.as_ref().is_some_and(|body| {
                        if self.unacknowledged() {
                            !self.body_settled(body)
                        } else {
                            body.persisted != body.length
                        }
                    })
                {
                    return Err(invalid("history complete with partial body"));
                }
                if let Some(cursor) = continuation {
                    self.check_continuation(cursor)?;
                }
                self.done = true;
            }
            _ => return Err(invalid("history unexpected response/request")),
        }
        self.wire_used = used;
        Ok(())
    }

    fn check_continuation(&self, cursor: &Continuation) -> Result<()> {
        let (kind, head, lo, hi) = match &self.query {
            Query::Proof { head, from, to, .. } => (2, head, *from, *to),
            Query::Entry { head, seq, .. } => (3, head, *seq, *seq),
            Query::Page { head, lo, hi, .. } => (4, head, *lo, *hi),
            Query::Range { head, want, .. } => {
                let (lo, hi) = want.interval();
                (5, head, lo, hi)
            }
            _ => return Err(invalid("history continuation for atomic object")),
        };
        if cursor.query_kind != kind
            || cursor.head != *head
            || cursor.lo != lo
            || cursor.hi != hi
            || cursor.next_seq < lo
            || cursor.next_seq > hi
            || cursor.entries_remaining > self.headers_left
        {
            return Err(invalid("history continuation widens demand"));
        }
        match (&self.body, cursor.entry) {
            (Some(body), Some(entry)) if entry == body.entry && cursor.offset == body.persisted => {
            }
            (None, None) if cursor.offset == 0 => {}
            (Some(body), None) if self.body_settled(body) && cursor.offset == 0 => {}
            _ => return Err(invalid("history continuation offset")),
        }
        Ok(())
    }
}

/// Every header a Range answer may carry under its head (server.rs `range`): the receipt of
/// the head's terminal position, sent first when the asker has not committed that head; the
/// receipt of `lo - 1` that leads a page; and one per position the want names (a body's own
/// header; none for a control interval, whose entries travel inside its proofs).
fn range_headers(want: super::RangeWant) -> usize {
    let positions = match want {
        super::RangeWant::Entries { lo, hi } => usize::from(lo > 1) + (hi - lo + 1) as usize,
        super::RangeWant::Body { .. } => 1,
        super::RangeWant::Controls { .. } => 0,
    };
    1 + positions
}
