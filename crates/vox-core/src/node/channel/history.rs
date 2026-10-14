//! Bounded, selected-room reads. PlaintextCache remains the sealed rendering store; the
//! published DAG supplies display order and cache ids supply local arrival order.
//! The remaining resident timeline is used only for its transient late marks here. Its
//! other consumers are deliberately unchanged until they move to this query seam too.

use super::*;
use crate::node::api::MessageRow;

pub(crate) enum Query {
    Read {
        since: Option<Digest32>,
        after: Option<Digest32>,
        limit: usize,
    },
    Older {
        before: Option<Digest32>,
        limit: usize,
    },
    Count {
        since: Option<Digest32>,
    },
    Locate {
        entries: Vec<Digest32>,
    },
    Exact {
        entry: Digest32,
        revision: Revision,
    },
}

pub(crate) enum Reply {
    Rows(Vec<MessageRow>),
    Older {
        rows: Vec<MessageRow>,
        older: u64,
    },
    Count {
        n: u64,
        last: Option<Digest32>,
    },
    Located {
        entries: Vec<Digest32>,
        revision: Revision,
    },
    Exact(MessageRow),
}

/// A short query may be followed by a client wait, but no Store snapshot or room lock is.
/// This token rejects a changed room before another part of one Find answer is read.
#[derive(Clone)]
pub(crate) struct Revision {
    incarnation: Arc<std::sync::atomic::AtomicU64>,
    facts: [u64; 8],
}

impl Revision {
    fn of(ch: &ChannelState) -> Self {
        Self {
            incarnation: ch.gen.clone(),
            facts: [
                ch.gen.load(std::sync::atomic::Ordering::Relaxed),
                ch.display_rewrite,
                ch.timeline.len() as u64,
                ch.dag.reorder_generation(),
                ch.dag.body_generation(),
                ch.legacy_sessions.display_revision(),
                ch.effective_retention(),
                ch.effective_step_retention(),
            ],
        }
    }
    fn current(&self, ch: &ChannelState) -> bool {
        let now = Self::of(ch);
        Arc::ptr_eq(&self.incarnation, &now.incarnation) && self.facts == now.facts
    }
}

enum Failure {
    Storage(Error),
    Request(&'static str),
}
impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Storage(error)
    }
}
type Answer<T> = std::result::Result<T, Failure>;
const CHANGED: &str = "the room changed while reading; refresh and retry";

struct View<'a> {
    ch: &'a ChannelState,
    order: OrderView<'a>,
}

impl View<'_> {
    fn row(&self, hash: &Digest32) -> Result<Option<MessageRow>> {
        if self.order.key(hash)?.is_none() {
            return Ok(None);
        }
        if let Some(id) = self.ch.retention.get(hash).and_then(|r| r.cache_id) {
            let bytes = self
                .order
                .cache(id)?
                .ok_or(Error::MalformedAtRest("rendering cache missing"))?;
            let cached = parse_cache(&bytes)?;
            let cached_hash = match &cached {
                CacheRow::Text(row) => row.entry_hash,
                CacheRow::Read(row) => row.entry_hash,
                CacheRow::Session(row) => row.entry_hash,
            };
            if cached_hash != *hash {
                return Err(Error::MalformedAtRest("rendering cache hash differs"));
            }
            let CacheRow::Text(mut row) = cached else {
                return Ok(None);
            };
            row.arrival = id;
            return self.rendered(row).map(Some);
        }
        let Some(entry) = self.order.entry(hash)? else {
            return Ok(None);
        };
        if entry.payload.is_some()
            || !self
                .ch
                .owed
                .contains(&(entry.skeleton.author_id, entry.skeleton.seq))
            || self.ch.legacy_sessions.is_session(hash)
            || expired_at(
                entry.skeleton.claimed_ms,
                self.ch.now_hint,
                self.ch.entry_retention(&entry),
            )
        {
            return Ok(None);
        }
        Ok(Some(MessageRow {
            entry_hash: *hash,
            author: entry.skeleton.author_id,
            created_millis: entry.skeleton.claimed_ms,
            text: String::new(),
            arrival: 0,
            late: false,
            owed: true,
        }))
    }

    fn rendered(&self, row: Rendered) -> Result<MessageRow> {
        let entry = self
            .order
            .entry(&row.entry_hash)?
            .ok_or(Error::MalformedAtRest("rendering has no published entry"))?;
        if entry.skeleton.author_id != row.author {
            return Err(Error::MalformedAtRest("rendering author differs"));
        }
        // Until the remaining consumers are converted, retain the existing transient late
        // semantics. Binary search uses this query's pinned order, not a second history copy.
        let key = self
            .order
            .key(&row.entry_hash)?
            .ok_or(Error::MalformedAtRest("rendering order missing"))?;
        let mut failure = None;
        let at = self
            .ch
            .timeline
            .binary_search_by(|r| match self.order.key(&r.entry_hash) {
                Ok(Some(k)) => k.cmp(&key),
                Ok(None) => {
                    failure = Some(Error::MalformedAtRest("timeline order missing"));
                    std::cmp::Ordering::Equal
                }
                Err(error) => {
                    failure = Some(error);
                    std::cmp::Ordering::Equal
                }
            });
        if let Some(error) = failure {
            return Err(error);
        }
        let at =
            at.map_err(|_| Error::MalformedAtRest("published rendering missing from timeline"))?;
        let shown = &self.ch.timeline[at];
        Ok(MessageRow {
            entry_hash: row.entry_hash,
            author: row.author,
            created_millis: row.created_millis,
            text: row.text,
            arrival: row.arrival,
            late: shown.late,
            owed: false,
        })
    }

    fn arrival(&self, after: &mut Option<u64>) -> Result<Option<MessageRow>> {
        while let Some((id, bytes)) = self.order.cache_after(*after)? {
            *after = Some(id);
            let CacheRow::Text(mut row) = parse_cache(&bytes)? else {
                continue;
            };
            if self
                .ch
                .retention
                .get(&row.entry_hash)
                .and_then(|r| r.cache_id)
                != Some(id)
                || self.order.key(&row.entry_hash)?.is_none()
            {
                continue;
            }
            row.arrival = id;
            return self.rendered(row).map(Some);
        }
        Ok(None)
    }

    fn display(
        &self,
        cursor: &mut Option<(u64, Digest32)>,
        backwards: bool,
    ) -> Result<Option<MessageRow>> {
        loop {
            let next = if backwards {
                self.order.previous(*cursor)?
            } else {
                self.order.next(*cursor)?
            };
            let Some(key) = next else { return Ok(None) };
            *cursor = Some(key);
            if let Some(row) = self.row(&key.1)? {
                return Ok(Some(row));
            }
        }
    }

    /// Transitional exact scalar metadata: no bodies are cloned or decrypted to count.
    /// The final resident-metadata retirement must replace this with stored counts/ranks.
    fn count_before(&self, before: Option<(u64, Digest32)>) -> Result<u64> {
        let mut failure = None;
        let rendered = match before {
            None => self.ch.timeline.len(),
            Some(mark) => {
                self.ch
                    .timeline
                    .partition_point(|row| match self.order.key(&row.entry_hash) {
                        Ok(Some(key)) => key < mark,
                        Ok(None) => {
                            failure = Some(Error::MalformedAtRest("timeline order missing"));
                            false
                        }
                        Err(error) => {
                            failure = Some(error);
                            false
                        }
                    })
            }
        };
        if let Some(error) = failure {
            return Err(error);
        }
        let mut count = rendered as u64;
        for item in self.ch.owed_shown(self.order.entries()) {
            let (_, hash, _) = item?;
            let key = self
                .order
                .key(&hash)?
                .ok_or(Error::MalformedAtRest("owed row order missing"))?;
            if before.is_none_or(|mark| key < mark) {
                count += 1;
            }
        }
        Ok(count)
    }

    fn mark(&self, hash: Digest32, arrival: bool, why: &'static str) -> Answer<MessageRow> {
        let row = self.row(&hash)?.ok_or(Failure::Request(why))?;
        if arrival && row.owed {
            return Err(Failure::Request(why));
        }
        Ok(row)
    }

    fn answer(&self, query: Query, bytes: usize) -> Answer<Reply> {
        let cursor_error = "cursor not in this room's timeline";
        match query {
            Query::Read {
                since,
                after,
                limit,
            } => {
                if since.is_some() && after.is_some() {
                    return Err(Failure::Request(
                        "a read takes a cursor or a page mark, not both",
                    ));
                }
                let mut arrival = match since {
                    Some(h) => Some(self.mark(h, true, cursor_error)?.arrival),
                    None => None,
                };
                let mut display = match after {
                    Some(h) => {
                        self.mark(h, false, "page mark not in this room's timeline")?;
                        self.order.key(&h)?
                    }
                    None => None,
                };
                let mut rows = Vec::new();
                let mut used = 0usize;
                while rows.len() < limit && (rows.is_empty() || used < bytes) {
                    let next = if since.is_some() {
                        self.arrival(&mut arrival)?
                    } else {
                        self.display(&mut display, false)?
                    };
                    let Some(row) = next else { break };
                    let cost = row
                        .text
                        .len()
                        .saturating_add(crate::node::ipc::ROW_OVERHEAD);
                    if !rows.is_empty() && used.saturating_add(cost) > bytes {
                        break;
                    }
                    used = used.saturating_add(cost);
                    rows.push(row);
                }
                Ok(Reply::Rows(rows))
            }
            Query::Older { before, limit } => {
                let mut cursor = match before {
                    Some(h) => {
                        self.mark(h, false, cursor_error)?;
                        self.order.key(&h)?
                    }
                    None => None,
                };
                let total = self.count_before(cursor)?;
                let mut rows = Vec::new();
                let mut used = 0usize;
                while rows.len() < limit && (rows.is_empty() || used < bytes) {
                    let Some(row) = self.display(&mut cursor, true)? else {
                        break;
                    };
                    let cost = row
                        .text
                        .len()
                        .saturating_add(crate::node::ipc::ROW_OVERHEAD);
                    if !rows.is_empty() && used.saturating_add(cost) > bytes {
                        break;
                    }
                    used = used.saturating_add(cost);
                    rows.push(row);
                }
                let older = total
                    .checked_sub(rows.len() as u64)
                    .ok_or(Error::MalformedAtRest("history count smaller than page"))?;
                rows.reverse();
                Ok(Reply::Older { rows, older })
            }
            Query::Count { since } => {
                let mark = match since {
                    Some(h) => Some(self.mark(h, true, cursor_error)?.arrival),
                    None => None,
                };
                let last = self
                    .ch
                    .timeline
                    .iter()
                    .max_by_key(|row| row.arrival)
                    .map(|row| row.entry_hash);
                let n = match mark {
                    Some(mark) => self
                        .ch
                        .timeline
                        .iter()
                        .filter(|row| row.arrival > mark)
                        .count() as u64,
                    None => self.count_before(None)?,
                };
                Ok(Reply::Count { n, last })
            }
            Query::Locate { entries } => {
                if entries.len() > crate::node::ipc::MAX_FIND {
                    return Err(Failure::Request("too many message ids"));
                }
                let mut found = BTreeSet::new();
                for hash in entries {
                    if self.row(&hash)?.is_some() {
                        let key = self
                            .order
                            .key(&hash)?
                            .ok_or(Error::MalformedAtRest("located row order missing"))?;
                        found.insert(key);
                    }
                }
                Ok(Reply::Located {
                    entries: found.into_iter().map(|(_, h)| h).collect(),
                    revision: Revision::of(self.ch),
                })
            }
            Query::Exact { entry, revision } => {
                if !revision.current(self.ch) {
                    return Err(Failure::Request(CHANGED));
                }
                Ok(Reply::Exact(
                    self.row(&entry)?.ok_or(Failure::Request(CHANGED))?,
                ))
            }
        }
    }
}

impl ChannelState {
    pub(crate) fn history_query(
        &mut self,
        store: &Store,
        query: Query,
        max_bytes: usize,
    ) -> std::result::Result<Reply, String> {
        if self.poisoned {
            return Err(self.save_failure().to_string());
        }
        let result = (|| -> Answer<Reply> {
            self.settle_timeline(store)?;
            let view = View {
                order: self.order_view(store)?,
                ch: self,
            };
            view.answer(query, max_bytes)
        })();
        match result {
            Ok(reply) => Ok(reply),
            Err(Failure::Request(why)) => Err(why.into()),
            Err(Failure::Storage(error)) => {
                self.poison(&error);
                Err(error.to_string())
            }
        }
    }
}
