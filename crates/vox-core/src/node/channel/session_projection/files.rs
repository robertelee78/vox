//! Short private-file reads for automatic pulls. No Session list or transcript is
//! copied into the node snapshot; cursor and permission checks happen on the actor.
//! A page answers from the rows the node has applied (ADR-037 R4): an author whose Session
//! control effects are not yet current is not readable this page, and the cyclic file scan
//! examines that author's rows again once they are. Expiry applies per row.

use crate::atrest::store::SegmentKind;
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::api::{HistoryCursor, SessionFilePage};
use crate::node::drive::SessionRow;
use crate::node::store::{Snapshot, Store};

use super::super::ChannelState;
use super::record::Key;
use super::storage::{Read, Tree};

const REFRESHING: &str = "the room is refreshing saved Sessions; retry";

pub(crate) enum FileQuery {
    Exact(Digest32),
    Page {
        after: Option<HistoryCursor>,
        limit: usize,
    },
}

pub(crate) enum FileReply {
    Exact(Option<SessionRow>),
    Page(SessionFilePage),
}

fn key(id: u64) -> Key {
    let mut key = [0; 64];
    key[..8].copy_from_slice(&id.to_be_bytes());
    key
}

impl ChannelState {
    /// The unexpired file row saved at `id`, whoever its author is; the caller decides whether
    /// that author's Sessions are readable here.
    fn saved_file(
        &self,
        snapshot: &Snapshot,
        id: u64,
        now: u64,
        retention: (u64, u64),
    ) -> Result<Option<SessionRow>> {
        let segment = snapshot
            .get_segment(&self.channel_id, SegmentKind::PrivateSession, id)?
            .ok_or(Error::MalformedAtRest("Session file locator has no record"))?;
        let saved = self.read_private(id, &segment)?;
        if super::super::private_session::expired(&saved, now, retention) {
            return Ok(None);
        }
        let Some(row) = saved.row else {
            return Ok(None);
        };
        if !crate::node::drive::is_file_out(&row) {
            return Ok(None);
        }
        Ok(Some(row))
    }

    pub(crate) fn session_file_query(
        &mut self,
        store: &Store,
        query: FileQuery,
        max_bytes: usize,
        now: u64,
    ) -> std::result::Result<FileReply, String> {
        let resource = self.history_read_resource();
        if self.poisoned
            && !resource
                .as_ref()
                .is_some_and(|read| read.has_pending_snapshot())
        {
            return Err(self.save_failure().to_string());
        }
        let answer = match resource {
            Some(resource) => resource.with_snapshot(|_, view, retention| {
                self.session_file_query_view(view, query, max_bytes, now, retention)
            }),
            None => self
                .entries
                .render_view(store, &self.sek, &self.channel_id)
                .and_then(|view| {
                    self.session_file_query_view(
                        &view,
                        query,
                        max_bytes,
                        now,
                        (self.effective_retention(), self.effective_step_retention()),
                    )
                }),
        };
        if let Err(error) = &answer {
            // A refreshing author is not a local failure; a storage error still poisons.
            if !matches!(error, Error::StreamRefused(_)) {
                self.poison(error);
            }
        }
        answer.map_err(|error| error.to_string())
    }

    fn session_file_query_view(
        &self,
        view: &super::super::entry_store::RenderView<'_>,
        query: FileQuery,
        max_bytes: usize,
        now: u64,
        retention: (u64, u64),
    ) -> Result<FileReply> {
        (|| -> Result<FileReply> {
            let instance = view.history_instance();
            let (authors, refreshing) = self.drive_from_known_view(view)?;
            let snapshot = view.snapshot();
            let read = Read::existing(snapshot, &self.sek, &self.channel_id)?;
            match query {
                FileQuery::Exact(hash) => {
                    let id =
                        super::private_index::find(snapshot, &self.sek, &self.channel_id, &hash)?;
                    let row = match id
                        .map(|id| self.saved_file(snapshot, id, now, retention))
                        .transpose()?
                    {
                        Some(Some(row)) if authors.contains(&row.author) => Some(row),
                        // Whether this node may still read inside that author's Sessions is
                        // not known yet: neither an offer nor its absence.
                        Some(Some(row)) if refreshing.contains(&row.author) => {
                            return Err(Error::StreamRefused(REFRESHING));
                        }
                        _ => None,
                    };
                    if row.as_ref().is_some_and(|row| row.entry_hash != hash) {
                        return Err(Error::MalformedAtRest("Session file hash differs"));
                    }
                    Ok(FileReply::Exact(row))
                }
                FileQuery::Page { after, limit } => {
                    let Some(read) = read else {
                        return Ok(FileReply::Page(SessionFilePage {
                            rows: Vec::new(),
                            instance,
                            next: None,
                        }));
                    };
                    let mut cursor = after.filter(|c| c.instance == instance).map(|c| c.arrival);
                    let mut rows = Vec::new();
                    let mut bytes = 0usize;
                    for _ in 0..256 {
                        let Some((found, id)) = read.next(Tree::Files, cursor.map(key))? else {
                            return Ok(FileReply::Page(SessionFilePage {
                                rows,
                                instance,
                                next: None,
                            }));
                        };
                        if found != key(id) {
                            return Err(Error::MalformedAtRest("Session file cursor differs"));
                        }
                        let row = self
                            .saved_file(snapshot, id, now, retention)?
                            .filter(|row| authors.contains(&row.author));
                        if let Some(row) = row {
                            let cost = row
                                .body
                                .len()
                                .saturating_add(row.session_id.len())
                                .saturating_add(128);
                            if !rows.is_empty()
                                && (rows.len() >= limit.clamp(1, 64)
                                    || bytes.saturating_add(cost) > max_bytes)
                            {
                                return Ok(FileReply::Page(SessionFilePage {
                                    rows,
                                    instance,
                                    next: cursor.map(|arrival| HistoryCursor { instance, arrival }),
                                }));
                            }
                            bytes = bytes.saturating_add(cost);
                            rows.push(row);
                        }
                        cursor = Some(id);
                    }
                    Ok(FileReply::Page(SessionFilePage {
                        rows,
                        instance,
                        next: cursor.map(|arrival| HistoryCursor { instance, arrival }),
                    }))
                }
            }
        })()
    }
}
