//! Short private-file reads for automatic pulls. No Session list or transcript is
//! copied into the node snapshot; cursor and permission checks happen on the actor.

use crate::atrest::store::SegmentKind;
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::api::{HistoryCursor, SessionFilePage};
use crate::node::drive::SessionRow;
use crate::node::store::{Snapshot, Store};

use super::super::ChannelState;
use super::record::Key;
use super::storage::{Read, Tree};

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
    fn readable_file(
        &self,
        snapshot: &Snapshot,
        id: u64,
        authors: &[Digest32],
        now: u64,
    ) -> Result<Option<SessionRow>> {
        let segment = snapshot
            .get_segment(&self.channel_id, SegmentKind::PrivateSession, id)?
            .ok_or(Error::MalformedAtRest("Session file locator has no record"))?;
        let saved = self.read_private(id, &segment)?;
        if self.private_expired(&saved, now) {
            return Ok(None);
        }
        let Some(row) = saved.row else {
            return Ok(None);
        };
        if !authors.contains(&row.author) || !crate::node::drive::is_file_out(&row) {
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
        if self.poisoned {
            return Err(self.save_failure().to_string());
        }
        if self.needs_session_upgrade() {
            return Err("the room is refreshing saved Sessions; retry".into());
        }
        match self.private_expiry_ready(store, now) {
            Ok(true) => {}
            Ok(false) => return Err("the room is refreshing saved Sessions; retry".into()),
            Err(error) => {
                self.poison(&error);
                return Err(error.to_string());
            }
        }
        let answer = (|| -> Result<FileReply> {
            let instance = self.history_instance(store)?;
            let authors = self.drive_from(store)?;
            let snapshot = store.snapshot()?;
            let read = Read::existing(&snapshot, &self.sek, &self.channel_id)?;
            match query {
                FileQuery::Exact(hash) => {
                    let id =
                        super::private_index::find(&snapshot, &self.sek, &self.channel_id, &hash)?;
                    let row = id
                        .map(|id| self.readable_file(&snapshot, id, &authors, now))
                        .transpose()?
                        .flatten();
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
                        let row = self.readable_file(&snapshot, id, &authors, now)?;
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
        })();
        if let Err(error) = &answer {
            self.poison(error);
        }
        answer.map_err(|error| error.to_string())
    }
}
