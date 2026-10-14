//! Compact Session selection and bounded text reads. Every query revalidates the
//! selected room incarnation, published inputs and current drive authority.

use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::cbor::Decoder;
use crate::error::{Error, Result};
use crate::hash::{sha256_concat, Digest32};
use crate::node::store::Store;

use super::super::ChannelState;
use super::record::{Descriptor, Field, Key};
use super::source::EnvelopeInput;
use super::storage::{Read, Tree};

const CHANGED: &str = "the room's Sessions changed; refresh the listing";
const REFRESHING: &str = "the room is refreshing saved Sessions; retry";
const PAGE_ROWS: usize = 64;
const TEXT_BYTES: usize = 32 * 1024;

#[derive(Clone)]
pub(crate) struct Revision {
    incarnation: Arc<std::sync::atomic::AtomicU64>,
    inputs: (u64, u64),
    drive: Digest32,
}

#[derive(Clone, Copy)]
pub(crate) enum FieldKind {
    Name,
    Harness,
}

/// A field's compact length/hash. The referenced value is never copied into a
/// listing or a daemon snapshot, regardless of its legal multipart size.
#[derive(Clone, Copy)]
pub(crate) struct Text {
    pub bytes: u64,
    pub hash: Digest32,
}

#[derive(Clone)]
pub(crate) struct Row {
    pub node: Digest32,
    pub id: String,
    pub name: Option<Text>,
    pub harness: Option<Text>,
    pub open: bool,
    pub opened_millis: u64,
    pub ended_millis: Option<u64>,
    pub opening: Digest32,
    pub ended: Option<Digest32>,
}

impl From<Descriptor> for Row {
    fn from(row: Descriptor) -> Self {
        let text = |field: Field| Text {
            bytes: field.bytes,
            hash: field.hash,
        };
        Self {
            node: row.node,
            id: row.id,
            name: row.name.map(text),
            harness: row.harness.map(text),
            open: row.ended.is_none(),
            opened_millis: row.position.created,
            ended_millis: row.ended.map(|end| end.position.created),
            opening: row.opening.position.hash,
            ended: row.ended.map(|end| end.position.hash),
        }
    }
}

pub(crate) struct TextPage {
    pub bytes: Vec<u8>,
    pub next: Option<u64>,
}

pub(crate) enum Query {
    Page {
        after: Option<Digest32>,
        revision: Option<Revision>,
        limit: usize,
    },
    Count {
        revision: Option<Revision>,
    },
    Lookup {
        node: Digest32,
        id: String,
    },
    Text {
        opening: Digest32,
        field: FieldKind,
        after: Option<u64>,
        revision: Revision,
    },
}

pub(crate) enum Reply {
    Page {
        rows: Vec<Row>,
        more: bool,
        revision: Revision,
    },
    Count {
        count: u64,
        revision: Revision,
    },
    Lookup(Option<Row>),
    Text(TextPage),
}

enum Failure {
    Storage(Error),
    Request(&'static str),
}
impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Self::Storage(e)
    }
}
type Answer<T> = std::result::Result<T, Failure>;

fn hash_key(hash: &Digest32) -> Key {
    let mut key = [0; 64];
    key[..32].copy_from_slice(hash);
    key
}

fn descriptor(read: &Read<'_>, id: u64) -> Result<Descriptor> {
    let bytes = read.descriptor(id)?;
    let mut d = Decoder::new(&bytes);
    let row = Descriptor::read(&mut d)?;
    d.finish()?;
    Ok(row)
}

fn next(read: &Read<'_>, authors: &[Digest32], after: u64) -> Result<Option<(u64, Descriptor)>> {
    let mut next = None;
    // Current drive holders are keyring-bounded. Each lookup walks one sealed
    // path; revoked authors' histories do not have to be scanned and discarded.
    for author in authors {
        let mut key = hash_key(author);
        key[32..40].copy_from_slice(&after.to_be_bytes());
        if let Some((found, id)) = read.next(Tree::AuthorOpenings, Some(key))? {
            if found[..32] == author[..] && next.is_none_or(|old| id < old) {
                next = Some(id);
            }
        }
    }
    next.map(|id| descriptor(read, id).map(|row| (id, row)))
        .transpose()
}

impl ChannelState {
    /// One bounded maintenance step; incomplete work stays unpublished. A local
    /// storage failure follows the room's existing poison/refusal boundary.
    pub(crate) fn advance_sessions(&mut self, store: &Store) -> Result<bool> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let result = super::build::advance(self, store);
        if let Err(ref error) = result {
            self.poison(error);
        }
        result
    }

    /// An opaque change token, including private-only inputs and room reincarnation.
    /// It carries no Session body, metadata string, or all-Session array.
    pub(crate) fn sessions_revision(&self, store: &Store) -> Result<Digest32> {
        let snapshot = store.snapshot()?;
        let read = Read::existing(&snapshot, &self.sek, &self.channel_id)?;
        let private = read.as_ref().map_or(0, |r| r.header.private_generation);
        let published = read
            .as_ref()
            .and_then(|r| r.header.published)
            .unwrap_or_default();
        let view = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?;
        let mut h = Sha256::new();
        h.update(b"vox/session-display/v1");
        h.update(&view.history_instance());
        h.update(&view.session_revision().to_be_bytes());
        h.update(&private.to_be_bytes());
        h.update(&published.0.to_be_bytes());
        h.update(&published.1.to_be_bytes());
        for author in self.drive_from(store)? {
            h.update(&author);
        }
        Ok(h.finalize().into())
    }

    pub(crate) fn session_query(
        &mut self,
        store: &Store,
        query: Query,
        max_bytes: usize,
    ) -> std::result::Result<Reply, String> {
        if self.poisoned {
            return Err(self.save_failure().to_string());
        }
        let result = (|| -> Answer<Reply> {
            let snapshot = store.snapshot()?;
            let read = Read::existing(&snapshot, &self.sek, &self.channel_id)?
                .ok_or(Failure::Request(REFRESHING))?;
            let public = self
                .entries
                .render_view(store, &self.sek, &self.channel_id)?
                .session_revision();
            let inputs = (public, read.header.private_generation);
            if !read.header.ready || read.header.published != Some(inputs) {
                return Err(Failure::Request(REFRESHING));
            }
            let authors = self.drive_from(store)?;
            let mut hash = Sha256::new();
            for author in &authors {
                hash.update(author);
            }
            let revision = Revision {
                incarnation: self.gen.clone(),
                inputs,
                drive: hash.finalize().into(),
            };
            let check = |previous: &Revision| -> Answer<()> {
                if !Arc::ptr_eq(&previous.incarnation, &revision.incarnation)
                    || previous.inputs != revision.inputs
                    || previous.drive != revision.drive
                {
                    return Err(Failure::Request(CHANGED));
                }
                Ok(())
            };
            match query {
                Query::Page {
                    after,
                    revision: previous,
                    limit,
                } => {
                    if let Some(previous) = &previous {
                        check(previous)?;
                    }
                    let mut cursor = match after {
                        None => 0,
                        Some(hash) => {
                            let id = read
                                .find(Tree::OpeningHash, &hash_key(&hash))?
                                .ok_or(Failure::Request("cursor not among this room's Sessions"))?;
                            if !authors.contains(&descriptor(&read, id)?.node) {
                                return Err(Failure::Request(CHANGED));
                            }
                            id
                        }
                    };
                    let mut rows = Vec::new();
                    let mut bytes = 0u64;
                    let mut candidate = next(&read, &authors, cursor)?;
                    while let Some((id, row)) = candidate {
                        let cost = 256u64
                            .saturating_add(row.name.map_or(0, |f| f.bytes))
                            .saturating_add(row.harness.map_or(0, |f| f.bytes));
                        if !rows.is_empty()
                            && (rows.len() >= limit.clamp(1, PAGE_ROWS)
                                || bytes.saturating_add(cost) > max_bytes as u64)
                        {
                            return Ok(Reply::Page {
                                rows,
                                more: true,
                                revision,
                            });
                        }
                        bytes = bytes.saturating_add(cost);
                        cursor = id;
                        rows.push(Row::from(row));
                        candidate = next(&read, &authors, cursor)?;
                    }
                    Ok(Reply::Page {
                        rows,
                        more: false,
                        revision,
                    })
                }
                Query::Count { revision: previous } => {
                    if let Some(previous) = &previous {
                        check(previous)?;
                    }
                    let mut count = 0u64;
                    for author in &authors {
                        count = count
                            .checked_add(read.find(Tree::Counts, &hash_key(author))?.unwrap_or(0))
                            .ok_or(Error::MalformedAtRest("Session count overflow"))?;
                    }
                    Ok(Reply::Count { count, revision })
                }
                Query::Lookup { node, id } => {
                    if !authors.contains(&node) {
                        return Err(Failure::Request("this node cannot read that Session"));
                    }
                    let group =
                        sha256_concat(&[b"vox/session-projection/id/v1", &node, id.as_bytes()]);
                    let row = read
                        .find(Tree::Groups, &hash_key(&group))?
                        .map(|id| descriptor(&read, id))
                        .transpose()?
                        .map(Row::from);
                    Ok(Reply::Lookup(row))
                }
                Query::Text {
                    opening,
                    field,
                    after,
                    revision: previous,
                } => {
                    check(&previous)?;
                    let id = read
                        .find(Tree::OpeningHash, &hash_key(&opening))?
                        .ok_or(Failure::Request(CHANGED))?;
                    let row = descriptor(&read, id)?;
                    if !authors.contains(&row.node) {
                        return Err(Failure::Request(CHANGED));
                    }
                    let field = match field {
                        FieldKind::Name => row.name,
                        FieldKind::Harness => row.harness,
                    };
                    let Some(field) = field else {
                        return Ok(Reply::Text(TextPage {
                            bytes: Vec::new(),
                            next: None,
                        }));
                    };
                    let mut input = EnvelopeInput::new(&read, field.envelope);
                    let page = super::text::page(
                        &mut input,
                        field,
                        after,
                        max_bytes.clamp(4, TEXT_BYTES),
                    )?;
                    Ok(Reply::Text(TextPage {
                        bytes: page.bytes,
                        next: page.next,
                    }))
                }
            }
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
