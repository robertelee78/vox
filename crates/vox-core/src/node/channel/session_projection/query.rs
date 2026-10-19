//! Compact Session selection and bounded text reads. Every query answers from the fold the
//! node has published (ADR-037 R4) and revalidates the selected room incarnation, the
//! published inputs and the drive authority it answered for. A fold behind its inputs, or an
//! author whose control effects are not yet current, is said in the answer's [`Revision`],
//! never a refusal of the room; only an absence that the published fold cannot prove is
//! refused as refreshing.

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
const CANNOT_READ: &str = "this node cannot read that Session";
const PAGE_ROWS: usize = 64;
const TEXT_BYTES: usize = 32 * 1024;

/// What an answer was made from. A continuation naming another basis is told CHANGED and
/// re-reads: the basis changes when the fold publishes new inputs, when the drive authority
/// it answered for changes, and when an author it could not answer becomes current.
#[derive(Clone)]
pub(crate) struct Revision {
    incarnation: Arc<std::sync::atomic::AtomicU64>,
    /// The inputs the published fold was built from; `None` before any fold has published.
    published: Option<(u64, u64)>,
    /// The known and the refreshing drive authors, as one hash ([`drive_basis`]).
    drive: Digest32,
    member: Option<Digest32>,
    refreshing: Vec<Digest32>,
    provisional: bool,
}

impl Revision {
    /// The authors whose Session control effects are not yet current here, sorted. Their
    /// Sessions are not in this answer; each is named so the caller can say it is fetching
    /// them now (ADR-036 H-1), never dropped silently.
    pub fn refreshing(&self) -> &[Digest32] {
        &self.refreshing
    }

    /// Whether this answer came from a fold behind the room's current Session inputs, from
    /// no published fold at all, or during a saved-Session upgrade, restore or import: the
    /// rows are what was last published, and a later listing may show more.
    pub fn provisional(&self) -> bool {
        self.provisional
    }
}

/// One hash over the drive authors an answer was made for and the ones it could not answer
/// for yet. Both lists are sorted by the caller; the length separates them.
pub(super) fn drive_basis(known: &[Digest32], refreshing: &[Digest32]) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"vox/session-drive-basis/v1");
    hash.update((known.len() as u64).to_be_bytes());
    for author in known {
        hash.update(author);
    }
    for author in refreshing {
        hash.update(author);
    }
    hash.finalize().into()
}

#[derive(Clone, Copy)]
pub(crate) enum FieldKind {
    Name,
    Harness,
    Cwd,
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
    pub cwd: Option<Text>,
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
            cwd: row.cwd.map(text),
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

#[derive(Clone)]
pub(crate) enum Query {
    Waiting,
    Pending {
        after: Option<crate::node::sessions::PendingCursor>,
    },
    Summary {
        opening: Digest32,
        revision: Revision,
    },
    Lifecycle {
        before: Option<crate::node::sessions::LifecycleCursor>,
        not_before: Option<u64>,
        limit: usize,
    },
    HasOpen {
        node: Digest32,
    },
    Join {
        node: Digest32,
    },
    Page {
        open_only: bool,
        after: Option<Digest32>,
        revision: Option<Revision>,
        limit: usize,
    },
    Validate {
        revision: Revision,
    },
    Lookup {
        node: Digest32,
        id: String,
    },
    Exact {
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
    Waiting(u64),
    Pending {
        targets: Vec<crate::node::sessions::PendingTarget>,
        next: Option<crate::node::sessions::PendingCursor>,
    },
    Summary(crate::node::ipc::SessionSummary),
    Lifecycle {
        rows: Vec<(Row, crate::node::sessions::LifecycleCursor)>,
        older: bool,
        revision: Revision,
    },
    HasOpen(bool),
    Page {
        rows: Vec<Row>,
        more: bool,
        revision: Revision,
    },
    Valid,
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

pub(super) fn lifecycle_key(author: &Digest32, at: u64, id: u64, ended: bool) -> Key {
    let mut key = hash_key(author);
    key[32..40].copy_from_slice(&at.to_be_bytes());
    key[40..48].copy_from_slice(&id.to_be_bytes());
    key[48] = u8::from(ended);
    key
}

fn previous_lifecycle(
    read: &Read<'_>,
    authors: &[Digest32],
    before: Option<(u64, u64, bool)>,
) -> Result<Option<(Key, u64)>> {
    let mut selected: Option<(Key, u64)> = None;
    for author in authors {
        let bound = before.map_or_else(
            || {
                let mut key = [255; 64];
                key[..32].copy_from_slice(author);
                key
            },
            |(time, id, ended)| lifecycle_key(author, time, id, ended),
        );
        if let Some((key, id)) = read.previous(Tree::Lifecycle, Some(bound))? {
            if key[..32] == author[..]
                && selected
                    .as_ref()
                    .is_none_or(|(old, _)| key[32..] > old[32..])
            {
                selected = Some((key, id));
            }
        }
    }
    Ok(selected)
}

fn descriptor(read: &Read<'_>, id: u64) -> Result<Descriptor> {
    let bytes = read.descriptor(id)?;
    let mut d = Decoder::new(&bytes);
    let row = Descriptor::read(&mut d)?;
    d.finish()?;
    Ok(row)
}

fn next(
    read: &Read<'_>,
    authors: &[Digest32],
    after: u64,
    open_only: bool,
) -> Result<Option<(u64, Descriptor)>> {
    let mut next = None;
    // Current drive holders are keyring-bounded. Each lookup walks one sealed
    // path; revoked authors' histories do not have to be scanned and discarded.
    for author in authors {
        let mut key = hash_key(author);
        key[32..40].copy_from_slice(&after.to_be_bytes());
        if let Some((found, id)) = read.next(
            if open_only {
                Tree::OpenSessions
            } else {
                Tree::AuthorOpenings
            },
            Some(key),
        )? {
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
    pub(crate) fn advance_sessions(&mut self, store: &Store, now: u64) -> Result<bool> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let result = (|| {
            if !self.advance_private_sessions(store, now)? {
                return Ok(false);
            }
            let metadata = super::build::advance(self, store)?;
            let activity = super::activity_fold::advance(self, store)?;
            let waiting = super::waiting::advance(self, store)?;
            Ok(metadata || activity || waiting)
        })();
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
        let activity = read.as_ref().map_or(0, |r| r.header.activity_generation);
        let published = read
            .as_ref()
            .and_then(|r| r.header.published)
            .unwrap_or_default();
        let view = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?;
        let mut h = Sha256::new();
        h.update(b"vox/session-display/v1");
        h.update(view.history_instance());
        h.update(view.session_revision().to_be_bytes());
        h.update(private.to_be_bytes());
        h.update(activity.to_be_bytes());
        // Completing bounded repair changes what the next query can return even
        // without another incoming row. Publish that transition to every client.
        if let Some(read) = &read {
            h.update([u8::from(read.header.activity.ready)]);
            h.update(read.header.activity.applied.to_be_bytes());
            h.update(read.header.activity.invalidated.to_be_bytes());
            // Raw request cleanup can finish after the incoming resolution was
            // announced. Wake page readers when its exact pending set is ready.
            for tree in [
                super::activity_state::ActivityTree::RawPending,
                super::activity_state::ActivityTree::RawRetire,
            ] {
                h.update(read.header.activity.roots[tree.index()].to_be_bytes());
            }
            h.update([u8::from(read.header.activity.waiting.ready)]);
            h.update(read.header.activity.waiting.root.to_be_bytes());
            h.update(read.header.activity.waiting.metadata.to_be_bytes());
        }

        h.update(self.legacy_sessions.display_revision().to_be_bytes());
        h.update(published.0.to_be_bytes());
        h.update(published.1.to_be_bytes());
        // An author becoming current, a fold publishing for the first time and a saved-Session
        // upgrade ending each change what a listing can show (ADR-037 R4): wake every client.
        let (known, refreshing) = self.drive_from_known(store)?;
        h.update(drive_basis(&known, &refreshing));
        h.update([u8::from(read.as_ref().is_some_and(|r| r.header.ready))]);
        h.update([u8::from(self.needs_session_upgrade())]);
        Ok(h.finalize().into())
    }

    pub(crate) fn session_query(
        &mut self,
        store: &Store,
        query: Query,
        max_bytes: usize,
        _now: u64,
    ) -> std::result::Result<Reply, String> {
        if self.poisoned {
            return Err(self.save_failure().to_string());
        }
        let result = (|| -> Answer<Reply> {
            let (authors, refreshing) = self.drive_from_known(store)?;
            let snapshot = store.snapshot()?;
            let read = Read::existing(&snapshot, &self.sek, &self.channel_id)?;
            let public = self
                .entries
                .render_view(store, &self.sek, &self.channel_id)?
                .session_revision();
            let published = read.as_ref().and_then(|read| read.header.published);
            // The published fold is the answer. It is provisional while the fold is behind
            // the room's inputs or has never published, and while a saved-Session upgrade,
            // restore, import or pending render runs: rows may still be added. What was
            // last published is shown and said to be provisional, and the next publication
            // changes the basis so every page re-reads. Expiry only ever removes rows and
            // applies per row where bodies are read; it makes no absence unproven.
            let provisional = read.as_ref().is_none_or(|read| {
                !read.header.ready
                    || read.header.published != Some((public, read.header.private_generation))
            }) || self.needs_session_upgrade();
            let revision = Revision {
                incarnation: self.gen.clone(),
                published,
                drive: drive_basis(&authors, &refreshing),
                member: None,
                refreshing: refreshing.clone(),
                provisional,
            };
            let check = |previous: &Revision| -> Answer<()> {
                if !Arc::ptr_eq(&previous.incarnation, &revision.incarnation)
                    || previous.published != revision.published
                    || previous.drive != revision.drive
                    || previous.member.is_some_and(|node| !self.is_member(&node))
                {
                    return Err(Failure::Request(CHANGED));
                }
                Ok(())
            };
            // Whether this node may read `node`'s Sessions. An author whose control effects
            // are refreshing is neither readable nor unreadable yet: that is said as such.
            let readable = |node: &Digest32| -> Answer<()> {
                if authors.contains(node) {
                    Ok(())
                } else if refreshing.contains(node) {
                    Err(Failure::Request(REFRESHING))
                } else {
                    Err(Failure::Request(CANNOT_READ))
                }
            };
            // A provisional fold proves no absence: a Session it does not hold may be among
            // the unfolded inputs, and "none" would let an idempotent opening post twice.
            let proven = |found: bool| -> Answer<()> {
                if !found && provisional {
                    return Err(Failure::Request(REFRESHING));
                }
                Ok(())
            };
            let Some(read) = read else {
                // No fold has run here yet: nothing is known, and every answer says so.
                return match query {
                    Query::Waiting => Ok(Reply::Waiting(0)),
                    Query::Pending { .. } => Ok(Reply::Pending {
                        targets: Vec::new(),
                        next: None,
                    }),
                    Query::Lifecycle { .. } => Ok(Reply::Lifecycle {
                        rows: Vec::new(),
                        older: false,
                        revision,
                    }),
                    Query::Page {
                        revision: previous, ..
                    } => {
                        if let Some(previous) = &previous {
                            check(previous)?;
                        }
                        Ok(Reply::Page {
                            rows: Vec::new(),
                            more: false,
                            revision,
                        })
                    }
                    Query::Validate { revision: previous } => {
                        check(&previous)?;
                        Ok(Reply::Valid)
                    }
                    Query::Join { node } => {
                        if self.is_member(&node)
                            && (authors.contains(&node) || refreshing.contains(&node))
                        {
                            return Err(Failure::Request(REFRESHING));
                        }
                        Ok(Reply::Page {
                            rows: Vec::new(),
                            more: false,
                            revision: Revision {
                                member: Some(node),
                                ..revision
                            },
                        })
                    }
                    Query::HasOpen { node }
                    | Query::Exact { node, .. }
                    | Query::Lookup { node, .. } => {
                        readable(&node)?;
                        Err(Failure::Request(REFRESHING))
                    }
                    Query::Summary { .. } | Query::Text { .. } => Err(Failure::Request(CHANGED)),
                };
            };
            match query {
                Query::Summary {
                    opening,
                    revision: previous,
                } => {
                    check(&previous)?;
                    let descriptor_id = read
                        .find(Tree::OpeningHash, &hash_key(&opening))?
                        .ok_or(Failure::Request(CHANGED))?;
                    let row = descriptor(&read, descriptor_id)?;
                    if !authors.contains(&row.node) {
                        return Err(Failure::Request(CHANGED));
                    }
                    let mut entries = 0u64;
                    let mut newest: Option<(u64, Digest32)> = None;
                    for author in &authors {
                        let group = super::activity_index::group(&row.id, author);
                        entries = entries
                            .checked_add(
                                read.find(Tree::ActivityCounts, &hash_key(&group))?
                                    .unwrap_or(0),
                            )
                            .ok_or(Error::MalformedAtRest("Session entry count exhausted"))?;
                        let mut bound = [255; 64];
                        bound[..32].copy_from_slice(&group);
                        if let Some((key, id)) = read.previous(Tree::ActivityRaw, Some(bound))? {
                            if key[..32] == group && newest.is_none_or(|(old, _)| id > old) {
                                let fact = super::activity_index::fact(&read, id)?;
                                if fact.author != *author || fact.session != row.id {
                                    return Err(
                                        Error::MalformedAtRest("Session newest binding").into()
                                    );
                                }
                                newest = Some((id, fact.hash));
                            }
                        }
                    }
                    let waiting = if row.ended.is_none() {
                        read.activity_find(
                            super::activity_state::ActivityTree::PendingCount,
                            &hash_key(&super::activity_index::group(&row.id, &row.node)),
                        )?
                        .unwrap_or(0)
                    } else {
                        0
                    };
                    Ok(Reply::Summary(crate::node::ipc::SessionSummary {
                        entries,
                        newest: newest.map(|(_, hash)| hash),
                        waiting: u32::try_from(waiting).unwrap_or(u32::MAX),
                    }))
                }
                Query::Pending { after } => {
                    use super::activity_index::{arrival_key, fact};
                    use super::activity_state::ActivityTree;
                    let stamp = self.sessions_revision(store)?;
                    if after.is_some_and(|c| c.revision != stamp) {
                        return Err(Failure::Request(CHANGED));
                    }
                    let mut cursor = after.map(|c| c.after);
                    let mut targets = Vec::new();
                    let mut complete = false;
                    for _ in 0..256 {
                        if targets.len() == 64 {
                            break;
                        }
                        let Some((key, id)) =
                            read.activity_next(ActivityTree::RoomPending, cursor.map(arrival_key))?
                        else {
                            complete = true;
                            break;
                        };
                        if key != arrival_key(id) {
                            return Err(
                                Error::MalformedAtRest("Session pending cursor binding").into()
                            );
                        }
                        cursor = Some(id);
                        let f = fact(&read, id)?;
                        if !authors.contains(&f.author) {
                            continue;
                        }
                        let reference = f
                            .outcome_reference()
                            .ok_or(Error::MalformedAtRest("Session pending request reference"))?;
                        if read
                            .activity_find(
                                ActivityTree::Resolved,
                                &hash_key(&super::activity_fold::authored_reference(
                                    &f, &reference,
                                )),
                            )?
                            .is_some()
                        {
                            continue;
                        }
                        let group = sha256_concat(&[
                            b"vox/session-projection/id/v1",
                            &f.author,
                            f.session.as_bytes(),
                        ]);
                        let Some(row_id) = read.find(Tree::Groups, &hash_key(&group))? else {
                            continue;
                        };
                        let row = descriptor(&read, row_id)?;
                        if row.node != f.author || row.id != f.session {
                            return Err(
                                Error::MalformedAtRest("Session pending opening binding").into()
                            );
                        }
                        if row.ended.is_some() {
                            continue;
                        }
                        targets.push(crate::node::sessions::PendingTarget {
                            node: f.author,
                            id: f.session,
                            opening: row.opening.position.hash,
                            entry: f.hash,
                        });
                    }
                    Ok(Reply::Pending {
                        targets,
                        next: if complete {
                            None
                        } else {
                            cursor.map(|after| crate::node::sessions::PendingCursor {
                                revision: stamp,
                                after,
                            })
                        },
                    })
                }
                Query::Waiting => {
                    // The published waiting root answers; a rebuild in flight publishes its
                    // own root later and changes the room's Session revision, so the count
                    // is read again then.
                    let waiting = &read.header.activity.waiting;
                    let mut total = 0u64;
                    for author in &authors {
                        total = total
                            .checked_add(
                                read.waiting_find(waiting.root, &hash_key(author))?
                                    .unwrap_or(0),
                            )
                            .ok_or(Error::MalformedAtRest("Session waiting total exhausted"))?;
                    }
                    Ok(Reply::Waiting(total))
                }
                Query::Lifecycle {
                    before,
                    not_before,
                    limit,
                } => {
                    let mut cursor = match before {
                        None => None,
                        Some(cursor) => {
                            let id = read
                                .find(Tree::OpeningHash, &hash_key(&cursor.opening))?
                                .ok_or(Failure::Request(CHANGED))?;
                            let row = descriptor(&read, id)?;
                            let time = if cursor.ended {
                                row.ended.map(|e| e.position.created)
                            } else {
                                Some(row.position.created)
                            };
                            if !authors.contains(&row.node) || time != Some(cursor.at_millis) {
                                return Err(Failure::Request(CHANGED));
                            }
                            Some((cursor.at_millis, id, cursor.ended))
                        }
                    };
                    let mut rows = Vec::new();
                    let mut bytes = 0u64;
                    let mut older = false;
                    while let Some((key, id)) = previous_lifecycle(&read, &authors, cursor)? {
                        let time = u64::from_be_bytes(
                            key[32..40]
                                .try_into()
                                .map_err(|_| Error::MalformedAtRest("Session lifecycle time"))?,
                        );
                        if not_before.is_some_and(|lower| time < lower) {
                            break;
                        }
                        let row = descriptor(&read, id)?;
                        let ended = key[48] == 1;
                        if key[48] > 1 || key != lifecycle_key(&row.node, time, id, ended) {
                            return Err(
                                Error::MalformedAtRest("Session lifecycle index binding").into()
                            );
                        }
                        let cost = 256u64
                            .saturating_add(row.name.map_or(0, |f| f.bytes))
                            .saturating_add(row.harness.map_or(0, |f| f.bytes))
                            .saturating_add(row.cwd.map_or(0, |f| f.bytes));
                        if !rows.is_empty()
                            && (rows.len() >= limit.clamp(1, PAGE_ROWS)
                                || bytes.saturating_add(cost) > max_bytes as u64)
                        {
                            older = true;
                            break;
                        }
                        bytes = bytes.saturating_add(cost);
                        cursor = Some((time, id, ended));
                        let cursor = crate::node::sessions::LifecycleCursor {
                            at_millis: time,
                            opening: row.opening.position.hash,
                            ended,
                        };
                        rows.push((Row::from(row), cursor));
                    }
                    rows.reverse();
                    Ok(Reply::Lifecycle {
                        rows,
                        older,
                        revision,
                    })
                }
                Query::HasOpen { node } => {
                    readable(&node)?;
                    let open = read.find(Tree::OpenCounts, &hash_key(&node))?.unwrap_or(0) != 0;
                    proven(open)?;
                    Ok(Reply::HasOpen(open))
                }
                Query::Join { node } => {
                    // One deterministic current opening, directly from the existing author
                    // index. Read-only members get the same empty answer as no opening; a
                    // member whose controls are refreshing, or whose opening a provisional
                    // fold does not hold yet, is told to retry rather than "none".
                    let row = if authors.contains(&node) && self.is_member(&node) {
                        next(&read, &[node], 0, true)?.map(|(_, row)| row)
                    } else {
                        None
                    };
                    if self.is_member(&node) {
                        if refreshing.contains(&node) {
                            return Err(Failure::Request(REFRESHING));
                        }
                        if authors.contains(&node) {
                            proven(row.is_some())?;
                        }
                    }
                    if row.as_ref().is_some_and(|row| {
                        256u64
                            .saturating_add(row.name.map_or(0, |f| f.bytes))
                            .saturating_add(row.harness.map_or(0, |f| f.bytes))
                            .saturating_add(row.cwd.map_or(0, |f| f.bytes))
                            > max_bytes as u64
                    }) {
                        return Err(Failure::Request("Session join metadata exceeds one page"));
                    }
                    Ok(Reply::Page {
                        rows: row.map(Row::from).into_iter().collect(),
                        more: false,
                        revision: Revision {
                            member: Some(node),
                            ..revision
                        },
                    })
                }
                Query::Page {
                    open_only,
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
                    let mut candidate = next(&read, &authors, cursor, open_only)?;
                    while let Some((id, row)) = candidate {
                        let cost = 256u64
                            .saturating_add(row.name.map_or(0, |f| f.bytes))
                            .saturating_add(row.harness.map_or(0, |f| f.bytes))
                            .saturating_add(row.cwd.map_or(0, |f| f.bytes));
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
                        candidate = next(&read, &authors, cursor, open_only)?;
                    }
                    Ok(Reply::Page {
                        rows,
                        more: false,
                        revision,
                    })
                }
                Query::Validate { revision: previous } => {
                    check(&previous)?;
                    Ok(Reply::Valid)
                }
                Query::Exact { node, id } => {
                    readable(&node)?;
                    let group =
                        sha256_concat(&[b"vox/session-projection/id/v1", &node, id.as_bytes()]);
                    let row = read
                        .find(Tree::Groups, &hash_key(&group))?
                        .map(|id| descriptor(&read, id))
                        .transpose()?
                        .map(Row::from);
                    proven(row.is_some())?;
                    Ok(Reply::Page {
                        rows: row.into_iter().collect(),
                        more: false,
                        revision,
                    })
                }
                Query::Lookup { node, id } => {
                    readable(&node)?;
                    let group =
                        sha256_concat(&[b"vox/session-projection/id/v1", &node, id.as_bytes()]);
                    let row = read
                        .find(Tree::Groups, &hash_key(&group))?
                        .map(|id| descriptor(&read, id))
                        .transpose()?
                        .map(Row::from);
                    proven(row.is_some())?;
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
                        FieldKind::Cwd => row.cwd,
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
