//! One indexed activity page and bounded companion walks. Only fixed locators
//! survive an actor turn; the IPC writer carries one authenticated record at a time.

use super::super::ChannelState;
use super::activity_index::{arrival_key, fact, group, hash_key, member_key, Fact, Kind};
use super::activity_state::ActivityTree as T;
use super::record::Key;
use super::storage::{Read, Tree};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::drive::{SessionFilter, SessionRow};
use crate::node::store::Store;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const CHANGED: &str = "the room's Session activity changed; refresh the page";
const REFRESHING: &str = "the room is refreshing saved Sessions; retry";
const STEPS: usize = 256;

#[derive(Clone)]
pub(crate) struct Revision {
    incarnation: Arc<std::sync::atomic::AtomicU64>,
    instance: [u8; 16],
    invalidated: u64,
    drive: Digest32,
    boundary: u64,
    pending: Option<(u64, u64)>,
}

#[derive(Clone)]
pub(crate) struct Plan {
    pub origins: Vec<u64>,
    pub older: u64,
    pub visible: bool,
    pub revision: Revision,
}

impl Plan {
    pub(crate) fn instance(&self) -> [u8; 16] {
        self.revision.instance
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Cursor {
    pub origin: usize,
    pub phase: u8,
    pub after: Option<u64>,
}

#[derive(Clone)]
pub(crate) enum Query {
    Resolve {
        typed: String,
        visible: bool,
        after: Option<Key>,
        candidate: Option<String>,
        revision: Option<Revision>,
    },
    Select {
        which: SessionFilter,
        before: Option<Digest32>,
        max_rows: usize,
        max_bytes: usize,
        revision: Option<Revision>,
    },
    Companions {
        plan: Plan,
        cursor: Cursor,
    },
    Row {
        plan: Plan,
        arrival: u64,
    },
}

pub(crate) enum Reply {
    Resolved {
        candidate: Option<String>,
        next: Option<Key>,
        ambiguous: bool,
        revision: Revision,
    },
    Selected(Plan),
    Companions {
        arrivals: Vec<u64>,
        next: Option<Cursor>,
    },
    Row(SessionRow),
}

fn bad() -> Error {
    Error::MalformedAtRest("Session activity projection")
}
fn id(key: &Key) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&key[32..40]);
    u64::from_be_bytes(bytes)
}
fn authored(reference: &Digest32, author: &Digest32) -> Digest32 {
    crate::hash::sha256_concat(&[b"vox/session-activity/authored-ref/v1", author, reference])
}
fn outcome_authors<'a>(origin: &'a Fact, authors: &'a [Digest32]) -> &'a [Digest32] {
    if origin.association.is_some() {
        std::slice::from_ref(&origin.author)
    } else {
        authors
    }
}

/// The reference index is shared across activity kinds. A matching reference alone must
/// not attach an unrelated failed drive result as another rendered line. `Other` includes
/// tool calls; their tool-done records are folded into the call, never standalone lines.
fn outcome_kind(origin: Kind) -> Option<Kind> {
    match origin {
        Kind::Other => Some(Kind::ToolDone),
        Kind::Approval | Kind::Question => Some(Kind::Resolved),
        Kind::Drive => Some(Kind::DriveResult),
        Kind::Resolved | Kind::ToolDone | Kind::DriveResult => None,
    }
}
/// Each applicable author contributes one indexed predecessor, not its whole
/// transcript. The greatest arrival is the room's next raw/visible origin.
fn previous(
    read: &Read<'_>,
    tree: T,
    groups: &[Digest32],
    before: u64,
) -> Result<Option<(u64, u64)>> {
    let mut found = None;
    for group in groups {
        let key = member_key(group, before);
        if let Some((key, rank)) = read.activity_previous(tree, Some(key))? {
            if key[..32] == group[..] {
                let arrival = id(&key);
                if found.is_none_or(|(old, _)| arrival > old) {
                    found = Some((arrival, rank));
                }
            }
        }
    }
    Ok(found)
}

fn prefix(read: &Read<'_>, tree: T, groups: &[Digest32], before: u64) -> Result<u64> {
    let mut count = 0u64;
    for group in groups {
        let rank = read
            .activity_previous(tree, Some(member_key(group, before)))?
            .filter(|(key, _)| key[..32] == group[..])
            .map_or(0, |(_, rank)| rank);
        count = count.checked_add(rank).ok_or_else(bad)?;
    }
    Ok(count)
}

fn byte_prefix(read: &Read<'_>, tree: T, group: &Digest32, boundary: u64) -> Result<u64> {
    Ok(read
        .activity_previous(
            tree,
            Some(member_key(group, boundary.checked_add(1).ok_or_else(bad)?)),
        )?
        .filter(|(key, _)| key[..32] == group[..] && id(key) != 0)
        .map_or(0, |(_, bytes)| bytes))
}
fn cost(
    read: &Read<'_>,
    origin: &Fact,
    authors: &[Digest32],
    visible: bool,
    boundary: u64,
) -> Result<u64> {
    let mut bytes = origin.bytes;
    if visible {
        bytes = bytes
            .checked_add(byte_prefix(read, T::PartBytes, &origin.hash, boundary)?)
            .ok_or_else(bad)?;
        if let Some(reference) = origin
            .outcome_reference()
            .filter(|_| outcome_kind(origin.kind).is_some())
        {
            for author in outcome_authors(origin, authors) {
                bytes = bytes
                    .checked_add(byte_prefix(
                        read,
                        T::OutcomeBytes,
                        &authored(&reference, author),
                        boundary,
                    )?)
                    .ok_or_else(bad)?;
            }
        }
    }
    Ok(bytes)
}

/// Conservative physical-row cost from sealed counters. Selection always uses the current
/// published boundary, so these totals include every companion eligible for that selection.
/// Shared outcomes may be charged to several origins: a narrower page can be requested, but
/// counting an oversized origin must never first walk its accumulated history.
fn physical_rows(
    read: &Read<'_>,
    origin: &Fact,
    authors: &[Digest32],
    visible: bool,
) -> Result<u64> {
    let mut rows = 1u64;
    if visible {
        rows = rows
            .checked_add(
                read.activity_find(T::PartCount, &hash_key(&origin.hash))?
                    .unwrap_or(0),
            )
            .ok_or(Error::StreamRefused(crate::node::ipc::SESSION_READ_LIMIT))?;
        if let Some(reference) = origin
            .outcome_reference()
            .filter(|_| outcome_kind(origin.kind).is_some())
        {
            for author in outcome_authors(origin, authors) {
                // OutcomeCount's producer uses (reference, author), unlike OutcomeBytes'
                // authored-reference hash. Keep this identical to activity_fold::visible.
                let mut key = hash_key(&reference);
                key[32..].copy_from_slice(author);
                rows = rows
                    .checked_add(read.activity_find(T::OutcomeCount, &key)?.unwrap_or(0))
                    .ok_or(Error::StreamRefused(crate::node::ipc::SESSION_READ_LIMIT))?;
            }
        }
    }
    Ok(rows)
}

fn bound_selection(rows: u64, bytes: u64) -> Result<()> {
    let encoded = rows
        .checked_mul(crate::node::ipc::ROW_OVERHEAD as u64)
        .and_then(|overhead| overhead.checked_add(bytes))
        .and_then(|bytes| bytes.checked_add(128));
    if rows > crate::node::ipc::SESSION_READ_ROWS as u64
        || encoded.is_none_or(|bytes| bytes > crate::node::ipc::SESSION_READ_BYTES as u64)
    {
        return Err(Error::StreamRefused(crate::node::ipc::SESSION_READ_LIMIT));
    }
    Ok(())
}

/// Test membership in an earlier selected origin instead of retaining a set of
/// every emitted part. The number of selected origins has the public page bound.
fn already_in(read: &Read<'_>, origins: &[u64], f: &Fact) -> Result<bool> {
    for origin in origins {
        if *origin == f.arrival {
            return Ok(true);
        }
        let old = fact(read, *origin)?;
        if read
            .activity_find(T::Parts, &member_key(&old.hash, f.arrival))?
            .is_some()
        {
            return Ok(true);
        }
        if let Some(reference) = old.outcome_reference() {
            if outcome_kind(old.kind) != Some(f.kind) {
                continue;
            }
            if old.association.is_some() && old.author != f.author {
                continue;
            }
            if read
                .activity_find(
                    T::Outcomes,
                    &member_key(&authored(&reference, &f.author), f.arrival),
                )?
                .is_some()
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn next_companion(
    read: &Read<'_>,
    plan: &Plan,
    cursor: &mut Cursor,
    authors: &[Digest32],
) -> Result<Option<u64>> {
    let Some(origin) = plan.origins.get(cursor.origin).copied() else {
        return Ok(None);
    };
    if !plan.visible {
        cursor.origin += 1;
        return Ok(Some(origin));
    }
    let original = fact(read, origin)?;
    match cursor.phase {
        0 => {
            cursor.phase = 1;
            cursor.after = None;
            Ok(Some(origin))
        }
        1 => {
            let bound = cursor.after.map_or_else(
                || hash_key(&original.hash),
                |after| member_key(&original.hash, after),
            );
            if let Some((key, arrival)) = read.activity_next(T::Parts, Some(bound))? {
                if key[..32] == original.hash && arrival <= plan.revision.boundary {
                    cursor.after = Some(arrival);
                    return Ok(Some(arrival));
                }
            }
            cursor.phase = 2;
            cursor.after = None;
            Ok(None)
        }
        2 => {
            let mut next = None;
            if let (Some(reference), Some(kind)) =
                (original.outcome_reference(), outcome_kind(original.kind))
            {
                for author in outcome_authors(&original, authors) {
                    let group = authored(&reference, author);
                    let bound = cursor
                        .after
                        .map_or_else(|| hash_key(&group), |after| member_key(&group, after));
                    if let Some((key, arrival)) = read.activity_next(T::Outcomes, Some(bound))? {
                        if key[..32] == group
                            && arrival <= plan.revision.boundary
                            && next.is_none_or(|old| arrival < old)
                        {
                            next = Some(arrival);
                        }
                    }
                }
                if let Some(arrival) = next {
                    // Advancing even past an unrelated kind keeps the actor's bounded scan
                    // progressing. Do not suppress that row when it is selected as an origin.
                    cursor.after = Some(arrival);
                    return Ok((fact(read, arrival)?.kind == kind).then_some(arrival));
                }
            }
            cursor.origin += 1;
            cursor.phase = 0;
            cursor.after = None;
            Ok(None)
        }
        _ => Err(bad()),
    }
}

impl ChannelState {
    pub(crate) fn session_activity_query(
        &mut self,
        store: &Store,
        query: Query,
        now: u64,
    ) -> std::result::Result<Reply, String> {
        if self.poisoned {
            return Err(self.save_failure().to_string());
        }
        if self.needs_session_upgrade() {
            return Err(REFRESHING.into());
        }
        let result = (|| -> Result<Reply> {
            if !self.private_controls_ready(store)? || !self.private_expiry_ready(store, now)? {
                return Err(Error::StreamRefused(REFRESHING));
            }
            let authors = self.drive_from(store)?;
            let snapshot = store.snapshot()?;
            let read = Read::existing(&snapshot, &self.sek, &self.channel_id)?
                .ok_or(Error::StreamRefused(REFRESHING))?;
            if !read.header.activity.ready {
                return Err(Error::StreamRefused(REFRESHING));
            }
            let mut hash = Sha256::new();
            for author in &authors {
                hash.update(author);
            }
            let current = Revision {
                incarnation: self.gen.clone(),
                instance: self.history_instance(store)?,
                invalidated: read.header.activity.invalidated,
                drive: hash.finalize().into(),
                boundary: read.header.activity.applied,
                pending: None,
            };
            let check = |revision: &Revision| -> Result<()> {
                if !Arc::ptr_eq(&current.incarnation, &revision.incarnation)
                    || current.instance != revision.instance
                    || current.invalidated != revision.invalidated
                    || current.drive != revision.drive
                    || current.boundary < revision.boundary
                {
                    return Err(Error::StreamRefused(CHANGED));
                }
                if let Some((membership, resolved)) = revision.pending {
                    if membership != read.header.activity.roots[T::RawPending.index()]
                        || resolved != read.header.activity.roots[T::RawResolved.index()]
                        || read.activity_next(T::RawRetire, None)?.is_some()
                    {
                        return Err(Error::StreamRefused(CHANGED));
                    }
                }
                Ok(())
            };
            match query {
                Query::Companions { plan, mut cursor } => {
                    check(&plan.revision)?;
                    if plan.origins.len() > crate::node::ipc::SESSION_PAGE_ROWS {
                        return Err(bad());
                    }
                    let mut arrivals = Vec::new();
                    for _ in 0..STEPS {
                        if cursor.origin >= plan.origins.len() {
                            return Ok(Reply::Companions {
                                arrivals,
                                next: None,
                            });
                        }
                        let owner = cursor.origin;
                        let phase = cursor.phase;
                        if let Some(arrival) = next_companion(&read, &plan, &mut cursor, &authors)?
                        {
                            let f = fact(&read, arrival)?;
                            if !authors.contains(&f.author) {
                                return Err(Error::StreamRefused(CHANGED));
                            }
                            let own = if phase == 2 {
                                let original = fact(&read, plan.origins[owner])?;
                                original.arrival == arrival
                                    || read
                                        .activity_find(
                                            T::Parts,
                                            &member_key(&original.hash, arrival),
                                        )?
                                        .is_some()
                            } else {
                                false
                            };
                            if !plan.visible
                                || (!own && !already_in(&read, &plan.origins[..owner], &f)?)
                            {
                                arrivals.push(arrival);
                            }
                            if arrivals.len() == 64 {
                                break;
                            }
                        }
                    }
                    Ok(Reply::Companions {
                        arrivals,
                        next: Some(cursor),
                    })
                }
                Query::Row { plan, arrival } => {
                    check(&plan.revision)?;
                    let f = fact(&read, arrival)?;
                    if arrival > plan.revision.boundary || !authors.contains(&f.author) {
                        return Err(Error::StreamRefused(CHANGED));
                    }
                    let sealed = snapshot
                        .get_segment(
                            &self.channel_id,
                            crate::atrest::store::SegmentKind::PrivateSession,
                            arrival,
                        )?
                        .ok_or_else(bad)?;
                    let saved = self.read_private(arrival, &sealed)?;
                    if self.private_expired(&saved, now) {
                        return Err(Error::StreamRefused(REFRESHING));
                    }
                    let row = saved.row.ok_or_else(bad)?;
                    if row.entry_hash != f.hash
                        || row.author != f.author
                        || row.session_id != f.session
                    {
                        return Err(bad());
                    }
                    Ok(Reply::Row(row))
                }
                Query::Resolve {
                    typed,
                    visible,
                    after,
                    mut candidate,
                    revision,
                } => {
                    let revision = match revision {
                        Some(r) => {
                            check(&r)?;
                            if r.boundary != current.boundary {
                                return Err(Error::StreamRefused(CHANGED));
                            }
                            r
                        }
                        None => current.clone(),
                    };
                    if after.is_none() {
                        let tree = if visible {
                            T::VisibleCount
                        } else {
                            T::RawCount
                        };
                        for author in &authors {
                            if read
                                .activity_find(tree, &hash_key(&group(&typed, author)))?
                                .unwrap_or(0)
                                != 0
                            {
                                return Ok(Reply::Resolved {
                                    candidate: Some(typed),
                                    next: None,
                                    ambiguous: false,
                                    revision,
                                });
                            }
                        }
                        if typed.trim().chars().count() < 8 {
                            return Ok(Reply::Resolved {
                                candidate: None,
                                next: None,
                                ambiguous: false,
                                revision,
                            });
                        }
                    }
                    let mut cursor = after;
                    for _ in 0..64 {
                        let Some((key, arrival)) = read.next(Tree::ActivitySessions, cursor)?
                        else {
                            return Ok(Reply::Resolved {
                                candidate,
                                next: None,
                                ambiguous: false,
                                revision,
                            });
                        };
                        cursor = Some(key);
                        let f = fact(&read, arrival)?;
                        if !authors.contains(&f.author) || !f.session.starts_with(typed.trim()) {
                            continue;
                        }
                        if visible
                            && read
                                .activity_find(T::VisibleCount, &hash_key(&f.group()))?
                                .unwrap_or(0)
                                == 0
                        {
                            continue;
                        }
                        if candidate.as_ref().is_some_and(|old| old != &f.session) {
                            return Ok(Reply::Resolved {
                                candidate: None,
                                next: None,
                                ambiguous: true,
                                revision,
                            });
                        }
                        candidate = Some(f.session);
                    }
                    Ok(Reply::Resolved {
                        candidate,
                        next: cursor,
                        ambiguous: false,
                        revision,
                    })
                }
                Query::Select {
                    which,
                    before,
                    max_rows,
                    max_bytes,
                    revision,
                } => {
                    if let Some(r) = revision {
                        check(&r)?;
                        if r.boundary != current.boundary {
                            return Err(Error::StreamRefused(CHANGED));
                        }
                    }
                    let mut revision = current;
                    if let SessionFilter::Entries {
                        node,
                        session_id,
                        entries,
                        instance,
                    } = &which
                    {
                        if session_id.is_empty()
                            || session_id.len() > crate::node::content::MAX_SESSION_ID_LEN
                        {
                            return Err(Error::StreamRefused(
                                "exact Session id is empty or too long",
                            ));
                        }
                        if entries.len() > 128 || before.is_some() {
                            return Err(Error::StreamRefused(
                                "exact Session selection exceeds 128 IDs or carries a page cursor",
                            ));
                        }
                        if *instance != revision.instance {
                            return Err(Error::StreamRefused(CHANGED));
                        }
                        if !authors.contains(node) {
                            return Err(Error::StreamRefused(
                                "this node no longer has drive access to the selected Session",
                            ));
                        }
                        let mut origins = Vec::new();
                        let mut bytes = 0u64;
                        let mut rows = 0u64;
                        for hash in entries {
                            let Some(arrival) = super::private_index::find(
                                &snapshot,
                                &self.sek,
                                &self.channel_id,
                                hash,
                            )?
                            else {
                                continue;
                            };
                            if read
                                .find(Tree::ActivityFacts, &arrival_key(arrival))?
                                .is_none()
                            {
                                return Err(Error::StreamRefused(
                                    "entry is not a Session activity origin",
                                ));
                            }
                            let f = fact(&read, arrival)?;
                            // The established Session view includes its owner's activity
                            // and authorized drivers' explicit drive rows naming this Session.
                            if f.hash != *hash
                                || f.session != *session_id
                                || (f.author != *node && f.kind != Kind::Drive)
                                || !authors.contains(&f.author)
                            {
                                return Err(Error::StreamRefused(
                                    "entry does not belong to the exact selected Session",
                                ));
                            }
                            if arrival > revision.boundary {
                                return Err(Error::StreamRefused(REFRESHING));
                            }
                            if read
                                .activity_find(T::Visible, &member_key(&f.group(), arrival))?
                                .is_none()
                            {
                                continue;
                            }
                            if origins.contains(&arrival) {
                                continue;
                            }
                            bytes = bytes
                                .checked_add(cost(&read, &f, &authors, true, revision.boundary)?)
                                .ok_or_else(bad)?;
                            rows = rows
                                .checked_add(physical_rows(&read, &f, &authors, true)?)
                                .ok_or(Error::StreamRefused(
                                    crate::node::ipc::SESSION_READ_LIMIT,
                                ))?;
                            bound_selection(rows, bytes)?;
                            origins.push(arrival);
                        }
                        // As for ordinary pages, one legal oversized logical activity is
                        // streamed whole. A larger exact selection is refused, never truncated.
                        if origins.len() > 1 && bytes > max_bytes as u64 {
                            return Err(Error::StreamRefused("held Session selection exceeds one page byte budget; refresh fewer IDs"));
                        }
                        origins.sort_unstable();
                        return Ok(Reply::Selected(Plan {
                            origins,
                            older: 0,
                            visible: true,
                            revision,
                        }));
                    }
                    if matches!(&which, SessionFilter::Pending(_)) {
                        if read.activity_next(T::RawRetire, None)?.is_some() {
                            return Err(Error::StreamRefused(REFRESHING));
                        }
                        revision.pending = Some((
                            read.header.activity.roots[T::RawPending.index()],
                            read.header.activity.roots[T::RawResolved.index()],
                        ));
                    }
                    let bound = match before {
                        Some(hash) => super::private_index::find(
                            &snapshot,
                            &self.sek,
                            &self.channel_id,
                            &hash,
                        )?
                        .ok_or(Error::StreamRefused(
                            "cursor not among these Session entries",
                        ))?,
                        None => revision.boundary.checked_add(1).ok_or_else(bad)?,
                    };
                    let (tree, groups, visible) = selection(&which, &authors)?;
                    if before.is_some() {
                        let mut member = false;
                        for g in &groups {
                            member |= read.activity_find(tree, &member_key(g, bound))?.is_some();
                        }
                        if !member || bound > revision.boundary {
                            return Err(Error::StreamRefused(
                                "cursor not among these Session entries",
                            ));
                        }
                        let f = fact(&read, bound)?;
                        if !authors.contains(&f.author) {
                            return Err(Error::StreamRefused(CHANGED));
                        }
                    }
                    let end = if matches!(&which, SessionFilter::Pending(_)) {
                        super::activity_pending::prefix(&read, &groups, bound)?
                    } else {
                        prefix(&read, tree, &groups, bound)?
                    };
                    let mut origins = Vec::new();
                    let mut cursor = bound;
                    let mut bytes = 0u64;
                    let mut rows = 0u64;
                    while origins.len() < max_rows.clamp(1, crate::node::ipc::SESSION_PAGE_ROWS) {
                        let Some((arrival, _)) = previous(&read, tree, &groups, cursor)? else {
                            break;
                        };
                        let f = fact(&read, arrival)?;
                        let cost = cost(&read, &f, &authors, visible, revision.boundary)?;
                        if !origins.is_empty() && bytes.saturating_add(cost) > max_bytes as u64 {
                            break;
                        }
                        bytes = bytes.checked_add(cost).ok_or_else(bad)?;
                        rows = rows
                            .checked_add(physical_rows(&read, &f, &authors, visible)?)
                            .ok_or(Error::StreamRefused(crate::node::ipc::SESSION_READ_LIMIT))?;
                        bound_selection(rows, bytes)?;
                        origins.push(arrival);
                        cursor = arrival;
                    }
                    let older = end.checked_sub(origins.len() as u64).ok_or_else(bad)?;
                    origins.reverse();
                    Ok(Reply::Selected(Plan {
                        origins,
                        older,
                        visible,
                        revision,
                    }))
                }
            }
        })();
        if let Err(ref error) = result {
            if !matches!(error, Error::StreamRefused(_)) {
                self.poison(error);
            }
        }
        result.map_err(|e| e.to_string())
    }
}

fn selection(which: &SessionFilter, authors: &[Digest32]) -> Result<(T, Vec<Digest32>, bool)> {
    Ok(match which {
        SessionFilter::Entries { .. } => return Err(bad()),
        SessionFilter::All => (T::AllRank, authors.to_vec(), false),
        SessionFilter::FilesOut => (T::FileRank, authors.to_vec(), false),
        SessionFilter::Session(id) => (
            T::Visible,
            authors.iter().map(|a| group(id, a)).collect(),
            true,
        ),
        SessionFilter::SessionRaw(id) => (
            T::RawRank,
            authors.iter().map(|a| group(id, a)).collect(),
            false,
        ),
        SessionFilter::Request {
            session_id,
            reference,
        } => {
            let reference = crate::hash::sha256_concat(&[
                b"vox/session-activity/ref/v1",
                &(session_id.len() as u64).to_be_bytes(),
                session_id.as_bytes(),
                reference.as_bytes(),
            ]);
            (
                T::RequestRank,
                authors.iter().map(|a| authored(&reference, a)).collect(),
                false,
            )
        }
        SessionFilter::Pending(id) => (
            T::RawPending,
            authors.iter().map(|a| group(id, a)).collect(),
            false,
        ),
    })
}
