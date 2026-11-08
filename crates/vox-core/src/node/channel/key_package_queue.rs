//! Durable progress over the authenticated package-only catalog. No package body remains
//! resident after an attempt, and unrelated room history is never walked for key delivery.

use std::collections::BTreeMap;

use super::{
    entry_store, governance, open_segment, seal_segment, session_projection, Digest32, Entry,
    Error, Result, SegmentKind, Sek, Store, AUTHORS_HARD_LIMIT,
};
use crate::cbor::{Decoder, Encoder};
use crate::node::keypackage::KeyPackage;

const RECORDS_PER_TURN: usize = 64;
const CHECKPOINT: u64 = 21;
const FLOOR_WAITS_HARD_LIMIT: usize = crate::node::drive::MAX_DRIVE_CHAINS;

#[derive(Clone, Copy)]
struct Replay {
    through: u64,
    end: u64,
}
#[derive(Clone, Copy)]
struct Attempt {
    cursor: u64,
    log_id: u64,
    author: Digest32,
    replay: bool,
    floor_exact: bool,
    floor_overflow: bool,
    binding: (u64, u64, u64),
}

#[derive(Clone, Copy)]
struct FloorWait {
    // Zero is only a legacy checkpoint's unknown catalog cursor, never a log id.
    cursor: u64,
    binding: (u64, u64, u64),
    pending: bool,
}

#[derive(Clone, Copy)]
struct FloorOverflow {
    first: u64,
    last: u64,
    // Frozen before the sweep; newer evidence requests one successor sweep.
    binding: (u64, u64, u64),
    scan: Option<Replay>,
    pending: bool,
}

pub(crate) struct Pending {
    pub(crate) log_id: u64,
    pub(crate) author: Digest32,
    pub(crate) package: KeyPackage,
}
pub(crate) struct Progress {
    pub(crate) package: Option<Pending>,
    pub(crate) pending: bool,
    pub(crate) floor_changed: bool,
}

#[derive(Clone)]
pub(super) struct Queue {
    through: u64,
    published: u64,
    refresh: bool,
    replay: Option<Replay>,
    replay_requested: u64,
    replay_next: bool,
    trust: Option<Digest32>,
    attempt: Option<Attempt>,
    // A bounded discovery hint, never permission to open a package or read a Session.
    authors: BTreeMap<Digest32, u64>,
    // Retained catalog locators whose floor evidence was incomplete at acknowledgement.
    // This is demand, not authorization; a changed binding requests a bounded replay.
    floor_wait: BTreeMap<(Digest32, u64, u64), FloorWait>,
    // Independent of trust replay: a completed range remains a dormant obligation.
    floor_overflow: BTreeMap<Digest32, FloorOverflow>,
}

impl Queue {
    pub(super) fn new(_next_log_id: u64) -> Self {
        Self {
            through: 0,
            published: 0,
            refresh: true,
            replay: None,
            replay_requested: 0,
            replay_next: false,
            trust: None,
            attempt: None,
            authors: BTreeMap::new(),
            floor_wait: BTreeMap::new(),
            floor_overflow: BTreeMap::new(),
        }
    }

    pub(super) fn restore(
        &mut self,
        store: &Store,
        sek: &Sek,
        room: &Digest32,
        tip: u64,
    ) -> Result<()> {
        let mut legacy = false;
        if let Some(segment) = store.get_segment(room, SegmentKind::KeyMaterial, CHECKPOINT)? {
            if segment.ciphertext.len()
                > AUTHORS_HARD_LIMIT * 160 + FLOOR_WAITS_HARD_LIMIT * 96 + 256
            {
                return Err(Error::MalformedAtRest("key-package checkpoint size"));
            }
            let bytes = open_segment(sek, SegmentKind::KeyMaterial, CHECKPOINT, &segment)?;
            let mut d = Decoder::new(&bytes);
            let fields = d.array()?;
            let version = d.uint()?;
            if !matches!(fields, 7..=9)
                || !matches!(version, 1 | 2)
                || (version == 2 && fields != 9)
            {
                return Err(Error::MalformedAtRest("key-package checkpoint version"));
            }
            self.through = d.uint()?;
            self.replay = match d.array()? {
                0 => None,
                2 => Some(Replay {
                    through: d.uint()?,
                    end: d.uint()?,
                }),
                _ => return Err(Error::MalformedAtRest("key-package replay cursor")),
            };
            self.replay_requested = d.uint()?;
            self.replay_next = match d.uint()? {
                0 => false,
                1 => true,
                _ => return Err(Error::MalformedAtRest("key-package replay flag")),
            };
            self.trust = match d.bytes()? {
                [] => None,
                b => Some(
                    b.try_into()
                        .map_err(|_| Error::MalformedAtRest("key-package trust binding"))?,
                ),
            };
            let count = d.array()?;
            if count > AUTHORS_HARD_LIMIT {
                return Err(Error::MalformedAtRest("key-package author bound"));
            }
            for _ in 0..count {
                if d.array()? != 2 {
                    return Err(Error::MalformedAtRest("key-package author row"));
                }
                let author = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedAtRest("key-package author"))?;
                let log = d.uint()?;
                if log == 0 {
                    return Err(Error::MalformedAtRest("key-package log position"));
                }
                self.authors
                    .entry(author)
                    .and_modify(|held| *held = (*held).max(log))
                    .or_insert(log);
            }
            if fields >= 8 {
                let count = d.array()?;
                if count > FLOOR_WAITS_HARD_LIMIT {
                    return Err(Error::MalformedAtRest("key-package floor wait bound"));
                }
                for _ in 0..count {
                    let row = d.array()?;
                    if !matches!(row, 6..=8) || (version == 2 && row != 8) {
                        return Err(Error::MalformedAtRest("key-package floor wait row"));
                    }
                    let author = d
                        .bytes()?
                        .try_into()
                        .map_err(|_| Error::MalformedAtRest("key-package floor wait author"))?;
                    let chain = d.uint()?;
                    let log_id = d.uint()?;
                    let cursor = if row == 8 { d.uint()? } else { 0 };
                    let binding = (d.uint()?, d.uint()?, d.uint()?);
                    let pending = if row >= 7 {
                        match d.uint()? {
                            0 => false,
                            1 => true,
                            _ => return Err(Error::MalformedAtRest("key-package floor wait flag")),
                        }
                    } else {
                        false
                    };
                    if log_id == 0
                        || cursor > self.through
                        || self
                            .floor_wait
                            .insert(
                                (author, chain, log_id),
                                FloorWait {
                                    cursor,
                                    binding,
                                    pending,
                                },
                            )
                            .is_some()
                    {
                        return Err(Error::MalformedAtRest("duplicate key-package floor wait"));
                    }
                }
            }
            if fields == 9 {
                let count = d.array()?;
                if count > AUTHORS_HARD_LIMIT {
                    return Err(Error::MalformedAtRest("key-package overflow author bound"));
                }
                for _ in 0..count {
                    let row = d.array()?;
                    if !matches!(row, 6..=8) || (version == 2 && row != 8) {
                        return Err(Error::MalformedAtRest("key-package overflow row"));
                    }
                    let author = d
                        .bytes()?
                        .try_into()
                        .map_err(|_| Error::MalformedAtRest("key-package overflow author"))?;
                    let first = d.uint()?;
                    let last = d.uint()?;
                    let binding = (d.uint()?, d.uint()?, d.uint()?);
                    let pending = if row >= 7 {
                        match d.uint()? {
                            0 => false,
                            1 => true,
                            _ => return Err(Error::MalformedAtRest("key-package overflow flag")),
                        }
                    } else {
                        false
                    };
                    let scan = if row == 8 {
                        match d.array()? {
                            0 => None,
                            2 => Some(Replay {
                                through: d.uint()?,
                                end: d.uint()?,
                            }),
                            _ => return Err(Error::MalformedAtRest("key-package overflow cursor")),
                        }
                    } else {
                        None
                    };
                    if first == 0
                        || first > last
                        || last > self.through
                        || scan.is_some_and(|scan| {
                            scan.through < first - 1 || scan.through >= scan.end || scan.end > last
                        })
                        || self
                            .floor_overflow
                            .insert(
                                author,
                                FloorOverflow {
                                    first,
                                    last,
                                    binding,
                                    scan,
                                    pending,
                                },
                            )
                            .is_some()
                    {
                        return Err(Error::MalformedAtRest("key-package overflow bounds"));
                    }
                }
            }
            d.finish()?;
            legacy = version == 1;
        }
        if self.authors.len() > AUTHORS_HARD_LIMIT
            || self.through > tip
            || self.replay_requested > self.through
            || self
                .replay
                .is_some_and(|r| r.through >= r.end || r.end > self.through)
        {
            return Err(Error::MalformedAtRest("key-package checkpoint bounds"));
        }
        self.published = tip;
        self.refresh = !self.floor_wait.is_empty() || !self.floor_overflow.is_empty();
        if legacy {
            // Old busy refusals had no wait mark. Check them once after upgrade,
            // and persist the new version with that request before returning.
            self.retry_retained();
            self.save(store, sek, room)?;
        }
        Ok(())
    }

    fn save(&self, store: &Store, sek: &Sek, room: &Digest32) -> Result<()> {
        let mut batch = store.batch()?;
        self.queue_save(&mut batch, sek, room)?;
        batch.commit()
    }

    fn queue_save(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
        sek: &Sek,
        room: &Digest32,
    ) -> Result<()> {
        let mut e = Encoder::new();
        e.array(9).uint(2).uint(self.through);
        match self.replay {
            Some(r) => {
                e.array(2).uint(r.through).uint(r.end);
            }
            None => {
                e.array(0);
            }
        }
        e.uint(self.replay_requested)
            .uint(u64::from(self.replay_next))
            .bytes(self.trust.as_ref().map_or(&[][..], |v| &v[..]))
            .array(self.authors.len());
        for (author, id) in &self.authors {
            e.array(2).bytes(author).uint(*id);
        }
        e.array(self.floor_wait.len());
        for ((author, chain, log_id), wait) in &self.floor_wait {
            let (revision, generation, membership) = wait.binding;
            e.array(8)
                .bytes(author)
                .uint(*chain)
                .uint(*log_id)
                .uint(wait.cursor)
                .uint(revision)
                .uint(generation)
                .uint(membership)
                .uint(u64::from(wait.pending));
        }
        e.array(self.floor_overflow.len());
        for (author, overflow) in &self.floor_overflow {
            let (revision, generation, membership) = overflow.binding;
            e.array(8)
                .bytes(author)
                .uint(overflow.first)
                .uint(overflow.last)
                .uint(revision)
                .uint(generation)
                .uint(membership)
                .uint(u64::from(overflow.pending));
            match overflow.scan {
                Some(scan) => {
                    e.array(2).uint(scan.through).uint(scan.end);
                }
                None => {
                    e.array(0);
                }
            }
        }
        let segment = seal_segment(sek, SegmentKind::KeyMaterial, CHECKPOINT, &e.finish())?;
        batch.put_segment(room, SegmentKind::KeyMaterial, CHECKPOINT, &segment)
    }

    pub(super) fn published(&mut self, _next_log_id: u64) {
        self.refresh = true;
    }
    pub(super) fn note(&mut self, author: Digest32, log_id: u64) -> Result<()> {
        if log_id == 0 {
            return Err(Error::MalformedAtRest("key-package log position"));
        }
        if !self.authors.contains_key(&author) && self.authors.len() == AUTHORS_HARD_LIMIT {
            return Err(Error::MalformedAtRest("too many key-package authors"));
        }
        self.authors
            .entry(author)
            .and_modify(|last| *last = (*last).max(log_id))
            .or_insert(log_id);
        self.refresh = true;
        Ok(())
    }
    pub(super) fn pending_from(&self, author: &Digest32) -> bool {
        self.authors.contains_key(author)
    }

    /// Selection does not acknowledge work. Effects are durable before this call; a crash
    /// between their commit and this checkpoint merely retries an idempotent installation.
    pub(super) fn attempted(
        &mut self,
        store: &Store,
        sek: &Sek,
        room: &Digest32,
        locator: (&Digest32, u64),
        floor_wait: Option<(u64, u64, u64, u64)>,
        accepted: bool,
    ) -> Result<()> {
        let (author, log_id) = locator;
        let attempt = self
            .attempt
            .ok_or(Error::MalformedAtRest("key-package attempt missing"))?;
        if attempt.author != *author || attempt.log_id != log_id {
            return Err(Error::MalformedAtRest("key-package attempt differs"));
        }
        let mut done = self.clone();
        if attempt.floor_exact {
            done.replay_next = false;
        } else if attempt.floor_overflow {
            done.advance_floor(author, attempt.cursor)?;
        } else {
            done.advance(attempt.cursor, attempt.replay);
        }
        done.attempt = None;
        if attempt.floor_overflow {
            done.refresh = true;
        }
        // A log locator is one immutable package, including when an earlier None
        // could not reveal its chain. Never clear another package by chain/author.
        let held = done
            .floor_wait
            .iter()
            .find(|((held_author, _, held_log), _)| held_author == author && *held_log == log_id)
            .map(|(_, wait)| *wait);
        done.floor_wait
            .retain(|(held_author, _, held_log), _| held_author != author || *held_log != log_id);
        if !accepted {
            let chain = floor_wait.map_or(u64::MAX, |wait| wait.0);
            let cursor = held.map_or(attempt.cursor, |wait| wait.cursor.max(attempt.cursor));
            if done.floor_wait.len() < FLOOR_WAITS_HARD_LIMIT {
                done.floor_wait.insert(
                    (*author, chain, log_id),
                    FloorWait {
                        cursor,
                        binding: attempt.binding,
                        pending: false,
                    },
                );
            } else {
                if cursor == 0 {
                    return Err(Error::MalformedAtRest(
                        "key-package overflow cursor missing",
                    ));
                }
                if !done.floor_overflow.contains_key(author)
                    && done.floor_overflow.len() == AUTHORS_HARD_LIMIT
                {
                    return Err(Error::MalformedAtRest(
                        "too many key-package overflow authors",
                    ));
                }
                done.floor_overflow
                    .entry(*author)
                    .and_modify(|overflow| {
                        overflow.first = overflow.first.min(cursor);
                        overflow.last = overflow.last.max(cursor);
                        // Do not overwrite the baseline of older unresolved rows.
                        overflow.pending |= overflow.binding != attempt.binding;
                    })
                    .or_insert(FloorOverflow {
                        first: cursor,
                        last: cursor,
                        binding: attempt.binding,
                        scan: None,
                        pending: false,
                    });
            }
            // Recheck after the atomic cursor+obligation checkpoint. Evidence that
            // arrived during Open/Install cannot be swallowed by acknowledgement.
            done.refresh = true;
        }
        // Floor waits protect only their exact chain, not every later generation
        // by the same author.
        if done.authors.get(author) == Some(&log_id) {
            done.authors.remove(author);
        }
        done.save(store, sek, room)?;
        *self = done;
        Ok(())
    }

    pub(super) fn attempt_binding(
        &self,
        author: &Digest32,
        log_id: u64,
    ) -> Result<(u64, u64, u64)> {
        self.attempt
            .filter(|attempt| attempt.author == *author && attempt.log_id == log_id)
            .map(|attempt| attempt.binding)
            .ok_or(Error::MalformedAtRest("key-package attempt differs"))
    }
    pub(super) fn has_attempt(&self) -> bool {
        self.attempt.is_some()
    }

    /// A selected locator whose work must be reselected remains at its original cursor.
    pub(super) fn abandon_unopened(&mut self) {
        self.attempt = None;
    }

    /// A physically available release slot and its bounded demand retry share the same
    /// transaction. The actor finishes a selected package before entering room maintenance.
    pub(super) fn capacity_retry(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
        sek: &Sek,
        room: &Digest32,
    ) -> Result<Self> {
        if self.attempt.is_some() {
            return Err(Error::MalformedAtRest(
                "release cleanup crossed unfinished key-package attempt",
            ));
        }
        let mut candidate = self.clone();
        for wait in candidate.floor_wait.values_mut() {
            wait.pending = true;
        }
        for overflow in candidate.floor_overflow.values_mut() {
            overflow.pending = true;
        }
        candidate.queue_save(batch, sek, room)?;
        Ok(candidate)
    }

    pub(super) fn retry_retained(&mut self) {
        self.replay_requested = self.replay_requested.max(self.through);
        self.start_replay();
    }
    fn start_replay(&mut self) {
        if self.replay.is_none() && self.replay_requested != 0 {
            self.replay = Some(Replay {
                through: 0,
                end: self.replay_requested,
            });
            self.replay_requested = 0;
        }
    }
    fn advance(&mut self, at: u64, replay: bool) {
        if replay {
            if let Some(scan) = self.replay.as_mut() {
                scan.through = at;
                if scan.through >= scan.end {
                    self.replay = None;
                    self.start_replay();
                }
            }
        } else {
            self.through = at;
        }
        self.replay_next = !replay;
    }

    fn advance_floor(&mut self, author: &Digest32, at: u64) -> Result<()> {
        let overflow = self
            .floor_overflow
            .get_mut(author)
            .ok_or(Error::MalformedAtRest("key-package overflow missing"))?;
        let scan = overflow.scan.as_mut().ok_or(Error::MalformedAtRest(
            "key-package overflow cursor missing",
        ))?;
        if at < scan.through || at > scan.end {
            return Err(Error::MalformedAtRest(
                "key-package overflow cursor differs",
            ));
        }
        scan.through = at;
        if at == scan.end {
            // Completion proves only that this evidence baseline was attempted.
            overflow.scan = None;
        }
        self.replay_next = false;
        Ok(())
    }
    pub(super) fn pending(&self) -> bool {
        self.refresh
            || self.through < self.published
            || self.replay.is_some()
            || self.replay_requested != 0
            || self.floor_wait.values().any(|wait| wait.pending)
            || self
                .floor_overflow
                .values()
                .any(|overflow| overflow.pending || overflow.scan.is_some())
            || self.attempt.is_some()
    }

    fn observe_floors(
        &mut self,
        store: &Store,
        sek: &Sek,
        room: &Digest32,
        (root, now, membership): (Digest32, u64, u64),
    ) -> Result<bool> {
        if self.floor_wait.is_empty() && self.floor_overflow.is_empty() {
            return Ok(false);
        }
        let snapshot = store.snapshot()?;
        let view = governance::View::pinned(&snapshot, sek, room, root, now)?;
        let generation = view.authority_generation();
        let mut changed = false;
        let mut waits = self.floor_wait.iter_mut().peekable();
        let mut overflows = self.floor_overflow.iter_mut().peekable();
        loop {
            // Both maps are author-ordered. Share one revision lookup across every
            // wait and overflow for this author, without allocating a cache.
            let author = match (waits.peek(), overflows.peek()) {
                (Some((key, _)), Some((author, _))) => key.0.min(**author),
                (Some((key, _)), None) => key.0,
                (None, Some((author, _))) => **author,
                (None, None) => break,
            };
            let revision = session_projection::floor_index::author(
                entry_store::Transaction::Snapshot(&snapshot),
                sek,
                room,
                &author,
            )?
            .revision;
            let current = (revision, generation, membership);
            while let Some((_, wait)) = waits.next_if(|(key, _)| key.0 == author) {
                if current != wait.binding {
                    wait.binding = current;
                    wait.pending = true;
                    changed = true;
                }
            }
            if let Some((_, overflow)) = overflows.next_if(|(key, _)| **key == author) {
                if current != overflow.binding && !overflow.pending {
                    overflow.pending = true;
                    changed = true;
                }
            }
        }
        Ok(changed)
    }

    // One bounded read needs the room's storage, binding and acceptance predicate together.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn next(
        &mut self,
        store: &Store,
        sek: &Sek,
        room: &Digest32,
        recipient: &Digest32,
        read: &super::entry_store::Read<'_>,
        trust: Digest32,
        verified: impl Fn(&Entry) -> Result<bool>,
        floor_context: (Digest32, u64, u64),
    ) -> Result<Progress> {
        if self.attempt.is_some() {
            return Err(Error::MalformedAtRest("key-package attempt unacknowledged"));
        }
        self.published = read.key_package_tip()?;
        self.refresh = false;
        let mut floor_changed = self.observe_floors(store, sek, room, floor_context)?;
        let floor_binding = |author: &Digest32| -> Result<(u64, u64, u64)> {
            let snapshot = store.snapshot()?;
            let view =
                governance::View::pinned(&snapshot, sek, room, floor_context.0, floor_context.1)?;
            let revision = session_projection::floor_index::author(
                entry_store::Transaction::Snapshot(&snapshot),
                sek,
                room,
                author,
            )?
            .revision;
            Ok((revision, view.authority_generation(), floor_context.2))
        };
        let mut changed = floor_changed;
        // Trust/prekey replay keeps its existing whole-catalog semantics. Floor
        // evidence never enters this cursor or requests a replay from zero.
        if self.trust != Some(trust) {
            self.retry_retained();
            self.trust = Some(trust);
            changed = true;
        }
        self.start_replay();
        for _ in 0..RECORDS_PER_TURN {
            let forward = self.through < self.published;
            let recovery = self.replay.is_some()
                || self.floor_wait.values().any(|wait| wait.pending)
                || self
                    .floor_overflow
                    .values()
                    .any(|overflow| overflow.pending || overflow.scan.is_some());
            let retry = recovery && (!forward || self.replay_next);
            let exact = if retry {
                self.floor_wait
                    .iter()
                    .find(|(_, wait)| wait.pending)
                    .map(|(key, wait)| (*key, *wait))
            } else {
                None
            };
            let overflow_author = if retry && exact.is_none() && self.replay.is_none() {
                self.floor_overflow
                    .iter()
                    .find(|(_, overflow)| overflow.pending || overflow.scan.is_some())
                    .map(|(author, _)| *author)
            } else {
                None
            };
            let replay = retry && exact.is_none() && overflow_author.is_none();
            let (cursor, id, expected_author) = if let Some((key, wait)) = exact {
                // Catalog cursors and log ids are different namespaces. Legacy
                // waits have only a log locator; never substitute it as a cursor.
                if wait.cursor != 0
                    && read.key_package_after(Some(wait.cursor - 1))? != Some((wait.cursor, key.2))
                {
                    if let Some(wait) = self.floor_wait.get_mut(&key) {
                        wait.pending = false;
                    }
                    self.replay_next = false;
                    changed = true;
                    continue;
                }
                (wait.cursor, key.2, Some(key.0))
            } else {
                let (after, end) = if let Some(author) = overflow_author {
                    let overflow = self
                        .floor_overflow
                        .get_mut(&author)
                        .ok_or(Error::MalformedAtRest("key-package overflow missing"))?;
                    if overflow.scan.is_none() {
                        // Freeze both evidence and the finite range before reading.
                        let current = floor_binding(&author)?;
                        floor_changed |= overflow.binding != current;
                        overflow.binding = current;
                        overflow.pending = false;
                        overflow.scan = Some(Replay {
                            through: overflow.first - 1,
                            end: overflow.last,
                        });
                        changed = true;
                    }
                    let scan = overflow.scan.ok_or(Error::MalformedAtRest(
                        "key-package overflow cursor missing",
                    ))?;
                    (scan.through, scan.end)
                } else if replay {
                    let scan = self
                        .replay
                        .ok_or(Error::MalformedAtRest("key-package replay missing"))?;
                    (scan.through, scan.end)
                } else if forward {
                    (self.through, self.published)
                } else {
                    break;
                };
                let Some((cursor, id)) = read
                    .key_package_after(Some(after))?
                    .filter(|(at, _)| *at <= end)
                else {
                    if let Some(author) = overflow_author {
                        self.advance_floor(&author, end)?;
                    } else {
                        self.advance(end, replay);
                    }
                    changed = true;
                    continue;
                };
                (cursor, id, overflow_author)
            };
            let package = match store.get_segment(room, SegmentKind::LogDb, id)? {
                // Legacy log-only waits may outlive eviction. A current catalog
                // locator with a missing body is still malformed, never success.
                None if exact.is_some_and(|(_, wait)| wait.cursor == 0) => None,
                None => return Err(Error::MalformedAtRest("key-package catalog body missing")),
                Some(segment) => {
                    let wire = open_segment(sek, SegmentKind::LogDb, id, &segment)?;
                    let entry = Entry::from_wire(&wire)?;
                    (verified(&entry)?
                        && expected_author.is_none_or(|author| author == entry.skeleton.author_id))
                    .then_some(&entry)
                    .and_then(|entry| entry.payload.as_deref())
                    .filter(|payload| KeyPackage::is_key_package(payload))
                    .and_then(|payload| KeyPackage::from_wire(payload).ok())
                    .filter(|package| &package.recipient == recipient)
                    .map(|package| Pending {
                        log_id: id,
                        author: entry.skeleton.author_id,
                        package,
                    })
                }
            };
            if let Some(package) = package {
                // Capture before Open and before authorized_floor_step, not after
                // either stage has advanced evidence. Acknowledgement reuses it.
                let binding = floor_binding(&package.author)?;
                if let Some(author) = overflow_author {
                    let overflow = self
                        .floor_overflow
                        .get_mut(&author)
                        .ok_or(Error::MalformedAtRest("key-package overflow missing"))?;
                    if binding != overflow.binding && !overflow.pending {
                        floor_changed = true;
                        overflow.pending = true;
                        changed = true;
                    }
                }
                if changed || retry {
                    self.save(store, sek, room)?;
                }
                self.attempt = Some(Attempt {
                    cursor,
                    log_id: id,
                    author: package.author,
                    replay,
                    floor_exact: exact.is_some(),
                    floor_overflow: overflow_author.is_some(),
                    binding,
                });
                return Ok(Progress {
                    package: Some(package),
                    pending: true,
                    floor_changed,
                });
            }
            if let Some((key, _)) = exact {
                if let Some(wait) = self.floor_wait.get_mut(&key) {
                    wait.pending = false;
                }
                self.replay_next = false;
            } else if let Some(author) = overflow_author {
                self.advance_floor(&author, cursor)?;
            } else {
                self.advance(cursor, replay);
            }
            changed = true;
        }
        if changed {
            self.save(store, sek, room)?;
        }
        // A finite sweep may finish while its source evidence is being published.
        // Recheck after committing its cursor, without treating completion as proof.
        if self.observe_floors(store, sek, room, floor_context)? {
            self.save(store, sek, room)?;
            floor_changed = true;
        }
        Ok(Progress {
            package: None,
            pending: self.pending(),
            floor_changed,
        })
    }
}
