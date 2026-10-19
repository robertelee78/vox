//! Exact governance and causal locators in the existing sealed page tree.
//!
//! Bodies remain in LogDb. No snapshot, row vector, or page survives a caller's
//! bounded turn. Header zero and all pages share this namespace's one allocator;
//! changes and their work cursor commit together in the profile's existing batch.

use super::super::entry_store::session_tree;
use crate::atrest::sek::Sek;
use crate::atrest::store::{open_segment, seal_segment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::store::{Batch, Snapshot, Store};
use zeroize::Zeroizing;

const KIND: SegmentKind = SegmentKind::GovernanceIndex;
const HEADER: u64 = 0;
const HEADER_BYTES: usize = 1024;
/// The derived index's own format. 4 (v0.4.6, ADR-037): the control settlement queue. An
/// older header is an obsolete index: `prepare` deletes it and the fold rebuilds from LogDb.
pub(super) const HEADER_VERSION: u64 = 4;

fn invalid(why: &'static str) -> Error {
    Error::MalformedAtRest(why)
}

pub(super) fn hash_key(hash: &Digest32) -> session_tree::Key {
    let mut key = [0; 64];
    key[..32].copy_from_slice(hash);
    key
}

pub(super) fn position(author: &Digest32, seq: u64) -> session_tree::Key {
    let mut key = hash_key(author);
    key[32..40].copy_from_slice(&seq.to_be_bytes());
    key
}

fn pending_key(log: u64, hash: &Digest32) -> session_tree::Key {
    let mut key = [0; 64];
    key[..8].copy_from_slice(&log.to_be_bytes());
    key[8..40].copy_from_slice(hash);
    key
}
fn pending_log(key: &session_tree::Key) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&key[..8]);
    u64::from_be_bytes(bytes)
}

fn frontier(entry: &Digest32, author: &Digest32) -> session_tree::Key {
    let mut key = hash_key(entry);
    key[32..].copy_from_slice(author);
    key
}

#[derive(Clone, Default)]
pub(super) struct Work {
    /// An entry whose parent frontiers are being joined.
    pub entry: Option<Digest32>,
    /// Queue version taken at start; a new late parent cannot be consumed by old work.
    pub serial: u64,
    pub log: u64,
    /// Strictly continue after this parent/author pair, including an empty page.
    pub parent: u64,
    pub author: Option<Digest32>,
    /// Descendants are enqueued when a frontier changes, even if clocks did not.
    pub child: Option<Digest32>,
    pub changed: bool,
}

/// Every tree in the namespace shares the same checked allocator and transaction.
#[derive(Clone, Copy)]
pub(super) enum Table {
    Hashes,
    Positions,
    Frontiers,
    Complete,
    Pending,
    PendingOrder,
    Dirty,
    Order,
    Ranks,
    AuthorOrder,
    Checks,
    Ready,
    Blocked,
    CreatorCerts,
    AllCerts,
    AllRevocations,
    NamedRevoked,
    Revocations,
    RevocationDecisions,
    AuthorityPositions,
    AuthorityHashes,
    AuthorityOrder,
    ActionOrder,
    Consent,
    EverRevoked,
    Presence,
    Back,
    ConsentReset,
    Shares,
    ShareFingerprints,
    Effects,
    EffectKinds,
    Notices,
    NoticeByHash,
    // Slot 34 was unused. Preserve the remaining sealed root positions.
    AuthorityCache = 35,
    IssuerRoles,
    ActiveAdmins,
    CurrentAuthority,
    /// Control rows awaiting frontier work (ADR-037 R2c): in a signed-format room the order
    /// settles on this queue alone, so content rows never hold the fold. Every row here is
    /// also in `PendingOrder`, the work queue; this one is worked first.
    ControlPending,
}

const TABLES: usize = Table::ControlPending as usize + 1;

#[derive(Clone, Copy)]
pub(super) enum Cursor {
    Canonical,
    Evaluation,
}
const CURSORS: usize = Cursor::Evaluation as usize + 1;
const CURSOR_BYTES: usize = 2048;

#[derive(Clone)]
struct Header {
    next: u64,
    roots: [u64; TABLES],
    cursors: [u64; CURSORS],
    /// A receipt cursor for reopen/backfill of authoritative saved inputs.
    through: u64,
    /// Every receipt past catchup_end through known_tail was observed live in
    /// its source Batch. Ordinary chat cannot extend an older replay obligation.
    known_tail: u64,
    catchup_end: u64,
    barrier: u64,
    initialized: bool,
    revision: u64,
    queue_serial: u64,
    display_revision: u64,
    admin_clock: u64,
    evaluated: u64,
    ordered: u64,
    order_ready: bool,
    ordered_from: u64,
    authority_generation: u64,
    authority_folded: u64,
    authority_deadline: u64,
    head_generation: u64,
    work: Work,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            next: 1,
            roots: [0; TABLES],
            cursors: [0; CURSORS],
            through: 0,
            known_tail: 0,
            catchup_end: 0,
            barrier: 0,
            initialized: false,
            revision: 0,
            queue_serial: 0,
            display_revision: 0,
            admin_clock: 0,
            evaluated: 0,
            ordered: 0,
            order_ready: true,
            ordered_from: 0,
            authority_generation: 1,
            authority_folded: 0,
            authority_deadline: 0,
            head_generation: 0,
            work: Work::default(),
        }
    }
}

fn write_hash(e: &mut Encoder, hash: Option<Digest32>) {
    match hash {
        Some(hash) => {
            e.array(1).bytes(&hash);
        }
        None => {
            e.array(0);
        }
    }
}

fn read_hash(d: &mut Decoder<'_>) -> Result<Option<Digest32>> {
    match d.array()? {
        0 => Ok(None),
        1 => Ok(Some(
            d.bytes()?
                .try_into()
                .map_err(|_| invalid("governance work hash"))?,
        )),
        _ => Err(invalid("governance work hash arity")),
    }
}

/// The format a sealed header's plaintext was written at, if it reads as a header at all.
pub(super) fn header_version(bytes: &[u8]) -> Option<u64> {
    let mut d = Decoder::new(bytes);
    (d.array().ok()? == 22).then(|| d.uint().ok()).flatten()
}

impl Header {
    fn bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Encoder::new();
        e.array(22)
            .uint(HEADER_VERSION)
            .uint(self.next)
            .array(TABLES);
        for root in self.roots {
            e.uint(root);
        }
        e.array(CURSORS);
        for cursor in self.cursors {
            e.uint(cursor);
        }
        e.uint(self.through)
            .uint(self.known_tail)
            .uint(self.catchup_end)
            .uint(self.barrier)
            .uint(u64::from(self.initialized))
            .uint(self.revision)
            .uint(self.queue_serial)
            .uint(self.display_revision)
            .uint(self.admin_clock)
            .uint(self.evaluated)
            .array(7);
        write_hash(&mut e, self.work.entry);
        e.uint(self.work.serial)
            .uint(self.work.log)
            .uint(self.work.parent);
        write_hash(&mut e, self.work.author);
        write_hash(&mut e, self.work.child);
        e.uint(u64::from(self.work.changed));
        e.uint(self.ordered)
            .uint(u64::from(self.order_ready))
            .uint(self.ordered_from)
            .uint(self.authority_generation)
            .uint(self.authority_folded)
            .uint(self.authority_deadline)
            .uint(self.head_generation);
        Zeroizing::new(e.finish())
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > HEADER_BYTES {
            return Err(invalid("governance header size"));
        }
        let mut d = Decoder::new(bytes);
        if d.array()? != 22 || d.uint()? != HEADER_VERSION {
            return Err(invalid("governance header format"));
        }
        let next = d.uint()?;
        if d.array()? != TABLES {
            return Err(invalid("governance root count"));
        }
        let mut roots = [0; TABLES];
        for root in &mut roots {
            *root = d.uint()?;
        }
        if d.array()? != CURSORS {
            return Err(invalid("governance cursor count"));
        }
        let mut cursors = [0; CURSORS];
        for cursor in &mut cursors {
            *cursor = d.uint()?;
        }
        let through = d.uint()?;
        let known_tail = d.uint()?;
        let catchup_end = d.uint()?;
        let barrier = d.uint()?;
        let initialized = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(invalid("governance initialization boolean")),
        };
        let revision = d.uint()?;
        let queue_serial = d.uint()?;
        let display_revision = d.uint()?;
        let admin_clock = d.uint()?;
        let evaluated = d.uint()?;
        if d.array()? != 7 {
            return Err(invalid("governance work format"));
        }
        let work = Work {
            entry: read_hash(&mut d)?,
            serial: d.uint()?,
            log: d.uint()?,
            parent: d.uint()?,
            author: read_hash(&mut d)?,
            child: read_hash(&mut d)?,
            changed: match d.uint()? {
                0 => false,
                1 => true,
                _ => return Err(invalid("governance work boolean")),
            },
        };
        let ordered = d.uint()?;
        let order_ready = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(invalid("governance order publication boolean")),
        };
        let ordered_from = d.uint()?;
        let authority_generation = d.uint()?;
        let authority_folded = d.uint()?;
        let authority_deadline = d.uint()?;
        let head_generation = d.uint()?;
        d.finish()?;
        if next == 0
            || through > known_tail
            || catchup_end > known_tail
            || (initialized && through != known_tail)
            || authority_generation == 0
            || authority_folded > authority_generation
            || head_generation > authority_generation
            || roots.iter().chain(cursors.iter()).any(|root| *root >= next)
            || evaluated > ordered
            || ordered > revision
            || (work.entry.is_none()
                && (work.serial != 0
                    || work.log != 0
                    || work.parent != 0
                    || work.author.is_some()
                    || work.child.is_some()
                    || work.changed))
            || (work.entry.is_some()
                && (work.serial == 0 || work.serial > queue_serial || work.log == 0))
        {
            return Err(invalid("governance header bounds"));
        }
        Ok(Self {
            next,
            roots,
            cursors,
            through,
            known_tail,
            catchup_end,
            barrier,
            initialized,
            revision,
            queue_serial,
            display_revision,
            admin_clock,
            evaluated,
            ordered,
            order_ready,
            ordered_from,
            authority_generation,
            authority_folded,
            authority_deadline,
            head_generation,
            work,
        })
    }
}

enum Input<'a> {
    Snapshot(Snapshot),
    Batch(&'a Batch<'a>),
}
impl Input<'_> {
    fn get_segment(
        &self,
        room: &Digest32,
        kind: SegmentKind,
        id: u64,
    ) -> Result<Option<crate::atrest::store::SealedSegment>> {
        match self {
            Self::Snapshot(s) => s.get_segment(room, kind, id),
            Self::Batch(b) => b.get_segment(room, kind, id),
        }
    }
    fn segment_id_after(
        &self,
        room: &Digest32,
        kind: SegmentKind,
        after: Option<u64>,
    ) -> Result<Option<u64>> {
        match self {
            Self::Snapshot(s) => s.segment_id_after(room, kind, after),
            Self::Batch(b) => b.segment_id_after(room, kind, after),
        }
    }
}

pub(super) struct Read<'a> {
    input: Input<'a>,
    sek: &'a Sek,
    room: &'a Digest32,
    header: Header,
}

impl<'a> Read<'a> {
    pub(super) fn open(store: &Store, sek: &'a Sek, room: &'a Digest32) -> Result<Self> {
        Self::from_input(Input::Snapshot(store.snapshot()?), sek, room)
    }
    pub(super) fn in_batch(batch: &'a Batch<'a>, sek: &'a Sek, room: &'a Digest32) -> Result<Self> {
        Self::from_input(Input::Batch(batch), sek, room)
    }
    fn from_input(input: Input<'a>, sek: &'a Sek, room: &'a Digest32) -> Result<Self> {
        let header = input
            .get_segment(room, KIND, HEADER)?
            .map(|sealed| Header::parse(&open_segment(sek, KIND, HEADER, &sealed)?))
            .transpose()?
            .ok_or(invalid("governance header missing"))?;
        Ok(Self {
            input,
            sek,
            room,
            header,
        })
    }
    fn tree(&self) -> session_tree::Read<'_> {
        match &self.input {
            Input::Snapshot(snapshot) => {
                session_tree::Read::snapshot(snapshot, self.sek, self.room, KIND)
            }
            Input::Batch(batch) => session_tree::Read::batch(batch, self.sek, self.room, KIND),
        }
    }

    pub(super) fn get(&self, table: Table, key: &session_tree::Key) -> Result<Option<u64>> {
        self.tree().find(self.header.roots[table as usize], key)
    }
    pub(super) fn first(
        &self,
        table: Table,
        after: Option<session_tree::Key>,
    ) -> Result<Option<(session_tree::Key, u64)>> {
        self.tree()
            .first_after(self.header.roots[table as usize], after)
    }
    pub(super) fn at_or_after(
        &self,
        table: Table,
        key: session_tree::Key,
    ) -> Result<Option<(session_tree::Key, u64)>> {
        self.tree()
            .first_at_or_after(self.header.roots[table as usize], key)
    }
    pub(super) fn last(
        &self,
        table: Table,
        before: Option<session_tree::Key>,
    ) -> Result<Option<(session_tree::Key, u64)>> {
        self.tree()
            .last_before(self.header.roots[table as usize], before)
    }
    pub(super) fn record(&self, id: u64) -> Result<Zeroizing<Vec<u8>>> {
        if id == 0 || id >= self.header.next {
            return Err(invalid("governance record id"));
        }
        let sealed = self
            .input
            .get_segment(self.room, KIND, id)?
            .ok_or(invalid("governance record missing"))?;
        let bytes = open_segment(self.sek, KIND, id, &sealed)?;
        if bytes.len() > CURSOR_BYTES {
            return Err(invalid("governance record size"));
        }
        Ok(bytes)
    }
    pub(super) fn entry(&self, log: u64) -> Result<crate::log::entry::Entry> {
        let sealed = self
            .input
            .get_segment(self.room, SegmentKind::LogDb, log)?
            .ok_or(invalid("governance source entry missing"))?;
        let bytes = open_segment(self.sek, SegmentKind::LogDb, log, &sealed)?;
        let entry = crate::log::entry::Entry::from_wire(&bytes)?;
        if entry.skeleton.channel_id != *self.room
            || self.locator(&entry.entry_hash())? != Some(log)
        {
            return Err(invalid("governance source binding"));
        }
        Ok(entry)
    }
    pub(super) fn authority_generation(&self) -> u64 {
        self.header.authority_generation
    }
    // This is the published display revision, not the internal directory write revision.
    #[allow(clippy::misnamed_getters)]
    pub(super) fn revision(&self) -> u64 {
        self.header.display_revision
    }
    pub(super) fn deadline(&self) -> u64 {
        self.header.authority_deadline
    }
    pub(super) fn admin_clock(&self) -> Option<u64> {
        (self.header.roots[Table::AuthorityHashes as usize] != 0).then_some(self.header.admin_clock)
    }
    pub(super) fn current_ready(&self) -> Result<bool> {
        Ok(self.header.initialized
            && self
                .input
                .segment_id_after(self.room, SegmentKind::LogDb, Some(self.header.known_tail))?
                .is_none())
    }
    pub(super) fn ready(&self, now: u64) -> Result<bool> {
        Ok(self.current_ready()?
            && self.settled()
            && (self.header.authority_deadline == 0 || now < self.header.authority_deadline))
    }

    pub(super) fn locator(&self, hash: &Digest32) -> Result<Option<u64>> {
        self.tree()
            .find(self.header.roots[Table::Hashes as usize], &hash_key(hash))
    }

    pub(super) fn pending(&self) -> bool {
        self.header.roots[Table::Pending as usize] != 0
            || !self.header.initialized
            || !self.settled()
    }

    pub(super) fn settled(&self) -> bool {
        self.header.initialized
            && self.header.order_ready
            && self.header.evaluated == self.header.ordered
            && self.header.authority_folded == self.header.authority_generation
            && self.header.head_generation == self.header.authority_generation
    }
}

fn frontier_row(
    entry: &Digest32,
    row: Option<(session_tree::Key, u64)>,
) -> Result<Option<(Digest32, u64)>> {
    row.filter(|(key, _)| key[..32] == entry[..])
        .map(|(key, seq)| {
            if seq == 0 {
                return Err(invalid("empty governance frontier"));
            }
            Ok((
                key[32..]
                    .try_into()
                    .map_err(|_| invalid("governance frontier author"))?,
                seq,
            ))
        })
        .transpose()
}

/// One transaction owns both the derived facts and their replay obligation.
pub(super) struct Write<'a, 'store> {
    batch: &'a mut Batch<'store>,
    sek: &'a Sek,
    room: &'a Digest32,
    header: Header,
    /// Whether the order settles on control rows alone (a signed-format room, ADR-037 R2c).
    /// Set by the caller from the entry index; never persisted.
    control_only: bool,
}

impl<'a, 'store> Write<'a, 'store> {
    pub(super) fn open(
        batch: &'a mut Batch<'store>,
        sek: &'a Sek,
        room: &'a Digest32,
    ) -> Result<Self> {
        let header = match batch.get_segment(room, KIND, HEADER)? {
            Some(sealed) => Header::parse(&open_segment(sek, KIND, HEADER, &sealed)?)?,
            None => {
                if batch.segment_after(room, KIND, None)?.is_some() {
                    return Err(invalid("governance pages without header"));
                }
                let known_tail = batch
                    .last_segment_id(room, SegmentKind::LogDb)?
                    .unwrap_or(0);
                Header {
                    known_tail,
                    catchup_end: known_tail,
                    initialized: known_tail == 0,
                    ..Header::default()
                }
            }
        };
        Ok(Self {
            batch,
            sek,
            room,
            header,
            control_only: false,
        })
    }

    /// In a signed-format room every control row carries its own signed control closure, so
    /// content rows neither raise the barrier nor hold the order (ADR-037 R2c). A legacy
    /// room's control rows can have content parents, so there everything settles as before.
    pub(super) fn set_control_only(&mut self, on: bool) {
        self.control_only = on;
    }
    pub(super) fn control_only(&self) -> bool {
        self.control_only
    }

    fn tree(&self) -> session_tree::Read<'_> {
        session_tree::Read::batch(self.batch, self.sek, self.room, KIND)
    }

    fn set_root(&mut self, root: u64, key: session_tree::Key, value: Option<u64>) -> Result<u64> {
        let mut writer =
            session_tree::Write::new(self.batch, self.sek, self.room, KIND, self.header.next)?;
        let changed = writer.set(root, key, value)?;
        self.header.next = writer.next_page();
        Ok(changed)
    }

    pub(super) fn get(&self, table: Table, key: &session_tree::Key) -> Result<Option<u64>> {
        self.tree().find(self.header.roots[table as usize], key)
    }

    pub(super) fn put(
        &mut self,
        table: Table,
        key: session_tree::Key,
        value: Option<u64>,
    ) -> Result<()> {
        let root = self.set_root(self.header.roots[table as usize], key, value)?;
        self.header.roots[table as usize] = root;
        if matches!(table, Table::Dirty) && value.is_some() {
            self.header.order_ready = false;
        }
        Ok(())
    }

    pub(super) fn first(
        &self,
        table: Table,
        after: Option<session_tree::Key>,
    ) -> Result<Option<(session_tree::Key, u64)>> {
        self.tree()
            .first_after(self.header.roots[table as usize], after)
    }

    pub(super) fn at_or_after(
        &self,
        table: Table,
        key: session_tree::Key,
    ) -> Result<Option<(session_tree::Key, u64)>> {
        self.tree()
            .first_at_or_after(self.header.roots[table as usize], key)
    }

    pub(super) fn last(
        &self,
        table: Table,
        before: Option<session_tree::Key>,
    ) -> Result<Option<(session_tree::Key, u64)>> {
        self.tree()
            .last_before(self.header.roots[table as usize], before)
    }

    /// A bounded derived record in this namespace, using the same allocator as
    /// its index pages. Neither a second database nor a retained body cache.
    pub(super) fn record(&self, id: u64) -> Result<Zeroizing<Vec<u8>>> {
        if id == 0 || id >= self.header.next {
            return Err(invalid("governance record id"));
        }
        let sealed = self
            .batch
            .get_segment(self.room, KIND, id)?
            .ok_or(invalid("governance record missing"))?;
        let bytes = open_segment(self.sek, KIND, id, &sealed)?;
        if bytes.len() > CURSOR_BYTES {
            return Err(invalid("governance record size"));
        }
        Ok(bytes)
    }

    pub(super) fn save_record(&mut self, old: Option<u64>, bytes: &[u8]) -> Result<u64> {
        if bytes.len() > CURSOR_BYTES {
            return Err(invalid("governance record size"));
        }
        let id = match old {
            Some(id) if id != 0 && id < self.header.next => id,
            Some(_) => return Err(invalid("governance record id")),
            None => {
                let id = self.header.next;
                self.header.next = id
                    .checked_add(1)
                    .ok_or(invalid("governance allocator exhausted"))?;
                id
            }
        };
        self.batch.put_segment(
            self.room,
            KIND,
            id,
            &seal_segment(self.sek, KIND, id, bytes)?,
        )?;
        Ok(id)
    }

    pub(super) fn reached(&self, entry: &Digest32, author: &Digest32) -> Result<u64> {
        if !self.causal_settled()? || self.get(Table::Complete, &hash_key(entry))?.is_none() {
            return Err(invalid("governance causal facts not settled"));
        }
        Ok(self
            .get(Table::Frontiers, &frontier(entry, author))?
            .unwrap_or(0))
    }

    pub(super) fn cursor(&self, cursor: Cursor) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let id = self.header.cursors[cursor as usize];
        if id == 0 {
            return Ok(None);
        }
        let sealed = self
            .batch
            .get_segment(self.room, KIND, id)?
            .ok_or(invalid("governance cursor missing"))?;
        let bytes = open_segment(self.sek, KIND, id, &sealed)?;
        if bytes.len() > CURSOR_BYTES {
            return Err(invalid("governance cursor size"));
        }
        Ok(Some(bytes))
    }

    pub(super) fn save_cursor(&mut self, cursor: Cursor, bytes: &[u8]) -> Result<()> {
        if bytes.len() > CURSOR_BYTES {
            return Err(invalid("governance cursor size"));
        }
        let mut id = self.header.cursors[cursor as usize];
        if id == 0 {
            id = self.header.next;
            self.header.next = id
                .checked_add(1)
                .ok_or(invalid("governance allocator exhausted"))?;
            self.header.cursors[cursor as usize] = id;
        }
        self.batch.put_segment(
            self.room,
            KIND,
            id,
            &seal_segment(self.sek, KIND, id, bytes)?,
        )
    }

    pub(super) fn delete_record(&mut self, id: u64) -> Result<()> {
        if id == 0 || id >= self.header.next {
            return Err(invalid("governance record id"));
        }
        self.batch.delete_segment(self.room, KIND, id)?;
        Ok(())
    }

    /// Read one indexed body, checking its immutable locator on every read.
    /// Signature verification happened before publishing `Hashes`; this is not
    /// a second copy of the log and cannot hide a missing/changed source record.
    pub(super) fn entry(&self, log: u64) -> Result<crate::log::entry::Entry> {
        let sealed = self
            .batch
            .get_segment(self.room, SegmentKind::LogDb, log)?
            .ok_or(invalid("governance source entry missing"))?;
        let bytes = open_segment(self.sek, SegmentKind::LogDb, log, &sealed)?;
        let entry = crate::log::entry::Entry::from_wire(&bytes)?;
        if entry.skeleton.channel_id != *self.room
            || self.get(Table::Hashes, &hash_key(&entry.entry_hash()))? != Some(log)
        {
            return Err(invalid("governance source binding"));
        }
        Ok(entry)
    }

    /// The cursor advances with its index/queue updates in this transaction.
    /// It never skips a source id merely because a later record was notified.
    pub(super) fn observed_through(&mut self, id: u64) -> Result<()> {
        if id <= self.header.through {
            return Err(invalid("governance source cursor regressed"));
        }
        self.header.through = id;
        self.header.initialized = false;
        Ok(())
    }

    pub(super) fn source_after(&self) -> Result<Option<(u64, crate::log::entry::Entry)>> {
        if self.header.initialized || self.header.through >= self.header.catchup_end {
            return Ok(None);
        }
        self.batch
            .segment_after(self.room, SegmentKind::LogDb, Some(self.header.through))?
            .map(|(id, sealed)| {
                if id > self.header.catchup_end {
                    return Err(invalid("governance source replay bound missing"));
                }
                let bytes = open_segment(self.sek, SegmentKind::LogDb, id, &sealed)?;
                Ok((id, crate::log::entry::Entry::from_wire(&bytes)?))
            })
            .transpose()?
            .map(Some)
            .ok_or(invalid("governance source replay row missing"))
    }

    /// Recover a publication that has no live observation yet. Snapshot the
    /// actual source tail once; subsequent observed appends do not move this debt.
    pub(super) fn discover_source(&mut self) -> Result<()> {
        if self
            .batch
            .segment_id_after(self.room, SegmentKind::LogDb, Some(self.header.known_tail))?
            .is_some()
        {
            let tail = self
                .batch
                .last_segment_id(self.room, SegmentKind::LogDb)?
                .ok_or(invalid("governance source tail missing"))?;
            self.header.known_tail = tail;
            self.header.catchup_end = tail;
            self.header.initialized = false;
        }
        Ok(())
    }

    pub(super) fn live_receipt(&mut self, id: u64) -> Result<()> {
        // LogDb ids share an allocator with plaintext-cache rows; a legal gap is
        // not a missing source entry. Never skip an actual unobserved LogDb key.
        if id <= self.header.known_tail {
            return Ok(());
        }
        let next = self
            .batch
            .segment_id_after(self.room, SegmentKind::LogDb, Some(self.header.known_tail))?
            .ok_or(invalid("governance live receipt source missing"))?;
        if next > id {
            return Err(invalid("governance live receipt source skipped"));
        }
        self.header.known_tail = id;
        if next == id {
            if self.header.initialized {
                self.header.through = id;
            }
        } else {
            // A signed witness may publish an unbounded bodyless prefix. That
            // prefix is replay debt; the witness and later observed chat are not.
            self.header.catchup_end = id;
            self.header.initialized = false;
        }
        Ok(())
    }

    pub(super) fn source_caught_up(&mut self) {
        self.header.through = self.header.known_tail;
        self.header.initialized = true;
    }

    pub(super) fn order_published(&mut self, from: u64) -> Result<()> {
        if !self.causal_settled()? || self.first(Table::Dirty, None)?.is_some() {
            return Err(invalid("governance order published before inputs"));
        }
        if from == 0 {
            return Err(invalid("governance order publication prefix"));
        }
        self.header.ordered = self.header.revision;
        self.header.ordered_from = if self.header.ordered_from == 0 {
            from
        } else {
            from.min(self.header.ordered_from)
        };
        self.header.order_ready = true;
        Ok(())
    }

    pub(super) fn revision(&self) -> u64 {
        self.header.revision
    }

    pub(super) fn causal_settled(&self) -> Result<bool> {
        let queue = if self.control_only {
            Table::ControlPending
        } else {
            Table::PendingOrder
        };
        Ok(self.header.initialized
            && self
                .first(queue, None)?
                .is_none_or(|(key, _)| pending_log(&key) > self.header.barrier))
    }
    pub(super) fn initialized(&self) -> bool {
        self.header.initialized
    }
    pub(super) fn barrier(&mut self, log: u64) {
        self.header.barrier = self.header.barrier.max(log);
        self.header.order_ready = false;
    }
    pub(super) fn order_unblocked(&mut self) -> Result<()> {
        if !self.causal_settled()? || self.first(Table::Dirty, None)?.is_some() {
            return Err(invalid("governance order unblocked before inputs"));
        }
        self.header.order_ready = true;
        Ok(())
    }

    /// Index only a governance body whose authenticated LogDb binding was checked.
    pub(super) fn verified(
        &mut self,
        hash: &Digest32,
        author: &Digest32,
        seq: u64,
        log: u64,
    ) -> Result<()> {
        if seq == 0 || log == 0 {
            return Err(invalid("governance locator is zero"));
        }
        if let Some(previous) = self
            .tree()
            .find(self.header.roots[Table::Hashes as usize], &hash_key(hash))?
        {
            if previous != log {
                return Err(invalid("governance locator changed"));
            }
            return Ok(());
        }
        if self
            .tree()
            .find(
                self.header.roots[Table::Positions as usize],
                &position(author, seq),
            )?
            .is_some()
        {
            return Err(invalid("governance sequence conflict"));
        }
        self.header.roots[Table::Hashes as usize] = self.set_root(
            self.header.roots[Table::Hashes as usize],
            hash_key(hash),
            Some(log),
        )?;
        self.header.roots[Table::Positions as usize] = self.set_root(
            self.header.roots[Table::Positions as usize],
            position(author, seq),
            Some(log),
        )?;
        self.put(Table::Dirty, hash_key(hash), Some(log))?;
        self.changed()?;
        Ok(())
    }

    pub(super) fn authority_input(
        &mut self,
        hash: &Digest32,
        author: &Digest32,
        seq: u64,
        log: u64,
        root: &Digest32,
        body: &crate::governance::entry::GovBody,
    ) -> Result<()> {
        use crate::governance::entry::GovBody;
        match body {
            GovBody::AdminCert(cert) => {
                let target = cert.body.delegate_id();
                self.put(Table::AllCerts, frontier(&target, hash), Some(log))?;
                if author == root {
                    self.put(Table::CreatorCerts, position(&target, seq), Some(log))?;
                }
            }
            GovBody::AdminRevocation(_) => {
                self.put(Table::AllRevocations, hash_key(hash), Some(log))?;
            }
            _ => return Ok(()),
        }
        self.put(Table::AuthorityPositions, position(author, seq), Some(log))?;
        self.put(Table::AuthorityHashes, hash_key(hash), Some(log))?;
        self.authority_changed()
    }

    pub(super) fn observe_clock(&mut self, hash: &Digest32, clock: u64) -> Result<()> {
        if self.get(Table::AuthorityHashes, &hash_key(hash))?.is_some() {
            self.header.admin_clock = self.header.admin_clock.max(clock);
        }
        Ok(())
    }

    fn latest(&mut self, table: Table, key: session_tree::Key, seq: u64, log: u64) -> Result<()> {
        if let Some(old) = self.get(table, &key)? {
            if self.entry(old)?.skeleton.seq >= seq {
                return Ok(());
            }
        }
        self.put(table, key, Some(log))
    }

    /// Single-writer current facts do not need a canonical-history replay. Old
    /// statements stay on disk, so an out-of-order older arrival cannot undo a
    /// revoke, leave or unshare that was already recorded.
    pub(super) fn current_input(
        &mut self,
        author: &Digest32,
        seq: u64,
        log: u64,
        body: &crate::governance::entry::GovBody,
    ) -> Result<()> {
        use crate::governance::entry::GovBody;
        match body {
            GovBody::ConsentGrant(c) if c.body.epoch == 0 => {
                self.latest(
                    Table::Consent,
                    frontier(author, &c.body.target_id),
                    seq,
                    log,
                )?;
            }
            GovBody::ConsentRevocation(c) => {
                self.latest(
                    Table::EverRevoked,
                    frontier(author, &c.body.target_id),
                    seq,
                    log,
                )?;
                if c.body.epoch == 0 {
                    self.latest(
                        Table::Consent,
                        frontier(author, &c.body.target_id),
                        seq,
                        log,
                    )?;
                }
            }
            GovBody::Presence(p) => {
                self.latest(Table::Presence, hash_key(author), seq, log)?;
                if p.body.here {
                    self.latest(Table::Back, hash_key(author), seq, log)?;
                    if p.body.epoch == 0 {
                        self.latest(Table::ConsentReset, hash_key(author), seq, log)?;
                    }
                }
            }
            GovBody::ServiceShare(s) => {
                let name = crate::hash::sha256(s.body.name.as_bytes());
                self.latest(Table::Shares, frontier(author, &name), seq, log)?;
                let fingerprint =
                    crate::governance::share::service_fingerprint(self.room, author, &s.body.name);
                self.latest(
                    Table::ShareFingerprints,
                    frontier(author, &fingerprint),
                    seq,
                    log,
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn authority_changed(&mut self) -> Result<()> {
        self.display_changed()?;
        self.header.authority_generation = self
            .header
            .authority_generation
            .checked_add(1)
            .ok_or(invalid("governance authority generation exhausted"))?;
        Ok(())
    }

    pub(super) fn authority_generation(&self) -> u64 {
        self.header.authority_generation
    }
    pub(super) fn authority_folded(&self) -> u64 {
        self.header.authority_folded
    }
    pub(super) fn head_ready(&self) -> bool {
        self.header.head_generation == self.header.authority_generation
    }
    pub(super) fn head_published(&mut self, generation: u64) -> Result<()> {
        if generation != self.header.authority_generation {
            return Err(invalid("governance head publication changed"));
        }
        self.header.head_generation = generation;
        Ok(())
    }
    pub(super) fn ordered(&self) -> u64 {
        self.header.ordered
    }
    pub(super) fn order_ready(&self) -> bool {
        self.header.order_ready
    }
    pub(super) fn ordered_from(&self) -> u64 {
        self.header.ordered_from
    }

    pub(super) fn expire_authority(&mut self, now: u64) -> Result<()> {
        if self.header.authority_folded == self.header.authority_generation
            && self.header.authority_deadline != 0
            && self.header.authority_deadline <= now
        {
            self.authority_changed()?;
        }
        Ok(())
    }

    pub(super) fn authority_published(&mut self, generation: u64, deadline: u64) -> Result<()> {
        if generation != self.header.authority_generation {
            return Err(invalid("governance authority publication changed"));
        }
        self.header.authority_folded = generation;
        self.header.authority_deadline = deadline;
        Ok(())
    }

    pub(super) fn evaluation_published(&mut self, ordered: u64) -> Result<()> {
        if ordered != self.header.ordered
            || !self.header.order_ready
            || !self.causal_settled()?
            || self.header.authority_generation != self.header.authority_folded
            || self.header.head_generation != self.header.authority_generation
        {
            return Err(invalid("governance evaluation publication changed"));
        }
        self.header.evaluated = ordered;
        self.header.ordered_from = 0;
        Ok(())
    }

    fn changed(&mut self) -> Result<()> {
        self.display_changed()?;
        self.header.revision = self
            .header
            .revision
            .checked_add(1)
            .ok_or(invalid("governance revision exhausted"))?;
        Ok(())
    }

    fn display_changed(&mut self) -> Result<()> {
        self.header.display_revision = self
            .header
            .display_revision
            .checked_add(1)
            .ok_or(invalid("governance display revision exhausted"))?;
        Ok(())
    }

    /// Retain the obligation before acknowledging the accepted input to its caller. A control
    /// row is queued on the control settlement queue too (ADR-037 R2c), where it is worked
    /// first and where a signed-format room's order settles.
    pub(super) fn enqueue(&mut self, hash: &Digest32, log: u64, control: bool) -> Result<()> {
        if log == 0 {
            return Err(invalid("governance queue source is zero"));
        }
        self.header.queue_serial = self
            .header
            .queue_serial
            .checked_add(1)
            .ok_or(invalid("governance queue serial exhausted"))?;
        self.header.roots[Table::Pending as usize] = self.set_root(
            self.header.roots[Table::Pending as usize],
            hash_key(hash),
            Some(self.header.queue_serial),
        )?;
        self.put(
            Table::PendingOrder,
            pending_key(log, hash),
            Some(self.header.queue_serial),
        )?;
        if control {
            self.put(
                Table::ControlPending,
                pending_key(log, hash),
                Some(self.header.queue_serial),
            )?;
        }
        Ok(())
    }

    pub(super) fn work(&mut self) -> Result<Option<&mut Work>> {
        if self.header.work.entry.is_none() {
            // Control rows first: the order settles on them, and a room converging must not
            // wait behind its content backlog (ADR-037 R2c). Content rows follow in log order.
            let next = match self.first(Table::ControlPending, None)? {
                Some(control) => Some(control),
                None => self.first(Table::PendingOrder, None)?,
            };
            let Some((key, serial)) = next else {
                return Ok(None);
            };
            let log = pending_log(&key);
            if log == 0
                || key[40..].iter().any(|byte| *byte != 0)
                || serial == 0
                || serial > self.header.queue_serial
            {
                return Err(invalid("governance work queue"));
            }
            let entry = key[8..40]
                .try_into()
                .map_err(|_| invalid("governance work entry"))?;
            if self.get(Table::Pending, &hash_key(&entry))? != Some(serial) {
                return Err(invalid("governance work queue disagreement"));
            }
            self.header.work = Work {
                entry: Some(entry),
                serial,
                log,
                ..Work::default()
            };
        }
        Ok(Some(&mut self.header.work))
    }

    pub(super) fn finish_work(&mut self) -> Result<()> {
        let work = &self.header.work;
        let entry = work.entry.ok_or(invalid("governance work missing"))?;
        let key = hash_key(&entry);
        let order_key = pending_key(work.log, &entry);
        let queued = self
            .tree()
            .find(self.header.roots[Table::Pending as usize], &key)?
            .ok_or(invalid("governance work obligation missing"))?;
        if queued < work.serial {
            return Err(invalid("governance work obligation regressed"));
        }
        if self.get(Table::PendingOrder, &order_key)? != Some(queued) {
            return Err(invalid("governance work completion disagreement"));
        }
        if queued == work.serial {
            self.put(Table::PendingOrder, order_key, None)?;
            if self.get(Table::ControlPending, &order_key)?.is_some() {
                self.put(Table::ControlPending, order_key, None)?;
            }
            self.header.roots[Table::Pending as usize] =
                self.set_root(self.header.roots[Table::Pending as usize], key, None)?;
            self.header.roots[Table::Complete as usize] = self.set_root(
                self.header.roots[Table::Complete as usize],
                key,
                Some(queued),
            )?;
        }
        self.header.work = Work::default();
        Ok(())
    }

    pub(super) fn save_work(&mut self, work: Work) -> Result<()> {
        if self.header.work.entry != work.entry
            || self.header.work.serial != work.serial
            || self.header.work.log != work.log
        {
            return Err(invalid("governance work changed ownership"));
        }
        self.header.work = work;
        Ok(())
    }

    pub(super) fn frontier_after(
        &self,
        entry: &Digest32,
        after: Option<Digest32>,
    ) -> Result<Option<(Digest32, u64)>> {
        let tree = self.tree();
        let item = match after {
            Some(author) => tree.first_after(
                self.header.roots[Table::Frontiers as usize],
                Some(frontier(entry, &author)),
            )?,
            None => tree.first_at_or_after(
                self.header.roots[Table::Frontiers as usize],
                hash_key(entry),
            )?,
        };
        frontier_row(entry, item)
    }

    pub(super) fn raise(&mut self, entry: &Digest32, author: &Digest32, seq: u64) -> Result<bool> {
        if self.header.work.entry != Some(*entry) {
            return Err(invalid("governance frontier outside its work"));
        }
        let key = frontier(entry, author);
        let held = self
            .tree()
            .find(self.header.roots[Table::Frontiers as usize], &key)?
            .unwrap_or(0);
        if seq <= held {
            return Ok(false);
        }
        self.header.roots[Table::Frontiers as usize] =
            self.set_root(self.header.roots[Table::Frontiers as usize], key, Some(seq))?;
        self.header.work.changed = true;
        if let Some(log) = self.get(Table::Hashes, &hash_key(entry))? {
            self.changed()?;
            self.put(Table::Dirty, hash_key(entry), Some(log))?;
            if self
                .get(Table::AuthorityHashes, &hash_key(entry))?
                .is_some()
            {
                self.authority_changed()?;
            }
        }
        Ok(true)
    }

    pub(super) fn seal(self) -> Result<()> {
        let sealed = seal_segment(self.sek, KIND, HEADER, &self.header.bytes())?;
        self.batch.put_segment(self.room, KIND, HEADER, &sealed)
    }
}
