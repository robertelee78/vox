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
/// The derived index's own format. 5 adds the canonical projection fingerprint used to publish
/// semantic revisions only after the authorized fold completes. 4 (v0.4.6, ADR-037 R2c) added
/// the control settlement queue.
/// A format-3 header (every release through v0.4.5) is read as is, with the new queue empty,
/// and `prepare` fills that queue from the pending rows and reseals the header at the current
/// version: the
/// index is migrated in place, never rebuilt from the source log, so an upgrade does not pay a
/// cold scan of a large store for a derived queue it can compute from the rows it already has.
pub(super) const HEADER_VERSION: u64 = 5;
const HEADER_VERSION_WITH_CONTROL_QUEUE: u64 = 4;
const HEADER_VERSION_BEFORE_CONTROL_QUEUE: u64 = 3;

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
    /// Latest authenticated sequence for each single-writer slot. Kept apart from its semantic
    /// table so a newer repetition can block late older rows without revising the projected value.
    CurrentHeads,
}

const TABLES: usize = Table::CurrentHeads as usize + 1;

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
    /// Rolling XOR of domain-separated canonical output rows. It is an equality token, not an
    /// authority input: the checked Effects/ActiveAdmins trees remain the source of truth.
    projection: Digest32,
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
            projection: [0; 32],
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
    matches!(d.array().ok()?, 22 | 23)
        .then(|| d.uint().ok())
        .flatten()
}

impl Header {
    fn bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Encoder::new();
        e.array(23)
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
            .bytes(&self.projection)
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
        let arity = d.array()?;
        if !matches!(arity, 22 | 23) {
            return Err(invalid("governance header format"));
        }
        let version = d.uint()?;
        if !matches!(
            version,
            HEADER_VERSION
                | HEADER_VERSION_WITH_CONTROL_QUEUE
                | HEADER_VERSION_BEFORE_CONTROL_QUEUE
        ) || (version == HEADER_VERSION && arity != 23)
            || (version != HEADER_VERSION && arity != 22)
        {
            return Err(invalid("governance header format"));
        }
        let next = d.uint()?;
        // Format 3 had every table but the control settlement queue, which is read as empty.
        let stored = d.array()?;
        if stored != TABLES
            && !(version == HEADER_VERSION_WITH_CONTROL_QUEUE && stored == TABLES - 1)
            && !(version == HEADER_VERSION_BEFORE_CONTROL_QUEUE && stored == TABLES - 2)
        {
            return Err(invalid("governance root count"));
        }
        let mut roots = [0; TABLES];
        for root in roots.iter_mut().take(stored) {
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
        let projection = if version == HEADER_VERSION {
            d.bytes()?
                .try_into()
                .map_err(|_| invalid("governance projection fingerprint"))?
        } else {
            [0; 32]
        };
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
            projection,
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

pub(super) struct Read<'a> {
    input: Snapshot,
    sek: &'a Sek,
    room: &'a Digest32,
    header: Header,
}

impl<'a> Read<'a> {
    pub(super) fn open(store: &Store, sek: &'a Sek, room: &'a Digest32) -> Result<Self> {
        let input = store.snapshot()?;
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
        session_tree::Read::snapshot(&self.input, self.sek, self.room, KIND)
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
        changes_projection: bool,
        changes_order: bool,
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
        // Keep the immutable locator for every authenticated governance row, including a
        // superseded single-writer statement. Only a row that can change what a person sees
        // enters canonical work or advances the published revision. Otherwise an older consent,
        // presence or share arriving late invalidated the whole projection and restarted render
        // backfill even though `latest` discarded its effect immediately below.
        if changes_order {
            self.put(Table::Dirty, hash_key(hash), Some(log))?;
            self.changed()?;
        } else if changes_projection {
            self.display_changed()?;
        }
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

    fn current_entry(
        &self,
        table: Table,
        key: &session_tree::Key,
    ) -> Result<Option<crate::log::entry::Entry>> {
        self.get(table, key)?.map(|log| self.entry(log)).transpose()
    }

    fn current_head_key(
        author: &Digest32,
        body: &crate::governance::entry::GovBody,
    ) -> Option<session_tree::Key> {
        use crate::governance::entry::GovBody;
        let (domain, tail): (&[u8], &[u8]) = match body {
            GovBody::ConsentGrant(value) => (b"consent", &value.body.target_id),
            GovBody::ConsentRevocation(value) => (b"consent", &value.body.target_id),
            GovBody::Presence(_) => (b"presence", &[]),
            GovBody::ServiceShare(value) => (b"share", value.body.name.as_bytes()),
            _ => return None,
        };
        let mut bytes = Vec::with_capacity(domain.len() + author.len() + tail.len());
        bytes.extend_from_slice(b"vox/governance-current-head/v1");
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(author);
        bytes.extend_from_slice(tail);
        Some(hash_key(&crate::hash::sha256(&bytes)))
    }

    fn current_head(
        &self,
        author: &Digest32,
        body: &crate::governance::entry::GovBody,
        fallback: Option<&crate::log::entry::Entry>,
    ) -> Result<u64> {
        let key =
            Self::current_head_key(author, body).ok_or(invalid("governance current head kind"))?;
        self.current_entry(Table::CurrentHeads, &key).map(|entry| {
            entry.as_ref().map_or_else(
                || fallback.map_or(0, |entry| entry.skeleton.seq),
                |entry| entry.skeleton.seq,
            )
        })
    }

    /// Whether this authenticated single-writer fact changes its canonical current value.
    /// Sequence freshness alone is not a semantic change: a newer repetition of the same grant,
    /// revocation, presence or share remains an immutable historical locator but neither replaces
    /// the current slot nor revises the published projection. Likewise, an older row cannot
    /// mutate the auxiliary reset/back/ever-revoked tables behind a newer current statement.
    pub(super) fn current_input_change(
        &self,
        author: &Digest32,
        seq: u64,
        body: &crate::governance::entry::GovBody,
    ) -> Result<(bool, bool)> {
        use crate::governance::entry::GovBody;
        match body {
            GovBody::ConsentGrant(c) if c.body.epoch == 0 => {
                let key = frontier(author, &c.body.target_id);
                let reset = self
                    .current_entry(Table::ConsentReset, &hash_key(author))?
                    .map_or(0, |entry| entry.skeleton.seq);
                let old = self.current_entry(Table::Consent, &key)?;
                if self.current_head(author, body, old.as_ref())? >= seq {
                    return Ok((false, false));
                }
                let Some(old) = old else {
                    return Ok((true, seq > reset));
                };
                if seq <= reset {
                    return Ok((true, false));
                }
                if old.skeleton.seq <= reset {
                    return Ok((true, true));
                }
                Ok((
                    true,
                    !matches!(
                        crate::governance::entry::GovEntry::body_bound_to(&old)?,
                        GovBody::ConsentGrant(old) if old.body == c.body
                    ),
                ))
            }
            // A grant for another epoch has no current or historical effect in this index.
            GovBody::ConsentGrant(_) => Ok((false, false)),
            GovBody::ConsentRevocation(c) => {
                let key = frontier(author, &c.body.target_id);
                let ever = self.current_entry(Table::EverRevoked, &key)?;
                let current = self.current_entry(Table::Consent, &key)?;
                let fallback = current.as_ref().or(ever.as_ref());
                let replaces = self.current_head(author, body, fallback)? < seq;
                let ever_changes = ever.is_none();
                if c.body.epoch != 0 {
                    return Ok((replaces || ever_changes, false));
                }
                let already_current = current
                    .as_ref()
                    .filter(|old| old.skeleton.seq < seq)
                    .map(crate::governance::entry::GovEntry::body_bound_to)
                    .transpose()?
                    .is_some_and(|old| matches!(old, GovBody::ConsentRevocation(_)));
                Ok((replaces || ever_changes, replaces && !already_current))
            }
            GovBody::Presence(_) => {
                let author_key = hash_key(author);
                let old = self.current_entry(Table::Presence, &author_key)?;
                if self.current_head(author, body, old.as_ref())? >= seq {
                    return Ok((false, false));
                }
                let Some(_old) = old else {
                    return Ok((true, true));
                };
                // Even an identical newer `here` statement can reset consent facts after rows
                // between the two positions, so every current replacement is semantic.
                Ok((true, true))
            }
            GovBody::ServiceShare(s) => {
                let name = crate::hash::sha256(s.body.name.as_bytes());
                let key = frontier(author, &name);
                let old = self.current_entry(Table::Shares, &key)?;
                if self.current_head(author, body, old.as_ref())? >= seq {
                    return Ok((false, false));
                }
                let Some(old) = old else {
                    return Ok((true, true));
                };
                Ok((
                    true,
                    !matches!(
                        crate::governance::entry::GovEntry::body_bound_to(&old)?,
                        GovBody::ServiceShare(old) if old.body == s.body
                    ),
                ))
            }
            _ => Ok((false, false)),
        }
    }

    pub(super) fn current_input_kind(body: &crate::governance::entry::GovBody) -> bool {
        use crate::governance::entry::GovBody;
        matches!(
            body,
            GovBody::ConsentGrant(_)
                | GovBody::ConsentRevocation(_)
                | GovBody::Presence(_)
                | GovBody::ServiceShare(_)
        )
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
        changes_projection: bool,
    ) -> Result<()> {
        use crate::governance::entry::GovBody;
        let head =
            Self::current_head_key(author, body).ok_or(invalid("governance current head kind"))?;
        self.latest(Table::CurrentHeads, head, seq, log)?;
        match body {
            // The durable slot carries causal sequence as well as displayed value. A repeated
            // equal grant must advance it even though it does not revise the projection: a reset
            // that arrives later but lies between the two grants must not revoke the newer one.
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
            GovBody::Presence(p) if changes_projection => {
                self.latest(Table::Presence, hash_key(author), seq, log)?;
                if p.body.here {
                    self.latest(Table::Back, hash_key(author), seq, log)?;
                    if p.body.epoch == 0 {
                        self.latest(Table::ConsentReset, hash_key(author), seq, log)?;
                    }
                }
            }
            GovBody::ServiceShare(s) if changes_projection => {
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

    pub(super) fn projection(&self) -> Digest32 {
        self.header.projection
    }

    /// Publish one completed canonical output. Intermediate clear/rebuild steps never revise the
    /// user-visible projection, and an authorized replay with identical meaning is a no-op.
    pub(super) fn projection_published(&mut self, projection: Digest32) -> Result<()> {
        if self.header.projection != projection {
            self.header.projection = projection;
            self.display_changed()?;
        }
        Ok(())
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

    /// A pending row's source id and hash, for the in-place migration of a format-3 index: the
    /// rows after `after` in the work queue, in order.
    pub(super) fn pending_after(
        &self,
        after: Option<session_tree::Key>,
    ) -> Result<Option<(session_tree::Key, u64, Digest32)>> {
        let Some((key, _)) = self.first(Table::PendingOrder, after)? else {
            return Ok(None);
        };
        let hash: Digest32 = key[8..40]
            .try_into()
            .map_err(|_| invalid("governance pending entry"))?;
        Ok(Some((key, pending_log(&key), hash)))
    }

    /// Put an already queued row on the control settlement queue too (the migration of a
    /// format-3 index, whose queue predates that table), with the serial the work queue holds.
    pub(super) fn mark_control_pending(&mut self, key: session_tree::Key) -> Result<()> {
        let serial = self
            .get(Table::PendingOrder, &key)?
            .ok_or(invalid("governance pending row missing"))?;
        self.put(Table::ControlPending, key, Some(serial))
    }

    /// The source row at `log` as the log holds it, for classification only: its hash binding
    /// is checked, its governance binding is not (a content row has none).
    pub(super) fn source_entry(&self, log: u64) -> Result<crate::log::entry::Entry> {
        let sealed = self
            .batch
            .get_segment(self.room, SegmentKind::LogDb, log)?
            .ok_or(invalid("governance source entry missing"))?;
        let bytes = open_segment(self.sek, SegmentKind::LogDb, log, &sealed)?;
        let entry = crate::log::entry::Entry::from_wire(&bytes)?;
        if entry.skeleton.channel_id != *self.room {
            return Err(invalid("governance source binding"));
        }
        Ok(entry)
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
            let source = self.entry(log)?;
            let body = crate::governance::entry::GovEntry::body_bound_to(&source)?;
            // Single-writer current facts never participate in canonical-history ordering.
            // Their latest register was published at acceptance, and a newly discovered older
            // frontier cannot make that fact current or revise what a person sees.
            if !Self::current_input_kind(&body) {
                self.changed()?;
                self.put(Table::Dirty, hash_key(entry), Some(log))?;
                if self
                    .get(Table::AuthorityHashes, &hash_key(entry))?
                    .is_some()
                {
                    self.authority_changed()?;
                }
            }
        }
        Ok(true)
    }

    pub(super) fn seal(self) -> Result<()> {
        let sealed = seal_segment(self.sek, KIND, HEADER, &self.header.bytes())?;
        self.batch.put_segment(self.room, KIND, HEADER, &sealed)
    }
}
