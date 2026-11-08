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
pub(super) const FORK_LOCATOR: u64 = 1 << 63;
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
    /// Authenticated member-removal source locators, keyed by target and entry hash.
    MemberRemovals,
    /// Authenticated readmission source locators, keyed by target and entry hash.
    MemberReadmissions,
    /// Generation-stamped checked member-fact decisions.
    MemberDecisions,
    /// Current effective removals, keyed by target, stamped with their fold generation.
    CurrentRemoved,
    /// Earliest proven divergence (or the conservative unknown-prefix boundary) per author.
    ForkBoundary,
    /// Authenticated, non-LogDb exclusion evidence from the other fork branch.
    ForkExclusions,
    /// Exact authenticated hash for each causal frontier coordinate.
    FrontierHashes,
    /// Creator revocations carried on authenticated alternate branches.
    ForkRevocations,
    /// Accepted source locators, including non-governance entries.
    SourceHashes,
    SourcePositions,
    /// Exact-entry projection work and published generation-stamped decisions.
    EligibilityPending,
    EligibilityDecisions,
    /// FIFO by source locator, independent of entry hash distribution.
    EligibilityOrder,
    /// Missing or unvalidated ancestry; such sources confer no authority.
    Incomplete,
    /// Reverse dependencies from an exact parent hash to a retained fork fact.
    #[allow(dead_code)] // Reserved sealed root slot; removing it would shift later roots.
    ForkDependencies,
    /// G-31 eligibility of a signed Session floor for its named recipient.
    FloorRecipientDecisions,
    /// Local sender position when an exact verified removal was first applied.
    SenderRemovalCuts,
    /// Every verified sender Presence, keyed by author and signed sequence.
    SenderPresence,
    /// Generation-stamped history-body cut for each once-removed target: the latest, across
    /// its validated removals, of each removal's earliest covering creator readmission. One
    /// extra room row (nonzero key tail) keeps the latest such cut for local authoring.
    RecipientCuts,
}

const TABLES: usize = Table::RecipientCuts as usize + 1;

#[derive(Clone, Copy)]
pub(super) enum Cursor {
    Canonical,
    Evaluation,
    Membership,
    ForkReplay,
    ForkEvidence,
    Eligibility,
    EligibilityReplay,
}
const CURSORS: usize = Cursor::EligibilityReplay as usize + 1;
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
            && !(version == HEADER_VERSION && (41..TABLES).contains(&stored))
            && !(version == HEADER_VERSION_WITH_CONTROL_QUEUE && stored == 40)
            && !(version == HEADER_VERSION_BEFORE_CONTROL_QUEUE && stored == 39)
        {
            return Err(invalid("governance root count"));
        }
        let mut roots = [0; TABLES];
        for root in roots.iter_mut().take(stored) {
            *root = d.uint()?;
        }
        let stored_cursors = d.array()?;
        if !(2..=CURSORS).contains(&stored_cursors) {
            return Err(invalid("governance cursor count"));
        }
        let mut cursors = [0; CURSORS];
        for cursor in cursors.iter_mut().take(stored_cursors) {
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
        // A header sealed before RecipientCuts existed may hold a finished membership fold that
        // never wrote those rows. Only a room with an indexed removal can need one: begin a new
        // authority generation there, exactly as an expiry does, so every stamped row reads
        // Refreshing until the existing driver refolds and stamps it.
        let authority_generation = if initialized
            && stored <= Table::RecipientCuts as usize
            && roots[Table::MemberRemovals as usize] != 0
        {
            authority_generation
                .checked_add(1)
                .ok_or(invalid("governance authority generation exhausted"))?
        } else {
            authority_generation
        };
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

/// Check the published fold barrier, not physical LogDb staging. A local append's
/// sealed promotion is already in LogDb before its source receipt and effects publish.
pub(super) fn settled_in(batch: &Batch<'_>, sek: &Sek, room: &Digest32) -> Result<bool> {
    let Some(sealed) = batch.get_segment(room, KIND, HEADER)? else {
        return Ok(false);
    };
    let header = Header::parse(&open_segment(sek, KIND, HEADER, &sealed)?)?;
    Ok(header.initialized
        && header.cursors[Cursor::ForkReplay as usize] == 0
        && header.cursors[Cursor::ForkEvidence as usize] == 0
        && header.order_ready
        && header.evaluated == header.ordered
        && header.authority_folded == header.authority_generation
        && header.head_generation == header.authority_generation)
}

enum ReadSnapshot<'a> {
    Owned(Snapshot),
    Borrowed(&'a Snapshot),
    Batch(&'a Batch<'a>),
}

impl ReadSnapshot<'_> {
    fn get_segment(
        &self,
        room: &Digest32,
        kind: SegmentKind,
        id: u64,
    ) -> Result<Option<crate::atrest::store::SealedSegment>> {
        match self {
            Self::Owned(snapshot) => snapshot.get_segment(room, kind, id),
            Self::Borrowed(snapshot) => snapshot.get_segment(room, kind, id),
            Self::Batch(batch) => batch.get_segment(room, kind, id),
        }
    }

    fn segment_id_after(
        &self,
        room: &Digest32,
        kind: SegmentKind,
        after: Option<u64>,
    ) -> Result<Option<u64>> {
        match self {
            Self::Owned(snapshot) => snapshot.segment_id_after(room, kind, after),
            Self::Borrowed(snapshot) => snapshot.segment_id_after(room, kind, after),
            Self::Batch(batch) => batch.segment_id_after(room, kind, after),
        }
    }
}

pub(super) struct Read<'a> {
    input: ReadSnapshot<'a>,
    sek: &'a Sek,
    room: &'a Digest32,
    header: Header,
}

impl<'a> Read<'a> {
    pub(super) fn open(store: &Store, sek: &'a Sek, room: &'a Digest32) -> Result<Self> {
        Self::open_existing(store, sek, room)?.ok_or(invalid("governance header missing"))
    }
    pub(super) fn from_snapshot(
        input: &'a Snapshot,
        sek: &'a Sek,
        room: &'a Digest32,
    ) -> Result<Self> {
        let header = input
            .get_segment(room, KIND, HEADER)?
            .map(|sealed| Header::parse(&open_segment(sek, KIND, HEADER, &sealed)?))
            .transpose()?
            .ok_or(invalid("governance header missing"))?;
        Ok(Self {
            input: ReadSnapshot::Borrowed(input),
            sek,
            room,
            header,
        })
    }
    pub(super) fn from_batch(
        input: &'a Batch<'a>,
        sek: &'a Sek,
        room: &'a Digest32,
    ) -> Result<Self> {
        Self::from_batch_existing(input, sek, room)?.ok_or(invalid("governance header missing"))
    }
    /// A room with no derived header has indexed no removal yet; callers decide that case.
    pub(super) fn open_existing(
        store: &Store,
        sek: &'a Sek,
        room: &'a Digest32,
    ) -> Result<Option<Self>> {
        let input = store.snapshot()?;
        let Some(sealed) = input.get_segment(room, KIND, HEADER)? else {
            return Ok(None);
        };
        let header = Header::parse(&open_segment(sek, KIND, HEADER, &sealed)?)?;
        Ok(Some(Self {
            input: ReadSnapshot::Owned(input),
            sek,
            room,
            header,
        }))
    }
    pub(super) fn from_batch_existing(
        input: &'a Batch<'a>,
        sek: &'a Sek,
        room: &'a Digest32,
    ) -> Result<Option<Self>> {
        let Some(sealed) = input.get_segment(room, KIND, HEADER)? else {
            return Ok(None);
        };
        let header = Header::parse(&open_segment(sek, KIND, HEADER, &sealed)?)?;
        Ok(Some(Self {
            input: ReadSnapshot::Batch(input),
            sek,
            room,
            header,
        }))
    }
    fn tree(&self) -> session_tree::Read<'_> {
        match &self.input {
            ReadSnapshot::Owned(snapshot) => {
                session_tree::Read::snapshot(snapshot, self.sek, self.room, KIND)
            }
            ReadSnapshot::Borrowed(snapshot) => {
                session_tree::Read::snapshot(snapshot, self.sek, self.room, KIND)
            }
            ReadSnapshot::Batch(batch) => {
                session_tree::Read::batch(batch, self.sek, self.room, KIND)
            }
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
        if log & FORK_LOCATOR != 0 {
            let id = log & !FORK_LOCATOR;
            let sealed = self
                .input
                .get_segment(self.room, KIND, id)?
                .ok_or(invalid("fork exclusion missing"))?;
            let bytes = open_segment(self.sek, KIND, id, &sealed)?;
            let mut d = Decoder::new(&bytes);
            if d.array()? != 4 || d.uint()? != 2 {
                return Err(invalid("fork exclusion format"));
            }
            let entry = crate::log::entry::Entry::from_wire(d.bytes()?)?;
            match d.array()? {
                0 => {}
                1 => {
                    let _ = d.bytes()?;
                }
                _ => return Err(invalid("fork exclusion context")),
            }
            match d.array()? {
                0 => {}
                1 => {
                    let _ = d.bytes()?;
                }
                _ => return Err(invalid("fork exclusion receipt")),
            }
            d.finish()?;
            if entry.skeleton.channel_id != *self.room
                || self.get(Table::ForkExclusions, &hash_key(&entry.entry_hash()))? != Some(id)
            {
                return Err(invalid("fork exclusion binding"));
            }
            return Ok(entry);
        }
        let sealed = self
            .input
            .get_segment(self.room, SegmentKind::LogDb, log)?
            .ok_or(invalid("governance source entry missing"))?;
        let bytes = open_segment(self.sek, SegmentKind::LogDb, log, &sealed)?;
        let entry = crate::log::entry::Entry::from_wire(&bytes)?;
        if entry.skeleton.channel_id != *self.room
            || (self.locator(&entry.entry_hash())? != Some(log)
                && self.get(Table::SourceHashes, &hash_key(&entry.entry_hash()))? != Some(log))
        {
            return Err(invalid("governance source binding"));
        }
        Ok(entry)
    }
    /// Strict ancestry on one pinned verified projection. `None` is missing
    /// branch evidence, never permission to treat a fork as a linear feed.
    /// Only the ancestor's exact signed identity (author, position, hash) is used.
    pub(super) fn causal_contains(
        &self,
        scope: &Digest32,
        ancestor: &crate::log::history::EntryReference,
    ) -> Result<Option<bool>> {
        if *scope == ancestor.hash {
            return Ok(Some(false));
        }
        if self.get(Table::Complete, &hash_key(scope))?.is_none()
            || self.get(Table::Incomplete, &hash_key(scope))?.is_some()
            || self.get(Table::Pending, &hash_key(scope))?.is_some()
        {
            return Ok(None);
        }
        let author = &ancestor.author;
        let key = frontier(scope, author);
        let reached = self.get(Table::Frontiers, &key)?.unwrap_or(0);
        if reached < ancestor.seq {
            return Ok(Some(false));
        }
        let Some(boundary) = self.get(Table::ForkBoundary, &hash_key(author))? else {
            return Ok(Some(true));
        };
        let Some(record) = self.get(Table::FrontierHashes, &key)? else {
            return Ok(None);
        };
        let bytes = self.record(record)?;
        let head: Digest32 = bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid("frontier hash"))?;
        if reached == ancestor.seq {
            return Ok(Some(head == ancestor.hash));
        }
        if reached == boundary && ancestor.seq < boundary {
            if let Some(id) = self.get(Table::ForkExclusions, &hash_key(&head))? {
                let branch = self.entry(id | FORK_LOCATOR)?;
                if branch.skeleton.author_id == *author && branch.skeleton.seq == boundary {
                    let Some(log) =
                        self.get(Table::SourcePositions, &position(author, ancestor.seq))?
                    else {
                        return Ok(None);
                    };
                    return Ok(Some(self.entry(log)?.entry_hash() == ancestor.hash));
                }
            }
        }
        let Some(head_log) = self.get(Table::SourcePositions, &position(author, reached))? else {
            return Ok(None);
        };
        if self.entry(head_log)?.entry_hash() != head {
            return Ok(None);
        }
        let Some(log) = self.get(Table::SourcePositions, &position(author, ancestor.seq))? else {
            return Ok(None);
        };
        Ok(Some(self.entry(log)?.entry_hash() == ancestor.hash))
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
            || self.header.roots[Table::EligibilityPending as usize] != 0
            || self.header.cursors[Cursor::EligibilityReplay as usize] != 0
            || self.header.cursors[Cursor::Eligibility as usize] != 0
            || !self.header.initialized
            || !self.settled()
    }

    pub(super) fn settled(&self) -> bool {
        self.header.initialized
            && self.header.cursors[Cursor::ForkReplay as usize] == 0
            && self.header.cursors[Cursor::ForkEvidence as usize] == 0
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

    /// Fence in-flight room egress in the same transaction that publishes a changed
    /// validated membership projection.
    pub(super) fn advance_removal_generation(&mut self) -> Result<u64> {
        let key = super::removal_generation_key(self.room);
        self.batch.update_meta(&key, |old| {
            let generation = match old {
                None => 0,
                Some(bytes) => u64::from_be_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| invalid("room removal generation length"))?,
                ),
            };
            let next = generation
                .checked_add(1)
                .ok_or(invalid("room removal generation exhausted"))?;
            Ok((next.to_be_bytes().to_vec(), next))
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

    /// Record the exact applied removal and the local sender position in the
    /// same durable batch. This is an observation boundary, not a claim that an
    /// off-line peer learned the removal at that position.
    pub(super) fn record_sender_cut(&mut self, hash: &Digest32, target: &Digest32) -> Result<()> {
        let key = hash_key(hash);
        if self.get(Table::SenderRemovalCuts, &key)?.is_some() {
            return Ok(());
        }
        let Some(segment) = self.batch.get_segment(
            self.room,
            SegmentKind::KeyMaterial,
            super::super::SEG_SENDER,
        )?
        else {
            return Err(invalid("removal sender boundary unavailable"));
        };
        let bytes = open_segment(
            self.sek,
            SegmentKind::KeyMaterial,
            super::super::SEG_SENDER,
            &segment,
        )?;
        let sender = crate::group::state::SenderChain::from_state(&bytes)?;
        let entitlement = self
            .batch
            .get_segment(
                self.room,
                SegmentKind::KeyMaterial,
                super::super::SEG_ENTITLED,
            )?
            .map(|segment| {
                let bytes = open_segment(
                    self.sek,
                    SegmentKind::KeyMaterial,
                    super::super::SEG_ENTITLED,
                    &segment,
                )?;
                Ok::<_, Error>(super::super::parse_positions(&bytes)?.get(target).copied())
            })
            .transpose()?
            .flatten();
        let mut e = Encoder::new();
        e.array(6)
            .uint(2)
            .bytes(target)
            .bytes(&sender.author_id())
            .uint(sender.chain_id())
            .uint(sender.next_iteration());
        match entitlement {
            Some((chain, iteration)) => {
                e.array(2).uint(chain).uint(iteration);
            }
            None => {
                e.array(0);
            }
        }
        let record = self.save_record(None, &e.finish())?;
        self.put(Table::SenderRemovalCuts, key, Some(record))?;
        self.batch.ruled();
        Ok(())
    }

    /// Retain one authenticated alternate fork body without inserting it into
    /// accepted log positions. The proof itself remains in SEG_FORKS.
    pub(super) fn retain_fork_exclusion(
        &mut self,
        entry: &crate::log::entry::Entry,
        context: Option<&crate::log::history::ControlContext>,
        receipt: Option<&[u8]>,
    ) -> Result<bool> {
        if context.is_some() != receipt.is_some() {
            return Err(invalid("fork provenance pairing"));
        }
        let hash = entry.entry_hash();
        let key = hash_key(&hash);
        let old = self.get(Table::ForkExclusions, &key)?;
        if let Some(id) = old {
            let (_, held_context) = self.fork_exclusion(id)?;
            if held_context.is_some() || context.is_none() {
                return Ok(false);
            }
        }
        let id = match old {
            Some(id) => id,
            None => {
                let id = self.header.next;
                self.header.next = id
                    .checked_add(1)
                    .ok_or(invalid("governance allocator exhausted"))?;
                id
            }
        };
        let mut encoded = Encoder::new();
        encoded.array(4).uint(2).bytes(&entry.to_wire());
        match context {
            Some(context) => {
                encoded.array(1).bytes(&context.to_wire()?);
            }
            None => {
                encoded.array(0);
            }
        }
        match receipt {
            Some(receipt) => {
                encoded.array(1).bytes(receipt);
            }
            None => {
                encoded.array(0);
            }
        }
        self.batch.put_segment(
            self.room,
            KIND,
            id,
            &seal_segment(self.sek, KIND, id, &encoded.finish())?,
        )?;
        self.put(Table::ForkExclusions, key, Some(id))?;
        Ok(true)
    }

    pub(super) fn fork_exclusion(
        &self,
        id: u64,
    ) -> Result<(
        crate::log::entry::Entry,
        Option<crate::log::history::ControlContext>,
    )> {
        if id == 0 || id >= self.header.next {
            return Err(invalid("fork exclusion locator"));
        }
        let sealed = self
            .batch
            .get_segment(self.room, KIND, id)?
            .ok_or(invalid("fork exclusion missing"))?;
        let bytes = open_segment(self.sek, KIND, id, &sealed)?;
        let mut d = Decoder::new(&bytes);
        if d.array()? != 4 || d.uint()? != 2 {
            return Err(invalid("fork exclusion format"));
        }
        let entry = crate::log::entry::Entry::from_wire(d.bytes()?)?;
        let context = match d.array()? {
            0 => None,
            1 => Some(crate::log::history::ControlContext::from_wire(d.bytes()?)?),
            _ => return Err(invalid("fork exclusion context")),
        };
        let receipt = match d.array()? {
            0 => None,
            1 => Some(crate::log::history::IncludedHeader::from_authenticated_receipt(d.bytes()?)?),
            _ => return Err(invalid("fork exclusion receipt")),
        };
        if context.is_some() != receipt.is_some()
            || receipt
                .as_ref()
                .is_some_and(|proof| proof.header().entry().entry_hash() != entry.entry_hash())
        {
            return Err(invalid("fork exclusion provenance binding"));
        }
        d.finish()?;
        if entry.skeleton.channel_id != *self.room
            || self.get(Table::ForkExclusions, &hash_key(&entry.entry_hash()))? != Some(id)
        {
            return Err(invalid("fork exclusion binding"));
        }
        Ok((entry, context))
    }

    /// Resolve an authenticated source or a proof-backed branch with a complete
    /// causal context, without inserting the branch into accepted positions.
    pub(super) fn evidence_locator(&self, hash: &Digest32) -> Result<Option<u64>> {
        if let Some(log) = self.get(Table::SourceHashes, &hash_key(hash))? {
            return Ok(Some(log));
        }
        if self.get(Table::Complete, &hash_key(hash))?.is_none() {
            return Ok(None);
        }
        let Some(id) = self.get(Table::ForkExclusions, &hash_key(hash))? else {
            return Ok(None);
        };
        if id & FORK_LOCATOR != 0 {
            return Err(invalid("fork exclusion locator overflow"));
        }
        Ok(Some(id | FORK_LOCATOR))
    }

    pub(super) fn reached(&self, entry: &Digest32, author: &Digest32) -> Result<u64> {
        if !self.causal_settled()? || self.get(Table::Complete, &hash_key(entry))?.is_none() {
            return Err(invalid("governance causal facts not settled"));
        }
        Ok(self
            .get(Table::Frontiers, &frontier(entry, author))?
            .unwrap_or(0))
    }

    /// A sequence comparison is sufficient only before equivocation. Once a
    /// fork is known, the signed coordinate's exact hash must bind the branch.
    pub(super) fn causal_contains(
        &self,
        scope: &Digest32,
        ancestor: &crate::log::entry::Entry,
    ) -> Result<bool> {
        let ancestor_hash = ancestor.entry_hash();
        if *scope == ancestor_hash {
            return Ok(false);
        }
        let author = &ancestor.skeleton.author_id;
        let reached = self.reached(scope, author)?;
        if reached < ancestor.skeleton.seq {
            return Ok(false);
        }
        let Some(boundary) = self.get(Table::ForkBoundary, &hash_key(author))? else {
            return Ok(true);
        };
        let Some(head) = self.frontier_identity(scope, author)? else {
            return Ok(false);
        };
        if reached == ancestor.skeleton.seq {
            return Ok(head == ancestor_hash);
        }
        if reached == boundary && ancestor.skeleton.seq < boundary {
            if let Some(id) = self.get(Table::ForkExclusions, &hash_key(&head))? {
                let (branch, _) = self.fork_exclusion(id)?;
                if branch.skeleton.author_id == *author && branch.skeleton.seq == boundary {
                    let Some(log) = self.get(
                        Table::SourcePositions,
                        &position(author, ancestor.skeleton.seq),
                    )?
                    else {
                        return Ok(false);
                    };
                    return Ok(self.entry(log)?.entry_hash() == ancestor_hash);
                }
            }
        }
        // A canonical accepted feed supplies a verified hash-linked prefix. Do
        // not infer ancestry through a different or unavailable branch head.
        let Some(head_log) = self.get(Table::SourcePositions, &position(author, reached))? else {
            return Ok(false);
        };
        if self.entry(head_log)?.entry_hash() != head {
            return Ok(false);
        }
        let Some(ancestor_log) = self.get(
            Table::SourcePositions,
            &position(author, ancestor.skeleton.seq),
        )?
        else {
            return Ok(false);
        };
        Ok(self.entry(ancestor_log)?.entry_hash() == ancestor_hash)
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

    pub(super) fn clear_cursor(&mut self, cursor: Cursor) -> Result<()> {
        let id = self.header.cursors[cursor as usize];
        if id != 0 {
            self.delete_record(id)?;
            self.header.cursors[cursor as usize] = 0;
        }
        Ok(())
    }

    pub(super) fn start_eligibility_replay(&mut self) -> Result<()> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(1)
            .uint(self.authority_generation())
            .uint(0)
            .uint(self.header.known_tail);
        self.save_cursor(Cursor::EligibilityReplay, &e.finish())
    }

    pub(super) fn eligibility_replay_step(
        &mut self,
        input: &super::super::entry_store::Read<'_>,
    ) -> Result<bool> {
        use crate::log::entry::EntryRead;
        let Some(bytes) = self.cursor(Cursor::EligibilityReplay)? else {
            return Ok(false);
        };
        let mut d = Decoder::new(&bytes);
        if d.array()? != 4 || d.uint()? != 1 {
            return Err(invalid("eligibility replay cursor"));
        }
        let generation = d.uint()?;
        let after = d.uint()?;
        let tail = d.uint()?;
        d.finish()?;
        if generation != self.authority_generation() {
            self.clear_cursor(Cursor::EligibilityReplay)?;
            return Ok(true);
        }
        let Some(log) = self
            .batch
            .segment_id_after(self.room, SegmentKind::LogDb, Some(after))?
        else {
            self.clear_cursor(Cursor::EligibilityReplay)?;
            return Ok(true);
        };
        if log > tail {
            self.clear_cursor(Cursor::EligibilityReplay)?;
            return Ok(true);
        }
        let entry = self.source_entry(log)?;
        let hash = entry.entry_hash();
        if input.clock(&hash)?.is_some() {
            self.observe_source(log, &entry)?;
            if self.get(Table::Hashes, &hash_key(&hash))? == Some(log)
                && matches!(
                    crate::governance::entry::GovEntry::body_bound_to(&entry),
                    Ok(crate::governance::entry::GovBody::Presence(_))
                )
            {
                self.put(
                    Table::SenderPresence,
                    position(&entry.skeleton.author_id, entry.skeleton.seq),
                    Some(log),
                )?;
            }
            if self.get(Table::Complete, &hash_key(&hash))?.is_some()
                && self.get(Table::Pending, &hash_key(&hash))?.is_none()
            {
                self.queue_eligibility(&hash, log)?;
            } else if self.get(Table::Pending, &hash_key(&hash))?.is_none() {
                self.enqueue(&hash, log, super::is_control(&entry))?;
            }
        }
        let mut e = Encoder::new();
        e.array(4).uint(1).uint(generation).uint(log).uint(tail);
        self.save_cursor(Cursor::EligibilityReplay, &e.finish())?;
        Ok(true)
    }

    /// Reconstruct exact signed coordinate hashes after a newly proven fork.
    pub(super) fn start_fork_replay(&mut self) -> Result<()> {
        let mut e = Encoder::new();
        e.array(3).uint(1).uint(0).uint(self.header.known_tail);
        self.save_cursor(Cursor::ForkReplay, &e.finish())?;
        let mut e = Encoder::new();
        e.array(4).uint(1).array(0).array(0).uint(0);
        self.save_cursor(Cursor::ForkEvidence, &e.finish())
    }

    /// Inspect one retained source row; cursor and queue changes commit together.
    pub(super) fn fork_replay_step(
        &mut self,
        input: &super::super::entry_store::Read<'_>,
    ) -> Result<bool> {
        use crate::log::entry::EntryRead;
        let Some(bytes) = self.cursor(Cursor::ForkReplay)? else {
            return Ok(false);
        };
        let mut d = Decoder::new(&bytes);
        if d.array()? != 3 || d.uint()? != 1 {
            return Err(invalid("fork replay cursor"));
        }
        let after = d.uint()?;
        let tail = d.uint()?;
        d.finish()?;
        let Some(id) = self
            .batch
            .segment_id_after(self.room, SegmentKind::LogDb, Some(after))?
        else {
            let cursor = self.header.cursors[Cursor::ForkReplay as usize];
            self.delete_record(cursor)?;
            self.header.cursors[Cursor::ForkReplay as usize] = 0;
            return Ok(true);
        };
        if id > tail {
            self.clear_cursor(Cursor::ForkReplay)?;
            return Ok(true);
        }
        let entry = self.source_entry(id)?;
        let hash = entry.entry_hash();
        if input.clock(&hash)?.is_some() {
            self.observe_source(id, &entry)?;
            if self.get(Table::Pending, &hash_key(&hash))?.is_none() {
                self.enqueue(&hash, id, super::is_control(&entry))?;
            }
        }
        let mut e = Encoder::new();
        e.array(3).uint(1).uint(id).uint(tail);
        self.save_cursor(Cursor::ForkReplay, &e.finish())?;
        Ok(true)
    }

    /// Index one coordinate from a proof-backed sparse fork context. The
    /// context was obtained from ValidatedSparseEntry and sealed with the proof.
    pub(super) fn fork_evidence_step(&mut self) -> Result<bool> {
        let Some(bytes) = self.cursor(Cursor::ForkEvidence)? else {
            return Ok(false);
        };
        let mut d = Decoder::new(&bytes);
        if d.array()? != 4 || d.uint()? != 1 {
            return Err(invalid("fork evidence cursor"));
        }
        let mut after = read_hash(&mut d)?;
        let mut current = read_hash(&mut d)?;
        let mut at = d.uint()?;
        d.finish()?;
        if current.is_none() {
            let row = self.first(Table::ForkExclusions, after.map(|hash| hash_key(&hash)))?;
            let Some((key, _)) = row else {
                let cursor = self.header.cursors[Cursor::ForkEvidence as usize];
                self.delete_record(cursor)?;
                self.header.cursors[Cursor::ForkEvidence as usize] = 0;
                return Ok(true);
            };
            let hash: Digest32 = key[..32]
                .try_into()
                .map_err(|_| invalid("fork evidence hash"))?;
            if key[32..].iter().any(|byte| *byte != 0) {
                return Err(invalid("fork evidence key"));
            }
            current = Some(hash);
            at = 0;
        }
        let hash = current.ok_or(invalid("fork evidence cursor hash"))?;
        let id = self
            .get(Table::ForkExclusions, &hash_key(&hash))?
            .ok_or(invalid("fork evidence source missing"))?;
        let (entry, context) = self.fork_exclusion(id)?;
        if let Some(context) = context {
            let v2 = entry
                .skeleton
                .v2
                .as_ref()
                .ok_or(invalid("fork context without v2"))?;
            if context.hash() != v2.pre_context
                || context.room != *self.room
                || context.scope != v2.scope
            {
                return Err(invalid("fork context binding"));
            }
            let index = usize::try_from(at).map_err(|_| invalid("fork context cursor"))?;
            let coordinate = if index == 0 {
                Some((entry.skeleton.author_id, entry.skeleton.seq, hash))
            } else {
                context
                    .coordinates
                    .get(index - 1)
                    .map(|c| (c.author, c.seq, c.hash))
            };
            if let Some((author, seq, identity)) = coordinate {
                let key = frontier(&hash, &author);
                let held = self.get(Table::Frontiers, &key)?.unwrap_or(0);
                if seq > held {
                    self.put(Table::Frontiers, key, Some(seq))?;
                    let old = self.get(Table::FrontierHashes, &key)?;
                    let record = self.save_record(old, &identity)?;
                    self.put(Table::FrontierHashes, key, Some(record))?;
                }
                at = at
                    .checked_add(1)
                    .ok_or(invalid("fork context cursor overflow"))?;
            } else {
                if id & FORK_LOCATOR != 0 {
                    return Err(invalid("fork source locator overflow"));
                }
                self.put(Table::Complete, hash_key(&hash), Some(1))?;
                match crate::governance::entry::GovEntry::body_bound_to(&entry)? {
                    crate::governance::entry::GovBody::MemberRemoval(body) => {
                        self.put(
                            Table::MemberRemovals,
                            frontier(&body.target_id, &hash),
                            Some(id | FORK_LOCATOR),
                        )?;
                    }
                    crate::governance::entry::GovBody::AdminRevocation(_) => {
                        self.put(
                            Table::ForkRevocations,
                            hash_key(&hash),
                            Some(id | FORK_LOCATOR),
                        )?;
                    }
                    _ => return Err(invalid("fork exclusion kind")),
                }
                after = Some(hash);
                current = None;
                at = 0;
            }
        } else {
            // G-29: an alternate exclusion without proven strict-prefix issuer
            // authority is inert; it must not block the room or its named target.
            after = Some(hash);
            current = None;
            at = 0;
        }
        let mut e = Encoder::new();
        e.array(4).uint(1);
        write_hash(&mut e, after);
        write_hash(&mut e, current);
        e.uint(at);
        self.save_cursor(Cursor::ForkEvidence, &e.finish())?;
        Ok(true)
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
        if log & FORK_LOCATOR != 0 {
            return Ok(self.fork_exclusion(log & !FORK_LOCATOR)?.0);
        }
        let sealed = self
            .batch
            .get_segment(self.room, SegmentKind::LogDb, log)?
            .ok_or(invalid("governance source entry missing"))?;
        let bytes = open_segment(self.sek, SegmentKind::LogDb, log, &sealed)?;
        let entry = crate::log::entry::Entry::from_wire(&bytes)?;
        if entry.skeleton.channel_id != *self.room
            || (self.get(Table::Hashes, &hash_key(&entry.entry_hash()))? != Some(log)
                && self.get(Table::SourceHashes, &hash_key(&entry.entry_hash()))? != Some(log))
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

    /// Retain exact locators for all accepted source skeletons, including content.
    pub(super) fn observe_source(
        &mut self,
        log: u64,
        entry: &crate::log::entry::Entry,
    ) -> Result<()> {
        if log == 0 || log & FORK_LOCATOR != 0 || entry.skeleton.seq == 0 {
            return Err(invalid("source locator bounds"));
        }
        let hash = hash_key(&entry.entry_hash());
        let pos = position(&entry.skeleton.author_id, entry.skeleton.seq);
        if self
            .get(Table::SourceHashes, &hash)?
            .is_some_and(|old| old != log)
            || self
                .get(Table::SourcePositions, &pos)?
                .is_some_and(|old| old != log)
        {
            return Err(invalid("source locator conflict"));
        }
        self.put(Table::SourceHashes, hash, Some(log))?;
        self.put(Table::SourcePositions, pos, Some(log))
    }

    pub(super) fn needs_source_replay(&self) -> bool {
        self.header.known_tail != 0
            && self.header.roots[Table::SourceHashes as usize] == 0
            && self.header.cursors[Cursor::EligibilityReplay as usize] == 0
    }

    pub(super) fn queue_eligibility(&mut self, hash: &Digest32, log: u64) -> Result<()> {
        self.put(Table::EligibilityPending, hash_key(hash), Some(log))?;
        self.put(Table::EligibilityOrder, pending_key(log, hash), Some(log))
    }

    pub(super) fn finish_eligibility(&mut self, hash: &Digest32, log: u64) -> Result<()> {
        if self.get(Table::EligibilityPending, &hash_key(hash))? == Some(log) {
            self.put(Table::EligibilityPending, hash_key(hash), None)?;
            self.put(Table::EligibilityOrder, pending_key(log, hash), None)?;
        }
        Ok(())
    }

    pub(super) fn eligibility_replaying(&self) -> bool {
        self.header.cursors[Cursor::EligibilityReplay as usize] != 0
    }

    pub(super) fn set_incomplete(&mut self, hash: &Digest32, incomplete: bool) -> Result<bool> {
        let key = hash_key(hash);
        if self.get(Table::Incomplete, &key)?.is_some() == incomplete {
            return Ok(false);
        }
        self.put(Table::Incomplete, key, incomplete.then_some(1))?;
        if let Some(log) = self.get(Table::Hashes, &key)? {
            let body = crate::governance::entry::GovEntry::body_bound_to(&self.entry(log)?)?;
            if !Self::current_input_kind(&body) {
                self.changed()?;
                self.put(Table::Dirty, key, Some(log))?;
            }
            if self.get(Table::AuthorityHashes, &key)?.is_some()
                || matches!(body, crate::governance::entry::GovBody::Presence(_))
            {
                self.authority_changed()?;
            }
        }
        Ok(true)
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
            && self.header.cursors[Cursor::ForkReplay as usize] == 0
            && self.header.cursors[Cursor::ForkEvidence as usize] == 0
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
            GovBody::MemberRemoval(removal) => {
                self.put(
                    Table::MemberRemovals,
                    frontier(&removal.target_id, hash),
                    Some(log),
                )?;
            }
            GovBody::MemberReadmission(readmission) => {
                self.put(
                    Table::MemberReadmissions,
                    frontier(&readmission.target_id, hash),
                    Some(log),
                )?;
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
    /// Only the verified common author-chain prefix retains non-exclusion authority.
    pub(super) fn fork_safe(&self, entry: &crate::log::entry::Entry) -> Result<bool> {
        Ok(self
            .get(Table::ForkBoundary, &hash_key(&entry.skeleton.author_id))?
            .is_none_or(|boundary| entry.skeleton.seq < boundary))
    }

    /// A mismatched predecessor proves no shared prefix. A branch at sequence
    /// one needs none; all other such branches lack enough own-history evidence.
    pub(super) fn fork_prefix_available(&self, entry: &crate::log::entry::Entry) -> Result<bool> {
        Ok(self
            .get(Table::ForkBoundary, &hash_key(&entry.skeleton.author_id))?
            .is_none_or(|boundary| boundary != 1 || entry.skeleton.seq == 1))
    }

    pub(super) fn authority_generation(&self) -> u64 {
        self.header.authority_generation
    }
    pub(super) fn authority_folded(&self) -> u64 {
        self.header.authority_folded
    }
    pub(super) fn authority_deadline(&self) -> u64 {
        self.header.authority_deadline
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

    /// Record the actual derived output before rebuilding a legacy fold.
    pub(super) fn rebaseline_projection(&mut self, projection: Digest32) -> Result<()> {
        self.header.projection = projection;
        Ok(())
    }

    /// Publish one completed canonical output. Intermediate clear/rebuild steps never revise the
    /// user-visible projection, and an authorized replay with identical meaning is a no-op.
    pub(super) fn projection_published(&mut self, projection: Digest32, force: bool) -> Result<()> {
        if force || self.header.projection != projection {
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

    pub(super) fn display_changed(&mut self) -> Result<()> {
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
        let log = work.log;
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
            self.queue_eligibility(&entry, log)?;
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

    pub(super) fn frontier_identity(
        &self,
        entry: &Digest32,
        author: &Digest32,
    ) -> Result<Option<Digest32>> {
        let Some(record) = self.get(Table::FrontierHashes, &frontier(entry, author))? else {
            return Ok(None);
        };
        let bytes = self.record(record)?;
        if bytes.is_empty() || bytes.as_slice() == [0] {
            return Ok(None);
        }
        Ok(Some(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| invalid("frontier identity"))?,
        ))
    }

    pub(super) fn raise(
        &mut self,
        entry: &Digest32,
        author: &Digest32,
        seq: u64,
        identity: Option<Digest32>,
    ) -> Result<bool> {
        if self.header.work.entry != Some(*entry) {
            return Err(invalid("governance frontier outside its work"));
        }
        let key = frontier(entry, author);
        let held = self
            .tree()
            .find(self.header.roots[Table::Frontiers as usize], &key)?
            .unwrap_or(0);
        if seq < held {
            return Ok(false);
        }
        let old = self.get(Table::FrontierHashes, &key)?;
        let prior = old.map(|id| self.record(id)).transpose()?;
        let next: &[u8] = if seq > held {
            identity.as_ref().map_or(&[], |hash| hash.as_slice())
        } else {
            match (
                prior.as_ref().map(|value| value.as_slice()),
                identity.as_ref(),
            ) {
                (Some([0]), _) => return Ok(false),
                (Some(bytes), Some(hash)) if bytes.len() == 32 && bytes != hash => &[0],
                (Some(bytes), _) if bytes.len() == 32 => return Ok(false),
                (_, Some(hash)) => hash.as_slice(),
                _ => return Ok(false),
            }
        };
        let record = self.save_record(old, next)?;
        self.put(Table::FrontierHashes, key, Some(record))?;
        if seq > held {
            self.header.roots[Table::Frontiers as usize] =
                self.set_root(self.header.roots[Table::Frontiers as usize], key, Some(seq))?;
        }
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
