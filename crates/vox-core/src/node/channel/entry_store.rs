//! Bounded encrypted entry locators. LogDb remains the authoritative wire storage.
//!
//! Entry locators and DAG facts use immutable, SEK-sealed pages. Only page ids appear outside ciphertext;
//! authors, hashes, sequence numbers, separator keys and locations are all encrypted.
//! A reader pins one redb snapshot for the directory, every page and the final entry.
//! A writer reads its own Batch. Roots are installed only by its durable commit.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};

use zeroize::Zeroizing;

use crate::atrest::sek::Sek;
use crate::atrest::store::{open_segment, seal_segment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::entry::{Entry, EntryRead, EntryWrite};
use crate::node::store::{Batch, Snapshot, Store};

const PAGE_BYTES: usize = 16 * 1024;
const PAGE_ITEMS: usize = 128;
const CACHE_BYTES: usize = 4 * 1024 * 1024;
const CACHE_ITEMS: usize = 128;
/// Plaintext page-cache retention is shared across all rooms/nodes in this process. A full
/// pool skips cache admission; saved pages remain readable from the sealed store as usual.
const ALL_CACHE_BYTES: usize = 64 * 1024 * 1024;
static CACHE_USED: AtomicUsize = AtomicUsize::new(0);
const MAX_DEPTH: usize = 64;
const DIRECTORY: u64 = 0;
type Key = [u8; 64];

mod dag_facts;
mod missing_facts;
mod packages;
mod receipt_facts;
mod render_facts;
mod restart;
mod retention_facts;
pub(crate) use restart::RestartState;
pub(crate) mod session_tree;
pub use dag_facts::OrderView;
pub(crate) use render_facts::{Filter, RenderFact, RenderView};

fn flag(d: &mut Decoder<'_>) -> Result<bool> {
    match d.uint()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid("entry directory boolean")),
    }
}

fn invalid(why: &'static str) -> Error {
    Error::MalformedAtRest(why)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Locator {
    pub author: Digest32,
    pub seq: u64,
    pub log: u64,
}

impl Locator {
    fn write(self, e: &mut Encoder) {
        e.array(3).bytes(&self.author).uint(self.seq).uint(self.log);
    }
}

fn position(author: &Digest32, seq: u64) -> Key {
    let mut key = [0; 64];
    key[..32].copy_from_slice(author);
    key[32..40].copy_from_slice(&seq.to_be_bytes());
    key
}

fn hashed(hash: &Digest32) -> Key {
    let mut key = [0; 64];
    key[..32].copy_from_slice(hash);
    key
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Roots {
    sequence: u64,
    hash: u64,
    clock: u64,
    order: u64,
    children: u64,
    referenced: u64,
    rendered: render_facts::Roots,
    retained: retention_facts::Roots,
    read_receipts: u64,
    read_pairs: u64,
    missing_positions: u64,
    read_pending: u64,
    key_packages: u64,
    key_latest: u64,
    key_tip: u64,
}

impl Roots {
    fn write(self, e: &mut Encoder) {
        e.array(15)
            .uint(self.sequence)
            .uint(self.hash)
            .uint(self.clock)
            .uint(self.order)
            .uint(self.children)
            .uint(self.referenced);
        self.rendered.write(e);
        self.retained.write(e);
        e.uint(self.read_receipts)
            .uint(self.read_pairs)
            .uint(self.missing_positions)
            .uint(self.read_pending)
            .uint(self.key_packages)
            .uint(self.key_latest)
            .uint(self.key_tip);
    }
    fn read(d: &mut Decoder<'_>) -> Result<Self> {
        let arity = d.array()?;
        if !matches!(arity, 12 | 15) {
            return Err(invalid("entry roots arity"));
        }
        Ok(Self {
            sequence: d.uint()?,
            hash: d.uint()?,
            clock: d.uint()?,
            order: d.uint()?,
            children: d.uint()?,
            referenced: d.uint()?,
            rendered: render_facts::Roots::read(d)?,
            retained: retention_facts::Roots::read(d)?,
            read_receipts: d.uint()?,
            read_pairs: d.uint()?,
            missing_positions: d.uint()?,
            read_pending: d.uint()?,
            key_packages: if arity >= 15 { d.uint()? } else { 0 },
            key_latest: if arity >= 15 { d.uint()? } else { 0 },
            key_tip: if arity >= 15 { d.uint()? } else { 0 },
        })
    }
}

/// Building roots are never readable history. Switched means the new active roots are
/// committed and only the old pages/spool may be reclaimed. The phase is never inferred
/// from whether a particular candidate row happens to exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Idle,
    Rebuilding,
    Building,
    Switched,
}

#[derive(Clone, Debug)]
struct Promotion {
    author: Digest32,
    from: u64,
    through: u64,
    base_hash: Digest32,
    received_ms: u64,
    witness: u64,
    witness_hash: Digest32,
    cursor: u64,
    work: Roots,
    first_log: u64,
    after_log: u64,
    first_page: u64,
    after_page: u64,
    retired: u64,
    bodyless_prefix: bool,
    reordered: u64,
    accepted: Option<crate::log::dag::PublishedFeed>,
}

#[derive(Clone, Debug)]
struct Directory {
    active: Roots,
    provisional: Roots,
    next_page: u64,
    next_provisional: u64,
    revision: u64,
    phase: Phase,
    promotion: Option<Promotion>,
    graph_ready: bool,
    origin: Option<u64>,
    order_revision: u64,
    work: dag_facts::Work,
    render_epoch: u64,
    render_ready: bool,
    render_cursor: Option<u64>,
    history_instance: [u8; 16],
    retention_stage: u8,
    retention_cursor: Option<u64>,
    read_sent_ms: u64,
    restart: Option<RestartState>,
    next_package: u64,
    packages_ready: bool,
    packages_cursor: Option<u64>,
}

impl Default for Directory {
    fn default() -> Self {
        Self {
            active: Roots::default(),
            provisional: Roots::default(),
            next_page: 1,
            next_provisional: 1,
            revision: 0,
            phase: Phase::Rebuilding,
            promotion: None,
            graph_ready: true,
            origin: None,
            order_revision: 0,
            work: dag_facts::Work::default(),
            render_epoch: 0,
            render_ready: false,
            render_cursor: None,
            history_instance: [0; 16],
            retention_stage: 0,
            retention_cursor: None,
            read_sent_ms: 0,
            restart: None,
            next_package: 1,
            packages_ready: false,
            packages_cursor: None,
        }
    }
}

impl Directory {
    fn ensure_instance(&mut self) -> Result<()> {
        if self.history_instance == [0; 16] {
            getrandom::fill(&mut self.history_instance).map_err(|_| Error::Rng)?;
            if self.history_instance == [0; 16] {
                return Err(Error::Rng);
            }
        }
        Ok(())
    }
    fn bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Encoder::new();
        e.array(23).uint(9);
        self.active.write(&mut e);
        self.provisional.write(&mut e);
        e.uint(self.next_page)
            .uint(self.next_provisional)
            .uint(self.revision)
            .uint(match self.phase {
                Phase::Idle => 0,
                Phase::Rebuilding => 1,
                Phase::Building => 2,
                Phase::Switched => 3,
            });
        match &self.promotion {
            None => {
                e.array(0);
            }
            Some(p) => {
                e.array(17)
                    .bytes(&p.author)
                    .uint(p.from)
                    .uint(p.through)
                    .bytes(&p.base_hash)
                    .uint(p.received_ms)
                    .uint(p.witness)
                    .bytes(&p.witness_hash)
                    .uint(p.cursor);
                p.work.write(&mut e);
                e.uint(p.first_log)
                    .uint(p.after_log)
                    .uint(p.first_page)
                    .uint(p.after_page)
                    .uint(p.retired)
                    .uint(u64::from(p.bodyless_prefix))
                    .uint(p.reordered);
                match &p.accepted {
                    Some(state) => {
                        e.array(1);
                        restart::write_feed(state, &mut e);
                    }
                    None => {
                        e.array(0);
                    }
                }
            }
        }
        e.uint(u64::from(self.graph_ready));
        match self.origin {
            Some(origin) => {
                e.array(1).uint(origin);
            }
            None => {
                e.array(0);
            }
        }
        e.uint(self.order_revision);
        self.work.write(&mut e);
        e.uint(self.render_epoch).uint(u64::from(self.render_ready));
        match self.render_cursor {
            Some(cursor) => {
                e.array(1).uint(cursor);
            }
            None => {
                e.array(0);
            }
        }
        e.bytes(&self.history_instance)
            .uint(u64::from(self.retention_stage));
        match self.retention_cursor {
            Some(id) => {
                e.array(1).uint(id);
            }
            None => {
                e.array(0);
            }
        }
        e.uint(self.read_sent_ms);
        match &self.restart {
            Some(state) => {
                e.array(1);
                state.write(&mut e);
            }
            None => {
                e.array(0);
            }
        }
        e.uint(self.next_package)
            .uint(u64::from(self.packages_ready));
        match self.packages_cursor {
            Some(cursor) => {
                e.array(1).uint(cursor);
            }
            None => {
                e.array(0);
            }
        }
        Zeroizing::new(e.finish())
    }
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 1024 * 1024 {
            return Err(invalid("entry directory exceeds bounded author state"));
        }
        let mut d = Decoder::new(bytes);
        let arity = d.array()?;
        let version = d.uint()?;
        // This unpublished format includes durable receipts, pending local read marks,
        // canonical operation members and retained conflict witnesses. Older partial roots
        // cannot be treated as empty without silently losing accepted work.
        if !matches!((arity, version), (19, 8) | (23, 9)) {
            return Err(invalid("entry directory format"));
        }
        let active = Roots::read(&mut d)?;
        let provisional = Roots::read(&mut d)?;
        let next_page = d.uint()?;
        let next_provisional = d.uint()?;
        let revision = d.uint()?;
        let phase = match d.uint()? {
            0 => Phase::Idle,
            1 => Phase::Rebuilding,
            2 => Phase::Building,
            3 => Phase::Switched,
            _ => return Err(invalid("entry directory phase")),
        };
        let promotion_arity = d.array()?;
        let promotion = match promotion_arity {
            0 => None,
            14 | 16 | 17 => Some(Promotion {
                author: d
                    .bytes()?
                    .try_into()
                    .map_err(|_| invalid("promotion author"))?,
                from: d.uint()?,
                through: d.uint()?,
                base_hash: d
                    .bytes()?
                    .try_into()
                    .map_err(|_| invalid("promotion base hash"))?,
                received_ms: d.uint()?,
                witness: d.uint()?,
                witness_hash: d
                    .bytes()?
                    .try_into()
                    .map_err(|_| invalid("promotion witness"))?,
                cursor: d.uint()?,
                work: Roots::read(&mut d)?,
                first_log: d.uint()?,
                after_log: d.uint()?,
                first_page: d.uint()?,
                after_page: d.uint()?,
                retired: d.uint()?,
                bodyless_prefix: if promotion_arity >= 16 {
                    flag(&mut d)?
                } else {
                    true
                },
                reordered: if promotion_arity >= 16 { d.uint()? } else { 0 },
                accepted: if promotion_arity >= 17 {
                    match d.array()? {
                        0 => None,
                        1 => Some(restart::read_feed(&mut d)?),
                        _ => return Err(invalid("promotion accepted state")),
                    }
                } else {
                    None
                },
            }),
            _ => return Err(invalid("promotion arity")),
        };
        let graph_ready = if version >= 2 { flag(&mut d)? } else { false };
        let origin = if version >= 2 {
            match d.array()? {
                0 => None,
                1 => Some(d.uint()?),
                _ => return Err(invalid("DAG origin arity")),
            }
        } else {
            None
        };
        let order_revision = if version >= 2 { d.uint()? } else { 0 };
        let work = if version >= 2 {
            dag_facts::Work::read(&mut d)?
        } else {
            dag_facts::Work::default()
        };
        let render_epoch = if version >= 3 { d.uint()? } else { 0 };
        let render_ready = version >= 3 && flag(&mut d)?;
        let render_cursor = if version >= 3 {
            match d.array()? {
                0 => None,
                1 => Some(d.uint()?),
                _ => return Err(invalid("render rebuild cursor")),
            }
        } else {
            None
        };
        let history_instance = if version >= 4 {
            let id: [u8; 16] = d
                .bytes()?
                .try_into()
                .map_err(|_| invalid("history instance"))?;
            if id == [0; 16] {
                return Err(invalid("empty history instance"));
            }
            id
        } else {
            [0; 16]
        };
        let retention_stage = if version >= 5 {
            u8::try_from(d.uint()?).map_err(|_| invalid("retention stage"))?
        } else {
            0
        };
        let retention_cursor = if version >= 5 {
            match d.array()? {
                0 => None,
                1 => Some(d.uint()?),
                _ => return Err(invalid("retention cursor")),
            }
        } else {
            None
        };
        let read_sent_ms = d.uint()?;
        let restart = if version >= 9 {
            match d.array()? {
                0 => None,
                1 => Some(RestartState::read(&mut d)?),
                _ => return Err(invalid("restart state option")),
            }
        } else {
            None
        };
        let next_package = if version >= 9 { d.uint()? } else { 1 };
        let packages_ready = version >= 9 && flag(&mut d)?;
        let packages_cursor = if version >= 9 {
            match d.array()? {
                0 => None,
                1 => Some(d.uint()?),
                _ => return Err(invalid("package catalog cursor")),
            }
        } else {
            None
        };
        d.finish()?;
        if next_package == 0
            || active.key_tip >= next_package
            || (packages_ready && packages_cursor.is_some())
            || retention_stage > 2
            || (retention_stage == 2 && retention_cursor.is_some())
            || next_page == 0
            || next_provisional == 0
            || [
                active.sequence,
                active.hash,
                active.clock,
                active.order,
                active.children,
                active.referenced,
                active.read_receipts,
                active.read_pairs,
                active.missing_positions,
                active.read_pending,
                active.key_packages,
                active.key_latest,
                provisional.sequence,
                provisional.hash,
                provisional.read_receipts,
                provisional.read_pairs,
                provisional.missing_positions,
                provisional.read_pending,
                provisional.key_packages,
                provisional.key_latest,
            ]
            .iter()
            .any(|id| *id >= next_page)
            || !active.rendered.valid_for(next_page)
            || !active.retained.valid_for(next_page)
            || !work.valid_for(next_page, phase)
            || matches!(phase, Phase::Building | Phase::Switched) != promotion.is_some()
        {
            return Err(invalid("entry directory bounds"));
        }
        if let Some(p) = &promotion {
            if p.from == 0
                || p.through < p.from
                || p.cursor < p.from
                || p.cursor > p.through.saturating_add(1)
                || p.witness == 0
                || p.witness >= next_provisional
                || p.first_log == 0
                || p.after_log < p.first_log
                || p.first_page == 0
                || p.after_page < p.first_page
                || p.after_page > next_page
                || p.work.sequence >= next_page
                || p.work.hash >= next_page
                || p.work.clock >= next_page
                || p.work.order >= next_page
                || p.work.children >= next_page
                || p.work.referenced >= next_page
                || p.work.read_receipts >= next_page
                || p.work.read_pairs >= next_page
                || p.work.missing_positions >= next_page
                || p.work.read_pending >= next_page
                || p.work.key_packages >= next_page
                || p.work.key_latest >= next_page
                || p.work.key_tip >= next_package
                || !p.work.rendered.valid_for(next_page)
                || !p.work.retained.valid_for(next_page)
                || p.retired >= next_page
            {
                return Err(invalid("promotion bounds"));
            }
        }
        Ok(Self {
            active,
            provisional,
            next_page,
            next_provisional,
            revision,
            phase,
            promotion,
            graph_ready,
            origin,
            order_revision,
            work,
            render_epoch,
            render_ready,
            render_cursor,
            history_instance,
            retention_stage,
            retention_cursor,
            read_sent_ms,
            restart,
            next_package,
            packages_ready,
            packages_cursor,
        })
    }
}

/// The cache retains bounded canonical plaintext pages, wiped on drop; decoded nodes and
/// complete Entries are owned call-local values. Large legal Entries never enter this cache.
#[derive(Default)]
struct PageCache {
    rows: VecDeque<(u64, Zeroizing<Vec<u8>>)>,
    bytes: usize,
}

impl PageCache {
    fn clear(&mut self) {
        // Free both page allocations and deque storage before returning shared credits.
        self.rows = VecDeque::new();
        CACHE_USED.fetch_sub(std::mem::take(&mut self.bytes), Ordering::Relaxed);
    }
    fn get(&mut self, id: u64) -> Option<Zeroizing<Vec<u8>>> {
        let at = self.rows.iter().position(|(key, _)| *key == id)?;
        let row = self.rows.remove(at)?;
        let found = row.1.clone();
        self.rows.push_back(row);
        Some(found)
    }
    fn put(&mut self, id: u64, bytes: Zeroizing<Vec<u8>>) {
        // Fixed slot overhead plus actual Vec capacity, not merely logical byte length.
        let charge = bytes.capacity() + std::mem::size_of::<(u64, Zeroizing<Vec<u8>>)>() * 2;
        if charge > CACHE_BYTES {
            return;
        }
        let mut released = 0;
        while self.bytes + charge > CACHE_BYTES || self.rows.len() >= CACHE_ITEMS {
            let Some((_, old)) = self.rows.pop_front() else {
                break;
            };
            let old_charge = old.capacity() + std::mem::size_of::<(u64, Zeroizing<Vec<u8>>)>() * 2;
            self.bytes -= old_charge;
            released += old_charge;
            drop(old);
        }
        if released != 0 {
            self.rows.shrink_to_fit();
            CACHE_USED.fetch_sub(released, Ordering::Relaxed);
        }
        if CACHE_USED
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(charge)
                    .filter(|next| *next <= ALL_CACHE_BYTES)
            })
            .is_err()
        {
            return;
        }
        self.bytes += charge;
        self.rows.push_back((id, bytes));
    }
}

impl Drop for PageCache {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Entry(Locator),
    Number(u64),
    Present,
    Rendered(RenderFact),
    Owed(render_facts::OwedFact),
    Retained(crate::node::retention::Tracked),
    Operation(render_facts::OperationFact),
}
impl Value {
    fn locator(self) -> Result<Locator> {
        match self {
            Self::Entry(at) => Ok(at),
            _ => Err(invalid("entry locator value kind")),
        }
    }
    fn write(self, e: &mut Encoder) {
        match self {
            Self::Entry(at) => at.write(e),
            Self::Number(number) => {
                e.array(2).uint(1).uint(number);
            }
            Self::Present => {
                e.array(1).uint(2);
            }
            Self::Rendered(fact) => fact.write(e),
            Self::Owed(fact) => fact.write(e),
            Self::Retained(fact) => retention_facts::write_fact(fact, e),
            Self::Operation(fact) => fact.write(e),
        }
    }
    fn read(d: &mut Decoder<'_>) -> Result<Self> {
        match d.array()? {
            3 => {
                let author = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| invalid("entry locator author"))?;
                let seq = d.uint()?;
                let log = d.uint()?;
                if seq == 0 || log == 0 {
                    return Err(invalid("zero entry location"));
                }
                Ok(Self::Entry(Locator { author, seq, log }))
            }
            2 if d.uint()? == 1 => Ok(Self::Number(d.uint()?)),
            1 if d.uint()? == 2 => Ok(Self::Present),
            5 if d.uint()? == 3 => Ok(Self::Rendered(RenderFact::read(d)?)),
            4 => match d.uint()? {
                4 => Ok(Self::Owed(render_facts::OwedFact::read(d)?)),
                6 => Ok(Self::Operation(render_facts::OperationFact::read(d)?)),
                _ => Err(invalid("entry page value kind")),
            },
            6 if d.uint()? == 5 => Ok(Self::Retained(retention_facts::read_fact(d)?)),
            _ => Err(invalid("entry page value kind")),
        }
    }
}

#[derive(Clone, Debug)]
enum Page {
    Leaf(Vec<(Key, Value)>),
    Branch(Vec<(Key, u64)>),
    Ranked(Vec<(Key, u64, render_facts::Summary)>),
}

impl Page {
    fn max(&self) -> Result<Key> {
        match self {
            Self::Leaf(rows) => rows.last().map(|r| r.0),
            Self::Branch(rows) => rows.last().map(|r| r.0),
            Self::Ranked(rows) => rows.last().map(|r| r.0),
        }
        .ok_or(invalid("empty entry page"))
    }
    fn bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut e = Encoder::new();
        e.array(3).uint(1);
        match self {
            Self::Leaf(rows) => {
                e.uint(0).array(rows.len());
                for (key, value) in rows {
                    e.array(2).bytes(key);
                    value.write(&mut e);
                }
            }
            Self::Branch(rows) => {
                e.uint(1).array(rows.len());
                for (key, id) in rows {
                    e.array(2).bytes(key).uint(*id);
                }
            }
            Self::Ranked(rows) => {
                e.uint(2).array(rows.len());
                for (key, id, summary) in rows {
                    e.array(3).bytes(key).uint(*id);
                    summary.write(&mut e);
                }
            }
        }
        let bytes = e.finish();
        if bytes.len() > PAGE_BYTES {
            return Err(invalid("entry page exceeds bound"));
        }
        Ok(Zeroizing::new(bytes))
    }
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > PAGE_BYTES {
            return Err(invalid("entry page exceeds bound"));
        }
        let mut d = Decoder::new(bytes);
        if d.array()? != 3 || d.uint()? != 1 {
            return Err(invalid("entry page format"));
        }
        let kind = d.uint()?;
        let count = d.array()?;
        if count == 0 || count > PAGE_ITEMS {
            return Err(invalid("entry page count"));
        }
        let mut previous = None;
        let mut leaves = Vec::new();
        let mut branches = Vec::new();
        let mut ranked = Vec::new();
        for _ in 0..count {
            if d.array()? != if kind == 2 { 3 } else { 2 } {
                return Err(invalid("entry page row arity"));
            }
            let encoded_key = d.bytes()?;
            if !matches!(encoded_key.len(), 40 | 64) {
                return Err(invalid("entry page key"));
            }
            let mut key = [0; 64];
            key[..encoded_key.len()].copy_from_slice(encoded_key);
            if previous.is_some_and(|p| p >= key) {
                return Err(invalid("entry page key order"));
            }
            previous = Some(key);
            match kind {
                0 => leaves.push((key, Value::read(&mut d)?)),
                1 => {
                    let id = d.uint()?;
                    if id == 0 {
                        return Err(invalid("entry child id"));
                    }
                    branches.push((key, id));
                }
                2 => {
                    let id = d.uint()?;
                    if id == 0 {
                        return Err(invalid("render child id"));
                    }
                    ranked.push((key, id, render_facts::Summary::read(&mut d)?));
                }
                _ => return Err(invalid("entry page kind")),
            }
        }
        d.finish()?;
        Ok(match kind {
            0 => Self::Leaf(leaves),
            1 => Self::Branch(branches),
            _ => Self::Ranked(ranked),
        })
    }
}

enum Source<'a> {
    Snapshot(&'a Snapshot),
    Cached(&'a Snapshot, &'a RefCell<PageCache>),
    Batch(&'a Batch<'a>),
    OtherSnapshot(&'a Snapshot, SegmentKind),
    OtherBatch(&'a Batch<'a>, SegmentKind),
}

impl Source<'_> {
    fn open(
        &self,
        sek: &Sek,
        channel: &Digest32,
        kind: SegmentKind,
        id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let sealed = match self {
            Self::Snapshot(snapshot)
            | Self::Cached(snapshot, _)
            | Self::OtherSnapshot(snapshot, _) => snapshot.get_segment(channel, kind, id)?,
            Self::Batch(batch) | Self::OtherBatch(batch, _) => {
                batch.get_segment(channel, kind, id)?
            }
        };
        sealed
            .map(|value| open_segment(sek, kind, id, &value))
            .transpose()
    }
    fn page(&self, sek: &Sek, channel: &Digest32, id: u64) -> Result<Page> {
        if let Self::Cached(_, cache) = self {
            if let Some(bytes) = cache.borrow_mut().get(id) {
                return Page::parse(&bytes);
            }
        }
        let kind = match self {
            Self::OtherSnapshot(_, kind) | Self::OtherBatch(_, kind) => *kind,
            _ => SegmentKind::EntryIndex,
        };
        let bytes = self
            .open(sek, channel, kind, id)?
            .ok_or(invalid("entry index page missing"))?;
        let page = Page::parse(&bytes)?;
        if let Self::Cached(_, cache) = self {
            cache.borrow_mut().put(id, bytes);
        }
        Ok(page)
    }
    fn find_value(
        &self,
        sek: &Sek,
        channel: &Digest32,
        mut root: u64,
        key: &Key,
    ) -> Result<Option<Value>> {
        if root == 0 {
            return Ok(None);
        }
        for _ in 0..MAX_DEPTH {
            match self.page(sek, channel, root)? {
                Page::Leaf(rows) => {
                    return Ok(rows
                        .binary_search_by_key(key, |r| r.0)
                        .ok()
                        .map(|at| rows[at].1))
                }
                Page::Branch(rows) => match rows.iter().find(|r| r.0 >= *key) {
                    Some((_, next)) => root = *next,
                    None => return Ok(None),
                },
                Page::Ranked(rows) => match rows.iter().find(|r| r.0 >= *key) {
                    Some((_, next, _)) => root = *next,
                    None => return Ok(None),
                },
            }
        }
        Err(invalid("entry index cycle or depth"))
    }
    fn find(&self, sek: &Sek, channel: &Digest32, root: u64, key: &Key) -> Result<Option<Locator>> {
        self.find_value(sek, channel, root, key)?
            .map(Value::locator)
            .transpose()
    }
    fn first(
        &self,
        sek: &Sek,
        channel: &Digest32,
        root: u64,
        key: &Key,
        depth: usize,
    ) -> Result<Option<(Key, Value)>> {
        if root == 0 {
            return Ok(None);
        }
        if depth >= MAX_DEPTH {
            return Err(invalid("entry index cycle or depth"));
        }
        match self.page(sek, channel, root)? {
            Page::Leaf(rows) => Ok(rows.into_iter().find(|r| r.0 >= *key)),
            Page::Ranked(rows) => {
                for (max, child, _) in rows {
                    if max >= *key {
                        if let Some(row) = self.first(sek, channel, child, key, depth + 1)? {
                            return Ok(Some(row));
                        }
                    }
                }
                Ok(None)
            }
            Page::Branch(rows) => {
                for (max, child) in rows {
                    if max >= *key {
                        if let Some(row) = self.first(sek, channel, child, key, depth + 1)? {
                            return Ok(Some(row));
                        }
                    }
                }
                Ok(None)
            }
        }
    }
}

/// The channel owns only this small directory/cache; Store and SEK are borrowed per call.
#[derive(Default)]
pub(crate) struct EntryIndex {
    cache: RefCell<PageCache>,
    cache_revision: Cell<u64>,
}

impl std::fmt::Debug for EntryIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryIndex")
            .field("cached_bytes", &self.cache.borrow().bytes)
            .finish()
    }
}

pub(crate) struct Read<'a> {
    snapshot: Snapshot,
    cache: &'a RefCell<PageCache>,
    sek: &'a Sek,
    channel: &'a Digest32,
    directory: Directory,
}

impl EntryIndex {
    pub(crate) fn read<'a>(
        &'a self,
        store: &Store,
        sek: &'a Sek,
        channel: &'a Digest32,
    ) -> Result<Read<'a>> {
        let snapshot = store.snapshot()?;
        let source = Source::Snapshot(&snapshot);
        let bytes = source
            .open(sek, channel, SegmentKind::EntryIndex, DIRECTORY)?
            .ok_or(invalid("entry index directory missing"))?;
        let directory = Directory::parse(&bytes)?;
        if directory.phase == Phase::Rebuilding {
            return Err(invalid("entry index publication incomplete"));
        }
        if self.cache_revision.replace(directory.revision) != directory.revision {
            self.cache.borrow_mut().clear();
        }
        Ok(Read {
            snapshot,
            cache: &self.cache,
            sek,
            channel,
            directory,
        })
    }
}

impl Read<'_> {
    pub(crate) fn restart_state(&self) -> Option<&RestartState> {
        self.directory.restart.as_ref()
    }
    pub(crate) fn transaction(&self) -> Transaction<'_, '_> {
        Transaction::Snapshot(&self.snapshot)
    }
    fn source(&self) -> Source<'_> {
        Source::Cached(&self.snapshot, self.cache)
    }
    pub(crate) fn staged(&self, author: &Digest32, seq: u64) -> Result<bool> {
        Ok(self
            .source()
            .find(
                self.sek,
                self.channel,
                self.directory.provisional.sequence,
                &position(author, seq),
            )?
            .is_some())
    }
    pub(crate) fn log_id(&self, hash: &Digest32) -> Result<Option<u64>> {
        Ok(self
            .source()
            .find(
                self.sek,
                self.channel,
                self.directory.active.hash,
                &hashed(hash),
            )?
            .map(|at| at.log))
    }
}

fn indexed_entry(
    source: &Source<'_>,
    sek: &Sek,
    channel: &Digest32,
    kind: SegmentKind,
    at: Locator,
) -> Result<Entry> {
    let wire = source
        .open(sek, channel, kind, at.log)?
        .ok_or(invalid("indexed log entry missing"))?;
    let entry = Entry::from_wire(&wire)?;
    if entry.skeleton.author_id != at.author
        || entry.skeleton.seq != at.seq
        || entry.skeleton.channel_id != *channel
    {
        return Err(invalid("indexed log entry identity differs"));
    }
    Ok(entry)
}

fn find_position(
    source: &Source<'_>,
    sek: &Sek,
    channel: &Digest32,
    directory: &Directory,
    author: &Digest32,
    seq: u64,
) -> Result<Option<Entry>> {
    let key = position(author, seq);
    for (root, kind) in [
        (directory.provisional.sequence, SegmentKind::ProvisionalLog),
        (directory.active.sequence, SegmentKind::LogDb),
    ] {
        if let Some(at) = source.find(sek, channel, root, &key)? {
            if at.author != *author || at.seq != seq {
                return Err(invalid("sequence locator differs"));
            }
            return indexed_entry(source, sek, channel, kind, at).map(Some);
        }
    }
    Ok(None)
}

fn find_hash(
    source: &Source<'_>,
    sek: &Sek,
    channel: &Digest32,
    directory: &Directory,
    hash: &Digest32,
) -> Result<Option<(Digest32, u64)>> {
    for (root, kind) in [
        (directory.provisional.hash, SegmentKind::ProvisionalLog),
        (directory.active.hash, SegmentKind::LogDb),
    ] {
        if let Some(at) = source.find(sek, channel, root, &hashed(hash))? {
            if indexed_entry(source, sek, channel, kind, at)?.entry_hash() != *hash {
                return Err(invalid("hash locator differs"));
            }
            return Ok(Some((at.author, at.seq)));
        }
    }
    Ok(None)
}

impl EntryRead for Read<'_> {
    fn clock(&self, hash: &Digest32) -> Result<Option<u64>> {
        if !self.directory.graph_ready {
            return Err(invalid("DAG facts not yet rebuilt"));
        }
        self.source().number(
            self.sek,
            self.channel,
            self.directory.active.clock,
            &hashed(hash),
        )
    }
    fn order_next(&self, after: Option<(u64, Digest32)>) -> Result<Option<(u64, Digest32)>> {
        self.source()
            .order_next(self.sek, self.channel, self.directory.active.order, after)
    }
    fn order_previous(&self, before: Option<(u64, Digest32)>) -> Result<Option<(u64, Digest32)>> {
        self.source()
            .order_previous(self.sek, self.channel, self.directory.active.order, before)
    }
    fn referenced(&self, author: &Digest32, other: &Digest32) -> Result<u64> {
        let mut key = [0; 64];
        key[..32].copy_from_slice(author);
        key[32..].copy_from_slice(other);
        Ok(self
            .source()
            .number(
                self.sek,
                self.channel,
                self.directory.active.referenced,
                &key,
            )?
            .unwrap_or(0))
    }

    fn get(&self, author: &Digest32, seq: u64) -> Result<Option<Entry>> {
        find_position(
            &self.source(),
            self.sek,
            self.channel,
            &self.directory,
            author,
            seq,
        )
    }
    fn locate(&self, hash: &Digest32) -> Result<Option<(Digest32, u64)>> {
        find_hash(
            &self.source(),
            self.sek,
            self.channel,
            &self.directory,
            hash,
        )
    }
}

/// Startup validates the exact persisted bytes through the ordinary acceptance predicate.
/// Replay never writes, or accepts bytes that differ from its pinned snapshot.
impl EntryWrite for Read<'_> {
    fn put(&mut self, entry: &Entry) -> Result<()> {
        let saved = self
            .get(&entry.skeleton.author_id, entry.skeleton.seq)?
            .ok_or(invalid("replayed entry missing"))?;
        if saved.to_wire() != entry.to_wire() {
            return Err(invalid("replayed entry differs"));
        }
        Ok(())
    }
    fn remove(&mut self, _author: &Digest32, _seq: u64) -> Result<()> {
        Err(invalid("a stored unsigned entry has no signed successor"))
    }
}

/// A write context sees only its own Batch, including earlier tree splits. Dropping the Batch
/// discards its directory as well: no root or cache is changed before commit.
pub(crate) struct Write<'a, 's> {
    kind: SegmentKind,
    batch: &'a mut Batch<'s>,
    sek: &'a Sek,
    channel: &'a Digest32,
    directory: Directory,
    destination: Option<u64>,
}

impl EntryIndex {
    pub(crate) fn write<'a, 's>(
        &self,
        batch: &'a mut Batch<'s>,
        sek: &'a Sek,
        channel: &'a Digest32,
    ) -> Result<Write<'a, 's>> {
        let mut directory =
            match Source::Batch(batch).open(sek, channel, SegmentKind::EntryIndex, DIRECTORY)? {
                Some(bytes) => Directory::parse(&bytes)?,
                None => Directory::default(),
            };
        directory.ensure_instance()?;
        Ok(Write {
            kind: SegmentKind::EntryIndex,
            batch,
            sek,
            channel,
            directory,
            destination: None,
        })
    }
    pub(crate) fn committed(&self) {
        self.cache.borrow_mut().clear();
    }
}

impl<'s> Write<'_, 's> {
    /// Read related sealed state in the same transaction as an entry update.
    pub(crate) fn batch(&self) -> &Batch<'s> {
        self.batch
    }

    fn allocate(&mut self) -> Result<u64> {
        let id = self.directory.next_page;
        self.directory.next_page = id
            .checked_add(1)
            .ok_or(invalid("entry page allocator exhausted"))?;
        if let Some(p) = &mut self.directory.promotion {
            p.after_page = self.directory.next_page;
        }
        Ok(id)
    }
    fn put_page(&mut self, page: &Page) -> Result<(Key, u64)> {
        let bytes = page.bytes()?;
        let id = self.allocate()?;
        let sealed = seal_segment(self.sek, self.kind, id, &bytes)?;
        self.batch
            .put_segment(self.channel, self.kind, id, &sealed)?;
        Ok((page.max()?, id))
    }
    fn retire(&mut self, id: u64) -> Result<()> {
        if self.directory.phase == Phase::Building {
            let previous = self
                .directory
                .promotion
                .as_ref()
                .ok_or(invalid("promotion missing"))?
                .retired;
            let mut e = Encoder::new();
            e.array(4).uint(1).uint(2).uint(previous).uint(id);
            let ledger = self.allocate()?;
            let sealed = seal_segment(self.sek, self.kind, ledger, &e.finish())?;
            self.batch
                .put_segment(self.channel, self.kind, ledger, &sealed)?;
            self.directory
                .promotion
                .as_mut()
                .ok_or(invalid("promotion missing"))?
                .retired = ledger;
        } else {
            self.batch.delete_segment(self.channel, self.kind, id)?;
        }
        Ok(())
    }
    fn replace(
        &mut self,
        root: u64,
        key: Key,
        value: Option<Value>,
        depth: usize,
    ) -> Result<Vec<(Key, u64)>> {
        if depth >= MAX_DEPTH {
            return Err(invalid("entry index cycle or depth"));
        }
        let old = if root == 0 {
            Page::Leaf(Vec::new())
        } else {
            Source::OtherBatch(self.batch, self.kind).page(self.sek, self.channel, root)?
        };
        let mut parts = Vec::with_capacity(2);
        match old {
            Page::Leaf(mut rows) => {
                match (rows.binary_search_by_key(&key, |r| r.0), value) {
                    (Ok(at), Some(value)) => rows[at].1 = value,
                    (Ok(at), None) => {
                        rows.remove(at);
                    }
                    (Err(at), Some(value)) => rows.insert(at, (key, value)),
                    (Err(_), None) => {
                        return Ok(if root == 0 {
                            Vec::new()
                        } else {
                            vec![(rows.last().ok_or(invalid("empty entry leaf"))?.0, root)]
                        })
                    }
                }
                if rows.len() > PAGE_ITEMS {
                    let right = rows.split_off(rows.len() / 2);
                    parts.push(self.put_page(&Page::Leaf(rows))?);
                    parts.push(self.put_page(&Page::Leaf(right))?);
                } else if !rows.is_empty() {
                    parts.push(self.put_page(&Page::Leaf(rows))?);
                }
            }
            Page::Ranked(_) => return Err(invalid("ranked page in entry tree")),
            Page::Branch(mut rows) => {
                let at = rows
                    .iter()
                    .position(|r| r.0 >= key)
                    .unwrap_or(rows.len() - 1);
                let children = self.replace(rows[at].1, key, value, depth + 1)?;
                rows.splice(at..=at, children);
                if rows.len() > PAGE_ITEMS {
                    let right = rows.split_off(rows.len() / 2);
                    parts.push(self.put_page(&Page::Branch(rows))?);
                    parts.push(self.put_page(&Page::Branch(right))?);
                } else if !rows.is_empty() {
                    parts.push(self.put_page(&Page::Branch(rows))?);
                }
            }
        }
        if root != 0 {
            self.retire(root)?;
        }
        Ok(parts)
    }
    fn change_value(&mut self, root: u64, key: Key, value: Option<Value>) -> Result<u64> {
        let parts = self.replace(root, key, value, 0)?;
        match parts.as_slice() {
            [] => Ok(0),
            [(_, id)] => Ok(*id),
            _ => Ok(self.put_page(&Page::Branch(parts))?.1),
        }
    }
    fn change(&mut self, root: u64, key: Key, value: Option<Locator>) -> Result<u64> {
        self.change_value(root, key, value.map(Value::Entry))
    }
    fn index(&mut self, mut roots: Roots, entry: &Entry, log: u64) -> Result<Roots> {
        let at = Locator {
            author: entry.skeleton.author_id,
            seq: entry.skeleton.seq,
            log,
        };
        let key = position(&at.author, at.seq);
        if let Some(existing) =
            Source::Batch(self.batch).find(self.sek, self.channel, roots.sequence, &key)?
        {
            if existing != at {
                return Err(invalid("entry position already indexed differently"));
            }
        }
        roots.sequence = self.change(roots.sequence, key, Some(at))?;
        roots.hash = self.change(roots.hash, hashed(&entry.entry_hash()), Some(at))?;
        Ok(roots)
    }
    pub(crate) fn index_existing(&mut self, entry: &Entry, log: u64) -> Result<()> {
        if self.directory.phase != Phase::Rebuilding {
            return Err(invalid("not rebuilding entry index"));
        }
        self.directory.active = self.index(self.directory.active, entry, log)?;
        if entry.payload.is_none() {
            self.directory.active = self.missing_in_roots(self.directory.active, entry, true)?;
        }
        Ok(())
    }
    pub(crate) fn finish_rebuild(&mut self) -> Result<()> {
        if self.directory.phase != Phase::Rebuilding {
            return Err(invalid("not rebuilding entry index"));
        }
        if !self.directory.work.is_empty() {
            return Err(invalid("DAG rebuild incomplete"));
        }
        self.directory.graph_ready =
            self.directory.active.sequence == 0 || self.directory.active.clock != 0;
        self.directory.phase = Phase::Idle;
        Ok(())
    }
    pub(crate) fn put_committed(&mut self, entry: &Entry, log: u64) -> Result<()> {
        if self.directory.phase != Phase::Idle {
            return Err(invalid("entry index publication in progress"));
        }
        let prior = Source::Batch(self.batch)
            .find(
                self.sek,
                self.channel,
                self.directory.active.hash,
                &hashed(&entry.entry_hash()),
            )?
            .ok_or(invalid("new entry requires prepared DAG publication"))?;
        if prior.log != log
            || prior.author != entry.skeleton.author_id
            || prior.seq != entry.skeleton.seq
        {
            return Err(invalid("entry rewrite location differs"));
        }
        let sealed = seal_segment(self.sek, SegmentKind::LogDb, log, &entry.to_wire())?;
        self.batch
            .put_segment(self.channel, SegmentKind::LogDb, log, &sealed)?;
        self.directory.active = self.index(self.directory.active, entry, log)?;
        self.directory.active = self.index_package(self.directory.active, entry, log)?;
        // A refill settles recovery atomically with its durable wire. Rewriting a body as
        // a skeleton for local retention deliberately does not create recovery work.
        if entry.payload.is_some() {
            self.set_missing(&entry.skeleton.author_id, entry.skeleton.seq, false)?;
            self.set_owed(entry.entry_hash(), None)?;
        }
        Ok(())
    }
    pub(crate) fn stage(&mut self, entry: &Entry) -> Result<u64> {
        if self.directory.phase != Phase::Idle {
            return Err(invalid("entry index publication in progress"));
        }
        let existing = Source::Batch(self.batch).find(
            self.sek,
            self.channel,
            self.directory.provisional.sequence,
            &position(&entry.skeleton.author_id, entry.skeleton.seq),
        )?;
        let id = match existing {
            Some(at) => {
                if indexed_entry(
                    &Source::Batch(self.batch),
                    self.sek,
                    self.channel,
                    SegmentKind::ProvisionalLog,
                    at,
                )?
                .entry_hash()
                    != entry.entry_hash()
                {
                    return Err(invalid("provisional replacement differs"));
                }
                at.log
            }
            None => {
                let id = self.directory.next_provisional;
                self.directory.next_provisional = id
                    .checked_add(1)
                    .ok_or(invalid("provisional allocator exhausted"))?;
                id
            }
        };
        let sealed = seal_segment(self.sek, SegmentKind::ProvisionalLog, id, &entry.to_wire())?;
        self.batch
            .put_segment(self.channel, SegmentKind::ProvisionalLog, id, &sealed)?;
        self.directory.provisional = self.index(self.directory.provisional, entry, id)?;
        Ok(id)
    }
    pub(crate) fn seal(&mut self) -> Result<()> {
        self.directory.revision = self
            .directory
            .revision
            .checked_add(1)
            .ok_or(invalid("entry index revision exhausted"))?;
        let sealed = seal_segment(
            self.sek,
            SegmentKind::EntryIndex,
            DIRECTORY,
            &self.directory.bytes(),
        )?;
        self.batch
            .put_segment(self.channel, SegmentKind::EntryIndex, DIRECTORY, &sealed)
    }
}

/// One verified feed interval to publish with its entry effects and DAG facts.
pub(crate) struct Publication<'a> {
    pub witness: &'a Entry,
    pub from: u64,
    pub first_log: u64,
    pub received_ms: u64,
    pub bodyless_prefix: bool,
    pub origin: u64,
}

const PROMOTION_ENTRIES: usize = 64;
const PROMOTION_BYTES: usize = 1024 * 1024;

impl Write<'_, '_> {
    pub(crate) fn initialize_restart(&mut self, epoch: u64) -> Result<()> {
        if self.directory.active.sequence != 0 {
            return Err(invalid("nonempty restart initialization"));
        }
        self.bootstrap_restart(RestartState::empty(*self.channel, epoch))?;
        self.directory.packages_ready = true;
        Ok(())
    }
    pub(crate) fn bootstrap_restart(&mut self, state: RestartState) -> Result<()> {
        if self.directory.phase != Phase::Idle
            || state.room != *self.channel
            || self.directory.restart.is_some()
        {
            return Err(invalid("restart bootstrap binding"));
        }
        self.directory.restart = Some(state);
        Ok(())
    }
    pub(crate) fn note_presence(
        &mut self,
        author: Digest32,
        state: super::governance::Presence,
    ) -> Result<()> {
        let restart = self
            .directory
            .restart
            .as_mut()
            .ok_or(invalid("presence without restart state"))?;
        if !restart
            .feeds
            .get(&author)
            .is_some_and(|f| state.last.0 <= f.seq)
        {
            return Err(invalid("presence beyond published feed"));
        }
        restart.presence.insert(author, state);
        Ok(())
    }
    pub(crate) fn note_swept(&mut self, dag: &crate::log::dag::Dag) -> Result<()> {
        let restart = self
            .directory
            .restart
            .as_mut()
            .ok_or(invalid("sweep without restart state"))?;
        for (author, seq) in dag.swept_positions() {
            if let Some(feed) = restart.feeds.get_mut(author) {
                if *seq > feed.checkpoint.map_or(0, |cp| cp.0) {
                    return Err(invalid("sweep beyond published checkpoint"));
                }
                feed.swept_to = *seq;
            }
        }
        Ok(())
    }
    pub(crate) fn clear_retained_step_marker(&mut self) -> Result<()> {
        self.directory
            .restart
            .as_mut()
            .ok_or(invalid("legacy completion without restart state"))?
            .retained_step_body = None;
        Ok(())
    }
    pub(crate) fn note_projection(&mut self, bytes: Vec<u8>) -> Result<()> {
        if bytes.len() > 256 {
            return Err(invalid("projection state bound"));
        }
        self.directory
            .restart
            .as_mut()
            .ok_or(invalid("projection without restart state"))?
            .projection = Some(bytes);
        Ok(())
    }
    /// The caller already checked the complete feed linkage and the successor's signature.
    /// The signed witness stays in the provisional store until publication and cleanup finish.
    pub(crate) fn begin_promotion(&mut self, publication: Publication<'_>) -> Result<()> {
        let Publication {
            witness,
            from,
            first_log,
            received_ms,
            bodyless_prefix,
            origin,
        } = publication;
        self.set_origin(origin)?;
        if self.directory.phase != Phase::Idle
            || !witness.is_signed()
            || from == 0
            || from > witness.skeleton.seq
            || first_log == 0
        {
            return Err(invalid("invalid entry promotion start"));
        }
        let author = witness.skeleton.author_id;
        let source = Source::Batch(self.batch);
        let at = source
            .find(
                self.sek,
                self.channel,
                self.directory.provisional.sequence,
                &position(&author, witness.skeleton.seq),
            )?
            .ok_or(invalid("promotion witness missing"))?;
        let wire = source
            .open(self.sek, self.channel, SegmentKind::ProvisionalLog, at.log)?
            .ok_or(invalid("promotion witness wire missing"))?;
        let saved = Entry::from_wire(&wire)?;
        if saved.to_wire() != witness.to_wire() {
            return Err(invalid("promotion witness differs"));
        }
        let base_hash = if from == 1 {
            [0; 32]
        } else {
            let at = source
                .find(
                    self.sek,
                    self.channel,
                    self.directory.active.sequence,
                    &position(&author, from - 1),
                )?
                .ok_or(invalid("promotion base missing"))?;
            let wire = source
                .open(self.sek, self.channel, SegmentKind::LogDb, at.log)?
                .ok_or(invalid("promotion base wire missing"))?;
            Entry::from_wire(&wire)?.entry_hash()
        };
        let count = witness
            .skeleton
            .seq
            .checked_sub(from)
            .and_then(|v| v.checked_add(1))
            .ok_or(invalid("promotion sequence overflow"))?;
        first_log
            .checked_add(count)
            .ok_or(invalid("promotion log allocator exhausted"))?;
        if self.directory.restart.is_none() && self.directory.active.sequence == 0 && from == 1 {
            self.directory.packages_ready = true;
            self.directory.restart =
                Some(RestartState::empty(*self.channel, witness.skeleton.epoch));
        }
        let restart = self
            .directory
            .restart
            .as_ref()
            .ok_or(invalid("accepted restart state was not prepared"))?;
        if restart.room != *self.channel || restart.epoch != witness.skeleton.epoch {
            return Err(invalid("restart room binding"));
        }
        let accepted = restart.feeds.get(&author).cloned().unwrap_or_default();
        if accepted.seq.checked_add(1) != Some(from) || accepted.hash != base_hash {
            return Err(invalid("restart prefix differs from promotion"));
        }
        self.directory.promotion = Some(Promotion {
            author,
            from,
            through: witness.skeleton.seq,
            base_hash,
            received_ms,
            witness: at.log,
            witness_hash: witness.entry_hash(),
            cursor: from,
            work: self.directory.active,
            first_log,
            after_log: first_log,
            first_page: self.directory.next_page,
            after_page: self.directory.next_page,
            retired: 0,
            bodyless_prefix,
            reordered: 0,
            accepted: Some(accepted),
        });
        self.directory.phase = Phase::Building;
        Ok(())
    }

    /// Copy at most one bounded chunk, never an entire authenticated suffix. A single legal
    /// large witness is allowed as one entry; the index-page bound is not a message-size cap.
    /// The caller seals this updated descriptor and commits the same Batch after each step.
    pub(crate) fn promotion_chunk(&mut self) -> Result<bool> {
        if self.directory.phase != Phase::Building {
            return Err(invalid("no building promotion"));
        }
        let mut p = self
            .directory
            .promotion
            .clone()
            .ok_or(invalid("promotion missing"))?;
        let mut bytes = 0usize;
        for _ in 0..PROMOTION_ENTRIES {
            if p.cursor > p.through {
                break;
            }
            let source = Source::Batch(self.batch);
            let at = source
                .find(
                    self.sek,
                    self.channel,
                    self.directory.provisional.sequence,
                    &position(&p.author, p.cursor),
                )?
                .ok_or(invalid("promotion suffix missing"))?;
            let wire = source
                .open(self.sek, self.channel, SegmentKind::ProvisionalLog, at.log)?
                .ok_or(invalid("promotion suffix wire missing"))?;
            if bytes != 0 && bytes.saturating_add(wire.len()) > PROMOTION_BYTES {
                break;
            }
            let entry = Entry::from_wire(&wire)?;
            if entry.skeleton.author_id != p.author
                || entry.skeleton.seq != p.cursor
                || entry.skeleton.channel_id != *self.channel
                || (p.cursor < p.through
                    && p.bodyless_prefix
                    && (entry.is_signed() || entry.payload.is_some()))
                || (!p.bodyless_prefix && !entry.is_signed())
                || (p.cursor == p.through
                    && (!entry.is_signed() || entry.entry_hash() != p.witness_hash))
            {
                return Err(invalid("promotion entry differs from authenticated suffix"));
            }
            let previous = if p.cursor == p.from {
                p.base_hash
            } else {
                let at = source
                    .find(
                        self.sek,
                        self.channel,
                        p.work.sequence,
                        &position(&p.author, p.cursor - 1),
                    )?
                    .ok_or(invalid("promotion predecessor missing"))?;
                indexed_entry(&source, self.sek, self.channel, SegmentKind::LogDb, at)?.entry_hash()
            };
            if entry.skeleton.prev_hash != previous
                || (p.cursor == p.through && at.log != p.witness)
            {
                return Err(invalid("promotion predecessor or witness differs"));
            }
            restart::advance(
                p.accepted
                    .as_mut()
                    .ok_or(invalid("promotion restart state missing"))?,
                &entry,
            )?;
            let log = p
                .first_log
                .checked_add(p.cursor - p.from)
                .ok_or(invalid("promotion log overflow"))?;
            if self
                .batch
                .get_segment(self.channel, SegmentKind::LogDb, log)?
                .is_some()
            {
                return Err(invalid("promotion would overwrite an active log entry"));
            }
            let sealed = seal_segment(self.sek, SegmentKind::LogDb, log, &wire)?;
            self.batch
                .put_segment(self.channel, SegmentKind::LogDb, log, &sealed)?;
            // Bodyless skeletons have no decrypt/ratchet effect. Their first-seen facts still
            // land with their wire and locator; the witness effects are queued at publication.
            if p.cursor < p.through && p.bodyless_prefix {
                let seen = seal_segment(
                    self.sek,
                    SegmentKind::Index,
                    log,
                    &super::first_seen_bytes(p.received_ms, false),
                )?;
                self.batch
                    .put_segment(self.channel, SegmentKind::Index, log, &seen)?;
            }
            p.work = self.index(p.work, &entry, log)?;
            p.work = self.index_package(p.work, &entry, log)?;
            if entry.payload.is_none() {
                // The membership stays unpublished with this authenticated suffix until the
                // witness's effects and root switch commit together.
                p.work = self.missing_in_roots(p.work, &entry, true)?;
            }
            self.enqueue_fact(entry.entry_hash())?;
            p.after_log = log
                .checked_add(1)
                .ok_or(invalid("promotion log overflow"))?;
            p.cursor = p
                .cursor
                .checked_add(1)
                .ok_or(invalid("promotion sequence overflow"))?;
            bytes = bytes.saturating_add(wire.len());
        }
        // Tree writes also appended retirement nodes and advanced the page allocator.
        let allocated = self
            .directory
            .promotion
            .as_ref()
            .ok_or(invalid("promotion missing"))?;
        p.after_page = allocated.after_page;
        p.retired = allocated.retired;
        let complete = p.cursor > p.through;
        self.directory.promotion = Some(p);
        Ok(complete)
    }

    /// Queue the root switch in the same Batch as the witness's ratchet/cache/governance
    /// effects. The caller must not publish the new head or stored credit before commit.
    pub(crate) fn publish_promotion(&mut self) -> Result<(u64, u64)> {
        if self.directory.phase != Phase::Building {
            return Err(invalid("no building promotion"));
        }
        let p = self
            .directory
            .promotion
            .as_ref()
            .ok_or(invalid("promotion missing"))?;
        if p.cursor <= p.through || !self.directory.work.is_empty() {
            return Err(invalid("promotion suffix or DAG facts incomplete"));
        }
        let accepted = p
            .accepted
            .clone()
            .ok_or(invalid("promotion accepted state missing"))?;
        if accepted.seq != p.through || accepted.hash != p.witness_hash {
            return Err(invalid("promotion accepted witness differs"));
        }
        let restart = self
            .directory
            .restart
            .as_mut()
            .ok_or(invalid("restart state missing at publication"))?;
        restart.feeds.insert(p.author, accepted);
        if restart.feeds.len() > super::AUTHORS_HARD_LIMIT {
            return Err(invalid("restart author bound"));
        }
        let result = (p.through - p.from + 1, p.after_log);
        let from = p.from;
        self.directory.active = p.work;
        self.directory.order_revision = self.directory.order_revision.wrapping_add(p.reordered);
        self.directory.phase = Phase::Switched;
        self.directory
            .promotion
            .as_mut()
            .ok_or(invalid("promotion missing"))?
            .cursor = from;
        Ok(result)
    }

    /// Cleanup is itself restartable. Building rolls back only unpublished allocations before
    /// LogDb replay; Switched never deletes newly active LogDb, only retired page versions.
    pub(crate) fn cleanup_chunk(&mut self) -> Result<bool> {
        let Some(mut p) = self.directory.promotion.clone() else {
            return Ok(true);
        };
        match self.directory.phase {
            Phase::Building => {
                for _ in 0..PROMOTION_ENTRIES {
                    if p.after_log > p.first_log {
                        p.after_log -= 1;
                        self.batch
                            .delete_segment(self.channel, SegmentKind::LogDb, p.after_log)?;
                        self.batch
                            .delete_segment(self.channel, SegmentKind::Index, p.after_log)?;
                    } else if p.after_page > p.first_page {
                        p.after_page -= 1;
                        self.batch.delete_segment(
                            self.channel,
                            SegmentKind::EntryIndex,
                            p.after_page,
                        )?;
                    } else {
                        self.directory.phase = Phase::Idle;
                        self.directory.promotion = None;
                        self.directory.work = dag_facts::Work::default();
                        return Ok(true);
                    }
                }
            }
            Phase::Switched => {
                for _ in 0..PROMOTION_ENTRIES {
                    if p.retired == 0 {
                        if p.cursor <= p.through {
                            self.remove_staged(&p.author, p.cursor)?;
                            p.cursor = p
                                .cursor
                                .checked_add(1)
                                .ok_or(invalid("promotion cleanup overflow"))?;
                            continue;
                        }
                        self.directory.phase = Phase::Idle;
                        self.directory.promotion = None;
                        return Ok(true);
                    }
                    let ledger = p.retired;
                    let bytes = Source::Batch(self.batch)
                        .open(self.sek, self.channel, SegmentKind::EntryIndex, ledger)?
                        .ok_or(invalid("entry retirement ledger missing"))?;
                    if bytes.len() > PAGE_BYTES {
                        return Err(invalid("entry retirement ledger exceeds bound"));
                    }
                    let mut d = Decoder::new(&bytes);
                    if d.array()? != 4 || d.uint()? != 1 || d.uint()? != 2 {
                        return Err(invalid("entry retirement ledger format"));
                    }
                    let previous = d.uint()?;
                    let retired = d.uint()?;
                    d.finish()?;
                    if retired == 0 || retired >= ledger || previous >= ledger {
                        return Err(invalid("entry retirement ledger order"));
                    }
                    self.batch
                        .delete_segment(self.channel, SegmentKind::EntryIndex, retired)?;
                    self.batch
                        .delete_segment(self.channel, SegmentKind::EntryIndex, ledger)?;
                    p.retired = previous;
                }
            }
            _ => return Err(invalid("unexpected promotion cleanup phase")),
        }
        self.directory.promotion = Some(p);
        Ok(false)
    }
}

impl EntryIndex {
    /// Complete crash cleanup before a caller scans authoritative LogDb. An absent derived
    /// index is rebuilt from sealed wire entries; no saved entry, key or first-seen fact is reset.
    pub(crate) fn prepare(
        &self,
        store: &Store,
        sek: &Sek,
        channel: &Digest32,
        origin: u64,
    ) -> Result<()> {
        loop {
            let mut batch = store.batch()?;
            let mut writer = self.write(&mut batch, sek, channel)?;
            if matches!(writer.directory.phase, Phase::Building | Phase::Switched) {
                let done = writer.cleanup_chunk()?;
                writer.seal()?;
                batch.commit()?;
                self.committed();
                if !done {
                    continue;
                }
            }
            break;
        }
        let snapshot = store.snapshot()?;
        let directory = Source::Snapshot(&snapshot)
            .open(sek, channel, SegmentKind::EntryIndex, DIRECTORY)?
            .map(|v| Directory::parse(&v))
            .transpose()?;
        let rebuilding = directory
            .as_ref()
            .is_none_or(|d| d.phase == Phase::Rebuilding);
        drop(snapshot);
        if rebuilding {
            let mut fresh = Directory {
                origin: Some(origin),
                history_instance: directory.as_ref().map_or([0; 16], |d| d.history_instance),
                ..Directory::default()
            };
            fresh.ensure_instance()?;
            // A crashed rebuild is restarted after discarding only its derived pages. Keep a
            // durable Rebuilding directory throughout, never an apparently complete empty index.
            loop {
                let mut batch = store.batch()?;
                let mut removed = 0;
                for _ in 0..PROMOTION_ENTRIES {
                    let Some((id, _)) =
                        batch.segment_after(channel, SegmentKind::EntryIndex, Some(0))?
                    else {
                        break;
                    };
                    batch.delete_segment(channel, SegmentKind::EntryIndex, id)?;
                    removed += 1;
                }
                let sealed = seal_segment(sek, SegmentKind::EntryIndex, DIRECTORY, &fresh.bytes())?;
                batch.put_segment(channel, SegmentKind::EntryIndex, DIRECTORY, &sealed)?;
                batch.commit()?;
                if removed < PROMOTION_ENTRIES {
                    break;
                }
            }
            // Read the immutable log through each write transaction. A read snapshot spanning
            // the whole rebuild pins every retired redb page until the last entry, preventing
            // reuse across these commits. Only the stable LogDb id crosses a batch boundary;
            // index writes cannot move or replace any of the log rows being visited.
            let mut after = None;
            loop {
                let mut batch = store.batch()?;
                let mut writer = self.write(&mut batch, sek, channel)?;
                let mut bytes = 0usize;
                let mut complete = false;
                for _ in 0..PROMOTION_ENTRIES {
                    let Some((id, sealed)) =
                        writer
                            .batch
                            .segment_after(channel, SegmentKind::LogDb, after)?
                    else {
                        complete = true;
                        break;
                    };
                    let wire = open_segment(sek, SegmentKind::LogDb, id, &sealed)?;
                    if bytes != 0 && bytes.saturating_add(wire.len()) > PROMOTION_BYTES {
                        break;
                    }
                    let entry = Entry::from_wire(&wire)?;
                    if entry.skeleton.channel_id != *channel {
                        return Err(invalid("saved entry belongs to another room"));
                    }
                    writer.index_existing(&entry, id)?;
                    bytes = bytes.saturating_add(wire.len());
                    after = Some(id);
                }
                // All changed roots and their directory become durable together. Keep one
                // writer for the batch instead of decrypting and resealing it for every row.
                writer.seal()?;
                batch.commit()?;
                if complete {
                    break;
                }
            }
            let mut batch = store.batch()?;
            let mut writer = self.write(&mut batch, sek, channel)?;
            writer.finish_rebuild()?;
            writer.seal()?;
            batch.commit()?;
            self.committed();
        }
        // An unfinished unsigned run is never recovered as an authentic feed. Reclaim its
        // sealed wire and both locator rows atomically, in bounded batches.
        // Provisional trees share no pages with active trees; ordinary COW updates have already
        // retired their superseded versions. Walk deletion by key so no whole-tree Vec is held.
        self.discard_provisional(store, sek, channel)
    }

    pub(crate) fn discard_provisional(
        &self,
        store: &Store,
        sek: &Sek,
        channel: &Digest32,
    ) -> Result<()> {
        loop {
            let mut batch = store.batch()?;
            let mut writer = self.write(&mut batch, sek, channel)?;
            if writer.directory.phase != Phase::Idle {
                return Err(invalid("provisional cleanup before publication cleanup"));
            }
            let mut removed = 0;
            for _ in 0..PROMOTION_ENTRIES {
                let roots = writer.directory.provisional;
                let first =
                    Source::Batch(writer.batch).first(sek, channel, roots.sequence, &[0; 64], 0)?;
                let Some((key, value)) = first else {
                    break;
                };
                let at = value.locator()?;
                let wire = Source::Batch(writer.batch)
                    .open(sek, channel, SegmentKind::ProvisionalLog, at.log)?
                    .ok_or(invalid("provisional entry missing"))?;
                let entry = Entry::from_wire(&wire)?;
                writer.directory.provisional.sequence = writer.change(roots.sequence, key, None)?;
                writer.directory.provisional.hash =
                    writer.change(roots.hash, hashed(&entry.entry_hash()), None)?;
                writer
                    .batch
                    .delete_segment(channel, SegmentKind::ProvisionalLog, at.log)?;
                removed += 1;
            }
            if removed == 0 {
                return Ok(());
            }
            writer.seal()?;
            batch.commit()?;
            self.committed();
            if removed < PROMOTION_ENTRIES {
                return Ok(());
            }
        }
    }
}

impl EntryRead for Write<'_, '_> {
    fn clock(&self, hash: &Digest32) -> Result<Option<u64>> {
        if !self.directory.graph_ready {
            return Err(invalid("DAG facts not yet rebuilt"));
        }
        Source::Batch(self.batch).number(
            self.sek,
            self.channel,
            self.directory.active.clock,
            &hashed(hash),
        )
    }
    fn order_next(&self, after: Option<(u64, Digest32)>) -> Result<Option<(u64, Digest32)>> {
        Source::Batch(self.batch).order_next(
            self.sek,
            self.channel,
            self.directory.active.order,
            after,
        )
    }
    fn order_previous(&self, before: Option<(u64, Digest32)>) -> Result<Option<(u64, Digest32)>> {
        Source::Batch(self.batch).order_previous(
            self.sek,
            self.channel,
            self.directory.active.order,
            before,
        )
    }
    fn referenced(&self, author: &Digest32, other: &Digest32) -> Result<u64> {
        let mut key = [0; 64];
        key[..32].copy_from_slice(author);
        key[32..].copy_from_slice(other);
        Ok(Source::Batch(self.batch)
            .number(
                self.sek,
                self.channel,
                self.directory.active.referenced,
                &key,
            )?
            .unwrap_or(0))
    }

    fn get(&self, author: &Digest32, seq: u64) -> Result<Option<Entry>> {
        find_position(
            &Source::Batch(self.batch),
            self.sek,
            self.channel,
            &self.directory,
            author,
            seq,
        )
    }
    fn locate(&self, hash: &Digest32) -> Result<Option<(Digest32, u64)>> {
        find_hash(
            &Source::Batch(self.batch),
            self.sek,
            self.channel,
            &self.directory,
            hash,
        )
    }
}

impl Write<'_, '_> {
    /// Local append or retention edits use the same transaction for wire, locator and effects.
    /// Existing positions keep their LogDb id; a new local entry uses exactly `next_log`.
    pub(crate) fn committing(&mut self, next_log: u64) {
        self.destination = Some(next_log);
    }

    pub(crate) fn remove_staged(&mut self, author: &Digest32, seq: u64) -> Result<()> {
        if !matches!(self.directory.phase, Phase::Idle | Phase::Switched) {
            return Err(invalid("remove during entry publication"));
        }
        let key = position(author, seq);
        let roots = self.directory.provisional;
        let Some(at) =
            Source::Batch(self.batch).find(self.sek, self.channel, roots.sequence, &key)?
        else {
            return Ok(());
        };
        let entry = indexed_entry(
            &Source::Batch(self.batch),
            self.sek,
            self.channel,
            SegmentKind::ProvisionalLog,
            at,
        )?;
        self.directory.provisional.sequence = self.change(roots.sequence, key, None)?;
        self.directory.provisional.hash =
            self.change(roots.hash, hashed(&entry.entry_hash()), None)?;
        self.batch
            .delete_segment(self.channel, SegmentKind::ProvisionalLog, at.log)?;
        Ok(())
    }
}

impl EntryWrite for Write<'_, '_> {
    fn put(&mut self, entry: &Entry) -> Result<()> {
        if let Some(next) = self.destination {
            let existing = Source::Batch(self.batch).find(
                self.sek,
                self.channel,
                self.directory.active.sequence,
                &position(&entry.skeleton.author_id, entry.skeleton.seq),
            )?;
            let id = match existing {
                Some(at) => {
                    if indexed_entry(
                        &Source::Batch(self.batch),
                        self.sek,
                        self.channel,
                        SegmentKind::LogDb,
                        at,
                    )?
                    .entry_hash()
                        != entry.entry_hash()
                    {
                        return Err(invalid("committed replacement differs"));
                    }
                    at.log
                }
                None => {
                    if self
                        .batch
                        .get_segment(self.channel, SegmentKind::LogDb, next)?
                        .is_some()
                    {
                        return Err(invalid("local append would overwrite log"));
                    }
                    self.destination = Some(
                        next.checked_add(1)
                            .ok_or(invalid("log allocator exhausted"))?,
                    );
                    next
                }
            };
            self.put_committed(entry, id)?;
            self.remove_staged(&entry.skeleton.author_id, entry.skeleton.seq)?;
        } else {
            self.stage(entry)?;
        }
        Ok(())
    }
    fn remove(&mut self, author: &Digest32, seq: u64) -> Result<()> {
        self.remove_staged(author, seq)
    }
}

/// A short transaction reference supplied by the caller. Never retained by the room.
#[derive(Clone, Copy)]
pub(crate) enum Transaction<'a, 's> {
    Snapshot(&'a Snapshot),
    Batch(&'a Batch<'s>),
}
impl Transaction<'_, '_> {
    fn source(&self) -> Source<'_> {
        match self {
            Self::Snapshot(s) => Source::Snapshot(s),
            Self::Batch(b) => Source::Batch(b),
        }
    }
}

pub(crate) struct View<'a, 's> {
    transaction: Transaction<'a, 's>,
    sek: &'a Sek,
    channel: &'a Digest32,
    directory: Directory,
}
impl EntryIndex {
    pub(crate) fn view<'a, 's>(
        &self,
        transaction: Transaction<'a, 's>,
        sek: &'a Sek,
        channel: &'a Digest32,
    ) -> Result<View<'a, 's>> {
        let bytes = transaction
            .source()
            .open(sek, channel, SegmentKind::EntryIndex, DIRECTORY)?
            .ok_or(invalid("entry index directory missing"))?;
        Ok(View {
            transaction,
            sek,
            channel,
            directory: Directory::parse(&bytes)?,
        })
    }
    pub(crate) fn in_batch<'a, 's>(
        &self,
        batch: &'a Batch<'s>,
        sek: &'a Sek,
        channel: &'a Digest32,
    ) -> Result<View<'a, 's>> {
        self.view(Transaction::Batch(batch), sek, channel)
    }
}
impl View<'_, '_> {
    pub(crate) fn log_id(&self, hash: &Digest32) -> Result<Option<u64>> {
        Ok(self
            .transaction
            .source()
            .find(
                self.sek,
                self.channel,
                self.directory.active.hash,
                &hashed(hash),
            )?
            .map(|at| at.log))
    }
}
impl EntryRead for View<'_, '_> {
    fn clock(&self, hash: &Digest32) -> Result<Option<u64>> {
        if !self.directory.graph_ready {
            return Err(invalid("DAG facts not yet rebuilt"));
        }
        self.transaction.source().number(
            self.sek,
            self.channel,
            self.directory.active.clock,
            &hashed(hash),
        )
    }
    fn order_next(&self, after: Option<(u64, Digest32)>) -> Result<Option<(u64, Digest32)>> {
        self.transaction.source().order_next(
            self.sek,
            self.channel,
            self.directory.active.order,
            after,
        )
    }
    fn order_previous(&self, before: Option<(u64, Digest32)>) -> Result<Option<(u64, Digest32)>> {
        self.transaction.source().order_previous(
            self.sek,
            self.channel,
            self.directory.active.order,
            before,
        )
    }
    fn referenced(&self, author: &Digest32, other: &Digest32) -> Result<u64> {
        let mut key = [0; 64];
        key[..32].copy_from_slice(author);
        key[32..].copy_from_slice(other);
        Ok(self
            .transaction
            .source()
            .number(
                self.sek,
                self.channel,
                self.directory.active.referenced,
                &key,
            )?
            .unwrap_or(0))
    }

    fn get(&self, author: &Digest32, seq: u64) -> Result<Option<Entry>> {
        find_position(
            &self.transaction.source(),
            self.sek,
            self.channel,
            &self.directory,
            author,
            seq,
        )
    }
    fn locate(&self, hash: &Digest32) -> Result<Option<(Digest32, u64)>> {
        find_hash(
            &self.transaction.source(),
            self.sek,
            self.channel,
            &self.directory,
            hash,
        )
    }
}

/// Streaming protocol/rollback access. Each staged entry/removal commits its own bounded
/// transaction; this context never holds a write transaction across a network wait.
pub(crate) struct Staging<'a> {
    index: &'a EntryIndex,
    store: &'a Store,
    sek: &'a Sek,
    channel: &'a Digest32,
}
impl EntryIndex {
    pub(crate) fn staging<'a>(
        &'a self,
        store: &'a Store,
        sek: &'a Sek,
        channel: &'a Digest32,
    ) -> Staging<'a> {
        Staging {
            index: self,
            store,
            sek,
            channel,
        }
    }
}
impl EntryRead for Staging<'_> {
    fn clock(&self, hash: &Digest32) -> Result<Option<u64>> {
        self.index
            .read(self.store, self.sek, self.channel)?
            .clock(hash)
    }
    fn order_next(&self, after: Option<(u64, Digest32)>) -> Result<Option<(u64, Digest32)>> {
        self.index
            .read(self.store, self.sek, self.channel)?
            .order_next(after)
    }
    fn order_previous(&self, before: Option<(u64, Digest32)>) -> Result<Option<(u64, Digest32)>> {
        self.index
            .read(self.store, self.sek, self.channel)?
            .order_previous(before)
    }
    fn referenced(&self, author: &Digest32, other: &Digest32) -> Result<u64> {
        self.index
            .read(self.store, self.sek, self.channel)?
            .referenced(author, other)
    }

    fn get_by_hash(&self, hash: &Digest32) -> Result<Option<Entry>> {
        self.index
            .read(self.store, self.sek, self.channel)?
            .get_by_hash(hash)
    }
    fn get(&self, author: &Digest32, seq: u64) -> Result<Option<Entry>> {
        self.index
            .read(self.store, self.sek, self.channel)?
            .get(author, seq)
    }
    fn locate(&self, hash: &Digest32) -> Result<Option<(Digest32, u64)>> {
        self.index
            .read(self.store, self.sek, self.channel)?
            .locate(hash)
    }
}
impl EntryWrite for Staging<'_> {
    fn put(&mut self, entry: &Entry) -> Result<()> {
        let mut batch = self.store.batch()?;
        let mut writer = self.index.write(&mut batch, self.sek, self.channel)?;
        writer.stage(entry)?;
        writer.seal()?;
        batch.commit()?;
        self.index.committed();
        Ok(())
    }
    fn remove(&mut self, author: &Digest32, seq: u64) -> Result<()> {
        let mut batch = self.store.batch()?;
        let mut writer = self.index.write(&mut batch, self.sek, self.channel)?;
        writer.remove_staged(author, seq)?;
        writer.seal()?;
        batch.commit()?;
        self.index.committed();
        Ok(())
    }
}
