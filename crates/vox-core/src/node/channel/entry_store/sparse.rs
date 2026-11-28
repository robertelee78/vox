//! Exact sparse-history evidence in the existing sealed EntryIndex allocation/transaction.
//!
//! These roots never stand in for `PublishedFeed`. A signature-valid observed head grants
//! neither prefix consistency nor control authority. Large immutable objects are separate
//! sealed records, not inline directory state or permanently retained plaintext.

use super::*;
use crate::hash::sha256;
use crate::log::history::{
    ConsistentPrefix, ControlContext, Descriptor, IncludedHeader, LogScope, SignedHead,
    TreeBinding, VerifiedControlRange, VerifiedHead, VerifiedHeader, MAX_CONTEXT_AUTHORS,
    MAX_CONTEXT_BYTES, MAX_FRAME_BYTES, MAX_HEADER_BYTES,
};

/// One slice of the one-time proof-cache reclamation of an old store
/// (`cleanup_history_proof_ranges`): object locators visited, and cache objects deleted.
const PROOF_CLEANUP_VISITS: usize = 4096;
const PROOF_CLEANUP_DELETES: usize = 256;

// One pool shared across every node, room, Store and read snapshot in the daemon.
// Descriptors are immutable serving math, never acceptance authority. Neither hits nor
// replacements change FIFO order.
const PROOF_CACHE_ENTRIES: usize = 8 * 1024;
const PROOF_CACHE_BYTES: usize = 8 * 1024 * 1024;
struct ProofCache {
    ranges: std::collections::HashMap<Digest32, Descriptor>,
    fifo: VecDeque<Digest32>,
}
// Reserve twice the entry cap, so eviction churn stays below half the table's load limit
// and tombstone cleanup rehashes rather than growing. Charge two complete backing tables
// (including transient rehash storage), control bytes/alignment, the FIFO and the container.
const PROOF_CACHE_CHARGE: usize =
    8 * PROOF_CACHE_ENTRIES * (std::mem::size_of::<(Digest32, Descriptor)>() + 1)
        + 128
        + PROOF_CACHE_ENTRIES * std::mem::size_of::<Digest32>()
        + std::mem::size_of::<ProofCache>();
const _: () = assert!(PROOF_CACHE_CHARGE <= PROOF_CACHE_BYTES);
static PROOF_CACHE: std::sync::Mutex<Option<ProofCache>> = std::sync::Mutex::new(None);

/// A descriptor verified or rebuilt under one signed head, kept under that head: the head may
/// be another branch of its author (unresolved, forked), so nothing else may read it.
pub(crate) fn cache_history_proof_range(
    head: Digest32,
    binding: TreeBinding,
    start: u64,
    descriptor: Descriptor,
) -> Result<()> {
    descriptor.validate()?;
    cache_proof_descriptor(
        proof_range_key(&head, binding, start, descriptor.leaves)?,
        descriptor,
    )
}

/// A descriptor rebuilt from the material of a committed source head while the author has no
/// conflict (`ProofRangeRestore`): a node's value depends only on the entries it spans, and
/// every committed head extends the one before, so it is kept by author, start and leaves and
/// found under every later committed head. In memory only (ADR-053 P rule 6); a range never
/// changes once its positions are committed, so nothing invalidates it.
pub(crate) fn cache_history_range(
    binding: TreeBinding,
    start: u64,
    descriptor: Descriptor,
) -> Result<()> {
    descriptor.validate()?;
    cache_proof_descriptor(
        cached_range_key(binding, start, descriptor.leaves)?,
        descriptor,
    )
}

/// A descriptor `cache_history_range` kept. Read only for a committed source (an unresolved
/// head may be another branch).
pub(crate) fn cached_history_range(
    binding: TreeBinding,
    start: u64,
    leaves: u64,
) -> Result<Option<Descriptor>> {
    let key = cached_range_key(binding, start, leaves)?;
    Ok(PROOF_CACHE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .and_then(|cache| cache.ranges.get(&key).copied()))
}

fn cache_proof_descriptor(key: Digest32, descriptor: Descriptor) -> Result<()> {
    let mut guard = PROOF_CACHE
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let cache = guard.get_or_insert_with(|| ProofCache {
        ranges: std::collections::HashMap::with_capacity(2 * PROOF_CACHE_ENTRIES),
        fifo: VecDeque::with_capacity(PROOF_CACHE_ENTRIES),
    });
    if let Some(old) = cache.ranges.get(&key) {
        if *old != descriptor {
            return Err(invalid("conflicting proof-serving range"));
        }
        return Ok(());
    }
    if cache.fifo.len() == PROOF_CACHE_ENTRIES {
        let oldest = cache
            .fifo
            .pop_front()
            .ok_or_else(|| invalid("proof cache FIFO is empty"))?;
        cache.ranges.remove(&oldest);
    }
    cache.ranges.insert(key, descriptor);
    cache.fifo.push_back(key);
    Ok(())
}

// Contexts a serving reconstruction generated for an asked prefix (ADR-053 P): request-only
// math, never acceptance evidence or a verification closure, so never a durable row. They stay
// in one daemon-wide FIFO bounded by bytes, keyed by room and content hash, for the joins of the
// same reconstruction and for the asker's `Query::Context`; eviction loses only serving work.
const SERVING_CONTEXT_BYTES: usize = 8 * 1024 * 1024;
struct ServingContexts {
    contexts: std::collections::HashMap<(Digest32, Digest32), ControlContext>,
    fifo: VecDeque<((Digest32, Digest32), usize)>,
    bytes: usize,
}
static SERVING_CONTEXTS: std::sync::Mutex<Option<ServingContexts>> = std::sync::Mutex::new(None);

/// The charge of one cached context: its coordinates, the value, both FIFO and table keys and
/// a conservative table slot overhead.
fn serving_context_bytes(context: &ControlContext) -> usize {
    context.coordinates.len() * std::mem::size_of::<crate::log::history::EntryReference>()
        + 2 * std::mem::size_of::<ControlContext>()
        + 4 * std::mem::size_of::<((Digest32, Digest32), usize)>()
}

pub(crate) fn cache_serving_context(context: &ControlContext) {
    let key = (context.room, context.hash());
    let bytes = serving_context_bytes(context);
    let mut guard = SERVING_CONTEXTS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let cache = guard.get_or_insert_with(|| ServingContexts {
        contexts: std::collections::HashMap::new(),
        fifo: VecDeque::new(),
        bytes: 0,
    });
    if cache.contexts.contains_key(&key) {
        return;
    }
    while cache.bytes + bytes > SERVING_CONTEXT_BYTES {
        let Some((oldest, size)) = cache.fifo.pop_front() else {
            return;
        };
        cache.contexts.remove(&oldest);
        cache.bytes -= size;
    }
    cache.contexts.insert(key, context.clone());
    cache.fifo.push_back((key, bytes));
    cache.bytes += bytes;
}

/// A context a serving reconstruction generated in this room, while it is still cached.
pub(crate) fn serving_context(room: &Digest32, hash: &Digest32) -> Option<ControlContext> {
    SERVING_CONTEXTS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .and_then(|cache| cache.contexts.get(&(*room, *hash)).cloned())
}

/// Locally signed material verified by the same v2 proof primitives. Only the final
/// contiguous publication transaction may attach it to the newly active roots.
pub(crate) struct LocalHistoryPublication<'a> {
    pub entry: &'a Entry,
    pub header: &'a VerifiedHeader,
    pub head: &'a VerifiedHead,
    pub consistency: &'a ConsistentPrefix,
    pub included: &'a IncludedHeader,
    pub pre_context: &'a ControlContext,
    pub post_context: &'a ControlContext,
    pub ranges: &'a [(u64, Descriptor)],
}

/// Exact locally verified publication whose semantic effects may be marked settled only in
/// the same append transaction. Fields stay private so no remote or merely observed entry can
/// manufacture local completion.
#[must_use]
pub(crate) struct LocalHistorySettlement {
    entry: Digest32,
    head: Digest32,
    author: Digest32,
    seq: u64,
}

const MAX_OBLIGATIONS: u64 = 4096;
const STATE_BYTES: usize = 256;

/// Whether a bodyless authenticated source still owes its body to this node's role. Ordinary
/// content and a package addressed here are owed; a package addressed only to another member is
/// complete here after its signed header/effect is accepted, and its private body must stay away.
fn body_owed_to(entry: &Entry, local_id: &Digest32) -> bool {
    if entry.payload.is_some() {
        return false;
    }
    !entry.skeleton.v2.as_ref().is_some_and(|v2| {
        v2.kind == crate::log::history::SignedEntryKind::KeyPackage
            && v2.recipient.is_some_and(|recipient| recipient != *local_id)
    })
}

fn expected_entry_wire(header: &Entry) -> Result<usize> {
    let length = usize::try_from(header.skeleton.payload_len)
        .map_err(|_| invalid("history payload length"))?;
    if length > crate::log::history::MAX_PAYLOAD_BYTES {
        return Err(invalid("history payload exceeds format bound"));
    }
    length
        .checked_add(MAX_HEADER_BYTES + 9)
        .ok_or(invalid("history entry size overflow"))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Roots {
    objects: u64,
    authors: u64,
    pub(super) validated_positions: u64,
    /// Control facts, keyed by AUTHOR (`control_prefix_complete`): coverage runs
    /// (`keep_control_run`), enumerated control sources, and the source and effect prefixes.
    /// A store written before format 14 kept them by head; its one-time reindex merges those of
    /// committed heads into the author's rows (`migrate_control_chunk`).
    control_intervals: u64,
    obligations: u64,
    key_body_obligations: u64,
    // Retired provider cursor directory slot; retain it for existing stores.
    key_body_providers: u64,
    key_body_debt_order: u64,
    key_body_debt_serial: u64,
    ranges: u64,
    commitments: u64,
    source_heads: u64,
    control_sources: u64,
    source_prefixes: u64,
    /// Kept only for the directory format: no longer read or written (the walk finds the run
    /// holding its prefix + 1 by one seek, `keep_control_run`).
    retired_source_cursors: u64,
    settled_entries: u64,
    effect_prefixes: u64,
    /// As `retired_source_cursors`.
    retired_effect_cursors: u64,
    terminations: u64,
    settled_tips: u64,
    prior_heads: u64,
    /// One current refused inventory head per `(source peer, author)`.
    declined_heads: u64,
    author_count: u64,
    obligation_count: u64,
    pub(super) enabled: bool,
}

impl Roots {
    pub(super) fn write(self, e: &mut Encoder) {
        e.array(25)
            .uint(self.objects)
            .uint(self.authors)
            .uint(self.validated_positions)
            .uint(self.control_intervals)
            .uint(self.obligations)
            .uint(self.ranges)
            .uint(self.commitments)
            .uint(self.source_heads)
            .uint(self.control_sources)
            .uint(self.source_prefixes)
            .uint(self.retired_source_cursors)
            .uint(self.settled_entries)
            .uint(self.effect_prefixes)
            .uint(self.retired_effect_cursors)
            .uint(self.terminations)
            .uint(self.settled_tips)
            .uint(self.prior_heads)
            .uint(self.declined_heads)
            .uint(self.key_body_obligations)
            .uint(self.key_body_providers)
            .uint(self.key_body_debt_order)
            .uint(self.key_body_debt_serial)
            .uint(self.author_count)
            .uint(self.obligation_count)
            .uint(u64::from(self.enabled));
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        let arity = d.array()?;
        if matches!(arity, 20..=23) {
            return Err(Error::Profile(super::super::UNSUPPORTED_ROOM_FORMAT));
        }
        if arity != 25 {
            return Err(invalid("sparse roots arity"));
        }
        let mut result = Self {
            objects: d.uint()?,
            authors: d.uint()?,
            validated_positions: d.uint()?,
            control_intervals: d.uint()?,
            obligations: d.uint()?,
            key_body_obligations: 0,
            key_body_providers: 0,
            key_body_debt_order: 0,
            key_body_debt_serial: 0,
            ranges: d.uint()?,
            commitments: d.uint()?,
            source_heads: d.uint()?,
            control_sources: d.uint()?,
            source_prefixes: d.uint()?,
            retired_source_cursors: d.uint()?,
            settled_entries: d.uint()?,
            effect_prefixes: d.uint()?,
            retired_effect_cursors: d.uint()?,
            terminations: d.uint()?,
            settled_tips: d.uint()?,
            prior_heads: d.uint()?,
            declined_heads: 0,
            author_count: 0,
            obligation_count: 0,
            enabled: false,
        };
        if arity >= 21 {
            result.declined_heads = d.uint()?;
        }
        if arity >= 22 {
            result.key_body_obligations = d.uint()?;
        }
        if arity >= 23 {
            result.key_body_providers = d.uint()?;
        }
        result.key_body_debt_order = d.uint()?;
        result.key_body_debt_serial = d.uint()?;
        result.author_count = d.uint()?;
        result.obligation_count = d.uint()?;
        result.enabled = flag(d)?;
        Ok(result)
    }
    pub(super) fn valid_for(self, next: u64) -> bool {
        [
            self.objects,
            self.authors,
            self.validated_positions,
            self.control_intervals,
            self.obligations,
            self.ranges,
            self.commitments,
            self.source_heads,
            self.control_sources,
            self.source_prefixes,
            self.retired_source_cursors,
            self.settled_entries,
            self.effect_prefixes,
            self.retired_effect_cursors,
            self.terminations,
            self.settled_tips,
            self.prior_heads,
            self.declined_heads,
            self.key_body_obligations,
            self.key_body_providers,
            self.key_body_debt_order,
        ]
        .iter()
        .all(|root| *root < next)
            && self.author_count <= MAX_CONTEXT_AUTHORS as u64
            && self.obligation_count <= MAX_OBLIGATIONS
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ObjectKind {
    Context = 0,
    Head = 1,
    Header = 2,
    Verifier = 4,
    ParentReceipt = 5,
    InclusionReceipt = 6,
    PrefixReceipt = 7,
    PendingHeader = 8,
    // Exact-head serving pieces a held inclusion/prefix receipt needs to be served again
    // (written with that receipt); never used by acceptance or authored appends.
    ProofRange = 9,
    // A context actually supplied by a proof of this returning author's public head.
    RecoveryContext = 10,
    // MP-9 (rule 6): per author, the id of the one signed head whose continuity with the
    // accepted chain is unresolved. A local owner of a retained Head object, never authority.
    Unresolved = 11,
    // The committed head under which a parent receipt for an author's position is kept.
    ParentHead = 12,
    // The first head of the author's accepted chain under which an inclusion receipt for an
    // author's position is kept (`history_included_header`).
    IncludedHead = 13,
}
impl ObjectKind {
    pub(crate) const fn limit(self) -> usize {
        match self {
            Self::Context => MAX_CONTEXT_BYTES,
            Self::ProofRange => STATE_BYTES,
            Self::RecoveryContext | Self::Unresolved | Self::ParentHead | Self::IncludedHead => 32,
            Self::Head | Self::Header | Self::PendingHeader => MAX_HEADER_BYTES,
            Self::Verifier => MAX_FRAME_BYTES + 12 * MAX_HEADER_BYTES + 512,
            Self::ParentReceipt | Self::InclusionReceipt | Self::PrefixReceipt => {
                4 * MAX_HEADER_BYTES
            }
        }
    }
}
fn object_key(kind: ObjectKind, hash: &Digest32) -> Key {
    let mut key = hashed(hash);
    key[32] = kind as u8;
    key
}
fn recovery_context_key(author: &Digest32, context: &Digest32) -> Digest32 {
    let mut input = b"vox/own-recovery-context/v1".to_vec();
    input.extend_from_slice(author);
    input.extend_from_slice(context);
    sha256(&input)
}
fn unresolved_key(author: &Digest32) -> Digest32 {
    let mut input = b"vox/local-unresolved-head/v1".to_vec();
    input.extend_from_slice(author);
    sha256(&input)
}

fn author_key(author: &Digest32, scope: LogScope) -> Key {
    let mut key = hashed(author);
    key[32] = scope as u8;
    key
}
/// A full aligned block: `leaves` is a power of two and the block starts at a multiple of it, so
/// it is one complete subtree, the same node in every tree over positions that contains it.
pub(crate) fn full_block(start: u64, leaves: u64) -> bool {
    start != 0 && leaves.is_power_of_two() && (start - 1).is_multiple_of(leaves)
}
fn range_key(binding: TreeBinding, start: u64, leaves: u64) -> Result<Key> {
    if start == 0
        || leaves == 0
        || start
            .checked_add(leaves - 1)
            .is_none_or(|n| n > crate::log::feed::MAX_SEQ)
    {
        return Err(invalid("sparse tree range bounds"));
    }
    let mut key = position(&binding.author, start);
    key[40..48].copy_from_slice(&leaves.to_be_bytes());
    key[48] = binding.scope as u8;
    Ok(key)
}
fn proof_range_key(
    head: &Digest32,
    binding: TreeBinding,
    start: u64,
    leaves: u64,
) -> Result<Digest32> {
    let _ = range_key(binding, start, leaves)?;
    let mut e = Encoder::new();
    e.array(5).bytes(b"vox/proof-serving-range/v1").bytes(head);
    binding.encode(&mut e);
    e.uint(start).uint(leaves);
    Ok(sha256(&e.finish()))
}
/// The in-memory key of a rebuilt range of the accepted chain (`cache_history_range`); a
/// different tag from `proof_range_key`, so no head-keyed descriptor is ever found by it.
fn cached_range_key(binding: TreeBinding, start: u64, leaves: u64) -> Result<Digest32> {
    let _ = range_key(binding, start, leaves)?;
    let mut e = Encoder::new();
    e.array(4).bytes(b"vox/proof-serving-position/v1");
    binding.encode(&mut e);
    e.uint(start).uint(leaves);
    Ok(sha256(&e.finish()))
}
fn decode_proof_range(
    bytes: &[u8],
    head: &Digest32,
    binding: TreeBinding,
    start: u64,
    leaves: u64,
) -> Result<Descriptor> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 5
        || d.uint()? != 1
        || d.bytes()? != head
        || TreeBinding::decode(&mut d)? != binding
        || d.uint()? != start
    {
        return Err(invalid("proof-serving range binding"));
    }
    let value = Descriptor::decode(&mut d)?;
    d.finish()?;
    if value.leaves != leaves {
        return Err(invalid("proof-serving range length"));
    }
    Ok(value)
}

fn hash_option(e: &mut Encoder, value: Option<Digest32>) {
    match value {
        Some(hash) => {
            e.array(1).bytes(&hash);
        }
        None => {
            e.array(0);
        }
    }
}
fn read_hash(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?.try_into().map_err(|_| invalid("sparse digest"))
}
fn read_hash_option(d: &mut Decoder<'_>) -> Result<Option<Digest32>> {
    match d.array()? {
        0 => Ok(None),
        1 => Ok(Some(read_hash(d)?)),
        _ => Err(invalid("sparse digest option")),
    }
}

/// A newcomer's walk floor for an author whose committed size is `size`: the lowest of its
/// newest 128 positions (ADR-052 RG-6).
fn newcomer_floor(size: u64) -> u64 {
    size.saturating_sub(crate::log::history::MAX_PAGE_ENTRIES as u64 - 1)
        .max(1)
}

/// Compact exact object references. None of these is a contiguous feed position.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AuthorState {
    pub observed: Option<Digest32>,
    pub committed: Option<Digest32>,
    /// One attributable same-size contradiction, retaining both exact signed heads.
    pub observed_conflict: Option<(Digest32, Digest32)>,
    /// The walk's floor (ADR-052 RG-6), 0 until set: set once, by the author's first non-empty
    /// committed head, to the lowest of its newest 128 positions, so a newcomer is never made
    /// to read from message one; for a store written before floors existed, at its upgrade, from
    /// what this member held of the author (`followed_floor`). Nothing below it is owed; it
    /// never moves afterwards.
    pub floor: u64,
}
impl AuthorState {
    /// Version 4. Slot 3 is retired: it held `control_ready`, one head id, which a store
    /// written by an older version still carries and which only that store's one-time upgrade
    /// reads, into the author's effect prefix (`migrate_control_ready`; control readiness is
    /// that prefix, `history_control_ready`). Version 3's slot 5 held a whole
    /// window (head, from, next, through) of which only `from`, the floor, is still read.
    fn bytes(self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(6).uint(4);
        hash_option(&mut e, self.observed);
        hash_option(&mut e, self.committed);
        hash_option(&mut e, None);
        match self.observed_conflict {
            Some((first, second)) => {
                e.array(2).bytes(&first).bytes(&second);
            }
            None => {
                e.array(0);
            }
        }
        e.uint(self.floor);
        e.finish()
    }
    fn parse(bytes: &[u8]) -> Result<Self> {
        Self::parse_with_control_ready(bytes).map(|(state, _)| state)
    }
    /// The record and its retired slot 3, which only the upgrade of an older store reads
    /// (`migrate_control_ready`); version 4 writes it empty.
    fn parse_with_control_ready(bytes: &[u8]) -> Result<(Self, Option<Digest32>)> {
        if bytes.len() > STATE_BYTES {
            return Err(invalid("sparse author state size"));
        }
        let mut d = Decoder::new(bytes);
        let arity = d.array()?;
        let version = d.uint()?;
        if !matches!((arity, version), (4, 1) | (5, 2) | (6, 3) | (6, 4)) {
            return Err(invalid("sparse author state format"));
        }
        let observed = read_hash_option(&mut d)?;
        let committed = read_hash_option(&mut d)?;
        let control_ready = read_hash_option(&mut d)?;
        let observed_conflict = if version >= 2 {
            match d.array()? {
                0 => None,
                2 => {
                    let pair = (read_hash(&mut d)?, read_hash(&mut d)?);
                    if pair.0 == pair.1 {
                        return Err(invalid("observed conflict heads equal"));
                    }
                    Some(pair)
                }
                _ => return Err(invalid("observed conflict arity")),
            }
        } else {
            None
        };
        let floor = match version {
            4 => d.uint()?,
            3 => match d.array()? {
                0 => 0,
                1 => {
                    if d.array()? != 4 {
                        return Err(invalid("live history window arity"));
                    }
                    let _retired_head = read_hash(&mut d)?;
                    let (from, next, through) = (d.uint()?, d.uint()?, d.uint()?);
                    if from == 0
                        || through > crate::log::feed::MAX_SEQ
                        || from > through.saturating_add(1)
                        || next > through
                        || next.saturating_add(1) < from
                    {
                        return Err(invalid("live history window bounds"));
                    }
                    from
                }
                _ => return Err(invalid("live history window option")),
            },
            _ => 0,
        };
        d.finish()?;
        if floor > crate::log::feed::MAX_SEQ {
            return Err(invalid("history walk floor"));
        }
        Ok((
            Self {
                observed,
                committed,
                observed_conflict,
                floor,
            },
            control_ready,
        ))
    }
}

/// Why exact-head verification remains pending. Coordinates are requirements, never evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObligationKind {
    Context,
    ParentReceipt,
    ControlRange,
    ControlBody,
    Authority,
    KeyBody,
    Verifier,
}
impl ObligationKind {
    fn code(self) -> u64 {
        match self {
            Self::Context => 0,
            Self::ParentReceipt => 1,
            Self::ControlRange => 2,
            Self::ControlBody => 3,
            Self::Authority => 4,
            Self::KeyBody => 5,
            Self::Verifier => 6,
        }
    }
    fn read(n: u64) -> Result<Self> {
        match n {
            0 => Ok(Self::Context),
            1 => Ok(Self::ParentReceipt),
            2 => Ok(Self::ControlRange),
            3 => Ok(Self::ControlBody),
            4 => Ok(Self::Authority),
            5 => Ok(Self::KeyBody),
            6 => Ok(Self::Verifier),
            _ => Err(invalid("sparse obligation kind")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Obligation {
    pub head: Digest32,
    pub kind: ObligationKind,
    pub object: Digest32,
    pub author: Digest32,
    pub from: u64,
    pub through: u64,
}
impl Obligation {
    fn authority(head: Digest32, entry: &Entry) -> Self {
        Self {
            head,
            kind: ObligationKind::Authority,
            object: entry.entry_hash(),
            author: entry.skeleton.author_id,
            from: entry.skeleton.seq,
            through: entry.skeleton.seq,
        }
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        if self.from > self.through || self.through > crate::log::feed::MAX_SEQ {
            return Err(invalid("sparse obligation interval"));
        }
        let mut e = Encoder::new();
        e.array(7)
            .uint(1)
            .bytes(&self.head)
            .uint(self.kind.code())
            .bytes(&self.object)
            .bytes(&self.author)
            .uint(self.from)
            .uint(self.through);
        Ok(e.finish())
    }
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > STATE_BYTES {
            return Err(invalid("sparse obligation size"));
        }
        let mut d = Decoder::new(bytes);
        if d.array()? != 7 || d.uint()? != 1 {
            return Err(invalid("sparse obligation format"));
        }
        let result = Self {
            head: read_hash(&mut d)?,
            kind: ObligationKind::read(d.uint()?)?,
            object: read_hash(&mut d)?,
            author: read_hash(&mut d)?,
            from: d.uint()?,
            through: d.uint()?,
        };
        d.finish()?;
        result.bytes()?;
        Ok(result)
    }
    fn key(&self) -> Result<Key> {
        let mut key = [0; 64];
        let digest = sha256(&self.bytes()?);
        match self.kind {
            ObligationKind::KeyBody => {
                // Key bodies use their own tree and retain the full obligation identity.
                key[0] = 0;
                key[1..33].copy_from_slice(&digest);
            }
            _ => {
                key[..32].copy_from_slice(&self.head);
                key[32..].copy_from_slice(&digest);
            }
        }
        Ok(key)
    }
}

impl Source<'_> {
    pub(super) fn sparse_effect_finished(
        &self,
        sek: &Sek,
        room: &Digest32,
        roots: Roots,
        hash: &Digest32,
    ) -> Result<bool> {
        Ok(
            self.find_value(sek, room, roots.settled_entries, &hashed(hash))?
                == Some(Value::Present),
        )
    }
    pub(super) fn published_sparse_entry(
        &self,
        sek: &Sek,
        room: &Digest32,
        roots: super::Roots,
        hash: &Digest32,
    ) -> Result<Option<Entry>> {
        if !roots.sparse.enabled
            || self.find_value(sek, room, roots.sparse.settled_entries, &hashed(hash))?
                != Some(Value::Present)
        {
            return Ok(None);
        }
        let at = self
            .find(sek, room, roots.hash, &hashed(hash))?
            .ok_or(invalid("published sparse source missing locator"))?;
        let header = self
            .sparse_header(sek, room, roots.sparse, hash)?
            .ok_or(invalid("published sparse header missing"))?;
        let wire = self.history_wire(
            sek,
            room,
            SegmentKind::LogDb,
            at.log,
            expected_entry_wire(&header)?,
        )?;
        let entry = Entry::from_wire(&wire)?;
        if entry.entry_hash() != *hash
            || entry.skeleton.channel_id != *room
            || entry.skeleton.author_id != at.author
            || entry.skeleton.seq != at.seq
            || entry.skeleton.v2.is_none()
        {
            return Err(invalid("published sparse source differs from locator"));
        }
        Ok(Some(entry))
    }
    pub(super) fn history_wire(
        &self,
        sek: &Sek,
        room: &Digest32,
        kind: SegmentKind,
        id: u64,
        limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let sealed = match self {
            Self::Snapshot(s) | Self::Cached(s, _) | Self::OtherSnapshot(s, _) => {
                s.get_segment_bounded(room, kind, id, limit)?
            }
            Self::Batch(b) | Self::OtherBatch(b, _) => {
                b.get_segment_bounded(room, kind, id, limit)?
            }
        }
        .ok_or(invalid("history record missing"))?;
        if sealed.ciphertext.len() > limit + 16 {
            return Err(invalid("history sealed record size"));
        }
        let bytes = open_segment(sek, kind, id, &sealed)?;
        if bytes.len() > limit {
            return Err(invalid("history record size"));
        }
        Ok(bytes)
    }
    pub(super) fn sparse_position_header(
        &self,
        sek: &Sek,
        room: &Digest32,
        roots: Roots,
        author: &Digest32,
        seq: u64,
    ) -> Result<Option<Entry>> {
        self.number(sek, room, roots.validated_positions, &position(author, seq))?
            .map(|id| {
                let entry =
                    Entry::from_wire(&self.sparse_record(sek, room, id, MAX_HEADER_BYTES)?)?;
                if entry.skeleton.channel_id != *room
                    || entry.skeleton.author_id != *author
                    || entry.skeleton.seq != seq
                    || entry.skeleton.v2.is_none()
                    || entry.payload.is_some()
                {
                    return Err(invalid("sparse validated header binding"));
                }
                Ok(entry)
            })
            .transpose()
    }
    pub(super) fn sparse_header(
        &self,
        sek: &Sek,
        room: &Digest32,
        roots: Roots,
        hash: &Digest32,
    ) -> Result<Option<Entry>> {
        self.number(
            sek,
            room,
            roots.objects,
            &object_key(ObjectKind::Header, hash),
        )?
        .map(|id| {
            let entry = Entry::from_wire(&self.sparse_record(sek, room, id, MAX_HEADER_BYTES)?)?;
            if entry.skeleton.channel_id != *room
                || entry.entry_hash() != *hash
                || entry.skeleton.v2.is_none()
                || entry.payload.is_some()
            {
                return Err(invalid("stored sparse header binding"));
            }
            Ok(entry)
        })
        .transpose()
    }
    fn sparse_head(
        &self,
        sek: &Sek,
        room: &Digest32,
        roots: Roots,
        hash: &Digest32,
    ) -> Result<Option<SignedHead>> {
        self.number(
            sek,
            room,
            roots.objects,
            &object_key(ObjectKind::Head, hash),
        )?
        .map(|id| {
            let head =
                SignedHead::from_wire(&self.sparse_record(sek, room, id, MAX_HEADER_BYTES)?)?;
            if head.binding.room != *room || head.id() != *hash {
                return Err(invalid("stored head binding"));
            }
            Ok(head)
        })
        .transpose()
    }
    pub(super) fn sparse_context(
        &self,
        sek: &Sek,
        room: &Digest32,
        roots: Roots,
        hash: &Digest32,
    ) -> Result<Option<ControlContext>> {
        self.number(
            sek,
            room,
            roots.objects,
            &object_key(ObjectKind::Context, hash),
        )?
        .map(|id| {
            let context = ControlContext::from_wire(&self.sparse_record(
                sek,
                room,
                id,
                MAX_CONTEXT_BYTES,
            )?)?;
            if context.room != *room || context.hash() != *hash {
                return Err(invalid("stored context binding"));
            }
            Ok(context)
        })
        .transpose()
    }
    /// The caller's worker owns its buffer permit before this copy/decryption. No object cache
    /// is retained here; bounds are checked before AEAD and again by each canonical decoder.
    fn sparse_record(
        &self,
        sek: &Sek,
        room: &Digest32,
        id: u64,
        limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let sealed = match self {
            Self::Snapshot(s) | Self::Cached(s, _) | Self::OtherSnapshot(s, _) => {
                s.get_segment_bounded(room, SegmentKind::EntryIndex, id, limit)?
            }
            Self::Batch(b) | Self::OtherBatch(b, _) => {
                b.get_segment_bounded(room, SegmentKind::EntryIndex, id, limit)?
            }
        }
        .ok_or(invalid("sparse record missing"))?;
        if sealed.ciphertext.len() > limit + 16 {
            return Err(invalid("sparse sealed record size"));
        }
        let bytes = open_segment(sek, SegmentKind::EntryIndex, id, &sealed)?;
        if bytes.len() > limit {
            return Err(invalid("sparse record size"));
        }
        Ok(bytes)
    }
    fn sparse_author(
        &self,
        sek: &Sek,
        room: &Digest32,
        roots: Roots,
        author: &Digest32,
        scope: LogScope,
    ) -> Result<Option<AuthorState>> {
        self.number(sek, room, roots.authors, &author_key(author, scope))?
            .map(|id| AuthorState::parse(&self.sparse_record(sek, room, id, STATE_BYTES)?))
            .transpose()
    }
    /// `head` is in its author's accepted chain (`Read::history_head_accepted`): committed here,
    /// or shorter than the committed head with its root equal to the kept range [1, n].
    fn sparse_head_accepted(
        &self,
        sek: &Sek,
        room: &Digest32,
        roots: Roots,
        head: &SignedHead,
    ) -> Result<bool> {
        let binding = head.binding;
        if binding.room != *room {
            return Ok(false);
        }
        if self.find_value(sek, room, roots.commitments, &hashed(&head.id()))?
            == Some(Value::Present)
        {
            return Ok(true);
        }
        let Some(current_id) = self
            .sparse_author(sek, room, roots, &binding.author, binding.scope)?
            .and_then(|state| state.committed)
        else {
            return Ok(false);
        };
        let Some(current) = self.sparse_head(sek, room, roots, &current_id)? else {
            return Err(invalid("accepted head missing"));
        };
        if current.binding != binding || head.root.leaves >= current.root.leaves {
            return Ok(false);
        }
        let prefix = if head.root.leaves == 0 {
            Descriptor::empty(binding)
        } else {
            let key = range_key(binding, 1, head.root.leaves)?;
            let Some(id) = self.number(sek, room, roots.ranges, &key)? else {
                return Ok(false);
            };
            let bytes = self.sparse_record(sek, room, id, STATE_BYTES)?;
            let mut decoder = Decoder::new(&bytes);
            let descriptor = Descriptor::decode(&mut decoder)?;
            decoder.finish()?;
            if descriptor.leaves != head.root.leaves {
                return Err(invalid("stored tree range length"));
            }
            descriptor
        };
        Ok(prefix == head.root)
    }
}

fn key_debt_order(serial: u64) -> Key {
    let mut key = [0; 64];
    key[0] = 0;
    key[1..9].copy_from_slice(&serial.to_be_bytes());
    key
}
fn key_debt_reverse(obligation: &Obligation) -> Result<Key> {
    let mut key = [0; 64];
    key[0] = 1;
    key[1..33].copy_from_slice(&sha256(&obligation.key()?));
    Ok(key)
}

fn key_debt_expiry(claimed_ms: u64, serial: u64) -> Key {
    let mut key = [0; 64];
    key[0] = 2;
    key[1..9].copy_from_slice(&claimed_ms.to_be_bytes());
    key[9..17].copy_from_slice(&serial.to_be_bytes());
    key
}
fn key_debt_claim(serial: u64) -> Key {
    let mut key = [0; 64];
    key[0] = 3;
    key[1..9].copy_from_slice(&serial.to_be_bytes());
    key
}

impl Directory {
    fn sparse_publication_source(&self) -> Result<Option<(Digest32, u64)>> {
        let Some(promotion) = &self.promotion else {
            return Ok(None);
        };
        if promotion.sparse_head.is_none() {
            return Ok(None);
        }
        Ok(Some((promotion.witness_hash, promotion.first_log)))
    }

    fn sparse_publication_request(&self) -> Option<[u8; 16]> {
        self.promotion
            .as_ref()
            .and_then(|promotion| promotion.sparse_request)
    }
}

impl View<'_, '_> {
    pub(crate) fn sparse_publication_source(&self) -> Result<Option<(Digest32, u64)>> {
        self.directory.sparse_publication_source()
    }

    pub(crate) fn sparse_publication_request(&self) -> Option<[u8; 16]> {
        self.directory.sparse_publication_request()
    }
}

impl Read<'_> {
    pub(crate) fn expired_key_debts(&self, cutoff: u64, limit: usize) -> Result<Vec<Obligation>> {
        if limit > 16 {
            return Err(invalid("key debt expiry page limit"));
        }
        let source = self.source();
        let mut seek = key_debt_expiry(0, 0);
        let mut debts = Vec::with_capacity(limit);
        for _ in 0..limit {
            let Some((key, value)) = source.first(
                self.sek,
                self.channel,
                self.directory.active.sparse.key_body_debt_order,
                &seek,
                0,
            )?
            else {
                break;
            };
            if key[0] != 2 {
                break;
            }
            if key[17..].iter().any(|v| *v != 0) {
                return Err(invalid("key debt expiry key"));
            }
            let claimed = u64::from_be_bytes(
                key[1..9]
                    .try_into()
                    .map_err(|_| invalid("key debt claim"))?,
            );
            if claimed > cutoff {
                break;
            }
            let Value::Number(id) = value else {
                return Err(invalid("key debt expiry locator"));
            };
            let debt = Obligation::parse(&source.sparse_record(
                self.sek,
                self.channel,
                id,
                STATE_BYTES,
            )?)?;
            if debt.kind != ObligationKind::KeyBody {
                return Err(invalid("key debt expiry kind"));
            }
            debts.push(debt);
            let Some(next) = dag_facts::successor(key) else {
                break;
            };
            seek = next;
        }
        Ok(debts)
    }

    /// Whether the published entry `hash` carries its body here. The one fact of possession for
    /// a key package: serving sends exactly this body or answers that it is not held
    /// (`ServedRoom::history_payload`), and the held record advertises it so
    /// (`HeldAuthor::position`), whatever a body debt or the missing set says.
    pub(crate) fn history_body_stored(&self, hash: &Digest32) -> Result<bool> {
        Ok(self
            .history_entry(hash)?
            .is_some_and(|entry| entry.payload.is_some()))
    }

    pub(crate) fn sparse_history_instance(&self) -> [u8; 16] {
        self.directory.history_instance
    }
    pub(crate) fn history_settled_tip(&self, author: &Digest32) -> Result<Option<Entry>> {
        let source = self.source();
        let Some(id) = source.number(
            self.sek,
            self.channel,
            self.directory.active.sparse.settled_tips,
            &hashed(author),
        )?
        else {
            return Ok(None);
        };
        let wire = source.sparse_record(self.sek, self.channel, id, MAX_HEADER_BYTES)?;
        let header = Entry::from_wire(&wire)?;
        if header.skeleton.channel_id != *self.channel
            || header.skeleton.author_id != *author
            || header.skeleton.v2.is_none()
            || !self.history_effect_finished(&header.entry_hash())?
        {
            return Err(invalid("settled sparse tip binding"));
        }
        Ok(Some(header))
    }
    /// The live body debt of the package published at `author`/`seq`: the durable KeyBody
    /// obligation keyed by its accepted entry (its fixed validated source head, author,
    /// position and entry hash), with that source head and header; `None` when nothing is owed.
    /// No head of the author but the entry's own source names it, so a later head neither
    /// recreates nor loses it, and a body missing everywhere leaves it owed.
    pub(crate) fn history_key_body_owed_at(
        &self,
        author: &Digest32,
        seq: u64,
    ) -> Result<Option<(Digest32, Entry)>> {
        let Some((head, entry)) = self.history_validated_header(author, seq)? else {
            return Ok(None);
        };
        let obligation = Obligation {
            head,
            kind: ObligationKind::KeyBody,
            object: entry.entry_hash(),
            author: *author,
            from: seq,
            through: seq,
        };
        let owed = self
            .source()
            .number(
                self.sek,
                self.channel,
                self.directory.active.sparse.key_body_obligations,
                &obligation.key()?,
            )?
            .is_some();
        Ok(owed.then_some((head, entry)))
    }

    pub(crate) fn history_effect_finished(&self, hash: &Digest32) -> Result<bool> {
        Ok(self.source().find_value(
            self.sek,
            self.channel,
            self.directory.active.sparse.settled_entries,
            &hashed(hash),
        )? == Some(Value::Present))
    }
    /// The last authenticated, semantically complete contiguous position of this author's
    /// public feed for this node's role. Unlike `settled_tips`, this cannot jump across an
    /// unfinished predecessor. The hash binds a receipt to the exact accepted position.
    pub(crate) fn history_held_through(&self, author: &Digest32) -> Option<(u64, Digest32)> {
        self.directory
            .restart
            .as_ref()
            .and_then(|state| state.feeds.get(author))
            .map(|feed| (feed.seq, feed.hash))
    }
    pub(crate) fn control_effects_complete(&self, head: &Digest32, through: u64) -> Result<bool> {
        self.control_prefix_complete(self.directory.active.sparse.effect_prefixes, head, through)
    }
    /// The author's control effects are complete through its whole committed head: its effect
    /// prefix, kept by author (`control_prefix_complete`), reaches the committed size. One
    /// predicate by position: whichever head's walk advanced the prefix, it holds as soon as
    /// the prefix reaches the size, and no head id has to be republished.
    pub(crate) fn history_control_ready(&self, author: &Digest32, scope: LogScope) -> Result<bool> {
        let Some(committed) = self
            .sparse_author(author, scope)?
            .and_then(|state| state.committed)
        else {
            return Ok(false);
        };
        let head = self
            .history_head(&committed)?
            .ok_or(invalid("committed history head missing"))?;
        Ok(self
            .source()
            .number(
                self.sek,
                self.channel,
                self.directory.active.sparse.effect_prefixes,
                &hashed(author),
            )?
            .unwrap_or(0)
            >= head.root.leaves)
    }
    /// A control prefix receipt `root` holds through `through` for committed `head`. Control
    /// facts are kept per AUTHOR, not per head: which positions are controls (coverage), and how
    /// far its controls are admitted (sources, effects), are facts about the author's positions,
    /// proven once under a committed head and true under every later one, since each committed
    /// head extends the one before (`commit_history_head`; a fork commits nothing). So the
    /// answer never changes when the author's head moves.
    fn control_prefix_complete(&self, root: u64, head: &Digest32, through: u64) -> Result<bool> {
        let source = self.source();
        if source.find_value(
            self.sek,
            self.channel,
            self.directory.active.sparse.commitments,
            &hashed(head),
        )? != Some(Value::Present)
        {
            return Ok(false);
        }
        let Some(target) = self.history_head(head)? else {
            return Ok(false);
        };
        if through > target.root.leaves {
            return Ok(false);
        }
        Ok(source
            .number(
                self.sek,
                self.channel,
                root,
                &hashed(&target.binding.author),
            )?
            .unwrap_or(0)
            >= through)
    }
    pub(crate) fn history_author_after(
        &self,
        after: Option<Digest32>,
    ) -> Result<Option<(Digest32, AuthorState)>> {
        let mut key = after.map_or([0; 64], |author| author_key(&author, LogScope::Public));
        if after.is_some() {
            let Some(next) = dag_facts::successor(key) else {
                return Ok(None);
            };
            key = next;
        }
        let source = self.source();
        let Some((key, Value::Number(record))) = source.first(
            self.sek,
            self.channel,
            self.directory.active.sparse.authors,
            &key,
            0,
        )?
        else {
            return Ok(None);
        };
        if key[32] != LogScope::Public as u8 || key[33..].iter().any(|v| *v != 0) {
            return Err(invalid("sparse author key"));
        }
        let author = key[..32]
            .try_into()
            .map_err(|_| invalid("sparse author identity"))?;
        let state = AuthorState::parse(&source.sparse_record(
            self.sek,
            self.channel,
            record,
            STATE_BYTES,
        )?)?;
        Ok(Some((author, state)))
    }
    pub(crate) fn publication_busy(&self) -> bool {
        self.directory.phase != Phase::Idle
    }

    pub(crate) fn sparse_publication_source(&self) -> Result<Option<(Digest32, u64)>> {
        self.directory.sparse_publication_source()
    }
    pub(crate) fn sparse_publication_request(&self) -> Option<[u8; 16]> {
        self.directory.sparse_publication_request()
    }
    /// A consistency-accepted exact head, including an older accepted head for which a
    /// verification cursor is still finishing. Observed hints do not satisfy this lookup.
    pub(crate) fn history_head_committed(
        &self,
        head: &Digest32,
        binding: TreeBinding,
    ) -> Result<bool> {
        if binding.room != *self.channel {
            return Ok(false);
        }
        if self.source().find_value(
            self.sek,
            self.channel,
            self.directory.active.sparse.commitments,
            &hashed(head),
        )? != Some(Value::Present)
        {
            return Ok(false);
        }
        Ok(self
            .history_head(head)?
            .is_some_and(|h| h.binding == binding))
    }
    /// Whether this exact signed head is in the accepted consistency chain. The current head and
    /// every cryptographically retained prefix are accepted; a same-size different descriptor is
    /// not. This never promotes or rolls back the author's current head.
    pub(crate) fn history_head_accepted(
        &self,
        head: &Digest32,
        binding: TreeBinding,
    ) -> Result<bool> {
        if self.history_head_committed(head, binding)? {
            return Ok(true);
        }
        let Some(target) = self.history_head(head)? else {
            return Ok(false);
        };
        if target.binding != binding {
            return Ok(false);
        }
        self.source().sparse_head_accepted(
            self.sek,
            self.channel,
            self.directory.active.sparse,
            &target,
        )
    }
    /// An individually evidence-complete published source and its exact inclusion target.
    /// This does not claim that the governance evaluator has applied the source's effect.
    pub(crate) fn history_validated_header(
        &self,
        author: &Digest32,
        seq: u64,
    ) -> Result<Option<(Digest32, Entry)>> {
        let Some(entry) = self.history_position_header(author, seq)? else {
            return Ok(None);
        };
        let source = self.source();
        let id = source
            .number(
                self.sek,
                self.channel,
                self.directory.active.sparse.source_heads,
                &hashed(&entry.entry_hash()),
            )?
            .ok_or(invalid("validated source has no head binding"))?;
        let bytes = source.sparse_record(self.sek, self.channel, id, MAX_HEADER_BYTES)?;
        let head = SignedHead::from_wire(&bytes)?;
        if head.binding.matches_entry(&entry).is_err() || head.binding.room != *self.channel {
            return Err(invalid("validated source head differs"));
        }
        Ok(Some((head.id(), entry)))
    }
    /// A durable source-complete prefix receipt, built only from no-omission coverage and
    /// individually validated control sources. It grants no authority and performs no scan.
    pub(crate) fn control_sources_complete(&self, head: &Digest32, through: u64) -> Result<bool> {
        self.control_prefix_complete(self.directory.active.sparse.source_prefixes, head, through)
    }
    /// The position at which `author` terminated its feed, once that Termination is a held
    /// source here (recorded at publication, `index_source_head`).
    pub(crate) fn history_termination(&self, author: &Digest32) -> Result<Option<u64>> {
        self.source().number(
            self.sek,
            self.channel,
            self.directory.active.sparse.terminations,
            &hashed(author),
        )
    }
    pub(crate) fn history_position_header(
        &self,
        author: &Digest32,
        seq: u64,
    ) -> Result<Option<Entry>> {
        self.source().sparse_position_header(
            self.sek,
            self.channel,
            self.directory.active.sparse,
            author,
            seq,
        )
    }
    pub(crate) fn history_entry(&self, hash: &Digest32) -> Result<Option<Entry>> {
        let source = self.source();
        let Some(at) = source.find(
            self.sek,
            self.channel,
            self.directory.active.hash,
            &hashed(hash),
        )?
        else {
            return Ok(None);
        };
        let header = source
            .sparse_header(self.sek, self.channel, self.directory.active.sparse, hash)?
            .ok_or(invalid("published history header missing"))?;
        let wire = source.history_wire(
            self.sek,
            self.channel,
            SegmentKind::LogDb,
            at.log,
            expected_entry_wire(&header)?,
        )?;
        let entry = Entry::from_wire(&wire)?;
        if entry.entry_hash() != *hash
            || entry.skeleton.channel_id != *self.channel
            || entry.skeleton.author_id != at.author
            || entry.skeleton.seq != at.seq
        {
            return Err(invalid("published history entry binding"));
        }
        Ok(Some(entry))
    }
    pub(crate) fn sparse_enabled(&self) -> bool {
        self.directory.active.sparse.enabled
    }
    pub(crate) fn sparse_author(
        &self,
        author: &Digest32,
        scope: LogScope,
    ) -> Result<Option<AuthorState>> {
        self.source().sparse_author(
            self.sek,
            self.channel,
            self.directory.active.sparse,
            author,
            scope,
        )
    }
    pub(crate) fn history_object(
        &self,
        kind: ObjectKind,
        hash: &Digest32,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let source = self.source();
        source
            .number(
                self.sek,
                self.channel,
                self.directory.active.sparse.objects,
                &object_key(kind, hash),
            )?
            .map(|id| source.sparse_record(self.sek, self.channel, id, kind.limit()))
            .transpose()
    }
    /// A source may require both a semantic-effect receipt and its addressed key body.
    /// Callers reserve this small capacity before mutating local sender state.
    pub(crate) fn history_obligation_capacity(&self) -> u64 {
        MAX_OBLIGATIONS.saturating_sub(self.directory.active.sparse.obligation_count)
    }
    pub(crate) fn history_head(&self, hash: &Digest32) -> Result<Option<SignedHead>> {
        self.source()
            .sparse_head(self.sek, self.channel, self.directory.active.sparse, hash)
    }
    pub(crate) fn recovery_context_head(
        &self,
        author: &Digest32,
        context: &Digest32,
    ) -> Result<Option<Digest32>> {
        self.history_object(
            ObjectKind::RecoveryContext,
            &recovery_context_key(author, context),
        )?
        .map(|bytes| {
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| invalid("own recovery context witness"))
        })
        .transpose()
    }
    /// MP-9 (rule 6): the signed head of `author` whose continuity is unresolved, if one is kept.
    pub(crate) fn history_unresolved_head(&self, author: &Digest32) -> Result<Option<Digest32>> {
        self.history_object(ObjectKind::Unresolved, &unresolved_key(author))?
            .map(|bytes| {
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| invalid("unresolved head owner"))
            })
            .transpose()
    }

    pub(crate) fn history_context(&self, hash: &Digest32) -> Result<Option<ControlContext>> {
        self.history_object(ObjectKind::Context, hash)?
            .map(|bytes| {
                let context = ControlContext::from_wire(&bytes)?;
                if context.room != *self.channel || context.hash() != *hash {
                    return Err(invalid("stored context binding"));
                }
                Ok(context)
            })
            .transpose()
    }
    /// Head-scoped serving material is deliberately separate from canonical prefix ranges.
    /// A verified proof may name a signed head whose consistency is still unresolved. Under a
    /// head committed here a range rebuilt for serving is also found by position
    /// (`cached_history_range`).
    pub(crate) fn history_proof_range(
        &self,
        head: &Digest32,
        binding: TreeBinding,
        start: u64,
        leaves: u64,
    ) -> Result<Option<Descriptor>> {
        if binding.room != *self.channel {
            return Err(invalid("proof-serving range room"));
        }
        let key = proof_range_key(head, binding, start, leaves)?;
        if let Some(value) = PROOF_CACHE
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .and_then(|cache| cache.ranges.get(&key).copied())
        {
            return Ok(Some(value));
        }
        if let Some(value) = self
            .history_object(ObjectKind::ProofRange, &key)?
            .map(|bytes| decode_proof_range(&bytes, head, binding, start, leaves))
            .transpose()?
        {
            return Ok(Some(value));
        }
        if self.history_head_committed(head, binding)? {
            return cached_history_range(binding, start, leaves);
        }
        Ok(None)
    }
    pub(crate) fn history_range(
        &self,
        binding: TreeBinding,
        start: u64,
        leaves: u64,
    ) -> Result<Option<Descriptor>> {
        if binding.room != *self.channel {
            return Err(invalid("tree range room"));
        }
        let key = range_key(binding, start, leaves)?;
        let source = self.source();
        source
            .number(
                self.sek,
                self.channel,
                self.directory.active.sparse.ranges,
                &key,
            )?
            .map(|id| {
                let bytes = source.sparse_record(self.sek, self.channel, id, STATE_BYTES)?;
                let mut decoder = Decoder::new(&bytes);
                let descriptor = Descriptor::decode(&mut decoder)?;
                decoder.finish()?;
                if descriptor.leaves != leaves {
                    return Err(invalid("stored tree range length"));
                }
                Ok(descriptor)
            })
            .transpose()
    }

    /// How far the author's verified control coverage runs from position 1 (0: none), kept per
    /// author whatever committed head proved it (`control_prefix_complete`): the author's first
    /// run when it starts at 1 (`keep_control_run`). One seek, keys and scalar values only.
    pub(crate) fn history_controls_covered(&self, author: &Digest32) -> Result<u64> {
        let runs = self.directory.active.sparse.control_intervals;
        Ok(
            match control_run(&self.source(), self.sek, self.channel, runs, author, 1)? {
                Some((_, 1, hi)) => hi,
                _ => 0,
            },
        )
    }

    /// Position `seq` is a control of the author that verified coverage enumerated. One key.
    pub(crate) fn history_is_control(&self, author: &Digest32, seq: u64) -> Result<bool> {
        Ok(self
            .source()
            .number(
                self.sek,
                self.channel,
                self.directory.active.sparse.control_sources,
                &position(author, seq),
            )?
            .is_some())
    }

    /// The positions of the author's controls its verified coverage enumerated, ascending.
    /// Keys only.
    pub(crate) fn history_control_positions(&self, author: &Digest32) -> Result<Vec<u64>> {
        let source = self.source();
        let mut positions = Vec::new();
        let mut key = position(author, 1);
        while let Some((found, _)) = source.first(
            self.sek,
            self.channel,
            self.directory.active.sparse.control_sources,
            &key,
            0,
        )? {
            if found[..32] != author[..] {
                break;
            }
            positions.push(u64::from_be_bytes(
                found[32..40]
                    .try_into()
                    .map_err(|_| invalid("control source position"))?,
            ));
            let Some(next) = dag_facts::successor(found) else {
                break;
            };
            key = next;
        }
        Ok(positions)
    }
}

/// The author's control coverage run that ends at or after position `at`, as `(key, lo, hi)`.
/// Runs are kept as `(author, hi) -> lo`, disjoint and never touching (`keep_control_run`), so
/// the run holding `at`, if any, is this one when its `lo <= at`.
fn control_run(
    source: &Source<'_>,
    sek: &Sek,
    channel: &Digest32,
    root: u64,
    author: &Digest32,
    at: u64,
) -> Result<Option<(Key, u64, u64)>> {
    let Some((key, value)) = source.first(sek, channel, root, &position(author, at), 0)? else {
        return Ok(None);
    };
    if key[..32] != author[..] {
        return Ok(None);
    }
    let hi = u64::from_be_bytes(
        key[32..40]
            .try_into()
            .map_err(|_| invalid("coverage end"))?,
    );
    let Value::Number(lo) = value else {
        return Err(invalid("coverage start"));
    };
    if lo == 0 || lo > hi {
        return Err(invalid("coverage run"));
    }
    Ok(Some((key, lo, hi)))
}

/// One bounded source-closure step; neither Complete nor Progress grants authority.
#[derive(Clone, Debug)]
pub(crate) enum SourceProgress {
    Progress {
        through: u64,
    },
    Complete {
        through: u64,
    },
    MissingCoverage {
        after: u64,
    },
    PendingEffect {
        hash: Digest32,
    },
    ConflictingSource {
        author: Digest32,
        seq: u64,
        expected: Digest32,
        actual: Digest32,
    },
    MissingSource {
        seq: u64,
    },
}

/// What one `keep_control_coverage` call kept.
pub(crate) enum CoverageKept {
    /// Only the enumeration's next 16 headers after `after` are kept; the coverage is not
    /// published yet (the caller continues from `after + 16`).
    Partial,
    /// The coverage is published; `grew` when it covers a position the author's verified
    /// coverage did not cover before (only then can an enumerated source be new).
    Complete { grew: bool },
}

impl Write<'_, '_> {
    pub(crate) fn publish_local_history(
        &mut self,
        publication: LocalHistoryPublication<'_>,
    ) -> Result<LocalHistorySettlement> {
        let LocalHistoryPublication {
            entry,
            header,
            head,
            consistency,
            included,
            pre_context,
            post_context,
            ranges,
        } = publication;
        let signed = head.head();
        let v2 = entry
            .skeleton
            .v2
            .as_ref()
            .ok_or(invalid("local history entry is legacy"))?;
        let promotion = self
            .directory
            .promotion
            .as_ref()
            .ok_or(invalid("local history publication absent"))?;
        if self.directory.phase != Phase::Switched
            || promotion.sparse_head.is_some()
            || promotion.witness_hash != entry.entry_hash()
            || !self.directory.active.sparse.enabled
            || entry.header_wire() != header.entry().header_wire()
            || included.header().entry().header_wire() != header.entry().header_wire()
            || included.head_id() != signed.id()
            || included.binding() != signed.binding
            || included.root() != signed.root
            || signed.root.leaves != entry.skeleton.seq
            || pre_context.hash() != v2.pre_context
            || post_context.hash() != signed.root.frontier
            || pre_context.room != *self.channel
            || post_context.room != *self.channel
            || pre_context.scope != v2.scope
            || post_context.scope != v2.scope
            || ranges.len() > crate::log::history::MAX_TREE_DEPTH + 1
        {
            return Err(invalid("local history publication binding"));
        }
        signed.binding.matches_entry(entry)?;
        // This is one final existing append Batch: no observer can see this temporary
        // mutation phase or an object/root before the original root switch commits.
        self.directory.phase = Phase::Idle;
        let result = (|| {
            self.keep_history_context(pre_context)?;
            self.keep_history_context(post_context)?;
            self.keep_history_header(header)?;
            self.keep_history_inclusion_receipt(included)?;
            if self.commit_history_head(head, consistency)? {
                // This head is still local, unpublished material. Refuse the whole local
                // append; previously received signed conflict evidence stays on disk.
                return Err(invalid(
                    "local head conflicts with authenticated observation",
                ));
            }
            for (start, range) in ranges {
                self.keep_history_range(signed.binding, *start, *range)?;
            }
            let mut roots = self.directory.active;
            self.index_source_head(&mut roots, entry, signed.id())?;
            self.directory.active = roots;
            self.keep_single_control_coverage(included)?;
            if !self.keep_history_obligation(&Obligation::authority(signed.id(), entry))? {
                return Err(invalid("pending local effect obligation capacity reached"));
            }
            Ok(LocalHistorySettlement {
                entry: entry.entry_hash(),
                head: signed.id(),
                author: entry.skeleton.author_id,
                seq: entry.skeleton.seq,
            })
        })();
        self.directory.phase = Phase::Switched;
        result
    }

    /// Inclusion of one exact signed header is complete class coverage of that one position,
    /// merged into the author's runs (`keep_control_run`).
    fn keep_single_control_coverage(&mut self, included: &IncludedHeader) -> Result<()> {
        let entry = included.header().entry();
        let (author, seq) = (entry.skeleton.author_id, entry.skeleton.seq);
        if entry
            .skeleton
            .v2
            .as_ref()
            .is_some_and(|v| v.kind.is_control())
        {
            let id = Source::Batch(self.batch)
                .number(
                    self.sek,
                    self.channel,
                    self.directory.active.sparse.objects,
                    &object_key(ObjectKind::Header, &entry.entry_hash()),
                )?
                .ok_or(invalid("control header object absent"))?;
            self.directory.active.sparse.control_sources = self.change_value(
                self.directory.active.sparse.control_sources,
                position(&author, seq),
                Some(Value::Number(id)),
            )?;
            self.batch.touch_history(self.channel, author, Some(seq));
        }
        self.keep_control_run(&author, seq, seq)?;
        Ok(())
    }
    /// The author's verified control coverage is kept as RUNS, `(author, hi) -> lo`, disjoint
    /// and never touching: coverage `[lo, hi]` is merged on write with every run it overlaps
    /// or touches, so an author admitted without gaps has one row. Each merged run is deleted
    /// once; a covered run is found by one seek (`control_run`), so neither this write nor the
    /// walk (`advance_control_receipt`) ever passes over older rows. Returns whether the
    /// author's coverage grew.
    fn keep_control_run(&mut self, author: &Digest32, lo: u64, hi: u64) -> Result<bool> {
        if lo == 0 || lo > hi {
            return Err(invalid("control coverage run"));
        }
        let (mut lo, mut hi) = (lo, hi);
        let mut at = lo - 1;
        let mut merged = false;
        loop {
            let root = self.directory.active.sparse.control_intervals;
            let Some((key, run_lo, run_hi)) = control_run(
                &Source::Batch(self.batch),
                self.sek,
                self.channel,
                root,
                author,
                at,
            )?
            else {
                break;
            };
            if run_lo > hi.saturating_add(1) {
                break;
            }
            if !merged && run_lo <= lo && run_hi >= hi {
                return Ok(false);
            }
            merged = true;
            lo = lo.min(run_lo);
            hi = hi.max(run_hi);
            self.directory.active.sparse.control_intervals = self.change_value(root, key, None)?;
            let Some(next) = run_hi.checked_add(1) else {
                break;
            };
            at = next;
        }
        self.directory.active.sparse.control_intervals = self.change_value(
            self.directory.active.sparse.control_intervals,
            position(author, hi),
            Some(Value::Number(lo)),
        )?;
        Ok(true)
    }
    /// The token can only be constructed by the channel's typed effect dispatcher after
    /// its exact signed context and current checks finish. This method grants nothing by
    /// source-completeness alone; all changes share the effect transaction. A control's effect
    /// also advances its author's control prefixes (`advance_received_control_prefixes`).
    /// Returns whether the package catalog changed, and whether the author's controls became
    /// current here.
    pub(in crate::node::channel) fn finish_history_effect(
        &mut self,
        entry: &Entry,
        finished: &super::super::sparse_history::FinishedHistoryEffect,
        local_id: Digest32,
        work: &mut crate::log::history::WorkBudget,
    ) -> Result<(bool, bool)> {
        if finished.entry_hash() != entry.entry_hash() {
            return Err(invalid("sparse effect token differs"));
        }
        let previous_package = self.directory.next_package;
        self.finish_history_effect_bookkeeping(entry, None)?;
        // A recipient-scoped package is satisfied for every other member by its authenticated
        // header and completed semantic dispatch. Its private body is neither owed nor fetched.
        // `entry` is the exact accepted source named by `finished`, so untrusted tag data cannot
        // clear recovery work. This lands with the effect receipt and survives restart.
        if !body_owed_to(entry, &local_id) {
            self.set_missing(&entry.skeleton.author_id, entry.skeleton.seq, false)?;
        }
        let ready = match &entry.skeleton.v2 {
            Some(v2) if v2.kind.is_control() => {
                self.advance_received_control_prefixes(entry, v2.scope, work)?
            }
            _ => false,
        };
        Ok((self.directory.next_package != previous_package, ready))
    }

    /// A received control's own effect advances its author's control-source, then
    /// control-effect prefix toward the author's committed size, with the existing walk
    /// (`advance_control_receipt`: it stops at a coverage gap, a missing or conflicting source
    /// and an unfinished effect, and never sets a prefix to a position), each step charged to
    /// the admission operation's budget. Where it stops, the next entry's admission walks on
    /// (`admission::advance_prefix`). Returns whether the author's controls became current here.
    fn advance_received_control_prefixes(
        &mut self,
        entry: &Entry,
        scope: LogScope,
        work: &mut crate::log::history::WorkBudget,
    ) -> Result<bool> {
        let author = entry.skeleton.author_id;
        let roots = self.directory.active.sparse;
        let Some(committed) = Source::Batch(self.batch)
            .sparse_author(self.sek, self.channel, roots, &author, scope)?
            .and_then(|state| state.committed)
        else {
            return Ok(false);
        };
        let record = Source::Batch(self.batch)
            .number(
                self.sek,
                self.channel,
                roots.objects,
                &object_key(ObjectKind::Head, &committed),
            )?
            .ok_or(invalid("control source head missing"))?;
        let leaves = SignedHead::from_wire(&Source::Batch(self.batch).sparse_record(
            self.sek,
            self.channel,
            record,
            MAX_HEADER_BYTES,
        )?)?
        .root
        .leaves;
        let effect_prefix = |write: &Self| -> Result<u64> {
            Ok(Source::Batch(&*write.batch)
                .number(
                    write.sek,
                    write.channel,
                    write.directory.active.sparse.effect_prefixes,
                    &hashed(&author),
                )?
                .unwrap_or(0))
        };
        let before = effect_prefix(self)?;
        for effects in [false, true] {
            while work.take_control_lookup() {
                if !matches!(
                    self.advance_control_receipt(&committed, leaves, effects)?,
                    SourceProgress::Progress { .. }
                ) {
                    break;
                }
            }
        }
        Ok(before < leaves && effect_prefix(self)? >= leaves)
    }

    /// Consume only the opaque token returned by this exact local publication. The caller has
    /// already written the entry's semantic rows into the same Batch; a later failure rolls all
    /// of this back together.
    pub(crate) fn finish_local_history_effect(
        &mut self,
        entry: &Entry,
        settlement: LocalHistorySettlement,
    ) -> Result<()> {
        let promotion = self
            .directory
            .promotion
            .as_ref()
            .ok_or(invalid("local settlement publication absent"))?;
        if self.directory.phase != Phase::Switched
            || promotion.witness_hash != settlement.entry
            || settlement.entry != entry.entry_hash()
            || settlement.author != entry.skeleton.author_id
            || settlement.seq != entry.skeleton.seq
        {
            return Err(invalid("local settlement binding"));
        }
        self.directory.phase = Phase::Idle;
        let result = self.finish_history_effect_bookkeeping(entry, Some(settlement.head));
        self.directory.phase = Phase::Switched;
        result
    }

    fn finish_history_effect_bookkeeping(
        &mut self,
        entry: &Entry,
        expected_head: Option<Digest32>,
    ) -> Result<()> {
        self.require_sparse_idle()?;
        let roots = self.directory.active;
        let source = Source::Batch(self.batch);
        let held = source
            .sparse_position_header(
                self.sek,
                self.channel,
                roots.sparse,
                &entry.skeleton.author_id,
                entry.skeleton.seq,
            )?
            .ok_or(invalid("effect source not published"))?;
        if held.entry_hash() != entry.entry_hash() {
            return Err(invalid("effect source conflicts"));
        }
        let at = source
            .find(
                self.sek,
                self.channel,
                roots.hash,
                &hashed(&entry.entry_hash()),
            )?
            .ok_or(invalid("effect locator missing"))?;
        self.directory.active.sparse.settled_entries = self.change_value(
            roots.sparse.settled_entries,
            hashed(&entry.entry_hash()),
            Some(Value::Present),
        )?;
        self.batch.touch_history(
            self.channel,
            entry.skeleton.author_id,
            Some(entry.skeleton.seq),
        );
        let tip = Source::Batch(self.batch)
            .number(
                self.sek,
                self.channel,
                roots.sparse.settled_tips,
                &hashed(&entry.skeleton.author_id),
            )?
            .map(|id| {
                Source::Batch(self.batch)
                    .sparse_record(self.sek, self.channel, id, MAX_HEADER_BYTES)
                    .and_then(|wire| Entry::from_wire(&wire))
            })
            .transpose()?;
        if tip.is_none_or(|held| held.skeleton.seq < entry.skeleton.seq) {
            let id = Source::Batch(self.batch)
                .number(
                    self.sek,
                    self.channel,
                    roots.sparse.objects,
                    &object_key(ObjectKind::Header, &entry.entry_hash()),
                )?
                .ok_or(invalid("settled header object missing"))?;
            self.directory.active.sparse.settled_tips = self.change_value(
                roots.sparse.settled_tips,
                hashed(&entry.skeleton.author_id),
                Some(Value::Number(id)),
            )?;
        }
        self.directory.active = self.index_package(self.directory.active, entry, at.log)?;
        let head_record = Source::Batch(self.batch)
            .number(
                self.sek,
                self.channel,
                self.directory.active.sparse.source_heads,
                &hashed(&entry.entry_hash()),
            )?
            .ok_or(invalid("settled source head missing"))?;
        let head = SignedHead::from_wire(&Source::Batch(self.batch).sparse_record(
            self.sek,
            self.channel,
            head_record,
            MAX_HEADER_BYTES,
        )?)?;
        if expected_head.is_some_and(|expected| expected != head.id()) {
            return Err(invalid("local settlement head differs"));
        }
        self.finish_history_obligation(&Obligation::authority(head.id(), entry))?;
        if expected_head.is_some() {
            // A local append extends only its already-ready predecessor, and this Batch contains
            // the new entry's semantic effect: the author's effects are complete through the new
            // head, so its effect prefix reaches it. No separate prefix walk remains.
            self.finish_local_control_effects(&head)?;
        }
        Ok(())
    }
    pub(crate) fn begin_sparse_publication(
        &mut self,
        publication: SparsePublication<'_>,
    ) -> Result<()> {
        self.require_sparse_idle()?;
        let SparsePublication {
            request,
            entry,
            validated,
            first_log,
            received_ms,
            origin,
        } = publication;
        let included = validated.included();
        let binding = validated.binding();
        if binding.room != *self.channel
            || included.head_id() != validated.head_id()
            || included.binding() != binding
            || entry.entry_hash() != validated.entry_hash()
            || entry.header_wire() != included.header().entry().header_wire()
            || first_log == 0
        {
            return Err(invalid("sparse publication evidence binding"));
        }
        binding.matches_entry(entry)?;
        if Source::Batch(self.batch)
            .number(
                self.sek,
                self.channel,
                self.directory.active.sparse.terminations,
                &hashed(&entry.skeleton.author_id),
            )?
            .is_some_and(|seq| entry.skeleton.seq > seq)
        {
            return Err(invalid("sparse source follows a terminated feed"));
        }

        if let Some(payload) = &entry.payload {
            if payload.len() as u64 != entry.skeleton.payload_len
                || sha256(payload) != entry.skeleton.payload_hash
            {
                return Err(invalid("sparse publication body differs"));
            }
        }
        let source = Source::Batch(self.batch);
        if source.find_value(
            self.sek,
            self.channel,
            self.directory.active.sparse.commitments,
            &hashed(&included.head_id()),
        )? != Some(Value::Present)
        {
            return Err(invalid("sparse entry has no accepted commitment"));
        }
        if source
            .find(
                self.sek,
                self.channel,
                self.directory.active.sequence,
                &position(&entry.skeleton.author_id, entry.skeleton.seq),
            )?
            .is_some()
        {
            return Err(invalid(
                "sparse entry position already held; check duplicate or fork before publication",
            ));
        }
        let v2 = entry
            .skeleton
            .v2
            .as_ref()
            .ok_or(invalid("sparse publication requires v2"))?;
        use super::super::governance::SparsePayloadState;
        use crate::log::history::SignedEntryKind;
        let implicit_empty = matches!(
            v2.kind,
            SignedEntryKind::ContextUpdate | SignedEntryKind::Termination
        ) && entry.skeleton.payload_len == 0
            && entry.skeleton.payload_hash == sha256(&[]);
        match validated.payload_state() {
            SparsePayloadState::Held if entry.payload.is_some() || implicit_empty => {}
            SparsePayloadState::ContentAbsent
                if v2.kind == SignedEntryKind::Content && entry.payload.is_none() => {}
            SparsePayloadState::KeyPackagePending { recipient }
                if v2.kind == SignedEntryKind::KeyPackage
                    && v2.recipient == Some(recipient)
                    && entry.payload.is_none() => {}
            _ => {
                return Err(invalid(
                    "sparse source body disposition differs from validation",
                ));
            }
        }
        if validated.pre_context().hash() != v2.pre_context
            || validated.pre_context().scope != v2.scope
        {
            return Err(invalid("sparse publication context differs"));
        }
        self.keep_history_context(validated.pre_context())?;
        self.keep_history_header(included.header())?;
        self.keep_single_control_coverage(included)?;
        if !self.keep_history_obligation(&Obligation::authority(included.head_id(), entry))? {
            return Err(invalid("pending source effect obligation capacity reached"));
        }
        self.set_origin(origin)?;
        let empty_entry;
        let staged = if implicit_empty && entry.payload.is_none() {
            empty_entry = Entry {
                skeleton: entry.skeleton.clone(),
                authenticator: entry.authenticator.clone(),
                payload: Some(Vec::new()),
            };
            &empty_entry
        } else {
            entry
        };
        let witness = self.stage(staged)?;
        first_log
            .checked_add(1)
            .ok_or(invalid("sparse log allocator exhausted"))?;
        self.directory.promotion = Some(Promotion {
            author: entry.skeleton.author_id,
            from: entry.skeleton.seq,
            through: entry.skeleton.seq,
            base_hash: entry.skeleton.prev_hash,
            received_ms,
            witness,
            witness_hash: entry.entry_hash(),
            cursor: entry.skeleton.seq,
            work: self.directory.active,
            first_log,
            after_log: first_log,
            first_page: self.directory.next_page,
            after_page: self.directory.next_page,
            retired: 0,
            bodyless_prefix: false,
            accepted: None,
            sparse_head: Some(included.head_id()),
            sparse_request: Some(request),
            cleanup_hash: None,
        });
        self.directory.phase = Phase::Building;
        Ok(())
    }

    /// Publish the body debt only with the source root switch. An interrupted Building
    /// promotion must never leave a debt for a header that was not published.
    pub(crate) fn publish_key_body_debt(
        &mut self,
        entry: &Entry,
        first_seen_ms: u64,
    ) -> Result<()> {
        if entry.payload.is_some()
            || !entry
                .skeleton
                .v2
                .as_ref()
                .is_some_and(|v| v.kind == crate::log::history::SignedEntryKind::KeyPackage)
        {
            return Ok(());
        }
        if self.directory.phase != Phase::Switched {
            return Err(invalid("key debt publication phase"));
        }
        let head = self
            .directory
            .promotion
            .as_ref()
            .and_then(|p| p.sparse_head)
            .ok_or(invalid("key debt source head missing"))?;
        self.directory.phase = Phase::Idle;
        let debt = Obligation {
            head,
            kind: ObligationKind::KeyBody,
            object: entry.entry_hash(),
            author: entry.skeleton.author_id,
            from: entry.skeleton.seq,
            through: entry.skeleton.seq,
        };
        let result = (|| -> Result<()> {
            if !self.keep_history_obligation(&debt)? {
                return Err(invalid("key debt publication failed"));
            }
            let order = self.directory.active.sparse.key_body_debt_order;
            let serial = Source::Batch(self.batch)
                .number(self.sek, self.channel, order, &key_debt_reverse(&debt)?)?
                .ok_or(invalid("key debt reverse locator missing"))?;
            let id = Source::Batch(self.batch)
                .number(
                    self.sek,
                    self.channel,
                    self.directory.active.sparse.key_body_obligations,
                    &debt.key()?,
                )?
                .ok_or(invalid("key debt locator missing"))?;
            let order = self.change_value(
                order,
                key_debt_expiry(entry.skeleton.claimed_ms.min(first_seen_ms), serial),
                Some(Value::Number(id)),
            )?;
            self.directory.active.sparse.key_body_debt_order = self.change_value(
                order,
                key_debt_claim(serial),
                Some(Value::Number(entry.skeleton.claimed_ms.min(first_seen_ms))),
            )?;
            Ok(())
        })();
        self.directory.phase = Phase::Switched;
        result
    }

    pub(super) fn index_sparse_source(
        &mut self,
        roots: &mut super::Roots,
        entry: &Entry,
    ) -> Result<()> {
        let head = self
            .directory
            .promotion
            .as_ref()
            .and_then(|p| p.sparse_head)
            .ok_or(invalid("sparse source publication lost its head"))?;
        self.index_source_head(roots, entry, head)
    }
    fn index_source_head(
        &mut self,
        roots: &mut super::Roots,
        entry: &Entry,
        head: Digest32,
    ) -> Result<()> {
        let source = Source::Batch(self.batch);
        let id = source
            .number(
                self.sek,
                self.channel,
                roots.sparse.objects,
                &object_key(ObjectKind::Header, &entry.entry_hash()),
            )?
            .ok_or(invalid("sparse validated source header missing"))?;
        roots.sparse.validated_positions = self.change_value(
            roots.sparse.validated_positions,
            position(&entry.skeleton.author_id, entry.skeleton.seq),
            Some(Value::Number(id)),
        )?;
        roots.sparse.objects = self.retire_pending_header(
            roots.sparse.objects,
            &entry.skeleton.author_id,
            entry.skeleton.seq,
            &head,
        )?;
        self.batch.touch_history(
            self.channel,
            entry.skeleton.author_id,
            Some(entry.skeleton.seq),
        );
        let head_record = Source::Batch(self.batch)
            .number(
                self.sek,
                self.channel,
                roots.sparse.objects,
                &object_key(ObjectKind::Head, &head),
            )?
            .ok_or(invalid("sparse source head object missing"))?;
        roots.sparse.source_heads = self.change_value(
            roots.sparse.source_heads,
            hashed(&entry.entry_hash()),
            Some(Value::Number(head_record)),
        )?;
        if entry.skeleton.end_of_feed {
            let prior = Source::Batch(self.batch).number(
                self.sek,
                self.channel,
                roots.sparse.terminations,
                &hashed(&entry.skeleton.author_id),
            )?;
            if prior.is_some_and(|seq| seq != entry.skeleton.seq) {
                return Err(invalid("conflicting terminal source"));
            }
            roots.sparse.terminations = self.change_value(
                roots.sparse.terminations,
                hashed(&entry.skeleton.author_id),
                Some(Value::Number(entry.skeleton.seq)),
            )?;
        }
        Ok(())
    }
    /// Only a genuinely empty new room starts this format. Opening an existing room does
    /// not call this, scan its archive, or reinterpret its legacy feed as a commitment.
    pub(crate) fn initialize_sparse_history(&mut self) -> Result<()> {
        if self.directory.phase != Phase::Idle
            || self.directory.active.sequence != 0
            || self
                .directory
                .restart
                .as_ref()
                .is_some_and(|r| !r.feeds.is_empty())
        {
            return Err(invalid("new history format requires an empty room"));
        }
        self.directory.active.sparse.enabled = true;
        let restart = self
            .directory
            .restart
            .as_mut()
            .ok_or(invalid("new history requires initialized restart state"))?;
        restart.sparse = true;
        Ok(())
    }
    fn require_sparse_idle(&self) -> Result<()> {
        if self.directory.phase != Phase::Idle {
            return Err(invalid("sparse mutation during publication"));
        }
        if !self.directory.active.sparse.enabled {
            return Err(invalid("legacy history activation is not authorized"));
        }
        Ok(())
    }
    fn save_sparse_record(&mut self, old: Option<u64>, bytes: &[u8], limit: usize) -> Result<u64> {
        if bytes.len() > limit {
            return Err(invalid("sparse record exceeds bound"));
        }
        let id = self.allocate()?;
        let sealed = seal_segment(self.sek, SegmentKind::EntryIndex, id, bytes)?;
        self.batch
            .put_segment(self.channel, SegmentKind::EntryIndex, id, &sealed)?;
        if let Some(old) = old {
            self.retire(old)?;
        }
        Ok(id)
    }
    fn save_history_object(
        &mut self,
        kind: ObjectKind,
        hash: Digest32,
        bytes: &[u8],
    ) -> Result<()> {
        self.require_sparse_idle()?;
        self.directory.active.sparse.objects =
            self.save_history_object_at(self.directory.active.sparse.objects, kind, hash, bytes)?;
        Ok(())
    }
    pub(crate) fn keep_recovery_context(
        &mut self,
        author: &Digest32,
        head: &Digest32,
        context: &Digest32,
    ) -> Result<()> {
        self.save_history_object(
            ObjectKind::RecoveryContext,
            recovery_context_key(author, context),
            head,
        )
    }
    /// MP-9 (rule 6): own the one signed head of `author` whose continuity with the accepted
    /// chain is unresolved, so it is listed, served by id and compared again after a restart.
    /// One per author: a newer unresolved observation replaces it. Fork proofs are kept apart
    /// (SEG_FORKS) and never replaced by this.
    pub(crate) fn keep_history_unresolved_head(
        &mut self,
        author: &Digest32,
        head: &Digest32,
    ) -> Result<()> {
        self.require_sparse_idle()?;
        let key = object_key(ObjectKind::Unresolved, &unresolved_key(author));
        let root = self.directory.active.sparse.objects;
        let prior = Source::Batch(self.batch).number(self.sek, self.channel, root, &key)?;
        let id = self.save_sparse_record(prior, head, ObjectKind::Unresolved.limit())?;
        self.directory.active.sparse.objects =
            self.change_value(root, key, Some(Value::Number(id)))?;
        // The record of what this node holds lists the author's unresolved head (its Have).
        self.batch.touch_history(self.channel, *author, None);
        Ok(())
    }

    /// Return one updated object root without choosing which publication owns it.
    /// allocate/retire retain the existing Building rollback and retirement accounting.
    fn save_history_object_at(
        &mut self,
        root: u64,
        kind: ObjectKind,
        hash: Digest32,
        bytes: &[u8],
    ) -> Result<u64> {
        if bytes.len() > kind.limit() {
            return Err(invalid("sparse object size"));
        }
        let key = object_key(kind, &hash);
        if Source::Batch(self.batch)
            .number(self.sek, self.channel, root, &key)?
            .is_some()
        {
            // The typed caller has checked this content identity. A different randomized
            // valid signature of the same head/header does not replace the retained witness.
            return Ok(root);
        }
        let id = self.save_sparse_record(None, bytes, kind.limit())?;
        self.change_value(root, key, Some(Value::Number(id)))
    }

    /// Local header verification and tree construction have already completed. Keep their
    /// contexts only in this unpublished promotion, before DAG placement consumes them.
    pub(super) fn seed_local_promotion_contexts(
        &mut self,
        witness: &Entry,
        pre: &ControlContext,
        post: &ControlContext,
    ) -> Result<()> {
        let v2 = witness
            .skeleton
            .v2
            .as_ref()
            .ok_or(invalid("legacy promotion supplied local v2 contexts"))?;
        let promotion = self
            .directory
            .promotion
            .as_ref()
            .ok_or(invalid("local promotion context owner missing"))?;
        if self.directory.phase != Phase::Building
            || promotion.sparse_head.is_some()
            || promotion.witness_hash != witness.entry_hash()
            || !promotion.work.sparse.enabled
            || pre.room != *self.channel
            || post.room != *self.channel
            || pre.scope != v2.scope
            || post.scope != v2.scope
            || pre.hash() != v2.pre_context
        {
            return Err(invalid("local promotion context binding"));
        }
        let mut root = promotion.work.sparse.objects;
        for context in [pre, post] {
            root = self.save_history_object_at(
                root,
                ObjectKind::Context,
                context.hash(),
                &context.to_wire()?,
            )?;
        }
        self.directory
            .promotion
            .as_mut()
            .ok_or(invalid("local promotion context owner missing"))?
            .work
            .sparse
            .objects = root;
        Ok(())
    }
    pub(crate) fn keep_history_context(&mut self, context: &ControlContext) -> Result<Digest32> {
        if context.room != *self.channel {
            return Err(invalid("context belongs to another room"));
        }
        let wire = context.to_wire()?;
        let hash = context.hash();
        self.save_history_object(ObjectKind::Context, hash, &wire)?;
        Ok(hash)
    }
    pub(crate) fn keep_history_header(&mut self, header: &VerifiedHeader) -> Result<Digest32> {
        let entry = header.entry();
        if entry.skeleton.channel_id != *self.channel {
            return Err(invalid("header belongs to another room"));
        }
        let hash = entry.entry_hash();
        self.save_history_object(ObjectKind::Header, hash, &entry.header_wire())?;
        Ok(hash)
    }
    /// A tree node kept by author and position: the author's own appended nodes, a prefix
    /// `[1, n]` of the accepted chain, or a full aligned block of a trace verified under a head
    /// of that chain (`keep_history_blocks`). Each is the same value under every head of the
    /// chain that contains it. The descriptor does not mark an interval as admitted or
    /// control-ready.
    pub(crate) fn keep_history_range(
        &mut self,
        binding: TreeBinding,
        start: u64,
        descriptor: Descriptor,
    ) -> Result<()> {
        self.require_sparse_idle()?;
        if binding.room != *self.channel {
            return Err(invalid("tree range room"));
        }
        descriptor.validate()?;
        let key = range_key(binding, start, descriptor.leaves)?;
        let root = self.directory.active.sparse.ranges;
        if let Some(id) = Source::Batch(self.batch).number(self.sek, self.channel, root, &key)? {
            let bytes =
                Source::Batch(self.batch).sparse_record(self.sek, self.channel, id, STATE_BYTES)?;
            let mut decoder = Decoder::new(&bytes);
            let prior = Descriptor::decode(&mut decoder)?;
            decoder.finish()?;
            if prior != descriptor {
                return Err(invalid("held tree range conflicts"));
            }
            return Ok(());
        }
        let mut encoder = Encoder::new();
        descriptor.encode(&mut encoder);
        let id = self.save_sparse_record(None, &encoder.finish(), STATE_BYTES)?;
        self.directory.active.sparse.ranges =
            self.change_value(root, key, Some(Value::Number(id)))?;
        Ok(())
    }
    /// Every full aligned block of a proof trace verified under a head on this node's accepted
    /// chain of the author (the caller checked `history_head_accepted`). Such a block is one
    /// complete subtree of the tree over positions, so it has the same descriptor under every head
    /// of the chain that contains it (ADR-053 MP-7: identical aligned nodes may be reused): kept
    /// once by author and position, it serves a proof under any later head without that head's
    /// history being walked or rebuilt. Right-edge nodes stay per head.
    pub(crate) fn keep_history_blocks(
        &mut self,
        binding: TreeBinding,
        trace: &[(u64, Descriptor)],
    ) -> Result<()> {
        for (start, descriptor) in trace {
            if full_block(*start, descriptor.leaves) {
                self.keep_history_range(binding, *start, *descriptor)?;
            }
        }
        Ok(())
    }
    /// One fully verified wire piece of a durable inclusion/prefix receipt or of a control
    /// coverage's trace, written in that owner's transaction so it can be served again after a
    /// restart. An existing key writes nothing. This does not change prefix acceptance. A full
    /// aligned block under a head of the author's accepted chain is kept once, by author and
    /// position (`keep_history_blocks`), the copy every committed source reads first; only the
    /// right edge, and every piece under a head not accepted, is kept under the head.
    pub(crate) fn keep_history_proof_range(
        &mut self,
        head: Digest32,
        binding: TreeBinding,
        start: u64,
        descriptor: Descriptor,
    ) -> Result<()> {
        self.require_sparse_idle()?;
        if binding.room != *self.channel {
            return Err(invalid("proof-serving range room"));
        }
        descriptor.validate()?;
        if full_block(start, descriptor.leaves) {
            let roots = self.directory.active.sparse;
            let source = Source::Batch(self.batch);
            if let Some(target) = source.sparse_head(self.sek, self.channel, roots, &head)? {
                if target.binding == binding
                    && source.sparse_head_accepted(self.sek, self.channel, roots, &target)?
                {
                    return self.keep_history_range(binding, start, descriptor);
                }
            }
        }
        let key = proof_range_key(&head, binding, start, descriptor.leaves)?;
        if let Some(id) = Source::Batch(self.batch).number(
            self.sek,
            self.channel,
            self.directory.active.sparse.objects,
            &object_key(ObjectKind::ProofRange, &key),
        )? {
            let bytes =
                Source::Batch(self.batch).sparse_record(self.sek, self.channel, id, STATE_BYTES)?;
            if decode_proof_range(&bytes, &head, binding, start, descriptor.leaves)? != descriptor {
                return Err(invalid("conflicting proof-serving range"));
            }
            return Ok(());
        }
        let mut e = Encoder::new();
        e.array(5).uint(1).bytes(&head);
        binding.encode(&mut e);
        e.uint(start);
        descriptor.encode(&mut e);
        self.save_history_object(ObjectKind::ProofRange, key, &e.finish())
    }
    /// One slice of the one-time reclamation of an old store's proof-serving cache: it visits at
    /// most `PROOF_CLEANUP_VISITS` object locators and deletes at most `PROOF_CLEANUP_DELETES`
    /// of the obsolete serving-cache kind, each object with its index reference in this room
    /// transaction (a delete rewrites one root-to-leaf path, so the second bound is what bounds
    /// the transaction's pages).
    pub(super) fn cleanup_history_proof_ranges(
        &mut self,
        mut after: Option<Key>,
    ) -> Result<(bool, Option<Key>, bool)> {
        self.require_sparse_idle()?;
        let mut changed = false;
        let mut deleted = 0;
        for _ in 0..PROOF_CLEANUP_VISITS {
            if deleted == PROOF_CLEANUP_DELETES {
                break;
            }
            let seek = match after {
                Some(key) => match dag_facts::successor(key) {
                    Some(next) => next,
                    None => return Ok((true, None, changed)),
                },
                None => [0; 64],
            };
            let root = self.directory.active.sparse.objects;
            let Some((key, value)) =
                Source::Batch(self.batch).first(self.sek, self.channel, root, &seek, 0)?
            else {
                return Ok((true, None, changed));
            };
            after = Some(key);
            if key[32] != ObjectKind::ProofRange as u8 {
                continue;
            }
            if key[33..] != [0; 31] {
                eprintln!(
                    "vox: room {} kept malformed proof-range cache key {:?}",
                    crate::node::link::b32_encode(self.channel),
                    key
                );
                continue;
            }
            let Value::Number(id) = value else {
                return Err(invalid("proof-serving object locator"));
            };
            self.retire(id)?;
            self.directory.active.sparse.objects = self.change_value(root, key, None)?;
            changed = true;
            deleted += 1;
        }
        Ok((false, after, changed))
    }
    fn save_sparse_author(&mut self, binding: TreeBinding, state: AuthorState) -> Result<()> {
        if binding.room != *self.channel {
            return Err(invalid("sparse author room"));
        }
        let key = author_key(&binding.author, binding.scope);
        let root = self.directory.active.sparse.authors;
        let old = Source::Batch(self.batch).number(self.sek, self.channel, root, &key)?;
        if old.is_none() && self.directory.active.sparse.author_count >= MAX_CONTEXT_AUTHORS as u64
        {
            return Err(invalid("sparse author bound"));
        }
        let id = self.save_sparse_record(old, &state.bytes(), STATE_BYTES)?;
        self.directory.active.sparse.authors =
            self.change_value(root, key, Some(Value::Number(id)))?;
        if old.is_none() {
            self.directory.active.sparse.author_count += 1;
        }
        self.batch.touch_history(self.channel, binding.author, None);
        Ok(())
    }

    /// Both observation and commitment preserve the highest authenticated observation.
    /// Commitment is a separate proof-gated position and cannot lower this requirement.
    fn merge_observed_head(&self, head: &SignedHead, state: &mut AuthorState) -> Result<()> {
        let hash = head.id();
        if state.observed == Some(hash) {
            return Ok(());
        }
        let held = state
            .observed
            .map(|id| {
                let prior = Source::Batch(self.batch)
                    .sparse_head(self.sek, self.channel, self.directory.active.sparse, &id)?
                    .ok_or(invalid("observed head missing"))?;
                if prior.binding != head.binding {
                    return Err(invalid("observed head author or scope differs"));
                }
                Ok(prior)
            })
            .transpose()?;
        match held {
            Some(old) if old.root.leaves > head.root.leaves => {}
            Some(old) if old.root.leaves == head.root.leaves => {
                if state.observed_conflict.is_none() {
                    state.observed_conflict = Some((old.id(), hash));
                }
            }
            _ => state.observed = Some(hash),
        }
        Ok(())
    }
    /// Retain authenticated head evidence only. Return true for an attributable conflict;
    /// the caller refuses it AFTER this Batch commits, so neither witness is rolled back.
    pub(crate) fn observe_history_head(&mut self, verified: &VerifiedHead) -> Result<bool> {
        self.require_sparse_idle()?;
        let head = verified.head();
        if head.binding.room != *self.channel {
            return Err(invalid("observed head room"));
        }
        let hash = head.id();
        self.save_history_object(ObjectKind::Head, hash, &head.to_wire())?;
        let mut state = Source::Batch(self.batch)
            .sparse_author(
                self.sek,
                self.channel,
                self.directory.active.sparse,
                &head.binding.author,
                head.binding.scope,
            )?
            .unwrap_or_default();
        let before = state;
        self.merge_observed_head(head, &mut state)?;
        if state != before {
            self.save_sparse_author(head.binding, state)?;
        }
        Ok(state.observed_conflict.is_some())
    }
    /// Publish only the exact consistency result against the root still accepted in this
    /// Batch. A stale result cannot replace a newer commitment. No contiguous head changes.
    /// Return true when retained observed conflict evidence must be reported after commit.
    pub(crate) fn commit_history_head(
        &mut self,
        verified: &VerifiedHead,
        proof: &ConsistentPrefix,
    ) -> Result<bool> {
        self.require_sparse_idle()?;
        let head = verified.head();
        if proof.head_id() != head.id()
            || proof.binding() != head.binding
            || proof.root() != head.root
            || head.binding.room != *self.channel
        {
            return Err(invalid("commitment proof target differs"));
        }
        let source = Source::Batch(self.batch);
        if head.root.leaves != 0 {
            let key = receipt_key(&head.id(), &head.binding.author, head.root.leaves);
            let id = source
                .number(
                    self.sek,
                    self.channel,
                    self.directory.active.sparse.objects,
                    &object_key(ObjectKind::InclusionReceipt, &key),
                )?
                .ok_or(invalid("head terminal inclusion is pending"))?;
            let receipt = IncludedHeader::from_authenticated_receipt(&source.sparse_record(
                self.sek,
                self.channel,
                id,
                ObjectKind::InclusionReceipt.limit(),
            )?)?;
            if receipt.head_id() != head.id()
                || receipt.binding() != head.binding
                || receipt.root() != head.root
                || receipt.header().entry().skeleton.seq != head.root.leaves
                || receipt.header().entry().skeleton.epoch != head.tail_epoch
            {
                return Err(invalid("head terminal inclusion differs"));
            }
        }
        let mut state = source
            .sparse_author(
                self.sek,
                self.channel,
                self.directory.active.sparse,
                &head.binding.author,
                head.binding.scope,
            )?
            .unwrap_or_default();
        if source.find_value(
            self.sek,
            self.channel,
            self.directory.active.sparse.commitments,
            &hashed(&head.id()),
        )? == Some(Value::Present)
        {
            // Reusing an older accepted target finishes its outstanding work; it must not
            // roll back the current head or create a cycle in prior-head receipts.
            return Ok(state.observed_conflict.is_some());
        }
        let prior_id = state.committed;
        let prior = if let Some(id) = state.committed {
            let record = source
                .number(
                    self.sek,
                    self.channel,
                    self.directory.active.sparse.objects,
                    &object_key(ObjectKind::Head, &id),
                )?
                .ok_or(invalid("committed head missing"))?;
            let old = SignedHead::from_wire(&source.sparse_record(
                self.sek,
                self.channel,
                record,
                MAX_HEADER_BYTES,
            )?)?;
            if old.id() != id || old.binding != head.binding {
                return Err(invalid("committed head binding"));
            }
            old.root
        } else {
            if self.directory.restart.as_ref().is_some_and(|r| {
                r.feeds
                    .get(&head.binding.author)
                    .is_some_and(|feed| !(r.sparse && feed.seq == 1 && head.root.leaves == 1))
            }) {
                return Err(invalid(
                    "legacy prefix cannot use an empty consistency baseline",
                ));
            }
            Descriptor::empty(head.binding)
        };
        if proof.prefix() != prior {
            return Err(invalid("consistency baseline changed before publication"));
        }
        self.save_history_object(ObjectKind::Head, head.id(), &head.to_wire())?;
        if let Some(prior_id) = prior_id {
            let record = Source::Batch(self.batch)
                .number(
                    self.sek,
                    self.channel,
                    self.directory.active.sparse.objects,
                    &object_key(ObjectKind::Head, &prior_id),
                )?
                .ok_or(invalid("consistency baseline head object missing"))?;
            self.directory.active.sparse.prior_heads = self.change_value(
                self.directory.active.sparse.prior_heads,
                hashed(&head.id()),
                Some(Value::Number(record)),
            )?;
        }
        self.merge_observed_head(head, &mut state)?;
        state.committed = Some(head.id());
        // The walk's floor is set once, by the author's first non-empty committed head: this
        // node's first window is the newest 128 positions, so a newcomer is never made to read
        // from message one; every position above the floor stays owed until walked (ADR-052
        // RG-6). The rest of the walk is the in-memory record of what this node holds
        // (`held_history`). An author a store written before floors existed committed got its
        // floor at upgrade, from what this member held of it (`followed_floor`).
        if state.floor == 0 && head.binding.scope == LogScope::Public && head.root.leaves != 0 {
            state.floor = newcomer_floor(head.root.leaves);
        }
        // An empty head has no control positions or effects: the author's effect prefix (0)
        // already reaches it (`history_control_ready`).
        if head.root.leaves != 0 {
            self.keep_history_range(head.binding, 1, head.root)?;
        }
        self.directory.active.sparse.commitments = self.change_value(
            self.directory.active.sparse.commitments,
            hashed(&head.id()),
            Some(Value::Present),
        )?;
        self.save_sparse_author(head.binding, state)?;
        Ok(state.observed_conflict.is_some())
    }
    /// Remember cryptographically complete coverage, not semantic control readiness. Bodies,
    /// parent receipts and authority evaluation remain durable obligations owned by admission.
    pub(crate) fn keep_control_coverage(
        &mut self,
        proof: &VerifiedControlRange,
        after: usize,
    ) -> Result<CoverageKept> {
        self.require_sparse_idle()?;
        if proof.binding().room != *self.channel
            || proof.lo() == 0
            || proof.lo() > proof.hi()
            || proof.hi() > proof.root().leaves
        {
            return Err(invalid("control coverage binding"));
        }
        let source = Source::Batch(self.batch);
        let record = source
            .number(
                self.sek,
                self.channel,
                self.directory.active.sparse.objects,
                &object_key(ObjectKind::Head, &proof.head_id()),
            )?
            .ok_or(invalid("control coverage head missing"))?;
        let head = SignedHead::from_wire(&source.sparse_record(
            self.sek,
            self.channel,
            record,
            MAX_HEADER_BYTES,
        )?)?;
        if head.id() != proof.head_id()
            || head.binding != proof.binding()
            || head.root != proof.root()
        {
            return Err(invalid("control coverage target differs"));
        }
        if after > proof.headers().len() {
            return Err(invalid("control coverage publication cursor"));
        }
        // A completed verifier can contain up to a page of controls. Persist only a bounded
        // slice of its exact enumeration per transaction; coverage is published last.
        let end = after.saturating_add(16).min(proof.headers().len());
        for header in &proof.headers()[after..end] {
            let entry = header.entry();
            if entry.skeleton.author_id != proof.binding().author
                || entry.skeleton.seq < proof.lo()
                || entry.skeleton.seq > proof.hi()
                || !entry
                    .skeleton
                    .v2
                    .as_ref()
                    .is_some_and(|v| v.kind.is_control())
            {
                return Err(invalid("control enumeration binding"));
            }
            let hash = self.keep_history_header(header)?;
            let id = Source::Batch(self.batch)
                .number(
                    self.sek,
                    self.channel,
                    self.directory.active.sparse.objects,
                    &object_key(ObjectKind::Header, &hash),
                )?
                .ok_or(invalid("control enumeration header missing"))?;
            let key = position(&proof.binding().author, entry.skeleton.seq);
            let root = self.directory.active.sparse.control_sources;
            if let Some(prior) =
                Source::Batch(self.batch).number(self.sek, self.channel, root, &key)?
            {
                let wire = Source::Batch(self.batch).sparse_record(
                    self.sek,
                    self.channel,
                    prior,
                    MAX_HEADER_BYTES,
                )?;
                if Entry::from_wire(&wire)?.entry_hash() != hash {
                    return Err(invalid("control enumeration conflicts"));
                }
            } else {
                self.directory.active.sparse.control_sources =
                    self.change_value(root, key, Some(Value::Number(id)))?;
                // The record of what this node holds adds this control position alone.
                self.batch.touch_history(
                    self.channel,
                    proof.binding().author,
                    Some(entry.skeleton.seq),
                );
            }
        }
        if end < proof.headers().len() {
            return Ok(CoverageKept::Partial);
        }
        // Recheck the complete enumeration before publishing coverage, so an arbitrary
        // caller-supplied cursor can never skip required source rows. This is bounded by
        // the protocol's page limit and reads only small authenticated headers.
        for header in proof.headers() {
            if Source::Batch(self.batch)
                .number(
                    self.sek,
                    self.channel,
                    self.directory.active.sparse.control_sources,
                    &position(&proof.binding().author, header.entry().skeleton.seq),
                )?
                .is_none()
            {
                return Err(invalid("control enumeration publication incomplete"));
            }
        }
        // Kept per author, whatever head proved it (`control_prefix_complete`), merged into the
        // author's runs: no walk position is lost or moved back by new coverage.
        let author = proof.binding().author;
        let grew = self.keep_control_run(&author, proof.lo(), proof.hi())?;
        if grew {
            self.batch.touch_history(self.channel, author, None);
        }
        Ok(CoverageKept::Complete { grew })
    }
    /// Advance through one enumerated control of the covered run holding the prefix's next
    /// position, or to that run's end. A source-complete receipt is distinct from governance
    /// completion and never requires a whole head ready first.
    pub(crate) fn advance_control_sources(
        &mut self,
        head_id: &Digest32,
        required: u64,
    ) -> Result<SourceProgress> {
        self.advance_control_receipt(head_id, required, false)
    }
    pub(crate) fn advance_control_effects(
        &mut self,
        head_id: &Digest32,
        required: u64,
    ) -> Result<SourceProgress> {
        self.advance_control_receipt(head_id, required, true)
    }
    fn advance_control_receipt(
        &mut self,
        head_id: &Digest32,
        required: u64,
        effects: bool,
    ) -> Result<SourceProgress> {
        self.require_sparse_idle()?;
        let roots = self.directory.active.sparse;
        let prefix_root = if effects {
            roots.effect_prefixes
        } else {
            roots.source_prefixes
        };
        let source = Source::Batch(self.batch);
        if source.find_value(self.sek, self.channel, roots.commitments, &hashed(head_id))?
            != Some(Value::Present)
        {
            return Err(invalid("control source target is not committed"));
        }
        let head_record = source
            .number(
                self.sek,
                self.channel,
                roots.objects,
                &object_key(ObjectKind::Head, head_id),
            )?
            .ok_or(invalid("control source head missing"))?;
        let head = SignedHead::from_wire(&source.sparse_record(
            self.sek,
            self.channel,
            head_record,
            MAX_HEADER_BYTES,
        )?)?;
        if head.id() != *head_id || head.binding.room != *self.channel {
            return Err(invalid("control source head binding"));
        }
        // Kept per author whatever head proved them (`control_prefix_complete`): a moved head
        // neither restarts nor inherits this progress, it is the same.
        let author = head.binding.author;
        let through = source
            .number(self.sek, self.channel, prefix_root, &hashed(&author))?
            .unwrap_or(0);
        if required == 0 || required > head.root.leaves {
            return Err(invalid("control receipt requested prefix"));
        }
        if through >= required {
            return Ok(SourceProgress::Complete { through });
        }
        // The run holding `through + 1` (`keep_control_run`): one seek whatever the author's
        // length. The prefix is the walk's only position; it only moves forward, and new
        // coverage, merged into the runs, can neither hide a run from it nor move it back.
        let Some((_, lo, hi)) = control_run(
            &source,
            self.sek,
            self.channel,
            roots.control_intervals,
            &author,
            through + 1,
        )?
        else {
            return Ok(SourceProgress::MissingCoverage { after: through });
        };
        if lo > through + 1 {
            return Ok(SourceProgress::MissingCoverage { after: through });
        }
        // A strict-past request must never require a later control (possibly the entry
        // whose own admission is waiting here).
        let stop = hi.min(required);
        let next = source.first(
            self.sek,
            self.channel,
            roots.control_sources,
            &position(&author, through + 1),
            0,
        )?;
        let next_through = match next {
            Some((key, Value::Number(id))) if key[..32] == author[..] => {
                let seq = u64::from_be_bytes(
                    key[32..40]
                        .try_into()
                        .map_err(|_| invalid("control source position"))?,
                );
                if seq > stop {
                    stop
                } else {
                    let wire =
                        source.sparse_record(self.sek, self.channel, id, MAX_HEADER_BYTES)?;
                    let expected = Entry::from_wire(&wire)?;
                    let actual = source.sparse_position_header(
                        self.sek,
                        self.channel,
                        roots,
                        &head.binding.author,
                        seq,
                    )?;
                    match actual {
                        None => return Ok(SourceProgress::MissingSource { seq }),
                        Some(actual) if actual.entry_hash() != expected.entry_hash() => {
                            return Ok(SourceProgress::ConflictingSource {
                                author: head.binding.author,
                                seq,
                                expected: expected.entry_hash(),
                                actual: actual.entry_hash(),
                            });
                        }
                        Some(_) => {}
                    }
                    if effects
                        && source.find_value(
                            self.sek,
                            self.channel,
                            roots.settled_entries,
                            &hashed(&expected.entry_hash()),
                        )? != Some(Value::Present)
                    {
                        return Ok(SourceProgress::PendingEffect {
                            hash: expected.entry_hash(),
                        });
                    }
                    seq
                }
            }
            Some((key, _)) if key[..32] == author[..] => {
                return Err(invalid("control source locator"));
            }
            _ => stop,
        };
        let updated = self.change_value(
            prefix_root,
            hashed(&author),
            Some(Value::Number(next_through)),
        )?;
        if effects {
            self.directory.active.sparse.effect_prefixes = updated;
        } else {
            self.directory.active.sparse.source_prefixes = updated;
        }
        Ok(if next_through >= required {
            SourceProgress::Complete {
                through: next_through,
            }
        } else {
            SourceProgress::Progress {
                through: next_through,
            }
        })
    }
    /// After a local append under `head`, the author's effect prefix reaches its size (see the
    /// caller): the same claim the walk makes for a remote author, kept by author.
    fn finish_local_control_effects(&mut self, head: &SignedHead) -> Result<()> {
        let state = Source::Batch(self.batch)
            .sparse_author(
                self.sek,
                self.channel,
                self.directory.active.sparse,
                &head.binding.author,
                head.binding.scope,
            )?
            .ok_or(invalid("control-ready author missing"))?;
        if state.committed != Some(head.id()) {
            return Ok(());
        }
        let author = head.binding.author;
        let root = self.directory.active.sparse.effect_prefixes;
        let through = Source::Batch(self.batch)
            .number(self.sek, self.channel, root, &hashed(&author))?
            .unwrap_or(0);
        if through < head.root.leaves {
            self.directory.active.sparse.effect_prefixes =
                self.change_value(root, hashed(&author), Some(Value::Number(head.root.leaves)))?;
        }
        Ok(())
    }

    /// One bounded slice of the one-time upgrade of the control facts of a store written before
    /// format 14 (main and v0.4.30), run by open before any reader, as stages 3 to 7 of the
    /// display reindex (`display_chunk`). Those versions kept each control fact under the head
    /// that proved it; this one keeps it by author (`control_prefix_complete`). Every row under
    /// a head COMMITTED here is a fact of the author's accepted chain and is merged into the
    /// author's rows; a row under any other head (unresolved, forked, only observed) stays as
    /// it is, under that head, and nothing reads it. A row's first 32 bytes name its head; an
    /// author is never a committed head, so rows this slice writes are passed over.
    ///
    /// - 3, coverage `(head, lo) -> hi`: merged into the author's runs `(author, hi) -> lo`.
    /// - 4, control sources `(head, seq) -> header`: `(author, seq) -> header`.
    /// - 5, 6, source and effect prefixes `head -> through`: `author -> ` the greatest.
    /// - 7, author records: one whose retired `control_ready` is its committed head raises the
    ///   author's effect prefix to that head's size (an own append set only that); and every
    ///   author with a non-empty committed head gets its walk floor (`followed_floor`).
    ///
    /// Each step is a merge, a maximum or the same header again, and no old row is changed or
    /// deleted: a slice repeated after a crash adds nothing twice. The caller seals the cursor
    /// with the slice.
    pub(super) fn migrate_control_chunk(
        &mut self,
        stage: u8,
        start: Option<Key>,
    ) -> Result<Option<Key>> {
        let mut key = start.unwrap_or([0; 64]);
        for _ in 0..PROMOTION_ENTRIES {
            let roots = self.directory.active.sparse;
            let root = match stage {
                3 => roots.control_intervals,
                4 => roots.control_sources,
                5 => roots.source_prefixes,
                6 => roots.effect_prefixes,
                _ => roots.authors,
            };
            let source = Source::Batch(self.batch);
            let Some((found, value)) = source.first(self.sek, self.channel, root, &key, 0)? else {
                return Ok(None);
            };
            let Value::Number(number) = value else {
                return Err(invalid("upgraded control fact value"));
            };
            let id: Digest32 = found[..32]
                .try_into()
                .map_err(|_| invalid("upgraded control fact key"))?;
            let at = u64::from_be_bytes(
                found[32..40]
                    .try_into()
                    .map_err(|_| invalid("upgraded control fact position"))?,
            );
            if stage == 7 {
                self.migrate_author_record(&found, number)?;
            } else if source.find_value(self.sek, self.channel, roots.commitments, &hashed(&id))?
                == Some(Value::Present)
            {
                let head = source
                    .sparse_head(self.sek, self.channel, roots, &id)?
                    .ok_or(invalid("committed history head missing"))?;
                let author = head.binding.author;
                match stage {
                    3 => {
                        if at == 0 || number < at || number > head.root.leaves {
                            return Err(invalid("upgraded control coverage"));
                        }
                        self.keep_control_run(&author, at, number)?;
                    }
                    4 => self.migrate_control_source(&author, at, number)?,
                    _ => {
                        if found[32..].iter().any(|byte| *byte != 0) || number > head.root.leaves {
                            return Err(invalid("upgraded control prefix"));
                        }
                        self.raise_control_prefix(stage == 6, &author, number)?;
                    }
                }
            }
            match dag_facts::successor(found) {
                Some(next) => key = next,
                None => return Ok(None),
            }
        }
        Ok(Some(key))
    }
    /// Stage 4 of `migrate_control_chunk`: the author's control source at `seq` is the header
    /// `record` (the same header object under every head).
    fn migrate_control_source(&mut self, author: &Digest32, seq: u64, record: u64) -> Result<()> {
        let source = Source::Batch(self.batch);
        let header = |id| -> Result<Entry> {
            Entry::from_wire(&source.sparse_record(self.sek, self.channel, id, MAX_HEADER_BYTES)?)
        };
        let entry = header(record)?;
        if entry.skeleton.author_id != *author
            || entry.skeleton.seq != seq
            || !entry
                .skeleton
                .v2
                .as_ref()
                .is_some_and(|v| v.kind.is_control())
        {
            return Err(invalid("upgraded control source"));
        }
        let key = position(author, seq);
        let root = self.directory.active.sparse.control_sources;
        match source.number(self.sek, self.channel, root, &key)? {
            None => {
                self.directory.active.sparse.control_sources =
                    self.change_value(root, key, Some(Value::Number(record)))?;
            }
            Some(held) if held != record && header(held)?.entry_hash() != entry.entry_hash() => {
                return Err(invalid("control enumeration conflicts"));
            }
            Some(_) => {}
        }
        Ok(())
    }
    /// Stages 5 and 6 of `migrate_control_chunk`: the author's source or effect prefix is at
    /// least `through`.
    fn raise_control_prefix(
        &mut self,
        effects: bool,
        author: &Digest32,
        through: u64,
    ) -> Result<()> {
        let root = if effects {
            self.directory.active.sparse.effect_prefixes
        } else {
            self.directory.active.sparse.source_prefixes
        };
        let held = Source::Batch(self.batch)
            .number(self.sek, self.channel, root, &hashed(author))?
            .unwrap_or(0);
        if through > held {
            let updated = self.change_value(root, hashed(author), Some(Value::Number(through)))?;
            if effects {
                self.directory.active.sparse.effect_prefixes = updated;
            } else {
                self.directory.active.sparse.source_prefixes = updated;
            }
        }
        Ok(())
    }
    /// Stage 7 of `migrate_control_chunk`: an author record (`author_key`). Its retired
    /// `control_ready`, when it names the committed head, claimed every control effect of that
    /// head complete, which is the author's effect prefix reaching its size; and its walk floor
    /// is set (`followed_floor`). Both are maxima or a fixed function of the store, so a
    /// repeated slice changes nothing.
    fn migrate_author_record(&mut self, key: &Key, record: u64) -> Result<()> {
        if key[32] != LogScope::Public as u8 || key[33..].iter().any(|v| *v != 0) {
            return Err(invalid("sparse author key"));
        }
        let author: Digest32 = key[..32]
            .try_into()
            .map_err(|_| invalid("sparse author identity"))?;
        let source = Source::Batch(self.batch);
        let bytes = source.sparse_record(self.sek, self.channel, record, STATE_BYTES)?;
        let (mut state, control_ready) = AuthorState::parse_with_control_ready(&bytes)?;
        let Some(committed) = state.committed else {
            return Ok(());
        };
        let head = source
            .sparse_head(
                self.sek,
                self.channel,
                self.directory.active.sparse,
                &committed,
            )?
            .ok_or(invalid("committed history head missing"))?;
        if control_ready == Some(committed) {
            self.raise_control_prefix(true, &author, head.root.leaves)?;
        }
        if head.root.leaves != 0 {
            let floor = self.followed_floor(&author, state.floor, head.root.leaves)?;
            if floor != state.floor {
                state.floor = floor;
                self.save_sparse_author(head.binding, state)?;
            }
        }
        Ok(())
    }
    /// The walk floor of an author a store written before format 14 committed (stage 7): that
    /// program left whatever it had not fetched missing anywhere in the author's history, so
    /// the newest-128 start, which is for a newcomer, would make all of it older history nobody
    /// fetches. A member that READ the author followed it from the lowest post of the author
    /// shown here (a rendered row: a key of this member opened it, `put_rendered`), and owes
    /// everything above. A published header alone is no such evidence: it may be ciphertext
    /// this member could never read, or outlive its body. That program's own window start, if
    /// it kept one (`floor`), is kept when lower: it already owed from there. A member with no
    /// shown post of the author (none read, or every one expired) starts as a newcomer does.
    fn followed_floor(&self, author: &Digest32, floor: u64, size: u64) -> Result<u64> {
        let source = Source::Batch(self.batch);
        let roots = self.directory.active.sparse;
        let mut key = position(author, 1);
        // The author's published positions in order, each header read once, until the first
        // whose post is a shown row here.
        let lowest = loop {
            let Some((found, value)) =
                source.first(self.sek, self.channel, roots.validated_positions, &key, 0)?
            else {
                break None;
            };
            if found[..32] != author[..] {
                break None;
            }
            let Value::Number(record) = value else {
                return Err(invalid("validated position locator"));
            };
            let header = Entry::from_wire(&source.sparse_record(
                self.sek,
                self.channel,
                record,
                MAX_HEADER_BYTES,
            )?)?;
            if self.has_rendered(&header.entry_hash())? {
                break Some(header.skeleton.seq);
            }
            let Some(next) = dag_facts::successor(found) else {
                break None;
            };
            key = next;
        };
        Ok(match (lowest, floor) {
            (Some(seq), 0) => seq,
            (Some(seq), floor) => seq.min(floor),
            (None, 0) => newcomer_floor(size),
            (None, floor) => floor,
        })
    }

    /// The exact body debt must still exist at the publication transaction boundary.
    pub(crate) fn history_key_body_pending(
        &self,
        need: crate::node::history_stream::KeyBodyNeed,
    ) -> Result<bool> {
        let obligation = Obligation {
            head: need.head,
            kind: ObligationKind::KeyBody,
            object: need.hash,
            author: need.author,
            from: need.seq,
            through: need.seq,
        };
        Ok(Source::Batch(self.batch)
            .number(
                self.sek,
                self.channel,
                self.directory.active.sparse.key_body_obligations,
                &obligation.key()?,
            )?
            .is_some())
    }
    /// Bounded durable pending work. At the cap the caller yields before staging more objects.
    pub(crate) fn keep_history_obligation(&mut self, obligation: &Obligation) -> Result<bool> {
        self.require_sparse_idle()?;
        let key = obligation.key()?;
        let key_body = obligation.kind == ObligationKind::KeyBody;
        let root = if key_body {
            self.directory.active.sparse.key_body_obligations
        } else {
            self.directory.active.sparse.obligations
        };
        if Source::Batch(self.batch)
            .number(self.sek, self.channel, root, &key)?
            .is_some()
        {
            return Ok(true);
        }
        if !key_body && self.directory.active.sparse.obligation_count == MAX_OBLIGATIONS {
            return Ok(false);
        }
        let id = self.save_sparse_record(None, &obligation.bytes()?, STATE_BYTES)?;
        let next = self.change_value(root, key, Some(Value::Number(id)))?;
        if key_body {
            self.directory.active.sparse.key_body_obligations = next;
            if obligation.kind == ObligationKind::KeyBody {
                let serial = self
                    .directory
                    .active
                    .sparse
                    .key_body_debt_serial
                    .checked_add(1)
                    .ok_or(invalid("key debt serial exhausted"))?;
                let order = self.directory.active.sparse.key_body_debt_order;
                let order =
                    self.change_value(order, key_debt_order(serial), Some(Value::Number(id)))?;
                let order = self.change_value(
                    order,
                    key_debt_reverse(obligation)?,
                    Some(Value::Number(serial)),
                )?;
                self.directory.active.sparse.key_body_debt_order = order;
                self.directory.active.sparse.key_body_debt_serial = serial;
                // The held record reads this debt as "body owed, not held" (`held_history`):
                // the position is read again at the next publication.
                self.batch
                    .touch_history(self.channel, obligation.author, Some(obligation.from));
            }
        } else {
            self.directory.active.sparse.obligations = next;
            self.directory.active.sparse.obligation_count += 1;
        }
        Ok(true)
    }
    pub(crate) fn finish_history_obligation(&mut self, obligation: &Obligation) -> Result<()> {
        self.require_sparse_idle()?;
        let key = obligation.key()?;
        let key_body = obligation.kind == ObligationKind::KeyBody;
        let root = if key_body {
            self.directory.active.sparse.key_body_obligations
        } else {
            self.directory.active.sparse.obligations
        };
        if let Some(id) = Source::Batch(self.batch).number(self.sek, self.channel, root, &key)? {
            self.retire(id)?;
            let next = self.change_value(root, key, None)?;
            if key_body {
                self.directory.active.sparse.key_body_obligations = next;
                if obligation.kind == ObligationKind::KeyBody {
                    let order = self.directory.active.sparse.key_body_debt_order;
                    let reverse = key_debt_reverse(obligation)?;
                    let serial = Source::Batch(self.batch)
                        .number(self.sek, self.channel, order, &reverse)?
                        .ok_or(invalid("key debt reverse locator missing"))?;
                    let claimed = Source::Batch(self.batch)
                        .number(self.sek, self.channel, order, &key_debt_claim(serial))?
                        .ok_or(invalid("key debt claim missing"))?;
                    let order = self.change_value(order, key_debt_expiry(claimed, serial), None)?;
                    let order = self.change_value(order, key_debt_claim(serial), None)?;
                    let order = self.change_value(order, key_debt_order(serial), None)?;
                    self.directory.active.sparse.key_body_debt_order =
                        self.change_value(order, reverse, None)?;
                    // The body is held now (refill) or no longer owed (expiry): the held record
                    // reads the position again at the next publication.
                    self.batch.touch_history(
                        self.channel,
                        obligation.author,
                        Some(obligation.from),
                    );
                }
            } else {
                self.directory.active.sparse.obligations = next;
                self.directory.active.sparse.obligation_count = self
                    .directory
                    .active
                    .sparse
                    .obligation_count
                    .checked_sub(1)
                    .ok_or(invalid("sparse obligation counter"))?;
            }
        }
        Ok(())
    }
}

/// The existing Feed predicate needs only authenticated headers for backlinks. This local
/// view avoids decrypting maximum-sized bodies merely to advance the actual contiguous line.
struct HeaderRead<'a, 'b> {
    source: Source<'a>,
    sek: &'b Sek,
    room: &'b Digest32,
    roots: super::Roots,
}
impl EntryRead for HeaderRead<'_, '_> {
    fn get(&self, author: &Digest32, seq: u64) -> Result<Option<Entry>> {
        self.source
            .sparse_position_header(self.sek, self.room, self.roots.sparse, author, seq)
    }
    fn locate(&self, hash: &Digest32) -> Result<Option<(Digest32, u64)>> {
        Ok(self
            .source
            .find(self.sek, self.room, self.roots.hash, &hashed(hash))?
            .map(|at| (at.author, at.seq)))
    }
    fn clock(&self, hash: &Digest32) -> Result<Option<u64>> {
        self.source
            .number(self.sek, self.room, self.roots.clock, &hashed(hash))
    }
    fn order_next(&self, after: Option<(u64, Digest32)>) -> Result<Option<(u64, Digest32)>> {
        self.source
            .order_next(self.sek, self.room, self.roots.order, after)
    }
    fn order_previous(&self, before: Option<(u64, Digest32)>) -> Result<Option<(u64, Digest32)>> {
        self.source
            .order_previous(self.sek, self.room, self.roots.order, before)
    }
    fn referenced(&self, author: &Digest32, other: &Digest32) -> Result<u64> {
        let mut key = [0; 64];
        key[..32].copy_from_slice(author);
        key[32..].copy_from_slice(other);
        Ok(self
            .source
            .number(self.sek, self.room, self.roots.referenced, &key)?
            .unwrap_or(0))
    }
}

impl Write<'_, '_> {
    /// Advance through at most one live-window page of actually held, semantically settled
    /// successors. There is no unbounded scan, guessed prefix, or promotion to a signed head's
    /// leaf count. Closing a formerly missing position can therefore carry already-settled later
    /// positions forward in this same bounded event instead of waiting for a timer or new peer.
    pub(crate) fn advance_sparse_contiguous(
        &mut self,
        author: &Digest32,
        local_id: &Digest32,
    ) -> Result<ContiguousAdvance> {
        self.require_sparse_idle()?;
        let restart = self
            .directory
            .restart
            .as_ref()
            .ok_or(invalid("sparse restart state absent"))?;
        let mut state = restart.feeds.get(author).cloned().unwrap_or_default();
        let mut advanced = 0usize;
        for _ in 0..crate::log::history::MAX_PAGE_ENTRIES {
            if state.ended {
                break;
            }
            let next = state
                .seq
                .checked_add(1)
                .ok_or(invalid("contiguous sequence overflow"))?;
            let headers = HeaderRead {
                source: Source::Batch(self.batch),
                sek: self.sek,
                room: self.channel,
                roots: self.directory.active,
            };
            let Some(entry) = headers.get(author, next)? else {
                break;
            };
            if headers.source.find_value(
                self.sek,
                self.channel,
                self.directory.active.sparse.settled_entries,
                &hashed(&entry.entry_hash()),
            )? != Some(Value::Present)
            {
                break;
            }
            // Effect completion alone is not receipt of a body this role is entitled to.
            // Conversely, another member's private key-package body is deliberately absent and
            // cannot hold the public feed prefix back.
            if headers.source.find_value(
                self.sek,
                self.channel,
                self.directory.active.missing_positions,
                &position(author, next),
            )? == Some(Value::Present)
                && body_owed_to(&entry, local_id)
            {
                break;
            }
            let feed = if state.seq == 0 {
                crate::log::feed::Feed::default()
            } else {
                crate::log::feed::Feed::restore_published(
                    *author,
                    state.seq,
                    state.hash,
                    state.first_claimed_ms,
                    state.ended,
                )?
            };
            feed.validate_next(&headers, &entry)
                .map_err(|error| match error {
                    crate::log::feed::FeedError::Invalid(error)
                    | crate::log::feed::FeedError::Local(error) => error,
                })?;
            restart::advance(&mut state, &entry)?;
            self.directory
                .restart
                .as_mut()
                .ok_or(invalid("sparse restart state vanished"))?
                .feeds
                .insert(*author, state.clone());
            advanced += 1;
        }
        Ok(ContiguousAdvance {
            state: (advanced != 0).then_some(state.clone()),
            // This is deliberately conservative: an exact full page schedules one bounded
            // successor turn. That turn either advances another page or observes the first
            // real hole and parks. No timer or unrelated peer event is needed for continuation.
            more: advanced == crate::log::history::MAX_PAGE_ENTRIES && !state.ended,
        })
    }
}

pub(crate) struct ContiguousAdvance {
    pub(crate) state: Option<crate::log::dag::PublishedFeed>,
    pub(crate) more: bool,
}

impl crate::log::history::ContextSource for Read<'_> {
    fn context(&self, hash: &Digest32) -> Result<Option<ControlContext>> {
        self.history_context(hash)
    }
}

/// Exact local operation ownership of a verifier cursor. This metadata cannot grant a
/// request: the operation owner rechecks its current authorization and cancellation serial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CursorBinding {
    pub request: [u8; 16],
    pub room: Digest32,
    pub head: Digest32,
    pub author: Digest32,
    pub proof_kind: u8,
    pub from: u64,
    pub through: u64,
    pub generation: Digest32,
}
impl CursorBinding {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > STATE_BYTES {
            return Err(invalid("verifier binding size"));
        }
        let mut d = Decoder::new(bytes);
        if d.array()? != 9 || d.uint()? != 1 {
            return Err(invalid("verifier binding format"));
        }
        let binding = Self {
            request: d
                .bytes()?
                .try_into()
                .map_err(|_| invalid("verifier request"))?,
            room: d
                .bytes()?
                .try_into()
                .map_err(|_| invalid("verifier room"))?,
            head: d
                .bytes()?
                .try_into()
                .map_err(|_| invalid("verifier head"))?,
            author: d
                .bytes()?
                .try_into()
                .map_err(|_| invalid("verifier author"))?,
            proof_kind: u8::try_from(d.uint()?).map_err(|_| invalid("verifier kind"))?,
            from: d.uint()?,
            through: d.uint()?,
            generation: d
                .bytes()?
                .try_into()
                .map_err(|_| invalid("verifier generation"))?,
        };
        d.finish()?;
        if binding.bytes()? != bytes {
            return Err(invalid("verifier binding encoding"));
        }
        Ok(binding)
    }
    fn bytes(self) -> Result<Vec<u8>> {
        if self.proof_kind > 3
            || self.from > self.through
            || self.through > crate::log::feed::MAX_SEQ
            || (self.proof_kind != 1 && self.from == 0)
        {
            return Err(invalid("verifier cursor bounds"));
        }
        let mut e = Encoder::new();
        e.array(9)
            .uint(1)
            .bytes(&self.request)
            .bytes(&self.room)
            .bytes(&self.head)
            .bytes(&self.author)
            .uint(self.proof_kind as u64)
            .uint(self.from)
            .uint(self.through)
            .bytes(&self.generation);
        Ok(e.finish())
    }
    fn id(self) -> Result<Digest32> {
        let mut input = b"vox/local-history-verifier/v1".to_vec();
        input.extend_from_slice(&self.bytes()?);
        Ok(sha256(&input))
    }
    fn obligation(self) -> Result<Obligation> {
        Ok(Obligation {
            head: self.head,
            kind: ObligationKind::Verifier,
            object: self.id()?,
            author: self.author,
            from: self.from,
            through: self.through,
        })
    }
}

/// Only these already-constructed verifier types can populate a trusted local checkpoint.
/// There is deliberately no setter accepting peer-supplied checkpoint bytes.
pub(crate) enum HistoryVerifier {
    Inclusion(crate::log::history::InclusionVerifier),
    Consistency(crate::log::history::ConsistencyVerifier),
    ControlRange(crate::log::history::ControlRangeVerifier),
    Validation(super::super::governance::SparseValidation),
}
impl HistoryVerifier {
    fn checkpoint(&self, binding: CursorBinding) -> Result<Vec<u8>> {
        let (kind, target, bytes) = match self {
            Self::Inclusion(v) => (0, v.checkpoint_target(), v.checkpoint()?),
            Self::Consistency(v) => (1, v.checkpoint_target(), v.checkpoint()?),
            Self::ControlRange(v) => (2, v.checkpoint_target(), v.checkpoint()?),
            Self::Validation(v) => (3, v.checkpoint_target(), v.checkpoint()?),
        };
        if binding.proof_kind != kind
            || target.0 != binding.head
            || target.1.room != binding.room
            || target.1.author != binding.author
            || target.1.scope != LogScope::Public
            || target.2 != binding.from
            || target.3 != binding.through
        {
            return Err(invalid("verifier cursor target differs"));
        }
        Ok(bytes)
    }
    fn restore(binding: CursorBinding, bytes: &[u8]) -> Result<Self> {
        use crate::log::history::{ConsistencyVerifier, ControlRangeVerifier, InclusionVerifier};
        let result = match binding.proof_kind {
            0 => Self::Inclusion(InclusionVerifier::from_authenticated_checkpoint(bytes)?),
            1 => Self::Consistency(ConsistencyVerifier::from_authenticated_checkpoint(bytes)?),
            2 => Self::ControlRange(ControlRangeVerifier::from_authenticated_checkpoint(bytes)?),
            3 => Self::Validation(
                super::super::governance::SparseValidation::from_authenticated_checkpoint(bytes)?,
            ),
            _ => return Err(invalid("verifier cursor kind")),
        };
        // Authenticated local bytes still retain exact operation and proof bindings.
        result.checkpoint(binding)?;
        Ok(result)
    }
}

fn receipt_key(head: &Digest32, author: &Digest32, seq: u64) -> Digest32 {
    let mut bytes = b"vox/local-parent-receipt/v1".to_vec();
    bytes.extend_from_slice(head);
    bytes.extend_from_slice(author);
    bytes.extend_from_slice(&seq.to_be_bytes());
    sha256(&bytes)
}
fn parent_head_key(author: &Digest32, seq: u64) -> Digest32 {
    let mut bytes = b"vox/local-parent-head/v1".to_vec();
    bytes.extend_from_slice(author);
    bytes.extend_from_slice(&seq.to_be_bytes());
    sha256(&bytes)
}
fn included_head_key(author: &Digest32, seq: u64) -> Digest32 {
    let mut bytes = b"vox/local-included-head/v1".to_vec();
    bytes.extend_from_slice(author);
    bytes.extend_from_slice(&seq.to_be_bytes());
    sha256(&bytes)
}

impl Read<'_> {
    /// The caller owns the four-MiB verifier envelope through restoration and use.
    /// This is the only checkpoint read boundary; bytes come from authenticated local AEAD.
    pub(crate) fn history_verifier_cursor(
        &self,
        binding: CursorBinding,
    ) -> Result<Option<HistoryVerifier>> {
        if binding.room != *self.channel {
            return Err(invalid("verifier cursor room"));
        }
        let Some(bytes) = self.history_object(ObjectKind::Verifier, &binding.id()?)? else {
            return Ok(None);
        };
        let mut d = Decoder::new(&bytes);
        if d.array()? != 3 || d.uint()? != 1 || d.bytes()? != binding.bytes()? {
            return Err(invalid("stored verifier cursor binding"));
        }
        let checkpoint = d.bytes()?;
        let result = HistoryVerifier::restore(binding, checkpoint)?;
        d.finish()?;
        Ok(Some(result))
    }
    pub(crate) fn history_parent_receipt(
        &self,
        head: &Digest32,
        author: &Digest32,
        seq: u64,
    ) -> Result<Option<super::super::governance::VerifiedParentPrefix>> {
        let Some(bytes) =
            self.history_object(ObjectKind::ParentReceipt, &receipt_key(head, author, seq))?
        else {
            return Ok(None);
        };
        let result =
            super::super::governance::VerifiedParentPrefix::from_authenticated_checkpoint(&bytes)?;
        let included = result.included();
        if included.head_id() != *head
            || included.binding().room != *self.channel
            || included.binding().author != *author
            || included.header().entry().skeleton.seq != seq
        {
            return Err(invalid("stored parent receipt binding"));
        }
        Ok(Some(result))
    }
    /// The committed head of `author` under which this node keeps a parent receipt for
    /// position `seq` (the first one kept): found by author and position, whatever head the
    /// answer that brought it was asked under. Committed heads of one author extend one
    /// another, so each names the same entry at a position.
    pub(crate) fn history_parent_head(
        &self,
        author: &Digest32,
        seq: u64,
    ) -> Result<Option<Digest32>> {
        self.history_object(ObjectKind::ParentHead, &parent_head_key(author, seq))?
            .map(|bytes| {
                <[u8; 32]>::try_from(bytes.as_slice())
                    .map_err(|_| invalid("stored parent head locator"))
            })
            .transpose()
    }

    /// Snapshot discovery uses the same settled-position kernel as the native writer.
    pub(crate) fn next_sparse_backfill(
        &self,
        author: &Digest32,
        from: u64,
    ) -> Result<Option<(u64, Option<Entry>)>> {
        self.source()
            .sparse_backfill(self.sek, self.channel, self.directory.active, author, from)
    }
}

impl Source<'_> {
    fn sparse_backfill(
        &self,
        sek: &Sek,
        channel: &Digest32,
        roots: super::Roots,
        author: &Digest32,
        from: u64,
    ) -> Result<Option<(u64, Option<Entry>)>> {
        if !roots.sparse.enabled {
            return Ok(None);
        }
        let Some((key, value)) = self.first(
            sek,
            channel,
            roots.sparse.validated_positions,
            &position(author, from),
            0,
        )?
        else {
            return Ok(None);
        };
        if key[..32] != author[..] {
            return Ok(None);
        }
        if key[40..].iter().any(|byte| *byte != 0) || !matches!(value, Value::Number(_)) {
            return Err(invalid("sparse validated position key"));
        }
        let seq = u64::from_be_bytes(
            key[32..40]
                .try_into()
                .map_err(|_| invalid("sparse validated position sequence"))?,
        );
        let header = self
            .sparse_position_header(sek, channel, roots.sparse, author, seq)?
            .ok_or(invalid("sparse validated position vanished"))?;
        let hash = header.entry_hash();
        if self.find_value(sek, channel, roots.sparse.settled_entries, &hashed(&hash))?
            != Some(Value::Present)
        {
            return Ok(Some((seq, None)));
        }
        let entry = self
            .published_sparse_entry(sek, channel, roots, &hash)?
            .ok_or(invalid("settled sparse backfill entry missing"))?;
        Ok(Some((seq, Some(entry))))
    }
}
impl Write<'_, '_> {
    /// Retire only this request's unfinished verifier checkpoints. Accepted receipts and
    /// authority/key-body obligations have independent lifetimes and are never removed here.
    pub(crate) fn cleanup_history_verifiers(
        &mut self,
        request: [u8; 16],
        after: Option<Key>,
    ) -> Result<(bool, Option<Key>, bool)> {
        let before = self.directory.active.sparse.obligation_count;
        let (done, next) = self.cleanup_verifiers(Some(request), after)?;
        Ok((
            done,
            next,
            self.directory.active.sparse.obligation_count != before,
        ))
    }

    /// Reopen has no live verifier owner. Explicit history keeps its separate body/cursor;
    /// a later Resume reacquires proofs rather than restoring an abandoned live operation.
    pub(super) fn cleanup_abandoned_history_verifiers(
        &mut self,
        after: Option<Key>,
    ) -> Result<(bool, Option<Key>, bool)> {
        let before = self.directory.active.sparse.obligation_count;
        let (done, next) = self.cleanup_verifiers(None, after)?;
        Ok((
            done,
            next,
            self.directory.active.sparse.obligation_count != before,
        ))
    }

    fn cleanup_verifiers(
        &mut self,
        request: Option<[u8; 16]>,
        mut after: Option<Key>,
    ) -> Result<(bool, Option<Key>)> {
        if self.directory.phase != Phase::Idle {
            return Ok((false, after));
        }
        if !self.directory.active.sparse.enabled {
            return Ok((true, None));
        }
        // Scan only the capped pending-work index, sixteen scalar rows per transaction.
        // At most one sealed checkpoint is opened at a time; its proof is never restored.
        for _ in 0..16 {
            let seek = match after {
                Some(key) => match dag_facts::successor(key) {
                    Some(next) => next,
                    None => return Ok((true, None)),
                },
                None => [0; 64],
            };
            let source = Source::Batch(self.batch);
            let Some((key, value)) = source.first(
                self.sek,
                self.channel,
                self.directory.active.sparse.obligations,
                &seek,
                0,
            )?
            else {
                return Ok((true, None));
            };
            let Value::Number(id) = value else {
                return Err(invalid("cleanup obligation locator"));
            };
            let obligation = Obligation::parse(&source.sparse_record(
                self.sek,
                self.channel,
                id,
                STATE_BYTES,
            )?)?;
            if obligation.key()? != key {
                return Err(invalid("cleanup obligation binding"));
            }
            after = Some(key);
            if obligation.kind != ObligationKind::Verifier {
                continue;
            }
            let object = source
                .number(
                    self.sek,
                    self.channel,
                    self.directory.active.sparse.objects,
                    &object_key(ObjectKind::Verifier, &obligation.object),
                )?
                .ok_or(invalid("cleanup verifier object missing"))?;
            let binding = {
                let bytes = source.sparse_record(
                    self.sek,
                    self.channel,
                    object,
                    ObjectKind::Verifier.limit(),
                )?;
                let mut d = Decoder::new(&bytes);
                if d.array()? != 3 || d.uint()? != 1 {
                    return Err(invalid("cleanup verifier format"));
                }
                let binding = CursorBinding::parse(d.bytes()?)?;
                let _checkpoint = d.bytes()?;
                d.finish()?;
                if binding.room != *self.channel || binding.obligation()?.key()? != key {
                    return Err(invalid("cleanup verifier ownership"));
                }
                binding
            };
            if request.is_none_or(|request| binding.request == request) {
                self.finish_history_verifier_cursor(binding)?;
            }
        }
        Ok((false, after))
    }

    /// Replace one operation's cursor atomically with its exact pending-work pointer.
    /// Returns false before storing when the existing bounded work queue is full.
    pub(crate) fn keep_history_verifier_cursor(
        &mut self,
        binding: CursorBinding,
        cursor: &HistoryVerifier,
    ) -> Result<bool> {
        self.require_sparse_idle()?;
        if binding.room != *self.channel {
            return Err(invalid("verifier cursor room"));
        }
        let checkpoint = cursor.checkpoint(binding)?;
        if !self.keep_history_obligation(&binding.obligation()?)? {
            return Ok(false);
        }
        let mut e = Encoder::new();
        e.array(3)
            .uint(1)
            .bytes(&binding.bytes()?)
            .bytes(&checkpoint);
        let bytes = e.finish();
        let key = object_key(ObjectKind::Verifier, &binding.id()?);
        let root = self.directory.active.sparse.objects;
        let prior = Source::Batch(self.batch).number(self.sek, self.channel, root, &key)?;
        let id = self.save_sparse_record(prior, &bytes, ObjectKind::Verifier.limit())?;
        self.directory.active.sparse.objects =
            self.change_value(root, key, Some(Value::Number(id)))?;
        Ok(true)
    }
    pub(crate) fn finish_history_verifier_cursor(&mut self, binding: CursorBinding) -> Result<()> {
        self.require_sparse_idle()?;
        if binding.room != *self.channel {
            return Err(invalid("verifier cursor room"));
        }
        let key = object_key(ObjectKind::Verifier, &binding.id()?);
        let root = self.directory.active.sparse.objects;
        if let Some(id) = Source::Batch(self.batch).number(self.sek, self.channel, root, &key)? {
            self.retire(id)?;
            self.directory.active.sparse.objects = self.change_value(root, key, None)?;
        }
        self.finish_history_obligation(&binding.obligation()?)
    }
    pub(crate) fn keep_history_parent_receipt(
        &mut self,
        receipt: &super::super::governance::VerifiedParentPrefix,
    ) -> Result<()> {
        let included = receipt.included();
        if included.binding().room != *self.channel {
            return Err(invalid("parent receipt room"));
        }
        let (head, author, seq) = (
            included.head_id(),
            included.binding().author,
            included.header().entry().skeleton.seq,
        );
        let key = receipt_key(&head, &author, seq);
        let prefix = receipt.prefix();
        // The range [1, n] is a fact of the author's accepted chain only once this head is on
        // it; under any other head the receipt stays bound to its head.
        if self.accepted_head(&head)? {
            self.keep_history_range(prefix.binding(), 1, prefix.prefix())?;
        }
        self.save_history_object(ObjectKind::ParentReceipt, key, &receipt.checkpoint()?)?;
        // Only a committed head is a locator admission may use; commitments are never undone.
        if Source::Batch(self.batch).find_value(
            self.sek,
            self.channel,
            self.directory.active.sparse.commitments,
            &hashed(&head),
        )? == Some(Value::Present)
        {
            self.save_history_object(ObjectKind::ParentHead, parent_head_key(&author, seq), &head)?;
        }
        Ok(())
    }
    /// `head` is on this node's accepted chain of its author, read in this transaction. A
    /// receipt kept under it is then also a fact by author and position (`history_range`);
    /// under a head not (yet) accepted it is a witness of that head only (audit §11).
    fn accepted_head(&self, head: &Digest32) -> Result<bool> {
        let roots = self.directory.active.sparse;
        let source = Source::Batch(self.batch);
        match source.sparse_head(self.sek, self.channel, roots, head)? {
            Some(target) => source.sparse_head_accepted(self.sek, self.channel, roots, &target),
            None => Ok(false),
        }
    }
}

impl Read<'_> {
    pub(crate) fn history_inclusion_receipt(
        &self,
        head: &Digest32,
        author: &Digest32,
        seq: u64,
    ) -> Result<Option<IncludedHeader>> {
        let Some(bytes) = self.history_object(
            ObjectKind::InclusionReceipt,
            &receipt_key(head, author, seq),
        )?
        else {
            return Ok(None);
        };
        let result = IncludedHeader::from_authenticated_receipt(&bytes)?;
        if result.head_id() != *head
            || result.binding().room != *self.channel
            || result.binding().author != *author
            || result.header().entry().skeleton.seq != seq
        {
            return Err(invalid("stored inclusion receipt binding"));
        }
        Ok(Some(result))
    }
    /// The inclusion receipt of `author`'s position `seq` kept under a head of the author's
    /// accepted chain (the first one kept): found by author and position, whatever head asks.
    /// Heads of the accepted chain extend one another, so each names the same entry there.
    pub(crate) fn history_included_header(
        &self,
        author: &Digest32,
        seq: u64,
    ) -> Result<Option<IncludedHeader>> {
        let Some(bytes) =
            self.history_object(ObjectKind::IncludedHead, &included_head_key(author, seq))?
        else {
            return Ok(None);
        };
        let head: Digest32 = bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid("stored included head locator"))?;
        self.history_inclusion_receipt(&head, author, seq)?
            .ok_or(invalid("located inclusion receipt missing"))
            .map(Some)
    }
    pub(crate) fn history_prefix_receipt(
        &self,
        head: &Digest32,
        author: &Digest32,
        seq: u64,
    ) -> Result<Option<ConsistentPrefix>> {
        let Some(bytes) =
            self.history_object(ObjectKind::PrefixReceipt, &receipt_key(head, author, seq))?
        else {
            return Ok(None);
        };
        let result = ConsistentPrefix::from_authenticated_receipt(&bytes)?;
        if result.head_id() != *head
            || result.binding().room != *self.channel
            || result.binding().author != *author
            || result.prefix().leaves != seq
        {
            return Err(invalid("stored prefix receipt binding"));
        }
        Ok(Some(result))
    }
}
impl Write<'_, '_> {
    pub(crate) fn keep_history_inclusion_receipt(
        &mut self,
        receipt: &IncludedHeader,
    ) -> Result<()> {
        if receipt.binding().room != *self.channel {
            return Err(invalid("inclusion receipt room"));
        }
        let (head, author, seq) = (
            receipt.head_id(),
            receipt.binding().author,
            receipt.header().entry().skeleton.seq,
        );
        let key = receipt_key(&head, &author, seq);
        self.save_history_object(ObjectKind::InclusionReceipt, key, &receipt.local_receipt()?)?;
        // Located by position only under a head of the accepted chain (an unresolved or forked
        // head borrows nothing); kept again once its head is accepted (`bundle::check`).
        let roots = self.directory.active.sparse;
        let source = Source::Batch(self.batch);
        let accepted = match source.sparse_head(self.sek, self.channel, roots, &head)? {
            Some(target) => source.sparse_head_accepted(self.sek, self.channel, roots, &target)?,
            None => false,
        };
        if accepted {
            self.save_history_object(
                ObjectKind::IncludedHead,
                included_head_key(&author, seq),
                &head,
            )?;
        }
        Ok(())
    }
    /// A verified prefix [1, n] of one signed head, kept under that head. Its range [1, n] is
    /// kept by author and position only while the head is on the author's accepted chain: a
    /// prefix of a head not accepted (unresolved, of another history, or not yet promoted) is a
    /// witness of that head and never a fact of the accepted chain (MP-9). A caller that
    /// promotes the head keeps the receipt again after the promotion (`bundle::check`).
    pub(crate) fn keep_history_prefix_receipt(&mut self, receipt: &ConsistentPrefix) -> Result<()> {
        if receipt.binding().room != *self.channel {
            return Err(invalid("prefix receipt room"));
        }
        let key = receipt_key(
            &receipt.head_id(),
            &receipt.binding().author,
            receipt.prefix().leaves,
        );
        if receipt.prefix().leaves != 0 && self.accepted_head(&receipt.head_id())? {
            self.keep_history_range(receipt.binding(), 1, receipt.prefix())?;
        }
        self.save_history_object(ObjectKind::PrefixReceipt, key, &receipt.local_receipt()?)
    }
}

/// A pending header under one head: kept so only while that head is not in the author's
/// accepted chain (it may belong to another branch), and by older versions for every head.
fn pending_header_key(head: &Digest32, seq: u64) -> Digest32 {
    let mut bytes = b"vox/local-pending-header/v1".to_vec();
    bytes.extend_from_slice(head);
    bytes.extend_from_slice(&seq.to_be_bytes());
    sha256(&bytes)
}
/// A pending header kept under a head in the author's accepted chain: a fact about the
/// author's position, which every later committed head extends, so it is kept once by author
/// and position and deleted when that position is published (`index_source_head`).
fn pending_position_key(author: &Digest32, seq: u64) -> Digest32 {
    let mut bytes = b"vox/local-pending-position/v1".to_vec();
    bytes.extend_from_slice(author);
    bytes.extend_from_slice(&seq.to_be_bytes());
    sha256(&bytes)
}
fn check_pending_header(head: &SignedHead, entry: &Entry) -> Result<()> {
    head.binding.matches_entry(entry)?;
    if entry.skeleton.seq > head.root.leaves
        || (entry.skeleton.seq == head.root.leaves && entry.skeleton.epoch != head.tail_epoch)
    {
        return Err(invalid("pending header target position or epoch"));
    }
    Ok(())
}
impl Read<'_> {
    /// Authenticated provisional header only; this locator is neither inclusion nor admission.
    /// Under a head in the author's accepted chain the header kept by position is found
    /// whichever accepted head it came with; under another head only the one kept under it.
    pub(crate) fn history_pending_header(
        &self,
        head: &Digest32,
        seq: u64,
    ) -> Result<Option<Entry>> {
        let target = self.history_head(head)?;
        if let Some(target) = &target {
            let source = self.source();
            let roots = self.directory.active.sparse;
            if source.sparse_head_accepted(self.sek, self.channel, roots, target)? {
                let key = pending_position_key(&target.binding.author, seq);
                if let Some(bytes) = self.history_object(ObjectKind::PendingHeader, &key)? {
                    let entry = Entry::from_wire(&bytes)?;
                    if entry.skeleton.seq != seq || entry.payload.is_some() {
                        return Err(invalid("pending header binding"));
                    }
                    // Kept under another accepted head: absent under this one when the position
                    // is past it or its tail epoch differs.
                    return Ok(check_pending_header(target, &entry)
                        .is_ok()
                        .then_some(entry));
                }
            }
        }
        let Some(bytes) =
            self.history_object(ObjectKind::PendingHeader, &pending_header_key(head, seq))?
        else {
            return Ok(None);
        };
        let target = target.ok_or(invalid("pending header head missing"))?;
        let entry = Entry::from_wire(&bytes)?;
        check_pending_header(&target, &entry)?;
        if entry.skeleton.seq != seq || entry.payload.is_some() {
            return Err(invalid("pending header binding"));
        }
        Ok(Some(entry))
    }
}
impl Write<'_, '_> {
    pub(crate) fn keep_history_pending_header(
        &mut self,
        head: &Digest32,
        header: &VerifiedHeader,
    ) -> Result<()> {
        self.require_sparse_idle()?;
        let source = Source::Batch(self.batch);
        let id = source
            .number(
                self.sek,
                self.channel,
                self.directory.active.sparse.objects,
                &object_key(ObjectKind::Head, head),
            )?
            .ok_or(invalid("pending header head missing"))?;
        let target = SignedHead::from_wire(&source.sparse_record(
            self.sek,
            self.channel,
            id,
            MAX_HEADER_BYTES,
        )?)?;
        if target.id() != *head || target.binding.room != *self.channel {
            return Err(invalid("pending header head binding"));
        }
        check_pending_header(&target, header.entry())?;
        let (author, seq) = (target.binding.author, header.entry().skeleton.seq);
        let roots = self.directory.active.sparse;
        let accepted = source.sparse_head_accepted(self.sek, self.channel, roots, &target)?;
        if accepted
            && source
                .sparse_position_header(self.sek, self.channel, roots, &author, seq)?
                .is_some_and(|held| held.entry_hash() == header.entry().entry_hash())
        {
            // Already published at this position: nothing is pending.
            return Ok(());
        }
        self.keep_history_header(header)?;
        let hash = if accepted {
            pending_position_key(&author, seq)
        } else {
            pending_header_key(head, seq)
        };
        let key = object_key(ObjectKind::PendingHeader, &hash);
        let source = Source::Batch(self.batch);
        if let Some(prior) = source.number(
            self.sek,
            self.channel,
            self.directory.active.sparse.objects,
            &key,
        )? {
            let held = Entry::from_wire(&source.sparse_record(
                self.sek,
                self.channel,
                prior,
                MAX_HEADER_BYTES,
            )?)?;
            if held.entry_hash() != header.entry().entry_hash() {
                return Err(invalid("pending header conflicts"));
            }
            return Ok(());
        }
        let id = source
            .number(
                self.sek,
                self.channel,
                self.directory.active.sparse.objects,
                &object_key(ObjectKind::Header, &header.entry().entry_hash()),
            )?
            .ok_or(invalid("pending header object missing"))?;
        self.directory.active.sparse.objects = self.change_value(
            self.directory.active.sparse.objects,
            key,
            Some(Value::Number(id)),
        )?;
        Ok(())
    }
    /// Position `seq` of `author` is published under `head`: its pending header, kept by
    /// position or under that head, is no longer pending. The header object itself stays.
    fn retire_pending_header(
        &mut self,
        objects: u64,
        author: &Digest32,
        seq: u64,
        head: &Digest32,
    ) -> Result<u64> {
        let mut objects = objects;
        for hash in [
            pending_position_key(author, seq),
            pending_header_key(head, seq),
        ] {
            let key = object_key(ObjectKind::PendingHeader, &hash);
            if Source::Batch(self.batch)
                .number(self.sek, self.channel, objects, &key)?
                .is_some()
            {
                objects = self.change_value(objects, key, None)?;
            }
        }
        Ok(objects)
    }
}
