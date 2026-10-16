//! Exact sparse-history evidence in the existing sealed EntryIndex allocation/transaction.
//!
//! These roots never stand in for `PublishedFeed`. A signature-valid observed head grants
//! neither prefix consistency nor control authority. Large immutable objects are separate
//! sealed records, not inline directory state or permanently retained plaintext.

use super::*;
use crate::hash::sha256;
use crate::log::history::{
    ConsistentPrefix, ControlContext, Descriptor, LogScope, SignedHead, TreeBinding,
    VerifiedControlRange, VerifiedHead, VerifiedHeader, MAX_CONTEXT_AUTHORS, MAX_CONTEXT_BYTES,
    MAX_FRAME_BYTES, MAX_HEADER_BYTES,
};

const MAX_OBLIGATIONS: u64 = 4096;
const STATE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Roots {
    objects: u64,
    authors: u64,
    validated_positions: u64,
    control_intervals: u64,
    obligations: u64,
    ranges: u64,
    commitments: u64,
    source_heads: u64,
    control_sources: u64,
    source_prefixes: u64,
    source_cursors: u64,
    settled_entries: u64,
    author_count: u64,
    obligation_count: u64,
    pub(super) enabled: bool,
}

impl Roots {
    pub(super) fn write(self, e: &mut Encoder) {
        e.array(15)
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
            .uint(self.source_cursors)
            .uint(self.settled_entries)
            .uint(self.author_count)
            .uint(self.obligation_count)
            .uint(u64::from(self.enabled));
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 15 {
            return Err(invalid("sparse roots arity"));
        }
        Ok(Self {
            objects: d.uint()?,
            authors: d.uint()?,
            validated_positions: d.uint()?,
            control_intervals: d.uint()?,
            obligations: d.uint()?,
            ranges: d.uint()?,
            commitments: d.uint()?,
            source_heads: d.uint()?,
            control_sources: d.uint()?,
            source_prefixes: d.uint()?,
            source_cursors: d.uint()?,
            settled_entries: d.uint()?,
            author_count: d.uint()?,
            obligation_count: d.uint()?,
            enabled: flag(d)?,
        })
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
            self.source_cursors,
            self.settled_entries,
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
    Proof = 3,
}
impl ObjectKind {
    pub(crate) const fn limit(self) -> usize {
        match self {
            Self::Context => MAX_CONTEXT_BYTES,
            Self::Head | Self::Header => MAX_HEADER_BYTES,
            Self::Proof => MAX_FRAME_BYTES,
        }
    }
}
fn object_key(kind: ObjectKind, hash: &Digest32) -> Key {
    let mut key = hashed(hash);
    key[32] = kind as u8;
    key
}
fn author_key(author: &Digest32, scope: LogScope) -> Key {
    let mut key = hashed(author);
    key[32] = scope as u8;
    key
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

/// Compact exact object references. None of these is a contiguous feed position.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AuthorState {
    pub observed: Option<Digest32>,
    pub committed: Option<Digest32>,
    pub control_ready: Option<Digest32>,
}
impl AuthorState {
    fn bytes(self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4).uint(1);
        hash_option(&mut e, self.observed);
        hash_option(&mut e, self.committed);
        hash_option(&mut e, self.control_ready);
        e.finish()
    }
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > STATE_BYTES {
            return Err(invalid("sparse author state size"));
        }
        let mut d = Decoder::new(bytes);
        if d.array()? != 4 || d.uint()? != 1 {
            return Err(invalid("sparse author state format"));
        }
        let state = Self {
            observed: read_hash_option(&mut d)?,
            committed: read_hash_option(&mut d)?,
            control_ready: read_hash_option(&mut d)?,
        };
        d.finish()?;
        if state.control_ready.is_some() && state.committed.is_none() {
            return Err(invalid("control-ready state without commitment"));
        }
        Ok(state)
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
}
impl ObligationKind {
    fn code(self) -> u64 {
        match self {
            Self::Context => 0,
            Self::ParentReceipt => 1,
            Self::ControlRange => 2,
            Self::ControlBody => 3,
            Self::Authority => 4,
        }
    }
    fn read(n: u64) -> Result<Self> {
        match n {
            0 => Ok(Self::Context),
            1 => Ok(Self::ParentReceipt),
            2 => Ok(Self::ControlRange),
            3 => Ok(Self::ControlBody),
            4 => Ok(Self::Authority),
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
        key[..32].copy_from_slice(&self.head);
        key[32..].copy_from_slice(&sha256(&self.bytes()?));
        Ok(key)
    }
}

impl Source<'_> {
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
        let wire = self.history_wire(
            sek,
            room,
            SegmentKind::LogDb,
            at.log,
            crate::log::history::MAX_ENTRY_WIRE,
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
}

impl Read<'_> {
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
        Ok(source
            .number(
                self.sek,
                self.channel,
                self.directory.active.sparse.source_prefixes,
                &hashed(head),
            )?
            .unwrap_or(0)
            >= through)
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
        let wire = source.history_wire(
            self.sek,
            self.channel,
            SegmentKind::LogDb,
            at.log,
            crate::log::history::MAX_ENTRY_WIRE,
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
    pub(crate) fn history_head(&self, hash: &Digest32) -> Result<Option<SignedHead>> {
        self.history_object(ObjectKind::Head, hash)?
            .map(|bytes| {
                let head = SignedHead::from_wire(&bytes)?;
                if head.binding.room != *self.channel || head.id() != *hash {
                    return Err(invalid("stored head binding"));
                }
                Ok(head)
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
    /// One interval in exact-head order. The admission driver's durable cursor folds
    /// overlapping ranges in bounded slices; absence is never itself a readiness verdict.
    pub(crate) fn control_interval_after(
        &self,
        head: &Digest32,
        after: Option<u64>,
    ) -> Result<Option<(u64, u64)>> {
        let lo = match after {
            Some(value) => value
                .checked_add(1)
                .ok_or(invalid("control interval cursor overflow"))?,
            None => 1,
        };
        let source = self.source();
        let Some((key, value)) = source.first(
            self.sek,
            self.channel,
            self.directory.active.sparse.control_intervals,
            &position(head, lo),
            0,
        )?
        else {
            return Ok(None);
        };
        if key[..32] != head[..] {
            return Ok(None);
        }
        let start = u64::from_be_bytes(
            key[32..40]
                .try_into()
                .map_err(|_| invalid("control interval key"))?,
        );
        let Value::Number(through) = value else {
            return Err(invalid("control interval value"));
        };
        if start == 0
            || through < start
            || through > crate::log::feed::MAX_SEQ
            || key[40..].iter().any(|byte| *byte != 0)
        {
            return Err(invalid("stored control interval bounds"));
        }
        Ok(Some((start, through)))
    }
    /// One exact-head dependency, without materializing the rest of the work queue.
    pub(crate) fn history_obligation_after(
        &self,
        head: &Digest32,
        after: Option<Digest32>,
    ) -> Result<Option<(Digest32, Obligation)>> {
        let mut key = [0; 64];
        key[..32].copy_from_slice(head);
        if let Some(after) = after {
            key[32..].copy_from_slice(&after);
            let Some(next) = dag_facts::successor(key) else {
                return Ok(None);
            };
            key = next;
        }
        let source = self.source();
        let Some((key, value)) = source.first(
            self.sek,
            self.channel,
            self.directory.active.sparse.obligations,
            &key,
            0,
        )?
        else {
            return Ok(None);
        };
        if key[..32] != head[..] {
            return Ok(None);
        }
        let Value::Number(id) = value else {
            return Err(invalid("sparse obligation locator"));
        };
        let item =
            Obligation::parse(&source.sparse_record(self.sek, self.channel, id, STATE_BYTES)?)?;
        if item.key()? != key {
            return Err(invalid("sparse obligation binding"));
        }
        Ok(Some((
            key[32..]
                .try_into()
                .map_err(|_| invalid("sparse obligation key"))?,
            item,
        )))
    }
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
    MissingSource {
        author: Digest32,
        seq: u64,
        hash: Digest32,
    },
}

impl Write<'_, '_> {
    pub(crate) fn begin_sparse_publication(
        &mut self,
        publication: SparsePublication<'_>,
    ) -> Result<()> {
        self.require_sparse_idle()?;
        let SparsePublication {
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
        if v2.kind.is_control() && entry.payload.is_none() {
            return Err(invalid("validated control source has no required body"));
        }
        if validated.pre_context().hash() != v2.pre_context
            || validated.pre_context().scope != v2.scope
        {
            return Err(invalid("sparse publication context differs"));
        }
        self.keep_history_context(validated.pre_context())?;
        self.keep_history_header(included.header())?;
        self.set_origin(origin)?;
        let witness = self.stage(entry)?;
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
            reordered: 0,
            accepted: None,
            sparse_head: Some(included.head_id()),
        });
        self.directory.phase = Phase::Building;
        Ok(())
    }

    pub(super) fn index_sparse_source(
        &mut self,
        roots: &mut super::Roots,
        entry: &Entry,
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
        let head = self
            .directory
            .promotion
            .as_ref()
            .and_then(|p| p.sparse_head)
            .ok_or(invalid("sparse source publication lost its head"))?;
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
        if bytes.len() > kind.limit() {
            return Err(invalid("sparse object size"));
        }
        let key = object_key(kind, &hash);
        let root = self.directory.active.sparse.objects;
        if Source::Batch(self.batch)
            .number(self.sek, self.channel, root, &key)?
            .is_some()
        {
            // The typed caller has checked this content identity. A different randomized
            // valid signature of the same head/header does not replace the retained witness.
            return Ok(());
        }
        let id = self.save_sparse_record(None, bytes, kind.limit())?;
        self.directory.active.sparse.objects =
            self.change_value(root, key, Some(Value::Number(id)))?;
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
    /// A proof object's byte identity confers no verification or publication authority.
    pub(crate) fn keep_history_proof(&mut self, bytes: &[u8]) -> Result<Digest32> {
        let hash = sha256(bytes);
        self.save_history_object(ObjectKind::Proof, hash, bytes)?;
        Ok(hash)
    }
    /// A previously reconstructed tree node, retained for bounded proof serving. The
    /// descriptor does not mark an interval as admitted or control-ready.
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
        Ok(())
    }
    /// Retain an authenticated hint only. Consistency and control readiness remain separate.
    pub(crate) fn observe_history_head(&mut self, verified: &VerifiedHead) -> Result<Digest32> {
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
        if state.observed != Some(hash) {
            state.observed = Some(hash);
            self.save_sparse_author(head.binding, state)?;
        }
        Ok(hash)
    }
    /// Publish only the exact consistency result against the root still accepted in this
    /// Batch. A stale result cannot replace a newer commitment. No contiguous head changes.
    pub(crate) fn commit_history_head(
        &mut self,
        verified: &VerifiedHead,
        proof: &ConsistentPrefix,
    ) -> Result<()> {
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
        let mut state = source
            .sparse_author(
                self.sek,
                self.channel,
                self.directory.active.sparse,
                &head.binding.author,
                head.binding.scope,
            )?
            .unwrap_or_default();
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
            if self
                .directory
                .restart
                .as_ref()
                .is_some_and(|r| r.feeds.contains_key(&head.binding.author))
            {
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
        state.observed = Some(head.id());
        state.committed = Some(head.id());
        self.directory.active.sparse.commitments = self.change_value(
            self.directory.active.sparse.commitments,
            hashed(&head.id()),
            Some(Value::Present),
        )?;
        // Previously ready evidence remains exact to its older head; it is not upgraded by
        // commitment alone. Readers must compare that ID with their requested target.
        self.save_sparse_author(head.binding, state)
    }
    /// Remember cryptographically complete coverage, not semantic control readiness. Bodies,
    /// parent receipts and authority evaluation remain durable obligations owned by admission.
    pub(crate) fn keep_control_coverage(
        &mut self,
        proof: &VerifiedControlRange,
        after: usize,
    ) -> Result<Option<usize>> {
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
            let key = position(&proof.head_id(), entry.skeleton.seq);
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
            }
        }
        if end < proof.headers().len() {
            return Ok(Some(end));
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
                    &position(&proof.head_id(), header.entry().skeleton.seq),
                )?
                .is_none()
            {
                return Err(invalid("control enumeration publication incomplete"));
            }
        }
        let key = position(&proof.head_id(), proof.lo());
        let root = self.directory.active.sparse.control_intervals;
        let prior = Source::Batch(self.batch)
            .number(self.sek, self.channel, root, &key)?
            .unwrap_or(0);
        if proof.hi() > prior {
            self.directory.active.sparse.control_intervals =
                self.change_value(root, key, Some(Value::Number(proof.hi())))?;
        }
        self.directory.active.sparse.source_cursors = self.change_value(
            self.directory.active.sparse.source_cursors,
            hashed(&proof.head_id()),
            None,
        )?;
        Ok(None)
    }
    /// Advance one covered interval or one enumerated control. A source-complete receipt
    /// is distinct from governance completion and never requires a whole head ready first.
    pub(crate) fn advance_control_sources(&mut self, head_id: &Digest32) -> Result<SourceProgress> {
        self.require_sparse_idle()?;
        let roots = self.directory.active.sparse;
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
        let through = source
            .number(
                self.sek,
                self.channel,
                roots.source_prefixes,
                &hashed(head_id),
            )?
            .unwrap_or(0);
        if through >= head.root.leaves {
            return Ok(SourceProgress::Complete { through });
        }
        let after = source
            .number(
                self.sek,
                self.channel,
                roots.source_cursors,
                &hashed(head_id),
            )?
            .unwrap_or(0);
        let Some((key, value)) = source.first(
            self.sek,
            self.channel,
            roots.control_intervals,
            &position(
                head_id,
                after
                    .checked_add(1)
                    .ok_or(invalid("control source cursor overflow"))?,
            ),
            0,
        )?
        else {
            return Ok(SourceProgress::MissingCoverage { after: through });
        };
        if key[..32] != head_id[..] {
            return Ok(SourceProgress::MissingCoverage { after: through });
        }
        let lo = u64::from_be_bytes(
            key[32..40]
                .try_into()
                .map_err(|_| invalid("coverage start"))?,
        );
        let Value::Number(hi) = value else {
            return Err(invalid("coverage end"));
        };
        if lo > through + 1 {
            return Ok(SourceProgress::MissingCoverage { after: through });
        }
        if hi <= through {
            self.directory.active.sparse.source_cursors = self.change_value(
                roots.source_cursors,
                hashed(head_id),
                Some(Value::Number(lo)),
            )?;
            return Ok(SourceProgress::Progress { through });
        }
        let next = source.first(
            self.sek,
            self.channel,
            roots.control_sources,
            &position(head_id, through + 1),
            0,
        )?;
        let (next_through, finish_interval) = match next {
            Some((key, Value::Number(id))) if key[..32] == head_id[..] => {
                let seq = u64::from_be_bytes(
                    key[32..40]
                        .try_into()
                        .map_err(|_| invalid("control source position"))?,
                );
                if seq > hi {
                    (hi, true)
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
                    if !actual.is_some_and(|entry| entry.entry_hash() == expected.entry_hash()) {
                        return Ok(SourceProgress::MissingSource {
                            author: head.binding.author,
                            seq,
                            hash: expected.entry_hash(),
                        });
                    }
                    (seq, seq == hi)
                }
            }
            Some((key, _)) if key[..32] == head_id[..] => {
                return Err(invalid("control source locator"))
            }
            _ => (hi, true),
        };
        self.directory.active.sparse.source_prefixes = self.change_value(
            roots.source_prefixes,
            hashed(head_id),
            Some(Value::Number(next_through)),
        )?;
        if finish_interval {
            self.directory.active.sparse.source_cursors = self.change_value(
                roots.source_cursors,
                hashed(head_id),
                Some(Value::Number(lo)),
            )?;
        }
        Ok(if next_through >= head.root.leaves {
            SourceProgress::Complete {
                through: next_through,
            }
        } else {
            SourceProgress::Progress {
                through: next_through,
            }
        })
    }
    /// Bounded durable pending work. At the cap the caller yields before staging more objects.
    pub(crate) fn keep_history_obligation(&mut self, obligation: &Obligation) -> Result<bool> {
        self.require_sparse_idle()?;
        let key = obligation.key()?;
        let root = self.directory.active.sparse.obligations;
        if Source::Batch(self.batch)
            .number(self.sek, self.channel, root, &key)?
            .is_some()
        {
            return Ok(true);
        }
        if self.directory.active.sparse.obligation_count == MAX_OBLIGATIONS {
            return Ok(false);
        }
        let id = self.save_sparse_record(None, &obligation.bytes()?, STATE_BYTES)?;
        self.directory.active.sparse.obligations =
            self.change_value(root, key, Some(Value::Number(id)))?;
        self.directory.active.sparse.obligation_count += 1;
        Ok(true)
    }
    pub(crate) fn finish_history_obligation(&mut self, obligation: &Obligation) -> Result<()> {
        self.require_sparse_idle()?;
        let key = obligation.key()?;
        let root = self.directory.active.sparse.obligations;
        if let Some(id) = Source::Batch(self.batch).number(self.sek, self.channel, root, &key)? {
            self.retire(id)?;
            self.directory.active.sparse.obligations = self.change_value(root, key, None)?;
            self.directory.active.sparse.obligation_count = self
                .directory
                .active
                .sparse
                .obligation_count
                .checked_sub(1)
                .ok_or(invalid("sparse obligation counter"))?;
        }
        Ok(())
    }
}
