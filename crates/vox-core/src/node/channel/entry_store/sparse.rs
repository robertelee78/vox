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
    admitted: u64,
    control_intervals: u64,
    obligations: u64,
    ranges: u64,
    author_count: u64,
    obligation_count: u64,
    enabled: bool,
}

impl Roots {
    pub(super) fn write(self, e: &mut Encoder) {
        e.array(9)
            .uint(self.objects)
            .uint(self.authors)
            .uint(self.admitted)
            .uint(self.control_intervals)
            .uint(self.obligations)
            .uint(self.ranges)
            .uint(self.author_count)
            .uint(self.obligation_count)
            .uint(u64::from(self.enabled));
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 9 {
            return Err(invalid("sparse roots arity"));
        }
        Ok(Self {
            objects: d.uint()?,
            authors: d.uint()?,
            admitted: d.uint()?,
            control_intervals: d.uint()?,
            obligations: d.uint()?,
            ranges: d.uint()?,
            author_count: d.uint()?,
            obligation_count: d.uint()?,
            enabled: flag(d)?,
        })
    }
    pub(super) fn valid_for(self, next: u64) -> bool {
        [
            self.objects,
            self.authors,
            self.admitted,
            self.control_intervals,
            self.obligations,
            self.ranges,
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

impl Write<'_, '_> {
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
        if proof.head_id != head.id()
            || proof.binding != head.binding
            || proof.root != head.root
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
        if proof.prefix != prior {
            return Err(invalid("consistency baseline changed before publication"));
        }
        self.save_history_object(ObjectKind::Head, head.id(), &head.to_wire())?;
        state.observed = Some(head.id());
        state.committed = Some(head.id());
        // Previously ready evidence remains exact to its older head; it is not upgraded by
        // commitment alone. Readers must compare that ID with their requested target.
        self.save_sparse_author(head.binding, state)
    }
    /// Remember cryptographically complete coverage, not semantic control readiness. Bodies,
    /// parent receipts and authority evaluation remain durable obligations owned by admission.
    pub(crate) fn keep_control_coverage(&mut self, proof: &VerifiedControlRange) -> Result<()> {
        self.require_sparse_idle()?;
        if proof.binding.room != *self.channel
            || proof.lo == 0
            || proof.lo > proof.hi
            || proof.hi > proof.root.leaves
        {
            return Err(invalid("control coverage binding"));
        }
        let source = Source::Batch(self.batch);
        let record = source
            .number(
                self.sek,
                self.channel,
                self.directory.active.sparse.objects,
                &object_key(ObjectKind::Head, &proof.head_id),
            )?
            .ok_or(invalid("control coverage head missing"))?;
        let head = SignedHead::from_wire(&source.sparse_record(
            self.sek,
            self.channel,
            record,
            MAX_HEADER_BYTES,
        )?)?;
        if head.id() != proof.head_id || head.binding != proof.binding || head.root != proof.root {
            return Err(invalid("control coverage target differs"));
        }
        let key = position(&proof.head_id, proof.lo);
        let root = self.directory.active.sparse.control_intervals;
        let prior = source
            .number(self.sek, self.channel, root, &key)?
            .unwrap_or(0);
        if proof.hi > prior {
            self.directory.active.sparse.control_intervals =
                self.change_value(root, key, Some(Value::Number(proof.hi)))?;
        }
        Ok(())
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
